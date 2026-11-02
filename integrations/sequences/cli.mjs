// Run a timed sequence from JSON files:
//   node integrations/sequences/cli.mjs --sequence seq.json --origin http://127.0.0.1:PORT
//        --observers observers.json --authorization record.json [--gate gate.json] [--out DIR] [--hold-open-ms N]
// observers.json: [{ "type": "otel", "port": 4318, "services": ["<service.name>"] }
//                  | { "type": "sqlite-audit", "path", "audit", "principals" }
//                  | { "type": "sqlite-snapshot", "path", "tables" }
//                  | { "type": "http-audit", ...createHttpAuditObserver options }
//                  | { "type": "mcp-log", "path" }]
// gate.json: { "upstream": "http://127.0.0.1:PORT", "port": PORT, "rules": [...] }
// Recompute a saved run from the windows it sealed:
//   node integrations/sequences/cli.mjs --validate run.json [--sequence seq.json] [--observers observers.json [--gate gate.json]]
// With --observers (and --gate when the run used one) the run is also bound to that configuration: the observers
// are built, never started, and each must match the run's declared observer, scope names included.
// Exit codes: 0 all pass, 1 a check failed, 3 inconclusive or observer failure, 2 configuration error
// or (with --validate) evidence refused, with its reason; a scopehaven-sequence/1 record is not recomputable.
// Save the run for the regression gate, and judge it there (exit code: the gate's 0, 1 or 2):
//   ... --save DATA_DIR --build LABEL [--regression-gate [--baseline RUN_ID]]
// --save stores the run in a core run store (integrations/sequences/native.mjs), which needs "applicationId",
// "contextId" and an allowed-use control in the sequence; --regression-gate judges it against the sequence
// and, with --baseline, against a run saved earlier in the same store. --gate stays the hold-gate config.
// Credentials come only from SCOPEHAVEN_TARGET_* variables named in the sequence.
// A run sends requests to an application the operator configured, so it needs --authorization record.json: a record
// (docs/RULES-OF-ENGAGEMENT.md) naming the sequence's id and applicationId, --origin, each observer's endpoint and the
// hold gate's upstream, and every credentialed actor's principal, valid now. Without one it exits 2 before anything
// starts. The record's stamp is printed and carried by the saved run (--save); the sealed --out record is unchanged.
// The window is checked again before every request step and when each call to a declared observer starts (start, mark,
// collect): once it ends, no further request is sent and no further observer call starts (one already running can finish
// its reads), and the run exits 2 (authorization-window-ended) without writing --out or saving anything. It is
// checked once more immediately before --out is written, so a run that ended at or after validUntil is refused too.
// Input files must be regular files of at most 64 MiB; a parse error names the argument, never the content.
// --files files.json (report only, integrations/observers/file-snapshot.mjs): lists the files under the declared roots before
// the run and after it, and writes what was added, changed or removed to <run file>.files.json (mode 0600) beside --out's
// record. It is never part of the run: no window, no verdict, no digest, and a files channel still reads not observed.
import { readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { runSequence, validateSequence } from './sequence.mjs';
import { sequenceTransport, actorCsrf, withActorCsrf, websocketWithActorCsrf } from './transport.mjs';
import { validateSequenceRun, SequenceRunError } from './run-validator.mjs';
import { createHoldGate } from './gate.mjs';
import { sequenceNativeRun, exportSequenceSuite, sequenceRunReady, sequenceControlIds, BUILD_LABEL } from './native.mjs';
import { buildObservers as buildDeclared } from '../observers/factory.mjs';
import { CREDENTIAL_ENV } from '../observers/events.mjs';
import { createStore } from '../../src/store.mjs';
import { stampProducer } from '../../src/producer.mjs';
import { summarizeGate, validateRun } from '../regression-gate/gate.mjs';
import { authorizeConfigured } from '../../src/authorization-file.mjs';
import { guardObserver } from '../../src/authorization.mjs';
import { validateFileSnapshotConfig, takeFileSnapshot, fileReport } from '../observers/file-snapshot.mjs';

// A sequence needs at least one observer to judge anything.
export function buildObservers(configs, options) {
  if (!Array.isArray(configs) || !configs.length || configs.length > 16) throw new Error('observers.json must list 1 to 16 observers.');
  // A sequence sends no witness request, so an audit-log file window could never be complete.
  if (configs.some(c => c?.type === 'audit-file')) throw new Error('Sequences cannot use an audit-file observer: they send no witness request, so its windows would always be partial.');
  // The same holds for a routed sink, whose witness proves the route; without "witness" a sink is presence-only and usable.
  // A provider feed is not supported in sequences (v1): it reads a feed only the HTTP connector's witness proves.
  if (configs.some(c => c?.type === 'provider-feed')) throw new Error('Sequences cannot use a provider-feed observer: it is supported only in HTTP profiles.');
  if (configs.some(c => ['egress-recorder', 'smtp-sink'].includes(c?.type) && c.witness !== undefined)) throw new Error('Sequences cannot use a routed egress recorder or SMTP sink (with "witness"): they send no witness request, so its windows would always be partial. Declare it without "routing" and "witness" (presence-only).');
  // Keyed retries are counted only by HTTP effect clauses (countBy, src/idempotency.mjs), which sequences do not use.
  if (configs.some(c => c?.type === 'egress-recorder' && Array.isArray(c.destinations) && c.destinations.some(d => d !== null && typeof d === 'object' && Object.hasOwn(d, 'idempotency')))) throw new Error('Sequences cannot use an egress destination that declares "idempotency": only HTTP effect clauses count keyed retries.');
  // Forwarding to an upstream is for HTTP profiles, whose validator checks the upstream against the target origin.
  if (configs.some(c => c?.type === 'egress-recorder' && Array.isArray(c.destinations) && c.destinations.some(d => d?.forward !== undefined))) throw new Error('Sequences cannot use an egress recorder destination with "forward": forwarding is checked only for HTTP profiles.');
  return buildDeclared(configs, options);
}
function gateFrom(gateConfig) {
  // The gate keeps its own instance id, so a saved run can be validated.
  if (gateConfig !== null && typeof gateConfig === 'object' && Object.hasOwn(gateConfig, 'instanceId')) throw new Error('gate.json cannot set instanceId.');
  return createHoldGate(gateConfig);
}
// The observers a configuration declares, as a run records them, built but never started (nothing binds, connects or
// reads a credential): each credential name gets a placeholder, since no observer reads its value before a mark.
export function declaredObservers(configs, gateConfig = null) {
  const placeholders = Object.fromEntries((Array.isArray(configs) ? configs : []).map(c => c?.credentialEnv).filter(name => typeof name === 'string' && CREDENTIAL_ENV.test(name)).map(name => [name, 'validate-only:placeholder']));
  const observers = buildObservers(configs, { env: placeholders });
  if (gateConfig !== null) observers.push(gateFrom(gateConfig).observer());
  return observers.map(({ instanceId, source, kind, scope }) => ({ instanceId, source, kind, scope }));
}
export const exitCodeOf = run => run.counts.fail ? 1 : run.counts.inconclusive || run.counts.error || run.aborted ? 3 : 0;
export const MAX_INPUT_BYTES = 64 * 1024 * 1024;
export function readJsonArg(path, name) {
  let stat;
  try { stat = statSync(path); } catch { throw new Error(`${name} is not a readable file.`); }
  if (!stat.isFile() || stat.size > MAX_INPUT_BYTES) throw new Error(`${name} must be a regular file of at most ${MAX_INPUT_BYTES} bytes.`);
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { throw new Error(`${name} is not valid JSON.`); }
}

// One printed line per row: effect rows name their corroboration and custody, status rows the status answered.
const rowLine = r => `  ${r.status.toUpperCase().padEnd(12)} ${r.id}  ${r.title}${r.kind === 'response-status' ? `  [answered: ${r.observed?.complete ? r.observed.status : 'none'}]` : ''}`
  + `${r.corroboratedBy?.length ? `  [corroborated: ${r.corroboratedBy.join(', ')}]` : ''}${r.custodyReason ? `  [${r.custodyReason}: the application can write every record that decided this]` : ''}`;
const SAVE_FLAGS = ['--save', '--build', '--regression-gate', '--baseline'];

export async function main(argv = process.argv.slice(2), { env = process.env, log = s => process.stdout.write(`${s}\n`) } = {}) {
  const opt = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  if (opt('--validate')) {
    if (SAVE_FLAGS.some(flag => argv.includes(flag))) { log('Configuration error: --save, --build, --regression-gate and --baseline apply to a new run, not to --validate.'); return 2; }
    let run;
    try {
      run = readJsonArg(opt('--validate'), '--validate');
      if (opt('--gate') && !opt('--observers')) throw new Error('--gate binds a run only together with --observers.');
      const expectedObservers = opt('--observers') ? declaredObservers(readJsonArg(opt('--observers'), '--observers'), opt('--gate') ? readJsonArg(opt('--gate'), '--gate') : null) : undefined;
      validateSequenceRun(run, { ...(opt('--sequence') ? { expectedSequence: readJsonArg(opt('--sequence'), '--sequence') } : {}), ...(expectedObservers ? { expectedObservers } : {}) });
    } catch (error) {
      log(error instanceof SequenceRunError ? `Run evidence refused: ${error.code}${error.detail ? ` (${error.detail})` : ''}` : `Configuration error: ${error.message}`);
      return 2;
    }
    const bound = [opt('--sequence') ? 'the given sequence' : null, opt('--observers') ? 'the given observer configuration' : null].filter(Boolean);
    log(`Recomputed ${run.results.length} assertion${run.results.length === 1 ? '' : 's'} of ${run.sequenceId} from the sealed windows: every verdict matches${bound.length ? `, bound to ${bound.join(' and ')}` : ''}.`);
    return exitCodeOf(run);
  }
  let observers, gate = null, sequence, store = null, baseline = null, authorization, granted, csrfPairs = null, files = null;
  const saveDir = opt('--save'), build = opt('--build'), regression = argv.includes('--regression-gate'), baselineId = opt('--baseline');
  try {
    if (!opt('--sequence') || !opt('--origin') || !opt('--observers')) throw new Error('Usage: cli.mjs --sequence seq.json --origin http://127.0.0.1:PORT --observers observers.json --authorization record.json [--gate gate.json] [--out DIR] [--save DATA_DIR --build LABEL [--regression-gate [--baseline RUN_ID]]]');
    // Checked before anything binds or sends: a saved run needs a build label, the gate needs a saved run, a baseline needs the gate.
    for (const flag of ['--save', '--build', '--baseline', '--authorization', '--files']) { const value = opt(flag); if (argv.includes(flag) && (typeof value !== 'string' || !value.length || value.startsWith('--'))) throw new Error(`${flag} needs a value.`); }
    if ((regression || baselineId !== undefined || build !== undefined) && saveDir === undefined) throw new Error('--build, --regression-gate and --baseline need --save DATA_DIR.');
    if (baselineId !== undefined && !regression) throw new Error('--baseline needs --regression-gate.');
    if (saveDir !== undefined && !(typeof build === 'string' && BUILD_LABEL.test(build))) throw new Error('--save needs --build LABEL: 1 to 200 printable characters naming the build under test.');
    sequence = readJsonArg(opt('--sequence'), '--sequence');
    const seq = validateSequence(sequence);
    // Actors' CSRF pairs (transport.mjs actorCsrf): refused here, before anything starts, like any other configuration error.
    csrfPairs = actorCsrf(seq, env);
    if (saveDir !== undefined) {
      if (!sequenceRunReady(seq)) throw new Error('A sequence saved with --save needs "applicationId" and "contextId" (1 to 80 letters, digits, "_" or "-").');
      if (!sequenceControlIds(seq).length) throw new Error('A sequence saved with --save needs at least one allowed-use control (severity "control"): without one, an absence could come from a target that does nothing.');
    }
    // The rows the assertions name: snapshot observers claim absence only about rows seen at both marks.
    const watchedResources = [...new Set((sequence.assertions ?? []).flatMap(a => [a.effect?.select, ...(a.corroborate ?? [])]).map(s => s?.resource).filter(r => typeof r === 'string'))];
    const observerConfigs = readJsonArg(opt('--observers'), '--observers'), gateConfig = opt('--gate') ? readJsonArg(opt('--gate'), '--gate') : null;
    // Building validates the configuration; nothing listens or connects until the runner starts it.
    observers = buildObservers(observerConfigs, { env, watchedResources });
    if (gateConfig !== null) gate = gateFrom(gateConfig);
    if (argv.includes('--files')) files = validateFileSnapshotConfig(readJsonArg(opt('--files'), '--files'));
    // The store and the baseline are read before the sequence runs, so a bad baseline costs no run.
    if (saveDir !== undefined) { store = createStore(resolve(saveDir)); await store.ready; }
    if (baselineId !== undefined) {
      try { baseline = await store.get(baselineId); validateRun(baseline); }
      catch (error) { throw new Error(`the baseline run was refused (${error.message})`); }
    }
    // The authorization record: checked last, once the configuration and any baseline are valid, before any observer or the gate starts
    // and any request is sent.
    try {
      granted = await authorizeConfigured({ id: seq.id, applicationId: seq.applicationId, origin: opt('--origin'), observers: observerConfigs, actors: seq.actors },
        argv.includes('--authorization') ? resolve(opt('--authorization')) : undefined, { alsoContacts: gateConfig === null ? [] : [gateConfig.upstream] });
      authorization = granted.stamp;
      // Every call the run makes to these observers, except stop, checks the window when it starts (an http-audit reader on
      // --origin included). The hold gate's own observer, added below, is not guarded: its calls read only the gate's memory.
      observers = observers.map(observer => guardObserver(observer, granted.window.check));
    } catch (error) {
      if (error?.name !== 'AuthorizationError') throw error;
      log(`Authorization refused (${error.code}): ${error.message}. Nothing was started or sent.`); return 2;
    }
  } catch (error) { log(`Configuration error: ${error.message}`); return 2; }
  const holdOpen = Number(opt('--hold-open-ms') ?? 0);
  let run, failure, failed = false, filesStart = null, filesEnd = null;
  try {
    if (files) filesStart = takeFileSnapshot(files);
    if (gate) { await gate.start(); observers.push(gate.observer()); }
    // The runner owns observer startup and cleanup, including this optional
    // wait after every observer is ready. It starts each observer only once.
    const onReady = holdOpen > 0 ? async () => { log(`Observers ready; starting in ${holdOpen} ms.`); await new Promise(r => setTimeout(r, Math.min(holdOpen, 600000))); } : null;
    run = await runSequence(sequence, { origin: opt('--origin'), observers, gate, env, onReady, transport: granted.window.guard(withActorCsrf(csrfPairs, sequenceTransport)), websocket: granted.window.guard(websocketWithActorCsrf(csrfPairs)) });
    if (files) filesEnd = takeFileSnapshot(files);
  } catch (error) { failed = true; failure = error; }
  finally {
    // A gate that partially started also needs cleanup; an observer failure
    // must not leave its listener running or be hidden by a stop failure.
    if (gate) try { await gate.stop(); } catch (error) { if (!failed) { failed = true; failure = error; } }
  }
  // The window once more, immediately before anything is written or saved (only synchronous writes follow until the save).
  try { granted.window.check(); }
  catch { log('Authorization refused (authorization-window-ended): the record\'s window ended before the run was saved. Nothing more was sent, and nothing was written or saved.'); return 2; }
  if (failed) { log(`Configuration error: ${failure?.message ?? 'Sequence failed.'}`); return 2; }
  const out = resolve(opt('--out') ?? '.scopehaven-sequences');
  mkdirSync(out, { recursive: true, mode: 0o700 });
  const file = join(out, `${run.sequenceId}-${run.runDigest.slice(0, 12)}.json`);
  writeFileSync(file, `${JSON.stringify(run, null, 2)}\n`, { mode: 0o600 });
  log(`Sequence ${run.sequenceId}: ${run.counts.pass} pass, ${run.counts.fail} fail, ${run.counts.inconclusive} inconclusive, ${run.counts.error} error${run.aborted ? ` (stopped: ${run.aborted})` : ''}`);
  for (const r of run.results) log(rowLine(r));
  log(`Saved ${file}`);
  if (files) {
    const report = fileReport(files, filesStart, filesEnd, { sequenceId: run.sequenceId, runFile: file.split('/').pop() });
    const reportFile = file.replace(/\.json$/, '.files.json');
    writeFileSync(reportFile, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    const count = op => report.changes.filter(c => c.operation === op).length;
    log(report.coverage === 'failed'
      ? `Files (report only, not a verdict): not compared (${[report.start, report.end].filter(s => !s.ok).map(s => s.reason).join(', ')}). Saved ${reportFile}`
      : `Files (report only, not a verdict): ${count('insert')} added, ${count('update')} changed, ${count('delete')} removed${report.omitted ? ` (${report.omitted} more not listed)` : ''}. Saved ${reportFile}`);
  }
  log(`Authorized by record ${authorization.id} (sha256 ${authorization.sha256}).`);
  if (store === null) return exitCodeOf(run);
  // The run, as a native saved run the regression gate reads (immutable in the store, mode 0600).
  let saved;
  try { saved = await store.save(stampProducer({ ...sequenceNativeRun({ sequence, run, build }), authorization })); }
  catch (error) { log(`Storage error: ${error instanceof SequenceRunError ? `run evidence refused: ${error.code}` : error.message}`); return 2; }
  log(`Stored run ${saved.id} (build: ${saved.build})`);
  if (!regression) return exitCodeOf(run);
  // Judged against the sequence this process ran and the observers it gave the run, and the baseline when given.
  const declared = observers.map(({ instanceId, source, kind, scope }) => ({ instanceId, source, kind, scope }));
  const summary = summarizeGate({ candidate: saved, baseline, expectedSuite: exportSequenceSuite(sequence, declared) });
  log(`Regression gate: ${summary.outcome} (exit ${summary.exitCode})${summary.reasons.length ? `: ${summary.reasons.join(', ')}` : ''}`);
  if (summary.comparison?.requested) {
    const labels = Object.entries(summary.comparison.labels).filter(([, n]) => n > 0).map(([label, n]) => `${label} ${n}`).join(', ');
    log(`  Against ${summary.comparison.baselineRunId}: ${summary.comparison.compatibility}; ${summary.comparison.restorationLabel}; ${labels}`);
  }
  log(`Gate summary: ${JSON.stringify(summary)}`);
  return summary.exitCode;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) process.exitCode = await main();
