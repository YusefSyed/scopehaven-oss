// node integrations/conversations/cli.mjs --spec <private spec.json> --out <private dir> --authorization <record.json>
//   [--save <data dir> [--gate [--baseline <run id>]]]
// The spec's origin is an application the operator configured, so a run needs an authorization record
// (docs/RULES-OF-ENGAGEMENT.md) naming the spec's id and applicationId, its origin and every credentialed
// actor's principal, valid now; without one nothing is sent. The report, the summary and the saved run carry its stamp.
// The window is checked again before every request, and once more immediately before the report is written: once it
// ends, nothing more is sent and the run is refused (authorization-window-ended, exit 2) with no report written and no
// run saved, also when it ended after the last request was sent.
// Runs a conversation spec, writes the report (0600) and prints a summary.
// --save also stores the run as a native saved run (history, compare, export),
// which needs applicationId, build and contextId in the spec; --gate then
// gates it against the spec's exported suite, optionally against a saved
// baseline run. Exit 0 when everything passed (or the gate was clean), 1 on any
// fail/error/inconclusive, 2 on a setup error.
import { lstat, readFile, mkdir, writeFile, chmod } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runConversations, validateConversationSpec, observeText } from './conversation.mjs';
import { observeHttp } from '../../src/http-connector.mjs';
import { AuthorizationError, WINDOW_ENDED } from '../../src/authorization.mjs';
import { conversationRunFromReport, exportConversationSuite, runReady } from './validation.mjs';
import { createStore } from '../../src/store.mjs';
import { summarizeGate } from '../regression-gate/gate.mjs';
import { authorizeConfigured } from '../../src/authorization-file.mjs';
import { stampProducer } from '../../src/producer.mjs';

export async function main(argv, { env = process.env, stdout = process.stdout } = {}) {
  const arg = name => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
  const specPath = arg('--spec'), outDir = arg('--out'), saveDir = arg('--save'), baselineId = arg('--baseline'), gate = argv.includes('--gate'), recordPath = arg('--authorization');
  if (!specPath || !outDir) throw new Error('Usage: cli.mjs --spec <file> --out <directory> --authorization <record.json> [--save <data dir> [--gate [--baseline <run id>]]]');
  if ((gate || baselineId) && !saveDir) throw new Error('--gate and --baseline need --save <data dir>.');
  const info = await lstat(specPath);
  if (!info.isFile() || info.size > 262144) throw new Error('The spec must be a regular file of at most 256 KiB (not a symlink).');
  const spec = validateConversationSpec(JSON.parse(await readFile(specPath, 'utf8')));
  if (saveDir && !runReady(spec)) throw new Error('This spec is report-only: add applicationId, build and contextId to save runs for comparison and the gate.');
  // The authorization record is checked before any request; a refusal throws (exit 2) with its code.
  let authorization, granted;
  try { granted = await authorizeConfigured({ id: spec.id, applicationId: spec.applicationId, origin: spec.origin, actors: spec.actors }, recordPath && !recordPath.startsWith('--') ? resolve(recordPath) : undefined); authorization = granted.stamp; }
  catch (error) { if (error?.name === 'AuthorizationError') error.message = `authorization refused (${error.code}): ${error.message}; nothing was sent`; throw error; }
  let ran;
  try { ran = await runConversations(spec, { env, transport: granted.window.guard(observeHttp), textTransport: granted.window.guard(observeText) }); }
  catch (error) { if (!granted.window.ended()) throw error; }
  // The window once more, immediately before the stamped report is written and the run saved.
  try { granted.window.check(); }
  catch { throw new AuthorizationError(WINDOW_ENDED, `authorization refused (${WINDOW_ENDED}): the record's window ended before the run was saved; nothing more was sent, no report was written and no run was saved`); }
  const report = { ...ran, authorization };
  const dir = resolve(outDir); await mkdir(dir, { recursive: true, mode: 0o700 }); await chmod(dir, 0o700);
  const file = join(dir, `${report.id}.json`); await writeFile(file, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  const summary = { id: report.id, authorization, counts: report.counts, identity: report.identity, conversations: report.conversations.map(c => ({ id: c.id, status: c.status, trials: c.trials, failureRate: c.failureRate, ...(c.scope ? { scope: c.scope } : {}) })), report: file,
    comparability: runReady(spec) ? `Saved runs compare only with runs of the same spec digest (${report.specDigest.slice(0, 12)}); any spec edit makes them incompatible.` : 'Report-only: add applicationId, build and contextId to the spec to save runs for comparison and the gate.' };
  let exitCode = report.exitCode;
  if (saveDir) {
    const store = createStore(resolve(saveDir)); await store.ready;
    const saved = await store.save(stampProducer({ ...conversationRunFromReport(spec, report), authorization })); summary.savedRun = saved.id;
    if (gate) {
      const baseline = baselineId ? await store.get(baselineId) : null;
      summary.gate = summarizeGate({ candidate: saved, baseline, expectedSuite: exportConversationSuite(spec, report.specDigest) });
      exitCode = summary.gate.exitCode;
    }
  }
  stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  return exitCode;
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }, error => { process.stderr.write(`Conversation run could not start: ${error.message}\n`); process.exitCode = 2; });
}
