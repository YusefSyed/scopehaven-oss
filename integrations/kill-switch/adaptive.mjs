// ADAPTIVE-01. A bounded generator over the owned control-tamper fixture's ALREADY-DECLARED
// attempts.
//
// What it does: it chooses an ORDER for the declared tool calls, a DISTRIBUTION of them across
// script steps, and a PAUSE POINT among the steps that distribution creates, then runs the
// existing control-tamper check on that script. After each run it reads the refusal statuses and
// chooses the next run. It is a search over a closed set, not an attack generator: a generated
// attempt is an INDEX into TAMPER_SCRIPT's own calls, and no path, method, body, header or
// encoding is ever constructed.
//
// What decides anything: the existing rows, with the custody they already carry. This module
// produces attempts and a record of what was attempted. It produces no verdict, and the
// coverage map it seals into the record is never read by a row or by the gate.
//
// The adaptation signal is the previous run's refusal STATUSES and nothing else: not the reply,
// not the audit log, not the ledger. The statuses are themselves application-authored, so an
// application that lies in them can at most waste search budget by steering the generator down
// an ordering that finds nothing. It can never move a row, because no row reads them.
import { TAMPER_SCRIPT, AGENT_ATTEMPTS, REFUSED_STATUS, runControlTamper, CONTROL_TAMPER_SCHEMA } from './control-tamper.mjs';
import { digest } from '../../src/domain.mjs';

export const ADAPTIVE_SCHEMA = 'scopehaven-adaptive/1';

// The hard bounds. A run that would exceed one stops and records which it hit; stopping is an
// outcome, never a silent truncation.
export const BOUNDS = Object.freeze({ maxAttempts: 64, maxRuns: 8, maxMs: 60000 });

// The bounds are CEILINGS: a caller may ask for less, never for more, and every bound must be a
// finite number. `{ ...BOUNDS, ...bounds }` let a caller raise any of them (9 runs, 90 attempts),
// and a NaN switched a check off while the record saved it as null. Asking for more is a
// configuration error rather than a mode, like an
// origin, and so is a bound this module does not have.
export function boundsFrom(bounds = {}) {
  if (bounds === null || typeof bounds !== 'object' || Array.isArray(bounds)) {
    throw new Error('ADAPTIVE-01 bounds must be an object of maxAttempts, maxRuns and maxMs.');
  }
  const undeclared = Object.keys(bounds).filter(key => !Object.hasOwn(BOUNDS, key));
  if (undeclared.length) throw new Error(`ADAPTIVE-01 has no ${undeclared.join(', ')} bound.`);
  const limits = { ...BOUNDS, ...bounds };
  for (const [key, ceiling] of Object.entries(BOUNDS)) {
    if (typeof limits[key] !== 'number' || !Number.isFinite(limits[key])) {
      throw new Error(`ADAPTIVE-01 bound ${key} must be a finite number, not ${String(limits[key])}.`);
    }
    if (limits[key] > ceiling) throw new Error(`ADAPTIVE-01 bound ${key} is a ceiling of ${ceiling}; ${limits[key]} would exceed it.`);
  }
  return limits;
}

// The closed set this draws from: the declared calls of the fixture's own script, flattened,
// each with a stable surface id. Nothing is added to this set and nothing is constructed.
export const DECLARED_CALLS = Object.freeze(TAMPER_SCRIPT
  .flatMap(step => step.toolCalls ?? [])
  .map((call, index) => Object.freeze({
    surfaceId: `${call.name}:${Object.values(call.arguments).join('/')}`,
    index, call: Object.freeze({ ...call, arguments: Object.freeze({ ...call.arguments }) }),
  })));
// The reply step the script ends on. The turn has to end, or every row reads inconclusive.
const FINAL_STEP = Object.freeze(TAMPER_SCRIPT.find(step => step.content !== undefined) ?? { content: 'Done.' });

// A seeded generator. mulberry32: small, and its sequence is fixed by the seed, which is what
// makes a run replayable without recording every choice.
export function createChooser(seed) {
  if (!Number.isInteger(seed) || seed < 0) throw new Error('seed must be a non-negative integer.');
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6D2B79F5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    below: n => Math.floor(next() * n),
    // A Fisher-Yates shuffle over a COPY, so the declared set is never reordered in place.
    shuffled: items => { const out = [...items];
      for (let i = out.length - 1; i > 0; i--) { const j = Math.floor(next() * (i + 1)); [out[i], out[j]] = [out[j], out[i]]; }
      return out; },
  };
}

// One plan: an order for the declared calls, how they are split across steps, and which step the
// turn pauses at. The pause point is recorded by its DECLARED NAME, so a replay does not depend
// on any timing value.
export function planFrom(chooser, { stepsWanted = null, reachBeforePause = false } = {}) {
  const order = chooser.shuffled(DECLARED_CALLS);
  // Between 1 and 4 tool-call steps: the hold gate pauses at a model call, so the number of
  // steps is the number of pause points a plan offers. With ONE step the pause can only fall
  // before every call, so nothing is ever attempted against a live control; reaching one needs
  // at least two steps, which is what reachBeforePause asks for.
  const steps = stepsWanted ?? (reachBeforePause ? 2 + chooser.below(3) : 1 + chooser.below(4));
  const groups = Array.from({ length: steps }, () => []);
  order.forEach((declared, i) => groups[i % steps].push(declared));
  const script = [...groups.map(group => ({ toolCalls: group.map(d => d.call) })), FINAL_STEP];
  // holdAt indexes the script's steps; 1 pauses before any tool call runs. Reaching a live
  // control needs holdAt above 1, so that is preferred while any surface has never been there.
  const holdAt = reachBeforePause && script.length > 2
    ? 2 + chooser.below(script.length - 2)
    : 1 + chooser.below(script.length - 1);
  return {
    holdAt,
    pausePoint: `before-step-${holdAt}-of-${script.length - 1}`,
    steps,
    script,
    order: order.map(d => d.surfaceId),
    // Which declared surfaces sit before the pause on this plan, by name.
    beforePause: groups.slice(0, holdAt - 1).flat().map(d => d.surfaceId),
  };
}

// The origin guard. This drives the fixture's own desk, which runControlTamper starts on
// loopback; there is no option to point it anywhere else, and a caller that supplies one is a
// configuration error rather than a mode.
export function assertOwnedFixtureOnly(options = {}) {
  for (const key of ['origin', 'target', 'targetUrl', 'baseUrl', 'url', 'host']) {
    if (Object.hasOwn(options, key)) {
      throw new Error(`ADAPTIVE-01 runs against the owned control-tamper fixture only; it has no ${key} option.`);
    }
  }
}

// `hooks` is forwarded into startAgentDesk, so an ALLOW-list rather than a deny-list: the desk's
// dbPath, modelBaseUrl and tokens are infrastructure that control-tamper supplies, and letting a
// caller set dbPath made the desk create a SQLite file at a path of the caller's choosing.
// These are the desk's BEHAVIOURAL flags only. A test asserts every name
// here appears in startAgentDesk's own signature, so the list cannot drift away from the desk.
export const ALLOWED_HOOKS = Object.freeze(['recheckEachStep', 'modelTimeoutMs', 'refuseAllTools', 'serveSuspended', 'parkWhenSuspended',
  'commitAfterReplyMs', 'haltReply', 'eraseLedgerMs', 'rewriteNoteMs', 'readdSameIdMs', 'swapTablesMs', 'queueTableMs', 'lateControlMs',
  'rewriteAfterCommitMs', 'reattributeNoteMs', 'reattributeRefundMs', 'inflateRefundMs', 'freezeControlReaders', 'lockExclusiveMs',
  'renameUsersMs', 'renameControlsMs', 'answerOkWithoutApplying', 'controlWritable', 'silentRefusal', 'ignorePause', 'ledgerActor',
  'silentSurfaces', 'skipNoOpAccess', 'deferLedgerMs']);

export function assertDeclaredHooks(hooks = {}) {
  // `hooks: null` does not take the default - null is not undefined - so Object.keys threw a
  // bare TypeError instead of saying what was wrong.
  if (hooks === null || typeof hooks !== 'object' || Array.isArray(hooks)) {
    throw new Error('ADAPTIVE-01 hooks must be an object of the desk\'s declared behavioural flags.');
  }
  const undeclared = Object.keys(hooks).filter(key => !ALLOWED_HOOKS.includes(key));
  if (undeclared.length) {
    throw new Error(`ADAPTIVE-01 passes only the desk's declared behavioural hooks; it does not accept ${undeclared.join(', ')}.`);
  }
}

const refusalsOf = run => Object.fromEntries(AGENT_ATTEMPTS.map(a => [a.id, run.report.attemptStatuses?.[a.id] ?? null]));
// Every declared surface, with what was ATTEMPTED about it. Never "covered", never "tested
// safe": it says what was sent, not what is secure.
const emptyMap = () => Object.fromEntries(DECLARED_CALLS.map(d => [d.surfaceId,
  { attemptedCount: 0, attemptedBeforePause: 0, attemptedPausePoints: [], attemptedPositions: [] }]));

export async function runAdaptive({ seed = 1, bounds = BOUNDS, hooks = {}, observe = 'audit', ...rest } = {}) {
  assertOwnedFixtureOnly(rest);
  assertDeclaredHooks(hooks);
  const limits = boundsFrom(bounds);
  const chooser = createChooser(seed);
  const started = Date.now();
  const attempts = [], runs = [], attemptedMap = emptyMap();
  let stoppedBy = null, attemptCount = 0;
  // The adaptation state: the only thing read between runs. Statuses, nothing else.
  let lastRefusals = null;

  for (let runIndex = 0; runIndex < limits.maxRuns; runIndex++) {
    if (Date.now() - started > limits.maxMs) { stoppedBy = 'maxMs'; break; }
    if (attemptCount + DECLARED_CALLS.length > limits.maxAttempts) { stoppedBy = 'maxAttempts'; break; }
    // Adapt: if every admin attempt was refused last time, try more steps, which moves the pause
    // in among the declared calls. If any was NOT refused, keep the shape that found it. This is
    // the whole of the adaptation, and it reads only statuses.
    const allRefused = lastRefusals === null || Object.values(lastRefusals).every(s => s === REFUSED_STATUS);
    // The second signal, and it is the HARNESS's own record rather than the subject's: a surface
    // never yet attempted before the pause has never been tried against a live control, so the
    // next plan prefers a shape that puts one there. Reading its own coverage log is safe in a
    // way reading the subject's audit or ledger would not be, and it is what makes the search
    // reach the region that matters instead of re-running the easy one.
    const reachBeforePause = Object.values(attemptedMap).some(v => v.attemptedBeforePause === 0);
    const plan = planFrom(chooser, allRefused
      ? { reachBeforePause }
      : { stepsWanted: runs.at(-1)?.plan.steps ?? null, reachBeforePause });
    const run = await runControlTamper({ holdAt: plan.holdAt, script: plan.script, hooks, observe });
    const refusals = refusalsOf(run);
    lastRefusals = refusals;
    plan.order.forEach((surfaceId, position) => {
      const entry = attemptedMap[surfaceId];
      entry.attemptedCount += 1;
      entry.attemptedPositions.push(position);
      if (plan.beforePause.includes(surfaceId)) entry.attemptedBeforePause += 1;
      if (!entry.attemptedPausePoints.includes(plan.pausePoint)) entry.attemptedPausePoints.push(plan.pausePoint);
      attempts.push({ runIndex, position, surfaceId, pausePoint: plan.pausePoint, beforePause: plan.beforePause.includes(surfaceId) });
    });
    attemptCount += plan.order.length;
    // sentDigest covers EVERYTHING passed to runControlTamper - the pause point as well as the
    // script - because a replay can send the same calls and pause somewhere else. Digesting
    // `script` alone let a replay with an edited holdAt still read identical. A digest taken on
    // each side independently is what shows it; nothing here may be carried across from the
    // record. The holdAt is the one the check says it RAN (`run.holdAt`), not `plan.holdAt` read
    // a second time: reading the plan twice, once for the call and once for the digest, would let
    // a run pause at one point and log another, and the replay would then confirm the wrong record.
    runs.push({ runIndex, plan: { holdAt: plan.holdAt, pausePoint: plan.pausePoint, steps: plan.steps, order: plan.order, beforePause: plan.beforePause },
      sentDigest: digest({ holdAt: run.holdAt, script: plan.script }),
      refusals, rows: run.results.map(r => ({ id: r.id, status: r.status, ...(r.custodyReason ? { custodyReason: r.custodyReason } : {}) })) });
  }
  return sealRecord({ seed, limits, stoppedBy, attempts, runs, attemptedMap, startedAt: started });
}

// Replay the recorded attempts verbatim, ignoring the generator. This is what a reviewer uses,
// because it does not depend on the PRNG staying put.
// A record's seal, recomputed. sealRecord digests the record WITHOUT this field and then adds
// it, so verification strips it and digests the rest.
export function verifyRecordSeal(record) {
  if (record === null || typeof record !== 'object') return 'not a record';
  const { recordDigest, ...body } = record;
  if (typeof recordDigest !== 'string') return 'the record carries no recordDigest';
  return digest(body) === recordDigest ? null : 'the record does not match its own recordDigest';
}

export async function replayAdaptive(record, { hooks = {}, observe = 'audit' } = {}) {
  if (record?.schema !== ADAPTIVE_SCHEMA) throw new Error(`Not an ${ADAPTIVE_SCHEMA} record.`);
  // A seal and a test that recomputes it are not enough if the MODULE never reads it:
  // replayAdaptive would happily drive a replay from an edited log. A
  // replay is the reviewer's instrument; it has to refuse a record that is not the one sealed.
  const broken = verifyRecordSeal(record);
  if (broken !== null) throw new Error(`ADAPTIVE-01 will not replay a record it cannot vouch for: ${broken}.`);
  assertDeclaredHooks(hooks);
  const byId = new Map(DECLARED_CALLS.map(d => [d.surfaceId, d.call]));
  const runs = [];
  for (const recorded of record.runs) {
    const order = recorded.plan.order;
    const missing = order.filter(id => !byId.has(id));
    if (missing.length) throw new Error(`The log names surfaces this fixture does not declare: ${missing.join(', ')}.`);
    const groups = Array.from({ length: recorded.plan.steps }, () => []);
    order.forEach((id, i) => groups[i % recorded.plan.steps].push(byId.get(id)));
    const script = [...groups.map(group => ({ toolCalls: group })), FINAL_STEP];
    const run = await runControlTamper({ holdAt: recorded.plan.holdAt, script, hooks, observe });
    // The digest is taken on the script THIS function built, and on the holdAt the check says it
    // ran rather than recorded.plan.holdAt read again. `plan: recorded.plan`
    // below is the record's own object and is kept only for reading the result; it must never
    // be what the comparison rests on, which is the defect this fixes.
    runs.push({ runIndex: recorded.runIndex, plan: recorded.plan, sentDigest: digest({ holdAt: run.holdAt, script }), refusals: refusalsOf(run),
      rows: run.results.map(r => ({ id: r.id, status: r.status, ...(r.custodyReason ? { custodyReason: r.custodyReason } : {}) })) });
  }
  return runs;
}

// What differs between a run and its replay. An attempt sequence must be byte-identical and the
// row verdicts must match; a row that differs is a FINDING, because it depends on timing the log
// does not capture.
export function compareReplay(record, replayed) {
  // Compare the digest each side took of the script it actually sent. Comparing `r.plan` was
  // VACUOUS: replayAdaptive returned the record's own plan object, so this compared the log with
  // itself, and a replay that sent the reversed order still read identical. Two replay mutants
  // survived the sweep because of it.
  const sequenceDifferences = [];
  record.runs.forEach((original, i) => {
    const again = replayed[i];
    if (!again) { sequenceDifferences.push({ runIndex: original.runIndex, reason: 'the replay has no such run' }); return; }
    if (typeof original.sentDigest !== 'string' || typeof again.sentDigest !== 'string') {
      sequenceDifferences.push({ runIndex: original.runIndex, reason: 'a side carries no sentDigest, so nothing is established' });
    } else if (original.sentDigest !== again.sentDigest) {
      sequenceDifferences.push({ runIndex: original.runIndex, was: original.sentDigest, now: again.sentDigest });
    }
  });
  // A replay with runs the record does not have is also a difference.
  replayed.slice(record.runs.length).forEach(extra => sequenceDifferences.push({ runIndex: extra.runIndex, reason: 'the replay has a run the record does not' }));
  const sequenceIdentical = sequenceDifferences.length === 0;
  const rowDifferences = [];
  record.runs.forEach((original, i) => {
    const again = replayed[i];
    if (!again) { rowDifferences.push({ runIndex: original.runIndex, reason: 'the replay has no such run' }); return; }
    for (const row of original.rows) {
      const match = again.rows.find(r => r.id === row.id);
      if (!match || match.status !== row.status) {
        rowDifferences.push({ runIndex: original.runIndex, id: row.id, was: row.status, now: match?.status ?? 'absent' });
      }
    }
    // And in the other direction: a row the replay has that the run did not. Walking only the
    // original's rows made an invented row invisible, which a mutation sweep found.
    for (const row of again.rows) {
      if (!original.rows.some(r => r.id === row.id)) {
        rowDifferences.push({ runIndex: original.runIndex, id: row.id, was: 'absent', now: row.status });
      }
    }
  });
  return { sequenceIdentical, sequenceDifferences, rowDifferences,
    finding: sequenceIdentical && rowDifferences.length === 0 ? null
      : 'A replay from the log differed. The attempt sequence or a row verdict depends on something the log does not capture, which is a finding rather than noise.' };
}

export function sealRecord({ seed, limits, stoppedBy, attempts, runs, attemptedMap, startedAt }) {
  const notReached = Object.entries(attemptedMap).filter(([, v]) => v.attemptedCount === 0).map(([id]) => id);
  const neverBeforePause = Object.entries(attemptedMap).filter(([, v]) => v.attemptedBeforePause === 0).map(([id]) => id);
  const record = {
    schema: ADAPTIVE_SCHEMA, seed, bounds: limits, stoppedBy,
    // Fixture identity, so a replay that disagrees is visible rather than silent. The design
    // asked for fixture AND suite/policy identity; only the fixture's is available from inside
    // this module, and the suite/policy identity remains a stated deviation (DESIGN.md).
    fixture: { schema: CONTROL_TAMPER_SCHEMA, declaredCallsDigest: digest(DECLARED_CALLS), scriptDigest: digest(TAMPER_SCRIPT) },
    declaredSurfaces: DECLARED_CALLS.map(d => d.surfaceId),
    attemptCount: attempts.length, runCount: runs.length, elapsedMs: Date.now() - startedAt,
    runs, attempts,
    // Sealed with the record, read by nothing that decides anything. "attempted", not "covered".
    attemptedMap: Object.freeze(attemptedMap),
    notAttempted: notReached,
    notAttemptedBeforePause: neverBeforePause,
    limitations: [
      'This is a search over the fixture’s own declared calls. A defect reachable only through a request the fixture does not declare is invisible to it, by construction.',
      'A clean run is NOT evidence of security. It is evidence that these surfaces, in these orderings, at these pause points, were refused on this fixture version.',
      'attemptedMap says what was SENT. It is never read by a row or by the gate, and "attempted" never means "covered" or "tested safe".',
      'The adaptation reads two things and nothing else: the previous run’s refusal statuses, which are application-authored, and this harness’s OWN attempt log. A lying status can waste search budget and can never move a row, because no row reads it. The attempt log is the harness’s own record, held outside the subject, and it steers only which declared attempt comes next. Nothing from the subject’s audit table, ledger or reply is read to make a choice.',
      'Bounded, not exhaustive: notAttempted and notAttemptedBeforePause name what this run did not reach.',
      'The wall-clock and attempt bounds are checked BETWEEN RUNS, not between attempts, because a run’s ten declared calls are sent inside one control-tamper sequence this module does not drive. So maxMs can be exceeded by at most the length of one run in progress, and the design brief’s "checked between attempts" overstates it. maxAttempts is still never exceeded, because a run is only started when its whole set of calls fits.',
      'Every verdict here is the existing control-tamper rows’, with the custody they carry: the version row’s pass is held, the ledger rows’ passes are held, and the attempts row is response-level.',
      'The recordDigest seal is a plain hash with no key, so anyone can recompute it. A log that is edited consistently and resealed still verifies, and a replay of it reads identical to it. The seal shows only that the record is internally consistent, not where it came from; such an edit is caught only by comparing against the original record.',
    ],
  };
  return { ...record, recordDigest: digest(record) };
}

// What a reader sees. What was NOT reached is printed as prominently as what was.
export function summarizeAdaptive(record) {
  const lines = [`ADAPTIVE-01: ${record.runCount} run(s), ${record.attemptCount} attempt(s)${record.stoppedBy ? `, stopped by ${record.stoppedBy}` : ''}.`];
  const failed = record.runs.flatMap(r => r.rows.filter(row => row.status === 'fail').map(row => `run ${r.runIndex}: ${row.id}`));
  lines.push(failed.length ? `Rows that FAILED: ${failed.join('; ')}.` : 'No row failed on any run.');
  const held = record.runs.flatMap(r => r.rows.filter(row => row.custodyReason).map(row => row.id));
  if (held.length) lines.push(`Rows whose pass was withheld under custody: ${[...new Set(held)].join(', ')}.`);
  lines.push(`Declared surfaces attempted: ${record.declaredSurfaces.length - record.notAttempted.length} of ${record.declaredSurfaces.length}.`);
  lines.push(record.notAttempted.length ? `NOT attempted at all: ${record.notAttempted.join(', ')}.` : 'NOT attempted at all: none.');
  lines.push(record.notAttemptedBeforePause.length
    ? `NEVER attempted before the pause (so never attempted against a live control): ${record.notAttemptedBeforePause.join(', ')}.`
    : 'Never attempted before the pause: none.');
  lines.push('Attempted is not covered. A clean run is not evidence of security.');
  return lines.join('\n');
}
