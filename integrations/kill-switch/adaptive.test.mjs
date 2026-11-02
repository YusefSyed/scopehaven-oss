// ADAPTIVE-01. Owned synthetic agent desk on loopback with a scripted model stand-in; no model,
// provider or customer system, and no target option.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ADAPTIVE_SCHEMA, BOUNDS, DECLARED_CALLS, createChooser, planFrom, assertOwnedFixtureOnly,
  runAdaptive, replayAdaptive, compareReplay, summarizeAdaptive, ALLOWED_HOOKS, assertDeclaredHooks, verifyRecordSeal, boundsFrom,
} from './adaptive.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { digest } from '../../src/domain.mjs';
import { TAMPER_SCRIPT, runControlTamper, REFUSED_STATUS } from './control-tamper.mjs';

const SMALL = Object.freeze({ ...BOUNDS, maxRuns: 2, maxAttempts: 64 });
const rowsOf = runs => runs.flatMap(r => r.rows.map(row => `${row.id}:${row.status}`));
// Edit a record AND fix its seal, which is what a tamperer who read the format would do. The
// seal stops a careless edit; the sentDigest comparison is what still
// catches a replay that sends something different from a record that is internally consistent.
// Resealing is therefore not a workaround here - it is the only way to test the digest at all.
const reseal = record => { const { recordDigest, ...body } = record; return { ...body, recordDigest: digest(body) }; };

test('the declared set is the fixture’s own calls, and nothing is constructed', () => {
  const declaredInScript = TAMPER_SCRIPT.flatMap(step => step.toolCalls ?? []);
  assert.equal(DECLARED_CALLS.length, declaredInScript.length, 'one entry per declared call, no more');
  // Every generated call is IDENTICAL to a call the fixture's own script declares. This is the
  // property that makes this a search rather than an attack generator: there is no code path
  // that builds a path, method, body, header or encoding.
  for (const { call } of DECLARED_CALLS) {
    assert(declaredInScript.some(d => JSON.stringify(d) === JSON.stringify(call)), JSON.stringify(call));
  }
  // And a plan is a permutation of exactly that set: nothing added, nothing dropped.
  const plan = planFrom(createChooser(3));
  assert.deepEqual([...plan.order].sort(), DECLARED_CALLS.map(d => d.surfaceId).sort());
  const planned = plan.script.flatMap(step => step.toolCalls ?? []);
  assert.equal(planned.length, DECLARED_CALLS.length);
  for (const call of planned) assert(declaredInScript.some(d => JSON.stringify(d) === JSON.stringify(call)), JSON.stringify(call));
});

test('the origin guard is a hard error: there is no option that points this anywhere else', async () => {
  for (const key of ['origin', 'target', 'targetUrl', 'baseUrl', 'url', 'host']) {
    assert.throws(() => assertOwnedFixtureOnly({ [key]: 'http://example.test' }),
      /runs against the owned control-tamper fixture only/, key);
  }
  assert.doesNotThrow(() => assertOwnedFixtureOnly({ seed: 1 }));
  // And it refuses at the entry point, before anything is started.
  await assert.rejects(() => runAdaptive({ seed: 1, origin: 'http://example.test' }), /owned control-tamper fixture only/);
});

test('the same seed gives the same plans, and a different seed does not', () => {
  const plans = seed => { const chooser = createChooser(seed); return [planFrom(chooser), planFrom(chooser), planFrom(chooser)]; };
  assert.deepEqual(plans(42), plans(42), 'every choice comes from the seed');
  assert.notDeepEqual(plans(42), plans(43), 'and the seed actually varies them');
  assert.throws(() => createChooser(-1), /non-negative integer/);
  assert.throws(() => createChooser(1.5), /non-negative integer/);
  // A plan names its pause point rather than a timing value, so a replay cannot depend on the
  // wall clock. There is no number of milliseconds anywhere in a plan.
  const plan = planFrom(createChooser(9));
  assert.match(plan.pausePoint, /^before-step-\d+-of-\d+$/);
  assert(!JSON.stringify(plan).includes('Ms'), JSON.stringify(plan));
});

test('the bounds stop a run and the record says which one stopped it', async () => {
  // An attempt budget smaller than one pass over the declared set stops before any run.
  const tiny = await runAdaptive({ seed: 1, bounds: { ...BOUNDS, maxAttempts: DECLARED_CALLS.length - 1 } });
  assert.equal(tiny.stoppedBy, 'maxAttempts');
  assert.equal(tiny.runCount, 0, 'stopping is an outcome, not a truncated run');
  assert.equal(tiny.attemptCount, 0);
  // A zero time budget stops on the clock instead, and says so.
  const instant = await runAdaptive({ seed: 1, bounds: { ...BOUNDS, maxMs: -1 } });
  assert.equal(instant.stoppedBy, 'maxMs');
  // A run that finishes inside its budget records no stop at all.
  const whole = await runAdaptive({ seed: 5, bounds: { ...BOUNDS, maxRuns: 1 } });
  assert.equal(whole.stoppedBy, null);
  assert.equal(whole.runCount, 1);
  assert(whole.attemptCount <= BOUNDS.maxAttempts && whole.elapsedMs >= 0);
});

test('a replay from the log is byte-identical and gives the same verdicts', async () => {
  const record = await runAdaptive({ seed: 11, bounds: SMALL });
  assert.equal(record.schema, ADAPTIVE_SCHEMA);
  assert.equal(typeof record.recordDigest, 'string');
  const replayed = await replayAdaptive(record);
  const comparison = compareReplay(record, replayed);
  // The attempt sequence must match byte for byte, and every row verdict with it. A difference
  // is a FINDING, not noise: it would mean a row depends on something the log does not capture.
  assert.equal(comparison.sequenceIdentical, true, JSON.stringify(comparison));
  assert.deepEqual(comparison.rowDifferences, [], JSON.stringify(comparison.rowDifferences));
  assert.equal(comparison.finding, null);
  // The replay ignores the generator entirely: a log naming a surface the fixture does not
  // declare is refused rather than improvised.
  const tampered = { ...record, runs: [{ ...record.runs[0], plan: { ...record.runs[0].plan, order: ['not_a_declared_call:x'] } }] };
  await assert.rejects(() => replayAdaptive(reseal(tampered)), /names surfaces this fixture does not declare/);
  await assert.rejects(() => replayAdaptive({ schema: 'something-else' }), /Not an scopehaven-adaptive\/1 record/);
  // compareReplay has to DETECT a difference, not just report none on a clean run. A sweep
  // found that hardcoding "no difference" survived every test, because a clean replay has none.
  const movedVerdict = replayed.map((r, i) => (i === 0 ? { ...r, rows: r.rows.map((row, j) => (j === 0 ? { ...row, status: 'pass' } : row)) } : r));
  const moved = compareReplay(record, movedVerdict);
  assert.equal(moved.rowDifferences.length > 0, true, 'a changed verdict is a difference');
  assert.match(moved.finding, /depends on something the log does not capture, which is a finding rather than noise/);
  // A row the replay INVENTS is a difference too, in the other direction. Walking only the
  // original's rows made that invisible, which is how a generator could add its own verdict.
  const invented = replayed.map((r, i) => (i === 0 ? { ...r, rows: [...r.rows, { id: 'adaptive-says-clean', status: 'pass' }] } : r));
  const extra = compareReplay(record, invented);
  assert(extra.rowDifferences.some(d => d.id === 'adaptive-says-clean' && d.was === 'absent'), JSON.stringify(extra.rowDifferences));
  // A reordered attempt sequence is a difference as well.
  const reordered = [...replayed].reverse();
  assert.equal(compareReplay(record, reordered).sequenceIdentical, record.runs.length === 1, 'a different order is a different sequence');
});

test('a build that answers a constant fake status cannot move any row, and the static run agrees', async () => {
  // The adaptation steers on refusal statuses, and those are the application's own. This build
  // answers 200 on the owner-only admin routes and applies nothing: the status lies, the state
  // is correct. A lying status can waste search budget; it must not move a verdict.
  const hooks = { answerOkWithoutApplying: true };
  const statik = await runControlTamper({ holdAt: 2, hooks });
  const adaptive = await runAdaptive({ seed: 3, bounds: SMALL, hooks });
  // The generator SEES the lie: the statuses it read are not refusals.
  const seen = adaptive.runs.flatMap(r => Object.values(r.refusals));
  assert(seen.some(status => status !== REFUSED_STATUS), `the fake status reached the generator: ${JSON.stringify(seen)}`);
  // And it changes no verdict. Every row the static run FAILS, the adaptive run also fails or
  // holds; no row the static run fails is a pass on any adaptive run.
  const staticFails = statik.results.filter(r => r.status === 'fail').map(r => r.id);
  for (const id of staticFails) {
    for (const run of adaptive.runs) {
      const row = run.rows.find(r => r.id === id);
      if (row) assert.notEqual(row.status, 'pass', `${id} failed statically and must not pass adaptively`);
    }
  }
  // The attempts row is the one that reads the request path, so the lie is exactly what it is
  // for: it answered 200 where a refusal was owed, and that is a fail, not a pass.
  const attempts = statik.results.find(r => r.id === 'attempts-refused-and-logged');
  assert.equal(attempts.status, 'fail', JSON.stringify(attempts.observed));
  for (const run of adaptive.runs) {
    const row = run.rows.find(r => r.id === 'attempts-refused-and-logged');
    assert.notEqual(row.status, 'pass', 'nor adaptively');
  }
});

test('the record seals an attempted map that nothing reads, and the summary leads with what was missed', async () => {
  const record = await runAdaptive({ seed: 7, bounds: { ...BOUNDS, maxRuns: 3 } });
  // Every declared surface has an entry, and the fields say "attempted".
  assert.deepEqual(Object.keys(record.attemptedMap).sort(), DECLARED_CALLS.map(d => d.surfaceId).sort());
  for (const entry of Object.values(record.attemptedMap)) {
    assert.deepEqual(Object.keys(entry).sort(), ['attemptedBeforePause', 'attemptedCount', 'attemptedPausePoints', 'attemptedPositions']);
  }
  // No FIELD is labelled coverage or safe. Checked on the keys and on the summary rather than on
  // the whole JSON, because the limitations legitimately say in prose that "attempted" never
  // means "covered" or "tested safe" - a disclaimer is the opposite of the problem. My first
  // version of this assertion scanned the whole record and failed on that very sentence.
  const keysOf = value => (value === null || typeof value !== 'object' ? []
    : Array.isArray(value) ? value.flatMap(keysOf)
    : Object.keys(value).concat(Object.values(value).flatMap(keysOf)));
  const labels = keysOf(record);
  assert(!labels.some(key => /cover|safe|secure|tested/i.test(key)), labels.filter(key => /cover|safe|secure|tested/i.test(key)).join(', '));
  assert(labels.includes('attemptedMap') && labels.includes('notAttempted'), 'the fields say attempted');
  // The map is sealed with the record and read by no verdict: every row verdict comes from the
  // control-tamper rows, and the map is not among their inputs.
  assert.equal(typeof record.recordDigest, 'string');
  assert(record.limitations.some(l => /never read by a row or by the gate/.test(l)));
  assert(record.limitations.some(l => /clean run is NOT evidence of security/.test(l)));
  // And it says what its own seal cannot show: the seal is unkeyed, so a
  // consistently edited and resealed log verifies and replays identical against itself.
  assert(record.limitations.some(l => /seal shows only that the record is internally consistent, not where it came from/.test(l)),
    'the record must say what its seal cannot show');
  // The summary prints what was not reached, and says attempted is not covered.
  const summary = summarizeAdaptive(record);
  assert.match(summary, /NOT attempted at all: /);
  assert.match(summary, /Attempted is not covered\. A clean run is not evidence of security\./);
  // On a repaired build nothing fails, and the summary must not read as a pass.
  assert.match(summary, /No row failed on any run\./);
  assert.match(summary, /withheld under custody: /, 'and it says which passes were withheld');
});

test('the verdicts are the existing rows’, with the custody they already carry', async () => {
  const record = await runAdaptive({ seed: 2, bounds: { ...BOUNDS, maxRuns: 1 } });
  const ids = record.runs[0].rows.map(r => r.id);
  // The generator adds no row of its own, and removes none.
  const statik = await runControlTamper({ holdAt: 1 });
  assert.deepEqual([...ids].sort(), statik.results.map(r => r.id).sort(), 'the same rows, no more');
  // And the held ones are still held: more search cannot manufacture a pass.
  const held = record.runs[0].rows.filter(r => r.custodyReason === 'subject-writable-custody').map(r => r.id);
  assert(held.includes('control-record-version-unchanged'), JSON.stringify(record.runs[0].rows));
  assert(held.includes('ledger-holds-only-pre-pause-work'), JSON.stringify(record.runs[0].rows));
  assert(rowsOf(record.runs).every(entry => !entry.endsWith(':error')), JSON.stringify(rowsOf(record.runs)));
  // The REPLAY path adds no row either. It builds its own row list, so it needs its own check:
  // a sweep mutant that invented a row there survived until this assertion existed.
  const replayed = await replayAdaptive(record);
  assert.deepEqual(replayed[0].rows.map(r => r.id).sort(), [...ids].sort(), 'the replay reports the same rows, no more');
});

test('a replay that sends a different order is caught, not reported identical', async () => {
  // `replayAdaptive` once returned `plan: recorded.plan` - the record's
  // OWN object - so compareReplay's sequence check compared the log with itself and could never
  // differ. A replay sending the reversed order read `sequenceIdentical: true`, and two replay
  // mutants survived the sweep. The comparison is now over a digest each side takes of the
  // script it actually sent, which cannot be carried across from the record.
  const record = await runAdaptive({ seed: 3, bounds: { ...BOUNDS, maxRuns: 2, maxAttempts: 24 } });
  assert(record.runs.every(r => typeof r.sentDigest === 'string' && r.sentDigest.length > 0), 'each run records what it sent');

  const honest = await replayAdaptive(record);
  const same = compareReplay(record, honest);
  assert.equal(same.sequenceIdentical, true, JSON.stringify(same.sequenceDifferences));
  assert.deepEqual(same.sequenceDifferences, []);
  assert.equal(same.finding, null);
  // The digests are equal because both sides built the same script, not because one was copied.
  assert.deepEqual(honest.map(r => r.sentDigest), record.runs.map(r => r.sentDigest));
  // Each side digests the holdAt the check says it RAN, so the
  // record's digest has to be of the pause point its plan logs. Rebuilt here from the logged plan
  // alone, a run that paused somewhere other than its log says is visible without a replay.
  const callOf = new Map(DECLARED_CALLS.map(d => [d.surfaceId, d.call]));
  const idOf = new Map(DECLARED_CALLS.map(d => [d.call, d.surfaceId]));
  const finalStep = TAMPER_SCRIPT.find(step => step.content !== undefined);
  for (const r of record.runs) {
    const groups = Array.from({ length: r.plan.steps }, () => []);
    r.plan.order.forEach((id, i) => groups[i % r.plan.steps].push(callOf.get(id)));
    const script = [...groups.map(toolCalls => ({ toolCalls })), finalStep];
    const logged = digest({ holdAt: r.plan.holdAt, script });
    assert.equal(r.sentDigest, logged, `run ${r.runIndex}: the digest must be of the pause point the record logs`);
    // beforePause drives the attempted map and the summary's "never attempted against a live
    // control", and nothing pinned it: a mutant shifting it by one step passed every test.
    // It must name exactly the calls the check releases before
    // the pause, the steps before holdAt, which is the slice control-tamper's permittedRows takes.
    const released = script.slice(0, r.plan.holdAt - 1).flatMap(step => step.toolCalls ?? []).map(call => idOf.get(call));
    assert.deepEqual(r.plan.beforePause, released, `run ${r.runIndex}: beforePause must be the calls released before the pause`);
    assert.deepEqual(record.attempts.filter(a => a.runIndex === r.runIndex && a.beforePause).map(a => a.surfaceId).sort(), [...released].sort(),
      `run ${r.runIndex}: and so must the attempt log's beforePause flags`);
  }
  // The attempted map and the "never attempted before the pause" list are counted from the same
  // flags, so they must agree with the attempt log: a mutant that stopped counting survived.
  for (const [id, entry] of Object.entries(record.attemptedMap)) {
    assert.equal(entry.attemptedBeforePause, record.attempts.filter(a => a.surfaceId === id && a.beforePause).length, `${id}: attemptedBeforePause`);
  }
  assert.deepEqual(record.notAttemptedBeforePause, DECLARED_CALLS.map(d => d.surfaceId).filter(id => !record.attempts.some(a => a.surfaceId === id && a.beforePause)));

  // Now drive a replay from a log whose order has been reversed. Same surfaces, same counts,
  // different sequence - exactly what the old check could not see.
  const reversed = reseal({ ...record, runs: record.runs.map(r => ({ ...r, plan: { ...r.plan, order: [...r.plan.order].reverse() } })) });
  assert.notDeepEqual(reversed.runs[0].plan.order, record.runs[0].plan.order, 'the tampered log must actually differ');
  assert.equal(verifyRecordSeal(reversed), null, 'resealed, so the SEAL is not what catches this - the digest is');
  const other = await replayAdaptive(reversed);
  const differs = compareReplay(record, other);
  assert.equal(differs.sequenceIdentical, false, 'a reversed order is not byte-identical');
  assert(differs.sequenceDifferences.length >= 1, JSON.stringify(differs.sequenceDifferences));
  assert(differs.finding !== null, 'and that is a finding');

  // The PAUSE POINT is inside the digest too. Digesting the
  // script alone meant a replay that sent the same calls and paused somewhere else read
  // identical - the same shape of hole as the order above, one field along.
  const movedPause = reseal({ ...record, runs: record.runs.map(r => ({ ...r, plan: { ...r.plan, holdAt: r.plan.holdAt === 1 ? 2 : 1 } })) });
  assert.equal(verifyRecordSeal(movedPause), null, 'internally consistent, so only the digest can catch it');
  const elsewhere = await replayAdaptive(movedPause);
  const pauseDiff = compareReplay(record, elsewhere);
  assert.equal(pauseDiff.sequenceIdentical, false, 'a replay pausing at a different holdAt is not identical');
  assert(pauseDiff.finding !== null);

  // A side with no digest at all establishes nothing, rather than passing by absence.
  const stripped = honest.map(({ sentDigest, ...rest }) => rest);
  assert.equal(compareReplay(record, stripped).sequenceIdentical, false);
  // And a replay with a run the record does not have is a difference too.
  assert.equal(compareReplay(record, [...honest, { ...honest[0], runIndex: 99 }]).sequenceIdentical, false);
});

test('the record seal is checked, not merely computed', async () => {
  // recordDigest was recomputable but nothing read it, which is a seal in name only.
  const record = await runAdaptive({ seed: 4, bounds: { ...BOUNDS, maxRuns: 1, maxAttempts: 12 } });
  const { recordDigest, ...body } = record;
  assert.equal(typeof recordDigest, 'string');
  assert.equal(recordDigest, digest(body), 'the seal must match the record it ships with');
  // An edited record no longer matches its own seal.
  assert.notEqual(digest({ ...body, runs: [] }), recordDigest);
  assert.notEqual(digest({ ...body, seed: body.seed + 1 }), recordDigest);
});

test('the adaptation reads statuses and its own log, and nothing of the subject’s', async () => {
  // A mutant that steered on `run.report.audit.length` survived, because
  // nothing pinned WHICH signals the search may read. `silentRefusal` is the probe that settles
  // it: every attempt is still refused with the same status, and the desk records none of them,
  // so the audit differs while the statuses do not. A search reading the subject's audit would
  // diverge; one reading only statuses and its own coverage log cannot.
  const bounds = { ...BOUNDS, maxRuns: 3, maxAttempts: 36 };
  const quiet = await runAdaptive({ seed: 7, bounds });
  const unlogged = await runAdaptive({ seed: 7, bounds, hooks: { silentRefusal: true } });
  assert.deepEqual(unlogged.runs.map(r => r.plan), quiet.runs.map(r => r.plan),
    'the two builds differ only in what the audit holds, so the plans must be identical');
  assert.deepEqual(unlogged.attempts, quiet.attempts, 'and so must the attempt log');
});

test('hooks are allow-listed, so a caller cannot redirect the desk’s storage', async () => {
  // `hooks` is spread into startAgentDesk, so `hooks.dbPath` had the desk create a SQLite
  // file wherever the caller said.
  await assert.rejects(() => runAdaptive({ seed: 1, hooks: { dbPath: '/tmp/anywhere.db' } }), /does not accept dbPath/);
  await assert.rejects(() => runAdaptive({ seed: 1, hooks: { modelBaseUrl: 'http://example.test' } }), /does not accept modelBaseUrl/);
  await assert.rejects(() => replayAdaptive(reseal({ schema: ADAPTIVE_SCHEMA, runs: [] }), { hooks: { tokens: {} } }), /does not accept tokens/);
  assert.doesNotThrow(() => assertDeclaredHooks({ controlWritable: true, silentRefusal: true, lockExclusiveMs: 0 }));
  // The list is only as good as its spelling, so every name must exist in the desk's own
  // signature. A typo here would silently stop allowing a hook that does work.
  const deskSource = readFileSync(fileURLToPath(new URL('./agent-desk.mjs', import.meta.url)), 'utf8');
  const start = deskSource.indexOf('export async function startAgentDesk({');
  assert(start > 0, 'the desk signature must be findable, or this check proves nothing');
  const signature = deskSource.slice(start, deskSource.indexOf('}) {', start));
  assert(signature.includes('dbPath'), 'the slice must actually cover the parameter list');
  for (const name of ALLOWED_HOOKS) assert(new RegExp(`\\b${name}\\b`).test(signature), `${name} is not a startAgentDesk parameter`);
  for (const name of ['dbPath', 'modelBaseUrl', 'tokens']) assert(!ALLOWED_HOOKS.includes(name), `${name} must never be allow-listed`);
});

test('a replay refuses a record that does not match its own seal', async () => {
  // A recordDigest that a test recomputes is not enough if the MODULE never reads it, since
  // replayAdaptive would drive a replay from an edited log and then compare against it. A
  // replay is the reviewer's instrument, so it has to refuse a record it cannot vouch for.
  const record = await runAdaptive({ seed: 11, bounds: { ...BOUNDS, maxRuns: 1, maxAttempts: 12 } });
  assert.equal(verifyRecordSeal(record), null, 'the record it just sealed verifies');
  await assert.doesNotReject(() => replayAdaptive(record));

  const edited = { ...record, runs: record.runs.map(r => ({ ...r, plan: { ...r.plan, order: [...r.plan.order].reverse() } })) };
  assert.match(String(verifyRecordSeal(edited)), /does not match its own recordDigest/);
  await assert.rejects(() => replayAdaptive(edited), /will not replay a record it cannot vouch for/);
  const { recordDigest, ...unsealed } = record;
  await assert.rejects(() => replayAdaptive({ ...unsealed }), /carries no recordDigest/);
});

test('the adaptation is blind to the audit COUNT, not just to whether it is empty', async () => {
  // The earlier probe was silentRefusal, which empties the audit entirely, so a mutant steering on
  // `audit.length > 3` survived: it reads the same on a full audit and on any audit above the
  // threshold. silentSurfaces refuses WITHOUT RECORDING on only the named surface, so the
  // statuses stay identical while the number of records changes by a controllable amount. Three
  // different counts, one seed.
  const bounds = { ...BOUNDS, maxRuns: 3, maxAttempts: 36 };
  const runs = {
    full: await runAdaptive({ seed: 7, bounds }),
    noTool: await runAdaptive({ seed: 7, bounds, hooks: { silentSurfaces: ['tool'] } }),
    none: await runAdaptive({ seed: 7, bounds, hooks: { silentRefusal: true } }),
  };
  // The precondition, asserted rather than assumed: identical statuses, and an audit that really
  // does differ - visible in the attempts row, which grades the records.
  const attemptsRowOf = record => record.runs.map(r => r.rows.find(row => row.id === 'attempts-refused-and-logged')?.status);
  assert.deepEqual(attemptsRowOf(runs.noTool), attemptsRowOf(runs.full).map(() => 'fail'), 'silentSurfaces must leave records missing');
  assert.notDeepEqual(attemptsRowOf(runs.full), attemptsRowOf(runs.noTool), 'or the builds do not differ in what the audit holds');
  for (const key of ['noTool', 'none']) {
    assert.deepEqual(runs[key].runs.map(r => r.refusals), runs.full.runs.map(r => r.refusals), `${key}: the statuses must be identical`);
    assert.deepEqual(runs[key].runs.map(r => r.plan), runs.full.runs.map(r => r.plan), `${key}: so the plans must be too`);
    assert.deepEqual(runs[key].attempts, runs.full.attempts, `${key}: and the attempt log`);
  }
});

test('the adaptation is blind to the audit count when the statuses are NOT refusals', async () => {
  // The mutant `lastRefusals = audit.length > 3 ? refusals : null`
  // changes nothing while every status is a refusal, because null and an all-refused map both
  // read as allRefused. Every build in the test above refuses everything, so that mutant was
  // equivalent there and survived. answerOkWithoutApplying answers 200 on the owner-only routes;
  // adding silentRefusal keeps those statuses and drops the desk's records, so the audit count
  // moves while no status does.
  const logged = { answerOkWithoutApplying: true };
  const unlogged = { answerOkWithoutApplying: true, silentRefusal: true };
  // The precondition, asserted rather than assumed: the same statuses, some of them not
  // refusals, and audits of different length.
  const a = await runControlTamper({ holdAt: 2, hooks: logged });
  const b = await runControlTamper({ holdAt: 2, hooks: unlogged });
  assert.deepEqual(b.report.attemptStatuses, a.report.attemptStatuses, 'the statuses must not differ');
  assert(Object.values(a.report.attemptStatuses).some(s => s !== REFUSED_STATUS), 'some status must not be a refusal, or the pair pins nothing');
  assert.notEqual(b.report.audit.length, a.report.audit.length, 'the audits must differ in length');
  const bounds = { ...BOUNDS, maxRuns: 3, maxAttempts: 36 };
  const full = await runAdaptive({ seed: 7, bounds, hooks: logged });
  const quiet = await runAdaptive({ seed: 7, bounds, hooks: unlogged });
  assert.deepEqual(quiet.runs.map(r => r.refusals), full.runs.map(r => r.refusals), 'the statuses the generator read are identical');
  assert.deepEqual(quiet.runs.map(r => r.plan), full.runs.map(r => r.plan), 'so the plans must be too');
  assert.deepEqual(quiet.attempts, full.attempts, 'and the attempt log');
});

test('the bounds are ceilings and must be finite numbers, so a caller cannot raise or switch one off', async () => {
  // `{ ...BOUNDS, ...bounds }` once accepted 9 runs and 90 attempts, and a
  // NaN switched a check off while the record saved it as null. The design calls these hard bounds.
  for (const key of Object.keys(BOUNDS)) {
    assert.throws(() => boundsFrom({ [key]: BOUNDS[key] + 1 }), new RegExp(`bound ${key} is a ceiling of ${BOUNDS[key]}`), key);
    for (const bad of [NaN, Infinity, -Infinity, '10', null, undefined]) {
      assert.throws(() => boundsFrom({ [key]: bad }), new RegExp(`bound ${key} must be a finite number`), `${key}: ${String(bad)}`);
    }
  }
  assert.throws(() => boundsFrom({ maxAttempt: 10 }), /has no maxAttempt bound/, 'a misspelt bound is not silently ignored');
  for (const bad of [null, [], 'small', 7]) assert.throws(() => boundsFrom(bad), /bounds must be an object/, JSON.stringify(bad));
  // At or below the ceilings is fine, and the record carries exactly what was used.
  assert.deepEqual(boundsFrom(BOUNDS), { ...BOUNDS });
  assert.deepEqual(boundsFrom({ maxRuns: 2, maxMs: -1 }), { ...BOUNDS, maxRuns: 2, maxMs: -1 });
  assert.deepEqual(boundsFrom(undefined), { ...BOUNDS }, 'omitted is the defaults');
  // And the entry point refuses before anything starts.
  await assert.rejects(() => runAdaptive({ seed: 1, bounds: { ...BOUNDS, maxAttempts: 90 } }), /bound maxAttempts is a ceiling of 64/);
  await assert.rejects(() => runAdaptive({ seed: 1, bounds: { ...BOUNDS, maxMs: NaN } }), /bound maxMs must be a finite number/);
  const used = await runAdaptive({ seed: 1, bounds: { ...BOUNDS, maxAttempts: DECLARED_CALLS.length - 1 } });
  assert.deepEqual(used.bounds, { ...BOUNDS, maxAttempts: DECLARED_CALLS.length - 1 }, 'every bound in the record is a number');
});

test('hooks must be an object, and says so instead of throwing a TypeError', () => {
  for (const bad of [null, [], 'controlWritable', 7]) {
    assert.throws(() => assertDeclaredHooks(bad), /hooks must be an object/, `hooks: ${JSON.stringify(bad)}`);
  }
  assert.doesNotThrow(() => assertDeclaredHooks(undefined), 'omitted is still fine');
});
