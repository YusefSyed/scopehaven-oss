// Owned loopback fixtures only: a synthetic access desk, a fake payment step
// and a hold gate. No models, providers, customer systems or network egress.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CASES, caseSequence, casesHash, runCase, runAccessChangeCases, revokeClosureResults } from './cases.mjs';
import { REPAIRS, startAccessDesk } from './desk.mjs';
import { validateSequence } from '../sequences/sequence.mjs';

// Pinned so that any change to a case definition (steps, assertions, guards,
// gate rules, expectations) is deliberate and reviewed.
const CASES_HASH = 'e4e62046390e1166ba2797a830c6a7fa3c02f3a099c096f22356639bd4d7c0e0';
// The eight cases before AC-RETRY-UNMARKED keep the hash the guard coverage matrix recorded (d2c637169da8).
const EIGHT_CASES_HASH = 'd2c637169da801d155475936c7bd979236eb8d6b8341a0c97167267937b9d75d';
const byId = report => Object.fromEntries(report.rows.map(row => [row.id, row]));
const result = (row, id) => row.results.find(r => r.id === id);
// Custody (src/custody.mjs): the forbidden variants' absences come from the desk's own audit table, a record the
// app writes, so in these boundary assertions a pass is held at inconclusive. The report keeps the reason in the basis.
const CUSTODY_BASIS = /Custody: every observer that decided this keeps a record the application can write, so it cannot support a pass\.$/;
const custodyHeld = r => r.status === 'inconclusive' && r.verdict === 'inconclusive' && CUSTODY_BASIS.test(r.basis);
let baseline, repaired;
test.before(async () => { baseline = await runAccessChangeCases({ recheckAtCommit: false }); repaired = await runAccessChangeCases({ recheckAtCommit: true }); });

test('every case is a valid sequence judged by the audit table, with exact-count controls and declared outcomes', () => {
  assert.equal(CASES.length, 9);
  assert.equal(casesHash(), CASES_HASH);
  assert.equal(casesHash(CASES.filter(c => c.id !== 'AC-RETRY-UNMARKED')), EIGHT_CASES_HASH);
  for (const def of CASES) for (const twin of [false, true]) {
    const seq = validateSequence(caseSequence(def, { twin }));
    for (const a of seq.assertions) {
      assert.equal(a.effect.select.source, 'sql-audit-table', `${a.id}: absence and counts come from the authoritative audit table`);
      assert(!Object.hasOwn(a.effect.select, 'actor'), `${a.id}: forbidden commits are selected by ticket, under any principal`);
      if (a.severity === 'control') assert.equal(a.effect.kind, 'effect.count', `${a.id}: a control pins an exact count`);
      if (twin) assert.equal(a.severity, 'control');
    }
    // Every access change, approval and drain is a precondition.
    for (const step of seq.steps) if (step.request && /suspend|regrant|drain|approve/.test(step.request.path)) assert(seq.steps.some(s => s.expectStatus?.request === step.request.id), `${seq.id}: ${step.request.id} needs expectStatus`);
    assert(seq.steps.some(s => s.sleep > 0) && seq.steps.at(-1).mark === 'after', `${seq.id} settles before its last mark`);
    assert(def.guards.length >= 1 && def.guards.every(g => REPAIRS.includes(g)));
    // Each twin declares a positive outcome, so a build that commits nothing cannot pass it.
    if (twin) assert(Object.values(def.expect(true)).some(n => n > 0), def.id);
  }
});

test('baseline: every case fails on its forbidden variant, confirmed by the desk\'s own tables, while every twin commits', () => {
  const rows = byId(baseline);
  assert.deepEqual(baseline.counts, { pass: 0, fail: 9, inconclusive: 0, error: 0 });
  for (const def of CASES) {
    const row = rows[def.id];
    assert.equal(row.status, 'fail', def.id);
    assert.deepEqual(row.aborted, { forbidden: null, twin: null }, def.id);
    assert.equal(result(row, def.id).status, 'fail', def.id);
    // The split: an EXTRA refund is the prohibition, so it lands on the boundary row at
    // critical severity. A missing allowed one would land on -WORK as a control failure, which
    // is the distinction an earlier version collapsed into one row.
    assert.equal(result(row, `${def.id}-FINAL-STATE`).status, 'fail', def.id);
    assert.equal(result(row, `${def.id}-FINAL-STATE`).severity, 'critical', def.id);
    assert.match(result(row, `${def.id}-FINAL-STATE`).basis, /^More refunds than declared/, def.id);
    for (const r of row.results.filter(r => r.severity === 'control')) assert.equal(r.status, 'pass', `${def.id} ${r.id}`);
    // Request-level refusals hold in every build.
    for (const refusal of def.refusals?.(false) ?? []) assert.equal(result(row, refusal.id).status, 'pass', refusal.id);
  }
});

test('repaired: nothing fails; every twin, same-run control and final state passes, and custody holds each audit-only absence', () => {
  assert.deepEqual(repaired.counts, { pass: 0, fail: 0, inconclusive: 9, error: 0 });
  for (const row of repaired.rows) {
    assert.equal(row.status, 'inconclusive', row.id);
    // Only the forbidden variant's own audit-table assertions are held; everything else passes as before.
    // A FINAL-STATE row that asserts an ABSENCE is a boundary row, so its
    // pass is held under custody like any other. The exclusion here used to let a boundary
    // pass resting on the desk's own tables through, because severity followed the outcome.
    // A boundary FINAL-STATE row is held on a twin run too: the question it asks (no refund
    // beyond the declared outcome) is a prohibition either way, and the desk's own tables are
    // what answer it.
    for (const r of row.results) assert.ok(r.status === 'pass' || (custodyHeld(r) && r.severity !== 'control'
      && (!r.id.includes('-TWIN') || r.id.endsWith('-FINAL-STATE'))), `${row.id} ${r.id}: ${r.status} ${r.basis}`);
    assert.ok(custodyHeld(result(row, row.id)), row.id);
  }
  assert.deepEqual(repaired.build.repairs, Object.fromEntries(REPAIRS.map(r => [r, true])));
  assert.deepEqual(baseline.build.repairs, Object.fromEntries(REPAIRS.map(r => [r, false])));
  for (const row of repaired.rows) assert.equal(row.desk.address, '127.0.0.1');
});

test('removing one guard fails exactly the cases that guard protects', async () => {
  for (const guard of REPAIRS) {
    const report = await runAccessChangeCases({ recheckAtCommit: true, repairs: { [guard]: false } });
    assert.equal(report.build.repairs[guard], false);
    for (const row of report.rows) {
      const def = CASES.find(c => c.id === row.id);
      // A case fails only when every guard it lists is gone; AC-RETRY lists two (layered defence).
      // The cases it does not protect read inconclusive, not pass: custody holds their audit-only absences.
      assert.equal(row.status, def.guards.every(g => g === guard) ? 'fail' : 'inconclusive', `${guard} removed: ${row.id}`);
    }
  }
  const retry = CASES.find(c => c.id === 'AC-RETRY');
  const both = await runAccessChangeCases({ recheckAtCommit: true, repairs: { idempotentRetry: false, commitRecheck: false }, cases: [retry] });
  assert.equal(both.rows[0].status, 'fail');
  assert.equal(result(both.rows[0], 'AC-RETRY').status, 'fail');
});

test('idempotentRetry has a case of its own: AC-RETRY-UNMARKED fails without it, while AC-RETRY does not depend on it', async () => {
  // The guard coverage matrix found idempotentRetry covered by no case: AC-RETRY's results are the
  // same with the guard on or off. The guard does deduplicate AC-RETRY's retry, but its crash comes
  // after the approval is marked used, so with the guard removed the commit-time recheck refuses
  // the retry instead: the guard is redundant there. AC-RETRY-UNMARKED's crash loses the mark, the
  // recheck passes the retry, and only the job's idempotency key stops it.
  const cases = ['AC-RETRY', 'AC-RETRY-UNMARKED'].map(id => CASES.find(c => c.id === id));
  const on = await runAccessChangeCases({ recheckAtCommit: true, cases });
  const off = await runAccessChangeCases({ recheckAtCommit: true, repairs: { idempotentRetry: false }, cases });
  assert.deepEqual(on.rows.map(r => r.status), ['inconclusive', 'inconclusive']);
  const statuses = row => row.results.map(r => [r.id, r.status]);
  assert.deepEqual(statuses(off.rows[0]), statuses(on.rows[0]), 'AC-RETRY reads the same either way: the guard is redundant there');
  assert.equal(off.rows[1].status, 'fail');
  // The second refund is seen twice over: in the audit count and in the desk's own refunds table.
  assert.deepEqual(off.rows[1].results.filter(r => r.status === 'fail').map(r => r.id).sort(), ['AC-RETRY-UNMARKED', 'AC-RETRY-UNMARKED-FINAL-STATE']);
  assert.match(result(off.rows[1], 'AC-RETRY-UNMARKED-FINAL-STATE').basis, /T-1: 2 of 1/);
  // Deduplication does not swallow other work: with the guard on, another user's job on another ticket in the same drain still commits.
  assert.equal(result(on.rows[1], 'AC-RETRY-UNMARKED-OTHER').status, 'pass');
  assert.equal(result(on.rows[1], 'AC-RETRY-UNMARKED-FINAL-STATE-WORK').status, 'pass');
});

test('a build that blocks everything never passes: its controls fail', async () => {
  const report = await runAccessChangeCases({ recheckAtCommit: true, hooks: { overBlock: true } });
  for (const row of report.rows) assert.notEqual(row.status, 'pass', row.id);
  assert.equal(result(byId(report)['AC-LATE-REVOKE'], 'AC-LATE-REVOKE-TWIN').status, 'fail');
});

test('a commit the audit table misses is still caught by the final-state check', async () => {
  const late = CASES.find(c => c.id === 'AC-LATE-REVOKE');
  const run = await runCase(late, { recheckAtCommit: false, hooks: { auditCommits: false } });
  // The audit table saw nothing, so the effect rules alone would pass it: exactly the self-report custody refuses to rest a pass on.
  assert.ok(custodyHeld(run.results.find(r => r.id === 'AC-LATE-REVOKE')), 'the audit table saw nothing');
  const final = run.results.find(r => r.id === 'AC-LATE-REVOKE-FINAL-STATE');
  assert.equal(final.status, 'fail'); assert.equal(final.severity, 'critical');
  assert.match(final.basis, /More refunds than declared \(T-1: 1 of 0\)/);
});

test('an access change that did not take effect aborts the run and is never a pass', async () => {
  // The suspension is sent by the agent itself, so the app refuses it (403).
  const queued = CASES.find(c => c.id === 'AC-QUEUED');
  const broken = { ...queued, steps: twin => queued.steps(twin).map(step => step.request?.path === '/api/admin/suspend' ? { request: { ...step.request, actorId: 'sam' } } : step) };
  for (const recheckAtCommit of [false, true]) {
    const run = await runCase(broken, { recheckAtCommit });
    assert.equal(run.aborted, 'precondition-failed:suspend-agent-sam');
    assert(run.results.every(r => r.status !== 'pass'), JSON.stringify(run.results.map(r => r.status)));
  }
  const report = await runAccessChangeCases({ recheckAtCommit: true, cases: [broken] });
  assert.notEqual(report.rows[0].status, 'pass');
});

test('the desk binds loopback, refuses foreign hosts and malformed input, and checks its payment origin', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-access-desk-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  await assert.rejects(startAccessDesk({ dbPath: join(dir, 'x.db'), paymentsUrl: 'http://example.com:80', tokens: {} }), /127\.0\.0\.1/);
  const app = await startAccessDesk({ dbPath: join(dir, 'desk.db'), paymentsUrl: 'http://127.0.0.1:9', tokens: { 'owner-olga': 'tok' } });
  t.after(() => app.stop());
  const port = new URL(app.origin).port;
  const send = (headers, body) => new Promise((resolve, reject) => {
    const r = request({ host: '127.0.0.1', port, method: 'POST', path: '/api/admin/suspend', headers: { Authorization: 'Bearer tok', 'Content-Type': 'application/json', ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    r.on('error', reject); r.end(body);
  });
  assert.equal(app.address, '127.0.0.1');
  assert.equal(await send({ Host: 'evil.example' }, '{}'), 403);
  assert.equal(await send({ Origin: 'http://evil.example' }, '{}'), 403);
  assert.equal(await send({}, 'null'), 400);
  assert.equal(await send({}, '{bad'), 400);
  assert.equal(await send({}, JSON.stringify({ userId: 'x'.repeat(20000) })), 413);
  assert.equal(await send({}, JSON.stringify({ userId: 'agent-sam' })), 200);
});

test('an audit row without a refund fails every control, and a lone audited forbidden commit is conflicting', async () => {
  const repairedNoInsert = await runAccessChangeCases({ recheckAtCommit: true, hooks: { insertRefunds: false } });
  for (const row of repairedNoInsert.rows) {
    assert.notEqual(row.status, 'pass', row.id);
    assert.match(result(row, `${row.id}-TWIN-FINAL-STATE-WORK`).basis, /^Fewer refunds than declared/, row.id);
  }
  const late = CASES.find(c => c.id === 'AC-LATE-REVOKE');
  const run = await runCase(late, { recheckAtCommit: false, hooks: { insertRefunds: false } });
  const forbidden = run.results.find(r => r.id === 'AC-LATE-REVOKE');
  assert.equal(forbidden.verdict, 'conflicting'); assert.equal(forbidden.status, 'inconclusive');
});

test('work left in a non-terminal state is unsettled and never a pass', async () => {
  const queued = CASES.find(c => c.id === 'AC-QUEUED');
  for (const recheckAtCommit of [false, true]) {
    const report = await runAccessChangeCases({ recheckAtCommit, hooks: { parkRevokedJobs: true }, cases: [queued] });
    const final = result(report.rows[0], 'AC-QUEUED-FINAL-STATE-WORK');
    assert.equal(final.status, 'inconclusive'); assert.match(final.basis, /not in a terminal state/);
    // The WORK row's claim is unchanged: it asks whether the declared work FINISHED, and a
    // parked job leaves that genuinely unknown. What changed with the closure row is the case
    // verdict. The parked job also means the revocation never CLOSED, which the closure row decides
    // as a fail, and a fail outranks an inconclusive. Without it the case read `inconclusive`, so a
    // build that leaves a revoked principal's work able to run looked the same as a reading the
    // harness could not take - the conflation the closure row exists to end.
    assert.equal(report.rows[0].status, 'fail');
    const closure = result(report.rows[0], 'AC-QUEUED-REVOKE-CLOSE');
    assert.equal(closure.status, 'fail', closure.basis);
    // And the fail comes from closure, not from the unsettled-work row: the two claims stay apart.
    assert.equal(report.rows[0].results.filter(r => r.status === 'fail').map(r => r.id).join(','), 'AC-QUEUED-REVOKE-CLOSE');
  }
});

test('a failed request-level refusal is reported as a fail, not an aborted run', async () => {
  const report = await runAccessChangeCases({ recheckAtCommit: true, hooks: { requestLevelChecks: false }, cases: CASES.filter(c => c.refusals) });
  for (const row of report.rows) {
    assert.equal(row.status, 'fail', row.id);
    assert.deepEqual(row.aborted, { forbidden: null, twin: null }, row.id);
  }
  assert.equal(result(byId(report)['AC-LATE-REVOKE'], 'AC-LATE-REVOKE-FRESH').status, 'fail');
  assert.equal(result(byId(report)['AC-TARGET'], 'AC-TARGET-OTHER-USER').status, 'fail');
  assert.equal(result(byId(report)['AC-TARGET'], 'AC-TARGET-OTHER-USER-QUEUED').status, 'fail');
});

test('a run that fails during setup or validation leaves no listener behind', async () => {
  const servers = () => process.getActiveResourcesInfo().filter(r => r === 'TCPServerWrap').length;
  // Closed listeners leave the handle list on a later turn of the event loop, so settle before counting.
  const settled = async () => { let last = -1; for (let i = 0; i < 40 && servers() !== last; i++) { last = servers(); await new Promise(resolve => setTimeout(resolve, 50)); } return servers(); };
  const before = await settled(), late = CASES.find(c => c.id === 'AC-LATE-REVOKE');
  await assert.rejects(runCase({ ...late, gateRules: [{ id: 'bad rule!', pathPrefix: '/x' }] }), /gate rule/);
  await assert.rejects(runCase({ ...late, steps: () => [{ unknownStep: true }] }), /Invalid sequence/);
  assert(await settled() <= before);
});

test('a FINAL-STATE row is a boundary row when it asserts an absence, and its pass is held', async () => {
  // An earlier version reasoned that the only verdict resting on the desk's own tables was a control, so
  // custody's role rule let it keep its pass. That argument was circular: severity was derived
  // FROM the outcome, so a passing row was a control by construction and the loop that checked
  // it was empty. Severity now comes from what the row asserts.
  const report = await runAccessChangeCases({ recheckAtCommit: true });
  // Both rows, deliberately: `endsWith('-FINAL-STATE')` excludes '-FINAL-STATE-WORK', so after
  // the split this selector held boundary rows ONLY and the control loop below was empty by
  // construction - the same mistake the code once made, repeated here in the test that
  // was meant to catch it.
  const finals = report.rows.flatMap(row => row.results.filter(r => /-FINAL-STATE(-WORK)?$/.test(r.id)));
  const controls = finals.filter(r => r.id.endsWith('-FINAL-STATE-WORK'));
  assert(finals.length >= 16, `both rows on every case: ${finals.length}`);
  assert(controls.length >= 8, `the control rows: ${controls.length}`);
  for (const r of finals) assert.equal(r.custody, 'subject-writable', `${r.id} must say whose record decided it`);
  for (const r of controls) assert.equal(r.severity, 'control', `${r.id} asserts allowed use`);
  // The boundary ones: a forbidden run, or any ticket declared at 0. None may PASS.
  const boundary = finals.filter(r => r.id.endsWith('-FINAL-STATE'));
  assert(boundary.length >= 1, 'the assertion below must not be empty by construction');
  for (const r of boundary) {
    assert.notEqual(r.status, 'pass', `${r.id} asserts an absence on the app's own tables`);
    if (r.status === 'inconclusive') {
      assert.equal(r.custodyReason, 'subject-writable-custody', r.id);
      assert.match(r.basis, /cannot support a pass/, r.id);
    }
  }
  // AC-LATE-REVOKE's forbidden run is the case in point: "no refunds, none declared".
  const named = finals.find(r => r.id === 'AC-LATE-REVOKE-FINAL-STATE');
  assert.equal(named.severity, 'critical', 'an absence is a boundary claim, whatever the outcome');
  assert.equal(named.status, 'inconclusive', named.basis);
  // A control keeps its verdict and states the limit instead. The guard is the point: this loop
  // asserted nothing for two rounds because its input was empty.
  const passingControls = controls.filter(r => r.status === 'pass');
  assert(passingControls.length >= 1, 'the assertion below must not be empty by construction');
  for (const r of passingControls) {
    assert.match(r.basis, /Allowed-use controls keep their verdicts and carry custody as a tag only/, r.id);
    // And it must not read like a count comparison: a forbidden run shows the control passing
    // beside the boundary row's fail on the SAME numbers, so "Refunds match (T-1: 4 of 0)" read
    // as a contradiction. It asserts nothing declared went missing.
    assert.match(r.basis, /No declared refund is missing and every job reached a terminal state/, r.id);
    assert(!/Refunds match/.test(r.basis), `${r.id}: a passing control must not claim the counts match`);
  }
  // And a fail is untouched: custody withholds passes, it does not excuse fails.
  for (const r of finals.filter(r => r.status === 'fail'))
    assert(!/cannot support a pass/.test(r.basis), `${r.id}: a fail is not tagged as a withheld pass`);
});

test('a refusal row is a response contract, paired with a row that decides what changed', async () => {
  // The status is the application's own answer, observed first-hand. It
  // decides a response contract, never that no effect happened, so it keeps its verdict but is
  // not tagged independent and is never a clean headline on its own.
  const report = await runAccessChangeCases({ recheckAtCommit: true });
  const refusals = report.rows.flatMap(row => row.results.filter(r => r.decides === 'response-contract'));
  assert(refusals.length >= 1, `the refusal rows: ${refusals.length}`);
  for (const r of refusals) {
    assert.equal(r.custody, 'subject-writable', `${r.id}: the app authors its own status`);
    assert.match(r.basis, /whether anything CHANGED is decided by the effect and final-state rows/, r.id);
  }
  // Every refusal row sits in a row that also carries a state or effect row, so a passing
  // refusal is never the only thing a reader sees.
  for (const row of report.rows) {
    if (!row.results.some(r => r.decides === 'response-contract')) continue;
    assert(row.results.some(r => r.id.endsWith('-FINAL-STATE')), `${row.id} must pair its refusals with a state row`);
  }
  // And a case whose state row is held does not headline as clean.
  for (const row of report.rows) {
    const heldHere = row.results.some(r => r.custodyReason === 'subject-writable-custody');
    if (heldHere) assert.notEqual(row.status, 'pass', `${row.id} has a held row, so it cannot headline clean`);
  }
});

// --- Revocation closure --------------------------------------------------------------------
// A fake case whose steps declare a revoke, so the row applies. Nothing here touches a desk:
// these are the Def. 5 Indeterminate cases, and no build can produce an unreadable table or a
// contradicting pair of its own records on demand.
const REVOKING_DEF = { id: 'FAKE', steps: () => [{ request: { path: '/api/admin/suspend' } }] };
const QUIET_DEF = { id: 'FAKE', steps: () => [{ request: { path: '/api/admin/approve' } }] };
const closureState = over => ({ refunds: {}, pendingJobs: 0, closure: {
  users: [{ id: 'agent-sam', suspended: true, grantsVersion: 2 }],
  openJobs: [], revocations: [{ actor: 'owner-olga', action: 'user.suspend', resource: 'users/agent-sam' }], unreadTables: [], ...over } });
const oneRow = (state, aborted = null, def = REVOKING_DEF) => {
  const rows = revokeClosureResults(def, false, state, aborted);
  assert.equal(rows.length, 1, `expected exactly one row, got ${rows.length}`);
  return rows[0];
};

test('a parked revoked job is not closed, and that is a fail, not an inconclusive', async () => {
  // The defect: the worker parks a suspended user's job as 'retry', so it keeps the revoked
  // grant and can still run. It landed in pendingJobs and read `inconclusive` - the same as a
  // reading the harness could not take. Only QUIESCENT certifies release (arXiv 2609.21284 p.8).
  const parked = await runAccessChangeCases({ recheckAtCommit: true, hooks: { parkRevokedJobs: true } });
  const rows = parked.rows.flatMap(r => r.results.filter(x => x.id.endsWith('-REVOKE-CLOSE')));
  assert(rows.length >= 6, `the revoking cases each get a row: ${rows.length}`);
  const queued = rows.find(r => r.id === 'AC-QUEUED-REVOKE-CLOSE');
  assert.equal(queued.status, 'fail', queued.basis);
  assert.equal(queued.severity, 'critical', 'an open carrier is a possible forbidden continuation');
  // Named per identity, with the version comparison that makes it RETIRED authority, not merely
  // open work (p.17: tokens are exact identities, not an aggregate counter).
  assert.match(queued.basis, /job \d+ \(agent-sam, status retry, grants v1 < v2\)/);
  // The allowed-use control is untouched: a user who kept access still gets their refund.
  const control = parked.rows.find(r => r.id === 'AC-QUEUED').results.find(r => r.id === 'AC-QUEUED-OTHER');
  assert.equal(control.status, 'pass', `${control.id}: ${control.basis}`);
});

test('closure on the app’s own tables can fail but never pass', async () => {
  const repaired = await runAccessChangeCases({ recheckAtCommit: true });
  const rows = repaired.rows.flatMap(r => r.results.filter(x => x.id.endsWith('-REVOKE-CLOSE')));
  assert(rows.length >= 6, `${rows.length} rows`);
  for (const row of rows) {
    assert.notEqual(row.status, 'pass', `${row.id}: both deciding tables are the app's own`);
    assert.equal(row.custody, 'subject-writable', row.id);
    assert.equal(row.custodyReason, 'subject-writable-custody', `${row.id}: a withheld pass says so`);
    assert.match(row.basis, /cannot support a pass/, row.id);
  }
  // And no row at all where nothing was revoked: the twins declare no suspend.
  assert.deepEqual(repaired.rows.flatMap(r => r.results.filter(x => x.id.includes('-TWIN-REVOKE-CLOSE'))), []);
  assert.deepEqual(revokeClosureResults(QUIET_DEF, false, closureState(), null), [], 'no revoke declared, no claim made');
});

test('a real evidence gap stays inconclusive, and is distinguishable from a withheld pass', () => {
  // Every case below is Indeterminate (Def. 5). What makes them different from the withheld
  // pass is that a withheld pass carries custodyReason and they do not - so "we could not see"
  // is never reported as "closed, but held".
  const gap = row => { assert.equal(row.status, 'inconclusive', row.basis);
    assert.equal(row.custodyReason, undefined, `a gap is not a withheld pass: ${row.basis}`); return row; };

  // A withheld pass, for contrast.
  const held = oneRow(closureState());
  assert.equal(held.custodyReason, 'subject-writable-custody');

  // An unreadable table is not an empty one.
  assert.match(gap(oneRow(closureState({ openJobs: null, unreadTables: ['jobs'] }))).basis, /Could not read jobs/);
  // A revoke the sequence performed and the desk never recorded: a missing fence record.
  assert.match(gap(oneRow(closureState({ revocations: [] }))).basis, /recorded no user\.suspend/);
  // The desk logged a revoke but its grants counter never moved: its own records disagree.
  assert.match(gap(oneRow(closureState({ users: [{ id: 'agent-sam', suspended: true, grantsVersion: 1 }] }))).basis, /the two records conflict/);
  // A run that stopped early answers nothing.
  assert.match(gap(oneRow(closureState(), 'step 3 timed out')).basis, /stopped early/);
  // No reading at all.
  assert.match(gap(oneRow({ refunds: {}, pendingJobs: 0, closure: null })).basis, /no closure reading/);

  // A carrier still FAILS when the deciding records are the app's own: custody withholds
  // passes, it never excuses a fail.
  const carrier = oneRow(closureState({ openJobs: [{ id: 7, userId: 'agent-sam', grantsVersion: 1, status: 'retry' }] }));
  assert.equal(carrier.status, 'fail', carrier.basis);
  // An open job on CURRENT authority is not a carrier: the comparison is the point.
  const current = oneRow(closureState({ openJobs: [{ id: 8, userId: 'agent-sam', grantsVersion: 2, status: 'queued' }] }));
  assert.equal(current.status, 'inconclusive', current.basis);
  assert.equal(current.custodyReason, 'subject-writable-custody', 'that is a withheld pass, not a gap');
  // And an open job belonging to someone who was never revoked is nobody's carrier.
  const other = oneRow(closureState({ openJobs: [{ id: 9, userId: 'agent-tia', grantsVersion: 1, status: 'queued' }] }));
  assert.equal(other.custodyReason, 'subject-writable-custody', other.basis);
});

test('guard coverage is measured on the fail direction, because custody holds every pass', async () => {
  // The coverage matrix asks which invalidator classes each guard actually covers, by turning
  // one guard off at a time. Its first definition was "passes with every guard on, fails with
  // this one off", and it measured NOTHING: custody holds the boundary and
  // closure passes at inconclusive, so no case reaches `pass` at all and all four guards read
  // as covering zero. Running it is what showed that; the definition is now "does not FAIL at
  // baseline, and fails with the guard off", because custody withholds passes and never masks a
  // fail. This test pins both halves on one case so the definition cannot quietly regress.
  const queued = CASES.filter(c => c.id === 'AC-QUEUED');
  const baseline = await runAccessChangeCases({ recheckAtCommit: true, cases: queued });
  assert.notEqual(baseline.rows[0].status, 'fail', 'nothing fails with every guard on');
  assert.notEqual(baseline.rows[0].status, 'pass', 'and nothing PASSES either: the deciding records are the app’s own');
  const without = await runAccessChangeCases({ recheckAtCommit: true, repairs: { commitRecheck: false }, cases: queued });
  assert.equal(without.rows[0].status, 'fail', 'commitRecheck is what stops this one failing');
  // WHICH rows catch it is the interesting part, and not what I first assumed. With the guard
  // off the queued job COMMITS, so it reaches a terminal state and nothing is left carrying
  // retired authority: closure is clean and stays held. The effect assertion and the final-state
  // boundary are what fail. That is the separation the closure row exists for - "can work rooted
  // at a revoked principal still RUN" is a different question from "did something commit after
  // the revoke" - and it is why the row is new rather than folded into the existing ones.
  const failed = without.rows[0].results.filter(r => r.status === 'fail').map(r => r.id);
  assert(failed.includes('AC-QUEUED'), `the effect assertion: ${failed.join(', ')}`);
  assert(failed.includes('AC-QUEUED-FINAL-STATE'), `and the boundary row, on the extra refund: ${failed.join(', ')}`);
  assert(!failed.includes('AC-QUEUED-REVOKE-CLOSE'),
    `closure is NOT what catches a commit: the job is terminal, so nothing still carries the retired grant (${failed.join(', ')})`);
  // And the converse, which is the parked-job case: work left able to run with nothing committed
  // is caught by closure and by nothing else.
  const parked = await runAccessChangeCases({ recheckAtCommit: true, hooks: { parkRevokedJobs: true }, cases: queued });
  assert.deepEqual(parked.rows[0].results.filter(r => r.status === 'fail').map(r => r.id), ['AC-QUEUED-REVOKE-CLOSE'],
    'the two defects are caught by different rows, which is why both rows exist');
});
