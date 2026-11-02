// App-log admissions end to end (src/http-connector.mjs, src/contracts.mjs, src/runner.mjs): an admitted clause fails in the live
// run and in the saved-run validator alike; a forged or stripped admission is refused; a line logged after the cut is never
// admitted; a baseline fail that rests only on admissions never credits a repair; an admitted lifecycle change check keeps
// the run valid. Injected transport and observers, a temporary file: no socket, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, appendFileSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { digest } from '../src/domain.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, PRECONDITION_ASSERTION, PRECONDITION_REASONS } from '../src/contracts.mjs';
import { compareRuns, NO_VERIFIED_REPAIR } from '../src/runner.mjs';
import { comparisonDocument, custodyEntries, custodySentence, renderReport } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';

const PAY = 'pay.example', SYNC = 'sync.desk.example', SHOP = 'shop.example';
const line = (path, event, actor, result = 'ok') => appendFileSync(path, `${JSON.stringify({ event, actor, result })}\n`);
const APP_LOG = path => ({ id: 'actions', use: 'admission', log: { file: { path } }, fields: { action: '/event', outcome: '/result', actor: '/actor' }, outcomes: { committed: ['ok'], error: ['error'] },
  rules: [{ action: 'refund.paid', operation: 'send', vocabulary: 'egress', name: PAY, resource: 'POST /v1/refunds', observedAs: ['http-egress'] },
    { action: 'carol.suspended', operation: 'send', vocabulary: 'egress', name: SYNC, resource: 'POST /suspend/', observedAs: ['http-egress'] }],
  logActors: { 'member-1': 'member-1', 'admin-1': 'admin-1' } });
const check = (id, severity, method, path, effects, extra = {}) => ({ id, title: id, category: severity === 'control' ? 'allowed-use' : 'object-access', severity, actorId: 'member', method, path,
  ...(method === 'POST' ? { body: {} } : {}), evidenceRequirement: severity === 'control' ? 'response' : 'backend', assertions: [{ kind: 'status.equals', expected: 200 }], ...(effects ? { effects } : {}), ...extra });
const NO_PAY = [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: PAY } }];
// earlier: checks of the same actor declared before NO-PAY. CHECKOUT is the actor's required allowed-use control with a positive
// effect (an order sent to the shop, another host than the payments one), so NO-PAY's absence is guarded.
const CHECKOUT = check('CHECKOUT', 'control', 'POST', '/checkout', [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: SHOP } }]);
function profile(path, earlier = []) {
  return { id: 'app-log-admission', name: 'App log admission', applicationId: 'app-log-admission', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-app-log',
    actors: { member: { principalId: 'member-1' } }, requiredControlIds: ['WHOAMI', 'CHECKOUT'],
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds'] }, { host: SHOP, paths: ['/v1/orders'] }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250 }],
    appLogs: [{ ...APP_LOG(path), logActors: { 'member-1': 'member-1' } }],
    checks: [check('WHOAMI', 'control', 'GET', '/me'), CHECKOUT, ...earlier, check('NO-PAY', 'high', 'POST', '/summarize', NO_PAY), check('NO-PAY-LATE', 'high', 'POST', '/late', NO_PAY)] };
}
// The egress recorder double records only the checkout's order (in CHECKOUT's own window): custody reads every NO-PAY clause a pass (independent).
let ordered = 0, orderSeq = 0;
const factory = configs => configs.map(c => {
  const out = OBSERVER_OUTPUT[c.type], instanceId = `${c.type}-${c.id}`;
  let marks = 0;
  return { kind: out.kind, instanceId, source: out.source, scope: { operations: ['send'], names: [PAY, SHOP], actorAttribution: 'none', evidence: 'authoritative' },
    witnessRequest: { actorId: 'member', method: 'GET', path: '/ping' }, async markWitnessRequest() {},
    async start() {}, async stop() {}, async mark() { return { at: ++marks, witnessNonce: `nonce-${marks}` }; },
    async collect() { const events = Array.from({ length: ordered }, () => makeEffect({ source: 'http-egress', observer: { kind: out.kind, instanceId }, seq: ++orderSeq, operation: 'send', name: SHOP, resource: 'POST /v1/orders', outcome: 'committed' })); ordered = 0; return { events, coverage: 'complete', reason: null }; } };
});
// path: the log file; two runs that compare share it (the path is part of the profile digest), each starting it empty.
async function run(t, { forbidden = true, path = null, earlier = [] } = {}) {
  if (path === null) { const dir = mkdtempSync(join(tmpdir(), 'scopehaven-app-log-admission-')); t.after(() => rmSync(dir, { recursive: true, force: true })); path = join(dir, 'actions.jsonl'); }
  writeFileSync(path, '');
  let last = null;
  const transport = async (origin, request) => {
    const p = request.path.split('?')[0];
    if (p === '/checkout') ordered++;
    if (p === '/summarize' && forbidden) line(path, 'refund.paid', 'member-1');
    if (p === '/late') last = 'late';
    // The witness of NO-PAY-LATE: the app logs its refund only now, after the cut.
    if (p === '/ping' && last === 'late') { line(path, 'refund.paid', 'member-1'); last = null; }
    return { status: 200, complete: true, jsonParsed: true, json: { ok: true }, bytes: 10 };
  };
  return runHttpAssessment(profile(path, earlier), { env: {}, transport, observerFactory: factory });
}
const row = (r, id) => r.results.find(x => x.id === id);
const reseal = r => { for (const x of r.results) if (x.trace[1]) x.evidenceDigest = digest({ evidence: x.trace[0].data, effects: x.trace[1].data, assertions: x.assertions }); return r; };

test('an admitted clause fails live and in the validator, names the app log, and a line logged after the cut is never admitted', async t => {
  const r = await run(t);
  validateHttpRunEvidence(r);
  const admitted = row(r, 'NO-PAY');
  assert.equal(admitted.status, 'fail');
  const [stored] = admitted.trace[1].data.effects;
  assert.equal(stored.verdict, 'fail');
  assert.equal(stored.custody, 'subject-writable');
  assert.deepEqual(stored.appLog, { finding: 'app-log-unobserved-admission', log: 'actions', entries: 1, contradicts: true, custodyVerdict: 'pass' });
  const assertion = admitted.assertions.find(a => a.name === 'Observed effect 1 (effect.none)');
  assert.equal(assertion.status, 'fail');
  assert.match(assertion.actual, /app log actions/);
  assert.equal(admitted.backendEvidence, 'unavailable', 'the application\'s own record decided it');
  // The report and SARIF name the app log as the source of the fail.
  const [entry] = custodyEntries(admitted);
  assert.deepEqual([entry.custody, entry.appLog, entry.appLogSource], ['subject-writable', 'app-log-unobserved-admission', 'actions']);
  assert.match(custodySentence(entry), /Failed by an admission: the application's own action log \(app log actions\)/);
  const html = renderReport(r);
  assert.ok(html.includes('<strong>FAIL (APP-ADMISSION)</strong>') && html.includes('<td>fail (app-admission)</td>'), 'the report labels the fail app-admission');
  const sarif = renderSarif(r).runs[0].results.find(x => x.locations[0].logicalLocations[0].name === 'NO-PAY');
  assert.deepEqual(sarif.properties.scopehavenAdmission, { finding: 'app-log-unobserved-admission', clauses: 1, logs: ['actions'], failRestsOnAdmissions: true });
  assert.equal(sarif.properties.custody[0].appLogSource, 'actions');
  assert.equal(Object.hasOwn(renderSarif(r).runs[0].results.find(x => x.locations[0].logicalLocations[0].name === 'NO-PAY-LATE').properties, 'scopehavenAdmission'), false);
  // The served dashboard's copy of the custody wording names the admission as the report does.
  assert.ok(readFileSync(new URL('../public/dashboard/dashboard.mjs', import.meta.url), 'utf8').includes("Failed by an admission: the application's own action log (app log "));
  // NO-PAY-LATE's refund line was written during its witness request: after the cut, so never its admission.
  assert.equal(row(r, 'NO-PAY-LATE').status, 'pass');
  assert.equal(row(r, 'NO-PAY-LATE').trace[1].data.appLogWindows[0].events.length, 0);
  assert.ok(r.limitations.some(l => l.includes('With "use": "admission"')));
});

test('the validator recomputes admissions: a stripped or forged admission, or a changed use, is refused', async t => {
  const r = await run(t);
  const refused = (mutate, label) => { const copy = structuredClone(r); mutate(copy); assert.throws(() => validateHttpRunEvidence(reseal(copy)), undefined, label); };
  validateHttpRunEvidence(reseal(structuredClone(r)));
  const admitted = x => row(x, 'NO-PAY');
  refused(x => { const e = admitted(x).trace[1].data.effects[0]; delete e.appLog; e.verdict = 'pass'; e.custody = 'independent'; const a = admitted(x).assertions.find(y => y.name === 'Observed effect 1 (effect.none)'); delete a.appLog; a.status = 'pass'; admitted(x).status = 'pass'; }, 'a stripped admission');
  refused(x => { row(x, 'NO-PAY-LATE').trace[1].data.effects[0].appLog = { finding: 'app-log-unobserved-admission', log: 'actions', entries: 1, contradicts: true, custodyVerdict: 'pass' }; }, 'a forged admission');
  refused(x => { x.appLogs[0].use = 'record'; }, 'a run relabelled record');
  refused(x => { admitted(x).trace[1].data.appLogWindows[0].events[0].actor = 'admin-1'; }, 'the entry given to another principal');
  // A malformed sealed clause is refused as run evidence, never as a raw TypeError (admission contexts are read in a guard too).
  const malformed = structuredClone(r);
  admitted(malformed).trace[1].data.effects[0] = { ...admitted(malformed).trace[1].data.effects[0], kind: 'effect.only', expect: 5 };
  assert.throws(() => validateHttpRunEvidence(reseal(malformed)), error => error.code === 'invalid-run-evidence' && typeof error.detail === 'string');
});

test('a baseline fail that rests only on admissions is unverified in the comparison, its document and the gate, never a repair', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-app-log-b2-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'actions.jsonl');
  const baseline = await run(t, { path }), candidate = await run(t, { forbidden: false, path });
  assert.equal(row(baseline, 'NO-PAY').status, 'fail');
  assert.equal(row(candidate, 'NO-PAY').status, 'pass');
  const comparison = compareRuns(baseline, candidate);
  assert.equal(comparison.compatible, true, JSON.stringify(comparison.reasons));
  const moved = comparison.rows.find(x => x.id === 'NO-PAY');
  assert.equal(moved.transition, 'unverified');
  assert.equal(moved.transitionReason, 'baseline-fail-app-admitted');
  assert.equal(comparison.summary.fixed, 0);
  assert.equal(comparison.restorationLabel, NO_VERIFIED_REPAIR);
  assert.ok(comparison.reasons.some(x => x.includes("rests only on the application's own log")));
  const document = comparisonDocument(baseline, candidate, comparison);
  assert.equal(document.comparison.rows.find(x => x.id === 'NO-PAY').transitionReason, 'baseline-fail-app-admitted');
  assert.match(document.interpretation, /rests only on the application's own action log \(an app-log admission\) is never labelled fixed or restored; it reads unverified/);
  const gate = summarizeGate({ candidate, baseline, comparison });
  assert.notEqual(gate.outcome, 'clean');
  assert.ok(gate.reasons.includes('comparison-incomplete'), JSON.stringify(gate.reasons));
});

// The change check is an allowed-use control that suspends carol; its own clause forbids a payment, and the application's
// log admits one in its window. The admission makes the change check fail after it was sent: the post-change check was sent and
// reads change-not-attributed, and the run stays valid evidence.
test('an admitted lifecycle change check keeps the run valid; the post-change check reads change-not-attributed', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-app-log-lifecycle-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'actions.jsonl'); writeFileSync(path, '');
  const ENV = { SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_C: 'tok-carol' };
  const WHO = { 'tok-admin': 'admin', 'tok-carol': 'carol' };
  const me = (id, actorId) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId, method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: actorId }] });
  const p = { id: 'app-log-lifecycle', name: 'App log lifecycle', applicationId: 'app-log-lifecycle', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { admin: { principalId: 'admin-1', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, carol: { principalId: 'carol-1', credentialEnv: 'SCOPEHAVEN_TARGET_C', identityValue: 'carol' } },
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40998, destinations: [{ host: SYNC, paths: ['/suspend/'] }, { host: PAY, paths: ['/v1/refunds'] }], settleMs: 250 }],
    appLogs: [{ ...APP_LOG(path), logActors: { 'admin-1': 'admin-1', 'carol-1': 'carol-1' } }],
    requiredControlIds: ['ADMIN-ME', 'CAROL-ME', 'CAROL-NOTES', 'SUSPEND'], lifecycle: [{ changeCheckId: 'SUSPEND', actorId: 'carol', after: 'refused' }],
    checks: [me('ADMIN-ME', 'admin'), me('CAROL-ME', 'carol'),
      { id: 'CAROL-NOTES', title: 'CAROL-NOTES', category: 'Allowed use', severity: 'control', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'SUSPEND', title: 'SUSPEND', category: 'Allowed use', severity: 'control', actorId: 'admin', method: 'POST', path: '/users/carol/suspend', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }],
        effects: [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: SYNC, resource: 'POST /suspend/' } }, ...NO_PAY] },
      { id: 'REUSE', title: 'REUSE', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: NO_PAY },
      // A post-change check whose request makes the application pay (the recorder sees it): a custody fail, which stays a fail.
      { id: 'REUSE-PAY', title: 'REUSE-PAY', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'POST', path: '/pay', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: NO_PAY }] };
  let suspended = false, now = 0, seq = 0;
  const events = [];
  const transport = async (origin, request, { credential }) => {
    now += 10;
    const who = WHO[credential] ?? null, route = request.path.split('?')[0];
    if (route === '/pay') events.push({ at: now, name: PAY, resource: 'POST /v1/refunds' });
    if (route === '/me') return who ? { status: 200, complete: true, jsonParsed: true, json: { user: who }, bytes: 10 } : { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (!who || (who === 'carol' && suspended)) return { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (route === '/users/carol/suspend') { suspended = true; events.push({ at: now, name: SYNC, resource: 'POST /suspend/' }); line(path, 'refund.paid', 'admin-1'); }
    return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  const clock = { now: () => now, sleep: async ms => { now += ms; } };
  const fake = configs => configs.map(c => ({ kind: 'http-egress-recorder', instanceId: `${c.type}-${c.id}`, source: 'http-egress', witnessRequest: null,
    scope: { operations: ['send'], names: [SYNC, PAY], actorAttribution: 'none', evidence: 'authoritative' }, async start() {}, async stop() {}, async mark() { return { at: now }; },
    async collect(from, to) { return { events: events.filter(e => e.at > from.at && e.at <= to.at).map(e => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: `${c.type}-${c.id}` }, seq: ++seq, operation: 'send', name: e.name, resource: e.resource, outcome: 'committed' })), coverage: 'complete', reason: null }; } }));
  const r = await runHttpAssessment(p, { env: ENV, clock, transport, observerFactory: fake });
  validateHttpRunEvidence(r);
  assert.equal(row(r, 'SUSPEND').status, 'fail');
  assert.equal(row(r, 'SUSPEND').trace[1].data.effects[1].appLog.finding, 'app-log-unobserved-admission');
  const reuse = row(r, 'REUSE');
  assert.notEqual(reuse.status, 'pass');
  assert.ok(reuse.assertions.some(a => a.name === PRECONDITION_ASSERTION && a.actual === PRECONDITION_REASONS['change-not-attributed']));
  // The other leg: a real custody fail among the post-change checks stays a fail, untagged by the log.
  const paid = row(r, 'REUSE-PAY');
  assert.equal(paid.status, 'fail');
  assert.ok(paid.assertions.some(a => a.name === PRECONDITION_ASSERTION && a.actual === PRECONDITION_REASONS['change-not-attributed']));
  const clause = paid.trace[1].data.effects[0];
  assert.deepEqual([clause.verdict, clause.custody, Object.hasOwn(clause, 'appLog')], ['fail', 'independent', false]);
});

// End to end: an earlier check by the same actor whose claim rule names the payment. Its selector sets NO-PAY's logged
// payment aside (it may be the earlier check's late line), in the live run and in the validator alike; without the claim it is
// NO-PAY's own and admitted.
test('an earlier same-actor check\'s claim selector sets a logged line aside, live and in the validator', async t => {
  const CLAIM = { trigger: { field: { pointer: '/ok', success: [true], refusal: [false] } }, select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' } };
  const withClaim = await run(t, { earlier: [check('CLAIMED', 'high', 'POST', '/claimed', undefined, { claims: [CLAIM] })] });
  validateHttpRunEvidence(withClaim);
  assert.equal(row(withClaim, 'NO-PAY').trace[1].data.appLogWindows[0].events.length, 1, 'the line is in NO-PAY\'s window');
  assert.equal(row(withClaim, 'NO-PAY').status, 'pass');
  assert.equal(Object.hasOwn(row(withClaim, 'NO-PAY').trace[1].data.effects[0], 'appLog'), false);
  // The validator recomputes the same context: forging the admission back is refused.
  const forged = structuredClone(withClaim);
  row(forged, 'NO-PAY').trace[1].data.effects[0].appLog = { finding: 'app-log-unobserved-admission', log: 'actions', entries: 1, contradicts: true, custodyVerdict: 'pass' };
  assert.throws(() => validateHttpRunEvidence(reseal(forged)));
  const without = await run(t, { earlier: [check('CLAIMED', 'high', 'POST', '/claimed')] });
  validateHttpRunEvidence(without);
  assert.equal(row(without, 'NO-PAY').status, 'fail', 'adjacent: no claim, so the line is NO-PAY\'s own');
});
