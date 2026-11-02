// The late tail (src/http-timing.mjs): a declared effect horizon and run budget. A send the app makes 35 to
// 45 s after its reply (one 36.6 s after it in a backoff tail, and queued sends) is judged in its own
// check's window, or withholds that check's pass, and never fails a later check it did not cause. A virtual clock, an
// injected transport and injected observers that place every committed send on that clock: no socket, no database, no
// model, no provider. The cases are general synthetic ones built from the class descriptions only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runHttpAssessment, HTTP_LIMITS } from '../src/http-connector.mjs';
import { createStore } from '../src/store.mjs';
import { httpLimitations } from '../src/http-scope-text.mjs';
import { validateTargetFile, validateHttpRunEvidence, contractDigest, identityControlPlan, CHECK_TIMEOUT_BOUNDS, IDENTITY_ASSERTION, PRECONDITION_ASSERTION, PRECONDITION_REASONS } from '../src/contracts.mjs';
import { makeEffect, REASON_PATTERN } from '../src/effect-events.mjs';
import { SETTLE_BOUNDS, decideEffects } from '../src/http-effects.mjs';
import { attributionFindings, applyAttribution, ATTRIBUTION_BASIS } from '../src/http-attribution.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { AUDIT_FILE_LIMITS } from '../integrations/observers/audit-file.mjs';
import { TIMING_SCHEMA, TIMING_BOUNDS, TIMING_BASE_MS, TIMING_REQUEST_MS, AUDIT_FILE_WITNESS_DEFAULTS, HORIZON_TRUNCATED, RUN_BUDGET_EXHAUSTED,
  applyHorizon, carriesHorizon, identityProbeBound, witnessCloseMs, plannedTimingMs, plannedTimingTerms } from '../src/http-timing.mjs';

const HOST = 'hooks.desk.example', START = 1000, H = 45000, SETTLE = 1000, LATENCY = 20;

// The virtual world: one clock, every request the run sends, and every send the app commits, each placed in time.
// early(ms, n): how far the n-th sleep actually advances (a timer that fires early); by default exactly ms.
function world({ early = null } = {}) {
  const w = { now: START, sleeps: [], requests: [], sends: [], marks: [] };
  w.clock = { now: () => w.now, sleep: async ms => { w.sleeps.push(ms); w.now += early ? early(ms, w.sleeps.length) : ms; await null; } };
  return w;
}
// routes: { 'METHOD /path': reply | req => reply }, reply { status, json, latency, timeout, sends: [[delayAfterResponseMs, spec], ...] }.
// A GET of a path not listed answers 200 (identity routes answer by credential, below); a witness carries its nonce in the query.
const WHO = { 'tok-owner': 'owner-1', 'tok-member': 'member-1' };
function transportOf(w, routes, { getLatency = LATENCY, everyGet = null } = {}) {
  return async (origin, check, options) => {
    const start = w.now, path = check.path.split('?')[0], key = `${check.method} ${path}`;
    const req = { method: check.method, path, query: check.path.split('?')[1] ?? null, who: WHO[options.credential] ?? null, credential: options.credential, timeoutMs: options.timeoutMs };
    let reply = typeof routes[key] === 'function' ? routes[key](req) : routes[key];
    if (reply === undefined && path === '/me') reply = req.who ? { status: 200, json: { user: req.who } } : { status: 401 };
    if (reply === undefined && path === '/notes') reply = req.who ? { status: 200 } : { status: 401 };
    reply ??= { status: check.method === 'GET' ? 200 : 404 };
    // A reply slower than the request's timeout is a timeout at that timeout, as observeHttp reads it.
    const latency = reply.latency ?? (check.method === 'GET' ? getLatency : LATENCY), timedOut = reply.timeout || latency > options.timeoutMs;
    w.now += timedOut ? options.timeoutMs : latency;
    w.requests.push({ start, end: w.now, key, query: req.query, who: req.who });
    for (const [delay, spec] of [...(reply.sends ?? []), ...(check.method === 'GET' && everyGet ? everyGet : [])]) w.sends.push({ at: w.now + delay, seq: w.sends.length + 1, spec });
    if (timedOut) return { status: null, complete: false, jsonParsed: false, json: undefined, bytes: 0, error: 'timeout' };
    return { status: reply.status ?? 200, complete: true, jsonParsed: true, json: reply.json ?? {}, bytes: 2 };
  };
}
// One request-path gate per declared observer: authoritative, attributing principals, an egress recorder's source (so
// custody is independent). A mark is a point on the clock; a window holds the sends committed after its start mark and
// at or before its end mark. markCost(n, w): the time the n-th mark of this observer takes (0 the run's first mark).
// gapCost: the time each gap collection takes (observer I/O after the final mark).
function observersOf(w, { markCost = () => 0, gapCost = 0, witness = true } = {}) {
  return configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`;
    let n = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [HOST], actorAttribution: 'principal', evidence: 'authoritative' },
      witnessRequest: witness && c.witness ? Object.freeze({ actorId: c.witness.actorId, method: 'GET', path: c.witness.path }) : null,
      async start() {}, async stop() {}, markWitnessRequest() {},
      async mark() { w.now += markCost(n, w); w.marks.push(w.now); return { at: w.now, witnessNonce: `nonce-${n++}` }; },
      async collect(from, to, options) {
        if (options?.gap) w.now += gapCost;
        const events = w.sends.filter(s => s.at > from.at && s.at <= to.at).map(s => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: s.seq, operation: 'send', name: HOST, outcome: 'committed', ...s.spec }));
        return { events, coverage: 'complete', reason: null };
      } };
  });
}
const sel = extra => ({ source: 'http-egress', operation: 'send', name: HOST, ...extra });
const O1 = 'POST /refunds/o1', O2 = 'POST /refunds/o2';
function check(id, { severity = 'high', actorId = 'member', method = 'POST', path, status, effects, ...rest } = {}) {
  return { id, title: id, category: severity === 'control' ? 'Allowed use' : 'Object access', severity, actorId, method, path: path ?? `/${id.toLowerCase()}`, ...(method === 'GET' ? {} : { body: {} }),
    evidenceRequirement: severity === 'control' ? 'response' : 'backend', assertions: [{ kind: 'status.equals', expected: status ?? (severity === 'control' ? 200 : 403) }], ...(effects ? { effects } : {}), ...rest };
}
const OBSERVER = { id: 'gate', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: HOST }], witness: { actorId: 'owner', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: SETTLE, quietMs: 150 };
// The desk: the owner refunds o1 and the member refunds o2 (allowed use, each sends its refund webhook); the member's refund
// and cancel of o1 must be refused with no o1 webhook. Uncredentialed actors, so identity proof stays out of the way.
const DESK = Object.freeze({
  'OWNER-REFUND': check('OWNER-REFUND', { severity: 'control', actorId: 'owner', path: '/owner/o1/refund', effects: [{ kind: 'effect.exists', select: sel({ actor: 'owner-1', resource: O1 }) }] }),
  'MEMBER-REFUND-OWNER': check('MEMBER-REFUND-OWNER', { path: '/member/o1/refund', effects: [{ kind: 'effect.none', select: sel({ resource: O1 }) }] }),
  'MEMBER-CANCEL-OWNER': check('MEMBER-CANCEL-OWNER', { path: '/member/o1/cancel', effects: [{ kind: 'effect.none', select: sel({ resource: O1 }) }] }),
  'MEMBER-OWN-REFUND': check('MEMBER-OWN-REFUND', { severity: 'control', path: '/member/o2/refund', effects: [{ kind: 'effect.count', select: sel({ actor: 'member-1', resource: O2 }), expected: 1 }] }),
});
function desk({ order = ['OWNER-REFUND', 'MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER', 'MEMBER-OWN-REFUND'], extra = {}, settleMs = SETTLE, observers, actors, required } = {}) {
  const checks = order.map(id => structuredClone(extra[id] ?? DESK[id]));
  return { id: 'desk-app', name: 'Desk app', applicationId: 'desk-app', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: actors ?? { member: { principalId: 'member-1' }, owner: { principalId: 'owner-1' } },
    observers: observers ?? [{ ...OBSERVER, settleMs }], requiredControlIds: required ?? checks.filter(c => c.severity === 'control' && c.method !== 'GET' || c.id.endsWith('-ME') || c.id.endsWith('-NOTES')).map(c => c.id), checks };
}
// The desk app: each allowed refund sends its webhook `delay` ms after the reply (a backoff tail or a queue). forbidden: the
// member's refund (or cancel) of o1 goes through too, its webhook `forbidden` ms after the reply.
function deskApp({ owner = 36600, member = owner, forbidden = null, forbiddenOn = 'refund' } = {}) {
  const leak = on => forbidden !== null && forbiddenOn === on ? { status: 403, sends: [[forbidden, { actor: 'member-1', resource: O1 }]] } : { status: 403 };
  return { 'POST /owner/o1/refund': { status: 200, sends: owner === null ? [] : [[owner, { actor: 'owner-1', resource: O1 }]] }, 'POST /member/o1/refund': leak('refund'), 'POST /member/o1/cancel': leak('cancel'),
    'POST /member/o2/refund': { status: 200, sends: member === null ? [] : [[member, { actor: 'member-1', resource: O2 }]] } };
}
const planOf = p => plannedTimingMs(p, { controlPlan: identityControlPlan(p) });
function timed(p, { effectHorizonMs = H, runBudgetMs, slack = 0, lateFails = false } = {}) {
  const q = structuredClone(p);
  q.timing = { effectHorizonMs, runBudgetMs: TIMING_BOUNDS.runBudgetMs[1], ...(lateFails ? { lateFails: 'withhold' } : {}) };
  q.timing.runBudgetMs = runBudgetMs ?? Math.max(TIMING_BOUNDS.runBudgetMs[0], planOf(q) + slack);
  return q;
}
async function assess(p, routes, { env = {}, early, markCost, gapCost, witness, getLatency, everyGet } = {}) {
  const w = world({ early });
  const run = await runHttpAssessment(p, { env, clock: w.clock, transport: transportOf(w, routes, { getLatency, everyGet }), observerFactory: observersOf(w, { markCost, gapCost, witness }) });
  return { w, run, deadline: START + (p.timing?.runBudgetMs ?? 0) };
}
const row = (run, id) => run.results.find(r => r.id === id);
const clause = (run, id, n = 0) => row(run, id).trace[1].data.effects[n];
const ownEvents = (run, id) => row(run, id).trace[1].data.windows.flatMap(w => w.events.map(e => e.resource));
const suiteOf = p => createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
const reseal = r => { r.evidenceDigest = digest(r.trace.length === 2 ? { evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions } : { evidence: r.trace[0].data, assertions: r.assertions }); };
const refusedAs = detail => error => error.code === 'invalid-run-evidence' && error.detail === detail;
// The n-th mark of the gate (0 the run's first mark): observed check k (0-based) is marked at 1 + 2k (start) and 2 + 2k (end).
const startMark = k => 1 + 2 * k, endMark = k => 2 + 2 * k;

// ---------------------------------------------------------------------------
// Acceptance (synthetic): late and queued sends.

test('late tail, backoff: a refund webhook sent 36.6 s after the reply is judged in its own check\'s window and never fails a later check', async () => {
  // Today's longest settle (30 s): the owner's webhook misses its control's window and lands in the member's boundary window.
  const today = await assess(desk({ settleMs: SETTLE_BOUNDS.maxMs }), deskApp());
  assert.equal(clause(today.run, 'OWNER-REFUND').verdict, 'fail');
  assert.deepEqual(ownEvents(today.run, 'MEMBER-REFUND-OWNER'), [O1]);
  assert.equal(row(today.run, 'MEMBER-REFUND-OWNER').status, 'fail', 'the false alarm');
  // A declared 45 s horizon: the webhook is in the control's own window and every row passes.
  const p = timed(desk());
  const { run } = await assess(p, deskApp());
  assert.deepEqual(ownEvents(run, 'OWNER-REFUND'), [O1]);
  assert.deepEqual(run.results.map(r => [r.id, r.status]), [['OWNER-REFUND', 'pass'], ['MEMBER-REFUND-OWNER', 'pass'], ['MEMBER-CANCEL-OWNER', 'pass'], ['MEMBER-OWN-REFUND', 'pass']]);
  assert.deepEqual(run.timing, { schema: TIMING_SCHEMA, effectHorizonMs: H, runBudgetMs: p.timing.runBudgetMs, lateFails: null, rows: p.checks.map(c => ({ id: c.id, waitedMs: H, barrierWaitedMs: null })), tailWaitedMs: SETTLE });
  assert.ok(run.settlement.gaps.every(g => g.windows.every(w => !carriesHorizon(w))) && run.results.every(r => r.trace[1].data.windows.every(w => w.coverage === 'complete')));
  assert.ok(run.limitations.some(l => l.startsWith(`Timing: the target declared an effect horizon of ${H} ms`)));
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suiteOf(p) });
});

test('late tail, queued sends: sends flushed 20 to 44 s after their replies each land in their own check\'s window', async () => {
  for (const [owner, member] of [[20000, 44000], [44000, 20000], [36600, 41000]]) {
    const { run } = await assess(timed(desk()), deskApp({ owner, member }));
    assert.equal(run.counts.pass, 4, `${owner}/${member}`);
    assert.deepEqual([ownEvents(run, 'OWNER-REFUND'), ownEvents(run, 'MEMBER-OWN-REFUND')], [[O1], [O2]]);
    validateHttpRunEvidence(run);
  }
});

test('late tail, forbidden late send: judged in its own boundary window (fail), and the next boundary it fits keeps its pass', async () => {
  const p = timed(desk());
  const { run } = await assess(p, deskApp({ owner: 100, forbidden: 36600 }));
  assert.deepEqual(ownEvents(run, 'MEMBER-REFUND-OWNER'), [O1]);
  assert.equal(clause(run, 'MEMBER-REFUND-OWNER').verdict, 'fail');
  assert.equal(row(run, 'MEMBER-REFUND-OWNER').status, 'fail');
  assert.equal(row(run, 'MEMBER-CANCEL-OWNER').status, 'pass', 'never fails a later check it did not cause');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  // Today (30 s settle): the same send lands in the cancel check's window and fails it, while the refund itself is only withheld.
  const today = await assess(desk({ settleMs: SETTLE_BOUNDS.maxMs }), deskApp({ owner: 100, forbidden: 36600 }));
  assert.equal(row(today.run, 'MEMBER-CANCEL-OWNER').status, 'fail');
  assert.equal(clause(today.run, 'MEMBER-REFUND-OWNER').settlement, 'effect-outside-window');
});

// ---------------------------------------------------------------------------
// Allowed and forbidden neighbours.

test('timing allowed: a late allowed send passes its control; a clean absence over the full horizon passes', async () => {
  const p = timed(desk({ order: ['OWNER-REFUND', 'MEMBER-REFUND-OWNER'] }));
  const { run } = await assess(p, deskApp({ owner: 40000 }));
  assert.deepEqual([row(run, 'OWNER-REFUND').status, row(run, 'MEMBER-REFUND-OWNER').status], ['pass', 'pass']);
  assert.deepEqual(run.timing.rows.map(r => r.waitedMs), [H, H]);
  validateHttpRunEvidence(run);
});

test('timing forbidden: a forbidden send 40 s after the reply fails in its own window; without timing it lands after the final mark and passes', async () => {
  const order = ['OWNER-REFUND', 'MEMBER-REFUND-OWNER'];
  const p = timed(desk({ order }));
  const { run } = await assess(p, deskApp({ owner: 100, forbidden: 40000 }));
  assert.equal(row(run, 'MEMBER-REFUND-OWNER').status, 'fail');
  assert.deepEqual(ownEvents(run, 'MEMBER-REFUND-OWNER'), [O1]);
  validateHttpRunEvidence(run);
  // Without timing (10 s settle) the send comes after the final mark: outside every window, so the absence passes.
  const today = await assess(desk({ order, settleMs: 10000 }), deskApp({ owner: 100, forbidden: 40000 }));
  assert.equal(row(today.run, 'MEMBER-REFUND-OWNER').status, 'pass');
});

test('timing: an unobserved write\'s late send lands in the lead-in gap, so it never passes a later control or shows its twin', async () => {
  // The owner's queue request (no effects of its own) sends the o1 webhook 40 s later; the owner's refund itself sends nothing.
  const extra = { 'OWNER-QUEUE': check('OWNER-QUEUE', { severity: 'control', actorId: 'owner', path: '/owner/o1/queue' }) };
  const order = ['MEMBER-CANCEL-OWNER', 'OWNER-QUEUE', 'OWNER-REFUND', 'MEMBER-REFUND-OWNER'];
  const routes = { ...deskApp({ owner: null }), 'POST /owner/o1/queue': { status: 200, sends: [[40000, { actor: 'owner-1', resource: O1 }]] } };
  const { run } = await assess(timed(desk({ order, extra, required: ['OWNER-REFUND'] })), routes);
  assert.deepEqual(ownEvents(run, 'OWNER-REFUND'), [], 'the queued send is not in the control\'s window');
  assert.deepEqual(run.settlement.gaps[1].windows[0].events.map(e => e.resource), [O1], 'it is in the gap before it');
  assert.equal(clause(run, 'OWNER-REFUND').verdict, 'fail');
  assert.equal(clause(run, 'MEMBER-REFUND-OWNER').pairing, 'selector-not-shown-to-match');
  assert.notEqual(row(run, 'MEMBER-REFUND-OWNER').status, 'pass');
  assert.equal(clause(run, 'MEMBER-CANCEL-OWNER').settlement, 'effect-outside-window', 'an earlier absence it fits is withheld');
  validateHttpRunEvidence(run);
  // Allowed neighbour: the same send caused by the control's own request passes it.
  const own = await assess(timed(desk({ order, extra, required: ['OWNER-REFUND'] })), { ...deskApp({ owner: 40000 }), 'POST /owner/o1/queue': { status: 200 } });
  assert.deepEqual([clause(own.run, 'OWNER-REFUND').verdict, row(own.run, 'MEMBER-REFUND-OWNER').status], ['pass', 'pass']);
});

test('timing: an effect just beyond the horizon withholds the absence pass it fits and never fails the next check (Gap 5 guard)', async () => {
  const { run } = await assess(timed(desk()), deskApp({ forbidden: H + 1000 }));
  assert.equal(clause(run, 'MEMBER-REFUND-OWNER').verdict, 'inconclusive');
  assert.equal(clause(run, 'MEMBER-REFUND-OWNER').settlement, 'effect-outside-window');
  assert.deepEqual(ownEvents(run, 'MEMBER-CANCEL-OWNER'), [], 'the lead-in keeps it out of the next window');
  assert.equal(row(run, 'MEMBER-CANCEL-OWNER').status, 'pass');
  validateHttpRunEvidence(run);
  // On the last check it lands in the tail: withheld, never passed.
  const last = await assess(timed(desk({ order: ['OWNER-REFUND', 'MEMBER-OWN-REFUND', 'MEMBER-REFUND-OWNER'] })), deskApp({ owner: 100, member: 100, forbidden: H + 500 }));
  assert.equal(clause(last.run, 'MEMBER-REFUND-OWNER').settlement, 'effect-outside-window');
  assert.equal(row(last.run, 'MEMBER-REFUND-OWNER').status, 'inconclusive');
});

// ---------------------------------------------------------------------------
// Credentialed actors: identity controls, surface controls and probe points.
const CRED_ACTORS = Object.freeze({ member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' }, owner: { principalId: 'owner-1', credentialEnv: 'SCOPEHAVEN_TARGET_OWNER', identityValue: 'owner-1' } });
const CRED_ENV = Object.freeze({ SCOPEHAVEN_TARGET_MEMBER: 'tok-member', SCOPEHAVEN_TARGET_OWNER: 'tok-owner' });
const me = actorId => check(`${actorId.toUpperCase()}-ME`, { severity: 'control', actorId, method: 'GET', path: '/me', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: `${actorId}-1` }] });
const notes = actorId => check(`${actorId.toUpperCase()}-NOTES`, { severity: 'control', actorId, method: 'GET', path: '/notes' });
const ID_CHECKS = Object.freeze({ 'OWNER-ME': me('owner'), 'MEMBER-ME': me('member'), 'OWNER-NOTES': notes('owner'), 'MEMBER-NOTES': notes('member') });
const credDesk = (order, { extra, actors = CRED_ACTORS, ...options } = {}) => desk({ order: ['OWNER-ME', 'MEMBER-ME', 'OWNER-NOTES', 'MEMBER-NOTES', ...order], extra: { ...ID_CHECKS, ...extra }, actors, ...options });
const probesOf = run => run.identityEvidence.actors.flatMap(a => [...a.before, ...a.between.flatMap(p => p.probes), ...a.after, ...a.anonymous, ...a.invalid, ...a.cross]);

test('timing: identity probe and witness GETs whose effects land 2 s later never land in an observed window', async () => {
  // An adversarial app commits the owner's o1 refund webhook 2 s after every GET it answers (identity and surface probes,
  // witnesses and the GET controls), and never for the owner's own refund request.
  const p = timed(credDesk(['MEMBER-REFUND-OWNER', 'OWNER-REFUND', 'MEMBER-CANCEL-OWNER', 'MEMBER-OWN-REFUND']));
  const { run, w } = await assess(p, deskApp({ owner: null, member: 100 }), { env: CRED_ENV, everyGet: [[2000, { actor: 'owner-1', resource: O1 }]] });
  assert.ok(w.requests.filter(r => r.key.startsWith('GET ')).length > 20, 'probes and witnesses were sent');
  for (const id of ['MEMBER-REFUND-OWNER', 'OWNER-REFUND', 'MEMBER-CANCEL-OWNER']) assert.deepEqual(ownEvents(run, id), [], id);
  assert.deepEqual(ownEvents(run, 'MEMBER-OWN-REFUND'), [O2]);
  assert.equal(clause(run, 'OWNER-REFUND').verdict, 'fail');
  for (const id of ['MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER']) assert.notEqual(row(run, id).status, 'pass', id);
  assert.ok(run.identityEvidence.actors.every(a => a.loginProven));
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
});

test('timing: the identity probe bound covers every probe a run sends, exactly when no check follows an account change', async () => {
  const third = { principalId: 'auditor-1', credentialEnv: 'SCOPEHAVEN_TARGET_AUDITOR', identityValue: 'auditor-1' };
  const auditor = { 'AUDITOR-ME': me('auditor'), 'AUDITOR-NOTES': notes('auditor'), 'AUDITOR-LOOK': check('AUDITOR-LOOK', { actorId: 'auditor', method: 'GET', path: '/look', status: 200 }) };
  const cases = [credDesk(['OWNER-REFUND', 'MEMBER-OWN-REFUND', 'MEMBER-REFUND-OWNER']),
    credDesk(['OWNER-REFUND', 'AUDITOR-ME', 'AUDITOR-NOTES', 'AUDITOR-LOOK', 'MEMBER-REFUND-OWNER'], { extra: auditor, actors: { ...CRED_ACTORS, auditor: third, guest: { principalId: 'guest-1' } } })];
  for (const p of cases) {
    const q = timed(p, { slack: 10000 });
    const { run } = await assess(q, { ...deskApp({ owner: 100 }), 'GET /look': { status: 200 } }, { env: { ...CRED_ENV, SCOPEHAVEN_TARGET_AUDITOR: 'tok-auditor' } });
    assert.equal(probesOf(run).length, identityProbeBound(q, identityControlPlan(q)), q.checks.map(c => c.id).join());
    validateHttpRunEvidence(run);
  }
});

// ---------------------------------------------------------------------------
// The gate, the reserve and the fallback.

test('timing gate: a check the budget cannot hold is not sent (run-budget-exhausted), nor is any later one, and the run ends inside its budget', async () => {
  const p = timed(desk({ order: ['OWNER-REFUND', 'MEMBER-OWN-REFUND', 'MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER'] })), close = witnessCloseMs(p.observers, p.actors);
  // After the second check's end mark, the third check's request, horizon and witness close fit exactly (spare 0) or miss by 1 ms.
  for (const [spare, cut] of [[-1, ['MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER']], [0, ['MEMBER-CANCEL-OWNER']]]) {
    const markCost = (n, x) => n === endMark(1) ? START + p.timing.runBudgetMs - SETTLE - (TIMING_REQUEST_MS + H + close) - spare - x.now : 0;
    const { run, w, deadline } = await assess(p, deskApp({ owner: 100, member: 100 }), { markCost });
    for (const r of run.results) {
      if (!cut.includes(r.id)) { assert.equal(r.status, 'pass', r.id); continue; }
      assert.deepEqual([r.status, r.trace.length, r.trace[0].data.notSent, r.trace[0].data.requestAttempted], ['inconclusive', 1, RUN_BUDGET_EXHAUSTED, false], r.id);
      assert.equal(r.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual, PRECONDITION_REASONS[RUN_BUDGET_EXHAUSTED]);
      assert.match(r.summary, /declared run budget could not hold this check/);
      assert.ok(!w.requests.some(q => q.key === `POST ${p.checks.find(c => c.id === r.id).path}`), `${r.id} was not sent`);
    }
    assert.deepEqual(run.timing.rows.map(x => x.id), run.results.filter(r => !cut.includes(r.id)).map(r => r.id));
    assert.equal(run.timing.tailWaitedMs, SETTLE);
    assert.ok(w.requests.every(q => q.end <= deadline) && w.now <= deadline, 'nothing ends after the deadline');
    assert.match(run.limitations.find(l => l.startsWith('Timing:')), new RegExp(`as does every check after it \\(in this run: ${cut.join(', ')}\\)`));
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  }
});

test('timing reserve: a cut keeps every earlier row\'s pass and its actor\'s login proven, because the remaining probes keep their time', async () => {
  const p = timed(credDesk(['OWNER-REFUND', 'MEMBER-OWN-REFUND', 'MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER']));
  const close = witnessCloseMs(p.observers, p.actors);
  // After the second observed check's end mark (two 2.5 s probes follow it, so the third check's lead-in is a full horizon),
  // leave the third check 1 s of room beyond its request, lead-in, horizon and witness close: enough only if the reserve for
  // the probes still to send were ignored.
  const markCost = (n, x) => n === endMark(1) ? START + p.timing.runBudgetMs - SETTLE - (TIMING_REQUEST_MS + 2 * H + close) - 2 * 2500 - 1000 - x.now : 0;
  const { run, w, deadline } = await assess(p, deskApp({ owner: 100, member: 100 }), { env: CRED_ENV, markCost, getLatency: 2500 });
  assert.deepEqual(run.results.filter(r => r.status !== 'pass').map(r => r.id), ['MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER']);
  assert.ok(run.results.filter(r => r.status !== 'pass').every(r => r.trace[0].data.notSent === RUN_BUDGET_EXHAUSTED));
  assert.ok(probesOf(run).every(x => x.transportOutcome === 'complete'), 'no probe ran out of time');
  assert.deepEqual(run.identityEvidence.actors.map(a => [a.actorId, a.loginProven]), [['member', true], ['owner', true]]);
  assert.ok(w.now <= deadline);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
});

test('timing reserve: the end-of-run probes go before the final settle, so a slow final collection never starves them', async () => {
  const p = timed(credDesk(['OWNER-REFUND', 'MEMBER-OWN-REFUND', 'MEMBER-REFUND-OWNER']));
  // Each gap collection takes 20 s of observer I/O after the final mark: far more than the end probes' reserve.
  const markCost = (n, x) => n === endMark(2) ? START + p.timing.runBudgetMs - x.now - SETTLE - 6 * TIMING_REQUEST_MS : 0;
  const { run, w, deadline } = await assess(p, deskApp({ owner: 100, member: 100 }), { env: CRED_ENV, markCost, gapCost: 20000 });
  assert.ok(w.now > deadline, 'the collections ran past the budget');
  assert.ok(probesOf(run).every(x => x.transportOutcome === 'complete'));
  assert.deepEqual(run.counts, { pass: 7, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 });
  assert.ok(Math.max(...w.requests.filter(r => r.key === 'GET /me').map(r => r.end)) <= w.marks.at(-1), 'every end probe precedes the final mark');
  validateHttpRunEvidence(run);
});

// A mark cost that leaves exactly `left` ms of horizon after the next request (the horizon's own clip point: the wait
// deadline less the witness close; no identity probes in the desk).
const leaving = (p, left) => x => START + p.timing.runBudgetMs - SETTLE - witnessCloseMs(p.observers, p.actors) - x.now - LATENCY - left;

test('timing fallback: a horizon cut short reads partial with effect-horizon-truncated, never pass, and cuts every later check', async () => {
  const p = timed(desk()), leave = leaving(p, 20000);
  const { run, w, deadline } = await assess(p, deskApp({ owner: 100, member: 100 }), { markCost: (n, x) => n === startMark(1) ? leave(x) : 0 });
  assert.deepEqual(run.timing.rows.map(r => [r.id, r.waitedMs]), [['OWNER-REFUND', H], ['MEMBER-REFUND-OWNER', 20000]]);
  const truncated = row(run, 'MEMBER-REFUND-OWNER');
  assert.ok(truncated.trace[1].data.windows.every(x => x.coverage === 'partial' && x.reason === HORIZON_TRUNCATED));
  assert.deepEqual([clause(run, 'MEMBER-REFUND-OWNER').verdict, truncated.status], ['missing', 'inconclusive']);
  assert.match(truncated.assertions.find(a => a.name.startsWith('Observed effect')).actual, /^missing: /);
  for (const id of ['MEMBER-CANCEL-OWNER', 'MEMBER-OWN-REFUND']) assert.equal(row(run, id).trace[0].data.notSent, RUN_BUDGET_EXHAUSTED, id);
  assert.equal(row(run, 'OWNER-REFUND').status, 'pass', 'an allowed-use control keeps its verdict');
  assert.equal(run.timing.tailWaitedMs, SETTLE, 'the witness close was reserved, so the tail is whole');
  const text = run.limitations.find(l => l.startsWith('Timing:'));
  assert.match(text, /\(in this run: MEMBER-CANCEL-OWNER, MEMBER-OWN-REFUND\)/);
  assert.match(text, /settlement-unobserved tag \(in this run: MEMBER-REFUND-OWNER\)/);
  assert.ok(w.now <= deadline);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
});

test('timing fallback: a truncated window keeps its recorded evidence (a forbidden send fails, a match passes, a count reads missing)', async () => {
  const O3 = 'POST /refunds/o3';
  const extra = { 'MIXED': check('MIXED', { path: '/member/mixed', effects: [{ kind: 'effect.none', select: sel({ resource: O1 }) }, { kind: 'effect.exists', select: sel({ resource: O2 }) }, { kind: 'effect.count', select: sel({ resource: O3 }), expected: 1 }] }) };
  const p = timed(desk({ order: ['MIXED', 'OWNER-REFUND'], extra, required: ['OWNER-REFUND'] })), leave = leaving(p, 20000);
  const routes = { ...deskApp({ owner: 100 }), 'POST /member/mixed': { status: 403, sends: [[100, { resource: O1 }], [100, { resource: O2 }], [100, { resource: O3 }], [200, { resource: O3 }]] } };
  const { run } = await assess(p, routes, { markCost: (n, x) => n === startMark(0) ? leave(x) : 0 });
  assert.equal(run.timing.rows[0].waitedMs, 20000);
  assert.deepEqual(row(run, 'MIXED').trace[1].data.effects.map(e => e.verdict), ['fail', 'pass', 'missing']);
  assert.equal(row(run, 'MIXED').status, 'fail');
  validateHttpRunEvidence(run);
});

test('timing fallback: an expected send not yet seen at the cut reads missing, so the actor is not established', async () => {
  const p = timed(desk({ order: ['MEMBER-REFUND-OWNER', 'MEMBER-OWN-REFUND', 'OWNER-REFUND'] })), leave = leaving(p, 20000);
  const { run } = await assess(p, deskApp({ owner: 100, member: 30000 }), { markCost: (n, x) => n === startMark(1) ? leave(x) : 0 });
  assert.deepEqual([clause(run, 'MEMBER-OWN-REFUND').verdict, row(run, 'MEMBER-OWN-REFUND').status], ['missing', 'inconclusive'], 'never a fail');
  assert.ok(row(run, 'MEMBER-REFUND-OWNER').assertions.some(a => a.name === IDENTITY_ASSERTION));
  assert.equal(row(run, 'MEMBER-REFUND-OWNER').status, 'inconclusive');
  assert.equal(row(run, 'OWNER-REFUND').trace[0].data.notSent, RUN_BUDGET_EXHAUSTED);
  validateHttpRunEvidence(run);
});

test('timing fallback: a truncated later window withholds an earlier absence pass from the same observer (settlement-unobserved)', async () => {
  const p = timed(desk({ order: ['OWNER-REFUND', 'MEMBER-OWN-REFUND', 'MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER'] })), leave = leaving(p, 20000);
  const { run } = await assess(p, deskApp({ owner: 100, member: 100 }), { markCost: (n, x) => n === startMark(3) ? leave(x) : 0 });
  assert.equal(run.timing.rows[3].waitedMs, 20000);
  assert.deepEqual([clause(run, 'MEMBER-REFUND-OWNER').verdict, clause(run, 'MEMBER-REFUND-OWNER').settlement], ['inconclusive', 'settlement-unobserved']);
  validateHttpRunEvidence(run);
});

test('timing: a wait equal to the horizon is not truncated; one ms less is', async () => {
  const p = timed(desk({ order: ['OWNER-REFUND', 'MEMBER-REFUND-OWNER'] }));
  for (const [short, status] of [[0, 'pass'], [1, 'inconclusive']]) {
    const leave = leaving(p, H - short);
    const { run } = await assess(p, deskApp({ owner: 100 }), { markCost: (n, x) => n === startMark(1) ? leave(x) : 0 });
    assert.deepEqual([run.timing.rows[1].waitedMs, row(run, 'MEMBER-REFUND-OWNER').status], [H - short, status]);
    assert.equal(row(run, 'MEMBER-REFUND-OWNER').trace[1].data.windows.some(carriesHorizon), short > 0);
    validateHttpRunEvidence(run);
  }
});

test('timing fallback: a clipped final settle or barrier reads partial and withholds the absence passes before it', async () => {
  // The tail: the last end mark leaves 500 of the 1000 ms final settle.
  const p = timed(desk({ order: ['OWNER-REFUND', 'MEMBER-REFUND-OWNER'] }));
  const tail = await assess(p, deskApp({ owner: 100 }), { markCost: (n, x) => n === endMark(1) ? START + p.timing.runBudgetMs - 500 - x.now : 0 });
  assert.equal(tail.run.timing.tailWaitedMs, 500);
  assert.ok(tail.run.settlement.gaps.at(-1).windows.every(x => x.coverage === 'partial' && carriesHorizon(x)));
  assert.ok(tail.run.settlement.gaps.slice(0, -1).every(g => !g.windows.some(carriesHorizon)));
  assert.equal(clause(tail.run, 'MEMBER-REFUND-OWNER').settlement, 'settlement-unobserved');
  assert.match(tail.run.limitations.find(l => l.startsWith('Timing:')), /\(in this run: the final settle\)/);
  validateHttpRunEvidence(tail.run, { expectedSuite: suiteOf(p) });
  // A barrier (per-check settlement): the first check's end mark leaves 300 of its 1000 ms barrier.
  const observers = [{ ...OBSERVER, destinations: [{ host: HOST, correlation: { header: 'x-desk-run' } }] }];
  const q = timed({ ...desk({ order: ['MEMBER-REFUND-OWNER', 'OWNER-REFUND'], observers }), correlation: { header: 'x-desk-run' }, settlement: { mode: 'per-check' } });
  const barrier = await assess(q, deskApp({ owner: 100 }), { markCost: (n, x) => n === 2 ? START + q.timing.runBudgetMs - SETTLE - 300 - x.now : 0 });
  assert.deepEqual(barrier.run.timing.rows, [{ id: 'MEMBER-REFUND-OWNER', waitedMs: H, barrierWaitedMs: 300 }]);
  assert.ok(barrier.run.settlement.barriers[0].windows.every(x => x.coverage === 'partial' && carriesHorizon(x)));
  assert.equal(clause(barrier.run, 'MEMBER-REFUND-OWNER').settlement, 'settlement-unobserved');
  assert.equal(row(barrier.run, 'OWNER-REFUND').trace[0].data.notSent, RUN_BUDGET_EXHAUSTED);
  validateHttpRunEvidence(barrier.run, { expectedSuite: suiteOf(q) });
});

test('timing: a timer that fires early never shortens a window or a lead-in', async () => {
  // No witness here, so each window ends right after its horizon.
  const observers = [{ id: 'gate', type: 'egress-recorder', port: 40999, destinations: [{ host: HOST }], settleMs: SETTLE }];
  const extra = { 'OWNER-QUEUE': check('OWNER-QUEUE', { severity: 'control', actorId: 'owner', path: '/owner/o1/queue' }) };
  const p = timed(desk({ order: ['OWNER-REFUND', 'OWNER-QUEUE', 'MEMBER-OWN-REFUND'], extra, observers }));
  const early = (ms, n) => n % 2 ? Math.max(0.5, ms - 1) : ms / 2;
  const { run, w } = await assess(p, { ...deskApp({ owner: H - 0.5, member: H - 0.5 }), 'POST /owner/o1/queue': { status: 200 } }, { early });
  assert.ok(w.sleeps.length > 4, 'the timer fired early');
  assert.deepEqual(run.timing.rows.map(r => r.waitedMs), [H, H]);
  assert.deepEqual([ownEvents(run, 'OWNER-REFUND'), ownEvents(run, 'MEMBER-OWN-REFUND')], [[O1], [O2]]);
  assert.ok(w.marks[startMark(1)] >= w.requests.find(r => r.key === 'POST /owner/o1/queue').end + H, 'the lead-in was held in full');
});

// ---------------------------------------------------------------------------
// Load-time rules: shape, bounds, a declared settle and a budget that holds the linear plan.
const load = (p, timing) => validateTargetFile({ schemaVersion: 1, targets: [{ ...structuredClone(p), timing }] });
const MAX_BUDGET = TIMING_BOUNDS.runBudgetMs[1];

test('timing load rules: shape and bounds', () => {
  const p = desk({ order: ['OWNER-REFUND'], observers: [{ ...OBSERVER, settleMs: SETTLE_BOUNDS.minMs }] });
  for (const effectHorizonMs of [250, 120000]) assert.doesNotThrow(() => load(p, { effectHorizonMs, runBudgetMs: 7200000 }), String(effectHorizonMs));
  for (const effectHorizonMs of [249, 120001, 1000.5, '45000', null]) assert.throws(() => load(p, { effectHorizonMs, runBudgetMs: 7200000 }), /"timing": timing-shape/, String(effectHorizonMs));
  for (const runBudgetMs of [59999, 7200001, -1, 1e9]) assert.throws(() => load(p, { effectHorizonMs: 250, runBudgetMs }), /timing-shape/, String(runBudgetMs));
  // 60000 is in bounds, but no plan fits it: 60 s of base slack plus at least one request.
  assert.throws(() => load(p, { effectHorizonMs: 250, runBudgetMs: 60000 }), /timing-budget-below-plan/);
  for (const timing of [undefined, null, [], 'x', 5, { effectHorizonMs: 250 }, { runBudgetMs: MAX_BUDGET }, { effectHorizonMs: 250, runBudgetMs: MAX_BUDGET, extra: 1 }]) assert.throws(() => load(p, timing), /timing-shape/, JSON.stringify(timing));
  // Late fails: only "withhold", and only as the one optional key.
  assert.doesNotThrow(() => load(p, { effectHorizonMs: 250, runBudgetMs: 7200000, lateFails: 'withhold' }));
  for (const lateFails of ['release', true, null, 'WITHHOLD']) assert.throws(() => load(p, { effectHorizonMs: 250, runBudgetMs: 7200000, lateFails }), /timing-shape/, String(lateFails));
  assert.throws(() => load(p, { effectHorizonMs: 250, runBudgetMs: 7200000, lateFails: 'withhold', extra: 1 }), /timing-shape/);
});

test('timing load rules: a declared settle is required, and the horizon is at least the largest one', () => {
  const p = desk({ order: ['OWNER-REFUND'], observers: [{ ...OBSERVER, settleMs: 5000 }] });
  assert.throws(() => load(p, { effectHorizonMs: 4999, runBudgetMs: MAX_BUDGET }), /timing-horizon-below-settle: .*5000 ms/);
  assert.doesNotThrow(() => load(p, { effectHorizonMs: 5000, runBudgetMs: MAX_BUDGET }));
  const { settleMs: _settle, ...unsettled } = OBSERVER;
  assert.throws(() => load(desk({ order: ['OWNER-REFUND'], observers: [unsettled] }), { effectHorizonMs: 5000, runBudgetMs: MAX_BUDGET }), /timing-needs-settle/);
  assert.throws(() => load(desk({ order: ['OWNER-REFUND'], observers: [] }), { effectHorizonMs: 5000, runBudgetMs: MAX_BUDGET }), /timing-needs-settle/);
});

test('timing load rules: the plan counts every term once, linearly, and the budget must hold it', () => {
  // Distinct terms: a 5 s check timeout, credentialed actors with probe points, a witness with its own wait and quiet
  // period, per-check barriers and a final settle.
  const observers = [{ ...OBSERVER, destinations: [{ host: HOST, correlation: { header: 'x-desk-run' } }], witnessWaitMs: 2000, quietMs: 200, settleMs: 1500 }];
  const p = { ...credDesk(['OWNER-REFUND', 'MEMBER-REFUND-OWNER'], { observers }), correlation: { header: 'x-desk-run' }, settlement: { mode: 'per-check' } };
  p.checks.find(c => c.id === 'OWNER-REFUND').timeoutMs = 5000;
  p.timing = { effectHorizonMs: 40000, runBudgetMs: MAX_BUDGET };
  const plan = identityControlPlan(p);
  assert.equal(identityProbeBound(p, plan), 18);
  assert.deepEqual(plannedTimingTerms(p, { controlPlan: plan }), { base: 60000, requests: 20000, probes: 54000, horizons: 160000, witnesses: 14000, barriers: 3000, tail: 1500 });
  assert.equal(plannedTimingMs(p, { controlPlan: plan }), 312500);
  assert.doesNotThrow(() => load(p, { effectHorizonMs: 40000, runBudgetMs: 312500 }));
  assert.throws(() => load(p, { effectHorizonMs: 40000, runBudgetMs: 312499 }), /timing-budget-below-plan: .*need 312500 ms and "runBudgetMs" is 312499 ms/);
  // A probed control's own declared timeout sets the reserve per probe.
  p.checks.find(c => c.id === 'MEMBER-ME').timeoutMs = 8000;
  assert.equal(plannedTimingTerms(p, { controlPlan: identityControlPlan(p) }).probes, 18 * 8000);
  // The witness close is each sink's collection cap: witness request, witness wait and ten quiet periods; an audit file
  // uses the observer's defaults when it declares none.
  assert.equal(witnessCloseMs([{ type: 'audit-file' }], {}), TIMING_REQUEST_MS + AUDIT_FILE_LIMITS.settleMs + 10 * AUDIT_FILE_LIMITS.quietMs);
  assert.equal(witnessCloseMs([{ ...OBSERVER, witness: undefined }], p.actors), 0, 'a presence-only recorder sends no witness');
});

// ---------------------------------------------------------------------------
// The validator: the record, the windows it held short, the cut and the suite.

test('timing validator: an edited timing record, truncated window or cut is refused', async () => {
  const p = timed(desk()), leave = leaving(p, 20000);
  const truncated = (await assess(p, deskApp({ owner: 100, member: 100 }), { markCost: (n, x) => n === startMark(1) ? leave(x) : 0 })).run;
  const clean = (await assess(p, deskApp({ owner: 100, member: 100 }))).run;
  for (const run of [truncated, clean]) validateHttpRunEvidence(run);
  const edit = (run, change) => { const r = structuredClone(run); change(r); return r; };
  const windowsOf = (r, id) => row(r, id).trace[1].data.windows;
  const mark = (r, id) => { for (const w of windowsOf(r, id)) { w.coverage = 'partial'; w.reason = HORIZON_TRUNCATED; } reseal(row(r, id)); };
  const timingRecord = refusedAs('timing-record');
  const refusals = {
    'the truncated windows restored to complete': edit(truncated, r => { for (const w of windowsOf(r, 'MEMBER-REFUND-OWNER')) { w.coverage = 'complete'; w.reason = null; } reseal(row(r, 'MEMBER-REFUND-OWNER')); }),
    'the reason removed from the truncated windows': edit(truncated, r => { for (const w of windowsOf(r, 'MEMBER-REFUND-OWNER')) w.reason = null; reseal(row(r, 'MEMBER-REFUND-OWNER')); }),
    'the reason on a row that was not truncated': edit(truncated, r => mark(r, 'OWNER-REFUND')),
    'the reason on an ordinary gap': edit(truncated, r => Object.assign(r.settlement.gaps[1].windows[0], { coverage: 'partial', reason: HORIZON_TRUNCATED })),
    'the reason on a tail that was not clipped': edit(clean, r => Object.assign(r.settlement.gaps.at(-1).windows[0], { coverage: 'partial', reason: HORIZON_TRUNCATED })),
    'the reason in a run whose timing record was deleted': edit(truncated, r => { delete r.timing; }),
    'a truncated row that is not the last effect row': edit(clean, r => { r.timing.rows[0].waitedMs = H - 1; mark(r, 'OWNER-REFUND'); }),
    'a clipped tail without its downgraded windows': edit(clean, r => { r.timing.tailWaitedMs = SETTLE - 1; }),
    'rows reordered': edit(clean, r => { r.timing.rows.reverse(); }),
    'a row renamed': edit(clean, r => { r.timing.rows[0].id = 'MEMBER-REFUND-OWNER'; }),
    'a duration below the wait': edit(clean, r => { row(r, 'OWNER-REFUND').durationMs = H - 1; }),
    'a wait above the horizon': edit(clean, r => { r.timing.rows[0].waitedMs = H + 1; }),
    'a tail above the settle': edit(clean, r => { r.timing.tailWaitedMs = SETTLE + 1; }),
    'a barrier wait in run mode': edit(clean, r => { r.timing.rows[0].barrierWaitedMs = 0; }),
    'a horizon below the largest settle': edit(clean, r => { r.timing.effectHorizonMs = SETTLE - 1; for (const x of r.timing.rows) x.waitedMs = SETTLE - 1; }),
    'an unknown key': edit(clean, r => { r.timing.note = 'x'; }),
    'another schema': edit(clean, r => { r.timing.schema = 'scopehaven-timing/2'; }),
  };
  for (const [name, run] of Object.entries(refusals)) assert.throws(() => validateHttpRunEvidence(run), timingRecord, name);
});

test('timing validator: run-budget-exhausted needs a timing record, and once a row is cut every later one is', async () => {
  const p = timed(desk({ order: ['OWNER-REFUND', 'MEMBER-OWN-REFUND', 'MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER'] })), close = witnessCloseMs(p.observers, p.actors);
  const markCost = (n, x) => n === endMark(1) ? START + p.timing.runBudgetMs - SETTLE - (TIMING_REQUEST_MS + H + close) + 1 - x.now : 0;
  const { run } = await assess(p, deskApp({ owner: 100, member: 100 }), { markCost });
  assert.deepEqual(run.results.map(r => r.trace[0].data.notSent ?? null), [null, null, RUN_BUDGET_EXHAUSTED, RUN_BUDGET_EXHAUSTED]);
  validateHttpRunEvidence(run);
  const edit = change => { const r = structuredClone(run); change(r); return r; };
  // The record deleted: the cut rows' reason is no longer accepted.
  assert.throws(() => validateHttpRunEvidence(edit(r => { delete r.timing; })), /invalid-run-evidence/);
  // A sent row after a cut row (an effect row moved after the first cut row; settlement keeps its order).
  assert.throws(() => validateHttpRunEvidence(edit(r => { const [b, c] = r.results.splice(1, 2); r.results.splice(1, 0, c, b); })), /invalid-run-evidence/);
  // A cut row relabelled with another not-sent reason.
  assert.throws(() => validateHttpRunEvidence(edit(r => { const x = row(r, 'MEMBER-CANCEL-OWNER'); x.trace[0].data.notSent = 'capture-unavailable'; x.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual = PRECONDITION_REASONS['capture-unavailable']; reseal(x); })), /invalid-run-evidence/);
});

test('timing validator: a timing record on a run labelled before http-contract/4 is refused', async () => {
  const p = desk({ order: ['OWNER-QUEUE'], extra: { 'OWNER-QUEUE': check('OWNER-QUEUE', { severity: 'control', actorId: 'owner', path: '/owner/o1/queue' }) } });
  delete p.observers;
  const { run } = await assess(p, { 'POST /owner/o1/queue': { status: 200 } });
  const v2 = structuredClone(run);
  Object.assign(v2, { adapterVersion: 'loopback-response-contract/2', assertionSchemaVersion: 'http-contract/3' });
  for (const key of ['targetContext', 'targetLabel']) delete v2[key];
  validateHttpRunEvidence(v2);
  assert.throws(() => validateHttpRunEvidence({ ...v2, timing: { schema: TIMING_SCHEMA, effectHorizonMs: H, runBudgetMs: MAX_BUDGET, rows: [], tailWaitedMs: null } }), /invalid-run-evidence/);
});

test('timing suite binding: the exported suite fixes the declared horizon and budget, with or without effect rows', async () => {
  const unsuite = error => error.code === 'unexpected-suite-evidence';
  const p = timed(desk());
  assert.deepEqual(suiteOf(p).timing, p.timing);
  assert.ok(!Object.hasOwn(suiteOf(desk()), 'timing'));
  const { run } = await assess(p, deskApp());
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  for (const other of [desk(), timed(desk(), { effectHorizonMs: H + 1000 }), { ...p, timing: { ...p.timing, runBudgetMs: p.timing.runBudgetMs + 1 } }]) assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: suiteOf(other) }), unsuite);
  const plain = (await assess(desk(), deskApp())).run;
  assert.throws(() => validateHttpRunEvidence(plain, { expectedSuite: suiteOf(p) }), unsuite);
  // A run with no effect rows still carries its record (no rows, no tail) and is bound the same way.
  const queue = { 'OWNER-QUEUE': check('OWNER-QUEUE', { severity: 'control', actorId: 'owner', path: '/owner/o1/queue' }) };
  const quiet = timed(desk({ order: ['OWNER-QUEUE'], extra: queue }));
  const q = (await assess(quiet, { 'POST /owner/o1/queue': { status: 200 } })).run;
  assert.deepEqual([q.timing.rows, q.timing.tailWaitedMs, Object.hasOwn(q, 'settlement')], [[], null, false]);
  validateHttpRunEvidence(q, { expectedSuite: suiteOf(quiet) });
  assert.throws(() => validateHttpRunEvidence(q, { expectedSuite: suiteOf(desk({ order: ['OWNER-QUEUE'], extra: queue })) }), unsuite);
  const stripped = structuredClone(q); delete stripped.timing;
  assert.throws(() => validateHttpRunEvidence(stripped, { expectedSuite: suiteOf(quiet) }), unsuite);
});

// ---------------------------------------------------------------------------
// Compatibility: a profile without "timing" behaves as before.

test('compat: without "timing" the waits, the record and the end-of-run probes are as before', async () => {
  // Run mode: one settle per observed check, then the final settle, each through the run's clock.
  const { run, w } = await assess(desk(), deskApp({ owner: 100, member: 100 }));
  assert.deepEqual(w.sleeps, [SETTLE, SETTLE, SETTLE, SETTLE, SETTLE]);
  assert.ok(!Object.hasOwn(run, 'timing') && !run.limitations.some(l => l.startsWith('Timing:')));
  // Per-check mode: a settle and a barrier per observed check, then the final settle.
  const observers = [{ ...OBSERVER, destinations: [{ host: HOST, correlation: { header: 'x-desk-run' } }] }];
  const perCheck = await assess({ ...desk({ order: ['OWNER-REFUND', 'MEMBER-REFUND-OWNER'], observers }), correlation: { header: 'x-desk-run' }, settlement: { mode: 'per-check' } }, deskApp({ owner: 100 }));
  assert.deepEqual(perCheck.w.sleeps, [SETTLE, SETTLE, SETTLE, SETTLE, SETTLE]);
  // The anonymous and look-alike end-of-run probes still follow the final mark: no warm-up without timing.
  const cred = await assess(credDesk(['OWNER-REFUND', 'MEMBER-REFUND-OWNER']), deskApp({ owner: 100 }), { env: CRED_ENV });
  const unknown = cred.w.requests.filter(r => r.key === 'GET /me' && r.who === null);
  assert.ok(unknown.length === 4 && unknown.every(r => r.start >= cred.w.marks.at(-1)));
  assert.equal(cred.run.counts.pass, 6);
});

test('compat: profiles without "timing" keep their digests; a declared timing moves only the profile and target-config hashes', async () => {
  const { makeLabProfile } = await import('../examples/http-lab.mjs');
  const P = await import('../integrations/core-practice/profiles.mjs');
  const origin = 'http://127.0.0.1:4100', sinkPort = 40100;
  const profiles = { lab: makeLabProfile(origin), lifecycle: P.lifecycleProfile({ origin, sinkPort }), creator: P.creatorProfile({ origin, sinkPort }), settlement: P.settlementProfile({ origin, sinkPort }) };
  // Computed on a build from before the declared horizon and run budget.
  const BASE = { lab: 'b87e6a535167384fffde0f98d1a19c20b51af85767fffa2cb2fea4ea76cb8a13', lifecycle: '496e538ad37ec33793ca3eb2b61b2c28865e3129b7e5f6c8c7d6385921d3ae1e',
    creator: 'db3394137718a6fe512ad902e7e6632442fa08d9b63ea05a0f46abb4f3d6a1a2', settlement: 'e032b66e75216311b7db783fcb7cbfbb1c762a0be09f3913cf6ce0f5fcc95d07' };
  for (const [name, p] of Object.entries(profiles)) assert.equal(contractDigest(validateTargetFile({ schemaVersion: 1, targets: [p] })[0]), BASE[name], name);
  const a = timed(desk()), b = timed(desk(), { effectHorizonMs: H + 1000 });
  const ra = (await assess(a, deskApp())).run, rb = (await assess(b, deskApp())).run, plain = (await assess(desk(), deskApp())).run;
  assert.equal(ra.suiteHash, plain.suiteHash); assert.equal(ra.policyHash, plain.policyHash);
  assert.notEqual(ra.profileHash, plain.profileHash); assert.notEqual(ra.profileHash, rb.profileHash); assert.notEqual(ra.targetConfigHash, rb.targetConfigHash);
});

test('timing lifecycle: a cut account change cuts its post-change checks too, and the validator reads them as cut', async () => {
  // The owner suspends the member; afterwards the app refuses the member's credential (401).
  const extra = { 'OWNER-SUSPEND': check('OWNER-SUSPEND', { severity: 'control', actorId: 'owner', path: '/owner/suspend-member' }),
    'MEMBER-AFTER': check('MEMBER-AFTER', { path: '/member/o1/refund-after', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: sel({ actor: 'member-1' }) }] }) };
  const p = timed({ ...credDesk(['MEMBER-OWN-REFUND', 'MEMBER-REFUND-OWNER', 'OWNER-SUSPEND', 'MEMBER-AFTER'], { extra }), lifecycle: [{ changeCheckId: 'OWNER-SUSPEND', actorId: 'member', after: 'refused' }] });
  const routes = () => { let suspended = false; const refused = reply => req => suspended && req.who === 'member-1' ? { status: 401 } : reply;
    return { ...Object.fromEntries(Object.entries(deskApp({ owner: 100, member: 100 })).map(([k, v]) => [k, refused(v)])), 'GET /me': req => suspended && req.who === 'member-1' ? { status: 401 } : req.who ? { status: 200, json: { user: req.who } } : { status: 401 },
      'POST /owner/suspend-member': () => { suspended = true; return { status: 200 }; }, 'POST /member/o1/refund-after': refused({ status: 200 }) }; };
  const sent = await assess(p, routes(), { env: CRED_ENV });
  assert.deepEqual([row(sent.run, 'OWNER-SUSPEND').status, row(sent.run, 'MEMBER-AFTER').status], ['pass', 'pass']);
  validateHttpRunEvidence(sent.run, { expectedSuite: suiteOf(p) });
  // The second observed check's end mark leaves 1 s before the final settle: the change check's 3 s request budget no longer fits.
  const markCost = (n, x) => n === endMark(1) ? START + p.timing.runBudgetMs - SETTLE - 1000 - x.now : 0;
  const { run, w, deadline } = await assess(p, routes(), { env: CRED_ENV, markCost });
  assert.deepEqual(['OWNER-SUSPEND', 'MEMBER-AFTER'].map(id => row(run, id).trace[0].data.notSent), [RUN_BUDGET_EXHAUSTED, RUN_BUDGET_EXHAUSTED]);
  assert.equal(run.identityEvidence.actors.find(a => a.actorId === 'member').lifecycle.changeConfirmed, false);
  assert.ok(probesOf(run).every(x => x.transportOutcome === 'complete') && w.now <= deadline);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
});

// One real run: the owned practice app on loopback, its egress recorder with proxy routing and a witness, and the system clock.
test('timing (loopback): a refused delete whose webhook goes out 1.5 s later is judged in its own window under a 2.5 s horizon', async t => {
  const { createCorePracticeApp } = await import('../integrations/core-practice/app.mjs');
  const { settlementProfile } = await import('../integrations/core-practice/profiles.mjs');
  const { freePorts } = await import('../integrations/observers/fixtures/free-port.mjs');
  const [sinkPort] = await freePorts(1);
  const app = await createCorePracticeApp({ sinkPort, refusedCommit: { timer: true, creatorRole: 'admin' }, lateMs: 1500 }); t.after(() => app.close());
  const p = timed(settlementProfile({ origin: app.origin, sinkPort }), { effectHorizonMs: 2500 });
  const run = await runHttpAssessment(p, { env: app.env });
  const late = row(run, 'BOB-DELETE-ADMIN-NOTE');
  assert.equal(late.trace[0].data.httpStatus, 403);
  assert.deepEqual(late.trace[1].data.windows[0].events.map(e => e.resource), ['POST /hooks/bob/admin']);
  assert.equal(late.status, 'fail');
  assert.equal(row(run, 'BOB-DELETE-MEMBER-NOTE').status, 'pass');
  assert.ok(run.timing.rows.length === 4 && run.timing.rows.every(r => r.waitedMs === 2500));
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: app.env }).exportSuite(p.id) });
});

test('compat: the timing constants restate the limits they mirror; truncation and the store summary and limitation follow the declaration', async () => {
  assert.equal(TIMING_BASE_MS, HTTP_LIMITS.runTimeoutMs);
  assert.equal(TIMING_REQUEST_MS, HTTP_LIMITS.requestTimeoutMs);
  assert.deepEqual(TIMING_BOUNDS.effectHorizonMs, [SETTLE_BOUNDS.minMs, CHECK_TIMEOUT_BOUNDS.maximumMs]);
  assert.deepEqual({ ...AUDIT_FILE_WITNESS_DEFAULTS }, { witnessWaitMs: AUDIT_FILE_LIMITS.settleMs, quietMs: AUDIT_FILE_LIMITS.quietMs });
  // A truncated window: only an authoritative one that did not fail reads partial; its events stay and the reason is appended.
  const w = { source: 'http-egress', instanceId: 'x', scope: { evidence: 'authoritative' }, coverage: 'complete', reason: null, events: ['e'] };
  assert.deepEqual(applyHorizon(w), { ...w, coverage: 'partial', reason: HORIZON_TRUNCATED });
  assert.equal(applyHorizon({ ...w, coverage: 'partial', reason: 'no-post-response-settle' }).reason, `no-post-response-settle,${HORIZON_TRUNCATED}`);
  for (const kept of [{ ...w, coverage: 'failed', reason: 'down' }, { ...w, scope: { evidence: 'presence-only' } }]) assert.equal(applyHorizon(kept), kept);
  assert.ok(carriesHorizon({ reason: `a,${HORIZON_TRUNCATED}` }) && !carriesHorizon({ reason: `${HORIZON_TRUNCATED}-x` }));
  // A long earlier reason (a sink's problem list) keeps the token within the 200-character window reason limit.
  const long = Array.from({ length: 8 }, (_, i) => `egress-problem-code-${i}x`).join(',');
  assert.ok(long.length === 183 && REASON_PATTERN.test(long) && !REASON_PATTERN.test(`${long},${HORIZON_TRUNCATED}`));
  const capped = applyHorizon({ ...w, coverage: 'partial', reason: long });
  assert.ok(capped.reason.length <= 200 && REASON_PATTERN.test(capped.reason) && carriesHorizon(capped) && long.startsWith(capped.reason.split(',').slice(0, -1).join(',')));
  // A wait that cannot be computed stops the run; it never reads as held.
  await assert.rejects(runHttpAssessment(timed(desk()), { env: {}, clock: world().clock, transport: transportOf(world(), deskApp()), observerFactory: observersOf(world()), limits: { ...HTTP_LIMITS, requestTimeoutMs: Number.NaN } }), /could not be applied to a wait/);
  // The store's history summary leaves the record out, as it does settlement.
  const { run } = await assess(timed(desk()), deskApp());
  const dir = await mkdtemp(join(tmpdir(), 'timing store '));
  try { const summary = createStore(dir).summary(run); assert.ok(!Object.hasOwn(summary, 'timing') && !Object.hasOwn(summary, 'settlement')); } finally { await rm(dir, { recursive: true, force: true }); }
  // An audit file's witness wait counts in a declared run budget only.
  const audit = { forwarded: false, observersDeclared: true, declared: [], auditFiles: [{ id: 'log', quietMs: 300 }] };
  assert.ok(httpLimitations(audit).some(l => l.includes('is not counted in the run\'s time budget')));
  assert.ok(httpLimitations({ ...audit, timing: { effectHorizonMs: H, runBudgetMs: MAX_BUDGET } }).some(l => l.includes('is counted in the declared run budget')));
});

// ---------------------------------------------------------------------------
// Late fails (timing "lateFails": "withhold"; src/http-attribution.mjs late rules): a fail a late effect could explain is
// not charged to the check. Pure rules over synthetic windows first, then runs.
const GATE = 'egress-recorder-gate', GATE_SCOPE = Object.freeze({ operations: ['send'], names: [HOST], actorAttribution: 'principal', evidence: 'authoritative' });
let lateSeq = 0;
const sendEv = spec => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: GATE }, seq: ++lateSeq, operation: 'send', name: HOST, outcome: 'committed', ...spec });
const gw = (events = []) => ({ source: 'http-egress', instanceId: GATE, scope: GATE_SCOPE, coverage: 'complete', reason: null, events });
const lrow = (clauses, events = [], role = 'boundary') => ({ effects: decideEffects(clauses, [gw(events)], { role }), windows: [gw(events)] });
const gapsOf = (n, tail = []) => [...Array.from({ length: n }, () => [gw()]), [gw(tail)]];
const lateFind = (rows, gaps = gapsOf(rows.length), background = []) => attributionFindings(rows, gaps, undefined, { background, lateFails: true });
const O3 = 'POST /refunds/o3', CANCEL = 'POST /cancels/o1';
const none = resource => ({ kind: 'effect.none', select: sel({ resource }) });

test('late rules: an absence or only fail whose events fit an earlier check\'s selector reads late-unattributed; a fail no earlier check explains stands', () => {
  const leak = () => sendEv({ actor: 'member-1', resource: O1 });
  assert.deepEqual(lateFind([lrow([none(O1)]), lrow([none(O1)], [leak()])]), [[null], ['late-unattributed']]);
  // The first check, or a send no earlier selector fits: the fail stands.
  assert.deepEqual(lateFind([lrow([none(O1)], [leak()])]), [[null]]);
  assert.deepEqual(lateFind([lrow([none(O1)]), lrow([none(CANCEL)], [sendEv({ actor: 'member-1', resource: CANCEL })])]), [[null], [null]]);
  // One unexplained event among explained ones keeps the fail.
  assert.deepEqual(lateFind([lrow([none(O1)]), lrow([{ kind: 'effect.none', select: sel({ actor: 'member-1' }) }], [leak(), sendEv({ actor: 'member-1', resource: CANCEL })])]), [[null], [null]]);
  // effect.only: an offender an earlier selector explains; and one it does not.
  const only = { kind: 'effect.only', expect: [sel({ resource: O2 })], allow: [] };
  assert.deepEqual(lateFind([lrow([none(O1)]), lrow([only], [leak(), sendEv({ resource: O2 })])]).at(-1), ['late-unattributed']);
  assert.deepEqual(lateFind([lrow([none(O1)]), lrow([only], [sendEv({ resource: O3 })])]).at(-1), [null]);
});

test('late rules: an exists or count fail its own late effect, or an earlier check\'s, could account for reads late-unattributed', () => {
  const exists = { kind: 'effect.exists', select: sel({ resource: O2 }) }, count = { kind: 'effect.count', select: sel({ resource: O2 }), expected: 1 };
  // The expected send arrives after the window (in the tail): the fail is not charged; another send there leaves it.
  assert.deepEqual(lateFind([lrow([exists]), lrow([none(O3)])], gapsOf(2, [sendEv({ resource: O2 })])), [['late-unattributed'], [null]]);
  assert.deepEqual(lateFind([lrow([exists]), lrow([none(O3)])], gapsOf(2, [sendEv({ resource: CANCEL })])), [[null], [null]]);
  assert.deepEqual(lateFind([lrow([count]), lrow([none(O3)])], gapsOf(2, [sendEv({ resource: O2 })])), [['late-unattributed'], [null]]);
  // Too many: both counted sends fit an earlier check's selector, so the count could be 0 to 2; a count no earlier check explains stands.
  assert.deepEqual(lateFind([lrow([exists], [sendEv({ resource: O2 })]), lrow([count], [sendEv({ resource: O2 }), sendEv({ resource: O2 })])]).at(-1), ['late-unattributed']);
  const own3 = { kind: 'effect.count', select: sel({ resource: O3 }), expected: 1 };
  assert.deepEqual(lateFind([lrow([exists], [sendEv({ resource: O2 })]), lrow([own3], [sendEv({ resource: O3 }), sendEv({ resource: O3 })])]).at(-1), [null]);
  // A keyed count (applications, src/idempotency.mjs): a later fitting send can explain too few applications, never too many.
  const keyed = (low, high) => ({ kind: 'effect.count', select: sel({ resource: O2 }), expected: 1, countBy: 'idempotency-key', applications: { low, high }, verdict: 'fail', matched: low, basis: 'synthetic', custody: null });
  const keyedRows = d => [{ effects: [d], windows: [gw(Array.from({ length: d.matched }, () => sendEv({ resource: O2 })))] }, lrow([none(O3)])];
  assert.deepEqual(lateFind(keyedRows(keyed(2, 2)), gapsOf(2, [sendEv({ resource: O2 })]))[0], [null]);
  assert.deepEqual(lateFind(keyedRows(keyed(0, 0)), gapsOf(2, [sendEv({ resource: O2 })]))[0], ['late-unattributed']);
  // An upstream outcome requirement is set aside: a later send could be the clause's own whatever its outcome reads.
  const upstreamFail = { kind: 'effect.exists', select: sel({ resource: O2, upstream: 'applied' }), verdict: 'fail', matched: 0, basis: 'synthetic', custody: null };
  const rejected = sendEv({ resource: O2, upstream: { outcome: 'rejected', status: 409, proven: true } });
  assert.deepEqual(lateFind([{ effects: [upstreamFail], windows: [gw()] }, lrow([none(O3)])], gapsOf(2, [rejected]))[0], ['late-unattributed']);
});

test('late rules never touch a pass, run only where no background rule applied, and only move a fail to inconclusive', () => {
  const exists = { kind: 'effect.exists', select: sel({ resource: O2 }) };
  // A pass whose events an earlier selector also fits, with more fitting sends later: no late finding (lateFails alone runs no background rule).
  const rows = [lrow([exists], [sendEv({ resource: O2 })]), lrow([exists], [sendEv({ resource: O2 })], 'control')];
  assert.equal(rows[1].effects[0].verdict, 'pass');
  assert.deepEqual(lateFind(rows, gapsOf(2, [sendEv({ resource: O2 })])), [[null], [null]]);
  // A background-possible send decides the fail: the background rule names it, the late rule does not.
  const sync = [{ id: 'sync', select: { actor: 'svc-sync', operation: 'send', name: HOST } }];
  assert.deepEqual(lateFind([lrow([none(O1)]), lrow([none(O1)], [sendEv({ actor: 'svc-sync', resource: O1 })])], undefined, sync).at(-1), ['background-unattributed']);
  // Applied: a boundary fail reads inconclusive with the basis; an allowed-use control keeps its fail with the tag.
  const failed = lrow([none(O1)], [sendEv({ resource: O1 })]).effects;
  const boundary = applyAttribution(failed, ['late-unattributed'], 'boundary'), control = applyAttribution(failed, ['late-unattributed'], 'control');
  assert.deepEqual([boundary[0].verdict, boundary[0].attribution], ['inconclusive', 'late-unattributed']);
  assert.ok(boundary[0].basis.endsWith(ATTRIBUTION_BASIS['late-unattributed']));
  assert.deepEqual([control[0].verdict, control[0].attribution], ['fail', 'late-unattributed']);
  // Without the option the background list must be a real declaration; the option must be a boolean.
  assert.throws(() => attributionFindings([lrow([none(O1)])], gapsOf(1), undefined, { background: [], lateFails: false }), /attribution-background/);
  assert.throws(() => attributionFindings([lrow([none(O1)])], gapsOf(1), undefined, { background: [], lateFails: 'withhold' }), /attribution-late/);
});

test('late fails (run): a forbidden send beyond the horizon that lands in a later boundary window is not charged to it; a send no earlier check explains still fails', async () => {
  const order = ['OWNER-REFUND', 'MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER'], late = 2 * H + 1000;
  // Timing alone: the refund's send, later than the horizon, lands in the cancel check's window and fails it (the stated limit).
  const plain = await assess(timed(desk({ order })), deskApp({ owner: 100, forbidden: late }));
  assert.deepEqual(ownEvents(plain.run, 'MEMBER-CANCEL-OWNER'), [O1]);
  assert.equal(row(plain.run, 'MEMBER-CANCEL-OWNER').status, 'fail');
  // lateFails: the cancel check is not charged (late-unattributed, inconclusive), and the refund check stays withheld.
  const p = timed(desk({ order }), { lateFails: true });
  const { run } = await assess(p, deskApp({ owner: 100, forbidden: late }));
  assert.deepEqual([row(run, 'MEMBER-CANCEL-OWNER').status, clause(run, 'MEMBER-CANCEL-OWNER').attribution], ['inconclusive', 'late-unattributed']);
  assert.deepEqual([row(run, 'MEMBER-REFUND-OWNER').status, clause(run, 'MEMBER-REFUND-OWNER').settlement], ['inconclusive', 'effect-outside-window']);
  assert.equal(run.timing.lateFails, 'withhold');
  assert.ok(run.limitations.find(l => l.startsWith('Timing:')).includes('Late fails (lateFails withhold)'));
  assert.deepEqual(suiteOf(p).timing, p.timing);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  // Allowed neighbour: the cancel check's own forbidden send, which no earlier selector fits, still fails it.
  const extra = { 'MEMBER-CANCEL-OWNER': check('MEMBER-CANCEL-OWNER', { path: '/member/o1/cancel', effects: [{ kind: 'effect.none', select: sel({ resource: CANCEL }) }] }) };
  const own = await assess(timed(desk({ order, extra }), { lateFails: true }), { ...deskApp({ owner: 100 }), 'POST /member/o1/cancel': { status: 403, sends: [[100, { actor: 'member-1', resource: CANCEL }]] } });
  assert.equal(row(own.run, 'MEMBER-CANCEL-OWNER').status, 'fail');
  validateHttpRunEvidence(own.run);
  // Edits: removing the tag, or the declaration, is refused; so is another value.
  const edit = change => { const r = structuredClone(run); change(r); return r; };
  assert.throws(() => validateHttpRunEvidence(edit(r => { r.timing.lateFails = null; })), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(edit(r => { r.timing.lateFails = 'release'; })), refusedAs('timing-record'));
  assert.throws(() => validateHttpRunEvidence(edit(r => { const x = row(r, 'MEMBER-CANCEL-OWNER'); const c = x.trace[1].data.effects[0]; c.verdict = 'fail'; delete c.attribution;
    x.assertions = x.assertions.map(a => a.name.startsWith('Observed effect') ? (({ attribution: _a, ...rest }) => ({ ...rest, status: 'fail' }))(a) : a); x.status = 'fail'; reseal(x); })), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: suiteOf(timed(desk({ order }))) }), e => e.code === 'unexpected-suite-evidence');
});

test('late fails compose with background attribution: a background send keeps its own reason, and neither rule releases a pass', async () => {
  const order = ['OWNER-REFUND', 'MEMBER-REFUND-OWNER', 'MEMBER-CANCEL-OWNER'];
  const p = { ...timed(desk({ order }), { lateFails: true }), attribution: { background: [{ id: 'sync', select: { actor: 'svc-sync', operation: 'send', name: HOST } }] } };
  const routes = { ...deskApp({ owner: 100 }), 'POST /member/o1/cancel': { status: 403, sends: [[100, { actor: 'svc-sync', resource: O1 }]] } };
  const { run } = await assess(p, routes);
  assert.deepEqual([row(run, 'MEMBER-CANCEL-OWNER').status, clause(run, 'MEMBER-CANCEL-OWNER').attribution], ['inconclusive', 'background-unattributed']);
  assert.notEqual(row(run, 'MEMBER-REFUND-OWNER').status, 'pass', 'the later background send still withholds the earlier absence');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
});
