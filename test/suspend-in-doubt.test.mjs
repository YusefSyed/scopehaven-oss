// Suspend-aware lead-in and stop beside in-doubt resolution. The in-doubt core and its transport-record resolver (r0) never
// decide on a window a host sleep left
// partial, and a check the run stopped after a short wait is never anyone's attempt:
//   - a window a sleep left short of its settle without a timing plan (host-suspend-wait-short), or whose horizon a sleep truncated
//     under one (effect-horizon-truncated): every opted-in clause stays undecided and its operation stays in doubt, where the same run
//     awake reads the attempt the transport record refutes as a refuted operation (the outcome-judged effect.only passes, the presence clauses fail);
//   - a check not sent after a short wait (host-suspend-run-stopped) carries no window, so no attempt and no operation record, while
//     the frozen build (an earlier connector and detector) sends it and counts the earlier check's displaced send as its applied attempt;
//   - with the opt-in declared, the validator still recomputes the stop from the sealed windows and refuses a changed reason.
// A virtual clock, the real suspend detector, an injected transport and an egress-recorder/7 observer over one forwarded name.
// Destination hosts are names only and are never resolved or contacted; no socket, no database, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createSuspendDetector, carriesSuspendShort, stopsRun, SUSPEND_SHORT, SUSPEND_STOPPED } from '../src/suspend-clock.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { forwardRecordOf } from '../src/effect-outcome.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, identityControlPlan, PRECONDITION_ASSERTION, PRECONDITION_REASONS } from '../src/contracts.mjs';
import { plannedTimingMs, carriesHorizon, TIMING_BOUNDS, HORIZON_TRUNCATED, RUN_BUDGET_EXHAUSTED } from '../src/http-timing.mjs';
import { COLLECTOR_RECORDS, IN_DOUBT_LABELS } from '../src/collector-identity.mjs';
import { BACKEND_ASSERTION } from '../src/http-effects.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';

const frozen = name => import(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));
const mainConnector = await frozen('http-connector-61adb01.mjs'), mainClock = await frozen('suspend-clock-61adb01.mjs');
const HEAD = Object.freeze({ assess: runHttpAssessment, detector: createSuspendDetector });
const MAIN = Object.freeze({ assess: mainConnector.runHttpAssessment, detector: mainClock.createSuspendDetector });

const WALL0 = Date.parse('2026-10-16T20:14:00.000Z');
const CRM = 'crm.example', CLOSE = 'POST /tickets/T-1/close', WITNESS = 'witness.scopehaven.invalid';
// The forwarder's upstream records: a connect that never completed (the transport record refutes the attempt), and a proven applied reply.
const UP = Object.freeze({
  refused: { outcome: 'unknown', status: null, proven: false, transport: { connected: false, mono: 10.5, wall: 1760000000000 } },
  applied: { outcome: 'applied', status: 201, proven: true },
});
// A virtual host, as in test/suspend-leadin.test.mjs: `now` counts sleep, awake time is now - suspended, and the application acts only
// in awake time. Each request schedules the sends its route declares ("METHOD path" -> [{ delay, up }]), `delay` ms of awake time
// after its reply, each a committed close of T-1 on CRM carrying the upstream record `up` and the recorder's exact, query-free target
// flags. onSleep(ms, n) => [awakeBeforeSleep, asleep] or null overlaps the n-th wait of the run with a suspend.
function host({ sends = {}, onSleep = () => null } = {}) {
  const v = { now: 1000, suspended: 0, sleeps: [], sent: [] };
  v.awake = () => v.now - v.suspended;
  v.clock = { now: () => v.now, sleep: async ms => {
    v.sleeps.push(ms);
    const s = onSleep(ms, v.sleeps.length);
    if (s) { const [before, asleep] = s; v.now += Math.max(ms, before + asleep); v.suspended += asleep; } else v.now += ms;
    await null;
  } };
  v.transport = async (origin, request) => {
    v.now += 20;
    for (const s of sends[`${request.method} ${request.path}`] ?? []) v.sent.push({ at: v.awake() + s.delay, seq: v.sent.length + 1, up: s.up });
    return { status: request.path === '/me' ? 200 : 201, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  v.observers = configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`;
    let n = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', witnessRequest: null,
      scope: { operations: ['send'], names: [CRM], actorAttribution: 'none', evidence: 'authoritative', ...forwardRecordOf(c) },
      async start() {}, async stop() {}, markWitnessRequest() {},
      async mark() { return { at: v.awake(), witnessNonce: `nonce-${n++}` }; },
      async collect(from, to) {
        const events = v.sent.filter(s => s.at > from.at && s.at <= to.at).map(s => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId },
          seq: s.seq, observedAt: '2026-10-16T00:00:00.000Z', operation: 'send', name: CRM, resource: CLOSE, outcome: 'committed', content: { content: 'c', resource: CLOSE },
          upstream: { ...structuredClone(s.up), target: { exact: true, query: false } } }));
        return { events, coverage: 'complete', reason: null };
      } };
  });
  return v;
}
async function assess(impl, p, { sends, onSleep } = {}) {
  const v = host({ sends, onSleep });
  const suspendClock = impl.detector({ wall: () => WALL0 + v.now, awake: v.awake, elapsed: () => v.now, timersCountSuspend: true });
  return { v, run: await impl.assess(p, { env: {}, clock: v.clock, transport: v.transport, observerFactory: v.observers, suspendClock }) };
}
// The opted-in clauses (gate A): a presence and an exactly-n clause under upstream "resolved", and an effect.only whose close is judged
// by its outcome. Each check is a POST whose application closes T-1 on CRM, forwarded through the recorder.
const RESOLVED = Object.freeze({ source: 'http-egress', operation: 'send', name: CRM, resource: CLOSE, upstream: 'resolved' });
const EXISTS = { kind: 'effect.exists', select: RESOLVED, semantics: 'agent-write' };
const COUNT1 = { kind: 'effect.count', select: RESOLVED, expected: 1, semantics: 'exactly-n' };
const ONLY = { kind: 'effect.only', expect: [], allow: [], outcomeJudged: [{ source: 'http-egress', operation: 'send', name: CRM, resource: CLOSE }] };
const task = (id, path, effects) => ({ id, title: id, category: 'collateral', severity: 'high', actorId: 'member', method: 'POST', path, body: {}, evidenceRequirement: 'backend',
  assertions: [{ kind: 'status.equals', expected: 201 }], effects });
function target(checks, { H = null } = {}) {
  const p = { id: 'sleep-in-doubt', name: 'Sleep and in-doubt', applicationId: 'sleep-in-doubt', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { member: { principalId: 'member-1' } }, requiredControlIds: ['WHOAMI'],
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', settleMs: 5000, quietMs: 150, witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS },
      destinations: [{ host: CRM, paths: ['/tickets/T-1/close'], forward: { upstream: 'http://127.0.0.1:47103', rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_CRM_PROOF' }, objectPaths: ['POST /tickets/{ticket}/close'] }] }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }, ...checks] };
  if (H) { p.timing = { effectHorizonMs: H, runBudgetMs: TIMING_BOUNDS.runBudgetMs[1] }; p.timing.runBudgetMs = Math.max(TIMING_BOUNDS.runBudgetMs[0], plannedTimingMs(p, { controlPlan: identityControlPlan(p) })); }
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return p;
}
const rowOf = (run, id) => run.results.find(r => r.id === id);
const windowOf = (run, id) => rowOf(run, id).trace[1].data.windows[0];
// Each clause's sealed verdict and operation; every attempt any row's operation record lists.
const clausesOf = (run, id) => rowOf(run, id).trace[1].data.effects.map(e => [e.verdict, e.resolution?.operation ?? null]);
const attemptsOf = run => run.results.flatMap(r => (r.trace[1]?.data?.effects ?? []).flatMap(e => (e.resolution?.attempts ?? []).map(a => ({ check: r.id, ...a }))));
const validated = (p, run) => {
  const expectedSuite = createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
  validateHttpRunEvidence(run, { expectedSuite });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite });
  return run;
};
const reseal = (run, edit) => {
  const forged = structuredClone(run);
  edit(forged);
  for (const row of forged.results) row.evidenceDigest = digest(row.trace.length === 2 ? { evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions } : { evidence: row.trace[0].data, assertions: row.assertions });
  return forged;
};

test('a window a host sleep left partial decides nothing in the in-doubt core: without a plan (host-suspend-wait-short) and under one (effect-horizon-truncated)', async () => {
  assert.ok(IN_DOUBT_LABELS.includes(COLLECTOR_RECORDS['egress-recorder'].label), 'this build admits its check windows to the in-doubt core (gate B)');
  // TASK's application tries to close T-1 100 ms of awake time after TASK's reply; the forwarder's connect never completes.
  const sends = { 'POST /task': [{ delay: 100, up: UP.refused }] };
  // The sleep falls 0.5 s into TASK's own wait: its settle without a plan (the run's first wait), its horizon under one (the second,
  // after the lead-in), and lasts longer than the budget can restore.
  for (const { H, wait, asleep, code, carries } of [{ H: null, wait: 1, asleep: 60000, code: SUSPEND_SHORT, carries: carriesSuspendShort }, { H: 30000, wait: 2, asleep: 100000, code: HORIZON_TRUNCATED, carries: carriesHorizon }]) {
    const p = target([task('TASK', '/task', [EXISTS, COUNT1, ONLY])], { H });
    const awake = await assess(HEAD, p, { sends }), slept = await assess(HEAD, p, { sends, onSleep: (ms, n) => (n === wait ? [500, asleep] : null) });
    for (const r of [awake, slept]) validated(p, r.run);
    assert.equal(slept.v.sleeps[wait - 1], H ?? 5000, 'the sleep falls in TASK\'s own settle or horizon');
    // Awake, the window is complete: the transport record refutes the one attempt, so the operation is refuted and every clause decides on it.
    assert.deepEqual(clausesOf(awake.run, 'TASK'), [['fail', 'refuted'], ['fail', 'refuted'], ['pass', 'refuted']], `awake, ${code}`);
    // Asleep: the same attempt in a window the sleep left partial, so a close the sleep displaced past its end could have applied.
    const w = windowOf(slept.run, 'TASK'), row = rowOf(slept.run, 'TASK');
    assert.deepEqual([w.coverage, w.reason.split(',').includes(code), carries(w), w.events.length], ['partial', true, true, 1], code);
    // r0 still reads the attempt it sees, but no operation is refuted and no clause decides, the effect.only absence included.
    assert.deepEqual(clausesOf(slept.run, 'TASK'), [['missing', 'in-doubt'], ['missing', 'in-doubt'], ['missing', 'in-doubt']], code);
    assert.deepEqual(row.trace[1].data.effects.map(e => e.resolution.attempts.map(a => `${a.fate} by ${a.by}`)), [['refuted by r0'], ['refuted by r0'], ['refuted by r0']]);
    // Awake the row's backend evidence is observed; asleep it is not.
    const backend = r => [rowOf(r, 'TASK').backendEvidence, rowOf(r, 'TASK').assertions.find(a => a.name === BACKEND_ASSERTION).status];
    assert.deepEqual([backend(awake.run), backend(slept.run), row.status], [['observed', 'pass'], ['unavailable', 'inconclusive'], 'inconclusive'], code);
  }
});

test('a check the run stopped after a short wait is never an attempt: no window and no operation record, while the frozen build counts the displaced send as its own', async () => {
  // A's application closes T-1 (a proven applied reply) 4.8 s of awake time after A's reply; a sleep 0.5 s into A's settle, with no spare
  // room to restore it, displaces that close past A's end marks in the frozen build. TASK, opted in, makes no close of its own.
  const A = task('A', '/a', [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: CRM } }]);
  const p = target([A, task('TASK', '/task', [EXISTS, COUNT1])]);
  const sends = { 'POST /a': [{ delay: 4800, up: UP.applied }] };
  for (const asleep of [45000, 50000]) {
    const onSleep = (ms, n) => (n === 1 ? [500, asleep] : null);
    const head = await assess(HEAD, p, { sends, onSleep }), main = await assess(MAIN, p, { sends, onSleep });
    validated(p, head.run);
    assert.ok(windowOf(main.run, 'A').suspend?.shortMs > 0 && carriesSuspendShort(windowOf(main.run, 'A')), `${asleep} ms: the frozen build left A's settle short`);
    // Head goes on into the later checks' time: restored (45 s) or still short (50 s), A is the last check sent either way.
    assert.ok(windowOf(head.run, 'A').suspend?.reserveMs > 0 && stopsRun(windowOf(head.run, 'A').suspend), `${asleep} ms: A's settle took the later checks' time`);
    // Head: TASK is not sent, so it has no window, no clause record and no attempt; no row of the run lists the displaced close.
    const t = rowOf(head.run, 'TASK');
    assert.deepEqual([t.status, t.trace[0].data.notSent, t.trace[0].data.requestAttempted, t.trace.length], ['inconclusive', SUSPEND_STOPPED, false, 1]);
    assert.equal(t.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual, PRECONDITION_REASONS[SUSPEND_STOPPED]);
    assert.deepEqual(attemptsOf(head.run), []);
    // The frozen build sends TASK after A's short settle, and its in-doubt core reads A's displaced close as TASK's own applied attempt.
    assert.deepEqual(attemptsOf(main.run).map(a => `${a.check}: ${a.fate} by ${a.by}`), ['TASK: applied by proof', 'TASK: applied by proof']);
    assert.deepEqual(clausesOf(main.run, 'TASK').map(([, operation]) => operation), ['confirmed', 'confirmed']);
  }
  // With the opt-in declared, the stop is still the validator's own (recomputed from A's sealed window): a changed reason is refused.
  const { run } = await assess(HEAD, p, { sends, onSleep: (ms, n) => (n === 1 ? [500, 50000] : null) });
  validated(p, run);
  for (const to of ['capture-unavailable', RUN_BUDGET_EXHAUSTED]) {
    const forged = reseal(run, r => { const row = rowOf(r, 'TASK'); row.trace[0].data.notSent = to; row.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual = PRECONDITION_REASONS[to]; });
    assert.throws(() => validateHttpRunEvidence(forged), error => error.code === 'invalid-run-evidence', to);
  }
});
