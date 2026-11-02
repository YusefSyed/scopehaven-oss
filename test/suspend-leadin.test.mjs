// Suspend-aware lead-in and stop.
// A host sleep must not move an earlier request's send into a later check's window, where a presence clause would pass on it:
//   (a) under a timing plan the lead-in before an observed check is held in awake time, and a check whose lead-in is still short is
//       not sent, nor any later one (run-budget-exhausted);
//   (b) without a plan, a check whose settle or barrier a sleep left short is the last one sent (host-suspend-run-stopped);
//   (c) an awake clock that moved earlier in the run but reads no movement over a pair past the threshold is a suspend of the
//       whole pair, while one that never moved stays inert;
//   and a second sleep inside an extension is owed again. The frozen side of every comparison is an earlier build's own code
// (test/fixtures/http-connector-61adb01.mjs and suspend-clock-61adb01.mjs). A virtual clock with an injected transport and observer:
// destination hosts are names only and are never resolved or contacted; no socket, no database, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createSuspendDetector, suspendRecord, validSuspendRecord, suspendHeldNote, carriesSuspendShort, SUSPEND_STOPPED, SUSPEND_UNCHECKED_NOTE, SUSPEND_LIMITS } from '../src/suspend-clock.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { runHttpAssessment, HTTP_LIMITS } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, identityControlPlan, PRECONDITION_ASSERTION, PRECONDITION_REASONS, NOT_SENT_REASONS } from '../src/contracts.mjs';
import { plannedTimingMs, TIMING_BOUNDS, HORIZON_TRUNCATED, RUN_BUDGET_EXHAUSTED } from '../src/http-timing.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { guardAdjusted } from './fixtures/allowed-use-guard-moves.mjs';

const frozen = name => import(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));
const mainConnector = await frozen('http-connector-61adb01.mjs'), mainClock = await frozen('suspend-clock-61adb01.mjs');
const HEAD = Object.freeze({ name: 'head', assess: runHttpAssessment, detector: createSuspendDetector });
const MAIN = Object.freeze({ name: 'main', assess: mainConnector.runHttpAssessment, detector: mainClock.createSuspendDetector });

const WALL0 = Date.parse('2026-10-16T20:14:00.000Z');
const PAY = 'pay.example.test', HOOK = 'hooks.example.test';
// A virtual host. `now` is the run's clock, which counts sleep as Node's does on macOS (mach_continuous_time); awake time is now -
// suspended, and the application acts only in awake time. Each request schedules the sends its route declares ("METHOD path" ->
// [{ name, delay }]), `delay` ms of awake time after its reply, tagged with the request that caused it. onSleep(ms, n, v) =>
// [awakeBeforeSleep, asleep] or null: the n-th wait of the run is overlapped by a suspend, and its timer fires at the later of its
// own end and the wake. One authoritative egress observer over PAY and HOOK marks points in awake time.
function host({ sends = {}, onSleep = () => null } = {}) {
  const v = { now: 1000, suspended: 0, sleeps: [], sent: [] };
  v.awake = () => v.now - v.suspended;
  v.clock = { now: () => v.now, sleep: async ms => {
    v.sleeps.push(ms);
    const s = onSleep(ms, v.sleeps.length, v);
    if (s) { const [before, asleep] = s; v.now += Math.max(ms, before + asleep); v.suspended += asleep; } else v.now += ms;
    await null;
  } };
  v.transport = async (origin, request) => {
    v.now += 20;
    const by = `${request.method} ${request.path}`;
    for (const s of sends[by] ?? []) v.sent.push({ at: v.awake() + s.delay, seq: v.sent.length + 1, name: s.name, by });
    return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  v.observers = configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`;
    let n = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [PAY, HOOK], actorAttribution: 'principal', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, markWitnessRequest() {},
      async mark() { return { at: v.awake(), witnessNonce: `nonce-${n++}` }; },
      async collect(from, to) {
        const events = v.sent.filter(s => s.at > from.at && s.at <= to.at).map(s => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: s.seq, operation: 'send', name: s.name, actor: 'owner-1', outcome: 'committed', content: { seq: s.seq } }));
        return { events, coverage: 'complete', reason: null };
      } };
  });
  return v;
}
// real: the awake clock is the virtual host's; inert: the timers count sleep but no awake clock can be read; still: an awake clock
// that never moves (frozen throughout).
const DETECTORS = Object.freeze({
  real: (impl, v) => impl.detector({ wall: () => WALL0 + v.now, awake: v.awake, elapsed: () => v.now, timersCountSuspend: true }),
  inert: (impl, v) => impl.detector({ wall: () => WALL0 + v.now, awake: null, elapsed: () => v.now, timersCountSuspend: true }),
  still: (impl, v) => impl.detector({ wall: () => WALL0 + v.now, awake: () => 5000, elapsed: () => v.now, timersCountSuspend: true }),
});
async function assess(impl, p, { sends, onSleep, detector = 'real', limits = HTTP_LIMITS } = {}) {
  const v = host({ sends, onSleep });
  const run = await impl.assess(p, { env: {}, clock: v.clock, transport: v.transport, observerFactory: v.observers, suspendClock: DETECTORS[detector](impl, v), limits });
  return { v, run };
}
// checks: [{ id, method, path, severity, effects? }], every control required; one egress recorder over PAY and HOOK.
function target(checks, { H = null, perCheck = false, settleMs = 5000, id = 'leadin' } = {}) {
  const p = { id, name: 'Lead-in', applicationId: 'leadin', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { owner: { principalId: 'owner-1' } }, requiredControlIds: checks.filter(c => c.severity === 'control').map(c => c.id),
    observers: [{ id: 'gate', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: PAY }, { host: HOOK }], witness: { actorId: 'owner', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs, quietMs: 150 }],
    checks: checks.map(c => ({ id: c.id, title: c.id, category: c.severity === 'control' ? 'Allowed use' : 'Object access', severity: c.severity, actorId: 'owner', method: c.method, path: c.path, ...(c.method === 'GET' ? {} : { body: {} }),
      evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...(c.effects ? { effects: c.effects } : {}) })) };
  if (perCheck) { Object.assign(p, { settlement: { mode: 'per-check' }, correlation: { header: 'x-request-id' } }); for (const d of p.observers[0].destinations) d.correlation = { header: 'x-request-id' }; }
  if (H) { p.timing = { effectHorizonMs: H, runBudgetMs: TIMING_BOUNDS.runBudgetMs[1] }; p.timing.runBudgetMs = Math.max(TIMING_BOUNDS.runBudgetMs[0], plannedTimingMs(p, { controlPlan: identityControlPlan(p) })); }
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return p;
}
const sel = name => ({ source: 'http-egress', operation: 'send', name });
const ME = Object.freeze({ id: 'ME', method: 'GET', path: '/me', severity: 'control' });
const rowOf = (run, id) => run.results.find(r => r.id === id);
const notSentOf = (run, id) => rowOf(run, id).trace[0].data.notSent ?? null;
// A clause's status: pass, fail or inconclusive, or not-sent for a check the run did not send.
const clauseOf = (run, id, i = 0) => (notSentOf(run, id) ? 'not-sent' : rowOf(run, id).assertions.filter(a => /^Observed effect \d+ /.test(a.name))[i].status);
const windowOf = (run, id) => rowOf(run, id).trace[1].data.windows[0];
// The exported suite each run is bound to. One registry is made per profile (or per
// twenty, the manifest's limit, in the property) and its suites kept.
const suites = new WeakMap();
const suiteOf = p => { if (!suites.has(p)) suites.set(p, createRegistry({ profiles: [p], env: {} }).exportSuite(p.id)); return suites.get(p); };
const validated = (p, run) => { validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) }); validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suiteOf(p) }); return run; };
// A forged run, resealed so only the validator's own rules decide.
const reseal = (run, edit) => {
  const forged = structuredClone(run);
  edit(forged);
  for (const row of forged.results) row.evidenceDigest = digest(row.trace.length === 2 ? { evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions } : { evidence: row.trace[0].data, assertions: row.assertions });
  return forged;
};
const refused = run => assert.throws(() => validateHttpRunEvidence(run), error => error.code === 'invalid-run-evidence');

// (a): H = 30 s; GET /me (unobserved) makes a send to HOOK 25 s of awake time after its reply, and
// REFUND (effect.exists on HOOK) makes none. A sleep in REFUND's lead-in (the run's first wait) used to put ME's send inside
// REFUND's window, where the presence clause passed on it.
test('lead-in, declared timing: a sleep in the lead-in never lets GET /me\'s send decide REFUND; the lead-in is extended in awake time, or REFUND and every later check is cut', async t => {
  const H = 30000, REFUND = { id: 'REFUND', method: 'POST', path: '/refund', severity: 'control', effects: [{ kind: 'effect.exists', select: sel(HOOK) }] };
  const AFTER = { id: 'AFTER', method: 'POST', path: '/after', severity: 'high', effects: [{ kind: 'effect.none', select: sel(PAY) }] };
  const p = target([ME, REFUND, AFTER], { H }), sends = { 'GET /me': [{ name: HOOK, delay: 25000 }] };
  const table = [];
  for (const [before, asleep] of [[0, 0], [1000, 10000], [1000, 40000], [0, 40000], [0, 100000], [1000, 100000], [1000, 150000], [1000, 175000], [0, 175000], [1000, 400000]]) {
    const onSleep = (ms, n) => (asleep && n === 1 ? [before, asleep] : null);
    const head = await assess(HEAD, p, { sends, onSleep }), main = await assess(MAIN, p, { sends, onSleep });
    validated(p, head.run);
    assert.equal(head.v.sleeps[0], H, 'the run\'s first wait is REFUND\'s lead-in');
    const status = clauseOf(head.run, 'REFUND'), was = clauseOf(main.run, 'REFUND');
    table.push(`${before}+${asleep / 1000}s:${status}/${was}`);
    assert.notEqual(status, 'pass', `${asleep} ms asleep ${before} ms into the lead-in: REFUND never passes on ME's send (${table.at(-1)})`);
    if (status === 'not-sent') {
      // A lead-in still short is clipped like one the budget clipped: REFUND and every later check are cut, never merely partial.
      assert.deepEqual([notSentOf(head.run, 'REFUND'), notSentOf(head.run, 'AFTER')], [RUN_BUDGET_EXHAUSTED, RUN_BUDGET_EXHAUSTED]);
      assert.deepEqual(['REFUND', 'AFTER'].map(id => rowOf(head.run, id).status), ['inconclusive', 'inconclusive']);
    } else {
      // Restored: the lead-in held H of awake time since ME's reply, so ME's send landed before REFUND's start mark.
      assert.equal(status, 'fail', table.at(-1));
      assert.deepEqual(windowOf(head.run, 'REFUND').events, []);
      if (asleep) assert.ok(head.v.sleeps[1] > 0 && head.v.sleeps[1] <= H, `the lead-in was extended: ${head.v.sleeps}`);
    }
  }
  // Not vacuous: the frozen build passes REFUND on ME's send, and head both restores lead-ins and cuts the ones it cannot restore.
  assert.ok(table.filter(r => r.endsWith('/pass')).length >= 4, table.join(' '));
  assert.ok(table.some(r => r.includes(':fail/pass')) && table.some(r => r.includes(':not-sent/pass')), table.join(' '));
  t.diagnostic(`lead-in sweep (before+asleep: head/frozen): ${table.join(' ')}`);
});

// (b): run mode, no timing plan. A forbids sends to PAY, and its app also sends to HOOK 4.8 s of awake
// time after its reply; B (effect.exists on HOOK) sends nothing. A 60 s sleep in A's settle used to leave A partial but let B pass on
// A's send. The short check watched a different destination, so settlement did not withhold B either.
test('short settle, no timing plan: after a settle a sleep left short, no later check is sent, so A\'s displaced send never decides B', async t => {
  const A = { id: 'A', method: 'POST', path: '/a', severity: 'high', effects: [{ kind: 'effect.none', select: sel(PAY) }] };
  const B = { id: 'B', method: 'POST', path: '/b', severity: 'control', effects: [{ kind: 'effect.exists', select: sel(HOOK) }] };
  const sends = { 'POST /a': [{ name: HOOK, delay: 4800 }] };
  const table = [];
  for (const perCheck of [false, true]) for (const [before, asleep] of [[500, 60000], [0, 60000], [500, 3000]]) {
    const p = target([ME, A, B], { perCheck }), onSleep = (ms, n) => (n === 1 ? [before, asleep] : null);
    const head = await assess(HEAD, p, { sends, onSleep }), main = await assess(MAIN, p, { sends, onSleep });
    validated(p, head.run);
    const a = windowOf(head.run, 'A'), status = clauseOf(head.run, 'B'), was = clauseOf(main.run, 'B');
    table.push(`${perCheck ? 'per-check' : 'run'} ${before}+${asleep / 1000}s: A ${clauseOf(head.run, 'A')}/${clauseOf(main.run, 'A')} B ${status}/${was}`);
    assert.notEqual(status, 'pass', table.at(-1));
    if (a.suspend?.shortMs > 0) {
      assert.deepEqual([a.coverage, carriesSuspendShort(a), clauseOf(head.run, 'A')], ['partial', true, 'inconclusive'], table.at(-1));
      assert.equal(notSentOf(head.run, 'B'), SUSPEND_STOPPED, 'B is not sent: the run stopped after A');
      const b = rowOf(head.run, 'B');
      assert.deepEqual([b.status, b.assertions.find(x => x.name === PRECONDITION_ASSERTION)?.actual], ['inconclusive', PRECONDITION_REASONS[SUSPEND_STOPPED]]);
      assert.match(b.summary, /host sleep/);
    } else {
      // A short sleep the spare budget restores: A's window held its settle, A's send is in it, and B correctly fails.
      assert.deepEqual([a.coverage, a.events.map(e => e.name), status], ['complete', [HOOK], 'fail'], table.at(-1));
    }
  }
  // The frozen build passes B on A's send in run mode (in per-check mode A's barrier already absorbed it, and head stops there too).
  assert.ok(table.filter(r => r.startsWith('run') && r.endsWith('/pass')).length >= 2, `the frozen build passes B on A's send: ${table.join(' | ')}`);
  t.diagnostic(table.join(' | '));
});

test('short barrier, per-check: a barrier a sleep left short stops the run too, and a run that stopped validates only as the connector wrote it', async () => {
  const A = { id: 'A', method: 'POST', path: '/a', severity: 'high', effects: [{ kind: 'effect.none', select: sel(PAY) }] };
  const B = { id: 'B', method: 'POST', path: '/b', severity: 'control', effects: [{ kind: 'effect.exists', select: sel(HOOK) }] };
  const p = target([ME, A, B], { perCheck: true });
  // The second wait is A's barrier: 60 s asleep in it, with no room left in the default budget to restore it.
  const head = await assess(HEAD, p, { sends: { 'POST /a': [{ name: HOOK, delay: 4800 }] }, onSleep: (ms, n) => (n === 2 ? [500, 60000] : null) });
  validated(p, head.run);
  const barrier = head.run.settlement.barriers[0].windows[0];
  assert.deepEqual([windowOf(head.run, 'A').coverage, windowOf(head.run, 'A').suspend ?? null], ['complete', null], 'A\'s own settle held');
  assert.ok(barrier.suspend?.shortMs > 0 && barrier.coverage === 'partial' && carriesSuspendShort(barrier));
  assert.equal(notSentOf(head.run, 'B'), SUSPEND_STOPPED);

  // Run mode: the stop is recomputed from the sealed windows, so it cannot be moved, dropped or added.
  const C = { id: 'C', method: 'GET', path: '/c', severity: 'low' };
  const q = target([ME, A, B, C]);
  const { run } = await assess(HEAD, q, { sends: { 'POST /a': [{ name: HOOK, delay: 4800 }] }, onSleep: (ms, n) => (n === 1 ? [500, 60000] : null) });
  validated(q, run);
  assert.deepEqual(['B', 'C'].map(id => notSentOf(run, id)), [SUSPEND_STOPPED, SUSPEND_STOPPED]);
  assert.ok(NOT_SENT_REASONS.includes(SUSPEND_STOPPED));
  validateHttpRunEvidence(reseal(run, () => {}));
  const reason = (row, to) => { row.trace[0].data.notSent = to; row.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual = PRECONDITION_REASONS[to]; };
  refused(reseal(run, r => reason(rowOf(r, 'B'), 'capture-unavailable')));
  refused(reseal(run, r => reason(rowOf(r, 'C'), RUN_BUDGET_EXHAUSTED)));
  // A's shortfall dropped with its code and the window stored complete: refused (the row's text and the stop both bind it).
  refused(reseal(run, r => { const w = windowOf(r, 'A'); delete w.suspend.shortMs; w.coverage = 'complete'; w.reason = null; }));
  // The stopped run's own not-sent row C, swapped into another run: into one a different sleep stopped, it validates; into a clean
  // run it is refused, because no sealed shortfall precedes it.
  const clean = await assess(HEAD, q, { sends: { 'POST /a': [{ name: HOOK, delay: 4800 }] } });
  const other = await assess(HEAD, q, { sends: { 'POST /a': [{ name: HOOK, delay: 4800 }] }, onSleep: (ms, n) => (n === 1 ? [0, 90000] : null) });
  for (const r of [clean.run, other.run]) validated(q, r);
  assert.equal(notSentOf(clean.run, 'C'), null);
  const swap = into => reseal(into, r => { r.results[r.results.findIndex(x => x.id === 'C')] = structuredClone(rowOf(run, 'C')); r.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const x of r.results) r.counts[x.status]++; });
  validateHttpRunEvidence(swap(other.run));
  refused(swap(clean.run));
});

// (c), fail closed: a sleep that begins the instant a wait does leaves the awake clock with no
// movement at all across that pair. Where the clock has moved earlier in the run (it is alive), the pair is a suspend of its whole
// length: the wait is extended, and a wait still short reads partial. A clock that never moves stays inert, exactly as the frozen build.
test('still clock, detector: a live awake clock that reads no movement over a pair past the threshold is a suspend of the whole pair; one that never moved is unchecked', () => {
  const h = { awake: 0, elapsed: 0 }, clocks = { wall: () => WALL0 + h.elapsed, awake: () => h.awake, elapsed: () => h.elapsed };
  const d = createSuspendDetector({ ...clocks, timersCountSuspend: true }), at = d.mark();
  h.awake += 20; h.elapsed += 20;
  assert.deepEqual(d.sample(), [], 'the clock moved: it is alive');
  h.elapsed += 60000;
  assert.deepEqual(d.sample().map(b => [b.kind, b.ms]), [['suspend', 60000]], 'no movement at all over 60 s: the whole pair held no awake time');
  assert.equal(d.lostSince(at), 60000);
  assert.equal(d.uncheckedSince(at), 0);
  assert.deepEqual(suspendRecord(d.between(at, d.mark())), { cause: 'host-sleep', count: 1, ms: 60000, from: new Date(WALL0 + 20).toISOString(), to: new Date(WALL0 + 60020).toISOString() });
  h.elapsed += 1500;
  assert.deepEqual(d.sample(), [], 'a short still pair decides nothing');
  // Never moved (frozen throughout, as the frozen build): unchecked, never a suspend, nothing lost.
  const g = { elapsed: 0 }, still = createSuspendDetector({ wall: () => WALL0 + g.elapsed, awake: () => 5000, elapsed: () => g.elapsed, timersCountSuspend: true }), m = still.mark();
  g.elapsed += 60000;
  assert.deepEqual(still.sample().map(b => b.kind), ['unchecked']);
  assert.deepEqual([still.lostSince(m), still.uncheckedSince(m)], [0, 60000]);
  // Where the timers do not count sleep, a still pair is nothing (a wait there already lasts in awake time), as before.
  const linuxLike = createSuspendDetector(clocks);
  linuxLike.sample(); h.awake += 20; h.elapsed += 20; linuxLike.sample(); h.elapsed += 60000;
  assert.deepEqual(linuxLike.sample(), []);
});

test('still clock, connector: a sleep at the exact instant a wait starts gives a partial window, with or without a timing plan; a clock frozen throughout keeps the frozen build\'s verdicts', async t => {
  // FORBID also proves its own send to PAY (a positive clause), so the allowed-use guard leaves its absence clause as the frozen build read it.
  const FORBID = { id: 'FORBID', method: 'POST', path: '/forbid', severity: 'high', effects: [{ kind: 'effect.none', select: sel(HOOK) }, { kind: 'effect.exists', select: sel(PAY) }] };
  // No plan: 60 s asleep from the instant FORBID's settle starts (its first wait), and again from the instant the final settle starts;
  // the default budget has no room to restore either.
  const p = target([ME, FORBID]), sends = { 'POST /forbid': [{ name: HOOK, delay: 4800 }, { name: PAY, delay: 100 }] }, atStart = (asleep, waits = 2) => (ms, n) => (n <= waits ? [0, asleep] : null);
  const head = await assess(HEAD, p, { sends, onSleep: atStart(60000) }), main = await assess(MAIN, p, { sends, onSleep: atStart(60000) });
  validated(p, head.run);
  const w = windowOf(head.run, 'FORBID'), tail = head.run.settlement.gaps.at(-1).windows[0];
  assert.deepEqual([w.coverage, carriesSuspendShort(w), w.suspend.cause, w.suspend.shortMs, Object.hasOwn(w, 'suspendUnchecked')], ['partial', true, 'host-sleep', 5000, false]);
  assert.deepEqual([tail.coverage, carriesSuspendShort(tail)], ['partial', true]);
  assert.equal(clauseOf(head.run, 'FORBID'), 'inconclusive');
  assert.deepEqual([clauseOf(main.run, 'FORBID'), windowOf(main.run, 'FORBID').coverage, windowOf(main.run, 'FORBID').suspendUnchecked], ['pass', 'complete', true], 'the frozen build read the still pairs unchecked and passed on missing evidence');
  // Room to restore it (a 300 s budget): extended by the whole settle, so the send lands in the window and the clause fails.
  const roomy = await assess(HEAD, p, { sends, onSleep: atStart(60000, 1), limits: { ...HTTP_LIMITS, runTimeoutMs: 300000 } });
  assert.deepEqual([roomy.v.sleeps.slice(0, 2), windowOf(roomy.run, 'FORBID').coverage, clauseOf(roomy.run, 'FORBID')], [[5000, 5000], 'complete', 'fail']);

  // Declared timing, at offset 0: H = 30 s, the send 28 s after the reply, asleep 30 to 100 s from the instant
  // the horizon starts. Never a pass; held short, the horizon reads truncated.
  const H = 30000, timed = target([ME, FORBID], { H }), late = { 'POST /forbid': [{ name: HOOK, delay: 28000 }] }, table = [];
  for (const seconds of [30, 40, 60, 80, 100]) {
    const inHorizon = (ms, n, v) => (ms === H && v.sent.length === 1 && !v.cut ? (v.cut = true, [0, seconds * 1000]) : null);
    const now = await assess(HEAD, timed, { sends: late, onSleep: inHorizon }), was = await assess(MAIN, timed, { sends: late, onSleep: inHorizon });
    validated(timed, now.run);
    const held = now.run.timing.rows.find(r => r.id === 'FORBID').waitedMs, status = clauseOf(now.run, 'FORBID');
    table.push(`${seconds}s:${status}/${held}/${clauseOf(was.run, 'FORBID')}`);
    assert.notEqual(status, 'pass', table.at(-1));
    if (held < H) assert.deepEqual([windowOf(now.run, 'FORBID').coverage, windowOf(now.run, 'FORBID').reason.split(',').includes(HORIZON_TRUNCATED)], ['partial', true]);
  }
  assert.ok(table.some(r => r.endsWith('/pass')), `the frozen build passes at offset 0: ${table.join(' ')}`);
  t.diagnostic(`offset-0 horizon sweep (seconds, head status/awake ms held/frozen): ${table.join(' ')}`);

  // Frozen throughout: inert, with verdicts and waits equal to the frozen build's, and the note says why nothing could be checked.
  const inert = await assess(HEAD, p, { sends, onSleep: atStart(60000), detector: 'still' }), mainInert = await assess(MAIN, p, { sends, onSleep: atStart(60000), detector: 'still' });
  validated(p, inert.run);
  assert.deepEqual(inert.v.sleeps, mainInert.v.sleeps);
  assert.deepEqual(inert.run.results.map(r => [r.id, r.status, r.assertions.map(a => a.status)]), mainInert.run.results.map(r => [r.id, r.status, r.assertions.map(a => a.status)]));
  assert.deepEqual([clauseOf(inert.run, 'FORBID'), windowOf(inert.run, 'FORBID').suspendUnchecked], ['pass', true]);
  const effect = rowOf(inert.run, 'FORBID').assertions.find(a => a.name === 'Observed effect 1 (effect.none)');
  assert.ok(effect.actual.endsWith(SUSPEND_UNCHECKED_NOTE));
  assert.match(SUSPEND_UNCHECKED_NOTE, /none could be read, or it never moved/);
});

// The extension (the settle extension's machinery, reused by the lead-in): a second sleep inside an extension step took awake time from it too, and
// is owed again. The frozen build capped the whole extension at what the first sleep took, so the wait held less than declared and read complete.
test('extension: a second sleep inside the extension is owed again, so the wait holds its declared awake time or reads short', async () => {
  const A = { id: 'A', method: 'POST', path: '/a', severity: 'high', effects: [{ kind: 'effect.none', select: sel(HOOK) }] };
  const B = { id: 'B', method: 'POST', path: '/b', severity: 'control', effects: [{ kind: 'effect.exists', select: sel(HOOK) }] };
  const p = target([ME, A, B]), sends = { 'POST /a': [{ name: HOOK, delay: 4800 }] };
  // A's settle (5000 ms) loses 3000 ms to a sleep 1000 ms in; the extension's first step (3000 ms) loses 2500 ms to a second sleep.
  const onSleep = (ms, n) => (n === 1 ? [1000, 3000] : n === 2 ? [500, 2500] : null);
  const head = await assess(HEAD, p, { sends, onSleep, limits: { ...HTTP_LIMITS, runTimeoutMs: 120000 } }), main = await assess(MAIN, p, { sends, onSleep, limits: { ...HTTP_LIMITS, runTimeoutMs: 120000 } });
  validated(p, head.run);
  assert.deepEqual(head.v.sleeps.slice(0, 3), [5000, 3000, 2500], 'owed again: 2500 ms more');
  assert.deepEqual(main.v.sleeps.slice(0, 3), [5000, 3000, 2000], 'the frozen build: capped at the first sleep\'s 3000 ms, 500 ms of awake time short');
  assert.deepEqual([clauseOf(head.run, 'A'), windowOf(head.run, 'A').coverage, clauseOf(head.run, 'B')], ['fail', 'complete', 'fail']);
  assert.deepEqual([clauseOf(main.run, 'A'), clauseOf(main.run, 'B')], ['inconclusive', 'pass'], 'the frozen build: A\'s send was displaced into B\'s window, where B passed on it');
  assert.deepEqual([windowOf(main.run, 'A').coverage, windowOf(main.run, 'A').events, windowOf(main.run, 'B').events.map(e => e.name)], ['complete', [], [HOOK]]);
  // With no room for the second step, the wait reads short and the run stops.
  const tight = await assess(HEAD, p, { sends, onSleep: (ms, n) => (n === 1 ? [1000, 3000] : n === 2 ? [500, 60000] : null) });
  validated(p, tight.run);
  assert.deepEqual([windowOf(tight.run, 'A').coverage, clauseOf(tight.run, 'A'), notSentOf(tight.run, 'B')], ['partial', 'inconclusive', SUSPEND_STOPPED]);
});

// Nits 4 to 6: records the connector never writes are refused; a discontinuity's note does not say the waits held; every record
// suspendRecord writes is sealable, so none is dropped (nor its shortfall) and none fails a run.
test('nits 4 to 6: suspend records only where the connector writes them, a note per cause, and every record sealable', async () => {
  const A = { id: 'A', method: 'POST', path: '/a', severity: 'high', effects: [{ kind: 'effect.none', select: sel(PAY) }] };
  const B = { id: 'B', method: 'POST', path: '/b', severity: 'control', effects: [{ kind: 'effect.exists', select: sel(HOOK) }] };
  const p = target([ME, A, B]), sends = { 'POST /b': [{ name: HOOK, delay: 1000 }] };
  // 3000 ms asleep in A's settle, restored: A's window carries a record; the run validates.
  const { run } = await assess(HEAD, p, { sends, onSleep: (ms, n) => (n === 1 ? [1000, 3000] : null) });
  validated(p, run);
  const record = windowOf(run, 'A').suspend;
  assert.ok(validSuspendRecord(record) && !Object.hasOwn(record, 'shortMs'));
  validateHttpRunEvidence(reseal(run, () => {}));
  refused(reseal(run, r => { r.settlement.gaps[1].windows[0].suspend = { ...record }; }));
  refused(reseal(run, r => { r.settlement.gaps.at(-1).windows[0].suspendUnchecked = true; }));
  refused(reseal(run, r => { r.settlement.gaps[0].windows[0].suspendUnchecked = true; }));
  // Under a timing plan a shortfall is sealed in the timing record, never on a window.
  const H = 10000, timed = target([ME, A, B], { H, settleMs: 5000 });
  const t1 = await assess(HEAD, timed, { sends, onSleep: (ms, n, v) => (ms === H && !v.cut ? (v.cut = true, [1000, 3000]) : null) });
  validated(timed, t1.run);
  const shortened = w => { w.suspend = { ...(w.suspend ?? { cause: 'host-sleep', count: 1, ms: 3000, from: '2026-10-16T20:14:01.000Z', to: '2026-10-16T20:14:04.000Z' }), shortMs: 1000 }; w.coverage = 'partial'; w.reason = 'host-suspend-wait-short'; delete w.scoped; };
  refused(reseal(t1.run, r => shortened(r.settlement.gaps.at(-1).windows[0])));
  // A discontinuity is never counted as lost time, so its note does not say the waits held.
  const disc = { cause: 'clock-discontinuity', count: 1, ms: 30000, from: '2026-10-16T20:14:00.000Z', to: '2026-10-16T20:14:30.000Z' };
  assert.doesNotMatch(suspendHeldNote(disc), /held their declared awake time/);
  assert.match(suspendHeldNote(disc), /not counted as lost awake time, so its waits may have held less awake time than declared/);
  assert.match(suspendHeldNote({ ...disc, cause: 'host-sleep' }), /its waits held their declared awake time/);
  // A wall clock outside the years a record can state is clamped into them, so the record and its shortfall are kept.
  for (const wall of [Date.parse('9999-12-31T23:59:59.000Z') + 5000, 8.64e15 + 1, -8.64e15 - 1]) {
    const r = suspendRecord([{ kind: 'suspend', ms: 60000, from: { wall, awake: 0, elapsed: 0 }, to: { wall: wall + 60000, awake: 0, elapsed: 60000 } }], { shortMs: 2500 });
    assert.ok(validSuspendRecord(r), JSON.stringify(r));
    assert.equal(r.shortMs, 2500);
  }
  assert.ok(SUSPEND_LIMITS.breaks >= 1);
});

// Property, against the frozen build's own code: seeded random runs, each made four ways (head and the frozen build, each with the real
// detector and with the inert one). The virtual host knows the truth: each check's own application sends, every one of them within
// its declared settle or horizon in awake time (an unobserved request's sends only under a timing plan, whose lead-in is meant to
// separate them). So with the real detector a clause head decides must agree with what the check's own request caused; every move
// from the frozen build is toward inconclusive (pass or fail to inconclusive, or a check not sent), or from a verdict the frozen build got wrong, or left
// undecided, to the true one; never an undecided clause to a wrong verdict. With the inert detector head is exactly the frozen build. The host
// sleeps either in the n-th wait of the run (at its very start or inside it), or at fixed instants of the application's awake time
// (in the wait under way then, or from the start of the next one), which head and the frozen build share until their waits first differ.
const UNDECIDED = ['inconclusive', 'not-sent'];
function scenario(seed, id) {
  let s = seed >>> 0;
  const rand = () => { s = (s + 0x6d2b79f5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const pick = list => list[Math.floor(rand() * list.length)], int = (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));
  const H = rand() < 0.5 ? pick([5000, 10000, 30000]) : null, perCheck = rand() < 0.35;
  const settleMs = H ? pick([2500, 5000].filter(ms => ms <= H)) : pick([2500, 5000]), span = H ?? settleMs;
  const delay = () => Math.round(span * (0.05 + 0.85 * rand()));
  const checks = [ME], sends = {}, truth = new Map();
  if (H && rand() < 0.6) sends['GET /me'] = [{ name: pick([PAY, HOOK]), delay: delay() }];
  const observed = int(1, 3);
  for (let k = 1; k <= observed; k++) {
    if (H && rand() < 0.3) { const id = `G${k}`; checks.push({ id, method: 'GET', path: `/g${k}`, severity: 'low' }); if (rand() < 0.7) sends[`GET /g${k}`] = [{ name: pick([PAY, HOOK]), delay: delay() }]; }
    const id = `C${k}`, control = rand() < 0.4, own = Array.from({ length: int(0, 2) }, () => ({ name: pick([PAY, HOOK]), delay: delay() }));
    const clause = kind => (kind === 'effect.count' ? { kind, select: sel(pick([PAY, HOOK])), expected: int(0, 2) } : { kind, select: sel(pick([PAY, HOOK])) });
    const effects = control ? [clause('effect.exists'), ...(rand() < 0.4 ? [clause(pick(['effect.none', 'effect.count']))] : [])] : Array.from({ length: int(1, 2) }, () => clause(pick(['effect.none', 'effect.exists', 'effect.count'])));
    checks.push({ id, method: 'POST', path: `/c${k}`, severity: control ? 'control' : 'high', effects });
    if (own.length) sends[`POST /c${k}`] = own;
    const count = name => own.filter(o => o.name === name).length;
    truth.set(id, effects.map(e => (e.kind === 'effect.none' ? (count(e.select.name) ? 'fail' : 'pass') : e.kind === 'effect.exists' ? (count(e.select.name) ? 'pass' : 'fail') : (count(e.select.name) === e.expected ? 'pass' : 'fail'))));
  }
  const asleep = () => pick([2500, 4000, 9000, 20000, 45000, 90000, 150000]), byWait = rand() < 0.5;
  // onSleep() makes a fresh schedule for each run.
  let onSleep, plan;
  if (byWait) {
    const sleeps = new Map(Array.from({ length: int(0, 3) }, () => [int(1, 9), { at: pick(['start', 'start', 'inside']), f: rand(), asleep: asleep() }]));
    onSleep = () => (ms, n) => { const z = sleeps.get(n); return z ? [z.at === 'start' ? 0 : Math.round(z.f * ms), z.asleep] : null; };
    plan = `waits ${[...sleeps].map(([n, z]) => `${n}:${z.at}:${z.asleep}`).join(' ')}`;
  } else {
    const awakeSpan = observed * (H ? 2 * H : settleMs) + settleMs, sleeps = Array.from({ length: int(0, 3) }, () => ({ at: 1000 + Math.round(rand() * awakeSpan), asleep: asleep() })).sort((a, b) => a.at - b.at);
    onSleep = () => { const due = sleeps.map(z => ({ ...z })); return (ms, n, v) => { const z = due.find(x => !x.done && x.at < v.awake() + ms); if (!z) return null; z.done = true; return [Math.max(0, z.at - v.awake()), z.asleep]; }; };
    plan = `awake ${sleeps.map(z => `${z.at}:${z.asleep}`).join(' ')}`;
  }
  const limits = { ...HTTP_LIMITS, runTimeoutMs: pick([60000, 120000, 300000]) };
  return { p: target(checks, { H, perCheck, settleMs, id }), sends, onSleep, limits, truth, label: `${H ? `H${H}` : `settle${settleMs}`} ${perCheck ? 'per-check' : 'run'} ${checks.map(c => c.id).join(',')} ${plan}` };
}
const clausesOf = (run, truth) => [...truth.keys()].flatMap(id => truth.get(id).map((_, i) => ({ id, i, status: clauseOf(run, id, i) })));

test('property (480 seeded runs against the frozen build\'s own code, real and inert detectors): every move is toward inconclusive or to the true verdict, never an undecided clause to a wrong one; inert is the frozen build', async t => {
  const moves = new Map(), count = key => moves.set(key, (moves.get(key) ?? 0) + 1);
  let mainWrong = 0, mainWrongPass = 0, headDecided = 0, stops = 0, leadCuts = 0, inertSame = 0;
  const scenarios = Array.from({ length: 480 }, (_, k) => scenario(0x4f4c0000 + k, `leadin-${k}`));
  for (let b = 0; b < scenarios.length; b += 20) {
    const batch = scenarios.slice(b, b + 20), registry = createRegistry({ profiles: batch.map(c => c.p), env: {} });
    for (const c of batch) suites.set(c.p, registry.exportSuite(c.p.id));
  }
  for (let k = 0; k < scenarios.length; k++) {
    const c = scenarios[k];
    const options = { sends: c.sends, limits: c.limits };
    const head = await assess(HEAD, c.p, { ...options, onSleep: c.onSleep() }), main = await assess(MAIN, c.p, { ...options, onSleep: c.onSleep() });
    const headInert = await assess(HEAD, c.p, { ...options, onSleep: c.onSleep(), detector: 'inert' }), mainInert = await assess(MAIN, c.p, { ...options, onSleep: c.onSleep(), detector: 'inert' });
    for (const r of [head.run, headInert.run]) validateHttpRunEvidence(r, { expectedSuite: suiteOf(c.p) });
    // Inert: the waits and every verdict exactly the frozen build's, but for the allowed-use guard's moves (an unguarded absence's pass
    // reads inconclusive; test/fixtures/allowed-use-guard-moves.mjs).
    assert.deepEqual(headInert.v.sleeps, mainInert.v.sleeps, `${k} ${c.label}: inert waits`);
    assert.deepEqual(headInert.run.results.map(r => [r.id, r.status, r.assertions.map(a => a.status)]), guardAdjusted(headInert.run, mainInert.run).map(r => [r.id, r.status, r.assertions.map(a => a.status)]), `${k} ${c.label}: inert verdicts`);
    inertSame++;
    // Real: a clause head decides is the truth; every move from the frozen build is toward inconclusive or to the truth.
    const now = clausesOf(head.run, c.truth), was = clausesOf(main.run, c.truth);
    now.forEach((x, j) => {
      const truth = c.truth.get(x.id)[x.i], before = was[j].status;
      if (!UNDECIDED.includes(x.status)) { headDecided++; assert.equal(x.status, truth, `${k} ${c.label}: head decided ${x.id} clause ${x.i + 1} against the truth (the frozen build ${before})`); }
      if (!UNDECIDED.includes(before) && before !== truth) { mainWrong++; if (before === 'pass') mainWrongPass++; }
      if (x.status !== before) {
        assert.ok(UNDECIDED.includes(x.status) || x.status === truth, `${k} ${c.label}: ${before} -> ${x.status}`);
        count(`${before} -> ${x.status}${UNDECIDED.includes(x.status) ? '' : UNDECIDED.includes(before) ? ' (undecided to the truth)' : ' (the frozen build wrong, head true)'}`);
      } else count(`${before} -> ${x.status}`);
    });
    if (head.run.results.some(r => r.trace[0].data.notSent === SUSPEND_STOPPED)) stops++;
    if (head.run.results.some(r => r.trace[0].data.notSent === RUN_BUDGET_EXHAUSTED) && !main.run.results.some(r => r.trace[0].data.notSent === RUN_BUDGET_EXHAUSTED)) leadCuts++;
  }
  t.diagnostic(`the frozen build -> head clause moves (real detector): ${[...moves].sort().map(([key, n]) => `${key}: ${n}`).join('; ')}`);
  t.diagnostic(`the frozen build decided against the truth ${mainWrong} times (${mainWrongPass} passes); head decided ${headDecided} clauses, none against it; ${stops} runs stopped after a short wait; ${leadCuts} runs cut where the frozen build sent every check; inert equal to the frozen build in ${inertSame} of 480`);
  // Not vacuous: the frozen build is wrong somewhere, head stops and cuts runs, and head still decides most clauses.
  assert.ok(mainWrongPass >= 5 && stops >= 10 && leadCuts >= 5 && headDecided > 500, `${mainWrongPass} ${stops} ${leadCuts} ${headDecided}`);
  assert.ok([...moves.keys()].some(key => key.startsWith('pass -> inconclusive') || key.startsWith('pass -> not-sent')) && [...moves.keys()].some(key => key.startsWith('fail -> inconclusive') || key.startsWith('fail -> not-sent')), [...moves.keys()].join('; '));
});
