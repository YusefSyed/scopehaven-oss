// Suspend follow-ups to the suspend-aware lead-in and stop: the time kept for later checks, the not-sent wording from one table,
// and an unreadable awake reading.
//   1. Without a timing plan, a check's settle or barrier the spare budget could not restore goes on into the time kept for later
//      checks. A wait that this restores held its declared awake time, so its check is decided; one it does not restore reads partial;
//      either way every later check is not sent (host-suspend-run-stopped), and the validator derives that stop from the sealed record
//      (reserveMs). A restored wait always held its full declared awake time (checked against the virtual host's own clock).
//   2. A row not sent is worded from one table; its summary, label and remediation are byte-identical to the frozen build for every reason.
//   3. A timed run a host sleep cut (a lead-in, horizon or barrier the budget could not make up) is worded as such; its reason stays
//      run-budget-exhausted, the one the validator derives.
//   4. An awake clock already seen to move that gives no usable reading over a pair past the threshold is a suspend of that pair;
//      one that never moved stays inert, exactly as the frozen build.
// The frozen side of every comparison is an earlier build's own code (test/fixtures/http-connector-ff3a980.mjs and
// suspend-clock-ff3a980.mjs). A virtual clock with an injected transport and observer: destination hosts are names only and are never
// resolved or contacted; no socket, no database, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createSuspendDetector, suspendRecord, validSuspendRecord, suspendHeldNote, stopsRun, carriesSuspendShort, SUSPEND_STOPPED } from '../src/suspend-clock.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { runHttpAssessment, NOT_SENT_TEXT, HTTP_LIMITS } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, identityControlPlan, PRECONDITION_ASSERTION, PRECONDITION_REASONS, NOT_SENT_REASONS } from '../src/contracts.mjs';
import { plannedTimingMs, TIMING_BOUNDS, HORIZON_TRUNCATED, RUN_BUDGET_EXHAUSTED } from '../src/http-timing.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { guardAdjusted, guardMoves } from './fixtures/allowed-use-guard-moves.mjs';

const frozen = name => import(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));
const mainConnector = await frozen('http-connector-ff3a980.mjs'), mainClock = await frozen('suspend-clock-ff3a980.mjs');
const HEAD = Object.freeze({ name: 'head', assess: runHttpAssessment, detector: createSuspendDetector });
const MAIN = Object.freeze({ name: 'main', assess: mainConnector.runHttpAssessment, detector: mainClock.createSuspendDetector });

const WALL0 = Date.parse('2026-10-16T21:30:00.000Z');
const PAY = 'pay.example.test', HOOK = 'hooks.example.test';
// A virtual host, as in test/suspend-leadin.test.mjs. `now` is the run's clock, which counts sleep as Node's does on macOS; awake time
// is now - suspended, and the application acts only in awake time. Each request schedules the sends its route declares ("METHOD path"
// -> [{ name, delay }]), `delay` ms of awake time after its reply. onSleep(ms, n, v) => [awakeBeforeSleep, asleep] or null: the n-th
// wait of the run is overlapped by a suspend, and its timer fires at the later of its own end and the wake. One authoritative egress
// observer over PAY and HOOK marks points in awake time, and the host logs every mark and collect, so a test can measure how much
// awake time each window physically held. After each sleep the next awake reading is unusable for the 'flaky' detector only. slow:
// "METHOD path" -> extra awake ms a request of that route takes (a slow application, with no sleep).
function host({ sends = {}, onSleep = () => null, slow = {} } = {}) {
  const v = { now: 1000, suspended: 0, sleeps: [], sent: [], marks: [], collected: [], unreadable: 0 };
  v.awake = () => v.now - v.suspended;
  v.clock = { now: () => v.now, sleep: async ms => {
    v.sleeps.push(ms);
    const s = onSleep(ms, v.sleeps.length, v);
    if (s) { const [before, asleep] = s; v.now += Math.max(ms, before + asleep); v.suspended += asleep; v.unreadable = 1; } else v.now += ms;
    await null;
  } };
  v.transport = async (origin, request) => {
    const by = `${request.method} ${request.path}`;
    v.now += 20 + (slow[by] ?? 0);
    for (const s of sends[by] ?? []) v.sent.push({ at: v.awake() + s.delay, seq: v.sent.length + 1, name: s.name, by });
    return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  v.observers = configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [PAY, HOOK], actorAttribution: 'principal', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, markWitnessRequest() {},
      async mark() { const m = { at: v.awake(), witnessNonce: `nonce-${v.marks.length}`, id: v.marks.length }; v.marks.push(m.at); return m; },
      async collect(from, to, options = {}) {
        v.collected.push({ from: from.id, to: to.id, gap: options.gap === true });
        const events = v.sent.filter(s => s.at > from.at && s.at <= to.at).map(s => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: s.seq, operation: 'send', name: s.name, actor: 'owner-1', outcome: 'committed', content: { seq: s.seq } }));
        return { events, coverage: 'complete', reason: null };
      } };
  });
  return v;
}
// real: the host's own awake clock; flaky: the same clock, unreadable once after each sleep; inert: no awake clock; still: an awake
// clock that never moves; nan: an awake clock that never gives a usable reading.
const DETECTORS = Object.freeze({
  real: (impl, v) => impl.detector({ wall: () => WALL0 + v.now, awake: v.awake, elapsed: () => v.now, timersCountSuspend: true }),
  flaky: (impl, v) => impl.detector({ wall: () => WALL0 + v.now, awake: () => (v.unreadable > 0 ? (v.unreadable -= 1, NaN) : v.awake()), elapsed: () => v.now, timersCountSuspend: true }),
  inert: (impl, v) => impl.detector({ wall: () => WALL0 + v.now, awake: null, elapsed: () => v.now, timersCountSuspend: true }),
  still: (impl, v) => impl.detector({ wall: () => WALL0 + v.now, awake: () => 5000, elapsed: () => v.now, timersCountSuspend: true }),
  nan: (impl, v) => impl.detector({ wall: () => WALL0 + v.now, awake: () => NaN, elapsed: () => v.now, timersCountSuspend: true }),
});
async function assess(impl, p, { sends, onSleep, slow, detector = 'real', limits = HTTP_LIMITS } = {}) {
  const v = host({ sends, onSleep, slow });
  const run = await impl.assess(p, { env: {}, clock: v.clock, transport: v.transport, observerFactory: v.observers, suspendClock: DETECTORS[detector](impl, v), limits });
  return { v, run };
}
// checks: [{ id, method, path, severity, effects? }], every control required; one egress recorder over PAY and HOOK.
function target(checks, { H = null, perCheck = false, settleMs = 5000, id = 'f4d' } = {}) {
  const p = { id, name: 'F4d', applicationId: 'f4d', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
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
const clausesOfRow = (run, id) => (notSentOf(run, id) ? ['not-sent'] : rowOf(run, id).assertions.filter(a => /^Observed effect \d+ /.test(a.name)).map(a => a.status));
const windowOf = (run, id) => rowOf(run, id).trace[1].data.windows[0];
const suites = new WeakMap();
const suiteOf = p => { if (!suites.has(p)) suites.set(p, createRegistry({ profiles: [p], env: {} }).exportSuite(p.id)); return suites.get(p); };
const validated = (p, run) => { validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) }); validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suiteOf(p) }); return run; };
// A forged run, resealed so only the validator's own rules decide.
const reseal = (run, edit) => {
  const forged = structuredClone(run);
  edit(forged);
  for (const row of forged.results) row.evidenceDigest = digest(row.trace.length === 2 ? { evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions } : { evidence: row.trace[0].data, assertions: row.assertions });
  forged.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 };
  for (const row of forged.results) forged.counts[row.status]++;
  return forged;
};
const refused = run => assert.throws(() => validateHttpRunEvidence(run), error => error.code === 'invalid-run-evidence');
// What the host measured: per sent observed check (in order), the awake time its window held after the reply (its start mark, then
// the 20 ms request), and per barrier the awake time from the check's end mark to the barrier mark.
function heldOf(v) {
  const own = v.collected.filter(c => !c.gap), ends = new Set(own.map(c => c.to));
  return { checks: own.map(c => v.marks[c.to] - v.marks[c.from] - 20), barriers: v.collected.filter(c => c.gap && ends.has(c.from)).map(c => v.marks[c.to] - v.marks[c.from]) };
}

// Without a plan the reserve laterNeedMs keeps for later checks was never used, so a settle the spare
// budget could not restore read partial (and its check inconclusive) even when the run had room. Run mode, settle 5 s, the default
// budget (60 s). A's application sends to HOOK 4.8 s of awake time after its reply and never to PAY; B would pass on its own send.
const A = Object.freeze({ id: 'A', method: 'POST', path: '/a', severity: 'high', effects: [{ kind: 'effect.none', select: sel(HOOK) }, { kind: 'effect.none', select: sel(PAY) }] });
const B = Object.freeze({ id: 'B', method: 'POST', path: '/b', severity: 'control', effects: [{ kind: 'effect.exists', select: sel(HOOK) }] });
const C = Object.freeze({ id: 'C', method: 'GET', path: '/c', severity: 'low' });
const SENDS = Object.freeze({ 'POST /a': [{ name: HOOK, delay: 4800 }], 'POST /b': [{ name: HOOK, delay: 1000 }] });

test('reserve, settle: a wait restored from the later checks\' time is decided and still stops the run; one it cannot restore reads partial and stops it', async t => {
  const p = target([ME, A, B, C]), table = [];
  for (const asleep of [3000, 45000, 50000, 60000]) {
    const onSleep = (ms, n) => (n === 1 ? [500, asleep] : null);
    const head = await assess(HEAD, p, { sends: SENDS, onSleep }), main = await assess(MAIN, p, { sends: SENDS, onSleep });
    validated(p, head.run);
    const w = windowOf(head.run, 'A'), was = windowOf(main.run, 'A'), held = heldOf(head.v).checks[0];
    const label = `${asleep / 1000}s: head ${clausesOfRow(head.run, 'A')} reserve ${w.suspend?.reserveMs ?? 0} short ${w.suspend?.shortMs ?? 0} held ${held}; the frozen build ${clausesOfRow(main.run, 'A')} short ${was.suspend?.shortMs ?? 0}`;
    table.push(label);
    // The run stops exactly as the frozen build's does: the same rows, with the same reason.
    assert.deepEqual(['B', 'C'].map(id => notSentOf(head.run, id)), ['B', 'C'].map(id => notSentOf(main.run, id)), label);
    if (asleep === 3000) {
      // The spare budget restored it: no reserve taken, nothing stops.
      assert.deepEqual([w.coverage, Object.hasOwn(w.suspend, 'reserveMs'), clausesOfRow(head.run, 'A'), clauseOf(head.run, 'B')], ['complete', false, ['fail', 'pass'], 'pass'], label);
      continue;
    }
    assert.ok(w.suspend.reserveMs === 5000 && stopsRun(w.suspend), label);
    assert.deepEqual(['B', 'C'].map(id => notSentOf(head.run, id)), [SUSPEND_STOPPED, SUSPEND_STOPPED], label);
    if (!(w.suspend.shortMs > 0)) {
      // Restored from the later checks' time: A's window held its full settle, its own send is in it, and A is decided on it: the
      // forbidden send fails the HOOK clause, and the PAY absence passes on complete coverage, naming why the run stopped.
      assert.deepEqual([w.coverage, w.events.map(e => e.name), clausesOfRow(head.run, 'A')], ['complete', [HOOK], ['fail', 'pass']], label);
      assert.ok(held >= 5000, `the window held its declared settle in awake time: ${label}`);
      assert.ok(rowOf(head.run, 'A').assertions.find(a => a.name === 'Observed effect 2 (effect.none)').actual.endsWith(suspendHeldNote(w.suspend)));
      assert.match(suspendHeldNote(w.suspend), /took the time kept for later checks .* so no later check was sent\.$/);
      // The frozen build read the same wait short, so A was undecided there.
      assert.deepEqual([was.coverage, was.suspend.shortMs, clausesOfRow(main.run, 'A')], ['partial', 5000, ['inconclusive', 'inconclusive']], label);
    } else {
      // Not restored: partial, with the shortfall; a recorded match still decides, and the absence does not.
      assert.ok(held < 5000 && w.suspend.shortMs <= w.suspend.reserveMs, label);
      assert.deepEqual([w.coverage, carriesSuspendShort(w), clauseOf(head.run, 'A', 1)], ['partial', true, 'inconclusive'], label);
    }
  }
  t.diagnostic(table.join(' | '));
  assert.ok(table.some(r => r.includes('reserve 5000 short 0')) && table.some(r => /reserve 5000 short [1-9]/.test(r)), table.join(' | '));
  // A second sleep inside the later checks' time takes awake time from it too, and is owed again: 3 s asleep 1 s into its first step
  // (the run's second wait) leaves 3 s more to hold, and the window holds its full settle.
  const twice = await assess(HEAD, p, { sends: SENDS, onSleep: (ms, n) => (n === 1 ? [500, 45000] : n === 2 ? [1000, 3000] : null) });
  validated(p, twice.run);
  const w = windowOf(twice.run, 'A');
  assert.deepEqual([twice.v.sleeps.slice(0, 3), w.coverage, w.suspend.reserveMs, Object.hasOwn(w.suspend, 'shortMs'), clausesOfRow(twice.run, 'A'), notSentOf(twice.run, 'B')], [[5000, 5000, 3000], 'complete', 5000, false, ['fail', 'pass'], SUSPEND_STOPPED]);
  assert.ok(heldOf(twice.v).checks[0] >= 5000, `held ${heldOf(twice.v).checks[0]}`);
});

test('reserve, per-check barrier: a barrier restored from the later checks\' time stops the run, and the validator recomputes that stop', async () => {
  const p = target([ME, A, B, C], { perCheck: true });
  // The second wait is A's barrier.
  for (const [asleep, restored] of [[45000, true], [70000, false]]) {
    const head = await assess(HEAD, p, { sends: SENDS, onSleep: (ms, n) => (n === 2 ? [500, asleep] : null) });
    const main = await assess(MAIN, p, { sends: SENDS, onSleep: (ms, n) => (n === 2 ? [500, asleep] : null) });
    validated(p, head.run);
    const barrier = head.run.settlement.barriers[0].windows[0], held = heldOf(head.v).barriers[0];
    assert.equal(windowOf(head.run, 'A').coverage, 'complete', 'A\'s own settle held');
    assert.ok(barrier.suspend.reserveMs > 0 && stopsRun(barrier.suspend));
    assert.deepEqual([barrier.coverage, Object.hasOwn(barrier.suspend, 'shortMs'), held >= 5000], restored ? ['complete', false, true] : ['partial', true, false]);
    assert.deepEqual(['B', 'C'].map(id => notSentOf(head.run, id)), [SUSPEND_STOPPED, SUSPEND_STOPPED]);
    assert.deepEqual(['B', 'C'].map(id => notSentOf(main.run, id)), [SUSPEND_STOPPED, SUSPEND_STOPPED]);
    assert.equal(main.run.settlement.barriers[0].windows[0].coverage, 'partial');
    // The barrier's reserve dropped: no stop is derived, so the not-sent rows are refused.
    refused(reseal(head.run, r => { delete r.settlement.barriers[0].windows[0].suspend.reserveMs; if (restored) return; delete r.settlement.barriers[0].windows[0].suspend.shortMs; r.settlement.barriers[0].windows[0].coverage = 'complete'; r.settlement.barriers[0].windows[0].reason = null; }));
  }
});

// A's record replaced, with the held note of its decided rows reworded as the validator recomputes it, so only the stop can refuse it.
const withRecord = (run, edit) => reseal(run, r => {
  const w = windowOf(r, 'A'), before = suspendHeldNote(w.suspend);
  w.suspend = edit({ ...w.suspend });
  for (const a of rowOf(r, 'A').assertions) if (typeof a.actual === 'string' && a.actual.endsWith(before)) a.actual = a.actual.slice(0, -before.length) + suspendHeldNote(w.suspend);
});

test('reserve, validator: the stop is derived from the sealed reserve, which cannot be dropped, added, moved or written where the connector never writes it', async () => {
  const p = target([ME, A, B, C]);
  const { run } = await assess(HEAD, p, { sends: SENDS, onSleep: (ms, n) => (n === 1 ? [500, 45000] : null) });
  // A 3 s sleep the spare budget restored: a record with no reserve, and B and C sent.
  const spare = (await assess(HEAD, p, { sends: SENDS, onSleep: (ms, n) => (n === 1 ? [500, 3000] : null) })).run;
  for (const r of [run, spare]) validated(p, r);
  const record = windowOf(run, 'A').suspend;
  assert.ok(validSuspendRecord(record) && record.reserveMs === 5000 && !Object.hasOwn(record, 'shortMs'));
  assert.ok(windowOf(spare, 'A').suspend && !stopsRun(windowOf(spare, 'A').suspend) && notSentOf(spare, 'B') === null);
  validateHttpRunEvidence(reseal(run, () => {}));
  // The rewording itself is sound: a different reserve that still stops the run validates.
  validateHttpRunEvidence(withRecord(run, r => ({ ...r, reserveMs: 4000 })));
  // Dropped: B and C read stopped with no stop derived.
  refused(withRecord(run, ({ reserveMs, ...r }) => r));
  // Added to a run whose A restored within the spare budget: a stop is derived, but B and C were sent.
  validateHttpRunEvidence(withRecord(spare, r => r));
  refused(withRecord(spare, r => ({ ...r, reserveMs: 1 })));
  refused(reseal(spare, r => { r.results[r.results.findIndex(x => x.id === 'C')] = structuredClone(rowOf(run, 'C')); }));
  // B's reason changed.
  const reason = (row, to) => { row.trace[0].data.notSent = to; row.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual = PRECONDITION_REASONS[to]; };
  refused(reseal(run, r => reason(rowOf(r, 'B'), RUN_BUDGET_EXHAUSTED)));
  // On the run-end window, which has no later check to take time from: refused, even beside a valid record.
  refused(reseal(run, r => { const tail = r.settlement.gaps.at(-1).windows[0]; tail.suspend = { ...record }; }));
  // Malformed: above ms, below the shortfall, zero or fractional.
  for (const bad of [{ reserveMs: record.ms + 1 }, { reserveMs: 0 }, { reserveMs: 1.5 }, { reserveMs: 100, shortMs: 200 }]) {
    const forged = { ...record, ...bad };
    assert.equal(validSuspendRecord(forged), false, JSON.stringify(bad));
    refused(reseal(run, r => { windowOf(r, 'A').suspend = forged; }));
  }
  assert.equal(validSuspendRecord({ ...record, reserveMs: 300, shortMs: 200 }), true);
  // Under a timing plan no wait takes the later checks' time: a reserve on any window is refused.
  const H = 10000, timed = target([ME, A, B], { H });
  // The second wait is A's horizon (the first is its lead-in).
  const t1 = await assess(HEAD, timed, { sends: SENDS, onSleep: (ms, n) => (n === 2 ? [1000, 3000] : null) });
  validated(timed, t1.run);
  assert.ok(windowOf(t1.run, 'A').suspend && !Object.hasOwn(windowOf(t1.run, 'A').suspend, 'reserveMs'));
  validateHttpRunEvidence(withRecord(t1.run, r => r));
  refused(withRecord(t1.run, r => ({ ...r, reserveMs: 1000 })));
  // The record writer keeps a reserve at least the shortfall and at most ms.
  const breaks = [{ kind: 'suspend', ms: 4000, from: { wall: WALL0, awake: 0, elapsed: 0 }, to: { wall: WALL0 + 4000, awake: 0, elapsed: 4000 } }];
  assert.deepEqual([suspendRecord(breaks, { reserveMs: 9000 }).reserveMs, suspendRecord(breaks, { reserveMs: 1000, shortMs: 1500 }).reserveMs, suspendRecord(breaks, { reserveMs: 2000.2 }).reserveMs], [4000, 1500, 2001]);
});

// Property, against the frozen build's own code: seeded random runs, each made four ways (head and the frozen build, each with the real and
// with the inert detector). Every application send falls within its own check's declared settle or horizon in awake time (an
// unobserved request's sends only under a timing plan, whose lead-in separates them), so with the real detector a clause head decides
// must agree with what the check's own request caused. Without a plan the run stops on exactly the frozen build's rows; a clause moves only from
// undecided to the truth, or toward undecided; every window and barrier that reads with no shortfall held its declared awake time on
// the host's own clock. Under a plan every verdict and wait is the frozen build's. With the inert detector head is exactly the frozen build.
const UNDECIDED = ['inconclusive', 'not-sent'];
function scenario(seed, id) {
  let s = seed >>> 0;
  const rand = () => { s = (s + 0x6d2b79f5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const pick = list => list[Math.floor(rand() * list.length)], int = (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));
  const H = rand() < 0.25 ? pick([5000, 10000, 30000]) : null, perCheck = rand() < 0.35;
  const settleMs = H ? pick([2500, 5000].filter(ms => ms <= H)) : pick([2500, 5000]), span = H ?? settleMs;
  const delay = () => Math.round(span * (0.05 + 0.85 * rand()));
  const checks = [ME], sends = {}, truth = new Map();
  if (H && rand() < 0.6) sends['GET /me'] = [{ name: pick([PAY, HOOK]), delay: delay() }];
  const observed = int(1, 3);
  for (let k = 1; k <= observed; k++) {
    if (rand() < 0.3) { const g = `G${k}`; checks.push({ id: g, method: 'GET', path: `/g${k}`, severity: 'low' }); if (H && rand() < 0.7) sends[`GET /g${k}`] = [{ name: pick([PAY, HOOK]), delay: delay() }]; }
    const cid = `C${k}`, control = rand() < 0.4, own = Array.from({ length: int(0, 2) }, () => ({ name: pick([PAY, HOOK]), delay: delay() }));
    const clause = kind => (kind === 'effect.count' ? { kind, select: sel(pick([PAY, HOOK])), expected: int(0, 2) } : { kind, select: sel(pick([PAY, HOOK])) });
    const effects = control ? [clause('effect.exists'), ...(rand() < 0.4 ? [clause(pick(['effect.none', 'effect.count']))] : [])] : Array.from({ length: int(1, 2) }, () => clause(pick(['effect.none', 'effect.exists', 'effect.count'])));
    checks.push({ id: cid, method: 'POST', path: `/c${k}`, severity: control ? 'control' : 'high', effects });
    if (own.length) sends[`POST /c${k}`] = own;
    const count = name => own.filter(o => o.name === name).length;
    truth.set(cid, effects.map(e => (e.kind === 'effect.none' ? (count(e.select.name) ? 'fail' : 'pass') : e.kind === 'effect.exists' ? (count(e.select.name) ? 'pass' : 'fail') : (count(e.select.name) === e.expected ? 'pass' : 'fail'))));
  }
  // Lengths around the band where the spare budget runs out but the later checks' time does not.
  const asleep = () => pick([2500, 4000, 9000, 20000, 30000, 38000, 42000, 45000, 48000, 52000, 60000, 90000, 150000]), byWait = rand() < 0.6;
  let onSleep, plan;
  if (byWait) {
    const sleeps = new Map(Array.from({ length: int(1, 3) }, () => [int(1, 8), { at: pick(['start', 'inside', 'inside']), f: rand(), asleep: asleep() }]));
    onSleep = () => (ms, n) => { const z = sleeps.get(n); return z ? [z.at === 'start' ? 0 : Math.round(z.f * ms), z.asleep] : null; };
    plan = `waits ${[...sleeps].map(([n, z]) => `${n}:${z.at}:${z.asleep}`).join(' ')}`;
  } else {
    const awakeSpan = observed * (H ? 2 * H : 2 * settleMs) + settleMs, sleeps = Array.from({ length: int(1, 3) }, () => ({ at: 1000 + Math.round(rand() * awakeSpan), asleep: asleep() })).sort((a, b) => a.at - b.at);
    onSleep = () => { const due = sleeps.map(z => ({ ...z })); return (ms, n, v) => { const z = due.find(x => !x.done && x.at < v.awake() + ms); if (!z) return null; z.done = true; return [Math.max(0, z.at - v.awake()), z.asleep]; }; };
    plan = `awake ${sleeps.map(z => `${z.at}:${z.asleep}`).join(' ')}`;
  }
  const limits = { ...HTTP_LIMITS, runTimeoutMs: pick([60000, 60000, 120000, 300000]) };
  return { p: target(checks, { H, perCheck, settleMs, id }), H, perCheck, settleMs, sends, onSleep, limits, truth, label: `${H ? `H${H}` : `settle${settleMs}`} ${perCheck ? 'per-check' : 'run'} ${checks.map(c => c.id).join(',')} ${plan} budget ${limits.runTimeoutMs}` };
}
const clausesOf = (run, truth) => [...truth.keys()].flatMap(id => truth.get(id).map((_, i) => ({ id, i, status: clauseOf(run, id, i) })));
const verdicts = run => run.results.map(r => [r.id, r.status, r.trace[0].data.notSent ?? null, r.assertions.map(a => a.status)]);

test('property (400 seeded runs against the frozen build\'s own code, real and inert detectors): the stop is the frozen build\'s, a restored wait held its awake time, and a clause moves only to the truth or toward undecided', async t => {
  const moves = new Map(), count = key => moves.set(key, (moves.get(key) ?? 0) + 1);
  let restored = 0, reservedShort = 0, decided = 0, toTruth = 0, timedSame = 0, inertSame = 0, checkedWindows = 0, checkedBarriers = 0, guarded = 0;
  const scenarios = Array.from({ length: 400 }, (_, k) => scenario(0xf4d00000 + k, `f4d-${k}`));
  for (let b = 0; b < scenarios.length; b += 20) {
    const batch = scenarios.slice(b, b + 20), registry = createRegistry({ profiles: batch.map(c => c.p), env: {} });
    for (const c of batch) suites.set(c.p, registry.exportSuite(c.p.id));
  }
  for (let k = 0; k < scenarios.length; k++) {
    const c = scenarios[k], options = { sends: c.sends, limits: c.limits }, at = `${k} ${c.label}`;
    const head = await assess(HEAD, c.p, { ...options, onSleep: c.onSleep() }), main = await assess(MAIN, c.p, { ...options, onSleep: c.onSleep() });
    const headInert = await assess(HEAD, c.p, { ...options, onSleep: c.onSleep(), detector: 'inert' }), mainInert = await assess(MAIN, c.p, { ...options, onSleep: c.onSleep(), detector: 'inert' });
    for (const r of [head.run, headInert.run]) validateHttpRunEvidence(r, { expectedSuite: suiteOf(c.p) });
    // Inert: the waits and every verdict exactly the frozen build's, but for the allowed-use guard's moves (an unguarded absence's pass
    // reads inconclusive; test/fixtures/allowed-use-guard-moves.mjs).
    assert.deepEqual([headInert.v.sleeps, verdicts(headInert.run)], [mainInert.v.sleeps, verdicts({ results: guardAdjusted(headInert.run, mainInert.run) })], `${at}: inert`);
    guarded += guardMoves(headInert.run);
    inertSame++;
    // A clause head decides is the truth; every move from the frozen build is to the truth or toward undecided.
    const now = clausesOf(head.run, c.truth), was = clausesOf(main.run, c.truth);
    now.forEach((x, j) => {
      const truth = c.truth.get(x.id)[x.i], before = was[j].status;
      if (!UNDECIDED.includes(x.status)) { decided++; assert.equal(x.status, truth, `${at}: head decided ${x.id} clause ${x.i + 1} against the truth (the frozen build ${before})`); }
      if (x.status !== before) {
        assert.ok(UNDECIDED.includes(x.status) || x.status === truth, `${at}: ${x.id} ${before} -> ${x.status}`);
        if (UNDECIDED.includes(before) && x.status === truth) toTruth++;
        count(`${before} -> ${x.status}`);
      }
    });
    if (c.H) {
      // Under a plan nothing here changes a wait or a verdict (only a cut row's words), but for the allowed-use guard's moves.
      assert.deepEqual([head.v.sleeps, verdicts(head.run)], [main.v.sleeps, verdicts({ results: guardAdjusted(head.run, main.run) })], `${at}: timed`);
      timedSame++;
    } else {
      // The run stops on exactly the frozen build's rows.
      const stops = run => run.results.map(r => [r.id, r.trace[0].data.notSent ?? null]);
      assert.deepEqual(stops(head.run), stops(main.run), `${at}: stops`);
    }
    // Physically: every check window and barrier that reads with no shortfall held its declared awake time.
    const held = heldOf(head.v), effectRows = head.run.results.filter(r => r.trace.length === 2);
    assert.equal(held.checks.length, effectRows.length, at);
    effectRows.forEach((row, i) => {
      const w = row.trace[1].data.windows[0], declared = c.H ? head.run.timing.rows[i].waitedMs : c.settleMs;
      if (!(w.suspend?.shortMs > 0)) { checkedWindows++; assert.ok(held.checks[i] >= declared, `${at}: ${row.id} held ${held.checks[i]} of ${declared} ms`); }
      if (w.suspend?.reserveMs > 0) { if (w.suspend.shortMs > 0) reservedShort++; else restored++; }
    });
    if (c.perCheck) (head.run.settlement?.barriers ?? []).forEach((b, i) => {
      const w = b.windows[0], declared = c.H ? head.run.timing.rows[i].barrierWaitedMs : c.settleMs;
      if (!(w.suspend?.shortMs > 0)) { checkedBarriers++; assert.ok(held.barriers[i] >= declared, `${at}: barrier ${i} held ${held.barriers[i]} of ${declared} ms`); }
      if (w.suspend?.reserveMs > 0) { if (w.suspend.shortMs > 0) reservedShort++; else restored++; }
    });
  }
  t.diagnostic(`the frozen build -> head clause moves (real detector): ${[...moves].sort().map(([key, n]) => `${key}: ${n}`).join('; ') || 'none'}`);
  t.diagnostic(`inert runs: ${guarded} clause passes the allowed-use guard withheld, every other verdict the frozen build's`);
  t.diagnostic(`head decided ${decided} clauses, none against the truth, ${toTruth} of them undecided on the frozen build; waits restored from the later checks' time ${restored}, still short after it ${reservedShort}; windows measured ${checkedWindows}, barriers ${checkedBarriers}; timed runs equal to the frozen build ${timedSame}; inert equal to the frozen build ${inertSame} of 400`);
  // Not vacuous: the second stage both restores and runs out, some clause moves from undecided to the truth, and nothing moves elsewhere.
  assert.ok(restored >= 10 && reservedShort >= 5 && toTruth >= 5 && decided > 500 && timedSame >= 50, `${restored} ${reservedShort} ${toTruth} ${decided} ${timedSame}`);
});

// The refactor: one table, keyed by reason. The words each reason had before it, byte for byte (the evidence digest does not cover them).
const POINTERS = id => ['Local target profile', `Check ${id}`];
const PINNED_TEXT = Object.freeze({
  precondition: { summary: 'Not sent: a declared precondition did not hold, so this check was not decided.', label: 'No request sent: a declared precondition did not hold',
    remediation: { title: 'Review the declared precondition', why: 'A check that was not sent decides nothing.', steps: ['Check that the creating check returns the captured value, or that the declared account change passes.', 'Retest the unchanged contract.'] } },
  [RUN_BUDGET_EXHAUSTED]: { summary: 'Not sent: the declared run budget could not hold this check, so it was not decided.', label: 'No request sent: the declared run budget could not hold this check',
    remediation: { title: 'Review the declared run budget', why: 'A check that was not sent decides nothing.', steps: ['Raise "timing.runBudgetMs", or lower the effect horizon or the number of checks in one run.', 'Retest the unchanged contract.'] } },
  [SUSPEND_STOPPED]: { summary: 'Not sent: a host sleep left an earlier check\'s wait short of its declared awake time, so the run stopped and this check was not decided.', label: 'No request sent: the run stopped after a host sleep',
    remediation: { title: 'Rerun on a host that stays awake', why: 'A check that was not sent decides nothing.', steps: ['Keep the host awake for the whole run, or declare a timing plan whose budget leaves room to extend a wait a sleep cut short.', 'Retest the unchanged contract.'] } },
});
const SLEEP_CUT_TEXT = Object.freeze({ summary: 'Not sent: a host sleep left a wait of this run short of its declared awake time and the declared run budget had no room to make it up, so this check was not decided.',
  label: 'No request sent: a host sleep used up the declared run budget',
  remediation: { title: 'Rerun on a host that stays awake', why: 'A check that was not sent decides nothing.', steps: ['Keep the host awake for the whole run, or raise "timing.runBudgetMs" so a wait a sleep cut short can be made up.', 'Retest the unchanged contract.'] } });
const textOf = row => ({ summary: row.summary, label: row.trace[0].label, remediation: row.remediation });
const expectedText = (pinned, id) => ({ summary: pinned.summary, label: pinned.label, remediation: { ...pinned.remediation, codePointers: POINTERS(id) } });

test('not-sent wording: every not-sent reason keeps its summary, trace label and remediation byte for byte, from one table keyed by reason', async () => {
  // The table: one entry per not-sent reason, and the sleep-cut wording; the two preconditions share theirs.
  const key = reason => (['change-not-confirmed', 'capture-unavailable'].includes(reason) ? 'precondition' : reason);
  for (const reason of NOT_SENT_REASONS) assert.equal(JSON.stringify(NOT_SENT_TEXT[reason]), JSON.stringify(PINNED_TEXT[key(reason)]), reason);
  assert.equal(Object.keys(NOT_SENT_TEXT).length, NOT_SENT_REASONS.length + 1);
  assert.equal(JSON.stringify(Object.values(NOT_SENT_TEXT).find(v => !NOT_SENT_REASONS.some(r => NOT_SENT_TEXT[r] === v))), JSON.stringify(SLEEP_CUT_TEXT));
  assert.ok(Object.isFrozen(NOT_SENT_TEXT) && Object.values(NOT_SENT_TEXT).every(v => Object.isFrozen(v) && Object.isFrozen(v.remediation) && Object.isFrozen(v.remediation.steps)));
  // Rows the connector writes, beside the frozen build's for the same run: byte-identical text.
  const rows = [];
  // capture-unavailable: the creating check's status does not match, so its value is not captured.
  const capture = { id: 'f4d-capture', name: 'Capture', applicationId: 'f4d', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { anon: { principalId: 'anon' } }, requiredControlIds: ['CREATE'],
    checks: [{ id: 'CREATE', title: 'c', category: 'Setup', severity: 'control', actorId: 'anon', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], capture: { note: { pointer: '/id', type: 'id' } } },
      { id: 'USE', title: 'u', category: 'Boundary', severity: 'high', actorId: 'anon', method: 'DELETE', path: '/notes/{{note}}', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }] };
  const refusing = async () => ({ status: 500, complete: true, jsonParsed: true, json: {}, bytes: 2 });
  for (const impl of [HEAD, MAIN]) rows.push([impl.name, 'USE', await impl.assess(capture, { env: {}, transport: refusing })]);
  // run-budget-exhausted, with no sleep: GET /me takes 180 s, so the budget holds no observed check after it.
  const tight = target([ME, A, B, C], { H: 30000, id: 'f4d-tight' }), SLOW = { 'GET /me': 180000 };
  for (const impl of [HEAD, MAIN]) rows.push([impl.name, 'B', (await assess(impl, tight, { sends: SENDS, slow: SLOW })).run]);
  // host-suspend-run-stopped: a settle left short.
  const stop = target([ME, A, B, C], { id: 'f4d-stop' });
  for (const impl of [HEAD, MAIN]) rows.push([impl.name, 'C', (await assess(impl, stop, { sends: SENDS, onSleep: (ms, n) => (n === 1 ? [500, 60000] : null) })).run]);
  const reasons = [];
  for (let i = 0; i < rows.length; i += 2) {
    const [, id, head] = rows[i], [, , main] = rows[i + 1], reason = notSentOf(head, id);
    reasons.push(reason);
    assert.equal(notSentOf(main, id), reason);
    assert.equal(JSON.stringify(textOf(rowOf(head, id))), JSON.stringify(textOf(rowOf(main, id))), `${reason}: head and the frozen build write the same words`);
    assert.equal(JSON.stringify(textOf(rowOf(head, id))), JSON.stringify(expectedText(PINNED_TEXT[key(reason)], id)), `${reason}: the pinned words`);
  }
  assert.deepEqual(reasons, ['capture-unavailable', RUN_BUDGET_EXHAUSTED, SUSPEND_STOPPED]);
  validateHttpRunEvidence(rows[0][2]); validated(tight, rows[2][2]); validated(stop, rows[4][2]);
});

test('sleep-cut wording: a timed run a host sleep cut is worded as such, while its reason stays run-budget-exhausted; a budget cut keeps the budget\'s words', async () => {
  const H = 30000, REFUND = { id: 'REFUND', method: 'POST', path: '/refund', severity: 'control', effects: [{ kind: 'effect.exists', select: sel(HOOK) }] };
  const AFTER = { id: 'AFTER', method: 'POST', path: '/after', severity: 'high', effects: [{ kind: 'effect.none', select: sel(PAY) }] };
  const FORBID = { id: 'FORBID', method: 'POST', path: '/forbid', severity: 'high', effects: [{ kind: 'effect.none', select: sel(HOOK) }] };
  const cases = [
    // A lead-in a sleep left short past the budget (the run's first wait is REFUND's lead-in): REFUND and AFTER are cut.
    { p: target([ME, REFUND, AFTER], { H }), sends: { 'GET /me': [{ name: HOOK, delay: 25000 }] }, onSleep: (ms, n) => (n === 1 ? [1000, 175000] : null), cut: ['REFUND', 'AFTER'], slept: true },
    // A horizon a sleep truncated (400 s from the instant it starts, past the budget): FORBID is sent and truncated, and AFTER is cut.
    { p: target([ME, FORBID, AFTER], { H }), sends: { 'POST /forbid': [{ name: HOOK, delay: 28000 }] }, onSleep: (ms, n, v) => (ms === H && v.sent.length === 1 && !v.cut ? (v.cut = true, [0, 400000]) : null), cut: ['AFTER'], slept: true },
    // No sleep, a slow application: GET /me takes 180 s, so the budget holds no observed check after it.
    { p: target([ME, A, B, C], { H }), sends: SENDS, onSleep: () => null, slow: { 'GET /me': 180000 }, cut: ['A', 'B', 'C'], slept: false },
  ];
  for (const { p, sends, onSleep, slow, cut, slept } of cases) {
    const head = await assess(HEAD, p, { sends, onSleep, slow }), main = await assess(MAIN, p, { sends, onSleep, slow });
    validated(p, head.run);
    assert.deepEqual(head.run.results.map(r => [r.id, r.status, r.trace[0].data.notSent ?? null]), main.run.results.map(r => [r.id, r.status, r.trace[0].data.notSent ?? null]), 'the same rows are cut, for the same reason');
    for (const id of cut) {
      const row = rowOf(head.run, id);
      assert.deepEqual([row.trace[0].data.notSent, row.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual], [RUN_BUDGET_EXHAUSTED, PRECONDITION_REASONS[RUN_BUDGET_EXHAUSTED]]);
      assert.equal(JSON.stringify(textOf(row)), JSON.stringify(expectedText(slept ? SLEEP_CUT_TEXT : PINNED_TEXT[RUN_BUDGET_EXHAUSTED], id)), id);
      // The frozen build named the budget either way.
      assert.equal(JSON.stringify(textOf(rowOf(main.run, id))), JSON.stringify(expectedText(PINNED_TEXT[RUN_BUDGET_EXHAUSTED], id)), id);
    }
    if (cut.includes('AFTER') && !cut.includes('REFUND')) assert.ok(windowOf(head.run, 'FORBID').reason.split(',').includes(HORIZON_TRUNCATED));
    // A run whose cut row carries the other wording still validates: the words are not evidence.
    validateHttpRunEvidence(reseal(head.run, r => { const row = rowOf(r, cut[0]); Object.assign(row, { summary: 'edited' }); row.trace[0].label = 'edited'; }));
  }
});

// An unreadable awake reading on a clock already seen to move fails closed, as a still one
// does: the pair is a suspend of its whole length. A clock that never moved stays inert, exactly as the frozen build.
test('unreadable reading, detector: a live awake clock with an unreadable reading over a pair past the threshold is a suspend of the whole pair; one that never moved stays unchecked', () => {
  for (const impl of [HEAD, MAIN]) {
    const h = { awake: 0, elapsed: 0, bad: false }, d = impl.detector({ wall: () => WALL0 + h.elapsed, awake: () => (h.bad ? NaN : h.awake), elapsed: () => h.elapsed, timersCountSuspend: true }), at = d.mark();
    h.awake += 20; h.elapsed += 20;
    assert.deepEqual(d.sample(), [], 'the clock moved: it is alive');
    h.elapsed += 60000; h.bad = true;
    const far = d.sample().map(b => [b.kind, b.ms]);
    h.bad = false; h.awake += 20; h.elapsed += 20;
    const back = d.sample().map(b => [b.kind, b.ms]);
    h.elapsed += 30000; h.bad = true; d.sample(); h.bad = false;
    h.elapsed += 1500; h.bad = true;
    const short = d.sample().map(b => b.kind);
    if (impl === HEAD) {
      assert.deepEqual([far, back, short], [[['suspend', 60000]], [], []], 'head: the unreadable 60 s pair held no awake time; back to readable, and a short pair, decide nothing');
      assert.deepEqual([d.lostSince(at), d.uncheckedSince(at)], [90000, 0]);
    } else {
      assert.deepEqual([far, back, short], [[['unchecked', 60000]], [], []], 'the frozen build: unchecked');
      assert.deepEqual([d.lostSince(at), d.uncheckedSince(at)], [0, 90000]);
    }
    // Never moved (frozen, then unreadable), or never readable at all: unchecked, never a suspend, on both.
    for (const awake of [(g => () => (g.bad ? NaN : 5000)), (() => () => NaN)]) {
      const g = { elapsed: 0, bad: false }, e = impl.detector({ wall: () => WALL0 + g.elapsed, awake: awake(g), elapsed: () => g.elapsed, timersCountSuspend: true }), m = e.mark();
      g.elapsed += 60000; g.bad = true;
      assert.deepEqual(e.sample().map(b => b.kind), ['unchecked']);
      assert.deepEqual([e.lostSince(m), e.uncheckedSince(m)], [0, 60000]);
    }
  }
});

test('unreadable reading, connector: an unreadable reading after a sleep leaves the settle partial or extends it in full, where the frozen build read it unchecked and passed on missing evidence; a clock that never moved is the frozen build', async () => {
  // FORBID also proves its own send to PAY (a positive clause), so the allowed-use guard leaves its absence clause as the frozen build read it.
  const FORBID = { id: 'FORBID', method: 'POST', path: '/forbid', severity: 'high', effects: [{ kind: 'effect.none', select: sel(HOOK) }, { kind: 'effect.exists', select: sel(PAY) }] };
  // 60 s asleep 500 ms into FORBID's settle and again into the final settle, each read unusable at wake; the default budget has no
  // room to restore either. A readable clock would have seen both (it moved 500 ms in each pair).
  const p = target([ME, FORBID]), sends = { 'POST /forbid': [{ name: HOOK, delay: 4800 }, { name: PAY, delay: 100 }] }, onSleep = (ms, n) => (n <= 2 ? [500, 60000] : null);
  const head = await assess(HEAD, p, { sends, onSleep, detector: 'flaky' }), main = await assess(MAIN, p, { sends, onSleep, detector: 'flaky' });
  validated(p, head.run);
  const w = windowOf(head.run, 'FORBID'), was = windowOf(main.run, 'FORBID');
  assert.deepEqual([w.coverage, carriesSuspendShort(w), w.suspend.cause, w.suspend.shortMs, Object.hasOwn(w, 'suspendUnchecked'), clauseOf(head.run, 'FORBID')], ['partial', true, 'host-sleep', 5000, false, 'inconclusive']);
  assert.deepEqual([was.coverage, was.suspendUnchecked, Object.hasOwn(was, 'suspend'), clauseOf(main.run, 'FORBID')], ['complete', true, false, 'pass'], 'the frozen build: unchecked, and a pass on missing evidence');
  // Room to restore it: the whole settle is held again, so the send lands in the window and the clause fails (the truth).
  const roomy = await assess(HEAD, p, { sends, onSleep: (ms, n) => (n === 1 ? [500, 60000] : null), detector: 'flaky', limits: { ...HTTP_LIMITS, runTimeoutMs: 300000 } });
  assert.deepEqual([roomy.v.sleeps.slice(0, 2), windowOf(roomy.run, 'FORBID').coverage, clauseOf(roomy.run, 'FORBID')], [[5000, 5000], 'complete', 'fail']);
  assert.ok(heldOf(roomy.v).checks[0] >= 5000);
  // A clock that never moved (frozen, or never readable): waits and verdicts exactly the frozen build's.
  for (const detector of ['still', 'nan', 'inert']) {
    const now = await assess(HEAD, p, { sends, onSleep, detector }), before = await assess(MAIN, p, { sends, onSleep, detector });
    validated(p, now.run);
    assert.deepEqual([now.v.sleeps, verdicts(now.run)], [before.v.sleeps, verdicts(before.run)], detector);
    assert.equal(windowOf(now.run, 'FORBID').suspendUnchecked, true, detector);
  }
});

// Compatibility: runs the frozen build sealed (its connector and detector, evaluator 33449ad9) validate under this validator, a
// stop it derived from a shortfall included: the reserve only adds a stop, and a record without one reads as before.
test('compatibility: runs the frozen build sealed validate unchanged, stopped, restored, unchecked and timed ones included', async () => {
  const H = 30000, REFUND = { id: 'REFUND', method: 'POST', path: '/refund', severity: 'control', effects: [{ kind: 'effect.exists', select: sel(HOOK) }] };
  const cases = [
    ['no sleep', target([ME, A, B, C]), {}],
    ['restored within the spare budget', target([ME, A, B, C]), { onSleep: (ms, n) => (n === 1 ? [500, 3000] : null) }],
    ['settle left short, run stopped', target([ME, A, B, C]), { onSleep: (ms, n) => (n === 1 ? [500, 45000] : null) }],
    ['barrier left short, run stopped', target([ME, A, B, C], { perCheck: true }), { onSleep: (ms, n) => (n === 2 ? [500, 45000] : null) }],
    ['frozen clock, unchecked', target([ME, A, B, C]), { onSleep: (ms, n) => (n === 1 ? [0, 60000] : null), detector: 'still' }],
    ['lead-in cut', target([ME, REFUND, B], { H }), { sends: { 'GET /me': [{ name: HOOK, delay: 25000 }] }, onSleep: (ms, n) => (n === 1 ? [1000, 175000] : null) }],
  ];
  for (const [label, p, options] of cases) {
    const { run } = await assess(MAIN, p, { sends: SENDS, ...options });
    validated(p, run);
    if (label.includes('stopped')) assert.equal(notSentOf(run, 'B'), SUSPEND_STOPPED, label);
  }
});
