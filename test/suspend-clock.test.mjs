// Suspend-aware custody time (src/suspend-clock.mjs). Fake clocks for the detector; synthetic windows for the coverage label and
// the property that the label
// never moves a verdict; a virtual clock with an injected transport and observer for the settle, horizon, barrier and final waits;
// and runs over real loopback HTTP (an egress recorder with proxy routing and a witness) for the label and for the wait extension
// end to end. Destination hosts are names only and are never resolved or contacted: no database, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createSuspendDetector, cpuAwakeClock, platformClocks, suspendRecord, suspendNote, suspendHeldNote, validSuspendRecord, applySuspendShort, carriesSuspendShort,
  SUSPEND_LIMITS, SUSPEND_CAUSES, SUSPEND_SHORT, SUSPEND_UNCHECKED_NOTE } from '../src/suspend-clock.mjs';
import { makeEffect, evaluateEffectAssertion, validateWindow } from '../src/effect-events.mjs';
import { decideEffects, effectAssertionRows } from '../src/http-effects.mjs';
import { runHttpAssessment, HTTP_LIMITS } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, identityControlPlan } from '../src/contracts.mjs';
import { plannedTimingMs, TIMING_BOUNDS, HORIZON_TRUNCATED } from '../src/http-timing.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';

const WALL0 = Date.parse('2026-10-16T20:14:00.000Z');
// A fake host: awake time stops while it is suspended; elapsed and wall time keep counting; the wall clock can also be stepped.
function fakeHost({ elapsed = true } = {}) {
  const h = { awake: 0, elapsed: 0, step: 0 };
  h.run = ms => { h.awake += ms; h.elapsed += ms; };
  h.sleep = ms => { h.elapsed += ms; };
  h.stepWall = ms => { h.step += ms; };
  h.clocks = { wall: () => WALL0 + h.elapsed + h.step, awake: () => h.awake, elapsed: elapsed ? () => h.elapsed : null };
  return h;
}
const iso = ms => new Date(WALL0 + ms).toISOString();

test('detector: clocks that advance together record nothing, sub-threshold drift and timer jitter included', () => {
  const h = fakeHost(), d = createSuspendDetector(h.clocks);
  assert.deepEqual(d.sample(), [], 'the first sample is only a baseline');
  for (const [ms, asleep, step] of [[1000, 0, 0], [1, 0, 0], [250, 0, 0], [5000, 1500, 0], [3000, 0, 1999], [0, 0, 0], [60000, 0, -1999]]) {
    h.run(ms); h.sleep(asleep); h.stepWall(step);
    assert.deepEqual(d.sample(), [], `${ms}/${asleep}/${step}`);
  }
  assert.deepEqual(d.breaks(), []);
  const m = d.mark();
  assert.equal(suspendRecord(d.between({ count: 0, lost: 0 }, m)), null);
  assert.equal(suspendNote(undefined), '');
  assert.equal(d.timersCountSuspend, false);
});

test('detector: a suspend is elapsed time without awake time, recorded with both ends on all three clocks', () => {
  const h = fakeHost(), d = createSuspendDetector({ ...h.clocks, timersCountSuspend: true });
  h.run(3000);
  const before = d.mark();
  h.run(400); h.sleep(112000); h.run(600);
  const found = d.sample();
  assert.deepEqual(found, [{ kind: 'suspend', ms: 112000, from: { wall: WALL0 + 3000, awake: 3000, elapsed: 3000 }, to: { wall: WALL0 + 116000, awake: 4000, elapsed: 116000 } }]);
  const after = d.mark();
  const record = suspendRecord(d.between(before, after));
  assert.deepEqual(record, { cause: 'host-sleep', count: 1, ms: 112000, from: iso(3000), to: iso(116000) });
  assert.ok(validSuspendRecord(record));
  assert.equal(suspendNote(record), `, host suspended (sleep) about 112 s between ${iso(3000)} and ${iso(116000)}`);
  // The awake time a wait begun at `before` lost (the run's timers count sleep): the suspended time. A mark after the break excludes it.
  assert.equal(d.lostSince(before), 112000);
  assert.equal(d.lostSince(after), 0);
  assert.deepEqual(d.between(after, d.mark()), []);
  // Where the timers do not count suspend (CLOCK_MONOTONIC), a wait already lasts in awake time: nothing is lost, the record stands.
  const linuxLike = createSuspendDetector(h.clocks), at = linuxLike.mark();
  h.sleep(112000); h.run(10);
  assert.equal(linuxLike.lostSince(at), 0);
  assert.equal(linuxLike.breaks()[0].kind, 'suspend');
});

test('detector: an NTP-like wall-clock step, back or forward, is a wall-step and never a suspend; with no elapsed clock a forward jump is only a discontinuity', () => {
  const h = fakeHost(), d = createSuspendDetector({ ...h.clocks, timersCountSuspend: true }), start = d.mark();
  h.run(1000); h.stepWall(-30000);
  assert.deepEqual(d.sample().map(b => [b.kind, b.ms]), [['wall-step', -30000]]);
  h.run(1000); h.stepWall(30000);
  assert.deepEqual(d.sample().map(b => [b.kind, b.ms]), [['wall-step', 30000]]);
  assert.equal(suspendRecord(d.between(start, d.mark())), null, 'a step takes no awake time, so it is left out of the record');
  assert.equal(d.lostSince(start), 0);
  // A suspend and a step in one interval: both are recorded, and the record holds only the suspend.
  h.run(500); h.sleep(40000); h.stepWall(-5000);
  assert.deepEqual(d.sample().map(b => [b.kind, b.ms]), [['suspend', 40000], ['wall-step', -5000]]);
  assert.equal(suspendRecord(d.breaks()).ms, 40000);
  // The two-clock design (wall against an awake clock, no elapsed clock): a forward jump is a suspend or a forward step, which the
  // two clocks cannot tell apart, so it is a discontinuity; a jump back can only be a step.
  const g = fakeHost({ elapsed: false }), two = createSuspendDetector(g.clocks), from = two.mark();
  g.run(1000); g.sleep(112000);
  assert.deepEqual(two.sample().map(b => [b.kind, b.ms]), [['discontinuity', 112000]]);
  g.run(1000); g.stepWall(-30000);
  assert.deepEqual(two.sample().map(b => [b.kind, b.ms]), [['wall-step', -30000]]);
  const record = suspendRecord(two.between(from, two.mark()));
  assert.deepEqual([record.cause, record.count, record.ms], ['clock-discontinuity', 1, 112000]);
  assert.match(suspendNote(record), /^, host clock discontinuity \(a sleep or a wall-clock step\) about 112 s between /);
});

test('detector: several suspends (a lid-closed sleep with maintenance DarkWakes) are each recorded, and the record sums them', () => {
  const h = fakeHost(), d = createSuspendDetector({ ...h.clocks, timersCountSuspend: true });
  h.run(2000);
  const before = d.mark();
  for (const asleep of [40000, 30000, 42000]) { h.run(300); h.sleep(asleep); h.run(5000); assert.equal(d.sample().length, 1); }
  const breaks = d.between(before, d.mark());
  assert.deepEqual(breaks.map(b => [b.kind, b.ms]), [['suspend', 40000], ['suspend', 30000], ['suspend', 42000]]);
  const record = suspendRecord(breaks);
  assert.deepEqual(record, { cause: 'host-sleep', count: 3, ms: 112000, from: iso(2000), to: iso(2000 + 3 * 5300 + 112000) });
  assert.equal(suspendNote(record), `, host suspended (sleep) 3 times, about 112 s in all, between ${record.from} and ${record.to}`);
  assert.equal(d.lostSince(before), 112000);
  // A record mixing a suspend with an unclassified discontinuity says only what both could be.
  assert.equal(suspendRecord([...breaks, { kind: 'discontinuity', ms: 5000, from: { wall: WALL0 }, to: { wall: WALL0 + 6000 } }]).cause, 'clock-discontinuity');
});

test('detector: an unusable reading decides nothing across it, a monotonic clock that went back is ignored, and the record stays bounded', () => {
  // Where the timers do not count sleep. Where they do, an unusable reading on an awake clock already seen to move is a suspend of the
  // pair (test/suspend-f4d.test.mjs).
  const h = fakeHost();
  let broken = false;
  const d = createSuspendDetector({ ...h.clocks, awake: () => { if (broken) throw new Error('EPERM'); return h.awake; } });
  d.sample(); h.run(1000); broken = true; h.sleep(50000);
  assert.deepEqual(d.sample(), [], 'no awake reading: no pair to compare');
  broken = false; h.run(1000);
  assert.deepEqual(d.sample(), [], 'the pair after an unusable reading starts again from it');
  h.run(1000); h.sleep(10000);
  assert.deepEqual(d.sample().map(b => b.kind), ['suspend'], 'detection resumes');
  for (const bad of [NaN, Infinity, 'x']) {
    const e = createSuspendDetector({ wall: () => WALL0, awake: () => bad, elapsed: () => 1e9 });
    e.sample(); assert.deepEqual(e.sample(), []);
  }
  let awake = 10000;
  const back = createSuspendDetector({ wall: () => WALL0, awake: () => awake, elapsed: () => 20000 });
  back.sample(); awake = 0;
  assert.deepEqual(back.sample(), [], 'awake went back: not a reading');
  assert.throws(() => createSuspendDetector({ wall: null }), TypeError);
  assert.throws(() => createSuspendDetector({ awake: 5 }), TypeError);
  // Past the limit the oldest breaks are dropped; the lost time is counted from the breaks still kept, the same ones a record is
  // made from, so an extension never outruns its record (dropping only shortens it, the inert direction).
  const many = fakeHost(), m = createSuspendDetector({ ...many.clocks, timersCountSuspend: true }), from = m.mark(), n = SUSPEND_LIMITS.breaks + 6;
  for (let i = 0; i < n; i++) { many.run(100); many.sleep(3000); m.sample(); }
  assert.equal(m.breaks().length, SUSPEND_LIMITS.breaks);
  assert.equal(m.lostSince(from), SUSPEND_LIMITS.breaks * 3000);
  assert.equal(suspendRecord(m.breaks()).ms, SUSPEND_LIMITS.breaks * 3000);
  assert.ok(validSuspendRecord(suspendRecord(m.breaks())));
});

test('detector: an awake clock that under-reads a little never adds up to a suspend over a long pair, and a frozen one decides nothing', () => {
  // The CPU tick clock under-reads by about 0.43% when idle. One 8-minute pair (the witness closes of several observers) with no
  // suspend: 2064 ms short, over the fixed 2 s threshold, but under the 2% floor.
  const drifting = (ratio = 0.0043) => { const h = { elapsed: 0 }; return { h, clocks: { wall: () => WALL0 + h.elapsed, awake: () => h.elapsed * (1 - ratio), elapsed: () => h.elapsed } }; };
  const idle = drifting(), d = createSuspendDetector({ ...idle.clocks, timersCountSuspend: true }), at = d.mark();
  idle.h.elapsed += 8 * 60 * 1000;
  assert.deepEqual(d.sample(), [], 'no suspend over an idle 8-minute pair');
  assert.equal(d.lostSince(at), 0);
  assert.equal(suspendRecord(d.between(at, d.mark())), null);
  const fixed = drifting(), old = createSuspendDetector({ ...fixed.clocks, driftRatio: 0 });
  old.sample(); fixed.h.elapsed += 8 * 60 * 1000;
  assert.deepEqual(old.sample().map(b => [b.kind, Math.round(b.ms)]), [['suspend', 2064]], 'adjacent: the fixed 2 s threshold alone reads a false suspend');
  // A real suspend inside a long pair is still seen: 112 s against a 2% floor of about 14 s.
  const both = fakeHost(), e = createSuspendDetector({ ...both.clocks, timersCountSuspend: true }), from = e.mark();
  both.run(10 * 60 * 1000); both.sleep(112000);
  assert.deepEqual(e.sample().map(b => [b.kind, b.ms]), [['suspend', 112000]]);
  assert.equal(e.lostSince(from), 112000);
  // A frozen awake clock (no counter moved) over a long pair: never a suspend, no record, nothing lost; where the timers count
  // suspend the pair is unchecked (a suspend in it could not have been seen), and only that is recorded.
  const frozen = { elapsed: 0 }, f = createSuspendDetector({ wall: () => WALL0 + frozen.elapsed, awake: () => 5000, elapsed: () => frozen.elapsed, timersCountSuspend: true }), mark = f.mark();
  for (const ms of [30000, 120000, 600000]) { frozen.elapsed += ms; assert.deepEqual(f.sample().map(b => [b.kind, b.ms]), [['unchecked', ms]], `frozen over ${ms} ms`); }
  assert.equal(f.lostSince(mark), 0);
  assert.equal(f.uncheckedSince(mark), 750000);
  assert.equal(suspendRecord(f.between(mark, f.mark())), null);
  // A short pair (under the threshold) is never unchecked, and nothing is unchecked where the timers do not count suspend.
  frozen.elapsed += 1500;
  assert.deepEqual(f.sample(), []);
  const linuxLike = createSuspendDetector({ wall: () => WALL0 + frozen.elapsed, awake: () => 5000, elapsed: () => frozen.elapsed }), m1 = linuxLike.mark();
  frozen.elapsed += 600000;
  assert.deepEqual(linuxLike.sample(), []);
  assert.equal(linuxLike.uncheckedSince(m1), 0);
  // The same through the CPU tick clock: counters that never move, or all zeros (unreadable).
  const ticks = t => [{ times: { user: t, nice: 0, sys: 0, idle: 0, irq: 0 } }, { times: { user: t, nice: 0, sys: 0, idle: 0, irq: 0 } }];
  for (const list of [ticks(4000), ticks(0)]) {
    const g = { elapsed: 0 }, c = createSuspendDetector({ wall: () => WALL0 + g.elapsed, awake: cpuAwakeClock(() => list), elapsed: () => g.elapsed, timersCountSuspend: true }), m0 = c.mark();
    g.elapsed += 300000;
    assert.deepEqual(c.sample().map(b => b.kind), ['unchecked'], `CPU counters ${list[0].times.user}`);
    assert.equal(c.lostSince(m0), 0);
    assert.equal(c.uncheckedSince(m0), 300000);
  }
});

test('detector: a wall-clock step back at wake cannot make a suspend\'s record vanish, and the extension comes from the same breaks as the record', () => {
  const h = fakeHost(), d = createSuspendDetector({ ...h.clocks, timersCountSuspend: true }), at = d.mark();
  h.run(400); h.sleep(3000); h.stepWall(-10000); h.run(100);
  assert.deepEqual(d.sample().map(b => [b.kind, b.ms]), [['suspend', 3000], ['wall-step', -10000]]);
  const record = suspendRecord(d.between(at, d.mark()));
  assert.deepEqual(record, { cause: 'host-sleep', count: 1, ms: 3000, from: iso(0), to: iso(3500) }, 'bounds from the first sample, measured forward in elapsed time');
  assert.ok(validSuspendRecord(record));
  assert.equal(d.lostSince(at), record.ms, 'the wait is extended by exactly what the record holds');
  // Without an elapsed clock a discontinuity is recorded, never counted as lost time: a forward wall step takes nothing from a timer.
  const g = fakeHost({ elapsed: false }), two = createSuspendDetector({ ...g.clocks, timersCountSuspend: true }), from = two.mark();
  g.run(1000); g.sleep(30000);
  assert.deepEqual(two.sample().map(b => b.kind), ['discontinuity']);
  assert.equal(two.lostSince(from), 0);
  assert.equal(suspendRecord(two.between(from, two.mark())).cause, 'clock-discontinuity');
});

test('platform clocks: on darwin the CPU tick counters are the awake clock and Node\'s own clock the elapsed one; elsewhere nothing is declared yet', () => {
  // The busiest CPU's step, from a baseline read when the clock is made; a reading in which no counter moved repeats the total; a
  // changed CPU list, an empty one, a bad counter or all-zero counters is unusable (NaN).
  const times = t => ({ times: { user: t, nice: 0, sys: 0, idle: 0, irq: 0 } });
  let list = [times(1000), times(5000)];
  const awake = cpuAwakeClock(() => list);
  assert.equal(awake(), 0, 'the baseline was read when the clock was made, so the first reading is usable');
  list = [times(1010), times(5250)];
  assert.equal(awake(), 250);
  list = [times(1400), times(5260)];
  assert.equal(awake(), 640);
  assert.equal(awake(), 640, 'no counter moved: the same total');
  list = [times(1500)];
  assert.ok(Number.isNaN(awake()), 'the CPU list changed');
  list = [];
  assert.ok(Number.isNaN(awake()));
  list = [{ times: { user: NaN, nice: 0, sys: 0, idle: 0, irq: 0 } }];
  assert.ok(Number.isNaN(awake()));
  list = [times(0), times(0)];
  assert.ok(Number.isNaN(awake()), 'all-zero counters');
  assert.ok(Number.isNaN(cpuAwakeClock(() => { throw new Error('EPERM'); })()), 'unreadable at creation and after');
  const darwin = platformClocks({ platform: 'darwin', cpus: () => [times(1)] });
  assert.equal(darwin.timersCountSuspend, true);
  assert.equal(typeof darwin.awake, 'function');
  assert.equal(typeof darwin.elapsed, 'function');
  assert.equal(createSuspendDetector(darwin).timersCountSuspend, true);
  for (const platform of ['linux', 'win32', 'freebsd']) {
    const clocks = platformClocks({ platform });
    assert.deepEqual([clocks.awake, clocks.elapsed, clocks.timersCountSuspend], [null, null, false], platform);
    const d = createSuspendDetector(clocks), at = d.mark();
    d.sample(); assert.deepEqual(d.sample(), []);
    assert.deepEqual([d.lostSince(at), d.uncheckedSince(at)], [0, 0], 'nothing seen, nothing unchecked: the timers there do not count suspend');
  }
  // This host's default clocks over a short busy interval: on darwin the first pair already has an awake reading (the CPU baseline is
  // read when the clock is made), and nothing is recorded.
  const live = createSuspendDetector(platformClocks()), at = live.mark();
  const until = performance.now() + 50; while (performance.now() < until);
  assert.deepEqual(live.sample().filter(b => b.kind !== 'wall-step'), []);
  assert.equal(live.lostSince(at), 0);
  if (process.platform === 'darwin') assert.ok(Number.isFinite(platformClocks().awake()), 'a usable first awake reading on this host');
});

test('a sealed record is exactly what suspendRecord writes', () => {
  const ok = { cause: 'host-sleep', count: 1, ms: 112000, from: '2026-10-16T20:14:03.000Z', to: '2026-10-16T20:15:56.000Z' };
  assert.ok(validSuspendRecord(ok));
  assert.ok(validSuspendRecord(Object.assign(Object.create(null), ok)));
  assert.deepEqual(SUSPEND_CAUSES, ['host-sleep', 'clock-discontinuity']);
  for (const bad of [null, [], 'host-sleep', { ...ok, extra: 1 }, { ...ok, cause: 'nap' }, { ...ok, count: 0 }, { ...ok, count: 1.5 }, { ...ok, count: SUSPEND_LIMITS.breaks + 1 },
    { ...ok, ms: 0 }, { ...ok, ms: SUSPEND_LIMITS.recordMs + 1 }, { ...ok, ms: '112000' }, { ...ok, from: '2026-10-16T20:14:03Z' }, { ...ok, from: '2026-02-30T00:00:00.000Z' },
    { ...ok, to: '2026-10-16T20:14:02.000Z' }, (({ to, ...rest }) => rest)(ok)]) assert.equal(validSuspendRecord(bad), false, JSON.stringify(bad));
});

// Synthetic windows: one authoritative egress observer over two declared hosts.
const PAY = 'pay.example.test', HOOK = 'hooks.example.test', WITNESS = 'witness.scopehaven.invalid';
const RECORD = Object.freeze({ cause: 'host-sleep', count: 1, ms: 112000, from: '2026-10-16T20:14:48.120Z', to: '2026-10-16T20:16:41.004Z' });
const egressWindow = (instanceId, { coverage = 'partial', reason = 'egress-request-after-witness-request', events = [] } = {}) => ({ source: 'http-egress', instanceId,
  scope: { operations: ['send'], names: [PAY, HOOK], actorAttribution: 'none', evidence: 'authoritative' }, coverage, reason: coverage === 'complete' ? null : reason, events });
const sendTo = (instanceId, seq, name, outcome = 'committed', resource = null) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq, operation: 'send', name, resource, outcome, content: { seq } });
const sel = name => ({ source: 'http-egress', operation: 'send', name });

test('coverage: a window a host suspend overlapped names it, specifically and first, where the generic partial reason stood; the verdict is unchanged', () => {
  const plainWindow = egressWindow('egress-recorder-helplane-backends'), slept = { ...plainWindow, suspend: { ...RECORD } };
  validateWindow(slept);
  const none = { kind: 'effect.none', select: sel(PAY) };
  const before = evaluateEffectAssertion(none, [plainWindow]), after = evaluateEffectAssertion(none, [slept]);
  assert.equal(before.basis, 'Not every authoritative observer that can see this effect covered the window (egress-recorder-helplane-backends: partial, egress-request-after-witness-request).');
  assert.equal(after.basis, 'Not every authoritative observer that can see this effect covered the window (egress-recorder-helplane-backends: partial, host suspended (sleep) about 112 s between 2026-10-16T20:14:48.120Z and 2026-10-16T20:16:41.004Z, egress-request-after-witness-request).');
  assert.deepEqual([after.verdict, after.matched], [before.verdict, before.matched]);
  assert.equal(after.verdict, 'missing');
  // effect.only (integrations/collateral/only.mjs) names it the same way.
  const only = [{ kind: 'effect.only', expect: [], allow: [], sources: ['http-egress'] }];
  const [o1] = decideEffects(only, [plainWindow]), [o2] = decideEffects(only, [slept]);
  assert.equal(o1.basis, 'Not every authoritative observer in scope covered the window (egress-recorder-helplane-backends: partial, egress-request-after-witness-request).');
  assert.equal(o2.basis, `Not every authoritative observer in scope covered the window (egress-recorder-helplane-backends: partial${suspendNote(RECORD)}, egress-request-after-witness-request).`);
  assert.equal(o2.verdict, o1.verdict);
  // A failed window too.
  const failed = { ...egressWindow('egress-recorder-a', { coverage: 'failed', reason: 'egress-listener-down' }), suspend: { ...RECORD } };
  assert.match(evaluateEffectAssertion(none, [failed]).basis, /egress-recorder-a: failed, host suspended \(sleep\) about 112 s between .*, egress-listener-down\)\.$/);
  // A complete window is never a gap, so the clause's own rule adds nothing; but every row decided on that coverage (an effect.none
  // pass, an effect.exists fail, an effect.count, an effect.only pass) ends with the suspend, appended last when the row is built
  // (effectAssertionRows), so no later stage's reason is cut for it. A presence-decided row (an effect.exists pass, an effect.none
  // fail) does not rest on coverage and is unchanged. The decisions themselves, basis included, are unchanged.
  const complete = { ...egressWindow('egress-recorder-a', { coverage: 'complete' }), suspend: { ...RECORD } };
  assert.doesNotMatch(evaluateEffectAssertion(none, [complete]).basis, /suspended/);
  const held = suspendHeldNote(RECORD);
  assert.equal(held, 'The host was suspended (sleep) about 112 s between 2026-10-16T20:14:48.120Z and 2026-10-16T20:16:41.004Z while this check\'s windows were open; its waits held their declared awake time, but a send the sleep cut off, on this host or off it, could have gone unseen.');
  const clauses = [none, { kind: 'effect.exists', select: sel(PAY) }, { kind: 'effect.count', select: sel(PAY), expected: 0 }, ...only];
  const { suspend: _record, ...unrecorded } = complete;
  const quiet = decideEffects(clauses, [complete]), bare = decideEffects(clauses, [unrecorded]);
  assert.deepEqual(quiet.map(d => d.verdict), ['pass', 'fail', 'pass', 'pass']);
  quiet.forEach((d, i) => { assert.equal(d.verdict, bare[i].verdict); assert.equal(d.basis, bare[i].basis, d.kind); });
  const quietRows = effectAssertionRows(quiet), bareRows = effectAssertionRows(bare);
  quietRows.forEach((r, i) => assert.equal(r.actual, `${bareRows[i].actual} ${held}`.slice(0, 600), quiet[i].kind));
  const sent = { ...complete, events: [sendTo('egress-recorder-a', 1, PAY)] };
  const [presence] = effectAssertionRows(decideEffects([{ kind: 'effect.exists', select: sel(PAY) }], [sent]));
  assert.equal(presence.status, 'pass');
  assert.doesNotMatch(presence.actual, /suspended/, 'a recorded match does not rest on coverage');
  // A later stage's reason in the basis comes before the note, so the 600-character cap cuts the note.
  const reasoned = { ...quiet[0], basis: `${quiet[0].basis} ${'A later stage gave its reason here. '.repeat(10)}END-OF-REASON.` };
  const [cut] = effectAssertionRows([reasoned]);
  assert.equal(cut.actual.length, 600);
  assert.ok(cut.actual.includes('END-OF-REASON.'), 'the reason survives the cap');
  // Where no suspend could be checked, a coverage-decided row says so instead, and decides exactly as before.
  const unchecked = decideEffects(clauses, [{ ...unrecorded, suspendUnchecked: true }]);
  validateWindow({ ...unrecorded, suspendUnchecked: true });
  assert.throws(() => validateWindow({ ...unrecorded, suspendUnchecked: false }), /suspend/);
  assert.deepEqual(unchecked.map(d => d.verdict), bare.map(d => d.verdict));
  effectAssertionRows(unchecked).forEach((r, i) => assert.equal(r.actual, `${bareRows[i].actual} ${SUSPEND_UNCHECKED_NOTE}`.slice(0, 600)));
  // A record that is not exactly one suspendRecord writes is refused wherever a window is validated.
  for (const bad of [{ ...RECORD, cause: 'nap' }, { ...RECORD, ms: -1 }, 'host-sleep', null]) assert.throws(() => validateWindow({ ...plainWindow, suspend: bad }), /suspend/);
});

// With absent fields: an absent-field fail rests on the window's coverage (a field absent from a body the recorder read in
// full reads "no"), so on a window a host suspend overlapped its basis names the suspend; the verdict, the count and the absenceDecided
// tag (which compareRuns never credits as a repair) are unchanged.
test('with absent fields: an absent-field fail on a window a host suspend overlapped names the suspend and keeps its verdict and absenceDecided tag', () => {
  const BILL = 'billing.example.test', instanceId = 'egress-recorder-sink';
  const scope = { operations: ['send'], names: [BILL], actorAttribution: 'none', evidence: 'authoritative', capture: { [BILL]: ['/amount', '/amount_cents'] }, captureForm: [BILL] };
  // The refund was captured in full as a form, amount=43, and the pinned /amount_cents is absent.
  const refund = makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: 1, operation: 'send', name: BILL, resource: 'POST /billing/v1/orders/QTN-6207/refunds',
    outcome: 'committed', content: { seq: 1 }, captured: { status: 'captured', values: { '/amount': { type: 'text', value: '43' }, '/amount_cents': { type: 'absent' } } } });
  const window = { source: 'http-egress', instanceId, scope, coverage: 'complete', reason: null, events: [refund] };
  const clause = { kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: BILL, fields: [{ pointer: '/amount_cents', equals: 4275, absent: 'fails' }] } };
  const [bare] = decideEffects([clause], [window]), [slept] = decideEffects([clause], [{ ...window, suspend: { ...RECORD } }]);
  assert.deepEqual([bare.verdict, bare.absenceDecided], ['fail', true], bare.basis);
  assert.deepEqual([slept.verdict, slept.matched, slept.absenceDecided, slept.authoritative, slept.custody ?? null, slept.custodyReason ?? null],
    [bare.verdict, bare.matched, true, bare.authoritative, bare.custody ?? null, bare.custodyReason ?? null]);
  const [bareRow] = effectAssertionRows([bare]), [sleptRow] = effectAssertionRows([slept]);
  assert.equal(sleptRow.actual, `${bareRow.actual} ${suspendHeldNote(RECORD)}`.slice(0, 600));
  assert.deepEqual({ ...sleptRow, actual: null }, { ...bareRow, actual: null }, 'every other row field, custody and the absence tag included, is the same');
});

// Property: the record never moves a decision. For random windows (coverage, events, outcomes, observers) and random clauses
// (exists, none, count, only), in either role, every verdict, count and custody is the same with and without the record, and the
// basis differs only by the record's own words. So no inconclusive result can become a pass through the label.
test('property: a suspend record never changes a verdict, a count or custody, so it never turns an inconclusive result into a pass', () => {
  let seed = 0x5eed1234;
  const rand = () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const pick = list => list[Math.floor(rand() * list.length)], int = (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));
  const resources = ['POST /v1/charges', 'POST /v1/refunds', null];
  const clause = () => {
    const name = pick([PAY, HOOK]), select = { ...sel(name), ...(rand() < 0.3 ? { resource: pick(resources.filter(Boolean)) } : {}) };
    const kind = pick(['effect.exists', 'effect.none', 'effect.count', 'effect.only']);
    if (kind === 'effect.count') return { kind, select, expected: int(0, 2) };
    if (kind === 'effect.only') return { kind, expect: rand() < 0.5 ? [] : [{ select: sel(PAY), count: 1 }], allow: rand() < 0.5 ? [] : [sel(HOOK)], sources: ['http-egress'] };
    return { kind, select };
  };
  let named = 0, undecided = 0;
  const seen = new Set();
  for (let trial = 0; trial < 400; trial++) {
    const windows = Array.from({ length: int(1, 2) }, (_, k) => {
      const instanceId = `egress-recorder-${k + 1}`, coverage = pick(['complete', 'complete', 'partial', 'failed']);
      const events = coverage === 'failed' ? [] : Array.from({ length: int(0, 3) }, (_, i) => sendTo(instanceId, i + 1, pick([PAY, HOOK]), pick(['committed', 'committed', 'denied', 'unknown']), pick(resources)));
      return egressWindow(instanceId, { coverage, reason: pick(['egress-request-after-witness-request', 'egress-request-in-flight', 'collect-failed']), events });
    });
    const record = { ...RECORD, count: int(1, 4), ms: int(2001, 400000) }, note = suspendNote(record), heldNote = ` ${suspendHeldNote(record)}`;
    const slept = windows.map(w => (rand() < 0.75 ? { ...w, suspend: { ...record } } : w));
    slept.forEach(w => validateWindow(w));
    const effects = Array.from({ length: int(1, 3) }, clause), role = pick(['boundary', 'control']);
    const before = decideEffects(effects, windows, { role }), after = decideEffects(effects, slept, { role });
    const kept = d => JSON.stringify({ kind: d.kind, verdict: d.verdict, matched: d.matched, custody: d.custody ?? null, custodyReason: d.custodyReason ?? null, counts: d.counts ?? null, applications: d.applications ?? null });
    after.forEach((d, i) => {
      assert.equal(kept(d), kept(before[i]), `trial ${trial} clause ${i}`);
      assert.equal(d.basis.split(heldNote).join('').split(note).join(''), before[i].basis, `trial ${trial} clause ${i}: only the record's words differ`);
      if (d.basis !== before[i].basis) named++;
      if (['missing', 'observer-failure'].includes(d.verdict)) undecided++;
      seen.add(d.verdict);
    });
  }
  assert.ok(named > 40 && undecided > 40, `the property was exercised: ${named} bases named a suspend, ${undecided} clauses were undecided`);
  assert.ok(seen.has('pass') && seen.has('fail'), [...seen].join(','));
});

// Property: a wait held short (record.shortMs, applySuspendShort) only ever moves a verdict toward inconclusive. For random windows and
// clauses, in either role, every verdict is unchanged or becomes missing or observer-failure; none becomes a pass or a fail it was
// not, and every recorded match still decides. So the shortfall never turns an inconclusive result into a pass.
test('property: a wait held short moves a verdict only from pass or fail toward inconclusive, never the reverse', () => {
  let seed = 0x5a1e7f03;
  const rand = () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t ^= t + Math.imul(t ^ (t >>> 7), 61 | t); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const pick = list => list[Math.floor(rand() * list.length)], int = (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));
  const resources = ['POST /v1/charges', 'POST /v1/refunds', null];
  const clause = () => {
    const select = { ...sel(pick([PAY, HOOK])), ...(rand() < 0.3 ? { resource: pick(resources.filter(Boolean)) } : {}) };
    const kind = pick(['effect.exists', 'effect.none', 'effect.count', 'effect.only']);
    if (kind === 'effect.count') return { kind, select, expected: int(0, 2) };
    if (kind === 'effect.only') return { kind, expect: rand() < 0.5 ? [] : [{ select: sel(PAY), count: 1 }], allow: rand() < 0.5 ? [] : [sel(HOOK)], sources: ['http-egress'] };
    return { kind, select };
  };
  const UNDECIDED = ['missing', 'observer-failure'];
  let moved = 0, fromPass = 0, fromFail = 0;
  for (let trial = 0; trial < 400; trial++) {
    const windows = Array.from({ length: int(1, 2) }, (_, k) => {
      const instanceId = `egress-recorder-${k + 1}`, coverage = pick(['complete', 'complete', 'complete', 'partial', 'failed']);
      const events = coverage === 'failed' ? [] : Array.from({ length: int(0, 3) }, (_, i) => sendTo(instanceId, i + 1, pick([PAY, HOOK]), pick(['committed', 'committed', 'denied', 'unknown']), pick(resources)));
      return egressWindow(instanceId, { coverage, reason: pick(['egress-request-after-witness-request', 'egress-request-in-flight', 'collect-failed']), events });
    });
    const shortened = windows.map(w => (rand() < 0.7 ? applySuspendShort({ ...w, suspend: { ...RECORD, shortMs: int(1, RECORD.ms) } }) : w));
    shortened.forEach(w => { validateWindow(w); assert.equal(applySuspendShort(w), w, 'a shortened window is its own fixed point'); });
    const effects = Array.from({ length: int(1, 3) }, clause), role = pick(['boundary', 'control']);
    const before = decideEffects(effects, windows, { role }), after = decideEffects(effects, shortened, { role });
    after.forEach((d, i) => {
      const was = before[i].verdict;
      if (d.verdict === was) return;
      assert.ok(UNDECIDED.includes(d.verdict), `trial ${trial} clause ${i}: ${was} -> ${d.verdict}`);
      assert.ok(!UNDECIDED.includes(was), `trial ${trial} clause ${i}: an undecided clause never moves`);
      moved++; if (was === 'pass') fromPass++; if (was === 'fail') fromFail++;
    });
  }
  assert.ok(fromPass > 20 && fromFail > 5, `exercised: ${moved} moved (${fromPass} from pass, ${fromFail} from fail)`);
});

// A virtual host for the settle waits. `now` is the run's clock, which counts sleep as Node's does on macOS (mach_continuous_time);
// `suspended` is the time asleep so far, so awake time is now - suspended. The app commits each send `delay` ms of awake time after
// its reply. onSleep(ms, n) => [awakeBeforeSleep, asleep] or null: the n-th wait of the run is overlapped by a suspend; its timer
// fires at the later of its own end and the wake, as a timer on mach_continuous_time does.
const VHOST = 'hooks.desk.example';
// sendOn: the POST path whose reply schedules the app's send (status: that reply's status); onSleep also gets the host, so a
// test can place a suspend after a given request (v.posts counts the POSTs sent).
function virtualHost({ onSleep = () => null, delay = 4000, sendOn = '/refund', status = 200 } = {}) {
  const v = { now: 1000, suspended: 0, sleeps: [], sends: [], posts: 0 };
  v.awake = () => v.now - v.suspended;
  v.clock = { now: () => v.now, sleep: async ms => {
    v.sleeps.push(ms);
    const s = onSleep(ms, v.sleeps.length, v);
    if (s) { const [before, asleep] = s; v.now += Math.max(ms, before + asleep); v.suspended += asleep; } else v.now += ms;
    await null;
  } };
  v.detector = (timersCountSuspend = true, awake = v.awake) => createSuspendDetector({ wall: () => WALL0 + v.now, awake, elapsed: () => v.now, timersCountSuspend });
  v.transport = async (origin, check) => {
    v.now += 20;
    if (check.method === 'POST') v.posts += 1;
    if (check.method === 'POST' && check.path === sendOn) { v.sends.push({ at: v.awake() + delay, seq: v.sends.length + 1 }); return { status, complete: true, jsonParsed: true, json: {}, bytes: 2 }; }
    return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  // One authoritative egress observer whose marks are points in awake time: a window holds the sends committed after its start mark.
  v.observers = configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`;
    let n = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [VHOST], actorAttribution: 'principal', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, markWitnessRequest() {},
      async mark() { return { at: v.awake(), witnessNonce: `nonce-${n++}` }; },
      async collect(from, to) {
        const events = v.sends.filter(s => s.at > from.at && s.at <= to.at).map(s => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: s.seq, operation: 'send', name: VHOST, actor: 'owner-1', outcome: 'committed', content: { seq: s.seq } }));
        return { events, coverage: 'complete', reason: null };
      } };
  });
  return v;
}
function deskProfile({ timing = null, perCheck = false } = {}) {
  const p = { id: 'suspend-desk', name: 'Suspend desk', applicationId: 'suspend-desk', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { owner: { principalId: 'owner-1' } }, requiredControlIds: ['REFUND'],
    // A declared witness (routing needs one); the injected observer sends none, so its windows close at the end mark.
    observers: [{ id: 'gate', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: VHOST }], witness: { actorId: 'owner', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 5000, quietMs: 150 }],
    checks: [{ id: 'REFUND', title: 'Refund', category: 'Allowed use', severity: 'control', actorId: 'owner', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: VHOST } }] }] };
  // Per-check settlement (one barrier, the largest settle, after each observed check) needs a declared correlation header.
  if (perCheck) { Object.assign(p, { settlement: { mode: 'per-check' }, correlation: { header: 'x-request-id' } }); p.observers[0].destinations[0].correlation = { header: 'x-request-id' }; }
  if (timing) p.timing = { effectHorizonMs: timing.H, runBudgetMs: TIMING_BOUNDS.runBudgetMs[1] };
  if (timing) p.timing.runBudgetMs = Math.max(TIMING_BOUNDS.runBudgetMs[0], plannedTimingMs(p, { controlPlan: identityControlPlan(p) }));
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return p;
}
const suiteOf = p => createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
const effectStatus = run => run.results.find(r => r.id === 'REFUND').assertions.find(a => a.name === 'Observed effect 1 (effect.exists)').status;

test('settle: a suspend inside the post-response settle extends it by the awake time it took, so the app\'s send lands in its own window', async () => {
  // The first wait of the run is the check's settle (5000 ms): asleep for 3000 ms of it, 500 ms in. The webhook comes 4000 ms of
  // awake time after the reply, which the shortened settle (2000 ms awake) misses.
  const asleep = () => (ms, n) => (n === 1 ? [500, 3000] : null);
  const p = deskProfile();
  const v = virtualHost({ onSleep: asleep() });
  const run = await runHttpAssessment(p, { env: {}, clock: v.clock, transport: v.transport, observerFactory: v.observers, suspendClock: v.detector() });
  assert.deepEqual(v.sleeps, [5000, 3000, 5000], 'settle, its 3000 ms extension, then the final settle');
  assert.equal(effectStatus(run), 'pass');
  const window = run.results.find(r => r.id === 'REFUND').trace[1].data.windows[0];
  assert.deepEqual(window.suspend, { cause: 'host-sleep', count: 1, ms: 3000, from: new Date(WALL0 + 1000 + 20).toISOString(), to: new Date(WALL0 + 1000 + 20 + 5000).toISOString() });
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suiteOf(p) });
  // Adjacent, the behaviour before this change (the wait not extended): the send falls after the end mark and the clause cannot pass.
  const old = virtualHost({ onSleep: asleep() });
  const before = await runHttpAssessment(p, { env: {}, clock: old.clock, transport: old.transport, observerFactory: old.observers, suspendClock: old.detector(false) });
  assert.deepEqual(old.sleeps, [5000, 5000]);
  assert.notEqual(effectStatus(before), 'pass');
  validateHttpRunEvidence(before, { expectedSuite: suiteOf(p) });
  // A suspend far longer than the wait: the timer fires at wake; with room in the run budget (here 300 s), the extension is at most
  // the wait's own length.
  const long = virtualHost({ onSleep: (ms, n) => (n === 1 ? [400, 112000] : null) });
  const capped = await runHttpAssessment(p, { env: {}, clock: long.clock, transport: long.transport, observerFactory: long.observers, suspendClock: long.detector(), limits: { ...HTTP_LIMITS, runTimeoutMs: 300000 } });
  assert.deepEqual(long.sleeps, [5000, 5000, 5000], 'extended by 5000 ms, not by the 112 s suspend');
  assert.equal(effectStatus(capped), 'pass', '400 + 5000 ms awake holds the 4000 ms send');
  validateHttpRunEvidence(capped, { expectedSuite: suiteOf(p) });
  // The same sleep under the default 60 s run budget: the run clock, counting the sleep, is already past where the final settle must
  // start, so nothing is extended (the run never passes its deadline for an extension).
  const spent = virtualHost({ onSleep: (ms, n) => (n === 1 ? [400, 112000] : null) });
  await runHttpAssessment(p, { env: {}, clock: spent.clock, transport: spent.transport, observerFactory: spent.observers, suspendClock: spent.detector() });
  assert.deepEqual(spent.sleeps, [5000, 5000]);
  // A run on an injected clock with no injected detector reads no host clock (virtual time waits on no host timer): never extended.
  const virtualOnly = virtualHost({ onSleep: asleep() });
  const inert = await runHttpAssessment(p, { env: {}, clock: virtualOnly.clock, transport: virtualOnly.transport, observerFactory: virtualOnly.observers });
  assert.deepEqual(virtualOnly.sleeps, [5000, 5000]);
  assert.equal(effectStatus(inert), effectStatus(before));
  // A suspend under the detector's 2 s threshold is not seen: nothing is extended or recorded (the threshold is the floor).
  const short = virtualHost({ onSleep: (ms, n) => (n === 1 ? [500, 1500] : null) });
  await runHttpAssessment(p, { env: {}, clock: short.clock, transport: short.transport, observerFactory: short.observers, suspendClock: short.detector() });
  assert.deepEqual(short.sleeps, [5000, 5000]);
  // No suspend: no extension, nothing recorded.
  const quiet = virtualHost();
  const q = await runHttpAssessment(p, { env: {}, clock: quiet.clock, transport: quiet.transport, observerFactory: quiet.observers, suspendClock: quiet.detector() });
  assert.deepEqual(quiet.sleeps, [5000, 5000]);
  assert.equal(Object.hasOwn(q.results.find(r => r.id === 'REFUND').trace[1].data.windows[0], 'suspend'), false);
});

test('horizon (declared timing): the extension is never past the wait deadline, and the horizon is sealed as the awake time it held', async () => {
  const H = 30000, delay = 28000, p = deskProfile({ timing: { H } });
  // 3000 ms asleep inside the horizon: extended by 3000 ms, within the budget, so the late webhook lands in its own window.
  const v = virtualHost({ delay, onSleep: (ms, n) => (ms === H && n === 1 ? [1000, 3000] : null) });
  const run = await runHttpAssessment(p, { env: {}, clock: v.clock, transport: v.transport, observerFactory: v.observers, suspendClock: v.detector() });
  assert.deepEqual(v.sleeps.slice(0, 2), [H, 3000]);
  assert.equal(effectStatus(run), 'pass');
  assert.deepEqual(run.timing.rows.map(r => r.waitedMs), [H], 'restored in full: the horizon held its declared awake time');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  const deadline = 1000 + p.timing.runBudgetMs;
  const windowOf = r => r.results.find(x => x.id === 'REFUND').trace[1].data.windows[0];
  // `before`: the earlier behaviour (the suspend is recorded but nothing is extended or sealed short), which seals H whatever was lost.
  const pair = async asleep => {
    const onSleep = (ms, n) => (ms === H && n === 1 ? [1000, asleep] : null);
    const now = virtualHost({ delay, onSleep }), old = virtualHost({ delay, onSleep });
    const run = await runHttpAssessment(p, { env: {}, clock: now.clock, transport: now.transport, observerFactory: now.observers, suspendClock: now.detector() });
    const before = await runHttpAssessment(p, { env: {}, clock: old.clock, transport: old.transport, observerFactory: old.observers, suspendClock: old.detector(false) });
    for (const r of [run, before]) validateHttpRunEvidence(r, { expectedSuite: suiteOf(p) });
    assert.deepEqual(before.timing.rows.map(x => x.waitedMs), [H]);
    return { now, old, run, before };
  };
  // 112 s asleep, waking with less room before the wait deadline than the awake time lost: the extension stops at that deadline, the
  // run's clock never passes its declared budget, and the horizon is sealed as the awake time it held (the extension, as the awake
  // time before the sleep is not counted), so it reads truncated: the window is partial and the clause cannot pass.
  const clipped = await pair(112000);
  assert.equal(clipped.old.sleeps.length, 2);
  assert.deepEqual([clipped.now.sleeps.length, clipped.now.sleeps[0], clipped.now.sleeps[2]], [3, H, clipped.old.sleeps[1]]);
  assert.ok(clipped.now.sleeps[1] >= 1 && clipped.now.sleeps[1] < H, `clipped below min(H, lost): ${clipped.now.sleeps[1]}`);
  assert.ok(clipped.now.now <= deadline, `${clipped.now.now} <= ${deadline}`);
  assert.deepEqual(clipped.run.timing.rows.map(x => x.waitedMs), [clipped.now.sleeps[1]], 'sealed as the awake time the horizon held');
  assert.deepEqual([windowOf(clipped.run).coverage, windowOf(clipped.run).reason], ['partial', HORIZON_TRUNCATED]);
  assert.equal(effectStatus(clipped.run), 'inconclusive', 'the clipped horizon could not hold the 28 s send: no verdict rests on it');
  // 300 s asleep: the wake is already past the wait deadline, so nothing is extended; the horizon held no awake time after the sleep.
  const past = await pair(300000);
  assert.deepEqual(past.now.sleeps, past.old.sleeps);
  assert.deepEqual(past.now.sleeps, [H]);
  assert.deepEqual(past.run.timing.rows.map(x => x.waitedMs), [0]);
  assert.equal(windowOf(past.run).coverage, 'partial');
  assert.equal(effectStatus(past.run), 'inconclusive');
});

test('barrier and final settle: a suspend in either is extended the same way, and without a declared plan never past the run deadline', async () => {
  const assess = async (p, onSleep, limits = HTTP_LIMITS) => {
    const v = virtualHost({ onSleep });
    const run = await runHttpAssessment(p, { env: {}, clock: v.clock, transport: v.transport, observerFactory: v.observers, suspendClock: v.detector(), limits });
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
    return { v, run };
  };
  const asleepIn = (wait, before = 1000, asleep = 3000) => (ms, n) => (n === wait ? [before, asleep] : null);
  // Per-check settlement: the check's settle, its barrier, then the final settle. 3000 ms asleep inside the barrier (wait 2).
  const barrier = await assess(deskProfile({ perCheck: true }), asleepIn(2));
  assert.deepEqual(barrier.v.sleeps, [5000, 5000, 3000, 5000], 'settle, barrier, the barrier\'s 3000 ms extension, final settle');
  assert.equal(effectStatus(barrier.run), 'pass');
  // Run mode: 3000 ms asleep inside the final settle (wait 2), extended before the final mark.
  const plain = deskProfile();
  const tail = await assess(plain, asleepIn(2));
  assert.deepEqual(tail.v.sleeps, [5000, 5000, 3000]);
  // Under a declared plan, the final settle's extension is bounded by the run deadline, and here fits within it.
  const H = 30000, timed = deskProfile({ timing: { H } });
  const timedTail = await assess(timed, asleepIn(2));
  assert.deepEqual(timedTail.v.sleeps, [H, 5000, 3000]);
  assert.ok(timedTail.v.now <= 1000 + timed.timing.runBudgetMs);
  // Without a declared plan, a 12 s run budget (deadline 13000 ms): the check's settle (from 1020 ms, 3000 ms of it asleep) may be
  // extended only to where the final settle still fits (13000 - 5000), so by 1980 ms, not 3000; the final settle (3000 ms of it
  // asleep too) ends at the deadline, which leaves no room to extend it. The run never passes its deadline.
  const tight = await assess(plain, (ms, n) => (n === 1 || n === 3 ? [500, 3000] : null), { ...HTTP_LIMITS, runTimeoutMs: 12000 });
  assert.deepEqual(tight.v.sleeps, [5000, 1980, 5000]);
  assert.ok(tight.v.now <= 1000 + 12000, `${tight.v.now} <= the run deadline`);
  // A 10 s budget leaves no room before the final settle at all: the settle is not extended (the declared waits are as before).
  const roomless = await assess(plain, asleepIn(1, 500, 3000), { ...HTTP_LIMITS, runTimeoutMs: 10000 });
  assert.deepEqual(roomless.v.sleeps, [5000, 5000]);
});

// A GET control, then a high-severity check whose app refuses (403) yet makes
// the forbidden send `delay` ms of awake time after its reply; an effect.none clause forbids it. A suspend the extension cannot
// restore used to leave the window complete, so the clause passed on missing evidence (the earlier behaviour does, silently).
function forbidProfile({ timing = null, settleMs = 5000 } = {}) {
  const p = { id: 'suspend-forbid', name: 'Suspend forbid', applicationId: 'suspend-forbid', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { owner: { principalId: 'owner-1' } }, requiredControlIds: ['ME'],
    observers: [{ id: 'gate', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: VHOST }], witness: { actorId: 'owner', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs, quietMs: 150 }],
    checks: [{ id: 'ME', title: 'Me', category: 'Allowed use', severity: 'control', actorId: 'owner', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'FORBID', title: 'Forbid', category: 'Object access', severity: 'high', actorId: 'owner', method: 'POST', path: '/forbid', body: {}, evidenceRequirement: 'response',
        assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: VHOST } }] }] };
  if (timing) { p.timing = { effectHorizonMs: timing.H, runBudgetMs: TIMING_BOUNDS.runBudgetMs[1] }; p.timing.runBudgetMs = Math.max(TIMING_BOUNDS.runBudgetMs[0], plannedTimingMs(p, { controlPlan: identityControlPlan(p) })); }
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return p;
}
const forbidRow = run => run.results.find(r => r.id === 'FORBID');
const forbidEffect = run => forbidRow(run).assertions.find(a => a.name === 'Observed effect 1 (effect.none)');
const forbidRun = async (p, { delay, onSleep, detectorOf }) => {
  const v = virtualHost({ delay, sendOn: '/forbid', status: 403, onSleep });
  const run = await runHttpAssessment(p, { env: {}, clock: v.clock, transport: v.transport, observerFactory: v.observers, suspendClock: detectorOf(v) });
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  return { v, run };
};

test('sweep (declared timing): a horizon the sleep cut short beyond what the budget restores is sealed short and reads partial; no absence passes on missing evidence', async t => {
  const H = 30000, p = forbidProfile({ timing: { H } });
  // The suspend lands 1 s into the FORBID horizon (the first H-long wait after its POST; the earlier one is its lead-in).
  const inHorizon = asleep => (ms, n, v) => (asleep && v.posts === 1 && ms === H && !v.cut ? (v.cut = true, [1000, asleep]) : null);
  const table = [];
  for (const seconds of [0, 50, 60, 70, 80, 90, 100, 112]) {
    const now = await forbidRun(p, { delay: 28000, onSleep: inHorizon(seconds * 1000), detectorOf: v => v.detector() });
    const main = await forbidRun(p, { delay: 28000, onSleep: inHorizon(seconds * 1000), detectorOf: v => v.detector(false) });
    const held = now.run.timing.rows.find(r => r.id === 'FORBID').waitedMs, window = forbidRow(now.run).trace[1].data.windows[0];
    const status = forbidEffect(now.run).status;
    table.push({ seconds, status, held, main: forbidEffect(main.run).status });
    assert.notEqual(status, 'pass', `${seconds} s asleep: never a pass on missing evidence (${JSON.stringify(table.at(-1))})`);
    if (held < H) {
      assert.deepEqual([window.coverage, window.reason.split(',').includes(HORIZON_TRUNCATED), status], ['partial', true, 'inconclusive'], `${seconds} s: held ${held} ms of ${H}`);
      assert.match(forbidEffect(now.run).actual, /host suspended \(sleep\) about \d+ s between .*effect-horizon-truncated/);
    } else assert.equal(status, 'fail', `${seconds} s: the horizon held in full, so the forbidden send is in its window`);
  }
  // Not vacuous: the sweep covers held-in-full and held-short horizons, and the earlier behaviour still passes where this one is short.
  assert.ok(table.some(r => r.held === H && r.seconds > 0) && table.some(r => r.held < H), JSON.stringify(table));
  assert.ok(table.some(r => r.seconds >= 80 && r.held < H && r.main === 'pass'), `the earlier behaviour passes wrongly where the horizon is short: ${JSON.stringify(table)}`);
  t.diagnostic(`timing sweep (seconds asleep, status, awake ms held of ${H}, the earlier behaviour): ${table.map(r => `${r.seconds}:${r.status}/${r.held}/${r.main}`).join(' ')}`);
});

test('sweep (no timing plan): a settle the sleep cut short beyond the spare budget reads partial (host-suspend-wait-short), and so does the run-end window; no absence passes', async t => {
  const p = forbidProfile();
  // The suspend lands in the FORBID settle (the first 5000 ms wait after its POST) and again in the final settle (the next one: with
  // the default 60 s budget these sleeps leave less than 5000 ms of room, so no extension is ever exactly 5000 ms).
  const inBoth = asleep => (ms, n, v) => (v.posts === 1 && ms === 5000 && (v.cuts ?? 0) < 2 ? (v.cuts = (v.cuts ?? 0) + 1, [v.cuts === 1 ? 500 : 100, asleep]) : null);
  const table = [];
  for (const seconds of [50, 60, 70, 80, 90, 100]) {
    const now = await forbidRun(p, { delay: 4800, onSleep: inBoth(seconds * 1000), detectorOf: v => v.detector() });
    const main = await forbidRun(p, { delay: 4800, onSleep: inBoth(seconds * 1000), detectorOf: v => v.detector(false) });
    const window = forbidRow(now.run).trace[1].data.windows[0], tail = now.run.settlement.gaps.at(-1).windows[0], status = forbidEffect(now.run).status;
    table.push({ seconds, status, shortMs: window.suspend?.shortMs ?? 0, tailShortMs: tail.suspend?.shortMs ?? 0, main: forbidEffect(main.run).status });
    assert.notEqual(status, 'pass', `${seconds} s asleep: ${JSON.stringify(table.at(-1))}`);
    assert.ok(window.suspend?.shortMs > 0 && window.coverage === 'partial' && carriesSuspendShort(window), JSON.stringify(window.suspend));
    assert.ok(tail.suspend?.shortMs > 0 && tail.coverage === 'partial' && carriesSuspendShort(tail), 'the run-end window, held short too, reads partial');
    // A recorded forbidden send still decides (fail, on presence); without one the clause is inconclusive, and says why.
    assert.equal(status, window.events.length ? 'fail' : 'inconclusive');
    if (status === 'inconclusive') assert.match(forbidEffect(now.run).actual, /and its wait held about \d+ s less awake time than declared, host-suspend-wait-short\)/);
  }
  assert.ok(table.some(r => r.main === 'pass'), `the earlier behaviour passes wrongly in this sweep: ${JSON.stringify(table)}`);
  t.diagnostic(`no-plan sweep (seconds asleep, status, settle shortMs, tail shortMs, the earlier behaviour): ${table.map(r => `${r.seconds}:${r.status}/${r.shortMs}/${r.tailShortMs}/${r.main}`).join(' ')}`);
  // The shortfall is sealed evidence: dropped from the record, or the window stored complete with it, the run is refused.
  const { run } = await forbidRun(p, { delay: 4800, onSleep: inBoth(80000), detectorOf: v => v.detector() });
  const reseal = edit => {
    const forged = structuredClone(run), fx = forged.results.find(x => x.id === 'FORBID');
    edit(fx.trace[1].data.windows[0]);
    fx.evidenceDigest = digest({ evidence: fx.trace[0].data, effects: fx.trace[1].data, assertions: fx.assertions });
    return forged;
  };
  validateHttpRunEvidence(reseal(() => {}));
  for (const edit of [w => { delete w.suspend.shortMs; }, w => { w.coverage = 'complete'; w.reason = null; }, w => { w.suspend.shortMs = w.suspend.ms + 1; }])
    assert.throws(() => validateHttpRunEvidence(reseal(edit)), error => error.code === 'invalid-run-evidence', String(edit));
});

test('inert: where the timers count sleep but no awake clock can be read, every verdict is exactly the earlier behaviour\'s, and every coverage-decided row says host sleep could not be checked', async () => {
  const p = forbidProfile();
  const inBoth = (ms, n, v) => (v.posts === 1 && ms === 5000 && (v.cuts ?? 0) < 2 ? (v.cuts = (v.cuts ?? 0) + 1, [v.cuts === 1 ? 500 : 100, 70000]) : null);
  // inert: the timers count sleep, no awake clock. The second run: a detector that reads no clock, which neither sees nor records a suspend.
  const inert = await forbidRun(p, { delay: 4800, onSleep: inBoth, detectorOf: v => v.detector(true, null) });
  const main = await forbidRun(p, { delay: 4800, onSleep: inBoth, detectorOf: v => v.detector(false, null) });
  assert.deepEqual(inert.v.sleeps, main.v.sleeps, 'nothing extended');
  assert.deepEqual(inert.run.results.map(r => [r.id, r.status, r.assertions.map(a => a.status)]), main.run.results.map(r => [r.id, r.status, r.assertions.map(a => a.status)]));
  const window = forbidRow(inert.run).trace[1].data.windows[0];
  assert.deepEqual([window.suspendUnchecked, Object.hasOwn(window, 'suspend'), window.coverage], [true, false, 'complete']);
  assert.equal(forbidEffect(main.run).status, 'pass', 'the earlier behaviour passes this case on missing evidence; inert is never more lenient than that');
  assert.equal(forbidEffect(inert.run).actual, `${forbidEffect(main.run).actual} ${SUSPEND_UNCHECKED_NOTE}`.slice(0, 600));
  assert.ok(!Object.hasOwn(forbidRow(main.run).trace[1].data.windows[0], 'suspendUnchecked'), 'where the timers do not count sleep, nothing is said');
});

// End to end over loopback: a check whose app makes a send after the witness request, with nothing after it to follow it,
// reads inconclusive. With a host suspend injected during the check (fake clocks over the real ones; the run's waits are not
// extended here), the same verdict now names the suspend; the run validates, and the record cannot be edited or dropped.
async function lateApp(t, sinkPort, onLate) {
  let pendingLate = false;
  const outbound = (target, body) => new Promise(resolve => { const url = new URL(target); const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(body); });
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { if (pendingLate) { pendingLate = false; await outbound(`http://${HOOK}/audit`, '{}'); } await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (url.pathname === '/charge/late') { pendingLate = true; onLate(); return reply(403, {}); }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const opsEnv = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const lateRun = (t, suspendMs) => onFreePorts(1, async port => {
  const host = { jump: 0 };
  const p = { id: 'late', name: 'Late', applicationId: 'late', origin: await lateApp(t, port, () => { host.jump += suspendMs; }), buildLabel: 'b1', contextId: 'synthetic-late',
    actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
    observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1'] }, { host: HOOK }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
      { id: 'LATE', title: 'LATE', category: 'payments', severity: 'high', actorId: 'ops', method: 'POST', path: '/charge/late', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: sel(PAY) }] }] };
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  // Real time, with the suspend added to the elapsed and wall clocks only (the awake clock never saw it).
  const suspendClock = createSuspendDetector({ wall: () => Date.now() + host.jump, awake: () => performance.now(), elapsed: () => performance.now() + host.jump });
  const watch = watchingBinds(buildObservers);
  return { p, run: await runHttpAssessment(p, { env: opsEnv, observerFactory: watch.factory, suspendClock }), lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('late send end to end: the partial window that made a clean case abstain now says the host was suspended; the verdict is the same, and the record is sealed', async t => {
  const plainRun = await lateRun(t, 0), slept = await lateRun(t, 112000);
  const rowOf = r => r.run.results.find(x => x.id === 'LATE'), effectOf = row => row.assertions.find(a => a.name === 'Observed effect 1 (effect.none)');
  const a = rowOf(plainRun), b = rowOf(slept);
  assert.deepEqual([effectOf(a).status, effectOf(b).status], ['inconclusive', 'inconclusive']);
  assert.deepEqual(a.trace[1].data.effects.map(d => d.verdict), b.trace[1].data.effects.map(d => d.verdict));
  assert.equal(Object.hasOwn(a.trace[1].data.windows[0], 'suspend'), false);
  const record = b.trace[1].data.windows[0].suspend;
  assert.deepEqual([record.cause, record.count, record.ms], ['host-sleep', 1, 112000]);
  assert.ok(validSuspendRecord(record));
  assert.equal(effectOf(a).actual, 'missing: Not every authoritative observer that can see this effect covered the window (egress-recorder-sink: partial, egress-request-after-witness-request).');
  assert.equal(effectOf(b).actual, `missing: Not every authoritative observer that can see this effect covered the window (egress-recorder-sink: partial${suspendNote(record)}, egress-request-after-witness-request).`);
  for (const r of [plainRun, slept]) validateHttpRunEvidence(r.run, { expectedSuite: createRegistry({ profiles: [r.p], env: opsEnv }).exportSuite(r.p.id) });
  // The record is evidence the basis is recomputed from: changed, malformed or dropped (and the row resealed), the run is refused.
  const reseal = (edit) => {
    const forged = structuredClone(slept.run), fx = forged.results.find(x => x.id === 'LATE');
    edit(fx.trace[1].data.windows[0]);
    fx.evidenceDigest = digest({ evidence: fx.trace[0].data, effects: fx.trace[1].data, assertions: fx.assertions });
    return forged;
  };
  validateHttpRunEvidence(reseal(() => {}));
  for (const edit of [w => { w.suspend.ms = 5000; }, w => { w.suspend.cause = 'nap'; }, w => { delete w.suspend; }, w => { w.suspend.from = 'yesterday'; }])
    assert.throws(() => validateHttpRunEvidence(reseal(edit)), error => error.code === 'invalid-run-evidence', String(edit));
});

// The mechanism, end to end over loopback: the host sleeps during the check's settle; the run's timer, counting the sleep, ends
// the settle at wake, and the app's requests made after wake (its wake burst) arrive after the witness request, so the window reads
// partial and the clean case inconclusive. Here the app answers at once and makes its send to HOOK burstMs later (or, when the witness
// ping comes first, just before answering it, after the witness request, as in the case above); the sleep is injected into the detector's
// clocks 100 ms into the settle, as lost awake time. The earlier behaviour (a detector that reads no clock: no record, no extension) is
// partial and inconclusive; with the extension the settle covers the burst, the recorder sees it inside the window, and the window
// is complete, so the clause decides on what the recorder saw.
async function wakeApp(t, sinkPort, { burstMs, onReply }) {
  let pending = null;
  const outbound = (target, body) => new Promise(resolve => { const url = new URL(target); const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(body); });
  const burst = () => { pending = null; return outbound(`http://${HOOK}/audit`, '{}'); };
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { if (pending) { clearTimeout(pending); await burst(); } await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (url.pathname === '/charge/wake') { pending = setTimeout(burst, burstMs); onReply(); return reply(403, {}); }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { if (pending) clearTimeout(pending); server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const SETTLE = 800, BURST = 1300, ASLEEP = 3000;
const wakeRun = (t, detectorOf) => onFreePorts(1, async port => {
  const host = { jump: 0 };
  const p = { id: 'wake', name: 'Wake', applicationId: 'wake', origin: await wakeApp(t, port, { burstMs: BURST, onReply: () => setTimeout(() => { host.jump += ASLEEP; }, 100) }), buildLabel: 'b1', contextId: 'synthetic-wake',
    actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
    observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1'] }, { host: HOOK }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: SETTLE, quietMs: 150 }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
      { id: 'LATE', title: 'LATE', category: 'payments', severity: 'high', actorId: 'ops', method: 'POST', path: '/charge/wake', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: sel(PAY) }] }] };
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const watch = watchingBinds(buildObservers);
  return { p, run: await runHttpAssessment(p, { env: opsEnv, observerFactory: watch.factory, suspendClock: detectorOf(host) }), lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('late send end to end, the wait: a settle the host slept through is extended in awake time, so the wake burst lands inside the window, the window is complete and the clean case decides', async t => {
  const rowOf = r => r.run.results.find(x => x.id === 'LATE'), effectOf = row => row.assertions.find(a => a.name === 'Observed effect 1 (effect.none)');
  const validated = r => validateHttpRunEvidence(r.run, { expectedSuite: createRegistry({ profiles: [r.p], env: opsEnv }).exportSuite(r.p.id) });
  // The earlier behaviour: no suspend is seen, the settle ends on its timer, the burst comes after the witness request.
  const main = await wakeRun(t, () => createSuspendDetector({ awake: null, elapsed: null }));
  const before = rowOf(main), beforeWindow = before.trace[1].data.windows[0];
  assert.deepEqual([beforeWindow.coverage, beforeWindow.reason], ['partial', 'egress-request-after-witness-request']);
  assert.equal(Object.hasOwn(beforeWindow, 'suspend'), false);
  assert.equal(effectOf(before).status, 'inconclusive');
  assert.equal(effectOf(before).actual, 'missing: Not every authoritative observer that can see this effect covered the window (egress-recorder-sink: partial, egress-request-after-witness-request).');
  validated(main);
  // This change: the detector sees the 3000 ms lost inside the settle and extends it (by at most its own 800 ms), the burst at
  // 1300 ms lands before the end mark, and the recorder saw everything the app sent in the window.
  const fixed = await wakeRun(t, host => createSuspendDetector({ wall: () => Date.now() + host.jump, awake: () => performance.now(), elapsed: () => performance.now() + host.jump, timersCountSuspend: true }));
  const after = rowOf(fixed), afterWindow = after.trace[1].data.windows[0];
  assert.deepEqual([afterWindow.coverage, afterWindow.reason, Object.hasOwn(afterWindow, 'scoped')], ['complete', null, false]);
  assert.deepEqual(afterWindow.events.map(e => [e.name, e.resource, e.outcome]), [[HOOK, 'POST *', 'committed']], 'the wake burst, seen inside the window');
  const record = afterWindow.suspend;
  assert.deepEqual([record.cause, record.count, record.ms], ['host-sleep', 1, ASLEEP]);
  assert.equal(effectOf(after).status, 'pass');
  assert.equal(effectOf(after).actual, `pass: Every authoritative observer that can see this effect (egress-recorder-sink) covered the window and recorded no matching committed effect. ${suspendHeldNote(record)}`);
  validated(fixed);
});
