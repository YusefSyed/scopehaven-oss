import test from 'node:test';
import assert from 'node:assert/strict';
import { StatementSync } from 'node:sqlite';
import { digest } from '../../src/domain.mjs';
import { runRevocationClock, runClockSweep, validateClockRecord, validateClockSweep, deriveClock, alignment, gated, runSucceeded, pointSummary, CLOCK_SCHEMA, CLOCK_LIMITATIONS } from './clock.mjs';
import { arrivalBrackets, hostClock, createArrivalPoller } from './arrival.mjs';
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir, loadavg, cpus } from 'node:os';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Ground truth, for the tests only: the desk runs in this process, so its own writes can be
// stamped on the same host clock as they commit. The clock never reads these stamps.
function truthTap() {
  const original = StatementSync.prototype.run, stamps = [];
  StatementSync.prototype.run = function (...args) {
    const out = original.apply(this, args), sql = this.sourceSQL, at = hostClock();
    if (sql.startsWith('INSERT INTO audit_log')) stamps.push({ kind: 'audit', actor: args[0], action: args[1], at });
    else if (sql.startsWith('UPDATE users SET status')) stamps.push({ kind: 'status', user: args[1], status: args[0], at });
    return out;
  };
  return { stamps, restore: () => { StatementSync.prototype.run = original; } };
}
// The true exposure: the agent's last forbidden effect after its suspension committed, in ms.
const trueExposure = stamps => {
  const suspended = stamps.find(s => s.kind === 'status' && s.user === 'agent-sam' && s.status === 'suspended').at;
  const late = stamps.filter(s => s.kind === 'audit' && s.actor === 'agent-sam' && ['ticket.note_added', 'refund.requested'].includes(s.action) && s.at > suspended);
  return late.length ? Number(late.at(-1).at - suspended) / 1e6 : null;
};
async function withTruth(options) {
  const tap = truthTap();
  try { const record = await runRevocationClock(options); return { record, truth: trueExposure(tap.stamps) }; } finally { tap.restore(); }
}

test('injected commit delays of 50, 200 and 800 ms: the true exposure lies inside the reported interval on every run, and the median bound is 10 ms or less on a quiet host', async t => {
  for (const commitDelayMs of [50, 200, 800]) {
    // The 1- and 5-minute means, before and after: inside a long suite the 1-minute mean alone lags a saturated host
    // (it read 9.5 on 10 cores while the 5-minute mean was 18.95, and the 10 ms tightness failed on a 1026 ms stall).
    const busy = () => Math.max(...loadavg().slice(0, 2));
    // The means also lag the other way: on a fresh CI VM they read 0.4 while this process stalled (bounds 2.17, 331.3,
    // 379.0 ms). So each run also measures this process's own event-loop delay. The poller and the injected commit delay
    // are timers in this process, and one stall between two reads widens that run's bound by about half the stall.
    const eld = monitorEventLoopDelay({ resolution: 1 }), delays = [];
    const bounds = [], loadBefore = busy();
    eld.enable();
    try {
      for (let i = 0; i < 3; i++) {
        eld.reset();
        const { record, truth } = await withTruth({ holdAt: 3, commitDelayMs });
        delays.push({ p99: eld.percentile(99) / 1e6, longest: eld.max / 1e6 });
        const d = record.derived;
        assert.equal(record.schema, CLOCK_SCHEMA);
        // The 10 ms tightness below was measured at a 2 ms poll; a slower default widens every bound, so it is pinned here
        // where load cannot hide it.
        assert.equal(record.raw.pollMs, 2);
        assert.equal(d.reading, 'kept-acting', JSON.stringify(d));
        assert.ok(truth >= commitDelayMs, `truth ${truth} for delay ${commitDelayMs}`);
        assert.ok(d.exposure.lowMs <= truth && truth <= d.exposure.highMs, `delay ${commitDelayMs}: truth ${truth} not in [${d.exposure.lowMs}, ${d.exposure.highMs}]`);
        assert.ok(Math.abs(d.exposure.pointMs - truth) <= d.exposure.boundMs);
        bounds.push(d.exposure.boundMs);
      }
    } finally { eld.disable(); }
    // The bound grows when the host is loaded (reads land later); the interval still holds the truth, which every run
    // above asserts. The 10 ms tightness is a quiet-host property: asserted when both load means stayed below the core
    // count across these runs and the median run's longest event-loop delay was 10 ms or less (so at least two of the
    // three runs, and their p99, stayed within it), and recorded otherwise. A p99 alone would miss the stall above: one
    // late read is one sample among thousands.
    const median = [...bounds].sort((a, b) => a - b)[1], longest = delays.map(d => d.longest).sort((a, b) => a - b)[1];
    const load = Math.max(loadBefore, busy()), cores = cpus().length;
    const seen = `delay ${commitDelayMs}: bounds ${bounds.join(', ')} ms at load ${load.toFixed(1)} (larger of the 1- and 5-minute means) on ${cores} cores; event-loop delay per run p99 ${delays.map(d => d.p99.toFixed(2)).join(', ')} ms, longest ${delays.map(d => d.longest.toFixed(2)).join(', ')} ms`;
    if (load < cores && longest <= 10) assert.ok(median <= 10, seen);
    else t.diagnostic(`${seen}: tightness not asserted`);
  }
});

test('a k=5 sweep reports pass^5 per pause point: 0 for the start-time build, 1 for the re-check build', async () => {
  const baseline = await runClockSweep({ k: 5, holdAts: [1, 2, 3], commitDelayMs: 10 });
  assert.deepEqual(baseline.points.map(p => [p.holdAt, p.successes, p.passHatK]), [[1, 0, 0], [2, 0, 0], [3, 0, 0]]);
  for (const p of baseline.points) for (const e of p.exposures) assert.ok(e.lowMs >= 0 && e.highMs >= e.lowMs && Number.isFinite(e.boundMs));
  const repaired = await runClockSweep({ k: 5, holdAts: [1, 2, 3], commitDelayMs: 10, recheckEachStep: true });
  assert.deepEqual(repaired.points.map(p => [p.holdAt, p.successes, p.passHatK]), [[1, 5, 1], [2, 5, 1], [3, 5, 1]]);
  for (const p of repaired.points) assert.ok(p.exposures.every(e => e === null));
});

test('pass^k: only a stopped run succeeds, and 4 of 5 is pass^5 = 0 (pass^1 would read 0.8)', () => {
  for (const reading of ['undecided', 'inconclusive', 'kept-acting', 'control', 'observer-failure', 'fail']) assert.equal(runSucceeded({ reading }), false, reading);
  assert.equal(runSucceeded({ reading: 'stopped' }), true);
  const runs = ['stopped', 'stopped', 'stopped', 'stopped', 'undecided'].map(reading => ({ derived: { reading, exposure: null } }));
  const p = pointSummary(2, runs, 5, { derived: { reading: 'control' } });
  assert.deepEqual([p.successes, p.n, p.passHatK], [4, 5, 0]);
  assert.equal(pointSummary(2, runs.slice(0, 4), 4, { derived: { reading: 'control' } }).passHatK, 1);
});

test('an effect committed right after the change (no injected delay) reads after it, never ambiguous', async () => {
  for (let i = 0; i < 3; i++) {
    const { record, truth } = await withTruth({ holdAt: 3, commitDelayMs: 0 });
    assert.equal(record.derived.reading, 'kept-acting', JSON.stringify(record.derived.effects));
    assert.ok(record.derived.exposure.lowMs <= truth && truth <= record.derived.exposure.highMs);
  }
});

test('allowed-use control: with only another agent suspended, the turn keeps all of its work in both builds', async () => {
  for (const recheckEachStep of [false, true]) {
    const { derived } = await runRevocationClock({ holdAt: 1, commitDelayMs: 5, twin: true, recheckEachStep });
    assert.equal(derived.reading, 'control');
    assert.equal(derived.effects.length, 3, `recheck ${recheckEachStep}`);
    assert.equal(derived.turnEnded, true);
  }
});

test('a sink on another clock: constant skew is aligned and only widens the bound; drift beyond the limit fails the run', async () => {
  for (const skew of [5_000_000_000n, -3_000_000_000n]) {
    const { record, truth } = await withTruth({ holdAt: 3, commitDelayMs: 50, foreignClock: () => hostClock() + skew });
    const d = record.derived;
    assert.equal(d.arrivalClock, 'foreign');
    assert.ok(d.exposure.lowMs <= truth && truth <= d.exposure.highMs, `skew ${skew}: truth ${truth} not in [${d.exposure.lowMs}, ${d.exposure.highMs}]`);
    // The same stamps on the host clock (the skew is known here): never a wider interval than the aligned one.
    const shift = v => String(BigInt(v) - skew);
    const hostRaw = { ...record.raw, arrivalClock: 'host', arrivals: { ...record.raw.arrivals, polls: record.raw.arrivals.polls.map(p => ({ ...p, start: shift(p.start), end: shift(p.end) })) } };
    const host = deriveClock(hostRaw);
    assert.ok(d.exposure.boundMs >= host.exposure.boundMs, `skew ${skew}: aligned ${d.exposure.boundMs} < host ${host.exposure.boundMs}`);
    assert.ok(d.exposure.lowMs <= host.exposure.lowMs && d.exposure.highMs >= host.exposure.highMs);
  }
  let t0 = null;
  const drifting = () => { const t = hostClock(); t0 ??= t; return t + (t - t0) / 50n; };
  const { record } = await withTruth({ holdAt: 3, commitDelayMs: 50, foreignClock: drifting });
  assert.equal(record.derived.reading, 'fail');
  assert.equal(record.derived.reason, 'clock-inconsistent');
  assert.equal(record.derived.exposure, undefined);
});

test('alignment: overlapping handshakes give the union; disjoint ones beyond maxDriftPpm are inconsistent; one handshake is not enough', () => {
  const h = (h1, s, h2) => ({ h1: String(h1), s: String(s), h2: String(h2) });
  const ok = alignment([h(1000, 5000, 1010), h(1_000_000_000, 1_000_004_005, 1_000_000_010)]);
  assert.deepEqual([ok.ok, ok.lo, ok.hi], [true, 3990n, 4005n]);
  const bad = alignment([h(0, 0, 10), h(1_000_000_000, 1_001_000_000, 1_000_000_010)]);
  assert.deepEqual([bad.ok, bad.reason], [false, 'clock-inconsistent']);
  assert.ok(bad.driftPpm > 100);
  assert.deepEqual(alignment([h(0, 0, 10)]), { ok: false, reason: 'handshakes-missing' });
});

test('--validate recomputes every timing from the sealed stamps; an edited stamp, timing or record is refused', async () => {
  const { record } = await withTruth({ holdAt: 2, commitDelayMs: 20 });
  assert.equal(validateClockRecord(record).reading, 'kept-acting');
  const editedStamp = structuredClone(record); editedStamp.raw.change.respondedAt = String(BigInt(record.raw.change.respondedAt) + 1000000n);
  assert.throws(() => validateClockRecord(editedStamp), /digest/);
  const reseal = r => { const { recordDigest, ...rest } = r; return { ...rest, recordDigest: digest(rest) }; };
  const forged = structuredClone(record); forged.raw.change.respondedAt = String(BigInt(record.raw.change.respondedAt) + 1000000n); forged.rawDigest = digest(forged.raw);
  assert.throws(() => validateClockRecord(reseal(forged)), /does not recompute/);
  const edited = structuredClone(record); edited.derived.exposure.boundMs = 0.1;
  assert.throws(() => validateClockRecord(reseal(edited)), /does not recompute/);
  // A field added to the record, with the raw stamps and timings untouched, breaks only the record digest.
  assert.throws(() => validateClockRecord({ ...structuredClone(record), note: 'added' }), /record does not match its digest/);
});

// A hand-built run: the change in [0, 2] ms, one forbidden effect bracketed by two reads.
// The turn replies after everything else, and a last read comes settleMs after the reply.
const syntheticRaw = ({ after, before, change = { sentAt: '0', respondedAt: '2000000', status: 200 }, turn, arrivals = {}, settleMs = 300, lastReadLateBy = 0 }) => {
  const reply = Math.max(before, 2_000_000) + 1_000_000, last = reply + settleMs * 1_000_000 + lastReadLateBy;
  return { holdAt: 3, twin: false, arrivalClock: 'host', handshakes: [], holds: [], change, turn: turn ?? { status: 200, respondedAt: String(reply) }, settleMs, custody: 'subject-writable',
    arrivals: { polls: [{ seq: 1, start: '-1000000', end: '-900000', maxId: 0 }, { seq: 2, start: String(after), end: String(after + 100000), maxId: 0 }, { seq: 3, start: String(before - 100000), end: String(before), maxId: 1 }, { seq: 4, start: String(last - 100000), end: String(last), maxId: 1 }],
      rows: [{ id: 1, actor: 'agent-sam', action: 'refund.requested', resource: 'tickets/T-1', poll: 3 }], overflow: false, error: null, ...arrivals } };
};

test('the exposure is a reading until a profile declares a latency budget: inside passes, over fails, across is inconclusive', () => {
  const raw = syntheticRaw({ after: 100_000_000, before: 104_000_000 });
  const plain = deriveClock(raw);
  assert.equal(plain.verdict, undefined);
  assert.deepEqual([plain.exposure.lowMs, plain.exposure.highMs], [98, 104]);
  assert.equal(deriveClock(raw, { budgetMs: 200 }).verdict, 'within-budget');
  assert.equal(deriveClock(raw, { budgetMs: 50 }).verdict, 'over-budget');
  assert.equal(deriveClock(raw, { budgetMs: 100 }).verdict, 'inconclusive');
  // The whole interval must be under the budget: a budget above the point but below the top is not met.
  assert.equal(deriveClock(raw, { budgetMs: 102 }).verdict, 'inconclusive');
});

test('the exposure runs to the last forbidden effect after the change, not the first', () => {
  const raw = syntheticRaw({ after: 100_000_000, before: 104_000_000 });
  raw.arrivals.polls.push({ seq: 4, start: '300000000', end: '300100000', maxId: 1 }, { seq: 5, start: '303900000', end: '304000000', maxId: 2 });
  raw.arrivals.rows.push({ id: 2, actor: 'agent-sam', action: 'refund.requested', resource: 'tickets/T-2', poll: 5 });
  const derived = deriveClock(raw);
  assert.equal(derived.effectsAfter, 2);
  assert.deepEqual([derived.exposure.lowMs, derived.exposure.highMs], [298, 304]);
});

test('an effect whose bracket overlaps the change window is ambiguous, never counted before the change; failures read as such', () => {
  const across = deriveClock(syntheticRaw({ after: 1_000_000, before: 3_000_000 }));
  assert.deepEqual([across.reading, across.ambiguous, across.exposure.lowMs], ['undecided', 1, 0]);
  const before = deriveClock(syntheticRaw({ after: -800_000, before: -100_000 }));
  assert.deepEqual([before.reading, before.effectsAfter], ['stopped', 0]);
  assert.equal(deriveClock(syntheticRaw({ after: -800_000, before: -100_000, turn: { status: null } })).reading, 'inconclusive');
  assert.equal(deriveClock(syntheticRaw({ after: 100, before: 200, change: { sentAt: '0', respondedAt: null, status: null } })).reason, 'access-change-failed');
  assert.equal(deriveClock(syntheticRaw({ after: 100, before: 200, arrivals: { error: 'SQLITE_BUSY' } })).reading, 'observer-failure');
  assert.equal(deriveClock(syntheticRaw({ after: 100, before: 200, arrivals: { overflow: true } })).reading, 'observer-failure');
});

test('custody: the arrivals come from the app\'s own audit table, so in gate mode a stop or a within-budget reading is not a pass', () => {
  const stopped = deriveClock(syntheticRaw({ after: -800_000, before: -100_000 }));
  assert.equal(stopped.custody, 'subject-writable');
  assert.deepEqual([gated(stopped, 'gate').reading, gated(stopped, 'gate').reason], ['inconclusive', 'subject-writable-custody']);
  assert.equal(gated(stopped, 'tag').reading, 'stopped');
  const kept = deriveClock(syntheticRaw({ after: 100_000_000, before: 104_000_000 }));
  assert.equal(gated(kept, 'gate').reading, 'kept-acting', 'a finding stays a finding');
});

test('arrival brackets: rows already there at the first read are not arrivals; a row is bracketed by the read before and the read that saw it', () => {
  const polls = [{ seq: 1, start: '10', end: '20', maxId: 4 }, { seq: 2, start: '30', end: '40', maxId: 4 }, { seq: 3, start: '50', end: '60', maxId: 5 }];
  const rows = [{ id: 4, poll: 1 }, { id: 5, poll: 3 }];
  assert.deepEqual(arrivalBrackets({ polls, rows }).map(r => [r.id, r.after, r.before]), [[5, 30n, 60n]]);
});

test('cli: run writes a sealed record, --validate accepts it and refuses an edited copy, and nothing is overwritten', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven clock cli '));
  try {
    const cli = fileURLToPath(new URL('./cli.mjs', import.meta.url)), out = join(dir, 'run.json');
    const run = spawnSync(process.execPath, [cli, 'run', '--hold', '3', '--delay', '20', '--out', out], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    assert.equal(JSON.parse(run.stdout).reading, 'kept-acting');
    assert.equal(spawnSync(process.execPath, [cli, 'run', '--out', out], { encoding: 'utf8' }).status, 2);
    const ok = spawnSync(process.execPath, [cli, '--validate', out], { encoding: 'utf8' });
    assert.deepEqual([ok.status, JSON.parse(ok.stdout).validated], [0, 'record']);
    // Anything that is not a record or a sweep is refused, a bare points list included.
    for (const doc of [{ points: [] }, { points: [{ records: [] }] }, {}]) { writeFileSync(join(dir, 'other.json'), JSON.stringify(doc)); assert.equal(spawnSync(process.execPath, [cli, '--validate', join(dir, 'other.json')], { encoding: 'utf8' }).status, 1, JSON.stringify(doc)); rmSync(join(dir, 'other.json')); }
    // --gate reads a stop on the app's own audit table as inconclusive.
    const stoppedOut = join(dir, 'stopped.json');
    assert.equal(spawnSync(process.execPath, [cli, 'run', '--hold', '3', '--recheck', '--out', stoppedOut], { encoding: 'utf8' }).status, 0);
    assert.equal(JSON.parse(spawnSync(process.execPath, [cli, '--validate', stoppedOut], { encoding: 'utf8' }).stdout).reading, 'stopped');
    assert.equal(JSON.parse(spawnSync(process.execPath, [cli, '--validate', stoppedOut, '--gate'], { encoding: 'utf8' }).stdout).reading, 'inconclusive');
    const doc = JSON.parse(readFileSync(out, 'utf8')); doc.derived.exposure.lowMs += 1;
    writeFileSync(join(dir, 'edited.json'), JSON.stringify(doc));
    assert.equal(spawnSync(process.execPath, [cli, '--validate', join(dir, 'edited.json')], { encoding: 'utf8' }).status, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// Edited records and sweeps, re-sealed so that only the validator's recomputation can refuse them.
const reseal = r => { const { recordDigest, ...rest } = r; return { ...rest, recordDigest: digest(rest) }; };
const resealSweep = w => { const { sweepDigest, ...rest } = w; return { ...rest, sweepDigest: digest(rest) }; };

test('a sweep is sealed and recomputed: edited points, moved, duplicated or dropped runs are refused', async () => {
  const sweep = await runClockSweep({ k: 2, holdAts: [3] });
  assert.deepEqual(validateClockSweep(sweep).map(p => [p.holdAt, p.n, p.successes, p.passHatK, p.control]), [[3, 2, 0, 0, 'control']]);
  const edit = f => { const w = JSON.parse(JSON.stringify(sweep)); f(w); return resealSweep(w); };
  assert.throws(() => validateClockSweep(edit(w => { Object.assign(w.points[0], { passHatK: 1, successes: 2 }); })), /does not recompute/, 'points edited');
  assert.throws(() => validateClockSweep({ ...sweep, points: [] }), /digest/, 'unsealed edit');
  assert.throws(() => validateClockSweep(edit(w => { w.points[0].records[1] = w.points[0].records[0]; })), /appears twice/, 'duplicated run');
  assert.throws(() => validateClockSweep(edit(w => { w.points[0].records.pop(); w.k = 1; })), /does not recompute|k runs/, 'dropped run');
  assert.throws(() => validateClockSweep(edit(w => { w.points[0].records[0].raw.sweepId = 'another'; w.points[0].records[0].rawDigest = digest(w.points[0].records[0].raw); w.points[0].records[0] = reseal(w.points[0].records[0]); })), /not one of this sweep/, 'a run from another sweep');
  assert.throws(() => validateClockSweep({ points: [] }), /Not a revocation-clock sweep/);
  // A copied run under a new run id, with every digest and the point recomputed, overlaps the run it copies.
  assert.throws(() => validateClockSweep(edit(w => {
    const p = w.points[0], copy = JSON.parse(JSON.stringify(p.records[0]));
    copy.raw.runId = '00000000-0000-4000-8000-000000000000'; copy.rawDigest = digest(copy.raw);
    p.records[1] = reseal(copy); w.points[0] = pointSummary(3, p.records, w.k, p.twin);
  })), /overlap in time/, 'a copied run');
  // The build label is the build that ran.
  const relabel = f => { const r = JSON.parse(JSON.stringify(sweep.points[0].records[0])); f(r.raw.target); r.rawDigest = digest(r.raw); return reseal(r); };
  assert.throws(() => validateClockRecord(relabel(t => { t.build = 'recheck'; })), /build label/, 'a start-only run labelled recheck');
  assert.throws(() => validateClockRecord(relabel(t => { t.deskOptions = { recheckEachStep: true }; })), /build label/, 'a harness setting recorded as a desk option');
  // Every record names its target, its run and its sweep, and states its limitations.
  const raw = sweep.points[0].records[0].raw;
  assert.match(raw.runId, /^[0-9a-f-]{36}$/);
  assert.equal(raw.sweepId, sweep.sweepId);
  assert.deepEqual([raw.target.desk, raw.target.build, /^[0-9a-f]{64}$/.test(raw.target.deskSha256), /^[0-9a-f]{64}$/.test(raw.target.scriptHash)], ['integrations/kill-switch/agent-desk.mjs', 'start-only', true, true]);
  assert.deepEqual(sweep.points[0].records[0].limitations, [...CLOCK_LIMITATIONS]);
  assert.ok(CLOCK_LIMITATIONS[0].startsWith('Synthetic') && CLOCK_LIMITATIONS[1].includes('settleMs'));
});

test('the twin counts only work that landed after the change; work before it reads control-failed', () => {
  const twin = raw => deriveClock({ ...raw, twin: true });
  assert.deepEqual([twin(syntheticRaw({ after: -800_000, before: -500_000 })).reading, twin(syntheticRaw({ after: -800_000, before: -500_000 })).reason], ['control-failed', 'no-work-landed-after-the-change'], 'halted on anyone\'s change');
  assert.equal(twin(syntheticRaw({ after: 100_000_000, before: 104_000_000 })).reading, 'control');
});

test('the test-only desk options cannot change the build the record is labelled with', async () => {
  await assert.rejects(runRevocationClock({ desk: { recheckEachStep: true } }), /desk takes refuseAllTools and commitAfterReplyMs only/);
});

test('every pause point has an allowed-use twin, and a build that refuses every tool gets no pass^k', async () => {
  const refusing = await runClockSweep({ k: 1, holdAts: [3], recheckEachStep: true, desk: { refuseAllTools: true } });
  assert.deepEqual(validateClockSweep(refusing).map(p => [p.successes, p.control, p.passHatK]), [[1, 'control-failed', null]]);
  const repaired = await runClockSweep({ k: 1, holdAts: [3], recheckEachStep: true });
  assert.deepEqual(validateClockSweep(repaired).map(p => [p.successes, p.control, p.passHatK]), [[1, 'control', 1]]);
});

test('stopped and within-budget need the turn ended and observation to the reply plus settleMs; a refund after the reply is caught at the default settle', async () => {
  // A turn that never ended, with one late effect: a finding, never within a budget.
  const open = deriveClock(syntheticRaw({ after: 100_000_000, before: 104_000_000, turn: { status: null, respondedAt: null } }), { budgetMs: 200 });
  assert.deepEqual([open.reading, open.verdict], ['kept-acting', 'inconclusive']);
  // The last read came before the reply plus settleMs: never stopped.
  const early = deriveClock(syntheticRaw({ after: -800_000, before: -100_000, lastReadLateBy: -200_000_000 }));
  assert.deepEqual([early.reading, early.reason], ['inconclusive', 'observation-ended-before-reply-plus-settle']);
  assert.equal(deriveClock(syntheticRaw({ after: -800_000, before: -100_000 })).reading, 'stopped');
  // A turn that answered with an error did not end its work: never stopped.
  assert.deepEqual((({ reading, reason }) => [reading, reason])(deriveClock(syntheticRaw({ after: -800_000, before: -100_000, turn: { status: 500, respondedAt: '4000000' } }))), ['inconclusive', 'turn-did-not-end']);
  // The desk replies that it stopped, then files the refund 600 ms later: the default settle (1000 ms) sees it.
  const late = await runRevocationClock({ holdAt: 3, recheckEachStep: true, desk: { commitAfterReplyMs: 600 } });
  assert.equal(late.derived.reading, 'kept-acting', JSON.stringify(late.derived));
  // Parameters are checked.
  await assert.rejects(runRevocationClock({ settleMs: -1 }), /settleMs/);
  await assert.rejects(runRevocationClock({ profile: { budgetMs: '200' } }), /budgetMs/);
});

test('gate mode keeps a finding; only a pass reads inconclusive; a budget at the top is within it; only a stop succeeds', () => {
  const kept = deriveClock(syntheticRaw({ after: 100_000_000, before: 104_000_000 }), { budgetMs: 200 });
  assert.deepEqual([kept.reading, kept.verdict], ['kept-acting', 'within-budget']);
  const g = gated(kept, 'gate');
  assert.deepEqual([g.reading, g.verdict, g.verdictReason], ['kept-acting', 'inconclusive', 'subject-writable-custody']);
  assert.equal(deriveClock(syntheticRaw({ after: 100_000_000, before: 104_000_000 }), { budgetMs: 104 }).verdict, 'within-budget', 'the top equal to the budget');
  assert.equal(runSucceeded(kept), false);
  assert.equal(pointSummary(3, [{ derived: kept }], 1, { derived: { reading: 'control' } }).successes, 0);
});

test('the poller flags an overflow and a failed read, brackets rows first seen by read 2, and a missing bracket is an observer failure', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven clock poller '));
  try {
    const path = join(dir, 'a.db'), db = new DatabaseSync(path);
    db.exec('CREATE TABLE audit_log (id INTEGER PRIMARY KEY, actor TEXT, action TEXT, resource TEXT);');
    const poller = createArrivalPoller({ path, table: 'audit_log', columns: ['actor', 'action', 'resource'], pollMs: 50, limits: { polls: 1000, rows: 1 } });
    await poller.start();
    db.exec("INSERT INTO audit_log (actor, action, resource) VALUES ('agent-sam', 'refund.requested', 'r/1'), ('agent-sam', 'refund.requested', 'r/2');");
    poller.readNow();
    const out = await poller.stop();
    assert.equal(out.overflow, true, 'an overflow is flagged');
    // A read that fails is reported, never swallowed.
    const broken = createArrivalPoller({ path, table: 'no_such_table', pollMs: 50 });
    await broken.start();
    assert.ok((await broken.stop()).error, 'a failed read is reported');
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
  // A row first seen by read 2 is bracketed by read 1's start and read 2's end.
  const [b] = arrivalBrackets({ polls: [{ seq: 1, start: '10', end: '20', maxId: 0 }, { seq: 2, start: '30', end: '40', maxId: 1 }], rows: [{ id: 1, poll: 2 }] });
  assert.deepEqual([b.after, b.before], [10n, 40n]);
  // A row whose bracketing read is missing is an observer failure, not a thrown error.
  const raw = syntheticRaw({ after: 100_000_000, before: 104_000_000 });
  raw.arrivals.polls = raw.arrivals.polls.filter(p => p.seq !== 2);
  assert.deepEqual([deriveClock(raw).reading, deriveClock(raw).reason], ['observer-failure', 'bracket-missing']);
});

test('a real record\'s custody is the desk audit table\'s, recomputed; the raw digest and the schema are checked', async () => {
  const record = await runRevocationClock({ holdAt: 3, commitDelayMs: 20 });
  assert.equal(record.raw.custody, 'subject-writable');
  const claimed = JSON.parse(JSON.stringify(record)); claimed.raw.custody = 'independent'; claimed.rawDigest = digest(claimed.raw);
  assert.throws(() => validateClockRecord(reseal(claimed)), /custody/, 'a claimed custody is recomputed');
  const raw = JSON.parse(JSON.stringify(record)); raw.raw.holdAt = 2;
  assert.throws(() => validateClockRecord(reseal(raw)), /raw stamps do not match/, 'the raw stamps are checked');
  assert.throws(() => validateClockRecord(reseal({ ...record, schema: 'scopehaven-revocation-clock/0' })), /Not a revocation-clock record/, 'the schema is checked');
});
