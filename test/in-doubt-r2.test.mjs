// In-doubt resolution by read-back, through the core, the clause rules, the run-end stage and the shared validator. Checked: inert
// equals the frozen evaluator (no read-back declared: every decision and sealed byte equals a frozen earlier evaluator's, whatever an
// observer returns, the request feed included; read-back declared but every record absent, failed or early: every verdict equals the
// frozen evaluator's); missing or weaker evidence never yields a pass, and never moves an attempt between confirmed and refuted; no
// in-doubt pass; a re-decided verdict is never more lenient than the frozen evaluator reading each derived fate as a proven reply; over
// a modelled system of record that honors its declarations, every decided group's count is the truth; read-back combines strictly with
// the transport record and the request feed; the connector's side equals the validator's recompute; tampering with a sealed read is refused on
// recompute and across rows; a lifecycle change check takes no late record; the run's resolver cap covers the reads.
// Owned synthetic data only. No socket is opened: observers, clocks and transports are injected (test/in-doubt-r2-e2e.test.mjs runs loopback).
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { admitInDoubt, fateOf, inDoubtAttempt, bindResolutions, lateEntriesFor, attemptBasis, sealedRecordsOf, boundRecords } from '../src/in-doubt.mjs';
import { admitScoped, markUnfollowed, makeEffect } from '../src/effect-events.mjs';
import { decideEffects, effectTrace, recomputeEffectTrace, redecideResolved, effectAssertionRows, backendObserved } from '../src/http-effects.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { readBackReserveMs } from '../src/read-back-rules.mjs';
import { REQUEST_FEED_READ_MS } from '../src/request-feed-rules.mjs';
import * as C from './fixtures/in-doubt-r2-cases.mjs';
import * as C1 from './fixtures/in-doubt-r1-cases.mjs';
import * as C2 from './fixtures/in-doubt-redecide-cases.mjs';

const frozenOf = name => import(fileURLToPath(new URL(`./fixtures/in-doubt-main-cfb545c/${name}`, import.meta.url)));
const main = { effects: await frozenOf('http-effects.mjs'), events: await frozenOf('effect-events.mjs'), inDoubt: await frozenOf('in-doubt.mjs'), idem: await frozenOf('idempotency.mjs') };
const RUNS = 2500;
const json = value => JSON.parse(JSON.stringify(value));
const isPass = d => d.verdict === 'pass';
const view = ds => ds.map(d => [d.verdict, d.matched, d.authoritative]);

// The connector's side for one read-back case: decided at seal time, then the run-end stage with the recorder's records. A fresh window each call.
function connectorSide(c, records, opts = {}) {
  const b = C.buildCase(c, opts), decide = { role: c.role, claims: [], readings: [] };
  const before = decideEffects(c.effects, [b.window], decide);
  const [again] = redecideResolved([{ effects: c.effects, claims: [], readings: [], role: c.role, windows: [b.window] }], typeof records === 'function' ? records(b) : records);
  const decisions = again ?? before;
  return { ...b, before, decisions, changed: Boolean(again), trace: effectTrace(decisions, [b.window], C.META), fates: b.events.map(e => (inDoubtAttempt(e) ? fateOf(e) : null)) };
}
const validatorSide = (c, trace) => recomputeEffectTrace(json(trace), undefined, [C.recordOf(c.variant)], { role: c.role });

test('1. inert equals the frozen evaluator: with no read-back declared, every decision and sealed byte equals the frozen evaluator\'s, at seal time and after the stage, the request feed included, whatever an observer returns', t => {
  const BOTH = { scoped: [admitScoped, main.events.admitScoped], inDoubt: [admitInDoubt, main.inDoubt.admitInDoubt] };
  const r2read = C.honest({ added: [{ id: 'n1', author: 'app', state: 'posted', text: 'hello' }] });
  const n = { idr2: 0, r1: 0, r2: 0, decisions: 0, recomputed: 0 };
  // The re-decide stage's seeded cases (keyed groups, unfollowed, partial, scoped and host-suspend-short windows), with read-back reads added for every send.
  for (let i = 0, g = C2.rng(4242); i < RUNS; i++) {
    const c = C2.randomCase(g, { later: C2.pick(g, ['r1', 'rx']) }), w = C2.buildWindow(c, { mark: BOTH }), windows = [w], opts = { role: c.role, claims: c.claims, readings: c.readings };
    const supplied = [...c.supplied, ...c.events.map(s => ({ observer: C2.INST, seq: s.seq, records: [{ resolver: 'r2', read: r2read }] }))];
    let live = decideEffects(c.effects, windows, opts), was = main.effects.decideEffects(c.effects, windows, opts);
    assert.deepEqual(live, was, 'at seal time');
    if (c.kind === 'unfollowed') { markUnfollowed(w); main.events.markUnfollowed(w); live = decideEffects(c.effects, windows, opts); was = main.effects.decideEffects(c.effects, windows, opts); assert.deepEqual(live, was); }
    assert.deepEqual(redecideResolved([{ effects: c.effects, claims: c.claims, readings: c.readings, role: c.role, windows }], supplied), [null], 'r2 applies to nothing without read-back');
    assert.deepEqual(decideEffects(c.effects, windows, opts), was, 'after the stage');
    assert.equal(digest(effectTrace(live, windows, C2.META).data), digest(main.effects.effectTrace(was, windows, C2.META).data), 'the sealed trace');
    if (!w.scoped) { const sealed = json(effectTrace(live, windows, C2.META)); assert.deepEqual(recomputeEffectTrace(sealed, undefined, [C2.recordOf(c)], { role: c.role }).rows, main.effects.recomputeEffectTrace(sealed, undefined, [C2.recordOf(c)], { role: c.role }).rows); n.recomputed++; }
    n.idr2++; n.decisions += live.length;
  }
  // The request feed's cases (the frozen evaluator has the request feed): the stage with its records and read-back reads added gives the
  // frozen evaluator's decisions and sealed bytes.
  for (let i = 0, g = C1.rng(4343); i < RUNS; i++) {
    const c = C1.randomCase(g), opts = { role: c.role, claims: [], readings: [] };
    const live = C1.buildCase(c), was = C1.buildCase(c, { admit: [main.inDoubt.admitInDoubt] });
    const withR2 = [...live.records, ...live.events.map(e => ({ observer: C1.INST, seq: e.seq, records: [{ resolver: 'r2', read: r2read }] }))];
    const [a] = redecideResolved([{ effects: c.effects, claims: [], readings: [], role: c.role, windows: [live.window] }], withR2);
    const [b] = main.effects.redecideResolved([{ effects: c.effects, claims: [], readings: [], role: c.role, windows: [was.window] }], was.records);
    assert.deepEqual(a, b);
    const da = a ?? decideEffects(c.effects, [live.window], opts), db = b ?? main.effects.decideEffects(c.effects, [was.window], opts);
    const sealed = json(effectTrace(da, [live.window], C1.META));
    assert.equal(digest(sealed.data), digest(main.effects.effectTrace(db, [was.window], C1.META).data));
    const record = C1.recordFor({ signing: c.signing });
    assert.deepEqual(recomputeEffectTrace(sealed, undefined, [record], { role: c.role }).rows, main.effects.recomputeEffectTrace(json(sealed), undefined, [record], { role: c.role }).rows);
    n.r1++; n.decisions += da.length; n.recomputed++;
  }
  // Read-back's own cases with none declared: the recorder writes no read-back record and its scope none, so it is the frozen evaluator's window exactly.
  for (let i = 0, g = C.rng(4444); i < RUNS; i++) {
    const c = C.randomCase(g), b = C.buildCase(c, { readBack: false, admit: [main.inDoubt.admitInDoubt] }), opts = { role: c.role, claims: [], readings: [] };
    const live = decideEffects(c.effects, [b.window], opts), was = main.effects.decideEffects(c.effects, [b.window], opts);
    assert.deepEqual(live, was);
    assert.deepEqual(redecideResolved([{ effects: c.effects, claims: [], readings: [], role: c.role, windows: [b.window] }], C.buildCase(c).records.map(x => ({ ...x }))), [null]);
    const sealed = json(effectTrace(live, [b.window], C.META));
    assert.equal(digest(sealed.data), digest(main.effects.effectTrace(was, [b.window], C.META).data));
    assert.deepEqual(recomputeEffectTrace(sealed, undefined, [C.RECORDS.plain], { role: c.role }).rows, main.effects.recomputeEffectTrace(sealed, undefined, [C.RECORDS.plain], { role: c.role }).rows);
    n.r2++; n.decisions += live.length; n.recomputed++;
  }
  t.diagnostic(`inert: ${JSON.stringify(n)}`);
  assert.ok(n.decisions > 25000 && n.recomputed > 4000, JSON.stringify(n));
});

test('2. with read-back declared but every record absent, failed, early or blind, every verdict equals the frozen evaluator\'s', t => {
  let compared = 0;
  for (let i = 0, g = C.rng(5151); i < RUNS; i++) {
    const c = C.randomCase(g), opts = { role: c.role, claims: [], readings: [] };
    const plain = C.buildCase(c, { readBack: false, admit: [main.inDoubt.admitInDoubt] }), was = main.effects.decideEffects(c.effects, [plain.window], opts);
    const reads = [() => [], b => b.records.map(x => ({ ...x, records: [{ resolver: 'r2', status: 'failed', reason: 'read-not-run' }] })),
      b => b.records.map(x => ({ ...x, records: [{ resolver: 'r2', read: { ...x.records[0].read, early: true } }] })),
      b => b.records.map(x => ({ ...x, records: [{ resolver: 'r2', read: { ...x.records[0].read, identity: null } }] }))];
    for (const records of reads) {
      const side = connectorSide(c, records);
      assert.deepEqual(view(side.decisions), view(was));
      compared += side.decisions.length;
    }
  }
  t.diagnostic(`verdicts compared with the frozen evaluator: ${compared}`);
  assert.ok(compared > 20000);
});

// The degradations: each replaces a record with its failed form, drops it, or weakens one fact of its read (a guarantee unmet, a bound short,
// a flag false, a count up, an explanation gone). None adds evidence: an item never appears, an author is never named.
const zeroed = x => ({ ...x, complete: false, ...Object.fromEntries(['total', 'missingPre', 'newIds', 'newInM', 'mInRead', 'credItems', 'credNew', 'credApplied', 'credNotApplied', 'credOther', 'credUnmatched', 'credChanged', 'anonNew', 'lateNew'].map(k => [k, 0])) });
const DEGRADE = [
  () => null, () => ({ resolver: 'r2', status: 'failed', reason: 'read-not-run' }),
  r => ({ ...r, read: { ...r.read, early: true } }), r => ({ ...r, read: { ...r.read, intervening: r.read.intervening + 1 } }), r => ({ ...r, read: { ...r.read, credOthers: r.read.credOthers + 1 } }),
  r => ({ ...r, read: { ...r.read, identity: null } }), r => ({ ...r, read: { ...r.read, groupSends: r.read.groupSends + 1 } }), r => ({ ...r, read: { ...r.read, laterRemovals: 0, laterCred: 0, laterTouching: 0 } }),
  r => ({ ...r, read: { ...r.read, control: null } }), r => ({ ...r, read: { ...r.read, s1: { ...r.read.s1, complete: false }, s2: { ...r.read.s2, complete: false } } }),
  r => ({ ...r, read: { ...r.read, s1: { ...r.read.s1, atMono: Math.max(0, r.read.s1.atMono - 400) } } }), r => ({ ...r, read: { ...r.read, s2: { ...r.read.s2, atWall: r.read.s2.atWall === null ? null : r.read.s2.atWall + 5000 } } }),
  ...['pre', 's1', 's2', 's3'].map(k => r => ({ ...r, read: { ...r.read, [k]: zeroed({ ...r.read[k], outcome: k === 'pre' ? 'abandoned' : 'status' }) } })),
];
const degradeAll = (g, list) => list.map(x => { if (g() < 0.4) return x; const r = C.pick(g, DEGRADE)(x.records[0]); return r === null ? null : { ...x, records: [r] }; }).filter(Boolean);

test('3. property: degrading or removing any record never turns a non-pass into a pass, and never moves an attempt between confirmed and refuted', t => {
  const n = { clauses: 0, fullOnly: 0, confirmed: 0, refuted: 0, undecided: 0, attempts: 0 };
  for (let i = 0, g = C.rng(777); i < RUNS * 2; i++) {
    const c = C.randomCase(g), full = connectorSide(c, b => b.records), less = connectorSide(c, b => degradeAll(g, b.records)), none = connectorSide(c, () => []);
    full.fates.forEach((f, k) => {
      if (f === null) return;
      n.attempts++; if (f === 'applied' && attemptBasis(full.events[k]).by === 'r2') n.confirmed++; if (f === 'refuted' && attemptBasis(full.events[k]).by === 'r2') n.refuted++;
      assert.ok(less.fates[k] === f || less.fates[k] === 'in-doubt', `an attempt moved ${f} -> ${less.fates[k]}`);
      if (less.fates[k] !== f) n.undecided++;
    });
    full.decisions.forEach((d, k) => {
      if (!C.opted(c.effects[k])) { assert.equal(less.decisions[k].verdict, d.verdict); assert.equal(none.decisions[k].verdict, d.verdict); return; }
      if (isPass(less.decisions[k])) assert.equal(d.verdict, 'pass', `a degraded pass needs a full pass: ${JSON.stringify(c)}`);
      if (isPass(none.decisions[k])) assert.equal(d.verdict, 'pass');
      if (isPass(d) && !isPass(less.decisions[k])) n.fullOnly++;
      n.clauses++;
    });
  }
  t.diagnostic(`degradation: ${JSON.stringify(n)}`);
  assert.ok(n.clauses > 8000 && n.fullOnly > 200 && n.confirmed > 500 && n.refuted > 500 && n.undecided > 500, JSON.stringify(n));
});

test('4. property: no in-doubt pass. An exists pass rests on a proven or confirmed match; a count or effect.only pass (no countBy) has nothing in doubt; nothing in doubt is ever backend observed', t => {
  let passes = 0;
  for (let i = 0, g = C.rng(9090); i < RUNS; i++) {
    const c = C.randomCase(g), side = connectorSide(c, b => b.records);
    side.decisions.forEach((d, k) => {
      const clause = c.effects[k];
      if (!C.opted(clause) || !d.resolution) return;
      if (d.authoritative) assert.equal(d.resolution.inDoubt, 0, 'backend observed with an attempt in doubt');
      if (!isPass(d)) return;
      passes++;
      if (clause.kind === 'effect.exists') assert.ok(d.resolution.applied >= 1);
      else if (clause.countBy === undefined && (clause.kind === 'effect.count' || clause.kind === 'effect.only')) assert.equal(d.resolution.inDoubt, 0, JSON.stringify({ c, d }));
    });
    assert.ok(!backendObserved(side.decisions) || side.decisions.every(d => !d.resolution || d.resolution.inDoubt === 0));
  }
  t.diagnostic(`opted-in passes checked: ${passes}`);
  assert.ok(passes > 1000);
});

test('5. property: every re-decided pass and fail is one the frozen evaluator gives reading each derived fate as a proven reply; over a backend that honors its declarations every decided group count is the truth', t => {
  let compared = 0, passes = 0, fails = 0, groups = 0, faulted = 0, keyedTruth = 0;
  for (let i = 0, g = C.rng(4711); i < RUNS; i++) {
    const c = C.randomCase(g), side = connectorSide(c, b => b.records);
    // Truth: the members of G every resolver decided carry read-back's count of the applied ones, when the backend kept its declared guarantees.
    const D = side.events.filter((e, k) => c.sends[k].kind === 'member' && inDoubtAttempt(e) && e.upstream.transport?.connected);
    if (D.length && D.every(e => attemptBasis(e).by === 'r2')) {
      if (side.faulted) faulted++;
      else { assert.equal(D.filter(e => fateOf(e) === 'applied').length, D.filter(e => side.truth.get(e)).length, `a decided count is not the truth: ${JSON.stringify(c)}`); groups++; }
    }
    if (!side.changed) continue;
    // Keyed verdicts against the truth: the model's backend dedupes no key (each applied member wrote its own note), so a
    // keyed clause the stage moved to a pass must count exactly the truly applied sends it selects.
    side.decisions.forEach((d, k) => {
      const clause = c.effects[k];
      if (side.faulted || clause?.countBy === undefined || clause.kind !== 'effect.count' || d.verdict !== 'pass' || side.before[k].verdict === 'pass') return;
      assert.equal(side.events.filter(e => e.name === C.CRM && side.truth.get(e)).length, clause.expected, `a keyed pass the truth does not give: ${JSON.stringify(c)}`);
      keyedTruth++;
    });
    // Oracle: a confirmation reads a proven 201 (its note minted), a refutation a proven declared 409, in doubt an unproven unknown with no
    // transport record (so the frozen evaluator's r0 adds nothing).
    const upOf = e => { const f = side.fates[side.events.findIndex(x => x.seq === e.seq)], { transport: _t, readBack: _r, ...up } = e.upstream;
      return f === 'applied' ? { outcome: 'applied', status: 201, proven: true, minted: [C.mintedOf(`o${e.seq}`)], target: up.target } : f === 'refuted' ? { outcome: 'rejected', status: 409, proven: true, target: up.target }
        : f === 'in-doubt' ? { outcome: 'unknown', status: null, proven: false, target: up.target } : up; };
    const oracle = C.buildCase(c, { readBack: false, admit: [main.inDoubt.admitInDoubt], upstreamOf: upOf });
    const want = main.effects.decideEffects(c.effects, [oracle.window], { role: c.role, claims: [], readings: [] });
    side.decisions.forEach((d, k) => {
      if (!d.resolution?.redecided) return;
      compared++;
      if (d.verdict === 'pass') { assert.equal(want[k].verdict, 'pass', `a pass the derived fates do not give: ${JSON.stringify(c)}`); passes++; }
      if (d.verdict === 'fail') { assert.equal(want[k].verdict, 'fail', `a fail the derived fates do not give: ${JSON.stringify(c)}`); fails++; }
    });
  }
  t.diagnostic(`derived-fate oracle: compared ${compared}, passes ${passes}, fails ${fails}; truth: ${groups} decided groups equal the truth, ${faulted} decided on a broken declaration (not checked); ${keyedTruth} keyed passes the stage made, each the true count`);
  // Coverage floors (the property is the assertions above): the read-back gates leave fewer decided groups than without them (580 -> about 490).
  assert.ok(passes > 300 && fails > 300 && groups > 400 && keyedTruth > 30, `${passes} ${fails} ${groups} ${keyedTruth}`);
});

test('6. strict combination: read-back beside the transport record and the request feed. A conflict, or any failed applicable resolver, leaves the attempt in doubt', () => {
  // One send on a host that declares both a request feed and read-back (the scope carries both; the feed's route is the exact declared path).
  const feed = { ...C1.FEED, hosts: [C.CRM], routes: [{ write: C.NOTES_T1, types: ['note.created'], applied: ['posted'], notApplied: ['declined'], settleMs: C.SETTLE, source: 'synthetic' }] };
  const both = () => {
    const base = C.send({ seq: 1, end: 1050 });
    const e = makeEffect({ source: base.source, observer: base.observer, seq: 1, observedAt: base.observedAt, operation: 'send', name: C.CRM, resource: C.NOTES_T1, outcome: 'committed', content: { target: 'x', body: 'hello', sendAt: 'absent' },
      captured: base.captured, idempotency: base.idempotency, upstream: { ...base.upstream, transport: { ...base.upstream.transport, arrivedMono: 1000, arrivedWall: C.OFFSET + 1000 } } });
    const w = admitInDoubt({ source: 'http-egress', instanceId: C.INST, scope: { ...C.scopeOf('full'), requestFeed: feed }, coverage: 'complete', reason: null, events: [e] });
    return { e, w };
  };
  const r1 = entries => ({ resolver: 'r1', read: C1.read({ key: C.hex('key K1'), headMono: 5000, headWall: C.OFFSET + 5000, watermark: C.OFFSET + 4900, entries }) });
  const r2 = read => ({ resolver: 'r2', read });
  const RA = C.honest({ added: [{ id: 'n1', author: 'app', state: 'posted', text: 'hello' }] }), RB = C.honest();
  const case_ = records => { const { e, w } = both(); bindResolutions([w], lateEntriesFor([w], [{ observer: C.INST, seq: 1, records }])); const b = attemptBasis(e); return [fateOf(e), b.resolvers, b.by === 'none' ? b.reason : b.by, boundRecords(e).map(r => r.result ?? r.reason)]; };
  const applied = [C1.entry({ at: C.OFFSET + 1020, state: 'applied' })];
  assert.deepEqual(case_([r1(applied), r2(RA)]), ['applied', ['r0', 'r1', 'r2'], 'r1', ['confirms', 'confirms']], 'both confirm');
  assert.deepEqual(case_([r1(applied), r2(RB)]), ['in-doubt', ['r0', 'r1', 'r2'], 'resolvers-disagree', ['confirms', 'refutes']], 'a conflict');
  assert.deepEqual(case_([r1(applied)]), ['in-doubt', ['r0', 'r1', 'r2'], 'record-missing', ['confirms']], 'r2 applicable but its record missing: strict');
  assert.deepEqual(case_([r2(RA)]), ['in-doubt', ['r0', 'r1', 'r2'], 'record-missing', ['confirms']], 'r1 missing: strict');
  assert.deepEqual(case_([r1([]), r2(RB)]), ['refuted', ['r0', 'r1', 'r2'], 'r1', ['refutes', 'refutes']], 'both refute (the feed under its watermark)');
  assert.deepEqual(case_([{ resolver: 'r1', read: C1.read({ key: C.hex('key K1'), watermark: null }) }, r2({ ...RA, credOthers: 1 })]), ['in-doubt', ['r0', 'r1', 'r2'], 'r0-connected', ['silent', 'silent']], 'both silent');
  assert.deepEqual(case_([r1(applied), r2({ ...RA, credOthers: 1 })]), ['applied', ['r0', 'r1', 'r2'], 'r1', ['confirms', 'silent']], 'read-back silent: the feed decides');
  // A send that never connected has the transport record alone (no later resolver applies to it), refuted as before.
  const refused = C.send({ seq: 2, outcome: 'refused', end: 1050 }), w = C.windowOf([refused]);
  assert.deepEqual([fateOf(refused), attemptBasis(refused).resolvers, attemptBasis(refused).by], ['refuted', ['r0'], 'r0'], 'r0 alone applies, and refutes');
  assert.throws(() => bindResolutions([w], [{ observer: C.INST, seq: 2, records: [r2(RB)] }]), /resolution-record/, 'no read-back record binds onto a never-connected send');
});

test('7. parity: the validator recomputes the connector\'s verdicts, rows, records and backend reading from the sealed reads alone', t => {
  const n = { runs: 0, changed: 0, clauses: 0 };
  for (let i = 0, g = C.rng(20261017); i < RUNS * 2; i++) {
    const c = C.randomCase(g), side = connectorSide(c, b => (g() < 0.7 ? b.records : degradeAll(g, b.records)));
    const again = validatorSide(c, side.trace);
    assert.deepEqual(again.decisions.map(d => d.verdict), side.decisions.map(d => d.verdict));
    assert.deepEqual(again.rows, effectAssertionRows(side.decisions));
    assert.equal(again.backendObserved, backendObserved(side.decisions));
    assert.equal(Object.hasOwn(side.trace.data, 'resolutions'), side.changed);
    n.runs++; n.clauses += side.decisions.length; if (side.changed) n.changed++;
  }
  t.diagnostic(`parity: ${JSON.stringify(n)}`);
  assert.ok(n.changed > 1500, JSON.stringify(n));
});

test('8. tamper: an edited read (counts, flags, times, the pre-image) or group digest that changes any derived fate or basis is refused on recompute; a bare result is refused', t => {
  const g = C.rng(31337);
  let refused = 0, inert = 0, groupRefused = 0, groupInert = 0;
  const EDITS = [
    ['credApplied', r => { r.s1.credApplied += 1; r.s1.credNew += 1; r.s1.newIds += 1; r.s1.total += 1; r.s2.credApplied += 1; r.s2.credNew += 1; r.s2.newIds += 1; r.s2.total += 1; }],
    ['newIds', r => { r.s1.newIds += 1; r.s1.total += 1; }], ['mInRead', r => { r.s1.mInRead = Math.max(0, r.s1.mInRead - 1); }], ['credItems', r => { r.s1.credItems = 0; r.s2.credItems = 0; r.control = null; }],
    ['complete', r => { r.s2.complete = !r.s2.complete; }], ['early', r => { r.early = !r.early; }], ['intervening', r => { r.intervening = r.intervening ? 0 : 1; }], ['credOthers', r => { r.credOthers = r.credOthers ? 0 : 1; }],
    ['s1 time', r => { r.s1.atMono = Math.max(0, r.s1.atMono - 300); }], ['s2 wall', r => { if (r.s2.atWall !== null) r.s2.atWall += 5000; }], ['identity', r => { r.identity = r.identity === null ? 'app' : null; }],
    ['pre-image', r => { r.pre.outcome = r.pre.outcome === 'ok' ? 'abandoned' : 'ok'; }], ['missingPre', r => { r.s3.missingPre += 1; }], ['lateNew', r => { r.s3.lateNew += 1; r.s3.newIds += 1; r.s3.total += 1; }],
  ];
  for (let i = 0; i < 1500; i++) {
    const c = C.randomCase(g), side = connectorSide(c, b => b.records);
    if (!side.changed) continue;
    const listed = new Set(side.decisions.flatMap(d => d.resolution?.attempts ?? []).map(a => `${a.seq} ${a.fate} ${a.by} ${a.reason ?? ''}`));
    for (const [why, edit] of EDITS) {
      const t2 = json(side.trace);
      for (const x of t2.data.resolutions) for (const r of x.records) if (r.read) edit(r.read);
      const fresh = C.buildCase(c), entries = lateEntriesFor([fresh.window], t2.data.resolutions);
      let bound = true;
      try { bindResolutions([fresh.window], entries); } catch { bound = false; }
      const now = new Set(fresh.events.map(e => { const b = attemptBasis(e); return `${e.seq} ${fateOf(e)} ${b.by} ${b.reason ?? ''}`; }));
      const moved = !bound || [...listed].some(a => !now.has(a));
      let threw = false;
      try { validatorSide(c, t2); } catch (error) { threw = true; assert.match(error.message, /effect-(trace|verdict)/); }
      if (moved) { assert.ok(threw, `${why}: a changed fate was accepted`); refused++; } else inert++;
    }
    const bare = json(side.trace); bare.data.resolutions[0].records = [{ resolver: 'r2', status: 'succeeded', result: 'confirms' }];
    assert.throws(() => validatorSide(c, bare), /effect-(trace|verdict)/); refused++;
    const moved = json(side.trace); moved.data.resolutions[0].seq = 999;
    assert.throws(() => validatorSide(c, moved), /effect-trace/); refused++;
    // A group digest edited on one sealed member: the read names the group it was read for, so it no longer binds (or the member leaves G).
    const grouped = json(side.trace), e = grouped.data.windows[0].events.find(x => x.seq === grouped.data.resolutions[0].seq);
    if (e?.upstream?.readBack && side.decisions.some(d => (d.resolution?.attempts ?? []).some(a => a.seq === e.seq))) {
      e.upstream.readBack.group = 'f'.repeat(64);
      try { validatorSide(c, grouped); groupInert++; } catch (error) { assert.match(error.message, /effect-(trace|verdict)/); groupRefused++; }
    }
  }
  t.diagnostic(`tamper: ${refused} refused, ${inert} edits that change no listed fate; group digest edits: ${groupRefused} refused, ${groupInert} recomputed identically`);
  assert.ok(refused > 1500 && groupRefused > 200 && groupRefused > 5 * Math.max(1, groupInert), `${refused} refused, group ${groupRefused}/${groupInert}`);
});

// --- The connector and the shared validator, end to end (injected recorder; no socket) ------------------------------------------
const suiteOf = p => createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
const virtualClock = () => { let now = 0; return { now: () => now, sleep: async ms => { now += ms; } }; };
async function runOf(p, factory, options = {}) {
  const run = await runHttpAssessment(p, { env: {}, transport: C.transport, observerFactory: factory, clock: virtualClock(), ...options });
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  validateHttpRunEvidence(json(run), { expectedSuite: suiteOf(p) });
  return run;
}
const rowOf = (run, id = 'TASK1') => run.results.find(r => r.id === id);
const verdictsOf = row => row.trace[1].data.effects.map(e => e.verdict);
const reseal = row => { row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); };
const NOTE = id => ({ id, author: 'app', state: 'posted', text: 'hello' });

test('9. end to end: a confirmation and a refutation are decided again before settlement, sealed as reads, and recomputed by the shared validator with the suite', async () => {
  const T2 = { exists: { ...C.EXISTS, select: C.sel(C.NOTES_T2, 'resolved') }, zero: { ...C.count(0), select: C.sel(C.NOTES_T2, 'resolved') } };
  const p = C.profileOf([[C.EXISTS, C.count(1)], [T2.zero, T2.exists]]);
  // TASK1 on T-1 (applied: its note is listed); TASK2 on T-2 (not applied), each its own group.
  const t2send = () => C.send({ seq: 2, object: 'T2', resource: C.NOTES_T2, end: 3100, key: 'K2' });
  const batches = [() => [C.send({ seq: 1, end: 1100 })], () => [t2send()]];
  const reads = sent => sent.filter(e => e.upstream.outcome === 'unknown').map(e => ({ seq: e.seq, records: [{ resolver: 'r2', read: e.seq === 1 ? C.honest({ added: [NOTE('n1')] })
    : C.honest({ lastEnd: 3100, group: e.upstream.readBack.group }) }] }));
  const without = await runOf(p, C.r2RecorderFactory(batches));
  assert.deepEqual([verdictsOf(rowOf(without)), verdictsOf(rowOf(without, 'TASK2'))], [['missing', 'missing'], ['missing', 'missing']], 'no read: in doubt, as without read-back');
  const run = await runOf(p, C.r2RecorderFactory(batches, { reads }));
  const t1 = rowOf(run), t2 = rowOf(run, 'TASK2');
  assert.deepEqual([verdictsOf(t1), t1.status, t1.backendEvidence], [['pass', 'pass'], 'pass', 'observed'], 'confirmed: exists, exactly one');
  // Refuted: the agent-write exists fails; exactly zero is decided as zero, then held by the positive-match pairing.
  assert.deepEqual([verdictsOf(t2), t2.status, t2.trace[1].data.effects[1].resolution.operation], [['inconclusive', 'fail'], 'fail', 'refuted']);
  assert.deepEqual(t1.trace[1].data.resolutions.map(x => x.records.map(r => Object.keys(r))), [[['resolver', 'read']]], 'sealed as the read, never a result');
  assert.deepEqual([t1.trace[1].data.effects[0].resolution.attempts[0].by, t2.trace[1].data.effects[1].resolution.attempts[0].by], ['r2', 'r2']);
  assert.equal(run.observers[0].collector.label, 'egress-recorder/13');
  assert.ok(run.limitations.some(l => /Read-back/.test(l)), 'the run says what read-back rests on');
  // Tamper on the saved run: an unsealed edit fails its evidence digest; a resealed read whose derivation no longer gives the stored verdicts,
  // or whose run-wide count is below what the sealed windows show, is refused; a relabelled or stripped record and another suite are refused.
  const unsealed = json(run); rowOf(unsealed).trace[1].data.resolutions[0].records[0].read.early = true;
  assert.throws(() => validateHttpRunEvidence(unsealed), error => error.code === 'invalid-run-evidence');
  const away = json(run), a1 = rowOf(away); a1.trace[1].data.resolutions[0].records[0].read.identity = null; reseal(a1);
  assert.throws(() => validateHttpRunEvidence(away), error => error.code === 'invalid-run-evidence', 'the derived result no longer matches the stored verdicts');
  const counted = json(run), c2 = rowOf(counted); c2.trace[1].data.resolutions[0].records[0].read.groupSends = 2; reseal(c2);
  assert.throws(() => validateHttpRunEvidence(counted), error => error.code === 'invalid-run-evidence');
  const relabelled = json(run); relabelled.observers[0].collector.label = 'egress-recorder/8';
  assert.throws(() => validateHttpRunEvidence(relabelled), error => error.code === 'invalid-run-evidence');
  const stripped = json(run); delete stripped.observers[0].readBack;
  assert.throws(() => validateHttpRunEvidence(stripped), error => error.code === 'invalid-run-evidence');
  assert.throws(() => validateHttpRunEvidence(json(run), { expectedSuite: suiteOf(C.profileOf([[C.EXISTS, C.count(1)], [T2.zero, T2.exists]], { variant: 'noControl' })) }), error => error.code === 'unexpected-suite-evidence');
});

test('10. end to end parity: seeded runs through the connector validate with their suite, and every clause no later stage tagged reads as the stage alone decided it', async t => {
  let runs = 0, changed = 0, compared = 0;
  // Every run carries a required allowed-use control (GUARD, an applied write to another backend) whose pass guards the task's effect.only
  // clauses, so those passes are compared too; the guard's own row is not.
  let guarded = 0;
  const g = C.rng(8181), cases = Array.from({ length: 200 }, (_, i) => { const c = C.randomCase(g), keep = g() < 0.7; return { c, keep, p: { ...C.profileOf([c.effects], { variant: c.variant, guard: true }), id: `r2-app-${i}`, applicationId: `r2-app-${i}` } }; });
  const registries = Array.from({ length: Math.ceil(cases.length / 20) }, (_, k) => createRegistry({ profiles: cases.slice(20 * k, 20 * k + 20).map(x => x.p), env: {} }));
  for (const [i, { c, keep, p }] of cases.entries()) {
    const records = C.buildCase(c).records, given = keep ? records : degradeAll(g, records);
    const run = await runHttpAssessment(p, { env: {}, transport: C.transport, observerFactory: C.r2RecorderFactory([C.guardBatch, () => C.buildCase(c).events], { reads: () => given, variant: c.variant }), clock: virtualClock() });
    const suite = registries[Math.floor(i / 20)].exportSuite(p.id);
    validateHttpRunEvidence(run, { expectedSuite: suite });
    validateHttpRunEvidence(json(run), { expectedSuite: suite });
    const row = rowOf(run), stage = connectorSide(c, () => given);
    assert.equal(rowOf(run, 'GUARD').trace[1].data.effects[0].verdict, 'pass', 'the guard passed');
    assert.ok(row.trace[1].data.effects.every(e => e.pairing !== 'allowed-use-not-declared'), 'the guard releases every effect.only pass');
    if (c.effects.every(x => x.kind === 'effect.only') && row.trace[1].data.effects.some(e => e.verdict === 'pass')) guarded++;
    row.trace[1].data.effects.forEach((e, k) => { if (!['settlement', 'attribution', 'pairing', 'appLog', 'later'].some(key => Object.hasOwn(e, key))) { assert.equal(e.verdict, stage.decisions[k].verdict, JSON.stringify(c)); compared++; } });
    if (Object.hasOwn(row.trace[1].data, 'resolutions')) changed++;
    runs++;
  }
  t.diagnostic(`end-to-end parity: ${runs} runs validated, ${changed} with sealed reads, ${compared} clauses equal to the stage alone; ${guarded} runs whose only clauses are effect.only passed beside the guard`);
  assert.ok(changed > 50 && compared > 300 && guarded > 0, `${changed} ${compared} ${guarded}`);
});

test('11. the run-end cap: the connector gives a read-back recorder its reserve (two settles and three reads), alone or beside a request feed, and nothing more without read-back', async () => {
  const seen = [];
  const spy = variant => configs => C.r2RecorderFactory([() => [C.send({ seq: 1 })]], { variant })(configs).map(o => ({ ...o, async resolutionRecords(mark, { capMs }) { seen.push(capMs); return []; } }));
  await runHttpAssessment(C.profileOf([[C.EXISTS]]), { env: {}, transport: C.transport, observerFactory: spy('full'), clock: virtualClock() });
  assert.deepEqual(seen, [Math.max(REQUEST_FEED_READ_MS, readBackReserveMs(C.profileOf([[C.EXISTS]]).observers))]);
  assert.equal(readBackReserveMs(C.profileOf([[C.EXISTS]]).observers), 2 * C.SETTLE + 3 * 1000);
  const big = structuredClone(C.profileOf([[C.EXISTS]])); big.observers[0].destinations[0].readBack.routes[0].settleMs = 4000; big.observers[0].destinations[0].readBack.routes[0].guarantees.settleMs = 4000;
  seen.length = 0;
  await runHttpAssessment(big, { env: {}, transport: C.transport, observerFactory: spy('full'), clock: virtualClock() });
  assert.deepEqual(seen, [2 * 4000 + 3 * 1000], 'a reserve above the feed\'s cap');
  seen.length = 0;
  await runHttpAssessment(C.profileOf([[C.EXISTS]], { readBack: false }), { env: {}, transport: C.transport, observerFactory: spy(null), clock: virtualClock() });
  assert.deepEqual(seen, [REQUEST_FEED_READ_MS], 'without read-back: the request-feed cap');
});
