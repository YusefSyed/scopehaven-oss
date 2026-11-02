// In-doubt resolution by the request feed, through the core, the clause rules, the run-end stage and the shared validator. Checked:
// inert equals the frozen evaluator (no feed declared: every decision and sealed byte equals a frozen earlier evaluator's; a feed
// declared but no record, or every record failed: every verdict equals the frozen evaluator's); missing or weaker evidence never yields
// a pass, and never moves an attempt between confirmed and refuted; no in-doubt pass; a re-decided verdict is never more lenient than
// the frozen evaluator reading each derived fate as a proven reply; the connector's side equals the validator's recompute; tampering
// with a sealed read is refused on recompute (and, across rows, by the run-level check); a lifecycle change check takes no late record;
// the timing plan reserves the read.
// Owned synthetic data only. No socket is opened: observers, clocks and transports are injected (test/in-doubt-r1-e2e.test.mjs runs loopback).
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { admitInDoubt, fateOf, inDoubtAttempt, bindResolutions, lateEntriesFor, attemptBasis, sealedRecordsOf, boundRecords } from '../src/in-doubt.mjs';
import { admitScoped, markUnfollowed } from '../src/effect-events.mjs';
import { decideEffects, effectTrace, recomputeEffectTrace, redecideResolved, effectAssertionRows, backendObserved, declaredObserverRecord } from '../src/http-effects.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { plannedTimingTerms } from '../src/http-timing.mjs';
import { identityControlPlan } from '../src/contracts.mjs';
import { REQUEST_FEED_READ_MS } from '../src/request-feed-rules.mjs';
import { validateEgressConfig } from '../src/egress-rules.mjs';
import { applySuspendShort } from '../src/suspend-clock.mjs';
import * as C from './fixtures/in-doubt-r1-cases.mjs';
import * as C2 from './fixtures/in-doubt-redecide-cases.mjs';

const frozenOf = name => import(fileURLToPath(new URL(`./fixtures/in-doubt-main-c8f8bd3/${name}`, import.meta.url)));
const main = { effects: await frozenOf('http-effects.mjs'), events: await frozenOf('effect-events.mjs'), inDoubt: await frozenOf('in-doubt.mjs'), idem: await frozenOf('idempotency.mjs') };
const RUNS = 3000;
const json = value => JSON.parse(JSON.stringify(value));
const isPass = d => d.verdict === 'pass';

// The connector's side for one request-feed case: decided at seal time, then the run-end stage with the recorder's records. A fresh window each call.
function connectorSide(c, records, { feed = C.FEED } = {}) {
  const b = C.buildCase(c, { feed }), opts = { role: c.role, claims: [], readings: [] };
  const before = decideEffects(c.effects, [b.window], opts);
  const [again] = redecideResolved([{ effects: c.effects, claims: [], readings: [], role: c.role, windows: [b.window] }], records(b));
  const decisions = again ?? before;
  return { ...b, before, decisions, changed: Boolean(again), trace: effectTrace(decisions, [b.window], C.META), fates: b.events.map(e => (inDoubtAttempt(e) ? fateOf(e) : null)) };
}
const validatorSide = (c, trace, record = C.recordFor({ signing: c.signing })) => recomputeEffectTrace(json(trace), undefined, [record], { role: c.role });

// ----------------------------------------------------------------------------------------------------------------------------------
test('1. inert equals the frozen evaluator: with no request feed declared, every decision and sealed byte equals the frozen evaluator\'s, at seal time and after the stage, whatever an observer returns', t => {
  const BOTH = { scoped: [admitScoped, main.events.admitScoped], inDoubt: [admitInDoubt, main.inDoubt.admitInDoubt] };
  const n = { idr2: 0, r1: 0, decisions: 0, recomputed: 0 };
  // The re-decide stage's seeded cases (keyed groups, unfollowed, partial, scoped and host-suspend-short windows), with request-feed reads added for every send.
  for (let i = 0, g = C2.rng(4242); i < RUNS; i++) {
    const c = C2.randomCase(g, { later: C2.pick(g, ['r1', 'rx']) }), w = C2.buildWindow(c, { mark: BOTH }), windows = [w], opts = { role: c.role, claims: c.claims, readings: c.readings };
    const supplied = [...c.supplied, ...c.events.map(s => ({ observer: C2.INST, seq: s.seq, records: [{ resolver: 'r1', read: C.read({ entries: [C.entry()] }) }] }))];
    let live = decideEffects(c.effects, windows, opts), was = main.effects.decideEffects(c.effects, windows, opts);
    assert.deepEqual(live, was, 'at seal time');
    if (c.kind === 'unfollowed') { markUnfollowed(w); main.events.markUnfollowed(w); live = decideEffects(c.effects, windows, opts); was = main.effects.decideEffects(c.effects, windows, opts); assert.deepEqual(live, was); }
    assert.deepEqual(redecideResolved([{ effects: c.effects, claims: c.claims, readings: c.readings, role: c.role, windows }], supplied), [null], 'r1 applies to nothing without a feed');
    assert.deepEqual(decideEffects(c.effects, windows, opts), was, 'after the stage');
    const sealed = effectTrace(live, windows, C2.META), sealedMain = main.effects.effectTrace(was, windows, C2.META);
    assert.equal(digest(sealed.data), digest(sealedMain.data), 'the sealed trace');
    if (!w.scoped) { assert.deepEqual(recomputeEffectTrace(json(sealed), undefined, [C2.recordOf(c)], { role: c.role }).rows, main.effects.recomputeEffectTrace(json(sealed), undefined, [C2.recordOf(c)], { role: c.role }).rows); n.recomputed++; }
    n.idr2++; n.decisions += live.length;
  }
  // The feed's own cases with none declared: the recorder writes no arrival and its scope no feed, so it is the frozen evaluator's window exactly.
  for (let i = 0, g = C.rng(4343); i < RUNS; i++) {
    const c = C.randomCase(g), b = C.buildCase(c, { feed: null, admit: [main.inDoubt.admitInDoubt] }), opts = { role: c.role, claims: [], readings: [] };
    const live = decideEffects(c.effects, [b.window], opts), was = main.effects.decideEffects(c.effects, [b.window], opts);
    assert.deepEqual(live, was);
    assert.deepEqual(redecideResolved([{ effects: c.effects, claims: [], readings: [], role: c.role, windows: [b.window] }], b.records), [null]);
    const sealed = effectTrace(live, [b.window], C.META);
    assert.equal(digest(sealed.data), digest(main.effects.effectTrace(was, [b.window], C.META).data));
    const plainRecord = C.recordFor({ feed: false, signing: c.signing });
    assert.deepEqual(recomputeEffectTrace(json(sealed), undefined, [plainRecord], { role: c.role }).rows, main.effects.recomputeEffectTrace(json(sealed), undefined, [plainRecord], { role: c.role }).rows);
    n.r1++; n.decisions += live.length; n.recomputed++;
  }
  t.diagnostic(`inert: ${JSON.stringify(n)}`);
  assert.ok(n.decisions > 25000 && n.recomputed > 4000, JSON.stringify(n));
});

test('2. with a feed declared but every record absent or failed (the feed unread, unclear or cut), every verdict equals the frozen evaluator\'s', t => {
  let compared = 0;
  for (let i = 0, g = C.rng(5151); i < RUNS; i++) {
    const c = C.randomCase(g), opts = { role: c.role, claims: [], readings: [] };
    const plain = C.buildCase(c, { feed: null, admit: [main.inDoubt.admitInDoubt] }), was = main.effects.decideEffects(c.effects, [plain.window], opts);
    const view = ds => ds.map(d => [d.verdict, d.matched, d.authoritative]);
    for (const records of [() => [], b => b.records.map(x => ({ ...x, records: [{ resolver: 'r1', status: 'failed', reason: 'read-not-run' }] })), b => b.records.map(x => ({ ...x, records: [{ resolver: 'r1', read: { ...x.records[0].read, clear: false } }] }))]) {
      const side = connectorSide(c, records);
      assert.deepEqual(view(side.decisions), view(was));
      compared += side.decisions.length;
    }
  }
  t.diagnostic(`verdicts compared with the frozen evaluator: ${compared}`);
  assert.ok(compared > 30000);
});

// The degradations: each replaces a record with its failed form, drops it, or weakens one fact of its read (a guarantee absent, a bound short,
// a flag false, a count up). None adds evidence; none deletes an entry (a feed cannot lose one unseen: test/request-feed.test.mjs test 11).
const DEGRADE = [
  r => null, r => ({ resolver: 'r1', status: 'failed', reason: 'read-not-run' }),
  r => ({ ...r, read: { ...r.read, clear: false } }), r => ({ ...r, read: { ...r.read, history: r.read.history + 1 } }), r => ({ ...r, read: { ...r.read, otherHosts: 1 } }),
  r => ({ ...r, read: { ...r.read, keySends: r.read.keySends + 1 } }), r => ({ ...r, read: { ...r.read, dirtySends: 1 } }), r => ({ ...r, read: { ...r.read, more: true } }),
  r => ({ ...r, read: { ...r.read, watermark: null } }), r => ({ ...r, read: { ...r.read, watermark: r.read.watermark === null ? null : r.read.watermark - 2000 } }),
  r => ({ ...r, read: { ...r.read, headMono: r.read.headMono - 2000 } }), r => ({ ...r, read: { ...r.read, headWall: null, headMono: r.read.headMono } }),
  ...['route', 'type', 'tenant'].map(flag => r => ({ ...r, read: { ...r.read, entries: r.read.entries.map((x, i) => (i ? x : { ...x, [flag]: false })) } })),
  r => ({ ...r, read: { ...r.read, entries: r.read.entries.map((x, i) => (i ? x : { ...x, state: 'other' })) } }),
  r => ({ ...r, read: { ...r.read, entries: r.read.entries.map((x, i) => (i ? x : { ...x, at: C.OFFSET })) } }),
];
const degradeAll = (g, list) => list.map(x => { if (g() < 0.4) return x; const r = C.pick(g, DEGRADE)(x.records[0]); return r === null ? null : { ...x, records: [r] }; }).filter(Boolean);

test('3. property: degrading or removing any record never turns a non-pass into a pass, and never moves an attempt between confirmed and refuted', t => {
  const n = { clauses: 0, fullOnly: 0, confirmed: 0, refuted: 0, undecided: 0, attempts: 0 };
  for (let i = 0, g = C.rng(777); i < RUNS * 2; i++) {
    const c = C.randomCase(g), full = connectorSide(c, b => b.records), less = connectorSide(c, b => degradeAll(g, b.records)), none = connectorSide(c, () => []);
    full.fates.forEach((f, k) => {
      if (f === null) return;
      n.attempts++; if (f === 'applied' && attemptBasis(full.events[k]).by === 'r1') n.confirmed++; if (f === 'refuted' && attemptBasis(full.events[k]).by === 'r1') n.refuted++;
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
  assert.ok(passes > 1500);
});

test('5. property: every re-decided pass and fail is one the frozen evaluator gives reading each derived fate as a proven reply; every further application the feed refutes is one the frozen evaluator\'s own key collapse counts with the application, the receiver\'s dedupe window included', t => {
  let compared = 0, equal = 0, passes = 0, fails = 0, keyed = 0, groups = 0, signingGroups = 0, late = 0;
  for (let i = 0, g = C.rng(4711); i < RUNS; i++) {
    const c = C.randomCase(g), side = connectorSide(c, b => b.records);
    late += side.events.filter(e => boundRecords(e).some(r => r.reason === 'key-identity-differs')).length;
    if (!side.changed) continue;
    // Each attempt as the feed left it: confirmed, refuted as a further application (its read lists an applied word: the provider applied the key
    // once and this send is not that application), refuted by absence or by the transport record, or in doubt.
    const kindOf = new Map(side.events.map((e, k) => {
      const f = side.fates[k], read = sealedRecordsOf(e).find(r => r.resolver === 'r1')?.read;
      return [e.seq, f === 'refuted' && attemptBasis(e).by === 'r1' && read?.entries.some(x => x.state === 'applied') ? 'further' : f];
    }));
    // Oracle A: confirmed reads a proven 201, any refutation a proven declared 409, in doubt an unproven unknown (no transport record, so
    // the frozen evaluator's r0 adds nothing). Oracle B: a further application reads a proven 201 too, a replay of the application, so
    // the frozen evaluator's own key collapse (its identity and the signing dedupe window) decides whether it is one application with it.
    const upOf = further => e => { const f = kindOf.get(e.seq), { transport: _t, ...up } = e.upstream, target = up.target;
      return f === 'applied' || (f === 'further' && further) ? { outcome: 'applied', status: 201, proven: true, target } : f === 'refuted' || f === 'further' ? { outcome: 'rejected', status: 409, proven: true, target }
        : f === 'in-doubt' ? { outcome: 'unknown', status: null, proven: false, target } : up; };
    const oracleA = C.buildCase(c, { feed: null, admit: [main.inDoubt.admitInDoubt], upstreamOf: upOf(false) }), oracleB = C.buildCase(c, { feed: null, admit: [main.inDoubt.admitInDoubt], upstreamOf: upOf(true) });
    const wantA = main.effects.decideEffects(c.effects, [oracleA.window], { role: c.role, claims: [], readings: [] });
    const wantB = main.effects.decideEffects(c.effects, [oracleB.window], { role: c.role, claims: [], readings: [] });
    side.decisions.forEach((d, k) => {
      if (!d.resolution?.redecided) return;
      compared++;
      if (d.verdict === 'pass') { assert.equal(wantA[k].verdict, 'pass', `a pass the derived fates do not give: ${JSON.stringify(c)}`); passes++; }
      if (d.verdict === 'fail') { assert.equal(wantA[k].verdict, 'fail', `a fail the derived fates do not give: ${JSON.stringify(c)}`); fails++; }
      if (d.verdict === wantA[k].verdict) equal++;
      // A keyed clause reads its key groups through the frozen evaluator's collapse in oracle B: never more lenient there either.
      if (c.effects[k]?.countBy !== undefined && ['pass', 'fail'].includes(d.verdict)) { assert.equal(wantB[k].verdict, d.verdict, `a keyed verdict the frozen evaluator's collapse does not give: ${JSON.stringify(c)}`); keyed++; }
    });
    // Every group with a further application: the frozen evaluator's countApplications over oracle B counts the group as exactly one application.
    for (const fold of new Set(oracleB.events.filter(e => kindOf.get(e.seq) === 'further').map(e => e.idempotency.fold))) {
      const members = oracleB.events.filter(e => e.name === C.CRM && e.idempotency?.fold === fold);
      assert.deepEqual((({ low, high }) => ({ low, high }))(main.idem.countApplications(oracleB.window, C.CRM, members)), { low: 1, high: 1 }, `the feed collapsed what the frozen evaluator's key collapse counts apart: ${JSON.stringify(c)}`);
      groups++; if (c.signing) signingGroups++;
    }
  }
  t.diagnostic(`derived-fate oracle: compared ${compared}, equal ${equal}, passes ${passes}, fails ${fails}, keyed against the frozen evaluator's collapse ${keyed}; further-application groups ${groups} (${signingGroups} on a signing host) each one application under the frozen evaluator's collapse; ${late} attempts left in doubt because the collapse reads their group apart`);
  assert.ok(passes > 300 && fails > 300 && keyed > 300 && groups > 100 && signingGroups > 20 && late > 50, `${passes} ${fails} ${keyed} ${groups} ${signingGroups} ${late}`);
});

test('6. parity: the validator recomputes the connector\'s verdicts, rows, records and backend reading from the sealed reads alone', t => {
  const n = { runs: 0, changed: 0, clauses: 0 };
  for (let i = 0, g = C.rng(20261016); i < RUNS * 2; i++) {
    const c = C.randomCase(g), side = connectorSide(c, b => (g() < 0.7 ? b.records : degradeAll(g, b.records)));
    const again = validatorSide(c, side.trace);
    assert.deepEqual(again.decisions.map(d => d.verdict), side.decisions.map(d => d.verdict));
    assert.deepEqual(again.rows, effectAssertionRows(side.decisions));
    assert.equal(again.backendObserved, backendObserved(side.decisions));
    assert.equal(Object.hasOwn(side.trace.data, 'resolutions'), side.changed);
    n.runs++; n.clauses += side.decisions.length; if (side.changed) n.changed++;
  }
  t.diagnostic(`parity: ${JSON.stringify(n)}`);
  assert.ok(n.changed > 2000, JSON.stringify(n));
});

test('7. tamper: an edited read (counts, flags, times), key digest or clock that changes any derived fate or basis is refused on recompute; an edit to a result is refused', t => {
  const g = C.rng(31337);
  let refused = 0, inert = 0, keyRefused = 0, keyInert = 0;
  const EDITS = [
    ['history', r => { r.history += 1; }], ['keySends', r => { r.keySends += 1; }], ['dirtySends', r => { r.dirtySends += 1; }], ['otherHosts', r => { r.otherHosts += 1; }],
    ['clear', r => { r.clear = !r.clear; }], ['more', r => { r.more = !r.more; }], ['watermark', r => { r.watermark = r.watermark === null ? r.headWall + 10000 : null; }],
    ['headMono', r => { r.headMono = Math.max(0, r.headMono - 3000); }], ['entry at', r => { if (r.entries[0]) r.entries[0].at = C.OFFSET; }],
    ['entry state', r => { if (r.entries[0]) r.entries[0].state = r.entries[0].state === 'applied' ? 'not-applied' : 'applied'; }], ['entry tenant', r => { if (r.entries[0]) r.entries[0].tenant = !r.entries[0].tenant; }],
    ['entries dropped', r => { r.entries = []; }],
  ];
  for (let i = 0; i < 1200; i++) {
    const c = C.randomCase(g), side = connectorSide(c, b => b.records);
    if (!side.changed) continue;
    const listed = new Set(side.decisions.flatMap(d => d.resolution?.attempts ?? []).map(a => `${a.seq} ${a.fate} ${a.by} ${a.reason ?? ''}`));
    for (const [why, edit] of EDITS) {
      const t2 = json(side.trace);
      for (const x of t2.data.resolutions) for (const r of x.records) if (r.read) edit(r.read);
      // The derived fates under the edit, on a fresh window: refused exactly when a fate or basis some clause lists changes.
      const fresh = C.buildCase(c), entries = lateEntriesFor([fresh.window], t2.data.resolutions);
      let bound = true;
      try { bindResolutions([fresh.window], entries); } catch { bound = false; }
      const now = new Set(fresh.events.map(e => { const b = attemptBasis(e); return `${e.seq} ${fateOf(e)} ${b.by} ${b.reason ?? ''}`; }));
      const moved = !bound || [...listed].some(a => !now.has(a));
      let threw = false;
      try { validatorSide(c, t2); } catch (error) { threw = true; assert.match(error.message, /effect-(trace|verdict)/); }
      if (moved) { assert.ok(threw, `${why}: a changed fate was accepted`); refused++; } else inert++;
    }
    // A sealed result in place of a read, and a record moved to another attempt: refused.
    const bare = json(side.trace); bare.data.resolutions[0].records = [{ resolver: 'r1', status: 'succeeded', result: 'confirms' }];
    assert.throws(() => validatorSide(c, bare), /effect-(trace|verdict)/); refused++;
    const moved = json(side.trace); moved.data.resolutions[0].seq = 99;
    assert.throws(() => validatorSide(c, moved), /effect-trace/); refused++;
    // A key digest edited on one sealed event (the join is by the exact key): refused, or recomputed identically when nothing reads it.
    const keyed = json(side.trace), e = keyed.data.windows[0].events.find(x => x.idempotency?.status === 'keyed' && x.seq === keyed.data.resolutions[0].seq);
    // The read names the key it was read for (read.key), so the edit reads key-mismatch (or key-variant): refused whenever that changes what a
    // clause lists; a group already failed for the same reason recomputes identically, as any other edit no verdict reads.
    if (e && side.decisions.some(d => (d.resolution?.attempts ?? []).some(a => a.seq === e.seq))) { e.idempotency.key = 'f'.repeat(64); try { validatorSide(c, keyed); keyInert++; } catch (error) { assert.match(error.message, /effect-(trace|verdict)/); keyRefused++; } }
  }
  t.diagnostic(`tamper: ${refused} refused, ${inert} edits that change no listed fate; key digest edits: ${keyRefused} refused, ${keyInert} recomputed identically`);
  assert.ok(refused > 1500 && keyRefused > 300 && keyRefused > 10 * Math.max(1, keyInert), `${refused} refused, key ${keyRefused}/${keyInert}`);
});

// --- The connector and the shared validator, end to end (injected recorder; no socket) ------------------------------------------
const suiteOf = p => createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
// A virtual clock: every wait advances it at once (no host timer, so no host suspend applies), so a run costs no real settle time.
const virtualClock = () => { let now = 0; return { now: () => now, sleep: async ms => { now += ms; } }; };
async function runOf(p, factory, options = {}) {
  const run = await runHttpAssessment(p, { env: {}, transport: C.transport, observerFactory: factory, clock: virtualClock(), ...options });
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  validateHttpRunEvidence(json(run), { expectedSuite: suiteOf(p) });
  return run;
}
const rowOf = (run, id = 'TASK1') => run.results.find(r => r.id === id);
const verdictsOf = row => row.trace[1].data.effects.map(e => e.verdict);
const readsFor = (make) => sent => sent.filter(e => e.name === C.CRM && e.upstream.outcome === 'unknown' && e.upstream.transport?.connected).map(e => ({ seq: e.seq, records: [{ resolver: 'r1', read: { ...make(e), key: e.idempotency.key } }] }));
const reseal = row => { row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); };

test('8. end to end: a confirmation and a refutation are decided again before settlement, sealed as reads, and recomputed by the shared validator with the suite', async () => {
  const p = C.profileOf([[C.EXISTS, C.count(1), C.KEYED_COUNT(1)], [C.count(0), C.EXISTS]]);
  const batches = [() => [C.send({ seq: 1 })], () => [C.send({ seq: 2, key: 'K2', arrived: 3000, ended: 3100 })]];
  const ok = e => C.read({ headMono: 9000, headWall: C.OFFSET + 9000, watermark: C.OFFSET + 8900, entries: e.seq === 1 ? [C.entry()] : [] });
  const without = await runOf(p, C.r1RecorderFactory(batches));
  assert.deepEqual([verdictsOf(rowOf(without)), verdictsOf(rowOf(without, 'TASK2'))], [['missing', 'missing', 'missing'], ['missing', 'missing']], 'no read: in doubt, as main');
  const run = await runOf(p, C.r1RecorderFactory(batches, { reads: readsFor(ok) }));
  const t1 = rowOf(run), t2 = rowOf(run, 'TASK2');
  assert.deepEqual([verdictsOf(t1), t1.status, t1.backendEvidence], [['pass', 'pass', 'pass'], 'pass', 'observed'], 'confirmed: exists, exactly one, one keyed application');
  // Refuted under the watermark: the agent-write exists fails; exactly zero is decided as zero applications, then held by the
  // positive-match pairing (an absence pinned to an outcome needs an allowed-use twin, which this profile does not declare).
  assert.deepEqual([verdictsOf(t2), t2.status, t2.trace[1].data.effects[0].resolution.operation, typeof t2.trace[1].data.effects[0].pairing], [['inconclusive', 'fail'], 'fail', 'refuted', 'string']);
  assert.deepEqual(t1.trace[1].data.resolutions.map(x => x.records.map(r => Object.keys(r))), [[['resolver', 'read']]], 'sealed as the read, never a result');
  assert.deepEqual([t1.trace[1].data.effects[0].resolution.attempts[0].by, t2.trace[1].data.effects[0].resolution.attempts[0].by], ['r1', 'r1']);
  assert.equal(run.observers[0].requestFeed.collector.label, 'request-feed/1');
  // Tamper on the saved run: an unsealed edit fails its evidence digest; a feed-level edit in one row, resealed, fails against the other row.
  const unsealed = json(run); rowOf(unsealed).trace[1].data.resolutions[0].records[0].read.history = 1;
  assert.throws(() => validateHttpRunEvidence(unsealed), error => error.code === 'invalid-run-evidence');
  const oneRow = json(run), r = rowOf(oneRow); r.trace[1].data.resolutions[0].records[0].read.headWall += 1; reseal(r);
  assert.throws(() => validateHttpRunEvidence(oneRow), error => error.code === 'invalid-run-evidence' && error.detail === 'effect-trace', 'one feed-level read per recorder');
  const confirmedAway = json(run), c1 = rowOf(confirmedAway); c1.trace[1].data.resolutions[0].records[0].read.entries = []; reseal(c1);
  assert.throws(() => validateHttpRunEvidence(confirmedAway), error => error.code === 'invalid-run-evidence', 'the derived result no longer matches the stored verdicts');
  const counted = json(run), c2 = rowOf(counted); c2.trace[1].data.resolutions[0].records[0].read.keySends = 0; reseal(c2);
  assert.throws(() => validateHttpRunEvidence(counted), error => error.code === 'invalid-run-evidence', 'a run-wide count below what the sealed windows show');
  // The record moved to egress-recorder/7 (which never declares a feed) or stripped of its feed: refused.
  const relabelled = json(run); relabelled.observers[0].collector.label = 'egress-recorder/7';
  assert.throws(() => validateHttpRunEvidence(relabelled), error => error.code === 'invalid-run-evidence');
  const stripped = json(run); delete stripped.observers[0].requestFeed;
  assert.throws(() => validateHttpRunEvidence(stripped), error => error.code === 'invalid-run-evidence');
  assert.throws(() => validateHttpRunEvidence(json(run), { expectedSuite: suiteOf(C.profileOf([[C.EXISTS, C.count(1), C.KEYED_COUNT(1)], [C.count(0), C.EXISTS]], { feed: C.requestFeed({ maxSkewMs: 1 }) })) }), error => error.code === 'unexpected-suite-evidence');
});

test('9. end to end parity: seeded runs through the connector validate with their suite, and every clause no later stage tagged reads as the stage alone decided it', async t => {
  let runs = 0, changed = 0, compared = 0;
  // One task per case, seqs fixed by the case (the injected recorder hands them out as sealed); one registry for every case's profile.
  const g = C.rng(8080), cases = Array.from({ length: 250 }, (_, i) => { const c = C.randomCase(g), keep = g() < 0.7; return { c, keep, p: { ...C.profileOf([c.effects], { signing: c.signing }), id: `r1-app-${i}`, applicationId: `r1-app-${i}` } }; });
  // A target file holds at most 20 targets: one registry per 20 cases.
  const registries = Array.from({ length: Math.ceil(cases.length / 20) }, (_, k) => createRegistry({ profiles: cases.slice(20 * k, 20 * k + 20).map(x => x.p), env: {} }));
  for (const [i, { c, keep, p }] of cases.entries()) {
    const registry = registries[Math.floor(i / 20)];
    const records = C.buildCase(c).records, given = keep ? records : degradeAll(g, records);
    const run = await runHttpAssessment(p, { env: {}, transport: C.transport, observerFactory: C.r1RecorderFactory([() => C.buildCase(c).events], { reads: () => given, signing: c.signing }), clock: virtualClock() });
    const suite = registry.exportSuite(p.id);
    validateHttpRunEvidence(run, { expectedSuite: suite });
    validateHttpRunEvidence(json(run), { expectedSuite: suite });
    const row = rowOf(run), stage = connectorSide(c, () => given);
    row.trace[1].data.effects.forEach((e, k) => { if (!['settlement', 'attribution', 'pairing', 'appLog', 'later'].some(key => Object.hasOwn(e, key))) { assert.equal(e.verdict, stage.decisions[k].verdict, JSON.stringify(c)); compared++; } });
    if (Object.hasOwn(row.trace[1].data, 'resolutions')) changed++;
    runs++;
  }
  t.diagnostic(`end-to-end parity: ${runs} runs validated, ${changed} with sealed reads, ${compared} clauses equal to the stage alone`);
  assert.ok(changed > 80 && compared > 400, `${changed} ${compared}`);
});

test('10. a lifecycle change check takes no late record, so its post-change gate and the validator agree; a record forged onto it is refused', async () => {
  const ENV = { SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_C: 'tok-carol' }, WHO = { 'tok-admin': 'admin', 'tok-carol': 'carol' };
  const control = (id, actorId, method, path, extra = {}) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId, method, path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...extra });
  const me = (id, actorId) => control(id, actorId, 'GET', '/me', { assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: actorId }] });
  const p = { id: 'r1-lifecycle', name: 'R1 lifecycle', applicationId: 'r1-lifecycle', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { admin: { principalId: 'admin', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, carol: { principalId: 'carol', credentialEnv: 'SCOPEHAVEN_TARGET_C', identityValue: 'carol' }, member: { principalId: 'member-1' } },
    observers: [C.declaration()], requiredControlIds: ['ADMIN-ME', 'CAROL-ME', 'CAROL-NOTES', 'CHANGE'], lifecycle: [{ changeCheckId: 'CHANGE', actorId: 'carol', after: 'refused' }],
    checks: [me('ADMIN-ME', 'admin'), me('CAROL-ME', 'carol'), control('CAROL-NOTES', 'carol', 'GET', '/notes'), control('CHANGE', 'admin', 'POST', '/users/carol/close', { body: {}, effects: [C.EXISTS] }),
      { id: 'REUSE', title: 'REUSE', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: { source: 'http-egress', name: C.ALT } }] }] };
  let closed = false;
  const transport = async (origin, check, { credential }) => {
    const who = WHO[credential] ?? null;
    if (check.path === '/me') return who ? { status: 200, complete: true, jsonParsed: true, json: { user: who }, bytes: 10 } : { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (!who || (who === 'carol' && closed)) return { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (check.path === '/users/carol/close') closed = true;
    return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  // The change's own close is forwarded and reset (in doubt); the feed later confirms it.
  const factory = C.r1RecorderFactory([() => [C.send({ seq: 1 })], () => []], { reads: readsFor(() => C.read({ entries: [C.entry()] })) });
  const run = await runHttpAssessment(p, { env: ENV, transport, observerFactory: factory, clock: virtualClock() });
  const change = run.results.find(r => r.id === 'CHANGE'), reuse = run.results.find(r => r.id === 'REUSE');
  assert.deepEqual([verdictsOf(change), Object.hasOwn(change.trace[1].data, 'resolutions'), change.status], [['missing'], false, 'inconclusive'], 'the change check read no late record');
  assert.deepEqual([reuse.trace[0].data.notSent, run.identityEvidence.actors.find(a => a.actorId === 'carol').lifecycle.changeConfirmed], ['change-not-confirmed', false]);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: ENV }).exportSuite(p.id) });
  // The same records bound on it (as a connector without the rule would): the row now passes and the run is refused.
  const forged = json(run), row = forged.results.find(r => r.id === 'CHANGE'), data = row.trace[1].data;
  data.resolutions = [{ observer: C.INST, seq: data.windows[0].events[0].seq, records: [{ resolver: 'r1', read: C.read({ entries: [C.entry()], key: data.windows[0].events[0].idempotency.key }) }] }];
  data.effects[0].verdict = 'pass'; reseal(row);
  assert.throws(() => validateHttpRunEvidence(forged), error => error.code === 'invalid-run-evidence');
});

test('11. the sleep-partial rule under the request feed: on a sleep-partial window a refutation decides no pass and no operation, as the transport record\'s does; a confirmation decides presence exactly as a proven applied reply does in the frozen evaluator', () => {
  const SHORT = { cause: 'host-sleep', count: 1, ms: 70000, from: '2026-10-16T00:00:01.000Z', to: '2026-10-16T00:01:11.000Z', shortMs: 150 };
  const ok = C.read({ headMono: 1100 + C.SETTLE, headWall: C.OFFSET + 1100 + C.SETTLE, watermark: C.OFFSET + 1100 + C.SETTLE + C.SKEW });
  const sleepy = (events, admit = admitInDoubt, feed = C.FEED) => admit(applySuspendShort({ source: 'http-egress', instanceId: C.INST, scope: C.scopeOf(feed), coverage: 'complete', reason: null, events, suspend: SHORT }));
  const clauses = [C.EXISTS, C.count(0), C.count(1), C.ONLY([]), C.KEYED_COUNT(1)];
  for (const [entries, want, operations] of [[[], ['missing', 'missing', 'missing', 'missing', 'missing'], 'in-doubt'], [[C.entry()], null, 'confirmed']]) {
    const e = C.send({ seq: 1 }), w = sleepy([e]);
    assert.deepEqual([w.coverage, w.reason.split(',').includes('host-suspend-wait-short')], ['partial', true]);
    const decisions = redecideResolved([{ effects: clauses, claims: [], readings: [], role: 'boundary', windows: [w] }], [C.supplied(e, { ...ok, entries })])[0];
    assert.equal(fateOf(e), entries.length ? 'applied' : 'refuted', 'r1 decided the attempt');
    assert.ok(decisions.every(d => d.resolution.operation === operations), JSON.stringify(decisions.map(d => d.resolution.operation)));
    if (want) { assert.deepEqual(decisions.map(d => d.verdict), want, 'a refutation: no pass, no operation'); continue; }
    // A confirmation: every verdict is the frozen evaluator's on the same sleep-partial window with that attempt a proven 201.
    const proven = C.send({ seq: 1, outcome: 'applied', feedHost: false }), mw = sleepy([proven], w2 => main.inDoubt.admitInDoubt(admitInDoubt(w2)), null);
    assert.deepEqual(decisions.map(d => d.verdict), main.effects.decideEffects(clauses, [mw], { role: 'boundary' }).map(d => d.verdict));
    assert.equal(decisions[0].verdict, 'pass', 'presence decides on any coverage');
  }
});

test('12. the timing plan reserves one resolver read for a declared request feed, and only then', () => {
  const p = C.profileOf([[C.EXISTS]]), timed = { ...p, timing: { effectHorizonMs: 1000, runBudgetMs: 600000 } };
  const terms = plannedTimingTerms(timed, { controlPlan: identityControlPlan(timed) });
  assert.equal(terms.resolvers, REQUEST_FEED_READ_MS);
  const plainTimed = { ...C.profileOf([[C.EXISTS]], { feed: null }), timing: { effectHorizonMs: 1000, runBudgetMs: 600000 } };
  assert.equal(Object.hasOwn(plannedTimingTerms(plainTimed, { controlPlan: identityControlPlan(plainTimed) }), 'resolvers'), false, 'no feed: the plan is unchanged');
  assert.deepEqual(declaredObserverRecord([C.declaration({ feed: null })])[0], C.RECORD_PLAIN);
});

test('13. on a feed host that declares signing, same-key same-body retries arriving past the receiver\'s dedupeSeconds are separate applications to the key collapse, so the feed leaves them in doubt; within the window it decides as before', () => {
  // crm.example declares signing (stripe, dedupeSeconds 1) and the feed; the loader accepts it.
  validateEgressConfig(C.declaration({ signing: true }), { member: { principalId: 'member-1' } });
  const clauses = [C.KEYED_COUNT(1), C.count(1), C.KEYED_ONLY([{ select: C.CLOSE_SEL, count: 1 }])];
  const decide = ({ arrivals, seconds, entries }) => {
    const events = arrivals.map((arrived, i) => C.signedSend({ seq: 10 + i, firstSeq: 10, arrived, ended: arrived + 100, signingAt: seconds[i] }));
    const w = C.windowOf(events, { signing: true }), before = decideEffects(clauses, [w], { role: 'boundary' });
    const r = C.read({ keySends: events.length, entries, headMono: 20000, headWall: C.OFFSET + 20000, watermark: C.OFFSET + 19000 });
    const [again] = redecideResolved([{ effects: clauses, claims: [], readings: [], role: 'boundary', windows: [w] }], events.map(e => C.supplied(e, r)));
    const decisions = again ?? before, recomputed = recomputeEffectTrace(json(effectTrace(decisions, [w], C.META)), undefined, [C.RECORD_SIGNING], { role: 'boundary' });
    assert.deepEqual(recomputed.decisions.map(d => d.verdict), decisions.map(d => d.verdict), 'the validator agrees');
    return { before: before.map(d => d.verdict), after: decisions.map(d => d.verdict), fates: events.map(e => fateOf(e)), reasons: events.map(e => boundRecords(e).map(x => x.reason ?? x.status)) };
  };
  // Two reset sends under K1, one body and head, arriving 10 s apart (signing items 10 s apart); the feed lists two applied entries on one
  // object inside the interval. The receiver no longer held the key for the second, so it may have applied it again: in doubt, no pass.
  const past = decide({ arrivals: [1000, 11000], seconds: [C.SEC0 + 1, C.SEC0 + 11], entries: [C.entry({ at: C.OFFSET + 1050 }), C.entry({ at: C.OFFSET + 11050 })] });
  assert.deepEqual(past, { before: ['missing', 'missing', 'missing'], after: ['missing', 'missing', 'missing'], fates: ['in-doubt', 'in-doubt'], reasons: [['key-identity-differs'], ['key-identity-differs']] });
  // The frozen evaluator's own collapse reads the pair the same way: with both proven applied it counts two applications (count(1) fails,
  // the keyed clauses read missing), so a pass here would be one it never gives.
  const proven = [1000, 11000].map((arrived, i) => C.signedSend({ seq: 10 + i, firstSeq: 10, outcome: 'applied', arrived, ended: arrived + 100, signingAt: C.SEC0 + 1 + 10 * i, feedHost: false }));
  const mw = C.windowOf(proven, { feed: null, signing: true }); main.inDoubt.admitInDoubt(mw);
  assert.deepEqual(main.effects.decideEffects(clauses, [mw], { role: 'boundary' }).map(d => d.verdict), ['missing', 'fail', 'missing']);
  // Within the window (both in one arrival second, one applied entry): one application, decided as before.
  const within = decide({ arrivals: [1000, 1400], seconds: [C.SEC0 + 1, C.SEC0 + 1], entries: [C.entry({ at: C.OFFSET + 1050 })] });
  assert.deepEqual([within.before, within.after, within.fates], [['missing', 'missing', 'missing'], ['pass', 'pass', 'pass'], ['applied', 'refuted']]);
});
