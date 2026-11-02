// In-doubt resolution, the run-end re-decide stage, as built: the later resolvers, the request feed (r1) and read-back (r2), apply only in a
// window whose recorder declares a request feed or read-back, so with neither declared the stage is inert. test/in-doubt-r1.test.mjs and
// test/in-doubt-r2.test.mjs exercise r1 and r2. Checked: the table holds r0, r1 and r2, and without either declaration every late record is
// dropped by the connector and refused by the validator; markUnfollowed marks a window and copies no event; a seeded differential against a
// frozen earlier evaluator: with any record an observer could return, every verdict, decision record and sealed byte equals the frozen one's, at seal time,
// under the follow rule and after the stage, and the validator recomputes them; end to end, a run whose recorder returns late records equals
// the same run without them, and a run that carries one is refused. test/in-doubt-redecide-stub.test.mjs exercises the stage with records.
// Owned synthetic data only. No socket is opened: observers and transports are injected.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { RESOLVER_TABLE, LATER_RESOLVER_NAMES, lateEntriesFor, bindResolutions, sealedResolutions, boundRecords, admitInDoubt, fateOf } from '../src/in-doubt.mjs';
import { makeEffect, admitScoped, markUnfollowed } from '../src/effect-events.mjs';
import { decideEffects, effectTrace, recomputeEffectTrace, redecideResolved, bindSealedResolutions } from '../src/http-effects.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { digest } from '../src/domain.mjs';
import * as C from './fixtures/in-doubt-redecide-cases.mjs';

const frozenOf = name => import(fileURLToPath(new URL(`./fixtures/in-doubt-main-8eaa589/${name}`, import.meta.url)));
const main = { effects: await frozenOf('http-effects.mjs'), events: await frozenOf('effect-events.mjs'), inDoubt: await frozenOf('in-doubt.mjs') };
const { CRM, INST, CLOSE, UP, EXISTS, ONLY, count } = C;

let seq = 0;
const send = upstream => { seq++; return makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq, observedAt: '2026-10-16T00:00:00.000Z', operation: 'send',
  name: CRM, resource: CLOSE, outcome: 'committed', content: { n: seq }, upstream: { ...structuredClone(upstream), target: { exact: true, query: false } } }); };
const win = events => admitInDoubt({ source: 'http-egress', instanceId: INST, scope: { operations: ['send'], names: [C.ALT, CRM], actorAttribution: 'none', evidence: 'authoritative', forward: C.RECORDS.plain.forward }, coverage: 'complete', reason: null, events });
const anyRecord = e => ({ observer: INST, seq: e.seq, records: [{ resolver: 'r1', status: 'succeeded', result: 'refutes' }] });

test('1. with no request feed or read-back declared, r1 and r2 (the later resolvers) apply to nothing: every late record is dropped by the connector side and refused by the validator side', () => {
  assert.deepEqual(Object.keys(RESOLVER_TABLE), ['r0', 'r1', 'r2']);
  assert.deepEqual(LATER_RESOLVER_NAMES, ['r1', 'r2']);
  const reset = send(UP.reset), w = win([reset]);
  const supplied = ['r1', 'r2', 'rx', 'r0'].flatMap(resolver => [{ observer: INST, seq: reset.seq, records: [{ resolver, status: 'succeeded', result: 'refutes' }] }, { observer: INST, seq: reset.seq, records: [{ resolver, status: 'failed', reason: 'read-failed' }] }]);
  assert.deepEqual(lateEntriesFor([w], supplied), []);
  for (const entries of [[anyRecord(reset)], [{ observer: INST, seq: reset.seq, records: [{ resolver: 'r0', status: 'succeeded', result: 'refutes' }] }]]) {
    assert.throws(() => bindResolutions([w], entries), /resolution-record/);
    assert.throws(() => bindSealedResolutions([w], entries), /effect-trace/);
  }
  assert.deepEqual([sealedResolutions([w]), boundRecords(reset), fateOf(reset)], [[], [], 'in-doubt']);
  assert.deepEqual(redecideResolved([{ effects: [count(0), ONLY], claims: [], readings: [], role: 'boundary', windows: [w] }], supplied), [null], 'the stage changes nothing');
  // A sealed trace that carries a record is refused, whatever it says (an empty list too).
  const trace = effectTrace(decideEffects([count(0)], [w]), [w], C.META);
  for (const resolutions of [[anyRecord(reset)], []]) {
    const forged = JSON.parse(JSON.stringify({ ...trace, data: { ...trace.data, resolutions } }));
    assert.throws(() => recomputeEffectTrace(forged, undefined, [C.RECORDS.plain]), /effect-trace/);
  }
  recomputeEffectTrace(JSON.parse(JSON.stringify(trace)), undefined, [C.RECORDS.plain]);
});

test('2. markUnfollowed adds the window to a set and copies nothing, so events keep their identity (and any overlay bound on them)', () => {
  const events = [send(UP.reset), send(UP.applied)];
  const w = admitScoped(win(events));
  Object.assign(w, { coverage: 'partial', reason: C.AFTER, scoped: [{ name: CRM, resource: 'POST /tickets/T-1/close', codes: [C.AFTER] }] });
  const list = w.events, marked = markUnfollowed(w);
  assert.equal(marked, w);
  assert.equal(marked.events, list);
  assert.ok(marked.events.every((e, i) => e === events[i]));
  assert.deepEqual(Object.keys(marked).sort(), ['coverage', 'events', 'instanceId', 'reason', 'scope', 'scoped', 'source']);
});

// --- Seeded differential against a frozen earlier evaluator ------------------------------------------------------------------------------
const BOTH = { scoped: [admitScoped, main.events.admitScoped], inDoubt: [admitInDoubt, main.inDoubt.admitInDoubt] };
const RUNS = 3000;
const scrubbed = trace => JSON.parse(JSON.stringify(trace));

test('3. differential: with any record an observer could return, every decision and every sealed byte equals the frozen evaluator\'s at seal time, under the follow rule and after the stage, and the validator recomputes them', t => {
  const g = C.rng(61);
  const n = { runs: 0, decisions: 0, opted: 0, supplied: 0, unfollowed: 0, short: 0, scoped: 0, keyed: 0, mainRecomputed: 0 };
  for (let i = 0; i < RUNS; i++) {
    const c = C.randomCase(g, { later: pick(g) }), w = C.buildWindow(c, { mark: BOTH }), windows = [w], opts = { role: c.role, claims: c.claims, readings: c.readings };
    let live = decideEffects(c.effects, windows, opts), was = main.effects.decideEffects(c.effects, windows, opts);
    assert.deepEqual(live, was, 'at seal time');
    if (c.kind === 'unfollowed') {
      markUnfollowed(w); main.events.markUnfollowed(w);
      live = decideEffects(c.effects, windows, opts); was = main.effects.decideEffects(c.effects, windows, opts);
      assert.deepEqual(live, was, 'under the follow rule');
    }
    // The run-end stage, with what an observer returned: nothing binds, so the row is as it was.
    assert.deepEqual(redecideResolved([{ effects: c.effects, claims: c.claims, readings: c.readings, role: c.role, windows }], c.supplied), [null]);
    assert.deepEqual(sealedResolutions(windows), []);
    assert.deepEqual(decideEffects(c.effects, windows, opts), was, 'after the stage');
    const sealed = effectTrace(live, windows, C.META), sealedMain = main.effects.effectTrace(was, windows, C.META);
    assert.deepEqual(sealed, sealedMain, 'the sealed trace');
    assert.equal(digest(sealed.data), digest(sealedMain.data));
    // The validator recomputes the sealed trace; the frozen evaluator's validator does too, on windows it alone binds (no destination-scoped entry, which
    // only one module instance would admit: the frozen http-effects reads custody through the live src/custody.mjs).
    const again = recomputeEffectTrace(scrubbed(sealed), undefined, [C.recordOf(c)], { role: c.role, unfollowed: C.unfollowedOf(c) });
    assert.deepEqual(again.decisions.map(d => d.verdict), live.map(d => d.verdict));
    if (!w.scoped) { const old = main.effects.recomputeEffectTrace(scrubbed(sealed), undefined, [C.recordOf(c)], { role: c.role, unfollowed: C.unfollowedOf(c) }); assert.deepEqual(old.rows, again.rows); n.mainRecomputed++; }
    n.runs++; n.decisions += live.length; n.opted += live.filter(d => d.resolution).length; n.supplied += c.supplied.length;
    if (c.kind in n) n[c.kind]++; if (c.keyed) n.keyed++;
  }
  t.diagnostic(`differential: ${JSON.stringify(n)}`);
  assert.ok(n.decisions > 15000 && n.opted > 5000 && n.unfollowed > 500 && n.short > 250 && n.keyed > 800 && n.mainRecomputed > 1500, JSON.stringify(n));
});
const pick = g => C.pick(g, ['r1', 'r2', 'rx', 'r0']);

test('4. end to end: a recorder that returns late records gives the same run as one that returns none; a run that carries a record is refused', async () => {
  const cases = [
    [C.profileOf([[EXISTS, count(0), ONLY]]), () => [send(UP.reset), send(UP.refused)], []],
    [C.profileOf([[EXISTS, count(1)]]), () => [send(UP.reset)], [true]],
    [C.profileOf([[C.KEYED_ONLY([]), C.KEYED_COUNT]], { keyed: true }), () => { const first = makeEffect({ ...send(UP.reset), idempotency: { status: 'keyed', key: '1'.repeat(64), fold: '1'.repeat(64), head: 'a'.repeat(64), firstSeq: seq } }); return [first]; }, []],
  ];
  for (const [p, events, late] of cases) {
    const reads = sent => sent.map(e => ({ seq: e.seq, records: [{ resolver: 'r1', status: 'succeeded', result: 'refutes' }, { resolver: 'r0', status: 'succeeded', result: 'refutes' }] }));
    const quiet = await C.runOf(p, C.recorderFactory([events], { late })), loud = await C.runOf(p, C.recorderFactory([events], { late, reads }));
    const view = run => run.results.map(r => [r.id, r.status, r.backendEvidence, r.assertions, r.trace[1]?.data ?? null]);
    // The events of the two runs differ only in their seq (fresh sends, whose bodies name it); everything decided and sealed is the same.
    const noSeq = value => JSON.parse(JSON.stringify(value, (key, v) => (['seq', 'firstSeq', 'contentDigest'].includes(key) ? undefined : v)));
    assert.deepEqual(noSeq(view(loud)), noSeq(view(quiet)));
    assert.ok(loud.results.every(r => !Object.hasOwn(r.trace[1]?.data ?? {}, 'resolutions')));
  }
  // A forged record on a sealed row, resealed under the evidence digest: refused.
  const run = await C.runOf(C.profileOf([[count(0)]]), C.recorderFactory([() => [send(UP.reset)]]));
  const forged = structuredClone(run), row = C.rowOf(forged), data = row.trace[1].data;
  data.resolutions = [{ observer: INST, seq: data.windows[0].events[0].seq, records: [{ resolver: 'r1', status: 'succeeded', result: 'refutes' }] }];
  row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: data, assertions: row.assertions });
  assert.throws(() => validateHttpRunEvidence(forged), error => error.code === 'invalid-run-evidence');
});
