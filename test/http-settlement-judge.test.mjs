// Judged late effects (settlement re-judge; src/http-settlement.mjs, opt-in by the target's settlement
// "outsideWindow": "judge"). Pure decisions over synthetic windows and scripted end-to-end runs (injected transport and
// observers, a virtual clock where one is needed): no socket, no database, no model, no provider. Every allowed behaviour sits
// beside the withheld one next to it. A late countBy release is not built: keyed counts read as without the declaration,
// and a countBy effect.only clause is judged with each late candidate as its own application (test 24).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile, contractDigest, passedAtSend } from '../src/contracts.mjs';
import { makeEffect, EFFECT_LIMITS } from '../src/effect-events.mjs';
import { decideEffects, OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { settlementFindings, applySettlement, validateSettlementRecord, SETTLEMENT_NOTES, SETTLEMENT_NOTE_BASIS, SETTLEMENT_REASONS } from '../src/http-settlement.mjs';
import { attributionFindings } from '../src/http-attribution.mjs';
import { closureOwners } from '../src/id-closure.mjs';
import { validateIdempotencyDeclaration } from '../src/idempotency.mjs';
import { judgeOnly } from '../integrations/collateral/only.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { httpScopeText, httpLimitations, observerScopeNote, correlationLimitation, JUDGED_LATE_EFFECTS_NOTE } from '../src/http-scope-text.mjs';
import { compareRuns } from '../src/runner.mjs';

const NOTE = 'effect-outside-window-judged';
const HOST = 'hooks.judge.example', INST = 'egress-recorder-hooks', OTHER_INST = 'egress-recorder-other';
const SINK = Object.freeze({ operations: ['send'], names: [HOST], actorAttribution: 'none', evidence: 'authoritative' });
const PRESENCE = Object.freeze({ ...SINK, evidence: 'presence-only' });
const T = i => (i + 1).toString(16).padStart(2, '0').repeat(16);
const OTHER = 'ab'.repeat(16), STRANGER = 'cd'.repeat(16);
const tokens = new Map([[T(0), 0], [T(1), 1], [T(2), 2], [OTHER, null]]);
const declared = new Set([`${INST}\n${HOST}`]);
const runMode = { mode: 'run', tokens, declared };
const perCheck = (rows, barriers = rows.map(() => [win()])) => ({ mode: 'per-check', barriers, tokens, declared });
let seq = 0;
// A committed send to HOST. Events are made in run order, so a later window's events carry higher seq, as a recorder's do.
const ev = (resource, { token, instanceId = INST, actor = null, captured, upstream, idempotency, content } = {}) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq,
  observedAt: '2026-10-11T00:00:00.000Z', operation: 'send', name: HOST, resource, outcome: 'committed', actor, correlation: token ? { settlementToken: token } : {}, captured, upstream, idempotency, content });
const win = (events = [], coverage = 'complete', extra = {}) => ({ source: 'http-egress', instanceId: INST, scope: SINK, coverage, reason: coverage === 'complete' ? null : 'synthetic', events, ...extra });
const presenceWin = (events = []) => ({ source: 'http-egress', instanceId: OTHER_INST, scope: PRESENCE, coverage: 'complete', reason: null, events });
const sel = resource => ({ source: 'http-egress', operation: 'send', name: HOST, ...(resource ? { resource } : {}) });
const A = 'POST /hooks/a', B = 'POST /hooks/b', C = 'POST /hooks/c';
// effect.only: expect [[resource, count]], allow [resource | selector].
const only = ({ expect = [[A, 1]], allow = [] } = {}) => ({ kind: 'effect.only', expect: expect.map(([r, count]) => ({ select: sel(r), count })), allow: allow.map(a => typeof a === 'string' || a === null ? sel(a) : a), sources: ['http-egress'] });
const none = r => ({ kind: 'effect.none', select: sel(r) });
const exists = r => ({ kind: 'effect.exists', select: sel(r) });
const count = (r, expected) => ({ kind: 'effect.count', select: sel(r), expected });
const rowOf = (effects, windows, role = 'boundary') => ({ effects: decideEffects(effects, windows, { role }), windows });
const gapsFor = rows => Array.from({ length: rows.length + 1 }, () => [win()]);
const inTail = (rows, windows) => [...Array.from({ length: rows.length }, () => [win()]), windows];
const judged = (rows, gaps, correlation) => settlementFindings(rows, gaps, correlation, { judge: true });
const plain = (rows, gaps, correlation) => settlementFindings(rows, gaps, correlation);
const withholds = reason => SETTLEMENT_REASONS.includes(reason);
// En and em dash (U+2013, U+2014), built from code points so this file carries neither.
const DASHES = new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`);
// One passing effect.only row over its own window (made first, so its events come first).
const passing = (spec = only({ allow: [B] }), ownEvents = () => [ev(A)], role = 'boundary') => { const row = rowOf([spec], [win(ownEvents())], role); assert.equal(row.effects[0].verdict, 'pass'); return row; };
// mulberry32: exact 32-bit integer steps.
const rng = seed => { let state = seed; return n => { state = (state + 0x6d2b79f5) | 0; let t = Math.imul(state ^ (state >>> 15), 1 | state); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return (((t ^ (t >>> 14)) >>> 0) % n); }; };

// ---------------------------------------------------------------------------
// 1. Without the declaration every finding is today's. The digest below was computed by running undeclaredTrials (verbatim)
// against a build from before the judge existed: a change that moves it changes undeclared settlement and needs its own review.
// Moved once, ab9ed59c -> ba23fa95, by the JSON decimal fail-open fix: a positive clause resting on another
// check's token reads effect-correlated-elsewhere before any other correlated or selector finding, since it is the one reason that
// also withholds a control's pass. Over these trials, against the build before that fix: 0 of the uncorrelated findings change, and 91 of 5,223
// findings in the run and per-check modes move, every one from another withholding reason to effect-correlated-elsewhere on an
// effect.exists or effect.count of at least one (71 boundary, only the reason's name; 20 control, a tagged pass now withheld).
const UNDECLARED_DIGEST = 'ba23fa95f03a163242035e474cb2608bc0d5726a444a8f98de1cbf6a0ef9883f';
// BEGIN UNDECLARED TRIALS
function undeclaredTrials({ settlementFindings: findings, decideEffects: decide, makeEffect: make, digest: hash }, { options } = {}) {
  const rand = rng(20261011), pick = list => list[rand(list.length)];
  let n = 0;
  const host = 'hooks.judge.example', inst = 'egress-recorder-hooks', other = 'egress-recorder-other';
  const sink = { operations: ['send'], names: [host], actorAttribution: 'none', evidence: 'authoritative' }, presence = { ...sink, evidence: 'presence-only' };
  const res = ['POST /hooks/a', 'POST /hooks/b', 'POST /hooks/c'];
  const tok = [undefined, '01'.repeat(16), '02'.repeat(16), '03'.repeat(16), 'ab'.repeat(16), 'cd'.repeat(16)];
  const sel = r => ({ source: 'http-egress', operation: 'send', name: host, ...(r ? { resource: r } : {}) });
  const ev = instanceId => make({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++n, observedAt: '2026-10-11T00:00:00.000Z', operation: 'send', name: host, resource: pick(res), outcome: 'committed', correlation: (t => t ? { settlementToken: t } : {})(pick(tok)) });
  const clauses = [
    () => ({ kind: 'effect.none', select: sel(pick(res)) }), () => ({ kind: 'effect.none', select: sel() }),
    () => ({ kind: 'effect.exists', select: sel(pick(res)) }), () => ({ kind: 'effect.exists', select: sel() }),
    () => ({ kind: 'effect.count', select: sel(pick(res)), expected: 1 + rand(2) }), () => ({ kind: 'effect.count', select: sel(), expected: rand(2) }),
    () => ({ kind: 'effect.only', expect: [{ select: sel(pick(res)), count: 1 + rand(3) }], allow: [], sources: ['http-egress'] }),
    () => ({ kind: 'effect.only', expect: [{ select: sel(pick(res)), count: 1 + rand(3) }], allow: [sel(pick(res))], sources: ['http-egress'] }),
    () => ({ kind: 'effect.only', allow: [sel(pick(res)), sel(pick(res))], sources: ['http-egress'] }),
  ];
  const window = (instanceId, scope) => { const coverage = pick(['complete', 'complete', 'complete', 'partial']); return { source: 'http-egress', instanceId, scope, coverage, reason: coverage === 'complete' ? null : 'synthetic', events: Array.from({ length: rand(3) }, () => ev(instanceId)) }; };
  const tokens = new Map([['01'.repeat(16), 0], ['02'.repeat(16), 1], ['03'.repeat(16), 2], ['ab'.repeat(16), null]]), declared = new Set([`${inst}\n${host}`]);
  const out = [];
  for (let trial = 0; trial < 600; trial++) {
    const size = 1 + rand(3), extra = rand(3) === 0;
    const windows = () => [window(inst, sink), ...(extra ? [window(other, rand(2) ? presence : sink)] : [])];
    const specs = Array.from({ length: size }, () => Array.from({ length: 1 + rand(2) }, () => pick(clauses)())), roles = specs.map(() => (rand(4) === 0 ? 'control' : 'boundary'));
    const gaps = [], rows = [], barriers = [];
    for (let k = 0; k < size; k++) { gaps.push(windows()); const own = windows(); rows.push({ effects: decide(specs[k], own, { role: roles[k] }), windows: own }); barriers.push(windows()); }
    gaps.push(windows());
    const args = options === undefined ? [] : [options];
    out.push([findings(rows, gaps, undefined, ...args), findings(rows, gaps, { mode: 'run', tokens, declared }, ...args), findings(rows, gaps, { mode: 'per-check', barriers, tokens, declared }, ...args)]);
  }
  return hash(out);
}
// END UNDECLARED TRIALS
test('1. undeclared: 600 generated runs settle exactly as before the judge (run level, run mode and per check); declaring it changes some', () => {
  const deps = { settlementFindings, decideEffects, makeEffect, digest };
  assert.equal(undeclaredTrials(deps), UNDECLARED_DIGEST);
  assert.equal(undeclaredTrials(deps, { options: {} }), UNDECLARED_DIGEST, 'an empty options object');
  assert.equal(undeclaredTrials(deps, { options: { judge: false } }), UNDECLARED_DIGEST, 'judge: false');
  assert.notEqual(undeclaredTrials(deps, { options: { judge: true } }), UNDECLARED_DIGEST, 'the generator reaches clauses the judge changes');
  assert.throws(() => settlementFindings([], [[win()]], null, { judge: 'yes' }), /settlement-judge/);
});

// ---------------------------------------------------------------------------
// A generator of judged scenarios, windows made in run order (gap k, row k's own window, barrier k, ..., the tail), so a later
// window's events carry higher seq. at(n): the n-th event's observedAt.
const RES = [A, B, C];
function scenarios(trials, seed, { at = () => '2026-10-11T00:00:00.000Z' } = {}) {
  const rand = rng(seed), pick = list => list[rand(list.length)];
  let n = 0;
  const tok = [undefined, T(0), T(1), T(2), OTHER, STRANGER];
  const make = instanceId => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++n, observedAt: at(n), operation: 'send', name: HOST, resource: pick(RES), outcome: 'committed', correlation: (t => t ? { settlementToken: t } : {})(pick(tok)) });
  const clauses = [
    () => none(pick(RES)), () => none(), () => exists(), () => exists(pick(RES)), () => count(pick(RES), 1 + rand(2)), () => count(null, 1),
    () => only({ expect: [[pick(RES), 1 + rand(3)]], allow: [pick(RES)] }), () => only({ expect: [[pick(RES), 2]], allow: [] }), () => only({ expect: [], allow: [pick(RES), pick(RES)] }),
  ];
  const window = (instanceId, scope) => { const coverage = pick(['complete', 'complete', 'complete', 'complete', 'partial']); return { source: 'http-egress', instanceId, scope, coverage, reason: coverage === 'complete' ? null : 'synthetic', events: Array.from({ length: rand(3) }, () => make(instanceId)) }; };
  const out = [];
  for (let trial = 0; trial < trials; trial++) {
    const size = 1 + rand(3), extra = rand(3) === 0, scope = rand(2) ? PRESENCE : SINK;
    const windows = () => [window(INST, SINK), ...(extra ? [window(OTHER_INST, scope)] : [])];
    const specs = Array.from({ length: size }, () => Array.from({ length: 1 + rand(2) }, () => pick(clauses)())), roles = specs.map(() => (rand(4) === 0 ? 'control' : 'boundary'));
    const gaps = [], rows = [], barriers = [];
    for (let k = 0; k < size; k++) { gaps.push(windows()); const own = windows(); rows.push(rowOf(specs[k], own, roles[k])); barriers.push(windows()); }
    gaps.push(windows());
    out.push({ rows, gaps, barriers });
  }
  return out;
}
const modes = ({ rows, gaps, barriers }) => [['run level', null], ['run mode', runMode], ['run mode, both declared', { ...runMode, declared: new Set([...declared, `${OTHER_INST}\n${HOST}`]) }], ['per check', perCheck(rows, barriers)]].map(([label, correlation]) => ({ label, correlation, gaps }));

// 2 and 3. The declaration changes effect.only only: effect.none, effect.count and effect.exists read exactly as without it.
test('2-3. differential: with the declaration every effect.none, effect.count and effect.exists finding is unchanged, in every mode', () => {
  let compared = 0, changedOnly = 0;
  for (const s of scenarios(400, 7)) for (const { label, correlation, gaps } of modes(s)) {
    const off = plain(s.rows, gaps, correlation), on = judged(s.rows, gaps, correlation);
    off.forEach((row, k) => row.forEach((reason, c) => {
      const d = s.rows[k].effects[c];
      if (d.kind !== 'effect.only') { assert.equal(on[k][c], reason, `${label}: ${d.kind}`); if (reason !== null) compared++; return; }
      if (on[k][c] !== reason) changedOnly++;
    }));
  }
  assert.ok(compared > 500 && changedOnly > 20, `not vacuous: ${compared} withheld core clauses compared, ${changedOnly} effect.only findings changed`);
});

test('2. effect.none stays withheld under the declaration: a decided, a null-actor, a blind, an unknown-field or an unproven later send, and an exact keyed replay', () => {
  const k = () => rowOf([none(A)], [win()]);
  assert.deepEqual(judged([k()], inTail([0], [win([ev(A)])])), [['effect-outside-window']], 'decided');
  const principal = { ...SINK, actorAttribution: 'principal' };
  const pinned = { kind: 'effect.none', select: { ...sel(A), actor: 'svc' } }, anon = rowOf([pinned], [win([], 'complete', { scope: principal })]);
  assert.equal(anon.effects[0].verdict, 'pass');
  assert.deepEqual(judged([anon], inTail([0], [win([ev(A, { actor: null })], 'complete', { scope: principal })])), [['effect-outside-window']], 'a null actor fits an actor pin');
  // Declared body fields: a later send whose fields could not be read fits; a later window that does not capture them is blind.
  const capture = { ...SINK, capture: { [HOST]: ['/amount'] } };
  const fieldNone = { kind: 'effect.none', select: { ...sel(A), fields: [{ pointer: '/amount', gt: 100 }] } };
  const fieldRow = rowOf([fieldNone], [win([], 'complete', { scope: capture })], 'control');
  assert.equal(fieldRow.effects[0].verdict, 'pass');
  assert.deepEqual(judged([fieldRow], inTail([0], [win([ev(A, { captured: { status: 'not-json', values: {} } })], 'complete', { scope: capture })])), [['effect-outside-window']], 'unknown field');
  assert.deepEqual(judged([fieldRow], inTail([0], [win([ev(A)])])), [['effect-outside-window']], 'a blind later window: the base selector fits');
  // An upstream requirement the later send cannot show (unproven, unknown outcome) still fits.
  const forward = { [HOST]: { rejected: [] } }, fwdScope = { ...SINK, forward };
  const upNone = { kind: 'effect.none', select: { ...sel(A), upstream: 'applied' } };
  const upRow = rowOf([upNone], [win([], 'complete', { scope: fwdScope })], 'control');
  assert.equal(upRow.effects[0].verdict, 'pass');
  assert.deepEqual(judged([upRow], inTail([0], [win([ev(A, { upstream: { outcome: 'unknown', status: null, proven: false } })], 'complete', { scope: fwdScope })])), [['effect-outside-window']], 'unproven');
  // An exact keyed replay of an earlier send (same key, content and head): dedup never satisfies an absence.
  const decl = validateIdempotencyDeclaration({ header: 'idempotency-key' }), keyed = { ...SINK, idempotency: { [HOST]: decl } };
  const first = ev(A, { content: { c: 1 }, idempotency: { status: 'keyed', key: 'a'.repeat(64), fold: 'a'.repeat(64), head: 'b'.repeat(64), firstSeq: seq + 1 } });
  const replayRow = rowOf([none(A)], [win([], 'complete', { scope: keyed })]);
  const replay = ev(A, { content: { c: 1 }, idempotency: { status: 'keyed', key: 'a'.repeat(64), fold: 'a'.repeat(64), head: 'b'.repeat(64), firstSeq: first.seq } });
  assert.deepEqual(judged([replayRow], [[win([first], 'complete', { scope: keyed })], [win([replay], 'complete', { scope: keyed })]]), [['effect-outside-window']], 'exact keyed replay');
  // A claim rule's refusal clause is an effect.none: settled the same way (the judge never sees claims).
  assert.deepEqual(judged([k()], inTail([0], [win([ev(A)])]), runMode), [['effect-outside-window']]);
});

test('3. send-unit counts, keyed counts (part 2 is not built) and effect.exists are unchanged by the declaration', () => {
  const counted = () => rowOf([count(B, 1)], [win([ev(B)])]);
  assert.deepEqual(judged([counted()], inTail([0], [win([ev(B)])])), [['effect-outside-window']], 'any later fitting send changes a send count');
  assert.deepEqual(judged([rowOf([count(B, 0)], [win()])], inTail([0], [win([ev(B)])])), [['effect-outside-window']], 'expected 0');
  // A keyed count whose own first use is replayed exactly after its window: still withheld (a late countBy release is part 2).
  const decl = validateIdempotencyDeclaration({ header: 'idempotency-key' }), keyed = { ...SINK, idempotency: { [HOST]: decl } };
  const key = { status: 'keyed', key: 'c'.repeat(64), fold: 'c'.repeat(64), head: 'd'.repeat(64) };
  const firstUse = ev(B, { content: { c: 2 }, idempotency: { ...key, firstSeq: seq + 1 } });
  const keyedCount = { kind: 'effect.count', select: sel(B), expected: 1, countBy: 'idempotency-key' };
  const keyedRow = rowOf([keyedCount], [win([firstUse], 'complete', { scope: keyed })], 'control');
  assert.equal(keyedRow.effects[0].verdict, 'pass');
  const replay = ev(B, { content: { c: 2 }, idempotency: { ...key, firstSeq: firstUse.seq } });
  assert.deepEqual(judged([keyedRow], inTail([0], [win([replay], 'complete', { scope: keyed })])), [['effect-outside-window']], 'keyed count, exact own replay late');
  // effect.exists has no late-candidate rule, and its ambiguity reads as before.
  const before = rowOf([none(A)], [win()]);
  const ex = [before, rowOf([exists()], [win([ev(A)])])];
  assert.deepEqual(judged(ex, gapsFor(ex)), plain(ex, gapsFor(ex)));
  assert.deepEqual(judged(ex, gapsFor(ex)).at(-1), ['effect-ambiguous-attribution']);
  assert.deepEqual(judged([rowOf([exists(A)], [win([ev(A)])])], inTail([0], [win([ev(A), ev(C)])])), [[null]], 'a later send never unsettles a presence');
});

// ---------------------------------------------------------------------------
test('4. an allowed late effect.only send stands with the note; the same run without the declaration withholds it', () => {
  for (const [where, place] of [['tail', r => inTail(r, [win([ev(B)])])], ['gap after it', r => [[win()], [win([ev(B)])], [win()]]]]) {
    const rows = where === 'tail' ? [passing()] : [passing(), rowOf([none(C)], [win()])];
    const gaps = place(rows);
    assert.equal(plain(rows, gaps)[0][0], 'effect-outside-window', `${where}: the withholding rule without the declaration`);
    assert.equal(judged(rows, gaps)[0][0], NOTE, where);
  }
  // In the next check's own window, and in a barrier (per check).
  const next = [passing()]; next.push(rowOf([none(C)], [win([ev(B)])]));
  assert.deepEqual(judged(next, gapsFor(next)), [[NOTE], [null]]);
  const barred = [passing()];
  assert.deepEqual(judged(barred, gapsFor(barred), perCheck(barred, [[win([ev(B)])]])), [[NOTE]]);
  assert.deepEqual(plain(barred, gapsFor(barred), perCheck(barred, [[win([ev(B)])]])), [['effect-outside-window']]);
  // Allowed in any number, and an expected item still within its count.
  assert.deepEqual(judged([passing()], inTail([0], [win([ev(B), ev(B), ev(B)])])), [[NOTE]]);
  const two = passing(only({ expect: [[A, 2]] }));
  assert.deepEqual(judged([two], inTail([0], [win([ev(A)])])), [[NOTE]]);
  // Nothing later: no note. The note only follows a candidate the rule would have withheld on.
  assert.deepEqual(judged([passing()], gapsFor([0])), [[null]]);
  // The note keeps the verdict and appends its basis; it is not a withholding reason.
  const applied = applySettlement(passing().effects, [NOTE], 'boundary')[0];
  assert.deepEqual([applied.verdict, applied.settlementNote, Object.hasOwn(applied, 'settlement')], ['pass', NOTE, false]);
  assert.ok(applied.basis.endsWith(SETTLEMENT_NOTE_BASIS[NOTE]));
  assert.deepEqual(SETTLEMENT_NOTES, [NOTE]);
  assert.ok(!SETTLEMENT_REASONS.includes(NOTE));
  assert.ok(!DASHES.test(SETTLEMENT_NOTE_BASIS[NOTE]));
  // Only an effect.only pass can carry it: handed to another clause it is refused.
  assert.throws(() => applySettlement(rowOf([none(A)], [win()]).effects, [NOTE], 'boundary'), /settlement-reason/);
});

test('5. an expected item already at its count plus a late match is withheld, also when an allow selector matches it too', () => {
  assert.deepEqual(judged([passing(only({ expect: [[A, 1]], allow: [B] }))], inTail([0], [win([ev(A)])])), [['effect-outside-window']]);
  assert.deepEqual(judged([passing(only({ expect: [[A, 1]], allow: [A] }))], inTail([0], [win([ev(A)])])), [['effect-outside-window']], 'a match beyond its count is collateral even if allowed');
  assert.deepEqual(judged([passing(only({ expect: [[A, 1]], allow: [null] }))], inTail([0], [win([ev(A)])])), [['effect-outside-window']], 'a host-wide allow does not absorb it either');
  // Adjacent allowed: under the count it stands; an unexpected late send is withheld.
  assert.deepEqual(judged([passing(only({ expect: [[A, 2]], allow: [B] }))], inTail([0], [win([ev(A)])])), [[NOTE]]);
  assert.deepEqual(judged([passing(only({ expect: [[A, 2]], allow: [B] }))], inTail([0], [win([ev(A), ev(A)])])), [['effect-outside-window']], 'two late matches pass the count of 2');
  assert.deepEqual(judged([passing()], inTail([0], [win([ev(C)])])), [['effect-outside-window']], 'outside the declared set');
});

test('6. an undecided candidate (unreadable fields, an unknown actor under an actor pin) or a presence-only one is withheld', () => {
  const capture = { ...SINK, capture: { [HOST]: ['/amount'] } };
  const cwin = (events, coverage = 'complete') => win(events, coverage, { scope: capture });
  const amountAllow = { ...sel(B), fields: [{ pointer: '/amount', equals: 5 }] };
  const row = () => { const r = rowOf([only({ allow: [amountAllow] })], [cwin([ev(A, { captured: { status: 'captured', values: { '/amount': { type: 'number', value: 1 } } } })])]); assert.equal(r.effects[0].verdict, 'pass'); return r; };
  const amount = value => ({ status: 'captured', values: { '/amount': { type: 'number', value } } });
  assert.deepEqual(judged([row()], inTail([0], [cwin([ev(B, { captured: { status: 'not-json', values: {} } })])])), [['effect-outside-window']], 'unreadable fields: undecided');
  assert.deepEqual(judged([row()], inTail([0], [cwin([ev(B, { captured: amount(7) })])])), [['effect-outside-window']], 'decided outside the allow');
  assert.deepEqual(judged([row()], inTail([0], [cwin([ev(B, { captured: amount(5) })])])), [[NOTE]], 'adjacent: decided inside it');
  // An unknown actor against an actor pin cannot be shown to be the allowed one.
  const pinnedAllow = { ...sel(B), actor: 'svc' };
  const pinned = () => passing(only({ allow: [pinnedAllow] }));
  assert.deepEqual(judged([pinned()], inTail([0], [win([ev(B, { actor: null })])])), [['effect-outside-window']], 'unknown actor');
  assert.deepEqual(judged([pinned()], inTail([0], [win([ev(B, { actor: 'unlisted:x' })])])), [['effect-outside-window']], 'undeclared actor');
  assert.deepEqual(judged([pinned()], inTail([0], [win([ev(B, { actor: 'svc' })])])), [[NOTE]], 'adjacent: the pinned actor');
  // A presence-only observer the clause reads (a self-report) only tightens: an allowed late send it alone recorded withholds.
  const both = () => { const r = rowOf([only({ allow: [B] })], [win([ev(A)]), presenceWin()]); assert.equal(r.effects[0].verdict, 'pass'); return r; };
  assert.deepEqual(judged([both()], inTail([0], [win(), presenceWin([ev(B, { instanceId: OTHER_INST })])])), [['effect-outside-window']], 'presence-only candidate');
  assert.deepEqual(judged([both()], inTail([0], [win([ev(B)]), presenceWin()])), [[NOTE]], 'adjacent: the authoritative recorder');
});

// ---------------------------------------------------------------------------
// 7. Downward closure: whenever the clause stands with every candidate counted, it stands with any subset of them.
test('7. property: a judged pass over all the late candidates is a judged pass over every subset of them (non-vacuous)', () => {
  const rand = rng(424242), pick = list => list[rand(list.length)];
  let full = 0, withheld = 0, subsetsChecked = 0;
  for (let trial = 0; trial < 500; trial++) {
    const expect = Array.from({ length: 1 + rand(2) }, () => [pick(RES), 1 + rand(3)]), allow = Array.from({ length: rand(3) }, () => pick([...RES, null]));
    const spec = only({ expect, allow });
    const second = rand(3) === 0;
    const ownWindows = [win(Array.from({ length: rand(3) }, () => ev(pick(RES)))), ...(second ? [{ ...win(Array.from({ length: rand(2) }, () => ev(pick(RES), { instanceId: OTHER_INST }))), instanceId: OTHER_INST }] : [])];
    const row = rowOf([spec], ownWindows);
    if (row.effects[0].verdict !== 'pass') continue;
    const late = Array.from({ length: 1 + rand(5) }, () => (second && rand(2) ? { e: ev(pick(RES), { instanceId: OTHER_INST }), other: true } : { e: ev(pick(RES)), other: false }));
    const tailOf = list => [[win()], [win(list.filter(x => !x.other).map(x => x.e)), ...(second ? [{ ...win(list.filter(x => x.other).map(x => x.e)), instanceId: OTHER_INST }] : [])]];
    const all = judged([row], tailOf(late))[0][0];
    assert.ok(all === NOTE || all === 'effect-outside-window', all);
    if (all !== NOTE) { withheld++; continue; }
    full++;
    for (let mask = 0; mask < 2 ** late.length; mask++) {
      const subset = late.filter((_, i) => mask & (1 << i));
      assert.equal(judged([row], tailOf(subset))[0][0], subset.length ? NOTE : null, `trial ${trial}, subset ${mask}`);
      // The same at the judge itself: own windows plus the subset, appended in seq order.
      const augmented = ownWindows.map(w => ({ ...w, events: [...w.events, ...subset.filter(x => (w.instanceId === OTHER_INST) === x.other).map(x => x.e)] }));
      assert.equal(judgeOnly(spec, augmented, { fields: true }).verdict, 'pass');
      subsetsChecked++;
    }
  }
  assert.ok(full >= 40 && withheld >= 40 && subsetsChecked >= 200, `not vacuous: ${full} judged passes, ${withheld} withheld, ${subsetsChecked} subsets`);
});

test('8. caps, duplicates and out-of-order seq withhold: over 512 expected-selector combinations, over the window event cap, a repeated seq, a seq not after the own window', () => {
  // 512 distinct combinations of ten expected selectors in the own window; a late send with a 513th reads missing.
  const pointers = Array.from({ length: 10 }, (_, i) => `/f${i}`), capture = { ...SINK, capture: { [HOST]: pointers } };
  const combo = mask => ({ status: 'captured', values: Object.fromEntries(pointers.map((p, i) => [p, { type: 'number', value: (mask >> i) & 1 }])) });
  const spec = { kind: 'effect.only', expect: pointers.map(p => ({ select: { ...sel(), fields: [{ pointer: p, equals: 1 }] }, count: 600 })), allow: [], sources: ['http-egress'] };
  const own = Array.from({ length: 512 }, (_, i) => ev(A, { captured: combo(i + 1) }));
  const groups = rowOf([spec], [win(own, 'complete', { scope: capture })]);
  assert.equal(groups.effects[0].verdict, 'pass');
  assert.deepEqual(judged([groups], inTail([0], [win([ev(A, { captured: combo(513) })], 'complete', { scope: capture })])), [['effect-outside-window']], 'a 513th combination');
  assert.deepEqual(judged([groups], inTail([0], [win([ev(A, { captured: combo(1) })], 'complete', { scope: capture })])), [[NOTE]], 'adjacent: a combination already seen');
  // The window event cap: an own window already at the cap plus one allowed late send cannot form a window (only.mjs throws).
  const cap = EFFECT_LIMITS.eventsPerWindow;
  const full = rowOf([only({ expect: [], allow: [B] })], [win(Array.from({ length: cap }, () => ev(B)))]);
  assert.equal(full.effects[0].verdict, 'pass');
  assert.deepEqual(judged([full], inTail([0], [win([ev(B)])])), [['effect-outside-window']], 'over the event cap');
  const room = rowOf([only({ expect: [], allow: [B] })], [win(Array.from({ length: cap - 1 }, () => ev(B)))]);
  assert.deepEqual(judged([room], inTail([0], [win([ev(B)])])), [[NOTE]], 'adjacent: exactly at the cap');
  // Two different effects with one seq (no recorder writes that), and a seq not after the own window's events.
  const dup = () => { const row = passing(), x = ev(B), twin = { ...x, resource: B }; return { row, x, twin }; };
  { const { row, x, twin } = dup(); assert.deepEqual(judged([row], [[win()], [win([x])]]), [[NOTE]], 'one of them alone stands');
    assert.deepEqual(judged([row, rowOf([none(C)], [win([twin])])], [[win()], [win([x])], [win()]])[0], ['effect-outside-window'], 'a repeated seq'); }
  { const { row, x } = dup(); assert.deepEqual(judged([row, rowOf([none(C)], [win([x])])], [[win()], [win()], [win([x])]])[0], [NOTE], 'adjacent: the same event reached twice counts once'); }
  const stale = ev(B), recent = passing();
  assert.deepEqual(judged([recent], inTail([0], [win([stale])])), [['effect-outside-window']], 'a seq before the own window');
  const same = passing(), clash = { ...same.windows[0].events[0], resource: B };
  assert.deepEqual(judged([same], inTail([0], [win([clash])])), [['effect-outside-window']], 'a seq equal to an own event');
  // Filed under another observer id in the instance's window, which only.mjs's per-observer order rule does not compare: the
  // judge's own order rule still refuses a seq before the own window, and two effects sharing one seq.
  const elsewhere = e => ({ ...e, observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-elsewhere' } });
  const early = elsewhere(ev(B)), afterIt = passing();
  assert.deepEqual(judged([afterIt], inTail([0], [win([early])])), [['effect-outside-window']], 'a seq before the own window, another observer id');
  const shared = passing(), d1 = ev(B), d2 = elsewhere({ ...d1 });
  assert.deepEqual(judged([shared, rowOf([none(C)], [win([d2])])], [[win()], [win([d1])], [win()]])[0], ['effect-outside-window'], 'one seq, two observer ids');
});

test('14. a candidate from a foreign instance or a drifted scope is withheld', () => {
  // The same instance id under another source is another instance (only.mjs instanceOf), so it has no own window here.
  const row = passing();
  const foreign = { source: 'smtp-capture', instanceId: INST, scope: { ...SINK }, coverage: 'complete', reason: null, events: [makeEffect({ source: 'smtp-capture', observer: { kind: 'smtp-sink-recorder', instanceId: INST }, seq: ++seq, operation: 'send', name: HOST, resource: B, outcome: 'committed' })] };
  assert.deepEqual(judged([row], inTail([0], [foreign])), [['effect-outside-window']], 'another source under the same id');
  // A malformed later window (another source, holding this source's sends: no bound window carries that) is not merged either.
  const relabelled = passing(), mislabel = { ...win([ev(B)]), source: 'smtp-capture' };
  assert.deepEqual(judged([relabelled], inTail([0], [mislabel])), [['effect-outside-window']], 'a window labelled with another source');
  // A later window of the instance whose scope drifted (another vocabulary): the candidate cannot be placed in the own window.
  const drifted = passing();
  const drift = { ...win([ev(B)]), scope: { ...SINK, names: [HOST, 'other.example'] } };
  assert.deepEqual(judged([drifted], inTail([0], [drift])), [['effect-outside-window']], 'scope drift');
  // A window with no instance id names no instance: it is never merged into one.
  const anonymous = w => { const { instanceId: _i, ...rest } = w; return rest; };
  const nameless = rowOf([only({ allow: [B] })], [anonymous(win([ev(A)]))]);
  assert.equal(nameless.effects[0].verdict, 'pass');
  assert.deepEqual(judged([nameless], inTail([0], [anonymous(win([ev(B)]))])), [['effect-outside-window']], 'no instance id');
  // Adjacent allowed: the same send from the own instance, same source and scope.
  assert.deepEqual(judged([passing()], inTail([0], [win([ev(B)])])), [[NOTE]]);
});

test('15. a later partial or failed window still gives settlement-unobserved after the judge', () => {
  for (const coverage of ['partial', 'failed']) {
    assert.deepEqual(judged([passing()], inTail([0], [win([ev(B)], coverage)])), [['settlement-unobserved']], `the candidate's own window ${coverage}`);
    const rows = [passing(), rowOf([none(C)], [win([], coverage)])];
    assert.deepEqual(judged(rows, [[win()], [win([ev(B)])], [win()]])[0], ['settlement-unobserved'], `a later check's window ${coverage}`);
    const barred = [passing()];
    assert.deepEqual(judged(barred, inTail([0], [win([ev(B)])]), perCheck(barred, [[win([], coverage)]])), [['settlement-unobserved']], `a barrier ${coverage}`);
  }
  // Adjacent: the same allowed send with every later window complete.
  assert.deepEqual(judged([passing()], inTail([0], [win([ev(B)])])), [[NOTE]]);
});

test('16. correlated precedence: an allowed own-token late send gives the note, an unexpected one effect-correlated-late; elsewhere is still read', () => {
  const own = () => passing(only({ allow: [B] }), () => [ev(A, { token: T(0) })]);
  for (const [label, corr] of [['run mode', () => runMode], ['per check', r => perCheck(r)]]) {
    const r = [own()];
    assert.deepEqual(judged(r, inTail(r, [win([ev(B, { token: T(0) })])]), corr(r)), [[NOTE]], `${label}: allowed, own token`);
    assert.deepEqual(plain(r, inTail(r, [win([ev(B, { token: T(0) })])]), corr(r)), [['effect-correlated-late-unsettled']], `${label}: without the declaration`);
    const u = [own()];
    assert.deepEqual(judged(u, inTail(u, [win([ev(C, { token: T(0) })])]), corr(u)), [['effect-correlated-late']], `${label}: unexpected, own token`);
    const b = [own()];
    assert.deepEqual(judged(b, inTail(b, [win([ev(A, { token: T(0) })])]), corr(b)), [['effect-correlated-late-unsettled']], `${label}: beyond its count, own token`);
    const n = [own()];
    assert.deepEqual(judged(n, inTail(n, [win([ev(B, { token: T(1) })])]), corr(n)), [[NOTE]], `${label}: allowed, another row's token`);
    // The judgement stood but a later window is partial: the own-token reason still withholds, never the note.
    const p = [own()];
    assert.ok(withholds(judged(p, inTail(p, [win([ev(B, { token: T(0) })], 'partial')]), corr(p))[0][0]), `${label}: partial`);
  }
  // In a barrier, per check.
  const r = [own()];
  assert.deepEqual(judged(r, gapsFor(r), perCheck(r, [[win([ev(B, { token: T(0) })])]])), [[NOTE]]);
  // Elsewhere is read as before beside a judged clause: an exists whose only match carries another row's token.
  const rows = [rowOf([only({ allow: [B] }), exists(A)], [win([ev(A, { token: OTHER })])])];
  assert.deepEqual(judged(rows, inTail(rows, [win([ev(B)])]), runMode), [[NOTE, 'effect-correlated-elsewhere']]);
});

// 17. The correlated-settlement property, extended: correlation never makes the judge more permissive than the run-level judge, the judge never
// makes settlement more permissive than without it except on effect.only, and nothing is ever failed.
test('17. property: correlated judged settlement withholds whatever run-level judged settlement withholds, and the note needs a candidate', () => {
  const seen = new Map(), mark = key => seen.set(key, (seen.get(key) ?? 0) + 1);
  for (const s of scenarios(600, 20261010)) {
    const runLevel = judged(s.rows, s.gaps), runLevelOff = plain(s.rows, s.gaps);
    for (const { label, correlation, gaps } of modes(s)) {
      const on = judged(s.rows, gaps, correlation), off = plain(s.rows, gaps, correlation);
      on.forEach((row, k) => row.forEach((reason, c) => {
        const d = s.rows[k].effects[c], L = runLevel[k][c];
        if (d.verdict === 'pass') mark(`${label}: ${off[k][c]} -> ${reason}`);
        if (withholds(L)) assert.ok(withholds(reason), `${label}: run level withholds (${L}), got ${reason}`);
        if (L === NOTE) assert.notEqual(reason, null, `${label}: the run-level note means a candidate exists`);
        if (reason === NOTE) assert.equal(d.kind, 'effect.only');
        // The judge only relaxes: it never withholds what is not withheld without it, and it changes effect.only only.
        if (off[k][c] === null) assert.equal(reason, null, `${label}: nothing to relax`);
        if (reason !== off[k][c]) assert.ok(d.kind === 'effect.only' && withholds(off[k][c]) && (reason === NOTE || withholds(reason)), `${label}: ${off[k][c]} -> ${reason}`);
        if (reason !== null) assert.notEqual(applySettlement(s.rows[k].effects, row, 'boundary')[c].verdict, 'fail');
      }));
    }
    runLevelOff.forEach((row, k) => row.forEach((reason, c) => { if (reason === null) assert.equal(runLevel[k][c], null); }));
  }
  const reached = [...seen.keys()].join('\n');
  for (const line of ['run level: effect-outside-window -> effect-outside-window-judged', 'per check: effect-outside-window -> effect-outside-window-judged', 'per check: effect-correlated-late-unsettled -> effect-outside-window-judged',
    'run mode: effect-correlated-late-unsettled -> effect-outside-window-judged', 'per check: effect-correlated-late -> effect-correlated-late', 'per check: effect-outside-window -> effect-outside-window', 'per check: null -> null']) assert.match(reached, new RegExp(`^${line}$`, 'm'), line);
});

test('18. observedAt is never read: shuffled timestamps give identical judged findings; the settlement source reads no time, horizon or wait', async () => {
  const fixed = scenarios(200, 99), times = rng(5);
  const shuffled = scenarios(200, 99, { at: () => new Date(Date.UTC(2001 + times(40), times(12), 1 + times(28), times(24), times(60))).toISOString() });
  let notes = 0, moved = 0;
  const stamps = s => [...s.gaps.flat(), ...s.rows.flatMap(r => r.windows), ...s.barriers.flat()].flatMap(w => w.events.map(e => e.observedAt));
  fixed.forEach((s, i) => {
    const t = shuffled[i];
    moved += stamps(s).filter((at, j) => at !== stamps(t)[j]).length;
    for (const [{ correlation, gaps }, { correlation: c2, gaps: g2 }] of modes(s).map((m, j) => [m, modes(t)[j]])) {
      const a = judged(s.rows, gaps, correlation), b = judged(t.rows, g2, c2);
      assert.deepEqual(a, b);
      notes += a.flat().filter(r => r === NOTE).length;
    }
  });
  assert.ok(notes > 20 && moved > 500, `not vacuous: ${notes} notes, ${moved} timestamps moved`);
  // The settlement module's code (comments aside) reads no observedAt, waitedMs, effectHorizonMs or horizon.
  const code = (await readFile(new URL('../src/http-settlement.mjs', import.meta.url), 'utf8')).split('\n').filter(l => !/^\s*\/\//.test(l)).join('\n');
  assert.doesNotMatch(code, /observedAt|waitedMs|effectHorizonMs|horizon/i);
});

test('19. background attribution still withholds: attribution runs on the settled clauses and never skips one that carries the note', () => {
  // A background-possible send (actor svc-sync) that could be the effect.none clause's own: background-unattributed, with or
  // without a note handed to the clause.
  const background = [{ id: 'sync', select: { actor: 'svc-sync', operation: 'send', name: HOST } }];
  const pinned = { kind: 'effect.none', select: { ...sel(A), actor: 'member-1' } };
  const audit = { ...SINK, actorAttribution: 'principal' };
  const row = rowOf([pinned, only({ allow: [B] })], [win([ev(A, { actor: 'svc-sync' })], 'complete', { scope: audit })]);
  assert.deepEqual(row.effects.map(d => d.verdict), ['pass', 'pass']);
  const noted = { ...row, effects: row.effects.map(d => ({ ...d, settlementNote: NOTE })) };
  const gaps = [[win([], 'complete', { scope: audit })], [win([], 'complete', { scope: audit })]];
  for (const r of [row, noted]) assert.deepEqual(attributionFindings([r], gaps, undefined, { background }), [['background-unattributed', null]]);
  // An effect.only fail resting on a background send still reads background-unattributed under the declaration (the judge
  // never touches a fail).
  const failing = rowOf([only({ allow: [] })], [win([ev(A), ev(C, { actor: 'svc-sync' })], 'complete', { scope: audit })]);
  assert.equal(failing.effects[0].verdict, 'fail');
  assert.deepEqual(judged([failing], gaps), [[null]]);
  assert.deepEqual(attributionFindings([failing], gaps, undefined, { background }), [['background-unattributed']]);
});

test('20. a returned-id closure never excuses a candidate: a late send the check\'s own minted id ties to it is judged like any other', () => {
  const D = 'e'.repeat(64);
  const seed = ev(A, { upstream: { outcome: 'applied', status: 201, proven: true, minted: [D] } });
  const row = passing(only({ allow: [B] }), () => [seed]);
  const owned = ev(C, { upstream: { outcome: 'applied', status: 201, proven: true, references: [D] } });
  const gaps = inTail([0], [win([owned])]);
  // Non-vacuous: closure ownership would attribute the late send to row 0.
  assert.equal(closureOwners([row], gaps, undefined, () => true)(owned), 0);
  assert.deepEqual(judged([row], gaps), [['effect-outside-window']], 'outside the declared set, whoever owns it');
  // Adjacent: an allowed late send stands whatever it refers to, an object of this check's or another's.
  for (const minted of [D, 'f'.repeat(64)]) {
    const other = passing(only({ allow: [B] }), () => [ev(A, { upstream: { outcome: 'applied', status: 201, proven: true, minted: [minted] } })]);
    const refers = ev(B, { upstream: { outcome: 'applied', status: 201, proven: true, references: [D] } });
    assert.deepEqual(judged([other], inTail([0], [win([refers])])), [[NOTE]], minted);
  }
});

test('21. a control gets the note instead of the tag and keeps its verdict; a boundary keeps its pass with the note', () => {
  const control = passing(only({ allow: [B] }), () => [ev(A)], 'control');
  const gaps = inTail([0], [win([ev(B)])]);
  assert.deepEqual(plain([control], gaps), [['effect-outside-window']]);
  assert.deepEqual(judged([control], gaps), [[NOTE]]);
  const tagged = applySettlement(control.effects, plain([control], gaps)[0], 'control')[0], noted = applySettlement(control.effects, judged([control], gaps)[0], 'control')[0];
  assert.deepEqual([tagged.verdict, tagged.settlement, Object.hasOwn(tagged, 'settlementNote')], ['pass', 'effect-outside-window', false]);
  assert.deepEqual([noted.verdict, noted.settlementNote, Object.hasOwn(noted, 'settlement')], ['pass', NOTE, false]);
  // A withheld control clause stays withheld by the other rules: an unexpected late send keeps the tag.
  assert.deepEqual(judged([passing(only({ allow: [B] }), () => [ev(A)], 'control')], inTail([0], [win([ev(C)])])), [['effect-outside-window']]);
});

// ---------------------------------------------------------------------------
// Scripted end-to-end runs: TASK's effect.only allows the coupon that COUPON (after it) sends in its own window.
const PAY = 'api.pay.example';
function scriptedFactory(queues) {
  return configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type], queue = [...(queues[c.id] ?? [])];
    let n = 0;
    return { kind: out.kind, instanceId: `${c.type}-${c.id}`, source: out.source, scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++n }; },
      async collect() {
        const next = queue.shift() ?? { events: [] }, coverage = next.coverage ?? 'complete';
        return { events: next.events.map((e, i) => makeEffect({ source: out.source, observer: { kind: out.kind, instanceId: `${c.type}-${c.id}` }, seq: 1000 + i + n * 10, outcome: 'committed', actor: null, operation: 'send', name: PAY, ...e })), coverage, reason: coverage === 'complete' ? null : 'synthetic' };
      } };
  });
}
const refundSel = { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' }, couponSel = { ...refundSel, resource: 'POST /v1/coupons' };
function judgeProfile({ judge = true, correlated = false, allowCoupon = true, mode = 'run', taskEffects } = {}) {
  const destination = { host: PAY, paths: ['/v1/refunds', '/v1/coupons'], ...(correlated ? { correlation: { header: 'traceparent' } } : {}) };
  return { id: 'judge-scripted', name: 'Judge scripted', applicationId: 'judge-scripted', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { member: { principalId: 'member-1' } },
    requiredControlIds: ['PING', 'COUPON'], observers: [{ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [destination], witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 }],
    ...(correlated ? { correlation: { header: 'traceparent' } } : {}), ...(judge || correlated ? { settlement: { mode, ...(judge ? { outsideWindow: 'judge' } : {}) } } : {}),
    checks: [
      { id: 'PING', title: 'Ping', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'GET', path: '/ping', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'TASK', title: 'Refund, and coupons allowed', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }],
        effects: taskEffects ?? [{ kind: 'effect.only', expect: [{ select: refundSel, count: 1 }], allow: allowCoupon ? [couponSel] : [], sources: ['http-egress'] }] },
      { id: 'COUPON', title: 'Coupon (allowed)', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'POST', path: '/coupon', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }],
        effects: [{ kind: 'effect.count', select: couponSel, expected: 1 }] },
    ] };
}
const scriptedTransport = async (origin, check) => ({ status: check.method === 'GET' ? 200 : 201, complete: true, jsonParsed: true, json: {}, bytes: 2 });
const refund = { resource: 'POST /v1/refunds' }, coupon = { resource: 'POST /v1/coupons' }, other = { resource: 'POST /v1/other' };
const suiteOf = p => createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
// Collect order: TASK's window, COUPON's window, then the gaps before TASK, between them, and the tail (per check adds the barriers).
const runWith = (p, queue) => runHttpAssessment(p, { env: {}, transport: scriptedTransport, observerFactory: scriptedFactory({ sink: queue }) });
const task = run => run.results.find(r => r.id === 'TASK');
const reseal = r => { r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions }); };

test('4 end to end: the connector stands the allowed late coupon with the note, the validator and gate agree, and the record carries the declaration', async () => {
  const p = judgeProfile(), suite = suiteOf(p);
  const run = await runWith(p, [{ events: [refund] }, { events: [coupon] }, { events: [] }, { events: [] }, { events: [] }]);
  const t = task(run), clause = t.trace[1].data.effects[0];
  assert.deepEqual([t.status, clause.verdict, clause.settlementNote, Object.hasOwn(clause, 'settlement')], ['pass', 'pass', NOTE, false]);
  const row = t.assertions.find(a => a.name.startsWith('Observed effect'));
  assert.deepEqual([row.status, row.settlementNote], ['pass', NOTE]);
  assert.match(row.actual, /effect-outside-window-judged/);
  assert.deepEqual([run.settlement.schema, run.settlement.outsideWindow], ['scopehaven-settlement/1', 'judge']);
  assert.equal(suite.outsideWindow, 'judge');
  validateHttpRunEvidence(run, { expectedSuite: suite });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)));
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suite }).exitCode, 0);
  // Without the declaration the same windows withhold TASK (the withholding rule), and the record and suite carry no key.
  const q = judgeProfile({ judge: false });
  const plainRun = await runWith(q, [{ events: [refund] }, { events: [coupon] }, { events: [] }, { events: [] }, { events: [] }]);
  assert.deepEqual([task(plainRun).status, task(plainRun).trace[1].data.effects[0].settlement], ['inconclusive', 'effect-outside-window']);
  assert.deepEqual(Object.keys(plainRun.settlement), ['schema', 'settleMs', 'gaps']);
  assert.equal(Object.hasOwn(suiteOf(q), 'outsideWindow'), false);
  validateHttpRunEvidence(plainRun, { expectedSuite: suiteOf(q) });
  // A send outside TASK's set after it stays withheld under the declaration, and validates.
  const offending = await runWith(p, [{ events: [refund] }, { events: [coupon] }, { events: [] }, { events: [] }, { events: [other] }]);
  assert.deepEqual([task(offending).status, task(offending).trace[1].data.effects[0].settlement], ['inconclusive', 'effect-outside-window']);
  validateHttpRunEvidence(offending, { expectedSuite: suite });
  // Correlated (/2, per check): the record carries the declaration beside its mode, and the note is recomputed the same way.
  const c = judgeProfile({ correlated: true, mode: 'per-check' });
  const correlatedRun = await runWith(c, [{ events: [refund] }, { events: [coupon] }, { events: [] }, { events: [] }, { events: [] }, { events: [] }, { events: [] }]);
  assert.deepEqual([correlatedRun.settlement.schema, correlatedRun.settlement.mode, correlatedRun.settlement.outsideWindow, task(correlatedRun).trace[1].data.effects[0].settlementNote], ['scopehaven-settlement/2', 'per-check', 'judge', NOTE]);
  validateHttpRunEvidence(correlatedRun, { expectedSuite: suiteOf(c) });
});

test('22. validator: a stripped, added or bad declaration, or an edited note, is refused', async () => {
  const p = judgeProfile(), suite = suiteOf(p), q = judgeProfile({ judge: false }), plainSuite = suiteOf(q);
  const run = await runWith(p, [{ events: [refund] }, { events: [coupon] }, { events: [] }, { events: [] }, { events: [] }]);
  const plainRun = await runWith(q, [{ events: [refund] }, { events: [coupon] }, { events: [] }, { events: [] }, { events: [] }]);
  const edit = (r, change) => { const copy = structuredClone(r); change(copy); return copy; };
  const refused = (r, detail, options) => assert.throws(() => validateHttpRunEvidence(r, options), e => (detail === 'unexpected-suite-evidence' ? e.code === detail : e.code === 'invalid-run-evidence' && e.detail === detail), detail);
  // Stripped: the recompute withholds the pass the note stood on; against the suite, the record no longer matches it.
  const stripped = edit(run, r => { delete r.settlement.outsideWindow; });
  refused(stripped, 'effect-verdict');
  refused(stripped, 'unexpected-suite-evidence', { expectedSuite: suite });
  // Added to a run made without it: the recompute stands the pass the record withheld; against that run's suite it is refused.
  const added = edit(plainRun, r => { r.settlement.outsideWindow = 'judge'; });
  refused(added, 'effect-verdict');
  refused(added, 'unexpected-suite-evidence', { expectedSuite: plainSuite });
  // Added with the verdicts recomputed to match: only the exported suite tells it apart (unsigned evidence, as KNOWN-LIMITS says).
  refused(edit(run, () => {}), 'unexpected-suite-evidence', { expectedSuite: plainSuite });
  // A bad value, or an extra key beside it.
  for (const value of ['release', 'JUDGE', true, null, ['judge']]) {
    refused(edit(run, r => { r.settlement.outsideWindow = value; }), 'settlement-record');
    refused(edit(run, r => { r.settlement.outsideWindow = value; }), 'unexpected-suite-evidence', { expectedSuite: suite });
  }
  refused(edit(run, r => { r.settlement.extra = 1; }), 'settlement-record');
  // The note itself is recomputed: removing it (resealed), or putting one on the withheld run, is refused.
  refused(edit(run, r => { const t = task(r); delete t.trace[1].data.effects[0].settlementNote; reseal(t); }), 'effect-verdict');
  refused(edit(plainRun, r => { const t = task(r); t.trace[1].data.effects[0].settlementNote = NOTE; reseal(t); }), 'effect-verdict');
  // Unit: the record rule itself.
  const bind = windows => windows, ids = ['TASK'], observers = [{ id: 'sink', type: 'egress-recorder', settleMs: 250 }];
  const record = extra => ({ schema: 'scopehaven-settlement/1', settleMs: 250, gaps: [{ after: null, before: 'TASK', windows: [] }, { after: 'TASK', before: null, windows: [] }], ...extra });
  assert.equal(validateSettlementRecord(record({ outsideWindow: 'judge' }), { effectRowIds: ids, declaredObservers: observers, bind }).judge, true);
  assert.equal(validateSettlementRecord(record(), { effectRowIds: ids, declaredObservers: observers, bind }).judge, false);
  assert.throws(() => validateSettlementRecord(record({ outsideWindow: 'all' }), { effectRowIds: ids, declaredObservers: observers, bind }), /settlement-record/);
});

test('23. load refusals (settlement-outside-window, settlement-judge-unused) and the scope sentence, present exactly when declared', async () => {
  const load = p => validateTargetFile({ schemaVersion: 1, targets: [p] })[0];
  assert.doesNotThrow(() => load(judgeProfile()));
  assert.doesNotThrow(() => load(judgeProfile({ correlated: true, mode: 'per-check' })));
  for (const outsideWindow of ['release', 'JUDGE', true, null, ['judge'], 1]) {
    const p = judgeProfile(); p.settlement.outsideWindow = outsideWindow;
    assert.throws(() => load(p), /settlement-outside-window/, String(outsideWindow));
  }
  const extra = judgeProfile(); extra.settlement.horizonMs = 1;
  assert.throws(() => load(extra), /"settlement".*unsupported field/);
  // A declaration no effect.only clause can use is refused (a keyed or send count does not count: part 2 is not built).
  const noOnly = judgeProfile({ taskEffects: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: PAY } }] });
  assert.throws(() => load(noOnly), /settlement-judge-unused/);
  const unused = judgeProfile(); unused.checks[1].applicability = { applies: false, reason: 'Not in this build.' };
  assert.throws(() => load(unused), /settlement-judge-unused/, 'the only effect.only check does not apply');
  // The profile digest and the exported suite carry it only when declared.
  assert.notEqual(contractDigest(load(judgeProfile())), contractDigest(load(judgeProfile({ judge: false }))));
  assert.equal(Object.hasOwn(suiteOf(judgeProfile({ judge: false, correlated: true })), 'outsideWindow'), false);
  // The scope sentence.
  const declaredObservers = [{ id: 'sink', type: 'egress-recorder', settleMs: 250 }];
  assert.ok(observerScopeNote(declaredObservers, { judge: true }).includes(JUDGED_LATE_EFFECTS_NOTE));
  assert.ok(!observerScopeNote(declaredObservers).includes(JUDGED_LATE_EFFECTS_NOTE));
  assert.ok(!httpScopeText({ observed: true, declared: declaredObservers }).includes('Judged late effects'));
  assert.ok(httpLimitations({ forwarded: false, observersDeclared: true, declared: declaredObservers, judge: true }).some(l => l.includes(JUDGED_LATE_EFFECTS_NOTE)));
  assert.ok(!DASHES.test(JUDGED_LATE_EFFECTS_NOTE));
  const run = await runWith(judgeProfile(), [{ events: [refund] }, { events: [coupon] }]);
  assert.ok(run.scopeLabel.includes(JUDGED_LATE_EFFECTS_NOTE) && run.limitations.some(l => l.includes(JUDGED_LATE_EFFECTS_NOTE)));
  const plainRun = await runWith(judgeProfile({ judge: false }), [{ events: [refund] }, { events: [coupon] }]);
  assert.ok(!plainRun.scopeLabel.includes('Judged late effects') && !plainRun.limitations.some(l => l.includes('Judged late effects')));
});

// ---------------------------------------------------------------------------
// 21 end to end: a lifecycle change control whose effect.only clause has an allowed late send keeps its pass, carries the note,
// and the change stays confirmed; 19 end to end: with a background source declared, attribution still withholds the change.
const SYNC_HOST = 'sync.desk.example', HOOK_HOST = 'hooks.desk.example', SINK_ID = 'egress-recorder-sink';
const ENV = Object.freeze({ SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_C: 'tok-carol' });
const WHO = { 'tok-admin': 'admin', 'tok-carol': 'carol' };
const sendTo = (name, resource) => ({ source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}) });
const lcControl = (id, actorId, method, path, extra = {}) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId, method, path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...extra });
const me = (id, actorId) => lcControl(id, actorId, 'GET', '/me', { assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: actorId }] });
function lifecycleProfile({ judge = true, attribution = false } = {}) {
  const reuse = { id: 'REUSE', title: 'REUSE', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: sendTo(HOOK_HOST) }] };
  return { id: 'judge-lifecycle', name: 'Judge lifecycle', applicationId: 'judge-lifecycle', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { admin: { principalId: 'admin', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, carol: { principalId: 'carol', credentialEnv: 'SCOPEHAVEN_TARGET_C', identityValue: 'carol' } },
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40998, destinations: [{ host: SYNC_HOST, paths: ['/suspend/', '/audit/'] }, { host: HOOK_HOST, paths: ['/notes'] }], settleMs: 250 }],
    ...(judge ? { settlement: { mode: 'run', outsideWindow: 'judge' } } : {}), ...(attribution ? { attribution: { background: [{ id: 'sync', select: { operation: 'send', name: SYNC_HOST } }] } } : {}),
    requiredControlIds: ['ADMIN-ME', 'CAROL-ME', 'CAROL-NOTES', 'SUSPEND'], lifecycle: [{ changeCheckId: 'SUSPEND', actorId: 'carol', after: 'refused' }],
    checks: [me('ADMIN-ME', 'admin'), me('CAROL-ME', 'carol'), lcControl('CAROL-NOTES', 'carol', 'GET', '/notes'),
      lcControl('SUSPEND', 'admin', 'POST', '/users/carol/suspend', { body: {}, effects: [{ kind: 'effect.exists', select: sendTo(SYNC_HOST, 'POST /suspend/') },
        { kind: 'effect.only', expect: [{ select: sendTo(SYNC_HOST, 'POST /suspend/'), count: 1 }], allow: [sendTo(SYNC_HOST, 'POST /audit/')], sources: ['http-egress'] }] }), reuse] };
}
// The app suspends carol (one sync send), and the first request carol makes afterwards (her refused pre-change credential)
// makes it send one allowed audit record to the sync host, after the change check's window.
function lifecycleApp() {
  let suspended = false, audited = false, now = 0, n = 0;
  const events = [];
  const clock = { now: () => now, sleep: async ms => { now += ms; } };
  const transport = async (origin, check, { credential }) => {
    now += 10;
    const who = WHO[credential] ?? null, path = check.path.split('?')[0];
    if (suspended && who === 'carol' && !audited) { audited = true; events.push({ at: now, name: SYNC_HOST, resource: 'POST /audit/' }); }
    if (path === '/me') return who ? { status: 200, complete: true, jsonParsed: true, json: { user: who }, bytes: 10 } : { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (!who || (who === 'carol' && suspended)) return { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (path === '/users/carol/suspend') { suspended = true; events.push({ at: now, name: SYNC_HOST, resource: 'POST /suspend/' }); }
    return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  const factory = configs => configs.map(c => ({ kind: 'http-egress-recorder', instanceId: `${c.type}-${c.id}`, source: 'http-egress', witnessRequest: null,
    scope: { operations: ['send'], names: [SYNC_HOST, HOOK_HOST], actorAttribution: 'none', evidence: 'authoritative' },
    async start() {}, async stop() {}, async mark() { return { at: now }; },
    async collect(from, to) { return { events: events.filter(e => e.at > from.at && e.at <= to.at).map(e => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: SINK_ID }, seq: ++n, operation: 'send', name: e.name, resource: e.resource, outcome: 'committed' })), coverage: 'complete', reason: null }; } }));
  return { clock, transport, factory };
}
const lifecycleRun = p => { const a = lifecycleApp(); return runHttpAssessment(p, { env: ENV, clock: a.clock, transport: a.transport, observerFactory: a.factory }); };
const byId = (run, id) => run.results.find(r => r.id === id);
const carol = run => run.identityEvidence.actors.find(a => a.actorId === 'carol');

test('21 end to end: a change control whose effect.only has an allowed late send keeps its pass with the note, and the change stays confirmed', async () => {
  const p = lifecycleProfile(), run = await lifecycleRun(p);
  const suspend = byId(run, 'SUSPEND'), onlyClause = suspend.trace[1].data.effects[1];
  assert.deepEqual([suspend.status, onlyClause.verdict, onlyClause.settlementNote, Object.hasOwn(onlyClause, 'settlement')], ['pass', 'pass', NOTE, false]);
  assert.equal(passedAtSend(suspend), true);
  assert.deepEqual([carol(run).lifecycle.changeConfirmed, byId(run, 'REUSE').status], [true, 'pass']);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: ENV }).exportSuite(p.id) });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)));
  // Without the declaration the control keeps its pass with the tag instead, and the change is confirmed the same way.
  const q = lifecycleProfile({ judge: false }), plainRun = await lifecycleRun(q);
  const tagged = byId(plainRun, 'SUSPEND').trace[1].data.effects[1];
  assert.deepEqual([byId(plainRun, 'SUSPEND').status, tagged.settlement, Object.hasOwn(tagged, 'settlementNote'), carol(plainRun).lifecycle.changeConfirmed], ['pass', 'effect-outside-window', false, true]);
  validateHttpRunEvidence(plainRun, { expectedSuite: createRegistry({ profiles: [q], env: ENV }).exportSuite(q.id) });
});

test('19 end to end: with a background source declared, attribution still withholds the change control beside its noted effect.only clause', async () => {
  const p = lifecycleProfile({ attribution: true }), run = await lifecycleRun(p);
  const suspend = byId(run, 'SUSPEND');
  assert.deepEqual([suspend.status, suspend.trace[1].data.effects[0].attribution, suspend.trace[1].data.effects[1].settlementNote], ['inconclusive', 'background-unattributed', NOTE]);
  assert.equal(carol(run).lifecycle.changeConfirmed, false);
  assert.equal(byId(run, 'REUSE').status, 'inconclusive');
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: ENV }).exportSuite(p.id) });
});

// ---------------------------------------------------------------------------
// 24. effect.only keyed applications under the declaration: a clause that declares countBy keeps the withholding rule
// (judging it with its countBy would release a late exact keyed replay, which is not built), and a declaration only such clauses
// could use is refused.
const KEYED = Object.freeze({ ...SINK, idempotency: { [HOST]: validateIdempotencyDeclaration({ header: 'idempotency-key' }) } });
const keyedOnly = () => ({ ...only({ allow: [B] }), countBy: 'idempotency-key' });
const NO_KEY = Object.freeze({ status: 'absent', key: null, fold: null, head: 'a'.repeat(64), firstSeq: null });
// 24 (an earlier build kept such a clause on the withholding rule): under the declaration a countBy effect.only clause is judged
// worst case. Its own window's sends keep their keyed collapse; every late candidate is its own send, never collapsed or
// absorbed, so a late exact keyed replay of its own send is one more application (a late countBy release is not built).
test('24. an effect.only clause with countBy is judged worst case under the declaration: a late allowed send stands; a late exact keyed replay of its own send counts again, never absorbed', () => {
  const key = { status: 'keyed', key: 'e'.repeat(64), fold: 'e'.repeat(64), head: 'f'.repeat(64) };
  const keyedRow = (spec = keyedOnly(), { replayed = false } = {}) => {
    const firstUse = ev(A, { content: { c: 3 }, idempotency: { ...key, firstSeq: seq + 1 } });
    const own = [firstUse, ...(replayed ? [ev(A, { content: { c: 3 }, idempotency: { ...key, firstSeq: firstUse.seq } })] : [])];
    const row = rowOf([spec], [win(own, 'complete', { scope: KEYED })]);
    assert.equal(row.effects[0].verdict, 'pass', row.effects[0].basis);
    return { row, firstUse };
  };
  const lateAllowed = () => [win([ev(B, { idempotency: NO_KEY })], 'complete', { scope: KEYED })];
  {
    const { row, firstUse } = keyedRow(), replay = ev(A, { content: { c: 3 }, idempotency: { ...key, firstSeq: firstUse.seq } });
    // Inside its own window the same replay counts with its application; after the window it is one more application.
    assert.equal(judgeOnly(keyedOnly(), [win([firstUse, replay], 'complete', { scope: KEYED })], { fields: true, countBy: true }).verdict, 'pass', 'adjacent: the same replay inside the window');
    assert.deepEqual(judged([row], inTail([0], [win([replay], 'complete', { scope: KEYED })])), [['effect-outside-window']], 'a late exact keyed replay is never absorbed');
    assert.deepEqual(plain([row], inTail([0], [win([replay], 'complete', { scope: KEYED })])), [['effect-outside-window']], 'undeclared: the same');
  }
  {
    const { row } = keyedRow();
    assert.deepEqual(judged([row], inTail([0], lateAllowed())), [[NOTE]], 'a late allowed send stands, as without countBy');
    assert.deepEqual(plain([row], inTail([0], lateAllowed())), [['effect-outside-window']], 'undeclared: withheld');
  }
  {
    // Worst case, not a refusal: with room for two applications, the late exact replay counted again still fits.
    const { row, firstUse } = keyedRow({ ...only({ expect: [[A, 2]], allow: [B] }), countBy: 'idempotency-key' });
    const replay = ev(A, { content: { c: 3 }, idempotency: { ...key, firstSeq: firstUse.seq } });
    assert.deepEqual(judged([row], inTail([0], [win([replay], 'complete', { scope: KEYED })])), [[NOTE]], 'count 2: one own application plus the late one');
  }
  {
    // The own window's collapse is kept: its in-window replay counts with its application, so the clause stands on a late allowed send.
    const { row } = keyedRow(keyedOnly(), { replayed: true });
    assert.deepEqual(judged([row], inTail([0], lateAllowed())), [[NOTE]], 'an in-window exact replay still collapses in the re-judge');
  }
  // Adjacent: the same clause without countBy stands on the late allowed send too.
  const { countBy, ...unkeyed } = keyedOnly();
  const plainRow = rowOf([unkeyed], [win([ev(A, { idempotency: NO_KEY })], 'complete', { scope: KEYED })]);
  assert.equal(plainRow.effects[0].verdict, 'pass', plainRow.effects[0].basis);
  assert.deepEqual(judged([plainRow], inTail([0], lateAllowed())), [[NOTE]], 'adjacent: no countBy');
  assert.equal(countBy, 'idempotency-key');
});

test('24 load: a declaration whose only effect.only clauses declare countBy now loads; one with no applicable effect.only clause is still refused', () => {
  const load = p => validateTargetFile({ schemaVersion: 1, targets: [p] })[0];
  const keyedProfile = (also = []) => {
    const p = judgeProfile({ taskEffects: [{ kind: 'effect.only', expect: [{ select: refundSel, count: 1 }], allow: [couponSel], sources: ['http-egress'], countBy: 'idempotency-key' }, ...also] });
    p.observers[0].destinations[0].idempotency = { header: 'idempotency-key' };
    return p;
  };
  assert.doesNotThrow(() => load(keyedProfile()), 'a countBy effect.only clause uses the declaration');
  const notApplied = keyedProfile(); notApplied.checks[1].applicability = { applies: false, reason: 'Not in this build.' };
  assert.throws(() => load(notApplied), /settlement-judge-unused/, 'adjacent: its only effect.only check does not apply');
  const undeclared = keyedProfile(); delete undeclared.settlement;
  assert.doesNotThrow(() => load(undeclared), 'without the declaration the keyed clause loads as before');
});

// ---------------------------------------------------------------------------
// S1 to S8: gaps a mutation sweep found. Each title names the mutant it kills.
const elsewhere = e => ({ ...e, observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-elsewhere' } });

test('S1. candidates from a later check\'s window and from the gap before it are merged in seq order (kills: candidates not sorted)', () => {
  // Time order: gap 0, row 0, gap 1, row 1, tail. The windows after row 0 are read as row 1's window, then gap 1, then the tail,
  // so the later check's window (higher seq) is met before the gap that precedes it (lower seq): the judge must sort them.
  const first = passing(only({ allow: [B] })), inGap = ev(B), inNext = ev(B);
  const second = rowOf([none(C)], [win([inNext])]);
  assert.equal(second.effects[0].verdict, 'pass');
  assert.ok(inNext.seq > inGap.seq);
  assert.deepEqual(judged([first, second], [[win()], [win([inGap])], [win()]]), [[NOTE], [null]]);
});

test('S2. a candidate under another observer id needs a seq after EVERY own event, equal or in between is withheld (kills: seq equal to the last own event allowed; last own seq read as the first)', () => {
  const row = passing(only({ allow: [B] }), () => [ev(A)]);
  const lastOwn = row.windows[0].events.at(-1);
  assert.deepEqual(judged([row], inTail([0], [win([elsewhere({ ...ev(B), seq: lastOwn.seq })])])), [['effect-outside-window']], 'a seq equal to the last own event, another observer id');
  // Two own events with a gap between their seqs; a candidate (another observer id) lands between them.
  const a = ev(A); seq += 4; const b = ev(B);
  const two = rowOf([only({ allow: [B] })], [win([a, b])]);
  assert.equal(two.effects[0].verdict, 'pass');
  assert.deepEqual(judged([two], inTail([0], [win([elsewhere({ ...ev(B), seq: a.seq + 2 })])])), [['effect-outside-window']], 'a seq between two own events, another observer id');
  assert.deepEqual(judged([two], inTail([0], [win([elsewhere({ ...ev(B), seq: b.seq + 1 })])])), [[NOTE]], 'adjacent: after the last own event');
});

test('S3. an allow-only clause with an empty own window stands on a later allowed send (kills: last own seq read as the first, which is +Infinity on an empty window)', () => {
  const empty = rowOf([only({ expect: [], allow: [B] })], [win()]);
  assert.equal(empty.effects[0].verdict, 'pass');
  assert.deepEqual(judged([empty], inTail([0], [win([ev(B)])])), [[NOTE]]);
});

test('S4. an instance with two own windows has no single window to merge into: withheld (kills: the single own window rule weakened)', () => {
  const dup = rowOf([only({ allow: [B] })], [win([ev(A)]), win([])]);
  assert.equal(dup.effects[0].verdict, 'pass');
  assert.deepEqual(judged([dup], inTail([0], [win([ev(B)])])), [['effect-outside-window']]);
  assert.deepEqual(judged([passing()], inTail([0], [win([ev(B)])])), [[NOTE]], 'adjacent: one own window');
});

test('S5. a fractional seq never merges (pins the behaviour; the integer check on a candidate seq is redundant with window validation, so dropping it alone changes nothing)', () => {
  const row = passing();
  assert.deepEqual(judged([row], inTail([0], [win([elsewhere({ ...ev(B), seq: seq + 0.5 })])])), [['effect-outside-window']]);
});

// ---------------------------------------------------------------------------
test('S6. a bad candidate window is withheld even after a good one was merged (kills: window checks applied to the first candidate window only)', () => {
  const good = () => win([ev(B)]);
  // A presence-only observer the clause reads, after an authoritative window with an allowed send.
  const both = () => { const r = rowOf([only({ allow: [B] })], [win([ev(A)]), presenceWin()]); assert.equal(r.effects[0].verdict, 'pass'); return r; };
  { const row = both(), g = good(), p = presenceWin([ev(B, { instanceId: OTHER_INST })]);
    assert.deepEqual(judged([row], inTail([0], [g, p])), [['effect-outside-window']], 'presence-only after an authoritative candidate window'); }
  { const row = both(), g = good();
    assert.deepEqual(judged([row], inTail([0], [g, presenceWin()])), [[NOTE]], 'adjacent: the presence-only window has no candidate'); }
  // A later window of the instance whose scope drifted, after a good one (the row and every window made in run order).
  { const row = passing(), g = good(), drift = { ...win([ev(B)]), scope: { ...SINK, names: [HOST, 'other.example'] } };
    assert.deepEqual(judged([row], inTail([0], [g, drift])), [['effect-outside-window']], 'scope drift after a good window'); }
  // A later window labelled with another source (holding this source's sends), after a good one.
  { const row = passing(), g = good(), mislabel = { ...win([ev(B)]), source: 'smtp-capture' };
    assert.deepEqual(judged([row], inTail([0], [g, mislabel])), [['effect-outside-window']], 'a window labelled with another source, after a good window'); }
  { const row = passing(), g = good(), g2 = good();
    assert.deepEqual(judged([row], inTail([0], [g, g2])), [[NOTE]], 'adjacent: two good windows'); }
});

test('S7. the profile digest tells settlement {mode} from settlement {mode, outsideWindow} (kills: the declaration dropped from the digest)', () => {
  const load = p => validateTargetFile({ schemaVersion: 1, targets: [p] })[0];
  const plainMode = judgeProfile(); plainMode.settlement = { mode: 'run' };
  assert.notEqual(contractDigest(load(plainMode)), contractDigest(load(judgeProfile())));
});

test('S8. KNOWN-LIMITS states the declaration, its refusal and the note (kills: the wording removed)', async () => {
  const limits = await readFile(new URL('../docs/KNOWN-LIMITS.md', import.meta.url), 'utf8');
  for (const needle of ['"outsideWindow": "judge"', 'settlement-judge-unused', 'effect-outside-window-judged', 'whether that effect is expected, allowed or outside its set',
    'an `effect.only` clause that declares `countBy`', 'a combined window over the window event cap', 'recomputed to match; the profile digest and the comparison signature still keep the two from comparing']) assert.ok(limits.includes(needle), needle);
});

// ---------------------------------------------------------------------------
// S9 and S10: the comparison signature and the wording.
test('S9. comparison: a judged run relabelled with the undeclared run\'s profile and target identities never compares with it (the signature carries the declaration)', async () => {
  const q = judgeProfile({ judge: false }), p = judgeProfile();
  const queue = () => [{ events: [refund] }, { events: [coupon] }, { events: [] }, { events: [] }, { events: [] }];
  const plainRun = await runWith(q, queue()), run = await runWith(p, queue());
  assert.notEqual(plainRun.profileHash, run.profileHash, 'honest runs differ by the profile digest');
  const forged = structuredClone(run);
  forged.profileHash = plainRun.profileHash; forged.targetConfigHash = plainRun.targetConfigHash;
  validateHttpRunEvidence(forged); // without the exported suite the relabelled run validates (unsigned evidence, as KNOWN-LIMITS says)
  const reason = 'Declared effects, evidence requirements or observers differ between the runs.';
  for (const [a, b] of [[plainRun, forged], [forged, plainRun]]) {
    const cmp = compareRuns(a, b);
    assert.equal(cmp.compatible, false);
    assert.ok(cmp.reasons.includes(reason), cmp.reasons.join(' | '));
  }
  // Adjacent: two runs of one kind still compare, declared or not (an undeclared run's signature is unchanged).
  for (const [profile, first] of [[q, plainRun], [p, run]]) {
    const cmp = compareRuns(first, await runWith(profile, queue()));
    assert.equal(cmp.compatible, true, cmp.reasons.join(' | '));
  }
});

test('S10. wording: the correlation limitation and ONBOARDING state the declaration, the limitation only when declared', async () => {
  const off = correlationLimitation({ header: 'traceparent', mode: 'run' }), on = correlationLimitation({ header: 'traceparent', mode: 'per-check', judge: true });
  const sentence = 'is not withheld on its own-token late sends';
  assert.ok(!off.includes('Judged late effects') && on.includes(sentence) && !DASHES.test(on));
  const declaredObservers = [{ id: 'sink', type: 'egress-recorder', settleMs: 250 }];
  const limitations = judge => httpLimitations({ forwarded: false, observersDeclared: true, declared: declaredObservers, judge, correlation: { header: 'traceparent', mode: 'run' } });
  assert.ok(limitations(true).some(l => l.startsWith('Correlation:') && l.includes(sentence)));
  assert.ok(!limitations(false).some(l => l.includes(sentence)));
  const onboarding = await readFile(new URL('../docs/ONBOARDING.md', import.meta.url), 'utf8');
  for (const needle of ['"outsideWindow": "judge"', 'effect-outside-window-judged', 'settlement-judge-unused', 'an `effect.only` clause with `countBy`']) assert.ok(onboarding.includes(needle), needle);
  assert.ok(!DASHES.test(onboarding));
});
