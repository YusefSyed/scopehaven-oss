// Background attribution (src/http-attribution.mjs): pure rules over synthetic windows. No I/O,
// no model, no provider. Each allowed behaviour sits beside the forbidden or fail-closed behaviour next to it. Clauses are
// decided with the control role so custody keeps their verdicts; roles are tested through applyAttribution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { makeEffect } from '../src/effect-events.mjs';
import { decideEffects } from '../src/http-effects.mjs';
import { applySettlement, SETTLEMENT_REASONS } from '../src/http-settlement.mjs';
import { attributionFindings, applyAttribution, attributionDeclarationProblem, backgroundProblem, backgroundUnseen, backgroundClassifier, fitsWide, attributionFields,
  attributionRecord, validateAttributionRecord, ATTRIBUTION_REASONS, ATTRIBUTION_BASIS, ATTRIBUTION_LIMITS, ATTRIBUTION_SCHEMA } from '../src/http-attribution.mjs';

const TABLES = ['docs', 'orders', 'export', 'report'];
const OPS = ['insert', 'update', 'delete'];
const OBS = {
  aud: { source: 'sql-audit-table', kind: 'sqlite-audit-table', instanceId: 'sqlite-audit-aud', scope: { operations: OPS, names: TABLES, actorAttribution: 'principal', evidence: 'authoritative' } },
  snap: { source: 'sql-snapshot', kind: 'sqlite-snapshot-diff', instanceId: 'sqlite-snapshot-snap', scope: { operations: OPS, names: TABLES, actorAttribution: 'none', evidence: 'authoritative' } },
  aud2: { source: 'sql-audit-table', kind: 'http-audit-endpoint', instanceId: 'http-audit-aud2', scope: { operations: OPS, names: TABLES, actorAttribution: 'principal', evidence: 'presence-only' } },
  tel: { source: 'otel-genai', kind: 'otlp-http-json-receiver', instanceId: 'otel-tel', scope: { operations: OPS, names: null, actorAttribution: 'principal', evidence: 'presence-only' } },
  hooks: { source: 'http-egress', kind: 'http-egress-recorder', instanceId: 'egress-recorder-hooks', scope: { operations: ['send'], names: ['hooks.example'], actorAttribution: 'none', evidence: 'authoritative' } },
};
let seq = 0;
const ev = (o, { actor = null, operation, name, resource = null, outcome = 'committed', correlation = {} }) =>
  makeEffect({ source: OBS[o].source, observer: { kind: OBS[o].kind, instanceId: OBS[o].instanceId }, seq: ++seq, actor, operation, name, resource, outcome, correlation });
const win = (o, events = [], coverage = 'complete') => ({ source: OBS[o].source, instanceId: OBS[o].instanceId, scope: OBS[o].scope, coverage, reason: coverage === 'complete' ? null : 'synthetic', events });
const rowOf = (clauses, windows) => ({ effects: decideEffects(clauses, windows, { role: 'control' }), windows });

const SYNC = { id: 'sync', select: { actor: 'svc-sync', operation: 'delete', name: 'docs' } };
const NONE_B = { kind: 'effect.none', select: { actor: 'alice', operation: 'delete', name: 'docs', resource: 'doc-B' } };
const FILLER = { kind: 'effect.none', select: { actor: 'alice', operation: 'insert', name: 'report' } };
const POSITIONS = ['before', 'own', 'barrier', 'middle', 'later', 'barrier1', 'tail'];
// A two-check run: row 0 is under test, row 1 a filler, with three gaps and per-check barriers. spec(position, observer)
// returns [events, coverage] for that window (default: no events, complete).
function layout(clauses, spec = () => null, obs = ['aud'], { second = [FILLER] } = {}) {
  const w = p => obs.map(o => { const [events = [], coverage = 'complete'] = spec(p, o) ?? []; return win(o, events, coverage); });
  return { rows: [rowOf(clauses, w('own')), rowOf(second, w('later'))], gaps: [w('before'), w('middle'), w('tail')], barriers: [w('barrier'), w('barrier1')] };
}
const find = ({ rows, gaps, barriers }, background = [SYNC]) => attributionFindings(rows, gaps, barriers, { background });
const at = (position, o, make) => (p, x) => p === position && x === o ? [[make()]] : null;

test('none pass: a worker effect on another row leaves an actor-pinned absence standing at every position; on the same row it is unattributed in the own window and every later one, never before it', () => {
  for (const p of POSITIONS) {
    const other = layout([NONE_B], at(p, 'aud', () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-C' })));
    assert.equal(other.rows[0].effects[0].verdict, 'pass', p);
    assert.equal(find(other)[0][0], null, `${p}: another row`);
    const same = layout([NONE_B], at(p, 'aud', () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-B' })));
    assert.equal(same.rows[0].effects[0].verdict, 'pass', `${p}: the actor pin alone passes it`);
    assert.equal(find(same)[0][0], p === 'before' ? null : 'background-unattributed', `${p}: the same row`);
  }
  // A worker effect with no row (the observer cannot name rows) never proves it was another row.
  const unnamed = layout([NONE_B], at('later', 'aud', () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: null })));
  assert.equal(find(unnamed)[0][0], 'background-unattributed');
  // Without a background declaration nothing is attributed: the rules never run (the connector never calls them).
  assert.throws(() => find(unnamed, []), /attribution-background/);
  // A trace pin is attribution, not content, like an actor pin: the worker runs under its own trace.
  const TRACED = { kind: 'effect.none', select: { operation: 'delete', name: 'docs', resource: 'doc-B', traceId: 't-1' } };
  const traced = id => layout([TRACED], at('later', 'aud', () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-B', correlation: { traceId: id } })));
  assert.equal(traced('t-2').rows[0].effects[0].verdict, 'pass');
  assert.equal(find(traced('t-2'))[0][0], 'background-unattributed');
  const otherRow = layout([TRACED], at('later', 'aud', () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-C', correlation: { traceId: 't-2' } })));
  assert.equal(find(otherRow)[0][0], null, 'content pins still exclude');
});

test('none pass: an observer that could record the worker\'s effect must decide absence in the own window and every later one (background-unobserved), gated by overlap', () => {
  const obs = ['aud', 'snap'];
  const clean = layout([NONE_B], () => null, obs);
  assert.equal(clean.rows[0].effects[0].verdict, 'pass');
  assert.equal(find(clean)[0][0], null);
  // The snapshot cannot attribute actors, so it never decides the actor-pinned clause and settlement does not read it.
  for (const [p, coverage] of [['tail', 'failed'], ['own', 'partial'], ['barrier', 'partial'], ['later', 'net-only']]) {
    const blind = layout([NONE_B], (q, o) => q === p && o === 'snap' ? [[], coverage] : null, obs);
    assert.equal(blind.rows[0].effects[0].verdict, 'pass', p);
    assert.equal(find(blind)[0][0], 'background-unobserved', `${p} ${coverage}`);
    // No declared source overlaps the clause (another table): background-unobserved is not reached.
    assert.equal(find(blind, [{ id: 'other', select: { actor: 'svc-sync', operation: 'delete', name: 'orders' } }])[0][0], null, `${p}: no overlap`);
    assert.equal(find(blind, [{ id: 'prefix', select: { operation: 'delete', name: { prefix: 'do' } } }])[0][0], 'background-unobserved', `${p}: a prefix overlaps`);
  }
  // A blind window before the check's own window cannot hide its effect.
  const before = layout([NONE_B], (q, o) => q === 'before' && o === 'snap' ? [[], 'failed'] : null, obs);
  assert.equal(find(before)[0][0], null);
});

test('none fail: a fail resting only on background effects is unattributed; one resting on any other committed effect stands', () => {
  const NONE_ANY = { kind: 'effect.none', select: { operation: 'delete', name: 'docs' } };
  const mixed = layout([NONE_ANY], (p, o) => p === 'own' && o === 'aud' ? [[ev('aud', { actor: 'alice', operation: 'delete', name: 'docs', resource: 'doc-A' }), ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-C' })]] : null);
  assert.equal(mixed.rows[0].effects[0].verdict, 'fail');
  assert.equal(find(mixed)[0][0], null);
  const only = layout([NONE_ANY], at('own', 'aud', () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-C' })));
  assert.equal(only.rows[0].effects[0].verdict, 'fail');
  assert.equal(find(only)[0][0], 'background-unattributed');
  // An unknown actor fits the actor-pinned source: the copy with no actor is background-possible too.
  const unknown = layout([NONE_ANY], at('own', 'aud', () => ev('aud', { actor: null, operation: 'delete', name: 'docs', resource: 'doc-C' })));
  assert.equal(find(unknown)[0][0], 'background-unattributed');
  const unlisted = layout([NONE_ANY], at('own', 'aud', () => ev('aud', { actor: 'unlisted:0a1b', operation: 'delete', name: 'docs', resource: 'doc-C' })));
  assert.equal(find(unlisted)[0][0], 'background-unattributed');
  // A declared principal other than the source's actor is not background.
  const bob = layout([NONE_ANY], at('own', 'aud', () => ev('aud', { actor: 'bob', operation: 'delete', name: 'docs', resource: 'doc-C' })));
  assert.equal(find(bob)[0][0], null);
});

test('exists pass: a pass resting only on background (or earlier-explained) effects is unattributed; any other matched effect keeps it, across observers', () => {
  const EXISTS = { kind: 'effect.exists', select: { operation: 'delete', name: 'docs' } };
  const mixed = layout([EXISTS], (p, o) => p === 'own' && o === 'aud' ? [[ev('aud', { actor: 'alice', operation: 'delete', name: 'docs', resource: 'doc-A' }), ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-C' })]] : null);
  assert.equal(mixed.rows[0].effects[0].verdict, 'pass');
  assert.equal(find(mixed)[0][0], null);
  const only = layout([EXISTS], at('own', 'aud', () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-C' })));
  assert.equal(only.rows[0].effects[0].verdict, 'pass');
  assert.equal(find(only)[0][0], 'background-unattributed', 'a pass resting only on a background effect');
  // One worker insert recorded twice: by the audit table (its principal) and the snapshot (no actor). Both copies are
  // background; with the audit copy by alice the snapshot copy alone is not all the pass rests on.
  const INS = [{ id: 'sync-ins', select: { actor: 'svc-sync', operation: 'insert', name: 'orders' } }];
  const EX_ORDERS = { kind: 'effect.exists', select: { operation: 'insert', name: 'orders' } };
  const copies = actor => layout([EX_ORDERS], (p, o) => p !== 'own' ? null : [[ev(o, { actor: o === 'aud' ? actor : null, operation: 'insert', name: 'orders', resource: 'o-1' })]], ['aud', 'snap']);
  const both = copies('svc-sync');
  assert.equal(both.rows[0].effects[0].verdict, 'pass');
  assert.equal(find(both, INS)[0][0], 'background-unattributed');
  assert.equal(find(copies('alice'), INS)[0][0], null);
});

test('exists pass: an effect an earlier check\'s selector explains plus a background effect is unattributed; a later check\'s selector explains nothing; the first fitting row decides', () => {
  const INS = [{ id: 'sync-ins', select: { actor: 'svc-sync', operation: 'insert', name: 'orders' } }];
  const EX = { kind: 'effect.exists', select: { operation: 'insert', name: 'orders' } };
  const O9 = { kind: 'effect.none', select: { operation: 'insert', name: 'orders', resource: 'o-9' } };
  const three = (first, third) => {
    const own = [win('aud', [ev('aud', { actor: 'alice', operation: 'insert', name: 'orders', resource: 'o-9' }), ev('aud', { actor: 'svc-sync', operation: 'insert', name: 'orders', resource: 'o-1' })])];
    const rows = [rowOf([first], [win('aud')]), rowOf([EX], own), rowOf([third], [win('aud')])];
    return attributionFindings(rows, [[win('aud')], [win('aud')], [win('aud')], [win('aud')]], undefined, { background: INS })[1][0];
  };
  assert.equal(three(O9, FILLER), 'background-unattributed', 'o-9 fits row 0, o-1 is background');
  assert.equal(three(FILLER, O9), null, 'o-9 fits only rows 1 and 2: it is row 1\'s own');
  assert.equal(three(O9, O9), 'background-unattributed', 'o-9 fits rows 0 and 2: the first row is earlier');
  // An event with no row fits an earlier resource-pinned selector (it could be that row).
  const unnamed = (() => {
    const own = [win('aud', [ev('aud', { actor: 'alice', operation: 'insert', name: 'orders', resource: null }), ev('aud', { actor: 'svc-sync', operation: 'insert', name: 'orders', resource: 'o-1' })])];
    const rows = [rowOf([O9], [win('aud')]), rowOf([EX], own)];
    return attributionFindings(rows, [[win('aud')], [win('aud')], [win('aud')]], undefined, { background: INS })[1][0];
  })();
  assert.equal(unnamed, 'background-unattributed');
});

test('exists fail: a background effect that could be the expected one (own or later window, any vocabulary) is unattributed; another name leaves the fail standing; a blind seer is unobserved', () => {
  const WORKER = [{ id: 'worker', select: { actor: 'svc-worker' } }];
  const EX = { kind: 'effect.exists', select: { actor: 'alice', operation: 'insert', name: 'export' } };
  for (const p of ['own', 'barrier', 'later', 'tail']) {
    const behalf = layout([EX], at(p, 'aud', () => ev('aud', { actor: 'svc-worker', operation: 'insert', name: 'export', resource: 'x-1' })));
    assert.equal(behalf.rows[0].effects[0].verdict, 'fail', p);
    assert.equal(find(behalf, WORKER)[0][0], 'background-unattributed', `${p}`);
    const other = layout([EX], at(p, 'aud', () => ev('aud', { actor: 'svc-worker', operation: 'insert', name: 'report', resource: 'x-1' })));
    assert.equal(find(other, WORKER)[0][0], null, `${p}: another name`);
  }
  // Recorded only by an observer with no name vocabulary: no vocabulary gate on the background side.
  const tel = name => layout([EX], at('later', 'tel', () => ev('tel', { actor: 'svc-worker', operation: 'insert', name, resource: null })), ['aud', 'tel']);
  assert.equal(tel('export').rows[0].effects[0].verdict, 'fail');
  assert.equal(find(tel('export'), WORKER)[0][0], 'background-unattributed');
  assert.equal(find(tel('report'), WORKER)[0][0], null);
  // A later window of an observer that sees the effect without its actor pin must decide absence.
  const seer = coverage => layout([EX], (p, o) => p === 'later' && o === 'snap' ? [[], coverage] : null, ['aud', 'snap']);
  assert.equal(find(seer('partial'), WORKER)[0][0], 'background-unobserved');
  assert.equal(find(seer('complete'), WORKER)[0][0], null);
});

test('count: substitution, a late double application and an interval that holds n are unattributed; a clean count and a fail outside the interval stand', () => {
  const SRC = [{ id: 'sync', select: { actor: 'svc-sync', operation: 'insert', name: 'orders' } }, { id: 'retry', select: { actor: 'svc-retry', operation: 'insert', name: 'orders' } }];
  const COUNT = n => ({ kind: 'effect.count', select: { source: 'sql-audit-table', operation: 'insert', name: 'orders' }, expected: n });
  const ins = (actor, o = 'aud', name = 'orders') => ev(o, { actor, operation: 'insert', name, resource: `r-${seq + 1}` });
  const run = (n, own, later = () => [], extra = {}) => layout([COUNT(n)], (p, o) => o === 'aud' && p === 'own' ? [own()] : o === 'aud' && p === 'later' ? [later()] : extra[`${p}/${o}`] ? extra[`${p}/${o}`]() : null, extra.obs ?? ['aud']);
  const clean = run(1, () => [ins('alice')]);
  assert.equal(clean.rows[0].effects[0].verdict, 'pass');
  assert.equal(find(clean, SRC)[0][0], null);
  assert.equal(find(run(1, () => [ins('svc-sync')]), SRC)[0][0], 'background-unattributed', 'substitution');
  const doubled = run(1, () => [ins('alice')], () => [ins('svc-retry')]);
  assert.equal(doubled.rows[0].effects[0].verdict, 'pass');
  assert.equal(find(doubled, SRC)[0][0], 'background-unattributed', 'late double application');
  assert.equal(find(run(1, () => [ins('alice')], () => [ins('svc-retry', 'aud', 'report')]), SRC)[0][0], null, 'a later effect of another name');
  // Two observers of one store: the other observer's copies bound the count by a max, not a sum.
  const twice = copies => run(1, () => [ins('alice')], () => [], { obs: ['aud', 'aud2'], 'own/aud2': () => [Array.from({ length: copies }, () => ins(null, 'aud2'))] });
  assert.equal(twice(1).rows[0].effects[0].verdict, 'pass');
  assert.equal(find(twice(1), SRC)[0][0], null, 'max(1, 1) = 1');
  assert.equal(find(twice(2), SRC)[0][0], 'background-unattributed', 'max(1, 2) = 2');
  // Fails: outside [lo, hi] stands; inside reads unattributed (inclusive at both ends).
  const tooMany = run(1, () => [ins('alice'), ins('bob'), ins('svc-sync')]);
  assert.equal(tooMany.rows[0].effects[0].verdict, 'fail');
  assert.equal(find(tooMany, SRC)[0][0], null, 'lo 2 > 1');
  const none = run(2, () => []);
  assert.equal(none.rows[0].effects[0].verdict, 'fail');
  assert.equal(find(none, SRC)[0][0], null, 'hi 0 < 2, nothing blind');
  assert.equal(find(run(1, () => [ins('alice'), ins('svc-sync')]), SRC)[0][0], 'background-unattributed', 'lo 1 = n <= hi 2');
  assert.equal(find(run(2, () => [ins('alice')], () => [ins('svc-retry')]), SRC)[0][0], 'background-unattributed', 'lo 1 <= n = hi 2');
  // n = hi + 1: with a blind authoritative seer after the check the missing effect could have been missed; without, it stands.
  const blind = run(2, () => [ins('alice')], () => [], { 'tail/aud': () => [[], 'partial'] });
  assert.equal(blind.rows[0].effects[0].verdict, 'fail');
  assert.equal(find(blind, SRC)[0][0], 'background-unobserved');
  assert.equal(find(run(2, () => [ins('alice')]), SRC)[0][0], null);
  // A count whose units are not the matched events (another counting rule) is never decided by these intervals.
  const units = run(1, () => [ins('alice')]);
  units.rows[0].effects[0] = { ...units.rows[0].effects[0], matched: 2 };
  assert.equal(find(units, SRC)[0][0], 'background-unattributed');
});

test('keyed count (countBy, decided in applications, not sends): a background send that could be its own leaves it unattributed; with none, a pass and a too-many fail stand and a too-few fail needs every seer', () => {
  const HOST = 'hooks.example';
  const KEYED = (expected, low, high, verdict, matched) => ({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: HOST }, expected, countBy: 'idempotency-key',
    applications: { low, high, reason: null }, verdict, matched, basis: 'b', authoritative: true, custody: 'independent' });
  const OTHER_HOST = [{ id: 'other', select: { operation: 'send', name: 'other.example' } }], THIS_HOST = [{ id: 'sync', select: { operation: 'send', name: HOST } }];
  const send = () => ev('hooks', { operation: 'send', name: HOST, resource: 'POST /charge' });
  const run = (decision, sends, tail = 'complete') => {
    const l = layout([{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: HOST } }], p => p === 'own' ? [Array.from({ length: sends }, send)] : p === 'tail' ? [[], tail] : null, ['hooks']);
    l.rows[0].effects = [decision];
    return l;
  };
  // A send and its exact keyed replay are one application: the pass stands (counted in sends it would read two).
  assert.equal(find(run(KEYED(1, 1, 1, 'pass', 2), 2), OTHER_HOST)[0][0], null);
  assert.equal(find(run(KEYED(1, 1, 1, 'pass', 2), 2), THIS_HOST)[0][0], 'background-unattributed');
  // Too many applications with no background send stands; with one that could be its own it does not.
  assert.equal(find(run(KEYED(1, 2, 2, 'fail', 2), 2), OTHER_HOST)[0][0], null);
  assert.equal(find(run(KEYED(1, 2, 2, 'fail', 2), 2), THIS_HOST)[0][0], 'background-unattributed');
  // Too few: a blind seer after the check could have missed the application, when a source overlaps.
  assert.equal(find(run(KEYED(1, 0, 0, 'fail', 0), 0, 'partial'), THIS_HOST)[0][0], 'background-unobserved');
  assert.equal(find(run(KEYED(1, 0, 0, 'fail', 0), 0), THIS_HOST)[0][0], null);
  assert.equal(find(run(KEYED(1, 0, 0, 'fail', 0), 0, 'partial'), OTHER_HOST)[0][0], null);
});

test('effect.only: a fail whose only offender is background is unattributed; one with any other offender stands; a pass is untouched', () => {
  const ONLY = { kind: 'effect.only', expect: [{ select: { actor: 'alice', operation: 'insert', name: 'orders' }, count: 1 }], allow: [], sources: ['sql-audit-table'], operations: ['insert'] };
  const SRC = [{ id: 'sync', select: { actor: 'svc-sync', operation: 'insert', name: 'orders' } }];
  const own = actors => layout([ONLY], (p, o) => p === 'own' && o === 'aud' ? [actors.map(actor => ev('aud', { actor, operation: 'insert', name: 'orders', resource: `r-${seq + 1}` }))] : null);
  const bgOnly = own(['alice', 'svc-sync']);
  assert.equal(bgOnly.rows[0].effects[0].verdict, 'fail');
  assert.equal(find(bgOnly, SRC)[0][0], 'background-unattributed');
  const other = own(['alice', 'bob', 'svc-sync']);
  assert.equal(other.rows[0].effects[0].verdict, 'fail');
  assert.equal(find(other, SRC)[0][0], null);
  const pass = own(['alice']);
  assert.equal(pass.rows[0].effects[0].verdict, 'pass');
  const later = layout([ONLY], (p, o) => o !== 'aud' ? null : p === 'own' ? [[ev('aud', { actor: 'alice', operation: 'insert', name: 'orders', resource: 'r-a' })]] : p === 'later' ? [[ev('aud', { actor: 'svc-sync', operation: 'insert', name: 'orders', resource: 'r-b' })]] : null);
  assert.equal(find(later, SRC)[0][0], null, 'settlement already withholds an effect.only pass on any later committed effect it judged');
});

test('claims are clauses: a refusal claim with a later fitting background effect and a success claim resting on one are unattributed; an untriggered claim is untouched', () => {
  const select = NONE_B.select;
  const bg = () => [[ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-B' })]];
  const { rows, gaps, barriers } = layout([FILLER], (p, o) => p === 'later' && o === 'aud' ? bg() : null);
  rows[0].effects = [...rows[0].effects,
    { claim: 0, trigger: { field: '/ok' }, select, reading: 'refusal', kind: 'effect.none', verdict: 'pass', matched: 0, basis: 'b', authoritative: true, custody: 'subject-writable' },
    { claim: 1, trigger: { field: '/ok' }, select, reading: 'untriggered', kind: null, verdict: 'inconclusive', matched: 0, basis: 'b', authoritative: false, custody: null }];
  assert.deepEqual(attributionFindings(rows, gaps, barriers, { background: [SYNC] })[0], [null, 'background-unattributed', null]);
  const success = layout([FILLER], at('own', 'aud', () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-B' })));
  success.rows[0].effects = [{ claim: 0, select: { operation: 'delete', name: 'docs' }, reading: 'success', kind: 'effect.exists', verdict: 'pass', matched: 1, basis: 'b', authoritative: true, custody: 'subject-writable' }];
  assert.deepEqual(find(success)[0], ['background-unattributed']);
});

test('classifier: only committed effects are background; a null or unlisted actor fits an actor pin, a declared other principal does not; an unknown row fits any row', () => {
  const isBg = backgroundClassifier([SYNC]);
  const e = fields => ev('aud', { operation: 'delete', name: 'docs', resource: 'doc-B', ...fields });
  assert.deepEqual([e({ actor: 'svc-sync' }), e({ actor: null }), e({ actor: 'unlisted:9f' }), e({ actor: 'bob' }), e({ actor: 'svc-sync', outcome: 'denied' }), e({ actor: 'svc-sync', outcome: 'error' })].map(isBg), [true, true, true, false, false, false]);
  assert.equal(isBg(ev('aud', { actor: 'svc-sync', operation: 'insert', name: 'docs' })), false, 'another operation');
  assert.equal(isBg(ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'orders' })), false, 'another name');
  // So a worker's delete on another table still fails a table-free absence.
  const elsewhere = layout([{ kind: 'effect.none', select: { operation: 'delete' } }], at('own', 'aud', () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'orders', resource: 'o-1' })));
  assert.equal(elsewhere.rows[0].effects[0].verdict, 'fail');
  assert.equal(find(elsewhere)[0][0], null);
  // A denied worker attempt on the same row leaves an absence pass standing.
  const denied = layout([NONE_B], at('own', 'aud', () => e({ actor: 'svc-sync', outcome: 'denied' })));
  assert.equal(find(denied)[0][0], null);
  // fitsWide: an event with no row fits a row pin; one with another row does not.
  assert.equal(fitsWide(e({ actor: 'svc-sync', resource: null }), { operation: 'delete', name: 'docs', resource: 'doc-B' }), true);
  assert.equal(fitsWide(e({ actor: 'svc-sync', resource: 'doc-C' }), { operation: 'delete', name: 'docs', resource: 'doc-B' }), false);
});

test('per-check barrier and correlation tokens: a background send in the barrier withholds a host-wide absence; tokens change nothing', () => {
  const HOST = 'hooks.example', BG = [{ id: 'sync', select: { operation: 'send', name: HOST } }];
  const NONE_HOOK = { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: HOST, resource: 'POST /notify' } };
  const send = (resource, token) => () => ev('hooks', { operation: 'send', name: HOST, resource, correlation: token ? { settlementToken: token } : {} });
  const run = make => layout([NONE_HOOK], p => p === 'barrier' ? [[make()]] : null, ['hooks'], { second: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: HOST, resource: 'POST /other' } }] });
  assert.equal(find(run(send('POST /notify')), BG)[0][0], 'background-unattributed');
  assert.equal(find(run(send('POST /notify', 'ab'.repeat(16))), BG)[0][0], 'background-unattributed');
  assert.equal(find(run(send('POST /sync')), BG)[0][0], null, 'a send the clause\'s own pin excludes');
  assert.equal(find(run(send('POST /sync', 'ab'.repeat(16))), BG)[0][0], null);
  // Without barriers (run mode) the same window simply is not there.
  const noBarrier = run(send('POST /notify'));
  assert.equal(attributionFindings(noBarrier.rows, noBarrier.gaps, undefined, { background: BG })[0][0], null);
});

test('settled clauses: a boundary pass settlement withheld is left alone; a control pass settlement only tagged is still attributed; only a pass or a fail is ever touched', () => {
  const later = () => ev('aud', { actor: 'svc-sync', operation: 'delete', name: 'docs', resource: 'doc-B' });
  const boundary = layout([NONE_B], at('later', 'aud', later));
  boundary.rows[0].effects = applySettlement(boundary.rows[0].effects, ['effect-outside-window'], 'boundary');
  assert.equal(boundary.rows[0].effects[0].verdict, 'inconclusive');
  assert.equal(find(boundary)[0][0], null);
  const control = layout([NONE_B], at('later', 'aud', later));
  control.rows[0].effects = applySettlement(control.rows[0].effects, ['settlement-unobserved'], 'control');
  assert.equal(control.rows[0].effects[0].verdict, 'pass');
  assert.equal(find(control)[0][0], 'background-unattributed');
  assert.deepEqual(applyAttribution(control.rows[0].effects, ['background-unattributed'], 'control').map(d => [d.verdict, d.settlement, d.attribution]), [['pass', 'settlement-unobserved', 'background-unattributed']]);
  // A control's positive pass resting on a worker effect is withheld whether or not a later window was unobserved: a
  // weaker later window never releases what a stronger one withholds.
  const EXISTS = { kind: 'effect.exists', select: { operation: 'delete', name: 'docs' } };
  for (const settled of [null, 'settlement-unobserved']) {
    const positive = layout([EXISTS], at('own', 'aud', later));
    if (settled) positive.rows[0].effects = applySettlement(positive.rows[0].effects, [settled], 'control');
    const reasons = find(positive)[0];
    assert.equal(reasons[0], 'background-unattributed', String(settled));
    assert.equal(applyAttribution(positive.rows[0].effects, reasons, 'control')[0].verdict, 'inconclusive', String(settled));
  }
  const base = { kind: 'effect.none', select: NONE_B.select, matched: 0, basis: 'b', custody: null };
  for (const verdict of ['inconclusive', 'missing', 'unobservable', 'observer-failure']) {
    for (const role of ['boundary', 'control']) {
      const d = { ...base, verdict };
      assert.deepEqual(applyAttribution([d], ['background-unattributed'], role), [d]);
      assert.deepEqual(applyAttribution([d], ['not-a-reason'], role), [d]);
    }
  }
  assert.throws(() => applyAttribution([{ ...base, verdict: 'pass' }], ['not-a-reason']), /attribution-reason/);
  assert.deepEqual(applyAttribution([{ ...base, verdict: 'pass' }], null), [{ ...base, verdict: 'pass' }]);
  // The reasons are a list of their own: none is a settlement reason.
  assert.ok(ATTRIBUTION_REASONS.every(r => !SETTLEMENT_REASONS.includes(r) && typeof ATTRIBUTION_BASIS[r] === 'string'));
});

test('roles: a boundary pass or fail reads inconclusive; a control keeps an absence pass or a fail as a tag, and its positive pass is withheld', () => {
  const d = (kind, verdict, extra = {}) => ({ kind, select: { operation: 'insert', name: 'orders' }, verdict, matched: 0, basis: 'b', custody: null, ...extra });
  const clauses = [d('effect.exists', 'pass'), d('effect.none', 'pass'), d('effect.none', 'fail'), d('effect.count', 'pass', { expected: 1 }), d('effect.count', 'pass', { expected: 0 }), d('effect.exists', 'fail'), d('effect.only', 'fail')];
  const reasons = clauses.map(() => 'background-unattributed');
  const control = applyAttribution(clauses, reasons, 'control');
  assert.deepEqual(control.map(c => c.verdict), ['inconclusive', 'pass', 'fail', 'inconclusive', 'pass', 'fail', 'fail']);
  assert.ok(control.every(c => c.attribution === 'background-unattributed'));
  assert.deepEqual(control.map(c => c.basis === 'b'), [false, true, true, false, true, true, true]);
  const boundary = applyAttribution(clauses, clauses.map(() => 'background-unobserved'), 'boundary');
  assert.ok(boundary.every(c => c.verdict === 'inconclusive' && c.attribution === 'background-unobserved' && c.basis === `b ${ATTRIBUTION_BASIS['background-unobserved']}`));
  assert.deepEqual(attributionFields(boundary[0]), { attribution: 'background-unobserved' });
  assert.deepEqual(attributionFields(clauses[0]), {});
});

// Seeded randomized properties (as in test/http-settlement-correlation.test.mjs).
function rng(seed) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; }; }
const POOL = [
  { id: 's1', select: { actor: 'svc-sync', operation: 'insert', name: 'orders' } },
  { id: 's2', select: { actor: 'svc-retry' } },
  { id: 's3', select: { operation: 'delete', name: { prefix: 'do' } } },
  { id: 's4', select: { actor: 'svc-sync', name: 'docs' } },
];
function randomRun(r) {
  const pick = list => list[Math.floor(r() * list.length)];
  const obs = ['aud', 'snap', 'aud2', 'tel'].filter((_, i) => i === 0 || r() < 0.5);
  const events = (o, n) => Array.from({ length: n }, () => ev(o, { actor: OBS[o].scope.actorAttribution === 'none' ? null : pick(['alice', 'bob', 'svc-sync', 'svc-retry', null, 'unlisted:7c']), operation: pick(['insert', 'delete']), name: pick(['orders', 'docs']), resource: pick(['r1', 'r2', null]), outcome: r() < 0.85 ? 'committed' : 'denied' }));
  const windows = () => obs.map(o => win(o, events(o, Math.floor(r() * 3)), r() < 0.8 ? 'complete' : pick(['partial', 'failed', 'net-only'])));
  const select = () => ({ ...(r() < 0.5 ? { actor: pick(['alice', 'bob']) } : {}), operation: pick(['insert', 'delete']), name: pick(['orders', 'docs']), ...(r() < 0.4 ? { resource: pick(['r1', 'r2']) } : {}) });
  const clause = () => {
    const kind = pick(['effect.none', 'effect.exists', 'effect.count', 'effect.only']);
    if (kind === 'effect.count') { const { actor, ...s } = select(); return { kind, select: { source: 'sql-audit-table', ...s }, expected: Math.floor(r() * 3) }; }
    if (kind === 'effect.only') return { kind, expect: [{ select: select(), count: 1 + Math.floor(r() * 2) }], allow: [], sources: ['sql-audit-table'], operations: ['insert', 'delete'] };
    return { kind, select: select() };
  };
  const n = 1 + Math.floor(r() * 3), perCheck = r() < 0.5;
  const rows = Array.from({ length: n }, () => rowOf(Array.from({ length: 1 + Math.floor(r() * 2) }, clause), windows()));
  return { rows, gaps: Array.from({ length: n + 1 }, windows), barriers: perCheck ? Array.from({ length: n }, windows) : undefined, role: r() < 0.5 ? 'boundary' : 'control' };
}
test('property: attribution never flips a verdict (pass never becomes fail or the reverse; nothing undecided becomes decided)', () => {
  const r = rng(20261011);
  let withheld = 0;
  for (let trial = 0; trial < 200; trial++) {
    const { rows, gaps, barriers, role } = randomRun(r);
    const background = POOL.filter(() => r() < 0.6);
    if (!background.length) background.push(POOL[0]);
    const findings = attributionFindings(rows, gaps, barriers, { background });
    rows.forEach((row, k) => {
      const out = applyAttribution(row.effects, findings[k], role);
      out.forEach((d, i) => {
        const before = row.effects[i];
        if (!['pass', 'fail'].includes(before.verdict)) assert.deepEqual(d, before);
        else assert.ok(d.verdict === before.verdict || d.verdict === 'inconclusive', `trial ${trial}`);
        if (d.verdict !== before.verdict) withheld++;
      });
    });
  }
  assert.ok(withheld > 20, `the property exercised withholding (${withheld})`);
});
test('property: attribution is monotone (more sources, or a later window marked partial, only add findings)', () => {
  const r = rng(11102026);
  let grew = 0;
  for (let trial = 0; trial < 200; trial++) {
    const { rows, gaps, barriers } = randomRun(r);
    const small = POOL.filter(() => r() < 0.4);
    if (!small.length) small.push(POOL[Math.floor(r() * POOL.length)]);
    const large = [...small, ...POOL.filter(s => !small.includes(s) && r() < 0.6)];
    const a = attributionFindings(rows, gaps, barriers, { background: small }), b = attributionFindings(rows, gaps, barriers, { background: large });
    a.forEach((row, k) => row.forEach((f, i) => { if (f !== null) assert.notEqual(b[k][i], null, `trial ${trial} sources`); if (f === null && b[k][i] !== null) grew++; }));
    // A gap window marked partial (gaps decide no clause) only adds findings.
    const marked = gaps.map((g, j) => j === gaps.length - 1 ? g.map(w => w.scope.evidence === 'authoritative' ? { ...w, coverage: 'partial', reason: 'synthetic' } : w) : g);
    const c = attributionFindings(rows, marked, barriers, { background: large });
    b.forEach((row, k) => row.forEach((f, i) => { if (f !== null) assert.notEqual(c[k][i], null, `trial ${trial} partial`); }));
  }
  assert.ok(grew > 0, 'the property exercised a larger source set');
});

test('declaration bounds: positions only, never values; 16 sources, prefix names; refused keys, sizes and shapes', () => {
  const src = (i, select = { operation: 'update', name: `t${i}` }) => ({ id: `s${i}`, select });
  assert.equal(attributionDeclarationProblem({ background: Array.from({ length: 16 }, (_, i) => src(i)) }), null);
  assert.equal(attributionDeclarationProblem({ background: [src(0, { name: { prefix: 'audit.' } }), src(1, { actor: 'svc-sync' })] }), null);
  assert.equal(ATTRIBUTION_LIMITS.sources, 16);
  const refused = [
    [{ background: Array.from({ length: 17 }, (_, i) => src(i)) }, /1 to 16 sources/],
    [{ background: [src(0), { ...src(1), id: 's0' }] }, /background source 2: needs a unique "id"/],
    [{ background: [{ id: 'bad id', select: { name: 'x' } }] }, /background source 1: needs a unique "id"/],
    [{ background: [src(0, {})] }, /background source 1: "select" pins only actor, operation, name/],
    [{ background: [src(0, { name: 'x', extra: 1 })] }, /pins only/],
    [{ background: [src(0, { operation: 'teleport' })] }, /background source 1: "select" needs a known operation/],
    [{ background: [src(0, { name: 'x'.repeat(201) })] }, /needs a known operation and a name of at most 200/],
    [{ background: [src(0, { actor: 7 })] }, /"actor" must be a principal/],
    [{ background: [{ id: 's0', select: { name: 'x' }, note: 1 }] }, /exactly \{ id, select \}/],
    [{ background: [] }, /1 to 16 sources/],
    [{}, /attribution is \{ "background"/],
    [{ background: [src(0)], lateFails: 'withhold' }, /attribution is \{ "background"/],
    [null, /attribution is/],
  ];
  for (const key of ['source', 'outcome', 'traceId', 'fields']) refused.push([{ background: [src(0, { name: 'x', [key]: key === 'fields' ? [] : 'committed' })] }, /source, outcome, traceId and fields are refused/]);
  // A resource pin only on an egress send (test/coverage-part-c.test.mjs): anywhere else it is refused.
  refused.push([{ background: [src(0, { name: 'x', resource: 'committed' })] }, /a "resource" pin needs operation "send", an exact host/]);
  for (const [declaration, pattern] of refused) assert.match(attributionDeclarationProblem(declaration) ?? '', pattern);
  // A refusal names the position, never the declared value.
  assert.doesNotMatch(attributionDeclarationProblem({ background: [src(0, { name: 'secret-table-name', resource: 'x' })] }), /secret-table-name/);
  assert.equal(backgroundProblem(undefined), '"background" must be a list of 1 to 16 sources');
});

test('visibility: a source no observer can see is reported by position; an actor pin does not need an observer that names actors', () => {
  const observers = ['aud', 'snap', 'hooks'].map(o => ({ source: OBS[o].source, scope: OBS[o].scope }));
  const background = [{ id: 'a', select: { operation: 'send', name: 'hooks.example' } }, { id: 'b', select: { name: 'api.unknown.example' } }, { id: 'c', select: { actor: 'svc', operation: 'insert', name: 'orders' } }, { id: 'd', select: { operation: 'claim' } }];
  assert.deepEqual(backgroundUnseen(background, observers), [2, 4]);
  assert.deepEqual(backgroundUnseen(background.slice(2, 3), [{ source: OBS.snap.source, scope: OBS.snap.scope }]), [], 'the snapshot sees the worker\'s insert without its actor');
  assert.deepEqual(backgroundUnseen(background, []), [1, 2, 3, 4]);
});

test('malformed inputs are refused, never read as no finding', () => {
  const { rows, gaps, barriers } = layout([NONE_B]);
  assert.throws(() => attributionFindings(rows, gaps.slice(1), barriers, { background: [SYNC] }), /attribution-gaps/);
  assert.throws(() => attributionFindings(rows, gaps, barriers.slice(1), { background: [SYNC] }), /attribution-barriers/);
  assert.throws(() => attributionFindings(rows, gaps, barriers, { background: [{ id: 'x', select: { resource: 'r' } }] }), /attribution-background/);
  assert.throws(() => attributionFindings(rows, gaps, barriers), /attribution-background/);
});

test('record: exactly { schema, background }, revalidated', () => {
  const record = attributionRecord({ background: [SYNC] });
  assert.deepEqual(record, { schema: ATTRIBUTION_SCHEMA, background: [SYNC] });
  assert.deepEqual(validateAttributionRecord(structuredClone(record)), { background: [SYNC] });
  for (const bad of [{ ...record, schema: 'scopehaven-attribution/2' }, { ...record, lateFails: null }, { schema: ATTRIBUTION_SCHEMA }, { ...record, background: Array.from({ length: 17 }, (_, i) => ({ id: `s${i}`, select: { name: 'x' } })) }, { ...record, background: [{ id: 's', select: { resource: 'r' } }] }, null, []]) {
    assert.throws(() => validateAttributionRecord(bad), /attribution-record/);
  }
});
