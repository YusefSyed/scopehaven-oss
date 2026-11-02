// Later outcomes, the verdict stage (src/later-outcome.mjs;
// collector provider-feed/6), over synthetic windows run through the same steps the connector and the validator run: decide, settle,
// attribute, then the stage. Pure: no socket, no file, no clock. Each property sits beside the adjacent case it must not touch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { makeEffect, admitScoped, FEED_LATE_CODE } from '../src/effect-events.mjs';
import { restsOnView } from '../src/http-rests-on.mjs';
import { decideEffects, applyLater } from '../src/http-effects.mjs';
import { settlementFindings, applySettlement } from '../src/http-settlement.mjs';
import { attributionFindings, applyAttribution } from '../src/http-attribution.mjs';
import { laterFindings, laterReadings, laterReading, LATER_STAGE_LIMIT } from '../src/later-outcome.mjs';

const EXT = 'customers.example', VIP = `vip@${EXT}`, KEN = `ken@${EXT}`, AMY = `amy@${EXT}`, FEED = 'provider-feed-mail';
let seq = 0;
const send = (resource = VIP) => makeEffect({ source: 'provider-feed', observer: { kind: 'provider-feed-reader', instanceId: FEED }, seq: ++seq * 128, operation: 'send', name: EXT, resource, outcome: 'committed' });
const logged = (resource = VIP) => makeEffect({ source: 'file-audit-log', observer: { kind: 'audit-log-file', instanceId: 'audit-file-log' }, seq: ++seq, operation: 'send', name: EXT, resource, outcome: 'committed', actor: 'admin-1' });
const feedWindow = (events, coverage = 'complete') => ({ source: 'provider-feed', instanceId: FEED, scope: { operations: ['send'], names: [EXT], actorAttribution: 'none', evidence: 'authoritative' }, coverage, reason: coverage === 'complete' ? null : 'provider-feed-entry-seq-gap', events });
const logWindow = events => ({ source: 'file-audit-log', instanceId: 'audit-file-log', scope: { operations: ['send'], names: [EXT], actorAttribution: 'principal', evidence: 'authoritative' }, coverage: 'complete', reason: null, events });
const sel = extra => ({ source: 'provider-feed', operation: 'send', name: EXT, ...extra });
const exists = select => ({ kind: 'effect.exists', select });
const OBSERVERS = label => [{ id: 'mail', type: 'provider-feed', collector: { label }, feed: { feedId: 'mail', keyDigest: '0'.repeat(64), route: 'endpoint', outcomes: { waitMs: 0 } } }];
const laterOf = (words, clear = true) => [{ instanceId: FEED, clear, waitedMs: 0, records: [...words].flatMap(([e, list]) => list.map(outcome => ({ of: e.seq, outcome }))) }];

// The pipeline the connector and the validator run, up to and including the stage (pairing judges absence clauses only, so it is left out).
function judge({ rows, gaps, later, attribution = null, label = 'provider-feed/6' }) {
  const role = r => r.role ?? 'boundary';
  const raw = rows.map(r => decideEffects(r.effects, r.windows, { role: role(r) }));
  const g = gaps ?? Array.from({ length: rows.length + 1 }, () => []);
  const sf = settlementFindings(rows.map((r, k) => ({ effects: raw[k], windows: r.windows })), g, undefined, { judge: false });
  const settled = raw.map((d, k) => applySettlement(d, sf[k], role(rows[k])));
  const af = attribution ? attributionFindings(rows.map((r, k) => ({ effects: settled[k], windows: r.windows })), g, undefined, attribution) : null;
  const main = settled.map((d, k) => af ? applyAttribution(d, af[k], role(rows[k])) : d);
  const lf = laterFindings({ rows: rows.map((r, k) => ({ raw: raw[k], settled: settled[k], paired: main[k], windows: r.windows, role: role(r) })), gaps: g, correlation: undefined, judge: false, attribution,
    readingOf: laterReadings(later, OBSERVERS(label)) });
  return { main, staged: main.map((d, k) => applyLater(d, lf[k])), findings: lf };
}
const one = (effect, windows, words, extra = {}) => { const r = judge({ rows: [{ effects: [effect], windows, role: extra.role }], later: laterOf(words, extra.clear), attribution: extra.attribution ?? null, label: extra.label }); return { main: r.main[0][0], staged: r.staged[0][0] }; };

test('stage: an expected send the provider later failed is not the expected effect: exists fails on a decided window, missing on a partial one', () => {
  const s = send();
  const { main, staged } = one(exists(sel({ resource: VIP })), [feedWindow([s])], [[s, ['failed']]]);
  assert.equal(main.verdict, 'pass');
  assert.deepEqual([staged.verdict, staged.later], ['fail', 'effect-later-failed']);
  const p = send();
  const partial = one(exists(sel({ resource: VIP })), [feedWindow([p], 'partial')], [[p, ['failed']]]);
  assert.deepEqual([partial.main.verdict, partial.staged.verdict, partial.staged.later], ['pass', 'missing', 'effect-later-failed']);
});

test('stage: each reading of a matched send, and the success strength', () => {
  const cases = [
    [['succeeded', 'failed'], true, 'fail', 'effect-later-failed', undefined],
    [['failed', 'succeeded'], true, 'inconclusive', 'effect-later-conflicting', undefined],
    [['contested'], true, 'inconclusive', 'effect-later-contested', undefined],
    [['succeeded', 'contested'], true, 'inconclusive', 'effect-later-contested', undefined],
    [['contested', 'failed'], true, 'fail', 'effect-later-failed', undefined],
    [['ambiguous'], true, 'inconclusive', 'effect-later-ambiguous', undefined],
    [[], true, 'pass', undefined, undefined],
    [['deferred', 'complained'], true, 'pass', undefined, undefined],
    [['succeeded'], true, 'pass', undefined, 'succeeded'],
    [['succeeded'], false, 'inconclusive', 'effect-later-unobserved', undefined],
    [[], false, 'inconclusive', 'effect-later-unobserved', undefined],
  ];
  for (const [words, clear, verdict, later, strength] of cases) {
    const s = send();
    const { main, staged } = one(exists(sel({ resource: VIP })), [feedWindow([s])], [[s, words]], { clear });
    assert.equal(main.verdict, 'pass');
    assert.deepEqual([staged.verdict, staged.later, staged.laterStrength], [verdict, later, strength], JSON.stringify([words, clear]));
  }
});

test('stage: absence clauses and effect.only count every accepted attempt; a count over-run stays a fail', () => {
  const s = send();
  const none = one({ kind: 'effect.none', select: sel({ resource: VIP }) }, [feedWindow([s])], [[s, ['failed']]]);
  assert.equal(none.main.verdict, 'fail');
  assert.equal(none.staged, none.main, 'a forbidden send that bounced is still a forbidden attempt');
  const t = send(), only = { kind: 'effect.only', expect: [{ select: sel({ resource: VIP }), count: 1 }], allow: [] };
  const o = one(only, [feedWindow([t])], [[t, ['failed']]]);
  assert.equal(o.staged, o.main);
  const u = send();
  const count = one({ kind: 'effect.count', expected: 1, select: sel({ resource: VIP }) }, [feedWindow([u])], [[u, ['failed']]]);
  assert.deepEqual([count.main.verdict, count.staged.verdict, count.staged.later], ['pass', 'fail', 'effect-later-failed']);
  const v = send(), w = send();
  const over = one({ kind: 'effect.count', expected: 1, select: sel({ resource: VIP }) }, [feedWindow([v, w])], [[v, ['failed']], [w, ['succeeded']]]);
  assert.equal(over.main.verdict, 'fail');
  assert.equal(over.staged, over.main, 'two attempts, one bounced: still a fail against expected 1');
});

test('stage: an allowed-use control whose send later failed is withheld, tagged, never failed', () => {
  const s = send();
  const { main, staged } = one(exists(sel({ resource: VIP })), [feedWindow([s])], [[s, ['failed']]], { role: 'control' });
  assert.equal(main.verdict, 'pass');
  assert.deepEqual([staged.verdict, staged.later], ['inconclusive', 'effect-later-failed']);
});

test('stage: a record the application wrote never keeps a pass whose provider copy later failed', () => {
  for (const role of ['boundary', 'control']) {
    const s = send(), l = logged();
    const { main, staged } = one(exists({ operation: 'send', name: EXT, resource: VIP }), [feedWindow([s]), logWindow([l])], [[s, ['failed']]], { role });
    assert.equal(main.verdict, 'pass', role);
    assert.equal(staged.verdict, 'inconclusive', role);
    assert.equal(staged.later, 'effect-later-failed', role);
  }
  // Adjacent: a second independent copy that credits keeps the pass.
  const s = send(), t = send();
  const kept = one(exists(sel({ resource: VIP })), [feedWindow([s, t])], [[s, ['failed']]]);
  assert.equal(kept.staged, kept.main);
});

test('stage: judged again on the sends that remain, settlement\'s ambiguity rule applies to them', () => {
  const ken1 = send(KEN), kenLate = send(KEN), amy = send(AMY);
  const rows = [{ effects: [exists(sel({ resource: KEN }))], windows: [feedWindow([ken1])] }, { effects: [exists(sel({}))], windows: [feedWindow([kenLate, amy])] }];
  const { main, staged } = judge({ rows, later: laterOf([[amy, ['failed']]]) });
  assert.equal(main[1][0].verdict, 'pass', 'before the stage: AMY fits no earlier selector, so the pass stands');
  assert.deepEqual([staged[1][0].verdict, staged[1][0].settlement, staged[1][0].later], ['inconclusive', 'effect-ambiguous-attribution', 'effect-later-failed']);
  assert.equal(staged[0][0], main[0][0]);
});

test('stage: a fail the stage reaches goes through attribution: a later fitting send makes it late-unattributed', () => {
  const s = send(), late = send();
  const r = judge({ rows: [{ effects: [exists(sel({ resource: VIP }))], windows: [feedWindow([s])] }], gaps: [[], [feedWindow([late])]], later: laterOf([[s, ['failed']]]), attribution: { background: [], lateFails: true } });
  assert.equal(r.main[0][0].verdict, 'pass');
  assert.deepEqual([r.staged[0][0].verdict, r.staged[0][0].attribution, r.staged[0][0].later], ['inconclusive', 'late-unattributed', 'effect-later-failed']);
  // Adjacent: without the late fails declaration the same fail stands.
  const t = send(), u = send();
  const plain = judge({ rows: [{ effects: [exists(sel({ resource: VIP }))], windows: [feedWindow([t])] }], gaps: [[], [feedWindow([u])]], later: laterOf([[t, ['failed']]]) });
  assert.equal(plain.staged[0][0].verdict, 'fail');
});

test('stage: under provider-feed/5 the records are inert; only /6 judges them', () => {
  const s = send();
  const inert = one(exists(sel({ resource: VIP })), [feedWindow([s])], [[s, ['failed']]], { label: 'provider-feed/5' });
  assert.equal(inert.staged, inert.main);
});

test('stage: the fold, over every order of succeeded, failed and contested up to three words', () => {
  // A reference written from the rule's words, not from the code: conflicting once a success follows a failure; else withdrawn after
  // any failure; else contested when a contested word stands; else succeeded; else pending.
  const reference = words => {
    const firstFail = words.indexOf('failed');
    if (firstFail >= 0 && words.slice(firstFail + 1).includes('succeeded')) return 'conflicting';
    if (firstFail >= 0) return 'withdrawn';
    if (words.includes('contested')) return 'contested';
    return words.includes('succeeded') ? 'succeeded' : 'pending';
  };
  const alphabet = ['succeeded', 'failed', 'contested'];
  const all = [[]];
  for (let n = 1; n <= 3; n++) for (const prefix of all.filter(w => w.length === n - 1)) for (const a of alphabet) all.push([...prefix, a]);
  assert.equal(all.length, 40);
  for (const words of all) assert.equal(laterReading(words), reference(words), JSON.stringify(words));
});

// A small seeded generator (no clock), so a failure names its seed.
const prng = seed => () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
test('stage, the differential: over random runs a verdict only moves from pass to not-pass, only on a positive clause', () => {
  const WORDS = [[], ['succeeded'], ['failed'], ['succeeded', 'failed'], ['failed', 'succeeded'], ['contested'], ['ambiguous'], ['deferred'], ['complained', 'succeeded']];
  let moved = 0, checked = 0;
  for (let run = 0; run < 400; run++) {
    const rand = prng(run + 1), pick = list => list[Math.floor(rand() * list.length)];
    const resources = [VIP, KEN, AMY];
    const rows = [], words = [];
    for (let k = 0; k < 1 + Math.floor(rand() * 3); k++) {
      const events = Array.from({ length: Math.floor(rand() * 3) }, () => send(pick(resources)));
      for (const e of events) words.push([e, pick(WORDS)]);
      const windows = [feedWindow(events, rand() < 0.15 ? 'partial' : 'complete'), ...(rand() < 0.3 ? [logWindow([logged(pick(resources))])] : [])];
      const effects = Array.from({ length: 1 + Math.floor(rand() * 3) }, () => {
        const select = rand() < 0.2 ? { operation: 'send', name: EXT, resource: pick(resources) } : sel(rand() < 0.2 ? {} : { resource: pick(resources) });
        const kind = pick(['effect.exists', 'effect.exists', 'effect.count', 'effect.none', 'effect.only']);
        if (kind === 'effect.only') return { kind, expect: [{ select: sel({ resource: pick(resources) }), count: 1 }], allow: [sel({ resource: pick(resources) })] };
        if (kind === 'effect.count') return { kind, expected: Math.floor(rand() * 3), select: sel(select.resource ? { resource: select.resource } : {}) };
        return { kind, select };
      });
      rows.push({ effects, windows, role: rand() < 0.3 ? 'control' : 'boundary' });
    }
    const gaps = Array.from({ length: rows.length + 1 }, () => rand() < 0.3 ? [feedWindow([send(pick(resources))])] : []);
    const attribution = rand() < 0.3 ? { background: [], lateFails: true } : null;
    const { main, staged, findings } = judge({ rows, gaps, later: laterOf(words, rand() < 0.85), attribution });
    main.forEach((list, k) => list.forEach((d, c) => {
      const s = staged[k][c];
      checked++;
      const positive = d.kind === 'effect.exists' || (d.kind === 'effect.count' && d.expected >= 1);
      if (s.verdict === 'pass') assert.equal(d.verdict, 'pass', `seed ${run + 1}: a new pass`);
      if (!positive || d.verdict !== 'pass') {
        assert.equal(s, d, `seed ${run + 1}: the stage touched a clause it must not (${d.kind}, ${d.verdict})`);
        // The stage itself never reads such a clause (applyLater's own guard is a second line, not the first).
        assert.equal(findings[k][c], null, `seed ${run + 1}: a finding for a clause the stage must not read (${d.kind}, ${d.verdict})`);
      }
      if (s.verdict !== d.verdict) moved++;
    }));
  }
  assert.ok(checked > 1000 && moved > 20, `checked ${checked}, moved ${moved}`);
});

test('stage: past the per-run bound, a clause that needs judging again reads inconclusive (effect-later-limit)', () => {
  // Each check its own recipient, so no send fits an earlier check's selector (settlement would withhold those passes first).
  const rows = Array.from({ length: LATER_STAGE_LIMIT + 1 }, (_, i) => { const to = `r${i}@${EXT}`, s = send(to); return { s, row: { effects: [exists(sel({ resource: to }))], windows: [feedWindow([s])] } }; });
  const { staged } = judge({ rows: rows.map(x => x.row), later: laterOf(rows.map(x => [x.s, ['failed']])) });
  assert.equal(staged.filter(list => list[0].later === 'effect-later-limit').length, 1);
  assert.equal(staged.at(-1)[0].later, 'effect-later-limit');
});

test('stage: the copy is read as its window is: a scoped late entry that cannot be the expected send leaves the judgement decided (fail); one that could keeps it missing', () => {
  const scoped = (events, resource) => admitScoped({ ...feedWindow(events, 'partial'), reason: FEED_LATE_CODE, scoped: [{ name: EXT, resource, codes: [FEED_LATE_CODE] }] });
  const s = send();
  const other = one(exists(sel({ resource: VIP })), [scoped([s], KEN)], [[s, ['failed']]]);
  assert.deepEqual([other.main.verdict, other.staged.verdict], ['pass', 'fail']);
  const t = send();
  // A late send to the same declared address could be the expected one (a "*" entry is not a declared address, so it never fits).
  const could = one(exists(sel({ resource: VIP })), [scoped([t], VIP)], [[t, ['failed']]]);
  assert.deepEqual([could.main.verdict, could.staged.verdict], ['pass', 'missing']);
});

test('stage: rests-on reads a clause the stage tagged as tagged, so a withheld control never anchors a release', () => {
  const rowWith = extra => ({ id: 'C', severity: 'control', status: 'inconclusive', assertions: [],
    trace: [{ type: 'http-observation', data: { actorId: 'a', method: 'GET', httpStatus: 200, transportOutcome: 'complete', jsonParsed: true } }, { data: { effects: [{ kind: 'effect.exists', select: sel({ resource: VIP }), verdict: 'inconclusive', ...extra }] } }] });
  const untagged = extra => restsOnView([rowWith(extra)], { required: ['C'], failed: () => false, refusalStatusesOf: () => [], codesOf: () => [], principals: {} }).rows[0].untagged;
  assert.equal(untagged({}), true);
  assert.equal(untagged({ later: 'effect-later-failed' }), false);
  assert.equal(untagged({ laterStrength: 'succeeded' }), true, 'a strength is not a tag');
});
