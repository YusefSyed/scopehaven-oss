// Attribution through returned ids (src/id-closure.mjs) and its one use in background attribution
// (src/http-attribution.mjs). A returned id says which object a send concerns, never which request caused it, so a tie only
// shows a withheld effect.exists pass is the check's own: it never decides a fail, never excuses a send tied to another
// check (the IDOR counter-property), and never touches an absence clause.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { closureOwners, AMBIGUOUS } from '../src/id-closure.mjs';
import { attributionFindings, backgroundClassifier } from '../src/http-attribution.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { upstreamBound } from '../src/effect-outcome.mjs';

const PAY = 'payments.example.test', HOOKS = 'hooks.example.test';
const id = text => createHash('sha256').update(text).digest('hex');
const [A, B, C, D, X, CUS] = ['A', 'B', 'C', 'D', 'X', 'CUS'].map(id);
let seq = 0;
const observer = { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' };
// A row's correlation token (32 hex digits).
const tok = k => String(k + 1).padStart(32, 'a');
// A send: name, upstream outcome, minted digests; extra: references, echoed, token, seq, observer, eventOutcome, resource.
const send = (name, outcome, minted, extra = {}) => makeEffect({ source: 'http-egress', observer: extra.observer ?? observer, seq: extra.seq ?? ++seq, operation: 'send', name, resource: extra.resource ?? 'POST /v1',
  outcome: extra.eventOutcome ?? 'committed', content: { n: seq }, correlation: extra.token ? { settlementToken: extra.token } : {},
  upstream: { outcome, status: outcome === 'applied' ? 201 : outcome === 'rejected' ? 402 : 500, proven: true, ...(minted?.length ? { minted: [...minted].sort() } : {}), ...(extra.references ? { references: [...extra.references].sort() } : {}), ...(extra.echoed ? { echoed: [...extra.echoed].sort() } : {}) } });
const ENTRY = { upstreamPort: 47002, applied: [200, 201, 204], rejected: [402], proof: true, proofVersion: 2, ids: { minted: ['/id'], references: ['/object'] } };
const win = (events, instanceId = 'egress-recorder-sink') => ({ source: 'http-egress', instanceId, coverage: 'complete', reason: null, events,
  scope: { operations: ['send'], names: [PAY, HOOKS], actorAttribution: 'none', evidence: 'authoritative', forward: { [PAY]: ENTRY, [HOOKS]: ENTRY } } });
const background = [{ id: 'sync', select: { operation: 'send', name: HOOKS } }];
const isBg = backgroundClassifier(background);
// Closures with only the background test for seeds (the selector tests are exercised through attributionFindings below).
const owners = (rowEvents, gapEvents = []) => {
  const rows = rowEvents.map(events => ({ windows: [win(events)] }));
  const gaps = Array.from({ length: rows.length + 1 }, (_, j) => gapEvents[j] ? [win(gapEvents[j])] : []);
  return closureOwners(rows, gaps, undefined, e => !isBg(e));
};

test('closures: minted ids of a check\'s own applied sends seed; a later send tied to one closure joins with its minted ids only', () => {
  const seed = send(PAY, 'applied', [A]);
  const hook = send(HOOKS, 'applied', [B], { references: [A] });   // tied through a reference; its minted B joins
  const later = send(PAY, 'unknown', [], { references: [B] });       // tied through B, in a gap
  const stray = send(PAY, 'applied', [C]);                           // in a gap: no check's own window
  const owner = owners([[seed, hook]], [[], [later, stray]]);
  assert.deepEqual([seed, hook, later, stray].map(owner), [0, 0, 0, null]);
  // References never seed or join: a shared customer id ties nothing.
  const s0 = send(PAY, 'applied', [A], { references: [CUS] }), statement = send(HOOKS, 'applied', [], { references: [CUS] });
  assert.equal(owners([[s0, statement]])(statement), null, 'a reference in a seed reply is not this check\'s object');
  // A background-possible send never seeds; neither does one whose outcome is not applied, or one not committed.
  const bgSeed = send(HOOKS, 'applied', [D]), rejectedSeed = send(PAY, 'rejected', [D]), uncommitted = send(PAY, 'unknown', [D], { eventOutcome: 'unknown' });
  const after = send(PAY, 'unknown', [], { references: [D] });
  assert.equal(owners([[bgSeed, rejectedSeed, uncommitted]], [[], [after]])(after), null);
});

test('closures: contested ids tie nothing anywhere, also earlier; order is causal; recorders are separate', () => {
  // X minted by two sends (two seeds) is no one object: the tie that came before the second seed is undone too.
  const s0 = send(PAY, 'applied', [X]), early = send(HOOKS, 'applied', [], { references: [X] }), s1 = send(PAY, 'applied', [X]), late = send(HOOKS, 'applied', [], { references: [X] });
  assert.deepEqual([early, late].map(owners([[s0, early], [s1, late]])), [null, null]);
  // A second mint by any send (here an untied one in a gap) contests the id run-wide: the earlier tie is undone.
  const m0 = send(PAY, 'applied', [X]), tieM = send(HOOKS, 'applied', [], { references: [X] }), remint = send(PAY, 'unknown', [X]);
  assert.deepEqual([m0, tieM].map(owners([[m0, tieM]], [[], [remint]])), [0, null]);
  // A send hitting two closures is ambiguous.
  const a0 = send(PAY, 'applied', [A]), b1 = send(PAY, 'applied', [B]), both = send(HOOKS, 'applied', [], { references: [A, B] });
  assert.equal(owners([[a0], [b1]], [[], [], [both]])(both), AMBIGUOUS);
  // A send carrying an id before any closure holds it is untied, even though the id is minted later.
  const before = send(HOOKS, 'unknown', [], { references: [C], seq: 1000 }), seedC = send(PAY, 'applied', [C], { seq: 1001 });
  assert.equal(owners([[], [seedC]], [[before], [], []])(before), null);
  // Another recorder's sends with the same digests are not tied to this recorder's closures.
  const other = { kind: 'http-egress-recorder', instanceId: 'egress-recorder-other' };
  const s = send(PAY, 'applied', [D]), elsewhere = send(HOOKS, 'applied', [], { references: [D], observer: other });
  assert.equal(closureOwners([{ windows: [win([s])] }], [[], [win([elsewhere], 'egress-recorder-other')]], undefined, e => !isBg(e))(elsewhere), null);
});

// The attribution matrix: background sources are HOOKS sends.
const sel = (name, extra = {}) => ({ source: 'http-egress', operation: 'send', name, ...extra });
const clause = (kind, verdict, select = sel(HOOKS), extra = {}) => ({ kind, select, verdict, matched: 0, ...extra });
const findingsOf = (rows, gapEvents = []) => {
  const r = rows.map(([effects, events]) => ({ effects, windows: [win(events)] }));
  const gaps = Array.from({ length: r.length + 1 }, (_, j) => gapEvents[j] ? [win(gapEvents[j])] : []);
  return attributionFindings(r, gaps, undefined, { background, tokens: tokensFor ?? new Map(r.map((_, k) => [tok(k), k])) });
};
let tokensFor;
// A charge minting A, sent by row k (it carries row k's correlation token).
const charge = (k = 0) => send(PAY, 'applied', [A], { token: tok(k) });
const notifyA = () => send(HOOKS, 'applied', [], { references: [A] });
const ownCheck = (second = clause('effect.exists', 'pass')) => [clause('effect.exists', 'pass', sel(PAY)), second];

test('the one use: a matched background-possible send tied to this check\'s own object keeps its effect.exists pass', () => {
  // The check's own PAY send (fitting its own selector) mints A; the notification about A is its own.
  assert.equal(findingsOf([[ownCheck(), [charge(), notifyA()]]])[0][1], null);
  // Tied to nothing the check minted: withheld as before.
  assert.equal(findingsOf([[ownCheck(), [charge(), send(HOOKS, 'applied', [], { references: [C] })]]])[0][1], 'background-unattributed');
  // A seed must fit one of the check's own selectors: a PAY send the check does not select seeds nothing.
  assert.equal(findingsOf([[[clause('effect.exists', 'pass')], [charge(), notifyA()]]])[0][0], 'background-unattributed');
  // Fails, absence clauses and effect.count are exactly background attribution's, even with a tie to this check.
  assert.equal(findingsOf([[ownCheck(clause('effect.none', 'fail')), [charge(), notifyA()]]])[0][1], 'background-unattributed');
  assert.equal(findingsOf([[ownCheck(clause('effect.count', 'pass', sel(HOOKS), { expected: 1, matched: 1 })), [charge(), notifyA()]]])[0][1], 'background-unattributed');
});

test('B1: an earlier check\'s late send in a later check\'s window seeds nothing; IDOR: a tie to another check never helps', () => {
  // J (row 0) selects PAY; its job runs late, inside K's window: a PAY charge minting A and a notification about A. K
  // (row 1) selects PAY and HOOKS, so the charge fits K's selectors too, but it fits J's earlier selector: no seed.
  const J = [clause('effect.exists', 'fail', sel(PAY))];
  // Even carrying K's token (an application that leaks the current request's token onto a job), the earlier selector bars it.
  assert.equal(findingsOf([[J, []], [ownCheck(), [charge(1), notifyA()]]])[1][1], 'background-unattributed', 'K\'s notification is not K\'s own');
  // The reviewer's variant: J declares only refunds, so its late charge fits no earlier selector; it carries J's token, not
  // K's, so it seeds nothing either.
  const Jrefund = [clause('effect.exists', 'pass', sel(PAY, { resource: 'POST /v1/refunds' }))];
  assert.equal(findingsOf([[Jrefund, []], [ownCheck(), [charge(0), notifyA()]]])[1][1], 'background-unattributed');
  assert.equal(findingsOf([[Jrefund, []], [ownCheck(), [charge(1), notifyA()]]])[1][1], null, 'with K\'s own token the charge is K\'s seed');
  // Without correlation tokens nothing seeds: returned ids decide nothing.
  tokensFor = new Map();
  assert.equal(findingsOf([[ownCheck(), [charge(), notifyA()]]])[0][1], 'background-unattributed');
  tokensFor = undefined;
  // IDOR (pinned): OWN mints A; M, a boundary check, makes the app notify about A. The tie is to OWN, so M's effect.none fail
  // stays unattributed, its effect.exists pass stays withheld, and a later notification never releases M's effect.none pass
  // or decides its effect.exists fail.
  assert.equal(findingsOf([[ownCheck(), [charge(), notifyA()]], [[clause('effect.none', 'fail')], [notifyA()]]])[1][0], 'background-unattributed');
  assert.equal(findingsOf([[ownCheck(), [charge(), notifyA()]], [[clause('effect.exists', 'pass')], [notifyA()]]])[1][0], 'background-unattributed');
  assert.equal(findingsOf([[ownCheck(), [charge(), notifyA()]], [[clause('effect.none', 'pass')], []]], [[], [], [notifyA()]])[1][0], 'background-unattributed');
  assert.equal(findingsOf([[ownCheck(), [charge(), notifyA()]], [[clause('effect.exists', 'fail')], []]], [[], [], [notifyA()]])[1][0], 'background-unattributed');
});

test('binding: minted and referenced ids only on a proven send of a name that declares ids', () => {
  const v1Entry = { upstreamPort: 47002, applied: [200, 201, 204], rejected: [402], proof: true };
  const withEntry = (entry, events) => ({ ...win(events), scope: { ...win([]).scope, forward: { [PAY]: entry, [HOOKS]: entry } } });
  assert.equal(upstreamBound(withEntry(ENTRY, [send(PAY, 'applied', [A], { references: [B] })])), true);
  assert.equal(upstreamBound(withEntry(v1Entry, [send(PAY, 'applied', [A])])), false, 'a /1 destination declares no ids');
  assert.equal(upstreamBound(withEntry(v1Entry, [send(PAY, 'applied', [], { references: [A] })])), false);
  assert.equal(upstreamBound(withEntry(v1Entry, [send(PAY, 'applied', null)])), true);
  const forge = upstream => () => makeEffect({ source: 'http-egress', observer, seq: ++seq, operation: 'send', name: PAY, resource: 'POST /v1', outcome: 'committed', content: {}, upstream });
  assert.throws(forge({ outcome: 'unknown', status: 200, proven: false, minted: [A] }), /upstream/, 'ids need a proof');
  for (const list of [[], [A, A], [B, A].sort().reverse(), ['F'.repeat(64)], Array.from({ length: 9 }, (_, i) => id(String(i))).sort()])
    for (const key of ['minted', 'references', 'echoed']) assert.throws(forge({ outcome: 'applied', status: 201, proven: true, [key]: list }), /upstream/, `${key} ${JSON.stringify(list).slice(0, 30)}`);
  assert.throws(forge({ outcome: 'applied', status: 201, proven: true, returned: [A] }), /upstream/, 'no other key');
});

test('mutation guards: one per property', () => {
  // M1: seeds exclude background-possible sends.
  const bgOnly = send(HOOKS, 'applied', [A]), afterBg = send(PAY, 'unknown', [], { references: [A] });
  assert.equal(owners([[bgOnly]], [[], [afterBg]])(afterBg), null);
  // M2: seeds need an applied outcome.
  const rejected = send(PAY, 'rejected', [A]), afterRejected = send(PAY, 'unknown', [], { references: [A] });
  assert.equal(owners([[rejected]], [[], [afterRejected]])(afterRejected), null);
  // M3: a send tying two closures is ambiguous, never the first one found.
  const t0 = send(PAY, 'applied', [A]), t1 = send(PAY, 'applied', [B]), tie2 = send(HOOKS, 'applied', [], { references: [A, B] });
  assert.equal(owners([[t0], [t1]], [[], [], [tie2]])(tie2), AMBIGUOUS);
  // M5: an echoed value contests its id everywhere, also an earlier tie.
  const e0 = send(PAY, 'applied', [X]), tieE = send(HOOKS, 'applied', [], { references: [X] }), echo = send(PAY, 'unknown', [], { echoed: [X] });
  assert.deepEqual([e0, tieE].map(owners([[e0, tieE]], [[], [echo]])), [0, null]);
  // M6: a recorder with an incomplete window ties nothing.
  const p0 = send(PAY, 'applied', [A]), tieP = send(HOOKS, 'applied', [], { references: [A] });
  const partialGap = { ...win([]), coverage: 'partial', reason: 'egress-request-in-flight' };
  assert.equal(closureOwners([{ windows: [win([p0, tieP])] }], [[], [partialGap]], undefined, e => !isBg(e))(tieP), null);
  // M7: a seed needs its own check's token (the earlier rule aside, a send with another row's token never seeds).
  assert.equal(findingsOf([[[clause('effect.exists', 'pass', sel(PAY, { resource: 'GET /none' }))], []], [ownCheck(), [charge(0), notifyA()]]])[1][1], 'background-unattributed');
  // M4: references never join a closure.
  const s = send(PAY, 'applied', [A]), viaRef = send(HOOKS, 'applied', [], { references: [A, C] }), viaC = send(PAY, 'unknown', [], { references: [C] });
  assert.deepEqual([viaRef, viaC].map(owners([[s]], [[], [viaRef, viaC]])), [0, null]);
});

test('differential compat against the frozen build: without a tie, attribution findings are exactly background attribution\'s', async () => {
  const frozen = await import(fileURLToPath(new URL('./fixtures/http-attribution-4e7001d.mjs', import.meta.url)));
  let state = 7;
  const rand = n => { state = (state * 1103515245 + 12345) % 2147483648; return (state >>> 16) % n; };
  const pick = list => list[rand(list.length)];
  const kinds = [['effect.none', {}], ['effect.exists', {}], ['effect.count', { expected: 1 }], ['effect.count', { expected: 0 }]];
  const selectors = [sel(HOOKS), sel(PAY), sel(PAY, { resource: 'POST /v1' }), { source: 'http-egress', name: { prefix: 'hooks' } }];
  // Events that tie nothing: no ids, ids only on background or not-applied sends (no seed), or references to nothing minted.
  const event = () => pick([
    () => send(HOOKS, 'unknown', null), () => send(PAY, 'unknown', null), () => send(HOOKS, 'applied', [pick([A, B])]),
    () => send(PAY, 'rejected', [C]), () => send(PAY, 'unknown', null, { eventOutcome: 'unknown' }), () => send(HOOKS, 'applied', [], { references: [D] }),
  ])();
  let compared = 0;
  for (let i = 0; i < 400; i++) {
    const n = 1 + rand(3);
    const rows = Array.from({ length: n }, () => {
      const events = Array.from({ length: rand(4) }, event);
      const effects = Array.from({ length: 1 + rand(2) }, () => { const [kind, extra] = pick(kinds); return { kind, select: pick(selectors), verdict: pick(['pass', 'fail', 'inconclusive']), matched: rand(3), ...extra }; });
      return { effects, windows: [win(events)] };
    });
    const gaps = Array.from({ length: n + 1 }, () => rand(2) ? [win(Array.from({ length: rand(3) }, event))] : []);
    assert.deepEqual(attributionFindings(rows, gaps, undefined, { background, tokens: new Map(rows.map((_, k) => [tok(k), k])) }), frozen.attributionFindings(rows, gaps, undefined, { background }), `case ${i}`);
    compared += rows.reduce((t, r) => t + r.effects.length, 0);
  }
  assert.ok(compared > 600, `compared ${compared} clauses`);
});

test('differential with ties: the only difference from 4e7001d is a withheld effect.exists pass released', async () => {
  const frozen = await import(fileURLToPath(new URL('./fixtures/http-attribution-4e7001d.mjs', import.meta.url)));
  let state = 11;
  const rand = n => { state = (state * 1103515245 + 12345) % 2147483648; return (state >>> 16) % n; };
  const pick = list => list[rand(list.length)];
  const kinds = [['effect.none', {}], ['effect.exists', {}], ['effect.count', { expected: 1 }], ['effect.count', { expected: 0 }]];
  const selectors = [sel(HOOKS), sel(PAY), { source: 'http-egress', name: { prefix: 'hooks' } }];
  let compared = 0, released = 0;
  for (let i = 0; i < 600; i++) {
    const n = 1 + rand(3);
    const rowId = Array.from({ length: n }, (_, k) => id(`case ${i} row ${k}`));
    const rows = Array.from({ length: n }, (_, k) => {
      const own = rowId[k], other = rowId[(k + 1) % n];
      const events = [
        ...(rand(4) ? [send(PAY, 'applied', [rand(5) ? own : other], { token: tok(rand(4) ? k : (k + 1) % n) })] : []),
        ...Array.from({ length: 1 + rand(2) }, () => pick([() => send(HOOKS, 'applied', [], { references: [rand(3) ? own : other] }), () => send(HOOKS, 'applied', [pick([own, C])]), () => send(PAY, 'unknown', null)])()),
      ];
      const effects = [clause('effect.exists', pick(['pass', 'fail']), sel(PAY)), clause('effect.exists', pick(['pass', 'pass', 'fail']), sel(HOOKS)),
        ...Array.from({ length: rand(2) }, () => { const [kind, extra] = pick(kinds); return { kind, select: pick(selectors), verdict: pick(['pass', 'fail', 'inconclusive']), matched: rand(3), ...extra }; })];
      return { effects, windows: [win(events)] };
    });
    const gaps = Array.from({ length: n + 1 }, () => rand(2) ? [win([send(HOOKS, 'applied', [], { references: [pick([...rowId, C])] })])] : []);
    const now = attributionFindings(rows, gaps, undefined, { background, tokens: new Map(rows.map((_, k) => [tok(k), k])) }), then = frozen.attributionFindings(rows, gaps, undefined, { background });
    rows.forEach((row, k) => row.effects.forEach((d, j) => {
      compared++;
      if (now[k][j] === then[k][j]) return;
      released++;
      assert.deepEqual([d.kind, d.verdict, then[k][j], now[k][j]], ['effect.exists', 'pass', 'background-unattributed', null], `case ${i} row ${k} clause ${j}`);
    }));
  }
  assert.ok(released > 10 && compared > 1500, `compared ${compared}, released ${released}`);
});
