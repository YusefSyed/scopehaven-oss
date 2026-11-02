// Late scoped entries (A: a decided fail or count; C: the late-entry lift) over synthetic admitted scoped egress windows (the shape
// the connector collects and the validator binds); a countBy effect.only clause under the judge is test 24 of
// test/http-settlement-judge.test.mjs, and the connector end to end is in
// test/egress-scoped-coverage.test.mjs. Pure decisions: no socket, no database, no model, no provider. Each newly decided case
// sits beside the forbidden case next to it.
//   A: a fail or count on a selector no entry could fit is decided on a scoped window whose late entries were followed.
//   C: an effect.only clause reads such a window complete toward a pass only when every entry has a resource, fits no expected
//      selector on its resource, under countBy is not on a host that records keys, and definitely fits an allowed selector pinning
//      only source, operation, name, resource.
import test from 'node:test';
import assert from 'node:assert/strict';
import { makeEffect, admitScoped, markUnfollowed, coverageFor, evaluateEffectAssertion } from '../src/effect-events.mjs';
import { decideEffects } from '../src/http-effects.mjs';
import { decidingWindows } from '../src/custody.mjs';
import { settlementFindings } from '../src/http-settlement.mjs';
import { validateIdempotencyDeclaration } from '../src/idempotency.mjs';
import { judgeOnly, onlyScopedComplete } from '../integrations/collateral/only.mjs';

const BILL = 'billing.example.test', CRM = 'crm.example.test', MAIL = 'mail.example.test', INST = 'egress-recorder-sink', INST2 = 'egress-recorder-other';
const CHARGE = 'POST /v1/charges', REFUND = 'POST /v1/refunds', SYNC = 'POST /v1/sync/contacts', CLOSE = 'POST /v1/tickets/t-1/close';
const AFTER = 'egress-request-after-witness-request', IN_FLIGHT = 'egress-request-in-flight', AMBIGUOUS = 'egress-path-ambiguous';
const SCOPE = Object.freeze({ operations: ['send'], names: [BILL, CRM], actorAttribution: 'none', evidence: 'authoritative' });
const KEYED = Object.freeze({ ...SCOPE, idempotency: { [BILL]: validateIdempotencyDeclaration({ header: 'idempotency-key' }) } });
const NO_KEY = Object.freeze({ status: 'absent', key: null, fold: null, head: 'a'.repeat(64), firstSeq: null });
const SCOPE2 = Object.freeze({ operations: ['send'], names: [MAIL], actorAttribution: 'none', evidence: 'authoritative' });
let seq = 0;
const ev = (name, resource, { instanceId = INST, ...extra } = {}) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, observedAt: '2026-10-12T00:00:00.000Z',
  operation: 'send', name, resource, outcome: 'committed', ...extra });
// A second egress recorder's window (MAIL), complete or window-wide partial.
const other = (events = [], coverage = 'complete') => ({ source: 'http-egress', instanceId: INST2, scope: SCOPE2, coverage, reason: coverage === 'complete' ? null : 'egress-scope-ineligible', events });
// A check window as the connector admits it. entries: [name, resource, codes?] in the recorder's order (host, then resource).
const scoped = (events, entries, { followed = true, scope = SCOPE } = {}) => {
  const list = entries.map(([name, resource, codes = [AFTER]]) => ({ name, resource, codes }));
  const w = admitScoped({ source: 'http-egress', instanceId: INST, scope, coverage: 'partial', reason: [...new Set(list.flatMap(e => e.codes))].sort().join(','), events, scoped: list });
  return followed ? w : markUnfollowed(w);
};
const complete = (events = [], scope = SCOPE) => ({ source: 'http-egress', instanceId: INST, scope, coverage: 'complete', reason: null, events });
const sel = (name, resource) => ({ source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}) });
const exists = (name, resource) => ({ kind: 'effect.exists', select: sel(name, resource) });
const none = (name, resource) => ({ kind: 'effect.none', select: sel(name, resource) });
const count = (name, resource, expected) => ({ kind: 'effect.count', select: sel(name, resource), expected });
const verdictOf = (clause, windows) => decideEffects([clause], windows)[0].verdict;
// effect.only: one expected charge, the CRM sync allowed.
const only = ({ expect = [sel(BILL, CHARGE)], allow = [sel(CRM, SYNC)], countBy } = {}) => ({ kind: 'effect.only', expect: expect.map(select => ({ select, count: 1 })), allow, sources: ['http-egress'], ...(countBy ? { countBy } : {}) });

// ---------------------------------------------------------------------------
// A.
test('A. a fail or a count on another destination is decided through a followed late entry; the pass rule is unchanged', () => {
  const crmLate = () => scoped([], [[CRM, SYNC]]);
  assert.equal(verdictOf(exists(BILL, CHARGE), [crmLate()]), 'fail', 'the missing write fails (was missing)');
  assert.equal(verdictOf(count(BILL, CHARGE, 1), [crmLate()]), 'fail', 'a count of 1 over 0 sends fails (was missing)');
  assert.equal(verdictOf(none(BILL, CHARGE), [crmLate()]), 'pass', 'the pass reads as before');
  assert.equal(verdictOf(count(BILL, CHARGE, 0), [crmLate()]), 'pass', 'a count that would pass reads as before');
  // An in-flight entry the drain followed reads the same.
  assert.equal(verdictOf(exists(BILL, CHARGE), [scoped([], [[CRM, SYNC, [IN_FLIGHT]]])]), 'fail');
  // Every outcome reads the same coverage now.
  const w = crmLate();
  assert.deepEqual(['pass', 'fail', 'missing'].map(outcome => coverageFor(w, sel(BILL, CHARGE), { outcome })), ['complete', 'complete', 'complete']);
  // Custody: the window that decided the fail is a deciding window for it.
  assert.deepEqual(decidingWindows([w], { kind: 'effect.exists', select: sel(BILL, CHARGE), verdict: 'fail' }).map(x => x.instanceId), [INST]);
});

test('A adjacent: a fitting entry, a path-ambiguous entry and an unfollowed window still read missing, for a fail and a pass alike', () => {
  for (const [w, why] of [[scoped([], [[BILL, CHARGE]]), 'a late send to the selected resource'], [scoped([], [[BILL, null, [AMBIGUOUS]]]), 'an ambiguous path on the selected host'],
    [scoped([], [[CRM, SYNC]], { followed: false }), 'a late entry nothing followed']]) {
    assert.equal(verdictOf(exists(BILL, CHARGE), [w]), 'missing', `fail: ${why}`);
    assert.equal(verdictOf(count(BILL, CHARGE, 1), [w]), 'missing', `count: ${why}`);
    assert.equal(verdictOf(none(BILL, CHARGE), [w]), 'missing', `pass: ${why}`);
  }
  // A copy of an admitted window is never admitted: window-wide, whatever the outcome.
  assert.equal(evaluateEffectAssertion(exists(BILL, CHARGE), [{ ...scoped([], [[CRM, SYNC]]) }], { scoped: true }).verdict, 'missing');
});

// ---------------------------------------------------------------------------
// C.
test('C. an effect.only pass reads through late sends that definitely fit an allowed selector and fit no expected one', () => {
  const w = () => scoped([ev(BILL, CHARGE)], [[CRM, SYNC]]);
  const decided = decideEffects([only()], [w()])[0];
  assert.equal(decided.verdict, 'pass', decided.basis);
  assert.match(decided.basis, /did not attribute fits an allowed selector and no expected one/);
  // Without the lift the same window reads missing.
  assert.equal(judgeOnly(only(), [w()], { fields: true, countBy: true }).verdict, 'missing');
  // An in-flight entry and a prefix allow (decided on the entry's exact text) lift alike.
  assert.equal(verdictOf(only(), [scoped([ev(BILL, CHARGE)], [[CRM, SYNC, [IN_FLIGHT]]])]), 'pass', 'in flight, drain followed');
  assert.equal(verdictOf(only({ allow: [sel(CRM, { prefix: 'POST /v1/sync' })] }), [w()]), 'pass', 'a prefix allow');
  assert.equal(verdictOf(only({ allow: [{ operation: 'send', name: CRM }] }), [w()]), 'pass', 'a name-only allow without a source pin');
  // Two entries, both allowed, in the recorder's order.
  assert.equal(verdictOf(only({ allow: [sel(CRM, SYNC), sel(CRM, 'POST *')] }), [scoped([ev(BILL, CHARGE)], [[CRM, 'POST *'], [CRM, SYNC]])]), 'pass');
});

test('C adjacent: an allow with a hidden pin, an expected could-fit, a null resource, an unfollowed window or an unallowed entry still read missing', () => {
  const w = (entries = [[CRM, SYNC]], options) => scoped([ev(BILL, CHARGE)], entries, options);
  const cases = [
    [only({ allow: [{ ...sel(CRM, SYNC), fields: [{ pointer: '/amount', equals: 5 }] }] }), w(), 'a field-pinned allow'],
    [only({ allow: [{ ...sel(CRM, SYNC), actor: 'svc' }] }), w(), 'an actor-pinned allow'],
    [only({ expect: [sel(BILL, CHARGE), sel(CRM)] }), w(), 'the entry could fit an expected selector'],
    [only({ expect: [sel(BILL, CHARGE), sel(CRM, { prefix: 'POST /v1/' })], allow: [sel(CRM, SYNC)] }), w(), 'an expected prefix the entry could fit'],
    [only({ allow: [sel(CRM)] }), w([[CRM, null, [AMBIGUOUS]]]), 'a null resource, even against a name-only allow'],
    [only(), w([[CRM, SYNC]], { followed: false }), 'an unfollowed window'],
    [only({ allow: [sel(CRM, 'POST /v1/other')] }), w(), 'no allow fits the entry'],
    [only(), w([[CRM, 'POST *'], [CRM, SYNC]]), 'one of two entries is not allowed'],
  ];
  for (const [clause, window, why] of cases) assert.equal(verdictOf(clause, [window]), 'missing', why);
  // A second recorder's window-wide gap is not lifted with the first one's (every gap must be lifted).
  const mailToo = only({ allow: [sel(CRM, SYNC), sel(MAIL)] });
  assert.equal(verdictOf(mailToo, [w(), other([], 'partial')]), 'missing', 'one lifted window, one window-wide partial');
  assert.equal(verdictOf(mailToo, [w(), other()]), 'pass', 'adjacent: the second recorder complete');
  // An event the window did not record as committed must be one of its entries' sends.
  const unknown = resource => scoped([ev(BILL, CHARGE), ev(CRM, resource, { outcome: 'unknown' })], [[CRM, SYNC]]);
  assert.equal(verdictOf(only(), [unknown('POST /v1/other')]), 'missing', 'a non-committed event no entry covers');
  assert.equal(verdictOf(only(), [unknown(SYNC)]), 'pass', 'adjacent: the entry covers it');
});

test('C adjacent: under countBy an entry anywhere on an expected selector\'s host that records keys blocks (key folds span the host); without countBy it lifts', () => {
  const w = () => scoped([ev(BILL, CHARGE, { idempotency: NO_KEY })], [[BILL, REFUND]], { scope: KEYED });
  const spec = countBy => only({ allow: [sel(BILL, REFUND)], countBy });
  assert.equal(verdictOf(spec(), [w()]), 'pass', 'no countBy: the refund is allowed and cannot be the charge');
  assert.equal(verdictOf(spec('idempotency-key'), [w()]), 'missing', 'countBy: host-wide');
  // Under countBy an entry on any host that records keys never lifts, allowed-only or not (an unseen send could
  // share a key with one seen and make it an unproven resend); a host that records no keys lifts as without countBy.
  const crmKeyed = Object.freeze({ ...SCOPE, idempotency: { [CRM]: validateIdempotencyDeclaration({ header: 'idempotency-key' }) } });
  const keyedCrm = scope => scoped([ev(BILL, CHARGE)], [[CRM, SYNC]], { scope });
  assert.equal(verdictOf(only({ countBy: 'idempotency-key' }), [keyedCrm(crmKeyed)]), 'missing', 'countBy: the allowed host records keys');
  assert.equal(verdictOf(only({ countBy: 'idempotency-key' }), [keyedCrm(SCOPE)]), 'pass', 'adjacent: countBy, the allowed host records none');
  assert.equal(verdictOf(only(), [keyedCrm(crmKeyed)]), 'pass', 'adjacent: no countBy, keys are not read');
});

// Host-wide fitting applies only on a host that records keys, whose entries never lift. On a host
// that records none, countBy judges a send as without it, so an entry there fits an expected selector only on its resource.
const CRM_KEYED = Object.freeze({ ...SCOPE, idempotency: { [CRM]: validateIdempotencyDeclaration({ header: 'idempotency-key' }) } });
const keyedOnly = (crm, allow = [sel(CRM, SYNC)]) => only({ expect: [sel(BILL, CHARGE), sel(CRM, crm)], allow, countBy: 'idempotency-key' });
const lateSync = (scope = KEYED) => scoped([ev(BILL, CHARGE, { idempotency: NO_KEY })], [[CRM, SYNC]], { scope });

test('C under countBy: a late send on a host that records no keys, to another resource than the expected one there, lifts when allowed', () => {
  // One late after-witness CRM contact sync; the clause expects a CRM ticket close and allows the sync. The window records keys
  // for the billing host only.
  const clause = keyedOnly(CLOSE), w = lateSync();
  const decided = decideEffects([clause], [w])[0];
  assert.equal(decided.verdict, 'pass', decided.basis);
  assert.match(decided.basis, /did not attribute fits an allowed selector and no expected one/);
  assert.equal(judgeOnly(clause, [lateSync()], { fields: true, countBy: true }).verdict, 'missing', 'without the lift');
  assert.equal(verdictOf(keyedOnly(CLOSE, [sel(CRM)]), [lateSync()]), 'pass', 'a whole-host allow');
  assert.equal(verdictOf(clause, [lateSync(SCOPE)]), 'pass', 'a window that records no keys at all');
  // Under the judge the pass stands when the sync lands after the check (counted as its own, worst case).
  const row = { effects: [decided], windows: [w] };
  assert.deepEqual(settlementFindings([row], [[complete([], KEYED)], [complete([ev(CRM, SYNC)], KEYED)]], undefined, { judge: true }), [['effect-outside-window-judged']]);
});

test('C under countBy adjacent: the same late send still blocks when it could be the expected send on its host', () => {
  assert.equal(verdictOf(keyedOnly(SYNC), [lateSync()]), 'missing', 'the expected selector names the entry\'s resource');
  assert.equal(verdictOf(keyedOnly({ prefix: 'POST /v1/sync' }), [lateSync()]), 'missing', 'an expected prefix the entry could fit');
});

test('C under countBy adjacent: a late send on a host that records keys still blocks (keyedHost)', () => {
  assert.equal(verdictOf(keyedOnly(CLOSE), [lateSync(CRM_KEYED)]), 'missing', 'the expected host, another resource');
  assert.equal(verdictOf(only({ countBy: 'idempotency-key' }), [scoped([ev(BILL, CHARGE)], [[CRM, SYNC]], { scope: CRM_KEYED })]), 'missing', 'no expected selector on the host');
  assert.equal(verdictOf(only({ expect: [sel(BILL, CHARGE), sel(CRM, CLOSE)] }), [lateSync(CRM_KEYED)]), 'pass', 'adjacent: no countBy, keys are not read');
});

test('C: the lift is toward a pass only; every other result is exactly the one without it', () => {
  const w = events => scoped(events, [[CRM, SYNC]]);
  const opts = { fields: true, countBy: true };
  const same = (clause, events, why) => {
    const windows = [w(events)];
    const lifted = judgeOnly(clause, windows, { ...opts, scopedComplete: onlyScopedComplete(clause, windows) });
    assert.notEqual(lifted.verdict, 'pass', why);
    assert.deepEqual(lifted, judgeOnly(clause, windows, opts), why);
  };
  same(only({ expect: [{ ...sel(BILL, CHARGE), actor: 'svc' }] }), [ev(BILL, CHARGE)], 'an unattributable expected send');
  same(only(), [ev(BILL, CHARGE), ev(BILL, REFUND)], 'an offending send');
  same(only(), [ev(BILL, CHARGE), ev(BILL, CHARGE)], 'beyond its count');
  // A claimed operation no vouching observer covers keeps the gap result (missing), never unobservable.
  const { sources, ...anySource } = only();
  const audit = { source: 'sql-audit-table', instanceId: 'sqlite-audit-db', scope: { operations: ['insert'], names: null, actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] };
  const windows = [w([ev(BILL, CHARGE)]), audit];
  const lifted = judgeOnly(anySource, windows, { ...opts, scopedComplete: onlyScopedComplete(anySource, windows) });
  assert.deepEqual([lifted.verdict, lifted], ['missing', judgeOnly(anySource, windows, opts)], 'insert has no vouching observer');
  assert.equal(sources.length, 1);
  assert.throws(() => judgeOnly(only(), [w([ev(BILL, CHARGE)])], { ...opts, scopedComplete: [w([])] }), /scoped-complete/);
});

test('C under the judge: an own scoped window carries the lift into the re-judge; a later one covers only under the declaration', () => {
  const rowOf = (effects, windows) => ({ effects: decideEffects(effects, windows), windows });
  // The late CRM sync after the witness lands in the gap after the check as a committed event.
  const own = () => rowOf([only()], [scoped([ev(BILL, CHARGE)], [[CRM, SYNC]])]);
  const first = own();
  assert.equal(first.effects[0].verdict, 'pass', first.effects[0].basis);
  const gaps = rows => [[complete()], ...rows.slice(1).map(() => [complete()]), [complete([ev(CRM, SYNC)])]];
  assert.deepEqual(settlementFindings([first], gaps([first]), undefined, { judge: true }), [['effect-outside-window-judged']], 'judged: the sync counted as its own is allowed');
  assert.deepEqual(settlementFindings([first], gaps([first]), undefined), [['effect-outside-window']], 'undeclared: the withholding rule');
  // A later check's scoped window with an allowed late sync and no event: covered under the declaration, unobserved without it.
  const before = rowOf([only()], [complete([ev(BILL, CHARGE)])]), after = rowOf([none(BILL, REFUND)], [scoped([], [[CRM, SYNC]])]);
  const quiet = [[complete()], [complete()], [complete()]];
  assert.deepEqual(settlementFindings([before, after], quiet, undefined, { judge: true })[0], [null], 'judged: the later window covers this clause');
  assert.deepEqual(settlementFindings([before, after], quiet, undefined)[0], ['settlement-unobserved'], 'undeclared: unchanged');
  // Adjacent: a later late entry this clause does not allow is still unobserved under the declaration.
  const otherLate = rowOf([none(BILL, REFUND)], [scoped([], [[CRM, 'POST *']])]);
  assert.deepEqual(settlementFindings([before, otherLate], quiet, undefined, { judge: true })[0], ['settlement-unobserved'], 'judged: an unallowed later entry');
  // A lifted own window with no candidate of its own keeps its lift when another instance's window takes one.
  const mailToo = only({ allow: [sel(CRM, SYNC), sel(MAIL)] });
  const two = rowOf([mailToo], [scoped([ev(BILL, CHARGE)], [[CRM, SYNC]]), other()]);
  assert.equal(two.effects[0].verdict, 'pass', two.effects[0].basis);
  const mailLate = [[complete(), other()], [complete(), other([ev(MAIL, 'POST *', { instanceId: INST2 })])]];
  assert.deepEqual(settlementFindings([two], mailLate, undefined, { judge: true }), [['effect-outside-window-judged']], 'the unaugmented own window stays lifted');
});
