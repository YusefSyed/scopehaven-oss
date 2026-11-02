// effect.only with countBy "idempotency-key": on a host whose egress window records keys, an exact
// keyed replay of a send is that send's application, not one more effect; any other later send under a reused key is undecided,
// so it can never pass. Pure unit tests over synthetic windows (no I/O).
import test from 'node:test';
import assert from 'node:assert/strict';
import { judgeOnly, validateOnlyAssertion } from '../integrations/collateral/only.mjs';
import { validateIdempotencyDeclaration, keyedReplays, countApplications } from '../src/idempotency.mjs';
import { makeEffect, validateWindow } from '../src/effect-events.mjs';
import { decideEffects, effectAssertionRows, validateDeclaredEffect } from '../src/http-effects.mjs';
import { validateTargetFile } from '../src/contracts.mjs';
import { attributionFindings } from '../src/http-attribution.mjs';

const HOST = 'payments.example.test';
const decl = validateIdempotencyDeclaration({ header: 'idempotency-key' });
const hex = c => c.repeat(64);
const observer = { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' };
// Each key's first use in these windows: key 1 at seq 1, key 2 at seq 2 (a window may state an earlier one explicitly).
const FIRST = { 1: 1, 2: 2 };
const send = (seq, { key = null, status = key === null ? 'absent' : 'keyed', content = 'c', head = 'a', firstSeq = null, resource = 'POST /v1/refunds', name = HOST, upstream } = {}) => makeEffect({
  source: 'http-egress', observer, seq, operation: 'send', name, resource, outcome: 'committed', content: { c: content },
  idempotency: { status, key: key === null ? null : hex(key), fold: key === null ? null : hex(key), head: hex(head), firstSeq: key === null ? null : firstSeq ?? FIRST[key] ?? seq }, ...(upstream ? { upstream } : {}) });
const scopeOf = (extra = {}) => ({ operations: ['send'], names: [HOST], actorAttribution: 'none', evidence: 'authoritative', idempotency: { [HOST]: decl }, ...extra });
const win = (events, scope = scopeOf()) => validateWindow({ source: 'http-egress', instanceId: 'egress-recorder-sink', scope, coverage: 'complete', reason: null, events });
const refunds = { source: 'http-egress', operation: 'send', name: HOST, resource: 'POST /v1/refunds' };
const only = (extra = {}) => ({ kind: 'effect.only', expect: [refunds], allow: [], operations: ['send'], countBy: 'idempotency-key', ...extra });
const { countBy, ...plainOnly } = only();
const judge = (events, clause = only(), scope) => judgeOnly(clause, [win(events, scope)], { fields: true, countBy: clause.countBy !== undefined });
const verdict = (events, clause, scope) => judge(events, clause, scope).verdict;

test('countBy on effect.only: HTTP clauses opt in; every other caller, and any other value, is refused', () => {
  assert.equal(countBy, 'idempotency-key');
  assert.doesNotThrow(() => validateOnlyAssertion(only(), 'x', { fields: true, countBy: true }));
  assert.throws(() => validateOnlyAssertion(only(), 'x', { fields: true }), e => e.code === 'count-by', 'collateral and other callers do not opt in');
  assert.throws(() => judgeOnly(only(), [win([])]), e => e.code === 'count-by');
  for (const value of ['idempotency', 'Idempotency-Key', null, true, ['idempotency-key']]) assert.throws(() => validateOnlyAssertion(only({ countBy: value }), 'x', { fields: true, countBy: true }), e => e.code === 'count-by', JSON.stringify(value));
  assert.doesNotThrow(() => validateDeclaredEffect(only(), 'effect 1'));
});

test('an exact keyed replay counts with its application; without countBy it is a second send outside the count', () => {
  const retry = [send(1, { key: '1' }), send(2, { key: '1' })];
  const d = judge(retry);
  assert.equal(d.verdict, 'pass', d.basis);
  assert.match(d.basis, /1 exact keyed replay\(s\) counted with their application/);
  assert.equal(d.counts.judged, 1);
  assert.equal(verdict(retry, plainOnly), 'fail', 'today: beyond the expected count');
  // A rejected-then-retried exact replay on a forwarded host: one application.
  const forward = { [HOST]: { upstreamPort: 47100, applied: [200, 201], rejected: [402], proof: true } };
  const declined = { outcome: 'rejected', status: 402, proven: true }, applied = { outcome: 'applied', status: 201, proven: true };
  assert.equal(verdict([send(1, { key: '1', upstream: declined }), send(2, { key: '1', upstream: applied })], only(), scopeOf({ forward })), 'pass');
});

test('anything that is not provably one application widens: undecided, so never a pass', () => {
  const missing = (events, why, scope) => { const d = judge(events, only(), scope); assert.equal(d.verdict, 'missing', `${why}: ${d.basis}`); return d; };
  assert.match(missing([send(1, { key: '1' }), send(2, { key: '1', content: 'd' })], 'content differs').basis, /not provably replays .*differ in content/);
  missing([send(2, { key: '1', firstSeq: 1 }), send(3, { key: '1', firstSeq: 1 })], 'the key was first used before this window');
  missing([send(1, { key: '1', status: 'overlap' }), send(2, { key: '1', status: 'overlap' })], 'concurrent sends under one key');
  // A send whose key could not be read makes every key group unprovable (expected count 2 keeps that send itself within the count).
  const two = only({ expect: [{ select: refunds, count: 2 }] });
  assert.equal(verdict([send(1, { key: '1' }), send(2, { key: '1' }), send(3, { status: 'unreadable' })], two), 'missing', 'a dirty window');
  assert.equal(verdict([send(1, { key: '1' }), send(2, { key: '1' }), send(3)], two), 'pass', 'a definite absence is not dirty');
  // On a forwarded host with no proven outcome, nothing is known to have applied.
  const forward = { [HOST]: { upstreamPort: 47100, applied: [200, 201], rejected: [402], proof: true } };
  missing([send(1, { key: '1' }), send(2, { key: '1' })], 'no proven outcome', scopeOf({ forward }));
});

test('countBy never hides an effect: two keys are two applications, a replayed offender still fails, unkeyed hosts are unchanged', () => {
  assert.equal(verdict([send(1, { key: '1' }), send(2, { key: '2' })]), 'fail', 'two keys for one refund');
  const payout = verdict([send(1, { key: '1', resource: 'POST /v1/payouts' }), send(2, { key: '1', resource: 'POST /v1/payouts' })]);
  assert.equal(payout, 'fail', 'the standing send is outside the declared set');
  // A rejected send under the key with another identity is judged on its own.
  const forward = { [HOST]: { upstreamPort: 47100, applied: [200, 201], rejected: [402], proof: true } };
  assert.equal(verdict([send(1, { key: '1', content: 'x', upstream: { outcome: 'rejected', status: 402, proven: true } }), send(2, { key: '1', upstream: { outcome: 'applied', status: 201, proven: true } })], only(), scopeOf({ forward })), 'fail');
  // A window that records no keys for the host: every send is judged as without countBy.
  const { idempotency, ...unkeyed } = scopeOf();
  assert.equal(verdict([send(1, { key: '1' }), send(2, { key: '1' })], only(), unkeyed), 'fail');
  assert.equal(idempotency[HOST], decl);
});

test('keyedReplays collapses exactly the groups countApplications counts as one decided application', () => {
  const cases = [
    [send(1, { key: '1' }), send(2, { key: '1' })],
    [send(1, { key: '1' }), send(2, { key: '1' }), send(3, { key: '1' })],
    [send(1, { key: '1' }), send(2, { key: '1', content: 'd' })],
    [send(2, { key: '1', firstSeq: 1 }), send(3, { key: '1', firstSeq: 1 })],
    [send(1, { key: '1' }), send(2, { key: '2' }), send(3, { key: '2' })],
    [send(1, { key: '1' }), send(2, { key: '1' }), send(3, { status: 'malformed' })],
  ];
  for (const events of cases) {
    const w = win(events), r = keyedReplays(w, HOST), a = countApplications(w, HOST, events);
    // Every send not dropped as a replay is judged or undecided; when nothing is undecided the judged sends are the applications.
    if (!r.unproven.size) assert.equal(events.length - r.replay.size, a.low, JSON.stringify(a));
    else assert.ok(a.low < a.high, JSON.stringify(a));
  }
});

test('HTTP evaluator: the clause records countBy and its rows say how replays count', () => {
  const [d] = decideEffects([only()], [win([send(1, { key: '1' }), send(2, { key: '1' })])]);
  assert.deepEqual([d.kind, d.countBy, d.verdict, Object.hasOwn(d, 'applications')], ['effect.only', 'idempotency-key', 'pass', false]);
  assert.match(effectAssertionRows([d])[0].expected, /an exact keyed replay counts with its application/);
  const [raw] = decideEffects([plainOnly], [win([send(1, { key: '1' }), send(2, { key: '1' })])]);
  assert.deepEqual([raw.verdict, Object.hasOwn(raw, 'countBy')], ['fail', false]);
});

test('profile: an effect.only countBy clause needs an egress-recorder destination that records keys', () => {
  const profile = idempotency => ({ id: 't', name: 'T', applicationId: 'a', origin: 'http://127.0.0.1:4000', buildLabel: 'b', contextId: 'c', actors: { u: { principalId: 'u' } }, requiredControlIds: ['C'],
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40998, routing: 'proxy', destinations: [{ host: HOST, ...(idempotency ? { idempotency } : {}) }], witness: { actorId: 'u', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 }],
    checks: [{ id: 'C', title: 'c', category: 'x', severity: 'control', actorId: 'u', method: 'GET', path: '/c', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'R', title: 'r', category: 'x', severity: 'high', actorId: 'u', method: 'POST', path: '/r', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [only()] }] });
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [profile({ header: 'idempotency-key' })] }));
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [profile(null)] }), /effect-only-count-by-unrecorded/);
});

// Settlement and attribution re-judge an effect.only clause with its countBy, and an
// unproven resend that fits no declared selector stays a fail.
test('re-judges keep countBy: a late or background effect removed leaves the keyed retry one application, so the fail is released', () => {
  const EARLY = 'POST /v1/early', BG_HOST = 'crm.example.test';
  const scope = scopeOf({ names: [HOST, BG_HOST] });
  // Row 0, an earlier check whose selector the late refund fits; row 1, the keyed clause: its own refund, an exact keyed retry,
  // and one more effect outside the declared set that fails it.
  const rows = extra => {
    const w0 = win([], scope), w1 = win([send(1, { key: '1' }), send(2, { key: '1' }), extra], scope);
    return [{ effects: decideEffects([{ kind: 'effect.exists', select: { ...refunds, resource: EARLY } }], [w0]), windows: [w0] }, { effects: decideEffects([only()], [w1]), windows: [w1] }];
  };
  const gaps = [[win([], scope)], [win([], scope)], [win([], scope)]];
  const late = rows(send(3, { key: '3', resource: EARLY, head: 'e' }));
  assert.equal(late[1].effects[0].verdict, 'fail', 'the late refund is outside the declared set');
  assert.equal(attributionFindings(late, gaps, undefined, { background: [], lateFails: true })[1][0], 'late-unattributed');
  const bg = rows(send(3, { name: BG_HOST, resource: 'POST /sync' }));
  assert.equal(bg[1].effects[0].verdict, 'fail');
  assert.equal(attributionFindings(bg, gaps, undefined, { background: [{ id: 'crm', select: { operation: 'send', name: BG_HOST } }] })[1][0], 'background-unattributed');
});

test('an unproven resend that fits no declared selector stays on the offending path: a fail, not missing', () => {
  // One key reused for an in-set refund and an out-of-set payout (another target, so another head): not one application.
  const reused = judge([send(1, { key: '1' }), send(2, { key: '1', resource: 'POST /v1/payouts', head: 'b' })]);
  assert.equal(reused.verdict, 'fail', reused.basis);
  // A changed in-set resend under the key is still undecided.
  assert.equal(verdict([send(1, { key: '1' }), send(2, { key: '1', content: 'd' })]), 'missing');
});

// Operator hint (basis text only): without countBy on a clause that could opt in, a fail names the beyond-count sends countBy would
// read as exact keyed replays of a judged send. Every decision field matches the same judge with the hint off (a caller that cannot
// opt in), and the basis differs only by the hint.
test('without countBy, a fail names the beyond-count sends countBy would count with their application; nothing else changes', () => {
  const hinted = (events, clause = plainOnly, extra = {}) => judgeOnly(clause, [win(events)], { fields: true, countBy: true, ...extra });
  const unhinted = (events, clause = plainOnly, extra = {}) => judgeOnly(clause, [win(events)], { fields: true, ...extra });
  const hint = n => `; ${n} of them exact keyed replay(s) of a judged send (countBy "idempotency-key" would count them with their application).`;
  const same = (events, clause, extra) => {
    const { basis: a, ...withHint } = hinted(events, clause, extra), { basis: b, ...without } = unhinted(events, clause, extra);
    assert.deepEqual(withHint, without, 'verdict, counts and offending are untouched');
    assert.ok(!b.includes('keyed replay(s) of a judged send'), b);
    return { a, b };
  };
  const one = same([send(1, { key: '1' }), send(2, { key: '1' })]);
  assert.equal(hinted([send(1, { key: '1' }), send(2, { key: '1' })]).verdict, 'fail');
  assert.equal(one.a, `${one.b.slice(0, -1)}${hint(1)}`, 'the exact replay is named');
  const mixed = same([send(1, { key: '1' }), send(2, { key: '1' }), send(3, { key: '2', firstSeq: 3 })]);
  assert.equal(mixed.a, `${mixed.b.slice(0, -1)}${hint(1)}`, 'counted: a different-key resend is beyond the count but no replay');
  for (const [events, why] of [[[send(1, { key: '1' }), send(2, { key: '2' })], 'a resend under a different key'], [[send(1, { key: '1' }), send(2, { key: '1', content: 'd' })], 'a resend whose content differs'],
    [[send(1, { key: '1', resource: 'POST /v1/payouts' }), send(2, { key: '1', resource: 'POST /v1/payouts' })], 'an exact replay outside the declared set, never beyond the count']]) {
    const r = same(events);
    assert.equal(r.a, r.b, why);
  }
  const separated = [send(1, { key: '1' }), send(2, { key: '1' })];
  const sep = same(separated, plainOnly, { separate: new Set([separated[0]]) });
  assert.equal(sep.a, sep.b, 'a send countBy never reads (separate) stands for no application');
  const declared = hinted([send(1, { key: '1' }), send(2, { key: '1' }), send(3, { key: '2', firstSeq: 3 })], only());
  assert.equal(declared.verdict, 'fail');
  assert.ok(!declared.basis.includes('keyed replay(s) of a judged send'), 'countBy already declared: no hint');
});
