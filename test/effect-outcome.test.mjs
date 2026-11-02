// The upstream outcome of a forwarded egress send (src/effect-outcome.mjs) and how the evaluator
// judges `upstream: "applied"` (src/effect-events.mjs). Unknown never reads as "not applied", only declared statuses
// read rejected, and a profile that never declares forward judges exactly as the frozen earlier recorder does.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { outcomeOf, upstreamRecord, validUpstreamRecord, validForwardScope, validForwardRecord, forwardSees, upstreamState, upstreamBound, forwardPortClash, forwardSecretClash, forwardRecordOf, validateForwardDeclaration, withoutUpstream, UNFORWARDED } from '../src/effect-outcome.mjs';
import { makeEffect, validateEffect, validateSelector, validateScope, matchState, matches, windowSees, blindToFields, baseSelector, evaluateEffectAssertion } from '../src/effect-events.mjs';
import { validateDeclaredEffect, validateDeclaredClaims } from '../src/http-effects.mjs';
import { fitsSelector, settlementFindings } from '../src/http-settlement.mjs';
import { needsPairing, pinsOf } from '../src/http-pairing.mjs';
import { attributionFindings } from '../src/http-attribution.mjs';

const frozen = await import(fileURLToPath(new URL('./fixtures/effect-events-d349c7c.mjs', import.meta.url)));
const PAY = 'payments.example.test', HOOKS = 'hooks.example.test';
const observer = { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' };
let seq = 0;
const send = (extra = {}) => makeEffect({ source: 'http-egress', observer, seq: ++seq, operation: 'send', name: PAY, resource: 'POST /v1/refunds', outcome: 'committed', content: { n: seq }, ...extra });
const scope = (extra = {}) => ({ operations: ['send'], names: [PAY, HOOKS], actorAttribution: 'none', evidence: 'authoritative', ...extra });
const ENTRY = { upstreamPort: 47002, applied: [200, 201, 204], rejected: [402], proof: true };
const FORWARD = { [PAY]: ENTRY };
const win = (events, extra = {}) => ({ source: 'http-egress', instanceId: 'egress-recorder-sink', scope: scope({ forward: FORWARD }), coverage: 'complete', reason: null, events, ...extra });
const sel = (extra = {}) => ({ source: 'http-egress', operation: 'send', name: PAY, ...extra });
// A recorded outcome; proven by default whenever a status was read.
const up = (outcome, status, proven = status !== null) => ({ upstream: { outcome, status, proven } });

test('outcome: only a proven listed 2xx is applied, only a proven listed 4xx is rejected, everything else is unknown', () => {
  const entry = { applied: [200, 201, 204], rejected: [402, 404] };
  for (const s of [200, 201, 204]) assert.equal(outcomeOf(s, true, entry, 'POST'), 'applied', String(s));
  for (const m of ['GET', 'HEAD', 'OPTIONS', 'TRACE', null, undefined]) assert.equal(outcomeOf(201, true, entry, m), 'unknown', `${m} applies nothing`);
  for (const m of ['PUT', 'PATCH', 'DELETE']) assert.equal(outcomeOf(201, true, entry, m), 'applied', m);
  assert.equal(outcomeOf(402, true, entry, 'GET'), 'rejected', 'a declared rejection reads the same for any method');
  for (const s of [206, 207, 208]) assert.equal(outcomeOf(s, true, { applied: [s], rejected: [] }, 'POST'), 'unknown', `${s} is never applied, even if listed`);
  for (const s of [402, 404]) assert.equal(outcomeOf(s, true, entry, 'POST'), 'rejected', String(s));
  for (const s of [null, undefined, 100, 199, 202, 203, 206, 299, 300, 302, 304, 400, 409, 429, 500, 502, 503, 599, 600, 201.5, '201']) assert.equal(outcomeOf(s, true, entry, 'POST'), 'unknown', String(s));
  for (const s of [201, 402]) assert.equal(outcomeOf(s, false, entry, 'POST'), 'unknown', `${s} without a proof decides nothing`);
  assert.equal(outcomeOf(402, true, { applied: [200], rejected: [] }, 'POST'), 'unknown', 'no status is "not applied" unless declared');
  assert.equal(outcomeOf(500, true, { applied: [200], rejected: [500] }, 'POST'), 'unknown', 'a 5xx is never rejected, even if listed');
  assert.equal(outcomeOf(202, true, { applied: [202], rejected: [] }, 'POST'), 'unknown', '202 Accepted is never applied, even if listed');
  assert.deepEqual(upstreamRecord({ complete: true, status: 201, proven: true }, entry, 'POST'), { outcome: 'applied', status: 201, proven: true });
  assert.deepEqual(upstreamRecord({ complete: true, status: 201, proven: false }, entry, 'POST'), { outcome: 'unknown', status: 201, proven: false });
  assert.deepEqual(upstreamRecord({ complete: false, status: 201, proven: true }, entry, 'POST'), { outcome: 'unknown', status: null, proven: false }, 'an incomplete reply keeps no status and no proof');
  assert.deepEqual(upstreamRecord({ complete: false, reason: 'timeout' }, entry, 'POST'), UNFORWARDED);
  assert.deepEqual(upstreamRecord({ complete: true, status: 402, proven: true }, entry, 'POST'), { outcome: 'rejected', status: 402, proven: true });
});

test('event record: outcome and status must agree; only http-egress sends carry one', () => {
  const r3 = (outcome, status, proven) => ({ outcome, status, proven });
  for (const r of [r3('applied', 201, true), r3('rejected', 402, true), r3('unknown', null, false), r3('unknown', 500, true), r3('unknown', 409, false), r3('unknown', 200, false), r3('unknown', 202, true)]) assert.equal(validUpstreamRecord(r), true, JSON.stringify(r));
  for (const r of [r3('applied', 402, true), r3('applied', null, true), r3('applied', 201, false), r3('applied', 202, true), r3('applied', 206, true), r3('rejected', 201, true), r3('rejected', 500, true), r3('rejected', null, false), r3('rejected', 402, false),
    r3('unknown', null, true), r3('committed', 201, true), r3('unknown', 600, false), r3('unknown', 200, 'yes'), { outcome: 'applied', status: 201 }, { ...r3('applied', 201, true), extra: 1 }, null, 'applied', []]) assert.equal(validUpstreamRecord(r), false, JSON.stringify(r));
  assert.doesNotThrow(() => send(up('applied', 201)));
  assert.throws(() => send(up('applied', 402)), /upstream/);
  assert.throws(() => send({ outcome: 'unknown', ...up('applied', 201) }), /upstream/, 'a decided outcome belongs only to a committed send');
  assert.doesNotThrow(() => send({ outcome: 'unknown', ...up('unknown', null) }));
  assert.throws(() => makeEffect({ source: 'sql-audit-table', observer: { kind: 'sqlite-audit-table', instanceId: 'a' }, seq: 1, operation: 'insert', name: 'refunds', outcome: 'committed', ...up('applied', 201) }), /upstream/);
});

test('declaration and scope: literal loopback upstream, sorted declared 4xx, names the observer reports', () => {
  assert.deepEqual(validateForwardDeclaration({ upstream: 'http://127.0.0.1:47002', rejected: [404, 402] }, 47001), { port: 47002, applied: [200, 201, 204], rejected: [402, 404], proofEnv: null, timeoutMs: 5000, maxReplyBytes: 65536 });
  assert.deepEqual(validateForwardDeclaration({ upstream: 'http://127.0.0.1:47002', applied: [205, 203, 201, 200], proofEnv: 'SCOPEHAVEN_TARGET_PROOF' }, 47001).applied, [200, 201, 203, 205]);
  for (const applied of [[202], [206], [207], [208], [226], [200, 299]]) assert.throws(() => validateForwardDeclaration({ upstream: 'http://127.0.0.1:47002', applied }, 47001), /forward\.applied/, JSON.stringify(applied));
  assert.equal(validForwardScope(FORWARD, [PAY]), true);
  for (const bad of [{}, { [HOOKS]: ENTRY }, { [PAY]: { ...ENTRY, rejected: [404, 402] } }, { [PAY]: { ...ENTRY, rejected: [500] } }, { [PAY]: { ...ENTRY, applied: [202] } }, { [PAY]: { ...ENTRY, applied: [] } },
    { [PAY]: { ...ENTRY, applied: [206] } }, { [PAY]: { ...ENTRY, proof: 'yes' } }, { [PAY]: { ...ENTRY, upstreamPort: 80 } }, { [PAY]: { ...ENTRY, x: 1 } }, { [PAY]: { rejected: [402] } }, { [PAY]: [] }, []]) assert.equal(validForwardScope(bad, [PAY]), false, JSON.stringify(bad));
  assert.doesNotThrow(() => validateScope(scope({ forward: FORWARD })));
  assert.throws(() => validateScope(scope({ forward: { 'other.test': { rejected: [] } } })), /scope-forward/);
  assert.equal(validForwardRecord(FORWARD), true);
  assert.equal(validForwardRecord({ [PAY]: { ...ENTRY, rejected: [402, 402] } }), false);
  assert.deepEqual(forwardRecordOf({ type: 'egress-recorder', port: 47001, destinations: [{ host: HOOKS }, { host: PAY, forward: { upstream: 'http://127.0.0.1:47002', rejected: [404, 402] } }] }),
    { forward: { [PAY]: { upstreamPort: 47002, applied: [200, 201, 204], rejected: [402, 404], proof: false } } });
  assert.deepEqual(forwardRecordOf({ type: 'egress-recorder', destinations: [{ host: PAY }] }), {});
  const target = (port, extra = []) => ({ origin: 'http://127.0.0.1:47100', observers: [{ id: 'sink', type: 'egress-recorder', port: 47101, destinations: [{ host: PAY, forward: { upstream: `http://127.0.0.1:${port}` } }] }, ...extra] });
  assert.equal(forwardPortClash(target(47102)), null);
  assert.match(forwardPortClash(target(47100)), /target origin/);
  assert.match(forwardPortClash(target(47101)), /observer "sink"/);
  assert.match(forwardPortClash(target(47103, [{ id: 'mail', type: 'smtp-sink', port: 47103 }])), /observer "mail"/);
  // The proof secret is never a credential the profile sends or an observer holds.
  const secretTarget = (proofEnv, extra = {}) => ({ actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS' } }, observers: [{ id: 'sink', type: 'egress-recorder', port: 47101, destinations: [{ host: PAY, forward: { upstream: 'http://127.0.0.1:47102', proofEnv } }] }, ...(extra.observers ?? [])] });
  assert.equal(forwardSecretClash(secretTarget('SCOPEHAVEN_TARGET_PROOF')), null);
  assert.match(forwardSecretClash(secretTarget('SCOPEHAVEN_TARGET_OPS')), /credential of actor "ops"/);
  assert.match(forwardSecretClash(secretTarget('SCOPEHAVEN_TARGET_PG', { observers: [{ id: 'db', type: 'pg-snapshot', credentialEnv: 'SCOPEHAVEN_TARGET_PG' }] })), /credential of observer "db"/);
});

test('selector: upstream "applied" only where the caller opts in, only that value, only with an exact name', () => {
  assert.doesNotThrow(() => validateSelector(sel({ upstream: 'applied' }), 's', { fields: true, upstream: true }));
  assert.throws(() => validateSelector(sel({ upstream: 'applied' }), 's', { fields: true }), /selector-upstream-unsupported/, 'effect.only and sequences never opt in');
  assert.throws(() => validateSelector(sel({ upstream: 'applied' })), /selector-upstream-unsupported/);
  for (const value of ['rejected', 'unknown', true, 'APPLIED', null]) assert.throws(() => validateSelector(sel({ upstream: value }), 's', { upstream: true }), /selector-upstream/, String(value));
  assert.throws(() => validateSelector(sel({ name: { prefix: 'pay' }, upstream: 'applied' }), 's', { upstream: true }), /selector-upstream-name/);
  assert.doesNotThrow(() => validateDeclaredEffect({ kind: 'effect.none', select: sel({ upstream: 'applied' }) }));
  assert.throws(() => validateDeclaredEffect({ kind: 'effect.only', expect: [sel({ upstream: 'applied' })], allow: [] }));
  assert.doesNotThrow(() => validateDeclaredClaims([{ trigger: { field: { pointer: '/status', success: ['done'], refusal: ['failed'] } }, select: sel({ upstream: 'applied' }) }]));
  assert.deepEqual(pinsOf(sel({ upstream: 'applied' })), ['upstream'], 'a pin: a setup where every send reads a declared rejection shows nothing applied');
  assert.equal(needsPairing(sel()), false);
});

test('matchState: applied matches, rejected is no, anything else is unknown; the requirement survives every outcome spread', () => {
  const s = { ...sel({ upstream: 'applied' }), outcome: 'committed' };
  assert.equal(matchState(send(up('applied', 201)), s), 'match');
  assert.equal(matchState(send(up('rejected', 402)), s), 'no');
  for (const e of [send(up('unknown', null)), send(up('unknown', 500)), send(up('unknown', 409)), send()]) assert.equal(matchState(e, s), 'unknown');
  assert.equal(matches(send(up('unknown', 500)), s), false);
  assert.equal(matchState(send({ name: HOOKS, ...up('applied', 201) }), s), 'no', 'base keys decide first');
  // With fields: any "no" wins; then any "unknown".
  const captured = value => ({ captured: { status: 'captured', values: { '/amount': { type: 'number', value } } } });
  const both = { ...s, fields: [{ pointer: '/amount', gt: 100 }] };
  assert.equal(matchState(send({ ...captured(250), ...up('applied', 201) }), both), 'match');
  assert.equal(matchState(send({ ...captured(25), ...up('unknown', null) }), both), 'no');
  assert.equal(matchState(send({ ...captured(250), ...up('rejected', 402) }), both), 'no');
  assert.equal(matchState(send({ ...captured(250), ...up('unknown', null) }), both), 'unknown');
  assert.deepEqual(baseSelector(both), sel({ outcome: 'committed' }));
  // Settlement: a later send whose outcome is unknown could be this check's; a rejected one could not.
  assert.equal(fitsSelector(send(up('unknown', null)), sel({ upstream: 'applied' })), true);
  assert.equal(fitsSelector(send(up('rejected', 402)), sel({ upstream: 'applied' })), false);
});

test('windows: only an observer that forwards the name sees the predicate; one that records it without forwarding holds missing', () => {
  const s = sel({ upstream: 'applied' });
  assert.equal(windowSees(win([]), s), true);
  assert.equal(windowSees(win([], { scope: scope() }), s), false);
  assert.equal(windowSees(win([], { scope: scope({ forward: { [HOOKS]: { rejected: [] } } }) }), s), false, 'forwarding another host');
  assert.equal(forwardSees(scope({ forward: FORWARD }), { prefix: 'pay' }), false);
  const blind = win([send()], { scope: scope() });
  assert.equal(blindToFields(blind, s), true);
  for (const kind of ['effect.none', 'effect.exists']) assert.equal(evaluateEffectAssertion({ kind, select: s }, [blind]).verdict, 'unobservable', kind);
  // A forwarding observer beside a blind one: the blind one's send could be the applied one.
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: s }, [win([send(up('rejected', 402))]), { ...blind, instanceId: 'egress-recorder-other' }]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: s }, [win([send(up('rejected', 402))]), { ...blind, events: [], instanceId: 'egress-recorder-other' }]).verdict, 'pass');
});

test('clauses: every kind, every outcome; unknown never passes, rejected is the only "not applied"', () => {
  const s = sel({ upstream: 'applied' });
  const v = (kind, events, extra = {}) => evaluateEffectAssertion({ kind, select: s, ...extra }, [win(events)]);
  const [A, R, U5, U4, U0, NONE] = [up('applied', 201), up('rejected', 402), up('unknown', 500), up('unknown', 409), up('unknown', null), {}].map(x => send(x));
  assert.equal(v('effect.none', []).verdict, 'pass');
  assert.equal(v('effect.none', [R]).verdict, 'pass');
  assert.equal(v('effect.none', [R, A]).verdict, 'fail');
  for (const e of [U5, U4, U0, NONE]) {
    assert.equal(v('effect.none', [R, e]).verdict, 'missing');
    assert.equal(v('effect.exists', [R, e]).verdict, 'missing');
    assert.equal(v('effect.count', [A, e], { expected: 1 }).verdict, 'missing');
    assert.match(v('effect.none', [e]).basis, /upstream outcome/);
  }
  assert.equal(v('effect.exists', [U5, A]).verdict, 'pass', 'one applied send shows it happened');
  assert.equal(v('effect.exists', [R]).verdict, 'fail');
  assert.deepEqual([v('effect.count', [A, R, A], { expected: 2 }).verdict, v('effect.count', [A, R, A], { expected: 2 }).matched], ['pass', 2]);
  assert.equal(v('effect.count', [A, R], { expected: 2 }).verdict, 'fail');
  // Partial coverage still withholds absence; a not-committed send never counts.
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: s }, [win([R], { coverage: 'partial', reason: 'egress-request-in-flight' })]).verdict, 'missing');
  // A send that never reached the recorder in full is no committed effect, but its outcome is undecided, so it holds the absence at
  // missing (the unresolved-send rule, test/unresolved-send.test.mjs); a window holding one reads partial through collectWindow anyway.
  assert.equal(v('effect.none', [send({ outcome: 'unknown', ...up('unknown', null) })]).verdict, 'missing', 'an undecided send is never an absence');
  // Without the requirement, the same windows judge every committed attempt, as before.
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: sel() }, [win([R])]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.count', select: sel(), expected: 2 }, [win([R, U5])]).verdict, 'pass');
});

test('binding: every event of a forwarded name carries the outcome its status reads; no other event carries one', () => {
  assert.equal(upstreamBound(win([send(up('applied', 201)), send(up('rejected', 402)), send(up('unknown', 409)), send({ name: HOOKS })])), true);
  assert.equal(upstreamBound(win([send()])), false, 'a forwarded name\'s send without an outcome');
  assert.equal(upstreamBound(win([send(up('rejected', 404))])), false, 'an undeclared status read as rejected');
  assert.equal(upstreamBound(win([send(up('unknown', 402))])), false, 'a declared status must read rejected');
  assert.equal(upstreamBound(win([send({ name: HOOKS, ...up('applied', 201) })])), false, 'an outcome on an unforwarded name');
  assert.equal(upstreamBound(win([send(up('applied', 201))], { scope: scope() })), false, 'an outcome without a forward scope');
  assert.equal(upstreamBound(win([send(up('unknown', 201, false)), send(up('unknown', 402, false))])), true, 'unproven statuses read unknown');
  assert.equal(upstreamBound(win([send(up('applied', 201))], { scope: scope({ forward: { [PAY]: { ...ENTRY, proof: false } } }) })), false, 'a proof on a destination that declares none');
  assert.equal(upstreamBound(win([send(up('unknown', 201, true))])), false, 'a proven listed 2xx must read applied');
  assert.equal(upstreamBound(win([send({ resource: 'GET /v1/refunds', ...up('unknown', 201, true) })])), true, 'a GET never reads applied');
  assert.equal(upstreamBound(win([send({ resource: 'GET /v1/refunds', ...up('applied', 201) })])), false, 'a GET recorded as applied is refused');
  assert.equal(upstreamState({ upstream: { outcome: 'applied' } }, 'applied'), 'match');
  assert.equal(upstreamState({}, 'applied'), 'unknown');
});

test('settlement: an earlier clause\'s upstream requirement does not narrow which check a later send may belong to', () => {
  const R = send(up('rejected', 402));
  const rows = [{ effects: [{ kind: 'effect.none', select: sel({ upstream: 'applied' }), verdict: 'pass' }], windows: [win([])] },
    { effects: [{ kind: 'effect.exists', select: sel(), verdict: 'pass' }], windows: [win([R])] }];
  assert.deepEqual(settlementFindings(rows, [[], [], []]).map(f => f[0]), [null, 'effect-ambiguous-attribution']);
  assert.deepEqual(withoutUpstream(sel({ upstream: 'applied', resource: 'POST /v1/refunds' })), sel({ resource: 'POST /v1/refunds' }));
  // Background attribution (src/http-attribution.mjs) asks the same question about an earlier check and sets it aside too.
  const background = [{ id: 'sync', select: { operation: 'send', name: HOOKS } }];
  assert.deepEqual(attributionFindings(rows, [[], [], []], undefined, { background }).map(f => f[0]), [null, 'background-unattributed']);
});

test('mutation guards: one per property, each would let a pass through', () => {
  // M1: the base loop must skip the key (comparing event.upstream, an object, to "applied" reads every event as no).
  const R = send(up('rejected', 402)), U = send(up('unknown', null)), A = send(up('applied', 201));
  assert.notEqual(matchState(A, sel({ upstream: 'applied' })), 'no');
  // M2: unknown is never "no".
  assert.equal(matchState(U, sel({ upstream: 'applied' })), 'unknown');
  // M3: an undeclared 4xx is never rejected, an unproven status decides nothing, and 202 is never applied.
  assert.equal(outcomeOf(409, true, ENTRY, 'POST'), 'unknown');
  assert.equal(outcomeOf(402, false, ENTRY, 'POST'), 'unknown');
  assert.equal(outcomeOf(202, true, { ...ENTRY, applied: [202] }, 'POST'), 'unknown');
  // M4: a window that records no outcome for the name never decides the predicate.
  assert.equal(windowSees(win([R], { scope: scope() }), sel({ upstream: 'applied' })), false);
  // M5: undecided sends are counted for an upstream-only selector (not just for fields).
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: sel({ upstream: 'applied' }) }, [win([U])]).verdict, 'missing');
  // M6: the base selector drops the predicate, so a blind observer's sends are judged on the base.
  assert.equal(Object.hasOwn(baseSelector(sel({ upstream: 'applied' })), 'upstream'), false);
});

test('differential compat against the frozen recorder: a profile that never declares forward judges exactly as before', () => {
  seq = 0;
  const captured = (status, value) => ({ captured: status === 'captured' ? { status, values: { '/amount': { type: 'number', value } } } : { status, values: {} } });
  const egress = [send(captured('captured', 25)), send(captured('captured', 250)), send(captured('not-json')), send(), send({ outcome: 'unknown' }), send({ name: HOOKS }), send({ resource: 'POST *' })];
  const sqlObserver = { kind: 'sqlite-audit-table', instanceId: 'sqlite-audit-db' };
  const sql = [['ops', 'insert'], ['unlisted:x', 'insert'], [null, 'insert'], ['ops', 'update']].map(([actor, operation], i) => makeEffect({ source: 'sql-audit-table', observer: sqlObserver, seq: i + 1, actor, operation, name: 'refunds', resource: `refunds/${i}`, outcome: 'committed' }));
  const egressScopes = [scope(), scope({ capture: { [PAY]: ['/amount'] } }), scope({ evidence: 'presence-only', capture: { [PAY]: ['/amount'] } })];
  const coverages = [['complete', null], ['partial', 'egress-witness-not-received'], ['failed', 'egress-listener-down']];
  const windows = [];
  for (const sc of egressScopes) for (const [coverage, reason] of coverages) for (const events of [egress, egress.slice(3), []]) windows.push({ source: 'http-egress', instanceId: 'egress-recorder-sink', scope: sc, coverage, reason, events: coverage === 'failed' ? [] : events });
  for (const [coverage, reason] of coverages.slice(0, 2)) windows.push({ source: 'sql-audit-table', instanceId: 'sqlite-audit-db', scope: { operations: ['insert', 'update'], names: ['refunds'], actorAttribution: 'principal', evidence: 'authoritative' }, coverage, reason, events: sql });
  const sets = [...windows.map(w => [w]), [windows[0], windows[27]], [windows[3], windows[9]], [windows[1], windows[10], windows[28]]];
  const selectors = [sel(), sel({ resource: 'POST /v1/refunds' }), { source: 'http-egress', name: { prefix: 'pay' } }, sel({ fields: [{ pointer: '/amount', equals: 25 }] }), sel({ fields: [{ pointer: '/amount', gt: 100 }] }),
    sel({ name: HOOKS }), { name: 'refunds', operation: 'insert' }, { name: 'refunds', operation: 'insert', actor: 'ops' }, { source: 'sql-audit-table', name: 'refunds', operation: 'update' }, { source: 'http-egress', name: PAY, outcome: 'denied' }];
  // The unresolved-send rule (test/unresolved-send.test.mjs) is the one later move: a clause a send whose outcome no observer decided
  // could still change reads missing where d349c7c passed or failed it. Every other clause judges exactly as before, basis included.
  const unresolvedMove = (now, was, set, select) => { const { actor: _a, fields: _f, upstream: _u, ...base } = select;
    return now.verdict === 'missing' && ['pass', 'fail'].includes(was.verdict) && set.some(w => w.events.some(e => (e.outcome === 'started' || e.outcome === 'unknown') && matchState(e, { ...base, outcome: e.outcome }) === 'match')); };
  let compared = 0, moved = 0;
  for (const select of selectors) for (const set of sets) for (const assertion of [{ kind: 'effect.none', select }, { kind: 'effect.exists', select }, { kind: 'effect.count', select: { source: select.source ?? 'http-egress', ...select }, expected: 1 }, { kind: 'effect.count', select: { source: select.source ?? 'http-egress', ...select }, expected: 0 }]) {
    const now = evaluateEffectAssertion(assertion, set), was = frozen.evaluateEffectAssertion(assertion, set);
    compared++;
    if (now.verdict !== was.verdict && unresolvedMove(now, was, set, assertion.select)) { moved++; continue; }
    assert.deepEqual(now, was, `${assertion.kind} ${JSON.stringify(select)}`);
  }
  for (const select of selectors) for (const w of windows) {
    assert.equal(windowSees(w, select), frozen.windowSees(w, select));
    assert.equal(blindToFields(w, select), frozen.blindToFields(w, select));
    for (const e of w.events) assert.equal(matchState(e, select), frozen.matchState(e, select));
  }
  for (const e of [...egress, ...sql]) assert.deepEqual(validateEffect(structuredClone(e)), frozen.validateEffect(structuredClone(e)));
  const verdictOf = fn => { try { fn(); return 'ok'; } catch (error) { return error.code; } };
  for (const s of [...selectors, {}, { name: 'x', fields: [] }, { name: { prefix: '' } }, { bogus: 1 }, { outcome: 'applied', name: PAY }])
    for (const opts of [undefined, { fields: true }]) assert.equal(verdictOf(() => validateSelector(s, 'selector', opts)), verdictOf(() => frozen.validateSelector(s, 'selector', opts)), JSON.stringify(s));
  for (const sc of [...egressScopes, scope({ forward: FORWARD })].slice(0, 3)) assert.deepEqual(validateScope(sc), frozen.validateScope(sc));
  assert.ok(compared > 1000 && moved < compared, `compared ${compared} clauses, ${moved} moved by the unresolved-send rule`);
});
