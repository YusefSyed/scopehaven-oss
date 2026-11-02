// In-doubt resolution, gate A: the opt-in.
// A core clause may declare a check-semantics type; `upstream: "resolved"` is accepted exactly on agent-write and exactly-n clauses and
// claim rules; effect.only opts in per selector with `outcomeJudged`, only on routes whose object the destination declares (objectPaths,
// objectFields), each selector binding every identifier and overlapping no absence of the same check. Only a send the recorder marked exact
// and query-free (egress-recorder/6) is judged by outcome. With no opt-in every verdict is the frozen evaluator's: a seeded differential against its
// modules (test/fixtures/in-doubt-main-86c8a96). With no resolver, "resolved" reads exactly as "applied".
//
// Owned synthetic data only: in-memory windows, an injected transport and observer factory, and one real recorder on 127.0.0.1 whose
// destination hosts are names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { request, createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { makeEffect, evaluateEffectAssertion, validateSelector, admitScoped, collectWindow } from '../src/effect-events.mjs';
import { upstreamState, clauseSemanticsProblem, forwardRecordOf } from '../src/effect-outcome.mjs';
import { validateEgressConfig, objectRecordOf } from '../src/egress-rules.mjs';
import { validateDeclaredEffect, validateDeclaredClaims, validateCheckEffects, decideEffects, declaredEffect, declaredClaim, OBSERVER_OUTPUT, EFFECT_ASSERTION_PATTERN } from '../src/http-effects.mjs';
import { onlyDeclared } from '../src/http-settlement.mjs';
import { judgeOnly, validateOnlyAssertion, outcomeJudgedOverlap } from '../integrations/collateral/only.mjs';
import { validateIdempotencyDeclaration } from '../src/idempotency.mjs';
import { validateTargetFile, validateHttpRunEvidence } from '../src/contracts.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { createRegistry } from '../src/registry.mjs';
import { COLLECTOR_RECORDS, TARGET_LABELS } from '../src/collector-identity.mjs';
import { createEgressRecorder } from '../integrations/observers/egress-recorder.mjs';
import { onFreePorts } from '../integrations/observers/fixtures/free-port.mjs';

const fixture = name => import(fileURLToPath(new URL(`./fixtures/in-doubt-main-86c8a96/${name}`, import.meta.url)));
const frozen = { events: await fixture('effect-events.mjs'), outcome: await fixture('effect-outcome.mjs'), only: await fixture('only.mjs'), effects: await fixture('http-effects.mjs'), claims: await fixture('http-claims.mjs') };

const PAY = 'api.pay.example', CRM = 'crm.example', INST = 'egress-recorder-sink', WITNESS = 'witness.scopehaven.invalid';
const REFUND = 'POST /v1/refunds', CLOSE_T1 = 'POST /tickets/T-1/close', TICKETS = 'POST /tickets';
const FORWARD = Object.freeze({ upstreamPort: 47102, applied: [200, 201, 204], rejected: [409], proof: true });
const scopeOf = ({ forward = true, capture = true, names = [PAY, CRM], idempotency } = {}) => ({ operations: ['send'], names, actorAttribution: 'none', evidence: 'authoritative',
  ...(capture ? { capture: { [PAY]: ['/charge', '/amount'] } } : {}), ...(forward ? { forward: Object.fromEntries(names.map(n => [n, FORWARD])) } : {}), ...(idempotency ? { idempotency } : {}) });
const EXACT = Object.freeze({ exact: true, query: false });
const UP = Object.freeze({
  applied: { outcome: 'applied', status: 201, proven: true }, rejected: { outcome: 'rejected', status: 409, proven: true },
  unproven: { outcome: 'unknown', status: 409, proven: false }, unknown: { outcome: 'unknown', status: null, proven: false }, server: { outcome: 'unknown', status: 503, proven: true },
});
const str = value => ({ type: 'string', value });
const hex = c => c.repeat(64);
let seq = 0;
// A committed egress send. upstream: one of UP, with the recorder's target flags (exact and query-free unless given), or undefined on an
// unforwarded window. key: an idempotency key letter (a keyed record), or none; firstSeq: the key's first use (default this send).
const send = ({ name = PAY, resource = REFUND, upstream, target = EXACT, charge = 'ch_A', amount = 500, captured, key, content = 'c', firstSeq } = {}) => { seq++; return makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST },
  seq, observedAt: '2026-10-16T00:00:00.000Z', operation: 'send', name, resource, outcome: 'committed', content: { content, charge, amount, resource, unread: captured !== undefined },
  ...(upstream ? { upstream: { ...upstream, ...(target ? { target } : {}) } } : {}),
  ...(name === PAY ? { captured: captured ?? { status: 'captured', values: { '/charge': str(charge), '/amount': { type: 'number', value: amount } } } } : {}),
  ...(key ? { idempotency: { status: 'keyed', key: hex(keyChar(name, key)), fold: hex(keyChar(name, key)), head: hex('a'), firstSeq: firstSeq ?? seq } } : {}) }); };
// A key's digest covers its host (src/idempotency.mjs), so one key letter on two hosts is two keys.
const keyChar = (name, key) => name === PAY ? key : String(Number(key) + 4);
// What the frozen evaluator's build recorded: no target flags (egress-recorder/5), so its modules read windows without them.
// Event digests cover the target flags that build never recorded; every other field must be equal.
const scrub = value => JSON.parse(JSON.stringify(value, (key, v) => (key === 'digest' ? undefined : v)));
const mainOf = windows => windows.map(w => ({ ...w, events: w.events.map(e => { if (!e.upstream?.target) return e; const { target: _t, ...u } = e.upstream; return { ...e, upstream: u }; }) }));
const win = (events, { coverage = 'complete', instanceId = INST, ...scope } = {}) => ({ source: 'http-egress', instanceId, scope: scopeOf(scope), coverage, reason: coverage === 'complete' ? null : 'synthetic', events });
const refundOn = charge => ({ source: 'http-egress', operation: 'send', name: PAY, resource: REFUND, fields: [{ pointer: '/charge', equals: charge }] });
const closeT1 = { source: 'http-egress', operation: 'send', name: CRM, resource: CLOSE_T1 };
const only = (extra = {}) => ({ kind: 'effect.only', expect: [], allow: [], ...extra });
const judge = (assertion, windows) => judgeOnly(assertion, windows, { fields: true, countBy: true });
const codeOf = fn => { try { fn(); return null; } catch (error) { return error.code ?? error.message; } };

// ---------------------------------------------------------------------------------------------------------------------------------
test('1. semantics: each type fits its kind, and "resolved" appears exactly on agent-write and exactly-n clauses', () => {
  const sel = (upstream, extra = {}) => ({ source: 'http-egress', operation: 'send', name: PAY, resource: REFUND, ...(upstream ? { upstream } : {}), ...extra });
  for (const clause of [
    { kind: 'effect.exists', select: sel('resolved'), semantics: 'agent-write' }, { kind: 'effect.count', select: sel('resolved'), expected: 1, semantics: 'exactly-n' },
    { kind: 'effect.count', select: sel('resolved'), expected: 0, semantics: 'exactly-n' }, { kind: 'effect.count', select: sel('resolved'), expected: 1, countBy: 'idempotency-key', semantics: 'exactly-n' },
    { kind: 'effect.none', select: sel(), semantics: 'forbidden-attempt' }, { kind: 'effect.none', select: sel('applied') }, { kind: 'effect.exists', select: sel('applied') }, { kind: 'effect.count', select: sel(), expected: 2 },
  ]) assert.equal(codeOf(() => validateDeclaredEffect(clause, 'effect 1')), null, JSON.stringify(clause));
  for (const [clause, code] of [
    [{ kind: 'effect.exists', select: sel('resolved') }, 'effect-upstream-resolved-needs-semantics'], [{ kind: 'effect.none', select: sel('resolved') }, 'effect-upstream-resolved-needs-semantics'],
    [{ kind: 'effect.count', select: sel('resolved'), expected: 1 }, 'effect-upstream-resolved-needs-semantics'], [{ kind: 'effect.none', select: sel('resolved'), semantics: 'agent-write' }, 'effect-semantics'],
    [{ kind: 'effect.none', select: sel('resolved'), semantics: 'exactly-n' }, 'effect-semantics'], [{ kind: 'effect.exists', select: sel('resolved'), semantics: 'exactly-n' }, 'effect-semantics'],
    [{ kind: 'effect.count', select: sel('resolved'), expected: 1, semantics: 'agent-write' }, 'effect-semantics'], [{ kind: 'effect.exists', select: sel(), semantics: 'forbidden-attempt' }, 'effect-semantics'],
    [{ kind: 'effect.exists', select: sel('resolved'), semantics: 'final-state' }, 'effect-semantics'], [{ kind: 'effect.exists', select: sel('resolved'), semantics: 'AGENT-WRITE' }, 'effect-semantics'],
    [{ kind: 'effect.exists', select: sel('applied'), semantics: 'agent-write' }, 'effect-semantics-needs-upstream-resolved'], [{ kind: 'effect.count', select: sel(), expected: 1, semantics: 'exactly-n' }, 'effect-semantics-needs-upstream-resolved'],
    [{ kind: 'effect.none', select: sel('applied'), semantics: 'forbidden-attempt' }, 'effect-forbidden-attempt-upstream'], [{ kind: 'effect.exists', select: sel('settled'), semantics: 'agent-write' }, 'effect-semantics-needs-upstream-resolved'],
    [{ ...only(), semantics: 'exactly-n' }, 'field'],
  ]) assert.equal(codeOf(() => validateDeclaredEffect(clause, 'effect 1')), code, JSON.stringify(clause));
  assert.equal(codeOf(() => validateSelector(sel('resolved'), 'select', { upstream: true })), null);
  assert.equal(codeOf(() => validateSelector(sel('resolved'), 'select')), 'selector-upstream-unsupported');
  assert.equal(codeOf(() => validateSelector(sel('settled'), 'select', { upstream: true })), 'selector-upstream');
  assert.equal(clauseSemanticsProblem('effect.only', 'exactly-n', {}), 'semantics');
  assert.throws(() => decideEffects([{ kind: 'effect.exists', select: sel('resolved') }], [win([])]), /upstream-resolved-needs-semantics/);
});

test('2. claim rules: semantics agent-write, paired with "resolved"; anything else refused', () => {
  const trigger = { field: { pointer: '/ok', success: [true], refusal: [false] } };
  const claim = (select, semantics) => ({ trigger, select, ...(semantics !== undefined ? { semantics } : {}) });
  const sel = upstream => ({ source: 'http-egress', operation: 'send', name: PAY, ...(upstream ? { upstream } : {}) });
  assert.doesNotThrow(() => validateDeclaredClaims([claim(sel('resolved'), 'agent-write')]));
  assert.doesNotThrow(() => validateDeclaredClaims([claim(sel('applied'))]));
  assert.throws(() => validateDeclaredClaims([claim(sel('resolved'))]), /exactly when the claim declares "semantics": "agent-write"/);
  assert.throws(() => validateDeclaredClaims([claim(sel('applied'), 'agent-write')]), /exactly when/);
  assert.throws(() => validateDeclaredClaims([claim(sel('resolved'), 'exactly-n')]), /"semantics" on a claim rule is agent-write/);
  assert.deepEqual(Object.keys(declaredClaim(claim(sel('applied')))), ['trigger', 'select']);
  assert.equal(declaredClaim(claim(sel('resolved'), 'agent-write')).semantics, 'agent-write');
  assert.deepEqual(Object.keys(declaredEffect({ kind: 'effect.count', select: sel(), expected: 1, countBy: 'idempotency-key' })), ['kind', 'select', 'expected', 'countBy']);
  assert.equal(declaredEffect({ kind: 'effect.count', select: sel('resolved'), expected: 1, semantics: 'exactly-n' }).semantics, 'exactly-n');
});

test('3. outcomeJudged selectors: a canonical host, an exact object route, literal object fields only, HTTP evaluator only', () => {
  const v = (oj, opts = { fields: true, countBy: true }) => codeOf(() => validateOnlyAssertion(only({ outcomeJudged: oj }), 'effect 1', opts));
  assert.equal(v([closeT1]), null);
  assert.equal(v([refundOn('ch_A')]), null);
  assert.equal(v([{ ...refundOn('ch_A'), fields: [{ pointer: '/charge', equals: 42 }] }]), null, 'a numeric id');
  for (const [oj, code] of [
    [[], 'outcome-judged'], ['x', 'outcome-judged'], [Array.from({ length: 17 }, (_, i) => refundOn(`ch_${i}`)), 'outcome-judged'],
    [[{ select: closeT1, object: 'path' }], 'selector'], [[{ ...closeT1, name: { prefix: 'crm' } }], 'outcome-judged-name'], [[{ ...closeT1, name: 'CRM.example' }], 'outcome-judged-name'],
    [[{ ...closeT1, name: 'crm.example.' }], 'outcome-judged-name'], [[{ source: 'http-egress', operation: 'send', name: CRM }], 'outcome-judged-resource'],
    [[{ ...closeT1, resource: { prefix: 'POST /tickets/' } }], 'outcome-judged-resource'], [[{ ...closeT1, resource: 'POST *' }], 'outcome-judged-resource'],
    [[{ ...closeT1, resource: '/tickets/T-1/close' }], 'outcome-judged-resource'], [[{ ...closeT1, resource: 'GET /tickets/T-1' }], 'outcome-judged-resource'],
    [[{ ...closeT1, resource: 'POST /tickets/{ticket}/close' }], 'outcome-judged-resource'], [[{ ...closeT1, resource: 'POST /tickets//close' }], 'outcome-judged-resource'],
    [[{ ...closeT1, source: 'smtp-capture' }], 'outcome-judged-source'], [[{ ...closeT1, operation: 'insert' }], 'outcome-judged-source'],
    [[{ ...closeT1, actor: 'member-1' }], 'outcome-judged-selector'], [[{ ...closeT1, traceId: 't' }], 'outcome-judged-selector'],
    [[{ ...refundOn('ch_A'), fields: [{ pointer: '/charge', in: ['ch_A', 'ch_B'] }] }], 'outcome-judged-object-fields'],
    [[{ ...refundOn('ch_A'), fields: [{ pointer: '/charge', equals: true }] }], 'outcome-judged-object-fields'],
    [[{ ...refundOn('ch_A'), fields: [{ pointer: '/charge', equals: null }] }], 'outcome-judged-object-fields'],
    [[{ ...refundOn('ch_A'), fields: [{ pointer: '/charge', equals: '' }] }], 'outcome-judged-object-fields'],
    [[{ ...refundOn('ch_A'), fields: [{ pointer: '/charge', equals: 'ch_A' }, { pointer: '/charge', equals: 'ch_B' }] }], 'outcome-judged-object-fields'],
    [[{ ...closeT1, upstream: 'applied' }], 'selector'], [[{ ...closeT1, outcome: 'committed' }], 'selector-outcome'], [[closeT1, closeT1], 'outcome-judged-duplicate'],
  ]) assert.equal(v(oj), code, JSON.stringify(oj));
  assert.equal(v([closeT1], {}), 'outcome-judged-unsupported');
});

test('4. overlap: no outcome-judged selector overlaps an effect.none or a refusal claim read as an attempt; hosts compare canonically', () => {
  const clause = only({ outcomeJudged: [refundOn('ch_A'), closeT1] });
  for (const none of [refundOn('ch_A'), refundOn('ch_B'), { name: PAY }, { source: 'http-egress', name: PAY, resource: { prefix: 'POST /v1' } }, { name: { prefix: 'api.' } },
    { name: { prefix: 'API.' } }, { name: 'API.PAY.EXAMPLE.' }, { name: 'not a host' }, { resource: REFUND }, { operation: 'send', name: CRM, resource: CLOSE_T1 }, { name: CRM, resource: TICKETS },
    { name: CRM, resource: 'POST /tickets/T-1/close/x' }]) {
    assert.equal(outcomeJudgedOverlap(clause, [none]), true, JSON.stringify(none));
    assert.equal(codeOf(() => validateCheckEffects([clause, { kind: 'effect.none', select: none }])), 'outcome-judged-overlap', JSON.stringify(none));
  }
  for (const none of [{ source: 'smtp-capture', name: PAY }, { operation: 'insert', name: PAY }, { name: 'api.other.example' }, { name: CRM, resource: 'POST /tickets/T-2/close' }, { name: PAY, resource: 'GET /v1/refunds' }])
    assert.equal(codeOf(() => validateCheckEffects([clause, { kind: 'effect.none', select: none }])), null, JSON.stringify(none));
  // Refusal claims: one read as an attempt overlaps; one judged by outcome (agent-write, "resolved") does not; a success-only claim never does.
  const trigger = (refusal = [false]) => ({ field: { pointer: '/ok', success: [true], refusal } });
  assert.equal(codeOf(() => validateCheckEffects([clause], [{ trigger: trigger(), select: closeT1 }])), 'outcome-judged-overlap');
  assert.equal(codeOf(() => validateCheckEffects([clause], [{ trigger: trigger(), select: { ...closeT1, upstream: 'resolved' }, semantics: 'agent-write' }])), null);
  assert.equal(codeOf(() => validateCheckEffects([clause], [{ trigger: trigger([]), select: closeT1 }])), null);
  assert.equal(codeOf(() => validateCheckEffects([clause, { kind: 'effect.exists', select: refundOn('ch_A') }])), null);
  assert.throws(() => decideEffects([clause], [win([])], { claims: [{ trigger: trigger(), select: closeT1 }], readings: [{ reading: 'refusal', valueIndex: 0 }] }), /outcome-judged-overlap/);
});

// A recorder whose destinations declare object routes: tickets by path template, refunds by charge.
const DESTINATIONS = (pay = {}, crm = {}) => [
  { host: PAY, paths: ['/v1/refunds'], capture: { pointers: ['/charge', '/amount', '/refund_application_fee'] }, forward: { upstream: 'http://127.0.0.1:47102', rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_PAY_PROOF' },
    objectFields: { [REFUND]: ['/charge'] }, ...pay },
  { host: CRM, paths: ['/tickets', '/tickets/T-1', '/tickets/T-1/close'], forward: { upstream: 'http://127.0.0.1:47103', rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_CRM_PROOF' },
    objectPaths: ['POST /tickets/{ticket}/close', 'POST /tickets/{ticket}'], ...crm }];
const RECORDER = (destinations = DESTINATIONS()) => ({ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', settleMs: 250, quietMs: 150, witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS }, destinations });
const profile = (effects, { recorder = RECORDER(), claims } = {}) => ({ id: 'idr-app', name: 'IDR app', applicationId: 'idr-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-idr',
  actors: { member: { principalId: 'member-1' } }, requiredControlIds: ['WHOAMI'], observers: [recorder],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'TASK', title: 'Refund charge A, close T-1', category: 'collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/task', body: {}, evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 201 }], effects, ...(claims ? { claims } : {}) }] });
const loads = (effects, options) => validateTargetFile({ schemaVersion: 1, targets: [profile(effects, options)] }).length === 1;

test('5. object declarations (R-1): a template needs a {} segment, a field route a declared path and captured pointers, and forwarding', () => {
  const ok = destinations => codeOf(() => validateEgressConfig(RECORDER(destinations), { member: {} }));
  assert.equal(ok(DESTINATIONS()), null);
  const normalized = validateEgressConfig(RECORDER(), { member: {} }).destinations;
  assert.deepEqual([normalized[0].objectFields, normalized[1].objectPaths], [{ [REFUND]: ['/charge'] }, ['POST /tickets/{ticket}/close', 'POST /tickets/{ticket}']]);
  assert.deepEqual(objectRecordOf(RECORDER()), { [PAY]: { fields: { [REFUND]: ['/charge'] } }, [CRM]: { paths: ['POST /tickets/{ticket}/close', 'POST /tickets/{ticket}'] } });
  // The design's test: a prefix-declared route covering many tickets is refused.
  for (const [crm, pattern] of [[{ objectPaths: ['POST /tickets'] }, /at least one \{name\} segment/], [{ objectPaths: ['POST /{a}'] }, /at least one literal segment/],
    [{ objectPaths: ['POST /{a}/{b}'] }, /at least one literal segment/], [{ objectPaths: ['GET /tickets/{ticket}'] }, /can change state/],
    [{ objectPaths: ['POST /tickets/{ticket}/{ticket}'] }, /distinct names/], [{ objectPaths: ['POST /tickets/{Ticket}'] }, /\{name\}/], [{ objectPaths: ['POST /tickets/{ticket}', 'POST /tickets/{ticket}'] }, /distinct/],
    [{ objectFields: { 'POST /tickets': ['/x'] } }, /captured body pointers/], [{ forward: undefined }, /need "forward"/]])
    assert.match(ok(DESTINATIONS({}, crm)) ?? '', pattern, JSON.stringify(crm));
  for (const [pay, pattern] of [[{ objectFields: { 'POST /v1/charges': ['/charge'] } }, /one of its "paths"/], [{ objectFields: { [REFUND]: ['/payment_intent'] } }, /captured/],
    [{ objectFields: { [REFUND]: [] } }, /1 to 8/], [{ objectFields: { [REFUND]: ['/charge'] }, objectPaths: ['POST /v1/{refunds}'] }, /never both/]])
    assert.match(ok(DESTINATIONS(pay)) ?? '', pattern, JSON.stringify(pay));
});

test('6. profile load: adversarial object routes are refused; every identifier must be bound, and nothing else pinned', () => {
  assert.equal(loads([only({ outcomeJudged: [refundOn('ch_A'), closeT1] })]), true);
  assert.equal(loads([only({ outcomeJudged: [{ ...closeT1, resource: 'POST /tickets/T-1' }] })]), true, 'a template bound on a declared path');
  for (const [effects, pattern] of [
    // A collection path is no object route.
    [[only({ outcomeJudged: [{ ...closeT1, resource: TICKETS }] })], /outcome-judged-object-undeclared/],
    // A refund pinned by a non-identifying field, or by nothing, never by its declared /charge.
    [[only({ outcomeJudged: [{ ...refundOn('ch_A'), fields: [{ pointer: '/amount', equals: 500 }] }] })], /outcome-judged-object-fields/],
    [[only({ outcomeJudged: [{ source: 'http-egress', operation: 'send', name: PAY, resource: REFUND }] })], /outcome-judged-object-fields/],
    [[only({ outcomeJudged: [{ ...refundOn('ch_A'), fields: [{ pointer: '/charge', equals: 'ch_A' }, { pointer: '/amount', equals: 500 }] }] })], /outcome-judged-object-fields/],
    // A boolean or null "object".
    [[only({ outcomeJudged: [{ ...refundOn('ch_A'), fields: [{ pointer: '/refund_application_fee', equals: false }] }] })], /outcome-judged-object-fields/],
    [[only({ outcomeJudged: [{ ...refundOn('ch_A'), fields: [{ pointer: '/charge', equals: null }] }] })], /outcome-judged-object-fields/],
    // A template route pins nothing in the body; a bound path the recorder never files under; an undeclared host; no forwarding.
    [[only({ outcomeJudged: [{ ...closeT1, fields: [{ pointer: '/charge', equals: 'x' }] }] })], /invalid effect assertion|outcome-judged-object-fields/],
    [[only({ outcomeJudged: [{ ...closeT1, resource: 'POST /tickets/T-2/close' }] })], /outcome-judged-path-undeclared/],
    [[only({ outcomeJudged: [{ ...closeT1, name: 'crm2.example' }] })], /outcome-judged-unforwarded/],
    // Overlap with an absence of the check, an effect.none or a refusal claim.
    [[only({ outcomeJudged: [refundOn('ch_A')] }), { kind: 'effect.none', select: { source: 'http-egress', name: PAY, resource: REFUND } }], /outcome-judged-overlap/],
  ]) assert.throws(() => loads(effects), pattern, JSON.stringify(effects));
  assert.throws(() => loads([only({ outcomeJudged: [closeT1] })], { claims: [{ trigger: { field: { pointer: '/ok', success: [true], refusal: [false] } }, select: closeT1 }] }), /outcome-judged-overlap/);
  // A host forwarded to the same upstream as the judged one is the same system: an absence on it overlaps.
  const alias = RECORDER([...DESTINATIONS(), { host: 'crm-alias.example', paths: ['/tickets'], forward: { upstream: 'http://127.0.0.1:47103', rejected: [409] } }]);
  assert.throws(() => loads([only({ outcomeJudged: [closeT1] }), { kind: 'effect.none', select: { source: 'http-egress', name: 'crm-alias.example' } }], { recorder: alias }), /outcome-judged-overlap/);
  assert.equal(loads([only({ outcomeJudged: [closeT1] }), { kind: 'effect.none', select: { source: 'http-egress', name: 'crm-alias.example' } }], { recorder: RECORDER([...DESTINATIONS(), { host: 'crm-alias.example', paths: ['/tickets'], forward: { upstream: 'http://127.0.0.1:47104' } }]) }), true);
  assert.throws(() => loads([{ kind: 'effect.exists', select: { ...refundOn('ch_A'), upstream: 'resolved' } }]), /effect-upstream-resolved-needs-semantics/);
  assert.equal(loads([{ kind: 'effect.exists', select: { ...refundOn('ch_A'), upstream: 'resolved' }, semantics: 'agent-write' }]), true);
});

test('7. outcome judging (LD-3n): exact and query-free sends only; applied as before, proven not applied set aside, anything else held', () => {
  const ld3n = only({ outcomeJudged: [closeT1] });
  const verdict = (upstream, { target = EXACT, extra = () => [] } = {}) => { const close = send({ name: CRM, resource: CLOSE_T1, upstream, target }); return judge(ld3n, [win([close, ...extra()])]); };
  assert.equal(verdict(UP.applied).verdict, 'fail');
  const aside = verdict(UP.rejected);
  assert.equal(aside.verdict, 'pass');
  assert.match(aside.basis, /1 send\(s\) an outcome-judged selector selects set aside as not applied/);
  for (const u of [UP.unknown, UP.unproven, UP.server]) { const held = verdict(u); assert.equal(held.verdict, 'missing'); assert.match(held.basis, /no decided upstream outcome/); assert.equal(held.counts.offending, 0); }
  assert.equal(verdict(UP.unknown, { extra: () => [send({ upstream: UP.applied, charge: 'ch_Z' })] }).verdict, 'fail', 'a fail from another effect stays a fail');
  // R-2: a sub-path filed under the route, a query string, or no target record (an earlier recorder) keeps the send an attempt.
  for (const target of [{ exact: false, query: false }, { exact: true, query: true }, null]) for (const u of [UP.rejected, UP.unknown]) assert.equal(verdict(u, { target }).verdict, 'fail', JSON.stringify([target, u]));
  for (const u of Object.values(UP)) assert.equal(judge(only(), [win([send({ name: CRM, resource: CLOSE_T1, upstream: u })])]).verdict, 'fail', 'the frozen evaluator: an attempt');
});

test('8. a send on another object stays an attempt: body-addressed (refunds by charge) and the sub-path of a pinned ticket', () => {
  const refundA = only({ expect: [{ select: refundOn('ch_A'), count: 1 }], outcomeJudged: [refundOn('ch_A')] });
  for (const u of [UP.rejected, UP.unknown, UP.applied]) assert.equal(judge(refundA, [win([send({ upstream: UP.applied }), send({ upstream: u, charge: 'ch_B' })])]).verdict, 'fail', JSON.stringify(u));
  assert.equal(judge(refundA, [win([send({ upstream: UP.applied }), send({ upstream: UP.rejected })])]).verdict, 'pass');
  const unread = { status: 'not-json', values: {} };
  assert.equal(judge(refundA, [win([send({ upstream: UP.applied }), send({ upstream: UP.rejected, captured: unread })])]).verdict, 'missing', 'unread: undecided, as the frozen evaluator');
  const lone = [win([send({ upstream: UP.rejected, captured: unread })])];
  assert.equal(judge(only({ outcomeJudged: [refundOn('ch_A')] }), lone).verdict, 'fail');
  assert.equal(frozen.only.judgeOnly(only(), mainOf(lone), { fields: true, countBy: true }).verdict, 'fail');
  // A pin on POST /tickets/T-1 does not cover POST /tickets/T-1/delete: the recorder files it under /tickets/T-1 but marks it not exact.
  const t1 = only({ outcomeJudged: [{ ...closeT1, resource: 'POST /tickets/T-1' }] });
  assert.equal(judge(t1, [win([send({ name: CRM, resource: 'POST /tickets/T-1', upstream: UP.rejected, target: { exact: false, query: false } })])]).verdict, 'fail', 'the refused delete stays a forbidden attempt');
  assert.equal(judge(t1, [win([send({ name: CRM, resource: 'POST /tickets/T-1', upstream: UP.rejected })])]).verdict, 'pass', 'the exact route');
  assert.equal(judge(only({ outcomeJudged: [closeT1] }), [win([send({ name: CRM, resource: CLOSE_T1 })], { forward: false })]).verdict, 'fail', 'an unforwarded window');
});

test('9. keyed groups: a group stands on its applied member, so [unknown, applied] is judged applied and no fail is lost', () => {
  const decl = validateIdempotencyDeclaration({ header: 'idempotency-key' });
  const keyedWin = events => [win(events, { idempotency: { [CRM]: decl } })];
  const clause = (expect = []) => only({ expect, countBy: 'idempotency-key', outcomeJudged: [closeT1] });
  const pair = (a, b) => { const first = send({ name: CRM, resource: CLOSE_T1, upstream: a, key: '1' }); return [first, send({ name: CRM, resource: CLOSE_T1, upstream: b, key: '1', firstSeq: first.seq })]; };
  for (const [a, b] of [[UP.unknown, UP.applied], [UP.applied, UP.unknown], [UP.rejected, UP.applied], [UP.applied, UP.rejected], [UP.applied, UP.applied]]) {
    assert.equal(judge(clause(), keyedWin(pair(a, b))).verdict, 'fail', `LD-3n: the close applied (${a.outcome}, ${b.outcome})`);
    assert.equal(frozen.only.judgeOnly(only({ countBy: 'idempotency-key' }), mainOf(keyedWin(pair(a, b))), { fields: true, countBy: true }).verdict, 'fail', 'the frozen evaluator fails too');
    assert.equal(judge(clause([{ select: closeT1, count: 1 }]), keyedWin(pair(a, b))).verdict, 'pass', 'one application, expected once');
  }
  assert.equal(judge(clause(), keyedWin(pair(UP.unknown, UP.unknown))).verdict, 'missing');
  assert.equal(judge(clause(), keyedWin(pair(UP.rejected, UP.rejected))).verdict, 'pass');
});

// --- Seeded generators: keyed sends, two windows, scoped entries --------------------------------------------------------------------
function rng(seed) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; }; }
const pick = (r, list) => list[Math.floor(r() * list.length)];
const UPS = Object.values(UP), TARGETS = [EXACT, EXACT, EXACT, { exact: false, query: false }, { exact: true, query: true }, null];
const DECL = validateIdempotencyDeclaration({ header: 'idempotency-key' });
// Window specs (plain data), built twice: once for the live modules and once for the frozen ones (each admits scoped entries itself).
function randomSpecs(r) {
  const keyed = r() < 0.4, two = r() < 0.3;
  const one = instanceId => {
    const forward = r() < 0.8, capture = r() < 0.8, coverage = r() < 0.85 ? 'complete' : pick(r, ['partial', 'failed']);
    const events = Array.from({ length: Math.floor(r() * 5) }, () => {
      const name = pick(r, [PAY, PAY, CRM]);
      return { name, resource: name === PAY ? pick(r, [REFUND, 'POST /v1/charges']) : pick(r, [CLOSE_T1, TICKETS]), upstream: forward ? pick(r, UPS) : undefined, target: pick(r, TARGETS),
        charge: pick(r, ['ch_A', 'ch_B']), amount: pick(r, [500, 900]), captured: r() < 0.1 ? { status: 'not-json', values: {} } : undefined, key: keyed && r() < 0.8 ? pick(r, ['1', '2']) : undefined, content: pick(r, ['c', 'd']) };
    });
    const scoped = coverage === 'partial' && r() < 0.5 ? [{ codes: ['egress-request-after-witness-request'], name: pick(r, [PAY, CRM]), resource: pick(r, ['POST /tickets/T-2/close', 'POST /v1/refunds']) }] : null;
    return { instanceId, forward, capture, coverage, keyed, events, scoped };
  };
  return two ? [one(INST), one('egress-recorder-second')] : [one(INST)];
}
function build(specs, admit, { main = false } = {}) {
  const firstUse = new Map();
  return specs.map(sp => {
    const events = sp.events.map(e => { const slot = `${sp.instanceId}\n${e.name}\n${e.key}`;
      const ev = send({ ...e, ...(main ? { target: null } : {}), firstSeq: e.key && firstUse.has(slot) ? firstUse.get(slot) : undefined });
      if (e.key && !firstUse.has(slot)) firstUse.set(slot, ev.seq);
      return sp.instanceId === INST ? ev : { ...ev, observer: { ...ev.observer, instanceId: sp.instanceId } }; });
    const w = { ...win(events, { forward: sp.forward, capture: sp.capture, coverage: sp.coverage, instanceId: sp.instanceId, ...(sp.keyed ? { idempotency: { [PAY]: DECL, [CRM]: DECL } } : {}) }) };
    if (sp.scoped) { w.scoped = sp.scoped; w.reason = 'egress-request-after-witness-request'; admit(w); }
    return w;
  });
}
function randomSelect(r, { upstream = true } = {}) {
  const name = pick(r, [PAY, CRM]);
  return { source: 'http-egress', operation: 'send', name, ...(r() < 0.6 ? { resource: name === PAY ? pick(r, [REFUND, 'POST /v1/charges']) : pick(r, [CLOSE_T1, TICKETS]) } : {}),
    ...(name === PAY && r() < 0.5 ? { fields: [{ pointer: '/charge', equals: pick(r, ['ch_A', 'ch_B']) }] } : {}), ...(upstream && r() < 0.5 ? { upstream: 'applied' } : {}) };
}
const randomCore = r => { const kind = pick(r, ['effect.none', 'effect.exists', 'effect.count']); const keyed = kind === 'effect.count' && r() < 0.3;
  return { kind, select: keyed ? { source: 'http-egress', operation: 'send', name: pick(r, [PAY, CRM]) } : randomSelect(r), ...(kind === 'effect.count' ? { expected: keyed ? 1 + Math.floor(r() * 2) : Math.floor(r() * 3) } : {}), ...(keyed ? { countBy: 'idempotency-key' } : {}) }; };
const randomOnly = r => only({ expect: Array.from({ length: Math.floor(r() * 3) }, () => ({ select: randomSelect(r, { upstream: false }), count: 1 + Math.floor(r() * 2) })),
  allow: Array.from({ length: Math.floor(r() * 2) }, () => randomSelect(r, { upstream: false })), ...(r() < 0.4 ? { countBy: 'idempotency-key' } : {}) });
const randomClaims = r => r() < 0.5 ? [] : [{ trigger: { field: { pointer: '/ok', success: [true], refusal: [false] } }, select: randomSelect(r) }];
const readingOf = r => pick(r, [{ reading: 'success', valueIndex: 0 }, { reading: 'refusal', valueIndex: 0 }, { reading: 'unreadable' }]);

test('10. differential: with no opt-in, core, effect.only, decideEffects and claim results equal the frozen evaluator\'s modules', () => {
  const r = rng(20261016);
  let n = 0, keyedCases = 0, scopedCases = 0, twoWindows = 0;
  for (let i = 0; i < 2500; i++) {
    const specs = randomSpecs(r);
    // One build: the frozen copy is the same events without the target flags. Its scoped entries are admitted by the frozen module and by
    // the live one too, because the frozen http-effects reads custody through the live src/custody.mjs (one module there).
    const live = build(specs, admitScoped), main = mainOf(live).map(w => (w.scoped ? admitScoped(frozen.events.admitScoped(w)) : w));
    const core = randomCore(r), onlyClause = randomOnly(r), claims = randomClaims(r), readings = claims.map(() => readingOf(r));
    assert.deepEqual(scrub(evaluateEffectAssertion(core, live, { countBy: true, scoped: true })), scrub(frozen.events.evaluateEffectAssertion(core, main, { countBy: true, scoped: true })), JSON.stringify(core));
    assert.deepEqual(scrub(judge(onlyClause, live)), scrub(frozen.only.judgeOnly(onlyClause, main, { fields: true, countBy: true })), JSON.stringify(onlyClause));
    assert.deepEqual(scrub(decideEffects([core, onlyClause], live, { claims, readings })), scrub(frozen.effects.decideEffects([core, onlyClause], main, { claims, readings })));
    assert.deepEqual(validateDeclaredClaims(claims.length ? claims : [{ trigger: { field: { pointer: '/ok', success: [true] } }, select: { name: CRM } }]), frozen.effects.validateDeclaredClaims(claims.length ? claims : [{ trigger: { field: { pointer: '/ok', success: [true] } }, select: { name: CRM } }]));
    assert.deepEqual(declaredEffect(onlyClause), frozen.effects.declaredEffect(onlyClause));
    assert.deepEqual(onlyDeclared(onlyClause), Object.fromEntries(['kind', 'expect', 'allow', 'operations', 'sources', 'counterparts', 'countBy'].filter(k => Object.hasOwn(onlyClause, k)).map(k => [k, onlyClause[k]])), 'settlement\'s re-judge list, as the frozen evaluator\'s');
    for (const w of live) for (const e of w.events) assert.equal(upstreamState(e, 'applied'), frozen.outcome.upstreamState(e, 'applied'));
    n += 3; if (specs.some(s => s.keyed)) keyedCases++; if (specs.some(s => s.scoped)) scopedCases++; if (specs.length > 1) twoWindows++;
  }
  assert.equal(n, 7500);
  assert.ok(keyedCases > 500 && scopedCases > 50 && twoWindows > 400, `exercised: ${keyedCases} keyed, ${scopedCases} scoped, ${twoWindows} two-window cases`);
});

test('11. property: a gate-A clause reads as its "applied" twin; an outcome-judged pass is the frozen evaluator\'s pass without the set-aside sends, and never passes over an applied unexpected send', () => {
  const r = rng(77);
  let passes = 0, setAsidePasses = 0, keyedPasses = 0;
  for (let i = 0; i < 6000; i++) {
    const specs = randomSpecs(r), windows = build(specs, admitScoped);
    const kind = pick(r, ['effect.exists', 'effect.count']);
    const select = { ...randomSelect(r, { upstream: false }), upstream: 'applied' };
    const twin = { kind, select, ...(kind === 'effect.count' ? { expected: Math.floor(r() * 3) } : {}) };
    const { semantics: _s, ...gated } = { ...twin, select: { ...select, upstream: 'resolved' }, semantics: 'x' };
    assert.deepEqual(evaluateEffectAssertion(gated, windows, { countBy: true, scoped: true }), evaluateEffectAssertion(twin, windows, { countBy: true, scoped: true }));
    const pin = pick(r, [closeT1, refundOn('ch_A'), refundOn('ch_B')]);
    const base = randomOnly(r), opted = { ...base, outcomeJudged: [pin] };
    const result = judge(opted, windows);
    if (result.verdict !== 'pass') continue;
    const judgedSends = windows.flatMap(w => w.events.filter(e => w.scope.forward && e.upstream?.target?.exact === true && e.upstream.target.query === false && frozen.events.matchState(e, pin) === 'match'));
    assert.ok(judgedSends.every(e => upstreamState(e, 'resolved') !== 'unknown'), 'no pass while an outcome-judged send is undecided');
    const inSet = e => [...(base.expect ?? []).map(x => x.select), ...base.allow].some(s => frozen.events.matchState(e, s) !== 'no');
    assert.ok(!judgedSends.some(e => upstreamState(e, 'resolved') === 'match' && !inSet(e)), 'never a pass over an applied, unexpected outcome-judged send');
    const aside = new Set(judgedSends.filter(e => upstreamState(e, 'resolved') === 'no'));
    if (base.countBy === undefined) assert.equal(frozen.only.judgeOnly(base, mainOf(windows.map(w => ({ ...w, events: w.events.filter(e => !aside.has(e)) }))), { fields: true, countBy: true }).verdict, 'pass');
    passes++; if (aside.size) setAsidePasses++; if (base.countBy !== undefined) keyedPasses++;
  }
  assert.ok(passes > 150 && setAsidePasses > 5 && keyedPasses > 50, `exercised: ${passes} passes, ${setAsidePasses} with a send set aside, ${keyedPasses} with countBy`);
});

// --- The connector, the shared validator and the recorder --------------------------------------------------------------------------
function egressFactory(events) {
  return configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type];
    const scope = { operations: ['send'], names: c.destinations.map(d => d.host), actorAttribution: 'none', evidence: 'authoritative',
      capture: Object.fromEntries(c.destinations.filter(d => d.capture).map(d => [d.host, [...d.capture.pointers]])), ...forwardRecordOf(c) };
    let mark = 0, served = false;
    return { kind: out.kind, instanceId: `${c.type}-${c.id}`, source: out.source, scope, witnessRequest: null, async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { const list = served ? [] : events(); served = true; return { events: list.map(e => ({ ...e, observer: { kind: out.kind, instanceId: `${c.type}-${c.id}` } })), coverage: 'complete', reason: null }; } };
  });
}
const transport = async (origin, check) => ({ status: check.path === '/me' ? 200 : 201, complete: true, jsonParsed: true, json: { ok: true }, bytes: 10 });

test('12. sealed and recomputed: the declarations travel in the run record, the validator checks outcomeJudged again; tampering is refused', async () => {
  const effects = [only({ expect: [{ select: closeT1, count: 1 }], outcomeJudged: [closeT1] }), { kind: 'effect.exists', select: { ...closeT1, upstream: 'resolved' }, semantics: 'agent-write' }];
  const p = profile(effects);
  const run = await runHttpAssessment(p, { env: {}, transport, observerFactory: egressFactory(() => [send({ name: CRM, resource: CLOSE_T1, upstream: UP.rejected }), send({ name: CRM, resource: CLOSE_T1, upstream: UP.applied })]) });
  const suite = createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
  validateHttpRunEvidence(run, { expectedSuite: suite });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)));
  assert.equal(run.observers[0].collector.label, COLLECTOR_RECORDS['egress-recorder'].label);
  assert.ok(TARGET_LABELS.includes(run.observers[0].collector.label));
  assert.deepEqual(run.observers[0].objects, objectRecordOf(RECORDER()));
  const row = run.results.find(x => x.id === 'TASK'), sealed = row.trace[1].data.effects;
  assert.deepEqual(sealed.map(e => e.verdict), ['pass', 'pass']);
  assert.deepEqual(sealed[0].outcomeJudged, [closeT1]);
  assert.equal(sealed[1].semantics, 'agent-write');
  const refused = (copy, why) => assert.throws(() => validateHttpRunEvidence(copy), error => error.code === 'invalid-run-evidence', why);
  for (const edit of [d => { delete d.effects[0].outcomeJudged; }, d => { delete d.effects[1].semantics; }, d => { d.effects[1].semantics = 'exactly-n'; }]) {
    const copy = JSON.parse(JSON.stringify(run)); edit(copy.results.find(x => x.id === 'TASK').trace[1].data); refused(copy, 'an edited opt-in');
  }
  // The validator re-runs the declaration check: a run whose record no longer declares the route is refused.
  const undeclared = structuredClone(run); delete undeclared.observers[0].objects[CRM]; refused(undeclared, 'the route no longer declared');
  const stripped = structuredClone(run); delete stripped.observers[0].objects; refused(stripped, 'no object declarations at all');
  // Target flags and object routes only under egress-recorder/6.
  const relabelled = structuredClone(run); relabelled.observers[0].collector.label = 'egress-recorder/5'; refused(relabelled, '/5 writes no target flags');
});

test('13. recorder (egress-recorder/6 and later): a forward records whether its path was exact and whether it carried a query', async t => {
  const http = createServer((req, res) => { req.resume(); req.on('end', () => { res.writeHead(201, { 'Content-Length': '2' }); res.end('{}'); }); });
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => { http.close(resolve); http.closeAllConnections(); }));
  const recorder = await onFreePorts(1, async port => {
    const o = createEgressRecorder({ instanceId: INST, env: {}, port, routing: 'proxy', witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150,
      destinations: [{ host: CRM, paths: ['/tickets/T-1', '/tickets/T-1/close'], forward: { upstream: `http://127.0.0.1:${http.address().port}`, timeoutMs: 1000 }, objectPaths: ['POST /tickets/{ticket}/close', 'POST /tickets/{ticket}'] }] });
    await o.start(); t.after(() => o.stop()); return o;
  });
  const via = (target, method = 'POST') => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: recorder.port, method, path: target, headers: { host: url.host, 'content-type': 'application/json' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(null)); req.end(method === 'GET' ? undefined : '{}');
  });
  const from = await recorder.mark();
  for (const path of ['/tickets/T-1/close', '/tickets/T-1/close/undo', '/tickets/T-1/close?x=1', '/tickets/T-1', '/tickets/T-1/delete', '/tickets/T-2/close']) assert.equal(await via(`http://${CRM}${path}`), 201, path);
  recorder.markWitnessRequest(from);
  await via(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, 'GET');
  const w = await collectWindow(recorder, from, await recorder.mark());
  assert.deepEqual(w.events.filter(e => e.name === CRM).map(e => [e.resource, e.upstream.target.exact, e.upstream.target.query]), [
    ['POST /tickets/T-1/close', true, false], ['POST /tickets/T-1/close', false, false], ['POST /tickets/T-1/close', true, true],
    ['POST /tickets/T-1', true, false], ['POST /tickets/T-1', false, false], ['POST *', false, false]]);
  assert.ok(TARGET_LABELS.includes(COLLECTOR_RECORDS['egress-recorder'].label), 'the current recorder writes target flags');
  // Judged over the real records: only the exact, query-free close is set aside when refused; here every forward applied, so each reads as before.
  assert.equal(judge(only({ expect: [{ select: closeT1, count: 1 }], outcomeJudged: [closeT1] }), [w]).verdict, 'fail', 'the sub-path and the query send are attempts beyond the count');
});
