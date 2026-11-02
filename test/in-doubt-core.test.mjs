// In-doubt resolution: the resolution core (src/in-doubt.mjs) and its first resolver, r0, the transport record. Checked: the strict
// combination with resolver applicability owned by the core; the transport record per attempt; the retry whose first attempt was
// forwarded and reset; operations and group intervals (full interval on any failure or conflict); gates A and B and the backend tier;
// countBy and keyed effect.only under "resolved" (a refused attempt beside an applied same-key retry fails); a seeded differential
// against a frozen earlier evaluator with no opt-in, keyed sends included; the
// property that failing any record never turns a non-pass into a pass, for clauses, operations and groups, and never narrows a group's
// interval; window copies; the forwarder and the recorder over real loopback; and sealed connector runs recomputed by the validator.
//
// Owned synthetic data only. Real sockets bind 127.0.0.1; destination hosts are names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { request, createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { makeEffect, evaluateEffectAssertion, validateWindow, collectWindow, withoutEvents } from '../src/effect-events.mjs';
import { upstreamState, validUpstreamRecord, forwardRecordOf, SAFE_METHODS } from '../src/effect-outcome.mjs';
import { combine, strictlyDecided, attemptResolution, attemptRecords, applicableResolvers, fateOf, resolvedState, r0Record, validTransport, transportRecord, operationOf, groupMember, admitGroupCount,
  admitInDoubt, inDoubtAdmitted, inDoubtAttempt, RESOLVER_TABLE } from '../src/in-doubt.mjs';
import { decideEffects, backendObserved, bindSealedWindows, OBSERVER_OUTPUT, EFFECT_ASSERTION_PATTERN, BACKEND_ASSERTION } from '../src/http-effects.mjs';
import { judgeOnly } from '../integrations/collateral/only.mjs';
import { validateIdempotencyDeclaration, keyedReplays } from '../src/idempotency.mjs';
import * as labels from '../src/collector-identity.mjs';
import { COLLECTOR_RECORDS, IN_DOUBT_LABELS, TARGET_LABELS } from '../src/collector-identity.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { forwardRequest } from '../integrations/observers/egress-forward.mjs';
import { createEgressRecorder } from '../integrations/observers/egress-recorder.mjs';
import { onFreePorts, freePorts } from '../integrations/observers/fixtures/free-port.mjs';

const fixture = name => import(fileURLToPath(new URL(`./fixtures/in-doubt-main-4b2e2f7/${name}`, import.meta.url)));
const frozen = { events: await fixture('effect-events.mjs'), only: await fixture('only.mjs') };

const CRM = 'crm.example', INST = 'egress-recorder-sink', CLOSE = 'POST /tickets/T-1/close', WITNESS = 'witness.scopehaven.invalid';
const FORWARD = Object.freeze({ upstreamPort: 47103, applied: [200, 201, 204], rejected: [409], proof: true });
const DECL = validateIdempotencyDeclaration({ header: 'idempotency-key' });
const scopeOf = (extra = {}) => ({ operations: ['send'], names: [CRM], actorAttribution: 'none', evidence: 'authoritative', forward: { [CRM]: FORWARD }, ...extra });
const T = Object.freeze({ refused: { connected: false, mono: 10.5, wall: 1760000000000 }, reset: { connected: true, mono: 11.25, wall: 1760000000001 } });
const EXACT = Object.freeze({ exact: true, query: false });
const UP = Object.freeze({
  applied: { outcome: 'applied', status: 201, proven: true }, rejected: { outcome: 'rejected', status: 409, proven: true }, unknown: { outcome: 'unknown', status: null, proven: false },
  refused: { outcome: 'unknown', status: null, proven: false, transport: T.refused }, reset: { outcome: 'unknown', status: null, proven: false, transport: T.reset },
  server: { outcome: 'unknown', status: 503, proven: true, transport: T.reset },
});
let seq = 0;
// A committed send to CRM. upstream: one of UP (the recorder's exact, query-free target flags added unless target is given); key: an
// idempotency key letter, with its first use (default this send); content: the request body's identity.
const send = (upstream, { resource = CLOSE, method, target = EXACT, key, firstSeq, content = 'c' } = {}) => { seq++; return makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST },
  seq, observedAt: '2026-10-16T00:00:00.000Z', operation: 'send', name: CRM, resource: method ? `${method} ${resource.split(' ')[1]}` : resource, outcome: 'committed', content: { content, resource },
  ...(upstream ? { upstream: { ...structuredClone(upstream), ...(target ? { target } : {}) } } : {}),
  ...(key ? { idempotency: { status: 'keyed', key: key.repeat(64), fold: key.repeat(64), head: 'a'.repeat(64), firstSeq: firstSeq ?? seq } } : {}) }); };
const win = (events, { coverage = 'complete', admit = true, keyed = false, ...scope } = {}) => { const w = { source: 'http-egress', instanceId: INST, scope: scopeOf({ ...scope, ...(keyed ? { idempotency: { [CRM]: DECL } } : {}) }),
  coverage, reason: coverage === 'complete' ? null : 'synthetic', events }; return admit ? admitInDoubt(w) : w; };
const close = (upstream = 'resolved') => ({ source: 'http-egress', operation: 'send', name: CRM, resource: CLOSE, upstream });
const CLOSE_SEL = Object.freeze({ source: 'http-egress', operation: 'send', name: CRM, resource: CLOSE });
const EXISTS = { kind: 'effect.exists', select: close(), semantics: 'agent-write' };
const REFUSAL = { kind: 'effect.none', select: close() };   // a refusal claim's clause under agent-write (core level)
const count = expected => ({ kind: 'effect.count', select: close(), expected, semantics: 'exactly-n' });
const ONLY = { kind: 'effect.only', expect: [], allow: [], outcomeJudged: [CLOSE_SEL] };
const KEYED_ONLY = expect => ({ kind: 'effect.only', expect, allow: [], countBy: 'idempotency-key', outcomeJudged: [CLOSE_SEL] });
const core = clause => { const { semantics: _s, ...rest } = clause; return rest; };
const verdictOf = (clause, windows) => clause.kind === 'effect.only' ? judgeOnly(clause, windows, { fields: true, countBy: true }).verdict : evaluateEffectAssertion(core(clause), windows, { countBy: true }).verdict;
const r = (resolver, status, result) => status === 'succeeded' ? { resolver, status, result } : { resolver, status, reason: result };
const stripTransport = events => events.map(e => { if (!e.upstream?.transport) return e; const { transport: _t, ...u } = e.upstream; return { ...e, upstream: u }; });
// A stub later resolver (r1) that applies to every in-doubt attempt and takes supplied records, as read-back and the request feed do.
const STUB_TABLE = Object.freeze({ ...RESOLVER_TABLE, r1: Object.freeze({ applies: inDoubtAttempt }) });

// ---------------------------------------------------------------------------------------------------------------------------------
test('1. strict combination, with resolver applicability owned by the core', () => {
  assert.equal(combine([]), 'in-doubt');
  assert.equal(combine([r('r0', 'succeeded', 'refutes')]), 'refuted');
  assert.equal(combine([r('r0', 'succeeded', 'silent')]), 'in-doubt');
  assert.equal(combine([r('r0', 'failed', 'record-missing')]), 'in-doubt');
  assert.equal(combine([r('r0', 'succeeded', 'silent'), r('r1', 'succeeded', 'confirms')]), 'confirmed');
  assert.equal(combine([r('r0', 'succeeded', 'refutes'), r('r1', 'succeeded', 'confirms')]), 'in-doubt', 'disagreement');
  assert.equal(combine([r('r0', 'succeeded', 'silent'), r('r1', 'succeeded', 'confirms'), r('r2', 'failed', 'read-not-run')]), 'in-doubt');
  for (const bad of [[null], [{ resolver: 'r0', status: 'succeeded', result: 'maybe' }], [{ resolver: 'r0', status: 'ok', result: 'refutes' }], 'x']) assert.equal(combine(bad), 'in-doubt', JSON.stringify(bad));
  assert.equal(strictlyDecided([r('r0', 'succeeded', 'silent')]), true);
  assert.equal(strictlyDecided([r('r0', 'succeeded', 'silent'), r('r1', 'failed', 'record-missing')]), false);
  // The core decides which resolvers apply: r0 (the transport record) to every in-doubt attempt;
  // a record for a resolver that does not apply is ignored.
  assert.deepEqual(applicableResolvers(send(UP.reset)), ['r0']);
  assert.deepEqual(applicableResolvers(send(UP.applied)), [], 'a proven reply needs no resolver');
  assert.equal(attemptResolution(send(UP.refused), [r('r1', 'succeeded', 'confirms')]).verdict, 'refuted', 'r1 does not apply in this build');
  assert.equal(attemptResolution(send(UP.reset), [r('r0', 'succeeded', 'refutes')]).verdict, 'in-doubt', 'r0 reads only its event');
  // With a later resolver that applies, a forgotten record is failed by construction, never skipped.
  assert.deepEqual(attemptRecords(send(UP.refused), [], STUB_TABLE), [r('r0', 'succeeded', 'refutes'), r('r1', 'failed', 'record-missing')]);
  assert.equal(attemptResolution(send(UP.refused), [], STUB_TABLE).verdict, 'in-doubt');
  assert.equal(attemptResolution(send(UP.refused), [r('r1', 'succeeded', 'confirms'), r('r1', 'succeeded', 'confirms')], STUB_TABLE).records[1].reason, 'record-duplicate');
  assert.equal(attemptResolution(send(UP.reset), [r('r1', 'succeeded', 'confirms')], STUB_TABLE).verdict, 'confirmed');
  assert.equal(attemptResolution(send(UP.refused), [r('r1', 'succeeded', 'confirms')], STUB_TABLE).conflict, true);
});

test('2. the transport record per attempt: a connect that never completed refutes; a reset after connect, a missing or invalid record stays in doubt', () => {
  assert.deepEqual(r0Record(send(UP.refused)), r('r0', 'succeeded', 'refutes'));
  assert.deepEqual(r0Record(send(UP.reset)), r('r0', 'succeeded', 'silent'));
  assert.deepEqual(r0Record(send(UP.unknown)), r('r0', 'failed', 'record-missing'));
  assert.equal(fateOf(send(UP.refused)), 'refuted');
  for (const u of [UP.reset, UP.unknown, UP.server]) assert.equal(fateOf(send(u)), 'in-doubt', JSON.stringify(u));
  assert.equal(fateOf(send(UP.applied)), 'applied'); assert.equal(fateOf(send(UP.rejected)), 'refuted');
  assert.equal(inDoubtAttempt(send(UP.refused, { method: 'GET' })), false);
  assert.equal(fateOf(send(UP.refused, { method: 'GET' })), 'in-doubt');
  assert.equal(fateOf(send(undefined)), 'in-doubt');
  assert.deepEqual([...SAFE_METHODS], ['GET', 'HEAD', 'OPTIONS', 'TRACE'], 'src/in-doubt.mjs keeps its own copy of this list');
  assert.equal(validTransport(T.refused, UP.unknown), true);
  assert.equal(validTransport(T.refused, { outcome: 'unknown', status: 503, proven: true }), false);
  for (const t of [{ ...T.reset, extra: 1 }, { connected: 'no', mono: 1, wall: 1 }, { connected: true, mono: -1, wall: 1 }, { connected: true, mono: Infinity, wall: 1 }, { connected: true, mono: 1, wall: 1.5 }, { connected: true, mono: 1 }])
    assert.equal(validTransport(t, UP.unknown), false, JSON.stringify(t));
  assert.equal(validTransport({ connected: true, mono: 0, wall: null }, UP.unknown), true);
  assert.equal(validUpstreamRecord(UP.refused), true); assert.equal(validUpstreamRecord({ ...UP.refused, target: EXACT }), true);
  assert.equal(validUpstreamRecord({ ...UP.applied, transport: T.refused }), false);
  assert.throws(() => send({ ...UP.unknown, transport: { connected: false, mono: 1 } }), /upstream/);
  assert.deepEqual(transportRecord({ connected: false }, 12.34567, 5), { connected: false, mono: 12.346, wall: 5 });
  assert.deepEqual(transportRecord({}, 1, Number.NaN), { connected: true, mono: 1, wall: null }, 'no flag reads connected: never a refutation');
});

test('3. gate A: only "resolved", outcomeJudged and their key collapse read a resolution; "applied" and unpinned clauses read the record as without the opt-in', () => {
  const refused = send(UP.refused);
  assert.equal(upstreamState(refused, 'applied'), 'unknown'); assert.equal(upstreamState(refused, 'resolved'), 'no'); assert.equal(resolvedState(send(UP.reset)), 'unknown');
  const w = [win([send(UP.refused)])];
  assert.equal(verdictOf({ kind: 'effect.count', select: close('applied'), expected: 0 }, w), 'missing', 'without the opt-in: a refused forward stays unknown');
  assert.equal(verdictOf(count(0), w), 'pass');
  assert.equal(verdictOf({ kind: 'effect.count', select: CLOSE_SEL, expected: 1 }, w), 'pass', 'unpinned: one attempt');
  assert.equal(verdictOf({ kind: 'effect.only', expect: [], allow: [] }, w), 'fail', 'effect.only without outcomeJudged: an attempt');
  assert.equal(verdictOf(ONLY, w), 'pass');
  assert.equal(verdictOf(ONLY, [win([send(UP.refused, { target: { exact: false, query: false } })])]), 'fail', 'a sub-path is never judged by outcome');
});

test('4. the retry: attempt 1 forwarded and reset, attempt 2 refused before forwarding: attempt 2 is refuted, the operation stays in doubt', () => {
  const windows = () => [win([send(UP.reset), send(UP.refused)])];
  for (const clause of [EXISTS, REFUSAL, count(0), count(1), ONLY]) assert.equal(verdictOf(clause, windows()), 'missing', JSON.stringify(clause));
  const [d] = decideEffects([EXISTS], windows());
  assert.deepEqual(d.resolution, { operation: 'in-doubt', applied: 0, refuted: 1, inDoubt: 1, attempts: [{ observer: INST, seq: seq - 1, fate: 'in-doubt', by: 'none', reason: 'r0-connected', resolvers: ['r0'] }, { observer: INST, seq, fate: 'refuted', by: 'r0', resolvers: ['r0'] }] });
  assert.match(d.basis, /In-doubt resolution: operation in-doubt; 0 applied, 1 refuted .* 1 still in doubt\./);
  assert.equal(d.authoritative, false);
  assert.equal(verdictOf(REFUSAL, [win([send(UP.refused), send(UP.reset)])]), 'missing');
  const lone = [win([send(UP.refused)])];
  assert.deepEqual([EXISTS, REFUSAL, count(0), count(1), ONLY].map(c => verdictOf(c, lone)), ['fail', 'pass', 'pass', 'fail', 'pass']);
  const partial = [win([send(UP.refused)], { coverage: 'partial' })];
  assert.deepEqual([EXISTS, REFUSAL, count(0), count(1), ONLY].map(c => verdictOf(c, partial)), ['missing', 'missing', 'missing', 'missing', 'missing']);
  assert.equal(decideEffects([EXISTS], partial)[0].resolution.operation, 'in-doubt');
  assert.equal(decideEffects([EXISTS], lone)[0].resolution.operation, 'refuted');
  const both = [win([send(UP.refused), send(UP.applied)])];
  assert.deepEqual([verdictOf(EXISTS, both), verdictOf(count(1), both), verdictOf(REFUSAL, both)], ['pass', 'pass', 'fail']);
  assert.equal(decideEffects([EXISTS], both)[0].resolution.operation, 'confirmed');
});

test('5. a refused attempt never stands for a key group whose retry applied (keyed effect.only with outcomeJudged)', () => {
  const pair = (a, b, contents = ['c', 'c']) => { const first = send(a, { key: '1', content: contents[0] }); return [win([first, send(b, { key: '1', firstSeq: first.seq, content: contents[1] })], { keyed: true })]; };
  // Nothing expected over a refused attempt and an exact same-key retry, proven applied. It must fail.
  const reviewed = judgeOnly(KEYED_ONLY([]), pair(UP.refused, UP.applied), { fields: true, countBy: true });
  assert.equal(reviewed.verdict, 'fail');
  assert.equal(reviewed.offending.length, 1);
  // The mirror: the close expected once passes; a refused attempt beside a reset retry stays in doubt; either order.
  assert.equal(verdictOf(KEYED_ONLY([{ select: CLOSE_SEL, count: 1 }]), pair(UP.refused, UP.applied)), 'pass');
  assert.equal(verdictOf(KEYED_ONLY([]), pair(UP.refused, UP.reset)), 'missing');
  assert.equal(verdictOf(KEYED_ONLY([]), pair(UP.applied, UP.refused)), 'fail');
  assert.equal(verdictOf(KEYED_ONLY([]), pair(UP.refused, UP.refused)), 'pass', 'nothing reached the upstream');
  assert.equal(verdictOf(KEYED_ONLY([]), pair(UP.refused, UP.applied, ['c', 'd'])), 'fail', 'another body: the applied one is judged on its own');
  // The collapse itself: under outcomeJudged the refused attempt is the replay, the applied retry stands.
  const w = pair(UP.refused, UP.applied)[0];
  assert.deepEqual([...keyedReplays(w, CRM, { outcomeJudged: true }).replay].map(e => e.seq), [w.events[0].seq]);
  assert.deepEqual([...keyedReplays(w, CRM).replay].map(e => e.seq), [w.events[1].seq], 'without the opt-in, the default reading: the earlier send stands');
  // The connector, the validator and the sealed record agree: the row fails.
});

test('6. operations and group intervals: refuted only on every attempt and route; the full interval on any failure or conflict', () => {
  assert.equal(operationOf([], { covered: true }).operation, 'none');
  assert.equal(operationOf(['refuted', 'refuted'], { covered: true }).operation, 'refuted');
  assert.equal(operationOf(['refuted', 'refuted'], { covered: false }).operation, 'in-doubt');
  assert.equal(operationOf(['refuted', 'applied']).operation, 'confirmed');
  assert.equal(operationOf(['in-doubt'], { covered: true }).operation, 'in-doubt');
  // Members from events: P proven applied, members the transport record refutes leave D, F = [P, P + D].
  const members = (...events) => events.map(e => groupMember(e));
  const g = (ms, results) => admitGroupCount(ms, results);
  assert.deepEqual(g(members(send(UP.applied), send(UP.reset), send(UP.refused)), []), { admitted: true, low: 1, high: 2, conflict: false }, 'no group result: I = F');
  assert.deepEqual(g(members(send(UP.applied), send(UP.reset)), [{ resolver: 'r2', status: 'succeeded', low: 2, high: 2 }]), { admitted: true, low: 2, high: 2, conflict: false });
  // Two confirmed (here: strict, in doubt) members and an exact count of 1 against r1's [2, 2]: a conflict, so F.
  const two = members(send(UP.reset), send(UP.reset));
  assert.deepEqual(g(two, [{ resolver: 'r1', status: 'succeeded', low: 2, high: 2 }, { resolver: 'r2', status: 'succeeded', low: 1, high: 1 }]), { admitted: false, low: 0, high: 2, conflict: true });
  assert.deepEqual(g(two, [{ resolver: 'r2', status: 'failed', reason: 'read-failed' }]), { admitted: false, low: 0, high: 2, conflict: false });
  assert.deepEqual(g(two, [{ resolver: 'r2', status: 'succeeded', low: 3, high: 3 }]), { admitted: false, low: 0, high: 2, conflict: true }, 'outside F');
  // A member whose record failed, or whose resolvers disagree: F, with that member back in D.
  assert.deepEqual(g(members(send(UP.unknown), send(UP.applied)), [{ resolver: 'r2', status: 'succeeded', low: 1, high: 1 }]), { admitted: false, low: 1, high: 2, conflict: false });
  assert.deepEqual(g([groupMember(send(UP.refused), [r('r1', 'succeeded', 'confirms')], STUB_TABLE)], []), { admitted: false, low: 0, high: 1, conflict: true });
  // The members' own decisions bound the group whatever the caller passes. A later resolver confirms both members and the
  // caller passes only an r2 count of 1: a conflict, so F. Passed nothing, the confirmations alone give [2, 2].
  const confirmedTwice = [send(UP.reset), send(UP.reset)].map(e => groupMember(e, [r('r1', 'succeeded', 'confirms')], STUB_TABLE));
  assert.deepEqual(confirmedTwice.map(m => m.decided), ['confirmed', 'confirmed']);
  assert.deepEqual(g(confirmedTwice, [{ resolver: 'r2', status: 'succeeded', low: 1, high: 1 }]), { admitted: false, low: 0, high: 2, conflict: true });
  assert.deepEqual(g(confirmedTwice, []), { admitted: true, low: 2, high: 2, conflict: false });
  // A later refutation leaves the member in D but lowers the high bound; a transport-record refutation removes it from D (never counted twice).
  const laterRefuted = groupMember(send(UP.reset), [r('r1', 'succeeded', 'refutes')], STUB_TABLE), r0AndLater = groupMember(send(UP.refused), [r('r1', 'succeeded', 'refutes')], STUB_TABLE);
  assert.deepEqual([laterRefuted.decided, laterRefuted.r0Refuted, r0AndLater.decided, r0AndLater.r0Refuted], ['refuted', false, null, true]);
  assert.deepEqual(g([laterRefuted, groupMember(send(UP.applied))], []), { admitted: true, low: 1, high: 1, conflict: false });
  assert.deepEqual(g([laterRefuted, groupMember(send(UP.applied))], [{ resolver: 'r2', status: 'succeeded', low: 2, high: 2 }]), { admitted: false, low: 1, high: 2, conflict: true });
  assert.deepEqual(g([{ proven: 'applied', r0Refuted: false, decided: 'confirmed', strict: true, conflict: false }], []), { admitted: false, low: 1, high: 1, conflict: false }, 'a proven member is never also decided');
  assert.deepEqual(g([], []), { admitted: false, low: 0, high: 0, conflict: false });
  assert.deepEqual(g([{ proven: 'maybe' }], []), { admitted: false, low: 0, high: 0, conflict: false });
});

test('7. gate B and the backend tier; a window copy keeps its admission and its in-doubt condition', () => {
  const events = () => [send(UP.applied), send(UP.reset)];
  const opted = decideEffects([EXISTS], [win(events())])[0];
  assert.deepEqual([opted.verdict, opted.authoritative, backendObserved([opted])], ['pass', false, false]);
  const applied = decideEffects([{ kind: 'effect.exists', select: close('applied') }], [win(events())])[0];
  assert.deepEqual([applied.authoritative, Object.hasOwn(applied, 'resolution')], [true, false]);
  const earlier = decideEffects([EXISTS], [win(stripTransport(events()), { admit: false })])[0];
  assert.deepEqual([earlier.authoritative, Object.hasOwn(earlier, 'resolution')], [true, false]);
  assert.equal(decideEffects([EXISTS], [win([send(UP.applied), send(UP.refused)])])[0].authoritative, true);
  const failing = decideEffects([ONLY], [win([send(UP.reset), send(UP.applied, { resource: 'POST /tickets/T-9/delete' })])])[0];
  assert.deepEqual([failing.verdict, failing.authoritative, failing.resolution.inDoubt], ['fail', false, 1]);
  // withoutEvents (the later-outcome stage's copy) carries the admission: the copy reads the same in-doubt condition, with a fresh record.
  const w = win([...events(), send(UP.applied, { resource: 'POST /tickets/T-9/close' })]);
  const copy = withoutEvents(w, new Set([w.events[2]]));
  assert.equal(inDoubtAdmitted(copy), true);
  const again = decideEffects([EXISTS], [copy])[0];
  assert.deepEqual([again.authoritative, again.resolution.inDoubt], [false, 1]);
  assert.equal(inDoubtAdmitted(withoutEvents(win([], { admit: false }), new Set())), false);
  assert.ok(IN_DOUBT_LABELS.includes(COLLECTOR_RECORDS['egress-recorder'].label));
});

test('8. countBy on effect.count under "resolved": a keyed attempt the transport record refutes drops out of its key group as a declared rejection does', () => {
  const c = upstream => { const { resource: _r, ...select } = close(upstream); return { kind: 'effect.count', select, expected: 1, countBy: 'idempotency-key' }; };
  const pair = (a, b) => { const first = send(a, { key: '1', content: 'x' }); return [validateWindow(win([first, send(b, { key: '1', firstSeq: first.seq, content: 'y' })], { keyed: true }))]; };
  assert.equal(evaluateEffectAssertion(c('resolved'), pair(UP.refused, UP.applied), { countBy: true }).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(c('applied'), pair(UP.refused, UP.applied), { countBy: true }).verdict, 'missing', 'without the opt-in: the first attempt stays unknown');
  assert.equal(evaluateEffectAssertion(c('resolved'), pair(UP.reset, UP.applied), { countBy: true }).verdict, 'missing');
});

// --- Seeded generators: keyed sends and countBy clauses included --------------------------------------------------------------------
function rng(seed) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; }; }
const pick = (g, list) => list[Math.floor(g() * list.length)];
const OUTCOMES = [UP.applied, UP.rejected, UP.unknown, UP.refused, UP.refused, UP.reset, UP.server];
const RESOURCES = [CLOSE, CLOSE, 'POST /tickets/T-2/close', 'PATCH /tickets/T-1'];
const TARGETS = [EXACT, EXACT, EXACT, { exact: false, query: false }, { exact: true, query: true }];
function randomEvents(g, keyed) {
  const first = new Map();
  return Array.from({ length: Math.floor(g() * 5) }, () => {
    // A keyed send is usually a retry: its key's route and body (an exact replay), sometimes another body under the same key.
    const key = keyed && g() < 0.95 ? pick(g, ['1', '2']) : undefined;
    const resource = key && g() < 0.8 ? CLOSE : pick(g, RESOURCES), content = key && g() < 0.8 ? `k${key}` : pick(g, ['c', 'd']);
    const e = send(pick(g, OUTCOMES), { resource, target: pick(g, TARGETS), key, firstSeq: key ? first.get(key) : undefined, content });
    if (key && !first.has(key)) first.set(key, e.seq);
    return e;
  });
}
const randomCase = g => { const keyed = g() < 0.5; return { keyed, events: randomEvents(g, keyed), coverage: g() < 0.85 ? 'complete' : 'partial' }; };
const scrub = value => JSON.parse(JSON.stringify(value, (key, v) => (key === 'digest' ? undefined : v)));
const OPTED = [EXISTS, REFUSAL, count(0), count(1), count(2), ONLY, { ...ONLY, expect: [{ select: CLOSE_SEL, count: 1 }] }, KEYED_ONLY([]), KEYED_ONLY([{ select: CLOSE_SEL, count: 1 }])];
const MAIN = [{ kind: 'effect.exists', select: close('applied') }, { kind: 'effect.none', select: close('applied') }, { kind: 'effect.count', select: close('applied'), expected: 1 },
  { kind: 'effect.none', select: { source: 'http-egress', name: CRM } }, { kind: 'effect.count', select: { source: 'http-egress', name: CRM, resource: CLOSE }, expected: 1 },
  { kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: CRM }, expected: 1, countBy: 'idempotency-key' },
  { kind: 'effect.only', expect: [{ select: CLOSE_SEL, count: 1 }], allow: [] }, { kind: 'effect.only', expect: [{ select: CLOSE_SEL, count: 1 }], allow: [], countBy: 'idempotency-key' }];

test('9. differential: with no opt-in, every result over windows carrying transport records equals the frozen earlier evaluator without them (keyed sends included)', () => {
  const g = rng(1016);
  let n = 0, keyedCases = 0;
  for (let i = 0; i < 1500; i++) {
    const c = randomCase(g);
    const live = [win(c.events, { coverage: c.coverage, keyed: c.keyed })], main = [win(stripTransport(c.events), { coverage: c.coverage, keyed: c.keyed, admit: false })];
    for (const clause of MAIN) {
      const now = clause.kind === 'effect.only' ? judgeOnly(clause, live, { fields: true, countBy: true }) : evaluateEffectAssertion(clause, live, { countBy: true });
      const was = clause.kind === 'effect.only' ? frozen.only.judgeOnly(clause, main, { fields: true, countBy: true }) : frozen.events.evaluateEffectAssertion(clause, main, { countBy: true });
      assert.deepEqual(scrub(now), scrub(was), JSON.stringify(clause));
      n++;
    }
    const plain3 = MAIN.slice(0, 3);
    assert.deepEqual(decideEffects(plain3, live).map(d => [d.verdict, d.authoritative, d.basis, Object.hasOwn(d, 'resolution')]),
      decideEffects(plain3, [win(stripTransport(c.events), { coverage: c.coverage, keyed: c.keyed, admit: false })]).map(d => [d.verdict, d.authoritative, d.basis, false]));
    if (c.keyed) keyedCases++;
  }
  assert.equal(n, 12000);
  assert.ok(keyedCases > 500, `${keyedCases} keyed cases`);
});

test('10. property: failing any record never turns a non-pass into a pass (clauses, keyed effect.only, operations); a refuted attempt never stands over an applied member', () => {
  const g = rng(4242);
  let degradedPasses = 0, fullOnlyPasses = 0, keyedChecked = 0;
  for (let i = 0; i < 2500; i++) {
    const c = randomCase(g);
    const degraded = c.events.map(e => (e.upstream?.transport && g() < 0.5 ? stripTransport([e])[0] : e));
    const full = [win(c.events, { coverage: c.coverage, keyed: c.keyed })], less = [win(degraded, { coverage: c.coverage, keyed: c.keyed })], none = [win(stripTransport(c.events), { coverage: c.coverage, keyed: c.keyed })];
    for (const clause of OPTED) {
      if (clause.countBy && !c.keyed) continue;
      const vFull = verdictOf(clause, full), vLess = verdictOf(clause, less), vNone = verdictOf(clause, none);
      if (vLess === 'pass') { assert.equal(vFull, 'pass', `${JSON.stringify(clause)} ${JSON.stringify(c.events.map(e => [e.upstream, e.idempotency?.key?.[0]]))}`); degradedPasses++; }
      if (vNone === 'pass') assert.equal(vFull, 'pass');
      if (vFull === 'pass' && vLess !== 'pass') fullOnlyPasses++;
      if (clause.kind !== 'effect.only') assert.equal(vNone, verdictOf({ ...core(clause), select: close('applied') }, [win(stripTransport(c.events), { coverage: c.coverage, keyed: c.keyed, admit: false })]));
      // effect.only with outcomeJudged never passes while an outcome-judged send applied and nothing expected or allowed it.
      if (clause.kind === 'effect.only' && vFull === 'pass') {
        const judgedApplied = full[0].events.filter(e => e.upstream?.target?.exact === true && e.upstream.target.query === false && frozen.events.matchState(e, CLOSE_SEL) === 'match' && fateOf(e) === 'applied');
        assert.ok(!judgedApplied.length || clause.expect.length > 0, 'never a pass over an applied, unexpected outcome-judged send');
      }
    }
    for (const clause of MAIN) { if (clause.countBy && !c.keyed) continue; assert.equal(verdictOf(clause, less), verdictOf(clause, full), 'a clause without the opt-in never depends on the records'); }
    const opOf = ws => decideEffects([EXISTS], ws)[0].resolution?.operation ?? 'none';
    if (['refuted', 'confirmed'].includes(opOf(less))) assert.equal(opOf(full), opOf(less));
    // The keyed collapse under outcomeJudged: a replay's standing member is never an attempt the strict combination refuted.
    if (c.keyed) {
      const { replay } = keyedReplays(full[0], CRM, { outcomeJudged: true });
      const identity = e => `${e.idempotency.key}\n${e.contentDigest}\n${e.idempotency.head}`;
      for (const e of replay) {
        const stands = full[0].events.filter(x => x !== e && !replay.has(x) && x.idempotency && identity(x) === identity(e));
        assert.ok(stands.length >= 1 && stands.every(x => fateOf(x) !== 'refuted'), 'the standing member is never refuted');
        if (fateOf(e) === 'applied') assert.ok(stands.every(x => fateOf(x) === 'applied'), 'an applied member is never the replay of one not applied');
        keyedChecked++;
      }
    }
  }
  assert.ok(degradedPasses > 300 && fullOnlyPasses > 50 && keyedChecked > 100, `exercised: ${degradedPasses} degraded passes, ${fullOnlyPasses} passes only with every record, ${keyedChecked} keyed replays checked`);
});

test('11. property, groups: with a stub group resolver, conflicts, failed results, blind reads and results that contradict the members\' own decisions, failing any record only widens I', () => {
  const g = rng(31337);
  let admitted = 0, conflicts = 0, narrowed = 0, contradicted = 0;
  const contains = (outer, inner) => outer.low <= inner.low && inner.high <= outer.high;
  for (let i = 0; i < 4000; i++) {
    // Members: proven, decided by the transport record or in doubt, each with a stub r1 record (or none, which the core makes failed).
    const events = Array.from({ length: 1 + Math.floor(g() * 4) }, () => send(pick(g, OUTCOMES)));
    const r1 = events.map(() => (g() < 0.8 ? [r('r1', 'succeeded', pick(g, ['confirms', 'silent', 'silent', 'refutes']))] : []));
    const P = events.filter(e => e.upstream.outcome === 'applied').length, D = events.length - P - events.filter(e => e.upstream.outcome === 'rejected').length;
    // The members' own decisions, read from the per-attempt combination: strict confirmations count, strict refutations by a later resolver
    // lower the high bound, and a transport-record refutation leaves D.
    const decisions = events.map((e, k) => (inDoubtAttempt(e) ? attemptResolution(e, r1[k], STUB_TABLE) : null));
    const r0Out = decisions.filter(d => d?.strict && d.verdict === 'refuted' && d.records.some(x => x.resolver === 'r0' && x.result === 'refutes')).length;
    const confirmedN = decisions.filter(d => d?.strict && d.verdict === 'confirmed').length;
    const refutedN = decisions.filter(d => d?.strict && d.verdict === 'refuted' && !d.records.some(x => x.resolver === 'r0' && x.result === 'refutes')).length;
    const Dcore = D - r0Out, perLow = P + confirmedN, perHigh = P + Dcore - refutedN;
    // Group results: a stub exact count, a blind read (F), an interval like the request feed's, a conflicting count, a count the members' own decisions
    // contradict (inside F, outside [perLow, perHigh]: the caller left out the later resolver's interval), or a failed result.
    const results = Array.from({ length: Math.floor(g() * 3) }, () => {
      const kind = pick(g, ['exact', 'blind', 'interval', 'conflict', 'contradict', 'contradict', 'failed']);
      const n = P + Math.floor(g() * (D + 1));
      const outside = perLow > P ? perLow - 1 : perHigh < P + Dcore ? perHigh + 1 : null;
      return kind === 'failed' ? { resolver: 'r2', status: 'failed', reason: 'read-failed' } : kind === 'blind' ? { resolver: 'r2', status: 'succeeded', low: P, high: P + D }
        : kind === 'interval' ? { resolver: 'r1', status: 'succeeded', low: P, high: Math.min(P + D, n + 1) } : kind === 'conflict' ? { resolver: 'r2', status: 'succeeded', low: P + D + 1, high: P + D + 1 }
        : kind === 'contradict' && outside !== null ? { resolver: 'r2', status: 'succeeded', low: outside, high: outside, contradicts: true } : { resolver: 'r2', status: 'succeeded', low: n, high: n };
    });
    const full = admitGroupCount(events.map((e, k) => groupMember(e, r1[k], STUB_TABLE)), results.map(({ contradicts: _c, ...x }) => x));
    // An admitted interval always lies within the members' own decisions; a contradicting result never gets admitted.
    if (full.admitted) assert.ok(full.low >= perLow && full.high <= perHigh, `I within the per-attempt interval: ${JSON.stringify({ full, perLow, perHigh })}`);
    if (results.some(x => x.contradicts) && decisions.every(d => d === null || d.strict)) { assert.equal(full.admitted, false, 'a result the members contradict'); contradicted++; }
    // Degrade: any member's records (transport removed, r1 record dropped) and any group result replaced by its failed form.
    const lessEvents = events.map(e => (e.upstream.transport && g() < 0.3 ? stripTransport([e])[0] : e));
    const lessR1 = r1.map(list => (g() < 0.3 ? [] : list));
    const lessResults = results.map(res => (g() < 0.3 ? { resolver: res.resolver, status: 'failed', reason: 'read-not-run' } : res));
    const less = admitGroupCount(lessEvents.map((e, k) => groupMember(e, lessR1[k], STUB_TABLE)), lessResults.map(({ contradicts: _c, ...x }) => x));
    assert.ok(contains(less, full), `I(R') must contain I(R): ${JSON.stringify({ full, less })}`);
    for (const N of [0, 1, 2, 3]) if (less.low === N && less.high === N && less.admitted) assert.ok(full.low === N && full.high === N, 'a degraded exact count is the full one');
    if (full.admitted) admitted++; if (full.conflict) conflicts++; if (full.high - full.low < D) narrowed++;
  }
  assert.ok(admitted > 300 && conflicts > 300 && narrowed > 100 && contradicted > 100, `exercised: ${admitted} admitted, ${conflicts} conflicts, ${narrowed} narrowed below F, ${contradicted} contradicted`);
});

// --- Real loopback: the forwarder and the recorder ---------------------------------------------------------------------------------
const busyWait = ms => { const until = performance.now() + ms; while (performance.now() < until) { /* hold the event loop */ } };
async function listening(t, onConnection) {
  const sockets = new Set();
  const server = net.createServer(socket => { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); onConnection(socket); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { for (const socket of sockets) socket.destroy(); server.close(resolve); }));
  return server.address().port;
}
const forward = (port, extra = {}) => forwardRequest({ port, host: CRM, method: 'POST', path: '/tickets/T-1/close', rawHeaders: ['Content-Type', 'application/json'], body: Buffer.from('{"note":"x"}'), timeoutMs: 1000, maxReplyBytes: 1024, ...extra });

test('12. forwarder: connected is false only when the TCP connect never completed (refused, timed out, stopped first)', async t => {
  const [unused] = await freePorts(1);
  const refused = await forward(unused);
  assert.deepEqual([refused.complete, refused.reason, refused.connected], [false, 'connect-error', false]);
  let requests = 0;
  const quiet = await listening(t, socket => { socket.on('data', () => { requests++; }); });
  const pending = forward(quiet, { timeoutMs: 0 }); busyWait(25);
  const timedOut = await pending;
  assert.deepEqual([timedOut.reason, timedOut.connected, requests], ['timeout', false, 0], 'a connect timeout: no request byte reached the upstream');
  const controller = new AbortController(); controller.abort();
  assert.equal((await forward(quiet, { signal: controller.signal })).connected, false);
  // A reset after connect, before the upstream read anything (it waits 10 ms so the client has surely seen its connect): connected.
  const resetBefore = await forward(await listening(t, socket => { socket.pause(); setTimeout(() => socket.destroy(), 10); }));
  assert.deepEqual([resetBefore.complete, resetBefore.connected], [false, true]);
  const resetAfter = await forward(await listening(t, socket => socket.once('data', () => socket.destroy())));
  assert.deepEqual([resetAfter.complete, resetAfter.connected], [false, true]);
  const http = createServer((req, res) => { req.resume(); req.on('end', () => { res.writeHead(201, { 'Content-Length': '2' }); res.end('{}'); }); });
  await new Promise(resolve => http.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => { http.close(resolve); http.closeAllConnections(); }));
  const ok = await forward(http.address().port);
  assert.deepEqual([ok.complete, ok.status, ok.connected], [true, 201, true]);
});

test('13. recorder (egress-recorder/7): each settled forward records its transport; a refused upstream reads refuted only under "resolved"', async t => {
  const [unused] = await freePorts(1);
  const resetPort = await listening(t, socket => socket.once('data', () => socket.destroy()));
  const recorder = await onFreePorts(1, async port => {
    const o = createEgressRecorder({ instanceId: INST, env: {}, port, routing: 'proxy', witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, wallClock: () => 1760000000000,
      destinations: [{ host: CRM, paths: ['/tickets/T-1/close'], forward: { upstream: `http://127.0.0.1:${unused}`, rejected: [409], timeoutMs: 1000 } }, { host: 'crm2.example', paths: ['/tickets/T-1/close'], forward: { upstream: `http://127.0.0.1:${resetPort}`, timeoutMs: 1000 } }] });
    await o.start(); t.after(() => o.stop()); return o;
  });
  const via = (target, method = 'POST') => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: recorder.port, method, path: target, headers: { host: url.host, 'content-type': 'application/json' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(null)); req.end(method === 'GET' ? undefined : '{}');
  });
  const from = await recorder.mark();
  assert.equal(await via(`http://${CRM}/tickets/T-1/close`), 502);
  assert.equal(await via(`http://crm2.example/tickets/T-1/close`), 502);
  recorder.markWitnessRequest(from);
  await via(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, 'GET');
  // The window may read partial (a 502 closes its connection, which the recorder counts as a possible gap); the events are recorded either way.
  const w = await collectWindow(recorder, from, await recorder.mark());
  const [refused, reset] = [CRM, 'crm2.example'].map(name => w.events.find(e => e.name === name));
  assert.deepEqual([refused.upstream.transport.connected, refused.upstream.transport.wall, refused.upstream.transport.mono > 0, refused.upstream.target.exact], [false, 1760000000000, true, true]);
  assert.equal(reset.upstream.transport.connected, true);
  assert.deepEqual([upstreamState(refused, 'applied'), upstreamState(refused, 'resolved'), upstreamState(reset, 'resolved')], ['unknown', 'no', 'unknown']);
  // The current recorder writes transport records (IN_DOUBT_LABELS: /7, and /8 since the request feed); with no request feed declared, no arrival.
  assert.ok(IN_DOUBT_LABELS.includes(COLLECTOR_RECORDS['egress-recorder'].label));
  assert.deepEqual([Object.keys(refused.upstream.transport), Object.keys(reset.upstream.transport)], [['connected', 'mono', 'wall'], ['connected', 'mono', 'wall']]);
});

// --- The connector and the shared validator ---------------------------------------------------------------------------------------
function egressFactory(events) {
  return configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type];
    const idempotency = Object.fromEntries(c.destinations.filter(d => d.idempotency).map(d => [d.host, validateIdempotencyDeclaration(d.idempotency)]));
    const scope = { operations: ['send'], names: c.destinations.map(d => d.host), actorAttribution: 'none', evidence: 'authoritative', ...forwardRecordOf(c), ...(Object.keys(idempotency).length ? { idempotency } : {}) };
    let mark = 0, served = false;
    return { kind: out.kind, instanceId: `${c.type}-${c.id}`, source: out.source, scope, witnessRequest: null, async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { const list = served ? [] : events(); served = true; return { events: list.map(e => ({ ...e, observer: { kind: out.kind, instanceId: `${c.type}-${c.id}` } })), coverage: 'complete', reason: null }; } };
  });
}
const RECORDER = (extra = {}) => ({ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', settleMs: 250, quietMs: 150, witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS },
  destinations: [{ host: CRM, paths: ['/tickets/T-1/close'], forward: { upstream: 'http://127.0.0.1:47103', rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_CRM_PROOF' }, objectPaths: ['POST /tickets/{ticket}/close'], ...extra }] });
const profile = (effects, { claims, recorder = RECORDER() } = {}) => ({ id: 'idr1-app', name: 'IDR-1 app', applicationId: 'idr1-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-idr1',
  actors: { member: { principalId: 'member-1' } }, requiredControlIds: ['WHOAMI'], observers: [recorder],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'TASK', title: 'Close T-1', category: 'collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/task', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }], effects, ...(claims ? { claims } : {}) }] });
const transport = async (origin, check) => ({ status: check.path === '/me' ? 200 : 201, complete: true, jsonParsed: true, json: check.path === '/me' ? {} : { closed: true }, bytes: 10 });
const reseal = (run, edit) => { const x = structuredClone(run); for (const row of x.results) if (row.trace?.[1]) { edit(row); row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); } return x; };
const runOf = async (effects, events, options) => {
  const p = profile(effects, options);
  const run = await runHttpAssessment(p, { env: {}, transport, observerFactory: egressFactory(events) });
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: {} }).exportSuite(p.id) });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)));
  return { run, row: run.results.find(x => x.id === 'TASK') };
};

test('14. sealed and recomputed: the operation record, the transport-record verdicts and gate B travel with the run; tampering is refused', async () => {
  const claims = [{ trigger: { field: { pointer: '/closed', success: [true], refusal: [false] } }, select: close(), semantics: 'agent-write' }];
  // Refused before any byte left (the transport record refutes it), then retried and applied. Positive clauses: an absence clause pinned to an outcome
  // also needs an allowed-use control twin (the positive-match pairing), which this profile does not declare.
  const { run, row } = await runOf([count(1), { ...ONLY, expect: [{ select: CLOSE_SEL, count: 1 }] }], () => [send(UP.refused), send(UP.applied)], { claims });
  const data = row.trace[1].data;
  assert.equal(run.observers[0].collector.label, COLLECTOR_RECORDS['egress-recorder'].label);
  assert.ok(IN_DOUBT_LABELS.includes(run.observers[0].collector.label));
  assert.deepEqual([...data.effects.map(e => e.verdict), ...data.claims.map(c => c.verdict)], ['pass', 'pass', 'pass']);
  assert.deepEqual(data.effects[0].resolution, { operation: 'confirmed', applied: 1, refuted: 1, inDoubt: 0, attempts: [{ observer: INST, seq: data.windows[0].events[0].seq, fate: 'refuted', by: 'r0', resolvers: ['r0'] }, { observer: INST, seq: data.windows[0].events[1].seq, fate: 'applied', by: 'proof', resolvers: [] }] });
  assert.equal(data.claims[0].resolution.attempts[0].by, 'r0');
  assert.deepEqual([row.backendEvidence, row.assertions.find(a => a.name === BACKEND_ASSERTION).status], ['observed', 'pass']);
  assert.equal(evaluateEffectAssertion({ kind: 'effect.count', select: close('applied'), expected: 1 }, [win(stripTransport([send(UP.refused), send(UP.applied)]), { admit: false })]).verdict, 'missing', 'without the transport records it stays missing');
  const refused = (copy, why) => assert.throws(() => validateHttpRunEvidence(copy), error => error.code === 'invalid-run-evidence', why);
  refused(reseal(run, x => { for (const w of x.trace[1].data.windows) for (const e of w.events) if (e.upstream?.transport) e.upstream.transport.connected = true; }), 'a refused connect edited to connected');
  const unsealed = structuredClone(run); unsealed.results.find(x => x.id === 'TASK').trace[1].data.windows[0].events[0].upstream.transport.connected = true; refused(unsealed, 'the evidence digest');
  refused(reseal(run, x => { x.trace[1].data.effects[0].resolution.operation = 'refuted'; }), 'an edited operation record');
  refused(reseal(run, x => { x.trace[1].data.effects[0].resolution.attempts[0].resolvers = []; }), 'an edited applicability record');
  refused(reseal(run, x => { delete x.trace[1].data.claims[0].resolution; }), 'a dropped operation record');
  const relabelled = structuredClone(run); relabelled.observers[0].collector.label = 'egress-recorder/6'; refused(relabelled, 'egress-recorder/6 never writes a transport record');
  // The same in-doubt pair bound under each label: that build's backend reading under /6, the in-doubt condition under /7.
  const plainWindows = data.windows.map(w => ({ ...w, events: stripTransport(w.events) }));
  const pair = [{ ...plainWindows[0], events: [send(UP.applied), send(UP.unknown)].map(e => ({ ...e, observer: data.windows[0].events[0].observer })) }];
  const under = label => decideEffects([EXISTS], bindSealedWindows(structuredClone(pair), [{ ...run.observers[0], collector: { ...run.observers[0].collector, label } }]))[0];
  assert.deepEqual([under('egress-recorder/6').authoritative, Object.hasOwn(under('egress-recorder/6'), 'resolution')], [true, false]);
  assert.deepEqual([under('egress-recorder/7').authoritative, under('egress-recorder/7').resolution.operation], [false, 'confirmed']);
});

test('15. connector rows: an opted-in pass beside an attempt in doubt is not backend observed; the keyed refused-then-applied case fails end to end', async () => {
  const { row } = await runOf([EXISTS], () => [send(UP.applied), send(UP.reset)]);
  assert.deepEqual([row.trace[1].data.effects[0].verdict, row.backendEvidence, row.assertions.find(a => a.name === BACKEND_ASSERTION).status], ['pass', 'unavailable', 'inconclusive']);
  // A refused attempt beside an applied same-key retry, through the connector and the shared validator: the row fails, and its sealed record agrees with the verdict.
  const keyed = RECORDER({ idempotency: { header: 'idempotency-key' } });
  const keyedEvents = () => { const first = send(UP.refused, { key: '1' }); return [first, send(UP.applied, { key: '1', firstSeq: first.seq })]; };
  const { row: k } = await runOf([KEYED_ONLY([])], keyedEvents, { recorder: keyed });
  const clause = k.trace[1].data.effects[0];
  assert.deepEqual([clause.verdict, k.status, clause.resolution.applied], ['fail', 'fail', 1]);
  const claimed = await runOf([EXISTS], () => [send(UP.applied), send(UP.reset)]);
  const forged = reseal(claimed.run, x => { x.backendEvidence = 'observed'; x.assertions = x.assertions.map(a => a.name === BACKEND_ASSERTION ? { ...a, status: 'pass', actual: 'Authoritative observers decided every declared effect' } : a); });
  assert.throws(() => validateHttpRunEvidence(forged), error => error.code === 'invalid-run-evidence');
});

test('16. label sequencing: each egress-recorder label keeps every capability the one before had (/6 to /7, /7 to /8 since the request feed, /8 to /9 since read-back, /9 to /10 since the exclusive loopback binds, /10 to /11 since declared aliases and sibling hosts, /11 to /12 since the drain\'s quiet recheck, /12 to /13 since another recorder\'s destinations), the target flags included', async () => {
  const current = COLLECTOR_RECORDS['egress-recorder'].label;
  assert.equal(current, 'egress-recorder/13');
  assert.ok(TARGET_LABELS.includes(current) && IN_DOUBT_LABELS.includes(current), 'a /13 run may carry target flags, object routes and transport records');
  const lists = Object.entries(labels).filter(([, v]) => Array.isArray(v) && v.every(x => typeof x === 'string') && v.some(x => x.startsWith('egress-recorder/')));
  assert.ok(lists.length >= 8, lists.map(([k]) => k).join(', '));
  for (const [name, list] of lists) {
    if (list.includes('egress-recorder/6')) assert.ok(list.includes('egress-recorder/7'), `${name} lists /6 but not /7`);
    if (list.includes('egress-recorder/7')) assert.ok(list.includes('egress-recorder/8'), `${name} lists /7 but not /8`);
    if (list.includes('egress-recorder/8')) assert.ok(list.includes('egress-recorder/9'), `${name} lists /8 but not /9`);
    if (list.includes('egress-recorder/9')) assert.ok(list.includes('egress-recorder/10'), `${name} lists /9 but not /10`);
    if (list.includes('egress-recorder/10')) assert.ok(list.includes('egress-recorder/11'), `${name} lists /10 but not /11`);
    if (list.includes('egress-recorder/11')) assert.ok(list.includes('egress-recorder/12'), `${name} lists /11 but not /12`);
    if (list.includes('egress-recorder/12')) assert.ok(list.includes('egress-recorder/13'), `${name} lists /12 but not /13`);
  }
  // A current run whose profile declares object routes and an outcomeJudged clause validates (with its suite) and keeps its object record
  // (no required allowed-use control guards its effect.only, so its pass reads inconclusive: allowed-use-not-declared).
  const { run, row } = await runOf([ONLY], () => [send(UP.refused)]);
  assert.deepEqual([run.observers[0].collector.label, Object.keys(run.observers[0].objects), row.trace[1].data.effects[0].pairing], [current, [CRM], 'allowed-use-not-declared']);
});
