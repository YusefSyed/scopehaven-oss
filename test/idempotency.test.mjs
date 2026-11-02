// Keyed retries. Declaration, key reading, records, window consistency and the application interval.
import test from 'node:test';
import assert from 'node:assert/strict';
import { consistentIdempotencyRun, validateIdempotencyDeclaration, validIdempotencyMap, idempotencyRecordOf, readIdempotencyKey, foldKey, headText, validateIdempotencyRecord, countApplications, applicationsVerdict,
  IDEMPOTENCY_VOLATILE_HEADERS, IDEMPOTENCY_RESERVED_HEADERS } from '../src/idempotency.mjs';
import { makeEffect, evaluateEffectAssertion, validateEffectAssertion, validateWindow, validateScope } from '../src/effect-events.mjs';

const HOST = 'payments.example.test';
const decl = validateIdempotencyDeclaration({ header: 'idempotency-key' });
const hex = c => c.repeat(64);
const observer = { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' };
// A send event with a key record. key/fold/head/content are single hex characters; firstSeq defaults to the group's first seq.
const send = (seq, { key = null, fold = key, status = key === null ? 'absent' : 'keyed', head = 'a', content = 'c', firstSeq = null, token, resource = 'POST /v1/refunds', outcome = 'committed', name = HOST } = {}) => {
  const e = makeEffect({ source: 'http-egress', observer, seq, operation: 'send', name, resource, outcome, correlation: token ? { settlementToken: token } : {}, content: { c: content },
    idempotency: { status, key: key === null ? null : hex(key), fold: fold === null ? null : hex(fold), head: hex(head), firstSeq: key === null ? null : firstSeq ?? seq } });
  return e;
};
const scope = { operations: ['send'], names: [HOST], actorAttribution: 'none', evidence: 'authoritative', idempotency: { [HOST]: decl } };
const win = events => validateWindow({ source: 'http-egress', instanceId: 'egress-recorder-sink', scope, coverage: 'complete', reason: null, events });
const count = expected => ({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: HOST }, expected, countBy: 'idempotency-key' });
const judge = (events, expected) => evaluateEffectAssertion(count(expected), [win(events)], { countBy: true });

test('declaration: header rules, defaults and normalization', () => {
  assert.deepEqual(decl, { header: 'idempotency-key', pointer: null, methods: ['POST'], volatile: [], maxBytes: null });
  assert.deepEqual(validateIdempotencyDeclaration({ header: 'paypal-request-id', methods: ['PATCH', 'POST'], volatile: ['traceparent', 'date'] }),
    { header: 'paypal-request-id', pointer: null, methods: ['POST', 'PATCH'], volatile: ['date', 'traceparent'], maxBytes: null });
  for (const header of ['Idempotency-Key', '', 'a b', '-x', 'x'.repeat(65), 5, ...IDEMPOTENCY_RESERVED_HEADERS, ...IDEMPOTENCY_VOLATILE_HEADERS, 'x-scopehaven-key']) assert.throws(() => validateIdempotencyDeclaration({ header }), /idempotency\.header/, String(header));
  assert.throws(() => validateIdempotencyDeclaration({ header: 'x-run-token' }, { correlationHeader: 'x-run-token' }), /idempotency\.header/);
  for (const methods of [[], ['GET'], ['POST', 'POST'], 'POST', ['POST', 'PUT', 'PATCH', 'DELETE', 'POST']]) assert.throws(() => validateIdempotencyDeclaration({ header: 'idempotency-key', methods }), /methods/);
  for (const volatile of [['authorization'], ['x-tenant'], ['date', 'date'], 'date']) assert.throws(() => validateIdempotencyDeclaration({ header: 'idempotency-key', volatile }), /volatile/);
  assert.throws(() => validateIdempotencyDeclaration({ header: 'idempotency-key', pointer: '/id' }), /exactly one key source/);
  assert.throws(() => validateIdempotencyDeclaration({}), /exactly one key source/);
  assert.throws(() => validateIdempotencyDeclaration({ header: 'idempotency-key', maxBytes: 4096 }), /only with "pointer"/);
  assert.throws(() => validateIdempotencyDeclaration({ header: 'idempotency-key', other: 1 }), /header or pointer/);
  assert.equal(validIdempotencyMap({ [HOST]: decl }), true);
  for (const map of [{}, { [HOST]: { ...decl, methods: ['PUT', 'POST'] } }, { [HOST]: { ...decl, pointer: '/k' } }, { [HOST]: { header: 'idempotency-key' } }, null]) assert.equal(validIdempotencyMap(map), false, JSON.stringify(map));
  assert.deepEqual(idempotencyRecordOf({ type: 'egress-recorder', destinations: [{ host: HOST, idempotency: { header: 'idempotency-key' } }, { host: 'hooks.example.test' }] }), { [HOST]: decl });
  assert.equal(idempotencyRecordOf({ type: 'egress-recorder', destinations: [{ host: HOST }] }), null);
});

test('key reading: one visible-ASCII value under a declared method, never truncated', () => {
  const read = (rawHeaders, method = 'POST') => readIdempotencyKey({ declaration: decl, method, rawHeaders });
  assert.deepEqual(read(['Idempotency-Key', 'k-1']), { status: 'keyed', value: 'k-1' });
  assert.deepEqual(read(['IDEMPOTENCY-KEY', '"Quoted"']), { status: 'keyed', value: '"Quoted"' });
  assert.equal(read(['Idempotency-Key', 'k-1'], 'GET').status, 'not-applicable');
  assert.equal(read([]).status, 'absent');
  for (const method of ['PUT', 'DELETE', 'PATCH']) assert.equal(read(['idempotency-key', 'k'], method).status, 'method-undeclared', method);
  for (const method of ['GET', 'HEAD', 'OPTIONS']) assert.equal(read(['idempotency-key', 'k'], method).status, 'not-applicable', method);
  assert.equal(read([], 'PUT').status, 'not-applicable');
  assert.equal(read(['idempotency-key', 'a', 'Idempotency-Key', 'a']).status, 'repeated');
  for (const value of ['', 'a b', 'a\tb', 'é', 'a\u0000']) assert.equal(read(['idempotency-key', value]).status, 'malformed', JSON.stringify(value));
  assert.equal(read(['idempotency-key', 'k'.repeat(255)]).status, 'keyed');
  assert.equal(read(['idempotency-key', 'k'.repeat(256)]).status, 'over-cap');
  assert.equal(foldKey('"ABC-1"'), 'abc-1');
  assert.equal(foldKey('"'), '"');
  assert.equal(headText({ method: 'POST', rawTarget: '/a', rawHeaders: ['B', '2', 'a', '1', 'Idempotency-Key', 'k', 'b', '3', 'Content-Length', '9'], exclude: ['idempotency-key', 'content-length'] }),
    'POST\n/a\n[["a",["1"]],["b",["2","3"]]]');
});

test('records: shape by status, and window consistency', () => {
  assert.doesNotThrow(() => validateIdempotencyRecord({ status: 'keyed', key: hex('1'), fold: hex('1'), head: hex('a'), firstSeq: 3 }, 3));
  for (const rec of [{ status: 'keyed', key: hex('1'), fold: hex('1'), head: hex('a'), firstSeq: 4 }, { status: 'keyed', key: null, fold: null, head: hex('a'), firstSeq: null },
    { status: 'absent', key: hex('1'), fold: null, head: hex('a'), firstSeq: null }, { status: 'odd', key: null, fold: null, head: hex('a'), firstSeq: null }, { status: 'absent', key: null, fold: null, head: 'x', firstSeq: null },
    { status: 'absent', key: null, fold: null, head: hex('a'), firstSeq: null, extra: 1 }]) assert.throws(() => validateIdempotencyRecord(rec, 3), /idempotency-record/, JSON.stringify(rec));
  assert.doesNotThrow(() => win([send(1, { key: '1' }), send(2, { key: '1', firstSeq: 1 })]));
  // One key, two folds; one fold, two first uses; a first use after the fold's first send; the same send with another resource.
  for (const events of [[send(1, { key: '1', fold: '2' }), send(2, { key: '1', fold: '3', firstSeq: 1 })], [send(1, { key: '1' }), send(2, { key: '1', firstSeq: 2 })],
    [send(1, { key: '1', firstSeq: 1 }), send(2, { key: '1', firstSeq: 2 })], [send(1, { key: '1' }), send(2, { key: '1', firstSeq: 1, resource: 'POST *' })]]) assert.throws(() => win(events), /idempotency-window/);
  assert.throws(() => win([send(1), send(2, { key: '1', firstSeq: 1 })]), /idempotency-window/, 'a first use pointing at a clean keyless send');
  assert.doesNotThrow(() => win([send(1, { status: 'repeated' }), send(2, { key: '1', firstSeq: 1 })]), 'a first use pointing at a dirty send to the host');
  assert.throws(() => validateScope({ ...scope, idempotency: { 'other.test': decl } }), /scope-idempotency/);
  assert.throws(() => makeEffect({ source: 'smtp-capture', observer, seq: 1, operation: 'send', name: HOST, outcome: 'committed', idempotency: { status: 'absent', key: null, fold: null, head: hex('a'), firstSeq: null } }), /idempotency-source/);
});

test('countBy clause: only effect.count of 1 or more over an exact egress host; refused where not opted in', () => {
  assert.doesNotThrow(() => validateEffectAssertion(count(1), 'a', { countBy: true }));
  assert.throws(() => validateEffectAssertion(count(1)), /effect-count-by-unsupported/);
  const bad = (patch, code) => assert.throws(() => validateEffectAssertion({ ...count(1), ...patch }, 'a', { countBy: true }), code);
  bad({ countBy: 'other' }, /effect-count-by/);
  bad({ kind: 'effect.none' }, /effect-assertion/);
  bad({ expected: 0 }, /effect-count-by-absence/);
  bad({ select: { source: 'sql-snapshot', operation: 'insert', name: 't' } }, /effect-count-by-source/);
  bad({ select: { source: 'http-egress', name: { prefix: 'pay' } } }, /effect-count-by-name/);
  bad({ select: { source: 'http-egress', operation: 'read', name: HOST } }, /effect-count-by-operation/);
});

test('applications: exact sequential replays of one key count once; everything ambiguous reads missing', () => {
  const v = (events, expected) => { const d = judge(events, expected); return [d.verdict, d.applications && [d.applications.low, d.applications.high]]; };
  // An exact replay: one application.
  assert.deepEqual(v([send(1, { key: '1' }), send(2, { key: '1', firstSeq: 1 })], 1), ['pass', [1, 1]]);
  assert.deepEqual(v([send(1, { key: '1' }), send(2, { key: '1', firstSeq: 1 })], 2), ['fail', [1, 1]]);
  // Two keys, or a keyless retry: two applications, a real double.
  assert.deepEqual(v([send(1, { key: '1' }), send(2, { key: '2' })], 1), ['fail', [2, 2]]);
  assert.deepEqual(v([send(1, { key: '1' }), send(2)], 1), ['fail', [2, 2]]);
  assert.deepEqual(v([send(1), send(2)], 2), ['pass', [2, 2]]);
  // Same key, changed content, head or token: [1, 2].
  for (const patch of [{ content: 'd' }, { head: 'b' }, { token: 'tok-2' }]) assert.deepEqual(v([send(1, { key: '1', token: 'tok-1' }), send(2, { key: '1', firstSeq: 1, token: 'tok-1', ...patch })], 1), ['missing', [1, 2]], JSON.stringify(patch));
  // Case or quote variants share a fold: [1, 2].
  assert.deepEqual(v([send(1, { key: '1', fold: '9' }), send(2, { key: '2', fold: '9', firstSeq: 1 })], 1), ['missing', [1, 2]]);
  // Concurrent: never collapsed.
  assert.deepEqual(v([send(1, { key: '1', status: 'overlap' }), send(2, { key: '1', status: 'overlap', firstSeq: 1 })], 1), ['missing', [1, 2]]);
  // Used before this window: [0, 1].
  assert.deepEqual(v([send(5, { key: '1', firstSeq: 2 }), send(6, { key: '1', firstSeq: 2 })], 1), ['missing', [0, 1]]);
  // A dirty send to the host drops every group's lower bound, counted or not.
  for (const status of ['method-undeclared', 'repeated', 'malformed', 'over-cap', 'unreadable', 'untracked']) {
    // The host-wide selector counts the dirty send too: [0, 2].
    assert.deepEqual(v([send(1, { key: '1' }), send(2, { key: '1', firstSeq: 1 }), send(3, { status, resource: 'POST *' })], 1), ['missing', [0, 2]], status);
    assert.deepEqual(v([send(1, { status })], 1), ['missing', [0, 1]], status);
  }
  // Bounds still decide a certain miscount.
  assert.deepEqual(v([send(1, { key: '1' }), send(2, { key: '2' }), send(3, { key: '3', status: 'overlap' }), send(4, { key: '3', status: 'overlap', firstSeq: 3 })], 1), ['fail', [3, 4]]);
  // Without a key record for the host the clause cannot count applications.
  const plainScope = { ...scope }; delete plainScope.idempotency;
  const plainWindow = validateWindow({ source: 'http-egress', instanceId: 'egress-recorder-sink', scope: plainScope, coverage: 'complete', reason: null, events: [makeEffect({ source: 'http-egress', observer, seq: 1, operation: 'send', name: HOST, outcome: 'committed' })] });
  assert.equal(evaluateEffectAssertion(count(1), [plainWindow], { countBy: true }).verdict, 'unobservable');
  assert.throws(() => evaluateEffectAssertion(count(1), [plainWindow]), /effect-count-by-unsupported/, 'a caller that does not opt in refuses countBy');
  // The plain count beside it is unchanged: it counts sends.
  const { countBy, ...raw } = count(2);
  assert.equal(evaluateEffectAssertion(raw, [win([send(1, { key: '1' }), send(2, { key: '1', firstSeq: 1 })])]).verdict, 'pass');
});

test('applicationsVerdict and countApplications edges', () => {
  assert.equal(applicationsVerdict({ low: 2, high: 2 }, 2), 'pass');
  assert.equal(applicationsVerdict({ low: 0, high: 1 }, 2), 'fail');
  assert.equal(applicationsVerdict({ low: 2, high: 3 }, 1), 'fail');
  assert.equal(applicationsVerdict({ low: 0, high: 2 }, 1), 'missing');
  // A group whose first member is not counted (another resource) never collapses the counted one into it.
  const w = win([send(1, { key: '1', resource: 'POST *', content: 'z' }), send(2, { key: '1', firstSeq: 1 })]);
  const counted = w.events.filter(e => e.resource === 'POST /v1/refunds');
  assert.deepEqual(countApplications(w, HOST, counted), { low: 0, high: 1, replays: 0, reason: 'idempotency-key-content-differs' });
  // Another host's sends never join the group.
  const other = win([send(1, { key: '1' }), send(2, { key: '2', name: 'other.example.test' })]);
  assert.deepEqual(countApplications(other, HOST, other.events.slice(0, 1)), { low: 1, high: 1, replays: 0, reason: null });
});

test('run consistency: one first use per observer fold across every sealed window', () => {
  const w1 = win([send(3, { key: '1' })]), w2 = win([send(9, { key: '1', firstSeq: 3 })]);
  assert.doesNotThrow(() => consistentIdempotencyRun([w1, w2]));
  const edited = win([send(9, { key: '1', firstSeq: 9 })]);
  assert.throws(() => consistentIdempotencyRun([w1, edited]), /idempotency-run/, 'a first use edited to this window');
  assert.throws(() => consistentIdempotencyRun([win([send(2, { key: '1' })]), win([send(5, { key: '1', firstSeq: 5 })])]), /idempotency-run/, 'each row claiming its own first use');
  assert.doesNotThrow(() => consistentIdempotencyRun([win([send(3, { key: '1', firstSeq: 1 })]), win([send(9, { key: '1', firstSeq: 1 })])]), 'a first use before every sealed window');
  // Another observer instance's fold is another key space.
  const other = { ...win([send(9, { key: '1', firstSeq: 9 })]), instanceId: 'egress-recorder-other' };
  assert.doesNotThrow(() => consistentIdempotencyRun([w1, other]));
});
