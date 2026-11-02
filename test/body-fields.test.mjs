// Declared body-field capture (src/body-fields.mjs) and the three-valued `fields` selector
// (src/effect-events.mjs), with its consumers: effect.only, settlement and pairing. Pure: no I/O.
import test from 'node:test';
import assert from 'node:assert/strict';
import { captureBody, validateCaptureDeclaration, validatePointer, validateCaptured, validateFieldPredicates, fieldState, secretShaped, countKeyTokens, CAPTURE_STATUSES } from '../src/body-fields.mjs';
import { makeEffect, validateEffect, validateSelector, validateEffectAssertion, evaluateEffectAssertion, matchState, matches, windowSees, validateScope } from '../src/effect-events.mjs';
import { validateEgressConfig } from '../src/egress-rules.mjs';
import { judgeOnly, validateOnlyAssertion } from '../integrations/collateral/only.mjs';
import { fitsSelector, settlementFindings } from '../src/http-settlement.mjs';
import { selectorPairs, showsPin, PINNED_KEYS } from '../src/http-pairing.mjs';
import { decideEffects, validateDeclaredEffect, declaredObserverRecord, bindSealedWindows } from '../src/http-effects.mjs';
import { checkAssertion } from '../integrations/sequences/sequence.mjs';
// Every egress recorder record carries its collector identity.
import { COLLECTOR_RECORDS } from '../src/collector-identity.mjs';

const PAY = 'payments.example.test';
const capture = { pointers: ['/amount', '/currency', '/ticket_id', '/meta/channel'], maxBytes: 4096 };
const json = (value, extra = []) => ({ rawHeaders: ['Content-Type', 'application/json', ...extra], buffer: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)) });
// search '': the recorder's reading of a request without a URL query (src/body-fields.mjs records absence beside a query as unusable).
const read = (value, extra) => { const r = json(value, extra); return captureBody({ ...r, bodyBytes: r.buffer.length, capture, search: '' }); };
const observer = { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' };
let seq = 0;
const send = (captured, { name = PAY, resource = 'POST /v1/refunds', outcome = 'committed' } = {}) => makeEffect({ source: 'http-egress', observer, seq: ++seq, operation: 'send', name, resource, outcome, content: { body: 'x' }, ...(captured === undefined ? {} : { captured }) });
const scope = (withCapture = true) => ({ operations: ['send'], names: [PAY, 'hooks.example.test'], actorAttribution: 'none', evidence: 'authoritative', ...(withCapture ? { capture: { [PAY]: capture.pointers } } : {}) });
const windowOf = (events, { withCapture = true, coverage = 'complete' } = {}) => ({ source: 'http-egress', instanceId: observer.instanceId, scope: scope(withCapture), coverage, reason: coverage === 'complete' ? null : 'egress-witness-not-received', events });
const select = fields => ({ source: 'http-egress', operation: 'send', name: PAY, fields });
const amount = (op, value) => [{ pointer: '/amount', [op]: value }];

test('capture is opt-in: a destination without capture keeps digests only, and its config has no capture', () => {
  const cfg = validateEgressConfig({ port: 47000, destinations: [{ host: PAY }] });
  assert.equal(Object.hasOwn(cfg.destinations[0], 'capture'), false);
  const e = send(undefined);
  assert.equal(Object.hasOwn(e, 'captured'), false);
  assert.match(e.contentDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(declaredObserverRecord([{ id: 'sink', type: 'egress-recorder', destinations: [{ host: PAY }] }]), [{ id: 'sink', type: 'egress-recorder', settleMs: null, collector: COLLECTOR_RECORDS['egress-recorder'] }]);
});

test('deny-list: secret-like keys are refused even when declared, also as interior tokens and in any case or separator', () => {
  for (const pointer of ['/password', '/user/Password', '/api_key', '/apiKey', '/x-api-key', '/auth/token', '/refresh_token', '/Authorization', '/cookie', '/sessionId', '/card/last4', '/card_number', '/cvv', '/CVC',
    '/pan', '/pin', '/ssn', '/sin', '/iban', '/account_number', '/accountNumber', '/client_secret', '/private_key', '/accessKey', '/credentials/0', '/passphrase', '/bearer']) {
    assert.throws(() => validatePointer(pointer), /secret-like key/, pointer);
    assert.throws(() => validateEgressConfig({ port: 47000, destinations: [{ host: PAY, capture: { pointers: [pointer] } }] }), /secret-like key/, pointer);
  }
  // Adjacent allowed: ordinary business fields, including ones that merely start with a denied token's letters.
  for (const pointer of ['/amount', '/currency', '/ticket_id', '/items/0/sku', '/template', '/recipient_count', '/pages', '/sinceDays', '/opinion']) assert.doesNotThrow(() => validatePointer(pointer), pointer);
});

test('declaration bounds: no whole-body pointer, 1 to 16 pointers per destination, 64 per recorder, maxBytes within bounds and maxBodyBytes', () => {
  const bad = (cap, pattern, extra = {}) => assert.throws(() => validateEgressConfig({ port: 47000, destinations: [{ host: PAY, capture: cap }], ...extra }), pattern);
  bad({ pointers: [''] }, /whole body is never captured/);
  bad({ pointers: ['amount'] }, /starting with "\/"/);
  bad({ pointers: [] }, /1 to 16/);
  bad({ pointers: Array.from({ length: 17 }, (_, i) => `/f${i}`) }, /1 to 16/);
  bad({ pointers: ['/a', '/a'] }, /1 to 16 distinct/);
  bad({ pointers: ['/a/b/c/d/e/f/g/h/i'] }, /at most 8 tokens/);
  bad({ pointers: ['/__proto__'] }, /__proto__/);
  bad({ pointers: ['/a~2'] }, /JSON pointer/);
  bad({ pointers: ['/a'], maxBytes: 512 }, /maxBytes/);
  bad({ pointers: ['/a'], maxBytes: 70000 }, /maxBytes/);
  bad({ pointers: ['/a'], maxBytes: 4096 }, /maxBytes/, { maxBodyBytes: 2048 });
  bad({ pointers: ['/a'], whole: true }, /\{ pointers, maxBytes\? \}/);
  const many = Array.from({ length: 5 }, (_, d) => ({ host: `h${d}.example.test`, paths: ['/v1'], capture: { pointers: Array.from({ length: 13 }, (_, i) => `/f${i}`) } }));
  assert.throws(() => validateEgressConfig({ port: 47000, destinations: many }), /at most 64 body fields/);
  assert.deepEqual(validateCaptureDeclaration({ pointers: ['/a'] }, 1024 * 1024), { pointers: ['/a'], maxBytes: 16384 });
  assert.deepEqual(validateCaptureDeclaration({ pointers: ['/a'] }, 4096), { pointers: ['/a'], maxBytes: 4096 });
});

test('captureBody: declared scalar fields only, typed; every unreadable body says why and keeps no values', () => {
  const ok = read({ amount: 25, currency: 'cad', ticket_id: 'T-1', note: 'never stored', meta: { channel: 'web' } });
  assert.deepEqual(ok, { status: 'captured', values: { '/amount': { type: 'number', value: 25 }, '/currency': { type: 'string', value: 'cad' }, '/ticket_id': { type: 'string', value: 'T-1' }, '/meta/channel': { type: 'string', value: 'web' } } });
  assert.ok(!JSON.stringify(ok).includes('never stored'), 'an undeclared field is never kept');
  assert.deepEqual(read({ amount: { value: 25 }, currency: ['cad'], ticket_id: 'x'.repeat(201), meta: { channel: null } }).values,
    { '/amount': { type: 'unusable', reason: 'not-scalar' }, '/currency': { type: 'unusable', reason: 'not-scalar' }, '/ticket_id': { type: 'unusable', reason: 'value-over-cap' }, '/meta/channel': { type: 'null', value: null } });
  assert.deepEqual(read({ amount: 2 ** 60 }).values['/amount'], { type: 'unusable', reason: 'number-unsafe' });
  assert.deepEqual(read({ currency: 'cad' }).values['/amount'], { type: 'absent' });
  const status = (r, bodyBytes = r.buffer.length, cap = capture) => captureBody({ ...r, bodyBytes, capture: cap }).status;
  assert.equal(captureBody({ rawHeaders: [], buffer: Buffer.alloc(0), bodyBytes: 0, capture }).status, 'no-body');
  assert.equal(status({ rawHeaders: ['Content-Type', 'application/json', 'content-type', 'text/plain'], buffer: Buffer.from('{"amount":25}') }), 'content-type-ambiguous');
  assert.equal(status({ rawHeaders: ['Content-Type', 'application/x-www-form-urlencoded'], buffer: Buffer.from('amount=25') }), 'not-json');
  assert.equal(status({ rawHeaders: [], buffer: Buffer.from('{"amount":25}') }), 'not-json');
  assert.equal(status({ rawHeaders: ['Content-Type', 'application/json; charset=latin1'], buffer: Buffer.from('{"amount":25}') }), 'not-json');
  assert.equal(status({ rawHeaders: ['Content-Type', 'application/vnd.api+json; charset=UTF-8'], buffer: Buffer.from('{"amount":25}') }), 'captured');
  assert.equal(status(json({ amount: 25 }, ['Content-Encoding', 'gzip'])), 'encoded');
  assert.equal(status(json({ amount: 25 }, ['Content-Encoding', 'identity'])), 'captured');
  assert.equal(status({ ...json({ amount: 25 }), buffer: null }, 5000), 'over-cap');
  assert.equal(status(json('{"amount":25')), 'json-invalid');
  assert.equal(status({ rawHeaders: ['Content-Type', 'application/json'], buffer: Buffer.from([0x7b, 0xff, 0x7d]) }), 'json-invalid');
  assert.equal(status(json('['.repeat(40) + ']'.repeat(40))), 'json-too-deep');
  assert.equal(status(json('{"amount":25,"amount":250}')), 'json-duplicate-key');
  assert.equal(status(json('{"meta":{"channel":"web","channel":"api"}}')), 'json-duplicate-key', 'a repeated nested key too');
  assert.equal(countKeyTokens('{"a":"b:\\"c\\":","d":[{"e":1}]}'), 3);
  for (const s of CAPTURE_STATUSES.filter(x => x !== 'captured')) assert.doesNotThrow(() => validateCaptured({ status: s, values: {} }));
});

test('secret-shaped values are redacted and never stored, whatever the key; ordinary ids are kept', () => {
  for (const value of ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc', 'sk_live_51Habc', 'rk_test_123', 'Bearer abc.def', '-----BEGIN PRIVATE KEY-----', 'a'.repeat(40), 'f'.repeat(32), 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo+/abc']) {
    assert.equal(secretShaped(value), true, value);
    assert.deepEqual(read({ ticket_id: value }).values['/ticket_id'], { type: 'unusable', reason: 'redacted' });
    assert.throws(() => validateCaptured({ status: 'captured', values: { '/ticket_id': { type: 'string', value } } }), /captured-value/);
  }
  for (const value of ['T-000123', '550e8400-e29b-41d4-a716-446655440000', 'refund approved for order 42', 'cad']) assert.equal(secretShaped(value), false, value);
});

test('events: captured is optional, http-egress only, shape-checked; old events still validate', () => {
  const values = { '/amount': { type: 'number', value: 25 } };
  assert.doesNotThrow(() => validateEffect(send({ status: 'captured', values })));
  assert.doesNotThrow(() => validateEffect(send(undefined)));
  const audit = { ...send(undefined), source: 'http-audit-log', captured: { status: 'captured', values } };
  assert.throws(() => validateEffect(audit), /captured-source/);
  assert.throws(() => validateEffect({ ...send(undefined), captured: { status: 'not-json', values } }), /captured-values/);
  assert.throws(() => validateEffect({ ...send(undefined), captured: { status: 'captured', values: { '/password': { type: 'string', value: 'x' } } } }), /captured-pointer/);
  assert.throws(() => validateEffect({ ...send(undefined), captured: { status: 'captured', values: { '/amount': { type: 'number', value: '25' } } } }), /captured-value/);
  assert.throws(() => validateEffect({ ...send(undefined), captured: { status: 'captured', values: { '/amount': { type: 'string', value: 'x'.repeat(201) } } } }), /captured-value/);
  assert.throws(() => validateEffect({ ...send(undefined), captured: { status: 'bogus', values: {} } }), /captured/);
});

test('fields selector: opt-in only; sequences, verdict services and collateral refuse it; an exact name is required', () => {
  const s = select(amount('equals', 25));
  assert.throws(() => validateSelector(s), /selector-fields-unsupported/);
  assert.doesNotThrow(() => validateSelector(s, 'x', { fields: true }));
  assert.throws(() => validateEffectAssertion({ kind: 'effect.exists', select: s }), /selector-fields-unsupported/, 'sequences validate effect assertions without the option');
  assert.doesNotThrow(() => validateDeclaredEffect({ kind: 'effect.exists', select: s }));
  assert.throws(() => validateOnlyAssertion({ kind: 'effect.only', allow: [s] }), /selector/, 'collateral validates effect.only without the option');
  assert.doesNotThrow(() => validateOnlyAssertion({ kind: 'effect.only', allow: [s] }, 'x', { fields: true }));
  assert.throws(() => validateSelector({ ...s, name: { prefix: 'pay' } }, 'x', { fields: true }), /selector-fields-name/);
  for (const fields of [[], [{ pointer: '/amount' }], [{ pointer: '/amount', equals: 1, in: [1] }], [{ pointer: '/amount', gt: '5' }], [{ pointer: '/amount', in: [] }], [{ pointer: '/amount', equals: {} }], [{ pointer: '/token', equals: 'x' }], Array(9).fill({ pointer: '/amount', equals: 1 })])
    assert.throws(() => validateFieldPredicates(fields), /selector-fields/, JSON.stringify(fields));
  assert.throws(() => checkAssertion({ id: 'a', from: 'm1', to: 'm2', title: 't', severity: 'high', effect: { kind: 'effect.exists', select: s } }, message => { throw new Error(message); }), /selector-fields-unsupported/, 'a sequence assertion refuses fields');
});

test('three-valued matching: base keys first, then match / no / unknown; type mismatch is unknown, never no', () => {
  const c = v => send({ status: 'captured', values: { '/amount': v, '/currency': { type: 'string', value: 'cad' }, '/ticket_id': { type: 'absent' }, '/meta/channel': { type: 'null', value: null } } });
  const e25 = c({ type: 'number', value: 25 }), e250 = c({ type: 'number', value: 250 }), str = c({ type: 'string', value: '250' });
  assert.equal(matchState(e25, select(amount('equals', 25))), 'match');
  assert.equal(matchState(e250, select(amount('equals', 25))), 'no');
  assert.equal(matchState(str, select(amount('equals', 250))), 'unknown', 'the string "250" never equals the number 250');
  assert.equal(matchState(str, select(amount('gt', 100))), 'unknown');
  assert.equal(matchState(e250, select(amount('gt', 100))), 'match');
  assert.equal(matchState(e25, select([{ pointer: '/amount', gte: 25 }, { pointer: '/amount', lte: 25 }])), 'match');
  assert.equal(matchState(e25, select([{ pointer: '/amount', in: [10, 25, 'x'] }])), 'match');
  assert.equal(matchState(e25, select([{ pointer: '/amount', in: ['25'] }])), 'unknown');
  assert.equal(matchState(e25, select([{ pointer: '/ticket_id', equals: 'T-1' }])), 'unknown', 'absent is unknown');
  assert.equal(matchState(e25, select([{ pointer: '/meta/channel', equals: null }])), 'match');
  assert.equal(matchState(e25, select([{ pointer: '/amount', equals: 25 }, { pointer: '/ticket_id', equals: 'x' }])), 'unknown');
  assert.equal(matchState(e250, select([{ pointer: '/amount', equals: 25 }, { pointer: '/ticket_id', equals: 'x' }])), 'no', 'any decided no wins');
  assert.equal(matchState(send(undefined), select(amount('equals', 25))), 'unknown', 'no captured record');
  assert.equal(matchState(send({ status: 'not-json', values: {} }), select(amount('equals', 25))), 'unknown');
  assert.equal(matchState(send(undefined, { name: 'hooks.example.test' }), select(amount('equals', 25))), 'no', 'a base miss is no, even without a captured record');
  assert.equal(matches(str, select(amount('equals', 250))), false);
  assert.equal(fieldState(undefined, { pointer: '/amount', equals: 1 }), 'unknown');
});

test('windowSees: a field selector is visible only where capture of every pointer it uses is declared for that name', () => {
  assert.equal(windowSees(windowOf([]), select(amount('equals', 25))), true);
  assert.equal(windowSees(windowOf([], { withCapture: false }), select(amount('equals', 25))), false);
  assert.equal(windowSees(windowOf([]), select([{ pointer: '/amout', equals: 25 }])), false, 'a pointer typo is unobservable, never absent');
  assert.equal(windowSees(windowOf([]), { ...select(amount('equals', 25)), name: 'hooks.example.test' }), false);
  assert.throws(() => validateScope({ ...scope(), capture: { 'unknown.example': ['/amount'] } }), /scope-capture/);
  assert.throws(() => validateScope({ ...scope(), capture: { [PAY]: ['/password'] } }), /scope-capture/);
});

test('effect clauses: decided match passes or fails; unknown is missing; undeclared capture is unobservable', () => {
  const v = n => ({ status: 'captured', values: { '/amount': { type: 'number', value: n }, '/currency': { type: 'string', value: 'cad' }, '/ticket_id': { type: 'absent' }, '/meta/channel': { type: 'absent' } } });
  const exists25 = { kind: 'effect.exists', select: select(amount('equals', 25)) }, none25 = { kind: 'effect.none', select: select(amount('equals', 25)) };
  const count25 = { kind: 'effect.count', expected: 1, select: select(amount('equals', 25)) };
  const verdict = (a, events, opts) => evaluateEffectAssertion(a, [windowOf(events, opts)]).verdict;
  assert.equal(verdict(exists25, [send(v(25))]), 'pass');
  assert.equal(verdict(exists25, [send(v(250))]), 'fail', 'a $250 refund is not the $25 one');
  assert.equal(verdict(none25, [send(v(250))]), 'pass');
  assert.equal(verdict(none25, [send(v(25))]), 'fail');
  assert.equal(verdict(count25, [send(v(25)), send(v(250))]), 'pass');
  assert.equal(verdict(count25, [send(v(25)), send(v(25))]), 'fail');
  // Unreadable bodies are never absence and never presence.
  for (const unread of [undefined, { status: 'not-json', values: {} }, { status: 'captured', values: { '/amount': { type: 'absent' }, '/currency': { type: 'absent' }, '/ticket_id': { type: 'absent' }, '/meta/channel': { type: 'absent' } } }]) {
    assert.equal(verdict(exists25, [send(unread)]), 'missing', JSON.stringify(unread));
    assert.equal(verdict(none25, [send(unread)]), 'missing');
    assert.equal(verdict(count25, [send(unread)]), 'missing');
  }
  const r = evaluateEffectAssertion(none25, [windowOf([send(undefined)])]);
  assert.match(r.basis, /declared body fields could not be read/);
  // A decided match still decides beside an unreadable send.
  assert.equal(verdict(none25, [send(undefined), send(v(25))]), 'fail');
  assert.equal(verdict(exists25, [send(undefined), send(v(25))]), 'pass');
  // An unrelated send to another destination does not make the clause undecided.
  assert.equal(verdict(none25, [send(undefined, { name: 'hooks.example.test' })]), 'pass');
  assert.equal(verdict(none25, [], { withCapture: false }), 'unobservable');
  assert.equal(verdict(none25, [], { coverage: 'partial' }), 'missing');
});

test('effect.only: an unreadable judged send holds a pass at missing and is never offending; a decided offender still fails', () => {
  const v = n => ({ status: 'captured', values: { '/amount': { type: 'number', value: n }, '/currency': { type: 'absent' }, '/ticket_id': { type: 'absent' }, '/meta/channel': { type: 'absent' } } });
  const only = { kind: 'effect.only', expect: [{ select: { ...select(amount('lte', 50)), resource: 'POST /v1/refunds' } }], allow: [], operations: ['send'] };
  const judge = events => judgeOnly(only, [windowOf(events)], { fields: true });
  assert.equal(judge([send(v(25))]).verdict, 'pass');
  assert.equal(judge([send(v(250))]).verdict, 'fail');
  const held = judge([send(undefined)]);
  assert.equal(held.verdict, 'missing'); assert.equal(held.counts.offending, 0);
  assert.equal(judge([send(undefined), send(v(250))]).verdict, 'fail', 'a fail stays a fail');
  assert.throws(() => judgeOnly(only, [windowOf([])]), /selector/, 'without the option, fields are refused');
});

test('settlement and pairing: an unreadable later send fits the selector; a fields pin needs a twin with the same fields', () => {
  const s = select(amount('equals', 25));
  assert.equal(fitsSelector(send(undefined), s), true, 'unknown fits, as an unknown actor does');
  assert.equal(fitsSelector(send({ status: 'captured', values: { '/amount': { type: 'number', value: 250 } } }), s), false);
  const v25 = { status: 'captured', values: { '/amount': { type: 'number', value: 25 }, '/currency': { type: 'absent' }, '/ticket_id': { type: 'absent' }, '/meta/channel': { type: 'absent' } } };
  const rowA = { effects: decideEffects([{ kind: 'effect.none', select: s }], [windowOf([])], { role: 'control' }), windows: [windowOf([])] };
  const findings = settlementFindings([rowA], [[windowOf([])], [windowOf([send(undefined)])]]);
  assert.deepEqual(findings, [['effect-outside-window']], 'a later unreadable send withholds an absence pass');
  assert.deepEqual(settlementFindings([rowA], [[windowOf([])], [windowOf([send(v25)].slice(0, 0))]]), [[null]]);
  assert.ok(PINNED_KEYS.includes('fields'));
  const principals = { a: 'p-a' };
  assert.equal(showsPin('fields', s, 'a', { ...s }, 'a', principals), true);
  assert.equal(showsPin('fields', s, 'a', select(amount('equals', 26)), 'a', principals), false);
  assert.equal(showsPin('actor', { ...s, actor: 'p-a' }, 'a', { source: 'http-egress', operation: 'send', name: PAY, actor: 'p-a' }, 'a', principals), true, 'an actor twin need not carry the fields');
  const target = { actors: { a: { principalId: 'p-a' } }, checks: [
    { id: 'B', severity: 'high', actorId: 'a', effects: [{ kind: 'effect.none', select: s }] },
    { id: 'C', severity: 'control', actorId: 'a', effects: [{ kind: 'effect.exists', select: s }] }] };
  assert.deepEqual(selectorPairs(target).get('B')[0].pins, { fields: [{ checkId: 'C', effect: 0 }] });
});

test('sealed windows: the scope must publish exactly the declared capture, and captured records exactly its pointers', () => {
  const declared = [{ id: 'sink', type: 'egress-recorder', settleMs: 250, capture: { [PAY]: capture.pointers } }];
  const v = { status: 'captured', values: Object.fromEntries(capture.pointers.map(p => [p, { type: 'absent' }])) };
  const sealed = w => [{ ...w, settleMs: 250, lineage: { observer: 'http-egress-recorder', independence: 'request-path' } }];
  assert.doesNotThrow(() => bindSealedWindows(sealed(windowOf([send(v)])), declared));
  assert.throws(() => bindSealedWindows(sealed(windowOf([send(v)], { withCapture: false })), declared), /effect-trace/, 'a scope without the declaration');
  assert.throws(() => bindSealedWindows(sealed(windowOf([])), [{ ...declared[0], capture: undefined }].map(({ capture: _, ...o }) => o)), /effect-trace/, 'a scope with an undeclared capture');
  const partial = { status: 'captured', values: { '/amount': { type: 'number', value: 25 } } };
  assert.throws(() => bindSealedWindows(sealed(windowOf([send(partial)])), declared), /effect-trace/, 'a captured record with fewer pointers');
});

test('field-blind observers: one that sees the base effect but cannot read the fields holds an absence at missing, never pass', () => {
  const blindScope = (pointers) => ({ operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative', ...(pointers ? { capture: { [PAY]: pointers } } : {}) });
  const win = (instanceId, events, pointers, coverage = 'complete') => ({ source: 'http-egress', instanceId, scope: blindScope(pointers), coverage, reason: coverage === 'complete' ? null : 'egress-witness-not-received', events });
  const otherObserver = { kind: 'http-egress-recorder', instanceId: 'rec-b' };
  const sendB = () => makeEffect({ source: 'http-egress', observer: otherObserver, seq: ++seq, operation: 'send', name: PAY, resource: 'POST /v1/refunds', outcome: 'committed', content: { body: 'x' } });
  const none = { kind: 'effect.none', select: select(amount('gt', 100)) }, exists = { kind: 'effect.exists', select: select(amount('gt', 100)) }, count = { kind: 'effect.count', expected: 0, select: select(amount('gt', 100)) };
  const a = win(observer.instanceId, [], ['/amount']);
  for (const pointers of [undefined, ['/currency']]) {
    const b = win('rec-b', [sendB()], pointers);
    assert.equal(evaluateEffectAssertion(none, [a, b]).verdict, 'missing', `rec-b capture ${JSON.stringify(pointers)}: a send it cannot read may be the selected one`);
    assert.match(evaluateEffectAssertion(none, [a, b]).basis, /does not capture those fields/);
    assert.equal(evaluateEffectAssertion(exists, [a, b]).verdict, 'missing');
    assert.equal(evaluateEffectAssertion(count, [a, b]).verdict, 'missing');
    assert.deepEqual(decideEffects([none], [a, b], { role: 'boundary' }).map(d => d.verdict), ['missing']);
    // A refusal claim selects effect.none through the same rule.
    const claim = { trigger: { field: { pointer: '/status', success: ['issued'], refusal: ['declined'] } }, select: select(amount('gt', 100)) };
    assert.deepEqual(decideEffects([], [a, b], { role: 'boundary', claims: [claim], readings: [{ reading: 'refusal', valueIndex: 0 }] }).map(d => [d.kind, d.verdict]), [['effect.none', 'missing']]);
  }
  // Adjacent allowed: the blind observer recorded nothing, or only another destination: the capturing one decides.
  assert.equal(evaluateEffectAssertion(none, [a, win('rec-b', [])]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(none, [a, win('rec-b', [makeEffect({ source: 'http-egress', observer: otherObserver, seq: ++seq, operation: 'send', name: 'hooks.example.test', resource: 'POST /', outcome: 'committed', content: { body: 'x' } })])]).verdict, 'pass');
  // A gap in the blind authoritative observer is a gap for the clause.
  assert.equal(evaluateEffectAssertion(none, [a, win('rec-b', [], undefined, 'partial')]).verdict, 'missing');
  // A decided match in the capturing observer still decides.
  const v250 = { status: 'captured', values: { '/amount': { type: 'number', value: 250 } } };
  assert.equal(evaluateEffectAssertion(none, [win(observer.instanceId, [send(v250)], ['/amount']), win('rec-b', [sendB()])]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(exists, [win(observer.instanceId, [send(v250)], ['/amount']), win('rec-b', [sendB()])]).verdict, 'pass');
  // Settlement: a later base send in the blind observer withholds the pass; a later gap in it does too.
  const row = { effects: decideEffects([none], [a, win('rec-b', [])], { role: 'control' }), windows: [a, win('rec-b', [])] };
  assert.equal(row.effects[0].verdict, 'pass');
  assert.deepEqual(settlementFindings([row], [[], [win('rec-b', [sendB()])]]), [['effect-outside-window']]);
  assert.deepEqual(settlementFindings([row], [[], [win('rec-b', [], undefined, 'partial')]]), [['settlement-unobserved']]);
  assert.deepEqual(settlementFindings([row], [[], [win('rec-b', [])]]), [[null]]);
});

test('deny-list covers compound keys and run-together words; secret and identifier shaped values are redacted', () => {
  for (const pointer of ['/customer_ssn', '/ssn_last4', '/customerSSN', '/SSNLast4', '/social_security_number', '/socialInsuranceNumber', '/pan_number', '/panNumber', '/user_pin', '/pinCode', '/pin_code', '/sin_number', '/pwd', '/pass', '/passcode', '/passport_no',
    '/otp', '/otpCode', '/totp', '/mfa_code', '/cc_number', '/ccNum', '/account_no', '/acct_number', '/acctNo', '/routing_number', '/security_code', '/auth', '/authCode', '/oauth', '/cvv2', '/customerssn', '/userpin'])
    assert.throws(() => validatePointer(pointer), /secret-like key/, pointer);
  for (const pointer of ['/sinceDays', '/single_use', '/span_id', '/company', '/shipping', '/opinion', '/author', '/display_name', '/subject', '/order_id', '/reason', '/pages', '/description', '/status'])
    assert.doesNotThrow(() => validatePointer(pointer), pointer);
  for (const value of ['4242424242424242', '4242 4242 4242 4242', '4242-4242-4242-4242', 'card 4111111111111111 on file', '123-45-6789', 'AKIAIOSFODNN7EXAMPLE', 'Basic dXNlcjpwYXNz', 'Token abc123', 4242424242424242, -4242424242424242]) {
    assert.equal(secretShaped(value), true, String(value));
    assert.deepEqual(read({ ticket_id: value }).values['/ticket_id'], { type: 'unusable', reason: 'redacted' }, String(value));
    assert.throws(() => validateCaptured({ status: 'captured', values: { '/ticket_id': { type: typeof value, value } } }), /captured-value/);
  }
  // Adjacent allowed: amounts, short ids, dates and a 13-digit run that fails the Luhn check.
  for (const value of [25, 250, 1234567890123, 'T-000123', '2026-10-10', 'order 1234567890123', '555-0100']) assert.equal(secretShaped(value), false, String(value));
  assert.deepEqual(read({ amount: 25 }).values['/amount'], { type: 'number', value: 25 });
});

// Deny-list spellings, NFKC folding, value separators, the safe-integer bound and path scope.
test('deny-list: password, session, signing, one-time-code, bank and identity spellings are refused; NFKC folds before the check', () => {
  for (const pointer of ['/pw', '/user_pswd', '/sid', '/csrf', '/xsrfValue', '/jwt', '/key', '/signingKey', '/hmac', '/signature', '/securityAnswer', '/2fa_code', '/totp', '/mfaCode', '/otpCode', '/otc', '/bankAccount', '/ccn', '/national_id', '/taxId', '/tin',
    '/dob', '/dateOfBirth', '/recovery_code', '/sortCode', '/seed_phrase',
    '/\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44', // fullwidth "password": NFKC folds it to ASCII, then the deny-list refuses it
    '/p\u0430ssword', '/\u0455\u0455n', '/amount\u200b', '/caf\u00e9']) { // Cyrillic lookalikes, a zero-width space and an accented letter stay non-ASCII
    assert.throws(() => validatePointer(pointer), /secret-like key/, pointer);
    assert.throws(() => validateEgressConfig({ port: 47000, destinations: [{ host: PAY, paths: ['/v1'], capture: { pointers: [pointer] } }] }), /secret-like key/, pointer);
  }
  // Adjacent allowed: ordinary words that merely contain those letters, and fullwidth letters that fold to an allowed key.
  for (const pointer of ['/keyboard_layout', '/monkey', '/sidebar', '/design', '/signup_source', '/doberman', '/tinted', '/total', '/attempt_count', '/photo_type', '/order/items/0/quantity', '/\uff41\uff4d\uff4f\uff55\uff4e\uff54'])
    assert.doesNotThrow(() => validatePointer(pointer), pointer);
});

test('value redaction: card runs and nine-digit identifiers with any one separator, embedded runs, folded and non-ASCII digits', () => {
  for (const value of ['4242.4242.4242.4242', '4242/4242/4242/4242', '4242\u20134242\u20134242\u20134242', '4242_4242_4242_4242', 'order 12 4242 4242 4242 4242', 'card 4242424242424242 exp 12', '\uff14\uff12\uff14\uff12\uff14\uff12\uff14\uff12\uff14\uff12\uff14\uff12\uff14\uff12\uff14\uff12',
    '123-45-6789', '123 45 6789', '123.45.6789', '123/45-6789', '123456789', 'id 123456789 ok', '\uff22\uff45\uff41\uff52\uff45\uff52 abc', 'sk\uff3flive\uff3f51H',  '\u0664\u0662', '12345678901234567890']) {
    assert.equal(secretShaped(value), true, value);
    assert.deepEqual(read({ ticket_id: value }).values['/ticket_id'], { type: 'unusable', reason: 'redacted' }, value);
  }
  // Adjacent allowed: other digit shapes (8 or 10 digits, 2-3-4 groups, dates, versions, money) are kept.
  for (const value of ['12345678', '1234567890', '12-345-6789', '2026-10-10', 'v1.2.3', '$1,234.56', 'ticket 12345', 'T-000123', '4242 4242 4242 4241'])
    assert.equal(secretShaped(value), false, value);
  assert.equal(secretShaped(123456789), false, 'a nine-digit JSON number (an amount in cents) is not redacted');
});

test('safe integers: the bound is Number.MAX_SAFE_INTEGER, not 2^53', () => {
  assert.deepEqual(read({ amount: 9007199254740991 }).values['/amount'], { type: 'number', value: 9007199254740991 });
  assert.deepEqual(read({ amount: 2 ** 53 }).values['/amount'], { type: 'unusable', reason: 'number-unsafe' });
  assert.deepEqual(read('{"amount":9007199254740993}').values['/amount'], { type: 'unusable', reason: 'number-unsafe' }, 'rounds to 2^53 when parsed');
  assert.throws(() => validateFieldPredicates([{ pointer: '/amount', equals: 2 ** 53 }]), /selector-fields/);
  assert.doesNotThrow(() => validateFieldPredicates([{ pointer: '/amount', equals: 2 ** 53 - 1 }]));
  assert.throws(() => validateCaptured({ status: 'captured', values: { '/amount': { type: 'number', value: 2 ** 53 } } }), /captured-value/);
});

test('path scope: a destination that declares capture declares paths; path-undeclared is a valid empty status', () => {
  assert.throws(() => validateEgressConfig({ port: 47000, destinations: [{ host: PAY, capture: { pointers: ['/amount'] } }] }), /declares "paths"/);
  assert.throws(() => validateEgressConfig({ port: 47000, destinations: [{ host: PAY, paths: [], capture: { pointers: ['/amount'] } }] }), /declares "paths"/);
  assert.doesNotThrow(() => validateEgressConfig({ port: 47000, destinations: [{ host: PAY, paths: ['/v1/refunds'], capture: { pointers: ['/amount'] } }] }));
  assert.doesNotThrow(() => validateCaptured({ status: 'path-undeclared', values: {} }));
  assert.throws(() => validateCaptured({ status: 'path-undeclared', values: { '/amount': { type: 'number', value: 1 } } }), /captured-values/);
  const other = send({ status: 'path-undeclared', values: {} }, { resource: 'POST *' });
  assert.equal(matchState(other, select(amount('gt', 100))), 'unknown', 'a send on an undeclared path is unknown, never absent');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: select(amount('gt', 100)) }, [windowOf([other])]).verdict, 'missing');
});
