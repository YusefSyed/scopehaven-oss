// Re-signed redeliveries (declared signature and timestamp headers) and event ids read from a declared body pointer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateIdempotencyDeclaration, validIdempotencyMap, idempotencyRecordOf, readBodyKey, IDEMPOTENCY_SIGNATURE_HEADERS, IDEMPOTENCY_VOLATILE_HEADERS } from '../src/idempotency.mjs';

const json = (value, extra = []) => { const buffer = Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)); return { rawHeaders: ['Content-Type', 'application/json', ...extra], buffer, bodyBytes: buffer.length }; };
const decl = validateIdempotencyDeclaration({ pointer: '/event_id' });
const read = (body, method = 'POST', d = decl) => readBodyKey({ declaration: d, method, ...body }).status;

test('signature and timestamp headers are declarable as volatile, never as the key; other names stay refused', () => {
  const d = validateIdempotencyDeclaration({ header: 'webhook-id', volatile: ['webhook-timestamp', 'webhook-signature', 'traceparent'] });
  assert.deepEqual(d.volatile, ['traceparent', 'webhook-signature', 'webhook-timestamp']);
  for (const header of IDEMPOTENCY_SIGNATURE_HEADERS) assert.throws(() => validateIdempotencyDeclaration({ header }), /idempotency\.header/, header);
  for (const volatile of [['stripe-account'], ['x-tenant-id'], ['authorization'], ['webhook-id'], ['user-agent']]) assert.throws(() => validateIdempotencyDeclaration({ header: 'webhook-id', volatile }), /volatile/, volatile[0]);
  assert.equal(new Set([...IDEMPOTENCY_SIGNATURE_HEADERS, ...IDEMPOTENCY_VOLATILE_HEADERS]).size, IDEMPOTENCY_SIGNATURE_HEADERS.length + IDEMPOTENCY_VOLATILE_HEADERS.length, 'the two fixed lists do not overlap');
  for (const name of IDEMPOTENCY_SIGNATURE_HEADERS) assert.match(name, /signature|timestamp|hmac/, 'every signature-list name is a signature, MAC or timestamp header');
});

test('body pointer declaration: one source, bounded body, normalized and published', () => {
  assert.deepEqual(decl, { header: null, pointer: '/event_id', methods: ['POST'], volatile: [], maxBytes: 16384 });
  assert.equal(validateIdempotencyDeclaration({ pointer: '/id' }, { maxBodyBytes: 4096 }).maxBytes, 4096);
  assert.deepEqual(validateIdempotencyDeclaration({ pointer: '/data/0/id', maxBytes: 65536, methods: ['PUT', 'POST'] }), { header: null, pointer: '/data/0/id', methods: ['POST', 'PUT'], volatile: [], maxBytes: 65536 });
  for (const bad of [{ pointer: 'id' }, { pointer: '' }, { pointer: '/__proto__' }, { pointer: '/a/b/c/d/e/f/g/h/i' }, { pointer: '/id', maxBytes: 512 }, { pointer: '/id', maxBytes: 70000 }]) assert.throws(() => validateIdempotencyDeclaration(bad), /idempotency/, JSON.stringify(bad));
  assert.throws(() => validateIdempotencyDeclaration({ pointer: '/id', maxBytes: 8192 }, { maxBodyBytes: 4096 }), /maxBytes/);
  // The capture deny-list does not apply: only a salted digest is stored.
  assert.doesNotThrow(() => validateIdempotencyDeclaration({ pointer: '/idempotency_key' }));
  assert.equal(validIdempotencyMap({ 'hooks.example.test': decl }), true);
  assert.equal(validIdempotencyMap({ 'hooks.example.test': { ...decl, maxBytes: 999 } }), false);
  assert.deepEqual(idempotencyRecordOf({ type: 'egress-recorder', maxBodyBytes: 2048, destinations: [{ host: 'hooks.example.test', idempotency: { pointer: '/event_id' } }] }), { 'hooks.example.test': { ...decl, maxBytes: 2048 } });
});

test('body key reading: a definite id, a definite absence, or a dirty status; never a guess', () => {
  assert.deepEqual(readBodyKey({ declaration: decl, method: 'POST', ...json({ event_id: 'evt_1', type: 'order.paid' }) }), { status: 'keyed', value: 'evt_1' });
  assert.equal(read(json({ type: 'order.paid' })), 'absent');
  assert.equal(read({ rawHeaders: [], buffer: Buffer.alloc(0), bodyBytes: 0 }), 'absent', 'no body: a definite absence');
  assert.equal(read(json([{ id: 'x' }]), 'POST', validateIdempotencyDeclaration({ pointer: '/0/id' })), 'keyed');
  assert.equal(read(json([{ id: 'x' }]), 'POST', validateIdempotencyDeclaration({ pointer: '/01/id' })), 'absent');
  for (const [body, why] of [[{ rawHeaders: ['Content-Type', 'application/x-www-form-urlencoded'], buffer: Buffer.from('event_id=e1'), bodyBytes: 11 }, 'form'], [json('{"event_id":"a","event_id":"b"}'), 'duplicate key'],
    [json('{"event_id":'), 'invalid'], [json({ event_id: 'e' }, ['Content-Encoding', 'gzip']), 'compressed'], [json({ event_id: 'e', pad: 'x'.repeat(17000) }), 'over maxBytes'], [{ ...json({ event_id: 'e' }), rawHeaders: [] }, 'no Content-Type']]) assert.equal(read(body), 'unreadable', why);
  for (const value of [1, true, null, { a: 1 }, '', 'has space', 'é']) assert.equal(read(json({ event_id: value })), 'malformed', JSON.stringify(value));
  assert.equal(read(json({ event_id: 'e'.repeat(256) })), 'over-cap');
  assert.equal(read(json({ event_id: 'e'.repeat(255) })), 'keyed');
  assert.equal(read(json({ event_id: 'e1' }), 'GET'), 'not-applicable');
  assert.equal(read(json({ event_id: 'e1' }), 'PUT'), 'method-undeclared', 'an id on a method the declaration does not key');
  assert.equal(read(json({ other: 1 }), 'PUT'), 'not-applicable');
  assert.equal(read({ rawHeaders: ['Content-Type', 'text/plain'], buffer: Buffer.from('x'), bodyBytes: 1 }, 'PUT'), 'unreadable');
});

test('review hardening: case-variant keys, a BOM and a null key source never give a decided id', () => {
  for (const body of ['{"Event_ID":"K","n":1}', '{"event_id":"A","EVENT_ID":"K"}', '{"event_id":"A","\uFF45vent_id":"K"}']) assert.equal(read(json(body)), 'unreadable', body);
  assert.equal(read(json('{"data":{"Id":"x"}}'), 'POST', validateIdempotencyDeclaration({ pointer: '/data/id' })), 'unreadable', 'a case variant at an inner token');
  assert.equal(read(json('{"other":"x"}')), 'absent', 'no variant: a definite absence');
  const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"event_id":"a"}')]);
  assert.equal(read({ rawHeaders: ['Content-Type', 'application/json'], buffer: bom, bodyBytes: bom.length }), 'unreadable');
  for (const d of [{ header: null }, { pointer: null }, { header: 5 }, { pointer: {} }]) assert.throws(() => validateIdempotencyDeclaration(d), /as a string/, JSON.stringify(d));
});
