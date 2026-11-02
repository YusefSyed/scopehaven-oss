// A declared webhook signature or timestamp header leaves head only for a timestamped scheme whose values parse
// inside the run window, and re-signed sends count as one application only when their signed items agree; MACs with no timestamp
// stay bound. Each condition is shown with the re-sign it still allows and the collapse it now refuses. Windows are built directly.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { validateEgressConfig } from '../src/egress-rules.mjs';
import { signedHead, countApplications, keyedReplays, validateIdempotencyDeclaration, validateIdempotencyRecord, IDEMPOTENCY_SIGNATURE_HEADERS, IDEMPOTENCY_UNTIMED_SIGNATURE_HEADERS,
  IDEMPOTENCY_SIGNATURE_SCHEMES, IDEMPOTENCY_SIGNATURE_WINDOW } from '../src/idempotency.mjs';

const T = 1791800000, HOST = 'hooks.example.test', hex = c => c.repeat(64);
const STD = validateIdempotencyDeclaration({ header: 'webhook-id', volatile: ['webhook-signature', 'webhook-timestamp', 'traceparent'] });
const head = (rawHeaders, declaration = STD, at = { startSec: T, nowSec: T }) => signedHead({ declaration, rawHeaders, ...at });
const b64 = (secret, t) => createHmac('sha256', secret).update(`msg_1.${t}.{}`).digest('base64');
const hexMac = (secret, t) => createHmac('sha256', secret).update(`${t}.{}`).digest('hex');
const std = (t, sig = `v1,${b64('a', t)}`) => ['webhook-timestamp', String(t), 'webhook-signature', sig];

test('the fixed signature list splits into timestamped schemes and untimed MACs; every name stays declarable', () => {
  const schemed = Object.values(IDEMPOTENCY_SIGNATURE_SCHEMES).flatMap(s => [s.signature, s.timestamp]).filter(Boolean);
  assert.deepEqual([...schemed, ...IDEMPOTENCY_UNTIMED_SIGNATURE_HEADERS].sort(), [...IDEMPOTENCY_SIGNATURE_HEADERS].sort());
  assert.equal(new Set([...schemed, ...IDEMPOTENCY_UNTIMED_SIGNATURE_HEADERS]).size, IDEMPOTENCY_SIGNATURE_HEADERS.length, 'no name in both');
  for (const name of IDEMPOTENCY_SIGNATURE_HEADERS) assert.doesNotThrow(() => validateIdempotencyDeclaration({ header: 'webhook-id', volatile: [name] }), name);
});

test('a signature or timestamp header can never be the correlation header, which always leaves head', () => {
  for (const correlationHeader of ['x-hub-signature-256', 'x-zm-signature', 'X-Slack-Signature', 'webhook-timestamp']) {
    assert.throws(() => validateIdempotencyDeclaration({ header: 'webhook-id', volatile: ['traceparent'] }, { correlationHeader }), /cannot name a webhook signature or timestamp header/, correlationHeader);
  }
  assert.doesNotThrow(() => validateIdempotencyDeclaration({ header: 'webhook-id', volatile: ['webhook-signature'] }, { correlationHeader: 'x-request-id' }));
  assert.throws(() => validateEgressConfig({ type: 'egress-recorder', port: 47199, routing: 'proxy', destinations: [{ host: HOST, correlation: { header: 'x-zm-signature' }, idempotency: { header: 'webhook-id', volatile: ['x-zm-request-timestamp'] } }] }), /cannot name a webhook signature or timestamp header/, 'refused when the profile loads');
});

test('untimed MACs are declarable but never leave head; tracing names always do; no scheme declared keeps the plain head', () => {
  const d = validateIdempotencyDeclaration({ header: 'x-github-delivery', volatile: [...IDEMPOTENCY_UNTIMED_SIGNATURE_HEADERS, 'traceparent'] });
  assert.deepEqual(head(['x-hub-signature-256', `sha256=${hexMac('a', T)}`], d), { exclude: ['traceparent'], marker: '', signed: null });
});

test('each timestamped scheme parses only its exact form, with each of its headers once', () => {
  const ok = (declaration, rawHeaders) => head(rawHeaders, validateIdempotencyDeclaration({ header: 'k', volatile: declaration })).signed;
  const v0 = `v0=${hexMac('a', T)}`, v1 = `v1,${b64('a', T)}`;
  const parsed = (volatile, rawHeaders, scheme) => { const s = ok(volatile, rawHeaders); assert.ok(s?.[scheme], `${scheme} ${JSON.stringify(rawHeaders)}`); return s[scheme]; };
  const refused = (volatile, rawHeaders, scheme, why) => assert.equal(ok(volatile, rawHeaders)[scheme], null, why);
  assert.deepEqual(parsed(['x-slack-signature'], ['x-slack-request-timestamp', String(T), 'x-slack-signature', v0], 'slack'), { t: T, mac: v0 });
  assert.equal(parsed(['x-zm-signature', 'x-zm-request-timestamp'], ['x-zm-request-timestamp', String(T), 'x-zm-signature', v0], 'zoom').t, T);
  assert.equal(parsed(['svix-signature'], ['svix-timestamp', String(T), 'svix-signature', `${v1} v1,${b64('b', T)}`], 'svix').t, T, 'a rotation: two v1 entries');
  assert.deepEqual(parsed(['stripe-signature'], ['stripe-signature', `t=${T},v1=${hexMac('a', T)},v0=${hexMac('z', T)}`], 'stripe'), { t: T, mac: `v1=${hexMac('a', T)},v0=${hexMac('z', T)}` });
  for (const [sig, why] of [[v0.toUpperCase().replace('V0', 'v0'), 'uppercase hex'], [`v0=${hexMac('a', T).slice(1)}`, '63 hex'], [`${v0}0`, '65 hex'], [`v1=${hexMac('a', T)}`, 'another label'], [hexMac('a', T), 'no label'], [` ${v0}`, 'a leading space']]) {
    refused(['x-slack-signature'], ['x-slack-request-timestamp', String(T), 'x-slack-signature', sig], 'slack', why);
  }
  const short = `v1,${Buffer.alloc(31, 7).toString('base64')}`, loose = `v1,${b64('a', T).slice(0, 42)}B=`;
  for (const [sig, why] of [[short, 'base64 of 31 bytes'], [loose, 'non-canonical padding bits'], [`${v1}  ${v1}`, 'two spaces'], [`${v1} v1a,${b64('b', T)}`, 'an unlisted v1a entry'], [Array(5).fill(v1).join(' '), 'five entries'], [`v1:${b64('a', T)}`, 'another separator']]) {
    refused(['webhook-signature'], ['webhook-timestamp', String(T), 'webhook-signature', sig], 'standard-webhooks', why);
  }
  for (const [sig, why] of [[`t=${T},v0=${hexMac('a', T)}`, 'no v1'], [`t=${T}`, 'no signature'], [`v1=${hexMac('a', T)},t=${T}`, 't not first'], [`t=${T}000,v1=${hexMac('a', T)}`, 'milliseconds'], [`t=${T},v1=${hexMac('a', T)},x=1`, 'an unknown element'], [`t=${T},${Array(5).fill(`v1=${hexMac('a', T)}`).join(',')}`, 'five entries']]) {
    refused(['stripe-signature'], ['stripe-signature', sig], 'stripe', why);
  }
  refused(['webhook-signature'], ['webhook-timestamp', `${T}000`, 'webhook-signature', v1], 'standard-webhooks', 'a timestamp in milliseconds');
  refused(['webhook-signature'], ['webhook-signature', v1], 'standard-webhooks', 'no timestamp header');
  refused(['webhook-signature'], [...std(T), 'webhook-signature', v1], 'standard-webhooks', 'the signature header twice');
  refused(['webhook-signature'], [...std(T), 'webhook-timestamp', String(T)], 'standard-webhooks', 'the timestamp header twice');
});

test('a scheme leaves head only when it parses, and only its declared headers; the marker binds which parsed and how many entries', () => {
  const two = `v1,${b64('a', T)} v1,${b64('b', T)}`;
  assert.deepEqual(head(std(T)), { exclude: ['traceparent', 'webhook-signature', 'webhook-timestamp'], marker: '\nsigned [["standard-webhooks","v1"]]', signed: { 'standard-webhooks': { t: T, mac: `v1,${b64('a', T)}` } } });
  assert.equal(head(std(T, two)).marker, '\nsigned [["standard-webhooks","v1 v1"]]');
  assert.deepEqual(head(std(T, 'v1,sig-1')), { exclude: ['traceparent'], marker: '\nsigned [["standard-webhooks",null]]', signed: { 'standard-webhooks': null } });
  assert.deepEqual(head([]).exclude, ['traceparent'], 'absent headers: nothing to leave out, and the marker says it did not parse');
  const sigOnly = validateIdempotencyDeclaration({ header: 'webhook-id', volatile: ['webhook-signature'] });
  assert.deepEqual(head(std(T), sigOnly).exclude, ['webhook-signature'], 'an undeclared timestamp header stays bound');
});

test('the signing timestamp must lie in the run window: from beforeStart before the recorder started to afterArrival after the send', () => {
  const at = { startSec: T, nowSec: T + 1000 };
  const { beforeStart, afterArrival } = IDEMPOTENCY_SIGNATURE_WINDOW;
  assert.deepEqual([beforeStart, afterArrival], [300, 60]);
  for (const [t, inside] of [[T - beforeStart, true], [T - beforeStart - 1, false], [T + 1000 + afterArrival, true], [T + 1000 + afterArrival + 1, false]]) {
    assert.equal(head(std(t), STD, at).signed['standard-webhooks'] !== null, inside, String(t - T));
  }  for (const at of [{ startSec: null, nowSec: null }, { startSec: T, nowSec: null }, { startSec: null, nowSec: T }, { startSec: T, nowSec: T + 0.5 }]) {
    assert.deepEqual(head(std(T), STD, at), { exclude: ['traceparent'], marker: '\nsigned [["standard-webhooks",null]]', signed: { 'standard-webhooks': null } }, `no signing clock: ${JSON.stringify(at)}`);
  }
});

// Sends under one key whose head left the scheme out; each carries its signed item as the recorder seals it.
const scope = { idempotency: { [HOST]: STD } };
const send = (seq, { t = T, mac = 'a', content = 'c', key = '1', signed } = {}) => ({ seq, name: HOST, operation: 'send', outcome: 'committed', contentDigest: hex(content), correlation: {},
  idempotency: { status: 'keyed', key: hex(key), fold: hex(key), head: hex('e'), firstSeq: key === '1' ? 1 : seq, signed: signed !== undefined ? signed : { 'standard-webhooks': { t, mac: hex(mac) } } } });
const counted = (events, w = { events, scope }) => {
  const group = events.filter(e => e.idempotency.key === hex('1'));
  const a = countApplications(w, HOST, group), r = keyedReplays(w, HOST);
  // keyedReplays collapses exactly what countApplications decides as one application.
  assert.equal(a.low === 1 && a.high === 1, group.length === 1 || group.slice(1).every(e => r.replay.has(e)), JSON.stringify([a, [...r.replay].map(e => e.seq)]));
  return [a.low, a.high];
};

test('re-signed: a new timestamp with a new MAC is one application; the same second under a second secret stays two', () => {
  assert.deepEqual(counted([send(1), send(2, { t: T + 1, mac: 'b' }), send(3, { t: T + 7, mac: 'c' })]), [1, 1]);
  assert.deepEqual(counted([send(1), send(2)]), [1, 1], 'an exact replay');
  assert.deepEqual(counted([send(1), send(2, { mac: 'b' })]), [1, 2], 'one timestamp, two MACs: a second secret or a nonce');
  assert.deepEqual(counted([send(1), send(2, { t: T + 1, mac: 'b' }), send(3, { t: T + 1, mac: 'c' })]), [1, 3], 'a later pair in one second');
});

test('order: timestamps never go back across a group', () => {
  assert.deepEqual(counted([send(1, { t: T + 5 }), send(2, { t: T + 5 }), send(3, { t: T + 6, mac: 'b' })]), [1, 1]);
  assert.deepEqual(counted([send(1, { t: T + 5 }), send(2, { t: T, mac: 'b' })]), [1, 2]);
});

test('parse: a member whose scheme did not parse keeps the whole group apart', () => {
  assert.deepEqual(counted([send(1, { signed: { 'standard-webhooks': null } }), send(2, { signed: { 'standard-webhooks': null } })]), [1, 1], 'neither parsed: compared by head alone');
  assert.deepEqual(counted([send(1), send(2, { t: T + 1, mac: 'b', signed: { 'standard-webhooks': null } })]), [1, 2]);
});

test('window disproval: one MAC with another timestamp or body anywhere on the host means the header is not a MAC over them', () => {
  const group = [send(1), send(2, { t: T + 1, mac: 'b' })];
  assert.deepEqual(counted([...group, send(3, { key: '2', t: T + 9, mac: 'z' })]), [1, 1], 'another send with its own MAC');
  assert.deepEqual(counted([...group, send(3, { key: '2', t: T + 9, mac: 'a' })]), [1, 2], 'the same MAC, another timestamp');
  assert.deepEqual(counted([...group, send(3, { key: '2', content: 'd' })]), [1, 2], 'the same MAC and timestamp, another body');
  assert.deepEqual(counted([send(1), send(2, { t: T + 1 })]), [1, 2], 'within the group too');
});

test('records must carry exactly the declared schemes, read through the window\'s own declaration', () => {
  const group = [send(1), send(2, { t: T + 1, mac: 'b' })];
  assert.deepEqual(counted(group, { events: group, scope: {} }), [1, 2], 'no declaration for the host');
  const bare = [send(1, { signed: null }), send(2, { signed: null })];
  for (const e of bare) delete e.idempotency.signed;
  assert.deepEqual(counted(bare), [1, 2], 'records without signed on a declaring host never collapse, not even exact copies');
  assert.deepEqual(counted(bare, { events: bare, scope: { idempotency: { [HOST]: validateIdempotencyDeclaration({ header: 'webhook-id' }) } } }), [1, 1], 'a host that declares no scheme: unchanged');
  const stray = [send(1, { signed: { svix: { t: T, mac: hex('a') } } }), send(2, { signed: { svix: { t: T, mac: hex('a') } } })];
  assert.deepEqual(counted(stray), [1, 2], 'another scheme than declared');
});

test('everything else stays bound: content, key and head', () => {
  assert.deepEqual(counted([send(1), send(2, { t: T + 1, mac: 'b', content: 'd' })]), [1, 2]);
  const other = send(2, { t: T + 1, mac: 'b' });
  other.idempotency.head = hex('f');
  assert.deepEqual(counted([send(1), other]), [1, 2]);
});

test('a stored signed item: per declared scheme, null or { t, mac } with a 10-digit time and a 64-hex digest', () => {
  const rec = signed => ({ status: 'keyed', key: hex('1'), fold: hex('1'), head: hex('a'), firstSeq: 1, signed });
  assert.doesNotThrow(() => validateIdempotencyRecord(rec({ 'standard-webhooks': { t: T, mac: hex('b') }, stripe: null }), 1));
  for (const signed of [null, {}, [], { other: null }, { stripe: { t: T, mac: hex('b'), extra: 1 } }, { stripe: { t: String(T), mac: hex('b') } }, { stripe: { t: 179180000, mac: hex('b') } },
    { stripe: { t: T, mac: 'v1=abc' } }, { stripe: { t: T + 0.5, mac: hex('b') } }]) assert.throws(() => validateIdempotencyRecord(rec(signed), 1), /idempotency-record/, JSON.stringify(signed));
  assert.doesNotThrow(() => validateIdempotencyRecord({ status: 'absent', key: null, fold: null, head: hex('a'), firstSeq: null, signed: { stripe: null } }, 1), 'an unkeyed send carries it too');
});
