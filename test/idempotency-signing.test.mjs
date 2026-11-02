// Verified signature headers, unit level: the declaration and its published form, the
// scheme menu's exact forms, key derivation, verification under exactly one declared secret, the head marker, the stored item, the
// clash rules and the identity gate. Each property is shown with the re-sign it collapses and the adjacent case it must keep apart.
// Every secret here is synthetic and built at run time; the reference HMAC below is written from RFC 2104, not node:crypto's HMAC.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { validateIdempotencyDeclaration, publishIdempotency, validIdempotencyMap, idempotencyRecordOf, signingKeyOf, effectiveHmacKey, createSigningCheck, signingHead,
  validateIdempotencyRecord, countApplications, keyedReplays, signingSecretClash, signingSecretValueClash, signingRunOf, validSigningRun, consistentSigningRun,
  IDEMPOTENCY_SIGNING_SCHEMES, IDEMPOTENCY_SIGNATURE_SCHEMES, IDEMPOTENCY_SIGNATURE_WINDOW, SIGNING_BOUNDS } from '../src/idempotency.mjs';
import { timestampedSignatureNames } from '../src/http-scope-text.mjs';

const T = 1791800000, HOST = 'hooks.example.test', hex = c => c.repeat(64);
const sha = data => createHash('sha256').update(data).digest();
// RFC 2104 HMAC-SHA256 from SHA-256 alone: the reference every MAC below is built with.
const refHmac = (key, message) => {
  const k = Buffer.alloc(64); (key.length > 64 ? sha(key) : key).copy(k);
  const pad = byte => Buffer.from(k.map(b => b ^ byte));
  return sha(Buffer.concat([pad(0x5c), sha(Buffer.concat([pad(0x36), Buffer.from(message)]))]));
};
// Synthetic secrets, built from parts at run time so no literal looks like a credential.
const secret = n => ['synthetic', 'signing', 'secret', String(n), 'abcdefgh'].join('-');
const standardSecret = n => ['wh', 'sec_', Buffer.alloc(32, n).toString('base64')].join('');
const BODY = '{"id":"evt_1","type":"ticket.updated"}';
const stripeSig = (key, t, body = BODY) => `t=${t},v1=${refHmac(key, `${t}.${body}`).toString('hex')}`;
const v1 = (key, id, t, body = BODY) => `v1,${refHmac(key, `${id}.${t}.${body}`).toString('base64')}`;
const v0 = (key, t, body = BODY) => `v0=${refHmac(key, `v0:${t}:${body}`).toString('hex')}`;
const ENV = n => `SCOPEHAVEN_TARGET_HOOK_SECRET_${n}`;
const STRIPE = { scheme: 'stripe', signature: 'x-hooks-signature', secretEnv: [ENV(1), ENV(2)] };
const STANDARD = { scheme: 'standard-webhooks', id: 'webhook-id', timestamp: 'webhook-timestamp', signature: 'webhook-signature', secretEnv: [ENV(1)] };
const SLACK = { scheme: 'slack-v0', timestamp: 'x-slack-request-timestamp', signature: 'x-slack-signature', secretEnv: [ENV(1)] };
const decl = (signing, extra = {}) => validateIdempotencyDeclaration({ header: 'x-event-id', ...extra, signing });
const slotsOf = (...keys) => keys.map(key => (key === null ? { key: Buffer.alloc(32, 9), usable: false } : { key, usable: true }));
const key = (scheme, value) => signingKeyOf(scheme, value);
// Verify one send: the headers, the body (in chunks), the slots and the clock; returns finish()'s result.
function verify(signing, rawHeaders, { body = BODY, slots, startSec = T, nowSec = T, trailers = [], chunks = 1 } = {}) {
  const check = createSigningCheck({ signing, rawHeaders, slots, startSec, nowSec });
  const bytes = Buffer.from(body), step = Math.ceil(bytes.length / chunks) || 1;
  for (let i = 0; i < bytes.length; i += step) check.update(bytes.subarray(i, i + step));
  return check.finish(trailers);
}

test('declaration: each scheme normalizes; the published form names how many secrets, never their variables; undeclared stays as it was', () => {
  const d = decl(STRIPE);
  assert.deepEqual(d.signing, { scheme: 'stripe', signature: 'x-hooks-signature', timestamp: null, id: null, dedupeSeconds: 300, secretEnv: [ENV(1), ENV(2)] });
  const published = publishIdempotency(d);
  assert.deepEqual(published.signing, { scheme: 'stripe', signature: 'x-hooks-signature', timestamp: null, id: null, dedupeSeconds: 300, secrets: 2 });
  assert.ok(!JSON.stringify(published).includes('SCOPEHAVEN_TARGET_'), 'no variable name is published');
  assert.equal(validIdempotencyMap({ [HOST]: published }), true);
  assert.equal(validIdempotencyMap({ [HOST]: d }), false, 'the internal form (with names) is not a published one');
  for (const s of [{ ...STANDARD, dedupeSeconds: 86400 }, SLACK]) assert.equal(validIdempotencyMap({ [HOST]: publishIdempotency(decl(s, s.scheme === 'standard-webhooks' ? { header: 'webhook-id' } : {})) }), true, s.scheme);
  for (const forge of [p => { p.signing.secrets = 5; }, p => { p.signing.secrets = 0; }, p => { p.signing.dedupeSeconds = 0; }, p => { p.signing.scheme = 'github'; }, p => { delete p.signing.secrets; }, p => { p.signing.timestamp = 'x-ts'; }]) {
    const p = structuredClone(published); forge(p);
    assert.equal(validIdempotencyMap({ [HOST]: p }), false, forge.toString());
  }
  const plainDecl = validateIdempotencyDeclaration({ header: 'x-event-id', volatile: ['traceparent'] });
  assert.equal(publishIdempotency(plainDecl), plainDecl, 'without signing the published form is the declaration itself');
  assert.deepEqual(Object.keys(plainDecl), ['header', 'pointer', 'methods', 'volatile', 'maxBytes'], 'byte-identical keys for undeclared profiles');
  assert.deepEqual(idempotencyRecordOf({ type: 'egress-recorder', destinations: [{ host: HOST, idempotency: { header: 'x-event-id', signing: STRIPE } }] })[HOST], published);
});

test('declaration refusals: scheme shape, names, the timestamped volatile route beside it, dedupeSeconds and secretEnv', () => {
  const refused = (signing, extra = {}, options = {}) => assert.throws(() => validateIdempotencyDeclaration({ header: 'x-event-id', ...extra, signing }, options), /signing|volatile|signature route/, JSON.stringify([signing, extra]));
  refused({ ...STRIPE, scheme: 'github' });
  refused({ ...STRIPE, scheme: 'toString' });
  refused({ ...STRIPE, timestamp: 'x-ts' }, {}, {}, 'stripe takes no timestamp');
  refused({ ...STANDARD, id: undefined }); refused((({ id, ...rest }) => rest)(STANDARD));
  refused((({ timestamp, ...rest }) => rest)(SLACK));
  refused({ ...SLACK, id: 'x-id' });
  refused({ ...STRIPE, extra: 1 });
  for (const name of ['Authorization', 'authorization', 'traceparent', 'x-hub-signature-256', 'x-scopehaven-sig', 'x-event-id', 'host', 'cookie']) refused({ ...STRIPE, signature: name });
  refused({ ...SLACK, timestamp: 'x-slack-signature' }, {}, {}, 'one name twice');
  refused({ ...STANDARD, id: 'traceparent' });
  refused({ ...STRIPE, signature: 'x-corr' }, {}, { correlationHeader: 'x-corr' });
  refused({ ...STANDARD, id: 'x-corr' }, { header: 'webhook-id' }, { correlationHeader: 'X-Corr' });
  refused(STRIPE, { volatile: ['x-hooks-signature'] }, {}, 'never in both');
  refused(STRIPE, { volatile: ['webhook-signature'] }, {}, 'a timestamped volatile scheme beside signing');
  assert.doesNotThrow(() => validateIdempotencyDeclaration({ header: 'x-event-id', volatile: ['traceparent', 'x-hub-signature'], signing: STRIPE }), 'tracing and untimed names stay allowed');
  assert.doesNotThrow(() => validateIdempotencyDeclaration({ header: 'webhook-id', signing: { ...STANDARD, signature: 'webhook-signature' } }), 'a fixed-list name may move to signing');
  for (const dedupeSeconds of [0, 86401, 1.5, '300', null]) refused({ ...STRIPE, dedupeSeconds });
  for (const secretEnv of [[], [ENV(1), ENV(1)], ['HOOK_SECRET'], ['SCOPEHAVEN_TARGET_'], [ENV(1), ENV(2), ENV(3), ENV(4), ENV(5)], 'SCOPEHAVEN_TARGET_X', [7]]) refused({ ...STRIPE, secretEnv });
  assert.equal(decl({ ...STANDARD, dedupeSeconds: 1 }, { header: 'webhook-id' }).signing.dedupeSeconds, 1);
});

test('key derivation: UTF-8 for stripe and slack-v0; optional whsec_ and canonical base64 for standard-webhooks; byte bounds', () => {
  assert.deepEqual(key('stripe', secret(1)), Buffer.from(secret(1)));
  assert.deepEqual(key('stripe', `wh${'sec_'}${secret(1)}`), Buffer.from(`wh${'sec_'}${secret(1)}`), 'stripe keys on the whole string');
  assert.deepEqual(key('standard-webhooks', standardSecret(1)), Buffer.alloc(32, 1));
  assert.deepEqual(key('standard-webhooks', Buffer.alloc(32, 1).toString('base64')), Buffer.alloc(32, 1), 'the prefix is optional');
  for (const value of [undefined, '', 'short-secret', 'x'.repeat(257)]) assert.equal(key('stripe', value), null, String(value));
  for (const value of ['not base64!', `wh${'sec_'}${Buffer.alloc(15, 1).toString('base64')}`, `wh${'sec_'}${Buffer.alloc(65, 1).toString('base64')}`, `wh${'sec_'}${Buffer.alloc(32, 1).toString('base64').replace(/=$/, '')}`,
    `wh${'sec_'}${Buffer.alloc(32, 0xfb).toString('base64url')}=`]) assert.equal(key('standard-webhooks', value), null, value);
});

test('HMAC-effective keys: K and K plus a zero byte, and a long key and its SHA-256, are one key', () => {
  const k = Buffer.from(secret(1)), long = Buffer.alloc(80, 7);
  assert.deepEqual(refHmac(k, 'm'), refHmac(Buffer.concat([k, Buffer.alloc(1)]), 'm'));
  assert.deepEqual(effectiveHmacKey(k), effectiveHmacKey(Buffer.concat([k, Buffer.alloc(1)])));
  assert.deepEqual(refHmac(long, 'm'), refHmac(sha(long), 'm'));
  assert.deepEqual(effectiveHmacKey(long), effectiveHmacKey(sha(long)));
  assert.notDeepEqual(effectiveHmacKey(k), effectiveHmacKey(Buffer.from(secret(2))));
});

test('stripe: verified only for its exact form, under exactly one usable slot, over the raw body bytes', () => {
  const s = decl(STRIPE).signing, k1 = key('stripe', secret(1)), k2 = key('stripe', secret(2));
  const ok = (value, options = {}) => verify(s, ['X-Hooks-Signature', value], { slots: slotsOf(k1, k2), ...options });
  assert.deepEqual(ok(stripeSig(k1, T)), { verified: true, t: T, at: T, slot: 0, count: 1 });
  assert.deepEqual(ok(stripeSig(Buffer.from(secret(3)), T)), { verified: false, t: null, at: T, slot: null, count: null }, 'every send carries its arrival second');
  assert.deepEqual(ok(stripeSig(k2, T)), { verified: true, t: T, at: T, slot: 1, count: 1 }, 'the second declared secret is its own slot');
  assert.equal(ok(stripeSig(k1, T), { chunks: 7 }).verified, true, 'chunk boundaries do not matter');
  const mac = refHmac(k1, `${T}.${BODY}`).toString('hex');
  assert.equal(ok(`t=${T},v1=${mac},v1=${mac}`).count, 2, 'two identical entries under one slot');
  for (const [value, why] of [[stripeSig(Buffer.from(secret(3)), T), 'an undeclared secret'], [`t=${T},v1=${mac},v1=${refHmac(k2, `${T}.${BODY}`).toString('hex')}`, 'entries under two slots (a rotation)'],
    [`t=${T},v1=${mac},v0=${mac}`, 'a v0 element'], [`t=${T},v1=${mac.toUpperCase()}`, 'uppercase hex'], [`t=${T},v1=${mac.slice(1)}`, '63 hex'], [`t=${T}000,v1=${mac}`, 'milliseconds'],
    [`v1=${mac},t=${T}`, 't not first'], [`t=${T}, v1=${mac}`, 'a space'], [`t=${T},v1=${mac},x=1`, 'an unknown element'], [`t=${T},${Array(5).fill(`v1=${mac}`).join(',')}`, 'five entries'],
    [stripeSig(k1, T, `${BODY} `), 'a MAC over another body']]) assert.equal(ok(value).verified, false, why);
  assert.equal(ok(stripeSig(k1, T), { body: JSON.stringify(JSON.parse(BODY), null, 1) }).verified, false, 'a re-serialized body is another body: the raw bytes decide');
  assert.equal(verify(s, [], { slots: slotsOf(k1) }).verified, null, 'no signature header: absent');
  assert.equal(verify(s, ['x-hooks-signature', stripeSig(k1, T), 'x-hooks-signature', stripeSig(k1, T)], { slots: slotsOf(k1) }).verified, false, 'the header twice');
});

test('exactly one slot: two slots that both match (an HMAC-equivalent pair) read unverified; an unusable slot never matches', () => {
  const s = decl(STRIPE).signing, k = key('stripe', secret(1));
  const header = ['x-hooks-signature', stripeSig(k, T)];
  assert.equal(verify(s, header, { slots: slotsOf(k, Buffer.concat([k, Buffer.alloc(1)])) }).verified, false, 'K and K plus 0x00');
  assert.equal(verify(s, header, { slots: [{ key: k, usable: false }, { key: Buffer.from(secret(2)), usable: true }] }).verified, false, 'the matching slot is unusable');
  assert.equal(verify(s, header, { slots: slotsOf(null, k) }).slot, 1);
  assert.equal(verify(s, header, { slots: null }).verified, false, 'a stopped recorder verifies nothing');
  assert.equal(verify(s, header, { slots: slotsOf(null, null) }).verified, false, 'no usable slot');
});

test('the compare is constant-time with no early exit: timingSafeEqual over every slot and entry, decided after the loop', async () => {
  const { readFile } = await import('node:fs/promises');
  const src = await readFile(new URL('../src/idempotency.mjs', import.meta.url), 'utf8');
  const finish = /finish\(rawTrailers = \[\]\) \{([\s\S]*?)\n {4}\},\n {2}\};/.exec(src)?.[1] ?? '';
  assert.match(finish, /all &= timingSafeEqual\(entry, digests\[s\]\) \? 1 : 0;/);
  const loop = finish.slice(finish.indexOf('for (let s'), finish.lastIndexOf('return'));
  assert.doesNotMatch(loop, /\b(break|return|continue)\b|\.equals\(|===\s*digests/, 'nothing leaves the loop early or compares bytes another way');
});

test('a mismatch in the last entry is caught even when the first matches (every entry is compared, no early exit)', () => {
  const s = decl(STRIPE).signing, k = key('stripe', secret(1)), mac = refHmac(k, `${T}.${BODY}`).toString('hex');
  assert.equal(verify(s, ['x-hooks-signature', `t=${T},v1=${mac},v1=${hex('0')}`], { slots: slotsOf(k) }).verified, false);
  assert.equal(verify(s, ['x-hooks-signature', `t=${T},v1=${hex('0')},v1=${mac}`], { slots: slotsOf(k) }).verified, false);
});

test('standard-webhooks: id, timestamp and body are all in the message; up to four v1 entries under one slot', () => {
  const s = decl(STANDARD, { header: 'webhook-id' }).signing, k = key('standard-webhooks', standardSecret(1));
  const headers = (id, t, sig) => ['webhook-id', id, 'webhook-timestamp', String(t), 'webhook-signature', sig];
  assert.deepEqual(verify(s, headers('msg_1', T, v1(k, 'msg_1', T)), { slots: slotsOf(k) }), { verified: true, t: T, at: T, slot: 0, count: 1 });
  assert.equal(verify(s, headers('msg_1', T, `${v1(k, 'msg_1', T)} ${v1(k, 'msg_1', T)}`), { slots: slotsOf(k) }).count, 2);
  const noId = `v1,${refHmac(k, `${T}.${BODY}`).toString('base64')}`;
  for (const [h, why] of [[headers('msg_2', T, v1(k, 'msg_1', T)), 'signed for another id'], [headers('msg_1', T, noId), 'a MAC without the id'], [headers('msg_1', T + 1, v1(k, 'msg_1', T)), 'another timestamp'],
    [headers('msg_1', T, `${v1(k, 'msg_1', T)} v1a,${Buffer.alloc(64).toString('base64')}`), 'a v1a entry'], [['webhook-timestamp', String(T), 'webhook-signature', v1(k, 'msg_1', T)], 'no id header'],
    [[...headers('msg_1', T, v1(k, 'msg_1', T)), 'webhook-id', 'msg_1'], 'the id twice'], [[...headers('msg_1', T, v1(k, 'msg_1', T)), 'webhook-timestamp', String(T)], 'the timestamp twice'],
    [headers('msg 1', T, v1(k, 'msg 1', T)), 'an id with a space']]) assert.equal(verify(s, h, { slots: slotsOf(k) }).verified, false, why);
});

test('slack-v0: v0= and 64 hex over "v0:t:body"', () => {
  const s = decl(SLACK).signing, k = key('slack-v0', secret(1));
  const headers = (t, sig) => ['x-slack-request-timestamp', String(t), 'x-slack-signature', sig];
  assert.equal(verify(s, headers(T, v0(k, T)), { slots: slotsOf(k) }).verified, true);
  assert.equal(verify(s, headers(T, v0(k, T).replace('v0=', 'v1=')), { slots: slotsOf(k) }).verified, false);
  assert.equal(verify(s, ['x-slack-signature', v0(k, T)], { slots: slotsOf(k) }).verified, false, 'no timestamp header');
  assert.equal(verify(s, headers(T, `v0=${refHmac(k, `${T}.${BODY}`).toString('hex')}`), { slots: slotsOf(k) }).verified, false, 'another scheme\'s message');
});

test('the run window and the signing clock: edges included, one second past either edge refused, no clock refused', () => {
  const s = decl(STRIPE).signing, k = key('stripe', secret(1)), at = { startSec: T, nowSec: T + 1000 };
  const { beforeStart, afterArrival } = IDEMPOTENCY_SIGNATURE_WINDOW;
  for (const [t, inside] of [[T - beforeStart, true], [T - beforeStart - 1, false], [T + 1000 + afterArrival, true], [T + 1000 + afterArrival + 1, false]]) {
    assert.equal(verify(s, ['x-hooks-signature', stripeSig(k, t)], { slots: slotsOf(k), ...at }).verified === true, inside, String(t - T));
  }
  for (const clock of [{ startSec: null, nowSec: null }, { startSec: T, nowSec: null }, { startSec: T, nowSec: T + 0.5 }]) assert.equal(verify(s, ['x-hooks-signature', stripeSig(k, T)], { slots: slotsOf(k), ...clock }).verified, false, JSON.stringify(clock));
});

test('trailers: any trailer makes the send unverified, and the marker binds them', () => {
  const s = decl(STRIPE).signing, k = key('stripe', secret(1));
  assert.equal(verify(s, ['x-hooks-signature', stripeSig(k, T)], { slots: slotsOf(k), trailers: ['x-account', 'b'] }).verified, false);
  assert.match(signingHead(s, { verified: false }, ['x-account', 'b']).marker, /x-account/);
});

test('head marker: verified leaves out signature and timestamp (never the id) and names slot and count; unverified and absent keep every header', () => {
  const st = decl(STANDARD, { header: 'webhook-id' }).signing;
  assert.deepEqual(signingHead(st, { verified: true, slot: 1, count: 2 }), { exclude: ['webhook-signature', 'webhook-timestamp'], marker: '\nsigning ["standard-webhooks","verified",1,2,[]]' });
  assert.deepEqual(signingHead(st, { verified: false }), { exclude: [], marker: '\nsigning ["standard-webhooks","unverified",null,null,[]]' });
  assert.deepEqual(signingHead(st, { verified: null }), { exclude: [], marker: '\nsigning ["standard-webhooks","absent",null,null,[]]' });
  assert.deepEqual(signingHead(decl(STRIPE).signing, { verified: true, slot: 0, count: 1 }).exclude, ['x-hooks-signature']);
});

test('the stored item: { scheme, verified, t, at }, with t and at only when verified', () => {
  const rec = signing => ({ status: 'keyed', key: hex('1'), fold: hex('1'), head: hex('a'), firstSeq: 1, signing });
  for (const signing of [{ scheme: 'stripe', verified: true, t: T, at: T }, { scheme: 'stripe', verified: true, t: T + 60, at: T }, { scheme: 'slack-v0', verified: false, t: null, at: null }, { scheme: 'standard-webhooks', verified: null, t: null, at: null },
    { scheme: 'stripe', verified: false, t: null, at: T }, { scheme: 'stripe', verified: null, t: null, at: T }]) {
    assert.doesNotThrow(() => validateIdempotencyRecord(rec(signing), 1), JSON.stringify(signing));
  }
  for (const signing of [null, {}, { scheme: 'github', verified: true, t: T, at: T }, { scheme: 'stripe', verified: true, t: T + 61, at: T }, { scheme: 'stripe', verified: true, t: null, at: T },
    { scheme: 'stripe', verified: false, t: T, at: null }, { scheme: 'stripe', verified: 'yes', t: null, at: null }, { scheme: 'stripe', verified: true, t: T, at: T, slot: 0 }, { scheme: 'stripe', verified: false, t: null, at: 17918 }]) {
    assert.throws(() => validateIdempotencyRecord(rec(signing), 1), /idempotency-record/, JSON.stringify(signing));
  }
  assert.throws(() => validateIdempotencyRecord({ ...rec({ scheme: 'stripe', verified: null, t: null, at: null }), signed: { stripe: null } }, 1), /idempotency-record/, 'never both');
});

// Gate: sends under one key on a host whose published declaration has signing. head stands for the sealed head (same slot and
// count when equal); each carries the signing item the recorder would write.
const SIGNING = publishIdempotency(decl({ ...STRIPE, dedupeSeconds: 300 }));
const scope = { idempotency: { [HOST]: SIGNING } };
const item = (verified, t = T, at = t) => ({ scheme: 'stripe', verified, t: verified === true ? t : null, at });
const send = (seq, { signing = item(true), head = 'e', content = 'c', key = '1' } = {}) => ({ seq, name: HOST, operation: 'send', outcome: 'committed', contentDigest: hex(content), correlation: {},
  idempotency: { status: 'keyed', key: hex(key), fold: hex(key), head: hex(head), firstSeq: key === '1' ? 1 : seq, ...(signing === 'none' ? {} : { signing }) } });
const counted = (events, w = { events, scope }) => {
  const group = events.filter(e => e.idempotency.key === hex('1'));
  const a = countApplications(w, HOST, group), r = keyedReplays(w, HOST);
  assert.equal(a.low === 1 && a.high === 1, group.length === 1 || group.slice(1).every(e => r.replay.has(e)), `keyedReplays agrees: ${JSON.stringify([a, [...r.replay].map(e => e.seq)])}`);
  return [a.low, a.high];
};

test('gate: verified re-signs under one slot collapse; a second slot, an undeclared secret or an unverified member stays apart', () => {
  assert.deepEqual(counted([send(1), send(2, { signing: item(true, T + 30) }), send(3, { signing: item(true, T + 90) })]), [1, 1]);
  assert.deepEqual(counted([send(1), send(2, { head: 'slot-1', signing: item(true, T + 30) })]), [1, 2], 'another slot is another head');
  assert.deepEqual(counted([send(1), send(2, { head: 'raw', signing: item(false) })]), [1, 2], 'an undeclared secret leaves the raw header bound');
  assert.deepEqual(counted([send(1), send(2, { signing: item(false) })]), [1, 2], 'mixed: even a forged equal head stays apart');
  assert.deepEqual(counted([send(1, { signing: item(null) }), send(2, { signing: item(null) })]), [1, 1], 'two absent sends with equal headers');
  assert.deepEqual(counted([send(1, { signing: item(false) }), send(2, { signing: item(false) })]), [1, 1], 'unverified: compared by the raw values in head');
  assert.deepEqual(counted([send(1, { signing: item(false) }), send(2, { head: 'f', signing: item(false) })]), [1, 2]);
});

test('gate: dedupeSeconds from the first member\'s base (the earlier of its signing timestamp and arrival) to each later arrival; exactly the bound collapses', () => {
  const D = SIGNING.signing.dedupeSeconds;
  assert.deepEqual(counted([send(1), send(2, { signing: item(true, T + D - 10, T + D) })]), [1, 1], 'exactly D');
  assert.deepEqual(counted([send(1), send(2, { signing: item(true, T + D - 10, T + D + 1) })]), [1, 2], 'D + 1');
  assert.deepEqual(counted([send(1, { signing: item(true, T + 60, T) }), send(2, { signing: item(true, T + 61, T + D + 1) })]), [1, 2], 'a first timestamp claimed 60 s ahead does not stretch the bound (review finding 2)');
  assert.deepEqual(counted([send(1, { signing: item(true, T - 100, T) }), send(2, { signing: item(true, T - 90, T + D - 99) })]), [1, 2], 'an early signing timestamp shortens it');
  assert.deepEqual(counted([send(1, { signing: item(false, T, T) }), send(2, { signing: item(false, T, T + D) })]), [1, 1], 'an exact unverified replay within D');
  assert.deepEqual(counted([send(1, { signing: item(false, T, T) }), send(2, { signing: item(false, T, T + D + 1) })]), [1, 2], 'an exact unverified replay after D (review finding 1)');
  assert.deepEqual(counted([send(1, { signing: item(null, T, T) }), send(2, { signing: item(null, T, T + 3600) })]), [1, 2], 'an exact unsigned replay an hour later');
  assert.deepEqual(counted([send(1, { signing: item(false, T, null) }), send(2, { signing: item(false, T, null) })]), [1, 2], 'no arrival second (no signing clock): nothing collapses');
  assert.deepEqual(counted([send(1), send(2, { signing: item(true, T + 10) }), send(3, { signing: item(true, T + 720) })]), [1, 2], 'a fresh re-sign twelve minutes later is its own application');
  const long = { idempotency: { [HOST]: publishIdempotency(decl({ ...STRIPE, dedupeSeconds: 3600 })) } };
  const late = [send(1), send(2, { signing: item(true, T + 720) })];
  assert.deepEqual(counted(late, { events: late, scope: long }), [1, 1], 'a destination declared to keep keys an hour');
});

test('gate: timestamps never go back; records must carry the declared scheme; content, key and head stay bound', () => {
  assert.deepEqual(counted([send(1, { signing: item(true, T + 5) }), send(2, { signing: item(true, T + 5) })]), [1, 1], 'equal timestamps');
  assert.deepEqual(counted([send(1, { signing: item(true, T + 5) }), send(2, { signing: item(true, T) })]), [1, 2]);
  assert.deepEqual(counted([send(1), send(2, { signing: { ...item(true), scheme: 'slack-v0' } })]), [1, 2], 'another scheme');
  assert.deepEqual(counted([send(1, { signing: 'none' }), send(2, { signing: 'none' })]), [1, 2], 'no signing item on a declaring host: by send, even exact copies');
  const signedToo = [send(1), send(2)]; signedToo[1].idempotency.signed = { stripe: null };
  assert.deepEqual(counted(signedToo), [1, 2]);
  assert.deepEqual(counted([send(1), send(2, { content: 'd', signing: item(true, T + 9) })]), [1, 2]);
  const bare = [send(1), send(2, { signing: item(true, T + 9) })];
  assert.deepEqual(counted(bare, { events: bare, scope: { idempotency: { [HOST]: validateIdempotencyDeclaration({ header: 'x-event-id' }) } } }), [1, 2], 'a signing item on a host that does not declare signing');
});

test('clashes: a signing variable that is a credential or a proof variable; a signing value that is a proof value in any form', () => {
  const profile = (signing, extra = {}) => ({ actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS' } }, observers: [{ id: 'db', type: 'pg-snapshot', credentialEnv: 'SCOPEHAVEN_TARGET_DB' },
    { id: 'sink', type: 'egress-recorder', destinations: [{ host: HOST, idempotency: { header: 'x-event-id', signing } }, { host: 'pay.example.test', forward: { upstream: 'http://127.0.0.1:47000', proofEnv: 'SCOPEHAVEN_TARGET_PROOF' } }] }], ...extra });
  assert.equal(signingSecretClash(profile(STRIPE)), null);
  for (const name of ['SCOPEHAVEN_TARGET_OPS', 'SCOPEHAVEN_TARGET_DB', 'SCOPEHAVEN_TARGET_PROOF']) assert.match(signingSecretClash(profile({ ...STRIPE, secretEnv: [ENV(1), name] })), /signing secretEnv/, name);
  const proof = secret(5), observers = signing => profile(signing).observers;
  const env = values => ({ SCOPEHAVEN_TARGET_PROOF: proof, ...values });
  assert.equal(signingSecretValueClash(observers(STRIPE), env({ [ENV(1)]: secret(1), [ENV(2)]: secret(2) })), null);
  const raw = signingSecretValueClash(observers(STRIPE), env({ [ENV(1)]: secret(1), [ENV(2)]: proof }));
  assert.match(raw, /signing secret 2 of "hooks.example.test" is the forward proof secret of "pay.example.test"/);
  assert.ok(!raw.includes(proof), 'the message names hosts and slots, never a value');
  const standard = { ...STANDARD, secretEnv: [ENV(1)] };
  assert.match(signingSecretValueClash(observers(standard), env({ [ENV(1)]: Buffer.from(proof).toString('base64') })) ?? '', /forward proof secret/, 'the same key bytes');
  assert.match(signingSecretValueClash(observers(standard), env({ [ENV(1)]: Buffer.concat([Buffer.from(proof), Buffer.alloc(1)]).toString('base64') })) ?? '', /forward proof secret/, 'K plus 0x00');
  const longProof = 'p'.repeat(80);
  assert.match(signingSecretValueClash(observers(standard), { SCOPEHAVEN_TARGET_PROOF: longProof, [ENV(1)]: sha(Buffer.from(longProof)).toString('base64') }) ?? '', /forward proof secret/, 'a long key and its SHA-256');
  const b64 = Buffer.alloc(32, 3).toString('base64');
  assert.match(signingSecretValueClash(observers(standard), { SCOPEHAVEN_TARGET_PROOF: b64, [ENV(1)]: `wh${'sec_'}${b64}` }) ?? '', /forward proof secret/, 'the proof is the signing secret without its prefix (review finding 3)');
  assert.match(signingSecretValueClash(observers(STRIPE), { SCOPEHAVEN_TARGET_PROOF: `wh${'sec_'}${b64}`, [ENV(1)]: b64, [ENV(2)]: secret(2) }) ?? '', /signing secret 1/, 'and the other way round');
  assert.match(signingSecretValueClash(observers(standard), { SCOPEHAVEN_TARGET_PROOF: b64, [ENV(1)]: b64 }) ?? '', /forward proof secret/, 'the proof read as base64 is the signing key');
  const words = ['plain', 'text', 'secret', 'not', 'base64'].join('-');
  assert.match(signingSecretValueClash(observers(STRIPE), { SCOPEHAVEN_TARGET_PROOF: `wh${'sec_'}${words}`, [ENV(1)]: words, [ENV(2)]: secret(2) }) ?? '', /signing secret 1/, 'a prefix on a remainder that is not base64');
  const k = Buffer.alloc(32, 5);
  assert.match(signingSecretValueClash(observers(standard), { SCOPEHAVEN_TARGET_PROOF: k.toString('base64'), [ENV(1)]: Buffer.concat([k, Buffer.alloc(1)]).toString('base64') }) ?? '', /forward proof secret/, 'the proof read as base64 is the same HMAC key');
});

test('the run record: usable per declared slot, present exactly when signing is declared; signing items bound to the declaration', () => {
  const observers = [{ id: 'db', type: 'pg-snapshot' }, { id: 'sink', type: 'egress-recorder', idempotency: { [HOST]: SIGNING, 'other.example.test': publishIdempotency(validateIdempotencyDeclaration({ header: 'k' })) } }];
  const run = signingRunOf(observers, [null, { [HOST]: { scheme: 'stripe', usable: [true, false] } }]);
  assert.deepEqual(run, [{ observer: 'sink', host: HOST, scheme: 'stripe', usable: [true, false] }]);
  assert.equal(validSigningRun(run, observers), true);
  assert.equal(validSigningRun(undefined, observers), false);
  for (const forge of [r => { r[0].usable.push(true); }, r => { r[0].usable[0] = 1; }, r => { r[0].host = 'other.example.test'; }, r => { r[0].fingerprints = []; }, r => { r.push(r[0]); }]) {
    const r = structuredClone(run); forge(r); assert.equal(validSigningRun(r, observers), false, forge.toString());
  }
  assert.equal(signingRunOf([{ id: 'sink', type: 'egress-recorder', idempotency: { other: validateIdempotencyDeclaration({ header: 'k' }) } }], null), null);
  assert.equal(validSigningRun(undefined, [{ id: 'sink', type: 'egress-recorder' }]), true);
  const window = events => [{ instanceId: 'egress-recorder-sink', scope, events }];
  assert.doesNotThrow(() => consistentSigningRun(window([send(1), send(2, { signing: item(false) })]), run));
  assert.throws(() => consistentSigningRun(window([send(1)]), [{ ...run[0], usable: [false, false] }]), /idempotency-signing/, 'verified with no usable secret');
  assert.throws(() => consistentSigningRun(window([send(1, { signing: 'none' })]), run), /idempotency-signing/);
  assert.throws(() => consistentSigningRun(window([send(1, { signing: { ...item(true), scheme: 'slack-v0' } })]), run), /idempotency-signing/);
  assert.throws(() => consistentSigningRun([{ instanceId: 'egress-recorder-sink', scope: { idempotency: { [HOST]: validateIdempotencyDeclaration({ header: 'x-event-id' }) } }, events: [send(1)] }], run), /idempotency-signing/, 'an item on an undeclared host');
});

test('the menu and bounds are fixed; the wording module\'s copy of the timestamped names matches the volatile schemes', () => {
  assert.deepEqual(Object.keys(IDEMPOTENCY_SIGNING_SCHEMES), ['stripe', 'standard-webhooks', 'slack-v0']);
  assert.deepEqual([SIGNING_BOUNDS.secrets, SIGNING_BOUNDS.secretsPerRecorder, SIGNING_BOUNDS.defaultDedupeSeconds, ...SIGNING_BOUNDS.dedupeSeconds], [4, 16, 300, 1, 86400]);
  assert.deepEqual(timestampedSignatureNames().sort(), Object.values(IDEMPOTENCY_SIGNATURE_SCHEMES).flatMap(s => [s.signature, s.timestamp]).filter(Boolean).sort());
});
