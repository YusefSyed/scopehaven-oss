// Stage 1: the Stripe stand-in, the Stripe read-back observer and the verdicts on its windows. Loopback only: every server here
// listens on 127.0.0.1 and every request goes to it; the fake-provider tests use an in-memory transport and open no socket. Keys are
// synthetic, made per test at run time.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { randomBytes } from 'node:crypto';
import { startStripeStandIn } from './stand-in.mjs';
import { createStripeReadBack, verifySealedRead, isAuthenticRead, digestOf, LEDGER_SCHEMA } from './read-back.mjs';
import { windowOf, evaluate, judge } from './verdict.mjs';

const testKey = prefix => `${prefix}_${'test'}_${randomBytes(16).toString('hex')}`;
const liveKey = prefix => `${prefix}_${'live'}_${randomBytes(16).toString('hex')}`;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const since = () => Math.floor(Date.now() / 1000) - 5;
const copyOf = value => JSON.parse(JSON.stringify(value));
// A saved read edited and given a fresh checksum: what a file could hold. Only mode 'sealed-file' accepts it.
const reseal = (read, edit) => { const r = copyOf(read); edit(r); delete r.sha256; return { ...r, sha256: digestOf(r) }; };

async function provider(t, options = {}) {
  const W = testKey('sk'), R = testKey('rk');
  const s = await startStripeStandIn({ keys: { write: [W], read: [R] }, ...options });
  t.after(() => s.stop());
  return { s, W, R };
}
function call(origin, path, { method = 'GET', key, form, body, idem, headers = {}, timeoutMs = 5000 } = {}) {
  const { port } = new URL(origin);
  const text = form ? new URLSearchParams(form).toString() : body ?? '';
  return new Promise(resolve => {
    let done = false; const end = v => { if (!done) { done = true; resolve(v); } };
    const req = request({ host: '127.0.0.1', port, path, method, agent: false, headers: { Connection: 'close', ...(key ? { Authorization: `Bearer ${key}` } : {}),
      ...(text ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(text) } : {}), ...(idem ? { 'Idempotency-Key': idem } : {}), ...headers } }, res => {
      const chunks = []; res.on('data', d => chunks.push(d));
      res.on('end', () => end({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString() || 'null'), headers: res.headers }));
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); end({ timeout: true }); });
    req.on('error', () => end({ failed: true }));
    req.end(text);
  });
}
async function seed(s, W, amount = 5000) {
  const cus = (await call(s.origin, '/v1/customers', { method: 'POST', key: W, form: { description: 'synthetic', source: 'tok_visa' } })).json;
  const ch = (await call(s.origin, '/v1/charges', { method: 'POST', key: W, form: { amount: String(amount), currency: 'usd', customer: cus.id, 'metadata[order]': 'A-1' } })).json;
  return { cus: cus.id, ch: ch.id };
}
const charge = async (s, W, cus, amount = 5000) => (await call(s.origin, '/v1/charges', { method: 'POST', key: W, form: { amount: String(amount), currency: 'usd', customer: cus } })).json.id;
const refund = (s, W, ch, amount, idem) => call(s.origin, '/v1/refunds', { method: 'POST', key: W, form: { charge: ch, amount: String(amount) }, idem });
const readBackOf = (s, R, { charges = [], customers = [], ...rest } = {}) => createStripeReadBack({ base: s.origin, key: R, account: s.account, charges, customers, since: since(), metadataKeys: ['order'], settleMs: 20, ...rest });

// ---- the stand-in follows Stripe's documented idempotency and refund semantics -------------------------------------------------

test('stand-in: a same-key, same-parameter retry replays the saved answer and creates no second refund', async t => {
  const { s, W } = await provider(t); const { ch } = await seed(s, W);
  const a = await refund(s, W, ch, 2000, 'k-1'), b = await refund(s, W, ch, 2000, 'k-1');
  assert.equal(a.status, 200); assert.equal(b.status, 200);
  assert.equal(b.headers['idempotent-replayed'], 'true'); assert.equal(a.headers['idempotent-replayed'], undefined);
  assert.equal(b.json.id, a.json.id);
  assert.equal(s.truthForTests().refunds.length, 1);
  assert.notEqual(a.headers['request-id'], b.headers['request-id']);
});

test('stand-in: the same parameters in another order are the same request', async t => {
  const { s, W } = await provider(t); const { ch } = await seed(s, W);
  const a = await call(s.origin, '/v1/refunds', { method: 'POST', key: W, body: `charge=${ch}&amount=300&metadata[order]=A-1`, idem: 'k-order' });
  const b = await call(s.origin, '/v1/refunds', { method: 'POST', key: W, body: `metadata[order]=A-1&amount=300&charge=${ch}`, idem: 'k-order' });
  assert.equal(a.status, 200); assert.equal(b.status, 200); assert.equal(b.headers['idempotent-replayed'], 'true');
  assert.equal(s.truthForTests().refunds.length, 1);
});

test('stand-in: a same-key retry while the first request is still running answers 409 idempotency_key_in_use, then the replay', async t => {
  const { s, W } = await provider(t); const { ch } = await seed(s, W);
  s.slowFirstRefund(ch, 1500);
  const first = refund(s, W, ch, 2000, 'k-run');
  await sleep(100);
  const during = await refund(s, W, ch, 2000, 'k-run');
  assert.equal(during.status, 409); assert.equal(during.json.error.code, 'idempotency_key_in_use');
  const a = await first; const after = await refund(s, W, ch, 2000, 'k-run');
  assert.equal(a.status, 200); assert.equal(after.status, 200); assert.equal(after.json.id, a.json.id); assert.equal(after.headers['idempotent-replayed'], 'true');
  assert.equal(s.truthForTests().refunds.length, 1);
});

test('stand-in: a key reused with other parameters answers idempotency_error and changes nothing', async t => {
  const { s, W } = await provider(t); const { ch } = await seed(s, W);
  await refund(s, W, ch, 2000, 'k-2');
  const other = await refund(s, W, ch, 999, 'k-2');
  assert.equal(other.status, 400); assert.equal(other.json.error.type, 'idempotency_error');
  assert.deepEqual(s.truthForTests().refunds.map(r => r.amount), [2000]);
});

test('stand-in: a refund can take only what is left on the charge, and that refusal is saved under its key', async t => {
  const { s, W } = await provider(t); const { ch } = await seed(s, W, 4000);
  assert.equal((await refund(s, W, ch, 2500, 'k-a')).status, 200);
  const over = await refund(s, W, ch, 2500, 'k-b');
  assert.equal(over.status, 400); assert.equal(over.json.error.param, 'amount');
  assert.deepEqual(s.truthForTests().charges.map(c => c.amount_refunded), [2500]);
  assert.equal((await refund(s, W, ch, 1500, 'k-c')).status, 200);
  const again = await refund(s, W, ch, 2500, 'k-b');
  assert.equal(again.status, 400); assert.equal(again.headers['idempotent-replayed'], 'true');
  assert.equal(s.truthForTests().refunds.length, 2);
});

test('stand-in: a fully refunded charge answers charge_already_refunded', async t => {
  const { s, W } = await provider(t); const { ch } = await seed(s, W, 1000);
  assert.equal((await call(s.origin, '/v1/refunds', { method: 'POST', key: W, form: { charge: ch } })).status, 200);
  const again = await refund(s, W, ch, 1);
  assert.equal(again.status, 400); assert.equal(again.json.error.code, 'charge_already_refunded');
  assert.equal(s.truthForTests().charges[0].refunded, true);
});

test('stand-in: a read key reads but cannot write; an unknown or live-mode key is refused', async t => {
  const { s, W, R } = await provider(t); const { ch } = await seed(s, W);
  const write = await refund(s, R, ch, 100);
  assert.equal(write.status, 403);
  assert.equal((await call(s.origin, `/v1/refunds?charge=${ch}`, { key: R })).status, 200);
  assert.equal((await call(s.origin, '/v1/account', { key: testKey('rk') })).status, 401);
  const live = await call(s.origin, '/v1/account', { key: liveKey('rk') });
  assert.equal(live.status, 401); assert.equal(live.json.error.code, 'livemode_mismatch');
  assert.equal(s.truthForTests().refunds.length, 0);
  await assert.rejects(startStripeStandIn({ keys: { write: [liveKey('sk')] } }), /test-mode/);
});

test('stand-in: lists are newest first and page by starting_after and ending_before', async t => {
  const { s, W, R } = await provider(t); const { ch } = await seed(s, W, 5000);
  const ids = [];
  for (let i = 0; i < 5; i++) ids.push((await refund(s, W, ch, 100 + i)).json.id);
  const p1 = await call(s.origin, `/v1/refunds?charge=${ch}&limit=2`, { key: R });
  assert.deepEqual(p1.json.data.map(r => r.id), [ids[4], ids[3]]); assert.equal(p1.json.has_more, true);
  const p3 = await call(s.origin, `/v1/refunds?charge=${ch}&limit=2&starting_after=${ids[1]}`, { key: R });
  assert.deepEqual(p3.json.data.map(r => r.id), [ids[0]]); assert.equal(p3.json.has_more, false);
  const back = await call(s.origin, `/v1/refunds?charge=${ch}&limit=2&ending_before=${ids[1]}`, { key: R });
  assert.deepEqual(back.json.data.map(r => r.id), [ids[3], ids[2]]); assert.equal(back.json.has_more, true);
});

test('stand-in: created[gte] lists only refunds created since then', async t => {
  const { s, W, R } = await provider(t); const { ch } = await seed(s, W);
  await refund(s, W, ch, 100);
  const now = Math.floor(Date.now() / 1000);
  assert.equal((await call(s.origin, `/v1/refunds?created[gte]=${now - 60}`, { key: R })).json.data.length, 1);
  assert.equal((await call(s.origin, `/v1/refunds?created[gte]=${now + 60}`, { key: R })).json.data.length, 0);
});

test('stand-in: a request that fails validation saves nothing under its key', async t => {
  const { s, W } = await provider(t); const { cus, ch } = await seed(s, W);
  for (const form of [{ charge: ch, amount: '100', refund_to: 'card_x' }, { charge: ch, amount: 'ten' }]) {
    const key = `k-v-${randomBytes(4).toString('hex')}`;
    const bad = await call(s.origin, '/v1/refunds', { method: 'POST', key: W, form, idem: key });
    assert.equal(bad.status, 400);
    const good = await refund(s, W, ch, 100, key);
    assert.equal(good.status, 200); assert.equal(good.headers['idempotent-replayed'], undefined);
  }
  const both = await call(s.origin, '/v1/charges', { method: 'POST', key: W, form: { amount: '900', currency: 'usd', customer: cus, source: 'tok_visa' }, idem: 'k-both' });
  assert.equal(both.status, 400);
  const charged = await call(s.origin, '/v1/charges', { method: 'POST', key: W, form: { amount: '900', currency: 'usd', customer: cus }, idem: 'k-both' });
  assert.equal(charged.status, 200);
  assert.equal(s.truthForTests().refunds.length, 2);
});

test('stand-in: a repeated parameter is refused', async t => {
  const { s, W } = await provider(t); const { ch } = await seed(s, W);
  const r = await call(s.origin, '/v1/refunds', { method: 'POST', key: W, body: `charge=${ch}&amount=100&amount=200` });
  assert.equal(r.status, 400); assert.match(r.json.error.message, /repeated/);
  assert.equal(s.truthForTests().refunds.length, 0);
});

test('stand-in: slowFirstRefund commits the refund before it answers', async t => {
  const { s, W } = await provider(t); const { ch } = await seed(s, W);
  s.slowFirstRefund(ch, 1000);
  const started = Date.now(), pending = refund(s, W, ch, 700, 'k-slow');
  await sleep(100);
  assert.equal(s.truthForTests().refunds.length, 1);
  const r = await pending;
  assert.equal(r.status, 200); assert.ok(Date.now() - started >= 990);
});

test('stand-in: listing refunds of an unknown charge, or with another account named, is refused', async t => {
  const { s, R } = await provider(t);
  const r = await call(s.origin, '/v1/refunds?charge=ch_000000000000', { key: R });
  assert.equal(r.status, 400); assert.equal(r.json.error.code, 'resource_missing');
  const other = await call(s.origin, '/v1/account', { key: R, headers: { 'Stripe-Account': 'acct_somebodyelse01' } });
  assert.equal(other.status, 403); assert.equal(other.json.error.code, 'account_invalid');
});

// ---- the read-back observer -------------------------------------------------------------------------------------------------------

test('read-back: a complete read keeps ids, amounts and request ids, never the key, and is frozen and branded', async t => {
  const { s, W, R } = await provider(t); const { cus, ch } = await seed(s, W);
  await refund(s, W, ch, 1200, 'k-r');
  const read = await readBackOf(s, R, { charges: [ch], customers: [cus] }).read('m0');
  assert.equal(read.schema, LEDGER_SCHEMA); assert.equal(read.coverage, 'complete', read.reasons.join());
  assert.equal(read.provider.account, s.account); assert.equal(read.observer.transport, 'default'); assert.equal(read.observer.seq, 1);
  assert.deepEqual(read.refunds.map(r => [r.charge, r.amount, r.status]), [[ch, 1200, 'succeeded']]);
  assert.equal(read.charges[0].amount_refunded, 1200); assert.equal(read.charges[0].metadata.order, 'A-1');
  assert.ok(read.requests.length >= 8 && read.requests.every(q => /^req_/.test(q.requestId) && q.status === 200));
  assert.ok(!JSON.stringify(read).includes(R) && !JSON.stringify(read).includes(R.slice(8)));
  assert.equal(read.credential.class, 'restricted-test-read');
  assert.ok(Object.isFrozen(read) && Object.isFrozen(read.refunds[0]) && isAuthenticRead(read));
  assert.equal(verifySealedRead(copyOf(read)).ok, true);
});

test('read-back: every page is followed', async t => {
  const { s, W, R } = await provider(t); const { ch } = await seed(s, W, 50000);
  for (let i = 0; i < 120; i++) await refund(s, W, ch, 1);
  const read = await readBackOf(s, R, { charges: [ch] }).read('m0');
  assert.equal(read.coverage, 'complete', read.reasons.join()); assert.equal(read.refunds.length, 120);
  assert.ok(read.requests.some(q => q.hasMore === true));
});

test('read-back: a list longer than maxPages leaves the read partial', async t => {
  const { s, W, R } = await provider(t); const { ch } = await seed(s, W, 50000);
  for (let i = 0; i < 101; i++) await refund(s, W, ch, 1);
  const read = await readBackOf(s, R, { charges: [ch], maxPages: 1 }).read('m0');
  assert.equal(read.coverage, 'partial'); assert.ok(read.reasons.includes('pagination-cap'));
});

test('read-back: a refund on a charge outside the declared ones is still seen, under outside', async t => {
  const { s, W, R } = await provider(t); const mine = await seed(s, W); const other = await seed(s, W);
  await refund(s, W, other.ch, 300);
  const read = await readBackOf(s, R, { charges: [mine.ch], customers: [mine.cus] }).read('m0');
  assert.equal(read.coverage, 'complete', read.reasons.join());
  assert.deepEqual(read.outside.map(r => [r.charge, r.amount]), [[other.ch, 300]]); assert.equal(read.refunds.length, 0);
});

test('read-back: a refund on a new charge of a declared customer is outside the declared charges', async t => {
  const { s, W, R } = await provider(t); const { cus, ch } = await seed(s, W);
  const added = await charge(s, W, cus, 9000);
  await refund(s, W, added, 9000);
  const read = await readBackOf(s, R, { charges: [ch], customers: [cus] }).read('m0');
  assert.equal(read.coverage, 'complete', read.reasons.join());
  assert.deepEqual(read.outside.map(r => [r.charge, r.amount]), [[added, 9000]]); assert.equal(read.refunds.length, 0);
  assert.ok(read.charges.some(c => c.id === added));
});

test('read-back: it refuses a non-loopback base, a secret key, a live key, an app key and a future since', () => {
  const base = 'http://127.0.0.1:12111', ok = { since: 1, charges: [] }, app = testKey('rk');
  assert.throws(() => createStripeReadBack({ base: 'https://api.stripe.com', key: testKey('rk'), ...ok }), /loopback/);
  assert.throws(() => createStripeReadBack({ base: 'http://localhost:12111', key: testKey('rk'), ...ok }), /loopback/);
  assert.throws(() => createStripeReadBack({ base, key: testKey('sk'), ...ok }), /restricted/);
  assert.throws(() => createStripeReadBack({ base, key: liveKey('rk'), ...ok }), /restricted/);
  assert.throws(() => createStripeReadBack({ base, key: app, refuseKeys: [app], ...ok }), /app holds/);
  assert.throws(() => createStripeReadBack({ base, key: testKey('rk'), ...ok, since: Math.floor(Date.now() / 1000) + 3600 }), /future/);
  assert.doesNotThrow(() => createStripeReadBack({ base, key: testKey('rk'), refuseKeys: [app], ...ok }));
});

test('read-back: a saved read is checked for edits, and a parsed copy is never the observer\'s own read', async t => {
  const { s, W, R } = await provider(t); const { ch } = await seed(s, W);
  await refund(s, W, ch, 900);
  const read = await readBackOf(s, R, { charges: [ch] }).read('m0');
  const copy = copyOf(read);
  assert.equal(isAuthenticRead(copy), false);
  copy.refunds[0].amount = 1;
  assert.deepEqual(verifySealedRead(copy), { ok: false, reason: 'checksum-mismatch' });
  const { sha256, ...rest } = copyOf(read);
  assert.equal(digestOf(rest), sha256);
});

test('read-back: reads are numbered in order, one at a time', async t => {
  const { s, W, R } = await provider(t); const { ch } = await seed(s, W);
  const rb = readBackOf(s, R, { charges: [ch] });
  const a = await rb.read('m0'), b = await rb.read('m1');
  assert.deepEqual([a.observer.seq, b.observer.seq], [1, 2]); assert.equal(a.observer.id, b.observer.id);
  const pending = rb.read('m2');
  await assert.rejects(rb.read('m3'), /one read at a time/);
  await pending;
});

test('read-back: a declared charge created before since leaves the read partial', async t => {
  const { s, W, R } = await provider(t); const { ch } = await seed(s, W);
  const read = await readBackOf(s, R, { charges: [ch], since: Math.floor(Date.now() / 1000) + 120 }).read('m0');
  assert.equal(read.coverage, 'partial'); assert.ok(read.reasons.includes('since-after-charge'));
});

test('read-back: with no declared charge, since cannot be checked and the read is partial', async t => {
  const { s, W, R } = await provider(t); const { cus } = await seed(s, W);
  const read = await readBackOf(s, R, { charges: [], customers: [cus] }).read('m0');
  assert.equal(read.coverage, 'partial'); assert.ok(read.reasons.includes('since-unverified'));
});

test('read-back: a reply over the size cap leaves the read partial', async t => {
  const { createServer } = await import('node:http');
  const big = createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', 'Request-Id': 'req_big', Connection: 'close' }); res.end(`{"id":"acct_bigbigbig01","pad":"${'x'.repeat(5 * 1024 * 1024)}"}`); });
  await new Promise(r => big.listen(0, '127.0.0.1', r)); t.after(() => new Promise(r => { big.closeAllConnections?.(); big.close(r); }));
  const read = await createStripeReadBack({ base: `http://127.0.0.1:${big.address().port}`, key: testKey('rk'), charges: ['ch_fakecharge0001'], since: 1, settleMs: 0 }).read('m0');
  assert.equal(read.coverage, 'partial'); assert.ok(read.reasons.includes('over-cap'), read.reasons.join());
});

// A provider in memory: Stripe-shaped answers from a small model, with one defect switched on through `state.defect`. One observer
// per scenario, so a window between two of its reads tests the reason named, not a difference between observers.
const C1 = { id: 'ch_fakecharge0001', amount: 5000, amount_refunded: 3000, refunded: false, currency: 'usd', customer: 'cus_fakecustomer1', status: 'succeeded', created: 1, metadata: {} };
const RF = [{ id: 're_fakerefund0001', charge: C1.id, amount: 2000, currency: 'usd', status: 'succeeded', created: 2, metadata: {} }, { id: 're_fakerefund0002', charge: C1.id, amount: 1000, currency: 'usd', status: 'succeeded', created: 3, metadata: {} }];
function fake(initial = {}) {
  const state = { account: 'acct_fakeaccount01', accountLivemode: false, charges: [C1], refunds: RF, defect: null, ...initial };
  let passes = 0;
  const page = (list, url) => { const after = url.searchParams.get('starting_after'); const limit = Number(url.searchParams.get('limit') ?? 10);
    const start = after ? list.findIndex(o => o.id === after) + 1 : 0; const data = list.slice(start, start + limit); return { object: 'list', url: url.pathname, has_more: start + data.length < list.length, data }; };
  const transport = async ({ path }) => {
    const url = new URL(path, 'http://127.0.0.1'), d = state.defect;
    const reply = json => ({ status: 200, requestId: `req_fake${passes}${randomBytes(3).toString('hex')}`, text: JSON.stringify(json) });
    if (url.pathname === '/v1/account') { passes++; return d === 'status' ? { status: 500, requestId: 'req_x', text: '{}' } : reply({ id: d === 'account-shape' ? 'bogus' : state.account, object: 'account', livemode: state.accountLivemode }); }
    if (d === 'timeout') return { error: 'timeout' };
    if (d === 'not-json' && url.pathname === '/v1/refunds') return { status: 200, requestId: 'req_y', text: '<html>' };
    const one = /^\/v1\/charges\/(.+)$/.exec(url.pathname);
    if (one) { const c = state.charges.find(x => x.id === one[1]); return c ? reply({ object: 'charge', livemode: d === 'livemode', ...c }) : { status: 404, requestId: 'req_z', text: '{"error":{}}' }; }
    if (url.pathname === '/v1/charges') {
      const cus = url.searchParams.get('customer');
      let list = state.charges.filter(c => c.customer === cus).map(c => ({ object: 'charge', livemode: false, ...c }));
      if (d === 'customer-mismatch') list = list.map(c => ({ ...c, customer: 'cus_someoneelse01' }));
      if (d === 'charge-disagreement' && cus === 'cus_fakecustomer2') list = [{ object: 'charge', livemode: false, ...C1, customer: cus, amount_refunded: 1 }];
      return reply(page(list, url));
    }
    if (url.pathname === '/v1/refunds') {
      const ch = url.searchParams.get('charge');
      let list = state.refunds.filter(r => ch === null || r.charge === ch).map(r => ({ object: 'refund', ...r }));
      if (d === 'unsettled' && passes === 2) list = [...list, { object: 'refund', id: 're_lateextra0001', charge: state.charges[0].id, amount: 1, currency: 'usd', status: 'succeeded', created: 2, metadata: {} }];
      if (d === 'duplicate' && ch !== null) list = [...list, list[0]];
      if (d === 'other-charge' && ch !== null) list = list.map(r => ({ ...r, charge: 'ch_someotherone01' }));
      if (d === 'account-list-misses' && ch === null) list = list.slice(1);
      if (d === 'charge-list-misses' && ch !== null) list = list.slice(1);
      if (d === 'empty-page' && ch !== null) return reply({ object: 'list', url: url.pathname, has_more: true, data: [] });
      return reply(page(list, url));
    }
    return { status: 404, requestId: 'req_n', text: '{}' };
  };
  const observer = (options = {}) => createStripeReadBack({ base: 'http://127.0.0.1:12111', key: testKey('rk'), account: 'acct_fakeaccount01', charges: [C1.id], since: 1, settleMs: 0, ...options, transport });
  return { state, observer };
}
const fakeRead = async (initial = {}, options = {}) => fake(initial).observer(options).read('m0');
const injected = { allowInjected: true };

test('read-back (fake provider): the honest fake reads complete, and is labelled injected', async () => {
  const read = await fakeRead({});
  assert.equal(read.coverage, 'complete', read.reasons.join()); assert.equal(read.refunds.length, 2); assert.equal(read.observer.transport, 'injected');
});

for (const [defect, reason, initial = {}, options = {}] of [
  ['livemode', 'livemode'], ['status', 'status-500'], ['timeout', 'timeout'], ['not-json', 'not-json'], ['unsettled', 'unsettled'], ['duplicate', 'duplicate-id'],
  ['other-charge', 'refund-charge-mismatch'], ['account-list-misses', 'list-disagreement'], ['charge-list-misses', 'list-disagreement'],
  ['empty-page', 'shape'], ['account-shape', 'shape'], ['customer-mismatch', 'customer-mismatch', {}, { customers: ['cus_fakecustomer1'] }],
  ['charge-disagreement', 'list-disagreement', {}, { customers: ['cus_fakecustomer1', 'cus_fakecustomer2'] }],
  ['account-livemode', 'livemode', { defect: null, accountLivemode: true }],
  ['amount-refunded', 'amount-refunded-mismatch', { defect: null, charges: [{ ...C1, amount_refunded: 2000 }] }],
  ['status-word', 'status-word', { defect: null, refunds: [RF[0], { ...RF[1], status: 'reversed' }] }],
  ['outside-status-word', 'status-word', { defect: null, refunds: [...RF, { id: 're_outsiderefund1', charge: 'ch_notdeclared0001', amount: 5, currency: 'usd', status: 'reversed', created: 4, metadata: {} }] }],
  ['currency', 'currency-mismatch', { defect: null, refunds: [RF[0], { ...RF[1], currency: 'eur' }] }],
  ['account', 'account-mismatch', { defect: null }, { account: 'acct_declaredother1' }],
  ['missing-charge', 'declared-charge-missing', { defect: null }, { charges: [C1.id, 'ch_notheldbyprov1'] }],
  ['since-after-charge', 'since-after-charge', { defect: null }, { since: 2 }],
]) {
  test(`read-back (fake provider): ${defect} leaves the read partial (${reason})`, async () => {
    const read = await fakeRead({ defect, ...initial }, options);
    assert.equal(read.coverage, 'partial'); assert.ok(read.reasons.includes(reason), `${reason} not in ${read.reasons.join()}`);
  });
}

test('read-back (fake provider): a failed refund is kept and does not count as money moved', async () => {
  const f = fake({ charges: [{ ...C1, amount_refunded: 0 }], refunds: [] }), rb = f.observer();
  const before = await rb.read('m0');
  f.state.charges = [{ ...C1, amount_refunded: 2000 }]; f.state.refunds = [RF[0], { ...RF[1], status: 'failed' }];
  const after = await rb.read('m1');
  assert.equal(after.coverage, 'complete', after.reasons.join());
  const w = windowOf(before, after, injected);
  assert.equal(w.coverage, 'complete', w.reasons.join());
  assert.equal(evaluate({ kind: 'stripe.refund.count', charge: C1.id, expected: 1 }, w).status, 'pass');
});

// ---- verdicts on windows --------------------------------------------------------------------------------------------------------

async function scene(t) {
  const { s, W, R } = await provider(t); const a = await seed(s, W), b = await seed(s, W);
  const rb = readBackOf(s, R, { charges: [a.ch, b.ch], customers: [a.cus, b.cus] });
  return { s, W, R, a, b, rb };
}

test('verdict: a count reads only the refunds added in the window', async t => {
  const { s, W, a, rb } = await scene(t);
  await refund(s, W, a.ch, 500);
  const m0 = await rb.read('m0');
  await refund(s, W, a.ch, 700);
  const m1 = await rb.read('m1');
  const w = windowOf(m0, m1);
  assert.equal(w.coverage, 'complete');
  assert.equal(evaluate({ kind: 'stripe.refund.count', charge: a.ch, expected: 1 }, w).status, 'pass');
  assert.equal(evaluate({ kind: 'stripe.refund.count', charge: a.ch, expected: 2 }, w).status, 'fail');
});

test('verdict: none fails on one refund, and passes on another charge\'s', async t => {
  const { s, W, a, b, rb } = await scene(t);
  const m0 = await rb.read('m0'); await refund(s, W, b.ch, 100); const m1 = await rb.read('m1');
  assert.equal(evaluate({ kind: 'stripe.refund.none', charge: a.ch }, windowOf(m0, m1)).status, 'pass');
  assert.equal(evaluate({ kind: 'stripe.refund.none', charge: b.ch }, windowOf(m0, m1)).status, 'fail');
});

test('verdict: max-total sums the refunds added on the charge', async t => {
  const { s, W, a, rb } = await scene(t);
  const m0 = await rb.read('m0'); await refund(s, W, a.ch, 2500); await refund(s, W, a.ch, 1500); const m1 = await rb.read('m1');
  const w = windowOf(m0, m1);
  assert.equal(evaluate({ kind: 'stripe.refund.max-total', charge: a.ch, max: 4000 }, w).status, 'pass');
  assert.equal(evaluate({ kind: 'stripe.refund.max-total', charge: a.ch, max: 3999 }, w).status, 'fail');
});

test('verdict: max-total on a charge already refunded at the window\'s start cannot pass', async t => {
  const { s, W, a, rb } = await scene(t);
  await refund(s, W, a.ch, 1000);
  const m0 = await rb.read('m0'); await refund(s, W, a.ch, 3500); const m1 = await rb.read('m1');
  const w = windowOf(m0, m1);
  const under = evaluate({ kind: 'stripe.refund.max-total', charge: a.ch, max: 4000 }, w);
  assert.equal(under.status, 'inconclusive'); assert.match(under.basis, /charge-refunded-before-window/);
  assert.equal(evaluate({ kind: 'stripe.refund.max-total', charge: a.ch, max: 3000 }, w).status, 'fail');
});

test('verdict: max-total in more than one currency is inconclusive', async t => {
  const { s, W, a, rb } = await scene(t);
  const m0 = await rb.read('m0'); await refund(s, W, a.ch, 100); await refund(s, W, a.ch, 200); const m1 = await rb.read('m1');
  const mixed = reseal(m1, r => { r.refunds = r.refunds.map((x, i) => (x.charge === a.ch && i === 0 ? { ...x, currency: 'eur' } : x)); });
  const w = windowOf(copyOf(m0), mixed, { mode: 'sealed-file' });
  assert.equal(w.coverage, 'complete', w.reasons.join());
  assert.equal(evaluate({ kind: 'stripe.refund.max-total', charge: a.ch, max: 5000 }, w).status, 'inconclusive');
});

test('verdict: a partial read makes every kind inconclusive, never pass', async () => {
  const f = fake(), rb = f.observer();
  const good = await rb.read('m0'); f.state.defect = 'livemode'; const bad = await rb.read('m1'); f.state.defect = null; const good2 = await rb.read('m2');
  for (const w of [windowOf(good, bad, injected), windowOf(bad, good2, injected)]) {
    assert.equal(w.coverage, 'partial'); assert.ok(!w.reasons.includes('observer-differs')); assert.ok(w.reasons.some(r => /read-partial/.test(r)), w.reasons.join());
    for (const a of [{ kind: 'stripe.refund.count', charge: C1.id, expected: 0 }, { kind: 'stripe.refund.none', charge: C1.id }, { kind: 'stripe.refund.max-total', charge: C1.id, max: 0 },
      { kind: 'stripe.refund.none-outside' }, { kind: 'rows.match-ledger', charges: [C1.id], rows: [] }]) assert.equal(evaluate(a, w).status, 'inconclusive', a.kind);
  }
});

test('verdict: a refund added after a boundary row\'s window withholds its pass; a control keeps its verdict with a tag', async t => {
  const { s, W, a, b, rb } = await scene(t);
  const m0 = await rb.read('m0'); await refund(s, W, b.ch, 100); const m1 = await rb.read('m1'); await refund(s, W, a.ch, 100); const final = await rb.read('final');
  const rows = judge({ reads: { m0, m1, final }, marks: ['m0', 'm1', 'final'], rows: [
    { id: 'B', title: 'boundary', severity: 'critical', from: 'm0', to: 'm1', assert: { kind: 'stripe.refund.none', charge: a.ch } },
    { id: 'C', title: 'control', severity: 'control', from: 'm0', to: 'm1', assert: { kind: 'stripe.refund.count', charge: a.ch, expected: 0 } },
    { id: 'F', title: 'fail', severity: 'critical', from: 'm0', to: 'm1', assert: { kind: 'stripe.refund.none', charge: b.ch } },
    { id: 'Q', title: 'quiet', severity: 'critical', from: 'm0', to: 'm1', assert: { kind: 'stripe.refund.count', charge: b.ch, expected: 1 } }] });
  const by = Object.fromEntries(rows.map(r => [r.id, r]));
  assert.equal(by.B.status, 'inconclusive'); assert.match(by.B.basis, /effect-outside-window/);
  assert.equal(by.C.status, 'pass'); assert.match(by.C.tags.join(), /effect-outside-window/);
  assert.equal(by.F.status, 'fail');
  assert.equal(by.Q.status, 'pass');
});

test('verdict: late money outside the declared charges, or on a rows row\'s charges, withholds those passes too', async t => {
  const { s, W, R } = await provider(t); const mine = await seed(s, W), other = await seed(s, W);
  const rb = readBackOf(s, R, { charges: [mine.ch], customers: [mine.cus] });
  const m0 = await rb.read('m0'); const r1 = (await refund(s, W, mine.ch, 100)).json.id; const m1 = await rb.read('m1');
  await refund(s, W, other.ch, 100); await refund(s, W, mine.ch, 200); const final = await rb.read('final');
  const rows = judge({ reads: { m0, m1, final }, marks: ['m0', 'm1', 'final'], rows: [
    { id: 'OUT', title: 'outside', severity: 'high', from: 'm0', to: 'm1', assert: { kind: 'stripe.refund.none-outside' } },
    { id: 'ROWS', title: 'rows', severity: 'high', from: 'm0', to: 'm1', assert: { kind: 'rows.match-ledger', charges: [mine.ch], rows: [{ charge: mine.ch, amount: 100, refund: r1 }] } }] });
  for (const r of rows) { assert.equal(r.status, 'inconclusive', r.id); assert.match(r.basis, /effect-outside-window/); }
});

test('verdict: a partial read after a row\'s window withholds its pass (settlement-unobserved)', async t => {
  const { s, W, a, b, rb } = await scene(t);
  const m0 = copyOf(await rb.read('m0')); await refund(s, W, b.ch, 100);
  const m1 = copyOf(await rb.read('m1'));
  const final = reseal(await rb.read('final'), r => { r.coverage = 'partial'; r.reasons = ['unsettled']; });
  const [boundary, control] = judge({ reads: { m0, m1, final }, marks: ['m0', 'm1', 'final'], mode: 'sealed-file', rows: [
    { id: 'B', title: 'boundary', severity: 'critical', from: 'm0', to: 'm1', assert: { kind: 'stripe.refund.none', charge: a.ch } },
    { id: 'C', title: 'control', severity: 'control', from: 'm0', to: 'm1', assert: { kind: 'stripe.refund.count', charge: b.ch, expected: 1 } }] });
  assert.equal(boundary.status, 'inconclusive'); assert.match(boundary.basis, /settlement-unobserved/);
  assert.equal(control.status, 'pass'); assert.match(control.tags.join(), /settlement-unobserved/);
});

test('verdict: a row whose driving request was not answered with a 2xx cannot pass', async t => {
  const { s, W, a, b, rb } = await scene(t);
  const m0 = await rb.read('m0'); await refund(s, W, b.ch, 100); const m1 = await rb.read('m1');
  const rows = judge({ reads: { m0, m1 }, marks: ['m0', 'm1'], rows: [
    { id: 'N', title: 'none', severity: 'critical', from: 'm0', to: 'm1', answered: [500], assert: { kind: 'stripe.refund.none', charge: a.ch } },
    { id: 'Z', title: 'nothing came', severity: 'critical', from: 'm0', to: 'm1', answered: [200, null], assert: { kind: 'stripe.refund.none', charge: a.ch } },
    { id: 'F', title: 'fail', severity: 'critical', from: 'm0', to: 'm1', answered: [500], assert: { kind: 'stripe.refund.none', charge: b.ch } },
    { id: 'P', title: 'answered', severity: 'critical', from: 'm0', to: 'm1', answered: [200], assert: { kind: 'stripe.refund.none', charge: a.ch } }] });
  assert.deepEqual(rows.map(r => r.status), ['inconclusive', 'inconclusive', 'fail', 'pass']);
});

test('verdict: the desk\'s rows must name exactly the refunds the ledger shows, under the right charge', async t => {
  const { s, W, a, b, rb } = await scene(t);
  const m0 = await rb.read('m0'); const r1 = (await refund(s, W, a.ch, 2000)).json.id; const r2 = (await refund(s, W, a.ch, 2000)).json.id; const m1 = await rb.read('m1');
  const w = windowOf(m0, m1), check = (rows, charges = [a.ch]) => evaluate({ kind: 'rows.match-ledger', charges, rows }, w);
  assert.equal(check([{ charge: a.ch, amount: 2000, refund: r1 }, { charge: a.ch, amount: 2000, refund: r2 }]).status, 'pass');
  assert.equal(check([{ charge: a.ch, amount: 2000, refund: r2 }]).status, 'fail');
  assert.equal(check([{ charge: a.ch, amount: 2000, refund: r1 }, { charge: a.ch, amount: 2000, refund: r2 }, { charge: a.ch, amount: 2000, refund: r2 }]).status, 'fail');
  assert.equal(check([{ charge: a.ch, amount: 2000, refund: r1 }, { charge: a.ch, amount: 1999, refund: r2 }]).status, 'fail');
  assert.equal(check([{ charge: a.ch, amount: 2000, refund: r1 }, { charge: a.ch, amount: 2000, refund: null }]).status, 'fail');
  const moved = check([{ charge: a.ch, amount: 2000, refund: r1 }, { charge: b.ch, amount: 2000, refund: r2 }], [a.ch, b.ch]);
  assert.equal(moved.status, 'fail'); assert.match(moved.basis, /booked under another order/);
  assert.equal(check([{ charge: a.ch, amount: 2000, refund: r1 }, { charge: a.ch, amount: 2000, refund: r2 }, { charge: b.ch, amount: 50, refund: 're_notinscope0001' }]).status, 'pass');
});

test('verdict: reads of two observers or providers, reads out of order, or reads not the observer\'s own never decide', async t => {
  const one = await scene(t), two = await scene(t);
  const x = await one.rb.read('m0'), y = await two.rb.read('m1');
  assert.ok(windowOf(x, y).reasons.includes('provider-differs')); assert.ok(windowOf(x, y).reasons.includes('observer-differs'));
  const twin = readBackOf(one.s, one.R, { charges: [one.a.ch, one.b.ch], customers: [one.a.cus, one.b.cus] });
  const z = await twin.read('m1');
  assert.deepEqual(windowOf(x, z).reasons, ['observer-differs', 'reads-out-of-order']);
  const later = await one.rb.read('m1');
  assert.deepEqual(windowOf(later, x).reasons, ['reads-out-of-order']);
  const copy = copyOf(later);
  assert.deepEqual(windowOf(x, copy).reasons, ['read-not-accepted']);
  assert.equal(windowOf(copyOf(x), copy, { mode: 'sealed-file' }).coverage, 'complete');
  copy.refunds = [...copy.refunds, { id: 're_forgedrefund01', charge: one.a.ch, amount: 1, currency: 'usd', status: 'succeeded', created: 1, metadata: {} }];
  assert.deepEqual(windowOf(copyOf(x), copy, { mode: 'sealed-file' }).reasons, ['read-not-accepted']);
  const nobody = reseal(later, r => { r.provider.account = null; }), nobody0 = reseal(x, r => { r.provider.account = null; });
  assert.ok(windowOf(nobody0, nobody, { mode: 'sealed-file' }).reasons.includes('provider-differs'));
});

test('verdict: two observers with one configuration never share a window; a forged configuration never decides', async t => {
  const { s, W, R } = await provider(t); const a = await seed(s, W); const fixed = since();
  const make = () => readBackOf(s, R, { charges: [a.ch], customers: [a.cus], since: fixed });
  const one = make(), two = make();
  const x = await one.read('m0'); await two.read('m0'); const y = await two.read('m1');
  assert.deepEqual(windowOf(x, y).reasons, ['observer-differs']);
  const z = await one.read('m1');
  const forged = reseal(z, r => { r.observer.settleMs += 1; });
  assert.deepEqual(windowOf(copyOf(x), forged, { mode: 'sealed-file' }).reasons, ['observer-differs']);
});

test('verdict: another provider base or account in a saved read never decides', async t => {
  const { a, rb } = await scene(t);
  const x = copyOf(await rb.read('m0')), y = await rb.read('m1');
  assert.deepEqual(windowOf(x, reseal(y, r => { r.provider.base = 'http://127.0.0.1:1'; }), { mode: 'sealed-file' }).reasons, ['provider-differs']);
  assert.deepEqual(windowOf(x, reseal(y, r => { r.provider.account = 'acct_anotherone001'; }), { mode: 'sealed-file' }).reasons, ['provider-differs']);
  assert.equal(windowOf(x, copyOf(y), { mode: 'sealed-file' }).coverage, 'complete');
  assert.ok(a.ch);
});

test('verdict: a charge the from read did not return is not observed', async t => {
  const { a, rb } = await scene(t);
  const x = reseal(await rb.read('m0'), r => { r.charges = r.charges.filter(c => c.id !== a.ch); }), y = copyOf(await rb.read('m1'));
  const w = windowOf(x, y, { mode: 'sealed-file' });
  assert.equal(w.coverage, 'complete'); assert.ok(!w.observed.includes(a.ch));
  assert.match(evaluate({ kind: 'stripe.refund.none', charge: a.ch }, w).basis, /charge-not-observed/);
});

test('verdict: a failed refund before the window does not block max-total', async t => {
  const { s, W, a, rb } = await scene(t);
  await refund(s, W, a.ch, 1000);
  const x = reseal(await rb.read('m0'), r => { r.refunds = r.refunds.map(f => ({ ...f, status: 'failed' })); r.charges = r.charges.map(c => (c.id === a.ch ? { ...c, amount_refunded: 0 } : c)); });
  await refund(s, W, a.ch, 500);
  const y = reseal(await rb.read('m1'), r => { r.refunds = r.refunds.map(f => (f.amount === 1000 ? { ...f, status: 'failed' } : f)); });
  const w = windowOf(x, y, { mode: 'sealed-file' });
  assert.equal(w.coverage, 'complete', w.reasons.join()); assert.equal(w.priorMoving[a.ch], 0);
  assert.equal(evaluate({ kind: 'stripe.refund.max-total', charge: a.ch, max: 4000 }, w).status, 'pass');
});

test('verdict: a saved read from an injected transport, or of an unknown provider kind, is not accepted', async () => {
  const rb = fake().observer();
  const a = copyOf(await rb.read('m0')), b = copyOf(await rb.read('m1'));
  assert.deepEqual(windowOf(a, b, { mode: 'sealed-file' }).reasons, ['read-not-accepted']);
  assert.equal(windowOf(a, b, { mode: 'sealed-file', allowInjected: true }).coverage, 'complete');
  const odd = reseal(b, r => { r.provider.kind = 'somewhere-else'; });
  assert.deepEqual(windowOf(a, odd, { mode: 'sealed-file', allowInjected: true }).reasons, ['read-not-accepted']);
});

test('verdict: reads made through an injected transport decide only when allowed', async () => {
  const rb = fake().observer();
  const a = await rb.read('m0'), b = await rb.read('m1');
  assert.deepEqual(windowOf(a, b).reasons, ['read-not-accepted']);
  assert.equal(windowOf(a, b, injected).coverage, 'complete');
});

test('verdict: reversed reads are out of order even within one millisecond', async () => {
  const rb = fake().observer();
  let reversedComplete = 0;
  for (let i = 0; i < 20; i++) { const a = await rb.read(`a${i}`), b = await rb.read(`b${i}`); if (windowOf(b, a, injected).coverage === 'complete') reversedComplete++; }
  assert.equal(reversedComplete, 0);
});

test('verdict: an assertion on a charge the reads did not observe is inconclusive', async t => {
  const { s, W, R } = await provider(t); const mine = await seed(s, W), other = await seed(s, W);
  const rb = readBackOf(s, R, { charges: [mine.ch], customers: [mine.cus, other.cus] });
  const m0 = await rb.read('m0'); await refund(s, W, other.ch, 700); const m1 = await rb.read('m1');
  const w = windowOf(m0, m1);
  assert.equal(w.coverage, 'complete'); assert.deepEqual(w.observed, [mine.ch]);
  for (const a of [{ kind: 'stripe.refund.none', charge: other.ch }, { kind: 'stripe.refund.max-total', charge: other.ch, max: 0 }, { kind: 'stripe.refund.count', charge: 'ch_neverdeclared01', expected: 0 },
    { kind: 'rows.match-ledger', charges: [mine.ch, other.ch], rows: [] }]) {
    const v = evaluate(a, w);
    assert.equal(v.status, 'inconclusive', a.kind); assert.match(v.basis, /charge-not-observed/);
  }
  assert.equal(evaluate({ kind: 'stripe.refund.none-outside' }, w).status, 'fail');
});

test('verdict: a refund that vanished or changed between reads leaves the window partial', async t => {
  const { s, W, a, b, rb } = await scene(t);
  await refund(s, W, a.ch, 400);
  const m0 = copyOf(await rb.read('m0')), m1 = await rb.read('m1');
  const gone = reseal(m1, r => { r.refunds = []; r.charges = r.charges.map(c => ({ ...c, amount_refunded: 0 })); });
  assert.ok(windowOf(m0, gone, { mode: 'sealed-file' }).reasons.includes('refund-vanished'));
  for (const edit of [x => ({ ...x, amount: 300 }), x => ({ ...x, charge: b.ch }), x => ({ ...x, currency: 'eur' })]) {
    const changed = reseal(m1, r => { r.refunds = r.refunds.map(edit); });
    assert.deepEqual(windowOf(m0, changed, { mode: 'sealed-file' }).reasons, ['refund-rewritten']);
  }
});

test('verdict: none-outside fails when a refund lands outside the declared charges, and only on money that moved', async t => {
  const { s, W, R } = await provider(t); const mine = await seed(s, W); const other = await seed(s, W);
  const rb = readBackOf(s, R, { charges: [mine.ch], customers: [mine.cus] });
  await refund(s, W, other.ch, 50);
  const m0 = await rb.read('m0'); await refund(s, W, mine.ch, 100); const m1 = await rb.read('m1'); await refund(s, W, other.ch, 100); const m2 = await rb.read('m2');
  assert.equal(evaluate({ kind: 'stripe.refund.none-outside' }, windowOf(m0, m1)).status, 'pass');
  assert.equal(evaluate({ kind: 'stripe.refund.none-outside' }, windowOf(m1, m2)).status, 'fail');
  const failed = reseal(m2, r => { r.outside = r.outside.map(x => (x.amount === 100 ? { ...x, status: 'failed' } : x)); });
  assert.equal(evaluate({ kind: 'stripe.refund.none-outside' }, windowOf(copyOf(m1), failed, { mode: 'sealed-file' })).status, 'pass');
});

test('verdict: assertions and marks are checked before they are read', async t => {
  const w = { coverage: 'complete', reasons: [], added: [], outsideAdded: [], observed: [C1.id], priorMoving: {} };
  assert.throws(() => evaluate({ kind: 'effect.count' }, w), /Unknown assertion/);
  assert.throws(() => evaluate({ kind: 'stripe.refund.none', charge: C1.id, extra: 1 }, w), /takes exactly/);
  assert.throws(() => evaluate({ kind: 'stripe.refund.count', charge: 'A-1008', expected: 1 }, w), /ch_ id/);
  const { a, rb } = await scene(t);
  const m0 = await rb.read('m0'), m1 = await rb.read('m1');
  assert.throws(() => judge({ reads: { m0: m1, m1: m0 }, marks: ['m0', 'm1'], rows: [{ id: 'X', title: 'x', severity: 'critical', from: 'm0', to: 'm1', assert: { kind: 'stripe.refund.none', charge: a.ch } }] }), /labelled/);
});

// ---- the idempotency case: one key across the retry is one refund; a fresh key per attempt is two -------------------------------

// A client that gives up after timeoutMs and retries once: reusing its key (waiting on 409) or minting a new one.
async function refundWithRetry(s, W, charge, amount, { reuse }) {
  let key = `turn-${randomBytes(6).toString('hex')}`;
  const once = () => call(s.origin, '/v1/refunds', { method: 'POST', key: W, form: { charge, amount: String(amount) }, idem: key, timeoutMs: 150 });
  let r = await once();
  if (!r.timeout) return r;
  if (!reuse) key = `turn-${randomBytes(6).toString('hex')}`;
  for (let i = 0; i < 40; i++) { r = await once(); if (!(r.timeout || r.status === 409)) return r; await sleep(60); }
  return r;
}

for (const reuse of [true, false]) {
  test(`idempotency: a timed-out refund retried ${reuse ? 'under the same key is one refund' : 'under a new key is two refunds'} on the read-back`, async t => {
    const { s, W, a, rb } = await scene(t);
    s.slowFirstRefund(a.ch, 800);
    const m0 = await rb.read('m0');
    const r = await refundWithRetry(s, W, a.ch, 2000, { reuse });
    assert.equal(r.status, 200);
    if (reuse) assert.equal(r.headers['idempotent-replayed'], 'true');
    await sleep(800);
    const m1 = await rb.read('m1');
    const verdict = evaluate({ kind: 'stripe.refund.count', charge: a.ch, expected: 1 }, windowOf(m0, m1));
    assert.equal(verdict.status, reuse ? 'pass' : 'fail', verdict.basis);
    assert.equal(windowOf(m0, m1).added.length, reuse ? 1 : 2);
  });
}
