// Local synthetic provider and owned app only. Every connection and listener is
// on 127.0.0.1; destination names are routing labels, never resolved.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { Socket, Server } from 'node:net';
import { setTimeout as wait } from 'node:timers/promises';
import { createPaymentsDouble, evaluateRefundCount, PAYMENTS_WINDOW_SCHEMA } from './payments-double.mjs';
import { evaluateEffectAssertion, validateWindow } from './events.mjs';
import { onFreePorts } from './fixtures/free-port.mjs';

const connections = [], listeners = [];
const connect = Socket.prototype.connect, listen = Server.prototype.listen;
Socket.prototype.connect = function (...args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  connections.push(first && typeof first === 'object' ? first.host : args[1]);
  return connect.apply(this, args);
};
Server.prototype.listen = function (...args) {
  listeners.push(typeof args[0] === 'object' ? args[0].host : args[1]);
  return listen.apply(this, args);
};

const PAY = 'api.payments.test', WITNESS = 'witness.scopehaven.invalid';
const CHARGE = 'ch_order_1', OTHER_CHARGE = 'ch_order_2';
const ORIGINAL = 'pm_card_on_file', NEW_CARD = 'pm_new_destination';
const config = port => ({ port, routing: 'base-url', destinations: [{ host: PAY }], routes: [{ prefix: '/pay/', host: PAY }, { prefix: '/w/', host: WITNESS }],
  witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 0, quietMs: 100 });
async function double(t, extra = {}) {
  return onFreePorts(1, async port => {
    const o = createPaymentsDouble({ instanceId: 'payments-effects-test', provider: { host: PAY, seed: [CHARGE, OTHER_CHARGE].map(id => ({ id, paymentMethod: ORIGINAL, amount: 2000, currency: 'cad' })) }, ...config(port), ...extra });
    await o.start(); t.after(() => o.stop()); return o;
  });
}
function send(o, { path = '/pay/v1/refunds', body, method = body === undefined ? 'GET' : 'POST', headers = {}, key, discardResponse = false } = {}) {
  return new Promise((resolve, reject) => {
    const text = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body);
    const req = request({ host: '127.0.0.1', port: o.port, path, method, headers: { 'Content-Type': 'application/json', ...headers, ...(key ? { 'Idempotency-Key': key } : {}) } }, res => {
      if (discardResponse) { res.destroy(); return resolve({ status: res.statusCode, json: null }); }
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString() || 'null') }));
    });
    req.on('error', reject); req.end(text);
  });
}
const witness = (o, from, nonce = from.witnessNonce) => send(o, { path: `/w/?scopehaven_witness=${encodeURIComponent(nonce)}` });
async function window(o, between = async () => {}, { witnesses = 1, afterWitness } = {}) {
  const from = await o.mark(); await between(); o.markWitnessRequest(from);
  for (let i = 0; i < witnesses; i++) await witness(o, from);
  if (afterWitness) await afterWitness();
  return o.collectPayments(from, await o.mark());
}
const count = (bundle, expected, charge = CHARGE) => evaluateRefundCount({ kind: 'payment.refund.count', charge, expected }, bundle);
const attemptsCount = (bundle, expected) => evaluateEffectAssertion({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'refund original-method' }, expected }, [bundle.attempts]);
const forbidden = bundle => evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'refund new-destination' } }, [bundle.attempts]);
function deeplyFrozen(value) {
  if (value !== null && typeof value === 'object') {
    assert.ok(Object.isFrozen(value)); for (const child of Object.values(value)) deeplyFrozen(child);
  }
}

test('payments effects: one send commits one privacy-safe, immutable refund receipt', async t => {
  const o = await double(t);
  let reply;
  const bundle = await window(o, async () => { reply = await send(o, { body: { charge: CHARGE, amount: 400 }, key: 'private-refund-key' }); });
  assert.equal(bundle.schema, PAYMENTS_WINDOW_SCHEMA);
  assert.deepEqual([bundle.coverage, bundle.reason, bundle.scope.evidence], ['complete', null, 'authoritative']);
  assert.equal(bundle.observer.instanceId, o.instanceId);
  assert.equal(bundle.window.from.epoch, bundle.window.to.epoch);
  assert.equal(validateWindow(bundle.attempts), bundle.attempts);
  assert.equal(count(bundle, 1).verdict, 'pass');
  assert.equal(count(bundle, 0, OTHER_CHARGE).verdict, 'pass', 'charge matching is exact');
  assert.equal(bundle.refunds.length, 1);
  const refund = bundle.refunds[0];
  assert.deepEqual([refund.seq, refund.id, refund.charge, refund.amount, refund.currency, refund.toOriginalMethod], [bundle.attempts.events[0].seq, reply.json.id, CHARGE, 400, 'cad', true]);
  assert.equal(refund.destination, o.digestOf(ORIGINAL));
  assert.match(refund.idempotency, /^[a-f0-9]{64}$/);
  for (const raw of [ORIGINAL, NEW_CARD, 'private-refund-key']) assert.equal(JSON.stringify(bundle).includes(raw), false);
  deeplyFrozen(bundle);
  assert.throws(() => { refund.amount = 900; }, TypeError);
  assert.throws(() => { bundle.refunds.push(refund); }, TypeError);
  assert.throws(() => { bundle.attempts.events[0].resource = 'read'; }, TypeError);
});

// A refund count matches its charge id exactly. Two seeded charges whose ids are a prefix of one another are
// separate charges: a refund on ch_order_10 is never counted for ch_order_1.
test('payments effects: a refund count matches the charge id exactly, never by prefix', async t => {
  const SHORT = 'ch_order_1', LONG = 'ch_order_10';
  const o = await double(t, { provider: { host: PAY, seed: [SHORT, LONG].map(id => ({ id, paymentMethod: ORIGINAL, amount: 2000, currency: 'cad' })) } });
  const bundle = await window(o, async () => { assert.equal((await send(o, { body: { charge: LONG, amount: 400 }, key: 'refund-long-charge' })).status, 200); });
  assert.deepEqual(bundle.refunds.map(refund => refund.charge), [LONG]);
  assert.deepEqual([count(bundle, 0, SHORT).verdict, count(bundle, 0, SHORT).matched], ['pass', 0], 'ch_order_1 is not a prefix match for ch_order_10');
  assert.deepEqual([count(bundle, 1, SHORT).verdict, count(bundle, 1, LONG).verdict], ['fail', 'pass']);
});

test('payments effects: same-key retry is two sends and one refund; different keys create two refunds', async t => {
  const o = await double(t), replies = [];
  const replay = await window(o, async () => {
    for (let i = 0; i < 2; i++) replies.push(await send(o, { body: { charge: CHARGE, amount: 400 }, key: 'same-key' }));
  });
  assert.equal(replies[0].json.id, replies[1].json.id);
  assert.equal(count(replay, 1).verdict, 'pass');
  assert.equal(attemptsCount(replay, 1).verdict, 'fail');
  assert.equal(attemptsCount(replay, 2).verdict, 'pass');
  assert.equal(replay.attempts.events[0].correlation.requestId, replay.attempts.events[1].correlation.requestId);
  const duplicate = await window(o, async () => {
    for (const key of ['different-key-1', 'different-key-2']) await send(o, { body: { charge: CHARGE, amount: 400 }, key });
  });
  assert.deepEqual([count(duplicate, 1).verdict, count(duplicate, 1).matched, count(duplicate, 2).verdict], ['fail', 2, 'pass']);
  assert.notEqual(duplicate.refunds[0].id, duplicate.refunds[1].id);
});

test('payments effects: a response discarded after commit can be retried without another refund', async t => {
  const o = await double(t);
  let retry;
  const bundle = await window(o, async () => {
    const lost = await send(o, { body: { charge: CHARGE, amount: 400 }, key: 'lost-response', discardResponse: true });
    assert.deepEqual([lost.status, lost.json], [200, null], 'destroy the response without reading the committed refund object');
    retry = await send(o, { body: { charge: CHARGE, amount: 400 }, key: 'lost-response' });
  });
  assert.equal(count(bundle, 1).verdict, 'pass');
  assert.equal(attemptsCount(bundle, 2).verdict, 'pass');
  assert.equal(bundle.refunds[0].id, retry.json.id);
  assert.equal(o.providerLedger().refunds.length, 1);
});

test('payments effects: duplicate sends without an idempotency key create two refunds', async t => {
  const o = await double(t);
  const bundle = await window(o, async () => {
    for (let i = 0; i < 2; i++) await send(o, { body: { charge: CHARGE, amount: 400 } });
  });
  assert.equal(count(bundle, 1).verdict, 'fail');
  assert.equal(count(bundle, 2).verdict, 'pass');
  assert.equal(attemptsCount(bundle, 2).verdict, 'pass');
  assert.ok(bundle.refunds.every(refund => refund.idempotency === null));
  assert.notEqual(bundle.refunds[0].id, bundle.refunds[1].id);
});

test('payments effects: changed-body key reuse preserves the forbidden attempt without another refund', async t => {
  const o = await double(t);
  const bundle = await window(o, async () => {
    await send(o, { body: { charge: CHARGE, amount: 400 }, key: 'reused-key' });
    const rejected = await send(o, { body: { charge: CHARGE, amount: 500, destination: NEW_CARD }, key: 'reused-key' });
    assert.deepEqual([rejected.status, rejected.json.error.type], [400, 'idempotency_error']);
  });
  assert.equal(count(bundle, 1).verdict, 'pass');
  assert.equal(bundle.attempts.events.length, 2);
  assert.equal(forbidden(bundle).verdict, 'fail');
  assert.equal(bundle.refunds[0].toOriginalMethod, true);
});

test('payments effects: a refused forbidden refund has zero commits and remains a committed send attempt', async t => {
  const o = await double(t);
  const bundle = await window(o, async () => {
    assert.equal((await send(o, { body: { charge: CHARGE, amount: 2500, destination: NEW_CARD } })).status, 400);
  });
  assert.equal(count(bundle, 0).verdict, 'pass');
  assert.equal(count(bundle, 1).verdict, 'fail');
  assert.equal(forbidden(bundle).verdict, 'fail');
  assert.equal(bundle.attempts.events[0].outcome, 'committed');
  assert.equal(o.providerLedger().refunds.length, 0);
});

test('payments effects: separate windows exclude old refunds, including an old-key replay', async t => {
  const o = await double(t);
  await send(o, { body: { charge: CHARGE, amount: 300 }, key: 'before-window' });
  const first = await window(o, async () => {
    await send(o, { body: { charge: CHARGE, amount: 300 }, key: 'window-one' });
    await send(o, { body: { charge: OTHER_CHARGE, amount: 300 } });
  });
  assert.equal(count(first, 1).verdict, 'pass');
  assert.equal(count(first, 1, OTHER_CHARGE).verdict, 'pass');
  const second = await window(o, async () => {
    await send(o, { body: { charge: CHARGE, amount: 300 }, key: 'window-one' });
    await send(o, { body: { charge: CHARGE, amount: 300 }, key: 'before-window' });
  });
  assert.deepEqual([count(second, 0).verdict, second.refunds.length, second.attempts.events.length], ['pass', 0, 2]);
  assert.equal(count(await window(o), 0).verdict, 'pass');
  assert.equal(first.refunds.length, 2, 'later provider changes cannot change an earlier bundle');
});

test('payments effects: witness gaps, unknown requests and post-witness sends are inconclusive', async t => {
  const o = await double(t);
  const missing = await window(o, async () => {}, { witnesses: 0 });
  const duplicate = await window(o, async () => {}, { witnesses: 2 });
  const foreign = await window(o, async () => { await witness(o, { witnessNonce: 'foreign-window' }); });
  const unclassified = await window(o, async () => { await send(o, { path: '/pay/v1/transfers', body: { amount: 1, destination: NEW_CARD } }); });
  const late = await window(o, async () => {}, { afterWitness: async () => { await send(o, { body: { charge: CHARGE, amount: 300 } }); } });
  for (const [bundle, reason] of [[missing, /witness-not-received/], [duplicate, /duplicate-witness/], [foreign, /foreign-witness/], [unclassified, /unclassified-request/], [late, /request-after-witness-request/]]) {
    assert.equal(bundle.coverage, 'partial'); assert.match(bundle.reason, reason);
    assert.equal(count(bundle, 0).verdict, 'inconclusive');
    assert.equal(count(bundle, 1).verdict, 'inconclusive');
  }
  assert.equal(late.refunds.length, 0, 'post-witness records are not attributed to the check');
  assert.equal(o.providerLedger().refunds.length, 1, 'the provider nevertheless received that late refund');
});

test('payments effects: repeating the witness marker cannot admit a send after the first cutoff', async t => {
  const o = await double(t), from = await o.mark();
  o.markWitnessRequest(from);
  await send(o, { body: { charge: CHARGE, amount: 300 } });
  o.markWitnessRequest(from); await witness(o, from);
  const bundle = await o.collectPayments(from, await o.mark());
  assert.equal(count(bundle, 0).verdict, 'inconclusive');
  assert.match(bundle.reason, /request-after-witness-request/);
  assert.equal(bundle.refunds.length, 0);
});

test('payments effects: an actual matching witness without a registered request cutoff is inconclusive', async t => {
  const o = await double(t), from = await o.mark();
  await send(o, { body: { charge: CHARGE, amount: 300 } });
  await witness(o, from);
  const bundle = await o.collectPayments(from, await o.mark());
  assert.equal(bundle.coverage, 'partial');
  assert.match(bundle.reason, /payments-witness-request-not-marked/);
  assert.equal(count(bundle, 1).verdict, 'inconclusive');
  assert.equal(count(bundle, 0).verdict, 'inconclusive');
});

test('payments effects: evicted request records cannot prove a refund count', async t => {
  const o = await double(t, { retainedRequests: 1 });
  const bundle = await window(o, async () => { await send(o, { body: { charge: CHARGE, amount: 300 } }); });
  assert.deepEqual([bundle.coverage, bundle.reason], ['failed', 'payments-records-evicted']);
  assert.equal(count(bundle, 0).verdict, 'inconclusive');
  assert.equal(count(bundle, 1).verdict, 'inconclusive');
  assert.equal(o.providerLedger().refunds.length, 1);
});

test('payments effects: concurrent forged legacy collection cannot erase the late-send cutoff', async t => {
  const o = await double(t), from = await o.mark();
  o.markWitnessRequest(from);
  await send(o, { body: { charge: CHARGE, amount: 300 } });
  await witness(o, from);
  const to = await o.mark(), pending = o.collectPayments(from, to);
  const forgedLegacy = await o.collect({ ...from }, { ...to, at: Date.now() - 1000 });
  assert.deepEqual(forgedLegacy, { events: [], coverage: 'failed', reason: 'payments-marks-invalid-or-reused' });
  const bundle = await pending;
  assert.equal(bundle.coverage, 'partial');
  assert.match(bundle.reason, /request-after-witness-request/);
  assert.equal(bundle.refunds.length, 0);
  assert.equal(count(bundle, 1).verdict, 'inconclusive');
});

test('payments effects: stopped listeners and presence-only routes cannot decide a count', async t => {
  const o = await double(t), from = await o.mark();
  await o.stop();
  const failed = await o.collectPayments(from, await o.mark());
  assert.equal(failed.coverage, 'failed'); assert.equal(count(failed, 0).verdict, 'inconclusive');
  const loose = await double(t, { routing: undefined, routes: undefined, witness: undefined });
  const start = await loose.mark();
  await send(loose, { path: `http://${PAY}/v1/refunds`, headers: { Host: PAY }, body: { charge: CHARGE, amount: 300 } });
  const presence = await loose.collectPayments(start, await loose.mark());
  assert.equal(presence.coverage, 'complete'); assert.equal(presence.scope.evidence, 'presence-only');
  assert.equal(presence.refunds.length, 1);
  assert.equal(count(presence, 1).verdict, 'inconclusive');
});

test('payments effects: copied, edited, foreign, reversed and reused marks are refused', async t => {
  const o = await double(t), other = await double(t);
  const reject = (from, to) => assert.rejects(o.collectPayments(from, to), /original, ordered, unused marks/);
  const from = await o.mark(), to = await o.mark();
  await reject({ ...from }, to);
  await reject(from, { ...to });
  await reject(await other.mark(), to);
  await reject(from, await other.mark());
  await reject(to, from); await reject(from, from);
  const altered = await o.mark(); altered.seq = -1;
  await reject(altered, await o.mark());
  const extended = await o.mark(); extended.extra = true;
  await reject(extended, await o.mark());
  const editedEnd = await o.mark(); editedEnd.witnessNonce = 'edited';
  await reject(from, editedEnd);
  assert.throws(() => o.markWitnessRequest({ ...from }), /original, unused mark/);
  o.markWitnessRequest(from); await witness(o, from);
  await o.collectPayments(from, to);
  await reject(from, to);
  const legacyFrom = await o.mark(); o.markWitnessRequest(legacyFrom); await witness(o, legacyFrom);
  const legacyTo = await o.mark(), legacy = await o.collect(legacyFrom, legacyTo);
  assert.deepEqual(Object.keys(legacy).sort(), ['coverage', 'events', 'reason']);
  await reject(legacyFrom, legacyTo);
  const concurrentFrom = await o.mark(); o.markWitnessRequest(concurrentFrom); await witness(o, concurrentFrom);
  const concurrentTo = await o.mark();
  const results = await Promise.allSettled([o.collectPayments(concurrentFrom, concurrentTo), o.collectPayments(concurrentFrom, concurrentTo)]);
  assert.deepEqual(results.map(r => r.status), ['fulfilled', 'rejected']);
  assert.equal((await o.collect(concurrentFrom, concurrentTo)).coverage, 'failed');
  const mixedFrom = await o.mark(); o.markWitnessRequest(mixedFrom); await witness(o, mixedFrom);
  const mixedTo = await o.mark(), pending = o.collectPayments(mixedFrom, mixedTo);
  assert.deepEqual(await o.collect(mixedFrom, mixedTo), { events: [], coverage: 'failed', reason: 'payments-marks-invalid-or-reused' });
  assert.equal((await o.collect({ ...mixedFrom }, { ...mixedTo })).coverage, 'failed');
  assert.equal(count(await pending, 0).verdict, 'pass', 'legacy calls cannot consume an active payments cutoff');
});

test('payments effects: fabricated or copied bundles and unsupported assertions cannot decide a count', async t => {
  const o = await double(t), bundle = await window(o);
  for (const fake of [null, {}, Object.freeze({ ...bundle }), JSON.parse(JSON.stringify(bundle)), { ...bundle, refunds: [] }]) {
    assert.equal(count(fake, 0).verdict, 'inconclusive');
  }
  const valid = { kind: 'payment.refund.count', charge: CHARGE, expected: 0 };
  for (const assertion of [{ ...valid, kind: 'effect.count' }, { ...valid, charge: { prefix: 'ch_' } }, { ...valid, charge: '' },
    { ...valid, expected: -1 }, { ...valid, expected: 0.5 }, { ...valid, expected: Number.MAX_SAFE_INTEGER + 1 }, { ...valid, expected: '0' },
    { ...valid, select: {} }, { ...valid, [Symbol('extra')]: true }, { kind: valid.kind, charge: CHARGE }]) {
    assert.throws(() => evaluateRefundCount(assertion, bundle), /A refund count is/);
  }
  const accessor = { ...valid }; Object.defineProperty(accessor, 'charge', { get() { throw new Error('Do not invoke assertion getters.'); } });
  assert.throws(() => evaluateRefundCount(accessor, bundle), /A refund count is/);
});

test('owned loopback refunds app: declared post-response settle and payment collector accept a correct retry', async t => {
  const o = await double(t);
  const app = await onFreePorts(1, async port => {
    const server = createServer((req, res) => {
      req.resume(); req.on('end', async () => {
        try {
          const url = new URL(req.url, 'http://127.0.0.1');
          if (req.method === 'POST' && url.pathname === '/refund') {
            for (let i = 0; i < 2; i++) await send(o, { body: { charge: CHARGE, amount: 400 }, key: 'owned-app-refund' });
          } else if (url.pathname === '/ping') await witness(o, { witnessNonce: url.searchParams.get('scopehaven_witness') });
          else { res.writeHead(404); return res.end('null'); }
          res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"ok":true}');
        } catch { res.writeHead(500); res.end('null'); }
      });
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ port, host: '127.0.0.1' }, resolve); });
    t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
    return { port, postResponseSettleMs: 250 };
  });
  const from = await o.mark();
  assert.equal((await send(app, { path: '/refund', body: {} })).status, 200);
  await wait(app.postResponseSettleMs);
  o.markWitnessRequest(from);
  assert.equal((await send(app, { path: `/ping?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` })).status, 200);
  const bundle = await o.collectPayments(from, await o.mark());
  assert.equal(count(bundle, 1).verdict, 'pass');
  assert.equal(attemptsCount(bundle, 2).verdict, 'pass');
  assert.equal(forbidden(bundle).verdict, 'pass');
  assert.equal(o.providerLedger().refunds.length, 1);
});

test('payments effects: all sockets and listeners in these tests use loopback', () => {
  assert.ok(connections.length > 0 && listeners.length > 0);
  assert.deepEqual([...new Set(connections)], ['127.0.0.1']);
  // The payments double holds its port on both loopback addresses: 127.0.0.1 and [::1].
  assert.deepEqual([...new Set(listeners)].sort(), ['127.0.0.1', '::1']);
});
