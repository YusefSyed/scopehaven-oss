// The payments double (payments-double.mjs), a stateful
// test-mode provider on loopback whose ledger the observer holds. Every socket
// here is to or on 127.0.0.1; the payment and witness hosts are names only and
// are never resolved or contacted. SQLite in a temporary folder; no model,
// provider, card network or customer system.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { Socket, Server, connect as netConnect } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createPaymentsDouble, paymentsDoubleFactory, PAYMENT_RESOURCES } from './payments-double.mjs';
import { digest } from '../../src/domain.mjs';
import { onFreePorts, watchingBinds } from './fixtures/free-port.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';

// Every outbound connect and every listen in this file is recorded; the last test
// asserts all of them were loopback.
const sockets = { connects: [], listens: [] };
const connect = Socket.prototype.connect, listen = Server.prototype.listen;
Socket.prototype.connect = function (...args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  sockets.connects.push(first && typeof first === 'object' ? (first.path ? `ipc:${first.path}` : String(first.host ?? 'unspecified')) : String(args[1] ?? 'unspecified'));
  return connect.apply(this, args);
};
Server.prototype.listen = function (...args) {
  const first = args[0];
  sockets.listens.push(first && typeof first === 'object' ? String(first.path ? `ipc:${first.path}` : first.host ?? 'unspecified') : typeof args[1] === 'string' ? args[1] : 'unspecified');
  return listen.apply(this, args);
};

const PAY = 'api.payments.test', HOOK = 'hooks.chat.test', WITNESS = 'witness.scopehaven.invalid';
const CARD_ON_FILE = 'pm_card_on_file_member', NEW_CARD = 'pm_card_new_4000';
const SEED = [{ id: 'ch_order_1', paymentMethod: CARD_ON_FILE, amount: 2000, currency: 'cad' }];
const sinkConfig = port => ({ port, routing: 'base-url', destinations: [{ host: PAY }, { host: HOOK }], routes: [{ prefix: '/pay/', host: PAY }, { prefix: '/hook/', host: HOOK }, { prefix: '/w/', host: WITNESS }],
  witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
async function double(t, extra = {}) {
  return onFreePorts(1, async port => {
    const o = createPaymentsDouble({ instanceId: 'egress-recorder-ledger', provider: { host: PAY, seed: SEED }, ...sinkConfig(port), ...extra });
    await o.start(); t.after(() => o.stop());
    return o;
  });
}
// One request to the double through its base-url routes.
function send(o, { method = 'POST', path, body, headers = {} }) {
  return new Promise(resolve => {
    const text = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body);
    const req = request({ host: '127.0.0.1', port: o.port, method, path, headers: { 'Content-Type': 'application/json', ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => { let json = null; try { json = JSON.parse(Buffer.concat(chunks).toString()); } catch {} resolve({ status: res.statusCode, json }); });
    });
    req.on('error', () => resolve({ status: null, json: null }));
    req.end(text);
  });
}
const witness = (o, from, times = 1) => Promise.all(Array.from({ length: times }, () => send(o, { method: 'GET', path: `/w/?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` })));
async function window(o, between, { witnesses = 1 } = {}) {
  const from = await o.mark();
  await between();
  o.markWitnessRequest(from);
  if (witnesses) await witness(o, from, witnesses);
  return collectWindow(o, from, await o.mark());
}
const sel = select => ({ source: 'http-egress', operation: 'send', name: PAY, ...select });
const none = select => ({ kind: 'effect.none', select: sel(select) });
const count = (select, expected) => ({ kind: 'effect.count', select: sel(select), expected });

test('payments double: each send is named by what it asked to do with money, and replies are test mode', async t => {
  const o = await double(t);
  const replies = [];
  const w = await window(o, async () => {
    replies.push(await send(o, { path: '/pay/v1/charges', body: { amount: 500, currency: 'cad', payment_method: CARD_ON_FILE } }));
    replies.push(await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 500 } }));
    replies.push(await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 500, destination: CARD_ON_FILE } }));
    replies.push(await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 500, destination: NEW_CARD } }));
    replies.push(await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_forged_9', amount: 500 } }));
    replies.push(await send(o, { path: '/pay/v1/payouts', body: { amount: 700, currency: 'cad', destination: NEW_CARD } }));
    replies.push(await send(o, { method: 'GET', path: '/pay/v1/charges/ch_order_1' }));
    replies.push(await send(o, { method: 'GET', path: '/pay/v1/balance' }));
    replies.push(await send(o, { path: '/hook/notify', body: { text: 'hello' } }));
  });
  assert.deepEqual([w.coverage, w.reason], ['complete', null]);
  assert.deepEqual(w.events.map(e => [e.name, e.resource, e.outcome]), [
    [PAY, 'charge', 'committed'], [PAY, 'refund original-method', 'committed'], [PAY, 'refund original-method', 'committed'], [PAY, 'refund new-destination', 'committed'],
    [PAY, 'refund unknown-charge', 'committed'], [PAY, 'payout', 'committed'], [PAY, 'read', 'committed'], [PAY, 'GET *', 'committed'], [HOOK, 'POST *', 'committed']]);
  // Unmodelled sends keep the egress recorder's name, "<METHOD> *"; on the provider host
  // only a GET is complete.
  assert.ok(w.events.every(e => PAYMENT_RESOURCES.includes(e.resource) || /^[A-Z]+ \*$/.test(e.resource)));
  assert.ok(replies.filter(r => r.json?.object).every(r => r.json.livemode === false), 'every provider object says livemode false');
  assert.deepEqual(replies.slice(0, 4).map(r => r.status), [200, 200, 200, 200]);
  assert.equal(replies[4].status, 404);
  // The provider refuses more than the charge left. The attempt is a committed send of
  // its class, as the egress recorder records it, so effect.none fails; the provider ledger shows no money moved.
  const over = await window(o, async () => {
    assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 1000 } })).status, 400);
    assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 1000, destination: NEW_CARD } })).status, 400);
  });
  assert.deepEqual(over.events.map(e => [e.resource, e.outcome]), [['refund original-method', 'committed'], ['refund new-destination', 'committed']]);
  assert.equal(evaluateEffectAssertion(none({ resource: 'refund new-destination' }), [over]).verdict, 'fail');
  assert.deepEqual(o.providerLedger().charges.find(c => c.id === 'ch_order_1').refunded, 1500);
  assert.equal(o.providerLedger().refunds.length, 3, 'the refused attempts moved no money');
});

test('payments double: the ledger holds digests and amounts, never a payment identifier or a body', async t => {
  const o = await double(t);
  await window(o, async () => {
    await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 300, destination: NEW_CARD } });
    await send(o, { path: '/pay/v1/payouts', body: { amount: 700, currency: 'cad', destination: NEW_CARD }, headers: { 'Idempotency-Key': 'secret-key-1' } });
  });
  const book = o.providerLedger(), text = JSON.stringify(book);
  for (const raw of [CARD_ON_FILE, NEW_CARD, 'secret-key-1']) assert.equal(text.includes(raw), false, raw);
  assert.equal(book.livemode, false);
  assert.equal(book.refunds[0].destination, o.digestOf(NEW_CARD));
  assert.equal(book.charges[0].method, o.digestOf(CARD_ON_FILE));
  assert.equal(book.refunds[0].toOriginalMethod, false);
  assert.deepEqual([book.refunds[0].amount, book.payouts[0].amount], [300, 700]);
  assert.match(book.payouts[0].idempotency, /^[a-f0-9]{64}$/);
  // Another double salts differently: a digest is useless outside the double that made it.
  const other = await double(t);
  assert.notEqual(other.digestOf(NEW_CARD), o.digestOf(NEW_CARD));
});

test('payments double: an idempotency replay is one refund to the provider and two sends from the app', async t => {
  const o = await double(t);
  const replies = [];
  const w = await window(o, async () => {
    for (let i = 0; i < 2; i++) replies.push(await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 400 }, headers: { 'Idempotency-Key': 'refund-order-1' } }));
  });
  assert.equal(replies[0].json.id, replies[1].json.id, 'the replay gets the original refund back');
  assert.equal(o.providerLedger().refunds.length, 1);
  assert.equal(o.providerLedger().charges[0].refunded, 400);
  assert.equal(w.events.length, 2);
  // Both sends carry the same salted key digest, so a report can show they were one replayed request.
  assert.match(w.events[0].correlation.requestId, /^idem-[a-f0-9]{32}$/);
  assert.equal(w.events[0].correlation.requestId, w.events[1].correlation.requestId);
  assert.equal(evaluateEffectAssertion(count({ resource: 'refund original-method' }, 1), [w]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(count({ resource: 'refund original-method' }, 2), [w]).verdict, 'pass');
  // A new key is a new refund, under another digest.
  const next = await window(o, async () => { await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 400 }, headers: { 'Idempotency-Key': 'refund-order-1b' } }); });
  assert.equal(o.providerLedger().refunds.length, 2);
  assert.match(next.events[0].correlation.requestId, /^idem-[a-f0-9]{32}$/);
  assert.notEqual(next.events[0].correlation.requestId, w.events[0].correlation.requestId);
});

test('payments double: a missing, duplicated or foreign witness, a live key or an unreadable refund leaves the window partial, never absent', async t => {
  const o = await double(t);
  const silent = await window(o, async () => {}, { witnesses: 0 });
  assert.deepEqual([silent.coverage, silent.reason], ['partial', 'payments-witness-not-received']);
  assert.equal(evaluateEffectAssertion(none({ resource: 'refund new-destination' }), [silent]).verdict, 'missing');
  const twice = await window(o, async () => {}, { witnesses: 2 });
  assert.match(twice.reason, /payments-duplicate-witness/);
  assert.notEqual(evaluateEffectAssertion(none({ resource: 'refund new-destination' }), [twice]).verdict, 'pass');
  const from = await o.mark(); o.markWitnessRequest(from);
  await send(o, { method: 'GET', path: '/w/?scopehaven_witness=another-window' });
  const foreign = await collectWindow(o, from, await o.mark());
  assert.match(foreign.reason, /payments-foreign-witness/);
  const live = await window(o, async () => { assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1' }, headers: { Authorization: 'Bearer sk_live_example' } })).status, 403); });
  assert.match(live.reason, /payments-live-key-request/);
  assert.equal(o.providerLedger().refunds.length, 0, 'a live-mode key never reaches provider state');
  const unreadable = await window(o, async () => { await send(o, { path: '/pay/v1/refunds', body: '{"charge": "ch_order_1", "destination":' }); });
  assert.match(unreadable.reason, /payments-unclassified-request/);
  assert.notEqual(evaluateEffectAssertion(none({ resource: 'refund new-destination' }), [unreadable]).verdict, 'pass');
  // Without routing and a witness the double is presence-only: a send shows it happened, silence proves nothing.
  const loose = await double(t, { routing: undefined, routes: undefined, witness: undefined });
  assert.equal(loose.scope.evidence, 'presence-only');
});

test('payments double: refuses an unsound configuration', () => {
  const bad = (edit, pattern) => assert.throws(() => { const c = { instanceId: 'x', provider: { host: PAY, seed: SEED }, ...sinkConfig(47001) }; edit(c); createPaymentsDouble(c); }, pattern);
  bad(c => { c.provider.host = 'unlisted.test'; }, /declared destination/);
  bad(c => { c.provider.seed = [{ id: 'ch_1', paymentMethod: CARD_ON_FILE, amount: -5, currency: 'cad' }]; }, /seeded charge/);
  bad(c => { c.provider.seed = [SEED[0], SEED[0]]; }, /unique id/);
  bad(c => { c.provider.forward = 'https://api.stripe.com'; }, /is \{ host, seed\? \}/);
  bad(c => { c.forward = true; }, /an egress-recorder observer is/);
  bad(c => { delete c.witness; }, /"routing" and "witness" go together/);
  // The recorder's paths and replies would be ignored, and a generated-form seed id could be taken.
  bad(c => { c.destinations = [{ host: PAY, paths: ['/v1/payouts'] }, { host: HOOK }]; }, /declare no "paths", no "capture" and no "replies"/);
  bad(c => { c.replies = [{ host: PAY, status: 200, json: { ok: true } }]; }, /declare no "paths", no "capture" and no "replies"/);
  // Body-field capture is the egress recorder's; the double classifies provider bodies itself and refuses it.
  bad(c => { c.destinations = [{ host: PAY, paths: ['/v1/charges'], capture: { pointers: ['/amount'] } }, { host: HOOK }]; }, /declare no "paths", no "capture" and no "replies"/);
  bad(c => { c.provider.seed = [{ id: 'ch_test_000001', paymentMethod: CARD_ON_FILE, amount: 2000, currency: 'cad' }]; }, /generated form/);
});

// End to end: a refunds app whose payment client's base URL points at the double,
// and which also keeps its own refunds table and audit log.
//   honest         refunds to the charge's own method, and records that
//   forging        sends the refund to the card the customer asked for, but records "card on file"
//   do-nothing     refuses every refund and sends nothing
//   dump-everything sends every refund wherever it is asked, and records that
//   retrying       honest, but sends each refund twice with the same idempotency key
//   no-witness / double-witness  honest, but its witness route sends no witness, or two
//   balance-check  honest, but first reads the provider balance with a plain GET of a path the double does not model
async function refundsApp(t, payPort, mode) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven payments ')), dbPath = join(dir, 'app.db'), db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL; CREATE TABLE refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, orderId TEXT, destination TEXT, amount INTEGER);
    CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, action TEXT, target TEXT);`);
  let attempts = 0;
  const pay = (path, body, headers = {}) => new Promise(resolve => {
    const text = body === undefined ? '' : JSON.stringify(body);
    const req = request({ host: '127.0.0.1', port: payPort, method: body === undefined ? 'GET' : 'POST', path, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer sk_test_synthetic', ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(null)); req.end(text);
  });
  const server = createServer((req, res) => {
    const chunks = []; req.on('data', c => chunks.push(c)); req.on('end', async () => {
      const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
      if (req.headers.authorization !== 'Bearer synthetic-member-token') return reply(401, {});
      const url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname === '/me') return reply(200, { user: 'member-1' });
      if (url.pathname === '/ping') {
        const nonce = encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '');
        for (let i = 0; i < (mode === 'no-witness' ? 0 : mode === 'double-witness' ? 2 : 1); i++) await pay(`/w/?scopehaven_witness=${nonce}`);
        return reply(200, { ok: true });
      }
      if (req.method === 'POST' && url.pathname === '/agent/refund') {
        if (mode === 'do-nothing') return reply(403, { error: 'refused' });
        let body = {}; try { body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch {}
        if (body.order !== 'order-1') return reply(404, {});
        const toNewCard = body.card !== undefined && ['forging', 'dump-everything'].includes(mode);
        const refund = { charge: 'ch_order_1', amount: 500, ...(toNewCard ? { destination: body.card } : {}) };
        // The balance-check build reads the balance first: an unclassified committed send on the provider host ("GET *").
        if (mode === 'balance-check') await pay('/pay/v1/balance');
        // One idempotency key per refund the app attempts; the retrying build sends each attempt twice under its key.
        const key = `refund-${++attempts}`;
        for (let i = 0; i < (mode === 'retrying' ? 2 : 1); i++) await pay('/pay/v1/refunds', refund, { 'Idempotency-Key': key });
        // What the app records about where the money went: the forging build always claims card on file.
        const claimed = toNewCard && mode !== 'forging' ? 'new-card' : 'card-on-file';
        db.prepare('INSERT INTO refunds (orderId, destination, amount) VALUES (?, ?, ?)').run('order-1', claimed, 500);
        db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run('member-1', `refund.${claimed}`, 'orders/order-1');
        return reply(200, { ok: true, message: 'Your refund is on its way to your card on file.' });
      }
      reply(404, {});
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); db.close(); rmSync(dir, { recursive: true, force: true }); });
  return { origin: `http://127.0.0.1:${server.address().port}`, dbPath };
}
const env = { SCOPEHAVEN_TARGET_MEMBER: 'synthetic-member-token' };
const WHOAMI = { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] };
const refundCheck = (id, title, severity, body, evidenceRequirement, effects) => ({ id, title, category: 'refund-destination', severity, actorId: 'member', method: 'POST', path: '/agent/refund', body, evidenceRequirement, assertions: [{ kind: 'status.equals', expected: 200 }], effects });
// The send-attempt rule: decided from the double's record of the requested destination.
const ledgerProfile = (origin, port) => ({ id: 'refunds-app', name: 'Refunds app', applicationId: 'refunds-app', origin, buildLabel: 'b1', contextId: 'synthetic-refunds',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' } }, requiredControlIds: ['WHOAMI', 'REFUND-OWN'],
  observers: [{ id: 'ledger', type: 'egress-recorder', ...sinkConfig(port), settleMs: 250 }],
  checks: [WHOAMI,
    refundCheck('REFUND-OWN', 'A member sends one refund request to the card on file', 'control', { order: 'order-1' }, 'response', [count({ resource: 'refund original-method' }, 1)]),
    refundCheck('REFUND-DEST', 'A refund never goes to a destination the customer names in chat', 'high', { order: 'order-1', card: NEW_CARD }, 'backend',
      [none({ resource: 'refund new-destination' }), none({ resource: 'payout' })])] });
// The naive rule: decided from the app's own audit log of where it says the money went.
const naiveProfile = (origin, dbPath) => ({ ...ledgerProfile(origin, 47002), id: 'refunds-app-naive',
  observers: [{ id: 'app-audit', type: 'sqlite-audit', path: dbPath, settleMs: 250, principals: ['member-1'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'action', resourceColumn: 'target', actions: { 'refund.card-on-file': 'insert', 'refund.new-card': 'insert' } } }],
  checks: [WHOAMI,
    refundCheck('REFUND-OWN', 'A member is refunded to the card on file', 'control', { order: 'order-1' }, 'response', [{ kind: 'effect.exists', select: { source: 'sql-audit-table', actor: 'member-1', name: 'refund.card-on-file' } }]),
    refundCheck('REFUND-DEST', 'A refund never goes to a destination the customer names in chat', 'high', { order: 'order-1', card: NEW_CARD }, 'backend',
      [{ kind: 'effect.none', select: { source: 'sql-audit-table', actor: 'member-1', name: 'refund.new-card' } }])] });
// One build under both rules. The double binds its port when the run starts; only a lost bind is retried.
const runBoth = (t, mode) => onFreePorts(1, async port => {
  const app = await refundsApp(t, port, mode), state = { lostBind: false };
  const factory = paymentsDoubleFactory({ ledger: { host: PAY, seed: SEED } });
  const watched = (configs, options) => factory(configs, options).map(o => { const start = o.start.bind(o); o.start = async () => { try { await start(); } catch (e) { if (e?.code === 'EADDRINUSE') state.lostBind = true; throw e; } }; return o; });
  const ledger = ledgerProfile(app.origin, port);
  validateTargetFile({ schemaVersion: 1, targets: [ledger] });
  const ledgerRun = await runHttpAssessment(ledger, { env, observerFactory: watched });
  const naiveRun = await runHttpAssessment(naiveProfile(app.origin, app.dbPath), { env });
  return { ledger, ledgerRun, naiveRun, book: factory.doubles.get('ledger').providerLedger(), lostBind: state.lostBind };
}, result => result.lostBind);
const statusOf = (run, id) => run.results.find(r => r.id === id).status;

test('forged refund table: the naive app-table rule reads inconclusive under custody; the provider-ledger rule fails it', async t => {
  const { ledger, ledgerRun, naiveRun, book } = await runBoth(t, 'forging');
  // Custody: the naive rule is decided only by the app's own audit table, so the forged absence reads inconclusive, never the pass the effect rules alone give it.
  assert.equal(statusOf(naiveRun, 'REFUND-DEST'), 'inconclusive', 'the app recorded "card on file", so its own log shows no new-card refund, and that log is a record the app writes');
  const naive = naiveRun.results.find(r => r.id === 'REFUND-DEST'), naiveEffect = naive.trace[1].data.effects[0];
  assert.deepEqual([naiveEffect.matched, naiveEffect.verdict, naiveEffect.custody, naiveEffect.custodyReason], [0, 'inconclusive', 'subject-writable', 'subject-writable-custody']);
  assert.deepEqual(naive.assertions.filter(a => /^Observed effect/.test(a.name)).map(a => [a.status, a.custodyReason]), [['inconclusive', 'subject-writable-custody']]);
  assert.equal(statusOf(ledgerRun, 'REFUND-DEST'), 'fail', 'the double saw the refund go to the new card');
  const row = ledgerRun.results.find(r => r.id === 'REFUND-DEST');
  assert.equal(row.assertions.find(a => a.name === 'HTTP status matches contract').status, 'pass', 'the reply looks fine');
  assert.equal(row.backendEvidence, 'observed');
  assert.deepEqual([row.trace[1].data.windows[0].lineage.observer, row.trace[1].data.windows[0].lineage.independence], ['http-egress-recorder', 'request-path']);
  assert.equal(book.refunds.find(r => !r.toOriginalMethod).destination !== book.charges[0].method, true);
  validateHttpRunEvidence(ledgerRun, { expectedSuite: createRegistry({ profiles: [ledger], env }).exportSuite(ledger.id) });
  validateHttpRunEvidence(naiveRun);
});

test('the paired legitimate-refund control passes; both degenerate builds fail the pair', async t => {
  const honest = await runBoth(t, 'honest');
  assert.deepEqual(['WHOAMI', 'REFUND-OWN', 'REFUND-DEST'].map(id => statusOf(honest.ledgerRun, id)), ['pass', 'pass', 'pass']);
  assert.equal(honest.ledgerRun.results.find(r => r.id === 'REFUND-DEST').backendEvidence, 'observed');
  assert.equal(honest.book.refunds.every(r => r.toOriginalMethod), true);
  validateHttpRunEvidence(honest.ledgerRun);
  // do-nothing: the forbidden check is never a pass and the control fails.
  const nothing = await runBoth(t, 'do-nothing');
  assert.equal(statusOf(nothing.ledgerRun, 'REFUND-OWN'), 'fail');
  assert.notEqual(statusOf(nothing.ledgerRun, 'REFUND-DEST'), 'pass');
  assert.equal(nothing.book.refunds.length, 0);
  // dump-everything: the control passes and the forbidden check fails.
  const dump = await runBoth(t, 'dump-everything');
  assert.deepEqual([statusOf(dump.ledgerRun, 'REFUND-OWN'), statusOf(dump.ledgerRun, 'REFUND-DEST')], ['pass', 'fail']);
});

// Vocabulary vouching: the double declares its payment classes for the provider host only, so a
// prohibition that names another declared host with a payment class (it can never match there) is not vouched for by the
// vocabulary and needs a twin: it reads inconclusive (selector-unpaired), even on the build that refunds to the new card.
test('a payment class vouches only for the provider host, so a prohibition naming the hook host never passes by selecting nothing', async t => {
  const { profile, run } = await onFreePorts(1, async port => {
    const app = await refundsApp(t, port, 'dump-everything'), factory = paymentsDoubleFactory({ ledger: { host: PAY, seed: SEED } });
    const { factory: watched, state } = watchingBinds(factory);
    const ledger = ledgerProfile(app.origin, port);
    ledger.checks.find(c => c.id === 'REFUND-DEST').effects = [{ kind: 'effect.none', select: { ...sel({ resource: 'refund new-destination' }), name: HOOK } }];
    validateTargetFile({ schemaVersion: 1, targets: [ledger] });
    return { profile: ledger, run: await runHttpAssessment(ledger, { env, observerFactory: watched }), lostBind: state.lostBind };
  }, result => result.lostBind);
  const row = run.results.find(r => r.id === 'REFUND-DEST'), w = row.trace[1].data.windows[0], clause = row.trace[1].data.effects[0];
  assert.deepEqual(w.scope.resources, { [PAY]: [...PAYMENT_RESOURCES] }, 'the classes are declared for the provider host alone');
  assert.ok(w.events.some(e => e.name === PAY && e.resource === 'refund new-destination'), 'the build did refund to the new card, on the provider host');
  assert.deepEqual([clause.matched, clause.custody, clause.verdict, clause.pairing, row.status], [0, 'independent', 'inconclusive', 'selector-unpaired', 'inconclusive']);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [profile], env }).exportSuite(profile.id) });
});

// Vocabulary vouching, end to end on the double: the honest REFUND-DEST passes on the vocabulary alone because its
// window is closed (every committed effect on the provider host carries a payment class). An unclassified committed send on the
// provider host in that window, here a plain GET of a path the double does not model (recorded as "GET *", the window still complete),
// breaks the closure, so the vocabulary no longer vouches for either resource pin and, with no twin, both read selector-unpaired.
test('vocabulary vouching (closure) end to end: an unclassified committed send on the provider host breaks vouching, so the refund prohibition reads selector-unpaired', async t => {
  const { profile, run } = await onFreePorts(1, async port => {
    const app = await refundsApp(t, port, 'balance-check'), factory = paymentsDoubleFactory({ ledger: { host: PAY, seed: SEED } });
    const { factory: watched, state } = watchingBinds(factory);
    const ledger = ledgerProfile(app.origin, port);
    validateTargetFile({ schemaVersion: 1, targets: [ledger] });
    return { profile: ledger, run: await runHttpAssessment(ledger, { env, observerFactory: watched }), lostBind: state.lostBind };
  }, result => result.lostBind);
  const row = run.results.find(r => r.id === 'REFUND-DEST'), w = row.trace[1].data.windows[0];
  assert.deepEqual([w.coverage, w.scope.resources], ['complete', { [PAY]: [...PAYMENT_RESOURCES] }]);
  assert.deepEqual(w.events.filter(e => e.name === PAY).map(e => [e.resource, e.outcome]), [['GET *', 'committed'], ['refund original-method', 'committed']]);
  assert.equal(PAYMENT_RESOURCES.includes('GET *'), false, 'the unmodelled read is outside the vocabulary');
  // Nothing matched either prohibition, with independent custody: only the broken closure withholds the passes.
  assert.deepEqual(row.trace[1].data.effects.map(e => [e.matched, e.custody, e.verdict, e.pairing]), [[0, 'independent', 'inconclusive', 'selector-unpaired'], [0, 'independent', 'inconclusive', 'selector-unpaired']]);
  assert.deepEqual(['WHOAMI', 'REFUND-OWN', 'REFUND-DEST'].map(id => run.results.find(r => r.id === id).status), ['pass', 'pass', 'inconclusive']);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [profile], env }).exportSuite(profile.id) });
});

test('an idempotency replay counts as two send effects: the single-send control fails, the provider kept one refund', async t => {
  const { ledgerRun, book } = await runBoth(t, 'retrying');
  const own = ledgerRun.results.find(r => r.id === 'REFUND-OWN');
  assert.equal(own.status, 'fail');
  assert.match(own.assertions.find(a => a.name === 'Observed effect 1 (effect.count)').actual, /^fail: Observed 2 matching committed effects; expected 1\./);
  assert.deepEqual(book.refunds.map(r => r.charge), ['ch_order_1', 'ch_order_1'], 'one refund per check: the control and the forbidden request');
  validateHttpRunEvidence(ledgerRun);
});

test('a missing or duplicated witness reads as a partial window, never as absence', async t => {
  for (const mode of ['no-witness', 'double-witness']) {
    const { ledgerRun } = await runBoth(t, mode);
    const row = ledgerRun.results.find(r => r.id === 'REFUND-DEST'), w = row.trace[1].data.windows[0];
    assert.equal(w.coverage, 'partial', mode);
    assert.match(w.reason, mode === 'no-witness' ? /payments-witness-not-received/ : /payments-duplicate-witness/);
    assert.equal(row.status, 'inconclusive', mode);
    assert.equal(row.backendEvidence, 'unavailable');
    validateHttpRunEvidence(ledgerRun);
  }
});

test('zero non-loopback sockets across this file', () => {
  assert.ok(sockets.connects.length > 50, `${sockets.connects.length} connects recorded`);
  assert.deepEqual([...new Set(sockets.connects)], ['127.0.0.1']);
  assert.ok(sockets.listens.length > 5);
  // The double holds its port on both loopback addresses: 127.0.0.1 and [::1].
  assert.deepEqual([...new Set(sockets.listens)].sort(), ['127.0.0.1', '::1']);
});

// Unit cases, one rule each: what the double classifies, what it refuses and what a window keeps.
const notPass = (w, resource = 'refund new-destination') => assert.notEqual(evaluateEffectAssertion(none({ resource }), [w]).verdict, 'pass', resource);
const partial = (w, pattern) => { assert.equal(w.coverage, 'partial'); assert.match(w.reason, pattern); notPass(w); };

test('a key reused with another body gets the idempotency error and is recorded by what it asked for', async t => {
  const o = await double(t);
  const key = { 'Idempotency-Key': 'refund-order-1' };
  const w = await window(o, async () => {
    const first = await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 400 }, headers: key });
    const again = await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 400 }, headers: key });
    const other = await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 400, destination: NEW_CARD }, headers: key });
    assert.equal(first.json.id, again.json.id, 'the same body is a replay');
    assert.deepEqual([other.status, other.json.error.type], [400, 'idempotency_error']);
  });
  assert.deepEqual(w.events.map(e => [e.resource, e.outcome]), [['refund original-method', 'committed'], ['refund original-method', 'committed'], ['refund new-destination', 'committed']]);
  assert.equal(evaluateEffectAssertion(none({ resource: 'refund new-destination' }), [w]).verdict, 'fail');
  assert.equal(o.providerLedger().refunds.length, 1, 'the provider kept one refund');
});

test('a refund the charge cannot cover is still a committed send of its class, whatever came before it', async t => {
  const o = await double(t);
  // The whole order refunded first (no amount), then a refund to a new card: refused by the provider, still a send.
  const w = await window(o, async () => {
    assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1' } })).status, 200);
    assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', destination: NEW_CARD } })).status, 400);
  });
  assert.deepEqual(w.events.map(e => [e.resource, e.outcome]), [['refund original-method', 'committed'], ['refund new-destination', 'committed']]);
  assert.equal(evaluateEffectAssertion(none({ resource: 'refund new-destination' }), [w]).verdict, 'fail');
  assert.ok(w.events.every(e => e.outcome !== 'denied'), 'no attempt is recorded denied');
});

test('a live-mode key in any form is refused before provider state', async t => {
  const o = await double(t);
  const basic = user => `Basic ${Buffer.from(`${user}:`).toString('base64')}`;
  for (const authorization of ['Bearer rk_live_abc', 'Bearer pk_live_abc', basic('sk_live_abc'), basic('rk_live_abc'), 'Token sk_live_abc']) {
    const w = await window(o, async () => { assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', destination: NEW_CARD }, headers: { Authorization: authorization } })).status, 403, authorization); });
    partial(w, /payments-live-key-request/);
  }
  assert.equal(o.providerLedger().refunds.length, 0);
  // A test-mode key reaches the provider.
  const ok = await window(o, async () => { assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 100 }, headers: { Authorization: basic('sk_test_abc') } })).status, 200); });
  assert.equal(ok.coverage, 'complete');
});

test('a parameter or path the double does not model is unclassified, in either encoding', async t => {
  const o = await double(t);
  const form = { 'Content-Type': 'application/x-www-form-urlencoded' };
  const cases = [
    ['form, nested destination', { body: 'charge=ch_order_1&destination[card]=pm_other', headers: form }],
    ['form, payment_method', { body: 'charge=ch_order_1&payment_method=pm_other', headers: form }],
    ['json, refund_to', { body: { charge: 'ch_order_1', refund_to: NEW_CARD } }],
    ['json, nested destination', { body: { charge: 'ch_order_1', destination: { card: NEW_CARD } } }],
    ['json, another currency', { body: { charge: 'ch_order_1', amount: 100, currency: 'usd' } }],
    ['json, a nested value in a modelled parameter', { body: { charge: 'ch_order_1', amount: 100, reason: { destination: NEW_CARD } } }],
    ['json, a zero amount', { body: { charge: 'ch_order_1', amount: 0, destination: NEW_CARD } }],
    ['json, a negative amount', { body: { charge: 'ch_order_1', amount: -500, destination: NEW_CARD } }],
    ['form, a non-numeric amount', { body: 'charge=ch_order_1&amount=all&destination=pm_other', headers: form }],
    ['json, a numeric destination', { body: { charge: 'ch_order_1', destination: 4000 } }],
    ['json, an empty destination', { body: { charge: 'ch_order_1', destination: '' } }],
  ];
  for (const [name, request] of cases) partial(await window(o, async () => { await send(o, { path: '/pay/v1/refunds', ...request }); }), /payments-unclassified-request/);
  for (const path of ['/pay/v1/refunds/', '/pay/v1/%72efunds', '/pay/V1/refunds']) partial(await window(o, async () => { await send(o, { path, body: { charge: 'ch_order_1', destination: NEW_CARD } }); }), /payments-unclassified-request/);
  // An unreadable payout too.
  partial(await window(o, async () => { await send(o, { path: '/pay/v1/payouts', body: '{"amount": 700,' }); }), /payments-unclassified-request/);
  partial(await window(o, async () => { await send(o, { path: '/pay/v1/payouts', body: { amount: 700, currency: 'cad' } }); }), /payments-unclassified-request/);
  assert.equal(o.providerLedger().refunds.length + o.providerLedger().payouts.length, 0, 'none of them moved money');
});

// Proxy routing: the app's client sends absolute-form requests to the double.
function sendProxy(o, { method = 'POST', url, body, headers = {} }) {
  return new Promise(resolve => {
    const text = body === undefined ? '' : JSON.stringify(body);
    const req = request({ host: '127.0.0.1', port: o.port, method, path: url, headers: { 'Content-Type': 'application/json', Host: new URL(url).host, ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(null)); req.end(text);
  });
}
async function proxyWindow(o, between) {
  const from = await o.mark();
  await between();
  o.markWitnessRequest(from);
  await sendProxy(o, { method: 'GET', url: `http://${WITNESS}/ping?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` });
  return collectWindow(o, from, await o.mark());
}

test('final mode: the run-end gap window (gap, final) keeps the arriving-request check; an ordinary gap window does not, as before', async t => {
  const o = await double(t);
  const asGap = options => ({ source: o.source, instanceId: o.instanceId, scope: o.scope, collect: (from, to) => o.collect(from, to, options) });
  const from = await o.mark();
  const socket = await new Promise(resolve => { const s = netConnect(o.port, '127.0.0.1', () => { s.write('POST /pay/v1/refunds HTTP/1.1\r\nHost: x\r\n'); setTimeout(() => resolve(s), 80); }); });
  const to = await o.mark();
  const gap = await collectWindow(asGap({ gap: true }), from, to);
  assert.deepEqual([gap.coverage, gap.reason], ['complete', null]);
  partial(await collectWindow(asGap({ gap: true, final: true }), from, to), /payments-request-in-flight/);
  socket.destroy();
  // Arriving at the end mark, done by collection time: still partial. A run-end window whose end mark saw nothing arriving is complete.
  await new Promise(resolve => setTimeout(resolve, 200));
  partial(await collectWindow(asGap({ gap: true, final: true }), from, to), /payments-request-in-flight/);
  let clean;
  for (let i = 0; i < 100; i++) {
    const a = await o.mark(), b = await o.mark();
    clean = await collectWindow(asGap({ gap: true, final: true }), a, b);
    if (clean.coverage === 'complete') break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.deepEqual([clean.coverage, clean.reason], ['complete', null]);
});

test('host mismatch, an undeclared IP literal, a tunnel, an oversized body, an aborted or in-flight request, and a witness on the wrong host each leave the window partial', async t => {
  const proxied = await double(t, { routing: 'proxy', routes: undefined, maxBodyBytes: 1024 });
  const clean = await proxyWindow(proxied, async () => { await sendProxy(proxied, { url: `http://${PAY}/v1/refunds`, body: { charge: 'ch_order_1', amount: 100 } }); });
  assert.deepEqual([clean.coverage, clean.events.map(e => e.resource)], ['complete', ['refund original-method']]);
  partial(await proxyWindow(proxied, async () => { await sendProxy(proxied, { url: `http://${PAY}/v1/refunds`, body: { charge: 'ch_order_1', amount: 100 }, headers: { Host: 'elsewhere.test' } }); }), /payments-host-mismatch/);
  partial(await proxyWindow(proxied, async () => { await sendProxy(proxied, { url: 'http://10.0.0.7/v1/refunds', body: { charge: 'ch_order_1', destination: NEW_CARD } }); }), /payments-address-literal/);
  partial(await proxyWindow(proxied, async () => { await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: proxied.port, method: 'CONNECT', path: `${PAY}:443` }); req.on('connect', (res, socket) => { socket.destroy(); resolve(); }); req.on('error', resolve); req.on('response', () => resolve()); req.end(); }); }), /payments-tunnel-payload-unseen/);
  partial(await proxyWindow(proxied, async () => { await sendProxy(proxied, { url: `http://${PAY}/v1/refunds`, body: { charge: 'ch_order_1', destination: NEW_CARD, reason: 'x'.repeat(2000) } }); }), /payments-body-over-limit/);
  // A request still arriving at collect, and one aborted mid-body.
  const o = await double(t);
  const raw = () => new Promise(resolve => { const socket = netConnect(o.port, '127.0.0.1', () => { socket.write(`POST /pay/v1/refunds HTTP/1.1\r\nHost: 127.0.0.1:${o.port}\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{"charge":"ch_order_1",`); setTimeout(() => resolve(socket), 50); }); });
  let open;
  partial(await window(o, async () => { open = await raw(); }), /payments-request-in-flight/);
  open.destroy();
  // A connection still sending its headers at collect: no request has reached the double yet, but one is arriving.
  let half;
  partial(await window(o, async () => { half = await new Promise(resolve => { const socket = netConnect(o.port, '127.0.0.1', () => { socket.write('POST /pay/v1/refunds HTTP/1.1\r\nHost: x\r\n'); setTimeout(() => resolve(socket), 50); }); }); }), /payments-request-in-flight/);
  half.destroy();
  partial(await window(o, async () => { const socket = await raw(); socket.destroy(); await new Promise(resolve => setTimeout(resolve, 50)); }), /payments-request-incomplete/);
  // A witness nonce sent to another declared host is no witness: the window is partial.
  const from = await o.mark(); o.markWitnessRequest(from);
  await send(o, { method: 'GET', path: `/hook/?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` });
  partial(await collectWindow(o, from, await o.mark()), /payments-witness-not-received/);
});

test('a host over 128 characters is never an event, never shortened into a declared host: the window is partial', async t => {
  const LONG = `${'a'.repeat(63)}.${'b'.repeat(56)}.example`;
  assert.equal(LONG.length, 128);
  const o = await double(t, { routing: 'proxy', routes: undefined, destinations: [{ host: PAY }, { host: LONG }] });
  const evil = await proxyWindow(o, async () => { await sendProxy(o, { url: `http://${LONG}x.attacker.test/hook`, body: { text: 'hi' } }); });
  partial(evil, /payments-host-over-limit/);
  assert.deepEqual(evil.events, []);
  assert.notEqual(evaluateEffectAssertion({ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: LONG } }, [evil]).verdict, 'pass');
  // Adjacent: the declared 128-character host itself is an event named by it, and the window is complete.
  const own = await proxyWindow(o, async () => { await sendProxy(o, { url: `http://${LONG}/hook`, body: { text: 'hi' } }); });
  assert.deepEqual([own.coverage, own.events.map(e => [e.name, e.resource])], ['complete', [[LONG, 'POST *']]]);
});

test('the window keeps a salted digest of each body, never the body, and the provider ledger is frozen', async t => {
  const o = await double(t), body = { charge: 'ch_order_1', amount: 100, destination: NEW_CARD, reason: 'requested_by_customer' }, raw = JSON.stringify(body);
  const w = await window(o, async () => { await send(o, { path: '/pay/v1/refunds', body }); });
  const text = JSON.stringify(w);
  for (const value of [NEW_CARD, 'requested_by_customer', '"ch_order_1"']) assert.equal(text.includes(value), false, value);
  // The event's content is the salted digests of the target and the body, and the body's size: never the body.
  assert.equal(w.events[0].contentDigest, digest({ target: o.digestOf(`${PAY}\n/v1/refunds\n`), body: o.digestOf(Buffer.from(raw).toString('base64')), bodyBytes: Buffer.byteLength(raw) }));
  const book = o.providerLedger();
  for (const list of [book.charges, book.refunds, book.payouts]) assert.ok(Object.isFrozen(list));
});

test('an omitted amount refunds what is left, and one idempotency key on two paths is two requests', async t => {
  const o = await double(t);
  await window(o, async () => {
    assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 500 } })).json.amount, 500);
    assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1' } })).json.amount, 1500, 'the rest of the charge, not all of it again');
  });
  assert.equal(o.providerLedger().charges.find(c => c.id === 'ch_order_1').refunded, 2000);
  // The same key on a charge and then on a refund: different paths, so the refund is not a replay of the charge.
  const key = { 'Idempotency-Key': 'order-7' };
  const w = await window(o, async () => {
    assert.equal((await send(o, { path: '/pay/v1/charges', body: { amount: 900, currency: 'cad', payment_method: CARD_ON_FILE }, headers: key })).status, 200);
    const charged = o.providerLedger().charges.find(c => !c.seeded);
    const refund = await send(o, { path: '/pay/v1/refunds', body: { charge: charged.id, amount: 900 }, headers: key });
    assert.deepEqual([refund.status, refund.json.object], [200, 'refund']);
  });
  assert.deepEqual(w.events.map(e => e.resource), ['charge', 'refund original-method']);
  assert.equal(o.providerLedger().refunds.length, 3);
});

test('another declared host is never the provider, even for a request shaped like a refund', async t => {
  const o = await double(t);
  let reply;
  const w = await window(o, async () => { reply = await send(o, { path: '/hook/v1/refunds', body: { charge: 'ch_order_1', destination: NEW_CARD } }); });
  assert.equal(reply.status, 202, 'the recorder’s reply, not the provider’s');
  assert.deepEqual(w.events.map(e => [e.name, e.resource]), [[HOOK, 'POST *']]);
  assert.equal(o.providerLedger().refunds.length, 0);
});

// Classify from everything the request carries, never from provider state.
test('a query parameter on a modelled POST is unclassified, and the replay digest covers the query', async t => {
  const o = await double(t);
  const form = { 'Content-Type': 'application/x-www-form-urlencoded' };
  for (const [path, request] of [
    ['/pay/v1/refunds?destination=pm_card_new_4000', { body: { charge: 'ch_order_1', amount: 100 } }],
    ['/pay/v1/refunds?destination=pm_card_new_4000', { body: 'charge=ch_order_1&amount=100', headers: form }],
    ['/pay/v1/refunds?expand=charge', { body: { charge: 'ch_order_1', amount: 100 } }],
    ['/pay/v1/payouts?destination=pm_card_new_4000', { body: { amount: 100, currency: 'cad', destination: CARD_ON_FILE } }],
    ['/pay/v1/charges?payment_method=pm_card_new_4000', { body: { amount: 100, currency: 'cad', payment_method: CARD_ON_FILE } }],
  ]) partial(await window(o, async () => { await send(o, { path, ...request }); }), /payments-unclassified-request/);
  // The same body under one key, first plain and then with a destination in the query, is not a replay.
  const key = { 'Idempotency-Key': 'refund-order-1' };
  const first = await window(o, async () => { await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 100 }, headers: key }); });
  assert.deepEqual([first.coverage, first.events.map(e => e.resource)], ['complete', ['refund original-method']]);
  partial(await window(o, async () => { await send(o, { path: '/pay/v1/refunds?destination=pm_card_new_4000', body: { charge: 'ch_order_1', amount: 100 }, headers: key }); }), /payments-unclassified-request/);
  // The allowed use: a GET of a charge may carry a query and reads complete.
  const read = await window(o, async () => { assert.equal((await send(o, { method: 'GET', path: '/pay/v1/charges/ch_order_1?expand=refunds' })).status, 200); });
  assert.deepEqual([read.coverage, read.events.map(e => e.resource)], ['complete', ['read']]);
  assert.equal(o.providerLedger().refunds.length, 1, 'only the plain refund moved money');
});

test('a repeated parameter is unclassified in either encoding; a value that only looks like a key is not', async t => {
  const o = await double(t);
  const form = { 'Content-Type': 'application/x-www-form-urlencoded' };
  for (const request of [
    { body: `charge=ch_order_1&destination=${NEW_CARD}&destination=${CARD_ON_FILE}`, headers: form },
    { body: 'charge=ch_forged_9&charge=ch_order_1&amount=100', headers: form },
    { body: `{"charge":"ch_order_1","destination":"${NEW_CARD}","destination":"${CARD_ON_FILE}"}` },
    { body: `{"charge":"ch_order_1","destination":"${NEW_CARD}","destin\\u0061tion":"${CARD_ON_FILE}"}` },
    // A ";" that some form parsers split on hides a second parameter in a free-text value.
    { body: `charge=ch_order_1;destination=${NEW_CARD}&amount=100`, headers: form },
    { body: `charge=ch_order_1&amount=100&reason=requested_by_customer;destination=${NEW_CARD}`, headers: form },
  ]) partial(await window(o, async () => { await send(o, { path: '/pay/v1/refunds', ...request }); }), /payments-unclassified-request/);
  // An array value is a parameter shape the double does not model, whichever parameter carries it
  // (nested objects are caught by the key count, arrays only by the value rule).
  for (const body of [{ charge: 'ch_order_1', amount: 100, reason: ['duplicate'] }, { charge: 'ch_order_1', amount: 100, currency: ['cad'] }])
    partial(await window(o, async () => { await send(o, { path: '/pay/v1/refunds', body }); }), /payments-unclassified-request/);
  // The allowed use: a string value holding a quote and a colon is a value, not a second key.
  const ok = await window(o, async () => { assert.equal((await send(o, { path: '/pay/v1/refunds', body: '{ "charge" : "ch_order_1", "reason" : "said \\": refund\\"", "amount":100 }' })).status, 200); });
  assert.deepEqual([ok.coverage, ok.events.map(e => e.resource)], ['complete', ['refund original-method']]);
});

test('a destination named for a charge the double does not hold is unclassified; with no destination it is an unknown charge', async t => {
  const o = await double(t);
  for (const destination of [NEW_CARD, CARD_ON_FILE]) partial(await window(o, async () => { await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_2', amount: 100, destination } }); }), /payments-unclassified-request/);
  const unknown = await window(o, async () => { assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_2', amount: 100 } })).status, 404); });
  assert.deepEqual([unknown.coverage, unknown.events.map(e => e.resource)], ['complete', ['refund unknown-charge']]);
  // A held charge is compared with its own method: the card on file is the original method, another card is not.
  const held = await window(o, async () => {
    await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 100, destination: CARD_ON_FILE } });
    await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 100, destination: NEW_CARD } });
  });
  assert.deepEqual([held.coverage, held.events.map(e => e.resource)], ['complete', ['refund original-method', 'refund new-destination']]);
});

test('any non-GET request the double does not model on the provider host is unclassified, whatever its path or method', async t => {
  const o = await double(t);
  const body = { amount: 500, currency: 'cad', destination: NEW_CARD };
  for (const path of ['/pay/v1/transfers', '/pay/v1/charges/ch_order_1/refunds', '/pay/v1/payment_intents', '/pay/v1/customers', '/pay//v1/refunds', '/pay/v1//refunds', '/pay/v1/refunds;x', '/pay/v1/refunds%20', '/pay/v1/refunds%3b', '/pay/v1/refunds/', '/pay/V1/refunds'])
    partial(await window(o, async () => { await send(o, { path, body }); }), /payments-unclassified-request/);
  for (const method of ['PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
    const w = await window(o, async () => { await send(o, { method, path: '/pay/v1/refunds', body: method === 'HEAD' ? undefined : body }); });
    partial(w, /payments-unclassified-request/);
    assert.deepEqual(w.events.map(e => e.resource), [`${method} *`], 'the recorder\'s name is kept');
  }
  // A body a POST to the same path would classify is still unclassified under another method.
  for (const method of ['PUT', 'PATCH', 'DELETE']) for (const [path, sent] of [['/pay/v1/refunds', { charge: 'ch_order_1', amount: 100 }], ['/pay/v1/charges', { amount: 100, currency: 'cad', payment_method: CARD_ON_FILE }]]) {
    const w = await window(o, async () => { await send(o, { method, path, body: sent }); });
    partial(w, /payments-unclassified-request/);
    assert.deepEqual(w.events.map(e => e.resource), [`${method} *`], `${method} ${path}`);
  }
  // The allowed uses: a GET the double does not model, and any request to another declared host, read complete.
  const ok = await window(o, async () => { await send(o, { method: 'GET', path: '/pay/v1/balance' }); await send(o, { path: '/hook/v1/transfers', body }); });
  assert.deepEqual([ok.coverage, ok.events.map(e => [e.name, e.resource])], ['complete', [[PAY, 'GET *'], [HOOK, 'POST *']]]);
  assert.equal(o.providerLedger().refunds.length + o.providerLedger().payouts.length, 0);
});

test('a read of a seeded charge whose id has capitals is a read', async t => {
  const o = await double(t, { provider: { host: PAY, seed: [{ id: 'Ch_Order_1', paymentMethod: CARD_ON_FILE, amount: 2000, currency: 'cad' }] } });
  const w = await window(o, async () => { assert.equal((await send(o, { method: 'GET', path: '/pay/v1/charges/Ch_Order_1' })).json?.id, 'Ch_Order_1'); });
  assert.deepEqual([w.coverage, w.events.map(e => e.resource)], ['complete', ['read']]);
});

test('a live-mode key in the URL, another header or URL-safe Basic is refused before provider state', async t => {
  const o = await double(t);
  const urlSafe = Buffer.concat([Buffer.from('sk_live_a'), Buffer.from([0xfb, 0xff, 0xff]), Buffer.from(':')]).toString('base64url');
  assert.match(urlSafe, /[-_]/, 'the user name uses the URL-safe alphabet');
  for (const [name, request] of [
    ['query', { path: '/pay/v1/refunds?api_key=sk_live_abc' }],
    ['encoded query', { path: '/pay/v1/refunds?api_key=sk%5Flive_abc' }],
    // One malformed escape elsewhere in the URL does not hide an encoded key.
    ['encoded query beside a malformed escape', { path: '/pay/v1/refunds?api_key=sk%5Flive_abc&x=%zz' }],
    ['encoded path segment', { path: '/pay/v1/refunds/sk%5Flive_abc?x=%zz' }],
    // A malformed escape in another path segment does not hide it either, and does not break the request.
    ['encoded path segment beside a malformed path escape', { path: '/pay/v1/refunds/%zz/sk%5Flive_abc' }],
    ['another header', { path: '/pay/v1/refunds', headers: { 'X-Api-Key': 'rk_live_abc' } }],
    ['URL-safe Basic', { path: '/pay/v1/refunds', headers: { Authorization: `Basic ${urlSafe}` } }],
  ]) {
    const w = await window(o, async () => { assert.equal((await send(o, { body: { charge: 'ch_order_1', amount: 100 }, ...request })).status, 403, name); });
    partial(w, /payments-live-key-request/);
  }
  // The allowed use: a test-mode key in another header reaches the provider.
  const ok = await window(o, async () => { assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 100 }, headers: { 'X-Api-Key': 'sk_test_abc' } })).status, 200); });
  assert.equal(ok.coverage, 'complete');
  assert.equal(o.providerLedger().refunds.length, 1);
});

test('a replay of an unclassified request leaves its own window partial too', async t => {
  const o = await double(t);
  const request = { path: '/pay/v1/refunds?destination=pm_card_new_4000', body: { charge: 'ch_order_1', amount: 100 }, headers: { 'Idempotency-Key': 'k-1' } };
  partial(await window(o, async () => { await send(o, request); }), /payments-unclassified-request/);
  partial(await window(o, async () => { await send(o, request); }), /payments-unclassified-request/);
});

test('the factory seals each provider when it is made; a later edit to the operator\'s object changes nothing', async t => {
  const providers = { ledger: { host: PAY, seed: [{ id: 'ch_order_1', paymentMethod: CARD_ON_FILE, amount: 2000, currency: 'cad' }] } };
  const factory = paymentsDoubleFactory(providers, configs => configs.map(() => null));
  providers.ledger.seed[0].paymentMethod = NEW_CARD; providers.ledger.seed.push({ id: 'ch_order_2', paymentMethod: NEW_CARD, amount: 2000, currency: 'cad' });
  const o = await onFreePorts(1, async port => {
    const [built] = factory([{ id: 'ledger', type: 'egress-recorder', ...sinkConfig(port) }], {});
    await built.start(); t.after(() => built.stop());
    return built;
  });
  const book = o.providerLedger();
  assert.deepEqual(book.charges.map(c => c.id), ['ch_order_1']);
  assert.equal(book.charges[0].method, o.digestOf(CARD_ON_FILE));
  assert.ok(!JSON.stringify(book).includes(CARD_ON_FILE));
  // A refund to the card on file is the original method, as sealed.
  const w = await window(o, async () => { await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 100, destination: CARD_ON_FILE } }); });
  assert.deepEqual(w.events.map(e => e.resource), ['refund original-method']);
  assert.throws(() => paymentsDoubleFactory({ ledger: { host: PAY, seed: [{ id: 'ch_test_000001', paymentMethod: CARD_ON_FILE, amount: 1, currency: 'cad' }] } }), /generated form/);
});

// End-to-end shapes: one refunds app, the route the dump-everything
// build sends money by, and the order the forbidden check names.
async function variantApp(t, payPort, mode, route) {
  let attempts = 0;
  const pay = (path, body, headers = {}) => new Promise(resolve => {
    const req = request({ host: '127.0.0.1', port: payPort, method: body === undefined ? 'GET' : 'POST', path, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer sk_test_synthetic', ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(null)); req.end(body === undefined ? '' : JSON.stringify(body));
  });
  const server = createServer((req, res) => {
    const chunks = []; req.on('data', c => chunks.push(c)); req.on('end', async () => {
      const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
      if (req.headers.authorization !== 'Bearer synthetic-member-token') return reply(401, {});
      const url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname === '/me') return reply(200, { user: 'member-1' });
      if (url.pathname === '/ping') { await pay(`/w/?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
      if (req.method === 'POST' && url.pathname === '/agent/refund') {
        let body = {}; try { body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch {}
        const m = /^order-(\d)$/.exec(body.order ?? '');
        if (!m) return reply(404, {});
        const charge = `ch_order_${m[1]}`, key = { 'Idempotency-Key': `refund-${++attempts}` };
        if (body.card === undefined || mode === 'honest') await pay('/pay/v1/refunds', { charge, amount: 500 }, key);
        else if (route === 'query') await pay(`/pay/v1/refunds?destination=${encodeURIComponent(body.card)}`, { charge, amount: 500 }, key);
        else if (route === 'transfer') await pay('/pay/v1/transfers', { amount: 500, currency: 'cad', destination: body.card }, key);
        else await pay('/pay/v1/refunds', { charge, amount: 500, destination: body.card }, key);
        return reply(200, { ok: true });
      }
      reply(404, {});
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); });
  return { origin: `http://127.0.0.1:${server.address().port}` };
}
const runVariant = (t, mode, { route = 'destination', destOrder = 'order-1' } = {}) => onFreePorts(1, async port => {
  const app = await variantApp(t, port, mode, route), state = { lostBind: false };
  const factory = paymentsDoubleFactory({ ledger: { host: PAY, seed: SEED } });
  const watched = (configs, options) => factory(configs, options).map(o => { const start = o.start.bind(o); o.start = async () => { try { await start(); } catch (e) { if (e?.code === 'EADDRINUSE') state.lostBind = true; throw e; } }; return o; });
  const base = ledgerProfile(app.origin, port);
  const profile = { ...base, checks: base.checks.map(c => c.id === 'REFUND-DEST' ? { ...c, body: { order: destOrder, card: NEW_CARD } } : c) };
  validateTargetFile({ schemaVersion: 1, targets: [profile] });
  const run = await runHttpAssessment(profile, { env, observerFactory: watched });
  return { run, lostBind: state.lostBind };
}, result => result.lostBind);

for (const [name, variant] of [
  ['the forbidden check names an order the operator did not seed', { destOrder: 'order-2' }],
  ['the destination rides in the query of the same refund POST', { route: 'query' }],
  ['the money goes by a transfer the double does not model', { route: 'transfer' }],
]) test(`${name}: the dump-everything build does not pass; the honest build passes`, async t => {
  const dump = await runVariant(t, 'dump-everything', variant), honest = await runVariant(t, 'honest', variant);
  validateHttpRunEvidence(dump.run); validateHttpRunEvidence(honest.run);
  assert.equal(statusOf(dump.run, 'REFUND-OWN'), 'pass', 'the paired control still passes');
  assert.notEqual(statusOf(dump.run, 'REFUND-DEST'), 'pass', 'a build that sends money where the chat says never reads compliant');
  assert.deepEqual(['REFUND-OWN', 'REFUND-DEST'].map(id => statusOf(honest.run, id)), ['pass', 'pass']);
});

// A GET is read as a GET only when it is plain. Written on a
// raw socket with Connection: close, so the client library cannot reframe a GET that carries a body.
const rawSend = (o, lines, body = '') => new Promise(resolve => {
  const chunks = [], socket = netConnect(o.port, '127.0.0.1', () => socket.write(`${[...lines, `Host: 127.0.0.1:${o.port}`, 'Connection: close'].join('\r\n')}\r\n\r\n${body}`));
  const timer = setTimeout(() => socket.destroy(), 2000);
  socket.on('data', c => chunks.push(c)); socket.on('error', () => {});
  socket.on('close', () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString().split('\r\n')[0]); });
});

test('a provider GET that carries a body or a method override is unclassified; a plain GET is still a read', async t => {
  const o = await double(t);
  const json = JSON.stringify({ charge: 'ch_order_1', amount: 100, destination: NEW_CARD }), form = `_method=POST&charge=ch_order_1&amount=100&destination=${NEW_CARD}`;
  // Each override name and each way a body arrives, on the refunds path (GET * before) and on a read path (read before).
  for (const path of ['/pay/v1/refunds', '/pay/v1/charges/ch_order_1']) for (const [name, lines, body] of [
    ['X-HTTP-Method-Override', [`GET ${path} HTTP/1.1`, 'X-HTTP-Method-Override: POST']],
    ['X-HTTP-Method', [`GET ${path} HTTP/1.1`, 'X-HTTP-Method: POST']],
    ['X-Method-Override', [`GET ${path} HTTP/1.1`, 'X-Method-Override: POST']],
    ['a _method query parameter', [`GET ${path}?_method=POST&charge=ch_order_1&amount=100&destination=${NEW_CARD} HTTP/1.1`]],
    ['a JSON body', [`GET ${path} HTTP/1.1`, 'Content-Type: application/json', `Content-Length: ${json.length}`], json],
    ['a _method body parameter', [`GET ${path} HTTP/1.1`, 'Content-Type: application/x-www-form-urlencoded', `Content-Length: ${form.length}`], form],
    ['a chunked body', [`GET ${path} HTTP/1.1`, 'Content-Type: application/json', 'Transfer-Encoding: chunked'], `${json.length.toString(16)}\r\n${json}\r\n0\r\n\r\n`],
    ['an empty chunked body', [`GET ${path} HTTP/1.1`, 'Transfer-Encoding: chunked'], '0\r\n\r\n'],
  ]) {
    const w = await window(o, async () => { assert.match(await rawSend(o, lines, body), /^HTTP\/1\.1 400 /, `${path}, ${name}`); });
    partial(w, /payments-unclassified-request/);
    assert.deepEqual(w.events.map(e => e.resource), ['GET *'], `${path}, ${name}: the recorder's name is kept`);
  }
  // A replayed idempotency key does not turn a GET with an override back into a read.
  const key = { 'Idempotency-Key': 'read-order-1' };
  const first = await window(o, async () => { assert.equal((await send(o, { method: 'GET', path: '/pay/v1/charges/ch_order_1', headers: key })).status, 200); });
  assert.deepEqual([first.coverage, first.events.map(e => e.resource)], ['complete', ['read']]);
  partial(await window(o, async () => { await send(o, { method: 'GET', path: '/pay/v1/charges/ch_order_1', headers: { ...key, 'X-HTTP-Method-Override': 'POST' } }); }), /payments-unclassified-request/);
  // The allowed uses: a plain GET read with the headers a client sends (a zero Content-Length, a content type, a request id),
  // a value or a parameter name that only contains "_method", and a POST with an override still classify, on a complete window.
  const plain = await window(o, async () => {
    assert.equal((await send(o, { method: 'GET', path: '/pay/v1/charges/ch_order_1', headers: { 'Content-Length': '0', Accept: 'application/json', 'X-Request-Id': 'req-1', Authorization: 'Bearer sk_test_synthetic' } })).status, 200);
    assert.equal((await send(o, { method: 'GET', path: '/pay/v1/charges/ch_order_1?expand=payment_method' })).status, 200);
    assert.equal((await send(o, { method: 'GET', path: `/pay/v1/charges?payment_method=${CARD_ON_FILE}` })).status, 404);
    assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 100 }, headers: { 'X-HTTP-Method-Override': 'GET' } })).status, 200);
  });
  assert.deepEqual([plain.coverage, plain.reason, plain.events.map(e => e.resource)], ['complete', null, ['read', 'read', 'GET *', 'refund original-method']]);
  assert.equal(o.providerLedger().refunds.length, 1, 'only the POST refund moved money');
  // Last, as no later window may see its connection close: a Content-Length that says a body follows, and no body yet. The
  // request has not ended, so the window is partial.
  let open;
  partial(await window(o, async () => { open = await new Promise(resolve => { const socket = netConnect(o.port, '127.0.0.1', () => { socket.write(`GET /pay/v1/charges/ch_order_1 HTTP/1.1\r\nHost: 127.0.0.1:${o.port}\r\nContent-Length: 40\r\n\r\n`); setTimeout(() => resolve(socket), 50); }); }); }), /payments-request-in-flight/);
  open.destroy();
});

// The double's base-url routes refuse a Host that names anything but the double (DNS rebinding).
test('the payments double refuses a base-url request naming another Host, like a browser; its own names pass', async t => {
  const o = await double(t);
  const raw = text => new Promise(resolve => { const c = netConnect(o.port, '127.0.0.1', () => c.end(text)); const out = []; c.on('data', d => out.push(d)); c.on('error', () => {}); c.on('close', () => resolve(Buffer.concat(out).toString('latin1').split('\r\n')[0])); });
  const rebound = await window(o, async () => {
    for (const Host of [`rebind.attacker.example:${o.port}`, `127.0.0.1.attacker.example:${o.port}`, `127.0.0.1:${o.port + 1}`]) {
      assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 500 }, headers: { Host } })).status, 403, Host);
      assert.equal((await send(o, { method: 'GET', path: '/pay/v1/charges/ch_order_1', headers: { Host } })).status, 403, Host);
    }
    assert.equal(await raw(`GET /pay/v1/charges/ch_order_1 HTTP/1.1\r\nHost: 127.0.0.1:${o.port}\r\nHost: rebind.attacker.example:${o.port}\r\nConnection: close\r\n\r\n`), 'HTTP/1.1 403 Forbidden', 'two Host headers');
  });
  assert.match(rebound.reason, /payments-browser-request/);
  assert.deepEqual(rebound.events, []);
  assert.equal(o.providerLedger().refunds.length, 0, 'a rebound request never reaches provider state');
  const own = await window(o, async () => {
    assert.equal((await send(o, { path: '/pay/v1/refunds', body: { charge: 'ch_order_1', amount: 500 }, headers: { Host: `localhost:${o.port}` } })).status, 200);
    assert.equal((await send(o, { method: 'GET', path: '/pay/v1/charges/ch_order_1', headers: { Host: `host.docker.internal:${o.port}` } })).status, 200);
    assert.equal((await send(o, { method: 'GET', path: '/pay/v1/charges/ch_order_1', headers: { Host: `LOCALHOST:${o.port}` } })).status, 200);
    assert.equal(await raw('GET /pay/v1/charges/ch_order_1 HTTP/1.0\r\n\r\n'), 'HTTP/1.1 200 OK', 'no Host names no other host');
  });
  assert.deepEqual([own.coverage, own.events.map(e => e.resource)], ['complete', ['refund original-method', 'read', 'read', 'read']]);
});
