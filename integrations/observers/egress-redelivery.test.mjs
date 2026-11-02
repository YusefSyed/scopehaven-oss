// End to end over real loopback HTTP: re-signed webhook redeliveries collapse only when the declared volatile signature
// headers are all that changed (and only when their scheme parses inside the run window and the
// signatures agree), and an event id read from a declared body pointer counts each event once. Every request goes to 127.0.0.1;
// destination hosts are names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createHmac } from 'node:crypto';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts, watchingBinds } from './fixtures/free-port.mjs';
import { buildObservers } from './factory.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { digest } from '../../src/domain.mjs';

const HOOK = 'hooks.example.test', WITNESS = 'witness.scopehaven.invalid';
// The signing clock the factory passes (the wall clock); null builds a recorder without one.
const sink = (t, destinations, { signingClock = () => Date.now() } = {}) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, signingClock });
  await o.start(); t.after(() => o.stop()); return o;
});
const post = (port, headers, body, { hold = null, type = 'application/json' } = {}) => new Promise(resolve => {
  const req = request({ host: '127.0.0.1', port, method: 'POST', path: `http://${HOOK}/events`, headers: { host: HOOK, 'content-type': type, 'content-length': String(Buffer.byteLength(body)), ...headers } }, res => { res.resume(); res.on('end', resolve); });
  req.on('error', resolve);
  if (hold) { req.write(body.slice(0, 1)); hold.then(() => req.end(body.slice(1))); } else req.end(body);
});
async function windowOf(o, between) {
  const from = await o.mark(); await between(); o.markWitnessRequest(from);
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark());
}
const count = expected => ({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: HOOK }, expected, countBy: 'idempotency-key' });
const verdict = (w, expected) => { const d = evaluateEffectAssertion(count(expected), [w], { countBy: true }); return [w.coverage, d.verdict, d.applications && [d.applications.low, d.applications.high]]; };
const event = JSON.stringify({ type: 'order.paid', data: { order_id: 'o-1', amount: 25 } });
// A Standard Webhooks delivery: the id is fixed, the timestamp and signature are recomputed per attempt (a later second each).
const now = () => Math.floor(Date.now() / 1000);
const mac = (secret, id, t, body = event) => `v1,${createHmac('sha256', secret).update(`${id}.${t}.${body}`).digest('base64')}`;
const signed = (id, attempt, extra = {}, { t = now() + attempt, secret = 'whsec-a' } = {}) => ({ 'webhook-id': id, 'webhook-timestamp': String(t), 'webhook-signature': mac(secret, id, t), ...extra });

test('re-signed redeliveries: collapse only with the signature headers declared volatile, and never over a changed body or account', async t => {
  const strict = await sink(t, [{ host: HOOK, paths: ['/events'], idempotency: { header: 'webhook-id' } }]);
  const loose = await sink(t, [{ host: HOOK, paths: ['/events'], idempotency: { header: 'webhook-id', volatile: ['webhook-signature', 'webhook-timestamp'] } }]);
  const twice = o => windowOf(o, async () => { await post(o.port, signed('msg_1', 1), event); await post(o.port, signed('msg_1', 2), event); });
  assert.deepEqual(verdict(await twice(strict), 1), ['complete', 'missing', [1, 2]], 'without volatile the re-signed redelivery differs');
  assert.deepEqual(verdict(await twice(loose), 1), ['complete', 'pass', [1, 1]], 'with volatile it is one delivery of one event');
  const body = await windowOf(loose, async () => { await post(loose.port, signed('msg_2', 1), event); await post(loose.port, signed('msg_2', 2), event.replace('25', '26')); });
  assert.deepEqual(verdict(body, 1), ['complete', 'missing', [1, 2]], 'a changed payload under one id is never hidden by a dropped signature');
  const account = await windowOf(loose, async () => { await post(loose.port, signed('msg_3', 1, { 'stripe-account': 'acct_a' }), event); await post(loose.port, signed('msg_3', 2, { 'stripe-account': 'acct_b' }), event); });
  assert.deepEqual(verdict(account, 1), ['complete', 'missing', [1, 2]], 'an account header is never volatile');
  const fresh = await windowOf(loose, async () => { await post(loose.port, signed('msg_4', 1), event); await post(loose.port, signed('msg_5', 1), event); });
  assert.deepEqual(verdict(fresh, 1), ['complete', 'fail', [2, 2]], 'a new id for the same event is a duplicate');
});

test('signatures leave head only when their scheme parses in the run window and agrees; untimed MACs never do', async t => {
  const o = await sink(t, [{ host: HOOK, paths: ['/events'], idempotency: { header: 'webhook-id', volatile: ['webhook-signature', 'webhook-timestamp', 'x-hub-signature-256'] } }]);
  const twice = (a, b) => windowOf(o, async () => { await post(o.port, a, event); await post(o.port, b, event); });
  const t0 = now();
  const resigned = await twice(signed('m-1', 0, {}, { t: t0 }), signed('m-1', 1, {}, { t: t0 + 1 }));
  assert.deepEqual(verdict(resigned, 1), ['complete', 'pass', [1, 1]], 'a re-sign in a later second');
  const [first] = resigned.events;
  assert.deepEqual(Object.keys(first.idempotency.signed), ['standard-webhooks']);
  assert.equal(first.idempotency.signed['standard-webhooks'].t, t0);
  assert.match(first.idempotency.signed['standard-webhooks'].mac, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(resigned).includes(mac('whsec-a', 'm-1', t0).slice(3)), 'the signature itself is never stored');
  const secrets = await twice(signed('m-2', 0, {}, { t: t0 }), signed('m-2', 0, {}, { t: t0, secret: 'whsec-b' }));
  assert.deepEqual(verdict(secrets, 1), ['complete', 'missing', [1, 2]], 'the same second under a second secret stays two');
  const stale = await twice(signed('m-3', 0, {}, { t: t0 - 1000 }), signed('m-3', 0, {}, { t: t0 - 999 }));
  assert.equal(stale.events[0].idempotency.signed['standard-webhooks'], null);
  assert.deepEqual(verdict(stale, 1), ['complete', 'missing', [1, 2]], 'a timestamp from before the run');
  const unparsed = await twice({ ...signed('m-4', 0), 'webhook-signature': 'v1,sig-1' }, { ...signed('m-4', 1), 'webhook-signature': 'v1,sig-2' });
  assert.deepEqual(verdict(unparsed, 1), ['complete', 'missing', [1, 2]], 'a signature that does not parse stays bound');
  const rotation = (id, n, at) => ({ 'webhook-id': id, 'webhook-timestamp': String(at), 'webhook-signature': ['whsec-a', 'whsec-b'].slice(0, n).map(k => mac(k, id, at)).join(' ') });
  assert.deepEqual(verdict(await twice(rotation('m-5', 2, t0), rotation('m-5', 2, t0 + 1)), 1), ['complete', 'pass', [1, 1]], 'a rotation with two signatures each time');
  assert.deepEqual(verdict(await twice(rotation('m-6', 1, t0), rotation('m-6', 2, t0 + 1)), 1), ['complete', 'missing', [1, 2]], 'one signature, then two');
  const hub = k => ({ ...signed('m-7', 0, {}, { t: t0 }), 'x-hub-signature-256': `sha256=${createHmac('sha256', k).update(event).digest('hex')}` });
  assert.deepEqual(verdict(await twice(hub('gh-a'), hub('gh-a')), 1), ['complete', 'pass', [1, 1]], 'an untimed MAC repeats on a same-secret redelivery');
  const hubKeys = await windowOf(o, async () => { await post(o.port, { ...hub('gh-a'), 'webhook-id': 'm-8' }, event); await post(o.port, { ...hub('gh-b'), 'webhook-id': 'm-8' }, event); });
  assert.deepEqual(verdict(hubKeys, 1), ['complete', 'missing', [1, 2]], 'declared or not, an untimed MAC stays bound');
});

test('the signing clock: a recorder without one never collapses a re-sign; the factory wires the wall clock', async t => {
  const destinations = [{ host: HOOK, paths: ['/events'], idempotency: { header: 'webhook-id', volatile: ['webhook-signature', 'webhook-timestamp'] } }];
  const resign = (o, id) => windowOf(o, async () => { const t0 = now(); await post(o.port, signed(id, 0, {}, { t: t0 }), event); await post(o.port, signed(id, 1, {}, { t: t0 + 1 }), event); });
  const bare = await resign(await sink(t, destinations, { signingClock: null }), 'c-1');
  assert.deepEqual(bare.events.map(e => e.idempotency.signed), [{ 'standard-webhooks': null }, { 'standard-webhooks': null }]);
  assert.deepEqual(verdict(bare, 1), ['complete', 'missing', [1, 2]], 'no clock: the scheme reads unparsed and stays bound');
  const [built] = await onFreePorts(1, async port => {
    const observers = buildObservers([{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 }]);
    await observers[0].start(); t.after(() => observers[0].stop()); return observers;
  });
  const wired = await resign(built, 'c-2');
  assert.equal(wired.events[0].idempotency.signed['standard-webhooks'].t > 0, true);
  assert.deepEqual(verdict(wired, 1), ['complete', 'pass', [1, 1]], 'built by the factory: the wall clock is wired');
});

test('event ids in the body: one application per id, a duplicate per new id, and an unreadable body spoils the host', async t => {
  const o = await sink(t, [{ host: HOOK, paths: ['/events'], idempotency: { pointer: '/event_id' } }]);
  const outbox = id => JSON.stringify({ event_id: id, type: 'order.paid', order_id: 'o-1' });
  const same = await windowOf(o, async () => { await post(o.port, {}, outbox('e-1')); await post(o.port, {}, outbox('e-1')); });
  assert.equal(same.events[0].idempotency.status, 'keyed');
  assert.ok(!JSON.stringify(same).includes('e-1'), 'the id itself is never stored');
  assert.deepEqual(verdict(same, 1), ['complete', 'pass', [1, 1]]);
  const dup = await windowOf(o, async () => { await post(o.port, {}, outbox('e-2')); await post(o.port, {}, outbox('e-3')); });
  assert.deepEqual(verdict(dup, 1), ['complete', 'fail', [2, 2]], 'the same business event under two ids');
  const number = await windowOf(o, () => post(o.port, {}, JSON.stringify({ event_id: 7 })));
  assert.equal(number.events[0].idempotency.status, 'malformed');
  const form = await windowOf(o, () => post(o.port, {}, 'event_id=e-9', { type: 'application/x-www-form-urlencoded' }));
  assert.equal(form.events[0].idempotency.status, 'unreadable');
  const after = await windowOf(o, async () => { await post(o.port, {}, outbox('e-10')); });
  assert.deepEqual(verdict(after, 1), ['complete', 'missing', [0, 1]], 'an unreadable body earlier in the run');
});

test('body keys: concurrent sends of one id overlap, also when another send ends between them', async t => {
  const o = await sink(t, [{ host: HOOK, paths: ['/events'], idempotency: { pointer: '/event_id' } }]);
  const body = id => JSON.stringify({ event_id: id });
  let release;
  const held = new Promise(r => { release = r; });
  const w = await windowOf(o, async () => {
    const a = post(o.port, {}, body('c-1'), { hold: held });
    await new Promise(r => setTimeout(r, 50));
    await post(o.port, {}, body('c-1'));
    await post(o.port, {}, body('c-1'));
    release(); await a;
  });
  assert.equal(w.coverage, 'complete');
  assert.ok(w.events.some(e => e.idempotency.status === 'overlap'), JSON.stringify(w.events.map(e => e.idempotency.status)));
  assert.equal(verdict(w, 1)[1], 'missing');
});

// An app whose routes emit an outbox event through its proxy (the sink): redelivered once, or under a fresh id.
async function outboxApp(t, sinkPort) {
  const outbound = (target, body) => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(body);
  });
  let n = 0;
  const server = createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return send(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return send(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return send(200, { ok: true }); }
    const run = ++n;
    if (url.pathname === '/order/redeliver') { const e = JSON.stringify({ event_id: `evt-${run}`, order_id: 'o-1' }); await outbound(`http://${HOOK}/redeliver`, e); await outbound(`http://${HOOK}/redeliver`, e); return send(200, { ok: true }); }
    if (url.pathname === '/order/duplicate') { for (const k of ['a', 'b']) await outbound(`http://${HOOK}/duplicate`, JSON.stringify({ event_id: `evt-${run}-${k}`, order_id: 'o-2' })); return send(200, { ok: true }); }
    return send(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const at = path => ({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: HOOK, resource: `POST ${path}` }, expected: 1, countBy: 'idempotency-key' });
const check = (id, path, effects) => ({ id, title: id, category: 'events', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects });

test('connector run: a body-pointer destination counts events, binds its declaration, and refuses a forged id record', async t => {
  const { p, run: r } = await onFreePorts(1, async port => {
    const p = { id: 'outbox', name: 'Outbox', applicationId: 'outbox', origin: await outboxApp(t, port), buildLabel: 'b1', contextId: 'synthetic-outbox',
      actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
      observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: HOOK, paths: ['/redeliver', '/duplicate'], idempotency: { pointer: '/event_id' } }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
      checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
        check('REDELIVER', '/order/redeliver', [at('/redeliver')]), check('DUPLICATE', '/order/duplicate', [at('/duplicate')])] };
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    const watch = watchingBinds(buildObservers);
    return { p, run: await runHttpAssessment(p, { env, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
  }, x => x.lostBind);
  const row = id => r.results.find(x => x.id === id);
  assert.equal(row('REDELIVER').status, 'pass', JSON.stringify(row('REDELIVER').assertions));
  assert.equal(row('DUPLICATE').status, 'fail');
  assert.deepEqual(r.observers[0].idempotency, { [HOOK]: { header: null, pointer: '/event_id', methods: ['POST'], volatile: [], maxBytes: 16384 } });
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  validateHttpRunEvidence(r, { expectedSuite: suite });
  const refused = detail => error => error.code === 'invalid-run-evidence' && error.detail === detail;
  const reseal = x => { x.evidenceDigest = digest({ evidence: x.trace[0].data, effects: x.trace[1].data, assertions: x.assertions }); };
  const forged = structuredClone(r), fx = forged.results.find(x => x.id === 'DUPLICATE');
  const [a, b] = fx.trace[1].data.windows[0].events;
  Object.assign(b.idempotency, { key: a.idempotency.key, fold: a.idempotency.fold, firstSeq: a.idempotency.firstSeq }); reseal(fx);
  assert.throws(() => validateHttpRunEvidence(forged), refused('effect-verdict'));
  const widened = structuredClone(r);
  for (const x of widened.results) if (x.trace?.[1]) { for (const w of x.trace[1].data.windows) w.scope.idempotency[HOOK].maxBytes = 65536; reseal(x); }
  assert.throws(() => validateHttpRunEvidence(widened), refused('effect-trace'));
});
