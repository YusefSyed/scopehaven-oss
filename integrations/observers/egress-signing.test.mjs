// Verified signature headers end to end over real loopback HTTP: the recorder reads a
// destination's declared signing secrets once, verifies each send on the raw body bytes it received, and lets a re-signed redelivery
// count as one application only when both sends verified under the same declared secret. Every request goes to 127.0.0.1;
// destination hosts are names only and are never resolved or contacted. Every secret is synthetic and built at run time, and the
// last test scans every artifact a run writes for any form of them.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createHash, createHmac, scryptSync } from 'node:crypto';
import { inspect } from 'node:util';
import { mkdtemp, rm, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts, watchingBinds } from './fixtures/free-port.mjs';
import { buildObservers } from './factory.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { createStore } from '../../src/store.mjs';
import { renderReport } from '../../src/report.mjs';
import { serializeSarif } from '../../src/sarif.mjs';
import { digest } from '../../src/domain.mjs';
import { signingLimitation } from '../../src/http-scope-text.mjs';

const HOOKS = 'hooks.example.test', WITNESS = 'witness.scopehaven.invalid', T = 1791800000;
const ENV = n => `SCOPEHAVEN_TARGET_HOOK_SECRET_${n}`;
// Synthetic secrets, built from parts at run time so no literal looks like a credential.
const secret = n => ['synthetic', 'signing', 'secret', String(n), 'abcdefgh'].join('-');
const standardSecret = bytes => ['wh', 'sec_', bytes.toString('base64')].join('');
const BODY = '{"id":"evt_1","type":"ticket.updated"}';
const mac = (key, message) => createHmac('sha256', key).update(message).digest();
const stripeSig = (key, t, body = BODY) => `t=${t},v1=${mac(key, `${t}.${body}`).toString('hex')}`;
const STRIPE = (secretEnv = [ENV(1), ENV(2)]) => ({ header: 'x-event-id', signing: { scheme: 'stripe', signature: 'x-hooks-signature', secretEnv } });
const ENV_OF = { [ENV(1)]: secret(1), [ENV(2)]: secret(2) };

const sink = (t, destinations, { env = ENV_OF, signingClock = () => T * 1000, maxBodyBytes } = {}) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, env, signingClock, ...(maxBodyBytes ? { maxBodyBytes } : {}) });
  await o.start(); t.after(() => o.stop()); return o;
});
// A send through the sink, resolved with its reply's status and headers. chunks splits the body over several writes (chunked);
// trailers adds chunked trailers; abort writes part of the body and resets the connection.
const post = (port, headers = {}, { body = BODY, path = '/hooks', chunks = 0, trailers = null, abort = false } = {}) => new Promise(resolve => {
  const chunked = chunks > 0 || trailers !== null;
  const req = request({ host: '127.0.0.1', port, method: 'POST', path: `http://${HOOKS}${path}`, headers: { host: HOOKS, 'content-type': 'application/json', ...(chunked ? { 'transfer-encoding': 'chunked' } : { 'content-length': String(Buffer.byteLength(body)) }), ...headers } },
    res => { const reply = { status: res.statusCode, headers: Object.fromEntries(Object.entries(res.headers).filter(([k]) => k !== 'date')) }; res.resume(); res.on('end', () => resolve(reply)); });
  req.on('error', () => resolve(null));
  if (abort) { req.write(body.slice(0, 5)); setTimeout(() => req.destroy(), 20); return; }
  if (chunked) { const step = Math.ceil(body.length / Math.max(chunks, 1)); for (let i = 0; i < body.length; i += step) req.write(body.slice(i, i + step)); if (trailers) req.addTrailers(trailers); req.end(); } else req.end(body);
});
async function windowOf(o, between) {
  const from = await o.mark(); await between(); o.markWitnessRequest(from);
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark());
}
const verdict = (w, expected = 1) => { const d = evaluateEffectAssertion({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: HOOKS }, expected, countBy: 'idempotency-key' }, [w], { countBy: true }); return [d.verdict, d.applications && [d.applications.low, d.applications.high]]; };
const signedBy = (key, t, id, body = BODY) => ({ 'x-event-id': id, 'x-hooks-signature': stripeSig(Buffer.from(key), t, body) });

test('stripe through a real recorder: a re-sign under one declared secret is one application; a second secret, an undeclared one, a tampered body or a stale time is not', async t => {
  const o = await sink(t, [{ host: HOOKS, paths: ['/hooks'], idempotency: STRIPE() }]);
  assert.deepEqual(o.scope.idempotency[HOOKS].signing, { scheme: 'stripe', signature: 'x-hooks-signature', timestamp: null, id: null, dedupeSeconds: 300, secrets: 2 }, 'published without names');
  const resign = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'e-1')); await post(o.port, signedBy(secret(1), T + 30, 'e-1')); });
  assert.deepEqual([resign.coverage, ...verdict(resign)], ['complete', 'pass', [1, 1]]);
  assert.deepEqual(resign.events.map(e => [e.idempotency.signing.verified, e.idempotency.signing.t]), [[true, T], [true, T + 30]]);
  assert.ok(resign.events.every(e => e.idempotency.signing.at >= T && e.idempotency.signing.at <= T + 5), 'the arrival second counts on from the signing clock read at start');
  assert.equal(resign.events[0].idempotency.head, resign.events[1].idempotency.head, 'the verified header left head');
  const second = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'e-2')); await post(o.port, signedBy(secret(2), T + 5, 'e-2')); });
  assert.deepEqual(verdict(second), ['missing', [1, 2]], 'the second declared secret is another slot (required)');
  assert.ok(second.events.every(e => e.idempotency.signing.verified === true), 'both verified, each under its own secret');
  const undeclared = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'e-3')); await post(o.port, signedBy(secret(3), T + 5, 'e-3')); });
  assert.deepEqual([verdict(undeclared), undeclared.events[1].idempotency.signing.verified], [['missing', [1, 2]], false], 'an undeclared secret');
  const tampered = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'e-4')); await post(o.port, signedBy(secret(1), T, 'e-4'), { body: '{"id":"evt_1","type":"ticket.deleted"}' }); });
  assert.deepEqual([verdict(tampered), tampered.events[1].idempotency.signing.verified], [['missing', [1, 2]], false], 'a tampered body fails verification (required)');
  const stale = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'e-5')); await post(o.port, signedBy(secret(1), T + 400, 'e-5')); });
  assert.deepEqual([verdict(stale), stale.events[1].idempotency.signing.verified], [['missing', [1, 2]], false], 'a timestamp past the window stays bound (required)');
  const absent = await windowOf(o, async () => { await post(o.port, { 'x-event-id': 'e-6' }); await post(o.port, { 'x-event-id': 'e-6' }); });
  assert.deepEqual([verdict(absent), absent.events[0].idempotency.signing.verified], [['pass', [1, 1]], null], 'an exact unsigned replay');
  const text = JSON.stringify([resign, second, undeclared, tampered, stale]);
  for (const value of [secret(1), secret(2), Buffer.from(secret(1)).toString('hex'), stripeSig(Buffer.from(secret(1)), T).slice(16)]) assert.ok(!text.includes(value), 'no secret or MAC in a window');
  const plain = await sink(t, [{ host: HOOKS, paths: ['/hooks'], idempotency: { header: 'x-event-id' } }]);
  const unsigned = await windowOf(plain, async () => { await post(plain.port, signedBy(secret(1), T, 'e-1')); await post(plain.port, signedBy(secret(1), T + 30, 'e-1')); });
  assert.deepEqual([verdict(unsigned), unsigned.events[0].idempotency.signing], [['missing', [1, 2]], undefined], 'without signing the header is bound and no item is written');
});

test('standard-webhooks with a body-pointer key: the head is recomputed before the body key; the id header stays bound', async t => {
  const k = Buffer.alloc(32, 7), env = { [ENV(1)]: standardSecret(k) };
  const o = await sink(t, [{ host: HOOKS, paths: ['/hooks'], idempotency: { pointer: '/id', signing: { scheme: 'standard-webhooks', id: 'webhook-id', timestamp: 'webhook-timestamp', signature: 'webhook-signature', secretEnv: [ENV(1)] } } }], { env });
  const sw = (id, tt, body = BODY) => ({ 'webhook-id': id, 'webhook-timestamp': String(tt), 'webhook-signature': `v1,${mac(k, `${id}.${tt}.${body}`).toString('base64')}` });
  const resign = await windowOf(o, async () => { await post(o.port, sw('msg_1', T)); await post(o.port, sw('msg_1', T + 20)); });
  assert.deepEqual([...verdict(resign), resign.events.map(e => [e.idempotency.status, e.idempotency.signing.verified])], ['pass', [1, 1], [['keyed', true], ['keyed', true]]]);
  const body = '{"id":"evt_2","type":"ticket.updated"}';
  const newId = await windowOf(o, async () => { await post(o.port, sw('msg_2', T, body), { body }); await post(o.port, sw('msg_3', T + 20, body), { body }); });
  assert.deepEqual(newId.events.map(e => e.idempotency.signing.verified), [true, true]);
  assert.deepEqual(verdict(newId), ['missing', [1, 2]], 'the same body key under another webhook-id: verified both, but the id is bound');
});

test('the raw bytes decide: chunk boundaries do not matter; trailers, an over-limit body and an aborted send never verify', async t => {
  const o = await sink(t, [{ host: HOOKS, paths: ['/hooks'], idempotency: STRIPE() }], { maxBodyBytes: 1024 });
  const chunked = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'c-1')); await post(o.port, signedBy(secret(1), T + 9, 'c-1'), { chunks: 9 }); });
  assert.deepEqual(verdict(chunked), ['pass', [1, 1]]);
  const trailed = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'c-2')); await post(o.port, signedBy(secret(1), T + 9, 'c-2'), { chunks: 2, trailers: { 'x-account': 'b' } }); });
  assert.deepEqual([verdict(trailed), trailed.events[1].idempotency.signing.verified], [['missing', [1, 2]], false], 'a trailer makes the send unverified');
  const big = 'x'.repeat(2048), bigBody = `{"id":"evt_1","pad":"${big}"}`;
  const over = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'c-3', bigBody), { body: bigBody }); });
  assert.deepEqual(over.events.map(e => [e.idempotency.status, e.idempotency.signing.verified]), [['unreadable', false]]);
  const cut = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'c-4'), { abort: true }); await new Promise(r => setTimeout(r, 60)); });
  assert.deepEqual(cut.events.map(e => [e.idempotency.status, e.idempotency.signing.verified]), [['unreadable', false]]);
});

test('the signing clock is read once, at start: a wall-clock step later changes no window or bound', async t => {
  let reads = 0, now = T * 1000;
  const o = await sink(t, [{ host: HOOKS, paths: ['/hooks'], idempotency: STRIPE() }], { signingClock: () => { reads++; return now; } });
  now = (T - 3600) * 1000;
  const w = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 'k-1')); await post(o.port, signedBy(secret(1), T + 9, 'k-1')); });
  assert.deepEqual([reads, verdict(w)], [1, ['pass', [1, 1]]]);
});

test('the reply never depends on verification', async t => {
  const o = await sink(t, [{ host: HOOKS, paths: ['/hooks'], idempotency: STRIPE() }]);
  const verified = await post(o.port, signedBy(secret(1), T, 'r-1')), forged = await post(o.port, { 'x-event-id': 'r-1', 'x-hooks-signature': `t=${T},v1=${'0'.repeat(64)}` }), none = await post(o.port, { 'x-event-id': 'r-1' });
  assert.deepEqual(verified, forged); assert.deepEqual(verified, none);
});

test('refused when built: equivalent secrets, a signing secret that is a proof secret, too many secrets; messages name hosts and slots only', () => {
  const build = (destinations, env) => createEgressRecorder({ port: 47911, routing: 'proxy', witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, destinations, env, signingClock: () => T * 1000 });
  const k = Buffer.from('0123456789abcdef0123456789abcdef');
  const sw = secretEnv => ({ host: HOOKS, idempotency: { header: 'webhook-id', signing: { scheme: 'standard-webhooks', id: 'webhook-id', timestamp: 'webhook-timestamp', signature: 'webhook-signature', secretEnv } } });
  const equivalent = { [ENV(1)]: standardSecret(k), [ENV(2)]: standardSecret(Buffer.concat([k, Buffer.alloc(1)])) };
  assert.throws(() => build([sw([ENV(1), ENV(2)])], equivalent), /signing secrets 1 and 2 of hooks\.example\.test are the same HMAC key/, 'K and K plus 0x00');
  const proof = { host: 'pay.example.test', forward: { upstream: 'http://127.0.0.1:47912', proofEnv: 'SCOPEHAVEN_TARGET_PROOF' } };
  let message = '';
  try { build([{ host: HOOKS, idempotency: STRIPE([ENV(1)]) }, proof], { [ENV(1)]: secret(1), SCOPEHAVEN_TARGET_PROOF: secret(1) }); } catch (error) { message = error.message; }
  assert.match(message, /signing secret 1 of "hooks\.example\.test" is the forward proof secret of "pay\.example\.test"/);
  assert.ok(!message.includes(secret(1)), 'never the value');
  const many = Array.from({ length: 5 }, (_, i) => ({ host: `h${i}.example.test`, idempotency: STRIPE([1, 2, 3, 4].map(n => ENV(`${i}_${n}`))) }));
  assert.throws(() => build(many, {}), /at most 16 signing secrets/);
});

test('a missing or unusable secret degrades: the run goes on, that slot verifies nothing, and nothing is logged', async t => {
  const written = [], tap = stream => { const write = stream.write; stream.write = function (chunk, ...rest) { written.push(String(chunk)); return write.call(this, chunk, ...rest); }; return () => { stream.write = write; }; };
  const untap = [tap(process.stdout), tap(process.stderr)];
  try {
    const short = 'short-secret';
    const o = await sink(t, [{ host: HOOKS, paths: ['/hooks'], idempotency: STRIPE() }], { env: { [ENV(1)]: short } });
    assert.deepEqual(o.signingRecord(), { [HOOKS]: { scheme: 'stripe', usable: [false, false] } });
    const w = await windowOf(o, async () => { await post(o.port, signedBy(short, T, 'm-1')); await post(o.port, signedBy(short, T + 9, 'm-1')); });
    assert.deepEqual([verdict(w), w.events.map(e => e.idempotency.signing.verified)], [['missing', [1, 2]], [false, false]], 'headers stay bound (required)');
    assert.ok(!written.join('').includes(short), 'the unusable value is never written');
  } finally { untap.forEach(u => u()); }
});

test('after stop, a restarted recorder verifies nothing, not even under the zeroed (empty) key; the observer object holds no key', async t => {
  const o = await sink(t, [{ host: HOOKS, paths: ['/hooks'], idempotency: STRIPE([ENV(1)]) }]);
  const seen = inspect(o, { showHidden: true, depth: Infinity }) + JSON.stringify(o) + JSON.stringify(o.signingRecord());
  for (const value of [secret(1), Buffer.from(secret(1)).toString('hex')]) assert.ok(!seen.includes(value));
  await o.stop(); await o.start();
  const w = await windowOf(o, async () => { await post(o.port, signedBy(secret(1), T, 's-1')); await post(o.port, signedBy(secret(1), T + 9, 's-1')); });
  assert.deepEqual([verdict(w), w.events.map(e => e.idempotency.signing.verified)], [['missing', [1, 2]], [false, false]]);
  const empty = await windowOf(o, async () => { await post(o.port, signedBy('', T, 's-2')); await post(o.port, signedBy('', T + 9, 's-2')); });
  assert.deepEqual([verdict(empty), empty.events.map(e => e.idempotency.signing.verified)], [['missing', [1, 2]], [false, false]], 'a forgery under the empty key');
  assert.deepEqual(o.signingRecord()[HOOKS].usable, [true], 'the run still says which secrets were usable when the run started');
});

// An app whose routes deliver signed webhooks through its proxy (the sink): a re-sign under one secret, a delivery under two secrets,
// and a single delivery. It signs with the wall clock's seconds, as the factory's signing clock reads it.
async function hookApp(t, sinkPort, sent) {
  const deliver = (path, id, key, t) => new Promise(resolve => {
    const headers = signedBy(key, t, id);
    sent.push(headers['x-hooks-signature']);
    const req = request({ host: '127.0.0.1', port: sinkPort, method: 'POST', path: `http://${HOOKS}${path}`, headers: { host: HOOKS, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(BODY)), ...headers } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(BODY);
  });
  let n = 0;
  const server = createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return send(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return send(200, { user: 'ops' });
    if (url.pathname === '/ping') {
      await new Promise(resolve => { const r = request({ host: '127.0.0.1', port: sinkPort, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`, headers: { host: WITNESS } }, x => { x.resume(); x.on('end', resolve); }); r.on('error', resolve); r.end(); });
      return send(200, { ok: true });
    }
    const run = ++n, now = Math.floor(Date.now() / 1000);
    if (url.pathname === '/resign') { await deliver('/hooks/resign', `e-r-${run}`, secret(1), now); await deliver('/hooks/resign', `e-r-${run}`, secret(1), now + 1); }
    else if (url.pathname === '/second') { await deliver('/hooks/second', `e-s-${run}`, secret(1), now); await deliver('/hooks/second', `e-s-${run}`, secret(2), now + 1); }
    else if (url.pathname === '/once') await deliver('/hooks/once', `e-o-${run}`, secret(1), now);
    else return send(404, {});
    send(200, { ok: true });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const actorEnv = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const count = path => ({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: HOOKS, resource: `POST ${path}` }, expected: 1, countBy: 'idempotency-key' });
const check = (id, path, hook) => ({ id, title: id, category: 'hooks', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [count(hook)] });
const profileOf = (origin, port, secretEnv, extraDestinations = []) => ({ id: 'signed-hooks', name: 'Signed hooks', applicationId: 'signed-hooks', origin, buildLabel: 'b1', contextId: 'synthetic-signed-hooks',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: HOOKS, paths: ['/hooks/resign', '/hooks/second', '/hooks/once'], idempotency: STRIPE(secretEnv) }, ...extraDestinations],
    witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    check('RESIGN', '/resign', '/hooks/resign'), check('SECOND', '/second', '/hooks/second'), check('ONCE', '/once', '/hooks/once')] });
const assess = (t, env, sent, { secretEnv = [ENV(1), ENV(2)] } = {}) => onFreePorts(1, async port => {
  const p = profileOf(await hookApp(t, port, sent), port, secretEnv), watch = watchingBinds(buildObservers);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return { p, run: await runHttpAssessment(p, { env: { ...actorEnv, ...env }, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
}, r => r.lostBind);
const refused = detail => error => error.code === 'invalid-run-evidence' && error.detail === detail;
const reseal = (run, edit) => { const x = structuredClone(run); for (const row of x.results) if (row.trace?.[1]) { edit(row); row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); } return x; };

test('connector run: a verified re-sign passes a count of 1, two secrets read inconclusive, and the run binds signing', async t => {
  const sent = [];
  const { p, run: r } = await assess(t, ENV_OF, sent);
  const row = id => r.results.find(x => x.id === id);
  assert.deepEqual(['RESIGN', 'SECOND', 'ONCE'].map(id => row(id).status), ['pass', 'inconclusive', 'pass'], JSON.stringify(r.results.map(x => [x.id, x.status, x.assertions.map(a => a.actual)])));
  assert.deepEqual(r.signing, [{ observer: 'sink', host: HOOKS, scheme: 'stripe', usable: [true, true] }]);
  assert.equal(r.observers[0].collector.label, 'egress-recorder/13');
  assert.ok(r.limitations.includes(signingLimitation([{ host: HOOKS, dedupeSeconds: 300 }])));
  const suite = createRegistry({ profiles: [p], env: actorEnv }).exportSuite(p.id);
  validateHttpRunEvidence(r, { expectedSuite: suite });
  const noUsable = structuredClone(r); noUsable.signing[0].usable = [false, false];
  assert.throws(() => validateHttpRunEvidence(noUsable), refused('effect-trace'), 'a verified record needs a usable secret');
  const dropped = structuredClone(r); delete dropped.signing;
  assert.throws(() => validateHttpRunEvidence(dropped), error => error.code === 'invalid-run-evidence');
  const relabelled = structuredClone(r); relabelled.observers[0].collector.label = 'egress-recorder/4';
  assert.throws(() => validateHttpRunEvidence(relabelled), error => error.code === 'invalid-run-evidence', 'only egress-recorder/5 and later verify');
  const stripped = reseal(r, row => { for (const w of row.trace[1].data.windows) for (const e of w.events) delete e.idempotency?.signing; });
  assert.throws(() => validateHttpRunEvidence(stripped), error => error.code === 'invalid-run-evidence', 'a send on a signing host without its item');
});

test('a declared secret missing at run time: the run degrades with a limitation line and validates; a proof clash refuses the run', async t => {
  const { run: r } = await assess(t, { [ENV(1)]: secret(1) }, []);
  assert.deepEqual(r.signing[0].usable, [true, false]);
  assert.equal(r.results.find(x => x.id === 'SECOND').status, 'inconclusive');
  assert.ok(r.limitations.some(l => /Signing secrets of hooks\.example\.test \(observer sink\): 2 of 2 were missing or unusable/.test(l)));
  validateHttpRunEvidence(r);
  await onFreePorts(1, async port => {
    const p = profileOf('http://127.0.0.1:47950', port, [ENV(1)], [{ host: 'pay.example.test', forward: { upstream: `http://127.0.0.1:${port + 1 === 65536 ? port - 1 : port + 1}`, proofEnv: 'SCOPEHAVEN_TARGET_PROOF' } }]);
    await assert.rejects(runHttpAssessment(p, { env: { ...actorEnv, [ENV(1)]: secret(1), SCOPEHAVEN_TARGET_PROOF: secret(1) } }), error => /forward proof secret/.test(error.message) && !error.message.includes(secret(1)));
  });
});

// Test S: every form of each secret, and every signature value the app sent, is absent from every artifact a run writes: the run
// record, the saved store, the HTML report, SARIF, the exported suite, the limitations and anything written to stdout or stderr.
test('secret scan: no artifact holds a secret in any form, nor a MAC the app sent', async t => {
  const written = [], tap = stream => { const write = stream.write; stream.write = function (chunk, ...rest) { written.push(String(chunk)); return write.call(this, chunk, ...rest); }; return () => { stream.write = write; }; };
  const untap = [tap(process.stdout), tap(process.stderr)];
  const sent = [];
  let r, p;
  try { ({ run: r, p } = await assess(t, { ...ENV_OF, [ENV(3)]: 'short-secret' }, sent, { secretEnv: [ENV(1), ENV(2), ENV(3)] })); } finally { untap.forEach(u => u()); }
  // Not vacuous: the run used its secrets and verified sends.
  assert.deepEqual(r.signing[0].usable, [true, true, false]);
  assert.ok(r.results.some(row => row.trace?.[1]?.data.windows.some(w => w.events.some(e => e.idempotency?.signing?.verified === true))));
  assert.ok(sent.length >= 4);
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-signing-scan-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const saved = await createStore(dir).save(r);
  const files = [];
  const walk = async d => { for (const entry of await readdir(d, { withFileTypes: true })) { const path = join(d, entry.name); if (entry.isDirectory()) await walk(path); else files.push(await readFile(path, 'utf8')); } };
  await walk(dir);
  const artifacts = [JSON.stringify(r), JSON.stringify(saved), ...files, renderReport(saved), serializeSarif(r), JSON.stringify(createRegistry({ profiles: [p], env: actorEnv }).exportSuite(p.id)), r.limitations.join('\n'), written.join(''), inspect(r, { depth: Infinity })];
  const forms = value => {
    const bytes = Buffer.from(value);
    return [value, bytes.toString('hex'), bytes.toString('base64'), bytes.toString('base64url'), createHash('sha256').update(bytes).digest('hex'), createHmac('sha256', bytes).update('scopehaven-signing-fingerprint/1').digest('hex'),
      scryptSync(bytes, `scopehaven-signing-fingerprint/1\n${HOOKS}`, 32, { N: 16384, r: 8, p: 1 }).toString('hex')];
  };
  const needles = [...[secret(1), secret(2), 'short-secret'].flatMap(forms), ...sent, ...sent.map(s => s.split('v1=')[1])];
  for (const [i, text] of artifacts.entries()) for (const needle of needles) assert.ok(!text.includes(needle), `artifact ${i} holds a secret form or a sent MAC`);
});
