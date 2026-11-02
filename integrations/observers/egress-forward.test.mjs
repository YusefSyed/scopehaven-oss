// Forwarding end to end over real loopback HTTP: a destination that declares `forward` has each recorded send
// forwarded, as recorded, to a declared loopback upstream, and its event records the upstream outcome. Only a proven,
// listed 2xx reads applied, only a proven, listed 4xx reads rejected, and everything else reads unknown, which never
// passes a clause that requires the outcome. Every connection goes to 127.0.0.1; destination hosts are names only.
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { request, createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts, watchingBinds, freePorts } from './fixtures/free-port.mjs';
import { buildObservers } from './factory.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { COLLECTOR_RECORDS } from '../../src/collector-identity.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { digest } from '../../src/domain.mjs';
import { FORWARD_LIMITATION } from '../../src/http-scope-text.mjs';
import { validateEgressConfig } from '../../src/egress-rules.mjs';
import { createEgressRecorder as createFrozenRecorder } from './fixtures/egress-recorder-d349c7c.mjs';
import { forwardProof } from './egress-forward.mjs';
import { buildObservers as buildSequenceObservers } from '../sequences/cli.mjs';

const PAY = 'payments.example.test', HOOKS = 'hooks.example.test', WITNESS = 'witness.scopehaven.invalid';
const sha = buffer => createHash('sha256').update(buffer).digest('hex');
// The upstream's proof secret: the recorder reads it from the dedicated namespace; the app is never given it.
const PROOF_ENV = 'SCOPEHAVEN_TARGET_PAY_UPSTREAM_PROOF', SECRET = 'synthetic-upstream-proof-secret-0123456789abcdef';
const ENV = { [PROOF_ENV]: SECRET };

// The upstream double: answers by path, and keeps what it received.
async function upstreamDouble(t, { slowMs = 1500 } = {}) {
  const received = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks), url = new URL(req.url, 'http://upstream');
      const nonces = req.rawHeaders.filter((h, i) => i % 2 === 0 && h.toLowerCase() === 'x-scopehaven-forward-nonce').length;
      received.push({ method: req.method, url: req.url, headers: req.headers, sha: sha(body), nonces });
      const last = url.pathname.split('/').pop();
      // The proof over what this upstream received and the status it answers (a "noproof" path omits it, "badproof" forges it).
      const proofOf = status => { const nonce = req.headers['x-scopehaven-forward-nonce']; if (!nonce || last === 'noproof') return {};
        return { 'X-Scopehaven-Forward-Proof': last === 'badproof' ? 'f'.repeat(64) : forwardProof(SECRET, { nonce, method: req.method, path: req.url, bodySha256: sha(body), contentType: req.headers['content-type'] ?? '', status }) }; };
      const json = (status, value, extra = {}) => { const text = JSON.stringify(value); res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text), 'X-Body-Sha256': sha(body), ...proofOf(status), ...extra }); res.end(text); };
      if (last === 'ok') return json(201, { id: 're_1', object: 'refund' });
      if (last === 'declined') return json(402, { error: 'card_declined' });
      if (last === 'conflict') return json(409, { error: 'conflict' });
      if (last === 'error') return json(500, { error: 'boom' });
      if (last === 'redirect') return json(302, {}, { Location: 'http://example.com/' });
      if (last === 'accepted') return json(202, { id: 're_queued' });
      if (last === 'slow') return setTimeout(() => json(200, { id: 're_slow' }), slowMs);
      if (last === 'big') { const text = 'x'.repeat(4096); res.writeHead(200, { 'Content-Length': text.length }); return res.end(text); }
      if (last === 'cut') { res.writeHead(200, { 'Content-Length': 100 }); res.write('0123456789'); return setTimeout(() => res.socket.destroy(), 20); }
      json(200, { ok: true });
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return { port: server.address().port, received };
}
const forwardOf = (port, extra = {}) => ({ upstream: `http://127.0.0.1:${port}`, rejected: [402], proofEnv: PROOF_ENV, timeoutMs: 1000, maxReplyBytes: 1024, ...extra });
const sink = (t, destinations, extra = {}) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', env: ENV, port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, ...extra });
  await o.start(); t.after(() => o.stop()); return o;
});
// One request through the sink as a proxy: { status, headers, body }.
const send = (port, target, body, headers = { 'content-type': 'application/json' }, method = 'POST') => new Promise(resolve => {
  const url = new URL(target);
  const req = request({ host: '127.0.0.1', port, method, path: target, headers: { host: url.host, ...headers } }, res => {
    const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
  });
  req.on('error', () => resolve({ status: null })); req.end(body);
});
async function windowOf(o, between) {
  const from = await o.mark(); const out = await between(); o.markWitnessRequest(from);
  await send(o.port, `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, undefined, {}, 'GET');
  return { w: await collectWindow(o, from, await o.mark()), out };
}
const sel = (name, extra = {}) => ({ source: 'http-egress', operation: 'send', name, ...extra });
// egress-recorder/6 adds each settled forward's target flags (exact path, query), and /7 its transport record
// (src/in-doubt.mjs: whether the TCP connect completed, and clock values that vary): the outcome fields are compared apart from them, and
// the flags read on their own.
const bare = u => { if (!u?.target && !u?.transport) return u; const { target: _t, transport: _p, ...rest } = u; return rest; };
const targetsOf = events => events.map(e => e.upstream?.target ?? null);
const connectedOf = events => events.map(e => e.upstream?.transport?.connected ?? null);
const applied = (kind, extra = {}) => ({ kind, select: sel(PAY, { upstream: 'applied' }), ...extra });
const verdict = (assertion, w) => evaluateEffectAssertion(assertion, [w]).verdict;

test('forwarded sends: the recorded bytes reach the upstream, its reply reaches the app, and its status decides the outcome', async t => {
  const up = await upstreamDouble(t);
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], capture: { pointers: ['/amount'] }, forward: forwardOf(up.port) }, { host: HOOKS }]);
  assert.deepEqual(o.scope.forward, { [PAY]: { upstreamPort: up.port, applied: [200, 201, 204], rejected: [402], proof: true } });
  const body = JSON.stringify({ amount: 25, currency: 'cad' });
  const { w, out } = await windowOf(o, async () => [
    await send(o.port, `http://${PAY}/v1/refunds/ok?expand=charge`, body, { 'content-type': 'application/json', 'proxy-connection': 'keep-alive', 'x-trace': 'abc', connection: 'x-trace', 'x-scopehaven-forward-nonce': 'app-chosen' }),
    await send(o.port, `http://${PAY}/v1/refunds/declined`, body),
    await send(o.port, `http://${PAY}/v1/refunds/conflict`, body),
    await send(o.port, `http://${PAY}/v1/refunds/error`, body),
    await send(o.port, `http://${PAY}/v1/refunds/redirect`, body),
    await send(o.port, `http://${HOOKS}/notify`, body),
  ]);
  assert.deepEqual([w.coverage, w.reason], ['complete', null]);
  // The app sees the upstream's own reply.
  assert.deepEqual(out.map(r => r.status), [201, 402, 409, 500, 302, 202]);
  assert.deepEqual(JSON.parse(out[0].body), { id: 're_1', object: 'refund' });
  assert.equal(out[0].headers['x-body-sha256'], sha(Buffer.from(body)), 'the upstream received exactly the recorded body');
  // The upstream received the recorded request: method, the named path and query, Host set to the destination, hop-by-hop headers dropped.
  assert.equal(up.received.length, 5, 'the unforwarded host never reaches the upstream');
  assert.deepEqual([up.received[0].method, up.received[0].url, up.received[0].headers.host], ['POST', '/v1/refunds/ok?expand=charge', PAY]);
  assert.equal(up.received[0].headers['proxy-connection'], undefined);
  assert.equal(up.received[0].headers['x-trace'], 'abc', 'a header the Connection header names is still forwarded: the upstream sees every header the record read');
  assert.equal(up.received[0].headers.connection, 'close', 'the app\'s own Connection header is not');
  assert.equal(up.received[0].nonces, 1, 'the app\'s own nonce header is dropped; the recorder sends one fresh nonce');
  assert.match(up.received[0].headers['x-scopehaven-forward-nonce'], /^[0-9a-f]{32}$/);
  assert.equal(out[0].headers['x-scopehaven-forward-proof'], undefined, 'the proof is not passed back to the app');
  // Recording is unchanged: the same send event, plus its upstream outcome.
  const proven = (outcome, status) => ({ outcome, status, proven: true });
  assert.deepEqual(w.events.map(e => bare(e.upstream) ?? null), [proven('applied', 201), proven('rejected', 402), proven('unknown', 409), proven('unknown', 500), proven('unknown', 302), null]);
  assert.deepEqual(targetsOf(w.events).slice(0, 5).map(t => [t.exact, typeof t.query]), Array(5).fill([false, 'boolean']), 'sub-paths of /v1/refunds: never exact');
  assert.deepEqual(connectedOf(w.events), [true, true, true, true, true, null], 'every forwarded send connected; the unforwarded one has no record');
  for (const e of w.events.slice(0, 5)) {
    assert.deepEqual([e.outcome, e.resource, e.captured.values['/amount']], ['committed', 'POST /v1/refunds', { type: 'number', value: 25 }]);
    assert.match(e.contentDigest, /^[a-f0-9]{64}$/);
  }
  assert.equal(Object.hasOwn(w.events[5], 'upstream'), false);
  // Judging: applied decides; rejected is not applied; anything else holds the clause at missing.
  assert.equal(verdict(applied('effect.exists'), w), 'pass');
  assert.equal(verdict(applied('effect.none'), w), 'fail');
  assert.equal(verdict({ kind: 'effect.none', select: sel(PAY) }, w), 'fail', 'without the requirement every attempt counts, as before');
  assert.equal(verdict({ kind: 'effect.none', select: sel(HOOKS, { upstream: 'applied' }) }, w), 'unobservable', 'an unforwarded host records no outcome');
  const one = async path => (await windowOf(o, () => send(o.port, `http://${PAY}/v1/refunds/${path}`, body))).w;
  const declined = await one('declined'), conflict = await one('conflict'), error = await one('error');
  assert.equal(verdict(applied('effect.none'), declined), 'pass', 'a declared rejection is not applied');
  assert.equal(verdict(applied('effect.exists'), declined), 'fail');
  assert.equal(verdict(applied('effect.count', { expected: 0 }), declined), 'pass');
  for (const [name, x] of [['409', conflict], ['500', error]]) {
    assert.equal(verdict(applied('effect.none'), x), 'missing', name);
    assert.equal(verdict(applied('effect.exists'), x), 'missing', name);
    assert.equal(verdict(applied('effect.count', { expected: 0 }), x), 'missing', name);
  }
  assert.equal(verdict(applied('effect.count', { expected: 1 }), w), 'missing', 'one applied send, but the unknown ones could be applied too');
});

test('no reply in full within the bounds reads unknown, and the app gets a gateway error', async t => {
  const up = await upstreamDouble(t);
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], forward: forwardOf(up.port, { timeoutMs: 300 }) }]);
  const { w, out } = await windowOf(o, async () => [
    await send(o.port, `http://${PAY}/v1/refunds/slow`, '{}'),
    await send(o.port, `http://${PAY}/v1/refunds/big`, '{}'),
    await send(o.port, `http://${PAY}/v1/refunds/cut`, '{}'),
  ]);
  assert.deepEqual(out.map(r => r.status), [504, 502, 502]);
  assert.deepEqual(w.events.map(e => bare(e.upstream)), Array(3).fill({ outcome: 'unknown', status: null, proven: false }));
  assert.deepEqual(connectedOf(w.events), [true, true, true], 'a timeout, an oversized and a cut reply all came after the connect');
  assert.equal(verdict(applied('effect.none'), w), 'missing');
  assert.equal(verdict(applied('effect.exists'), w), 'missing');
  // Nothing listens on the declared upstream port: a refused connection.
  const [closed] = await freePorts(1);
  const o2 = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], forward: forwardOf(closed) }]);
  const refused = await windowOf(o2, () => send(o2.port, `http://${PAY}/v1/refunds/ok`, '{}'));
  assert.equal(refused.out.status, 502);
  assert.deepEqual(bare(refused.w.events[0].upstream), { outcome: 'unknown', status: null, proven: false });
  assert.equal(refused.w.events[0].upstream.transport.connected, false, 'the transport record: the connect never completed');
  assert.equal(verdict(applied('effect.none'), refused.w), 'missing');
  // HTTPS through the proxy to a forwarded host: the tunnel is refused, never forwarded, and reads unknown.
  const tunnel = await windowOf(o, () => new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'CONNECT', path: `${PAY}:443` }); req.on('connect', (res, socket) => { socket.destroy(); resolve(res.statusCode); }); req.on('response', res => { res.resume(); resolve(res.statusCode); }); req.on('error', () => resolve(null)); req.end(); }));
  assert.equal(tunnel.w.coverage, 'partial');
  assert.deepEqual(tunnel.w.events.map(e => [e.resource, e.upstream]), [['CONNECT :443', { outcome: 'unknown', status: null, proven: false }]]);
});

test('a forward still in flight when the window is collected leaves it partial; its outcome is never read early', async t => {
  const up = await upstreamDouble(t, { slowMs: 1200 });
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], forward: forwardOf(up.port, { timeoutMs: 3000 }) }]);
  let pending;
  const { w } = await windowOf(o, async () => { pending = send(o.port, `http://${PAY}/v1/refunds/slow`, '{}'); await new Promise(r => setTimeout(r, 100)); });
  assert.equal(w.coverage, 'partial');
  assert.match(w.reason, /egress-request-in-flight/);
  assert.equal(w.events.length, 0);
  assert.equal(verdict(applied('effect.none'), w), 'missing');
  assert.equal((await pending).status, 200);
});

test('a forwarded body over the forward bound gets 413 and is never forwarded', async t => {
  const up = await upstreamDouble(t);
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], forward: forwardOf(up.port) }], { maxBodyBytes: 4 * 1024 * 1024 });
  const { w, out } = await windowOf(o, () => send(o.port, `http://${PAY}/v1/refunds/ok`, Buffer.alloc(1024 * 1024 + 1, 0x61)));
  assert.ok(out.status === 413 || out.status === null, String(out.status));
  assert.equal(up.received.length, 0);
  assert.equal(w.coverage, 'partial');
  assert.match(w.reason, /egress-body-over-limit/);
  assert.deepEqual(w.events[0].upstream, { outcome: 'unknown', status: null, proven: false });
});

test('allowlists and proof: 202, an unproven or wrongly proven reply, and a destination without a proof decide nothing', async t => {
  const up = await upstreamDouble(t);
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], forward: forwardOf(up.port) }]);
  const { w, out } = await windowOf(o, async () => [
    await send(o.port, `http://${PAY}/v1/refunds/accepted`, '{}'),
    await send(o.port, `http://${PAY}/v1/refunds/noproof`, '{}'),
    await send(o.port, `http://${PAY}/v1/refunds/badproof`, '{}'),
    await send(o.port, `http://${PAY}/v1/refunds/ok`, undefined, {}, 'GET'),
  ]);
  assert.deepEqual(out.map(r => r.status), [202, 200, 200, 201], 'the app still gets the upstream\'s reply');
  assert.deepEqual(w.events.map(e => bare(e.upstream)), [{ outcome: 'unknown', status: 202, proven: true }, { outcome: 'unknown', status: 200, proven: false }, { outcome: 'unknown', status: 200, proven: false },
    { outcome: 'unknown', status: 201, proven: true }], 'a proven 201 to a GET applied nothing');
  for (const kind of ['effect.none', 'effect.exists']) assert.equal(verdict(applied(kind), w), 'missing', kind);
  // A destination that declares no proof: statuses are recorded, nothing is decided.
  const o2 = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], forward: forwardOf(up.port, { proofEnv: undefined }) }]);
  assert.equal(o2.scope.forward[PAY].proof, false);
  const plainUp = await windowOf(o2, async () => [await send(o2.port, `http://${PAY}/v1/refunds/ok`, '{}'), await send(o2.port, `http://${PAY}/v1/refunds/declined`, '{}')]);
  assert.equal(up.received.at(-1).nonces, 0, 'no proof declared, no nonce sent');
  assert.deepEqual(plainUp.w.events.map(e => bare(e.upstream)), [{ outcome: 'unknown', status: 201, proven: false }, { outcome: 'unknown', status: 402, proven: false }]);
  assert.equal(verdict(applied('effect.none'), plainUp.w), 'missing');
  // A declared proof secret that is missing or short fails the recorder before it listens.
  for (const env of [{}, { [PROOF_ENV]: 'short' }]) assert.throws(() => createEgressRecorder({ port: 47011, env, destinations: [{ host: PAY, forward: forwardOf(47012) }] }), /forward proof/);
});

test('an upstream status outside 100 to 599 reads unknown, the app gets 502, and the process stays up', async t => {
  const raw = net.createServer(socket => { socket.on('data', () => socket.end('HTTP/1.1 099 Odd\r\nContent-Length: 0\r\n\r\n')); socket.on('error', () => {}); });
  await new Promise(r => raw.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => raw.close(r)));
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], forward: forwardOf(raw.address().port) }]);
  const { w, out } = await windowOf(o, () => send(o.port, `http://${PAY}/v1/refunds/ok`, '{}'));
  assert.equal(out.status, 502);
  assert.deepEqual(bare(w.events[0].upstream), { outcome: 'unknown', status: null, proven: false });
  assert.equal(w.events[0].upstream.transport.connected, true);
  assert.equal(verdict(applied('effect.exists'), w), 'missing');
});

test('the upstream receives every header the record read, also one the Connection header names', async t => {
  const up = await upstreamDouble(t);
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], capture: { pointers: ['/amount'] }, forward: forwardOf(up.port) }]);
  const { w } = await windowOf(o, () => send(o.port, `http://${PAY}/v1/refunds/ok`, JSON.stringify({ amount: 25 }), { 'content-type': 'application/json', connection: 'keep-alive, content-type' }));
  assert.equal(up.received[0].headers['content-type'], 'application/json', 'the content type capture read is the one the upstream received');
  assert.deepEqual(w.events[0].captured.values['/amount'], { type: 'number', value: 25 });
  assert.equal(verdict({ kind: 'effect.exists', select: sel(PAY, { upstream: 'applied', fields: [{ pointer: '/amount', equals: 25 }] }) }, w), 'pass');
});

test('forwarding leaves the idempotency key record as without it, except that a key stays in flight until its forward settles (header and body-pointer keys)', async t => {
  const up = await upstreamDouble(t);
  const destinations = forward => [{ host: PAY, paths: ['/v1/refunds'], idempotency: { header: 'idempotency-key' }, ...(forward ? { forward: forwardOf(up.port) } : {}) },
    { host: HOOKS, paths: ['/hooks'], idempotency: { pointer: '/id' }, ...(forward ? { forward: forwardOf(up.port, { proofEnv: undefined }) } : {}) }];
  const script = async port => {
    const k = key => ({ 'content-type': 'application/json', 'idempotency-key': key });
    await send(port, `http://${PAY}/v1/refunds/ok`, '{"amount":5}', k('k1'));
    await send(port, `http://${PAY}/v1/refunds/ok`, '{"amount":5}', k('k1'));
    await send(port, `http://${PAY}/v1/refunds/declined`, '{"amount":6}', k('k2'));
    await send(port, `http://${PAY}/v1/refunds/ok`, '{"amount":7}');
    await send(port, `http://${HOOKS}/hooks/ok`, '{"id":"evt_1"}');
    await send(port, `http://${HOOKS}/hooks/ok`, '{"id":"evt_1"}');
    // A same-key send that arrives while the first is still being forwarded: the upstream is still applying the first, so both
    // overlap (the key settles at the forward's settle point). Without forwarding the sink answers at once: sequential.
    const first = send(port, `http://${PAY}/v1/refunds/slow`, '{"amount":8}', k('k3'));
    await new Promise(r => setTimeout(r, 150));
    await send(port, `http://${PAY}/v1/refunds/ok`, '{"amount":8}', k('k3'));
    await first;
  };
  // Salted digests differ per recorder: compare statuses, first uses and which sends share a key, a fold, a head or a body.
  const shape = events => {
    const index = new Map(), id = v => v === null ? null : (index.has(v) ? index.get(v) : (index.set(v, index.size), index.size - 1));
    return events.map(e => ({ status: e.idempotency.status, firstSeq: e.idempotency.firstSeq, key: id(e.idempotency.key), fold: id(e.idempotency.fold), head: id(e.idempotency.head), body: id(e.contentDigest) }));
  };
  const observe = (make, forward) => onFreePorts(1, async port => {
    const o = make({ instanceId: 'egress-recorder-sink', ...(forward ? { env: ENV } : {}), port, routing: 'proxy', destinations: destinations(forward), witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
    await o.start(); t.after(() => o.stop());
    const { w } = await windowOf(o, () => script(port));
    return { coverage: w.coverage, events: w.events };
  });
  const [now, then] = [await observe(createEgressRecorder, true), await observe(createFrozenRecorder, false)];
  assert.equal(now.coverage, 'complete');
  assert.equal(now.events.length, 8);
  assert.deepEqual(shape(now.events).slice(0, 6), shape(then.events).slice(0, 6));
  assert.deepEqual(now.events.slice(6).map(e => e.idempotency.status), ['overlap', 'overlap'], 'concurrent with the forward');
  assert.deepEqual(then.events.slice(6).map(e => e.idempotency.status), ['keyed', 'keyed'], 'sequential without it');
  assert.deepEqual(shape(now.events).slice(6).map(({ status, ...rest }) => rest), shape(then.events).slice(6).map(({ status, ...rest }) => rest));
  assert.deepEqual(now.events.map(e => e.upstream?.outcome), ['applied', 'applied', 'rejected', 'applied', 'unknown', 'unknown', 'unknown', 'applied'], 'and each forwarded send still carries its own outcome');
});

test('guard: every connection made while forwarding goes to 127.0.0.1', async t => {
  const hosts = [];
  const connect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function (...args) {
    const a = args[0], options = Array.isArray(a) ? a[0] : a !== null && typeof a === 'object' ? a : { port: a, host: typeof args[1] === 'string' ? args[1] : undefined };
    // TCP connects only (a Unix socket has no port); an HTTP client's options also carry its request path.
    if (options?.port !== undefined) hosts.push(options?.host ?? 'localhost');
    return connect.apply(this, args);
  };
  t.after(() => { net.Socket.prototype.connect = connect; });
  const up = await upstreamDouble(t);
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], forward: forwardOf(up.port) }, { host: 'api.example.com' }]);
  await windowOf(o, async () => {
    for (const path of ['ok', 'declined', 'error', 'redirect', 'slow', 'big']) await send(o.port, `http://${PAY}/v1/refunds/${path}`, '{}');
    await send(o.port, 'http://api.example.com/x', '{}');
  });
  assert.ok(hosts.length >= 8, `the spy saw the connections (${hosts.length})`);
  assert.deepEqual([...new Set(hosts)], ['127.0.0.1']);
});

test('validation: the upstream is literal loopback, never the recorder, and a forwarded host takes no static replies', () => {
  const base = { port: 47001, destinations: [{ host: PAY }] };
  const withForward = forward => ({ ...base, destinations: [{ host: PAY, forward }] });
  assert.equal(validateEgressConfig(withForward({ upstream: 'http://127.0.0.1:47002' })).destinations[0].forward.port, 47002);
  for (const upstream of ['http://localhost:47002', 'http://10.0.0.1:80', 'http://127.0.0.2:47002', 'http://[::1]:47002', 'https://127.0.0.1:47002', 'http://127.0.0.1:47002/', 'http://127.0.0.1:47002/v1',
    'http://user@127.0.0.1:47002', 'http://127.0.0.1', 'http://127.0.0.1:80', 'http://127.0.0.1:47002?x=1', 'http://api.example.com:47002', 'http://0.0.0.0:47002', 'http://2130706433:47002', ' http://127.0.0.1:47002', 47002, null]) {
    assert.throws(() => validateEgressConfig(withForward({ upstream })), /forward\.upstream/, String(upstream));
  }
  assert.throws(() => validateEgressConfig(withForward({ upstream: 'http://127.0.0.1:47001' })), /own port/);
  for (const rejected of [[200], [302], [500], [402, 402], ['402'], Array.from({ length: 17 }, (_, i) => 400 + i), 402]) assert.throws(() => validateEgressConfig(withForward({ upstream: 'http://127.0.0.1:47002', rejected })), /forward\.rejected/, JSON.stringify(rejected));
  for (const extra of [{ timeoutMs: 99 }, { timeoutMs: 30001 }, { maxReplyBytes: 1023 }, { maxReplyBytes: 1048577 }, { host: '127.0.0.1' }]) assert.throws(() => validateEgressConfig(withForward({ upstream: 'http://127.0.0.1:47002', ...extra })), /forward/, JSON.stringify(extra));
  assert.throws(() => validateEgressConfig({ ...withForward({ upstream: 'http://127.0.0.1:47002' }), replies: [{ host: PAY, status: 200, json: { id: 'x' } }] }), /takes no "replies"/);
  assert.equal(Object.hasOwn(validateEgressConfig(base).destinations[0], 'forward'), false, 'no forward key unless declared');
  for (const applied of [[202], [200, 202], [206], [207], [302], [404], [], [200, 200], ['200']]) assert.throws(() => validateEgressConfig(withForward({ upstream: 'http://127.0.0.1:47002', applied })), /forward\.applied/, JSON.stringify(applied));
  for (const proofEnv of ['PAY_SECRET', 'SCOPEHAVEN_TARGET_', 'scopehaven_target_x', 7]) assert.throws(() => validateEgressConfig(withForward({ upstream: 'http://127.0.0.1:47002', proofEnv })), /forward\.proofEnv/, String(proofEnv));
  // Sequences never forward: their observers are not checked against a target origin.
  assert.throws(() => buildSequenceObservers([{ id: 'sink', type: 'egress-recorder', port: 47001, destinations: [{ host: PAY, forward: { upstream: 'http://127.0.0.1:47002' } }] }]), /cannot use an egress recorder destination with "forward"/);
});

test('differential compat against the frozen recorder copy: a recorder without forward records and answers exactly as before', async t => {
  const config = port => ({ port, routing: 'proxy', witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, maxBodyBytes: 2048,
    destinations: [{ host: PAY, paths: ['/v1/refunds'], capture: { pointers: ['/amount'], encodings: ['json', 'form'] }, correlation: { header: 'x-request-id' } }, { host: HOOKS }],
    replies: [{ host: PAY, method: 'POST', path: '/v1/refunds', status: 200, json: { id: 're_static' } }] });
  const script = async port => [
    await send(port, `http://${PAY}/v1/refunds`, JSON.stringify({ amount: 25 }), { 'content-type': 'application/json', 'x-request-id': '0b6c3f5e-1d2a-4c3b-9a8e-7f6d5c4b3a21' }),
    await send(port, `http://${PAY}/v1/refunds/A-1?x=1`, 'amount=30', { 'content-type': 'application/x-www-form-urlencoded' }),
    await send(port, `http://${PAY}/elsewhere`, '{}'),
    await send(port, `http://${HOOKS}/notify`, '{}'),
    await send(port, `http://${PAY}/v1/refunds`, 'x'.repeat(4096)),
    await send(port, `http://${PAY}/v1/refunds`, undefined, {}, 'GET'),
  ];
  const observe = make => onFreePorts(1, async port => {
    const o = make({ instanceId: 'egress-recorder-sink', ...config(port) });
    await o.start(); t.after(() => o.stop());
    const { w, out } = await windowOf(o, () => script(port));
    return { scope: o.scope, coverage: w.coverage, reason: w.reason, out: out.map(r => [r.status, r.body]), events: w.events.map(({ contentDigest, observedAt, ...rest }) => rest) };
  });
  const [now, then] = [await observe(createEgressRecorder), await observe(createFrozenRecorder)];
  assert.equal(now.events.length, 6, 'every send, the over-limit one included');
  assert.deepEqual(now, then);
});

// An app whose routes send a refund to the payments host through its proxy (the sink).
async function refundApp(t, sinkPort) {
  const outbound = (target, body) => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(body);
  });
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    const m = /^\/refund\/(ok|declined|conflict)$/.exec(url.pathname);
    if (!m) return reply(404, {});
    await outbound(`http://${PAY}/v1/refunds/${m[1]}`, JSON.stringify({ amount: 25 }));
    // The app claims failure whatever the provider did.
    reply(200, { status: 'failed' });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token', ...ENV };
const check = (id, path, extra) => ({ id, title: id, category: 'refunds', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...extra });
const profileOf = (origin, port, upstreamPort, checks) => ({ id: 'forward-refunds', name: 'Forward refunds', applicationId: 'forward-refunds', origin, buildLabel: 'b1', contextId: 'synthetic-forward-refunds',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds'], forward: { upstream: `http://127.0.0.1:${upstreamPort}`, rejected: [402], proofEnv: PROOF_ENV } }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] }, ...checks] });

test('connector run: the app claims failure; the upstream outcome decides, the run record and suite carry forward, tampering is refused', async t => {
  const up = await upstreamDouble(t);
  const noneApplied = { kind: 'effect.none', select: sel(PAY, { upstream: 'applied' }) };
  const runWith = checks => onFreePorts(1, async port => {
    const p = profileOf(await refundApp(t, port), port, up.port, checks);
    const watch = watchingBinds(buildObservers);
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    return { p, run: await runHttpAssessment(p, { env, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
  }, x => x.lostBind);
  // An allowed-use control that shows an applied send can be read here: the twin of the "nothing applied" pin.
  const twin = { ...check('SHOWN', '/refund/ok', { effects: [{ kind: 'effect.exists', select: sel(PAY, { upstream: 'applied' }) }] }), severity: 'control' };
  const { p, run: r } = await runWith([twin, check('OK', '/refund/ok', { effects: [noneApplied] }), check('CONFLICT', '/refund/conflict', { effects: [noneApplied] }), check('DECLINED', '/refund/declined', { effects: [noneApplied] })]);
  const row = id => r.results.find(x => x.id === id);
  assert.equal(row('SHOWN').status, 'pass', JSON.stringify(row('SHOWN').assertions));
  assert.equal(row('OK').status, 'fail', 'the provider applied the refund the app called failed');
  assert.equal(row('CONFLICT').status, 'inconclusive', 'an undeclared 409 could have been applied');
  assert.equal(row('DECLINED').status, 'pass', JSON.stringify(row('DECLINED').assertions));
  // Without the twin, "nothing applied" is not shown to be able to read applied in this setup: unpaired.
  const { run: alone } = await runWith([check('DECLINED', '/refund/declined', { effects: [noneApplied] })]);
  assert.equal(alone.results.find(x => x.id === 'DECLINED').status, 'inconclusive');
  assert.match(JSON.stringify(alone.results.find(x => x.id === 'DECLINED').assertions), /selector-unpaired/);
  const declared = { [PAY]: { upstreamPort: up.port, applied: [200, 201, 204], rejected: [402], proof: true } };
  assert.deepEqual(r.observers.map(o => o.collector), [COLLECTOR_RECORDS['egress-recorder']], 'the collector that built the windows');
  assert.deepEqual(r.observers.map(({ collector, ...o }) => o), [{ id: 'sink', type: 'egress-recorder', settleMs: 250, forward: declared }]);
  assert.ok(r.limitations.includes(FORWARD_LIMITATION));
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  assert.deepEqual(suite.observers[0].forward, declared);
  validateHttpRunEvidence(r, { expectedSuite: suite });
  const refused = detail => error => error.code === 'invalid-run-evidence' && error.detail === detail;
  const reseal = x => { x.evidenceDigest = digest({ evidence: x.trace[0].data, effects: x.trace[1].data, assertions: x.assertions }); };
  const forge = (onEvent, onWindow = () => {}) => { const f = structuredClone(r); for (const x of f.results) if (x.trace?.[1]) { for (const w of x.trace[1].data.windows) { w.events.forEach(onEvent); onWindow(w); } reseal(x); } return f; };
  // An outcome its status does not read, an outcome on its own, or a re-labelled status: refused or recomputed.
  assert.throws(() => validateHttpRunEvidence(forge(e => { if (e.upstream?.status === 402) e.upstream = { outcome: 'applied', status: 402, proven: true }; })), refused('effect-window-upstream'), 'applied needs a listable 2xx');
  assert.throws(() => validateHttpRunEvidence(forge(e => { if (e.upstream?.status === 402) e.upstream = { outcome: 'rejected', status: 402, proven: false }; })), refused('effect-window-upstream'), 'a decided outcome needs a proof');
  assert.throws(() => validateHttpRunEvidence(forge(e => { if (e.upstream?.status === 409) e.upstream = { outcome: 'rejected', status: 409, proven: true }; })), refused('effect-trace'), 'an undeclared status never reads rejected');
  assert.throws(() => validateHttpRunEvidence(forge(e => { if (e.upstream?.status === 201) e.upstream = { outcome: 'rejected', status: 402, proven: true }; })), refused('effect-verdict'));
  assert.throws(() => validateHttpRunEvidence(forge(() => {}, w => { w.scope.forward[PAY].proof = false; })), refused('effect-trace'), 'a proven outcome on a destination that declares no proof');
  assert.throws(() => validateHttpRunEvidence(forge(e => { delete e.upstream; })), refused('effect-trace'));
  assert.throws(() => validateHttpRunEvidence(forge(() => {}, w => { delete w.scope.forward; })), refused('effect-trace'));
  assert.throws(() => validateHttpRunEvidence(forge(e => { if (e.upstream?.status === 409) e.upstream = { outcome: 'rejected', status: 409, proven: true }; }, w => { w.scope.forward[PAY].rejected = [402, 409]; })), refused('effect-trace'));
  const stripped = structuredClone(r); delete stripped.observers[0].forward;
  assert.throws(() => validateHttpRunEvidence(stripped, { expectedSuite: suite }), error => error.code === 'unexpected-suite-evidence');
  // The profile refuses a proof secret that is also an actor's credential: the connector would send it to the app.
  const leaky = profileOf('http://127.0.0.1:47100', 47101, 47102, []);
  leaky.observers[0].destinations[0].forward.proofEnv = 'SCOPEHAVEN_TARGET_OPS';
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [leaky] }), /credential of actor "ops"/);
  // The profile refuses an upstream on the target origin's port or another observer's port.
  const origin = 'http://127.0.0.1:47100';
  const bad = (upstreamPort, observers = []) => ({ ...profileOf(origin, 47101, upstreamPort, []), observers: [...profileOf(origin, 47101, upstreamPort, []).observers, ...observers] });
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [bad(47100)] }), /target origin/);
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [bad(47102, [{ id: 'sink2', type: 'egress-recorder', port: 47102, destinations: [{ host: HOOKS }] }])] }), /port of observer "sink2"/);
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [bad(47103, [{ id: 'sink2', type: 'egress-recorder', port: 47102, destinations: [{ host: HOOKS }] }])] }));
});
