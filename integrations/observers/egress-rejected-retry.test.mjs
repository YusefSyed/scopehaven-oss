// Rejected retries end to end over real loopback HTTP: on a forwarded host, a send whose proven upstream status is in the destination's
// declared rejected list applied nothing, so a rejected attempt followed by a retry under the same key that the upstream applied
// counts once. Every other outcome only widens the interval. Every request goes to 127.0.0.1; destination hosts are names only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { createEgressRecorder } from './egress-recorder.mjs';
import { forwardProof } from './egress-forward.mjs';
import { onFreePorts } from './fixtures/free-port.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';

const PAY = 'payments.example.test', WITNESS = 'witness.scopehaven.invalid';
const PROOF_ENV = 'SCOPEHAVEN_TARGET_PAY_UPSTREAM_PROOF', SECRET = 'synthetic-upstream-proof-secret-0123456789abcdef', ENV = { [PROOF_ENV]: SECRET };
const sha = buffer => createHash('sha256').update(buffer).digest('hex');
// The upstream: 201 on .../ok, 402 on .../declined, 500 on .../error, a slow 200 on .../slow; every reply proven.
async function upstream(t) {
  let onceSlow = 0;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks), last = new URL(req.url, 'http://upstream').pathname.split('/').pop();
      const answer = status => { const nonce = req.headers['x-scopehaven-forward-nonce'];
        res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': '2', ...(nonce ? { 'X-Scopehaven-Forward-Proof': forwardProof(SECRET, { nonce, method: req.method, path: req.url, bodySha256: sha(body), contentType: req.headers['content-type'] ?? '', status }) } : {}) });
        res.end('{}'); };
      if (last === 'slow') return setTimeout(() => answer(200), 400);
      // Applies every request; the first one answers late (after the recorder's timeout), later ones at once.
      if (last === 'once-slow') return onceSlow++ === 0 ? setTimeout(() => answer(201), 400) : answer(201);
      answer(last === 'ok' ? 201 : last === 'declined' ? 402 : last === 'error' ? 500 : 200);
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return server.address().port;
}
const sink = (t, forward, idempotency = { header: 'idempotency-key' }) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', env: ENV, port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds'], idempotency, ...(forward ? { forward } : {}) }],
    witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
  await o.start(); t.after(() => o.stop()); return o;
});
const post = (port, path, key, body = '{"amount":25}') => new Promise(resolve => {
  const req = request({ host: '127.0.0.1', port, method: 'POST', path: `http://${PAY}/v1/refunds/${path}`, headers: { host: PAY, 'content-type': 'application/json', ...(key ? { 'idempotency-key': key } : {}) } }, res => { res.resume(); res.on('end', resolve); });
  req.on('error', resolve); req.end(body);
});
async function windowOf(o, between) {
  const from = await o.mark(); await between(); o.markWitnessRequest(from);
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark());
}
const count = expected => ({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: PAY }, expected, countBy: 'idempotency-key' });
const verdict = (w, expected = 1) => { const d = evaluateEffectAssertion(count(expected), [w], { countBy: true }); return [w.coverage, d.verdict, d.applications && [d.applications.low, d.applications.high], d.applications?.reason ?? null]; };
const forwardTo = (port, extra = {}) => ({ upstream: `http://127.0.0.1:${port}`, rejected: [402], proofEnv: PROOF_ENV, timeoutMs: 2000, maxReplyBytes: 1024, ...extra });

test('rejected then retried under one key: one application only for a proven, declared rejection', async t => {
  const up = await upstream(t);
  const o = await sink(t, forwardTo(up));
  const retried = await windowOf(o, async () => { await post(o.port, 'declined', 'k-1'); await post(o.port, 'ok', 'k-1', '{"amount":25,"card":"tok_2"}'); });
  assert.deepEqual(retried.events.map(e => e.upstream.outcome), ['rejected', 'applied']);
  assert.deepEqual(verdict(retried), ['complete', 'pass', [1, 1], null], 'the declined attempt applied nothing');
  const declined = await windowOf(o, async () => { await post(o.port, 'declined', 'k-2'); await post(o.port, 'declined', 'k-2'); });
  assert.deepEqual(verdict(declined), ['complete', 'fail', [0, 0], null], 'two declined attempts applied nothing');
  const replay = await windowOf(o, async () => { await post(o.port, 'ok', 'k-3'); await post(o.port, 'ok', 'k-3'); });
  assert.deepEqual(verdict(replay), ['complete', 'pass', [1, 1], null], 'an exact replay of an applied send');
  const errored = await windowOf(o, async () => { await post(o.port, 'ok', 'k-4'); await post(o.port, 'error', 'k-4'); });
  assert.deepEqual(verdict(errored).slice(0, 3), ['complete', 'missing', [1, 2]], 'a 5xx under one key may have applied too');
  const unknownOnly = await windowOf(o, async () => { await post(o.port, 'error', 'k-5'); await post(o.port, 'error', 'k-5'); });
  assert.deepEqual(verdict(unknownOnly), ['complete', 'missing', [0, 1], 'idempotency-key-outcome-unknown'], 'nothing proven applied');
  const keyless = await windowOf(o, async () => { await post(o.port, 'declined'); await post(o.port, 'ok'); });
  assert.deepEqual(verdict(keyless), ['complete', 'pass', [1, 1], null], 'a keyless rejected send applied nothing, a keyless applied one did');
  const keylessError = await windowOf(o, () => post(o.port, 'error'));
  assert.deepEqual(verdict(keylessError), ['complete', 'missing', [0, 1], 'idempotency-key-outcome-unknown']);
});

test('without a declared rejection, or without a proof, a rejection only widens the interval', async t => {
  const up = await upstream(t);
  const undeclared = await sink(t, forwardTo(up, { rejected: [] }));
  const w = await windowOf(undeclared, async () => { await post(undeclared.port, 'declined', 'k-1'); await post(undeclared.port, 'ok', 'k-1', '{"amount":25,"card":"tok_2"}'); });
  assert.deepEqual(w.events.map(e => e.upstream.outcome), ['unknown', 'applied']);
  assert.deepEqual(verdict(w).slice(0, 3), ['complete', 'missing', [1, 2]], 'an undeclared 402 may have applied');
  const unproven = await sink(t, forwardTo(up, { proofEnv: undefined }));
  const replay = await windowOf(unproven, async () => { await post(unproven.port, 'ok', 'k-2'); await post(unproven.port, 'ok', 'k-2'); });
  assert.deepEqual(replay.events.map(e => [e.upstream.outcome, e.upstream.proven]), [['unknown', false], ['unknown', false]]);
  assert.deepEqual(verdict(replay), ['complete', 'missing', [0, 1], 'idempotency-key-outcome-unknown'], 'an unproven forward decides no application');
  // The same exact replay on a host the sink does not forward keeps the re-signed redelivery rule: the declared provider applied it once.
  const plain = await sink(t, null);
  const sameReplay = await windowOf(plain, async () => { await post(plain.port, 'ok', 'k-3'); await post(plain.port, 'ok', 'k-3'); });
  assert.deepEqual(verdict(sameReplay), ['complete', 'pass', [1, 1], null]);
});

test('a same-key send while the first is still being forwarded overlaps; a rejected member never makes a pass', async t => {
  const up = await upstream(t);
  const o = await sink(t, forwardTo(up));
  const w = await windowOf(o, async () => { const first = post(o.port, 'slow', 'k-1'); await new Promise(r => setTimeout(r, 120)); await post(o.port, 'ok', 'k-1'); await first; });
  assert.deepEqual(w.events.map(e => e.idempotency.status), ['overlap', 'overlap']);
  assert.equal(verdict(w)[1], 'missing');
  const body = await sink(t, forwardTo(up), { pointer: '/event_id' });
  const pw = await windowOf(body, async () => { const first = post(body.port, 'slow', null, '{"event_id":"e-1"}'); await new Promise(r => setTimeout(r, 120)); await post(body.port, 'ok', null, '{"event_id":"e-1"}'); await first; });
  assert.ok(pw.events.some(e => e.idempotency.status === 'overlap'), 'a body key too');
  assert.equal(verdict(pw)[1], 'missing');
  // Applied, then a declared rejection, then an unknown under one key: the rejection drops out, the unknown keeps it open.
  const mixed = await windowOf(o, async () => { await post(o.port, 'ok', 'k-2'); await post(o.port, 'declined', 'k-2', '{"amount":26}'); await post(o.port, 'error', 'k-2', '{"amount":27}'); });
  assert.deepEqual(verdict(mixed).slice(0, 3), ['complete', 'missing', [1, 2]]);
});

test('a forward that times out leaves its key in flight: an identical retry the upstream applied never collapses into it', async t => {
  for (const idempotency of [{ header: 'idempotency-key' }, { pointer: '/event_id' }]) {
    const up = await upstream(t);
    const o = await sink(t, forwardTo(up, { timeoutMs: 100 }), idempotency);
    const key = idempotency.header ? 'k-1' : null, body = '{"event_id":"e-1","amount":25}';
    const w = await windowOf(o, async () => { await post(o.port, 'once-slow', key, body); await new Promise(r => setTimeout(r, 150)); await post(o.port, 'once-slow', key, body); });
    assert.deepEqual(w.events.map(e => e.upstream.outcome), ['unknown', 'applied'], JSON.stringify(idempotency));
    assert.deepEqual(w.events.map(e => e.idempotency.status), ['overlap', 'overlap'], 'the timed-out send may still be applying');
    assert.equal(verdict(w)[1], 'missing', 'the upstream may have applied both');
    await o.stop();
  }
});

test('a rejection that may still apply upstream can never be declared', async () => {
  const { validateForwardDeclaration } = await import('../../src/effect-outcome.mjs');
  for (const status of [408, 425, 429, 499]) assert.throws(() => validateForwardDeclaration({ upstream: 'http://127.0.0.1:47101', rejected: [status] }, 47000), /forward\.rejected/, String(status));
  assert.doesNotThrow(() => validateForwardDeclaration({ upstream: 'http://127.0.0.1:47101', rejected: [400, 402, 409, 422] }, 47000));
});
