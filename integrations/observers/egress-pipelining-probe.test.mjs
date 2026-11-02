// Scoped-coverage acceptance probe: bytes pipelined in the same write behind a close are still recorded; bytes written
// after the server closed a connection are lost unseen. So a window with any server-made close in its range is never
// scoped (egress-scope-ineligible).
import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts } from './fixtures/free-port.mjs';

const PAY = 'pay.example.test', OTHER = 'hooks.example.test', WITNESS = 'witness.scopehaven.invalid';
const req = (host, path, body = '{}') => `POST http://${host}${path} HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
const raw = (port, data, { gapMs = 0, second = null } = {}) => new Promise(resolve => {
  const s = net.connect(port, '127.0.0.1', () => { s.write(data); if (second) setTimeout(() => s.write(second, () => {}), gapMs); });
  s.on('data', () => {}); s.on('error', () => {}); s.on('close', resolve);
  setTimeout(() => s.destroy(), gapMs + 1500);
});

test('probe: pipelined bytes behind a Connection: close or an over-limit destroy are recorded; bytes after an idle close are lost', async t => {
  const o = await onFreePorts(1, async port => {
    const r = createEgressRecorder({ instanceId: 'probe', port, routing: 'proxy', maxBodyBytes: 1024, destinations: [{ host: PAY, paths: ['/v1'] }, { host: OTHER }],
      replies: [{ host: PAY, path: '/v1/declined', status: 402, json: { error: 'declined' } }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 0, quietMs: 150 });
    await r.start(); t.after(() => r.stop()); return r;
  });
  const recorded = async run => { const from = await o.mark(); await run(); await new Promise(r => setTimeout(r, 300)); const w = await o.collect(from, await o.mark(), { scoped: true }); return { names: w.events.map(e => e.name), reason: w.reason }; };
  const p1 = await recorded(() => raw(o.port, req(PAY, '/v1/declined') + req(OTHER, '/x')));
  assert.deepEqual(p1.names, [PAY, OTHER], 'pipelined behind Connection: close');
  assert.match(p1.reason, /egress-scope-ineligible|egress-witness-not-received/);
  const p2 = await recorded(() => raw(o.port, req(PAY, '/v1/big', 'x'.repeat(2000)) + req(OTHER, '/x')));
  assert.deepEqual(p2.names, [PAY, OTHER], 'pipelined behind an over-limit destroy');
  // Written 8 s after the first request, well past Node's default 5 s keep-alive idle close (a 6 s gap raced it under load).
  const p4 = await recorded(() => raw(o.port, req(PAY, '/v1/ok'), { gapMs: 8000, second: req(OTHER, '/late') }));
  assert.deepEqual(p4.names, [PAY], 'written after the keep-alive idle close: never seen');
  // With a witness and a late unit on a fresh connection: the idle close in range keeps the window from being scoped; without it, scoped.
  const witnessed = async ({ idle }) => {
    const from = await o.mark();
    await raw(o.port, req(PAY, '/v1/ok'), idle ? { gapMs: 8000, second: '' } : {});
    o.markWitnessRequest(from);
    await raw(o.port, req(OTHER, '/late'));
    await raw(o.port, `GET http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)} HTTP/1.1\r\nHost: ${WITNESS}\r\nConnection: close\r\n\r\n`);
    return o.collect(from, await o.mark(), { scoped: true });
  };
  const idle = await witnessed({ idle: true });
  assert.equal(Object.hasOwn(idle, 'scoped'), false);
  assert.match(idle.reason, /egress-scope-ineligible/, 'the idle close is logged, so nothing is scoped');
  const control = await witnessed({ idle: false });
  assert.deepEqual(control.scoped?.map(e => [e.name, e.codes]), [[OTHER, ['egress-request-after-witness-request']]], `no server close: scoped (${control.reason})`);
  // A close the client asked for (the witness request above carried Connection: close) is never logged.
  // A pooled connection answered before the window's start mark, then closed by the idle timer inside the
  // window before any record arrives in it, still counts (closes are counted by mark position, not by the records around them).
  const pooled = raw(o.port, req(PAY, '/v1/ok'), { gapMs: 8000, second: '' });
  await new Promise(r => setTimeout(r, 300));
  const from = await o.mark();
  await pooled;
  o.markWitnessRequest(from);
  await raw(o.port, req(OTHER, '/late'));
  await raw(o.port, `GET http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)} HTTP/1.1\r\nHost: ${WITNESS}\r\nConnection: close\r\n\r\n`);
  const early = await o.collect(from, await o.mark(), { scoped: true });
  assert.equal(Object.hasOwn(early, 'scoped'), false, 'an idle close before the window\'s first record keeps it from being scoped');
  assert.match(early.reason, /egress-scope-ineligible/);
  // A mark this recorder did not make reads closed.
  const foreign = await o.collect({ ...(await o.mark()) }, await o.mark(), { scoped: true });
  assert.equal(Object.hasOwn(foreign, 'scoped'), false);
});
