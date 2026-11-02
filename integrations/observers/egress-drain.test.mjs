// The bounded run-end drain. Before the final mark each egress recorder waits, under one shared cap,
// until no request is arriving, no record is pending and its quiet period has passed since the latest arrival, forward settle
// or reply. A drain follows a recorder's late entries only when it ended quiescent, its final mark was clear and no record
// pending at a collect had its connection closed after it. Over real loopback HTTP; destination hosts are names only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import net from 'node:net';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts } from './fixtures/free-port.mjs';
import { collectWindow } from './events.mjs';
import { drainCapOf, followedDrains, validDrains, drainsDeclared } from '../../src/run-end-drain.mjs';
import { unfollowedLate } from '../../src/effect-events.mjs';

const PAY = 'payments.example.test', HOOKS = 'hooks.example.test', WITNESS = 'witness.scopehaven.invalid';
const PROOF_ENV = 'SCOPEHAVEN_TARGET_PAY_UPSTREAM_PROOF', ENV = { [PROOF_ENV]: 'synthetic-upstream-proof-secret-0123456789abcdef' };
// An upstream that answers /slow after delayMs and anything else at once (no proof, so every outcome reads unknown).
async function upstream(t, delayMs) {
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const answer = () => { if (!res.destroyed) { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 2 }); res.end('{}'); } };
    if (req.url.endsWith('/slow')) setTimeout(answer, delayMs); else answer();
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return server.address().port;
}
const sink = (t, up, { timeoutMs = 1000, quietMs = 150, drainTurn = null } = {}) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', env: ENV, drainTurn, port, routing: 'proxy', witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs,
    destinations: [{ host: PAY, paths: ['/v1'], forward: { upstream: `http://127.0.0.1:${up}`, rejected: [402], proofEnv: PROOF_ENV, timeoutMs, maxReplyBytes: 1024 } }, { host: HOOKS }] });
  await o.start(); t.after(() => o.stop()); return o;
});
const send = (port, target, method = 'POST') => new Promise(resolve => {
  const url = new URL(target);
  const req = request({ host: '127.0.0.1', port, method, path: target, headers: { host: url.host, 'content-type': 'application/json' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', () => resolve(null)); req.end(method === 'GET' ? undefined : '{}');
});
const pause = ms => new Promise(r => setTimeout(r, ms));

test('drain: quiet is measured from the last forward settle and reply, and the drain waits for a pending forward', async t => {
  const o = await sink(t, await upstream(t, 300));
  const forwarded = send(o.port, `http://${PAY}/v1/slow`);
  await pause(20);
  const d = await o.drain({ capMs: 5000 });
  assert.equal(await forwarded, 200);
  assert.equal(d.quiescent, true);
  // The arrival is ~20 ms old when the drain starts; the forward settles and is answered at ~300 ms, so quiet ends at ~450 ms.
  assert.ok(d.waitedMs >= 300 + 150 - 40, `waited ${d.waitedMs} ms: quiet must count the settle and the reply, and wait for the pending record`);
  assert.equal(d.closedAfterCollect, false);
});

test('drain: a forward held past the cap, or a stream that never goes quiet, is not quiescent', async t => {
  const o = await sink(t, await upstream(t, 1500), { timeoutMs: 3000 });
  const held = send(o.port, `http://${PAY}/v1/slow`);
  await pause(20);
  const d = await o.drain({ capMs: 400 });
  assert.equal(d.quiescent, false);
  assert.ok(d.waitedMs >= 380 && d.waitedMs < 1200, `waited ${d.waitedMs} ms`);
  await held;
  // A request still arriving through the whole drain (its request line and one header sent, the rest not yet, so nothing is recorded or
  // pending) keeps the recorder from ever being quiet. Quiet timing itself, an arrival inside the drain's last look, is covered
  // deterministically by the drain's own regression test. A stream of sends cannot cover it here: on a stalled host the
  // recorder can be truly quiet for quietMs between two of the stream's sends.
  const arriving = net.connect(o.port, '127.0.0.1');
  await new Promise(resolve => arriving.once('connect', resolve));
  const answered = new Promise(resolve => arriving.once('data', bytes => resolve(String(bytes).split(' ')[1])));
  arriving.write(`POST http://${HOOKS}/tick HTTP/1.1\r\nHost: ${HOOKS}\r\n`);
  const busy = await o.drain({ capMs: 600 });
  arriving.write('Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}');
  assert.equal(await answered, '202');
  arriving.destroy();
  assert.equal(busy.quiescent, false, 'a request still arriving through the drain is never quiet');
  assert.equal((await o.drain({ capMs: 0 })).quiescent, false, 'no time, no drain');
});

test('egress-recorder/12: a request recorded in the drain\'s last turn is an arrival; the drain reads quiet only quietMs after it', async t => {
  // The drain's last look waits one turn (drainTurn, setImmediate by default) for bytes already read but not yet parsed. Here that turn
  // sends one request and resolves only once the recorder has answered it, so a request read, recorded and answered inside the turn is
  // certain. Under /3 to /11 the last look checked only that nothing was arriving or pending, and read quiescent at once.
  let turns = 0, sentAt = null, port = null;
  const drainTurn = async () => { turns++; if (turns === 1) { sentAt = performance.now(); assert.equal(await send(port, `http://${HOOKS}/turn`), 202); } };
  const o = await sink(t, await upstream(t, 10), { drainTurn });
  port = o.port;
  const d = await o.drain({ capMs: 3000 });
  const since = performance.now() - sentAt;
  assert.ok(turns >= 2, `the drain looked again after the request (turns ${turns})`);
  assert.equal(d.quiescent, true);
  assert.ok(since >= 150, `quiescent ${Math.round(since)} ms after a request recorded in its last turn (quietMs 150)`);
});

test('markClear: idle at the mark reads clear; a pending record or an arriving request does not', async t => {
  const o = await sink(t, await upstream(t, 400));
  assert.equal(o.markClear(await o.mark()), true);
  const pending = send(o.port, `http://${PAY}/v1/slow`);
  await pause(60);
  assert.equal(o.markClear(await o.mark()), false, 'a forward still settling');
  await pending;
  assert.equal(o.markClear(await o.mark()), true);
  assert.equal(o.markClear({ ...(await o.mark()) }), false, 'a mark this recorder did not make');
});

test('closedAfterCollect: after a scoped collect left a late entry, a forward that fails at settle or any later server close is recorded; a quiet success is not', async t => {
  const window = async (o, path) => {
    const from = await o.mark(); const sent = send(o.port, `http://${PAY}/v1/${path}`); await pause(40); o.markWitnessRequest(from);
    await send(o.port, `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, 'GET');
    const w = await collectWindow(o, from, await o.mark(), { scoped: true });
    return { w, status: await sent };
  };
  // The forward times out (504) only after the window's witness request and scoped collect, however slow the host: the collect must see
  // it in flight. With a 300 ms bound a loaded host's witness and collect outlasted it, and the request had settled before the collect.
  const failing = await sink(t, await upstream(t, 6000), { timeoutMs: 3000 });
  const f = await window(failing, 'slow');
  assert.deepEqual(f.w.scoped?.map(e => e.codes), [['egress-request-in-flight']], JSON.stringify(f.w.reason));
  assert.equal(f.status, 504);
  await pause(50); // the 504's Connection: close ends the socket just after the reply is read
  assert.equal(failing.closedAfterCollect(), true);
  assert.equal((await failing.drain({ capMs: 2000 })).closedAfterCollect, true);
  // The same for the quiet success: it is still in flight at the collect (a late entry) and succeeds before its own 3000 ms bound.
  const ok = await sink(t, await upstream(t, 2000), { timeoutMs: 3000 });
  const s = await window(ok, 'slow');
  assert.equal(s.status, 200);
  assert.equal(ok.closedAfterCollect(), false);
  // Any close the recorder makes after that collect counts, here an over-limit body it destroys.
  const big = await new Promise(resolve => { const url = new URL(`http://${HOOKS}/big`); const req = request({ host: '127.0.0.1', port: ok.port, method: 'POST', path: url.href, headers: { host: url.host, 'content-type': 'application/json' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); req.on('error', () => resolve(null)); req.end('x'.repeat(2 * 1024 * 1024)); });
  assert.ok(big === 413 || big === null, String(big));
  await pause(50);
  assert.equal(ok.closedAfterCollect(), true);
  // A recorder with no late entry yet records nothing, whatever it closes.
  const fresh = await sink(t, await upstream(t, 10));
  await send(fresh.port, `http://${PAY}/v1/fast`);
  assert.equal(fresh.closedAfterCollect(), false);
});

test('drain: no time, a stopped listener or an unreadable state is never quiescent, and a stopped listener\'s mark is not clear', async t => {
  const o = await sink(t, await upstream(t, 10));
  assert.equal((await o.drain({ capMs: 0 })).quiescent, false, 'an idle recorder with no time');
  assert.equal((await o.drain({ capMs: NaN })).quiescent, false);
  assert.equal((await o.drain({ capMs: 2000 })).quiescent, true, 'the adjacent allowed case');
  await o.stop();
  assert.equal((await o.drain({ capMs: 2000 })).quiescent, false, 'the listener stopped');
  assert.equal(o.markClear(await o.mark()), false);
});

test('the shared cap, the drains record and the follow rule (pure)', () => {
  // The cap: the largest recorder's own, never past the time left; nothing left means no drain.
  assert.deepEqual([drainCapOf([1500, 3100], 10000), drainCapOf([1500, 3100], 2000.7), drainCapOf([1500], 0), drainCapOf([1500], -5), drainCapOf([], 9000), drainCapOf([1500], NaN)], [3100, 2000, 0, 0, 0, 0]);
  const observers = [{ id: 'sink', type: 'egress-recorder' }, { id: 'mail', type: 'smtp-sink' }, { id: 'pay', type: 'egress-recorder' }];
  const drain = (instanceId, extra = {}) => ({ instanceId, quiescent: true, waitedMs: 120, markClear: true, closedAfterCollect: false, ...extra });
  const ok = [drain('egress-recorder-sink'), drain('egress-recorder-pay', { quiescent: false })];
  assert.equal(validDrains(ok, observers), true);
  for (const bad of [[drain('egress-recorder-sink')], [...ok].reverse(), [drain('egress-recorder-sink', { waitedMs: -1 }), ok[1]], [drain('egress-recorder-sink', { waitedMs: 1.5 }), ok[1]],
    [drain('egress-recorder-sink', { markClear: 'yes' }), ok[1]], [{ ...drain('egress-recorder-sink'), extra: 1 }, ok[1]], [drain('smtp-sink-mail'), ok[1]], []])
    assert.equal(validDrains(bad, observers), false, JSON.stringify(bad));
  assert.deepEqual([...followedDrains([drain('a'), drain('b', { quiescent: false }), drain('c', { markClear: false }), drain('d', { closedAfterCollect: true })])], ['a']);
  // Declared only with attribution or a forwarded destination (a profile or a saved run's records).
  assert.deepEqual([drainsDeclared({ attribution: { background: [] } }), drainsDeclared({ observers: [{ type: 'egress-recorder', destinations: [{ host: PAY, forward: {} }] }] }), drainsDeclared({ observers: [{ type: 'egress-recorder', forward: { [PAY]: {} } }] }),
    drainsDeclared({ observers: [{ type: 'egress-recorder', destinations: [{ host: PAY }] }] }), drainsDeclared({})], [true, true, true, false, false]);
  // A followed drain follows every late entry of its recorder, on the last check and in flight; another recorder's does not.
  const late = (id, code) => ({ source: 'http-egress', instanceId: id, coverage: 'partial', reason: code, scoped: [{ name: HOOKS, resource: 'POST *', codes: [code] }], events: [] });
  const after = 'egress-request-after-witness-request', inflight = 'egress-request-in-flight';
  assert.deepEqual(unfollowedLate([[late('a', after)], [late('a', inflight)]], { followed: new Set(['a']) }).map(s => [...s]), [[], []]);
  assert.deepEqual(unfollowedLate([[late('a', after)], [late('a', inflight)]], { followed: new Set(['b']) }).map(s => [...s]), [[], ['a']]);
  assert.deepEqual(unfollowedLate([[late('a', after)]]).map(s => [...s]), [['a']], 'no drain: the last check stays unfollowed');
});

// Clocks and arriving connections.
// A step of the wall clock: Date.now jumps after the first few reads. Every quiet and elapsed comparison is monotonic.
const stepClock = (t, deltaMs, after = 2) => { const real = Date.now; let calls = 0; Date.now = () => real() + (calls++ >= after ? deltaMs : 0); t.after(() => { Date.now = real; }); return () => { Date.now = real; }; };
test('monotonic clock: a forward wall-clock step never fakes quiet for the drain', async t => {
  const o = await sink(t, await upstream(t, 10), { quietMs: 300 });
  await send(o.port, `http://${HOOKS}/recent`);
  const restore = stepClock(t, 3600000, 0);
  const d = await o.drain({ capMs: 2000 });
  restore();
  assert.equal(d.quiescent, true);
  assert.ok(d.waitedMs >= 200, `waited ${d.waitedMs} ms: the quiet period after the last reply is still waited out`);
});

test('monotonic clock: a backward wall-clock step never stalls a collect', async t => {
  const o = await sink(t, await upstream(t, 10));
  const from = await o.mark(); await send(o.port, `http://${HOOKS}/in-window`); o.markWitnessRequest(from);
  await send(o.port, `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, 'GET');
  const to = await o.mark();
  const restore = stepClock(t, -3600000);
  const w = await Promise.race([collectWindow(o, from, to), pause(8000).then(() => 'stalled')]);
  restore();
  assert.notEqual(w, 'stalled');
  assert.equal(w.coverage, 'complete', JSON.stringify(w.reason));
});

test('a freshly accepted connection that has sent nothing, or part of its headers, is never quiet; an idle kept-alive one is', async t => {
  const o = await sink(t, await upstream(t, 10), { quietMs: 100 });
  await pause(150);
  assert.equal((await o.drain({ capMs: 400 })).quiescent, true, 'nothing open');
  const s = net.connect(o.port, '127.0.0.1'); s.on('error', () => {}); t.after(() => s.destroy());
  await new Promise(r => s.on('connect', r)); await pause(150);
  // Node's parser state counts an accepted connection before its first byte (probe, pinned Node 24.21.0).
  assert.equal((await o.drain({ capMs: 400 })).quiescent, false, 'accepted, silent');
  assert.equal(o.markClear(await o.mark()), false);
  s.write(`POST http://${HOOKS}/x HTTP/1.1\r\nHost: ${HOOKS}`); await pause(150);
  assert.equal((await o.drain({ capMs: 400 })).quiescent, false, 'headers still arriving');
  s.write('\r\nContent-Length: 2\r\n\r\n{}'); await pause(300);
  // Answered and kept alive: the next request may still come, which the quiet period alone covers.
  assert.equal((await o.drain({ capMs: 1000 })).quiescent, true, 'idle after a complete request');
});

test('the ledger and the recorder read no wall clock (the clock tests only catch Date.now itself)', async () => {
  const { readFile } = await import('node:fs/promises');
  for (const name of ['sink-ledger.mjs', 'egress-recorder.mjs']) {
    const code = (await readFile(new URL(`./${name}`, import.meta.url), 'utf8')).replace(/\/\/.*$/gm, '');
    assert.doesNotMatch(code, /Date\.now|new Date\b|Date\(\)|timeOrigin|hrtime\.bigint|getTime\(/, name);
    assert.match(code, /performance\.now\(\)/, name);
  }
});
