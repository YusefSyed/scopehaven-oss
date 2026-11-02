// In-doubt resolution by the request feed end to end on loopback: a real egress recorder (egress-recorder/8 or later) that declares a request feed, a forward
// upstream double that applies a request (or not) and then resets the connection, so every send is in doubt, a provider stub that signs its
// request entries with a key made in this process, and a small app that sends each task's close through the recorder with its own
// idempotency key. runHttpAssessment and the shared validator, with the exported suite. Checked: reset after apply is confirmed, reset before
// apply is refuted under the watermark, a key the feed held before the run stays in doubt, and the same run without the feed reads as before; the
// sealed run holds no key, object id or tenant; the recorder writes arrivals only for feed hosts. Loopback only: 127.0.0.1, owned synthetic
// names and dummy secrets in an env object (never the process environment). No real provider, no hosted write, no spend.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { createRequestFeedStub } from './fixtures/request-feed-stub.mjs';
import * as C from './fixtures/in-doubt-r1-cases.mjs';

const { CRM, WITNESS } = C;
// Dummy forward proof secrets (the double never proves, so every outcome reads unknown), in an env object only.
const ENV = Object.freeze({ SCOPEHAVEN_TARGET_CRM_PROOF: 'synthetic-proof-secret-crm-0000000000000000', SCOPEHAVEN_TARGET_ALT_PROOF: 'synthetic-proof-secret-alt-0000000000000000' });
const KEY_OF = { 1: 'idem-ra-0001', 2: 'idem-rb-0002', 3: 'idem-old-0003' };
const APPLIES = new Set([KEY_OF[1], KEY_OF[3]]);

const listen = async (t, server) => { await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); })); return server.address().port; };
// The upstream: reads the whole request, records the provider's entry for the key when it applies it, then resets the connection.
async function upstreamDouble(t, feed) {
  const seen = [];
  const port = await listen(t, createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const key = req.headers['idempotency-key'];
      seen.push(key);
      if (APPLIES.has(key)) feed.add({ host: CRM, key, object: `obj-${key}`, state: 'closed' });
      req.socket.destroy();
    });
  }));
  return { port, seen };
}
// The app: each /task/N sends POST http://crm.example/tickets/T-1/close through the recorder (its proxy) with task N's key; /ping sends the
// witness; /me names the member.
async function appOf(t, sinkPort, task) {
  const outbound = (target, headers = {}, body) => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...headers, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(body);
  });
  return `http://127.0.0.1:${await listen(t, createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, {});
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, {}); }
    if (url.pathname !== '/task/1') return reply(404, {});
    await outbound(`http://${CRM}/tickets/T-1/close`, { 'idempotency-key': KEY_OF[task] }, JSON.stringify({ ticket: 'T-1' }));
    return reply(201, { closed: true });
  }))}`;
}
const verdictsOf = row => row.trace[1].data.effects.map(e => e.verdict);
const byOf = row => row.trace[1].data.effects[0].resolution?.attempts?.[0]?.by ?? null;

// One run with one task (a later task sending the same close would hold this one's counts at settlement, the run-level settlement rule).
const EFFECTS = { 1: [C.EXISTS, C.count(1), C.KEYED_COUNT(1)], 2: [C.EXISTS, C.KEYED_ONLY([])], 3: [C.EXISTS] };
async function scenario(t, { withFeed, task }) {
  const stub = await createRequestFeedStub({ feedId: 'crm-requests' }).listen();
  t.after(() => stub.close());
  stub.add({ host: CRM, key: KEY_OF[3], object: 'obj-before' });
  const up = await upstreamDouble(t, stub), alt = await upstreamDouble(t, stub);
  return onFreePorts(1, async port => {
    const feed = withFeed ? C.requestFeed({ endpoint: { port: stub.port, path: stub.path }, publicKey: stub.publicKey }) : null;
    const p = { ...C.profileOf([EFFECTS[task]], { feed }), origin: await appOf(t, port, task) };
    p.observers = [C.declaration({ feed, port, upstream: up.port, altUpstream: alt.port })];
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    const watch = watchingBinds(buildObservers);
    const run = await runHttpAssessment(p, { env: ENV, observerFactory: watch.factory });
    return { p, run, stub, up, lostBind: watch.state.lostBind };
  }, x => x.lostBind);
}

test('1. reset after apply is confirmed, reset before apply refuted under the watermark, a key the feed held before the run stays in doubt; each run validates with its suite', async t => {
  const runs = {};
  for (const task of [1, 2, 3]) {
    const { p, run, up } = await scenario(t, { withFeed: true, task });
    assert.deepEqual(up.seen, [KEY_OF[task]], `task ${task}: one close, with its own key`);
    const row = run.results.find(r => r.id === 'TASK1');
    assert.equal(row.trace[1].data.windows[0].coverage, 'complete', `task ${task}: ${row.trace[1].data.windows[0].reason}`);
    const suite = createRegistry({ profiles: [p], env: ENV }).exportSuite(p.id);
    validateHttpRunEvidence(run, { expectedSuite: suite });
    validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suite });
    runs[task] = { run, row };
  }
  const [t1, t2, t3] = [1, 2, 3].map(k => runs[k].row);
  assert.deepEqual([verdictsOf(t1), t1.status, t1.backendEvidence, byOf(t1)], [['pass', 'pass', 'pass'], 'pass', 'observed', 'r1'], 'reset after apply: confirmed (exists, exactly one, one keyed application)');
  assert.deepEqual([verdictsOf(t2), t2.status, byOf(t2)], [['fail', 'pass'], 'fail', 'r1'], 'reset before apply: refuted (the agent-write exists fails; nothing outside the set applied)');
  assert.deepEqual([verdictsOf(t3), t3.trace[1].data.effects[0].resolution.attempts[0].reason], [['missing'], 'key-history'], 'a key used before the run: in doubt');
  // Sealed: the recorder's transport carries the arrival on the feed host; every request-feed record is a read; nothing names a key, object or tenant.
  const e1 = t1.trace[1].data.windows[0].events[0];
  assert.deepEqual(Object.keys(e1.upstream.transport).sort(), ['arrivedMono', 'arrivedWall', 'connected', 'mono', 'wall']);
  assert.ok(e1.upstream.transport.arrivedMono <= e1.upstream.transport.mono && e1.upstream.transport.connected);
  const read = t1.trace[1].data.resolutions[0].records[0].read;
  assert.deepEqual([read.clear, read.key === e1.idempotency.key, read.entries.map(x => x.state), read.history, read.keySends, read.dirtySends], [true, true, ['applied'], 0, 1, 0]);
  for (const k of [1, 2, 3]) {
    const text = JSON.stringify(runs[k].run);
    for (const secret of [...Object.values(KEY_OF), `obj-${KEY_OF[1]}`, 'obj-before', ENV.SCOPEHAVEN_TARGET_CRM_PROOF]) assert.ok(!text.includes(secret), `run ${k} holds no "${secret}"`);
  }
  const { run } = runs[1];
  assert.deepEqual([run.observers[0].collector.label, run.observers[0].requestFeed.collector.label, run.observers[0].requestFeed.feedId], ['egress-recorder/13', 'request-feed/1', 'crm-requests']);
  assert.ok(run.limitations.some(l => /request feed/i.test(l)), 'the run says what the request feed rests on');
});

test('2. the same app and upstream with no request feed: the attempt stays in doubt, as before, and no arrival is recorded', async t => {
  const { p, run } = await scenario(t, { withFeed: false, task: 1 });
  const row = run.results.find(r => r.id === 'TASK1');
  assert.deepEqual(verdictsOf(row), ['missing', 'missing', 'missing']);
  assert.deepEqual(Object.keys(row.trace[1].data.windows[0].events[0].upstream.transport).sort(), ['connected', 'mono', 'wall']);
  assert.ok(run.results.every(r => !Object.hasOwn(r.trace?.[1]?.data ?? {}, 'resolutions')));
  assert.equal(Object.hasOwn(run.observers[0], 'requestFeed'), false);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: ENV }).exportSuite(p.id) });
});
