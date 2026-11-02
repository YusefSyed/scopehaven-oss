// Keyed retries end to end over real loopback HTTP: an egress destination that declares an idempotency header records a
// salted key record on each send, and an effect.count clause with countBy "idempotency-key" counts an exact keyed replay
// once. Every request goes to 127.0.0.1; destination hosts are names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts, watchingBinds } from './fixtures/free-port.mjs';
import { buildObservers } from './factory.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { COLLECTOR_RECORDS } from '../../src/collector-identity.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { digest } from '../../src/domain.mjs';
import { IDEMPOTENCY_LIMITATION } from '../../src/http-scope-text.mjs';

const PAY = 'payments.example.test', WITNESS = 'witness.scopehaven.invalid';
const IDEM = { header: 'idempotency-key', volatile: ['traceparent'] };
const sink = (t, destinations) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
  await o.start(); t.after(() => o.stop()); return o;
});
// A send through the sink; `hold` delays the body's end so another send can overlap it.
const post = (port, headers = {}, { body = '{"amount":25}', method = 'POST', hold = null, target = `http://${PAY}/v1/refunds` } = {}) => new Promise(resolve => {
  const req = request({ host: '127.0.0.1', port, method, path: target, headers: { host: PAY, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)), ...headers } }, res => { res.resume(); res.on('end', resolve); });
  req.on('error', resolve);
  if (hold) { req.write(body.slice(0, 1)); hold.then(() => req.end(body.slice(1))); } else req.end(body);
});
async function windowOf(o, between) {
  const from = await o.mark(); await between(); o.markWitnessRequest(from);
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark());
}
const count = (expected, extra = {}) => ({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: PAY, ...extra }, expected, countBy: 'idempotency-key' });
const verdict = (w, expected) => { const d = evaluateEffectAssertion(count(expected), [w], { countBy: true }); return [d.verdict, d.applications && [d.applications.low, d.applications.high]]; };

test('sink: key records are salted digests; an exact replay is one application, a new key or a changed request is not', async t => {
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], idempotency: IDEM }, { host: 'hooks.example.test' }]);
  assert.deepEqual(o.scope.idempotency, { [PAY]: { header: 'idempotency-key', pointer: null, methods: ['POST'], volatile: ['traceparent'], maxBytes: null } });
  const replay = await windowOf(o, async () => {
    await post(o.port, { 'Idempotency-Key': 'refund-7f3a', traceparent: '00-a-b-01' });
    await post(o.port, { 'idempotency-key': 'refund-7f3a', traceparent: '00-c-d-01' });
  });
  assert.deepEqual([replay.coverage, replay.reason], ['complete', null]);
  const [a, b] = replay.events;
  assert.equal(a.idempotency.status, 'keyed');
  assert.deepEqual([b.idempotency.key, b.idempotency.fold, b.idempotency.head, b.idempotency.firstSeq], [a.idempotency.key, a.idempotency.fold, a.idempotency.head, a.seq], 'header-name case and a declared volatile header do not matter');
  assert.ok(!JSON.stringify(replay).includes('refund-7f3a'), 'the key itself is never stored');
  assert.deepEqual(verdict(replay, 1), ['pass', [1, 1]]);
  assert.equal(evaluateEffectAssertion({ kind: 'effect.count', select: count(2).select, expected: 2 }, [replay]).verdict, 'pass', 'a plain count still counts sends');
  const twoKeys = await windowOf(o, async () => { await post(o.port, { 'idempotency-key': 'k-1' }); await post(o.port, { 'idempotency-key': 'k-2' }); });
  assert.deepEqual(verdict(twoKeys, 1), ['fail', [2, 2]], 'two keys are two applications');
  const keyless = await windowOf(o, async () => { await post(o.port, { 'idempotency-key': 'k-3' }); await post(o.port); });
  assert.deepEqual(verdict(keyless, 1), ['fail', [2, 2]], 'a retry that drops its key is a double');
  const changed = await windowOf(o, async () => { await post(o.port, { 'idempotency-key': 'k-4' }); await post(o.port, { 'idempotency-key': 'k-4' }, { body: '{"amount":250}' }); });
  assert.deepEqual(verdict(changed, 1), ['missing', [1, 2]], 'same key, changed body');
  const reauth = await windowOf(o, async () => { await post(o.port, { 'idempotency-key': 'k-5', authorization: 'Bearer a' }); await post(o.port, { 'idempotency-key': 'k-5', authorization: 'Bearer b' }); });
  assert.deepEqual(verdict(reauth, 1), ['missing', [1, 2]], 'Authorization is bound');
  const variant = await windowOf(o, async () => { await post(o.port, { 'idempotency-key': 'K-6' }); await post(o.port, { 'idempotency-key': '"k-6"' }); });
  assert.equal(variant.events[0].idempotency.fold, variant.events[1].idempotency.fold);
  assert.deepEqual(verdict(variant, 1), ['missing', [1, 2]], 'case and quote variants');
  const repeated = await windowOf(o, () => new Promise(resolve => {
    const req = request({ host: '127.0.0.1', port: o.port, method: 'POST', path: `http://${PAY}/v1/refunds`, headers: [['host', PAY], ['idempotency-key', 'k-7'], ['idempotency-key', 'k-7']].flat() }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end('{}');
  }));
  assert.equal(repeated.events[0].idempotency.status, 'repeated');
  assert.deepEqual(verdict(repeated, 1), ['missing', [0, 1]]);
  const get = await windowOf(o, () => post(o.port, { 'idempotency-key': 'k-8' }, { method: 'GET', body: '' }));
  assert.equal(get.events[0].idempotency.status, 'not-applicable');
  const hooks = await windowOf(o, () => new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'POST', path: 'http://hooks.example.test/x', headers: { host: 'hooks.example.test' } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end('{}'); }));
  assert.equal(Object.hasOwn(hooks.events[0], 'idempotency'), false, 'an undeclared host carries no key record');
});

test('sink: concurrent sends under one key overlap; a key or an unreadable send seen earlier makes later uses inconclusive', async t => {
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], idempotency: IDEM }]);
  let release;
  const held = new Promise(r => { release = r; });
  const both = await windowOf(o, async () => {
    const first = post(o.port, { 'idempotency-key': 'c-1' }, { hold: held });
    await new Promise(r => setTimeout(r, 50));
    await post(o.port, { 'idempotency-key': 'c-1' });
    release(); await first;
  });
  assert.deepEqual(both.events.map(e => e.idempotency.status), ['overlap', 'overlap']);
  assert.deepEqual(verdict(both, 1), ['missing', [1, 2]]);
  const before = await windowOf(o, () => post(o.port, { 'idempotency-key': 'e-1' }));
  assert.deepEqual(verdict(before, 1), ['pass', [1, 1]]);
  const again = await windowOf(o, () => post(o.port, { 'idempotency-key': 'e-1' }));
  assert.equal(again.events[0].idempotency.firstSeq, before.events[0].seq);
  assert.deepEqual(verdict(again, 1), ['missing', [0, 1]], 'a key first used in an earlier window');
  await windowOf(o, () => post(o.port, { 'idempotency-key': 'bad key' }));
  const after = await windowOf(o, () => post(o.port, { 'idempotency-key': 'f-1' }));
  assert.deepEqual(verdict(after, 1), ['missing', [0, 1]], 'a malformed key earlier in the run');
});

test('sink: a keyed request the recorder refuses or files under another name makes a later use of any key inconclusive', async t => {
  for (const [label, earlier] of [
    ['a browser-origin request', port => post(port, { 'idempotency-key': 'g-1', origin: 'http://evil.test' })],
    ['a host mismatch', port => new Promise(resolve => { const req = request({ host: '127.0.0.1', port, method: 'POST', path: 'http://other.example.test/v1/refunds', headers: { host: PAY, 'idempotency-key': 'g-1' } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end('{}'); })],
  ]) {
    const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], idempotency: IDEM }]);
    await windowOf(o, () => earlier(o.port));
    const later = await windowOf(o, () => post(o.port, { 'idempotency-key': 'g-1' }));
    assert.deepEqual([later.coverage, ...verdict(later, 1)], ['complete', 'missing', [0, 1]], label);
    await o.stop();
  }
});

// An app whose routes send refunds through its proxy (the sink): the same key twice, two keys, or one send.
async function keyedApp(t, sinkPort) {
  const outbound = (target, headers) => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: sinkPort, method: headers === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(headers === undefined ? {} : { 'content-type': 'application/json', ...headers }) } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(headers === undefined ? undefined : '{"amount":25}');
  });
  let n = 0;
  // '/order': the allowed use, one keyed order on its own path (the profile's ORDER control).
  const routes = { '/refund/retry': ['/v1/retry', ['r', 'r']], '/refund/double': ['/v1/double', ['d1', 'd2']], '/refund/once': ['/v1/once', ['o']], '/refund/reuse': ['/v1/reuse', ['fixed']], '/order': ['/v1/orders', ['order']] };
  const server = createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return send(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return send(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return send(200, { ok: true }); }
    if (!Object.hasOwn(routes, url.pathname)) return send(404, {});
    const run = ++n;
    const [path, keys] = routes[url.pathname];
    for (const key of keys) await outbound(`http://${PAY}${path}`, { 'idempotency-key': key === 'fixed' ? key : `${key}-${run}` });
    send(200, { ok: true });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const check = (id, path, effects) => ({ id, title: id, category: 'refunds', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects });
// ORDER is the actor's required allowed-use control with a positive effect (one keyed order on its own path), so an unpinned
// effect.only is guarded.
const profileOf = (origin, port, checks) => ({ id: 'keyed-refunds', name: 'Keyed refunds', applicationId: 'keyed-refunds', origin, buildLabel: 'b1', contextId: 'synthetic-keyed-refunds',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'ORDER'],
  observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/retry', '/v1/double', '/v1/once', '/v1/reuse', '/v1/orders'], idempotency: { header: 'idempotency-key' } }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'ORDER', title: 'An order is placed', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/order', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }],
      effects: [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/orders' } }] }, ...checks] });
const run = (t, checks) => onFreePorts(1, async port => {
  const p = profileOf(await keyedApp(t, port), port, checks), watch = watchingBinds(buildObservers);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return { p, run: await runHttpAssessment(p, { env, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('connector run: countBy counts applications, the run binds the declaration, and a forged interval or scope is refused', async t => {
  // Each check's sends go to its own path, so no check's sends fit another's selector (settlement would withhold a count pass).
  const at = path => count(1, { resource: `POST ${path}` });
  const { p, run: r } = await run(t, [check('RETRY', '/refund/retry', [at('/v1/retry'), { kind: 'effect.count', select: at('/v1/retry').select, expected: 2 }]), check('DOUBLE', '/refund/double', [at('/v1/double')]), check('ONCE', '/refund/once', [at('/v1/once')]), check('REUSE-A', '/refund/reuse', [at('/v1/reuse')]), check('REUSE-B', '/refund/reuse', [at('/v1/reuse')])]);
  const row = id => r.results.find(x => x.id === id);
  assert.equal(row('RETRY').status, 'pass', JSON.stringify(row('RETRY').assertions));
  assert.equal(row('DOUBLE').status, 'fail', 'two keys for one refund is a double');
  assert.equal(row('ONCE').status, 'pass');
  assert.equal(row('REUSE-B').status, 'inconclusive', 'a key the app already used in an earlier check');
  assert.match(row('RETRY').assertions.find(a => a.name === 'Observed effect 1 (effect.count)').expected, /application/);
  assert.deepEqual(r.observers.map(o => o.collector), [COLLECTOR_RECORDS['egress-recorder']], 'the collector that built the windows');
  assert.deepEqual(r.observers.map(({ collector, ...o }) => o), [{ id: 'sink', type: 'egress-recorder', settleMs: 250, idempotency: { [PAY]: { header: 'idempotency-key', pointer: null, methods: ['POST'], volatile: [], maxBytes: null } } }]);
  assert.ok(r.limitations.includes(IDEMPOTENCY_LIMITATION));
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  validateHttpRunEvidence(r, { expectedSuite: suite });
  const refused = detail => error => error.code === 'invalid-run-evidence' && error.detail === detail;
  const reseal = x => { x.evidenceDigest = digest({ evidence: x.trace[0].data, effects: x.trace[1].data, assertions: x.assertions }); };
  const forged = structuredClone(r), fx = forged.results.find(x => x.id === 'DOUBLE');
  fx.trace[1].data.effects[0].applications = { low: 1, high: 1, reason: null }; reseal(fx);
  assert.throws(() => validateHttpRunEvidence(forged), refused('effect-verdict'));
  const merged = structuredClone(r), mx = merged.results.find(x => x.id === 'DOUBLE');
  const [k1, k2] = mx.trace[1].data.windows[0].events;
  Object.assign(k2.idempotency, { key: k1.idempotency.key, fold: k1.idempotency.fold, firstSeq: k1.idempotency.firstSeq }); reseal(mx);
  assert.throws(() => validateHttpRunEvidence(merged), refused('effect-verdict'), 'a key record rewritten to merge two keys is caught on recompute');
  const stripped = structuredClone(r);
  for (const x of stripped.results) if (x.trace?.[1]) { for (const w of x.trace[1].data.windows) delete w.scope.idempotency; reseal(x); }
  assert.throws(() => validateHttpRunEvidence(stripped), refused('effect-trace'));
  // A scope whose declaration was widened (another method keyed) while every event still carries its record.
  const widened = structuredClone(r);
  for (const x of widened.results) if (x.trace?.[1]) { for (const w of x.trace[1].data.windows) w.scope.idempotency[PAY].methods = ['POST', 'PUT']; reseal(x); }
  assert.throws(() => validateHttpRunEvidence(widened), refused('effect-trace'), 'the published declaration must equal the run\'s');
  // A first use edited in one row only (REUSE-B claims the key's first use) is caught against the earlier row.
  const reused = structuredClone(r), rx = reused.results.find(x => x.id === 'REUSE-B');
  for (const e of rx.trace[1].data.windows[0].events) if (e.idempotency?.fold) e.idempotency.firstSeq = e.seq;
  reseal(rx);
  assert.throws(() => validateHttpRunEvidence(reused), refused('effect-trace'));
  const strippedSuite = structuredClone(suite); delete strippedSuite.observers[0].idempotency;
  assert.throws(() => validateHttpRunEvidence(r, { expectedSuite: strippedSuite }), error => error.code === 'unexpected-suite-evidence');
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [{ ...p, observers: [{ ...p.observers[0], destinations: [{ host: PAY, paths: ['/v1/retry', '/v1/double', '/v1/once', '/v1/reuse'] }] }] }] }), /effect-count-by-unrecorded/);
});

// effect.only with countBy "idempotency-key", end to end. The pass is the last check with sends: a
// later committed send would withhold an effect.only pass (settlement), whatever its key.
test('connector run: an effect.only countBy clause counts an exact keyed retry once; without countBy it is a second send', async t => {
  const onlyAt = (path, extra = {}) => ({ kind: 'effect.only', expect: [{ source: 'http-egress', operation: 'send', name: PAY, resource: `POST ${path}` }], allow: [], operations: ['send'], ...extra });
  const keyed = { countBy: 'idempotency-key' };
  const { run: r } = await run(t, [check('RAW', '/refund/retry', [onlyAt('/v1/retry')]), check('DOUBLE', '/refund/double', [onlyAt('/v1/double', keyed)]), check('RETRY', '/refund/retry', [onlyAt('/v1/retry', keyed)])]);
  const row = id => r.results.find(x => x.id === id);
  assert.equal(row('RAW').status, 'fail', 'without countBy the keyed retry is a second send beyond the count');
  assert.equal(row('DOUBLE').status, 'fail', 'two keys for one refund is a double');
  assert.equal(row('RETRY').status, 'pass', JSON.stringify(row('RETRY').assertions));
  assert.match(row('RETRY').assertions.find(a => a.name === 'Observed effect 1 (effect.only)').actual, /1 exact keyed replay\(s\) counted with their application/);
  validateHttpRunEvidence(r);
  // The stored clause binds countBy: removing it makes the recomputed verdict disagree with the stored one.
  const refused = detail => error => error.code === 'invalid-run-evidence' && error.detail === detail;
  const reseal = x => { x.evidenceDigest = digest({ evidence: x.trace[0].data, effects: x.trace[1].data, assertions: x.assertions }); };
  const stripped = structuredClone(r), sx = stripped.results.find(x => x.id === 'RETRY');
  delete sx.trace[1].data.effects[0].countBy; reseal(sx);
  assert.throws(() => validateHttpRunEvidence(stripped), refused('effect-verdict'));
});
