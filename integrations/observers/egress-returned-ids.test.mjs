// Returned ids end to end over real loopback HTTP: forward-proof/2 binds the reply body, a destination that declares
// ids records the salted digests of a /2-proven reply's minted and referenced ids (a minted value the request carried is an
// echo and is dropped), and background attribution uses them in one place: a withheld effect.exists pass stands when its
// matched send refers to an object the check's own send had created. forward-proof/1 is unchanged (pinned vector).
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts, watchingBinds } from './fixtures/free-port.mjs';
import { buildObservers } from './factory.mjs';
import { collectWindow } from './events.mjs';
import { forwardProof, forwardProofV2, forwardProofMessage, forwardProofV2Message } from './egress-forward.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { digest } from '../../src/domain.mjs';
import { RETURNED_IDS_LIMITATION } from '../../src/http-scope-text.mjs';
import { validateEgressConfig } from '../../src/egress-rules.mjs';

const PAY = 'payments.example.test', HOOKS = 'hooks.example.test', WITNESS = 'witness.scopehaven.invalid';
const PROOF_ENV = 'SCOPEHAVEN_TARGET_UPSTREAM_PROOF', SECRET = 'synthetic-upstream-proof-secret-0123456789abcdef';
const sha = buffer => createHash('sha256').update(buffer).digest('hex');

test('forward-proof/1 is unchanged: a pinned vector; /2 adds the reply body digest under its own prefix', () => {
  const fields = { nonce: '0'.repeat(31) + '1', method: 'POST', path: '/v1/refunds?x=1', bodySha256: sha('{"amount":5}'), contentType: 'application/json', status: 201 };
  assert.equal(forwardProofMessage(fields), `scopehaven-forward-proof/1\n${'0'.repeat(31)}1\nPOST\n/v1/refunds?x=1\n${sha('{"amount":5}')}\napplication/json\n201`);
  assert.equal(forwardProof('k'.repeat(32), fields), 'd18f0a9fc11c4da63c0982f72b309634b1cb99949cc7d21b17d653ced7ff0790');
  const v2 = { ...fields, replyBodySha256: sha('{"id":"re_00000001"}') };
  assert.equal(forwardProofV2Message(v2), `scopehaven-forward-proof/2\n${'0'.repeat(31)}1\nPOST\n/v1/refunds?x=1\n${sha('{"amount":5}')}\napplication/json\n201\n${sha('{"id":"re_00000001"}')}`);
  assert.notEqual(forwardProofV2('k'.repeat(32), v2), forwardProof('k'.repeat(32), fields));
});

// The upstream double: answers by path; proves with /1 for the hooks host and a "v1" path, otherwise /2 ("tamper" proves a
// different body).
async function upstreamDouble(t) {
  let n = 0;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks), url = new URL(req.url, 'http://upstream'), last = url.pathname.split('/').pop();
      let json = {};
      try { json = JSON.parse(body.toString() || '{}'); } catch {}
      const answer = last === 'charges' ? { id: `ch_${String(++n).padStart(8, '0')}`, object: 'charge' }
        : last === 'hooks' ? { id: `dlv_${String(++n).padStart(8, '0')}`, object: json.charge ?? null }
        : last === 'echo' ? { id: json.ref ?? null }
        : last === 'echo-header' ? { id: Buffer.from(req.headers['x-ref'] ?? '', 'base64').toString() }
        : last === 'echo-upper' ? { id: String(json.ref ?? '').toUpperCase() }
        : last === 'echo-derived' ? { id: `cus_${json.ref ?? ''}` }
        : last === 'echo-b64json' ? { id: Buffer.from(String(json.payload ?? ''), 'base64').toString() }
        : last === 'short' ? { id: 'ch_1', count: 12345678 }
        : last === 'secret' ? { id: '4242424242424242' }
        : { id: `re_${String(++n).padStart(8, '0')}` };
      const text = JSON.stringify(answer), status = 200;
      const nonce = req.headers['x-scopehaven-forward-nonce'];
      const base = { nonce, method: req.method, path: req.url, bodySha256: sha(body), contentType: req.headers['content-type'] ?? '', status };
      const v1 = last === 'v1' || (req.headers.host === HOOKS && url.searchParams.has('v1'));
      const proof = !nonce ? null : v1 ? forwardProof(SECRET, base) : forwardProofV2(SECRET, { ...base, replyBodySha256: sha(last === 'tamper' ? '{}' : text) });
      res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text), ...(proof ? { 'X-Scopehaven-Forward-Proof': proof } : {}) });
      res.end(text);
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return server.address().port;
}
const forwardOf = (port, extra = {}) => ({ upstream: `http://127.0.0.1:${port}`, proofEnv: PROOF_ENV, proofVersion: 2, ids: { minted: ['/id'], references: ['/object'] }, ...extra });
const sink = (t, destinations) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', env: { [PROOF_ENV]: SECRET }, port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
  await o.start(); t.after(() => o.stop()); return o;
});
const send = (port, target, body = '{}', method = 'POST') => new Promise(resolve => {
  const url = new URL(target);
  const req = request({ host: '127.0.0.1', port, method, path: target, headers: { host: url.host, 'content-type': 'application/json' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', () => resolve(null)); req.end(body ?? undefined);
});
async function windowOf(o, between) {
  const from = await o.mark(); await between(); o.markWitnessRequest(from);
  await send(o.port, `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, null, 'GET');
  return collectWindow(o, from, await o.mark());
}

test('a /2-proven reply records salted id digests; echoed, /1, tampered, unproven and short or numeric values record none', async t => {
  const up = await upstreamDouble(t);
  const o = await sink(t, [{ host: PAY, paths: ['/v1'], forward: forwardOf(up) }, { host: HOOKS, forward: forwardOf(up, { proofVersion: undefined, ids: undefined }) }]);
  assert.deepEqual(o.scope.forward[PAY], { upstreamPort: up, applied: [200, 201, 204], rejected: [], proof: true, proofVersion: 2, ids: { minted: ['/id'], references: ['/object'] } });
  assert.deepEqual(o.scope.forward[HOOKS], { upstreamPort: up, applied: [200, 201, 204], rejected: [], proof: true }, 'a /1 destination keeps exactly its forward-proof/1 entry');
  const w = await windowOf(o, async () => {
    for (const path of ['charges', 'v1', 'tamper', 'short', 'secret']) await send(o.port, `http://${PAY}/v1/${path}`);
    await send(o.port, `http://${HOOKS}/hooks?v1`);
    await send(o.port, `http://${PAY}/v1/echo`, '{"ref":"ord_12345678"}');
    await new Promise(resolve => { const r = request({ host: '127.0.0.1', port: o.port, method: 'POST', path: `http://${PAY}/v1/echo-header`, headers: { host: PAY, 'content-type': 'application/json', 'x-ref': Buffer.from('ord_hdr_87654321').toString('base64') } }, res => { res.resume(); res.on('end', resolve); }); r.end('{}'); });
    await send(o.port, `http://${PAY}/v1/echo-upper`, '{"ref":"ord_abcdefgh"}');
    await send(o.port, `http://${PAY}/v1/echo-derived`, '{"ref":"abc_def_ghi_jkl"}');
    await send(o.port, `http://${PAY}/v1/echo-b64json`, JSON.stringify({ payload: Buffer.from('ord_b64_12345678').toString('base64') }));
  });
  assert.equal(w.coverage, 'complete', w.reason);
  const [charge, v1, tamper, short, secret, hooks, echo, echoHeader, echoUpper, echoDerived, echoB64] = w.events.map(e => e.upstream);
  for (const [name, record] of [['base64 header', echoHeader], ['re-cased', echoUpper], ['derived', echoDerived], ['base64 in a JSON field', echoB64]]) assert.deepEqual([record.minted, record.echoed?.length], [undefined, 1], name);
  assert.equal(charge.proven, true);
  assert.deepEqual([charge.minted.length, charge.references], [1, undefined], 'the charge id is minted; "charge" is too short to be an id');
  assert.match(charge.minted[0], /^[a-f0-9]{64}$/);
  assert.deepEqual([echo.proven, echo.minted, echo.echoed?.length], [true, undefined, 1], 'an id the request carried is an echo: never minted, recorded to contest');
  assert.ok(!JSON.stringify(w).includes('ch_00000001'), 'raw ids are never stored');
  assert.deepEqual([v1.proven, v1.minted], [false, undefined], 'a /1 proof on a /2 destination is no proof');
  assert.deepEqual([tamper.proven, tamper.minted], [false, undefined], 'a proof over another body is no proof');
  assert.deepEqual([short.proven, short.minted], [true, undefined], 'ch_1 is too short and a number is never an id');
  assert.deepEqual([secret.proven, secret.minted], [true, undefined], 'a card-number-shaped value is refused by the body-field reader');
  assert.deepEqual([hooks.proven, hooks.outcome, Object.hasOwn(hooks, 'minted'), Object.hasOwn(hooks, 'references')], [true, 'applied', false, false], 'a /1 destination: a forward-proof/1 record');
  // The same id from two sends of one recorder has one digest; validation of the declaration.
  const v2 = ids => ({ upstream: 'http://127.0.0.1:47002', proofEnv: PROOF_ENV, proofVersion: 2, ids });
  for (const forward of [{ upstream: 'http://127.0.0.1:47002', proofEnv: PROOF_ENV, ids: { minted: ['/id'] } }, { upstream: 'http://127.0.0.1:47002', proofVersion: 2 },
    { upstream: 'http://127.0.0.1:47002', proofEnv: PROOF_ENV, proofVersion: 3 }, v2({ minted: ['/token'] }), v2({ minted: Array.from({ length: 9 }, (_, i) => `/a${i}`) }), v2(['/id']),
    v2({}), v2({ minted: ['/id'], references: ['/id'] }), v2({ pointers: ['/id'] }), v2({ minted: ['/a', '/b', '/c', '/d', '/e'], references: ['/f', '/g', '/h', '/i'] })])
    assert.throws(() => validateEgressConfig({ port: 47001, destinations: [{ host: PAY, forward }] }), /forward/, JSON.stringify(forward));
});

// An app: /charge creates a charge and notifies about it; /notify-other notifies about the last charge (another check's
// object: the IDOR-shaped defect); /quiet sends nothing.
async function app(t, sinkPort) {
  let lastCharge = null;
  const outbound = (target, body, extra = {}) => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...extra } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString())); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null)); req.end(body);
  });
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    // The app forwards the check's correlation token on its own charge call (and only there).
    const token = req.headers['x-request-id'] ? { 'x-request-id': req.headers['x-request-id'] } : {};
    if (url.pathname === '/charge') { const charge = await outbound(`http://${PAY}/v1/charges`, '{"amount":5}', token); lastCharge = charge?.id ?? null; await outbound(`http://${HOOKS}/hooks`, JSON.stringify({ charge: lastCharge })); return reply(200, { ok: true }); }
    if (url.pathname === '/notify-other') { await outbound(`http://${HOOKS}/hooks`, JSON.stringify({ charge: lastCharge })); return reply(200, { ok: true }); }
    if (url.pathname === '/quiet') return reply(200, { ok: true });
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token', [PROOF_ENV]: SECRET };
const sel = (name, extra = {}) => ({ source: 'http-egress', operation: 'send', name, ...extra });
const check = (id, path, effects, severity = 'high') => ({ id, title: id, category: 'refunds', severity, actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects });
const profileOf = (origin, port, upstreamPort, checks, correlated = true) => ({ id: 'e3-ids', name: 'E3 ids', applicationId: 'e3-ids', origin, buildLabel: 'b1', contextId: 'synthetic-e3-ids',
  ...(correlated ? { correlation: { header: 'x-request-id' } } : {}),
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
  attribution: { background: [{ id: 'notifier', select: { operation: 'send', name: HOOKS } }] },
  observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', settleMs: 250, quietMs: 150, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS },
    destinations: [{ host: PAY, paths: ['/v1'], ...(correlated ? { correlation: { header: 'x-request-id' } } : {}), forward: { upstream: `http://127.0.0.1:${upstreamPort}`, proofEnv: PROOF_ENV, proofVersion: 2, ids: { minted: ['/id'] } } },
      { host: HOOKS, forward: { upstream: `http://127.0.0.1:${upstreamPort}`, proofEnv: PROOF_ENV, proofVersion: 2, ids: { minted: ['/id'], references: ['/object'] } } }] }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] }, ...checks] });

test('connector run: a send tied to the check\'s own object releases its effect.exists pass; nothing else changes; an IDOR send never passes', async t => {
  const up = await upstreamDouble(t);
  const hooksSent = { kind: 'effect.exists', select: sel(HOOKS) }, noHooks = { kind: 'effect.none', select: sel(HOOKS) }, charged = { kind: 'effect.exists', select: sel(PAY) };
  const run = (checks, withIds = true, correlated = true) => onFreePorts(1, async port => {
    const p = profileOf(await app(t, port), port, up, checks, correlated);
    if (!withIds) for (const d of p.observers[0].destinations) { delete d.forward.ids; }
    const watch = watchingBinds(buildObservers);
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    return { p, run: await runHttpAssessment(p, { env, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
  }, x => x.lostBind);
  // OWN creates a charge (its own selected, non-background PAY send seeds closure(OWN)) and notifies about it: the
  // notification is background-possible but refers to OWN's charge, so its effect.exists pass stands. QUIET sends nothing,
  // and its effect.exists fail stays background attribution's (inconclusive). IDOR's request makes the app notify about OWN's charge: the
  // send is tied to OWN, and it never passes or decides IDOR's effect.none (pinned).
  const checks = [check('OWN', '/charge', [charged, hooksSent]), check('QUIET', '/quiet', [hooksSent]), check('IDOR', '/notify-other', [noHooks])];
  const { p, run: r } = await run(checks);
  const row = (x, id) => x.results.find(y => y.id === id);
  assert.equal(row(r, 'OWN').status, 'pass', JSON.stringify(row(r, 'OWN').assertions));
  assert.equal(row(r, 'QUIET').status, 'inconclusive', 'a fail is never decided through a tie');
  assert.equal(row(r, 'IDOR').status, 'inconclusive', 'pinned: a send tied to another check never passes or decides this absence clause');
  assert.match(JSON.stringify(row(r, 'IDOR').assertions), /background-unattributed/);
  assert.ok(r.limitations.includes(RETURNED_IDS_LIMITATION));
  assert.deepEqual(r.observers[0].forward[PAY], { upstreamPort: up, applied: [200, 201, 204], rejected: [], proof: true, proofVersion: 2, ids: { minted: ['/id'], references: [] } });
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  validateHttpRunEvidence(r, { expectedSuite: suite });
  // Without ids, background attribution alone holds OWN at inconclusive: the difference is the returned ids'. Without correlation nothing seeds either.
  const { run: plain } = await run(checks, false);
  assert.deepEqual(['OWN', 'QUIET', 'IDOR'].map(id => row(plain, id).status), ['inconclusive', 'inconclusive', 'inconclusive']);
  const { run: uncorrelated } = await run(checks, true, false);
  assert.deepEqual(['OWN', 'QUIET', 'IDOR'].map(id => row(uncorrelated, id).status), ['inconclusive', 'inconclusive', 'inconclusive']);
  // Tampering: returned ids on a destination that declares none, or a changed digest, are refused.
  const refused = detail => error => error.code === 'invalid-run-evidence' && error.detail === detail;
  const reseal = x => { x.evidenceDigest = digest({ evidence: x.trace[0].data, effects: x.trace[1].data, assertions: x.assertions }); };
  const forge = (onEvent, onWindow = () => {}) => { const f = structuredClone(r); for (const x of f.results) if (x.trace?.[1]) { for (const w of x.trace[1].data.windows) { w.events.forEach(onEvent); onWindow(w); } reseal(x); } return f; };
  assert.throws(() => validateHttpRunEvidence(forge(() => {}, w => { if (w.scope.forward) delete w.scope.forward[HOOKS].ids; })), refused('effect-trace'));
  assert.throws(() => validateHttpRunEvidence(forge(e => { if (e.name === HOOKS && e.upstream?.references) e.upstream.references = ['f'.repeat(64)]; })));
  assert.throws(() => validateHttpRunEvidence(forge(e => { if (e.upstream?.minted) e.upstream.minted = ['F'.repeat(64)]; })), refused('effect-window-upstream'));
});
