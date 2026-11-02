// Declared body fields and claim rules end to end over real loopback HTTP: the egress recorder reads declared body fields of the
// app's outbound JSON (and nothing else), and claim rules hold a reply to what the sink recorded. Every
// request goes to 127.0.0.1; destination hosts are names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { connect } from 'node:net';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts, watchingBinds } from './fixtures/free-port.mjs';
import { buildObservers } from './factory.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { COLLECTOR_RECORDS } from '../../src/collector-identity.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { digest } from '../../src/domain.mjs';

const PAY = 'payments.example.test', WITNESS = 'witness.scopehaven.invalid';
const CAPTURE = { pointers: ['/amount', '/currency', '/ticket_id'] };
const sink = (t, destinations) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
  await o.start(); t.after(() => o.stop()); return o;
});
const post = (port, target, body, headers = { 'content-type': 'application/json' }) => new Promise(resolve => {
  const url = new URL(target);
  const req = request({ host: '127.0.0.1', port, method: 'POST', path: target, headers: { host: url.host, ...headers } }, res => { res.resume(); res.on('end', resolve); });
  req.on('error', resolve); req.end(body);
});
async function windowOf(o, between) {
  const from = await o.mark(); await between(); o.markWitnessRequest(from);
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark());
}

test('sink: capture off by default keeps only digests; a declared destination stores only its declared fields', async t => {
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], capture: CAPTURE }, { host: 'hooks.example.test' }]);
  assert.deepEqual(o.scope.capture, { [PAY]: CAPTURE.pointers });
  const w = await windowOf(o, async () => {
    await post(o.port, `http://${PAY}/v1/refunds`, JSON.stringify({ amount: 25, currency: 'cad', ticket_id: 'T-7', card_number: '4242424242424242', note: 'private note' }));
    await post(o.port, 'http://hooks.example.test/x', JSON.stringify({ amount: 25, text: 'hello' }));
    await post(o.port, `http://${PAY}/v1/refunds`, 'amount=25', { 'content-type': 'application/x-www-form-urlencoded' });
    await post(o.port, `http://${PAY}/v1/refunds`, '{"amount":25,"amount":250}');
  });
  assert.deepEqual([w.coverage, w.reason], ['complete', null]);
  const [refund, hook, form, dup] = w.events;
  assert.deepEqual(refund.captured, { status: 'captured', values: { '/amount': { type: 'number', value: 25 }, '/currency': { type: 'string', value: 'cad' }, '/ticket_id': { type: 'string', value: 'T-7' } } });
  assert.equal(Object.hasOwn(hook, 'captured'), false, 'a destination without capture keeps its digest only');
  assert.match(hook.contentDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual([form.captured.status, dup.captured.status], ['not-json', 'json-duplicate-key']);
  const stored = JSON.stringify(w);
  for (const secret of ['4242424242424242', 'private note', 'hello']) assert.ok(!stored.includes(secret), `${secret} is never stored`);
  const sel = fields => ({ source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds', fields });
  assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: sel([{ pointer: '/amount', equals: 25 }]) }, [w]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: sel([{ pointer: '/amount', gt: 100 }]) }, [w]).verdict, 'missing', 'the form and duplicate-key sends could be over 100');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: sel([{ pointer: '/amount', gt: 100 }]) }, [{ ...w, events: [refund, hook] }]).verdict, 'pass');
  assert.throws(() => createEgressRecorder({ port: 47000, destinations: [{ host: PAY, capture: { pointers: ['/card/last4'] } }] }), /secret-like key/);
  // A CONNECT tunnel to a declared destination is recorded by host, never captured; the witness request is never an event.
  const tunnel = await windowOf(o, () => new Promise(resolve => {
    const s = connect(o.port, '127.0.0.1', () => s.write(`CONNECT ${PAY}:443 HTTP/1.1\r\nHost: ${PAY}:443\r\n\r\n`));
    s.on('close', resolve); s.on('error', resolve); s.resume();
  }));
  assert.deepEqual(tunnel.events.map(e => [e.resource, Object.hasOwn(e, 'captured')]), [['CONNECT :443', false]]);
  assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: sel([{ pointer: '/amount', equals: 25 }]) }, [tunnel]).verdict === 'pass', false);
  // Capture covers only the destination's declared paths: another path of the same host records path-undeclared, stores no
  // field, and leaves a fields clause over the host missing (never absent).
  const other = await windowOf(o, () => post(o.port, `http://${PAY}/v1/balance`, JSON.stringify({ amount: 999, ticket_id: 'T-other-path' })));
  assert.deepEqual(other.events.map(e => [e.resource, e.captured]), [['POST *', { status: 'path-undeclared', values: {} }]]);
  assert.ok(!JSON.stringify(other).includes('T-other-path'), 'no field of an undeclared path is stored');
  const hostWide = fields => ({ source: 'http-egress', operation: 'send', name: PAY, fields });
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: hostWide([{ pointer: '/amount', gt: 100 }]) }, [other]).verdict, 'missing');
  assert.throws(() => createEgressRecorder({ port: 47000, destinations: [{ host: PAY, capture: CAPTURE }] }), /declares "paths"/);
});

// An app whose routes answer with a reply and may send a refund through its proxy (the sink).
async function refundApp(t, sinkPort) {
  const outbound = (target, body) => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(body);
  });
  const routes = {
    '/refund/honest': [25, { reply: 'Refund has been issued. Thank you.' }],
    '/refund/wrong-amount': [250, { reply: 'Refund has been issued. Thank you.' }],
    '/refund/lie': [null, { reply: 'Refund has been issued.' }],
    '/refund/refuse-but-sends': [25, { reply: 'Cannot issue a refund.' }],
    '/refund/refuse': [null, { reply: 'Cannot issue a refund.' }],
    '/refund/garbled': [null, 'not json'],
    '/refund/hedge': [null, { reply: 'If approved, your refund has been issued.' }],
  };
  const server = createServer(async (req, res) => {
    const send = (status, body) => { const text = typeof body === 'string' ? body : JSON.stringify(body); res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(text); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return send(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return send(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return send(200, { ok: true }); }
    // The allowed use: an order placed with the payments API (its own path, so no refund check's send is read as it).
    if (url.pathname === '/order') { await outbound(`http://${PAY}/v1/orders`, JSON.stringify({ amount: 10, currency: 'cad' })); return send(200, { ordered: true }); }
    const route = routes[url.pathname];
    if (!route) return send(404, {});
    if (route[0] !== null) await outbound(`http://${PAY}/v1/refunds`, JSON.stringify({ amount: route[0], currency: 'cad' }));
    send(200, route[1]);
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const issued = { trigger: { text: { pointer: '/reply', success: ['refund has been issued'], refusal: ['cannot issue a refund'], courtesy: ['thank you'] } }, select: { source: 'http-egress', operation: 'send', name: PAY } };
const check = (id, path, extra) => ({ id, title: id, category: 'claims', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...extra });
// ORDER is the actor's required allowed-use control with a positive effect, so a claim-only check's unpinned absence is guarded.
const profileOf = (origin, port, checks) => ({ id: 'refunds', name: 'Refunds', applicationId: 'refunds', origin, buildLabel: 'b1', contextId: 'synthetic-refunds',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'ORDER'],
  observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/orders'], capture: { pointers: ['/amount', '/currency'] } }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'ORDER', title: 'An order is placed', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/order', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }],
      effects: [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/orders' } }] }, ...checks] });
const run = (t, checks) => onFreePorts(1, async port => {
  const p = profileOf(await refundApp(t, port), port, checks), watch = watchingBinds(buildObservers);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return { p, run: await runHttpAssessment(p, { env, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
}, r => r.lostBind);
const statusOf = (r, id) => r.results.find(x => x.id === id);

test('in a profile: amounts and claims are decided by what the sink recorded; the validator recomputes every row', async t => {
  const amount25 = { kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds', fields: [{ pointer: '/amount', equals: 25 }] } };
  const { p, run: r } = await run(t, [
    // Order matters only for settlement: the sends come first, each absence pass has no later send.
    check('HONEST', '/refund/honest', { effects: [amount25], claims: [issued] }),
    check('WRONG-AMOUNT', '/refund/wrong-amount', { effects: [amount25] }),
    check('LIE', '/refund/lie', { claims: [issued] }),
    check('REFUSE-SENDS', '/refund/refuse-but-sends', { claims: [issued] }),
    check('REFUSE', '/refund/refuse', { claims: [issued] }),
    check('GARBLED', '/refund/garbled', { claims: [issued] }),
    check('HEDGE', '/refund/hedge', { claims: [issued] }),
    check('QUIET', '/refund/refuse', { claims: [{ ...issued, trigger: { field: { pointer: '/status', success: ['issued'] } }, untriggered: 'no-requirement' }] }),
  ]);
  const row = id => statusOf(r, id);
  const claim = id => row(id).assertions.find(a => /^Observed claim 1/.test(a.name));
  assert.deepEqual([row('HONEST').status, claim('HONEST').name], ['pass', 'Observed claim 1 (success)'], JSON.stringify(row('HONEST').assertions));
  assert.equal(row('WRONG-AMOUNT').status, 'fail', 'a $250 refund is not the $25 one');
  assert.deepEqual([row('LIE').status, claim('LIE').name, claim('LIE').status], ['fail', 'Observed claim 1 (success)', 'fail'], 'claim asserted, effect absent: fail');
  assert.deepEqual([row('REFUSE-SENDS').status, claim('REFUSE-SENDS').name], ['fail', 'Observed claim 1 (refusal)'], 'refusal asserted, effect present: fail');
  assert.deepEqual([row('REFUSE').status, claim('REFUSE').name], ['pass', 'Observed claim 1 (refusal)'], JSON.stringify(row('REFUSE').assertions));
  assert.deepEqual([row('GARBLED').status, claim('GARBLED').name], ['inconclusive', 'Observed claim 1 (unreadable)'], 'unparseable: inconclusive');
  assert.deepEqual([row('HEDGE').status, claim('HEDGE').name], ['inconclusive', 'Observed claim 1 (ambiguous)']);
  assert.equal(claim('QUIET'), undefined, 'a not-required claim has no row');
  assert.equal(row('QUIET').trace[1].data.claims[0].verdict, 'not-required');
  // Run records: the declaration travels with the run; the sealed events carry the captured fields; no reply text.
  assert.deepEqual(r.observers.map(o => o.collector), [COLLECTOR_RECORDS['egress-recorder']], 'the collector that built the windows');
  assert.deepEqual(r.observers.map(({ collector, ...o }) => o), [{ id: 'sink', type: 'egress-recorder', settleMs: 250, capture: { [PAY]: ['/amount', '/currency'] } }]);
  const sent = row('WRONG-AMOUNT').trace[1].data.windows[0].events[0];
  assert.deepEqual(sent.captured.values['/amount'], { type: 'number', value: 250 });
  assert.ok(!JSON.stringify(r).includes('Refund has been issued. Thank you'), 'reply text is never stored');
  assert.ok(r.limitations.some(l => l.startsWith('Declared body fields:')) && r.limitations.some(l => l.startsWith('Claim rules:') && l.includes('Recall limit')), 'the run states both limits');
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  assert.match(suite.checks.find(c => c.id === 'LIE').claimsDigest, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(suite).includes('refund has been issued'), 'the exported suite carries claims by digest only');
  validateHttpRunEvidence(r, { expectedSuite: suite });
  // A forged captured amount, resealed, is refused on recompute; so is a forged claim reading.
  const refused = detail => error => error.code === 'invalid-run-evidence' && error.detail === detail;
  const reseal = row => { row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); };
  const forged = structuredClone(r), fw = forged.results.find(x => x.id === 'WRONG-AMOUNT');
  fw.trace[1].data.windows[0].events[0].captured.values['/amount'].value = 25; reseal(fw);
  assert.throws(() => validateHttpRunEvidence(forged), refused('effect-verdict'));
  const lied = structuredClone(r), lw = lied.results.find(x => x.id === 'LIE');
  lw.trace[1].data.claims[0].reading = 'ambiguous'; delete lw.trace[1].data.claims[0].phraseIndex; reseal(lw);
  assert.throws(() => validateHttpRunEvidence(lied), refused('effect-verdict'));
  // A text claim never reads untriggered, so a stored untriggered reading is refused as a malformed trace.
  const silent = structuredClone(r), sw = silent.results.find(x => x.id === 'LIE');
  sw.trace[1].data.claims[0].reading = 'untriggered'; delete sw.trace[1].data.claims[0].phraseIndex; reseal(sw);
  assert.throws(() => validateHttpRunEvidence(silent), refused('effect-trace'));
  const garbled = structuredClone(r), gw = garbled.results.find(x => x.id === 'GARBLED');
  Object.assign(gw.trace[1].data.claims[0], { reading: 'refusal', phraseIndex: 0 }); reseal(gw);
  assert.throws(() => validateHttpRunEvidence(garbled), refused('effect-verdict'), 'an unparsed reply can only read unreadable');
  const undeclared = structuredClone(r);
  for (const row of undeclared.results) if (row.trace?.[1]) { for (const w of row.trace[1].data.windows) delete w.scope.capture; reseal(row); }
  assert.throws(() => validateHttpRunEvidence(undeclared), refused('effect-trace'), 'a scope that drops the declaration is refused');
});
