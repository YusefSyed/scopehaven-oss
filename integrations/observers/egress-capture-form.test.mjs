// Form-encoded capture end to end over real loopback HTTP: a destination that declares capture.encodings ["json", "form"] has its
// declared fields read from the app's form-encoded sends too, and every aliasing attempt (a URL query, a Cookie, a
// repeated or non-canonical value) reads missing, never pass. Every request goes to 127.0.0.1; destination hosts are
// names only and are never resolved or contacted.
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
import { BODY_CAPTURE_LIMITATION, FORM_CAPTURE_LIMITATION } from '../../src/http-scope-text.mjs';

const PAY = 'payments.example.test', WITNESS = 'witness.scopehaven.invalid', FORM = 'application/x-www-form-urlencoded';
const CAPTURE = { pointers: ['/amount', '/currency', '/metadata/ticket_id'], encodings: ['json', 'form'] };
const sink = (t, destinations) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
  await o.start(); t.after(() => o.stop()); return o;
});
const post = (port, target, body, headers = { 'content-type': FORM }, method = 'POST') => new Promise(resolve => {
  const url = new URL(target);
  const req = request({ host: '127.0.0.1', port, method, path: target, headers: { host: url.host, ...headers } }, res => { res.resume(); res.on('end', resolve); });
  req.on('error', resolve); req.end(body);
});
async function windowOf(o, between) {
  const from = await o.mark(); await between(); o.markWitnessRequest(from);
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark());
}
const sel = fields => ({ source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds', fields });
const exists25 = { kind: 'effect.exists', select: sel([{ pointer: '/amount', equals: 25 }]) };
const noneOver100 = { kind: 'effect.none', select: sel([{ pointer: '/amount', gt: 100 }]) };
// Any method: a PUT is not the selector's POST, so a host-wide selector judges every attempt.
const hostNoneOver100 = { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: PAY, fields: [{ pointer: '/amount', gt: 100 }] } };

test('form sink: form and JSON sends are read; aliasing attempts read missing, never pass; undeclared fields are never stored', async t => {
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], capture: CAPTURE }]);
  assert.deepEqual([o.scope.capture, o.scope.captureForm], [{ [PAY]: CAPTURE.pointers }, [PAY]]);
  const w = await windowOf(o, async () => {
    await post(o.port, `http://${PAY}/v1/refunds`, 'amount=25&currency=cad&metadata%5Bticket_id%5D=T-7&card_number=4242424242424242');
    await post(o.port, `http://${PAY}/v1/refunds`, JSON.stringify({ amount: 25, currency: 'cad' }), { 'content-type': 'application/json' });
    await post(o.port, `http://${PAY}/v1/refunds?`, 'amount=25');
  });
  assert.deepEqual([w.coverage, w.reason], ['complete', null]);
  const [form, json, bare] = w.events;
  assert.deepEqual(form.captured, { status: 'captured', values: { '/amount': { type: 'text', value: '25' }, '/currency': { type: 'text', value: 'cad' }, '/metadata/ticket_id': { type: 'text', value: 'T-7' } } });
  assert.deepEqual(json.captured.values['/amount'], { type: 'number', value: 25 });
  assert.equal(bare.captured.status, 'captured', 'a bare "?" is no query');
  assert.ok(!JSON.stringify(w).includes('4242424242424242'), 'an undeclared card number is never stored');
  assert.equal(evaluateEffectAssertion(exists25, [w]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(noneOver100, [w]).verdict, 'pass');
  const big = await windowOf(o, () => post(o.port, `http://${PAY}/v1/refunds`, 'amount=250'));
  assert.equal(evaluateEffectAssertion(noneOver100, [big]).verdict, 'fail');
  // Each aliasing attempt is a send whose amount cannot be decided: an absence clause over it reads missing.
  const attempts = [
    ['amount=0250', undefined, 'captured'],
    ['amount=1&amount=300', undefined, 'form-duplicate-key'],
    ['amount=5', { target: `http://${PAY}/v1/refunds?amount=50000` }, 'form-query-or-cookie'],
    ['amount=5', { headers: { 'content-type': FORM, cookie: 'amount=50000' } }, 'form-query-or-cookie'],
    ['amount=5', { target: `http://${PAY}/v1/refunds#?amount=50000` }, 'form-query-or-cookie'],
    ['amount=5', { method: 'PUT' }, 'form-method'],
    ['--x\r\nContent-Disposition: form-data; name="amount"\r\n\r\n500\r\n--x--', { headers: { 'content-type': 'multipart/form-data; boundary=x' } }, 'not-json-or-form'],
  ];
  for (const [body, opts, status] of attempts) {
    const aw = await windowOf(o, () => post(o.port, opts?.target ?? `http://${PAY}/v1/refunds`, body, opts?.headers, opts?.method));
    assert.equal(aw.events[0].captured.status, status, body);
    assert.equal(evaluateEffectAssertion(hostNoneOver100, [aw]).verdict, 'missing', body);
    assert.notEqual(evaluateEffectAssertion(exists25, [aw]).verdict, 'pass', body);
  }
  assert.throws(() => createEgressRecorder({ port: 47000, destinations: [{ host: PAY, paths: ['/v1/refunds'], capture: { pointers: ['/se/cret'], encodings: ['json', 'form'] } }] }), /secret-like key/);
});

test('compat sink: without encodings a form send records not-json and the scope has no captureForm', async t => {
  const o = await sink(t, [{ host: PAY, paths: ['/v1/refunds'], capture: { pointers: CAPTURE.pointers } }]);
  assert.equal(Object.hasOwn(o.scope, 'captureForm'), false);
  const w = await windowOf(o, () => post(o.port, `http://${PAY}/v1/refunds`, 'amount=25'));
  assert.deepEqual(w.events[0].captured, { status: 'not-json', values: {} });
  assert.match(w.events[0].contentDigest, /^[a-f0-9]{64}$/);
  assert.equal(evaluateEffectAssertion(noneOver100, [w]).verdict, 'missing');
});

// An app whose routes send a form-encoded refund through its proxy (the sink).
async function formApp(t, sinkPort) {
  const outbound = (target, body) => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(body === undefined ? {} : { 'content-type': FORM }) } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(body);
  });
  const routes = { '/refund/small': 'amount=25&currency=cad', '/refund/large': 'amount=250&currency=cad', '/refund/aliased': 'amount=25&Amount=250' };
  const server = createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return send(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return send(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return send(200, { ok: true }); }
    if (!Object.hasOwn(routes, url.pathname)) return send(404, {});
    await outbound(`http://${PAY}/v1/refunds`, routes[url.pathname]);
    send(200, { ok: true });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const check = (id, path, extra) => ({ id, title: id, category: 'refunds', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...extra });
const profileOf = (origin, port, checks, capture) => ({ id: 'form-refunds', name: 'Form refunds', applicationId: 'form-refunds', origin, buildLabel: 'b1', contextId: 'synthetic-form-refunds',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds'], capture }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] }, ...checks] });
const run = (t, checks, capture) => onFreePorts(1, async port => {
  const p = profileOf(await formApp(t, port), port, checks, capture), watch = watchingBinds(buildObservers);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return { p, run: await runHttpAssessment(p, { env, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('connector run with form declared: verdicts from form fields, captureForm on the run and suite, limitation stated', async t => {
  const capture = { pointers: ['/amount', '/currency'], encodings: ['json', 'form'] };
  const { p, run: r } = await run(t, [
    check('SMALL', '/refund/small', { effects: [exists25] }),
    check('LARGE', '/refund/large', { effects: [exists25] }),
    check('ALIASED', '/refund/aliased', { effects: [exists25] }),
  ], capture);
  const row = id => r.results.find(x => x.id === id);
  assert.equal(row('SMALL').status, 'pass', JSON.stringify(row('SMALL').assertions));
  assert.equal(row('LARGE').status, 'fail', 'a 250 refund is not the 25 one');
  assert.notEqual(row('ALIASED').status, 'pass', 'a case-folded duplicate key never passes');
  assert.deepEqual(r.observers.map(o => o.collector), [COLLECTOR_RECORDS['egress-recorder']], 'the collector that built the windows');
  assert.deepEqual(r.observers.map(({ collector, ...o }) => o), [{ id: 'sink', type: 'egress-recorder', settleMs: 250, capture: { [PAY]: ['/amount', '/currency'] }, captureForm: [PAY] }]);
  const bodyAt = r.limitations.indexOf(BODY_CAPTURE_LIMITATION), formAt = r.limitations.indexOf(FORM_CAPTURE_LIMITATION);
  assert.ok(bodyAt >= 0 && formAt === bodyAt + 1, 'the form limitation follows the unchanged body-field limitation');
  assert.ok(FORM_CAPTURE_LIMITATION.startsWith('Form-encoded body fields (this overrides'));
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  assert.deepEqual(suite.observers[0].captureForm, [PAY]);
  validateHttpRunEvidence(r, { expectedSuite: suite });
  const refused = detail => error => error.code === 'invalid-run-evidence' && error.detail === detail;
  const stripped = structuredClone(r); delete stripped.observers[0].captureForm;
  assert.throws(() => validateHttpRunEvidence(stripped, { expectedSuite: suite }), error => error.code === 'unexpected-suite-evidence');
  const strippedSuite = structuredClone(suite); delete strippedSuite.observers[0].captureForm;
  assert.throws(() => validateHttpRunEvidence(r, { expectedSuite: strippedSuite }), error => error.code === 'unexpected-suite-evidence');
  // A window whose scope drops captureForm, resealed, is refused: its form records then sit on a JSON-only name.
  const reseal = row => { row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); };
  const forged = structuredClone(r);
  for (const x of forged.results) if (x.trace?.[1]) { for (const w of x.trace[1].data.windows) delete w.scope.captureForm; reseal(x); }
  assert.throws(() => validateHttpRunEvidence(forged), refused('effect-trace'));
  // Without form, no form limitation and no captureForm.
  const { run: plain } = await run(t, [check('SMALL', '/refund/small', { effects: [exists25] })], { pointers: ['/amount', '/currency'] });
  assert.equal(plain.limitations.includes(FORM_CAPTURE_LIMITATION), false);
  assert.equal(Object.hasOwn(plain.observers[0], 'captureForm'), false);
  assert.notEqual(plain.results.find(x => x.id === 'SMALL').status, 'pass', 'a JSON-only destination never reads the form amount');
});
