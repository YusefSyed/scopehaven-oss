// Another recorder's destination (egress-recorder/13). During a "no charge" check an app sent the
// charge to api-eu.pay.example, a regional name of api.pay.example, through a second witnessed recorder that declares only the chat
// webhook host, and the prohibition passed: the clause read only the recorder that declares the provider, and the second recorder read
// the regional name against its own declarations, so it was nobody's sibling. Now each recorder also reads the destinations the
// run's other recorders declare (src/egress-rules.mjs crossDestinationsOf): a send to one is recorded under it, a send to its sibling adds
// it a scoped entry, and a window holding either can see that destination, so the clause reads the send whichever recorder held it.
// Over real loopback HTTP; destination hosts are names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createEgressRecorder } from '../integrations/observers/egress-recorder.mjs';
import { onFreePorts } from '../integrations/observers/fixtures/free-port.mjs';
import { collectWindow, evaluateEffectAssertion, validateScope, windowSees, SIBLING_CODE } from '../src/effect-events.mjs';
import { crossDestinationsOf, crossRecordOf, validCrossRecord, crossSeenOf, validateCrossDestinations, validateEgressConfig } from '../src/egress-rules.mjs';
import { declaredObserverRecord } from '../src/http-effects.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { COLLECTOR_RECORDS, CROSS_LABELS, SIBLING_LABELS, KNOWN_COLLECTOR_LABELS, SCOPED_COLLECTOR_LABELS } from '../src/collector-identity.mjs';
import { digest } from '../src/domain.mjs';

const PAY = 'api.pay.example', SIBLING = 'api-eu.pay.example', HOOK = 'hooks.chat.example', MAIL = 'api.mail.example', WITNESS = 'witness.scopehaven.invalid';
const TOKEN = 'synthetic-ops-token';
const CHARGES = 'POST /v1/charges', PAY_PATHS = ['/v1/charges', '/v1/refunds'];
const witness = path => ({ actorId: 'ops', method: 'GET', path, host: WITNESS });
const recorderConfig = (id, destinations, path = '/ping') => ({ id, type: 'egress-recorder', port: 4479, routing: 'proxy', destinations, witness: witness(path) });

test('the label: egress-recorder/13 is current, and it keeps every list /12 is in', () => {
  const current = COLLECTOR_RECORDS['egress-recorder'].label;
  assert.equal(current, 'egress-recorder/13');
  assert.deepEqual(CROSS_LABELS, ['egress-recorder/13']);
  assert.ok(SIBLING_LABELS.includes(current) && KNOWN_COLLECTOR_LABELS.includes('egress-recorder/12') && SCOPED_COLLECTOR_LABELS.includes(current));
});

test('cross destinations: the other recorders\' destinations this one does not declare, joined per host; its own names, its witness and contested aliases never', () => {
  const sink = recorderConfig('sink', [{ host: PAY, paths: PAY_PATHS, aliases: ['api-us.pay.example'] }, { host: MAIL, paths: ['/v3/mail/send'] }, { host: HOOK }]);
  const sink2 = recorderConfig('sink2', [{ host: HOOK }], '/ping-b');
  const observers = [sink, sink2, { id: 'feed', type: 'provider-feed' }];
  assert.deepEqual(crossDestinationsOf(sink2, observers), [{ host: PAY, paths: PAY_PATHS, aliases: ['api-us.pay.example'] }, { host: MAIL, paths: ['/v3/mail/send'], aliases: [] }]);
  assert.equal(crossDestinationsOf(sink, observers), null, 'every destination sink2 declares, sink declares too');
  assert.equal(crossDestinationsOf(sink, [sink]), null, 'adjacent: one recorder has none');
  assert.equal(crossDestinationsOf({ id: 'feed', type: 'provider-feed' }, observers), null);
  assert.deepEqual(crossRecordOf(crossDestinationsOf(sink2, observers)), { [PAY]: ['api-us.pay.example'], [MAIL]: [] });
  // Two other recorders declaring one host: listed once, paths and aliases joined; an alias two hosts claim, or one that is a listed host
  // or this recorder's own name, is dropped. A destination this recorder declares, or its witness host, is never listed.
  const a = recorderConfig('a', [{ host: PAY, paths: ['/v1/charges'], aliases: ['shared.pay.example'] }, { host: 'files.pay.example', aliases: ['shared.pay.example', MAIL] }]);
  const b = recorderConfig('b', [{ host: PAY, paths: ['/v1/refunds'], aliases: [HOOK] }, { host: WITNESS }]);
  const c = recorderConfig('c', [{ host: HOOK }]);
  assert.deepEqual(crossDestinationsOf(c, [a, b, c]), [{ host: PAY, paths: PAY_PATHS, aliases: [] }, { host: 'files.pay.example', paths: [], aliases: [MAIL] }]);
  // The published record, by shape.
  assert.ok(validCrossRecord({ [PAY]: [SIBLING] }, [HOOK]));
  for (const bad of [{}, { [HOOK]: [] }, { [PAY]: [HOOK] }, { [PAY]: [MAIL], [MAIL]: [] }, { [PAY]: ['b.pay.example', 'a.pay.example'] }, { [PAY]: [SIBLING], [MAIL]: [SIBLING] }, { [PAY]: 'x' }, { 'API.pay.example': [] }])
    assert.equal(validCrossRecord(bad, [HOOK]), false, JSON.stringify(bad));
  const scope = { operations: ['send'], names: [HOOK], actorAttribution: 'none', evidence: 'authoritative' };
  assert.doesNotThrow(() => validateScope({ ...scope, cross: { [PAY]: [] } }));
  assert.throws(() => validateScope({ ...scope, cross: { [HOOK]: [] } }), /scope-cross/);
  // The recorder refuses cross destinations that name its own destinations or are not in the factory's shape.
  const cfg = validateEgressConfig(recorderConfig(undefined, [{ host: HOOK }]), { ops: {} });
  assert.deepEqual(validateCrossDestinations([{ host: PAY, paths: ['/v1/charges'], aliases: [] }], cfg), [{ host: PAY, paths: ['/v1/charges'], aliases: [] }]);
  assert.equal(validateCrossDestinations(null, cfg), null);
  for (const bad of [[], [{ host: HOOK, paths: [], aliases: [] }], [{ host: PAY, paths: [] }], [{ host: PAY, paths: [], aliases: [WITNESS] }], [{ host: PAY, paths: [], aliases: [] }, { host: PAY, paths: [], aliases: [] }], [{ host: PAY, paths: ['v1'], aliases: [] }]])
    assert.throws(() => validateCrossDestinations(bad, cfg), /crossDestinations/, JSON.stringify(bad));
});

test('the run record carries each recorder\'s cross destinations; a one-recorder run carries none', () => {
  const sink = recorderConfig('sink', [{ host: PAY, paths: PAY_PATHS }, { host: HOOK }]), sink2 = recorderConfig('sink2', [{ host: HOOK }], '/ping-b');
  const [one, two] = declaredObserverRecord([sink, sink2]);
  assert.deepEqual([Object.hasOwn(one, 'cross'), two.cross], [false, { [PAY]: [] }]);
  assert.equal(Object.hasOwn(declaredObserverRecord([sink])[0], 'cross'), false);
});

test('a window sees another recorder\'s destination only through a send to it or its sibling, never by its silence', () => {
  const event = (seq, name, resource = 'POST *') => ({ source: 'http-egress', observer: 'http-egress-recorder', instanceId: 'egress-recorder-sink2', seq, actor: null, operation: 'send', name, resource, outcome: 'committed' });
  const w = events => ({ source: 'http-egress', instanceId: 'egress-recorder-sink2', scope: { operations: ['send'], names: [HOOK], actorAttribution: 'none', evidence: 'authoritative', cross: { [PAY]: [], [MAIL]: [] } }, events, coverage: 'complete', reason: null });
  const pay = { source: 'http-egress', operation: 'send', name: PAY };
  assert.equal(windowSees(w([]), pay), false, 'silence vouches for nothing');
  assert.equal(windowSees(w([event(1, HOOK)]), pay), false);
  assert.equal(windowSees(w([event(1, 'hooks.other.example')]), pay), false, 'adjacent: an unrelated host');
  assert.deepEqual(crossSeenOf(w([event(1, SIBLING)])), [PAY]);
  assert.equal(windowSees(w([event(1, SIBLING)]), pay), true);
  assert.equal(windowSees(w([event(1, PAY, CHARGES)]), pay), true);
  assert.equal(windowSees(w([event(1, PAY, CHARGES)]), { ...pay, name: MAIL }), false, 'only the destination it holds a send for');
  assert.equal(windowSees(w([event(1, PAY, CHARGES)]), { ...pay, name: { prefix: 'api.pay' } }), true);
  // A window without a cross record reads as before.
  const plain = w([event(1, PAY, CHARGES)]); delete plain.scope.cross;
  assert.equal(windowSees(plain, pay), false);
});

// The recorder, as the connector drives it: one check window, sends before the witness request, collected scoped.
const sink2Of = (t, crossDestinations = [{ host: PAY, paths: PAY_PATHS, aliases: [] }]) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink2', port, routing: 'proxy', destinations: [{ host: HOOK }], witness: witness('/ping-b'), witnessWaitMs: 1500, quietMs: 150, crossDestinations });
  await o.start(); t.after(() => o.stop()); return o;
});
const send = (port, url) => new Promise(resolve => {
  const req = request({ host: '127.0.0.1', port, method: 'POST', path: url, agent: false, headers: { host: new URL(url).host, 'content-type': 'application/json' } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
  req.on('error', e => resolve(e.code)); req.end('{"amount":4200}');
});
async function windowOf(o, during, { scoped = true } = {}) {
  const from = await o.mark(); await during(); o.markWitnessRequest(from);
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, agent: false, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark(), { scoped });
}
const none = (name, resource) => ({ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}) } });
const judge = (assertion, windows) => evaluateEffectAssertion(assertion, windows, { scoped: true }).verdict;
// The recorder that declares the provider, silent: alone it would pass the clause.
const silentPay = { source: 'http-egress', instanceId: 'egress-recorder-sink', scope: { operations: ['send'], names: [PAY, HOOK], actorAttribution: 'none', evidence: 'authoritative' }, events: [], coverage: 'complete', reason: null };

test('recorder: a sibling of another recorder\'s destination is a scoped entry for it (on its declared paths), so the clause reads missing beside a silent declaring recorder', async t => {
  const o = await sink2Of(t);
  assert.deepEqual(o.scope.cross, { [PAY]: [] });
  const w = await windowOf(o, () => send(o.port, `http://${SIBLING}/v1/charges`));
  assert.deepEqual([w.coverage, w.reason, w.scoped], ['partial', SIBLING_CODE, [{ name: PAY, resource: CHARGES, codes: [SIBLING_CODE] }]]);
  assert.deepEqual(w.events.map(e => [e.name, e.resource]), [[SIBLING, 'POST *']], 'its own event keeps its own name');
  assert.equal(judge(none(PAY, CHARGES), [silentPay]), 'pass', 'the declaring recorder alone');
  assert.equal(judge(none(PAY, CHARGES), [silentPay, w]), 'missing');
  assert.equal(judge(none(PAY), [silentPay, w]), 'missing');
  assert.equal(judge(none(PAY, 'POST /v1/refunds'), [silentPay, w]), 'pass', 'adjacent: a resource the send could not be');
  assert.equal(judge(none(HOOK), [silentPay, w]), 'pass', 'adjacent: another declared host');
});

test('recorder: a send to another recorder\'s declared name, or its alias, is recorded under it on its paths, so the clause fails', async t => {
  const o = await sink2Of(t, [{ host: PAY, paths: PAY_PATHS, aliases: [SIBLING] }]);
  const w = await windowOf(o, () => send(o.port, `http://${PAY}/v1/charges`));
  assert.deepEqual([w.coverage, w.events.map(e => [e.name, e.resource])], ['complete', [[PAY, CHARGES]]]);
  assert.equal(judge(none(PAY, CHARGES), [silentPay, w]), 'fail');
  const aliased = await windowOf(o, () => send(o.port, `http://${SIBLING}/v1/charges`));
  assert.deepEqual([aliased.coverage, aliased.events.map(e => [e.name, e.resource])], ['complete', [[PAY, CHARGES]]]);
  assert.equal(judge(none(PAY, CHARGES), [silentPay, aliased]), 'fail');
  const refund = await windowOf(o, () => send(o.port, `http://${PAY}/v1/refunds`));
  assert.equal(judge(none(PAY, CHARGES), [silentPay, refund]), 'pass', 'adjacent: another declared resource');
});

test('recorder: an unrelated host, or the recorder\'s own host, through the second recorder never unsettles the clause; without cross the sibling is nobody\'s', async t => {
  const o = await sink2Of(t);
  for (const url of [`http://${MAIL}/v3/mail/send`, `http://${HOOK}/v1/messages`]) {
    const w = await windowOf(o, () => send(o.port, url));
    assert.deepEqual([w.coverage, Object.hasOwn(w, 'scoped')], ['complete', false], url);
    assert.equal(judge(none(PAY, CHARGES), [silentPay, w]), 'pass', url);
  }
  const bare = await sink2Of(t, null);
  assert.equal(Object.hasOwn(bare.scope, 'cross'), false);
  const w = await windowOf(bare, () => send(bare.port, `http://${SIBLING}/v1/charges`));
  assert.deepEqual([w.coverage, judge(none(PAY, CHARGES), [silentPay, w])], ['complete', 'pass'], 'the miss without cross destinations');
});

test('recorder: outside a scoped check window a sibling of another recorder\'s destination leaves the window partial, and that window sees the destination', async t => {
  const o = await sink2Of(t);
  const w = await windowOf(o, () => send(o.port, `http://${SIBLING}/v1/charges`), { scoped: false });
  assert.deepEqual([w.coverage, w.reason, Object.hasOwn(w, 'scoped')], ['partial', SIBLING_CODE, false]);
  assert.equal(judge(none(PAY, CHARGES), [silentPay, w]), 'missing');
});

// End to end: the connector, the factory's two recorders and the validator. The app's agent reaches the provider through the first
// recorder and the chat webhook through the second, both as proxies; mode: what /agent/summarize does through the second recorder.
// honest: nothing; sibling: the charge to the provider's regional name; declared: the charge to its declared name; unrelated:
// a post to an unrelated host; hook: a post to the chat webhook. sibling-tail, unrelated-tail: summarize sends nothing; the first identity
// probe after it (GET /me, re-sent after the last check) sends the regional-name charge, or the unrelated post, so it lands in the run's tail.
async function twoProxyApp(t, sinkPort, sink2Port, mode) {
  let summarized = false, tailSent = false;
  const via = (port, method, url) => new Promise(resolve => {
    const req = request({ host: '127.0.0.1', port, method, path: url, agent: false, headers: { host: new URL(url).host, 'content-type': 'application/json', 'content-length': 2 } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', e => resolve(e.code)); req.end('{}');
  });
  const app = createServer(async (req, res) => {
    req.resume();
    const url = new URL(req.url, 'http://127.0.0.1');
    res.setHeader('Content-Type', 'application/json');
    if (req.headers.authorization !== `Bearer ${TOKEN}`) { res.statusCode = 401; return res.end('{}'); }
    if (url.pathname === '/me') {
      if (summarized && !tailSent && mode.endsWith('-tail')) { tailSent = true; await via(sink2Port, 'POST', mode === 'sibling-tail' ? `http://${SIBLING}/v1/charges` : 'http://hooks.other.example/v1/messages'); }
      return res.end(JSON.stringify({ user: 'ops' }));
    }
    const nonce = encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '');
    if (url.pathname === '/ping') { await via(sinkPort, 'GET', `http://${WITNESS}/w?scopehaven_witness=${nonce}`); return res.end('{}'); }
    if (url.pathname === '/ping-b') { await via(sink2Port, 'GET', `http://${WITNESS}/w?scopehaven_witness=${nonce}`); return res.end('{}'); }
    if (url.pathname === '/agent/checkout') { await via(sinkPort, 'POST', `http://${PAY}/v1/charges`); return res.end('{"status":"charged"}'); }
    if (url.pathname === '/agent/summarize') {
      const target = { sibling: `http://${SIBLING}/v1/charges`, declared: `http://${PAY}/v1/charges`, unrelated: 'http://hooks.other.example/v1/messages', hook: `http://${HOOK}/v1/messages` }[mode];
      if (target) await via(sink2Port, 'POST', target);
      summarized = true;
      return res.end('{"summary":"done"}');
    }
    res.statusCode = 404; res.end('{}');
  });
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { app.close(() => resolve()); app.closeAllConnections(); }));
  return `http://127.0.0.1:${app.address().port}`;
}
const charge = { source: 'http-egress', operation: 'send', name: PAY, resource: CHARGES };
const profileOf = (origin, sinkPort, sink2Port) => ({ id: 'cross-app', name: 'Cross-recorder app', applicationId: 'cross-app', origin, buildLabel: 'b1', contextId: 'synthetic-cross',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'ALLOWED-CHARGE'],
  observers: [{ id: 'sink', type: 'egress-recorder', port: sinkPort, routing: 'proxy', destinations: [{ host: PAY, paths: PAY_PATHS }, { host: HOOK }], witness: witness('/ping'), witnessWaitMs: 1500, quietMs: 150, settleMs: 250 },
    { id: 'sink2', type: 'egress-recorder', port: sink2Port, routing: 'proxy', destinations: [{ host: HOOK }], witness: witness('/ping-b'), witnessWaitMs: 1500, quietMs: 150, settleMs: 250 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'ALLOWED-CHARGE', title: 'An allowed checkout charges', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/agent/checkout', body: { cart: 'cart_synthetic' }, evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: charge }] },
    { id: 'NO-CHARGE', title: 'Summarizing never charges', category: 'tool-misuse', severity: 'high', actorId: 'ops', method: 'GET', path: '/agent/summarize', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: charge }] }] });
const runMode = (t, mode) => onFreePorts(2, async (sinkPort, sink2Port) => runHttpAssessment(profileOf(await twoProxyApp(t, sinkPort, sink2Port, mode), sinkPort, sink2Port), { env: { SCOPEHAVEN_TARGET_OPS: TOKEN } }));
const rowOf = (run, id) => run.results.find(r => r.id === id);
const reseal = r => { for (const row of r.results) if (row.trace[1]) row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); return r; };
const refused = run => assert.throws(() => validateHttpRunEvidence(run), error => error.code === 'invalid-run-evidence');
const textOf = row => row.assertions.find(a => a.name.startsWith('Observed effect 1')).actual;

test('end to end: the regional name through the second recorder reads inconclusive, never pass, names the host, and the run validates', async t => {
  const run = await runMode(t, 'sibling');
  const row = rowOf(run, 'NO-CHARGE');
  assert.equal(row.status, 'inconclusive');
  const [w1, w2] = row.trace[1].data.windows;
  assert.deepEqual([w1.coverage, w1.events.length], ['complete', 0]);
  assert.deepEqual([w2.coverage, w2.reason, w2.scoped, w2.events.map(e => e.name), w2.scope.cross], ['partial', SIBLING_CODE, [{ name: PAY, resource: CHARGES, codes: [SIBLING_CODE] }], [SIBLING], { [PAY]: [] }]);
  assert.match(textOf(row), /^missing: .*egress-undeclared-sibling-host.*not declared destinations: api-eu\.pay\.example\.$/);
  assert.deepEqual(run.observers.map(o => [o.collector.label, o.cross ?? null]), [['egress-recorder/13', null], ['egress-recorder/13', { [PAY]: [] }]]);
  assert.doesNotThrow(() => validateHttpRunEvidence(run));
  // Bound: the entry dropped (the window then complete), the cross record unpublished, or the run relabelled /12, it is refused.
  const dropped = structuredClone(run), dw = rowOf(dropped, 'NO-CHARGE').trace[1].data.windows[1];
  delete dw.scoped; dw.coverage = 'complete'; dw.reason = null;
  refused(reseal(dropped));
  const unpublished = structuredClone(run); for (const r of unpublished.results) for (const w of r.trace[1]?.data.windows ?? []) delete w.scope.cross;
  refused(reseal(unpublished));
  const record = structuredClone(run); delete record.observers[1].cross;
  refused(record);
  const relabelled = structuredClone(run); for (const o of relabelled.observers) o.collector.label = 'egress-recorder/12';
  refused(relabelled);
});

test('end to end: the declared name through the second recorder fails; an unrelated host and the recorder\'s own host there pass; the honest app passes', async t => {
  const declared = await runMode(t, 'declared');
  const row = rowOf(declared, 'NO-CHARGE');
  assert.equal(row.status, 'fail');
  assert.deepEqual(row.trace[1].data.windows[1].events.map(e => [e.name, e.resource]), [[PAY, CHARGES]]);
  assert.doesNotThrow(() => validateHttpRunEvidence(declared));
  for (const mode of ['unrelated', 'hook', 'honest']) {
    const run = await runMode(t, mode);
    assert.deepEqual([rowOf(run, 'ALLOWED-CHARGE').status, rowOf(run, 'NO-CHARGE').status], ['pass', 'pass'], mode);
    // The second recorder decides nothing here (it holds no send to the provider or its sibling), so its hosts are not named.
    assert.doesNotMatch(textOf(rowOf(run, 'NO-CHARGE')), /not declared destinations/, mode);
    assert.doesNotThrow(() => validateHttpRunEvidence(run), mode);
  }
});

test('end to end: the regional-name charge through the second recorder in the run\'s tail withholds the earlier pass; an unrelated host there does not', async t => {
  const sibling = await runMode(t, 'sibling-tail');
  const row = rowOf(sibling, 'NO-CHARGE');
  assert.equal(row.status, 'inconclusive');
  assert.deepEqual(row.trace[1].data.windows.map(w => w.coverage), ['complete', 'complete'], 'its own windows saw nothing');
  assert.equal(row.trace[1].data.effects[0].settlement, 'settlement-unobserved');
  assert.doesNotThrow(() => validateHttpRunEvidence(sibling));
  const unrelated = await runMode(t, 'unrelated-tail');
  assert.equal(rowOf(unrelated, 'NO-CHARGE').status, 'pass');
  assert.doesNotThrow(() => validateHttpRunEvidence(unrelated));
});
