// Egress recorder correlation (src/egress-rules.mjs, integrations/observers/egress-recorder.mjs):
// a destination that declares the run's correlation header records the token one well-formed value carries in
// event.correlation.settlementToken, and nothing else. Every request goes to 127.0.0.1; destination hosts are names only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { createEgressRecorder } from './egress-recorder.mjs';
import { onFreePorts } from './fixtures/free-port.mjs';
import { collectWindow, evaluateEffectAssertion, validateEffect, makeEffect } from './events.mjs';
import { validateEgressConfig, correlationTokenOf, correlationHeaderValue, correlationToken, correlationHeaderValid, correlationRecorded } from '../../src/egress-rules.mjs';

const PAY = 'api.pay.example', HOOK = 'hooks.chat.example', WITNESS = 'witness.scopehaven.invalid';
// TOKEN is the bare 32-hex form of the synthetic UUID ID, derived (not hard-coded) so no key-like literal sits in the file.
const ID = '3f1c2a9e-7b4d-4e8f-9a61-0c5d2e7f8b90', TOKEN = ID.replaceAll('-', '');
const config = (header, extra = {}) => ({ port: 47000, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges'], correlation: { header } }, { host: HOOK }],
  witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, ...extra });
function recorder(t, header) {
  return onFreePorts(1, async port => {
    const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', ...config(header, { port }) });
    await o.start(); t.after(() => o.stop());
    return o;
  });
}
function send(o, target, headers = {}) {
  return new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: o.port, method: url.host === WITNESS ? 'GET' : 'POST', path: target, headers: { host: url.host, ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(null));
    req.end();
  });
}
async function window(o, sends) {
  const from = await o.mark();
  for (const [target, headers] of sends) await send(o, target, headers);
  o.markWitnessRequest(from);
  await send(o, `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, { traceparent: `00-${TOKEN}-1111111111111111-01` });
  return collectWindow(o, from, await o.mark());
}

test('header rules: the connector value, the parsed token and the accepted names', () => {
  assert.equal(correlationToken(ID), TOKEN);
  assert.equal(correlationToken(ID.toUpperCase()), TOKEN);
  assert.equal(correlationToken('00000000-0000-0000-0000-000000000000'), null);
  assert.equal(correlationHeaderValue('traceparent', ID, 'a1b2c3d4e5f60718'), `00-${TOKEN}-a1b2c3d4e5f60718-01`);
  assert.equal(correlationHeaderValue('x-request-id', ID), ID);
  assert.throws(() => correlationHeaderValue('traceparent', ID, '0000000000000000'), /correlation-header/);
  assert.throws(() => correlationHeaderValue('authorization', ID), /correlation-header/);
  assert.equal(correlationTokenOf('traceparent', [`00-${TOKEN}-a1b2c3d4e5f60718-01`]), TOKEN);
  for (const values of [[], [`00-${TOKEN}-a1b2c3d4e5f60718-01`, `00-${TOKEN}-a1b2c3d4e5f60718-01`], [`00-${TOKEN.toUpperCase()}-a1b2c3d4e5f60718-01`], [`01-${TOKEN}-a1b2c3d4e5f60718-01`],
    [`00-${'0'.repeat(32)}-a1b2c3d4e5f60718-01`], [`00-${TOKEN}-0000000000000000-01`], [`00-${TOKEN}-a1b2c3d4e5f60718`], ['garbage']]) assert.equal(correlationTokenOf('traceparent', values), null, JSON.stringify(values));
  assert.equal(correlationTokenOf('x-request-id', [ID]), TOKEN, 'the exact value the connector sent');
  // Normalization never creates a match, so a re-cased custom value carries no token.
  for (const values of [['not-a-uuid'], [TOKEN], [ID, ID], [ID.toUpperCase()], [`${ID.slice(0, 8).toUpperCase()}${ID.slice(8)}`], [` ${ID}`]]) assert.equal(correlationTokenOf('x-request-id', values), null, JSON.stringify(values));
  assert.ok(['traceparent', 'x-request-id', 'x-correlation-id'].every(correlationHeaderValid));
  assert.ok(!['tracestate', 'authorization', 'x-scopehaven', 'X-Request-Id', 'x-'].some(correlationHeaderValid));
  // Configuration: { header } only, and the recorded pairs follow the destinations that declare it.
  assert.equal(validateEgressConfig(config('traceparent'), { ops: {} }).destinations[0].correlation, 'traceparent');
  assert.equal(validateEgressConfig(config('traceparent'), { ops: {} }).destinations[1].correlation, null);
  assert.throws(() => validateEgressConfig({ ...config('traceparent'), destinations: [{ host: PAY, correlation: { header: 'traceparent', copy: true } }] }, { ops: {} }), /"correlation" is \{ header \}/);
  assert.throws(() => validateEgressConfig({ ...config('traceparent'), destinations: [{ host: PAY, correlation: 'traceparent' }] }, { ops: {} }), /"correlation" is \{ header \}/);
  assert.deepEqual(correlationRecorded([{ id: 'sink', type: 'egress-recorder', ...config('traceparent') }, { id: 'mail', type: 'smtp-sink' }]), [{ observer: 'sink', names: [PAY] }]);
});

test('recorder: one well-formed header gives the token; a duplicate, malformed, all-zero or uppercase value, an undeclared destination and the witness give none', async t => {
  const o = await recorder(t, 'traceparent');
  const w = await window(o, [
    [`http://${PAY}/v1/charges`, { traceparent: `00-${TOKEN}-a1b2c3d4e5f60718-01` }],
    [`http://${PAY}/v1/charges`, { traceparent: [`00-${TOKEN}-a1b2c3d4e5f60718-01`, `00-${TOKEN}-a1b2c3d4e5f60719-01`] }],
    [`http://${PAY}/v1/charges`, { traceparent: `00-${TOKEN.toUpperCase()}-a1b2c3d4e5f60718-01` }],
    [`http://${PAY}/v1/charges`, { traceparent: `00-${'0'.repeat(32)}-a1b2c3d4e5f60718-01` }],
    [`http://${PAY}/v1/charges`, { traceparent: 'garbage' }],
    [`http://${PAY}/v1/charges`, {}],
    [`http://${HOOK}/x`, { traceparent: `00-${TOKEN}-a1b2c3d4e5f60718-01` }],
  ]);
  assert.deepEqual([w.coverage, w.reason], ['complete', null]);
  assert.deepEqual(w.events.map(e => [e.name, e.correlation.settlementToken ?? null]), [[PAY, TOKEN], [PAY, null], [PAY, null], [PAY, null], [PAY, null], [PAY, null], [HOOK, null]]);
  assert.ok(w.events.every(e => e.name !== WITNESS), 'the witness is never an effect, so never tagged');
});

test('recorder: a custom header carries the exact lowercase UUID; any letter case of the name is read once, a re-cased value is not', async t => {
  const o = await recorder(t, 'x-request-id');
  const w = await window(o, [
    [`http://${PAY}/v1/charges`, { 'X-Request-ID': ID }],
    [`http://${PAY}/v1/charges`, { 'X-Request-ID': ID.toUpperCase() }],
    [`http://${PAY}/v1/charges`, { 'x-request-id': TOKEN }],
    [`http://${PAY}/v1/charges`, { traceparent: `00-${TOKEN}-a1b2c3d4e5f60718-01` }],
  ]);
  assert.deepEqual(w.events.map(e => e.correlation.settlementToken ?? null), [TOKEN, null, null, null]);
});

// Never pass or fail on the application's own self-written token alone.
// APP is a well-formed trace id the application chose (never a connector token), derived from ID so no key-like literal sits here.
const APP = [...TOKEN].reverse().join('');
const scoped = w => ({ source: 'http-egress', instanceId: 'egress-recorder-sink', scope: { operations: ['send'], names: [PAY, HOOK], actorAttribution: 'none', evidence: 'authoritative' }, ...w });
test('forbidden: an app-chosen value is recorded only as settlementToken; a traceId selector never reads it, so it neither passes nor fails a clause', async t => {
  // The format check cannot tell the connector's token from the app's own value: both are recorded (stated in the docs).
  assert.equal(correlationTokenOf('traceparent', [`00-${APP}-1111111111111111-01`]), APP);
  const o = await recorder(t, 'traceparent');
  const forged = scoped(await window(o, [[`http://${PAY}/v1/charges`, { traceparent: `00-${APP}-1111111111111111-01` }]]));
  const bare = scoped(await window(o, [[`http://${PAY}/v1/charges`, {}]]));
  assert.deepEqual([forged.coverage, forged.events.map(e => e.correlation)], ['complete', [{ settlementToken: APP }]]);
  assert.ok([...forged.events, ...bare.events].every(e => !Object.hasOwn(e.correlation, 'traceId')), 'an http-egress event never carries a traceId');
  const pinned = { source: 'http-egress', operation: 'send', name: PAY, traceId: APP };
  // The same send with and without the app's value reads the same: the value decides nothing.
  for (const w of [forged, bare]) {
    assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: pinned }, [w]).verdict, 'fail', 'effect.exists is not passed by the app value');
    assert.equal(evaluateEffectAssertion({ kind: 'effect.count', select: pinned, expected: 1 }, [w]).verdict, 'fail', 'effect.count is not passed by the app value');
  }
  // Allowed, adjacent: the unpinned selector still matches the committed send in both windows.
  for (const w of [forged, bare]) assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: PAY } }, [w]).verdict, 'pass');
});
test('settlementToken lives only on http-egress events, and an http-egress event never carries a traceId', () => {
  const observer = { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' };
  const egress = correlation => makeEffect({ source: 'http-egress', observer, seq: 1, operation: 'send', name: PAY, outcome: 'committed', correlation });
  const otel = correlation => makeEffect({ source: 'otel-genai', observer: { kind: 'otel', instanceId: 'otel-1' }, seq: 1, operation: 'send', name: PAY, outcome: 'committed', correlation });
  // Allowed.
  assert.deepEqual(egress({ settlementToken: APP }).correlation, { settlementToken: APP });
  assert.deepEqual(egress({}).correlation, {});
  assert.deepEqual(otel({ traceId: APP }).correlation, { traceId: APP });
  // Forbidden: refused at validation, so a stored record cannot move the value into a selector field.
  assert.throws(() => egress({ traceId: APP }), /correlation/);
  assert.throws(() => egress({ traceId: APP, settlementToken: APP }), /correlation/);
  assert.throws(() => otel({ settlementToken: APP }), /correlation/);
  const stored = egress({ settlementToken: APP });
  assert.throws(() => validateEffect({ ...stored, correlation: { traceId: APP } }), /correlation/);
});
