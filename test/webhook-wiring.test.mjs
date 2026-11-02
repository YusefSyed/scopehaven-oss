// The signed-webhook wiring (src/http-connector.mjs, src/contracts.mjs, src/registry.mjs): a check that declares "webhook" is
// sent by the connector itself as its provider would send it (src/webhook-driver.mjs builds the exact bytes and headers), with no
// operator transport. Over real loopback HTTP into owned fixture apps: the statuses, the record on each sent webhook row and on the
// run, the exported suite's key slots (never a variable name), the run validating with and without that suite while a moved or
// dropped record reads invalid-run-evidence against it, the requests exactly as they reach the app (checked by independent
// verifiers), and the profile rules that keep the connector's own headers and the run's other credentials apart from the
// driver's. Every request goes to 127.0.0.1; every provider host is a name only; every key is synthetic and built at run time.
// The driver's own tests are test/webhook-driver.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createHash, createHmac, createPrivateKey, createPublicKey, randomUUID, timingSafeEqual, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createWebhookDriver, stripeSignature, WebhookDriverError, WEBHOOK_PROVIDERS } from '../src/webhook-driver.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { observeHttp, runHttpAssessment } from '../src/http-connector.mjs';
import { digest } from '../src/domain.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import * as R2 from './fixtures/in-doubt-r2-cases.mjs';

// Synthetic keys, built from parts at run time so no literal looks like a credential.
const synthetic = (...parts) => ['synthetic', 'webhook', ...parts, 'k7'].join('-');
const seedFrom = label => createHash('sha256').update(synthetic(label)).digest().toString('base64');
const ENV = Object.freeze({ twilio: 'SCOPEHAVEN_TARGET_TWILIO_AUTH_TOKEN', twilioForged: 'SCOPEHAVEN_TARGET_FORGED_TWILIO_TOKEN', stripe: 'SCOPEHAVEN_TARGET_STRIPE_WHSEC',
  telnyx: 'SCOPEHAVEN_TARGET_TELNYX_SEED', billing: 'SCOPEHAVEN_TARGET_BILLING_WHSEC', ops: 'SCOPEHAVEN_TARGET_OPS', gateway: 'SCOPEHAVEN_TARGET_GATEWAY' });
const KEY = Object.freeze({ [ENV.twilio]: synthetic('twilio', 'one'), [ENV.twilioForged]: synthetic('twilio', 'forged'), [ENV.stripe]: ['wh', 'sec_', synthetic('stripe', 'one')].join(''),
  [ENV.telnyx]: seedFrom('telnyx-one'), [ENV.billing]: ['wh', 'sec_', synthetic('billing')].join(''), [ENV.ops]: synthetic('ops', 'bearer'), [ENV.gateway]: synthetic('gateway', 'key') });
const SMS = Object.freeze({ MessageSid: 'SM0000000000000000000000000000001', AccountSid: 'AC0000000000000000000000000000001', From: '+15550100001', To: '+15550100002', Body: 'Call me back & soon, please' });
const EVENT = Object.freeze({ id: 'evt_0001', type: 'invoice.paid', data: { object: { id: 'in_0001', amount_paid: 2500 } } });
const TELNYX_EVENT = Object.freeze({ data: { event_type: 'message.received', id: 'b301ed3f-0000-4000-8000-000000000001', payload: { direction: 'inbound', text: 'call me back' } }, meta: { attempt: 1 } });
const load = target => { try { validateTargetFile({ schemaVersion: 1, targets: [target] }); return 'loaded'; } catch (error) { return error.message; } };
const drive = (target, env) => { try { createWebhookDriver({ target, env }).close(); return 'created'; } catch (error) { return `${error.code}: ${error.message}`; } };
const outcome = async action => { try { await action(); return 'ok'; } catch (error) { return error instanceof WebhookDriverError ? `${error.code}: ${error.message}` : error.message; } };

// Independent verifiers, written from each provider's documentation.
// Twilio (webhooks-security): HMAC-SHA1 under the auth token of the URL and the sorted POST parameters, base64.
function twilioValid(token, url, params, header) {
  let text = url;
  for (const name of [...new Set(params.keys())].sort()) for (const value of [...new Set(params.getAll(name))].sort()) text += name + value;
  const expected = createHmac('sha1', token).update(text, 'utf8').digest(), got = Buffer.from(String(header ?? ''), 'base64');
  return typeof header === 'string' && got.length === expected.length && timingSafeEqual(got, expected);
}
// Twilio, a JSON body (webhooks-security; twilio-node validateRequestWithBody): the URL's bodySHA256 is the body's hex SHA-256, and
// the signature covers the URL alone.
function twilioJsonValid(token, url, raw, header) {
  const hash = new URL(url).searchParams.get('bodySHA256');
  return hash === createHash('sha256').update(raw).digest('hex') && twilioValid(token, url, new URLSearchParams(), header);
}
// Stripe (webhooks#verify-manually): split on ",", then "="; t and every v1; HMAC-SHA256 of "<t>.<body>"; constant-time compare; tolerance.
function stripeValid(secret, header, raw, nowSeconds, tolerance = 300) {
  let t = null; const v1 = [];
  for (const element of String(header ?? '').split(',')) { const at = element.indexOf('='); const [prefix, value] = [element.slice(0, at), element.slice(at + 1)]; if (prefix === 't') t = /^\d+$/.test(value) ? Number(value) : null; if (prefix === 'v1') v1.push(value); }
  if (t === null || !v1.length) return false;
  const expected = Buffer.from(createHmac('sha256', secret).update(Buffer.concat([Buffer.from(`${t}.`), raw])).digest('hex'));
  return v1.some(s => s.length === expected.length && timingSafeEqual(Buffer.from(s), expected)) && Math.abs(nowSeconds - t) <= tolerance;
}
// Telnyx (receiving-webhooks): Ed25519 over "<telnyx-timestamp>|<raw body>", the signature base64, the public key raw 32 bytes base64.
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const publicKeyOf = seedBase64 => createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedBase64, 'base64')]), format: 'der', type: 'pkcs8' }))
  .export({ format: 'der', type: 'spki' }).subarray(SPKI.length).toString('base64');
function telnyxValid(publicKey, signature, timestamp, raw, nowSeconds, tolerance = 300) {
  if (typeof signature !== 'string' || typeof timestamp !== 'string' || !/^\d+$/.test(timestamp)) return false;
  const key = createPublicKey({ key: Buffer.concat([SPKI, Buffer.from(publicKey, 'base64')]), format: 'der', type: 'spki' });
  return verify(null, Buffer.concat([Buffer.from(`${timestamp}|`), raw]), key, Buffer.from(signature, 'base64')) && Math.abs(nowSeconds - Number(timestamp)) <= tolerance;
}

// The worked example: an inbound Twilio-style SMS into an owned fixture app, whose write path sends one Stripe-style event
// to billing through the egress recorder, signed with the app's own synthetic billing secret; a connector run drives it.
// defect: null (verifies every signature), "none" (verifies nothing) or "header-optional" (verifies a signature only when the
// request carries one). requests: every request the app received (method and path).
const PUBLIC_URL = 'https://sms-app.example.test', BILLING = 'billing.example.test', WITNESS = 'witness.scopehaven.invalid';
async function smsApp(t, sinkPort, { defect = null } = {}) {
  const requests = [];
  const relay = (host, path, headers = {}, body = null) => new Promise(resolve => {
    const r = request({ host: '127.0.0.1', port: sinkPort, method: body === null ? 'GET' : 'POST', path: `http://${host}${path}`, agent: false, headers: { host, ...headers, ...(body === null ? {} : { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) }) } },
      x => { x.resume(); x.on('end', resolve); });
    r.on('error', resolve); r.end(body ?? undefined);
  });
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
      const raw = Buffer.concat(chunks), url = new URL(req.url, 'http://127.0.0.1');
      requests.push(`${req.method} ${url.pathname}`);
      if (url.pathname === '/me') return req.headers.authorization === `Bearer ${KEY[ENV.ops]}` ? reply(200, { user: 'ops' }) : reply(401, {});
      if (url.pathname === '/ping') { await relay(WITNESS, `/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
      if (url.pathname !== '/twilio/sms' || req.method !== 'POST') return reply(404, {});
      const params = new URLSearchParams(raw.toString()), header = req.headers['x-twilio-signature'];
      const valid = defect === 'none' || (defect === 'header-optional' && header === undefined) || twilioValid(KEY[ENV.twilio], `${PUBLIC_URL}${req.url}`, params, header);
      if (!valid) return reply(403, { error: 'signature' });
      const event = JSON.stringify({ id: `evt_${params.get('MessageSid')}`, type: 'usage.recorded', data: { sms: 1 } });
      await relay(BILLING, '/hooks/usage', { 'stripe-signature': stripeSignature(KEY[ENV.billing], Math.floor(Date.now() / 1000), event) }, event);
      reply(200, { ok: true });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${server.address().port}`, requests };
}
// The prohibitions' selectors name the billing host only. Pinning each to its own event id (a declared field) would need an
// allowed-use twin carrying the same field value (src/http-pairing.mjs), which a refused request never has.
const billingSends = [{ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: BILLING, resource: 'POST /hooks/usage' }, expected: 1, countBy: 'idempotency-key' }];
const noBilling = [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: BILLING } }];
const smsCheck = (id, severity, status, effects, sid) => ({ id, title: id, category: 'webhooks', severity, actorId: 'provider', method: 'POST', path: '/twilio/sms',
  body: { ...SMS, MessageSid: sid }, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: status }], effects });
const EXAMPLE_WEBHOOKS = Object.freeze({
  'SMS-SIGNED': { provider: 'twilio', secretEnv: ENV.twilio, url: `${PUBLIC_URL}/twilio/sms`, headers: { 'I-Twilio-Idempotency-Token': 'idem-signed' } },
  'SMS-FORGED': { provider: 'twilio', secretEnv: ENV.twilioForged, url: `${PUBLIC_URL}/twilio/sms` },
  'SMS-UNSIGNED': { provider: 'twilio', signature: 'omit', url: `${PUBLIC_URL}/twilio/sms` },
});
const exampleProfile = (origin, port) => ({ id: 'webhook-worked-example', name: 'Signed webhook worked example', applicationId: 'sms-fixture', origin, buildLabel: 'b1', contextId: 'synthetic-webhooks',
  actors: { ops: { principalId: 'ops', credentialEnv: ENV.ops, identityValue: 'ops' }, provider: { principalId: 'sms-provider' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: BILLING, paths: ['/hooks/usage'], idempotency: { pointer: '/id', signing: { scheme: 'stripe', signature: 'stripe-signature', secretEnv: [ENV.billing] } } }],
    witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250 }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    smsCheck('SMS-SIGNED', 'control', 200, billingSends, 'SM-signed'), smsCheck('SMS-FORGED', 'critical', 403, noBilling, 'SM-forged'), smsCheck('SMS-UNSIGNED', 'critical', 403, noBilling, 'SM-unsigned')] });
const withWebhooks = base => ({ ...base, checks: base.checks.map(c => (EXAMPLE_WEBHOOKS[c.id] ? { ...c, webhook: EXAMPLE_WEBHOOKS[c.id] } : c)) });
// The target's correlation header, recorded on a second egress destination (a correlation header needs one that records it).
const correlated = (p, header) => ({ ...p, correlation: { header }, observers: p.observers.map(o => ({ ...o, destinations: [...o.destinations, { host: 'audit.example.test', paths: ['/x'], correlation: { header } }] })) });
// The provider actor sending a header key; it sends every SMS check.
const keyedProvider = (p, credentialHeader) => ({ ...p, actors: { ...p.actors, provider: { principalId: 'sms-provider', credentialEnv: ENV.gateway, credentialHeader } } });
const exampleRun = (t, { defect = null, shape = p => p } = {}) => onFreePorts(1, async port => {
  const app = await smsApp(t, port, { defect }), p = shape(withWebhooks(exampleProfile(app.origin, port))), watch = watchingBinds(buildObservers);
  let run = null, refused = null;
  try { run = await runHttpAssessment(p, { env: { ...KEY }, observerFactory: watch.factory }); } catch (error) { refused = error.message; }
  return { p, app, run, refused, lostBind: watch.state.lostBind };
}, r => r.lostBind);
const evidence = (run, opts) => { try { validateHttpRunEvidence(run, opts); return 'ok'; } catch (e) { return `${e.code}${e.detail ? ':' + e.detail : ''}`; } };
// Each edited row is resealed (its evidenceDigest recomputed), so only the webhook rule in validateHttpRunEvidence can refuse it.
const reseal = row => { row.evidenceDigest = digest(row.trace.length === 2 ? { evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions } : { evidence: row.trace[0].data, assertions: row.assertions }); };

test('wired: the connector sends declared webhook checks, records them, and the run validates against its exported suite', async t => {
  const out = {};
  for (const defect of [null, 'none']) {
    const r = await exampleRun(t, { defect });
    assert.equal(r.refused, null);
    const suite = createRegistry({ profiles: [r.p], env: { [ENV.ops]: KEY[ENV.ops] } }).exportSuite(r.p.id);
    const row = id => r.run.results.find(x => x.id === id);
    // Moved: the forged check's record re-pointed to the real key, its variable and its digest together, so only the suite's slots refuse it.
    const tampered = structuredClone(r.run), moved = tampered.results.find(x => x.id === 'SMS-FORGED'), real = tampered.webhookDriver.keys.find(k => k.secretEnv === ENV.twilio);
    Object.assign(moved.trace[0].data.webhook, { secretEnv: real.secretEnv, keyDigest: real.keyDigest }); reseal(moved);
    const dropped = structuredClone(r.run), bare = dropped.results.find(x => x.id === 'SMS-SIGNED'); delete bare.trace[0].data.webhook; reseal(bare);
    out[defect ?? 'fixed'] = { statuses: Object.fromEntries(r.run.results.map(x => [x.id, x.status])), suiteViews: suite.checks.filter(c => c.webhook).map(c => [c.id, c.webhook.key]),
      suiteHasNames: JSON.stringify(suite).includes('TWILIO'), valid: evidence(r.run), validSuite: evidence(r.run, { expectedSuite: suite }),
      tampered: evidence(tampered, { expectedSuite: suite }), tamperedNoSuite: evidence(tampered), dropped: evidence(dropped, { expectedSuite: suite }), droppedNoSuite: evidence(dropped),
      recorded: ['SMS-SIGNED', 'SMS-FORGED', 'SMS-UNSIGNED'].map(id => Boolean(row(id).trace[0].data.webhook)), driverRecord: Boolean(r.run.webhookDriver), unrecorded: Boolean(row('WHOAMI').trace[0].data.webhook) };
  }
  for (const build of ['fixed', 'none']) {
    const o = out[build];
    assert.deepEqual(o.suiteViews, [['SMS-SIGNED', 1], ['SMS-FORGED', 0], ['SMS-UNSIGNED', null]], `${build}: the suite's key slots`);
    assert.equal(o.suiteHasNames, false, `${build}: the exported suite names no key variable`);
    assert.deepEqual([o.recorded, o.driverRecord, o.unrecorded], [[true, true, true], true, false], `${build}: each sent webhook row and the run carry their records; other rows none`);
    assert.deepEqual([o.valid, o.validSuite], ['ok', 'ok'], `${build}: the run validates with and without its exported suite`);
    assert.deepEqual([o.tampered, o.dropped], ['invalid-run-evidence', 'invalid-run-evidence'], `${build}: a moved or dropped record, resealed, against the suite`);
    // Without the suite nothing says which checks declared a webhook, or under which key, so both read valid (KNOWN-LIMITS).
    assert.deepEqual([o.tamperedNoSuite, o.droppedNoSuite], ['ok', 'ok'], `${build}: a moved or dropped record without the suite`);
  }
  assert.deepEqual(out.fixed.statuses, { WHOAMI: 'pass', 'SMS-SIGNED': 'pass', 'SMS-FORGED': 'pass', 'SMS-UNSIGNED': 'pass' });
  assert.deepEqual(out.none.statuses, { WHOAMI: 'pass', 'SMS-SIGNED': 'pass', 'SMS-FORGED': 'fail', 'SMS-UNSIGNED': 'fail' });
});

// Earlier, the connector sent the correlation header after the driver's headers and the
// credential before them, so a correlation header named x-twilio-signature replaced the signature and gave the unsigned check
// one, and SMS-UNSIGNED read pass against an app that accepts unsigned deliveries; a credentialHeader of that name went out
// as the unsigned check's signature while the run recorded it as the credential.
test('a correlation header or a webhook actor\'s credentialHeader named as a provider header refuses the run before any request', async t => {
  for (const [label, shape, refusal] of [
    ['correlation x-twilio-signature', p => correlated(p, 'x-twilio-signature'), /the target's correlation header is X-Twilio-Signature, a twilio webhook header of check "SMS-SIGNED"/],
    ['credentialHeader X-Twilio-Signature', p => keyedProvider(p, 'X-Twilio-Signature'), /actor "provider" sends its key in X-Twilio-Signature, a twilio webhook header of its check "SMS-SIGNED"/],
  ]) {
    const r = await exampleRun(t, { defect: 'header-optional', shape });
    assert.equal(r.run?.results.find(x => x.id === 'SMS-UNSIGNED').status ?? 'not run', 'not run', `${label}: no run, so no SMS-UNSIGNED reading`);
    assert.match(r.refused ?? '', refusal, label);
    assert.deepEqual(r.app.requests, [], `${label}: nothing reached the application`);
  }
  // Without the clash, the same app's defect shows: SMS-UNSIGNED fails.
  const plain = await exampleRun(t, { defect: 'header-optional' });
  assert.equal(plain.run.results.find(x => x.id === 'SMS-UNSIGNED').status, 'fail');
});

test('the profile validator: header and key clashes and a bad declaration are refused; their neighbours load', () => {
  const base = withWebhooks(exampleProfile('http://127.0.0.1:9', 40999));
  assert.equal(load(base), 'loaded');
  // A provider header name, in any case, as the correlation header or as a webhook actor's credentialHeader (the extra
  // I-Twilio-Idempotency-Token too, declared or not); a name of no provider header, or on an actor that sends no webhook, loads.
  assert.match(load(correlated(base, 'x-twilio-signature')), /correlation header is X-Twilio-Signature/);
  for (const header of ['X-Twilio-Signature', 'x-twilio-signature', 'I-Twilio-Idempotency-Token']) assert.match(load(keyedProvider(base, header)), new RegExp(`sends its key in ${header.replace(/-/g, '\\-')}, a twilio webhook header`, 'i'), header);
  assert.equal(load(correlated(base, 'x-request-id')), 'loaded');
  assert.equal(load(keyedProvider(base, 'x-api-key')), 'loaded');
  assert.equal(load({ ...base, actors: { ...base.actors, ops: { ...base.actors.ops, credentialHeader: 'x-twilio-signature' } } }), 'loaded', 'the ops actor sends no webhook check');
  // The driver refuses the same clashes itself, for operator code that builds requests without the profile validator.
  assert.match(drive(correlated(base, 'x-twilio-signature'), { ...KEY }), /^webhook-header: the target's correlation header is X-Twilio-Signature/);
  assert.match(drive(keyedProvider(base, 'x-twilio-signature'), { ...KEY }), /^webhook-header: actor "provider" sends its key in X-Twilio-Signature/);
  assert.equal(drive(keyedProvider(base, 'x-api-key'), { ...KEY }), 'created');
  // Stripe and Telnyx: their header names cannot be a correlation header ("x-" names only), so only a credentialHeader can clash.
  const hooks = { ...base, checks: [base.checks[0], hookCheck('ST', '/stripe/events', structuredClone(EVENT), { provider: 'stripe', secretEnv: ENV.stripe }), hookCheck('TX', '/telnyx/messages', structuredClone(TELNYX_EVENT), { provider: 'telnyx', secretEnv: ENV.telnyx })] };
  assert.equal(load(hooks), 'loaded');
  assert.match(load(keyedProvider(hooks, 'stripe-signature')), /sends its key in Stripe-Signature, a stripe webhook header of its check "ST"/);
  assert.match(load(keyedProvider(hooks, 'Telnyx-Timestamp')), /sends its key in telnyx-timestamp, a telnyx webhook header of its check "TX"/);
  // The webhook key's variable as an actor's credential (a mutant without the profile clash check).
  assert.match(load({ ...base, actors: { ...base.actors, provider: { principalId: 'sms-provider', credentialEnv: ENV.twilio } } }), /webhook signing key variable SCOPEHAVEN_TARGET_TWILIO_AUTH_TOKEN is also named elsewhere in the profile/);
  // A declaration only the driver's rules refuse (a mutant without validateWebhookDeclaration in validCheck).
  const declared = webhook => ({ ...base, checks: base.checks.map(c => (c.id === 'SMS-SIGNED' ? { ...c, webhook: { ...c.webhook, ...webhook } } : c)) });
  assert.match(load(declared({ encoding: 'xml' })), /"webhook\.encoding" for twilio is "form" or "json"/);
  assert.match(load(declared({ url: `${PUBLIC_URL}/twilio/other` })), /"webhook\.url" is its origin followed by the check's own "path"/);
  // Unsigned checks only: the rule covers every provider header name, the signature's included, whether or
  // not the check is signed, at load and at driver creation.
  const unsignedOnly = { ...base, checks: base.checks.filter(c => c.id !== 'SMS-SIGNED' && c.id !== 'SMS-FORGED') };
  assert.equal(load(unsignedOnly), 'loaded');
  assert.match(load(correlated(unsignedOnly, 'x-twilio-signature')), /correlation header is X-Twilio-Signature, a twilio webhook header of check "SMS-UNSIGNED"/);
  assert.match(drive(correlated(unsignedOnly, 'x-twilio-signature'), { ...KEY }), /^webhook-header: the target's correlation header is X-Twilio-Signature/);
  const unsignedStripe = { ...base, checks: [base.checks[0], hookCheck('ST-OMIT', '/stripe/events', structuredClone(EVENT), { provider: 'stripe', signature: 'omit' })] };
  assert.match(load(keyedProvider(unsignedStripe, 'stripe-signature')), /sends its key in Stripe-Signature, a stripe webhook header of its check "ST-OMIT"/);
  assert.match(drive(keyedProvider(unsignedStripe, 'stripe-signature'), { ...KEY }), /^webhook-header: actor "provider" sends its key in Stripe-Signature/);
  // A check that does not apply is not sent, so its provider's header names are free.
  const notApplicable = { ...unsignedOnly, checks: [unsignedOnly.checks[0], { ...hookCheck('SMS-OFF', '/twilio/sms', { ...SMS }, { provider: 'twilio', signature: 'omit' }), applicability: { applies: false, reason: 'No SMS route in this build.' } }] };
  assert.equal(load(correlated(notApplicable, 'x-twilio-signature')), 'loaded');
});

// Read-back declares its credentials under "env" (readBack.credential.env, readBack.identities.*.env), which
// the clash rule's "...Env" match missed, so a webhook key could be ScopeHaven's read credential, by variable or by value.
test('a webhook key is never a read-back credential, by variable or by value', () => {
  const p = R2.profileOf([[R2.EXISTS]]);
  const hooked = secretEnv => ({ ...p, checks: [...p.checks, { id: 'HOOK', title: 'Stripe event', category: 'webhooks', severity: 'high', actorId: 'member', method: 'POST', path: '/stripe/events', body: structuredClone(EVENT),
    evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], webhook: { provider: 'stripe', secretEnv } }] });
  for (const taken of ['SCOPEHAVEN_TARGET_CRM_READ', 'SCOPEHAVEN_TARGET_CRM_APP', 'SCOPEHAVEN_TARGET_CRM_PROOF']) assert.match(load(hooked(taken)), new RegExp(`webhook signing key variable ${taken} is also named elsewhere in the profile`), taken);
  const own = 'SCOPEHAVEN_TARGET_STRIPE_HOOK', target = hooked(own);
  assert.equal(load(target), 'loaded');
  const key = ['wh', 'sec_', synthetic('crm')].join('');
  const env = taken => ({ SCOPEHAVEN_TARGET_CRM_READ: synthetic('crm', 'read'), SCOPEHAVEN_TARGET_CRM_APP: synthetic('crm', 'app'), SCOPEHAVEN_TARGET_CRM_JOBS: synthetic('crm', 'jobs'), SCOPEHAVEN_TARGET_CRM_PROOF: synthetic('crm', 'proof'), [own]: key, ...(taken ? { [taken]: key } : {}) });
  for (const taken of ['SCOPEHAVEN_TARGET_CRM_READ', 'SCOPEHAVEN_TARGET_CRM_JOBS']) assert.equal(drive(target, env(taken)), `webhook-secret-clash: ${own} and ${taken} hold the same key: a webhook signing key is its own synthetic key, distinct from every other key and credential of the run`, taken);
  assert.equal(drive(target, env(null)), 'created');
});

// The requests exactly as they reach an app: the received header names, one Content-Type of the
// driver's value, a Content-Length equal to the bytes received, the sent path, and each signature checked by an independent verifier.
async function rawReceiver(t) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = []; req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks), url = new URL(req.url, 'http://127.0.0.1'), now = Math.floor(Date.now() / 1000);
      const names = req.rawHeaders.filter((_, i) => i % 2 === 0).map(h => h.toLowerCase()).sort(), form = req.headers['content-type'] === 'application/x-www-form-urlencoded';
      const valid = url.pathname.startsWith('/twilio/') ? (form ? twilioValid(KEY[ENV.twilio], `${origin}${req.url}`, new URLSearchParams(raw.toString()), req.headers['x-twilio-signature']) : twilioJsonValid(KEY[ENV.twilio], `${origin}${req.url}`, raw, req.headers['x-twilio-signature']))
        : url.pathname.startsWith('/stripe/') ? stripeValid(KEY[ENV.stripe], req.headers['stripe-signature'], raw, now)
          : url.pathname.startsWith('/telnyx/') ? telnyxValid(publicKeyOf(KEY[ENV.telnyx]), req.headers['telnyx-signature-ed25519'], req.headers['telnyx-timestamp'], raw, now) : null;
      seen.push({ method: req.method, url: req.url, names, contentType: req.headers['content-type'] ?? null, contentLength: Number(req.headers['content-length'] ?? 0), bytes: raw.length, raw: raw.toString(), valid,
        signatures: ['x-twilio-signature', 'stripe-signature', 'telnyx-signature-ed25519'].map(h => req.headers[h]).filter(Boolean) });
      res.writeHead(valid === false ? 403 : 200, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify({ ok: valid !== false, n: 5 }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { origin, seen };
}
function hookCheck(id, path, body, webhook, expected = 200) {
  return { id, title: id, category: 'webhooks', severity: 'high', actorId: 'provider', method: 'POST', path, body, webhook, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected }] };
}
const PING = { id: 'PING', title: 'Ping', category: 'availability', severity: 'control', actorId: 'provider', method: 'GET', path: '/ping', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] };
const miniProfile = (origin, checks) => ({ id: 'wh-requests', name: 'Webhook requests', applicationId: 'wh-requests', origin, buildLabel: 'b1', contextId: 'synthetic-wh-requests', actors: { provider: { principalId: 'provider' } }, requiredControlIds: ['PING'], checks: [PING, ...checks] });

test('each provider\'s request reaches the app as the driver built it: headers, bytes and path, verified independently', async t => {
  const r = await rawReceiver(t);
  const p = miniProfile(r.origin, [
    hookCheck('TW-FORM', "/twilio/sms?name=O'Brien", { ...SMS }, { provider: 'twilio', secretEnv: ENV.twilio, headers: { 'i-twilio-idempotency-token': 'idem-form' } }),
    hookCheck('TW-JSON', '/twilio/json?tenant=a', structuredClone(EVENT), { provider: 'twilio', secretEnv: ENV.twilio, encoding: 'json' }),
    hookCheck('ST', '/stripe/events', structuredClone(EVENT), { provider: 'stripe', secretEnv: ENV.stripe }),
    hookCheck('ST-STALE', '/stripe/events', structuredClone(EVENT), { provider: 'stripe', secretEnv: ENV.stripe, timestampOffsetSeconds: -3600 }, 403),
    hookCheck('TX', '/telnyx/messages', structuredClone(TELNYX_EVENT), { provider: 'telnyx', secretEnv: ENV.telnyx }),
    hookCheck('ST-OMIT', '/stripe/events', structuredClone(EVENT), { provider: 'stripe', signature: 'omit' }, 403),
  ]);
  const run = await runHttpAssessment(p, { env: { ...KEY } }), suite = createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
  assert.deepEqual(Object.fromEntries(run.results.map(x => [x.id, x.status])), { PING: 'pass', 'TW-FORM': 'pass', 'TW-JSON': 'pass', ST: 'pass', 'ST-STALE': 'pass', TX: 'pass', 'ST-OMIT': 'pass' });
  const framing = ['accept', 'connection', 'content-length', 'content-type', 'host'];
  const json = JSON.stringify(EVENT), hex = createHash('sha256').update(json).digest('hex');
  const expected = [
    { url: "/twilio/sms?name=O%27Brien", contentType: 'application/x-www-form-urlencoded', raw: new URLSearchParams(SMS).toString(), valid: true, names: [...framing, 'i-twilio-idempotency-token', 'x-twilio-signature'] },
    { url: `/twilio/json?tenant=a&bodySHA256=${hex}`, contentType: 'application/json', raw: json, valid: true, names: [...framing, 'x-twilio-signature'] },
    { url: '/stripe/events', contentType: 'application/json', raw: json, valid: true, names: [...framing, 'stripe-signature'] },
    { url: '/stripe/events', contentType: 'application/json', raw: json, valid: false, names: [...framing, 'stripe-signature'] },
    { url: '/telnyx/messages', contentType: 'application/json', raw: JSON.stringify(TELNYX_EVENT), valid: true, names: [...framing, 'telnyx-signature-ed25519', 'telnyx-timestamp'] },
    { url: '/stripe/events', contentType: 'application/json', raw: json, valid: false, names: framing },
  ];
  assert.deepEqual(r.seen.map(s => `${s.method} ${s.url}`)[0], 'GET /ping');
  const hooks = r.seen.slice(1);
  assert.deepEqual(hooks.map(({ url, contentType, raw, valid, names }) => ({ url, contentType, raw, valid, names: names.sort() })), expected.map(e => ({ ...e, names: [...e.names].sort() })));
  for (const s of hooks) assert.equal(s.contentLength, s.bytes, `${s.url}: Content-Length is the bytes received`);
  // Nothing of a key or a signature is in the run or the suite.
  const text = JSON.stringify({ run, suite });
  assert.deepEqual([Object.values(KEY).filter(v => text.includes(v)), hooks.flatMap(s => s.signatures).filter(v => text.includes(v) || text.includes(v.split('v1=')[1] ?? '\u0000'))], [[], []]);
  assert.deepEqual([evidence(run), evidence(run, { expectedSuite: suite })], ['ok', 'ok']);
});

test('the connector refuses, before writing, a webhook request with a header named as one of its own or as any provider header', async t => {
  const r = await rawReceiver(t);
  // No provider header is one of the connector's fixed names.
  const fixed = ['accept', 'connection', 'content-length', 'authorization', 'cookie', 'host'];
  assert.deepEqual(Object.values(WEBHOOK_PROVIDERS).flatMap(f => [...f.signatureHeaders, ...f.extraHeaders]).filter(h => fixed.includes(h.toLowerCase())), []);
  const checks = { TW: hookCheck('TW', '/twilio/sms', { ...SMS }, { provider: 'twilio', secretEnv: ENV.twilio }), 'TW-OMIT': hookCheck('TW-OMIT', '/twilio/sms', { ...SMS }, { provider: 'twilio', signature: 'omit' }),
    'ST-OMIT': hookCheck('ST-OMIT', '/stripe/events', structuredClone(EVENT), { provider: 'stripe', signature: 'omit' }), 'TX-OMIT': hookCheck('TX-OMIT', '/telnyx/messages', structuredClone(TELNYX_EVENT), { provider: 'telnyx', signature: 'omit' }) };
  const driver = createWebhookDriver({ target: { actors: { provider: { principalId: 'provider' } }, checks: Object.values(checks) }, env: { ...KEY } });
  t.after(() => driver.close());
  const sent = id => { const built = driver.build(checks[id], { origin: r.origin }); return { method: 'POST', path: built.path, webhookRequest: built }; };
  const token = randomUUID(), credential = KEY[ENV.gateway];
  const refused = 'A webhook header has the name of a header the connector sends.';
  for (const [label, request, options, expected = refused] of [
    // A header the driver built (the signature), as the correlation header or the credential header, in any case.
    ['correlation header, signed', sent('TW'), { correlationHeader: { name: 'x-twilio-signature', value: token } }],
    ['credential header, signed', sent('TW'), { credential, credentialHeader: 'X-TWILIO-SIGNATURE' }],
    // A provider header this request does not carry: the extra header, and the signature of an unsigned request.
    ['credential header as the undeclared extra header', sent('TW'), { credential, credentialHeader: 'i-twilio-idempotency-token' }],
    ['correlation header, unsigned Twilio', sent('TW-OMIT'), { correlationHeader: { name: 'x-twilio-signature', value: token } }],
    ['credential header, unsigned Twilio', sent('TW-OMIT'), { credential, credentialHeader: 'x-twilio-signature' }],
    ['credential header, unsigned Stripe', sent('ST-OMIT'), { credential, credentialHeader: 'Stripe-Signature' }],
    ['credential header, unsigned Telnyx', sent('TX-OMIT'), { credential, credentialHeader: WEBHOOK_PROVIDERS.telnyx.signatureHeaders[0] }],
    // A built header with one of the connector's fixed names, and a request that names no provider.
    ['a fixed connector header', { ...sent('TW'), webhookRequest: { ...sent('TW').webhookRequest, headers: { ...sent('TW').webhookRequest.headers, connection: 'keep-alive' } } }, {}],
    ['no provider', { ...sent('TW'), webhookRequest: { ...sent('TW').webhookRequest, record: { ...sent('TW').webhookRequest.record, provider: 'constructor' } } }, {}, 'A webhook request names no supported provider.'],
  ]) assert.equal(await outcome(() => observeHttp(r.origin, request, options)), expected, label);
  assert.deepEqual(r.seen, [], 'nothing was written');
  // Under other names both go out beside one valid signature (or none, unsigned) and the driver's Content-Type.
  for (const [id, options] of [['TW', { correlationHeader: { name: 'x-request-id', value: token } }], ['TW', { credential, credentialHeader: 'x-api-key' }], ['TW-OMIT', { credential, credentialHeader: 'x-api-key' }]]) {
    assert.equal((await observeHttp(r.origin, sent(id), options)).status, id === 'TW' ? 200 : 403);
  }
  assert.deepEqual(r.seen.map(s => [s.valid, s.contentType, s.names.filter(n => ['x-request-id', 'x-api-key', 'x-twilio-signature'].includes(n))]),
    [[true, 'application/x-www-form-urlencoded', ['x-request-id', 'x-twilio-signature']], [true, 'application/x-www-form-urlencoded', ['x-api-key', 'x-twilio-signature']], [false, 'application/x-www-form-urlencoded', ['x-api-key']]]);
});

// A build refusal mid-run names the check, never a value. An integer capture placed whole
// into a form value fills a number, which a form cannot carry; the checks before it were sent, the webhook was not.
test('a webhook build refusal stops the run and names its check', async t => {
  const r = await rawReceiver(t);
  const p = miniProfile(r.origin, [
    { id: 'COUNT', title: 'Count', category: 'setup', severity: 'high', actorId: 'provider', method: 'GET', path: '/count', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], capture: { n: { pointer: '/n', type: 'integer' } } },
    hookCheck('HOOK', '/twilio/sms', { Count: '{{n}}', Body: 'hello there' }, { provider: 'twilio', secretEnv: ENV.twilio }),
  ]);
  assert.equal(load(p), 'loaded');
  const error = await runHttpAssessment(p, { env: { ...KEY } }).then(() => null, e => e);
  assert.ok(error instanceof WebhookDriverError);
  assert.deepEqual([error.code, error.message], ['webhook-body', 'check "HOOK": a form parameter\'s value is a string, or a list of 1 to 32 strings (a repeated parameter)']);
  assert.deepEqual([Object.values(KEY).some(v => error.message.includes(v)), r.seen.map(x => `${x.method} ${x.url}`)], [false, ['GET /ping', 'GET /count']]);
});

// A mutant without webhooks.close() changes nothing a run shows: the keys are unreachable once the run returns. So the
// source is pinned instead: the driver's keys are zeroed on every exit of runHttpAssessment.
test('runHttpAssessment closes its webhook driver on every exit (source)', async () => {
  const source = await readFile(new URL('../src/http-connector.mjs', import.meta.url), 'utf8');
  const body = source.slice(source.indexOf('export async function runHttpAssessment'));
  assert.match(body, /const webhooks = createWebhookDriver\(\{ target: profile, env \}\);\n.*\n  let modelCapture;\n  try \{ modelCapture = await beginModelIdentityCapture\(.*\); \} catch \(error\) \{ webhooks\.close\(\); throw error; \}\n  try \{/);
  assert.match(body, /\} finally \{ webhooks\.close\(\); await releaseModelIdentityCapture\(modelCapture\); \}\n\}/);
});
