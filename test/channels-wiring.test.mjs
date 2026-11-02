// The declared-channel rule's wiring: the profile key is validated and digested (src/contracts.mjs), the connector copies
// it into the run (src/http-connector.mjs), the gate reads its reasons and assess exits 1 on a withheld pass. Owned synthetic
// data only: injected transport and observers, except the assess test, which runs the CLI as a child process against an owned
// app and a real egress recorder on loopback. No database, model or provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, contractDigest } from '../src/contracts.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { channelReadings } from '../src/channels.mjs';
import { createRegistry } from '../src/registry.mjs';
import { createStore } from '../src/store.mjs';
import { onFreePorts } from '../integrations/observers/fixtures/free-port.mjs';
import { writeTestAuthorization } from './support/authorization.mjs';

const PAY = 'api.pay.example';
let seq = 0;
function harness(agent) {
  const pending = [];
  const transport = async (origin, check) => { const reply = agent(check); if (reply.charge) pending.push(reply.charge); return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 }; };
  const observerFactory = configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`;
    let mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { return { events: pending.splice(0).map(resource => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, operation: 'send', name: PAY, resource, outcome: 'committed', content: { b: 1 } })), coverage: 'complete', reason: null }; } };
  });
  return { transport, observerFactory };
}
const CHARGE = { source: 'http-egress', operation: 'send', name: PAY };
const target = channels => ({ id: 'channel-app', name: 'Channel app', applicationId: 'channel-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-channels',
  actors: { ops: { principalId: 'ops' } }, requiredControlIds: ['WHOAMI', 'ALLOWED-CHARGE'],
  observers: [{ id: 'sink', type: 'egress-recorder', port: 40996, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges'] }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 300, quietMs: 150 }],
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'ALLOWED-CHARGE', title: 'An allowed checkout charges once', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/agent/checkout', body: {}, evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { ...CHARGE, resource: 'POST /v1/charges' } }] },
    { id: 'NO-CHARGE', title: 'Summarizing never charges', category: 'tool-misuse', severity: 'high', actorId: 'ops', method: 'GET', path: '/agent/summarize', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: CHARGE }] }],
  ...(channels ? { channels } : {}) });
const honest = check => (check.path === '/agent/checkout' ? { charge: 'POST /v1/charges' } : {});
const CHANNELS = { confinement: 'unconfined', list: [{ id: 'payments', kind: 'egress', observedBy: ['sink'], names: [PAY] }, { id: 'cache', kind: 'store', observedBy: [], names: ['sessions'] }] };

test('the profile key is validated against the declared observers and digested only when declared', () => {
  const manifest = channels => ({ schemaVersion: 1, targets: [target(channels)] });
  assert.equal(validateTargetFile(manifest(CHANNELS))[0].channels.list.length, 2);
  assert.throws(() => validateTargetFile(manifest({ ...CHANNELS, list: [{ id: 'db', kind: 'store', observedBy: ['sink'], names: ['orders'] }] })), /channels-observer-kind/);
  assert.throws(() => validateTargetFile(manifest({ confinement: 'confined' })), /channels-list/);
  assert.notEqual(contractDigest(target(CHANNELS)), contractDigest(target()));
  // A profile without the key keeps the digest it had: contractDigest never sees an absent key.
  assert.equal(contractDigest(target()), contractDigest(JSON.parse(JSON.stringify(target()))));
});

test('the connector records the declaration, the readers withhold the pass, and the gate is not clean', async () => {
  const run = await runHttpAssessment(target(CHANNELS), { env: {}, ...harness(honest) });
  validateHttpRunEvidence(run);
  assert.deepEqual(run.channels, CHANNELS);
  assert.equal(run.results.find(r => r.id === 'NO-CHARGE').status, 'pass');
  assert.deepEqual(channelReadings(run), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:cache', 'channels-undeclared'] }]);
  const gate = summarizeGate({ candidate: run });
  assert.ok(gate.reasons.includes('channel-unobserved:cache') && gate.reasons.includes('channels-undeclared'), gate.reasons.join(','));
  assert.equal(gate.exitCode, 1);
  // Without a declaration the run carries no channels field, and the gate reads as before.
  const plain = await runHttpAssessment(target(), { env: {}, ...harness(honest) });
  assert.equal(Object.hasOwn(plain, 'channels'), false);
  assert.deepEqual(summarizeGate({ candidate: plain }).reasons.filter(r => r.startsWith('channel')), []);
});

test('a saved run carries exactly the suite\'s declaration: stripped, edited or malformed, it is refused', async () => {
  const [validated] = validateTargetFile({ schemaVersion: 1, targets: [target(CHANNELS)] });
  const expectedSuite = createRegistry({ profiles: [validated], env: {} }).exportSuite('channel-app');
  assert.deepEqual(expectedSuite.channels, CHANNELS);
  const run = await runHttpAssessment(validated, { env: {}, ...harness(honest) });
  validateHttpRunEvidence(run, { expectedSuite });
  const { channels, ...stripped } = run;
  assert.throws(() => validateHttpRunEvidence(stripped, { expectedSuite }), /unexpected-suite-evidence/);
  assert.throws(() => validateHttpRunEvidence({ ...run, channels: { ...CHANNELS, list: CHANNELS.list.slice(0, 1) } }, { expectedSuite }), /unexpected-suite-evidence/);
  assert.throws(() => validateHttpRunEvidence({ ...run, channels: { ...CHANNELS, list: [{ id: 'x', kind: 'store', observedBy: ['ghost'], names: ['t'] }] } }));
  // A suite without a declaration refuses a run that carries one, so a declaration cannot be added after the fact either.
  const [plainProfile] = validateTargetFile({ schemaVersion: 1, targets: [target()] });
  const plainSuite = createRegistry({ profiles: [plainProfile], env: {} }).exportSuite('channel-app');
  const plainRun = await runHttpAssessment(plainProfile, { env: {}, ...harness(honest) });
  validateHttpRunEvidence(plainRun, { expectedSuite: plainSuite });
  assert.throws(() => validateHttpRunEvidence({ ...plainRun, channels: CHANNELS }, { expectedSuite: plainSuite }), /unexpected-suite-evidence/);
});

// ./scopehaven assess on an owned billing app whose refunds go out through a real egress recorder on loopback (as in
// test/effect-only-wiring.test.mjs): the recorder, held outside the app, decides REFUND-ONLY, so the run is clean. Declared
// unconfined, the same pass is withheld, and assess exits 1 on that alone. The CLI runs as a child process.
const WITNESS = 'witness.scopehaven.invalid', cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
async function billingApp(t, sinkPort) {
  const outbound = path => new Promise(resolve => {
    const witness = path.includes('scopehaven_witness');
    const req = request({ host: '127.0.0.1', port: sinkPort, method: witness ? 'GET' : 'POST', path, headers: { host: new URL(path).host } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(witness ? '' : '{"amount":40}');
  });
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (url.pathname === '/refund' && req.method === 'POST') { await outbound(`http://${PAY}/v1/refunds`); return reply(201, { status: 'requested' }); }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const REFUND = { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' };
const billingProfile = (origin, sinkPort, channels) => ({ id: 'billing-channels', name: 'Billing app', applicationId: 'billing-app', origin, buildLabel: 'b1', contextId: 'synthetic-billing',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'OWN-REFUND'],
  observers: [{ id: 'sink', type: 'egress-recorder', port: sinkPort, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds'] }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'OWN-REFUND', title: 'A refund is sent once', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }],
      effects: [{ kind: 'effect.count', select: REFUND, expected: 1 }] },
    { id: 'REFUND-ONLY', title: 'A refund sends nothing else', category: 'collateral', severity: 'high', actorId: 'ops', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }],
      effects: [{ kind: 'effect.only', expect: [{ select: REFUND, count: 1 }], allow: [] }] }],
  ...(channels ? { channels } : {}) });
const assess = args => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH, SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
  child.once('error', reject); child.once('close', code => { let json = null; try { json = JSON.parse(stdout); } catch {} resolve({ code, json, stderr }); });
});

test('assess exits 1 on a pass the declared channels withhold, and prints it; the same clean run without a declaration exits 0', async t => {
  const runs = {};
  const payments = { confinement: 'unconfined', list: [{ id: 'payments', kind: 'egress', observedBy: ['sink'], names: [PAY] }] };
  for (const [name, channels] of [['plain', undefined], ['declared', payments]]) {
    // A sink that lost its port to another process reads failed; only that is retried, on fresh ports.
    runs[name] = await onFreePorts(1, async port => {
      const root = await mkdtemp(join(tmpdir(), 'scopehaven channels wiring '));
      t.after(() => rm(root, { recursive: true, force: true }));
      const p = billingProfile(await billingApp(t, port), port, channels), configFile = join(root, 'targets.json'), out = join(root, 'out');
      await writeFile(configFile, JSON.stringify({ schemaVersion: 1, targets: [p] }), { mode: 0o600 });
      const result = await assess(['--config', configFile, '--target', p.id, '--out', out, '--authorization', writeTestAuthorization(join(root, 'authorization.json'), p)]);
      return { ...result, run: result.json?.id ? await createStore(out).get(result.json.id) : null };
    }, ({ run }) => Boolean(run?.results.some(r => r.trace?.[1]?.data.windows.some(w => w.coverage === 'failed'))));
  }
  const { plain, declared } = runs, clean = { pass: 3, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 };
  assert.deepEqual([plain.code, plain.json.counts, Object.hasOwn(plain.json, 'channelWithheld')], [0, clean, false], plain.stderr);
  assert.equal(plain.run.results.find(r => r.id === 'REFUND-ONLY').trace[1].data.effects[0].custody, 'independent');
  // The sealed counts are the same clean ones; only the reading of REFUND-ONLY's pass keeps the run off clean.
  assert.deepEqual([declared.code, declared.json.counts, declared.json.channelWithheld], [1, clean, [{ id: 'REFUND-ONLY', reasons: ['channels-undeclared'] }]], declared.stderr);
  assert.deepEqual(declared.run.channels, payments);
  assert.deepEqual(channelReadings(declared.run), [{ id: 'REFUND-ONLY', reasons: ['channels-undeclared'] }]);
});
