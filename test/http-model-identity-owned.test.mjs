// The owned route: Scopehaven starts the model tap in its own process for the assessment window,
// marks it at both ends and stops it, so no closure or cooperation is needed from the application.
// Loopback only: a fixed local model stub, a synthetic application and the real gate path (runGate,
// what `scopehaven gate` runs). No model, provider or customer system is contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runGate } from '../integrations/regression-gate/gate.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { OWNED_TAP_ENV, ownedTapConfig, beginModelIdentityCapture, finishModelIdentityCapture } from '../src/http-model-identity.mjs';
import { makeLabProfile } from '../examples/http-lab.mjs';
import { writeTestAuthorization } from './support/authorization.mjs';

const listen = (server, port = 0) => new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => resolve(server.address().port)); });
const close = server => new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); });
async function freePort() { const probe = createNetServer(); const port = await listen(probe); await close(probe); return port; }
// True when nothing listens on the port any more (the owned tap was stopped).
async function released(port) { const probe = createNetServer(); try { await listen(probe, port); return true; } catch { return false; } finally { if (probe.listening) await close(probe); } }
async function scratch(t) { const dir = await mkdtemp(join(tmpdir(), 'scopehaven owned tap ')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; }
function postModel(port) {
  const body = JSON.stringify({ model: 'stub-request', messages: [{ role: 'user', content: 'synthetic' }], stream: false });
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path: '/v1/chat/completions', method: 'POST', agent: false, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('error', reject);
      res.on('end', () => res.statusCode === 200 ? resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))) : reject(new Error(`model status ${res.statusCode}`)));
    });
    req.on('error', reject); req.end(body);
  });
}
// A fixed model stub, and a synthetic application whose model base URL is the tap port. The
// application only sends its model call through that port; it never starts, stops, marks or reads a tap.
async function modelServedApp(t, { tags = false } = {}) {
  const state = { served: 'stub-model-a', fingerprint: 'stub-fingerprint-a', digest: 'a'.repeat(64), repaired: false };
  const model = createServer(async (req, res) => {
    for await (const _chunk of req) {} // Discard synthetic request content.
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (req.url === '/api/tags') { res.end(JSON.stringify({ models: [{ name: `${state.served}:latest`, digest: state.digest }] })); return; }
    res.end(JSON.stringify({ model: state.served, system_fingerprint: state.fingerprint, choices: [{ message: { content: 'synthetic' } }] }));
  });
  const modelPort = await listen(model); t.after(() => close(model));
  const tapPort = await freePort();
  const app = createServer(async (req, res) => {
    let status = 200;
    if (req.url === '/boundary') { try { await postModel(tapPort); status = state.repaired ? 403 : 200; } catch { status = 502; } }
    res.writeHead(status, { 'Content-Type': 'application/json' }); res.end('{}');
  });
  const appPort = await listen(app); t.after(() => close(app));
  const target = buildLabel => ({ id: 'owned-stub', name: 'Synthetic owned-tap target', applicationId: 'owned-stub', origin: `http://127.0.0.1:${appPort}`, buildLabel, contextId: 'owned-stub-v1',
    actors: { anonymous: { principalId: 'anonymous' } }, requiredControlIds: ['allowed'], checks: [
      { id: 'allowed', title: 'Allowed', category: 'Synthetic', severity: 'control', actorId: 'anonymous', method: 'GET', path: '/allowed', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'boundary', title: 'Boundary', category: 'Synthetic', severity: 'high', actorId: 'anonymous', method: 'GET', path: '/boundary', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }] });
  const env = { [OWNED_TAP_ENV.upstream]: `http://127.0.0.1:${modelPort}`, [OWNED_TAP_ENV.port]: String(tapPort), ...(tags ? {} : { [OWNED_TAP_ENV.ollamaTags]: 'false' }) };
  return { state, target, env, tapPort, modelPort };
}

test('the gate holds the model tap itself: strict passes an unchanged model and fails a swap, with no app cooperation', async t => {
  const { state, target, env, tapPort } = await modelServedApp(t);
  const dir = await scratch(t), outputDirectory = join(dir, 'gate');
  const config = async build => { const path = join(dir, `targets-${build}.json`); await writeFile(path, JSON.stringify({ schemaVersion: 1, targets: [target(build)] })); return path; };
  // The authorization record covers the app and the owned tap's model upstream, which the gate forwards to.
  const authorizationFile = writeTestAuthorization(join(dir, 'authorization.json'), target('any'), { origins: [env[OWNED_TAP_ENV.upstream]] });
  const gate = async (build, extra = {}) => runGate({ targetId: 'owned-stub', configFile: await config(build), outputDirectory, authorizationFile, ...extra }, { env });
  // Baseline: the unrepaired build fails its boundary check. No strict switch without a baseline.
  const before = await gate('before');
  assert.deepEqual([before.exitCode, before.reasons], [1, ['checks-failed']]);
  assert.equal(await released(tapPort), true);
  const baselineRunId = before.current.runId;
  state.repaired = true;
  const after = await gate('after', { baselineRunId, requireModelIdentity: true });
  assert.deepEqual([after.exitCode, after.reasons], [0, []]);
  assert.deepEqual(after.comparison.modelAttribution, { state: 'recorded', flipCause: 'app', relation: 'same', strength: 'vendor-fingerprint', repairCreditedToApp: true });
  assert.deepEqual(after.comparison.modelIdentityPolicy, { required: true, met: true, causes: [] });
  assert.equal(await released(tapPort), true);
  // The model behind the same name, port and upstream changes.
  state.served = 'stub-model-b'; state.fingerprint = 'stub-fingerprint-b';
  const swapped = await gate('after-swap', { baselineRunId, requireModelIdentity: true });
  assert.deepEqual([swapped.exitCode, swapped.reasons], [1, ['repair-not-attributable']]);
  assert.deepEqual(swapped.comparison.modelAttribution, { state: 'recorded', flipCause: 'confounded', relation: 'different', strength: 'vendor-fingerprint', repairCreditedToApp: false });
  assert.equal(swapped.comparison.modelIdentityPolicy.met, true);
  assert.equal(await released(tapPort), true);
});

test('an owned-tap identity records its window, session, head and tap-memory custody, and nothing the app sent', async t => {
  const { state, target, env, modelPort } = await modelServedApp(t, { tags: true });
  state.repaired = true;
  const run = await runHttpAssessment(target('x'), { env });
  const id = run.modelIdentity;
  // Ollama-style model lists bracket the window, so the reading reaches weights-digest strength,
  // which is still what the upstream listed, not attested weights.
  assert.deepEqual([id.state, id.strength, id.custody, id.upstream, id.upstreamKind, id.calls.total], ['observed', 'weights-digest', 'tap-memory', `http://127.0.0.1:${modelPort}`, 'loopback', 1]);
  assert.equal(id.models[0].weightsDigest, 'a'.repeat(64));
  assert.match(id.tapSession, /^[0-9a-f-]{36}$/); assert.match(id.head, /^[a-f0-9]{64}$/);
  assert.ok(Number.isInteger(id.window.from) && id.window.to > id.window.from);
  assert.ok(!JSON.stringify(id).includes('synthetic'), 'no request or response content');
});

test('owned-tap configuration is refused unless it is a literal loopback upstream and a valid port', async t => {
  const transport = async (_o, c) => ({ status: c.path === '/boundary' ? 403 : 200, complete: true, jsonParsed: true, json: {}, bytes: 2 });
  const port = String(await freePort());
  const profile = { id: 'cfg', name: 'Config', applicationId: 'cfg', origin: 'http://127.0.0.1:4318', buildLabel: 'x', contextId: 'cfg', actors: { anonymous: { principalId: 'anonymous' } }, requiredControlIds: ['allowed'],
    checks: [{ id: 'allowed', title: 'Allowed', category: 'S', severity: 'control', actorId: 'anonymous', method: 'GET', path: '/allowed', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] };
  const U = OWNED_TAP_ENV.upstream, P = OWNED_TAP_ENV.port, O = OWNED_TAP_ENV.ollamaTags;
  for (const env of [
    { [U]: 'https://api.openai.com', [P]: port }, // a hosted vendor: the owned tap never forwards off the machine
    { [U]: 'http://localhost:11434', [P]: port }, { [U]: 'http://127.0.0.1:11434/', [P]: port },
    { [U]: 'http://127.0.0.1:11434', [P]: '0' }, { [U]: 'http://127.0.0.1:11434', [P]: '70000' }, { [U]: 'http://127.0.0.1:11434', [P]: '08080' },
    { [U]: 'http://127.0.0.1:11434', [P]: port, [O]: 'yes' }, { [P]: port }, { [U]: 'http://127.0.0.1:11434' },
  ]) {
    const run = await runHttpAssessment(profile, { env, transport });
    assert.deepEqual([run.modelIdentity.state, run.modelIdentity.reasons, run.modelIdentity.custody], ['partial', ['tap-owned-config-invalid'], 'tap-memory'], JSON.stringify(env));
  }
  // A port already taken: the tap cannot listen, and the run says so.
  const taken = createNetServer(); const takenPort = await listen(taken); t.after(() => close(taken));
  const busy = await runHttpAssessment(profile, { env: { [U]: 'http://127.0.0.1:11434', [P]: String(takenPort), [O]: 'false' }, transport });
  assert.deepEqual([busy.modelIdentity.state, busy.modelIdentity.reasons], ['partial', ['tap-owned-unavailable-at-start']]);
  // Two configured sources are refused, never silently preferred.
  const both = await runHttpAssessment(profile, { env: { [U]: 'http://127.0.0.1:11434', [P]: port, SCOPEHAVEN_MODEL_TAP_LOG: '/abs/tap.jsonl' }, transport });
  assert.deepEqual([both.modelIdentity.reasons, both.modelIdentity.custody], [['tap-capture-ambiguous-sources'], null]);
  assert.equal(await released(Number(port)), true);
});

test('the owned tap never outlives its run, including a run that throws', async t => {
  const { env, tapPort } = await modelServedApp(t);
  // A credential the profile references is missing: the run throws before any request.
  await assert.rejects(runHttpAssessment(makeLabProfile('http://127.0.0.1:4318', 'lab-x'), { env }), /credentials are missing/);
  assert.equal(await released(tapPort), true);
});

test('finishing an owned capture stops its tap at the end mark, without a separate release', async t => {
  const { env, tapPort } = await modelServedApp(t);
  const capture = await beginModelIdentityCapture({ owned: ownedTapConfig(env) });
  assert.equal(await released(tapPort), false, 'the tap listens during the window');
  await postModel(tapPort);
  const id = await finishModelIdentityCapture(capture);
  assert.equal(await released(tapPort), true, 'the tap stopped when the capture finished');
  assert.deepEqual([id.state, id.custody, id.calls.total], ['observed', 'tap-memory', 1]);
});
