import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { createConnection } from 'node:net';
import { mkdtemp, rm, readFile, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { startServer } from '../src/server.mjs';
import { runHttpAssessment, observeHttp } from '../src/http-connector.mjs';
import { compareRuns } from '../src/runner.mjs';
import { INPUT_CONTRACT, importPromptfooJson } from '../integrations/evaluation-import/import.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { Script, createContext } from 'node:vm';

// Independent attack-path review. All sockets connect to owned ephemeral
// 127.0.0.1 listeners, all disk writes use private temporary directories,
// and credentials/data are synthetic. No provider, proxy or customer calls.
async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-security-review-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
async function lab(t, handler) {
  const instance = createServer(handler);
  await new Promise((resolve, reject) => { instance.once('error', reject); instance.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => { instance.close(resolve); instance.closeAllConnections(); }));
  return `http://127.0.0.1:${instance.address().port}`;
}
const respond = (res, value, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
function profile(origin) {
  return { id: 'review-lab', name: 'Synthetic review lab', applicationId: 'review-app', origin, buildLabel: 'test-build', contextId: 'private-synthetic-context', actors: { member: { principalId: 'synthetic-member', credentialEnv: 'SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN' } }, requiredControlIds: ['allowed'], checks: [
    { id: 'allowed', title: 'Allowed operation', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/allowed', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/ok', expected: true }] },
    { id: 'restricted', title: 'Restricted operation', category: 'Access', severity: 'high', actorId: 'member', method: 'GET', path: '/restricted', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
  ] };
}
// actor-identity/4: a credentialed actor's 403 counts as a refusal only after its earlier complete 2xx on a
// protected route, so the gate tests that need the member's refusal give it a surface control (a required GET).
const withSurface = target => { target.checks.push({ id: 'own-list', title: 'Own list', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/own-list', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }); target.requiredControlIds.push('own-list'); return target; };
// idleMs: how long the socket may sit silent before the request fails as hung.
function raw(origin, path, { method = 'GET', headers = {}, payload, idleMs = 3000 } = {}) {
  return new Promise((resolve, reject) => {
    const buffer = payload === undefined ? undefined : Buffer.from(payload);
    const req = request(`${origin}${path}`, { method, agent: false, headers: { ...headers, ...(buffer ? { 'Content-Length': buffer.length } : {}) } }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c)); res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject); req.setTimeout(idleMs, () => req.destroy(new Error('Owned local test request timed out.'))); req.end(buffer);
  });
}
const auth = app => ({ Authorization: `Bearer ${app.accessToken}` });
function wireStatus(origin, lines) {
  const address = new URL(origin);
  return new Promise((resolve, reject) => {
    let response = '';
    const socket = createConnection({ host: '127.0.0.1', port: Number(address.port) }, () => socket.write(`${lines.join('\r\n')}\r\n\r\n`));
    socket.on('data', chunk => { response += chunk.toString('ascii'); });
    socket.on('error', reject); socket.on('end', () => resolve(Number(/^HTTP\/1\.[01] (\d+)/.exec(response)?.[1])));
    socket.setTimeout(3000, () => socket.destroy(new Error('Owned local wire test timed out.')));
  });
}
const post = app => ({ ...auth(app), 'Content-Type': 'application/json', 'X-Scopehaven-Request': '1' });
async function workbench(t, options = {}) {
  const dataDir = await directory(t);
  const app = await startServer({ port: 0, dataDir, env: {}, ...options });
  t.after(() => app.close()); return { ...app, dataDir };
}
async function seed(t, app) {
  const origin = await lab(t, (req, res) => respond(res, { ok: true }, req.url === '/restricted' ? 403 : 200));
  return app.store.save(await runHttpAssessment(profile(origin), { env: { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: 'synthetic-review-secret' } }));
}

test('unauthorized reads, exports, comparisons, notes and runs cannot disclose or mutate stored evidence', async t => {
  let calls = 0;
  const app = await workbench(t, { assess: async () => { calls++; throw new Error('Synthetic invocation'); } });
  const saved = await seed(t, app);
  const paths = ['/api/bootstrap', '/api/history', '/api/suite/export.json', `/api/runs/${saved.id}`, `/api/runs/${saved.id}/export.json`, `/api/runs/${saved.id}/report.html`, `/api/compare?baseline=${saved.id}&candidate=${saved.id}`, '/api/unknown'];
  for (const path of paths) {
    for (const headers of [{}, { Authorization: `Bearer ${'wrong'.repeat(9)}` }, { Cookie: `access=${app.accessToken}`, 'X-Authorization': `Bearer ${app.accessToken}` }]) {
      const response = await raw(app.origin, path, { headers });
      assert.equal(response.status, 401, path);
      assert.equal(response.text.includes(saved.id), false);
      assert.equal(response.text.includes(app.accessToken), false);
    }
  }
  assert.equal((await raw(app.origin, `/api/runs/${saved.id}?access=${app.accessToken}`)).status, 401);
  for (const [path, payload] of [['/api/runs', '{"targetId":"demo-repaired"}'], [`/api/runs/${saved.id}/notes`, '{"caseId":"allowed","note":"unauthorized"}']]) {
    assert.equal((await raw(app.origin, path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Scopehaven-Request': '1' }, payload })).status, 401);
  }
  assert.equal(calls, 0); assert.deepEqual((await app.store.get(saved.id)).notes, {});
  assert.equal((await raw(app.origin, `/api/runs/${saved.id}/export.json`, { headers: auth(app) })).status, 200);
  const info = await raw(app.origin, '/api/access-info');
  assert.equal(info.status, 200); assert.equal(JSON.parse(info.text).authenticationRequired, true); assert.equal(info.text.includes(app.accessToken), false);
});

test('valid capability cannot bypass exact Host, Origin, fetch-site or POST header checks through forwarding headers', async t => {
  const app = await workbench(t);
  const legitimate = await raw(app.origin, '/api/suite/export.json', { headers: auth(app) }); assert.equal(legitimate.status, 200);
  for (const headers of [
    { Host: 'attacker.invalid', 'X-Forwarded-Host': new URL(app.origin).host },
    { Host: `localhost:${new URL(app.origin).port}` }, { Host: `${new URL(app.origin).host}.attacker.invalid` },
    { Origin: 'null' }, { Origin: `${app.origin}/` }, { Origin: `${app.origin}.attacker.invalid` },
    { Origin: 'https://attacker.invalid', 'X-Forwarded-Origin': app.origin }, { 'Sec-Fetch-Site': 'cross-site' },
  ]) assert.equal((await raw(app.origin, '/api/suite/export.json', { headers: { ...auth(app), ...headers } })).status, 403);
  assert.equal((await raw(app.origin, '/api/suite/export.json', { headers: { ...auth(app), Origin: app.origin, 'Sec-Fetch-Site': 'same-origin' } })).status, 200);
  for (const value of [undefined, '0', 'true', '1, 1']) {
    const headers = post(app); if (value === undefined) delete headers['X-Scopehaven-Request']; else headers['X-Scopehaven-Request'] = value;
    assert.equal((await raw(app.origin, '/api/runs', { method: 'POST', headers, payload: '{}' })).status, 403);
  }
  for (const method of ['OPTIONS', 'PUT', 'DELETE']) assert.equal((await raw(app.origin, '/api/suite/export.json', { method, headers: auth(app) })).status, 405);
});

test('capabilities from another launch and expired capabilities cannot read a known run', async t => {
  let time = 100;
  const first = await workbench(t, { accessOptions: { now: () => time, ttlMs: 10 } });
  const saved = await seed(t, first);
  const second = await workbench(t);
  assert.equal((await raw(second.origin, '/api/suite/export.json', { headers: auth(first) })).status, 401);
  time = 109; assert.equal((await raw(first.origin, `/api/runs/${saved.id}`, { headers: auth(first) })).status, 200);
  time = 110; assert.equal((await raw(first.origin, `/api/runs/${saved.id}`, { headers: auth(first) })).status, 401);
});

test('malformed, invalid UTF-8, oversized and profile-override API bodies are rejected before assessment', async t => {
  let calls = 0;
  const app = await workbench(t, { assess: async () => { calls++; throw new Error('Synthetic invocation'); } });
  for (const [payload, status] of [
    ['{broken', 400], ['null', 400], ['[]', 400], ['true', 400],
    [Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]), 400],
    [JSON.stringify({ targetId: 'demo-repaired', padding: 'x'.repeat(17000) }), 413],
    ['{"targetId":"demo-repaired","origin":"http://127.0.0.1:1"}', 400],
    ['{"targetId":"demo-repaired","__proto__":{"targetId":"demo-vulnerable"}}', 400],
    ['{"targetId":"not-configured"}', 400],
  ]) assert.equal((await raw(app.origin, '/api/runs', { method: 'POST', headers: post(app), payload })).status, status);
  assert.equal((await raw(app.origin, '/api/runs', { method: 'POST', headers: { ...post(app), 'Content-Type': 'text/plain' }, payload: '{}' })).status, 415);
  assert.equal(calls, 0);
  assert.equal((await raw(app.origin, '/api/runs', { method: 'POST', headers: post(app), payload: '{"targetId":"demo-repaired"}' })).status, 500);
  assert.equal(calls, 1);
});

test('unknown evidence and note fields are rejected; a human HTML note cannot alter verdict or integrity', async t => {
  const app = await workbench(t), saved = await seed(t, app);
  assert.equal((await raw(app.origin, `/api/runs/${randomUUID()}`, { headers: auth(app) })).status, 404);
  assert.equal((await raw(app.origin, '/api/runs/not-a-run-id/export.json', { headers: auth(app) })).status, 400);
  for (const input of [{ caseId: 'missing', note: 'test' }, { caseId: '__proto__', note: 'test' }, { caseId: 'allowed', note: 'test', status: 'pass' }, { caseId: 'allowed', note: 'x'.repeat(5001) }]) {
    assert.equal((await raw(app.origin, `/api/runs/${saved.id}/notes`, { method: 'POST', headers: post(app), payload: JSON.stringify(input) })).status, 400);
  }
  const note = '<img src="https://attacker.invalid/pixel" onerror="alert(1)"><script>alert(2)</script>';
  assert.equal((await raw(app.origin, `/api/runs/${saved.id}/notes`, { method: 'POST', headers: post(app), payload: JSON.stringify({ caseId: 'allowed', note }) })).status, 200);
  const after = await app.store.get(saved.id);
  assert.deepEqual(after.results, saved.results); assert.equal(after.integrity.sha256, saved.integrity.sha256);
  const report = await raw(app.origin, `/api/runs/${saved.id}/report.html`, { headers: auth(app) });
  assert.equal(report.status, 200); assert.doesNotMatch(report.text, /<img|<script/); assert.match(report.text, /&lt;img/);
  assert.match(report.headers['content-disposition'], /attachment/); assert.match(report.headers['content-security-policy'], /default-src 'none'/);
});

test('encoded destination and traversal variants reject the full assessment before even its allowed control is sent', async t => {
  let hits = 0;
  const origin = await lab(t, (_, res) => { hits++; respond(res, { ok: true }); });
  const paths = ['/%25252f%25252fattacker.invalid/x', '/%25255c%25255cattacker.invalid/x', '/x/%25252e%25252e/private', '/%250d%250aInjected:yes', '/%25252525252fhidden'];
  for (const path of paths) {
    const target = profile(origin); target.checks[1].path = path;
    await assert.rejects(runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: 'synthetic-review-secret' } }), /Invalid HTTP contract/);
  }
  for (const field of ['origin', 'url', 'headers', 'host']) {
    const target = profile(origin); target.checks[1][field] = 'https://attacker.invalid';
    await assert.rejects(runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: 'synthetic-review-secret' } }), /Invalid HTTP contract/);
  }
  assert.equal(hits, 0);
});

test('credential echoes in failed, malformed and oversized responses remain absent from disk and every API export', async t => {
  const credential = 'synthetic-failure-echo-secret', privateData = 'synthetic-person-private-marker';
  const origin = await lab(t, (req, res) => {
    const content = { ok: req.url === '/allowed', echo: req.headers.authorization, privateData };
    if (req.url === '/malformed') return res.end(`{"echo":"${req.headers.authorization}","privateData":"${privateData}"`);
    if (req.url === '/oversized') content.padding = 'x'.repeat(70000);
    respond(res, content, req.url === '/failed' ? 500 : 200);
  });
  const target = profile(origin); const template = target.checks[1];
  target.checks = [target.checks[0], ...['failed', 'malformed', 'oversized'].map(id => ({ ...structuredClone(template), id, path: `/${id}`, assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/absent', expected: false }] }))];
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: credential } });
  assert.deepEqual(run.results.map(result => result.status), ['inconclusive', 'fail', 'inconclusive', 'error']);
  const app = await workbench(t, { profiles: [target], env: { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: credential } });
  await app.store.save(run);
  const outputs = [await readFile(join(app.dataDir, 'runs', `${run.id}.json`), 'utf8')];
  for (const path of ['/api/bootstrap', '/api/history', `/api/runs/${run.id}`, `/api/runs/${run.id}/export.json`, `/api/runs/${run.id}/report.html`, `/api/suite/export.json?targetId=${target.id}`]) {
    const response = await raw(app.origin, path, { headers: auth(app) }); assert.equal(response.status, 200); outputs.push(response.text);
  }
  for (const output of outputs) for (const secret of [credential, privateData]) assert.equal(output.includes(secret), false, 'Private response content must not enter retained evidence.');
});

test('comparison rejects omitted identities, duplicate cases and missing permitted-use controls', async t => {
  const origin = await lab(t, (req, res) => respond(res, { ok: true }, req.url === '/restricted' ? 403 : 200));
  const run = await runHttpAssessment(profile(origin), { env: { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: 'synthetic-review-secret' } });
  for (const key of ['evidenceOrigin', 'runtimeMode', 'assertionSchemaVersion', 'contextId', 'profileHash']) {
    const candidate = structuredClone(run); delete candidate[key]; assert.equal(compareRuns(run, candidate).compatible, false, key);
  }
  const duplicate = structuredClone(run); duplicate.results.push(structuredClone(duplicate.results[0])); assert.equal(compareRuns(run, duplicate).compatible, false);
  const missing = structuredClone(run); missing.results = missing.results.filter(r => r.id !== 'allowed'); assert.equal(compareRuns(run, missing).compatible, false); assert.equal(compareRuns(run, missing).controlsPass, false);
  for (const status of ['inconclusive', 'error']) {
    const candidate = structuredClone(run); candidate.results[0].status = status;
    const comparison = compareRuns(run, candidate); assert.equal(comparison.controlsPass, false); assert.equal(comparison.summary.fixed, 0);
  }
});

test('malformed UTF-8 response bytes cannot establish a passing JSON absence predicate', async t => {
  const origin = await lab(t, (_, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d])); });
  const target = profile(origin); target.checks = [{ ...target.checks[0], path: '/', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/private', expected: false }] }];
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: 'synthetic-review-secret' } });
  assert.equal(run.results[0].status, 'inconclusive', 'An invalid UTF-8 response cannot prove a JSON field is absent.');
  const observation = await observeHttp(origin, { method: 'GET', path: '/' });
  assert.equal(observation.complete, true); assert.equal(observation.jsonParsed, false, 'Invalid UTF-8 must not be decoded with replacement and accepted as JSON.');
  assert.equal(observation.error, 'invalid-json');
});

test('duplicate Authorization headers cannot be silently reduced to one valid capability', async t => {
  const app = await workbench(t);
  const response = await raw(app.origin, '/api/suite/export.json', { headers: { Authorization: [`Bearer ${app.accessToken}`, `Bearer ${'wrong'.repeat(9)}`] } });
  assert.equal(response.status, 401, 'A duplicated Authorization header must fail closed at the live HTTP boundary.');
});

test('duplicate Host headers cannot select the allowed host while discarding a foreign host', async t => {
  const app = await workbench(t);
  const status = await wireStatus(app.origin, ['GET /api/suite/export.json HTTP/1.1', `Host: ${new URL(app.origin).host}`, 'Host: attacker.invalid', `Authorization: Bearer ${app.accessToken}`, 'Connection: close']);
  assert.ok([400, 403].includes(status), `Ambiguous Host headers must not satisfy the exact local Host boundary; observed HTTP ${status}.`);
});

test('a foreign Origin after the header count bound cannot disappear before origin validation', async t => {
  const app = await workbench(t);
  const headers = { ...auth(app), Host: new URL(app.origin).host, ...Object.fromEntries(Array.from({ length: 41 }, (_, i) => [`X-Synthetic-Padding-${i}`, '1'])), Origin: 'https://attacker.invalid' };
  const response = await raw(app.origin, '/api/suite/export.json', { headers });
  assert.ok([400, 403, 431].includes(response.status), 'Excess headers must be rejected rather than silently dropping security headers.');
});

test('release: imported provider passes stay outside native gate approval even with copied native identity fields', async () => {
  const source = JSON.parse(await readFile(new URL('../integrations/evaluation-import/fixtures/promptfoo-0.123.1-v3.synthetic.json', import.meta.url), 'utf8'));
  source.results.results = [source.results.results[0]];
  const imported = importPromptfooJson(JSON.stringify(source), INPUT_CONTRACT);
  assert.equal(imported.ok, true); assert.equal(imported.record.summary.pass, 1);
  for (const candidate of [imported.record, { ...imported.record, schemaVersion: 1, id: randomUUID(), targetId: 'external-preview', evidenceOrigin: 'local-http-response' }]) {
    const gate = summarizeGate({ candidate });
    assert.equal(gate.exitCode, 2); assert.equal(gate.current, null);
    assert.equal(gate.outcome, 'config-or-runtime-error');
  }
  assert.equal(imported.record.trust.nativeAssessment, false);
  assert.equal(imported.record.trust.backendObservations, false);
  assert.equal(imported.record.trust.repairVerification, 'not-assessed');
});

test('release: importer treats fetch URLs and executable provider fields as inert private input', async t => {
  let hits = 0;
  const origin = await lab(t, (_, res) => { hits++; respond(res, { ok: true }); });
  const source = JSON.parse(await readFile(new URL('../integrations/evaluation-import/fixtures/promptfoo-0.123.1-v3.synthetic.json', import.meta.url), 'utf8'));
  const marker = 'synthetic-import-private-marker';
  source.config.providers = [{ id: `${origin}/provider`, config: { apiKey: marker, webhook: `${origin}/webhook`, command: `throw new Error('${marker}')` } }];
  source.blobAssets = [{ url: `${origin}/asset` }]; source.shareableUrl = `${origin}/share`;
  source.results.results[0].provider = { id: `${origin}/provider`, config: { apiKey: marker } };
  source.results.results[0].testCase = { assert: [{ type: 'javascript', value: `fetch('${origin}/assertion')` }] };
  source.results.results[0].response = { output: `<img src="${origin}/pixel">${marker}` };
  const imported = importPromptfooJson(JSON.stringify(source), INPUT_CONTRACT);
  assert.equal(imported.ok, true);
  const serialized = JSON.stringify(imported);
  for (const privateValue of [origin, marker, 'webhook', '<img', 'apiKey', 'fetch(']) assert.equal(serialized.includes(privateValue), false);
  assert.equal(hits, 0);
  const malformed = importPromptfooJson(JSON.stringify(source).slice(0, -1), INPUT_CONTRACT);
  assert.equal(malformed.ok, false); assert.equal(JSON.stringify(malformed).includes(marker), false); assert.equal(hits, 0);
});

test('release: preview endpoint rejects Origin, duplicate auth/content type and opt-in header ambiguity', async t => {
  let calls = 0;
  const app = await workbench(t, { assess: async () => { calls++; throw new Error('Synthetic invocation'); } });
  const content = await readFile(new URL('../integrations/evaluation-import/fixtures/promptfoo-0.123.1-v3.synthetic.json', import.meta.url), 'utf8');
  const payload = JSON.stringify({ format: INPUT_CONTRACT, content });
  const path = '/api/external-evaluations/preview';
  assert.equal((await raw(app.origin, path, { method: 'POST', headers: post(app), payload })).status, 200);
  for (const [headers, status] of [
    [{ ...post(app), Origin: 'https://attacker.invalid' }, 403],
    [{ ...post(app), Origin: 'null' }, 403],
    [{ ...post(app), Origin: [app.origin, 'https://attacker.invalid'] }, 403],
    [{ ...post(app), 'Sec-Fetch-Site': 'cross-site' }, 403],
    [{ ...post(app), Authorization: [`Bearer ${app.accessToken}`, `Bearer ${'wrong'.repeat(9)}`] }, 401],
    [{ ...post(app), 'Content-Type': ['application/json', 'text/plain'] }, 415],
    [{ ...post(app), 'X-Scopehaven-Request': ['1', '1'] }, 403],
  ]) {
    const response = await raw(app.origin, path, { method: 'POST', headers, payload });
    assert.equal(response.status, status);
    assert.equal(response.text.includes(app.accessToken), false);
    assert.equal(response.text.includes('SYNTHETIC_PRIVATE_SENTINEL'), false);
  }
  assert.equal(calls, 0);
});

test('release: saved response gate requires auth and compatible registry evidence without executing assessments', async t => {
  let targetRequests = 0, assessments = 0;
  const origin = await lab(t, (req, res) => { targetRequests++; respond(res, req.headers.authorization === 'Bearer synthetic-review-secret' ? { ok: true, principal: 'synthetic-member' } : { ok: true }, req.url === '/restricted' ? 403 : req.headers.authorization === 'Bearer synthetic-review-secret' ? 200 : 401); });
  const target = withSurface(profile(origin));
  target.actors.member.identityValue = 'synthetic-member'; target.checks[0].assertions.push({ kind: 'json.equals', pointer: '/principal', expected: 'synthetic-member' });
  const app = await workbench(t, { profiles: [target], env: { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: 'synthetic-review-secret' }, assess: async () => { assessments++; throw new Error('Unexpected assessment'); } });
  const saved = await app.store.save(await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: 'synthetic-review-secret' } }));
  const requestsBeforeGate = targetRequests;
  await app.store.note(saved.id, 'allowed', 'synthetic-private-note-<script>ignored</script>');
  const path = `/api/runs/${saved.id}/gate`;
  assert.equal((await raw(app.origin, path)).status, 401);
  assert.equal((await raw(app.origin, path, { headers: { ...auth(app), Origin: 'https://attacker.invalid' } })).status, 403);
  const response = await raw(app.origin, path, { headers: auth(app) }); assert.equal(response.status, 200);
  const summary = JSON.parse(response.text);
  assert.equal(summary.exitCode, 0); assert.equal(summary.evaluationMode, 'saved-evidence');
  assert.equal(summary.assessmentExecuted, false); assert.equal(summary.scheduled, false);
  assert.equal(summary.current.evidenceScope, 'response-only');
  assert.equal(response.text.includes('synthetic-private-note'), false); assert.equal(response.text.includes(app.accessToken), false);
  assert.equal((await raw(app.origin, `${path}?baseline=invalid`, { headers: auth(app) })).status, 400);
  assert.equal((await raw(app.origin, `${path}?baseline=${randomUUID()}`, { headers: auth(app) })).status, 404);
  const incompatible = { ...structuredClone(saved), id: randomUUID(), profileHash: '0'.repeat(64) };
  delete incompatible.notes; delete incompatible.integrity;
  await app.store.save(incompatible);
  const rejected = JSON.parse((await raw(app.origin, `/api/runs/${incompatible.id}/gate`, { headers: auth(app) })).text);
  assert.equal(rejected.exitCode, 2);
  assert.equal(assessments, 0); assert.equal(targetRequests, requestsBeforeGate);
});

test('release: intro assets remain public, capability-free and unable to authorize protected work', async t => {
  let calls = 0;
  const app = await workbench(t, { assess: async () => { calls++; throw new Error('Synthetic invocation'); } });
  for (const path of ['/intro/', '/intro/index.html', '/intro/intro.js', '/intro/particle-scene.js', '/intro/styles.css']) {
    const response = await raw(app.origin, path);
    assert.equal(response.status, 200, path);
    assert.match(response.headers['content-security-policy'], /connect-src 'none'/);
    assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
    assert.equal(response.text.includes(app.accessToken), false);
    if (path.endsWith('.js')) assert.doesNotMatch(response.text, /\bfetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\s*\(/);
    if (path.endsWith('/') || path.endsWith('.html')) {
      const anchors = [...response.text.matchAll(/<a\b[^>]*href="([^"]+)"[^>]*>/g)];
      assert.ok(anchors.some(match => match[1] === '/'));
      for (const [tag, href] of anchors) {
        if (href === '/' || href.startsWith('#')) continue;
        // Public source citations may open HTTPS pages only through a user click.
        // Keep credentials, local evidence and the referrer out of that navigation.
        const source = new URL(href);
        assert.equal(source.protocol, 'https:');
        assert.equal(source.username, ''); assert.equal(source.password, '');
        assert.equal(source.hash, ''); assert.equal(source.search, '');
        assert.doesNotMatch(href, /localhost|127\.0\.0\.1|#access=|\/api\//);
        assert.match(tag, /\btarget="_blank"/);
        assert.match(tag, /\brel="(?=[^"]*\bnoopener\b)(?=[^"]*\bnoreferrer\b)[^"]+"/);
      }
    }
  }
  for (const path of ['/intro/local-access.html', '/intro/../../data/local-access.html', '/intro/missing.js']) assert.equal((await raw(app.origin, path)).status, 404);
  assert.equal((await raw(app.origin, '/api/bootstrap', { headers: { Referer: `${app.origin}/intro/` } })).status, 401);
  assert.equal(calls, 0);
});

test('release: digested contradictory response observations cannot make the saved-evidence gate clean', async t => {
  const origin = await lab(t, (req, res) => respond(res, req.headers.authorization === 'Bearer synthetic-review-secret' ? { ok: true, principal: 'synthetic-member' } : { ok: true }, req.url === '/restricted' ? 403 : req.headers.authorization === 'Bearer synthetic-review-secret' ? 200 : 401));
  const target = withSurface(profile(origin)), env = { SCOPEHAVEN_TARGET_REVIEW_TEST_TOKEN: 'synthetic-review-secret' };
  target.actors.member.identityValue = 'synthetic-member'; target.checks[0].assertions.push({ kind: 'json.equals', pointer: '/principal', expected: 'synthetic-member' });
  const run = await runHttpAssessment(target, { env });
  const expectedSuite = createRegistry({ profiles: [target], env }).exportSuite(target.id);
  assert.equal(summarizeGate({ candidate: run, expectedSuite }).exitCode, 0);
  const app = await workbench(t, { profiles: [target], env });
  const outcomes = [];
  for (const mutation of ['not-attempted-timeout', 'unparsed-json']) {
    const candidate = structuredClone(run); candidate.id = randomUUID();
    const row = candidate.results.find(result => result.id === 'allowed'), evidence = row.trace[0].data;
    if (mutation === 'not-attempted-timeout') {
      Object.assign(evidence, { httpStatus: null, requestAttempted: false, transportOutcome: 'timeout', responseComplete: true, responseBytes: 0, jsonParsed: false });
      Object.assign(row.observed, { httpStatus: null, complete: true, jsonParsed: false });
    } else {
      Object.assign(evidence, { transportOutcome: 'invalid-json', jsonParsed: false });
      row.observed.jsonParsed = false;
    }
    row.evidenceDigest = digest({ evidence, assertions: row.assertions });
    const direct = summarizeGate({ candidate, expectedSuite });
    await app.store.save(candidate);
    const response = await raw(app.origin, `/api/runs/${candidate.id}/gate`, { headers: auth(app) });
    assert.equal(response.status, 200);
    outcomes.push({ mutation, exitCodes: [direct.exitCode, JSON.parse(response.text).exitCode] });
  }
  assert.deepEqual(outcomes, [{ mutation: 'not-attempted-timeout', exitCodes: [2, 2] }, { mutation: 'unparsed-json', exitCodes: [2, 2] }]);
});

// Small DOM port for deterministic lifecycle tests, not a browser/layout mock.
// Unsupported HTML sinks fail loudly. The browser owner verifies native DOM,
// keyboard/layout/CSP behavior separately against the same integrated bytes.
class ReviewElement {
  constructor(tagName) {
    this.tagName = tagName.toLowerCase(); this.nodeType = 1; this.childNodes = [];
    this.dataset = {}; this.attributes = {}; this.listeners = new Map();
    this.className = ''; this.value = ''; this.ownText = ''; this.parentNode = null;
    this.classList = {
      contains: value => this.className.split(/\s+/).includes(value),
      add: value => { if (!this.classList.contains(value)) this.className = `${this.className} ${value}`.trim(); },
      remove: value => { this.className = this.className.split(/\s+/).filter(v => v !== value).join(' '); },
      toggle: (value, enabled) => { const add = enabled ?? !this.classList.contains(value); this.classList[add ? 'add' : 'remove'](value); return add; },
    };
  }
  get children() { return this.childNodes; }
  get textContent() { return this.ownText + this.childNodes.map(child => child.textContent).join(''); }
  set textContent(value) { this.replaceChildren(); this.ownText = String(value); }
  set innerHTML(_) { throw new Error('Untrusted HTML sink used by dashboard.'); }
  insertAdjacentHTML() { throw new Error('Untrusted HTML sink used by dashboard.'); }
  append(...children) {
    for (const child of children) {
      assert.ok(child instanceof ReviewElement, 'Dashboard should construct DOM elements explicitly.');
      child.parentNode = this; this.childNodes.push(child);
    }
  }
  replaceChildren(...children) { for (const child of this.childNodes) child.parentNode = null; this.childNodes = []; this.ownText = ''; this.append(...children); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name] ?? null; }
  matches(selector) {
    if (selector.startsWith('.')) return this.classList.contains(selector.slice(1));
    const attr = /^\[([^=\]]+)(?:="([^"]*)")?\]$/.exec(selector);
    if (attr) {
      const value = attr[1].startsWith('data-') ? this.dataset[attr[1].slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] : this.getAttribute(attr[1]);
      return value !== undefined && value !== null && (attr[2] === undefined || value === attr[2]);
    }
    return this.tagName === selector.toLowerCase();
  }
  querySelectorAll(selector) {
    const selectors = selector.split(',').map(value => value.trim()), found = [];
    for (const child of this.childNodes) { if (selectors.some(s => child.matches(s))) found.push(child); found.push(...child.querySelectorAll(selector)); }
    return found;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  addEventListener(type, fn, options = {}) { const handlers = this.listeners.get(type) || []; handlers.push({ fn, signal: options.signal }); this.listeners.set(type, handlers); }
  fire(type) { return Promise.all((this.listeners.get(type) || []).filter(handler => !handler.signal?.aborted).map(({ fn }) => fn({ type, target: this, preventDefault() {} }))); }
  focus() {}
}
const uiTick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
function reviewButton(root, name) {
  const button = root.querySelectorAll('button').find(element => element.getAttribute('aria-label') === name || element.textContent === name);
  assert.ok(button, `Expected dashboard control: ${name}`); return button;
}
async function dashboardHarness(t, { adapter = {}, data, onLock } = {}) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'document');
  globalThis.document = { createElement: tag => new ReviewElement(tag) };
  let dashboard;
  t.after(() => { dashboard?.destroy(); if (previous) Object.defineProperty(globalThis, 'document', previous); else delete globalThis.document; });
  const moduleURL = new URL('../public/dashboard/dashboard.mjs', import.meta.url);
  const sourceHash = createHash('sha256').update(await readFile(moduleURL)).digest('hex');
  const { mountDashboard } = await import(`${moduleURL.href}?security-review=${sourceHash}`);
  assert.equal(createHash('sha256').update(await readFile(moduleURL)).digest('hex'), sourceHash, 'Dashboard changed during test-module loading; rerun against stable source.');
  const root = new ReviewElement('div');
  const bootstrap = data || { targets: [], runs: [], history: { total: 0, nextCursor: null } };
  dashboard = mountDashboard(root, { adapter: { bootstrap: async () => structuredClone(bootstrap), ...adapter }, onLock });
  await dashboard.ready;
  return { root, dashboard };
}
async function externalRecord() {
  const content = await readFile(new URL('../integrations/evaluation-import/fixtures/promptfoo-0.123.1-v3.synthetic.json', import.meta.url), 'utf8');
  const result = importPromptfooJson(content, INPUT_CONTRACT); assert.equal(result.ok, true); return result.record;
}

test('release UI: late preview after lock cannot restore private state or detached raw input', async t => {
  const pending = deferred(), record = await externalRecord(); let locks = 0;
  record.checks[0].label = 'private-late-preview-marker';
  const { root } = await dashboardHarness(t, { adapter: { previewExternal: () => pending.promise }, onLock: () => { locks++; } });
  await reviewButton(root, 'External evaluation').fire('click');
  const input = root.querySelector('textarea'), form = root.querySelector('form');
  input.value = '{"private":"synthetic-raw-preview"}'; await form.fire('submit');
  assert.equal(input.value, ''); input.value = 'synthetic-unsent-private-input';
  await reviewButton(root, 'Lock view').fire('click');
  assert.equal(input.value, ''); assert.equal(locks, 1); assert.match(root.textContent, /Workbench locked/);
  pending.resolve({ ok: true, record }); await uiTick();
  assert.match(root.textContent, /Workbench locked/); assert.doesNotMatch(root.textContent, /private-late-preview-marker|synthetic-unsent-private-input/);
  assert.equal(root.querySelector('textarea'), null);
});

test('release UI: unmount invalidates pending native evidence', async t => {
  const id = randomUUID(), late = deferred(), marker = 'synthetic-private-native-result';
  const data = { targets: [], runs: [{ id, targetName: 'Saved native run', createdAt: '2026-01-01T00:00:00Z', counts: { pass: 1, fail: 0 }, build: 'synthetic' }], history: { total: 1 } };
  const { root, dashboard } = await dashboardHarness(t, { data, adapter: { run: () => late.promise } });
  void reviewButton(root, `Open run ${id}`).fire('click'); await uiTick();
  dashboard.destroy();
  late.resolve({ ...data.runs[0], targetName: marker, results: [], counts: { pass: 1 }, notes: { any: { note: marker } } }); await uiTick();
  assert.equal(root.childNodes.length, 0); assert.doesNotMatch(root.textContent, /synthetic-private-native-result/);
});

test('release UI: unmount clears detached investigation notes and ignores a late note receipt', async t => {
  const id = randomUUID(), pending = deferred(), marker = 'synthetic-private-note-on-unmount';
  const run = { id, targetName: 'Note fixture', build: 'synthetic', createdAt: '2026-01-01T00:00:00Z', counts: { pass: 1 }, results: [{ id: 'allowed', title: 'Allowed check', category: 'Control', severity: 'control', status: 'pass', assertions: [], trace: [] }], notes: {} };
  const { root, dashboard } = await dashboardHarness(t, { data: { targets: [], runs: [run], history: { total: 1 } }, adapter: { run: async () => structuredClone(run), note: () => pending.promise } });
  await reviewButton(root, `Open run ${id}`).fire('click'); await uiTick();
  await root.querySelector('.sh-finding').fire('click');
  const input = root.querySelector('textarea'); input.value = marker;
  await root.querySelector('form').fire('submit'); dashboard.destroy();
  assert.equal(input.value, ''); assert.equal(root.childNodes.length, 0);
  pending.resolve({ note: marker, updatedAt: '2026-01-01T00:00:01Z' }); await uiTick();
  assert.equal(root.childNodes.length, 0); assert.equal(input.value, '');
});

test('release UI: hostile preview text stays inert and cannot enter native history or comparison', async t => {
  const record = await externalRecord(), hostile = '<img src="data:x" onerror="globalThis.syntheticXss=true"><script>synthetic</script>';
  record.checks[0].label = hostile; record.limitations.push(hostile);
  const id = randomUUID(), data = { targets: [], runs: [{ id, targetName: 'Native evidence only', build: 'synthetic', createdAt: '2026-01-01T00:00:00Z', counts: { pass: 1, fail: 0 } }], history: { total: 1 } };
  const { root } = await dashboardHarness(t, { data, adapter: { previewExternal: async () => ({ ok: true, record }) } });
  await reviewButton(root, 'External evaluation').fire('click');
  root.querySelector('textarea').value = '{"synthetic":true}'; await root.querySelector('form').fire('submit'); await uiTick();
  assert.ok(root.textContent.includes(hostile)); assert.match(root.textContent, /EXTERNAL \/ UNVERIFIED/);
  assert.match(root.textContent, /not become native evidence or verified repairs/);
  assert.equal(root.querySelectorAll('img, script').length, 0); assert.equal(globalThis.syntheticXss, undefined);
  await reviewButton(root, 'Run history').fire('click');
  assert.match(root.textContent, /Native evidence only/); assert.equal(root.textContent.includes(hostile), false);
  assert.match(root.textContent, /1 loaded of 1 saved/);
  await reviewButton(root, 'Compare runs').fire('click');
  assert.match(root.textContent, /Two runs make a comparison/); assert.equal(root.textContent.includes(hostile), false);
});

function hostResponse(value, { status = 200, read, cancel = async () => {} } = {}) {
  const bytes = new TextEncoder().encode(JSON.stringify(value)); let delivered = false;
  return { status, ok: status >= 200 && status < 300, body: { getReader: () => ({
    read: read || (async () => { if (delivered) return { done: true }; delivered = true; return { value: bytes, done: false }; }),
    cancel,
  }) } };
}
async function hostHarness(t) {
  const hostURL = new URL('../public/workbench-host.js', import.meta.url);
  const source = await readFile(hostURL, 'utf8');
  const imports = "import { mountDashboard } from '/dashboard/dashboard.mjs';\nimport { createDashboardAdapter } from '/dashboard/adapter.mjs';\n";
  assert.ok(source.startsWith(imports), 'Review the changed host dependency interface before extending this harness.');
  const body = source.slice(imports.length); assert.doesNotMatch(body, /^import\s/m);
  const { createDashboardAdapter } = await import('../public/dashboard/adapter.mjs');
  const elements = Object.fromEntries(['access-panel', 'access-form', 'access-key', 'access-status', 'unlock-button', 'dashboard-root', 'close-access'].map(id => [id, new ReviewElement('div')]));
  elements['access-panel'].open = false;
  elements['access-panel'].showModal = () => { elements['access-panel'].open = true; };
  elements['access-panel'].close = () => { elements['access-panel'].open = false; void elements['access-panel'].fire('close'); };
  const calls = [], replacedURLs = [], blobs = [], revoked = [], timers = new Map(), windowHandlers = new Map();
  const token = `${randomUUID().replaceAll('-', '')}${randomUUID().replaceAll('-', '')}`;
  let timerId = 0, now = 1000, requestOverride, adapter, callbacks, mountOptions, locks = 0, destroyed = 0, reloads = 0;
  class ReviewURL extends URL {
    static createObjectURL() { const url = `blob:synthetic-review-${blobs.length + 1}`; blobs.push(url); return url; }
    static revokeObjectURL(url) { revoked.push(url); }
  }
  const location = { origin: 'http://127.0.0.1:4317', pathname: '/', search: '', hash: `#access=${token}`, reload: () => { reloads++; } };
  const context = createContext({
    URL: ReviewURL, URLSearchParams, TextDecoder, TextEncoder, Uint8Array, Blob, AbortController,
    AbortSignal: { any: signals => AbortSignal.any(signals), timeout: () => new AbortController().signal },
    Date: { now: () => now }, location,
    history: { replaceState: (_, __, url) => { replacedURLs.push(url); location.hash = ''; } },
    setTimeout: (fn, delay) => { timers.set(++timerId, { fn, delay }); return timerId; }, clearTimeout: id => timers.delete(id),
    window: { addEventListener: (type, fn) => windowHandlers.set(type, fn) },
    document: { getElementById: id => elements[id], body: new ReviewElement('body'), createElement: tag => { const node = new ReviewElement(tag); node.click = () => {}; node.remove = () => { if (node.parentNode) node.parentNode.childNodes = node.parentNode.childNodes.filter(child => child !== node); }; return node; } },
    fetch: async (url, options) => {
      const path = new URL(url, location.origin).pathname; calls.push({ path, options });
      if (requestOverride) { const response = await requestOverride(path, options); if (response) return response; }
      return hostResponse(path === '/api/access-info' ? { expiresAt: 11000 } : { targets: [], runs: [], history: { total: 0 } });
    },
    createDashboardAdapter: options => { callbacks = options; adapter = createDashboardAdapter(options); return adapter; },
    mountDashboard: (_, options) => {
      mountOptions = options;
      const bootstrap = () => options.adapter.bootstrap().catch(error => { if (error.status === 401) locks++; else throw error; });
      return { ready: bootstrap(), unlock: bootstrap, lock: () => { locks++; }, destroy: () => { destroyed++; } };
    },
  }, { codeGeneration: { strings: false, wasm: false } });
  await new Script(`(async () => {${body}\n})()`, { filename: hostURL.pathname }).runInContext(context, { timeout: 1000 });
  assert.equal(await readFile(hostURL, 'utf8'), source, 'Host changed during execution; rerun against stable source.');
  t.after(() => { windowHandlers.get('pagehide')?.(); });
  return { elements, calls, replacedURLs, blobs, revoked, timers, adapter, callbacks, mountOptions, token,
    setRequest(fn) { requestOverride = fn; }, setTime(value) { now = value; }, event(type, event = {}) { windowHandlers.get(type)?.(event); },
    get locks() { return locks; }, get destroyed() { return destroyed; }, get reloads() { return reloads; } };
}

test('release host: lock during a streaming response aborts the session and rejects stale evidence', async t => {
  const host = await hostHarness(t), pending = deferred(); let reads = 0;
  assert.deepEqual(host.replacedURLs, ['/']);
  host.setRequest(path => path === '/api/history' ? hostResponse(null, { read: async () => ++reads === 1 ? pending.promise : { done: true } }) : undefined);
  const request = host.adapter.history(); const rejected = assert.rejects(request, error => error.code === 'ACCESS_REQUIRED');
  await uiTick(); const call = host.calls.find(item => item.path === '/api/history'); assert.ok(call);
  assert.ok(call.options.headers.Authorization === `Bearer ${host.token}`, 'Capability must appear only in the authorization header.');
  assert.equal(call.options.credentials, 'omit'); assert.equal(call.options.redirect, 'error');
  host.elements['access-key'].value = 'synthetic-unsent-key'; host.mountOptions.onLock();
  assert.equal(call.options.signal.aborted, true); assert.equal(host.elements['access-key'].value, '');
  pending.resolve({ value: new TextEncoder().encode('{"private":"late-response"}'), done: false }); await rejected;
  const before = host.calls.length; await assert.rejects(host.adapter.history(), error => error.code === 'ACCESS_REQUIRED'); assert.equal(host.calls.length, before);
});

test('release host: expiry and page lifecycle clear access before pending work can complete', async t => {
  const host = await hostHarness(t), pending = deferred(); let reads = 0;
  host.setRequest(path => path === '/api/history' ? hostResponse(null, { read: async () => ++reads === 1 ? pending.promise : { done: true } }) : undefined);
  const request = host.adapter.history(), rejected = assert.rejects(request, error => error.code === 'ACCESS_REQUIRED'); await uiTick();
  const expiry = [...host.timers.values()].find(timer => timer.delay === 10000); assert.ok(expiry);
  host.setTime(11000); expiry.fn(); assert.ok(host.locks >= 1);
  pending.resolve({ value: new TextEncoder().encode('{}'), done: false }); await rejected;
  host.event('pagehide'); assert.equal(host.destroyed, 1);
  host.event('pageshow', { persisted: true }); assert.equal(host.reloads, 1);
  const before = host.calls.length; await assert.rejects(host.adapter.bootstrap(), error => error.code === 'ACCESS_REQUIRED'); assert.equal(host.calls.length, before);
});

test('release host: bounded authenticated exports reject unsafe routes and revoke every prepared blob on lock', async t => {
  const host = await hostHarness(t), id = randomUUID();
  for (const path of ['https://attacker.invalid/api/x', '//attacker.invalid/api/x', '/not-api/x', '/api/x#fragment']) {
    const before = host.calls.length; await assert.rejects(host.callbacks.request(path), /Unsupported local API destination/); assert.equal(host.calls.length, before);
  }
  let cancelled = false;
  host.setRequest(path => path.includes(`/api/runs/${id}/`) ? hostResponse(null, { read: async () => ({ value: new Uint8Array(8 * 1024 * 1024 + 1), done: false }), cancel: async () => { cancelled = true; } }) : undefined);
  await assert.rejects(host.adapter.exportRun(id), /response exceeds its limit/);
  assert.equal(cancelled, true); assert.equal(host.blobs.length, 0); host.setRequest(undefined);
  for (let i = 0; i < 9; i++) {
    const result = await host.adapter.exportRun(id, i % 2 ? 'html' : 'json'); assert.equal(result.prepared, true); assert.equal(result.saved, undefined);
  }
  assert.equal(host.blobs.length, 9); assert.ok(host.revoked.includes(host.blobs[0]));
  for (const call of host.calls.filter(item => item.path.includes(`/api/runs/${id}/`))) {
    assert.equal(call.options.credentials, 'omit'); assert.equal(call.options.redirect, 'error');
    assert.ok(call.options.headers.Authorization === `Bearer ${host.token}`, 'Exports retain header authentication.');
  }
  host.mountOptions.onLock(); assert.deepEqual(new Set(host.revoked), new Set(host.blobs));
  assert.equal(host.blobs.some(url => url.includes(host.token)), false);
});

test('release: mounted dashboard serves only reviewed runtime assets and keeps the access gate authoritative', async t => {
  let assessments = 0;
  const app = await workbench(t, { assess: async () => { assessments++; throw new Error('Unexpected assessment'); } });
  const index = await raw(app.origin, '/'); assert.equal(index.status, 200);
  assert.match(index.text, /id="dashboard-root"/); assert.match(index.text, /workbench-host\.js/);
  assert.match(index.text, /id="access-panel"/); assert.doesNotMatch(index.text, /preview-data\.json|preview\.mjs/);
  for (const [route, file] of [['/workbench-host.js', 'workbench-host.js'], ['/access.css', 'access.css'], ['/dashboard/dashboard.mjs', 'dashboard/dashboard.mjs'], ['/dashboard/adapter.mjs', 'dashboard/adapter.mjs'], ['/dashboard/dashboard.css', 'dashboard/dashboard.css']]) {
    const response = await raw(app.origin, route); assert.equal(response.status, 200, route);
    assert.equal(response.text, await readFile(new URL(`../public/${file}`, import.meta.url), 'utf8'));
    assert.equal(response.text.includes(app.accessToken), false); assert.equal(response.headers['cache-control'], 'no-store');
    assert.match(response.headers['content-security-policy'], /script-src 'self'/);
  }
  for (const path of ['/dashboard/preview-data.json', '/dashboard/preview.mjs', '/dashboard/INTEGRATION.md']) assert.equal((await raw(app.origin, path)).status, 404);
  assert.equal((await raw(app.origin, '/api/bootstrap')).status, 401);
  assert.equal(assessments, 0);
});

test('release UI: an incompatible HTTP v2 comparison renders as not comparable, never as restored', async t => {
  const runOf = (id, createdAt) => ({ id, targetId: 'session-cases', targetName: 'Synthetic session cases', build: 'test', createdAt, counts: { pass: 2, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }, checksTotal: 2, evidenceOrigin: 'local-http-response' });
  const incompatible = { compatible: false, controlsPass: true, reasons: ['Actors, login modes or identity controls differ between the runs.'], baselineId: 'a'.repeat(8) + '-0000-4000-8000-000000000001', candidateId: 'b'.repeat(8) + '-0000-4000-8000-000000000002',
    summary: { fixed: 0, stillFailing: 0, newFailures: 0, preservedPasses: 0, unverified: 0 }, rows: [{ id: 'member-denied', title: 'Member refused', before: 'fail', after: 'pass', transition: 'incompatible' }],
    restorationLabel: 'Unverified changes', evidenceScope: 'Response comparison only; backend effects remain unverified.' };
  const data = { targets: [], runs: [runOf(incompatible.candidateId, '2026-10-05T10:00:00Z'), runOf(incompatible.baselineId, '2026-10-05T09:00:00Z')], history: { total: 2, nextCursor: null } };
  const { root } = await dashboardHarness(t, { data, adapter: { compare: async () => structuredClone(incompatible) } });
  await reviewButton(root, 'Compare runs').fire('click');
  await root.querySelector('form').fire('submit'); await uiTick(); await uiTick();
  assert.match(root.textContent, /These runs are not comparable/); assert.match(root.textContent, /Not comparable/);
  assert.doesNotMatch(root.textContent, /restored/i); assert.doesNotMatch(root.textContent, /Verified repair\b(?!s)/);
});

test('release UI: a repair the model attribution does not credit to the app is never shown as a verified repair', async t => {
  const runOf = (id, createdAt) => ({ id, targetId: 'support', targetName: 'Support app', build: 'test', createdAt, counts: { pass: 2, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }, checksTotal: 2, evidenceOrigin: 'local-http-response' });
  const ids = ['a'.repeat(8) + '-0000-4000-8000-000000000001', 'b'.repeat(8) + '-0000-4000-8000-000000000002'];
  const base = { compatible: true, controlsPass: true, reasons: [], baselineId: ids[0], candidateId: ids[1], summary: { fixed: 1, stillFailing: 0, newFailures: 0, preservedPasses: 1, unverified: 0 },
    evidenceScope: 'Response comparison only; backend effects remain unverified.' };
  const swapped = { ...base, restorationLabel: 'Not attributable to the application: the model changed and the application may have changed too',
    rows: [{ id: 'leak', title: 'No other customer data', before: 'fail', after: 'pass', transition: 'contract-restored', attribution: 'confounded' }, { id: 'own', title: 'Own order', before: 'pass', after: 'pass', transition: 'preserved', attribution: 'held-across-model-change' }],
    modelAttribution: { state: 'recorded', flipCause: 'confounded', relation: 'different', strength: 'weights-digest', app: { changed: false, evidence: 'declared-label', basis: 'same:build' }, repairCreditedToApp: false, caveats: [] } };
  const data = { targets: [], runs: [runOf(ids[1], '2026-10-06T10:00:00Z'), runOf(ids[0], '2026-10-06T09:00:00Z')], history: { total: 2, nextCursor: null } };
  let reply = swapped;
  const { root } = await dashboardHarness(t, { data, adapter: { compare: async () => structuredClone(reply) } });
  await reviewButton(root, 'Compare runs').fire('click');
  await root.querySelector('form').fire('submit'); await uiTick(); await uiTick();
  assert.match(root.textContent, /Verdict changes are attributed to: Model and application may both have changed\./);
  // The stat card, not the help line: "<count>Verified repairs<next count>".
  assert.doesNotMatch(root.textContent, /\dVerified repairs\d/); assert.match(root.textContent, /\dNot credited to the application\d/);
  assert.match(root.textContent, /Not credited to the application/); assert.match(root.textContent, /Held across a model change/);
  assert.doesNotMatch(root.textContent, /Verified repair(?!s)/);
  assert.ok(root.querySelectorAll('th').some(th => th.textContent === 'Attribution'));
  // Not recorded: the rows keep the core labels, and the note says a change may come from the model.
  reply = { ...base, restorationLabel: 'Response contracts restored', rows: [{ id: 'leak', title: 'No other customer data', before: 'fail', after: 'pass', transition: 'contract-restored' }],
    modelAttribution: { state: 'not-recorded', note: 'Model identity was not recorded for one or both runs, so a verdict change may come from the model.' } };
  await root.querySelector('form').fire('submit'); await uiTick(); await uiTick();
  assert.match(root.textContent, /a verdict change may come from the model/); assert.match(root.textContent, /Verified repair(?!s)/);
  assert.match(root.textContent, /\dVerified repairs\d/);
  assert.ok(!root.querySelectorAll('th').some(th => th.textContent === 'Attribution'));
  // An identity present but unreadable: no row and no count is a verified repair.
  reply = { ...reply, restorationLabel: 'Not attributable to the application: a model identity was present but could not be read',
    modelAttribution: { state: 'not-recorded', note: 'Model identity was not recorded for one or both runs, so a verdict change may come from the model.', malformed: ['baseline'], coreRestorationLabel: 'Response contracts restored' } };
  await root.querySelector('form').fire('submit'); await uiTick(); await uiTick();
  assert.match(root.textContent, /could not be read \(baseline\)/); assert.doesNotMatch(root.textContent, /Verified repair(?!s)/);
  assert.doesNotMatch(root.textContent, /\dVerified repairs\d/);
  assert.match(root.textContent, /Not credited to the application/);
});
