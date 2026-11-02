import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { connect } from 'node:net';
import { mkdtemp, writeFile, mkdir, symlink, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { observeHttp, runHttpAssessment, credentialReadiness, HTTP_LIMITS } from '../src/http-connector.mjs';
import { loadProfiles, createRegistry } from '../src/registry.mjs';
import { compareRuns } from '../src/runner.mjs';
import { createStore } from '../src/store.mjs';
import { startServer } from '../src/server.mjs';
import { writeTestAuthorization } from './support/authorization.mjs';
import { renderReport } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { digest } from '../src/domain.mjs';
import { validateTargetFile, CHECK_TIMEOUT_BOUNDS, PER_CHECK_BARRIER_LIMIT_MS } from '../src/contracts.mjs';
import { TIMING_BOUNDS } from '../src/http-timing.mjs';
import { createHttpLab, makeLabProfile } from '../examples/http-lab.mjs';

async function server(t, handler) {
  const instance = createServer(handler);
  await new Promise((resolve, reject) => { instance.once('error', reject); instance.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => { instance.close(resolve); instance.closeAllConnections(); }));
  return `http://127.0.0.1:${instance.address().port}`;
}
async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-connector-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
const json = (res, status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
const httpCheck = (path, method = 'GET', body) => ({ path, method, ...(body === undefined ? {} : { body }) });
function profile(origin) {
  return { id: 'owned-lab', name: 'Owned local lab', applicationId: 'separate-app', origin, buildLabel: 'baseline', contextId: 'synthetic-data', actors: { member: { principalId: 'member-one', credentialEnv: 'SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN' }, anonymous: { principalId: 'anonymous' } }, requiredControlIds: ['allowed'], checks: [
    { id: 'allowed', title: 'Permitted response', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/own', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/record', expected: true }] },
    { id: 'denied', title: 'Restricted response', category: 'Access', severity: 'high', actorId: 'anonymous', method: 'GET', path: '/foreign', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
  ] };
}
const manifest = target => ({ schemaVersion: 1, targets: [target] });
// Positive identity for the member (connector v2): a declared identityValue and a
// json.equals predicate on the 'allowed' control. Servers name the member only for
// the member's own credential and refuse anything else.
const MEMBER = 'member-one';
function proven(target) {
  target.actors.member.identityValue = MEMBER;
  target.checks = target.checks.map(check => check.id === 'allowed' ? { ...check, assertions: [...check.assertions, { kind: 'json.equals', pointer: '/user', expected: MEMBER }] } : check);
  return target;
}
const ownRecord = (req, res) => req.headers.authorization === 'Bearer synthetic-token' ? json(res, 200, { record: true, user: MEMBER }) : json(res, 401, {});

test('real 401, 403 and empty 204 responses are observed without treating HTTP denial as network failure', async t => {
  const origin = await server(t, (req, res) => { const status = Number(req.url.slice(1)); res.writeHead(status); res.end(status === 204 ? undefined : 'Denied'); });
  for (const status of [401, 403, 204]) {
    const result = await observeHttp(origin, httpCheck(`/${status}`));
    assert.equal(result.status, status); assert.equal(result.complete, true); assert.equal(result.jsonParsed, false); assert.equal(result.error, 'invalid-json');
  }
});

test('malformed JSON is a complete observation with parsing unavailable', async t => {
  const origin = await server(t, (_, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{malformed'); });
  const observation = await observeHttp(origin, httpCheck('/malformed'));
  assert.equal(observation.status, 200); assert.equal(observation.complete, true); assert.equal(observation.error, 'invalid-json'); assert.equal(observation.json, undefined);
});

test('redirect destination is never contacted', async t => {
  let destinationHits = 0;
  const destination = await server(t, (_, res) => { destinationHits++; json(res, 200, { secret: 'not-followed' }); });
  let sourceHits = 0;
  const origin = await server(t, (_, res) => { sourceHits++; res.writeHead(302, { Location: `${destination}/destination` }); res.end(); });
  const result = await observeHttp(origin, httpCheck('/redirect'));
  assert.equal(result.status, 302); assert.equal(result.complete, true); assert.equal(sourceHits, 1); assert.equal(destinationHits, 0);
});

test('oversized and truncated responses cannot become complete evidence', async t => {
  const origin = await server(t, (req, res) => {
    if (req.url === '/large') json(res, 200, { content: 'x'.repeat(300) });
    else { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '100' }); res.end('{"ok":true}'); }
  });
  const large = await observeHttp(origin, httpCheck('/large'), { maxResponseBytes: 32 });
  assert.equal(large.status, 200); assert.equal(large.complete, false); assert.equal(large.error, 'too-large'); assert.equal(large.json, undefined);
  const truncated = await observeHttp(origin, httpCheck('/truncated'), { timeoutMs: 100 });
  assert.equal(truncated.status, 200); assert.equal(truncated.complete, false); assert.equal(truncated.error, 'network'); assert.equal(truncated.json, undefined);
});

test('slow bodies time out and timed-out POST actions are attempted once without retry', async t => {
  let posts = 0;
  const origin = await server(t, (req, res) => {
    if (req.method === 'POST') posts++;
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{');
    const timer = setTimeout(() => res.end('"ok":true}'), 500); timer.unref();
  });
  const slow = await observeHttp(origin, httpCheck('/slow'), { timeoutMs: 100 });
  assert.equal(slow.status, 200); assert.equal(slow.complete, false); assert.equal(slow.error, 'timeout');
  const post = await observeHttp(origin, httpCheck('/mutate', 'POST', { request: 'synthetic' }), { timeoutMs: 100 });
  assert.equal(post.error, 'timeout'); assert.equal(posts, 1);
  const target = profile(origin); target.checks = [{ ...target.checks[0], method: 'POST', path: '/mutate', body: { request: 'synthetic' } }];
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' }, limits: { requestTimeoutMs: 100, runTimeoutMs: 1000, responseBytes: 1024 } });
  assert.equal(run.results[0].status, 'error'); assert.equal(posts, 2);
  assert.match(run.results[0].trace[0].data.mutationEffects, /timeout does not undo an action/);
});

test('invalid origins, destination overrides and CRLF credentials are rejected before sending', async t => {
  let hits = 0;
  const origin = await server(t, (_, res) => { hits++; json(res, 200, {}); });
  for (const invalid of ['http://localhost:4317', 'https://127.0.0.1:4317', 'http://127.0.0.1:0', `${origin}/path`, `${origin}?query=1`]) assert.throws(() => observeHttp(invalid, httpCheck('/')));
  for (const path of ['http://example.invalid/path', '//example.invalid/path', 'http://127.0.0.1:1/other', '/path#fragment']) assert.throws(() => observeHttp(origin, httpCheck(path)));
  for (const credential of ['token\r\nX-Injected: value', '', 'space token', 'é-token']) assert.throws(() => observeHttp(origin, httpCheck('/'), { credential }));
  assert.equal(hits, 0);
});

test('missing or invalid actor credentials stop the whole assessment before any request', async t => {
  let hits = 0;
  const origin = await server(t, (_, res) => { hits++; json(res, 200, { record: true }); });
  for (const env of [{}, { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: '' }, { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'sensitive\r\nvalue' }]) await assert.rejects(runHttpAssessment(profile(origin), { env }), error => /credentials are missing or invalid/.test(error.message) && !error.message.includes('sensitive'));
  assert.equal(hits, 0);
});

test('echoed credentials, PII, request bodies and expected predicate values never enter retained run or exports', async t => {
  const credential = 'synthetic-private-token-123', pii = 'synthetic-person@example.invalid', marker = 'private-expected-marker', requestSecret = 'synthetic-request-secret';
  let receivedAuthorization, receivedBody;
  const origin = await server(t, (req, res) => {
    receivedAuthorization = req.headers.authorization;
    let data = ''; req.on('data', chunk => { data += chunk; }); req.on('end', () => { receivedBody = data; json(res, 200, { record: true, authorization: req.headers.authorization, contact: pii, marker }); });
  });
  const target = profile(origin);
  target.checks = [{ ...target.checks[0], method: 'POST', body: { private: requestSecret }, assertions: [...target.checks[0].assertions, { kind: 'json.equals', pointer: '/marker', expected: marker }] }];
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: credential } });
  // No identity control proves this login, so the passing control is inconclusive (login not proven).
  assert.equal(run.results[0].status, 'inconclusive'); assert.equal(receivedAuthorization, `Bearer ${credential}`); assert.match(receivedBody, /synthetic-request-secret/);
  const dir = await directory(t); const store = createStore(dir); const saved = await store.save(run);
  for (const output of [JSON.stringify(run), JSON.stringify(run.results), JSON.stringify(saved), await readFile(join(dir, 'runs', `${run.id}.json`), 'utf8'), renderReport(saved), JSON.stringify(createRegistry({ profiles: [target], env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: credential } }).exportSuite(target.id))]) {
    for (const secret of [credential, pii, marker, requestSecret, 'SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN']) assert.equal(output.includes(secret), false, 'Retained evidence and exports must omit private values and environment references');
  }
});

test('backend-required checks stay inconclusive when all observed response predicates pass', async t => {
  const origin = await server(t, (_, res) => json(res, 200, { record: true }));
  const target = profile(origin); target.checks[1] = { ...target.checks[1], path: '/backend', evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 200 }] };
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' } });
  // No identity control proves this login, so the passing control is inconclusive (login not proven).
  assert.equal(run.results[0].status, 'inconclusive'); assert.equal(run.results[1].status, 'inconclusive'); assert.equal(run.results[1].backendEvidence, 'unavailable');
  assert.equal(run.counts.inconclusive, 2);
});

test('declared builds compare as response contracts while changed identity or config requires a fresh baseline', async t => {
  let repaired = false;
  const origin = await server(t, (req, res) => req.url === '/own' ? ownRecord(req, res) : json(res, req.url === '/foreign' && repaired ? 403 : 200, { record: true }));
  const target = proven(profile(origin)), env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' };
  const baseline = await runHttpAssessment(target, { env }); repaired = true;
  const candidate = await runHttpAssessment({ ...target, buildLabel: 'repaired', name: 'New display name' }, { env });
  assert.equal(baseline.counts.fail, 1); assert.equal(candidate.counts.pass, 2);
  assert.equal(baseline.profileHash, candidate.profileHash); assert.notEqual(baseline.targetConfigHash, candidate.targetConfigHash);
  const comparison = compareRuns(baseline, candidate);
  assert.equal(comparison.compatible, true); assert.equal(comparison.rows.find(row => row.id === 'denied').transition, 'contract-restored'); assert.match(comparison.evidenceScope, /backend effects remain unverified/);
  for (const mutate of [
    run => { run.adapterVersion = 'owned-loopback-http/1'; },
    run => { run.runtimeMode = 'deterministic-model-free'; },
    run => { run.assertionSchemaVersion = 'fixture-policy/1'; },
    run => { run.fixtureVersion = 'support-fixture/2'; },
    run => { run.targetBuildHash = 'a'.repeat(64); },
    run => { run.provenance = {}; },
    run => { run.results[0].attempts = []; },
    run => { run.results[0].trace[0].type = 'foreign-observation'; },
  ]) {
    const before = structuredClone(baseline), after = structuredClone(candidate); mutate(before); mutate(after);
    assert.equal(compareRuns(before, after).compatible, false);
    assert.equal(compareRuns(before, after).summary.fixed, 0);
  }
  for (const change of [{ contextId: 'other-context' }, { applicationId: 'other-app' }, { actors: { ...target.actors, member: { ...target.actors.member, credentialEnv: 'SCOPEHAVEN_TARGET_OTHER_TOKEN' } } }]) {
    const changed = await runHttpAssessment({ ...target, ...change }, { env: { ...env, SCOPEHAVEN_TARGET_OTHER_TOKEN: 'synthetic-token' } });
    assert.equal(compareRuns(baseline, changed).compatible, false);
  }
  const otherOrigin = await server(t, (_, res) => json(res, 200, { record: true }));
  const relocated = await runHttpAssessment({ ...target, origin: otherOrigin }, { env });
  assert.equal(compareRuns(baseline, relocated).compatible, false);
  const changedContract = structuredClone(target); changedContract.checks[1].path = '/different-path';
  const changedRun = await runHttpAssessment(changedContract, { env });
  assert.equal(compareRuns(baseline, changedRun).compatible, false);
});

test('profile loading rejects malformed, nonregular, symlink and oversized files; reserved IDs cannot collide', async t => {
  const dir = await directory(t), target = profile('http://127.0.0.1:5001');
  assert.deepEqual(await loadProfiles(undefined), []);
  const good = join(dir, 'good.json'); await writeFile(good, JSON.stringify(manifest(target)));
  assert.equal((await loadProfiles(good))[0].id, target.id);
  const malformed = join(dir, 'malformed.json'); await writeFile(malformed, '{"secret":"do-not-echo"');
  await assert.rejects(loadProfiles(malformed), error => /invalid JSON/.test(error.message) && !error.message.includes('do-not-echo'));
  const invalidSchema = join(dir, 'invalid-schema.json'); await writeFile(invalidSchema, JSON.stringify({ ...manifest(target), unknown: 'secret-value' }));
  await assert.rejects(loadProfiles(invalidSchema), error => /Invalid HTTP contract/.test(error.message) && !error.message.includes('secret-value'));
  const folder = join(dir, 'directory'); await mkdir(folder); await assert.rejects(loadProfiles(folder), /regular JSON file/);
  const linked = join(dir, 'linked.json'); await symlink(good, linked); await assert.rejects(loadProfiles(linked), /regular JSON file/);
  const oversized = join(dir, 'oversized.json'); await writeFile(oversized, `${JSON.stringify(manifest(target))}${' '.repeat(2097153)}`); await assert.rejects(loadProfiles(oversized), /2 MiB/);
  for (const id of ['demo-vulnerable', 'demo-repaired']) assert.throws(() => createRegistry({ profiles: [{ ...target, id }] }), /cannot replace a built-in demo identifier/);
});

test('readiness discloses missing reference names only and redacted suite omits endpoint and private configuration', () => {
  const target = profile('http://127.0.0.1:5001');
  target.checks[1].body = { private: 'private-body-marker' }; target.checks[1].method = 'POST';
  target.checks[1].assertions.push({ kind: 'json.equals', pointer: '/private-pointer-marker', expected: 'private-expected-marker' });
  assert.deepEqual(credentialReadiness(target, {}), { ready: false, missingCredentialRefs: ['SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN'] });
  const invalid = credentialReadiness(target, { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'private-value\r\n' });
  assert.equal(JSON.stringify(invalid).includes('private-value'), false);
  assert.deepEqual(credentialReadiness(target, { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'valid-private-value' }), { ready: true, missingCredentialRefs: [] });
  const registry = createRegistry({ profiles: [target], env: {} });
  const listed = registry.list().find(item => item.id === target.id); assert.equal(listed.available, false); assert.deepEqual(listed.missingCredentialRefs, ['SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN']);
  const output = JSON.stringify(registry.exportSuite(target.id));
  for (const secret of ['private-body-marker', 'private-expected-marker', 'private-pointer-marker', 'SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN', '127.0.0.1', 'member-one']) assert.equal(output.includes(secret), false);
  assert.match(output, /not an executable profile/);
});

test('cookie actors send only a named cookie, never Authorization, and the value stays out of evidence and exports', async t => {
  const credential = 'synthetic.cookie-value_123', received = [];
  const origin = await server(t, (req, res) => {
    received.push({ path: req.url, cookie: req.headers.cookie, authorization: req.headers.authorization });
    if (req.url === '/own') return req.headers.cookie === `authjs.session-token=${credential}` ? json(res, 200, { record: true, user: MEMBER }) : json(res, 401, {});
    if (req.url === '/own-list') return req.headers.cookie === `authjs.session-token=${credential}` ? json(res, 200, { items: [] }) : json(res, 401, {});
    json(res, 403, { record: true });
  });
  const target = proven(profile(origin)); target.actors.member.credentialCookie = 'authjs.session-token';
  target.checks[1] = { ...target.checks[1], actorId: 'member' };
  // actor-identity/4: the member's 403 counts as a refusal only after its earlier complete 2xx on a protected route (a surface control).
  target.checks.splice(1, 0, { id: 'own-list', title: 'Own list', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/own-list', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] });
  target.requiredControlIds = ['allowed', 'own-list'];
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: credential } });
  assert.deepEqual(run.results.map(r => r.status), ['pass', 'pass', 'pass']);
  // The control, then the identity and surface controls at each probe point around the member's other checks (actor-identity/5:
  // before own-list, after it, and after foreign), then one request without the cookie and one with an invalid cookie.
  const withCookie = path => ({ path, cookie: `authjs.session-token=${credential}`, authorization: undefined });
  assert.deepEqual(received.slice(0, 10), [withCookie('/own'), withCookie('/own'), withCookie('/own-list'), withCookie('/own-list'), withCookie('/own'), withCookie('/own-list'), withCookie('/foreign'), withCookie('/own'), withCookie('/own-list'), { path: '/own', cookie: undefined, authorization: undefined }]);
  // The invalid cookie is a per-run look-alike of the real one: same length, not equal, no fixed marker.
  const invalid = /^authjs\.session-token=(.+)$/.exec(received[10].cookie)?.[1];
  assert.equal(received.length, 11); assert.equal(invalid.length, credential.length); assert.notEqual(invalid, credential); assert.equal(received[10].authorization, undefined);
  assert.equal(JSON.stringify(run).includes(invalid), false, 'The invalid credential is never retained.');
  assert.deepEqual(run.identityEvidence.actors.map(a => [a.actorId, a.credentialMode, a.reason]), [['member', 'cookie', 'established']]);
  assert.equal(run.results[0].trace[0].data.credentialMode, 'cookie');
  const dir = await directory(t), saved = await createStore(dir).save(run);
  for (const output of [JSON.stringify(run), await readFile(join(dir, 'runs', `${run.id}.json`), 'utf8'), renderReport(saved), JSON.stringify(createRegistry({ profiles: [target], env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: credential } }).exportSuite(target.id))]) {
    assert.equal(output.includes(credential), false); assert.equal(output.includes('authjs.session-token'), false);
  }
});

test('cookie values that could add or split cookies are refused before any request', async t => {
  let hits = 0;
  const origin = await server(t, (_, res) => { hits++; json(res, 200, { record: true }); });
  const target = profile(origin); target.actors.member.credentialCookie = 'session';
  for (const value of ['a;admin=1', 'a,b', 'quoted"value', 'back\\slash', 'space value', 'tab\tvalue', 'é']) {
    assert.deepEqual(credentialReadiness(target, { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: value }), { ready: false, missingCredentialRefs: ['SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN'] });
    await assert.rejects(runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: value } }), error => /credentials are missing or invalid/.test(error.message) && !error.message.includes(value));
    assert.throws(() => observeHttp(origin, httpCheck('/own'), { credential: value, credentialCookie: 'session' }));
  }
  for (const name of ['a;b', 'a=b', '', 'é']) assert.throws(() => observeHttp(origin, httpCheck('/own'), { credential: 'ok', credentialCookie: name }));
  assert.throws(() => observeHttp(origin, httpCheck('/own'), { credentialCookie: 'session' }));
  assert.equal(hits, 0);
  // Bearer mode keeps its existing visible-ASCII rule, so a comma stays valid there.
  assert.equal(credentialReadiness(profile(origin), { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'a,b' }).ready, true);
});

test('a declared per-check timeout lets one slow model-turn endpoint finish while others keep the default limit', async t => {
  const origin = await server(t, (req, res) => {
    if (req.url === '/own') return ownRecord(req, res);
    const timer = setTimeout(() => json(res, 200, { record: true }), req.url === '/turn' || req.url === '/own-slow' ? 400 : 0); timer.unref();
  });
  const target = profile(origin);
  target.checks = [target.checks[0], { ...target.checks[0], id: 'model-turn', severity: 'high', path: '/turn', timeoutMs: 1000 }, { ...target.checks[0], id: 'undeclared-slow', severity: 'high', path: '/own-slow' }];
  proven(target);
  const limits = { requestTimeoutMs: 100, runTimeoutMs: 300, responseBytes: 1024 };
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' }, limits });
  assert.deepEqual(run.results.map(r => [r.id, r.status]), [['allowed', 'pass'], ['model-turn', 'pass'], ['undeclared-slow', 'error']]);
  assert.deepEqual(run.results.map(r => r.trace[0].data.requestTimeoutMs), [100, 1000, 100]);
  // Without the declaration the same endpoint times out at the default limit.
  delete target.checks[1].timeoutMs;
  assert.equal((await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' }, limits })).results[1].status, 'error');
});

test('a boundary check cannot pass when its actor\'s required control failed; failures and other actors are unaffected', async t => {
  // Shaped like the Vercel chatbot onboarding: the target ignored the member's
  // credential, so the "denial" only proves the member was treated as anonymous.
  let foreignStatus = 403;
  const origin = await server(t, (req, res) => json(res, req.url === '/own' ? 401 : req.url === '/foreign' ? foreignStatus : 401, { record: false }));
  const target = profile(origin);
  target.checks = [target.checks[0], { ...target.checks[1], id: 'member-denied', actorId: 'member' }, { ...target.checks[1], id: 'anonymous-denied', path: '/anon', assertions: [{ kind: 'status.equals', expected: 401 }] }];
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' };
  const run = await runHttpAssessment(target, { env });
  assert.deepEqual(run.results.map(r => [r.id, r.status]), [['allowed', 'fail'], ['member-denied', 'inconclusive'], ['anonymous-denied', 'pass']]);
  const downgraded = run.results[1];
  assert.deepEqual(downgraded.assertions.map(a => [a.name, a.status]), [['HTTP status matches contract', 'pass'], ['Actor identity established by required controls', 'inconclusive']]);
  // The third state's summary: identity or allowed use not established, whichever reason it carries.
  assert.match(downgraded.summary, /identity or allowed use not established/);
  assert.equal(run.counts.pass, 1); assert.equal(run.counts.inconclusive, 1);
  assert.equal(run.results[2].assertions.some(a => a.name.startsWith('Actor identity')), false);
  foreignStatus = 200; // A real exposure is still reported as a failure.
  const exposed = await runHttpAssessment(target, { env });
  assert.equal(exposed.results[1].status, 'fail');
  assert.equal(exposed.results[1].assertions.at(-1).name, 'Actor identity established by required controls');
});

const IDENTITY = 'Actor identity established by required controls';
// Rebuild a run as connector v1 (Scopehaven 0.6.0) recorded
// it: v1 versions and evaluator, schema-2 suite/profile hashes, no v2 evidence fields.
function asV1(run, target) {
  const [p] = validateTargetFile(manifest(target)), v1 = structuredClone(run);
  const actors = Object.fromEntries(Object.entries(p.actors).map(([alias, actor]) => [alias, Object.fromEntries(['principalId', 'tenantId', 'role', 'credentialEnv'].filter(key => Object.hasOwn(actor, key)).map(key => [key, actor[key]]))]));
  const profileHash = digest({ schemaVersion: 1, assertionSchemaVersion: 'http-contract/2', id: p.id, applicationId: p.applicationId, contextId: p.contextId, origin: p.origin, actors, checks: p.checks, requiredControlIds: p.requiredControlIds });
  const suiteHash = digest({ checks: p.checks, requiredControlIds: p.requiredControlIds, schema: 'http-contract/2' });
  delete v1.identityEvidence; delete v1.targetContext; delete v1.targetLabel; delete v1.principals; // v1 runs predate the v3 target context and the actor-identity/5 fields
  Object.assign(v1, { adapterVersion: 'loopback-response-contract/1', assertionSchemaVersion: 'http-contract/2', evaluatorHash: 'bb0d3bbc4ec43dc8af69e4fa74152ff401dcd0a69e92e801c3bc58178871d69e', profileHash, suiteHash, policyHash: suiteHash, targetConfigHash: digest({ profileHash, buildLabel: p.buildLabel }) });
  for (const row of v1.results) {
    delete row.decision; // actor-identity/5: a per-row decision is a v2+ field
    if (row.trace[0].type !== 'http-observation') continue;
    row.assertions = row.assertions.filter(a => a.name !== IDENTITY);
    if (row.status === 'inconclusive' && row.assertions.every(a => a.status === 'pass')) row.status = 'pass';
    delete row.trace[0].data.credentialMode; delete row.trace[0].data.requestTimeoutMs;
    delete row.trace[0].data.routeSegments; delete row.trace[0].data.controlScope; // actor-identity/6 fields
    row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions });
  }
  v1.counts = Object.fromEntries(['pass', 'fail', 'inconclusive', 'error', 'not_applicable'].map(status => [status, v1.results.filter(row => row.status === status).length]));
  return v1;
}

test('previous-version runs still compare with each other, but never as fixed against the current version', async t => {
  let repaired = false;
  const origin = await server(t, (req, res) => req.url === '/own' ? ownRecord(req, res) : json(res, req.url === '/foreign' && repaired ? 403 : 200, { record: true }));
  const target = proven(profile(origin)), env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' };
  const current = await runHttpAssessment(target, { env });
  assert.equal(current.adapterVersion, 'loopback-response-contract/3'); assert.equal(current.assertionSchemaVersion, 'http-contract/4');
  repaired = true;
  const candidate = await runHttpAssessment({ ...target, buildLabel: 'repaired' }, { env });
  assert.equal(current.results[1].status, 'fail'); assert.equal(candidate.results[1].status, 'pass');
  assert.equal(compareRuns(current, candidate).summary.fixed, 1, 'Same-version runs compare normally.');
  const v1Baseline = asV1(current, target), v1Candidate = asV1(candidate, { ...target, buildLabel: 'repaired' });
  const v1Pair = compareRuns(v1Baseline, v1Candidate);
  assert.equal(v1Pair.compatible, true, v1Pair.reasons.join(' ')); assert.equal(v1Pair.summary.fixed, 1);
  assert.equal(v1Pair.rows.find(row => row.id === 'denied').transition, 'contract-restored');
  for (const [before, after] of [[v1Baseline, candidate], [candidate, v1Baseline], [current, v1Candidate]]) {
    const comparison = compareRuns(before, after);
    assert.equal(comparison.compatible, false); assert.equal(comparison.summary.fixed, 0);
    assert.ok(comparison.rows.every(row => row.transition === 'incompatible'));
    for (const key of ['adapterVersion', 'assertionSchemaVersion', 'evaluatorHash', 'suiteHash', 'policyHash', 'profileHash']) assert.ok(comparison.reasons.includes(`${key} differs or is missing.`), key);
  }
  // A run claiming a mix of versions belongs to no family.
  for (const mix of [{ adapterVersion: 'loopback-response-contract/2' }, { assertionSchemaVersion: 'http-contract/3' }]) {
    const mixed = { ...structuredClone(v1Baseline), ...mix }, other = { ...structuredClone(v1Candidate), ...mix };
    assert.equal(compareRuns(mixed, other).compatible, false);
  }
});

test('a credentialed actor without a required control can never pass: an expired session redirected to sign-in is not "restored"', async t => {
  // The auditor's session expires, the app redirects it to sign-in,
  // and a refusal set that includes 302 would otherwise read as a repair.
  let expired = false;
  const origin = await server(t, (req, res) => {
    if (req.url === '/own') return json(res, 200, { record: true });
    if (req.url === '/audit') { if (expired) { res.writeHead(302, { Location: '/sign-in' }); return res.end(); } return json(res, 200, { record: 'exposed' }); }
    json(res, 403, {});
  });
  const target = profile(origin);
  target.actors.auditor = { principalId: 'auditor-one', credentialEnv: 'SCOPEHAVEN_TARGET_AUDITOR_TOKEN', credentialCookie: 'session' };
  target.checks.push({ id: 'auditor-denied', title: 'Auditor refused', category: 'Access', severity: 'high', actorId: 'auditor', method: 'GET', path: '/audit', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [302, 403] }] });
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'member-token', SCOPEHAVEN_TARGET_AUDITOR_TOKEN: 'auditor-token' };
  const before = await runHttpAssessment(target, { env }); expired = true;
  const after = await runHttpAssessment(target, { env });
  const row = run => run.results.find(r => r.id === 'auditor-denied');
  assert.equal(row(before).status, 'fail'); assert.equal(row(after).status, 'inconclusive');
  assert.deepEqual(row(after).assertions.map(a => [a.name, a.status]), [['HTTP status matches contract', 'pass'], [IDENTITY, 'inconclusive']]);
  assert.equal(after.results.find(r => r.id === 'denied').status, 'pass', 'An anonymous actor has no identity to establish.');
  const comparison = compareRuns(before, after);
  assert.equal(comparison.summary.fixed, 0); assert.notEqual(comparison.rows.find(r => r.id === 'auditor-denied').transition, 'contract-restored');
});

test('identity is established only when every required control of the actor passes; errors and not-applicable rows are untouched', async t => {
  let mode = 'timeout';
  const origin = await server(t, (req, res) => {
    if (['/own', '/second'].includes(req.url) && req.headers.authorization !== 'Bearer synthetic-token') return json(res, 401, {});
    if (req.url === '/own') {
      if (mode === 'timeout') { const timer = setTimeout(() => json(res, 200, { record: true, user: MEMBER }), 400); timer.unref(); return; }
      if (mode === 'non-json') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<html>sign in</html>'); }
      return json(res, 200, { record: true, user: MEMBER });
    }
    if (req.url === '/second') return json(res, mode === 'two-controls' ? 401 : 200, { record: true });
    if (req.url === '/slow-boundary') { const timer = setTimeout(() => json(res, 403, {}), 400); timer.unref(); return; }
    json(res, 403, {});
  });
  const target = profile(origin);
  target.checks = [target.checks[0],
    { ...target.checks[0], id: 'second-control', path: '/second' },
    { id: 'member-denied', title: 'Member refused', category: 'Access', severity: 'high', actorId: 'member', method: 'GET', path: '/foreign', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
    { id: 'member-slow', title: 'Member refused slowly', category: 'Access', severity: 'high', actorId: 'member', method: 'GET', path: '/slow-boundary', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
    { id: 'member-excluded', title: 'Member capability absent', category: 'Access', severity: 'high', actorId: 'member', method: 'GET', path: '/absent', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], applicability: { applies: false, reason: 'Not in this build.' } }];
  target.requiredControlIds = ['allowed', 'second-control']; proven(target);
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' }, limits = { requestTimeoutMs: 150, runTimeoutMs: 5000, responseBytes: 1024 };
  // actor-identity/4: 'second-control' is a surface control (a required GET on a protected route), re-sent in the brackets.
  // In 'two-controls' the protected route refuses the credential (401) that the identity route accepts, so the login is
  // not proven at every probe point (surface-refused) and the actor is not established. Under actor-identity/5 a refused
  // surface probe is route-level (the surface-refusal rule): it withholds every row of the actor, the identity control
  // that passed included, as under actor-identity/4.
  for (const [current, control] of [['timeout', 'error'], ['non-json', 'inconclusive'], ['two-controls', 'inconclusive']]) {
    mode = current;
    const run = await runHttpAssessment(target, { env, limits }), by = id => run.results.find(r => r.id === id);
    assert.equal(by('allowed').status, control, current);
    if (current === 'two-controls') assert.equal(by('second-control').status, 'fail');
    if (current === 'two-controls') assert.match(by('allowed').assertions.at(-1).actual, /^A surface control .* was refused/, 'the identity control is withheld by the refusal');
    assert.equal(by('member-denied').status, 'inconclusive', current); assert.equal(by('member-denied').assertions.at(-1).name, IDENTITY);
    assert.equal(by('member-slow').status, 'error', current); assert.equal(by('member-slow').assertions.at(-1).name, IDENTITY);
    assert.equal(by('member-excluded').status, 'not_applicable'); assert.equal(by('member-excluded').assertions.some(a => a.name === IDENTITY), false);
  }
  mode = 'established';
  const clean = await runHttpAssessment(target, { env, limits });
  assert.equal(clean.results.find(r => r.id === 'member-denied').status, 'pass');
  assert.ok(clean.results.every(r => !r.assertions.some(a => a.name === IDENTITY)));
});

test('evidence records the timeout actually applied, which the shared run budget can shorten', async () => {
  const applied = [];
  const transport = async (_, check, options) => { applied.push(options.timeoutMs); if (check.path === '/first') await new Promise(resolve => setTimeout(resolve, 300)); return { status: 200, complete: true, jsonParsed: true, json: { record: true }, bytes: 15 }; };
  const target = profile('http://127.0.0.1:5001');
  target.checks = [{ ...target.checks[0], path: '/first' }, { ...target.checks[0], id: 'model-turn', severity: 'high', path: '/turn', timeoutMs: 1000 }];
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' }, transport, limits: { requestTimeoutMs: 100, runTimeoutMs: 350, responseBytes: 1024 } });
  const recorded = run.results.map(r => r.trace[0].data.requestTimeoutMs);
  assert.deepEqual(recorded, applied.slice(0, recorded.length), 'Identity proof requests follow the rows.');
  assert.equal(recorded[0], 100); assert.ok(recorded[1] < 1000 && recorded[1] > 0, `applied ${recorded[1]} ms`);
});

test('cookie values keep = / + % unchanged; evidence names the credential mode for every actor', async t => {
  const value = 'a=b/c+d%3D', received = [];
  const origin = await server(t, (req, res) => { received.push(req.headers.cookie); json(res, req.url === '/own' ? 200 : 403, { record: true }); });
  const cookie = profile(origin); cookie.actors.member.credentialCookie = 'sid';
  const run = await runHttpAssessment(cookie, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: value } });
  // No identity control proves this login, so the passing control is inconclusive (login not proven).
  assert.equal(run.results[0].status, 'inconclusive'); assert.equal(received[0], `sid=${value}`);
  assert.equal(JSON.stringify(run).includes(value), false);
  const bearer = await runHttpAssessment(profile(origin), { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' } });
  assert.deepEqual(bearer.results.map(r => [r.actorId ?? r.trace[0].data.actorId, r.trace[0].data.credentialMode]), [['member', 'bearer'], ['anonymous', 'none']]);
});

test('the owned lab accepts its lab_session cookie exactly like its Bearer token, and nothing else', async t => {
  const lab = await createHttpLab({ build: 'repaired' }); t.after(() => lab.close());
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken };
  const bearer = await runHttpAssessment(makeLabProfile(lab.origin), { env });
  const cookieProfile = makeLabProfile(lab.origin); cookieProfile.actors.member.credentialCookie = 'lab_session';
  const cookie = await runHttpAssessment(cookieProfile, { env });
  assert.deepEqual(cookie.results.map(r => [r.id, r.status]), bearer.results.map(r => [r.id, r.status]));
  assert.equal(cookie.results.find(r => r.id === 'WHOAMI').status, 'pass');
  const wrong = await runHttpAssessment(cookieProfile, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'not-the-lab-token' } });
  assert.equal(wrong.results.find(r => r.id === 'WHOAMI').trace[0].data.httpStatus, 401);
  const status = async cookieHeader => (await fetch(`${lab.origin}/me`, { headers: { Cookie: cookieHeader } })).status;
  assert.equal(await status('x=1; lab_session=bad'), 401);
  assert.equal(await status(`lab_session=${lab.memberToken}x`), 401);
  assert.equal(await status(`x=1; lab_session=${lab.memberToken}`), 200);
});

// Identity proof. A shared Auth.js-like app: /ping is public, /api/auth/session
// answers 200 with JSON null when signed out, /records/foreign redirects signed-out
// users to sign-in. `session.alive` lets a test kill or expire the member's login.
async function sessionApp(t, session) {
  const token = 'synthetic-session';
  return server(t, (req, res) => {
    const signedIn = session.alive && req.headers.cookie === `sid=${token}`;
    session.requests.push({ path: req.url, signedIn, credential: req.headers.cookie !== undefined });
    if (req.url === '/ping') return json(res, 200, { ok: true });
    if (req.url === '/api/auth/session') { const body = signedIn ? { user: { email: 'member@example.test' } } : null; if (signedIn && session.expireAfterControl) session.alive = false; return json(res, 200, body); }
    if (req.url === '/records/foreign') { if (!signedIn) { res.writeHead(302, { Location: '/sign-in' }); return res.end(); } return json(res, session.exposed ? 200 : 403, {}); }
    if (req.url === '/records/own') { if (!signedIn) { res.writeHead(302, { Location: '/sign-in' }); return res.end(); } return json(res, 200, { items: [] }); }
    json(res, 404, {});
  });
}
// surface: the member's surface control, a required GET on a protected route (actor-identity/4), so its refusal counts.
const ownRecords = { id: 'member-own', title: 'Member lists own records', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/records/own', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] };
function sessionProfile(origin, controlAssertions, controlPath = '/api/auth/session', { surface = false } = {}) {
  return { id: 'session-app', name: 'Session app', applicationId: 'session-app', origin, buildLabel: 'b', contextId: 'synthetic', actors: { member: { principalId: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_SESSION', credentialCookie: 'sid', identityValue: 'member@example.test' } }, requiredControlIds: ['whoami', ...(surface ? ['member-own'] : [])], checks: [
    { id: 'whoami', title: 'Member session', category: 'Identity', severity: 'control', actorId: 'member', method: 'GET', path: controlPath, evidenceRequirement: 'response', assertions: controlAssertions },
    ...(surface ? [ownRecords] : []),
    { id: 'member-denied', title: 'Member refused a foreign record', category: 'Access', severity: 'high', actorId: 'member', method: 'GET', path: '/records/foreign', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [302, 403] }] }] };
}
const sessionEnv = { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session' };
const statusOnly = [{ kind: 'status.equals', expected: 200 }];
const identifying = [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user/email', expected: 'member@example.test' }];

test('a status-only control on a public route proves no login; no "restored" label', async t => {
  const session = { alive: true, exposed: true, requests: [] }, origin = await sessionApp(t, session), target = sessionProfile(origin, statusOnly, '/ping');
  const before = await runHttpAssessment(target, { env: sessionEnv });
  session.alive = false; session.exposed = false;
  const after = await runHttpAssessment(target, { env: sessionEnv });
  assert.equal(before.results[1].status, 'fail', 'A real exposure still fails.');
  assert.equal(after.results[0].status, 'inconclusive', 'The status-only control answered 200, but no login was proven.'); assert.equal(after.results[1].trace[0].data.httpStatus, 302);
  assert.equal(after.results[1].status, 'inconclusive'); assert.match(after.results[1].assertions.at(-1).actual, /no required GET control that returns its declared identity/);
  assert.equal(after.identityEvidence.actors[0].reason, 'no-identity-control');
  const comparison = compareRuns(before, after);
  assert.equal(comparison.summary.fixed, 0); assert.notEqual(comparison.rows[1].transition, 'contract-restored'); assert.equal(comparison.controlsPass, false);
});

test('an Auth.js-style session route answering 200 null when signed out establishes only through its identity predicate', async t => {
  const session = { alive: false, exposed: false, requests: [] }, origin = await sessionApp(t, session);
  const loose = await runHttpAssessment(sessionProfile(origin, statusOnly), { env: sessionEnv });
  assert.deepEqual(loose.results.map(r => r.status), ['inconclusive', 'inconclusive'], 'Expired cookie: neither the status-only control nor the 302 boundary can pass.');
  assert.equal(loose.identityEvidence.actors[0].reason, 'no-identity-control');
  const strict = await runHttpAssessment(sessionProfile(origin, identifying), { env: sessionEnv });
  assert.deepEqual(strict.results.map(r => r.status), ['fail', 'inconclusive']); assert.equal(strict.identityEvidence.actors[0].reason, 'identity-control-not-passed');
  session.alive = true;
  // With a surface control (actor-identity/4), so the member's 403 counts as a refusal.
  const valid = await runHttpAssessment(sessionProfile(origin, identifying, undefined, { surface: true }), { env: sessionEnv });
  assert.deepEqual(valid.results.map(r => r.status), ['pass', 'pass', 'pass']);
  const entry = valid.identityEvidence.actors[0];
  assert.equal(entry.reason, 'established'); assert.deepEqual(entry.identityControlIds, ['whoami']); assert.deepEqual(entry.surfaceControlIds, ['member-own']);
  assert.deepEqual([...entry.before, ...entry.after].map(o => o.outcome), ['pass', 'pass', 'pass', 'pass']);
  assert.deepEqual(entry.anonymous.map(o => [o.httpStatus, o.predicates.find(p => p.identity).outcome]), [[200, 'fail']], 'Signed out, the same route answers 200 null, which does not name the member: a refusal.');
});

test('the identity control brackets the actor\'s other checks, so expiry after the control or a login not yet valid before the boundary never passes', async t => {
  const session = { alive: true, exposed: true, requests: [] }, origin = await sessionApp(t, session), target = sessionProfile(origin, identifying);
  const before = await runHttpAssessment(target, { env: sessionEnv });
  assert.deepEqual(before.results.map(r => r.status), ['pass', 'fail']);
  Object.assign(session, { alive: true, exposed: false, expireAfterControl: true, requests: [] });
  const after = await runHttpAssessment(target, { env: sessionEnv });
  assert.deepEqual(session.requests.map(r => [r.path, r.signedIn]), [['/api/auth/session', true], ['/api/auth/session', false], ['/records/foreign', false], ['/api/auth/session', false], ['/api/auth/session', false], ['/api/auth/session', false]]);
  // actor-identity/5: the boundary's opening point did not pass, so it never passes. Re-pinned for the other-principal
  // rule: the expired session's identity probes answer 200 null, a complete 2xx that names no one, which identityRefused counts as
  // a refusal; a refused identity probe withholds every row of the actor, so the control's own row is now inconclusive too (it kept
  // its pass on the route proof while only refusal statuses counted).
  assert.deepEqual(after.results.map(r => r.status), ['inconclusive', 'inconclusive']); assert.equal(after.identityEvidence.actors[0].reason, 'bracket-not-passed');
  const comparison = compareRuns(before, after);
  assert.equal(comparison.summary.fixed, 0); assert.notEqual(comparison.rows[1].transition, 'contract-restored');
  // The boundary is declared before the control and runs while the login is not yet valid.
  const reordered = sessionProfile(origin, identifying); reordered.checks.reverse();
  let requests = 0; const late = await server(t, (req, res) => {
    const signedIn = ++requests > 2 && req.headers.cookie === 'sid=synthetic-session';
    if (req.url === '/api/auth/session') return json(res, 200, signedIn ? { user: { email: 'member@example.test' } } : null);
    if (!signedIn) { res.writeHead(302, { Location: '/sign-in' }); return res.end(); }
    json(res, 403, {});
  });
  const early = await runHttpAssessment({ ...reordered, origin: late }, { env: sessionEnv });
  // actor-identity/5: the boundary's own opening point did not pass. Re-pinned for the other-principal rule: that point's identity probe, sent
  // before the login is valid, answers 200 null, which identityRefused counts as a refusal, so the control's row is withheld as well
  // (it kept its pass on the route proof while only refusal statuses counted).
  assert.deepEqual(early.results.map(r => [r.id, r.status]), [['member-denied', 'inconclusive'], ['whoami', 'inconclusive']]);
  assert.equal(early.identityEvidence.actors[0].reason, 'bracket-not-passed');
});

test('identity proof re-sends only GET identity controls: a POST-only identity control is never repeated and cannot establish the actor', async t => {
  let posts = 0;
  const origin = await server(t, (req, res) => { if (req.method === 'POST') posts++; json(res, req.url === '/foreign' ? 403 : 200, { record: true, user: MEMBER }); });
  const target = proven(profile(origin));
  target.checks = [{ ...target.checks[0], method: 'POST', body: { probe: 'synthetic' } }, { ...target.checks[1], actorId: 'member' }];
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' } });
  assert.equal(posts, 1); assert.deepEqual(run.results.map(r => r.status), ['inconclusive', 'inconclusive']);
  assert.deepEqual(run.identityEvidence.actors.map(a => [a.reason, a.before.length, a.after.length, a.anonymous.length]), [['no-identity-control', 0, 0, 0]]);
});

test('controls of credentialed actors must expect 2xx, and the dashboard waits for the largest valid run budget', async () => {
  const target = profile('http://127.0.0.1:5001');
  for (const expected of [302, 401, 404]) { const bad = structuredClone(target); bad.checks[0].assertions[0].expected = expected; assert.throws(() => validateTargetFile(manifest(bad)), /credentialed actor need a 2xx status\.equals/); }
  const anonymousControl = structuredClone(target); anonymousControl.checks.push({ ...target.checks[1], id: 'anon-control', severity: 'control', assertions: [{ kind: 'status.equals', expected: 401 }] });
  assert.doesNotThrow(() => validateTargetFile(manifest(anonymousControl)), 'An uncredentialed actor may expect a refusal.');
  const host = await readFile(new URL('../public/workbench-host.js', import.meta.url), 'utf8');
  const [, sum] = /ASSESSMENT_TIMEOUT_MS = ([0-9 +]+);/.exec(host);
  const assessmentTimeout = sum.split('+').reduce((total, part) => total + Number(part.trim()), 0);
  // The largest declared run budget (src/http-timing.mjs) plus 60 s for observer collections in progress, which also
  // covers the largest budget a profile without timing can reach (60 s, its per-check timeouts and its barriers).
  assert.equal(assessmentTimeout, TIMING_BOUNDS.runBudgetMs[1] + 60000 + 5000);
  assert.ok(assessmentTimeout > HTTP_LIMITS.runTimeoutMs + CHECK_TIMEOUT_BOUNDS.profileTotalMs + PER_CHECK_BARRIER_LIMIT_MS);
  assert.match(host, /url\.pathname === '\/api\/runs' \? ASSESSMENT_TIMEOUT_MS/);
});

// Positive identity, refusal semantics and the exported suite shape.
function authApp(t, { anonymousStatus = 401, anonymousBody, presenceOnly = false } = {}) {
  const state = { valid: true };
  return server(t, (req, res) => {
    const cookie = req.headers.cookie, credentialed = cookie !== undefined, valid = state.valid && cookie === 'sid=synthetic-session';
    if (req.url === '/api/auth/session') {
      if (!credentialed) {
        if (anonymousBody === 'html') { res.writeHead(anonymousStatus, { 'Content-Type': 'text/html' }); return res.end('<html>sign in</html>'); }
        if (anonymousBody === 'truncated') { res.writeHead(anonymousStatus, { 'Content-Type': 'application/json', 'Content-Length': '100' }); return res.end('{"user":'); }
        if (anonymousStatus >= 300 && anonymousStatus < 400) { res.writeHead(anonymousStatus, { Location: '/sign-in' }); return res.end(); }
        return json(res, anonymousStatus, anonymousBody === undefined ? null : anonymousBody);
      }
      return json(res, 200, valid ? { user: { email: 'member@example.test', admin: true } } : null);
    }
    // Presence-only middleware: any cookie is treated as signed in.
    if (req.url === '/records/foreign') return presenceOnly && credentialed ? json(res, 403, {}) : valid ? json(res, 403, {}) : (res.writeHead(302, { Location: '/sign-in' }), res.end());
    if (req.url === '/records/own') return presenceOnly && credentialed ? json(res, 200, { items: [] }) : valid ? json(res, 200, { items: [] }) : (res.writeHead(302, { Location: '/sign-in' }), res.end());
    json(res, 404, {});
  }).then(origin => ({ origin, state }));
}

test('refusal semantics: only 401, 403, a declared sign-in redirect or a 2xx JSON response that does not name the actor count as refused', async t => {
  const cases = [
    [{ anonymousStatus: 401 }, 'established'], [{ anonymousStatus: 403 }, 'established'], [{ anonymousStatus: 200, anonymousBody: null }, 'established'],
    [{ anonymousStatus: 200, anonymousBody: { user: { email: 'someone-else@example.test' } } }, 'established'],
    [{ anonymousStatus: 500 }, 'not-refused-without-credential'], [{ anonymousStatus: 503 }, 'not-refused-without-credential'], [{ anonymousStatus: 429 }, 'not-refused-without-credential'],
    [{ anonymousStatus: 404 }, 'not-refused-without-credential'], [{ anonymousStatus: 307 }, 'not-refused-without-credential'],
    [{ anonymousStatus: 200, anonymousBody: 'html' }, 'not-refused-without-credential'], [{ anonymousStatus: 200, anonymousBody: 'truncated' }, 'identity-probe-incomplete'],
  ];
  for (const [options, reason] of cases) {
    const { origin } = await authApp(t, options);
    const run = await runHttpAssessment(sessionProfile(origin, identifying, undefined, { surface: true }), { env: sessionEnv });
    assert.equal(run.identityEvidence.actors[0].reason, reason, JSON.stringify(options));
    assert.equal(run.results.find(r => r.id === 'member-denied').status, reason === 'established' ? 'pass' : 'inconclusive', JSON.stringify(options));
  }
  const { origin } = await authApp(t, { anonymousStatus: 307 }), declared = sessionProfile(origin, identifying);
  declared.actors.member.signInRedirectStatus = 307;
  const run = await runHttpAssessment(declared, { env: sessionEnv });
  assert.equal(run.identityEvidence.actors[0].reason, 'established'); assert.deepEqual(run.identityEvidence.actors[0].refusalStatuses, [401, 403, 307]);
});

test('presence-only middleware lets an expired cookie through, but the identity control fails, so the boundary cannot pass', async t => {
  const { origin, state } = await authApp(t, { presenceOnly: true });
  const target = sessionProfile(origin, identifying, undefined, { surface: true });
  assert.deepEqual((await runHttpAssessment(target, { env: sessionEnv })).results.map(r => r.status), ['pass', 'pass', 'pass']);
  state.valid = false;
  const expired = await runHttpAssessment(target, { env: sessionEnv });
  assert.equal(expired.results[2].trace[0].data.httpStatus, 403, 'The middleware still refused the foreign record...');
  assert.deepEqual(expired.results.map(r => r.status), ['fail', 'inconclusive', 'inconclusive'], '...but only because any cookie looks signed in, so it proves nothing.');
  assert.equal(expired.identityEvidence.actors[0].reason, 'identity-control-not-passed');
});

test('a control-only actor and non-required controls cannot be restored on an unproven login', async t => {
  // A negative predicate ("not an admin") on Auth.js /api/auth/session flips from fail to pass when the session expires (200 null).
  const { origin, state } = await authApp(t);
  const notAdmin = { id: 'not-admin', title: 'Member is not an admin', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/api/auth/session', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/user/admin', expected: false }] };
  for (const required of [true, false]) {
    const target = sessionProfile(origin, identifying);
    target.checks = [target.checks[0], notAdmin]; if (required) target.requiredControlIds = ['whoami', 'not-admin'];
    state.valid = true;
    const before = await runHttpAssessment(target, { env: sessionEnv });
    state.valid = false;
    const after = await runHttpAssessment(target, { env: sessionEnv });
    const row = run => run.results.find(r => r.id === 'not-admin');
    assert.equal(row(before).status, 'fail', `required=${required}`);
    assert.equal(after.identityEvidence.actors[0].established, false);
    assert.equal(row(after).status, 'inconclusive', `required=${required}: with the login unproven, a passing control is inconclusive whether or not it is required`);
    const comparison = compareRuns(before, after);
    assert.equal(comparison.summary.fixed, 0); assert.ok(!['contract-restored', 'fixed'].includes(comparison.rows.find(r => r.id === 'not-admin').transition));
    assert.equal(comparison.controlsPass, false);
  }
});

test('a required control of an unproven actor never gets a restored or fixed transition, even when every row passes', async t => {
  const { origin } = await authApp(t, { anonymousStatus: 500 });
  const target = sessionProfile(origin, identifying);
  const passing = await runHttpAssessment(target, { env: sessionEnv });
  assert.deepEqual(passing.results.map(r => r.status), ['inconclusive', 'inconclusive']); assert.equal(passing.identityEvidence.actors[0].reason, 'not-refused-without-credential');
  const failing = structuredClone(passing); failing.id = 'synthetic-failing'; failing.results[0].status = 'fail';
  const comparison = compareRuns(failing, passing);
  assert.notEqual(comparison.rows[0].transition, 'contract-restored'); assert.equal(comparison.summary.fixed, 0); assert.equal(comparison.controlsPass, false);
  assert.match(comparison.reasons.join(' '), /proven login/);
});

test('exported HTTP suites name each check\'s actor alias and credential mode, never credential references; other suites are unchanged', async () => {
  const target = profile('http://127.0.0.1:5001'); target.actors.member.credentialCookie = 'authjs.session-token'; target.actors.member.identityValue = 'private-identity@example.test';
  const registry = createRegistry({ profiles: [target], env: {} }), exported = registry.exportSuite(target.id);
  assert.deepEqual(exported.checks.map(c => [c.id, c.actorId, c.credentialMode]), [['allowed', 'member', 'cookie'], ['denied', 'anonymous', 'none']]);
  const text = JSON.stringify(exported);
  for (const secret of ['SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN', 'authjs.session-token', 'private-identity@example.test', 'member-one', '127.0.0.1']) assert.equal(text.includes(secret), false, secret);
  const { SUITE } = await import('../src/suite.mjs');
  assert.equal(JSON.stringify(registry.exportSuite('demo-vulnerable')), JSON.stringify({ ...SUITE, scope: 'Owned fixture, deterministic policies; not a general customer connector.', runnableWith: './scopehaven assess --target demo-repaired' }));
});

// Baseline identity, bracketing every other check, credential binding probes,
// declared sign-in redirects, POST once, suite binding.
function sessionServer(t, state) {
  // /api/auth/session: names the member only for the valid, unexpired cookie; 200 null otherwise.
  // /records/foreign: 403 for the signed-in member, 302 to sign-in otherwise.
  // /api/users/member: a lookup route (state.lookup: 'presence' accepts any cookie, 'any-login' any valid cookie).
  return server(t, (req, res) => {
    const cookie = req.headers.cookie, valid = id => state.alive && cookie === `sid=${id}`;
    const member = valid('member-session'), other = valid('other-session');
    state.requests.push({ path: req.url, method: req.method, member });
    if (req.url === '/api/auth/session') {
      if (cookie === undefined && state.anonymousDelayMs) { const timer = setTimeout(() => json(res, 200, null), state.anonymousDelayMs); timer.unref(); return; }
      const body = member || (cookie === undefined && state.anonymousNamesMember) ? { user: { email: 'member@example.test', admin: state.admin ?? false } } : other ? { user: { email: 'other@example.test' } } : null;
      if (member && state.expireAfterSession) state.alive = false; return json(res, 200, body);
    }
    if (req.url === '/api/users/member') { const allowed = state.lookup === 'presence' ? cookie !== undefined : member || other; return allowed ? json(res, 200, { user: { email: 'member@example.test' } }) : json(res, 401, {}); }
    if (req.url === '/history') return json(res, state.historyStatus ?? 200, { items: [] });
    if (req.url === '/records/own') { if (!member && !other) { res.writeHead(state.redirect ?? 302, { Location: '/sign-in' }); return res.end(); } return json(res, 200, { items: [] }); }
    if (req.url === '/records/foreign') {
      if (req.method === 'POST') state.posts = (state.posts || 0) + 1;
      if (!member && !other) { res.writeHead(state.redirect ?? 302, { Location: '/sign-in' }); return res.end(); }
      if (state.expireAfterForeign) state.alive = false;
      return json(res, state.exposed ? 200 : 403, {});
    }
    json(res, 404, {});
  });
}
const memberSessionEnv = { SCOPEHAVEN_TARGET_MEMBER: 'member-session', SCOPEHAVEN_TARGET_OTHER: 'other-session' };
// surface: add the member's surface control (a required GET on a protected route), so its refusal counts (actor-identity/4).
function memberProfile(origin, { controls, boundary = [403], other = false, surface = false } = {}) {
  const actors = { member: { principalId: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', credentialCookie: 'sid', identityValue: 'member@example.test' } };
  if (other) actors.other = { principalId: 'other', credentialEnv: 'SCOPEHAVEN_TARGET_OTHER', credentialCookie: 'sid', identityValue: 'other@example.test' };
  const whoami = { id: 'whoami', title: 'Member session', category: 'Identity', severity: 'control', actorId: 'member', method: 'GET', path: '/api/auth/session', evidenceRequirement: 'response', assertions: identifying };
  const checks = [...(controls || [whoami]), ...(surface ? [ownRecords] : []), { id: 'member-denied', title: 'Member refused a foreign record', category: 'Access', severity: 'high', actorId: 'member', method: 'GET', path: '/records/foreign', evidenceRequirement: 'response', assertions: [boundary.length === 1 ? { kind: 'status.equals', expected: boundary[0] } : { kind: 'status.in', expected: boundary }] }];
  if (other) checks.push({ id: 'other-whoami', title: 'Other session', category: 'Identity', severity: 'control', actorId: 'other', method: 'GET', path: '/api/auth/session', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user/email', expected: 'other@example.test' }] });
  return { id: 'member-app', name: 'Member app', applicationId: 'member-app', origin, buildLabel: 'b', contextId: 'synthetic', actors, requiredControlIds: checks.filter(c => c.severity === 'control').map(c => c.id), checks };
}

test('a baseline taken while the login was not proven can show no fix; a baseline whose only failure is a non-identity control still can', async t => {
  const state = { alive: false, requests: [] }, origin = await sessionServer(t, state), target = memberProfile(origin, { surface: true });
  const expired = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.equal(expired.identityEvidence.actors[0].loginProven, false); assert.equal(expired.results[2].trace[0].data.httpStatus, 302);
  state.alive = true;
  const fresh = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.deepEqual(fresh.results.map(r => r.status), ['pass', 'pass', 'pass']);
  const comparison = compareRuns(expired, fresh);
  assert.equal(comparison.compatible, true); assert.equal(comparison.summary.fixed, 0);
  assert.deepEqual(comparison.rows.map(r => r.transition), ['unverified', 'unverified', 'unverified']); assert.match(comparison.reasons.join(' '), /baseline run did not prove/);
  // A failed non-identity control in the baseline (login proven) keeps restoration meaningful.
  const history = { id: 'own-history', title: 'Member history', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/history', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] };
  const withHistory = memberProfile(origin, { controls: [target.checks[0], history] });
  Object.assign(state, { historyStatus: 500, exposed: true });
  const broken = await runHttpAssessment(withHistory, { env: memberSessionEnv });
  assert.equal(broken.identityEvidence.actors[0].reason, 'control-not-passed'); assert.equal(broken.identityEvidence.actors[0].loginProven, true);
  Object.assign(state, { historyStatus: 200, exposed: false });
  const repaired = await runHttpAssessment(withHistory, { env: memberSessionEnv });
  const restored = compareRuns(broken, repaired);
  assert.equal(restored.summary.fixed, 2); assert.deepEqual(restored.rows.map(r => r.transition), ['preserved', 'contract-restored', 'contract-restored']);
});

test('every other check of the actor is bracketed, including non-identity required controls and control-only actors', async t => {
  const notAdmin = { id: 'not-admin', title: 'Member is not an admin', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/api/auth/session', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/user/admin', expected: false }] };
  const state = { alive: true, admin: true, requests: [] }, origin = await sessionServer(t, state);
  const target = memberProfile(origin); target.checks = [target.checks[0], notAdmin]; target.requiredControlIds = ['whoami', 'not-admin'];
  const before = await runHttpAssessment(target, { env: memberSessionEnv });
  // actor-identity/4: the bracket re-sends the identity control and the surface control ('not-admin', a GET on a protected route).
  assert.equal(before.results[1].status, 'fail'); assert.deepEqual(before.identityEvidence.actors[0].before.map(p => p.controlId), ['whoami', 'not-admin'], 'A control-only actor is bracketed around its non-identity control.');
  Object.assign(state, { alive: true, expireAfterSession: true, requests: [] });
  const after = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.equal(after.results[1].assertions.find(a => a.name.startsWith('json.exists')).status, 'pass', 'The negative predicate passes on the expired session (200 null)...');
  assert.equal(after.results[1].status, 'inconclusive');
  assert.equal(after.identityEvidence.actors[0].reason, 'bracket-not-passed', '...but the bracket shows the login no longer held.');
  const comparison = compareRuns(before, after);
  assert.equal(comparison.summary.fixed, 0); assert.equal(comparison.controlsPass, false);
});

test('an identity control that accepts an invalid credential or another actor\'s credential cannot prove the login', async t => {
  const lookup = { id: 'whoami', title: 'Member lookup', category: 'Identity', severity: 'control', actorId: 'member', method: 'GET', path: '/api/users/member', evidenceRequirement: 'response', assertions: identifying };
  const state = { alive: true, lookup: 'presence', requests: [] }, origin = await sessionServer(t, state);
  const presence = await runHttpAssessment(memberProfile(origin, { controls: [lookup] }), { env: memberSessionEnv });
  assert.equal(presence.identityEvidence.actors[0].reason, 'accepted-invalid-credential'); assert.equal(presence.results[1].status, 'inconclusive');
  state.lookup = 'any-login';
  const anyLogin = await runHttpAssessment(memberProfile(origin, { controls: [lookup], other: true }), { env: memberSessionEnv });
  const entry = anyLogin.identityEvidence.actors.find(a => a.actorId === 'member');
  assert.equal(entry.reason, 'accepted-other-actor-credential'); assert.deepEqual(entry.cross.map(p => [p.crossActorId, p.httpStatus]), [['other', 200]]);
  assert.equal(anyLogin.results.find(r => r.id === 'member-denied').status, 'inconclusive');
  // A session-derived whoami names whoever is signed in, so the same two actors are both proven.
  const sessionDerived = await runHttpAssessment(memberProfile(origin, { other: true }), { env: memberSessionEnv });
  assert.deepEqual(sessionDerived.identityEvidence.actors.map(a => [a.actorId, a.reason]), [['member', 'established'], ['other', 'established']]);
});

test('a declared sign-in redirect on a checked request means the login did not hold; undeclared it stays a refusal', async t => {
  // The foreign route redirects the signed-in member to sign-in: the login did not hold for that request.
  const redirecting = await server(t, (req, res) => { if (req.url.startsWith('/records/foreign')) { res.writeHead(307, { Location: '/sign-in' }); return res.end(); } return json(res, req.headers.cookie === 'sid=member-session' ? 200 : 401, req.headers.cookie === 'sid=member-session' ? { user: { email: 'member@example.test' } } : {}); });
  // With a surface control (actor-identity/4), so an undeclared redirect counts as the refusal.
  const declared = memberProfile(redirecting, { boundary: [307, 403], surface: true }); declared.actors.member.signInRedirectStatus = 307;
  const undeclared = memberProfile(redirecting, { boundary: [307, 403], surface: true });
  const a = await runHttpAssessment(declared, { env: memberSessionEnv }), b = await runHttpAssessment(undeclared, { env: memberSessionEnv });
  const denied = run => run.results.find(r => r.id === 'member-denied');
  assert.equal(a.identityEvidence.actors[0].established, true); assert.equal(denied(a).status, 'inconclusive'); assert.match(denied(a).assertions.at(-1).actual, /redirected to sign-in/);
  assert.equal(b.identityEvidence.actors[0].established, true); assert.equal(denied(b).status, 'pass');
  // Without a surface control the undeclared redirect is not a refusal either: the login was proven only on the identity route.
  const bare = await runHttpAssessment(memberProfile(redirecting, { boundary: [307, 403] }), { env: memberSessionEnv });
  assert.equal(denied(bare).status, 'inconclusive'); assert.match(denied(bare).assertions.at(-1).actual, /proven only on its identity route/);
});

test('identity probes are GET-only: a POST check is sent once even with invalid-credential and cross-actor probes', async t => {
  const state = { alive: true, requests: [] }, origin = await sessionServer(t, state);
  const target = memberProfile(origin, { other: true }); target.checks[1].method = 'POST'; target.checks[1].body = { probe: 'synthetic' };
  const run = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.equal(state.posts, 1); assert.ok(state.requests.filter(r => r.method === 'POST').length === 1);
  assert.ok(run.identityEvidence.actors.every(a => [...a.before, ...a.after, ...a.anonymous, ...a.invalid, ...a.cross].every(p => ['whoami', 'other-whoami'].includes(p.controlId))));
});

test('the exported HTTP suite names its evidence origin and binds identity controls by position and refusal statuses, never by value', async t => {
  const origin = 'http://127.0.0.1:5001', target = memberProfile(origin, { other: true }); target.actors.member.signInRedirectStatus = 307;
  const exported = createRegistry({ profiles: [target], env: {} }).exportSuite(target.id);
  assert.equal(exported.evidenceOrigin, 'local-http-response');
  assert.deepEqual(exported.checks.filter(c => c.identityControl).map(c => [c.id, c.identityPredicate, c.refusalStatuses]), [['whoami', 0, [401, 403, 307]], ['other-whoami', 0, [401, 403]]]);
  assert.equal(JSON.stringify(exported).includes('@example.test'), false);
  const duplicate = memberProfile(origin, { other: true }); duplicate.actors.other.identityValue = 'member@example.test';
  assert.throws(() => validateTargetFile(manifest(duplicate)), /actor "(member|other)": "identityValue" must be unique across actors/);
});

test('the dashboard labels both identity gate reasons in plain language', async () => {
  const dashboard = await readFile(new URL('../public/dashboard/dashboard.mjs', import.meta.url), 'utf8');
  assert.match(dashboard, /'identity-not-established':'Login not proven for one or more test users\.'/);
  assert.match(dashboard, /'baseline-identity-not-established':'The earlier run’s login wasn’t proven, so it can’t show a fix\.'/);
});

test('compareRuns refuses a candidate the gate would reject (edited identity evidence or a v1 downgrade)', async t => {
  const state = { alive: true, exposed: true, requests: [] }, origin = await sessionServer(t, state), target = memberProfile(origin, { surface: true });
  const before = await runHttpAssessment(target, { env: memberSessionEnv }); state.exposed = false;
  const after = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.equal(compareRuns(before, after).summary.fixed, 1);
  const edits = [
    run => { Object.assign(run.identityEvidence.actors[0], { established: false }); },
    run => { delete run.identityEvidence; },
    run => { Object.assign(run, { adapterVersion: 'loopback-response-contract/1', assertionSchemaVersion: 'http-contract/2' }); },
    run => { run.identityEvidence.actors[0].anonymous[0].outcome = 'pass'; },
  ];
  for (const edit of edits) {
    const candidate = structuredClone(after); edit(candidate);
    const comparison = compareRuns(before, candidate);
    assert.equal(comparison.compatible, false); assert.equal(comparison.summary.fixed, 0);
  }
});

test('identity proof details: the after-bracket alone is decisive, a probe that names the actor or cannot complete is not a refusal, and the identity value must match', async t => {
  const state = { alive: true, requests: [] }, origin = await sessionServer(t, state), target = memberProfile(origin);
  const proven = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.equal(proven.identityEvidence.actors[0].reason, 'established');
  assert.ok([...proven.identityEvidence.actors[0].before, ...proven.identityEvidence.actors[0].anonymous].every(p => Number.isSafeInteger(p.requestTimeoutMs) && p.requestTimeoutMs > 0), 'Each probe records its applied timeout.');
  // The session expires right after the boundary: the before-bracket passed, only the after-bracket catches it.
  Object.assign(state, { expireAfterForeign: true });
  const late = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.deepEqual([late.identityEvidence.actors[0].before[0].outcome, late.identityEvidence.actors[0].after[0].outcome], ['pass', 'fail']);
  assert.equal(late.identityEvidence.actors[0].reason, 'bracket-not-passed'); assert.equal(late.results[1].status, 'inconclusive');
  // A route that names the member without any credential is not a refusal.
  Object.assign(state, { alive: true, expireAfterForeign: false, anonymousNamesMember: true });
  const leaky = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.equal(leaky.identityEvidence.actors[0].reason, 'not-refused-without-credential');
  // A probe that times out is reported as incomplete, not as the app failing to refuse.
  Object.assign(state, { anonymousNamesMember: false, anonymousDelayMs: 400 });
  const slow = await runHttpAssessment(target, { env: memberSessionEnv, limits: { requestTimeoutMs: 150, runTimeoutMs: 5000, responseBytes: 65536 } });
  assert.equal(slow.identityEvidence.actors[0].anonymous[0].transportOutcome, 'timeout'); assert.equal(slow.identityEvidence.actors[0].reason, 'identity-probe-incomplete');
  assert.match(slow.results[1].assertions.at(-1).actual, /could not complete/);
  // The identity predicate must use exactly the declared identity value.
  Object.assign(state, { anonymousDelayMs: 0 });
  const mismatched = memberProfile(origin); mismatched.actors.member.identityValue = 'Member@Example.test';
  const wrongValue = await runHttpAssessment(mismatched, { env: memberSessionEnv });
  assert.equal(wrongValue.identityEvidence.actors[0].reason, 'no-identity-control'); assert.equal(wrongValue.results[1].status, 'inconclusive');
});

test('a non-required control of a credentialed actor is bracketed and carries the identity assertion when the login lapses', async t => {
  const notAdmin = { id: 'not-admin', title: 'Member is not an admin', category: 'Access', severity: 'control', actorId: 'member', method: 'GET', path: '/api/auth/session', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/user/admin', expected: false }] };
  const state = { alive: true, admin: false, expireAfterSession: true, requests: [] }, origin = await sessionServer(t, state);
  const target = memberProfile(origin); target.checks = [target.checks[0], notAdmin]; target.requiredControlIds = ['whoami'];
  const run = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.equal(run.identityEvidence.actors[0].reason, 'bracket-not-passed');
  assert.equal(run.results[1].status, 'inconclusive'); assert.equal(run.results[1].assertions.at(-1).name, IDENTITY);
});

test('run history omits identityEvidence while the saved full run keeps it', async t => {
  const state = { alive: true, requests: [] }, origin = await sessionServer(t, state);
  const run = await runHttpAssessment(memberProfile(origin), { env: memberSessionEnv });
  const store = createStore(await directory(t)); await store.ready; await store.save(run);
  const page = await store.historyPage();
  assert.equal(page.runs.length, 1); assert.equal(Object.hasOwn(page.runs[0], 'identityEvidence'), false);
  assert.equal(JSON.stringify(page).includes('member@example.test'), false);
  const full = await store.get(run.id);
  assert.equal(full.identityEvidence.schema, 'actor-identity/6'); assert.equal(full.identityEvidence.actors[0].reason, 'established');
  // Through the local API: the bootstrap history row omits it and GET /api/runs/:id keeps it.
  // The authorization record: the dashboard's run path needs a covering record (test/authorization.test.mjs pins the refusals).
  const authorizationFile = writeTestAuthorization(join(await directory(t), 'authorization.json'), memberProfile(origin));
  const app = await startServer({ port: 0, dataDir: await directory(t), profiles: [memberProfile(origin)], env: memberSessionEnv, authorizationFile }); t.after(() => app.close());
  const call = (method, path, payload) => new Promise((resolve, reject) => {
    const body = payload === undefined ? undefined : Buffer.from(JSON.stringify(payload));
    const req = request(`${app.origin}${path}`, { method, agent: false, headers: { Authorization: `Bearer ${app.accessToken}`, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json', 'X-Scopehaven-Request': '1', 'Content-Length': body.length } : {}) } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString() || 'null') }));
    });
    req.on('error', reject); req.end(body);
  });
  const created = await call('POST', '/api/runs', { targetId: 'member-app' });
  assert.equal(created.status, 201);
  const bootstrap = await call('GET', '/api/bootstrap');
  assert.equal(bootstrap.json.runs.length, 1); assert.equal(Object.hasOwn(bootstrap.json.runs[0], 'identityEvidence'), false);
  const saved = await call('GET', `/api/runs/${created.json.id}`);
  assert.equal(saved.status, 200); assert.equal(saved.json.identityEvidence.schema, 'actor-identity/6'); assert.equal(saved.json.identityEvidence.actors[0].reason, 'established');
});

test('identity probes share the run budget: a probe late in the run gets only the time that remains', async () => {
  const sent = [];
  const transport = async (_, check, options) => {
    sent.push({ path: check.path, credential: options.credential, timeoutMs: options.timeoutMs });
    if (check.path === '/records/foreign') { await new Promise(resolve => setTimeout(resolve, 250)); return { status: 403, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' }; }
    return options.credential === 'member-session' ? { status: 200, complete: true, jsonParsed: true, json: { user: { email: 'member@example.test' } }, bytes: 40 } : { status: 401, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
  };
  const run = await runHttpAssessment(memberProfile('http://127.0.0.1:1'), { env: memberSessionEnv, transport, limits: { requestTimeoutMs: 300, runTimeoutMs: 400, responseBytes: 1024 } });
  const entry = run.identityEvidence.actors[0], late = [...entry.anonymous, ...entry.invalid];
  assert.equal(entry.reason, 'established'); assert.equal(late.length, 2);
  for (const probe of late) assert.ok(probe.requestTimeoutMs > 0 && probe.requestTimeoutMs < 300, `${probe.kind} probe applied ${probe.requestTimeoutMs} ms`);
  assert.deepEqual(sent.slice(-2).map(s => s.timeoutMs), late.map(p => p.requestTimeoutMs), 'The recorded timeout is the one the request was given.');
});

test('a control-only actor whose login is not proven is never a clean pass: assess exit code, SARIF and report.html agree with the gate', async t => {
  // The session route names the member even without a credential, so the login is not proven. The actor has only its required control.
  const state = { alive: true, anonymousNamesMember: true, requests: [] }, origin = await sessionServer(t, state);
  const target = memberProfile(origin); target.checks = [target.checks[0]]; target.requiredControlIds = ['whoami'];
  const run = await runHttpAssessment(target, { env: memberSessionEnv });
  assert.equal(run.identityEvidence.actors[0].reason, 'not-refused-without-credential');
  assert.deepEqual(run.results.map(r => r.status), ['inconclusive']); assert.deepEqual([run.counts.pass, run.counts.inconclusive], [0, 1]);
  assert.equal(run.results[0].assertions.at(-1).name, IDENTITY);
  const sarif = renderSarif(run).runs[0].results;
  assert.equal(sarif.length, 1); assert.notEqual(sarif[0].kind, 'pass');
  assert.match(renderReport(run), /0 passed · 0 failed · 1 inconclusive/);
  const config = join(await directory(t), 'targets.json'); await writeFile(config, JSON.stringify({ schemaVersion: 1, targets: [target] }), { mode: 0o600 });
  const out = await directory(t), cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
  const authorization = writeTestAuthorization(join(await directory(t), 'authorization.json'), target);
  const result = await new Promise(resolve => execFile(process.execPath, [cli, '--config', config, '--target', target.id, '--out', out, '--authorization', authorization], { env: { PATH: process.env.PATH, SCOPEHAVEN_TARGET_MEMBER: 'member-session' } }, (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr })));
  assert.equal(result.code, 1, result.stderr); assert.deepEqual(JSON.parse(result.stdout).counts, { pass: 0, fail: 0, inconclusive: 1, error: 0, not_applicable: 0 });
});

// A malformed target or an aborted body is answered or dropped, never a crash of the lab.
test('the HTTP lab answers a target that is no URL (//) with 400 and survives an aborted body; ordinary requests still work', async t => {
  const lab = await createHttpLab(); t.after(() => lab.close());
  const port = Number(new URL(lab.origin).port);
  const raw = text => new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1', () => socket.end(text));
    const chunks = []; socket.on('data', c => chunks.push(c)); socket.on('error', reject); socket.on('close', () => resolve(Buffer.concat(chunks).toString('latin1').split('\r\n')[0]));
  });
  for (const target of ['//', '//%zz', '/\\%zz']) assert.equal(await raw(`GET ${target} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`), 'HTTP/1.1 400 Bad Request', target);
  // A POST whose body never arrives: the connection closes while the handler is reading it.
  await new Promise(resolve => {
    const socket = connect(port, '127.0.0.1', () => socket.write(`POST /echo HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nAuthorization: Bearer ${lab.memberToken}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"m`));
    socket.on('error', () => {}); setTimeout(() => { socket.destroy(); setTimeout(resolve, 100); }, 100);
  });
  const me = await fetch(`${lab.origin}/me`, { headers: { Authorization: `Bearer ${lab.memberToken}` } });
  assert.equal(me.status, 200, 'the lab is still serving');
  assert.equal((await me.json()).principalId, 'lab-member-aster');
  assert.equal((await fetch(`${lab.origin}/me`)).status, 401);
});
