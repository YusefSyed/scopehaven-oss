// Header API keys. An actor's credential can be sent in a named header (x-api-key, apikey) instead of
// Authorization: Bearer or a cookie. Its value comes only from a SCOPEHAVEN_TARGET_ variable, the evidence keeps a
// digest of it only, it goes only to the target's origin, and the names the connector, HTTP framing or a proxy owns
// are refused. A loopback app in this process records the headers every request carried. No model or provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { runHttpAssessment, observeHttp } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, credentialHeaderProblem, CREDENTIAL_HEADER_DIGEST } from '../src/contracts.mjs';
import { digest } from '../src/domain.mjs';
import { createRegistry } from '../src/registry.mjs';
import { renderReport } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { checksumAuthorization, AUTHORIZATION_SCHEMA } from '../src/authorization.mjs';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { writeJump, realNow } from './support/window-clock.mjs';

// Synthetic header values (not secrets): the app accepts exactly these two.
const KEY = 'synthetic-header-value-one', OTHER = 'synthetic-header-value-two';
async function keyApp(t, { header = 'x-api-key', redirectTo } = {}) {
  const seen = [];
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    seen.push({ url: req.url, headers: { ...req.headers } });
    const json = (s, b, h = {}) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close', ...h }); res.end(JSON.stringify(b)); };
    if (redirectTo && req.url === '/admin/settings') return json(302, {}, { Location: `${redirectTo}/admin/settings` });
    const user = req.headers[header] === KEY ? 'member-1' : req.headers[header] === OTHER ? 'member-2' : null;
    if (!user) return json(401, {});
    if (req.url === '/me') return json(200, { user });
    if (req.url === '/notes') return json(200, { notes: [] });
    return json(403, {});
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${server.address().port}`, seen };
}
const keyProfile = (origin, actor = {}) => ({ id: 'keyed', name: 'Keyed API', applicationId: 'keyed-api', origin, buildLabel: 'b1', contextId: 'synthetic',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_API_KEY', credentialHeader: 'x-api-key', identityValue: 'member-1', ...actor } }, requiredControlIds: ['WHOAMI', 'READ-NOTES'],
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] },
    { id: 'READ-NOTES', title: 'A member reads the notes list', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'GET', path: '/notes', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'ADMIN-SETTINGS', title: 'A member cannot read the admin settings', category: 'admin', severity: 'high', actorId: 'member', method: 'GET', path: '/admin/settings', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
  ] });
const valid = target => validateTargetFile({ schemaVersion: 1, targets: [target] })[0];

test('the header name is a token the connector, framing or a proxy does not own; it needs credentialEnv and excludes a cookie', () => {
  for (const name of ['x-api-key', 'apikey', 'X-API-Key', 'api_key', 'x-tenant-token']) assert.equal(credentialHeaderProblem(name), null, name);
  for (const name of ['Host', 'cookie', 'AUTHORIZATION', 'Proxy-Authorization', 'proxy-anything', 'content-length', 'Transfer-Encoding', 'connection', 'te', 'upgrade', 'accept', 'origin',
    'x-forwarded-for', 'X-Forwarded-Host', 'x-real-ip', 'sec-fetch-site', 'x-scopehaven-request', 'forwarded', 'via', 'Content-Range', 'content-location', 'content-md5',
    'traceparent', 'TraceState', 'baggage', 'set-cookie', 'X-HTTP-Method-Override', 'x-original-url', 'www-authenticate'])
    assert.match(credentialHeaderProblem(name), /owns/, name);
  for (const name of ['', 'x api key', 'x-api-key:', 'x-api-key\r\nInjected: 1', 'clé', 'x'.repeat(65), 'a/b', '(key)', 12]) assert.match(String(credentialHeaderProblem(name)), /must be a header name/, JSON.stringify(name));
  assert.equal(valid(keyProfile('http://127.0.0.1:1')).actors.member.credentialHeader, 'x-api-key');
  assert.throws(() => valid(keyProfile('http://127.0.0.1:1', { credentialHeader: 'Authorization' })), /"credentialHeader" names a header the connector/);
  assert.throws(() => valid(keyProfile('http://127.0.0.1:1', { credentialHeader: 'Host' })), /"credentialHeader" names a header the connector/);
  assert.throws(() => valid(keyProfile('http://127.0.0.1:1', { credentialHeader: 'x api' })), /"credentialHeader" must be a header name/);
  assert.throws(() => valid(keyProfile('http://127.0.0.1:1', { credentialCookie: 'session' })), /a cookie or in a header, not both/);
  const { credentialEnv: _e, identityValue: _i, ...bare } = keyProfile('http://127.0.0.1:1').actors.member;
  assert.throws(() => valid({ ...keyProfile('http://127.0.0.1:1'), actors: { member: bare } }), /"credentialHeader" needs a "credentialEnv"/);
  // The connector checks the name again before it sends anything.
  assert.throws(() => observeHttp('http://127.0.0.1:1', { method: 'GET', path: '/' }, { credential: KEY, credentialHeader: 'Cookie' }), /Credential header is missing or has an unsupported name/);
  assert.throws(() => observeHttp('http://127.0.0.1:1', { method: 'GET', path: '/' }, { credential: KEY, credentialHeader: 'x-api-key', credentialCookie: 'session' }), /Credential header/);
});

test('no observer credential may name a header actor\'s variable, so the key never reaches an observer as its own bearer token', () => {
  const audit = credentialEnv => ({ id: 'audit', type: 'http-audit', origin: 'http://127.0.0.1:2', path: '/audit', credentialEnv, itemsPointer: '/items', pageLimit: 100,
    fields: { id: '/id', actor: '/actor', action: '/action' }, actions: { 'note.create': 'insert' }, principals: ['member-1'] });
  const withObserver = (observer, actor) => ({ ...keyProfile('http://127.0.0.1:1', actor), observers: [observer] });
  // An http-audit observer naming the X-Api-Key actor's variable was accepted and sent the key as Authorization: Bearer.
  assert.throws(() => valid(withObserver(audit('SCOPEHAVEN_TARGET_API_KEY'))), /an observer credential names a header actor's "credentialEnv"/);
  // Its own variable is accepted, and so is a bearer actor's variable reused by an observer (unchanged).
  assert.equal(valid(withObserver(audit('SCOPEHAVEN_TARGET_AUDIT'))).observers[0].credentialEnv, 'SCOPEHAVEN_TARGET_AUDIT');
  const { credentialHeader: _h, ...bearer } = keyProfile('http://127.0.0.1:1').actors.member;
  assert.doesNotThrow(() => valid({ ...withObserver(audit('SCOPEHAVEN_TARGET_API_KEY')), actors: { member: bearer } }));
  // A database observer's credential too; with its own variable it is accepted.
  const pg = credentialEnv => ({ id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv, tables: [{ table: 'notes', key: 'id' }] });
  assert.doesNotThrow(() => valid(withObserver(pg('SCOPEHAVEN_TARGET_PG'))));
  assert.throws(() => valid(withObserver(pg('SCOPEHAVEN_TARGET_API_KEY'))), /an observer credential names a header actor's "credentialEnv"/);
});

test('no other actor may name a header actor\'s variable, so the key is never sent as another actor\'s bearer token, cookie or header', async t => {
  const app = await keyApp(t), base = keyProfile(app.origin);
  const withOther = other => ({ ...base, actors: { ...base.actors, other: { principalId: 'other-1', ...other } } });
  // A bearer actor, and a cookie actor, on the X-Api-Key actor's variable were accepted, and the key went out as Authorization: Bearer.
  for (const [name, other] of [['bearer', { credentialEnv: 'SCOPEHAVEN_TARGET_API_KEY' }], ['cookie', { credentialEnv: 'SCOPEHAVEN_TARGET_API_KEY', credentialCookie: 'session' }],
    ['another header', { credentialEnv: 'SCOPEHAVEN_TARGET_API_KEY', credentialHeader: 'x-other-key' }], ['the same header', { credentialEnv: 'SCOPEHAVEN_TARGET_API_KEY', credentialHeader: 'x-api-key' }]]) {
    assert.throws(() => valid(withOther(other)), /"credentialEnv" names another actor's header key variable/, name);
    await assert.rejects(runHttpAssessment(withOther(other), { env: { SCOPEHAVEN_TARGET_API_KEY: KEY } }), /"credentialEnv" names another actor's header key variable/, name);
  }
  assert.equal(app.seen.length, 0, 'nothing was sent');
  // With its own variable it is accepted; two bearer actors on one variable are unchanged.
  assert.equal(valid(withOther({ credentialEnv: 'SCOPEHAVEN_TARGET_OTHER' })).actors.other.credentialEnv, 'SCOPEHAVEN_TARGET_OTHER');
  const { credentialHeader: _h, ...bearer } = base.actors.member;
  assert.doesNotThrow(() => valid({ ...base, actors: { member: bearer, other: { principalId: 'other-1', credentialEnv: 'SCOPEHAVEN_TARGET_API_KEY' } } }));
});

test('a header key goes in its header only, to the origin only; the evidence keeps a digest, never the value', async t => {
  const decoy = await keyApp(t);
  const app = await keyApp(t, { redirectTo: decoy.origin });
  const profile = keyProfile(app.origin);
  const run = await runHttpAssessment(profile, { env: { SCOPEHAVEN_TARGET_API_KEY: KEY } });
  const expectedSuite = createRegistry({ profiles: [profile], env: {} }).exportSuite('keyed');
  validateHttpRunEvidence(run, { expectedSuite });
  // Every request that carried the key carried it in x-api-key and nowhere else; none carried Authorization or a cookie.
  const keyed = app.seen.filter(r => Object.values(r.headers).some(v => String(v).includes(KEY)));
  assert.ok(keyed.length >= 3);
  for (const r of keyed) { assert.equal(r.headers['x-api-key'], KEY); assert.equal(r.headers.authorization, undefined); assert.equal(r.headers.cookie, undefined); }
  // The identity probes: one without the key, one with a random value in the same header.
  assert.ok(app.seen.some(r => r.url === '/me' && r.headers['x-api-key'] === undefined));
  assert.ok(app.seen.some(r => r.url === '/me' && typeof r.headers['x-api-key'] === 'string' && ![KEY, OTHER].includes(r.headers['x-api-key'])));
  assert.equal(decoy.seen.length, 0, 'a redirect is never followed, so the key never reaches another origin');
  assert.equal(run.results.find(r => r.id === 'ADMIN-SETTINGS').status, 'fail', 'the 302 is the response');
  assert.deepEqual(run.results.map(r => r.trace[0].data.credentialMode), ['header', 'header', 'header']);
  assert.deepEqual(expectedSuite.checks.map(c => c.credentialMode), ['header', 'header', 'header']);
  assert.deepEqual(run.credentialHeaders, [{ actorId: 'member', header: 'x-api-key', valueDigest: digest({ schema: CREDENTIAL_HEADER_DIGEST, header: 'x-api-key', value: KEY }) }]);
  for (const text of [JSON.stringify(run), renderReport(run), JSON.stringify(renderSarif(run)), JSON.stringify(summarizeGate({ candidate: run, expectedSuite }))]) assert.ok(!text.includes(KEY), 'the value is never kept');
  // The entries are bound to the rows that sent a key: a dropped, relabelled or extra entry is refused. The digest itself can only be
  // checked against the value, which the run does not hold, so an edited digest of the right shape still validates.
  for (const edit of [r => { r.credentialHeaders[0].valueDigest = '0'.repeat(64); }, r => { delete r.credentialHeaders; }, r => { r.credentialHeaders[0].header = 'Authorization'; }, r => { r.credentialHeaders.push({ actorId: 'other', header: 'x-api-key', valueDigest: '0'.repeat(64) }); }]) {
    const edited = structuredClone(run); edit(edited);
    if (edited.credentialHeaders?.[0]?.valueDigest === '0'.repeat(64) && edited.credentialHeaders.length === 1) { assert.doesNotThrow(() => validateHttpRunEvidence(edited, { expectedSuite }), 'a digest is not checked against a value the run does not hold'); continue; }
    assert.throws(() => validateHttpRunEvidence(edited, { expectedSuite }), error => error.code === 'invalid-run-evidence');
  }
  // A bearer or cookie run carries no entry, and refuses one.
  const bearer = await runHttpAssessment({ ...profile, actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_API_KEY', identityValue: 'member-1' } } }, { env: { SCOPEHAVEN_TARGET_API_KEY: KEY } });
  assert.equal(Object.hasOwn(bearer, 'credentialHeaders'), false);
  assert.throws(() => validateHttpRunEvidence({ ...bearer, credentialHeaders: run.credentialHeaders }), error => error.code === 'invalid-run-evidence');
});

test('the value comes only from its SCOPEHAVEN_TARGET_ variable: missing, or with a line break, nothing is sent', async t => {
  const app = await keyApp(t);
  for (const env of [{}, { SCOPEHAVEN_TARGET_API_KEY: `${KEY}\r\nX-Injected: 1` }, { SCOPEHAVEN_TARGET_API_KEY: '' }])
    await assert.rejects(runHttpAssessment(keyProfile(app.origin), { env }), /credential/i, JSON.stringify(env));
  assert.equal(app.seen.length, 0);
  // A profile cannot carry the value: the actor shape has no field for it.
  assert.throws(() => valid(keyProfile(app.origin, { credentialValue: KEY })), /unsupported field/);
});

test('another header name is honoured case-insensitively, and the run says only which header', async t => {
  const app = await keyApp(t, { header: 'apikey' });
  const run = await runHttpAssessment(keyProfile(app.origin, { credentialHeader: 'ApiKey' }), { env: { SCOPEHAVEN_TARGET_API_KEY: KEY } });
  assert.equal(run.results.find(r => r.id === 'WHOAMI').status, 'pass');
  assert.equal(run.credentialHeaders[0].header, 'apikey');
  // The correlation header cannot double as the key's.
  const correlated = header => ({ ...keyProfile(app.origin, { credentialHeader: header }), correlation: { header: 'x-request-id' },
    observers: [{ id: 'pay', type: 'egress-recorder', port: 47221, destinations: [{ host: 'pay.example', correlation: { header: 'x-request-id' } }] }] });
  assert.equal(valid(correlated('x-api-key')).actors.member.credentialHeader, 'x-api-key');
  assert.throws(() => valid(correlated('X-Request-Id')), /"credentialHeader" must not be the target's correlation header/);
});

test('cross probes with mixed credential modes send each credential the way its actor sends it, so a key never leaves its header', async t => {
  const seen = [];
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    seen.push({ ...req.headers });
    const json = (s, b) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(b)); };
    const user = req.headers['x-api-key'] === KEY ? 'member-1' : req.headers.authorization === `Bearer ${OTHER}` ? 'admin-1' : null;
    if (!user) return json(401, {});
    if (req.url === '/me') return json(200, { user });
    if (req.url === '/notes') return json(200, { notes: [] });
    return json(403, {});
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`, base = keyProfile(origin);
  const profile = { ...base, actors: { ...base.actors, admin: { principalId: 'admin-1', credentialEnv: 'SCOPEHAVEN_TARGET_ADMIN', identityValue: 'admin-1' } }, requiredControlIds: [...base.requiredControlIds, 'ADMIN-WHOAMI', 'ADMIN-NOTES'],
    checks: [...base.checks, { id: 'ADMIN-WHOAMI', title: 'The admin is the admin', category: 'identity', severity: 'control', actorId: 'admin', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'admin-1' }] },
      { id: 'ADMIN-NOTES', title: 'The admin reads the notes list', category: 'allowed-use', severity: 'control', actorId: 'admin', method: 'GET', path: '/notes', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] };
  const run = await runHttpAssessment(profile, { env: { SCOPEHAVEN_TARGET_API_KEY: KEY, SCOPEHAVEN_TARGET_ADMIN: OTHER } });
  // The member's key only ever travels in x-api-key, and the admin's token only ever as Authorization: Bearer.
  for (const headers of seen) {
    for (const [name, value] of Object.entries(headers)) {
      if (String(value).includes(KEY)) assert.equal(name, 'x-api-key');
      if (String(value).includes(OTHER)) assert.equal(name, 'authorization');
    }
  }
  // Each actor's cross probe presented the other credential: the member's /me answered as the admin, and the reverse.
  assert.ok(seen.some(h => h.authorization === `Bearer ${OTHER}`) && seen.some(h => h['x-api-key'] === KEY));
  assert.deepEqual(run.identityEvidence.actors.map(a => [a.actorId, a.reason]).sort(), [['admin', 'established'], ['member', 'established']]);
});

test('a header-key target goes through the same record and window checks: refused before any request, no request after validUntil, nothing saved', async t => {
  // The key app, slow: it holds each response until hold(at) says and records when each connection arrived (real clock);
  // onConnect, when set, runs once at the next connection.
  let holdUntil = 0, onConnect = null;
  const arrivals = [], seen = [];
  const server = createServer((req, res) => { seen.push({ url: req.url, headers: { ...req.headers } }); req.resume(); req.on('end', () => setTimeout(() => {
    const json = (st, b) => { res.writeHead(st, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(b)); };
    if (req.headers['x-api-key'] !== KEY) return json(401, {});
    if (req.url === '/me') return json(200, { user: 'member-1' });
    if (req.url === '/notes') return json(200, { notes: [] });
    return json(403, {});
  }, Math.max(0, holdUntil - realNow()))); });
  server.on('connection', () => { arrivals.push(realNow()); if (onConnect) { const fn = onConnect; onConnect = null; fn(); } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven header keys ')); chmodSync(dir, 0o700); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const oneRequest = { ...keyProfile(origin), id: 'keyed-one', actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_API_KEY', credentialHeader: 'x-api-key' } }, requiredControlIds: ['READ-NOTES'],
    checks: keyProfile(origin).checks.filter(c => c.id === 'READ-NOTES') };
  const profiles = join(dir, 'profiles.json');
  writeFileSync(profiles, JSON.stringify({ schemaVersion: 1, targets: [keyProfile(origin), oneRequest] }));
  const DAY = 86400000, ago = days => new Date(Date.now() - days * DAY).toISOString().replace(/\.\d{3}Z$/, 'Z');
  let n = 0;
  const record = (targetId, edit = () => {}) => { const r = { schema: AUTHORIZATION_SCHEMA, id: 'keyed-window', target: { id: targetId, applicationId: 'keyed-api' }, origins: [origin], identities: ['member-1'],
    validFrom: ago(1), validUntil: ago(-30), signer: { name: 'A. Example', role: 'Owner' }, signedAt: ago(1) }; edit(r); const path = join(dir, `record-${++n}.json`); writeFileSync(path, JSON.stringify(checksumAuthorization(r))); return path; };
  const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url)), CLOCK = fileURLToPath(new URL('./support/window-clock.mjs', import.meta.url));
  // clockFile: the child preloads the test window clock (test/support/window-clock.mjs), which follows that file.
  const assess = (args, clockFile = null) => new Promise(resolve => {
    const child = spawn(process.execPath, [...(clockFile ? ['--import', CLOCK] : []), cli, ...args], { env: { PATH: process.env.PATH, SCOPEHAVEN_TARGET_API_KEY: KEY, ...(clockFile ? { SCOPEHAVEN_TEST_WINDOW_CLOCK: clockFile } : {}) } });
    let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
  const savedRuns = out => existsSync(join(out, 'runs')) ? readdirSync(join(out, 'runs')).filter(f => f.endsWith('.json')).length : 0;
  // The record is checked before any request: by assess, and by roe check, which the Action's prepare step runs before its wait.
  const { main: roe } = await import('../integrations/roe/cli.mjs');
  for (const [name, path, code] of [['no record', null, 'authorization-missing'], ['a record without the key holder', record('keyed', r => { r.identities = ['someone-else']; }), 'authorization-identity'],
    ['an expired record', record('keyed', r => { r.validFrom = ago(10); r.validUntil = ago(2); r.signedAt = ago(10); }), 'authorization-window']]) {
    const r = await assess(['--config', profiles, '--target', 'keyed', '--out', join(dir, `out-refused-${name.length}`), ...(path ? ['--authorization', path] : [])]);
    assert.equal(r.code, 2, `${name}: ${r.stderr}`); assert.match(r.stderr, new RegExp(`authorization refused \\(${code}\\)`), name);
    if (path) { let err = ''; assert.equal(await roe(['check', path, '--config', profiles, '--target', 'keyed'], { stdout: { write() {} }, stderr: { write: x => { err += x; } } }), 2, name); assert.equal(JSON.parse(err).code, code, name); }
  }
  assert.equal(arrivals.length, 0, 'no refused run connected to the target');
  // The window ends while the run waits on the target, at a moment the test chooses (test/support/window-clock.mjs): the
  // record is valid for a minute, so a slow start is never refused, and at the run's first connection the child's guard
  // clock jumps past validUntil and the response is held 300 ms. `until` is the real time of that jump. The next request
  // is never sent, and the run is refused before it is saved.
  const ARRIVAL_SLACK_MS = 200;
  const windowEndsMidRun = async (targetId, out) => {
    const validUntil = realNow() + 60000, before = arrivals.length, seenBefore = seen.length, file = join(dir, `window-clock-${targetId}`);
    let until = null;
    onConnect = () => { until = realNow(); writeJump(file, validUntil); holdUntil = until + 300; };
    try {
      const result = await assess(['--config', profiles, '--target', targetId, '--out', out, '--authorization', record(targetId, r => { r.validUntil = new Date(validUntil).toISOString(); })], file);
      assert.ok(until !== null && arrivals.length > before, 'the run reached the target inside its window');
      return { until, result, arrivals: arrivals.slice(before), seen: seen.slice(seenBefore) };
    } finally { onConnect = null; holdUntil = 0; }
  };
  for (const [targetId, out] of [['keyed', join(dir, 'out-window')], ['keyed-one', join(dir, 'out-after-last')]]) {
    const r = await windowEndsMidRun(targetId, out);
    assert.equal(r.result.code, 2, `${targetId}: ${r.result.stderr}`);
    assert.match(r.result.stderr, /authorization refused \(authorization-window-ended\)/, targetId);
    assert.ok(r.arrivals.every(at => at < r.until + ARRIVAL_SLACK_MS), `${targetId}: a request arrived ${Math.max(...r.arrivals) - r.until} ms after the window ended (the clock jump)`);
    if (targetId === 'keyed-one') assert.deepEqual(r.seen.map(x => x.url), ['/notes'], 'only the one request was sent');
    assert.ok(r.seen.filter(x => x.headers['x-api-key'] === KEY).length >= 1 && r.seen.every(x => x.headers.authorization === undefined), `${targetId}: the key went only in its header`);
    assert.equal(savedRuns(out), 0, `${targetId}: no run was saved`);
  }
});
