// The authorization record. A loopback notes app (counting every request it
// receives) and the owned synthetic fixture; no network beyond 127.0.0.1, no model, provider or
// customer system. The record is checked before any request and never changes a verdict.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { runHttpAssessment, observeHttp } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { REFUND_TARGET_IDS } from '../temporal-contracts/contract.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { runAssessment } from '../../src/runner.mjs';
import { SUITE } from '../../src/suite.mjs';
import { AUTHORIZATION_SCHEMA, AuthorizationError, validateAuthorization, checksumAuthorization, authorizationDigest, checkAuthorization, authorizationStamp, needsAuthorization, BUILT_IN_KINDS, contactedEndpoints } from './authorization.mjs';
import { readAuthorizationFile, MAX_RECORD_BYTES } from './file.mjs';
import { mkdtempSync, writeFileSync, symlinkSync, rmSync, truncateSync, openSync, closeSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAuthorized } from './run.mjs';

const EXAMPLE = JSON.parse(readFileSync(new URL('./fixtures/authorization.example.json', import.meta.url), 'utf8'));
const TOKEN = 'synthetic-member-token', env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN };
const NOW = new Date('2026-10-08T12:00:00Z');
const refused = (fn, code, pattern) => assert.throws(fn, error => error instanceof AuthorizationError && error.code === code && (!pattern || pattern.test(error.message)), `expected ${code}`);
const record = (edit = () => {}) => { const r = structuredClone(EXAMPLE); edit(r); return checksumAuthorization(r); };

// The notes app; it counts every request, so a refusal can be shown to send nothing.
async function notesApp(t, mode = 'secure') {
  let requests = 0;
  const server = createServer((req, res) => { requests++; req.resume(); req.on('end', () => {
    const json = (s, b) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(b)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, {});
    if (req.url === '/me') return json(200, { user: 'member-1' });
    if (req.url === '/notes') return json(201, { id: 'n1' });
    return json(mode === 'leaky' ? 200 : 403, {});
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const [profile] = validateTargetFile({ schemaVersion: 1, targets: [{ id: 'notes', name: 'Notes app', applicationId: 'notes-app', origin, buildLabel: 'b1', contextId: 'synthetic-notes',
    actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' }, anonymous: { principalId: 'anonymous' } }, requiredControlIds: ['WHOAMI', 'OWN-NOTE'],
    checks: [
      { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] },
      { id: 'OWN-NOTE', title: 'A member can create a note', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }] },
      { id: 'OTHER-NOTE', title: "A member cannot edit another user's note", category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/notes/n-other/edit', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
      { id: 'ANON-NOTES', title: 'Nobody signed out reads notes', category: 'object-access', severity: 'high', actorId: 'anonymous', method: 'GET', path: '/notes/n-other', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [401, 403] }] },
    ] }] });
  return { profile, origin, requests: () => requests };
}
const covering = origin => record(r => { r.origins = [origin]; });

test('the example record validates; its checksum is the digest of everything else, and an edit that does not recompute it is refused', () => {
  const r = validateAuthorization(EXAMPLE);
  assert.equal(r.sha256, authorizationDigest(EXAMPLE));
  assert.ok(Object.isFrozen(r));
  assert.deepEqual(authorizationStamp(r), { schema: AUTHORIZATION_SCHEMA, id: 'acme-notes-staging-2026-10', sha256: EXAMPLE.sha256 });
  for (const [name, edit] of [
    ['an origin added', r => { r.origins.push('http://127.0.0.1:4501'); }],
    ['the window extended', r => { r.validUntil = '2026-12-14T00:00:00Z'; }],
    ['an identity added', r => { r.identities.push('admin-1'); }],
    ['the signer changed', r => { r.signer.name = 'Someone Else'; }],
  ]) { const edited = structuredClone(EXAMPLE); edit(edited); refused(() => validateAuthorization(edited), 'authorization-checksum', /edited after its checksum was computed/); assert.ok(name); }
  const unsealed = structuredClone(EXAMPLE); delete unsealed.sha256;
  refused(() => validateAuthorization(unsealed), 'authorization-invalid', /missing "sha256"/);
});

test('every field is checked, each for its own reason, and a refusal never echoes a value', () => {
  const cases = [
    ['another schema', r => { r.schema = 'scopehaven-authorization/2'; }, /"schema" must be/],
    ['an id with spaces', r => { r.id = 'acme notes'; }, /"id" must be/],
    ['no target application', r => { delete r.target.applicationId; }, /"target" is missing "applicationId"/],
    // A host name is an endpoint only as a remote target's https origin, written as its origin.
    ['a plain http hostname origin', r => { r.origins = ['http://staging.acme.example']; }, /lists 1-16 distinct endpoints/],
    ['an https origin with a path', r => { r.origins = ['https://staging.acme.example/app']; }, /lists 1-16 distinct endpoints/],
    ['an https origin not written as its origin', r => { r.origins = ['https://Staging.acme.example:443']; }, /lists 1-16 distinct endpoints/],
    ['a duplicated origin', r => { r.origins = ['http://127.0.0.1:4500', 'http://127.0.0.1:4500']; }, /lists 1-16 distinct endpoints/],
    ['a port out of range', r => { r.origins = ['http://127.0.0.1:70000']; }, /literal loopback ones/],
    ['no identities', r => { r.identities = []; }, /"identities" lists 1-50/],
    ['a local-time window', r => { r.validFrom = '2026-10-07T00:00:00'; }, /"validFrom" must be an ISO 8601 UTC instant/],
    ['a reversed window', r => { r.validUntil = r.validFrom; }, /"validFrom" must be before "validUntil"/],
    ['no signer role', r => { delete r.signer.role; }, /"signer" is missing "role"/],
    ['an unsupported field', r => { r.scope = 'everything'; }, /unsupported field/],
    ['a bad document digest', r => { r.rulesOfEngagement.sha256 = 'abc'; }, /"rulesOfEngagement" names a title/],
  ];
  for (const [name, edit, pattern] of cases) {
    const r = record(edit);
    assert.throws(() => validateAuthorization(r), error => error instanceof AuthorizationError && error.code === 'authorization-invalid' && pattern.test(error.message) && !error.message.includes('staging.acme.example') && !error.message.includes('everything'), name);
  }
  refused(() => validateAuthorization('not a record'), 'authorization-invalid', /must be a JSON object/);
  refused(() => validateAuthorization({ get schema() { throw new Error('x'); } }), 'authorization-invalid');
});

test('the record must cover the target, its origin, every credentialed test account and the current time', async t => {
  const { profile, origin } = await notesApp(t);
  const ok = covering(origin);
  assert.deepEqual(checkAuthorization(ok, profile, { now: NOW }), { schema: AUTHORIZATION_SCHEMA, id: ok.id, sha256: ok.sha256 });
  refused(() => checkAuthorization(EXAMPLE, profile, { now: NOW }), 'authorization-origin', /1 endpoint the run contacts is not one the record allows/);
  refused(() => checkAuthorization(record(r => { r.origins = [origin]; r.target.id = 'notes-prod'; }), profile, { now: NOW }), 'authorization-target');
  refused(() => checkAuthorization(record(r => { r.origins = [origin]; r.target.applicationId = 'billing'; }), profile, { now: NOW }), 'authorization-target');
  refused(() => checkAuthorization(record(r => { r.origins = [origin]; r.identities = ['someone-else']; }), profile, { now: NOW }), 'authorization-identity', /1 test account is not covered/);
  // The window is [validFrom, validUntil).
  refused(() => checkAuthorization(ok, profile, { now: new Date('2026-10-06T23:59:59Z') }), 'authorization-window', /not valid yet/);
  assert.equal(checkAuthorization(ok, profile, { now: new Date('2026-10-07T00:00:00Z') }).id, ok.id);
  refused(() => checkAuthorization(ok, profile, { now: new Date('2026-10-14T00:00:00Z') }), 'authorization-window', /has expired/);
  refused(() => checkAuthorization(ok, profile, {}), 'authorization-clock');
  // The anonymous actor holds no credential, so it needs no identity in the record.
  assert.ok(!ok.identities.includes('anonymous'));
});

test('a refusal (no record, expired, another origin, an edited record) sends no request at all', async t => {
  const app = await notesApp(t);
  for (const [name, options, code] of [
    ['no record', {}, 'authorization-missing'],
    ['expired', { record: covering(app.origin), now: new Date('2026-11-01T00:00:00Z') }, 'authorization-window'],
    ['another origin', { record: EXAMPLE }, 'authorization-origin'],
    ['edited without recomputing the checksum', { record: { ...covering(app.origin), validUntil: '2027-01-01T00:00:00Z' } }, 'authorization-checksum'],
  ]) await assert.rejects(runAuthorized(app.profile, { env, now: NOW, ...options }), error => error instanceof AuthorizationError && error.code === code, name);
  assert.equal(app.requests(), 0, 'no request reached the app');
});

test('runAuthorized checks the window before every request: once it ends mid-run nothing more is sent and the run is refused', async t => {
  const app = await notesApp(t), ok = covering(app.origin), now = new Date(Date.parse(ok.validUntil) - 1000);
  let sent = 0, refusedSends = 0;
  await assert.rejects(runAuthorized(app.profile, { env, now, record: ok, run: async (profile, { beforeRequest }) => {
    // The connector calls beforeRequest immediately before each request it sends, on whichever transport it uses.
    const transport = async (...args) => { beforeRequest(); return observeHttp(...args); };
    await transport(profile.origin, { method: 'GET', path: '/me' }, { credential: TOKEN }); sent++;
    await new Promise(resolve => setTimeout(resolve, 1200));
    await transport(profile.origin, { method: 'GET', path: '/me' }, { credential: TOKEN }).catch(error => { if (error.code === 'authorization-window-ended') refusedSends++; });
    return { counts: {} };
  } }), error => error instanceof AuthorizationError && error.code === 'authorization-window-ended');
  assert.deepEqual([sent, refusedSends, app.requests()], [1, 1, 1], 'the request after the end was never sent');
});

test('runAuthorized checks the window once more before it returns: a run whose window ends after its last request is refused', async t => {
  const app = await notesApp(t), ok = covering(app.origin), now = new Date(Date.parse(ok.validUntil) - 1000);
  let sent = 0;
  await assert.rejects(runAuthorized(app.profile, { env, now, record: ok, run: async (profile, { beforeRequest }) => {
    // The connector calls beforeRequest immediately before each request it sends, on whichever transport it uses.
    const transport = async (...args) => { beforeRequest(); return observeHttp(...args); };
    await transport(profile.origin, { method: 'GET', path: '/me' }, { credential: TOKEN }); sent++;
    await new Promise(resolve => setTimeout(resolve, 1200)); // the window ends here; nothing is sent after it
    return { counts: {} };
  } }), error => error instanceof AuthorizationError && error.code === 'authorization-window-ended');
  assert.deepEqual([sent, app.requests()], [1, 1]);
});

test('runAuthorized gives the run a guarded observer factory: an observer built by it reads nothing once the window ends', async t => {
  const app = await notesApp(t), ok = covering(app.origin), now = new Date(Date.parse(ok.validUntil) - 1000);
  let refusedMark = false;
  await assert.rejects(runAuthorized(app.profile, { env, now, record: ok, run: async (profile, { observerFactory }) => {
    const [audit] = observerFactory([{ id: 'audit', type: 'http-audit', origin: profile.origin, path: '/me', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', itemsPointer: '/items', pageLimit: 10,
      fields: { id: '/id', actor: '/actor', action: '/action' }, actions: { 'note.create': 'insert' } }], { env });
    await audit.start().catch(() => {}); // inside the window: one read reaches the app
    await new Promise(resolve => setTimeout(resolve, 1200));
    await audit.mark().catch(error => { refusedMark = error.code === 'authorization-window-ended'; });
    await audit.stop();
    return { counts: {} };
  } }), error => error instanceof AuthorizationError && error.code === 'authorization-window-ended');
  assert.deepEqual([refusedMark, app.requests()], [true, 1], 'the read after the end was refused before it was sent');
});

test('the record never changes a verdict: the same run with and without it differs only by the stamp', async t => {
  for (const mode of ['secure', 'leaky']) {
    const app = await notesApp(t, mode);
    const plain = await runHttpAssessment(app.profile, { env });
    const authorized = await runAuthorized(app.profile, { env, now: NOW, record: covering(app.origin) });
    validateHttpRunEvidence(authorized);
    const expectedSuite = createRegistry({ profiles: [app.profile], env: {} }).exportSuite('notes');
    validateHttpRunEvidence(authorized, { expectedSuite });
    assert.deepEqual(authorized.authorization, { schema: AUTHORIZATION_SCHEMA, id: 'acme-notes-staging-2026-10', sha256: covering(app.origin).sha256 });
    assert.equal(Object.hasOwn(plain, 'authorization'), false);
    // Every field a verdict, its scope or its identity rests on, not only a few.
    for (const key of ['profileHash', 'suiteHash', 'evaluatorHash', 'targetConfigHash', 'counts', 'checksTotal', 'limitations', 'scopeLabel', 'evidenceOrigin', 'targetId', 'buildLabel', 'applicationId'])
      assert.deepEqual(authorized[key], plain[key], `${mode} ${key}`);
    assert.deepEqual(Object.keys(authorized).filter(k => k !== 'authorization').sort(), Object.keys(plain).sort(), 'no other field added or dropped');
    assert.deepEqual(authorized.results.map(r => [r.id, r.status, r.assertions.map(a => a.status)]), plain.results.map(r => [r.id, r.status, r.assertions.map(a => a.status)]), mode);
  }
});

test('built-in fixture targets need no record and run unchanged; every configured target needs one', async () => {
  const registry = createRegistry({ profiles: [], env: {} });
  for (const entry of registry.list()) assert.equal(needsAuthorization(entry), false, entry.id);
  assert.equal(needsAuthorization({ kind: 'http-contract' }), true);
  const repaired = await runAssessment('demo-repaired');
  assert.equal(repaired.suiteHash, SUITE.hash);
  assert.equal(Object.hasOwn(repaired, 'authorization'), false);
  assert.equal(repaired.counts.fail, 0);
});

test('every endpoint the run contacts is in the record, observers included; an unknown observer type is refused', async t => {
  const { profile, origin } = await notesApp(t);
  const withObservers = observers => ({ ...profile, observers });
  const audit = { id: 'audit', type: 'http-audit', origin: 'http://127.0.0.1:4555', path: '/audit' };
  const pg = { id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_PG', tables: [{ table: 'notes', key: 'id' }] };
  refused(() => checkAuthorization(covering(origin), withObservers([audit]), { now: NOW }), 'authorization-origin', /1 endpoint the run contacts is not one the record allows/);
  refused(() => checkAuthorization(covering(origin), withObservers([pg]), { now: NOW }), 'authorization-origin');
  assert.deepEqual(contactedEndpoints(withObservers([audit, pg])), [origin, 'http://127.0.0.1:4555', 'tcp://127.0.0.1:5432']);
  checkAuthorization(record(r => { r.origins = [origin, 'http://127.0.0.1:4555', 'tcp://127.0.0.1:5432']; }), withObservers([audit, pg]), { now: NOW });
  // Observers that contact nothing (a local file, a loopback sink the app reaches) need no entry.
  checkAuthorization(covering(origin), withObservers([{ id: 'log', type: 'sqlite-audit', path: '/tmp/x.db' }, { id: 'out', type: 'egress-recorder', port: 18089 }]), { now: NOW });
  refused(() => checkAuthorization(covering(origin), withObservers([{ id: 'x', type: 'vendor-api' }]), { now: NOW }), 'authorization-origin', /does not know/);
  // A trailing slash on the target origin is the same origin, and no message echoes an endpoint.
  checkAuthorization(covering(origin), { ...profile, origin: `${origin}/` }, { now: NOW });
  assert.throws(() => checkAuthorization(covering(origin), withObservers([audit]), { now: NOW }), error => !error.message.includes('4555'));
});

test('every credentialed actor is covered by its principal, whatever its credential or use; origins match exactly', async t => {
  const { profile, origin } = await notesApp(t);
  const ok = covering(origin);
  const actors = extra => ({ ...profile, actors: { ...profile.actors, ...extra } });
  for (const [name, extra] of [
    ['a second bearer actor', { admin: { principalId: 'admin-1', credentialEnv: 'SCOPEHAVEN_TARGET_ADMIN', identityValue: 'admin-1' } }],
    ['a cookie actor', { owner: { principalId: 'owner-1', credentialEnv: 'SCOPEHAVEN_TARGET_OWNER', credentialCookie: 'session', identityValue: 'owner-1' } }],
    ['an actor no check uses', { spare: { principalId: 'spare-1', credentialEnv: 'SCOPEHAVEN_TARGET_SPARE' } }],
  ]) assert.throws(() => checkAuthorization(ok, actors(extra), { now: NOW }), error => error.code === 'authorization-identity' && /1 test account is not covered/.test(error.message), name);
  // Coverage is by principalId, never by the value the login proof expects.
  const shifted = { ...profile, actors: { ...profile.actors, member: { ...profile.actors.member, principalId: 'member-1-alt', identityValue: 'member-1' } } };
  refused(() => checkAuthorization(ok, shifted, { now: NOW }), 'authorization-identity');
  // An origin matches exactly, never by prefix (:580 does not cover :5800).
  refused(() => checkAuthorization(record(r => { r.origins = [origin.slice(0, -1)]; }), profile, { now: NOW }), 'authorization-origin');
});

test('an unknown or missing kind needs a record; dates are real calendar instants in a bounded window', () => {
  for (const entry of [undefined, null, {}, { kind: 'vendor-adapter' }, { kind: 'http-contract' }]) assert.equal(needsAuthorization(entry), true, JSON.stringify(entry));
  for (const kind of BUILT_IN_KINDS) assert.equal(needsAuthorization({ kind }), false, kind);
  for (const [name, edit, pattern] of [
    ['February 30', r => { r.validFrom = '2026-02-30T00:00:00Z'; }, /"validFrom" must be an ISO 8601 UTC instant/],
    ['hour 24', r => { r.validUntil = '2026-10-13T24:00:00Z'; }, /"validUntil" must be an ISO 8601 UTC instant/],
    ['minute 60', r => { r.signedAt = '2026-10-06T18:60:00Z'; }, /"signedAt" must be an ISO 8601 UTC instant/],
    ['a window over 366 days', r => { r.validUntil = '2027-10-14T00:00:00Z'; }, /at most 366 days/],
    ['signed after the window ends', r => { r.signedAt = '2026-10-15T00:00:00Z'; }, /"signedAt" must be before "validUntil"/],
  ]) assert.throws(() => validateAuthorization(record(edit)), error => error.code === 'authorization-invalid' && pattern.test(error.message), name);
  validateAuthorization(record(r => { r.validFrom = '2028-02-29T00:00:00Z'; r.validUntil = '2028-03-01T00:00:00Z'; r.signedAt = '2028-02-28T23:59:59Z'; }));
  // Seconds and milliseconds are optional, as the pattern says.
  validateAuthorization(record(r => { r.validFrom = '2026-10-07T00:00Z'; r.validUntil = '2026-10-14T00:00:00.500Z'; }));
});

test('the record file is a regular file, never a symlink, at most 256 KiB, and JSON', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven roe ')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const good = join(dir, 'record.json'); writeFileSync(good, JSON.stringify(EXAMPLE));
  assert.deepEqual(await readAuthorizationFile(good), EXAMPLE);
  const link = join(dir, 'link.json'); symlinkSync(good, link);
  const big = join(dir, 'big.json'); writeFileSync(big, JSON.stringify({ pad: 'x'.repeat(MAX_RECORD_BYTES) }));
  const text = join(dir, 'text.json'); writeFileSync(text, 'not json');
  // The limit is exact: a valid record padded to 256 KiB is read; one byte more is refused, never parsed.
  const padded = bytes => { const body = JSON.stringify(EXAMPLE); return body + ' '.repeat(bytes - Buffer.byteLength(body)); };
  const atLimit = join(dir, 'at-limit.json'); writeFileSync(atLimit, padded(MAX_RECORD_BYTES));
  assert.deepEqual(await readAuthorizationFile(atLimit), EXAMPLE);
  const overLimit = join(dir, 'over-limit.json'); writeFileSync(overLimit, padded(MAX_RECORD_BYTES + 1));
  // A file too large to read whole (sparse, so it takes no disk) is refused the same way, not with a read error.
  const huge = join(dir, 'huge.json'); writeFileSync(huge, ''); truncateSync(huge, 2 ** 31 + 1);
  for (const path of [link, big, overLimit, huge, text, join(dir, 'missing.json'), dir]) await assert.rejects(readAuthorizationFile(path), error => error.code === 'authorization-invalid' && !error.message.includes(dir), path);
});

test('a MySQL snapshot\'s endpoint must be in the record, as a Postgres one must', async t => {
  const { profile, origin } = await notesApp(t);
  const mysql = { id: 'db', type: 'mysql-snapshot', host: '127.0.0.1', port: 3306, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_MYSQL', tables: [{ table: 'notes', key: 'id' }] };
  const withMysql = { ...profile, observers: [mysql] };
  assert.deepEqual(contactedEndpoints(withMysql), [origin, 'tcp://127.0.0.1:3306']);
  refused(() => checkAuthorization(covering(origin), withMysql, { now: NOW }), 'authorization-origin', /1 endpoint the run contacts is not one the record allows/);
  refused(() => checkAuthorization(record(r => { r.origins = [origin, 'tcp://127.0.0.1:5432']; }), withMysql, { now: NOW }), 'authorization-origin');
  checkAuthorization(record(r => { r.origins = [origin, 'tcp://127.0.0.1:3306']; }), withMysql, { now: NOW });
});

test('a FIFO at the record path is refused at once, never waited on', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven roe fifo ')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fifo = join(dir, 'record.json'); execFileSync('mkfifo', [fifo]);
  const outcome = await Promise.race([readAuthorizationFile(fifo).then(() => 'read', error => error.code), new Promise(resolve => setTimeout(() => resolve('blocked'), 2000))]);
  // A reader that blocked is released (a writer opens and closes the FIFO), so the test ends either way.
  if (outcome === 'blocked') closeSync(openSync(fifo, 'w'));
  assert.equal(outcome, 'authorization-invalid');
});

test('the check and the run see one copy of the profile, read once', async t => {
  const { profile, origin } = await notesApp(t);
  let reads = 0;
  const shifting = { ...profile };
  // An accessor that names the covered origin first and an uncovered one after.
  Object.defineProperty(shifting, 'origin', { enumerable: true, get: () => (reads++ ? 'http://127.0.0.1:1' : origin) });
  let seen = null;
  const result = await runAuthorized(shifting, { record: covering(origin), env: {}, now: NOW, run: async given => { seen = given.origin; return { counts: {} }; } });
  assert.equal(reads, 1, 'the accessor is read once');
  assert.equal(seen, origin, 'the run gets the origin the check covered');
  assert.equal(result.authorization.id, covering(origin).id);
  // A nested accessor too: an observer's port read once, and the run gets the port the check covered.
  let portReads = 0;
  const observer = { id: 'db', type: 'pg-snapshot', host: '127.0.0.1', database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_PG', tables: [{ table: 'notes', key: 'id' }] };
  Object.defineProperty(observer, 'port', { enumerable: true, get: () => (portReads++ ? 6543 : 5432) });
  let seenPort = null;
  await runAuthorized({ ...profile, observers: [observer] }, { record: record(r => { r.origins = [origin, 'tcp://127.0.0.1:5432']; }), env: {}, now: NOW, run: async given => { seenPort = given.observers[0].port; return { counts: {} }; } });
  assert.deepEqual([portReads, seenPort], [1, 5432]);
  // A profile that is not plain data is refused under its own code, and nothing runs.
  let ran = false;
  await assert.rejects(runAuthorized({ ...profile, hook: () => 1 }, { record: covering(origin), env: {}, now: NOW, run: async () => { ran = true; return {}; } }),
    error => error instanceof AuthorizationError && error.code === 'authorization-profile');
  assert.equal(ran, false);
});

test('the boundaries hold exactly (366 days, signedAt before the end, tcp and http only, a slashed audit origin)', async t => {
  validateAuthorization(record(r => { r.validFrom = '2026-10-07T00:00:00Z'; r.validUntil = '2027-10-08T00:00:00Z'; }));
  assert.throws(() => validateAuthorization(record(r => { r.validFrom = '2026-10-07T00:00:00Z'; r.validUntil = '2027-10-08T00:00:01Z'; })), /at most 366 days/);
  assert.throws(() => validateAuthorization(record(r => { r.signedAt = r.validUntil; })), /"signedAt" must be before "validUntil"/);
  assert.throws(() => validateAuthorization(record(r => { r.origins = ['udp://127.0.0.1:53']; })), /literal loopback ones/);
  validateAuthorization(record(r => { r.origins = ['https://staging.acme.example:8443']; }));
  const { profile, origin } = await notesApp(t);
  const audit = { id: 'audit', type: 'http-audit', origin: 'http://127.0.0.1:4555/', path: '/audit' };
  checkAuthorization(record(r => { r.origins = [origin, 'http://127.0.0.1:4555']; }), { ...profile, observers: [audit] }, { now: NOW });
});


test('owned refund IDs are reserved while configured targets and unknown refund labels still require authorization',()=>{
  const profile={id:'refund-customer',name:'Configured customer',applicationId:'configured-customer',origin:'http://127.0.0.1:4318',buildLabel:'review',contextId:'customer',actors:{anon:{principalId:'anonymous'}},requiredControlIds:['allow'],checks:[{id:'allow',title:'Allowed',category:'Control',severity:'control',actorId:'anon',method:'GET',path:'/allow',evidenceRequirement:'response',assertions:[{kind:'status.equals',expected:200}]}]};
  for(const id of REFUND_TARGET_IDS)assert.throws(()=>createRegistry({profiles:[{...profile,id}],env:{}}),/cannot replace a built-in/);
  const registry=createRegistry({profiles:[profile],env:{}});
  assert.equal(needsAuthorization(registry.list().find(t=>t.id===profile.id)),true);
  assert.equal(needsAuthorization({id:'refund-not-registered',kind:'owned-refund-contract'}),true);
  assert.equal(needsAuthorization({kind:'owned-refund-contract'}),true);
  for(const id of REFUND_TARGET_IDS)assert.equal(needsAuthorization({id,kind:'owned-refund-contract'}),false);
});
