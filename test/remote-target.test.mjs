// A remote target over direct HTTPS (targetContext "operator-remote"). It runs only under an authorization
// record naming its exact origin; its host is resolved once and pinned, checked again before each request, and refused
// when an answer changes or holds an address that is not public and not named in the record; the certificate is
// verified; no redirect is followed. No real network: an injected resolver maps test host names to 127.0.0.1, where a
// TLS server with a throwaway test CA (made with the openssl command line) plays the remote staging app, and every
// TLS server counts the connections it accepts. The CLI end to end uses an IPv4 literal origin and NODE_EXTRA_CA_CERTS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, readdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, REMOTE_MARKER } from '../src/contracts.mjs';
import { remoteOriginOf, addressClass, pinRemoteTarget } from '../src/remote-target.mjs';
import { checksumAuthorization, checkAuthorization, AUTHORIZATION_SCHEMA, WINDOW_ENDED, authorizedRemote, windowGuard, instantMs } from '../src/authorization.mjs';
import { createRegistry } from '../src/registry.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { renderReport } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { compareRuns } from '../src/runner.mjs';
import { makeTestCa } from './support/test-ca.mjs';

const TOKEN = 'synthetic-remote-member-token', HOST = 'staging.remote.test';
const DAY = 86400000, iso = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z'), ago = days => iso(Date.now() - days * DAY);
const scratch = t => { const dir = mkdtempSync(join(tmpdir(), 'scopehaven remote ')); chmodSync(dir, 0o700); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; };
let pki = null;
const tls = t => { if (pki === null) { const dir = mkdtempSync(join(tmpdir(), 'scopehaven test ca ')); chmodSync(dir, 0o700); pki = makeTestCa(dir, { dnsNames: [HOST], ips: ['127.0.0.1'] }) ?? false; } if (!pki) t.skip('openssl is not available'); return pki; };

// The remote staging app over TLS. connections() counts accepted TLS connections, requests() the HTTP requests.
async function remoteApp(t, { routes = {} } = {}) {
  let connections = 0, requests = 0, sawCredential = 0;
  const { key, cert } = tls(t);
  const server = createServer({ key, cert }, (req, res) => { requests++; req.resume(); req.on('end', () => {
    const json = (s, b, h = {}) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close', ...h }); res.end(JSON.stringify(b)); };
    if (routes[req.url]) return routes[req.url](req, res, json);
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, {});
    sawCredential++;
    if (req.url === '/me') return json(200, { user: 'member-1' });
    if (req.url === '/notes') return json(200, { notes: [] });
    return json(403, {});
  }); });
  server.on('secureConnection', () => { connections++; });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { port: server.address().port, connections: () => connections, requests: () => requests, sawCredential: () => sawCredential };
}
const remoteProfile = (origin, extra = {}) => ({ id: 'remote-notes', name: 'Remote notes', applicationId: 'notes-app', origin, buildLabel: 'b1', contextId: 'synthetic-notes',
  targetContext: 'operator-remote', targetLabel: 'Notes staging (direct)',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' } }, requiredControlIds: ['WHOAMI', 'READ-NOTES'],
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] },
    { id: 'READ-NOTES', title: 'A member reads the notes list', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'GET', path: '/notes', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'ADMIN-SETTINGS', title: 'A member cannot read the admin settings', category: 'admin', severity: 'high', actorId: 'member', method: 'GET', path: '/admin/settings', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
  ], ...extra });
const env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN };
// A resolver that answers from a script: the nth lookup of a host returns answers[min(n, last)].
const scripted = answers => { let n = 0; const fn = async () => answers[Math.min(n++, answers.length - 1)]; fn.calls = () => n; return fn; };
// A record naming the remote origin (and, when given, the non-public addresses it may resolve to).
const libraryRecord = (origin, addresses = [], edit) => { const r = { schema: AUTHORIZATION_SCHEMA, id: 'remote-library', target: { id: 'remote-notes', applicationId: 'notes-app' }, origins: [origin],
  ...(addresses.length ? { addresses } : {}), identities: ['member-1'], validFrom: ago(1), validUntil: ago(-30), signer: { name: 'A. Example', role: 'Owner' }, signedAt: ago(1) }; edit?.(r); return checksumAuthorization(r); };
// What every entry point passes the connector for a remote target: the record's grant (authorizedRemote) and
// window check, with the test resolver and CA spread beside the grant.
const granted = (origin, { addresses = [], resolve, ca, beforeRequest, record = libraryRecord(origin, addresses) } = {}) => ({ beforeRequest: beforeRequest ?? windowGuard(record).check,
  remote: { ...authorizedRemote(record), ...(resolve ? { resolve } : {}), ...(ca ? { ca } : {}) } });

test('a remote origin is https://host[:port] with a host name or IPv4 address and nothing else, and needs operator-remote', () => {
  for (const [value, expected] of [['https://staging.remote.test', 'https://staging.remote.test'], ['https://Staging.Remote.Test:443/', 'https://staging.remote.test'], ['https://staging.remote.test:8443', 'https://staging.remote.test:8443'],
    ['https://203.0.113.10', 'https://203.0.113.10'], ['http://staging.remote.test', null], ['https://user:pw@staging.remote.test', null], ['https://staging.remote.test/app', null], ['https://staging.remote.test/?x=1', null],
    ['https://staging.remote.test/#x', null], ['https://[::1]:8443', null], ['https://localhost', null], ['https://-bad-.remote.test', null], ['https://1.2.3', null], ['https://3232235521', null], ['https://0x7f.0.0.1', null], ['ftp://staging.remote.test', null]])
    assert.equal(remoteOriginOf(value), expected, value);
  const valid = target => validateTargetFile({ schemaVersion: 1, targets: [target] })[0];
  assert.equal(valid(remoteProfile('https://Staging.Remote.Test:443/')).origin, 'https://staging.remote.test');
  assert.throws(() => valid(remoteProfile('http://staging.remote.test')), /remote target's origin must be https/);
  const { targetLabel: _l, targetContext: _c, ...unlabelled } = remoteProfile('https://staging.remote.test');
  assert.throws(() => valid({ ...unlabelled, targetContext: 'local-app' }), /origin must be literal loopback HTTP/);
  assert.throws(() => valid(unlabelled), /an https origin needs "targetContext": "operator-remote"/);
  assert.throws(() => valid(remoteProfile('http://127.0.0.1:4500')), /remote target's origin must be https/);
});

test('address classes: only a public address is dialled without the record naming it', () => {
  for (const [address, cls] of [['8.8.8.8', 'public'], ['1.1.1.1', 'public'], ['2606:4700:4700::1111', 'public'], ['10.1.2.3', 'private'], ['172.20.0.1', 'private'], ['172.32.0.1', 'public'],
    ['192.168.1.1', 'private'], ['127.0.0.1', 'loopback'], ['127.9.9.9', 'loopback'], ['::1', 'loopback'], ['169.254.169.254', 'metadata'], ['169.254.170.2', 'metadata'], ['100.100.100.200', 'metadata'],
    ['fd00:ec2::254', 'metadata'], ['169.254.1.1', 'link-local'], ['fe80::1', 'link-local'], ['fc00::1', 'private'], ['100.64.0.1', 'shared'], ['0.0.0.0', 'unspecified'], ['::', 'unspecified'],
    ['224.0.0.1', 'multicast'], ['ff02::1', 'multicast'], ['203.0.113.10', 'documentation'], ['2001:db8::1', 'documentation'], ['::ffff:10.0.0.1', 'private'], ['::ffff:8.8.8.8', 'public'],
    ['240.0.0.1', 'reserved'], ['192.0.0.8', 'reserved'], ['not-an-ip', 'invalid'],
    // IPv4 carried in IPv6, in hex as well as dotted notation: mapped, translated and compatible forms; local-use NAT64; site-local.
    ['::ffff:7f00:1', 'loopback'], ['0:0:0:0:0:ffff:a9fe:a9fe', 'metadata'], ['::ffff:0:7f00:1', 'loopback'], ['::ffff:0:10.0.0.1', 'private'], ['::127.0.0.1', 'loopback'],
    ['::a00:1', 'private'], ['::ffff:808:808', 'public'], ['64:ff9b:1::a00:1', 'reserved'], ['64:ff9b::808:808', 'reserved'], ['fec0::1', 'private'], ['FE80::1%en0'.split('%')[0], 'link-local'],
    // IPv6 documentation (RFC 9637), SRv6 SIDs and the deprecated 6to4 relay anycast.
    ['3fff::1', 'documentation'], ['3fff:fff::1', 'documentation'], ['3fff:1000::1', 'public'], ['5f00::1', 'reserved'], ['192.88.99.1', 'reserved'], ['192.88.100.1', 'public']])
    assert.equal(addressClass(address), cls, address);
});

test('the record must name the remote origin exactly; addresses are IP literals', () => {
  const profile = validateTargetFile({ schemaVersion: 1, targets: [remoteProfile(`https://${HOST}:8443`)] })[0];
  const record = edit => { const r = { schema: AUTHORIZATION_SCHEMA, id: 'remote-test', target: { id: 'remote-notes', applicationId: 'notes-app' }, origins: [`https://${HOST}:8443`], identities: ['member-1'],
    validFrom: ago(1), validUntil: ago(-30), signer: { name: 'A. Example', role: 'Owner' }, signedAt: ago(1) }; edit?.(r); return checksumAuthorization(r); };
  assert.doesNotThrow(() => checkAuthorization(record(), profile, { now: new Date() }));
  for (const [name, edit, code] of [
    ['another port', r => { r.origins = [`https://${HOST}`]; }, 'authorization-origin'],
    ['another host', r => { r.origins = ['https://prod.remote.test:8443']; }, 'authorization-origin'],
    ['plain http', r => { r.origins = [`http://${HOST}:8443`]; }, 'authorization-invalid'],
    ['a path', r => { r.origins = [`https://${HOST}:8443/app`]; }, 'authorization-invalid'],
    ['not normalized', r => { r.origins = [`https://STAGING.remote.test:8443`]; }, 'authorization-invalid'],
    ['an address that is not an IP', r => { r.addresses = ['staging.remote.test']; }, 'authorization-invalid'],
    ['expired', r => { r.validFrom = ago(10); r.validUntil = ago(2); r.signedAt = ago(10); }, 'authorization-window'],
  ]) assert.throws(() => checkAuthorization(record(edit), profile, { now: new Date() }), error => error.code === code, name);
});

test('refusals before any request: a private, loopback or metadata answer the record does not name, an unresolvable host', async t => {
  const app = await remoteApp(t), origin = `https://${HOST}:${app.port}`, { ca } = tls(t);
  for (const [answer, allowed, code] of [[['127.0.0.1'], [], 'remote-address-refused'], [['10.0.0.5'], [], 'remote-address-refused'], [['169.254.169.254'], [], 'remote-address-refused'],
    [['8.8.8.8', '10.0.0.5'], ['8.8.8.8'], 'remote-address-refused'], [['127.0.0.1'], ['127.0.0.2'], 'remote-address-refused']]) {
    await assert.rejects(runHttpAssessment(remoteProfile(origin), { env, ...granted(origin, { addresses: allowed, resolve: scripted([answer]), ca }) }), error => error.code === code, JSON.stringify(answer));
  }
  await assert.rejects(runHttpAssessment(remoteProfile(origin), { env, ...granted(origin, { resolve: async () => { throw new Error('ENOTFOUND'); }, ca }) }), error => error.code === 'remote-dns-failed');
  assert.equal(app.connections(), 0, 'no refused run connected to the target');
});

test('a changed DNS answer refuses the run: before the first request nothing is sent, mid-run the rest is not sent, and no run is returned', async t => {
  const app = await remoteApp(t), origin = `https://${HOST}:${app.port}`, { ca } = tls(t);
  const changed = scripted([['127.0.0.1'], ['127.0.0.2']]);
  await assert.rejects(runHttpAssessment(remoteProfile(origin), { env, ...granted(origin, { addresses: ['127.0.0.1', '127.0.0.2'], resolve: changed, ca }) }), error => error.code === 'remote-dns-changed');
  assert.equal(app.connections(), 0, 'the answer changed before the first request: nothing was sent');
  const later = scripted([['127.0.0.1'], ['127.0.0.1'], ['127.0.0.1'], ['127.0.0.2']]);
  await assert.rejects(runHttpAssessment(remoteProfile(origin), { env, ...granted(origin, { addresses: ['127.0.0.1', '127.0.0.2'], resolve: later, ca }) }), error => error.code === 'remote-dns-changed');
  assert.equal(app.connections(), 2, 'the two requests before the change were sent, none after it');
  // The same answer in another order is the same answer.
  const pin = await pinRemoteTarget(origin, { resolve: scripted([['127.0.0.1', '127.0.0.2'], ['127.0.0.2', '127.0.0.1']]), allowedAddresses: ['127.0.0.1', '127.0.0.2'] });
  await pin.recheck();
  assert.equal(pin.address, '127.0.0.1');
});

test('an authorized remote run: TLS verified for the host, every request to the pinned address, the run says it was remote, and its passes need a same-route control', async t => {
  const app = await remoteApp(t), origin = `https://${HOST}:${app.port}`, { ca } = tls(t);
  const resolve = scripted([['127.0.0.1']]);
  const run = await runHttpAssessment(remoteProfile(origin), { env, ...granted(origin, { addresses: ['127.0.0.1'], resolve, ca }) });
  assert.deepEqual(run.counts, { pass: 3, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 });
  assert.equal(resolve.calls(), 1 + app.requests(), 'one lookup to pin, then one check per request');
  assert.ok(app.sawCredential() > 0, 'the credential reached the authorized origin');
  assert.deepEqual([run.targetContext, run.targetLabel], ['operator-remote', 'Notes staging (direct)']);
  assert.ok(run.scopeLabel.startsWith('remote target over HTTPS: Notes staging (direct). '));
  assert.ok(run.limitations.some(l => l.includes(REMOTE_MARKER)));
  assert.ok(!JSON.stringify(run).includes(HOST), 'the host is in the profile, not the run');
  const expectedSuite = createRegistry({ profiles: [remoteProfile(origin)], env: {} }).exportSuite('remote-notes');
  validateHttpRunEvidence(run, { expectedSuite });
  // The remote sentence is bound to the context: a remote run without it, or relabelled local, is refused.
  const stripped = structuredClone(run); stripped.limitations = stripped.limitations.filter(l => !l.includes(REMOTE_MARKER));
  assert.throws(() => validateHttpRunEvidence(stripped), error => error.code === 'invalid-run-evidence');
  const relabelled = structuredClone(run); relabelled.targetContext = 'local-app'; relabelled.targetLabel = null; relabelled.scopeLabel = relabelled.scopeLabel.replace(/^remote target over HTTPS: [^.]*\. /, '');
  assert.throws(() => validateHttpRunEvidence(relabelled), error => error.code === 'invalid-run-evidence');
  const gate = summarizeGate({ candidate: run, expectedSuite });
  assert.deepEqual([gate.exitCode, gate.reasons, gate.current.targetContext], [1, ['remote-pass-unpaired'], 'operator-remote'], 'ADMIN-SETTINGS has no same-route control');
  assert.match(renderReport(run), /Not clean on the remote target:<\/strong> ADMIN-SETTINGS/);
  // On a remote target too, the comparison and SARIF read the unpaired pass as the gate does.
  const compared = compareRuns(run, run), admin = compared.rows.find(r => r.id === 'ADMIN-SETTINGS');
  assert.deepEqual([admin.transition, admin.transitionReason], ['unverified', 'candidate-remote-pass-unpaired']);
  assert.ok(compared.reasons.some(r => r.includes('remote-pass-unpaired: ADMIN-SETTINGS') && r.includes('a gateway in front of the target')), JSON.stringify(compared.reasons));
  const sarif = renderSarif(run).runs[0], adminResult = sarif.results.find(r => r.ruleId === 'ADMIN-SETTINGS');
  assert.deepEqual([adminResult.kind, adminResult.properties.scopehavenUnpaired, sarif.properties.unpairedPasses.checks], ['review', 'remote-pass-unpaired', ['ADMIN-SETTINGS']]);
  assert.match(adminResult.message.text, /^PASS, NOT CLEAN ON THE REMOTE TARGET: /);
  // The certificate is checked: without the test CA, or for a name the certificate does not carry, nothing reads pass.
  const before = app.requests();
  const untrusted = await runHttpAssessment(remoteProfile(origin), { env, ...granted(origin, { addresses: ['127.0.0.1'], resolve: scripted([['127.0.0.1']]) }) });
  assert.equal(untrusted.counts.pass, 0); assert.equal(app.requests(), before, 'no HTTP request completed a handshake');
  const otherOrigin = `https://other.remote.test:${app.port}`;
  const otherName = await runHttpAssessment(remoteProfile(otherOrigin), { env, ...granted(otherOrigin, { addresses: ['127.0.0.1'], resolve: scripted([['127.0.0.1']]), ca }) });
  assert.equal(otherName.counts.pass, 0); assert.equal(app.requests(), before);
});

test('a redirect off the pinned origin is a response, never followed', async t => {
  const decoy = await remoteApp(t);
  const app = await remoteApp(t, { routes: { '/admin/settings': (_req, _res, json) => json(302, {}, { Location: `https://${HOST}:${decoy.port}/admin/settings` }) } });
  const { ca } = tls(t);
  const run = await runHttpAssessment(remoteProfile(`https://${HOST}:${app.port}`), { env, ...granted(`https://${HOST}:${app.port}`, { addresses: ['127.0.0.1'], resolve: scripted([['127.0.0.1']]), ca }) });
  assert.equal(run.results.find(r => r.id === 'ADMIN-SETTINGS').status, 'fail', '302 is not the 403 the check expects');
  assert.equal(decoy.connections(), 0, 'the redirect target was never contacted');
});

test('assess end to end: a remote target runs only under a record naming its origin and, for a non-public address, that address', async t => {
  const app = await remoteApp(t), origin = `https://127.0.0.1:${app.port}`, { caFile } = tls(t), dir = scratch(t);
  const profiles = join(dir, 'profiles.json');
  writeFileSync(profiles, JSON.stringify({ schemaVersion: 1, targets: [remoteProfile(origin)] }));
  const record = edit => { const r = { schema: AUTHORIZATION_SCHEMA, id: 'remote-cli', target: { id: 'remote-notes', applicationId: 'notes-app' }, origins: [origin], identities: ['member-1'],
    validFrom: ago(1), validUntil: ago(-30), signer: { name: 'A. Example', role: 'Owner' }, signedAt: ago(1) }; edit?.(r); const path = join(dir, `record-${Math.random().toString(16).slice(2)}.json`); writeFileSync(path, JSON.stringify(checksumAuthorization(r))); return path; };
  const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
  const assess = (args, extraEnv = {}) => new Promise(resolve => {
    const child = spawn(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH, SCOPEHAVEN_TARGET_MEMBER: TOKEN, NODE_EXTRA_CA_CERTS: caFile, ...extraEnv } });
    let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
  for (const [name, path, pattern] of [
    ['no record', null, /authorization refused \(authorization-missing\)/],
    ['a record for the loopback forwarder, not this origin', record(r => { r.origins = ['http://127.0.0.1:4500']; }), /authorization refused \(authorization-origin\)/],
    ['the origin, but not the loopback address it is', record(), /remote target's host resolves to a loopback address the authorization record does not name/],
  ]) {
    const r = await assess(['--config', profiles, '--target', 'remote-notes', '--out', join(dir, `out-${name.length}`), ...(path ? ['--authorization', path] : [])]);
    assert.equal(r.code, 2, `${name}: ${r.stderr}`); assert.match(r.stderr, pattern, name);
  }
  assert.equal(app.connections(), 0);
  const r = await assess(['--config', profiles, '--target', 'remote-notes', '--out', join(dir, 'out-ok'), '--authorization', record(x => { x.addresses = ['127.0.0.1']; })]);
  assert.equal(r.code, 1, r.stderr);
  const printed = JSON.parse(r.stdout);
  assert.deepEqual([printed.counts.pass, printed.remoteUnpaired], [3, ['ADMIN-SETTINGS']]);
  const saved = JSON.parse(readFileSync(join(dir, 'out-ok', 'runs', readdirSync(join(dir, 'out-ok', 'runs')).find(f => f.endsWith('.json'))), 'utf8')).core;
  assert.equal(saved.targetContext, 'operator-remote'); assert.equal(saved.authorization.id, 'remote-cli');
  assert.ok(app.connections() > 0);
});

test('the gate and the dashboard report a remote refusal by its code, with nothing sent', async t => {
  const app = await remoteApp(t), origin = `https://127.0.0.1:${app.port}`, dir = scratch(t);
  const profiles = join(dir, 'profiles.json');
  writeFileSync(profiles, JSON.stringify({ schemaVersion: 1, targets: [remoteProfile(origin)] }));
  const recordPath = join(dir, 'record.json');
  writeFileSync(recordPath, JSON.stringify(checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: 'remote-gate', target: { id: 'remote-notes', applicationId: 'notes-app' }, origins: [origin], identities: ['member-1'],
    validFrom: ago(1), validUntil: ago(-30), signer: { name: 'A. Example', role: 'Owner' }, signedAt: ago(1) })));
  const { runGate } = await import('../integrations/regression-gate/gate.mjs');
  const summary = await runGate({ targetId: 'remote-notes', configFile: profiles, outputDirectory: join(dir, 'gate'), authorizationFile: recordPath }, { env });
  assert.deepEqual([summary.exitCode, summary.reasons], [2, ['remote-address-refused']]);
  const { startServer } = await import('../src/server.mjs'), { loadProfiles } = await import('../src/registry.mjs'), { request } = await import('node:http');
  const server = await startServer({ port: 0, dataDir: join(dir, 'data'), profiles: await loadProfiles(profiles), env, authorizationFile: recordPath });
  try {
    const payload = JSON.stringify({ targetId: 'remote-notes' });
    const answer = await new Promise((resolve, reject) => {
      const req = request(`${server.origin}/api/runs`, { method: 'POST', agent: false, headers: { Authorization: `Bearer ${server.accessToken}`, 'Content-Type': 'application/json', 'X-Scopehaven-Request': '1', 'Content-Length': Buffer.byteLength(payload) } }, res => {
        let text = ''; res.on('data', d => { text += d; }); res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(text) }));
      });
      req.on('error', reject); req.end(payload);
    });
    assert.deepEqual([answer.status, answer.json.code], [403, 'remote-address-refused']);
  } finally { await server.close(); }
  assert.equal(app.connections(), 0);
});

// The authorization window applies to a remote target's requests as to loopback ones. The
// remote app holds every response until hold(at) says and records when each TCP connection arrived; with hold set just past
// the record's validUntil, the window ends while the run waits on the remote target. A request the check let through left
// before validUntil and arrives within milliseconds; one sent after the held response would arrive 300 ms or more after it.
async function slowRemoteApp(t) {
  let holdUntil = 0;
  const arrivals = [], paths = [], { key, cert } = tls(t);
  const server = createServer({ key, cert }, (req, res) => { paths.push(req.url); req.resume(); req.on('end', () => setTimeout(() => {
    const json = (s, b) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(b)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, {});
    if (req.url === '/me') return json(200, { user: 'member-1' });
    if (req.url === '/notes') return json(200, { notes: [] });
    return json(403, {});
  }, Math.max(0, holdUntil - Date.now()))); });
  server.on('connection', () => { arrivals.push(Date.now()); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { port: server.address().port, arrivals, paths, hold: at => { holdUntil = at; } };
}
const ARRIVAL_SLACK_MS = 200;
const allBefore = (times, until, what = 'a connection') => assert.ok(times.every(at => at < until + ARRIVAL_SLACK_MS), `${what} arrived ${Math.max(...times) - until} ms after validUntil`);
// The record is valid until `ms` from now; if the entry point took longer than that just to start (a loaded machine), it
// refused at the start and nothing reached the target, and the attempt is repeated once with a longer window. A window
// shorter than the request timeout (3000 ms) keeps the held response, not the timeout, as what the run waits on.
async function remoteWindowEndsMidRun(app, recordUntil, run, windows = [2500, 15000]) {
  for (const ms of windows) {
    const until = Date.now() + ms, before = app.arrivals.length, pathsBefore = app.paths.length;
    app.hold(until + 300);
    const result = await run(recordUntil(new Date(until).toISOString()));
    const arrivals = app.arrivals.slice(before);
    if (arrivals.length) return { until, result, arrivals, paths: app.paths.slice(pathsBefore) };
  }
  assert.fail('the run never reached the remote target inside its window');
}
const windowRecord = (origin, targetId, validUntil) => checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: 'remote-window', target: { id: targetId, applicationId: 'notes-app' }, origins: [origin], addresses: ['127.0.0.1'],
  identities: ['member-1'], validFrom: ago(1), validUntil, signer: { name: 'A. Example', role: 'Owner' }, signedAt: ago(1) });
// One check, no identity probe: its one request is the run's last contact with the remote target.
const oneRequestRemote = origin => ({ ...remoteProfile(origin), id: 'remote-one', actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER' } }, requiredControlIds: ['READ-NOTES'],
  checks: remoteProfile(origin).checks.filter(c => c.id === 'READ-NOTES') });
const savedRunCount = out => existsSync(join(out, 'runs')) ? readdirSync(join(out, 'runs')).filter(f => f.endsWith('.json')).length : 0;

test('assess holds a remote target to the record\'s window: no request after validUntil, and a run whose window ends is not saved', async t => {
  const app = await slowRemoteApp(t), origin = `https://127.0.0.1:${app.port}`, { caFile } = tls(t), dir = scratch(t);
  const profiles = join(dir, 'profiles.json');
  writeFileSync(profiles, JSON.stringify({ schemaVersion: 1, targets: [remoteProfile(origin), oneRequestRemote(origin)] }));
  const recordFor = targetId => validUntil => { const path = join(dir, `record-${targetId}-${Date.now()}.json`); writeFileSync(path, JSON.stringify(windowRecord(origin, targetId, validUntil))); return path; };
  const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
  const assess = args => new Promise(resolve => {
    const child = spawn(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH, SCOPEHAVEN_TARGET_MEMBER: TOKEN, NODE_EXTRA_CA_CERTS: caFile } });
    let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
  // The window ends while the run waits on the remote target: the next request is never sent.
  const out = join(dir, 'out-window');
  let r = await remoteWindowEndsMidRun(app, recordFor('remote-notes'), path => assess(['--config', profiles, '--target', 'remote-notes', '--out', out, '--authorization', path]));
  assert.equal(r.result.code, 2, r.result.stderr);
  assert.match(r.result.stderr, /authorization refused \(authorization-window-ended\)/);
  allBefore(r.arrivals, r.until);
  assert.equal(savedRunCount(out), 0, 'no run was saved');
  // The window ends after the run's one request was sent: only the check made immediately before saving refuses it.
  const outOne = join(dir, 'out-after-last');
  r = await remoteWindowEndsMidRun(app, recordFor('remote-one'), path => assess(['--config', profiles, '--target', 'remote-one', '--out', outOne, '--authorization', path]));
  assert.equal(r.result.code, 2, r.result.stderr);
  assert.match(r.result.stderr, /authorization refused \(authorization-window-ended\)/);
  assert.deepEqual([r.arrivals.length, r.paths], [1, ['/notes']]);
  allBefore(r.arrivals, r.until);
  assert.equal(savedRunCount(outOne), 0, 'no run was saved');
});

test('the dashboard run path and runAuthorized hold a remote target to the window: no request and no DNS lookup after validUntil, nothing saved', async t => {
  const app = await slowRemoteApp(t), origin = `https://${HOST}:${app.port}`, { ca } = tls(t), dir = scratch(t);
  // The injected resolver answers 127.0.0.1, a loopback address the record names (addresses), and records when it was asked.
  const lookups = [], resolve = async () => { lookups.push(Date.now()); return ['127.0.0.1']; };
  const profilesFile = join(dir, 'profiles.json');
  writeFileSync(profilesFile, JSON.stringify({ schemaVersion: 1, targets: [remoteProfile(origin)] }));
  const { startServer } = await import('../src/server.mjs'), { loadProfiles } = await import('../src/registry.mjs'), { request } = await import('node:http');
  const { runAuthorized } = await import('../integrations/roe/run.mjs');
  const registry = createRegistry({ profiles: await loadProfiles(profilesFile), env });
  // The dashboard's own run path, with only the test resolver and CA added to what it passes the registry (the record's
  // window check and addresses included).
  const recordFile = join(dir, 'record.json'), dataDir = join(dir, 'data');
  const server = await startServer({ port: 0, dataDir, profiles: await loadProfiles(profilesFile), env, authorizationFile: recordFile,
    assess: (id, options) => registry.run(id, { ...options, remote: { ...options?.remote, resolve, ca } }) });
  t.after(() => server.close());
  const postRun = () => new Promise((done, reject) => {
    const payload = JSON.stringify({ targetId: 'remote-notes' });
    const req = request(`${server.origin}/api/runs`, { method: 'POST', agent: false, headers: { Authorization: `Bearer ${server.accessToken}`, 'Content-Type': 'application/json', 'X-Scopehaven-Request': '1', 'Content-Length': Buffer.byteLength(payload) } }, res => {
      let text = ''; res.on('data', d => { text += d; }); res.on('end', () => done({ status: res.statusCode, json: JSON.parse(text) }));
    });
    req.on('error', reject); req.end(payload);
  });
  let lookupsBefore = lookups.length;
  let r = await remoteWindowEndsMidRun(app, validUntil => { writeFileSync(recordFile, JSON.stringify(windowRecord(origin, 'remote-notes', validUntil))); return recordFile; }, () => postRun(), [1500, 2500]);
  assert.deepEqual([r.result.status, r.result.json.code], [403, WINDOW_ENDED], JSON.stringify(r.result.json));
  allBefore(r.arrivals, r.until);
  allBefore(lookups.slice(lookupsBefore), r.until, 'a DNS lookup');
  const { createStore } = await import('../src/store.mjs'), store = createStore(dataDir); await store.ready;
  assert.deepEqual(await store.list(), [], 'no run was saved');
  // runAuthorized, the checked library path: the real connector, with the test resolver and CA added to what it passes.
  lookupsBefore = lookups.length;
  r = await remoteWindowEndsMidRun(app, validUntil => windowRecord(origin, 'remote-notes', validUntil),
    record => runAuthorized(remoteProfile(origin), { record, env, run: (profile, options) => runHttpAssessment(profile, { ...options, remote: { ...options.remote, resolve, ca } }) }).then(run => ({ run }), error => ({ error })), [1500, 2500]);
  assert.equal(r.result.error?.code, WINDOW_ENDED, JSON.stringify(r.result));
  allBefore(r.arrivals, r.until);
  allBefore(lookups.slice(lookupsBefore), r.until, 'a DNS lookup');
});

test('the connector makes the window check before a remote host is resolved: a check that refuses stops the run with no lookup and no connection', async t => {
  const app = await remoteApp(t), { ca } = tls(t), resolve = scripted([['127.0.0.1']]);
  const ended = () => { throw Object.assign(new Error('the window ended'), { code: WINDOW_ENDED }); };
  await assert.rejects(runHttpAssessment(remoteProfile(`https://${HOST}:${app.port}`), { env, ...granted(`https://${HOST}:${app.port}`, { addresses: ['127.0.0.1'], resolve, ca, beforeRequest: ended }) }), error => error.code === WINDOW_ENDED);
  assert.deepEqual([resolve.calls(), app.connections()], [0, 0]);
});

test('a slow DNS check that runs past validUntil sends nothing: the window is checked again after it, immediately before the connection', async t => {
  const app = await remoteApp(t), { ca } = tls(t), origin = `https://${HOST}:${app.port}`;
  // The record's window on an injected clock, which passes validUntil while the third lookup (the DNS check before the
  // second request) is still pending; that lookup then takes 150 ms more, as a slow system resolver can.
  const record = libraryRecord(origin, ['127.0.0.1']), until = instantMs(record.validUntil);
  let clock = until - 60000, atEnd = null;
  const resolve = scripted([['127.0.0.1']]), slow = async host => {
    const answer = await resolve(host);
    if (resolve.calls() === 3) { clock = until; atEnd = { requests: app.requests(), connections: app.connections() }; await new Promise(done => setTimeout(done, 150)); }
    return answer;
  };
  const guard = windowGuard(record, { now: () => clock });
  const outcome = await runHttpAssessment(remoteProfile(origin), { env, ...granted(origin, { record, resolve: slow, ca, beforeRequest: guard.check }) }).then(run => ({ run }), error => ({ error }));
  assert.ok(atEnd, 'the run reached its second request');
  assert.ok(atEnd.requests >= 1, 'the first request was sent inside the window');
  assert.deepEqual([app.requests(), app.connections()], [atEnd.requests, atEnd.connections], 'nothing reached the target after the window ended, the credentialed request included');
  assert.equal(resolve.calls(), 3, 'no lookup started after the window ended');
  assert.ok(guard.ended());
  // The entry points refuse such a run (windowRefusal); the connector itself returned rows or threw, and sent nothing more.
  assert.ok(outcome.run || outcome.error);
});

test('with a header key: after a slow DNS check that runs past validUntil, no request carrying X-Api-Key is sent', async t => {
  // The remote app answers the X-Api-Key actor and records each request that carried the key.
  const keyed = [], byKey = handler => (req, res, json) => { if (req.headers['x-api-key'] !== TOKEN) return json(401, {}); keyed.push(req.url); return handler(json); };
  const app = await remoteApp(t, { routes: { '/me': byKey(json => json(200, { user: 'member-1' })), '/notes': byKey(json => json(200, { notes: [] })), '/admin/settings': byKey(json => json(403, {})) } });
  const { ca } = tls(t), origin = `https://${HOST}:${app.port}`;
  const profile = remoteProfile(origin, { actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', credentialHeader: 'X-Api-Key', identityValue: 'member-1' } } });
  const record = libraryRecord(origin, ['127.0.0.1']), until = instantMs(record.validUntil);
  let clock = until - 60000, atEnd = null;
  const resolve = scripted([['127.0.0.1']]), slow = async host => {
    const answer = await resolve(host);
    if (resolve.calls() === 3) { clock = until; atEnd = { keyed: keyed.length, connections: app.connections() }; await new Promise(done => setTimeout(done, 150)); }
    return answer;
  };
  const guard = windowGuard(record, { now: () => clock });
  await runHttpAssessment(profile, { env, ...granted(origin, { record, resolve: slow, ca, beforeRequest: guard.check }) }).catch(() => null);
  assert.ok(atEnd && atEnd.keyed >= 1, 'the key was sent inside the window');
  assert.deepEqual([keyed.length, app.connections()], [atEnd.keyed, atEnd.connections], 'no request, and so no key, reached the target after the window ended');
  assert.equal(resolve.calls(), 3);
  assert.ok(guard.ended());
});

test('no proxy and no shared agent: with NODE_USE_ENV_PROXY=1 and HTTPS_PROXY set, the run reaches the target directly while a control request in the same process goes to the proxy', async t => {
  const app = await remoteApp(t), { caFile } = tls(t), origin = `https://${HOST}:${app.port}`;
  // A counting proxy that records the CONNECT line of each connection and tunnels nothing.
  const { createServer: createTcpServer } = await import('node:net');
  const connects = [];
  const proxy = createTcpServer(socket => { socket.once('data', data => { connects.push(String(data).split('\r\n')[0]); socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); }); socket.on('error', () => {}); });
  await new Promise(done => proxy.listen(0, '127.0.0.1', done));
  t.after(() => new Promise(done => proxy.close(done)));
  const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
  const child = `
    const { readFileSync } = await import('node:fs'), https = await import('node:https');
    const { runHttpAssessment } = await import(${JSON.stringify(new URL('../src/http-connector.mjs', import.meta.url).href)});
    const { authorizedRemote, windowGuard } = await import(${JSON.stringify(new URL('../src/authorization.mjs', import.meta.url).href)});
    const ca = readFileSync(process.env.T_CA), record = JSON.parse(process.env.T_RECORD), lookup = (_h, o, cb) => o?.all ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(null, '127.0.0.1', 4);
    const run = await runHttpAssessment(JSON.parse(process.env.T_PROFILE), { env: { SCOPEHAVEN_TARGET_MEMBER: process.env.T_TOKEN }, beforeRequest: windowGuard(record).check,
      remote: { ...authorizedRemote(record), resolve: async () => ['127.0.0.1'], ca } });
    console.log(JSON.stringify(run.counts));
    await new Promise(done => { const req = https.get('https://control.remote.test:' + process.env.T_PORT + '/me', { ca, lookup, timeout: 3000 }, res => { res.resume(); res.on('end', done); }); req.on('error', done); req.on('timeout', () => req.destroy()); });`;
  const result = await new Promise(resolve => {
    const proc = spawn(process.execPath, ['--input-type=module', '-e', child], { env: { PATH: process.env.PATH, NODE_USE_ENV_PROXY: '1', HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, https_proxy: proxyUrl, http_proxy: proxyUrl,
      T_CA: caFile, T_PORT: String(app.port), T_TOKEN: TOKEN, T_PROFILE: JSON.stringify(remoteProfile(origin)), T_RECORD: JSON.stringify(libraryRecord(origin, ['127.0.0.1'])) } });
    let stdout = '', stderr = ''; proc.stdout.on('data', d => { stdout += d; }); proc.stderr.on('data', d => { stderr += d; });
    proc.on('close', code => resolve({ code, stdout, stderr }));
  });
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout.trim().split('\n')[0]), { pass: 3, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }, 'the target served the run');
  assert.ok(app.requests() > 0);
  assert.deepEqual(connects.filter(line => line.includes(HOST)), [], 'no assessment request went to the proxy');
  assert.ok(connects.some(line => line.startsWith('CONNECT control.remote.test:')), `the proxy setting was live: the control request reached it (${JSON.stringify(connects)})`);
});

test('the library entry refuses a remote target without a grant from a record naming its origin, and a window check, before any lookup', async t => {
  const app = await remoteApp(t), { ca } = tls(t), origin = `https://${HOST}:${app.port}`, resolve = scripted([['127.0.0.1']]);
  const missing = error => error?.name === 'AuthorizationError' && error.code === 'authorization-missing';
  const record = libraryRecord(origin, ['127.0.0.1']), check = windowGuard(record).check;
  for (const [name, options] of [
    ['no remote option and no window check', {}],
    ['addresses with no record', { remote: { allowedAddresses: ['127.0.0.1'], resolve, ca } }],
    ['a window check, but addresses with no record', { beforeRequest: check, remote: { allowedAddresses: ['127.0.0.1'], resolve, ca } }],
    ['a grant, but no window check', { remote: { ...authorizedRemote(record), resolve, ca } }],
    ['a grant from a record for another origin', { beforeRequest: check, remote: { ...authorizedRemote(libraryRecord(`https://prod.remote.test:${app.port}`, ['127.0.0.1'])), resolve, ca } }],
    ['a look-alike grant', { beforeRequest: check, remote: { allowedAddresses: ['127.0.0.1'], resolve, ca, [Object.getOwnPropertySymbols(authorizedRemote(record))[0]]: { origins: [origin], allowedAddresses: ['127.0.0.1'] } } }],
  ]) await assert.rejects(runHttpAssessment(remoteProfile(origin), { env, ...options }), missing, name);
  // Through the registry as a library caller would use it, with no record: the same refusal.
  await assert.rejects(createRegistry({ profiles: [remoteProfile(origin)], env }).run('remote-notes', { remote: { allowedAddresses: ['127.0.0.1'], resolve, ca } }), missing, 'registry.run');
  assert.deepEqual([resolve.calls(), app.connections()], [0, 0], 'nothing was resolved or sent');
  // A copy of the grant with wider addresses dials only what the record allows.
  const narrow = libraryRecord(origin), widened = { ...authorizedRemote(narrow), allowedAddresses: ['127.0.0.1'], resolve, ca };
  await assert.rejects(runHttpAssessment(remoteProfile(origin), { env, beforeRequest: windowGuard(narrow).check, remote: widened }), error => error.code === 'remote-address-refused');
  assert.equal(app.connections(), 0);
  // With the record's grant and window check it runs.
  const run = await runHttpAssessment(remoteProfile(origin), { env, ...granted(origin, { record, resolve, ca }) });
  assert.equal(run.counts.pass, 3);
});

// A target whose TLS handshake the test holds. A TCP listener accepts each connection, calls onAccept,
// and keeps the socket paused for holdMs() before it hands it to a TLS server. That server counts every request byte it
// decrypts (none can arrive before its handshake ends) and answers 200.
async function heldHandshakeApp(t, { holdMs, onAccept = () => {} }) {
  const { createServer: createTlsServer } = await import('node:tls'), { createServer: createTcpServer } = await import('node:net');
  const { key, cert } = tls(t), sockets = new Set();
  let accepted = 0, requestBytes = 0;
  const target = createTlsServer({ key, cert }, socket => {
    let text = '';
    socket.on('error', () => {});
    socket.on('data', chunk => {
      requestBytes += chunk.length; text += chunk;
      if (text.includes('\r\n\r\n')) socket.end('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{"notes":[]}');
    });
  });
  target.on('tlsClientError', () => {});
  const listener = createTcpServer({ pauseOnConnect: true }, socket => {
    accepted++; sockets.add(socket); socket.on('error', () => {}); onAccept();
    setTimeout(() => target.emit('connection', socket), holdMs());
  });
  await new Promise(done => listener.listen(0, '127.0.0.1', done));
  t.after(() => new Promise(done => { for (const socket of sockets) socket.destroy(); listener.close(done); }));
  return { port: listener.address().port, accepted: () => accepted, requestBytes: () => requestBytes };
}

test('a connection opened before validUntil whose TLS handshake ends after it writes no request: the socket is closed, no byte of the request arrives, and the run is refused', async t => {
  // 1. The connector, on an injected clock. The window ends when the target accepts the connection, while its handshake is held.
  let clock = 0, endOnAccept = false;
  const app = await heldHandshakeApp(t, { holdMs: () => 300, onAccept: () => { if (endOnAccept) clock = until; } });
  const { ca } = tls(t), origin = `https://${HOST}:${app.port}`, profile = oneRequestRemote(origin);
  const record = libraryRecord(origin, ['127.0.0.1']), until = instantMs(record.validUntil);
  const run = async () => { clock = until - 60000; const guard = windowGuard(record, { now: () => clock });
    return { guard, run: await runHttpAssessment(profile, { env, ...granted(origin, { record, resolve: scripted([['127.0.0.1']]), ca, beforeRequest: guard.check }) }) }; };
  // Control: the same held handshake inside the window, and the request arrives.
  let r = await run();
  const outcomes = ran => ran.results.map(row => [row.trace[0].data.transportOutcome, row.trace[0].data.httpStatus]);
  assert.deepEqual([outcomes(r.run), app.accepted()], [[['complete', 200]], 1]);
  assert.ok(app.requestBytes() > 0, 'the held handshake alone does not stop the request');
  const bytesBefore = app.requestBytes();
  endOnAccept = true;
  r = await run();
  assert.equal(app.accepted(), 2, 'the connection was opened inside the window');
  assert.equal(app.requestBytes(), bytesBefore, 'no request byte arrived after the window ended, the credential included');
  assert.deepEqual(outcomes(r.run), [['network', null]], 'the request was refused, not answered');
  assert.ok(r.guard.ended());
  assert.throws(() => r.guard.check(), error => error.code === WINDOW_ENDED, 'the check every entry point makes before saving refuses the run');
  // 2. runAuthorized on the real clock, a check declaring a 10 s timeout: the handshake is held until 300 ms past validUntil.
  const { runAuthorized } = await import('../integrations/roe/run.mjs');
  let realUntil = 0;
  const live = await heldHandshakeApp(t, { holdMs: () => Math.max(realUntil, Date.now()) + 300 - Date.now() });
  const liveOrigin = `https://${HOST}:${live.port}`, slowCheck = { ...oneRequestRemote(liveOrigin), checks: oneRequestRemote(liveOrigin).checks.map(c => ({ ...c, timeoutMs: 10000 })) };
  for (const ms of [1500, 6000]) {
    realUntil = Date.now() + ms;
    const outcome = await runAuthorized(slowCheck, { record: windowRecord(liveOrigin, 'remote-one', new Date(realUntil).toISOString()), env,
      run: (p, options) => runHttpAssessment(p, { ...options, remote: { ...options.remote, resolve: async () => ['127.0.0.1'], ca } }) }).then(ran => ({ ran }), error => ({ error }));
    // A loaded machine that took longer than the window just to start refused before connecting: then once more, longer.
    if (live.accepted()) { assert.equal(outcome.error?.code, WINDOW_ENDED, JSON.stringify(outcome)); break; }
  }
  assert.equal(live.accepted(), 1, 'the run reached the target inside its window');
  assert.equal(live.requestBytes(), 0, 'no request byte arrived after the window ended');
});

test('the remote transport is not exported: no caller can dial a remote pin without the grant and window checks', async () => {
  const connector = await import('../src/http-connector.mjs');
  assert.equal('observeRemote' in connector, false);
  assert.deepEqual(Object.keys(connector).filter(name => /remote/i.test(name)), []);
  assert.throws(() => connector.observeHttp(`https://${HOST}`, { method: 'GET', path: '/me' }), /outside the configured local origin/);
});
