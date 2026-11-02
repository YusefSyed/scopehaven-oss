// Authorization record wiring: every entry point that sends requests to a target the operator configured (assess, the
// regression gate, the dashboard's run path, sequences and conversation specs) refuses it without an authorization
// record that covers it now, before any connection is made, and stamps the run it authorized. Built-in fixture
// targets are unchanged. A loopback notes app in this process counts every connection it accepts; the CLI runs as
// a child process against it. No model, provider or customer system.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync, chmodSync, symlinkSync, existsSync } from 'node:fs';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { checksumAuthorization, windowGuard, guardObserver, AUTHORIZATION_SCHEMA, WINDOW_ENDED } from '../src/authorization.mjs';
import { loadProfiles } from '../src/registry.mjs';
import { renderReport, comparisonDocument } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { compareRuns } from '../src/runner.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { startServer } from '../src/server.mjs';
import { createStore } from '../src/store.mjs';
import { runGate, summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { main as sequenceMain } from '../integrations/sequences/cli.mjs';
import { main as conversationMain } from '../integrations/conversations/cli.mjs';
import { CONVERSATION_SCHEMA } from '../integrations/conversations/conversation.mjs';
import { installClock, writeJump, realNow } from './support/window-clock.mjs';

const TOKEN = 'synthetic-member-token';
// Record times relative to the clock, so the test never expires with the calendar.
const DAY = 86400000, iso = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z'), ago = days => iso(Date.now() - days * DAY);
const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const CLOCK = fileURLToPath(new URL('./support/window-clock.mjs', import.meta.url));
const STAMP = sealed => ({ schema: AUTHORIZATION_SCHEMA, id: sealed.id, sha256: sealed.sha256 });

// The application under test. connections() counts every TCP connection it accepted, so "nothing was sent" is
// observed at the listener, not inferred from a request handler.
async function notesApp(t) {
  let connections = 0;
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const json = (s, b) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(b)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, {});
    if (req.url === '/me') return json(200, { user: 'member-1' });
    if (req.url === '/notes') return json(201, { id: 'n1' });
    return json(403, {});
  }); });
  server.on('connection', () => { connections++; });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${server.address().port}`, connections: () => connections };
}
// The same application, slow: it holds each response until hold(at) says, and records when each request arrived at the
// listener (real clock), and its path. onArrival(fn) runs fn once, at the next request's arrival, before its response is
// scheduled: windowEndsMidRun ends the window there. It also serves its own audit log (/audit), which an http-audit
// observer reads on the same origin: each note adds a row.
async function slowNotesApp(t) {
  let holdUntil = 0, auditRows = [], arrival = null;
  const arrivals = [], paths = [];
  const server = createServer((req, res) => { arrivals.push(realNow()); paths.push(req.url.split('?')[0]); if (arrival) { const fn = arrival; arrival = null; fn(); } req.resume(); req.on('end', () => setTimeout(() => {
    const json = (s, b) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(b)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, {});
    if (req.url === '/me') return json(200, { user: 'member-1' });
    if (req.url === '/audit') return json(200, { items: auditRows });
    if (req.url === '/notes') { auditRows = [...auditRows, { id: auditRows.length + 1, actor: 'member-1', action: 'note.create' }]; return json(201, { id: 'n1' }); }
    return json(403, {});
  }, Math.max(0, holdUntil - realNow()))); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${server.address().port}`, arrivals, paths, hold: at => { holdUntil = at; }, onArrival: fn => { arrival = fn; } };
}
const notesProfile = origin => ({ id: 'notes', name: 'Notes app', applicationId: 'notes-app', origin, buildLabel: 'b1', contextId: 'synthetic-notes',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' } }, requiredControlIds: ['WHOAMI', 'OWN-NOTE'],
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] },
    { id: 'OWN-NOTE', title: 'A member can create a note', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }] },
    { id: 'OTHER-NOTE', title: "A member cannot edit another user's note", category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/notes/n-other/edit', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
  ] });
function setup(t, origin) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven authorization ')); chmodSync(dir, 0o700);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const profiles = join(dir, 'profiles.json');
  writeFileSync(profiles, JSON.stringify({ schemaVersion: 1, targets: [notesProfile(origin)] }));
  let n = 0;
  const record = (edit = () => {}) => { const r = { schema: AUTHORIZATION_SCHEMA, id: 'notes-staging-test', target: { id: 'notes', applicationId: 'notes-app' }, origins: [origin], identities: ['member-1'],
    validFrom: ago(1), validUntil: ago(-30), signer: { name: 'A. Example', role: 'Owner' }, signedAt: ago(1) }; edit(r); const sealed = checksumAuthorization(r);
    const path = join(dir, `auth-${++n}.json`); writeFileSync(path, JSON.stringify(sealed)); return { path, sealed }; };
  return { dir, profiles, record, out: join(dir, 'out') };
}
// The refusals every entry point must make, each with the reason code it reports. assess runs all of them; the
// gate and the dashboard, whose registries take seconds to start, run the first, the window, the origin and the checksum.
const refusals = s => [
  ['no record', null, 'authorization-missing'],
  ['expired', s.record(r => { r.validFrom = ago(10); r.validUntil = ago(2); r.signedAt = ago(10); }).path, 'authorization-window'],
  ['not yet valid', s.record(r => { r.validFrom = ago(-1); r.validUntil = ago(-30); }).path, 'authorization-window'],
  ['another origin', s.record(r => { r.origins = ['http://127.0.0.1:1']; }).path, 'authorization-origin'],
  ['another target', s.record(r => { r.target = { id: 'notes', applicationId: 'other-app' }; }).path, 'authorization-target'],
  ['an uncovered test account', s.record(r => { r.identities = ['someone-else']; }).path, 'authorization-identity'],
  ['a signedAt after now', s.record(r => { r.signedAt = ago(-1); }).path, 'authorization-invalid'],
  ['edited without recomputing the checksum', (() => { const { path, sealed } = s.record(); writeFileSync(path, JSON.stringify({ ...sealed, validUntil: ago(-60) })); return path; })(), 'authorization-checksum'],
  ['a symlink to a valid record', (() => { const link = join(s.dir, 'link.json'); symlinkSync(s.record().path, link); return link; })(), 'authorization-invalid'],
];
const fewer = list => list.filter(([, , code]) => ['authorization-missing', 'authorization-window', 'authorization-origin', 'authorization-checksum'].includes(code)).filter(([name]) => name !== 'not yet valid');
// While a window case runs (windowClockFile set), the child preloads the test window clock (test/support/window-clock.mjs).
let windowClockFile = null;
const assess = (args, env = {}) => new Promise(resolve => {
  const clock = windowClockFile ? { argv: ['--import', CLOCK], env: { SCOPEHAVEN_TEST_WINDOW_CLOCK: windowClockFile } } : { argv: [], env: {} };
  const child = spawn(process.execPath, [...clock.argv, cli, ...args], { env: { PATH: process.env.PATH, SCOPEHAVEN_TARGET_MEMBER: TOKEN, ...clock.env, ...env } });
  let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
  child.on('close', code => resolve({ code, stdout, stderr }));
});
const savedRun = out => { const file = readdirSync(join(out, 'runs')).find(f => f.endsWith('.json')); return JSON.parse(readFileSync(join(out, 'runs', file), 'utf8')).core; };
const savedRunFiles = out => existsSync(join(out, 'runs')) ? readdirSync(join(out, 'runs')).filter(f => f.endsWith('.json')) : [];
// POST /api/runs on a dashboard started by startServer.
const postRun = (server, body) => new Promise((resolve, reject) => {
  const payload = JSON.stringify(body);
  const req = request(`${server.origin}/api/runs`, { method: 'POST', agent: false, headers: { Authorization: `Bearer ${server.accessToken}`, Accept: 'application/json', 'Content-Type': 'application/json', 'X-Scopehaven-Request': '1', 'Content-Length': Buffer.byteLength(payload) } }, res => {
    let text = ''; res.on('data', d => { text += d; }); res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(text) }));
  });
  req.on('error', reject); req.end(payload);
});
// A window that ends mid-run, at a moment the test chooses rather than a wall-clock
// deadline (test/support/window-clock.mjs). The record is valid from a day ago until a minute from now, so no entry point,
// however slow to start on a loaded machine, is refused at the start. At the run's first request the target ends the
// window: the guard's clock (in this process, or the assess child's) jumps past validUntil, and that response is held
// HOLD_MS. `until` is the real time of that jump. A request the guard let through left before it and reaches the listener
// within milliseconds, so arrivals are compared with until plus ARRIVAL_SLACK_MS; one sent after the held response, as it
// would be without the guard, arrives HOLD_MS or more after until.
const WINDOW_MS = 60000, HOLD_MS = 300, ARRIVAL_SLACK_MS = 200;
async function windowEndsMidRun(app, s, target, run) {
  const validUntil = realNow() + WINDOW_MS, before = app.arrivals.length;
  const { path } = s.record(r => { r.target = target; r.validUntil = new Date(validUntil).toISOString(); });
  const file = join(s.dir, `window-clock-${before}-${validUntil}`), clock = installClock();
  let until = null;
  windowClockFile = file;
  app.onArrival(() => { until = realNow(); clock.jumpPast(validUntil); writeJump(file, validUntil); app.hold(until + HOLD_MS); });
  try {
    const result = await run(path);
    const arrivals = app.arrivals.slice(before);
    assert.ok(until !== null && arrivals.length, 'the run reached the target inside its window');
    return { until, result, arrivals, paths: app.paths.slice(before) };
  } finally { clock.restore(); windowClockFile = null; app.onArrival(null); app.hold(0); }
}
const allBefore = (arrivals, until) => assert.ok(arrivals.every(at => at < until + ARRIVAL_SLACK_MS), `a request arrived ${Math.max(...arrivals) - until} ms after the window ended (the clock jump)`);
// The synthetic sequence and conversation spec the sequence and conversation cases run against the notes app.
const notesSequence = () => ({ schema: 'scopehaven-sequence/1', id: 'NOTES-SEQ', applicationId: 'notes-app', contextId: 'synthetic-notes',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER' } },
  steps: [{ request: { id: 'me', actorId: 'member', method: 'GET', path: '/me' }, assertStatus: { id: 'ME-OK', title: 'The member is accepted', severity: 'control', in: [200] } }, { mark: 'before' },
    { request: { id: 'other', actorId: 'member', method: 'POST', path: '/notes/n-other/edit', body: {} }, assertStatus: { id: 'OTHER-REFUSED', title: 'Another note is refused', severity: 'high', in: [403] } }, { mark: 'after' }],
  assertions: [{ id: 'NOTE-SEEN', title: 'Control: a note tool call is seen', severity: 'control', from: 'before', to: 'after', effect: { kind: 'effect.exists', select: { source: 'otel-genai', name: 'add_note' } } }] });
const notesSpec = origin => ({ schema: CONVERSATION_SCHEMA, id: 'notes-chat', origin, applicationId: 'notes-app', build: 'b1', contextId: 'ctx',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identity: { path: '/me', pointer: '/user', value: 'member-1' } } },
  conversations: [{ id: 'reply-ok', title: 'Control: the app answers', severity: 'control', actorId: 'member', turns: [{ path: '/me', mode: 'json', body: { message: 'hi' }, replyPointer: '/user', expect: [{ kind: 'status.in', codes: [200] }] }] }] });
// Profiles whose last contact with the target is an observer read, or a single request.
// auditedProfile: three observed checks, with an http-audit observer reading the application's own /audit on its origin.
// oneRequestProfile: one check, no identity probe and no observer, so its one request is the run's last contact.
const AUDIT_OBSERVER = origin => ({ id: 'audit', type: 'http-audit', origin, path: '/audit', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', itemsPointer: '/items', pageLimit: 100,
  fields: { id: '/id', actor: '/actor', action: '/action' }, actions: { 'note.create': 'insert' }, principals: ['member-1'] });
const NOTE_LOGGED = { kind: 'effect.exists', select: { source: 'http-audit-log', actor: 'member-1', name: 'note.create' } };
const auditedProfile = origin => ({ id: 'notes-audited', name: 'Notes app with its audit log', applicationId: 'notes-app', origin, buildLabel: 'b1', contextId: 'synthetic-notes',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER' } }, observers: [AUDIT_OBSERVER(origin)], requiredControlIds: ['CREATE-1', 'CREATE-2', 'CREATE-3'],
  checks: [1, 2, 3].map(n => ({ id: `CREATE-${n}`, title: `Create note ${n}`, category: 'allowed-use', severity: 'control', actorId: 'member', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 201 }], effects: [NOTE_LOGGED] })) });
const oneRequestProfile = origin => ({ id: 'notes-one', name: 'Notes app, one request', applicationId: 'notes-app', origin, buildLabel: 'b1', contextId: 'synthetic-notes',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER' } }, requiredControlIds: ['OWN-NOTE'],
  checks: [{ id: 'OWN-NOTE', title: 'A member can create a note', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }] }] });
const profilesFile = (s, profile) => { const path = join(s.dir, `${profile.id}-profiles.json`); writeFileSync(path, JSON.stringify({ schemaVersion: 1, targets: [profile] })); return path; };
const freePort = () => new Promise(resolve => { const probe = createServer(); probe.listen(0, '127.0.0.1', () => { const { port } = probe.address(); probe.close(() => resolve(port)); }); });

test('assess refuses a configured target without a covering record, before any connection, and exits 2 with the reason', async t => {
  const app = await notesApp(t), s = setup(t, app.origin);
  for (const [name, path, code] of refusals(s)) {
    const r = await assess(['--config', s.profiles, '--target', 'notes', '--out', join(s.dir, `out-${code}`), ...(path ? ['--authorization', path] : [])]);
    assert.equal(r.code, 2, `${name}: ${r.stderr}`);
    assert.match(r.stderr, new RegExp(`authorization refused \\(${code}\\)`), name);
    assert.doesNotMatch(r.stderr, new RegExp(s.dir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), `${name}: the refusal never echoes the record path`);
  }
  assert.equal(app.connections(), 0, 'no refused run connected to the application');
});

test('assess with a covering record stamps the run; its HTML, SARIF and comparison export carry the id and checksum; verdicts are unchanged', async t => {
  const app = await notesApp(t), s = setup(t, app.origin), { path, sealed } = s.record();
  const r = await assess(['--config', s.profiles, '--target', 'notes', '--out', s.out, '--authorization', path]);
  assert.notEqual(r.code, 2, r.stderr);
  const printed = JSON.parse(r.stdout);
  assert.deepEqual(printed.authorization, STAMP(sealed));
  const full = savedRun(s.out);
  assert.deepEqual(full.authorization, printed.authorization, 'the saved run carries the stamp');
  assert.ok(renderReport(full).includes(sealed.sha256), 'the HTML report names the checksum');
  assert.deepEqual(renderSarif(full).runs[0].properties.authorization, printed.authorization);
  assert.deepEqual(comparisonDocument(full, full, compareRuns(full, full)).candidate.authorization, printed.authorization);
  // The record never changes a verdict: the same profile run directly (no record, no stamp) reads the same.
  const [profile] = await loadProfiles(s.profiles), direct = await runHttpAssessment(profile, { env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN } });
  assert.deepEqual(printed.counts, direct.counts);
  assert.equal(r.code, direct.counts.fail || direct.counts.error || direct.counts.inconclusive ? 1 : 0);
  assert.deepEqual(full.results.map(x => [x.id, x.status, x.assertions.map(a => a.status)]), direct.results.map(x => [x.id, x.status, x.assertions.map(a => a.status)]));
  assert.deepEqual([full.suiteHash, full.policyHash, full.evaluatorHash, full.profileHash, full.targetConfigHash], [direct.suiteHash, direct.policyHash, direct.evaluatorHash, direct.profileHash, direct.targetConfigHash]);
  assert.equal(Object.hasOwn(direct, 'authorization'), false);
});

test('built-in fixture targets run unchanged without a record, and a record given for one is not stamped on it', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven builtin ')); chmodSync(dir, 0o700); t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const extra of [[], ['--authorization', join(dir, 'unused.json')]]) {
    const out = join(dir, `out-${extra.length}`), r = await assess(['--target', 'demo-repaired', '--out', out, ...extra]);
    assert.equal(r.code, 0, r.stderr);
    const printed = JSON.parse(r.stdout);
    assert.equal(Object.hasOwn(printed, 'authorization'), false);
    assert.equal(Object.hasOwn(savedRun(out), 'authorization'), false);
    assert.equal(printed.counts.fail, 0);
  }
});

test('the gate refuses a configured target without a covering record (exit 2, the refusal code as its reason), and stamps its summary and run with one', async t => {
  const app = await notesApp(t), s = setup(t, app.origin);
  const env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN };
  for (const [name, path, code] of fewer(refusals(s))) {
    const summary = await runGate({ targetId: 'notes', configFile: s.profiles, outputDirectory: join(s.dir, `gate-${code}-${name.length}`), ...(path ? { authorizationFile: path } : {}) }, { env });
    assert.deepEqual([summary.exitCode, summary.reasons], [2, [code]], name);
  }
  assert.equal(app.connections(), 0);
  // A relative record path is refused as an option, as a relative --config is.
  assert.deepEqual((await runGate({ targetId: 'notes', configFile: s.profiles, outputDirectory: join(s.dir, 'gate-rel'), authorizationFile: 'auth-1.json' }, { env })).reasons, ['invalid-options']);
  const { path, sealed } = s.record();
  const ok = await runGate({ targetId: 'notes', configFile: s.profiles, outputDirectory: join(s.dir, 'gate-ok'), authorizationFile: path }, { env });
  assert.notEqual(ok.exitCode, 2, JSON.stringify(ok.reasons));
  assert.ok(!ok.reasons.some(reason => reason.startsWith('authorization-')));
  assert.deepEqual(ok.current.authorization, STAMP(sealed));
  const store = createStore(join(s.dir, 'gate-ok')); await store.ready;
  const saved = await store.get(ok.current.runId);
  assert.deepEqual(saved.authorization, STAMP(sealed));
  // The stamp is presentation: the same run without it gates the same way.
  const { authorization: _a, ...unstamped } = saved;
  const again = summarizeGate({ candidate: unstamped }), stamped = summarizeGate({ candidate: saved });
  assert.deepEqual([again.exitCode, again.reasons], [stamped.exitCode, stamped.reasons]);
  assert.equal(Object.hasOwn(again.current, 'authorization'), false);
});

test('the dashboard run path refuses a configured target without a covering record (403, its code) and stamps the run with one', async t => {
  const app = await notesApp(t), s = setup(t, app.origin), profiles = await loadProfiles(s.profiles), call = postRun;
  for (const [name, path, code] of fewer(refusals(s))) {
    const server = await startServer({ port: 0, dataDir: join(s.dir, `data-${code}-${name.length}`), profiles, env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN }, ...(path ? { authorizationFile: path } : {}) });
    try {
      const refused = await call(server, { targetId: 'notes' });
      assert.deepEqual([refused.status, refused.json.code], [403, code], name);
      assert.match(refused.json.error, /nothing was sent/);
      // A built-in target on the same server still runs without one.
      assert.equal((await call(server, { targetId: 'demo-repaired' })).status, 201);
    } finally { await server.close(); }
  }
  assert.equal(app.connections(), 0);
  const { path, sealed } = s.record();
  const server = await startServer({ port: 0, dataDir: join(s.dir, 'data-ok'), profiles, env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN }, authorizationFile: path });
  try {
    const created = await call(server, { targetId: 'notes' });
    assert.equal(created.status, 201, JSON.stringify(created.json));
    assert.deepEqual(created.json.authorization, STAMP(sealed));
    const direct = await runHttpAssessment(profiles[0], { env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN } });
    assert.deepEqual(created.json.counts, direct.counts);
    // The record is read at each run: once it expires, the next run is refused.
    writeFileSync(path, JSON.stringify(checksumAuthorization({ ...sealed, validFrom: ago(10), validUntil: ago(2), signedAt: ago(10) })));
    assert.deepEqual((await call(server, { targetId: 'notes' })).json.code, 'authorization-window');
  } finally { await server.close(); }
});

test('a sequence run needs a record naming the sequence, --origin, the hold gate upstream and its credentialed actors; refused, it starts nothing', async t => {
  const app = await notesApp(t), s = setup(t, app.origin), sequence = notesSequence();
  writeFileSync(join(s.dir, 'seq.json'), JSON.stringify(sequence));
  const otel = await freePort();
  writeFileSync(join(s.dir, 'observers.json'), JSON.stringify([{ type: 'otel', port: otel, services: ['notes'], tools: ['add_note'], principals: ['member-1'], settleMs: 50 }]));
  // A database snapshot observer reaches its own endpoint, which the record must list too; this listener counts every connection.
  let pgConnections = 0;
  const pg = createNetServer(socket => { pgConnections++; socket.destroy(); });
  await new Promise(resolve => pg.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => pg.close(resolve)));
  writeFileSync(join(s.dir, 'observers-pg.json'), JSON.stringify([{ type: 'otel', port: otel, services: ['notes'], tools: ['add_note'], principals: ['member-1'], settleMs: 50 },
    { type: 'pg-snapshot', host: '127.0.0.1', port: pg.address().port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_PG', tables: [{ table: 'notes', key: 'id' }] }]));
  const seqRecord = edit => { const { path, sealed } = s.record(r => { r.target = { id: 'NOTES-SEQ', applicationId: 'notes-app' }; edit?.(r); }); return { path, sealed }; };
  const args = (extra, observers = 'observers.json') => ['--sequence', join(s.dir, 'seq.json'), '--origin', app.origin, '--observers', join(s.dir, observers), '--out', join(s.dir, 'seq-runs'), ...extra];
  const env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN, SCOPEHAVEN_TARGET_PG: 'reader:synthetic' };
  for (const [name, extra, code, observers] of [
    ['no record', [], 'authorization-missing'],
    ['the profile record, not the sequence', ['--authorization', s.record().path], 'authorization-target'],
    ['another origin', ['--authorization', seqRecord(r => { r.origins = ['http://127.0.0.1:1']; }).path], 'authorization-origin'],
    ['expired', ['--authorization', seqRecord(r => { r.validFrom = ago(10); r.validUntil = ago(2); r.signedAt = ago(10); }).path], 'authorization-window'],
    ['an uncovered test account', ['--authorization', seqRecord(r => { r.identities = ['someone-else']; }).path], 'authorization-identity'],
    ["an observer's endpoint the record does not list", ['--authorization', seqRecord().path], 'authorization-origin', 'observers-pg.json'],
  ]) {
    const lines = [];
    assert.equal(await sequenceMain(args(extra, observers), { env, log: x => lines.push(x) }), 2, `${name}: ${lines.join('\n')}`);
    assert.match(lines.join('\n'), new RegExp(`Authorization refused \\(${code}\\)`), name);
  }
  assert.equal(app.connections(), 0);
  assert.equal(pgConnections, 0, 'the refused run never reached the database observer endpoint');
  const { path, sealed } = seqRecord(), lines = [];
  const code = await sequenceMain(args(['--authorization', path, '--save', join(s.dir, 'seq-data'), '--build', 'b1']), { env, log: x => lines.push(x) });
  assert.notEqual(code, 2, lines.join('\n'));
  assert.ok(app.connections() > 0, 'the authorized run reached the application');
  assert.match(lines.join('\n'), new RegExp(`Authorized by record notes-staging-test \\(sha256 ${sealed.sha256}\\)`));
  const store = createStore(join(s.dir, 'seq-data')); await store.ready;
  const [listed] = await store.list(), saved = await store.get(listed.id);
  assert.deepEqual(saved.authorization, STAMP(sealed));
  // The stamp sits outside the sealed run: the run validates with it and without it, and a malformed one is refused.
  const { validateSequenceNativeRun } = await import('../integrations/sequences/native.mjs');
  const { authorization: _stamp, ...unstamped } = saved;
  assert.doesNotThrow(() => validateSequenceNativeRun(saved)); assert.doesNotThrow(() => validateSequenceNativeRun(unstamped));
  // So does the build that made it, which is also outside the sealed run: a run saved before the field validates.
  const { PRODUCER_RELEASE } = await import('../src/producer.mjs');
  assert.deepEqual(saved.producer, { release: PRODUCER_RELEASE });
  const { producer: _build, ...unnamed } = saved;
  assert.doesNotThrow(() => validateSequenceNativeRun(unnamed));
  assert.doesNotThrow(() => validateSequenceNativeRun({ ...saved, producer: { release: { ...PRODUCER_RELEASE, commit: 'unknown', source: 'unknown', manifestSha256: null } } }));
  assert.throws(() => validateSequenceNativeRun({ ...saved, authorization: { ...saved.authorization, extra: 1 } }), error => error.code === 'invalid-sequence-evidence' && error.detail === 'authorization');
  // A hold gate's upstream is an endpoint the run reaches: a record without it is refused.
  writeFileSync(join(s.dir, 'gate.json'), JSON.stringify({ upstream: 'http://127.0.0.1:9', port: otel, rules: [{ id: 'model', method: 'POST', pathPrefix: '/v1/chat' }] }));
  const gated = [];
  assert.equal(await sequenceMain([...args(['--authorization', path]), '--gate', join(s.dir, 'gate.json')], { env, log: x => gated.push(x) }), 2);
  assert.match(gated.join('\n'), /Authorization refused \(authorization-origin\)/);
});

test('a conversation spec needs a record naming the spec, its origin and its credentialed actors; refused, nothing is sent', async t => {
  const app = await notesApp(t), s = setup(t, app.origin);
  const spec = notesSpec(app.origin);
  const specFile = join(s.dir, 'spec.json'); writeFileSync(specFile, JSON.stringify(spec), { mode: 0o600 });
  const env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN }, convRecord = edit => s.record(r => { r.target = { id: 'notes-chat', applicationId: 'notes-app' }; edit?.(r); });
  let out = ''; const stdout = { write: x => { out += x; } };
  for (const [name, extra, code] of [
    ['no record', [], 'authorization-missing'],
    ['an uncovered actor', ['--authorization', convRecord(r => { r.identities = ['someone-else']; }).path], 'authorization-identity'],
    ['another origin', ['--authorization', convRecord(r => { r.origins = ['http://127.0.0.1:1']; }).path], 'authorization-origin'],
  ]) await assert.rejects(conversationMain(['--spec', specFile, '--out', join(s.dir, 'reports'), ...extra], { env, stdout }), error => error.code === code && /nothing was sent/.test(error.message), name);
  assert.equal(app.connections(), 0);
  const { path, sealed } = convRecord();
  assert.equal(await conversationMain(['--spec', specFile, '--out', join(s.dir, 'reports'), '--authorization', path, '--save', join(s.dir, 'conv-data')], { env, stdout }), 0, out);
  const summary = JSON.parse(out);
  assert.deepEqual(summary.authorization, STAMP(sealed));
  const store = createStore(join(s.dir, 'conv-data')); await store.ready;
  assert.deepEqual((await store.get(summary.savedRun)).authorization, STAMP(sealed));
  assert.deepEqual((await store.get(summary.savedRun)).producer, { release: (await import('../src/producer.mjs')).PRODUCER_RELEASE });
  assert.deepEqual(JSON.parse(readFileSync(summary.report, 'utf8')).authorization, STAMP(sealed));
});

test('the roe CLI seals a draft into a new file (never overwriting) and checks a record as assess would, without echoing values', async t => {
  const { main: roe } = await import('../integrations/roe/cli.mjs');
  const app = await notesApp(t), s = setup(t, app.origin);
  const io = () => { const o = { out: '', err: '' }; return [o, { stdout: { write: x => { o.out += x; } }, stderr: { write: x => { o.err += x; } } }]; };
  const draft = join(s.dir, 'draft.json'), sealedPath = join(s.dir, 'sealed.json');
  writeFileSync(draft, JSON.stringify({ schema: AUTHORIZATION_SCHEMA, id: 'notes-draft', target: { id: 'notes', applicationId: 'notes-app' }, origins: [app.origin], identities: ['member-1'],
    validFrom: ago(1), validUntil: ago(-30), signer: { name: 'A. Example', role: 'Owner' }, signedAt: ago(1) }));
  let [o, streams] = io();
  assert.equal(await roe(['seal', draft, sealedPath], streams), 0, o.err);
  const sealed = JSON.parse(readFileSync(sealedPath, 'utf8'));
  assert.equal(JSON.parse(o.out).sha256, sealed.sha256);
  [o, streams] = io();
  assert.equal(await roe(['seal', draft, sealedPath], streams), 2, 'an existing file is never overwritten');
  assert.equal(JSON.parse(o.err).code, 'authorization-io');
  [o, streams] = io();
  assert.equal(await roe(['check', sealedPath, '--config', s.profiles, '--target', 'notes'], streams), 0, o.err);
  assert.deepEqual(JSON.parse(o.out).stamp, STAMP(sealed));
  assert.equal(JSON.parse(o.out).validUntil, sealed.validUntil, 'the end of the window, which the GitHub Action bounds its wait by');
  for (const [args, code] of [[['--at', ago(40)], 'authorization-window'], [['--at', 'not-a-time'], 'authorization-clock'],
    // --at is read as the record's instants are: no 02-31 rolled over to March, no hour 24.
    [['--at', '2026-02-31T00:00:00Z'], 'authorization-clock'], [['--at', '2026-10-07T24:00:00Z'], 'authorization-clock'],
    // The GitHub Action's wait-url: its origin must be one of the record's origins.
    [['--wait-url', 'http://127.0.0.1:1/health'], 'authorization-origin'], [['--wait-url', 'https://example.com/health'], 'authorization-origin']]) {
    [o, streams] = io();
    assert.equal(await roe(['check', sealedPath, '--config', s.profiles, '--target', 'notes', ...args], streams), 2);
    assert.equal(JSON.parse(o.err).code, code);
    assert.doesNotMatch(o.err, /A\. Example|127\.0\.0\.1/, 'a refusal never echoes a field value');
  }
  [o, streams] = io();
  assert.equal(await roe(['check', sealedPath, '--config', s.profiles, '--target', 'other'], streams), 2);
  assert.equal(JSON.parse(o.err).code, 'authorization-target');
  // A wait-url on the record's origin, spelled with localhost (which the wait dials as 127.0.0.1), is covered.
  for (const url of [`${app.origin}/health`, app.origin.replace('127.0.0.1', 'localhost')]) {
    [o, streams] = io();
    assert.equal(await roe(['check', sealedPath, '--config', s.profiles, '--target', 'notes', '--wait-url', url], streams), 0, o.err);
  }
  for (const args of [['--wait-url'], ['--wait-url', '--at'], ['--target', 'notes'], ['--at', ago(0), '--at', ago(0)], ['--unknown', 'x']]) {
    [o, streams] = io();
    assert.equal(await roe(['check', sealedPath, '--config', s.profiles, '--target', 'notes', ...args], streams), 2, `options are named once, each with a value: ${args.join(' ')}`);
  }
  assert.equal(app.connections(), 0, 'the CLI sends no request');
});

test('the roe CLI checks when run through a symlinked path: a missing record exits 2, never a silent 0', async t => {
  const s = setup(t, 'http://127.0.0.1:9'), link = join(s.dir, 'linked-root');
  symlinkSync(fileURLToPath(new URL('..', import.meta.url)), link);
  const result = await new Promise(resolve => {
    const child = spawn(process.execPath, [join(link, 'integrations/roe/cli.mjs'), 'check', join(s.dir, 'missing.json'), '--config', s.profiles, '--target', 'notes'], { env: { PATH: process.env.PATH } });
    let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
  assert.equal(result.code, 2, result.stderr);
  assert.equal(JSON.parse(result.stderr).code, 'authorization-invalid');
  assert.equal(result.stdout, '');
});

test('the endpoints a record must list include a forwarding egress destination\'s upstream and a request feed, and an unknown observer fails closed', async () => {
  const { contactedEndpoints } = await import('../src/authorization.mjs');
  const base = { origin: 'http://127.0.0.1:4100/' };
  assert.deepEqual(contactedEndpoints({ ...base, observers: [{ type: 'egress-recorder', port: 47110, destinations: [{ host: 'pay.example' }] }] }), ['http://127.0.0.1:4100'], 'a recorder that only listens adds nothing');
  assert.deepEqual(contactedEndpoints({ ...base, observers: [{ type: 'egress-recorder', port: 47110, destinations: [{ host: 'pay.example', forward: { upstream: 'http://127.0.0.1:4200/' } }], requestFeed: { endpoint: { port: 4300, path: '/feed' } } }] }),
    ['http://127.0.0.1:4100', 'http://127.0.0.1:4200', 'http://127.0.0.1:4300']);
  assert.ok(contactedEndpoints({ ...base, observers: [{ type: 'egress-recorder', destinations: [{ forward: {} }] }] }).includes(undefined), 'a forward without an upstream adds an endpoint no record can list');
  assert.throws(() => contactedEndpoints({ ...base, observers: [{ type: 'brand-new-observer' }] }), error => error.code === 'authorization-origin');
});

test('the owned model tap upstream is an endpoint the run contacts: a record without it is refused before anything starts', async t => {
  const app = await notesApp(t), s = setup(t, app.origin), { path } = s.record();
  const env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN, SCOPEHAVEN_MODEL_TAP_UPSTREAM: 'http://127.0.0.1:11434', SCOPEHAVEN_MODEL_TAP_PORT: '4999', SCOPEHAVEN_MODEL_TAP_OLLAMA_TAGS: 'false' };
  const summary = await runGate({ targetId: 'notes', configFile: s.profiles, outputDirectory: join(s.dir, 'gate-tap'), authorizationFile: path }, { env });
  assert.deepEqual([summary.exitCode, summary.reasons], [2, ['authorization-origin']]);
  const r = await assess(['--config', s.profiles, '--target', 'notes', '--out', join(s.dir, 'out-tap'), '--authorization', path], env);
  assert.equal(r.code, 2, r.stderr); assert.match(r.stderr, /authorization refused \(authorization-origin\)/);
  // The dashboard's run path counts it too (its process forwards the same model calls).
  const server = await startServer({ port: 0, dataDir: join(s.dir, 'data-tap'), profiles: await loadProfiles(s.profiles), env, authorizationFile: path });
  try {
    const refused = await postRun(server, { targetId: 'notes' });
    assert.deepEqual([refused.status, refused.json.code], [403, 'authorization-origin']);
  } finally { await server.close(); }
  // And the roe CLI's check, which the GitHub Action runs before its wait, makes the same check from the same environment.
  const { main: roe } = await import('../integrations/roe/cli.mjs');
  let err = '';
  assert.equal(await roe(['check', path, '--config', s.profiles, '--target', 'notes'], { stdout: { write() {} }, stderr: { write: x => { err += x; } }, env }), 2);
  assert.equal(JSON.parse(err).code, 'authorization-origin');
  assert.equal(app.connections(), 0);
});

test('a saved run whose stamp is not exactly { schema, id, sha256 } is refused by the gate and the sequence validator', async t => {
  const app = await notesApp(t), s = setup(t, app.origin), { path } = s.record();
  const ok = await runGate({ targetId: 'notes', configFile: s.profiles, outputDirectory: join(s.dir, 'gate-shape'), authorizationFile: path }, { env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN } });
  const store = createStore(join(s.dir, 'gate-shape')); await store.ready;
  const saved = await store.get(ok.current.runId);
  assert.notEqual(summarizeGate({ candidate: saved }).exitCode, 2);
  for (const stamp of [{ ...saved.authorization, signer: 'x' }, { ...saved.authorization, sha256: 'not-hex' }, { schema: 'other/1', id: saved.authorization.id, sha256: saved.authorization.sha256 }, 'notes-staging-test', null]) {
    const summary = summarizeGate({ candidate: { ...saved, authorization: stamp } });
    assert.deepEqual([summary.exitCode, summary.reasons], [2, ['invalid-run-evidence']], JSON.stringify(stamp));
  }
});

test('the window guard admits a request inside [validFrom, validUntil) and, from validUntil on, refuses every request without calling the transport', async () => {
  const record = checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: 'guard-unit', target: { id: 'notes', applicationId: 'notes-app' }, origins: ['http://127.0.0.1:4100'], identities: ['member-1'],
    validFrom: '2026-10-07T00:00:00Z', validUntil: '2026-10-07T00:00:01.500Z', signer: { name: 'A. Example', role: 'Owner' }, signedAt: '2026-10-06T00:00:00Z' });
  let now = Date.parse('2026-10-07T00:00:01.499Z'), sent = 0;
  const window = windowGuard(record, { now: () => now }), send = window.guard(async () => { sent++; return 'sent'; });
  assert.equal(await send(), 'sent');
  assert.equal(window.ended(), false);
  now += 1; // exactly validUntil: the window is half open
  await assert.rejects(send(), error => error.code === WINDOW_ENDED);
  now -= 1000; // a clock that steps back inside the window does not reopen it
  await assert.rejects(send(), error => error.code === WINDOW_ENDED);
  assert.deepEqual([sent, window.ended()], [1, true]);
  assert.throws(() => windowGuard(record, { now: () => Date.parse('2026-10-06T23:59:59.999Z') }).check(), error => error.code === WINDOW_ENDED, 'before validFrom');
  assert.throws(() => windowGuard({ ...record, validUntil: '2026-10-08T00:00:00Z' }), error => error.code === 'authorization-checksum', 'the guard reads only a record whose checksum matches');
});

// The window cases rely on windowGuard reading the global Date.now when it is built (test/support/window-clock.mjs): pinned
// here, so a change that gives the guard its own clock fails with this message instead of as a timing puzzle.
test('the window guard reads the clock it was built with: a jump of that clock ends the window, the global restored', () => {
  const validUntil = realNow() + 60000;
  const record = checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: 'guard-clock', target: { id: 'notes', applicationId: 'notes-app' }, origins: ['http://127.0.0.1:4100'], identities: ['member-1'],
    validFrom: ago(1), validUntil: new Date(validUntil).toISOString(), signer: { name: 'A. Example', role: 'Owner' }, signedAt: ago(1) });
  const clock = installClock();
  let window;
  try { window = windowGuard(record); window.check(); clock.jumpPast(validUntil); } finally { clock.restore(); }
  assert.ok(Math.abs(Date.now() - realNow()) < 1000, 'the global clock is the real one again');
  assert.throws(() => window.check(), error => error.code === WINDOW_ENDED);
});

test('assess stops sending when the window ends mid-run: exit 2 (authorization-window-ended), no run saved or stamped', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin), out = join(s.dir, 'out-window');
  const { until, result, arrivals } = await windowEndsMidRun(app, s, { id: 'notes', applicationId: 'notes-app' },
    path => assess(['--config', s.profiles, '--target', 'notes', '--out', out, '--authorization', path]));
  assert.equal(result.code, 2, result.stderr);
  assert.match(result.stderr, /authorization refused \(authorization-window-ended\)/);
  assert.equal(result.stdout, '');
  allBefore(arrivals, until);
  assert.deepEqual(savedRunFiles(out), []);
});

test('the gate stops sending when the window ends mid-run: exit 2 with reason authorization-window-ended, no run or summary saved', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin);
  let directory, n = 0;
  const { until, result, arrivals } = await windowEndsMidRun(app, s, { id: 'notes', applicationId: 'notes-app' },
    path => runGate({ targetId: 'notes', configFile: s.profiles, outputDirectory: directory = join(s.dir, `gate-window-${++n}`), authorizationFile: path }, { env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN } }));
  assert.deepEqual([result.exitCode, result.reasons], [2, [WINDOW_ENDED]]);
  assert.equal(Object.hasOwn(result.current ?? {}, 'authorization'), false);
  allBefore(arrivals, until);
  const store = createStore(directory); await store.ready;
  assert.deepEqual(await store.list(), []);
  assert.deepEqual(readdirSync(join(directory, 'gate-summaries')), []);
});

test('the dashboard run path stops sending when the window ends mid-run: 403 authorization-window-ended, no run saved', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin), recordFile = join(s.dir, 'dashboard-record.json'), dataDir = join(s.dir, 'data-window');
  const server = await startServer({ port: 0, dataDir, profiles: await loadProfiles(s.profiles), env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN }, authorizationFile: recordFile });
  t.after(() => server.close());
  // The record is read at each run, so it is written just before the run starts.
  const { until, result, arrivals } = await windowEndsMidRun(app, s, { id: 'notes', applicationId: 'notes-app' },
    path => { writeFileSync(recordFile, readFileSync(path)); return postRun(server, { targetId: 'notes' }); });
  assert.deepEqual([result.status, result.json.code], [403, WINDOW_ENDED]);
  assert.match(result.json.error, /nothing more was sent, and no run was saved/);
  allBefore(arrivals, until);
  const store = createStore(dataDir); await store.ready;
  assert.deepEqual(await store.list(), []);
});

test('a sequence stops sending when the window ends mid-run: exit 2 (authorization-window-ended), nothing written or saved', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin), sequence = notesSequence();
  // A second request straight after the first, before any mark: the window ends at the first, so only the request guard
  // stands between the run and the next request (with a mark next, its observer guard would refuse first).
  sequence.steps.splice(1, 0, { request: { id: 'me-again', actorId: 'member', method: 'GET', path: '/me' } });
  writeFileSync(join(s.dir, 'seq.json'), JSON.stringify(sequence));
  writeFileSync(join(s.dir, 'observers.json'), JSON.stringify([{ type: 'otel', port: await freePort(), services: ['notes'], tools: ['add_note'], principals: ['member-1'], settleMs: 50 }]));
  const out = join(s.dir, 'seq-window-runs'), data = join(s.dir, 'seq-window-data'), lines = [];
  const { until, result, arrivals, paths } = await windowEndsMidRun(app, s, { id: 'NOTES-SEQ', applicationId: 'notes-app' }, path => { lines.length = 0;
    return sequenceMain(['--sequence', join(s.dir, 'seq.json'), '--origin', app.origin, '--observers', join(s.dir, 'observers.json'), '--out', out, '--save', data, '--build', 'b1', '--authorization', path],
      { env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN }, log: x => lines.push(x) }); });
  assert.equal(result, 2, lines.join('\n'));
  assert.match(lines.join('\n'), /Authorization refused \(authorization-window-ended\)/);
  assert.doesNotMatch(lines.join('\n'), /Authorized by record|Stored run|Saved /);
  allBefore(arrivals, until);
  assert.deepEqual(paths, ['/me'], 'the second request was never sent');
  assert.equal(existsSync(out), false, 'no sealed run file was written');
  const store = createStore(data); await store.ready;
  assert.deepEqual(await store.list(), []);
});

test('a conversation spec stops sending when the window ends mid-run: refused (authorization-window-ended), no report written or run saved', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin), specFile = join(s.dir, 'spec.json');
  writeFileSync(specFile, JSON.stringify(notesSpec(app.origin)), { mode: 0o600 });
  const reports = join(s.dir, 'window-reports'), data = join(s.dir, 'window-data');
  let out = ''; const stdout = { write: x => { out += x; } };
  const { until, result, arrivals } = await windowEndsMidRun(app, s, { id: 'notes-chat', applicationId: 'notes-app' },
    path => conversationMain(['--spec', specFile, '--out', reports, '--authorization', path, '--save', data], { env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN }, stdout }).then(code => ({ code }), error => ({ error })));
  assert.equal(result.error?.code, WINDOW_ENDED, JSON.stringify(result));
  assert.match(result.error.message, /authorization refused \(authorization-window-ended\)/);
  allBefore(arrivals, until);
  assert.equal(out, '');
  assert.equal(existsSync(reports), false, 'no report was written');
  assert.equal(existsSync(data), false, 'no run was saved');
});

// The rule: a run with any request outside the window is never saved or stamped as authorized.
test('every observer call except stop checks the window first: refused calls never reach the observer, stop always runs', async () => {
  let now = 1000, calls = [];
  const record = checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: 'guard-observer', target: { id: 'notes', applicationId: 'notes-app' }, origins: ['http://127.0.0.1:4100'], identities: ['member-1'],
    validFrom: '1970-01-01T00:00:00Z', validUntil: '1970-01-01T00:00:02Z', signer: { name: 'A. Example', role: 'Owner' }, signedAt: '1970-01-01T00:00:00Z' });
  const window = windowGuard(record, { now: () => now });
  const raw = { kind: 'probe', settleMs: 7, async start() { calls.push('start'); }, async mark() { calls.push('mark'); return this.kind; }, markClear() { calls.push('markClear'); return true; }, async stop() { calls.push('stop'); } };
  const observer = guardObserver(raw, window.check);
  await observer.start();
  assert.equal(await observer.mark(), 'probe', 'a method runs on the observer itself');
  assert.equal(observer.markClear(), true);
  now = 2000; // validUntil: the window has ended
  await assert.rejects(observer.mark(), error => error.code === WINDOW_ENDED, 'an async method rejects');
  await assert.rejects(observer.start(), error => error.code === WINDOW_ENDED);
  assert.throws(() => observer.markClear(), error => error.code === WINDOW_ENDED, 'a synchronous method throws');
  await observer.stop();
  assert.deepEqual(calls, ['start', 'mark', 'markClear', 'stop'], 'nothing after the end reached the observer, and stop ran');
  assert.deepEqual([observer.kind, observer.settleMs, window.ended()], ['probe', 7, true], 'values read through unchanged');
});

test('assess stops an observer reading the target\'s own origin when the window ends: no read after validUntil, exit 2, no run saved', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin), config = profilesFile(s, auditedProfile(app.origin)), out = join(s.dir, 'out-observer-window');
  // The window ends at the target's first request (windowEndsMidRun jumps the guard's clock there and holds that response
  // HOLD_MS), during the observer's first read, and without the observer guard the next marks would read /audit after the end.
  const { until, result, arrivals, paths } = await windowEndsMidRun(app, s, { id: 'notes-audited', applicationId: 'notes-app' },
    path => assess(['--config', config, '--target', 'notes-audited', '--out', out, '--authorization', path]));
  assert.equal(result.code, 2, result.stderr);
  assert.match(result.stderr, /authorization refused \(authorization-window-ended\)/);
  assert.equal(paths[0], '/audit', 'the observer read the target\'s own origin inside the window');
  allBefore(arrivals, until);
  assert.deepEqual(savedRunFiles(out), []);
});

test('assess, the gate and the dashboard refuse a run whose window ends after its last request, before it is saved: exit 2 or 403, nothing saved', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin), config = profilesFile(s, oneRequestProfile(app.origin)), target = { id: 'notes-one', applicationId: 'notes-app' };
  // The run's one request leaves inside the window and its response is held past validUntil: nothing is sent after the
  // end, so only the check made immediately before saving refuses the run.
  const out = join(s.dir, 'out-after-last');
  let r = await windowEndsMidRun(app, s, target, path => assess(['--config', config, '--target', 'notes-one', '--out', out, '--authorization', path]));
  assert.equal(r.result.code, 2, r.result.stderr);
  assert.match(r.result.stderr, /authorization refused \(authorization-window-ended\)/);
  assert.deepEqual([r.arrivals.length, r.paths], [1, ['/notes']]);
  allBefore(r.arrivals, r.until);
  assert.deepEqual(savedRunFiles(out), []);
  let directory, n = 0;
  r = await windowEndsMidRun(app, s, target, path => runGate({ targetId: 'notes-one', configFile: config, outputDirectory: directory = join(s.dir, `gate-after-last-${++n}`), authorizationFile: path }, { env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN } }));
  assert.deepEqual([r.result.exitCode, r.result.reasons], [2, [WINDOW_ENDED]]);
  assert.equal(r.arrivals.length, 1);
  allBefore(r.arrivals, r.until);
  const gateStore = createStore(directory); await gateStore.ready;
  assert.deepEqual(await gateStore.list(), []);
  assert.deepEqual(readdirSync(join(directory, 'gate-summaries')), []);
  const recordFile = join(s.dir, 'dashboard-after-last.json'), dataDir = join(s.dir, 'data-after-last');
  const server = await startServer({ port: 0, dataDir, profiles: await loadProfiles(config), env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN }, authorizationFile: recordFile });
  t.after(() => server.close());
  r = await windowEndsMidRun(app, s, target, path => { writeFileSync(recordFile, readFileSync(path)); return postRun(server, { targetId: 'notes-one' }); });
  assert.deepEqual([r.result.status, r.result.json.code], [403, WINDOW_ENDED]);
  assert.equal(r.arrivals.length, 1);
  allBefore(r.arrivals, r.until);
  const dashboardStore = createStore(dataDir); await dashboardStore.ready;
  assert.deepEqual(await dashboardStore.list(), []);
});

test('a sequence stops its observers\' reads when the window ends, and refuses a run whose window ends after its last request: exit 2, nothing written or saved', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin), lines = [];
  const sequence = id => ({ schema: 'scopehaven-sequence/1', id, applicationId: 'notes-app', contextId: 'synthetic-notes', actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER' } } });
  const run = (name, seq, observers) => {
    writeFileSync(join(s.dir, `${name}-seq.json`), JSON.stringify(seq)); writeFileSync(join(s.dir, `${name}-observers.json`), JSON.stringify(observers));
    const out = join(s.dir, `${name}-runs`);
    return { out, run: path => { lines.length = 0; return sequenceMain(['--sequence', join(s.dir, `${name}-seq.json`), '--origin', app.origin, '--observers', join(s.dir, `${name}-observers.json`), '--out', out, '--authorization', path],
      { env: { SCOPEHAVEN_TARGET_MEMBER: TOKEN }, log: x => lines.push(x) }); } };
  };
  // An http-audit observer on --origin: its start read is held past validUntil, so the window ends during it, and the
  // marks after it would read /audit after the end without the observer guard.
  const audited = run('audited', { ...sequence('NOTES-AUDIT-SEQ'), steps: [{ mark: 'before' }, { request: { id: 'create', actorId: 'member', method: 'POST', path: '/notes', body: {} } }, { mark: 'after' }],
    assertions: [{ id: 'NOTE-LOGGED', title: 'Control: the note is logged', severity: 'control', from: 'before', to: 'after', effect: NOTE_LOGGED }] }, [AUDIT_OBSERVER(app.origin)]);
  let r = await windowEndsMidRun(app, s, { id: 'NOTES-AUDIT-SEQ', applicationId: 'notes-app' }, audited.run);
  assert.equal(r.result, 2, lines.join('\n'));
  assert.match(lines.join('\n'), /Authorization refused \(authorization-window-ended\)/);
  assert.equal(r.paths[0], '/audit');
  allBefore(r.arrivals, r.until);
  assert.equal(existsSync(audited.out), false, 'no sealed run file was written');
  // One request, answered after validUntil; its precondition then stops the sequence, so no observer is read after the
  // end either: only the check made immediately before writing refuses the run.
  const aborted = run('aborted', { ...sequence('NOTES-ABORT-SEQ'), steps: [{ mark: 'before' }, { request: { id: 'me', actorId: 'member', method: 'GET', path: '/me' } }, { expectStatus: { request: 'me', in: [418] } }, { mark: 'after' }],
    assertions: [{ id: 'NOTE-SEEN', title: 'Control: a note tool call is seen', severity: 'control', from: 'before', to: 'after', effect: { kind: 'effect.exists', select: { source: 'otel-genai', name: 'add_note' } } }] },
    [{ type: 'otel', port: await freePort(), services: ['notes'], tools: ['add_note'], principals: ['member-1'] }]);
  r = await windowEndsMidRun(app, s, { id: 'NOTES-ABORT-SEQ', applicationId: 'notes-app' }, aborted.run);
  assert.equal(r.result, 2, lines.join('\n'));
  assert.match(lines.join('\n'), /Authorization refused \(authorization-window-ended\)/);
  assert.deepEqual(r.paths, ['/me']);
  allBefore(r.arrivals, r.until);
  assert.equal(existsSync(aborted.out), false, 'no sealed run file was written');
});

test('a conversation guards its stream turns, and refuses a run whose window ends after its last request: no report written or run saved', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin), target = { id: 'notes-anon-chat', applicationId: 'notes-app' };
  // An actor without a credential needs no login proof, so each conversation sends exactly its turn.
  const turn = mode => ({ path: '/me', mode, body: { message: 'hi' }, ...(mode === 'sse' ? { sse: { deltaEvent: 'delta', textPointer: '/text', doneEvent: 'done' } } : { replyPointer: '/user' }), expect: [{ kind: 'status.in', codes: [200] }] });
  const spec = (...modes) => ({ schema: CONVERSATION_SCHEMA, id: 'notes-anon-chat', origin: app.origin, applicationId: 'notes-app', build: 'b1', contextId: 'ctx', actors: { visitor: { principalId: 'visitor-1' } },
    conversations: modes.map((mode, i) => ({ id: `c${i + 1}-${mode}`, title: `Control: a ${mode} turn`, severity: 'control', actorId: 'visitor', turns: [turn(mode)] })) });
  const run = (name, body) => {
    const specFile = join(s.dir, `${name}-spec.json`), reports = join(s.dir, `${name}-reports`), data = join(s.dir, `${name}-data`);
    writeFileSync(specFile, JSON.stringify(body), { mode: 0o600 });
    return { reports, data, run: path => conversationMain(['--spec', specFile, '--out', reports, '--authorization', path, '--save', data], { env: {}, stdout: { write() {} } }).then(code => ({ code }), error => ({ error })) };
  };
  // A JSON turn answered after validUntil, then a stream turn: the stream transport is guarded too, so it is never sent.
  const stream = run('stream', spec('json', 'sse'));
  let r = await windowEndsMidRun(app, s, target, stream.run);
  assert.equal(r.result.error?.code, WINDOW_ENDED, JSON.stringify(r.result));
  assert.deepEqual(r.paths, ['/me'], 'the stream turn after the end was never sent');
  allBefore(r.arrivals, r.until);
  assert.deepEqual([existsSync(stream.reports), existsSync(stream.data)], [false, false]);
  // One JSON turn answered after validUntil: nothing is sent after the end, and the check before writing refuses the run.
  const single = run('single', spec('json'));
  r = await windowEndsMidRun(app, s, target, single.run);
  assert.equal(r.result.error?.code, WINDOW_ENDED, JSON.stringify(r.result));
  assert.match(r.result.error.message, /authorization refused \(authorization-window-ended\)/);
  assert.deepEqual(r.paths, ['/me']);
  allBefore(r.arrivals, r.until);
  assert.deepEqual([existsSync(single.reports), existsSync(single.data)], [false, false]);
});

test('a record that repeats a field name is refused (authorization-duplicate-key) before any connection, so the file cannot show one value and enforce another', async t => {
  const app = await notesApp(t), s = setup(t, app.origin);
  const { main: roe } = await import('../integrations/roe/cli.mjs');
  const { sealed } = s.record(), text = JSON.stringify(sealed);
  // Each file parses to the sealed record, so its checksum matches: JSON.parse keeps the last of a repeated name.
  const variants = [
    ['a repeated top-level field', text.replace('"origins":', '"origins":["http://127.0.0.1:1"],"origins":')],
    ['a repeated nested field', text.replace('"target":{', '"target":{"applicationId":"other-app",')],
    ['a repeat spelled with an escape', text.replace('"origins":', '"\\u006frigins":["http://127.0.0.1:1"],"origins":')],
  ];
  for (const [name, body] of variants) {
    const path = join(s.dir, `dup-${name.length}.json`); writeFileSync(path, body);
    const r = await assess(['--config', s.profiles, '--target', 'notes', '--out', join(s.dir, `out-dup-${name.length}`), '--authorization', path]);
    assert.equal(r.code, 2, `${name}: ${r.stderr}`);
    assert.match(r.stderr, /authorization refused \(authorization-duplicate-key\)/, name);
    let err = '';
    assert.equal(await roe(['check', path, '--config', s.profiles, '--target', 'notes'], { stdout: { write() {} }, stderr: { write: x => { err += x; } } }), 2, name);
    assert.equal(JSON.parse(err).code, 'authorization-duplicate-key', name);
  }
  // The same record without the repeat is accepted, and a draft with one is not sealed.
  assert.equal((await roe(['check', s.record().path, '--config', s.profiles, '--target', 'notes'], { stdout: { write() {} }, stderr: { write() {} } })), 0);
  const draft = join(s.dir, 'dup-draft.json'); writeFileSync(draft, JSON.stringify({ ...sealed, sha256: undefined }).replace('"id":', '"id":"shown-id","id":'));
  let err = '';
  assert.equal(await roe(['seal', draft, join(s.dir, 'dup-sealed.json')], { stdout: { write() {} }, stderr: { write: x => { err += x; } } }), 2);
  assert.equal(JSON.parse(err).code, 'authorization-duplicate-key');
  assert.equal(existsSync(join(s.dir, 'dup-sealed.json')), false);
  assert.equal(app.connections(), 0);
});

test('an operator-forwarded target runs only under a record naming the forwarder\'s destination, and a forwarded pass needs a same-route control', async t => {
  const app = await notesApp(t), s = setup(t, app.origin);
  // The boundary check reads GET /admin/settings (the app refuses it), with no required control on that route.
  const base = notesProfile(app.origin);
  const forwardedProfile = { ...base, targetContext: 'operator-forwarded', targetLabel: 'Notes staging (forwarded)', requiredControlIds: [...base.requiredControlIds, 'READ-NOTES'], checks: [...base.checks.filter(c => c.id !== 'OTHER-NOTE'),
    { id: 'READ-NOTES', title: 'A member reads the notes list', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'GET', path: '/notes', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }] },
    { id: 'ADMIN-SETTINGS', title: 'A member cannot read the admin settings', category: 'admin', severity: 'high', actorId: 'member', method: 'GET', path: '/admin/settings', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }] };
  writeFileSync(s.profiles, JSON.stringify({ schemaVersion: 1, targets: [forwardedProfile] }));
  const destination = r => { r.forwarded = { destination: 'https://staging.notes.example' }; };
  for (const [name, path, code] of [
    ['no destination', s.record().path, 'authorization-forwarded'],
    ['a destination with a path', s.record(r => { r.forwarded = { destination: 'https://staging.notes.example/app' }; }).path, 'authorization-invalid'],
    ['a destination with credentials', s.record(r => { r.forwarded = { destination: 'https://ops:pw@staging.notes.example' }; }).path, 'authorization-invalid'],
    ['another scheme', s.record(r => { r.forwarded = { destination: 'ftp://staging.notes.example' }; }).path, 'authorization-invalid'],
  ]) {
    const r = await assess(['--config', s.profiles, '--target', 'notes', '--out', join(s.dir, `fwd-${name.length}`), '--authorization', path]);
    assert.equal(r.code, 2, `${name}: ${r.stderr}`); assert.match(r.stderr, new RegExp(`authorization refused \\(${code}\\)`), name);
    assert.doesNotMatch(r.stderr, /staging\.notes\.example/, 'the destination is never echoed');
  }
  assert.equal(app.connections(), 0);
  // check-config names the boundary check with no same-route required control before any run.
  const config = await assess(['--check-config', '--config', s.profiles]);
  assert.deepEqual(JSON.parse(config.stdout).targets.find(x => x.id === 'notes').forwardedUnpaired, ['ADMIN-SETTINGS']);
  const { path, sealed } = s.record(destination);
  const r = await assess(['--config', s.profiles, '--target', 'notes', '--out', join(s.dir, 'fwd-ok'), '--authorization', path]);
  const printed = JSON.parse(r.stdout);
  assert.deepEqual(printed.authorization, STAMP(sealed));
  assert.ok(!JSON.stringify(savedRun(join(s.dir, 'fwd-ok'))).includes('staging.notes.example'), 'the destination never reaches the run');
  assert.deepEqual(printed.counts, { pass: 4, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }, 'every row passes');
  assert.deepEqual(printed.forwardedUnpaired, ['ADMIN-SETTINGS']);
  assert.equal(r.code, 1, 'a forwarded pass with no same-route control is not a clean exit');
  // A record that names a forwarder does not cover a local-app target.
  writeFileSync(s.profiles, JSON.stringify({ schemaVersion: 1, targets: [notesProfile(app.origin)] }));
  const before = app.connections();
  const local = await assess(['--config', s.profiles, '--target', 'notes', '--out', join(s.dir, 'fwd-local'), '--authorization', path]);
  assert.equal(local.code, 2); assert.match(local.stderr, /authorization refused \(authorization-forwarded\)/);
  assert.equal(app.connections(), before);
});

test('a forwarded target is held to the same window: no request after validUntil, and a run whose window ends after its last request is refused before it is saved', async t => {
  const app = await slowNotesApp(t), s = setup(t, app.origin);
  const forwarded = profile => ({ ...profile, targetContext: 'operator-forwarded', targetLabel: 'Notes staging (forwarded)' });
  // Every record names the forwarder's destination, as a forwarded target needs, so only the window refuses these runs.
  const named = { ...s, record: (edit = () => {}) => s.record(r => { r.forwarded = { destination: 'https://staging.notes.example' }; edit(r); }) };
  // The window ends while the run waits on the forwarder: the next request is never sent.
  const config = profilesFile(s, forwarded(notesProfile(app.origin))), out = join(s.dir, 'out-fwd-window');
  let r = await windowEndsMidRun(app, named, { id: 'notes', applicationId: 'notes-app' }, path => assess(['--config', config, '--target', 'notes', '--out', out, '--authorization', path]));
  assert.equal(r.result.code, 2, r.result.stderr);
  assert.match(r.result.stderr, /authorization refused \(authorization-window-ended\)/);
  allBefore(r.arrivals, r.until);
  assert.deepEqual(savedRunFiles(out), []);
  // The window ends after the run's one request was sent: only the check made immediately before saving refuses it.
  const one = profilesFile(s, forwarded(oneRequestProfile(app.origin))), outOne = join(s.dir, 'out-fwd-after-last');
  r = await windowEndsMidRun(app, named, { id: 'notes-one', applicationId: 'notes-app' }, path => assess(['--config', one, '--target', 'notes-one', '--out', outOne, '--authorization', path]));
  assert.equal(r.result.code, 2, r.result.stderr);
  assert.match(r.result.stderr, /authorization refused \(authorization-window-ended\)/);
  assert.deepEqual([r.arrivals.length, r.paths], [1, ['/notes']]);
  allBefore(r.arrivals, r.until);
  assert.deepEqual(savedRunFiles(outOne), []);
});
