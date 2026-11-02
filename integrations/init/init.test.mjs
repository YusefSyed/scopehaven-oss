// Focused tests for scopehaven init (v0). They run init end to end against the owned synthetic lab
// (examples/http-lab.mjs, the server behind ./scopehaven lab) and a small owned two-tenant app, over loopback only.
// Run unsandboxed: the starter assessment binds loopback and spawns the workbench CLI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, stat, chmod, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHttpLab } from '../../examples/http-lab.mjs';
import { main } from './cli.mjs';
import { observerCandidates, observerDrafts } from './observers.mjs';
import { sessionSecrets, sessionUnchanged, holdsSecret } from './envfile.mjs';
import { identityPointers, loopbackOrigin, makeProber, parseSlot, safePath } from './probe.mjs';
import { createServer } from 'node:http';
import { draftAuthorization, sealAuthorization, parseContact } from './authorization.mjs';
import { summarizeRun, formatFirstRow, firedAssertions } from './findings.mjs';
import { createTwoTenantApp } from './test/fixtures/two-tenant-app.mjs';
import { computeReceipt, timingTable, tableMarkdown, initClock, STAMPS_FILE, STAMP_SCHEMA, TABLE_LIMITS, LABEL, ROLE } from './clocks.mjs';

const ROE = ['--client', 'Synthetic test owner', '--contact', 'Test operator, Owner of the local copy'];
const NO_PASS_WORDING = /\bpass(ed|es|ing)?\b/i;

async function workspace() {
  // A folder whose name has a space, as the real checkout path does.
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven init test '));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}
async function envFile(dir, pairs, mode = 0o600) {
  const path = join(dir, 'identities.env');
  await writeFile(path, `${Object.entries(pairs).map(([k, v]) => `${k}=${v}`).join('\n')}\n`, { mode });
  await chmod(path, mode);
  return path;
}
async function runInit(argv, options = {}) {
  let text = '';
  const code = await main(argv, { stdout: { write: chunk => { text += chunk; } }, env: options.env ?? process.env, ask: options.ask, stdin: { isTTY: false }, hooksRoot: options.hooksRoot, ...(Object.hasOwn(options, 'head') ? { head: options.head } : {}) });
  return { code, text };
}
async function filesUnder(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await filesUnder(path)); else out.push(path);
  }
  return out;
}

test('init on the owned lab: one identity, sealed record, starter run, first INCONCLUSIVE row with its fired check', async () => {
  const lab = await createHttpLab();
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken });
    const out = join(dir, 'out');
    const { code, text } = await runInit(['--yes', '--base-url', lab.origin.replace('127.0.0.1', 'localhost'), '--env', env, '--id', 'lab', '--record-a', '/records/own', '--record-b', '/records/foreign',
      ...ROE, '--confirm-authorization', '--out', out]);
    assert.equal(code, 0, text);
    assert.match(text, /Who-am-I: \/me via bearer; identity field \/principalId/);
    assert.match(text, /check-config: configuration valid/);
    assert.match(text, /roe check: authorized until/);
    assert.match(text, /First decided row: INCONCLUSIVE {2}A-READS-B-RECORD-BACKEND/);
    assert.match(text, /fired check: Trusted backend observation available/);
    assert.doesNotMatch(text, NO_PASS_WORDING);
    const profile = JSON.parse(await readFile(join(out, 'targets.json'), 'utf8')).targets[0];
    assert.deepEqual(profile.requiredControlIds, ['A-WHOAMI', 'A-OWN-RECORD']);
    assert.equal(profile.actors.a.identityValue, 'lab-member-aster');
    assert.equal(profile.actors.a.credentialEnv, 'SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN');
    assert.ok(profile.checks.every(c => c.method === 'GET'));
    for (const file of await filesUnder(out)) assert.equal((await stat(file)).mode & 0o077, 0, `${file} is private`);
  } finally { await lab.close(); await cleanup(); }
});

test('two identities, leaky app: the cross-tenant read is the first FAIL row, twins recorded', async () => {
  const app = await createTwoTenantApp({ leaky: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const out = join(dir, 'out');
    const { code, text } = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--out', out]);
    assert.equal(code, 1, text);
    assert.match(text, /Who-am-I: \/api\/auth\/session via bearer; identity field \/user\/email/);
    assert.match(text, /Login or session routes: \/api\/auth\/signin \(200\)/);
    assert.match(text, /First decided row: FAIL {2}B-READS-A-RECORD/);
    assert.match(text, /Candidate FAIL before the run: B reading A's record answered 200/); assert.match(text, /Exit 1: the starter run has \d+ FAIL row/);
    assert.doesNotMatch(text, NO_PASS_WORDING);
    const report = JSON.parse(await readFile(join(out, 'init-report.json'), 'utf8'));
    assert.deepEqual(report.twins.map(t => [t.prohibition, t.allowedUse]), [['B-READS-A-RECORD', 'A-OWN-RECORD'], ['A-READS-B-RECORD', 'B-OWN-RECORD'], ['ANON-READS-A-RECORD', 'A-OWN-RECORD'], ['B-READS-A-RECORD-BACKEND', 'A-OWN-RECORD']]);
    const profile = JSON.parse(await readFile(join(out, 'targets.json'), 'utf8')).targets[0];
    assert.deepEqual(Object.keys(profile.actors), ['a', 'b', 'anonymous']);
    assert.notEqual(profile.actors.a.tenantId, profile.actors.b.tenantId);
    const record = JSON.parse(await readFile(join(out, 'authorization.json'), 'utf8'));
    assert.deepEqual(record.identities, ['identity-a', 'identity-b']);
    assert.equal(record.signer.organization, 'Synthetic test owner');
    assert.match(record.rulesOfEngagement.sha256, /^[a-f0-9]{64}$/);
  } finally { await app.close(); await cleanup(); }
});

test('cookie-only app: init finds the cookie slot; a correct app leaves the backend row as the first INCONCLUSIVE', async () => {
  const app = await createTwoTenantApp({ cookieOnly: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const { code, text } = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--out', join(dir, 'out')]);
    assert.equal(code, 0, text);
    assert.match(text, /via cookie:/);
    assert.match(text, /0 FAIL, 1 INCONCLUSIVE/);
    assert.match(text, /First decided row: INCONCLUSIVE {2}B-READS-A-RECORD-BACKEND/);
    assert.doesNotMatch(text, NO_PASS_WORDING);
  } finally { await app.close(); await cleanup(); }
});

test('no environment value ever reaches disk: credentials, observer variables and app .env values', async () => {
  // echoRef: each note answer carries the caller's own token in a "ref" field, which init must never declare or assert.
  const app = await createTwoTenantApp({ leaky: true, echoRef: true });
  const { dir, cleanup } = await workspace();
  const sentinels = ['SENTINELdbpass7f3a', 'SENTINELsmtp91c2', 'SENTINELprovider5d8e', 'SENTINELappenv44b1', 'SENTINELappdb0e9d'];
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const appEnv = join(dir, 'app.env');
    await writeFile(appEnv, `DATABASE_URL=postgres://app:${sentinels[4]}@127.0.0.1:5432/app\nSMTP_HOST=${sentinels[3]}.mail.example\nPAYMENTS_API_BASE_URL=https://${sentinels[3]}.example\n`);
    const processEnv = { ...process.env, DATABASE_URL: `postgres://app:${sentinels[0]}@127.0.0.1:5432/app`, SMTP_PASSWORD: sentinels[1], OPENAI_BASE_URL: `https://${sentinels[2]}.example/v1` };
    const out = join(dir, 'out');
    const { code, text } = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE,
      '--confirm-authorization', '--out', out, '--app-env', appEnv, '--use-observer', 'DATABASE_URL', '--use-observer', 'SMTP_HOST'], { env: processEnv });
    assert.equal(code, 1, text);
    assert.match(text, /Observer candidate: pg-snapshot from DATABASE_URL in the app \.env/);
    assert.match(text, /DATABASE_URL: not set in this environment/);
    assert.match(text, /Observer candidate: egress-recorder from PAYMENTS_API_BASE_URL in the app \.env/);
    assert.doesNotMatch(text, /OPENAI_BASE_URL/, 'with --app-env, the shell is not scanned');
    const secrets = [...sentinels, app.tokenA, app.tokenB];
    for (const secret of secrets) assert.ok(!text.includes(secret), 'no value in the output');
    const files = await filesUnder(out);
    assert.ok(files.some(f => f.endsWith('.json') && f.includes(`${join('evidence', 'runs')}`)), 'the starter run was saved');
    for (const file of files) {
      const content = await readFile(file, 'utf8');
      for (const secret of secrets) assert.ok(!content.includes(secret), `${file} holds no environment value`);
    }
    const drafts = JSON.parse(await readFile(join(out, 'observers.draft.json'), 'utf8')).drafts;
    assert.equal(drafts[0].observer.type, 'pg-snapshot');
    assert.equal(drafts[0].observer.port, '<port of the app database>');
    assert.match(drafts[0].observer.credentialEnv, /^SCOPEHAVEN_TARGET_NOTES_PG$/);
  } finally { await app.close(); await cleanup(); }
});

test('the authorization boundary: without confirmation init drafts the record and sends nothing', async () => {
  const app = await createTwoTenantApp();
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const out = join(dir, 'out');
    const { code, text } = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--out', out]);
    assert.equal(code, 2, text);
    assert.match(text, /Stopped before any request/);
    assert.equal(app.requests(), 0);
    const names = (await readdir(out)).sort();
    // The drafts, and this run's timing stamps (stage names and times only), nothing else.
    assert.deepEqual(names, ['authorization.draft.json', 'init-stamps.jsonl', 'rules-of-engagement.md']);
    // The printed recovery works: the same command with --confirm-authorization, no --force needed.
    const again = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--out', out, '--confirm-authorization', '--no-run']);
    assert.equal(again.code, 0, again.text);
    assert.ok((await readdir(out)).includes('authorization.json'));
  } finally { await app.close(); await cleanup(); }
});

test('a declined --force rerun removes the record sealed before, so it cannot outlive its answers', async () => {
  const app = await createTwoTenantApp();
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const out = join(dir, 'out');
    const base = ['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', '--out', out, '--no-run'];
    assert.equal((await runInit([...base, ...ROE, '--confirm-authorization'])).code, 0);
    const refused = await runInit([...base, ...ROE, '--confirm-authorization']);
    assert.equal(refused.code, 2); assert.match(refused.text, /from an earlier init; use --force/);
    assert.ok((await readdir(out)).includes('authorization.json'), 'a refused rerun changes nothing');
    const declined = await runInit([...base, '--client', 'Another owner', '--contact', 'Someone else, Owner', '--force']);
    assert.equal(declined.code, 2, declined.text);
    assert.match(declined.text, /Removed the record an earlier run sealed/);
    assert.ok(!(await readdir(out)).includes('authorization.json'));
  } finally { await app.close(); await cleanup(); }
});

test('records: the same path for A and B is refused (a session-scoped route would read as a false FAIL)', async () => {
  const app = await createTwoTenantApp();
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const r = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-a1', ...ROE, '--confirm-authorization', '--out', join(dir, 'out')]);
    assert.equal(r.code, 3); assert.match(r.text, /--record-b is the same path as --record-a/);
    assert.ok(!(await readdir(join(dir, 'out'))).includes('targets.json'));
  } finally { await app.close(); await cleanup(); }
});

test('unsafe paths and reserved credential headers are refused before any request', async () => {
  const app = await createTwoTenantApp();
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    for (const [flag, value] of [['--whoami', 'http://other.example/x'], ['--whoami', '/a//b'], ['--record-a', '/api/../notes/x'], ['--record-b', '/api/notes/%2e%2e/x'], ['--credential', 'header:Host'], ['--credential', 'header:Authorization']]) {
      const r = await runInit(['--yes', '--base-url', app.origin, '--env', env, ...ROE, '--confirm-authorization', '--out', join(dir, `o-${Math.random()}`), flag, value]);
      assert.notEqual(r.code, 0, `${flag} ${value}`);
    }
    assert.equal(app.requests(), 0);
    assert.ok(safePath('/api/document?id=977cb1a7-bb09-49a8-b382-ef9e01444648'));
    assert.throws(() => parseSlot('header:content-length'), /not a header a credential may use/);
    assert.deepEqual(parseSlot('header:x-api-key'), { kind: 'header', name: 'x-api-key' });
  } finally { await app.close(); await cleanup(); }
});


test('--session reaches the session-import hook by path; no credential from the session or env file is written', async () => {
  const app = await createTwoTenantApp();
  const { dir, cleanup } = await workspace();
  // Session values are generated per run (gitleaks-safe); the HAR carries them as a cookie, a bearer header and a token field.
  const cookieValue = randomBytes(24).toString('base64url'), bearerValue = randomBytes(24).toString('base64url'), csrfValue = randomBytes(16).toString('hex');
  const passwordValue = randomBytes(12).toString('hex'), accessValue = randomBytes(24).toString('base64url'), urlTokenValue = randomBytes(20).toString('hex');
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const har = join(dir, 'identity a.har');
    // Credentials sit in headers and cookies, and also inside the request body, the response body and the URL's query.
    const harBody = { log: { version: '1.2', entries: [{ request: { method: 'GET', url: `${app.origin}/api/notes/note-a1?access_token=${urlTokenValue}`,
      headers: [{ name: 'Cookie', value: `authjs.session-token=${cookieValue}` }, { name: 'Authorization', value: `Bearer ${bearerValue}` }], cookies: [{ name: 'authjs.session-token', value: cookieValue }],
      postData: { mimeType: 'application/json', text: JSON.stringify({ email: 'ada@tenant-a.example', password: passwordValue }) } },
      response: { status: 200, headers: [], content: { text: JSON.stringify({ csrfToken: csrfValue, access_token: accessValue }) } } }] } };
    await writeFile(har, JSON.stringify(harBody), { mode: 0o644 });
    const hooksRoot = fileURLToPath(new URL('./test/fixtures/hooks/', import.meta.url));
    const args = ['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--no-run', '--session', har];
    // A session file others can read is refused before anything is drafted or sent.
    let r = await runInit([...args, '--out', join(dir, 'o1')], { hooksRoot });
    assert.equal(r.code, 2); assert.match(r.text, /the session file has mode 644/); assert.equal(app.requests(), 0);
    await chmod(har, 0o600);
    globalThis.__initSessionHookCalls = [];
    const out = join(dir, 'out');
    r = await runInit([...args, '--out', out], { hooksRoot });
    assert.equal(r.code, 0, r.text);
    assert.deepEqual(globalThis.__initSessionHookCalls, [{ session: har, actors: ['a', 'b', 'anonymous'] }]);
    assert.match(r.text, /session-import\/init-hook\.mjs 1 drafted/);
    assert.match(r.text, /policy-import\/init-hook\.mjs: not written \(its output held a credential value/);
    const inference = JSON.parse(await readFile(join(out, 'inference-draft.json'), 'utf8'));
    assert.match(r.text, /model-standin\/init-hook\.mjs: not written \(its output held a credential value/);
    assert.deepEqual(inference.proposals.map(p => [p.module, Boolean(p.withheld)]), [['policy-import/init-hook.mjs', true], ['session-import/init-hook.mjs', false], ['model-standin/init-hook.mjs', true]]);
    const kept = inference.proposals.find(p => p.module === 'session-import/init-hook.mjs');
    assert.equal(kept.checks[0].path, '/api/notes/note-a1'); assert.equal(kept.session, undefined, 'the imported session is not kept');
    for (const file of await filesUnder(out)) {
      const content = await readFile(file, 'utf8');
      for (const secret of [cookieValue, bearerValue, csrfValue, passwordValue, accessValue, urlTokenValue, app.tokenA, app.tokenB]) assert.ok(!content.includes(secret), `${file} holds no credential`);
      assert.ok(!content.includes('identity a.har'), `${file} does not record the session path`);
    }
    for (const secret of [cookieValue, bearerValue, csrfValue, passwordValue, accessValue, urlTokenValue]) assert.ok(!r.text.includes(secret));
    // A JSON-lines request log: a token in a URL query and a form body are collected; escaped forms and the path are matched.
    const log = join(dir, 'requests.jsonl');
    const formSecret = randomBytes(10).toString('hex'), quoted = `"${randomBytes(10).toString('hex')}"`;
    await writeFile(log, `${JSON.stringify({ method: 'GET', url: `/api/x?api_key=${urlTokenValue}` })}\n${JSON.stringify({ method: 'POST', url: '/login', body: `user=ada&password=${formSecret}`, headers: { cookie: `sid=${quoted}` } })}\n`, { mode: 0o600 });
    const collected = (await sessionSecrets(log)).secrets;
    assert.ok(collected.has(urlTokenValue) && collected.has(formSecret), 'query and form-body values collected');
    assert.ok(holdsSecret({ title: JSON.parse(JSON.stringify({ t: quoted })).t }, collected), 'a quoted cookie value is matched in its JSON-escaped form');
    assert.ok(holdsSecret({ warnings: [`parsed ${har}`] }, new Set([har])), 'the session path is matched');
    // Set-Cookie attributes are not collected as credentials; a jwt field is.
    const attrs = join(dir, 'attrs.jsonl'), jwtValue = randomBytes(20).toString('hex');
    await writeFile(attrs, `${JSON.stringify({ url: '/login', headers: { 'set-cookie': `sid=${formSecret}; Path=/api/auth/refresh; Max-Age=31536000` }, body: JSON.stringify({ jwt: jwtValue }) })}\n`, { mode: 0o600 });
    const attrSecrets = (await sessionSecrets(attrs)).secrets;
    assert.ok(attrSecrets.has(formSecret) && attrSecrets.has(jwtValue));
    assert.ok(!attrSecrets.has('/api/auth/refresh') && !attrSecrets.has('31536000'));
    assert.ok(holdsSecret('Unexpected token, "Bearer ' + bearerValue + '" is not valid JSON', new Set([bearerValue])), 'error text is checked like output');
    // A file swapped after the check is detected.
    const { identity } = await sessionSecrets(log);
    assert.ok(await sessionUnchanged(log, identity));
    await rm(log); await writeFile(log, `${JSON.stringify({ method: 'GET', url: '/other' })}\n`, { mode: 0o600 });
    assert.ok(!(await sessionUnchanged(log, identity)));
  } finally { await app.close(); await cleanup(); delete globalThis.__initSessionHookCalls; }
});

test('PostgREST-style filtering: 200 [] for another tenant or a signed-out read keeps its empty shape, no false FAIL', async () => {
  const app = await createTwoTenantApp({ postgrest: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const out = join(dir, 'out');
    const { code, text } = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/rest/v1/notes?id=eq.note-a1', '--record-b', '/rest/v1/notes?id=eq.note-b1', ...ROE, '--confirm-authorization', '--out', out]);
    assert.equal(code, 0, text);
    assert.match(text, /B-READS-A-RECORD: answered 2xx with an empty list, so it must stay empty \(judged by content, not status\)/);
    assert.match(text, / 0 FAIL, /);
    assert.doesNotMatch(text, /First decided row: FAIL/);
    const profile = JSON.parse(await readFile(join(out, 'targets.json'), 'utf8')).targets[0];
    const byId = Object.fromEntries(profile.checks.map(c => [c.id, c]));
    // An empty list keeps its shape, so any populated answer later fails whichever fields it holds.
    for (const id of ['B-READS-A-RECORD', 'A-READS-B-RECORD', 'ANON-READS-A-RECORD']) assert.deepEqual(byId[id].assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/0', expected: false }], id);
    assert.equal(profile.tenantValues, undefined, 'no check judges by tenant values, so none are declared');
    // The own-record control shows the owner's record was served, not just a 200.
    assert.deepEqual(byId['A-OWN-RECORD'].assertions[1], { kind: 'json.equals', pointer: '/0/id', expected: 'note-a1' });
  } finally { await app.close(); await cleanup(); }
});

test('PostgREST-style app that leaks: a 200 carrying the other tenant\'s row, seen during discovery, is a FAIL on its status, exit 1', async () => {
  const app = await createTwoTenantApp({ postgrest: true, leaky: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const { code, text } = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/rest/v1/notes?id=eq.note-a1', '--record-b', '/rest/v1/notes?id=eq.note-b1', ...ROE, '--confirm-authorization', '--out', join(dir, 'out')]);
    assert.equal(code, 1, text);
    assert.match(text, /First decided row: FAIL {2}B-READS-A-RECORD/);
    // A leak seen during discovery keeps the refusal statuses, so the run decides it on the status (an echoed id alone
    // would read inconclusive under the content rules).
    assert.match(text, /Candidate FAIL before the run: B reading A's record answered 200 with 2 of the owner's record values; its check expects a refusal/);
    assert.match(text, /fired check: HTTP status matches contract: expected HTTP 403 or 404; got HTTP 200/);
    assert.doesNotMatch(text, NO_PASS_WORDING);
  } finally { await app.close(); await cleanup(); }
});

test('a wrapped empty list ({ data: [] }) keeps its shape; another 2xx body is judged by the other tenant\'s values; no false FAIL', async () => {
  const wrappedApp = await createTwoTenantApp({ postgrest: true, wrapped: true });
  const messageApp = await createTwoTenantApp({ postgrest: true, wrapped: 'message' });
  const { dir, cleanup } = await workspace();
  try {
    const args = async (app, out) => ['--yes', '--base-url', app.origin, '--env', await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB }), '--id', 'notes',
      '--record-a', '/rest/v1/notes?id=eq.note-a1', '--record-b', '/rest/v1/notes?id=eq.note-b1', ...ROE, '--confirm-authorization', '--out', out];
    const ids = ['B-READS-A-RECORD', 'A-READS-B-RECORD', 'ANON-READS-A-RECORD'];
    let r = await runInit(await args(wrappedApp, join(dir, 'wrapped')));
    assert.equal(r.code, 0, r.text); assert.match(r.text, / 0 FAIL, /);
    let profile = JSON.parse(await readFile(join(dir, 'wrapped', 'targets.json'), 'utf8')).targets[0];
    for (const id of ids) assert.deepEqual(profile.checks.find(c => c.id === id).assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/data/0', expected: false }, { kind: 'json.noForeignValues', pointer: '' }], id);
    r = await runInit(await args(messageApp, join(dir, 'message')));
    assert.equal(r.code, 0, r.text); assert.match(r.text, / 0 FAIL, /);
    profile = JSON.parse(await readFile(join(dir, 'message', 'targets.json'), 'utf8')).targets[0];
    for (const id of ids) assert.deepEqual(profile.checks.find(c => c.id === id).assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '' }], id);
    assert.deepEqual(Object.keys(profile.tenantValues.tenants), ['tenant-a', 'tenant-b', 'signed-out']);
    assert.ok(profile.tenantValues.tenants['tenant-a'].identifiers.includes('Ada synthetic note'));
    assert.equal(profile.actors.anonymous.tenantId, 'signed-out');
    // An empty "errors" array is not the list of rows: the body is judged by the other tenant's values.
    const errorsApp = await createTwoTenantApp({ postgrest: true, wrapped: 'errors' });
    try {
      r = await runInit(await args(errorsApp, join(dir, 'errors')));
      assert.equal(r.code, 0, r.text);
      profile = JSON.parse(await readFile(join(dir, 'errors', 'targets.json'), 'utf8')).targets[0];
      for (const id of ids) assert.deepEqual(profile.checks.find(c => c.id === id).assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '' }], id);
    } finally { await errorsApp.close(); }
  } finally { await wrappedApp.close(); await messageApp.close(); await cleanup(); }
});

test('who-am-I discovery: a custom cookie name set on the login page is tried; a miss says what was tried and what came back', async () => {
  const app = await createTwoTenantApp({ cookieOnly: true, cookieName: 'nw_session' });
  const sick = await createTwoTenantApp({ unhealthy: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const base = ['--yes', '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--no-run'];
    let r = await runInit([...base, '--base-url', app.origin, '--out', join(dir, 'o1')]);
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /Who-am-I: \/api\/auth\/session via cookie:nw_session/);
    // The same app, with the cookie slot ruled out: the miss names the refusals, not the sessions.
    r = await runInit([...base, '--base-url', app.origin, '--credential', 'bearer', '--whoami', '/api/notes/note-a1', '--out', join(dir, 'o2')]);
    assert.equal(r.code, 3, r.text);
    assert.match(r.text, /tried 1 route x 1 credential slot; none named each identity/);
    assert.match(r.text, /answered only 401 or 403 under every slot tried/);
    assert.doesNotMatch(r.text, /Check that both sessions are signed in/);
    r = await runInit([...base, '--base-url', sick.origin, '--out', join(dir, 'o3')]);
    assert.equal(r.code, 3, r.text);
    assert.match(r.text, /every answer was a 5xx or no answer: is the app healthy\?/);
    assert.match(r.text, /signed out and one signed in, and stopped there/);
    assert.match(r.text, /Looking for the who-am-I route/);
    // A handler that fails signed out but answers signed in is still found, with --whoami or by the search.
    const crash = await createTwoTenantApp({ crashSignedOut: true });
    try {
      const crashEnv = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: crash.tokenA, SCOPEHAVEN_TARGET_NOTES_B: crash.tokenB });
      const crashBase = ['--yes', '--env', crashEnv, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--no-run', '--base-url', crash.origin];
      r = await runInit([...crashBase, '--whoami', '/api/me', '--out', join(dir, 'o4')]);
      assert.equal(r.code, 0, r.text); assert.match(r.text, /Who-am-I: \/api\/me via bearer; identity field \/email/);
      // Without --whoami, the search finds it too (other candidate routes answer 404, so the app is not stopped early).
      r = await runInit([...crashBase, '--out', join(dir, 'o5')]);
      assert.equal(r.code, 0, r.text); assert.match(r.text, /Who-am-I: \/api\/me via bearer; identity field \/email/);
    } finally { await crash.close(); }
  } finally { await app.close(); await sick.close(); await cleanup(); }
});

test('refusals: a non-loopback base URL, an env file readable by others, hosts that leave out the app', async () => {
  const { dir, cleanup } = await workspace();
  try {
    assert.throws(() => loopbackOrigin('http://example.com:3000'), /loopback/);
    assert.throws(() => loopbackOrigin('https://127.0.0.1:3000'), /http app on loopback/);
    const open = await envFile(dir, { SCOPEHAVEN_TARGET_X_A: 'tokenvalue1' }, 0o644);
    let r = await runInit(['--yes', '--base-url', 'http://127.0.0.1:9', '--env', open, ...ROE, '--record-a', '/a', '--record-b', '/b', '--confirm-authorization', '--out', join(dir, 'o1')]);
    assert.equal(r.code, 2); assert.match(r.text, /chmod 600/);
    const ok = await envFile(dir, { SCOPEHAVEN_TARGET_X_A: 'tokenvalue1' });
    r = await runInit(['--yes', '--base-url', 'http://127.0.0.1:9', '--env', ok, ...ROE, '--record-a', '/a', '--record-b', '/b', '--hosts', 'http://127.0.0.1:10', '--confirm-authorization', '--out', join(dir, 'o2')]);
    assert.equal(r.code, 2); assert.match(r.text, /hosts do not include/);
    r = await runInit(['--yes', '--base-url', 'http://127.0.0.1:9', '--env', ok, '--out', join(dir, 'o3')]);
    assert.equal(r.code, 2); assert.match(r.text, /init needs --client, --contact, --record-a, --record-b \(and --confirm-authorization/);
  } finally { await cleanup(); }
});

test('interactive: init asks for what it cannot find and re-asks for a record the identity cannot open', async () => {
  const app = await createTwoTenantApp();
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const asked = [];
    const answers = { '--base-url': app.origin, '--env': env, '--id': 'notes', '--client': 'Synthetic owner', '--contact': 'Test operator, Owner', '--confirm-authorization': 'yes',
      '--record-a': ['/api/notes/note-b1', '/api/notes/note-a1'], '--record-b': '/api/notes/note-b1' };
    const ask = async flag => { asked.push(flag); const a = answers[flag]; return Array.isArray(a) ? a.shift() : a ?? ''; };
    const { code, text } = await runInit(['--no-run', '--out', join(dir, 'out')], { ask });
    assert.equal(code, 0, text);
    assert.match(text, /answered identity A with 403/);
    assert.equal(asked.filter(f => f === '--record-a').length, 2);
    for (const flag of ['--base-url', '--env', '--client', '--contact', '--confirm-authorization']) assert.ok(asked.includes(flag), `asked ${flag}`);
    assert.match(text, /Stopped after writing/);
  } finally { await app.close(); await cleanup(); }
});

test('units: observer candidates come from names, identity pointers need distinct values, findings never say pass', () => {
  const candidates = observerCandidates(['DATABASE_URL', 'PGHOST', 'SMTP_HOST', 'SMTP_PASSWORD', 'STRIPE_API_BASE', 'NEXT_PUBLIC_API_URL', 'REDIS_URL', 'HOME']);
  assert.deepEqual(candidates.map(c => [c.observer, c.names]), [['pg-snapshot', ['DATABASE_URL', 'PGHOST']], ['smtp-sink', ['SMTP_HOST', 'SMTP_PASSWORD']], ['egress-recorder', ['STRIPE_API_BASE']]]);
  assert.ok(JSON.stringify(observerDrafts('app', candidates)).includes('<port of the app database>'));
  // The operator's container and cluster client settings are not an API the app calls; an app's own *_HOST still is.
  assert.deepEqual(observerCandidates(['DOCKER_HOST', 'CONTAINER_HOST', 'BUILDKIT_HOST', 'KUBERNETES_SERVICE_HOST', 'OLLAMA_HOST']).map(c => [c.observer, c.names]), [['egress-recorder', ['OLLAMA_HOST']]]);
  const ans = (status, json) => ({ status, json, jsonParsed: true });
  const a = ans(200, { user: { email: 'a@x.example', role: 'member' } }), b = ans(200, { user: { email: 'b@x.example', role: 'member' } });
  assert.deepEqual(identityPointers(a, ans(200, null), b).map(p => p.pointer), ['/user/email']);
  assert.deepEqual(identityPointers(a, ans(200, null), a), [], 'the same account twice names no identity');
  assert.deepEqual(identityPointers(a, ans(200, { user: { email: 'a@x.example' } })), [], 'a value the signed-out answer carries is not session-derived');
  // A who-am-I answer that echoes the session token never yields the token as the identity value.
  const token = randomBytes(18).toString('base64url');
  const echo = ans(200, { sub: token, session: { token }, user: { name: 'Ada Example' } });
  assert.deepEqual(identityPointers(echo, ans(401, null), undefined, [token]).map(p => p.pointer), ['/user/name']);
  // A user's email under a tenant object outranks the tenant's bare id; a key ending in email counts as an email.
  const settingsA = ans(200, { business: { id: 'biz-1', owner_email: 'ada@x.example' } }), settingsB = ans(200, { business: { id: 'biz-2', owner_email: 'bo@x.example' } });
  assert.equal(identityPointers(settingsA, ans(401, null), settingsB)[0].pointer, '/business/owner_email');
  assert.equal(identityPointers(ans(200, { support_email: 'a@x.example', sub: 'user-a' }), ans(401, null), ans(200, { support_email: 'b@x.example', sub: 'user-b' }))[0].pointer, '/sub');
  // The session file's name alone is withheld.
  assert.ok(holdsSecret({ warnings: ['parsed identity a.har'] }, new Set(['identity a.har'])));
  // A long target id still makes a valid record id (at most 80 characters).
  const long = 'x'.repeat(80);
  const { draft } = draftAuthorization({ id: long, origin: 'http://127.0.0.1:3000', answers: { client: 'c', hosts: ['http://127.0.0.1:3000'], actions: 'a', dataClass: 'd', contact: parseContact('N, R') }, identities: ['identity-a'] });
  assert.ok(sealAuthorization(draft).id.length <= 80);
  // The workbench's reason texts say "did not pass"; the summary says "did not hold".
  const fired = firedAssertions({ status: 'inconclusive', assertions: [{ name: 'Actor identity established by required controls', status: 'inconclusive', expected: 'Identity proven', actual: "This actor's identity control did not pass" }] });
  assert.doesNotMatch(JSON.stringify(fired), NO_PASS_WORDING);
  assert.match(fired[0].actual, /did not hold/);
  // The app's own values are never reworded.
  assert.equal(firedAssertions({ status: 'fail', assertions: [{ name: 'n', status: 'fail', expected: 'pass.holder@x.example', actual: 'other' }] })[0].expected, 'pass.holder@x.example');
  assert.doesNotMatch(formatFirstRow({ verdict: 'INCONCLUSIVE', id: 'Z', title: 't', severity: 'high', decision: 'inconclusive', summary: 'A distinct state, never a pass.', fired: [] }).join('\n'), NO_PASS_WORDING);
  // safePath follows the loader: an encoded percent sign is a valid path.
  assert.ok(safePath('/api/search?q=50%25'));
  assert.ok(!safePath('/api/%252e%252e/x'));
  const run = { results: [{ id: 'X', title: 't', severity: 'high', status: 'pass', assertions: [] },
    { id: 'Y', title: 'u', severity: 'high', status: 'inconclusive', summary: 'One assertion passed and one did not.', assertions: [{ name: 'n', status: 'inconclusive', expected: 'e', actual: 'a' }] }] };
  const summary = summarizeRun(run);
  assert.equal(summary.first.id, 'Y');
  assert.doesNotMatch(formatFirstRow(summary.first).join('\n'), NO_PASS_WORDING);
  assert.doesNotMatch(formatFirstRow(null).join('\n'), NO_PASS_WORDING);
});

test('GoTrue who-am-I, labelled shell candidates, Supabase candidate, re-asked empty answers, the rerun line, assistant routes', async () => {
  const app = await createTwoTenantApp({ gotrue: true, chat: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const appEnv = join(dir, 'app.env');
    await writeFile(appEnv, 'SUPABASE_URL=http://127.0.0.1:54321\nNEXT_PUBLIC_SUPABASE_ANON_KEY=x\n');
    const base = ['--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', '--no-run'];
    let r = await runInit(['--yes', ...base, ...ROE, '--confirm-authorization', '--app-env', appEnv, '--out', join(dir, 'o1')]);
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /Who-am-I: \/auth\/v1\/user via bearer; identity field \/email/);
    assert.match(r.text, /Observer candidate: pg-snapshot from SUPABASE_URL in the app \.env \(Supabase stack: a local one keeps its Postgres on 127\.0\.0\.1:54322/);
    assert.match(r.text, /Assistant or agent routes: \/api\/chat \(405\)\. Not drafted: assistant-turn checks need a message and a planted value/);
    assert.deepEqual(JSON.parse(await readFile(join(dir, 'o1', 'init-report.json'), 'utf8')).chatRoutes, [{ path: '/api/chat', status: 405 }]);
    assert.ok(r.text.includes(`set -a; . ${/\s/.test(env) ? `'${env}'` : env}; set +a;`), 'the rerun line names the env file init was given');
    assert.doesNotMatch(r.text, /YOUR_ENV_FILE/);
    // Interactive, no --app-env: a shell candidate is labelled and never asked about; an empty answer is asked again.
    const asked = [];
    const answers = { '--client': ['', 'Synthetic owner'], '--contact': 'Test operator, Owner', '--confirm-authorization': 'yes' };
    const ask = async flag => { asked.push(flag); const a = answers[flag]; return Array.isArray(a) ? a.shift() : a ?? ''; };
    r = await runInit([...base, '--out', join(dir, 'o2')], { ask, env: { ...process.env, ANTHROPIC_BASE_URL: 'https://operator-tool.example' } });
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /egress-recorder from ANTHROPIC_BASE_URL in this shell \(may be your own tools' settings, not the app's; give --app-env for the app's\)/);
    assert.ok(!asked.includes('--use-observer'), 'a shell candidate is never asked about');
    assert.match(r.text, /--client needs an answer\./);
    assert.equal(asked.filter(f => f === '--client').length, 2);
  } finally { await app.close(); await cleanup(); }
});

test('cold-setup follow-up: n8n\'s GET /rest/login and its n8n-auth cookie are found without --whoami or --credential', async () => {
  const app = await createTwoTenantApp({ n8n: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const r = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1',
      ...ROE, '--confirm-authorization', '--no-run', '--out', join(dir, 'out')]);
    assert.equal(r.code, 0, r.text);
    assert.match(r.text, /Who-am-I: \/rest\/login via cookie:n8n-auth; identity field \/data\/email \(signed out it answers 401\)/);
    const targets = JSON.parse(await readFile(join(dir, 'out', 'targets.json'), 'utf8'));
    assert.match(JSON.stringify(targets), /"\/rest\/login"/);
    assert.ok(!JSON.stringify(targets).includes(app.tokenA), 'no session value in the profile');
  } finally { await app.close(); await cleanup(); }
});

const stampsIn = async out => (await readFile(join(out, STAMPS_FILE), 'utf8')).trim().split('\n').map(line => JSON.parse(line));

test('timed onboarding: start, init stamps every stage, the review of a FAIL, the receipt with both clocks', async () => {
  const app = await createTwoTenantApp({ leaky: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: app.tokenA, SCOPEHAVEN_TARGET_NOTES_B: app.tokenB });
    const out = join(dir, 'onboarding one');
    let r = await runInit(['start', '--out', out, '--label', 'owned-notes', '--owned', 'yes', '--operator-role', 'agent operator, never saw the app'], { head: 'f'.repeat(40) });
    assert.equal(r.code, 0, r.text);
    r = await runInit(['start', '--out', out, '--label', 'owned-notes', '--owned', 'yes', '--operator-role', 'agent operator'], { head: null });
    assert.equal(r.code, 2, 'one folder is one onboarding'); assert.match(r.text, /already has stamps/);
    // A first init run that stops before any request still stamps its end, with its exit status and stop code.
    r = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--out', out], { head: 'f'.repeat(40) });
    assert.equal(r.code, 2, r.text);
    r = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--out', out], { head: 'f'.repeat(40) });
    assert.equal(r.code, 1, r.text);
    assert.equal((await stat(join(out, STAMPS_FILE))).mode & 0o077, 0);
    const stamps = await stampsIn(out);
    const runs = [...new Set(stamps.filter(s => s.stage !== 'onboarding-start').map(s => s.run))];
    assert.equal(runs.length, 2);
    assert.deepEqual(stamps.filter(s => s.run === runs[0]).map(s => s.stage), ['start', 'identities-read', 'authorization-drafted', 'end']);
    assert.equal(stamps.find(s => s.run === runs[0] && s.stage === 'end').exit, 2);
    assert.deepEqual(stamps.filter(s => s.run === runs[1]).map(s => s.stage), ['start', 'identities-read', 'authorization-drafted', 'authorization-sealed', 'probe-start', 'whoami-found', 'records-probed', 'profile-written', 'config-checked', 'run-saved', 'first-decided-row', 'end']);
    const saved = stamps.find(s => s.stage === 'run-saved');
    assert.ok(saved.failChecks.includes('B-READS-A-RECORD'));
    // The stamps hold no credential, path or host.
    const raw = await readFile(join(out, STAMPS_FILE), 'utf8');
    for (const secret of [app.tokenA, app.tokenB, dir, app.origin, '127.0.0.1']) assert.ok(!raw.includes(secret), 'no value, path or host in the stamps');
    // The report carries this run's timing and the starter run.
    const report = JSON.parse(await readFile(join(out, 'init-report.json'), 'utf8'));
    assert.equal(report.timing.firstDecidedRow.verdict, 'FAIL');
    assert.equal(report.starterRun.id, saved.runId);
    assert.match(report.timing.firstHeldFail, /pending review/);
    // Review: only a FAIL row of a stamped run; then the receipt.
    r = await runInit(['review', '--out', out, '--run', saved.runId, '--check', 'A-WHOAMI', '--holds', 'yes', '--reviewer-role', 'onboarding reviewer']);
    assert.equal(r.code, 2); assert.match(r.text, /not a FAIL row/);
    r = await runInit(['receipt', '--out', out]);
    assert.equal(r.code, 0, r.text); assert.match(r.text, /unreviewed [1-9]/);
    for (const check of saved.failChecks) {
      r = await runInit(['review', '--out', out, '--run', saved.runId, '--check', check, '--holds', check === 'B-READS-A-RECORD' ? 'yes' : 'no', '--reviewer-role', 'onboarding reviewer']);
      assert.equal(r.code, 0, r.text);
    }
    r = await runInit(['receipt', '--out', out]);
    assert.equal(r.code, 0, r.text);
    const receipt = JSON.parse(await readFile(join(out, 'onboarding-receipt.json'), 'utf8'));
    assert.equal((await stat(join(out, 'onboarding-receipt.json'))).mode & 0o077, 0);
    assert.equal(receipt.clockStart.from, 'onboarding-start');
    assert.equal(receipt.label, 'owned-notes'); assert.equal(receipt.owned, true); assert.equal(receipt.productHead, 'f'.repeat(40));
    assert.equal(receipt.clocks.firstDecidedRow.verdict, 'FAIL');
    assert.equal(receipt.clocks.firstHeldFail.check, 'B-READS-A-RECORD');
    assert.ok(receipt.clocks.firstHeldFail.minutes >= receipt.clocks.firstDecidedRow.minutes - 0.01);
    assert.deepEqual(receipt.initRuns.map(x => x.exit), [2, 1]);
    assert.deepEqual(receipt.initRuns.map(x => x.reached), ['authorization-drafted', 'first-decided-row']);
    assert.equal(receipt.fails.unreviewed.length, 0);
    assert.equal(receipt.fails.falseFails.length, saved.failChecks.length - 1);
    r = await runInit(['table', out]);
    assert.equal(r.code, 0, r.text); assert.match(r.text, /\| owned-notes \| yes \|/); assert.match(r.text, /met: no/);
    assert.match(r.text, /\nLimits: stamps are this machine's wall clock and carry no key: a timing table, not evidence; what each operator had in context before the start stamp is only what the operator role says; init cannot check it\.\n/);
    r = await runInit(['table', out, '--json']);
    assert.equal(r.code, 0, r.text);
    assert.deepEqual(JSON.parse(r.text).limits, ['stamps are this machine\'s wall clock and carry no key: a timing table, not evidence',
      'what each operator had in context before the start stamp is only what the operator role says; init cannot check it']);
    // One onboarding counts once: the same folder twice, or a copy of it, is refused.
    r = await runInit(['table', out, out]); assert.equal(r.code, 2); assert.match(r.text, /given twice/);
    const copy = join(dir, 'copy');
    await mkdir(copy, { mode: 0o700 });
    await writeFile(join(copy, STAMPS_FILE), await readFile(join(out, STAMPS_FILE)), { mode: 0o600 });
    r = await runInit(['table', out, copy]); assert.equal(r.code, 2); assert.match(r.text, /same onboarding appears twice/);
    assert.doesNotMatch(r.text + receipt.note, NO_PASS_WORDING);
    // A --force rerun into the same folder adds a third run to the same onboarding; its new FAIL rows are unreviewed.
    r = await runInit(['--yes', '--base-url', app.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--force', '--out', out], { head: 'f'.repeat(40) });
    assert.equal(r.code, 1, r.text);
    r = await runInit(['receipt', '--out', out]);
    const again = JSON.parse(await readFile(join(out, 'onboarding-receipt.json'), 'utf8'));
    assert.deepEqual(again.initRuns.map(x => x.exit), [2, 1, 1]);
    assert.equal(again.clocks.firstDecidedRow.runId, receipt.clocks.firstDecidedRow.runId, 'the first decided row stays the first run\'s');
    assert.ok(again.fails.unreviewed.length > 0);
  } finally { await app.close(); await cleanup(); }
});

test('timed onboarding: a stop after requests stamps its stop code; --stack without the stack module refuses', async () => {
  const sick = await createTwoTenantApp({ unhealthy: true });
  const { dir, cleanup } = await workspace();
  try {
    const env = await envFile(dir, { SCOPEHAVEN_TARGET_NOTES_A: sick.tokenA, SCOPEHAVEN_TARGET_NOTES_B: sick.tokenB });
    const out = join(dir, 'out');
    let r = await runInit(['--yes', '--base-url', sick.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--no-run', '--out', out]);
    assert.equal(r.code, 3, r.text);
    const end = (await stampsIn(out)).at(-1);
    assert.deepEqual([end.stage, end.exit, end.stop], ['end', 3, 'whoami']);
    const first = await runInit(['receipt', '--out', out]);
    assert.equal(first.code, 0, first.text);
    assert.equal(JSON.parse(await readFile(join(out, 'onboarding-receipt.json'), 'utf8')).initRuns[0].reached, 'probe-start');
    r = await runInit(['receipt', '--out', out]);
    assert.equal(r.code, 0, r.text); assert.match(r.text, /first decided row: not reached/); assert.match(r.text, /Clock from first-init-run/);
    if (!(await readdir(fileURLToPath(new URL('.', import.meta.url)))).includes('stack.mjs')) {
      r = await runInit(['--stack', 'supabase', '--base-url', sick.origin]);
      assert.equal(r.code, 2); assert.match(r.text, /--stack needs integrations\/init\/stack.mjs/);
    }
    // A stamps file that is not a stamp, or a review missing its answer, stops the receipt rather than giving a wrong clock.
    const good = await readFile(join(out, STAMPS_FILE), 'utf8');
    // ... and an end stamp whose exit is not one of init's four statuses.
    for (const bad of ['{"schema":"other"}', JSON.stringify({ schema: STAMP_SCHEMA, run: 'v', stage: 'review', at: new Date().toISOString(), runId: 'x', check: 'B-READS-A-RECORD', reviewerRole: 'r' }),
      JSON.stringify({ schema: STAMP_SCHEMA, run: 'e', stage: 'end', at: new Date().toISOString(), exit: 7 })]) {
      await writeFile(join(out, STAMPS_FILE), `${good}${bad}\n`, { mode: 0o600 });
      r = await runInit(['receipt', '--out', out]);
      assert.equal(r.code, 2); assert.match(r.text, /is not a stamp/);
    }
    await writeFile(join(out, STAMPS_FILE), good, { mode: 0o600 });
    // --help on a subcommand prints the commands; --json belongs to table only.
    r = await runInit(['receipt', '--help']); assert.equal(r.code, 0); assert.match(r.text, /init review {2}--out DIR/);
    r = await runInit(['receipt', '--out', out, '--json']); assert.equal(r.code, 2); assert.match(r.text, /unknown option --json/);
    // An env-file stop in an existing --out folder is stamped (exit 2, stop env-file).
    await chmod(env, 0o644);
    r = await runInit(['--yes', '--base-url', sick.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--no-run', '--out', out]);
    assert.equal(r.code, 2, r.text);
    const last = (await stampsIn(out)).at(-1);
    // An existing folder that is not an init or onboarding folder gets no stamps from a run that stops on its inputs.
    const plain = join(dir, 'plain folder');
    await mkdir(plain, { mode: 0o700 });
    await chmod(env, 0o644);
    r = await runInit(['--yes', '--base-url', sick.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--no-run', '--out', plain]);
    assert.equal(r.code, 2, r.text);
    assert.deepEqual(await readdir(plain), []);
    await chmod(env, 0o600);
    assert.deepEqual([last.stage, last.exit, last.stop], ['end', 2, 'env-file']);
    // A stamps file that cannot be appended (a symlink) is reported and never changes the exit status.
    const elsewhere = join(dir, 'elsewhere.jsonl');
    await writeFile(elsewhere, '', { mode: 0o600 });
    await rm(join(out, STAMPS_FILE));
    await symlink(elsewhere, join(out, STAMPS_FILE));
    r = await runInit(['--yes', '--base-url', sick.origin, '--env', env, '--id', 'notes', '--record-a', '/api/notes/note-a1', '--record-b', '/api/notes/note-b1', ...ROE, '--confirm-authorization', '--no-run', '--force', '--out', out]);
    assert.equal(r.code, 3, r.text); assert.match(r.text, /Note: timing stamps not written/);
    assert.equal(await readFile(elsewhere, 'utf8'), '', 'nothing written through the symlink');
  } finally { await sick.close(); await cleanup(); }
});

test('units: receipts and the timing table decide the onboarding done condition from stamps', () => {
  const at = m => new Date(Date.UTC(2026, 9, 27, 12, 0) + m * 60000).toISOString();
  const onboarding = ({ label, owned, firstRow, fails = [], reviews = [], start = true, runs = true }) => {
    const s = start ? [{ schema: STAMP_SCHEMA, run: `o-${label}`, stage: 'onboarding-start', at: at(0), label, owned, operatorRole: 'design partner engineer', head: 'a'.repeat(40) }] : [];
    if (!runs) return computeReceipt(s);
    s.push({ schema: STAMP_SCHEMA, run: 'r1', stage: 'start', at: at(1), ms: 0, head: 'a'.repeat(40) });
    if (firstRow !== null) s.push({ schema: STAMP_SCHEMA, run: 'r1', stage: 'run-saved', at: at(firstRow), runId: `run-${label}`, fail: fails.length, inconclusive: 1, notExercised: 0, failChecks: fails },
      { schema: STAMP_SCHEMA, run: 'r1', stage: 'first-decided-row', at: at(firstRow), runId: `run-${label}`, verdict: fails.length ? 'FAIL' : 'INCONCLUSIVE', check: fails[0] ?? 'B-READS-A-RECORD-BACKEND' });
    s.push({ schema: STAMP_SCHEMA, run: 'r1', stage: 'end', at: at((firstRow ?? 5) + 0.1), exit: fails.length ? 1 : 0 });
    for (const [check, holds] of reviews) s.push({ schema: STAMP_SCHEMA, run: 'v', stage: 'review', at: at(200), runId: `run-${label}`, check, holds, reviewerRole: 'reviewer' });
    return computeReceipt(s);
  };
  const five = [onboarding({ label: 'p1', owned: false, firstRow: 40 }), onboarding({ label: 'p2', owned: false, firstRow: 55, fails: ['X'], reviews: [['X', true]] }),
    onboarding({ label: 'o1', owned: true, firstRow: 20 }), onboarding({ label: 'o2', owned: true, firstRow: 30 }), onboarding({ label: 'o3', owned: true, firstRow: 85 })];
  assert.equal(five[1].clocks.firstHeldFail.minutes, 55);
  let t = timingTable(five);
  assert.equal(t.summary.medianMinutes, 40); assert.equal(t.summary.worstMinutes, 85);
  assert.equal(t.done.met, true, tableMarkdown(t));
  // The limits line is printed under every table and kept in its JSON.
  assert.match(tableMarkdown(t), /\nLimits: stamps are this machine's wall clock .*operator role says; init cannot check it\.$/);
  assert.deepEqual(t.limits, TABLE_LIMITS);
  // A false FAIL, an unreviewed FAIL, a worst case of 90 minutes, an onboarding that never reached a row, or a single
  // outside onboarding each leave the condition unmet.
  t = timingTable([...five.slice(0, 4), onboarding({ label: 'o3', owned: true, firstRow: 30, fails: ['Y'], reviews: [['Y', false]] })]); assert.equal(t.done.zeroFalseFails, false);
  t = timingTable([...five.slice(0, 4), onboarding({ label: 'o3', owned: true, firstRow: 30, fails: ['Y'] })]); assert.equal(t.done.zeroFalseFails, false);
  t = timingTable([...five.slice(0, 4), onboarding({ label: 'o3', owned: true, firstRow: 90 })]); assert.equal(t.done.worstUnder90, false);
  t = timingTable([...five.slice(0, 4), onboarding({ label: 'o3', owned: true, firstRow: null })]); assert.equal(t.summary.allReached, false); assert.equal(t.done.met, false);
  assert.match(tableMarkdown(t), /not reached/);
  t = timingTable([onboarding({ label: 'p1', owned: true, firstRow: 40 }), ...five.slice(1)]); assert.equal(t.done.twoNotOwned, false);
  assert.equal(timingTable(five.slice(0, 4)).done.atLeastFive, false);
  // A clock that started at the first init run (no init start) understates, so the condition is unmet.
  t = timingTable([...five.slice(0, 4), onboarding({ label: 'o3', owned: true, firstRow: 30, start: false })]);
  assert.equal(t.done.allFromOnboardingStart, false); assert.equal(t.done.met, false);
  // An onboarding with only its start stamp keeps its row, not reached.
  const abandoned = onboarding({ label: 'o4', owned: true, firstRow: null, runs: false });
  assert.equal(abandoned.initRuns.length, 0); assert.equal(abandoned.clocks.firstDecidedRow, null);
  t = timingTable([...five, abandoned]); assert.equal(t.summary.allReached, false); assert.equal(t.done.met, false);
  assert.match(tableMarkdown(t), /\| o4 \| yes \|.*not reached/);
  // An even count: the median is the mean of the middle two (30 and 40).
  assert.equal(timingTable(five.slice(0, 4)).summary.medianMinutes, 35);
  // The receipt's head comes from the stamps only.
  assert.equal(computeReceipt([{ schema: STAMP_SCHEMA, run: 'r', stage: 'start', at: at(0), ms: 0 }, { schema: STAMP_SCHEMA, run: 'r', stage: 'end', at: at(1), exit: 2 }]).productHead, null);
  // The same receipt five times is one onboarding, not five; so is a copied folder with no start stamp (named by its first run).
  const unstarted = onboarding({ label: 'u1', owned: true, firstRow: 20, start: false });
  assert.equal(unstarted.onboardingId, 'r1');
  assert.throws(() => timingTable([unstarted, structuredClone(unstarted)]), /same onboarding appears twice/);
  assert.throws(() => timingTable([five[0], five[0], five[0], five[0], five[0]]), /same onboarding appears twice/);
  // The latest review of a row counts.
  assert.equal(onboarding({ label: 'p9', owned: false, firstRow: 10, fails: ['Z'], reviews: [['Z', false], ['Z', true]] }).fails.falseFails.length, 0);
});

test('init --help lists every option, the exit statuses and the onboarding commands', async () => {
  const { code, text } = await runInit(['--help']);
  assert.equal(code, 0);
  for (const flag of ['--base-url', '--env', '--id', '--whoami', '--credential', '--record-a', '--record-b', '--client', '--hosts', '--hours', '--confirm-authorization', '--app-env',
    '--use-observer', '--openapi', '--session', '--out', '--force', '--no-run', '--yes', '--stack']) assert.match(text, new RegExp(`\\s${flag}\\b`), flag);
  assert.match(text, /Exit status: 0 set up/);
  for (const command of ['init start', 'init review', 'init receipt', 'init table']) assert.ok(text.includes(command), command);
});

test('units: init writes each stage as it happens, so a run killed mid-way keeps what it reached', async () => {
  const { dir, cleanup } = await workspace();
  try {
    const clock = initClock(() => new Date(), { head: null });
    clock.stamp('identities-read');
    clock.setOut(dir);
    clock.stamp('probe-start');
    // No flush: the process could have been killed here.
    const lines = await stampsIn(dir);
    assert.deepEqual(lines.map(l => l.stage), ['start', 'identities-read', 'probe-start']);
    const receipt = computeReceipt(lines);
    assert.deepEqual([receipt.initRuns[0].reached, receipt.initRuns[0].ended, receipt.initRuns[0].exit], ['probe-start', false, null]);
    await clock.flush(3);
    assert.equal((await stampsIn(dir)).length, 4, 'flush appends only the end line');
  } finally { await cleanup(); }
});

test('every documented onboarding example passes the label and role patterns', async () => {
  // A documented example init refuses (an apostrophe in a role, say) stops a newcomer at exit 2 on the first command.
  const docs = ['../../docs/QUICKSTART.md', 'README.md'];
  let examples = 0;
  for (const doc of docs) {
    const text = await readFile(fileURLToPath(new URL(doc, import.meta.url)), 'utf8');
    for (const [, value] of text.matchAll(/--(?:operator|reviewer)-role "([^"]*)"/g)) { examples++; assert.match(value, ROLE, `${doc}: role ${value}`); }
    for (const [, value] of text.matchAll(/--label ([^\s`]+)/g)) { examples++; assert.match(value, LABEL, `${doc}: label ${value}`); }
  }
  assert.ok(examples >= 3, `found ${examples} examples`);
});

test('the probe opens a fresh connection per request and asks the server to close it, so no reused socket can answer a later request', async t => {
  const sockets = new Set(), headers = [];
  const server = createServer({ keepAliveTimeout: 5000 }, (req, res) => { sockets.add(req.socket); headers.push(req.headers.connection); res.setHeader('content-type', 'application/json'); res.end('{}'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const prober = makeProber({ port: server.address().port });
  for (const path of ['/a', '/b', '/c']) assert.equal((await prober.get(path)).status, 200);
  assert.equal(sockets.size, 3);
  assert.deepEqual(headers, ['close', 'close', 'close']);
});
