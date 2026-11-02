import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { validateTargetFile } from '../../src/contracts.mjs';
import { digest } from '../../src/domain.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { buildMatrix, diffMatrices, GATED_KINDS, MATRIX_SCHEMA, sha256, verifyMatrixId } from './matrix.mjs';
import { proposeStatement } from './statement.mjs';
import { CATALOG_DUMP_SQL, COMMANDS, importRls, LAYER as RLS_LAYER } from './rls.mjs';
import { tokenize } from './sql-lexer.mjs';
import { importOpenApi, LAYER as OPENAPI_LAYER } from './openapi.mjs';
import { importOpenWebUi, LAYER as OPENWEBUI_LAYER } from './openwebui.mjs';
import { BINDING_SCHEMA, DRAFT_SCHEMA, checkDraftChecks, checkIdFor, confirmDraft, draftChecks, explainRun, verifyDraftId, verifyRecord } from './draft.mjs';
import { main } from './cli.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const fixture = name => readFile(join(here, 'fixtures', name));
const migrations = async () => {
  const dir = join(here, 'fixtures', 'supabase-migrations');
  return Promise.all((await readdir(dir)).sort().map(async id => ({ id, content: await readFile(join(dir, id)), kind: 'sql' })));
};
const cell = (m, role, resource, action) => m.cells.find(c => c.role === role && c.resource === resource && c.action === action);
const rls = (sql, options = {}) => importRls([{ id: 'm.sql', content: sql }], { application: 'app', roles: ['anon', 'authenticated'], ...options });
const scratch = async t => { const dir = await mkdtemp(join(tmpdir(), 'scopehaven policy import ')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };
// A matrix as an earlier importer wrote it (scopehaven-policy-matrix/1, no gap identities), resealed.
const reseal = body => { const { matrixId: _id, ...rest } = body; return { ...rest, matrixId: sha256(canonical(rest)) }; };
const asSchema1 = m => reseal({ ...m, schema: 'scopehaven-policy-matrix/1', gaps: m.gaps.map(({ id: _id, ...g }) => g), cells: m.cells.map(({ unknownReasons: _r, ...c }) => c) });

// ---- Postgres RLS -------------------------------------------------------------

test('RLS enabled with no applicable permissive policy is a cited default deny; RLS off is undeclared, never deny', async () => {
  const m = importRls(await migrations(), { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  const anonProfiles = cell(m, 'anon', 'public.profiles', 'SELECT');
  assert.equal(anonProfiles.decision, 'deny');
  assert.match(anonProfiles.basis, /rls-default-deny/);
  assert.equal(anonProfiles.citations[0].source, '20260101000000_init.sql');
  for (const action of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
    const audit = cell(m, 'authenticated', 'public.audit_log', action);
    assert.equal(audit.decision, 'undeclared');
    assert.equal(audit.basis, 'rls-not-enabled');
  }
  assert.equal(m.complete, true);
  assert.ok(m.notEvaluated.some(n => /GRANT\/REVOKE/.test(n)));
});

test('USING (true) is allow; an owner predicate is conditional with the normalized expression', async () => {
  const m = importRls(await migrations(), { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  assert.equal(cell(m, 'anon', 'public.announcements', 'SELECT').decision, 'allow');
  assert.equal(cell(m, 'anon', 'public.announcements', 'INSERT').decision, 'deny');
  const own = cell(m, 'authenticated', 'public.profiles', 'SELECT');
  assert.equal(own.decision, 'conditional');
  assert.deepEqual(own.conditions, ['permissive using: (select auth.uid()) = owner_id [Profiles are readable by their owner]']);
  assert.deepEqual(cell(m, 'authenticated', 'public.profiles', 'INSERT').conditions, ['permissive check: (select auth.uid()) = owner_id [Owners insert their profile]']);
  assert.equal(cell(m, 'authenticated', 'public.profiles', 'UPDATE').decision, 'deny');
});

test('formatting and keyword case do not change decisions or conditions (citations keep their own lines)', () => {
  const a = rls('create table t (id int); alter table t enable row level security; create policy p on t for select to authenticated using (owner = auth.uid());');
  const b = rls('CREATE TABLE T (ID INT);\nALTER TABLE public.T ENABLE ROW LEVEL SECURITY;\n-- note\nCREATE POLICY p ON T\n  FOR SELECT TO AUTHENTICATED\n  USING ( ( OWNER = AUTH.UID ( ) ) );');
  const reading = m => m.cells.map(({ role, resource, action, decision, basis, conditions }) => ({ role, resource, action, decision, basis, conditions }));
  assert.deepEqual(reading(a), reading(b));
  assert.notDeepEqual(a.cells.map(c => c.citations), b.cells.map(c => c.citations));
});

test('restrictive policies narrow; a restrictive or every permissive false is deny', async () => {
  const m = importRls(await migrations(), { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  const tickets = cell(m, 'authenticated', 'public.tickets', 'SELECT');
  assert.equal(tickets.decision, 'conditional');
  assert.ok(tickets.conditions.some(c => c.startsWith('restrictive using: (auth.jwt() ->> \'aal\') = \'aal2\'')));
  assert.equal(rls('alter table t enable row level security; create policy a on t using (true); create policy r on t as restrictive using (false);').cells.find(c => c.action === 'SELECT').decision, 'deny');
  const allFalse = rls('alter table t enable row level security; create policy a on t for select using (false);');
  assert.equal(cell(allFalse, 'anon', 'public.t', 'SELECT').decision, 'deny');
  assert.match(cell(allFalse, 'anon', 'public.t', 'SELECT').basis, /every applicable permissive policy is false/);
});

test('FOR ALL feeds INSERT from WITH CHECK or USING and UPDATE from both', () => {
  const m = rls('alter table t enable row level security; create policy a on t for all to authenticated using (x = 1) with check (y = 2);');
  assert.deepEqual(cell(m, 'authenticated', 'public.t', 'INSERT').conditions, ['permissive check: y = 2 [a]']);
  assert.deepEqual(cell(m, 'authenticated', 'public.t', 'UPDATE').conditions, ['permissive using: x = 1 [a]', 'permissive check: y = 2 [a]']);
  assert.deepEqual(cell(m, 'authenticated', 'public.t', 'DELETE').conditions, ['permissive using: x = 1 [a]']);
  const usingOnly = rls('alter table t enable row level security; create policy a on t for all to authenticated using (x = 1);');
  assert.deepEqual(cell(usingOnly, 'authenticated', 'public.t', 'INSERT').conditions, ['permissive check: x = 1 [a]']);
});

test('policies apply only to their roles; PUBLIC applies to every role', async () => {
  const m = importRls(await migrations(), { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  assert.equal(cell(m, 'anon', 'public.profiles', 'INSERT').decision, 'deny');
  const pub = rls('alter table t enable row level security; create policy a on t for select to public using (true);');
  assert.equal(cell(pub, 'anon', 'public.t', 'SELECT').decision, 'allow');
  assert.equal(cell(pub, 'authenticated', 'public.t', 'SELECT').decision, 'allow');
});

test('history is applied in order: drop, alter, rename, disable, drop table and table rename', async () => {
  const m = importRls(await migrations(), { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  assert.equal(cell(m, 'anon', 'public.tickets', 'SELECT').decision, 'deny', 'the later DROP POLICY removed the temporary anon read');
  const history = rls(`create table t (id int); alter table t enable row level security;
    create policy a on t for select to authenticated using (true);
    alter policy a on t using (owner = auth.uid());
    alter policy a on t rename to b;
    alter table t rename to u;`);
  assert.equal(cell(history, 'authenticated', 'public.t', 'SELECT'), undefined);
  assert.deepEqual(cell(history, 'authenticated', 'public.u', 'SELECT').conditions, ['permissive using: owner = auth.uid() [b]']);
  assert.equal(cell(rls('alter table t enable row level security; create policy a on t using (true); alter table t disable row level security;'), 'anon', 'public.t', 'SELECT').decision, 'undeclared');
  assert.equal(rls('create table t (id int); alter table t enable row level security; drop table t; create table v (id int);').resources.includes('public.t'), false);
});

test('an unreadable policy makes only its table unknown, keeping the computed decision', () => {
  const m = rls(`alter table good enable row level security; create policy g on good for select using (true);
    alter table bad enable row level security; create policy b on bad for select to authenticated using (x = 1) garbage;`);
  assert.equal(cell(m, 'anon', 'public.good', 'SELECT').decision, 'allow');
  const bad = cell(m, 'anon', 'public.bad', 'SELECT');
  assert.equal(bad.decision, 'unknown');
  assert.equal(bad.computedDecision, 'deny');
  assert.equal(m.complete, false);
  assert.equal(m.gaps[0].scope, 'public.bad');
});

test('policy text inside procedural code, an unterminated literal or a current_user role is never guessed', () => {
  const dollar = rls(`alter table t enable row level security; do $$ begin execute 'create policy x on t using (true)'; end $$;`);
  assert.ok(dollar.cells.every(c => c.decision === 'unknown'));
  assert.match(dollar.gaps[0].reason, /procedural code/);
  assert.ok(rls("alter table t enable row level security; create policy a on t using ('oops);").cells.every(c => c.decision === 'unknown'));
  const current = rls('alter table t enable row level security; create policy a on t for select to current_user using (true);');
  assert.equal(cell(current, 'anon', 'public.t', 'SELECT').decision, 'unknown');
});

test('statements PostgreSQL would reject become gaps, not policies', () => {
  for (const sql of ['create policy a on t for insert using (true);', 'create policy a on t for select with check (true);', 'drop policy missing on t;',
    'create policy a on t using (true); create policy a on t using (true);', 'alter policy missing on t using (true);']) {
    const m = rls(`alter table t enable row level security; ${sql}`);
    assert.equal(m.complete, false, sql);
    assert.ok(m.cells.every(c => c.decision === 'unknown'), sql);
  }
  assert.equal(rls('alter table t enable row level security; drop policy if exists missing on t;').complete, true);
});

test('search_path decides unqualified names; an empty or unreadable one is a gap', () => {
  const app = rls('set search_path to app; alter table t enable row level security; create policy a on t for select using (true);');
  assert.equal(cell(app, 'anon', 'app.t', 'SELECT').decision, 'allow');
  const empty = rls("select pg_catalog.set_config('search_path', '', false); alter table t enable row level security;");
  assert.equal(empty.complete, false);
  const qualified = rls("select pg_catalog.set_config('search_path', '', false); alter table public.t enable row level security; create policy a on public.t for select using (true);");
  assert.equal(qualified.complete, true);
  assert.equal(cell(qualified, 'anon', 'public.t', 'SELECT').decision, 'allow');
});

test('a catalog dump reads the same declarations as the migration history', async () => {
  const fromSql = importRls(await migrations(), { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  const dump = {
    tables: [['profiles', true], ['announcements', true], ['audit_log', false], ['tickets', true]].map(([tablename, rowsecurity]) => ({ schemaname: 'public', tablename, rowsecurity, forcerowsecurity: false })),
    policies: [
      { schemaname: 'public', tablename: 'profiles', policyname: 'Profiles are readable by their owner', permissive: 'PERMISSIVE', roles: '{authenticated}', cmd: 'SELECT', qual: '(( SELECT auth.uid() AS uid) = owner_id)', with_check: null },
      { schemaname: 'public', tablename: 'profiles', policyname: 'Owners insert their profile', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'INSERT', qual: null, with_check: '(( SELECT auth.uid() AS uid) = owner_id)' },
      { schemaname: 'public', tablename: 'announcements', policyname: 'Announcements are public', permissive: 'PERMISSIVE', roles: '{public}', cmd: 'SELECT', qual: 'true', with_check: null },
      { schemaname: 'public', tablename: 'tickets', policyname: 'Org members manage tickets', permissive: 'PERMISSIVE', roles: '{authenticated}', cmd: 'ALL', qual: '(org_id IN ( SELECT memberships.org_id FROM memberships WHERE (memberships.user_id = auth.uid())))', with_check: null },
      { schemaname: 'public', tablename: 'tickets', policyname: 'Require MFA', permissive: 'RESTRICTIVE', roles: '{authenticated}', cmd: 'ALL', qual: "((auth.jwt() ->> 'aal'::text) = 'aal2'::text)", with_check: null },
    ],
  };
  const fromCatalog = importRls([{ id: 'catalog.json', content: JSON.stringify(dump), kind: 'catalog-json' }], { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  const decisions = m => m.cells.map(c => `${c.role} ${c.resource} ${c.action} ${c.decision}`);
  assert.deepEqual(decisions(fromCatalog), decisions(fromSql));
});

test('operator-declared bypass roles are allow and cited to the operator', () => {
  const m = rls('alter table t enable row level security;', { bypassRoles: ['service_role'] });
  const bypass = cell(m, 'service_role', 'public.t', 'DELETE');
  assert.equal(bypass.decision, 'allow');
  assert.equal(bypass.citations[0].source, 'operator-options');
  assert.equal(cell(m, 'authenticated', 'public.t', 'DELETE').decision, 'deny');
});

// ---- OpenAPI ------------------------------------------------------------------

test('OpenAPI: empty security is public, a missing one is undeclared, unmet requirements are deny', async () => {
  const roleMap = { member: { session: [] }, reader: { oauth: ['tickets:read'] }, admin: { oauth: ['admin', 'tickets:read'] } };
  const m = importOpenApi({ id: 'openapi.json', content: await fixture('openapi.json') }, { application: 'helpdesk', roleMap });
  assert.equal(cell(m, 'anonymous', '/health', 'GET').decision, 'allow');
  assert.equal(cell(m, 'anonymous', '/me', 'GET').decision, 'deny', 'the document-level requirement applies');
  assert.equal(cell(m, 'member', '/me', 'GET').decision, 'allow');
  assert.equal(cell(m, 'reader', '/tickets', 'GET').decision, 'allow', 'requirements are alternatives');
  assert.equal(cell(m, 'reader', '/tickets', 'POST').decision, 'deny');
  assert.equal(cell(m, 'reader', '/admin/users', 'GET').decision, 'deny', 'scopes in one requirement are all needed');
  assert.equal(cell(m, 'admin', '/admin/users', 'GET').decision, 'allow');
  assert.equal(cell(m, 'anonymous', '/search', 'GET').basis, 'optional-authentication');
  const bare = importOpenApi({ id: 'x.json', content: JSON.stringify({ openapi: '3.0.3', paths: { '/a': { get: {} } } }) }, { application: 'x' });
  assert.equal(cell(bare, 'anonymous', '/a', 'GET').decision, 'undeclared');
});

test('OpenAPI: undefined schemes and $ref path items are unknown; YAML and non-3.x are refused', () => {
  const doc = { openapi: '3.0.0', components: { securitySchemes: {} }, paths: { '/a': { get: { security: [{ ghost: [] }] } }, '/b': { $ref: '#/components/pathItems/b' } } };
  const m = importOpenApi({ id: 'x.json', content: JSON.stringify(doc) }, { application: 'x' });
  assert.equal(cell(m, 'anonymous', '/a', 'GET').decision, 'unknown');
  assert.equal(cell(m, 'anonymous', '/b', '*').decision, 'unknown');
  assert.equal(m.complete, false);
  assert.throws(() => importOpenApi({ id: 'x.yaml', content: 'openapi: 3.0.0' }, { application: 'x' }), /not JSON/);
  assert.throws(() => importOpenApi({ id: 'x.json', content: '{"swagger":"2.0"}' }, { application: 'x' }), /not an OpenAPI 3/);
});

// ---- Open WebUI ---------------------------------------------------------------

test('Open WebUI: owner, group, user:* and per-user grants follow 0.11.4; write does not imply read', async () => {
  const m = importOpenWebUi({ id: 'export.json', content: await fixture('openwebui-export.json') }, { application: 'owui' });
  assert.equal(cell(m, 'alice', 'knowledge:kb-private', 'write').basis, 'owner');
  assert.equal(cell(m, 'bob', 'knowledge:kb-private', 'read').decision, 'deny');
  assert.equal(cell(m, 'bob', 'knowledge:kb-support', 'read').decision, 'allow');
  assert.equal(cell(m, 'bob', 'knowledge:kb-support', 'write').decision, 'deny');
  assert.equal(cell(m, 'carol', 'knowledge:kb-support', 'read').decision, 'deny');
  assert.equal(cell(m, 'carol', 'knowledge:kb-everyone', 'read').decision, 'allow');
  assert.equal(cell(m, 'carol', 'knowledge:kb-everyone', 'write').decision, 'allow');
  assert.equal(cell(m, 'bob', 'knowledge:kb-everyone', 'write').decision, 'deny');
});

test('Open WebUI: admin bypass, anonymous, pending and legacy access_control', async () => {
  const data = JSON.parse(await fixture('openwebui-export.json'));
  const m = importOpenWebUi({ id: 'export.json', content: JSON.stringify(data) }, { application: 'owui' });
  assert.equal(cell(m, 'admin', 'knowledge:kb-private', 'read').decision, 'conditional');
  assert.equal(cell(m, 'anonymous', 'knowledge:kb-everyone', 'read').decision, 'deny', 'user:* is signed-in users, not anonymous');
  assert.equal(cell(m, 'pending', 'knowledge:kb-everyone', 'read').decision, 'unknown');
  assert.equal(cell(m, 'carol', 'knowledge:kb-legacy-public', 'read').decision, 'allow', 'legacy null is public read');
  assert.equal(cell(m, 'carol', 'file:f-legacy', 'read').decision, 'deny', 'legacy null is private for files');
  const bypass = importOpenWebUi({ id: 'export.json', content: JSON.stringify({ ...data, bypassAdminAccessControl: true }) }, { application: 'owui' });
  assert.equal(cell(bypass, 'admin', 'knowledge:kb-private', 'read').decision, 'allow');
  const anyone = importOpenWebUi({ id: 'e.json', content: JSON.stringify({ ...data, grants: [...data.grants, { resource_type: 'knowledge', resource_id: 'kb-private', principal_type: 'anyone', principal_id: '*', permission: 'read' }] }) }, { application: 'owui' });
  assert.equal(cell(anyone, 'anonymous', 'knowledge:kb-private', 'read').decision, 'conditional');
});

test('Open WebUI: an unreadable grant row makes every cell unknown', async () => {
  const data = JSON.parse(await fixture('openwebui-export.json'));
  data.grants.push({ resource_type: 'knowledge', principal_type: 'user', principal_id: 'u-bob', permission: 'read' });
  const m = importOpenWebUi({ id: 'e.json', content: JSON.stringify(data) }, { application: 'owui' });
  assert.ok(m.cells.every(c => c.decision === 'unknown'));
  assert.equal(cell(m, 'alice', 'knowledge:kb-private', 'read').computedDecision, 'allow');
});

// ---- Matrix and diff -------------------------------------------------------------

test('matrixId detects edits; cells need citations and unique keys', () => {
  const m = rls('alter table t enable row level security; create policy a on t for select using (true);');
  assert.equal(verifyMatrixId(m), true);
  const edited = structuredClone(m); edited.cells[0].decision = 'allow';
  assert.equal(verifyMatrixId(edited), false);
  assert.throws(() => buildMatrix({ application: 'a', layer: 'l', sources: [], cells: [{ role: 'r', resource: 'x', action: 'GET', decision: 'deny', basis: 'b', citations: [] }] }), /citation/);
  const dup = { role: 'r', resource: 'x', action: 'GET', decision: 'undeclared', basis: 'b', citations: [] };
  assert.throws(() => buildMatrix({ application: 'a', layer: 'l', sources: [], cells: [dup, dup] }), /Duplicate/);
});

test('release diff names widened, narrowed, condition, unknown, added and removed cells, and refuses mismatched matrices', async () => {
  const files = await migrations();
  const before = importRls(files.slice(0, 2), { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  const after = importRls(files, { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  const d = diffMatrices(before, after);
  assert.equal(d.comparable, true);
  assert.ok(d.changes.some(c => c.kind === 'narrowed' && c.role === 'anon' && c.resource === 'public.tickets' && c.action === 'SELECT'));
  assert.ok(d.changes.some(c => c.kind === 'conditions-changed' && c.role === 'authenticated' && c.resource === 'public.tickets'));
  const back = diffMatrices(after, before);
  assert.equal(back.changes[0].kind, 'widened');
  const added = diffMatrices(rls('alter table t enable row level security;'), rls('alter table t enable row level security; alter table u enable row level security;'));
  assert.ok(added.changes.some(c => c.kind === 'added') && !added.changes.some(c => c.kind === 'removed'));
  assert.ok(diffMatrices(rls('alter table t enable row level security; alter table u enable row level security;'), rls('alter table t enable row level security;')).changes.some(c => c.kind === 'removed'));
  const unknown = diffMatrices(rls('alter table t enable row level security;'), rls('alter table t enable row level security; create policy a on t using (x) junk;'));
  assert.ok(unknown.changes.every(c => c.kind === 'became-unknown'));
  assert.equal(diffMatrices(before, importRls(files, { application: 'other', roles: ['anon', 'authenticated'] })).reason, 'application-differs');
  assert.equal(diffMatrices(before, importOpenApi({ id: 'o.json', content: await fixture('openapi.json') }, { application: 'helpdesk' })).reason, 'layer-differs');
  const tampered = structuredClone(after); tampered.cells[0].decision = 'allow';
  assert.equal(diffMatrices(before, tampered).reason, 'after-matrix-invalid');
});

// ---- Draft, confirm and explain ---------------------------------------------------

const token = () => randomBytes(24).toString('base64url');
const ENV = { SCOPEHAVEN_TARGET_PI_ALICE: token(), SCOPEHAVEN_TARGET_PI_BOB: token(), SCOPEHAVEN_TARGET_PI_CAROL: token() };
const PEOPLE = { [ENV.SCOPEHAVEN_TARGET_PI_ALICE]: 'u-alice', [ENV.SCOPEHAVEN_TARGET_PI_BOB]: 'u-bob', [ENV.SCOPEHAVEN_TARGET_PI_CAROL]: 'u-carol' };
const whoami = (id, actorId, email) => ({ id, title: `${actorId} session`, category: 'Identity', severity: 'control', actorId, method: 'GET', path: '/api/v1/auths/', evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: email }] });
const actor = (name, env) => ({ principalId: name, credentialEnv: env, identityValue: `${name}@example.test` });
const baseProfile = () => ({ schemaVersion: 1, targets: [{ id: 'owui-practice', name: 'Open WebUI practice (synthetic)', applicationId: 'owui', origin: 'http://127.0.0.1:4420',
  buildLabel: 'open-webui 0.11.4 practice', contextId: 'synthetic-seed-1',
  actors: { alice: actor('alice', 'SCOPEHAVEN_TARGET_PI_ALICE'), bob: actor('bob', 'SCOPEHAVEN_TARGET_PI_BOB'), carol: actor('carol', 'SCOPEHAVEN_TARGET_PI_CAROL'), anonymous: { principalId: 'anonymous' } },
  requiredControlIds: ['ALICE-WHOAMI', 'BOB-WHOAMI', 'CAROL-WHOAMI'],
  checks: [whoami('ALICE-WHOAMI', 'alice', 'alice@example.test'), whoami('BOB-WHOAMI', 'bob', 'bob@example.test'), whoami('CAROL-WHOAMI', 'carol', 'carol@example.test')] }] });
const binding = () => ({ schema: BINDING_SCHEMA, targetId: 'owui-practice', actors: { alice: 'alice', bob: 'bob', carol: 'carol', anonymous: 'anonymous' },
  resources: Object.fromEntries(['kb-private', 'kb-support', 'kb-everyone', 'kb-legacy-public'].map(id => [`knowledge:${id}`, {
    read: { method: 'GET', path: `/api/v1/knowledge/${id}` }, write: { method: 'POST', path: `/api/v1/knowledge/${id}/update` } }])) });
const owuiMatrix = async () => importOpenWebUi({ id: 'export.json', content: await fixture('openwebui-export.json') }, { application: 'owui' });
// Confirmation re-drafts from the matrix and binding, so tests pass both.
const confirmWith = async (draft, profile, options) => confirmDraft(draft, profile, { matrix: await owuiMatrix(), binding: binding(), ...options });

// Captured from the original draft.mjs, before the bound-write guard. These pins
// cover both allow and deny; the legacy write drafts were also confirmed there.
const boundActionCases = [
  { layer: RLS_LAYER, read: 'SELECT', readDraftId: 'b2b07c00b9d0f8f972ae025955606a2a1a7caddb5896ef34c24d95a4db1de56d',
    readCheckIds: ['PI-8A45B118AD02', 'PI-928E5F6D519F'], writes: {
      INSERT: '90feece29e39b3430a0f7465bbb4e9c0253ce998b9535216890b4dc068ea96c8',
      UPDATE: '2cf3654a9c6d6083b8ddab1fff9d6c75098e28d4cb1cda8403779f9b2987c7b3',
      DELETE: 'd6b02e9a57e953db7cdf601f8c79f7ebedf7eac54e651a86ba7a1793974c83cc' } },
  { layer: OPENAPI_LAYER, read: 'GET', readDraftId: '92d90d6bcda68c33c5e385b5ce517730f4f1d6c5a046754145be412a759fe3ab',
    readCheckIds: ['PI-3C527EBEF9EB', 'PI-98211D763E58'], writes: {
      POST: 'bc7a0aaf25dac1d7e93b77e7cf3f63eacea9414434528267684b5275cb2888ab',
      PUT: 'ea48804fa7a868609c1247fc8cbea83f500d8a00e2aa7a3bdcdda369f32dcb03',
      PATCH: '65674065547aa36e1858122fa44ef3bc046b447eb6f4da7e593c96747bc30003',
      DELETE: '25254d298e0c844159bceb017ca706d22c65ce02e60f2e6c9ff31fcb029274f8' } },
  { layer: OPENWEBUI_LAYER, read: 'read', readDraftId: 'd1444a5b2faf90f4e88db3b3b1f928128c37dad70a59b6633a55e095ed62fdcd',
    readCheckIds: ['PI-B8436B1A47B3', 'PI-D35BB2C978C0'], writes: {
      write: 'dc78b89542c5803d12d554b99045e8fb2be063e0f7692ac8132751d52a66cde6' } },
];
const boundActionMatrix = (layer, action) => buildMatrix({ application: 'owui', layer, sources: [],
  cells: [['alice', 'allow'], ['bob', 'deny']].map(([role, decision]) => ({ role, resource: 'synthetic-resource', action, decision,
    basis: 'synthetic declaration', citations: [{ source: 'synthetic-declaration', lineStart: 1, lineEnd: 1 }] })) });
const boundActionBinding = (action, method = 'GET') => ({ schema: BINDING_SCHEMA, targetId: 'owui-practice', actors: { alice: 'alice', bob: 'bob' },
  resources: { 'synthetic-resource': { [action]: { method, path: '/synthetic-resource' } } } });
// Compact representation of the captured legacy fixtures, sealed with their
// literal original digests. It does not use the current drafter to create them.
const legacyBoundDraft = (matrix, binding, draftId) => ({ schema: DRAFT_SCHEMA, confirmed: false, application: matrix.application,
  layer: matrix.layer, matrixId: matrix.matrixId, targetId: binding.targetId,
  checks: matrix.cells.map(c => ({ id: checkIdFor(c), title: `${c.role} ${c.decision === 'allow' ? 'may' : 'may not'} ${c.action} ${c.resource} (declared)`,
    category: 'Declared policy', severity: c.decision === 'allow' ? 'control' : 'high', actorId: binding.actors[c.role], method: 'GET',
    path: '/synthetic-resource', evidenceRequirement: 'response',
    assertions: c.decision === 'allow' ? [{ kind: 'status.equals', expected: 200 }] : [{ kind: 'status.in', expected: [401, 403, 404] }] })),
  provenance: matrix.cells.map(c => ({ checkId: checkIdFor(c), role: c.role, resource: c.resource, action: c.action, decision: c.decision,
    requestKind: 'bound', basis: c.basis, citations: c.citations })), notDrafted: [], warnings: [], draftId });

for (const { layer, read, readDraftId, readCheckIds, writes } of boundActionCases) {
  test(`bound-write: ${layer} rejects every allow/deny write action bound to GET`, () => {
    for (const action of Object.keys(writes)) {
      const matrix = boundActionMatrix(layer, action), draft = draftChecks(matrix, boundActionBinding(action));
      assert.deepEqual(draft.checks, [], action);
      assert.deepEqual(draft.provenance, [], action);
      assert.deepEqual(draft.notDrafted, matrix.cells.map(({ role, resource, action, decision }) =>
        ({ role, resource, action, decision, reason: 'write action bound to GET' })), action);
      assert.equal(verifyDraftId(draft), true);
    }
  });

  test(`bound-write: ${layer} preserves the original read draft and check IDs`, () => {
    // The original drafts came from scopehaven-policy-matrix/1 matrices, which every reader still takes.
    const matrix = asSchema1(boundActionMatrix(layer, read)), bound = boundActionBinding(read), draft = draftChecks(matrix, bound);
    assert.equal(draft.draftId, readDraftId);
    assert.deepEqual(draft.checks.map(c => c.id), readCheckIds);
    assert.deepEqual(draft, legacyBoundDraft(matrix, bound, readDraftId));
    assert.doesNotThrow(() => confirmDraft(draft, baseProfile(), { confirmedBy: 'Synthetic Reviewer', matrix, binding: bound }));
    // The same declarations as a /2 matrix draft the same checks; only the matrixId, and so the draftId, differ.
    const current = boundActionMatrix(layer, read), now = draftChecks(current, bound);
    assert.equal(current.schema, MATRIX_SCHEMA);
    assert.deepEqual(now.checks, draft.checks);
    assert.deepEqual(now.provenance, draft.provenance);
    assert.notEqual(now.matrixId, matrix.matrixId);
  });

  test(`bound-write: ${layer} preserves non-GET rejection reasons`, () => {
    for (const action of [read, ...Object.keys(writes)]) for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE']) {
      const matrix = boundActionMatrix(layer, action), draft = draftChecks(matrix, boundActionBinding(action, method));
      assert.deepEqual(draft.checks, [], `${action} ${method}`);
      assert.deepEqual(draft.provenance, [], `${action} ${method}`);
      assert.deepEqual(draft.notDrafted, matrix.cells.map(({ role, resource, action, decision }) => ({ role, resource, action, decision,
        reason: `bound to ${method}; only GET checks are drafted because other methods can change data` })), `${action} ${method}`);
    }
  });

  test(`bound-write: ${layer} cannot confirm any original sealed write-to-GET draft`, () => {
    for (const [action, draftId] of Object.entries(writes)) {
      const matrix = asSchema1(boundActionMatrix(layer, action)), bound = boundActionBinding(action), legacy = legacyBoundDraft(matrix, bound, draftId);
      assert.equal(verifyDraftId(legacy), true, 'this is the sealed original fixture');
      assert.doesNotThrow(() => checkDraftChecks(legacy), 'legacy checks passed the existing per-check safety rules');
      const profile = baseProfile(), before = structuredClone(profile);
      assert.throws(() => confirmDraft(legacy, profile, { confirmedBy: 'Synthetic Reviewer', matrix, binding: bound }),
        /not what this matrix and binding produce/, action);
      assert.deepEqual(profile, before, 'rejected confirmation leaves the profile untouched');
    }
  });
}

test('bound-write: action names in another layer retain their existing drafting behavior', () => {
  for (const action of ['INSERT', 'UPDATE', 'DELETE', 'POST', 'PUT', 'PATCH', 'write']) {
    const draft = draftChecks(boundActionMatrix('synthetic-other-layer', action), boundActionBinding(action));
    assert.equal(draft.checks.length, 2);
    assert.equal(draft.provenance.length, 2);
    assert.deepEqual(draft.notDrafted, []);
  }
});

test('bound-write: the existing Open WebUI read/POST-binding draft keeps its original ID', async () => {
  // Drafted, as originally, from the /1 matrix of this export (it has no gaps).
  assert.equal(draftChecks(asSchema1(await owuiMatrix()), binding()).draftId, '7124b11adbd097c5d568d482ecb96bd722da5d17e5a74fc262b3f70fee2cc085');
  assert.deepEqual(draftChecks(await owuiMatrix(), binding()).checks, draftChecks(asSchema1(await owuiMatrix()), binding()).checks);
});

// A stand-in for the app: enforces the 0.11.4 rules, or leaks / over-blocks one cell.
function fakeApp(mode = 'enforcing') {
  const readable = { 'kb-private': ['u-alice'], 'kb-support': ['u-alice', 'u-bob'], 'kb-everyone': ['u-alice', 'u-bob', 'u-carol'], 'kb-legacy-public': ['u-alice', 'u-bob', 'u-carol'] };
  return async (_origin, check, { credential }) => {
    const user = PEOPLE[credential];
    const reply = (status, json) => ({ status, complete: true, jsonParsed: true, json, bytes: 2 });
    if (!user) return reply(401, { detail: 'Not authenticated' });
    if (check.path === '/api/v1/auths/') return reply(200, { email: `${user.slice(2)}@example.test` });
    const id = check.path.split('/').at(-1);
    let allowed = readable[id]?.includes(user) ?? false;
    if (mode === 'leaky' && user === 'u-carol' && id === 'kb-private') allowed = true;
    if (mode === 'overblocking' && user === 'u-bob' && id === 'kb-support') allowed = false;
    return allowed ? reply(200, { id }) : reply(403, { detail: 'Access prohibited' });
  };
}

test('drafts cover only declared allow/deny GET cells, and list the rest with a reason', async () => {
  const draft = draftChecks(await owuiMatrix(), binding());
  assert.equal(draft.confirmed, false);
  assert.ok(draft.checks.every(c => c.method === 'GET'));
  const carolPrivate = draft.checks.find(c => c.id === checkIdFor({ role: 'carol', resource: 'knowledge:kb-private', action: 'read', decision: 'deny' }));
  assert.deepEqual(carolPrivate.assertions, [{ kind: 'status.in', expected: [401, 403, 404] }]);
  assert.equal(carolPrivate.severity, 'high');
  const bobSupport = draft.checks.find(c => c.id === checkIdFor({ role: 'bob', resource: 'knowledge:kb-support', action: 'read', decision: 'allow' }));
  assert.deepEqual(bobSupport.assertions, [{ kind: 'status.equals', expected: 200 }]);
  assert.equal(bobSupport.severity, 'control');
  assert.ok(draft.notDrafted.some(n => n.action === 'write' && /only GET/.test(n.reason)));
  assert.ok(draft.notDrafted.some(n => n.role === 'admin' && n.decision === 'conditional' && /paired checks/.test(n.reason)));
  assert.ok(draft.notDrafted.some(n => n.role === 'pending' && n.decision === 'unknown'));
  assert.notEqual(checkIdFor({ role: 'r', resource: 'x', action: 'read', decision: 'allow' }), checkIdFor({ role: 'r', resource: 'x', action: 'read', decision: 'deny' }));
  const tampered = structuredClone(await owuiMatrix()); tampered.cells[0].decision = 'deny';
  assert.throws(() => draftChecks(tampered, binding()), /edited after import/);
});

test('confirmation needs a named person and an unedited draft, and yields a profile the product validator accepts', async () => {
  const draft = draftChecks(await owuiMatrix(), binding());
  await assert.rejects(confirmWith(draft, baseProfile(), {}), /Name the person/);
  await assert.rejects(confirmWith({ ...draft, checks: draft.checks.slice(1) }, baseProfile(), { confirmedBy: 'Yusef' }), /edited after drafting/);
  assert.throws(() => confirmDraft(draft, baseProfile(), { confirmedBy: 'Yusef' }), /needs the matrix and binding/);
  const { profile, record } = await confirmWith(draft, baseProfile(), { confirmedBy: 'Synthetic Reviewer', now: new Date('2026-10-06T07:00:00Z') });
  validateTargetFile(profile);
  const controls = draft.checks.filter(c => c.severity === 'control').map(c => c.id);
  assert.ok(controls.length > 0 && controls.every(id => profile.targets[0].requiredControlIds.includes(id)));
  assert.equal(record.confirmedBy, 'Synthetic Reviewer');
  assert.deepEqual(record.checks.map(c => c.id), draft.checks.map(c => c.id));
  await assert.rejects(confirmWith(draft, profile, { confirmedBy: 'x' }), /already has a check/);
});

test('end to end: confirmed checks run through the product connector and explain names each mismatch', async () => {
  const draft = draftChecks(await owuiMatrix(), binding());
  const { profile, record } = await confirmWith(draft, baseProfile(), { confirmedBy: 'Synthetic Reviewer' });
  const target = profile.targets[0];
  const enforcing = explainRun(await runHttpAssessment(target, { env: ENV, transport: fakeApp('enforcing') }), record, { profile });
  assert.deepEqual(enforcing.mismatches, []);
  assert.ok(enforcing.counts['consistent: refused as declared'] > 0 && enforcing.counts['consistent: allowed as declared'] > 0);
  const leaky = explainRun(await runHttpAssessment(target, { env: ENV, transport: fakeApp('leaky') }), record, { profile });
  assert.deepEqual(leaky.mismatches.map(r => [r.role, r.resource, r.reading]), [['carol', 'knowledge:kb-private', 'mismatch: declared deny, not refused']]);
  assert.equal(leaky.mismatches[0].citations[0].source, 'export.json');
  const over = explainRun(await runHttpAssessment(target, { env: ENV, transport: fakeApp('overblocking') }), record, { profile });
  assert.deepEqual(over.mismatches.map(r => [r.role, r.resource, r.reading]), [['bob', 'knowledge:kb-support', 'mismatch: declared allow, not granted']]);
  const enforcingRun = await runHttpAssessment(target, { env: ENV, transport: fakeApp('enforcing') });
  const empty = explainRun({ ...enforcingRun, results: [] }, record, { profile });
  assert.equal(empty.rows.every(r => r.reading === 'not-run'), true);
  assert.equal(empty.verified, false);
  assert.equal(enforcing.verified, false, 'an unwrapped run has no checksum, so it is never verified');
  const leakyRun = await runHttpAssessment(target, { env: ENV, transport: fakeApp('leaky') });
  const stored = explainRun({ core: leakyRun, sha256: digest(leakyRun) }, record, { profile });
  assert.equal(stored.runIntegrity, 'store-checksum-verified');
  assert.equal(stored.mismatches.length, 1);
  assert.equal(explainRun({ ...leakyRun, integrity: { algorithm: 'SHA-256', sha256: digest(leakyRun) }, notes: [] }, record, { profile }).runIntegrity, 'export-checksum-verified');
  assert.equal(explainRun(leakyRun, record, { profile }).runIntegrity, 'unverified');
  const edited = structuredClone(leakyRun); edited.results.find(r => r.status === 'fail').status = 'pass';
  assert.throws(() => explainRun({ core: edited, sha256: digest(leakyRun) }, record, { profile }), /checksum/);
});

test('PostgREST: allow needs a visible row, and a refusal is drafted only beside a role that sees rows', async () => {
  const m = rls(`alter table staff enable row level security; create policy r on staff for select to authenticated using (true);`);
  const binding = { schema: BINDING_SCHEMA, targetId: 'supabase-local', actors: { anon: 'anonymous', authenticated: 'member' }, postgrest: { basePath: '/rest/v1' } };
  const draft = draftChecks(m, binding);
  const allow = draft.checks.find(c => c.id === checkIdFor({ role: 'authenticated', resource: 'public.staff', action: 'SELECT', decision: 'allow' }));
  assert.deepEqual(allow.assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/0', expected: true }]);
  assert.ok(draft.warnings.some(w => w.startsWith(allow.id) && /seed at least one row/.test(w)));
  const deny = draft.checks.find(c => c.id === checkIdFor({ role: 'anon', resource: 'public.staff', action: 'SELECT', decision: 'deny' }));
  assert.equal(deny.path, '/rest/v1/staff?select=*&limit=1');
  assert.deepEqual(deny.assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/0', expected: false }]);
  const helpdesk = draftChecks(importRls(await migrations(), { application: 'helpdesk', roles: ['anon', 'authenticated'] }), binding);
  assert.ok(helpdesk.notDrafted.some(n => n.role === 'anon' && n.resource === 'public.profiles' && /empty result could not show a refusal/.test(n.reason)));
  assert.ok(helpdesk.notDrafted.some(n => n.action === 'INSERT' && /changes data/.test(n.reason)));
  assert.ok(helpdesk.notDrafted.some(n => n.resource === 'public.audit_log' && n.decision === 'undeclared'));
  const quoted = draftChecks(rls('alter table "Staff" enable row level security; create policy r on "Staff" for select using (true);'), binding);
  assert.ok(quoted.notDrafted.some(n => /plain names/.test(n.reason)));
});

// ---- CLI ----------------------------------------------------------------------

test('CLI: import, draft, confirm and diff in a path with spaces; outputs are new files, mode 0600', async t => {
  const dir = await scratch(t), out = [], run = argv => main(argv, { out: line => out.push(line) });
  const matrixFile = join(dir, 'owui matrix.json');
  assert.equal(await run(['import', 'openwebui', '--app', 'owui', join(here, 'fixtures', 'openwebui-export.json'), '--out', matrixFile]), 0);
  assert.equal((await stat(matrixFile)).mode & 0o777, 0o600);
  await assert.rejects(run(['import', 'openwebui', '--app', 'owui', join(here, 'fixtures', 'openwebui-export.json'), '--out', matrixFile]), /EEXIST/);
  await writeFile(join(dir, 'binding.json'), JSON.stringify(binding()));
  await writeFile(join(dir, 'profile.json'), JSON.stringify(baseProfile()));
  assert.equal(await run(['draft', matrixFile, '--binding', join(dir, 'binding.json'), '--out', join(dir, 'draft.json')]), 0);
  assert.equal(await run(['confirm', join(dir, 'draft.json'), '--matrix', matrixFile, '--binding', join(dir, 'binding.json'), '--profile', join(dir, 'profile.json'), '--confirmed-by', 'Synthetic Reviewer', '--out-profile', join(dir, 'confirmed.json'), '--out-record', join(dir, 'record.json')]), 0);
  validateTargetFile(JSON.parse(await readFile(join(dir, 'confirmed.json'))));
  const migrationsDir = join(here, 'fixtures', 'supabase-migrations');
  assert.equal(await run(['import', 'rls', '--app', 'helpdesk', '--roles', 'anon,authenticated', migrationsDir, '--out', join(dir, 'after.json')]), 0);
  assert.equal(await run(['import', 'rls', '--app', 'helpdesk', '--roles', 'anon,authenticated', join(migrationsDir, '20260101000000_init.sql'), join(migrationsDir, '20260102000000_tickets.sql'), '--out', join(dir, 'before.json')]), 0);
  assert.equal(await run(['diff', join(dir, 'after.json'), join(dir, 'before.json')]), 1, 'going back to the open anon read widens access');
  assert.equal(await run(['diff', join(dir, 'before.json'), join(dir, 'after.json')]), 0);
  await assert.rejects(run(['import', 'rls', migrationsDir, '--out', join(dir, 'x.json')]), /--app/);
});

test('lexer: semicolons and policy words inside literals, nested comments and E-string escapes are read, not split', () => {
  const m = rls(`/* outer /* nested ; */ still comment */ alter table t enable row level security;
    create policy "a;b" on t for select using (label <> 'x;y' and note <> E'it\\'s;' and tag <> $q$z;$q$);`);
  assert.equal(m.complete, true);
  assert.deepEqual(cell(m, 'anon', 'public.t', 'SELECT').conditions, ["permissive using: label <> 'x;y' and note <> 'it''s;' and tag <> 'z;' [a;b]"]);
  const dotted = rls('create table "My.Table" (id int); alter table "My.Table" enable row level security; create policy p on "My.Table" for select using (true);');
  assert.equal(cell(dotted, 'anon', 'public."My.Table"', 'SELECT').decision, 'allow');
});

test('explain refuses to read a result whose severity differs from the drafted check', async () => {
  const draft = draftChecks(await owuiMatrix(), binding());
  const { profile, record } = await confirmWith(draft, baseProfile(), { confirmedBy: 'Synthetic Reviewer' });
  const deny = record.provenance.find(p => p.decision === 'deny');
  const run = await runHttpAssessment(profile.targets[0], { env: ENV, transport: fakeApp('enforcing') });
  run.results.find(r => r.id === deny.checkId).severity = 'control';
  const explained = explainRun(run, record, { profile });
  assert.equal(explained.rows.find(r => r.checkId === deny.checkId).reading, 'check-differs-from-draft');
});

test('CLI confirm writes nothing when the product validator rejects the resulting profile', async t => {
  const dir = await scratch(t), run = argv => main(argv, { out: () => {} });
  const matrixFile = join(dir, 'm.json');
  await run(['import', 'openwebui', '--app', 'owui', join(here, 'fixtures', 'openwebui-export.json'), '--out', matrixFile]);
  await writeFile(join(dir, 'binding.json'), JSON.stringify(binding()));
  const broken = baseProfile(); broken.targets[0].origin = 'http://example.com:80';
  await writeFile(join(dir, 'profile.json'), JSON.stringify(broken));
  await run(['draft', matrixFile, '--binding', join(dir, 'binding.json'), '--out', join(dir, 'draft.json')]);
  await assert.rejects(run(['confirm', join(dir, 'draft.json'), '--matrix', matrixFile, '--binding', join(dir, 'binding.json'), '--profile', join(dir, 'profile.json'), '--confirmed-by', 'Synthetic Reviewer', '--out-profile', join(dir, 'c.json'), '--out-record', join(dir, 'r.json')]));
  await assert.rejects(stat(join(dir, 'c.json')), /ENOENT/);
  await assert.rejects(stat(join(dir, 'r.json')), /ENOENT/);
});

test('turning RLS off or deleting a security requirement is a gated became-undeclared change', async t => {
  const before = rls('alter table t enable row level security; create policy p on t for select to authenticated using (owner = auth.uid());');
  const after = rls('alter table t enable row level security; create policy p on t for select to authenticated using (owner = auth.uid()); alter table t disable row level security;');
  const d = diffMatrices(before, after);
  assert.ok(d.changes.length > 0 && d.changes.every(c => c.kind === 'became-undeclared'));
  assert.equal(d.gated, true);
  const doc = sec => ({ openapi: '3.0.3', components: { securitySchemes: { s: { type: 'http', scheme: 'bearer' } } }, paths: { '/a': { get: sec ? { security: [{ s: [] }] } : {} } } });
  assert.equal(diffMatrices(importOpenApi({ id: 'a.json', content: JSON.stringify(doc(true)) }, { application: 'x' }), importOpenApi({ id: 'a.json', content: JSON.stringify(doc(false)) }, { application: 'x' })).gated, true);
  const dir = await scratch(t);
  await writeFile(join(dir, 'b.json'), JSON.stringify(before)); await writeFile(join(dir, 'a.json'), JSON.stringify(after));
  assert.equal(await main(['diff', join(dir, 'b.json'), join(dir, 'a.json')], { out: () => {} }), 1);
});

test('a gap follows its table through RENAME and SET SCHEMA', () => {
  const renamed = rls('alter table t enable row level security; create policy p on t for select to authenticated using (x = 1) garbage; alter table t rename to u;');
  assert.equal(cell(renamed, 'authenticated', 'public.u', 'SELECT').decision, 'unknown');
  const moved = rls('alter table t enable row level security; create policy p on t for select to authenticated using (x = 1) garbage; alter table t set schema app;');
  assert.equal(cell(moved, 'authenticated', 'app.t', 'SELECT').decision, 'unknown');
});

test('confirmation re-derives GET, no body, id, title and assertions, so a recomputed draftId cannot smuggle a change', async () => {
  const draft = draftChecks(await owuiMatrix(), binding());
  const reseal = d => { const { draftId, ...body } = d; return { ...body, draftId: createHashHex(body) }; };
  const forge = edit => { const d = structuredClone(draft); edit(d); return reseal(d); };
  const deny = draft.checks.findIndex(c => c.severity === 'high'), allow = draft.checks.findIndex(c => c.severity === 'control');
  for (const [name, edit] of [
    ['POST', d => { d.checks[deny].method = 'POST'; }],
    ['body', d => { d.checks[deny].body = {}; }],
    ['5xx refusal', d => { d.checks[deny].assertions = [{ kind: 'status.in', expected: [403, 500] }]; }],
    ['allow as 403', d => { d.checks[allow].assertions = [{ kind: 'status.equals', expected: 403 }]; }],
    ['severity', d => { d.checks[deny].severity = 'control'; }],
    ['id', d => { d.checks[deny].id = 'PI-000000000000'; d.provenance[deny].checkId = 'PI-000000000000'; }],
    ['decision flip', d => { d.provenance[deny].decision = 'allow'; }],
    ['dropped provenance', d => { d.provenance.splice(deny, 1); }],
    ['unsafe path', d => { d.checks[deny].path = '//evil.example/x'; }],
  ]) await assert.rejects(confirmWith(forge(edit), baseProfile(), { confirmedBy: 'x' }), /not drafted from a declaration|exactly one provenance/, name);
});
import { createHash } from 'node:crypto';
import { canonical } from './matrix.mjs';
const createHashHex = body => createHash('sha256').update(canonical(body)).digest('hex');

test('search_path is a list resolved in order; RESET and DEFAULT mean public; an unresolvable name is a gap', () => {
  const listed = rls('alter table public.t enable row level security; set search_path to app, public; create policy p on t for select using (true);');
  assert.equal(cell(listed, 'anon', 'public.t', 'SELECT').decision, 'allow');
  assert.equal(listed.complete, true);
  const reset = rls('set search_path to app; reset search_path; alter table t enable row level security; create policy p on t for select using (true);');
  assert.equal(cell(reset, 'anon', 'public.t', 'SELECT').decision, 'allow');
  const dflt = rls('set search_path to default; alter table t enable row level security;');
  assert.ok(dflt.resources.includes('public.t'));
  const lost = rls('set search_path to app, other; create policy p on t for select using (true);');
  assert.equal(lost.complete, false);
});

test('SET SCHEMA and ALTER SCHEMA RENAME move policies; DROP OWNED makes everything unknown', () => {
  const moved = rls('create policy p on public.t for select using (true); alter table public.t set schema app; alter table app.t enable row level security;');
  assert.equal(cell(moved, 'anon', 'app.t', 'SELECT').decision, 'allow');
  const renamed = rls('create policy p on app.t for select using (true); alter schema app rename to core; alter table core.t enable row level security;');
  assert.equal(cell(renamed, 'anon', 'core.t', 'SELECT').decision, 'allow');
  const dropped = rls('alter table t enable row level security; create policy p on t for select to editor using (true); drop owned by editor;');
  assert.ok(dropped.cells.every(c => c.decision === 'unknown'));
});

test('role membership, BYPASSRLS and table owners are never guessed', () => {
  const member = rls('alter table t enable row level security; create policy p on t for select to authenticated using (true); grant authenticated to editor;', { roles: ['anon', 'authenticated', 'editor'] });
  assert.equal(cell(member, 'editor', 'public.t', 'SELECT').decision, 'unknown');
  assert.equal(cell(member, 'anon', 'public.t', 'SELECT').decision, 'deny');
  const bypass = rls('create role svc bypassrls; alter table t enable row level security;', { roles: ['anon', 'svc'] });
  assert.equal(cell(bypass, 'svc', 'public.t', 'SELECT').decision, 'unknown');
  assert.equal(cell(bypass, 'anon', 'public.t', 'SELECT').decision, 'deny');
  const owned = rls('alter table t enable row level security; alter table t owner to app_owner;', { roles: ['anon', 'app_owner'] });
  assert.equal(cell(owned, 'app_owner', 'public.t', 'SELECT').decision, 'unknown');
  const forced = rls('alter table t enable row level security, force row level security; alter table t owner to app_owner;', { roles: ['anon', 'app_owner'] });
  assert.equal(cell(forced, 'app_owner', 'public.t', 'SELECT').decision, 'deny');
  const objectGrant = rls('alter table t enable row level security; grant select on t to anon;');
  assert.equal(objectGrant.complete, true, 'object privileges are listed as not evaluated, not gaps');
});

test('clauses out of PostgreSQL\'s order are a gap', () => {
  const m = rls('alter table t enable row level security; create policy p on t to authenticated for select using (true);');
  assert.equal(m.complete, false);
  assert.ok(m.cells.every(c => c.decision === 'unknown'));
});

test('EXECUTE or policy text in a body is a gap; a comment or seed row mentioning RLS is not', () => {
  const concat = rls("alter table t enable row level security; do $$ begin execute 'create ' || 'pol' || 'icy p on t using (true)'; end $$;");
  assert.ok(concat.cells.every(c => c.decision === 'unknown'));
  assert.match(concat.gaps[0].reason, /catalog dump/);
  const harmless = rls("alter table t enable row level security; comment on table t is 'protected by row level security policy'; insert into notes values ('row level security docs');");
  assert.equal(harmless.complete, true);
  const called = rls("alter table t enable row level security; select run_sql('create policy p on t using (true)');");
  assert.equal(called.complete, false);
});

test('quoted names with dots get distinct keys', () => {
  const m = rls('alter table "x.y".z enable row level security; create policy p on x."y.z" for select using (true);');
  assert.equal(cell(m, 'anon', '"x.y".z', 'SELECT').decision, 'deny');
  assert.equal(cell(m, 'anon', 'x."y.z"', 'SELECT').decision, 'undeclared');
});

test('OpenAPI drafts use the server path, skip operations with their own servers, and never count 404', () => {
  const doc = { openapi: '3.1.0', servers: [{ url: 'https://api.example.test/api/v1' }], components: { securitySchemes: { s: { type: 'http', scheme: 'bearer' } } },
    paths: { '/me': { get: { security: [{ s: [] }] } }, '/other': { servers: [{ url: '/x' }], get: { security: [{ s: [] }] } } } };
  const m = importOpenApi({ id: 'o.json', content: JSON.stringify(doc) }, { application: 'x', roleMap: { member: { s: [] } } });
  const draft = draftChecks(m, { schema: BINDING_SCHEMA, targetId: 't', actors: { anonymous: 'anonymous', member: 'member' } });
  const me = draft.checks.find(c => c.id === checkIdFor({ role: 'anonymous', resource: '/me', action: 'GET', decision: 'deny' }));
  assert.equal(me.path, '/api/v1/me');
  assert.deepEqual(me.assertions, [{ kind: 'status.in', expected: [401, 403] }]);
  assert.ok(draft.notDrafted.some(n => n.resource === '/other' && /own servers/.test(n.reason)));
  const many = importOpenApi({ id: 'o.json', content: JSON.stringify({ ...doc, servers: [{ url: '/a' }, { url: '/b' }] }) }, { application: 'x', roleMap: { member: { s: [] } } });
  assert.ok(draftChecks(many, { schema: BINDING_SCHEMA, targetId: 't', actors: { anonymous: 'anonymous' } }).notDrafted.some(n => /several or unreadable servers/.test(n.reason)));
  assert.throws(() => importOpenApi({ id: 'o.json', content: JSON.stringify(doc) }, { application: 'x', roleMap: { member: { s: true } } }), /roleMap/);
});

test('explain refuses another target or application, and the CLI exits 0 only when everything is verified', async t => {
  const draft = draftChecks(await owuiMatrix(), binding());
  const { profile, record } = await confirmWith(draft, baseProfile(), { confirmedBy: 'Synthetic Reviewer' });
  const target = profile.targets[0];
  const run = await runHttpAssessment(target, { env: ENV, transport: fakeApp('enforcing') });
  assert.throws(() => explainRun({ ...run, targetId: 'other' }, record, { profile }), /not owui-practice/);
  assert.throws(() => explainRun({ ...run, applicationId: 'other-app' }, record, { profile }), /not owui-practice/);
  const retitled = structuredClone(run); retitled.results.find(r => r.id.startsWith('PI-')).title = 'something else';
  assert.ok(explainRun(retitled, record, { profile }).rows.some(r => r.reading === 'check-differs-from-draft'));
  const dir = await scratch(t), write = async (name, value) => { await writeFile(join(dir, name), JSON.stringify(value)); return join(dir, name); };
  const recordFile = await write('record.json', record);
  const profileFile = await write('profile.json', profile);
  const exit = async value => main(['explain', await write(`run-${Math.random()}.json`, value), '--record', recordFile, '--profile', profileFile], { out: () => {} });
  assert.equal(await exit({ core: run, sha256: digest(run) }), 0);
  assert.equal(await exit(run), 3, 'no checksum');
  const partial = structuredClone(run); partial.results = partial.results.filter(r => !r.id.startsWith('PI-'));
  assert.equal(await exit({ core: partial, sha256: digest(partial) }), 3, 'not run');
  const leaky = await runHttpAssessment(target, { env: ENV, transport: fakeApp('leaky') });
  assert.equal(await exit({ core: leaky, sha256: digest(leaky) }), 1);
});

test('Open WebUI group data that is missing or malformed, or a malformed legacy field, is unknown', async () => {
  const data = JSON.parse(await fixture('openwebui-export.json'));
  const read = d => importOpenWebUi({ id: 'e.json', content: JSON.stringify(d) }, { application: 'owui' });
  const { groups, ...noGroups } = data;
  assert.equal(cell(read(noGroups), 'bob', 'knowledge:kb-support', 'read').decision, 'unknown');
  assert.equal(cell(read(noGroups), 'bob', 'knowledge:kb-private', 'read').decision, 'deny', 'resources without group grants stay evaluated');
  assert.equal(cell(read({ ...data, groups: [{ id: 'g-support', member_ids: 'u-bob' }] }), 'bob', 'knowledge:kb-support', 'read').decision, 'unknown');
  assert.equal(cell(read({ ...data, groups: [] }), 'bob', 'knowledge:kb-support', 'read').decision, 'unknown', 'a grant to an undescribed group');
  for (const ac of ['public', [], { read: { group_ids: 'g-support' } }]) {
    const d = structuredClone(data); d.resources.push({ type: 'knowledge', id: 'kb-odd', user_id: 'u-alice', access_control: ac });
    assert.equal(cell(read(d), 'bob', 'knowledge:kb-odd', 'read').decision, 'unknown', JSON.stringify(ac));
  }
});

test('semantics: a policy without an expression for a command grants nothing; a lone restrictive grants nothing; quoted "true" is not true', () => {
  assert.equal(cell(rls('alter table t enable row level security; create policy p on t for select to authenticated;'), 'authenticated', 'public.t', 'SELECT').decision, 'deny');
  const checkOnly = rls('alter table t enable row level security; create policy p on t for all to authenticated with check (x = 1);');
  assert.equal(cell(checkOnly, 'authenticated', 'public.t', 'SELECT').decision, 'deny');
  assert.equal(cell(checkOnly, 'authenticated', 'public.t', 'INSERT').decision, 'conditional');
  assert.equal(checkOnly.complete, true);
  assert.equal(cell(rls('alter table t enable row level security; create policy r on t as restrictive for select using (true);'), 'anon', 'public.t', 'SELECT').decision, 'deny');
  assert.equal(cell(rls('alter table t enable row level security; create policy p on t for select using ("true");'), 'anon', 'public.t', 'SELECT').decision, 'conditional');
  const lone = rls('alter policy p on t using (true);');
  assert.equal(lone.complete, false);
});

test('Open WebUI: a write-only grant gives no read', async () => {
  const data = JSON.parse(await fixture('openwebui-export.json'));
  data.grants.push({ resource_type: 'knowledge', resource_id: 'kb-private', principal_type: 'user', principal_id: 'u-carol', permission: 'write' });
  const m = importOpenWebUi({ id: 'e.json', content: JSON.stringify(data) }, { application: 'owui' });
  assert.equal(cell(m, 'carol', 'knowledge:kb-private', 'write').decision, 'allow');
  assert.equal(cell(m, 'carol', 'knowledge:kb-private', 'read').decision, 'deny');
});


test('confirm re-drafts from the matrix and binding, so a fully recomputed forgery is refused', async () => {
  const matrix = await owuiMatrix(), draft = draftChecks(matrix, binding());
  const reseal = d => { const { draftId, ...body } = d; return { ...body, draftId: createHashHex(body) }; };
  const i = draft.provenance.findIndex(p => p.role === 'carol' && p.resource === 'knowledge:kb-private' && p.action === 'read');
  const flip = structuredClone(draft), p = flip.provenance[i], c = flip.checks[i];
  p.decision = 'allow'; p.checkId = c.id = checkIdFor(p); c.title = `carol may read knowledge:kb-private (declared)`; c.severity = 'control'; c.assertions = [{ kind: 'status.equals', expected: 200 }];
  for (const [name, forged] of [['decision flip', flip], ['actor swap', (() => { const d = structuredClone(draft); d.checks[i].actorId = 'anonymous'; return d; })()],
    ['path swap', (() => { const d = structuredClone(draft); d.checks[i].path = '/api/v1/knowledge/missing'; return d; })()],
    ['kind relabel', (() => { const d = structuredClone(draft); d.provenance[i].requestKind = 'openapi-literal'; return d; })()]])
    await assert.rejects(confirmWith(reseal(forged), baseProfile(), { confirmedBy: 'x' }), /not what this matrix and binding produce/, name);
  assert.throws(() => confirmDraft(draft, baseProfile(), { confirmedBy: 'x', matrix: importOpenWebUi({ id: 'e.json', content: '{"users":[],"resources":[],"grants":[]}' }, { application: 'owui' }), binding: binding() }), /not the one this draft came from/);
  // Defence in depth: the per-check rules still refuse what re-drafting would also refuse.
  const bad = structuredClone(draft); bad.checks[i].assertions = [{ kind: 'status.in', expected: [405, 429] }];
  assert.doesNotThrow(() => checkDraftChecks(draft));
  for (const [name, edit] of [['title', d => { d.checks[i].title = 'x'; }], ['kind', d => { d.provenance[i].requestKind = 'mystery'; }], ['count', d => { d.provenance.pop(); }],
    ['duplicate', d => { d.provenance[1] = { ...d.provenance[0] }; }], ['derived 404', d => { d.provenance[i].requestKind = 'openapi-literal'; }]]) {
    const d = structuredClone(draft); edit(d); assert.throws(() => checkDraftChecks(d), /not drafted from a declaration|provenance/i, name);
  }
  for (const [name, edit] of [['POST', d => { d.checks[i].method = 'POST'; }], ['body', d => { d.checks[i].body = {}; }], ['5xx refusal', d => { d.checks[i].assertions = [{ kind: 'status.in', expected: [403, 500] }]; }]]) {
    const d = structuredClone(draft); edit(d); assert.throws(() => checkDraftChecks(d), /not a GET|fields a draft never writes|assertions its decision/, name);
  }
});

test('explain refuses a run of an edited profile and an edited record, and compares actor and path', async () => {
  const draft = draftChecks(await owuiMatrix(), binding());
  const { profile, record } = await confirmWith(draft, baseProfile(), { confirmedBy: 'Synthetic Reviewer' });
  assert.equal(verifyRecord(record), true);
  const edited = structuredClone(profile); const carol = edited.targets[0].checks.find(c => c.id === checkIdFor({ role: 'carol', resource: 'knowledge:kb-private', action: 'read', decision: 'deny' }));
  carol.actorId = 'anonymous';
  const run = await runHttpAssessment(edited.targets[0], { env: ENV, transport: fakeApp('leaky') });
  assert.throws(() => explainRun({ core: run, sha256: digest(run) }, record, { profile: edited }), /profile changed after confirmation/);
  const trimmed = structuredClone(record); trimmed.provenance.pop();
  assert.throws(() => explainRun(run, trimmed, { profile }), /unedited confirmation record/);
  const real = await runHttpAssessment(profile.targets[0], { env: ENV, transport: fakeApp('enforcing') });
  const swapped = structuredClone(real); swapped.results.find(r => r.id === carol.id).trace[0].data.actorId = 'anonymous';
  assert.equal(explainRun(swapped, record, { profile }).rows.find(r => r.checkId === carol.id).reading, 'check-differs-from-draft');
  const repathed = structuredClone(real); repathed.results.find(r => r.id === carol.id).trace[0].data.requestPathHash = digest('/elsewhere');
  assert.equal(explainRun(repathed, record, { profile }).rows.find(r => r.checkId === carol.id).reading, 'check-differs-from-draft');
  const exported = { ...real, integrity: { algorithm: 'SHA-256', sha256: digest(real) }, notes: [] }; exported.results = structuredClone(real.results); exported.results[0].status = 'fail';
  assert.throws(() => explainRun(exported, record, { profile }), /exported run no longer matches/);
});

test('a DO block or a called function is a gap; defining a function or commenting is not', () => {
  for (const sql of ['do $$ begin grant authenticated to anon; end $$;', "do 'begin grant authenticated to anon; end';", "create function f() returns void language sql as 'create policy p on public.t for select using (true)'; select f();",
    "do $$ begin perform set_config('search_path','app',false); end $$;", 'do $$ begin alter table t rename to t_old; end $$;'])
    assert.ok(rls(`alter table t enable row level security; create policy p on t for select to authenticated using (true); ${sql}`).cells.every(c => c.decision === 'unknown'), sql);
  for (const sql of ['create function helper() returns uuid language sql as $$ select auth.uid() -- helper used by the RLS policy $$;', 'comment on table t is $$protected by a row level security policy$$;',
    "select set_config('search_path', 'public', false);", 'create or replace function public.touch() returns trigger language plpgsql as $$ begin new.updated_at = now(); return new; end $$;'])
    assert.equal(rls(`alter table t enable row level security; ${sql}`).complete, true, sql);
  assert.equal(rls('create event trigger e on ddl_command_end execute function f(); alter table t enable row level security;').complete, false);
});

test('CREATE TABLE goes to the first schema in search_path, not an existing table further along', () => {
  const m = rls('alter table public.t enable row level security; set search_path = app, public; create table t (id int); alter table t enable row level security; create policy p on t for select using (true);');
  assert.equal(cell(m, 'anon', 'app.t', 'SELECT').decision, 'allow');
  assert.equal(cell(m, 'anon', 'public.t', 'SELECT').decision, 'deny');
});

test('a release that adds open cells is gated', async () => {
  const before = rls('alter table t enable row level security;', { roles: ['anon'] });
  const after = rls('alter table t enable row level security; create policy p on t for select to editor using (true);', { roles: ['anon'] });
  const d = diffMatrices(before, after);
  assert.ok(d.changes.some(c => c.kind === 'added-open' && c.role === 'editor'));
  assert.equal(d.gated, true);
  const renamed = diffMatrices(rls('alter table secrets enable row level security;'), rls('alter table secrets enable row level security; alter table secrets rename to vault; create policy p on vault for select using (true);'));
  assert.equal(renamed.gated, true);
  const closed = diffMatrices(rls('alter table t enable row level security;'), rls('alter table t enable row level security; alter table u enable row level security;'));
  assert.equal(closed.gated, false, 'added deny cells are not gated');
});

test('role renames, REASSIGN OWNED, quoted search_path and SET LOCAL are handled; role settings are not gaps', () => {
  const renamed = rls('alter table t enable row level security; create policy p on t for select to editor using (true); alter role editor rename to writer;', { roles: ['writer', 'anon'] });
  assert.equal(cell(renamed, 'writer', 'public.t', 'SELECT').decision, 'unknown');
  assert.equal(cell(renamed, 'anon', 'public.t', 'SELECT').decision, 'deny');
  assert.ok(rls('alter table t enable row level security; reassign owned by postgres to anon;').cells.every(c => c.decision === 'unknown'));
  const quoted = rls('set "search_path" to app; alter table t enable row level security; create policy p on t for select using (true);');
  assert.equal(cell(quoted, 'anon', 'app.t', 'SELECT').decision, 'allow');
  assert.equal(rls('begin; set local search_path to app; commit; alter table t enable row level security;').complete, false);
  assert.equal(rls("select set_config('search_path', 'app', true); alter table t enable row level security;").complete, false);
  for (const sql of ['alter role authenticator set search_path to "$user", public;', "alter role authenticator set pgrst.db_schemas = 'public, admin';", 'alter table t add column policy text;'])
    assert.equal(rls(`alter table t enable row level security; ${sql}`).complete, true, sql);
  assert.equal(rls('create role reader in role authenticated; alter table t enable row level security;').complete, false);
});

test('an Open WebUI group without member_ids is unknown', async () => {
  const data = JSON.parse(await fixture('openwebui-export.json'));
  const m = importOpenWebUi({ id: 'e.json', content: JSON.stringify({ ...data, groups: [{ id: 'g-support' }] }) }, { application: 'owui' });
  assert.equal(cell(m, 'bob', 'knowledge:kb-support', 'read').decision, 'unknown');
});

test('statements PostgreSQL rejects, temp tables, unbalanced parentheses and ASCII-only case folding', () => {
  for (const sql of ['alter table t rename to app.u;', 'create table u (id int); alter table t rename to u;', 'create table app.x (id int); drop schema app;', 'create policy p on t using (true); alter policy p on t rename to q extra;',
    'create policy p on t for insert with check (true); alter policy p on t using (true);', 'drop policy if exists p on t extra;', 'alter table t enable row level security extra;'])
    assert.equal(rls(`create table t (id int); alter table t enable row level security; ${sql}`).complete, false, sql);
  const temp = rls('alter table public.t enable row level security; create temp table t (id int); create policy p on t for select using (true);');
  assert.equal(cell(temp, 'anon', 'public.t', 'SELECT').decision, 'deny', 'the unqualified policy lands on the temp table');
  const hidden = rls('alter table u enable row level security; create policy open on u for select using (true); alter table t enable row level security; create policy p on t using ((true); drop policy open on u;');
  assert.equal(cell(hidden, 'anon', 'public.u', 'SELECT').decision, 'unknown', 'a later DROP POLICY hidden by the unbalanced parenthesis is not guessed away');
  const folded = rls('create table ÉCOLE (id int); alter table ÉCOLE enable row level security;');
  assert.ok(folded.resources.includes('public."École"'));
  assert.equal(rls("set search_path to 'a, b'; alter table t enable row level security;").complete, false);
});

test('malformed OpenAPI and Open WebUI inputs become gaps instead of throwing; role labels cannot collide', async () => {
  const doc = { openapi: '3.0.0', components: { securitySchemes: { s: { type: 'http', scheme: 'bearer' }, anonymous: { type: 'http', scheme: 'bearer' } } },
    paths: { '/a': { get: { security: [{ s: { length: 1 } }] } }, '/b': { get: { security: [{ anonymous: [] }] } }, '/c': { get: { security: 'bad' } } }, servers: [{ url: 'v1' }] };
  const m = importOpenApi({ id: 'o.json', content: JSON.stringify(doc) }, { application: 'x' });
  assert.equal(cell(m, 'anonymous', '/a', 'GET').decision, 'unknown');
  assert.equal(cell(m, 'anonymous', '/b', 'GET').decision, 'deny', 'a scheme named anonymous is not the anonymous caller');
  assert.equal(cell(m, 'anonymous', '/c', 'GET').decision, 'unknown');
  assert.equal(m.complete, false);
  assert.equal(m.context.serverBases, null);
  const data = JSON.parse(await fixture('openwebui-export.json'));
  const dupUser = importOpenWebUi({ id: 'e.json', content: JSON.stringify({ ...data, users: [...data.users, data.users[0]] }) }, { application: 'owui' });
  assert.ok(dupUser.cells.every(c => c.decision === 'unknown'));
  const anonUser = importOpenWebUi({ id: 'e.json', content: JSON.stringify({ ...data, users: [...data.users, { id: 'u-x', role: 'user', alias: 'anonymous' }] }) }, { application: 'owui' });
  assert.equal(anonUser.complete, false);
  const dupRes = importOpenWebUi({ id: 'e.json', content: JSON.stringify({ ...data, resources: [...data.resources, data.resources[0]] }) }, { application: 'owui' });
  assert.equal(cell(dupRes, 'alice', 'knowledge:kb-private', 'read').decision, 'unknown');
});

test('any CASCADE is a gap (it can drop dependent policies); DROP POLICY and TRUNCATE CASCADE are not', () => {
  const base = 'create table t (id int, tenant_id int); alter table t enable row level security; create policy open on t for select using (true); create policy r on t as restrictive for select using (tenant_id = app_tenant());';
  for (const sql of ['drop function app_tenant() cascade;', 'alter table t drop column tenant_id cascade;', 'drop type tier cascade;', 'drop schema private cascade;', 'drop table b cascade;'])
    assert.ok(rls(`${base} ${sql}`).cells.every(c => c.decision === 'unknown'), sql);
  assert.equal(rls(`${base} drop policy if exists gone on t cascade;`).complete, true);
  assert.equal(rls(`${base} truncate t cascade;`).complete, true);
});

test('calling a function these files define is a gap wherever the call runs; defining or triggering a built-in is not', () => {
  const f = "create function f() returns int language plpgsql as $$ begin execute 'create policy sneaky on public.t for select using (true)'; return 1; end $$; alter table t enable row level security;";
  for (const sql of ['with x as (select f() as v) select v from x;', 'insert into log values (f());', '(select f());', 'values (f());', 'create table t2 as select f();', 'prepare p as select 1; execute p;',
    'create table log (id int); create trigger tr after insert on log for each row execute function f(); insert into log values (1);',
    'create table log (id int default f()); insert into log default values;'])
    assert.equal(rls(`${f} ${sql}`).complete, false, sql);
  assert.equal(rls(f).complete, true, 'defining a function runs nothing');
  for (const sql of ["with x as (select cron.schedule('j', '* * * * *', 'select 1')) select 1;", "values (cron.schedule('j', '* * * * *', 'select 1'));"])
    assert.equal(rls(`alter table t enable row level security; ${sql}`).complete, false, sql);
  assert.equal(rls('create table log (id int); create trigger tr before update on log for each row execute function moddatetime(updated_at); insert into log values (1); alter table t enable row level security;').complete, true);
  assert.equal(rls(`${f} create table log (id int); create trigger tr after insert on log for each row execute function f(); insert into other values (1);`).complete, true, 'a write to another table fires nothing');
});

test('explain survives a later confirmation into the same profile, and still refuses an edited confirmed check or actor', async () => {
  const draft = draftChecks(await owuiMatrix(), binding());
  const { profile, record } = await confirmWith(draft, baseProfile(), { confirmedBy: 'Synthetic Reviewer' });
  const later = structuredClone(profile);
  later.targets[0].checks.push({ id: 'LATER-1', title: 'A later confirmation', category: 'Declared policy', severity: 'high', actorId: 'carol', method: 'GET', path: '/api/v1/knowledge/kb-x', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [401, 403, 404] }] });
  const run = await runHttpAssessment(later.targets[0], { env: ENV, transport: fakeApp('enforcing') });
  const explained = explainRun({ core: run, sha256: digest(run) }, record, { profile: later });
  assert.equal(explained.verified, true);
  assert.throws(() => explainRun(run, record, { profile }), /not of this profile/);
  const identity = structuredClone(later); identity.targets[0].actors.carol.identityValue = 'other@example.test';
  identity.targets[0].checks.find(c => c.id === 'CAROL-WHOAMI').assertions[1].expected = 'other@example.test';
  const run2 = await runHttpAssessment(identity.targets[0], { env: ENV, transport: fakeApp('enforcing') });
  assert.throws(() => explainRun(run2, record, { profile: identity }), /Actor carol changed/);
  assert.throws(() => explainRun(run, record), /needs the profile/);
});

test('PostgREST refusal by table privilege is its own mode', async () => {
  const m = rls('alter table staff enable row level security; create policy r on staff for select to authenticated using (true);');
  const draft = draftChecks(m, { schema: BINDING_SCHEMA, targetId: 'sb', actors: { anon: 'anonymous', authenticated: 'member' }, postgrest: { basePath: '/rest/v1', refusal: 'privilege' } });
  const deny = draft.checks.find(c => c.id === checkIdFor({ role: 'anon', resource: 'public.staff', action: 'SELECT', decision: 'deny' }));
  assert.deepEqual(deny.assertions, [{ kind: 'status.in', expected: [401, 403] }, { kind: 'json.equals', pointer: '/code', expected: '42501' }]);
  assert.doesNotThrow(() => checkDraftChecks(draft));
  const other = draftChecks(m, { schema: BINDING_SCHEMA, targetId: 'sb', actors: { anon: 'anonymous', authenticated: 'anonymous' }, postgrest: { basePath: '/rest/v1' } });
  assert.ok(other.warnings.some(w => /stands for several roles/.test(w)));
  assert.throws(() => draftChecks(m, { schema: BINDING_SCHEMA, targetId: 'sb', actors: {}, postgrest: { basePath: '/rest/v1', refusal: 'maybe' } }), /refusal/);
});

test('a rename that drops RLS, a new table without RLS, and a changed function body all show in the diff', () => {
  const renamed = diffMatrices(rls('alter table secrets enable row level security;'), rls('alter table secrets enable row level security; alter table secrets rename to vault; alter table vault disable row level security;'));
  assert.equal(renamed.gated, true);
  assert.equal(diffMatrices(rls('alter table t enable row level security;'), rls('alter table t enable row level security; create table u (id int);')).gated, true);
  const fn = body => rls(`create function is_admin() returns boolean language sql as $$ ${body} $$; alter table t enable row level security; create policy p on t for select using (is_admin());`);
  const d = diffMatrices(fn('select false'), fn('select true'));
  assert.ok(d.changes.some(c => c.kind === 'conditions-changed'), JSON.stringify(d.counts));
});

test('search_path edge cases, BEGIN ATOMIC, schema elements, rename collisions and temp tables', () => {
  const two = rls("select set_config('application_name', 'x', false), set_config('search_path', 'app', false); alter table t enable row level security; create policy p on t for select using (true);");
  assert.equal(cell(two, 'anon', 'app.t', 'SELECT').decision, 'allow');
  assert.equal(rls("select set_config('search_path', 'app', 'true'); alter table t enable row level security;").complete, false);
  assert.equal(rls("select set_config('search_path', 'app' || ', public', false); alter table t enable row level security;").complete, false);
  const atomic = rls("create function g() returns void language sql begin atomic select 1; select set_config('search_path', 'app', false); end; alter table t enable row level security; create policy p on t for select using (true);");
  assert.equal(cell(atomic, 'anon', 'public.t', 'SELECT').decision, 'allow', 'a function body does not run when defined');
  for (const sql of ['create schema app create table t (id int);', 'create table app.t (id int); alter table public.t set schema app;', 'alter table t set schema app extra;',
    'create table core.x (id int); alter schema app rename to core;', 'create policy a on t using (true); create policy b on t using (false); alter policy a on t rename to b;'])
    assert.equal(rls(`create table app.y (id int); create table t (id int); alter table t enable row level security; ${sql}`).complete, false, sql);
  const files = [{ id: '1.sql', content: 'alter table public.t enable row level security; create temp table t (id int);', kind: 'sql' }, { id: '2.sql', content: 'create policy p on t for select using (true);', kind: 'sql' }];
  assert.equal(cell(importRls(files, { application: 'app', roles: ['anon'] }), 'anon', 'public.t', 'SELECT').decision, 'deny', 'files share one session, so the temp table still shadows public.t');
  for (const sql of ["select pg_notify('pgrst', 'reload schema');", "select pg_catalog.setval('t_id_seq', 1, false);", "alter table t alter column note set default 'see row level security docs';"])
    assert.equal(rls(`alter table t enable row level security; ${sql}`).complete, true, sql);
  assert.ok(rls('alter table t enable row level security;').assumptions.some(a => /catalog dump of the migrated test database is the authoritative input/.test(a)));
});

test('confirmation records a warning when the matrix names another application', async () => {
  const draft = draftChecks(await owuiMatrix(), binding());
  const other = baseProfile(); other.targets[0].applicationId = 'sb';
  const { record } = await confirmWith(draft, other, { confirmedBy: 'x' });
  assert.ok(record.warnings.some(w => /names application owui/.test(w)));
});


test('a "case" label inside BEGIN ATOMIC does not swallow the file; an unclosed body is a gap', () => {
  const files = [{ id: '1.sql', content: 'create table t (id int); alter table t enable row level security;', kind: 'sql' },
    { id: '2.sql', content: 'create table ev (id int, "case" int); create function g() returns int language sql begin atomic select e.case from ev e; end; create policy open on t for select using (true);', kind: 'sql' }];
  assert.equal(cell(importRls(files, { application: 'app', roles: ['anon'] }), 'anon', 'public.t', 'SELECT').decision, 'allow');
  assert.equal(rls('create table t (id int); alter table t enable row level security; create function g() returns int language sql begin atomic select 1; create policy open on t for select using (true);').complete, false);
});

test('the diff sees a widening between two unknown cells', () => {
  const before = rls('alter table t enable row level security; do $$ begin null; end $$;');
  const after = rls('alter table t enable row level security; do $$ begin null; end $$; create policy anyone on t for select using (true);');
  const d = diffMatrices(before, after);
  assert.ok(d.changes.some(c => c.kind === 'widened' && c.fromComputed === 'deny' && c.toComputed === 'allow'), JSON.stringify(d.counts));
  assert.equal(d.gated, true);
});

test('foreign-key actions, statements that only name a function, views and indexes are not gaps', () => {
  const f = 'create function is_admin() returns boolean language sql as $$ select true $$;';
  for (const sql of ['create table child (id int, parent_id int references t(id) on delete cascade on update cascade);', 'alter table t add constraint fk foreign key (id) references t(id) on delete cascade;',
    `${f} alter function is_admin() owner to postgres;`, `${f} alter function is_admin() set search_path = '';`, `${f} grant all on function is_admin() to authenticated;`, `${f} revoke execute on function is_admin() from anon;`,
    `${f} drop function is_admin();`, `${f} comment on function is_admin() is 'helper';`, 'create view v with (security_invoker = true) as select count(*), coalesce(null, 1) from t;',
    `${f} create or replace view v2 as select is_admin();`, `${f} create unique index i on t (is_admin());`])
    assert.equal(rls(`create table t (id int); alter table t enable row level security; ${sql}`).complete, true, sql);
});

test('CTAS forms, renamed trigger tables, TRUNCATE triggers, ALTER TABLE expressions and trigger WHEN clauses are gaps', () => {
  const f = "create function f() returns int language plpgsql as $$ begin execute 'create policy sneaky on public.t for select using (true)'; return 1; end $$; create table t (id int); alter table t enable row level security;";
  for (const sql of ['create table t2 as with x as (select f() as v) select v from x;', 'create table t2 as values (f());', 'create table t2 as (select f());', 'create materialized view mv as select f();',
    'create table log (id int); create trigger tr after insert on log for each row execute function f(); alter table log rename to log2; insert into log2 values (1);',
    'create table log (id int); create trigger tr after truncate on log for each statement execute function f(); truncate log;',
    'create table log (id int); alter table log add column c int default f();', 'create table log (id int); alter table log add constraint ck check (f() > 0);',
    'create table log (id int); create trigger tr before insert on log for each row when (f() > 0) execute function suppress_redundant_updates_trigger(); insert into log values (1);'])
    assert.equal(rls(`${f} ${sql}`).complete, false, sql);
  assert.ok(rls('alter table t enable row level security;').assumptions.some(a => /attribute notation or operators/.test(a)), 'what replay does not follow is stated');
});

test('helpers, overloads, quoted names and function attributes are part of a condition', () => {
  const policy = 'alter table t enable row level security; create policy p on t for select using (is_member(org_id));';
  const helper = body => rls(`create function has_role(r text) returns boolean language sql as $$ ${body} $$; create function is_member(o uuid) returns boolean language sql as $$ select has_role('member') $$; ${policy}`);
  assert.ok(diffMatrices(helper('select false'), helper('select true')).changes.some(c => c.kind === 'conditions-changed'));
  const overload = body => rls(`create function is_member() returns boolean language sql as $$ ${body} $$; create function is_member(o uuid) returns boolean language sql as $$ select false $$; ${policy}`);
  assert.ok(diffMatrices(overload('select false'), overload('select true')).changes.some(c => c.kind === 'conditions-changed'));
  const quoted = body => rls(`create function "IsAdmin"() returns boolean language sql as $$ ${body} $$; alter table t enable row level security; create policy p on t for select using ("IsAdmin"());`);
  assert.ok(diffMatrices(quoted('select false'), quoted('select true')).changes.some(c => c.kind === 'conditions-changed'));
  const attr = sec => rls(`create function is_member(o uuid) returns boolean language sql ${sec} as $$ select true $$; ${policy}`);
  assert.ok(diffMatrices(attr('security invoker'), attr('security definer')).changes.some(c => c.kind === 'conditions-changed'));
});

test('ON COMMIT DROP and DISCARD end a temporary table', () => {
  const base = 'create table t (id int); alter table t enable row level security;';
  assert.equal(cell(rls(`${base} begin; create temp table t (id int) on commit drop; commit; alter table t disable row level security;`), 'anon', 'public.t', 'SELECT').decision, 'undeclared');
  assert.equal(cell(rls(`${base} create temp table t (id int); discard temp; alter table t disable row level security;`), 'anon', 'public.t', 'SELECT').decision, 'undeclared');
});

test('a dump with owners, roles, memberships and functions decides what replay leaves unknown', () => {
  const dump = { tables: [{ schemaname: 'public', tablename: 't', rowsecurity: true, forcerowsecurity: false }, { schemaname: 'public', tablename: 'f', rowsecurity: true, forcerowsecurity: true }],
    policies: [{ schemaname: 'public', tablename: 't', policyname: 'auth read', permissive: 'PERMISSIVE', roles: '{authenticated}', cmd: 'SELECT', qual: 'is_member(org_id)', with_check: null }],
    owners: [{ schemaname: 'public', tablename: 't', owner: 'app_owner' }, { schemaname: 'public', tablename: 'f', owner: 'app_owner' }],
    roles: [{ rolname: 'authenticated', rolbypassrls: false, rolsuper: false, rolinherit: true }, { rolname: 'editor', rolbypassrls: false, rolsuper: false, rolinherit: true },
      { rolname: 'service_role', rolbypassrls: true, rolsuper: false, rolinherit: true }, { rolname: 'app_owner', rolbypassrls: false, rolsuper: false, rolinherit: true }, { rolname: 'anon', rolbypassrls: false, rolsuper: false, rolinherit: true }],
    members: [{ role: 'authenticated', member: 'editor' }], functions: [{ schema: 'public', name: 'is_member', digest: 'aaa' }] };
  const read = d => importRls([{ id: 'catalog.json', content: JSON.stringify(d), kind: 'catalog-json' }], { application: 'app', roles: ['anon', 'editor', 'service_role', 'app_owner'] });
  const m = read(dump);
  assert.equal(cell(m, 'editor', 'public.t', 'SELECT').decision, 'conditional', 'a member gets the policies of the role it inherits from');
  assert.equal(cell(m, 'anon', 'public.t', 'SELECT').decision, 'deny');
  assert.equal(cell(m, 'service_role', 'public.t', 'DELETE').basis, 'bypassrls (catalog)');
  assert.equal(cell(m, 'app_owner', 'public.t', 'DELETE').decision, 'allow', 'the owner bypasses RLS without FORCE');
  assert.equal(cell(m, 'app_owner', 'public.f', 'DELETE').decision, 'deny', 'FORCE applies RLS to the owner');
  const changed = read({ ...dump, functions: [{ schema: 'public', name: 'is_member', digest: 'bbb' }] });
  assert.ok(diffMatrices(m, changed).changes.some(c => c.kind === 'conditions-changed'));
});

test('explain refuses a profile whose origin or context changed after confirmation', async () => {
  const draft = draftChecks(await owuiMatrix(), binding());
  const { profile, record } = await confirmWith(draft, baseProfile(), { confirmedBy: 'x' });
  const moved = structuredClone(profile); moved.targets[0].origin = 'http://127.0.0.1:4999';
  const run = await runHttpAssessment(moved.targets[0], { env: ENV, transport: fakeApp('enforcing') });
  assert.throws(() => explainRun(run, record, { profile: moved }), /origin or context changed/);
});

test('in a catalog dump a member of the owning role skips RLS like the owner; FORCE and a non-member keep their policies', () => {
  const role = rolname => ({ rolname, rolbypassrls: false, rolsuper: false, rolinherit: true });
  const dump = members => ({ tables: [{ schemaname: 'public', tablename: 'docs', rowsecurity: true, forcerowsecurity: false }, { schemaname: 'public', tablename: 'forced', rowsecurity: true, forcerowsecurity: true }],
    policies: ['docs', 'forced'].map(tablename => ({ schemaname: 'public', tablename, policyname: 'tenant only', permissive: 'PERMISSIVE', roles: '{authenticated}', cmd: 'ALL', qual: 'tenant_id = 1', with_check: null })),
    owners: [{ schemaname: 'public', tablename: 'docs', owner: 'app_owner' }, { schemaname: 'public', tablename: 'forced', owner: 'app_owner' }],
    roles: ['anon', 'authenticated', 'app_owner'].map(role), members });
  const read = d => importRls([{ id: 'catalog.json', content: JSON.stringify(d), kind: 'catalog-json' }], { application: 'app', roles: ['anon', 'authenticated'] });
  const before = read(dump([])), after = read(dump([{ role: 'app_owner', member: 'authenticated' }]));
  assert.equal(cell(before, 'authenticated', 'public.docs', 'SELECT').decision, 'conditional');
  const member = cell(after, 'authenticated', 'public.docs', 'DELETE');
  assert.equal(member.decision, 'allow', 'GRANT app_owner TO authenticated: authenticated has the owner\'s privileges, so RLS is skipped');
  assert.equal(member.basis, 'table owner bypasses RLS (catalog; authenticated has the privileges of owner app_owner; no FORCE ROW LEVEL SECURITY)');
  assert.ok(member.citations.some(c => c.statement === 'members: authenticated has the privileges of app_owner'));
  assert.equal(cell(after, 'anon', 'public.docs', 'SELECT').decision, 'deny', 'a role outside the owning role keeps its policies');
  assert.equal(cell(after, 'authenticated', 'public.forced', 'SELECT').decision, 'conditional', 'FORCE applies RLS to a member of the owning role too');
  const diff = diffMatrices(before, after);
  assert.equal(diff.gated, true);
  assert.deepEqual(diff.changes.filter(c => c.kind === 'widened').map(c => `${c.role} ${c.resource} ${c.action}`).sort(), COMMANDS.map(a => `authenticated public.docs ${a}`).sort());
  // Replay names the owner (OWNER TO) and a dump only the roles: a member's cells are unknown, never decided from its policies.
  const mixed = members => importRls([{ id: 'roles.json', content: JSON.stringify({ tables: [], policies: [], roles: ['anon', 'authenticated', 'app_owner'].map(role), members }), kind: 'catalog-json' },
    { id: 'm.sql', content: 'create table docs (tenant_id int); alter table docs enable row level security; alter table docs owner to app_owner; create policy p on docs for select to authenticated using (tenant_id = 1);' }], { application: 'app', roles: ['anon', 'authenticated'] });
  const replayed = cell(mixed([{ role: 'app_owner', member: 'authenticated' }]), 'authenticated', 'public.docs', 'SELECT');
  assert.equal(replayed.decision, 'unknown');
  assert.equal(replayed.basis, 'owning-role-member-bypasses-rls (no FORCE ROW LEVEL SECURITY)');
  assert.equal(cell(mixed([]), 'authenticated', 'public.docs', 'SELECT').decision, 'conditional', 'without the membership the policies decide');
});

test('a statement with a U&"..." name or U&\'...\' string is a gap on every table, so a policy on it never lands on a phantom table', () => {
  const base = 'create table docs (tenant_id int); alter table docs enable row level security; create policy tenant_only on docs for select to authenticated using (tenant_id = 1);';
  const before = rls(base);
  assert.equal(cell(before, 'authenticated', 'public.docs', 'SELECT').decision, 'conditional');
  for (const sql of ['create policy anyone_reads on public.U&"docs" for select using (true);', 'drop policy tenant_only on public.U&"docs";',
    'create policy anyone_reads on public.u&"d\\006fcs" uescape \'\\\' for select using (true);', "create policy p on docs for select using (tenant_id = 1 or U&'x' = 'x');"]) {
    const after = rls(`${base}\n${sql}`);
    assert.equal(cell(after, 'authenticated', 'public.docs', 'SELECT').decision, 'unknown', sql);
    assert.ok(!after.cells.some(c => c.resource === 'public.u'), sql);
    assert.ok(after.gaps.some(g => g.scope === '*' && /Unicode-escape/.test(g.reason)), sql);
    assert.equal(cell(after, 'authenticated', 'public.docs', 'SELECT').computedDecision, 'conditional', 'the rest of the file is still read');
    assert.equal(diffMatrices(before, after).gated, true, sql);
  }
  // A ; inside the U& string does not split the statement, and the statements after it are still read.
  const split = rls(`${base}\ncreate policy p2 on docs for select using (U&'a;b' = 'a;b');\nalter table docs disable row level security;`);
  assert.equal(split.gaps.length, 1);
  assert.equal(cell(split, 'authenticated', 'public.docs', 'SELECT').computedDecision, 'undeclared');
  // A catalog expression is never read undecoded either: that policy's table is a gap.
  const dump = qual => ({ tables: [{ schemaname: 'public', tablename: 'docs', rowsecurity: true, forcerowsecurity: false }],
    policies: [{ schemaname: 'public', tablename: 'docs', policyname: 'p', permissive: 'PERMISSIVE', roles: '{authenticated}', cmd: 'SELECT', qual, with_check: null }] });
  const catalog = qual => importRls([{ id: 'catalog.json', content: JSON.stringify(dump(qual)), kind: 'catalog-json' }], { application: 'app', roles: ['authenticated'] });
  assert.equal(cell(catalog("(tenant_id = 1)"), 'authenticated', 'public.docs', 'SELECT').decision, 'conditional');
  assert.equal(cell(catalog("(U&'x' = 'x')"), 'authenticated', 'public.docs', 'SELECT').decision, 'unknown');
  // PostgreSQL reads these as a name, an operator and a quoted name or number: still read.
  assert.deepEqual(tokenize('menu&"mask" u &"x" u&1').map(t => `${t.t}:${t.v}`), ['ident:menu', 'op:&', 'qident:mask', 'ident:u', 'op:&', 'qident:x', 'ident:u', 'op:&', 'number:1']);
  const readable = rls(`${base}\ncreate policy masked on docs for update to authenticated using (menu&"mask" = 1);`);
  assert.equal(readable.complete, true);
  assert.deepEqual(cell(readable, 'authenticated', 'public.docs', 'UPDATE').conditions, ['permissive using: menu & mask = 1 [masked]', 'permissive check: menu & mask = 1 [masked]']);
});

// PostgreSQL 16+ sets inheritance per grant, so a NOINHERIT role between a role and the owner can pass it on.
test('inheritance is read per grant; a role reached only by SET ROLE, or through a grant the dump cannot show, makes the cells it decides unknown', () => {
  assert.match(CATALOG_DUMP_SQL, /'inherit', \(to_jsonb\(a\)->>'inherit_option'\)::boolean, 'set', \(to_jsonb\(a\)->>'set_option'\)::boolean/);
  const role = (rolname, rolinherit = true) => ({ rolname, rolbypassrls: false, rolsuper: false, rolinherit });
  const dump = members => ({ tables: [{ schemaname: 'public', tablename: 'docs', rowsecurity: true, forcerowsecurity: false }],
    policies: [{ schemaname: 'public', tablename: 'docs', policyname: 'tenant only', permissive: 'PERMISSIVE', roles: '{authenticated}', cmd: 'ALL', qual: 'tenant_id = 1', with_check: null },
      { schemaname: 'public', tablename: 'docs', policyname: 'readers', permissive: 'PERMISSIVE', roles: '{reader}', cmd: 'SELECT', qual: 'true', with_check: null }],
    owners: [{ schemaname: 'public', tablename: 'docs', owner: 'app_owner' }],
    roles: [role('anon'), role('authenticated'), role('app_owner'), role('reader'), role('mid', false)], members });
  const read = d => importRls([{ id: 'catalog.json', content: JSON.stringify(d), kind: 'catalog-json' }], { application: 'app', roles: ['anon', 'authenticated'] });
  const at = (m, action = 'DELETE') => cell(m, 'authenticated', 'public.docs', action);
  const UNSURE = 'role-reachable-without-inheritance (SET ROLE, or a NOINHERIT grant with no inherit_option in the dump)';
  // GRANT <to> TO mid WITH INHERIT <inherit>, SET <set>; GRANT mid TO authenticated (mid is NOINHERIT; null: a dump without the flags).
  const via = (to, inherit, set) => [{ role: to, member: 'mid', inherit, set }, { role: 'mid', member: 'authenticated', inherit: inherit === null ? null : true, set: set === null ? null : true }];
  // PostgreSQL 17.11: WITH INHERIT TRUE lets authenticated read 2/2 rows of app_owner's table.
  const before = read(dump([])), after = read(dump(via('app_owner', true, true)));
  assert.equal(at(before).decision, 'conditional');
  assert.equal(at(after).decision, 'allow', 'the grant to mid is WITH INHERIT TRUE, so authenticated has the owner\'s privileges');
  assert.equal(diffMatrices(before, after).gated, true);
  assert.equal(at(read(dump(via('app_owner', false, false)))).decision, 'conditional', 'WITH INHERIT FALSE, SET FALSE: the policies decide');
  // WITH INHERIT FALSE (SET TRUE by default): authenticated can SET ROLE app_owner. A dump without the flags (before 16, where any
  // member may SET ROLE, or from an older CATALOG_DUMP_SQL) cannot rule it out either.
  for (const members of [via('app_owner', false, true), via('app_owner', null, null)]) {
    const unsure = at(read(dump(members)));
    assert.deepEqual([unsure.decision, unsure.basis, unsure.computedDecision], ['unknown', UNSURE, 'conditional'], JSON.stringify(members[0]));
    assert.ok(unsure.citations.some(c => c.statement === 'members: authenticated may reach app_owner'));
    assert.equal(diffMatrices(before, read(dump(members))).gated, true);
  }
  assert.equal(cell(read(dump(via('app_owner', null, null))), 'anon', 'public.docs', 'SELECT').decision, 'deny', 'a role without such a grant is still decided');
  // A NOINHERIT matrix role's own grants without a flag are unsure too: it inherits none of them, but may SET ROLE to them.
  const asMid = importRls([{ id: 'catalog.json', content: JSON.stringify(dump([{ role: 'app_owner', member: 'mid' }])), kind: 'catalog-json' }], { application: 'app', roles: ['mid'] });
  assert.deepEqual([cell(asMid, 'mid', 'public.docs', 'DELETE').decision, cell(asMid, 'mid', 'public.docs', 'DELETE').basis], ['unknown', UNSURE]);
  // The policies a role inherits follow the same grants.
  assert.equal(at(read(dump(via('reader', true, true))), 'SELECT').decision, 'allow', 'reader\'s USING (true) applies through the INHERIT TRUE grant');
  assert.equal(at(read(dump(via('reader', false, false))), 'SELECT').decision, 'conditional');
  assert.equal(at(read(dump(via('reader', false, true))), 'SELECT').decision, 'unknown');
  assert.equal(at(read(dump(via('reader', null, null))), 'SELECT').decision, 'unknown');
  // BYPASSRLS is not inherited, but a member may SET ROLE to it unless the grant says SET FALSE (from 16; before 16 it always may).
  const withBypasser = members => ({ ...dump(members), roles: [...dump([]).roles, { rolname: 'bypasser', rolbypassrls: true, rolsuper: false, rolinherit: true }] });
  for (const [grant, expected] of [[{ inherit: true, set: true }, 'unknown'], [{ inherit: false, set: true }, 'unknown'], [{}, 'unknown'], [{ inherit: true, set: false }, 'conditional']]) {
    const c = at(read(withBypasser([{ role: 'bypasser', member: 'authenticated', ...grant }])), 'SELECT');
    assert.equal(c.decision, expected, JSON.stringify(grant));
    if (expected === 'unknown') assert.equal(c.basis, 'role-may-set-role-to-a-bypassrls-or-superuser-role');
  }
  // Through a chain of SET-able grants too, and not through one that says SET FALSE.
  assert.equal(at(read(withBypasser([{ role: 'bypasser', member: 'mid', set: true }, { role: 'mid', member: 'authenticated', set: true }])), 'SELECT').decision, 'unknown');
  assert.equal(at(read(withBypasser([{ role: 'bypasser', member: 'mid', inherit: true, set: false }, { role: 'mid', member: 'authenticated', inherit: true, set: true }])), 'SELECT').decision, 'conditional');
  assert.equal(cell(read(withBypasser([{ role: 'bypasser', member: 'authenticated', inherit: true, set: true }])), 'anon', 'public.docs', 'SELECT').decision, 'deny', 'only the member is unknown');
});

// Where a '...' string ends depends on standard_conforming_strings.
test('standard_conforming_strings set other than on, or a quote after an odd run of backslashes in a \'...\' string, is a gap on every table', () => {
  const base = 'create table docs (tenant_id int); alter table docs enable row level security; create policy tenant_only on docs for select to authenticated using (tenant_id = 1);';
  const before = rls(base);
  assert.ok(before.assumptions.some(a => /standard_conforming_strings on/.test(a)), 'replay states how it reads strings');
  for (const sql of [
    "set standard_conforming_strings = off;\nselect 'x\\''; create policy anyone_reads on docs for select using (true); --';",
    "select 'x\\''; create policy anyone_reads on docs for select using (true); --';", // the setting made outside these files
    'alter role authenticator set standard_conforming_strings = off;',
    'alter database app set standard_conforming_strings to off;',
    "select set_config('standard_conforming_strings', 'off', false);",
    "set session standard_conforming_strings to 'off';",
    'SET "STANDARD_CONFORMING_STRINGS" = off;', "select set_config($$standard_conforming_strings$$, 'off', false);",
    "select set_config('standard_' || 'conforming_strings', 'off', false);",
  ]) {
    const after = rls(`${base}\n${sql}`);
    assert.equal(cell(after, 'authenticated', 'public.docs', 'SELECT').decision, 'unknown', sql);
    assert.ok(after.gaps.some(g => g.scope === '*' && /standard_conforming_strings|set_config with a setting name/.test(g.reason)), sql);
    assert.equal(diffMatrices(before, after).gated, true, sql);
  }
  // Still read: pg_dump's SET ... = on and the other spellings of on or the default, RESET, an E'' escaped quote, a backslash
  // that is not before a quote, and an even run before one.
  for (const sql of ['SET standard_conforming_strings = on;', "set standard_conforming_strings = 'on';", 'set session standard_conforming_strings to on;',
    'set standard_conforming_strings to default;', 'reset standard_conforming_strings;',
    "create policy p2 on docs for select to authenticated using (note <> E'it\\'s' and code ~ '^\\d+$' and path <> 'a\\\\');"]) {
    assert.equal(rls(`${base}\n${sql}`).complete, true, sql);
  }
});

// A NOINHERIT matrix role and RESTRICTIVE policies; roles a role can grant itself.
test('a NOINHERIT matrix role\'s unflagged grants are unsure (RESTRICTIVE included); WITH ADMIN and pre-16 CREATEROLE reach roles like SET ROLE', () => {
  for (const exported of [/'admin', a\.admin_option\)/, /'rolcreaterole', rolcreaterole\)/, /'server_version_num', current_setting\('server_version_num'\)::int/]) assert.match(CATALOG_DUMP_SQL, exported);
  const role = (rolname, extra = {}) => ({ rolname, rolbypassrls: false, rolsuper: false, rolinherit: true, rolcreaterole: false, ...extra });
  const docs = (owner, policies) => ({ tables: [{ schemaname: 'public', tablename: 'docs', rowsecurity: true, forcerowsecurity: false }],
    policies: policies.map(([policyname, permissive, r, qual]) => ({ schemaname: 'public', tablename: 'docs', policyname, permissive, roles: `{${r}}`, cmd: 'SELECT', qual, with_check: null })),
    owners: [{ schemaname: 'public', tablename: 'docs', owner }] });
  const read = d => importRls([{ id: 'catalog.json', content: JSON.stringify(d), kind: 'catalog-json' }], { application: 'app', roles: ['authenticated'] });
  const at = d => cell(read(d), 'authenticated', 'public.docs', 'SELECT');
  // PostgreSQL 15.19: authenticated (member of restricted) reads 0 rows; after ALTER ROLE authenticated NOINHERIT, 2.
  const restrictive = (authenticated, members) => ({ ...docs('app_owner', [['all rows', 'PERMISSIVE', 'authenticated', 'true'], ['nothing', 'RESTRICTIVE', 'restricted', 'false']]),
    roles: [authenticated, role('restricted'), role('app_owner')], members });
  assert.equal(at(restrictive(role('authenticated'), [{ role: 'restricted', member: 'authenticated', admin: false }])).decision, 'deny');
  const noinherit = at(restrictive(role('authenticated', { rolinherit: false }), [{ role: 'restricted', member: 'authenticated', admin: false }]));
  assert.deepEqual([noinherit.decision, noinherit.computedDecision], ['unknown', 'allow'], 'before 16 the restrictive policy no longer applies');
  // PostgreSQL 16+: the existing grant keeps its inherit_option, so the restrictive policy still applies.
  assert.equal(at({ ...restrictive(role('authenticated', { rolinherit: false }), [{ role: 'restricted', member: 'authenticated', inherit: true, set: true, admin: false }]), server_version_num: 170011 }).decision, 'deny');
  // Self-grant. GRANT app_owner TO authenticated WITH ADMIN TRUE, INHERIT FALSE, SET FALSE (PostgreSQL 17.11: it grants itself, 2/2 rows).
  const owned = (members, roles = [role('authenticated'), role('app_owner')], extra = { server_version_num: 170011 }) => ({ ...docs('app_owner', [['tenant only', 'PERMISSIVE', 'authenticated', 'tenant_id = 1']]), roles, members, ...extra });
  const grant = admin => [{ role: 'app_owner', member: 'authenticated', inherit: false, set: false, admin }];
  assert.equal(at(owned(grant(false))).decision, 'conditional', 'no ADMIN, no SET, no INHERIT: the policies decide');
  assert.deepEqual([at(owned(grant(true))).decision, at(owned(grant(true))).basis], ['unknown', 'role-reachable-without-inheritance (SET ROLE, or a NOINHERIT grant with no inherit_option in the dump)']);
  const bypasser = role('bypasser', { rolbypassrls: true });
  assert.equal(at(owned([{ role: 'bypasser', member: 'authenticated', inherit: false, set: false, admin: true }], [role('authenticated'), role('app_owner'), bypasser])).basis, 'role-may-set-role-to-a-bypassrls-or-superuser-role');
  assert.equal(at(owned([{ role: 'bypasser', member: 'authenticated', inherit: false, set: false, admin: false }], [role('authenticated'), role('app_owner'), bypasser])).decision, 'conditional');
  // ALTER ROLE authenticated CREATEROLE: before 16 it can grant itself any role but a superuser (15.19: 2/2 rows); 17.11 refuses.
  const creator = [role('authenticated', { rolcreaterole: true }), role('app_owner')];
  for (const extra of [{ server_version_num: 150019 }, {}]) assert.equal(at(owned([], creator, extra)).decision, 'unknown', JSON.stringify(extra));
  assert.equal(at(owned([], creator, { server_version_num: 170011 })).decision, 'conditional');
  assert.equal(at(owned([], [role('authenticated', { rolcreaterole: true }), role('app_owner'), bypasser], { server_version_num: 150019 })).basis, 'role-may-set-role-to-a-bypassrls-or-superuser-role');
  // A superuser is out of CREATEROLE's reach: with the table and the only privileged role a superuser's, the policies decide.
  const supers = { ...docs('postgres', [['tenant only', 'PERMISSIVE', 'authenticated', 'tenant_id = 1']]), roles: [role('authenticated', { rolcreaterole: true }), role('postgres', { rolsuper: true })], members: [], server_version_num: 150019 };
  assert.equal(at(supers).decision, 'conditional');
});

// client_encoding decides which bytes are a backslash or a quote.
test('client_encoding set other than UTF8 (SET, SET NAMES, SET LOCAL, set_config, ALTER ROLE or DATABASE) is a gap on every table', () => {
  const base = 'create table docs (tenant_id int); alter table docs enable row level security; create policy tenant_only on docs for select to authenticated using (tenant_id = 1);';
  const before = rls(base);
  assert.ok(before.assumptions.some(a => /client_encoding UTF8/.test(a)), 'replay states the encoding it reads');
  const hidden = "select E'ā\\'; create policy anyone_reads on docs for select using (true); --';"; // valid UTF-8; in SJIS the 0x5C is no backslash
  for (const sql of [`set client_encoding = 'SJIS';\n${hidden}`, `SET NAMES 'SJIS';\n${hidden}`, `begin; set local client_encoding to 'BIG5';\n${hidden}\ncommit;`,
    "select set_config('client_encoding', 'SJIS', false);", "alter database app set client_encoding = 'SJIS';", 'alter role authenticator set client_encoding to sjis;', "set session client_encoding = 'LATIN1';"]) {
    const after = rls(`${base}\n${sql}`);
    assert.equal(cell(after, 'authenticated', 'public.docs', 'SELECT').decision, 'unknown', sql);
    assert.ok(after.gaps.some(g => g.scope === '*' && /client_encoding/.test(g.reason)), sql);
    assert.equal(diffMatrices(before, after).gated, true, sql);
  }
  // Parameter names are case-insensitive, quoted or not; set_config takes a dollar-quoted name, or any expression.
  for (const [sql, reason] of [[`SET "CLIENT_ENCODING" = 'SJIS';\n${hidden}`, /client_encoding/], [`SET "Client_Encoding" TO 'SJIS';\n${hidden}`, /client_encoding/],
    [`ALTER ROLE authenticator SET "CLIENT_ENCODING" = 'SJIS';`, /client_encoding/], [`select set_config($$client_encoding$$, 'SJIS', false);\n${hidden}`, /client_encoding/],
    [`select set_config('client' || '_encoding', 'SJIS', false);\n${hidden}`, /set_config with a setting name/],
    [`select set_config(name, 'SJIS', false) from pg_settings where name like 'client_enc%';\n${hidden}`, /set_config with a setting name/],
    [`select pg_catalog.set_config(lower('CLIENT_ENCODING'), 'SJIS', false);`, /set_config with a setting name/],
    [`select "set_config"('client' || '_encoding', 'SJIS', false);`, /set_config with a setting name/]]) {
    const after = rls(`${base}\n${sql}`);
    assert.equal(cell(after, 'authenticated', 'public.docs', 'SELECT').decision, 'unknown', sql);
    assert.ok(after.gaps.some(g => g.scope === '*' && reason.test(g.reason)), sql);
    assert.equal(diffMatrices(before, after).gated, true, sql);
  }
  // Still read: pg_dump's SET client_encoding = 'UTF8' and the other spellings of UTF-8, DEFAULT and RESET, a quoted name set
  // to UTF8, and set_config with one literal name (an optional ::text cast) for another setting.
  for (const sql of ["SET client_encoding = 'UTF8';", "set client_encoding to 'utf-8';", "SET NAMES 'UTF8';", 'set client_encoding = unicode;', 'set client_encoding to default;', 'reset client_encoding;',
    `SET "CLIENT_ENCODING" = 'UTF8';`, "select set_config('application_name', 'migrations', false);", "select set_config('application_name'::text, 'migrations', false);", "select set_config($$application_name$$, 'migrations', false);"])
    assert.equal(rls(`${base}\n${sql}`).complete, true, sql);
});

// pg_dump 17.6+ brackets its output in \restrict <key> ... \unrestrict <key>.
test('exactly pg_dump\'s \\restrict and \\unrestrict pair (one key, first and last) is skipped; any other backslash command is a gap', () => {
  const body = ['SET client_encoding = \'UTF8\';', 'SET standard_conforming_strings = on;', "SELECT pg_catalog.set_config('search_path', '', false);",
    'CREATE TABLE public.docs (tenant_id integer);', 'ALTER TABLE public.docs ENABLE ROW LEVEL SECURITY;', 'CREATE POLICY tenant_only ON public.docs FOR SELECT TO authenticated USING ((tenant_id = 1));'];
  const dumpOf = (open, close, extra = []) => ['--', '-- PostgreSQL database dump', '--', '', open, '', ...extra, ...body, '', '--', '-- PostgreSQL database dump complete', '--', '', close, ''].join('\n');
  const KEY = 'syntheticRestrictKey000000000000';  // pg_dump writes a random one
  const read = text => importRls([{ id: 'dump.sql', content: text }], { application: 'app', roles: ['authenticated'] });
  const m = read(dumpOf(`\\restrict ${KEY}`, `\\unrestrict ${KEY}`));
  assert.equal(m.complete, true);
  const c = cell(m, 'authenticated', 'public.docs', 'SELECT');
  assert.equal(c.decision, 'conditional');
  assert.ok(c.citations.some(x => x.line === 12), 'line numbers are kept');
  for (const [label, text] of [['another key', dumpOf(`\\restrict ${KEY}`, '\\unrestrict other0key')], ['another command', dumpOf(`\\restrict ${KEY}`, `\\unrestrict ${KEY}`, ['\\! echo hi'])],
    ['not first', dumpOf('', `\\unrestrict ${KEY}`, [`SET lock_timeout = 0;`, `\\restrict ${KEY}`])], ['no closing line', dumpOf(`\\restrict ${KEY}`, '')],
    ['closing line not last', dumpOf(`\\restrict ${KEY}`, 'CREATE POLICY anyone_reads ON public.docs FOR SELECT USING (true);', [`\\unrestrict ${KEY}`])]]) {
    const g = read(text);
    assert.equal(g.complete, false, label);
    assert.equal(cell(g, 'authenticated', 'public.docs', 'SELECT')?.decision ?? 'no cell', 'no cell', `${label}: the file is unreadable`);
  }
});

// PostgreSQL decodes E'' escapes, so each name below is client_encoding (PostgreSQL 17.11: each
// switches the encoding, and the hidden policy is created).
test('a set_config name written as an E\'...\' string with a backslash escape is not one literal, so it is a gap on every table', () => {
  const base = 'create table docs (tenant_id int); alter table docs enable row level security; create policy tenant_only on docs for select to authenticated using (tenant_id = 1);';
  const before = rls(base);
  const hidden = "select E'ā\\'; create policy anyone_reads on docs for select using (true); --';";
  for (const name of ["E'client\\x5fencoding'", "E'\\143lient_encoding'", "E'\\u0063lient_encoding'", "e'client\\x5Fencoding'"]) {
    const sql = `select set_config(${name}, 'SJIS', false);\n${hidden}`;
    const after = rls(`${base}\n${sql}`);
    assert.equal(cell(after, 'authenticated', 'public.docs', 'SELECT').decision, 'unknown', sql);
    assert.ok(after.gaps.some(g => g.scope === '*' && /set_config with a setting name/.test(g.reason)), sql);
    assert.equal(diffMatrices(before, after).gated, true, sql);
  }
  // Still read: an E'' name with no backslash, and pg_dump's header.
  for (const sql of ["select set_config(E'application_name', 'migrations', false);", "SET client_encoding = 'UTF8';", "SELECT pg_catalog.set_config('search_path', '', false);"])
    assert.equal(rls(`${base}\n${sql}`).complete, true, sql);
});

// After set search_path = scratch, PostgreSQL 17.11 puts the unqualified policy on public.docs after each form in the
// first test below and on scratch.docs after each in the second (where a form fails on the server, nothing changes).
const twoSchemas = 'create schema scratch; create table public.docs (tenant_id int); alter table public.docs enable row level security; create policy tenant_only on public.docs for select to authenticated using (tenant_id = 1);\ncreate table scratch.docs (tenant_id int); set search_path = scratch;';
const anyoneReads = 'create policy anyone_reads on docs for select using (true);';
test('SET SCHEMA, quoted and dollar-quoted names, a quoted "set_config", RESET and DISCARD ALL move search_path as PostgreSQL does', () => {
  const before = rls(twoSchemas);
  for (const form of ["SET SCHEMA 'public';", 'SET SESSION SCHEMA $$public$$;', 'SET "SEARCH_PATH" = public;', 'RESET "SEARCH_PATH";', 'discard all;',
    "select set_config($$search_path$$, 'public', false);", `select "set_config"('search_path', 'public', false);`, "select set_config('SEARCH_PATH', 'public', false);",
    "SELECT pg_catalog.set_config('search_path', 'public', false);", "select set_config('search_path', 'public', 'false');",
    "select set_config('search_path', 'public', false), set_config('application_name', 'x', false);",
    "select set_config('search_path', current_setting('search_path') || ', public', false); set search_path = public;"]) {
    const after = rls(`${twoSchemas}\n${form}\n${anyoneReads}`);
    assert.equal(after.complete, true, form);
    assert.equal(cell(after, 'authenticated', 'public.docs', 'SELECT').decision, 'allow', form);
    assert.equal(diffMatrices(before, after).gated, true, form);
  }
  // DISCARD TEMP leaves the path alone, so the policy lands on scratch.docs.
  const temp = rls(`${twoSchemas}\ndiscard temp;\n${anyoneReads}`);
  assert.deepEqual([temp.complete, cell(temp, 'authenticated', 'public.docs', 'SELECT').decision], [true, 'conditional']);
});

test('a search_path PostgreSQL may not have set as written is a gap for later unqualified names; outside a SELECT, for the rest of the history', () => {
  const before = rls(twoSchemas);
  for (const form of ["select set_config(E'search\\x5fpath', 'public', false);", "set search_path = E'pub\\x6cic';", "select set_config('search_path', E'pub\\x6cic', false);", "SET SCHEMA E'pub\\x6cic';",
    "set search_path = '';", "SET SCHEMA '';", "SET SCHEMA 'public', 'scratch';", "select set_config('search_path', 'public,', false);",
    "select set_config('search_path', 'public', false) where false;", "select set_config('search_path', 'public', false) limit 0;", "select * from set_config('search_path', 'public', false);",
    "select set_config('search_path', 'public', false), 1/0;", "select set_config('search_path', 'public', not false);", "select set_config('search_path', 'public', false or true);",
    "explain analyze select set_config('search_path', 'public', false);", "create table scratch.t2 as select set_config('search_path', 'public', false);",
    "begin; set local schema 'public'; commit;", 'begin; set search_path = public; rollback;', 'begin; savepoint s; set search_path = public; rollback to savepoint s; commit;',
    'begin; set search_path = public; abort;', "begin; set search_path = public; prepare transaction 'm1';"]) {
    const after = rls(`${twoSchemas}\n${form}\n${anyoneReads}`);
    assert.equal(after.complete, false, form);
    for (const resource of ['public.docs', 'scratch.docs']) assert.equal(cell(after, 'authenticated', resource, 'SELECT').decision, 'unknown', `${form} ${resource}`);
    assert.equal(diffMatrices(before, after).gated, true, form);
  }
  // Outside a SELECT a set_config of search_path may run on a later statement (17.11: this INSERT's default moves the path
  // to public), so the path stays unknown after a readable SET.
  const later = rls(`${twoSchemas}\ncreate table scratch.log (v text default set_config('search_path', 'public', false)); set search_path = scratch; insert into scratch.log default values;\n${anyoneReads}`);
  assert.equal(later.complete, false);
  assert.ok(later.gaps.some(g => /search_path could not be read/.test(g.reason)));
  // Still read: PREPARE of a statement, and a transaction that commits.
  for (const form of ['prepare q as select 1;', 'begin; set search_path = public; commit;'])
    assert.equal(rls(`${twoSchemas}\n${form}\n${anyoneReads}`).complete, true, form);
});

// Carried: PostgreSQL cuts every name to 63 bytes (17.11: the policies below land on the 63-byte and 62-byte tables).
test('names are cut to 63 bytes at a character boundary, in statements, search_path values and function bodies', () => {
  const a = n => 'a'.repeat(n);
  for (const [table, spelling] of [[a(63), a(70)], [a(62), `"${a(62)}é"`]]) {
    const m = rls(`create table ${table} (tenant_id int); alter table ${table} enable row level security; create policy anyone_reads on ${spelling} for select using (true);`);
    assert.deepEqual([m.resources, cell(m, 'anon', `public.${table}`, 'SELECT').decision], [[`public.${table}`], 'allow'], spelling);
  }
  // In search_path: an unquoted name folded and cut, a quoted one kept as written, and a SET string cut.
  for (const [schema, form] of [[`s${a(62)}`, `select set_config('search_path', 'S${'A'.repeat(69)}', false);`], ['"App"', `select set_config('search_path', '"App"', false);`], [a(63), `set search_path = '${a(70)}';`]]) {
    const m = rls(`create table ${schema}.t (id int); alter table ${schema}.t enable row level security; ${form} create policy p on t for select using (true);`);
    assert.equal(cell(m, 'anon', `${schema}.t`, 'SELECT')?.decision, 'allow', form);
  }
  // A function body calls a helper by its first 63 bytes, so the helper's hash is part of the condition.
  const helper = `h${'x'.repeat(69)}`;
  const m = rls(`create function ${helper}() returns boolean language sql as $$ select true $$; create function is_member() returns boolean language sql as $$ select ${helper}() $$; alter table t enable row level security; create policy p on t for select using (is_member());`);
  assert.match(cell(m, 'anon', 'public.t', 'SELECT').conditions[0], new RegExp(`${helper.slice(0, 63)}#`));
});

// pg_database_owner's member is the database owner, implicitly (17.11: with authenticated owning the database,
// both statements let it read every row; with FORCE ROW LEVEL SECURITY it reads its policies' rows).
test('a table pg_database_owner owns without FORCE, or a policy aimed at pg_database_owner, makes that table\'s cells unknown', () => {
  const base = 'create table docs (tenant_id int); alter table docs enable row level security; create policy tenant_only on docs for select to authenticated using (tenant_id = 1);';
  const before = rls(base);
  for (const sql of ['alter table docs owner to pg_database_owner;', 'create policy owner_reads on docs for select to pg_database_owner using (true);']) {
    const c = cell(rls(`${base} ${sql}`), 'authenticated', 'public.docs', 'SELECT');
    assert.deepEqual([c.decision, c.computedDecision, c.basis], ['unknown', 'conditional', 'pg_database_owner-member-is-implicit (the database owner, any role)'], sql);
    assert.equal(diffMatrices(before, rls(`${base} ${sql}`)).gated, true, sql);
  }
  assert.equal(cell(rls(`${base} alter table docs owner to pg_database_owner; alter table docs force row level security;`), 'authenticated', 'public.docs', 'SELECT').decision, 'conditional');
  assert.equal(cell(rls('create table notes (id int); alter table notes owner to pg_database_owner;'), 'authenticated', 'public.notes', 'SELECT').decision, 'undeclared');
  // A catalog dump's members never show the implicit grant.
  const dump = owner => JSON.stringify({ tables: [{ schemaname: 'public', tablename: 'docs', rowsecurity: true, forcerowsecurity: false }],
    policies: [{ schemaname: 'public', tablename: 'docs', policyname: 'tenant only', permissive: 'PERMISSIVE', roles: '{authenticated}', cmd: 'SELECT', qual: '(tenant_id = 1)', with_check: null }],
    owners: [{ schemaname: 'public', tablename: 'docs', owner }], roles: [{ rolname: 'authenticated', rolbypassrls: false, rolsuper: false, rolinherit: true, rolcreaterole: false }], members: [], server_version_num: 170011 });
  const read = owner => cell(importRls([{ id: 'catalog.json', content: dump(owner), kind: 'catalog-json' }], { application: 'app', roles: ['authenticated'] }), 'authenticated', 'public.docs', 'SELECT').decision;
  assert.deepEqual([read('app_owner'), read('pg_database_owner')], ['conditional', 'unknown']);
});

// ---- Gap identity: diff gates on a new gap even where cells are already unknown ----------------------
// With one standing gap every cell is unknown, so a release that adds a hidden change (and with it new gaps) changed no
// cell, and the diff did not gate. A gap now has an identity; a new one gates.
const STANDING = 'do $$ begin perform refresh_reports(); end $$;';
const DOCS = 'create table docs (tenant_id int); alter table docs enable row level security; create policy tenant_only on docs for select to authenticated using (tenant_id = 1);';
const replay = files => importRls(files.map(([id, content]) => ({ id, content, kind: 'sql' })), { application: 'app', roles: ['anon', 'authenticated'] });
const cellGated = d => d.changes.filter(c => GATED_KINDS.includes(c.kind));

test('with a standing gap, a release that adds a gap is gated although every cell was already unknown', () => {
  const before = rls(`${DOCS}\n${STANDING}`);
  assert.equal(before.gaps.length, 1);
  assert.ok(before.cells.every(c => c.decision === 'unknown'), 'the standing gap makes every cell unknown');
  // The hidden-change rules (client_encoding, standard_conforming_strings, U&, an E'' set_config name), and a
  // second procedural block. Each hides a policy anyone_reads that no cell shows.
  const hidden = "select E'ā\\'; create policy anyone_reads on docs for select using (true); --';";
  for (const sql of [`set client_encoding = 'SJIS';\n${hidden}`,
    "set standard_conforming_strings = off;\nselect 'x\\''; create policy anyone_reads on docs for select using (true); --';",
    'create policy anyone_reads on public.U&"docs" for select using (true);',
    `select set_config(E'client\\x5fencoding', 'SJIS', false);\n${hidden}`,
    "do $$ begin execute 'create policy anyone_reads on docs for select using (true)'; end $$;"]) {
    const after = rls(`${DOCS}\n${STANDING}\n${sql}`);
    const d = diffMatrices(before, after);
    assert.deepEqual(cellGated(d), [], `${sql}: no cell shows the change`);
    assert.equal(d.gated, true, sql);
    assert.equal(d.gapComparison, 'identity', sql);
    assert.deepEqual(d.gapCounts, { 'gap-added': after.gaps.length - 1 }, sql);
    assert.ok(d.gapChanges.every(c => c.kind === 'gap-added' && c.scope === '*' && /^[a-f0-9]{64}$/.test(c.id)), sql);
    assert.ok(!d.gapChanges.some(c => c.id === before.gaps[0].id), `${sql}: the standing gap is matched, not added`);
  }
});

test('a standing gap keeps its identity through comments, spacing, keyword case, a renamed or split file and migrations appended after it', () => {
  const before = replay([['001_init.sql', `${DOCS}\n${STANDING}`]]);
  for (const [files, moved] of [
    // Comments, blank lines and spacing move the block down; keyword case, in it and before it, folds as PostgreSQL folds it.
    [[['001_init.sql', `-- notes\n\n/* a block\n comment */\n${DOCS.replace('create table', 'CREATE TABLE')}\n\n\nDO   $$ begin perform refresh_reports(); end $$\n  ;`]], true],
    // The same statements, in the same order, in a renamed file split in two.
    [[['000_tables.sql', DOCS], ['001_jobs.sql', STANDING]], true],
    // Migrations appended after it, the normal flow.
    [[['001_init.sql', `${DOCS}\n${STANDING}`], ['002_more.sql', "create index docs_tenant on docs (tenant_id);\ncomment on table docs is 'tenant notes';"]], false]]) {
    const after = replay(files);
    const d = diffMatrices(before, after);
    assert.deepEqual([d.gated, d.gapComparison, d.gapChanges, d.changes], [false, 'identity', [], []], files.map(f => f[0]).join());
    assert.equal(after.gaps[0].id, before.gaps[0].id);
    if (moved) assert.notDeepEqual([after.gaps[0].source, after.gaps[0].line], [before.gaps[0].source, before.gaps[0].line], 'it really moved');
  }
  // A narrowed condition in a later migration is reported, not gated, and leaves the gap alone.
  const narrowed = diffMatrices(before, replay([['001_init.sql', `${DOCS}\n${STANDING}`],
    ['002_narrow.sql', 'drop policy tenant_only on docs; create policy tenant_only on docs for select to authenticated using (tenant_id = 2);']]));
  assert.deepEqual([narrowed.gated, narrowed.counts, narrowed.gapChanges], [false, { 'conditions-changed': 1 }, []]);
  // A changed gap statement is another gap, and so is one after an edited earlier statement: removed and added (gated).
  const changed = diffMatrices(before, replay([['001_init.sql', `${DOCS}\ndo $$ begin perform refresh_reports(); perform grant_all(); end $$;`]]));
  assert.deepEqual([changed.gated, changed.gapCounts, cellGated(changed)], [true, { 'gap-added': 1, 'gap-removed': 1 }, []]);
  const editedBefore = diffMatrices(before, replay([['001_init.sql', `${DOCS.replace('tenant_id = 1', 'tenant_id = 2')}\n${STANDING}`]]));
  assert.deepEqual([editedBefore.gated, editedBefore.counts, editedBefore.gapCounts], [true, { 'conditions-changed': 1 }, { 'gap-added': 1, 'gap-removed': 1 }]);
});

test('identical statements are counted: a second copy of a standing gap is a new gap; a copy keeps its id only while the history before it is unchanged', () => {
  const one = replay([['001.sql', `${DOCS}\n${STANDING}`]]);
  const two = replay([['001.sql', `${DOCS}\n${STANDING}`], ['002.sql', STANDING]]);
  assert.equal(new Set(two.gaps.map(g => g.id)).size, 2, 'two identical statements are two gaps');
  assert.equal(two.gaps[0].id, one.gaps[0].id, 'the first copy keeps its identity');
  const added = diffMatrices(one, two);
  assert.deepEqual([added.gated, added.gapCounts, cellGated(added)], [true, { 'gap-added': 1 }, []]);
  assert.deepEqual(added.gapChanges.map(c => [c.kind, c.source, c.id]), [['gap-added', '002.sql', two.gaps[1].id]]);
  // Both copies in one file, in the same order: the same two gaps.
  const regrouped = diffMatrices(two, replay([['001.sql', `${DOCS}\n${STANDING}\n${STANDING}`]]));
  assert.deepEqual([regrouped.gated, regrouped.gapChanges], [false, []]);
  // One copy dropped: removed, not gated.
  const dropped = diffMatrices(two, one);
  assert.deepEqual([dropped.gated, dropped.gapCounts], [false, { 'gap-removed': 1 }]);
  // A copy moved ahead of the tables it runs against is another gap (gated).
  const ahead = diffMatrices(one, replay([['001.sql', `${STANDING}\n${DOCS}`]]));
  assert.deepEqual([ahead.gated, ahead.gapCounts, cellGated(ahead)], [true, { 'gap-added': 1, 'gap-removed': 1 }, []]);
  // Matching counts ids: an edited matrix that repeats a standing gap's id still shows the extra copy.
  const repeated = diffMatrices(one, reseal({ ...one, gaps: [...one.gaps, { ...one.gaps[0] }] }));
  assert.deepEqual([repeated.gated, repeated.gapCounts], [true, { 'gap-added': 1 }]);
});

test('a removed gap does not gate', () => {
  const closed = 'create table docs (tenant_id int); alter table docs enable row level security;';
  const before = rls(`${closed}\n${STANDING}`), after = rls(closed);
  assert.deepEqual([cell(before, 'authenticated', 'public.docs', 'SELECT').decision, cell(after, 'authenticated', 'public.docs', 'SELECT').decision], ['unknown', 'deny']);
  const d = diffMatrices(before, after);
  assert.deepEqual([d.gated, d.gapCounts, d.gapChanges.map(c => [c.kind, c.id])], [false, { 'gap-removed': 1 }, [['gap-removed', before.gaps[0].id]]]);
});

test('a scopehaven-policy-matrix/1 matrix is still compared, but its gaps fail closed: every gap after is gated, and the diff says why', () => {
  const current = rls(`${DOCS}\n${STANDING}`), old = asSchema1(current);
  assert.deepEqual([old.schema, verifyMatrixId(old), Object.hasOwn(old.gaps[0], 'id')], ['scopehaven-policy-matrix/1', true, false]);
  const d = diffMatrices(old, current);
  assert.deepEqual([d.comparable, d.changes], [true, []], 'the cells compare as before');
  assert.deepEqual([d.gated, d.gapComparison, d.gapCounts], [true, 'before-unidentified', { 'gap-unidentified': 1 }]);
  assert.match(d.gapNote, /before matrix has gaps without identities .* every gap of the after matrix is gated\. Re-import/);
  assert.deepEqual(d.gapChanges.map(c => [c.kind, c.id]), [['gap-unidentified', current.gaps[0].id]]);
  // With no gap after, nothing is gated: a removed gap never gates.
  const closed = 'create table docs (tenant_id int); alter table docs enable row level security;';
  const none = diffMatrices(asSchema1(rls(`${closed}\n${STANDING}`)), rls(closed));
  assert.deepEqual([none.gated, none.gapComparison, none.gapChanges], [false, 'before-unidentified', []]);
  // A /1 matrix without gaps has nothing to identify, so a new gap is added by identity.
  const fromClean = diffMatrices(asSchema1(rls(DOCS)), current);
  assert.deepEqual([fromClean.gated, fromClean.gapComparison, fromClean.gapCounts, Object.hasOwn(fromClean, 'gapNote')], [true, 'identity', { 'gap-added': 1 }, false]);
  // An old after matrix, two old matrices, and a /2 gap without a well-formed id fail closed the same way.
  assert.deepEqual([diffMatrices(current, old).gated, diffMatrices(current, old).gapComparison], [true, 'after-unidentified']);
  assert.match(diffMatrices(current, old).gapNote, /after matrix has gaps without identities/);
  assert.deepEqual([diffMatrices(old, old).gated, diffMatrices(old, old).gapComparison], [true, 'before-unidentified']);
  for (const edit of [g => { delete g.id; }, g => { g.id = g.id.slice(0, 12); }, g => { g.id = g.id.toUpperCase(); }, g => { g.id = null; }]) {
    const copy = structuredClone(current); edit(copy.gaps[0]);
    const r = diffMatrices(reseal(copy), current);
    assert.deepEqual([r.comparable, r.gated, r.gapComparison], [true, true, 'before-unidentified']);
  }
  // A tampered /1 matrix whose gaps carry well-formed ids still fails closed: ids are trusted on /2 only.
  const relabelled = diffMatrices(reseal({ ...current, schema: 'scopehaven-policy-matrix/1' }), current);
  assert.deepEqual([relabelled.gated, relabelled.gapComparison, relabelled.gapCounts], [true, 'before-unidentified', { 'gap-unidentified': 1 }]);
  // A matrix whose gaps are not a list is not comparable.
  assert.deepEqual(diffMatrices(reseal({ ...current, gaps: {} }), current), { comparable: false, reason: 'before-matrix-invalid' });
});

test('in a catalog dump, an Open WebUI export and an OpenAPI document a gap is its row or item, not its index or the file name', () => {
  // Catalog: an unreadable policy row keeps its id when the rows reorder and the dump has another name; a changed row is a new gap.
  const good = { schemaname: 'public', tablename: 'docs', policyname: 'tenant only', permissive: 'PERMISSIVE', roles: '{authenticated}', cmd: 'SELECT', qual: '(tenant_id = 1)', with_check: null };
  const bad = { ...good, policyname: 'odd', cmd: 'MERGE' };
  const dump = (policies, id = 'catalog-2026-10-15.json') => importRls([{ id, kind: 'catalog-json',
    content: JSON.stringify({ tables: [{ schemaname: 'public', tablename: 'docs', rowsecurity: true, forcerowsecurity: true }], policies }) }], { application: 'app', roles: ['authenticated'] });
  const base = dump([bad, good]), reordered = dump([good, bad], 'catalog-2026-10-16.json');
  assert.deepEqual([base.gaps[0].reason.slice(0, 11), reordered.gaps[0].reason.slice(0, 11)], ['policies[0]', 'policies[1]']);
  assert.deepEqual([diffMatrices(base, reordered).gated, reordered.gaps[0].id], [false, base.gaps[0].id]);
  const changedRow = diffMatrices(base, dump([good, { ...bad, qual: '(true)' }]));
  assert.deepEqual([changedRow.gated, changedRow.gapCounts, cellGated(changedRow)], [true, { 'gap-added': 1, 'gap-removed': 1 }, []]);
  // Rows have no order, so the occurrence count is what tells two identical unreadable rows apart: a second copy is a new gap.
  const twice = dump([bad, good, bad]);
  assert.equal(new Set(twice.gaps.map(g => g.id)).size, 2);
  assert.deepEqual([diffMatrices(base, twice).gated, diffMatrices(base, twice).gapCounts], [true, { 'gap-added': 1 }]);
  // Open WebUI: an unreadable user row is scoped by its index, and identified without it.
  const owui = users => importOpenWebUi({ id: 'export.json', content: JSON.stringify({ users, resources: [{ type: 'knowledge', id: 'kb1', user_id: 'u-a' }], grants: [], groups: [] }) }, { application: 'owui' });
  const alice = { id: 'u-a', role: 'user' }, broken = { id: 7, role: 'user' };
  const first = owui([alice, broken]), second = owui([broken, alice]);
  assert.deepEqual([first.gaps[0].scope, second.gaps[0].scope], ['users[1]', 'users[0]']);
  assert.deepEqual([diffMatrices(first, second).gated, second.gaps[0].id], [false, first.gaps[0].id]);
  assert.equal(diffMatrices(first, owui([alice, { ...broken, id: 8 }])).gated, true, 'another unreadable row is another gap');
  // OpenAPI: an unresolved $ref is identified by the item, so reordering paths keeps it and another target is a new gap.
  const api = (paths, description = 'v1') => importOpenApi({ id: 'openapi.json', content: JSON.stringify({ openapi: '3.1.0', info: { title: 't', version: '1', description }, paths }) },
    { application: 'api', roleMap: { member: { key: ['read'] } } });
  const ref = { $ref: '#/components/pathItems/notes' }, open = { get: { security: [] } };
  const doc = api({ '/notes': ref, '/health': open });
  assert.deepEqual([diffMatrices(doc, api({ '/health': open, '/notes': ref }, 'v2')).gated, api({ '/health': open, '/notes': ref }, 'v2').gaps[0].id], [false, doc.gaps[0].id]);
  const retargeted = diffMatrices(doc, api({ '/notes': { $ref: '#/components/pathItems/other' }, '/health': open }));
  assert.deepEqual([retargeted.gated, cellGated(retargeted)], [true, []]);
  // An undefined scheme is identified by the security list it could not read.
  const scheme = scopes => api({ '/notes': { get: { security: [{ missing: scopes }] } } });
  assert.equal(diffMatrices(scheme([]), scheme([])).gated, false);
  const rescoped = diffMatrices(scheme([]), scheme(['read']));
  assert.deepEqual([rescoped.gated, cellGated(rescoped)], [true, []]);
});

test('the CLI diff exits 1 on a new gap where every cell was already unknown and 0 when the gaps only moved; an old baseline says why it fails closed', async t => {
  const dir = await scratch(t);
  const write = async (name, m) => { await writeFile(join(dir, name), JSON.stringify(m)); return join(dir, name); };
  const before = await write('before.json', rls(`${DOCS}\n${STANDING}`));
  const run = async args => { const lines = []; const code = await main(args, { out: line => lines.push(line) }); return [code, JSON.parse(lines[0])]; };
  const [addedCode, added] = await run(['diff', before, await write('added.json', rls(`${DOCS}\n${STANDING}\nset client_encoding = 'SJIS';`))]);
  assert.deepEqual([addedCode, added.gated, added.counts, added.gapComparison, added.gapCounts], [1, true, {}, 'identity', { 'gap-added': 1 }]);
  const [movedCode, moved] = await run(['diff', before, await write('moved.json', rls(`-- moved\n\n${DOCS}\n\n${STANDING}`))]);
  assert.deepEqual([movedCode, moved.gated, moved.gapCounts, Object.hasOwn(moved, 'gapNote')], [0, false, {}, false]);
  const [oldCode, old] = await run(['diff', await write('old.json', asSchema1(rls(`${DOCS}\n${STANDING}`))), before, '--out', join(dir, 'old-diff.json')]);
  assert.deepEqual([oldCode, old.gated, old.gapComparison, old.gapCounts], [1, true, 'before-unidentified', { 'gap-unidentified': 1 }]);
  assert.match(old.gapNote, /Re-import/);
  assert.deepEqual(JSON.parse(await readFile(join(dir, 'old-diff.json'), 'utf8')).gapChanges.map(c => c.kind), ['gap-unidentified']);
});

test('every replayed matrix says replay reads every statement as succeeded, and that the 63-byte cut assumes a UTF-8 server', () => {
  const replayed = rls(DOCS);
  assert.ok(replayed.assumptions.some(a => /reads every statement as having succeeded/.test(a) && /BEGIN \.\.\. COMMIT rolls the transaction back/.test(a) && /catalog dump reads the real result/.test(a)));
  assert.ok(replayed.assumptions.some(a => /cut to 63 bytes as a server with UTF-8 encoding cuts them/.test(a)));
  const dumped = importRls([{ id: 'c.json', content: JSON.stringify({ tables: [], policies: [] }), kind: 'catalog-json' }], { application: 'app' });
  assert.ok(!dumped.assumptions.some(a => /having succeeded|63 bytes/.test(a)), 'a catalog dump reads the real result and the real names');
});

test('matrices are scopehaven-policy-matrix/2 with an id on every gap; the readers take a /1 matrix and refuse an edited or unknown one', () => {
  const m = rls(`${DOCS}\n${STANDING}\nalter table docs enable row level security junk;`);
  assert.deepEqual([m.schema, MATRIX_SCHEMA], ['scopehaven-policy-matrix/2', 'scopehaven-policy-matrix/2']);
  assert.ok(m.gaps.length === 2 && m.gaps.every(g => /^[a-f0-9]{64}$/.test(g.id) && !Object.hasOwn(g, 'identity')), 'an id on every gap; the identity basis is not written');
  assert.equal(new Set(m.gaps.map(g => g.id)).size, 2);
  const old = asSchema1(m);
  assert.equal(proposeStatement({ application: 'app', matrices: [old] }).matrices[0].matrixId, old.matrixId);
  assert.equal(diffMatrices(old, asSchema1(rls(`${DOCS}\n${STANDING}\nalter table docs enable row level security junk;`))).comparable, true);
  for (const bad of [reseal({ ...old, schema: 'scopehaven-policy-matrix/3' }), { ...old, application: 'other' }]) {
    assert.throws(() => proposeStatement({ application: 'app', matrices: [bad] }), /missing or was edited/);
    assert.equal(diffMatrices(bad, m).comparable, false);
  }
});

// A DO block's effect depends on what ran before it, so a replayed gap is placed by the history before it.
test('moving a DO block that disables RLS past ENABLE ROW LEVEL SECURITY, or editing or inserting a statement before a gap, gates; appending does not', () => {
  const DISABLE = "do $$ begin execute 'alter table docs disable row level security'; end $$;";
  const ENABLE = 'alter table docs enable row level security; create policy tenant_only on docs for select to authenticated using (tenant_id = 1);';
  const before = replay([['1.sql', `create table docs (tenant_id int);\n${DISABLE}`], ['2.sql', ENABLE]]);
  // The old copy deleted and the same block added in a new migration after the ENABLE: RLS now ends off.
  const moved = replay([['1.sql', 'create table docs (tenant_id int);'], ['2.sql', ENABLE], ['3.sql', DISABLE]]);
  const d = diffMatrices(before, moved);
  assert.deepEqual([d.changes, before.gaps.length, moved.gaps.length], [[], 1, 1], 'no cell changes, one gap on each side');
  assert.deepEqual([d.gated, d.gapCounts], [true, { 'gap-added': 1, 'gap-removed': 1 }]);
  for (const [label, files] of [['an earlier statement edited', [['1.sql', `create table docs (tenant_id int, owner text);\n${DISABLE}`], ['2.sql', ENABLE]]],
    ['a statement inserted before it', [['1.sql', `create table docs (tenant_id int);\ncreate index docs_tenant on docs (tenant_id);\n${DISABLE}`], ['2.sql', ENABLE]]],
    ['an earlier statement removed', [['0.sql', 'create table audit (id int);'], ['1.sql', `create table docs (tenant_id int);\n${DISABLE}`], ['2.sql', ENABLE]]]]) {
    const [b, a] = label === 'an earlier statement removed' ? [replay(files), before] : [before, replay(files)];
    const r = diffMatrices(b, a);
    assert.deepEqual([r.gated, r.gapCounts], [true, { 'gap-added': 1, 'gap-removed': 1 }], label);
  }
  const appended = replay([['1.sql', `create table docs (tenant_id int);\n${DISABLE}`], ['2.sql', ENABLE], ['3.sql', 'create index docs_tenant on docs (tenant_id);']]);
  assert.deepEqual([diffMatrices(before, appended).gated, appended.gaps[0].id], [false, before.gaps[0].id], 'migrations appended later keep every earlier id');
});

// Nothing in an untokenizable file is read, and psql runs what is above a meta-command before reaching it.
test('a file that cannot be tokenized is one gap over the whole file, so an edit above its failing line gates', () => {
  const before = replay([['0.sql', DOCS], ['1.sql', '\\i other.sql\n']]);
  assert.match(before.gaps[0].reason, /could not tokenize: unexpected character "\\\\" \(line 1\)/);
  const above = diffMatrices(before, replay([['0.sql', DOCS], ['1.sql', 'create policy anyone_reads on docs for select using (true);\n\\i other.sql\n']]));
  assert.deepEqual([above.changes, above.gated, above.gapCounts], [[], true, { 'gap-added': 1, 'gap-removed': 1 }]);
  assert.equal(diffMatrices(before, replay([['0.sql', DOCS], ['1.sql', '\\i other.sql\ncreate policy anyone_reads on docs for select using (true);\n']])).gated, true, 'below it too');
  assert.equal(diffMatrices(before, replay([['0.sql', DOCS], ['1.sql', '-- a comment\n\\i other.sql\n']])).gated, true, 'a comment cannot be told from code there');
  // Renaming it, or appending migrations after it, keeps its id; a later gap's position covers the unreadable file.
  assert.equal(diffMatrices(before, replay([['0.sql', DOCS], ['1_renamed.sql', '\\i other.sql\n'], ['2.sql', 'create index docs_tenant on docs (tenant_id);']])).gated, false);
  const later = text => replay([['0.sql', DOCS], ['1.sql', text], ['2.sql', STANDING]]).gaps[1].id;
  assert.notEqual(later('\\i other.sql\n'), later('\\i another.sql\n'));
});

// After a non-UTF8 client_encoding the readers disagree on every later quote, so nothing after it can be read.
test('once the history sets a non-UTF8 client_encoding, every later change gates', () => {
  const enc = [['1.sql', `${DOCS}\nset client_encoding = 'SJIS';`]];
  const before = replay(enc);
  assert.equal(diffMatrices(before, replay(enc)).gated, false, 'an unchanged history stays clean');
  assert.equal(diffMatrices(before, replay([['1.sql', `-- a comment\n${DOCS}\n\nset client_encoding = 'SJIS';`]])).gated, false, 'comments and spacing are no change');
  for (const later of ["select E'ā\\'; create policy anyone_reads on docs for select using (true); --';",
    "select '; create policy evil on docs for select using (true); --';", // ASCII only: after a desync, this quote can open code
    'create index docs_tenant on docs (tenant_id);']) {
    const d = diffMatrices(before, replay([...enc, ['2.sql', later]]));
    assert.deepEqual([cellGated(d), d.gated, d.gapCounts], [[], true, { 'gap-added': 1, 'gap-removed': 1 }], later);
  }
  // A set_config whose name is not one literal could set it, so it covers the rest the same way.
  const named = [['1.sql', `${DOCS}\nselect set_config('client' || '_encoding', 'SJIS', false);`]];
  assert.equal(diffMatrices(replay(named), replay([...named, ['2.sql', 'create index docs_tenant on docs (tenant_id);']])).gated, true);
  // UTF8 keeps the normal reading: a migration appended after a standing gap keeps every id.
  const utf8 = [['1.sql', `${DOCS}\nset client_encoding = 'UTF8';\n${STANDING}`]];
  assert.equal(diffMatrices(replay(utf8), replay([...utf8, ['2.sql', 'create index docs_tenant on docs (tenant_id);']])).gated, false);
});

// RLS turned off after a standing gap used to read `changed` between two unknown cells and did not gate.
test('a cell that would now be undeclared, from any other state (unknown included), became undeclared and gates, gap or no gap', () => {
  const ENABLE = 'alter table docs enable row level security; create policy tenant_only on docs for select to authenticated using (tenant_id = 1);';
  const offAfter = standing => {
    const before = replay([['1.sql', `create table docs (tenant_id int);\n${standing}`], ['2.sql', ENABLE]]);
    const after = replay([['1.sql', `create table docs (tenant_id int);\n${standing}`], ['2.sql', 'create policy tenant_only on docs for select to authenticated using (tenant_id = 1);']]);
    return diffMatrices(before, after);
  };
  // With a standing gap: both sides unknown, the gap ids unchanged (the edit is after the gap), and every cell gated.
  const behind = offAfter(STANDING);
  assert.deepEqual([behind.gated, behind.counts, behind.gapChanges], [true, { 'became-undeclared': 8 }, []]);
  const c = behind.changes.find(x => x.role === 'authenticated' && x.action === 'SELECT');
  assert.deepEqual([c.from, c.to, c.fromComputed, c.toComputed], ['unknown', 'unknown', 'conditional', 'undeclared']);
  // The same edit without a standing gap gates as before.
  assert.deepEqual([offAfter('').gated, offAfter('').counts], [true, { 'became-undeclared': 8 }]);
  // From no computed decision (unknown) too, and on any layer, by the cells alone.
  const one = (decision, computedDecision) => buildMatrix({ application: 'a', layer: 'x', sources: [], cells: [{ role: 'r', resource: 't', action: 'read', decision, basis: 'b', citations: ['s'], ...(computedDecision ? { computedDecision } : {}) }] });
  assert.deepEqual([diffMatrices(one('unknown'), one('unknown', 'undeclared')).changes[0].kind, diffMatrices(one('unknown'), one('unknown', 'undeclared')).gated], ['became-undeclared', true]);
  // Every other move between two unknown cells keeps today's reading.
  for (const [from, to, kind, gated] of [['conditional', 'deny', 'changed', false], ['allow', 'conditional', 'changed', false], ['undeclared', 'deny', 'changed', false],
    ['undeclared', 'allow', 'widened', true], ['deny', 'conditional', 'widened', true], ['deny', undefined, 'changed', false]]) {
    const d = diffMatrices(one('unknown', from), one('unknown', to));
    assert.deepEqual([d.changes[0].kind, d.gated], [kind, gated], `${from} -> ${to}`);
  }
  // A cell that stays undeclared behind the gap, or a declared move to undeclared, reads as before.
  assert.deepEqual(diffMatrices(one('unknown', 'undeclared'), one('unknown', 'undeclared')).changes, []);
  assert.deepEqual([diffMatrices(one('unknown', 'undeclared'), one('undeclared')).changes[0].kind, diffMatrices(one('deny'), one('undeclared')).changes[0].kind], ['became-undeclared', 'became-undeclared']);
});

// Behind a standing gap a cell used to keep only its last unknown reason (source-gap), so a reason a release
// added (an owner that bypasses RLS, a policy for current_user) changed nothing in the cell.
test('a cell that stays unknown but gains a reason other than a gap became unknown and gates; a lost reason does not', () => {
  const owned = `${DOCS} alter table docs owner to authenticated; alter table docs force row level security;`;
  const cases = [['OWNER TO authenticated', DOCS, 'alter table docs owner to authenticated;', 'table-owner-bypasses-rls (no FORCE ROW LEVEL SECURITY)', 4],
    ['NO FORCE with authenticated the owner', owned, 'alter table docs no force row level security;', 'table-owner-bypasses-rls (no FORCE ROW LEVEL SECURITY)', 4],
    ['a policy TO current_user', DOCS, 'create policy mine on docs for select to current_user using (true);', 'policy-targets-current_user-or-session_user', 8]];
  for (const [label, base, change, reason, cells] of cases) for (const standing of [STANDING, '']) {
    const d = diffMatrices(rls(`${base}\n${standing}`), rls(`${base}\n${standing}\n${change}`));
    assert.deepEqual([d.gated, d.counts, d.gapChanges], [true, { 'became-unknown': cells }, []], `${label}${standing ? ', behind a standing gap' : ''}`);
    if (standing) assert.ok(d.changes.every(c => c.from === 'unknown' && c.to === 'unknown' && c.addedReasons.includes(reason)), label);
  }
  // Every reason is kept, as a sorted set; a cell that is not unknown has none.
  const both = rls(`${DOCS}\n${STANDING}\nalter table docs owner to authenticated;\ncreate policy mine on docs for select to current_user using (true);`);
  assert.deepEqual(cell(both, 'authenticated', 'public.docs', 'SELECT').unknownReasons,
    ['policy-targets-current_user-or-session_user', 'source-gap', 'table-owner-bypasses-rls (no FORCE ROW LEVEL SECURITY)']);
  assert.equal(Object.hasOwn(cell(rls(DOCS), 'authenticated', 'public.docs', 'SELECT'), 'unknownReasons'), false);
  // A cell whose reasons do not change stays clean; a reason lost (FORCE added) is listed and not gated.
  assert.deepEqual(diffMatrices(rls(`${DOCS}\n${STANDING}`), rls(`${DOCS}\n${STANDING}\ncreate index docs_tenant on docs (tenant_id);`)).changes, []);
  const lost = diffMatrices(rls(`${DOCS}\n${STANDING}\nalter table docs owner to authenticated;`), rls(`${DOCS}\n${STANDING}\nalter table docs owner to authenticated;\nalter table docs force row level security;`));
  assert.deepEqual([lost.gated, lost.counts, lost.changes[0].removedReasons], [false, { changed: 4 }, ['table-owner-bypasses-rls (no FORCE ROW LEVEL SECURITY)']]);
  // A new gap adds only source-gap to a cell already unknown: the gap is what gates (gap-added), not a cell kind.
  const gapOnly = diffMatrices(rls(`${DOCS}\nalter table docs owner to authenticated;`), rls(`${DOCS}\nalter table docs owner to authenticated;\n${STANDING}`));
  assert.deepEqual([gapOnly.gated, gapOnly.gapCounts, [...new Set(gapOnly.changes.filter(c => c.from === 'unknown').map(c => c.kind))]], [true, { 'gap-added': 1 }, ['changed']]);
  // A cell without unknownReasons (a /1 matrix, or a hand-built one) reads its basis; the same content does not gate.
  const ownedOnly = rls(`${DOCS}\nalter table docs owner to authenticated;`);
  assert.equal(diffMatrices(asSchema1(ownedOnly), ownedOnly).gated, false);
  // Open WebUI keeps both reasons when a gap hides a cell already unknown for its role.
  const owui = importOpenWebUi({ id: 'export.json', content: JSON.stringify({ users: [{ id: 'u-a', role: 'user' }, { id: 'u-p', role: 'pending' }],
    resources: [{ type: 'knowledge', id: 'kb1', user_id: 'u-a' }], grants: [{ resource_type: 'knowledge', resource_id: 'kb1', principal_type: 'group', principal_id: 'g-x', permission: 'read' }], groups: [] }) }, { application: 'owui' });
  assert.deepEqual(cell(owui, 'u-p', 'knowledge:kb1', 'read').unknownReasons, ['role pending not evaluated (only verified user and admin roles reach these routes)', 'source-gap']);
  assert.throws(() => buildMatrix({ application: 'a', layer: 'x', sources: [], cells: [{ role: 'r', resource: 't', action: 'read', decision: 'unknown', basis: 'b', citations: ['s'], unknownReasons: [] }] }), /unreadable unknownReasons/);
});
