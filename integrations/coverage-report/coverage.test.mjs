// Coverage report on a small synthetic app: two tenants, three roles, a fixture id per tenant.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CONNECTOR_METHODS, coverageReport, coverageLines, runComparability, runFindings, datastoreCoverage, validateInventory, validateContract, INVENTORY_SCHEMA, CONTRACT_SCHEMA, COMPARISON_KEYS, MARKS, COVERAGE_SCOPE } from './coverage.mjs';
import { main } from './cli.mjs';
import { contractDigest, validateTargetFile, HTTP_CHECK_METHODS } from '../../src/contracts.mjs';
import { compareRuns, runAssessment } from '../../src/runner.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { CONTROL_CUSTODY_LIMIT } from '../../src/custody.mjs';
import { createHttpLab, makeLabProfile } from '../../examples/http-lab.mjs';
import { createObservedSupportApp, bindExampleProfile } from '../../examples/observed-support-app.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const inventory = () => ({
  schema: INVENTORY_SCHEMA, applicationId: 'desk', tenants: ['t1', 't2'], roles: ['owner', 'agent', 'viewer'],
  // t2 has no viewer, so its viewer cells are unreachable.
  members: { t1: ['owner', 'agent', 'viewer'], t2: ['owner', 'agent'] },
  operations: [
    { id: 'GET /health', surface: 'api', method: 'GET', path: '/health', auth: 'none', tenantScoped: false },
    { id: 'GET /api/items', surface: 'api', method: 'GET', path: '/api/items', object: 'items', auth: 'session', tenantScoped: true },
    { id: 'GET /api/items/:id', surface: 'api', method: 'GET', path: '/api/items/:id', object: 'items', auth: 'session', tenantScoped: true },
    { id: 'POST /api/items/:id/approve', surface: 'api', method: 'POST', path: '/api/items/:id/approve', object: 'items', auth: 'session', tenantScoped: true, writes: ['items', 'audit'] },
    { id: 'PATCH /api/items/:id', surface: 'api', method: 'PATCH', path: '/api/items/:id', object: 'items', auth: 'session', tenantScoped: true, writes: ['items'] },
    { id: 'tool lookup', surface: 'assistant-tool', reach: 'model-turn', object: 'items', auth: 'session', tenantScoped: true, addressable: true },
  ],
  datastores: [{ name: 'items' }, { name: 'audit' }, { name: 'sessions' }],
  objects: { items: { 1: 't1', 2: 't2' } },
});
const contract = (extra = {}) => ({
  schema: CONTRACT_SCHEMA, applicationId: 'desk', basis: 'stated-policy', crossTenant: 'deny',
  rules: [
    { operation: 'GET /health', allow: 'anyone' },
    { operation: 'GET /api/items', allow: ['owner', 'agent', 'viewer'] },
    { operation: 'GET /api/items/:id', allow: ['owner', 'agent', 'viewer'] },
    { operation: 'POST /api/items/:id/approve', allow: ['owner', 'agent'], conditional: ['agent'] },
    { operation: 'PATCH /api/items/:id', allow: ['owner'] },
    { operation: 'tool lookup', allow: ['owner', 'agent', 'viewer'] },
  ], ...extra,
});
// An inventory and contract with more operations: extra operations and their rules appended.
const withOps = (ops, rules) => { const inv = inventory(), con = contract(); inv.operations.push(...ops); con.rules.push(...rules); return { inv, con }; };
const check = (id, actorId, method, path, severity = 'high', more = {}) => ({ id, title: id, category: 'authorization', severity, actorId, method, path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...more });
const target = (extra = {}) => ({
  id: 'desk-local', applicationId: 'desk',
  actors: {
    o1: { principalId: 'o1', credentialEnv: 'SCOPEHAVEN_TARGET_O1', role: 'owner', tenantId: 't1' },
    a1: { principalId: 'a1', credentialEnv: 'SCOPEHAVEN_TARGET_A1', role: 'agent', tenantId: 't1' },
    a2: { principalId: 'a2', credentialEnv: 'SCOPEHAVEN_TARGET_A2', role: 'agent', tenantId: 't2' },
    anon: { principalId: 'anonymous' },
  },
  requiredControlIds: ['C-A1-READ'],
  checks: [
    check('C-A1-READ', 'a1', 'GET', '/api/items/1', 'control'),
    check('X-A2-READ', 'a2', 'GET', '/api/items/1'),
    check('X-ANON-READ', 'anon', 'GET', '/api/items/1'),
    check('L-A2-LIST', 'a2', 'GET', '/api/items?q=widget'),
    check('B-A1-APPROVE', 'a1', 'POST', '/api/items/1/approve', 'medium'),
  ], ...extra,
});
const report = (over = {}) => coverageReport({ inventory: inventory(), contract: contract(), target: target(), ...over });
const cell = (r, role, tenant, operation, scope) => r.cells.find(c => c.role === role && c.tenant === tenant && c.operation === operation && c.scope === scope);
const markOf = (r, ...key) => { const c = cell(r, ...key); return [c.mark, c.reason ?? null]; };
const keysNamed = (value, name, out = []) => { if (Array.isArray(value)) value.forEach(v => keysNamed(v, name, out)); else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) { if (k === name) out.push(k); keysNamed(v, name, out); } return out; };

test('every suite check lands in exactly one cell: the drafted count equals the suite check count, and no row carries a severity', () => {
  const r = report();
  assert.deepEqual(r.reconciliation, { suiteChecks: 5, draftedChecks: 5, declaredNotApplicable: [], outsideInventory: 0, duplicates: [], missingFromSuite: [], equal: true });
  assert.equal(r.scope, COVERAGE_SCOPE);
  assert.match(coverageLines(r)[1], /^Scope: computed only from the given inventory, contract, profile .*sends no request and observes nothing/);
  assert.deepEqual(keysNamed(r, 'severity'), [], 'severities never reach a coverage row');
  // Own and cross-tenant objects are told apart by the fixture's owner, a listing sits on the own cell.
  assert.deepEqual(cell(r, 'agent', 't1', 'GET /api/items/:id', 'own').drafts, [{ checkId: 'C-A1-READ', side: 'allowed' }]);
  assert.deepEqual(cell(r, 'agent', 't2', 'GET /api/items/:id', 'cross').drafts, [{ checkId: 'X-A2-READ', side: 'forbidden' }]);
  assert.deepEqual(cell(r, 'anonymous', null, 'GET /api/items/:id', 'none').drafts, [{ checkId: 'X-ANON-READ', side: 'forbidden' }]);
  assert.deepEqual(cell(r, 'agent', 't2', 'GET /api/items', 'own').drafts, [{ checkId: 'L-A2-LIST', side: 'forbidden' }]);
  // A plain listing has no cross-tenant cell: a caller cannot point it at another tenant's object.
  assert.equal(cell(r, 'agent', 't1', 'GET /api/items', 'cross'), undefined);
});

test('a check declared not applicable is accounted for but drafts nothing and covers nothing', () => {
  const t = target();
  t.checks.push(check('NA-A1', 'a1', 'GET', '/api/items/2', 'high', { applicability: { applies: false, reason: 'no cross-tenant data in this build' } }));
  const r = report({ target: t });
  assert.deepEqual([r.reconciliation.draftedChecks, r.reconciliation.declaredNotApplicable, r.reconciliation.equal], [5, ['NA-A1'], true]);
  assert.equal(cell(r, 'agent', 't1', 'GET /api/items/:id', 'cross').drafts.length, 0);
  assert.equal(r.forbiddenSide.covered, report().forbiddenSide.covered);
  assert.match(coverageLines(r).join('\n'), /5 drafted and 1 declared not applicable of 6 suite checks \(equal\)/);
});

test('a check the inventory cannot place is listed with its reason, and the counts then disagree', () => {
  const t = target();
  t.actors.nobody = { principalId: 'n', credentialEnv: 'SCOPEHAVEN_TARGET_N' };
  t.actors.far = { principalId: 'f', credentialEnv: 'SCOPEHAVEN_TARGET_F', role: 'agent', tenantId: 't9' };
  t.checks.push(check('Z-UNKNOWN-PATH', 'a1', 'GET', '/api/other'), check('Z-UNKNOWN-OBJECT', 'a1', 'GET', '/api/items/99'), check('Z-NO-ROLE', 'nobody', 'GET', '/api/items/1'),
    check('Z-GHOST-ACTOR', 'ghost', 'GET', '/api/items/1'), check('Z-FAR', 'far', 'GET', '/api/items/1'));
  const r = report({ target: t });
  assert.equal(r.reconciliation.equal, false);
  assert.deepEqual(r.outsideInventory, [{ checkId: 'Z-UNKNOWN-PATH', reason: 'operation-not-in-inventory' }, { checkId: 'Z-UNKNOWN-OBJECT', reason: 'object-owner-unknown' }, { checkId: 'Z-NO-ROLE', reason: 'actor-role-not-in-inventory' },
    { checkId: 'Z-GHOST-ACTOR', reason: 'unknown-actor' }, { checkId: 'Z-FAR', reason: 'actor-tenant-not-in-inventory' }]);
  assert.match(coverageLines(r).join('\n'), /outside the inventory: Z-UNKNOWN-PATH \(operation-not-in-inventory\), .*Z-FAR \(actor-tenant-not-in-inventory\)/);
  // The exported suite is the reference: an id it has that the profile lacks, or one listed twice, also disagrees.
  const ids = target().checks.map(c => c.id);
  assert.deepEqual(report({ suiteCheckIds: [...ids, 'GHOST'] }).outsideInventory, [{ checkId: 'GHOST', reason: 'not-in-profile' }]);
  // Both directions: a suite that leaves out a profile check never reconciles as equal (an edited export).
  const short = report({ suiteCheckIds: ids.slice(1) });
  assert.deepEqual([short.reconciliation.missingFromSuite, short.reconciliation.equal], [['C-A1-READ'], false]);
  assert.match(coverageLines(short).join('\n'), /4 drafted of 4 suite checks; profile checks the suite leaves out: C-A1-READ\./);
  const dup = report({ suiteCheckIds: [...ids, ids[0]] });
  assert.deepEqual([dup.reconciliation.draftedChecks, dup.reconciliation.duplicates, dup.reconciliation.equal], [5, ['C-A1-READ'], false]);
  assert.match(coverageLines(dup).join('\n'), /5 drafted of 6 suite checks; listed more than once: C-A1-READ\./);
  // Literal characters in a template are matched literally.
  const { inv, con } = withOps([{ id: 'GET /export.json', surface: 'api', method: 'GET', path: '/export.json', auth: 'session', tenantScoped: false }], [{ operation: 'GET /export.json', allow: ['owner'] }]);
  const e = target(); e.checks.push(check('E-DOT', 'o1', 'GET', '/exportXjson'));
  assert.deepEqual(coverageReport({ inventory: inv, contract: con, target: e }).outsideInventory, [{ checkId: 'E-DOT', reason: 'operation-not-in-inventory' }]);
});

test('a request lands on the most specific operation of its method: literal before parameter, any listed path, a trailing slash', () => {
  const { inv, con } = withOps([
    { id: 'GET /api/items/mine', surface: 'api', method: 'GET', path: '/api/items/mine', object: 'items', auth: 'session', tenantScoped: true },
    { id: 'POST /api/items/:id', surface: 'api', method: 'POST', path: '/api/items/:id', object: 'items', auth: 'session', tenantScoped: true },
    { id: 'GET pages', surface: 'web', method: 'GET', paths: ['/', '/login'], auth: 'none', tenantScoped: false },
  ], [{ operation: 'GET /api/items/mine', allow: ['owner', 'agent', 'viewer'] }, { operation: 'POST /api/items/:id', allow: ['owner'] }, { operation: 'GET pages', allow: 'anyone' }]);
  const t = target();
  t.checks.push(check('M-MINE', 'a1', 'GET', '/api/items/mine'), check('M-POST', 'a1', 'POST', '/api/items/1'), check('M-LOGIN', 'a1', 'GET', '/login'), check('M-ROOT', 'anon', 'GET', '/'), check('M-SLASH', 'o1', 'GET', '/api/items/1/'));
  const r = coverageReport({ inventory: inv, contract: con, target: t });
  assert.equal(r.reconciliation.equal, true);
  assert.deepEqual(cell(r, 'agent', 't1', 'GET /api/items/mine', 'own').drafts.map(d => d.checkId), ['M-MINE']);
  assert.deepEqual(cell(r, 'agent', 't1', 'POST /api/items/:id', 'own').drafts.map(d => d.checkId), ['M-POST']);
  assert.equal(cell(r, 'agent', 't1', 'POST /api/items/:id', 'own').stated, 'deny');
  // A session-less operation anyone may call has an anonymous and a signed-in cell, not one per role and tenant.
  assert.deepEqual(r.cells.filter(c => c.operation === 'GET pages').map(c => [c.role, c.tenant, c.stated]), [['anonymous', null, 'allow'], ['signed-in', null, 'allow']]);
  assert.deepEqual(cell(r, 'signed-in', null, 'GET pages', 'none').drafts.map(d => d.checkId), ['M-LOGIN']);
  assert.deepEqual(cell(r, 'anonymous', null, 'GET pages', 'none').drafts.map(d => d.checkId), ['M-ROOT']);
  assert.deepEqual(cell(r, 'owner', 't1', 'GET /api/items/:id', 'own').drafts.map(d => d.checkId), ['M-SLASH']);
  // Two operations whose templates match one request equally well are an ambiguity, not a placement.
  const twin = withOps([{ id: 'GET /api/items/:key', surface: 'api', method: 'GET', path: '/api/items/:key', object: 'items', auth: 'session', tenantScoped: true }], [{ operation: 'GET /api/items/:key', allow: ['owner'] }]);
  assert.deepEqual(coverageReport({ inventory: twin.inv, contract: twin.con, target: target() }).outsideInventory.map(o => o.reason), ['operation-ambiguous', 'operation-ambiguous', 'operation-ambiguous']);
});

test('object references in the path, query or body decide own or cross; a named idParam picks the object id', () => {
  const { inv, con } = withOps([
    { id: 'GET /api/search', surface: 'api', method: 'GET', path: '/api/search', object: 'items', auth: 'session', tenantScoped: true, refs: [{ in: 'query', field: 'item', object: 'items' }] },
    { id: 'POST /api/items/:id/link', surface: 'api', method: 'POST', path: '/api/items/:id/link', object: 'items', auth: 'session', tenantScoped: true, refs: [{ in: 'body', field: 'other', object: 'items' }] },
    { id: 'GET /api/orgs/:org/items/:id', surface: 'api', method: 'GET', path: '/api/orgs/:org/items/:id', object: 'items', idParam: 'id', auth: 'session', tenantScoped: true },
  ], ['GET /api/search', 'POST /api/items/:id/link', 'GET /api/orgs/:org/items/:id'].map(operation => ({ operation, allow: ['owner', 'agent', 'viewer'] })));
  const t = target();
  t.checks.push(check('R-Q-CROSS', 'a1', 'GET', '/api/search?item=2'), check('R-Q-OWN', 'a1', 'GET', '/api/search?item=1'), check('R-Q-NONE', 'a1', 'GET', '/api/search?q=x'),
    check('R-B-CROSS', 'a1', 'POST', '/api/items/1/link', 'high', { body: { other: 2 } }), check('R-B-OWN', 'a1', 'POST', '/api/items/1/link', 'high', { body: { other: 1 } }),
    check('R-P-NAMED', 'a1', 'GET', '/api/orgs/t2/items/1'), check('R-Q-UNKNOWN', 'a1', 'GET', '/api/search?item=77'));
  const r = coverageReport({ inventory: inv, contract: con, target: t });
  assert.deepEqual(cell(r, 'agent', 't1', 'GET /api/search', 'cross').drafts.map(d => d.checkId), ['R-Q-CROSS']);
  assert.deepEqual(cell(r, 'agent', 't1', 'GET /api/search', 'own').drafts.map(d => d.checkId), ['R-Q-OWN', 'R-Q-NONE']);
  assert.deepEqual(cell(r, 'agent', 't1', 'POST /api/items/:id/link', 'cross').drafts.map(d => d.checkId), ['R-B-CROSS']);
  assert.deepEqual(cell(r, 'agent', 't1', 'POST /api/items/:id/link', 'own').drafts.map(d => d.checkId), ['R-B-OWN']);
  // idParam: the item id decides the cell, not the first parameter.
  assert.deepEqual(cell(r, 'agent', 't1', 'GET /api/orgs/:org/items/:id', 'own').drafts.map(d => d.checkId), ['R-P-NAMED']);
  assert.deepEqual(r.outsideInventory, [{ checkId: 'R-Q-UNKNOWN', reason: 'object-owner-unknown' }]);
  assert.equal(cell(r, 'agent', 't1', 'GET /api/search', 'cross').stated, 'deny');
});

test('ids and names that are JavaScript built-ins resolve to nothing: object-owner-unknown, never a covered cross-tenant cell', () => {
  // An actor id that is a built-in name is an unknown actor, never the object prototype read as an anonymous actor.
  assert.deepEqual(report({ target: target({ checks: [check('B-PROTO-ACTOR', '__proto__', 'GET', '/api/items/1'), check('B-CTOR-ACTOR', 'constructor', 'GET', '/api/items/1')] }) }).outsideInventory,
    [{ checkId: 'B-PROTO-ACTOR', reason: 'unknown-actor' }, { checkId: 'B-CTOR-ACTOR', reason: 'unknown-actor' }]);
  const builtins = ['constructor', '__proto__', 'toString', 'hasOwnProperty'];
  const t = target({ checks: builtins.map(id => check(`B-${id}`, 'a2', 'GET', `/api/items/${id}`)) });
  const r = report({ target: t });
  assert.deepEqual(r.outsideInventory.map(o => o.reason), builtins.map(() => 'object-owner-unknown'));
  assert.deepEqual([r.reconciliation.equal, r.forbiddenSide.covered], [false, 0]);
  // An object type named like a built-in, and a tenant named like one, resolve to nothing too.
  const { inv, con } = withOps([{ id: 'GET /api/odd/:id', surface: 'api', method: 'GET', path: '/api/odd/:id', object: 'constructor', auth: 'session', tenantScoped: true }], [{ operation: 'GET /api/odd/:id', allow: ['agent'] }]);
  assert.deepEqual(coverageReport({ inventory: inv, contract: con, target: target({ checks: [check('B-ODD', 'a2', 'GET', '/api/odd/1')] }) }).outsideInventory, [{ checkId: 'B-ODD', reason: 'object-owner-unknown' }]);
  // A body reference whose field name is a built-in reads only the body's own field.
  const ref = withOps([{ id: 'POST /api/link', surface: 'api', method: 'POST', path: '/api/link', object: 'items', auth: 'session', tenantScoped: true, refs: [{ in: 'body', field: 'constructor', object: 'items' }] }], [{ operation: 'POST /api/link', allow: ['agent'] }]);
  const linked = coverageReport({ inventory: ref.inv, contract: ref.con, target: target({ checks: [check('B-LINK', 'a2', 'POST', '/api/link', 'high', { body: { text: 'x' } })] }) });
  assert.deepEqual([linked.reconciliation.equal, cell(linked, 'agent', 't2', 'POST /api/link', 'own').drafts.map(d => d.checkId)], [true, ['B-LINK']]);
  const odd = coverageReport({ inventory: { ...inventory(), tenants: ['t1', 't2', 'constructor'] }, contract: contract(), target: target() });
  assert.deepEqual(markOf(odd, 'owner', 'constructor', 'GET /api/items/:id', 'own'), ['unreachable', 'no-user-with-this-role-in-this-tenant']);
});

test('marks: drafted, then unreachable, then not judgeable, then needs an actor, then stated-only or unstated', () => {
  // The connector-method rule, shown with a connector that sends GET and POST only (the default is the
  // HTTP connector's own set, which sends PATCH).
  const r = report({ connectorMethods: ['GET', 'POST'] });
  assert.deepEqual(markOf(r, 'viewer', 't2', 'GET /api/items/:id', 'own'), ['unreachable', 'no-user-with-this-role-in-this-tenant']);
  assert.deepEqual(markOf(r, 'viewer', 't2', 'tool lookup', 'cross'), ['unreachable', 'no-user-with-this-role-in-this-tenant'], 'unreachable before model-turn');
  assert.deepEqual(markOf(r, 'owner', 't1', 'PATCH /api/items/:id', 'own'), ['not-judgeable', 'connector-sends-get-and-post-only']);
  assert.deepEqual(markOf(r, 'viewer', 't1', 'PATCH /api/items/:id', 'own'), ['not-judgeable', 'connector-sends-get-and-post-only'], 'the connector method before a missing actor');
  assert.deepEqual(markOf(r, 'agent', 't1', 'tool lookup', 'cross'), ['not-judgeable', 'reached-only-through-a-model-turn']);
  assert.deepEqual(markOf(r, 'viewer', 't1', 'GET /api/items/:id', 'own'), ['needs-actor', 'no-actor-for-this-role-and-tenant']);
  assert.deepEqual(markOf(r, 'owner', 't1', 'GET /api/items/:id', 'own'), ['stated-only', null]);
  // The anonymous caller is an actor of this profile: its undrafted cells are judgeable.
  assert.deepEqual(markOf(r, 'anonymous', null, 'GET /health', 'none'), ['stated-only', null]);
  assert.deepEqual(markOf(r, 'anonymous', null, 'GET /api/items', 'none'), ['stated-only', null]);
  // 61 cells: health 2 (anonymous, signed-in), the listing 7, each of the four item operations and the tool 13.
  assert.deepEqual(r.marks, { drafted: 5, 'stated-only': 15, unstated: 0, 'needs-actor': 10, 'not-judgeable': 22, unreachable: 9 });
  assert.deepEqual(r.reasons, { 'no-user-with-this-role-in-this-tenant': 9, 'connector-sends-get-and-post-only': 11, 'reached-only-through-a-model-turn': 11, 'no-actor-for-this-role-and-tenant': 10 });
  // A drafted cell is drafted even where the inventory lists no such member (the check's actor exists).
  const t = target(); t.actors.v2 = { principalId: 'v2', credentialEnv: 'SCOPEHAVEN_TARGET_V2', role: 'viewer', tenantId: 't2' }; t.checks.push(check('V2-READ', 'v2', 'GET', '/api/items/2'));
  assert.equal(cell(report({ target: t }), 'viewer', 't2', 'GET /api/items/:id', 'own').mark, 'drafted');
  // A method the connector gains is judgeable again.
  assert.equal(cell(report({ connectorMethods: ['GET', 'POST', 'PATCH'] }), 'owner', 't1', 'PATCH /api/items/:id', 'own').mark, 'stated-only');
  // An inventory without members marks nothing unreachable.
  const open = inventory(); delete open.members;
  assert.equal(coverageReport({ inventory: open, contract: contract(), target: target() }).marks.unreachable, 0);
  // An operation with no rule is unstated: the contract does not cover it.
  const c = contract(); c.rules = c.rules.filter(rule => rule.operation !== 'GET /api/items');
  const u = report({ contract: c });
  assert.equal(cell(u, 'owner', 't1', 'GET /api/items', 'own').mark, 'unstated');
  assert.deepEqual([u.unstatedOperations, cell(u, 'agent', 't2', 'GET /api/items', 'own').stated, u.draftsOnUnstatedCells], [['GET /api/items'], null, ['L-A2-LIST']]);
  // With one tenant there is no other tenant's object to name: the cross cells are unreachable, in neither denominator.
  const solo = { ...inventory(), tenants: ['t1'], members: { t1: ['owner', 'agent', 'viewer'] }, objects: { items: { 1: 't1' } } };
  const s = coverageReport({ inventory: solo, contract: contract(), target: target({ actors: { a1: target().actors.a1 }, checks: [check('C-A1-READ', 'a1', 'GET', '/api/items/1', 'control')] }) });
  assert.deepEqual(markOf(s, 'owner', 't1', 'GET /api/items/:id', 'cross'), ['unreachable', 'no-other-tenant-object']);
  assert.equal(s.forbiddenSide.cells, s.cells.filter(x => x.mark !== 'unreachable' && x.stated === 'deny').length);
  assert.ok(!s.cells.some(x => x.scope === 'cross' && x.mark !== 'unreachable'));
});

test('stated decisions: cross-tenant is denied, a role outside the rule is denied, a conditional role reads conditional, anonymous only where anyone may', () => {
  const r = report();
  assert.equal(cell(r, 'owner', 't1', 'GET /api/items/:id', 'cross').stated, 'deny');
  assert.equal(cell(r, 'viewer', 't1', 'POST /api/items/:id/approve', 'own').stated, 'deny');
  assert.equal(cell(r, 'agent', 't1', 'POST /api/items/:id/approve', 'own').stated, 'conditional');
  assert.equal(cell(r, 'owner', 't1', 'POST /api/items/:id/approve', 'own').stated, 'allow');
  assert.equal(cell(r, 'anonymous', null, 'GET /health', 'none').stated, 'allow');
  assert.equal(cell(r, 'signed-in', null, 'GET /health', 'none').stated, 'allow');
  assert.equal(cell(r, 'anonymous', null, 'GET /api/items', 'none').stated, 'deny');
});

test('both sides compute, broken down by role, surface and tenant; forbidden checks on permitted cells are counted apart', () => {
  const r = report();
  const sideCells = test => r.cells.filter(c => c.mark !== 'unreachable' && test(c));
  const permitted = c => ['allow', 'conditional'].includes(c.stated), denied = c => c.stated === 'deny';
  // Allowed side: reachable allow and conditional cells; one has its twin.
  assert.equal(r.allowedSide.covered, 1);
  assert.equal(r.allowedSide.cells, sideCells(permitted).length);
  assert.equal(r.allowedSide.notJudgeable, sideCells(c => permitted(c) && c.mark === 'not-judgeable').length);
  assert.equal(r.allowedSide.needsActor, sideCells(c => permitted(c) && c.mark === 'needs-actor').length);
  assert.deepEqual(r.allowedSide.byRole.agent, { cells: sideCells(c => c.role === 'agent' && permitted(c)).length, covered: 1, notJudgeable: sideCells(c => c.role === 'agent' && permitted(c) && c.mark === 'not-judgeable').length, needsActor: 0, unreachable: 0 });
  // A role whose cells are all unreachable still has its breakdown row, with its unreachable count.
  assert.deepEqual(r.allowedSide.byRole.viewer.unreachable, r.cells.filter(c => c.role === 'viewer' && permitted(c) && c.mark === 'unreachable').length);
  assert.equal(r.allowedSide.byTenant.t1.covered, 1);
  assert.equal(r.allowedSide.bySurface['assistant-tool'].covered, 0);
  // Forbidden side: the cross-tenant read and the anonymous read; unreachable cells are in neither denominator.
  assert.equal(r.forbiddenSide.covered, 2);
  assert.equal(r.forbiddenSide.cells, sideCells(denied).length);
  assert.equal(r.forbiddenSide.notJudgeable, sideCells(c => denied(c) && c.mark === 'not-judgeable').length);
  assert.equal(r.forbiddenSide.byTenant.t2.cells, sideCells(c => denied(c) && c.tenant === 't2').length);
  assert.deepEqual([r.forbiddenSide.byTenant.t2.covered, r.forbiddenSide.byTenant.null.covered, r.forbiddenSide.byRole.anonymous.covered], [1, 1, 1]);
  assert.ok(r.cells.some(c => c.mark === 'unreachable'));
  // The plan's role-action-surface count folds tenants and scopes: agent GET /api/items/:id api is covered on the allowed side.
  assert.equal(r.allowedSide.roleActionSurface.covered, 1);
  assert.equal(r.allowedSide.roleActionSurface.cells, new Set(sideCells(permitted).map(c => JSON.stringify([c.role, c.operation, c.surface]))).size);
  // A role with no member anywhere is unreachable everywhere: none of its (role, operation, surface) triples is counted.
  const noViewer = coverageReport({ inventory: { ...inventory(), members: { t1: ['owner', 'agent'], t2: ['owner', 'agent'] } }, contract: contract(), target: target() });
  for (const s of ['allowedSide', 'forbiddenSide']) {
    const live = noViewer.cells.filter(c => c.mark !== 'unreachable' && (s === 'allowedSide' ? permitted(c) : denied(c)));
    assert.equal(noViewer[s].roleActionSurface.cells, new Set(live.map(c => JSON.stringify([c.role, c.operation, c.surface]))).size, s);
  }
  // The listing leak check and the boundary on a conditional approve are forbidden checks on permitted cells; an allowed
  // control sharing a cell with a forbidden check stays out of that list.
  const t = target(); t.checks.push(check('F-A1-READ', 'a1', 'GET', '/api/items/1?fields=secret'));
  assert.deepEqual(report({ target: t }).forbiddenChecksOnPermittedCells.sort(), ['B-A1-APPROVE', 'F-A1-READ', 'L-A2-LIST']);
  // One rule for what a control is: severity "control" in the profile, required or not. A control on a stated-deny
  // cell covers nothing there and is listed as a disagreement.
  const t2 = target(); t2.checks.push(check('C-A2-XREAD', 'a2', 'GET', '/api/items/1', 'control'));
  const odd = report({ target: t2 });
  assert.deepEqual([odd.forbiddenSide.covered, odd.allowedControlsOnDeniedCells], [2, ['C-A2-XREAD']]);
  // Alone on a deny cell (no forbidden check there), a control still covers nothing.
  const t4 = target(); t4.checks.push(check('C-A1-XREAD', 'a1', 'GET', '/api/items/2', 'control'));
  assert.deepEqual([report({ target: t4 }).forbiddenSide.covered, report({ target: t4 }).allowedControlsOnDeniedCells], [2, ['C-A1-XREAD']]);
  assert.deepEqual(cell(odd, 'agent', 't2', 'GET /api/items/:id', 'cross').drafts.map(d => [d.checkId, d.side]), [['X-A2-READ', 'forbidden'], ['C-A2-XREAD', 'allowed']]);
  assert.match(coverageLines(odd).join('\n'), /Allowed-use controls on stated-deny cells \(the contract and the profile disagree\): C-A2-XREAD\./);
  // A tenant with no member at all keeps its by-tenant row: every cell unreachable, none dropped.
  const t3 = coverageReport({ inventory: { ...inventory(), tenants: ['t1', 't2', 't3'] }, contract: contract(), target: target() });
  assert.deepEqual([t3.forbiddenSide.byTenant.t3.cells, t3.forbiddenSide.byTenant.t3.unreachable > 0], [0, true]);
  assert.match(coverageLines(t3).join('\n'), /by tenant: .*t3 0\/0 \(\d+ unreachable\)/);
});

test('a check sent through a model turn is listed apart, and names the tool cells it could reach; a listing tool has no cross cell', () => {
  const { inv, con } = withOps([
    { id: 'POST /api/chat', surface: 'assistant-api', method: 'POST', path: '/api/chat', auth: 'session', tenantScoped: true, refs: [{ in: 'body', field: 'item_id', object: 'items' }] },
    { id: 'tool list', surface: 'assistant-tool', reach: 'model-turn', object: 'items', auth: 'session', tenantScoped: true, addressable: false, via: 'POST /api/chat' },
  ], [{ operation: 'POST /api/chat', allow: ['owner', 'agent', 'viewer'] }, { operation: 'tool list', allow: ['owner', 'agent', 'viewer'] }]);
  inv.operations.find(op => op.id === 'tool lookup').via = 'POST /api/chat';
  const t = target();
  t.checks.push(check('AST-A1', 'a1', 'POST', '/api/chat', 'high', { body: { message: 'show me item 2' } }), check('AST-A1-CTX', 'a1', 'POST', '/api/chat', 'high', { body: { message: 'summarise', item_id: 2 } }));
  const r = coverageReport({ inventory: inv, contract: con, target: t });
  assert.deepEqual(r.modelTurnChecks.map(m => [m.checkId, m.scope, m.tools]), [['AST-A1', 'own', ['tool lookup', 'tool list']], ['AST-A1-CTX', 'cross', ['tool lookup', 'tool list']]]);
  assert.ok(!r.forbiddenChecksOnPermittedCells.includes('AST-A1'), 'a model-turn probe is not a forbidden check on the chat cell');
  // The context id in the body is the endpoint's own boundary: it covers the chat's cross cell.
  assert.equal(cell(r, 'agent', 't1', 'POST /api/chat', 'cross').mark, 'drafted');
  for (const scope of ['own', 'cross']) assert.deepEqual([cell(r, 'agent', 't1', 'tool lookup', scope).mark, cell(r, 'agent', 't1', 'tool lookup', scope).probedThroughModelTurn], ['not-judgeable', ['AST-A1', 'AST-A1-CTX']]);
  assert.equal(cell(r, 'agent', 't2', 'tool lookup', 'own').probedThroughModelTurn, undefined);
  assert.equal(cell(r, 'agent', 't1', 'tool list', 'cross'), undefined);
  assert.match(coverageLines(r).join('\n'), /Checks sent through a model turn .*: AST-A1, AST-A1-CTX\./);
});

test('per-datastore observer coverage: table-mapped observers count, application-record observers are listed apart, writes give the drafted checks per store', () => {
  const observers = [{ id: 'db', type: 'sqlite-snapshot', path: '/x.db', tables: [{ table: 'items', key: 'id' }] }, { id: 'log', type: 'sqlite-audit', path: '/x.db', audit: { table: 'audit' } }, { id: 'tr', type: 'otel' }, { id: 'act', type: 'http-audit' }];
  const d = datastoreCoverage(inventory(), { observers });
  assert.deepEqual([d.total, d.observed], [3, 2]);
  assert.deepEqual(d.rows.map(r => [r.name, r.observers.map(o => o.mode)]), [['items', ['snapshot']], ['audit', ['audit-table']], ['sessions', []]]);
  assert.deepEqual(d.otherObservers, [{ observer: 'tr', type: 'otel' }, { observer: 'act', type: 'http-audit' }]);
  for (const type of ['pg-snapshot', 'mysql-snapshot']) assert.equal(datastoreCoverage(inventory(), { observers: [{ id: 'p', type, tables: [{ table: 'sessions', key: 'id' }] }] }).observed, 1, type);
  assert.deepEqual([datastoreCoverage(inventory(), {}).observed, datastoreCoverage(inventory(), {}).total], [0, 3], 'a profile without observers computes 0 of 3, not nothing');
  // The approve check writes items and audit; with no observer at all, it writes only unobserved stores.
  const r = report();
  assert.deepEqual(r.datastores.rows.map(row => [row.name, row.writtenBy, row.draftedChecksOnWriters]), [['items', ['POST /api/items/:id/approve', 'PATCH /api/items/:id'], 1], ['audit', ['POST /api/items/:id/approve'], 1], ['sessions', [], 0]]);
  assert.equal(r.datastores.draftedChecksWritingOnlyUnobservedStores, 1);
  assert.equal(report({ target: target({ observers }) }).datastores.draftedChecksWritingOnlyUnobservedStores, 0);
  const lines = coverageLines(report({ target: target({ observers: [observers[3]] }) })).join('\n');
  assert.match(lines, /Datastores with a table-mapped observer: 0 of 3: items \(none\), audit \(none\), sessions \(none\)\./);
  assert.match(lines, /Observers of the application's own record, not mapped to a datastore here: act \(http-audit\)\./);
  const bare = inventory(); for (const op of bare.operations) delete op.writes;
  assert.match(coverageLines(coverageReport({ inventory: bare, contract: contract(), target: target() })).join('\n'), /Which operations write which datastore is not declared in this inventory\./);
});

test('intent read from the application carries the declared-intent warning: a declaration-based contract and policy-imported checks', () => {
  const declared = report({ contract: contract({ basis: 'app-declaration' }) });
  assert.match(declared.warning, /own declarations/);
  assert.match(coverageLines(declared).join('\n'), /^Warning: .*own declarations/m);
  assert.equal(report().warning, undefined);
  const t = target(); t.checks.push({ ...check('PI-1', 'a1', 'GET', '/api/items/2'), category: 'Declared policy' });
  const imported = report({ target: t });
  assert.deepEqual(imported.policyImport.checks, ['PI-1']);
  assert.match(coverageLines(imported).join('\n'), /^Warning: 1 check came from policy import \(PI-1\)\..*undeclared never becomes deny/m);
  assert.equal(report().policyImport, undefined);
});

test('malformed inventories and contracts are refused', () => {
  const op = patch => ({ ...inventory(), operations: [{ ...inventory().operations[2], ...patch }] });
  const refused = [
    [{ ...inventory(), schema: 'other/1' }, /schema/], [{ ...inventory(), roles: ['owner', 'anonymous'] }, /caller classes/], [{ ...inventory(), roles: ['signed-in'] }, /caller classes/],
    [{ ...inventory(), operations: [...inventory().operations, inventory().operations[0]] }, /unique/], [{ ...inventory(), objects: { items: { 1: 't9' } } }, /undeclared tenant/],
    [{ ...inventory(), members: { t9: ['owner'] } }, /undeclared tenant t9/], [op({ surface: undefined }), /surface/], [op({ tenantScoped: undefined }), /tenantScoped/], [op({ path: 'api/items' }), /starts with/],
    [op({ method: 'get' }), /upper case/], [op({ path: '/api/items/{id}' }), /:name/], [op({ path: '/api/orgs/:org/items/:id' }), /idParam/], [op({ idParam: 'nope' }), /idParam/],
    [op({ object: undefined }), /names the object/], [op({ refs: [{ in: 'body', field: 'x', object: 'items' }] }), /body reference/], [op({ refs: [{ in: 'header', field: 'x', object: 'items' }] }), /refs/],
    [op({ writes: ['nowhere'] }), /writes/], [op({ addressable: true }), /model-turn/],
    [{ ...inventory(), operations: [{ ...inventory().operations[5], addressable: undefined }] }, /addressable/], [{ ...inventory(), operations: [{ ...inventory().operations[5], via: 'POST /nope' }] }, /via/],
    [{ ...inventory(), datastores: [{ name: 'items' }, { name: 'items' }] }, /distinct/],
  ];
  for (const [inv, pattern] of refused) assert.throws(() => validateInventory(inv), pattern, String(pattern));
  assert.throws(() => validateContract({ ...contract(), schema: 'other/1' }, inventory()), /schema/);
  assert.throws(() => validateContract({ ...contract(), basis: 'app-declarations' }, inventory()), /basis/);
  assert.throws(() => validateContract({ ...contract(), rules: [...contract().rules, { operation: 'PATCH /api/items/:id', allow: ['owner'] }] }, inventory()), /once/);
  assert.throws(() => validateContract({ ...contract(), rules: [{ operation: 'GET /nope', allow: 'anyone' }] }, inventory()), /inventory operation/);
  assert.throws(() => validateContract({ ...contract(), rules: [{ operation: 'GET /health', allow: ['root'] }] }, inventory()), /inventory roles/);
  assert.throws(() => validateContract({ ...contract(), rules: [{ operation: 'GET /api/items', allow: ['owner'], conditional: ['agent'] }] }, inventory()), /conditional/);
  assert.throws(() => validateContract({ ...contract(), crossTenant: 'allow' }, inventory()), /crossTenant/);
  assert.throws(() => validateContract({ ...contract(), applicationId: 'other' }, inventory()), /same application/);
});

// A full profile, as the CLI sees it.
const profile = () => ({ ...target(), name: 'Desk', origin: 'http://127.0.0.1:4999', buildLabel: 'b1', contextId: 'desk-1' });
// The owned HTTP lab (examples/http-lab.mjs): one tenant's member, a foreign-record endpoint it must be refused, an echo POST.
const labInventory = () => ({ schema: INVENTORY_SCHEMA, applicationId: 'owned-http-lab', tenants: ['aster', 'borealis'], roles: ['member'], members: { aster: ['member'], borealis: ['member'] },
  operations: [
    { id: 'GET /me', surface: 'api', method: 'GET', path: '/me', auth: 'session', tenantScoped: false },
    { id: 'GET /records/own', surface: 'api', method: 'GET', path: '/records/own', auth: 'session', tenantScoped: true },
    { id: 'GET /records/foreign', surface: 'api', method: 'GET', path: '/records/foreign', auth: 'session', tenantScoped: true },
    { id: 'POST /echo', surface: 'api', method: 'POST', path: '/echo', auth: 'session', tenantScoped: false },
  ] });
const labContract = () => ({ schema: CONTRACT_SCHEMA, applicationId: 'owned-http-lab', basis: 'stated-policy', crossTenant: 'deny',
  rules: [{ operation: 'GET /me', allow: ['member'] }, { operation: 'GET /records/own', allow: ['member'] }, { operation: 'GET /records/foreign', allow: [] }, { operation: 'POST /echo', allow: ['member'] }] });
async function labRun(t, build, mutate = p => p) {
  const lab = await createHttpLab({ build }); t.after(() => lab.close());
  const target = mutate(makeLabProfile(lab.origin, `lab-${build}`));
  return { target, run: await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken } }) };
}
const refusedBy = (fn, pattern) => assert.throws(fn, pattern);

test('a stored run\'s findings are printed beside the not-judgeable count and never added to it (C8\'s negative control)', async t => {
  const { target: repairedTarget, run: repaired } = await labRun(t, 'repaired');
  const r = coverageReport({ inventory: labInventory(), contract: labContract(), target: repairedTarget });
  assert.equal(r.reconciliation.equal, true);
  const clean = runFindings(repaired, repairedTarget);
  assert.deepEqual([clean.findings, clean.failedControls, clean.profileMatches, clean.warning], [0, 0, true, undefined]);
  assert.equal(clean.passed, repaired.results.filter(x => x.status === 'pass').length);
  assert.match(coverageLines(r, { run: clean }).join('\n'), new RegExp(`Run ${repaired.id}, from its own grading: 0 findings, 0 failed controls, .* The ${r.notJudgeable.cells} not-judgeable cells are a separate number`));
  const { target: baselineTarget, run: baseline } = await labRun(t, 'baseline');
  const found = runFindings(baseline, baselineTarget);
  assert.equal(found.findings, baseline.results.filter(x => x.status === 'fail' && x.severity !== 'control').length);
  assert.ok(found.findings > 0, 'the baseline build has findings');
  // Whether a row is a control comes from the profile: the same run read against a profile that makes a failing check a control.
  const failing = baseline.results.find(x => x.status === 'fail' && x.severity !== 'control').id;
  const asControl = { ...baselineTarget, checks: baselineTarget.checks.map(c => (c.id === failing ? { ...c, severity: 'control' } : c)) };
  const reread = runFindings(baseline, asControl);
  assert.deepEqual([reread.findings, reread.failedControls - found.failedControls, reread.profileMatches], [found.findings - 1, 1, false]);
});

test('runFindings reads only runs the shared HTTP validator accepts: edited, relabelled, fabricated or duplicated rows and unknown statuses are refused', async t => {
  const { target, run } = await labRun(t, 'baseline');
  const failing = run.results.find(x => x.status === 'fail' && x.severity !== 'control').id;
  const edit = fn => { const copy = structuredClone(run); fn(copy); return copy; };
  refusedBy(() => runFindings(edit(r => { const row = r.results.find(x => x.id === failing); row.status = 'pass'; for (const a of row.assertions) a.status = 'pass'; }), target), /run validator/);
  refusedBy(() => runFindings(edit(r => { r.results.find(x => x.id === failing).severity = 'control'; }), target), /run validator/);
  refusedBy(() => runFindings({ id: 'fabricated', createdAt: '2026-10-08T00:00:00Z', targetId: target.id, results: target.checks.map(c => ({ id: c.id, status: 'pass' })) }, target), /evidence origin null is not one this report reads/);
  refusedBy(() => runFindings(edit(r => { r.results.push(structuredClone(r.results[0])); }), target), /the run lists a check more than once/);
  // A failing row relabelled not applicable, while the profile declares the check applicable, is refused.
  refusedBy(() => runFindings(edit(r => { const row = r.results.find(x => x.id === failing); row.status = 'not_applicable'; }), target), new RegExp(`not-applicable status disagrees with the profile's applicability: ${failing}`));
  // The gate's own run validator also runs: a count that disagrees with the rows is refused.
  refusedBy(() => runFindings(edit(r => { r.checksTotal += 1; }), target), /does not pass the run validator/);
  refusedBy(() => runFindings(edit(r => { r.results[0].status = 'skipped'; r.results[1].status = 'PASS'; }), target), /unknown run statuses for WHOAMI, OWN-RECORD/);
  refusedBy(() => runFindings({ ...run, evidenceOrigin: 'synthetic-local-http' }, target), /is not one this report reads/);
  refusedBy(() => runFindings(run, { ...target, id: 'other' }), /target "http-lab"/);
  refusedBy(() => runFindings(run, target, target.checks.slice(1).map(c => c.id)), /exactly this suite/);
});

test('a not-applicable row counts as not applicable, never as passed', async t => {
  const { target, run } = await labRun(t, 'repaired', p => ({ ...p, checks: p.checks.map(c => (c.id === 'ECHO' ? { ...c, applicability: { applies: false, reason: 'not part of this build' } } : c)) }));
  const f = runFindings(run, target);
  assert.deepEqual([f.notApplicable, f.passed], [1, run.results.filter(x => x.status === 'pass').length]);
  assert.equal(f.passed + f.notApplicable + f.findings + f.failedControls + f.inconclusive + f.errors, run.results.length, 'every row is in one bucket');
});

test('a control that passes on records the application can write says so, with custody\'s stated limit', async t => {
  const app = await createObservedSupportApp({ build: 'secure' }); t.after(() => app.close());
  const file = JSON.parse(readFileSync(join(here, '../../docs/profiles/sqlite-audit.example.json'), 'utf8'));
  const target = bindExampleProfile(file, app).targets[0];
  const run = await runHttpAssessment(target, { env: app.env });
  const f = runFindings(run, target);
  assert.ok(f.controlPassesOnAppRecords.includes('A-OWN-REFUND'), JSON.stringify(f.controlPassesOnAppRecords));
  assert.equal(f.controlLimit, CONTROL_CUSTODY_LIMIT);
  const inv = JSON.parse(readFileSync(join(here, 'examples/example-support.inventory.json'), 'utf8')), con = JSON.parse(readFileSync(join(here, 'examples/example-support.contract.json'), 'utf8'));
  assert.match(coverageLines(coverageReport({ inventory: inv, contract: con, target }), { run: f }).join('\n'), /Control passes decided by records the application can write \(.*A-OWN-REFUND.*\): Allowed-use controls keep their verdicts/);
});

// Summaries as GET /api/history serves them; at is minutes after midnight on 2026-10-08.
const at = minutes => new Date(Date.UTC(2026, 9, 8, 0, minutes)).toISOString();
const summary = (id, minutes, extra = {}) => ({ id, createdAt: at(minutes), targetId: 'desk-local', requiredControlIds: ['C-A1-READ'], ...Object.fromEntries(COMPARISON_KEYS.map(k => [k, k === 'evaluatorHash' ? 'a'.repeat(64) : `${k}-1`])), ...extra });

test('the comparison keys are compareRuns\' own: changing each makes compareRuns refuse the pair with that key named', () => {
  const base = { ...summary('b', 1), results: [] };
  const all = compareRuns(base, { ...base, ...Object.fromEntries(COMPARISON_KEYS.map(k => [k, 'other'])) });
  assert.deepEqual(all.reasons.map(r => /^(\w+) differs or is missing\.$/.exec(r)?.[1]).filter(Boolean).sort(), [...COMPARISON_KEYS].sort());
  assert.ok(!compareRuns(base, { ...base, build: 'other' }).reasons.some(r => r.startsWith('build ')));
});

test('stored runs stop comparing where compareRuns\' identity moves; a run rejoins an earlier series it compares with; other applications and targets are separate series', () => {
  const runs = [
    summary('r3', 180, { evaluatorHash: 'b'.repeat(64) }), summary('r1', 60), summary('r2', 120),
    summary('r4', 240, { evaluatorHash: 'b'.repeat(64), profileHash: 'profileHash-2' }),
    summary('r5', 300), // back to r1's identity: it continues r1's series
    summary('o1', 150, { applicationId: 'other' }), summary('t1', 160, { targetId: 'elsewhere' }),
  ];
  const c = runComparability(runs);
  assert.deepEqual(c.series.map(s => s.runIds), [['r1', 'r2', 'r5'], ['r3'], ['r4'], ['o1'], ['t1']]);
  assert.deepEqual(c.breaks.map(b => [b.before, b.after, b.continues]), [['r2', 'r3', null], ['r3', 'r4', null], ['r4', 'r5', 'r2']]);
  assert.match(c.breaks[0].message, /^Run r3 is not comparable with run r2 before it: evaluatorHash differs or is missing\. The evaluator identity changed \(aaaaaaaa to bbbbbbbb\)\. A new series starts here; no trend is drawn across this point\.$/);
  assert.match(c.breaks[1].message, /profileHash differs or is missing\./);
  assert.match(c.breaks[2].message, /It is comparable with run r2 and continues that earlier series\./);
  assert.deepEqual(c.bases, ['identity-keys']);
  assert.match(c.note, /identity keys only/);
  // Each key alone breaks; another application is another series; a missing key is incomparable; runId is read where id is absent.
  for (const k of ['adapterVersion', 'policyHash', 'suiteHash']) assert.deepEqual(runComparability([summary('x1', 1), summary('x2', 2, { [k]: 'moved' })]).breaks[0].reasons, [`${k} differs or is missing.`], k);
  const apps = runComparability([summary('x1', 1), summary('x2', 2, { applicationId: 'moved' }), summary('x3', 3, { applicationId: 'moved' })]);
  assert.deepEqual([apps.series.map(s => s.runIds), apps.breaks], [[['x1'], ['x2', 'x3']], []]);
  const missing = summary('m2', 2); delete missing.contextId;
  assert.deepEqual(runComparability([summary('m1', 1), missing]).breaks[0].reasons, ['contextId differs or is missing.']);
  // Summaries also compare their required allowed-use controls.
  assert.deepEqual(runComparability([summary('q1', 1), summary('q2', 2, { requiredControlIds: ['C-OTHER'] })]).breaks[0].reasons, ['Required permitted-use controls differ or are missing.']);
  const legacy = summary(undefined, 2); delete legacy.id; legacy.runId = 'legacy';
  assert.deepEqual(runComparability([summary('n1', 1), legacy]).series[0].runIds, ['n1', 'legacy']);
  assert.throws(() => runComparability([{ createdAt: at(1) }]), /id and a createdAt date/);
  assert.throws(() => runComparability([summary('d1', 1, { createdAt: 'yesterday' })]), /createdAt date/);
  const scoped = runComparability(runs, { target: { id: 'desk-local' } });
  assert.deepEqual([scoped.otherTargets, scoped.series.length], [1, 4]);
});

test('runs are ordered by parsed time, then by id: mixed precision and offsets sort correctly, and equal times break by id', () => {
  const later = summary('half-second', 0, { createdAt: '2026-10-08T01:00:00.5Z' }), earlier = summary('whole-second', 0, { createdAt: '2026-10-08T01:00:00Z' });
  const offset = summary('offset', 0, { createdAt: '2026-10-08T02:00:00+01:00' }); // 01:00:00Z, the same instant as earlier
  assert.deepEqual(runComparability([later, earlier, offset]).series[0].runIds, ['offset', 'whole-second', 'half-second']);
  assert.deepEqual(runComparability([summary('b', 5), summary('a', 5)]).series[0].runIds, ['a', 'b']);
});

test('full stored runs are compared with compareRuns itself', async () => {
  const first = await runAssessment('demo-vulnerable'), again = await runAssessment('demo-vulnerable');
  assert.equal(compareRuns(first, again).compatible, true, 'precondition: two runs of one build compare');
  const c = runComparability([first, again]);
  assert.deepEqual([c.series.length, c.breaks, c.bases, c.note], [1, [], ['compareRuns'], undefined]);
  const resealed = { ...again, id: `${again.id}-x`, createdAt: new Date(Date.parse(again.createdAt) + 1000).toISOString(), evaluatorHash: 'c'.repeat(64) };
  const moved = runComparability([first, resealed]);
  assert.deepEqual(moved.breaks[0].reasons, compareRuns(first, resealed).reasons);
  assert.match(moved.breaks[0].message, /evaluatorHash differs or is missing\..*The evaluator identity changed/);
});

test('the printed lines give each side by role, surface and tenant with its not-judgeable counts, and the not-judgeable fraction', () => {
  const r = report(), lines = coverageLines(r).join('\n');
  assert.match(lines, /Suite reconciliation: 5 drafted of 5 suite checks \(equal\)\./);
  assert.match(lines, new RegExp(`Allowed side: legitimate cells with a twin \\(an allowed-use control\\): 1 of ${r.allowedSide.cells} \\(\\d+\\.\\d%\\); ${r.allowedSide.notJudgeable} not judgeable, ${r.allowedSide.needsActor} need an actor\\.`));
  assert.match(lines, /Forbidden side: stated-deny cells with a forbidden check: 2 of \d+/);
  for (const dim of ['role', 'surface', 'tenant']) assert.equal(lines.match(new RegExp(`  by ${dim}: `, 'g')).length, 2, dim);
  const a = r.allowedSide.byRole.agent, f = r.forbiddenSide.byTenant.null;
  assert.match(lines, new RegExp(`by role: .*agent ${a.covered}/${a.cells} \\(${a.notJudgeable} not judgeable\\)`));
  assert.match(lines, new RegExp(`by tenant: .*\\(none\\) ${f.covered}/${f.cells}`));
  assert.match(lines, new RegExp(`Not judgeable: ${r.notJudgeable.cells} of ${r.notJudgeable.reachable} reachable cells .*held-out validation fails a holdout application above 50%`));
  assert.equal(r.notJudgeable.fraction, r.notJudgeable.cells / r.notJudgeable.reachable);
  assert.match(lines, /Forbidden checks on permitted cells .*: 2: L-A2-LIST, B-A1-APPROVE\./);
  const c = contract(); c.rules = c.rules.filter(rule => rule.operation !== 'GET /api/items');
  assert.match(coverageLines(report({ contract: c })).join('\n'), /Operations with no rule in this contract \(whether the application guards them is not observed here.*\): GET \/api\/items\./);
  assert.ok(MARKS.every(m => lines.includes(` ${m}`)));
});

test('the CLI validates the profile, reconciles against this profile\'s exported suite, reads runs, and exits 0, 1 or 2', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-coverage-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const write = (name, value) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(value)); return p; };
  const p = profile(), targets = write('targets.json', { schemaVersion: 1, targets: [p] });
  const inv = write('inventory.json', inventory()), con = write('contract.json', contract());
  const base = ['--inventory', inv, '--contract', con, '--targets', targets];
  const lines = [], log = s => lines.push(s);
  assert.equal(main(base, { log }), 0);
  assert.match(lines.join('\n'), /5 drafted of 5 suite checks \(equal\)/);
  const suite = { targetId: 'desk-local', hash: contractDigest(p), checks: p.checks };
  assert.equal(main([...base, '--suite', write('suite.json', suite)], { log }), 0);
  lines.length = 0;
  assert.equal(main([...base, '--suite', write('ghost.json', { ...suite, checks: [...p.checks, { id: 'GHOST' }] })], { log }), 1);
  assert.match(lines.join('\n'), /GHOST \(not-in-profile\)/);
  // An export edited to drop a check but keep its hash is caught by the reconciliation in both directions.
  lines.length = 0;
  assert.equal(main([...base, '--suite', write('dropped.json', { ...suite, checks: p.checks.slice(1) })], { log }), 1);
  assert.match(lines.join('\n'), /profile checks the suite leaves out: C-A1-READ/);
  assert.equal(main([...base, '--suite', write('stale.json', { ...suite, hash: '0'.repeat(64) })], { log }), 2);
  assert.match(lines.at(-1), /another version of this profile/);
  assert.equal(main([...base, '--suite', write('other.json', { targetId: 'other', checks: [] })], { log }), 2);
  assert.match(lines.at(-1), /exported suite of this target/);
  assert.equal(main(['--inventory', inv, '--contract', con, '--targets', write('bad.json', { schemaVersion: 1, targets: [{ ...p, origin: 'http://example.com' }] })], { log }), 2);
  assert.equal(main(['--inventory', inv, '--contract', con], { log }), 2);
  // Text mode prints where stored runs stop comparing.
  lines.length = 0;
  assert.equal(main([...base, '--runs', write('runs.json', { runs: [summary('r1', 1), summary('r2', 2, { evaluatorHash: 'b'.repeat(64) })] })], { log }), 0);
  assert.match(lines.join('\n'), /Run r2 is not comparable with run r1 before it: evaluatorHash differs or is missing\. The evaluator identity changed \(aaaaaaaa to bbbbbbbb\)/);
  // --run reads a real stored run of the target, beside the not-judgeable count; another target's run is a configuration error.
  const { target: lab, run } = await labRun(t, 'repaired');
  const labBase = ['--inventory', write('lab-inventory.json', labInventory()), '--contract', write('lab-contract.json', labContract()), '--targets', write('lab-targets.json', { schemaVersion: 1, targets: [lab] })];
  lines.length = 0;
  assert.equal(main([...labBase, '--run', write('run.json', run)], { log }), 0);
  assert.match(lines.join('\n'), new RegExp(`Run ${run.id}, from its own grading: 0 findings`));
  assert.equal(main([...base, '--run', write('wrong-run.json', run)], { log }), 2);
  assert.match(lines.at(-1), /Configuration error: .*target "http-lab"/);
  const json = []; assert.equal(main([...base, '--json', '--runs', write('one.json', [summary('r1', 1)])], { log: s => json.push(s) }), 0);
  const parsed = JSON.parse(json.join('\n'));
  assert.deepEqual([parsed.schema, parsed.comparability.breaks], ['scopehaven-coverage-report/1', []]);
  // Run through a symlink, as from a compatibility path: it still runs and prints.
  const link = join(dir, 'linked-cli.mjs'); symlinkSync(join(here, 'cli.mjs'), link);
  assert.match(execFileSync(process.execPath, [link, ...base], { encoding: 'utf8' }), /5 drafted of 5 suite checks \(equal\)/);
});

test('the allowed-side number computes for every shipped example profile (C8 in-sample acceptance)', () => {
  const read = name => JSON.parse(readFileSync(join(here, name), 'utf8'));
  const inv = read('examples/example-support.inventory.json'), con = read('examples/example-support.contract.json');
  const mapped = { 'response-only': [0, []], 'sqlite-audit': [1, []], 'http-audit': [0, ['http-audit']], 'sqlite-snapshot': [1, []] };
  for (const name of Object.keys(mapped)) {
    const targets = JSON.parse(readFileSync(join(here, `../../docs/profiles/${name}.example.json`), 'utf8'));
    validateTargetFile(targets);
    const r = coverageReport({ inventory: inv, contract: con, target: targets.targets[0] });
    assert.equal(r.reconciliation.equal, true, name);
    assert.ok(r.allowedSide.cells > 0 && Number.isFinite(r.allowedSide.covered / r.allowedSide.cells), name);
    assert.ok(['byRole', 'bySurface', 'byTenant'].every(d => Object.keys(r.allowedSide[d]).length && Object.keys(r.forbiddenSide[d]).length), name);
    assert.deepEqual([r.datastores.observed, r.datastores.otherObservers.map(o => o.type)], mapped[name], name);
    assert.deepEqual(keysNamed(r, 'severity'), [], name);
  }
});

// A profile check may send PUT, PATCH and DELETE, so the coverage report reads the connector's own method set; a GET/POST
// literal would leave those cells not judgeable.
test('the default connector methods are the HTTP connector\'s own set, PUT, PATCH and DELETE included', () => {
  assert.deepEqual(CONNECTOR_METHODS, HTTP_CHECK_METHODS);
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) assert.ok(CONNECTOR_METHODS.includes(method), method);
  const r = report();
  assert.deepEqual(markOf(r, 'owner', 't1', 'PATCH /api/items/:id', 'own'), ['stated-only', null]);
  assert.deepEqual(markOf(r, 'viewer', 't1', 'PATCH /api/items/:id', 'own'), ['needs-actor', 'no-actor-for-this-role-and-tenant']);
  assert.equal(Object.keys(r.reasons).some(reason => reason.startsWith('connector-sends-')), false);
});
