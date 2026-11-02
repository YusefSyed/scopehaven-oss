// Two identities by default (src/two-identities.mjs): the single-identity rule, the generated mirror of each
// boundary check under the second identity, and the CLI's warning and refusal. The app is an owned two-tenant stand-in on
// 127.0.0.1 with a fixed build and an asymmetric defective build; no model, provider or database.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, chmodSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateTargetFile, contractDigest, identityControlPlan } from '../src/contracts.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { identityCoverage, mirrorPlan, mirrorReport, mirrorChecks, MIRROR_SKIP_REASONS } from '../src/two-identities.mjs';
import { writeTestAuthorization } from './support/authorization.mjs';

const TOKENS = { ana: 'synthetic-ana-token', gil: 'synthetic-gil-token' };
const ENV = { SCOPEHAVEN_TARGET_ANA: TOKENS.ana, SCOPEHAVEN_TARGET_GIL: TOKENS.gil };
const control = (id, actorId, path, assertions, extra = {}) => ({ id, title: id, category: 'Identity', severity: 'control', actorId, method: 'GET', path, evidenceRequirement: 'response', assertions, ...extra });
const boundary = (id, actorId, method, path, assertions, extra = {}) => ({ id, title: id, category: 'Tenant', severity: 'high', actorId, method, path, evidenceRequirement: 'response', assertions, ...extra });
const REFUSED = [{ kind: 'status.in', expected: [403, 404] }, { kind: 'json.noForeignValues', pointer: '' }];
const ANSWERED = [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '/reply' }];
// Two identities in two tenants, each with an identity control and a surface control on its own order; gil's own chat
// control is the route the chat mirrors go to.
const MIRRORS = Object.freeze({ counterparts: [['ORD-1001', 'ORD-2002']], readOnlyRoutes: ['POST /api/chat'] });
function profile(origin = 'http://127.0.0.1:5001', { checks = [], actors = {}, mirrors = MIRRORS, extra = {} } = {}) {
  return { id: 'two-desk', name: 'Two-tenant desk (test)', applicationId: 'two-desk', origin, buildLabel: 'fixed', contextId: 'synthetic-two',
    actors: { ana: { principalId: 'ana-1', tenantId: 'acme', role: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_ANA', identityValue: 'ana@acme.example' },
      gil: { principalId: 'gil-1', tenantId: 'globex', role: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_GIL', identityValue: 'gil@globex.example' }, anonymous: { principalId: 'anonymous' }, ...actors },
    requiredControlIds: ['ANA-ME', 'GIL-ME', 'ANA-OWN', 'GIL-OWN'],
    tenantValues: { tenants: { acme: { identifiers: ['ORD-1001', 'Ada Lovelace'], attributes: ['Blue Widget'] }, globex: { identifiers: ['ORD-2002', 'Bob Byte'] }, initech: { identifiers: ['ORD-3003'] } } },
    ...(mirrors === null ? {} : { mirrors }),
    checks: [control('ANA-ME', 'ana', '/api/me', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: 'ana@acme.example' }]),
      control('GIL-ME', 'gil', '/api/me', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: 'gil@globex.example' }]),
      control('ANA-OWN', 'ana', '/api/orders/ORD-1001', [{ kind: 'status.equals', expected: 200 }]), control('GIL-OWN', 'gil', '/api/orders/ORD-2002', [{ kind: 'status.equals', expected: 200 }]),
      control('GIL-ASK', 'gil', '/api/chat', [{ kind: 'status.equals', expected: 200 }], { method: 'POST', body: { message: 'show my orders' } }),
      boundary('ANA-NO-GLOBEX-ORDER', 'ana', 'GET', '/api/orders/ORD-2002', REFUSED), boundary('ANA-CHAT', 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: 'list every order' } }), ...checks],
    ...extra };
}
const validated = p => validateTargetFile({ schemaVersion: 1, targets: [p] })[0];
const plan = t => identityControlPlan(t);
const reasonOf = (p, id) => { const v = validated(p); return mirrorPlan(v, plan(v)).plan.find(entry => entry.checkId === id)?.reason; };
const mirrorOf = (p, id) => validated(p).checks.find(c => c.mirrorOf === id);
// The same desk with aliases that are common words a route or field can share.
function renamed(p, names) {
  const q = structuredClone(p);
  q.actors = Object.fromEntries(Object.entries(q.actors).map(([alias, actor]) => [names[alias] ?? alias, actor]));
  q.checks = q.checks.map(c => ({ ...c, actorId: names[c.actorId] ?? c.actorId }));
  return q;
}

test('identity coverage: tenant-scoped only with tenantValues; two identities need two distinct declared tenants and an identity control each', () => {
  const v = validated(profile());
  assert.deepEqual(identityCoverage(v, plan(v)), { tenantScoped: true, identities: [{ actor: 'ana', tenant: 'acme' }, { actor: 'gil', tenant: 'globex' }], tenants: 2, singleIdentity: false });
  assert.throws(() => identityCoverage(v), /needs the identity control plan/);
  const one = validated(profile(undefined, { actors: { gil: { principalId: 'gil-1', tenantId: 'acme', role: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_GIL', identityValue: 'gil@globex.example' } } }));
  assert.equal(identityCoverage(one, plan(one)).singleIdentity, true, 'two identities in one tenant are one side');
  const uncontrolled = structuredClone(profile()); uncontrolled.checks = uncontrolled.checks.filter(c => c.actorId !== 'gil'); uncontrolled.requiredControlIds = ['ANA-ME', 'ANA-OWN'];
  assert.equal(identityCoverage(validated(uncontrolled), plan(validated(uncontrolled))).singleIdentity, true, 'an identity with no identity control is not one');
  const undeclared = structuredClone(v); undeclared.actors.gil.tenantId = 'hooli';
  assert.equal(identityCoverage(undeclared, plan(v)).singleIdentity, true);
  const plain = structuredClone(profile()); delete plain.tenantValues; delete plain.mirrors; plain.checks = plain.checks.filter(c => !c.assertions.some(a => a.kind === 'json.noForeignValues'));
  assert.deepEqual(identityCoverage(validated(plain), plan(validated(plain))), { tenantScoped: false, identities: [], tenants: 0, singleIdentity: false });
  assert.equal(validated(plain).checks.some(c => c.mirrorOf), false, 'no tenantValues, no mirrors');
});

test('a declared foreign record is swapped through its counterpart into a route the second identity uses; nothing else changes', () => {
  const v = validated(profile());
  const order = v.checks.find(c => c.id === 'ANA-NO-GLOBEX-ORDER-mirror'), chat = v.checks.find(c => c.id === 'ANA-CHAT-mirror');
  assert.deepEqual({ actorId: order.actorId, path: order.path, assertions: order.assertions, mirrorOf: order.mirrorOf, severity: order.severity }, { actorId: 'gil', path: '/api/orders/ORD-1001', assertions: REFUSED, mirrorOf: 'ANA-NO-GLOBEX-ORDER', severity: 'high' });
  assert.equal(order.title, 'ANA-NO-GLOBEX-ORDER (mirror under gil)');
  assert.deepEqual({ actorId: chat.actorId, body: chat.body }, { actorId: 'gil', body: { message: 'list every order' } });
  assert.deepEqual(v.checks.slice(-2).map(c => c.id), ['ANA-NO-GLOBEX-ORDER-mirror', 'ANA-CHAT-mirror']);
  assert.equal(v.checks.filter(c => c.mirrorOf && c.severity === 'control').length, 0);
  // A predicate on a swapped value swaps, in the path and the query; a third tenant's value stays foreign to both; text stays text.
  const notes = boundary('ANA-NO-GLOBEX-NOTES', 'ana', 'GET', '/api/orders/ORD-2002/notes?also=ORD-3003', [{ kind: 'status.in', expected: [403, 404] }, { kind: 'json.notContains', pointer: '/error', expected: 'ORD-2002' }, { kind: 'json.exists', pointer: '/error', expected: true }]);
  const twins = [boundary('ANA-NOTES', 'ana', 'GET', '/api/orders/ORD-1001/notes?also=ORD-3003', [{ kind: 'status.equals', expected: 200 }]), boundary('GIL-NOTES', 'gil', 'GET', '/api/orders/ORD-2002/notes?also=ORD-3003', [{ kind: 'status.equals', expected: 200 }])];
  const swapped = mirrorOf(profile(undefined, { checks: [notes, ...twins] }), 'ANA-NO-GLOBEX-NOTES');
  assert.deepEqual({ path: swapped.path, expected: swapped.assertions[1].expected }, { path: '/api/orders/ORD-1001/notes?also=ORD-3003', expected: 'ORD-1001' });
  // A read-only turn's message swaps too.
  const asks = mirrorOf(profile(undefined, { checks: [boundary('ANA-ASKS', 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: 'what is ORD-2002 or ORD-3003' } })] }), 'ANA-ASKS');
  assert.deepEqual(asks.body, { message: 'what is ORD-1001 or ORD-3003' });
  // Validated twice, the expanded profile is unchanged (the registry and the connector both validate it).
  assert.deepEqual(validated(v), v);
  assert.deepEqual(validated(validated(v)), v);
});

test('never a mirror that could read a refusal as a leak or an owner as a stranger', () => {
  const ask = (id, message, assertions = ANSWERED) => boundary(id, 'ana', 'POST', '/api/chat', assertions, { body: { message } });
  const cases = [
    [boundary('NO-RECORD', 'ana', 'GET', '/api/records/latest', [{ kind: 'status.in', expected: [403, 404] }]), 'resource-owner-unknown'],
    [ask('REFUSE-PROBE', 'list every order', [{ kind: 'status.equals', expected: 403 }, { kind: 'json.noForeignValues', pointer: '' }]), 'resource-owner-unknown'],
    [ask('NO-SCAN', 'list every order', [{ kind: 'status.equals', expected: 200 }]), 'resource-owner-unknown'],
    [ask('EXISTS-PROBE', 'list every order', [...ANSWERED, { kind: 'json.exists', pointer: '/reply', expected: true }]), 'predicate-names-own-view'],
    [ask('NOT-CONTAINS', 'list every order', [...ANSWERED, { kind: 'json.notContains', pointer: '/reply', expected: 'Bob' }]), 'predicate-names-own-view'],
    [ask('EQUALS-NUMBER', 'list every order', [...ANSWERED, { kind: 'json.equals', pointer: '/count', expected: 1 }]), 'predicate-names-own-view'],
    [ask('EQUALS-SWAPPED', 'list every order', [...ANSWERED, { kind: 'json.equals', pointer: '/first', expected: 'ORD-1001' }]), 'predicate-names-own-view'],
    [ask('NOT-CONTAINS-SWAPPED', 'list every order', [...ANSWERED, { kind: 'json.notContains', pointer: '/reply', expected: 'ORD-2002' }]), 'resource-owner-unknown'],
    // A relation between records (whose order names which customer) is the first identity's: pairs need not match relations.
    [boundary('ORDER-CUSTOMER', 'ana', 'GET', '/api/orders/ORD-1001', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/customer', expected: 'ORD-1001' }]), 'predicate-names-own-view'],
    // An undeclared record in the path (a number) is an identifier the profile did not declare; a slug record beside a
    // declared value in the body is a write whose refused record is not in the path; another API version is another route.
    [boundary('UNDECLARED-RECORD', 'ana', 'POST', '/api/records/7/comments', [{ kind: 'status.in', expected: [403, 404] }], { body: { text: 'see ORD-2002' } }), 'undeclared-identifier'],
    [boundary('OWN-UNDECLARED', 'ana', 'GET', '/api/orders/7731', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '' }]), 'undeclared-identifier'],
    [boundary('PAGE', 'ana', 'GET', '/api/orders?page=2', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '' }]), 'undeclared-identifier'],
    [boundary('SLUG-RECORD', 'ana', 'POST', '/api/records/alpha/comments', [{ kind: 'status.in', expected: [403, 404] }], { body: { text: 'see ORD-2002' } }), 'refusal-not-a-read'],
    [boundary('V2', 'ana', 'GET', '/api/v2/orders/ORD-2002', REFUSED), 'refusal-twin-not-shown'],
    [boundary('QUERY-ONLY', 'ana', 'GET', '/api/orders?id=ORD-2002', REFUSED), 'refusal-twin-not-shown'],
    // A word after the record, in the path or the query, the first identity's own allowed twin does not show.
    [boundary('MOVE-TO', 'ana', 'GET', '/api/orders/ORD-2002/history?workspace=beta', REFUSED), 'refusal-twin-not-shown'],
    [boundary('MOVE-WRITE', 'ana', 'POST', '/api/orders/ORD-2002/move/beta', [{ kind: 'status.equals', expected: 403 }]), 'refusal-not-a-read'],
    [boundary('GUEST-ADD', 'ana', 'PUT', '/api/users/ORD-2002/workspaces/beta', [{ kind: 'status.in', expected: [403, 404] }]), 'refusal-not-a-read'],
    [boundary('DELETE-ORDER', 'ana', 'DELETE', '/api/orders/ORD-2002', [{ kind: 'status.in', expected: [403, 404] }]), 'refusal-not-a-read'],
    // The direction: a refusal only across the boundary with a boundary status, a success only
    // on the first tenant's own values or as an answer probe, and only as a read.
    [boundary('CANCEL-SHIPPED', 'ana', 'POST', '/api/orders/ORD-1001/cancel', [{ kind: 'status.equals', expected: 409 }]), 'refusal-not-boundary-status'],
    [boundary('OWN-REFUSAL', 'ana', 'POST', '/api/orders/ORD-1001/cancel', [{ kind: 'status.in', expected: [403, 404] }]), 'own-record-refusal'],
    [boundary('BODY-TRANSFER', 'ana', 'POST', '/api/transfers', [{ kind: 'status.in', expected: [403, 404] }], { body: { order: 'ORD-2002' } }), 'refusal-not-a-read'],
    [boundary('REFUND-VISIBLE', 'ana', 'GET', '/api/orders/ORD-1001', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/refund', expected: true }]), 'predicate-names-own-view'],
    [boundary('FOREIGN-READ', 'ana', 'GET', '/api/orders/ORD-2002', [{ kind: 'status.equals', expected: 200 }]), 'foreign-record-success'],
    [boundary('OWN-WRITE', 'ana', 'POST', '/api/orders/ORD-1001/copy', [{ kind: 'status.equals', expected: 200 }], { body: { note: 'please copy' } }), 'success-not-a-read'],
    [ask('CREATED', 'open a ticket', [{ kind: 'status.equals', expected: 201 }, { kind: 'json.noForeignValues', pointer: '' }]), 'success-not-a-read'],
    // Identifiers the profile did not declare, in the body.
    [boundary('NUMBER-FIELD', 'ana', 'POST', '/api/chat', ANSWERED, { body: { order: 1001 } }), 'undeclared-identifier'],
    [boundary('ID-FIELD', 'ana', 'POST', '/api/chat', ANSWERED, { body: { order: 'ord_77' } }), 'undeclared-identifier'],
    [boundary('WORD-FIELD', 'ana', 'POST', '/api/chat', ANSWERED, { body: { record: 'alpha' } }), 'undeclared-identifier'],
    [boundary('SPLIT', 'ana', 'POST', '/api/chat', ANSWERED, { body: { prefix: 'ORD-', id: '2002' } }), 'undeclared-identifier'],
    [boundary('REFUND-TEXT', 'ana', 'POST', '/api/orders/ORD-2002/copy', [{ kind: 'status.in', expected: [403, 404] }], { body: { note: 'refund order 9 too' } }), 'undeclared-identifier'],
    // Declared values in another form, without a counterpart, or shared.
    [ask('NAME', 'what did Bob Byte order'), 'tenant-value-without-counterpart'],
    [ask('OWN-ATTR', 'how many Blue Widget orders'), 'tenant-value-without-counterpart'],
    [ask('LOWER', 'show ord-2002'), 'tenant-value-variant'],
    [ask('GLUED', 'show ORD-20021'), 'tenant-value-variant'],
    [ask('PREFIXED', 'show XORD-2002'), 'tenant-value-variant'],
    [ask('BODY-ENCODED', 'summarize ORD%2D2002'), 'tenant-value-variant'],
    [boundary('ENCODED', 'ana', 'GET', '/api/search?q=ORD%2D2002', REFUSED), 'tenant-value-variant'],
    // Either identity's names, anywhere: an alias in the path, the other identity's alias, a tenant id, an identity value.
    [boundary('USER-ROUTE', 'ana', 'GET', '/api/users/ana/orders', ANSWERED), 'names-an-identity'],
    [boundary('GIL-ROUTE', 'ana', 'GET', '/api/users/gil/orders', REFUSED), 'names-an-identity'],
    [boundary('ORG-ROUTE', 'ana', 'GET', '/api/orgs/acme/orders', ANSWERED), 'names-an-identity'],
    [boundary('MOVE', 'ana', 'POST', '/api/orders/ORD-2002/copy', [{ kind: 'status.in', expected: [403, 404] }], { body: { toOrg: 'Globex' } }), 'names-an-identity'],
    [ask('OWN-EMAIL', 'list every order', [...ANSWERED, { kind: 'json.equals', pointer: '/user', expected: 'ana@acme.example' }]), 'names-an-identity'],
  ];
  for (const [check, reason] of cases) assert.equal(reasonOf(profile(undefined, { checks: [check] }), check.id), reason, check.id);
  // The second identity's own checks decide the route: a plan feature it is refused (the same request, other statuses), a
  // route it is shown only refused on, a success there of another status, and a check that is not applicable.
  const gilSide = (id, method, path, assertions, extra) => boundary(id, 'gil', method, path, assertions, extra);
  const answer = path => [boundary(`ANA${path.replaceAll('/', '-').toUpperCase()}`, 'ana', 'GET', path, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '' }])];
  const routes = [
    [answer('/api/reports/export'), gilSide('GIL-EXPORT', 'GET', '/api/reports/export', [{ kind: 'status.equals', expected: 403 }]), 'contradicts-second-identity-check'],
    [answer('/api/notes/ORD-1001'), gilSide('GIL-NO-ACME-NOTES', 'GET', '/api/notes/ORD-1001', REFUSED), 'route-not-used-by-second-identity'],
    [answer('/api/files/ORD-1001'), gilSide('GIL-FILES', 'GET', '/api/files/ORD-3003', [{ kind: 'status.equals', expected: 204 }]), 'route-not-used-by-second-identity'],
    [answer('/api/audit'), gilSide('GIL-AUDIT', 'GET', '/api/audit', [{ kind: 'status.equals', expected: 200 }], { applicability: { applies: false, reason: 'no audit log on this plan' } }), 'route-not-used-by-second-identity'],
  ];
  for (const [[check], gil, reason] of routes) assert.equal(reasonOf(profile(undefined, { checks: [check, gil] }), check.id), reason, check.id);
  // The other way: gil's refusal on acme's notes is mirrored under ana, onto a route ana is shown on.
  const notes = profile(undefined, { checks: [answer('/api/notes/ORD-1001')[0], gilSide('GIL-NO-ACME-NOTES', 'GET', '/api/notes/ORD-1001', REFUSED), gilSide('GIL-OWN-NOTES', 'GET', '/api/notes/ORD-2002', [{ kind: 'status.equals', expected: 200 }])] });
  assert.deepEqual([mirrorOf(notes, 'GIL-NO-ACME-NOTES').actorId, mirrorOf(notes, 'GIL-NO-ACME-NOTES').path], ['ana', '/api/notes/ORD-2002']);
  // Without gil's own record shown on that route, the refusal is not mirrored.
  assert.equal(reasonOf(profile(undefined, { checks: [answer('/api/notes/ORD-1001')[0], gilSide('GIL-NO-ACME-NOTES', 'GET', '/api/notes/ORD-1001', REFUSED)] }), 'GIL-NO-ACME-NOTES'), 'refusal-twin-not-shown');
  // The first identity's own allowed twin: an exact success of its own on the same route (a value of its own beside the other's,
  // a bare query, an undeclared word where the record stands, or a refusal of its own, is not one).
  const recordCases = [
    [[boundary('QUERY-SHARE', 'ana', 'GET', '/api/orders/ORD-1001?share=ORD-2002', REFUSED)], 'QUERY-SHARE'],
    [[boundary('BARE-QUERY', 'ana', 'GET', '/api/orders?ORD-2002', REFUSED)], 'BARE-QUERY'],
    [[boundary('ANA-NO-INVOICE', 'ana', 'GET', '/api/invoices/ORD-2002', REFUSED), boundary('ANA-INVOICES', 'ana', 'GET', '/api/invoices/summary', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '' }]),
      gilSide('GIL-INVOICE', 'GET', '/api/invoices/ORD-2002', [{ kind: 'status.equals', expected: 200 }])], 'ANA-NO-INVOICE'],
    [[boundary('ANA-NO-RECEIPT', 'ana', 'GET', '/api/receipts/ORD-2002', REFUSED), boundary('ANA-NO-OWN-RECEIPT', 'ana', 'GET', '/api/receipts/ORD-1001', [{ kind: 'status.equals', expected: 404 }]),
      gilSide('GIL-RECEIPT', 'GET', '/api/receipts/ORD-2002', [{ kind: 'status.equals', expected: 200 }])], 'ANA-NO-RECEIPT'],
  ];
  for (const [checks, id] of recordCases) assert.equal(reasonOf(profile(undefined, { checks }), id), 'refusal-twin-not-shown', id);
  // A query is not more path: /orders/ORD-1001?view=full is not the route /orders/ORD-2002/view/full.
  assert.equal(reasonOf(profile(undefined, { checks: [boundary('VIEW-QUERY', 'ana', 'GET', '/api/orders/ORD-2002?view=full', REFUSED), boundary('ANA-VIEW', 'ana', 'GET', '/api/orders/ORD-1001?view=full', [{ kind: 'status.equals', expected: 200 }]),
    gilSide('GIL-VIEW', 'GET', '/api/orders/ORD-2002/view/full', [{ kind: 'status.equals', expected: 200 }])] }), 'VIEW-QUERY'), 'route-not-used-by-second-identity');
  // The second identity's own allowed twin: its own record through the first tenant's workspace is not one (an IDOR).
  const tasks = profile(undefined, { checks: [boundary('ANA-ALPHA-IDOR', 'ana', 'GET', '/api/workspaces/alpha/tasks/ORD-2002', [{ kind: 'status.equals', expected: 404 }]), boundary('ANA-ALPHA-TASK', 'ana', 'GET', '/api/workspaces/alpha/tasks/ORD-1001', [{ kind: 'status.equals', expected: 200 }]),
    gilSide('GIL-BETA-TASK', 'GET', '/api/workspaces/beta/tasks/ORD-2002', [{ kind: 'status.equals', expected: 200 }])] });
  assert.equal(reasonOf(tasks, 'ANA-ALPHA-IDOR'), 'route-not-used-by-second-identity');
  // A declared write to a counterpart (gil deletes its own order) keeps every mirror off that record, whether the write names it
  // in its path or in its body (an RPC-style route, an assistant told to act), or answers with a redirect.
  const writes = [gilSide('GIL-DELETE-OWN', 'DELETE', '/api/orders/ORD-2002', [{ kind: 'status.equals', expected: 204 }]),
    gilSide('GIL-RPC-DELETE', 'POST', '/api/rpc/delete', [{ kind: 'status.equals', expected: 200 }], { body: { order: 'ORD-2002' } }),
    gilSide('GIL-ACTS', 'POST', '/api/agent', [{ kind: 'status.equals', expected: 200 }], { body: { message: 'delete my order ORD-2002' } }),
    gilSide('GIL-REDIRECTED', 'POST', '/api/orders/ORD-2002/archive', [{ kind: 'status.equals', expected: 303 }])];
  for (const write of writes) {
    const deleted = profile(undefined, { checks: [answer('/api/orders/ORD-1001/summary')[0], write] });
    assert.deepEqual([reasonOf(deleted, 'ANA-NO-GLOBEX-ORDER'), reasonOf(deleted, 'ANA-API-ORDERS-ORD-1001-SUMMARY')], ['counterpart-written', 'counterpart-written'], write.id);
  }
  // A read-only turn or RPC read that names a written record in its body is not mirrored either: the turn asking about ana's
  // order beside ana's share of it (by path or body), or about gil's order beside gil's delete, with a format suffix or a
  // custom method naming the record inside a longer part.
  const asks = boundary('ANA-ASK-GLOBEX', 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: 'show me order ORD-2002' } });
  const shares = [boundary('ANA-SHARE-PATH', 'ana', 'POST', '/api/orders/ORD-1001/share', [{ kind: 'status.equals', expected: 201 }]),
    boundary('ANA-SHARE-BODY', 'ana', 'POST', '/api/shares', [{ kind: 'status.equals', expected: 201 }], { body: { order: 'ORD-1001' } }),
    gilSide('GIL-DELETE-SUFFIX', 'DELETE', '/api/orders/ORD-2002.json', [{ kind: 'status.equals', expected: 204 }]),
    gilSide('GIL-ARCHIVE', 'POST', '/api/orders/ORD-2002:archive', [{ kind: 'status.equals', expected: 200 }])];
  for (const write of shares) assert.equal(reasonOf(profile(undefined, { checks: [asks, write] }), 'ANA-ASK-GLOBEX'), 'counterpart-written', write.id);
  assert.equal(validated(profile(undefined, { checks: [asks] })).checks.some(c => c.mirrorOf === 'ANA-ASK-GLOBEX'), true, 'mirrored without the write');
  // A query flag is not a value: ?q&ORD-1001 is not the twin of ?q=ORD-2002.
  assert.equal(reasonOf(profile(undefined, { checks: [boundary('ANA-NO-SEARCH', 'ana', 'GET', '/api/search?q=ORD-2002', REFUSED), boundary('ANA-FLAGS', 'ana', 'GET', '/api/search?q&ORD-1001', [{ kind: 'status.equals', expected: 200 }])] }), 'ANA-NO-SEARCH'), 'refusal-twin-not-shown');
  // A longer declared value that folds over a shorter one never hides the shorter one's exact name.
  const overlap = structuredClone(profile(undefined, { checks: [gilSide('GIL-DELETE-JSON', 'DELETE', '/api/orders/ORD-2002.json', [{ kind: 'status.equals', expected: 204 }])] }));
  overlap.tenantValues.tenants.initech.identifiers.push('ord-2002.json');
  assert.equal(reasonOf(overlap, 'ANA-NO-GLOBEX-ORDER'), 'counterpart-written');
  // A write naming the record in another letter case, or as a JSON number written as a declared value, is seen too.
  const lower = gilSide('GIL-ARCHIVE-LOWER', 'POST', '/api/orders/ord-2002/archive', [{ kind: 'status.equals', expected: 200 }]);
  assert.equal(reasonOf(profile(undefined, { checks: [lower] }), 'ANA-NO-GLOBEX-ORDER'), 'counterpart-written');
  const tickets = structuredClone(profile(undefined, { mirrors: { ...MIRRORS, counterparts: [...MIRRORS.counterparts, ['7001', '8002']] }, checks: [boundary('ANA-NO-TICKET', 'ana', 'GET', '/api/tickets/8002', REFUSED),
    boundary('ANA-TICKET', 'ana', 'GET', '/api/tickets/7001', [{ kind: 'status.equals', expected: 200 }]), gilSide('GIL-TICKET', 'GET', '/api/tickets/8002', [{ kind: 'status.equals', expected: 200 }])] }));
  tickets.tenantValues.tenants.acme.identifiers.push('7001'); tickets.tenantValues.tenants.globex.identifiers.push('8002');
  assert.equal(mirrorOf(tickets, 'ANA-NO-TICKET').path, '/api/tickets/7001');
  tickets.checks.push(gilSide('GIL-TICKET-DELETE', 'POST', '/api/tickets/delete', [{ kind: 'status.equals', expected: 200 }], { body: { id: 8002 } }));
  assert.equal(reasonOf(tickets, 'ANA-NO-TICKET'), 'counterpart-written');
  // A turn on a declared read-only route is no write.
  const asked = profile(undefined, { checks: [boundary('GIL-ASKS', 'gil', 'POST', '/api/chat', ANSWERED, { body: { message: 'what is ORD-2002' } })] });
  assert.equal(validated(asked).checks.some(c => c.mirrorOf === 'ANA-NO-GLOBEX-ORDER'), true);
  // Related values: the twins must name the exact counterparts, in the same relation.
  const related = profile(undefined, { checks: [boundary('ANA-NO-COMPARE', 'ana', 'GET', '/api/orders/ORD-2002/compare/ORD-1001', REFUSED),
    boundary('ANA-COMPARE-OTHER', 'ana', 'GET', '/api/orders/ORD-1001/compare/ORD-1003', [{ kind: 'status.equals', expected: 200 }]),
    gilSide('GIL-COMPARE', 'GET', '/api/orders/ORD-2002/compare/ORD-2002', [{ kind: 'status.equals', expected: 200 }])], extra: {} });
  related.tenantValues.tenants.acme.identifiers.push('ORD-1003');
  assert.equal(reasonOf(related, 'ANA-NO-COMPARE'), 'refusal-twin-not-shown');
  related.checks.push(boundary('ANA-COMPARE-OWN', 'ana', 'GET', '/api/orders/ORD-1001/compare/ORD-1001', [{ kind: 'status.equals', expected: 200 }]));
  assert.equal(mirrorOf(related, 'ANA-NO-COMPARE').path, '/api/orders/ORD-1001/compare/ORD-2002');
  // A twin on another method does not show the route: the refused GET needs the first identity's own GET.
  assert.equal(reasonOf(profile(undefined, { checks: [boundary('ANA-NO-INVOICE-GET', 'ana', 'GET', '/api/invoices/ORD-2002', REFUSED), boundary('ANA-INVOICE-POST', 'ana', 'POST', '/api/invoices/ORD-1001', [{ kind: 'status.equals', expected: 200 }]),
    gilSide('GIL-INVOICE-GET', 'GET', '/api/invoices/ORD-2002', [{ kind: 'status.equals', expected: 200 }])] }), 'ANA-NO-INVOICE-GET'), 'refusal-twin-not-shown');
  // An encoded "?" in a segment is a segment, never the query mark.
  assert.equal(reasonOf(profile(undefined, { checks: [boundary('ENCODED-MARK', 'ana', 'GET', '/api/orders/ORD-2002/%3Fview', REFUSED), boundary('ANA-MARK', 'ana', 'GET', '/api/orders/ORD-1001?view', [{ kind: 'status.equals', expected: 200 }])] }), 'ENCODED-MARK'), 'refusal-twin-not-shown');
  // A read-only POST mirror needs the second identity's own turn on the same method.
  const getChat = structuredClone(profile()); Object.assign(getChat.checks.find(c => c.id === 'GIL-ASK'), { method: 'GET' }); delete getChat.checks.find(c => c.id === 'GIL-ASK').body;
  assert.equal(reasonOf(getChat, 'ANA-CHAT'), 'route-not-used-by-second-identity');
  // A read-only POST mirror needs the second identity's own turn there to expect a status the mirror expects.
  const created = structuredClone(profile()); created.checks.find(c => c.id === 'GIL-ASK').assertions = [{ kind: 'status.equals', expected: 201 }];
  assert.equal(reasonOf(created, 'ANA-CHAT'), 'route-not-used-by-second-identity');
  // A POST answer probe is a read only on a route the profile declares read-only.
  assert.equal(reasonOf(profile(undefined, { mirrors: { counterparts: MIRRORS.counterparts } }), 'ANA-CHAT'), 'success-not-a-read');
  // A sign-in redirect both identities declare is a boundary status.
  const redirect = structuredClone(profile(undefined, { checks: [boundary('REDIRECTED', 'ana', 'GET', '/api/orders/ORD-2002', [{ kind: 'status.in', expected: [303, 404] }])] }));
  redirect.actors.ana.signInRedirectStatus = 303; redirect.actors.gil.signInRedirectStatus = 303;
  assert.equal(mirrorOf(redirect, 'REDIRECTED').path, '/api/orders/ORD-1001');
  // A declared value inside which a principal id is written is read as the declared value, never rewritten in part.
  const numeric = structuredClone(profile(undefined, { checks: [boundary('INV', 'ana', 'GET', '/api/orders/INV-100', REFUSED)] })); numeric.actors.ana.principalId = '100'; numeric.actors.gil.principalId = '200';
  numeric.tenantValues.tenants.globex.identifiers.push('INV-100');
  assert.equal(reasonOf(numeric, 'INV'), 'tenant-value-without-counterpart');
  const shared = structuredClone(profile(undefined, { checks: [boundary('TEAM', 'ana', 'GET', '/api/orders/TEAM-77', REFUSED)] })); shared.tenantValues.tenants.acme.identifiers.push('TEAM-77'); shared.tenantValues.tenants.globex.identifiers.push('TEAM-77');
  assert.equal(reasonOf(shared, 'TEAM'), 'tenant-value-shared');
  assert.equal(reasonOf(profile(undefined, { mirrors: { counterparts: [] } }), 'ANA-NO-GLOBEX-ORDER'), 'tenant-value-without-counterpart');
  assert.equal(reasonOf(profile(undefined, { mirrors: null }), 'ANA-NO-GLOBEX-ORDER'), 'mirrors-undeclared');
  // Collisions: aliases that are route words and field names are never rewritten; the check is left out.
  const words = renamed(profile(undefined, { checks: [boundary('AGENT-CHAT', 'ana', 'POST', '/api/agent/chat', ANSWERED, { body: { message: 'list every order' } }),
    boundary('AGENT-FIELD', 'ana', 'POST', '/api/chat', ANSWERED, { body: { agent_id: 'desk', message: 'list every order' } })] }), { ana: 'agent', gil: 'rival' });
  assert.equal(reasonOf(words, 'AGENT-CHAT'), 'names-an-identity'); assert.equal(reasonOf(words, 'AGENT-FIELD'), 'names-an-identity');
  assert.equal(validated(words).checks.find(c => c.mirrorOf === 'ANA-CHAT').path, '/api/chat', 'an unrelated check of the same desk is mirrored as before');
  const short = renamed(profile(undefined, { checks: [boundary('SHORT', 'ana', 'GET', '/api/users/ana/orders', ANSWERED)] }), { gil: 'gi' });
  assert.equal(reasonOf(short, 'SHORT'), 'names-an-identity', 'one short alias does not stop the check being read for the other');
});

test('who gets a mirror: a second identity with another tenant, the same declared role and refusals; never controls, effects or captures', () => {
  const role = structuredClone(profile()); role.actors.gil.role = 'admin';
  assert.equal(reasonOf(role, 'ANA-CHAT'), 'no-second-identity');
  const refusals = structuredClone(profile()); refusals.actors.ana.refusesWith401 = true;
  assert.equal(reasonOf(refusals, 'ANA-CHAT'), 'no-second-identity', 'another refusal declaration');
  const noRole = structuredClone(profile()); delete noRole.actors.ana.role; delete noRole.actors.gil.role;
  assert.equal(reasonOf(noRole, 'ANA-CHAT'), 'role-undeclared', 'two actors without a role are not the same role');
  assert.equal(reasonOf(profile(undefined, { checks: [boundary('ANON', 'anonymous', 'GET', '/api/orders/ORD-2002', [{ kind: 'status.equals', expected: 401 }])] }), 'ANON'), 'actor-not-tenant-identity');
  for (const [extra, reason] of [[{ capture: { orderId: { pointer: '/id', type: 'id' } } }, 'uses-capture'], [{ applicability: { applies: false, reason: 'not on this build' } }, 'not-applicable']])
    assert.equal(reasonOf(profile(undefined, { checks: [boundary('SHAPED', 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: 'list every order' }, ...extra })] }), 'SHAPED'), reason, reason);
  const effects = boundary('WRITE', 'ana', 'POST', '/api/orders/ORD-2002/copy', [{ kind: 'status.in', expected: [403, 404] }], { effects: [{ kind: 'effect.none', select: { source: 'sql-snapshot', operation: 'update', name: 'orders' } }] });
  assert.equal(reasonOf(profile(undefined, { checks: [effects], extra: { observers: [] } }), 'WRITE'), 'uses-effects');
  // The plan reads only that a key is there (a validated target carries each one whole), so it is read here directly.
  const offline = () => { const v = structuredClone(validated(profile(undefined, { mirrors: 'off' }))); v.mirrors = structuredClone(MIRRORS); return v; };
  for (const [key, reason] of [['precondition', 'uses-precondition'], ['restsOn', 'uses-rests-on'], ['webhook', 'uses-webhook'], ['claims', 'uses-claims'], ['readBack', 'uses-read-back']]) {
    const v = offline(); v.checks.find(c => c.id === 'ANA-CHAT')[key] = [];
    assert.equal(mirrorPlan(v, plan(v)).plan.find(p => p.checkId === 'ANA-CHAT').reason, reason, key);
  }
  const used = offline(); used.checks.push(boundary('USES', 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: '{{orderId}}' } }));
  assert.equal(mirrorPlan(used, plan(used)).plan.find(p => p.checkId === 'USES').reason, 'uses-capture');
  for (const [key, reason] of [['lifecycle', 'lifecycle-declared'], ['timing', 'timing-declared']]) {
    const v = offline(); v[key] = {};
    assert.deepEqual(new Set(mirrorPlan(v, plan(v)).plan.map(p => p.reason)), new Set([reason]), key);
  }
  // A third identity: the one whose tenant the check names is the second identity.
  const three = structuredClone(profile(undefined, { checks: [boundary('ANA-NO-INITECH', 'ana', 'GET', '/api/orders/ORD-3003', REFUSED), boundary('ANA-OWN-1003', 'ana', 'GET', '/api/orders/ORD-1003', [{ kind: 'status.equals', expected: 200 }]),
    control('IAN-OWN', 'ian', '/api/orders/ORD-3003', [{ kind: 'status.equals', expected: 200 }]),
    control('IAN-ME', 'ian', '/api/me', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: 'ian@initech.example' }])],
    actors: { ian: { principalId: 'ian-1', tenantId: 'initech', role: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_IAN', identityValue: 'ian@initech.example' } }, mirrors: { counterparts: [['ORD-1001', 'ORD-2002'], ['ORD-1003', 'ORD-3003']] } }));
  three.requiredControlIds.push('IAN-ME', 'IAN-OWN'); three.tenantValues.tenants.acme.identifiers.push('ORD-1003');
  assert.deepEqual([mirrorOf(three, 'ANA-NO-INITECH').actorId, mirrorOf(three, 'ANA-NO-INITECH').path], ['ian', '/api/orders/ORD-1003']);
  assert.equal(reasonOf(profile(undefined, { mirrors: 'off' }), 'ANA-CHAT'), 'mirrors-off');
  assert.equal(validated(profile(undefined, { mirrors: 'off' })).checks.some(c => c.mirrorOf), false);
  const both = boundary('GIL-CHAT', 'gil', 'POST', '/api/chat', ANSWERED, { body: { message: 'list every order' } });
  assert.equal(reasonOf(profile(undefined, { checks: [both] }), 'ANA-CHAT'), 'already-declared');
  assert.equal(reasonOf(profile(undefined, { checks: [boundary('ANA-CHAT-mirror', 'ana', 'GET', '/api/x', [{ kind: 'status.equals', expected: 403 }])] }), 'ANA-CHAT'), 'mirror-id-unavailable');
  const long = boundary('L'.repeat(75), 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: 'what now' } });
  assert.equal(reasonOf(profile(undefined, { checks: [long] }), long.id), 'mirror-id-unavailable');
  for (const reason of ['mirrors-off', 'role-undeclared', 'names-an-identity', 'route-not-used-by-second-identity', 'uses-effects', 'undeclared-identifier', 'predicate-names-own-view', 'profile-rule', 'tenant-value-shared']) assert(MIRROR_SKIP_REASONS.includes(reason));
});

test('a declared mirror must be exactly the generated one, in canonical order; a mirror that would break a rule is left out alone', () => {
  const v = validated(profile());
  const edited = structuredClone(v); edited.checks.find(c => c.id === 'ANA-CHAT-mirror').path = '/api/chat?x=1';
  assert.throws(() => validated(edited), /"mirrors": check "ANA-CHAT-mirror": a check that declares "mirrorOf" must be exactly the mirror/);
  const stray = structuredClone(v); stray.checks.find(c => c.id === 'ANA-CHAT-mirror').mirrorOf = 'ANA-ME';
  assert.throws(() => validated(stray), /must be exactly the mirror/);
  const off = structuredClone(v); off.mirrors = 'off';
  assert.throws(() => validated(off), /must be exactly the mirror/);
  assert.throws(() => mirrorChecks({ ...v, checks: [...v.checks, { ...v.checks.at(-1), id: 'X', mirrorOf: '__proto__' }] }, plan(v)), /"mirrorOf" must name a check/);
  const moved = structuredClone(v); moved.checks = [...moved.checks.slice(-2), ...moved.checks.slice(0, -2)];
  assert.deepEqual(validated(moved).checks.map(c => c.id), v.checks.map(c => c.id));
  const partial = structuredClone(v); partial.checks = partial.checks.filter(c => c.id !== 'ANA-NO-GLOBEX-ORDER-mirror');
  assert.deepEqual(validated(partial).checks.map(c => c.id), v.checks.map(c => c.id));
  assert.equal(contractDigest(validated(moved)), contractDigest(v));
  const bad = [
    [{ counterparts: [['ORD-1001', 'ORD-9999']] }, /written exactly as one tenant/], [{ counterparts: [['ORD-1001', 'Ada Lovelace']] }, /two different tenants/],
    [{ counterparts: [['ORD-1001', 'ORD-2002'], ['ORD-1001', 'ORD-3003']] }, /at most one pair/], [{ counterparts: [['ORD-1001']] }, /a pair is two strings/], [{ pairs: [] }, /must be "off" or/], ['on', /must be "off" or/],
    [{ counterparts: [], readOnlyRoutes: ['GET /api/chat'] }, /a route is "POST \/path" \(no query\)/], [{ counterparts: [], readOnlyRoutes: ['POST /api/chat?x=1'] }, /no query/],
    [{ counterparts: [], readOnlyRoutes: ['POST /api/elsewhere'] }, /no declared check uses it/], [{ counterparts: [], readOnlyRoutes: null }, /"readOnlyRoutes" must be a list/], [{ counterparts: null }, /"counterparts" must be a list/], [{ counterparts: [], readOnlyRoutes: ['POST /api/chat', 'POST /api/chat'] }, /distinct routes/],
    // The mirror phase's declared rate-limit answers: never a status a mirror expects, and 429 is always one.
    [{ counterparts: [], rateLimitStatuses: 503 }, /"rateLimitStatuses" must be a list/], [{ counterparts: [], rateLimitStatuses: [503, 503] }, /distinct statuses/], [{ counterparts: [], rateLimitStatuses: [500, 502, 503, 504, 599] }, /at most 4/],
    [{ counterparts: [], rateLimitStatuses: [200] }, /rate-limit status 1: a status from 400 to 599/], [{ counterparts: [], rateLimitStatuses: [302] }, /from 400 to 599/], [{ counterparts: [], rateLimitStatuses: ['503'] }, /from 400 to 599/],
    [{ counterparts: [], rateLimitStatuses: [503, 403] }, /rate-limit status 2: 401, 403 and 404 are the boundary refusals/], [{ counterparts: [], rateLimitStatuses: [401] }, /boundary refusals/], [{ counterparts: [], rateLimitStatuses: [404] }, /boundary refusals/],
    [{ counterparts: [], rateLimitStatuses: [429] }, /429 is always read as a limit answer/],
  ];
  for (const [mirrors, pattern] of bad) assert.throws(() => validated(profile(undefined, { mirrors })), pattern, JSON.stringify(mirrors));
  // Declared, they change no mirror, only the profile's identity.
  const limited = validated(profile(undefined, { mirrors: { ...MIRRORS, rateLimitStatuses: [503, 409] } }));
  assert.deepEqual(limited.checks, v.checks);
  assert.notEqual(contractDigest(limited), contractDigest(v));
  const shared = structuredClone(profile()); shared.tenantValues.tenants.globex.identifiers.push('ORD-1001');
  assert.throws(() => validated(shared), /written exactly as one tenant/, 'a value two tenants declare cannot be a counterpart');
  const noValues = structuredClone(profile()); delete noValues.tenantValues; noValues.checks = noValues.checks.filter(c => !c.assertions.some(a => a.kind === 'json.noForeignValues'));
  assert.throws(() => validated(noValues), /needs the target to declare "tenantValues"/);
  // One mirror over the profile's timeout total is left out alone; the others stay.
  const slow = boundary('ASK-SLOW', 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: 'think long' }, timeoutMs: 120000 });
  const slowProfile = profile(undefined, { checks: [slow, ...Array.from({ length: 3 }, (_, i) => boundary(`ASK-WAIT-${'abc'[i]}`, 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: `wait ${'abc'[i]}` }, timeoutMs: 120000 }))] });
  const loaded = validated(slowProfile), report = mirrorReport(loaded, plan(loaded));
  assert.deepEqual(report.mirrored.map(m => m.checkId), ['ANA-NO-GLOBEX-ORDER', 'ANA-CHAT', 'ASK-SLOW']);
  assert.deepEqual(report.notMirrored.map(n => [n.checkId, n.reason]), [['ASK-WAIT-a', 'profile-rule'], ['ASK-WAIT-b', 'profile-rule'], ['ASK-WAIT-c', 'profile-rule']]);
  // Over the check limit: the profile loads with as many mirrors as fit (an unrelated target in the same file too).
  const many = profile(undefined, { checks: Array.from({ length: 98 }, (_, i) => boundary(`ASK-${i}`, 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: `question ${'abcdefghij'[i % 10]}${'abcdefghij'[Math.floor(i / 10)]}` } })) });
  const other = { ...structuredClone(profile()), id: 'other-desk' };
  const [full, unrelated] = validateTargetFile({ schemaVersion: 1, targets: [many, other] });
  assert.equal(full.checks.length, 200); assert.equal(full.checks.filter(c => c.mirrorOf).length, 95);
  assert.equal(unrelated.checks.filter(c => c.mirrorOf).length, 2);
  // Over the request plan (each mirror adds a probe point for each control of the second identity): the first mirrors that
  // fit, one at a time in canonical order; the rest are profile-rule.
  const letters = i => 'abcdefghij'[i % 10] + 'abcdefghij'[Math.floor(i / 10)];
  const pages = Array.from({ length: 39 }, (_, i) => control(`GIL-PAGE-${i}`, 'gil', `/api/pages/${letters(i)}`, [{ kind: 'status.equals', expected: 200 }]));
  const busy = profile(undefined, { checks: [...pages, ...Array.from({ length: 60 }, (_, i) => boundary(`ASKS-${i}`, 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: `question ${letters(i)}` } }))] });
  busy.requiredControlIds.push(...pages.map(c => c.id));
  const planned = validated(busy), kept = planned.checks.filter(c => c.mirrorOf), generated = mirrorPlan(planned, plan(planned)).plan.filter(p => p.mirror);
  assert.equal(generated.length, 62);
  assert(kept.length > 0 && kept.length < 62, `${kept.length} mirrors kept`);
  assert.deepEqual(kept.map(c => c.mirrorOf), generated.slice(0, kept.length).map(p => p.checkId), 'the first ones, in canonical order');
  assert.equal(mirrorReport(planned, plan(planned)).notMirrored.filter(n => n.reason === 'profile-rule').length, 62 - kept.length);
});

test('mirrors are opt-in: a target with no "mirrors" object gets none and keeps exactly its declared checks and digest', () => {
  const declared = profile(undefined, { mirrors: null }), v = validated(declared);
  assert.equal(Object.hasOwn(declared, 'mirrors'), false);
  assert.deepEqual(v.checks.map(c => c.id), declared.checks.map(c => c.id), 'no mirror, the declared checks in their order');
  assert.equal(v.checks.some(c => Object.hasOwn(c, 'mirrorOf')), false);
  assert.equal(Object.hasOwn(v, 'mirrors'), false);
  // The digest an earlier build computed for this very profile.
  assert.equal(contractDigest(v), '4fe1dc01fde69fe8a336eef46eefb7c15de628fcd79504ef479500fd70d1fac3');
  const report = mirrorReport(v, plan(v));
  assert.deepEqual([report.mirrored, report.extraRequests, new Set(report.notMirrored.map(n => n.reason))], [[], [], new Set(['mirrors-undeclared'])]);
  assert.equal(identityCoverage(v, plan(v)).singleIdentity, false, 'the two-identity requirement still holds');
  // Declared again, the same checks get their mirrors.
  assert.equal(validated(profile()).checks.filter(c => c.mirrorOf).length, 2);
});

test('mirrors are part of the profile identity', () => {
  assert.notEqual(contractDigest(validated(profile())), contractDigest(validated(profile(undefined, { mirrors: 'off' }))));
  // The declaration itself, too: a pair no check uses changes no mirror but changes the identity.
  const more = profile(undefined, { mirrors: { ...MIRRORS, counterparts: [['ORD-1001', 'ORD-2002'], ['Ada Lovelace', 'Bob Byte']] } });
  assert.deepEqual(validated(more).checks, validated(profile()).checks);
  assert.notEqual(contractDigest(validated(more)), contractDigest(validated(profile())));
  const v = validated(profile(undefined, { checks: [boundary('NO-RECORD', 'ana', 'GET', '/api/records/latest', [{ kind: 'status.in', expected: [403, 404] }])] }));
  assert.deepEqual(mirrorReport(v, plan(v)), { tenantScoped: true, identities: ['ana', 'gil'], distinctTenants: 2, singleIdentity: false, extraRequests: [{ actorId: 'gil', mirrors: 2, requests: 8 }],
    mirrored: [{ checkId: 'ANA-NO-GLOBEX-ORDER', mirrorId: 'ANA-NO-GLOBEX-ORDER-mirror', actorId: 'gil' }, { checkId: 'ANA-CHAT', mirrorId: 'ANA-CHAT-mirror', actorId: 'gil' }],
    notMirrored: [{ checkId: 'NO-RECORD', reason: 'resource-owner-unknown' }] });
});

// The owned stand-in. Fixed: every reply is the caller's own tenant, and every other route answers by its own rules (a
// user's page refuses anyone else, an unknown route 404). Defective (asymmetric): a globex caller also gets acme's order,
// on the order route and in the chat reply; an acme caller is still refused, so the declared one-sided profile passes.
const ORDERS = { 'ORD-1001': { tenant: 'acme', customer: 'Ada Lovelace' }, 'ORD-2002': { tenant: 'globex', customer: 'Bob Byte' } };
const WHO = { [TOKENS.ana]: { email: 'ana@acme.example', tenant: 'acme', alias: 'ana' }, [TOKENS.gil]: { email: 'gil@globex.example', tenant: 'globex', alias: 'gil' } };
async function desk(t, build) {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    let body = ''; req.on('data', d => { body += d; }); req.on('end', () => {
      const json = (status, value) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
      const who = WHO[(req.headers.authorization ?? '').replace(/^Bearer /, '')], url = req.url.split('?')[0];
      if (!who) return json(401, { error: 'sign in' });
      if (url === '/api/me') return json(200, { email: who.email });
      const leaks = build === 'defective' && who.tenant === 'globex';
      const mine = id => ORDERS[id].tenant === who.tenant || leaks;
      const order = /^\/api\/orders\/(ORD-\d{4})$/.exec(url);
      if (order && ORDERS[order[1]] && mine(order[1])) return json(200, { id: order[1], customer: ORDERS[order[1]].customer });
      if (order) return json(404, { error: 'not found' });
      const user = /^\/api\/users\/([a-z]+)\/orders$/.exec(url);
      if (user) return user[1] === who.alias ? json(200, { reply: `Orders: ${Object.keys(ORDERS).filter(mine).join(' ')}` }) : json(403, { error: 'not yours' });
      if (req.method === 'POST' && url === '/api/chat') return json(200, { reply: `Your orders: ${Object.keys(ORDERS).filter(mine).join(' ')}`, user: who.email });
      json(404, { error: 'not found' });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { origin: `http://127.0.0.1:${server.address().port}`, seen };
}
const statuses = run => Object.fromEntries(run.results.map(r => [r.id, r.status]));

test('a per-user request limit: check-config reports the extra requests mirrors add, the headroom that keeps them decided', () => {
  const v = validated(profile());
  // gil holds both mirrors: each adds its request, and the mirror phase a probe point of gil's identity and surface controls
  // (GIL-ME, GIL-OWN) before its first mirror and after each: 2 + 3 x 2 (test/mirror-phase.test.mjs measures it).
  assert.deepEqual(mirrorReport(v, plan(v)).extraRequests, [{ actorId: 'gil', mirrors: 2, requests: 8 }]);
  assert.deepEqual(mirrorReport(validated(profile(undefined, { mirrors: 'off' })), plan(validated(profile(undefined, { mirrors: 'off' })))).extraRequests, []);
});

test('fixed twin: every check and mirror passes, the adversarial patterns included; the asymmetric defect passes the declared side and fails its mirror', async t => {
  const fixed = await desk(t, 'fixed');
  const patterns = [boundary('ANA-OWN-ROUTE', 'ana', 'GET', '/api/users/ana/orders', ANSWERED), boundary('ANA-ASKS-GLOBEX', 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: 'what is ORD-2002' } }),
    boundary('ANA-ORG-ROUTE', 'ana', 'GET', '/api/users/ana/orders?org=acme', ANSWERED), boundary('ANA-SLUG', 'ana', 'POST', '/api/records/alpha/comments', [{ kind: 'status.in', expected: [403, 404] }], { body: { text: 'see ORD-2002' } })];
  const p = profile(fixed.origin, { checks: patterns });
  assert.deepEqual(mirrorReport(validated(p), plan(validated(p))).mirrored.map(m => m.checkId), ['ANA-NO-GLOBEX-ORDER', 'ANA-CHAT', 'ANA-ASKS-GLOBEX']);
  const clean = await runHttpAssessment(p, { env: ENV });
  assert.deepEqual(Object.entries(statuses(clean)).filter(([, s]) => s !== 'pass'), [], 'every check and mirror passes on the correct app');
  assert(fixed.seen.includes('GET /api/orders/ORD-1001'), 'the mirrors were sent');
  const defective = await desk(t, 'defective');
  const run = await runHttpAssessment(profile(defective.origin), { env: ENV });
  const s = statuses(run);
  assert.deepEqual([s['ANA-NO-GLOBEX-ORDER'], s['ANA-CHAT']], ['pass', 'pass'], 'the declared side cannot see the leak');
  assert.deepEqual([s['ANA-NO-GLOBEX-ORDER-mirror'], s['ANA-CHAT-mirror']], ['fail', 'fail'], 'its mirror under the second identity does');
  assert.equal(run.results.find(r => r.id === 'ANA-CHAT-mirror').assertions.find(a => a.name.startsWith('json.noForeignValues')).status, 'fail', 'the mirror\'s TENANT scan read gil\'s tenant');
  const off = await runHttpAssessment(profile(defective.origin, { mirrors: 'off' }), { env: ENV });
  assert.equal(Object.values(statuses(off)).every(v => v === 'pass'), true, 'with mirrors off the same defective build reads clean');
});

// A correct two-tenant app with state, plans and undeclared records (adversarial patterns): ORD-1001 is acme's,
// shipped and refunded; ORD-2002 globex's and open (a cancel changes it); order 7731 acme's but undeclared; record 7
// globex's; only acme's plan has exports. Every reply and refusal is the caller's own tenant's. Each write it accepts is
// logged, so a mirror that writes is seen.
async function stateful(t) {
  const orders = { 'ORD-1001': { tenant: 'acme', customer: 'Ada Lovelace', state: 'shipped', refund: { amount: 5 } }, 'ORD-2002': { tenant: 'globex', customer: 'Bob Byte', state: 'open' }, 7731: { tenant: 'acme', customer: 'Ada Lovelace', state: 'open' } };
  const writes = [];
  const server = createServer((req, res) => {
    let body = ''; req.on('data', d => { body += d; }); req.on('end', () => {
      const json = (status, value) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
      const who = WHO[(req.headers.authorization ?? '').replace(/^Bearer /, '')], url = req.url.split('?')[0];
      if (!who) return json(401, { error: 'sign in' });
      const mine = id => orders[id]?.tenant === who.tenant;
      let m;
      if (url === '/api/me') return json(200, { email: who.email });
      if (req.method === 'POST' && url === '/api/chat') return json(200, { reply: `Your orders: ${Object.keys(orders).filter(mine).join(' ')}` });
      if (req.method === 'GET' && (m = /^\/api\/orders\/([A-Z0-9-]+)$/.exec(url))) return mine(m[1]) ? json(200, { id: m[1], customer: orders[m[1]].customer, state: orders[m[1]].state, ...(orders[m[1]].refund ? { refund: orders[m[1]].refund } : {}) }) : json(404, { error: 'not found' });
      if (req.method === 'POST' && (m = /^\/api\/orders\/([A-Z0-9-]+)\/cancel$/.exec(url))) {
        if (!mine(m[1])) return json(404, { error: 'not found' });
        if (orders[m[1]].state !== 'open') return json(409, { error: 'not open' });
        orders[m[1]].state = 'cancelled'; writes.push(`${who.alias} cancel ${m[1]}`); return json(200, { id: m[1], state: 'cancelled' });
      }
      if (req.method === 'POST' && url === '/api/records/7/comments') { if (who.tenant !== 'globex') return json(404, { error: 'not found' }); writes.push(`${who.alias} comment 7`); return json(201, { ok: true }); }
      if (req.method === 'GET' && url === '/api/reports/export') return who.tenant === 'acme' ? json(200, { rows: Object.keys(orders).filter(mine) }) : json(403, { error: 'your plan has no exports' });
      if (req.method === 'GET' && url === '/api/audit') return who.tenant === 'acme' ? json(200, { entries: [] }) : json(404, { error: 'not found' });
      json(404, { error: 'not found' });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { origin: `http://127.0.0.1:${server.address().port}`, writes, orders };
}

test('a correct app with plans, record state and undeclared records passes every mirror, twice, and no mirror writes', async t => {
  const app = await stateful(t), NFV = pointer => ({ kind: 'json.noForeignValues', pointer });
  const cases = [
    boundary('GIL-COMMENT-OWN', 'gil', 'POST', '/api/records/7/comments', [{ kind: 'status.equals', expected: 201 }], { body: { text: 'my own note' } }),
    boundary('ANA-COMMENT-7', 'ana', 'POST', '/api/records/7/comments', [{ kind: 'status.in', expected: [403, 404] }, NFV('')], { body: { text: 'see ORD-2002' } }),
    boundary('ANA-READS-7731', 'ana', 'GET', '/api/orders/7731', [{ kind: 'status.equals', expected: 200 }, NFV('')]),
    boundary('GIL-NO-7731', 'gil', 'GET', '/api/orders/7731', [{ kind: 'status.in', expected: [403, 404] }, NFV('')]),
    boundary('ANA-EXPORT', 'ana', 'GET', '/api/reports/export', [{ kind: 'status.equals', expected: 200 }, NFV('/rows')]),
    boundary('GIL-EXPORT-GATED', 'gil', 'GET', '/api/reports/export', [{ kind: 'status.equals', expected: 403 }]),
    boundary('ANA-CANCEL-SHIPPED', 'ana', 'POST', '/api/orders/ORD-1001/cancel', [{ kind: 'status.equals', expected: 409 }]),
    boundary('GIL-NO-CANCEL-ACME', 'gil', 'POST', '/api/orders/ORD-1001/cancel', [{ kind: 'status.in', expected: [403, 404] }]),
    boundary('ANA-REFUND-VISIBLE', 'ana', 'GET', '/api/orders/ORD-1001', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/refund', expected: true }]),
    boundary('GIL-AUDIT', 'gil', 'GET', '/api/audit', [{ kind: 'status.equals', expected: 200 }], { applicability: { applies: false, reason: 'no audit log on this plan' } }),
    boundary('ANA-AUDIT', 'ana', 'GET', '/api/audit', [{ kind: 'status.equals', expected: 200 }, NFV('')]),
  ];
  const p = profile(app.origin, { checks: cases }), report = mirrorReport(validated(p), plan(validated(p)));
  assert.deepEqual(report.mirrored.map(m => m.checkId), ['ANA-NO-GLOBEX-ORDER', 'ANA-CHAT']);
  assert.deepEqual(Object.fromEntries(report.notMirrored.map(n => [n.checkId, n.reason])), { 'GIL-COMMENT-OWN': 'undeclared-identifier', 'ANA-COMMENT-7': 'undeclared-identifier', 'ANA-READS-7731': 'undeclared-identifier',
    'GIL-NO-7731': 'undeclared-identifier', 'ANA-EXPORT': 'contradicts-second-identity-check', 'GIL-EXPORT-GATED': 'resource-owner-unknown', 'ANA-CANCEL-SHIPPED': 'refusal-not-boundary-status',
    'GIL-NO-CANCEL-ACME': 'refusal-not-a-read', 'ANA-REFUND-VISIBLE': 'predicate-names-own-view', 'GIL-AUDIT': 'not-applicable', 'ANA-AUDIT': 'route-not-used-by-second-identity' });
  const first = await runHttpAssessment(p, { env: ENV }), second = await runHttpAssessment(p, { env: ENV });
  for (const run of [first, second]) assert.deepEqual(Object.entries(statuses(run)).filter(([id, s]) => s !== 'pass' && id !== 'GIL-AUDIT'), [], 'every applicable check and mirror passes');
  assert.deepEqual(app.writes, ['gil comment 7', 'gil comment 7'], 'only the declared write was made, once a run');
  assert.equal(app.orders['ORD-2002'].state, 'open', 'no mirror cancelled an order');
  const { compareRuns } = await import('../src/runner.mjs');
  assert.deepEqual(compareRuns(first, second).rows.filter(r => r.before !== r.after), [], 'nothing differs between the two runs');
});

// A second correct app: workspaces with undeclared slugs (alpha is acme's, beta globex's) whose search, task
// filter, guest invites and watcher removals answer only members; an assistant that acts ("cancel my latest order"); a
// create route that answers 200; a refund sub-resource that exists only for refunded orders (ORD-1001 and ORD-2003, not
// ORD-2002). Every accepted write is logged.
async function workspaces(t) {
  const orders = { 'ORD-1001': { tenant: 'acme', state: 'open', refunded: true }, 'ORD-2002': { tenant: 'globex', state: 'open' }, 'ORD-2003': { tenant: 'globex', state: 'shipped', refunded: true } };
  const spaces = { alpha: 'acme', beta: 'globex' }, writes = [];
  const server = createServer((req, res) => {
    let body = ''; req.on('data', d => { body += d; }); req.on('end', () => {
      const json = (status, value) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(status === 204 ? undefined : JSON.stringify(value)); };
      const who = WHO[(req.headers.authorization ?? '').replace(/^Bearer /, '')], [url, query = ''] = req.url.split('?'), params = new URLSearchParams(query);
      if (!who) return json(401, { error: 'sign in' });
      const mine = id => orders[id]?.tenant === who.tenant;
      let m;
      if (url === '/api/me') return json(200, { email: who.email });
      if (req.method === 'GET' && (m = /^\/api\/orders\/([A-Z0-9-]+)$/.exec(url))) return mine(m[1]) ? json(200, { id: m[1], state: orders[m[1]].state }) : json(404, { error: 'not found' });
      if (req.method === 'GET' && (m = /^\/api\/orders\/([A-Z0-9-]+)\/refund$/.exec(url))) return mine(m[1]) && orders[m[1]].refunded ? json(200, { order: m[1], refunded: true }) : json(404, { error: 'not found' });
      if (req.method === 'POST' && url === '/api/chat') {
        const latest = Object.keys(orders).filter(id => mine(id) && orders[id].state === 'open').at(-1);
        if (/cancel my latest order/.test(body) && latest) { orders[latest].state = 'cancelled'; writes.push(`${who.alias} cancelled ${latest} through the assistant`); return json(200, { reply: 'Cancelled your latest order.' }); }
        return json(200, { reply: `Your orders: ${Object.keys(orders).filter(mine).join(' ')}` });
      }
      if (req.method === 'POST' && url === '/api/notes') { writes.push(`${who.alias} created a note`); return json(200, { ok: true }); }
      if ((m = /^\/api\/workspaces\/([a-z]+)\/(.+)$/.exec(url))) {
        const [, space, rest] = m;
        if (spaces[space] !== who.tenant) return json(403, { error: 'not a member' });
        if (req.method === 'GET' && rest === 'search') return json(200, { results: Object.keys(orders).filter(id => mine(id) && id === params.get('q')) });
        if (req.method === 'GET' && rest === 'tasks') return json(200, { tasks: [] });
        if (req.method === 'POST' && rest.startsWith('invites/')) { writes.push(`${who.alias} invited a guest to ${space}`); return json(201, { invited: true }); }
        if (req.method === 'DELETE' && rest.startsWith('watchers/')) { writes.push(`${who.alias} removed a watcher from ${space}`); return json(204); }
      }
      json(404, { error: 'not found' });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { origin: `http://127.0.0.1:${server.address().port}`, writes };
}

test('the workspace app\'s patterns: slugs, searches, filters, invites, acting turns, create routes and record state are never mirrored into a FAIL or a write', async t => {
  const NFV = pointer => ({ kind: 'json.noForeignValues', pointer }), OK = status => [{ kind: 'status.equals', expected: status }];
  const cases = [
    boundary('ANA-NO-BETA-SEARCH', 'ana', 'GET', '/api/workspaces/beta/search?q=ORD-2002', REFUSED), boundary('GIL-BETA-SEARCH', 'gil', 'GET', '/api/workspaces/beta/search?q=ORD-2002', [...OK(200), NFV('/results')]),
    boundary('ANA-NO-BETA-TASKS', 'ana', 'GET', '/api/workspaces/beta/tasks?assignee=bob@globex.example', [...OK(403), NFV('')]), boundary('GIL-BETA-TASKS', 'gil', 'GET', '/api/workspaces/beta/tasks?assignee=bob@globex.example', [...OK(200), NFV('')]),
    boundary('ANA-NO-BETA-INVITE', 'ana', 'POST', '/api/workspaces/beta/invites/bob@globex.example', [{ kind: 'status.in', expected: [403, 404] }]), boundary('GIL-BETA-INVITE', 'gil', 'POST', '/api/workspaces/beta/invites/bob@globex.example', OK(201)),
    boundary('ANA-NO-BETA-UNWATCH', 'ana', 'DELETE', '/api/workspaces/beta/watchers/bob@globex.example', [{ kind: 'status.in', expected: [403, 404] }]), boundary('GIL-BETA-UNWATCH', 'gil', 'DELETE', '/api/workspaces/beta/watchers/bob@globex.example', OK(204)),
    boundary('ANA-AGENT-CANCEL', 'ana', 'POST', '/api/chat', [...OK(200), NFV('/reply')], { body: { message: 'cancel my latest order' } }),
    boundary('ANA-NOTE', 'ana', 'POST', '/api/notes', [...OK(200), NFV('')], { body: { title: 'weekly summary' } }),
    boundary('ANA-REFUND-OWN', 'ana', 'GET', '/api/orders/ORD-1001/refund', [...OK(200), NFV('')]), boundary('GIL-REFUND-OTHER', 'gil', 'GET', '/api/orders/ORD-2003/refund', [...OK(200), NFV('')]),
  ];
  const tenantValues = { tenants: { acme: { identifiers: ['ORD-1001', 'Ada Lovelace', 'ada@acme.example'], attributes: ['Blue Widget'] }, globex: { identifiers: ['ORD-2002', 'ORD-2003', 'Bob Byte', 'bob@globex.example'] }, initech: { identifiers: ['ORD-3003'] } } };
  const declare = (origin, mirrors) => profile(origin, { checks: cases, mirrors, extra: { tenantValues } });
  // The chat route is not declared read-only here: the profile has an acting turn on it.
  const mirrors = { counterparts: [['ORD-1001', 'ORD-2002'], ['ada@acme.example', 'bob@globex.example']] };
  const v = validated(declare(undefined, mirrors)), report = mirrorReport(v, plan(v));
  assert.deepEqual(report.mirrored.map(m => m.checkId), ['ANA-NO-GLOBEX-ORDER']);
  const reasons = Object.fromEntries(report.notMirrored.map(n => [n.checkId, n.reason]));
  assert.deepEqual([reasons['ANA-NO-BETA-SEARCH'], reasons['ANA-NO-BETA-TASKS'], reasons['ANA-NO-BETA-INVITE'], reasons['ANA-NO-BETA-UNWATCH']], ['refusal-twin-not-shown', 'refusal-twin-not-shown', 'refusal-not-a-read', 'refusal-not-a-read']);
  assert.deepEqual([reasons['GIL-BETA-SEARCH'], reasons['ANA-REFUND-OWN']], Array(2).fill('route-not-used-by-second-identity'));
  assert.equal(reasons['GIL-BETA-TASKS'], 'counterpart-written', 'gil\'s declared invite writes to bob@globex.example');
  assert.deepEqual([reasons['GIL-BETA-INVITE'], reasons['GIL-BETA-UNWATCH'], reasons['ANA-AGENT-CANCEL'], reasons['ANA-NOTE'], reasons['ANA-CHAT']], Array(5).fill('success-not-a-read'));
  assert.equal(reasons['GIL-REFUND-OTHER'], 'tenant-value-without-counterpart');
  // Two runs with mirrors and two without, each on an app of its own: every check passes, and the writes are the same.
  const on = await workspaces(t), off = await workspaces(t);
  for (const [app, decl] of [[on, mirrors], [off, 'off']]) for (let i = 0; i < 2; i++) {
    const run = await runHttpAssessment(declare(app.origin, decl), { env: ENV });
    assert.deepEqual(Object.entries(statuses(run)).filter(([, status]) => status !== 'pass'), [], `${decl === 'off' ? 'mirrors off' : 'mirrors on'}, run ${i + 1}`);
  }
  assert.deepEqual(on.writes, off.writes, 'no mirror wrote');
});

const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const spawned = (args, env = ENV) => new Promise(resolve => {
  const child = spawn(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH, ...env } });
  let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
  child.on('close', code => resolve({ code, stdout, stderr }));
});
function files(t, p) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven two identities ')); chmodSync(dir, 0o700);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = join(dir, 'profiles.json'); writeFileSync(config, JSON.stringify({ schemaVersion: 1, targets: [p] }));
  return { dir, config, record: writeTestAuthorization(join(dir, 'record.json'), p) };
}
// The configured target's entry (the built-in fixture targets are listed first).
const desk2 = r => JSON.parse(r.stdout).targets.find(t => t.id === 'two-desk');
// One identity: gil and its controls removed (tenantValues still declares both tenants).
const single = origin => { const p = structuredClone(profile(origin, { mirrors: null })); delete p.actors.gil; p.checks = p.checks.filter(c => c.actorId !== 'gil'); p.requiredControlIds = ['ANA-ME', 'ANA-OWN']; return p; };

test('check-config: the two-identity report, and a warning (exit 0) for a single-identity target or one with no mirror', async t => {
  const two = files(t, profile());
  const ok = await spawned(['--config', two.config, '--check-config']);
  assert.equal(ok.code, 0, ok.stderr);
  assert.deepEqual(desk2(ok).twoIdentities.mirrored.map(m => m.mirrorId), ['ANA-NO-GLOBEX-ORDER-mirror', 'ANA-CHAT-mirror']);
  assert.equal(desk2(ok).checks, 9, 'the check count includes the mirrors');
  assert.doesNotMatch(ok.stderr, /Warning/);
  const one = files(t, single('http://127.0.0.1:5001'));
  const warned = await spawned(['--config', one.config, '--check-config']);
  assert.equal(warned.code, 0);
  assert.equal(desk2(warned).twoIdentities.singleIdentity, true);
  assert.match(warned.stderr, /Warning: target two-desk declares tenant-scoped resources \("tenantValues"\) but fewer than two credentialed identities \(actors with an "identityValue", a declared "tenantId" and an identity control\)/);
  // Mirrors are opt-in: a declared "mirrors" object that yields no mirror warns; no "mirrors" key, or "off", does not.
  const none = files(t, profile(undefined, { mirrors: { counterparts: [] } }));
  assert.match((await spawned(['--config', none.config, '--check-config'])).stderr, /Warning: target two-desk declares tenant-scoped resources but no boundary check was mirrored/);
  for (const mirrors of [null, 'off']) assert.doesNotMatch((await spawned(['--config', files(t, profile(undefined, { mirrors })).config, '--check-config'])).stderr, /Warning/, String(mirrors));
  const plainProfile = structuredClone(single('http://127.0.0.1:5001')); delete plainProfile.tenantValues; plainProfile.checks = plainProfile.checks.filter(c => !c.assertions.some(a => a.kind === 'json.noForeignValues'));
  const plain = await spawned(['--config', files(t, plainProfile).config, '--check-config']);
  assert.equal(plain.code, 0); assert.equal(Object.hasOwn(desk2(plain), 'twoIdentities'), false); assert.doesNotMatch(plain.stderr, /Warning/);
  const misused = await spawned(['--config', two.config, '--check-config', '--single-identity']);
  assert.equal(misused.code, 2); assert.match(misused.stderr, /--single-identity applies to an assess run only/);
  // --list lists the same targets and prints neither warning.
  for (const config of [one.config, none.config]) {
    const [listed, checked] = [await spawned(['--config', config, '--list']), await spawned(['--config', config, '--check-config'])];
    assert.equal(listed.code, 0); assert.equal(listed.stderr, ''); assert.equal(listed.stdout, checked.stdout); assert.match(checked.stderr, /Warning/);
  }
});

test('assess refuses a single-identity target before authorization or any request, unless --single-identity; it warns when nothing was mirrored', async t => {
  const app = await desk(t, 'fixed'), one = files(t, single(app.origin)), out = join(one.dir, 'out');
  const unauthorized = await spawned(['--config', one.config, '--target', 'two-desk', '--out', out]);
  assert.equal(unauthorized.code, 2); assert.match(unauthorized.stderr, /Single identity refused: target two-desk declares tenant-scoped resources/);
  const refused = await spawned(['--config', one.config, '--target', 'two-desk', '--out', out, '--authorization', one.record]);
  assert.equal(refused.code, 2); assert.match(refused.stderr, /Single identity refused/);
  assert.deepEqual(app.seen, [], 'nothing was sent'); assert.equal(existsSync(join(out, 'runs')), false, 'no run was saved');
  const waived = await spawned(['--config', one.config, '--target', 'two-desk', '--out', out, '--authorization', one.record, '--single-identity']);
  assert.notEqual(waived.code, 2, waived.stderr);
  assert.equal(JSON.parse(waived.stdout).singleIdentity, 'run with --single-identity: cross-tenant checks ran from one side only');
  assert.equal(readdirSync(join(out, 'runs')).filter(f => f.endsWith('.json')).length, 1);
  const two = files(t, profile(app.origin)), twoOut = join(two.dir, 'out');
  const ran = await spawned(['--config', two.config, '--target', 'two-desk', '--out', twoOut, '--authorization', two.record]);
  assert.equal(ran.code, 0, ran.stderr);
  assert.equal(Object.hasOwn(JSON.parse(ran.stdout), 'singleIdentity'), false); assert.doesNotMatch(ran.stderr, /Warning|Note/);
  const flagged = await spawned(['--config', two.config, '--target', 'two-desk', '--out', join(two.dir, 'out2'), '--authorization', two.record, '--single-identity']);
  assert.match(flagged.stderr, /Note: --single-identity had no effect/);
  // A two-identity target that declares no "mirrors" runs its declared checks with no warning (mirrors are opt-in).
  const undeclared = files(t, profile(app.origin, { mirrors: null }));
  const plainRun = await spawned(['--config', undeclared.config, '--target', 'two-desk', '--out', join(undeclared.dir, 'out'), '--authorization', undeclared.record]);
  assert.equal(plainRun.code, 0, plainRun.stderr); assert.doesNotMatch(plainRun.stderr, /Warning/);
  const mirrorless = files(t, profile(app.origin, { mirrors: { counterparts: [] } }));
  const quiet = await spawned(['--config', mirrorless.config, '--target', 'two-desk', '--out', join(mirrorless.dir, 'out'), '--authorization', mirrorless.record]);
  assert.match(quiet.stderr, /Warning: target two-desk declares tenant-scoped resources but no boundary check was mirrored/);
});
