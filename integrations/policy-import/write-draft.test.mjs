import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { validateTargetFile } from '../../src/contracts.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { importOpenApi } from './openapi.mjs';
import { importRls } from './rls.mjs';
import { draftChecks, BINDING_SCHEMA } from './draft.mjs';
import { CONFIRMED_STATUS, DRAFT_STATUS, RESET_RULE, WRITE_DRAFT_BINDING_SCHEMA, WRITE_DRAFT_SCHEMA, checkWriteDraftChecks, confirmWriteDraft, draftWriteChecks, generatedShare, inferBody, verifyWriteDraftId, verifyWriteDraftRecord } from './write-draft.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const fixture = name => readFile(join(here, 'fixtures', name));
const token = () => randomBytes(12).toString('hex');
const ENV = { SCOPEHAVEN_TARGET_WD_A: token(), SCOPEHAVEN_TARGET_WD_B: token() };
const USERS = { [ENV.SCOPEHAVEN_TARGET_WD_A]: { id: 'agent-a', tenant: 'acme', email: 'agent-a@acme.test' }, [ENV.SCOPEHAVEN_TARGET_WD_B]: { id: 'agent-b', tenant: 'globex', email: 'agent-b@globex.test' } };

const openapiMatrix = async () => importOpenApi({ id: 'openapi-writes.json', content: await fixture('openapi-writes.json') }, { application: 'tickets' });
const binding = (extra = {}) => ({ schema: WRITE_DRAFT_BINDING_SCHEMA, targetId: 'tickets', pairs: { 'requirement:session': { A: 'agentA', B: 'agentB' } }, anonymous: 'anonymous',
  parameters: { ticketId: { values: { A: ['T-A1', 'T-A2', 'T-A3'], B: ['T-B1'] }, read: '/tickets/{ticketId}', unchanged: { pointer: '/title', B: 'Globex printer' } }, commentId: { values: { A: ['c-a1', 'c-a2', 'c-a3'], B: ['c-b1'] } } },
  foreignFields: { 'POST /tickets': { '/tenant': { A: 'acme', B: 'globex' } } }, statuses: { deleted: 204 }, ...extra });
const whoami = (id, actorId, email) => ({ id, title: `${actorId} session`, category: 'Identity', severity: 'control', actorId, method: 'GET', path: '/api/me', evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: email }] });
const baseProfile = () => ({ schemaVersion: 1, targets: [{ id: 'tickets', name: 'Synthetic ticketing (write drafting)', applicationId: 'tickets', origin: 'http://127.0.0.1:4421', buildLabel: 'synthetic', contextId: 'synthetic-seed-1',
  actors: { agentA: { principalId: 'agent-a', tenantId: 'acme', credentialEnv: 'SCOPEHAVEN_TARGET_WD_A', identityValue: 'agent-a@acme.test' }, agentB: { principalId: 'agent-b', tenantId: 'globex', credentialEnv: 'SCOPEHAVEN_TARGET_WD_B', identityValue: 'agent-b@globex.test' }, anonymous: { principalId: 'anonymous' } },
  requiredControlIds: ['A-WHOAMI', 'B-WHOAMI'], checks: [whoami('A-WHOAMI', 'agentA', 'agent-a@acme.test'), whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test')] }] });
const variantsOf = (draft, action, resource) => draft.provenance.filter(p => p.action === action && p.resource === resource).map(p => p.variant);
const byVariant = (draft, action, resource, variant) => { const p = draft.provenance.find(q => q.action === action && q.resource === resource && q.variant === variant); return draft.checks.find(c => c.id === p.checkId); };

// A stateful synthetic ticket app as a connector transport. "leaky" applies a foreign write and still answers 404.
function ticketApp(mode = 'enforcing') {
  const tickets = { 'T-A1': { tenant: 'acme', title: 'Acme laptop' }, 'T-A2': { tenant: 'acme', title: 'Acme badge' }, 'T-A3': { tenant: 'acme', title: 'Acme chair' }, 'T-B1': { tenant: 'globex', title: 'Globex printer' } };
  const log = [];
  const transport = async (_origin, check, { credential }) => {
    const user = USERS[credential];
    const reply = (status, json) => ({ status, complete: true, jsonParsed: json !== undefined, json: json ?? null, bytes: json === undefined ? 0 : 2 });
    log.push({ actor: check.actorId, method: check.method, path: check.path });
    if (!user) return reply(401, { error: 'sign in' });
    const [, path] = check.path.split('/api');
    if (check.method === 'GET' && path === '/me') return reply(200, { email: user.email });
    if (check.method === 'POST' && path === '/public/feedback') return reply(201, { ok: true });
    if (check.method === 'POST' && path === '/tickets') return check.body?.tenant === user.tenant ? reply(201, { id: 'T-new' }) : reply(403, { error: 'tenant' });
    if (check.method === 'POST' && path === '/admin/reindex') return reply(403, { error: 'admin only' });
    const m = /^\/tickets\/([^/]+)(\/comments(?:\/([^/]+))?)?$/.exec(path ?? '');
    if (!m) return reply(404, { error: 'route' });
    const t = tickets[m[1]], own = t && t.tenant === user.tenant;
    if (!t) return reply(404, { error: 'gone' });
    if (m[3]) return check.method === 'DELETE' && own && m[3].startsWith('c-a') ? reply(204) : reply(404, { error: 'not found' });
    if (check.method === 'GET') return own ? reply(200, { id: m[1], title: t.title }) : reply(404, { error: 'not found' });
    if (m[2]) return own ? reply(201, { id: 'c-1' }) : reply(404, { error: 'not found' });
    if (check.method === 'PATCH') { if (own || mode === 'leaky') Object.assign(t, check.body ?? {}); return own ? reply(200, { id: m[1] }) : reply(404, { error: 'not found' }); }
    if (check.method === 'DELETE') { if (own || mode === 'leaky') delete tickets[m[1]]; return own ? reply(204) : reply(404, { error: 'not found' }); }
    return reply(405, { error: 'method' });
  };
  return { transport, log, tickets };
}

test('OpenAPI writes: each allowed operation gets its owner read, twins, foreign-owner, anonymous and read-back; deny cells get one refusal', async () => {
  const matrix = await openapiMatrix(), doc = await fixture('openapi-writes.json');
  const draft = draftWriteChecks(matrix, binding(), { document: doc });
  assert.equal(draft.schema, WRITE_DRAFT_SCHEMA);
  assert.equal(draft.confirmed, false);
  assert.ok(verifyWriteDraftId(draft));
  const full = ['owner-read-before', 'own-read', 'twin-before', 'foreign-owner', 'anonymous', 'read-back', 'twin-after'];
  assert.deepEqual(variantsOf(draft, 'PATCH', '/tickets/{ticketId}'), full);
  assert.deepEqual(variantsOf(draft, 'DELETE', '/tickets/{ticketId}'), full);
  assert.deepEqual(variantsOf(draft, 'POST', '/tickets/{ticketId}/comments'), full);
  const ownRead = byVariant(draft, 'PATCH', '/tickets/{ticketId}', 'own-read');
  assert.deepEqual([ownRead.actorId, ownRead.method, ownRead.path, ownRead.severity], ['agentA', 'GET', '/api/tickets/T-A1', 'control']);
  // A create on a collection: no record to read, so the foreign side comes from the declared owned field.
  assert.deepEqual(variantsOf(draft, 'POST', '/tickets'), ['twin-before', 'foreign-owner', 'anonymous', 'twin-after']);
  assert.deepEqual(byVariant(draft, 'POST', '/tickets', 'foreign-owner').body, { title: 'Synthetic ticket', priority: 'low', tenant: 'globex' });
  assert.deepEqual(byVariant(draft, 'POST', '/tickets', 'twin-before').body, { title: 'Synthetic ticket', priority: 'low', tenant: 'acme' });
  // Bindings inferred from the path parameter and the request schema (a $ref, a format, a nested required object).
  const patchForeign = byVariant(draft, 'PATCH', '/tickets/{ticketId}', 'foreign-owner');
  assert.equal(patchForeign.path, '/api/tickets/T-B1');
  assert.equal(patchForeign.actorId, 'agentA');
  assert.deepEqual(patchForeign.body, { title: 'synthetic', assignee: { email: 'synthetic@example.test' }, dueAt: '2026-01-01T00:00:00Z' });
  assert.deepEqual(patchForeign.assertions, [{ kind: 'status.in', expected: [401, 403, 404] }]);
  const readBack = byVariant(draft, 'PATCH', '/tickets/{ticketId}', 'read-back');
  assert.equal(readBack.actorId, 'agentB');
  assert.equal(readBack.method, 'GET');
  assert.deepEqual(readBack.assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/title', expected: 'Globex printer' }]);
  assert.equal(draft.provenance.find(p => p.checkId === patchForeign.id).decidedBy, readBack.id);
  // Twins: before and after; delete twins use up A's second and third records, and A's own read keeps the first.
  assert.equal(byVariant(draft, 'DELETE', '/tickets/{ticketId}', 'twin-before').path, '/api/tickets/T-A2');
  assert.equal(byVariant(draft, 'DELETE', '/tickets/{ticketId}', 'twin-after').path, '/api/tickets/T-A3');
  assert.equal(byVariant(draft, 'DELETE', '/tickets/{ticketId}', 'own-read').path, '/api/tickets/T-A1');
  // A nested delete moves only the last parameter: the parent stays A's first (or B's first for the foreign side).
  assert.equal(byVariant(draft, 'DELETE', '/tickets/{ticketId}/comments/{commentId}', 'twin-before').path, '/api/tickets/T-A1/comments/c-a2');
  assert.equal(byVariant(draft, 'DELETE', '/tickets/{ticketId}/comments/{commentId}', 'twin-after').path, '/api/tickets/T-A1/comments/c-a3');
  // The foreign probe is B's whole chain (M2): B's ticket and B's comment, never A's ticket with B's comment.
  assert.equal(byVariant(draft, 'DELETE', '/tickets/{ticketId}/comments/{commentId}', 'foreign-owner').path, '/api/tickets/T-B1/comments/c-b1');
  assert.equal(byVariant(draft, 'POST', '/tickets/{ticketId}/comments', 'foreign-owner').path, '/api/tickets/T-B1/comments');
  const twoValues = draftWriteChecks(matrix, binding({ parameters: { ticketId: { values: { A: ['T-A1', 'T-A2'], B: ['T-B1'] }, read: '/tickets/{ticketId}' } } }), { document: doc });
  assert.ok(twoValues.notDrafted.some(n => n.action === 'DELETE' && n.variant === 'twin-after' && /needs 3 value/.test(n.reason)));
  assert.deepEqual(byVariant(draft, 'DELETE', '/tickets/{ticketId}', 'twin-after').assertions, [{ kind: 'status.equals', expected: 204 }]);
  assert.equal(byVariant(draft, 'DELETE', '/tickets/{ticketId}', 'twin-before').body, undefined);
  // Anonymous: once per operation, never for an operation the document declares public.
  const anon = byVariant(draft, 'PATCH', '/tickets/{ticketId}', 'anonymous');
  assert.equal(anon.actorId, 'anonymous');
  assert.deepEqual(anon.assertions, [{ kind: 'status.in', expected: [401, 403] }]);
  assert.deepEqual(variantsOf(draft, 'POST', '/public/feedback'), ['twin-before', 'twin-after']);
  assert.ok(draft.notDrafted.some(n => n.resource === '/public/feedback' && n.variant === 'anonymous' && /anonymous role/.test(n.reason)));
  // Deny: the session role lacks the admin scope.
  assert.deepEqual(variantsOf(draft, 'POST', '/admin/reindex'), ['role-refusal']);
  assert.equal(byVariant(draft, 'POST', '/admin/reindex', 'role-refusal').severity, 'high');
  // Not drafted, each with a reason: own servers, a non-JSON body, an unmapped role, a collection create without a foreign field.
  assert.ok(draft.notDrafted.some(n => n.resource === '/legacy/{id}' && /own servers/.test(n.reason)));
  assert.ok(draft.notDrafted.some(n => n.resource === '/exports' && /not JSON/.test(n.reason)));
  assert.ok(draft.notDrafted.some(n => n.role === 'requirement:oauth[admin]' && /not mapped/.test(n.reason)));
  assert.ok(draft.notDrafted.some(n => n.resource === '/public/feedback' && n.variant === 'foreign-owner' && /foreignFields/.test(n.reason)));
  assert.ok(draft.provenance.every(p => p.status === DRAFT_STATUS));
  assert.ok(draft.warnings.includes(RESET_RULE));
  assert.equal(draft.checks.length, 32);
  assert.deepEqual(draft.counts, { 'owner-read-before': 3, 'own-read': 3, 'twin-before': 6, 'foreign-owner': 5, anonymous: 5, 'read-back': 3, 'twin-after': 6, 'role-refusal': 1 });
  // With surface reads declared, one GET control per actor stands at the top instead of a per-operation own read.
  const surfaced = draftWriteChecks(matrix, binding({ surfaceReads: { agentA: '/api/tickets', agentB: '/api/tickets' } }), { document: doc });
  assert.deepEqual(surfaced.provenance.slice(0, 2).map(p => [p.variant, p.role]), [['surface-read', 'agentA'], ['surface-read', 'agentB']]);
  assert.equal(surfaced.counts['own-read'], undefined);
  assert.equal(surfaced.checks[0].path, '/api/tickets');
  assert.ok(!surfaced.warnings.some(w => /identity-unproven/.test(w)));
  // The GET drafter is untouched: it still drafts only GETs from the same matrix, under its own ids.
  const gets = draftChecks(matrix, { schema: BINDING_SCHEMA, targetId: 'tickets', actors: { 'requirement:session': 'agentA', anonymous: 'anonymous' } });
  assert.ok(gets.checks.length > 0 && gets.checks.every(c => c.method === 'GET' && c.id.startsWith('PI-')));
  assert.ok(draft.checks.every(c => c.id.startsWith('PW-')));
});

test('OpenAPI writes: the document must be the imported bytes; parameters and pairs are checked; bodies can be overridden', async () => {
  const matrix = await openapiMatrix(), doc = await fixture('openapi-writes.json');
  assert.throws(() => draftWriteChecks(matrix, binding()), /document bytes/);
  assert.throws(() => draftWriteChecks(matrix, binding(), { document: Buffer.from('{"openapi":"3.1.0"}') }), /not the one the matrix was imported from/);
  assert.throws(() => draftWriteChecks(matrix, binding({ pairs: { 'requirement:session': { A: 'agentA', B: 'agentA' } } }), { document: doc }), /two distinct actor ids/);
  assert.throws(() => draftWriteChecks(matrix, binding({ parameters: { ticketId: { values: { A: ['../x'], B: ['T-B1'] } } } }), { document: doc }), /safe path values/);
  assert.throws(() => draftWriteChecks(matrix, binding({ surfaceReads: { agentA: 'tickets' } }), { document: doc }), /surfaceReads/);
  assert.throws(() => draftWriteChecks(matrix, { ...binding(), schema: 'other' }, { document: doc }), /schema/);
  const unbound = draftWriteChecks(matrix, binding({ parameters: {} }), { document: doc });
  assert.ok(unbound.notDrafted.some(n => n.resource === '/tickets/{ticketId}' && /ticketId not bound/.test(n.reason)));
  assert.equal(unbound.checks.filter(c => c.path.includes('/tickets/T-')).length, 0);
  const overridden = draftWriteChecks(matrix, binding({ bodies: { 'PATCH /tickets/{ticketId}': { title: 'from the binding' } } }), { document: doc });
  assert.deepEqual(byVariant(overridden, 'PATCH', '/tickets/{ticketId}', 'twin-before').body, { title: 'from the binding' });
  assert.equal(overridden.provenance.find(p => p.action === 'PATCH' && p.variant === 'twin-before').bodyInferred, undefined);
  assert.equal(draftWriteChecks(matrix, binding(), { document: doc }).provenance.find(p => p.action === 'PATCH' && p.variant === 'twin-before').bodyInferred, true);
  // Without a read template there is no owner read and no read-back, and the probe says so.
  const noRead = draftWriteChecks(matrix, binding({ parameters: { ticketId: { values: { A: ['T-A1', 'T-A2', 'T-A3'], B: ['T-B1'] } } } }), { document: doc });
  assert.deepEqual(variantsOf(noRead, 'PATCH', '/tickets/{ticketId}'), ['twin-before', 'foreign-owner', 'anonymous', 'twin-after']);
  assert.ok(noRead.warnings.some(w => /agentA has no allowed-use GET control/.test(w)));
  assert.equal(noRead.provenance.find(p => p.action === 'PATCH' && p.variant === 'foreign-owner').decidedBy, undefined);
  assert.ok(noRead.notDrafted.some(n => n.variant === 'owner-read-before' && /parameters\.ticketId\.read/.test(n.reason)));
  // One identity class (no B): twins and the anonymous probe only, each missing variant with its reason.
  const single = draftWriteChecks(matrix, binding({ pairs: { 'requirement:session': { A: 'agentA' } } }), { document: doc });
  assert.deepEqual(variantsOf(single, 'PATCH', '/tickets/{ticketId}'), ['own-read', 'twin-before', 'anonymous', 'twin-after']);
  assert.ok(single.notDrafted.some(n => n.action === 'PATCH' && n.variant === 'foreign-owner' && /no second actor/.test(n.reason)));
  // The twin's status comes from the operation's documented 2xx when the document lists one; the binding's per-operation status wins.
  const withResponses = JSON.parse(doc.toString()); withResponses.paths['/tickets/{ticketId}/comments'].post.responses = { 200: { description: 'ok' }, 400: { description: 'bad' } };
  const responsesBytes = Buffer.from(JSON.stringify(withResponses));
  const responsesMatrix = importOpenApi({ id: 'openapi-writes.json', content: responsesBytes }, { application: 'tickets' });
  const documented = draftWriteChecks(responsesMatrix, binding(), { document: responsesBytes });
  assert.deepEqual(byVariant(documented, 'POST', '/tickets/{ticketId}/comments', 'twin-before').assertions, [{ kind: 'status.equals', expected: 200 }]);
  assert.deepEqual(byVariant(draftWriteChecks(matrix, binding(), { document: doc }), 'POST', '/tickets/{ticketId}/comments', 'twin-before').assertions, [{ kind: 'status.equals', expected: 201 }]);
  const overriddenStatus = draftWriteChecks(responsesMatrix, binding({ statuses: { operations: { 'POST /tickets/{ticketId}/comments': 202 } } }), { document: responsesBytes });
  assert.deepEqual(byVariant(overriddenStatus, 'POST', '/tickets/{ticketId}/comments', 'twin-before').assertions, [{ kind: 'status.equals', expected: 202 }]);
  // inferBody on its own.
  const parsed = JSON.parse(doc.toString());
  assert.deepEqual(inferBody(parsed, '/tickets/{ticketId}/comments', 'POST'), { body: { text: 'synthetic' }, inferred: true });
  assert.deepEqual(inferBody(parsed, '/tickets/{ticketId}', 'DELETE'), { body: null });
  assert.match(inferBody(parsed, '/exports', 'POST').skip, /not JSON/);
});

test('confirmation re-drafts, refuses edits and partial confirmations that leave a probe without its twins, and yields a profile the validator accepts', async () => {
  const matrix = await openapiMatrix(), doc = await fixture('openapi-writes.json'), bound = binding();
  const draft = draftWriteChecks(matrix, bound, { document: doc });
  assert.throws(() => confirmWriteDraft(draft, baseProfile(), { matrix, binding: bound, document: doc }), /name the person/i);
  assert.throws(() => confirmWriteDraft({ ...draft, checks: draft.checks.slice(1) }, baseProfile(), { confirmedBy: 'R', matrix, binding: bound, document: doc }), /edited after drafting/);
  // A recomputed draftId over a changed body is caught by re-drafting from the matrix and binding.
  const forged = structuredClone(draft); forged.checks.find(c => c.method === 'PATCH').body = { title: 'owned' };
  const { draftId: _d, ...body } = forged; const { sha256, canonical } = await import('./matrix.mjs');
  assert.throws(() => confirmWriteDraft({ ...body, draftId: sha256(canonical(body)) }, baseProfile(), { confirmedBy: 'R', matrix, binding: bound, document: doc }), /not what this matrix and binding produce/);
  // checkWriteDraftChecks on its own: a probe turned into a control, or given a 2xx, is refused.
  const bad = structuredClone(draft); bad.checks.find(c => c.actorId === 'anonymous').severity = 'control';
  assert.throws(() => checkWriteDraftChecks(bad), /severity/);
  const bad2 = structuredClone(draft); const probe = bad2.checks.find(c => c.id === bad2.provenance.find(p => p.variant === 'foreign-owner').checkId); probe.assertions = [{ kind: 'status.equals', expected: 200 }];
  assert.throws(() => checkWriteDraftChecks(bad2), /assertions/);
  // A foreign-owner probe without its twins, or without its read-back, is refused.
  const foreign = draft.provenance.find(p => p.action === 'PATCH' && p.variant === 'foreign-owner');
  assert.throws(() => confirmWriteDraft(draft, baseProfile(), { confirmedBy: 'R', matrix, binding: bound, document: doc, checkIds: [foreign.checkId] }), /together with its twins/);
  const twins = draft.provenance.filter(p => p.action === 'PATCH' && p.resource === '/tickets/{ticketId}' && p.variant.startsWith('twin')).map(p => p.checkId);
  assert.throws(() => confirmWriteDraft(draft, baseProfile(), { confirmedBy: 'R', matrix, binding: bound, document: doc, checkIds: [foreign.checkId, ...twins] }), /decided by its read-back/);
  assert.throws(() => confirmWriteDraft(draft, baseProfile(), { confirmedBy: 'R', matrix, binding: bound, document: doc, checkIds: ['PW-NOPE'] }), /does not contain/);
  // The whole draft confirmed under a name: the profile validates, controls are required, the record is sealed and says what it confirmed.
  const { profile, record } = confirmWriteDraft(draft, baseProfile(), { confirmedBy: 'Synthetic Reviewer', matrix, binding: bound, document: doc, now: new Date('2026-10-26T00:00:00Z'), reset: { declaration: 'reset.json', sha256: 'a'.repeat(64) } });
  assert.ok(validateTargetFile(profile));
  assert.equal(profile.targets[0].checks.length, 2 + 32);
  assert.ok(profile.targets[0].requiredControlIds.length > 2);
  assert.ok(verifyWriteDraftRecord(record));
  assert.equal(record.confirmedBy, 'Synthetic Reviewer');
  assert.ok(record.provenance.every(p => p.status === CONFIRMED_STATUS));
  assert.deepEqual(record.notConfirmed, []);
  assert.equal(record.resetRule, RESET_RULE);
  assert.deepEqual(record.warnings, []);
  assert.throws(() => confirmWriteDraft(draft, profile, { confirmedBy: 'R', matrix, binding: bound, document: doc }), /already has a check/);
  // A partial confirmation: one operation's six checks; the rest are listed as not confirmed, and the missing reset is a warning.
  const seven = draft.provenance.filter(p => p.action === 'DELETE').map(p => p.checkId);
  const partial = confirmWriteDraft(draft, baseProfile(), { confirmedBy: 'R', matrix, binding: bound, document: doc, checkIds: seven });
  assert.equal(partial.record.checks.length, 11);
  assert.equal(partial.record.notConfirmed.length, 21);
  assert.match(partial.record.warnings[0], /reset declaration/);
  assert.deepEqual(generatedShare(partial.profile.targets[0], [partial.record]), { total: 13, generated: 11, handWritten: 2, share: 0.846 });
});

test('end to end: the confirmed write checks run through the connector; a foreign write that is applied behind a 404 fails on the read-back', async () => {
  const matrix = await openapiMatrix(), doc = await fixture('openapi-writes.json'), bound = binding();
  const draft = draftWriteChecks(matrix, bound, { document: doc });
  const { profile } = confirmWriteDraft(draft, baseProfile(), { confirmedBy: 'Synthetic Reviewer', matrix, binding: bound, document: doc });
  const target = profile.targets[0];
  const enforcing = ticketApp('enforcing');
  const run = await runHttpAssessment(target, { env: ENV, transport: enforcing.transport });
  const failed = run.results.filter(r => r.status !== 'pass').map(r => [r.id, r.status, r.title]);
  assert.deepEqual(failed, []);
  // Run order is the draft order: the owner read comes before the probe, the read-back after it, the twin after last.
  const order = enforcing.log.filter(e => e.path.startsWith('/api/tickets/T-B1') || e.method === 'DELETE').map(e => `${e.actor} ${e.method} ${e.path}`);
  const i = s => order.indexOf(s);
  assert.ok(i('agentB GET /api/tickets/T-B1') < i('agentA DELETE /api/tickets/T-B1') && i('agentA DELETE /api/tickets/T-B1') < i('agentA DELETE /api/tickets/T-A3'));
  assert.ok(enforcing.tickets['T-A1'], 'the record A reads as its surface control is never deleted');
  const leaky = ticketApp('leaky');
  const leakyRun = await runHttpAssessment(target, { env: ENV, transport: leaky.transport });
  const fails = leakyRun.results.filter(r => r.status === 'fail');
  const byId = new Map(draft.provenance.map(p => [p.checkId, p]));
  const leaked = fails.map(r => [byId.get(r.id).action, byId.get(r.id).variant]);
  // The first leak (the PATCH) is caught by its read-back; every later read of B's altered record fails too, so a record an earlier
  // probe altered blocks the rows after it instead of reading as restored (docs/ONBOARDING.md). No probe row fails: 404 is a refusal shape.
  assert.ok(leaked.some(([action, variant]) => action === 'PATCH' && variant === 'read-back'));
  assert.ok(leaked.some(([action, variant]) => action === 'DELETE' && variant === 'read-back'));
  assert.ok(leaked.every(([, variant]) => ['read-back', 'owner-read-before'].includes(variant)), JSON.stringify(leaked));
  // The probes themselves passed (404 is a declared refusal shape), so without the read-back the leak would read as refused.
  assert.ok(leakyRun.results.filter(r => byId.get(r.id)?.variant === 'foreign-owner').every(r => r.status === 'pass'));
});

test('RLS writes through PostgREST: conditional policies get the twin, the foreign owner (silent refusal decided by the read-back) and the anonymous probe', async () => {
  const dir = join(here, 'fixtures', 'supabase-migrations');
  const files = await Promise.all((await readdir(dir)).sort().map(async id => ({ id, content: await readFile(join(dir, id)), kind: 'sql' })));
  const matrix = importRls(files, { application: 'helpdesk', roles: ['anon', 'authenticated'] });
  const bound = { schema: WRITE_DRAFT_BINDING_SCHEMA, targetId: 'tickets', pairs: { authenticated: { A: 'agentA', B: 'agentB' } }, anonymous: 'anonymous', postgrest: { basePath: '/rest/v1', anonymous: 'anon-key' },
    tables: { 'public.tickets': { key: 'id', values: { A: ['11', '12', '13'], B: ['21'] }, insert: { body: { org_id: 'org-a', body: 'synthetic' }, ownerColumn: 'created_by', owners: { A: 'uid-a', B: 'uid-b' } }, update: { body: { body: 'edited by scopehaven' } }, unchanged: { column: 'body', B: 'B ticket' } },
      'public.profiles': { key: 'id', values: { A: ['pa'], B: ['pb'] }, insert: { body: { display_name: 'synthetic' }, ownerColumn: 'owner_id', owners: { A: 'uid-a', B: 'uid-b' } } } } };
  const draft = draftWriteChecks(matrix, bound);
  assert.deepEqual(variantsOf(draft, 'UPDATE', 'public.tickets'), ['owner-read-before', 'own-read', 'twin-before', 'foreign-owner', 'anonymous', 'read-back', 'twin-after']);
  assert.equal(byVariant(draft, 'UPDATE', 'public.tickets', 'own-read').path, '/rest/v1/tickets?id=eq.11&select=*');
  // m3: the PostgREST controls assert the row is there (200 [] is a row that is gone or filtered).
  assert.deepEqual(byVariant(draft, 'UPDATE', 'public.tickets', 'own-read').assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/0/id', expected: '11' }]);
  assert.deepEqual(byVariant(draft, 'UPDATE', 'public.tickets', 'owner-read-before').assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/0/id', expected: '21' }, { kind: 'json.equals', pointer: '/0/body', expected: 'B ticket' }]);
  const foreign = byVariant(draft, 'UPDATE', 'public.tickets', 'foreign-owner');
  assert.equal(foreign.method, 'PATCH');
  assert.equal(foreign.path, '/rest/v1/tickets?id=eq.21');
  assert.deepEqual(foreign.body, { body: 'edited by scopehaven' });
  assert.deepEqual(foreign.assertions, [{ kind: 'status.equals', expected: 204 }]);
  assert.equal(foreign.severity, 'medium');
  assert.equal(draft.provenance.find(p => p.checkId === foreign.id).refusal, 'silent');
  assert.equal(draft.provenance.find(p => p.checkId === foreign.id).decidedBy, byVariant(draft, 'UPDATE', 'public.tickets', 'read-back').id);
  const back = byVariant(draft, 'UPDATE', 'public.tickets', 'read-back');
  assert.equal(back.path, '/rest/v1/tickets?id=eq.21&select=*');
  assert.deepEqual(back.assertions, [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/0/id', expected: '21' }, { kind: 'json.equals', pointer: '/0/body', expected: 'B ticket' }]);
  // B1: the DELETE read-back asserts B's row is still there, so a deleted foreign row (PostgREST: 200 []) fails it.
  assert.deepEqual(byVariant(draft, 'DELETE', 'public.tickets', 'read-back').assertions.slice(0, 2), [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/0/id', expected: '21' }]);
  // M1: the anonymous UPDATE and DELETE are silent probes aimed at B's row, decided by the read-back.
  const anonPatch = byVariant(draft, 'UPDATE', 'public.tickets', 'anonymous');
  assert.deepEqual([anonPatch.actorId, anonPatch.path, anonPatch.severity, anonPatch.assertions], ['anonymous', '/rest/v1/tickets?id=eq.21', 'medium', [{ kind: 'status.equals', expected: 204 }]]);
  assert.equal(draft.provenance.find(p => p.checkId === anonPatch.id).decidedBy, back.id);
  assert.deepEqual(byVariant(draft, 'UPDATE', 'public.tickets', 'twin-before').assertions, [{ kind: 'status.equals', expected: 204 }]);
  assert.equal(byVariant(draft, 'DELETE', 'public.tickets', 'twin-after').path, '/rest/v1/tickets?id=eq.13');
  // An insert refusal is a status (42501), and the foreign side is the other owner's id in the owner column.
  const insert = byVariant(draft, 'INSERT', 'public.tickets', 'foreign-owner');
  assert.deepEqual(insert.body, { org_id: 'org-a', body: 'synthetic', created_by: 'uid-b' });
  assert.deepEqual(insert.assertions, [{ kind: 'status.in', expected: [401, 403, 404] }]);
  assert.deepEqual(byVariant(draft, 'INSERT', 'public.tickets', 'twin-before').assertions, [{ kind: 'status.equals', expected: 201 }]);
  // profiles: INSERT is conditional on the owner; no UPDATE or DELETE policy, so those are default deny for authenticated (role-refusal).
  assert.deepEqual(variantsOf(draft, 'INSERT', 'public.profiles'), ['twin-before', 'foreign-owner', 'anonymous', 'twin-after']);
  // A silent deny (no UPDATE policy, PostgREST answers 204 either way) has no owner read-back to decide it, so it is listed, not drafted.
  assert.deepEqual(variantsOf(draft, 'UPDATE', 'public.profiles'), []);
  assert.ok(draft.notDrafted.some(n => n.resource === 'public.profiles' && n.action === 'UPDATE' && n.variant === 'role-refusal' && /silent/.test(n.reason)));
  // M1: the importer's anon role is the anonymous side; its cells are covered by the anonymous variants, never "not mapped".
  // N2: they are listed as not drafted with that reason.
  assert.ok(!draft.notDrafted.some(n => n.role === 'anon' && /not mapped/.test(n.reason)));
  assert.ok(draft.notDrafted.some(n => n.role === 'anon' && /covered by the anonymous variant/.test(n.reason)));
  assert.ok(draft.checks.some(c => c.actorId === 'anonymous' && c.method === 'PATCH'));
  // With no key, the gateway refuses before RLS: the anonymous probe is a status refusal on A's row (it tests the gateway).
  const noKey = draftWriteChecks(matrix, { ...bound, postgrest: { basePath: '/rest/v1', anonymous: 'no-key' } });
  assert.deepEqual(byVariant(noKey, 'UPDATE', 'public.tickets', 'anonymous').assertions, [{ kind: 'status.in', expected: [401, 403] }]);
  assert.throws(() => draftWriteChecks(matrix, { ...bound, postgrest: { basePath: '/rest/v1', anonymous: 'maybe' } }), /anon-key/);
  // N1: undeclared, the anonymous UPDATE and DELETE probes are not drafted (the expected status depends on the anon role's grant).
  const undeclared = draftWriteChecks(matrix, { ...bound, postgrest: { basePath: '/rest/v1' } });
  assert.ok(!undeclared.provenance.some(p => p.action === 'UPDATE' && p.resource === 'public.tickets' && p.variant === 'anonymous'));
  assert.ok(undeclared.notDrafted.some(n => n.action === 'UPDATE' && n.variant === 'anonymous' && /declare postgrest.anonymous/.test(n.reason)));
  assert.ok(byVariant(undeclared, 'INSERT', 'public.tickets', 'anonymous'), 'an anonymous INSERT is a status refusal either way');
  // The anon key without the grant: a status refusal aimed at B's row.
  const noGrant = draftWriteChecks(matrix, { ...bound, postgrest: { basePath: '/rest/v1', anonymous: 'anon-key-no-grant' } });
  const ng = byVariant(noGrant, 'UPDATE', 'public.tickets', 'anonymous');
  assert.deepEqual([ng.path, ng.severity, ng.assertions], ['/rest/v1/tickets?id=eq.21', 'high', [{ kind: 'status.in', expected: [401, 403] }]]);
  // Unbound tables and the unknown layer are refused or listed.
  assert.ok(draft.notDrafted.some(n => n.resource === 'public.announcements' && /not bound/.test(n.reason)));
  const confirmed = confirmWriteDraft(draft, { ...baseProfile(), targets: [{ ...baseProfile().targets[0], applicationId: 'helpdesk' }] }, { confirmedBy: 'R', matrix, binding: bound });
  assert.ok(validateTargetFile(confirmed.profile));
  assert.equal(confirmed.record.layer, 'postgres-rls');
});

// A PostgREST stand-in over RLS-like rules: a filtered write answers 204 and changes nothing; a filtered read answers 200 [].
// "leaky" lets user A delete or update B's ticket (the cross-tenant RLS defect B1 must catch).
// "no-grant": the anon role's UPDATE and DELETE grant is revoked, so an anonymous write is refused with 401 (42501).
function postgrest(mode = 'enforcing') {
  const rows = new Map([['11', { id: '11', org: 'a', body: 'A ticket' }], ['12', { id: '12', org: 'a', body: 'A two' }], ['13', { id: '13', org: 'a', body: 'A three' }], ['21', { id: '21', org: 'b', body: 'B ticket' }]]);
  const org = { [ENV.SCOPEHAVEN_TARGET_WD_A]: 'a', [ENV.SCOPEHAVEN_TARGET_WD_B]: 'b' };
  return async (_origin, check, { credential }) => {
    const reply = (status, json) => ({ status, complete: true, jsonParsed: json !== undefined, json: json ?? null, bytes: json === undefined ? 0 : 2 });
    if (check.path === '/api/me') return org[credential] ? reply(200, { email: org[credential] === 'a' ? 'agent-a@acme.test' : 'agent-b@globex.test' }) : reply(401, {});
    const who = org[credential] ?? null;
    const m = /^\/rest\/v1\/tickets(?:\?id=eq\.([^&]+))?/.exec(check.path);
    if (!m) return reply(404, {});
    const row = m[1] ? rows.get(m[1]) : null, visible = r => r && who !== null && (r.org === who || (mode === 'leaky' && who === 'a'));
    if (check.method === 'GET') return reply(200, visible(row) ? [row] : []);
    if (check.method === 'POST') return who && check.body?.created_by === (who === 'a' ? 'uid-a' : 'uid-b') ? reply(201) : reply(403, { code: '42501' });
    if (mode === 'no-grant' && who === null && ['PATCH', 'DELETE'].includes(check.method)) return reply(401, { code: '42501' });
    if (check.method === 'PATCH') { if (visible(row)) Object.assign(row, check.body); return reply(204); }
    if (check.method === 'DELETE') { if (visible(row)) rows.delete(m[1]); return reply(204); }
    return reply(405, {});
  };
}

test('B1 end to end: through PostgREST a deleted or altered foreign row FAILS its read-back, and an enforcing app passes every row', async () => {
  const dir = join(here, 'fixtures', 'supabase-migrations');
  const files = await Promise.all((await readdir(dir)).sort().map(async id => ({ id, content: await readFile(join(dir, id)), kind: 'sql' })));
  const matrix = importRls(files, { application: 'tickets', roles: ['anon', 'authenticated'] });
  const bound = { schema: WRITE_DRAFT_BINDING_SCHEMA, targetId: 'tickets', pairs: { authenticated: { A: 'agentA', B: 'agentB' } }, anonymous: 'anonymous', postgrest: { basePath: '/rest/v1', anonymous: 'anon-key' },
    tables: { 'public.tickets': { key: 'id', values: { A: ['11', '12', '13'], B: ['21'] }, insert: { body: { org_id: 'org-a', body: 'synthetic' }, ownerColumn: 'created_by', owners: { A: 'uid-a', B: 'uid-b' } }, update: { body: { body: 'edited by scopehaven' } }, unchanged: { column: 'body', B: 'B ticket' } } } };
  const draft = draftWriteChecks(matrix, bound);
  const ids = draft.checks.filter(c => /tickets/.test(c.path)).map(c => c.id);
  const { profile } = confirmWriteDraft(draft, baseProfile(), { confirmedBy: 'R', matrix, binding: bound, checkIds: ids });
  const byId = new Map(draft.provenance.map(p => [p.checkId, p]));
  const enforcing = await runHttpAssessment(profile.targets[0], { env: ENV, transport: postgrest('enforcing') });
  assert.deepEqual(enforcing.results.filter(r => r.status !== 'pass').map(r => [byId.get(r.id)?.action, byId.get(r.id)?.variant, r.status]), []);
  const leaky = await runHttpAssessment(profile.targets[0], { env: ENV, transport: postgrest('leaky') });
  const failed = leaky.results.filter(r => r.status === 'fail').map(r => `${byId.get(r.id)?.action} ${byId.get(r.id)?.variant}`);
  assert.ok(failed.includes('UPDATE read-back'), JSON.stringify(failed));
  assert.ok(failed.includes('DELETE read-back') || failed.includes('DELETE owner-read-before'), JSON.stringify(failed));
  // A delete-only leak: B's row survives every update, then the leaky DELETE removes it; its read-back alone catches it.
  const delOnly = draft.checks.filter(c => byId.get(c.id).action !== 'UPDATE' && /tickets/.test(c.path)).map(c => c.id);
  const { profile: delProfile } = confirmWriteDraft(draft, baseProfile(), { confirmedBy: 'R', matrix, binding: bound, checkIds: delOnly });
  const delRun = await runHttpAssessment(delProfile.targets[0], { env: ENV, transport: postgrest('leaky') });
  assert.deepEqual(delRun.results.filter(r => r.status === 'fail').map(r => `${byId.get(r.id).action} ${byId.get(r.id).variant}`), ['DELETE read-back']);
});

test('M1: an operation the RLS anon role may do gets no anonymous refusal probe', () => {
  const sql = `create table public.notes (id bigint primary key, body text);
alter table public.notes enable row level security;
create policy "read own" on public.notes for select to authenticated using (true);
create policy "anyone edits" on public.notes for update to anon using (true);
create policy "members edit" on public.notes for update to authenticated using (true);`;
  const matrix = importRls([{ id: 'm.sql', content: sql }], { application: 'notes', roles: ['anon', 'authenticated'] });
  const draft = draftWriteChecks(matrix, { schema: WRITE_DRAFT_BINDING_SCHEMA, targetId: 'notes', pairs: { authenticated: { A: 'agentA', B: 'agentB' } }, anonymous: 'anonymous', postgrest: { basePath: '/rest/v1' },
    tables: { 'public.notes': { key: 'id', values: { A: ['1'], B: ['2'] }, update: { body: { body: 'x' } }, unchanged: { column: 'body', B: 'b' } } } });
  assert.ok(!draft.checks.some(c => c.actorId === 'anonymous' && c.method === 'PATCH'));
  assert.ok(draft.notDrafted.some(n => n.action === 'UPDATE' && n.variant === 'anonymous' && /anonymous role/.test(n.reason)));
});

test('M2: a nested read template with a parent parameter is accepted and filled with the same side\'s chain', async () => {
  const doc = Buffer.from(JSON.stringify({ openapi: '3.1.0', info: { title: 't', version: '1' }, servers: [{ url: '/api' }], security: [{ s: [] }], components: { securitySchemes: { s: { type: 'http', scheme: 'bearer' } } },
    paths: { '/workspaces/{ws}/threads/{thread}': { get: {}, patch: { requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' } } } } } } } } } }));
  const matrix = importOpenApi({ id: 'n.json', content: doc }, { application: 'nested' });
  const draft = draftWriteChecks(matrix, { schema: WRITE_DRAFT_BINDING_SCHEMA, targetId: 'nested', pairs: { 'requirement:s': { A: 'agentA', B: 'agentB' } },
    parameters: { ws: { values: { A: ['ws-a'], B: ['ws-b'] } }, thread: { values: { A: ['t-a1'], B: ['t-b1'] }, read: '/workspaces/{ws}/threads/{thread}', unchanged: { pointer: '/name', B: 'b thread' } } } }, { document: doc });
  const path = v => draft.checks.find(c => c.id === draft.provenance.find(p => p.variant === v).checkId).path;
  assert.equal(path('foreign-owner'), '/api/workspaces/ws-b/threads/t-b1');
  assert.equal(path('owner-read-before'), '/api/workspaces/ws-b/threads/t-b1');
  assert.equal(path('own-read'), '/api/workspaces/ws-a/threads/t-a1');
  assert.equal(path('twin-before'), '/api/workspaces/ws-a/threads/t-a1');
});

test('an enforcing app whose anon role lacks the write grant (401, row untouched) never reads FAIL', async () => {
  const dir = join(here, 'fixtures', 'supabase-migrations');
  const files = await Promise.all((await readdir(dir)).sort().map(async id => ({ id, content: await readFile(join(dir, id)), kind: 'sql' })));
  const matrix = importRls(files, { application: 'tickets', roles: ['anon', 'authenticated'] });
  const base = { schema: WRITE_DRAFT_BINDING_SCHEMA, targetId: 'tickets', pairs: { authenticated: { A: 'agentA', B: 'agentB' } }, anonymous: 'anonymous',
    tables: { 'public.tickets': { key: 'id', values: { A: ['11', '12', '13'], B: ['21'] }, insert: { body: { org_id: 'org-a', body: 'synthetic' }, ownerColumn: 'created_by', owners: { A: 'uid-a', B: 'uid-b' } }, update: { body: { body: 'edited by scopehaven' } }, unchanged: { column: 'body', B: 'B ticket' } } } };
  for (const anonymous of [undefined, 'anon-key-no-grant']) {
    const bound = { ...base, postgrest: { basePath: '/rest/v1', ...(anonymous ? { anonymous } : {}) } };
    const draft = draftWriteChecks(matrix, bound);
    const { profile } = confirmWriteDraft(draft, baseProfile(), { confirmedBy: 'R', matrix, binding: bound, checkIds: draft.checks.filter(c => /tickets/.test(c.path)).map(c => c.id) });
    const byId = new Map(draft.provenance.map(p => [p.checkId, p]));
    const run = await runHttpAssessment(profile.targets[0], { env: ENV, transport: postgrest('no-grant') });
    assert.deepEqual(run.results.filter(r => r.status === 'fail').map(r => `${byId.get(r.id)?.action} ${byId.get(r.id)?.variant}`), [], `postgrest.anonymous ${anonymous ?? 'undeclared'}`);
    if (anonymous) assert.ok(run.results.some(r => byId.get(r.id)?.variant === 'anonymous' && byId.get(r.id).action === 'UPDATE' && r.status === 'pass'));
  }
});
