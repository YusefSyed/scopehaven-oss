// Supabase identity rules without a database: the service-role resolver, its note on actor-pinned clauses,
// and the FAIL-only rls-zero-row reading. supabase-rules.live.test.mjs runs them over a local Supabase stack.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateSupabaseRules, supabaseResolver, isServiceWrite, serviceRoleNotes, rlsZeroRow, SERVICE_ACTOR_PREFIX, RLS_ZERO_ROW_CHECK, DEFAULT_SERVICE_ROLES } from './supabase-rules.mjs';
import { parseLedger, attributeChange } from './pg-actor.mjs';
import { makeEffect } from './events.mjs';
import { evaluateHttpCheck } from '../../src/contracts.mjs';

const ANA = 'a11ce000-0000-4000-8000-000000000001', GIL = 'b0b00000-0000-4000-8000-000000000002';
const BLOCK = { testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', tables: [{ table: 'orders', key: 'id', actorColumn: 'made_by' }, { table: 'items', key: 'id', actorColumn: 'made_by' }], actor: { from: 'jwt-claims' }, principals: { [ANA]: 'ana', [GIL]: 'gil' } };
const ACTORS = { ana: { principalId: 'ana' }, gil: { principalId: 'gil' } };
const DECL = { tool: 'desk-agent', allowedWrites: { 'ANA-REFUND-OWN': { table: 'public.orders', op: 'UPDATE' } } };
let seq = 0;
// A ledger entry; the bearer token's sub follows the claims' unless given.
const entry = (over = {}) => { const r = { seq: String(++seq), txid: '1100', xid32: '1100', tbl: 'public.orders', key: 'ORD-1', op: 'UPDATE', rowcount: null, depth: '1', row_xmin: '1100', claims_sub: ANA, claims_role: 'authenticated', legacy_sub: null, header_sub: undefined, set_role: 'authenticated', session_role: 'authenticator', app_actor: null, ...over };
  if (r.header_sub === undefined) r.header_sub = r.claims_sub; return parseLedger([Object.values(r)])[0]; };
const service = over => entry({ claims_sub: null, claims_role: 'service_role', set_role: 'service_role', ...over });
const tool = { actor: `${SERVICE_ACTOR_PREFIX}desk-agent`, via: 'service-role', serviceRole: true, tool: 'desk-agent', reason: 'service-role-write' };

test('the declaration: a named tool, its roles, an optional pass-through and the allowed-use controls\' writes', () => {
  assert.deepEqual(validateSupabaseRules({ tool: 'desk-agent', serviceRoles: ['service_role', 'etl'], passThrough: { from: 'column' }, allowedWrites: { 'A-1': { table: 'public.orders', op: 'DELETE' } } }, { block: BLOCK }).serviceRoles, ['service_role', 'etl']);
  for (const [decl, pattern] of [[{}, /"tool" names/], [{ tool: 'a b' }, /"tool" names/], [{ tool: 'x', serviceRoles: [] }, /1 to 8 distinct/], [{ tool: 'x', serviceRoles: ['a', 'a'] }, /1 to 8 distinct/],
    [{ tool: 'x', passThrough: { from: 'header' } }, /"passThrough" is/], [{ tool: 'x', extra: 1 }, /is \{ "tool"/], [null, /is \{ "tool"/],
    [{ tool: 'x', allowedWrites: { 'A-1': { table: 'orders', op: 'UPDATE' } } }, /"table": "schema.table"/], [{ tool: 'x', allowedWrites: { 'A-1': { table: 'public.orders', op: 'INSERT' } } }, /"op": "UPDATE" \| "DELETE"/],
    [{ tool: 'x', allowedWrites: JSON.parse('{"__proto__": {"table": "public.orders", "op": "UPDATE"}}') }, /a check id/]]) assert.throws(() => validateSupabaseRules(decl), pattern, JSON.stringify(decl));
  assert.throws(() => validateSupabaseRules({ tool: 'x', passThrough: { from: 'column' } }, { block: { ...BLOCK, tables: [{ table: 'orders', key: 'id' }] } }), /needs every captured table's "actorColumn"/);
  assert.throws(() => validateSupabaseRules({ tool: 'x', allowedWrites: { 'A-1': { table: 'public.notes', op: 'UPDATE' } } }, { block: BLOCK }), /one the actor capture declares/);
  assert.deepEqual(DEFAULT_SERVICE_ROLES, ['service_role', 'postgres', 'supabase_admin']);
});

test('(a) a service-role write is the tool\'s, never the end user\'s, unless the declared pass-through names a declared principal', () => {
  const resolve = supabaseResolver(DECL);
  assert.deepEqual(resolve(entry(), BLOCK), { actor: 'ana', via: 'jwt-claims' }, 'a signed-in user resolves as the capture declares');
  assert.deepEqual(resolve(service(), BLOCK), tool);
  assert.deepEqual(resolve(service({ claims_sub: ANA }), BLOCK), tool, 'a service JWT that carries the user\'s sub is still the tool\'s');
  // A direct connection: SET ROLE service_role with no claims, and the login role postgres with the user's claims set.
  assert.deepEqual(resolve(entry({ claims_sub: null, claims_role: null, set_role: 'service_role', session_role: 'postgres' }), BLOCK), tool);
  assert.deepEqual(resolve(entry({ claims_role: 'authenticated', set_role: 'none', session_role: 'postgres' }), BLOCK), tool, 'postgres bypasses row-level security: never the user\'s');
  assert.equal(isServiceWrite(entry({ claims_role: 'authenticated', set_role: 'service_role' }), DECL), true);
  assert.equal(isServiceWrite(entry({ claims_role: 'service_role', set_role: 'authenticated' }), DECL), true, 'the claims alone name the service role');
  assert.equal(isServiceWrite(entry(), DECL), false);
  const claims = supabaseResolver({ tool: 'desk-agent', passThrough: { from: 'jwt-claims' } }), column = supabaseResolver({ tool: 'desk-agent', passThrough: { from: 'column' } });
  assert.deepEqual(claims(service({ claims_sub: ANA }), BLOCK), { actor: 'ana', via: 'service-role-pass-through:jwt-claims', serviceRole: true, tool: 'desk-agent' });
  assert.deepEqual(column(service({ app_actor: GIL }), BLOCK), { actor: 'gil', via: 'service-role-pass-through:column', serviceRole: true, tool: 'desk-agent' });
  assert.deepEqual(column(service({ app_actor: GIL, op: 'DELETE' }), BLOCK), tool, 'a deleted row\'s column never passes a user through');
  assert.deepEqual(column(service({ app_actor: null }), BLOCK), tool, 'an UPDATE that did not write the column (the capture records null) passes no one through');
  assert.deepEqual(claims(service({ claims_sub: 'c0ffee00-0000-4000-8000-000000000009' }), BLOCK), tool, 'a pass-through value that is no declared principal is still the tool\'s');
  assert.equal(supabaseResolver({ tool: 'etl', serviceRoles: ['etl_writer'] })(entry({ claims_role: null, set_role: 'etl_writer' }), BLOCK).actor, `${SERVICE_ACTOR_PREFIX}etl`);
  assert.equal(supabaseResolver({ tool: 'etl', serviceRoles: ['etl_writer'] })(service(), BLOCK).actor, null, 'service_role not declared there: the capture\'s own rules read it (not a user role)');
  assert.throws(() => supabaseResolver(), /needs the rules' declaration/);
  assert.equal(attributeChange({ xid: '1100', table: 'public.orders', key: 'ORD-2', op: 'UPDATE' }, [service({ key: 'ORD-2' })], BLOCK, { capture: 'intact', resolve }).actor, `${SERVICE_ACTOR_PREFIX}desk-agent`);
});

const windowOf = events => ({ source: 'sql-snapshot', observer: { kind: 'postgres-wal-decode', instanceId: 'wal-1' }, instanceId: 'wal-1', coverage: 'complete', reason: null,
  scope: { operations: ['insert', 'update', 'delete'], names: ['orders'], actorAttribution: 'principal', evidence: 'authoritative' }, events });
const event = (actor, resource = 'orders/ORD-2', operation = 'update') => makeEffect({ source: 'sql-snapshot', observer: { kind: 'postgres-wal-decode', instanceId: 'wal-1' }, seq: 1, actor, operation, name: 'orders', resource, outcome: 'committed', content: 'x' });
test('(a) a clause pinned to the end user is named service-role-write only when it reads missing and a tool write fits it without the pin', () => {
  const none = { kind: 'effect.none', select: { source: 'sql-snapshot', operation: 'update', name: 'orders', resource: 'orders/ORD-2', actor: 'ana' } };
  const exists = { kind: 'effect.exists', select: { source: 'sql-snapshot', operation: 'update', name: 'orders', resource: 'orders/ORD-2', actor: 'ana' } };
  const check = { id: 'ANA-NO-GLOBEX', effects: [none, { kind: 'effect.none', select: { source: 'sql-snapshot', name: 'orders', resource: 'orders/ORD-2' } }] };
  const notes = serviceRoleNotes(check, [windowOf([event(`${SERVICE_ACTOR_PREFIX}desk-agent`)])], { principals: ['ana', 'gil'] });
  assert.deepEqual(notes.map(n => [n.clause, n.reason, n.tools]), [[1, 'service-role-write', ['desk-agent']]]);
  assert.match(notes[0].basis, /pinned to ana cannot read that write as the user.s or as anyone else.s .*declare passThrough if the application passes the user through/);
  // The user's own write decides the clause: no note, whether it passes (exists) or fails (none).
  assert.deepEqual(serviceRoleNotes({ id: 'E', effects: [exists] }, [windowOf([event('ana'), event(`${SERVICE_ACTOR_PREFIX}desk-agent`)])]), []);
  assert.deepEqual(serviceRoleNotes({ id: 'N', effects: [none] }, [windowOf([event('ana'), event(`${SERVICE_ACTOR_PREFIX}desk-agent`)])]), []);
  assert.deepEqual(serviceRoleNotes(check, [windowOf([event(`${SERVICE_ACTOR_PREFIX}desk-agent`, 'orders/ORD-9')])]), [], 'another row');
  assert.deepEqual(serviceRoleNotes(check, [windowOf([event('gil')])]), [], 'a declared user\'s write is not the tool\'s');
  assert.deepEqual(serviceRoleNotes(check, [windowOf([event(`${SERVICE_ACTOR_PREFIX}desk-agent`)])], { principals: ['gil'] }), [], 'a pin that is not a declared principal');
  assert.deepEqual(serviceRoleNotes({ id: 'X' }, [windowOf([event(`${SERVICE_ACTOR_PREFIX}desk-agent`)])]), []);
});

const control = (method = 'POST', id = 'ANA-REFUND-OWN') => ({ id, title: 'Ana refunds her own order', category: 'Refunds', severity: 'control', actorId: 'ana', method, path: '/api/orders/ORD-1/refund', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/ok', expected: true }] });
const rowOf = (check, status, json, observation = {}) => evaluateHttpCheck(check, { status, complete: true, jsonParsed: true, json, ...observation });
const zero = (over = {}) => entry({ key: null, rowcount: '0', row_xmin: null, ...over });
test('(b) rls-zero-row: FAIL only on the declared write of an allowed-use twin whose response decided success; informational otherwise; never a pass', () => {
  const okRow = rowOf(control(), 200, { ok: true });
  const read = (over = {}) => rlsZeroRow({ check: control(), row: okRow, entries: [zero()], block: BLOCK, capture: 'intact', actors: ACTORS, decl: DECL, ...over });
  const fail = read();
  assert.deepEqual([fail.check, fail.status, fail.reason, fail.failOnly], [RLS_ZERO_ROW_CHECK, 'fail', 'rls-zero-row', true]);
  assert.deepEqual(fail.findings, [{ table: 'public.orders', op: 'UPDATE', actor: 'ana', txid: '1100' }]);
  assert.match(fail.basis, /declared UPDATE on public\.orders under ana's own session changed no row/);
  const informational = [
    [{ row: rowOf(control(), 404, { ok: false }) }, /did not decide a success/, 'response-not-decided'],
    [{ row: rowOf(control(), 200, null, { jsonParsed: false }) }, /did not decide a success/, 'response-not-decided'],
    [{ row: rowOf(control(), 200, { ok: true }, { complete: false }) }, /did not decide a success/, 'response-not-decided'],
    [{ check: { ...control(), severity: 'high' } }, /the check is a boundary check/, 'rls-zero-row'],
    [{ check: control('GET'), row: rowOf(control('GET'), 200, { ok: true }) }, /the control does not write/, 'rls-zero-row'],
    [{ check: control('POST', 'ANA-OTHER') }, /declares no expected write/, 'rls-zero-row'],
    [{ entries: [zero({ claims_sub: GIL })] }, /no zero-row statement is the control's own actor's declared write/, 'rls-zero-row'],
    [{ entries: [zero({ op: 'DELETE' })] }, /no zero-row statement is the control's own actor's declared write/, 'rls-zero-row'],
    [{ entries: [zero({ tbl: 'public.items' })] }, /no zero-row statement is the control's own actor's declared write/, 'rls-zero-row'],
    // The tool's own statement (a service role bypasses row-level security), with and without a pass-through.
    [{ entries: [zero({ claims_role: 'service_role', set_role: 'service_role' })] }, /no zero-row statement is the control's own actor's declared write/, 'rls-zero-row'],
    [{ entries: [zero({ claims_role: 'service_role', set_role: 'service_role' })], decl: { ...DECL, passThrough: { from: 'jwt-claims' } } }, /no zero-row statement is the control's own actor's declared write/, 'rls-zero-row'],
    // The declared write was made by another statement in the window (the tool retried it, or the same user's second request).
    [{ entries: [zero(), service({ txid: '1101', xid32: '1101' })] }, /made by another statement/, 'rls-zero-row'],
    [{ entries: [zero(), entry({ txid: '1101', xid32: '1101', key: 'ORD-1' })] }, /made by another statement/, 'rls-zero-row'],
  ];
  for (const [over, why, reason] of informational) { const r = read(over); assert.deepEqual([r.status, r.reason], ['informational', reason], why.source); assert.match(r.basis, why); }
  // Another principal's write to the table in the window does not stand in for the refused one; it is named on the finding.
  const another = read({ entries: [zero(), entry({ txid: '1102', xid32: '1102', key: 'ORD-2', claims_sub: GIL })] });
  assert.deepEqual([another.status, another.alsoWrittenBy], ['fail', ['gil']]); assert.match(another.basis, /an idempotent request that matched nothing/);
  assert.equal(Object.hasOwn(fail, 'alsoWrittenBy'), false);
  // A zero-row statement a trigger the request fired issued (an INSTEAD OF view, an apply trigger) is the declared write's path.
  const forwarded = read({ entries: [zero({ depth: '2' })] });
  assert.deepEqual([forwarded.status, forwarded.findings[0].depth], ['fail', 2]); assert.match(forwarded.basis, /a trigger the request fired issued/);
  // Not refusals at all: an upsert that inserted (its ON CONFLICT UPDATE changed nothing), a MERGE's untaken action, and a
  // cascade into a table the control did not declare.
  const upsert = read({ entries: [entry({ op: 'INSERT', key: 'ORD-9' }), zero()] });
  assert.deepEqual([upsert.status, upsert.verdict], ['informational', 'no-zero-row-observed']);
  assert.equal(read({ entries: [entry({ op: 'DELETE', key: 'ORD-8' }), zero()] }).verdict, 'no-zero-row-observed', 'a MERGE that deleted where its UPDATE branch changed nothing');
  assert.equal(read({ entries: [zero({ tbl: 'public.items', op: 'DELETE' })] }).status, 'informational', 'a cascade lands on another table');
  const tool = read({ entries: [zero({ claims_sub: ANA, claims_role: 'service_role', set_role: 'service_role' })] });
  assert.deepEqual(tool.findings[0], { table: 'public.orders', op: 'UPDATE', actor: `${SERVICE_ACTOR_PREFIX}desk-agent`, tool: 'desk-agent', txid: '1100' });
  assert.deepEqual([read({ entries: [entry()] }).verdict, read({ entries: [entry()] }).reason], ['no-zero-row-observed', null]);
  assert.equal(read({ entries: [zero({ op: 'INSERT' })] }).verdict, 'no-zero-row-observed', 'an INSERT that inserted nothing is no refusal of a write');
  // A status-only control: an unfinished response decides no success even though its status matched.
  const statusOnly = { ...control(), assertions: [{ kind: 'status.equals', expected: 200 }] };
  const unfinished = read({ check: statusOnly, row: rowOf(statusOnly, 200, null, { complete: false, jsonParsed: false }) });
  assert.deepEqual([unfinished.status, unfinished.reason], ['informational', 'response-not-decided']);
  assert.equal(read({ check: statusOnly, row: rowOf(statusOnly, 200, { ok: true }) }).status, 'fail', 'the same control on a complete response');
  for (const capture of ['absent', 'altered', 'unreadable']) assert.deepEqual([read({ capture }).status, read({ capture }).reason], ['inconclusive', `capture-${capture}`]);
  assert.equal(read({ entries: null }).reason, 'ledger-unreadable');
  assert.throws(() => rlsZeroRow({ check: control(), row: okRow, entries: [zero()], block: BLOCK, actors: ACTORS, decl: DECL }), /needs the window's capture status/);
  assert.throws(() => rlsZeroRow({ check: control(), row: okRow, entries: [zero()], block: BLOCK, capture: 'intact', actors: ACTORS }), /rlsZeroRow needs the rules' declaration/);
  // Never a pass, over every combination of the inputs above, with and without a pass-through and with service entries.
  const decls = [DECL, { ...DECL, passThrough: { from: 'jwt-claims' } }, { ...DECL, passThrough: { from: 'column' } }, { tool: 'desk-agent' }];
  const sets = [[], [zero()], [zero({ claims_sub: GIL })], [entry()], [zero({ claims_role: 'service_role', set_role: 'service_role' })], [entry({ op: 'INSERT' }), zero()], [zero(), service({ txid: '1101', xid32: '1101' })]];
  for (const check of [control(), control('GET'), { ...control(), severity: 'high' }, control('POST', 'ANA-OTHER')]) for (const r of [okRow, rowOf(check, 500, {})]) for (const entries of sets) for (const capture of ['intact', 'absent']) for (const decl of decls)
    assert.notEqual(rlsZeroRow({ check, row: r, entries, block: BLOCK, capture, actors: ACTORS, decl }).status, 'pass');
});
