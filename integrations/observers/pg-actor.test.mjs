// pg-actor without a database: the profile block, the installed SQL, the definition check, the install and
// removal flow, the ledger, the claims binding and the txid joins. pg-actor.live.test.mjs runs the same against a local
// Supabase stack.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateActorCapture, installSql, uninstallSql, verifySql, verifyRecord, verifyAtInstall, installActorCapture, removeActorCapture, installationRecord, ledgerSql, parseLedger,
  resolveActor, claimsBinding, attributeChange, attributeNetChange, windowLedger, ledgerOp, schemaOf, PG_ACTOR_SCHEMA, PLATFORM_SCHEMAS } from './pg-actor.mjs';

const ANA = 'a11ce000-0000-4000-8000-000000000001', GIL = 'b0b00000-0000-4000-8000-000000000002';
const BLOCK = Object.freeze({ testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', tables: [{ table: 'orders', key: 'id' }, { schema: 'billing', table: 'refunds', key: 'ref', actorColumn: 'made_by' }],
  actor: { from: 'jwt-claims' }, principals: { [ANA]: 'ana', [GIL]: 'gil' } });
const ACTORS = { ana: { principalId: 'ana' }, gil: { principalId: 'gil' } };
const block = (patch = {}) => ({ ...structuredClone(BLOCK), ...patch });

test('the profile block: a disposable copy, a superuser credential, declared tables, one actor source and declared principals', () => {
  assert.equal(validateActorCapture(block(), { actors: ACTORS }).actor.from, 'jwt-claims');
  assert.equal(validateActorCapture(block({ actor: { from: 'jwt-claims', claim: 'sub', authenticators: ['authenticator'], userRoles: ['authenticated', 'member'] } })).actor.userRoles.length, 2);
  const refused = [
    [{ testCopy: false }, /"testCopy": true is required/],
    [{ installCredentialEnv: 'PGPASSWORD' }, /SCOPEHAVEN_TARGET_ namespace/],
    ...['public', 'auth', 'storage', 'net', 'extensions', 'pg_audit', 'Auth'].map(schema => [{ schema }, /a schema of its own/]),
    [{ tables: [] }, /"tables" lists 1 to 32/],
    [{ tables: [{ table: 'orders', key: 'id' }, { table: 'orders', key: 'id' }] }, /declared twice/],
    [{ tables: [{ table: 'orders', key: 'id', schema: 'scopehaven_actor' }] }, /in the capture's own schema/],
    [{ tables: [{ table: 'orders', key: 'id; drop' }] }, /"key" is a plain identifier/],
    [{ tables: [{ table: 'orders', key: 'id', actorColumn: 'id' }] }, /never the actor column/],
    [{ tables: [{ table: 'orders', key: 'id', extra: 1 }] }, /\{ table, key, schema\?, actorColumn\? \}/],
    [{ actor: { from: 'header' } }, /"actor" is \{ "from"/],
    [{ actor: { from: 'current-user', claim: 'sub' } }, /allows only "from"/],
    [{ actor: { from: 'jwt-claims', claim: 'email' } }, /"claim" is "sub"/],
    [{ actor: { from: 'jwt-claims', userRoles: [] } }, /lists 1 to 8 distinct role names/],
    [{ actor: { from: 'jwt-claims', authenticators: ['a', 'a'] } }, /lists 1 to 8 distinct role names/],
    [{ actor: { from: 'column' } }, /needs every table's "actorColumn"/],
    [{ principals: {} }, /"principals" maps 1 to 64/],
    [{ principals: { u1: 'not a principal' } }, /names a principal id/],
    [{ principals: { u1: 'mallory' } }, /principalId of a declared actor/],
    [{ principals: JSON.parse('{"__proto__": "ana"}') }, /not __proto__/],
    [{ other: true }, /unsupported field "other"/],
  ];
  for (const [patch, pattern] of refused) assert.throws(() => validateActorCapture(block(patch), { actors: ACTORS }), pattern, JSON.stringify(patch));
  assert.throws(() => validateActorCapture(null), /must be a JSON object/);
  assert(PLATFORM_SCHEMAS.includes('auth') && PLATFORM_SCHEMAS.includes('net'));
});

test('the installation: a marked private schema, a definer function and reader, and three statement triggers per table named for this installation', () => {
  const sql = installSql(block(), { readers: ['sh_wal_reader'] });
  assert.deepEqual(sql.slice(0, 3), ['CREATE SCHEMA "scopehaven_actor"', `COMMENT ON SCHEMA "scopehaven_actor" IS '${PG_ACTOR_SCHEMA}'`, 'REVOKE ALL ON SCHEMA "scopehaven_actor" FROM PUBLIC']);
  assert(sql.includes('REVOKE ALL ON "scopehaven_actor".audit FROM PUBLIC') && sql.includes('ALTER TABLE "scopehaven_actor".audit ENABLE ROW LEVEL SECURITY'));
  assert.equal(sql.some(s => s.startsWith('DROP')), false, 'installSql drops nothing: the install removes only a marked earlier installation');
  const fn = sql.find(s => s.startsWith('CREATE FUNCTION "scopehaven_actor".capture'));
  assert.match(fn, /SECURITY DEFINER SET search_path = pg_catalog, pg_temp/);
  for (const piece of [/current_setting\('request\.jwt\.claims', true\)/, /current_setting\('request\.jwt\.claim\.sub', true\)/, /current_setting\('role'\)/, /session_user/, /current_setting\('request\.headers', true\)/, /pg_trigger_depth\(\)/, /IF n = 0 THEN/,
    /IF appcol IS NULL OR TG_OP = 'DELETE' THEN actor_sql := 'NULL'/, /CASE WHEN o\.%2\$I IS NULL THEN NULL WHEN \(o\.%1\$I\)::pg_catalog\.text IS DISTINCT FROM \(r\.%1\$I\)::pg_catalog\.text THEN/, /LEFT JOIN scopehaven_old o ON o\.%1\$I = r\.%1\$I/, /SELECT x\.xmin::pg_catalog\.text FROM %s x WHERE x\.%2\$I = r\.%2\$I LIMIT 1/]) assert.match(fn, piece);
  const triggers = sql.filter(s => s.startsWith('CREATE TRIGGER'));
  assert.equal(triggers.length, 6);
  assert(triggers.every(s => /^CREATE TRIGGER sh_actor_[0-9a-f]{10}_(insert|update|delete) AFTER /.test(s) && /FOR EACH STATEMENT EXECUTE FUNCTION "scopehaven_actor"\.capture\(/.test(s)));
  assert(triggers.some(s => /AFTER UPDATE ON "billing"\."refunds" REFERENCING OLD TABLE AS scopehaven_old NEW TABLE AS scopehaven_new FOR EACH STATEMENT EXECUTE FUNCTION "scopehaven_actor"\.capture\('ref', 'made_by'\)$/.test(s)));
  // Two installations never share a trigger name.
  const other = installSql(block({ schema: 'sh_other' })).filter(s => s.startsWith('CREATE TRIGGER')).map(s => s.split(' ')[2]);
  assert.equal(other.some(name => triggers.some(s => s.split(' ')[2] === name)), false);
  assert.deepEqual(sql.slice(-2), ['GRANT USAGE ON SCHEMA "scopehaven_actor" TO "sh_wal_reader"', 'GRANT EXECUTE ON FUNCTION "scopehaven_actor".ledger(bigint, integer) TO "sh_wal_reader"']);
  const reader = sql.find(s => s.startsWith('CREATE FUNCTION "scopehaven_actor".ledger'));
  assert.match(reader, /LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp/);
  assert(sql.includes('REVOKE ALL ON FUNCTION "scopehaven_actor".ledger(bigint, integer) FROM PUBLIC'));
  assert.equal(sql.some(s => /GRANT SELECT|CREATE POLICY/.test(s)), false, 'no reader gets the table itself');
  assert.throws(() => installSql(block(), { readers: ['x; drop'] }), /reader role/);
  assert.deepEqual(uninstallSql(block()).slice(-1), ['DROP SCHEMA IF EXISTS "scopehaven_actor" CASCADE']);
  assert.equal(schemaOf(block({ schema: 'sh_capture' })), 'sh_capture');
  assert.match(verifySql(block({ schema: 'sh_capture' })), /n\.nspname = 'sh_capture'/);
  assert.equal(/pg_get_triggerdef|pg_get_functiondef/.test(verifySql(block())), false, 'structured fields only: no text that depends on the search_path');
});

// verifySql's five results for an intact installation of BLOCK, as the server would print them.
const NAMES = installSql(block()).filter(s => s.startsWith('CREATE TRIGGER')).map(s => [s.split(' ')[2], s.split(' ')[6].replaceAll('"', '')]);
const intact = () => [
  { rows: [['supabase_admin:true', '{supabase_admin=UC/supabase_admin}', PG_ACTOR_SCHEMA, '900']] },
  { rows: [['capture', '', 'true', '{"search_path=pg_catalog, pg_temp"}', 'f1', 'supabase_admin:true', '{supabase_admin=X/supabase_admin}', '901', 'v'], ['ledger', 'after_seq bigint, max_rows integer', 'true', '{"search_path=pg_catalog, pg_temp"}', 'f2', 'supabase_admin:true', '{supabase_admin=X/supabase_admin}', '902', 's']] },
  { rows: NAMES.map(([name, table]) => [table, name, 'O', '29', '6964', '', '', 'true', '', 'capture', '903']).sort((x, y) => (`${x[0]}|${x[1]}` < `${y[0]}|${y[1]}` ? -1 : 1)) },
  { rows: [['true', 'false', 'p', 'r', '0', '0', '0', 'supabase_admin:true', '{supabase_admin=arwdDxtm/supabase_admin}']] },
  { rows: 'seq,txid,tbl,key,op,rowcount,depth,row_xmin,claims_sub,claims_role,legacy_sub,header_sub,set_role,session_role,app_actor,at'.split(',').map(c => [c, 'text']) },
];
test('the definition check: intact only as installed; absent and altered name what differs; the digest is required', () => {
  const base = verifyAtInstall(intact(), block());
  assert.equal(base.status, 'intact');
  assert.equal(verifyRecord(intact(), block(), base.sha256).status, 'intact');
  assert.throws(() => verifyRecord(intact(), block()), /needs the installation's digest/);
  const absent = [
    [r => { r[0].rows = []; }, 'schema'], [r => { r[1].rows = []; }, 'function'], [r => { r[1].rows.pop(); }, 'function'], [r => { r[3].rows = []; }, 'audit-table'], [r => { r[2].rows.pop(); }, 'trigger'],
    [r => { r[2].rows[0][2] = 'D'; }, 'trigger-disabled'], [r => { r[2].rows[0][2] = 'R'; }, 'trigger-disabled'],
  ];
  for (const [edit, missing] of absent) { const r = intact(); edit(r); const v = verifyRecord(r, block(), base.sha256); assert.deepEqual([v.status, v.reason, v.missing.includes(missing)], ['absent', 'capture-absent', true], missing); }
  const altered = [
    [r => { r[0].rows[0][2] = 'something else'; }, 'schema-mark'],
    [r => { r[1].rows[0][2] = 'false'; }, 'function-not-security-definer'], [r => { r[1].rows[1][2] = 'false'; }, 'function-not-security-definer'],
    [r => { r[1].rows[1][3] = '{"search_path=public"}'; }, 'function-search-path'], [r => { r[1].rows[0][3] = '{"search_path=pg_catalog, pg_temp, public"}'; }, 'function-search-path'],
    [r => { r[1].rows.push(['helper', '', 'false', null, 'f3', 'supabase_admin:true', null, '905', 'v']); }, 'functions'],
    [r => { r[1].rows[0][5] = 'postgres:false'; }, 'owner-not-superuser'], [r => { r[3].rows[0][7] = 'postgres:false'; }, 'owner-not-superuser'], [r => { r[0].rows[0][0] = 'postgres:false'; }, 'owner-not-superuser'],
    [r => { r[2].rows.push(['public.notes', NAMES[0][0], 'O', '29', '6964', '', '', 'true', '', 'capture', '906']); }, 'triggers'],
    [r => { r[3].rows[0][0] = 'false'; }, 'audit-row-security'], [r => { r[3].rows[0][6] = '1'; }, 'audit-row-security'],
    [r => { r[3].rows[0][2] = 'u'; }, 'audit-persistence'], [r => { r[3].rows[0][4] = '1'; }, 'audit-rewritten'], [r => { r[3].rows[0][5] = '1'; }, 'audit-rewritten'],
    [r => { r[4].rows.pop(); }, 'audit-columns'],
    // A body replaced, a privilege granted, a trigger disabled and enabled again (a new row version): only the digest sees them.
    [r => { r[1].rows[0][4] = 'f9'; }, 'definition-changed'], [r => { r[3].rows[0][8] = '{supabase_admin=arwdDxtm/supabase_admin,service_role=a/supabase_admin}'; }, 'definition-changed'],
    [r => { r[2].rows[0][10] = '999'; }, 'definition-changed'], [r => { r[1].rows[1][6] = '{supabase_admin=X/supabase_admin,authenticated=X/supabase_admin}'; }, 'definition-changed'],
  ];
  for (const [edit, what] of altered) { const r = intact(); edit(r); const v = verifyRecord(r, block(), base.sha256); assert.deepEqual([v.status, v.reason, v.altered.includes(what)], ['altered', 'capture-altered', true], what); }
  assert.deepEqual(verifyRecord([{ rows: [] }], block(), base.sha256), { status: 'unreadable', sha256: null, reason: 'capture-unreadable' });
});

// A scripted session: answers by statement, and records what was sent.
function session(answer) {
  const sent = [];
  return { sent, query: async sql => { sent.push(sql); const out = answer(sql, sent); if (out instanceof Error) throw out; return out ?? [{ rows: [] }]; } };
}
const superuser = sql => (sql.startsWith('SELECT current_user') ? [{ rows: [['supabase_admin', 'true']] }] : null);
// The table checks: kind, key column, actor column, unique index.
const tablesOk = sql => (sql.startsWith('SELECT c.relkind') ? BLOCK.tables.map(() => ({ rows: [['r', '1', '1', '1']] })) : null);
const verifyReads = sql => sql.startsWith('SELECT (SELECT r.rolname');
test('install: a superuser, in one transaction; a foreign schema, a missing column or a failed statement leaves nothing behind', async () => {
  const ok = session(sql => superuser(sql) ?? tablesOk(sql) ?? (sql.startsWith('SELECT pg_catalog.obj_description') ? [{ rows: [] }] : verifyReads(sql) ? intact() : null));
  const record = await installActorCapture(ok, block(), { at: '2026-10-24T23:00:00Z' });
  assert.deepEqual(record, installationRecord(block(), verifyAtInstall(intact(), block()).sha256, { at: '2026-10-24T23:00:00Z', replaced: false, installRole: 'supabase_admin' }));
  assert.deepEqual([record.change, record.auditTable, record.principals], ['installed', 'scopehaven_actor.audit', 2]);
  assert.equal(JSON.stringify(record).includes('a11ce000'), false, 'no captured value in the record');
  assert.equal(ok.sent[1], 'BEGIN'); assert(ok.sent.includes('COMMIT')); assert.equal(ok.sent.some(s => s.startsWith('DROP')), false, 'nothing earlier to remove');
  // An earlier marked installation is removed first, inside the same transaction.
  const again = session(sql => superuser(sql) ?? tablesOk(sql) ?? (sql.startsWith('SELECT pg_catalog.obj_description') ? [{ rows: [[PG_ACTOR_SCHEMA]] }] : verifyReads(sql) ? intact() : null));
  assert.equal((await installActorCapture(again, block())).replacedEarlier, true);
  const drop = again.sent.indexOf('DROP SCHEMA IF EXISTS "scopehaven_actor" CASCADE');
  assert(drop > again.sent.indexOf('BEGIN') && drop < again.sent.indexOf('COMMIT'));
  // Refusals.
  await assert.rejects(installActorCapture(session(sql => (sql.startsWith('SELECT current_user') ? [{ rows: [['postgres', 'false']] }] : null)), block()), /install with a superuser/);
  const foreign = session(sql => superuser(sql) ?? (sql.startsWith('SELECT pg_catalog.obj_description') ? [{ rows: [['an application schema']] }] : null));
  await assert.rejects(installActorCapture(foreign, block()), /exists and is not a capture's/);
  assert.equal(foreign.sent.some(s => /^(DROP|CREATE)/.test(s)), false); assert.equal(foreign.sent.at(-1), 'ROLLBACK');
  for (const [bad, pattern] of [[['v', '1', '1', '1'], /not an ordinary or partitioned table/], [['r', '0', '1', '1'], /no column named as its "key"/], [['r', '1', '0', '1'], /no column named as its "actorColumn"/], [['r', '1', '1', '0'], /no unique index on its "key" alone/]]) {
    const s = session(sql => superuser(sql) ?? (sql.startsWith('SELECT pg_catalog.obj_description') ? [{ rows: [] }] : sql.startsWith('SELECT c.relkind') ? [{ rows: [['r', '1', '1', '1']] }, { rows: [bad] }] : null));
    await assert.rejects(installActorCapture(s, block()), pattern); assert.equal(s.sent.some(x => x.startsWith('CREATE')), false); assert.equal(s.sent.at(-1), 'ROLLBACK');
  }
  const missing = session(sql => superuser(sql) ?? (sql.startsWith('SELECT pg_catalog.obj_description') ? [{ rows: [] }] : sql.startsWith('SELECT c.relkind') ? [{ rows: [['r', '1', '1', '1']] }, { rows: [] }] : null));
  await assert.rejects(installActorCapture(missing, block()), /table 2 does not exist/);
  const failing = session(sql => superuser(sql) ?? tablesOk(sql) ?? (sql.startsWith('SELECT pg_catalog.obj_description') ? [{ rows: [] }] : /AFTER DELETE ON "billing"/.test(sql) ? new Error('42809') : null));
  await assert.rejects(installActorCapture(failing, block()), /42809/); assert.equal(failing.sent.at(-1), 'ROLLBACK', 'the triggers created before it are rolled back with it');
  // The plan check: the trigger's own expressions over each table, writing nothing (no INSERT, UPDATE or DELETE of a declared
  // table, so no application trigger fires); one that fails refuses the install.
  assert(ok.sent.includes('SELECT (r."ref")::pg_catalog.text, (SELECT x.xmin::pg_catalog.text FROM "billing"."refunds" x WHERE x."ref" = r."ref" LIMIT 1), CASE WHEN o."ref" IS NULL THEN NULL WHEN (o."made_by")::pg_catalog.text IS DISTINCT FROM (r."made_by")::pg_catalog.text THEN (r."made_by")::pg_catalog.text END FROM "billing"."refunds" r LEFT JOIN "billing"."refunds" o ON o."ref" = r."ref" WHERE false'));
  assert.equal(ok.sent.filter(s => / WHERE false$/.test(s)).length, BLOCK.tables.length);
  assert.equal(ok.sent.some(s => /^(INSERT INTO|UPDATE|DELETE FROM) "(public|billing)"\."(orders|refunds)"/.test(s)), false, 'no declared table is written');
  const plan = session(sql => superuser(sql) ?? tablesOk(sql) ?? (sql.startsWith('SELECT pg_catalog.obj_description') ? [{ rows: [] }] : sql.includes('FROM "billing"."refunds" r LEFT JOIN') ? Object.assign(new Error('postgres: query-failed'), { sqlState: '42883' }) : null));
  await assert.rejects(installActorCapture(plan, block()), /"key" or "actorColumn" cannot be read as the trigger reads it \(42883\)/); assert.equal(plan.sent.at(-1), 'ROLLBACK');
  // Verified after commit: one that does not verify is removed again.
  const half = session((sql, sent) => superuser(sql) ?? tablesOk(sql) ?? (sql.startsWith('SELECT pg_catalog.obj_description') ? [{ rows: sent.includes('COMMIT') ? [[PG_ACTOR_SCHEMA]] : [] }] : verifyReads(sql) ? [{ rows: [] }, { rows: [] }, { rows: [] }, { rows: [] }, { rows: [] }] : null));
  await assert.rejects(installActorCapture(half, block()), /did not verify \(capture-absent\)/);
  assert(half.sent.includes('DROP SCHEMA IF EXISTS "scopehaven_actor" CASCADE'), 'removed again');
  // Removal: only a marked schema.
  const notOurs = session(sql => (sql.startsWith('SELECT pg_catalog.obj_description') ? [{ rows: [[null]] }] : null));
  await assert.rejects(removeActorCapture(notOurs, block()), /is not a capture's; nothing was removed/); assert.equal(notOurs.sent.some(s => s.startsWith('DROP')), false);
});

// A ledger row; the bearer token's sub follows the claims' unless given.
const row = (over = {}) => { const r = { seq: '1', txid: '4294968396', xid32: '1100', tbl: 'public.orders', key: 'ORD-1', op: 'UPDATE', rowcount: null, depth: '1', row_xmin: '1100', claims_sub: ANA, claims_role: 'authenticated', legacy_sub: null, header_sub: undefined, set_role: 'authenticated', session_role: 'authenticator', app_actor: null, ...over };
  if (r.header_sub === undefined) r.header_sub = r.claims_sub; return Object.values(r); };
test('the ledger: rows of one shape, the 32-bit id derived from the 64-bit one, a read cut at its limit refused', () => {
  const [e] = parseLedger([row()]);
  assert.deepEqual({ xid: e.xid, txid: e.txid, zeroRow: e.zeroRow, table: e.table, depth: e.depth, rowXmin: e.rowXmin }, { xid: '1100', txid: '4294968396', zeroRow: false, table: 'public.orders', depth: 1, rowXmin: '1100' });
  assert.equal(parseLedger([row({ rowcount: '0', key: null, row_xmin: null })])[0].zeroRow, true);
  for (const bad of [row({ xid32: '1101' }), row({ op: 'TRUNCATE' }), row({ rowcount: '2' }), row({ seq: 'x' }), row({ depth: '0' }), row({ row_xmin: 'x' }), row().slice(1), 'row']) assert.throws(() => parseLedger([bad]), /unreadable ledger/);
  assert.throws(() => parseLedger(null), /unreadable ledger/);
  assert.throws(() => parseLedger([row(), row({ seq: '2' })], { limit: 1 }), e2 => e2.code === 'ledger-truncated');
  assert.match(ledgerSql(block(), { afterSeq: 7, limit: 10 }), /FROM "scopehaven_actor"\.ledger\(7, 11\) AS l$/, 'one row past the limit');
  for (const bounds of [{ afterSeq: -1 }, { afterSeq: 1.5 }, { limit: 0 }, { limit: 200001 }]) assert.throws(() => ledgerSql(block(), bounds), /invalid ledger bounds/);
  assert.deepEqual(windowLedger(parseLedger([row()]), parseLedger([row(), row({ seq: '2' })])).map(x => x.seq), [2]);
});

test('the claims name a user only as PostgREST binds them: an authenticator login, SET ROLE to the claims\' user role, no conflicting legacy sub', () => {
  const [e] = parseLedger([row()]);
  assert.deepEqual(resolveActor(e, block()), { actor: 'ana', via: 'jwt-claims' });
  const cases = [
    [{ set_role: 'none', session_role: 'postgres' }, 'claims-unbound'],                       // a direct connection that set the claims (or kept them)
    [{ session_role: 'postgres' }, 'claims-unbound'],                                         // SET ROLE authenticated by another login
    [{ set_role: 'anon' }, 'claims-unbound'],                                                  // claims and role disagree
    [{ claims_role: 'service_role', set_role: 'service_role' }, 'not-a-user-role'],            // a service JWT that carries a sub
    [{ claims_role: 'anon', set_role: 'anon', claims_sub: null }, 'not-a-user-role'],
    [{ legacy_sub: GIL }, 'claims-conflict'],
    [{ header_sub: GIL }, 'claims-conflict'],                                                  // an RPC that rewrote the claims mid-request
    [{ header_sub: null }, 'claims-conflict'],                                                 // claims with no bearer sub behind them
    [{ claims_sub: null }, 'actor-unattributed'],
  ];
  for (const [over, reason] of cases) { const [x] = parseLedger([row(over)]); assert.deepEqual(resolveActor(x, block()), { actor: null, via: 'jwt-claims', reason }, JSON.stringify(over)); }
  const [legacy] = parseLedger([row({ legacy_sub: ANA })]); assert.equal(resolveActor(legacy, block()).actor, 'ana', 'an agreeing legacy sub');
  assert.equal(claimsBinding(parseLedger([row({ session_role: 'pgrst' })])[0], block({ actor: { from: 'jwt-claims', authenticators: ['pgrst'] } })), null);
  assert.equal(resolveActor(parseLedger([row({ claims_role: 'member', set_role: 'member' })])[0], block({ actor: { from: 'jwt-claims', userRoles: ['member'] } })).actor, 'ana');
  const [stranger] = parseLedger([row({ claims_sub: 'c0ffee00-0000-4000-8000-000000000009' })]);
  assert.match(resolveActor(stranger, block()).actor, /^unlisted:[0-9a-f]{16}$/);
  const roles = block({ actor: { from: 'current-user' }, principals: { authenticated: 'ana', postgres: 'gil' } }), [direct] = parseLedger([row({ claims_sub: null, claims_role: null, set_role: 'none', session_role: 'postgres' })]);
  assert.equal(resolveActor(e, roles).actor, 'ana'); assert.equal(resolveActor(direct, roles).actor, 'gil', 'no SET ROLE: the login role');
  const column = block({ actor: { from: 'column' }, tables: [{ table: 'orders', key: 'id', actorColumn: 'made_by' }], principals: { u1: 'ana' } });
  assert.equal(resolveActor(parseLedger([row({ app_actor: 'u1' })])[0], column).actor, 'ana');
  assert.equal(resolveActor(parseLedger([row({ app_actor: 'u1', op: 'DELETE' })])[0], column).reason, 'actor-unattributed', 'a deleted row\'s column says who wrote it, not who removed it');
  // The trigger leaves app_actor null on an UPDATE that did not change the column; that reads unattributed, never the last writer.
  assert.equal(resolveActor(parseLedger([row({ app_actor: null })])[0], column).reason, 'actor-unattributed');
});

test('the join: same transaction, table, key and operation; none, two actors or a null key is never an actor; the capture status is required', () => {
  const ledger = parseLedger([row(), row({ seq: '2', key: 'ORD-2', claims_sub: GIL }), row({ seq: '3', key: null, rowcount: '0', row_xmin: null }),
    row({ seq: '4', key: 'ORD-3' }), row({ seq: '5', key: 'ORD-3', claims_sub: GIL }), row({ seq: '6', key: 'ORD-4' }), row({ seq: '7', key: 'ORD-4' }), row({ seq: '8', key: null, row_xmin: null })]);
  const change = (key, over = {}) => ({ xid: '1100', table: 'public.orders', key, op: 'UPDATE', ...over });
  const at = (c, opts = {}) => attributeChange(c, ledger, block(), { capture: 'intact', ...opts });
  assert.deepEqual(at(change('ORD-1')), { actor: 'ana', via: 'jwt-claims' });
  assert.equal(at(change('ORD-2')).actor, 'gil');
  assert.equal(at(change('ORD-4')).actor, 'ana', 'the same actor twice is that actor');
  for (const [c, reason] of [[change('ORD-1', { xid: '1101' }), 'actor-unattributed'], [change('ORD-1', { op: 'DELETE' }), 'actor-unattributed'], [change('ORD-1', { table: 'billing.refunds' }), 'actor-unattributed'],
    [change(null), 'key-null'], [change('ORD-3'), 'actor-ambiguous']]) assert.equal(at(c).reason, reason, JSON.stringify(c));
  assert.equal(at(change(null, { xid: null })).reason, 'key-null', 'a null key never matches the null-key entries');
  // A zero-row entry names no row: one carrying a key (the trigger never writes one) is still never an actor.
  assert.equal(attributeChange(change('ORD-7'), parseLedger([row({ key: 'ORD-7', rowcount: '0' })]), block(), { capture: 'intact' }).reason, 'actor-unattributed');
  for (const capture of ['absent', 'altered', 'unreadable']) assert.deepEqual(at(change('ORD-1'), { capture }), { actor: null, reason: 'actor-unattributed', capture });
  for (const capture of [undefined, 'yes']) assert.throws(() => attributeChange(change('ORD-1'), ledger, block(), { capture }), /needs the window's capture status/);
  // A resolver of its own (the Supabase rules) decides what a row says; an ambiguous join keeps the resolvers' reasons.
  assert.deepEqual(at(change('ORD-1'), { resolve: () => ({ actor: 'unlisted:tool:desk', via: 'service-role' }) }), { actor: 'unlisted:tool:desk', via: 'service-role' });
  assert.deepEqual(at(change('ORD-1'), { resolve: () => ({ actor: null, via: 'service-role', reason: 'service-role-write' }) }), { actor: null, reason: 'service-role-write' });
  let n = 0; assert.deepEqual(at(change('ORD-4'), { resolve: () => (n++ ? { actor: 'ana' } : { actor: 'unlisted:tool:desk', reason: 'service-role-write' }) }), { actor: null, reason: 'actor-ambiguous', reasons: ['service-role-write'] });
  assert.deepEqual(['insert', 'update', 'delete', 'read'].map(ledgerOp), ['INSERT', 'UPDATE', 'DELETE', null]);
});

test('the net join (a snapshot row): every write to the row in the window must resolve to one actor; savepoint writes match on their own xmin', () => {
  const window = parseLedger([row({ seq: '1', key: 'ORD-2', xid32: '1100', txid: '4294968396', row_xmin: '1100' }), row({ seq: '2', key: 'ORD-2', xid32: '1101', txid: '4294968397', row_xmin: '1101', claims_sub: GIL }),
    row({ seq: '3', key: 'ORD-3', xid32: '1102', txid: '4294968398', row_xmin: '1102' }), row({ seq: '4', key: 'ORD-3', xid32: '1103', txid: '4294968399', row_xmin: '1103', op: 'INSERT' }),
    row({ seq: '5', key: 'ORD-4', op: 'DELETE', xid32: '1104', txid: '4294968400', row_xmin: null }), row({ seq: '6', key: 'ORD-5', xid32: '1105', txid: '4294968401', row_xmin: '1106' })]);
  const net = (key, xid, op = 'UPDATE') => attributeNetChange({ xid, table: 'public.orders', key, op }, window, block(), { capture: 'intact' });
  assert.deepEqual(net('ORD-2', '1101'), { actor: null, reason: 'actor-ambiguous', reasons: [] }, 'ana wrote it, then its owner gil: no one\'s');
  assert.equal(attributeChange({ xid: '1101', table: 'public.orders', key: 'ORD-2', op: 'UPDATE' }, window, block(), { capture: 'intact' }).actor, 'gil', 'the per-change join (pg-wal) reads each write on its own');
  assert.equal(net('ORD-3', '1103', 'INSERT').actor, 'ana', 'two writes by one actor, any operations');
  assert.deepEqual(net('ORD-3', '1199'), { actor: null, reason: 'actor-unattributed' }, 'the last write is not in the ledger: an uncaptured write');
  assert.equal(net('ORD-5', '1106').actor, 'ana', 'a write inside a savepoint: the row\'s xmin is the subtransaction\'s');
  assert.equal(net('ORD-4', null, 'DELETE').actor, 'ana', 'a deleted row: no xmin, the window\'s writes');
  assert.deepEqual(net('ORD-9', null, 'DELETE'), { actor: null, reason: 'actor-unattributed' });
  assert.equal(net(null, '1100').reason, 'key-null');
  assert.deepEqual(attributeNetChange({ xid: '1100', table: 'public.orders', key: 'ORD-2', op: 'UPDATE' }, window, block(), { capture: 'altered' }), { actor: null, reason: 'actor-unattributed', capture: 'altered' });
  assert.throws(() => attributeNetChange({ xid: '1100', table: 'public.orders', key: 'ORD-2', op: 'UPDATE' }, window, block()), /needs the window's capture status/);
});
