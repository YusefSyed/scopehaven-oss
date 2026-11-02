// pg-actor against a local Supabase stack (supabase start), through its own PostgREST and auth services, with synthetic
// users. Skipped unless all of these name a disposable local stack (never a hosted project):
//   SCOPEHAVEN_PG_ACTOR_LIVE        "user:password@127.0.0.1:port/database" for the role the application's tables belong to
//                                   (postgres on a Supabase stack): it creates the test tables and makes the direct writes
//   SCOPEHAVEN_PG_ACTOR_SUPERUSER   the same for a superuser (supabase_admin), which installs the capture
//   SCOPEHAVEN_SUPABASE_LIVE        the stack's API URL, http://127.0.0.1:<port>
//   SCOPEHAVEN_SUPABASE_ANON_KEY, SCOPEHAVEN_SUPABASE_SERVICE_KEY   the stack's local anon and service_role keys
// Each test creates its own tables, policies, roles, users and capture and removes them after.
//
// Covers what the scripted session cannot: request.jwt.claims as PostgREST sets it for a signed-in user and for the
// service role, and as a direct connection sets it (unbound); SET ROLE read through a SECURITY DEFINER function; an
// UPDATE that row-level security filters to zero rows; the join on a row's real xmin, inside a savepoint too; an UPDATE
// that leaves the app column unchanged; a cascaded statement's depth; the application roles and the table owner kept out
// of the capture; a dropped, disabled (even within one transaction), replaced or granted capture; a foreign or platform
// schema, a misdeclared column and a second installation; verification from another session.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { pgConnect } from './pg-wire.mjs';
import { installActorCapture, removeActorCapture, verifySql, verifyRecord, ledgerSql, parseLedger, attributeChange, attributeNetChange, resolveActor } from './pg-actor.mjs';

const dsn = text => /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(text ?? '');
const app = dsn(process.env.SCOPEHAVEN_PG_ACTOR_LIVE), su = dsn(process.env.SCOPEHAVEN_PG_ACTOR_SUPERUSER);
const api = /^http:\/\/127\.0\.0\.1:\d+$/.test(process.env.SCOPEHAVEN_SUPABASE_LIVE ?? '') ? process.env.SCOPEHAVEN_SUPABASE_LIVE : null;
const anonKey = process.env.SCOPEHAVEN_SUPABASE_ANON_KEY, serviceKey = process.env.SCOPEHAVEN_SUPABASE_SERVICE_KEY;
const skip = app && su && api && anonKey && serviceKey ? false : 'set SCOPEHAVEN_PG_ACTOR_LIVE, SCOPEHAVEN_PG_ACTOR_SUPERUSER, SCOPEHAVEN_SUPABASE_LIVE, SCOPEHAVEN_SUPABASE_ANON_KEY and SCOPEHAVEN_SUPABASE_SERVICE_KEY to a local supabase start stack to run';
const connect = m => pgConnect({ host: '127.0.0.1', port: Number(m[3]), database: m[4], user: m[1], password: m[2] });

const call = async (path, { method = 'GET', token = anonKey, key = anonKey, body, prefer } = {}) => {
  const res = await fetch(`${api}${path}`, { method, headers: { apikey: key, authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(prefer ? { prefer } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};
// A synthetic user through the stack's auth admin API, signed in with a password used only here.
async function user(t, email) {
  const password = randomBytes(18).toString('base64url');
  const made = await call('/auth/v1/admin/users', { method: 'POST', token: serviceKey, key: serviceKey, body: { email, password, email_confirm: true } });
  assert.equal(made.status, 200, `create ${email}`);
  t.after(() => call(`/auth/v1/admin/users/${made.json.id}`, { method: 'DELETE', token: serviceKey, key: serviceKey }));
  const signed = await call('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
  assert.equal(signed.status, 200, `sign in ${email}`);
  return { id: made.json.id, token: signed.json.access_token };
}
// Two tenants' orders (and a child table with a cascading key) behind owner-only policies, the capture installed on them by
// the superuser, and a reload of PostgREST's schema cache.
async function fixture(t, { actorColumn = false } = {}) {
  const owner = await connect(app), admin = await connect(su), x = randomBytes(4).toString('hex'), table = `sh_actor_orders_${x}`, child = `sh_actor_items_${x}`;
  // Cleanup first, so a failure anywhere below (a timed-out sign-up, a refused installation) still closes the sessions and
  // drops what was made, the run's synthetic users included: matched on the run's suffix, so a sign-up that answered 504
  // but still made the user is removed too.
  let block = null;
  t.after(async () => {
    try { if (block) await removeActorCapture(admin, block).catch(() => {}); await owner.query(`DROP TABLE IF EXISTS public.${child}; DROP TABLE IF EXISTS public.${table}`); await owner.query(`NOTIFY pgrst, 'reload schema'`); await admin.query(`DELETE FROM auth.users WHERE email LIKE '%-${x}@%.test'`); }
    finally { owner.close(); admin.close(); }
  });
  const ana = await user(t, `ana-${x}@acme.test`), gil = await user(t, `gil-${x}@globex.test`);
  await owner.query(`CREATE TABLE public.${table} (id text PRIMARY KEY, owner uuid NOT NULL, status text NOT NULL, made_by text);
    CREATE TABLE public.${child} (id text PRIMARY KEY, order_id text NOT NULL REFERENCES public.${table} (id) ON DELETE CASCADE);
    ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY;
    CREATE POLICY own_select ON public.${table} FOR SELECT TO authenticated USING (owner = auth.uid());
    CREATE POLICY own_update ON public.${table} FOR UPDATE TO authenticated USING (owner = auth.uid());
    CREATE POLICY own_delete ON public.${table} FOR DELETE TO authenticated USING (owner = auth.uid());
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.${table}, public.${child} TO authenticated, service_role;
    INSERT INTO public.${table} VALUES ('ORD-1', '${ana.id}', 'open', NULL), ('ORD-2', '${gil.id}', 'open', NULL)`);
  block = { testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', schema: `sh_actor_${x}`, tables: actorColumn ? [{ table, key: 'id', actorColumn: 'made_by' }] : [{ table, key: 'id' }, { table: child, key: 'id' }],
    actor: actorColumn ? { from: 'column' } : { from: 'jwt-claims' }, principals: { [ana.id]: 'ana', [gil.id]: 'gil' } };
  const installed = await installActorCapture(admin, block);
  await owner.query(`NOTIFY pgrst, 'reload schema'`);
  for (let i = 0; i < 50 && (await call(`/rest/v1/${table}?select=id`, { token: ana.token })).status !== 200; i++) await new Promise(r => setTimeout(r, 100));
  const ledger = async () => parseLedger((await admin.query(ledgerSql(block)))[0].rows);
  const xmin = async id => (await owner.query(`SELECT xmin::text FROM public.${table} WHERE id = '${id}'`))[0].rows[0][0];
  // Verified from a session of its own, as an observer's mark is.
  const verify = async () => { const s = await connect(su); try { return verifyRecord(await s.query(verifySql(block)), block, installed.definitionSha256); } finally { s.close(); } };
  return { owner, admin, table, child, block, installed, ana, gil, ledger, xmin, verify, rest: `/rest/v1/${table}` };
}
const intactOf = async f => { const v = await f.verify(); assert.equal(v.status, 'intact', JSON.stringify(v)); return v; };

test('PostgREST writes are recorded with their claims and role; a filtered update is a zero-row statement; a direct write\'s claims are unbound', { skip }, async t => {
  const f = await fixture(t);
  await intactOf(f);
  const own = await call(`${f.rest}?id=eq.ORD-1`, { method: 'PATCH', token: f.ana.token, body: { status: 'refunded' }, prefer: 'return=representation' });
  assert.deepEqual([own.status, own.json.length], [200, 1]);
  const x1 = await f.xmin('ORD-1');
  const foreign = await call(`${f.rest}?id=eq.ORD-2`, { method: 'PATCH', token: f.ana.token, body: { status: 'refunded' }, prefer: 'return=representation' });
  assert.deepEqual([foreign.status, foreign.json], [200, []], 'row-level security filters it, and PostgREST answers 200 with nothing changed');
  const service = await call(`${f.rest}?id=eq.ORD-2`, { method: 'PATCH', token: serviceKey, key: serviceKey, body: { status: 'closed' }, prefer: 'return=representation' });
  assert.deepEqual([service.status, service.json.length], [200, 1]);
  const x3 = await f.xmin('ORD-2');
  // A direct connection by the table owner that sets the user's claims itself (no SET ROLE): unbound, never the user's.
  await f.owner.query(`BEGIN; SELECT set_config('request.jwt.claims', '{"sub":"${f.ana.id}","role":"authenticated"}', true); UPDATE public.${f.table} SET status = 'direct' WHERE id = 'ORD-1'; COMMIT`);
  const x4 = await f.xmin('ORD-1');
  const gone = await call(`${f.rest}?id=eq.ORD-2`, { method: 'DELETE', token: f.gil.token, prefer: 'return=representation' });
  assert.deepEqual([gone.status, gone.json.length], [200, 1]);
  const rows = (await f.ledger()).filter(e => e.table === `public.${f.table}` && e.op !== 'INSERT');
  assert.deepEqual(rows.map(e => [e.op, e.key, e.zeroRow, e.depth, e.claimsSub, e.claimsRole, e.setRole, e.sessionRole]), [
    ['UPDATE', 'ORD-1', false, 1, f.ana.id, 'authenticated', 'authenticated', 'authenticator'],
    ['UPDATE', null, true, 1, f.ana.id, 'authenticated', 'authenticated', 'authenticator'],
    ['UPDATE', 'ORD-2', false, 1, null, 'service_role', 'service_role', 'authenticator'],
    ['UPDATE', 'ORD-1', false, 1, f.ana.id, 'authenticated', 'none', app[1]],
    ['DELETE', 'ORD-2', false, 1, f.gil.id, 'authenticated', 'authenticated', 'authenticator'],
  ]);
  const ledger = await f.ledger(), at = (xid, key, op = 'UPDATE') => attributeChange({ xid, table: `public.${f.table}`, key, op }, ledger, f.block, { capture: 'intact' });
  assert.deepEqual(at(x1, 'ORD-1'), { actor: 'ana', via: 'jwt-claims' });
  assert.deepEqual(at(x3, 'ORD-2'), { actor: null, reason: 'not-a-user-role' }, 'the service role carries no user (./supabase-rules.mjs names it the tool\'s)');
  assert.deepEqual(at(x4, 'ORD-1'), { actor: null, reason: 'claims-unbound' }, 'claims a direct session set itself bind no request');
  // The cascade: deleting the order ran a foreign-key action's DELETE on its (absent) items, a zero-row statement on the
  // child table. PostgreSQL 17 fires it at depth 1, as if the session had sent it, so depth does not mark a cascade:
  // ./supabase-rules.mjs counts only the table and operation an allowed-use control declares it writes.
  const cascade = (await f.ledger()).filter(e => e.table === `public.${f.child}` && e.op === 'DELETE');
  assert.deepEqual(cascade.map(e => [e.zeroRow, e.depth]), [[true, 1]]);
});

test('a write inside a savepoint joins on its own xmin; an UPDATE that leaves the app column alone names no one', { skip }, async t => {
  const f = await fixture(t, { actorColumn: true }), table = `public.${f.table}`;
  await f.owner.query(`BEGIN; SAVEPOINT a; UPDATE ${table} SET status = 'sub', made_by = '${f.ana.id}' WHERE id = 'ORD-1'; RELEASE SAVEPOINT a; COMMIT`);
  const x = await f.xmin('ORD-1'), [e] = (await f.ledger()).filter(r => r.table === table && r.op === 'UPDATE');
  assert.notEqual(e.xid, x, 'the row\'s xmin is the subtransaction\'s'); assert.equal(e.rowXmin, x);
  assert.equal(attributeNetChange({ xid: x, table, key: 'ORD-1', op: 'UPDATE' }, await f.ledger(), f.block, { capture: 'intact' }).actor, 'ana');
  // Later, a write of the status alone: the column still holds ana's id, but this statement did not write it.
  await f.owner.query(`UPDATE ${table} SET status = 'later' WHERE id = 'ORD-1'`);
  const later = (await f.ledger()).filter(r => r.table === table && r.op === 'UPDATE').at(-1);
  assert.equal(later.appActor, null);
  assert.equal(resolveActor(later, f.block).reason, 'actor-unattributed');
});

test('the application roles cannot read, forge or call the capture, the table owner cannot rewrite it, and a reader reads only through the ledger function', { skip }, async t => {
  const f = await fixture(t), schema = f.block.schema;
  for (const role of ['authenticated', 'anon', 'service_role']) {
    for (const sql of [`SELECT count(*) FROM ${schema}.audit`, `INSERT INTO ${schema}.audit (txid, tbl, op, depth) VALUES (1, 'x', 'UPDATE', 1)`, `SELECT ${schema}.capture()`, `SELECT * FROM ${schema}.ledger(0, 10)`, `TRUNCATE ${schema}.audit`]) {
      await assert.rejects(f.owner.query(`BEGIN; SET LOCAL ROLE ${role}; ${sql}; COMMIT`), e => ['42501', '0A000'].includes(e.sqlState), `${role}: ${sql}`);
      await f.owner.query('ROLLBACK');
    }
  }
  // The application tables' owner (postgres) is no superuser: it cannot rewrite, replace or reconfigure the capture, and a
  // GRANT from it grants nothing (PostgreSQL warns and changes no privilege), so service_role still cannot write it.
  for (const sql of [`UPDATE ${schema}.audit SET claims_sub = 'x'`, `CREATE OR REPLACE FUNCTION ${schema}.capture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`,
    `ALTER TABLE ${schema}.audit DISABLE ROW LEVEL SECURITY`, `DELETE FROM ${schema}.audit`]) {
    await assert.rejects(f.owner.query(sql), e => e.sqlState === '42501', sql);
  }

  assert.notEqual((await call(`/rest/v1/audit`, { token: serviceKey, key: serviceKey })).status, 200, 'the capture\'s schema is not exposed');
  await intactOf(f);
  const reader = `sh_actor_reader_${randomBytes(4).toString('hex')}`, password = randomBytes(12).toString('base64url');
  await f.admin.query(`CREATE ROLE ${reader} LOGIN PASSWORD '${password}'`);
  t.after(async () => { const a = await connect(su); try { await a.query(`DROP OWNED BY ${reader}; DROP ROLE IF EXISTS ${reader}`); } finally { a.close(); } });
  f.installed.definitionSha256 = (await installActorCapture(f.admin, f.block, { readers: [reader] })).definitionSha256;
  await call(`${f.rest}?id=eq.ORD-1`, { method: 'PATCH', token: f.ana.token, body: { status: 'seen' } });
  const r = await pgConnect({ host: '127.0.0.1', port: Number(app[3]), database: app[4], user: reader, password });
  try {
    const read = await r.query(`BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path = pg_catalog; SET LOCAL row_security = off; ${ledgerSql(f.block)}; COMMIT`);
    assert.deepEqual(parseLedger(read[3].rows).filter(e => e.op === 'UPDATE').map(e => [e.key, e.claimsSub]), [['ORD-1', f.ana.id]]);
    await assert.rejects(r.query(`SELECT count(*) FROM ${schema}.audit`), e => e.sqlState === '42501');
  } finally { r.close(); }
  // A GRANT from the table owner grants nothing (PostgreSQL warns, the privileges stay as installed), so the capture stays
  // intact and service_role still cannot write the audit table.
  try { await f.owner.query(`GRANT INSERT ON ${schema}.audit TO service_role`); } catch (e) { assert.equal(e.sqlState, '42501'); }
  assert.equal((await f.verify()).status, 'intact');
  await assert.rejects(f.owner.query(`BEGIN; SET LOCAL ROLE service_role; INSERT INTO ${schema}.audit (txid, tbl, op, depth) VALUES (1, 'x', 'UPDATE', 1); COMMIT`), e => e.sqlState === '42501');
  await f.owner.query('ROLLBACK');
});

test('a dropped, disabled, replaced, granted or re-owned capture reads absent or altered at the next mark, even when undone within one transaction', { skip }, async t => {
  const f = await fixture(t), table = `public.${f.table}`;
  const [name] = (await f.admin.query(`SELECT tgname FROM pg_trigger WHERE tgrelid = '${table}'::regclass AND tgname LIKE '%_update'`))[0].rows[0];
  const tamper = [
    [`DROP TRIGGER ${name} ON ${table}`, 'absent'],
    [`ALTER TABLE ${table} DISABLE TRIGGER ${name}`, 'absent'],
    [`BEGIN; ALTER TABLE ${table} DISABLE TRIGGER ${name}; UPDATE ${table} SET status = 'unseen' WHERE id = 'ORD-1'; ALTER TABLE ${table} ENABLE TRIGGER ${name}; COMMIT`, 'altered'],
    [`ALTER TABLE ${f.block.schema}.audit DISABLE ROW LEVEL SECURITY`, 'altered'],
    [`CREATE OR REPLACE FUNCTION ${f.block.schema}.capture() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ BEGIN RETURN NULL; END $$`, 'altered'],
    [`GRANT INSERT ON ${f.block.schema}.audit TO service_role`, 'altered'],
    [`ALTER TABLE ${f.block.schema}.audit OWNER TO postgres`, 'altered'],
    [`CREATE POLICY open ON ${f.block.schema}.audit FOR SELECT USING (true)`, 'altered'],
  ];
  for (const [sql, status] of tamper) {
    await f.admin.query(sql);
    const v = await f.verify();
    assert.equal(v.status, status, sql);
    assert.equal(attributeChange({ xid: '1', table, key: 'ORD-1', op: 'UPDATE' }, await f.ledger(), f.block, { capture: v.status }).reason, 'actor-unattributed');
    // Installed again for the next case; the record says it replaced an earlier installation.
    if (sql.includes('OWNER TO')) await f.admin.query(`ALTER TABLE ${f.block.schema}.audit OWNER TO ${su[1]}`);
    const again = await installActorCapture(f.admin, f.block);
    assert.equal(again.replacedEarlier, true);
    f.installed.definitionSha256 = again.definitionSha256;
    await intactOf(f);
  }
});

test('a foreign or platform schema, a misdeclared column or a non-superuser is refused and leaves nothing; two installations live side by side', { skip }, async t => {
  const f = await fixture(t), x = randomBytes(4).toString('hex');
  // A schema that is not a capture's is never taken (nor dropped).
  await f.owner.query(`CREATE SCHEMA sh_app_${x}`);
  t.after(async () => { const a = await connect(app); try { await a.query(`DROP SCHEMA IF EXISTS sh_app_${x} CASCADE`); } finally { a.close(); } });
  await assert.rejects(installActorCapture(f.admin, { ...f.block, schema: `sh_app_${x}` }), /exists and is not a capture's/);
  assert.deepEqual((await f.owner.query(`SELECT count(*)::text FROM pg_namespace WHERE nspname = 'sh_app_${x}'`))[0].rows, [['1']]);
  await assert.rejects(removeActorCapture(f.admin, { ...f.block, schema: `sh_app_${x}` }), /is not a capture's; nothing was removed/);
  // A misdeclared key column: refused before any trigger exists, so no application write fails.
  const wrong = { ...f.block, schema: `sh_wrong_${x}`, tables: [{ table: f.table, key: 'ref' }] };
  await assert.rejects(installActorCapture(f.admin, wrong), /no column named as its "key"/);
  assert.deepEqual((await f.owner.query(`SELECT count(*)::text FROM pg_namespace WHERE nspname = 'sh_wrong_${x}'`))[0].rows, [['0']]);
  assert.equal((await call(`${f.rest}?id=eq.ORD-1`, { method: 'PATCH', token: f.ana.token, body: { status: 'still' }, prefer: 'return=representation' })).json.length, 1);
  await assert.rejects(installActorCapture(f.owner, { ...f.block, schema: `sh_owner_${x}` }), /install with a superuser/);
  // A second installation on the same table: each verifies intact, and removing one leaves the other's triggers.
  const second = { ...f.block, schema: `sh_second_${x}`, tables: [{ table: f.table, key: 'id' }] };
  const record = await installActorCapture(f.admin, second);
  t.after(async () => { const a = await connect(su); try { await removeActorCapture(a, second); } finally { a.close(); } });
  await intactOf(f);
  assert.equal(verifyRecord(await f.admin.query(verifySql(second)), second, record.definitionSha256).status, 'intact');
  await removeActorCapture(f.admin, second);
  await intactOf(f);
});

test('a 2,000-row update stays fast, a claims rewrite mid-request is caught, and keys, json columns and a rewritten audit table are handled', { skip }, async t => {
  const f = await fixture(t), table = `public.${f.table}`, x = randomBytes(4).toString('hex');
  // A bulk write as a signed-in user: every row gets its audit entry, through the key's index, in well under the timeout.
  await f.owner.query(`INSERT INTO ${table} SELECT 'BULK-' || g, '${f.ana.id}', 'open', NULL FROM generate_series(1, 2000) g`);
  const started = Date.now();
  const bulk = await call(`${f.rest}?id=like.BULK-*`, { method: 'PATCH', token: f.ana.token, body: { status: 'bulk' }, prefer: 'return=minimal' });
  const took = Date.now() - started;
  assert.equal(bulk.status, 204); assert(took < 5000, `the bulk update took ${took} ms`);
  assert.equal((await f.ledger()).filter(e => e.op === 'UPDATE' && e.key?.startsWith('BULK-') && e.claimsSub === f.ana.id).length, 2000);
  // An RPC that rewrites the claims to gil's before writing gil's row: the request's own bearer token still names ana.
  await f.owner.query(`CREATE FUNCTION public.sh_rewrite_${x}() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$ BEGIN
      PERFORM set_config('request.jwt.claims', json_build_object('sub', '${f.gil.id}', 'role', 'authenticated')::text, true);
      UPDATE ${table} SET status = 'rpc' WHERE id = 'ORD-2'; END $$;
    GRANT EXECUTE ON FUNCTION public.sh_rewrite_${x}() TO authenticated; NOTIFY pgrst, 'reload schema'`);
  t.after(async () => { const a = await connect(app); try { await a.query(`DROP FUNCTION IF EXISTS public.sh_rewrite_${x}()`); } finally { a.close(); } });
  let rpc;
  for (let i = 0; i < 50; i++) { rpc = await call(`/rest/v1/rpc/sh_rewrite_${x}`, { method: 'POST', token: f.ana.token, body: {} }); if (rpc.status !== 404) break; await new Promise(r => setTimeout(r, 100)); }
  assert.equal(rpc.status, 204);
  const rewritten = (await f.ledger()).filter(e => e.op === 'UPDATE' && e.key === 'ORD-2').at(-1);
  assert.deepEqual([rewritten.claimsSub, rewritten.headerSub], [f.gil.id, f.ana.id]);
  assert.equal(attributeChange({ xid: rewritten.xid, table, key: 'ORD-2', op: 'UPDATE' }, await f.ledger(), f.block, { capture: 'intact' }).reason, 'claims-conflict', 'never credited to gil');
  // A table whose key has no unique index is refused before any trigger exists.
  await f.owner.query(`CREATE TABLE public.sh_nokey_${x} (id text, made_by jsonb)`);
  t.after(async () => { const a = await connect(app); try { await a.query(`DROP TABLE IF EXISTS public.sh_nokey_${x}; DROP TABLE IF EXISTS public.sh_json_${x}`); } finally { a.close(); } });
  await assert.rejects(installActorCapture(f.admin, { ...f.block, schema: `sh_nokey_${x}`, tables: [{ table: `sh_nokey_${x}`, key: 'id' }] }), /no unique index on its "key" alone/);
  // A json actor column installs and verifies, an UPDATE that writes it records it, and one that moves the key records no one.
  await f.owner.query(`CREATE TABLE public.sh_json_${x} (id text PRIMARY KEY, made_by json); INSERT INTO public.sh_json_${x} VALUES ('J-1', '"a"')`);
  const json = { ...f.block, schema: `sh_jsoncap_${x}`, actor: { from: 'column' }, tables: [{ table: `sh_json_${x}`, key: 'id', actorColumn: 'made_by' }], principals: { '"b"': 'ana' } };
  const record = await installActorCapture(f.admin, json);
  t.after(async () => { const a = await connect(su); try { await removeActorCapture(a, json); } finally { a.close(); } });
  await f.owner.query(`UPDATE public.sh_json_${x} SET made_by = '"b"' WHERE id = 'J-1'; UPDATE public.sh_json_${x} SET id = 'J-2', made_by = '"c"' WHERE id = 'J-1'`);
  const jrows = parseLedger((await f.admin.query(ledgerSql(json)))[0].rows).filter(e => e.op === 'UPDATE');
  assert.deepEqual(jrows.map(e => [e.key, e.appActor]), [['J-1', '"b"'], ['J-2', null]]);
  // VACUUM FULL rewrites the audit table, but changes none of the definitions: still intact.
  await f.admin.query(`VACUUM FULL ${json.schema}.audit`);
  assert.equal(verifyRecord(await f.admin.query(verifySql(json)), json, record.definitionSha256).status, 'intact');
});

test('a key GENERATED ALWAYS AS IDENTITY and a generated stored column install, and their writes are recorded', { skip }, async t => {
  const f = await fixture(t), x = randomBytes(4).toString('hex'), table = `sh_ident_${x}`;
  // The default Supabase table shape: an identity key the application never writes, and a generated search column.
  await f.owner.query(`CREATE TABLE public.${table} (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, title text NOT NULL, made_by text, search tsvector GENERATED ALWAYS AS (to_tsvector('simple', title)) STORED)`);
  t.after(async () => { const a = await connect(app); try { await a.query(`DROP TABLE IF EXISTS public.${table}`); } finally { a.close(); } });
  const ident = { ...f.block, schema: `sh_identcap_${x}`, actor: { from: 'column' }, tables: [{ table, key: 'id', actorColumn: 'made_by' }], principals: { u1: 'ana', u2: 'gil' } };
  const record = await installActorCapture(f.admin, ident);
  t.after(async () => { const a = await connect(su); try { await removeActorCapture(a, ident); } finally { a.close(); } });
  await f.owner.query(`INSERT INTO public.${table} (title, made_by) VALUES ('first', 'u1'); UPDATE public.${table} SET made_by = 'u2', title = 'second' WHERE made_by = 'u1'`);
  const rows = parseLedger((await f.admin.query(ledgerSql(ident)))[0].rows);
  assert.deepEqual(rows.map(e => [e.op, e.key, e.appActor]), [['INSERT', '1', 'u1'], ['UPDATE', '1', 'u2']]);
  assert.equal(verifyRecord(await f.admin.query(verifySql(ident)), ident, record.definitionSha256).status, 'intact');
  // With no actor column, an identity key installs too.
  const bare = { ...f.block, schema: `sh_identbare_${x}`, tables: [{ table, key: 'id' }] };
  await installActorCapture(f.admin, bare);
  t.after(async () => { const a = await connect(su); try { await removeActorCapture(a, bare); } finally { a.close(); } });
  // The install writes nothing to a declared table: an identity key beside a column whose name needs quoting, and an
  // append-only table whose own trigger refuses every UPDATE and DELETE, both install.
  const spaced = `sh_spaced_${x}`, ledger = `sh_ledger_${x}`;
  await f.owner.query(`CREATE TABLE public.${spaced} (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, "Created At" timestamptz DEFAULT now());
    CREATE TABLE public.${ledger} (id text PRIMARY KEY, made_by text);
    CREATE FUNCTION public.${ledger}_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'append only'; END $$;
    CREATE TRIGGER ${ledger}_append_only BEFORE UPDATE OR DELETE ON public.${ledger} FOR EACH STATEMENT EXECUTE FUNCTION public.${ledger}_append_only()`);
  t.after(async () => { const a = await connect(app); try { await a.query(`DROP TABLE IF EXISTS public.${spaced}; DROP TABLE IF EXISTS public.${ledger}; DROP FUNCTION IF EXISTS public.${ledger}_append_only()`); } finally { a.close(); } });
  const ledgerBlock = { ...f.block, schema: `sh_ledgercap_${x}`, tables: [{ table: ledger, key: 'id', actorColumn: 'made_by' }] };
  for (const more of [{ ...f.block, schema: `sh_spacedcap_${x}`, tables: [{ table: spaced, key: 'id' }] }, ledgerBlock]) {
    await installActorCapture(f.admin, more);
    t.after(async () => { const a = await connect(su); try { await removeActorCapture(a, more); } finally { a.close(); } });
  }
  await f.owner.query(`INSERT INTO public.${ledger} VALUES ('L-1', 'u1')`);
  assert.deepEqual(parseLedger((await f.admin.query(ledgerSql(ledgerBlock)))[0].rows).map(e => [e.op, e.key]), [['INSERT', 'L-1']]);
});
