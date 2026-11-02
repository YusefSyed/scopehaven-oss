// The actor join inside pg-snapshot and pg-wal, against a local Supabase stack
// through its PostgREST and auth services with synthetic users; the capture is installed by the stack's superuser, the
// tables are the postgres role's. Skipped unless the pg-actor.live.test.mjs variables name a
// local supabase start stack (never a hosted project; its Postgres has wal_level = logical). Each test creates its own
// table, roles, users and capture and removes them after.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { pgConnect } from './pg-wire.mjs';
import { installActorCapture, removeActorCapture } from './pg-actor.mjs';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { createPgWalObserver } from './pg-wal.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';

const live = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(process.env.SCOPEHAVEN_PG_ACTOR_LIVE ?? '');
const su = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(process.env.SCOPEHAVEN_PG_ACTOR_SUPERUSER ?? '');
const api = /^http:\/\/127\.0\.0\.1:\d+$/.test(process.env.SCOPEHAVEN_SUPABASE_LIVE ?? '') ? process.env.SCOPEHAVEN_SUPABASE_LIVE : null;
const anonKey = process.env.SCOPEHAVEN_SUPABASE_ANON_KEY, serviceKey = process.env.SCOPEHAVEN_SUPABASE_SERVICE_KEY;
const skip = live && su && api && anonKey && serviceKey ? false : 'set SCOPEHAVEN_PG_ACTOR_LIVE, SCOPEHAVEN_PG_ACTOR_SUPERUSER, SCOPEHAVEN_SUPABASE_LIVE, SCOPEHAVEN_SUPABASE_ANON_KEY and SCOPEHAVEN_SUPABASE_SERVICE_KEY to a local supabase start stack to run';
const [, adminUser, adminPassword, portText, database] = live ?? [];
const port = Number(portText);
const connect = (user = adminUser, password = adminPassword) => pgConnect({ host: '127.0.0.1', port, database, user, password });
const call = async (path, { method = 'GET', token = anonKey, key = anonKey, body, prefer } = {}) => {
  const res = await fetch(`${api}${path}`, { method, headers: { apikey: key, authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(prefer ? { prefer } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};
async function user(t, email) {
  const password = randomBytes(18).toString('base64url');
  const made = await call('/auth/v1/admin/users', { method: 'POST', token: serviceKey, key: serviceKey, body: { email, password, email_confirm: true } });
  assert.equal(made.status, 200);
  t.after(() => call(`/auth/v1/admin/users/${made.json.id}`, { method: 'DELETE', token: serviceKey, key: serviceKey }));
  const signed = await call('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
  assert.equal(signed.status, 200);
  return { id: made.json.id, token: signed.json.access_token };
}
// Owner-only orders, a WAL reader (REPLICATION) and a snapshot reader (SELECT, BYPASSRLS: pg-snapshot reads with
// row_security = off), the capture installed with both as readers, and both observers started on it.
async function fixture(t) {
  const admin = await connect(), superuser = await connect(su[1], su[2]), x = randomBytes(4).toString('hex'), table = `sh_join_orders_${x}`, walRole = `sh_join_wal_${x}`, snapRole = `sh_join_snap_${x}`;
  // Cleanup first, so a failure anywhere below (a timed-out sign-up, a refused installation) still closes the sessions and
  // drops what was made, the run's synthetic users included: matched on the run's suffix, so a sign-up that answered 504
  // but still made the user is removed too.
  const observers = [];
  let block = null;
  t.after(async () => {
    for (const o of observers) { try { await o.stop(); } catch {} }
    try { if (block) await removeActorCapture(superuser, block).catch(() => {}); await admin.query(`DROP TABLE IF EXISTS public.${table}`); await admin.query(`NOTIFY pgrst, 'reload schema'`); await admin.query(`DROP ROLE IF EXISTS ${walRole}; DROP ROLE IF EXISTS ${snapRole}`); await superuser.query(`DELETE FROM auth.users WHERE email LIKE '%-${x}@%.test'`); } finally { admin.close(); superuser.close(); }
  });
  const walPass = randomBytes(12).toString('base64url'), snapPass = randomBytes(12).toString('base64url');
  const ana = await user(t, `ana-${x}@acme.test`), gil = await user(t, `gil-${x}@globex.test`);
  await admin.query(`CREATE TABLE public.${table} (id text PRIMARY KEY, owner uuid NOT NULL, status text NOT NULL);
    ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY;
    CREATE POLICY own_select ON public.${table} FOR SELECT TO authenticated USING (owner = auth.uid());
    CREATE POLICY own_update ON public.${table} FOR UPDATE TO authenticated USING (owner = auth.uid());
    CREATE POLICY own_delete ON public.${table} FOR DELETE TO authenticated USING (owner = auth.uid());
    GRANT SELECT, UPDATE, DELETE ON public.${table} TO authenticated, service_role;
    INSERT INTO public.${table} VALUES ('ORD-1', '${ana.id}', 'open'), ('ORD-2', '${gil.id}', 'open')`);
  await admin.query(`CREATE ROLE ${walRole} LOGIN REPLICATION PASSWORD '${walPass}'; CREATE ROLE ${snapRole} LOGIN BYPASSRLS PASSWORD '${snapPass}'; GRANT SELECT ON public.${table} TO ${snapRole}`);
  block = { testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', schema: `sh_join_${x}`, tables: [{ table, key: 'id' }], actor: { from: 'jwt-claims' }, principals: { [ana.id]: 'ana', [gil.id]: 'gil' } };
  const installed = await installActorCapture(superuser, block, { readers: [walRole, snapRole] });
  await admin.query(`NOTIFY pgrst, 'reload schema'`);
  const env = { SCOPEHAVEN_TARGET_NC2_WAL: `${walRole}:${walPass}`, SCOPEHAVEN_TARGET_NC2_SNAP: `${snapRole}:${snapPass}` };
  const actorCapture = { block, installedSha256: installed.definitionSha256 };
  // The stack's pg_net extension keeps two unlogged tables in schema net (its outbound HTTP queue and responses), which the
  // checked-in supabase list does not name, so without this every window reads table-not-in-wal. This profile does not
  // observe pg_net's outbound requests and says so by ignoring the schema.
  const wal = createPgWalObserver({ instanceId: 'wal-1', env, host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_NC2_WAL', platform: 'supabase', ignore: ['net'], tables: [{ table, key: 'id', values: ['status'] }], actorCapture });
  const snap = createPgSnapshotObserver({ instanceId: 'snap-1', env, host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_NC2_SNAP', tables: [{ table, key: 'id' }], watchedResources: [`${table}/ORD-1`, `${table}/ORD-2`], actorCapture });
  const plain = createPgSnapshotObserver({ instanceId: 'snap-plain', env, host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_NC2_SNAP', tables: [{ table, key: 'id' }] });
  for (let i = 0; i < 50 && (await call(`/rest/v1/${table}?select=id`, { token: ana.token })).status !== 200; i++) await new Promise(r => setTimeout(r, 100));
  observers.push(wal, snap, plain);
  for (const o of observers) await o.start();
  const marks = async () => Promise.all([wal.mark(), snap.mark(), plain.mark()]);
  return { admin, superuser, table, block, ana, gil, wal, snap, plain, marks, rest: `/rest/v1/${table}` };
}
const shape = window => window.events.map(e => [e.operation, e.resource.split('/')[1], e.actor]).sort((x, y) => (`${x}` < `${y}` ? -1 : 1));

test('pg-wal joins each write on its own transaction; pg-snapshot attributes a row only when one actor wrote it', { skip }, async t => {
  const f = await fixture(t), [w0, s0, p0] = await f.marks();
  assert.equal((await call(`${f.rest}?id=eq.ORD-1`, { method: 'PATCH', token: f.ana.token, body: { status: 'refunded' }, prefer: 'return=representation' })).json.length, 1);
  assert.deepEqual((await call(`${f.rest}?id=eq.ORD-2`, { method: 'PATCH', token: f.ana.token, body: { status: 'refunded' }, prefer: 'return=representation' })).json, [], 'row-level security filters it');
  assert.equal((await call(`${f.rest}?id=eq.ORD-1`, { method: 'PATCH', token: serviceKey, key: serviceKey, body: { status: 'closed' }, prefer: 'return=representation' })).json.length, 1);
  assert.equal((await call(`${f.rest}?id=eq.ORD-2`, { method: 'PATCH', token: f.gil.token, body: { status: 'held' }, prefer: 'return=representation' })).json.length, 1);
  assert.equal((await call(`${f.rest}?id=eq.ORD-2`, { method: 'DELETE', token: f.gil.token, prefer: 'return=representation' })).json.length, 1);
  const [w1, s1, p1] = await f.marks();
  const raw = await f.wal.collect(w0, w1), wal = await collectWindow(f.wal, w0, w1), snap = await collectWindow(f.snap, s0, s1), plain = await collectWindow(f.plain, p0, p1);
  assert.equal(wal.coverage, 'complete', wal.reason);
  // pg-wal: each write, the service role's unattributed (the default resolver; ./supabase-rules.mjs names it the tool's).
  assert.deepEqual(shape(wal), [['delete', 'ORD-2', 'gil'], ['update', 'ORD-1', null], ['update', 'ORD-1', 'ana'], ['update', 'ORD-2', 'gil']]);
  assert.deepEqual(raw.actors, { schema: 'scopehaven-pg-actor/1', capture: { start: 'intact', end: 'intact', window: 'intact' }, attributed: 3, unattributed: 1, ambiguous: 0 });
  // The audit table's own changes are the capture's, counted apart, and never take a slot on the profile's ignore list.
  assert.deepEqual(raw.wal.others.unlisted, []);
  assert(raw.wal.others.capture > 0, 'the capture\'s audit rows are counted as its own');
  assert.deepEqual(raw.wal.others.ignore.profile, ['net']);
  // pg-snapshot: ORD-1 was written by ana and by the service role, so it is no one's; ORD-2's writes were all gil's.
  assert.deepEqual(shape(snap), [['delete', 'ORD-2', 'gil'], ['update', 'ORD-1', null]]);
  assert.deepEqual([snap.scope.actorAttribution, plain.scope.actorAttribution, wal.scope.actorAttribution], ['principal', 'none', 'principal']);
  const select = (operation, id, actor) => ({ source: 'sql-snapshot', operation, name: f.table, resource: `${f.table}/${id}`, actor });
  // Each observer's own source (pg-wal's is sql-wal).
  const verdict = (kind, sel, windows) => evaluateEffectAssertion({ kind, select: { ...sel, source: windows[0].source } }, windows).verdict;
  assert.equal(verdict('effect.exists', select('update', 'ORD-1', 'ana'), [wal]), 'pass');
  assert.equal(verdict('effect.none', select('update', 'ORD-2', 'ana'), [wal]), 'pass', 'her filtered update changed nothing, and every ORD-2 write was gil\'s');
  assert.equal(verdict('effect.exists', select('update', 'ORD-2', 'gil'), [wal]), 'pass');
  // The service role's write could be anyone's: an absence pinned to gil on ORD-1 is never a pass.
  assert.equal(verdict('effect.none', select('update', 'ORD-1', 'gil'), [wal]), 'missing');
  assert.notEqual(verdict('effect.none', select('update', 'ORD-1', 'gil'), [snap]), 'pass');
  assert.notEqual(verdict('effect.exists', select('update', 'ORD-1', 'ana'), [snap]), 'pass', 'a row two actors wrote is no one\'s');
  // Without the capture an actor pin is unobservable, as before.
  assert.equal(verdict('effect.none', select('update', 'ORD-1', 'gil'), [plain]), 'unobservable');
});

test('a capture dropped before the end mark attributes nothing in that window', { skip }, async t => {
  const f = await fixture(t), [w0, s0] = await f.marks();
  await call(`${f.rest}?id=eq.ORD-1`, { method: 'PATCH', token: f.ana.token, body: { status: 'refunded' } });
  const [name] = (await f.superuser.query(`SELECT tgname FROM pg_trigger WHERE tgrelid = 'public.${f.table}'::regclass AND tgname LIKE '%_update'`))[0].rows[0];
  await f.superuser.query(`DROP TRIGGER ${name} ON public.${f.table}`);
  const [w1, s1] = await f.marks();
  const raw = await f.wal.collect(w0, w1), wal = await collectWindow(f.wal, w0, w1), snapRaw = await f.snap.collect(s0, s1);
  assert.deepEqual([raw.actors.capture.end, snapRaw.actors.capture.end], ['absent', 'absent']);
  assert.deepEqual(shape(wal), [['update', 'ORD-1', null]]);
  assert.deepEqual(snapRaw.events.map(e => e.actor), [null]);
  assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: { source: wal.source, operation: 'update', name: f.table, resource: `${f.table}/ORD-1`, actor: 'ana' } }, [wal]).verdict, 'missing');
});
