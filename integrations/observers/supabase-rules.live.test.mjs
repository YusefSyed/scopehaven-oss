// Supabase identity rules over a local Supabase stack (supabase start), with an owned app on 127.0.0.1 in
// front of the stack's PostgREST and synthetic users. Skipped unless the same variables as pg-actor.live.test.mjs name a
// disposable local stack (never a hosted project). Each test creates its own tables, policies and users and removes them.
//
// The owned app: POST /api/orders/<id>/refund updates the order with the caller's own JWT; its "quiet" build answers
// { ok: true } whatever PostgREST changed, its "surfacing" build answers 404 when nothing changed. POST
// /api/orders/<id>/upsert upserts the order as supabase-js .upsert() does (an insert with ON CONFLICT DO UPDATE). DELETE
// /api/orders/<id> deletes it (its items cascade). POST /api/agent/orders/<id>/close is the server-side tool: it updates
// with the service role key, and its "pass-through" build writes the caller's user id into made_by.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { pgConnect } from './pg-wire.mjs';
import { installActorCapture, removeActorCapture, verifySql, verifyRecord, ledgerSql, parseLedger, attributeChange, windowLedger } from './pg-actor.mjs';
import { supabaseResolver, serviceRoleNotes, rlsZeroRow, SERVICE_ACTOR_PREFIX } from './supabase-rules.mjs';
import { makeEffect } from './events.mjs';
import { evaluateHttpCheck } from '../../src/contracts.mjs';

const dsn = text => /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(text ?? '');
const appDb = dsn(process.env.SCOPEHAVEN_PG_ACTOR_LIVE), su = dsn(process.env.SCOPEHAVEN_PG_ACTOR_SUPERUSER);
const api = /^http:\/\/127\.0\.0\.1:\d+$/.test(process.env.SCOPEHAVEN_SUPABASE_LIVE ?? '') ? process.env.SCOPEHAVEN_SUPABASE_LIVE : null;
const anonKey = process.env.SCOPEHAVEN_SUPABASE_ANON_KEY, serviceKey = process.env.SCOPEHAVEN_SUPABASE_SERVICE_KEY;
const skip = appDb && su && api && anonKey && serviceKey ? false : 'set SCOPEHAVEN_PG_ACTOR_LIVE, SCOPEHAVEN_PG_ACTOR_SUPERUSER, SCOPEHAVEN_SUPABASE_LIVE, SCOPEHAVEN_SUPABASE_ANON_KEY and SCOPEHAVEN_SUPABASE_SERVICE_KEY to a local supabase start stack to run';
const connect = m => pgConnect({ host: '127.0.0.1', port: Number(m[3]), database: m[4], user: m[1], password: m[2] });

const call = async (path, { method = 'GET', token = anonKey, key = anonKey, body, prefer } = {}) => {
  const res = await fetch(`${api}${path}`, { method, headers: { apikey: key, authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(prefer ? { prefer } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
};
async function user(t, email) {
  const password = randomBytes(18).toString('base64url');
  const made = await call('/auth/v1/admin/users', { method: 'POST', token: serviceKey, key: serviceKey, body: { email, password, email_confirm: true } });
  assert.equal(made.status, 200, `create ${email}`);
  t.after(() => call(`/auth/v1/admin/users/${made.json.id}`, { method: 'DELETE', token: serviceKey, key: serviceKey }));
  const signed = await call('/auth/v1/token?grant_type=password', { method: 'POST', body: { email, password } });
  assert.equal(signed.status, 200, `sign in ${email}`);
  return { id: made.json.id, token: signed.json.access_token };
}
// The owned app over the stack. build: { refund: 'quiet' | 'surfacing', tool: 'plain' | 'pass-through' }.
async function app(t, f, build) {
  const server = createServer((req, res) => {
    let body = ''; req.on('data', d => { body += d; }); req.on('end', async () => {
      const json = (status, value) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
      const token = (req.headers.authorization ?? '').replace(/^Bearer /, ''), m = /^\/api\/(agent\/)?orders\/(ORD-\d)(\/[a-z]+)?$/.exec(req.url);
      if (!m) return json(404, { ok: false });
      const [, agent, id, action] = m, rest = `/rest/v1/${f.table}`;
      if (!agent && req.method === 'POST' && action === '/refund') {
        const r = await call(`${rest}?id=eq.${id}`, { method: 'PATCH', token, body: { status: 'refunded' }, prefer: 'return=representation' });
        return build.refund === 'surfacing' && Array.isArray(r.json) && !r.json.length ? json(404, { ok: false }) : json(200, { ok: true });
      }
      if (!agent && req.method === 'POST' && action === '/upsert') {
        const me = await call('/auth/v1/user', { token });
        const r = await call(`${rest}?on_conflict=id`, { method: 'POST', token, body: { id, owner: me.json.id, status: 'new' }, prefer: 'resolution=merge-duplicates,return=representation' });
        return json(r.status < 300 ? 200 : r.status, { ok: r.status < 300 });
      }
      if (!agent && req.method === 'DELETE' && !action) { const r = await call(`${rest}?id=eq.${id}`, { method: 'DELETE', token, prefer: 'return=representation' }); return json(200, { ok: true, deleted: r.json?.length ?? 0 }); }
      if (agent && req.method === 'POST' && action === '/close') {
        const me = await call('/auth/v1/user', { token });
        if (me.status !== 200) return json(401, { ok: false });
        await call(`${rest}?id=eq.${id}`, { method: 'PATCH', token: serviceKey, key: serviceKey, body: { status: 'closed', ...(build.tool === 'pass-through' ? { made_by: me.json.id } : {}) }, prefer: 'return=representation' });
        return json(200, { ok: true });
      }
      json(404, { ok: false });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return (path, token, method = 'POST') => fetch(`http://127.0.0.1:${server.address().port}${path}`, { method, headers: { authorization: `Bearer ${token}` } }).then(async r => ({ status: r.status, json: await r.json() }));
}
async function fixture(t) {
  const owner = await connect(appDb), admin = await connect(su), x = randomBytes(4).toString('hex'), table = `sh_rules_orders_${x}`, items = `sh_rules_items_${x}`;
  // Cleanup first, so a failure anywhere below (a timed-out sign-up, a refused installation) still closes the sessions and
  // drops what was made, the run's synthetic users included: matched on the run's suffix, so a sign-up that answered 504
  // but still made the user is removed too.
  let block = null;
  t.after(async () => {
    try { if (block) await removeActorCapture(admin, block).catch(() => {}); await owner.query(`DROP TABLE IF EXISTS public.${items}; DROP TABLE IF EXISTS public.${table}`); await owner.query(`NOTIFY pgrst, 'reload schema'`); await admin.query(`DELETE FROM auth.users WHERE email LIKE '%-${x}@%.test'`); }
    finally { owner.close(); admin.close(); }
  });
  const ana = await user(t, `ana-${x}@acme.test`), gil = await user(t, `gil-${x}@globex.test`);
  await owner.query(`CREATE TABLE public.${table} (id text PRIMARY KEY, owner uuid NOT NULL, status text NOT NULL, made_by text);
    CREATE TABLE public.${items} (id text PRIMARY KEY, order_id text NOT NULL REFERENCES public.${table} (id) ON DELETE CASCADE, made_by text);
    ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY;
    CREATE POLICY own_select ON public.${table} FOR SELECT TO authenticated USING (owner = auth.uid());
    CREATE POLICY own_insert ON public.${table} FOR INSERT TO authenticated WITH CHECK (owner = auth.uid());
    CREATE POLICY own_update ON public.${table} FOR UPDATE TO authenticated USING (owner = auth.uid());
    CREATE POLICY own_delete ON public.${table} FOR DELETE TO authenticated USING (owner = auth.uid());
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.${table}, public.${items} TO authenticated, service_role;
    INSERT INTO public.${table} VALUES ('ORD-1', '${ana.id}', 'open', NULL), ('ORD-2', '${gil.id}', 'open', NULL)`);
  block = { testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', schema: `sh_rules_${x}`, tables: [{ table, key: 'id', actorColumn: 'made_by' }, { table: items, key: 'id', actorColumn: 'made_by' }],
    actor: { from: 'jwt-claims' }, principals: { [ana.id]: 'ana', [gil.id]: 'gil' } };
  const installed = await installActorCapture(admin, block);
  await owner.query(`NOTIFY pgrst, 'reload schema'`);
  for (let i = 0; i < 50 && (await call(`/rest/v1/${table}?select=id`, { token: ana.token })).status !== 200; i++) await new Promise(r => setTimeout(r, 100));
  const ledger = async () => parseLedger((await admin.query(ledgerSql(block)))[0].rows);
  const capture = async () => verifyRecord(await admin.query(verifySql(block)), block, installed.definitionSha256).status;
  // One check's window: the ledger's rows the read after the request holds that the read before it did not.
  const windowOf = async send => { const start = await ledger(), response = await send(), end = await ledger(); return { response, entries: windowLedger(start, end) }; };
  const xmin = async id => (await owner.query(`SELECT xmin::text FROM public.${table} WHERE id = '${id}'`))[0].rows[0][0];
  return { owner, table, items, block, ana, gil, windowOf, capture, ledger, xmin, actors: { ana: { principalId: 'ana' }, gil: { principalId: 'gil' } } };
}
const control = (id, path = '/api/orders/ORD-1/refund') => ({ id, title: id, category: 'Refunds', severity: 'control', actorId: 'ana', method: 'POST', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/ok', expected: true }] });
const rowOf = (check, response) => evaluateHttpCheck(check, { status: response.status, complete: true, jsonParsed: true, json: response.json });

test('(b) a missing update policy: the quiet build FAILs its declared allowed-use twin; the surfacing build, the fixed policy, an upsert and a cascade do not', { skip }, async t => {
  const f = await fixture(t), quiet = await app(t, f, { refund: 'quiet' }), surfacing = await app(t, f, { refund: 'surfacing' });
  const decl = { tool: 'desk-agent', allowedWrites: { 'ANA-REFUND-OWN': { table: `public.${f.table}`, op: 'UPDATE' }, 'ANA-UPSERT-OWN': { table: `public.${f.table}`, op: 'UPDATE' } } };
  const read = async (send, check = control('ANA-REFUND-OWN')) => { const { response, entries } = await f.windowOf(send); return rlsZeroRow({ check, row: rowOf(check, response), entries, block: f.block, capture: await f.capture(), actors: f.actors, decl }); };
  const fixed = await read(() => quiet('/api/orders/ORD-1/refund', f.ana.token));
  assert.deepEqual([fixed.status, fixed.verdict], ['informational', 'no-zero-row-observed']);
  // An upsert that inserts: PostgREST's ON CONFLICT DO UPDATE writes a zero-row UPDATE beside the insert. Not a refusal.
  const upsert = await read(() => quiet('/api/orders/ORD-3/upsert', f.ana.token), control('ANA-UPSERT-OWN', '/api/orders/ORD-3/upsert'));
  assert.deepEqual([upsert.status, upsert.verdict], ['informational', 'no-zero-row-observed']);
  // A cascade into the items table the control does not declare: a zero-row DELETE there, informational.
  const cascade = await read(() => quiet('/api/orders/ORD-3', f.ana.token, 'DELETE'), control('ANA-REFUND-OWN', '/api/orders/ORD-3'));
  assert.equal(cascade.status, 'informational');
  // The defect: the update policy is gone, so row-level security filters the owner's own update to nothing.
  await f.owner.query(`DROP POLICY own_update ON public.${f.table}`);
  const failed = await read(() => quiet('/api/orders/ORD-1/refund', f.ana.token));
  assert.deepEqual([failed.status, failed.reason, failed.findings.map(z => [z.op, z.actor])], ['fail', 'rls-zero-row', [['UPDATE', 'ana']]]);
  const surfaced = await read(() => surfacing('/api/orders/ORD-1/refund', f.ana.token));
  assert.deepEqual([surfaced.status, surfaced.reason], ['informational', 'response-not-decided']);
  // The policy back: a refund of another tenant's order is the refusal working, never a FAIL.
  await f.owner.query(`CREATE POLICY own_update ON public.${f.table} FOR UPDATE TO authenticated USING (owner = auth.uid())`);
  const boundary = { ...control('ANA-NO-GLOBEX-REFUND', '/api/orders/ORD-2/refund'), severity: 'high' };
  const refused = await read(() => quiet('/api/orders/ORD-2/refund', f.ana.token), boundary);
  assert.deepEqual([refused.status, refused.reason], ['informational', 'rls-zero-row']);
  assert.match(refused.basis, /boundary check/);
});

test('(a) the tool\'s service-role write is never the end user\'s; the declared pass-through names the user', { skip }, async t => {
  const f = await fixture(t), plain = await app(t, f, { tool: 'plain' }), passing = await app(t, f, { tool: 'pass-through' });
  const decl = { tool: 'desk-agent' }, resolve = supabaseResolver(decl), table = `public.${f.table}`;
  const { entries } = await f.windowOf(() => plain('/api/agent/orders/ORD-2/close', f.ana.token));
  assert.deepEqual(entries.map(e => [e.op, e.key, e.claimsRole, e.claimsSub]), [['UPDATE', 'ORD-2', 'service_role', null]]);
  const x = await f.xmin('ORD-2'), change = { xid: x, table, key: 'ORD-2', op: 'UPDATE' };
  const toolWrite = attributeChange(change, await f.ledger(), f.block, { capture: 'intact', resolve });
  assert.deepEqual([toolWrite.actor, toolWrite.reason], [`${SERVICE_ACTOR_PREFIX}desk-agent`, 'service-role-write']);
  // The event as an observer would carry it after the join, and the note on a clause pinned to ana that reads missing.
  const event = makeEffect({ source: 'sql-snapshot', observer: { kind: 'postgres-wal-decode', instanceId: 'wal-1' }, seq: 1, actor: toolWrite.actor, operation: 'update', name: f.table, resource: `${f.table}/ORD-2`, outcome: 'committed', content: x });
  const window = { source: 'sql-snapshot', observer: { kind: 'postgres-wal-decode', instanceId: 'wal-1' }, instanceId: 'wal-1', coverage: 'complete', reason: null, scope: { operations: ['insert', 'update', 'delete'], names: [f.table], actorAttribution: 'principal', evidence: 'authoritative' }, events: [event] };
  const check = { id: 'ANA-NO-GLOBEX-CLOSE', effects: [{ kind: 'effect.none', select: { source: 'sql-snapshot', operation: 'update', name: f.table, resource: `${f.table}/ORD-2`, actor: 'ana' } }] };
  assert.deepEqual(serviceRoleNotes(check, [window], { principals: ['ana', 'gil'] }).map(n => n.reason), ['service-role-write']);
  // With the user passed through in made_by (written by that statement), the same tool write is ana's.
  await f.windowOf(() => passing('/api/agent/orders/ORD-2/close', f.ana.token));
  const passed = attributeChange({ xid: await f.xmin('ORD-2'), table, key: 'ORD-2', op: 'UPDATE' }, await f.ledger(), f.block, { capture: 'intact', resolve: supabaseResolver({ tool: 'desk-agent', passThrough: { from: 'column' } }) });
  assert.deepEqual([passed.actor, passed.via], ['ana', 'service-role-pass-through:column']);
  // A later tool write that leaves made_by alone passes no one through: the capture recorded no app actor for it.
  await f.windowOf(() => plain('/api/agent/orders/ORD-2/close', f.ana.token));
  const later = attributeChange({ xid: await f.xmin('ORD-2'), table, key: 'ORD-2', op: 'UPDATE' }, await f.ledger(), f.block, { capture: 'intact', resolve: supabaseResolver({ tool: 'desk-agent', passThrough: { from: 'column' } }) });
  assert.equal(later.actor, `${SERVICE_ACTOR_PREFIX}desk-agent`);
  // A direct connection as postgres that sets ana's claims (bypassing row-level security) is the tool's, never ana's.
  await f.owner.query(`BEGIN; SELECT set_config('request.jwt.claims', '{"sub":"${f.ana.id}","role":"authenticated"}', true); UPDATE ${table} SET status = 'direct' WHERE id = 'ORD-1'; COMMIT`);
  assert.equal(attributeChange({ xid: await f.xmin('ORD-1'), table, key: 'ORD-1', op: 'UPDATE' }, await f.ledger(), f.block, { capture: 'intact', resolve }).actor, `${SERVICE_ACTOR_PREFIX}desk-agent`);
});
