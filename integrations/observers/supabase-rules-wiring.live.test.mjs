// The Supabase identity rules wired into a run, end to end on a local Supabase stack: a refund app over the stack's
// PostgREST, assessed by runHttpAssessment with a pg-snapshot observer whose actor capture the stack's superuser installed, and a
// target that declares supabaseRules. The defective twin's row-level security filters the allowed user's own refund to zero rows and
// the app reports success anyway: the allowed-use control fails, rls-zero-row. The fixed twin's refund changes the row, and a twin
// that surfaces the zero rows answers no success, so neither fails on the rule. Synthetic users only, made and removed by each test.
// Skipped unless the pg-actor.live.test.mjs variables name a local supabase start stack (never a hosted project).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { pgConnect } from './pg-wire.mjs';
import { installActorCapture, removeActorCapture } from './pg-actor.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';

const live = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(process.env.SCOPEHAVEN_PG_ACTOR_LIVE ?? '');
const su = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(process.env.SCOPEHAVEN_PG_ACTOR_SUPERUSER ?? '');
const api = /^http:\/\/127\.0\.0\.1:\d+$/.test(process.env.SCOPEHAVEN_SUPABASE_LIVE ?? '') ? process.env.SCOPEHAVEN_SUPABASE_LIVE : null;
const anonKey = process.env.SCOPEHAVEN_SUPABASE_ANON_KEY, serviceKey = process.env.SCOPEHAVEN_SUPABASE_SERVICE_KEY;
const skip = live && su && api && anonKey && serviceKey ? false : 'set SCOPEHAVEN_PG_ACTOR_LIVE, SCOPEHAVEN_PG_ACTOR_SUPERUSER, SCOPEHAVEN_SUPABASE_LIVE, SCOPEHAVEN_SUPABASE_ANON_KEY and SCOPEHAVEN_SUPABASE_SERVICE_KEY to a local supabase start stack';
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
// The refund app: GET /me names the signed-in user; PATCH /refund/<id> updates the order through PostgREST with the user's own token.
// surfaces: whether it reports a refund that changed no row as a failure (the fixed behaviour) or as a success (the defect).
async function refundApp(t, table, names, { surfaces }) {
  const server = createServer((req, res) => { req.resume(); req.on('end', async () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
    if (!token) return reply(401, {});
    const me = await call('/auth/v1/user', { token });
    if (me.status !== 200 || !names[me.json?.id]) return reply(401, {});
    if (req.method === 'GET' && req.url === '/me') return reply(200, { user: names[me.json.id] });
    const id = /^\/refund\/([A-Z0-9-]+)$/.exec(req.url)?.[1];
    if (req.method === 'PATCH' && id) {
      const updated = await call(`/rest/v1/${table}?id=eq.${id}`, { method: 'PATCH', token, body: { status: 'refunded' }, prefer: 'return=representation' });
      if (surfaces && Array.isArray(updated.json) && updated.json.length === 0) return reply(404, { ok: false });
      return reply(200, { ok: true });
    }
    reply(404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
// One order table per test: ana owns ORD-1. policy: the UPDATE policy's USING clause (the defect is a policy too strict for the
// allowed user's own refund). The capture is installed by the stack's superuser with the snapshot reader as its reader.
async function fixture(t, policy) {
  const admin = await connect(), superuser = await connect(su[1], su[2]), x = randomBytes(4).toString('hex'), table = `sh_rls_orders_${x}`, snapRole = `sh_rls_snap_${x}`;
  let block = null;
  t.after(async () => {
    try { if (block) await removeActorCapture(superuser, block).catch(() => {}); await admin.query(`DROP TABLE IF EXISTS public.${table}`); await admin.query(`NOTIFY pgrst, 'reload schema'`); await admin.query(`DROP ROLE IF EXISTS ${snapRole}`); }
    finally { admin.close(); superuser.close(); }
  });
  const snapPass = randomBytes(12).toString('base64url');
  const ana = await user(t, `ana-${x}@acme.test`);
  await admin.query(`CREATE TABLE public.${table} (id text PRIMARY KEY, owner uuid NOT NULL, status text NOT NULL);
    ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY;
    CREATE POLICY own_select ON public.${table} FOR SELECT TO authenticated USING (owner = auth.uid());
    CREATE POLICY own_update ON public.${table} FOR UPDATE TO authenticated USING (${policy});
    GRANT SELECT, UPDATE ON public.${table} TO authenticated, service_role;
    INSERT INTO public.${table} VALUES ('ORD-1', '${ana.id}', 'open')`);
  await admin.query(`CREATE ROLE ${snapRole} LOGIN BYPASSRLS PASSWORD '${snapPass}'; GRANT SELECT ON public.${table} TO ${snapRole}`);
  block = { testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', schema: `sh_rls_${x}`, tables: [{ table, key: 'id' }], actor: { from: 'jwt-claims' }, principals: { [ana.id]: 'ana' } };
  const installed = await installActorCapture(superuser, block, { readers: [snapRole] });
  await admin.query(`NOTIFY pgrst, 'reload schema'`);
  for (let i = 0; i < 50 && (await call(`/rest/v1/${table}?select=id`, { token: ana.token })).status !== 200; i++) await new Promise(r => setTimeout(r, 100));
  return { table, ana, block, installed, env: { SCOPEHAVEN_TARGET_ANA: ana.token, SCOPEHAVEN_TARGET_RLS_SNAP: `${snapRole}:${snapPass}` } };
}
const profile = (f, origin) => ({ id: 'refunds', name: 'Refunds', applicationId: 'refunds-app', origin, buildLabel: 'b1', contextId: 'synthetic-refunds',
  actors: { ana: { principalId: 'ana', credentialEnv: 'SCOPEHAVEN_TARGET_ANA', identityValue: 'ana' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_RLS_SNAP', tables: [{ table: f.table, key: 'id' }], settleMs: 250,
    actorCapture: { block: f.block, installedSha256: f.installed.definitionSha256 } }],
  supabaseRules: { tool: 'refund-agent', allowedWrites: { REFUND: { table: `public.${f.table}`, op: 'UPDATE' } } },
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ana', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ana' }] },
    { id: 'REFUND', title: 'Ana refunds her own order', category: 'allowed-use', severity: 'control', actorId: 'ana', method: 'PATCH', path: '/refund/ORD-1', evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/ok', expected: true }],
      effects: [{ kind: 'effect.exists', select: { source: 'sql-snapshot', name: f.table, operation: 'update', actor: 'ana' } }] },
  ] });
async function assess(t, policy, { surfaces = false } = {}) {
  const f = await fixture(t, policy), origin = await refundApp(t, f.table, { [f.ana.id]: 'ana' }, { surfaces }), p = profile(f, origin);
  const run = await runHttpAssessment(p, { env: f.env });
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: f.env }).exportSuite(p.id) });
  const refund = run.results.find(r => r.id === 'REFUND');
  return { run, refund, data: refund.trace[1].data };
}

test('the defect: row-level security filters the allowed user\'s own refund to zero rows and the app reports success, so the control fails (rls-zero-row)', { skip }, async t => {
  const { refund, data } = await assess(t, `owner = auth.uid() AND status = 'pending'`);
  assert.equal(refund.status, 'fail');
  assert.deepEqual([data.effects[0].verdict, data.effects[0].zeroRow?.finding, data.effects[0].zeroRow?.priorVerdict], ['fail', 'rls-zero-row', 'missing']);
  assert.equal(data.zeroRow.facts.capture, 'intact');
  assert.deepEqual(data.zeroRow.facts.statements.map(s => [s.op, s.actor, s.serviceRole]), [['UPDATE', 'ana', false]]);
  assert.deepEqual(data.zeroRow.facts.writes, []);
});

test('the fixed twin: the refund changes the row, so the control passes on the window; a twin that surfaces the zero rows is not judged a success', { skip }, async t => {
  const fixed = await assess(t, 'owner = auth.uid()');
  assert.deepEqual(fixed.data.windows[0].events.map(e => [e.operation, e.actor]), [['update', 'ana']]);
  assert.deepEqual([fixed.refund.status, fixed.data.effects[0].verdict, fixed.data.effects[0].zeroRow], ['pass', 'pass', undefined]);
  const surfaced = await assess(t, `owner = auth.uid() AND status = 'pending'`, { surfaces: true });
  assert.deepEqual([surfaced.refund.status, surfaced.data.effects[0].zeroRow], ['fail', undefined], 'it fails on its own status assertion, never on the rule');
  assert.equal(surfaced.refund.assertions.find(a => a.name === 'HTTP status matches contract').status, 'fail');
});
