// pg-wal as a profile observer, end to end on a local Supabase stack: a refund app over the stack's PostgREST, assessed by
// runHttpAssessment with a pg-wal observer (its own REPLICATION role) on the orders table. The check is database-only: reading an order
// refunds nothing. The fixed twin's read writes nothing, so the prohibition passes on the WAL (custody observer-held), beside the
// allowed-use twin whose refund the observer is shown to see; the defective twin's read refunds the order too, and the prohibition fails.
// Synthetic users only, made and removed by each test. Skipped unless the pg-actor.live.test.mjs variables name a local supabase start
// stack (never a hosted project; its Postgres has wal_level = logical).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { pgConnect } from './pg-wire.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';

const live = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(process.env.SCOPEHAVEN_PG_ACTOR_LIVE ?? '');
const api = /^http:\/\/127\.0\.0\.1:\d+$/.test(process.env.SCOPEHAVEN_SUPABASE_LIVE ?? '') ? process.env.SCOPEHAVEN_SUPABASE_LIVE : null;
const anonKey = process.env.SCOPEHAVEN_SUPABASE_ANON_KEY, serviceKey = process.env.SCOPEHAVEN_SUPABASE_SERVICE_KEY;
const skip = live && api && anonKey && serviceKey ? false : 'set SCOPEHAVEN_PG_ACTOR_LIVE, SCOPEHAVEN_SUPABASE_LIVE, SCOPEHAVEN_SUPABASE_ANON_KEY and SCOPEHAVEN_SUPABASE_SERVICE_KEY to a local supabase start stack';
const [, adminUser, adminPassword, portText, database] = live ?? [];
const port = Number(portText);
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
async function fixture(t, { defective }) {
  const admin = await pgConnect({ host: '127.0.0.1', port, database, user: adminUser, password: adminPassword }), x = randomBytes(4).toString('hex'), table = `sh_wal_orders_${x}`, walRole = `sh_wal_reader_${x}`;
  t.after(async () => { try { await admin.query(`DROP TABLE IF EXISTS public.${table}`); await admin.query(`NOTIFY pgrst, 'reload schema'`); await admin.query(`DROP ROLE IF EXISTS ${walRole}`); } finally { admin.close(); } });
  const walPass = randomBytes(12).toString('base64url'), ana = await user(t, `ana-${x}@acme.test`);
  await admin.query(`CREATE TABLE public.${table} (id text PRIMARY KEY, owner uuid NOT NULL, status text NOT NULL);
    ALTER TABLE public.${table} ENABLE ROW LEVEL SECURITY;
    CREATE POLICY own_select ON public.${table} FOR SELECT TO authenticated USING (owner = auth.uid());
    CREATE POLICY own_update ON public.${table} FOR UPDATE TO authenticated USING (owner = auth.uid());
    GRANT SELECT, UPDATE ON public.${table} TO authenticated, service_role;
    INSERT INTO public.${table} VALUES ('ORD-1', '${ana.id}', 'open')`);
  await admin.query(`CREATE ROLE ${walRole} LOGIN REPLICATION PASSWORD '${walPass}'; NOTIFY pgrst, 'reload schema'`);
  for (let i = 0; i < 50 && (await call(`/rest/v1/${table}?select=id`, { token: ana.token })).status !== 200; i++) await new Promise(r => setTimeout(r, 100));
  // The app: GET /me names ana; PATCH /refund/ORD-1 refunds her order with her token; GET /orders/ORD-1 reads it, and the defective twin
  // also stamps the order through the service role on every read (a database write the response never shows).
  const server = createServer((req, res) => { req.resume(); req.on('end', async () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
    if (token !== ana.token) return reply(401, {});
    if (req.url === '/me') return reply(200, { user: 'ana' });
    if (req.method === 'PATCH' && req.url === '/refund/ORD-1') { const r = await call(`/rest/v1/${table}?id=eq.ORD-1`, { method: 'PATCH', token, body: { status: 'refunded' }, prefer: 'return=representation' }); return reply(200, { ok: r.json?.length === 1 }); }
    if (req.url === '/orders/ORD-1') {
      if (defective) await call(`/rest/v1/${table}?id=eq.ORD-1`, { method: 'PATCH', token: serviceKey, key: serviceKey, body: { status: 'reviewed' } });
      const r = await call(`/rest/v1/${table}?id=eq.ORD-1&select=id,status`, { token });
      return reply(200, r.json?.[0] ?? {});
    }
    reply(404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`, select = { source: 'sql-wal', name: table, operation: 'update', resource: `${table}/ORD-1` };
  // pg_net's unlogged tables in schema net are not observed here, so the profile ignores that schema (as pg-actor-join.live does).
  const profile = { id: 'refunds', name: 'Refunds', applicationId: 'refunds-app', origin, buildLabel: 'b1', contextId: 'synthetic-refunds',
    actors: { ana: { principalId: 'ana', credentialEnv: 'SCOPEHAVEN_TARGET_ANA', identityValue: 'ana' } }, requiredControlIds: ['WHOAMI'],
    observers: [{ id: 'wal', type: 'pg-wal', host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_WAL_READER', settleMs: 500, platform: 'supabase', ignore: ['net'],
      tables: [{ table, key: 'id', values: ['status'] }] }],
    checks: [
      { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ana', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ana' }] },
      { id: 'REFUND', title: 'Ana refunds her own order', category: 'allowed-use', severity: 'control', actorId: 'ana', method: 'PATCH', path: '/refund/ORD-1', evidenceRequirement: 'backend',
        assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/ok', expected: true }], effects: [{ kind: 'effect.exists', select }] },
      { id: 'NO-WRITE-ON-READ', title: 'Reading an order changes nothing (database only)', category: 'object-access', severity: 'high', actorId: 'ana', method: 'GET', path: '/orders/ORD-1', evidenceRequirement: 'backend',
        assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select }] },
    ] };
  const env = { SCOPEHAVEN_TARGET_ANA: ana.token, SCOPEHAVEN_TARGET_WAL_READER: `${walRole}:${walPass}` };
  const run = await runHttpAssessment(profile, { env });
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [profile], env }).exportSuite(profile.id) });
  return { run, row: id => run.results.find(r => r.id === id) };
}

test('the fixed twin: reading the order writes nothing, so the database-only prohibition passes on the WAL observer (observer-held)', { skip }, async t => {
  const { row } = await fixture(t, { defective: false });
  assert.equal(row('REFUND').status, 'pass', 'the observer is shown to see the allowed refund');
  const r = row('NO-WRITE-ON-READ'), w = r.trace[1].data.windows[0];
  assert.equal(w.coverage, 'complete', w.reason);
  assert.deepEqual([r.status, r.backendEvidence, r.trace[1].data.effects[0].verdict, r.trace[1].data.effects[0].custody], ['pass', 'observed', 'pass', 'observer-held']);
});

test('the defective twin: the read also writes the order through the service role, and the prohibition fails on the decoded write', { skip }, async t => {
  const { row } = await fixture(t, { defective: true });
  const r = row('NO-WRITE-ON-READ');
  assert.deepEqual([r.status, r.trace[1].data.effects[0].verdict], ['fail', 'fail']);
  assert.ok(r.trace[1].data.windows[0].events.some(e => e.source === 'sql-wal' && e.operation === 'update' && e.resource.endsWith('/ORD-1')));
});
