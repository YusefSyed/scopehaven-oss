// The catalog fingerprint (./catalog.mjs) against a real PostgreSQL (13+). Skipped unless SCOPEHAVEN_PG_LIVE names a
// disposable test database as "user:password@127.0.0.1:port/database" for a role that may create databases, schemas,
// tables, functions, roles and extensions. Each test builds its own database and drops it after. Covers what a scripted
// server cannot: the definitions the server prints, a second database built by the same statements, data operations that
// rewrite a relation (TRUNCATE, VACUUM FULL, REFRESH) and leave the catalog unchanged, and DDL made and reverted between two
// reads (a trigger disabled and enabled again, row-level security switched off and on, a function replaced), and then
// pg-snapshot and pg-wal reading it at their marks as their own least-privileged roles.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { pgConnect } from './pg-wire.mjs';
import { pgCatalogSql, pgCatalogOf, catalogReasons, catalogExclusions, CATALOG_KINDS, SCHEMA_DRIFT } from './catalog.mjs';
import { resolveIgnoreList } from './ignore-lists/ignore-list.mjs';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { createPgWalObserver } from './pg-wal.mjs';
import { collectWindow } from './events.mjs';

const live = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(process.env.SCOPEHAVEN_PG_LIVE ?? '');
const skip = live ? false : 'set SCOPEHAVEN_PG_LIVE=user:password@127.0.0.1:port/db (a disposable test database) to run';
const PINNED = "SET search_path = pg_catalog; SET quote_all_identifiers = off; SET DateStyle = 'ISO, MDY'; SET TimeZone = 'UTC'; SET IntervalStyle = 'postgres'; SET extra_float_digits = 1; SET bytea_output = 'hex'; SET standard_conforming_strings = on";
const SCHEMA = `CREATE TABLE public.orders (id text PRIMARY KEY, tenant text NOT NULL, total numeric(10,2) DEFAULT 0, status text CHECK (status IN ('open', 'paid')));
  ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;
  CREATE POLICY p_tenant ON public.orders USING (tenant = current_setting('app.tenant', true));
  CREATE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.total := NEW.total; RETURN NEW; END$$;
  CREATE TRIGGER t_touch BEFORE UPDATE ON public.orders FOR EACH ROW EXECUTE FUNCTION public.touch();
  CREATE VIEW public.v_orders AS SELECT id, total FROM public.orders;
  CREATE MATERIALIZED VIEW public.m_orders AS SELECT tenant, count(*) AS n FROM public.orders GROUP BY tenant;
  CREATE TYPE public.status AS ENUM ('open', 'paid');
  CREATE DOMAIN public.cents AS bigint CHECK (VALUE >= 0);
  CREATE AGGREGATE public.mysum(int) (sfunc = int4pl, stype = int, initcond = '0');
  CREATE TABLE public.events (id bigint GENERATED ALWAYS AS IDENTITY, at date NOT NULL, body text) PARTITION BY RANGE (at);
  CREATE TABLE public.events_2026_10 PARTITION OF public.events FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
  CREATE FUNCTION public.noop() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$;
  CREATE TRIGGER t_events BEFORE INSERT ON public.events FOR EACH ROW EXECUTE FUNCTION public.noop();
  GRANT SELECT ON public.orders TO PUBLIC;
  CREATE UNIQUE INDEX m_orders_tenant ON public.m_orders (tenant);
  CREATE EXTENSION pgcrypto SCHEMA public; REVOKE EXECUTE ON FUNCTION public.digest(text, text) FROM PUBLIC;
  CREATE TABLE public.parts (id int, at date, PRIMARY KEY (id, at)) PARTITION BY RANGE (at);
  CREATE TABLE public.parts_1 PARTITION OF public.parts FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
  CREATE TABLE public.refs (pid int, pat date, FOREIGN KEY (pid, pat) REFERENCES public.parts (id, at));
  CREATE TABLE public.base (id int); CREATE TABLE public.kid (extra int) INHERITS (public.base);
  CREATE EXTENSION pg_stat_statements SCHEMA public;
  CREATE TABLE public.ml (id int, at date, k int) PARTITION BY RANGE (at);
  CREATE TABLE public.ml_1 PARTITION OF public.ml FOR VALUES FROM ('2026-01-01') TO ('2026-02-01') PARTITION BY LIST (k);
  CREATE TABLE public.ml_1_a PARTITION OF public.ml_1 FOR VALUES IN (1); CREATE TABLE public.ml_1_b PARTITION OF public.ml_1 FOR VALUES IN (2);
  CREATE SCHEMA platform_own; CREATE TABLE platform_own.jobs (id int);`;

// A test database is dropped only after its sessions have ended and their temporary replication slots are gone (DROP
// DATABASE refuses, 55006, while a slot remains, even WITH (FORCE)).
async function dropDatabase(admin, name) {
  await admin.query(`SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = '${name}' AND pid <> pg_catalog.pg_backend_pid()`);
  for (let i = 0; i < 100; i++) {
    const [slots] = await admin.query(`SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_replication_slots WHERE database = '${name}'`);
    if (slots.rows[0][0] === '0') break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
}

// DDL only a superuser (or an extension objects' owner) can run: skipped, with a diagnostic, when the test role is neither
// (a Supabase image's postgres role, where a GRANT on the platform admin's extension functions grants nothing).
const SUPERUSER_ONLY = [/DISABLE TRIGGER ALL/, /FOREIGN DATA WRAPPER/, /public\.(digest|gen_salt)/, /pg_stat_statements/];
const superuserOnly = ddl => SUPERUSER_ONLY.some(p => p.test(ddl));
async function isSuperuser(db) { return (await db.query('SELECT rolsuper::text FROM pg_catalog.pg_roles WHERE rolname = current_user'))[0].rows[0][0] === 'true'; }

async function database(t) {
  const [, user, password, port, adminDb] = live;
  const connect = database => pgConnect({ host: '127.0.0.1', port: Number(port), database, user, password });
  const admin = await connect(adminDb), names = [];
  const make = async () => {
    const name = `sh_cat_${randomBytes(4).toString('hex')}`;
    await admin.query(`CREATE DATABASE ${name}`); names.push(name);
    const db = await connect(name), other = await connect(name);
    await db.query(SCHEMA);
    t.after(() => { db.close(); other.close(); });
    // A read as a mark makes it: the pinned settings, then the two statements.
    const read = async (excluded = {}) => {
      const sql = pgCatalogSql(excluded);
      await db.query(PINNED);
      const [kinds, versions] = await db.query(`${sql.catalog};\n${sql.versions}`, { maxRows: sql.rows });
      return pgCatalogOf(kinds, versions);
    };
    return { db, other, read };
  };
  t.after(async () => { try { for (const name of names) await dropDatabase(admin, name); } finally { admin.close(); } });
  return make;
}

test('live catalog: every kind is read; two databases built by the same statements read the same definition digest and a different instance', { skip }, async t => {
  const make = await database(t);
  const a = await make(), b = await make();
  // A policy's roles in another order read the same (they are sorted by name).
  const r1 = `sh_cat_ra_${randomBytes(3).toString('hex')}`, r2 = `sh_cat_rb_${randomBytes(3).toString('hex')}`;
  await a.db.query(`CREATE ROLE ${r1}; CREATE ROLE ${r2}`);
  t.after(async () => { const [, user, password, port, adminDb] = live; const admin = await pgConnect({ host: '127.0.0.1', port: Number(port), database: adminDb, user, password });
    try { await admin.query(`DROP ROLE IF EXISTS ${r1}; DROP ROLE IF EXISTS ${r2}`); } finally { admin.close(); } });
  await a.db.query(`CREATE POLICY p_roles ON public.orders TO ${r1}, ${r2} USING (true)`); await b.db.query(`CREATE POLICY p_roles ON public.orders TO ${r2}, ${r1} USING (true)`);
  const [x, y] = [await a.read(), await b.read()];
  assert.equal(x.ok, true); assert.equal(y.ok, true);
  assert.deepEqual(x.kinds.map(k => k.kind), CATALOG_KINDS.postgres);
  const count = Object.fromEntries(x.kinds.map(k => [k.kind, k.objects]));
  for (const kind of ['schema', 'relation', 'column', 'constraint', 'index', 'policy', 'trigger', 'rule', 'function', 'type', 'extension']) assert.ok(count[kind] > 0, kind);
  assert.equal(x.sha256, y.sha256, 'the same migrations read the same');
  // A column dropped and added again: its position among the live columns is the same, though its attnum is not (a
  // database restored from a dump numbers its columns afresh).
  await b.db.query("ALTER TABLE public.orders DROP COLUMN status; ALTER TABLE public.orders ADD COLUMN status text CHECK (status IN ('open', 'paid'))");
  assert.equal((await b.read()).sha256, x.sha256, 'the same columns in the same order');
  assert.notEqual(x.instance, y.instance, 'row versions and oids differ between the databases');
  // The partition is not a relation of its own, and the parent's identity column is read once.
  assert.equal((await a.read()).sha256, x.sha256, 'a second read with nothing changed');
});

test('live catalog: data operations change nothing, including the rewrites TRUNCATE, VACUUM FULL, CLUSTER and REFRESH', { skip }, async t => {
  const { db, read } = await (await database(t))();
  const before = await read();
  await db.query("INSERT INTO public.orders VALUES ('a', 't', 1, 'open'), ('b', 'u', 2, 'paid'); UPDATE public.orders SET total = 3 WHERE id = 'a'; INSERT INTO public.events (at, body) VALUES ('2026-10-05', 'x')");
  // One statement per query: VACUUM refuses to run in the implicit transaction of a multi-statement query.
  for (const op of ['ANALYZE public.orders', 'VACUUM public.orders', 'VACUUM FREEZE public.orders', 'TRUNCATE public.orders', 'VACUUM FULL public.orders', 'CLUSTER public.orders USING orders_pkey', 'REFRESH MATERIALIZED VIEW public.m_orders'])
    await db.query(op);
  await db.query('CREATE TEMPORARY TABLE scratch (x int) ; DROP TABLE scratch');
  const after = await read();
  assert.deepEqual(catalogReasons(before, before, after), []);
  assert.equal(after.sha256, before.sha256);
});

test('live catalog: a lasting change reads schema-drift against the baseline, at every later mark', { skip }, async t => {
  const make = await database(t);
  for (const ddl of ['ALTER TABLE public.orders ADD COLUMN note text', 'ALTER TABLE public.orders ALTER COLUMN total SET DEFAULT 5', 'DROP POLICY p_tenant ON public.orders',
    "CREATE POLICY p_open ON public.orders FOR SELECT USING (status = 'open')", 'ALTER POLICY p_tenant ON public.orders USING (true)', "ALTER POLICY p_tenant ON public.orders WITH CHECK (tenant = 'acme')", 'ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY', 'ALTER TABLE public.orders FORCE ROW LEVEL SECURITY',
    'GRANT INSERT ON public.orders TO PUBLIC', 'ALTER TABLE public.orders DISABLE TRIGGER t_touch', "CREATE OR REPLACE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL; END$$",
    'ALTER FUNCTION public.touch() SECURITY DEFINER', "ALTER TYPE public.status ADD VALUE 'void'", 'ALTER DOMAIN public.cents SET NOT NULL', 'CREATE INDEX ON public.orders (tenant)',
    'CREATE VIEW public.v2 AS SELECT 1 AS one', 'CREATE OR REPLACE VIEW public.v_orders AS SELECT id, total, tenant FROM public.orders',
    'CREATE RULE r_no_delete AS ON DELETE TO public.orders DO INSTEAD NOTHING', 'ALTER TABLE public.orders ADD CONSTRAINT c_total CHECK (total >= 0) NOT VALID',
    'ALTER TABLE public.orders RENAME COLUMN tenant TO org', 'CREATE SCHEMA app2', 'ALTER TABLE public.events DETACH PARTITION public.events_2026_10',
    // An extension member's grants, a partition's own trigger state, grants and row-level security, the
    // foreign keys' internal triggers, replica identity (also beside a TRUNCATE), inheritance, and further object kinds.
    'GRANT EXECUTE ON FUNCTION public.digest(text, text) TO PUBLIC', 'REVOKE EXECUTE ON FUNCTION public.gen_salt(text) FROM PUBLIC', 'CREATE EXTENSION "uuid-ossp" SCHEMA public',
    'ALTER TABLE public.events_2026_10 DISABLE TRIGGER t_events', 'ALTER TABLE public.refs DISABLE TRIGGER ALL', 'GRANT SELECT ON public.events_2026_10 TO PUBLIC',
    'ALTER TABLE public.events_2026_10 ENABLE ROW LEVEL SECURITY', 'ALTER TABLE public.orders REPLICA IDENTITY FULL', 'ALTER TABLE public.orders REPLICA IDENTITY FULL; TRUNCATE public.orders',
    'ALTER TABLE public.kid NO INHERIT public.base', 'CREATE FOREIGN DATA WRAPPER sh_w0; CREATE SERVER sh_s0 FOREIGN DATA WRAPPER sh_w0', 'CREATE PUBLICATION sh_pub0 FOR TABLE public.orders',
    'ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC', 'CREATE OPERATOR public.=== (LEFTARG = int, RIGHTARG = int, FUNCTION = int4eq)', 'CREATE CAST (public.status AS text) WITH INOUT',
    // An extension member's column grant, view option and SECURITY DEFINER; a partition's column grant; a
    // grant on a leaf two levels down.
    'GRANT SELECT (query) ON public.pg_stat_statements TO PUBLIC', 'ALTER VIEW public.pg_stat_statements SET (security_invoker = true)', 'ALTER FUNCTION public.digest(text, text) SECURITY DEFINER',
    'GRANT SELECT (body) ON public.events_2026_10 TO PUBLIC', 'GRANT SELECT ON public.ml_1_a TO PUBLIC']) {
    const { db, read } = await make();
    if (superuserOnly(ddl) && !(await isSuperuser(db))) { t.diagnostic(`skipped (not a superuser): ${ddl}`); continue; }
    const baseline = await read();
    await db.query(ddl).catch(error => { throw new Error(`${ddl}: ${error.sqlState}`); });
    const changed = await read(), later = await read();
    assert.deepEqual(catalogReasons(baseline, baseline, changed), [SCHEMA_DRIFT], ddl);
    assert.deepEqual(catalogReasons(baseline, changed, later), [SCHEMA_DRIFT], `${ddl} (a later window)`);
  }
});

test('live catalog: a change made and reverted between two marks reads schema-drift; a window after it does not', { skip }, async t => {
  const make = await database(t);
  for (const pair of [['ALTER TABLE public.orders DISABLE TRIGGER t_touch', 'ALTER TABLE public.orders ENABLE TRIGGER t_touch'],
    ['ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY', 'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY'],
    ['REVOKE SELECT ON public.orders FROM PUBLIC', 'GRANT SELECT ON public.orders TO PUBLIC'],
    ['DROP POLICY p_tenant ON public.orders', "CREATE POLICY p_tenant ON public.orders USING (tenant = current_setting('app.tenant', true))"],
    ["CREATE OR REPLACE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL; END$$", "CREATE OR REPLACE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.total := NEW.total; RETURN NEW; END$$"],
    ['ALTER TABLE public.orders ADD COLUMN x int', 'ALTER TABLE public.orders DROP COLUMN x'],
    ['ALTER TABLE public.events_2026_10 DISABLE TRIGGER t_events', 'ALTER TABLE public.events_2026_10 ENABLE TRIGGER t_events'],
    ['ALTER TABLE public.refs DISABLE TRIGGER ALL', 'ALTER TABLE public.refs ENABLE TRIGGER ALL'],
    ['GRANT EXECUTE ON FUNCTION public.digest(text, text) TO PUBLIC', 'REVOKE EXECUTE ON FUNCTION public.digest(text, text) FROM PUBLIC']]) {
    const { db, read } = await make();
    if (superuserOnly(pair[0]) && !(await isSuperuser(db))) { t.diagnostic(`skipped (not a superuser): ${pair[0]}`); continue; }
    const baseline = await read();
    await db.query(pair[0]); await db.query(pair[1]);
    const end = await read(), next = await read();
    assert.equal(end.sha256, baseline.sha256, `${pair[0]} then back: the definitions are the baseline's`);
    assert.deepEqual(catalogReasons(baseline, baseline, end), [SCHEMA_DRIFT], pair[0]);
    assert.deepEqual(catalogReasons(baseline, end, next), [], `${pair[0]}: the next window ran under the baseline schema`);
  }
});

test('live catalog: a new partition, another session\'s temporary table and the platform\'s own objects are not a change', { skip }, async t => {
  const { db, other, read } = await (await database(t))();
  const excluded = { schemas: ['platform_own'], tables: [] };
  const baseline = await read(excluded);
  await db.query("CREATE TABLE public.events_2026_11 PARTITION OF public.events FOR VALUES FROM ('2026-11-01') TO ('2026-12-01')");
  await other.query('CREATE TEMPORARY TABLE held (x int)');
  await db.query('ALTER TABLE platform_own.jobs ADD COLUMN y int; CREATE TABLE platform_own.more (id int)');
  // A new partition of a table a foreign key references (the key's clones on the referencing table are its own), and a
  // materialized view refreshed CONCURRENTLY (its catalog row moves without a new file).
  await db.query("CREATE TABLE public.parts_2 PARTITION OF public.parts FOR VALUES FROM ('2026-02-01') TO ('2026-03-01')");
  await db.query('REFRESH MATERIALIZED VIEW CONCURRENTLY public.m_orders');
  const end = await read(excluded);
  assert.deepEqual(catalogReasons(baseline, baseline, end), []);
  // Without the exclusion the platform's schema is in the fingerprint.
  const plain = await read();
  assert.notEqual(plain.sha256, end.sha256);
});

// The observers themselves, each as its own least-privileged role: pg-snapshot with SELECT on its table only, pg-wal with
// REPLICATION only. The catalog is readable by both.
async function observerDb(t) {
  const [, user, password, port] = live;
  const { db, read } = await (await database(t))();
  const [[name]] = (await db.query('SELECT pg_catalog.current_database()::text'))[0].rows;
  const suffix = randomBytes(4).toString('hex'), reader = `sh_cat_r_${suffix}`, wal = `sh_cat_w_${suffix}`, secret = randomBytes(12).toString('base64url');
  // pg-snapshot reads with row_security off, so its table has no policy (orders has one: a filtered role fails the mark).
  await db.query(`CREATE TABLE public.ledger (id text PRIMARY KEY, n int); INSERT INTO public.ledger VALUES ('l1', 1);
    CREATE ROLE ${reader} LOGIN PASSWORD '${secret}'; GRANT SELECT ON public.ledger TO ${reader}; CREATE ROLE ${wal} LOGIN REPLICATION PASSWORD '${secret}'`);
  t.after(async () => {
    const admin = await pgConnect({ host: '127.0.0.1', port: Number(port), database: live[4], user, password });
    try { await dropDatabase(admin, name); await admin.query(`DROP ROLE IF EXISTS ${reader}; DROP ROLE IF EXISTS ${wal}`); } finally { admin.close(); }
  });
  const env = { SCOPEHAVEN_TARGET_CAT_READER: `${reader}:${secret}`, SCOPEHAVEN_TARGET_CAT_WAL: `${wal}:${secret}` };
  const common = { env, host: '127.0.0.1', port: Number(port), database: name };
  return { db, read, common };
}

test('live pg-snapshot: a migration during the run reads schema-drift on its window and the next; a TRUNCATE elsewhere and a quiet window do not', { skip }, async t => {
  const { db, common } = await observerDb(t);
  const o = createPgSnapshotObserver({ ...common, credentialEnv: 'SCOPEHAVEN_TARGET_CAT_READER', tables: [{ table: 'ledger', key: 'id' }] });
  await o.start();
  const step = async fn => { const from = await o.mark(); await fn(); return collectWindow(o, from, await o.mark()); };
  const quiet = await step(async () => { await db.query('TRUNCATE platform_own.jobs'); });
  assert.ok(!String(quiet.reason).includes(SCHEMA_DRIFT) && quiet.coverage !== 'failed', JSON.stringify([quiet.coverage, quiet.reason]));
  const migrated = await step(async () => { await db.query("CREATE POLICY p_paid ON public.orders FOR SELECT USING (status = 'paid'); UPDATE public.ledger SET n = 2 WHERE id = 'l1'"); });
  assert.equal(migrated.coverage, 'partial'); assert.ok(migrated.reason.split(',').includes(SCHEMA_DRIFT), migrated.reason);
  assert.deepEqual(migrated.events.map(e => `${e.operation} ${e.resource}`), ['update ledger/l1']);
  const later = await step(async () => {});
  assert.ok(later.reason.split(',').includes(SCHEMA_DRIFT), 'against the baseline, not only the window');
  const record = o.catalog();
  assert.equal(record.changedDuringRun, true); assert.notEqual(record.final, record.sha256);
  assert.equal(record.kinds.policy.objects, 1, 'the baseline had one policy');
  await o.stop();
});

test('live pg-wal: the database catalog sees DDL its own declared-table catalog does not, and a function changed and restored inside a window', { skip }, async t => {
  const { db, common } = await observerDb(t);
  const o = createPgWalObserver({ ...common, credentialEnv: 'SCOPEHAVEN_TARGET_CAT_WAL', tables: [{ table: 'orders', key: 'id' }] });
  await o.start();
  t.after(() => o.stop());
  const step = async fn => { const from = await o.mark(); await fn(); return collectWindow(o, from, await o.mark()); };
  const quiet = await step(async () => { await db.query("INSERT INTO public.orders VALUES ('o2', 't', 1, 'open')"); });
  assert.deepEqual([quiet.coverage, quiet.reason], ['complete', null]);
  // A policy on another table: not a declared table's catalog, but the database's.
  const elsewhere = await step(async () => { await db.query('ALTER TABLE platform_own.jobs ENABLE ROW LEVEL SECURITY'); });
  assert.ok(elsewhere.reason.split(',').includes(SCHEMA_DRIFT), elsewhere.reason);
  const o2 = createPgWalObserver({ ...common, credentialEnv: 'SCOPEHAVEN_TARGET_CAT_WAL', tables: [{ table: 'orders', key: 'id' }], runLease: false });
  await o2.start(); t.after(() => o2.stop());
  const from = await o2.mark();
  await db.query("CREATE OR REPLACE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL; END$$");
  await db.query("CREATE OR REPLACE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.total := NEW.total; RETURN NEW; END$$");
  const restored = await collectWindow(o2, from, await o2.mark());
  assert.ok(restored.reason.split(',').includes(SCHEMA_DRIFT), 'the trigger function was replaced and restored inside the window');
  assert.equal(o2.catalog().sha256, o2.catalog().final, 'the definitions are the baseline\'s again');
});

test('live catalog: the server\'s own database (on a Supabase image, its platform schemas and extensions) reads the same twice, with and without the platform\'s exclusions, inside the mark budget', { skip }, async t => {
  const [, user, password, port, name] = live;
  const db = await pgConnect({ host: '127.0.0.1', port: Number(port), database: name, user, password });
  t.after(() => db.close());
  const supabase = catalogExclusions(resolveIgnoreList({ engine: 'postgres', platform: 'supabase' }));
  const read = async excluded => {
    const sql = pgCatalogSql(excluded), started = performance.now();
    await db.query(PINNED);
    const [kinds, versions] = await db.query(`${sql.catalog};\n${sql.versions}`, { maxRows: sql.rows });
    return { fp: pgCatalogOf(kinds, versions), ms: performance.now() - started };
  };
  for (const excluded of [{}, supabase]) {
    const a = await read(excluded), b = await read(excluded);
    assert.equal(a.fp.ok, true); assert.equal(a.fp.sha256, b.fp.sha256); assert.equal(a.fp.instance, b.fp.instance);
    assert.deepEqual(catalogReasons(a.fp, a.fp, b.fp), []);
    assert.ok(a.ms < 5000, `${Math.round(a.ms)} ms`);
    t.diagnostic(`${excluded.schemas ? 'supabase exclusions' : 'no exclusions'}: ${a.fp.kinds.map(k => `${k.kind} ${k.objects}`).join(', ')}; ${Math.round(a.ms)} ms`);
  }
});

test('live catalog: a lock on a relation a view or policy names delays the catalog read at most a second and reads catalog-unreadable; the marks and pg-wal\'s slot stay', { skip }, async t => {
  const { db, common } = await observerDb(t);
  const [, user, password, port] = live;
  await db.query('CREATE TABLE public.locked (id int); CREATE VIEW public.v_locked AS SELECT id FROM public.locked; CREATE POLICY p_sub ON public.orders USING (EXISTS (SELECT 1 FROM public.locked))');
  const snap = createPgSnapshotObserver({ ...common, credentialEnv: 'SCOPEHAVEN_TARGET_CAT_READER', tables: [{ table: 'ledger', key: 'id' }] });
  const wal = createPgWalObserver({ ...common, credentialEnv: 'SCOPEHAVEN_TARGET_CAT_WAL', tables: [{ table: 'orders', key: 'id' }] });
  await snap.start(); await wal.start();
  t.after(() => wal.stop());
  const holder = await pgConnect({ host: '127.0.0.1', port: Number(port), database: common.database, user, password });
  t.after(() => holder.close());
  const sf = await snap.mark(), wf = await wal.mark();
  await holder.query('BEGIN; LOCK TABLE public.locked IN ACCESS EXCLUSIVE MODE');
  const started = performance.now();
  const st = await snap.mark(), wt = await wal.mark();
  const took = performance.now() - started;
  await holder.query('ROLLBACK');
  const [sw, ww] = [await collectWindow(snap, sf, st), await collectWindow(wal, wf, wt)];
  // The holder's ACCESS EXCLUSIVE lock takes a transaction id, so pg-snapshot also counts it as a writer in flight.
  assert.equal(sw.coverage, 'partial'); assert.ok(sw.reason.split(',').includes('catalog-unreadable'), `never a failed mark: ${sw.reason}`);
  assert.equal(ww.coverage, 'partial'); assert.ok(ww.reason.split(',').includes('catalog-unreadable') && !/slot|connection/.test(ww.reason), `never a lost slot: ${ww.reason}`);
  assert.ok(took < 2 * (2 * 1000 + 1500), `${Math.round(took)} ms for two marks`);
  // Released: the next windows read normally, in the same slot generation.
  const [s2, w2] = [await snap.mark(), await wal.mark()];
  const [sn, wn] = [await collectWindow(snap, st, s2), await collectWindow(wal, wt, w2)];
  assert.ok(sn.reason.split(',').includes('catalog-unreadable'), 'the window that starts at the locked mark');
  const [s3, w3] = [await snap.mark(), await wal.mark()];
  assert.deepEqual([(await collectWindow(snap, s2, s3)).coverage, (await collectWindow(wal, w2, w3)).coverage], ['net-only', 'complete']);
  assert.ok(wn.reason.split(',').includes('catalog-unreadable'), wn.reason);
});

test('live catalog: a foreign server option whose name reads as a secret is kept by its name only, so a new password is not a lasting change; another option is', { skip }, async t => {
  const { db, read } = await (await database(t))();
  if (!(await isSuperuser(db))) { t.diagnostic('skipped (not a superuser): CREATE FOREIGN DATA WRAPPER'); return; }
  await db.query("CREATE FOREIGN DATA WRAPPER sh_w1; CREATE SERVER sh_s1 FOREIGN DATA WRAPPER sh_w1 OPTIONS (host 'a.example', api_key 'k1')");
  const baseline = await read();
  await db.query("ALTER SERVER sh_s1 OPTIONS (SET api_key 'k2')");
  const rotated = await read(), later = await read();
  assert.deepEqual(catalogReasons(baseline, baseline, rotated), [SCHEMA_DRIFT], 'the server changed inside the window');
  assert.equal(rotated.sha256, baseline.sha256, 'the key\'s value is not in the definition');
  assert.deepEqual(catalogReasons(baseline, rotated, later), []);
  await db.query("ALTER SERVER sh_s1 OPTIONS (SET host 'b.example')");
  assert.notEqual((await read()).sha256, baseline.sha256, 'another option\'s value is');
});
