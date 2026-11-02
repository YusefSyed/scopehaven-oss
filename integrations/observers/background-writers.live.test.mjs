// Background writers against a real PostgreSQL with wal_level = logical: pg-snapshot's attribution of in-flight
// writers by their real locks, the end barrier with a worker that finishes while the mark waits (pg-snapshot and pg-wal),
// and the run lease between two runs. Skipped unless SCOPEHAVEN_PG_LIVE names a disposable test database as
// "user:password@127.0.0.1:port/database" for a superuser (the test creates a second database, schemas and roles, and
// drops them after), as pg-wal.live.test.mjs. Without it every test skips with the reason.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { pgConnect } from './pg-wire.mjs';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { createPgWalObserver, PG_WAL_SOURCE } from './pg-wal.mjs';
import { pgLeaseSql } from './run-lease.mjs';
import { evaluateEffectAssertion, validateWindow } from './events.mjs';

const live = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(process.env.SCOPEHAVEN_PG_LIVE ?? '');
const [, adminUser, adminPassword, portText, database] = live ?? [];
const port = Number(portText);
const connectAs = (user, password, db = database) => pgConnect({ host: '127.0.0.1', port, database: db, user, password });
let skip = live ? false : 'set SCOPEHAVEN_PG_LIVE=user:password@127.0.0.1:port/db (a disposable test database with wal_level=logical, as a superuser) to run';
if (live) {
  try {
    const probe = await connectAs(adminUser, adminPassword);
    try {
      const [[level, superuser]] = (await probe.query("SELECT current_setting('wal_level'), (SELECT rolsuper::text FROM pg_roles WHERE rolname = current_user)"))[0].rows;
      if (level !== 'logical') skip = `the server's wal_level is ${level}: start it with -c wal_level=logical to run`;
      else if (superuser !== 'true') skip = 'the role named by SCOPEHAVEN_PG_LIVE is not a superuser (the test creates a database)';
    } finally { probe.close(); }
  } catch (error) { skip = `the server named by SCOPEHAVEN_PG_LIVE could not be reached (${error.code ?? 'error'})`; }
}

async function fixture(t) {
  const admin = await connectAs(adminUser, adminPassword), writer = await connectAs(adminUser, adminPassword), worker = await connectAs(adminUser, adminPassword);
  const x = randomBytes(4).toString('hex'), orders = `sh_bg_orders_${x}`, audit = `sh_bg_audit_${x}`, events = `sh_bg_events_${x}`, jobs = `sh_bg_jobs_${x}`, other = `sh_bg_other_${x}`;
  const snapRole = `sh_bg_snap_${x}`, walRole = `sh_bg_wal_${x}`, snapPass = randomBytes(12).toString('base64url'), walPass = randomBytes(12).toString('base64url');
  // A platform background table: one of the test's own in _analytics, a schema Supabase's checked-in list covers whole.
  // And a table the list names one by one (cron.job_run_details), the test's own when the server has no cron schema: its
  // index and its owned sequence must read as the table (a schema-wide entry would cover them by name anyway).
  const free = (await admin.query("SELECT (SELECT count(*)::text FROM pg_namespace WHERE nspname = '_analytics'), (SELECT count(*)::text FROM pg_namespace WHERE nspname = 'cron')"))[0].rows[0];
  const cronFree = free[1] === '0';
  if (cronFree) await admin.query('CREATE SCHEMA cron; CREATE TABLE cron.job_run_details (runid serial PRIMARY KEY, status text)');
  const platformTable = `_analytics.sh_bg_platform_${x}`, heartbeat = `sh_bg_heartbeat_${x}`;
  await admin.query(`CREATE SCHEMA IF NOT EXISTS _analytics;
    CREATE TABLE ${platformTable} (id serial PRIMARY KEY, what text); CREATE TABLE ${heartbeat} (id serial PRIMARY KEY, at timestamptz);
    CREATE TABLE ${orders} (id text PRIMARY KEY, status text NOT NULL); INSERT INTO ${orders} VALUES ('o1', 'open');
    CREATE TABLE ${audit} (id serial PRIMARY KEY, what text);
    CREATE TABLE ${events} (id text NOT NULL, region text NOT NULL, PRIMARY KEY (id, region)) PARTITION BY LIST (region);
    CREATE TABLE _analytics.${events}_p1 PARTITION OF ${events} FOR VALUES IN ('p1');
    CREATE TABLE ${jobs} (id serial PRIMARY KEY, state text NOT NULL);
    CREATE ROLE ${snapRole} LOGIN PASSWORD '${snapPass}'; GRANT SELECT ON ${orders}, ${events}, ${jobs} TO ${snapRole}; GRANT USAGE ON SCHEMA _analytics TO ${snapRole}; GRANT SELECT ON _analytics.${events}_p1 TO ${snapRole};
    CREATE ROLE ${walRole} LOGIN REPLICATION PASSWORD '${walPass}'; GRANT SELECT ON ${jobs} TO ${walRole}`);
  await admin.query(`CREATE DATABASE ${other}`);
  const otherAdmin = await connectAs(adminUser, adminPassword, other);
  await otherAdmin.query('CREATE TABLE elsewhere (n int)');
  const observers = [];
  t.after(async () => {
    for (const o of observers) { try { await o.stop(); } catch {} }
    for (const c of [writer, worker, otherAdmin]) { try { await c.query('ROLLBACK'); } catch {} c.close(); }
    try {
      await admin.query(`DROP TABLE IF EXISTS ${orders}, ${audit}, ${events}, ${jobs}, ${platformTable}, ${heartbeat} CASCADE; DROP OWNED BY ${snapRole}, ${walRole}; DROP ROLE IF EXISTS ${snapRole}; DROP ROLE IF EXISTS ${walRole}`);
      if (free[0] === '0') await admin.query('DROP SCHEMA IF EXISTS _analytics CASCADE');
      if (cronFree) await admin.query('DROP SCHEMA IF EXISTS cron CASCADE');
      await admin.query(`DROP DATABASE IF EXISTS ${other} WITH (FORCE)`);
    } finally { admin.close(); }
  });
  const snapshot = (extra = {}) => { const o = createPgSnapshotObserver({ env: { SCOPEHAVEN_TARGET_SNAP: `${snapRole}:${snapPass}` }, host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_SNAP',
    tables: [{ table: orders, key: 'id', resourcePrefix: 'orders' }, { table: events, key: 'id', resourcePrefix: 'events' }], watchedResources: ['orders/o1'], ...extra }); observers.push(o); return o; };
  const wal = (extra = {}) => { const o = createPgWalObserver({ env: { SCOPEHAVEN_TARGET_WAL: `${walRole}:${walPass}` }, host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_WAL',
    tables: [{ table: orders, key: 'id', resourcePrefix: 'orders', values: ['status'] }], ...extra }); observers.push(o); return o; };
  return { admin, writer, worker, otherAdmin, orders, audit, events, jobs, platformTable, heartbeat, walRole, snapRole, cronFree, snapshot, wal };
}
const span = async (o, between, after = async () => {}) => { const from = await o.mark(); await between(); const to = await o.mark(); await after(); return o.collect(from, to); };
const asWindow = (o, w) => validateWindow({ source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: w.coverage, reason: w.reason, events: w.events, ...(w.exact ? { exact: w.exact } : {}) });

test('live pg-snapshot attribution: an open writer on an ignored table, or in another database, no longer holds the window; one on an unlisted table or a declared partition still does', { skip }, async t => {
  const f = await fixture(t);
  const listed = f.snapshot({ platform: 'supabase', ignore: [`public.${f.heartbeat}`] }), plain = f.snapshot(), none = f.snapshot({ platform: 'none' });
  await none.start();
  await listed.start(); await plain.start();
  // Each writer stays open across the end mark and is rolled back after it.
  const around = async (o, begin) => span(o, () => begin(), () => f.writer.query('ROLLBACK').then(() => f.otherAdmin.query('ROLLBACK')));
  const platformWrite = () => f.writer.query(`BEGIN; INSERT INTO ${f.platformTable} (what) VALUES ('sign-in')`);
  const ignored = await around(listed, platformWrite);
  assert.deepEqual([ignored.coverage, ignored.background.ignoredWriters], ['net-only', 1], ignored.reason);
  assert.equal((await around(plain, platformWrite)).reason, 'transaction-in-flight-at-window-end', 'without a list every writer counts, as before');
  if (f.cronFree) {
    const run = await around(listed, () => f.writer.query("BEGIN; INSERT INTO cron.job_run_details (status) VALUES ('running')"));
    assert.deepEqual([run.coverage, run.background.ignoredWriters], ['net-only', 1], 'its primary key index and serial sequence read as the listed table');
  } else t.diagnostic('the server has a cron schema of its own: the table-level platform entry case was not run');
  assert.equal((await around(listed, () => f.writer.query(`BEGIN; INSERT INTO ${f.audit} (what) VALUES ('refund sent')`))).reason, 'transaction-in-flight-at-window-end', 'an unlisted table is never ignored');
  // A partition of a declared table, in a schema the platform list covers whole (_analytics): written directly, only the
  // partition is locked, and its rows are the declared table's.
  assert.equal((await around(listed, () => f.writer.query(`BEGIN; INSERT INTO _analytics.${f.events}_p1 VALUES ('e1', 'p1')`))).reason, 'transaction-in-flight-at-window-end', 'a declared partition in an ignored schema');
  // A writer in another database cannot write this one's tables.
  const elsewhere = await around(listed, () => f.otherAdmin.query('BEGIN; INSERT INTO elsewhere VALUES (1)'));
  assert.deepEqual([elsewhere.coverage, elsewhere.background.ignoredWriters], ['net-only', 1]);
  assert.equal((await around(plain, () => f.otherAdmin.query('BEGIN; INSERT INTO elsewhere VALUES (1)'))).reason, 'transaction-in-flight-at-window-end');
  // A writer that held only the platform table at the first lock read but also a declared table by the second: counted.
  const both = await around(listed, () => f.writer.query(`BEGIN; INSERT INTO ${f.platformTable} (what) VALUES ('x'); INSERT INTO ${f.orders} VALUES ('o2', 'new')`));
  assert.equal(both.reason, 'transaction-in-flight-at-window-end');
  // A profile's own ignored table never makes a writer quiet: a worker that has written its heartbeat can still write
  // an application table before it commits (the review's probe: heartbeat, end mark, then the refund, then COMMIT).
  const worker = await around(listed, () => f.writer.query(`BEGIN; INSERT INTO ${f.heartbeat} (at) VALUES (now())`));
  assert.equal(worker.reason, 'transaction-in-flight-at-window-end');
  // A shared catalog (database 0) is not another database: an open ALTER ROLE is a writer like any other.
  assert.equal((await around(none, () => f.writer.query(`BEGIN; ALTER ROLE ${f.walRole} SET work_mem = '64kB'`))).reason, 'transaction-in-flight-at-window-end');
  // Committed background writes still keep the cluster from being quiescent: a table-wide absence stays undecided.
  const committed = await span(listed, () => f.writer.query(`INSERT INTO ${f.platformTable} (what) VALUES ('refresh')`));
  assert.equal(committed.coverage, 'net-only');
  const ew = asWindow(listed, committed);
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', name: f.orders, operation: 'insert' } }, [ew]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', name: f.orders, operation: 'update', resource: 'orders/o1' } }, [ew]).verdict, 'pass');
});

test('live end barrier: a worker that finishes while the mark waits is inside the window; pending work at the end mark reads queue-not-drained (pg-snapshot and pg-wal)', { skip }, async t => {
  const f = await fixture(t);
  const Q = { queues: [{ table: f.jobs, pending: { column: 'state', in: ['queued', 'running'] } }], drainTimeoutMs: 4000, pollMs: 25 };
  // The app enqueues a refund job and replies; the worker picks it up 300 ms later, refunds, and marks the job done.
  const enqueueAndWork = async () => {
    const [[id]] = (await f.admin.query(`INSERT INTO ${f.jobs} (state) VALUES ('queued') RETURNING id::text`))[0].rows;
    setTimeout(() => { f.worker.query(`BEGIN; UPDATE ${f.jobs} SET state = 'running' WHERE id = ${id}; COMMIT; UPDATE ${f.orders} SET status = 'refunded' WHERE id = 'o1'; UPDATE ${f.jobs} SET state = 'done' WHERE id = ${id}`).catch(() => {}); }, 300);
  };
  for (const make of [() => f.snapshot(Q), () => f.wal({ ...Q, platform: 'supabase' })]) {
    await f.admin.query(`UPDATE ${f.orders} SET status = 'open' WHERE id = 'o1'`);
    const o = make(); await o.start();
    const w = await span(o, enqueueAndWork);
    assert.ok(['net-only', 'complete'].includes(w.coverage), `${o.kind}: ${w.reason}`);
    assert.deepEqual(w.events.filter(e => e.name === f.orders).map(e => `${e.operation} ${e.resource}`), ['update orders/o1'], `${o.kind}: the worker's refund is in the window`);
    const end = o.kind === 'postgres-wal-decode' ? w.wal.queues.end : w.background.queues.end;
    assert.ok(end.clean && end.waitedMs > 0, `${o.kind}: the mark waited for the queue`);
    if (o.kind === 'postgres-wal-decode') assert.deepEqual([w.wal.others.queue, w.wal.others.unlisted], [3, []], 'the queue\'s own writes (enqueue, running, done) are the queue\'s, never unlisted');
    // A job no worker takes: the end mark's queue is not drained.
    const stuck = await span(o, () => f.admin.query(`INSERT INTO ${f.jobs} (state) VALUES ('queued')`), () => f.admin.query(`UPDATE ${f.jobs} SET state = 'done'`));
    assert.equal(stuck.reason, 'queue-not-drained', o.kind);
    await o.stop();
  }
});

test('live shared database: a second run is refused while the first holds its lease; a lease that appears mid-run fails the window; one run\'s observers share it', { skip }, async t => {
  const f = await fixture(t);
  const first = f.snapshot({ runLease: true, runKey: 1001 }); await first.start();
  await assert.rejects(f.snapshot({ runLease: true, runKey: 2002 }).start(), /shared-database/);
  await assert.rejects(f.wal({ runKey: 2002 }).start(), /shared-database/);
  const sameRun = f.wal({ runKey: 1001 }); await sameRun.start(); // the first run's own pg-wal
  const m0 = await first.mark(), w0 = await sameRun.mark();
  const intruder = await connectAs(adminUser, adminPassword);
  try {
    assert.deepEqual((await intruder.query(pgLeaseSql(3003)))[0].rows, [['true']]);
    // No absence passes, and the events stay: a lock of the lease's class (anyone can take one) cannot erase a fail.
    await f.admin.query(`UPDATE ${f.orders} SET status = 'shared' WHERE id = 'o1'`);
    const sharedSnap = await first.collect(m0, await first.mark()), sharedWal = await sameRun.collect(w0, await sameRun.mark());
    assert.deepEqual([sharedSnap.coverage, sharedSnap.reason, sharedSnap.events.filter(e => e.name === f.orders).length], ['partial', 'shared-database', 1]);
    assert.ok(sharedWal.reason.split(',').includes('shared-database') && sharedWal.events.length === 1, sharedWal.reason);
  } finally { intruder.close(); }
  const after = await first.mark(), next = await first.mark();
  assert.equal((await first.collect(after, next)).coverage, 'net-only', 'the intruder gone, windows decide again');
  // The lease session is ended from outside: the next mark takes the lease again, so a later run is still refused.
  const [[ended]] = (await f.admin.query(`SELECT pg_catalog.count(pg_catalog.pg_terminate_backend(l.pid))::text FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_stat_activity a ON a.pid = l.pid
    WHERE l.locktype = 'advisory' AND l.objid = 1001 AND l.objsubid = 2 AND a.usename = '${f.snapRole}'`))[0].rows;
  assert.equal(ended, '1');
  await first.mark();
  await assert.rejects(f.snapshot({ runLease: true, runKey: 2002 }).start(), /shared-database/, 'the lease was taken again');
  await first.stop(); await sameRun.stop();
  const later = f.snapshot({ runLease: true, runKey: 2002 }); await later.start(); // the first run released its lease
  await later.stop();
  // pg-wal holds the lease in its own session: a run with only a pg-wal still refuses a second run.
  const walOnly = f.wal({ runKey: 4004 }); await walOnly.start();
  await assert.rejects(f.snapshot({ runLease: true, runKey: 5005 }).start(), /shared-database/);
  await walOnly.stop();
});

test('live pg-wal: an unlisted unlogged table holds absence back (its writes are not in the WAL), and an unlogged queue is refused', { skip }, async t => {
  const f = await fixture(t);
  const cache = `${f.orders}_cache`, ujobs = `${f.orders}_ujobs`;
  await f.admin.query(`CREATE UNLOGGED TABLE ${cache} (id int); CREATE UNLOGGED TABLE ${ujobs} (id serial PRIMARY KEY, state text); GRANT SELECT ON ${ujobs} TO ${f.walRole}`);
  try {
    const o = f.wal(); await o.start();
    const w = await span(o, () => f.admin.query(`INSERT INTO ${cache} VALUES (1)`));
    assert.deepEqual([w.coverage, w.reason, w.wal.others.notInWal], ['partial', 'table-not-in-wal', [`public.${cache}`, `public.${ujobs}`]]);
    assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: PG_WAL_SOURCE, name: f.orders, operation: 'insert' } }, [asWindow(o, w)]).verdict, 'missing');
    const ignored = f.wal({ ignore: [`public.${cache}`, `public.${ujobs}`] }); await ignored.start();
    assert.equal((await span(ignored, () => f.admin.query(`INSERT INTO ${cache} VALUES (2)`))).coverage, 'complete', 'listed, it is accounted for');
    const q = f.wal({ ignore: [`public.${cache}`], queues: [{ table: ujobs }], drainTimeoutMs: 0 }); await q.start();
    assert.equal((await span(q, () => {})).reason, 'queue-not-in-wal');
  } finally { await f.admin.query(`DROP TABLE IF EXISTS ${cache}, ${ujobs}`); }
});

export { PG_WAL_SOURCE };
