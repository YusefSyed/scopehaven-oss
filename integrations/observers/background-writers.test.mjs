// Background writers: the per-platform ignore lists and their one reader, the end barrier and the shared-database rule,
// in pg-snapshot (against a scripted session: no server) and sqlite-snapshot (real database files in a spaced temp folder).
// pg-wal's own rules are in pg-wal.test.mjs; both Postgres observers against a real server are in
// background-writers.live.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { readPlatformList, platformList, resolveIgnoreList, IGNORE_LIST_SCHEMA } from './ignore-lists/ignore-list.mjs';
import { validateQueues, validateDrain, pgQueueCountSql, drainWait, BARRIER_LIMITS } from './end-barrier.mjs';
import { LEASE_CLASS, pgLeaseSql, pgOtherRunsSql, fileLease } from './run-lease.mjs';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { createSqliteSnapshotObserver } from './sqlite.mjs';
import { evaluateEffectAssertion, validateWindow } from './events.mjs';
import { catalogAnswer } from './fixtures/fake-postgres.mjs';

const SUPABASE = JSON.parse(readFileSync(new URL('./ignore-lists/supabase.json', import.meta.url), 'utf8'));

test('the checked-in lists: each entry names its writer and why; tables that carry an application effect stay off the Supabase list', () => {
  const supabase = platformList('supabase', 'postgres'), litestream = platformList('litestream', 'sqlite');
  assert.equal(supabase.entries.length, SUPABASE.entries.length);
  for (const e of [...supabase.entries, ...litestream.entries]) assert.ok(e.writer.trim() && e.why.trim(), JSON.stringify(e));
  const listed = new Set(supabase.entries.map(e => (e.table === null ? e.schema : `${e.schema}.${e.table}`)));
  for (const name of ['auth.audit_log_entries', 'cron.job_run_details', 'net._http_response', 'realtime.subscription']) assert.ok(listed.has(name), name);
  // Accounts, logins sent, files, broadcasts, scheduled jobs, outbound requests and secrets are effects.
  for (const [schema, table] of [['auth', 'users'], ['auth', 'identities'], ['auth', 'one_time_tokens'], ['storage', 'objects'], ['storage', 'buckets'], ['realtime', 'messages'],
    ['cron', 'job'], ['net', 'http_request_queue'], ['vault', 'secrets'], ['public', 'orders']])
    assert.equal(resolveIgnoreList({ engine: 'postgres', platform: 'supabase' }).ignores(schema, table), false, `${schema}.${table}`);
  assert.equal(platformList('none', 'postgres').entries.length, 0);
  assert.throws(() => platformList('supabase', 'sqlite'), /platform is one of none, litestream/);
  assert.throws(() => platformList('heroku', 'postgres'), /platform is one of none, supabase/);
});

test('a checked-in list that does not read fails as it is read', () => {
  const ok = { schema: IGNORE_LIST_SCHEMA, platform: 'p', engine: 'postgres', note: 'n', entries: [{ schema: 'a', table: 'b', writer: 'w', why: 'y' }] };
  assert.doesNotThrow(() => readPlatformList(ok, { platform: 'p', engine: 'postgres' }));
  for (const [bad, pattern] of [
    [{ ...ok, schema: 'x/1' }, /not a scopehaven-ignore-list\/1 list/], [{ ...ok, platform: 'q' }, /not a/], [{ ...ok, entries: [] }, /1 to 64 entries/],
    [{ ...ok, entries: [{ schema: 'a', table: 'b', writer: 'w' }] }, /writer and a reason/], [{ ...ok, entries: [{ schema: 'a', table: 'b', writer: 'w', why: ' ' }] }, /writer and a reason/],
    [{ ...ok, entries: [{ schema: 'a', table: 'b c', writer: 'w', why: 'y' }] }, /unsupported identifier/],
    [{ ...ok, entries: [ok.entries[0], ok.entries[0]] }, /repeats a\.b/],
    [{ ...ok, entries: [{ schema: 'a', writer: 'w', why: 'y' }, ok.entries[0]] }, /under a schema-wide entry/],
  ]) assert.throws(() => readPlatformList(bad, { platform: 'p', engine: 'postgres' }), pattern);
});

test('the one reader: a declared table or queue is never ignored, a schema-wide profile entry never covers one, and nothing unlisted is ignored', () => {
  const declared = [{ schema: 'public', table: 'orders' }], queues = [{ schema: 'public', table: 'jobs' }];
  const list = resolveIgnoreList({ engine: 'postgres', platform: 'supabase', ignore: ['public.heartbeats', 'worker'], declared, queues });
  assert.deepEqual([list.ignores('public', 'heartbeats'), list.ignores('worker', 'anything'), list.ignores('auth', 'audit_log_entries')], [true, true, true]);
  assert.deepEqual([list.ignores('public', 'orders'), list.ignores('public', 'jobs'), list.ignores('public', 'sessions_log'), list.ignores('auth', 'users')], [false, false, false, false]);
  assert.deepEqual(list.record.profile, ['public.heartbeats', 'worker']);
  assert.match(list.record.digest, /^[a-f0-9]{64}$/);
  for (const [ignore, pattern] of [[['public.orders'], /declared table; an observed table or queue is never on the ignore list/], [['public.jobs'], /declared queue/],
    [['public'], /cannot cover schema public whole: it holds the declared table public\.orders/], [['a.b.c'], /'schema' or 'schema\.table'/], [['x', 'x'], /listed once/]])
    assert.throws(() => resolveIgnoreList({ engine: 'postgres', ignore, declared, queues }), pattern, JSON.stringify(ignore));
  // A platform entry that would cover a declared table (observing auth.sessions on Supabase) is overridden for that table only.
  const sessions = resolveIgnoreList({ engine: 'postgres', platform: 'supabase', declared: [{ schema: 'auth', table: 'sessions' }, { schema: '_realtime', table: 'tenants' }] });
  assert.deepEqual([sessions.ignores('auth', 'sessions'), sessions.ignores('auth', 'refresh_tokens'), sessions.ignores('_realtime', 'tenants'), sessions.ignores('_realtime', 'extensions')], [false, true, false, true]);
  assert.deepEqual(sessions.overridden, ['_realtime.tenants', 'auth.sessions']);
  // SQLite: table names; Litestream's tables are on its list.
  const lite = resolveIgnoreList({ engine: 'sqlite', platform: 'litestream', ignore: ['heartbeat'], declared: [{ schema: 'main', table: 'orders' }] });
  assert.deepEqual([lite.ignores('main', '_litestream_seq'), lite.ignores('main', 'heartbeat'), lite.ignores('main', 'orders'), lite.ignores('main', 'audit')], [true, true, false, false]);
  assert.throws(() => resolveIgnoreList({ engine: 'sqlite', ignore: ['main.orders'] }), /table names/);
});

test('the end barrier helpers: queue declarations, a bounded count, and a wait that ends clean or at its timeout', async () => {
  assert.deepEqual(validateQueues([{ table: 'jobs' }, { table: 'job', schema: 'pgboss', pending: { column: 'state', in: ['created', 'retry', 'active'] } }, { table: 't', pending: { column: 'done_at', isNull: true } }], { engine: 'postgres' }).map(q => [q.schema, q.table, q.pending]),
    [['public', 'jobs', null], ['pgboss', 'job', { column: 'state', in: ['created', 'retry', 'active'] }], ['public', 't', { column: 'done_at', isNull: true }]]);
  for (const [queues, pattern] of [[[{ table: 'a b' }], /unsupported identifier/], [[{ table: 'j', pending: { column: 'state', in: ["x'); DROP"] } }], /pending is/],
    [[{ table: 'j', pending: { column: 'state' } }], /pending is/], [[{ table: 'j' }, { table: 'j' }], /declared once/], [[{ table: 'j', where: 'x' }], /is \{ table, schema, pending \}/],
    [Array.from({ length: 9 }, (_, i) => ({ table: `q${i}` })), /up to 8/]])
    assert.throws(() => validateQueues(queues, { engine: 'postgres' }), pattern);
  assert.throws(() => validateQueues([{ table: 'j', schema: 'main' }], { engine: 'sqlite' }), /is \{ table, pending \}/);
  assert.throws(() => validateDrain({ drainTimeoutMs: -1 }), /drainTimeoutMs/);
  const sql = pgQueueCountSql(validateQueues([{ table: 'job', schema: 'pgboss', pending: { column: 'state', in: ['created'] } }], { engine: 'postgres' }));
  assert.match(sql, /FROM "pgboss"\."job" WHERE \("state"\)::pg_catalog\.text IN \('created'\) LIMIT 10001/);
  assert.equal(BARRIER_LIMITS.countCap, 10000);
  let clock = 0, reads = 0;
  const fake = { now: () => clock, wait: async ms => { clock += ms; } };
  assert.deepEqual(await drainWait(async () => ({ clean: ++reads >= 3 }), { drainTimeoutMs: 1000, pollMs: 100 }, fake), { clean: true, waitedMs: 200 });
  clock = 0;
  assert.deepEqual(await drainWait(async () => ({ clean: false }), { drainTimeoutMs: 250, pollMs: 100 }, fake), { clean: false, waitedMs: 250 });
  clock = 0; reads = 0;
  assert.deepEqual(await drainWait(async () => ({ clean: false, n: ++reads }), { drainTimeoutMs: 0, pollMs: 100 }, fake), { clean: false, n: 1, waitedMs: 0 }, 'drainTimeoutMs 0 reads once');
});

test('the run lease: one advisory lock class, keyed by run; a SQLite lease file counts other live runs only', t => {
  assert.match(pgLeaseSql(7), new RegExp(`pg_try_advisory_lock_shared\\(${LEASE_CLASS}, 7\\)`));
  assert.match(pgOtherRunsSql(7), /l\.locktype = 'advisory'[\s\S]*l\.objid <> 7::pg_catalog\.oid[\s\S]*current_database/);
  assert.throws(() => pgLeaseSql(0), /runKey/);
  const root = mkdtempSync(join(tmpdir(), 'scopehaven lease ')); t.after(() => rmSync(root, { recursive: true, force: true }));
  const db = join(root, 'app db.sqlite'); writeFileSync(db, '');
  const leases = join(root, 'leases');
  const a = fileLease(db, { runKey: 11, root: leases }), b = fileLease(db, { runKey: 22, root: leases }), a2 = fileLease(db, { runKey: 11, root: leases });
  assert.equal(a.others(), 0);
  a.acquire(); a2.acquire();
  assert.deepEqual([a.others(), b.others()], [0, 1], 'the same run never counts itself');
  const folder = join(leases, readdirSync(leases)[0]);
  writeFileSync(join(folder, '2147480000-33'), 'x'); // a process that is not running
  assert.equal(b.others(), 1, 'a dead process holds no lease');
  a.release(); assert.equal(b.others(), 1, 'the lease stays while another observer of the run holds it');
  a2.release(); assert.equal(b.others(), 0);
});

// pg-snapshot against a scripted session (one per mark, as pg-wire gives): each mark reads the state its index names.
const SNAPSHOT_ENV = { SCOPEHAVEN_TARGET_DB: 'reader:pw' };
function snapshotSession(states, log = []) {
  let mark = -1;
  const answer = sql => {
    const statements = sql.split('; ');
    if (statements[0].startsWith('BEGIN')) mark += 1;
    // The end barrier's poll runs before its mark's transaction: it reads the coming mark's state.
    const poll = statements[0].startsWith('SET search_path') || (statements.length === 1 && /sh:queuecount/.test(statements[0]));
    const st = states[Math.max(mark + (poll ? 1 : 0), 0)] ?? states.at(-1);
    return statements.map(x => {
      log.push(x.slice(0, 40));
      // The catalog fingerprint (./catalog.mjs): one unchanging catalog.
      const catalog = catalogAnswer(x);
      if (catalog) return { rows: catalog };
      if (/sh:lease/.test(x) && !/pg_current_snapshot/.test(x)) return { rows: [['true']] };
      if (/sh:shared/.test(x) && !/pg_current_snapshot/.test(x)) return { rows: [[String(st.others ?? 0)]] };
      if (/sh:queuecount/.test(x)) return { rows: [(typeof st.pending === 'function' ? st.pending() : st.pending ?? []).map(String)] };
      if (/^(BEGIN|SET|LOCK|COMMIT)/.test(x)) return { rows: [] };
      if (/pg_current_snapshot/.test(x)) return { rows: [[st.snapshot, st.writers1 ?? null, 'false', '2026-10-24 00:00:00+00', ...(/WITH RECURSIVE decl/.test(x) ? [st.quiet1 ?? null] : []), ...(/sh:shared/.test(x) ? [String(st.others ?? 0)] : []),
        ...(/sh:ownlease/.test(x) ? [String(st.ownLease ?? 1)] : [])]] };
      if (/WHERE pid = pg_catalog\.pg_backend_pid\(\)/.test(x)) return { rows: [['{16384}']] };
      if (/^WITH RECURSIVE d\(oid, pending\)/.test(x)) return { rows: [] };
      if (/^SELECT c\.oid::text, c\.relkind::text/.test(x)) return { rows: [['16384', 'r', 'heap', '16384', 'p']] };
      if (/AS r ORDER BY/.test(x)) return { rows: (st.rows ?? [['o1', '50']]).map(([key, xmin]) => [key, xmin, `h-${key}-${xmin}`, '16384']) };
      if (/^SELECT \(SELECT pg_catalog\.array_agg\(transactionid/.test(x)) return { rows: [[st.writers2 ?? null, ...(/WITH RECURSIVE decl/.test(x) ? [st.quiet2 ?? null] : [])]] };
      if (/pg_relation_filenode/.test(x)) return { rows: [['16384', '16384']] };
      if (/pg_catalog\.pg_proc/.test(x)) return { rows: [['16384', '', 'i', 'pg_catalog.textout']] };
      if (/FROM pg_catalog\.pg_attribute WHERE attrelid/.test(x)) return { rows: [['16384', '1', 'id', '25', 'false']] };
      throw new Error(`unscripted: ${x.slice(0, 80)}`);
    });
  };
  return async () => ({ async query(sql) { return answer(sql); }, close() { log.push('close'); } });
}
const snapshotObserver = (states, extra = {}, log = []) => createPgSnapshotObserver({ env: SNAPSHOT_ENV, host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB',
  tables: [{ table: 'orders', key: 'id' }], watchedResources: ['orders/o1'], connect: snapshotSession(states, log), ...extra });
const quietWindow = async (states, extra) => { const o = snapshotObserver(states, extra); await o.start(); const from = await o.mark(), to = await o.mark(); return o.collect(from, to); };
// States: the start reading (start(), then mark 0) and the end mark's. Writers are transaction ids (as pg_locks prints them).
const ends = end => [{ snapshot: '100:100:' }, { snapshot: '100:100:' }, { snapshot: '100:104:', ...end }];

test('pg-snapshot attribution: an end-mark writer quiet at every lock read that saw it stops counting; any other still does', async () => {
  const IGN = { platform: 'supabase' };
  // Without an ignore list every writer counts, as before.
  assert.equal((await quietWindow(ends({ writers1: '{101}', quiet1: '{101}', writers2: '{101}', quiet2: '{101}' }))).reason, 'transaction-in-flight-at-window-end');
  const quiet = await quietWindow(ends({ writers1: '{101}', quiet1: '{101}', writers2: '{101}', quiet2: '{101}' }), IGN);
  assert.deepEqual([quiet.coverage, quiet.background.ignoredWriters], ['net-only', 1]);
  assert.equal((await quietWindow(ends({ writers1: '{101}', quiet1: '{101}' }), IGN)).coverage, 'net-only', 'quiet at read 1, gone by read 2');
  assert.equal((await quietWindow(ends({ writers1: '{101}', quiet1: '{101}', writers2: '{101}', quiet2: null }), IGN)).reason, 'transaction-in-flight-at-window-end', 'it took a lock on another table by read 2');
  assert.equal((await quietWindow(ends({ writers1: '{101}', quiet1: null }), IGN)).reason, 'transaction-in-flight-at-window-end', 'not quiet at read 1');
  assert.equal((await quietWindow(ends({ snapshot: '100:104:102', writers1: null }), IGN)).reason, 'transaction-in-flight-at-window-end', 'in the snapshot, seen by no lock read');
  assert.equal((await quietWindow(ends({ writers2: '{103}', quiet2: '{103}' }), IGN)).coverage, 'net-only', 'first seen at read 2, quiet there');
  assert.equal((await quietWindow(ends({ writers2: '{103}', quiet2: null }), IGN)).reason, 'transaction-in-flight-at-window-end', 'first seen at read 2, not quiet');
  assert.equal((await quietWindow(ends({ snapshot: '100:104:101', writers1: '{101}', quiet1: '{101}' }), IGN)).coverage, 'net-only', 'in the snapshot and quiet at read 1');
  assert.equal((await quietWindow(ends({ snapshot: '100:104:102', writers2: '{102}', quiet2: '{102}' }), IGN)).reason, 'transaction-in-flight-at-window-end', 'in the snapshot, seen only at read 2');
  // The snapshot prints 64-bit ids, pg_locks 32-bit ones: compared at 32 bits (an id one epoch on).
  const epoch = [{ snapshot: '4294967396:4294967396:' }, { snapshot: '4294967396:4294967396:' }, { snapshot: '4294967396:4294967400:4294967397', writers1: '{101}', quiet1: '{101}' }];
  assert.equal((await quietWindow(epoch, IGN)).coverage, 'net-only', 'xid8 4294967397 is lock id 101');
  // Attribution never makes a cluster with background writes quiescent: a table-wide absence stays undecided.
  const w = await quietWindow(ends({ writers1: '{101}', quiet1: '{101}' }), IGN);
  const ew = validateWindow({ source: 'sql-snapshot', instanceId: 'pg-snapshot-1', scope: { operations: ['insert', 'update', 'delete'], names: ['orders'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: w.coverage, reason: w.reason, events: w.events, exact: w.exact });
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'orders', operation: 'insert' } }, [ew]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'orders', operation: 'update', resource: 'orders/o1' } }, [ew]).verdict, 'pass');
  // The quiet read names the declared tree and the ignore list in SQL; without a list it is never sent.
  const log = [], o = snapshotObserver(ends({}), IGN, log); await o.start(); await o.mark();
  assert.ok(log.some(l => l.startsWith('SELECT pg_catalog.pg_current_snapshot')));
  const statements = []; const conn = snapshotSession(ends({}));
  const spy = createPgSnapshotObserver({ env: SNAPSHOT_ENV, host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB', tables: [{ table: 'orders', key: 'id' }], platform: 'supabase', ignore: ['public.heartbeats'],
    connect: async () => { const c = await conn(); return { query: async sql => { statements.push(sql); return c.query(sql); }, close() {} }; } });
  await spy.start();
  const quietSql = statements.join('\n');
  assert.match(quietSql, /decl\(nsp, rel\) AS \(VALUES \('public'::pg_catalog\.text, 'orders'::pg_catalog\.text\)\)/);
  assert.match(quietSql, /\('auth'::pg_catalog\.text, 'audit_log_entries'::pg_catalog\.text\)/);
  // Only the platform's list makes a writer quiet: a profile's own background table is the application's worker's.
  assert.doesNotMatch(quietSql, /'heartbeats'/);
  // A shared catalog (database 0) is not another database.
  assert.match(quietSql, /\(l\.database <> 0 AND l\.database IS DISTINCT FROM/);
  assert.match(quietSql, /NOT EXISTS \(SELECT 1 FROM tree JOIN owner o ON o\.tab = tree\.oid WHERE o\.oid = l\.relation\)/);
  // An index, a TOAST table and an owned sequence each read as their table (a real INSERT write-locks all three).
  assert.match(quietSql, /x\.indrelid FROM pg_catalog\.pg_index x WHERE x\.indexrelid = k\.oid/);
  assert.match(quietSql, /c\.reltoastrelid = b\.tab/);
  assert.match(quietSql, /pg_catalog\.pg_depend d JOIN pg_catalog\.pg_class q ON q\.oid = d\.objid AND q\.relkind = 'S'/);
  assert.match(quietSql, /l\.database IS DISTINCT FROM/);
  const plainStatements = []; const conn2 = snapshotSession(ends({}));
  await createPgSnapshotObserver({ env: SNAPSHOT_ENV, host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB', tables: [{ table: 'orders', key: 'id' }],
    connect: async () => { const c = await conn2(); return { query: async sql => { plainStatements.push(sql); return c.query(sql); }, close() {} }; } }).start();
  assert.ok(!plainStatements.join('\n').includes('WITH RECURSIVE decl'), 'no ignore list: the mark reads exactly as before');
});

test('pg-snapshot end barrier and run lease: pending work in the end mark\'s own snapshot, and another run\'s lease, each hold the window back', async () => {
  const Q = { queues: [{ table: 'jobs' }], drainTimeoutMs: 200, pollMs: 20 };
  const clean = await quietWindow(ends({ pending: [0] }).map(s => ({ pending: [0], ...s })), Q);
  assert.deepEqual([clean.coverage, clean.background.queues.end], ['net-only', { clean: true, waitedMs: 0, pending: [{ queue: 'public.jobs', pending: 0 }] }]);
  const pending = await quietWindow(ends({ pending: [3] }).map(s => ({ pending: [0], ...s })), Q);
  assert.deepEqual([pending.coverage, pending.reason, pending.background.queues.end.pending], ['partial', 'queue-not-drained', [{ queue: 'public.jobs', pending: 3 }]]);
  assert.equal(pending.events.length, 0);
  // The poll before the transaction waits for the queue; the count that decides is the one under the snapshot.
  // A job enqueued after the poll read clean and before the mark's snapshot: the snapshot's own count decides.
  let reads = 0;
  const raced = await quietWindow(ends({ pending: () => (++reads === 1 ? [0] : [2]) }).map(s => ({ pending: [0], ...s })), Q);
  assert.deepEqual([raced.coverage, raced.reason, reads], ['partial', 'queue-not-drained', 2]);
  let polls = 0;
  const waited = await quietWindow(ends({ pending: () => (++polls > 3 ? [0] : [1]) }).map(s => ({ pending: [0], ...s })), Q);
  assert.deepEqual([waited.coverage, waited.background.queues.end.clean, polls > 3], ['net-only', true, true]);
  // The run lease: start refuses while another run holds one; one seen at a mark fails the window.
  await assert.rejects(snapshotObserver([{ snapshot: '100:100:', others: 1 }], { runLease: true }).start(), /shared-database/);
  // No absence passes on it, and its events stay (a lock of the lease's class cannot erase a fail).
  const shared = await quietWindow([{ snapshot: '100:100:' }, { snapshot: '100:100:' }, { snapshot: '100:102:', others: 1, rows: [['o1', '101']] }], { runLease: true });
  assert.deepEqual([shared.coverage, shared.reason, shared.events.map(e => `${e.operation} ${e.resource}`)], ['partial', 'shared-database', ['update orders/o1']]);
  // A lease whose session has gone is taken again at the next mark.
  const log = [], lost = snapshotObserver([{ snapshot: '100:100:' }, { snapshot: '100:100:', ownLease: 0 }, { snapshot: '100:100:' }], { runLease: true }, log);
  await lost.start(); await lost.mark();
  assert.equal(log.filter(l => l.startsWith('/* sh:lease */')).length, 2, 'the lease taken at start and again after the mark that found it gone');
  // Taken again even while another run holds one (no refusal on that path); the window ending at that mark reads lease-lost.
  const log2 = [], gap = snapshotObserver([{ snapshot: '100:100:' }, { snapshot: '100:100:' }, { snapshot: '100:100:', ownLease: 0, others: 1 }], { runLease: true }, log2);
  await gap.start();
  const g0 = await gap.mark(), g1 = await gap.mark();
  assert.equal((await gap.collect(g0, g1)).reason, 'lease-lost,shared-database');
  assert.equal(log2.filter(l => l.startsWith('/* sh:lease */')).length, 2, 'taken again although another run holds a lease');
  const closes = () => log2.filter(l => l === 'close').length, open = closes();
  await gap.stop();
  assert.equal(closes() - open, 1, 'the lease taken again is held until stop');
  assert.equal((await quietWindow([{ snapshot: '100:100:' }, { snapshot: '100:100:' }, { snapshot: '100:100:', others: 1 }])).coverage, 'net-only', 'without runLease nothing reads leases');
});

// sqlite-snapshot against real database files (the application writes through its own connection between marks).
function sqliteApp(t) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven bg writers ')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'app.db'), db = new DatabaseSync(path);
  db.exec(`CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT); CREATE TABLE audit (n INTEGER PRIMARY KEY AUTOINCREMENT, what TEXT);
    CREATE TABLE _litestream_seq (id INTEGER PRIMARY KEY, seq INTEGER); CREATE TABLE heartbeat (at INTEGER); CREATE TABLE jobs (id INTEGER PRIMARY KEY, state TEXT);
    INSERT INTO orders VALUES ('o1', 'open'); INSERT INTO audit (what) VALUES ('seed');`);
  t.after(() => db.close());
  return { dir, path, db };
}
const sqliteWindow = async (o, between) => { const from = await o.mark(); await between(); const to = await o.mark(); return o.collect(from, to); };

test('sqlite-snapshot with an ignore list: an unlisted table that changed holds absence back; ignored tables and SQLite\'s own never do', async t => {
  const { path, db } = sqliteApp(t);
  const plain = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }] });
  await plain.start();
  assert.equal((await sqliteWindow(plain, () => db.exec("INSERT INTO audit (what) VALUES ('x')"))).coverage, 'net-only', 'no list: other tables are not read, as before');
  const o = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], platform: 'litestream', ignore: ['heartbeat'] });
  await o.start();
  // audit is AUTOINCREMENT, so sqlite_sequence changes with it; Litestream and the heartbeat are ignored.
  const noisy = await sqliteWindow(o, () => db.exec("INSERT INTO _litestream_seq VALUES (1, 1); INSERT INTO heartbeat VALUES (1); UPDATE orders SET status = 'paid'"));
  assert.deepEqual([noisy.coverage, noisy.events.map(e => `${e.operation} ${e.resource}`), noisy.background.unlisted], ['net-only', ['update orders/o1'], []]);
  const unlisted = await sqliteWindow(o, () => db.exec("INSERT INTO audit (what) VALUES ('refund sent')"));
  assert.deepEqual([unlisted.coverage, unlisted.reason, unlisted.background.unlisted], ['partial', 'unlisted-table-changed', ['audit']]);
  const created = await sqliteWindow(o, () => db.exec('CREATE TABLE outbox (id INTEGER)'));
  // A table created during the run is also a schema change against the run's baseline (./catalog.mjs).
  assert.deepEqual([created.reason, created.background.unlisted], ['schema-drift,unlisted-table-changed', ['outbox']], 'a table that appeared');
  // A run that starts after those tables exist has them in its baseline.
  db.exec('INSERT INTO outbox VALUES (9007199254740993)');
  db.exec("CREATE VIRTUAL TABLE notes USING fts5(body); INSERT INTO notes VALUES ('seed')");
  const later = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], platform: 'litestream', ignore: ['heartbeat'] });
  await later.start();
  // An integer past 2^53 reads exactly; a virtual table is not read, but its shadow tables are.
  const big = await sqliteWindow(later, () => db.exec('UPDATE outbox SET id = 9007199254740995'));
  assert.deepEqual([big.reason, big.background.unlisted], ['unlisted-table-changed', ['outbox']]);
  const fts = await sqliteWindow(later, () => db.exec("INSERT INTO notes VALUES ('refund sent')"));
  assert.equal(fts.reason, 'unlisted-table-changed');
  assert.ok(!fts.background.unlisted.includes('notes') && fts.background.unlisted.some(n => n.startsWith('notes_')), JSON.stringify(fts.background.unlisted));
  const quiet = await sqliteWindow(later, () => {});
  assert.equal(quiet.coverage, 'net-only');
  assert.throws(() => createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], ignore: ['orders'] }), /never on the ignore list/);
  assert.throws(() => createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], ignore: ['ORDERS'] }), /never on the ignore list/, 'SQLite names compare without case');
  // SQLite folds ASCII only: a table named with a Kelvin sign is not the declared kv table, and stays watched.
  db.exec('CREATE TABLE kv (k TEXT PRIMARY KEY); CREATE TABLE "\u212Av" (k TEXT)');
  const kelvin = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }, { table: 'kv', key: 'k' }], platform: 'litestream', ignore: ['heartbeat', 'audit', 'outbox'] });
  await kelvin.start();
  const k = await sqliteWindow(kelvin, () => db.exec('INSERT INTO "\u212Av" VALUES (1)'));
  assert.deepEqual([k.reason, k.background.unlisted], ['unlisted-table-changed', ['\u212Av']]);
  // A declared table stored under another case is the declared one, never an unlisted table.
  const cased = createSqliteSnapshotObserver({ path, tables: [{ table: 'ORDERS', key: 'id' }], platform: 'litestream' });
  await cased.start();
  assert.equal((await sqliteWindow(cased, () => db.exec("UPDATE orders SET status = 'x'"))).coverage, 'net-only');
});

test('sqlite-snapshot end barrier and run lease: a mark waits for its queue in the same copy; another run\'s lease refuses or fails the window', async t => {
  const { dir, path, db } = sqliteApp(t);
  const Q = { queues: [{ table: 'jobs', pending: { column: 'state', in: ['queued', 'running'] } }], drainTimeoutMs: 150, pollMs: 20 };
  const o = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], ...Q });
  await o.start();
  db.exec("INSERT INTO jobs VALUES (1, 'done')");
  const done = await sqliteWindow(o, () => {});
  assert.deepEqual([done.coverage, done.background.queues.end.pending], ['net-only', [{ queue: 'jobs', pending: 0 }]]);
  const stuck = await sqliteWindow(o, () => db.exec("INSERT INTO jobs VALUES (2, 'queued')"));
  assert.deepEqual([stuck.coverage, stuck.reason, stuck.background.queues.end.pending], ['partial', 'queue-not-drained', [{ queue: 'jobs', pending: 1 }]]);
  // The worker finishes while the mark waits: its effect is inside the window.
  const slow = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], ...Q, drainTimeoutMs: 3000 });
  await slow.start();
  db.exec("UPDATE jobs SET state = 'done'");
  const from = await slow.mark();
  db.exec("INSERT INTO jobs VALUES (3, 'queued')");
  const timer = setTimeout(() => db.exec("UPDATE orders SET status = 'refunded'; UPDATE jobs SET state = 'done' WHERE id = 3"), 120);
  const to = await slow.mark(); clearTimeout(timer);
  const late = await slow.collect(from, to);
  assert.deepEqual([late.coverage, late.events.map(e => `${e.operation} ${e.resource}`), late.background.queues.end.waitedMs > 0], ['net-only', ['update orders/o1'], true]);
  // The run lease (runKey and leaseRoot are test seams): a second run is refused; a lease that appears later fails the window.
  const leaseRoot = join(dir, 'leases');
  const a = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], runLease: true, runKey: 101, leaseRoot });
  await a.start();
  await assert.rejects(createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], runLease: true, runKey: 202, leaseRoot }).start(), /shared-database/);
  const m0 = await a.mark();
  const folder = join(leaseRoot, readdirSync(leaseRoot)[0]);
  mkdirSync(folder, { recursive: true }); writeFileSync(join(folder, `${process.pid}-303`), 'x');
  db.exec("UPDATE orders SET status = 'shared'");
  const shared = await a.collect(m0, await a.mark());
  assert.deepEqual([shared.coverage, shared.reason, shared.events.map(e => `${e.operation} ${e.resource}`)], ['partial', 'shared-database', ['update orders/o1']], 'the events stay');
  await a.stop();
  assert.deepEqual(readdirSync(folder), [`${process.pid}-303`], 'stop removes this run\'s lease file');
  // A start whose read fails releases the lease it took.
  const notDb = join(dir, 'not a database'); writeFileSync(notDb, 'plain text, not SQLite');
  await assert.rejects(createSqliteSnapshotObserver({ path: notDb, tables: [{ table: 'orders', key: 'id' }], runLease: true, runKey: 404, leaseRoot }).start());
  assert.ok(readdirSync(leaseRoot).every(f => !readdirSync(join(leaseRoot, f)).some(n => n.endsWith('-404'))), 'no lease left behind');
});
