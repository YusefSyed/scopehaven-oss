// The catalog fingerprint (./catalog.mjs): its reader, its rule and its record, then pg-snapshot against a scripted
// server and the SQLite observers against real database files (in a spaced temp folder). pg-wal's use of it is in
// pg-wal.test.mjs; the definitions a real server prints, and the data operations and reverted DDL it must tell apart, are in
// catalog.live.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { CATALOG_SCHEMA, CATALOG_KINDS, CATALOG_LIMITS, SCHEMA_DRIFT, CATALOG_UNREADABLE, MIGRATION_BETWEEN_RUNS, CATALOG_NOT_COMPARABLE, SCHEMA_CHANGED_DURING_RUN,
  catalogExclusions, pgCatalogSql, pgCatalogOf, sqliteCatalogOf, catalogReasons, catalogRecord, compareCatalogRecords, openPgCatalogSession, bracketCatalog } from './catalog.mjs';
import { resolveIgnoreList } from './ignore-lists/ignore-list.mjs';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { createSqliteSnapshotObserver, createSqliteAuditObserver } from './sqlite.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { scriptedDb, FAKE_CATALOG, USER, PASSWORD } from './fixtures/fake-postgres.mjs';
import { catalogIdentity, validCatalogIdentity, CATALOG_IDENTITY_SCHEMA, CATALOG_RECORD_SCHEMA, CATALOG_RECORD_KINDS } from '../../src/suite.mjs';

const sha = text => createHash('sha256').update(text).digest('hex');
// A server's answer to the kinds statement: each kind's definition and instance, by a short label (default "base", "v1").
const kindRows = (over = {}) => CATALOG_KINDS.postgres.map(kind => [kind, '1', sha(`${kind}:${over[kind]?.[0] ?? 'base'}`), sha(`${kind}:${over[kind]?.[0] ?? 'base'}:${over[kind]?.[1] ?? 'v1'}`)]);
const read = (over, versions = []) => pgCatalogOf({ rows: kindRows(over) }, { rows: versions });

test('pgCatalogOf: one row per kind, in order, with sha256 digests; anything else has no fingerprint', () => {
  const base = read();
  assert.equal(base.ok, true); assert.equal(base.engine, 'postgres');
  assert.deepEqual(base.kinds.map(k => k.kind), CATALOG_KINDS.postgres);
  assert.match(base.sha256, /^[0-9a-f]{64}$/); assert.match(base.instance, /^[0-9a-f]{64}$/);
  // The definition digest ignores the instance; the instance does not.
  const moved = read({ trigger: ['base', 'v2'] });
  assert.equal(moved.sha256, base.sha256); assert.notEqual(moved.instance, base.instance);
  assert.notEqual(read({ policy: ['other'] }).sha256, base.sha256);
  // A count is part of the definition digest.
  const counted = kindRows(); counted[5][1] = '2';
  assert.notEqual(pgCatalogOf({ rows: counted }, { rows: [] }).sha256, base.sha256);
  const unreadable = { ok: false, reason: CATALOG_UNREADABLE };
  assert.deepEqual(pgCatalogOf({ rows: kindRows().slice(1) }, { rows: [] }), unreadable, 'a kind missing');
  assert.deepEqual(pgCatalogOf({ rows: [kindRows()[1], kindRows()[0], ...kindRows().slice(2)] }, { rows: [] }), unreadable, 'kinds out of order');
  const bad = kindRows(); bad[3][2] = 'not-a-digest';
  assert.deepEqual(pgCatalogOf({ rows: bad }, { rows: [] }), unreadable, 'a digest that is not sha256 hex');
  assert.deepEqual(pgCatalogOf(undefined, { rows: [] }), unreadable, 'no result');
  assert.deepEqual(read({}, [['16384', '700']]), unreadable, 'a version row of the wrong width');
  assert.deepEqual(read({}, [['16384', 'x', '16384']]), unreadable, 'a version that is not a number');
  const many = Array.from({ length: CATALOG_LIMITS.versions + 1 }, (_, i) => [String(16384 + i), '700', String(16384 + i)]);
  assert.deepEqual(read({}, many), unreadable, 'more versioned rows than the limit');
  assert.equal(read({}, many.slice(1)).ok, true, 'the limit itself');
  assert.equal(read({}, [['t16500', '700', '']]).ok, true, 'a trigger kept by its enabled state: no file node');
  assert.deepEqual(read({}, [['x16500', '700', '']]), unreadable, 'an id that is neither');
});

test('catalogReasons: the definitions against the baseline at both marks, the instance and each relation\'s row between the marks', () => {
  const base = read({}, [['16384', '700', '16384']]);
  assert.deepEqual(catalogReasons(base, base, base), []);
  assert.deepEqual(catalogReasons(base, base, read({ column: ['added'] }, [['16384', '700', '16384']])), [SCHEMA_DRIFT], 'a change at the end mark');
  const changed = read({ column: ['added'] }, [['16384', '700', '16384']]);
  assert.deepEqual(catalogReasons(base, changed, changed), [SCHEMA_DRIFT], 'a window after a lasting change: its start mark already differs from the baseline');
  assert.deepEqual(catalogReasons(base, base, read({ trigger: ['base', 'v2'] }, [['16384', '700', '16384']])), [SCHEMA_DRIFT], 'changed and changed back inside the window');
  // Changed and changed back before this window: the window itself ran under the baseline's definitions.
  const past = read({ trigger: ['base', 'v2'] }, [['16384', '700', '16384']]);
  assert.deepEqual(catalogReasons(base, past, past), []);
  // A relation's own row: moved under the same file node is DDL (row-level security off and on); with a new file node, a rewrite.
  assert.deepEqual(catalogReasons(base, base, read({}, [['16384', '705', '16384']])), [SCHEMA_DRIFT], 'row moved, same file node');
  assert.deepEqual(catalogReasons(base, base, read({}, [['16384', '705', '16399']])), [], 'TRUNCATE or VACUUM FULL: a rewrite');
  assert.deepEqual(catalogReasons(base, base, read({}, [['16384', '700', '16384'], ['16390', '701', '16390']])), [], 'a relation the end mark alone has: its kind\'s instance decides');
  // A trigger kept by its enabled state (a partition's clone, an internal one): any move of its row is a change; one that
  // appears with a new partition is not.
  const trig = read({}, [['16384', '700', '16384'], ['t16500', '710', '']]);
  assert.deepEqual(catalogReasons(trig, trig, read({}, [['16384', '700', '16384'], ['t16500', '711', '']])), [SCHEMA_DRIFT], 'a clone disabled and enabled again');
  assert.deepEqual(catalogReasons(trig, trig, read({}, [['16384', '700', '16384'], ['t16500', '710', ''], ['t16501', '712', '']])), [], 'a new partition\'s clone');
  // A catalog that changed while a mark (or the baseline) was read: the bracket's two reads differ.
  const shaky = bracketCatalog(base, read({ trigger: ['base', 'v2'] }, [['16384', '700', '16384']]));
  assert.equal(shaky.stable, false); assert.equal(bracketCatalog(base, base).stable, true);
  assert.equal(bracketCatalog(base, read({}, [['16384', '705', '16399']])).stable, true, 'a rewrite during the mark is not a change');
  assert.deepEqual(catalogReasons(base, base, shaky), [SCHEMA_DRIFT]); assert.deepEqual(catalogReasons(base, shaky, base), [SCHEMA_DRIFT]);
  assert.deepEqual(catalogReasons(shaky, base, base), [SCHEMA_DRIFT], 'an unstable baseline');
  assert.deepEqual(bracketCatalog(base, { ok: false, reason: CATALOG_UNREADABLE }), { ok: false, reason: CATALOG_UNREADABLE });
  assert.deepEqual(bracketCatalog({ ok: false, reason: CATALOG_UNREADABLE }, base), { ok: false, reason: CATALOG_UNREADABLE });
  // Each mark is compared with the baseline on its own, whatever its instance says (a server whose instance digest left
  // the definitions out would otherwise hide a change at one mark).
  const odd = (sha256, instance) => ({ ok: true, sha256, instance, versions: new Map() });
  assert.deepEqual(catalogReasons(base, odd('changed', 'same'), odd(base.sha256, 'same')), [SCHEMA_DRIFT], 'the start mark alone differs');
  assert.deepEqual(catalogReasons(base, odd(base.sha256, 'same'), odd('changed', 'same')), [SCHEMA_DRIFT], 'the end mark alone differs');
  const none = { ok: false, reason: CATALOG_UNREADABLE };
  for (const [label, args] of [['no baseline', [null, base, base]], ['an unreadable baseline', [none, base, base]], ['an unreadable start mark', [base, none, base]], ['an unreadable end mark', [base, base, none]], ['a mark without one', [base, undefined, base]]])
    assert.deepEqual(catalogReasons(...args), [CATALOG_UNREADABLE], label);
});

test('catalogExclusions: the platform\'s own schemas (Postgres) and tables (SQLite) only; never a declared table or queue, never a profile entry', () => {
  const declared = [{ schema: 'public', table: 'orders' }, { schema: 'realtime', table: 'subscription' }], queues = [{ schema: '_analytics', table: 'jobs' }];
  const list = resolveIgnoreList({ engine: 'postgres', platform: 'supabase', ignore: ['public.heartbeat'], declared, queues });
  const out = catalogExclusions(list, { declared, queues });
  assert.deepEqual(out.schemas, ['_realtime', '_supavisor', 'supabase_migrations'], 'a schema holding a declared queue stays in');
  // A platform table's grants, policies and triggers are the application's concern on Postgres: table entries stay in.
  assert.deepEqual(out.tables, []);
  const profileSchema = catalogExclusions(resolveIgnoreList({ engine: 'postgres', ignore: ['scratch'] }), {});
  assert.deepEqual(profileSchema.schemas, [], 'a profile entry names application objects and stays in');
  assert.deepEqual(catalogExclusions(resolveIgnoreList({ engine: 'postgres' }), {}), { schemas: [], tables: [] });
  const lite = resolveIgnoreList({ engine: 'sqlite', platform: 'litestream', declared: [{ schema: 'main', table: 'orders' }] });
  assert.deepEqual(catalogExclusions(lite, { declared: [{ schema: 'main', table: 'orders' }], engine: 'sqlite' }).tables, ['main._litestream_lock', 'main._litestream_seq']);
  assert.deepEqual(catalogExclusions(lite, { declared: [{ schema: 'main', table: '_LITESTREAM_SEQ' }], engine: 'sqlite' }).tables, ['main._litestream_lock'], 'SQLite names compare without case');
});

test('pgCatalogSql: the exclusions reach both statements, identifiers are checked, and each statement is one statement', () => {
  const plain = pgCatalogSql(), out = pgCatalogSql({ schemas: ['_realtime'] });
  for (const x of [plain, out]) for (const s of [x.catalog, x.versions]) assert.ok(!s.includes('; ') && !s.includes(';\n') && !/;\s*$/.test(s), 'no statement separator inside');
  assert.match(plain.catalog, /^\/\* sh:dbcatalog \*\//); assert.match(plain.versions, /^\/\* sh:dbversions \*\//);
  for (const s of [out.catalog, out.versions]) assert.ok(s.includes("n.nspname NOT IN ('_realtime')"));
  assert.ok(!plain.catalog.includes('NOT IN ()') && !plain.catalog.includes('NOT IN (NULL'), 'no exclusion clause without exclusions');
  assert.equal(plain.rows, CATALOG_KINDS.postgres.length + CATALOG_LIMITS.versions + 1);
  assert.throws(() => pgCatalogSql({ schemas: ["x'; DROP"] }), /Unsupported SQL identifier/);
});

test('openPgCatalogSession: its own session with the settings pinned and a short lock wait; any error reads as no fingerprint', async () => {
  const sql = pgCatalogSql(), sent = [], answers = { kinds: kindRows(), versions: [] };
  let fail = null, closed = 0;
  const connect = async options => { sent.push(['connect', options.user]); return {
    async query(text) { sent.push(text); if (fail && fail(text)) throw Object.assign(new Error('x'), { sqlState: '55P03' }); return [{ rows: /sh:dbcatalog/.test(text) ? answers.kinds : /sh:dbversions/.test(text) ? answers.versions : [] }]; },
    close() { closed += 1; } }; };
  const session = await openPgCatalogSession(connect, { user: 'reader' }, sql, { statementTimeoutMs: 10000 });
  const fp = await session.read();
  assert.equal(fp.ok, true); assert.equal(fp.sha256, read().sha256);
  const settings = sent[1];
  for (const s of ['SET search_path = pg_catalog', 'SET quote_all_identifiers = off', 'SET standard_conforming_strings = on', 'SET jit = off', `SET lock_timeout = ${CATALOG_LIMITS.lockTimeoutMs}`, 'SET statement_timeout = 10000']) assert.ok(settings.includes(s), s);
  fail = text => /sh:dbversions/.test(text);
  assert.deepEqual(await session.read(), { ok: false, reason: CATALOG_UNREADABLE }, 'a lock not granted in time');
  session.close(); session.close();
  assert.equal(closed, 1);
  assert.deepEqual(await session.read(), { ok: false, reason: CATALOG_UNREADABLE }, 'after close');
  const refused = await openPgCatalogSession(async () => { throw new Error('connect-failed'); }, {}, sql, { statementTimeoutMs: 10000 });
  assert.deepEqual(await refused.read(), { ok: false, reason: CATALOG_UNREADABLE }, 'a session that never opened');
  const short = await openPgCatalogSession(connect, { user: 'r' }, sql, { statementTimeoutMs: 500 });
  assert.ok(sent.at(-1).includes('SET lock_timeout = 500'), 'never longer than the statement timeout'); short.close();
});

test('catalogRecord: counts and digests only, the baseline\'s and the last mark\'s, and whether the run changed', () => {
  const base = read(), record = catalogRecord({ engine: 'postgres', baseline: base, latest: read({ index: ['added'] }), drifted: true, excluded: { schemas: ['_realtime'], tables: [] } });
  assert.deepEqual(Object.keys(record).sort(), ['changedDuringRun', 'engine', 'excluded', 'final', 'kinds', 'schema', 'sha256']);
  assert.equal(record.schema, CATALOG_SCHEMA); assert.equal(record.sha256, base.sha256); assert.equal(record.changedDuringRun, true);
  assert.notEqual(record.final, base.sha256);
  assert.deepEqual(record.kinds.policy, { objects: 1, sha256: base.kinds[5].sha256 });
  assert.ok(!JSON.stringify(record).includes(base.instance), 'the instance (oids, row versions) is never recorded');
  const unread = catalogRecord({ engine: 'postgres', baseline: { ok: false, reason: CATALOG_UNREADABLE }, latest: null, drifted: false });
  assert.deepEqual([unread.sha256, unread.reason, unread.final, unread.kinds], [null, CATALOG_UNREADABLE, null, undefined]);
  assert.equal(catalogRecord({ engine: 'sqlite', baseline: null }).reason, CATALOG_UNREADABLE, 'no baseline');
});

test('compareCatalogRecords: a retest across changed definitions is migration-between-runs, naming the kinds; anything it cannot compare says so', () => {
  const rec = (over, extra = {}) => ({ instanceId: 'db', ...catalogRecord({ engine: 'postgres', baseline: read(over), latest: read(over), drifted: false, excluded: { schemas: [], tables: [] } }), ...extra });
  assert.deepEqual(compareCatalogRecords(undefined, []), { state: 'not-recorded', flags: [], duringRun: [] }, 'runs from before the catalog fingerprint read as before');
  assert.deepEqual(compareCatalogRecords([rec()], [rec()]).state, 'unchanged');
  assert.deepEqual(compareCatalogRecords([rec()], [rec()]).flags, []);
  const migrated = compareCatalogRecords([rec()], [rec({ policy: ['added'], function: ['replaced'] })]);
  assert.deepEqual([migrated.state, migrated.flags, migrated.observers], ['changed', [MIGRATION_BETWEEN_RUNS], [{ instanceId: 'db', kinds: ['function', 'policy'] }]]);
  const counted = rec(); counted.kinds = { ...counted.kinds, policy: { ...counted.kinds.policy, objects: 2 } }; counted.sha256 = 'f'.repeat(64);
  assert.deepEqual(compareCatalogRecords([rec()], [counted]).observers, [{ instanceId: 'db', kinds: ['policy'] }], 'a count is a change of that kind');
  for (const [label, a, b, reason] of [['one run only', [rec()], undefined, 'one-run-only'], ['another observer', [rec()], [rec({}, { instanceId: 'db2' })], 'observers-differ'],
    ['an observer twice', [rec(), rec()], [rec(), rec()], 'observers-differ'], ['another engine', [rec()], [rec({}, { engine: 'sqlite' })], 'record-differs'],
    ['another record version', [rec()], [rec({}, { schema: 'scopehaven-catalog/0' })], 'record-differs'], ['other exclusions', [rec()], [rec({}, { excluded: { schemas: ['_realtime'], tables: [] } })], 'exclusions-differ'],
    ['an unreadable baseline', [rec()], [rec({}, { sha256: null })], 'baseline-unreadable']]) {
    const c = compareCatalogRecords(a, b);
    assert.deepEqual([c.state, c.reason, c.flags], ['not-comparable', reason, [CATALOG_NOT_COMPARABLE]], label);
  }
  const during = compareCatalogRecords([rec({}, { changedDuringRun: true })], [rec()]);
  assert.deepEqual([during.state, during.flags, during.duringRun], ['unchanged', [SCHEMA_CHANGED_DURING_RUN], ['baseline']]);
});

test('the run\'s catalog identity (src/catalog-identity.mjs, re-exported by src/suite.mjs): each observer\'s record by instance and one digest over their starts; anything else is refused', () => {
  assert.equal(CATALOG_RECORD_SCHEMA, CATALOG_SCHEMA, 'the identity names the observers\' own record schema');
  assert.deepEqual(CATALOG_RECORD_KINDS, CATALOG_KINDS, 'and their kinds, per engine');
  const rec = (instanceId, over, extra = {}) => ({ instanceId, ...catalogRecord({ engine: 'postgres', baseline: read(over), latest: read(over), drifted: false, excluded: { schemas: [], tables: [] } }), ...extra });
  const ids = ['pg-snapshot-db', 'pg-wal-wal'];
  assert.equal(catalogIdentity([]), null); assert.equal(catalogIdentity(undefined), null);
  const a = catalogIdentity([rec('pg-wal-wal'), rec('pg-snapshot-db')]);
  assert.equal(a.schema, CATALOG_IDENTITY_SCHEMA); assert.deepEqual(a.observers.map(r => r.instanceId), ids, 'sorted by instance');
  assert.equal(validCatalogIdentity(a, ids), true);
  assert.equal(catalogIdentity([rec('pg-snapshot-db'), rec('pg-wal-wal')]).sha256, a.sha256, 'in any order');
  assert.notEqual(catalogIdentity([rec('pg-snapshot-db', { policy: ['added'] }), rec('pg-wal-wal')]).sha256, a.sha256, 'another schema, another identity');
  assert.notEqual(catalogIdentity([rec('pg-snapshot-db', {}, { excluded: { schemas: ['_realtime'], tables: [] } }), rec('pg-wal-wal')]).sha256, a.sha256, 'other exclusions, another identity');
  assert.equal(catalogIdentity([rec('pg-snapshot-db'), rec('pg-wal-wal', {}, { changedDuringRun: true })]).sha256, a.sha256, 'the start decides, not the run\'s own drift');
  const unreadRecord = { instanceId: 'pg-wal-wal', ...catalogRecord({ engine: 'postgres', baseline: { ok: false, reason: CATALOG_UNREADABLE }, latest: null, drifted: false, excluded: { schemas: [], tables: [] } }) };
  const unread = catalogIdentity([rec('pg-snapshot-db'), unreadRecord]);
  assert.equal(unread.sha256, null, 'an unknown start is never the same schema as another unknown one');
  assert.equal(validCatalogIdentity(unread, ids), true, 'a record without a baseline names why');
  const lite = { instanceId: 'sqlite-snapshot-db', ...catalogRecord({ engine: 'sqlite', baseline: { ok: true, sha256: 'a'.repeat(64), kinds: CATALOG_KINDS.sqlite.map(kind => ({ kind, objects: 1, sha256: 'b'.repeat(64) })) },
    latest: null, drifted: false, excluded: { schemas: [], tables: ['main._litestream_lock', 'main._litestream_seq'] } }) };
  assert.equal(validCatalogIdentity(catalogIdentity([lite]), ['sqlite-snapshot-db']), true, 'SQLite\'s table exclusions');
  const pgKinds = Object.fromEntries(CATALOG_KINDS.postgres.map(k => [k, { objects: 1, sha256: 'b'.repeat(64) }]));
  const bad = [
    ['another digest', { ...a, sha256: 'f'.repeat(64) }], ['an undeclared observer', catalogIdentity([rec('pg-snapshot-other')])], ['an observer twice', { ...a, observers: [a.observers[0], a.observers[0]] }],
    ['out of order', { ...a, observers: [...a.observers].reverse() }], ['another record schema', catalogIdentity([rec('pg-wal-wal', {}, { schema: 'scopehaven-catalog/0' })])],
    ['an unknown key', { ...a, extra: 1 }], ['a record key', catalogIdentity([rec('pg-wal-wal', {}, { names: ['orders'] })])], ['a kind that is not a digest', catalogIdentity([rec('pg-wal-wal', {}, { kinds: { ...pgKinds, policy: { objects: 1, sha256: 'x' } } })])],
    ['a kind missing', catalogIdentity([rec('pg-wal-wal', {}, { kinds: Object.fromEntries(Object.entries(pgKinds).slice(1)) })])], ['no kinds', catalogIdentity([rec('pg-wal-wal', {}, { kinds: {} })])],
    ['another engine\'s kinds', catalogIdentity([{ ...lite, instanceId: 'pg-wal-wal', engine: 'postgres', excluded: { schemas: [], tables: [] } }])],
    ['table exclusions on Postgres', catalogIdentity([rec('pg-wal-wal', {}, { excluded: { schemas: [], tables: ['auth.sessions'] } })])],
    ['an unreadable start that drifted', catalogIdentity([{ ...unreadRecord, changedDuringRun: true }])],
    ['a baseline and a reason', catalogIdentity([rec('pg-wal-wal', {}, { reason: 'catalog-unreadable' })])], ['another engine', catalogIdentity([rec('pg-wal-wal', {}, { engine: 'mysql' })])],
    ['no observers', { schema: CATALOG_IDENTITY_SCHEMA, sha256: 'f'.repeat(64), observers: [] }], ['not an identity', null]];
  for (const [label, x] of bad) assert.equal(validCatalogIdentity(x, [...ids, 'sqlite-snapshot-db']), false, label);
});

// SQLite, against real files in a folder whose name has spaces.
function sqliteDir(t) { const dir = mkdtempSync(join(tmpdir(), 'scopehaven catalog ')); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; }
const APP = `CREATE TABLE orders (id TEXT PRIMARY KEY, status TEXT UNIQUE, n INTEGER); CREATE INDEX orders_n ON orders (n);
  CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, what TEXT, target TEXT);
  CREATE TRIGGER audit_orders AFTER UPDATE ON orders BEGIN INSERT INTO audit (who, what, target) VALUES ('app', 'order.update', 'orders/' || NEW.id); END;
  CREATE VIEW open_orders AS SELECT id FROM orders WHERE status = 'open';`;

test('sqliteCatalogOf: the same statements read the same; DDL, user_version and a change made and reverted are changes; data, a later ANALYZE and the platform\'s tables are not', t => {
  const dir = sqliteDir(t), open = name => { const db = new DatabaseSync(join(dir, name)); t.after(() => db.close()); return db; };
  const a = open('a.db'), b = open('b.db');
  a.exec(APP); b.exec(APP);
  const x = sqliteCatalogOf(a);
  assert.equal(x.ok, true); assert.deepEqual(x.kinds.map(k => [k.kind, k.objects]), [['table', 2], ['index', 1], ['view', 1], ['trigger', 1], ['pragma', 2]]);
  assert.equal(sqliteCatalogOf(b).sha256, x.sha256, 'two files built by the same statements');
  a.exec("INSERT INTO orders VALUES ('o1', 'open', 1); UPDATE orders SET n = 2; ANALYZE");
  const analyzed = sqliteCatalogOf(a);
  assert.equal(analyzed.sha256, x.sha256, 'data and SQLite\'s own statistics table are not in the definitions');
  a.exec("INSERT INTO orders VALUES ('o2', 'paid', 3); ANALYZE; DELETE FROM orders WHERE id = 'o2'");
  assert.deepEqual(catalogReasons(analyzed, analyzed, sqliteCatalogOf(a)), [], 'a later ANALYZE does not move the cookie');
  a.exec('CREATE INDEX tmp ON orders (status); DROP INDEX tmp');
  const reverted = sqliteCatalogOf(a);
  assert.equal(reverted.sha256, x.sha256); assert.deepEqual(catalogReasons(x, analyzed, reverted), [SCHEMA_DRIFT], 'created and dropped: the cookie moved');
  for (const ddl of ['ALTER TABLE orders ADD COLUMN note TEXT', 'DROP TRIGGER audit_orders', 'PRAGMA user_version = 3', 'PRAGMA application_id = 7', 'DROP VIEW open_orders', 'CREATE TABLE more (x)']) {
    const db = open(`${createHash('md5').update(ddl).digest('hex')}.db`);
    db.exec(APP); const before = sqliteCatalogOf(db);
    db.exec(ddl);
    assert.deepEqual(catalogReasons(before, before, sqliteCatalogOf(db)), [SCHEMA_DRIFT], ddl);
  }
  // A platform's tables (Litestream's) are left out with their indexes and triggers.
  const lite = open('lite.db'); lite.exec(APP);
  const plainBase = sqliteCatalogOf(lite), liteBase = sqliteCatalogOf(lite, { tables: ['main._litestream_seq'] });
  lite.exec('CREATE TABLE _litestream_seq (id INTEGER PRIMARY KEY, seq INTEGER); CREATE INDEX lseq ON _litestream_seq (seq)');
  assert.equal(sqliteCatalogOf(lite, { tables: ['main._litestream_seq'] }).sha256, liteBase.sha256);
  assert.notEqual(sqliteCatalogOf(lite).sha256, plainBase.sha256, 'without the exclusion it is a change');
  assert.deepEqual(sqliteCatalogOf({ prepare() { throw new Error('closed'); } }), { ok: false, reason: CATALOG_UNREADABLE }, 'a copy that cannot be read');
});

test('sqlite-snapshot: a schema change during the run reads schema-drift on its window and every later one, events kept; the record says so', async t => {
  const dir = sqliteDir(t), path = join(dir, 'app.db'), db = new DatabaseSync(path);
  t.after(() => db.close());
  db.exec(`${APP} INSERT INTO orders VALUES ('o1', 'open', 1)`);
  const o = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }] });
  await o.start();
  const step = async fn => { const from = await o.mark(); fn(); return collectWindow(o, from, await o.mark()); };
  const quiet = await step(() => db.exec("UPDATE orders SET n = 2 WHERE id = 'o1'"));
  assert.deepEqual([quiet.coverage, quiet.reason], ['net-only', 'net-change-between-snapshots']);
  assert.equal(o.catalog().changedDuringRun, false);
  const migrated = await step(() => db.exec("ALTER TABLE orders ADD COLUMN note TEXT; UPDATE orders SET n = 3 WHERE id = 'o1'"));
  assert.deepEqual([migrated.coverage, migrated.reason], ['partial', SCHEMA_DRIFT]);
  assert.deepEqual(migrated.events.map(e => `${e.operation} ${e.resource}`), ['update orders/o1'], 'the events stay, so a fail stays a fail');
  const none = { kind: 'effect.none', select: { source: 'sql-snapshot', name: 'orders', operation: 'update' } };
  assert.equal(evaluateEffectAssertion(none, [migrated]).verdict, 'fail');
  const later = await step(() => {});
  assert.deepEqual([later.coverage, later.reason], ['partial', SCHEMA_DRIFT], 'a later window still differs from the baseline');
  const record = o.catalog();
  assert.equal(record.engine, 'sqlite'); assert.equal(record.changedDuringRun, true); assert.notEqual(record.final, record.sha256);
  // A run that starts after the migration has it in its baseline.
  const next = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }] });
  await next.start();
  const f = await next.mark(), w = await collectWindow(next, f, await next.mark());
  assert.equal(w.coverage, 'net-only'); assert.equal(next.catalog().sha256, record.final);
});

test('sqlite-snapshot: the baseline is start()\'s own reading, so a migration between start() and the first mark already reads schema-drift', async t => {
  const dir = sqliteDir(t), path = join(dir, 'app.db'), db = new DatabaseSync(path);
  t.after(() => db.close());
  db.exec(APP);
  const o = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }] });
  await o.start();
  db.exec('ALTER TABLE orders ADD COLUMN note TEXT');
  const w = await collectWindow(o, await o.mark(), await o.mark());
  assert.deepEqual([w.coverage, w.reason], ['partial', SCHEMA_DRIFT]);
  const audit = createSqliteAuditObserver({ path, audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what' } });
  await audit.start();
  db.exec('DROP VIEW open_orders');
  const a = await collectWindow(audit, await audit.mark(), await audit.mark());
  assert.deepEqual([a.coverage, a.reason], ['partial', SCHEMA_DRIFT]);
});

test('sqlite-snapshot: without start() the first mark is the baseline; a platform\'s table created during the run moves the cookie in its own window only', async t => {
  const dir = sqliteDir(t), path = join(dir, 'app.db'), db = new DatabaseSync(path);
  t.after(() => db.close());
  db.exec(APP);
  const o = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], platform: 'litestream' });
  const from = await o.mark();
  db.exec('CREATE TABLE _litestream_seq (id INTEGER PRIMARY KEY, seq INTEGER); INSERT INTO _litestream_seq VALUES (1, 1)');
  // The cookie is the whole database's: the window it moved in cannot tell this from a change made and reverted.
  const w = await collectWindow(o, from, await o.mark());
  assert.deepEqual([w.coverage, w.reason], ['partial', SCHEMA_DRIFT]);
  // Later windows: the definitions, without the platform's table, are still the baseline's.
  const h = await o.mark(); db.exec('INSERT INTO _litestream_seq VALUES (2, 2)');
  const after = await collectWindow(o, h, await o.mark());
  assert.deepEqual([after.coverage, after.reason], ['net-only', 'net-change-between-snapshots']);
  assert.deepEqual(o.catalog().excluded, { schemas: [], tables: ['main._litestream_lock', 'main._litestream_seq'] });
  const g = await o.mark(); db.exec('CREATE TABLE outbox (id INTEGER)');
  assert.equal((await collectWindow(o, g, await o.mark())).reason, `${SCHEMA_DRIFT},unlisted-table-changed`);
});

test('sqlite audit table: a dropped audit trigger is a schema change, so the quiet audit table after it never reads complete', async t => {
  const dir = sqliteDir(t), path = join(dir, 'app.db'), db = new DatabaseSync(path);
  t.after(() => db.close());
  db.exec(`${APP} INSERT INTO orders VALUES ('o1', 'open', 1)`);
  const audit = createSqliteAuditObserver({ path, principals: ['app'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what', resourceColumn: 'target', actions: { 'order.update': 'update' } } });
  await audit.start();
  const a0 = await audit.mark(); db.exec("UPDATE orders SET n = 2 WHERE id = 'o1'");
  const seen = await collectWindow(audit, a0, await audit.mark());
  assert.deepEqual([seen.coverage, seen.events.length], ['complete', 1]);
  const a1 = await audit.mark(); db.exec("UPDATE orders SET n = 3 WHERE id = 'o1'; DROP TRIGGER audit_orders; UPDATE orders SET n = 4 WHERE id = 'o1'");
  const dropped = await collectWindow(audit, a1, await audit.mark());
  assert.deepEqual([dropped.coverage, dropped.reason, dropped.events.length], ['partial', SCHEMA_DRIFT, 1], 'its events stay');
  const a2 = await audit.mark(); db.exec("UPDATE orders SET n = 5 WHERE id = 'o1'");
  const silent = await collectWindow(audit, a2, await audit.mark());
  assert.deepEqual([silent.coverage, silent.reason, silent.events.length], ['partial', SCHEMA_DRIFT, 0], 'no audit row, and no complete window either');
  assert.equal(audit.catalog().changedDuringRun, true);
});

// pg-snapshot against the scripted server: each state's catalog { kinds, versions } (FAKE_CATALOG when absent).
const env = { SCOPEHAVEN_TARGET_DB_READER: `${USER}:${PASSWORD}` };
const observerOn = server => createPgSnapshotObserver({ env, host: '127.0.0.1', port: server.port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables: [{ table: 'Chat', key: 'id' }], watchedResources: ['Chat/c1'] });
const state = (catalog, rows = [['c1', '700', 'h1']], snapshot = '800:800:') => ({ snapshot, tables: { Chat: rows }, ...(catalog ? { catalog } : {}) });

test('pg-snapshot: each mark reads the catalog on its own session around the transaction; a change against start()\'s baseline reads schema-drift and keeps the events', async t => {
  const base = { kinds: kindRows(), versions: [['16384', '700', '16384']] }, migrated = { kinds: kindRows({ column: ['added'] }), versions: [['16384', '701', '16384']] };
  const log = [], server = await scriptedDb(t, [state(base), state(base), state(base), state(base), state(migrated, [['c1', '805', 'h2']], '806:806:'), state(migrated)], log);
  const o = observerOn(server);
  await o.start();
  const first = await collectWindow(o, await o.mark(), await o.mark());
  assert.deepEqual([first.coverage, first.reason], ['net-only', 'net-change-between-snapshots']);
  // The catalog is read on its own session, before the mark's BEGIN and after its COMMIT, never inside its transaction
  // (printing a view or policy locks what it names), with the settings the printed definitions depend on.
  const begin = log.lastIndexOf(log.filter(s => /^BEGIN/.test(s)).at(-1)), commit = log.indexOf('COMMIT', begin);
  assert.ok(!log.slice(begin, commit).some(s => /sh:db(catalog|versions)/.test(s)), 'nothing of the catalog inside the transaction');
  const reads = log.flatMap((s, i) => (/^\/\* sh:dbcatalog \*\//.test(s) ? [i] : []));
  assert.ok(reads.some(i => i < begin) && reads.some(i => i > commit), 'one read before the mark, one after');
  for (const setting of ['SET search_path = pg_catalog', 'SET quote_all_identifiers = off', 'SET standard_conforming_strings = on', `SET lock_timeout = ${CATALOG_LIMITS.lockTimeoutMs}`]) assert.ok(log.includes(setting), setting);
  const from = await o.mark(), drift = await collectWindow(o, from, await o.mark());
  assert.deepEqual([drift.coverage, drift.reason], ['partial', SCHEMA_DRIFT]);
  assert.deepEqual(drift.events.map(e => `${e.operation} ${e.resource}`), ['update Chat/c1'], 'the update stays an event');
  const none = { kind: 'effect.none', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', resource: 'Chat/c1' } };
  assert.equal(evaluateEffectAssertion(none, [drift]).verdict, 'fail', 'a fail stays a fail');
  const record = o.catalog();
  assert.equal(record.sha256, pgCatalogOf({ rows: base.kinds }, { rows: [] }).sha256);
  assert.equal(record.final, pgCatalogOf({ rows: migrated.kinds }, { rows: [] }).sha256);
  assert.equal(record.changedDuringRun, true);
});

test('pg-snapshot: a catalog changed and changed back between two marks reads schema-drift; a rewrite does not; an unreadable one reads catalog-unreadable', async t => {
  const v = (xmin, node) => [['16384', xmin, node]];
  const windows = async (...pairs) => {
    const server = await scriptedDb(t, [state({ kinds: kindRows(), versions: v('700', '16384') }), ...pairs.flat().map(c => state(c))]);
    const o = observerOn(server); await o.start();
    const out = [];
    for (let i = 0; i < pairs.length; i++) { const from = await o.mark(); out.push(await collectWindow(o, from, await o.mark())); }
    return out;
  };
  const base = { kinds: kindRows(), versions: v('700', '16384') };
  const [instance, rls, rewrite, unreadable] = await windows([base, { kinds: kindRows({ trigger: ['base', 'v2'] }), versions: v('700', '16384') }], [base, { kinds: kindRows(), versions: v('702', '16384') }],
    [base, { kinds: kindRows(), versions: v('703', '16391') }], [base, { kinds: kindRows().slice(1), versions: [] }]);
  assert.deepEqual([instance.coverage, instance.reason], ['partial', SCHEMA_DRIFT], 'a trigger disabled and enabled again');
  assert.deepEqual([rls.coverage, rls.reason], ['partial', SCHEMA_DRIFT], 'row-level security switched off and on');
  assert.deepEqual([rewrite.coverage, rewrite.reason], ['net-only', 'net-change-between-snapshots'], 'TRUNCATE or VACUUM FULL');
  assert.deepEqual([unreadable.coverage, unreadable.reason], ['partial', CATALOG_UNREADABLE]);
});

test('pg-snapshot: the baseline is start()\'s own reading, so a migration between start() and the first mark already reads schema-drift', async t => {
  const base = { kinds: kindRows(), versions: [] }, migrated = { kinds: kindRows({ function: ['replaced'] }), versions: [] };
  const server = await scriptedDb(t, [state(base), state(migrated), state(migrated)]);
  const o = observerOn(server);
  await o.start();
  const w = await collectWindow(o, await o.mark(), await o.mark());
  assert.deepEqual([w.coverage, w.reason], ['partial', SCHEMA_DRIFT]);
});

test('pg-snapshot: a catalog changed while a mark was read (between its two catalog reads) reads schema-drift', async t => {
  const base = { kinds: kindRows(), versions: [] }, moved = { kinds: kindRows({ policy: ['base', 'v2'] }), versions: [] };
  const server = await scriptedDb(t, [state(base), state(base), { ...state(base), catalogAfter: moved }, state(moved)]);
  const o = observerOn(server);
  await o.start();
  const w = await collectWindow(o, await o.mark(), await o.mark());
  assert.deepEqual([w.coverage, w.reason], ['partial', SCHEMA_DRIFT]);
});

test('pg-snapshot: the baseline is the latest read before the first mark, tried again when it does not read; a start without one is refused', async t => {
  const bad = { kinds: kindRows().slice(1), versions: [] }, base = { kinds: kindRows(), versions: [] };
  // start(): the read before its mark does not read (so the one after is skipped), nor does the first retry; the second does.
  const retried = await scriptedDb(t, [state(bad), state(base), state(base), state(base)]);
  const o = observerOn(retried);
  await o.start();
  assert.equal(o.catalog().sha256, pgCatalogOf({ rows: base.kinds }, { rows: [] }).sha256);
  const refused = await scriptedDb(t, [state(bad), state(bad), state(bad), state(bad), state(bad)]);
  await assert.rejects(observerOn(refused).start(), /catalog-unreadable at start/);
});

test('pg-snapshot: marked without start(), the first mark is the baseline; the default fake catalog never drifts', async t => {
  const migrated = { kinds: kindRows({ policy: ['dropped'] }), versions: [] };
  const server = await scriptedDb(t, [state(), state(), state(migrated)]);
  const o = observerOn(server);
  const a = await o.mark(), b = await o.mark(), c = await o.mark();
  assert.equal((await collectWindow(o, a, b)).coverage, 'net-only');
  assert.equal((await collectWindow(o, b, c)).reason, SCHEMA_DRIFT);
  assert.equal(o.catalog().sha256, pgCatalogOf({ rows: FAKE_CATALOG.kinds }, { rows: [] }).sha256);
});
