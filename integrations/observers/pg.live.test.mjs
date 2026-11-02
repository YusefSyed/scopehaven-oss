// pg-snapshot against a real PostgreSQL (13+). Skipped unless SCOPEHAVEN_PG_LIVE
// names a disposable test database as "user:password@127.0.0.1:port/database"
// for a role that may create tables and roles (for example the practice
// Postgres). Each run creates its own table and two roles and drops them after.
// Covers what a scripted server cannot: VACUUM and VACUUM FREEZE, row locks,
// HOT updates, a transaction spanning the start mark, a transaction in flight
// at the end mark, a write reverted within the window, a role without SELECT,
// an idle (quiescent) window, partitions and inheritance children, descendant
// shapes (temporary child, pending detach, duplicated key, detach), DDL between a mark's snapshot and its scan,
// a rewrite between marks, a child joining during the lock wait, renamed keys, columns and encodings, and read-back (each type's
// text output read as its canonical value, refused types, and a value written wrong by a real UPDATE).
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { pgConnect } from './pg-wire.mjs';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { judgeReadBack } from '../../src/pg-readback.mjs';

const live = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(process.env.SCOPEHAVEN_PG_LIVE ?? '');
const skip = live ? false : 'set SCOPEHAVEN_PG_LIVE=user:password@127.0.0.1:port/db (a disposable test database) to run';

async function fixture(t) {
  const [, adminUser, adminPassword, port, database] = live;
  const connect = (user, password) => pgConnect({ host: '127.0.0.1', port: Number(port), database, user, password });
  const admin = await connect(adminUser, adminPassword), other = await connect(adminUser, adminPassword);
  const suffix = randomBytes(4).toString('hex'), table = `sh_obs_${suffix}`, reader = `sh_reader_${suffix}`, noread = `sh_noread_${suffix}`;
  const readerPass = randomBytes(12).toString('base64url'), noreadPass = randomBytes(12).toString('base64url');
  await admin.query(`CREATE TABLE ${table} (id text PRIMARY KEY, v text, n int) WITH (fillfactor = 50); INSERT INTO ${table} VALUES ('a', 'x', 1), ('b', 'y', 2), ('c', 'z', 3)`);
  await admin.query(`CREATE ROLE ${reader} LOGIN PASSWORD '${readerPass}'; GRANT SELECT ON ${table} TO ${reader}; CREATE ROLE ${noread} LOGIN PASSWORD '${noreadPass}'`);
  t.after(async () => {
    try {
      try { await other.query('ROLLBACK'); } catch {}
      // Dependent views and foreign tables go with the table; the roles' grants go with DROP OWNED.
      await admin.query(`DROP TABLE IF EXISTS ${table} CASCADE; DROP OWNED BY ${reader}, ${noread}; DROP ROLE IF EXISTS ${reader}; DROP ROLE IF EXISTS ${noread}`);
    } finally { admin.close(); other.close(); }
  });
  const observer = (user, password) => createPgSnapshotObserver({ env: { SCOPEHAVEN_TARGET_PG_READER: `${user}:${password}` }, host: '127.0.0.1', port: Number(port), database,
    credentialEnv: 'SCOPEHAVEN_TARGET_PG_READER', tables: [{ table, key: 'id' }] });
  const o = createPgSnapshotObserver({ env: { SCOPEHAVEN_TARGET_PG_READER: `${reader}:${readerPass}` }, host: '127.0.0.1', port: Number(port), database,
    credentialEnv: 'SCOPEHAVEN_TARGET_PG_READER', tables: [{ table, key: 'id' }], watchedResources: ['a', 'b', 'c'].map(id => `${table}/${id}`) });
  const window = async between => { const from = await o.mark(); await between(); const to = await o.mark(); return collectWindow(o, from, to); };
  const none = id => ({ kind: 'effect.none', select: { source: 'sql-snapshot', name: table, operation: 'update', resource: `${table}/${id}` } });
  const readerOn = (relation, extra = {}) => createPgSnapshotObserver({ env: { SCOPEHAVEN_TARGET_PG_READER: `${reader}:${readerPass}` }, host: '127.0.0.1', port: Number(port), database,
    credentialEnv: 'SCOPEHAVEN_TARGET_PG_READER', tables: [{ table: relation, key: 'id' }], watchedResources: [`${relation}/a`], ...extra });
  return { admin, other, table, reader, suffix, window, none, readerOn, noReader: observer(noread, noreadPass) };
}

test('live: VACUUM and VACUUM FREEZE are not updates (xmin stable, or ambiguous; never an update event)', { skip }, async t => {
  const f = await fixture(t);
  const vacuumed = await f.window(() => f.admin.query(`VACUUM ${f.table}`));
  assert.equal(vacuumed.events.length, 0); assert.equal(evaluateEffectAssertion(f.none('a'), [vacuumed]).verdict, 'pass');
  const frozen = await f.window(() => f.admin.query(`VACUUM (FREEZE) ${f.table}`));
  assert.equal(frozen.events.length, 0, 'freezing never reads as an update');
  assert.notEqual(evaluateEffectAssertion(f.none('a'), [frozen]).verdict, 'fail');
});

test('live: row locks (SELECT FOR UPDATE / FOR SHARE) change xmax, not xmin: not updates', { skip }, async t => {
  const f = await fixture(t);
  const locked = await f.window(async () => { await f.other.query(`BEGIN; SELECT * FROM ${f.table} WHERE id = 'a' FOR UPDATE; SELECT * FROM ${f.table} WHERE id = 'b' FOR SHARE; COMMIT`); });
  assert.equal(locked.events.length, 0); assert.equal(locked.coverage, 'net-only');
  assert.equal(evaluateEffectAssertion(f.none('a'), [locked]).verdict, 'pass');
});

test('live: HOT updates, no-op updates and a write reverted within the window are all updates', { skip }, async t => {
  const f = await fixture(t);
  const hot = await f.window(() => f.admin.query(`UPDATE ${f.table} SET n = n + 1 WHERE id = 'a'`)); // non-indexed column, fillfactor 50: HOT
  assert.equal(evaluateEffectAssertion(f.none('a'), [hot]).verdict, 'fail');
  const noop = await f.window(() => f.admin.query(`UPDATE ${f.table} SET v = v WHERE id = 'b'`));
  assert.equal(evaluateEffectAssertion(f.none('b'), [noop]).verdict, 'fail');
  const reverted = await f.window(async () => { await f.admin.query(`UPDATE ${f.table} SET v = 'changed' WHERE id = 'c'`); await f.admin.query(`UPDATE ${f.table} SET v = 'z' WHERE id = 'c'`); });
  assert.equal(evaluateEffectAssertion(f.none('c'), [reverted]).verdict, 'fail', 'same content, new row version');
  assert.equal(evaluateEffectAssertion(f.none('a'), [reverted]).verdict, 'pass');
});

test('live: a transaction open across the start mark that commits inside the window is seen; one open at the end mark makes it partial', { skip }, async t => {
  const f = await fixture(t);
  await f.other.query(`BEGIN; UPDATE ${f.table} SET v = 'spanning' WHERE id = 'a'`);
  const spanning = await f.window(() => f.other.query('COMMIT'));
  assert.equal(spanning.coverage, 'net-only'); assert.equal(evaluateEffectAssertion(f.none('a'), [spanning]).verdict, 'fail');
  const inflight = await f.window(() => f.other.query(`BEGIN; UPDATE ${f.table} SET v = 'pending' WHERE id = 'b'`));
  assert.deepEqual([inflight.coverage, inflight.reason], ['partial', 'transaction-in-flight-at-window-end']);
  assert.notEqual(evaluateEffectAssertion(f.none('b'), [inflight]).verdict, 'pass');
  await f.other.query('ROLLBACK');
});

test('live: a role without SELECT on the table fails the window', { skip }, async t => {
  const f = await fixture(t);
  const from = await f.noReader.mark(), to = await f.noReader.mark();
  const w = await collectWindow(f.noReader, from, to);
  assert.deepEqual([w.coverage, w.reason], ['failed', 'permission-denied']);
});

test('live: with row-level security on the table, the mark fails instead of reading only the policy\'s rows', { skip }, async t => {
  const f = await fixture(t);
  await f.admin.query(`ALTER TABLE ${f.table} ENABLE ROW LEVEL SECURITY; CREATE POLICY only_a ON ${f.table} FOR SELECT TO ${f.reader} USING (id = 'a')`);
  const o = f.readerOn(f.table);
  const from = await o.mark(), to = await o.mark();
  const w = await collectWindow(o, from, to);
  assert.deepEqual([w.coverage, w.reason], ['failed', 'permission-denied']);
});

test('live: a view and a foreign table are refused before any row is read', { skip }, async t => {
  const f = await fixture(t);
  await f.admin.query(`CREATE VIEW ${f.table}_v AS SELECT * FROM ${f.table}; GRANT SELECT ON ${f.table}_v TO ${f.reader}`);
  const view = f.readerOn(`${f.table}_v`);
  const vm = await view.mark();
  assert.deepEqual([(await view.collect(vm, vm)).coverage, (await view.collect(vm, vm)).reason], ['failed', 'relation-not-heap-table']);
  // The extension is created only if absent, and then dropped again after the test.
  const existed = (await f.admin.query("SELECT count(*)::text FROM pg_extension WHERE extname = 'postgres_fdw'"))[0].rows[0][0] === '1';
  let fdw = true;
  try { if (!existed) await f.admin.query('CREATE EXTENSION postgres_fdw'); } catch { fdw = false; }
  if (!fdw) { t.diagnostic('postgres_fdw is not available on this server: the foreign-table case is not run'); return; }
  const server = `sh_fdw_${f.suffix}`;
  // Cleaned up here, while the fixture's admin connection is still open.
  try {
    await f.admin.query(`CREATE SERVER ${server} FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host '127.0.0.1', dbname 'none'); CREATE FOREIGN TABLE ${f.table}_f (id text, v text) SERVER ${server}; GRANT SELECT ON ${f.table}_f TO ${f.reader}`);
    const foreign = f.readerOn(`${f.table}_f`);
    const fm = await foreign.mark();
    assert.deepEqual([(await foreign.collect(fm, fm)).coverage, (await foreign.collect(fm, fm)).reason], ['failed', 'relation-not-heap-table'], 'refused before any remote read');
  } finally {
    await f.admin.query(`DROP SERVER IF EXISTS ${server} CASCADE`);
    if (!existed) await f.admin.query('DROP EXTENSION IF EXISTS postgres_fdw');
  }
});

test('live: an idle window is quiescent and a table-wide absence is exact; any other committed transaction ends that', { skip }, async t => {
  const f = await fixture(t);
  // Created before the first mark: a table created during the run is a schema change (./catalog.mjs).
  await f.admin.query(`CREATE TABLE ${f.table}_other (id int)`);
  const wide = { kind: 'effect.none', select: { source: 'sql-snapshot', name: f.table, operation: 'update' } };
  const idle = await f.window(async () => {});
  if (idle.exact?.[0]?.quiescent !== true) t.diagnostic(`another session completed a transaction during the idle window (marks ${JSON.stringify(idle.exact?.[0]?.marks)}): the quiescent case is not asserted`);
  else assert.equal(evaluateEffectAssertion(wide, [idle]).verdict, 'pass');
  // A write to an unrelated table moves xmax: a table-wide selector is no longer exact, a named row still is.
  try {
    const busy = await f.window(() => f.admin.query(`INSERT INTO ${f.table}_other VALUES (1)`));
    assert.equal(busy.exact[0].quiescent, undefined);
    assert.equal(evaluateEffectAssertion(wide, [busy]).verdict, 'missing');
    assert.equal(evaluateEffectAssertion(f.none('a'), [busy]).verdict, 'pass');
  } finally { await f.admin.query(`DROP TABLE IF EXISTS ${f.table}_other`); }
});

test('live: partitions and inheritance children are read with their parent and checked', { skip }, async t => {
  const f = await fixture(t);
  const part = `${f.table}_part`, child = `${f.table}_inh`;
  try {
    await f.admin.query(`CREATE TABLE ${part} (id text, region text, v text, PRIMARY KEY (id, region)) PARTITION BY LIST (region);
      CREATE TABLE ${part}_eu PARTITION OF ${part} FOR VALUES IN ('eu') PARTITION BY LIST (region);
      CREATE TABLE ${part}_eu1 PARTITION OF ${part}_eu FOR VALUES IN ('eu');
      CREATE TABLE ${part}_us PARTITION OF ${part} FOR VALUES IN ('us');
      INSERT INTO ${part} VALUES ('a', 'eu', 'x'), ('b', 'us', 'y'); GRANT SELECT ON ${part}, ${part}_eu, ${part}_eu1, ${part}_us TO ${f.reader};
      CREATE TABLE ${child} () INHERITS (${f.table}); INSERT INTO ${child} VALUES ('d', 'w', 4); GRANT SELECT ON ${child} TO ${f.reader}`);
    const o = f.readerOn(part, { watchedResources: [`${part}/a`, `${part}/b`] });
    const none = id => ({ kind: 'effect.none', select: { source: 'sql-snapshot', name: part, operation: 'update', resource: `${part}/${id}` } });
    let from = await o.mark(); await f.admin.query(`UPDATE ${part} SET v = 'changed' WHERE id = 'a'`); let w = await collectWindow(o, from, await o.mark());
    assert.deepEqual([w.coverage, w.exact[0].violated], ['net-only', false]);
    assert.equal(evaluateEffectAssertion(none('a'), [w]).verdict, 'fail', 'an update in a nested partition is seen');
    assert.equal(evaluateEffectAssertion(none('b'), [w]).verdict, 'pass');
    // A partition attached during the window: the set of descendants changed.
    from = await o.mark(); await f.admin.query(`CREATE TABLE ${part}_ap PARTITION OF ${part} FOR VALUES IN ('ap'); GRANT SELECT ON ${part}_ap TO ${f.reader}`); w = await collectWindow(o, from, await o.mark());
    // The set of descendants changed: the rows cannot be identified, so the window fails with no events.
    assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'relation-unverified', 0]); assert.notEqual(evaluateEffectAssertion(none('b'), [w]).verdict, 'pass');
    // Inheritance: the child's rows are read through the parent, from a verified heap child.
    const parent = f.readerOn(f.table, { watchedResources: [`${f.table}/a`, `${f.table}/d`] });
    from = await parent.mark(); await f.admin.query(`UPDATE ${child} SET v = 'changed' WHERE id = 'd'`); w = await collectWindow(parent, from, await parent.mark());
    assert.equal(w.exact[0].violated, false);
    assert.equal(evaluateEffectAssertion(f.none('d'), [w]).verdict, 'fail'); assert.equal(evaluateEffectAssertion(f.none('a'), [w]).verdict, 'pass');
  } finally { await f.admin.query(`DROP TABLE IF EXISTS ${part} CASCADE; DROP TABLE IF EXISTS ${child}`); }
});

test('live: unread descendants fail the mark; rows that cannot be identified fail the window with no events', { skip }, async t => {
  const f = await fixture(t);
  const part = `${f.table}_r4p`, tmp = `${f.table}_tmp`;
  const reasonOf = async o => { const m = await o.mark(), n = await o.mark(); const w = await collectWindow(o, m, n); return [w.coverage, w.reason, w.events.length]; };
  try {
    // Another session's temporary child is skipped by the parent scan.
    await f.other.query(`CREATE TEMP TABLE ${tmp} () INHERITS (public.${f.table}); GRANT SELECT ON ${tmp} TO ${f.reader}`);
    assert.deepEqual(await reasonOf(f.readerOn(f.table)), ['failed', 'descendant-not-scanned', 0]);
    await f.other.query(`DROP TABLE ${tmp}`);
    // A key duplicated across the parent and an inheritance child.
    await f.admin.query(`CREATE TABLE ${f.table}_dupchild () INHERITS (${f.table}); INSERT INTO ${f.table}_dupchild VALUES ('a', 'copy', 9); GRANT SELECT ON ${f.table}_dupchild TO ${f.reader}`);
    assert.deepEqual(await reasonOf(f.readerOn(f.table)), ['failed', 'duplicate-key', 0]);
    await f.admin.query(`DROP TABLE ${f.table}_dupchild`);
    // A partition detached with no DELETE: the set of descendants changed.
    await f.admin.query(`CREATE TABLE ${part} (id text, region text, PRIMARY KEY (id, region)) PARTITION BY LIST (region);
      CREATE TABLE ${part}_eu PARTITION OF ${part} FOR VALUES IN ('eu'); CREATE TABLE ${part}_us PARTITION OF ${part} FOR VALUES IN ('us');
      INSERT INTO ${part} VALUES ('a', 'eu'), ('b', 'us'); GRANT SELECT ON ${part}, ${part}_eu, ${part}_us TO ${f.reader}`);
    const o = f.readerOn(part, { watchedResources: [`${part}/a`] });
    const from = await o.mark(); await f.admin.query(`ALTER TABLE ${part} DETACH PARTITION ${part}_us`); const w = await collectWindow(o, from, await o.mark());
    assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'relation-unverified', 0]);
    // A concurrent detach left pending (interrupted while an older snapshot still reads the parent; PostgreSQL 14+).
    const version = Number((await f.admin.query('SHOW server_version_num'))[0].rows[0][0]);
    if (version >= 140000) {
      await f.admin.query(`ALTER TABLE ${part} ATTACH PARTITION ${part}_us FOR VALUES IN ('us')`);
      await f.other.query(`BEGIN ISOLATION LEVEL REPEATABLE READ; SELECT count(*) FROM ${part}`);
      await f.admin.query('SET statement_timeout = 500');
      await assert.rejects(f.admin.query(`ALTER TABLE ${part} DETACH PARTITION ${part}_us CONCURRENTLY`));
      await f.admin.query('SET statement_timeout = 0');
      await f.other.query('COMMIT');
      const pending = (await f.admin.query(`SELECT inhdetachpending::text FROM pg_inherits WHERE inhrelid = '${part}_us'::regclass`))[0].rows[0]?.[0];
      if (pending !== 'true') t.diagnostic(`the interrupted detach did not stay pending (${pending}): that case is not asserted`);
      else assert.deepEqual(await reasonOf(f.readerOn(part, { watchedResources: [`${part}/a`] })), ['failed', 'descendant-not-scanned', 0]);
      if (pending === 'true') await f.admin.query(`ALTER TABLE ${part} DETACH PARTITION ${part}_us FINALIZE`);
    } else t.diagnostic('PostgreSQL 13: no concurrent detach');
  } finally {
    try { await f.other.query('ROLLBACK'); } catch {}
    try { await f.other.query(`DROP TABLE IF EXISTS ${tmp}`); } catch {}
    await f.admin.query(`SET statement_timeout = 0; DROP TABLE IF EXISTS ${part} CASCADE; DROP TABLE IF EXISTS ${part}_us; DROP TABLE IF EXISTS ${f.table}_dupchild`);
  }
});

test('live: DDL between a mark\'s snapshot and its scan waits for the mark; a rewrite between marks fails the window', { skip }, async t => {
  const f = await fixture(t);
  const [, adminUser, adminPassword, port, database] = live;
  const watcher = await pgConnect({ host: '127.0.0.1', port: Number(port), database, user: adminUser, password: adminPassword });
  const part = `${f.table}_r5p`;
  // Runs `ddl` from another session right after a mark's first round trip, and waits until it is queued behind the mark's lock.
  let armed = null;
  const connect = async options => {
    const client = await pgConnect(options), wrapped = Object.create(client);
    let calls = 0;
    wrapped.query = async (sql, opts) => {
      const out = await client.query(sql, opts);
      // The mark's own transaction (BEGIN); the catalog fingerprint's session (./catalog.mjs) connects first, around it.
      if (++calls === 1 && armed && /^BEGIN/.test(sql)) {
        const ddl = armed; armed = null;
        ddl.pending = f.admin.query(ddl.sql);
        const until = Date.now() + 5000;
        while ((await watcher.query("SELECT count(*)::text FROM pg_catalog.pg_locks WHERE NOT granted"))[0].rows[0][0] === '0') {
          if (Date.now() > until) { ddl.waited = false; return out; }
          await new Promise(r => setTimeout(r, 50));
        }
        ddl.waited = true;
      }
      return out;
    };
    return wrapped;
  };
  try {
    // TRUNCATE between the snapshot and the scan: it waits for the mark, so the mark reads the rows as they were.
    const o = f.readerOn(f.table, { connect, watchedResources: [`${f.table}/a`] });
    const m0 = await o.mark();
    const truncate = { sql: `TRUNCATE ${f.table}` }; armed = truncate;
    const m1 = await o.mark();
    assert.equal(truncate.waited, true, 'the TRUNCATE waited for the mark\'s lock');
    await truncate.pending;
    // The waiting TRUNCATE may already hold a transaction id at the end mark (then the window is partial): never a delete.
    const quiet = await collectWindow(o, m0, m1);
    assert.equal(quiet.events.length, 0, 'no false deletes'); assert.ok(['net-only', 'partial'].includes(quiet.coverage), quiet.reason);
    // The TRUNCATE then committed: the next window sees a rewritten table and fails with no events.
    const after = await collectWindow(o, m1, await o.mark());
    assert.deepEqual([after.coverage, after.reason, after.events.length], ['failed', 'relation-rewritten', 0]);
    // DETACH between the snapshot and the scan of a partitioned table: it also waits.
    await f.admin.query(`CREATE TABLE ${part} (id text, region text, PRIMARY KEY (id, region)) PARTITION BY LIST (region);
      CREATE TABLE ${part}_eu PARTITION OF ${part} FOR VALUES IN ('eu'); CREATE TABLE ${part}_us PARTITION OF ${part} FOR VALUES IN ('us');
      INSERT INTO ${part} VALUES ('a', 'eu'), ('b', 'us'); GRANT SELECT ON ${part}, ${part}_eu, ${part}_us TO ${f.reader}`);
    const p = f.readerOn(part, { connect, watchedResources: [`${part}/a`] });
    const p0 = await p.mark();
    const detach = { sql: `ALTER TABLE ${part} DETACH PARTITION ${part}_us` }; armed = detach;
    const p1 = await p.mark();
    assert.equal(detach.waited, true, 'the DETACH waited for the mark\'s lock');
    await detach.pending;
    const held = await collectWindow(p, p0, p1);
    assert.equal(held.events.length, 0, 'no false deletes'); assert.ok(['net-only', 'partial'].includes(held.coverage), held.reason);
    assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await collectWindow(p, p1, await p.mark())), ['failed', 'relation-unverified']);
    // ALTER COLUMN TYPE between the marks rewrites every row: never read as updates.
    await f.admin.query(`INSERT INTO ${f.table} VALUES ('a', 'x', 1), ('b', 'y', 2)`);
    const q = f.readerOn(f.table, { watchedResources: [`${f.table}/a`] });
    const q0 = await q.mark(); await f.admin.query(`ALTER TABLE ${f.table} ALTER COLUMN n TYPE bigint`); const rewritten = await collectWindow(q, q0, await q.mark());
    assert.deepEqual([rewritten.coverage, rewritten.reason, rewritten.events.length], ['failed', 'relation-rewritten', 0]);
    // Locking through the parent: on PostgreSQL 17 a reader without SELECT on a child still locks it (only the parent is checked).
    await f.admin.query(`REVOKE SELECT ON ${part}_eu FROM ${f.reader}`);
    const parentOnly = f.readerOn(part), d0 = await parentOnly.mark(), d1 = await parentOnly.mark();
    const w = await collectWindow(parentOnly, d0, d1);
    t.diagnostic(`reader without SELECT on a partition: ${w.coverage}${w.reason ? ` (${w.reason})` : ''}`);
    assert.ok(w.coverage === 'net-only' || (w.coverage === 'failed' && w.reason === 'permission-denied'), 'either locked through the parent, or refused; never a partial read');
  } finally {
    watcher.close();
    await f.admin.query(`DROP TABLE IF EXISTS ${part} CASCADE; DROP TABLE IF EXISTS ${part}_us`);
  }
});

test('live: a child that joins during the lock wait fails the mark; renamed keys, columns and encodings never read as deletes plus inserts', { skip }, async t => {
  const f = await fixture(t);
  const [, adminUser, adminPassword, port, database] = live;
  const session = () => pgConnect({ host: '127.0.0.1', port: Number(port), database, user: adminUser, password: adminPassword });
  const holder = await session(), joiner = await session();
  const y = `${f.table}_y`, x = `${f.table}_x`, k = `${f.table}_k`, mood = `${f.table}_mood`;
  try {
    // H-B: the mark's LOCK lists the tree (child y) and waits on y, held by another session; x joins meanwhile.
    await f.admin.query(`CREATE TABLE ${y} () INHERITS (${f.table}); CREATE TABLE ${x} (id text NOT NULL, v text, n int); INSERT INTO ${x} VALUES ('x1', 'late', 9)`);
    const o = f.readerOn(f.table, { watchedResources: [`${f.table}/a`] });
    const m0 = await o.mark();
    await holder.query(`BEGIN; LOCK TABLE ${y} IN ACCESS EXCLUSIVE MODE`);
    const pending = o.mark();
    const until = Date.now() + 5000;
    while ((await f.other.query("SELECT count(*)::text FROM pg_catalog.pg_locks WHERE NOT granted AND locktype = 'relation'"))[0].rows[0][0] === '0') { if (Date.now() > until) break; await new Promise(r => setTimeout(r, 50)); }
    await joiner.query(`ALTER TABLE ${x} INHERIT ${f.table}`);
    // Another session holds a lock on x when the mark reads pg_locks: only this backend's own locks count.
    await f.other.query(`BEGIN; LOCK TABLE ${x} IN ACCESS SHARE MODE`);
    await holder.query('COMMIT');
    const m1 = await pending;
    assert.deepEqual((({ coverage, reason, events }) => [coverage, reason, events.length])(await collectWindow(o, m0, m1)), ['failed', 'descendant-not-locked', 0]);
    await f.other.query('COMMIT');
    await f.admin.query(`ALTER TABLE ${x} NO INHERIT ${f.table}; DROP TABLE ${x}; DROP TABLE ${y}`);
    // Two columns swap names between the marks (no write, no new row version, same file node).
    await f.admin.query(`CREATE TABLE ${k} (id text PRIMARY KEY, alt text NOT NULL); INSERT INTO ${k} VALUES ('a', 'zz1'), ('b', 'zz2'); GRANT SELECT ON ${k} TO ${f.reader}`);
    const kk = f.readerOn(k, { watchedResources: [`${k}/a`] });
    const k0 = await kk.mark(); await f.admin.query(`ALTER TABLE ${k} RENAME COLUMN id TO tmp; ALTER TABLE ${k} RENAME COLUMN alt TO id; ALTER TABLE ${k} RENAME COLUMN tmp TO alt`);
    assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await collectWindow(kk, k0, await kk.mark())), ['failed', 'columns-changed']);
    await f.admin.query(`DROP TABLE ${k}`);
    // An enum key label renamed between the marks. An enum key is refused at every mark.
    await f.admin.query(`CREATE TYPE ${mood} AS ENUM ('calm', 'busy'); CREATE TABLE ${k} (id ${mood} PRIMARY KEY, v text); INSERT INTO ${k} VALUES ('calm', 'x'), ('busy', 'y'); GRANT SELECT ON ${k} TO ${f.reader}`);
    const ke = f.readerOn(k, { watchedResources: [`${k}/calm`] });
    const e0 = await ke.mark(); await f.admin.query(`ALTER TYPE ${mood} RENAME VALUE 'busy' TO 'swamped'`);
    assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await collectWindow(ke, e0, await ke.mark())), ['failed', 'key-type-refused']);
    await f.admin.query(`DROP TABLE ${k}; DROP TYPE ${mood}`);
    // A role-level client_encoding default added between the marks does not change how keys decode.
    await f.admin.query(`INSERT INTO ${f.table} VALUES ('café', 'x', 1)`);
    const ce = f.readerOn(f.table, { watchedResources: [`${f.table}/café`] });
    const c0 = await ce.mark(); await f.admin.query(`ALTER ROLE ${f.reader} SET client_encoding = 'LATIN1'`);
    const cw = await collectWindow(ce, c0, await ce.mark());
    assert.deepEqual([cw.coverage, cw.events.length], ['net-only', 0]);
    assert.equal(evaluateEffectAssertion(f.none('café'), [cw]).verdict, 'pass');
  } finally {
    try { await holder.query('ROLLBACK'); } catch {}
    holder.close(); joiner.close();
    await f.admin.query(`DROP TABLE IF EXISTS ${x}; DROP TABLE IF EXISTS ${y}; DROP TABLE IF EXISTS ${k}; DROP TYPE IF EXISTS ${mood}; ALTER ROLE ${f.reader} RESET client_encoding`);
  }
});

test('live: a row written by a subtransaction in progress at the start mark is an insert, not a relabelled key', { skip }, async t => {
  const f = await fixture(t);
  // A top-level id, then a subtransaction id for the insert; then another transaction commits, so the subtransaction
  // id is below the start mark's xmax.
  await f.other.query(`BEGIN; SELECT pg_catalog.pg_current_xact_id(); SAVEPOINT s; INSERT INTO ${f.table} VALUES ('d', 'sub', 4)`);
  const sub = (await f.other.query(`SELECT xmin::text FROM ${f.table} WHERE id = 'd'`))[0].rows[0][0];
  await f.admin.query('SELECT pg_catalog.pg_current_xact_id()');
  // The premise, observed: the subtransaction id is inside [xmin, xmax) of a new snapshot, absent from its xip, and locked.
  const [snapshot, locked] = (await f.admin.query(`SELECT pg_catalog.pg_current_snapshot()::text, EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE locktype = 'transactionid' AND transactionid::text = '${sub}')::text`))[0].rows[0];
  const [xmin, xmax, xip] = snapshot.split(':');
  assert.ok(BigInt(xmin) < BigInt(sub) && BigInt(sub) < BigInt(xmax), `${sub} within ${snapshot}`);
  assert.ok(!xip.split(',').includes(sub), `${sub} not in xip ${xip}`);
  assert.equal(locked, 'true');
  const o = f.readerOn(f.table, { watchedResources: [`${f.table}/d`] });
  const m0 = await o.mark();
  await f.other.query('RELEASE SAVEPOINT s; COMMIT');
  const w = await collectWindow(o, m0, await o.mark());
  assert.deepEqual([w.coverage, w.reason, w.events.map(e => `${e.operation} ${e.resource}`)], ['net-only', 'net-change-between-snapshots', [`insert ${f.table}/d`]]);
});

test('live: keys whose text is not fixed by stored bytes, and unlogged tables, fail the mark; a domain over text is accepted', { skip }, async t => {
  const f = await fixture(t);
  const k = `${f.table}_k`, mood = `${f.table}_mood`, dmood = `${f.table}_dm`, dtext = `${f.table}_dt`, fn = `${f.table}_fn`, u = `${f.table}_u`, uc = `${f.table}_uc`;
  const windowOn = async (relation, extra = {}, between = async () => {}) => { const o = f.readerOn(relation, { watchedResources: [], ...extra }); const m0 = await o.mark(); await between(); return collectWindow(o, m0, await o.mark()); };
  const outcome = w => [w.coverage, w.reason, w.events.length];
  try {
    // Enum labels swapped between two rows by three RENAME VALUEs, with no row written.
    await f.admin.query(`CREATE TYPE ${mood} AS ENUM ('c1', 'c2'); CREATE TABLE ${k} (id ${mood} PRIMARY KEY, v text); INSERT INTO ${k} VALUES ('c1', 'x'), ('c2', 'y'); GRANT SELECT ON ${k} TO ${f.reader}`);
    const swapped = await windowOn(k, { watchedResources: [`${k}/c1`, `${k}/c2`] },
      () => f.admin.query(`ALTER TYPE ${mood} RENAME VALUE 'c1' TO 'tmp'; ALTER TYPE ${mood} RENAME VALUE 'c2' TO 'c1'; ALTER TYPE ${mood} RENAME VALUE 'tmp' TO 'c2'`));
    assert.deepEqual(outcome(swapped), ['failed', 'key-type-refused', 0]);
    const select = { source: 'sql-snapshot', name: k, operation: 'update', resource: `${k}/c1` };
    assert.notEqual(evaluateEffectAssertion({ kind: 'effect.exists', select }, [swapped]).verdict, 'pass');
    assert.notEqual(evaluateEffectAssertion({ kind: 'effect.none', select }, [swapped]).verdict, 'fail');
    // Domains are resolved: a domain over the enum is refused, a domain over text is accepted.
    await f.admin.query(`DROP TABLE ${k}; CREATE DOMAIN ${dmood} AS ${mood}; CREATE TABLE ${k} (id ${dmood} PRIMARY KEY); GRANT SELECT ON ${k} TO ${f.reader}`);
    assert.deepEqual(outcome(await windowOn(k)), ['failed', 'key-type-refused', 0]);
    await f.admin.query(`DROP TABLE ${k}; CREATE DOMAIN ${dtext} AS text CHECK (VALUE <> ''); CREATE TABLE ${k} (id ${dtext} PRIMARY KEY); INSERT INTO ${k} VALUES ('a'); GRANT SELECT ON ${k} TO ${f.reader}`);
    const accepted = await windowOn(k, { watchedResources: [`${k}/a`] });
    assert.notEqual(accepted.coverage, 'failed');
    assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { ...select, resource: `${k}/a` } }, [accepted]).verdict, 'pass');
    // An array key and a reg* key are refused.
    await f.admin.query(`DROP TABLE ${k}; CREATE TABLE ${k} (id text[] PRIMARY KEY); GRANT SELECT ON ${k} TO ${f.reader}`);
    assert.deepEqual(outcome(await windowOn(k)), ['failed', 'key-type-refused', 0]);
    await f.admin.query(`DROP TABLE ${k}; CREATE TABLE ${k} (id regclass PRIMARY KEY); GRANT SELECT ON ${k} TO ${f.reader}`);
    assert.deepEqual(outcome(await windowOn(k)), ['failed', 'key-type-refused', 0]);
    // A key name that is not a column. The mark pins search_path to pg_catalog, so attribute notation (r.name calls
    // name(row)) reaches only pg_catalog functions: one in public makes the row read fail; to_jsonb is refused by type.
    await f.admin.query(`DROP TABLE ${k}; CREATE TABLE ${k} (id text PRIMARY KEY); INSERT INTO ${k} VALUES ('a'); GRANT SELECT ON ${k} TO ${f.reader}; CREATE FUNCTION ${fn}(${k}) RETURNS text LANGUAGE sql IMMUTABLE AS 'SELECT ($1).id'`);
    assert.equal((await f.admin.query(`SELECT (r.${fn})::text FROM ${k} AS r`))[0].rows[0][0], 'a', 'the premise: attribute notation calls the function');
    assert.deepEqual(outcome(await windowOn(k, { tables: [{ table: k, key: fn }] })), ['failed', 'read-failed', 0]);
    assert.match((await f.admin.query(`BEGIN; SET LOCAL search_path = pg_catalog; SELECT (r.to_jsonb)::text FROM public.${k} AS r; ROLLBACK`))[2].rows[0][0], /"id": "a"/);
    assert.deepEqual(outcome(await windowOn(k, { tables: [{ table: k, key: 'to_jsonb' }] })), ['failed', 'key-type-refused', 0]);
    await f.admin.query(`DROP TABLE ${k} CASCADE`);
    // An unlogged table, and an unlogged inheritance child of a permanent table.
    await f.admin.query(`CREATE UNLOGGED TABLE ${u} (id text PRIMARY KEY); GRANT SELECT ON ${u} TO ${f.reader}`);
    assert.deepEqual(outcome(await windowOn(u)), ['failed', 'unlogged-table', 0]);
    await f.admin.query(`CREATE UNLOGGED TABLE ${uc} () INHERITS (${f.table}); GRANT SELECT ON ${uc} TO ${f.reader}`);
    assert.deepEqual(outcome(await windowOn(f.table)), ['failed', 'unlogged-table', 0]);
  } finally {
    await f.admin.query(`DROP TABLE IF EXISTS ${k} CASCADE; DROP TABLE IF EXISTS ${u}; DROP TABLE IF EXISTS ${uc}; DROP DOMAIN IF EXISTS ${dmood}; DROP DOMAIN IF EXISTS ${dtext}; DROP TYPE IF EXISTS ${mood}`);
  }
});

test('live: a role rename relabels an aclitem key with no row written, and the key is refused; pinned-setting outputs are accepted', { skip }, async t => {
  const f = await fixture(t);
  const k = `${f.table}_acl`, ra = `${f.table}_ra`, rb = `${f.table}_rb`, rt = `${f.table}_rt`, dacl = `${f.table}_dacl`, ts = `${f.table}_ts`;
  const windowOn = async (relation, extra = {}, between = async () => {}) => { const o = f.readerOn(relation, { watchedResources: [], ...extra }); const m0 = await o.mark(); await between(); return collectWindow(o, m0, await o.mark()); };
  const outcome = w => [w.coverage, w.reason, w.events.length];
  try {
    // Two rows whose aclitem keys name two roles; v records which role each row was written for.
    await f.admin.query(`CREATE ROLE ${ra}; CREATE ROLE ${rb}; CREATE TABLE ${k} (id aclitem NOT NULL, v text); GRANT SELECT ON ${k} TO ${f.reader}; INSERT INTO ${k} SELECT pg_catalog.makeaclitem(r.oid, (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user), 'SELECT', false), r.rolname FROM pg_catalog.pg_roles r WHERE r.rolname IN ('${ra}', '${rb}')`);
    const read = async () => (await f.admin.query(`SELECT v, id::text, xmin::text FROM ${k} ORDER BY v`))[0].rows;
    const before = await read();
    const w = await windowOn(k, {}, () => f.admin.query(`ALTER ROLE ${ra} RENAME TO ${rt}; ALTER ROLE ${rb} RENAME TO ${ra}; ALTER ROLE ${rt} RENAME TO ${rb}`));
    // The premise, observed: swapping the roles' names swapped the key texts, and no row was written.
    const after = await read();
    assert.deepEqual(after.map(r => r[2]), before.map(r => r[2]), 'same row versions');
    assert.deepEqual(after.map(r => r[1]), [before[1][1], before[0][1]], 'key texts swapped');
    assert.deepEqual(outcome(w), ['failed', 'key-type-refused', 0]);
    // A domain over aclitem has aclitem's output function: refused too.
    await f.admin.query(`DROP TABLE ${k}; CREATE DOMAIN ${dacl} AS aclitem; CREATE TABLE ${k} (id ${dacl} NOT NULL); GRANT SELECT ON ${k} TO ${f.reader}`);
    assert.deepEqual(outcome(await windowOn(k)), ['failed', 'key-type-refused', 0]);
    // Outputs that are not immutable only because of a setting each mark pins: timestamptz and date keys are accepted.
    await f.admin.query(`CREATE TABLE ${ts} (id timestamptz PRIMARY KEY, d date NOT NULL); INSERT INTO ${ts} VALUES ('2026-10-06 12:00:00+00', '2026-10-06'); GRANT SELECT ON ${ts} TO ${f.reader}`);
    assert.notEqual((await windowOn(ts)).coverage, 'failed');
    assert.notEqual((await windowOn(ts, { tables: [{ table: ts, key: 'd' }] })).coverage, 'failed');
  } finally {
    await f.admin.query(`DROP TABLE IF EXISTS ${k}; DROP TABLE IF EXISTS ${ts}; DROP DOMAIN IF EXISTS ${dacl}; DROP ROLE IF EXISTS ${ra}; DROP ROLE IF EXISTS ${rb}; DROP ROLE IF EXISTS ${rt}`);
  }
});

// Read-back (src/pg-readback.mjs) on the real server: each type's own text output, read as its canonical value; types the
// reader refuses; and a refund of 40 written as 4 by a real UPDATE.
test('live read-back: each supported type reads as its canonical value; refused types decide nothing; 40 written as 4 fails and 40 passes', { skip }, async t => {
  const [, adminUser, adminPassword, port, database] = live;
  const admin = await pgConnect({ host: '127.0.0.1', port: Number(port), database, user: adminUser, password: adminPassword });
  const suffix = randomBytes(4).toString('hex'), typed = `sh_rb_${suffix}`, odd = `sh_rbodd_${suffix}`, reader = `sh_rbreader_${suffix}`, readerPass = randomBytes(12).toString('base64url');
  await admin.query(`CREATE DOMAIN sh_amount_${suffix} AS numeric(10,2); CREATE TYPE sh_tier_${suffix} AS ENUM ('gold')`);
  await admin.query(`CREATE TABLE ${typed} (id text PRIMARY KEY, t_text text, t_bpchar char(3), t_uuid uuid, t_int8 int8, t_numeric numeric(10,2), t_float4 float4, t_float8 float8, t_negzero float8, t_bool boolean, t_ts timestamp, t_tstz timestamptz, t_date date, t_json json, t_jsonb jsonb, t_domain sh_amount_${suffix}, t_jnul json, note text)`);
  await admin.query(`INSERT INTO ${typed} VALUES ('r1', 'hello', 'ab', '6f1c2a3e-0000-4000-8000-00000000abcd', 9007199254740993, 40, 0.1, 1e21, '-0', true, '2026-10-18 06:07:35.1205', '2026-10-18 06:07:35+00', '2026-02-28', '{"b": 1, "a": [1.0, "x"]}', '{"k": null}', 12.5, '{"z": "nul\\u0000"}', 'n')`);
  await admin.query(`CREATE TABLE ${odd} (id text PRIMARY KEY, t_enum sh_tier_${suffix}, t_array text[], t_interval interval); INSERT INTO ${odd} VALUES ('r1', 'gold', '{a,b}', '1 day')`);
  await admin.query(`CREATE ROLE ${reader} LOGIN PASSWORD '${readerPass}'; GRANT SELECT ON ${typed}, ${odd} TO ${reader}`);
  t.after(async () => {
    try { await admin.query(`DROP TABLE IF EXISTS ${typed}, ${odd}; DROP OWNED BY ${reader}; DROP ROLE IF EXISTS ${reader}; DROP TYPE IF EXISTS sh_tier_${suffix}; DROP DOMAIN IF EXISTS sh_amount_${suffix}`); } finally { admin.close(); }
  });
  const observer = tables => createPgSnapshotObserver({ env: { SCOPEHAVEN_TARGET_PG_READER: `${reader}:${readerPass}` }, host: '127.0.0.1', port: Number(port), database, credentialEnv: 'SCOPEHAVEN_TARGET_PG_READER', tables });
  const windowOf = async (o, between) => { const from = await o.mark(); await between(); const to = await o.mark(); return o.collect(from, to); };
  // t_jnul holds json that jsonb refuses ("\u0000"): read as text, it never fails the mark.
  const columns = ['t_text', 't_bpchar', 't_uuid', 't_int8', 't_numeric', 't_float4', 't_float8', 't_negzero', 't_bool', 't_ts', 't_tstz', 't_date', 't_json', 't_jsonb', 't_domain', 't_jnul'];
  const refund = (from, to) => observer([{ table: typed, key: 'id', readBack: { columns, expect: [{ key: 'r1', change: { t_numeric: { from, to } } }] } }]);
  const defective = await windowOf(refund('40', '40'), () => admin.query(`UPDATE ${typed} SET t_numeric = 4 WHERE id = 'r1'`));
  assert.equal(defective.coverage, 'net-only');
  const row = defective.readBack.tables[0].rows[0];
  assert.deepEqual(row.before, { t_text: 'hello', t_bpchar: 'ab', t_uuid: '6f1c2a3e-0000-4000-8000-00000000abcd', t_int8: '9007199254740993', t_numeric: '40', t_float4: '0.1', t_float8: '1000000000000000000000',
    t_negzero: '0', t_bool: true, t_ts: '2026-10-18T06:07:35.1205', t_tstz: '2026-10-18T06:07:35Z', t_date: '2026-02-28', t_json: '{"a":[1,"x"],"b":1}', t_jsonb: '{"k":null}', t_domain: '12.5', t_jnul: '{"z":"nul\\u0000"}' });
  assert.equal(row.after.t_numeric, '4');
  assert.deepEqual([judgeReadBack(defective.readBack).verdict, judgeReadBack(defective.readBack).reasons], ['fail', ['change-mismatch']]);
  const fixed = await windowOf(refund('4', '40'), () => admin.query(`UPDATE ${typed} SET t_numeric = 40.00 WHERE id = 'r1'`));
  assert.equal(judgeReadBack(fixed.readBack).verdict, 'pass');
  // An undeclared column written beside it moves the remainder: the pass is left inconclusive.
  const collateral = await windowOf(refund('40', '40'), () => admin.query(`UPDATE ${typed} SET note = 'changed' WHERE id = 'r1'`));
  assert.deepEqual(judgeReadBack(collateral.readBack).reasons, ['remainder-changed']);
  for (const column of ['t_enum', 't_array', 't_interval']) {
    const refused = await windowOf(observer([{ table: odd, key: 'id', readBack: { columns: [column], expect: [{ key: 'r1', values: { [column]: 'gold' } }] } }]), async () => {});
    assert.deepEqual([refused.coverage, refused.readBack.tables[0].status, judgeReadBack(refused.readBack).verdict], ['net-only', 'type-refused', 'inconclusive'], column);
  }
});

// Read-back on the real server: a 64-bit id in jsonb compared digit for digit, the JSON value null,
// a uuid expected in upper case and an exact-key delete count.
test('live read-back: a rounded 64-bit id in jsonb fails and the exact one passes; JSON null, an upper-case uuid and an exact-key delete read as declared', { skip }, async t => {
  const [, adminUser, adminPassword, port, database] = live;
  const admin = await pgConnect({ host: '127.0.0.1', port: Number(port), database, user: adminUser, password: adminPassword });
  const suffix = randomBytes(4).toString('hex'), docs = `sh_rbrev_${suffix}`, reader = `sh_rbrevreader_${suffix}`, readerPass = randomBytes(12).toString('base64url');
  const uuid = '6f1c2a3e-0000-4000-8000-00000000abcd';
  await admin.query(`CREATE TABLE ${docs} (id text PRIMARY KEY, meta jsonb, jn json, u uuid)`);
  await admin.query(`INSERT INTO ${docs} VALUES ('A100', '{"order_id": 1234567890123456789}', 'null', '${uuid}'), ('A101', NULL, NULL, NULL)`);
  await admin.query(`CREATE ROLE ${reader} LOGIN PASSWORD '${readerPass}'; GRANT SELECT ON ${docs} TO ${reader}`);
  t.after(async () => {
    try { await admin.query(`DROP TABLE IF EXISTS ${docs}; DROP OWNED BY ${reader}; DROP ROLE IF EXISTS ${reader}`); } finally { admin.close(); }
  });
  const observer = readBack => createPgSnapshotObserver({ env: { SCOPEHAVEN_TARGET_PG_READER: `${reader}:${readerPass}` }, host: '127.0.0.1', port: Number(port), database, credentialEnv: 'SCOPEHAVEN_TARGET_PG_READER', tables: [{ table: docs, key: 'id', readBack }] });
  const windowOf = async (o, between) => { const from = await o.mark(); await between(); const to = await o.mark(); return o.collect(from, to); };
  const exact = '{"order_id": 1234567890123456789}', rounded = '{"order_id": 1234567890123456800}';
  const values = expect => ({ columns: ['meta', 'jn', 'u'], remainder: 'may-change', expect: [{ key: 'A100', values: expect }] });
  const idle = await windowOf(observer(values({ meta: exact, jn: 'null', u: uuid.toUpperCase() })), async () => {});
  assert.deepEqual(idle.readBack.tables[0].rows[0].after, { meta: '{"order_id":1234567890123456789}', jn: 'null', u: uuid });
  assert.deepEqual([judgeReadBack(idle.readBack).verdict, judgeReadBack(idle.readBack).reasons], ['pass', []]);
  // An expected null is SQL NULL, not the JSON value null; a JavaScript number has already been rounded.
  const sqlNull = await windowOf(observer(values({ jn: null })), async () => {});
  assert.deepEqual(judgeReadBack(sqlNull.readBack).reasons, ['value-mismatch']);
  const asNumber = await windowOf(observer(values({ meta: JSON.parse(exact) })), async () => {});
  assert.deepEqual([judgeReadBack(asNumber.readBack).verdict, judgeReadBack(asNumber.readBack).reasons], ['inconclusive', ['expectation-not-canonical']]);
  // The app rounds the id through a double: the change fails; written exactly, it passes.
  const change = { columns: ['meta'], expect: [{ key: 'A100', change: { meta: { from: exact, to: exact } } }] };
  const defective = await windowOf(observer(change), () => admin.query(`UPDATE ${docs} SET meta = '${rounded}' WHERE id = 'A100'`));
  assert.deepEqual([judgeReadBack(defective.readBack).verdict, judgeReadBack(defective.readBack).reasons], ['fail', ['change-mismatch']]);
  const fixed = await windowOf(observer({ ...change, expect: [{ key: 'A100', change: { meta: { from: rounded, to: exact } } }] }), () => admin.query(`UPDATE ${docs} SET meta = '${exact}' WHERE id = 'A100'`));
  assert.deepEqual([judgeReadBack(fixed.readBack).verdict, judgeReadBack(fixed.readBack).reasons], ['pass', []]);
  // An exact-key range: deleting the other row fails the count.
  const wrong = await windowOf(observer({ columns: ['u'], range: { keys: ['A100'] }, deletes: 1 }), () => admin.query(`DELETE FROM ${docs} WHERE id = 'A101'`));
  assert.deepEqual([judgeReadBack(wrong.readBack).verdict, judgeReadBack(wrong.readBack).reasons], ['fail', ['deletes-mismatch', 'remainder-changed']]);
});

// Read-back on the real server: an exact key is compared as the key column prints it. A uuid key written in
// upper case is printed in lower case, a char(4) key is read without its padding, and an int4 key by its digits.
test('live read-back: a forbidden delete of an upper-case uuid key fails and its fixed twin passes; char and integer keys read as their columns print them', { skip }, async t => {
  const [, adminUser, adminPassword, port, database] = live;
  const admin = await pgConnect({ host: '127.0.0.1', port: Number(port), database, user: adminUser, password: adminPassword });
  const suffix = randomBytes(4).toString('hex'), byUuid = `sh_rbm5u_${suffix}`, byChar = `sh_rbm5c_${suffix}`, byInt = `sh_rbm5i_${suffix}`, reader = `sh_rbm5reader_${suffix}`;
  const readerPass = randomBytes(12).toString('base64url'), uuid = '6f1c2a3e-0000-4000-8000-00000000a100', other = '6f1c2a3e-0000-4000-8000-00000000a101';
  await admin.query(`CREATE TABLE ${byUuid} (id uuid PRIMARY KEY, owner text); INSERT INTO ${byUuid} VALUES ('${uuid.toUpperCase()}', 'u1'), ('${other}', 'u1')`);
  await admin.query(`CREATE TABLE ${byChar} (id char(4) PRIMARY KEY, owner text); INSERT INTO ${byChar} VALUES ('A1', 'u1'), ('B2', 'u1')`);
  await admin.query(`CREATE TABLE ${byInt} (id int4 PRIMARY KEY, owner text); INSERT INTO ${byInt} VALUES (42, 'u1'), (43, 'u1')`);
  await admin.query(`CREATE ROLE ${reader} LOGIN PASSWORD '${readerPass}'; GRANT SELECT ON ${byUuid}, ${byChar}, ${byInt} TO ${reader}`);
  t.after(async () => {
    try { await admin.query(`DROP TABLE IF EXISTS ${byUuid}, ${byChar}, ${byInt}; DROP OWNED BY ${reader}; DROP ROLE IF EXISTS ${reader}`); } finally { admin.close(); }
  });
  const keep = (table, keys) => createPgSnapshotObserver({ env: { SCOPEHAVEN_TARGET_PG_READER: `${reader}:${readerPass}` }, host: '127.0.0.1', port: Number(port), database, credentialEnv: 'SCOPEHAVEN_TARGET_PG_READER',
    tables: [{ table, key: 'id', readBack: { columns: ['owner'], remainder: 'may-change', range: { keys }, deletes: 0 } }] });
  const verdictOf = async (table, keys, sql) => {
    const o = keep(table, keys), from = await o.mark(); await admin.query(sql); const to = await o.mark();
    const out = await o.collect(from, to), v = judgeReadBack(out.readBack);
    assert.equal(out.coverage, 'net-only');
    return [v.verdict, v.reasons];
  };
  assert.deepEqual(await verdictOf(byUuid, [uuid.toUpperCase()], `DELETE FROM ${byUuid} WHERE id = '${other}'`), ['pass', []], 'fixed twin');
  assert.deepEqual(await verdictOf(byUuid, [uuid.toUpperCase()], `DELETE FROM ${byUuid} WHERE id = '${uuid}'`), ['fail', ['deletes-mismatch']], 'defective twin');
  assert.deepEqual(await verdictOf(byChar, ['A1  '], `DELETE FROM ${byChar} WHERE id = 'A1'`), ['fail', ['deletes-mismatch']], 'char');
  assert.deepEqual(await verdictOf(byInt, ['042'], `DELETE FROM ${byInt} WHERE id = 43`), ['inconclusive', ['range-key-not-canonical']], 'leading zero');
  assert.deepEqual(await verdictOf(byInt, ['42'], `DELETE FROM ${byInt} WHERE id = 42`), ['fail', ['deletes-mismatch']], 'integer');
});
