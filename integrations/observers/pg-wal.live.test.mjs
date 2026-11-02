// pg-wal against a real PostgreSQL (13+) with wal_level = logical. Skipped unless SCOPEHAVEN_PG_LIVE names a disposable
// test database as "user:password@127.0.0.1:port/database" for a role that may create tables and roles (as for
// pg.live.test.mjs), and skipped with the reason when that server's wal_level is not logical (start it with
// -c wal_level=logical). Each test creates its own tables and roles and drops them after. One test changes a server
// setting (max_slot_wal_keep_size) and runs only with SCOPEHAVEN_PG_LIVE_ALTER_SYSTEM=1, on a server of your own.
//
// Covers what the scripted session cannot: test_decoding's own output read back through the server-side projection; an
// owned refund app's fixed and defective twins; a write through a second connection that bypasses the app; rolled-back
// and RLS-filtered writes; the server dropping the temporary slot on a session error, a terminated session, and a lost
// WAL segment; schema drift (and a change reverted between marks); an in-flight writer; TRUNCATE; TOAST; partitions; a
// table without a key in its replica identity; what leaves the server for other tables; and the completeness table
// against pg-snapshot on the same planted writes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { pgConnect } from './pg-wire.mjs';
import { createPgWalObserver, PG_WAL_SOURCE } from './pg-wal.mjs';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { collectWindow, evaluateEffectAssertion, validateWindow } from './events.mjs';

const live = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)\/([A-Za-z_][A-Za-z0-9_]*)$/.exec(process.env.SCOPEHAVEN_PG_LIVE ?? '');
const [, adminUser, adminPassword, portText, database] = live ?? [];
const port = Number(portText);
const connectAs = (user, password) => pgConnect({ host: '127.0.0.1', port, database, user, password });
let skip = live ? false : 'set SCOPEHAVEN_PG_LIVE=user:password@127.0.0.1:port/db (a disposable test database with wal_level=logical) to run';
if (live) {
  try {
    const probe = await connectAs(adminUser, adminPassword);
    try { const level = (await probe.query('SHOW wal_level'))[0].rows[0][0]; if (level !== 'logical') skip = `the server's wal_level is ${level}: start it with -c wal_level=logical to run`; }
    finally { probe.close(); }
  } catch (error) { skip = `the server named by SCOPEHAVEN_PG_LIVE could not be reached (${error.code ?? 'error'})`; }
}
const alterSystem = process.env.SCOPEHAVEN_PG_LIVE_ALTER_SYSTEM === '1' ? false : 'set SCOPEHAVEN_PG_LIVE_ALTER_SYSTEM=1 to change max_slot_wal_keep_size on a server of your own';

// An owned refund app over two tables, and roles: the app (DML only), a WAL reader (REPLICATION, no table grants), and a
// snapshot reader (SELECT only) for the comparison. Everything is dropped after the test.
async function fixture(t) {
  const admin = await connectAs(adminUser, adminPassword), other = await connectAs(adminUser, adminPassword);
  const x = randomBytes(4).toString('hex'), orders = `sh_wal_orders_${x}`, payouts = `sh_wal_payouts_${x}`, appRole = `sh_wal_app_${x}`, walRole = `sh_wal_reader_${x}`, snapRole = `sh_wal_snap_${x}`;
  const appPass = randomBytes(12).toString('base64url'), walPass = randomBytes(12).toString('base64url'), snapPass = randomBytes(12).toString('base64url');
  await admin.query(`CREATE TABLE ${orders} (id text PRIMARY KEY, tenant text NOT NULL, status text NOT NULL, refund numeric, card_last4 text, body text);
    ALTER TABLE ${orders} ALTER COLUMN body SET STORAGE EXTERNAL;
    CREATE TABLE ${payouts} (id text PRIMARY KEY, order_id text NOT NULL, amount numeric NOT NULL);
    INSERT INTO ${orders} VALUES ('o1', 't1', 'open', NULL, '4242', NULL), ('o2', 't2', 'open', NULL, '1111', NULL), ('o3', 't1', 'open', NULL, '0000', NULL)`);
  await admin.query(`CREATE ROLE ${appRole} LOGIN PASSWORD '${appPass}'; GRANT SELECT, INSERT, UPDATE, DELETE ON ${orders}, ${payouts} TO ${appRole};
    CREATE ROLE ${walRole} LOGIN REPLICATION PASSWORD '${walPass}'; CREATE ROLE ${snapRole} LOGIN PASSWORD '${snapPass}'; GRANT SELECT ON ${orders}, ${payouts} TO ${snapRole}`);
  const app = await connectAs(appRole, appPass);
  const observers = [];
  t.after(async () => {
    for (const o of observers) { try { await o.stop(); } catch {} }
    try {
      try { await other.query('ROLLBACK'); } catch {}
      app.close();
      await admin.query(`DROP TABLE IF EXISTS ${orders}, ${payouts} CASCADE; DROP OWNED BY ${appRole}, ${walRole}, ${snapRole}; DROP ROLE IF EXISTS ${appRole}; DROP ROLE IF EXISTS ${walRole}; DROP ROLE IF EXISTS ${snapRole}`);
    } finally { admin.close(); other.close(); }
  });
  const wal = (extra = {}) => {
    const o = createPgWalObserver({ env: { SCOPEHAVEN_TARGET_WAL: `${walRole}:${walPass}` }, host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_WAL', barrierMs: 3000,
      tables: [{ table: orders, key: 'id', resourcePrefix: 'orders', values: ['status', 'refund', 'body'] }, { table: payouts, key: 'id', resourcePrefix: 'payouts', values: ['amount'] }], ...extra });
    observers.push(o);
    return o;
  };
  const snapshot = (extra = {}) => createPgSnapshotObserver({ env: { SCOPEHAVEN_TARGET_SNAP: `${snapRole}:${snapPass}` }, host: '127.0.0.1', port, database, credentialEnv: 'SCOPEHAVEN_TARGET_SNAP',
    tables: [{ table: orders, key: 'id', resourcePrefix: 'orders' }, { table: payouts, key: 'id', resourcePrefix: 'payouts' }], watchedResources: ['orders/o1', 'orders/o2', 'orders/o3'], ...extra });
  return { admin, other, app, orders, payouts, walRole, wal, snapshot, suffix: x };
}
// The owned refund app. Fixed: one UPDATE of the order's own row. Defective: refunds a tenth of the amount and creates a
// payout row it then deletes again (an insert and delete within the window, so a net reader sees nothing).
const refundApp = (f, { defective }) => ({
  async refund(order, amount) {
    if (!defective) return f.app.query(`UPDATE ${f.orders} SET status = 'refunded', refund = ${amount} WHERE id = '${order}'`);
    await f.app.query(`UPDATE ${f.orders} SET status = 'refunded', refund = ${amount / 10} WHERE id = '${order}'`);
    await f.app.query(`INSERT INTO ${f.payouts} VALUES ('p-${order}', '${order}', ${amount})`);
    await f.app.query(`DELETE FROM ${f.payouts} WHERE id = 'p-${order}'`);
  },
});
const asWindow = (o, w) => validateWindow({ source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: w.coverage, reason: w.reason, events: w.events });
const span = async (o, between) => { const from = await o.mark(); await between(); const to = await o.mark(); return o.collect(from, to); };
const sel = (name, operation, resource) => ({ source: PG_WAL_SOURCE, name, operation, ...(resource ? { resource } : {}) });
const verdict = (kind, select, windows, extra = {}) => evaluateEffectAssertion({ kind, select, ...extra }, windows).verdict;

test('live: the owned refund app: the fixed twin passes and the defective twin fails, on the payout it made and undid and on the amount', { skip }, async t => {
  const f = await fixture(t);
  const run = async defective => {
    const o = f.wal(); await o.start();
    const w = await span(o, () => refundApp(f, { defective }).refund('o1', 40));
    return { w, ew: asWindow(o, w), value: o.judgeValue(w.wal, { table: f.orders, key: 'o1', column: 'refund', equals: '40' }) };
  };
  const fixed = await run(false);
  assert.equal(fixed.w.coverage, 'complete', fixed.w.reason);
  assert.equal(verdict('effect.none', sel(f.payouts, 'insert'), [fixed.ew]), 'pass');
  assert.equal(verdict('effect.none', sel(f.orders, 'update', 'orders/o2'), [fixed.ew]), 'pass');
  assert.deepEqual(fixed.value, { verdict: 'pass', reason: null });
  await f.admin.query(`UPDATE ${f.orders} SET status = 'open', refund = NULL WHERE id = 'o1'`);
  const defective = await run(true);
  assert.equal(defective.w.coverage, 'complete', defective.w.reason);
  assert.equal(verdict('effect.none', sel(f.payouts, 'insert'), [defective.ew]), 'fail', 'the payout it inserted and deleted again');
  assert.deepEqual(defective.w.wal.tables[1].counts, { insert: 1, update: 0, delete: 1 });
  assert.deepEqual(defective.value, { verdict: 'fail', reason: 'value-mismatch' }, 'a refund of 4 for 40');
});

test('live: a write through a second connection that bypasses the app is caught; a write to an ignored table leaves absence decidable, an unlisted one holds it back', { skip }, async t => {
  const f = await fixture(t);
  // The same writes seen by two observers: one lists the unrelated table on its ignore list, one does not.
  // Created before the observers start: a table created during the run is a schema change (./catalog.mjs).
  await f.admin.query(`CREATE TABLE ${f.orders}_bg (n int)`);
  const o = f.wal({ ignore: [`public.${f.orders}_bg`] }); await o.start();
  const plain = f.wal(); await plain.start();
  try {
    const from = await o.mark(), fromPlain = await plain.mark();
    await refundApp(f, { defective: false }).refund('o1', 40);
    await f.other.query(`UPDATE ${f.orders} SET status = 'cancelled' WHERE id = 'o2'`); // not the app: another session
    await f.admin.query(`INSERT INTO ${f.orders}_bg VALUES (1)`); // an unrelated table
    const w = await o.collect(from, await o.mark()), unlisted = await plain.collect(fromPlain, await plain.mark());
    assert.deepEqual([w.coverage, w.reason, w.wal.others.ignored], ['complete', null, 1]);
    assert.deepEqual([unlisted.coverage, unlisted.reason], ['partial', 'unlisted-table-changed']);
    assert.equal(verdict('effect.none', sel(f.payouts, 'insert'), [asWindow(plain, unlisted)]), 'missing', 'an unlisted table could have carried the effect');
    const ew = asWindow(o, w);
    assert.equal(verdict('effect.none', sel(f.orders, 'update', 'orders/o2'), [ew]), 'fail', 'the planted write');
    assert.equal(verdict('effect.none', sel(f.orders, 'update', 'orders/o3'), [ew]), 'pass');
    assert.equal(verdict('effect.none', sel(f.payouts, 'insert'), [ew]), 'pass', 'table-wide absence with an ignored table written in the window');
    assert.deepEqual(unlisted.wal.others.unlisted, [{ name: `public.${f.orders}_bg`, changes: 1 }]);
  } finally { await f.admin.query(`DROP TABLE IF EXISTS ${f.orders}_bg`); }
});

test('live: rolled-back writes and an UPDATE that RLS filtered to zero rows are not decoded (invisible by design); committed subtransactions are', { skip }, async t => {
  const f = await fixture(t);
  await f.admin.query(`ALTER TABLE ${f.orders} ENABLE ROW LEVEL SECURITY; CREATE POLICY own ON ${f.orders} TO PUBLIC USING (tenant = 't9')`);
  // A 64kB decoding budget for the reader's session: with streaming on, the large rolled-back transaction below would be
  // decoded in streamed blocks before it aborted. Streaming is off, so it never is.
  await f.admin.query(`ALTER ROLE ${f.walRole} SET logical_decoding_work_mem = '64kB'`);
  const o = f.wal(); await o.start();
  const w = await span(o, async () => {
    await f.other.query(`BEGIN; INSERT INTO ${f.payouts} VALUES ('rolled', 'o1', 1); ROLLBACK`);
    await f.other.query(`BEGIN; INSERT INTO ${f.payouts} SELECT 'big-' || g, 'o1', g FROM generate_series(1, 5000) g; ROLLBACK`);
    await f.other.query(`BEGIN; SAVEPOINT s; INSERT INTO ${f.payouts} VALUES ('sp', 'o1', 1); ROLLBACK TO s; SAVEPOINT k; INSERT INTO ${f.payouts} VALUES ('kept', 'o1', 2); RELEASE k; COMMIT`);
    const [filtered] = await f.app.query(`UPDATE ${f.orders} SET status = 'x' WHERE id = 'o1'`); // the app role is filtered by the policy
    assert.equal(filtered.command, 'UPDATE 0');
  });
  assert.equal(w.coverage, 'complete', w.reason);
  assert.deepEqual(w.events.map(e => `${e.operation} ${e.resource}`), ['insert payouts/kept']);
  // Under the same 64kB budget a large committed transaction is decoded whole at its commit (streaming on, it would come
  // as streamed blocks without row content, which the observer cannot read: decode-unparsed).
  const large = await span(o, () => f.other.query(`INSERT INTO ${f.payouts} SELECT 'many-' || g, 'o1', g FROM generate_series(1, 3000) g`));
  assert.deepEqual([large.coverage, large.reason, large.wal.tables[1].counts.insert], ['complete', null, 3000]);
});

test('live: a server error in the observer session drops its temporary slot, and a terminated session ends it; each window across reads inconclusive', { skip }, async t => {
  const f = await fixture(t);
  // An injected failing statement in the observer's own session: the server drops the session's temporary slots on ERROR.
  let inject = false;
  const connect = async options => {
    const client = await pgConnect(options);
    return { close: () => client.close(), query: async (sql, opts) => (inject && sql.includes('sh:flush') ? (inject = false, client.query('SELECT 1/0', opts)) : client.query(sql, opts)) };
  };
  const o = f.wal({ connect }); await o.start();
  const slotsOf = async () => (await f.admin.query(`SELECT count(*)::text FROM pg_replication_slots WHERE slot_name LIKE 'scopehaven_wal_%' AND active_pid IS NOT NULL`))[0].rows[0][0];
  const before = Number(await slotsOf());
  const m0 = await o.mark();
  await f.app.query(`UPDATE ${f.orders} SET status = 'x' WHERE id = 'o1'`);
  const m1 = await o.mark();
  inject = true;
  const errored = await o.collect(m0, m1);
  assert.deepEqual([errored.coverage, errored.reason], ['partial', 'decode-failed,slot-lost']);
  assert.equal(Number(await slotsOf()), before - 1, 'the server dropped the temporary slot');
  assert.notEqual(verdict('effect.none', sel(f.orders, 'update', 'orders/o2'), [asWindow(o, errored)]), 'pass');
  const m2 = await o.mark(); // a new session and slot
  assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await o.collect(m0, m2)), ['partial', 'slot-created-after-baseline,slot-lost']);
  assert.equal((await o.collect(m2, await o.mark())).coverage, 'complete', 'the new slot reads its own windows');
  // Another session terminates the observer's backend between the marks.
  const m3 = await o.mark();
  await f.app.query(`UPDATE ${f.orders} SET status = 'y' WHERE id = 'o1'`);
  const m4 = await o.mark();
  await f.admin.query("SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name LIKE 'scopehaven_wal_%' AND active_pid IS NOT NULL AND active_pid IN (SELECT pid FROM pg_stat_activity WHERE application_name = 'scopehaven-observer')");
  const cut = await o.collect(m3, m4);
  assert.equal(cut.coverage, 'partial');
  assert.ok(['connection-lost', 'decode-failed,slot-lost', 'slot-lost'].includes(cut.reason) || cut.reason.includes('connection-lost'), cut.reason);
  assert.notEqual(verdict('effect.none', sel(f.orders, 'update', 'orders/o2'), [asWindow(o, cut)]), 'pass');
});

test('live: WAL the slot needed is removed (max_slot_wal_keep_size): the window reads inconclusive', { skip: skip || alterSystem }, async t => {
  const f = await fixture(t);
  // ALTER SYSTEM cannot run in a transaction block, so each statement is sent alone; the reset runs before the fixture closes.
  await f.admin.query("ALTER SYSTEM SET max_slot_wal_keep_size = '1MB'"); await f.admin.query('SELECT pg_reload_conf()');
  try {
    const o = f.wal(); await o.start();
    const m0 = await o.mark();
    await f.admin.query(`CREATE TABLE ${f.orders}_fill (b text)`);
    for (let i = 0; i < 3; i++) {
      await f.admin.query(`INSERT INTO ${f.orders}_fill SELECT repeat(md5(g::text), 64) FROM generate_series(1, 20000) g`);
      await f.admin.query('SELECT pg_switch_wal()'); await f.admin.query('CHECKPOINT');
    }
    await f.admin.query(`DROP TABLE ${f.orders}_fill`);
    const m1 = await o.mark();
    const w = await o.collect(m0, m1);
    t.diagnostic(`after the WAL was removed: ${w.coverage} (${w.reason})`);
    assert.notEqual(w.coverage, 'complete');
    assert.match(w.reason, /wal-status-lost|slot-lost|connection-lost/);
  } finally {
    await f.admin.query(`DROP TABLE IF EXISTS ${f.orders}_fill`);
    await f.admin.query('ALTER SYSTEM RESET max_slot_wal_keep_size'); await f.admin.query('SELECT pg_reload_conf()');
  }
});

test('live: schema drift (a column added, RLS enabled and disabled again), an in-flight writer, TRUNCATE and an unlogged table read inconclusive or refused', { skip }, async t => {
  const f = await fixture(t);
  let o = f.wal(); await o.start();
  // A lasting schema change makes every later window differ from the run's baseline (./catalog.mjs): a fresh
  // observer (its own baseline) after each one, so the checks after it read their own reasons.
  const restart = async () => { await o.stop(); o = f.wal(); await o.start(); };
  t.after(() => o.stop());
  const reasonOf = async between => (await span(o, between)).reason;
  // TRUNCATE gives the table a new file node, a new pg_class row version: the fingerprint drifts as well.
  assert.equal(await reasonOf(() => f.admin.query(`ALTER TABLE ${f.orders} ADD COLUMN extra int`)), 'schema-drift');
  await restart();
  assert.equal(await reasonOf(() => f.admin.query(`ALTER TABLE ${f.orders} ENABLE ROW LEVEL SECURITY; ALTER TABLE ${f.orders} DISABLE ROW LEVEL SECURITY`)), 'schema-drift', 'a change reverted between the marks');
  // Its own uncommitted WAL may also sit on a partial page the server does not flush yet (wal-barrier): either way inconclusive.
  const inflight = await reasonOf(() => f.other.query(`BEGIN; UPDATE ${f.orders} SET status = 'pending' WHERE id = 'o3'`));
  await f.other.query('ROLLBACK');
  assert.ok(['transaction-in-flight-at-window-end', 'transaction-in-flight-at-window-end,wal-barrier'].includes(inflight), inflight);
  await f.admin.query(`CREATE TABLE ${f.orders}_side (n int)`);
  await restart();
  try {
    // A writer open on another table holds no lock on an observed one. Its uncommitted WAL can still hold the flush below
    // the end mark until some commit flushes it: the window then reads wal-barrier, never in-flight.
    const side = await span(o, () => f.other.query(`BEGIN; INSERT INTO ${f.orders}_side VALUES (1)`));
    await f.other.query('ROLLBACK');
    t.diagnostic(`a writer open on another table: ${side.coverage}${side.reason ? ` (${side.reason})` : ''}`);
    assert.ok(side.reason === null || side.reason === 'wal-barrier', side.reason);
    assert.ok(!String(side.reason).includes('transaction-in-flight'));
  } finally { await f.admin.query(`DROP TABLE IF EXISTS ${f.orders}_side`); }
  await restart();
  assert.equal(await reasonOf(() => f.admin.query(`TRUNCATE ${f.payouts}`)), 'schema-drift,table-truncated');
  assert.equal(await reasonOf(() => f.admin.query(`CREATE TABLE ${f.orders}_t2 (n int); TRUNCATE ${f.orders}_t2, ${f.payouts}; DROP TABLE ${f.orders}_t2`)), 'schema-drift,table-truncated,unlisted-table-changed', 'a TRUNCATE naming it second (the other table it names is unlisted)');
  const m0 = await o.mark();
  await f.admin.query(`ALTER TABLE ${f.payouts} SET UNLOGGED`);
  const w = await o.collect(m0, await o.mark());
  assert.deepEqual([w.coverage, w.reason], ['failed', 'unlogged-table']);
  await f.admin.query(`ALTER TABLE ${f.payouts} SET LOGGED`);
});

test('live: TOAST: an UPDATE that leaves a large value unchanged carries a marker, and a check on it reads inconclusive unless the window wrote it', { skip }, async t => {
  const f = await fixture(t);
  const big = `(SELECT string_agg(md5(i::text || '${f.suffix}'), '') FROM generate_series(1, 300) i)`;
  await f.admin.query(`UPDATE ${f.orders} SET body = ${big} WHERE id = 'o1'`);
  const o = f.wal(); await o.start();
  const w = await span(o, () => f.app.query(`UPDATE ${f.orders} SET status = 'shipped' WHERE id = 'o1'`));
  assert.equal(w.coverage, 'complete', w.reason);
  assert.deepEqual(w.wal.tables[0].changes[0].values.body, { toast: 'unchanged' });
  assert.deepEqual(o.judgeValue(w.wal, { table: f.orders, key: 'o1', column: 'body', equals: 'x' }), { verdict: 'inconclusive', reason: 'toast-unchanged' });
  assert.deepEqual(o.judgeValue(w.wal, { table: f.orders, key: 'o1', column: 'status', equals: 'shipped' }), { verdict: 'pass', reason: null });
  const both = await span(o, async () => { await f.app.query(`UPDATE ${f.orders} SET body = 'short' WHERE id = 'o1'`); await f.app.query(`UPDATE ${f.orders} SET status = 'done' WHERE id = 'o1'`); });
  assert.deepEqual(o.judgeValue(both.wal, { table: f.orders, key: 'o1', column: 'body', equals: 'short' }), { verdict: 'pass', reason: null });
});

test('live: the session pins how values print: a role default TimeZone and DateStyle on the reader change nothing', { skip }, async t => {
  const f = await fixture(t);
  const stamped = `${f.orders}_ts`;
  await f.admin.query(`CREATE TABLE ${stamped} (id int PRIMARY KEY, at timestamptz, d date, amount float8); ALTER ROLE ${f.walRole} SET TimeZone = 'America/New_York'; ALTER ROLE ${f.walRole} SET DateStyle = 'SQL, DMY'; ALTER ROLE ${f.walRole} SET extra_float_digits = -3`);
  try {
    const o = f.wal({ tables: [{ table: stamped, key: 'id', resourcePrefix: 'ts', values: ['at', 'd', 'amount'] }] }); await o.start();
    const w = await span(o, () => f.admin.query(`INSERT INTO ${stamped} VALUES (1, '2026-10-24 01:02:03+00', '2026-10-24', 0.1)`));
    assert.equal(w.coverage, 'complete', w.reason);
    assert.deepEqual(w.wal.tables[0].changes[0].values, { at: '2026-10-24 01:02:03+00', d: '2026-10-24', amount: '0.1' });
  } finally { await f.admin.query(`DROP TABLE IF EXISTS ${stamped}`); }
});

test('live: partitions decode under the declared table; a table without a key in its replica identity keeps inserts exact and leaves deletes inconclusive', { skip }, async t => {
  const f = await fixture(t);
  const part = `${f.orders}_p`, bare = `${f.orders}_bare`;
  await f.admin.query(`CREATE TABLE ${part} (id text, region text, v text, PRIMARY KEY (id, region)) PARTITION BY LIST (region); CREATE TABLE ${part}_eu PARTITION OF ${part} FOR VALUES IN ('eu');
    CREATE TABLE ${bare} (id text NOT NULL, v text); INSERT INTO ${bare} VALUES ('b1', 'x')`);
  try {
    const o = f.wal({ tables: [{ table: part, key: 'id', resourcePrefix: 'part' }, { table: bare, key: 'id', resourcePrefix: 'bare' }] }); await o.start();
    const p = await span(o, () => f.admin.query(`INSERT INTO ${part} VALUES ('e1', 'eu', 'x'); INSERT INTO ${bare} VALUES ('b2', 'y')`));
    assert.deepEqual([p.coverage, p.events.map(e => `${e.name} ${e.operation} ${e.resource}`)], ['complete', [`${part} insert part/e1`, `${bare} insert bare/b2`]]);
    const d = await span(o, () => f.admin.query(`DELETE FROM ${bare} WHERE id = 'b1'`));
    assert.deepEqual([d.coverage, d.reason], ['partial', 'key-not-in-replica-identity']);
    assert.notEqual(verdict('effect.none', sel(bare, 'delete', 'bare/b2'), [asWindow(o, d)]), 'pass');
  } finally { await f.admin.query(`DROP TABLE IF EXISTS ${part} CASCADE; DROP TABLE IF EXISTS ${bare}`); }
});

test('live: what leaves the server: another table\'s values and a logical message never reach the observer; a declared table\'s undeclared columns are digested', { skip }, async t => {
  const f = await fixture(t);
  const secret = `sekret-${f.suffix}`, received = [];
  const connect = async options => {
    const client = await pgConnect(options);
    return { close: () => client.close(), query: async (sql, opts) => { const out = await client.query(sql, opts); if (sql.includes('sh:peek')) received.push(JSON.stringify(out)); return out; } };
  };
  await f.admin.query(`CREATE TABLE ${f.orders}_priv (id int, token text)`);
  try {
    const o = f.wal({ connect }); await o.start();
    const w = await span(o, async () => {
      await f.admin.query(`INSERT INTO ${f.orders}_priv VALUES (1, '${secret}-other')`);
      await f.admin.query(`SELECT pg_logical_emit_message(true, 'x', 'table public.${f.payouts}: INSERT: id[text]:''forged'' order_id[text]:''o1'' amount[numeric]:1 ${secret}-message')`);
      await f.app.query(`UPDATE ${f.orders} SET card_last4 = '${secret}-declared' WHERE id = 'o2'`);
    });
    // The other table and the message each hold absence back; what reaches the observer is the same either way.
    assert.deepEqual([w.coverage, w.reason], ['partial', 'logical-message,unlisted-table-changed']);
    const wire = received.join('\n');
    assert.ok(!wire.includes(`${secret}-other`), 'another table\'s value stays in the server');
    assert.ok(!wire.includes(`${secret}-message`), 'a logical message\'s content stays in the server');
    assert.ok(wire.includes(`${secret}-declared`), 'the premise: a declared table\'s change is read whole');
    assert.ok(!JSON.stringify(w).includes(secret), 'and its undeclared column is kept only as a digest');
    assert.deepEqual(w.events.map(e => `${e.operation} ${e.resource}`), ['update orders/o2'], 'the message is never a change');
    assert.equal(w.wal.others.messages, 1);
  } finally { await f.admin.query(`DROP TABLE IF EXISTS ${f.orders}_priv`); }
});

// Probes, each a former false pass: a rename after the end mark read with the
// later catalog, a key moved inside a window while the primary key was swapped away and back, a system catalog declared
// as a table, a change in a relation two declared trees share, a domain over char as the key, and a schema renamed away
// and back inside a window.
test('live: renames after the mark, a primary key swapped inside a window, system catalogs, overlapping trees and a char-domain key', { skip }, async t => {
  const f = await fixture(t);
  const part = `${f.orders}_rp`, keyed = `${f.orders}_pk`, coded = `${f.orders}_cd`, code = `${f.orders}_code`;
  await f.admin.query(`CREATE TABLE ${part} (id text, region text, v text, PRIMARY KEY (id, region)) PARTITION BY LIST (region); CREATE TABLE ${part}_eu PARTITION OF ${part} FOR VALUES IN ('eu');
    CREATE TABLE ${keyed} (id text NOT NULL, alt text NOT NULL UNIQUE, v text, CONSTRAINT ${keyed}_pkey PRIMARY KEY (id)); INSERT INTO ${keyed} VALUES ('A', 'x1', 'v');
    CREATE DOMAIN ${code} AS character(6); CREATE TABLE ${coded} (id ${code} PRIMARY KEY, v text); INSERT INTO ${coded} VALUES ('ab', 'v')`);
  try {
    // 1. A partition renamed after the end mark of the window holding its insert; the later window collected first.
    const o = f.wal({ tables: [{ table: part, key: 'id', resourcePrefix: 'part' }, { table: f.orders, key: 'id', resourcePrefix: 'orders' }] }); await o.start();
    const m0 = await o.mark();
    await f.admin.query(`INSERT INTO ${part} VALUES ('e1', 'eu', 'x'); INSERT INTO ${f.orders} VALUES ('o9', 't1', 'open', NULL, NULL, NULL)`);
    const m1 = await o.mark();
    await f.admin.query(`ALTER TABLE ${part}_eu RENAME TO ${part}_europe; ALTER TABLE ${f.orders} RENAME TO ${f.orders}_was`);
    const m2 = await o.mark();
    await f.admin.query(`ALTER TABLE ${part}_europe RENAME TO ${part}_eu; ALTER TABLE ${f.orders}_was RENAME TO ${f.orders}`);
    const later = await o.collect(m1, m2);
    assert.notEqual(later.coverage, 'complete');
    const first = await o.collect(m0, m1);
    assert.deepEqual([first.coverage, first.events.map(e => `${e.operation} ${e.resource}`)], ['complete', ['insert part/e1', 'insert orders/o9']]);
    assert.equal(verdict('effect.none', sel(part, 'insert'), [asWindow(o, first)]), 'fail');
    // 2. The primary key swapped to another column and back inside one window, with the key moved meanwhile.
    const k = f.wal({ tables: [{ table: keyed, key: 'id', resourcePrefix: 'k' }] }); await k.start();
    const swapped = await span(k, () => f.admin.query(`ALTER TABLE ${keyed} DROP CONSTRAINT ${keyed}_pkey; ALTER TABLE ${keyed} ADD CONSTRAINT ${keyed}_alt PRIMARY KEY (alt);
      UPDATE ${keyed} SET id = 'B' WHERE id = 'A'; ALTER TABLE ${keyed} DROP CONSTRAINT ${keyed}_alt; ALTER TABLE ${keyed} ADD CONSTRAINT ${keyed}_pkey PRIMARY KEY (id)`));
    assert.equal(swapped.coverage, 'partial'); assert.match(swapped.reason, /schema-drift/);
    assert.notEqual(verdict('effect.none', sel(keyed, 'update', 'k/A'), [asWindow(k, swapped)]), 'pass');
    // 3. A system catalog is refused: its changes are never decoded as rows.
    const c = f.wal({ tables: [{ table: 'pg_namespace', key: 'nspname', schema: 'pg_catalog', resourcePrefix: 'ns' }] }); await c.start();
    const cat = await span(c, () => f.admin.query(`CREATE SCHEMA ${f.orders}_ns; DROP SCHEMA ${f.orders}_ns`));
    assert.deepEqual([cat.coverage, cat.reason], ['failed', 'system-catalog-refused']);
    // 4. A table and its own partition both declared: a change is reported under both names.
    const both = f.wal({ tables: [{ table: part, key: 'id', resourcePrefix: 'part' }, { table: `${part}_eu`, key: 'id', resourcePrefix: 'eu' }] }); await both.start();
    const shared = await span(both, () => f.admin.query(`INSERT INTO ${part} VALUES ('e2', 'eu', 'y')`));
    assert.deepEqual([shared.coverage, shared.events.map(e => `${e.name} ${e.resource}`)], ['complete', [`${part} part/e2`, `${part}_eu eu/e2`]]);
    // 5. A domain over char(6) as the key reads without its padding, as pg-snapshot's ::text does.
    const d = f.wal({ tables: [{ table: coded, key: 'id', resourcePrefix: 'cd' }] }); await d.start();
    const padded = await span(d, () => f.admin.query(`UPDATE ${coded} SET v = 'w' WHERE id = 'ab'`));
    assert.deepEqual(padded.events.map(e => e.resource), ['cd/ab']);
    // 6. The schema renamed away and back inside one window, with a write made under the other name meanwhile.
    const ns = `${f.orders}_s`;
    await f.admin.query(`CREATE SCHEMA ${ns}; CREATE TABLE ${ns}.t (id text PRIMARY KEY, v text)`);
    try {
      const r = f.wal({ tables: [{ table: 't', key: 'id', schema: ns, resourcePrefix: 'nt' }] }); await r.start();
      // Each step its own transaction, as an application would run them.
      const moved = await span(r, async () => {
        await f.admin.query(`ALTER SCHEMA ${ns} RENAME TO ${ns}_tmp`); await f.admin.query(`INSERT INTO ${ns}_tmp.t VALUES ('x', 'v')`); await f.admin.query(`ALTER SCHEMA ${ns}_tmp RENAME TO ${ns}`);
      });
      // The write made under the other name meanwhile is also an unlisted table's change.
      assert.deepEqual([moved.coverage, moved.reason], ['partial', 'schema-drift,unlisted-table-changed']);
      assert.notEqual(verdict('effect.none', sel('t', 'insert'), [asWindow(r, moved)]), 'pass');
    } finally { await f.admin.query(`DROP SCHEMA IF EXISTS ${ns} CASCADE; DROP SCHEMA IF EXISTS ${ns}_tmp CASCADE`); }
  } finally { await f.admin.query(`DROP TABLE IF EXISTS ${part} CASCADE; DROP TABLE IF EXISTS ${part}_europe; DROP TABLE IF EXISTS ${keyed}; DROP TABLE IF EXISTS ${coded}; DROP DOMAIN IF EXISTS ${code}; DROP SCHEMA IF EXISTS ${f.orders}_ns`); }
});

// The completeness table: the same planted writes read by pg-snapshot (net change between two snapshots) and by
// pg-wal (every committed change), each pair of marks taken around the same writes. Internal numbers only.
test('live completeness: pg-snapshot against pg-wal on the same planted writes', { skip }, async t => {
  const f = await fixture(t);
  let authExisted = true;
  try { authExisted = (await f.admin.query("SELECT count(*)::text FROM pg_namespace WHERE nspname = 'auth'"))[0].rows[0][0] === '1'; } catch {}
  // The platform job writes a table on Supabase's checked-in list (the list names tables, not whole schemas). A
  // server that already has auth.audit_log_entries (a real Supabase stack) gets a table of the test's own on the profile's list.
  const free = (await f.admin.query("SELECT (pg_catalog.to_regclass('auth.audit_log_entries') IS NULL)::text"))[0].rows[0][0] === 'true';
  const job = free ? 'audit_log_entries' : `sessions_${f.suffix}`;
  await f.admin.query(`CREATE SCHEMA IF NOT EXISTS auth; CREATE TABLE auth.${job} (id int PRIMARY KEY, seen timestamptz); INSERT INTO auth.${job} VALUES (1, now())`);
  try { await completeness(t, f, job, free ? [] : [`auth.${job}`]); }
  finally { await f.admin.query(`DROP TABLE IF EXISTS auth.${job}${authExisted ? '' : '; DROP SCHEMA IF EXISTS auth'}`); }
});
async function completeness(t, f, job, ignore) {
  const o = f.wal({ platform: 'supabase', ignore }); await o.start();
  const snap = f.snapshot();
  const both = async between => {
    const s0 = await snap.mark(), w0 = await o.mark();
    await between();
    const w1 = await o.mark(), s1 = await snap.mark();
    return { snap: await collectWindow(snap, s0, s1), raw: await o.collect(w0, w1) };
  };
  const rows = [];
  const record = (name, snapReads, walReads) => { rows.push({ case: name, pgSnapshot: snapReads, pgWal: walReads }); t.diagnostic(`COMPLETENESS ${JSON.stringify(rows.at(-1))}`); };
  const ops = w => w.events.map(e => `${e.operation} ${e.resource}`).join(', ') || 'nothing';
  // Each observer's own source: pg-wal's is sql-wal, pg-snapshot's sql-snapshot.
  const v = (kind, select, w, extra) => verdict(kind, { ...select, source: w.source }, [w], extra);

  // 1. Write and undo: a payout inserted and deleted again.
  let r = await both(async () => { await f.app.query(`INSERT INTO ${f.payouts} VALUES ('p1', 'o1', 40)`); await f.app.query(`DELETE FROM ${f.payouts} WHERE id = 'p1'`); });
  let ew = asWindow(o, r.raw);
  record('insert then delete of one row', `${ops(r.snap)}; "no payout inserted": ${v('effect.none', sel(f.payouts, 'insert'), r.snap)}`, `${ops(ew)}; "no payout inserted": ${v('effect.none', sel(f.payouts, 'insert'), ew)}`);
  assert.equal(v('effect.none', sel(f.payouts, 'insert'), ew), 'fail'); assert.notEqual(v('effect.none', sel(f.payouts, 'insert'), r.snap), 'fail');
  // 2. An update and its revert.
  r = await both(async () => { await f.app.query(`UPDATE ${f.orders} SET status = 'refunded' WHERE id = 'o1'`); await f.app.query(`UPDATE ${f.orders} SET status = 'open' WHERE id = 'o1'`); });
  ew = asWindow(o, r.raw);
  record('update then revert of one row', `${ops(r.snap)} (one row version; values equal at both marks)`, `${ops(ew)}; status ${r.raw.wal.tables[0].changes.map(c => c.values.status).join(' -> ')}`);
  assert.deepEqual(r.raw.wal.tables[0].changes.map(c => c.values.status), ['refunded', 'open']);
  // 3. A delete and a reinsert of the same key.
  r = await both(async () => { await f.app.query(`DELETE FROM ${f.orders} WHERE id = 'o3'`); await f.app.query(`INSERT INTO ${f.orders} VALUES ('o3', 't1', 'open', NULL, '0000', NULL)`); });
  ew = asWindow(o, r.raw);
  record('delete then reinsert of one key', `${ops(r.snap)}; "no delete": ${v('effect.none', sel(f.orders, 'delete', 'orders/o3'), r.snap)}`, `${ops(ew)}; "no delete": ${v('effect.none', sel(f.orders, 'delete', 'orders/o3'), ew)}`);
  assert.equal(v('effect.none', sel(f.orders, 'delete', 'orders/o3'), ew), 'fail');
  // 4. Exact counts: four inserts and one delete, one of the inserts deleted again.
  r = await both(() => f.app.query(`INSERT INTO ${f.payouts} VALUES ('a', 'o1', 1), ('b', 'o1', 1), ('c', 'o1', 1); DELETE FROM ${f.payouts} WHERE id = 'a'; INSERT INTO ${f.payouts} VALUES ('d', 'o1', 1)`));
  ew = asWindow(o, r.raw);
  const count = (op, n, w) => v('effect.count', sel(f.payouts, op), w, { expected: n });
  record('exact counts (4 inserts, 1 delete)', `inserts=4: ${count('insert', 4, r.snap)}, deletes=1: ${count('delete', 1, r.snap)} (${r.snap.events.filter(e => e.operation === 'insert').length} net inserts)`,
    `inserts=4: ${count('insert', 4, ew)}, deletes=1: ${count('delete', 1, ew)}`);
  assert.deepEqual([count('insert', 4, ew), count('delete', 1, ew)], ['pass', 'pass']);
  await f.admin.query(`DELETE FROM ${f.payouts}`);
  // 5. Absence on an observed table while a platform job writes elsewhere (Supabase-style auth table).
  r = await both(async () => { await f.app.query(`UPDATE ${f.orders} SET status = 'viewed' WHERE id = 'o1'`); await f.admin.query(`UPDATE auth.${job} SET seen = now() WHERE id = 1`); });
  ew = asWindow(o, r.raw);
  record('table-wide absence with a background writer (auth job, supabase ignore list)', `"no payout inserted": ${v('effect.none', sel(f.payouts, 'insert'), r.snap)} (quiescent: ${r.snap.exact?.[1]?.quiescent === true})`,
    `"no payout inserted": ${v('effect.none', sel(f.payouts, 'insert'), ew)}; other tables: ignored ${r.raw.wal.others.ignored}, unlisted ${r.raw.wal.others.unlisted.length}`);
  assert.equal(v('effect.none', sel(f.payouts, 'insert'), ew), 'pass'); assert.equal(v('effect.none', sel(f.payouts, 'insert'), r.snap), 'missing');
  assert.equal(r.raw.wal.others.ignored, 1);
  // 6. A named-row absence and a planted write through a second connection.
  r = await both(() => f.other.query(`UPDATE ${f.orders} SET status = 'tampered' WHERE id = 'o2'`));
  ew = asWindow(o, r.raw);
  record('planted write through a second connection', `"o2 not updated": ${v('effect.none', sel(f.orders, 'update', 'orders/o2'), r.snap)}; "o1 not updated": ${v('effect.none', sel(f.orders, 'update', 'orders/o1'), r.snap)}`,
    `"o2 not updated": ${v('effect.none', sel(f.orders, 'update', 'orders/o2'), ew)}; "o1 not updated": ${v('effect.none', sel(f.orders, 'update', 'orders/o1'), ew)}`);
  assert.deepEqual([v('effect.none', sel(f.orders, 'update', 'orders/o2'), ew), v('effect.none', sel(f.orders, 'update', 'orders/o1'), ew)], ['fail', 'pass']);
  t.diagnostic(`COMPLETENESS-TABLE ${JSON.stringify(rows)}`);
}
