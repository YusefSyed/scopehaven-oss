// Live checks of the MySQL snapshot observer against a disposable server. Skipped unless
// SCOPEHAVEN_MYSQL_LIVE=user:password@127.0.0.1:port names an administrator of a throwaway server.
// SCOPEHAVEN_MYSQL_LIVE_KEY names the server's RSA public key file (public_key.pem in its data directory, copied
// out of the container): full caching_sha2 authentication encrypts only to a pinned key.
// Each test makes its own database (synthetic rows) and a SELECT-only reader (plus PROCESS where a test declares
// tableIds), and drops both afterwards.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mysqlConnect } from './mysql-wire.mjs';
import { createMysqlSnapshotObserver } from './mysql-snapshot.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';

const live = /^([^:@/]+):([^@]+)@127\.0\.0\.1:(\d+)$/.exec(process.env.SCOPEHAVEN_MYSQL_LIVE ?? '');
const skip = live ? false : 'set SCOPEHAVEN_MYSQL_LIVE=user:password@127.0.0.1:port (a disposable server) to run';
const serverKey = process.env.SCOPEHAVEN_MYSQL_LIVE_KEY ? readFileSync(process.env.SCOPEHAVEN_MYSQL_LIVE_KEY, 'utf8') : null;
const OLD = '2026-01-01 00:00:00';
// CREATE_TIME has whole seconds: a mark in the same second as a table's creation or rebuild cannot follow it.
const nextSecond = () => new Promise(resolve => setTimeout(resolve, 1100));

async function fixture(t, { column = 'TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)', process = false, partition = '' } = {}) {
  const [, adminUser, adminPassword, port] = live;
  const sx = randomBytes(4).toString('hex'), db = `sh_live_${sx}`, reader = `sh_reader_${sx}`, readerPass = randomBytes(12).toString('base64url');
  const admin = await mysqlConnect({ host: '127.0.0.1', port: Number(port), database: 'mysql', user: adminUser, password: adminPassword, serverPublicKey: serverKey });
  const q = sql => admin.query(sql);
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-mysql-live-')), audit = join(dir, 'SOURCE-AUDIT.md');
  writeFileSync(audit, 'synthetic: no writer sets notes.updated_at\n');
  t.after(async () => {
    try { await q(`DROP DATABASE IF EXISTS ${db}`); await q(`DROP USER IF EXISTS '${reader}'@'%'`); }
    finally { admin.close(); rmSync(dir, { recursive: true, force: true }); }
  });
  await q(`CREATE DATABASE ${db}`);
  await q(`CREATE USER '${reader}'@'%' IDENTIFIED BY '${readerPass}'`);
  await q(`GRANT SELECT ON ${db}.* TO '${reader}'@'%'`);
  if (process) await q(`GRANT PROCESS ON *.* TO '${reader}'@'%'`);
  const table = (name, suffix = '') => q(`CREATE TABLE ${db}.${name} (id VARCHAR(32) PRIMARY KEY, body TEXT, updated_at ${column}) ENGINE=InnoDB${suffix}`);
  await table('notes', partition);
  // Setup writes old stamps directly; inside a window only the server sets them, as the audit records.
  await q(`INSERT INTO ${db}.notes (id, body, updated_at) VALUES ('n1', 'first', '${OLD}'), ('n2', 'second', '${OLD}')`);
  await nextSecond();
  const env = { SCOPEHAVEN_TARGET_MYSQL_READER: `${reader}:${readerPass}`, ...(serverKey ? { SCOPEHAVEN_TARGET_MYSQL_READER_RSA_PUBLIC_KEY: serverKey } : {}) };
  const observer = (extra = {}) => createMysqlSnapshotObserver({ instanceId: 'mysql-snapshot-live', env, host: '127.0.0.1', port: Number(port), database: db, credentialEnv: 'SCOPEHAVEN_TARGET_MYSQL_READER',
    tables: [{ table: 'notes', key: 'id', changeColumn: { column: 'updated_at', audit } }], maxCommitLagMs: 1000, watchedResources: ['notes/n1', 'notes/n2'], ...extra });
  const window = async (o, between = async () => {}) => { const m0 = await o.mark(); await between(); return collectWindow(o, m0, await o.mark()); };
  return { q, db, reader, observer, window, table };
}
const none = resource => ({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'notes', operation: 'update', ...(resource ? { resource } : {}) } });
const ops = w => w.events.map(e => `${e.operation} ${e.resource}`).sort();

test('live mysql: the reader signs in (caching_sha2, full auth); an untouched named row is exact; an update and a write-and-revert are updates; inserts and deletes are net', { skip }, async t => {
  const f = await fixture(t), o = f.observer();
  const quiet = await f.window(o);
  assert.deepEqual([quiet.coverage, quiet.events.length, quiet.exact[0].violated], ['net-only', 0, false]);
  assert.equal(evaluateEffectAssertion(none('notes/n1'), [quiet]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(none(), [quiet]).verdict, 'missing', 'a table-wide selector also covers rows never seen');
  const updated = await f.window(o, () => f.q(`UPDATE ${f.db}.notes SET body = 'changed' WHERE id = 'n1'`));
  assert.deepEqual(ops(updated), ['update notes/n1']);
  assert.equal(evaluateEffectAssertion(none('notes/n1'), [updated]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(none('notes/n2'), [updated]).verdict, 'pass');
  // Written and reverted inside one window: the content is the same, the server moved the stamp.
  const reverted = await f.window(o, async () => { await f.q(`UPDATE ${f.db}.notes SET body = 'x' WHERE id = 'n2'`); await f.q(`UPDATE ${f.db}.notes SET body = 'second' WHERE id = 'n2'`); });
  assert.ok(ops(reverted).includes('update notes/n2'), ops(reverted).join(', '));
  assert.equal(evaluateEffectAssertion(none('notes/n2'), [reverted]).verdict, 'fail');
  const churn = await f.window(o, async () => { await f.q(`INSERT INTO ${f.db}.notes (id, body) VALUES ('n3', 'third')`); await f.q(`DELETE FROM ${f.db}.notes WHERE id = 'n1'`); });
  assert.deepEqual(ops(churn).filter(x => !x.startsWith('update')), ['delete notes/n1', 'insert notes/n3']);
});

test('live mysql: content changed under an unchanged stamp voids the table; a rebuilt or altered table and a reader without SELECT fail the window', { skip }, async t => {
  const f = await fixture(t), o = f.observer();
  // An explicit write of the column keeps the old stamp (what the audit rules out): the table is violated, no event reported.
  const sneaky = await f.window(o, () => f.q(`UPDATE ${f.db}.notes SET body = 'sneaky', updated_at = updated_at WHERE id = 'n2'`));
  assert.deepEqual([sneaky.exact[0].violated, sneaky.events.length], [true, 0]);
  assert.notEqual(evaluateEffectAssertion(none('notes/n1'), [sneaky]).verdict, 'pass');
  for (const [label, ddl] of [['rebuild', `ALTER TABLE ${f.db}.notes ENGINE=InnoDB`], ['optimize', `OPTIMIZE TABLE ${f.db}.notes`], ['added column', `ALTER TABLE ${f.db}.notes ADD COLUMN extra INT`]]) {
    await nextSecond();
    const w = await f.window(o, () => f.q(ddl));
    assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'relation-rewritten', 0], label);
  }
  // TRUNCATE keeps CREATE_TIME on MySQL 8.4 and removes every row: it reads as deletes.
  await nextSecond();
  const truncated = await f.window(o, () => f.q(`TRUNCATE TABLE ${f.db}.notes`));
  assert.deepEqual([truncated.coverage, ops(truncated)], ['net-only', ['delete notes/n1', 'delete notes/n2']]);
  // A window that starts in the same second as the last rebuild cannot rule out another rebuild in that second.
  await f.q(`ALTER TABLE ${f.db}.notes ENGINE=InnoDB`);
  const sameSecond = await f.window(o, () => f.q(`ALTER TABLE ${f.db}.notes ENGINE=InnoDB`));
  assert.ok([['failed', 'relation-unverified'], ['failed', 'relation-rewritten']].some(([c, r]) => sameSecond.coverage === c && sameSecond.reason === r), `${sameSecond.coverage} ${sameSecond.reason}`);
  assert.equal(sameSecond.events.length, 0);
  const revoked = await f.window(o, () => f.q(`REVOKE SELECT ON ${f.db}.* FROM '${f.reader}'@'%'`));
  assert.deepEqual([revoked.coverage, revoked.events.length], ['failed', 0]);
  assert.notEqual(evaluateEffectAssertion(none('notes/n1'), [revoked]).verdict, 'pass');
});

test('live mysql: only a TIMESTAMP the server sets on insert and update is a change column; a partitioned table is refused', { skip }, async t => {
  for (const [label, options, reason] of [
    ['DATETIME (stamped in the writer\'s time zone)', { column: 'DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)' }, 'change-column-not-server-maintained'],
    ['a constant default', { column: "TIMESTAMP(6) NOT NULL DEFAULT '2020-01-01 00:00:00' ON UPDATE CURRENT_TIMESTAMP(6)" }, 'change-column-not-server-maintained'],
    ['ON UPDATE only', { column: 'TIMESTAMP(6) NULL ON UPDATE CURRENT_TIMESTAMP(6)' }, 'change-column-not-server-maintained'],
    ['partitioned', { partition: ' PARTITION BY KEY(id) PARTITIONS 2' }, 'relation-partitioned-refused']]) {
    const f = await fixture(t, options), w = await f.window(f.observer());
    assert.deepEqual([w.coverage, w.reason], ['failed', reason], label);
  }
});

test('live mysql: a writer four hours behind UTC still moves a TIMESTAMP(0) stamp; REPLACE stamps the new row', { skip }, async t => {
  const f = await fixture(t, { column: 'TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP' }), o = f.observer();
  const behind = await f.window(o, async () => { await f.q("SET SESSION time_zone = '-04:00'"); await f.q(`UPDATE ${f.db}.notes SET body = 'x' WHERE id = 'n1'`); await f.q(`UPDATE ${f.db}.notes SET body = 'first' WHERE id = 'n1'`); await f.q('SET SESSION time_zone = SYSTEM'); });
  assert.notEqual(evaluateEffectAssertion(none('notes/n1'), [behind]).verdict, 'pass');
  await nextSecond();
  const replaced = await f.window(o, async () => { await f.q(`REPLACE INTO ${f.db}.notes (id, body) VALUES ('n2', 'x')`); await f.q(`REPLACE INTO ${f.db}.notes (id, body) VALUES ('n2', 'second')`); });
  assert.equal(evaluateEffectAssertion(none('notes/n2'), [replaced]).verdict, 'fail');
});

test('live mysql: EXCHANGE PARTITION keeps CREATE_TIME (stated limit); with tableIds it, a same-second RENAME swap and TRUNCATE fail the window', { skip }, async t => {
  const f = await fixture(t, { process: true });
  // A partitioned twin with the same rows, made seconds after notes.
  await f.table('pt', ' PARTITION BY RANGE COLUMNS(id) (PARTITION p0 VALUES LESS THAN (MAXVALUE))');
  await f.q(`INSERT INTO ${f.db}.pt SELECT * FROM ${f.db}.notes`);
  await nextSecond();
  const exchange = () => f.q(`ALTER TABLE ${f.db}.pt EXCHANGE PARTITION p0 WITH TABLE ${f.db}.notes`);
  const blind = await f.window(f.observer(), async () => { await f.q(`UPDATE ${f.db}.notes SET body = 'evil' WHERE id = 'n1'`); await exchange(); });
  assert.deepEqual([blind.coverage, evaluateEffectAssertion(none('notes/n1'), [blind]).verdict], ['net-only', 'pass'], 'premise: a SELECT-only reader cannot see the exchange');
  await nextSecond();
  const seen = await f.window(f.observer({ tableIds: true }), async () => { await f.q(`UPDATE ${f.db}.notes SET body = 'evil' WHERE id = 'n2'`); await exchange(); });
  assert.deepEqual([seen.coverage, seen.reason, seen.events.length], ['failed', 'relation-rewritten', 0]);
  // A twin created in the same second as a rebuilt notes, renamed into its place.
  await f.q(`DROP TABLE ${f.db}.pt`);
  await f.q(`ALTER TABLE ${f.db}.notes ENGINE=InnoDB`); await f.table('twin'); await f.q(`INSERT INTO ${f.db}.twin SELECT * FROM ${f.db}.notes`);
  const created = (await f.q(`SELECT TABLE_NAME, CREATE_TIME FROM information_schema.TABLES WHERE TABLE_SCHEMA = '${f.db}' ORDER BY 1`)).rows;
  await nextSecond();
  const renamed = await f.window(f.observer({ tableIds: true }), () => f.q(`RENAME TABLE ${f.db}.notes TO ${f.db}.old, ${f.db}.twin TO ${f.db}.notes`));
  t.diagnostic(`notes and twin created ${created[0][1] === created[1][1] ? 'in the same second' : 'in different seconds'}: ${renamed.coverage} ${renamed.reason}`);
  if (created[0][1] === created[1][1]) assert.deepEqual([renamed.coverage, renamed.reason], ['failed', 'relation-rewritten']);
  else assert.equal(renamed.coverage, 'failed', 'created in different seconds: CREATE_TIME alone already differs');
  // TRUNCATE keeps CREATE_TIME (it reads as deletes without tableIds) but gives the table new ids.
  await nextSecond();
  const truncated = await f.window(f.observer({ tableIds: true }), () => f.q(`TRUNCATE TABLE ${f.db}.notes`));
  assert.deepEqual([truncated.coverage, truncated.reason], ['failed', 'relation-rewritten']);
});
