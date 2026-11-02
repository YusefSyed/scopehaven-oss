// pg-wire and pg-snapshot against a scripted fake Postgres server (protocol 3.0,
// server-side SCRAM-SHA-256 and md5 verification, simple-query responses). No
// Docker or real database: behaviour that needs a real server (VACUUM, HOT
// updates, row locks, transactions spanning marks) is in pg.live.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { pgConnect, PgError } from './pg-wire.mjs';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { collectWindow, evaluateEffectAssertion, validateWindow } from './events.mjs';
import { decideEffects, backendObserved } from '../../src/http-effects.mjs';

import { fakePostgres, scriptedDb, USER, PASSWORD } from './fixtures/fake-postgres.mjs';

test('pg-wire: SCRAM-SHA-256 and md5 log in and query; a wrong password and a wrong server signature are refused', async t => {
  const select = s => /^select 1/i.test(s) ? [['1']] : [];
  for (const auth of ['scram', 'md5']) {
    const server = await fakePostgres(t, { auth, onQuery: select });
    const allowMd5 = auth === 'md5'; // md5 only when operator code opts in
    const client = await pgConnect({ host: '127.0.0.1', port: server.port, database: 'app', user: USER, password: PASSWORD, allowMd5 });
    const [result] = await client.query('select 1');
    assert.deepEqual(result.rows, [['1']], auth); client.close();
    await assert.rejects(pgConnect({ host: '127.0.0.1', port: server.port, database: 'app', user: USER, password: 'wrong', allowMd5 }), e => e instanceof PgError && e.code === 'authentication-failed' && e.sqlState === '28P01', auth);
  }
  const forged = await fakePostgres(t, { auth: 'scram-bad-signature' });
  await assert.rejects(pgConnect({ host: '127.0.0.1', port: forged.port, database: 'app', user: USER, password: PASSWORD }), e => e.code === 'server-signature-mismatch');
});

test('pg-wire: cleartext password authentication is refused before any password is sent', async t => {
  const server = await fakePostgres(t, { auth: 'cleartext' });
  await assert.rejects(pgConnect({ host: '127.0.0.1', port: server.port, database: 'app', user: USER, password: PASSWORD }), e => e.code === 'cleartext-password-refused');
  assert.notEqual(server.cleartextReceived, true);
});

test('pg-wire: only the literal 127.0.0.1 is dialled, and server error text never surfaces', async t => {
  for (const host of ['localhost', '127.0.0.2', '::1', '0.0.0.0', 'db.example.com', '127.1'])
    await assert.rejects(pgConnect({ host, port: 5432, database: 'app', user: USER, password: PASSWORD }), e => e.code === 'host-must-be-literal-loopback', host);
  const server = await fakePostgres(t, { onQuery: () => ({ error: '42501' }) });
  const client = await pgConnect({ host: '127.0.0.1', port: server.port, database: 'app', user: USER, password: PASSWORD });
  await assert.rejects(client.query('select 1'), e => e.sqlState === '42501' && !String(e.message).includes('fake server message'));
  client.close();
});

test('pg-wire: the password is not kept by the client after the handshake', async t => {
  const server = await fakePostgres(t);
  const client = await pgConnect({ host: '127.0.0.1', port: server.port, database: 'app', user: USER, password: PASSWORD });
  assert.ok(!inspect(client, { showHidden: true, depth: 6 }).includes(PASSWORD) && !JSON.stringify(Object.entries(client)).includes(PASSWORD));
  client.close();
  // In a separate process: after login and a forced GC, the heap holds no copy of the password.
  const script = fileURLToPath(new URL('./pg-wire.mjs', import.meta.url));
  const heapHolds = async keep => {
  const child = spawn(process.execPath, ['--expose-gc', '--input-type=module', '-e', `
    import { pgConnect } from ${JSON.stringify(script)};
    import { writeHeapSnapshot } from 'node:v8';
    import { readFileSync, rmSync } from 'node:fs';
    const chunks = []; for await (const c of process.stdin) chunks.push(c);
    // The control (keep) is a caller that does hold on to it; otherwise the password exists only in the call.
    let client = await pgConnect({ host: '127.0.0.1', port: ${server.port}, database: 'app', user: 'reader',
      password: ${keep} ? (globalThis.kept = Buffer.concat(chunks).toString('utf8')) : Buffer.concat(chunks).toString('utf8') });
    chunks.length = 0; await client.query('select 1');
    for (let i = 0; i < 4; i++) { globalThis.gc(); await new Promise(r => setTimeout(r, 20)); }
    const file = writeHeapSnapshot(); const heap = readFileSync(file, 'utf8'); rmSync(file);
    // The needle is built only now, from hex, so the child's own code never holds the password.
    process.stdout.write(JSON.stringify({ found: heap.includes(Buffer.from('${Buffer.from(PASSWORD).toString('hex')}', 'hex').toString('utf8')) }));
    client.close();
  `], { stdio: ['pipe', 'pipe', 'inherit'], cwd: fileURLToPath(new URL('.', import.meta.url)) });
  let out = ''; child.stdout.on('data', d => { out += d; });
  child.stdin.end(PASSWORD);
  await new Promise(r => child.once('exit', r));
  return JSON.parse(out).found;
  };
  assert.equal(await heapHolds(true), true, 'control: a kept reference is found');
  assert.equal(await heapHolds(false), false, 'the client keeps no copy');
});

const env = { SCOPEHAVEN_TARGET_DB_READER: `${USER}:${PASSWORD}` };
const observerOn = (server, extra = {}) => createPgSnapshotObserver({ env, host: '127.0.0.1', port: server.port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables: [{ table: 'Chat', key: 'id' }],
  watchedResources: ['Chat/c1', 'Chat/c2'], ...extra });
async function window(t, before, after, extra = {}) {
  const server = await scriptedDb(t, [before, after]);
  const o = observerOn(server, extra);
  const from = await o.mark(), to = await o.mark();
  return collectWindow(o, from, to);
}
const none = resource => ({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', ...(resource ? { resource } : {}) } });
const exists = resource => ({ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', resource } });

test('pg-snapshot: an unchanged xmin proves no committed update (exact); a new xmin is an update', async t => {
  const rows = [['c1', '700', 'h1'], ['c2', '701', 'h2']];
  const quiet = await window(t, { snapshot: '800:800:', tables: { Chat: rows } }, { snapshot: '805:805:', tables: { Chat: rows } });
  assert.equal(quiet.coverage, 'net-only'); assert.equal(quiet.exact[0].method, 'xmin'); assert.equal(quiet.exact[0].auditSha256, null);
  assert.equal(evaluateEffectAssertion(none('Chat/c1'), [quiet]).verdict, 'pass');
  // Other transactions completed during the window (xmax 800 -> 805): a table-wide selector is not exact.
  assert.deepEqual(quiet.exact[0].marks, { startXmax: '800', endXmax: '805', inProgress: 0 }); assert.equal(quiet.exact[0].quiescent, undefined);
  assert.equal(evaluateEffectAssertion(none(), [quiet]).verdict, 'missing');
  // A write and its revert inside the window: same content hash, new xmin. Still an update.
  const reverted = await window(t, { snapshot: '800:800:', tables: { Chat: rows } }, { snapshot: '806:806:', tables: { Chat: [['c1', '803', 'h1'], ['c2', '701', 'h2']] } });
  assert.deepEqual(reverted.events.map(e => [e.operation, e.resource]), [['update', 'Chat/c1']]);
  assert.equal(evaluateEffectAssertion(none('Chat/c1'), [reverted]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(exists('Chat/c1'), [reverted]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(none('Chat/c2'), [reverted]).verdict, 'pass');
});

test('pg-snapshot: freezing, inserts and deletes are never exact; content changed under the same xmin is a violation', async t => {
  const frozen = await window(t, { snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1']] } }, { snapshot: '801:801:', tables: { Chat: [['c1', '2', 'h1']] } });
  assert.equal(frozen.events.length, 0, 'freezing is not an update');
  assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [frozen]).verdict, 'pass', 'a frozen row is ambiguous');
  const churn = await window(t, { snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1'], ['gone', '701', 'h2']] } }, { snapshot: '802:802:', tables: { Chat: [['c1', '700', 'h1'], ['new', '801', 'h3']] } });
  assert.deepEqual(churn.events.map(e => e.operation).sort(), ['delete', 'insert']);
  assert.deepEqual(churn.exact[0].ambiguousResources.sort(), ['Chat/gone', 'Chat/new']);
  assert.equal(evaluateEffectAssertion(none('Chat/c1'), [churn]).verdict, 'pass');
  assert.notEqual(evaluateEffectAssertion(none(), [churn]).verdict, 'pass', 'a table-wide selector cannot be exact with ambiguous rows');
  const odd = await window(t, { snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1']] } }, { snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h9']] } });
  assert.equal(odd.exact[0].violated, true); assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [odd]).verdict, 'pass');
});

test('pg-snapshot: a write transaction in progress at the end mark makes the window partial (xip)', async t => {
  const rows = [['c1', '700', 'h1']];
  const inflight = await window(t, { snapshot: '800:800:', tables: { Chat: rows } }, { snapshot: '803:806:803', tables: { Chat: rows } });
  assert.deepEqual([inflight.coverage, inflight.reason], ['partial', 'transaction-in-flight-at-window-end']);
  assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [inflight]).verdict, 'pass');
  // The newest writer is not in xip (its id is not below xmax): the transactionid lock shows it.
  const newest = await window(t, { snapshot: '800:800:', tables: { Chat: rows } }, { snapshot: '808:808:', writers: '{808}', tables: { Chat: rows } });
  assert.deepEqual([newest.coverage, newest.reason], ['partial', 'transaction-in-flight-at-window-end']);
  const lateWriter = await window(t, { snapshot: '800:800:', tables: { Chat: rows } }, { snapshot: '808:808:', writersAtEnd: '{809}', tables: { Chat: rows } });
  assert.equal(lateWriter.coverage, 'partial', 'a writer seen at the end of the mark counts too');
  // One in progress at the start mark that committed inside the window: its update is seen, and the end is clean.
  const committed = await window(t, { snapshot: '799:800:799', tables: { Chat: rows } }, { snapshot: '801:801:', tables: { Chat: [['c1', '799', 'h2']] } });
  assert.equal(committed.coverage, 'net-only'); assert.deepEqual(committed.events.map(e => e.operation), ['update']);
});

test('pg-snapshot: a role without SELECT on a table fails the window, never complete and empty', async t => {
  const w = await window(t, { snapshot: '800:800:', tables: { Chat: 'denied' } }, { snapshot: '801:801:', tables: { Chat: [] } });
  assert.deepEqual([w.coverage, w.reason], ['failed', 'permission-denied']);
  assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [w]).verdict, 'pass');
});

test('pg-snapshot: the credential comes only from the SCOPEHAVEN_TARGET_ namespace, and the host only from loopback', async t => {
  const server = await scriptedDb(t, []);
  assert.throws(() => observerOn(server, { credentialEnv: 'PGPASSWORD' }), /SCOPEHAVEN_TARGET_ namespace/);
  assert.throws(() => observerOn(server, { host: 'localhost' }), /literal loopback address 127\.0\.0\.1/);
  assert.throws(() => observerOn(server, { tables: [{ table: 'Chat"; DROP TABLE x; --', key: 'id' }] }), /Unsupported SQL identifier/);
  // A missing credential fails the mark (no anonymous or default login).
  const o = createPgSnapshotObserver({ env: {}, host: '127.0.0.1', port: server.port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables: [{ table: 'Chat', key: 'id' }] });
  const from = await o.mark(), to = await o.mark();
  assert.deepEqual([(await collectWindow(o, from, to)).coverage, (await o.collect(from, to)).reason], ['failed', 'credential-missing']);
});

test('pg-snapshot: explicit limits: a server statement timeout, a stalled server and an over-limit table all fail the mark within its bound', async t => {
  const rows = [['c1', '700', 'h1'], ['c2', '701', 'h2'], ['c3', '702', 'h3']];
  const timedOut = await window(t, { snapshot: '800:800:', tables: { Chat: { error: '57014' } } }, { snapshot: '801:801:', tables: { Chat: rows } });
  assert.deepEqual([timedOut.coverage, timedOut.reason], ['failed', 'statement-timeout']);
  // A server that never answers: the client gives up at statementTimeoutMs + 1 s.
  const stalled = await scriptedDb(t, [{ snapshot: '800:800:', tables: { Chat: { stall: true } } }]);
  const slow = observerOn(stalled, { statementTimeoutMs: 500 });
  const started = Date.now(), mark = await slow.mark();
  assert.ok(Date.now() - started < 3000, `the mark gave up within its bound (${Date.now() - started} ms)`);
  assert.deepEqual([(await slow.collect(mark, mark)).coverage, (await slow.collect(mark, mark)).reason], ['failed', 'read-timeout-or-closed']);
  // More rows than rowsPerTable: never a truncated snapshot.
  const capped = await scriptedDb(t, [{ snapshot: '800:800:', tables: { Chat: rows } }, { snapshot: '801:801:', tables: { Chat: rows } }]);
  const small = observerOn(capped, { rowsPerTable: 2 });
  const from = await small.mark(), to = await small.mark();
  assert.deepEqual([(await collectWindow(small, from, to)).coverage, (await small.collect(from, to)).reason], ['failed', 'row-limit']);
  // The limits themselves are bounded.
  assert.throws(() => observerOn(capped, { rowsPerTable: 0 }), /rowsPerTable must be an integer from 1 to 200000/);
  assert.throws(() => observerOn(capped, { statementTimeoutMs: 100 }), /statementTimeoutMs must be an integer from 500 to 60000/);
  assert.throws(() => observerOn(capped, { statementTimeoutMs: 120000 }), /statementTimeoutMs must be an integer from 500 to 60000/);
});


// ---- Declared tables, row-level security, row identity and connection limits ----
const rowsAt = (...rows) => ({ snapshot: '800:800:', tables: { Chat: rows } });
const updated = (at, ...rows) => ({ snapshot: at, tables: { Chat: rows } });

test('a table name declared twice (two schemas) is refused, never silently collapsed', async t => {
  const server = await scriptedDb(t, []);
  assert.throws(() => observerOn(server, { tables: [{ table: 'Chat', key: 'id' }, { table: 'Chat', key: 'id', schema: 'audit' }] }), /Each table name is declared once per observer/);
});

test('row-level security is switched off for the mark, so a filtered role fails instead of reading short', async t => {
  const log = [];
  const server = await scriptedDb(t, [rowsAt(['c1', '700', 'h1']), rowsAt(['c1', '700', 'h1'])], log);
  const o = observerOn(server); const from = await o.mark(), to = await o.mark();
  assert.equal((await collectWindow(o, from, to)).coverage, 'net-only');
  assert.ok(log.includes('SET LOCAL row_security = off'), 'the mark sets row_security = off');
  // With row_security off, Postgres refuses (42501) where a policy would filter rows: the mark fails.
  const filtered = await window(t, { snapshot: '800:800:', tables: { Chat: { error: '42501' } } }, rowsAt(['c1', '700', 'h1']));
  assert.deepEqual([filtered.coverage, filtered.reason], ['failed', 'permission-denied']);
});

test('a selected row absent at either mark is never exact (insert-update-delete inside the window, or a selector typo)', async t => {
  // The connector watches every row a check names, typos included.
  const watched = { watchedResources: ['Chat/c1', 'Chat/c9', 'chat/c1'] };
  // c9 was inserted, updated and deleted inside the window: absent at both marks.
  const churned = await window(t, rowsAt(['c1', '700', 'h1']), updated('806:806:', ['c1', '700', 'h1']), watched);
  assert.notEqual(evaluateEffectAssertion(none('Chat/c9'), [churned]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(none('Chat/c1'), [churned]).verdict, 'pass', 'a watched row seen at both marks is still exact');
  // A typo in the selector ("chat/c1") while c1 really was updated.
  const typo = await window(t, rowsAt(['c1', '700', 'h1']), updated('806:806:', ['c1', '804', 'h2']), watched);
  assert.notEqual(evaluateEffectAssertion(none('chat/c1'), [typo]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(none('Chat/c1'), [typo]).verdict, 'fail');
  // Without the connector's watched rows, no row-specific absence is exact at all.
  const server = await scriptedDb(t, [rowsAt(['c1', '700', 'h1']), rowsAt(['c1', '700', 'h1'])]);
  const unwatched = observerOn(server, { watchedResources: [] }); const from = await unwatched.mark(), to = await unwatched.mark();
  assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [await collectWindow(unwatched, from, to)]).verdict, 'pass');
});

test('only heap tables are read; xmin 0 or 1 and a replaced table (new oid) are never exact', async t => {
  for (const [relkind, am] of [['f', ''], ['v', ''], ['r', 'columnar'], ['m', 'heap']]) {
    const w = await window(t, { ...rowsAt(['c1', '0', 'h1']), relations: { Chat: [['16384', relkind, am]] } }, rowsAt(['c1', '0', 'h1']));
    assert.deepEqual([w.coverage, w.reason], ['failed', 'relation-not-heap-table'], `${relkind}/${am}`);
  }
  // Rows that cannot be identified across the marks fail the window, with no events.
  const zero = await window(t, rowsAt(['c1', '0', 'h1']), updated('806:806:', ['c1', '0', 'h1']));
  assert.deepEqual([zero.coverage, zero.reason, zero.events.length], ['failed', 'invalid-row-version', 0]); assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [zero]).verdict, 'pass');
  const swapped = await window(t, rowsAt(['c1', '700', 'h1']), { ...updated('806:806:', ['c1', '700', 'h1']), relations: { Chat: [['99999', 'r', 'heap']] } });
  assert.deepEqual([swapped.coverage, swapped.reason], ['failed', 'relation-unverified']); assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [swapped]).verdict, 'pass');
  // A duplicated or NULL key: the rows cannot be matched.
  for (const rows of [[['c1', '700', 'h1'], ['c1', '701', 'h2']], [['c1', '700', 'h1'], [null, '701', 'h2']]]) {
    const dup = await window(t, rowsAt(...rows), updated('806:806:', ...rows));
    assert.deepEqual([dup.coverage, dup.reason], ['failed', 'duplicate-key']); assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [dup]).verdict, 'pass');
  }
  const missing = await window(t, { ...rowsAt(), relations: { Chat: [] } }, rowsAt());
  assert.deepEqual([missing.coverage, missing.reason], ['failed', 'table-missing']);
});

test('standby refused, search_path pinned and names schema-qualified, xmin wraparound coincidence is ambiguous', async t => {
  const standby = await window(t, { ...rowsAt(['c1', '700', 'h1']), recovery: 'true' }, rowsAt(['c1', '700', 'h1']));
  assert.deepEqual([standby.coverage, standby.reason], ['failed', 'standby-refused']);
  const log = [];
  const server = await scriptedDb(t, [rowsAt(['c1', '700', 'h1']), rowsAt(['c1', '700', 'h1'])], log);
  const o = observerOn(server); await o.mark();
  assert.ok(log.includes('SET LOCAL search_path = pg_catalog'));
  assert.ok(log.some(st => /FROM "public"\."Chat" AS r/.test(st)), 'the table is schema-qualified');
  assert.ok(log.every(st => !/\bFROM "Chat"/.test(st)));
  // 2^32 + 5 is assigned during the window; a row whose unchanged 32-bit xmin is 5 could be its new version.
  const big = n => (4294967296n + BigInt(n)).toString();
  const wrapped = await window(t, { snapshot: `${big(4)}:${big(4)}:`, tables: { Chat: [['c1', '5', 'h1'], ['c2', '700', 'h2']] } }, { snapshot: `${big(10)}:${big(10)}:`, tables: { Chat: [['c1', '5', 'h1'], ['c2', '700', 'h2']] } });
  assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [wrapped]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(none('Chat/c2'), [wrapped]).verdict, 'pass', 'a row whose xmin is outside the window ids stays exact');
});

test('trust, md5 (by default), weak SCRAM iterations and an echoed SCRAM nonce are refused', async t => {
  const login = async (auth, extra = {}) => pgConnect({ host: '127.0.0.1', port: (await fakePostgres(t, { auth })).port, database: 'app', user: USER, password: PASSWORD, ...extra });
  await assert.rejects(login('trust'), e => e.code === 'authentication-not-challenged');
  await assert.rejects(login('md5'), e => e.code === 'md5-authentication-refused');
  await assert.rejects(login('scram-low-iterations'), e => e.code === 'authentication-failed');
  await assert.rejects(login('scram-echo-nonce'), e => e.code === 'authentication-failed');
  (await login('scram')).close();
});

test('a malformed ErrorResponse never hangs, and only a valid SQLSTATE surfaces', async t => {
  let answer = { rawError: Buffer.from('Cabc') }; // a field with no NUL terminator
  const server = await fakePostgres(t, { onQuery: () => answer });
  const client = await pgConnect({ host: '127.0.0.1', port: server.port, database: 'app', user: USER, password: PASSWORD });
  const started = Date.now();
  await assert.rejects(client.query('select 1'), e => e.code === 'query-failed' && e.sqlState === null);
  assert.ok(Date.now() - started < 2000);
  answer = { rawError: Buffer.concat([Buffer.from('Cnot a code; injected'), Buffer.from([0, 0])]) };
  await assert.rejects(client.query('select 1'), e => e.sqlState === null && !String(e.message).includes('injected'));
  client.close();
});

test('a connect that never completes settles at the connect timeout (wedged listener)', { skip: process.platform === 'win32' }, async t => {
  const listener = spawn(process.execPath, ['-e', "const s=require('net').createServer(()=>{});s.listen({port:0,host:'127.0.0.1',backlog:1},()=>console.log(s.address().port))"], { stdio: ['ignore', 'pipe', 'inherit'] });
  const fillers = [];
  t.after(() => { for (const f of fillers) f.destroy(); try { process.kill(listener.pid, 'SIGCONT'); } catch {} listener.kill('SIGKILL'); });
  const port = Number(await new Promise(r => listener.stdout.once('data', d => r(String(d).trim()))));
  // Watchdog: if this test process dies before t.after runs, the stopped listener is still resumed and killed.
  const watchdog = spawn('/bin/sh', ['-c', `sleep 20; kill -CONT ${listener.pid} 2>/dev/null; kill -9 ${listener.pid} 2>/dev/null`], { detached: true, stdio: 'ignore' });
  watchdog.unref(); t.after(() => { try { process.kill(-watchdog.pid, 'SIGKILL'); } catch {} });
  process.kill(listener.pid, 'SIGSTOP');
  const { connect } = await import('node:net');
  for (let i = 0; i < 12; i++) { const f = connect({ host: '127.0.0.1', port }); f.on('error', () => {}); fillers.push(f); }
  await new Promise(r => setTimeout(r, 300));
  const started = Date.now();
  await assert.rejects(pgConnect({ host: '127.0.0.1', port, database: 'app', user: USER, password: PASSWORD, connectTimeoutMs: 500 }), e => ['connect-failed', 'connection-closed', 'startup-failed'].includes(e.code));
  assert.ok(Date.now() - started < 3000, `settled after ${Date.now() - started} ms`);
});

test('retained marks are bounded, and the client row cap never exceeds the observer limit', async t => {
  const state = { snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1']], Message: [] } };
  // md5 (opted in here only) keeps 130 logins fast; the observer itself always uses SCRAM.
  const fast = options => pgConnect({ ...options, allowMd5: true });
  const server = await scriptedDb(t, Array.from({ length: 140 }, () => state), [], { auth: 'md5' });
  const o = observerOn(server, { connect: fast });
  const first = await o.mark();
  for (let i = 0; i < 130; i++) await o.mark();
  assert.deepEqual([(await o.collect(first, first)).coverage, (await o.collect(first, first)).reason], ['failed', 'missing-snapshot'], 'the oldest mark was dropped');
  let maxRows = 0;
  const spying = async options => { const client = await fast(options); return { ...client, query: (sql, opts) => { maxRows = Math.max(maxRows, opts?.maxRows ?? 0); return client.query(sql, opts); }, close: client.close }; };
  const capped = await scriptedDb(t, [state], [], { auth: 'md5' });
  const big = createPgSnapshotObserver({ env, host: '127.0.0.1', port: capped.port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', connect: spying,
    tables: [{ table: 'Chat', key: 'id' }, { table: 'Message', key: 'id' }] });
  await big.mark();
  assert.ok(maxRows > 0 && maxRows <= 250000, `client maxRows ${maxRows}`);
});

// Presence is checked for a string row selector; a prefix or table-wide
// selector is exact only on a quiescent window (no transaction completed or in progress).
const prefix = value => ({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', resource: { prefix: value } } });
test('pg-snapshot: a prefix or table-wide selector never passes over changes it could not see (A/B/C)', async t => {
  // A: c1 really updated; the selector's prefix is a case typo ("chat/c1") that matches no event.
  const a = await window(t, { snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1'], ['c2', '701', 'h2']] } }, { snapshot: '805:805:', tables: { Chat: [['c1', '804', 'h1x'], ['c2', '701', 'h2']] } });
  assert.notEqual(evaluateEffectAssertion(prefix('chat/c1'), [a]).verdict, 'pass', 'A: prefix typo over a real update');
  // B and C: c9 inserted, updated and deleted inside the window, absent at both marks.
  const transient = await window(t, { snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1']] } }, { snapshot: '809:809:', tables: { Chat: [['c1', '700', 'h1']] } });
  assert.equal(transient.events.length, 0);
  assert.notEqual(evaluateEffectAssertion(none(), [transient]).verdict, 'pass', 'B: table-wide over a transient row');
  assert.notEqual(evaluateEffectAssertion(prefix('Chat/c9'), [transient]).verdict, 'pass', 'C: prefix over a transient row');
  assert.notEqual(evaluateEffectAssertion(none('Chat/c9'), [transient]).verdict, 'pass', 'the row itself was never seen');
});

test('pg-snapshot: on a quiescent window (same xmax, nothing in progress) a table-wide or prefix absence is exact', async t => {
  const rows = [['c1', '700', 'h1'], ['c2', '701', 'h2']];
  const idle = await window(t, { snapshot: '800:800:', tables: { Chat: rows } }, { snapshot: '800:800:', tables: { Chat: rows } });
  assert.deepEqual([idle.coverage, idle.exact[0].quiescent, idle.exact[0].marks], ['net-only', true, { startXmax: '800', endXmax: '800', inProgress: 0 }]);
  assert.equal(evaluateEffectAssertion(none(), [idle]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(prefix('Chat/c'), [idle]).verdict, 'pass');
  // Not quiescent: a writer at the start mark (pg_locks), or one in xip at the start.
  const lockedStart = await window(t, { snapshot: '800:800:', writers: '{800}', tables: { Chat: rows } }, { snapshot: '800:800:', tables: { Chat: rows } });
  assert.equal(lockedStart.exact[0].quiescent, undefined); assert.notEqual(evaluateEffectAssertion(none(), [lockedStart]).verdict, 'pass');
  const xipStart = await window(t, { snapshot: '799:800:799', tables: { Chat: rows } }, { snapshot: '800:800:', tables: { Chat: rows } });
  assert.equal(xipStart.exact[0].quiescent, undefined); assert.notEqual(evaluateEffectAssertion(none(), [xipStart]).verdict, 'pass');
  // A frozen row inside an idle window stays ambiguous, so the table-wide selector is not exact.
  const frozen = await window(t, { snapshot: '800:800:', tables: { Chat: rows } }, { snapshot: '800:800:', tables: { Chat: [['c1', '2', 'h1'], ['c2', '701', 'h2']] } });
  assert.equal(frozen.exact[0].quiescent, undefined); assert.notEqual(evaluateEffectAssertion(none(), [frozen]).verdict, 'pass');
});

test('pg-snapshot: the wraparound window starts at the start snapshot xmin; an end xmax below the start xmax is a violation', async t => {
  // 797 lies between the start snapshot's xmin (795) and xmax (800): an unchanged xmin there is ambiguous.
  const mid = await window(t, { snapshot: '795:800:795', tables: { Chat: [['c1', '797', 'h1']] } }, { snapshot: '805:805:', tables: { Chat: [['c1', '797', 'h1']] } });
  assert.deepEqual(mid.exact[0].ambiguousResources, ['Chat/c1']);
  assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [mid]).verdict, 'pass');
  const backwards = await window(t, { snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1']] } }, { snapshot: '790:790:', tables: { Chat: [['c1', '700', 'h1']] } });
  assert.deepEqual([backwards.coverage, backwards.reason, backwards.events.length], ['failed', 'xmax-regressed', 0]); assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [backwards]).verdict, 'pass');
});

test('pg-snapshot: partitions and inheritance children must be verified heap tables, and every row must come from one', async t => {
  const rows = [['c1', '700', 'h1', '17001'], ['c2', '701', 'h2', '17002']];
  const partitioned = { relations: { Chat: [['16384', 'p', '']] }, descendants: { Chat: [['17001', 'r', 'heap'], ['17002', 'r', 'heap']] } };
  const ok = await window(t, { snapshot: '800:800:', ...partitioned, tables: { Chat: rows } }, { snapshot: '805:805:', ...partitioned, tables: { Chat: rows } });
  assert.deepEqual([ok.coverage, ok.exact[0].violated], ['net-only', false]); assert.equal(evaluateEffectAssertion(none('Chat/c1'), [ok]).verdict, 'pass');
  // A foreign-table partition is refused before any row is read.
  const foreign = { relations: partitioned.relations, descendants: { Chat: [['17001', 'r', 'heap'], ['17002', 'f', '']] } };
  const f = await window(t, { snapshot: '800:800:', ...foreign, tables: { Chat: rows } }, { snapshot: '805:805:', ...foreign, tables: { Chat: rows } });
  assert.deepEqual([f.coverage, f.reason], ['failed', 'relation-not-heap-table']);
  // A row from a relation outside the verified set, or a partition attached during the window, is a violation.
  const stray = await window(t, { snapshot: '800:800:', ...partitioned, tables: { Chat: rows } }, { snapshot: '805:805:', ...partitioned, tables: { Chat: [rows[0], ['c2', '701', 'h2', '99999']] } });
  assert.deepEqual([stray.coverage, stray.reason], ['failed', 'relation-unverified']); assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [stray]).verdict, 'pass');
  const attached = { relations: partitioned.relations, descendants: { Chat: [...partitioned.descendants.Chat, ['17003', 'r', 'heap']] } };
  const grew = await window(t, { snapshot: '800:800:', ...partitioned, tables: { Chat: rows } }, { snapshot: '805:805:', ...attached, tables: { Chat: rows } });
  assert.deepEqual([grew.coverage, grew.reason], ['failed', 'relation-unverified']);
  // An ordinary table with an inheritance child: rows from the parent and the child both count.
  const inherited = { descendants: { Chat: [['17001', 'r', 'heap']] } };
  const mixed = [['c1', '700', 'h1', '16384'], ['c2', '701', 'h2', '17001']];
  const inh = await window(t, { snapshot: '800:800:', ...inherited, tables: { Chat: mixed } }, { snapshot: '805:805:', ...inherited, tables: { Chat: mixed } });
  assert.equal(inh.exact[0].violated, false);
  // A partitioned parent stores no rows itself: a row claiming its oid is a violation.
  const parentRow = [['c1', '700', 'h1', '16384']];
  const pr = await window(t, { snapshot: '800:800:', ...partitioned, tables: { Chat: parentRow } }, { snapshot: '805:805:', ...partitioned, tables: { Chat: parentRow } });
  assert.deepEqual([pr.coverage, pr.reason], ['failed', 'relation-unverified']);
});

// A window whose rows cannot be identified across the marks reports no
// committed effect, so it never decides a presence check or makes backend evidence observed.
const updateExists = resource => ({ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', ...(resource ? { resource } : {}) } });
const anyExists = operation => ({ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'Chat', operation } });
function neverObserved(w, assertion, label) {
  const decisions = decideEffects([assertion], [w]);
  assert.notEqual(decisions[0].verdict, 'pass', `${label}: exists must not pass`);
  assert.equal(backendObserved(decisions), false, `${label}: backend evidence must not read observed`);
  assert.equal(w.events.length, 0, `${label}: no events`);
}
test('identity failures (key tie flip, non-unique key, stray tableoid, oid swap, xmax regression, detach, attach) report no effect', async t => {
  const part = { relations: { Chat: [['16384', 'p', '']] }, descendants: { Chat: [['17001', 'r', 'heap'], ['17002', 'r', 'heap']] } };
  const inh = { descendants: { Chat: [['17001', 'r', 'heap']] } };
  const cases = [
    // c1 in the parent and in a child; no write, only the tie order flips.
    ['tie flip', { snapshot: '800:800:', ...inh, tables: { Chat: [['c1', '700', 'h1', '16384'], ['c1', '701', 'h2', '17001']] } }, { snapshot: '800:800:', ...inh, tables: { Chat: [['c1', '701', 'h2', '17001'], ['c1', '700', 'h1', '16384']] } }, updateExists('Chat/c1'), 'duplicate-key'],
    // A non-unique declared key; a real write elsewhere reorders the rows.
    ['non-unique key', rowsAt(['c1', '700', 'h1'], ['c1', '701', 'h2']), updated('806:806:', ['c1', '701', 'h2'], ['c1', '700', 'h1']), updateExists('Chat/c1'), 'duplicate-key'],
    ['stray tableoid', { snapshot: '800:800:', ...part, tables: { Chat: [['c1', '700', 'h1', '17001']] } }, { snapshot: '806:806:', ...part, tables: { Chat: [['c1', '805', 'h1', '99999']] } }, updateExists('Chat/c1'), 'relation-unverified'],
    ['oid swap', rowsAt(['c1', '700', 'h1']), { ...updated('806:806:', ['c1', '805', 'h1']), relations: { Chat: [['99999', 'r', 'heap']] } }, updateExists('Chat/c1'), 'relation-unverified'],
    ['xmax regressed', rowsAt(['c1', '700', 'h1']), updated('790:790:', ['c1', '785', 'h1']), updateExists('Chat/c1'), 'xmax-regressed'],
    ['detach', { snapshot: '800:800:', ...part, tables: { Chat: [['c1', '700', 'h1', '17001'], ['c2', '701', 'h2', '17002']] } }, { snapshot: '801:801:', relations: part.relations, descendants: { Chat: [['17001', 'r', 'heap']] }, tables: { Chat: [['c1', '700', 'h1', '17001']] } }, anyExists('delete'), 'relation-unverified'],
    ['attach', { snapshot: '800:800:', relations: part.relations, descendants: { Chat: [['17001', 'r', 'heap']] }, tables: { Chat: [['c1', '700', 'h1', '17001']] } }, { snapshot: '801:801:', ...part, tables: { Chat: [['c1', '700', 'h1', '17001'], ['c9', '650', 'h9', '17002']] } }, anyExists('insert'), 'relation-unverified'],
    // A stray row at the start mark only.
    ['start-only stray', { snapshot: '800:800:', ...part, tables: { Chat: [['c1', '700', 'h1', '17001'], ['c2', '701', 'h2', '99999']] } }, { snapshot: '806:806:', ...part, tables: { Chat: [['c1', '805', 'h1', '17001']] } }, updateExists('Chat/c1'), 'relation-unverified'],
  ];
  for (const [label, before, after, assertion, reason] of cases) {
    const w = await window(t, before, after);
    assert.deepEqual([w.coverage, w.reason], ['failed', reason], label);
    neverObserved(w, assertion, label);
    assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [w]).verdict, 'pass', label);
  }
});

test('a table whose content changed under an unchanged xmin reports none of its changes; the validator refuses events for a violated table', async t => {
  const w = await window(t, rowsAt(['c1', '700', 'h1'], ['c2', '701', 'h2']), updated('806:806:', ['c1', '700', 'h9'], ['c2', '805', 'h2']));
  assert.equal(w.exact[0].violated, true);
  neverObserved(w, updateExists('Chat/c2'), 'content under same xmin');
  const forged = structuredClone(w);
  forged.events = (await window(t, rowsAt(['c2', '701', 'h2']), updated('806:806:', ['c2', '805', 'h2']))).events;
  assert.throws(() => validateWindow(forged), e => e.code === 'violated-table-events');
});

test('a temporary child of another session or a partition being detached concurrently is never read, so it fails the mark', async t => {
  const rows = [['c1', '700', 'h1', '16384']];
  for (const [label, child] of [['temp child', ['17001', 'r', 'heap', 't', 'false']], ['detach pending', ['17001', 'r', 'heap', 'p', 'true']]]) {
    const d = { descendants: { Chat: [child] } };
    for (const end of ['800:800:', '806:806:']) { // idle and moving xmax
      const w = await window(t, { snapshot: '800:800:', ...d, tables: { Chat: rows } }, { snapshot: end, ...d, tables: { Chat: rows } });
      assert.deepEqual([w.coverage, w.reason], ['failed', 'descendant-not-scanned'], `${label} ${end}`);
      assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [w]).verdict, 'pass');
    }
  }
  // An unlogged child is refused: crash recovery empties it without a new file node.
  const unlogged = { descendants: { Chat: [['17001', 'r', 'heap', 'u', 'false']] } };
  const u = await window(t, { snapshot: '800:800:', ...unlogged, tables: { Chat: rows } }, { snapshot: '806:806:', ...unlogged, tables: { Chat: rows } });
  assert.deepEqual([u.coverage, u.reason], ['failed', 'unlogged-table']);
});

test('a window whose end mark is not after its start mark fails (zero-length or reversed)', async t => {
  const server = await scriptedDb(t, [rowsAt(['c1', '700', 'h1']), updated('806:806:', ['c1', '805', 'h1'])]);
  const o = observerOn(server);
  const a = await o.mark(), b = await o.mark();
  for (const [from, to] of [[b, b], [a, a], [b, a]]) {
    const w = await collectWindow(o, from, to);
    assert.deepEqual([w.coverage, w.reason], ['failed', 'window-not-forward']);
    assert.notEqual(evaluateEffectAssertion(none(), [w]).verdict, 'pass');
  }
  assert.equal((await collectWindow(o, a, b)).coverage, 'net-only');
});

test('a partitioned table recorded with the heap access method (PostgreSQL 17) is accepted; other access methods are not', async t => {
  const rows = [['c1', '700', 'h1', '17001']];
  const ok = { relations: { Chat: [['16384', 'p', 'heap']] }, descendants: { Chat: [['17000', 'p', 'heap'], ['17001', 'r', 'heap']] } };
  const w = await window(t, { snapshot: '800:800:', ...ok, tables: { Chat: rows } }, { snapshot: '806:806:', ...ok, tables: { Chat: [['c1', '805', 'h1', '17001']] } });
  assert.equal(w.coverage, 'net-only'); assert.equal(evaluateEffectAssertion(none('Chat/c1'), [w]).verdict, 'fail', 'a real leaf update is still seen');
  for (const shape of [{ relations: { Chat: [['16384', 'p', 'columnar']] } }, { relations: ok.relations, descendants: { Chat: [['17001', 'r', 'columnar']] } }]) {
    const bad = await window(t, { snapshot: '800:800:', ...shape, tables: { Chat: rows } }, { snapshot: '806:806:', ...shape, tables: { Chat: rows } });
    assert.deepEqual([bad.coverage, bad.reason], ['failed', 'relation-not-heap-table']);
  }
});

test('xmax is compared as a number across a digit-width boundary', async t => {
  const down = await window(t, { snapshot: '1000:1000:', tables: { Chat: [['c1', '700', 'h1']] } }, { snapshot: '999:999:', tables: { Chat: [['c1', '700', 'h1']] } });
  assert.deepEqual([down.coverage, down.reason], ['failed', 'xmax-regressed']);
  const up = await window(t, { snapshot: '999:999:', tables: { Chat: [['c1', '700', 'h1']] } }, { snapshot: '1000:1000:', tables: { Chat: [['c1', '700', 'h1']] } });
  assert.equal(up.coverage, 'net-only'); assert.equal(evaluateEffectAssertion(none('Chat/c1'), [up]).verdict, 'pass');
});

test('up to 10000 descendants are read; more fail the mark as too-many-descendants', async t => {
  const many = n => ({ descendants: { Chat: Array.from({ length: n }, (_, i) => [String(20000 + i), 'r', 'heap']) } });
  const rows = [['c1', '700', 'h1', '16384']];
  const okWindow = await window(t, { snapshot: '800:800:', ...many(10000), tables: { Chat: rows } }, { snapshot: '806:806:', ...many(10000), tables: { Chat: rows } });
  assert.equal(okWindow.coverage, 'net-only');
  const tooMany = await window(t, { snapshot: '800:800:', ...many(10001), tables: { Chat: rows } }, { snapshot: '806:806:', ...many(10001), tables: { Chat: rows } });
  assert.deepEqual([tooMany.coverage, tooMany.reason], ['failed', 'too-many-descendants']);
});

// DDL cannot commit between a mark's snapshot and its scan, and a rewrite
// between marks never reads as an update of every row.
test('each table is locked before the snapshot; output-affecting settings are pinned; the descendant query reads persistence and detach state', async t => {
  const all = [];
  const server = await scriptedDb(t, [rowsAt(['c1', '700', 'h1'])], all);
  await observerOn(server).mark();
  // The mark's own transaction; the catalog fingerprint is read on a second session before and after it (./catalog.mjs).
  const log = all.slice(all.findIndex(s => /^BEGIN/.test(s)));
  const lock = log.findIndex(s => /^LOCK TABLE "public"\."Chat" IN ACCESS SHARE MODE$/.test(s)), snap = log.findIndex(s => /pg_current_snapshot/.test(s));
  assert.ok(log[0].startsWith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY'));
  assert.ok(lock > 0 && lock < snap, 'LOCK precedes the snapshot');
  assert.ok(log.slice(0, lock).every(s => /^(BEGIN|SET LOCAL) /.test(s)), 'nothing before the lock takes a snapshot');
  for (const setting of ["DateStyle = 'ISO, MDY'", "TimeZone = 'UTC'", "IntervalStyle = 'postgres'", 'extra_float_digits = 1', "bytea_output = 'hex'", "lc_monetary = 'C'", 'lock_timeout = ']) assert.ok(log.slice(0, snap).some(s => s.startsWith(`SET LOCAL ${setting}`)), setting);
  const descendants = log.find(s => /WITH RECURSIVE/.test(s));
  // The detach state is read at every level (the anchor and the recursive part of the query).
  assert.equal(descendants.match(/to_jsonb\(i\) ->> 'inhdetachpending'/g)?.length, 2); assert.match(descendants, /relpersistence/); assert.match(descendants, /relfilenode/);
  assert.ok(log.some(s => /pg_relation_filenode/.test(s)), 'current file nodes are read after the scan');
});

test('a table rewritten between the marks fails the window with no events; one rewritten during a mark fails the mark', async t => {
  const rows = [['c1', '700', 'h1'], ['c2', '701', 'h2']];
  // ALTER COLUMN TYPE between the marks: every row has a new xmin and the file node changed.
  const w = await window(t, rowsAt(...rows), { ...updated('806:806:', ['c1', '805', 'h1'], ['c2', '805', 'h2']), filenodes: { 16384: '99001' } });
  assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'relation-rewritten', 0]);
  neverObserved(w, updateExists('Chat/c1'), 'rewrite between marks');
  // A heap descendant rewritten between the marks too.
  const inh = { descendants: { Chat: [['17001', 'r', 'heap']] } };
  const mixed = [['c1', '700', 'h1', '16384'], ['c2', '701', 'h2', '17001']];
  const child = await window(t, { snapshot: '800:800:', ...inh, tables: { Chat: mixed } }, { snapshot: '806:806:', ...inh, filenodes: { 17001: '99002' }, tables: { Chat: [mixed[0], ['c2', '805', 'h2', '17001']] } });
  assert.deepEqual([child.coverage, child.reason], ['failed', 'relation-rewritten']);
  // Rewritten after this mark's snapshot (the file node now differs from the snapshot's): the mark fails.
  const during = await window(t, rowsAt(...rows), { ...updated('806:806:', ...rows), filenodesNow: { 16384: '99003' } });
  assert.deepEqual([during.coverage, during.reason], ['failed', 'relation-rewritten']);
});

test('duplicate or NULL keys at one mark only, xmin 1, and an overflowing ambiguous list never pass', async t => {
  const cases = [
    ['end-only duplicate', rowsAt(['c1', '700', 'h1'], ['c2', '701', 'h2']), updated('806:806:', ['c1', '700', 'h1'], ['c1', '805', 'h9']), 'duplicate-key'],
    ['start-only duplicate', rowsAt(['c1', '700', 'h1'], ['c1', '701', 'h2']), updated('806:806:', ['c1', '805', 'h1']), 'duplicate-key'],
    ['start-only NULL key', rowsAt(['c1', '700', 'h1'], [null, '701', 'h2']), updated('806:806:', ['c1', '700', 'h1']), 'duplicate-key'],
    ['xmin 1', rowsAt(['c1', '1', 'h1']), updated('806:806:', ['c1', '1', 'h1']), 'invalid-row-version'],
  ];
  for (const [label, before, after, reason] of cases) {
    const w = await window(t, before, after);
    assert.deepEqual([w.coverage, w.reason], ['failed', reason], label);
    assert.notEqual(evaluateEffectAssertion(none('Chat/c1'), [w]).verdict, 'pass', label);
  }
  // 10001 frozen (ambiguous) rows; the watched one sorts last, beyond a 10000-entry list. The overflow makes the table violated.
  const keys = Array.from({ length: 10001 }, (_, i) => `k${String(i).padStart(5, '0')}`);
  const server = await scriptedDb(t, [{ snapshot: '800:800:', tables: { Chat: keys.map(k => [k, '700', 'h']) } }, { snapshot: '806:806:', tables: { Chat: keys.map(k => [k, '2', 'h']) } }]);
  const o = observerOn(server, { watchedResources: ['Chat/k10000'] });
  const w = await collectWindow(o, await o.mark(), await o.mark());
  assert.equal(w.exact[0].violated, true);
  assert.notEqual(evaluateEffectAssertion(none('Chat/k10000'), [w]).verdict, 'pass');
});

test('a gap basis names the violated table', async t => {
  const w = await window(t, rowsAt(['c1', '700', 'h1']), updated('806:806:', ['c1', '700', 'h9']));
  const v = evaluateEffectAssertion(none('Chat/c1'), [w]);
  assert.equal(v.verdict, 'missing'); assert.match(v.basis, /Chat violated/);
});

// A key whose text changes without a new row version is never a delete plus insert.
test('a key that changes without a new row version fails the window (renamed column, renamed enum label); honest inserts are unaffected', async t => {
  const start = rowsAt(['c1', '700', 'h1'], ['c2', '701', 'h2']);
  // RENAME COLUMN swap between the marks: the column layout changed.
  const swapped = await window(t, start, { ...updated('806:806:', ['zz1', '700', 'h1'], ['zz2', '701', 'h2']), attributes: { 16384: [['1', 'alt', '25', 'false'], ['2', 'id', '25', 'false']] } });
  assert.deepEqual([swapped.coverage, swapped.reason, swapped.events.length], ['failed', 'columns-changed', 0]);
  // An enum label renamed (same layout): the "new" key carries a row version committed before the start mark.
  const relabelled = await window(t, start, updated('806:806:', ['c1', '700', 'h1'], ['c9', '701', 'h2']));
  assert.deepEqual([relabelled.coverage, relabelled.reason, relabelled.events.length], ['failed', 'key-without-new-version', 0]);
  neverObserved(relabelled, anyExists('delete'), 'renamed enum label');
  // Honest inserts: a new id after the start xmax, one in progress at the start (xip), the newest writer at the start (pg_locks),
  // and a subtransaction in progress at the start: below the start xmax and absent from xip (pg_current_snapshot lists
  // top-level ids only), but holding its own transactionid lock.
  for (const [label, before, xmin] of [['new id', start, '803'], ['in progress at start', { ...start, snapshot: '799:800:799' }, '799'], ['newest writer at start', { ...start, writers: '{800}' }, '800'],
    ['subtransaction in progress at start', { ...start, snapshot: '795:800:795', writers: '{795,797}' }, '797']]) {
    const w = await window(t, before, updated('806:806:', ['c1', '700', 'h1'], ['c2', '701', 'h2'], ['c3', xmin, 'h3']));
    assert.deepEqual([w.coverage, w.events.map(e => e.operation)], ['net-only', ['insert']], label);
  }
  // The precise rule, not the wraparound range: 797 completed before the start mark even though 795 was still open.
  const held = await window(t, { ...start, snapshot: '795:800:795' }, updated('806:806:', ['c1', '700', 'h1'], ['c2', '701', 'h2'], ['c3', '797', 'h3']));
  assert.deepEqual([held.coverage, held.reason], ['failed', 'key-without-new-version']);
  // A new key with a frozen row version cannot be told from a relabelled one: fails closed.
  const frozen = await window(t, start, updated('806:806:', ['c1', '700', 'h1'], ['c2', '701', 'h2'], ['c3', '2', 'h3']));
  assert.deepEqual([frozen.coverage, frozen.reason], ['failed', 'key-without-new-version']);
});

test('the client pins client_encoding to UTF8 at startup', async t => {
  const startups = [];
  const server = await scriptedDb(t, [rowsAt(['c1', '700', 'h1'])], [], { startups });
  await observerOn(server).mark();
  assert.equal(startups[0].client_encoding, 'UTF8');
});

test('a descendant the mark does not hold a lock on fails the mark (it joined during the lock wait)', async t => {
  const inh = { descendants: { Chat: [['17010', 'r', 'heap'], ['17011', 'r', 'heap']] } };
  const rowsInh = [['c1', '700', 'h1', '16384'], ['c2', '701', 'h2', '17010']];
  // At the end mark, 17010 is listed by the snapshot but not locked; its rows can leave before the scan.
  const end = await window(t, { snapshot: '800:800:', ...inh, tables: { Chat: rowsInh } }, { snapshot: '806:806:', ...inh, locked: ['16384', '17011'], tables: { Chat: [rowsInh[0]] } });
  assert.deepEqual([end.coverage, end.reason, end.events.length], ['failed', 'descendant-not-locked', 0]);
  // The same at the start mark.
  const begin = await window(t, { snapshot: '800:800:', ...inh, locked: ['16384', '17011'], tables: { Chat: [rowsInh[0]] } }, { snapshot: '806:806:', ...inh, tables: { Chat: rowsInh } });
  assert.deepEqual([begin.coverage, begin.reason], ['failed', 'descendant-not-locked']);
  // The parent itself unlocked fails too.
  const parent = await window(t, { ...rowsAt(['c1', '700', 'h1']), locked: [] }, rowsAt(['c1', '700', 'h1']));
  assert.deepEqual([parent.coverage, parent.reason], ['failed', 'descendant-not-locked']);
  // Only this backend's locks count. Another session holding the late child does not lock it for this mark.
  const others = await window(t, { snapshot: '800:800:', ...inh, tables: { Chat: rowsInh } }, { snapshot: '806:806:', ...inh, locked: ['16384', '17011'], otherLocks: ['17010'], tables: { Chat: [rowsInh[0]] } });
  assert.deepEqual([others.coverage, others.reason], ['failed', 'descendant-not-locked']);
});

test('a server restart between the marks fails the window (a crash resets unlogged tables without a new file node)', async t => {
  const w = await window(t, rowsAt(['c1', '700', 'h1'], ['c2', '701', 'h2']), { ...updated('806:806:'), serverStart: '2026-10-06 09:00:00+00' });
  assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'server-restarted', 0]);
});

test('every declared table is locked before the snapshot; a descendant rewritten during a mark fails it', async t => {
  const log = [];
  const server = await scriptedDb(t, [{ snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1']], Msg: [['m1', '700', 'h1']] }, relations: { Chat: [['16384', 'r', 'heap']], Msg: [['16390', 'r', 'heap']] } }], log);
  await observerOn(server, { tables: [{ table: 'Chat', key: 'id' }, { table: 'Msg', key: 'id' }] }).mark();
  const snap = log.findIndex(s => /pg_current_snapshot/.test(s));
  assert.deepEqual(log.slice(0, snap).filter(s => /^LOCK/.test(s)), ['LOCK TABLE "public"."Chat" IN ACCESS SHARE MODE', 'LOCK TABLE "public"."Msg" IN ACCESS SHARE MODE']);
  const inh = { descendants: { Chat: [['17010', 'r', 'heap']] } };
  const rowsInh = [['c1', '700', 'h1', '16384'], ['c2', '701', 'h2', '17010']];
  const w = await window(t, { snapshot: '800:800:', ...inh, tables: { Chat: rowsInh } }, { snapshot: '806:806:', ...inh, filenodesNow: { 17010: '0' }, tables: { Chat: [rowsInh[0]] } });
  assert.deepEqual([w.coverage, w.reason], ['failed', 'relation-rewritten']);
});

// ---- Key permutations, key types, unlogged tables, layouts and id widths. ----
const E = 4294967296; // 2^32: snapshots carry 64-bit ids; xmin and pg_locks carry their low 32 bits.
// Neither a presence nor an absence check is decided by a failed window.
const inconclusiveBoth = (w, label) => {
  for (const [name, assertion] of [['exists update c1', updateExists('Chat/c1')], ['none update c1', none('Chat/c1')], ['none update c2', none('Chat/c2')], ['none update', none()]])
    assert.equal(evaluateEffectAssertion(assertion, [w]).verdict, 'observer-failure', `${label}: ${name}`);
  neverObserved(w, updateExists('Chat/c1'), label);
};

test('key texts permuted between rows with no row written fail the window; honest key changes and updates do not', async t => {
  const start = rowsAt(['c1', '700', 'h1'], ['c2', '701', 'h2'], ['c3', '702', 'h3']);
  // Labels c1 and c2 swapped (three RENAME VALUEs): no key is new, each now carries the other row's version.
  const swapped = await window(t, start, updated('806:806:', ['c1', '701', 'h2'], ['c2', '700', 'h1'], ['c3', '702', 'h3']));
  assert.deepEqual([swapped.coverage, swapped.reason, swapped.events.length], ['failed', 'key-without-new-version', 0]);
  inconclusiveBoth(swapped, 'swap');
  // A three-way rotation.
  const rotated = await window(t, start, updated('806:806:', ['c1', '702', 'h3'], ['c2', '700', 'h1'], ['c3', '701', 'h2']));
  assert.deepEqual([rotated.coverage, rotated.reason, rotated.events.length], ['failed', 'key-without-new-version', 0]);
  inconclusiveBoth(rotated, 'rotation');
  // A swap alongside an honest update of a third row in the same window.
  const mixed = await window(t, start, updated('806:806:', ['c1', '701', 'h2'], ['c2', '700', 'h1'], ['c3', '803', 'h9']));
  assert.deepEqual([mixed.coverage, mixed.reason, mixed.events.length], ['failed', 'key-without-new-version', 0]);
  // Honest: an update of c1, a key-changing UPDATE (c2 becomes c9 with a new version), in the same window.
  const honest = await window(t, start, updated('806:806:', ['c1', '803', 'h9'], ['c3', '702', 'h3'], ['c9', '804', 'h2']));
  assert.equal(honest.coverage, 'net-only');
  assert.deepEqual(honest.events.map(e => `${e.operation} ${e.resource}`).sort(), ['delete Chat/c2', 'insert Chat/c9', 'update Chat/c1']);
  // Honest: an update by a transaction in progress at the start (xip), and by its subtransaction (pg_locks only).
  for (const [label, before, xmin] of [['open at start', { ...start, snapshot: '799:800:799' }, '799'], ['subtransaction', { ...start, snapshot: '795:800:795', writers: '{795,797}' }, '797']]) {
    const w = await window(t, before, updated('806:806:', ['c1', xmin, 'h9'], ['c2', '701', 'h2'], ['c3', '702', 'h3']));
    assert.deepEqual([w.coverage, w.events.map(e => `${e.operation} ${e.resource}`)], ['net-only', ['update Chat/c1']], label);
  }
  // Freezing between the marks is ambiguous, never a failure or an event.
  const frozen = await window(t, start, updated('806:806:', ['c1', '2', 'h1'], ['c2', '701', 'h2'], ['c3', '702', 'h3']));
  assert.deepEqual([frozen.coverage, frozen.events.length], ['net-only', 0]);
  assert.ok(frozen.exact[0].ambiguousResources.includes('Chat/c1'));
});

test('a key whose text is not fixed by its stored bytes fails the mark (output not immutable, virtual, not a column)', async t => {
  const rows = [['c1', '700', 'h1']];
  // attributes: [attnum, attname, atttypid, attisdropped, attgenerated?]; types add to the fake's built-in TYPE_OUTPUTS.
  const key = (typid, gen) => ({ 16384: [['1', 'id', typid, 'false', ...(gen ? [gen] : [])]] });
  const types = { 90001: ['pg_catalog.enum_out', 's'], 90002: ['pg_catalog.record_out', 's'], 90003: ['pg_catalog.aclitemout', 's'], // a domain over aclitem has its base's output
    90004: ['pg_catalog.textout', 'i'], 90005: ['public.my_type_out', 's'], 90006: ['public.timestamptz_out', 's'], 90007: ['public.my_pure_out', 'i'] };
  const refused = [['enum', key('90001')], ['composite', key('90002')], ['aclitem (role names from the catalog)', key('1033')], ['domain over aclitem', key('90003')],
    ['regclass', key('2205')], ['regrole', key('4096')], ['array', key('1009')], ['range', key('3904')], ['multirange', key('4451')],
    ['a user type with a stable output', key('90005')], ['a pinned output name outside pg_catalog', key('90006')], ['virtual generated text', key('25', 'v')],
    ['not a column (a function of the row)', { 16384: [['1', 'key', '25', 'false']] }]];
  for (const [label, attributes] of refused) {
    const atStart = await window(t, { ...rowsAt(...rows), attributes, types }, updated('806:806:', ...rows));
    const atEnd = await window(t, rowsAt(...rows), { ...updated('806:806:', ...rows), attributes, types });
    for (const w of [atStart, atEnd]) assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'key-type-refused', 0], label);
  }
  // A descendant's key column counts too.
  const inh = { descendants: { Chat: [['17010', 'r', 'heap']] } };
  const child = await window(t, { snapshot: '800:800:', ...inh, attributes: { 17010: [['1', 'id', '90001', 'false']] }, types, tables: { Chat: rows } }, { snapshot: '806:806:', ...inh, tables: { Chat: rows } });
  assert.deepEqual([child.coverage, child.reason], ['failed', 'key-type-refused']);
  // Accepted: immutable outputs, the outputs whose settings each mark pins, a stored generated column, a domain over
  // text, a user type with an immutable output, and a key beside other columns (one key row per relation).
  const accepted = [['text', key('25')], ['varchar', key('1043')], ['uuid', key('2950')], ['int4', key('23')], ['numeric', key('1700')], ['bytea', key('17')],
    ['timestamptz', key('1184')], ['timestamp', key('1114')], ['date', key('1082')], ['interval', key('1186')], ['money', key('790')],
    ['stored generated text', key('25', 's')], ['domain over text', key('90004')], ['a user type with an immutable output', key('90007')],
    ['a key beside other columns', { 16384: [['1', 'id', '25', 'false'], ['2', 'note', '1033', 'false'], ['3', 'v', '25', 'false', 'v']] }]];
  for (const [label, attributes] of accepted) {
    const w = await window(t, { ...rowsAt(...rows), attributes, types }, { ...updated('806:806:', ...rows), attributes, types });
    assert.equal(w.coverage, 'net-only', label);
  }
});

test('an unlogged or temporary declared table, or an unlogged descendant, fails the mark', async t => {
  const rows = [['c1', '700', 'h1']];
  for (const [label, state, reason] of [
    ['unlogged table', { relations: { Chat: [['16384', 'r', 'heap', '16384', 'u']] } }, 'unlogged-table'],
    ['temporary table', { relations: { Chat: [['16384', 'r', 'heap', '16384', 't']] } }, 'temporary-table'],
    ['unlogged partition', { relations: { Chat: [['16384', 'p', '']] }, descendants: { Chat: [['17001', 'r', 'heap', 'u', 'false']] } }, 'unlogged-table']]) {
    const w = await window(t, { snapshot: '800:800:', ...state, tables: { Chat: rows } }, { snapshot: '806:806:', ...state, tables: { Chat: rows } });
    assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', reason, 0], label);
  }
});

test('every column of every relation is part of the layout (a descendant, attnum 1, a retype)', async t => {
  const rows = [['c1', '700', 'h1']];
  // A column of a descendant renamed between the marks.
  const inh = { descendants: { Chat: [['17010', 'r', 'heap']] } };
  const childLayout = name => ({ 17010: [['1', 'id', '25', 'false'], ['2', name, '25', 'false']] });
  const child = await window(t, { snapshot: '800:800:', ...inh, attributes: childLayout('note'), tables: { Chat: rows } }, { snapshot: '806:806:', ...inh, attributes: childLayout('memo'), tables: { Chat: rows } });
  assert.deepEqual([child.coverage, child.reason], ['failed', 'columns-changed']);
  // The first column (attnum 1) renamed, the key being the second.
  const first = name => ({ 16384: [['1', name, '25', 'false'], ['2', 'id', '25', 'false']] });
  const one = await window(t, { ...rowsAt(...rows), attributes: first('v') }, { ...updated('806:806:', ...rows), attributes: first('w') });
  assert.deepEqual([one.coverage, one.reason], ['failed', 'columns-changed']);
  // A retype with the same name and no rewrite (text to varchar).
  const typed = typid => ({ 16384: [['1', 'id', typid, 'false']] });
  const retyped = await window(t, { ...rowsAt(...rows), attributes: typed('25') }, { ...updated('806:806:', ...rows), attributes: typed('1043') });
  assert.deepEqual([retyped.coverage, retyped.reason], ['failed', 'columns-changed']);
});

test('ids are compared at their own width in any epoch', async t => {
  const start = (snapshot, extra = {}) => ({ snapshot, tables: { Chat: [['c1', '700', 'h1'], ['c2', '701', 'h2']] }, ...extra });
  const end = (snapshot, ...more) => updated(snapshot, ['c1', '700', 'h1'], ['c2', '701', 'h2'], ...more);
  // The first id after the start mark (equal to its xmax) is a new id.
  const firstNew = await window(t, start('800:800:'), end('806:806:', ['c3', '800', 'h3']));
  assert.deepEqual([firstNew.coverage, firstNew.events.map(e => e.operation)], ['net-only', ['insert']]);
  // Epoch 1: xip holds 64-bit ids, pg_locks 32-bit ids.
  const inXip = await window(t, start(`${E + 799}:${E + 800}:${E + 799}`), end(`${E + 806}:${E + 806}:`, ['c3', '799', 'h3']));
  assert.deepEqual([inXip.coverage, inXip.events.map(e => e.operation)], ['net-only', ['insert']], 'epoch 1, in xip');
  const subxact = await window(t, start(`${E + 795}:${E + 800}:${E + 795}`, { writers: '{795,797}' }), end(`${E + 806}:${E + 806}:`, ['c3', '797', 'h3']));
  assert.deepEqual([subxact.coverage, subxact.events.map(e => e.operation)], ['net-only', ['insert']], 'epoch 1, subtransaction');
  // A new key whose 32-bit version equals the end xmax's low bits is from the previous epoch: already committed.
  const old = await window(t, start(`${E + 800}:${E + 800}:`), end(`${E + 806}:${E + 806}:`, ['c9', '806', 'h3']));
  assert.deepEqual([old.coverage, old.reason], ['failed', 'key-without-new-version']);
});

test('an unlogged relation anywhere in the tree, and a permutation in any declared table, fail the window', async t => {
  const rows = [['c1', '700', 'h1']];
  // The unlogged relation is not the first descendant.
  const tree = { descendants: { Chat: [['17001', 'r', 'heap', 'p', 'false'], ['17002', 'r', 'heap', 'p', 'false'], ['17003', 'r', 'heap', 'u', 'false']] } };
  const deep = await window(t, { snapshot: '800:800:', ...tree, tables: { Chat: rows } }, { snapshot: '806:806:', ...tree, tables: { Chat: rows } });
  assert.deepEqual([deep.coverage, deep.reason], ['failed', 'unlogged-table']);
  // Two declared tables; the keys are permuted in the second.
  const two = { tables: [{ table: 'Chat', key: 'id' }, { table: 'Msg', key: 'id' }], watchedResources: ['Chat/c1', 'Msg/m1'] };
  const rel = { relations: { Chat: [['16384', 'r', 'heap']], Msg: [['16390', 'r', 'heap']] } };
  const chat = [['c1', '700', 'h1']];
  const swapped = await window(t, { snapshot: '800:800:', ...rel, tables: { Chat: chat, Msg: [['m1', '710', 'g1'], ['m2', '711', 'g2']] } },
    { snapshot: '806:806:', ...rel, tables: { Chat: chat, Msg: [['m1', '711', 'g2'], ['m2', '710', 'g1']] } }, two);
  assert.deepEqual([swapped.coverage, swapped.reason, swapped.events.length], ['failed', 'key-without-new-version', 0]);
  // The same two tables with an honest update in the second are fine.
  const honest = await window(t, { snapshot: '800:800:', ...rel, tables: { Chat: chat, Msg: [['m1', '710', 'g1'], ['m2', '711', 'g2']] } },
    { snapshot: '806:806:', ...rel, tables: { Chat: chat, Msg: [['m1', '803', 'g9'], ['m2', '711', 'g2']] } }, two);
  assert.deepEqual([honest.coverage, honest.events.map(e => `${e.operation} ${e.resource}`)], ['net-only', ['update Msg/m1']]);
});

test('a refused key in the second declared table (its own name and type), system-column keys and unknown types are refused', async t => {
  // The second table Msg is keyed by an aclitem column ref, beside a text column named like the first table's key.
  // Its twins m1 and m2 share an xmin; m2 is updated and the role names swapped, so m1's key now sits on the untouched twin.
  const rel = { relations: { Chat: [['16384', 'r', 'heap']], Msg: [['16390', 'r', 'heap']] } };
  const attributes = { 16384: [['1', 'id', '25', 'false']], 16390: [['1', 'id', '25', 'false'], ['2', 'ref', '1033', 'false']] };
  const two = { tables: [{ table: 'Chat', key: 'id' }, { table: 'Msg', key: 'ref' }], watchedResources: ['Chat/c1', 'Msg/m1', 'Msg/m2'] };
  const chat = [['c1', '700', 'h1']];
  const w = await window(t, { snapshot: '800:800:', ...rel, attributes, tables: { Chat: chat, Msg: [['m1', '710', 'g1'], ['m2', '710', 'g2']] } },
    { snapshot: '806:806:', ...rel, attributes, tables: { Chat: chat, Msg: [['m1', '710', 'g1'], ['m2', '803', 'g3']] } }, two);
  assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'key-type-refused', 0]);
  const msg = (kind, resource) => ({ kind, select: { source: 'sql-snapshot', name: 'Msg', operation: 'update', resource } });
  assert.equal(evaluateEffectAssertion(msg('effect.none', 'Msg/m1'), [w]).verdict, 'observer-failure');
  neverObserved(w, msg('effect.exists', 'Msg/m2'), 'second table');
  // System columns (attnum < 0) are not keys, though their outputs are immutable. xmax changes on SELECT ... FOR UPDATE
  // with no new row version; ctid moves on any update; cmin is per command.
  const system = { 16384: [['-5', 'xmax', '28', 'false'], ['-1', 'ctid', '27', 'false'], ['-3', 'cmin', '29', 'false'], ['1', 'id', '25', 'false']] };
  for (const key of ['xmax', 'ctid', 'cmin']) {
    const s = await window(t, { ...rowsAt(['0', '700', 'h1']), attributes: system }, { ...updated('806:806:', ['0', '700', 'h1']), attributes: system }, { tables: [{ table: 'Chat', key }], watchedResources: ['Chat/0'] });
    assert.deepEqual([s.coverage, s.reason, s.events.length], ['failed', 'key-type-refused', 0], key);
  }
  // A key type the server reports with an output function the observer has never seen is judged by its volatility alone:
  // an unknown stable output is refused.
  const unknown = await window(t, { ...rowsAt(['c1', '700', 'h1']), attributes: { 16384: [['1', 'id', '99999', 'false']] }, types: { 99999: ['ext.thing_out', 's'] } }, updated('806:806:', ['c1', '700', 'h1']));
  assert.deepEqual([unknown.coverage, unknown.reason], ['failed', 'key-type-refused']);
  // The fake itself never invents an immutable output: a type id it does not model reads as refused, not accepted.
  const unmodelled = await window(t, { ...rowsAt(['c1', '700', 'h1']), attributes: { 16384: [['1', 'id', '99998', 'false']] } }, updated('806:806:', ['c1', '700', 'h1']));
  assert.deepEqual([unmodelled.coverage, unmodelled.reason], ['failed', 'key-type-refused']);
});

test('the fake server answers 42601 to key-type and layout statements it does not model, so a changed statement cannot pass quietly', async t => {
  // The statements as the observer sends them, captured from one mark.
  const log = [];
  const attributes = { 16384: [['1', 'id', '25', 'false'], ['2', 'note', '1033', 'false']] };
  await observerOn(await scriptedDb(t, [{ ...rowsAt(['c1', '700', 'h1']), attributes }], log)).mark();
  // The catalog fingerprint's statements (./catalog.mjs) read pg_proc and pg_attribute too, and are answered by their own rule.
  const keyType = log.find(s => /pg_catalog\.pg_proc/.test(s) && !/^\/\* sh:db(catalog|versions) \*\//.test(s)), layout = log.find(s => /pg_catalog\.pg_attribute/.test(s) && !/pg_proc/.test(s));
  assert.ok(keyType && layout);
  const db = await scriptedDb(t, [{ ...rowsAt(['c1', '700', 'h1']), attributes }]);
  // The client is closed before the test ends: the fake server's own close waits for open connections.
  const c = await pgConnect({ host: '127.0.0.1', port: db.port, database: 'app', user: USER, password: PASSWORD });
  const answers = [];
  try {
    await c.query('BEGIN');
    const answer = async statement => { try { return (await c.query(statement))[0].rows; } catch (error) { return error.sqlState ?? error.code; } };
    answers.push(['as sent', await answer(keyType)], ['layout as sent', await answer(layout)]);
    for (const [label, statement] of [
    ['text before the first AND', keyType.replace(' AND a.attname', ' OR TRUE AND a.attname')],
    ['an unknown where clause', keyType.replace(' ORDER BY 1', ' AND a.attislocal ORDER BY 1')],
    ['an unknown select item', keyType.replace('p.provolatile::text', 'p.proisstrict::text')],
    ['another join', keyType.replace('JOIN pg_catalog.pg_proc p ON p.oid = ty.typoutput', 'JOIN pg_catalog.pg_proc p ON p.oid = ty.typinput')],
    ['layout: an unknown select item', layout.replace('atttypid::text', 'attcollation::text')],
    ['layout: an unknown where clause', layout.replace(' ORDER BY 1, 2', ' AND attislocal ORDER BY 1, 2')]]) answers.push([label, await answer(statement)]);
  } finally { c.close(); }
  assert.deepEqual(answers[0][1], [['16384', '', 'i', 'pg_catalog.textout']], 'as sent');
  assert.equal(answers[1][1].length, 2, 'layout as sent');
  for (const [label, got] of answers.slice(2)) assert.equal(got, '42601', label);
  assert.equal(answers.length, 8);
});

// Without actorCapture the observer is byte-for-byte what it was before the actor join: every statement it
// sends, in order, and every window and record it returns, over three marks with an update, an insert, a delete and a revert.
// The digest was computed with this same scenario on pg-snapshot.mjs before the actor join. Only the clock is normalised.
const SNAPSHOT_MAIN_DIGEST = 'aa33ad7134e0c95098d7ea832062272ec6f4cce19fe794084bdfe5454347940a';
test('without actorCapture, pg-snapshot sends and returns exactly what it did before the actor join', async t => {
  const sent = [];
  // start() reads the first state; the marks read the other three.
  const states = [rowsAt(['c1', '700', 'h1'], ['c2', '701', 'h2']), rowsAt(['c1', '700', 'h1'], ['c2', '701', 'h2']), { snapshot: '805:805:', tables: { Chat: [['c1', '803', 'h3'], ['c3', '804', 'h4']] } },
    { snapshot: '809:809:', tables: { Chat: [['c1', '807', 'h1'], ['c3', '804', 'h4']] } }, { snapshot: '809:809:', tables: { Chat: [['c1', '807', 'h1'], ['c3', '804', 'h4']] } }];
  const server = await scriptedDb(t, states, sent);
  const o = observerOn(server);
  await o.start();
  const a = await o.mark(), b = await o.mark(), c = await o.mark();
  const windows = [await o.collect(a, b), await o.collect(b, c)];
  const view = JSON.parse(JSON.stringify({ sent, scope: o.scope, source: o.source, kind: o.kind, windows, record: o.catalog() }, (k, v) => (['observedAt', 'at'].includes(k) ? 'time' : v)));
  const sha = text => createHash('sha256').update(text).digest('hex');
  assert.equal(sha(JSON.stringify(view)), SNAPSHOT_MAIN_DIGEST, `view digest ${sha(JSON.stringify(view))}`);
});
