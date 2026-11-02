// pg-wal (the Postgres logical-decoding observer) against a scripted session: no server, no socket. The fake answers the
// observer's tagged statements (/* sh:... */) from a model of the WAL, the slot and the catalog, so each rule the module
// states is driven directly: the window bounds by commit LSN, peek before advance, the end barrier, the slot and session
// failures, schema drift, in-flight writers, TRUNCATE, replica identity, digest at decode, TOAST and the value judge.
// The server-side projection and test_decoding's own output are covered against a real server in pg-wal.live.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PgError } from './pg-wire.mjs';
import { createPgWalObserver, parseChangeLine, judgeWalValue, lsnValue, PG_WAL_SCHEMA, PG_WAL_SOURCE } from './pg-wal.mjs';
import { platformList } from './ignore-lists/ignore-list.mjs';
import { collectWindow, evaluateEffectAssertion, validateWindow } from './events.mjs';
import { createHash } from 'node:crypto';
import { catalogAnswer, FAKE_CATALOG } from './fixtures/fake-postgres.mjs';

const sha = text => createHash('sha256').update(text).digest('hex');

import { lsnText, ORDERS, relation, row, fakeServer } from './fixtures/fake-pg-wal.mjs';
const ENV = { SCOPEHAVEN_TARGET_WAL: 'wal_reader:pw' };
const make = (s, extra = {}) => createPgWalObserver({ env: ENV, host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_WAL', connect: s.connect, barrierMs: 100,
  tables: [{ table: 'orders', key: 'id', values: ['status', 'amount'] }], ...extra });
const window = async (o, between) => { const from = await o.mark(); await between(); const to = await o.mark(); return o.collect(from, to); };
const none = (operation, resource) => ({ kind: 'effect.none', select: { source: PG_WAL_SOURCE, name: 'orders', operation, ...(resource ? { resource } : {}) } });

test('parseChangeLine: test_decoding values by type, quotes doubled, old keys as a subset, and anything off the catalog labels is unparsed', () => {
  const ins = parseChangeLine(row('INSERT', " id[text]:'a' status[text]:'it''s: TRUNCATE: (no-flags)' amount[numeric]:12.50 email[text]:null note[text]:unchanged-toast-datum"), relation);
  assert.equal(ins.op, 'insert');
  assert.deepEqual([...ins.tuple], [['id', { text: 'a' }], ['status', { text: "it's: TRUNCATE: (no-flags)" }], ['amount', { text: '12.50' }], ['email', null], ['note', { toast: 'unchanged' }]]);
  const upd = parseChangeLine(row('UPDATE', " old-key: id[text]:'a' new-tuple: id[text]:'b' status[text]:' new-tuple: x' amount[numeric]:-1e+21 email[text]:'' note[text]:'n'"), relation);
  assert.deepEqual([upd.op, upd.oldTuple.get('id'), upd.tuple.get('id'), upd.tuple.get('status')], ['update', { text: 'a' }, { text: 'b' }, { text: ' new-tuple: x' }]);
  assert.deepEqual([...parseChangeLine(row('DELETE', " id[text]:'a'"), relation).oldTuple], [['id', { text: 'a' }]]);
  assert.deepEqual(parseChangeLine(row('DELETE', ' (no-tuple-data)'), relation), { op: 'delete', tuple: null, oldTuple: null });
  assert.deepEqual(parseChangeLine('table public.orders: TRUNCATE: (no-flags)', relation), { op: 'truncate' });
  const bad = [
    row('INSERT', " id[text]:'a' status[text]:'x'"), // a column missing from a new tuple
    row('INSERT', " id[text]:'a' status[varchar]:'x' amount[numeric]:1 email[text]:null note[text]:null"), // a type label the catalog does not print
    row('INSERT', " id[text]:'a' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null junk"), // trailing text
    row('INSERT', " id[text]:'a' status[text]:'x amount[numeric]:1 email[text]:null note[text]:null"), // an unterminated quote
    row('INSERT', " id[text]:'a' status[text]:'x' amount[numeric]:1;DROP email[text]:null note[text]:null"), // an unquoted token that is not a number
    row('DELETE', " note[text]:'n' id[text]:'a'"), // an old key out of attnum order
    row('UPSERT', " id[text]:'a'"), 'table public.ordersx: INSERT: id[text]:\'a\'', 'message: transactional: 1 prefix: p, sz: 1 content:x'];
  for (const line of bad) assert.deepEqual(parseChangeLine(line, relation), { error: 'decode-unparsed' }, line);
});

test('construction: loopback only, the credential namespace, sensitive names, the key never a value, and the ignore list never names an observed table', () => {
  const base = { env: ENV, host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_WAL', tables: [{ table: 'orders', key: 'id' }] };
  assert.doesNotThrow(() => createPgWalObserver(base));
  for (const [extra, pattern] of [[{ host: 'localhost' }, /loopback/], [{ credentialEnv: 'PGPASSWORD' }, /namespace/], [{ tables: [{ table: 'orders', key: 'id', values: ['email'] }] }, /sensitive/],
    [{ tables: [{ table: 'orders', key: 'id', values: ['id'] }] }, /never a value/], [{ tables: [{ table: 'orders', key: 'id', values: ['status'], reveal: ['status'] }] }, /reveal/],
    [{ ignore: ['public.orders'] }, /ignore list/], [{ ignore: ['public'] }, /ignore list/], [{ platform: 'heroku' }, /platform/], [{ tables: [{ table: 'orders', key: 'id' }, { table: 'orders', key: 'id', schema: 'b' }] }, /once/],
    [{ tables: [{ table: 'orders', key: 'id', where: 'x' }] }, /pg-wal table/], [{ barrierMs: 50 }, /barrierMs/]])
    assert.throws(() => createPgWalObserver({ ...base, ...extra }), pattern, JSON.stringify(extra));
  // The platform list is the shared reader's checked-in one.
  assert.ok(platformList('supabase', 'postgres').entries.some(e => e.schema === 'auth' && e.table === 'audit_log_entries') && platformList('supabase', 'postgres').entries.some(e => e.schema === 'cron' && e.table === 'job_run_details'));
});

test('a window holds every committed change between the marks: write-and-undo, exact inserts and deletes, and absence with other tables busy', async () => {
  const s = fakeServer(), o = make(s, { platform: 'supabase' });
  await o.start();
  s.commit([['declared', row('INSERT', " id[text]:'before' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null")]]);
  const w = await window(o, () => {
    s.commit([['declared', row('INSERT', " id[text]:'b' status[text]:'new' amount[numeric]:5 email[text]:'p@q' note[text]:'n'")], ['declared', row('DELETE', " id[text]:'b'")]]);
    s.commit([['declared', row('UPDATE', " id[text]:'a' status[text]:'refunded' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")]]);
    s.commit([['declared', row('UPDATE', " id[text]:'a' status[text]:'open' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")]]);
    s.commit([['other', 'public.audit'], ['other', 'auth.sessions'], ['message', null]]);
    s.message('0'); s.message(String(s.xid + 1)); s.commit([['other', 'public.audit']]);
  });
  // An unlisted table and logical messages keep it from passing an absence; every change it read is still an event.
  assert.deepEqual([w.coverage, w.reason], ['partial', 'logical-message,unlisted-table-changed']);
  assert.deepEqual(w.events.map(e => `${e.operation} ${e.resource}`), ['insert orders/b', 'delete orders/b', 'update orders/a', 'update orders/a']);
  const t = w.wal.tables[0];
  assert.deepEqual([t.counts, t.inserted, t.deleted, t.updated], [{ insert: 1, update: 2, delete: 1 }, ['b'], ['b'], ['a', 'a']]);
  assert.deepEqual(t.changes.filter(c => c.key === 'a').map(c => c.values.status), ['refunded', 'open'], 'the write and its revert');
  const { ignore: list, ...counts } = w.wal.others;
  assert.deepEqual(counts, { platform: 'supabase', ignored: 1, queue: 0, unlisted: [{ name: 'public.audit', changes: 2 }], unlistedOmitted: 0, messages: 3, notInWal: [], notInWalOmitted: 0 }, 'framed and unframed messages, counted, never read');
  assert.equal(list.platform, 'supabase'); assert.match(list.digest, /^[a-f0-9]{64}$/);
  assert.equal(w.wal.schema, PG_WAL_SCHEMA); assert.match(w.wal.digest, /^[a-f0-9]{64}$/);
  assert.equal(evaluateEffectAssertion(none('insert'), [validateWindow({ source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: w.coverage, reason: w.reason, events: w.events })]).verdict, 'fail', 'a forbidden write it saw still fails');
  // The same writes with the audit table on the profile's ignore list and no messages: complete, so absence on the
  // observed table decides; the earlier insert is outside it.
  const s2 = fakeServer(), o2 = make(s2, { platform: 'supabase', ignore: ['public.audit'] });
  await o2.start();
  s2.commit([['declared', row('INSERT', " id[text]:'before' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null")]]);
  const w2 = await window(o2, () => {
    s2.commit([['declared', row('INSERT', " id[text]:'b' status[text]:'new' amount[numeric]:5 email[text]:'p@q' note[text]:'n'")], ['declared', row('DELETE', " id[text]:'b'")]]);
    s2.commit([['declared', row('UPDATE', " id[text]:'a' status[text]:'refunded' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")], ['other', 'public.audit'], ['other', 'auth.sessions']]);
  });
  assert.deepEqual([w2.coverage, w2.reason, w2.wal.others.ignored, w2.wal.others.unlisted], ['complete', null, 2, []]);
  const ew = validateWindow({ source: o2.source, instanceId: o2.instanceId, scope: o2.scope, coverage: w2.coverage, reason: w2.reason, events: w2.events });
  assert.equal(evaluateEffectAssertion(none('insert'), [ew]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(none('update', 'orders/c'), [ew]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.count', expected: 1, select: { source: PG_WAL_SOURCE, name: 'orders', operation: 'delete' } }, [ew]).verdict, 'pass');
  const ew1 = validateWindow({ source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: w.coverage, reason: w.reason, events: w.events });
  assert.equal(evaluateEffectAssertion(none('update', 'orders/c'), [ew1]).verdict, 'missing', 'the unlisted table holds absence back');
  const idle = await collectWindow(o, await o.mark(), (s.commit([['other', 'cron.job_run_details']]), await o.mark()));
  assert.deepEqual([idle.coverage, idle.events.length, evaluateEffectAssertion(none('insert'), [idle]).verdict], ['complete', 0, 'pass'], 'a background writer elsewhere leaves absence decidable');
});

test('only commits that end after the start mark and at or before the end mark are in the window; a re-read transaction counts once', async () => {
  const s = fakeServer(), o = make(s);
  await o.start();
  const ins = id => [['declared', row('INSERT', ` id[text]:'${id}' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null`)]];
  const m0 = await o.mark();
  s.commit(ins('in1'));
  const m1 = await o.mark();
  s.commit(ins('late'));
  s.overshoot = true; // the decoder may return the first transaction past its upto position
  const first = await o.collect(m0, m1);
  assert.deepEqual(first.events.map(e => e.resource), ['orders/in1']);
  const m2 = await o.mark();
  // The wider window reads the ledger and the new commit; nothing twice.
  assert.deepEqual((await o.collect(m0, m2)).events.map(e => e.resource), ['orders/in1', 'orders/late']);
  assert.deepEqual((await o.collect(m1, m2)).events.map(e => e.resource), ['orders/late']);
  // Peek, then advance, never the other way round, and never get_changes.
  const reads = s.log.filter(t => ['peek', 'advance'].includes(t));
  assert.deepEqual(reads, ['peek', 'advance', 'peek', 'advance']);
  // A slot that was not advanced re-reads the same transactions: the ledger keeps each commit once.
  const s2 = fakeServer(), o2 = make(s2);
  await o2.start();
  const a0 = await o2.mark(); s2.commit(ins('x')); const a1 = await o2.mark(); s2.commit(ins('y')); const a2 = await o2.mark();
  s2.fail.push({ tag: 'advance', error: new Error('advance dropped') });
  await o2.collect(a0, a1);
  assert.deepEqual((await o2.collect(a0, a2)).events.map(e => e.resource), ['orders/x', 'orders/y']);
});

test('the end barrier: a flush short of the end mark reads wal-barrier and decodes nothing; a flush at the page start before the header reaches it', async () => {
  const s = fakeServer(), o = make(s);
  await o.start();
  const m0 = await o.mark();
  s.commit([['declared', row('INSERT', " id[text]:'a' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null")]]);
  const m1 = await o.mark();
  s.flush = s.lsn - 0x10n;
  const short = await o.collect(m0, m1);
  assert.deepEqual([short.coverage, short.reason, short.events.length, short.wal.barrier.reached], ['partial', 'wal-barrier', 0, false]);
  assert.ok(!s.log.includes('peek'), 'nothing is decoded before the barrier');
  assert.notEqual(evaluateEffectAssertion(none('insert'), [validateWindow({ source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: short.coverage, reason: short.reason, events: short.events })]).verdict, 'pass');
  // The insert position just past a page header (24 bytes, 40 at a segment start): the flush at that page's start has
  // reached it. Any other gap has not: a record continued from the previous page can end at +32.
  const at = async (lsn, flush) => { s.lsn = lsn; s.flush = flush; const from = await o.mark(); const w = await o.collect(from, await o.mark()); return w.wal.barrier.reached; };
  s.lsn = 0x2002018n; s.flush = 0x2002000n;
  const page = await o.collect(m1, await o.mark());
  assert.deepEqual([page.coverage, page.wal.barrier.reached], ['complete', true]);
  const p = 0x2004000n; // a page start inside a segment
  assert.equal(await at(p + 32n, p), false, '+32 is not a header');
  assert.equal(await at(p + 40n, p), false, '+40 inside a segment is not a header');
  assert.equal(await at(p + 24n, p), true);
  assert.equal(await at(0x3000028n, 0x3000000n), true, '+40 at a segment start');
  assert.equal(await at(0x4000020n, 0x4000000n), false, '+32 at a segment start');
});

test('slot and session failures read inconclusive with their reason, never no change; the next mark opens a new slot', async () => {
  const ins = id => [['declared', row('INSERT', ` id[text]:'${id}' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null`)]];
  const outcome = w => [w.coverage, w.reason];
  // WAL the slot needed was removed.
  let s = fakeServer(), o = make(s);
  await o.start();
  let m0 = await o.mark(); s.commit(ins('a')); s.walStatus = 'lost';
  assert.deepEqual(outcome(await o.collect(m0, await o.mark())), ['failed', 'wal-status-lost'], 'the end mark itself sees the lost slot');
  s = fakeServer(); o = make(s); await o.start();
  m0 = await o.mark(); s.commit(ins('a')); let m1 = await o.mark(); s.walStatus = 'lost';
  assert.deepEqual(outcome(await o.collect(m0, m1)), ['partial', 'wal-status-lost']);
  // The slot is no longer held by this session.
  s = fakeServer(); o = make(s); await o.start();
  m0 = await o.mark(); s.commit(ins('a')); m1 = await o.mark(); s.notHeld = true;
  assert.deepEqual(outcome(await o.collect(m0, m1)), ['partial', 'slot-not-held']);
  // The connection was lost between the marks: the read cannot happen, and the window across the new slot is not covered.
  s = fakeServer(); o = make(s); await o.start();
  m0 = await o.mark(); s.commit(ins('a')); m1 = await o.mark();
  s.fail.push({ tag: 'flush', error: new PgError('connection-closed') });
  const cut = await o.collect(m0, m1);
  assert.deepEqual(outcome(cut), ['partial', 'connection-lost']);
  const m2 = await o.mark();
  assert.equal(s.slots.size, 1, 'a new temporary slot');
  const across = await o.collect(m0, m2);
  assert.deepEqual(outcome(across), ['partial', 'connection-lost,slot-created-after-baseline']);
  assert.equal(evaluateEffectAssertion(none('insert'), [validateWindow({ source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: across.coverage, reason: across.reason, events: across.events })]).verdict, 'missing');
  // Any server error in the session ends its temporary slot: the generation ends as slot-lost.
  s = fakeServer(); o = make(s); await o.start();
  m0 = await o.mark(); s.commit(ins('a')); m1 = await o.mark();
  s.fail.push({ tag: 'flush', error: new PgError('query-failed', '22012') });
  assert.deepEqual(outcome(await o.collect(m0, m1)), ['partial', 'decode-failed,slot-lost']);
  assert.deepEqual(outcome(await o.collect(m0, await o.mark())), ['partial', 'slot-created-after-baseline,slot-lost']);
  // A mark that cannot be read fails its windows.
  s = fakeServer(); o = make(s); await o.start();
  m0 = await o.mark(); s.fail.push({ tag: 'catalog', error: new PgError('query-failed', '42501') });
  assert.deepEqual(outcome(await o.collect(m0, await o.mark())), ['failed', 'permission-denied']);
});

test('the database\'s catalog fingerprint: start() reads the baseline in its new session; a change against it, or inside a window, reads schema-drift', async () => {
  const kinds = (label = 'base', inst = 'v1') => FAKE_CATALOG.kinds.map(([kind, n]) => [kind, n, sha(`${kind}:${label}`), sha(`${kind}:${label}:${inst}`)]);
  let s = fakeServer();
  s.dbCatalog = { kinds: kinds(), versions: [['16400', '100', '16400']] };
  const o = make(s);
  await o.start();
  assert.ok(s.log.includes('dbcatalog') && s.log.includes('dbversions') && !s.log.includes('writers'), 'the baseline is read at start, before any mark');
  assert.equal((await window(o, () => {})).coverage, 'complete');
  assert.equal((await window(o, () => { s.dbCatalog = { kinds: kinds('migrated'), versions: [['16400', '101', '16400']] }; })).reason, 'schema-drift');
  assert.equal((await window(o, () => {})).reason, 'schema-drift', 'a later window still differs from the baseline');
  const record = o.catalog();
  assert.deepEqual([record.engine, record.changedDuringRun], ['postgres', true]); assert.notEqual(record.final, record.sha256);
  // Changed and changed back inside a window (the instance), and a relation's row moved under the same file node.
  s = fakeServer(); s.dbCatalog = { kinds: kinds(), versions: [['16400', '100', '16400']] };
  const r = make(s); await r.start();
  assert.equal((await window(r, () => { s.dbCatalog = { kinds: kinds('base', 'v2'), versions: [['16400', '100', '16400']] }; })).reason, 'schema-drift');
  s.dbCatalog = { kinds: kinds('base', 'v2'), versions: [['16400', '100', '16400']] };
  assert.equal((await window(r, () => { s.dbCatalog = { kinds: kinds('base', 'v2'), versions: [['16400', '102', '16400']] }; })).reason, 'schema-drift', 'row-level security switched off and on');
  assert.equal((await window(r, () => { s.dbCatalog = { kinds: kinds('base', 'v2'), versions: [['16400', '103', '16410']] }; })).coverage, 'complete', 'a rewrite (TRUNCATE) is not a schema change');
  // A baseline read that fails once (a lock held past the wait, on the catalog's own session) is tried again: the start
  // goes on and the slot is untouched. One that never reads refuses the start, and the slot goes with it.
  s = fakeServer(); s.fail.push({ tag: 'dbcatalog', error: new PgError('query-failed', '55P03') });
  const retried = make(s);
  await retried.start();
  assert.equal(s.slots.size, 1, 'the error never reached the slot\'s session');
  assert.equal((await window(retried, () => {})).coverage, 'complete');
  s = fakeServer(); for (let i = 0; i < 3; i++) s.fail.push({ tag: 'dbcatalog', error: new PgError('query-failed', '55P03') });
  await assert.rejects(make(s).start(), /catalog-unreadable at start/);
  assert.equal(s.slots.size, 0);
  // An error on the catalog's session at a mark (a lock not granted in time): catalog-unreadable, and the slot stays.
  s = fakeServer(); const u = make(s); await u.start();
  s.fail.push({ tag: 'dbcatalog', error: new PgError('query-failed', '55P03') });
  const locked = await window(u, () => {});
  assert.equal(locked.reason, 'catalog-unreadable'); assert.equal(s.slots.size, 1);
  assert.equal((await window(u, () => {})).coverage, 'complete', 'the next window reads normally, in the same slot generation');
  // A fingerprint that does not read as one at a mark: catalog-unreadable, never complete.
  assert.equal((await window(u, () => { s.dbCatalog = { kinds: kinds().slice(1), versions: [] }; })).reason, 'catalog-unreadable');
  // A catalog changed while a mark was read (between the bracket's two reads): schema-drift.
  s = fakeServer(); const b = make(s); await b.start();
  const from = await b.mark(); s.onDbCatalog = () => { s.dbCatalog = { kinds: kinds('during'), versions: [] }; s.onDbCatalog = null; };
  const to = await b.mark(); s.dbCatalog = undefined;
  assert.equal((await b.collect(from, to)).reason, 'schema-drift');
});

test('schema drift, a write lock held at the end mark, a TRUNCATE and a key the WAL does not carry each make the window partial', async () => {
  const ins = id => ['declared', row('INSERT', ` id[text]:'${id}' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null`)];
  const reasonOf = async (s, between, o = make(s)) => { await o.start(); const w = await window(o, between); return w.reason; };
  let s = fakeServer();
  assert.equal(await reasonOf(s, () => { s.drift += 1; }), 'schema-drift', 'a catalog row version changed between the marks');
  s = fakeServer();
  assert.equal(await reasonOf(s, () => { s.driftDuringMark = true; }), 'schema-drift', 'the catalog changed while the end mark was read');
  s = fakeServer();
  assert.equal(await reasonOf(s, () => { s.writers = 1; }), 'transaction-in-flight-at-window-end');
  s = fakeServer();
  assert.equal(await reasonOf(s, () => { s.writersAfter = 1; }), 'transaction-in-flight-at-window-end', 'a writer that takes its lock after the first read and is open at the position');
  // Defence in depth: a catalog that came back to an earlier fingerprint (row versions only move forward, so only a change
  // the fingerprint does not see could do this): a transaction parsed under neither mark's catalog is drift.
  s = fakeServer();
  const back = make(s); await back.start();
  const c0 = await back.mark(); s.drift += 1;
  s.commit([row('INSERT', " id[text]:'z' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null")]);
  await back.collect(c0, await back.mark()); s.drift -= 1;
  assert.equal((await back.collect(c0, await back.mark())).reason, 'schema-drift');
  s = fakeServer();
  const o = make(s); await o.start();
  s.writers = 1; const m0 = await o.mark(); s.writers = 0; // a writer at the start mark only: its commit, if any, is in the window
  assert.equal((await o.collect(m0, await o.mark())).coverage, 'complete');
  s = fakeServer();
  assert.equal(await reasonOf(s, () => s.commit([['declared', 'table public.orders: TRUNCATE: (no-flags)']])), 'table-truncated');
  s = fakeServer();
  assert.equal(await reasonOf(s, () => s.commit([['truncate', 'table public.audit, public.orders: TRUNCATE: restart_seqs cascade']])), 'table-truncated,unlisted-table-changed', 'the other table it names is unlisted');
  s = fakeServer();
  const other = make(s); await other.start();
  const t = await window(other, () => s.commit([['truncate', 'table public.audit, "Odd, name".x: TRUNCATE: (no-flags)']]));
  assert.deepEqual([t.coverage, t.reason, t.wal.others.unlisted], ['partial', 'unlisted-table-changed', [{ name: '"Odd, name".x', changes: 1 }, { name: 'public.audit', changes: 1 }]]);
  // Not in the replica identity: inserts stay exact; an UPDATE without an old key and a DELETE without a tuple cannot name the row.
  for (const [line, want] of [[ins('k'), null], [['declared', row('UPDATE', " id[text]:'k' status[text]:'y' amount[numeric]:1 email[text]:null note[text]:null")], 'key-not-in-replica-identity'],
    [['declared', row('DELETE', ' (no-tuple-data)')], 'key-not-in-replica-identity']]) {
    s = fakeServer(); s.relations[0].covered = 'false';
    assert.equal(await reasonOf(s, () => s.commit([line])), want, line[1]);
  }
  s = fakeServer(); s.relations[0].covered = 'false';
  const uncovered = make(s); await uncovered.start();
  const kept = await window(uncovered, () => s.commit([row('UPDATE', " id[text]:'k' status[text]:'y' amount[numeric]:1 email[text]:null note[text]:null")]));
  assert.deepEqual([kept.reason, kept.events.map(e => `${e.operation} ${e.resource}`)], ['key-not-in-replica-identity', ['update orders/k']], 'the new key is certain; the old one is not');
  for (const [line, want] of [[['declared', row('INSERT', " id[text]:null status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null")], 'key-unreadable'],
    [['declared', `table public.orders: INSERT: id[text]:'${'k'.repeat(200)}' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null`], 'key-too-long'],
    [['declared', row('INSERT', " id[text]:'a'")], 'decode-unparsed'], [['oversize', null], 'change-too-large'], [['unknown', null], 'decode-unparsed'], [['truncate', 'table x: TRUNCATE: (no-flags)'], 'decode-unparsed']]) {
    s = fakeServer();
    assert.equal(await reasonOf(s, () => s.commit([line])), want, String(line[1]).slice(0, 60));
  }
  // A change outside BEGIN and COMMIT breaks the stream's framing: the read is refused, never half kept.
  s = fakeServer();
  assert.equal(await reasonOf(s, () => s.loose('declared', row('INSERT', " id[text]:'x' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null"), '9')), 'decode-unparsed');
});

test('an UPDATE that moves the key is an update of both keys; a key-covered UPDATE without an old key keeps its key', async () => {
  const s = fakeServer(), o = make(s);
  await o.start();
  const w = await window(o, () => {
    s.commit([['declared', row('UPDATE', " old-key: id[text]:'a' new-tuple: id[text]:'z' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null")]]);
    s.commit([['declared', row('UPDATE', " id[text]:'q' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null")]]);
  });
  assert.deepEqual(w.events.map(e => `${e.operation} ${e.resource}`), ['update orders/a', 'update orders/z', 'update orders/q']);
  assert.deepEqual(w.wal.tables[0].changes.map(c => [c.key, c.oldKey ?? null]), [['z', 'a'], ['q', null]]);
});

test('digest at decode: undeclared values never leave the observer, sensitive values are sealed, and each change carries its transaction id and commit LSN', async () => {
  const s = fakeServer(), o = make(s, { tables: [{ table: 'orders', key: 'id', values: ['status', 'email'], sensitive: ['email'] }] });
  await o.start();
  const w = await window(o, () => s.commit([['declared', row('INSERT', " id[text]:'a' status[text]:'open' amount[numeric]:777.77 email[text]:'vip@example.test' note[text]:'internal-note-123'")]], { xid: 4242 }));
  const text = JSON.stringify(w);
  for (const secret of ['vip@example.test', 'internal-note-123', '777.77']) assert.ok(!text.includes(secret), secret);
  const c = w.wal.tables[0].changes[0];
  assert.equal(c.values.status, 'open'); assert.match(c.values.email.sealed, /^[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(c.digests).sort(), ['amount', 'note']); assert.match(c.digests.note, /^[a-f0-9]{64}$/);
  assert.equal(c.xid, '4242'); assert.match(c.commitLsn, /^[0-9A-F]+\/[0-9A-F]+$/);
  // The same undeclared value digests the same within the observer, so a change and its revert are visible.
  const again = await window(o, () => s.commit([['declared', row('UPDATE', " id[text]:'a' status[text]:'open' amount[numeric]:777.77 email[text]:'vip@example.test' note[text]:'other'")]]));
  assert.notEqual(again.wal.tables[0].changes[0].digests.note, c.digests.note);
  assert.equal(again.wal.tables[0].changes[0].digests.amount, c.digests.amount);
  assert.deepEqual(o.judgeValue(w.wal, { table: 'orders', key: 'a', column: 'email', equals: 'vip@example.test' }), { verdict: 'pass', reason: null });
  assert.deepEqual(o.judgeValue(w.wal, { table: 'orders', key: 'a', column: 'email', equals: 'other@example.test' }), { verdict: 'fail', reason: 'value-mismatch' });
  assert.deepEqual(judgeWalValue(w.wal, { table: 'orders', key: 'a', column: 'email', equals: 'vip@example.test' }), { verdict: 'inconclusive', reason: 'sealed' }, 'only the observer holds the salt');
});

test('the value judge: the last change of the key decides; an unchanged TOAST value reads an earlier change or is inconclusive', async () => {
  const s = fakeServer(), o = make(s, { tables: [{ table: 'orders', key: 'id', values: ['status', 'note'] }] });
  await o.start();
  const upd = (id, status, note) => ['declared', row('UPDATE', ` id[text]:'${id}' status[text]:'${status}' amount[numeric]:1 email[text]:null note[text]:${note}`)];
  const w = await window(o, () => {
    s.commit([upd('a', 'open', "'long text'"), upd('a', 'refunded', 'unchanged-toast-datum')]);
    s.commit([upd('t', 'open', 'unchanged-toast-datum')]);
    s.commit([['declared', row('DELETE', " id[text]:'d'")]]);
  });
  const judge = expectation => o.judgeValue(w.wal, { table: 'orders', ...expectation });
  assert.deepEqual(judge({ key: 'a', column: 'status', equals: 'refunded' }), { verdict: 'pass', reason: null });
  assert.deepEqual(judge({ key: 'a', column: 'status', equals: 'open' }), { verdict: 'fail', reason: 'value-mismatch' });
  assert.deepEqual(judge({ key: 'a', column: 'note', equals: 'long text' }), { verdict: 'pass', reason: null }, 'the marker reads the change before it');
  assert.deepEqual(judge({ key: 't', column: 'note', equals: 'long text' }), { verdict: 'inconclusive', reason: 'toast-unchanged' });
  assert.deepEqual(judge({ key: 'd', column: 'status', equals: 'x' }), { verdict: 'fail', reason: 'row-deleted' });
  assert.deepEqual(judge({ key: 'n', column: 'status', equals: 'x' }), { verdict: 'inconclusive', reason: 'row-not-written-in-window' });
  assert.deepEqual(judge({ key: 'a', column: 'amount', equals: '1' }), { verdict: 'inconclusive', reason: 'column-not-declared' });
  assert.deepEqual(judgeWalValue({ ...w.wal, coverage: 'partial', reasons: ['wal-barrier'] }, { table: 'orders', key: 'a', column: 'status', equals: 'refunded' }), { verdict: 'inconclusive', reason: 'wal-barrier' });
});

test('marks refuse what the WAL does not hold: wal_level, a standby, an unlogged or temporary table or descendant, a missing table, an unstable key type', async () => {
  for (const [server, code] of [[{ walLevel: 'replica' }, 'wal-level-not-logical'], [{ version: '120000' }, 'server-too-old'], [{ recovery: 'true' }, 'standby-refused']]) {
    const s = fakeServer(server);
    await assert.rejects(make(s).start(), e => e.code === code, code);
    assert.equal(s.closed, 1, 'the session is closed');
  }
  for (const [change, reason] of [[r => { r.persistence = 'u'; }, 'unlogged-table'], [r => { r.persistence = 't'; }, 'temporary-table'], [r => { r.relkind = 'v'; }, 'relation-not-heap-table'],
    [r => { r.key = [1, false, false, 'mood']; }, 'key-type-refused'], [r => { r.key = [0, null, null, null]; }, 'key-type-refused'], [r => { r.root = 'false'; }, 'table-missing']]) {
    const s = fakeServer(); change(s.relations[0]);
    const o = make(s); await o.start();
    const w = await o.collect(await o.mark(), await o.mark());
    assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', reason, 0], reason);
  }
  const s = fakeServer();
  s.relations.push({ i: 0, oid: '16401', xmin: '101', qualified: 'public.orders_child', relkind: 'r', persistence: 'u', replident: 'd', root: 'false', columns: ORDERS, key: [1, true, false, 'text'], covered: 'true' });
  const o = make(s); await o.start();
  assert.equal((await o.collect(await o.mark(), await o.mark())).reason, 'descendant-not-decoded');
});

test('partitions decode under their own names and count as the declared table; a window must move forward; stop drops the slot', async () => {
  const s = fakeServer();
  s.relations = [{ i: 0, oid: '16500', xmin: '1', qualified: 'public.orders', relkind: 'p', am: '', persistence: 'p', replident: 'd', root: 'true', columns: ORDERS, key: [1, true, false, 'text'], covered: 'true' },
    { i: 0, oid: '16501', xmin: '2', qualified: 'public.orders_eu', relkind: 'r', persistence: 'p', replident: 'd', root: 'false', columns: ORDERS, key: [1, true, false, 'text'], covered: 'true' }];
  const o = make(s); await o.start();
  const m0 = await o.mark();
  s.commit([['declared', "table public.orders_eu: INSERT: id[text]:'e1' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null"]]);
  const m1 = await o.mark();
  assert.deepEqual((await o.collect(m0, m1)).events.map(e => `${e.name} ${e.resource}`), ['orders orders/e1']);
  assert.deepEqual([(await o.collect(m1, m0)).coverage, (await o.collect(m1, m1)).reason], ['failed', 'window-not-forward']);
  assert.equal(s.slots.size, 1);
  await o.stop();
  assert.equal(s.slots.size, 0); assert.equal(s.closed, 1); assert.ok(s.log.includes('drop'));
});

test('a stretch is read with its own end mark\'s catalog: a rename after the mark keeps the window\'s change, however the windows are collected', async () => {
  const s = fakeServer(), o = make(s);
  await o.start();
  const m0 = await o.mark();
  s.commit([row('INSERT', " id[text]:'a' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null")]);
  const m1 = await o.mark();
  // Renamed after the end mark: test_decoding printed the change under the old name.
  s.relations[0].qualified = 'public.orders_renamed'; s.drift += 1;
  s.commit(["table public.orders_renamed: INSERT: id[text]:'b' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null"]);
  const m2 = await o.mark();
  const later = await o.collect(m1, m2); // collected first, as a run-end gap window may be
  assert.deepEqual([later.reason, later.events.map(e => e.resource)], ['schema-drift', ['orders/b']]);
  const first = await o.collect(m0, m1);
  assert.deepEqual([first.coverage, first.events.map(e => e.resource)], ['complete', ['orders/a']]);
  assert.equal(evaluateEffectAssertion(none('insert'), [validateWindow({ source: o.source, instanceId: o.instanceId, scope: o.scope, coverage: first.coverage, reason: first.reason, events: first.events })]).verdict, 'fail');
  // Each stretch was peeked up to its own end mark, with that mark's names as the prefixes.
  assert.deepEqual(s.log.filter(t => t === 'peek' || t === 'advance'), ['peek', 'advance', 'peek', 'advance']);
});

test('a relation in two declared trees reports each change under both names; system catalogs are refused', async () => {
  const s = fakeServer(), eu = { i: 1, oid: '16401', xmin: '101', qualified: 'public.orders_eu', relkind: 'r', persistence: 'p', replident: 'd', root: 'true', columns: ORDERS, key: [1, true, false, 'pg_catalog.textout'], covered: 'true' };
  s.relations.push({ ...eu, i: 0, root: 'false' }, eu);
  const o = make(s, { tables: [{ table: 'orders', key: 'id' }, { table: 'orders_eu', key: 'id' }] }); await o.start();
  const w = await window(o, () => s.commit(["table public.orders_eu: INSERT: id[text]:'e1' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null"]));
  assert.deepEqual([w.coverage, w.events.map(e => `${e.name} ${e.resource}`)], ['complete', ['orders orders/e1', 'orders_eu orders_eu/e1']]);
  const sys = fakeServer(); sys.relations[0].oid = '1260';
  const c = make(sys); await c.start();
  assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await c.collect(await c.mark(), await c.mark())), ['failed', 'system-catalog-refused']);
});

test('a blank-padded char key, or a domain over one, reads without its padding (by its output function)', async () => {
  const s = fakeServer();
  s.relations[0].columns = [[1, 'id[public.code]', 'id'], ...ORDERS.slice(1)]; s.relations[0].key = [1, true, false, 'pg_catalog.bpcharout'];
  const o = make(s); await o.start();
  const w = await window(o, () => s.commit(["table public.orders: INSERT: id[public.code]:'ab    ' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null"]));
  assert.deepEqual(w.events.map(e => e.resource), ['orders/ab']);
});

// Every other table is a declared queue, ignored or unlisted; the end barrier; the shared-database rule.
const QUEUE = { queues: [{ table: 'jobs', pending: { column: 'state', in: ['created', 'active'] } }], drainTimeoutMs: 200, pollMs: 20 };
const ins = id => ['declared', row('INSERT', ` id[text]:'${id}' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null`)];

test('other tables: an unlisted change or a logical message holds absence back; an ignored or queue change only counts; a declared table is never ignored', async () => {
  for (const [lines, extra, want, counts] of [
    [[['other', 'public.sessions_log']], {}, 'unlisted-table-changed', { ignored: 0, queue: 0, unlisted: 1 }],
    [[['other', 'public.sessions_log']], { ignore: ['public.sessions_log'] }, null, { ignored: 1, queue: 0, unlisted: 0 }],
    [[['other', 'auth.audit_log_entries'], ['other', 'cron.job_run_details'], ['other', 'net._http_response']], { platform: 'supabase' }, null, { ignored: 3, queue: 0, unlisted: 0 }],
    // On the Supabase list's purpose: requests pg_net sends, scheduled jobs and accounts are effects, never ignored.
    [[['other', 'net.http_request_queue'], ['other', 'cron.job'], ['other', 'auth.users']], { platform: 'supabase' }, 'unlisted-table-changed', { ignored: 0, queue: 0, unlisted: 3 }],
    [[['other', 'public.jobs']], QUEUE, null, { ignored: 0, queue: 1, unlisted: 0 }],
    [[['message', null]], {}, 'logical-message', { ignored: 0, queue: 0, unlisted: 0 }],
  ]) {
    const s = fakeServer(), o = make(s, extra); s.pending = [0]; await o.start();
    const w = await window(o, () => s.commit([ins('n'), ...lines]));
    assert.deepEqual([w.reason, w.wal.others.ignored, w.wal.others.queue, w.wal.others.unlisted.length], [want, counts.ignored, counts.queue, counts.unlisted], JSON.stringify(lines));
    assert.equal(w.events.length, 1, 'the declared change is an event either way');
  }
  // A platform entry that would cover a declared table is overridden for it; a profile entry naming one is refused.
  const s = fakeServer(), o = make(s, { platform: 'supabase', tables: [{ table: 'sessions', schema: 'auth', key: 'id' }] });
  s.relations[0].qualified = 'auth.sessions';
  await o.start();
  const w = await window(o, () => s.commit([['other', 'auth.refresh_tokens']]));
  assert.deepEqual([w.coverage, w.wal.others.ignored, w.wal.others.ignore.overridden], ['complete', 1, ['auth.sessions']]);
  assert.throws(() => make(fakeServer(), { ignore: ['public.jobs'], ...QUEUE }), /never on the ignore list/);
  assert.throws(() => make(fakeServer(), { ignore: ['pg_catalog'] }), /system schema/);
});

test('tables the WAL never carries: an unlogged or foreign table that is neither declared, a queue nor ignored holds absence back', async () => {
  for (const [notInWal, extra, want] of [[['public.cache'], {}, 'table-not-in-wal'], [['public.cache'], { ignore: ['public.cache'] }, null], [['_analytics.log_events'], { platform: 'supabase' }, null],
    [['remote.orders_fdw'], { platform: 'supabase' }, 'table-not-in-wal'], [[], {}, null]]) {
    const s = fakeServer(), o = make(s, extra); await o.start();
    s.notInWal = notInWal;
    const w = await window(o, () => s.commit([ins('n')]));
    assert.deepEqual([w.reason, w.wal.others.notInWal], [want, want ? notInWal : []], JSON.stringify(notInWal));
  }
  // Present at the start mark only still counts: its writes in the window are unseen either way.
  const s = fakeServer(), o = make(s); await o.start();
  s.notInWal = ['public.cache']; const m0 = await o.mark(); s.notInWal = []; const m1 = await o.mark();
  assert.equal((await o.collect(m0, m1)).reason, 'table-not-in-wal');
});

test('end barrier: a drained queue reads complete; pending work, a queue write lock, a failed drain read or a queue change after the drain read does not', async () => {
  const run = async (setup, between = () => {}) => { const s = fakeServer(); setup(s); const o = make(s, QUEUE); await o.start(); return window(o, () => between(s)); };
  const clean = await run(s => { s.pending = [0]; });
  assert.deepEqual([clean.coverage, clean.wal.queues.end.clean, clean.wal.queues.end.pending], ['complete', true, [{ queue: 'public.jobs', pending: 0 }]]);
  assert.equal((await run(s => { s.pending = [2]; })).reason, 'queue-not-drained');
  assert.equal((await run(s => { s.pending = [0]; s.queueLocks = 1; })).reason, 'queue-not-drained', 'a write lock on the queue at the drain read');
  assert.equal((await run(s => { s.pending = [0]; s.queueError = new PgError('query-failed', '42501'); })).reason, 'queue-unreadable');
  // The queue drains while the mark waits: the reading that ended the wait was clean.
  let polls = 0;
  const waited = await run(s => { s.pending = () => (++polls > 4 ? [0] : [1]); });
  assert.deepEqual([waited.coverage, polls > 4, waited.wal.queues.end.waitedMs >= 0], ['complete', true, true]);
  // A queue change committed between the drain read (P0) and the mark (P): the job may have finished after its effect.
  const late = await run(s => { s.pending = [0]; }, s => { s.onQueueCount = () => { s.onQueueCount = null; s.commit([['other', 'public.jobs']]); }; });
  assert.equal(late.reason, 'queue-not-drained');
  // An unlogged queue is refused: its changes never reach the WAL, so the (P0, P] check would be blind to them.
  assert.equal((await run(s => { s.pending = [0]; s.queueNames = ['public.jobs']; s.queuePersistence = { 'public.jobs': 'ur' }; })).reason, 'queue-not-in-wal');
  assert.equal((await run(s => { s.pending = [0]; s.queueNames = ['public.jobs']; s.queuePersistence = { 'public.jobs': 'pv' }; })).reason, 'queue-not-in-wal', 'a view declared as a queue');
  // Queue partitions, named by the drain read, are the queue's changes, not unlisted ones.
  const parts = await run(s => { s.pending = [0]; s.queueNames = ['public.jobs', 'public.jobs_p1']; }, s => s.commit([['other', 'public.jobs_p1']]));
  assert.deepEqual([parts.coverage, parts.wal.others.queue], ['complete', 1]);
  // A queue write lock at the end mark counts as an in-flight writer: the slot session's lock read names the queue tables.
  const s = fakeServer(), o = make(s, QUEUE); s.pending = [0]; await o.start(); await o.mark();
  // The drain read comes before the mark's own reads: P0, then the locks, then the counts.
  assert.match(s.log.join(), /drainsession,set,set,set,drainlsn,queuelocks,queuecount,queuenames,catalog,writers,position/);
  const statements = []; const conn = s.connect; s.connect = async (...a) => { const c = await conn(...a); return { query: async sql => { statements.push(sql); return c.query(sql); }, close: () => c.close() }; };
  const o2 = make(s, QUEUE); await o2.start(); await o2.mark();
  assert.ok(statements.some(sql => /sh:writers/.test(sql) && /"public", "jobs"|\('public', 'jobs'\)/.test(sql)), 'the writers read covers the queue tree');
});

test('shared database: start refuses while another run holds a lease; a lease seen at a mark fails the window; the lease is held in the slot session', async () => {
  const s = fakeServer(); s.otherRuns = 1;
  await assert.rejects(make(s).start(), /shared-database/);
  assert.equal(s.slots.size, 0, 'the refused start leaves no slot');
  const t = fakeServer(), o = make(t); await o.start();
  const m0 = await o.mark(); t.commit([ins('x')]); t.otherRuns = 1; const m1 = await o.mark();
  // No absence passes on it, and the write it read stays an event: a lock of the lease's class cannot erase a fail.
  const shared = await o.collect(m0, m1);
  assert.deepEqual([shared.coverage, shared.reason, shared.events.map(e => e.resource)], ['partial', 'shared-database', ['orders/x']]);
  assert.ok(t.log.includes('lease') && t.log.includes('shared'));
  const u = fakeServer(), off = make(u, { runLease: false }); u.otherRuns = 1; await off.start();
  assert.equal((await window(off, () => {})).coverage, 'complete');
  assert.ok(!u.log.includes('lease') && !u.log.includes('shared'), 'runLease false reads no lease');
});

// Without actorCapture the observer is byte-for-byte what it was before the actor join: every statement it
// sends, in order and on which session, and every window and record it returns, in a scenario with a declared queue-free
// platform list, a run lease, inserts, a write and its revert, other tables and messages. The digest was computed with this
// same scenario on pg-wal.mjs before the actor join. Only what differs per run is normalised: the temporary slot's random name, the
// observer's salted column digests (and the event content digests and sealed record digest over them), the run lease's
// random key (fixed here through its test seam), and the clock (times, and the barrier's measured wait).
const WAL_MAIN_DIGEST = '79fe3b530ecd606b26069371df1d12537f405f5006bae9facebef0663dc3586d';
test('without actorCapture, pg-wal sends and returns exactly what it did before the actor join', async () => {
  const s = fakeServer(), sent = [];
  const connect = async (...args) => { const c = await s.connect(...args), id = sent.length; sent.push([id, 'open']);
    return Object.assign(Object.create(c), { query: (sql, opts) => { sent.push([id, sql]); return c.query(sql, opts); }, close: () => { sent.push([id, 'close']); return c.close(); } }); };
  const o = make({ connect }, { platform: 'supabase', runKey: 424242 });
  await o.start();
  s.commit([['declared', row('INSERT', " id[text]:'before' status[text]:'x' amount[numeric]:1 email[text]:null note[text]:null")]]);
  const w = await window(o, () => {
    s.commit([['declared', row('INSERT', " id[text]:'b' status[text]:'new' amount[numeric]:5 email[text]:'p@q' note[text]:'n'")], ['declared', row('DELETE', " id[text]:'b'")]]);
    s.commit([['declared', row('UPDATE', " id[text]:'a' status[text]:'refunded' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")]]);
    s.commit([['other', 'public.audit'], ['other', 'auth.sessions'], ['message', null]]);
  });
  const w2 = await window(o, () => { s.commit([['declared', row('UPDATE', " id[text]:'a' status[text]:'open' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")]]); });
  const record = o.catalog();
  await o.stop();
  const scrub = value => JSON.parse(JSON.stringify(value, (k, v) => (k === 'digests' && v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).map(n => [n, 'hmac'])) : ['observedAt', 'at', 'waitedMs'].includes(k) ? 'time' : k === 'contentDigest' ? 'over-hmac' : v))
    .replace(/scopehaven_wal_[0-9a-f]{16}/g, 'slot')
    // The observer now has a source of its own (sql-wal); before, its windows carried sql-snapshot. The rename is the only difference.
    .replace(/"sql-wal"/g, '"sql-snapshot"'));
  const view = scrub({ sent, scope: o.scope, source: o.source, kind: o.kind, windows: [w, w2].map(x => ({ ...x, wal: (({ digest: _sealed, ...rest }) => rest)(x.wal) })), record });
  assert.equal(sha(JSON.stringify(view)), WAL_MAIN_DIGEST, `view digest ${sha(JSON.stringify(view))}`);
});

// The per-write join with an intact capture answered through the connect seam: each
// decoded write named by its own transaction, a write the capture never saw named by no one, and the capture's own audit rows
// counted apart (others.capture), never unlisted.
test('with an intact actor capture, each decoded write is its own transaction\'s actor, and the capture\'s audit rows are counted apart', async () => {
  const { verifySql, verifyAtInstall, PG_ACTOR_SCHEMA } = await import('./pg-actor.mjs');
  const block = { testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', tables: [{ table: 'orders', key: 'id' }], actor: { from: 'jwt-claims' }, principals: { 'sub-alice': 'alice', 'sub-bob': 'bob' } };
  const h = createHash('sha256').update(`${PG_ACTOR_SCHEMA}\nscopehaven_actor`).digest('hex').slice(0, 10), owner = 'supabase_admin:true', path = '{search_path=pg_catalog, pg_temp}';
  const definitions = [
    { rows: [[owner, null, PG_ACTOR_SCHEMA, '900']] },
    { rows: [['capture', '', 'true', path, 'md5a', owner, null, '901', 'v'], ['ledger', 'after_seq bigint, max_rows integer', 'true', path, 'md5b', owner, null, '902', 's']] },
    { rows: ['insert', 'update', 'delete'].map((op, i) => ['public.orders', `sh_actor_${h}_${op}`, 'O', '0', '', '', '', 'true', '', 'capture', String(903 + i)]) },
    { rows: [['true', 'false', 'p', 'r', '0', '0', '0', owner, null]] },
    { rows: 'seq,txid,tbl,key,op,rowcount,depth,row_xmin,claims_sub,claims_role,legacy_sub,header_sub,set_role,session_role,app_actor,at'.split(',').map(c => [c, 'text']) },
  ];
  const entry = (seq, xid, key, sub) => [String(seq), String(xid), String(xid), 'public.orders', key, 'UPDATE', null, '1', String(xid), sub, 'authenticated', null, sub, 'authenticated', 'authenticator', null];
  const s = fakeServer(), ledger = [];
  const connect = async (...args) => { const c = await s.connect(...args);
    return Object.assign(Object.create(c), { query: (sql, opts) => (sql === verifySql(block) ? Promise.resolve(definitions) : /^SELECT l\.seq::pg_catalog\.text/.test(sql) ? Promise.resolve([{ rows: [...ledger] }]) : c.query(sql, opts)), close: () => c.close() }); };
  const o = make({ connect }, { actorCapture: { block, installedSha256: verifyAtInstall(definitions, block).sha256 } });
  assert.equal(o.scope.actorAttribution, 'principal');
  await o.start();
  const w = await window(o, () => {
    const write = (xid, key, sub, status) => { s.commit([['declared', row('UPDATE', ` id[text]:'${key}' status[text]:'${status}' amount[numeric]:10 email[text]:'x@y' note[text]:'n'`)], ['other', 'scopehaven_actor.audit']], { xid }); ledger.push(entry(ledger.length + 1, xid, key, sub)); };
    write(801, 'a', 'sub-alice', 'refunded');
    write(802, 'b', 'sub-bob', 'held');
    // One key written by both, each in a transaction of its own: each write is its own transaction's actor's.
    write(804, 'd', 'sub-alice', 'refunded');
    write(805, 'd', 'sub-bob', 'held');
    // A write the capture never saw (no audit row in its transaction, no ledger entry).
    s.commit([['declared', row('UPDATE', " id[text]:'c' status[text]:'open' amount[numeric]:1 email[text]:null note[text]:null")]], { xid: 803 });
  });
  assert.equal(w.coverage, 'complete', w.reason);
  assert.deepEqual(w.events.map(e => [e.resource, e.actor]), [['orders/a', 'alice'], ['orders/b', 'bob'], ['orders/d', 'alice'], ['orders/d', 'bob'], ['orders/c', null]]);
  assert.deepEqual([w.wal.others.capture, w.wal.others.unlisted], [4, []]);
  assert.deepEqual(w.actors, { schema: PG_ACTOR_SCHEMA, capture: { start: 'intact', end: 'intact', window: 'intact' }, attributed: 4, unattributed: 1, ambiguous: 0 });
});

// The capture reads intact only when both marks verified it (pg-wal.mjs collect). Its definitions
// altered before the end mark (a capture function replaced in the window) name no one in that window, as pg-actor-join.test.mjs test 3
// pins for pg-snapshot.
test('a capture altered at the end mark names no one in that window', async () => {
  const { verifySql, verifyAtInstall, PG_ACTOR_SCHEMA } = await import('./pg-actor.mjs');
  const block = { testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', tables: [{ table: 'orders', key: 'id' }], actor: { from: 'jwt-claims' }, principals: { 'sub-alice': 'alice' } };
  const h = createHash('sha256').update(`${PG_ACTOR_SCHEMA}\nscopehaven_actor`).digest('hex').slice(0, 10), owner = 'supabase_admin:true', path = '{search_path=pg_catalog, pg_temp}';
  const definitions = fn => [
    { rows: [[owner, null, PG_ACTOR_SCHEMA, '900']] },
    { rows: [['capture', '', 'true', path, fn, owner, null, '901', 'v'], ['ledger', 'after_seq bigint, max_rows integer', 'true', path, 'md5b', owner, null, '902', 's']] },
    { rows: ['insert', 'update', 'delete'].map((op, i) => ['public.orders', `sh_actor_${h}_${op}`, 'O', '0', '', '', '', 'true', '', 'capture', String(903 + i)]) },
    { rows: [['true', 'false', 'p', 'r', '0', '0', '0', owner, null]] },
    { rows: 'seq,txid,tbl,key,op,rowcount,depth,row_xmin,claims_sub,claims_role,legacy_sub,header_sub,set_role,session_role,app_actor,at'.split(',').map(c => [c, 'text']) },
  ];
  const s = fakeServer(), ledger = [];
  let current = definitions('md5a');
  const connect = async (...args) => { const c = await s.connect(...args);
    return Object.assign(Object.create(c), { query: (sql, opts) => (sql === verifySql(block) ? Promise.resolve(current) : /^SELECT l\.seq::pg_catalog\.text/.test(sql) ? Promise.resolve([{ rows: [...ledger] }]) : c.query(sql, opts)), close: () => c.close() }); };
  const o = make({ connect }, { actorCapture: { block, installedSha256: verifyAtInstall(definitions('md5a'), block).sha256 } });
  await o.start();
  const w = await window(o, () => {
    s.commit([['declared', row('UPDATE', " id[text]:'a' status[text]:'refunded' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")], ['other', 'scopehaven_actor.audit']], { xid: 801 });
    ledger.push(['1', '801', '801', 'public.orders', 'a', 'UPDATE', null, '1', '801', 'sub-alice', 'authenticated', null, 'sub-alice', 'authenticated', 'authenticator', null]);
    // The capture function is replaced before the end mark: its definition no longer matches the installation digest.
    current = definitions('md5-replaced');
  });
  await o.stop();
  assert.deepEqual(w.events.map(e => [e.resource, e.actor]), [['orders/a', null]]);
  assert.deepEqual([w.actors.capture.start, w.actors.capture.end, w.actors.attributed], ['intact', 'altered', 0]);
});

// pg_net on the wire (./pg-net-wire.mjs): a wire window covers the queue only when complete. A stub wire stands in here; the
// wire's own windows are pinned in pg-net-wire.test.mjs.
const QUEUE_TABLE = 'net.http_request_queue';
const stubWire = (windowOf, { failMark = false } = {}) => {
  let n = 0;
  const w = { covers: [QUEUE_TABLE], started: 0, stopped: 0, calls: [],
    async start() { w.started += 1; }, async mark() { if (failMark) throw new Error('tap down'); return { index: ++n }; },
    async collect(from, to) { w.calls.push([from.index, to.index]); return windowOf(); }, async stop() { w.stopped += 1; } };
  return w;
};
const DECLARATION = { programRoles: ['supabase_admin'], requestRoles: ['app_gateway'], refused: [], checked: true };
const wireWindow = (coverage, covers = coverage === 'complete' ? [QUEUE_TABLE] : [], custody = 'observer-held') => ({ events: [], coverage, reason: coverage === 'complete' ? null : 'pg-net-sent', custody, declaration: DECLARATION, covers, wire: { schema: 'scopehaven-pg-net-wire/1', coverage, custody } });

test('pg_net on the wire: a complete wire window counts the queue as observed; any other leaves it table-not-in-wal', async () => {
  const run = async (wire, notInWal = [QUEUE_TABLE]) => { const s = fakeServer(), o = make(s, { platform: 'supabase', wire }); await o.start(); s.notInWal = notInWal; const w = await window(o, () => s.commit([ins('n')])); await o.stop(); return w; };
  const complete = stubWire(() => wireWindow('complete')), w = await run(complete);
  assert.deepEqual([w.coverage, w.reason, w.wal.others.notInWal, w.wal.others.wire.covered, w.wal.others.wire.coverage, w.wal.others.wire.custody], ['complete', null, [], [QUEUE_TABLE], 'complete', 'observer-held']);
  assert.deepEqual([complete.started, complete.stopped, complete.calls], [1, 1, [[1, 2]]]);
  // The declaration the wire window rests on goes beside the window, word for word, and in its record.
  assert.deepEqual([w.declaration, w.wal.others.wire.declaration], [DECLARATION, DECLARATION]);
  for (const wire of [stubWire(() => wireWindow('partial')), stubWire(() => wireWindow('failed')),
    // A wire window that is not complete never covers, whatever it lists.
    stubWire(() => wireWindow('partial', [QUEUE_TABLE])), stubWire(() => wireWindow('complete'), { failMark: true }),
    // Nor does a complete window the subject could have closed early (its custody is subject-writable), whatever it lists.
    stubWire(() => wireWindow('complete', [QUEUE_TABLE], 'subject-writable'))]) {
    const p = await run(wire);
    assert.deepEqual([p.reason, p.wal.others.notInWal, p.wal.others.wire.covered], ['table-not-in-wal', [QUEUE_TABLE], []]);
  }
  assert.deepEqual((await run(stubWire(() => wireWindow('complete')), [])).wal.others.wire.covered, [QUEUE_TABLE]);
  // It covers its own table only: another unlogged table still holds absence back.
  const other = await run(stubWire(() => wireWindow('complete')), [QUEUE_TABLE, 'public.cache']);
  assert.deepEqual([other.reason, other.wal.others.notInWal], ['table-not-in-wal', ['public.cache']]);
  // A failed wire mark fails only the wire window.
  const failedMark = await run(stubWire(() => wireWindow('complete'), { failMark: true }));
  assert.deepEqual([failedMark.wal.others.wire.coverage, failedMark.wal.others.wire.reason], ['failed', 'pg-net-mark-failed']);
  // Without wire the record has no wire entry (the pinned digest below holds the rest).
  const s = fakeServer(), o = make(s, { platform: 'supabase' }); await o.start(); s.notInWal = [QUEUE_TABLE];
  const bare = await window(o, () => s.commit([ins('n')]));
  assert.deepEqual([bare.reason, Object.hasOwn(bare.wal.others, 'wire'), Object.hasOwn(bare, 'declaration')], ['table-not-in-wal', false, false]);
  assert.throws(() => make(fakeServer(), { wire: { covers: [] } }), /pg_net wire observer/);
  // attachWire (src/http-connector.mjs gives a profile's pgNetWire this way): before the first start only, once, and only a wire.
  const late = stubWire(() => wireWindow('complete')), s2 = fakeServer(), o2 = make(s2, { platform: 'supabase' });
  assert.throws(() => o2.attachWire({ covers: [] }), /pg_net wire observer/);
  o2.attachWire(late);
  assert.throws(() => o2.attachWire(stubWire(() => wireWindow('complete'))), /attaches once, before the observer starts/);
  await o2.start(); s2.notInWal = [QUEUE_TABLE];
  const attached = await window(o2, () => s2.commit([ins('n')])); await o2.stop();
  assert.deepEqual([attached.reason, attached.wal.others.wire.covered, late.started, late.stopped], [null, [QUEUE_TABLE], 1, 1]);
  const s3 = fakeServer(), o3 = make(s3, { platform: 'supabase' }); await o3.start(); await o3.stop();
  assert.throws(() => o3.attachWire(stubWire(() => wireWindow('complete'))), /attaches once, before the observer starts/);
});
