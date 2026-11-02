import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createSqliteSnapshotObserver } from './sqlite.mjs';
import { collectWindow, evaluateEffectAssertion, validateWindow } from './events.mjs';
import { decideEffects, backendObserved, effectTrace, recomputeEffectTrace } from '../../src/http-effects.mjs';

// A knowledge table whose application sets updated_at = int(time.time()) on every update.
const nowSec = () => Math.floor(Date.now() / 1000);
const sleep = ms => new Promise(r => setTimeout(r, ms));
function auditFile(dir) { const p = join(dir, 'SOURCE-AUDIT.md'); writeFileSync(p, 'synthetic source audit for tests\n'); return p; }
function setup(t, { updatedAt = nowSec() - 3600, wal = true, lag = 0, keyCol = 'id' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-changecol-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'app.db');
  const db = new DatabaseSync(path);
  db.exec(`${wal ? 'PRAGMA journal_mode=WAL;' : 'PRAGMA journal_mode=DELETE;'} CREATE TABLE knowledge (id TEXT PRIMARY KEY, owner TEXT, description TEXT, updated_at INTEGER); CREATE TABLE knowledge_file (id INTEGER PRIMARY KEY, knowledge_id TEXT);`);
  db.prepare('INSERT INTO knowledge VALUES (?, ?, ?, ?)').run('fin', 'finance', 'finance', updatedAt);
  db.prepare('INSERT INTO knowledge VALUES (?, ?, ?, ?)').run('hb', 'support', 'handbook', updatedAt);
  t.after(() => db.close());
  const update = (id, description, at = nowSec()) => db.prepare('UPDATE knowledge SET description = ?, updated_at = ? WHERE id = ?').run(description, at, id);
  const o = createSqliteSnapshotObserver({ path, changeColumnSkewMs: 50, maxCommitLagMs: lag, watchedResources: ['knowledge/fin', 'knowledge/finance', 'knowledge/hb', 'knowledge/new', 'knowledge/fni'],
    tables: [{ table: 'knowledge', key: keyCol, changeColumn: { column: 'updated_at', unit: 'seconds', audit: auditFile(dir) } }, { table: 'knowledge_file', key: 'id' }] });
  return { db, path, update, o };
}
const noUpdate = (resource = 'knowledge/fin') => ({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'knowledge', operation: 'update', ...(resource ? { resource } : {}) } });

test('drilled case: a committed update of the row fails', async t => {
  const { update, o } = setup(t);
  const from = await o.mark(); update('fin', 'tampered'); const w = await collectWindow(o, from, await o.mark());
  assert.equal(evaluateEffectAssertion(noUpdate(), [w]).verdict, 'fail');
});

test('restored case: with the change column unchanged, update absence passes on the source-checked basis', async t => {
  const { o } = setup(t);
  const from = await o.mark(); const w = await collectWindow(o, from, await o.mark());
  const v = evaluateEffectAssertion(noUpdate(), [w]);
  assert.equal(v.verdict, 'pass');
  assert.match(v.basis, /change-column updated_at \(operator-asserted, source-checked: .*SOURCE-AUDIT\.md sha256 [0-9a-f]{12}; skew 50 ms, commit lag 0 ms, 0 ambiguous rows\)/);
  // The observer records presentResources, so a table-wide selector is not exact: it would also cover rows never seen.
  assert.equal(evaluateEffectAssertion(noUpdate(null), [w]).verdict, 'missing');
});

test('negative control: a write and its revert inside one window still fails (updated_at moved)', async t => {
  const { update, o } = setup(t);
  const from = await o.mark(); update('fin', 'tampered'); update('fin', 'finance'); const w = await collectWindow(o, from, await o.mark());
  const v = evaluateEffectAssertion(noUpdate(), [w]);
  assert.equal(v.verdict, 'fail');
});

test('same-second guard: a row updated within 1 s + skew of the start mark stays net-only', async t => {
  const { update, o } = setup(t);
  update('fin', 'recent'); // updated_at = this second
  const from = await o.mark(); const w = await collectWindow(o, from, await o.mark());
  assert.deepEqual(w.exact[0].ambiguousResources, ['knowledge/fin']);
  assert.equal(evaluateEffectAssertion(noUpdate(), [w]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion(noUpdate('knowledge/hb'), [w]).verdict, 'pass'); // other rows are unaffected
  assert.equal(evaluateEffectAssertion(noUpdate(null), [w]).verdict, 'missing'); // a table-wide check includes the ambiguous row
});

test('a content change without the change column voids the assertion for the window', async t => {
  const { db, o } = setup(t);
  const from = await o.mark();
  db.prepare("UPDATE knowledge SET description = 'sneaky' WHERE id = 'hb'").run(); // not stamping updated_at
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.exact[0].violated, true);
  assert.equal(evaluateEffectAssertion(noUpdate('knowledge/fin'), [w]).verdict, 'missing');
  // A violated table reports none of its changes: the update reads missing, never a decided fail or pass.
  assert.equal(w.events.length, 0);
  assert.equal(evaluateEffectAssertion(noUpdate('knowledge/hb'), [w]).verdict, 'missing');
});

test('scope: inserts, deletes, other tables and non-update selectors stay net-only', async t => {
  const { o } = setup(t);
  const from = await o.mark(); const w = await collectWindow(o, from, await o.mark());
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'knowledge', operation: 'insert' } }, [w]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'knowledge', operation: 'delete' } }, [w]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'knowledge_file', operation: 'update' } }, [w]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'knowledge' } }, [w]).verdict, 'missing');
});

test('validation: audit file, positive skew, commit lag and unit are required', t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-changecol-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'x.db'), audit = auditFile(dir);
  const cc = extra => ({ column: 'updated_at', unit: 'seconds', audit, ...extra });
  assert.throws(() => createSqliteSnapshotObserver({ path, changeColumnSkewMs: 50, maxCommitLagMs: 0, tables: [{ table: 'k', key: 'id', changeColumn: cc({ audit: 'pilot-owui/a-string-not-a-file.md' }) }] }), /audit file/);
  assert.throws(() => createSqliteSnapshotObserver({ path, changeColumnSkewMs: 0, maxCommitLagMs: 0, tables: [{ table: 'k', key: 'id', changeColumn: cc() }] }), /changeColumnSkewMs/);
  assert.throws(() => createSqliteSnapshotObserver({ path, changeColumnSkewMs: 50, tables: [{ table: 'k', key: 'id', changeColumn: cc() }] }), /maxCommitLagMs/);
  assert.throws(() => createSqliteSnapshotObserver({ path, changeColumnSkewMs: 50, maxCommitLagMs: 0, tables: [{ table: 'k', key: 'id', changeColumn: cc({ unit: 'ms' }) }] }), /seconds/);
  assert.throws(() => createSqliteSnapshotObserver({ path, changeColumnSkewMs: 50, maxCommitLagMs: 0, tables: [{ table: 'k', key: 'id', changeColumn: cc({ column: 'bad name' }) }] }), /identifier/);
  const scope = { operations: ['tool-call'], names: ['x'], actorAttribution: 'none', evidence: 'authoritative' };
  assert.throws(() => validateWindow({ source: 'hold-proxy', instanceId: 'g', scope, coverage: 'complete', events: [], exact: [] }), /exact/);
});

// ---- changes inside one window, exact counts and key uniqueness -------------------
test('insert then update inside the window never passes the update check', async t => {
  const { db, update, o } = setup(t);
  const from = await o.mark();
  db.prepare('INSERT INTO knowledge VALUES (?, ?, ?, ?)').run('new', 'x', 'draft', nowSec());
  update('new', 'edited');
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(evaluateEffectAssertion(noUpdate('knowledge/new'), [w]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion(noUpdate(null), [w]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion(noUpdate('knowledge/fin'), [w]).verdict, 'pass'); // untouched rows stay exact
});

for (const wal of [true, false]) test(`${wal ? 'WAL' : 'rollback journal'}: update then delete inside the window never passes`, async t => {
  const { db, update, o } = setup(t, { wal });
  const from = await o.mark();
  update('fin', 'tampered');
  db.prepare("DELETE FROM knowledge WHERE id = 'fin'").run();
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(evaluateEffectAssertion(noUpdate('knowledge/fin'), [w]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion(noUpdate(null), [w]).verdict, 'missing');
});

test('a change column never makes an exact count (two updates are not one)', async t => {
  const { update, o } = setup(t);
  const from = await o.mark(); update('fin', 'one'); update('fin', 'two');
  const w = await collectWindow(o, from, await o.mark());
  const count = { kind: 'effect.count', select: { source: 'sql-snapshot', name: 'knowledge', operation: 'update', resource: 'knowledge/fin' }, expected: 1 };
  assert.equal(evaluateEffectAssertion(count, [w]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ ...count, expected: 0 }, [w]).verdict, 'missing');
});

test('a stamp taken before the window but committed inside it, then reverted, stays ambiguous with the commit lag declared', async t => {
  const { path, update, o } = setup(t, { lag: 3000 });
  while (Date.now() % 1000 > 100) await sleep(5);
  const S = nowSec();
  update('fin', 'finance', S);
  const b = new DatabaseSync(path); b.exec('BEGIN IMMEDIATE'); b.prepare('UPDATE knowledge SET description = ?, updated_at = ? WHERE id = ?').run('tampered', S, 'fin');
  await sleep(2600);
  const from = await o.mark();
  b.exec('COMMIT'); b.close(); update('fin', 'finance', S);
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(evaluateEffectAssertion(noUpdate('knowledge/fin'), [w]).verdict, 'missing');
});

test('a key column that is not unique makes the table non-exact', async t => {
  const { db, o } = setup(t, { keyCol: 'owner' });
  db.prepare('INSERT INTO knowledge VALUES (?, ?, ?, ?)').run('fin2', 'finance', 'q3', 1700000000);
  const from = await o.mark();
  db.prepare("UPDATE knowledge SET description = 'tampered', updated_at = ? WHERE id = 'fin'").run(nowSec());
  const w = await collectWindow(o, from, await o.mark());
  // Rows that cannot be matched across the snapshots decide nothing: the window fails, with no events.
  assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'duplicate-key', 0]);
  assert.equal(evaluateEffectAssertion(noUpdate('knowledge/finance'), [w]).verdict, 'observer-failure');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: noUpdate('knowledge/finance').select }, [w]).verdict, 'observer-failure');
});

test('as for pg-snapshot: a watched row absent at either snapshot (a selector typo) is never exact', async t => {
  const { update, o } = setup(t);
  const from = await o.mark();
  update('fin', 'changed in the window', nowSec() - 5);
  const w = await collectWindow(o, from, await o.mark());
  assert.notEqual(evaluateEffectAssertion(noUpdate('knowledge/fni'), [w]).verdict, 'pass', 'the typo names no row seen at both snapshots');
  assert.ok(!w.exact[0].presentResources.includes('knowledge/fni'));
});

// On the change-column observer, prefix and table-wide selectors are never exact.
const prefixNone = value => ({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'knowledge', operation: 'update', resource: { prefix: value } } });
test('change-column: a prefix or table-wide selector never passes over changes it could not see (A/B/C)', async t => {
  const { db, update, o } = setup(t);
  // A: fin really updated; the selector's prefix is a case typo.
  let from = await o.mark(); update('fin', 'tampered'); const a = await collectWindow(o, from, await o.mark());
  assert.notEqual(evaluateEffectAssertion(prefixNone('knowledge/Fin'), [a]).verdict, 'pass', 'A: prefix typo over a real update');
  // B and C: a row inserted, updated and deleted inside one window.
  from = await o.mark();
  db.prepare('INSERT INTO knowledge VALUES (?, ?, ?, ?)').run('tmp', 'x', 'x', nowSec() - 3600); update('tmp', 'y'); db.prepare('DELETE FROM knowledge WHERE id = ?').run('tmp');
  const b = await collectWindow(o, from, await o.mark());
  assert.equal(b.events.length, 0);
  assert.notEqual(evaluateEffectAssertion(noUpdate(null), [b]).verdict, 'pass', 'B: table-wide over a transient row');
  assert.notEqual(evaluateEffectAssertion(prefixNone('knowledge/tmp'), [b]).verdict, 'pass', 'C: prefix over a transient row');
});

// On the SQLite observer: unmatched rows report nothing, a window must move forward, and presentResources is required.
test('sqlite: a non-unique key fails the window with no events, even on a table without a change column', async t => {
  const { db, o } = setup(t, { keyCol: 'owner' });
  db.prepare('INSERT INTO knowledge_file VALUES (?, ?)').run(1, 'fin');
  db.prepare('INSERT INTO knowledge VALUES (?, ?, ?, ?)').run('fin2', 'finance', 'q3', 1700000000);
  const from = await o.mark();
  db.prepare("UPDATE knowledge SET description = 'tampered', updated_at = ? WHERE id = 'fin2'").run(nowSec());
  const w = await collectWindow(o, from, await o.mark());
  assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'duplicate-key', 0]);
  const decisions = decideEffects([{ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'knowledge', operation: 'update' } }], [w]);
  assert.notEqual(decisions[0].verdict, 'pass'); assert.equal(backendObserved(decisions), false);
});

test('sqlite: a zero-length or reversed window fails', async t => {
  const { update, o } = setup(t);
  const a = await o.mark(); update('fin', 'tampered'); const b = await o.mark();
  for (const [from, to] of [[b, b], [b, a]]) assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await collectWindow(o, from, to)), ['failed', 'window-not-forward']);
});

test('a change-column entry without presentResources (the earlier shape) is refused, including on recompute', async t => {
  const { db, o } = setup(t);
  const from = await o.mark();
  db.prepare('INSERT INTO knowledge VALUES (?, ?, ?, ?)').run('tmp', 'x', 'x', nowSec() - 3600);
  db.prepare("UPDATE knowledge SET description = 'y', updated_at = ? WHERE id = 'tmp'").run(nowSec());
  db.prepare("DELETE FROM knowledge WHERE id = 'tmp'").run();
  const w = await collectWindow(o, from, await o.mark());
  for (const select of [noUpdate(null), prefixNone('knowledge/tmp'), noUpdate('knowledge/tmp')]) assert.notEqual(evaluateEffectAssertion(select, [w]).verdict, 'pass');
  const legacy = structuredClone(w); delete legacy.exact[0].presentResources;
  assert.throws(() => validateWindow(legacy), e => e.code === 'exact');
  for (const select of [noUpdate(null), prefixNone('knowledge/tmp'), noUpdate('knowledge/tmp')]) assert.notEqual(evaluateEffectAssertion(select, [legacy]).verdict, 'pass', 'exactFor never treats a missing list as exact');
  // Through recompute: the same sealed trace recomputes with the list, and is refused without it.
  const effects = [noUpdate(null)], meta = new Map([[w.instanceId, { kind: 'sqlite-snapshot-diff', settleMs: 250 }]]), declared = [{ id: w.instanceId.replace(/^sqlite-snapshot-/, ''), type: 'sqlite-snapshot', settleMs: 250 }];
  recomputeEffectTrace(effectTrace(decideEffects(effects, [w]), [w], meta), effects, declared);
  assert.throws(() => recomputeEffectTrace(effectTrace(decideEffects(effects, [legacy]), [legacy], meta), effects, declared), e => e.code === 'exact');
});
