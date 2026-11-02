// SQLite backend observers: what the application's own database recorded.
// Two read-only modes:
//   snapshot    - hash selected tables at each mark and diff (insert/update/delete).
//                 Coverage is "net-only": a write undone between marks is invisible,
//                 and a row's owner column is not who changed it, so snapshot
//                 events carry no actor and cannot support actor-scoped checks.
//   audit-table - read an existing append-only audit table past a cursor id.
//                 The audit row names who acted, so it can.
// The application's database is never opened by SQLite (the one exception is
// the opt-in lockFallback below, for rollback-journal databases only): its
// files are read as bytes and every query runs on a private copy. A WAL
// database is copied too (the database file, then its -wal file; never the
// -shm index). Opening the live file, even read-only, creates -wal/-shm files
// in the application's directory, and the
// wal-index and file locks are not shared across a container's VM file share,
// so a host-side reader of the live file can read a stale snapshot, and its
// wal-index writes can disturb the application's own view. The pair is accepted
// only when the WAL header (checkpoint sequence and salts) and the database
// file (size, mtime, inode) are unchanged from before the first byte copied to
// after the last: no checkpoint restarted the log and none wrote the database
// mid-copy, so the copied log covers every page it could have touched. SQLite
// then recovers the private copy from the copied log, keeping only committed,
// checksummed frames. Otherwise the copy is retried, then the mark fails.
// A rollback-journal database is never opened by SQLite at all, because any
// shared lock (including the online backup API's per-step locks) blocks the
// application's writers. Instead the file is copied byte for byte and the copy
// is accepted only when nothing committed during the copy: no hot journal
// before or after, and the header's file change counter (bytes 24-27, bumped
// by every commit) is the same before, after and in the copy. Otherwise the
// copy is retried, and the mark fails after a few tries ("no-consistent-copy").
// Under a constant commit storm that can fail every mark: the observer never
// disturbs the app by default. lockFallback: true trades that for one short
// shared lock per failed mark, held only while the file is copied. The check relies on
// the journal file: PERSIST mode always looks hot (marks fail, never torn), and
// journal_mode OFF or MEMORY leaves no journal, so only the counter guards those. Rows are reduced to
// keys and hashes; values are never stored. node:sqlite is still flagged
// experimental in Node 24.
//
// Background writers, each opt-in on the snapshot observer, so a profile that declares none reads exactly as before:
//   - platform / ignore (./ignore-lists/ignore-list.mjs): declaring either makes each mark also digest every other table
//     in the copy (SQLite's own sqlite_ tables and virtual tables excepted; a virtual table's content is in its shadow
//     tables, which are read), names compared without case as SQLite does, and a window in which one that is neither
//     declared, a declared queue nor ignored changed, appeared or vanished reads unlisted-table-changed (partial): the
//     effect could have been written there, and a table nobody declared is never ignored. A table over the row limit or
//     with an unreadable name cannot be shown unchanged and counts as changed.
//   - queues (./end-barrier.mjs): each mark is retaken until its queues' pending counts, read from the same private copy
//     as its tables, are zero or drainTimeoutMs passes; an end mark with pending work reads queue-not-drained (partial).
//   - runLease (./run-lease.mjs): a lease file for this database under this machine's temporary directory, held from
//     start() to stop(); start() refuses while another run holds one, and a window either of whose marks saw one reads
//     partial with shared-database (its events stay).
//
// Catalog fingerprint (./catalog.mjs), always on, in both modes: each mark also reads the database's catalog
// fingerprint (sqlite_master, user_version, application_id and the schema cookie) from the same private copy, and
// start() keeps its own as the run's baseline (an observer marked without start() keeps its first mark's). A window whose
// marks' definitions differ from the baseline, or whose cookie moved between its two marks, reads schema-drift; one
// without a readable fingerprint reads catalog-unreadable. Both are partial and keep the events (a dropped audit trigger
// is a schema change too). catalog() returns the record a run keeps (counts and sha256 digests only).
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync, openSync, readSync, closeSync, copyFileSync, statSync, readFileSync } from 'node:fs';
import { createHash, createHmac, randomBytes, hash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { digest } from '../../src/domain.mjs';
import { makeEffect, OPERATIONS } from './events.mjs';
import { resolveIgnoreList } from './ignore-lists/ignore-list.mjs';
import { validateQueues, validateDrain, sqliteQueueCounts, drainWait, pendingOf } from './end-barrier.mjs';
import { RUN_KEY, fileLease } from './run-lease.mjs';
import { catalogExclusions, sqliteCatalogOf, catalogReasons, catalogRecord, SCHEMA_DRIFT } from './catalog.mjs';

const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const quote = name => { if (!IDENT.test(name)) throw new Error(`Unsupported SQL identifier "${String(name).slice(0, 64)}".`); return `"${name}"`; };
// rowsPerTable: the most rows one table may hold for a mark to read it (L8 fix 1: was 200000). sortedRows: up to this many
// rows, an unlisted table's content hash is order-free (its sorted row digests); past it, a scan-order hash (scanDigest).
export const SQLITE_LIMITS = Object.freeze({ rowsPerTable: 2000000, sortedRows: 200000, tables: 32, auditRowsPerWindow: 5000 });

// Database header fields read straight from the file, without SQLite locks.
function header(path) {
  const fd = openSync(path, 'r'), buf = Buffer.alloc(100);
  try { if (readSync(fd, buf, 0, 100, 0) < 100 || buf.toString('latin1', 0, 15) !== 'SQLite format 3') throw new Error('not-sqlite'); } finally { closeSync(fd); }
  return { wal: buf[18] === 2, counter: buf.readUInt32BE(24) };
}
// A rollback journal with content means a write transaction is committing or must be rolled back.
// One stat, not exists-then-stat: the journal can vanish in between when a commit ends.
const hotJournal = path => { try { return statSync(`${path}-journal`).size > 0; } catch (error) { if (error.code === 'ENOENT') return false; throw error; } };
export const COPY_ATTEMPTS = 5;
// WAL header bytes 12-23: checkpoint sequence and both salts; every log restart changes them.
function walState(path) {
  let fd;
  try { fd = openSync(`${path}-wal`, 'r'); } catch (error) { if (error.code === 'ENOENT') return 'none'; throw error; }
  try { const buf = Buffer.alloc(32); return readSync(fd, buf, 0, 32, 0) < 32 ? 'empty' : buf.toString('hex', 12, 24); } finally { closeSync(fd); }
}
const fileState = path => { const st = statSync(path, { bigint: true }); return `${st.ino}:${st.size}:${st.mtimeNs}`; };
async function copyWal(path, dir, run) {
  const copy = join(dir, 'snapshot.db');
  for (let attempt = 0; attempt < COPY_ATTEMPTS; attempt++) {
    if (attempt) await new Promise(resolve => setTimeout(resolve, 20 * attempt));
    rmSync(`${copy}-wal`, { force: true }); rmSync(`${copy}-shm`, { force: true });
    const wal = walState(path), file = fileState(path), counter = header(path).counter;
    copyFileSync(path, copy);
    if (wal !== 'none') try { copyFileSync(`${path}-wal`, `${copy}-wal`); } catch (error) { if (error.code !== 'ENOENT') throw error; continue; }
    if (walState(path) !== wal || fileState(path) !== file || header(path).counter !== counter || !header(copy).wal) continue;
    // A private copy: SQLite may build its own index and checkpoint it; the application's files are untouched.
    const db = new DatabaseSync(copy);
    try { return run(db); } finally { db.close(); }
  }
  throw new Error('no-consistent-copy');
}
async function readConsistent(path, run, { lockFallback = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sqlite-')), copy = join(dir, 'snapshot.db');
  try {
    if (header(path).wal) return await copyWal(path, dir, run);
    for (let attempt = 0; attempt < COPY_ATTEMPTS; attempt++) {
      if (attempt) await new Promise(resolve => setTimeout(resolve, 20 * attempt));
      // Read the counter first, then require no hot journal: any commit that can touch the
      // copy then either leaves a hot journal at the end or a changed counter.
      const before = header(path).counter;
      if (hotJournal(path)) continue;
      copyFileSync(path, copy);
      if (hotJournal(path) || header(path).counter !== before || header(copy).counter !== before || header(copy).wal) continue;
      const db = new DatabaseSync(copy, { readOnly: true });
      try { return run(db); } finally { db.close(); }
    }
    // Never on WAL: opening a WAL database creates and writes its -shm index.
    if (!lockFallback || header(path).wal) throw new Error('no-consistent-copy');
    // Opt-in: hold a shared lock only while the file is copied, so no commit can land mid-copy.
    // Wait briefly for an in-progress commit rather than failing; the app's writers are what must not wait.
    const lock = new DatabaseSync(path, { readOnly: true, timeout: 2000 });
    try {
      lock.exec('BEGIN'); lock.prepare('SELECT count(*) FROM sqlite_master').get();
      try { copyFileSync(path, copy); } finally { lock.exec('COMMIT'); }
    } finally { lock.close(); }
    const db = new DatabaseSync(copy, { readOnly: true });
    try { return run(db); } finally { db.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
// Principal values are kept only when they are a declared actor principal;
// anything else (an email, a name) is replaced by a digest keyed with a secret the observer
// never stores, because an unkeyed hash of a guessable value is confirmed by hashing guesses
// (the same rule as src/app-log-rules.mjs).
const principalOf = (value, principals, key) => value === null || value === undefined ? null : principals.includes(String(value)) ? String(value) : `unlisted:${createHmac('sha256', key).update(String(value)).digest('hex').slice(0, 16)}`;
// Declared tables and the audit table are read with big integers on (L8 fix 3), so an INTEGER past 2^53 (a nanosecond
// timestamp) reads exactly instead of failing the whole mark. exactRow keeps an integer inside the safe range a number, so
// every row digest a readable table had before is unchanged, and tags one past it ({ integer: digits }), so it never digests
// like TEXT holding the same digits (a TEXT-to-INTEGER rewrite still reads as an update).
const SAFE_INT = BigInt(Number.MAX_SAFE_INTEGER);
const exactInt = v => typeof v !== 'bigint' ? v : v >= -SAFE_INT && v <= SAFE_INT ? Number(v) : { integer: String(v) };
const exactRow = row => Object.fromEntries(Object.entries(row).map(([k, v]) => [k, exactInt(v)]));
// rowDigest(exactRow(row)) in one pass, for the declared-table read of up to rowsPerTable rows a mark: the same entries, and
// JSON.stringify writes an array of [name, scalar or { integer }] pairs exactly as stable() does, so the digest is identical.
const declaredRowDigest = row => {
  const entries = [];
  for (const k in row) { const v = exactInt(row[k]); entries.push([k, v instanceof Uint8Array ? hash('sha256', Buffer.from(v).toString('hex')) : v]); }
  return hash('sha256', JSON.stringify(entries));
};
const rowDigest = row => digest(Object.entries(row).map(([k, v]) => [k, typeof v === 'bigint' ? String(v) : v instanceof Uint8Array ? digest(Buffer.from(v).toString('hex')) : v]));
// An unlisted table past sortedRows rows: one sha256 over its row digests in the order a full scan returns them (rowid order,
// or primary-key order WITHOUT ROWID), so a table of any size up to rowsPerTable is read in one pass. The same rows in another
// order (a VACUUM that renumbers rowids, a row deleted and inserted back) read as changed, never as unchanged; the prefix keeps it
// apart from an order-free digest, so a table that crosses sortedRows between marks reads as changed too.
const scanDigest = digests => { const h = createHash('sha256').update('scan-order/1\n'); for (const d of digests) h.update(d); return h; };
// A declared table's state at a mark, compact so a table of millions of rows fits and a run of many marks does not hold a copy
// per mark (L8 fix 1b, after a bench measured a 4,947 MiB peak): its rows in key order, in sealed chunks of CHUNK_ROWS, each holding
// one 32-byte row digest per row and the keys as UTF-8 bytes, outside the JS heap; the change column's raw values when declared.
// A chunk byte-identical to the same chunk of the table's previous read is that chunk, shared, so N marks cost one state plus
// the chunks a write changed. (Its change values need no comparison: the row digest covers every column.) Sealed chunks never
// change. The rows are streamed (iterate), in the key's index order where it has one, never held as objects.
const HASH_BYTES = 32, CHUNK_ROWS = 4096, CHUNK_SHIFT = 12;
const sameEnds = (a, b, rows) => { for (let i = 0; i < rows; i++) if (a[i] !== b[i]) return false; return true; };
function readDeclared(db, t, rowsPerTable, previous) {
  // key "rowid": the table's rowid, for a table whose primary key spans columns (or has none). A table with its own column
  // named rowid keys on that column as on any other; a WITHOUT ROWID table has no rowid and its mark fails (read-failed).
  // A VACUUM can renumber the rowids of a table without an INTEGER PRIMARY KEY: its rows then read as deleted and inserted.
  const byRowid = t.key === 'rowid' && !db.prepare("SELECT 1 FROM pragma_table_info(?) WHERE lower(name) = 'rowid'").get(t.table);
  const stmt = db.prepare(`SELECT ${byRowid ? 'rowid AS "rowid", ' : ''}* FROM ${quote(t.table)} ORDER BY ${quote(t.key)} LIMIT ${rowsPerTable + 1}`);
  stmt.setReadBigInts(true);
  const chunks = [], hashes = Buffer.alloc(HASH_BYTES * CHUNK_ROWS), ends = new Uint32Array(CHUNK_ROWS);
  let keyBytes = Buffer.alloc(64 * 1024), keyLength = 0, rows = 0, count = 0, changes = t.changeColumn ? [] : null;
  const seal = () => {
    const had = previous?.chunks[chunks.length];
    if (had && had.rows === rows && had.keys.length === keyLength && had.hashes.compare(hashes, 0, rows * HASH_BYTES) === 0 && had.keys.compare(keyBytes, 0, keyLength) === 0 && sameEnds(had.ends, ends, rows)) chunks.push(had);
    else chunks.push(Object.freeze({ rows, hashes: Buffer.from(hashes.subarray(0, rows * HASH_BYTES)), keys: Buffer.from(keyBytes.subarray(0, keyLength)), ends: ends.slice(0, rows), changes }));
    rows = 0; keyLength = 0; changes = t.changeColumn ? [] : null;
  };
  for (const row of stmt.iterate()) {
    if (count === rowsPerTable) throw new Error('row-limit');
    // The key's digits as stored (a bigint's String is exact); the change column raw (seconds() in collect reads it).
    hashes.write(declaredRowDigest(row), rows * HASH_BYTES, 'hex');
    const key = String(row[t.key]), needed = keyLength + Buffer.byteLength(key);
    if (needed > keyBytes.length) { const grown = Buffer.alloc(Math.max(needed, keyBytes.length * 2)); keyBytes.copy(grown, 0, 0, keyLength); keyBytes = grown; }
    keyLength += keyBytes.write(key, keyLength);
    ends[rows] = keyLength;
    if (changes) changes.push(row[t.changeColumn.column]);
    rows++; count++;
    if (rows === CHUNK_ROWS) seal();
  }
  if (rows) seal();
  // Unchanged since the previous read: its answer stands, and no index is built.
  const unchanged = previous && previous.count === count && chunks.every((c, n) => c === previous.chunks[n]);
  return { count, chunks, duplicateKeys: unchanged ? previous.duplicateKeys : buildIndex({ count, chunks }).duplicate };
}
const keyStart = (c, k) => k === 0 ? 0 : c.ends[k - 1];
const keyAt = (state, i) => { const c = state.chunks[i >>> CHUNK_SHIFT], k = i & (CHUNK_ROWS - 1); return c.keys.toString('utf8', keyStart(c, k), c.ends[k]); };
const hashAt = (state, i) => { const c = state.chunks[i >>> CHUNK_SHIFT], k = i & (CHUNK_ROWS - 1); return c.hashes.toString('hex', k * HASH_BYTES, (k + 1) * HASH_BYTES); };
const changeAt = (state, i) => state.chunks[i >>> CHUNK_SHIFT].changes[i & (CHUNK_ROWS - 1)];
const sameDigest = (a, i, b, j) => {
  const ca = a.chunks[i >>> CHUNK_SHIFT], cb = b.chunks[j >>> CHUNK_SHIFT], ka = i & (CHUNK_ROWS - 1), kb = j & (CHUNK_ROWS - 1);
  return (ca === cb && ka === kb) || ca.hashes.compare(cb.hashes, kb * HASH_BYTES, (kb + 1) * HASH_BYTES, ka * HASH_BYTES, (ka + 1) * HASH_BYTES) === 0;
};
const sameKey = (a, i, b, j) => {
  const ca = a.chunks[i >>> CHUNK_SHIFT], cb = b.chunks[j >>> CHUNK_SHIFT], ka = i & (CHUNK_ROWS - 1), kb = j & (CHUNK_ROWS - 1);
  return (ca === cb && ka === kb) || ca.keys.compare(cb.keys, keyStart(cb, kb), cb.ends[kb], keyStart(ca, ka), ca.ends[ka]) === 0;
};
// Row index by key: an open-addressing table of row numbers in one typed array, built for one read or collect and dropped after
// it. The hash is seeded per process, so an application's keys cannot be chosen to collide; a match always compares the key's bytes.
const KEY_SEED = randomBytes(4).readUInt32LE(0);
const keyHash = (bytes, start, end) => {
  let h = KEY_SEED;
  for (let p = start; p < end; p++) h = Math.imul(h ^ bytes[p], 16777619);
  return (h ^ (h >>> 15)) >>> 0;
};
function buildIndex(state) {
  let size = 8;
  while (size < state.count * 2) size *= 2;
  const slots = new Int32Array(size), mask = size - 1;
  let duplicate = false;
  for (let i = 0; i < state.count; i++) {
    const c = state.chunks[i >>> CHUNK_SHIFT], k = i & (CHUNK_ROWS - 1);
    let p = keyHash(c.keys, keyStart(c, k), c.ends[k]) & mask;
    while (slots[p] !== 0) { if (sameKey(state, slots[p] - 1, state, i)) duplicate = true; p = (p + 1) & mask; }
    slots[p] = i + 1;
  }
  return { slots, mask, duplicate, state };
}
// The row of `bytes[start, end)` in an index's state, or -1.
const findKey = (index, bytes, start, end) => {
  const length = end - start;
  let p = keyHash(bytes, start, end) & index.mask;
  while (index.slots[p] !== 0) {
    const i = index.slots[p] - 1, c = index.state.chunks[i >>> CHUNK_SHIFT], k = i & (CHUNK_ROWS - 1), from = keyStart(c, k);
    if (c.ends[k] - from === length && c.keys.compare(bytes, start, end, from, c.ends[k]) === 0) return i;
    p = (p + 1) & index.mask;
  }
  return -1;
};
// Which row of a each row of b is (iOf, -1 for a row new in b), and the reverse (jOf). Both states have unique keys here. Rows
// usually line up, so the next row is tried first and the index is built only at the first row that does not.
function alignRows(a, b) {
  const iOf = new Int32Array(b.count), jOf = new Int32Array(a.count).fill(-1);
  let index = null, next = 0;
  for (let j = 0; j < b.count; j++) {
    let i;
    if (next < a.count && sameKey(a, next, b, j)) i = next;
    else {
      index ??= buildIndex(a);
      const c = b.chunks[j >>> CHUNK_SHIFT], k = j & (CHUNK_ROWS - 1);
      i = findKey(index, c.keys, keyStart(c, k), c.ends[k]);
    }
    iOf[j] = i;
    if (i >= 0) { jOf[i] = j; next = i + 1; }
  }
  return { iOf, jOf };
}

// tables: [{ table, key, resourcePrefix?, changeColumn? }]
// changeColumn: { column, unit: 'seconds', audit } - an operator assertion,
//   backed by a recorded source audit (audit: the path of that file; its
//   sha256 is recorded in every window), that every committed UPDATE of a row
//   in this table sets this column to the current time in whole seconds
//   (for example int(time.time())). A changed column proves at least one
//   committed update of that row, so a row whose column is unchanged between
//   the two snapshots had none: effect.none / effect.exists on updates of
//   existing rows of that table can be exact. Never effect.count. Inserts,
//   deletes and other tables stay net-only, and any row present in only one
//   snapshot (inserted or deleted in the window) makes the table's update
//   check ambiguous for that row. Absence is claimed only about rows named in
//   watchedResources and seen at both snapshots: a prefix or table-wide
//   selector is never exact (a row added and removed in the window is not seen).
// changeColumnSkewMs: the measured container-to-host clock skew bound (> 0).
// maxCommitLagMs: the longest the app can take from computing the stamp to
//   committing it (for example its database busy timeout). A row whose column
//   at the start snapshot is at or after floor((start - 1 s - skew - lag) / 1 s)
//   is ambiguous: a write stamped earlier but committed in the window, then
//   reverted in the same second, would leave the column unchanged.
// A table whose key column is not unique in a snapshot fails the window ('duplicate-key'):
// its rows cannot be matched, so no change is reported. A violated change-column table
// (content changed without the column) reports none of its changes.
// platform, ignore, queues (with drainTimeoutMs, pollMs) and runLease: the background-writer options above (runKey and
// leaseRoot are test seams, never from a configuration). rowLimits: a test seam too ({ rowsPerTable, sortedRows }, each at most
// SQLITE_LIMITS'), so a test reaches both bounds without millions of rows; the factory never passes it.
export function createSqliteSnapshotObserver({ instanceId = 'sqlite-snapshot-1', path, tables, lockFallback = false, changeColumnSkewMs, maxCommitLagMs, watchedResources = [],
  platform, ignore, queues: queueDecl, drainTimeoutMs, pollMs, runLease = false, runKey = RUN_KEY, leaseRoot, rowLimits = SQLITE_LIMITS }) {
  const { rowsPerTable, sortedRows } = rowLimits;
  if (!Number.isInteger(rowsPerTable) || rowsPerTable < 1 || rowsPerTable > SQLITE_LIMITS.rowsPerTable || !Number.isInteger(sortedRows) || sortedRows < 1 || sortedRows > Math.min(rowsPerTable, SQLITE_LIMITS.sortedRows)) throw new Error('rowLimits: rowsPerTable and sortedRows are integers within SQLITE_LIMITS, sortedRows at most rowsPerTable.');
  if (!Array.isArray(tables) || !tables.length || tables.length > SQLITE_LIMITS.tables) throw new Error('Declare 1 to 32 tables to observe.');
  for (const t of tables) { quote(t.table); quote(t.key); if (Object.hasOwn(t, 'actorColumn')) throw new Error('Snapshot observers cannot attribute a change to an actor; use an audit-table observer.'); }
  const audits = new Map();
  for (const t of tables) if (t.changeColumn !== undefined) {
    quote(t.changeColumn?.column ?? '');
    if (t.changeColumn.unit !== 'seconds') throw new Error('A changeColumn needs unit: "seconds" (whole-second timestamps).');
    let auditBytes;
    try { auditBytes = readFileSync(t.changeColumn.audit); } catch { throw new Error('A changeColumn needs "audit": the path of its recorded source audit file.'); }
    audits.set(t.table, { ref: String(t.changeColumn.audit).split('/').slice(-3).join('/'), sha256: createHash('sha256').update(auditBytes).digest('hex') });
    if (!Number.isFinite(changeColumnSkewMs) || changeColumnSkewMs <= 0 || changeColumnSkewMs > 60000) throw new Error('A changeColumn needs "changeColumnSkewMs": the measured container-to-host clock skew bound (1 to 60000 ms).');
    if (!Number.isFinite(maxCommitLagMs) || maxCommitLagMs < 0 || maxCommitLagMs > 600000) throw new Error('A changeColumn needs "maxCommitLagMs": the longest stamp-to-commit delay (for example the database busy timeout), 0 to 600000 ms.');
  }
  const queues = validateQueues(queueDecl, { engine: 'sqlite' }), drain = validateDrain({ drainTimeoutMs, pollMs });
  if (typeof runLease !== 'boolean') throw new Error('runLease is true or false.');
  const watchOthers = platform !== undefined || ignore !== undefined;
  const ignoreList = resolveIgnoreList({ engine: 'sqlite', platform: platform ?? 'none', ignore: ignore ?? [], declared: tables.map(t => ({ schema: 'main', table: t.table })), queues });
  const lease = runLease ? fileLease(path, { runKey, ...(leaseRoot ? { root: leaseRoot } : {}) }) : null;
  // The catalog fingerprint leaves out the platform's own tables only (never a declared table or queue).
  const catalogExcluded = catalogExclusions(ignoreList, { declared: tables.map(t => ({ schema: 'main', table: t.table })), queues, engine: 'sqlite' });
  const observer = { kind: 'sqlite-snapshot-diff', instanceId };
  const snapshots = [];
  // baseline: start()'s catalog fingerprint; latest: the last readable mark's; drifted: a mark or window differed from it.
  let seq = 0, baseline = null, latest = null, drifted = false;
  // Every other table's content hash, by name (declared tables and queues are read on their own; SQLite's sqlite_ tables
  // and ignored tables are not read). A table that cannot be shown unchanged reads unreadable.
  // SQLite folds ASCII letters only (a Kelvin sign is not a k), so names are folded the same way.
  const fold = n => n.replace(/[A-Z]/g, c => c.toLowerCase());
  const accounted = new Set([...tables.map(t => t.table), ...queues.map(q => q.table)].map(fold));
  const othersOf = db => {
    const out = new Map();
    for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' AND (sql IS NULL OR sql NOT LIKE 'CREATE VIRTUAL TABLE%') ORDER BY name").all()) {
      if (typeof name !== 'string' || !/^[^\u0000-\u001f\u007f]{1,1024}$/.test(name)) { out.set(String(name).slice(0, 128), { unreadable: 'name-refused' }); continue; }
      if (accounted.has(fold(name)) || (IDENT.test(name) && ignoreList.ignores('main', name))) continue;
      const read = db.prepare(`SELECT * FROM "${name.replace(/"/g, '""')}" LIMIT ${rowsPerTable + 1}`);
      read.setReadBigInts(true); // an integer past 2^53 reads exactly instead of throwing
      // Streamed: the first sortedRows row digests are kept for the order-free digest; past them, a scan-order hash.
      const kept = []; let scan = null, count = 0;
      for (const row of read.iterate()) {
        if (++count > rowsPerTable) break;
        const d = rowDigest(row);
        if (scan) scan.update(d); else if (kept.push(d) > sortedRows) { scan = scanDigest(kept); kept.length = 0; }
      }
      out.set(name, count > rowsPerTable ? { unreadable: 'row-limit' } : scan ? { digest: `scan:${scan.digest('hex')}` } : { digest: digest(kept.sort()) });
    }
    return out;
  };
  // The last state read of each table: what a new read shares its unchanged chunks with.
  const previousStates = Object.create(null);
  const read = () => readConsistent(path, db => ({
    tables: Object.fromEntries(tables.map(t => [t.table, previousStates[t.table] = readDeclared(db, t, rowsPerTable, previousStates[t.table])])),
    ...(watchOthers ? { others: othersOf(db) } : {}),
    ...(queues.length ? { pending: sqliteQueueCounts(db, queues) } : {}),
    catalog: sqliteCatalogOf(db, catalogExcluded),
  }), { lockFallback });
  // A mark: without queues one read; with them, the read is retaken until its own pending counts are zero or the wait ends.
  const take = async () => {
    if (!queues.length) return read();
    const last = await drainWait(async () => { const r = await read(); return { clean: r.pending.every(n => n === 0), r }; }, drain);
    return { ...last.r, queues: { clean: last.clean, waitedMs: last.waitedMs, pending: pendingOf(queues, last.r.pending) } };
  };
  return {
    kind: observer.kind, instanceId, source: 'sql-snapshot',
    scope: Object.freeze({ operations: ['insert', 'update', 'delete'], names: tables.map(t => t.table), actorAttribution: 'none', evidence: 'authoritative' }),
    async start() {
      if (lease) {
        lease.acquire();
        if (lease.others() > 0) { lease.release(); throw new Error('shared-database: another ScopeHaven run holds a lease on this database; runs that reseed one database never share it.'); }
      }
      try { baseline = (await read()).catalog; } catch (error) { lease?.release(); throw error; }
    },
    async mark() {
      try { const atMs = Date.now(), m = await take(); snapshots.push({ ok: true, atMs, at: new Date(atMs).toISOString(), ...m, otherRuns: lease ? lease.others() : 0 }); }
      catch (error) { snapshots.push({ ok: false, at: new Date().toISOString(), reason: ['row-limit', 'no-consistent-copy'].includes(error.message) ? error.message : 'read-failed' }); }
      const taken = snapshots.at(-1);
      if (taken.ok) baseline ??= taken.catalog;
      if (taken.ok && taken.catalog.ok) { latest = taken.catalog; drifted ||= Boolean(baseline?.ok) && taken.catalog.sha256 !== baseline.sha256; }
      return { index: snapshots.length - 1 };
    },
    async collect(from, to) {
      const before = snapshots[from.index], after = snapshots[to.index];
      if (!before?.ok || !after?.ok) return { events: [], coverage: 'failed', reason: (!before?.ok ? before : after)?.reason || 'missing-snapshot' };
      if (!(to.index > from.index)) return { events: [], coverage: 'failed', reason: 'window-not-forward' };
      // Rows whose key is not unique cannot be matched across the snapshots: they decide nothing.
      if (tables.some(t => before.tables[t.table].duplicateKeys || after.tables[t.table].duplicateKeys)) return { events: [], coverage: 'failed', reason: 'duplicate-key' };
      const events = [], exact = [];
      for (const t of tables) {
        const a = before.tables[t.table], b = after.tables[t.table], resourceOf = key => `${t.resourcePrefix ?? t.table}/${key}`;
        const { iOf, jOf } = alignRows(a, b);
        const found = [];
        const emit = (operation, key, hash) => found.push(makeEffect({ source: 'sql-snapshot', observer, seq: ++seq, observedAt: after.at, actor: null,
          operation, name: t.table, resource: resourceOf(key), outcome: 'committed', content: hash }));
        for (let j = 0; j < b.count; j++) { const i = iOf[j]; if (i < 0) emit('insert', keyAt(b, j), hashAt(b, j)); else if (!sameDigest(a, i, b, j)) emit('update', keyAt(b, j), hashAt(b, j)); }
        for (let i = 0; i < a.count; i++) if (jOf[i] < 0) emit('delete', keyAt(a, i), hashAt(a, i));
        if (!t.changeColumn) { events.push(...found); continue; }
        // Compare snapshot to snapshot, never to the observer's clock, except for the same-second guard.
        const guardSec = Math.floor((before.atMs - 1000 - changeColumnSkewMs - maxCommitLagMs) / 1000);
        const ambiguous = new Set(), seconds = v => typeof v === 'bigint' ? Number(v) : v;
        let violated = false;
        for (let i = 0; i < a.count; i++) {
          const v = seconds(changeAt(a, i));
          // A stamp past 2^53 is no whole-second clock reading, and its Number is rounded: ambiguous.
          if (!Number.isSafeInteger(v) || v >= guardSec) ambiguous.add(resourceOf(keyAt(a, i)));
          const j = jOf[i];
          if (j < 0) { ambiguous.add(resourceOf(keyAt(a, i))); continue; } // deleted in the window: an update before the delete is invisible
          // Content changed but the column did not: the assertion does not hold here.
          if (!sameDigest(a, i, b, j) && seconds(changeAt(b, j)) === v) violated = true;
        }
        // Inserted in the window: an update after the insert is invisible.
        for (let j = 0; j < b.count; j++) if (iOf[j] < 0) ambiguous.add(resourceOf(keyAt(b, j)));
        // Absence is claimed only about selected rows seen at both snapshots.
        const present = [];
        let indexA = null;
        for (const resource of new Set(watchedResources)) {
          const prefix = `${t.resourcePrefix ?? t.table}/`;
          if (!resource.startsWith(prefix)) continue;
          const key = Buffer.from(resource.slice(prefix.length));
          indexA ??= buildIndex(a);
          const i = findKey(indexA, key, 0, key.length);
          if (i >= 0 && jOf[i] >= 0) present.push(resource); // a selected row missing at either mark is simply not exact
        }
        const audit = audits.get(t.table), list = [...ambiguous];
        violated ||= list.length > 10000 || present.length > 1000;
        // A violated table's changes are never reported: its rows decide no check.
        if (!violated) events.push(...found);
        exact.push({ name: t.table, auditSha256: audit.sha256, ambiguousResources: list.slice(0, 10000), presentResources: present.slice(0, 1000), violated,
          basis: `change-column ${t.changeColumn.column} (operator-asserted, source-checked: ${audit.ref} sha256 ${audit.sha256.slice(0, 12)}; skew ${changeColumnSkewMs} ms, commit lag ${maxCommitLagMs} ms, ${list.length} ambiguous row${list.length === 1 ? '' : 's'})`.slice(0, 512) });
      }
      // Other tables (watchOthers): any that changed, appeared, vanished or cannot be shown unchanged; and the end barrier.
      const changed = watchOthers ? [...new Set([...before.others.keys(), ...after.others.keys()])].filter(name => {
        const x = before.others.get(name), y = after.others.get(name);
        return !x || !y || x.unreadable || y.unreadable || x.digest !== y.digest;
      }).sort() : [];
      // And another run on this database at either mark (the run lease): no absence passes, and the events stay. And the
      // catalog against the run's baseline, and between the window's own marks (./catalog.mjs).
      const reasons = [...(changed.length ? ['unlisted-table-changed'] : []), ...(after.queues && !after.queues.clean ? ['queue-not-drained'] : []),
        ...(before.otherRuns > 0 || after.otherRuns > 0 ? ['shared-database'] : []), ...catalogReasons(baseline, before.catalog, after.catalog)].sort();
      drifted ||= reasons.includes(SCHEMA_DRIFT);
      const background = watchOthers || queues.length || lease ? { background: { ...(watchOthers ? { ignore: ignoreList.record, unlisted: changed.slice(0, 32), unlistedOmitted: Math.max(0, changed.length - 32) } : {}),
        ...(queues.length ? { queues: { start: before.queues, end: after.queues } } : {}) } } : {};
      if (reasons.length) return { events, coverage: 'partial', reason: reasons.join(','), ...background };
      return { events, coverage: 'net-only', reason: 'net-change-between-snapshots', ...(exact.length ? { exact } : {}), ...background };
    },
    // The catalog record a run keeps for this observer (./catalog.mjs catalogRecord).
    catalog() { return catalogRecord({ engine: 'sqlite', baseline, latest, drifted, excluded: catalogExcluded }); },
    async stop() { lease?.release(); },
  };
}

// audit: { table, idColumn, actorColumn, actionColumn, resourceColumn?, actions: { <action value>: operation }, deniedActions?: [..] }
// Unmapped actions are reported as "update".
export function createSqliteAuditObserver({ instanceId = 'sqlite-audit-1', path, audit, principals = [], maxRowsPerWindow = SQLITE_LIMITS.auditRowsPerWindow }) {
  for (const key of ['table', 'idColumn', 'actorColumn', 'actionColumn']) quote(audit[key]);
  if (audit.resourceColumn) quote(audit.resourceColumn);
  const mapped = Object.values(audit.actions || {});
  if (!mapped.every(op => OPERATIONS.includes(op))) throw new Error('Audit actions must map to supported operations.');
  const observer = { kind: 'sqlite-audit-table', instanceId };
  // The row's digest is keyed too: its other fields are in the event, so an unkeyed one would confirm a guessed actor.
  const key = randomBytes(32), keyed = value => createHmac('sha256', key).update(digest(value)).digest('hex');
  // The cursor and the catalog fingerprint, from one private copy. Each mark's fingerprint is kept here, by the index its
  // mark names (catalogAt); baseline, latest and drifted as the snapshot observer keeps them.
  // Read without big integers on purpose: an id past 2^53 throws, so that mark fails (read-failed), never a rounded cursor.
  const maxId = () => readConsistent(path, db => ({ id: Number(db.prepare(`SELECT COALESCE(MAX(${quote(audit.idColumn)}), 0) AS id FROM ${quote(audit.table)}`).get().id), catalog: sqliteCatalogOf(db) }));
  const catalogs = [];
  let baseline = null, latest = null, drifted = false;
  return {
    kind: observer.kind, instanceId, source: 'sql-audit-table',
    // The declared actions are its name vocabulary: it vouches only for actions it logs.
    scope: Object.freeze({ operations: [...new Set([...mapped, 'update'])], names: [...new Set([...Object.keys(audit.actions || {}), ...(audit.deniedActions || [])])], actorAttribution: 'principal', evidence: 'authoritative' }),
    async start() { baseline = (await maxId()).catalog; },
    async mark() {
      try {
        const { id, catalog } = await maxId();
        baseline ??= catalog;
        if (catalog.ok) { latest = catalog; drifted ||= Boolean(baseline.ok) && catalog.sha256 !== baseline.sha256; }
        return { ok: true, id, catalogAt: catalogs.push(catalog) - 1 };
      } catch { return { ok: false }; }
    },
    async collect(from, to) {
      if (!from.ok || !to.ok) return { events: [], coverage: 'failed', reason: 'read-failed' };
      // The audit store was reset or replaced during the window (ids restarted): nothing in it can be judged.
      if (to.id < from.id) return { events: [], coverage: 'failed', reason: 'audit-id-went-backward' };
      const columns = [audit.idColumn, audit.actorColumn, audit.actionColumn, ...(audit.resourceColumn ? [audit.resourceColumn] : [])].map(quote).join(', ');
      // Big integers on: an actor, action or resource past 2^53 keeps its exact digits (String of a bigint).
      const rows = await readConsistent(path, db => {
        const stmt = db.prepare(`SELECT ${columns} FROM ${quote(audit.table)} WHERE ${quote(audit.idColumn)} > ? AND ${quote(audit.idColumn)} <= ? ORDER BY ${quote(audit.idColumn)} LIMIT ${maxRowsPerWindow + 1}`);
        stmt.setReadBigInts(true);
        return stmt.all(from.id, to.id);
      });
      const truncated = rows.length > maxRowsPerWindow;
      const events = rows.slice(0, maxRowsPerWindow).map(row => {
        const action = String(row[audit.actionColumn]);
        const denied = (audit.deniedActions || []).includes(action);
        return makeEffect({ source: 'sql-audit-table', observer, seq: Number(row[audit.idColumn]), actor: principalOf(row[audit.actorColumn], principals, key),
          operation: audit.actions?.[action] ?? 'update', name: action.slice(0, 128), resource: audit.resourceColumn && row[audit.resourceColumn] !== null ? String(row[audit.resourceColumn]).slice(0, 200) : null,
          outcome: denied ? 'denied' : 'committed', content: keyed(exactRow(row)) });
      });
      const reasons = [...(truncated ? ['audit-row-limit'] : []), ...catalogReasons(baseline, catalogs[from.catalogAt], catalogs[to.catalogAt])].sort();
      drifted ||= reasons.includes(SCHEMA_DRIFT);
      return { events, coverage: reasons.length ? 'partial' : 'complete', reason: reasons.length ? reasons.join(',') : null };
    },
    catalog() { return catalogRecord({ engine: 'sqlite', baseline, latest, drifted, excluded: { schemas: [], tables: [] } }); },
    async stop() {},
  };
}
