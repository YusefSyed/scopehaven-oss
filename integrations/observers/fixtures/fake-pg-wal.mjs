// pg-wal's scripted session (moved unchanged from ../pg-wal.test.mjs, so a connector-level test can drive a pg-wal
// profile too): no server, no socket. The fake answers the observer's tagged statements (/* sh:... */) from a model of the WAL, the
// slot and the catalog. connect is the observer's connect seam.
import { PgError } from '../pg-wire.mjs';
import { lsnValue } from '../pg-wal.mjs';
import { catalogAnswer } from './fake-postgres.mjs';

export const lsnText = v => `${(v >> 32n).toString(16).toUpperCase()}/${(v & 0xffffffffn).toString(16).toUpperCase()}`;
export const ORDERS = [[1, 'id[text]', 'id'], [2, 'status[text]', 'status'], [3, 'amount[numeric]', 'amount'], [4, 'email[text]', 'email'], [5, 'note[text]', 'note']];
export const relation = { qualified: 'public.orders', columns: ORDERS.map(([, label, name]) => ({ label, name })) };
export const row = (op, values) => `table public.orders: ${op}:${values}`;

// A scripted server. Each table spec is a catalog row; wal holds committed transactions { end, xid, lines: [[kind, data]] }.
export function fakeServer({ walLevel = 'logical', version = '170000', recovery = 'false' } = {}) {
  const s = { lsn: 0x1000000n, flush: null, writers: 0, walStatus: 'reserved', overshoot: false, wal: [], slots: new Map(), log: [], fail: [], drift: 0, driftDuringMark: false, xid: 700, closed: 0,
    relations: [{ i: 0, oid: '16400', xmin: '100', qualified: 'public.orders', relkind: 'r', persistence: 'p', replident: 'd', root: 'true', columns: ORDERS, key: [1, true, false, 'pg_catalog.textout'], covered: 'true' }] };
  const catalogRows = () => s.relations.map(r => [String(r.i), r.oid, String(Number(r.xmin) + s.drift), r.qualified, r.relkind, r.am ?? 'heap', r.persistence, r.replident, 'false', 'false', r.root,
    JSON.stringify(r.columns.map(([n, label, name]) => [n, label, name, '', '100'])), JSON.stringify(r.key), r.covered, '[]', '[]', JSON.stringify(r.indexes ?? []), '[]', '2200', String(100 + s.drift)]);
  // Commits one transaction of change lines; returns its commit end.
  s.commit = (lines, { xid = ++s.xid } = {}) => { s.lsn += 0x100n; s.wal.push({ end: s.lsn, xid: String(xid), lines }); return s.lsn; };
  // A logical message decoded outside BEGIN and COMMIT: a non-transactional one (xid 0, or its writer's xid before that
  // transaction's BEGIN), and on PostgreSQL 15 a transaction holding only a message.
  s.message = (xid = '0') => s.loose('message', null, xid);
  s.loose = (kind, data, xid = '0') => { s.lsn += 0x40n; s.wal.push({ end: s.lsn, xid, loose: [kind, data], lines: [] }); };
  const answer = (statement, slotName) => {
    const tag = /^\/\* sh:([a-z]+) \*\//.exec(statement)?.[1] ?? (statement.startsWith('SET ') ? 'set' : null);
    s.log.push(tag);
    const failure = s.fail.find(f => f.tag === tag);
    if (failure) { s.fail.splice(s.fail.indexOf(failure), 1); throw failure.error; }
    if (/get_changes/.test(statement)) throw new Error('get_changes is never used');
    if (tag === 'set') return { rows: [], command: 'SET' };
    if (tag === 'session' || tag === 'drainsession') return { rows: [], command: 'SET' };
    // The run lease: always granted; other runs' leases as the test sets them.
    if (tag === 'lease') return { rows: [['true']] };
    if (tag === 'shared') return { rows: [[String(s.otherRuns ?? 0)]] };
    // The end barrier's drain read, on its own session: P0, the queue write locks, the pending counts, the names.
    if (tag === 'drainlsn') return { rows: [[lsnText(s.lsn)]] };
    if (tag === 'queuelocks') return { rows: [[String(s.queueLocks ?? 0)]] };
    if (tag === 'queuecount') { if (s.queueError) throw s.queueError; s.onQueueCount?.(); return { rows: [(typeof s.pending === 'function' ? s.pending() : s.pending ?? []).map(String)] }; }
    if (tag === 'queuenames') return { rows: (s.queueNames ?? []).map(n => [n, s.queuePersistence?.[n] ?? 'pr']) };
    // The tables whose writes the WAL never carries (unlogged and foreign), as the mark lists them.
    if (tag === 'notinwal') return { rows: (s.notInWal ?? []).map(n => [n]) };
    if (tag === 'server') return { rows: [[walLevel, version, recovery, '8192', '16777216']] };
    if (tag === 'create') { const name = /replication_slot\('([a-z0-9_]+)'/.exec(statement)[1]; s.slots.set(name, { confirmed: s.lsn }); return { rows: [[lsnText(s.lsn)]] }; }
    // The database's catalog fingerprint (./catalog.mjs): one unchanging catalog unless a test sets s.dbCatalog.
    if (tag === 'dbcatalog' || tag === 'dbversions') { const out = { rows: catalogAnswer(statement, s.dbCatalog) }; if (tag === 'dbversions') s.onDbCatalog?.(); return out; }
    if (tag === 'catalog') { const out = { rows: catalogRows() }; if (s.driftDuringMark) { s.drift += 1; s.driftDuringMark = false; } return out; }
    // The mark reads the write locks twice, before and after the position.
    if (tag === 'writers') { s.lockReads = (s.lockReads ?? 0) + 1; return { rows: [[String(s.lockReads % 2 === 0 && s.writersAfter !== undefined ? s.writersAfter : s.writers)]] }; }
    if (tag === 'position') return { rows: [[lsnText(s.lsn), recovery]] };
    if (tag === 'slot') { const slot = s.slots.get(slotName()); return { rows: slot ? [[s.walStatus, s.notHeld ? 'false' : 'true']] : [] }; }
    if (tag === 'flush') return { rows: [[lsnText(s.flush ?? s.lsn)]] };
    if (tag === 'peek') {
      const upto = lsnValue(/'([0-9A-F]+\/[0-9A-F]+)'::pg_catalog\.pg_lsn/.exec(statement)[1]), slot = s.slots.get(slotName());
      if (!slot) throw new PgError('query-failed', '42704');
      const after = s.wal.filter(x => x.end > slot.confirmed), within = after.filter(x => x.end <= upto);
      const out = s.overshoot && after.length > within.length ? [...within, after[within.length]] : within;
      // A raw test_decoding line is classified as the server's projection does, against the prefixes the statement sends.
      const prefixes = [...statement.matchAll(/\(E'((?:[^'\\]|''|\\\\)*)'\)/g)].map(m => m[1].replace(/''/g, "'").replace(/\\\\/g, '\\')).filter(x => x.startsWith('table '));
      const project = line => {
        if (Array.isArray(line)) return line;
        if (prefixes.some(x => line.startsWith(x))) return ['declared', line];
        if (/^table .*: TRUNCATE:( \(no-flags\)| restart_seqs| cascade| restart_seqs cascade)$/.test(line)) return ['truncate', line];
        const other = /^table (.+?): (?:INSERT|UPDATE|DELETE):/.exec(line);
        return other ? ['other', other[1]] : line.startsWith('message: ') ? ['message', null] : ['unknown', null];
      };
      return { rows: out.flatMap(x => x.loose ? [[lsnText(x.end), x.xid, ...x.loose]] : [[lsnText(x.end - 0x80n), x.xid, 'tx', `BEGIN ${x.xid}`], ...x.lines.map((line, k) => [lsnText(x.end - 0x80n + BigInt(k)), x.xid, ...project(line)]), [lsnText(x.end), x.xid, 'tx', `COMMIT ${x.xid}`]]) };
    }
    if (tag === 'advance') { const slot = s.slots.get(slotName()); slot.confirmed = lsnValue(/'([0-9A-F]+\/[0-9A-F]+)'::pg_catalog\.pg_lsn/.exec(statement)[1]); return { rows: [[lsnText(slot.confirmed)]] }; }
    if (tag === 'drop') { s.slots.delete(/replication_slot\('([a-z0-9_]+)'/.exec(statement)[1]); return { rows: [] }; }
    throw new Error(`unscripted statement: ${statement.slice(0, 60)}`);
  };
  s.connect = async () => {
    let mine = null, alive = true, catalog = false;
    return {
      async query(sql) {
        if (!alive) throw new PgError('connection-closed');
        if (/SET quote_all_identifiers/.test(sql)) catalog = true; // the catalog fingerprint's own session (./catalog.mjs)
        const out = [];
        for (const statement of sql.split(';\n')) {
          try { out.push(answer(statement, () => mine)); }
          catch (error) {
            // As the server does: any ERROR drops this backend's temporary slots.
            if (error instanceof PgError && error.sqlState && mine) s.slots.delete(mine);
            if (error instanceof PgError && error.code === 'connection-closed') { alive = false; if (mine) s.slots.delete(mine); }
            throw error;
          }
          if (statement.includes('sh:create')) mine = /replication_slot\('([a-z0-9_]+)'/.exec(statement)[1];
        }
        return out;
      },
      // closed counts this observer's own sessions, not the catalog fingerprint's short ones.
      close() { if (alive) { alive = false; if (!catalog) s.closed += 1; if (mine) s.slots.delete(mine); } },
    };
  };
  return s;
}
