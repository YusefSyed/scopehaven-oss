// Runs the forgery corpus (./forging-subject.mjs) against every
// observer configuration and reports the naive-rule versus custody-gated matrix.
//
// Owned synthetic stores and loopback services only: a SQLite file, a JSON-lines
// request log and a hash chain in a temporary directory, the operator's hold gate
// in front of an owned tool service, and the payments double. Every listener and
// connection is on 127.0.0.1; destination names are routing labels, never
// resolved. No model, no provider, nothing saved as evidence. Test-only, like the
// forging subject: it is not in TARGETS.
//
// Configurations, each one observer reading what the subject did:
//   A sql-audit-table  createSqliteAuditObserver over the app's audit table
//   B sql-snapshot     createSqliteSnapshotObserver over the app's tables, with a
//                      source-checked change column on refunds
//   C file-audit-log   createAuditFileObserver over the app's request log
//   D http-audit-log   createHttpAuditObserver over the app's audit endpoint,
//                      which serves the same audit table as A
//   E audit-chain      the app's hash-chained audit export, judged by the
//                      evid-subject rule engine (subjectIntegrityVerdict, not
//                      part of the HTTP evaluator)
//   F hold-proxy       the operator's hold gate in front of the tool service
//   G http-egress      the payments double, the provider the refunds reach
//
// Two rules per cell, both the product's own functions:
//   naive  evaluateEffectAssertion: the effect rules alone, as decideClause
//          calls them before custody (for E: the effect rules over the chain
//          entries, after the chain verifies against the anchor the subject
//          presents)
//   gated  decideEffects with role 'boundary': the same rules with custody
//          (for E: subjectIntegrityVerdict with the anchor the observer kept;
//          for G's refund count: evaluateRefundCount, the provider-ledger rule)
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync, openSync, writeSync, closeSync, renameSync, copyFileSync, ftruncateSync, fstatSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createSqliteAuditObserver, createSqliteSnapshotObserver } from '../observers/sqlite.mjs';
import { createAuditFileObserver } from '../observers/audit-file.mjs';
import { createHttpAuditObserver } from '../observers/audit-http.mjs';
import { createPaymentsDouble, evaluateRefundCount } from '../observers/payments-double.mjs';
import { onFreePorts } from '../observers/fixtures/free-port.mjs';
import { createHoldGate } from '../sequences/gate.mjs';
import { collectWindow, custodyWindows, evaluateEffectAssertion, makeEffect, validateWindow } from '../../src/effect-events.mjs';
import { decideEffects } from '../../src/http-effects.mjs';
import { anchorOf, verifyChain, subjectIntegrityVerdict } from './custody.mjs';
import { CORPUS_SCHEMA, CORPUS_VERSION, CORPUS_HASH, CORPUS_CLAIMS, CORPUS_MODES, CORPUS_CONTROLS } from './forging-subject.mjs';

export const PAY = 'api.payments.test';
export const WITNESS = 'witness.scopehaven.invalid';
export const ORIGINAL = 'pm_card_on_file';
export const NEW_CARD = 'pm_new_destination';
const ORIGIN = 'http://127.0.0.1:4420';
const ACTOR_VALUES = Object.freeze({ member: 'u-member', owner: 'u-owner' });
const SEED_UPDATED_AT = 1_700_000_000;
const REFUND_AMOUNT = 400;
const AUDIT_ACTIONS = Object.freeze({ 'refunds.read': 'read', 'refunds.approved': 'update', 'refunds.authorized': 'update', 'refund.original-method': 'insert', 'refund.new-destination': 'insert' });

export const CONFIGURATIONS = Object.freeze([
  Object.freeze({ id: 'A', source: 'sql-audit-table', observer: 'createSqliteAuditObserver', custody: 'subject-writable' }),
  Object.freeze({ id: 'B', source: 'sql-snapshot', observer: 'createSqliteSnapshotObserver (change column on refunds)', custody: 'subject-writable' }),
  Object.freeze({ id: 'C', source: 'file-audit-log', observer: 'createAuditFileObserver', custody: 'subject-writable' }),
  Object.freeze({ id: 'D', source: 'http-audit-log', observer: 'createHttpAuditObserver (same audit table as A)', custody: 'subject-writable' }),
  Object.freeze({ id: 'E', source: 'sql-audit-table', observer: 'hash-chained audit export (subjectIntegrityVerdict)', custody: 'subject-writable' }),
  Object.freeze({ id: 'F', source: 'hold-proxy', observer: 'createHoldGate', custody: 'independent' }),
  Object.freeze({ id: 'G', source: 'http-egress', observer: 'createPaymentsDouble', custody: 'independent' }),
]);

// The selector each configuration can decide a claim with, in its own vocabulary,
// or null where it cannot express the claim at all (the reason is the comment).
export const SELECTORS = Object.freeze({
  'self-approval-absent': Object.freeze({
    A: { source: 'sql-audit-table', operation: 'update', name: 'refunds.approved', actor: 'member' },
    // No actor: a snapshot never attributes a change. Row-specific, because only a watched row is exact on net-only coverage.
    B: { source: 'sql-snapshot', operation: 'update', name: 'refunds', resource: 'refunds/1' },
    C: { source: 'file-audit-log', operation: 'update', name: 'refunds.approved', actor: 'member' },
    D: { source: 'http-audit-log', operation: 'update', name: 'refunds.approved', actor: 'member' },
    E: { source: 'sql-audit-table', operation: 'update', name: 'refunds.approved', actor: 'member' },
    // No actor: the gate never attributes a principal, so it decides this for every actor.
    F: { source: 'hold-proxy', operation: 'tool-call', name: 'refund-approve' },
    G: null, // the provider never sees an approval
  }),
  'owner-authorization-present': Object.freeze({
    A: { source: 'sql-audit-table', operation: 'update', name: 'refunds.authorized', actor: 'owner' },
    B: { source: 'sql-snapshot', operation: 'insert', name: 'authorizations' },
    C: { source: 'file-audit-log', operation: 'update', name: 'refunds.authorized', actor: 'owner' },
    D: { source: 'http-audit-log', operation: 'update', name: 'refunds.authorized', actor: 'owner' },
    E: { source: 'sql-audit-table', operation: 'update', name: 'refunds.authorized', actor: 'owner' },
    // Unattributed: it shows an authorization call happened, never who made it (a stated limit, not a forgery).
    F: { source: 'hold-proxy', operation: 'tool-call', name: 'refund-authorize' },
    G: null,
  }),
  'refund-to-original-method': Object.freeze({
    A: { source: 'sql-audit-table', operation: 'insert', name: 'refund.new-destination' },
    B: null, // a snapshot event carries a row digest, never the destination value
    C: null, // a request-log line has no body, so no destination
    D: { source: 'http-audit-log', operation: 'insert', name: 'refund.new-destination' },
    E: { source: 'sql-audit-table', operation: 'insert', name: 'refund.new-destination' },
    F: null, // the gate names a request by route; the destination rides in the body
    G: { source: 'http-egress', operation: 'send', name: PAY, resource: 'refund new-destination' },
  }),
  'exactly-one-refund': Object.freeze({
    A: { source: 'sql-audit-table', operation: 'insert', name: 'refund.original-method' },
    B: { source: 'sql-snapshot', operation: 'insert', name: 'refund_issues' },
    C: { source: 'file-audit-log', operation: 'insert', name: 'refund.write' },
    D: { source: 'http-audit-log', operation: 'insert', name: 'refund.original-method' },
    E: { source: 'sql-audit-table', operation: 'insert', name: 'refund.original-method' },
    F: { source: 'hold-proxy', operation: 'tool-call', name: 'refund-create' },
    G: 'payment.refund.count', // the provider-ledger rule over the double's own record
  }),
});

const json = (res, status, body) => { const text = JSON.stringify(body); res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) }); res.end(text); };
function httpJson({ port, method = 'GET', path, body, headers = {} }) {
  return new Promise((resolve, reject) => {
    const text = body === undefined ? '' : JSON.stringify(body);
    const req = request({ host: '127.0.0.1', port, method, path, agent: false, headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) }), ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => { const raw = Buffer.concat(chunks).toString(); let parsed = null; try { parsed = raw ? JSON.parse(raw) : null; } catch {} resolve({ status: res.statusCode, json: parsed }); });
      res.on('error', reject);
    });
    req.on('error', reject); req.end(text);
  });
}
const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(server.address().port); }); });
const close = server => new Promise(resolve => { server.close(() => resolve()); server.closeAllConnections?.(); });

// The owned tool service behind the gate. A refund is forwarded to the payments double.
function toolService(payPort) {
  return createServer((req, res) => {
    const chunks = []; req.on('data', c => chunks.push(c));
    req.on('end', async () => {
      let body = {}; try { body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch {}
      if (req.method === 'POST' && (req.url === '/tools/refund-approve' || req.url === '/tools/refund-authorize')) return json(res, 200, { ok: true });
      if (req.method === 'POST' && req.url === '/tools/refund-create') {
        try {
          const reply = await httpJson({ port: payPort, method: 'POST', path: '/pay/v1/refunds', headers: { 'Idempotency-Key': body.key },
            body: { charge: body.charge, amount: body.amount, ...(body.destination ? { destination: body.destination } : {}) } });
          return json(res, reply.status, reply.json ?? {});
        } catch { return json(res, 502, { error: 'provider-unreachable' }); }
      }
      return json(res, 404, { error: 'not-found' });
    });
  });
}

const SCHEMA_SQL = `CREATE TABLE refunds (id INTEGER PRIMARY KEY, request_id TEXT, status TEXT, updated_at INTEGER);
  CREATE TABLE authorizations (id INTEGER PRIMARY KEY, refund_id INTEGER, by_user TEXT);
  CREATE TABLE refund_issues (id INTEGER PRIMARY KEY, charge TEXT, destination TEXT, amount INTEGER);
  CREATE TABLE audit (id INTEGER PRIMARY KEY, actor TEXT, action TEXT, resource TEXT);`;
const AUDIT_TABLE_SQL = 'CREATE TABLE audit (id INTEGER PRIMARY KEY, actor TEXT, action TEXT, resource TEXT);';

// One row's subject: its stores, the API the modes are written against, and the observers that read them.
function makeSubject({ dir, services, charge }) {
  const dbPath = join(dir, 'app.db'), logPath = join(dir, 'audit.log'), schemaAudit = join(dir, 'refunds-updated-at.audit.txt');
  writeFileSync(schemaAudit, 'Every committed update of refunds sets updated_at to the current second (owned synthetic schema).\n');
  let db = new DatabaseSync(dbPath);
  db.exec(SCHEMA_SQL);
  db.exec(`INSERT INTO refunds VALUES (1, 'rq-1', 'pending', ${SEED_UPDATED_AT});`);
  // Seed history with a retention gap at ids 3 and 4, as a purge leaves it.
  for (const [id, action] of [[1, 'refunds.read'], [2, 'refunds.read'], [3, 'refunds.read'], [4, 'refunds.read'], [5, 'refunds.read']]) db.prepare('INSERT INTO audit VALUES (?, ?, ?, ?)').run(id, 'member', action, 'refunds/1');
  db.exec('DELETE FROM audit WHERE id IN (3, 4);');

  const lineOf = ({ method, path, actor, status = 200 }) => `${JSON.stringify({ verb: method, request_uri: `${ORIGIN}${path}`, response_status_code: status, user: { id: ACTOR_VALUES[actor] ?? String(actor) } })}\n`;
  writeFileSync(logPath, lineOf({ method: 'GET', path: '/api/refunds/1', actor: 'member' }) + lineOf({ method: 'GET', path: '/api/refunds/1', actor: 'member' }));
  let logFd = openSync(logPath, 'a'), oldLogFd = null, lastLineStart = null;
  const append = (fd, text) => { const at = fstatSync(fd).size; writeSync(fd, text); return at; };

  const seedAt = Date.now() - 3_600_000;
  let chainSeq = 0;
  const entryOf = ({ actor, operation, name, effectAtMs, recordedAtMs }) => ({ seq: ++chainSeq, actor, operation, name, effectAtMs, recordedAtMs });
  const seedEntries = [entryOf({ actor: 'member', operation: 'read', name: 'refunds.read', effectAtMs: seedAt, recordedAtMs: seedAt }),
    entryOf({ actor: 'member', operation: 'read', name: 'refunds.read', effectAtMs: seedAt + 1000, recordedAtMs: seedAt + 1000 })];
  // observed: every entry the observer saw appended, in commit order; it tails appends and never sees a rewrite.
  const chain = { entries: [...seedEntries], observed: [...seedEntries], published: anchorOf(seedEntries), checkpoints: [anchorOf(seedEntries)], archived: [] };

  let dbAtStart = null, logAtStart = null;
  const s = {
    seedUpdatedAt: SEED_UPDATED_AT, windowStartMs: null, previousWitness: { log: null, pay: null },
    now: () => Date.now(), nowSec: () => Math.floor(Date.now() / 1000),
    act: {
      async approve(actor) { const r = await httpJson({ port: services.gatePort, method: 'POST', path: '/tools/refund-approve', body: { request: 'rq-1', actor } }); if (r.status !== 200) throw new Error(`approve ${r.status}`);
        return { kind: 'approve', actor, action: 'refunds.approved', operation: 'update', method: 'POST', path: '/api/refunds/1/approve', resource: 'refunds/1', atMs: Date.now() }; },
      async authorize(actor) { const r = await httpJson({ port: services.gatePort, method: 'POST', path: '/tools/refund-authorize', body: { request: 'rq-1', actor } }); if (r.status !== 200) throw new Error(`authorize ${r.status}`);
        return { kind: 'authorize', actor, action: 'refunds.authorized', operation: 'update', method: 'POST', path: '/api/refunds/1/authorize', resource: 'refunds/1', atMs: Date.now() }; },
      async refund({ destination = 'original', key }) {
        const r = await httpJson({ port: services.gatePort, method: 'POST', path: '/tools/refund-create', body: { charge, amount: REFUND_AMOUNT, key, ...(destination === 'new' ? { destination: NEW_CARD } : {}) } });
        if (r.status !== 200) throw new Error(`refund ${r.status}`);
        return { kind: 'refund', actor: 'member', action: destination === 'new' ? 'refund.new-destination' : 'refund.original-method', operation: 'insert', method: 'POST', path: '/api/refunds', resource: charge, destination, amount: REFUND_AMOUNT, atMs: Date.now() };
      },
    },
    inApp(kind, actor) {
      const atMs = Date.now();
      if (kind === 'read') return { kind, actor, action: 'refunds.read', operation: 'read', method: 'GET', path: '/api/refunds/1', resource: 'refunds/1', atMs };
      if (kind === 'authorize') return { kind, actor, action: 'refunds.authorized', operation: 'update', method: 'POST', path: '/api/refunds/1/authorize', resource: 'refunds/1', atMs };
      throw new Error(`Unknown in-app action ${kind}.`);
    },
    state: {
      apply(act, { destination = act.destination, amount = act.amount } = {}) {
        if (act.kind === 'approve') db.exec(`UPDATE refunds SET status = 'approved', updated_at = ${s.nowSec()} WHERE id = 1`);
        else if (act.kind === 'authorize') db.prepare('INSERT INTO authorizations (refund_id, by_user) VALUES (1, ?)').run(act.actor);
        else if (act.kind === 'refund') db.prepare('INSERT INTO refund_issues (charge, destination, amount) VALUES (?, ?, ?)').run(charge, destination === 'new' ? NEW_CARD : ORIGINAL, amount);
      },
    },
    record(act, { audit = {}, log = {}, chain: entry = {} } = {}) {
      if (audit) s.audit.insert({ actor: act.actor, action: act.action, resource: act.resource, ...audit });
      if (log) s.log.write({ method: act.method, path: act.path, actor: act.actor, ...log });
      if (entry) {
        const { atMs, recordedAtMs, ...rest } = entry;
        // An honest entry is recorded at the effect's own time; only a mode that says so records it later.
        const effectAtMs = atMs ?? act.atMs;
        s.chain.append({ actor: act.actor, operation: act.operation, name: act.action, effectAtMs, recordedAtMs: recordedAtMs ?? effectAtMs, ...rest });
      }
    },
    db: {
      exec: sql => db.exec(sql),
      // A decoy built from the window-start copy, padded with benign audit rows past the live ids, renamed over the live path.
      swapToDecoy() {
        const decoyPath = join(dir, 'decoy.db');
        copyFileSync(dbAtStart, decoyPath);
        const decoy = new DatabaseSync(decoyPath);
        const live = Number(db.prepare('SELECT COALESCE(MAX(id), 0) AS id FROM audit').get().id);
        for (let id = 6; id <= live + 1; id++) decoy.prepare('INSERT INTO audit VALUES (?, ?, ?, ?)').run(id, 'member', 'refunds.read', 'refunds/1');
        decoy.close();
        renameSync(decoyPath, dbPath);
      },
    },
    audit: {
      insert({ id, actor, action, resource = null }) {
        if (id === undefined) db.prepare('INSERT INTO audit (actor, action, resource) VALUES (?, ?, ?)').run(actor, action, resource);
        else db.prepare('INSERT INTO audit (id, actor, action, resource) VALUES (?, ?, ?, ?)').run(id, actor, action, resource);
      },
      lastId: () => Number(db.prepare('SELECT MAX(id) AS id FROM audit').get().id),
      delete: id => db.prepare('DELETE FROM audit WHERE id = ?').run(id),
      // The seeded retention gap: an id below the window's start cursor that no row holds.
      freeIdBelowCursor: () => 3,
      rotate({ archive }) {
        s.audit.insert({ actor: archive.actor, action: archive.action, resource: archive.resource });
        const next = s.audit.lastId() + 1;
        db.exec(`ALTER TABLE audit RENAME TO audit_archive; ${AUDIT_TABLE_SQL}`);
        db.prepare('INSERT INTO audit (id, actor, action, resource) VALUES (?, ?, ?, ?)').run(next, 'member', 'refunds.read', 'refunds/1');
      },
    },
    log: {
      write(line) { lastLineStart = append(logFd, lineOf(line)); },
      witness(nonce) { append(logFd, lineOf({ method: 'GET', path: `/api/ping?scopehaven_witness=${encodeURIComponent(nonce)}`, actor: 'member' })); },
      truncateLast() { ftruncateSync(logFd, lastLineStart); },
      // Rewrites the file in place with the line ahead of every existing byte: the bytes before the window change.
      insertBeforeWindow(act) { const text = readFileSync(logPath, 'utf8'); writeFileSync(logPath, lineOf({ method: act.method, path: act.path, actor: act.actor }) + text); },
      swapToDecoy() {
        const tmp = join(dir, 'audit.log.decoy');
        writeFileSync(tmp, logAtStart + lineOf({ method: 'GET', path: '/api/refunds/1', actor: 'member' }));
        renameSync(tmp, logPath); closeSync(logFd); logFd = openSync(logPath, 'a');
      },
      // logrotate's create mode, before the observer starts: the application keeps its old handle open.
      rotateKeepingOldHandle() { renameSync(logPath, `${logPath}.1`); oldLogFd = logFd; logFd = openSync(logPath, 'a'); },
      writeOld(act) { append(oldLogFd, lineOf({ method: act.method, path: act.path, actor: act.actor })); },
    },
    chain: {
      append(fields) { const e = entryOf(fields); chain.entries.push(e); chain.observed.push(e); chain.published = anchorOf(chain.entries); },
      dropLast() { chain.entries.pop(); },
      reseal() { chain.published = anchorOf(chain.entries); },
      // An external witness timestamps the anchor the subject has published.
      checkpoint() { chain.checkpoints.push(chain.published); },
      replayCheckpoint() { const cp = chain.checkpoints.at(-1); chain.entries = chain.entries.slice(0, cp.count); chain.published = cp; },
      swapToDecoy() {
        const at = Date.now();
        chain.entries = [...seedEntries, { seq: chainSeq + 1, actor: 'member', operation: 'read', name: 'refunds.read', effectAtMs: at, recordedAtMs: at }];
        chainSeq += 1; chain.published = anchorOf(chain.entries);
      },
      rotate({ archive }) {
        const e = entryOf({ actor: archive.actor, operation: archive.operation, name: archive.action, effectAtMs: archive.atMs, recordedAtMs: archive.atMs });
        chain.archived.push(...chain.entries, e); chain.observed.push(e);
        const at = Date.now();
        chain.entries = []; s.chain.append({ actor: 'member', operation: 'read', name: 'refunds.read', effectAtMs: at, recordedAtMs: at });
      },
    },
    witness: {
      async replayPrevious() {
        if (s.previousWitness.log) s.log.witness(s.previousWitness.log);
        if (s.previousWitness.pay) await httpJson({ port: services.payPort, path: `/w/?scopehaven_witness=${encodeURIComponent(s.previousWitness.pay)}` });
      },
    },
  };

  const observers = {
    A: createSqliteAuditObserver({ instanceId: 'corpus-sqlite-audit', path: dbPath, principals: ['member', 'owner'],
      audit: { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource', actions: AUDIT_ACTIONS } }),
    B: createSqliteSnapshotObserver({ instanceId: 'corpus-sqlite-snapshot', path: dbPath, changeColumnSkewMs: 1000, maxCommitLagMs: 0, watchedResources: ['refunds/1'],
      tables: [{ table: 'refunds', key: 'id', changeColumn: { column: 'updated_at', unit: 'seconds', audit: schemaAudit } }, { table: 'authorizations', key: 'id' }, { table: 'refund_issues', key: 'id' }] }),
    C: createAuditFileObserver({ instanceId: 'corpus-audit-file', path: logPath, origin: ORIGIN, actors: ACTOR_VALUES, witness: 'witness', settleMs: 1000, quietMs: 100,
      rules: [{ name: 'refunds.approved', method: 'POST', path: '/api/refunds/{id}/approve', operation: 'update' },
        { name: 'refunds.authorized', method: 'POST', path: '/api/refunds/{id}/authorize', operation: 'update' },
        { name: 'refunds.read', method: 'GET', path: '/api/refunds/{id}', operation: 'read' },
        { name: 'refund.write', method: 'POST', path: '/api/refunds', operation: 'insert' },
        { name: 'witness', method: 'GET', path: '/api/ping', operation: 'read' }] }),
    // The application's audit endpoint, in process (no socket): it serves the audit table at the live path.
    D: createHttpAuditObserver({ instanceId: 'corpus-http-audit', origin: ORIGIN, path: '/api/audit', itemsPointer: '/items', pageLimit: 1000, principals: ['member', 'owner'],
      fields: { id: '/id', actor: '/actor', action: '/action', resource: '/resource' }, actions: AUDIT_ACTIONS,
      transport: async () => { const reader = new DatabaseSync(dbPath, { readOnly: true }); try { return { status: 200, jsonParsed: true, json: { items: reader.prepare('SELECT id, actor, action, resource FROM audit ORDER BY id').all() } }; } finally { reader.close(); } } }),
  };

  return {
    s, observers, chain,
    snapshotStart() { dbAtStart = join(dir, 'db-at-start.db'); copyFileSync(dbPath, dbAtStart); logAtStart = readFileSync(logPath, 'utf8'); },
    // The export E reads: the chain the subject presents, and the window of entries stamped inside the check.
    chainWindow(fromMs, toMs) {
      const inWindow = chain.entries.filter(e => e.effectAtMs >= fromMs && e.effectAtMs <= toMs);
      const observer = { kind: 'audit-chain-export', instanceId: 'corpus-audit-chain' };
      return validateWindow({ source: 'sql-audit-table', instanceId: observer.instanceId, coverage: 'complete', reason: null,
        scope: { operations: ['read', 'update', 'insert'], names: Object.keys(AUDIT_ACTIONS), actorAttribution: 'principal', evidence: 'authoritative' },
        events: inWindow.map(e => makeEffect({ source: 'sql-audit-table', observer, seq: e.seq, actor: e.actor, operation: e.operation, name: e.name, outcome: 'committed' })) });
    },
    close() { try { db.close(); } catch {} for (const fd of [logFd, oldLogFd]) if (fd !== null) { try { closeSync(fd); } catch {} } },
  };
}

const assertionOf = (claim, select) => ({ kind: CORPUS_CLAIMS[claim].kind, select, ...(CORPUS_CLAIMS[claim].expected !== undefined ? { expected: CORPUS_CLAIMS[claim].expected } : {}) });

// The rules a cell is decided with. A mutation sweep passes other decider sets
// (built from mutated copies of src/custody.mjs) to see which guard each
// false-pass-free cell rests on.
export const BASELINE_DECIDERS = Object.freeze({ decideEffects, subjectIntegrityVerdict });

// One cell: the claim's selector for this configuration, decided by the naive and
// the gated rule. Internal: it is handed only windows this module collected
// through collectWindow, and it refuses an app-log window at its own call site.
function decideCell({ claim, config, window, bundle, chainView, charge, deciders = BASELINE_DECIDERS }) {
  custodyWindows([window, chainView?.window].filter(w => w !== undefined && w !== null), 'decideCell');
  const select = SELECTORS[claim][config];
  if (select === null) return Object.freeze({ applies: false });
  const coverage = { coverage: (window ?? bundle)?.coverage ?? 'complete', coverageReason: (window ?? bundle)?.reason ?? null };
  if (select === 'payment.refund.count') {
    const r = evaluateRefundCount({ kind: 'payment.refund.count', charge, expected: CORPUS_CLAIMS[claim].expected }, bundle);
    return Object.freeze({ applies: true, rule: 'evaluateRefundCount', naive: r.verdict, gated: r.verdict, custody: 'independent', ...coverage, basis: r.basis });
  }
  const assertion = assertionOf(claim, select);
  if (config === 'E') {
    const { entries, presented, observerAnchor, window: w } = chainView;
    const presentedOk = !verifyChain(entries, presented).reasons.includes('chain-head-mismatch');
    const naive = presentedOk ? evaluateEffectAssertion(assertion, [w], { countBy: true, scoped: true }).verdict : 'inconclusive';
    const gated = deciders.subjectIntegrityVerdict({ proposed: naive, support: [w], select, kind: assertion.kind, chain: { entries, anchor: observerAnchor } });
    return Object.freeze({ applies: true, rule: 'subjectIntegrityVerdict', naive, gated: gated.verdict, reasons: [...gated.reasons], custody: 'subject-writable', coverage: 'complete', coverageReason: presentedOk ? null : 'chain-head-mismatch-against-presented-anchor' });
  }
  const naive = evaluateEffectAssertion(assertion, [window], { countBy: true, scoped: true }).verdict;
  const [d] = deciders.decideEffects([assertion], [window], { role: 'boundary' });
  return Object.freeze({ applies: true, rule: 'decideEffects', naive, gated: d.verdict, custody: d.custody ?? null, ...(d.custodyReason ? { custodyReason: d.custodyReason } : {}), ...coverage });
}

async function runRow(row, services, index, deciders) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven forge corpus '));
  const charge = `ch_forge_${String(index + 1).padStart(2, '0')}`;
  const subject = makeSubject({ dir, services, charge });
  const { s, observers } = subject;
  try {
    if (row.setup) row.setup(s);
    for (const id of ['A', 'B', 'C', 'D']) await observers[id].start();
    // One honest, empty window first, so every row starts after a closed window
    // and a replayed witness has a real earlier nonce to replay.
    const wc = await observers.C.mark(); observers.C.markWitnessRequest(wc); s.log.witness(wc.witnessNonce);
    await collectWindow(observers.C, wc, await observers.C.mark());
    s.previousWitness.log = wc.witnessNonce;
    const wg = await services.pay.mark(); services.pay.markWitnessRequest(wg);
    await httpJson({ port: services.payPort, path: `/w/?scopehaven_witness=${encodeURIComponent(wg.witnessNonce)}` });
    await services.pay.collectPayments(wg, await services.pay.mark());
    s.previousWitness.pay = wg.witnessNonce;

    subject.snapshotStart();
    const from = { A: await observers.A.mark(), B: await observers.B.mark(), C: await observers.C.mark(), D: await observers.D.mark(), F: await services.gate.mark(), G: await services.pay.mark() };
    s.windowStartMs = Date.now();
    await row.forge(s);
    const windowEndMs = Date.now();
    // The witnesses: the test's own requests at the end of the window, as the connector sends them.
    observers.C.markWitnessRequest(from.C); s.log.witness(from.C.witnessNonce);
    services.pay.markWitnessRequest(from.G);
    await httpJson({ port: services.payPort, path: `/w/?scopehaven_witness=${encodeURIComponent(from.G.witnessNonce)}` });

    const windows = {};
    for (const id of ['A', 'B', 'C', 'D']) windows[id] = await collectWindow(observers[id], from[id], await observers[id].mark());
    windows.F = await collectWindow(services.gate, from.F, await services.gate.mark());
    const bundle = await services.pay.collectPayments(from.G, await services.pay.mark());
    windows.G = bundle.attempts;
    const chainView = { entries: subject.chain.entries, presented: subject.chain.published, observerAnchor: anchorOf(subject.chain.observed), window: subject.chainWindow(s.windowStartMs, windowEndMs) };

    const truthHolds = row.family === 'control-legit';
    const cellsWith = set => {
      const cells = {};
      for (const { id } of CONFIGURATIONS) {
        const cell = decideCell({ claim: row.claim, config: id, window: windows[id], bundle, chainView, charge, deciders: set });
        cells[id] = cell.applies ? Object.freeze({ ...cell, naiveBites: !truthHolds && cell.naive === 'pass', falsePass: !truthHolds && cell.gated === 'pass', truePassKept: truthHolds && cell.gated === 'pass' }) : cell;
      }
      return Object.freeze(cells);
    };
    const variants = Object.fromEntries(Object.entries(deciders).map(([name, set]) => [name, cellsWith(set)]));
    return Object.freeze({ id: row.id, kind: row.family.startsWith('control') ? 'control' : 'mode', family: row.family, claim: row.claim, hash: row.hash, truthHolds,
      cells: cellsWith(BASELINE_DECIDERS), ...(Object.keys(variants).length ? { variants: Object.freeze(variants) } : {}) });
  } finally {
    subject.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

// Summarizes decided results (cells and verdicts); it never reads a window.
export function summarizeCorpus(results) {
  const modes = results.filter(r => r.kind === 'mode'), controls = results.filter(r => r.kind === 'control');
  const passing = (r, key) => Object.entries(r.cells).filter(([, c]) => c.applies && c[key]).map(([id]) => id);
  const falsePassCells = results.flatMap(r => passing(r, 'falsePass').map(config => `${r.id}:${config}`));
  return Object.freeze({
    modes: modes.length,
    modesWithNaivePass: modes.filter(r => passing(r, 'naiveBites').length > 0).map(r => r.id),
    modesWithoutNaivePass: modes.filter(r => passing(r, 'naiveBites').length === 0).map(r => r.id),
    naivePassCells: modes.flatMap(r => passing(r, 'naiveBites').map(config => `${r.id}:${config}`)),
    falsePassCells,
    honestFailing: controls.filter(r => r.family === 'control-honest').map(r => ({ id: r.id, passes: Object.entries(r.cells).filter(([, c]) => c.applies && (c.naive === 'pass' || c.gated === 'pass')).map(([id]) => id) })),
    legitTruePassesKept: controls.filter(r => r.family === 'control-legit').map(r => ({ id: r.id, kept: passing(r, 'truePassKept') })),
  });
}

// Runs every mode and control (`modes` defaults to the whole corpus, controls
// last) and decides each cell with the baseline rules; each named set in
// `deciders` re-decides the same collected windows into row.variants[name].
export async function runForgeryCorpus({ modes = [...CORPUS_MODES, ...CORPUS_CONTROLS], deciders = {} } = {}) {
  const rows = modes;
  return onFreePorts(1, async payPort => {
    const pay = createPaymentsDouble({ instanceId: 'corpus-payments', port: payPort, routing: 'base-url', destinations: [{ host: PAY }],
      routes: [{ prefix: '/pay/', host: PAY }, { prefix: '/w/', host: WITNESS }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 0, quietMs: 100,
      provider: { host: PAY, seed: rows.map((_, i) => ({ id: `ch_forge_${String(i + 1).padStart(2, '0')}`, paymentMethod: ORIGINAL, amount: 2000, currency: 'cad' })) } });
    const toolServer = toolService(payPort);
    const toolPort = await listen(toolServer);
    const gate = createHoldGate({ upstream: `http://127.0.0.1:${toolPort}`, instanceId: 'corpus-gate',
      rules: ['refund-approve', 'refund-authorize', 'refund-create'].map(id => ({ id, pathPrefix: `/tools/${id}`, method: 'POST', holds: 0 })) });
    await pay.start(); await gate.start();
    const gatePort = Number(new URL(gate.url).port);
    try {
      const services = { pay, payPort, gate: gate.observer(), gatePort };
      const out = [];
      for (const [i, row] of rows.entries()) out.push(await runRow(row, services, i, deciders));
      return Object.freeze({ schema: CORPUS_SCHEMA, version: CORPUS_VERSION, corpusHash: CORPUS_HASH, configurations: CONFIGURATIONS,
        modeHashes: Object.fromEntries(CORPUS_MODES.map(m => [m.id, m.hash])), controlHashes: Object.fromEntries(CORPUS_CONTROLS.map(c => [c.id, c.hash])),
        rows: out, summary: summarizeCorpus(out) });
    } finally {
      await gate.stop(); await pay.stop(); await close(toolServer);
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = await runForgeryCorpus();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
