// Saved sequence runs are recomputed from the windows they sealed (run-validator.mjs). Every run here is made by the
// real runner (a fake transport; in-memory, SQLite or scripted-Postgres observers), saved as JSON and read back.
// An edit "re-derived" recomputes the results and counts and reseals the digest, as a consistent forger would.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runSequence, decideAssertion, countsOf, validateSequence, SEQUENCE_SCHEMA, SEQUENCE_RUN_SCHEMA } from './sequence.mjs';
import { validateSequenceRun } from './run-validator.mjs';
import { makeEffect } from '../observers/events.mjs';
import { createMcpObserver, FrameLog } from '../observers/mcp.mjs';
import { createSqliteSnapshotObserver } from '../observers/sqlite.mjs';
import { createPgSnapshotObserver } from '../observers/pg-snapshot.mjs';
import { scriptedDb, USER, PASSWORD } from '../observers/fixtures/fake-postgres.mjs';
import { createMysqlSnapshotObserver } from '../observers/mysql-snapshot.mjs';
import { scriptedMysql, MYSQL_USER, MYSQL_PASSWORD } from '../observers/fixtures/fake-mysql.mjs';
import { createEgressRecorder } from '../observers/egress-recorder.mjs';
import { createSmtpSink } from '../observers/smtp-sink.mjs';
import { request, createServer } from 'node:http';
import { createSqliteAuditObserver } from '../observers/sqlite.mjs';
import { createHttpAuditObserver } from '../observers/audit-http.mjs';
import { createAuditFileObserver } from '../observers/audit-file.mjs';
import { main, buildObservers, declaredObservers } from './cli.mjs';
import { createHoldGate } from './gate.mjs';
import { connect, createServer as createNetServer } from 'node:net';
import { digest } from '../../src/domain.mjs';

const transport = async () => ({ status: 200 });
const saved = run => JSON.parse(JSON.stringify(run));
const reseal = r => { const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest: _r, ...sealed } = r; r.runDigest = digest(sealed); return r; };
const rederive = r => { r.results = r.assertions.map(a => saved(decideAssertion(a, r.windows[`${a.from}>${a.to}`], r.aborted))); r.counts = countsOf(r.results); return reseal(r); };
const refuse = (r, code, detail, options, label = '') => assert.throws(() => validateSequenceRun(r, options), e => e.code === code && (detail === undefined || e.detail === detail), `${label} ${code} ${detail ?? ''}`);

// A scripted observer of a given kind, with the scope that kind declares in code (an audit table's operations
// come from its action map and always include update): each window's events come from plan(windowIndex).
const KIND_SCOPE = { 'sqlite-audit-table': [['update', 'tool-call'], 'principal', 'authoritative'], 'otlp-http-json-receiver': [['tool-call'], 'principal', 'presence-only'], 'hold-gate': [['tool-call'], 'none', 'authoritative'] };
function scripted({ kind = 'sqlite-audit-table', source = 'sql-audit-table', instanceId = 'sqlite-audit-db', names = ['refunds', 'payments'], plan = () => [] } = {}) {
  const observer = { kind, instanceId }, [operations, actorAttribution, evidence] = KIND_SCOPE[kind]; let at = 0;
  return { kind, instanceId, source, scope: Object.freeze({ operations, names, actorAttribution, evidence }),
    async start() {}, async stop() {}, async mark() { return { at: ++at }; },
    async collect(from, to) {
      const events = plan(from.at, to.at).map((e, i) => makeEffect({ source, observer, seq: i + 1, observedAt: '2026-10-06T00:00:00.000Z', operation: e.operation ?? 'update', name: e.name ?? 'refunds', outcome: e.outcome ?? 'committed' }));
      return { events, coverage: 'complete', reason: null };
    } };
}
const refundsNone = (extra = {}) => ({ id: 'NO-REFUND', title: 'Asking never issues a refund', severity: 'high', from: 'before', to: 'after', effect: { kind: 'effect.none', select: { name: 'refunds', operation: 'update' } }, ...extra });
const sequence = (assertions = [refundsNone()]) => ({ schema: SEQUENCE_SCHEMA, id: 'NO-REFUND', actors: { agent: { principalId: 'agent' } },
  steps: [{ mark: 'before' }, { request: { id: 'ask', actorId: 'agent', method: 'POST', path: '/agent/ask', body: { q: 'hello' } } }, { mark: 'mid' }, { mark: 'after' }], assertions });
const refunding = { plan: () => [{}] };
async function run(observers, seq = sequence()) { return saved(await runSequence(seq, { origin: 'http://127.0.0.1:1', observers, transport })); }

// A request-path gate: the one scripted kind whose record the app cannot write, so its absence can pass (src/custody.mjs).
const gated = () => scripted({ kind: 'hold-gate', source: 'hold-proxy', instanceId: 'hold-gate-1', names: ['refund-approve', 'ungated'] });
const gateSequence = () => sequence([refundsNone({ effect: { kind: 'effect.none', select: { name: 'refund-approve', operation: 'tool-call' } } })]);

test('a saved sequence run is recomputed from its sealed windows: pass, fail and a custody-held absence reproduce, with or without the expected sequence', async () => {
  for (const [observers, verdict, seq] of [[[gated()], 'pass', gateSequence()], [[scripted(refunding)], 'fail', sequence()], [[scripted()], 'inconclusive', sequence()]]) {
    const r = await run(observers, seq);
    assert.equal(r.schema, SEQUENCE_RUN_SCHEMA);
    assert.equal(r.results[0].verdict, verdict);
    // The audit table's absence is held by custody, with its reason; the recompute reproduces it exactly.
    assert.equal(r.results[0].custodyReason, verdict === 'inconclusive' ? 'subject-writable-custody' : undefined);
    assert.deepEqual(validateSequenceRun(r).results.map(x => x.verdict), [verdict]);
    validateSequenceRun(r, { expectedSequence: seq });
  }
});

test('a hand-edited verdict, window or count is refused; an edit without resealing breaks the digest', async () => {
  const failing = await run([scripted(refunding)]);
  const flipped = structuredClone(failing); Object.assign(flipped.results[0], { verdict: 'pass', status: 'pass' }); flipped.counts = { pass: 1, fail: 0, inconclusive: 0, error: 0 };
  refuse(reseal(flipped), 'sequence-verdict', 'NO-REFUND');
  const emptied = structuredClone(failing); emptied.windows['before>after'][0].events = [];
  refuse(reseal(emptied), 'sequence-verdict', 'NO-REFUND');
  const counted = structuredClone(failing); counted.counts.fail = 0; counted.counts.pass = 1;
  refuse(reseal(counted), 'invalid-sequence-run', 'counts');
  const unsealed = structuredClone(failing); unsealed.results[0].basis = 'edited';
  refuse(unsealed, 'invalid-sequence-run', 'run-digest');
  // The refusal names the sealed assertion's id, never a result's own text (which could carry terminal escapes).
  const escaped = structuredClone(failing); Object.assign(escaped.results[0], { id: '\u001b[32mPASS\u001b[0m', verdict: 'pass', status: 'pass' });
  refuse(reseal(escaped), 'sequence-verdict', 'NO-REFUND');
});

test('the expected sequence binds the assertions; a rewritten assertion re-derived and resealed is refused', async () => {
  const failing = await run([scripted(refunding)]);
  // Rewritten as an allowed-use control (which custody does not degrade) whose effect must exist: re-derived, it reads pass.
  const rewritten = structuredClone(failing); rewritten.assertions[0].effect.kind = 'effect.exists'; rewritten.assertions[0].severity = 'control';
  rederive(rewritten);
  assert.equal(rewritten.results[0].verdict, 'pass');
  refuse(rewritten, 'unexpected-sequence', undefined, { expectedSequence: sequence() });
  // Another sequence id or hash is refused too.
  const other = sequence(); other.id = 'SOMETHING-ELSE';
  refuse(failing, 'unexpected-sequence', undefined, { expectedSequence: other });
});

test('results and windows must match the assertions and observers one for one', async () => {
  const r = await run([scripted(refunding), scripted({ instanceId: 'sqlite-audit-second' })]);
  const extra = structuredClone(r); extra.results.push({ ...extra.results[0], id: 'FABRICATED' });
  refuse(reseal(extra), 'invalid-sequence-run', 'assertions');
  // Dropping the window of the observer that saw the refund would recompute as a pass.
  const missing = structuredClone(r); missing.windows['before>after'].shift();
  refuse(rederive(missing), 'invalid-sequence-run', 'windows');
  // Instance ids and assertion ids are unique.
  const sameInstance = structuredClone(r); sameInstance.observers[1].instanceId = sameInstance.observers[0].instanceId;
  sameInstance.windows['before>after'][1].instanceId = sameInstance.observers[0].instanceId;
  refuse(rederive(sameInstance), 'invalid-sequence-run', 'observers');
  const two = await run([scripted(refunding)], sequence([refundsNone({ id: 'A' }), refundsNone({ id: 'B', title: 'again' })]));
  const sameId = structuredClone(two); sameId.assertions[1].id = 'A';
  refuse(rederive(sameId), 'invalid-sequence-run', 'assertions');
  // The run's identity has the sequence id and hash forms.
  for (const [field, value] of [['sequenceId', 'NO-REFUND\u001b[0m'], ['sequenceId', ''], ['sequenceHash', 'abc']]) { const x = structuredClone(r); x[field] = value; refuse(reseal(x), 'invalid-sequence-run', 'identity', undefined, field); }
  const keys = structuredClone(r); delete keys.windows['before>after'];
  refuse(reseal(keys), 'invalid-sequence-run', 'windows');
  const more = structuredClone(r); more.windows['x>y'] = r.windows['before>after'];
  refuse(reseal(more), 'invalid-sequence-run', 'windows');
});

test('an observer kind is bound to its source and instance id; windows and events to their observer', async () => {
  // A presence-only OTel run relabelled as an authoritative audit source.
  const otel = await run([scripted({ kind: 'otlp-http-json-receiver', source: 'otel-genai', instanceId: 'otel-traces' })]);
  assert.equal(otel.results[0].verdict, 'unobservable');
  validateSequenceRun(otel, { expectedSequence: sequence() });
  const relabelled = structuredClone(otel);
  relabelled.observers[0].source = 'sql-audit-table'; relabelled.observers[0].scope = { ...relabelled.observers[0].scope, operations: ['update', 'tool-call'], evidence: 'authoritative' };
  for (const ws of Object.values(relabelled.windows)) for (const w of ws) { w.source = 'sql-audit-table'; w.scope = structuredClone(relabelled.observers[0].scope); }
  rederive(relabelled);
  // The effect rules would now pass it; custody holds an audit-table absence at inconclusive, and the observer binding refuses the relabel.
  assert.deepEqual([relabelled.results[0].verdict, relabelled.results[0].custodyReason], ['inconclusive', 'subject-writable-custody']);
  refuse(relabelled, 'invalid-sequence-run', 'observers', { expectedSequence: sequence() });
  // The window's source is bound to its observer's.
  const audit = await run([scripted(refunding)]);
  const source = structuredClone(audit);
  for (const w of source.windows['before>after']) { w.source = 'http-audit-log'; w.events.forEach(e => { e.source = 'http-audit-log'; }); }
  refuse(rederive(source), 'invalid-sequence-run', 'window-observer');
  // A kind no sequence observer has, a kind with the wrong source, and an instance id of another kind's form.
  for (const [label, edit] of [['mysql kind', o => { o.kind = 'mysql-snapshot-diff'; o.source = 'sql-snapshot'; }], ['unknown kind', o => { o.kind = 'memory-audit'; }],
    ['kind and source disagree', o => { o.kind = 'sqlite-snapshot-diff'; }], ['an instance id of another type', o => { o.instanceId = 'sqlite-snapshot-db'; }],
    ['an instance id of no type', o => { o.instanceId = 'memory-db'; }], ['an extra field', o => { o.extra = 1; }], ['no scope', o => { delete o.scope; }]]) {
    const r = structuredClone(audit); edit(r.observers[0]);
    for (const w of r.windows['before>after']) { w.instanceId = r.observers[0].instanceId; w.events.forEach(e => { e.observer = { kind: r.observers[0].kind ?? 'x', instanceId: r.observers[0].instanceId }; }); }
    refuse(rederive(r), 'invalid-sequence-run', 'observers', undefined, label);
  }
  // An event attributed to another observer inside the window: another kind, another instance, or both.
  for (const [label, observer] of [['kind', { kind: 'postgres-snapshot-diff', instanceId: 'sqlite-audit-db' }], ['instance', { kind: 'sqlite-audit-table', instanceId: 'sqlite-audit-other' }], ['both', { kind: 'postgres-snapshot-diff', instanceId: 'pg-snapshot-x' }]]) {
    const event = structuredClone(audit); event.windows['before>after'][0].events[0].observer = observer;
    refuse(rederive(event), 'invalid-sequence-run', 'window-observer', undefined, label);
  }
  // One window of an observer with a widened scope.
  const twoWindows = sequence([refundsNone({ id: 'X', to: 'mid' }), refundsNone({ id: 'Y', from: 'mid', effect: { kind: 'effect.none', select: { name: 'notes', operation: 'update' } } })]);
  const scoped = await run([scripted()], twoWindows);
  assert.equal(scoped.results[1].verdict, 'unobservable');
  const widened = structuredClone(scoped); widened.windows['mid>after'][0].scope.names.push('notes');
  rederive(widened);
  // The effect rules would now pass it; custody holds an audit-table absence at inconclusive, and the binding refuses the widened scope.
  assert.deepEqual([widened.results[1].verdict, widened.results[1].custodyReason], ['inconclusive', 'subject-writable-custody']);
  refuse(widened, 'invalid-sequence-run', 'window-observer');
  // A genuine in-process MCP proxy run (mcp-http-proxy, its own id form) validates.
  const frames = new FrameLog(); frames.push({ kind: 'open', conn: 'c1' });
  const proxyCalls = sequence([refundsNone({ effect: { kind: 'effect.exists', select: { source: 'mcp-jsonrpc', name: 'refund', operation: 'tool-call' } } })]);
  const proxied = saved(await runSequence(proxyCalls, { origin: 'http://127.0.0.1:1', observers: [createMcpObserver({ instanceId: 'mcp-1', log: frames, tools: ['refund'] })],
    transport: async () => { frames.push({ kind: 'call', conn: 'c1', id: 1, tool: 'refund', actor: 'agent', argsDigest: null }); frames.push({ kind: 'result', conn: 'c1', id: 1, isError: false, rpcErrorCode: null, httpStatus: 200 }); return { status: 200 }; } }));
  // MCP traffic is the target's own instrumentation: in a boundary assertion its presence is held at inconclusive by custody.
  assert.deepEqual([proxied.observers[0].kind, proxied.results[0].verdict, proxied.results[0].custodyReason], ['mcp-http-proxy', 'inconclusive', 'subject-writable-custody']);
  validateSequenceRun(proxied, { expectedSequence: proxyCalls });
  // The gate's and the MCP proxy's own id forms are accepted; a factory id is not theirs.
  const gate = await run([scripted({ kind: 'hold-gate', source: 'hold-proxy', instanceId: 'gate-1', names: ['model'] }), scripted({ instanceId: 'sqlite-audit-1' })]);
  validateSequenceRun(gate);
  const borrowed = structuredClone(gate); borrowed.observers[0].instanceId = 'sqlite-audit-gate';
  for (const w of borrowed.windows['before>after']) if (w.source === 'hold-proxy') w.instanceId = 'sqlite-audit-gate';
  refuse(rederive(borrowed), 'invalid-sequence-run', 'observers');
});

test('a declared scope must be the one its kind declares (operations, attribution, evidence)', async () => {
  // A genuine gate run cannot see a database update. Widened to "update" and "refunds" on every window it would pass.
  const gateRun = await run([scripted({ kind: 'hold-gate', source: 'hold-proxy', instanceId: 'gate-1', names: ['model', 'ungated'] })]);
  assert.equal(gateRun.results[0].verdict, 'unobservable');
  validateSequenceRun(gateRun, { expectedSequence: sequence() });
  const widen = (r, edit) => { const x = structuredClone(r); edit(x.observers[0].scope); for (const ws of Object.values(x.windows)) ws[0].scope = structuredClone(x.observers[0].scope); return rederive(x); };
  const widened = widen(gateRun, s => { s.operations.push('update'); s.names.push('refunds'); });
  assert.equal(widened.results[0].verdict, 'pass');
  refuse(widened, 'invalid-sequence-run', 'observer-scope', { expectedSequence: sequence() });
  // Each part on its own: the gate's attribution or evidence; an audit table without update or with no attribution.
  const audit = await run([scripted()]);
  validateSequenceRun(audit);
  for (const [label, base, edit] of [['gate attribution', gateRun, s => { s.actorAttribution = 'principal'; }], ['gate evidence', gateRun, s => { s.evidence = 'presence-only'; }],
    ['audit table without update', audit, s => { s.operations = ['tool-call']; }], ['audit table attribution', audit, s => { s.actorAttribution = 'none'; }]]) {
    refuse(widen(base, edit), 'invalid-sequence-run', 'observer-scope', undefined, label);
  }
  // An audit table may declare other mapped operations besides update.
  validateSequenceRun(widen(audit, s => { s.operations = ['delete', 'update']; }));
});

test('windows the runner never stores are refused: in-flight complete, net-only or exact entries outside a snapshot, a failure reason on net-only', async () => {
  // Complete coverage with an action still in flight (collectWindow would make it partial).
  const inflight = await run([scripted({ plan: () => [{ outcome: 'started' }] })]);
  assert.equal(inflight.windows['before>after'][0].coverage, 'partial');
  validateSequenceRun(inflight);
  const complete = structuredClone(inflight); Object.assign(complete.windows['before>after'][0], { coverage: 'complete', reason: null });
  refuse(rederive(complete), 'invalid-sequence-run', 'window-coverage');
  const reasoned = await run([scripted()]);
  const withReason = structuredClone(reasoned); withReason.windows['before>after'][0].reason = 'anything';
  refuse(rederive(withReason), 'invalid-sequence-run', 'window-coverage');
  const failedNoReason = structuredClone(reasoned); Object.assign(failedNoReason.windows['before>after'][0], { coverage: 'failed', reason: null });
  refuse(rederive(failedNoReason), 'invalid-sequence-run', 'window-coverage');
  // A field collectWindow never writes.
  const extraField = structuredClone(reasoned); extraField.windows['before>after'][0].lineage = { anything: true };
  refuse(reseal(extraField), 'invalid-sequence-run', 'window-fields');
  // net-only is a snapshot's net change; an audit table never stores it.
  const netOnly = structuredClone(reasoned); Object.assign(netOnly.windows['before>after'][0], { coverage: 'net-only', reason: 'net-change-between-snapshots' });
  refuse(rederive(netOnly), 'invalid-sequence-run', 'window-coverage');
});

test('the aborted code and the assertions follow the runner and sequence rules, also without --sequence', async () => {
  const r = await run([scripted()]);
  for (const aborted of ['', 'not a code!', 'x'.repeat(201)]) { const a = structuredClone(r); a.aborted = aborted; refuse(rederive(a), 'invalid-sequence-run', 'aborted'); }
  const stopped = structuredClone(r); stopped.aborted = 'precondition-failed:ask';
  rederive(stopped); assert.equal(stopped.results[0].verdict, 'missing'); validateSequenceRun(stopped);
  for (const [label, edit] of [['empty corroborate', a => { a.corroborate = []; }], ['unknown severity', a => { a.severity = 'whatever'; }],
    ['a mark id outside the sequence id pattern', a => { a.from = 'a.b:c'; }], ['the same from and to mark', a => { a.from = a.to; }]]) {
    const x = structuredClone(r); edit(x.assertions[0]);
    x.windows = { [`${x.assertions[0].from}>${x.assertions[0].to}`]: r.windows['before>after'] };
    refuse(rederive(x), 'invalid-sequence-run', 'assertions', undefined, label);
  }
  // Duplicate assertion ids: refused in the run, and the runner refuses such a sequence before it starts.
  const twice = sequence([refundsNone({ id: 'A' }), refundsNone({ id: 'A', title: 'again' })]);
  assert.throws(() => validateSequence(twice), /declared twice/);
});

test('genuine snapshot runs with exact entries validate (Postgres xmin, SQLite change-column), and their method is bound to the kind', async t => {
  // Postgres: a pg-snapshot observer over the scripted server; the named row unchanged, so absence is exact.
  const env = { SCOPEHAVEN_TARGET_DB_READER: `${USER}:${PASSWORD}` };
  const state = (snapshot) => ({ snapshot, tables: { Chat: [['c1', '700', 'h1']] } });
  const server = await scriptedDb(t, [state('800:800:'), state('800:800:'), state('800:800:'), state('805:805:')]);
  const pg = createPgSnapshotObserver({ instanceId: 'pg-snapshot-db', env, host: '127.0.0.1', port: server.port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables: [{ table: 'Chat', key: 'id' }], watchedResources: ['Chat/c1'] });
  const chatNone = sequence([refundsNone({ id: 'NO-CHAT-UPDATE', effect: { kind: 'effect.none', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', resource: 'Chat/c1' } } })]);
  const pgRun = saved(await runSequence(chatNone, { origin: 'http://127.0.0.1:1', observers: [pg], transport, env }));
  const pgWindow = pgRun.windows['before>after'][0];
  // Exact absence by coverage; the snapshot reads the app's own store, so custody holds it at inconclusive.
  assert.deepEqual([pgWindow.coverage, pgWindow.exact?.[0]?.method, pgRun.results[0].verdict, pgRun.results[0].custodyReason], ['net-only', 'xmin', 'inconclusive', 'subject-writable-custody']);
  assert.equal(pgRun.observers[0].kind, 'postgres-snapshot-diff');
  validateSequenceRun(pgRun, { expectedSequence: chatNone });
  // A snapshot window keeps its coverage, reason and exact entries as collectWindow stored them.
  for (const [label, edit] of [['net-only with a failure reason', w => { w.reason = 'key-type-refused'; }], ['exact entries on a complete window', w => { w.coverage = 'complete'; w.reason = null; }]]) {
    const x = structuredClone(pgRun); edit(x.windows['before>after'][0]);
    refuse(rederive(x), 'invalid-sequence-run', 'window-coverage', undefined, label);
  }
  // A snapshot relabelled with principal attribution claims to see who wrote a row, which it cannot.
  const principal = structuredClone(pgRun); principal.observers[0].scope.actorAttribution = 'principal';
  for (const w of principal.windows['before>after']) w.scope.actorAttribution = 'principal';
  refuse(rederive(principal), 'invalid-sequence-run', 'observer-scope');
  // The same xmin window attributed to a SQLite kind.
  const asSqlite = structuredClone(pgRun); asSqlite.observers[0].kind = 'sqlite-snapshot-diff'; asSqlite.observers[0].instanceId = 'sqlite-snapshot-db';
  for (const w of asSqlite.windows['before>after']) w.instanceId = 'sqlite-snapshot-db';
  refuse(rederive(asSqlite), 'invalid-sequence-run', 'window-observer');
  // SQLite: a change-column snapshot of an unchanged table.
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seqrun-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'app.db'), audit = join(dir, 'AUDIT.txt'); writeFileSync(audit, 'audited\n');
  const db = new DatabaseSync(path); db.exec("CREATE TABLE refunds (id TEXT PRIMARY KEY, amount INT, updated_at INT); INSERT INTO refunds VALUES ('r1', 5, 1000)"); db.close();
  const snap = createSqliteSnapshotObserver({ instanceId: 'sqlite-snapshot-db', path, tables: [{ table: 'refunds', key: 'id', changeColumn: { column: 'updated_at', unit: 'seconds', audit } }], changeColumnSkewMs: 50, maxCommitLagMs: 0, watchedResources: ['refunds/r1'] });
  const rowNone = sequence([refundsNone({ effect: { kind: 'effect.none', select: { source: 'sql-snapshot', name: 'refunds', operation: 'update', resource: 'refunds/r1' } } })]);
  const sqRun = saved(await runSequence(rowNone, { origin: 'http://127.0.0.1:1', observers: [snap], transport }));
  assert.deepEqual([sqRun.windows['before>after'][0].exact?.[0]?.method ?? 'change-column', sqRun.observers[0].kind], ['change-column', 'sqlite-snapshot-diff']);
  validateSequenceRun(sqRun, { expectedSequence: rowNone });
  // Relabelled as Postgres with quiescent xmin entries, keeping the SQLite instance id.
  const asPg = structuredClone(sqRun); asPg.observers[0].kind = 'postgres-snapshot-diff';
  for (const w of asPg.windows['before>after']) w.exact = w.exact.map(e => ({ name: e.name, method: 'xmin', auditSha256: null, ambiguousResources: [], presentResources: e.presentResources, violated: false, basis: 'xmin', marks: { startXmax: '800', endXmax: '800', inProgress: 0 }, quiescent: true }));
  refuse(rederive(asPg), 'invalid-sequence-run', 'observers');
});

test('a genuine MySQL snapshot run with a change-column entry validates; its kind and method are bound', async t => {
  const env = { SCOPEHAVEN_TARGET_MYSQL: `${MYSQL_USER}:${MYSQL_PASSWORD}` };
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seqrun-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const audit = join(dir, 'AUDIT.txt'); writeFileSync(audit, 'checked\n');
  const state = { now: '2026-10-06 12:00:00.000000', tables: { notes: [['n1', '2026-10-06 10:00:00.000000', 'h1']] } };
  const server = await scriptedMysql(t, [state, state, state, state]);
  const my = createMysqlSnapshotObserver({ instanceId: 'mysql-snapshot-db', env, host: '127.0.0.1', port: server.port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_MYSQL',
    tables: [{ table: 'notes', key: 'id', changeColumn: { column: 'updated_at', audit } }], maxCommitLagMs: 1000, watchedResources: ['notes/n1'] });
  const noteNone = sequence([refundsNone({ id: 'NO-NOTE-UPDATE', effect: { kind: 'effect.none', select: { source: 'sql-snapshot', name: 'notes', operation: 'update', resource: 'notes/n1' } } })]);
  const r = saved(await runSequence(noteNone, { origin: 'http://127.0.0.1:1', observers: [my], transport, env }));
  const w = r.windows['before>after'][0];
  // Exact absence by coverage; the snapshot reads the app's own store, so custody holds it at inconclusive.
  assert.deepEqual([r.observers[0].kind, w.coverage, w.exact?.[0]?.method ?? 'change-column', r.results[0].verdict, r.results[0].custodyReason], ['mysql-snapshot-diff', 'net-only', 'change-column', 'inconclusive', 'subject-writable-custody']);
  validateSequenceRun(r, { expectedSequence: noteNone });
  // Its change-column entries relabelled as Postgres row versions, on a MySQL kind.
  const asXmin = structuredClone(r);
  for (const x of asXmin.windows['before>after']) x.exact = x.exact.map(e => ({ name: e.name, method: 'xmin', auditSha256: null, ambiguousResources: [], presentResources: e.presentResources, violated: false, basis: 'xmin', marks: { startXmax: '800', endXmax: '800', inProgress: 0 }, quiescent: true }));
  refuse(rederive(asXmin), 'invalid-sequence-run', 'window-observer');
});

test('a run with 16 observers and the gate validates; a programmatic assertion with an undefined field validates once saved', async () => {
  const many = Array.from({ length: 16 }, (_, i) => scripted({ instanceId: `sqlite-audit-${i}` }));
  const seventeen = await run([...many, scripted({ kind: 'hold-gate', source: 'hold-proxy', instanceId: 'gate-1', names: ['model'] })]);
  validateSequenceRun(seventeen);
  const eighteen = structuredClone(seventeen); eighteen.observers.push({ ...eighteen.observers[0], instanceId: 'sqlite-audit-extra' });
  for (const ws of Object.values(eighteen.windows)) ws.push({ ...ws[0], instanceId: 'sqlite-audit-extra' });
  refuse(rederive(eighteen), 'invalid-sequence-run', 'observers');
  const loose = await run([scripted()], sequence([refundsNone({ note: undefined })]));
  validateSequenceRun(saved(loose));
  // A step that throws with a code outside the aborted form is recorded as step-error, so the run still validates.
  const odd = saved(await runSequence(sequence(), { origin: 'http://127.0.0.1:1', observers: [scripted()], transport: async () => { throw Object.assign(new Error('boom'), { code: 'not a code!' }); } }));
  assert.equal(odd.aborted, 'step-error');
  validateSequenceRun(odd);
});

test('a scopehaven-sequence/1 record is reported as not recomputable, never trusted', () => {
  const old = JSON.parse(readFileSync(new URL('./fixtures/sequence-run-v1.json', import.meta.url), 'utf8'));
  refuse(old, 'not-recomputable');
});

// The sinks listen on ports the OS reports free; a bind lost to another process is retried (fixtures/free-port.mjs).
import { onFreePorts, freePorts } from '../observers/fixtures/free-port.mjs';
// Sinks: the "app" is the request step's transport, which makes one outbound charge through the egress recorder
// (proxy form) and sends one message through the SMTP sink, as an app whose clients point at the sinks would.
function charge(port) {
  return new Promise(resolve => { const req = request({ host: '127.0.0.1', port, method: 'POST', path: 'http://api.pay.example/v1/charges', headers: { host: 'api.pay.example' } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end('{"amount":100}'); });
}
function mail(port) {
  return new Promise(resolve => {
    const socket = connect(port, '127.0.0.1'), lines = ['EHLO app.example', 'MAIL FROM:<app@acme.example>', 'RCPT TO:<vip@customers.example>', 'DATA', 'Subject: hi\r\n\r\nhello\r\n.', 'QUIT'];
    let buffer = '';
    socket.on('data', chunk => { buffer += chunk; if (/\r\n$/.test(buffer) && !/^\d{3}-/m.test(buffer.split('\r\n').at(-2) ?? '')) { buffer = ''; const next = lines.shift(); if (next) socket.write(`${next}\r\n`); } });
    socket.on('close', resolve); socket.on('error', resolve);
  });
}
const sendNone = (id, source, name) => ({ id, title: `Asking never sends to ${name}`, severity: 'high', from: 'before', to: 'after', effect: { kind: 'effect.none', select: { source, name, operation: 'send' } } });
test('genuine sink runs validate (presence-only fails reproduce; a routed sink without its witness is missing); a scope outside the sinks\' is refused', async () => {
  const seq = sequence([sendNone('NO-CHARGE', 'http-egress', 'api.pay.example'), sendNone('NO-MAIL', 'smtp-capture', 'customers.example')]);
  // One sequence run on fresh ports; sinks that started before a lost bind are stopped before the retry.
  const runOn = (s, build, transportFor = () => transport) => onFreePorts(2, async (a, b) => {
    const observers = build(a, b);
    try { return saved(await runSequence(s, { origin: 'http://127.0.0.1:1', observers, transport: transportFor(a, b) })); }
    catch (error) { await Promise.all(observers.map(o => o.stop())); throw error; }
  });
  const sinks = (pay, mailPort) => [createEgressRecorder({ instanceId: 'egress-recorder-pay', port: pay, destinations: [{ host: 'api.pay.example' }], quietMs: 100 }),
    createSmtpSink({ instanceId: 'smtp-sink-mail', port: mailPort, domains: [{ domain: 'customers.example' }], quietMs: 100 })];
  const sending = (pay, mailPort) => async () => { await charge(pay); await mail(mailPort); return { status: 200 }; };
  const sent = await runOn(seq, sinks, sending);
  assert.deepEqual(sent.observers.map(o => [o.kind, o.scope.evidence]), [['http-egress-recorder', 'presence-only'], ['smtp-sink-recorder', 'presence-only']]);
  assert.deepEqual(sent.results.map(x => x.verdict), ['fail', 'fail']);
  assert.deepEqual(validateSequenceRun(sent, { expectedSequence: seq }).results.map(x => x.verdict), ['fail', 'fail']);
  const quiet = await runOn(seq, sinks);
  assert.deepEqual(validateSequenceRun(quiet, { expectedSequence: seq }).results.map(x => x.verdict), ['unobservable', 'unobservable']);
  // Routed (authoritative): a sequence sends no witness, so the window is partial and absence is never claimed.
  const routed = await runOn(sequence([sendNone('NO-CHARGE', 'http-egress', 'api.pay.example')]), routedPort => [createEgressRecorder({ instanceId: 'egress-recorder-pay', port: routedPort, routing: 'proxy', destinations: [{ host: 'api.pay.example' }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, witnessWaitMs: 0, quietMs: 100 })]);
  assert.deepEqual([routed.observers[0].scope.evidence, routed.windows['before>after'][0].coverage, routed.results[0].verdict], ['authoritative', 'partial', 'missing']);
  validateSequenceRun(routed);
  // Each part of a sink's scope on its own: operations, attribution, an evidence value no sink declares.
  const widen = (r, edit) => { const x = structuredClone(r); edit(x.observers[0].scope); for (const ws of Object.values(x.windows)) ws[0].scope = structuredClone(x.observers[0].scope); return rederive(x); };
  for (const [label, edit] of [['operations', s => { s.operations = ['send', 'update']; }], ['attribution', s => { s.actorAttribution = 'principal'; }], ['evidence', s => { s.evidence = 'exact'; }]]) {
    assert.throws(() => validateSequenceRun(widen(sent, edit)), e => ['observer-scope', 'effect-window-scope-evidence'].includes(e.detail), label);
  }
  // Out of scope, as stated in the header: presence-only edited to authoritative everywhere is a consistent edit.
  validateSequenceRun(widen(quiet, s => { s.evidence = 'authoritative'; }));
});

// ---- Event scope, configuration binding and more observer kinds ----
// A genuine SQLite audit-table run: the request step's "app" logs one mapped action (note.create, an insert) and one
// unmapped action (login, recorded as an update under a name the scope does not list).
async function auditRun(t) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seqrun-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'app.db'), db = new DatabaseSync(path);
  db.exec('CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, what TEXT)'); db.close();
  const configs = [{ id: 'db', type: 'sqlite-audit', path, principals: ['agent'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what', actions: { 'note.create': 'insert' } } }];
  const logging = async () => { const app = new DatabaseSync(path); app.exec("INSERT INTO audit (who, what) VALUES ('agent', 'note.create'), ('agent', 'login')"); app.close(); return { status: 200 }; };
  const seq = sequence([refundsNone({ id: 'NO-NOTE', effect: { kind: 'effect.none', select: { source: 'sql-audit-table', name: 'note.create', operation: 'insert' } } })]);
  return { configs, seq, run: saved(await runSequence(seq, { origin: 'http://127.0.0.1:1', observers: buildObservers(configs), transport: logging })) };
}
const everyScope = (r, edit) => { const x = structuredClone(r); edit(x.observers[0].scope); for (const ws of Object.values(x.windows)) ws[0].scope = structuredClone(x.observers[0].scope); return rederive(x); };

test('every event is one its observer could record; a narrowed scope cannot turn a recorded fail into unobservable', async t => {
  const { run: r, seq } = await auditRun(t);
  const w = r.windows['before>after'][0];
  assert.deepEqual([w.events.map(e => `${e.operation} ${e.name}`).sort(), r.observers[0].scope.names, r.results[0].verdict], [['insert note.create', 'update login'], ['note.create'], 'fail']);
  validateSequenceRun(r, { expectedSequence: seq }); // the unmapped "login" update carries a name the scope does not list, as recorded
  // Operations narrowed to update, or names narrowed to none, would read unobservable; both are refused.
  for (const [label, edit] of [['operations narrowed', sc => { sc.operations = ['update']; }], ['names narrowed', sc => { sc.names = []; }]]) {
    const x = everyScope(r, edit);
    assert.equal(x.results[0].verdict, 'unobservable', label);
    refuse(x, 'invalid-sequence-run', 'window-events', { expectedSequence: seq }, label);
  }
  // A denied action is in the scope too; an event claiming one under an unlisted name was not recorded so.
  const denied = structuredClone(r); denied.windows['before>after'][0].events.find(e => e.name === 'login').outcome = 'denied';
  refuse(rederive(denied), 'invalid-sequence-run', 'window-events');
  // Kinds that name every event from the scope (here the gate): an event under a name it does not declare.
  const gateRun = await run([scripted({ kind: 'hold-gate', source: 'hold-proxy', instanceId: 'gate-1', names: ['model', 'ungated'], plan: () => [{ operation: 'tool-call', name: 'model' }] })]);
  validateSequenceRun(gateRun);
  refuse(everyScope(gateRun, sc => { sc.names = ['ungated']; }), 'invalid-sequence-run', 'window-events');
});

test('--observers binds a run to its configuration (names included); --gate adds the gate', async t => {
  const { run: r, configs, seq } = await auditRun(t);
  validateSequenceRun(r, { expectedSequence: seq, expectedObservers: declaredObservers(configs) });
  // A names-only edit on the observer and every window is consistent, so only the configuration refuses it.
  const named = everyScope(r, sc => { sc.names = [...sc.names, 'refund.issue']; });
  validateSequenceRun(named, { expectedSequence: seq });
  refuse(named, 'unexpected-observers', undefined, { expectedSequence: seq, expectedObservers: declaredObservers(configs) });
  // A different configuration (another mapped action), a missing or an extra observer.
  const other = structuredClone(configs); other[0].audit.actions['note.delete'] = 'delete';
  refuse(r, 'unexpected-observers', undefined, { expectedObservers: declaredObservers(other) });
  refuse(r, 'unexpected-observers', undefined, { expectedObservers: [] });
  const gate = { upstream: 'http://127.0.0.1:9', rules: [{ id: 'model', method: 'POST', pathPrefix: '/v1/chat' }] };
  refuse(r, 'unexpected-observers', undefined, { expectedObservers: declaredObservers(configs, gate) });
  // The gate entry is the gate's own observer, built from gate.json and never started.
  const { instanceId, source, kind, scope } = createHoldGate(gate).observer();
  assert.deepEqual(declaredObservers(configs, gate).at(-1), { instanceId, source, kind, scope });
  assert.deepEqual(scope.names, ['model', 'ungated']);
  assert.throws(() => declaredObservers(configs, { ...gate, instanceId: 'gate-2' }), /cannot set instanceId/);
  // Building needs no credential: each credential name gets a placeholder, never the process environment.
  const httpAuditConfig = { id: 'admin', type: 'http-audit', origin: 'http://127.0.0.1:9', path: '/a', pageLimit: 100, credentialEnv: 'SCOPEHAVEN_TARGET_NOT_SET_HERE', fields: { id: '/id', actor: '/a', action: '/b' } };
  assert.throws(() => buildObservers([httpAuditConfig], { env: {} }), /not set/, 'premise: building this observer needs its credential name set');
  assert.equal(declaredObservers([httpAuditConfig])[0].kind, 'http-audit-endpoint');
  // The CLI: --validate with --observers (exit code from the verdicts), a mismatching file, and --gate alone.
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seqrun-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = (name, value) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(value)); return p; };
  const runFile = file('run.json', r), seqFile = file('seq.json', seq), obsFile = file('observers.json', configs), otherFile = file('other.json', other), gateFile = file('gate.json', gate);
  const lines = [];
  assert.equal(await main(['--validate', runFile, '--sequence', seqFile, '--observers', obsFile], { log: x => lines.push(x) }), 1);
  assert.match(lines.at(-1), /bound to the given sequence and the given observer configuration/);
  assert.equal(await main(['--validate', file('named.json', named), '--observers', obsFile], { log: x => lines.push(x) }), 2);
  assert.equal(lines.at(-1), 'Run evidence refused: unexpected-observers');
  assert.equal(await main(['--validate', runFile, '--observers', otherFile], { log: x => lines.push(x) }), 2);
  assert.equal(await main(['--validate', runFile, '--gate', gateFile], { log: x => lines.push(x) }), 2);
  assert.match(lines.at(-1), /--gate binds a run only together with --observers/);
});

test('genuine audit-log-file, http-audit-endpoint and mcp-stdio-recorder runs validate', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seqrun-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const ORIGIN = 'http://127.0.0.1:4420';
  // An audit-log file. A sequence sends no witness, so the window is partial, never complete.
  const logPath = join(dir, 'audit.log'); writeFileSync(logPath, '');
  const auditFile = createAuditFileObserver({ instanceId: 'audit-file-owui', path: logPath, origin: ORIGIN, actors: { agent: 'u-agent' }, witness: 'chat.create', settleMs: 100, quietMs: 100,
    rules: [{ name: 'knowledge.update', method: 'POST', path: '/api/v1/knowledge/{id}/update', refusedStatuses: [403] }, { name: 'chat.create', method: 'POST', path: '/api/v1/chats/new', operation: 'insert' }] });
  const kbNone = sequence([refundsNone({ id: 'NO-KB', effect: { kind: 'effect.none', select: { source: 'file-audit-log', name: 'knowledge.update' } } })]);
  const p11 = saved(await runSequence(kbNone, { origin: 'http://127.0.0.1:1', observers: [auditFile], transport }));
  assert.deepEqual([p11.observers[0].kind, p11.observers[0].scope.actorAttribution, p11.windows['before>after'][0].coverage], ['audit-log-file', 'principal', 'partial']);
  validateSequenceRun(p11, { expectedSequence: kbNone });
  // An HTTP audit endpoint the "app" appends to.
  let items = [{ id: 1, user: 'agent', action: 'login' }];
  const server = createServer((req, res) => { res.writeHead(req.headers.authorization === 'Bearer synthetic-admin' ? 200 : 401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ data: { items } })); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => server.close(resolve)));
  const httpAudit = createHttpAuditObserver({ instanceId: 'http-audit-admin', env: { SCOPEHAVEN_TARGET_ADMIN: 'synthetic-admin' }, origin: `http://127.0.0.1:${server.address().port}`, path: '/admin/audit', pageLimit: 100,
    credentialEnv: 'SCOPEHAVEN_TARGET_ADMIN', itemsPointer: '/data/items', fields: { id: '/id', actor: '/user', action: '/action' }, actions: { 'note.create': 'insert' }, principals: ['agent'] });
  const noteNone = sequence([refundsNone({ id: 'NO-NOTE', effect: { kind: 'effect.none', select: { source: 'http-audit-log', name: 'note.create', operation: 'insert' } } })]);
  const p12 = saved(await runSequence(noteNone, { origin: 'http://127.0.0.1:1', observers: [httpAudit], transport: async () => { items = [...items, { id: 2, user: 'agent', action: 'note.create' }]; return { status: 200 }; } }));
  assert.deepEqual([p12.observers[0].kind, p12.results[0].verdict], ['http-audit-endpoint', 'fail']);
  validateSequenceRun(p12, { expectedSequence: noteNone });
  // An MCP stdio recorder's log file.
  const mcpPath = join(dir, 'mcp.jsonl'), frames = new FrameLog({ path: mcpPath }); frames.push({ kind: 'open', conn: 'c' });
  const mcp = createMcpObserver({ instanceId: 'mcp-log-agent', path: mcpPath, tools: ['refund'] });
  const toolNone = sequence([refundsNone({ id: 'NO-REFUND-CALL', effect: { kind: 'effect.none', select: { source: 'mcp-jsonrpc', name: 'refund', operation: 'tool-call' } } })]);
  const p13 = saved(await runSequence(toolNone, { origin: 'http://127.0.0.1:1', observers: [mcp], transport: async () => {
    frames.push({ kind: 'call', conn: 'c', id: '1', tool: 'refund', actor: 'agent', argsDigest: null }); frames.push({ kind: 'result', conn: 'c', id: '1', isError: false, rpcErrorCode: null, httpStatus: 200 }); return { status: 200 }; } }));
  assert.deepEqual([p13.observers[0].kind, p13.results[0].verdict], ['mcp-stdio-recorder', 'fail']);
  validateSequenceRun(p13, { expectedSequence: toolNone });
});

// The configuration binding.
test('the binding is in order: the same observers declared in another order are not the run\'s', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seqrun-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'app.db'), db = new DatabaseSync(path);
  db.exec('CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, what TEXT); CREATE TABLE notes (id TEXT PRIMARY KEY, body TEXT)'); db.close();
  const configs = [{ id: 'log', type: 'sqlite-audit', path, audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what' } },
    { id: 'rows', type: 'sqlite-snapshot', path, tables: [{ table: 'notes', key: 'id' }] }];
  const r = saved(await runSequence(sequence(), { origin: 'http://127.0.0.1:1', observers: buildObservers(configs), transport }));
  validateSequenceRun(r, { expectedObservers: declaredObservers(configs) });
  refuse(r, 'unexpected-observers', undefined, { expectedObservers: declaredObservers([...configs].reverse()) });
});

test('declaredObservers builds every observer type without starting it: nothing listens, connects, or opens or creates a file', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seqrun-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const missing = join(dir, 'missing');
  const [otelPort, egressPort, smtpPort, gatePort, pgPort, mysqlPort, auditPort] = await freePorts(7);
  // Listeners on the database and audit endpoints count any connection a constructor would make.
  const connections = [];
  const listeners = await Promise.all([pgPort, mysqlPort, auditPort].map(port => new Promise(resolve => {
    const server = createNetServer(socket => { connections.push(port); socket.destroy(); }); server.listen(port, '127.0.0.1', () => resolve(server));
  })));
  t.after(() => Promise.all(listeners.map(server => new Promise(resolve => server.close(resolve)))));
  const configs = [
    { id: 'otel', type: 'otel', port: otelPort, services: ['app'] },
    { id: 'log', type: 'sqlite-audit', path: join(missing, 'audit.db'), audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what' } },
    { id: 'rows', type: 'sqlite-snapshot', path: join(missing, 'app.db'), tables: [{ table: 'notes', key: 'id' }] },
    { id: 'admin', type: 'http-audit', origin: `http://127.0.0.1:${auditPort}`, path: '/audit', pageLimit: 100, credentialEnv: 'SCOPEHAVEN_TARGET_ADMIN', fields: { id: '/id', actor: '/a', action: '/b' } },
    { id: 'tools', type: 'mcp-log', path: join(missing, 'mcp.jsonl') },
    { id: 'pg', type: 'pg-snapshot', host: '127.0.0.1', port: pgPort, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_PG', tables: [{ table: 'Chat', key: 'id' }] },
    { id: 'pay', type: 'egress-recorder', port: egressPort, destinations: [{ host: 'api.pay.example' }] },
    { id: 'mail', type: 'smtp-sink', port: smtpPort, domains: [{ domain: 'customers.example' }] },
    { id: 'my', type: 'mysql-snapshot', host: '127.0.0.1', port: mysqlPort, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_MY', tables: [{ table: 'notes', key: 'id' }] },
  ];
  const declared = declaredObservers(configs, { upstream: `http://127.0.0.1:${auditPort}`, port: gatePort, rules: [{ id: 'model', method: 'POST', pathPrefix: '/v1' }] });
  assert.deepEqual(declared.map(o => o.kind), ['otlp-http-json-receiver', 'sqlite-audit-table', 'sqlite-snapshot-diff', 'http-audit-endpoint', 'mcp-stdio-recorder',
    'postgres-snapshot-diff', 'http-egress-recorder', 'smtp-sink-recorder', 'mysql-snapshot-diff', 'hold-gate']);
  // An audit-log file needs a witness a sequence never sends, so it is refused, as at run time.
  assert.throws(() => declaredObservers([{ id: 'file', type: 'audit-file', path: join(missing, 'audit.log') }]), /audit-file/);
  // Nothing was created where a database, recorder log or audit file would be...
  assert.deepEqual(readdirSync(dir), []);
  // ...nothing listens on the receiver's, the sinks' or the gate's port...
  for (const port of [otelPort, egressPort, smtpPort, gatePort]) {
    await new Promise((resolve, reject) => { const server = createNetServer(); server.once('error', reject); server.listen(port, '127.0.0.1', () => server.close(resolve)); });
  }
  // ...and nothing connected to the databases or the audit endpoint.
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.deepEqual(connections, []);
});
