// pg-wal in profiles (integrations/observers/pg-wal.mjs, docs/PG-WAL.md): a profile observer type with a source of its own
// (sql-wal: lineage database-log, custody observer-held), so a database-only prohibition on a Postgres target can reach a verdict
// through an authoritative observer. Through runHttpAssessment and the shared validator, against pg-wal's scripted session (no server).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { runHttpAssessment, HTTP_EVALUATOR_HASH } from '../src/http-connector.mjs';
import { compareRuns } from '../src/runner.mjs';
import { renderReport, settlementDeclarationsHtml } from '../src/report.mjs';
import { collectWindow, validateWindow, validWireDeclaration } from '../src/effect-events.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { COLLECTOR_RECORDS } from '../src/collector-identity.mjs';
import { OBSERVER_OUTPUT, observerInstanceId, decideEffects, recomputeEffectTrace } from '../src/http-effects.mjs';
import { CUSTODY_BY_SOURCE, clauseCustody, onlyClauseCustody, custodyUpgrade, onlyCustodyUpgrade, PRINCIPAL_REASON, CUSTODY_REASON } from '../src/custody.mjs';
import { channelDeclarationProblem, rowChannelState, CHANNEL_OBSERVERS, CHANNELS_UNDECLARED } from '../src/channels.mjs';
import { LINEAGE_BY_SOURCE } from '../src/effect-lineage.mjs';
import { contactedEndpoints } from '../src/authorization.mjs';
import { MODELLED_OBSERVER_TYPES, observerScopes } from '../src/known-negative.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { createPgWalObserver, PG_WAL_SOURCE } from '../integrations/observers/pg-wal.mjs';
import { fakeServer, row as walRow } from '../integrations/observers/fixtures/fake-pg-wal.mjs';
import recordedAtMain from './fixtures/pre-pgwal-run-9d2e44a6.mjs';
import recordedBeforeWire from './fixtures/pre-pgnet-run-8ecfe737.mjs';

const TOKEN = 'synthetic-bob-token', env = { SCOPEHAVEN_TARGET_BOB: TOKEN, SCOPEHAVEN_TARGET_WAL: 'wal_reader:pw' };
const walObserver = (extra = {}) => ({ id: 'wal', type: 'pg-wal', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_WAL', settleMs: 250,
  tables: [{ table: 'orders', key: 'id', values: ['status', 'amount'] }], platform: 'supabase', barrierMs: 100, ...extra });
const profile = (origin, observers) => ({ id: 'refunds', name: 'Refunds', applicationId: 'refunds-app', origin, buildLabel: 'b1', contextId: 'synthetic-refunds',
  actors: { bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } }, requiredControlIds: ['WHOAMI'], observers,
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'bob', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'bob' }] },
    // The allowed-use twin (pairing): bob's own refund, which the WAL observer is shown to see, so the absence below can pass.
    { id: 'REFUND', title: 'Bob refunds order a', category: 'allowed-use', severity: 'control', actorId: 'bob', method: 'PATCH', path: '/orders/a/refund', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { source: 'sql-wal', name: 'orders', operation: 'update', resource: 'orders/a' } }] },
    { id: 'NO-REFUND-ON-READ', title: 'Reading an order refunds nothing (database only)', category: 'object-access', severity: 'high', actorId: 'bob', method: 'GET', path: '/orders/a', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: { source: 'sql-wal', name: 'orders', operation: 'update', resource: 'orders/a' } }] },
  ] });
const load = target => validateTargetFile({ schemaVersion: 1, targets: [target] })[0];
async function app(t, onRead, onRefund) {
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return reply(401, {});
    if (req.url === '/me') return reply(200, { user: 'bob' });
    if (req.url === '/orders/a') { onRead(); return reply(200, { id: 'a' }); }
    if (req.method === 'PATCH' && req.url === '/orders/a/refund') { onRefund(); return reply(200, { ok: true }); }
    reply(404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
// The connector's observers over pg-wal's scripted session: the profile's own declarations, the session as the connect seam.
const factoryOver = s => (configs, { env: e }) => configs.map(c => Object.assign(createPgWalObserver({ instanceId: observerInstanceId(c.type, c.id), env: e, host: c.host, port: c.port, database: c.database,
  credentialEnv: c.credentialEnv, tables: c.tables, platform: c.platform, barrierMs: c.barrierMs, connect: s.connect }), { postResponseSettleMs: c.settleMs }));
async function assess(t, onRead) {
  const refund = () => s.commit([['declared', walRow('UPDATE', " id[text]:'a' status[text]:'refunded' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")]]);
  const s = fakeServer(), origin = await app(t, () => onRead(s), refund), p = profile(origin, [walObserver()]);
  // The real factory runs first on the options the connector passes (it builds, never connects), so its opt-in is the connector's.
  const run = await runHttpAssessment(p, { env, observerFactory: (configs, options) => { buildObservers(configs, options); return factoryOver(s)(configs, options); } });
  return { run, p, row: run.results.find(r => r.id === 'NO-REFUND-ON-READ') };
}

test('pg-wal is a profile observer type with its own source: lineage database-log, custody observer-held', () => {
  assert.deepEqual(OBSERVER_OUTPUT['pg-wal'], { source: 'sql-wal', kind: 'postgres-wal-decode' });
  assert.equal(PG_WAL_SOURCE, 'sql-wal');
  assert.deepEqual([LINEAGE_BY_SOURCE['sql-wal'], CUSTODY_BY_SOURCE['sql-wal']], ['database-log', 'observer-held']);
  // The database snapshot keeps the app's own store's custody.
  assert.equal(CUSTODY_BY_SOURCE['sql-snapshot'], 'subject-writable');
  // The authorization record lists its endpoint; the self-test models it (complete coverage).
  const p = load(profile('http://127.0.0.1:4000', [walObserver()]));
  assert.ok(contactedEndpoints(p).includes('tcp://127.0.0.1:5432'));
  assert.ok(MODELLED_OBSERVER_TYPES.includes('pg-wal'));
  assert.deepEqual(observerScopes(p).map(m => [m.instanceId, m.source]), [['pg-wal-wal', 'sql-wal']]);
});

test('a pg-wal observer\'s profile shape: loopback, plain identifiers, value columns, the barrier and the background-writer options', () => {
  assert.doesNotThrow(() => load(profile('http://127.0.0.1:4000', [walObserver({ ignore: ['public.heartbeats'], queues: [{ table: 'jobs' }], drainTimeoutMs: 2000, pollMs: 50, runLease: true, statementTimeoutMs: 5000 })])));
  const reject = (extra, pattern) => assert.throws(() => load(profile('http://127.0.0.1:4000', [walObserver(extra)])), pattern, JSON.stringify(extra));
  reject({ password: 'x' }, /a pg-wal observer is \{ id, type, host/);
  reject({ host: 'localhost' }, /literal loopback address/);
  reject({ database: 'app db' }, /plain identifier/);
  reject({ credentialEnv: 'PGPASSWORD' }, /SCOPEHAVEN_TARGET_/);
  reject({ tables: [{ table: 'orders', key: 'id', values: ['status; DROP'] }] }, /"tables" lists 1 to 32/);
  reject({ tables: [{ table: 'orders', key: 'id' }, { table: 'orders', key: 'id', schema: 'billing' }] }, /each table name is declared once per pg-wal observer/);
  reject({ barrierMs: 50 }, /"barrierMs" must be an integer from 100 to 30000/);
  reject({ statementTimeoutMs: 90000 }, /"statementTimeoutMs" must be an integer from 500 to 60000/);
  reject({ platform: 'litestream' }, /"platform" is "none" or "supabase"/);
  reject({ ignore: ['a.b.c'] }, /"ignore" lists at most 64/);
  reject({ queues: Array.from({ length: 9 }, (_, i) => ({ table: `q${i}` })) }, /"queues" lists 1 to 8/);
  reject({ pollMs: 50 }, /declare "queues"/);
  reject({ runLease: 'yes' }, /"runLease" is true or false/);
  reject({ credentialEnv: 'SCOPEHAVEN_TARGET_BOB' }, /the REPLICATION role's own, never an actor's credential/);
  reject({ actorCapture: { block: { testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', tables: [{ table: 'orders', key: 'id' }], actor: { from: 'jwt-claims' }, principals: { s: 'eve' } }, installedSha256: 'a'.repeat(64) } }, /principalId of a declared actor/);
  // pg_net on the wire (integrations/observers/pg-net-wire.mjs): the database container and the witness role's own credential.
  // The tap's image is required and named by digest only (never pulled).
  const wire = { container: 'supabase_db_copy', credentialEnv: 'SCOPEHAVEN_TARGET_PGNET', image: 'python@sha256:' + 'a'.repeat(64) };
  assert.doesNotThrow(() => load(profile('http://127.0.0.1:4000', [walObserver({ pgNetWire: wire })])));
  assert.doesNotThrow(() => load(profile('http://127.0.0.1:4000', [walObserver({ pgNetWire: { ...wire, witnessWaitMs: 5000, quietMs: 1500 } })])));
  assert.doesNotThrow(() => load(profile('http://127.0.0.1:4000', [walObserver({ pgNetWire: { ...wire, programRoles: ['supabase_admin', 'postgres'] } })])));
  assert.doesNotThrow(() => load(profile('http://127.0.0.1:4000', [walObserver({ pgNetWire: { ...wire, programRoles: ['supabase_admin'], requestRoles: ['anon', 'authenticated', 'authenticator', 'service_role'] } })])));
  for (const bad of [{ ...wire, container: 'db; rm' }, { ...wire, credentialEnv: 'PGPASSWORD' }, { ...wire, image: 'Bad Image' }, { ...wire, image: 'python:3.12-slim' }, { ...wire, image: undefined }, { ...wire, witnessWaitMs: 10 }, { ...wire, quietMs: 20000 },
    { ...wire, mounts: ['/'] }, { container: 'supabase_db_copy' }, 'supabase_db_copy',
    { ...wire, programRoles: [] }, { ...wire, programRoles: 'supabase_admin' }, { ...wire, programRoles: ['a', 'a'] }, { ...wire, programRoles: ['bad-name'] },
    { ...wire, programRoles: Array.from({ length: 17 }, (_, i) => `r${i}`) }, { ...wire, requestRoles: [] }, { ...wire, requestRoles: ['(PUBLIC)'] }, { ...wire, requestRoles: ['a', 'a'] }])
    reject({ pgNetWire: bad }, /"pgNetWire" is \{ container, credentialEnv/);
  reject({ pgNetWire: { ...wire, credentialEnv: 'SCOPEHAVEN_TARGET_WAL' } }, /the witness role's own, never an actor's, the REPLICATION role's or another observer's/);
  reject({ pgNetWire: { ...wire, credentialEnv: 'SCOPEHAVEN_TARGET_BOB' } }, /the witness role's own, never an actor's, the REPLICATION role's or another observer's/);
  // Nor another observer's: a second pg-wal observer's REPLICATION credential.
  assert.throws(() => load(profile('http://127.0.0.1:4000', [walObserver({ pgNetWire: { ...wire, credentialEnv: 'SCOPEHAVEN_TARGET_WAL2' } }), walObserver({ id: 'wal2', credentialEnv: 'SCOPEHAVEN_TARGET_WAL2' })])),
    /the witness role's own, never an actor's, the REPLICATION role's or another observer's/);
  // pg-snapshot takes the same background-writer options from a profile now.
  const snapshot = { id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_WAL', tables: [{ table: 'orders', key: 'id' }], settleMs: 250 };
  assert.doesNotThrow(() => load(profile('http://127.0.0.1:4000', [{ ...snapshot, platform: 'supabase', queues: [{ table: 'jobs' }], runLease: true }])));
  assert.throws(() => load(profile('http://127.0.0.1:4000', [{ ...snapshot, platform: 'mysql' }])), /"platform" is "none" or "supabase"/);
});

test('the factory builds pg-wal as declared, and passes pg-snapshot its background-writer options', () => {
  // Only a caller that pairs and validates pg-wal windows (the HTTP connector) is given one; sequences are refused.
  assert.throws(() => buildObservers([walObserver()], { env }), /pg-wal is built only for an HTTP assessment's observers/);
  const [wal] = buildObservers([walObserver()], { env, pgWal: true });
  assert.deepEqual([wal.instanceId, wal.source, wal.kind, wal.scope.actorAttribution, wal.postResponseSettleMs], ['pg-wal-wal', 'sql-wal', 'postgres-wal-decode', 'none', 250]);
  // The observer's own rules run at build: an ignore entry naming an observed table is refused (the option reached it).
  assert.throws(() => buildObservers([walObserver({ ignore: ['public.orders'] })], { env, pgWal: true }), /ignore/i);
  // Each declared key reaches the observer: its own refusal at build shows it was passed.
  const builds = (type, extra) => () => buildObservers([type === 'pg-wal' ? walObserver(extra) : { id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_WAL', tables: [{ table: 'orders', key: 'id' }], ...extra }], { env, pgWal: true });
  for (const type of ['pg-wal', 'pg-snapshot']) {
    assert.doesNotThrow(builds(type, { queues: [{ table: 'jobs' }] }), type);
    assert.throws(builds(type, { queues: [{ table: 'jobs' }], ignore: ['public.jobs'] }), /queue|ignore/i, `${type}: queues reach it`);
    assert.throws(builds(type, { platform: 'bogus' }), /platform|Unknown/i, `${type}: platform reaches it`);
    assert.throws(builds(type, { queues: [{ table: 'jobs' }], drainTimeoutMs: 999999 }), /drainTimeoutMs/, `${type}: drainTimeoutMs reaches it`);
    assert.throws(builds(type, { queues: [{ table: 'jobs' }], pollMs: 1 }), /pollMs/, `${type}: pollMs reaches it`);
  }
  assert.throws(builds('pg-wal', { barrierMs: 5 }), /barrierMs/);
  assert.throws(builds('pg-wal', { statementTimeoutMs: 5 }), /statementTimeoutMs/);
  assert.throws(() => buildObservers([{ id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_WAL', tables: [{ table: 'orders', key: 'id' }], ignore: ['public.orders'] }], { env }), /ignore/i);
});

test('a database-only prohibition on Postgres passes on the WAL observer when nothing changed, and fails when the app writes', async t => {
  const quiet = await assess(t, () => {});
  validateHttpRunEvidence(quiet.run, { expectedSuite: createRegistry({ profiles: [quiet.p], env }).exportSuite(quiet.p.id) });
  const [clause] = quiet.row.trace[1].data.effects, [w] = quiet.row.trace[1].data.windows;
  assert.deepEqual([quiet.row.status, quiet.row.backendEvidence, clause.verdict, clause.custody], ['pass', 'observed', 'pass', 'observer-held']);
  assert.equal(quiet.run.results.find(r => r.id === 'REFUND').status, 'pass', 'the twin shows the observer sees such a write');
  assert.deepEqual([w.source, w.coverage, w.lineage], ['sql-wal', 'complete', { observer: 'postgres-wal-decode', independence: 'database-log' }]);
  assert.deepEqual(quiet.run.observers[0].collector, COLLECTOR_RECORDS['pg-wal']);
  assert.ok(quiet.run.limitations.some(l => l.startsWith('Postgres WAL observers (wal)')));
  // The defective twin refunds on a read: the write is decoded from the WAL and the prohibition fails.
  const written = await assess(t, s => { s.commit([['declared', walRow('UPDATE', " id[text]:'a' status[text]:'refunded' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")]]); });
  validateHttpRunEvidence(written.run);
  assert.deepEqual([written.row.status, written.row.trace[1].data.effects[0].verdict], ['fail', 'fail']);
  assert.deepEqual(written.row.trace[1].data.windows[0].events.map(e => [e.source, e.operation, e.resource]), [['sql-wal', 'update', 'orders/a']]);
  // A sealed window relabelled to the snapshot source no longer binds to the declared observer: refused.
  const forged = structuredClone(quiet.run), r = forged.results.find(x => x.id === 'NO-REFUND-ON-READ');
  r.trace[1].data.windows[0].source = 'sql-snapshot'; r.trace[1].data.windows[0].lineage.independence = 'application-store';
  r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions });
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
});

// sql-wal's custody holds for an absence only, and no observer names an acting principal from outside the
// application, so a boundary pass resting on either reads inconclusive with its reason; a fail stays a fail, a control keeps its verdict.
test('custody on the WAL: an absence passes observer-held; a presence pass and an actor-pinned pass do not', () => {
  const window = (events = [], attribution = 'none') => ({ source: 'sql-wal', instanceId: 'pg-wal-wal', scope: { operations: ['insert', 'update', 'delete'], names: ['orders'], actorAttribution: attribution, evidence: 'authoritative' },
    coverage: 'complete', reason: null, events });
  const event = actor => ({ schema: 'scopehaven-effect/1', source: 'sql-wal', observer: { kind: 'postgres-wal-decode', instanceId: 'pg-wal-wal' }, seq: 1, observedAt: '2026-10-25T00:00:00.000Z', actor, operation: 'update', name: 'orders', resource: 'orders/a', outcome: 'committed', content: null, correlation: {} });
  const select = { source: 'sql-wal', name: 'orders', operation: 'update', resource: 'orders/a' };
  const custody = (kind, verdict, windows, extra = {}, role = 'boundary', expected) => clauseCustody({ kind, select: { ...select, ...extra }, verdict, windows, role, expected });
  assert.deepEqual(custody('effect.none', 'pass', [window()]), { verdict: 'pass', custody: 'observer-held' });
  assert.deepEqual(custody('effect.count', 'pass', [window()], {}, 'boundary', 0), { verdict: 'pass', custody: 'observer-held' });
  // A count of one or more cannot pass without showing the write, so its lower bound is the app's own.
  for (const expected of [1, undefined]) {
    const counted = custody('effect.count', 'pass', [window([event(null)])], {}, 'boundary', expected);
    assert.deepEqual([counted.verdict, counted.custody, counted.custodyReason], ['inconclusive', 'subject-writable', CUSTODY_REASON], String(expected));
  }
  // A row the app wrote itself shows that it happened, not that the app could not author it: a presence pass reads subject-writable.
  const exists = custody('effect.exists', 'pass', [window([event(null)])]);
  assert.deepEqual([exists.verdict, exists.custody, exists.custodyReason], ['inconclusive', 'subject-writable', CUSTODY_REASON]);
  assert.deepEqual(custody('effect.exists', 'fail', [window()]), { verdict: 'fail', custody: 'observer-held' });
  assert.deepEqual(custody('effect.none', 'fail', [window([event(null)])]), { verdict: 'fail', custody: 'subject-writable' });
  // An actor the capture names is the claim the app's session set: an actor-pinned absence never passes in a boundary check.
  const pinned = custody('effect.none', 'pass', [window([], 'principal')], { actor: 'bob' });
  assert.deepEqual([pinned.verdict, pinned.custodyReason], ['inconclusive', PRINCIPAL_REASON]);
  assert.match(pinned.custodyUpgrade, /names the acting principal from outside the application/);
  assert.deepEqual(custody('effect.none', 'pass', [window([], 'principal')], { actor: 'bob' }, 'control'), { verdict: 'pass', custody: 'observer-held' });
  assert.equal(custody('effect.none', 'fail', [window([event('bob')], 'principal')], { actor: 'bob' }).verdict, 'fail');
  // A window held outside the app that names principals itself keeps the pass (pairing, settlement and timing read
  // such windows), beside the WAL or alone; the rule reaches only actor names the capture supplies (CAPTURED_ACTOR_SOURCES).
  const named = { source: 'http-egress', instanceId: 'egress-recorder-egress', scope: { operations: ['send'], names: ['api.stripe.com'], actorAttribution: 'principal', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] };
  const SENT = { source: 'http-egress', operation: 'send', name: 'api.stripe.com', actor: 'bob' };
  assert.deepEqual(clauseCustody({ kind: 'effect.none', select: SENT, verdict: 'pass', windows: [named], role: 'boundary' }), { verdict: 'pass', custody: 'independent' });
  const both = clauseCustody({ kind: 'effect.none', select: { operation: 'update', actor: 'bob' }, verdict: 'pass', windows: [window([], 'principal'), { ...named, scope: { ...named.scope, operations: ['insert', 'update', 'delete', 'send'] } }], role: 'boundary' });
  assert.deepEqual([both.verdict, both.custody], ['pass', 'independent'], 'a held window that names principals decides beside the WAL');
  // effect.only through the HTTP path (decideEffects). It cannot pass without its expected effects: one the WAL window holds is the
  // app's own write, an actor-pinned one included. Expecting a send another observer holds, the WAL decides only the
  // absence of other writes, which holds, unless an allowed selector pins an actor (principal-unverified).
  const { content, ...sealed } = event('bob');
  const wal = (events = []) => window(events.map(e => ({ ...e, contentDigest: null })), 'principal');
  const only = (expectSelect, allow = [], windows = [wal([sealed])]) => decideEffects([{ kind: 'effect.only', expect: [{ select: expectSelect, count: 1 }], allow }], windows)[0];
  for (const expectSelect of [select, { ...select, actor: 'bob' }]) {
    const matched = only(expectSelect);
    assert.deepEqual([matched.verdict, matched.custody, matched.custodyReason], ['inconclusive', 'subject-writable', CUSTODY_REASON], JSON.stringify(expectSelect));
  }
  const SEND = { source: 'http-egress', operation: 'send', name: 'api.stripe.com', resource: 'POST /v1/refunds' };
  const egress = { source: 'http-egress', instanceId: 'egress-recorder-egress', scope: { operations: ['send'], names: ['api.stripe.com'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null,
    events: [{ ...sealed, source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-egress' }, actor: null, operation: 'send', name: 'api.stripe.com', resource: 'POST /v1/refunds', contentDigest: null }] };
  // Through decideEffects too: a count of 0 on the WAL is an absence and holds; a count of one that the window shows is a presence.
  const [zero] = decideEffects([{ kind: 'effect.count', select, expected: 0 }], [wal()]);
  assert.deepEqual([zero.verdict, zero.custody], ['pass', 'observer-held']);
  const [one] = decideEffects([{ kind: 'effect.count', select, expected: 1 }], [wal([sealed])]);
  assert.deepEqual([one.verdict, one.custody, one.custodyReason], ['inconclusive', 'subject-writable', CUSTODY_REASON]);
  const sendOnly = only(SEND, [], [wal(), egress]);
  assert.deepEqual([sendOnly.verdict, sendOnly.custody], ['pass', 'observer-held']);
  const allowPinned = only(SEND, [{ source: 'sql-wal', name: 'orders', operation: 'insert', actor: 'bob' }], [wal(), egress]);
  assert.deepEqual([allowPinned.verdict, allowPinned.custody, allowPinned.custodyReason], ['inconclusive', 'observer-held', PRINCIPAL_REASON]);
  // An expected send pinned to an actor, on an egress window that names principals itself: no capture supplies the names, so it stands.
  const expectPinned = only({ ...SEND, actor: 'bob' }, [], [{ ...egress, scope: { ...egress.scope, actorAttribution: 'principal' }, events: egress.events.map(e => ({ ...e, actor: 'bob' })) }]);
  assert.deepEqual([expectPinned.verdict, expectPinned.custody], ['pass', 'independent']);
  // A pin no window in scope could match (no window names principals) decides nothing: the pass stands (as in test/app-log-admission.test.mjs).
  const unmatchable = only(SEND, [{ source: 'http-egress', operation: 'send', name: 'api.stripe.com', resource: 'POST /other', actor: 'svc-sync' }], [egress]);
  assert.deepEqual([unmatchable.verdict, unmatchable.custody], ['pass', 'independent']);
});

test('a boundary presence on the WAL is not satisfied by a row the app stamped itself, through the connector', async t => {
  const STAMP = { source: 'sql-wal', name: 'orders', operation: 'update', resource: 'orders/a' };
  // The forms a presence takes: effect.exists, effect.count of one, and effect.only expecting the write beside that count.
  for (const [form, effects] of [['exists', [{ kind: 'effect.exists', select: STAMP }]], ['count', [{ kind: 'effect.count', select: STAMP, expected: 1 }]],
    ['only', [{ kind: 'effect.only', expect: [{ select: STAMP, count: 1 }], allow: [] }, { kind: 'effect.count', select: STAMP, expected: 1 }]]]) {
    const s = fakeServer(), stamp = () => s.commit([['declared', walRow('UPDATE', " id[text]:'a' status[text]:'verified' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")]]);
    const origin = await app(t, () => stamp(), () => {});
    const p = profile(origin, [walObserver()]);
    p.checks = [p.checks[0], { id: 'VERIFY-FIRST', title: 'A refund is preceded by its verification record', category: 'object-access', severity: 'high', actorId: 'bob', method: 'GET', path: '/orders/a', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects }];
    const run = await runHttpAssessment(p, { env, observerFactory: factoryOver(s) });
    validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
    const r = run.results.find(x => x.id === 'VERIFY-FIRST');
    assert.equal(r.status, 'inconclusive', form);
    for (const clause of r.trace[1].data.effects) assert.deepEqual([clause.verdict, clause.custody, clause.custodyReason], ['inconclusive', 'subject-writable', CUSTODY_REASON], `${form} ${clause.kind}`);
  }
});

test('pg-wal holds a store channel\'s records', () => {
  assert.ok(CHANNEL_OBSERVERS.store.includes('pg-wal'));
  assert.equal(channelDeclarationProblem({ confinement: 'confined', list: [{ id: 'orders-db', kind: 'store', observedBy: ['wal'], names: ['orders'], port: 5432 }] }, [walObserver()]), null);
  // A stray committed insert recorded by an observer no channel lists reads channels-undeclared, under pg-wal as
  // under pg-snapshot, so a boundary absence on another channel does not pass beside it.
  const event = source => ({ schema: 'scopehaven-effect/1', source, observer: { kind: 'k', instanceId: 'x' }, seq: 1, observedAt: '2026-01-01T00:00:00.000Z', actor: null, operation: 'insert',
    name: 'refund_requests', resource: 'refund_requests/1', outcome: 'committed', correlation: {}, contentDigest: null });
  const egress = { source: 'http-egress', instanceId: 'egress-recorder-egress', scope: { operations: ['send'], names: ['api.stripe.com'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] };
  for (const [type, source] of [['pg-snapshot', 'sql-snapshot'], ['pg-wal', 'sql-wal']]) {
    const db = { source, instanceId: `${type}-db`, scope: { operations: ['insert', 'update', 'delete'], names: ['refund_requests'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [event(source)] };
    const run = { evidenceOrigin: 'local-http-response', channels: { confinement: 'unconfined', list: [{ id: 'stripe', kind: 'egress', observedBy: ['egress'], names: ['api.stripe.com'] }] },
      observers: [{ id: 'egress', type: 'egress-recorder', settleMs: 250 }, { id: 'db', type, settleMs: 250 }] };
    const row = { id: 'NO-SEND', status: 'pass', severity: 'high', trace: [{ data: {} }, { data: { windows: [egress, db], effects: [{ kind: 'effect.none', verdict: 'pass', select: { source: 'http-egress', name: 'api.stripe.com', operation: 'send' } }] } }] };
    const state = rowChannelState(run, row);
    assert.deepEqual([state.unlisted, state.reasons.includes(CHANNELS_UNDECLARED)], [[{ observer: 'db', type, count: 1 }], true], type);
  }
});

// A degraded database-write absence in an HTTP assessment names pg-wal as its upgrade, only where a Postgres
// observer's window decided it; a presence, an actor-pinned clause, a send, another engine's or an
// audit table's window, and every caller that cannot build pg-wal (sequences, collateral) keep their text.
test('a degraded database-write absence names a pg-wal observer as its upgrade only on a Postgres window; nothing else does', () => {
  const store = (instanceId, source = 'sql-snapshot') => ({ source, instanceId, scope: { operations: ['insert', 'update', 'delete'], names: ['orders'], actorAttribution: source === 'sql-audit-table' ? 'principal' : 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] });
  const pg = store('pg-snapshot-db');
  const select = { source: 'sql-snapshot', operation: 'update', name: 'orders' };
  const WAL = "For operation update, name orders: add a pg-wal observer on the table it writes and select the effect by source sql-wal and that table's name (it reads every committed write to its tables from outside the application), or accept this row as inconclusive.";
  const upgrade = (kind, sel, walObservers = true, expected, windows = [pg]) => clauseCustody({ kind, select: sel, verdict: 'pass', windows, role: 'boundary', walObservers, expected }).custodyUpgrade;
  assert.equal(upgrade('effect.none', select), WAL);
  assert.equal(upgrade('effect.count', select, true, 0), WAL);
  const none = custodyUpgrade(select);
  assert.match(none, /^No shipped observer held outside the application sees operation update/);
  assert.equal(upgrade('effect.none', select, false), none, 'a caller that cannot build pg-wal');
  assert.equal(upgrade('effect.exists', select), none, 'a presence: the WAL holds custody for an absence only');
  assert.equal(upgrade('effect.count', select, true, 1), none, 'a count of one or more is a presence too');
  assert.match(upgrade('effect.none', { ...select, actor: 'bob' }), /^No shipped observer held outside the application sees operation update, name orders, acting principal bob\./);
  assert.match(upgrade('effect.none', { operation: 'send', name: 'api.stripe.com' }), /^Add an egress recorder or SMTP sink that sees/);
  // The engine is the deciding window's: a Postgres window beside it that does not see the clause decides nothing.
  const elsewhere = { ...pg, scope: { ...pg.scope, names: ['refunds'] } }, audit = store('audit-table-audit', 'sql-audit-table'), { source: _s, ...unpinned } = select;
  assert.equal(upgrade('effect.none', unpinned, true, undefined, [audit, elsewhere]), custodyUpgrade(unpinned));
  assert.equal(upgrade('effect.none', unpinned, true, undefined, [audit, pg]), custodyUpgrade(unpinned, { wal: true }));
  // Another engine's snapshot, or an audit table, is no store pg-wal can watch.
  for (const w of [store('sqlite-snapshot-db'), store('mysql-snapshot-db'), store('audit-table-audit', 'sql-audit-table')])
    assert.equal(upgrade('effect.none', { ...select, source: w.source }, true, undefined, [w]), custodyUpgrade({ ...select, source: w.source }), w.instanceId);
  // effect.only: every held operation one the WAL reads, no actor pinned, a Postgres window in scope.
  const only = (claimedOperations, opts, windows = [pg]) => onlyClauseCustody({ result: { verdict: 'pass', observers: windows.map(w => w.instanceId), claimedOperations }, windows, role: 'boundary', ...opts }).custodyUpgrade;
  assert.equal(only(['insert', 'update'], { walObservers: true }), 'For insert, update effects: add a pg-wal observer on the tables they write and name source sql-wal in "sources" (it reads every committed write to its tables from outside the application), or accept this row as inconclusive.');
  assert.match(only(['insert', 'send'], { walObservers: true }), /, and an egress recorder or SMTP sink for the sends, or accept this row as inconclusive\.$/);
  for (const [ops, opts, windows] of [[['insert', 'update'], {}], [['insert', 'update'], { walObservers: true, pinsActor: true }], [['insert', 'tool-call'], { walObservers: true }],
    [['insert', 'update'], { walObservers: true, expect: [{ operation: 'insert', name: 'orders' }] }], [['insert', 'update'], { walObservers: true, expect: [{ name: 'orders' }] }],
    [['insert', 'update'], { walObservers: true }, [store('mysql-snapshot-db')]]])
    assert.equal(only(ops, opts, windows), onlyCustodyUpgrade(ops), JSON.stringify([ops, opts, windows?.[0]?.instanceId]));
  // The HTTP path (decideEffects, what the connector and the validator call): the effect.only expects a send (an egress recorder holds
  // it) and the store decides the absence of writes. On a Postgres snapshot both name pg-wal; on an audit table neither does.
  const sent = { schema: 'scopehaven-effect/1', source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-egress' }, seq: 1, observedAt: '2026-01-01T00:00:00.000Z',
    actor: null, operation: 'send', name: 'api.stripe.com', resource: 'POST /v1/refunds', outcome: 'committed', correlation: {}, contentDigest: null };
  const egress = { source: 'http-egress', instanceId: 'egress-recorder-egress', scope: { operations: ['send'], names: ['api.stripe.com'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [sent] };
  const clauses = source => [{ kind: 'effect.none', select: { ...select, source } }, { kind: 'effect.only', expect: [{ select: { source: 'http-egress', operation: 'send', name: 'api.stripe.com', resource: 'POST /v1/refunds' }, count: 1 }], allow: [] }];
  const [noneRow, onlyRow] = decideEffects(clauses('sql-snapshot'), [pg, egress]);
  assert.deepEqual([noneRow.verdict, noneRow.custodyUpgrade], ['inconclusive', WAL]);
  assert.equal(onlyRow.verdict, 'inconclusive');
  assert.match(onlyRow.custodyUpgrade, /^For insert, update, delete effects: add a pg-wal observer on the tables they write .*, and an egress recorder or SMTP sink for the sends, or accept this row as inconclusive\.$/);
  const [auditNone, auditOnly] = decideEffects(clauses('sql-audit-table'), [store('audit-table-audit', 'sql-audit-table'), egress]);
  assert.deepEqual([auditNone.custodyUpgrade, auditOnly.custodyUpgrade], [custodyUpgrade({ ...select, source: 'sql-audit-table' }), onlyCustodyUpgrade(['insert', 'update', 'delete', 'send'])]);
  // walUpgrade false is the text an earlier build wrote, which the recompute also accepts (an earlier record, below).
  const [earlierNone, earlierOnly] = decideEffects(clauses('sql-snapshot'), [pg, egress], { walUpgrade: false });
  assert.deepEqual([earlierNone.custodyUpgrade, earlierOnly.custodyUpgrade], [none, onlyCustodyUpgrade(['insert', 'update', 'delete', 'send'])]);
});

// A run recorded and sealed by an earlier build before pg-wal profiles (test/fixtures/pre-pgwal-run-9d2e44a6.mjs,
// written by that build's own connector over the scripted fake Postgres, not by hand) still validates here and a comparison reads it, although
// this head writes the pg-wal text on the same degraded row. Only that text may differ: any other, resealed, is refused.
test('a run recorded by an earlier build before pg-wal profiles still validates, and its custody text stays bound', async () => {
  const { recordedAt, profile, suite, run } = structuredClone(recordedAtMain);
  assert.equal(recordedAt, '9d2e44a6');
  // As the regression gate and a comparison read a saved run (src/runner.mjs), and against the suite that build exported for its profile.
  validateHttpRunEvidence(run);
  validateHttpRunEvidence(run, { expectedSuite: suite });
  assert.equal(compareRuns(run, run).compatible, true);
  // This head's suite for the same profile differs only in the pg-snapshot collector record, pg-snapshot/4 then /5 (the announced move).
  const here = createRegistry({ profiles: [profile], env: { SCOPEHAVEN_TARGET_BOB: TOKEN, SCOPEHAVEN_TARGET_DB_READER: 'reader:pw' } }).exportSuite(profile.id);
  assert.deepEqual([suite.observers[0].collector.label, here.observers[0].collector.label], ['pg-snapshot/4', 'pg-snapshot/5']);
  assert.deepEqual({ ...here, observers: here.observers.map(({ collector, ...o }) => o) }, { ...suite, observers: suite.observers.map(({ collector, ...o }) => o) });
  const id = 'BOB-ALICE-CHAT', [clause] = run.results.find(r => r.id === id).trace[1].data.effects;
  assert.deepEqual([clause.custodyReason, clause.custodyUpgrade], [CUSTODY_REASON, custodyUpgrade(clause.select)]);
  const resealed = text => {
    const copy = structuredClone(run), r = copy.results.find(x => x.id === id);
    r.trace[1].data.effects[0].custodyUpgrade = text;
    for (const a of r.assertions) if (Object.hasOwn(a, 'custodyUpgrade')) a.custodyUpgrade = text;
    r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions });
    return copy;
  };
  // The text this head writes on that row (a Postgres snapshot decided it) validates too.
  const wal = custodyUpgrade(clause.select, { wal: true });
  assert.match(wal, /^For operation update, name Chat, resource Chat\/c1: add a pg-wal observer/);
  validateHttpRunEvidence(resealed(wal), { expectedSuite: suite });
  for (const text of ['Any other upgrade text.', custodyUpgrade({ ...clause.select, operation: 'insert' })])
    assert.throws(() => validateHttpRunEvidence(resealed(text), { expectedSuite: suite }), /invalid-run-evidence/, text);
  // The effect trace's own recompute binds it too, before the assertion rows are compared: that build's text and this head's pass, no other.
  const check = profile.checks.find(c => c.id === id), traceWith = text => resealed(text).results.find(x => x.id === id).trace[1];
  for (const text of [clause.custodyUpgrade, wal]) assert.equal(recomputeEffectTrace(traceWith(text), check.effects, profile.observers, { role: 'boundary' }).decisions[0].custodyUpgrade, text);
  assert.throws(() => recomputeEffectTrace(traceWith('Any other upgrade text.'), check.effects, profile.observers, { role: 'boundary' }), /effect-verdict/);
});

// pg_net on the wire, "no pgNetWire, no change": a run recorded and sealed by an earlier build's own connector
// (test/fixtures/pre-pgnet-run-8ecfe737.mjs), a pg-wal profile with no pgNetWire over the scripted session in which pg_net's unlogged
// queue exists. It validates here, with and without the suite that build exported; this head exports the same suite for its profile apart
// from the collector record (pg-wal/4 then /5, the announced move); and the same profile run here decides the same rows for the same
// reason. Only evaluatorHash (b1c4a90d then this head's) and the collector record differ.
test('no pgNetWire, no change: a pg-wal run recorded by an earlier build validates here, the suite differs only in its collector record, and the rows decide the same', async t => {
  const { recordedAt, profile: recorded, suite, run } = structuredClone(recordedBeforeWire);
  assert.equal(recordedAt, '8ecfe737');
  assert.ok(!Object.hasOwn(recorded.observers[0], 'pgNetWire'));
  validateHttpRunEvidence(run);
  validateHttpRunEvidence(run, { expectedSuite: suite });
  assert.equal(compareRuns(run, run).compatible, true);
  const here = createRegistry({ profiles: [recorded], env }).exportSuite(recorded.id);
  assert.deepEqual([suite.observers[0].collector.label, here.observers[0].collector.label], ['pg-wal/4', 'pg-wal/5']);
  assert.deepEqual(here.observers[0].collector, COLLECTOR_RECORDS['pg-wal']);
  const withoutCollector = x => ({ ...x, observers: x.observers.map(({ collector, ...o }) => o) });
  assert.deepEqual(withoutCollector(here), withoutCollector(suite));
  assert.deepEqual([here.hash, run.profileHash], [suite.hash, suite.hash]);
  assert.equal(run.evaluatorHash, 'b1c4a90d0b49fadc0a11da2cf87d81dbad5893e60cff301aee17cbeabd1ab5d4');
  assert.notEqual(HTTP_EVALUATOR_HASH, run.evaluatorHash);
  // The same profile at this head, on a fresh copy of the app (its port is new, so the origin is too): the same rows, decided the same.
  const s = fakeServer(); s.notInWal = ['net.http_request_queue'];
  const refund = () => s.commit([['declared', walRow('UPDATE', " id[text]:'a' status[text]:'refunded' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")]]);
  const p = { ...recorded, origin: await app(t, () => {}, refund) };
  const now = await runHttpAssessment(p, { env, observerFactory: (configs, options) => { buildObservers(configs, options); return factoryOver(s)(configs, options); } });
  const decided = r => r.results.map(x => [x.id, x.status, x.assertions.map(a => [a.name, a.status, String(a.actual ?? '').replace(/\d+ms/g, 'Nms')])]);
  assert.deepEqual(decided(now), decided(run));
  assert.deepEqual(now.counts, run.counts);
  assert.match(now.results.find(x => x.id === 'NO-REFUND-ON-READ').assertions.at(-1).actual, /table-not-in-wal/);
  assert.equal(now.evaluatorHash, HTTP_EVALUATOR_HASH);
  assert.equal(now.profileHash, createRegistry({ profiles: [p], env }).exportSuite(p.id).hash);
});

// pg_net on the wire through the connector: a pg-wal observer that declares pgNetWire is given a pg-net-wire built from the profile
// (src/http-connector.mjs startObservers), before it starts, from whatever factory built it; the observer factory itself is unchanged.
test('pgNetWire: the connector gives the pg-wal observer its wire, and the backend row decides only on a complete, observer-held wire window', async t => {
  const queue = 'net.http_request_queue', given = [];
  const declaration = custody => ({ programRoles: custody === 'observer-held' ? ['supabase_admin'] : ['postgres', 'supabase_admin'], requestRoles: ['authenticator', 'service_role'], refused: custody === 'observer-held' ? [] : ['postgres'], checked: true });
  const scripted = custody => ({ covers: [queue], async start() {}, async stop() {}, async mark() { return { index: 1 }; },
    async collect() { return { events: [], coverage: 'complete', reason: null, custody, declaration: declaration(custody), covers: custody === 'observer-held' ? [queue] : [], wire: { schema: 'scopehaven-pg-net-wire/1', coverage: 'complete', custody } }; } });
  const run = async (custody, { takesWire = true } = {}) => {
    const s = fakeServer(); s.notInWal = [queue];
    const p = profile(await app(t, () => {}, () => s.commit([['declared', walRow('UPDATE', " id[text]:'a' status[text]:'refunded' amount[numeric]:10 email[text]:'x@y' note[text]:'n'")]])),
      [walObserver({ pgNetWire: { container: 'supabase_db_copy', credentialEnv: 'SCOPEHAVEN_TARGET_PGNET', programRoles: ['supabase_admin'], requestRoles: ['service_role', 'authenticator', 'anon', 'authenticated'], image: 'python@sha256:' + 'a'.repeat(64), quietMs: 500 } })]);
    const e = { ...env, SCOPEHAVEN_TARGET_PGNET: 'witness:pw' };
    const factory = (configs, options) => factoryOver(s)(configs, options).map(o => (takesWire ? Object.assign(Object.create(null), o, { attachWire: w => { given.push(w); o.attachWire(scripted(custody)); } }) : o));
    return runHttpAssessment(p, { env: e, observerFactory: takesWire ? factory : (configs, options) => factoryOver(s)(configs, options).map(o => { const { attachWire, ...rest } = o; return rest; }) });
  };
  const held = await run('observer-held');
  assert.equal(given.length, 1);
  assert.deepEqual([given[0].kind, given[0].instanceId, given[0].covers], ['pg-net-wire', 'pg-wal-wal-pg-net-wire', [queue]]);
  // The wire the connector built carries the profile's declaration, request roles included.
  assert.deepEqual(given[0].declaration(), { programRoles: ['supabase_admin'], requestRoles: ['anon', 'authenticated', 'authenticator', 'service_role'], refused: null, checked: false });
  assert.equal(held.results.find(r => r.id === 'NO-REFUND-ON-READ').status, 'pass');
  // The declaration the window rests on is sealed beside it, word for word, validates with the run, and the report shows it.
  const sealedWindow = run => run.results.find(r => r.id === 'NO-REFUND-ON-READ').trace.flatMap(e => e.data?.windows ?? []).find(w => w.source === 'sql-wal');
  assert.deepEqual(sealedWindow(held).declaration, declaration('observer-held'));
  validateHttpRunEvidence(held);
  const report = renderReport(held);
  assert.match(report, /pg_net custody declaration/);
  assert.match(report, /Program roles declared as the operator&#39;s: supabase_admin\. Request roles: authenticator, service_role\. Refused as reachable by the application: none\. Checked: yes\./);
  // The settlement's gap windows carry their declarations too, and the report shows every one.
  const gapWindows = held.settlement.gaps.flatMap(g => g.windows).filter(w => w.source === 'sql-wal');
  assert.ok(gapWindows.length >= 1);
  assert.ok(gapWindows.every(w => JSON.stringify(w.declaration) === JSON.stringify(declaration('observer-held'))));
  assert.match(report, /<h2>pg_net custody declarations between checks<\/h2><ul><li>Gap before the first check, pg-wal-wal: /);
  assert.equal((report.match(/Program roles declared as the operator&#39;s: supabase_admin\./g) ?? []).length, held.results.filter(r => r.trace.some(e => e.data?.windows?.some(w => w.declaration))).length + gapWindows.length);
  const writable = await run('subject-writable');
  const row = writable.results.find(r => r.id === 'NO-REFUND-ON-READ');
  assert.deepEqual(sealedWindow(writable).declaration.refused, ['postgres']);
  assert.match(renderReport(writable), /Refused as reachable by the application: postgres\./);
  assert.equal(row.status, 'inconclusive');
  assert.match(row.assertions.at(-1).actual, /table-not-in-wal/);
  await assert.rejects(run('observer-held', { takesWire: false }), /Declared observers could not be created: Observer entry 1: pgNetWire needs a pg-wal observer that takes a wire/);
  // The sealed declaration's shape: sorted distinct role names, refused a subset of the declared, nothing else; only on a pg-wal window.
  const good = declaration('observer-held');
  assert.ok(validWireDeclaration(good));
  // Unchecked, as the wire writes one without request roles or before it read them.
  assert.ok(validWireDeclaration({ ...good, requestRoles: [], refused: null, checked: false }));
  // Request roles but no program roles, as the wire writes it: checked, nothing refused.
  assert.ok(validWireDeclaration({ programRoles: [], requestRoles: ['authenticator'], refused: [], checked: true }));
  // The settlement's barrier windows (per-check mode) are shown as well as its gaps.
  const barrierRun = { settlement: { gaps: [], barriers: [{ after: 'B-READS-A-RECORD-BACKEND', windows: [{ ...sealedWindow(held), declaration: good }] }] } };
  assert.match(settlementDeclarationsHtml(barrierRun), /<li>Barrier after B-READS-A-RECORD-BACKEND, pg-wal-wal: complete\. Program roles declared as the operator&#39;s: supabase_admin\./);
  assert.equal(settlementDeclarationsHtml({ settlement: { gaps: [], barriers: [] } }), '');
  for (const bad of [{ ...good, refused: ['other'] }, { ...good, programRoles: ['b', 'a'] }, { ...good, extra: 1 }, { ...good, checked: 'yes' }, { ...good, requestRoles: ['bad-name'] }, null,
    { ...good, requestRoles: [] }, { ...good, refused: null }])
    assert.equal(validWireDeclaration(bad), false, JSON.stringify(bad));
  const sealed = sealedWindow(held);
  assert.throws(() => validateWindow({ ...sealed, declaration: { ...good, refused: ['other'] } }), /declaration/);
  assert.throws(() => validateWindow({ ...sealed, source: 'sql-snapshot', declaration: good, events: [] }), /declaration/);
  // An observer that is not a pg-wal observer has its declaration dropped, never sealed.
  const other = await collectWindow({ source: 'sql-snapshot', instanceId: 'x', scope: sealed.scope, async collect() { return { events: [], coverage: 'complete', reason: null, declaration: good }; } }, { index: 1 }, { index: 2 });
  assert.deepEqual([other.coverage, Object.hasOwn(other, 'declaration')], ['complete', false]);
});
