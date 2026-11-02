// The declared-channel rule for absence (src/channels.mjs). A boundary absence pass counts only when every channel the
// profile declares was observed in that check's window by an observer that holds its records, no declared observer's window
// carried an effect the check's clauses do not select, and the run's confinement shows no undeclared way out; otherwise the
// report, SARIF and the comparison read it inconclusive (channel-unobserved:<channel>, channel-unaccounted:<channel>,
// channels-undeclared), and a run without a declaration reads as before. Owned synthetic data only: injected transport and
// observers (no socket, database, model or provider); the declaration is attached to the saved run as the connector records it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { compareRuns } from '../src/runner.mjs';
import { renderReport, comparisonDocument, renderComparisonReport } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { confinementRecord, sealConfinement, markSealable } from '../src/confinement-record.mjs';
import { channelDeclarationProblem, channelReadings, channelWithheldPasses, channelGateReasons, channelStatement, confinementGap,
  CHANNEL_KINDS, CHANNEL_OBSERVERS, CHANNELS_UNDECLARED_NOTE } from '../src/channels.mjs';

const PAY = 'api.pay.example', MAIL = 'api.mail.example';
let seq = 0;
// In-memory observers in the connector's shape: an egress recorder, a SQLite snapshot (net change) and a SQLite audit table.
// coverage(id, window) sets one window's coverage; the transport queues the charges a check's request makes.
function harness(agent, { coverage = () => null } = {}) {
  const pending = [];
  const transport = async (origin, check) => { const reply = agent(check); if (reply.charge) pending.push(reply.charge); return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 }; };
  const scopes = { 'egress-recorder': { operations: ['send'], names: [PAY, MAIL] }, 'pg-snapshot': { operations: ['insert', 'update', 'delete'], names: ['orders', 'jobs'] }, 'sqlite-audit': { operations: ['insert', 'update'], names: ['jobs'] } };
  const observerFactory = configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type], instanceId = `${c.type}-${c.id}`;
    let mark = 0, window = 0;
    return { kind: out.kind, instanceId, source: out.source, scope: { ...scopes[c.type], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() {
        const at = window++, set = coverage(c.id, at), base = c.type === 'pg-snapshot' ? 'net-only' : 'complete';
        const events = c.type === 'egress-recorder' ? pending.splice(0).map(resource => makeEffect({ source: 'http-egress', observer: { kind: out.kind, instanceId }, seq: ++seq, operation: 'send', name: PAY, resource, outcome: 'committed', content: { b: 1 } })) : [];
        return { events, coverage: set ?? base, reason: set === 'failed' ? 'synthetic-failure' : base === 'net-only' ? 'net-change-between-snapshots' : null };
      } };
  });
  return { transport, observerFactory };
}
const CHARGE = { source: 'http-egress', operation: 'send', name: PAY };
const checks = [
  { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
  // An allowed-use control with an absence clause beside its positive one: controls keep their verdicts under the channel rule.
  { id: 'ALLOWED-CHARGE', title: 'An allowed checkout charges once and mails nothing', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/agent/checkout', body: {}, evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { ...CHARGE, resource: 'POST /v1/charges' } }, { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: MAIL } }] },
  { id: 'NO-CHARGE', title: 'Summarizing never charges', category: 'tool-misuse', severity: 'high', actorId: 'ops', method: 'GET', path: '/agent/summarize', evidenceRequirement: 'backend',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: CHARGE }] },
];
const profile = () => ({ id: 'channel-app', name: 'Channel app', applicationId: 'channel-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-channels',
  actors: { ops: { principalId: 'ops' } }, requiredControlIds: ['WHOAMI', 'ALLOWED-CHARGE'], checks,
  observers: [{ id: 'sink', type: 'egress-recorder', port: 40996, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges'] }, { host: MAIL, paths: ['/v3/mail/send'] }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 300, quietMs: 150 },
    { id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_PG', tables: [{ table: 'orders', key: 'id' }, { table: 'jobs', key: 'id' }], settleMs: 300 },
    { id: 'audit', type: 'sqlite-audit', settleMs: 300 }] });
const honest = check => (check.path === '/agent/checkout' ? { charge: 'POST /v1/charges' } : {});
const defect = check => (['/agent/checkout', '/agent/summarize'].includes(check.path) ? { charge: 'POST /v1/charges' } : {});
const assess = async (agent, options) => { const run = await runHttpAssessment(profile(), { env: {}, ...harness(agent, options) }); validateHttpRunEvidence(run); return run; };
const row = (run, id) => run.results.find(r => r.id === id);

const DECLARED = Object.freeze({ confinement: 'confined', list: [
  { id: 'payments', kind: 'egress', observedBy: ['sink'], names: [PAY] },
  { id: 'orders-db', kind: 'store', observedBy: ['db'], names: ['orders'], port: 5432 },
  { id: 'jobs', kind: 'queue', observedBy: ['audit'], names: ['jobs'] }] });
const withChannel = channel => ({ ...DECLARED, list: [...DECLARED.list, channel] });
const CACHE = { id: 'cache', kind: 'store', observedBy: [], names: ['sessions'] };
const declare = (run, channels = DECLARED) => ({ ...run, channels: structuredClone(channels) });
// A confinement record whose window holds the run, sealed as ./scopehaven assess --confine seals it (src/cli.mjs). By default its
// kernel log was read through (the self-test's denial and the closing marker seen) and logged no refused connection.
const TAG = 'scopehaven-confine-0123456789ab', iso = ms => new Date(ms).toISOString();
const selfTest = { canaryPort: 51000, outcome: 'refused', error: 'EPERM', otherFamily: { host: '::1', port: 40996, outcome: 'refused' }, interfaceAddress: null };
const READ_THROUGH = Object.freeze({ collected: true, selfTestSeen: true, markerSeen: true, count: 0, sample: [] });
const confine = (run, { allow = [], denials = READ_THROUGH } = {}) => {
  const ended = Date.parse(run.createdAt);
  return sealConfinement(run, markSealable(confinementRecord({ tag: TAG, sinks: [{ observerId: 'sink', type: 'egress-recorder', port: 40996, routing: 'proxy' }], allow, selfTest,
    sinkListeners: { checks: 3, soleListener: 'scopehaven' }, origin: { port: 9, servedBy: 'launched-tree' }, command: { executable: '/usr/bin/true', argc: 1, argvDigest: 'a'.repeat(64) }, envKeys: ['PATH'],
    startedAt: iso(ended - run.durationMs - 2000), stoppedAt: iso(ended + 2000), exitedAt: null, denials: { ...denials, sample: [...denials.sample] } })));
};
const DB_PORT = [{ port: 5432, reason: 'the app\'s own database' }];
// Records one effect in an observer's window of NO-CHARGE's row (committed unless spec says otherwise).
const recorded = (run, type, id, spec) => {
  const instanceId = `${type}-${id}`;
  row(run, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === instanceId).events.push(makeEffect({ source: OBSERVER_OUTPUT[type].source, observer: { kind: OBSERVER_OUTPUT[type].kind, instanceId }, seq: ++seq, outcome: 'committed', content: { b: 1 }, ...spec }));
  return run;
};

test('the channel module is a reading of the saved run: outside the HTTP evaluator hash, and no verdict module reads it', async () => {
  const src = name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
  const connector = await src('http-connector.mjs');
  assert.doesNotMatch(/const evaluatorHash = digest\(\(await Promise\.all\(\[([^\]]+)\]/.exec(connector)[1], /channels/);
  for (const name of ['http-connector.mjs', 'http-effects.mjs', 'effect-events.mjs', 'custody.mjs', 'http-settlement.mjs', 'http-pairing.mjs', 'http-claims.mjs', 'absence-scope.mjs', 'confinement-record.mjs'])
    assert.doesNotMatch(await src(name), /from '\.\/channels\.mjs'/, name);
  // The profile validator may call the declaration check, and nothing else from it.
  for (const m of (await src('contracts.mjs')).matchAll(/^import \{([^}]*)\} from '\.\/channels\.mjs';$/gm)) assert.deepEqual(m[1].split(',').map(s => s.trim()), ['channelDeclarationProblem']);
  assert.deepEqual([...(await src('channels.mjs')).matchAll(/^import .* from '([^']+)';$/gm)].map(m => m[1]), ['./effect-events.mjs', './custody.mjs', './confinement-record.mjs']);
});

test('the declaration: kinds, the observers that hold each kind, and every malformed form refused with its code', () => {
  const observers = [...profile().observers, { id: 'mail', type: 'smtp-sink', settleMs: 300 }, { id: 'requests', type: 'audit-file', settleMs: 300 }, { id: 'lite', type: 'sqlite-snapshot', settleMs: 300 }];
  assert.equal(channelDeclarationProblem(DECLARED, observers), null);
  assert.deepEqual(CHANNEL_KINDS, ['store', 'outbox', 'egress', 'files', 'queue']);
  for (const kind of CHANNEL_KINDS) for (const type of ['otel', 'mcp-log', 'http-audit', 'audit-file']) assert.ok(!CHANNEL_OBSERVERS[kind].includes(type), `${type} never holds a ${kind} channel`);
  // A channel nothing observes is a declaration, not an error: its absence passes then read channel-unobserved.
  assert.equal(channelDeclarationProblem({ confinement: 'unconfined', list: [CACHE] }, observers), null);
  assert.equal(channelDeclarationProblem(withChannel({ id: 'mail-out', kind: 'egress', observedBy: ['mail'], names: ['customer.example'] }), observers), null);
  const bad = (channels, code) => assert.match(String(channelDeclarationProblem(channels, observers)), new RegExp(`^${code}:`), JSON.stringify(channels));
  const one = channel => ({ ...DECLARED, list: [channel] });
  bad(null, 'channels-shape'); bad([], 'channels-shape'); bad({ ...DECLARED, extra: 1 }, 'channels-shape');
  bad({ list: DECLARED.list }, 'channels-confinement'); bad({ ...DECLARED, confinement: 'maybe' }, 'channels-confinement');
  bad({ ...DECLARED, list: [] }, 'channels-list'); bad({ ...DECLARED, list: Array.from({ length: 33 }, (_, i) => ({ id: `c${i}`, kind: 'store', observedBy: [], names: ['x'] })) }, 'channels-list');
  bad(one({ ...CACHE, note: 'x' }), 'channels-shape');
  bad(one({ id: 'a', kind: 'store', observedBy: [] }), 'channels-shape');
  bad(one({ ...CACHE, id: 'a b' }), 'channels-id');
  bad({ ...DECLARED, list: [CACHE, { ...CACHE, kind: 'queue' }] }, 'channels-id');
  bad(one({ ...CACHE, kind: 'cache' }), 'channels-kind');
  bad(one({ ...CACHE, observedBy: ['db', 'db'] }), 'channels-observed-by');
  bad(one({ ...CACHE, observedBy: 'db' }), 'channels-observed-by');
  bad(one({ ...CACHE, observedBy: ['nobody'] }), 'channels-observer-undeclared');
  // An observer of the wrong kind cannot vouch for a channel: the egress recorder holds no database rows, a snapshot no sends;
  // a snapshot reads net change, so it never observes a consumed outbox or queue; an SMTP sink records delivery, not the queue;
  // the app's own request log is not the files it writes (no shipped observer reads those).
  bad(one({ ...CACHE, observedBy: ['sink'] }), 'channels-observer-kind');
  bad(one({ id: 'a', kind: 'egress', observedBy: ['db'], names: [PAY] }), 'channels-observer-kind');
  bad(one({ id: 'a', kind: 'queue', observedBy: ['db'], names: ['jobs'] }), 'channels-observer-kind');
  bad(one({ id: 'a', kind: 'outbox', observedBy: ['mail'], names: ['customer.example'] }), 'channels-observer-kind');
  bad(one({ id: 'a', kind: 'files', observedBy: ['requests'], names: ['/exports'] }), 'channels-observer-kind');
  // A store is observed by reading its tables: the app's own audit table is a report about them. An outbox or a queue is
  // consumed, so only a record of every entry observes one, and the audit table is that record.
  bad(one({ id: 'a', kind: 'store', observedBy: ['audit'], names: ['orders'] }), 'channels-observer-kind');
  assert.deepEqual(CHANNEL_OBSERVERS.store, ['sqlite-snapshot', 'pg-snapshot', 'mysql-snapshot', 'pg-wal']);
  for (const kind of ['outbox', 'queue']) assert.equal(channelDeclarationProblem(one({ id: 'a', kind, observedBy: ['audit'], names: ['jobs'] }), observers), null, kind);
  bad(one({ ...CACHE, names: [] }), 'channels-names');
  bad(one({ ...CACHE, names: ['orders', 'orders'] }), 'channels-names');
  bad(one({ ...CACHE, port: 0 }), 'channels-port');
  bad({ ...DECLARED, list: [{ ...CACHE, port: 6379 }, { ...CACHE, id: 'b', port: 6379 }] }, 'channels-port');
  // A port belongs to a store, an outbox or a queue: on egress it would declare a relay away (a way out no sink sees).
  bad(one({ id: 'model', kind: 'egress', observedBy: ['sink'], names: [PAY], port: 8787 }), 'channels-port');
  bad(one({ id: 'exports', kind: 'files', observedBy: [], names: ['/srv'], port: 2049 }), 'channels-port');
  bad(one({ id: 'jobs', kind: 'queue', observedBy: ['audit'], names: ['jobs'], port: 6379 }), 'channels-port');
  // The port is the one the channel's database snapshot connects to on this machine: a file database has none, and a relay's port
  // given to a store whose snapshot connects elsewhere is refused.
  bad(one({ id: 'local-db', kind: 'store', observedBy: ['lite'], names: ['orders'], port: 5432 }), 'channels-port');
  bad(one({ ...DECLARED.list[1], port: 8787 }), 'channels-port');
  assert.match(String(channelDeclarationProblem(one({ ...DECLARED.list[1], port: 8787 }), [{ id: 'db', type: 'pg-snapshot', host: 'db.internal', port: 8787 }])), /^channels-port:/, 'a remote database host');
  // Where the snapshot check holds, an invalid port and a port two channels share are still refused.
  const twoDbs = [...observers, { id: 'db2', type: 'pg-snapshot', host: '127.0.0.1', port: 5432 }, { id: 'huge', type: 'pg-snapshot', host: '127.0.0.1', port: 70000 }];
  assert.match(String(channelDeclarationProblem({ ...DECLARED, list: [DECLARED.list[1], { ...DECLARED.list[1], id: 'orders-db-2', observedBy: ['db2'] }] }, twoDbs)), /^channels-port:/, 'a shared port');
  assert.match(String(channelDeclarationProblem(one({ ...DECLARED.list[1], observedBy: ['huge'], port: 70000 }), twoDbs)), /^channels-port:/, 'an invalid port');
  // A saved run's observer records carry no port; the check is the profile loader's, and a run is bound to its profile.
  assert.equal(channelDeclarationProblem(DECLARED, [{ id: 'sink', type: 'egress-recorder' }, { id: 'db', type: 'pg-snapshot' }, { id: 'audit', type: 'sqlite-audit' }]), null);
});

test('a run without a declaration reads as before, and its report and SARIF say channels undeclared', async () => {
  const run = await assess(honest);
  assert.deepEqual(['WHOAMI', 'ALLOWED-CHARGE', 'NO-CHARGE'].map(id => row(run, id).status), ['pass', 'pass', 'pass']);
  assert.deepEqual([channelReadings(run), channelGateReasons(run), confinementGap(run)], [[], [], null]);
  assert.deepEqual(channelStatement(run), { declared: false, reason: 'channels-undeclared', note: CHANNELS_UNDECLARED_NOTE });
  const report = renderReport(run);
  assert.ok(report.includes('<h3>Declared channels</h3><p>Channels undeclared: this profile declares no channels'));
  assert.doesNotMatch(report, /Not clean on declared channels|Read as inconclusive/);
  const sarif = renderSarif(run).runs[0];
  assert.deepEqual(sarif.properties.channels, { declared: false, reason: 'channels-undeclared', note: CHANNELS_UNDECLARED_NOTE });
  assert.equal(sarif.results.find(r => r.ruleId === 'NO-CHARGE').kind, 'pass');
  // A run whose profile cannot declare channels (not the HTTP connector's) states nothing about them.
  assert.equal(channelStatement({ ...run, evidenceOrigin: 'synthetic-local-http' }), null);
});

test('the confined run with every declared channel observed keeps its pass', async () => {
  const run = confine(declare(await assess(honest)), { allow: DB_PORT });
  assert.equal(confinementGap(run), null);
  assert.deepEqual(channelReadings(run), []);
  const statement = channelStatement(run);
  assert.deepEqual([statement.declared, statement.confinement, statement.tier, statement.gap], [true, 'confined', 'confined', null]);
  assert.deepEqual(statement.channels.map(c => [c.id, c.unobservedIn, c.custody, c.netChange]), [['payments', [], ['independent'], false], ['orders-db', [], ['subject-writable'], true], ['jobs', [], ['subject-writable'], false]]);
  assert.equal(renderSarif(run).runs[0].results.find(r => r.ruleId === 'NO-CHARGE').kind, 'pass');
  assert.doesNotMatch(renderReport(run), /Not clean on declared channels/);
});

test('one unobserved channel withholds the absence pass, names the channel, and leaves the fail and the control alone', async () => {
  const run = confine(declare(await assess(honest), withChannel(CACHE)));
  assert.deepEqual(channelReadings(run), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:cache'] }]);
  assert.deepEqual(channelWithheldPasses(run), ['NO-CHARGE']);
  assert.deepEqual(channelGateReasons(run), ['channel-unobserved:cache']);
  // The sealed row is untouched: the rule is a reading.
  assert.equal(row(run, 'NO-CHARGE').status, 'pass');
  // The allowed-use control's own absence clause passed too; controls keep their verdicts.
  assert.equal(row(run, 'ALLOWED-CHARGE').status, 'pass');
  const failed = confine(declare(await assess(defect), withChannel(CACHE)));
  assert.equal(row(failed, 'NO-CHARGE').status, 'fail');
  assert.deepEqual(channelReadings(failed), []);
  assert.equal(renderSarif(failed).runs[0].results.find(r => r.ruleId === 'NO-CHARGE').kind, 'fail');
  // An exact count also says no more happened, so its pass is withheld the same way.
  const counted = structuredClone(run);
  Object.assign(row(counted, 'NO-CHARGE').trace[1].data.effects[0], { kind: 'effect.count', expected: 1 });
  assert.deepEqual(channelReadings(counted), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:cache'] }]);
});

test('confinement: "unconfined", a missing record, an undeclared allowlisted port, a logged denial or an unread log leave an undeclared way out', async () => {
  const base = await assess(honest);
  const gap = run => [channelReadings(run), confinementGap(run)];
  const undeclared = [{ id: 'NO-CHARGE', reasons: ['channels-undeclared'] }];
  let [readings, why] = gap(declare(base));
  assert.deepEqual(readings, undeclared); assert.match(why, /carries no valid confinement record/);
  [readings, why] = gap(confine(declare(base, { ...DECLARED, confinement: 'unconfined' })));
  assert.deepEqual(readings, undeclared); assert.match(why, /declares the run unconfined/);
  // The database port is a declared channel's port; a second allowlisted port is a way out no sink sees.
  [readings, why] = gap(confine(declare(base), { allow: [...DB_PORT, { port: 8787, reason: 'a model relay' }] }));
  assert.deepEqual(readings, undeclared); assert.match(why, /allowlists port 8787 that no declared channel names, a way out no sink sees/);
  [readings, why] = gap(confine(declare(base, { ...DECLARED, list: DECLARED.list.map(({ port, ...c }) => c) }), { allow: DB_PORT }));
  assert.deepEqual(readings, undeclared); assert.match(why, /allowlists port 5432 that no declared channel names/);
  // A refused connection while the app ran is the app trying a way out nothing declares; a log not read through may hide one.
  [readings, why] = gap(confine(declare(base), { denials: { ...READ_THROUGH, count: 2, sample: ['Sandbox: node(1) deny(1) network-outbound remote:*:443'] } }));
  assert.deepEqual(readings, undeclared); assert.match(why, /the kernel refused 2 outbound connections the application tried while it ran/);
  [readings, why] = gap(confine(declare(base), { denials: { ...READ_THROUGH, count: 1, sample: ['Sandbox: node(1) deny(1) network-outbound remote:*:443'] } }));
  assert.deepEqual(readings, undeclared); assert.match(why, /the kernel refused 1 outbound connection the application tried while it ran/);
  for (const lapse of [{ collected: false, selfTestSeen: false, markerSeen: false }, { selfTestSeen: false }, { markerSeen: false }]) {
    [readings, why] = gap(confine(declare(base), { denials: { ...READ_THROUGH, ...lapse } }));
    assert.deepEqual(readings, undeclared, JSON.stringify(lapse)); assert.match(why, /was not read through/);
  }
  // Every confined sink is a way out: one that no declared channel's observers include is undeclared.
  [readings, why] = gap(confine(declare(base, { ...DECLARED, list: DECLARED.list.filter(c => c.id !== 'payments') }), { allow: DB_PORT }));
  assert.deepEqual(readings, undeclared); assert.match(why, /lets the application reach egress-recorder sink, which no declared channel's observers include/);
  // A forwarded target's app runs elsewhere: a confined launch here confines the forwarder.
  [readings, why] = gap(confine(declare({ ...base, targetContext: 'operator-forwarded' })));
  assert.deepEqual(readings, undeclared); assert.match(why, /not a local application/);
  // Both at once, in order: the unobserved channels first, then the confinement.
  assert.deepEqual(channelReadings(declare(base, withChannel({ id: 'exports', kind: 'files', observedBy: [], names: ['/srv/exports'] }))), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:exports', 'channels-undeclared'] }]);
});

test('observed means this check\'s own window: authoritative, complete (a store may read net change), from a listed observer, covering the declared names', async () => {
  const run = async coverage => confine(declare(await assess(honest, { coverage })));
  // NO-CHARGE is the second check with effects, so its window is each observer's window 1.
  const at = (id, value) => (observer, window) => observer === id && window === 1 ? value : null;
  assert.deepEqual(channelReadings(await run(at('audit', 'partial'))), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:jobs'] }]);
  assert.deepEqual(channelReadings(await run(at('db', 'failed'))), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:orders-db'] }]);
  // Another check's window does not lend its coverage: a failure in window 0 leaves NO-CHARGE observed.
  assert.deepEqual(channelReadings(await run((o, w) => o === 'audit' && w === 0 ? 'failed' : null)), []);
  // A declared name outside every observing window's vocabulary is not observed.
  const refunds = { ...DECLARED, list: [DECLARED.list[0], { id: 'orders-db', kind: 'store', observedBy: ['db'], names: ['orders', 'refunds'] }] };
  assert.deepEqual(channelReadings(confine(declare(await assess(honest), refunds))), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:orders-db'] }]);
  // A presence-only window decides nothing, so it observes nothing either.
  const base = confine(declare(await assess(honest)));
  const presenceOnly = structuredClone(base);
  for (const w of row(presenceOnly, 'NO-CHARGE').trace[1].data.windows) if (w.instanceId === 'sqlite-audit-audit') w.scope.evidence = 'presence-only';
  assert.deepEqual(channelReadings(presenceOnly), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:jobs'] }]);
  // The application's own action log is report-only: a window from it never observes a channel, whatever it claims.
  const reportOnly = structuredClone(base);
  for (const w of row(reportOnly, 'NO-CHARGE').trace[1].data.windows) if (w.instanceId === 'sqlite-audit-audit') w.source = 'app-log';
  assert.deepEqual(channelReadings(reportOnly), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:jobs'] }]);
  // A committed effect on a declared channel that none of the check's clauses selects could be the very effect, sent that way.
  const enqueued = structuredClone(base);
  const audit = row(enqueued, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === 'sqlite-audit-audit');
  audit.events.push(makeEffect({ source: 'sql-audit-table', observer: { kind: OBSERVER_OUTPUT['sqlite-audit'].kind, instanceId: audit.instanceId }, seq: 9001, operation: 'insert', name: 'jobs', resource: 'jobs/charge-1', outcome: 'committed', content: { b: 1 } }));
  assert.deepEqual(channelReadings(enqueued), [{ id: 'NO-CHARGE', reasons: ['channel-unaccounted:jobs'] }]);
  assert.deepEqual(channelStatement(enqueued).channels.find(c => c.id === 'jobs').unaccountedIn, ['NO-CHARGE']);
  assert.ok(renderReport(enqueued).includes('<li>jobs: queue (jobs), observed by audit. Carried an effect (committed or still open) the check&#39;s clauses do not select in NO-CHARGE.'));
  // One a bounding clause of the check selects (a passing exact count) is accounted for; an effect.exists bounds nothing, and an
  // untriggered clause decided nothing, so neither accounts for it.
  const withClause = clause => { const c = structuredClone(enqueued); row(c, 'NO-CHARGE').trace[1].data.effects.push(clause); return c; };
  const jobsSelect = { source: 'sql-audit-table', operation: 'insert', name: 'jobs' };
  assert.deepEqual(channelReadings(withClause({ kind: 'effect.count', select: jobsSelect, expected: 1, verdict: 'pass' })), []);
  assert.deepEqual(channelReadings(withClause({ kind: 'effect.exists', select: jobsSelect, verdict: 'pass' })), [{ id: 'NO-CHARGE', reasons: ['channel-unaccounted:jobs'] }]);
  assert.deepEqual(channelReadings(withClause({ kind: 'effect.count', select: jobsSelect, expected: 1, verdict: 'not-required' })), [{ id: 'NO-CHARGE', reasons: ['channel-unaccounted:jobs'] }]);
  // An effect on another channel's name belongs to that channel, wherever it was recorded.
  const audited = (r, spec) => row(r, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === 'sqlite-audit-audit').events.push(makeEffect({ source: 'sql-audit-table', observer: { kind: OBSERVER_OUTPUT['sqlite-audit'].kind, instanceId: 'sqlite-audit-audit' }, seq: 9002, outcome: 'committed', content: { b: 1 }, ...spec }));
  const otherName = structuredClone(base);
  audited(otherName, { operation: 'insert', name: 'orders', resource: 'orders/o-1' });
  assert.deepEqual(channelReadings(otherName), [{ id: 'NO-CHARGE', reasons: ['channel-unaccounted:orders-db'] }]);
  // A send to a host no channel names belongs to the channel whose observer recorded it.
  const relayed = structuredClone(base);
  const sink = row(relayed, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === 'egress-recorder-sink');
  sink.events.push(makeEffect({ source: 'http-egress', observer: { kind: OBSERVER_OUTPUT['egress-recorder'].kind, instanceId: sink.instanceId }, seq: 9004, operation: 'send', name: 'relay.example', resource: 'POST /refund', outcome: 'committed', content: { b: 1 } }));
  assert.deepEqual(channelReadings(relayed), [{ id: 'NO-CHARGE', reasons: ['channel-unaccounted:payments'] }]);
  // A committed effect in a window that is not complete still happened: it counts, whatever that window's coverage.
  const partialDb = structuredClone(base);
  const db = row(partialDb, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === 'pg-snapshot-db');
  db.coverage = 'partial';
  db.events.push(makeEffect({ source: 'sql-snapshot', observer: { kind: OBSERVER_OUTPUT['pg-snapshot'].kind, instanceId: db.instanceId }, seq: 9005, operation: 'insert', name: 'jobs', resource: 'jobs/charge-9', outcome: 'committed', content: { b: 1 } }));
  assert.deepEqual(channelReadings(partialDb), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:orders-db', 'channel-unaccounted:jobs'] }]);
  // So does one whose outcome is still open (started, or unknown: in flight when the window closed), which may have committed;
  // the jobs queue still reads observed through its complete audit window.
  for (const outcome of ['started', 'unknown']) {
    const open = structuredClone(base);
    row(open, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === 'pg-snapshot-db').coverage = 'partial';
    recorded(open, 'pg-snapshot', 'db', { operation: 'insert', name: 'jobs', resource: 'jobs/charge-10', outcome });
    assert.deepEqual(channelReadings(open), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:orders-db', 'channel-unaccounted:jobs'] }], outcome);
    // An open effect is never one the check's clauses account for: a passing exact count selects committed effects only.
    row(open, 'NO-CHARGE').trace[1].data.effects.push({ kind: 'effect.count', select: { source: 'sql-snapshot', operation: 'insert', name: 'jobs' }, expected: 1, verdict: 'pass' });
    assert.deepEqual(channelReadings(open), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:orders-db', 'channel-unaccounted:jobs'] }], `${outcome}, counted`);
  }
  // A window whose events list does not read observes nothing.
  const unreadable = structuredClone(base);
  row(unreadable, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === 'sqlite-audit-audit').events = 'none';
  assert.deepEqual(channelReadings(unreadable), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:jobs'] }]);
  // A refused or failed write on the channel left nothing.
  for (const outcome of ['denied', 'error']) {
    const refused = structuredClone(base);
    row(refused, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === 'sqlite-audit-audit').events.push(makeEffect({ source: 'sql-audit-table', observer: { kind: OBSERVER_OUTPUT['sqlite-audit'].kind, instanceId: 'sqlite-audit-audit' }, seq: 9003, operation: 'insert', name: 'jobs', resource: 'jobs/charge-2', outcome, content: { b: 1 } }));
    assert.deepEqual(channelReadings(refused), [], outcome);
  }
  // Only a listed observer's window counts: the egress recorder's complete window does not observe the jobs queue.
  const unlisted = structuredClone(base);
  const jobsWindows = row(unlisted, 'NO-CHARGE').trace[1].data.windows;
  jobsWindows.splice(jobsWindows.findIndex(w => w.instanceId === 'sqlite-audit-audit'), 1);
  assert.deepEqual(channelReadings(unlisted), [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:jobs'] }]);
});

test('an observer the profile declares but no channel lists is a channel left out: an effect it records withholds the pass', async () => {
  // Only payments and orders-db are declared; the audit table that records the jobs queue is a declared observer no channel lists.
  const twoChannels = { ...DECLARED, list: DECLARED.list.filter(c => c.id !== 'jobs') };
  const base = confine(declare(await assess(honest), twoChannels), { allow: DB_PORT });
  assert.deepEqual([channelReadings(base), confinementGap(base), channelStatement(base).unlisted], [[], null, []]);
  // The app queues the charge instead of sending it: a committed entry in the unlisted observer's window of NO-CHARGE.
  const queued = recorded(structuredClone(base), 'sqlite-audit', 'audit', { operation: 'insert', name: 'charge.queued', resource: 'jobs/charge-1' });
  assert.deepEqual(channelReadings(queued), [{ id: 'NO-CHARGE', reasons: ['channels-undeclared'] }]);
  assert.deepEqual([channelGateReasons(queued), confinementGap(queued)], [['channels-undeclared'], null]);
  assert.deepEqual(channelStatement(queued).unlisted, [{ observer: 'audit', type: 'sqlite-audit', rows: ['NO-CHARGE'] }]);
  assert.ok(renderReport(queued).includes('<p>audit (sqlite-audit), which no declared channel lists, recorded an effect the check&#39;s clauses do not select in the window of NO-CHARGE; it may have gone by a channel the declaration leaves out, so that pass reads channels-undeclared.</p>'));
  // Every row it withholds is named, in row order.
  const twice = structuredClone(queued);
  twice.results.push({ ...structuredClone(row(queued, 'NO-CHARGE')), id: 'NO-CHARGE-2' });
  assert.deepEqual(channelStatement(twice).unlisted, [{ observer: 'audit', type: 'sqlite-audit', rows: ['NO-CHARGE', 'NO-CHARGE-2'] }]);
  assert.ok(renderReport(twice).includes('in the window of NO-CHARGE, NO-CHARGE-2; it may have gone by a channel the declaration leaves out, so those passes read channels-undeclared.</p>'));
  assert.deepEqual(renderSarif(queued).runs[0].properties.channels.unlisted, [{ observer: 'audit', type: 'sqlite-audit', rows: ['NO-CHARGE'] }]);
  // Listing it again reads the same entry as that channel's (it names no channel, so it belongs to the observer's channel).
  assert.deepEqual(channelReadings(recorded(confine(declare(await assess(honest)), { allow: DB_PORT }), 'sqlite-audit', 'audit', { operation: 'insert', name: 'charge.queued', resource: 'jobs/charge-1' })),
    [{ id: 'NO-CHARGE', reasons: ['channel-unaccounted:jobs'] }]);
  // An entry on a declared channel's name belongs to that channel, whoever recorded it; an open one counts, a refused one does not.
  assert.deepEqual(channelReadings(recorded(structuredClone(base), 'sqlite-audit', 'audit', { operation: 'insert', name: 'orders', resource: 'orders/o-1' })), [{ id: 'NO-CHARGE', reasons: ['channel-unaccounted:orders-db'] }]);
  // An open entry arrives only in a partial window (collectWindow marks a window with an action in flight so), and a committed one
  // in a partial window (one the audit observer truncated at its row limit) still happened: both count, whatever the unlisted
  // window's coverage or reason.
  for (const outcome of ['unknown', 'started', 'committed']) {
    const inFlight = structuredClone(base);
    Object.assign(row(inFlight, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === 'sqlite-audit-audit'), { coverage: 'partial', reason: outcome === 'committed' ? 'audit-row-limit' : 'action-in-flight-at-window-end' });
    assert.deepEqual(channelReadings(recorded(inFlight, 'sqlite-audit', 'audit', { operation: 'insert', name: 'charge.queued', resource: 'jobs/charge-1', outcome })), [{ id: 'NO-CHARGE', reasons: ['channels-undeclared'] }], outcome);
  }
  assert.deepEqual(channelReadings(recorded(structuredClone(base), 'sqlite-audit', 'audit', { operation: 'insert', name: 'charge.queued', resource: 'jobs/charge-1', outcome: 'denied' })), []);
  // A passing bounding clause of the check that selects the entry accounts for it.
  const counted = structuredClone(queued);
  row(counted, 'NO-CHARGE').trace[1].data.effects.push({ kind: 'effect.count', select: { source: 'sql-audit-table', operation: 'insert', name: 'charge.queued' }, expected: 1, verdict: 'pass' });
  assert.deepEqual(channelReadings(counted), []);
  // An observer of a type that observes no channel (the app's own request log) is not a channel left out.
  const logged = structuredClone(base);
  logged.observers = [...logged.observers, { id: 'requests', type: 'audit-file', settleMs: 300 }];
  row(logged, 'NO-CHARGE').trace[1].data.windows.push({ ...structuredClone(row(logged, 'NO-CHARGE').trace[1].data.windows.find(w => w.instanceId === 'sqlite-audit-audit')), instanceId: 'audit-file-requests', source: 'file-audit-log',
    events: [makeEffect({ source: 'file-audit-log', observer: { kind: OBSERVER_OUTPUT['audit-file'].kind, instanceId: 'audit-file-requests' }, seq: ++seq, operation: 'insert', name: 'charge.queued', resource: 'jobs/charge-1', outcome: 'committed', content: { b: 1 } })] });
  assert.deepEqual(channelReadings(logged), []);
});

test('a declaration the saved run carries but that does not read withholds every absence pass (channels-undeclared)', async () => {
  const base = await assess(honest);
  const edited = confine({ ...base, channels: { ...DECLARED, list: [{ id: 'orders-db', kind: 'store', observedBy: ['ghost'], names: ['orders'] }] } });
  assert.deepEqual(channelReadings(edited), [{ id: 'NO-CHARGE', reasons: ['channels-undeclared'] }]);
  assert.equal(channelStatement(edited).readable, false);
  assert.match(renderReport(edited), /does not read against its declared observers; every absence pass reads channels-undeclared/);
});

test('the report, SARIF and the comparison read a withheld pass as inconclusive, with its reasons', async () => {
  const candidate = confine(declare(await assess(honest), withChannel(CACHE)));
  const report = renderReport(candidate);
  assert.ok(report.includes('<p><strong>Not clean on declared channels:</strong> NO-CHARGE (channel-unobserved:cache) passed an absence check'));
  assert.ok(report.includes('The gate reads channel-unobserved:cache.</p>'));
  assert.ok(report.includes('<p><strong>Read as inconclusive</strong> on the declared channels: channel-unobserved:cache. The sealed status is pass;'));
  assert.ok(report.includes('<li>cache: store (sessions), observed by nothing. Not observed in the window of NO-CHARGE.</li>'));
  assert.ok(report.includes('<li>orders-db: store (orders), reached at allowlisted port 5432, observed by db. Custody of the observing windows: subject-writable. Read from net change between snapshots'));
  const sarif = renderSarif(candidate).runs[0], result = sarif.results.find(r => r.ruleId === 'NO-CHARGE');
  assert.deepEqual([result.kind, result.level, result.properties.scopehavenStatus], ['open', 'none', 'pass']);
  assert.deepEqual(result.properties.scopehavenChannels, { reading: 'inconclusive', reasons: ['channel-unobserved:cache'] });
  assert.match(result.message.text, /^INCONCLUSIVE ON DECLARED CHANNELS: .* Reasons: channel-unobserved:cache\.$/);
  assert.deepEqual(sarif.properties.channels.withheld, [{ id: 'NO-CHARGE', reasons: ['channel-unobserved:cache'] }]);
  assert.equal(sarif.results.find(r => r.ruleId === 'ALLOWED-CHARGE').kind, 'pass');
  // A baseline fail repaired to a pass the channels do not support is not fixed: it reads unverified.
  const baseline = confine(declare(await assess(defect), withChannel(CACHE)));
  const comparison = compareRuns(baseline, candidate);
  const compared = comparison.rows.find(r => r.id === 'NO-CHARGE');
  assert.deepEqual([compared.before, compared.after, compared.transition, compared.transitionReason], ['fail', 'pass', 'unverified', 'candidate-channel-unobserved']);
  assert.equal(comparison.summary.fixed, 0);
  assert.ok(comparison.reasons.some(r => r.startsWith('A candidate absence pass is not supported by the declared channels (NO-CHARGE)')));
  const doc = comparisonDocument(baseline, candidate, comparison);
  assert.deepEqual(doc.comparison.rows.find(r => r.id === 'NO-CHARGE').channels, { baseline: [], candidate: ['channel-unobserved:cache'] });
  assert.ok(renderComparisonReport(doc).includes('<li>NO-CHARGE. Candidate: read inconclusive (channel-unobserved:cache). Baseline: not withheld on declared channels.</li>'));
  // A baseline pass the channels did not support (its jobs window was partial) was never shown, so a later pass is not preserved.
  const gapped = confine(declare(await assess(honest, { coverage: (o, w) => o === 'audit' && w === 1 ? 'partial' : null })), { allow: DB_PORT });
  const preserved = compareRuns(gapped, confine(declare(await assess(honest)), { allow: DB_PORT })).rows.find(r => r.id === 'NO-CHARGE');
  assert.deepEqual([preserved.transition, preserved.transitionReason], ['unverified', 'baseline-channel-unobserved']);
  // A fail after a withheld baseline pass is still a regression: the comparison never hides a new failure.
  const regressed = compareRuns(gapped, confine(declare(await assess(defect)), { allow: DB_PORT }));
  assert.deepEqual([regressed.rows.find(r => r.id === 'NO-CHARGE').transition, regressed.summary.newFailures], ['regression', 1]);
  // With every channel observed on both sides, the repair stands.
  const clean = compareRuns(confine(declare(await assess(defect)), { allow: DB_PORT }), confine(declare(await assess(honest)), { allow: DB_PORT })).rows.find(r => r.id === 'NO-CHARGE');
  assert.equal(clean.transition, 'contract-restored');
});

test('a run that gained, shed or edited its declaration never compares as the other\'s peer', async () => {
  const baseline = confine(declare(await assess(defect), withChannel(CACHE)));
  const repaired = confine(declare(await assess(honest), withChannel(CACHE)));
  const { channels, ...stripped } = repaired;
  for (const candidate of [stripped, { ...repaired, channels: DECLARED }]) {
    const comparison = compareRuns(baseline, candidate);
    assert.equal(comparison.compatible, false);
    assert.ok(comparison.reasons.includes('Declared effects, evidence requirements or observers differ between the runs.'));
    assert.equal(comparison.rows.find(r => r.id === 'NO-CHARGE').transition, 'incompatible');
  }
});
