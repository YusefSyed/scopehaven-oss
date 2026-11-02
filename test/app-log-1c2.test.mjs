// App-log admissions: countBy clauses read on lines the application writes once per
// application, and an effect.only allow that is a background job's alone (allowBackground), with the job named by its own
// principal and the check's own lines told apart by their correlation token. Admissions still only ever add fails; at the custody
// tier allowBackground is exactly the shape-only allow it expands to. Pure tests over synthetic lines and windows: no socket, no
// file, no model.
import test from 'node:test';
import assert from 'node:assert/strict';
import { makeEffect } from '../src/effect-events.mjs';
import { validateTargetFile } from '../src/contracts.mjs';
import { compileAppLog, readAppLogLine } from '../src/app-log-rules.mjs';
import { admissionsFor, admissionRows, appLogRecords, validAppLogRecords, bindAppLogWindows } from '../src/app-log-verdicts.mjs';

const MAIL = 'mail.example';
const T1 = '2f1c9a1e-7c3b-4a8e-9d2f-1b2c3d4e5f60', T2 = '9a8b7c6d-5e4f-4321-8765-0fedcba98765';
const tok = uuid => uuid.replace(/-/g, '');
const SOURCE = { id: 'digest', select: { actor: 'svc-digest', operation: 'send', name: MAIL, resource: 'POST /v1/messages' } };
const LOG = (extra = {}) => ({ id: 'actions', use: 'admission', log: { file: { path: '/srv/app/actions.jsonl' } },
  fields: { action: '/event', outcome: '/result', actor: '/actor', id: '/id', key: '/key', trace: '/trace' }, outcomes: { committed: ['ok'], error: ['error'] },
  rules: [
    { action: 'message.sent', operation: 'send', vocabulary: 'egress', name: MAIL, resource: 'POST /v1/messages', observedAs: ['http-egress'], lines: 'per-application',
      fields: { '/template': { from: '/params/template', values: { ticket_update: ['ticket_update'], refund_confirmation: ['refund_confirmation'] } } } },
    { action: 'note.added', operation: 'insert', vocabulary: 'named', name: 'notes', observedAs: ['sql-audit-table'] },
  ],
  logActors: { 'member-1': 'u-1', 'svc-digest': 'system' }, ...extra });
const ONLY = (extra = {}) => ({ kind: 'effect.only', allow: [{ source: 'http-egress', operation: 'send', name: MAIL, resource: 'POST /v1/messages', fields: [{ pointer: '/template', equals: 'ticket_update' }] }], allowBackground: ['digest'], ...extra });
const TARGET = ({ log = LOG(), effects = [ONLY()], correlation = true, background = [SOURCE] } = {}) => ({ id: 'app', name: 'App', applicationId: 'app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'c1',
  actors: { member: { principalId: 'member-1' } }, requiredControlIds: ['WHOAMI'],
  ...(correlation ? { correlation: { header: 'x-request-id' } } : {}),
  observers: [{ id: 'mail', type: 'egress-recorder', port: 47220, routing: 'base-url', destinations: [{ host: MAIL, paths: ['/v1/messages'], capture: { pointers: ['/template'] }, ...(correlation ? { correlation: { header: 'x-request-id' } } : {}) }],
    routes: [{ prefix: '/mail/', host: MAIL }, { prefix: '/w/', host: 'witness.scopehaven.invalid' }], witness: { actorId: 'member', method: 'GET', path: '/api/egress-witness', host: 'witness.scopehaven.invalid' }, settleMs: 250 }],
  attribution: { background },
  checks: [{ id: 'WHOAMI', title: 'whoami', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'STATUS', title: 'status', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/status', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 200 }], effects }],
  ...(log ? { appLogs: [log] } : {}) });
const valid = target => validateTargetFile({ schemaVersion: 1, targets: [target] })[0];
const refused = (target, pattern, label) => assert.throws(() => valid(target), pattern, label);
const PROFILE = valid(TARGET());
const RECORDS = (profile = PROFILE) => appLogRecords(profile.appLogs);
const CFG = compileAppLog(PROFILE.appLogs[0], PROFILE);
let seq = 0;
const line = obj => JSON.stringify({ result: 'ok', actor: 'u-1', ...obj });
const entry = (obj, cfg = CFG) => { const { effects: [e] } = readAppLogLine(line(obj), cfg); return makeEffect({ source: 'app-log', observer: { kind: 'app-action-log', instanceId: 'app-log-actions' }, seq: (++seq) * 128, ...e }); };
const message = (template, extra = {}) => entry({ event: 'message.sent', params: { template }, trace: T1, ...extra });
const W = (events, extra = {}, profile = PROFILE) => ({ source: 'app-log', instanceId: 'app-log-actions', scope: RECORDS(profile)[0].scope, coverage: 'complete', reason: null, events, ...extra });
// A decided effect.only clause as the connector stores it (declared fields after normalization, then what custody decided).
const stored = (clause = PROFILE.checks[1].effects[0]) => ({ ...clause, verdict: 'pass', matched: 0, counts: {}, basis: 'b', custody: 'independent', authoritative: true });
const admit = (decisions, events, context = {}, profile = PROFILE) => admissionsFor(decisions, { windows: [], appLogWindows: [W(events, {}, profile)], records: RECORDS(profile), principal: 'member-1',
  background: profile.attribution.background, check: 'STATUS', token: tok(T1), ...context });
// A committed send the egress recorder saw (no known actor), and its window.
const send = actor => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-mail' }, seq: ++seq, actor, operation: 'send', name: MAIL, resource: 'POST /v1/messages', outcome: 'committed' });
const egress = events => ({ source: 'http-egress', instanceId: 'egress-recorder-mail', scope: { operations: ['send'], names: [MAIL], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events });
const jobLine = () => entry({ event: 'message.sent', actor: 'system', params: { template: 'refund_confirmation' } });

// ---------------------------------------------------------------------------------------------------------------------------
// (d) allowBackground: the custody tier reads the shape-only allow; admissions never let it excuse the check's own actor.
test('allowBackground expands into the shape-only allow at load, is recorded on the app log, and validating again changes nothing', () => {
  const clause = PROFILE.checks[1].effects[0];
  assert.equal(Object.hasOwn(clause, 'allowBackground'), false, 'every custody path sees plain allow entries');
  assert.deepEqual(clause.allow[1], { operation: 'send', name: MAIL, resource: 'POST /v1/messages' }, 'the source select without its actor pin');
  assert.deepEqual(PROFILE.appLogs[0].backgroundAllows, [{ check: 'STATUS', effect: 0, allow: 1, source: 'digest' }]);
  assert.deepEqual(valid(PROFILE), PROFILE, 'idempotent');
  // The same clause written with the expanded allow by hand reads the same at the custody tier.
  const explicit = valid(TARGET({ log: null, effects: [{ kind: 'effect.only', allow: [ONLY().allow[0], { operation: 'send', name: MAIL, resource: 'POST /v1/messages' }] }] }));
  assert.deepEqual(valid(TARGET({ log: null })).checks[1].effects, explicit.checks[1].effects, 'without an app log it is exactly that allow');
  assert.deepEqual(RECORDS()[0].reads.backgroundAllows, [{ check: 'STATUS', effect: 0, allow: 1, source: 'digest' }]);
});

test('refused at load: an unknown source, a clause that is not effect.only, and under admission an unpinned or unmapped source or no fields.trace', () => {
  refused(TARGET({ effects: [ONLY({ allowBackground: ['nightly'] })] }), /"allowBackground" \(effect\.only only\) lists/, 'unknown id');
  refused(TARGET({ effects: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: MAIL }, allowBackground: ['digest'] }] }), /"allowBackground" \(effect\.only only\)/, 'effect.none');
  refused(TARGET({ effects: [ONLY({ allowBackground: ['digest', 'digest'] })] }), /distinct/, 'a repeat');
  refused(TARGET({ background: [{ id: 'digest', select: { operation: 'send', name: MAIL, resource: 'POST /v1/messages' } }], log: LOG({ logActors: { 'member-1': 'u-1' } }) }), /pins its "actor"/, 'shape-only source');
  refused(TARGET({ log: LOG({ logActors: { 'member-1': 'u-1' } }) }), /pins its "actor" to a principal "logActors" names/, 'unmapped principal');
  const { trace, ...noTrace } = LOG().fields;
  refused(TARGET({ log: LOG({ fields: noTrace }) }), /declares "fields.trace"/, 'no trace');
  refused(TARGET({ correlation: false }), /"fields.trace" needs the target's "correlation" header/, 'trace without correlation');
  valid(TARGET({ log: LOG({ use: 'record', fields: noTrace }) }));
  refused(TARGET({ log: LOG({ logActors: { 'member-1': 'u-1', 'svc-other': 'x' } }) }), /principals of declared actors .* or the actor pin of a declared background source/, 'a principal nobody declares');
});

test('the reader keeps the trace token of the value the app received, and only a well-formed one', () => {
  assert.equal(message('ticket_update').correlation.settlementToken, tok(T1));
  assert.equal(message('ticket_update', { trace: T1.toUpperCase() }).correlation.settlementToken, undefined, 'not re-cased');
  assert.equal(message('ticket_update', { trace: 'not-a-uuid' }).correlation.settlementToken, undefined);
  assert.equal(message('ticket_update', { trace: undefined }).correlation.settlementToken, undefined);
});

test('the background allow never excuses the check\'s own line; the plain allow still does; told only in a window that names the job, with the own token', () => {
  const clause = stored();
  assert.equal(admit([clause], [message('refund_confirmation')], { token: tok(T1) })[0].entries, 1, 'the own forbidden send, with the own token');
  assert.deepEqual(admit([clause], [message('ticket_update')], { token: tok(T1) }), [null], 'the plain template allow excuses it');
  assert.deepEqual(admit([clause], [message('refund_confirmation', { trace: T2 })], { token: tok(T1) }), [null], 'another trace: could be the job\'s');
  assert.deepEqual(admit([clause], [message('refund_confirmation', { trace: undefined })], { token: tok(T1) }), [null], 'no trace');
  // In this check's own window: custody recorded a send the job could be, and the log names the job on none of its lines.
  assert.deepEqual(admit([clause], [message('refund_confirmation')], { token: tok(T1), windows: [egress([send(null), send(null)])] }), [null], 'the job ran here, logged under the user');
  assert.equal(admit([clause], [message('refund_confirmation'), jobLine()], { token: tok(T1), windows: [egress([send(null), send(null)])] })[0].entries, 1, 'the job named itself here');
  assert.deepEqual(admit([clause], [message('refund_confirmation'), entry({ event: 'message.sent', actor: 'system', result: 'error', params: { template: 'refund_confirmation' } })], { token: tok(T1), windows: [egress([send(null)])] }), [null], 'only a committed job line names it');
  assert.deepEqual(admit([clause], [message('refund_confirmation'), entry({ event: 'note.added', actor: 'system' })], { token: tok(T1), windows: [egress([send(null)])] }), [null], 'only a job line of the source\'s shape names it');
  assert.deepEqual(admit([clause], [message('refund_confirmation')], { token: null }), [null], 'no own token');
  // The job's own lines are never the check's.
  assert.deepEqual(admit([clause], [entry({ event: 'message.sent', actor: 'system', params: { template: 'refund_confirmation' } })], { token: tok(T1) }), [null]);
  // An effect.none against the same shape is held to the same guards.
  const none = { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: MAIL, fields: [{ pointer: '/template', equals: 'refund_confirmation' }] }, verdict: 'inconclusive', matched: 0, basis: 'b', custody: 'independent', authoritative: true };
  assert.equal(admit([none], [message('refund_confirmation')], { token: tok(T1) })[0].entries, 1);
  assert.deepEqual(admit([none], [message('refund_confirmation', { trace: T2 })], { token: tok(T1) }), [null]);
  // Adjacent: the same clause with the expanded allow written by hand (not the background's alone) excuses the own line.
  const explicit = valid(TARGET({ effects: [{ kind: 'effect.only', allow: [ONLY().allow[0], { operation: 'send', name: MAIL, resource: 'POST /v1/messages' }] }] }));
  assert.deepEqual(admit([stored(explicit.checks[1].effects[0])], [message('refund_confirmation')], { token: tok(T1) }, explicit), [null]);
});

test('each row\'s context carries its own token and every other row\'s', () => {
  const row = (id, requestId) => ({ id, principal: 'member-1', requestId, decisions: [], windows: [] });
  const [a, b, c] = admissionRows([row('A', T1), row('B', T2), row('C', 'not-a-uuid')], { background: PROFILE.attribution.background });
  assert.deepEqual([a.token, a.foreign], [tok(T1), [tok(T2)]]);
  assert.deepEqual([b.token, b.foreign], [tok(T2), [tok(T1)]]);
  assert.deepEqual([c.token, c.foreign], [null, [tok(T1), tok(T2)]]);
});

test('a token says which request context wrote a line, not which request caused it: the late-line rule still holds; another check\'s token is that check\'s', () => {
  const none = { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: MAIL, fields: [{ pointer: '/template', equals: 'refund_confirmation' }] }, verdict: 'inconclusive', matched: 0, basis: 'b', custody: 'independent', authoritative: true };
  const earlier = [{ source: 'http-egress', operation: 'send', name: MAIL }];
  assert.deepEqual(admit([none], [message('refund_confirmation')], { token: tok(T1), earlier }), [null], 'its own token, but it fits an earlier check\'s selector');
  assert.equal(admit([none], [message('refund_confirmation', { trace: T2 })], { token: tok(T1), background: [] })[0].entries, 1, 'adjacent: no other check');
  assert.deepEqual(admit([none], [message('refund_confirmation', { trace: T2 })], { token: tok(T1), background: [], foreign: [tok(T2)] }), [null], 'another check\'s token');
});

// ---------------------------------------------------------------------------------------------------------------------------
// (c) countBy on lines written once per application.
test('"lines" is per-application or absent; a key is kept as a run-local digest, never the key', () => {
  refused(TARGET({ log: LOG({ rules: [{ ...LOG().rules[0], lines: 'per-attempt' }] }) }), /"lines" is "per-application"/);
  const a = message('ticket_update', { key: 'k-1' }), b = message('ticket_update', { key: 'k-1' }), c = message('ticket_update', { key: 'k-2' });
  assert.match(a.correlation.requestId, /^key:[0-9a-f]{16}$/);
  assert.equal(a.correlation.requestId, b.correlation.requestId);
  assert.notEqual(a.correlation.requestId, c.correlation.requestId);
  assert.equal(JSON.stringify(a).includes('k-1'), false, 'the key itself is not stored');
  assert.notEqual(message('ticket_update', { key: 1 }).correlation.requestId, message('ticket_update', { key: '1' }).correlation.requestId, 'type-strict');
  assert.match(message('ticket_update', { key: { k: 1 } }).correlation.requestId, /^key:[0-9a-f]{16}$/, 'any bounded JSON value');
  assert.match(message('ticket_update', { key: 'k'.repeat(200) }).correlation.requestId, /^key:[0-9a-f]{16}$/, 'a long provider key');
  assert.equal(message('ticket_update', { key: 'k'.repeat(2000) }).correlation.requestId, 'key:unreadable');
  assert.equal(message('ticket_update', { key: null }).correlation.requestId, undefined, 'no key');
  assert.deepEqual(RECORDS()[0].reads.perApplication, [MAIL]);
});

test('countBy counts applications on per-application lines: one key is one application; a non-opted line or a duplicated window reads nothing', () => {
  const count = expected => ({ kind: 'effect.count', countBy: 'idempotency-key', select: { source: 'http-egress', operation: 'send', name: MAIL }, expected, verdict: 'inconclusive', matched: 0, basis: 'b', custody: 'independent', authoritative: true });
  const keyed = key => message('ticket_update', { key });
  assert.deepEqual(admit([count(1)], [keyed('k-1'), keyed('k-1')]), [null], 'a retry logged twice under one key');
  assert.equal(admit([count(1)], [keyed('k-1'), keyed('k-2')])[0].entries, 2, 'two applications');
  assert.equal(admit([count(1)], [message('ticket_update'), message('ticket_update')])[0].entries, 2, 'two keyless lines, two applications');
  assert.deepEqual(admit([count(2)], [keyed('k-1'), keyed('k-2')]), [null], 'within the count');
  assert.deepEqual(admissionsFor([count(1)], { windows: [], appLogWindows: [W([keyed('k-1'), keyed('k-2')], { coverage: 'partial', reason: 'app-log-duplicate-id' })], records: RECORDS(), principal: 'member-1',
    background: PROFILE.attribution.background, check: 'STATUS', token: tok(T1), confirmed: new Set(['digest']) }), [null], 'a duplicated window');
  // A rule that does not declare per-application lines: its lines may be attempts, so the clause is never read.
  const notOpted = valid(TARGET({ log: LOG({ rules: [{ ...LOG().rules[0], lines: undefined }, LOG().rules[1]] }) }));
  const cfg = compileAppLog(notOpted.appLogs[0], notOpted);
  assert.deepEqual(admit([count(1)], [entry({ event: 'message.sent', params: { template: 'ticket_update' }, trace: T1, key: 'k-1' }, cfg), entry({ event: 'message.sent', params: { template: 'ticket_update' }, trace: T1, key: 'k-2' }, cfg)], {}, notOpted), [null]);
  // effect.only with countBy: applications beyond the expected count.
  const only = { kind: 'effect.only', countBy: 'idempotency-key', expect: [{ select: { source: 'http-egress', operation: 'send', name: MAIL }, count: 1 }], allow: [], verdict: 'pass', matched: 0, counts: {}, basis: 'b', custody: 'independent', authoritative: true };
  assert.deepEqual(admit([only], [keyed('k-1'), keyed('k-1')], { check: 'UPDATE' }), [null]);
  assert.equal(admit([only], [keyed('k-1'), keyed('k-2')], { check: 'UPDATE' })[0].entries, 1);
  const notOptedLine = key => entry({ event: 'message.sent', params: { template: 'ticket_update' }, trace: T1, key }, cfg);
  assert.deepEqual(admit([only], [notOptedLine('k-1'), notOptedLine('k-2')], { check: 'UPDATE' }, notOpted), [null], 'effect.only countBy on a rule without per-application lines');
  // A key the reader could not read: the application cannot be told, so no countBy clause is read on that window.
  assert.deepEqual(admit([count(1)], [keyed('x'.repeat(2000)), keyed('k-2')]), [null]);
  assert.deepEqual(admit([only], [keyed('x'.repeat(2000)), keyed('k-2')], { check: 'UPDATE' }), [null]);
  // A mark that does not point at its background source's exact shape reads nothing.
  assert.deepEqual(admit([only], [keyed('k-1'), keyed('k-2')], { check: 'STATUS' }), [null], 'STATUS effect 1 is marked at allow 2, which this clause lacks');
});

test('records: reads carry perApplication, trace and backgroundAllows, held to the scope and the writer\'s order', () => {
  const ok = RECORDS();
  assert.ok(validAppLogRecords(ok));
  const edit = mutate => { const r = structuredClone(ok); mutate(r[0].reads); return validAppLogRecords(r); };
  assert.equal(edit(reads => { reads.perApplication = ['zz.example']; }), false, 'a name outside the scope');
  assert.equal(edit(reads => { reads.trace = 'yes'; }), false);
  assert.equal(edit(reads => { reads.backgroundAllows.push({ check: 'STATUS', effect: 0, allow: 0, source: 'digest' }); }), false, 'out of order');
  assert.equal(edit(reads => { delete reads.backgroundAllows; }), false);
  assert.equal(edit(reads => { reads.backgroundAllows[0].allow = 127; }), true, 'up to the effect.only selector limit');
  // A sealed app-log event's correlation holds only what the reader writes.
  const ok1 = W([message('ticket_update', { key: 'k-1' })]);
  assert.equal(bindAppLogWindows([ok1], ok).length, 1);
  for (const [label, correlation] of [['a traceId', { traceId: 't-1' }], ['a raw key', { requestId: 'k-1' }], ['a malformed token', { settlementToken: 'abc' }]]) {
    const forged = structuredClone(ok1); forged.events[0].correlation = correlation;
    assert.throws(() => bindAppLogWindows([forged], ok), /effect-trace/, label);
  }
  const untraced = structuredClone(ok); untraced[0].reads.trace = false;
  assert.throws(() => bindAppLogWindows([ok1], untraced), /effect-trace/, 'a token where the log declares no trace');
});

test('the marks are the clause\'s last allow entries, in order; a hand-written mark on an author\'s allow is refused', () => {
  const shape = { operation: 'send', name: MAIL, resource: 'POST /v1/messages' };
  // Hand-written in the normalized form, at the tail: accepted (it is what normalization writes).
  valid(TARGET({ effects: [{ kind: 'effect.only', allow: [ONLY().allow[0], shape] }], log: LOG({ backgroundAllows: [{ check: 'STATUS', effect: 0, allow: 1, source: 'digest' }] }) }));
  // Pointing at an allow before the tail: refused.
  refused(TARGET({ effects: [{ kind: 'effect.only', allow: [shape, ONLY().allow[0]] }], log: LOG({ backgroundAllows: [{ check: 'STATUS', effect: 0, allow: 0, source: 'digest' }] }) }), /the marks are the last 1 allow entries/);
  refused(TARGET({ effects: [{ kind: 'effect.only', allow: [ONLY().allow[0], ONLY().allow[0]] }], log: LOG({ backgroundAllows: [{ check: 'STATUS', effect: 0, allow: 1, source: 'digest' }] }) }), /is not background source digest's shape/);
});
