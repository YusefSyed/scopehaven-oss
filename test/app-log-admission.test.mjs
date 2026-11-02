// App-log admissions (src/app-log-verdicts.mjs, "use": "admission"): the application's own
// log can only make a clause fail, and only on a committed action of the check's own actor in the check's own window that the
// clause forbids. Pure tests over synthetic windows: no socket, no file, no model.
import test from 'node:test';
import assert from 'node:assert/strict';
import { makeEffect, admitScoped, onlyCoverageFor } from '../src/effect-events.mjs';
import { admissionsFor, applyAdmissions, appLogRecords, ownEntries, projectSelector, admissionContexts, restsOnAdmissions, ADMISSION_FINDING } from '../src/app-log-verdicts.mjs';
import { judgeOnly } from '../integrations/collateral/only.mjs';
import { decideEffects } from '../src/http-effects.mjs';
import { settlementFindings } from '../src/http-settlement.mjs';
import { allowedUse, allowedUseLabel, comparisonAllowedUse } from '../src/allowed-use.mjs';

const PAY = 'pay.example', TICKETS = 'tickets.example', MIXED = 'mixed.example';
const DECL = (use = 'admission') => ({ id: 'actions', use, log: { file: { path: '/srv/app/actions.jsonl' } },
  fields: { action: '/event', outcome: '/result', actor: '/actor', target: '/target' }, outcomes: { committed: ['ok'], denied: ['refused'], error: ['error'] },
  rules: [
    { action: 'refund.paid', operation: 'send', vocabulary: 'egress', name: PAY, resource: 'POST /v1/refunds', observedAs: ['http-egress'] },
    { action: 'ticket.mailed', operation: 'send', vocabulary: 'egress', name: TICKETS, resource: 'POST *', observedAs: ['http-egress'], fields: { '/template': { const: 'ticket_update' } } },
    { action: 'note.added', operation: 'insert', vocabulary: 'named', name: 'notes', resource: { from: '/target' }, observedAs: ['sql-audit-table'] },
    // Two rules name MIXED and only one says the egress recorder sees it, so a selector pinned to http-egress on MIXED is unreadable.
    { action: 'mixed.a', operation: 'send', vocabulary: 'egress', name: MIXED, resource: 'POST *', observedAs: ['http-egress'] },
    { action: 'mixed.b', operation: 'send', vocabulary: 'egress', name: MIXED, resource: 'POST *' },
  ],
  logActors: { 'member-1': 'u-1', 'other-1': 'u-2', 'svc-sync': 'system' } });
const RECORDS = (use = 'admission') => appLogRecords([DECL(use)]);
let seq = 0;
const ev = (spec = {}) => makeEffect({ source: 'app-log', observer: { kind: 'app-action-log', instanceId: 'app-log-actions' }, seq: (++seq) * 128, actor: 'member-1', operation: 'send', name: PAY, resource: 'POST /v1/refunds', outcome: 'committed', ...spec });
const TEMPLATE = template => ({ captured: { status: 'captured', values: { '/template': { type: 'string', value: template } } } });
const W = (events, extra = {}) => ({ source: 'app-log', instanceId: 'app-log-actions', scope: RECORDS()[0].scope, coverage: 'complete', reason: null, events, ...extra });
const clause = (kind, select, extra = {}) => ({ kind, select, verdict: 'pass', matched: 0, basis: 'Custody basis.', custody: 'independent', authoritative: true, ...extra });
const NO_PAY = clause('effect.none', { source: 'http-egress', operation: 'send', name: PAY });
const admit = (decisions, events, context = {}) => admissionsFor(decisions, { windows: [], appLogWindows: [W(events)], records: RECORDS(), principal: 'member-1', ...context });

test('an admission: a committed forbidden action of the check\'s own actor in its window makes the clause fail, labelled as the app log\'s', () => {
  const [a] = admit([NO_PAY], [ev()]);
  assert.deepEqual(a, { log: 'actions', entries: 1, contradicts: false });
  const [d] = applyAdmissions([NO_PAY], [a]);
  assert.equal(d.verdict, 'fail');
  assert.equal(d.custody, 'subject-writable', 'the application\'s own record decided it');
  assert.equal(d.authoritative, false);
  assert.deepEqual(d.appLog, { finding: ADMISSION_FINDING, log: 'actions', entries: 1, contradicts: false, custodyVerdict: 'pass' });
  assert.match(d.basis, /the application's own action log \(app log actions\) records 1 committed action/);
  // An authoritative observer that covered the window and saw nothing: the log contradicts it, and the finding says so.
  const egress = { source: 'http-egress', instanceId: 'egress-recorder-sink', scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] };
  assert.equal(admissionsFor([NO_PAY], { windows: [egress], appLogWindows: [W([ev()])], records: RECORDS(), principal: 'member-1' })[0].contradicts, true);
});

test('only the check\'s own principal; another declared actor, an unlisted actor or none is never an admission', () => {
  for (const actor of ['other-1', 'svc-sync', 'unlisted:0123456789abcdef', null]) assert.deepEqual(admit([NO_PAY], [ev({ actor })]), [null], String(actor));
  assert.deepEqual(admit([NO_PAY], [ev()], { principal: undefined }), [null], 'no principal, no admission');
});

test('an entry that fits a declared background source is never an admission; an actor-pinned source never fits the check\'s own actor', () => {
  assert.deepEqual(admit([NO_PAY], [ev()], { background: [{ id: 'sync', select: { operation: 'send', name: PAY } }] }), [null], 'a shape-only source fits');
  // An exact egress resource pin is kept for a name every rule of which is an egress rule with an exact resource (PAY
  // here), so a source on another path of the same host leaves the entry the check's; test/app-log-1c-reads.test.mjs has the rest.
  assert.notEqual(admit([NO_PAY], [ev()], { background: [{ id: 'sync', select: { operation: 'send', name: PAY, resource: 'POST /v1/other' } }] })[0], null, 'an exact pin on another path');
  assert.deepEqual(admit([NO_PAY], [ev()], { background: [{ id: 'sync', select: { operation: 'send', name: PAY, resource: 'POST /v1/refunds' } }] }), [null], 'the same exact path');
  // An actor-pinned source never fits the check's own actor, but a job may log under the requesting user, so an own
  // entry of its shape counts only when the run confirms the source and the line carries the check's own correlation token
  // (test/app-log-1c2.test.mjs); here neither holds, so it is set aside.
  assert.deepEqual(admit([NO_PAY], [ev()], { background: [{ id: 'sync', select: { actor: 'svc-sync', operation: 'send', name: PAY } }] }), [null]);
});

test('an entry that fits an earlier same-principal check\'s selector (its late effect) is never an admission on this check', () => {
  assert.deepEqual(admit([NO_PAY], [ev()], { earlier: [{ source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' }] }), [null]);
  // A selector that cannot be that entry leaves it the check's.
  assert.notEqual(admit([NO_PAY], [ev()], { earlier: [{ source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/other' }] })[0], null);
  // Read as attribution reads a check's selectors (fitsWide): a named rule with no resource maps entries with resource null, and
  // such an entry may be the one an earlier resource-pinned selector describes, so it is set aside.
  const NO_NOTES = clause('effect.none', { source: 'sql-audit-table', operation: 'insert', name: 'notes' });
  const note = () => ev({ operation: 'insert', name: 'notes', resource: null });
  assert.notEqual(admit([NO_NOTES], [note()])[0], null, 'without the earlier check, the entry is this check\'s');
  assert.deepEqual(admit([NO_NOTES], [note()], { earlier: [{ source: 'sql-audit-table', operation: 'insert', name: 'notes', resource: 'notes/7' }] }), [null], 'a resource-pinned earlier selector');
  // A selector left empty once its source, trace and upstream pins are set aside fits every entry.
  for (const earlier of [{ source: 'smtp-capture' }, { source: 'http-egress', traceId: 't-1' }, { upstream: 'applied' }]) assert.deepEqual(admit([NO_PAY], [ev()], { earlier: [earlier] }), [null], JSON.stringify(earlier));
});

test('the validator\'s contexts: earlier selectors come from the same principal\'s earlier rows, their claims included', () => {
  const rowWith = (id, actorId, effects, claims) => ({ id, trace: [{ data: { actorId } }, { data: { effects, ...(claims ? { claims } : {}) } }] });
  const claimSelect = { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' };
  const rows = [rowWith('A', 'member', [], [{ clause: 'effect.exists', select: claimSelect }]), rowWith('B', 'other', [NO_PAY]), rowWith('C', 'member', [NO_PAY])];
  const contexts = admissionContexts(rows, { member: 'member-1', other: 'other-1' });
  assert.deepEqual(contexts.get(rows[0]).earlier, []);
  assert.deepEqual(contexts.get(rows[1]).earlier, [], 'another principal\'s rows are not earlier for it');
  assert.deepEqual(contexts.get(rows[2]).earlier, [claimSelect], 'the claim\'s selector');
  assert.deepEqual(admit([NO_PAY], [ev()], contexts.get(rows[2])), [null], 'so the earlier claim\'s late line is set aside');
  // A malformed sealed clause throws here; the validator refuses it as a trace error (test/app-log-admission-connector.test.mjs).
  assert.throws(() => admissionContexts([rowWith('A', 'member', [{ kind: 'effect.only', expect: 5 }]), rowWith('C', 'member', [NO_PAY])], { member: 'member-1' }));
});

test('denied, error and unknown outcomes are never admissions', () => {
  for (const outcome of ['denied', 'error', 'unknown', 'started']) assert.deepEqual(admit([NO_PAY], [ev({ outcome })]), [null], outcome);
  // Nor beyond a count or outside an only set: a refused second payment is not a second payment.
  const count = clause('effect.count', { source: 'http-egress', operation: 'send', name: PAY }, { expected: 1 });
  const only = { kind: 'effect.only', expect: [{ select: { source: 'http-egress', operation: 'send', name: PAY }, count: 1 }], allow: [], verdict: 'pass', matched: 0, basis: 'b', custody: 'independent', authoritative: true, counts: {} };
  for (const outcome of ['denied', 'error']) assert.deepEqual(admit([count, only], [ev(), ev({ outcome })]), [null, null], outcome);
});

test('kinds: effect.count only over its expected count, never on a duplicated window; effect.exists, countBy and absence never', () => {
  const count = clause('effect.count', { source: 'http-egress', operation: 'send', name: PAY }, { expected: 1 });
  assert.deepEqual(admit([count], [ev()]), [null], 'exactly the expected count');
  assert.equal(admit([count], [ev(), ev()])[0].entries, 2);
  assert.deepEqual(admissionsFor([count], { windows: [], appLogWindows: [W([ev(), ev()], { coverage: 'partial', reason: 'app-log-duplicate-id' })], records: RECORDS(), principal: 'member-1' }), [null]);
  assert.deepEqual(admit([{ ...count, countBy: 'idempotency-key' }], [ev(), ev()]), [null]);
  assert.deepEqual(admit([clause('effect.exists', { source: 'http-egress', operation: 'send', name: PAY }, { verdict: 'inconclusive' })], []), [null]);
  assert.deepEqual(admit([clause('effect.exists', { source: 'http-egress', operation: 'send', name: PAY })], [ev()]), [null]);
  assert.deepEqual(admit([NO_PAY], []), [null], 'nothing in the log is never an admission');
});

test('what the log can name: a source pin only where every rule of the exact name lists it; field pins only from declared constants', () => {
  assert.deepEqual(admit([clause('effect.none', { source: 'sql-snapshot', operation: 'send', name: PAY })], [ev()]), [null], 'unmapped source');
  assert.deepEqual(admit([clause('effect.none', { source: 'http-egress', operation: 'send', name: { prefix: 'pay' } })], [ev()]), [null], 'a prefix with a source pin');
  assert.deepEqual(admit([clause('effect.none', { source: 'http-egress', operation: 'send', name: MIXED })], [ev({ name: MIXED, resource: 'POST *' })]), [null], 'not every rule lists it');
  assert.notEqual(admit([clause('effect.none', { operation: 'send', name: MIXED })], [ev({ name: MIXED, resource: 'POST *' })])[0], null, 'no source pin');
  assert.equal(projectSelector({ source: 'http-egress', name: PAY, operation: 'send' }, RECORDS()[0].projection).source, undefined);
  // Field pins: the rule's constant decides; a different constant or none is never an admission.
  const pinned = equals => clause('effect.none', { source: 'http-egress', operation: 'send', name: TICKETS, fields: [{ pointer: '/template', equals }] });
  assert.notEqual(admit([pinned('ticket_update')], [ev({ name: TICKETS, resource: 'POST *', ...TEMPLATE('ticket_update') })])[0], null);
  assert.deepEqual(admit([pinned('refund_confirmation')], [ev({ name: TICKETS, resource: 'POST *', ...TEMPLATE('ticket_update') })]), [null]);
  assert.deepEqual(admit([pinned('ticket_update')], [ev({ name: TICKETS, resource: 'POST *' })]), [null], 'no constant reads unknown');
  // Upstream and trace pins never match a log entry; a resource the rule does not map never matches either.
  assert.deepEqual(admit([clause('effect.none', { source: 'http-egress', operation: 'send', name: PAY, upstream: 'applied' })], [ev()]), [null]);
  assert.deepEqual(admit([clause('effect.none', { source: 'http-egress', operation: 'send', name: PAY, traceId: 't-1' })], [ev()]), [null]);
  assert.deepEqual(admit([clause('effect.none', { source: 'sql-audit-table', operation: 'insert', name: 'notes', resource: 'notes/7' })], [ev({ operation: 'insert', name: 'notes', resource: null })]), [null]);
  assert.notEqual(admit([clause('effect.none', { source: 'sql-audit-table', operation: 'insert', name: 'notes', resource: 'notes/7' })], [ev({ operation: 'insert', name: 'notes', resource: 'notes/7' })])[0], null);
});

test('effect.only: the check\'s own entry outside the set or beyond its count fails it; an allow pinned to a background actor never excuses it', () => {
  const only = allow => ({ kind: 'effect.only', expect: [{ select: { source: 'http-egress', operation: 'send', name: PAY }, count: 1 }], allow, verdict: 'pass', matched: 0, basis: 'b', custody: 'independent', authoritative: true, counts: {} });
  // Events in log order (a window's seq order).
  const extra = () => ev({ name: TICKETS, resource: 'POST *', ...TEMPLATE('ticket_update') });
  assert.equal(admit([only([{ operation: 'send', name: TICKETS, actor: 'svc-sync' }])], [ev(), extra()])[0].entries, 1, 'the strict background allow');
  assert.deepEqual(admit([only([{ operation: 'send', name: TICKETS }])], [ev(), extra()]), [null], 'a plain allow allows it');
  assert.deepEqual(admit([only([])], [ev()]), [null], 'the expected effect within its count');
  assert.equal(admit([only([])], [ev(), ev()])[0].entries, 1, 'beyond its count');
  assert.deepEqual(admit([{ ...only([]), expect: [{ select: { source: 'sql-snapshot', operation: 'insert', name: 'orders' }, count: 1 }] }], [ev()]), [null], 'an expect the log cannot name');
  assert.deepEqual(admit([{ ...only([]), sources: ['sql-audit-table'] }], [ev(), ev()]), [null], 'declared sources the entries are not');
  // A repeated entry id can double a line: "beyond its count" is never read on such a window, as for effect.count.
  const duplicated = (events, reason) => admissionsFor([only([])], { windows: [], appLogWindows: [W(events, { coverage: 'partial', reason })], records: RECORDS(), principal: 'member-1' });
  assert.deepEqual(duplicated([ev(), ev()], 'app-log-duplicate-id'), [null]);
  assert.equal(duplicated([ev(), ev()], 'app-log-unknown-action')[0].entries, 1, 'adjacent: another partial reason still reads');
  // The undecided rule (only.mjs): an entry whose fields cannot be read under a fields-pinned expected selector could be one more
  // of the expected effect, so it is never offending, even where a plain allow fits it. The log reads fields only from a rule's
  // declared constants, so such an entry is never an admission; with the constant it is beyond the count and is one.
  const pinnedExpect = { ...only([{ operation: 'send', name: TICKETS }]), expect: [{ select: { source: 'http-egress', operation: 'send', name: TICKETS, fields: [{ pointer: '/template', equals: 'ticket_update' }] }, count: 1 }] };
  const mailed = extra => ev({ name: TICKETS, resource: 'POST *', ...extra });
  assert.deepEqual(admit([pinnedExpect], [mailed(TEMPLATE('ticket_update')), mailed()]), [null], 'undecided: no constant to read');
  assert.equal(admit([pinnedExpect], [mailed(TEMPLATE('ticket_update')), mailed(TEMPLATE('ticket_update'))])[0].entries, 1, 'adjacent: beyond its count');
  // And the repeated-id rule still holds over it.
  assert.deepEqual(admissionsFor([pinnedExpect], { windows: [], appLogWindows: [W([mailed(TEMPLATE('ticket_update')), mailed(TEMPLATE('ticket_update'))], { coverage: 'partial', reason: 'app-log-duplicate-id' })], records: RECORDS(), principal: 'member-1' }), [null]);
});

test('admissions never make, extend or rescue a pass: every output is the input verdict or fail', () => {
  const verdicts = ['pass', 'fail', 'inconclusive', 'missing', 'unobservable', 'observer-failure'];
  for (const verdict of verdicts) for (const a of [null, { log: 'actions', entries: 1, contradicts: true }]) {
    const d = { ...NO_PAY, verdict };
    const [out] = applyAdmissions([d], [a]);
    assert.ok(out.verdict === verdict || out.verdict === 'fail', `${verdict} -> ${out.verdict}`);
    if (out.verdict === 'pass') assert.ok(verdict === 'pass' && a === null);
    if (verdict === 'fail') assert.equal(out, d, 'a custody fail stays a custody fail, untagged');
  }
});

test('"use": "record" and a failed app-log window decide nothing', () => {
  assert.deepEqual(admissionsFor([NO_PAY], { windows: [], appLogWindows: [W([ev()])], records: RECORDS('record'), principal: 'member-1' }), [null]);
  assert.deepEqual(admissionsFor([NO_PAY], { windows: [], appLogWindows: [W([], { coverage: 'failed', reason: 'app-log-truncated-or-rotated' })], records: RECORDS(), principal: 'member-1' }), [null]);
  assert.equal(ownEntries([ev()], { principal: 'member-1' }).length, 1);
});

test('an allow pinned to a background actor never allows an actor-null send and never lifts a late entry', () => {
  // In-window: the egress recorder names no actor, so an actor-pinned allow cannot be shown to allow the send (missing, never pass).
  const egress = events => ({ source: 'http-egress', instanceId: 'egress-recorder-sink', scope: { operations: ['send'], names: [TICKETS], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events });
  const send = makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' }, seq: 1, actor: null, operation: 'send', name: TICKETS, resource: 'POST /tickets', outcome: 'committed' });
  const spec = allow => ({ kind: 'effect.only', allow, operations: ['send'] });
  assert.equal(judgeOnly(spec([{ operation: 'send', name: TICKETS, actor: 'svc-sync' }]), [egress([send])]).verdict, 'missing');
  assert.equal(judgeOnly(spec([{ operation: 'send', name: TICKETS }]), [egress([send])]).verdict, 'pass');
  // Late (a scoped entry after the witness request): the late-entry lift takes only allows on source, operation, name and resource.
  const late = () => admitScoped({ source: 'http-egress', instanceId: 'egress-recorder-sink', scope: { operations: ['send'], names: [TICKETS], actorAttribution: 'none', evidence: 'authoritative' },
    coverage: 'partial', reason: 'egress-request-after-witness-request', events: [], scoped: [{ codes: ['egress-request-after-witness-request'], name: TICKETS, resource: 'POST /tickets' }] });
  assert.equal(onlyCoverageFor(late(), { expects: [], allows: [{ operation: 'send', name: TICKETS }] }), 'complete');
  assert.equal(onlyCoverageFor(late(), { expects: [], allows: [{ operation: 'send', name: TICKETS, actor: 'svc-sync' }] }), 'partial');
  // Judged late effects (settlement "outsideWindow": "judge"): a later actor-null send counted as the check's own is never
  // allowed by an actor-pinned allow, so the pass is withheld; a plain allow lets it stand with the judged note.
  const expectSel = { source: 'http-egress', operation: 'send', name: TICKETS, resource: 'POST /tickets' };
  const judgedFor = allowActor => {
    const own = egress([makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' }, seq: 1, actor: null, operation: 'send', name: TICKETS, resource: 'POST /tickets', outcome: 'committed' })]);
    const after = egress([makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-sink' }, seq: 2, actor: null, operation: 'send', name: TICKETS, resource: 'POST /other', outcome: 'committed' })]);
    const spec = { kind: 'effect.only', expect: [{ select: expectSel, count: 1 }], allow: [{ source: 'http-egress', operation: 'send', name: TICKETS, resource: 'POST /other', ...allowActor }], sources: ['http-egress'] };
    const row = { effects: decideEffects([spec], [own], { role: 'boundary' }), windows: [own] };
    assert.equal(row.effects[0].verdict, 'pass');
    return settlementFindings([row], [[egress([])], [after]], null, { judge: true });
  };
  assert.deepEqual(judgedFor({ actor: 'svc-sync' }), [['effect-outside-window']]);
  assert.deepEqual(judgedFor({}), [['effect-outside-window-judged']]);
});

test('a fail resting only on admissions is never counted as over-blocking, in the run or in a comparison', () => {
  const admitted = { name: 'Observed effect 1 (effect.none)', status: 'fail', appLog: { finding: ADMISSION_FINDING, log: 'actions', entries: 1, contradicts: false, custodyVerdict: 'pass' } };
  const plain = { name: 'HTTP status matches contract', status: 'fail' }, ok = { name: 'HTTP status matches contract', status: 'pass' };
  const runOf = rows => ({ requiredControlIds: rows.map(r => r.id), results: rows });
  const baseline = runOf([{ id: 'C1', status: 'pass', assertions: [ok] }, { id: 'C2', status: 'pass', assertions: [ok] }, { id: 'C3', status: 'pass', assertions: [ok] }]);
  const candidate = runOf([{ id: 'C1', status: 'fail', assertions: [ok, admitted] }, { id: 'C2', status: 'fail', assertions: [plain] }, { id: 'C3', status: 'fail', assertions: [plain, admitted] }]);
  assert.deepEqual(candidate.results.map(restsOnAdmissions), [true, false, false], 'a row with any other fail does not rest on admissions');
  const summary = allowedUse(candidate);
  assert.deepEqual([summary.controlsFailed, summary.controlsFailedByAdmission, summary.overBlockingRate], [3, 1, 2 / 3]);
  assert.match(allowedUseLabel(summary), /1 failed by an app-log admission/);
  assert.equal(Object.hasOwn(allowedUse(baseline), 'controlsFailedByAdmission'), false, 'absent when none');
  const rows = ['C1', 'C2', 'C3'].map(id => ({ id, before: 'pass', after: 'fail' }));
  const entry = comparisonAllowedUse(baseline, candidate, { compatible: true, rows });
  assert.deepEqual([entry.newlyOverBlocked, entry.newlyFailedByAdmission], [['C2', 'C3'], ['C1']]);
});
