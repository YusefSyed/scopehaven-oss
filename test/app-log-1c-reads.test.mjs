// App-log admissions: rule fields read from the line through a closed word map,
// effect.only judged on the part of the clause the log can read (an entry only when it is provably none of the rest), and a
// background source's exact egress resource kept where both sides name it the same way. Each only lets an admission read more of
// the application's own log; every output is still the input verdict or fail. Pure tests over synthetic lines and windows: no
// socket, no file, no model.
import test from 'node:test';
import assert from 'node:assert/strict';
import { makeEffect } from '../src/effect-events.mjs';
import { validateTargetFile } from '../src/contracts.mjs';
import { compileAppLog, readAppLogLine, appLogReads } from '../src/app-log-rules.mjs';
import { admissionsFor, applyAdmissions, appLogRecords, validAppLogRecords, ownEntries, bindAppLogWindows, ADMISSION_FINDING } from '../src/app-log-verdicts.mjs';

const MAIL = 'mail.example', CRM = 'crm.example';
const TEMPLATE = { from: '/params/template', values: { ticket_update: ['ticket_update', 'TicketUpdate'], refund_confirmation: ['refund_confirmation'], legacy_code: [7] } };
const LOG = (extra = {}) => ({ id: 'actions', use: 'admission', log: { file: { path: '/srv/app/actions.jsonl' } },
  fields: { action: '/event', outcome: '/result', actor: '/actor', id: '/id' }, outcomes: { committed: ['ok'], error: ['error'] },
  rules: [
    { action: 'message.sent', operation: 'send', vocabulary: 'egress', name: MAIL, resource: 'POST /v1/messages', observedAs: ['http-egress'], fields: { '/template': TEMPLATE } },
    { action: 'digest.sent', operation: 'send', vocabulary: 'egress', name: MAIL, resource: 'POST /v1/batch', observedAs: ['http-egress'], fields: { '/template': { const: 'ticket_update' } } },
    { action: 'customer.notified', operation: 'send', vocabulary: 'named', name: 'crm-notify', resource: { from: '/customer' } },
    { action: 'discount.created', operation: 'insert', vocabulary: 'named', name: 'discounts', observedAs: ['sql-audit-table'], distinctFrom: ['http-egress', 'provider-feed', 'smtp-capture'] },
    { action: 'webhook.sent', operation: 'send', vocabulary: 'egress', name: 'hooks.example', resource: 'POST *', observedAs: ['http-egress'] },
  ],
  logActors: { 'member-1': 'u-1', 'svc-digest': 'system' }, ...extra });
const target = (log = LOG()) => ({ id: 'app', name: 'App', applicationId: 'app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'c1',
  actors: { member: { principalId: 'member-1' }, digest: { principalId: 'svc-digest' } }, requiredControlIds: ['WHOAMI'],
  checks: [{ id: 'WHOAMI', title: 'whoami', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }],
  appLogs: [log] });
const valid = log => validateTargetFile({ schemaVersion: 1, targets: [target(log)] })[0];
const refused = (log, pattern, label) => assert.throws(() => valid(log), pattern, label);
const CFG = compileAppLog(LOG());
const line = obj => JSON.stringify({ result: 'ok', actor: 'u-1', ...obj });
const RECORDS = (log = LOG()) => appLogRecords([log]);
let seq = 0;
// An entry as the reader would make it from one line (the record's scope and reads bind it).
const fromLine = (obj, cfg = CFG) => { const { effects: [e] } = readAppLogLine(line(obj), cfg); return makeEffect({ source: 'app-log', observer: { kind: 'app-action-log', instanceId: 'app-log-actions' }, seq: (++seq) * 128, ...e }); };
const W = (events, extra = {}, log = LOG()) => ({ source: 'app-log', instanceId: 'app-log-actions', scope: RECORDS(log)[0].scope, coverage: 'complete', reason: null, events, ...extra });
const clause = (kind, select, extra = {}) => ({ kind, select, verdict: 'pass', matched: 0, basis: 'Custody basis.', custody: 'independent', authoritative: true, ...extra });
const admit = (decisions, events, context = {}, log = LOG()) => admissionsFor(decisions, { windows: [], appLogWindows: [W(events, {}, log)], records: RECORDS(log), principal: 'member-1', ...context });
const pin = (op, operand) => ({ source: 'http-egress', operation: 'send', name: MAIL, fields: [{ pointer: '/template', [op]: operand }] });

// ---------------------------------------------------------------------------------------------------------------------------
// (a) Fields read from the line through a closed word map.
test('a word map validates; a word under two values, a log-field pointer, an unbounded map and a secret-shaped value are refused', () => {
  valid(LOG());
  const withField = field => LOG({ rules: [{ action: 'm', operation: 'send', vocabulary: 'egress', name: MAIL, resource: 'POST /v1/messages', fields: { '/template': field } }] });
  refused(withField({ from: '/t', values: { a: ['x'], b: ['x'] } }), /listed under one value only/, 'one word, two values');
  refused(withField({ from: '/actor', values: { a: ['x'] } }), /none of the log's own fields/, 'the actor pointer');
  refused(withField({ from: '/t', values: {} }), /"fields" maps/, 'no values');
  refused(withField({ from: '/t', values: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`v${i}`, [`w${i}`]])) }), /"fields" maps/, '33 values');
  refused(withField({ from: '/t', values: { a: [] } }), /"fields" maps/, 'a value with no word');
  refused(withField({ from: '/t', values: { a: [{ nested: 1 }] } }), /"fields" maps/, 'a word that is not a scalar');
  refused(withField({ from: '/t', values: { 'sk_live_51Habc': ['x'] } }), /"fields" maps/, 'a secret-shaped value');
  refused(withField({ from: 't', values: { a: ['x'] } }), /"fields" maps/, 'a pointer that is not one');
  refused(withField({ from: '/t', values: { a: ['x'] }, const: 'a' }), /"fields" maps/, 'const and from together');
});

test('the reader captures a listed word\'s selector value; any other word, a missing pointer or a non-scalar captures nothing', () => {
  const captured = obj => readAppLogLine(line({ event: 'message.sent', ...obj }), CFG).effects[0].captured;
  assert.deepEqual(captured({ params: { template: 'TicketUpdate' } }), { status: 'captured', values: { '/template': { type: 'string', value: 'ticket_update' } } });
  assert.deepEqual(captured({ params: { template: 7 } }), { status: 'captured', values: { '/template': { type: 'string', value: 'legacy_code' } } }, 'an integer word');
  for (const params of [{ template: '7' }, { template: 'ticket-update' }, { template: 'TICKET_UPDATE' }, {}, { template: ['ticket_update'] }, { template: { id: 'ticket_update' } }, { template: null }])
    assert.equal(captured({ params }), undefined, JSON.stringify(params));
  // An unlisted word is not a problem of the line: the window stays complete, the field reads unknown.
  assert.deepEqual(readAppLogLine(line({ event: 'message.sent', params: { template: 'other' } }), CFG).problems, []);
  // Constants are unchanged.
  assert.deepEqual(readAppLogLine(line({ event: 'digest.sent' }), CFG).effects[0].captured, { status: 'captured', values: { '/template': { type: 'string', value: 'ticket_update' } } });
});

test('a line-read field decides equals and in; an unlisted word, a range or a type mismatch decides nothing', () => {
  const sent = template => fromLine({ event: 'message.sent', params: { template } });
  assert.deepEqual(admit([clause('effect.none', pin('equals', 'refund_confirmation'))], [sent('refund_confirmation')]), [{ log: 'actions', entries: 1, contradicts: false }]);
  assert.notEqual(admit([clause('effect.none', pin('in', ['refund_confirmation', 'x']))], [sent('refund_confirmation')])[0], null);
  assert.deepEqual(admit([clause('effect.none', pin('equals', 'refund_confirmation'))], [sent('ticket_update')]), [null], 'another mapped value');
  assert.deepEqual(admit([clause('effect.none', pin('equals', 'refund_confirmation'))], [sent('refund-confirmation')]), [null], 'an unlisted word reads unknown');
  assert.deepEqual(admit([clause('effect.none', pin('gt', 3))], [sent(7)]), [null], 'a range on a line-read field: its values are strings');
  assert.deepEqual(admit([clause('effect.none', pin('equals', 7))], [sent(7)]), [null], 'the log word is not the selector value');
  // effect.only: an expected item pinned to the template; an unlisted word is undecided (only.mjs), never offending, even where
  // a plain allow fits it; with a listed other value it is outside the set.
  const only = allow => ({ kind: 'effect.only', expect: [{ select: pin('equals', 'ticket_update'), count: 1 }], allow, verdict: 'pass', matched: 0, basis: 'b', custody: 'independent', authoritative: true, counts: {} });
  assert.deepEqual(admit([only([])], [sent('ticket_update'), sent('mystery')]), [null], 'undecided');
  assert.deepEqual(admit([only([{ source: 'http-egress', operation: 'send', name: MAIL }])], [sent('ticket_update'), sent('mystery')]), [null], 'undecided beside a plain allow');
  assert.equal(admit([only([])], [sent('ticket_update'), sent('refund_confirmation')])[0].entries, 1, 'outside the set');
  const [d] = applyAdmissions([clause('effect.none', pin('equals', 'refund_confirmation'))], admit([clause('effect.none', pin('equals', 'refund_confirmation'))], [sent('refund_confirmation')]));
  assert.deepEqual([d.verdict, d.appLog.finding], ['fail', ADMISSION_FINDING]);
});

test('the validator binds each captured value to its record: one the word map does not name is refused', () => {
  const records = RECORDS();
  assert.deepEqual(records[0].reads.values[MAIL], { '/template': ['ticket_update', 'refund_confirmation', 'legacy_code'] });
  const ok = W([fromLine({ event: 'message.sent', params: { template: 'refund_confirmation' } })]);
  assert.equal(bindAppLogWindows([ok], records).length, 1);
  const forged = structuredClone(ok);
  forged.events[0].captured.values['/template'].value = 'password_reset';
  assert.throws(() => bindAppLogWindows([forged], records), /effect-trace/, 'a value outside the map');
  const typed = structuredClone(ok);
  typed.events[0].captured.values['/template'] = { type: 'number', value: 7 };
  assert.throws(() => bindAppLogWindows([typed], records), /effect-trace/, 'the raw log word, not the selector value');
  const stray = structuredClone(ok);
  stray.events[0].captured.values['/amount'] = { type: 'number', value: 5 };
  assert.throws(() => bindAppLogWindows([stray], records), /effect-trace/, 'an undeclared pointer');
});

// ---------------------------------------------------------------------------------------------------------------------------
// (b) effect.only on the part of the clause the log can read.
test('distinctFrom validates; an unknown source, the app log, a repeat or one of its own observedAs is refused', () => {
  const withRule = distinctFrom => LOG({ rules: [{ action: 'd', operation: 'insert', vocabulary: 'named', name: 'discounts', observedAs: ['sql-audit-table'], distinctFrom }] });
  valid(withRule(['provider-feed']));
  refused(withRule(['payments']), /"distinctFrom" lists/, 'unknown');
  refused(withRule(['app-log']), /"distinctFrom" lists/, 'the app log');
  refused(withRule(['provider-feed', 'provider-feed']), /"distinctFrom" lists/, 'a repeat');
  refused(withRule(['sql-audit-table']), /"distinctFrom" lists/, 'one of its own observedAs');
  refused(withRule([]), /"distinctFrom" lists/, 'empty');
  // A name's distinct sources are the ones every rule producing it declares.
  const two = LOG({ rules: [{ action: 'd1', operation: 'insert', vocabulary: 'named', name: 'discounts', distinctFrom: ['provider-feed', 'smtp-capture'] }, { action: 'd2', operation: 'insert', vocabulary: 'named', name: 'discounts', distinctFrom: ['provider-feed'] }] });
  assert.deepEqual(appLogReads(two).distinct, { discounts: ['provider-feed'] });
  assert.deepEqual(appLogReads(LOG({ rules: [...two.rules, { action: 'd3', operation: 'insert', vocabulary: 'named', name: 'discounts' }] })).distinct, {}, 'a rule without it');
});

test('a selector the log cannot read is dropped only for entries provably not its effect; any other entry is set aside', () => {
  // The clause allows a provider-feed send the log cannot name (its lines carry a customer id, no address) and expects one message.
  const feedAllow = { source: 'provider-feed', operation: 'send', name: 'customers.example' };
  const only = (allow, expect = [{ select: { source: 'http-egress', operation: 'send', name: MAIL, resource: 'POST /v1/messages' }, count: 1 }]) => ({ kind: 'effect.only', expect, allow, verdict: 'pass', matched: 0, basis: 'b', custody: 'independent', authoritative: true, counts: {} });
  const message = () => fromLine({ event: 'message.sent', params: { template: 'ticket_update' } });
  const discount = () => fromLine({ event: 'discount.created' });
  const notified = () => fromLine({ event: 'customer.notified', customer: 'C-7' });
  // The discount's rule says it is never a provider-feed effect: judged, outside the readable set, offending.
  assert.equal(admit([only([feedAllow])], [message(), discount()])[0].entries, 1);
  // The customer-id notification could be the allowed feed send: set aside, never offending (the honest app stays clean).
  assert.deepEqual(admit([only([feedAllow])], [message(), notified()]), [null]);
  // A message is an http-egress effect, which no rule of its name declares distinct from provider-feed: set aside too, so a second
  // message is never read beyond the expected count while the feed allow cannot be read.
  assert.deepEqual(admit([only([feedAllow])], [message(), message()]), [null]);
  // Adjacent: with nothing unreadable the second message is beyond its count.
  assert.equal(admit([only([])], [message(), message()])[0].entries, 1);
  // An expected item the log cannot read gives no count: a judged entry it could not be is offending only if nothing allows it.
  const feedExpect = [{ select: feedAllow, count: 1 }];
  assert.equal(admit([only([], feedExpect)], [discount()])[0].entries, 1, 'provably not the expected feed send');
  assert.deepEqual(admit([only([], feedExpect)], [notified(), notified()]), [null], 'could be the expected send: set aside');
  // A source-pinned selector on a name prefix is never readable on the log: dropped only for entries provably not its effect.
  assert.equal(admit([only([{ source: 'provider-feed', operation: 'send', name: { prefix: 'customers' } }])], [message(), discount()])[0].entries, 1);
  // A repeated entry id still reads nothing.
  assert.deepEqual(admissionsFor([only([feedAllow])], { windows: [], appLogWindows: [W([message(), discount()], { coverage: 'partial', reason: 'app-log-duplicate-id' })], records: RECORDS(), principal: 'member-1' }), [null]);
});

// ---------------------------------------------------------------------------------------------------------------------------
// (e) A background source's exact egress resource.
test('reads.exact names only the names every rule of which is an egress rule with an exact resource', () => {
  assert.deepEqual(appLogReads(LOG()).exact, [MAIL]);
  const mixed = LOG({ rules: [...LOG().rules, { action: 'mail.logged', operation: 'send', vocabulary: 'named', name: MAIL }] });
  assert.deepEqual(appLogReads(mixed).exact, [], 'a named rule of the same name');
});

test('an exact pin is kept for those names; a "<METHOD> *" pin, a wildcard rule and a named rule set the resource aside', () => {
  const digestSource = { id: 'digest', select: { operation: 'send', name: MAIL, resource: 'POST /v1/batch' } };
  const own = fromLine({ event: 'message.sent', params: { template: 'refund_confirmation' } });
  const job = fromLine({ event: 'digest.sent' });
  const exact = RECORDS()[0].reads.exact;
  assert.deepEqual(ownEntries([own, job], { principal: 'member-1', background: [digestSource], exact }), [own], 'the job\'s path is set aside, the own message is the check\'s');
  assert.deepEqual(ownEntries([own, job], { principal: 'member-1', background: [digestSource] }), [], 'adjacent: without the exact names, every line on the host');
  assert.deepEqual(ownEntries([own], { principal: 'member-1', background: [{ id: 'all', select: { operation: 'send', name: MAIL, resource: 'POST *' } }], exact }), [], 'a wildcard pin');
  const hook = fromLine({ event: 'webhook.sent' });
  assert.deepEqual(ownEntries([hook], { principal: 'member-1', background: [{ id: 'h', select: { operation: 'send', name: 'hooks.example', resource: 'POST /other' } }], exact }), [], 'a wildcard rule');
  // End to end over admissionsFor: the own forbidden template is admitted beside the background job's lines.
  const forbid = clause('effect.none', pin('equals', 'refund_confirmation'));
  assert.equal(admit([forbid], [own, job], { background: [digestSource] })[0].entries, 1);
  // The job's own line, logged under the requesting user, is still set aside by its path.
  const jobAsUser = fromLine({ event: 'digest.sent', actor: 'u-1' });
  assert.deepEqual(admit([clause('effect.none', { source: 'http-egress', operation: 'send', name: MAIL, fields: [{ pointer: '/template', equals: 'ticket_update' }] })], [jobAsUser], { background: [digestSource] }), [null]);
});

// ---------------------------------------------------------------------------------------------------------------------------
// Fail-open fixes.
const RECORDER = { id: 'mail', type: 'egress-recorder', port: 47210, routing: 'base-url', destinations: [{ host: MAIL, paths: ['/v1/messages', '/v1/batch'], capture: { pointers: ['/template'] } }, { host: 'hooks.example' }],
  routes: [{ prefix: '/mail/', host: MAIL }, { prefix: '/hooks/', host: 'hooks.example' }, { prefix: '/w/', host: 'witness.scopehaven.invalid' }], witness: { actorId: 'member', method: 'GET', path: '/api/egress-witness', host: 'witness.scopehaven.invalid' }, settleMs: 250 };
const observed = (log, effects = [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: MAIL } }]) => validateTargetFile({ schemaVersion: 1, targets: [{ ...target(log), observers: [RECORDER],
  checks: [...target(log).checks, { id: 'STATUS', title: 'status', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/status', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 200 }], effects }] }] })[0];

test('a clause that pins a word-mapped field with a non-string equals or in operand is refused at load', () => {
  const pinOn = (name, f) => [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name, fields: [{ pointer: '/template', ...f }] } }];
  observed(LOG(), pinOn(MAIL, { equals: 'refund_confirmation' }));
  assert.throws(() => observed(LOG(), pinOn(MAIL, { equals: 7 })), /non-string value/, 'an integer');
  assert.throws(() => observed(LOG(), pinOn(MAIL, { in: ['a', 7] })), /non-string value/, 'a mixed in');
  assert.throws(() => observed(LOG(), [{ kind: 'effect.only', allow: [{ source: 'http-egress', operation: 'send', name: MAIL, fields: [{ pointer: '/template', in: ['x', true] }] }] }]), /non-string value/, 'an effect.only allow');
  observed(LOG(), pinOn('hooks.example', { equals: 7 }));
  observed(LOG(), pinOn(MAIL, { gt: 3 }));
});

test('an earlier check\'s field pins are set aside, so its late allowed line is never this check\'s', () => {
  // Check 1 forbids refund_confirmation and honestly sends ticket_update; that line lands late in check 2's window, which forbids it.
  const late = fromLine({ event: 'message.sent', params: { template: 'ticket_update' } });
  const earlier = [{ source: 'http-egress', operation: 'send', name: MAIL, fields: [{ pointer: '/template', equals: 'refund_confirmation' }] }];
  assert.deepEqual(ownEntries([late], { principal: 'member-1', earlier }), []);
  assert.deepEqual(admit([clause('effect.none', pin('equals', 'ticket_update'))], [late], { earlier }), [null]);
  assert.equal(admit([clause('effect.none', pin('equals', 'ticket_update'))], [late])[0].entries, 1, 'adjacent: no earlier check');
});

test('an egress rule\'s exact path is one the recorder declares for its host', () => {
  const ruleAt = resource => LOG({ rules: [{ action: 'm', operation: 'send', vocabulary: 'egress', name: MAIL, resource, observedAs: ['http-egress'] }] });
  observed(ruleAt('POST /v1/batch'));
  observed(ruleAt('POST *'));
  assert.throws(() => observed(ruleAt('POST /v1/digest')), /a path the egress recorder's destinations for mail\.example do not declare/);
  assert.throws(() => observed(LOG({ rules: [{ action: 'h', operation: 'send', vocabulary: 'egress', name: 'hooks.example', resource: 'POST /x' }] })), /do not declare/, 'a destination with no paths');
});

test('distinctFrom never names the source that records the rule\'s own kind of send', () => {
  refused(LOG({ rules: [{ action: 'm', operation: 'send', vocabulary: 'egress', name: MAIL, resource: 'POST *', distinctFrom: ['http-egress'] }] }), /records its own kind of send/);
  const mail = distinctFrom => LOG({ fields: { ...LOG().fields, target: '/to' }, rules: [{ action: 'e', operation: 'send', vocabulary: 'mail', domains: [{ domain: 'customers.example' }], distinctFrom }] });
  refused(mail(['provider-feed']), /records its own kind of send/);
  refused(mail(['smtp-capture']), /records its own kind of send/);
  valid(mail(['sql-audit-table']));
});

test('names are data: "__proto__" pollutes nothing and "constructor" reads no inherited property', () => {
  const odd = LOG({ rules: [{ action: 'p', operation: 'insert', vocabulary: 'named', name: '__proto__', fields: { '/x': { const: 'y' } }, distinctFrom: ['provider-feed'] },
    { action: 'c', operation: 'insert', vocabulary: 'named', name: 'constructor' }] });
  const reads = appLogReads(odd);
  assert.equal(Object.prototype['/x'], undefined, 'no pollution');
  assert.deepEqual(Object.getOwnPropertyNames(reads.values), ['__proto__']);
  const entry = fromLine({ event: 'c' }, compileAppLog(odd));
  const only = { kind: 'effect.only', allow: [{ source: 'provider-feed', operation: 'send', name: 'customers.example' }], verdict: 'pass', matched: 0, basis: 'b', custody: 'independent', authoritative: true, counts: {} };
  assert.deepEqual(admit([only, clause('effect.none', { source: 'sql-audit-table', operation: 'insert', name: 'constructor' })], [entry], {}, odd), [null, null]);
});

test('mail to an undeclared domain carries no captured record; capture and name bounds hold at load', () => {
  const mail = LOG({ fields: { ...LOG().fields, target: '/to' }, rules: [{ action: 'e', operation: 'send', vocabulary: 'mail', domains: [{ domain: 'customers.example' }], fields: { '/template': { from: '/t', values: { welcome: ['welcome'] } } } }] });
  const read = to => readAppLogLine(line({ event: 'e', to, t: 'welcome' }), compileAppLog(mail)).effects[0];
  assert.equal(read('a@customers.example').captured.values['/template'].value, 'welcome');
  assert.equal(read('a@elsewhere.example').captured, undefined);
  const many = LOG({ rules: [0, 1, 2].map(i => ({ action: `n${i}`, operation: 'insert', vocabulary: 'named', name: 'notes', fields: Object.fromEntries(Array.from({ length: 8 }, (_, j) => [`/f${i}${j}`, { const: 'v' }])) })) });
  refused(many, /at most 16 pointers per name/);
  const wide = LOG({ fields: { ...LOG().fields, target: '/to' }, rules: Array.from({ length: 5 }, (_, i) => ({ action: `m${i}`, operation: 'send', vocabulary: 'mail', domains: Array.from({ length: 60 }, (_, j) => ({ domain: `d${i}x${j}.example` })) })) });
  refused(wide, /at most 256 distinct names/);
});

test('the validator holds a record\'s reads to what appLogReads writes and to its scope', () => {
  const ok = RECORDS();
  assert.ok(validAppLogRecords(ok));
  const edit = mutate => { const r = structuredClone(ok); mutate(r[0].reads, r[0]); return validAppLogRecords(r); };
  assert.equal(edit(reads => { reads.distinct.discounts = ['payments']; }), false, 'an unknown source');
  assert.equal(edit(reads => { reads.distinct.discounts = ['smtp-capture', 'http-egress']; }), false, 'unsorted');
  assert.equal(edit(reads => { reads.distinct['nowhere.example'] = ['provider-feed']; }), false, 'a name outside the scope');
  assert.equal(edit(reads => { reads.exact = [MAIL, 'zz.example']; }), false, 'an exact name outside the scope');
  assert.equal(edit(reads => { reads.values[MAIL]['/other'] = ['x']; }), false, 'a pointer the scope does not capture');
  assert.equal(edit(reads => { delete reads.values[MAIL]; }), false, 'a captured name without values');
  assert.equal(edit(reads => { reads.values[MAIL]['/template'].push('sk_live_51Habc'); }), false, 'a secret-shaped value');
  assert.equal(edit(reads => { reads.values[MAIL]['/template'].push('ticket_update'); }), false, 'a repeated value');
});
