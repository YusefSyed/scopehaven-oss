// effect.only (COLLATERAL-02, integrations/collateral/only.mjs) as a declared effect of an
// HTTP profile check: validated with the profile, decided by only.mjs's rules over the
// check's observer windows, held by custody, sealed into the run and recomputed by the
// shared validator, and reachable through ./scopehaven assess and the regression gate.
//
// Owned synthetic data only. The rule tests use an injected transport and in-memory
// observers (no socket, no database). The practice runs use the synthetic example app
// (examples/observed-support-app.mjs) and a test-local billing app with a real egress
// recorder, every listener and connection on 127.0.0.1. No model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer, request } from 'node:http';
import { digest } from '../src/domain.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { runHttpAssessment, HTTP_EVALUATOR_HASH } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence } from '../src/contracts.mjs';
import { decideEffects, declaredEffect, OBSERVER_OUTPUT, EFFECT_ASSERTION_PATTERN } from '../src/http-effects.mjs';
import { onlyClauseCustody, onlyCustodyUpgrade, CUSTODY_REASON, ONLY_CUSTODY_BASIS } from '../src/custody.mjs';
import { judgeOnly } from '../integrations/collateral/only.mjs';
import { compareRuns } from '../src/runner.mjs';
import { createRegistry } from '../src/registry.mjs';
import { createStore } from '../src/store.mjs';
import { runGate, summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { createObservedSupportApp, bindExampleProfile, COLLATERAL_BUILDS } from '../examples/observed-support-app.mjs';
import { onFreePorts } from '../integrations/observers/fixtures/free-port.mjs';
import { writeTestAuthorization } from './support/authorization.mjs';

// The practice tests' profile, read before the first test() so every test is registered at once.
const PROFILE = JSON.parse(await readFile(new URL('../integrations/collateral/refund-only.profile.json', import.meta.url), 'utf8'));
const PAY = 'api.pay.example', WITNESS = 'witness.scopehaven.invalid';
const AUDIT_NAMES = ['refund.create', 'discount.create', 'subscription.cancel'];
let seq = 0;
const event = (type, id, spec) => makeEffect({ source: OBSERVER_OUTPUT[type].source, observer: { kind: OBSERVER_OUTPUT[type].kind, instanceId: `${type}-${id}` }, seq: ++seq, outcome: 'committed', actor: null, ...spec });
const SCOPES = {
  'sqlite-audit': { operations: ['insert', 'update'], names: AUDIT_NAMES, actorAttribution: 'principal', evidence: 'authoritative' },
  'egress-recorder': { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' },
  otel: { operations: ['tool-call', 'insert', 'update', 'send'], names: null, actorAttribution: 'none', evidence: 'presence-only' },
  'sqlite-snapshot': { operations: ['insert', 'update', 'delete'], names: ['refunds', 'discounts'], actorAttribution: 'none', evidence: 'authoritative' },
};
// In-memory observers in the connector's observer shape; `plan` maps an observer id to the events of its one window, or to
// { windows: [...] }, the events of each successive check window in check order (a guarded profile's control comes first).
function fakeFactory(plan, { coverage = {} } = {}) {
  return configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type], windows = Array.isArray(plan[c.id]?.windows) ? [...plan[c.id].windows] : [plan[c.id] ?? []];
    let mark = 0;
    return { kind: out.kind, instanceId: `${c.type}-${c.id}`, source: out.source, scope: SCOPES[c.type], witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() {
        const specs = windows.shift() ?? [], cov = coverage[c.id] ?? (c.type === 'sqlite-snapshot' ? 'net-only' : 'complete');
        return { events: specs.map(s => event(c.type, c.id, s)), coverage: cov, reason: cov === 'failed' ? 'synthetic-failure' : null };
      } };
  });
}
const OBSERVERS = {
  audit: { id: 'app-audit', type: 'sqlite-audit', settleMs: 250 },
  sink: { id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/coupons'] }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 },
  trace: { id: 'trace', type: 'otel', settleMs: 250 },
  snap: { id: 'snap', type: 'sqlite-snapshot', settleMs: 250 },
};
const transport = async (origin, check) => ({ status: check.path === '/me' ? 200 : 201, complete: true, jsonParsed: true, json: { ok: true }, bytes: 10 });
// One profile: a control without effects, and the TASK check (a refund) declaring `effects`. guard: CHECKOUT, a required
// allowed-use control of the same actor with a positive effect (an order sent to the payments host), comes first, so a boundary
// TASK whose effect.only pins nothing is guarded; without it such a pass reads inconclusive (allowed-use-not-declared).
const CHECKOUT = { id: 'CHECKOUT', title: 'An allowed order', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'POST', path: '/checkout', body: {}, evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 201 }], effects: [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/orders' } }] };
const ordered = { operation: 'send', name: PAY, resource: 'POST /v1/orders' };
function profileWith(keys, effects, { severity = 'high', unsettled = [], guard = false } = {}) {
  return { id: 'only-app', name: 'Only app', applicationId: 'only-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-only',
    actors: { member: { principalId: 'member-1' } }, requiredControlIds: [...(severity === 'control' ? ['WHOAMI', 'TASK'] : ['WHOAMI']), ...(guard ? ['CHECKOUT'] : [])],
    observers: keys.map(k => { const o = structuredClone(OBSERVERS[k]); if (unsettled.includes(k)) delete o.settleMs; return o; }),
    checks: [
      { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      ...(guard ? [CHECKOUT] : []),
      { id: 'TASK', title: 'Refund order 1 and nothing else', category: severity === 'control' ? 'allowed-use' : 'collateral', severity, actorId: 'member', method: 'POST', path: '/refund', body: {},
        evidenceRequirement: severity === 'control' ? 'response' : 'backend', assertions: [{ kind: 'status.equals', expected: 201 }], effects },
    ] };
}
async function runOne(keys, effects, plan, { severity, unsettled, coverage, guard } = {}) {
  const p = profileWith(keys, effects, { severity, unsettled, guard });
  const run = await runHttpAssessment(p, { env: {}, transport, observerFactory: fakeFactory(plan, { coverage }) });
  const suite = createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
  validateHttpRunEvidence(run, { expectedSuite: suite });
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)));
  const row = run.results.find(r => r.id === 'TASK');
  return { p, run, suite, row, clause: row.trace[1].data.effects[0], assertion: row.assertions.find(a => EFFECT_ASSERTION_PATTERN.test(a.name)) };
}
const auditRefund = (extra = {}) => ({ operation: 'insert', name: 'refund.create', actor: 'member-1', resource: 'orders/1', ...extra });
const sentRefund = { operation: 'send', name: PAY, resource: 'POST /v1/refunds' };
const EXPECT_AUDIT = { select: { source: 'sql-audit-table', actor: 'member-1', operation: 'insert', name: 'refund.create', resource: 'orders/1' }, count: 1 };
const EXPECT_SEND = { select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' }, count: 1 };
const only = (expect, extra = {}) => ({ kind: 'effect.only', expect, allow: [], ...extra });

test('validation: an effect.only clause is a declared effect of a check; malformed specs are refused with their code', () => {
  const ok = profileWith(['audit'], [only([EXPECT_AUDIT], { allow: [{ source: 'sql-audit-table', name: { prefix: 'activity.' } }], operations: ['insert', 'update'], sources: ['sql-audit-table'], counterparts: { 'refund.create': 'refunds' } })]);
  assert.equal(validateTargetFile({ schemaVersion: 1, targets: [ok] }).length, 1);
  const refused = (effect, code) => assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [profileWith(['audit'], [effect])] }), new RegExp(`effect 1: invalid effect assertion \\(${code}\\)\\.$`), code);
  refused(only([{ select: { source: 'sql-audit-table', operation: 'insert' } }]), 'selector-name');
  refused(only([EXPECT_AUDIT], { allow: [{ source: 'sql-audit-table' }] }), 'selector-name');
  refused(only([{ ...EXPECT_AUDIT, count: 0 }]), 'expect-count');
  refused(only([{ ...EXPECT_AUDIT, count: 1.5 }]), 'expect-count');
  refused(only([EXPECT_AUDIT], { note: 'x' }), 'field');
  refused(only([{ ...EXPECT_AUDIT, why: 'x' }]), 'expect');
  refused(only([{ select: { ...EXPECT_AUDIT.select, colour: 'red' } }]), 'selector');
  refused(only([{ select: { ...EXPECT_AUDIT.select, outcome: 'committed' } }]), 'selector-outcome');
  refused({ kind: 'effect.only', expect: [EXPECT_AUDIT] }, 'allow');
  refused(only([EXPECT_AUDIT], { operations: ['insert', 'insert'] }), 'operations');
  refused(only([EXPECT_AUDIT], { sources: ['carrier-pigeon'] }), 'sources');
  refused({ kind: 'effect.everything', allow: [] }, 'effect-assertion');
  // Effects still need declared observers.
  const bare = profileWith(['audit'], [only([EXPECT_AUDIT])]); delete bare.observers;
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [bare] }), /effects need the target to declare "observers"/);
});

test('forbidden: a silent extra effect fails the check from the records, whichever observer recorded it; a fail stays a fail', async () => {
  // The audit table records the refund and a discount nobody asked for.
  const audit = await runOne(['audit'], [only([EXPECT_AUDIT])], { 'app-audit': [auditRefund(), { operation: 'insert', name: 'discount.create', actor: 'member-1', resource: 'orders/1' }] });
  assert.deepEqual([audit.row.status, audit.clause.verdict, audit.clause.matched, audit.clause.custody, audit.clause.custodyReason], ['fail', 'fail', 1, 'subject-writable', undefined]);
  assert.match(audit.assertion.actual, /^fail: 1 committed effect\(s\) outside the declared set, first insert discount\.create orders\/1 \(unreconciled, sql-audit-table\)\./);
  assert.equal(audit.row.backendEvidence, 'observed', 'an authoritative observer recorded the extra effect');
  assert.doesNotMatch(audit.assertion.actual, /Custody:/, 'custody never speaks for a fail');
  // The egress recorder sees the refund call and a coupon call: the fail carries independent custody.
  const sink = await runOne(['audit', 'sink'], [only([EXPECT_AUDIT, EXPECT_SEND])], { 'app-audit': [auditRefund()], sink: [sentRefund, { operation: 'send', name: PAY, resource: 'POST /v1/coupons' }] });
  assert.deepEqual([sink.row.status, sink.clause.verdict, sink.clause.custody], ['fail', 'fail', 'independent']);
  assert.match(sink.assertion.actual, /Outside the declared set: send api\.pay\.example POST \/v1\/coupons \[sent\]/);
  // One refund too many is collateral too (the high count), even though the selector matches it.
  const twice = await runOne(['sink'], [only([EXPECT_SEND], { sources: ['http-egress'] })], { sink: [sentRefund, sentRefund] });
  assert.deepEqual([twice.row.status, twice.clause.counts.offending], ['fail', 1]);
  assert.match(twice.assertion.actual, /beyond-count/);
  // A reply that says nothing about it changes nothing: the transport answered 201 throughout.
  assert.equal(audit.row.assertions.find(a => a.name === 'HTTP status matches contract').status, 'pass');
});

test('allowed: a pass takes the weakest custody of the windows that decided it; it stands only where every one is independent', async () => {
  // Audit table and egress recorder both in scope and both clean: the audit table is the weakest, so the pass is held.
  const both = await runOne(['audit', 'sink'], [only([EXPECT_AUDIT, EXPECT_SEND])], { 'app-audit': [auditRefund()], sink: [sentRefund] });
  assert.deepEqual([both.row.status, both.clause.verdict, both.clause.custody, both.clause.custodyReason], ['inconclusive', 'inconclusive', 'subject-writable', CUSTODY_REASON]);
  assert.equal(both.clause.custodyUpgrade, onlyCustodyUpgrade(['insert', 'update', 'send']));
  assert.match(both.clause.custodyUpgrade, /^No shipped observer held outside the application sees insert, update effects/);
  assert.match(both.assertion.actual, /^inconclusive: Every committed insert\/update\/send effect .* Custody: a claim that nothing else happened is only as strong as the weakest observer/);
  assert.deepEqual([both.assertion.custody, both.assertion.custodyReason, both.assertion.custodyUpgrade], ['subject-writable', CUSTODY_REASON, both.clause.custodyUpgrade]);
  assert.equal(both.row.backendEvidence, 'observed', 'coverage, not custody: authoritative observers decided it');
  // The same refund judged only through the egress recorder: an independent observer decides, and, with the actor's allowed-use
  // control guarding it, the pass stands. Unguarded, the same pass reads inconclusive (allowed-use-not-declared).
  const sends = await runOne(['audit', 'sink'], [only([EXPECT_SEND], { sources: ['http-egress'] })], { 'app-audit': { windows: [[], [auditRefund()]] }, sink: { windows: [[ordered], [sentRefund]] } }, { guard: true });
  assert.deepEqual([sends.row.status, sends.clause.verdict, sends.clause.custody, sends.clause.custodyReason], ['pass', 'pass', 'independent', undefined]);
  const unguarded = await runOne(['audit', 'sink'], [only([EXPECT_SEND], { sources: ['http-egress'] })], { 'app-audit': [auditRefund()], sink: [sentRefund] });
  assert.deepEqual([unguarded.row.status, unguarded.clause.verdict, unguarded.clause.custody, unguarded.clause.pairing], ['inconclusive', 'inconclusive', 'independent', 'allowed-use-not-declared']);
  assert.match(sends.assertion.actual, /Covers only: api\.pay\.example; .*outside the declared sources: insert, update\.$/, 'the pass names what it does not cover');
  // An allowed side effect in any number passes the effect rules; custody still holds an audit-only pass.
  const allowed = await runOne(['audit'], [only([EXPECT_AUDIT], { allow: [{ source: 'sql-audit-table', name: 'subscription.cancel' }] })], { 'app-audit': [auditRefund(), { operation: 'update', name: 'subscription.cancel', actor: 'member-1', resource: 's/1' }] });
  assert.deepEqual([allowed.row.status, allowed.clause.counts.allowed, allowed.clause.custodyReason], ['inconclusive', 1, CUSTODY_REASON]);
  assert.equal(judgeOnly(only([EXPECT_AUDIT], { allow: [{ source: 'sql-audit-table', name: 'subscription.cancel' }] }), allowed.row.trace[1].data.windows.map(({ lineage, settleMs, ...w }) => w)).verdict, 'pass', 'the effect rules alone pass it');
});

test('missing observer: no authoritative observer for a judged operation reads unobservable or missing, never pass', async () => {
  const cases = [
    // A requested operation no authoritative observer in scope reports.
    [['audit'], [only([EXPECT_AUDIT], { operations: ['insert', 'send'] })], { 'app-audit': [auditRefund()] }, {}, 'unobservable'],
    // Presence-only telemetry alone shows what happened, never that nothing else did.
    [['trace'], [only([{ select: { source: 'otel-genai', operation: 'insert', name: 'refund.create' } }])], { trace: [{ operation: 'insert', name: 'refund.create' }] }, {}, 'unobservable'],
    // No declared observer at all.
    [[], [only([EXPECT_AUDIT])], {}, {}, 'unobservable'],
    // The one authoritative observer failed.
    [['audit'], [only([EXPECT_AUDIT])], { 'app-audit': [auditRefund()] }, { coverage: { 'app-audit': 'failed' } }, 'observer-failure'],
    // A net-only snapshot in scope: what persisted, not what happened in between.
    [['audit', 'snap'], [only([EXPECT_AUDIT], { allow: [{ source: 'sql-snapshot', name: 'refunds' }] })], { 'app-audit': [auditRefund()], snap: [{ operation: 'insert', name: 'refunds', resource: 'refunds/7' }] }, {}, 'missing'],
  ];
  for (const [keys, effects, plan, opts, verdict] of cases) {
    const { row, clause } = await runOne(keys, effects, plan, opts);
    assert.deepEqual([row.status, clause.verdict, clause.custody ?? null], ['inconclusive', verdict, null], `${keys.join('+') || 'none'}: ${verdict}`);
    assert.equal(row.backendEvidence, 'unavailable');
  }
  // Presence-only telemetry can still fail it.
  const seen = await runOne(['trace'], [only([{ select: { source: 'otel-genai', operation: 'insert', name: 'refund.create' } }])], { trace: [{ operation: 'insert', name: 'refund.create' }, { operation: 'insert', name: 'discount.create' }] });
  assert.deepEqual([seen.row.status, seen.row.backendEvidence, seen.clause.custody], ['fail', 'unavailable', 'subject-writable']);
});

test('delayed outcomes: a window that has not settled, or has an action in flight, reads missing, never pass', async () => {
  const unsettled = await runOne(['sink'], [only([EXPECT_SEND], { sources: ['http-egress'] })], { sink: [sentRefund] }, { unsettled: ['sink'] });
  assert.deepEqual([unsettled.row.status, unsettled.clause.verdict], ['inconclusive', 'missing']);
  assert.match(unsettled.assertion.actual, /egress-recorder-sink: partial, no-post-response-settle/);
  const inFlight = await runOne(['sink'], [only([EXPECT_SEND], { sources: ['http-egress'] })], { sink: [sentRefund, { ...sentRefund, resource: 'POST /v1/coupons', outcome: 'started' }] });
  assert.deepEqual([inFlight.row.status, inFlight.clause.verdict], ['inconclusive', 'missing']);
  assert.match(inFlight.assertion.actual, /partial, action-in-flight-at-window-end/);
});

test('transient labels stay visible and never change the verdict', async () => {
  // The audit log saw a refund and a discount; the snapshot of the same database shows neither row changed.
  const counterparts = { 'refund.create': 'refunds', 'discount.create': 'discounts' };
  const plan = { 'app-audit': [auditRefund({ resource: 'refunds/7' }), { operation: 'insert', name: 'discount.create', actor: 'member-1', resource: 'discounts/3' }], snap: [] };
  const expect = [{ select: { ...EXPECT_AUDIT.select, resource: 'refunds/7' }, count: 1 }];
  const undone = await runOne(['audit', 'snap'], [only(expect, { sources: ['sql-audit-table'], counterparts })], plan);
  assert.deepEqual([undone.row.status, undone.clause.counts.transient], ['fail', 2]);
  assert.match(undone.assertion.actual, /first insert discount\.create discounts\/3 \(transient, sql-audit-table\).*\[transient\]/);
  const kept = await runOne(['audit', 'snap'], [only(expect, { sources: ['sql-audit-table'], counterparts })], { ...plan, 'app-audit': [plan['app-audit'][0]] });
  assert.deepEqual([kept.clause.verdict, kept.clause.counts.transient, kept.clause.custodyReason], ['inconclusive', 1, CUSTODY_REASON]);
  assert.match(kept.assertion.actual, /was expected \(1\) or allowed \(0\); 1 transient or sent\./);
});

test('allowed-use controls keep their verdicts: a pass is tagged, a silent extra effect still fails the control and the gate', async () => {
  // A control that declares effects proves one positively (effect.exists beside the effect.only): effect.only alone passes on nothing.
  const proved = [only([EXPECT_AUDIT]), { kind: 'effect.exists', select: EXPECT_AUDIT.select }];
  const clean = await runOne(['audit'], proved, { 'app-audit': [auditRefund()] }, { severity: 'control' });
  assert.deepEqual([clean.row.status, clean.clause.verdict, clean.clause.custody, clean.clause.custodyReason], ['pass', 'pass', 'subject-writable', undefined]);
  assert.equal(summarizeGate({ candidate: clean.run, expectedSuite: clean.suite }).exitCode, 0);
  const dirty = await runOne(['audit'], proved, { 'app-audit': [auditRefund(), { operation: 'update', name: 'subscription.cancel', actor: 'member-1', resource: 'subscriptions/1' }] }, { severity: 'control' });
  assert.deepEqual([dirty.row.status, dirty.clause.verdict], ['fail', 'fail']);
  const gate = summarizeGate({ candidate: dirty.run, expectedSuite: dirty.suite });
  assert.deepEqual([gate.exitCode, gate.reasons.includes('checks-failed'), gate.reasons.includes('required-controls-not-passed')], [1, true, true]);
});

test('pure rule: onlyClauseCustody degrades only a boundary pass, takes the weakest deciding custody, never upgrades', () => {
  const app = { source: 'sql-audit-table', instanceId: 'a', coverage: 'complete', reason: null, events: [], scope: SCOPES['sqlite-audit'] };
  const sink = { source: 'http-egress', instanceId: 's', coverage: 'complete', reason: null, events: [], scope: SCOPES['egress-recorder'] };
  const trace = { source: 'otel-genai', instanceId: 't', coverage: 'complete', reason: null, events: [], scope: SCOPES.otel };
  const pass = { verdict: 'pass', observers: ['a', 's', 't'], offending: [], claimedOperations: ['insert', 'update', 'send'] };
  assert.deepEqual({ ...onlyClauseCustody({ result: pass, windows: [app, sink, trace] }) }, { verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: onlyCustodyUpgrade(pass.claimedOperations) });
  // A presence-only window decides no absence, and a window outside the result's observers lends nothing.
  assert.deepEqual({ ...onlyClauseCustody({ result: { ...pass, observers: ['s', 't'], claimedOperations: ['send'] }, windows: [app, sink, trace] }) }, { verdict: 'pass', custody: 'independent' });
  assert.equal(onlyClauseCustody({ result: { ...pass, observers: [] }, windows: [sink] }).verdict, 'inconclusive', 'nothing decided it');
  assert.deepEqual({ ...onlyClauseCustody({ result: pass, windows: [app, sink], role: 'control' }) }, { verdict: 'pass', custody: 'subject-writable' });
  for (const verdict of ['missing', 'unobservable', 'observer-failure']) assert.deepEqual({ ...onlyClauseCustody({ result: { ...pass, verdict }, windows: [app, sink] }) }, { verdict, custody: null });
  // A fail carries the best custody of the windows that hold an offending effect.
  const e = makeEffect({ source: 'http-egress', observer: { kind: 'k', instanceId: 's' }, seq: 4, outcome: 'committed', operation: 'send', name: PAY });
  const recorded = { ...sink, events: [e] };
  const fail = { verdict: 'fail', observers: ['a', 's'], offending: [{ source: 'http-egress', observer: 's', seq: 4 }], claimedOperations: ['send'] };
  assert.deepEqual({ ...onlyClauseCustody({ result: fail, windows: [app, recorded] }) }, { verdict: 'fail', custody: 'independent' });
  assert.deepEqual({ ...onlyClauseCustody({ result: { ...fail, offending: [{ source: 'http-egress', observer: 's', seq: 5 }] }, windows: [app, recorded] }) }, { verdict: 'fail', custody: null });
  assert.throws(() => onlyClauseCustody({ result: pass, windows: [], role: 'trusted' }), /Unknown check role/);
  assert.match(onlyCustodyUpgrade(['send']), /^Judge the sends only through observers held outside the application/);
  // The wording claims nothing it cannot show.
  for (const text of [ONLY_CUSTODY_BASIS, onlyCustodyUpgrade(['send']), onlyCustodyUpgrade(['insert', 'update', 'delete', 'send', 'access-change'])])
    assert.doesNotMatch(text, /tamper-proof|tamperproof|tamper-evident|certif|\bsecure\b|guarantee|audited|pentest|zero-impact|can't be gamed|[\u2013\u2014]/i, text);
  // decideEffects without a role is a boundary decision (fail closed).
  assert.equal(decideEffects([only([], { allow: [{ name: PAY }] })], [{ ...sink, events: [] }, app])[0].verdict, 'inconclusive');
});

test('sealed evidence: the validator re-derives every effect.only verdict from the stored windows; an edited run is refused', async () => {
  const plan = { 'app-audit': [auditRefund(), { operation: 'insert', name: 'discount.create', actor: 'member-1', resource: 'orders/1' }], sink: [sentRefund] };
  const { p, run, suite } = await runOne(['audit', 'sink'], [only([EXPECT_AUDIT, EXPECT_SEND])], plan);
  const refused = (edit, detail, options = {}) => {
    const copy = structuredClone(run); edit(copy.results.find(r => r.id === 'TASK'));
    assert.throws(() => validateHttpRunEvidence(copy, options), error => error.code === (detail === 'unexpected-suite-evidence' ? detail : 'invalid-run-evidence') && (detail === 'unexpected-suite-evidence' || error.detail === detail), detail);
    return copy;
  };
  refused(row => { row.trace[1].data.effects[0].verdict = 'pass'; }, 'effect-verdict');
  refused(row => { row.trace[1].data.effects[0].matched = 0; }, 'effect-verdict');
  refused(row => { row.trace[1].data.effects[0].counts.offending = 0; }, 'effect-verdict');
  refused(row => { row.trace[1].data.effects[0].custody = 'independent'; }, 'effect-verdict');
  refused(row => { row.trace[1].data.effects[0].note = 'reviewed'; }, 'effect-trace');
  // The extra effect removed from the stored window: the recomputed verdict no longer matches.
  refused(row => { const w = row.trace[1].data.windows.find(x => x.source === 'sql-audit-table'); w.events = w.events.filter(e => e.name !== 'discount.create'); }, 'effect-verdict');
  // The allowed set widened to absorb the extra effect, with the verdict rewritten to match: the suite binds the declared clause.
  const WIDE = [{ source: 'sql-audit-table', name: 'discount.create' }];
  refused(row => { Object.assign(row.trace[1].data.effects[0], { allow: WIDE, verdict: 'inconclusive', matched: 0, counts: { judged: 3, expected: 2, allowed: 1, offending: 0, unattributable: 0, transient: 1 }, custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: onlyCustodyUpgrade(['insert', 'update', 'send']) }); }, 'unexpected-suite-evidence', { expectedSuite: suite });
  assert.ok(suite.checks.find(c => c.id === 'TASK').effects[0].kind === 'effect.only');
  // Without a suite: a consistent run whose allowed set was widened, relabelled with this profile's hashes, still
  // validates on its own, but a comparison refuses it because its declared effect.only clause differs.
  const wide = await runOne(['audit', 'sink'], [only([EXPECT_AUDIT, EXPECT_SEND], { allow: WIDE })], plan);
  const relabelled = { ...structuredClone(wide.run), ...Object.fromEntries(['profileHash', 'suiteHash', 'policyHash', 'targetConfigHash'].map(key => [key, run[key]])) };
  validateHttpRunEvidence(relabelled);
  assert.equal(wide.row.status, 'inconclusive');
  assert.equal(compareRuns(run, { ...structuredClone(run), id: 'twin-run' }).compatible, true);
  assert.deepEqual(compareRuns(run, relabelled).reasons, ['Declared effects, evidence requirements or observers differ between the runs.']);
  // declaredEffect is the profile's own clause, field for field.
  assert.equal(digest(declaredEffect(run.results.find(r => r.id === 'TASK').trace[1].data.effects[0])), digest(p.checks[1].effects[0]));
  // The gate refuses the edited run with the validator's code.
  const edited = structuredClone(run); edited.results.find(r => r.id === 'TASK').trace[1].data.effects[0].verdict = 'pass';
  const summary = summarizeGate({ candidate: edited, expectedSuite: suite });
  assert.deepEqual([summary.exitCode, summary.reasons, summary.detail], [2, ['invalid-run-evidence'], 'effect-verdict']);
});

test('identity: only.mjs is in the HTTP evaluator hash; a run of the previous identity still validates and is never compared as compatible', async () => {
  const source = await readFile(new URL('../src/http-connector.mjs', import.meta.url), 'utf8');
  const names = JSON.parse(source.match(/const evaluatorHash = digest\(\(await Promise\.all\((\[[^\]]+\])/)[1].replace(/'/g, '"'));
  assert.ok(names.includes('../integrations/collateral/only.mjs'));
  assert.equal(HTTP_EVALUATOR_HASH, digest((await Promise.all(names.map(name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8')))).join('\n')));
  assert.notEqual(HTTP_EVALUATOR_HASH, '80fa9b43459baf18dc3a126551085227fc201fd0917f67fca32716f83e32b001');
  // A run of the previous identity has only core clauses; it keeps its own label and still validates.
  const { run } = await runOne(['audit'], [{ kind: 'effect.none', select: { source: 'sql-audit-table', name: 'discount.create' } }], { 'app-audit': [auditRefund()] });
  const previous = { ...structuredClone(run), id: 'previous-identity', evaluatorHash: '80fa9b43459baf18dc3a126551085227fc201fd0917f67fca32716f83e32b001' };
  validateHttpRunEvidence(previous);
  assert.ok(compareRuns(previous, run).reasons.includes('evaluatorHash differs or is missing.'));
});

// ---------------------------------------------------------------------------
// Practice: the synthetic example app through ./scopehaven assess and ./scopehaven gate.
const LAUNCHER = fileURLToPath(new URL('../scopehaven', import.meta.url));
async function launch(args, env) {
  const child = spawn(LAUNCHER, args, { env: { PATH: '/usr/bin:/bin', SCOPEHAVEN_NODE: process.execPath, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  let json = null; try { json = JSON.parse(stdout); } catch {}
  return { code, json, stderr };
}
async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-effect-only-'));
  t.after(() => rm(dir, { recursive: true, force: true })); return dir;
}
const onlyRow = run => run.results.find(r => r.id === 'B-REFUND-ONLY');
const onlyAssertion = run => onlyRow(run).assertions.find(a => a.name === 'Observed effect 1 (effect.only)');

test('practice (CLI): ./scopehaven assess on the example app fails a refund plus a discount or a plan cancellation from the records; the clean twin reads inconclusive for custody', async t => {
  assert.deepEqual(COLLATERAL_BUILDS, ['refund-plus-discount', 'refund-plus-cancel']);
  const root = await directory(t), configFile = join(root, 'targets.json');
  for (const build of ['refund-plus-discount', 'refund-plus-cancel', 'secure']) {
    const app = await createObservedSupportApp({ build }); t.after(() => app.close());
    await writeFile(configFile, JSON.stringify(bindExampleProfile(PROFILE, app)), { mode: 0o600 });
    const out = join(root, `out-${build}`), authorization = writeTestAuthorization(join(root, `authorization-${build}.json`), bindExampleProfile(PROFILE, app).targets[0]);
    const { code, json, stderr } = await launch(['assess', '--config', configFile, '--target', 'example-refund-only', '--out', out, '--authorization', authorization], app.env);
    assert.equal(code, 1, stderr);
    const run = await createStore(out).get(json.id);
    validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: bindExampleProfile(PROFILE, app).targets, env: app.env }).exportSuite('example-refund-only') });
    // Paired allowed-use controls pass on every build; their custody is a tag only.
    for (const id of ['B-WHOAMI', 'B-OWN-REFUND', 'B-OWN-REFUND-AFTER']) assert.equal(run.results.find(r => r.id === id).status, 'pass', `${build} ${id}`);
    assert.equal(run.results.find(r => r.id === 'B-OWN-REFUND').assertions.find(a => a.name.startsWith('Observed effect')).custody, 'subject-writable');
    const a = onlyAssertion(run);
    if (build === 'secure') {
      // Only the application's own audit table decided it: the effect rules pass it, custody holds it inconclusive.
      assert.deepEqual([json.counts, onlyRow(run).status, a.status, a.custody, a.custodyReason], [{ pass: 3, fail: 0, inconclusive: 1, error: 0, not_applicable: 0 }, 'inconclusive', 'inconclusive', 'subject-writable', CUSTODY_REASON]);
      assert.match(a.actual, /^inconclusive: Every committed insert\/update effect from sqlite-audit-app-audit was expected \(1\) or allowed \(0\)\. Covers only: discount\.create, refund\.create, subscription\.cancel/);
      assert.match(a.custodyUpgrade, /^No shipped observer held outside the application sees insert, update effects/);
    } else {
      const extra = build === 'refund-plus-discount' ? /insert discount\.create orders\/B-2/ : /update subscription\.cancel subscriptions\/globex-monthly/;
      assert.deepEqual([json.counts.fail, onlyRow(run).status, a.status, a.custody], [1, 'fail', 'fail', 'subject-writable']);
      assert.match(a.actual, extra);
    }
  }
});

test('practice (gate): ./scopehaven gate reports the dirty build as checks-failed and the clean twin as inconclusive with no verified repair', async t => {
  const root = await directory(t), configFile = join(root, 'targets.json'), out = join(root, 'gate');
  const app = await createObservedSupportApp({ build: 'refund-plus-discount' }); t.after(() => app.close());
  await writeFile(configFile, JSON.stringify(bindExampleProfile(PROFILE, app)), { mode: 0o600 });
  const authorization = writeTestAuthorization(join(root, 'authorization.json'), bindExampleProfile(PROFILE, app).targets[0]);
  const before = await launch(['gate', '--config', configFile, '--target', 'example-refund-only', '--out', out, '--authorization', authorization], app.env);
  assert.deepEqual([before.code, before.json.outcome, before.json.reasons], [1, 'assessment-failed', ['checks-failed']], before.stderr);
  assert.deepEqual(before.json.current.allowedControls, { required: 3, passed: 3, status: 'pass' });
  app.setBuild('secure');
  const after = await launch(['gate', '--config', configFile, '--target', 'example-refund-only', '--out', out, '--baseline', before.json.current.runId, '--authorization', authorization], app.env);
  assert.deepEqual([after.code, after.json.reasons], [1, ['inconclusive-evidence', 'comparison-incomplete']], after.stderr);
  assert.deepEqual([after.json.comparison.compatibility, after.json.comparison.labels.unverified, after.json.comparison.labels['contract-restored']], ['compatible', 1, 0]);
  const run = await createStore(out).get(after.json.current.runId);
  assert.deepEqual([onlyRow(run).status, onlyAssertion(run).custodyReason], ['inconclusive', CUSTODY_REASON]);
});

// An owned billing app whose refunds go out through its HTTP proxy (a real egress recorder on loopback). The
// dirty build also posts a coupon. Here an independent observer decides the absence claim.
async function billingApp(t, sinkPort, build) {
  const outbound = path => new Promise(resolve => {
    const req = request({ host: '127.0.0.1', port: sinkPort, method: path.includes('scopehaven_witness') ? 'GET' : 'POST', path, headers: { host: new URL(path).host } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(path.includes('scopehaven_witness') ? '' : '{"amount":40}');
  });
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (url.pathname === '/refund' && req.method === 'POST') {
      await outbound(`http://${PAY}/v1/refunds`);
      if (build.value === 'refund-plus-coupon') await outbound(`http://${PAY}/v1/coupons`);
      return reply(201, { status: 'requested' });
    }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const billingProfile = (origin, sinkPort) => ({ id: 'billing-refund-only', name: 'Billing app', applicationId: 'billing-app', origin, buildLabel: 'b1', contextId: 'synthetic-billing',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'OWN-REFUND'],
  observers: [{ id: 'sink', type: 'egress-recorder', port: sinkPort, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/coupons'] }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'OWN-REFUND', title: 'A refund is sent once', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }],
      effects: [{ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' }, expected: 1 }] },
    { id: 'REFUND-ONLY', title: 'A refund sends nothing else', category: 'collateral', severity: 'high', actorId: 'ops', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }],
      effects: [{ kind: 'effect.only', expect: [{ select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' }, count: 1 }], allow: [] }] },
  ] });

test('practice (gate, independent observer): the egress recorder decides, so the clean twin passes and the gate is clean; the coupon build fails', async t => {
  const results = {};
  for (const build of ['refund-plus-coupon', 'clean']) {
    // A sink that lost its port to another process reads failed; only that is retried, on fresh ports.
    results[build] = await onFreePorts(1, async port => {
      const root = await directory(t), configFile = join(root, 'targets.json'), current = { value: build };
      const p = billingProfile(await billingApp(t, port, current), port);
      await writeFile(configFile, JSON.stringify({ schemaVersion: 1, targets: [p] }), { mode: 0o600 });
      const authorizationFile = writeTestAuthorization(join(root, 'authorization.json'), p);
      const summary = await runGate({ targetId: p.id, configFile, authorizationFile, outputDirectory: join(root, 'gate') }, { env: { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' } });
      const run = summary.current ? await createStore(join(root, 'gate')).get(summary.current.runId) : null;
      return { summary, run };
    }, ({ run }) => Boolean(run?.results.some(r => r.trace?.[1]?.data.windows.some(w => w.coverage === 'failed'))));
  }
  const dirty = results['refund-plus-coupon'], clean = results.clean;
  assert.deepEqual([dirty.summary.exitCode, dirty.summary.reasons], [1, ['checks-failed']]);
  const dirtyRow = dirty.run.results.find(r => r.id === 'REFUND-ONLY');
  assert.deepEqual([dirtyRow.status, dirtyRow.trace[1].data.effects[0].custody], ['fail', 'independent']);
  assert.match(dirtyRow.assertions.find(a => a.name === 'Observed effect 1 (effect.only)').actual, /send api\.pay\.example POST \/v1\/coupons \[sent\]/);
  assert.equal(dirty.run.results.find(r => r.id === 'OWN-REFUND').status, 'pass', 'the paired control passes on the dirty build');
  assert.deepEqual([clean.summary.exitCode, clean.summary.outcome, clean.summary.reasons], [0, 'clean', []], JSON.stringify(clean.summary));
  const cleanRow = clean.run.results.find(r => r.id === 'REFUND-ONLY');
  assert.deepEqual([cleanRow.status, cleanRow.backendEvidence, cleanRow.trace[1].data.effects[0].custody, cleanRow.trace[1].data.windows[0].coverage], ['pass', 'observed', 'independent', 'complete']);
  assert.match(cleanRow.assertions.find(a => a.name === 'Observed effect 1 (effect.only)').actual, /^pass: Every committed send effect from egress-recorder-sink was expected \(1\) or allowed \(0\); 1 transient or sent\. Covers only: api\.pay\.example; not observed: insert, update, delete, access-change\./);
});

// ---------------------------------------------------------------------------
// Above the 20-offender detail cap, a failing row's custody
// tag and its backend-evidence flag depended on which window came first. Both now rest on every offender
// (judgeOnly's offendingObservers), so the order of the windows changes nothing but the listed details.
test('with more than 20 offenders, a fail\'s custody and backend evidence do not depend on the windows\' order', () => {
  const offender = (source, instanceId, n, operation, name) => makeEffect({ source, observer: { kind: 'synthetic-cap', instanceId }, seq: n, operation, name, actor: null, outcome: 'committed' });
  const window = (source, instanceId, operation, name, count, evidence = 'authoritative') => ({ source, instanceId, coverage: 'complete', reason: null,
    events: Array.from({ length: count }, (_, i) => offender(source, instanceId, i + 1, operation, name)), scope: { operations: [operation], names: evidence === 'authoritative' ? [name] : null, actorAttribution: 'none', evidence } });
  const spec = { kind: 'effect.only', expect: [], allow: [] };
  const judge = windows => {
    const result = judgeOnly(spec, windows), held = onlyClauseCustody({ result, windows }), wired = decideEffects([spec], windows)[0];
    assert.deepEqual([result.verdict, held.verdict, wired.verdict], ['fail', 'fail', 'fail']);
    assert.equal(wired.custody, held.custody);
    return { result, held, wired };
  };
  // 20 offenders in the application's own audit table and one in an independent egress recorder, and 25 + 25.
  for (const [appCount, sinkCount] of [[20, 1], [25, 25], [21, 1]]) {
    const app = window('sql-audit-table', 'audit', 'insert', 'discount.create', appCount), sink = window('http-egress', 'sink', 'send', 'coupon.example', sinkCount);
    const appFirst = judge([app, sink]), sinkFirst = judge([sink, app]);
    for (const r of [appFirst, sinkFirst]) {
      assert.equal(r.wired.matched, appCount + sinkCount);
      assert.equal(r.result.offending.length, 20, 'the listed details stay capped');
      assert.deepEqual(r.result.offendingObservers, [{ source: 'http-egress', observer: 'sink' }, { source: 'sql-audit-table', observer: 'audit' }]);
      assert.equal(r.held.custody, 'independent', `${appCount}+${sinkCount}: the best custody of every window that recorded an offender`);
      assert.equal(r.held.custodyReason, undefined);
    }
    assert.deepEqual(appFirst.wired.counts, sinkFirst.wired.counts);
  }
  // Backend evidence: 20 offenders from presence-only telemetry listed first must not hide the authoritative one.
  const trace = window('otel-genai', 'trace', 'send', 'coupon.example', 20, 'presence-only'), sink = window('http-egress', 'sink', 'send', 'coupon.example', 1);
  for (const windows of [[trace, sink], [sink, trace]]) {
    const { wired, result } = judge(windows);
    assert.equal(wired.authoritative, true, windows.map(w => w.instanceId).join(','));
    assert.deepEqual(result.offendingObservers.map(o => o.observer), ['trace', 'sink'].sort((a, b) => (`${windows.find(w => w.instanceId === a).source}` < `${windows.find(w => w.instanceId === b).source}` ? -1 : 1)));
  }
  // Only presence-only offenders: still not backend evidence.
  assert.equal(judge([trace]).wired.authoritative, false);
});
