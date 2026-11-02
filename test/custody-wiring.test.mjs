// Custody decides HTTP effect verdicts and sequence
// assertions. Owned synthetic data only: the HTTP runs use an injected transport
// and injected observers (no socket, no database, no model, no provider), and
// the sequence run uses an injected transport and in-memory observers.
//
// The rule (src/custody.mjs): in a boundary check (any severity except
// 'control') every effect clause's pass needs a deciding window held outside the
// application; otherwise it reads inconclusive with reason
// subject-writable-custody. Allowed-use controls carry custody as a tag only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { digest } from '../src/domain.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { runHttpAssessment, HTTP_EVALUATOR_HASH } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { decideEffects, effectAssertionRows, OBSERVER_OUTPUT, LINEAGE_BY_SOURCE as LINEAGE_FROM_EFFECTS } from '../src/http-effects.mjs';
import { LINEAGE_BY_SOURCE } from '../src/effect-lineage.mjs';
import { clauseCustody, custodyUpgrade, decidingWindows, roleOfSeverity, CUSTODY_REASON, CONTROL_CUSTODY_LIMIT } from '../src/custody.mjs';
import * as reExported from '../integrations/evid-subject/custody.mjs';
import * as core from '../src/custody.mjs';
import { FORGERY_MODES, runForgingSubject } from '../integrations/evid-subject/forging-subject.mjs';
import { compareRuns } from '../src/runner.mjs';
import { createRegistry } from '../src/registry.mjs';
import { renderReport, comparisonDocument, renderComparisonReport, CUSTODY_RULE } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { runSequence, decideAssertion, SEQUENCE_SCHEMA } from '../integrations/sequences/sequence.mjs';
import { validateSequenceRun } from '../integrations/sequences/run-validator.mjs';
import { mountDashboard } from '../public/dashboard/dashboard.mjs';
import { CUSTODY_LIMITATION } from '../src/http-scope-text.mjs';
import { applySettlement } from '../src/http-settlement.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';

const PAY = 'api.pay.example', HOOK = 'hooks.chat.example', WITNESS = 'witness.scopehaven.invalid';
const AUDIT_NAMES = ['note.create', 'note.update', 'order.write', 'identity.verify', 'customer.read', 'confirmation.consume', 'approval.grant', 'refund.write', 'refunds.approved', 'refunds.authorized', 'refunds'];
let seq = 0;
const event = (type, id, spec) => makeEffect({ source: OBSERVER_OUTPUT[type].source, observer: { kind: OBSERVER_OUTPUT[type].kind, instanceId: `${type}-${id}` }, seq: ++seq, outcome: 'committed', actor: null, ...spec });
// In-memory observers in the connector's observer shape. `plan` maps an observer id to the events of each
// successive window it is collected for (one window per check with declared effects, in check order).
function fakeFactory(plan, { coverage = {} } = {}) {
  return configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type], windows = [...(plan[c.id] ?? [])];
    const scope = c.type === 'egress-recorder'
      ? { operations: ['send'], names: [PAY, HOOK], actorAttribution: 'none', evidence: 'authoritative' }
      : { operations: ['read', 'insert', 'update'], names: AUDIT_NAMES, actorAttribution: 'principal', evidence: 'authoritative' };
    let mark = 0;
    return { kind: out.kind, instanceId: `${c.type}-${c.id}`, source: out.source, scope, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { const specs = windows.shift() ?? []; return { events: specs.map(s => event(c.type, c.id, s)), coverage: coverage[c.id] ?? 'complete', reason: coverage[c.id] === 'failed' ? 'synthetic-failure' : null }; } };
  });
}
const RESPONSES = { '/me': [200, { user: 'member-1' }], '/notes': [201, { id: 'n-1' }], '/notes/n-other/edit': [403, { error: 'forbidden' }], '/orders': [201, { ok: true }],
  '/agent/summarize': [200, { summary: 'done' }], '/customers/other': [200, { ok: true }], '/orders/confirm': [200, { ok: true }], '/refunds': [200, { ok: true }], '/notify': [200, { ok: true }] };
const transport = async (origin, check) => { const [status, json] = RESPONSES[check.path.split('?')[0]] ?? [404, {}]; return { status, complete: true, jsonParsed: true, json, bytes: 10 }; };
const check = (id, severity, method, path, status, effects, extra = {}) => ({ id, title: id, category: severity === 'control' ? 'allowed-use' : 'object-access', severity, actorId: 'member', method, path,
  ...(method === 'POST' ? { body: {} } : {}), evidenceRequirement: severity === 'control' ? 'response' : 'backend', assertions: [{ kind: 'status.equals', expected: status }], ...(effects ? { effects } : {}), ...extra });
const audit = (name, operation = 'update', extra = {}) => ({ source: 'sql-audit-table', operation, name, ...extra });
function profile() {
  return { id: 'custody-app', name: 'Custody app', applicationId: 'custody-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-custody',
    actors: { member: { principalId: 'member-1' } }, requiredControlIds: ['WHOAMI', 'OWN-NOTE'],
    observers: [{ id: 'app-audit', type: 'sqlite-audit', settleMs: 250 },
      { id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges'] }, { host: HOOK, paths: ['/notify'] }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
    checks: [
      check('WHOAMI', 'control', 'GET', '/me', 200),
      check('NO-EDIT', 'high', 'POST', '/notes/n-other/edit', 403, [{ kind: 'effect.none', select: audit('note.update') }]),
      check('NO-CHARGE', 'high', 'GET', '/agent/summarize', 200, [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: PAY } }]),
      check('OWN-NOTE', 'control', 'POST', '/notes', 201, [{ kind: 'effect.exists', select: audit('note.create', 'insert') }]),
      check('EDIT-SEEN', 'high', 'POST', '/notes/n-other/edit', 403, [{ kind: 'effect.none', select: audit('note.update') }]),
      check('ONE-ORDER', 'medium', 'POST', '/orders', 201, [{ kind: 'effect.count', select: audit('order.write', 'insert'), expected: 1 }]),
      // The three role cases: a precondition (effect.exists) that a forged row can satisfy in front of the guarded action.
      check('VERIFY-BEFORE-READ', 'high', 'GET', '/customers/other', 200, [{ kind: 'effect.exists', select: audit('identity.verify', 'insert') }, { kind: 'effect.exists', select: audit('customer.read', 'read') }]),
      check('CONFIRM-ONCE', 'high', 'POST', '/orders/confirm', 200, [{ kind: 'effect.exists', select: audit('confirmation.consume') }, { kind: 'effect.count', select: audit('order.write', 'insert'), expected: 1 }]),
      check('APPROVE-BEFORE-WRITE', 'high', 'POST', '/refunds', 200, [{ kind: 'effect.exists', select: audit('approval.grant', 'insert') }, { kind: 'effect.exists', select: audit('refund.write', 'insert') }]),
      check('NOTIFY-SENT', 'high', 'POST', '/notify', 200, [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: HOOK } }]),
    ] };
}
// One window per check with effects, in check order: NO-EDIT, NO-CHARGE, OWN-NOTE, EDIT-SEEN, ONE-ORDER, VERIFY, CONFIRM, APPROVE, NOTIFY.
const PLAN = {
  'app-audit': [[], [], [{ operation: 'insert', name: 'note.create', actor: 'member-1' }], [{ operation: 'update', name: 'note.update', actor: 'member-1' }], [{ operation: 'insert', name: 'order.write', actor: 'member-1' }],
    // Forged by the application: a verification, a confirmation and an approval it never performed.
    [{ operation: 'insert', name: 'identity.verify', actor: 'member-1' }, { operation: 'read', name: 'customer.read', actor: 'member-1' }],
    [{ operation: 'update', name: 'confirmation.consume', actor: 'member-1' }, { operation: 'insert', name: 'order.write', actor: 'member-1' }],
    [{ operation: 'insert', name: 'approval.grant', actor: 'member-1' }, { operation: 'insert', name: 'refund.write', actor: 'member-1' }], []],
  sink: [[], [], [], [], [], [], [], [], [{ operation: 'send', name: HOOK }]],
};
const assess = (p = profile(), plan = PLAN) => runHttpAssessment(p, { env: {}, transport, observerFactory: fakeFactory(plan) });
const rowOf = (run, id) => run.results.find(r => r.id === id);
const effectRows = row => row.assertions.filter(a => /^Observed effect/.test(a.name));
const BOUNDARY_RE = /tamper-proof|tamperproof|certif|\bsecure\b|guarantee/i;

test('the custody core lives in src, the lineage table in its own module, and both are in the HTTP evaluator identity', async () => {
  assert.equal(LINEAGE_FROM_EFFECTS, LINEAGE_BY_SOURCE, 'http-effects.mjs re-exports the same table');
  for (const name of ['subjectIntegrityVerdict', 'custodyOf', 'verifyChain', 'anchorOf', 'decidesAbsence', 'CUSTODY_BY_SOURCE', 'clauseCustody']) assert.equal(reExported[name], core[name], name);
  const source = await readFile(new URL('../src/http-connector.mjs', import.meta.url), 'utf8');
  const names = JSON.parse(source.match(/const evaluatorHash = digest\(\(await Promise\.all\((\[[^\]]+\])/)[1].replace(/'/g, '"'));
  for (const name of ['http-effects.mjs', 'effect-events.mjs', 'effect-lineage.mjs', 'custody.mjs']) assert.ok(names.includes(name), name);
  const files = await Promise.all(names.map(name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8')));
  assert.equal(HTTP_EVALUATOR_HASH, digest(files.join('\n')));
  // No cycle: the custody core and the lineage table never import the HTTP effect rules.
  for (const name of ['custody.mjs', 'effect-lineage.mjs']) assert.doesNotMatch(await readFile(new URL(`../src/${name}`, import.meta.url), 'utf8'), /from '\.\/http-effects\.mjs'/, name);
});

test('a boundary pass decided only by app-store windows is inconclusive; a request-path pass, an exists in a control and a fail are kept', async () => {
  const run = await assess();
  validateHttpRunEvidence(run);
  validateHttpRunEvidence(JSON.parse(JSON.stringify(run)));
  const byId = Object.fromEntries(run.results.map(r => [r.id, r]));
  // effect.none decided only by the application's own audit table.
  const none = effectRows(byId['NO-EDIT'])[0];
  assert.equal(none.status, 'inconclusive'); assert.equal(none.custody, 'subject-writable'); assert.equal(none.custodyReason, CUSTODY_REASON);
  assert.equal(byId['NO-EDIT'].status, 'inconclusive');
  assert.equal(byId['NO-EDIT'].trace[1].data.effects[0].verdict, 'inconclusive');
  // Coverage is unchanged: an authoritative observer decided it, whoever can write its record.
  assert.equal(byId['NO-EDIT'].backendEvidence, 'observed');
  // effect.count decided only by the audit table.
  const count = effectRows(byId['ONE-ORDER'])[0];
  assert.equal(count.status, 'inconclusive'); assert.equal(count.custodyReason, CUSTODY_REASON); assert.equal(byId['ONE-ORDER'].status, 'inconclusive');
  // A request-path window decided the absence: the pass stands, with independent custody.
  const egress = effectRows(byId['NO-CHARGE'])[0];
  assert.equal(egress.status, 'pass'); assert.equal(egress.custody, 'independent'); assert.equal(egress.custodyReason, undefined);
  assert.equal(byId['NO-CHARGE'].status, 'pass');
  // An exists clause in a boundary check decided by the request path also stands.
  assert.equal(byId['NOTIFY-SENT'].status, 'pass'); assert.equal(effectRows(byId['NOTIFY-SENT'])[0].custody, 'independent');
  // An allowed-use control keeps its exists pass and carries custody as a tag only.
  const control = effectRows(byId['OWN-NOTE'])[0];
  assert.equal(control.status, 'pass'); assert.equal(control.custody, 'subject-writable'); assert.equal(control.custodyReason, undefined);
  assert.equal(byId['OWN-NOTE'].status, 'pass');
  // A fail stays a fail, and carries the custody of the window that recorded it.
  const fail = effectRows(byId['EDIT-SEEN'])[0];
  assert.equal(fail.status, 'fail'); assert.equal(fail.custody, 'subject-writable'); assert.equal(fail.custodyReason, undefined);
  assert.equal(byId['EDIT-SEEN'].status, 'fail');
  // Every effect row carries custody.
  for (const r of run.results) for (const a of effectRows(r)) assert.ok(Object.hasOwn(a, 'custody'), `${r.id} ${a.name}`);
  assert.equal(run.counts.pass, 4); assert.equal(run.counts.fail, 1); assert.equal(run.counts.inconclusive, 5);
  // The run states the rule and its control limit, and the gate counts a held row as it counts any inconclusive row.
  assert.ok(run.limitations.includes(CUSTODY_LIMITATION));
  const expectedSuite = createRegistry({ profiles: [profile()], env: {} }).exportSuite('custody-app');
  const gate = summarizeGate({ candidate: run, expectedSuite });
  assert.equal(gate.exitCode, 1); assert.ok(gate.reasons.includes('inconclusive-evidence'), JSON.stringify(gate.reasons));
});

// Role cases: the application forges the precondition row in front of the guarded action. Its own
// audit table is the only witness, so each boundary check reads inconclusive, never pass.
for (const [id, what] of [['VERIFY-BEFORE-READ', 'a forged verification row in front of a cross-customer read'],
  ['CONFIRM-ONCE', 'a forged confirmation row in front of the order write'], ['APPROVE-BEFORE-WRITE', 'a forged approval row before a refund write']]) {
  test(`role case: ${what} reads inconclusive, never pass`, async () => {
    const run = await assess();
    validateHttpRunEvidence(run);
    const r = rowOf(run, id);
    assert.equal(r.status, 'inconclusive', id);
    // The effect rules alone accept the forged row: it matched, so without custody this precondition would pass.
    assert.equal(r.trace[1].data.effects[0].matched, 1, id);
    const precondition = effectRows(r)[0];
    assert.deepEqual([precondition.status, precondition.custody, precondition.custodyReason], ['inconclusive', 'subject-writable', CUSTODY_REASON], id);
    for (const a of effectRows(r)) assert.notEqual(a.status, 'pass', `${id} ${a.name}`);
  });
}

test('role cases: the same forged rows in an allowed-use control keep their verdicts and carry custody as a tag', async () => {
  // The same records in an allowed-use control keep their verdicts: the role, not the assertion type, decides.
  const asControl = profile();
  for (const c of asControl.checks) if (['VERIFY-BEFORE-READ', 'CONFIRM-ONCE', 'APPROVE-BEFORE-WRITE'].includes(c.id)) Object.assign(c, { severity: 'control', evidenceRequirement: 'response' });
  const controlRun = await assess(asControl);
  validateHttpRunEvidence(controlRun);
  for (const id of ['VERIFY-BEFORE-READ', 'CONFIRM-ONCE', 'APPROVE-BEFORE-WRITE']) {
    assert.equal(rowOf(controlRun, id).status, 'pass', id);
    for (const a of effectRows(rowOf(controlRun, id))) { assert.equal(a.custody, 'subject-writable'); assert.equal(a.custodyReason, undefined); }
  }
});

test('a degraded row says what could decide it: a request-path observer for a send or a tool call, none for a database write; never how to make the app\'s records independent', async () => {
  const run = await assess();
  const none = effectRows(rowOf(run, 'NO-EDIT'))[0];
  // Nothing held outside the application sees its database writes, so a database-write clause names no observer.
  assert.equal(none.custodyUpgrade, 'No shipped observer held outside the application sees operation update, name note.update. Decide it through the tool call or outbound send that carries it, if there is one, or accept this row as inconclusive.');
  assert.match(none.actual, /^inconclusive: .*Custody: every observer that decided this keeps a record the application can write, so it cannot support a pass\.$/);
  assert.equal(custodyUpgrade({ operation: 'tool-call', name: 'refund-approve' }), 'Add a hold gate that sees operation tool-call, name refund-approve, or accept this row as inconclusive.');
  // A request-path observer records no acting principal: naming the actor would be advice that cannot work.
  assert.equal(custodyUpgrade({ operation: 'tool-call', name: 'refund', actor: 'mcp-viewer' }), 'Add a hold gate that sees operation tool-call, name refund; it records no acting principal, so it decides this for every actor, not only mcp-viewer, or accept this row as inconclusive.');
  assert.equal(custodyUpgrade({ source: 'sql-audit-table', operation: 'send', name: PAY }), `Add an egress recorder or SMTP sink that sees operation send, name ${PAY} and select it by that observer's source rather than sql-audit-table, or accept this row as inconclusive.`);
  assert.match(custodyUpgrade({ name: { prefix: 'refund.' }, actor: 'member-1' }), /^No shipped observer held outside the application sees name starting refund\., acting principal member-1\./);
  for (const r of run.results) for (const a of effectRows(r)) if (a.custodyReason) {
    assert.match(a.custodyUpgrade, /^(Add (a hold gate|an egress recorder or SMTP sink) that sees .+|No shipped observer held outside the application sees .+ Decide it through the tool call or outbound send that carries it, if there is one), or accept this row as inconclusive\.$/);
    assert.doesNotMatch(a.custodyUpgrade, /sign|hash|append-only|immutable|protect|lock/i);
    assert.doesNotMatch(a.custodyUpgrade, BOUNDARY_RE);
  }
});

test('saved-run recompute: the validator recomputes custody under the row\'s role and rejects an edited verdict or role', async () => {
  const run = await assess();
  const expectedSuite = createRegistry({ profiles: [profile()], env: {} }).exportSuite('custody-app');
  validateHttpRunEvidence(run, { expectedSuite });
  const reseal = r => { r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions }); };
  // Restoring the pass a custody-degraded row would have had.
  const restored = structuredClone(run), r1 = rowOf(restored, 'NO-EDIT'), a1 = effectRows(r1)[0];
  const { custodyReason: _r, custodyUpgrade: _u, ...plain } = a1; Object.assign(r1.assertions[r1.assertions.indexOf(a1)] = plain, { status: 'pass', actual: a1.actual.replace(/^inconclusive/, 'pass').replace(/ Custody: .*$/, '') });
  r1.trace[1].data.effects[0] = { ...r1.trace[1].data.effects[0], verdict: 'pass' }; delete r1.trace[1].data.effects[0].custodyReason; delete r1.trace[1].data.effects[0].custodyUpgrade;
  r1.status = 'pass'; reseal(r1);
  assert.throws(() => validateHttpRunEvidence(restored), e => e.detail === 'effect-verdict');
  // Relabelling the row an allowed-use control: its stored inconclusive no longer matches the recompute.
  const relabelled = structuredClone(run); rowOf(relabelled, 'NO-EDIT').severity = 'control';
  assert.throws(() => validateHttpRunEvidence(relabelled), e => e.detail === 'effect-verdict');
  // With the exported suite, the role is bound to the suite's severity.
  assert.throws(() => validateHttpRunEvidence(relabelled, { expectedSuite }), e => e.detail === 'unexpected-suite-evidence' || e.code === 'unexpected-suite-evidence');
  // A consistent relabel to an allowed-use control, recomputed under that role and resealed: the forger restates custody,
  // settlement (src/http-settlement.mjs) and the per-row decision (actor-identity/5).
  const relabel = (id, findings) => {
    const x = structuredClone(run), r = rowOf(x, id), data = r.trace[1].data;
    r.severity = 'control';
    const decisions = applySettlement(decideEffects(data.effects.map(({ kind, select, expected }) => ({ kind, select, ...(expected === undefined ? {} : { expected }) })), data.windows.map(({ lineage: _l, settleMs: _s, ...w }) => w), { role: 'control' }), findings, 'control');
    assert.ok(decisions.every(d => d.verdict === 'pass'), `${id}: a control keeps its verdicts`);
    data.effects = decisions.map(d => ({ kind: d.kind, select: d.select, ...(d.kind === 'effect.count' ? { expected: d.expected } : {}), verdict: d.verdict, matched: d.matched, custody: d.custody, ...(d.settlement === undefined ? {} : { settlement: d.settlement }) }));
    r.assertions = [...r.assertions.filter(a => !a.name.startsWith('Observed effect')), ...effectAssertionRows(decisions)];
    r.status = 'pass'; r.decision = 'pass'; reseal(r);
    x.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const y of x.results) x.counts[y.status]++;
    return x;
  };
  // A row whose clauses include a positive one (ONE-ORDER's exact count) passes on its own: the same out-of-scope consistent edit
  // as any whole-record forgery. The exported suite binds the role and refuses it. A later order.write insert fits ONE-ORDER's
  // selector, so the relabelled control's count pass carries effect-outside-window as a tag.
  const consistent = relabel('ONE-ORDER', ['effect-outside-window']);
  validateHttpRunEvidence(consistent);
  assert.throws(() => validateHttpRunEvidence(consistent, { expectedSuite }), e => e.code === 'unexpected-suite-evidence' || e.detail === 'unexpected-suite-evidence');
  // A row renamed out of the suite and relabelled a control is refused with the suite, never judged unbound.
  const renamed = structuredClone(consistent); rowOf(renamed, 'ONE-ORDER').id = 'ONE-ORDER-X';
  assert.throws(() => validateHttpRunEvidence(renamed, { expectedSuite }), e => e.code === 'unexpected-suite-evidence' || e.detail === 'unexpected-suite-evidence');
  // A row whose only clause is an absence proves no allowed use as a control: refused even without the suite. EDIT-SEEN's later
  // note.update fits NO-EDIT's selector, so the relabelled absence pass carries effect-outside-window as a tag.
  assert.throws(() => validateHttpRunEvidence(relabel('NO-EDIT', ['effect-outside-window'])), e => e.detail === 'control-no-positive-effect');
  // Dropping the custody tag of a kept pass is also caught.
  const untagged = structuredClone(run), r2 = rowOf(untagged, 'NO-CHARGE'); delete r2.trace[1].data.effects[0].custody; reseal(r2);
  assert.throws(() => validateHttpRunEvidence(untagged), e => e.detail === 'effect-verdict');
});

test('forging subject: every mode through the wired HTTP path gives 0 subject-only passes', async () => {
  const forging = { ...profile(), id: 'forging-app', applicationId: 'forging-app', requiredControlIds: ['WHOAMI'], observers: [{ id: 'app-audit', type: 'sqlite-audit', settleMs: 250 }],
    checks: [check('WHOAMI', 'control', 'GET', '/me', 200),
      // The prohibited effect: a member approving their own refund.
      check('PROHIBITED', 'high', 'POST', '/refunds', 200, [{ kind: 'effect.none', select: audit('refunds.approved', 'update', { actor: 'member' }) }]),
      // The approval a forged entry claims, in front of the same action.
      check('AUTHORIZED', 'high', 'POST', '/refunds', 200, [{ kind: 'effect.exists', select: audit('refunds.authorized', 'update') }])] };
  const naivePasses = [], wiredPasses = [];
  for (const mode of FORGERY_MODES) {
    const subject = runForgingSubject(mode);
    const entries = subject.entries.map(e => ({ operation: e.operation, name: e.name, actor: e.actor }));
    const plan = { 'app-audit': [entries, entries] };
    const run = await runHttpAssessment(forging, { env: {}, transport, observerFactory: fakeFactory(plan, { coverage: subject.missing ? { 'app-audit': 'failed' } : {} }) });
    validateHttpRunEvidence(run);
    for (const id of ['PROHIBITED', 'AUTHORIZED']) {
      const r = rowOf(run, id);
      // What the effect rules alone (no custody) conclude from the same window.
      if (r.trace[1].data.effects.some(e => e.custodyReason)) naivePasses.push(`${mode}:${id}`);
      if (r.status === 'pass') wiredPasses.push(`${mode}:${id}`);
    }
  }
  assert.deepEqual(wiredPasses, []);
  // Without custody, the subject's own records would have passed these.
  assert.ok(naivePasses.length >= 4, String(naivePasses));
  assert.ok(naivePasses.includes('truncate-tail:PROHIBITED') && naivePasses.includes('forge-authorize:AUTHORIZED'), String(naivePasses));
});

test('pure rule: degrades only a boundary pass, never upgrades, and judges only the deciding windows', () => {
  const appWindow = { source: 'sql-audit-table', instanceId: 'sqlite-audit-a', coverage: 'complete', reason: null, events: [], scope: { operations: ['update'], names: ['x'], actorAttribution: 'principal', evidence: 'authoritative' } };
  const failedGate = { source: 'http-egress', instanceId: 'egress-recorder-s', coverage: 'failed', reason: 'x', events: [], scope: { operations: ['send'], names: ['x'], actorAttribution: 'none', evidence: 'authoritative' } };
  const select = { operation: 'update', name: 'x' };
  // A non-deciding independent window lends nothing.
  assert.equal(decidingWindows([appWindow, failedGate], { kind: 'effect.none', select, verdict: 'pass' }).length, 1);
  assert.equal(clauseCustody({ kind: 'effect.none', select, verdict: 'pass', windows: [appWindow, failedGate] }).verdict, 'inconclusive');
  for (const verdict of ['fail', 'missing', 'unobservable', 'observer-failure', 'inconclusive']) assert.equal(clauseCustody({ kind: 'effect.none', select, verdict, windows: [appWindow] }).verdict, verdict);
  assert.equal(clauseCustody({ kind: 'effect.none', select, verdict: 'pass', windows: [appWindow], role: 'control' }).verdict, 'pass');
  assert.throws(() => clauseCustody({ kind: 'effect.none', select, verdict: 'pass', windows: [], role: 'trusted' }), /Unknown check role/);
  assert.equal(roleOfSeverity('control'), 'control');
  for (const s of ['critical', 'high', 'medium', 'low', undefined, 'Control']) assert.equal(roleOfSeverity(s), 'boundary', String(s));
  // decideEffects without a role is a boundary decision (fail closed).
  assert.equal(decideEffects([{ kind: 'effect.none', select }], [appWindow])[0].verdict, 'inconclusive');
  assert.equal(decideEffects([{ kind: 'effect.none', select }], [appWindow], { role: 'control' })[0].verdict, 'pass');
});

// Sequences. The audit table is subject-writable; the hold gate is in the request path.
const SEQ_AUDIT = { kind: 'sqlite-audit-table', instanceId: 'sqlite-audit-app', source: 'sql-audit-table',
  scope: { operations: ['insert', 'update'], names: ['refunds.requested', 'refunds.approved', 'approval.grant'], actorAttribution: 'principal', evidence: 'authoritative' } };
const SEQ_GATE = { kind: 'hold-gate', instanceId: 'hold-gate-1', source: 'hold-proxy', scope: { operations: ['tool-call'], names: ['refund-approve', 'ungated'], actorAttribution: 'none', evidence: 'authoritative' } };
function seqObserver(o, specs) {
  let n = 0;
  return { ...o, async start() {}, async stop() {}, async mark() { return { n: ++n }; },
    async collect() { return { events: specs.map((s, i) => makeEffect({ source: o.source, observer: { kind: o.kind, instanceId: o.instanceId }, seq: i + 1, outcome: 'committed', actor: null, ...s })), coverage: 'complete', reason: null }; } };
}
const SEQUENCE = { schema: SEQUENCE_SCHEMA, id: 'custody-seq', actors: { agent: { principalId: 'agent-1' } },
  steps: [{ mark: 'a' }, { request: { id: 'r1', actorId: 'agent', method: 'POST', path: '/refund' } }, { mark: 'b' }],
  assertions: [
    { id: 'S-NONE-APP', title: 'No approval in the app store', severity: 'high', from: 'a', to: 'b', effect: { kind: 'effect.none', select: { source: 'sql-audit-table', operation: 'update', name: 'refunds.approved' } } },
    { id: 'S-NONE-GATE', title: 'No gated approval call', severity: 'high', from: 'a', to: 'b', effect: { kind: 'effect.none', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund-approve' } } },
    { id: 'S-CONTROL', title: 'The request is recorded', severity: 'control', from: 'a', to: 'b', effect: { kind: 'effect.exists', select: { source: 'sql-audit-table', operation: 'insert', name: 'refunds.requested' } } },
    { id: 'S-APPROVAL', title: 'Approval precedes the write', severity: 'high', from: 'a', to: 'b', effect: { kind: 'effect.exists', select: { source: 'sql-audit-table', operation: 'insert', name: 'approval.grant' } } },
    { id: 'S-FAIL', title: 'No request recorded', severity: 'low', from: 'a', to: 'b', effect: { kind: 'effect.none', select: { source: 'sql-audit-table', operation: 'insert', name: 'refunds.requested' } } },
  ] };
const sequenceRun = () => runSequence(SEQUENCE, { origin: 'http://127.0.0.1:9', transport: async () => ({ status: 200 }),
  observers: [seqObserver(SEQ_AUDIT, [{ operation: 'insert', name: 'refunds.requested', actor: 'agent-1' }, { operation: 'insert', name: 'approval.grant', actor: 'agent-1' }]), seqObserver(SEQ_GATE, [])] });

test('sequence assertions apply the same rule by severity, and the run validator recomputes it', async () => {
  const run = await sequenceRun();
  const by = Object.fromEntries(run.results.map(r => [r.id, r]));
  assert.deepEqual([by['S-NONE-APP'].status, by['S-NONE-APP'].verdict, by['S-NONE-APP'].custody, by['S-NONE-APP'].custodyReason], ['inconclusive', 'inconclusive', 'subject-writable', CUSTODY_REASON]);
  assert.match(by['S-NONE-APP'].custodyUpgrade, /^No shipped observer held outside the application sees /);
  assert.deepEqual([by['S-NONE-GATE'].status, by['S-NONE-GATE'].custody, by['S-NONE-GATE'].custodyReason], ['pass', 'independent', undefined]);
  assert.deepEqual([by['S-CONTROL'].status, by['S-CONTROL'].custody, by['S-CONTROL'].custodyReason], ['pass', 'subject-writable', undefined]);
  assert.deepEqual([by['S-APPROVAL'].status, by['S-APPROVAL'].custodyReason], ['inconclusive', CUSTODY_REASON]);
  assert.deepEqual([by['S-FAIL'].status, by['S-FAIL'].custody, by['S-FAIL'].custodyReason], ['fail', 'subject-writable', undefined]);
  assert.deepEqual(run.counts, { pass: 2, fail: 1, inconclusive: 2, error: 0 });
  assert.ok(run.limitations.some(l => l.includes(CONTROL_CUSTODY_LIMIT)));
  validateSequenceRun(run, { expectedSequence: SEQUENCE });
  validateSequenceRun(JSON.parse(JSON.stringify(run)));
  // A consistent edit back to pass (digest resealed) is caught by the recompute.
  const forged = structuredClone(run), r = forged.results.find(x => x.id === 'S-NONE-APP');
  Object.assign(r, { status: 'pass', verdict: 'pass', basis: r.basis.replace(/ Custody: .*$/, '') }); delete r.custodyReason; delete r.custodyUpgrade;
  forged.counts = { pass: 3, fail: 1, inconclusive: 1, error: 0 };
  const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest: _rd, ...sealed } = forged; forged.runDigest = digest(sealed);
  assert.throws(() => validateSequenceRun(forged), e => e.code === 'sequence-verdict' && e.detail === 'S-NONE-APP');
  // decideAssertion is the shared judge.
  const windows = run.windows['a>b'];
  assert.equal(decideAssertion(SEQUENCE.assertions[0], windows, null).status, 'inconclusive');
  assert.equal(decideAssertion({ ...SEQUENCE.assertions[0], severity: 'control' }, windows, null).status, 'pass');
});

test('custody shows in the HTML report, SARIF, the comparison export and the served dashboard, in plain wording', async t => {
  const before = await assess(), after = await assess();
  // HTML report.
  const html = renderReport(before);
  assert.match(html, /<h3>Record custody<\/h3>/);
  assert.ok(html.includes('Observed effect 1 (effect.none): the application can write this record. Read as inconclusive (subject-writable-custody). No shipped observer held outside the application sees'));
  assert.ok(html.includes('Observed effect 1 (effect.none): held outside the application, in the request path.'));
  assert.ok(html.includes(CUSTODY_RULE)); assert.ok(html.includes(CONTROL_CUSTODY_LIMIT));
  // SARIF result property.
  const sarif = renderSarif(before), result = id => sarif.runs[0].results.find(r => r.ruleId === id);
  assert.deepEqual(result('NO-EDIT').properties.custody[0], { assertion: 'Observed effect 1 (effect.none)', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: effectRows(rowOf(before, 'NO-EDIT'))[0].custodyUpgrade });
  assert.equal(result('NO-EDIT').kind, 'open'); assert.equal(result('NO-EDIT').properties.custodyNote, CUSTODY_RULE);
  assert.equal(result('OWN-NOTE').properties.custodyNote, CONTROL_CUSTODY_LIMIT);
  assert.equal(result('WHOAMI').properties.custody, undefined, 'a row without effect clauses carries no custody property');
  // Comparison export (JSON) and its HTML.
  const doc = comparisonDocument(before, after, compareRuns(before, after)), row = doc.comparison.rows.find(r => r.id === 'NO-EDIT');
  assert.equal(row.custody.candidate[0].custodyReason, CUSTODY_REASON); assert.equal(row.custody.baseline[0].custody, 'subject-writable');
  assert.equal(doc.comparison.rows.find(r => r.id === 'WHOAMI').custody, undefined);
  assert.ok(renderComparisonReport(doc).includes('Record custody'));
  // Served dashboard: the selected finding shows a custody note on its effect row.
  withDocument(t);
  const pane = await dashboardFinding(t, before, 'NO-EDIT');
  assert.ok(pane.includes('Record custody: the application can write this record. Read as inconclusive (subject-writable-custody). No shipped observer held outside the application sees'), pane);
  assert.ok(pane.includes(CUSTODY_RULE));
  const controlPane = await dashboardFinding(t, before, 'OWN-NOTE');
  assert.ok(controlPane.includes('Record custody: the application can write this record.')); assert.ok(controlPane.includes(CONTROL_CUSTODY_LIMIT));
  // The dashboard's copy of the wording matches the report's.
  const dashboardSource = await readFile(new URL('../public/dashboard/dashboard.mjs', import.meta.url), 'utf8');
  assert.ok(dashboardSource.includes(CUSTODY_RULE) && dashboardSource.includes(CONTROL_CUSTODY_LIMIT));
  // Check every custody block and its associated rule. The closing limits can contain a
  // certification disclaimer; scanning the entire document suffix confuses it with a custody claim.
  const blocksOf = report => {
    const blocks = [...report.matchAll(/<h3>Record custody<\/h3><ul>[\s\S]*?<\/ul><p><small>[\s\S]*?<\/small><\/p>/g)].map(match => match[0]);
    assert.equal(blocks.length, (report.match(/<h3>Record custody<\/h3>/g) || []).length, 'every custody heading has a complete block and rule');
    return blocks;
  };
  const blocks = blocksOf(html), markedRows = before.results.filter(r => r.assertions.some(a => Object.hasOwn(a, 'custody')));
  assert.equal(blocks.length, markedRows.length, 'every row carrying custody is disclosed');
  for (let i = 0; i < blocks.length; i++) assert.ok(blocks[i].includes(markedRows[i].severity === 'control' ? CONTROL_CUSTODY_LIMIT : CUSTODY_RULE), markedRows[i].id);
  // Plain wording: who can write a record, never a claim about its integrity.
  // Same surface as before the move: from the first custody block to the closing limits section.
  const custodySuffix = html.slice(html.indexOf('<h3>Record custody'), html.indexOf('<section class="limits">')).split('<h3>Remediation')[0];
  for (const text of [CUSTODY_RULE, CONTROL_CUSTODY_LIMIT, custodySuffix, ...blocks, JSON.stringify(result('NO-EDIT').properties.custody), JSON.stringify(row.custody)]) assert.doesNotMatch(text, BOUNDARY_RE);
  const mutated = html.replace('<h3>Record custody</h3><ul>', '<h3>Record custody</h3><ul><li>guarantee</li>');
  assert.throws(() => blocksOf(mutated).forEach(block => assert.doesNotMatch(block, BOUNDARY_RE)), { code: 'ERR_ASSERTION' }, 'a forbidden claim planted in a custody block is caught');
  const limits = html.slice(html.indexOf('<section class="limits">'));
  assert.ok(limits.includes('These are observed checks, not a safety certification.'), 'the disclaimer remains in closing limits');
  assert.ok(limits.includes('A passing response contract is not a security certification.'), 'the existing HTTP limitation remains');
});

// A minimal DOM port for the dashboard modules.
class Element {
  constructor(tagName) { this.tagName = tagName.toLowerCase(); this.nodeType = 1; this.childNodes = []; this.dataset = {}; this.attributes = {}; this.listeners = new Map(); this.className = ''; this.value = ''; this.ownText = '';
    this.classList = { contains: v => this.className.split(/\s+/).includes(v), add: v => { if (!this.classList.contains(v)) this.className = `${this.className} ${v}`.trim(); }, remove: v => { this.className = this.className.split(/\s+/).filter(x => x !== v).join(' '); }, toggle: (v, on) => { const a = on ?? !this.classList.contains(v); this.classList[a ? 'add' : 'remove'](v); return a; } }; }
  get children() { return this.childNodes; }
  get textContent() { return this.ownText + this.childNodes.map(c => c.textContent).join(''); }
  set textContent(v) { this.childNodes = []; this.ownText = String(v); }
  set innerHTML(_) { throw new Error('Untrusted HTML sink used by dashboard.'); }
  append(...children) { for (const c of children) { assert.ok(c instanceof Element); c.parentNode = this; this.childNodes.push(c); } }
  replaceChildren(...children) { this.childNodes = []; this.ownText = ''; this.append(...children); }
  setAttribute(n, v) { this.attributes[n] = String(v); }
  getAttribute(n) { return this.attributes[n] ?? null; }
  matches(s) { return s.startsWith('.') ? this.classList.contains(s.slice(1)) : this.tagName === s.toLowerCase(); }
  querySelectorAll(s) { const found = []; for (const c of this.childNodes) { if (c.matches(s)) found.push(c); found.push(...c.querySelectorAll(s)); } return found; }
  querySelector(s) { return this.querySelectorAll(s)[0] || null; }
  addEventListener(type, fn) { this.listeners.set(type, [...(this.listeners.get(type) || []), fn]); }
  fire(type) { return Promise.all((this.listeners.get(type) || []).map(fn => fn({ type, target: this, preventDefault() {} }))); }
  focus() {}
}
function withDocument(t) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'document');
  globalThis.document = { createElement: tag => new Element(tag) };
  t.after(() => { if (previous) Object.defineProperty(globalThis, 'document', previous); else delete globalThis.document; });
}
async function dashboardFinding(t, run, id) {
  const root = new Element('div'), saved = structuredClone(run);
  const view = mountDashboard(root, { adapter: { bootstrap: async () => ({ targets: [], runs: [saved], history: { total: 1, nextCursor: null } }), run: async () => saved }, preview: true });
  t.after(() => view.destroy());
  await view.ready;
  await root.querySelectorAll('button').find(b => b.textContent === 'Inspect latest run ↗').fire('click');
  await root.querySelectorAll('.sh-finding').find(b => b.textContent.includes(id)).fire('click');
  return root.querySelector('.sh-evidence-pane').textContent;
}

test('the evidence pane says when a row was not timed and keeps a measured duration, zero included', async t => {
  withDocument(t);
  const run = await assess();
  for (const [value, measured, expected] of [[0, false, 'Timing not measured'], [null, undefined, 'Timing not measured'], [undefined, undefined, 'Timing not measured'], [0, undefined, '0 ms'], [17, true, '17 ms']]) {
    const copy = structuredClone(run), row = rowOf(copy, 'NO-EDIT');
    row.durationMs = value; row.durationMeasured = measured;
    assert.ok((await dashboardFinding(t, copy, 'NO-EDIT')).includes(` · ${expected} · Evidence digest`), expected);
  }
});

test('records saved before custody are refused as pre-custody, not as edited verdicts; a run that repeats a requestId is refused', async () => {
  const run = await assess();
  const reseal = r => { r.evidenceDigest = digest(r.trace[1] ? { evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions } : { evidence: r.trace[0].data, assertions: r.assertions }); };
  const strip = e => { delete e.custody; delete e.custodyReason; delete e.custodyUpgrade; };
  // Every clause without custody: the shape every run saved before the wiring has.
  const old = structuredClone(run);
  for (const row of old.results) if (row.trace?.[1]) { row.trace[1].data.effects.forEach(strip); reseal(row); }
  assert.throws(() => validateHttpRunEvidence(old), e => e.code === 'invalid-run-evidence' && e.detail === 'effect-pre-custody');
  // Removing it from one clause only is an edit, and still reads as one.
  const partial = structuredClone(run), p = rowOf(partial, 'NO-EDIT'); strip(p.trace[1].data.effects[0]); reseal(p);
  assert.throws(() => validateHttpRunEvidence(partial), e => e.detail === 'effect-verdict');
  // A row copied into another check's slot repeats the requestId of the request it came from.
  const copied = structuredClone(run), target = rowOf(copied, 'NO-EDIT');
  target.trace[0].data.requestId = rowOf(copied, 'WHOAMI').trace[0].data.requestId; reseal(target);
  assert.throws(() => validateHttpRunEvidence(copied), e => e.code === 'invalid-run-evidence' && e.detail === 'duplicate-request-id');
  validateHttpRunEvidence(run);
  // Sequences: no custody on any result is a pre-custody run; on one result only, an edited verdict.
  const seqRun = await sequenceRun();
  const resealSeq = r => { const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest: _rd, ...sealed } = r; r.runDigest = digest(sealed); };
  const oldSeq = structuredClone(seqRun); oldSeq.results.forEach(strip); resealSeq(oldSeq);
  assert.throws(() => validateSequenceRun(oldSeq), e => e.code === 'sequence-pre-custody');
  const partSeq = structuredClone(seqRun); strip(partSeq.results[0]); resealSeq(partSeq);
  assert.throws(() => validateSequenceRun(partSeq), e => e.code === 'sequence-verdict');
});

// pool-http-write-methods: a check's write method changes what is sent, never how it is judged. The same profile with
// every POST check sent as PUT, PATCH or DELETE decides status, response, effect and custody assertions exactly as with
// POST (the transport and observers here answer by path, whatever the method).
test('PUT, PATCH and DELETE checks decide effects and custody exactly as the same POST checks', async () => {
  // Less the method, request ids, timings and the wall-clock time each synthetic event was observed.
  const clock = t => ({ ...t, data: { ...t.data, windows: t.data.windows.map(w => ({ ...w, events: w.events.map(e => ({ ...e, observedAt: null })) })) } });
  const judged = run => run.results.map(r => ({ ...r, durationMs: 0, evidenceDigest: null, trace: r.trace.map(t => t.type === 'http-observation' ? { ...t, data: { ...t.data, requestId: null, method: null, routeSegments: null, controlScope: null } } : clock(t)) }));
  const gateOf = (run, p) => summarizeGate({ candidate: run, expectedSuite: createRegistry({ profiles: [p], env: {} }).exportSuite('custody-app') });
  seq = 0; const post = await assess();
  const writes = post.results.filter(r => r.trace[0].data.method === 'POST').map(r => r.id);
  assert.ok(writes.length >= 6 && writes.includes('NO-EDIT') && writes.includes('OWN-NOTE') && writes.includes('APPROVE-BEFORE-WRITE'));
  for (const method of ['PUT', 'PATCH', 'DELETE']) {
    const p = profile(); p.checks = p.checks.map(c => c.method === 'POST' ? { ...c, method } : c);
    seq = 0; const run = await assess(p);
    validateHttpRunEvidence(run); validateHttpRunEvidence(JSON.parse(JSON.stringify(run)));
    for (const r of run.results) assert.equal(r.trace[0].data.method, writes.includes(r.id) ? method : 'GET', `${method} ${r.id}`);
    assert.deepEqual(judged(run), judged(post), method);
    assert.deepEqual(run.counts, post.counts, method);
    // Custody held the same rows: the app-store absences and counts read inconclusive, the request-path decisions stand.
    for (const id of ['NO-EDIT', 'ONE-ORDER']) assert.equal(effectRows(rowOf(run, id))[0].custodyReason, CUSTODY_REASON, `${method} ${id}`);
    assert.deepEqual(gateOf(run, p).reasons, gateOf(post, profile()).reasons, method);
  }
});
