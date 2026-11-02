// Positive-match pairing of absence selectors (src/http-pairing.mjs, ledger EFFECT-SELECTOR-SEMANTICS): an absence
// clause whose selector pins an actor, a resource or a trace id needs an allowed-use twin that matched in a deciding
// observer's window, or it reads inconclusive with a named reason; a resource every deciding observer declares in its
// vocabulary needs no twin. Injected transport and injected observers only: no socket, no database, no model, no provider.
// The observer here is a fake request-path gate (an egress recorder's source, so custody is independent) that attributes
// principals, so an actor-pinned absence can reach a pass that only the pairing rule withholds.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { createRegistry } from '../src/registry.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { digest } from '../src/domain.mjs';
import { showsPin, selectorPairs, unpairedSelectors, pairingFindings, applyPairing, absenceClause, positiveClause, needsPairing, PAIRING_REASONS, PAIRING_BASIS } from '../src/http-pairing.mjs';

const HOST = 'api.notes.example', GATE = 'egress-recorder-gate';
let seq = 0;
const event = spec => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: GATE }, seq: ++seq, operation: 'send', name: HOST, outcome: 'committed', ...spec });
// plan: the events of each successive window (one per check with declared effects, in check order), as one list for the
// gate or as { [observer id]: list }; coverage and evidence likewise apply to every observer or per id. resources: a resource
// vocabulary keyed by name ({ [name]: [...] }) every observer declares; resourcesById: one per observer id. names: the names
// every observer reports; operations: the operations every observer reports (send by default).
const perId = (value, id) => value !== null && typeof value === 'object' && !Array.isArray(value) ? value[id] : value;
function fakeFactory(plan, { resources, resourcesById, names = [HOST], operations = ['send'], coverage = 'complete', evidence = 'authoritative' } = {}) {
  return configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`, windows = [...(Array.isArray(plan) ? plan : plan[c.id] ?? [])], own = resourcesById ? resourcesById[c.id] : resources;
    const coverages = Array.isArray(perId(coverage, c.id)) ? [...perId(coverage, c.id)] : null;
    let mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations, names, actorAttribution: 'principal', evidence: perId(evidence, c.id) ?? 'authoritative', ...(own ? { resources: own } : {}) }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { const specs = windows.shift() ?? [], cov = coverages ? coverages.shift() ?? 'complete' : perId(coverage, c.id) ?? 'complete'; return { events: specs.map(s => event({ ...s, observer: { kind: 'http-egress-recorder', instanceId } })), coverage: cov, reason: cov === 'complete' ? null : 'synthetic' }; } };
  });
}
const transport = async (origin, check) => ({ status: check.severity === 'control' ? 200 : 403, complete: true, jsonParsed: true, json: {}, bytes: 2 });
const sel = extra => ({ source: 'http-egress', operation: 'send', name: HOST, ...extra });
const check = (id, severity, actorId, path, effects) => ({ id, title: id, category: severity === 'control' ? 'Allowed use' : 'Object access', severity, actorId, method: 'POST', path, body: {},
  evidenceRequirement: severity === 'control' ? 'response' : 'backend', assertions: [{ kind: 'status.equals', expected: severity === 'control' ? 200 : 403 }], effects });
const OWNER_EDIT = { actor: 'owner-1', resource: 'POST /notes/n1/edit' }, MEMBER_OWN = { actor: 'member-1', resource: 'POST /notes/n2/edit' };
// Two uncredentialed actors, so no identity proof is in the way. The owner's allowed edit of n1 is the resource twin of the
// member's forbidden edit of n1; the member's allowed edit of n2 is the actor twin (attribution of member-1 shown).
function profile({ select = sel({ actor: 'member-1', resource: 'POST /notes/n1/edit' }), kind = 'effect.none', controls = ['OWNER-EDIT', 'MEMBER-OWN-EDIT'] } = {}) {
  const all = { 'OWNER-EDIT': check('OWNER-EDIT', 'control', 'owner', '/notes/n1/edit', [{ kind: 'effect.exists', select: sel(OWNER_EDIT) }]),
    'MEMBER-OWN-EDIT': check('MEMBER-OWN-EDIT', 'control', 'member', '/notes/n2/edit', [{ kind: 'effect.count', select: sel(MEMBER_OWN), expected: 1 }]) };
  return { id: 'pairing-app', name: 'Pairing app', applicationId: 'pairing-app', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { member: { principalId: 'member-1' }, owner: { principalId: 'owner-1' } },
    observers: [{ id: 'gate', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: HOST }], witness: { actorId: 'owner', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 }],
    requiredControlIds: controls, checks: [...controls.map(id => all[id]), check('MEMBER-EDIT', 'high', 'member', '/notes/n1/edit', [kind === 'effect.count' ? { kind, select, expected: 0 } : { kind, select }])] };
}
// Windows in check order: the owner's edit, the member's own edit, then nothing behind the member's refused edit.
const PLAN = [[OWNER_EDIT], [MEMBER_OWN], []];
const assess = (p, plan = PLAN, options = {}) => runHttpAssessment(p, { env: {}, transport, observerFactory: fakeFactory(plan, options) });
const row = (run, id) => run.results.find(r => r.id === id);
const clause = (run, id, n = 0) => row(run, id).trace[1].data.effects[n];
const effectRow = (run, id, n = 1) => row(run, id).assertions.find(a => a.name.startsWith(`Observed effect ${n} `));
const suiteOf = p => createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
const recount = run => { run.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const r of run.results) run.counts[r.status]++; };
const reseal = r => { r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions }); };

test('pairing (pure): a pin is shown by a twin on the same selector but the actor; an actor pin by the actor\'s own allowed action on the same source, operation and name', () => {
  const principals = { member: 'member-1', owner: 'owner-1' };
  const absence = sel({ actor: 'member-1', resource: 'POST /notes/n1/edit' });
  assert.equal(showsPin('resource', absence, 'member', sel(OWNER_EDIT), 'owner', principals), true, 'another actor, the same resource');
  assert.equal(showsPin('resource', absence, 'member', sel({ resource: 'POST /notes/n1/edit' }), 'owner', principals), true, 'the twin need not pin an actor');
  assert.equal(showsPin('resource', absence, 'member', sel({ actor: 'owner-1', resource: 'POST /notes/n9/edit' }), 'owner', principals), false, 'a different resource');
  assert.equal(showsPin('resource', absence, 'member', sel({ actor: 'member-1', resource: 'POST /notes/n1/edit' }), 'owner', principals), false, 'a twin pinning another principal than its own actor');
  assert.equal(showsPin('actor', absence, 'member', sel(MEMBER_OWN), 'member', principals), true, 'the actor\'s own allowed action, another resource');
  assert.equal(showsPin('actor', absence, 'member', sel(OWNER_EDIT), 'owner', principals), false, 'another principal shows nothing about this one');
  assert.equal(showsPin('actor', sel({ actor: 'owner-1', resource: 'POST /notes/n1/edit' }), 'member', sel(OWNER_EDIT), 'owner', principals), false, 'an absence selector naming another principal than its own check\'s is not shown by that principal\'s twin');
  assert.equal(showsPin('actor', sel({ actor: 'member-l', resource: 'POST /notes/n1/edit' }), 'member', sel(MEMBER_OWN), 'member', principals), false, 'a wrong actor value is never the check\'s principal');
  assert.equal(showsPin('actor', { actor: 'member-1', operation: 'send' }, 'member', sel(MEMBER_OWN), 'member', principals), true, 'without a source any source shows attribution');
  assert.equal(showsPin('actor', absence, 'member', { ...sel(MEMBER_OWN), source: 'sql-audit-table' }, 'member', principals), false, 'another source does not');
  assert.deepEqual([absenceClause({ kind: 'effect.none', select: {} }), absenceClause({ kind: 'effect.count', select: {}, expected: 0 }), absenceClause({ kind: 'effect.count', select: {}, expected: 1 }), absenceClause({ kind: 'effect.exists', select: {} })], [true, true, false, false]);
  assert.deepEqual([positiveClause({ kind: 'effect.exists', select: {} }), positiveClause({ kind: 'effect.count', select: {}, expected: 1 }), positiveClause({ kind: 'effect.count', select: {}, expected: 0 })], [true, true, false]);
  assert.deepEqual([needsPairing(sel({})), needsPairing(sel({ actor: 'a' })), needsPairing(sel({ resource: 'r' })), needsPairing(sel({ traceId: 't' })), needsPairing({ source: 'http-egress', resource: { prefix: 'POST /n' } })], [false, true, true, true, true]);
  const pairs = selectorPairs(profile());
  assert.deepEqual(pairs.get('MEMBER-EDIT').map(e => [e.effect, Object.fromEntries(Object.entries(e.pins).map(([pin, twins]) => [pin, twins.map(t => t.checkId)]))]), [[0, { actor: ['MEMBER-OWN-EDIT'], resource: ['OWNER-EDIT'] }]]);
  assert.deepEqual(unpairedSelectors(profile()), []);
  assert.deepEqual(unpairedSelectors(profile({ select: sel({ actor: 'member-l', resource: 'POST /notes/n1/edit' }) })).map(u => [u.checkId, u.effect, u.pin]), [['MEMBER-EDIT', 1, 'actor']]);
  assert.deepEqual(unpairedSelectors(profile({ select: sel({ actor: 'member-1', resource: 'POST /notes/n9/edit' }) })).map(u => [u.checkId, u.effect, u.pin]), [['MEMBER-EDIT', 1, 'resource']]);
  assert.deepEqual(unpairedSelectors(profile({ select: sel({}) })), [], 'a selector the observer\'s vocabulary covers needs no twin');
  // allowed-use-not-declared is the allowed-use guard's reason (test/allowed-use-guard.test.mjs).
  assert.deepEqual(PAIRING_REASONS, ['selector-unpaired', 'selector-not-shown-to-match', 'allowed-use-not-declared']);
  for (const reason of PAIRING_REASONS) assert.match(PAIRING_BASIS[reason], new RegExp(reason));
  // applyPairing withholds a boundary pass only; a fail, an inconclusive and a control's clause are left as decided.
  const pass = { kind: 'effect.none', select: sel({ actor: 'member-1' }), verdict: 'pass', basis: 'b' };
  assert.deepEqual(applyPairing([pass], ['selector-unpaired'], 'boundary'), [{ ...pass, verdict: 'inconclusive', basis: `b ${PAIRING_BASIS['selector-unpaired']}`, pairing: 'selector-unpaired' }]);
  assert.deepEqual(applyPairing([{ ...pass, verdict: 'fail' }], ['selector-unpaired'], 'boundary'), [{ ...pass, verdict: 'fail' }]);
  assert.deepEqual(applyPairing([{ ...pass, verdict: 'inconclusive' }], ['selector-unpaired'], 'boundary'), [{ ...pass, verdict: 'inconclusive' }]);
  assert.deepEqual(applyPairing([pass], ['selector-unpaired'], 'control'), [pass]);
  assert.deepEqual(applyPairing([pass], [null], 'boundary'), [pass]);
  assert.throws(() => applyPairing([pass], ['no-such-reason'], 'boundary'), /pairing-reason/);
});

test('paired and shown: both pins have twins that matched in the deciding window, so the absence passes, with the suite\'s principals digest bound', async () => {
  const p = profile(), run = await assess(p);
  assert.deepEqual(run.results.map(r => [r.id, r.status]), [['OWNER-EDIT', 'pass'], ['MEMBER-OWN-EDIT', 'pass'], ['MEMBER-EDIT', 'pass']]);
  assert.deepEqual([clause(run, 'MEMBER-EDIT').verdict, clause(run, 'MEMBER-EDIT').custody, Object.hasOwn(clause(run, 'MEMBER-EDIT'), 'pairing')], ['pass', 'independent', false]);
  assert.deepEqual(run.principals, { member: 'member-1', owner: 'owner-1' });
  const suite = suiteOf(p);
  assert.equal(suite.principalsDigest, digest(run.principals)); assert.equal(Object.hasOwn(suite, 'principals'), false, 'the redacted suite carries the digest, not the map');
  validateHttpRunEvidence(run, { expectedSuite: suite });
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suite }).exitCode, 0);
  // The principals are bound: a run whose declared principals differ from the suite's is refused with it.
  const other = structuredClone(run); other.principals = { ...other.principals, member: 'member-2' };
  assert.throws(() => validateHttpRunEvidence(other, { expectedSuite: suite }), e => e.code === 'unexpected-suite-evidence');
  // Without principals a run under these rules is refused.
  const bare = structuredClone(run); delete bare.principals;
  assert.throws(() => validateHttpRunEvidence(bare), e => e.code === 'invalid-run-evidence');
});

test('a wrong actor or resource in the selector no longer passes vacuously: it reads inconclusive (selector-unpaired), check-config names it, and the gate fails', async () => {
  for (const [why, select, pin] of [['actor', sel({ actor: 'member-l', resource: 'POST /notes/n1/edit' }), 'actor'], ['resource', sel({ actor: 'member-1', resource: 'POST /notes/n9/edit' }), 'resource'], ['actor alone', sel({ actor: 'nobody' }), 'actor'],
    ['another principal', sel({ actor: 'owner-1', resource: 'POST /notes/n1/edit' }), 'actor']]) {
    const p = profile({ select }), run = await assess(p), r = row(run, 'MEMBER-EDIT');
    // The gate recorded nothing behind the refusal: the effect rules alone would pass this.
    assert.deepEqual([r.status, clause(run, 'MEMBER-EDIT').verdict, clause(run, 'MEMBER-EDIT').pairing, effectRow(run, 'MEMBER-EDIT').status, effectRow(run, 'MEMBER-EDIT').pairing], ['inconclusive', 'inconclusive', 'selector-unpaired', 'inconclusive', 'selector-unpaired'], why);
    assert.match(effectRow(run, 'MEMBER-EDIT').actual, /selector-unpaired/, why);
    assert.deepEqual(createRegistry({ profiles: [p], env: {} }).list().find(t => t.id === p.id).unpairedSelectors?.map(u => [u.checkId, u.effect, u.pin]) ?? [], [['MEMBER-EDIT', 1, pin]], why);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
    assert.deepEqual([summarizeGate({ candidate: run, expectedSuite: suiteOf(p) }).exitCode, summarizeGate({ candidate: run }).reasons.includes('inconclusive-evidence')], [1, true], why);
  }
  assert.equal(Object.hasOwn(createRegistry({ profiles: [profile()], env: {} }).list().find(t => t.id === 'pairing-app'), 'unpairedSelectors'), false, 'a paired profile reports nothing');
});

test('paired but not shown: a twin that matched nothing in the deciding window withholds the absence (selector-not-shown-to-match); a twin seen only by another observer does not count', async () => {
  // The owner's allowed edit was not recorded by the gate in this build: the resource twin matched nothing.
  const p = profile(), run = await assess(p, [[], [MEMBER_OWN], []]);
  assert.deepEqual([row(run, 'OWNER-EDIT').status, row(run, 'MEMBER-EDIT').status, clause(run, 'MEMBER-EDIT').pairing], ['fail', 'inconclusive', 'selector-not-shown-to-match']);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  // The actor twin alone unmatched withholds it too.
  const actorOnly = await assess(p, [[OWNER_EDIT], [], []]);
  assert.deepEqual([row(actorOnly, 'MEMBER-OWN-EDIT').status, clause(actorOnly, 'MEMBER-EDIT').pairing], ['fail', 'selector-not-shown-to-match']);
  // The twin's match recorded by a window that did not decide the absence (partial coverage never decides it): the absence is
  // not a pass for its own reason, and carries no pairing finding.
  const partial = await assess(p, PLAN, { coverage: 'partial' });
  assert.deepEqual([clause(partial, 'MEMBER-EDIT').verdict, Object.hasOwn(clause(partial, 'MEMBER-EDIT'), 'pairing')], ['missing', false]);
  // Two observers: the authoritative gate decides the absence and recorded neither twin; a presence-only mirror (an egress
  // recorder without routing) recorded both twins but decides no absence. A twin seen only by a non-deciding observer does
  // not show the selector. (The owner's effect.exists passes from the mirror's record; the member's exact count, decided by
  // the one authoritative observer, fails: the gate saw nothing.)
  const two = structuredClone(p); two.observers.push({ ...two.observers[0], id: 'mirror' });
  const mirrored = await assess(two, { gate: [[], [], []], mirror: PLAN }, { evidence: { gate: 'authoritative', mirror: 'presence-only' } });
  assert.deepEqual([row(mirrored, 'OWNER-EDIT').status, row(mirrored, 'MEMBER-OWN-EDIT').status, clause(mirrored, 'MEMBER-EDIT').verdict, clause(mirrored, 'MEMBER-EDIT').pairing], ['pass', 'fail', 'inconclusive', 'selector-not-shown-to-match']);
  validateHttpRunEvidence(mirrored, { expectedSuite: suiteOf(two) });
});

test('a fail stays a fail, a control is never paired, and effect.count expecting 0 is an absence clause', async () => {
  const p = profile(), failing = await assess(p, [[OWNER_EDIT], [MEMBER_OWN], [{ actor: 'member-1', resource: 'POST /notes/n1/edit' }]]);
  assert.deepEqual([row(failing, 'MEMBER-EDIT').status, clause(failing, 'MEMBER-EDIT').verdict, Object.hasOwn(clause(failing, 'MEMBER-EDIT'), 'pairing')], ['fail', 'fail', false]);
  validateHttpRunEvidence(failing, { expectedSuite: suiteOf(p) });
  // A control's own absence clause, pinned and unpaired, keeps its verdict without a tag. (A control that declares effects proves
  // one positively, so this one also shows the owner's allowed view landing.)
  const control = profile({ controls: ['OWNER-EDIT', 'MEMBER-OWN-EDIT'] });
  control.checks.push(check('OWNER-NO-SELF', 'control', 'owner', '/notes/n3/edit', [{ kind: 'effect.none', select: sel({ actor: 'owner-1', resource: 'POST /notes/n3/edit' }) },
    { kind: 'effect.exists', select: sel({ actor: 'owner-1', resource: 'POST /notes/n3/view' }) }])); control.requiredControlIds.push('OWNER-NO-SELF');
  const withControl = await assess(control, [[OWNER_EDIT], [MEMBER_OWN], [], [{ actor: 'owner-1', resource: 'POST /notes/n3/view' }]]);
  assert.deepEqual([row(withControl, 'OWNER-NO-SELF').status, clause(withControl, 'OWNER-NO-SELF').verdict, Object.hasOwn(clause(withControl, 'OWNER-NO-SELF'), 'pairing')], ['pass', 'pass', false]);
  assert.deepEqual(unpairedSelectors(control), []);
  validateHttpRunEvidence(withControl, { expectedSuite: suiteOf(control) });
  // effect.count expecting 0: the same rule as effect.none.
  const zero = profile({ kind: 'effect.count', select: sel({ actor: 'member-1', resource: 'POST /notes/n9/edit' }) }), count = await assess(zero);
  assert.deepEqual([row(count, 'MEMBER-EDIT').status, clause(count, 'MEMBER-EDIT').kind, clause(count, 'MEMBER-EDIT').pairing], ['inconclusive', 'effect.count', 'selector-unpaired']);
  validateHttpRunEvidence(count, { expectedSuite: suiteOf(zero) });
});

const VOCAB = ['refund original-method', 'refund new-destination', 'payout'], OTHER = 'hooks.notes.example';
test('a resource the deciding observer declares for the selector\'s name needs no twin; one outside the vocabulary still does', async () => {
  const p = profile({ select: sel({ resource: 'refund new-destination' }), controls: ['OWNER-EDIT'] });
  const vouched = await assess(p, [[OWNER_EDIT], []], { resources: { [HOST]: VOCAB } });
  assert.deepEqual([row(vouched, 'MEMBER-EDIT').status, clause(vouched, 'MEMBER-EDIT').verdict, Object.hasOwn(clause(vouched, 'MEMBER-EDIT'), 'pairing')], ['pass', 'pass', false]);
  assert.deepEqual(vouched.results.find(r => r.id === 'MEMBER-EDIT').trace[1].data.windows[0].scope.resources, { [HOST]: VOCAB }, 'the vocabulary is sealed with the window, keyed by name');
  validateHttpRunEvidence(vouched, { expectedSuite: suiteOf(p) });
  const typo = profile({ select: sel({ resource: 'refund new-destinaton' }), controls: ['OWNER-EDIT'] });
  const outside = await assess(typo, [[OWNER_EDIT], []], { resources: { [HOST]: VOCAB } });
  assert.deepEqual([row(outside, 'MEMBER-EDIT').status, clause(outside, 'MEMBER-EDIT').pairing], ['inconclusive', 'selector-unpaired']);
  // A prefix is vouched for when a resource declared for the name starts with it.
  const prefixed = profile({ select: sel({ resource: { prefix: 'refund new' } }), controls: ['OWNER-EDIT'] });
  assert.equal(clause(await assess(prefixed, [[OWNER_EDIT], []], { resources: { [HOST]: ['refund new-destination'] } }), 'MEMBER-EDIT').verdict, 'pass');
  assert.equal(clause(await assess(prefixed, [[OWNER_EDIT], []], { resources: { [HOST]: ['payout'] } }), 'MEMBER-EDIT').pairing, 'selector-unpaired');
  // Without a vocabulary the same selector needs its twin.
  assert.equal(clause(await assess(p, [[OWNER_EDIT], []]), 'MEMBER-EDIT').pairing, 'selector-unpaired');
  // Two deciding observers: the vocabulary must be declared by every one of them.
  const two = structuredClone(p); two.observers.push({ ...two.observers[0], id: 'mirror' });
  const both = { gate: [[OWNER_EDIT], []], mirror: [[OWNER_EDIT], []] };
  assert.equal(clause(await assess(two, both, { resourcesById: { gate: { [HOST]: VOCAB }, mirror: { [HOST]: VOCAB } } }), 'MEMBER-EDIT').verdict, 'pass');
  assert.equal(clause(await assess(two, both, { resourcesById: { mirror: { [HOST]: VOCAB } } }), 'MEMBER-EDIT').pairing, 'selector-unpaired');
  // The vocabulary is validated with the sealed window's scope: a malformed one is refused as evidence, as are the earlier flat
  // list (a vocabulary for no name in particular) and a vocabulary for a name the observer does not report.
  for (const [why, resources] of [['a string', 'refund new-destination'], ['a flat list', VOCAB], ['an unreported name', { [OTHER]: VOCAB }], ['an empty list', { [HOST]: [] }], ['no name', {}]]) {
    const malformed = structuredClone(vouched); row(malformed, 'MEMBER-EDIT').trace[1].data.windows[0].scope.resources = resources;
    assert.throws(() => validateHttpRunEvidence(malformed), e => e.code === 'invalid-run-evidence' && e.detail === 'effect-window-scope-resources', why);
  }
  validateTargetFile({ schemaVersion: 1, targets: [p] });
});

// Vocabulary vouching: the vocabulary vouches a resource only for the exact name that lists
// it, and only while the deciding window is closed for the selector: every committed effect in it with the selector's source,
// operation and name carries a resource from that name's vocabulary. Otherwise the pin needs a twin as usual.
test('vocabulary vouching: a class vouches only for the name whose vocabulary lists it, and only in a window whose effects of that name all carry a listed class', async () => {
  const names = [HOST, OTHER];
  // A selector naming another declared name with a class that only HOST's vocabulary lists can never match: it needs a twin.
  const offName = profile({ select: sel({ name: OTHER, resource: 'refund new-destination' }), controls: ['OWNER-EDIT'] });
  const unpaired = await assess(offName, [[OWNER_EDIT], []], { names, resources: { [HOST]: VOCAB } });
  assert.deepEqual([row(unpaired, 'MEMBER-EDIT').status, clause(unpaired, 'MEMBER-EDIT').custody, clause(unpaired, 'MEMBER-EDIT').pairing], ['inconclusive', 'independent', 'selector-unpaired']);
  validateHttpRunEvidence(unpaired, { expectedSuite: suiteOf(offName) });
  // Declared for that name too, it is vouched for.
  assert.equal(clause(await assess(offName, [[OWNER_EDIT], []], { names, resources: { [HOST]: VOCAB, [OTHER]: VOCAB } }), 'MEMBER-EDIT').verdict, 'pass');
  // An effect of the name outside its vocabulary (an unclassified send) in the deciding window breaks the closure: the observer's
  // output for this name is not shown to be in the vocabulary's format, so the pin needs its twin.
  const p = profile({ select: sel({ resource: 'refund new-destination' }), controls: ['OWNER-EDIT'] });
  const open = await assess(p, [[OWNER_EDIT], [{ resource: 'GET *' }]], { resources: { [HOST]: VOCAB } });
  assert.deepEqual([clause(open, 'MEMBER-EDIT').matched, row(open, 'MEMBER-EDIT').status, clause(open, 'MEMBER-EDIT').pairing], [0, 'inconclusive', 'selector-unpaired']);
  validateHttpRunEvidence(open, { expectedSuite: suiteOf(p) });
  // A listed class of another kind keeps it closed; so does an off-vocabulary effect on another name, or one that did not commit.
  for (const [why, events] of [['a listed class', [{ resource: 'refund original-method' }]], ['another name', [{ name: OTHER, resource: 'GET *' }]], ['not committed', [{ resource: 'GET *', outcome: 'denied' }]]]) {
    assert.equal(clause(await assess(p, [[OWNER_EDIT], events], { names, resources: { [HOST]: VOCAB } }), 'MEMBER-EDIT').verdict, 'pass', why);
  }
  // Pure: one window reporting two names, with the vocabulary declared for one of them.
  const PAY = 'api.payments.test', HOOK = 'hooks.chat.test';
  const w = { source: 'http-egress', instanceId: GATE, scope: { operations: ['send'], names: [PAY, HOOK], actorAttribution: 'none', evidence: 'authoritative', resources: { [PAY]: VOCAB } }, coverage: 'complete', reason: null, events: [] };
  const absence = name => ({ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name, resource: 'refund new-destination' }, verdict: 'pass', basis: 'b' });
  const finding = (name, window = w) => pairingFindings([{ id: 'B', actorId: 'member', role: 'boundary', effects: [absence(name)], windows: [window] }], new Map([['B', [{ effect: 0, select: absence(name).select, pins: { resource: [] } }]]]))[0][0];
  const unclassified = { ...w, events: [makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: GATE }, seq: 1, operation: 'send', name: PAY, resource: 'POST *', outcome: 'committed' })] };
  assert.deepEqual([finding(PAY), finding(HOOK), finding(PAY, unclassified)], [null, 'selector-unpaired', 'selector-unpaired']);
});

// Vocabulary vouching: the closure also binds a selector that leaves out its operation or its source. Every committed
// effect of the name (and of the selector's source and operation, when it gives them) must carry a listed class; a selector that gives
// neither is closed over every committed effect of the name. The narrowing is pinned too.
test('vocabulary vouching (closure): a selector without an operation or a source is vouched for only while every committed effect of its name carries a listed class', async () => {
  for (const [why, select] of [['no operation', { source: 'http-egress', name: HOST, resource: 'refund new-destination' }], ['no source', { operation: 'send', name: HOST, resource: 'refund new-destination' }], ['neither', { name: HOST, resource: 'refund new-destination' }]]) {
    const p = profile({ select, controls: ['OWNER-EDIT'] });
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    // Closed: the deciding window holds only a listed class, so the vocabulary vouches for the pin.
    const closed = await assess(p, [[OWNER_EDIT], [{ resource: 'refund original-method' }]], { resources: { [HOST]: VOCAB } });
    assert.deepEqual([row(closed, 'MEMBER-EDIT').status, clause(closed, 'MEMBER-EDIT').verdict, Object.hasOwn(clause(closed, 'MEMBER-EDIT'), 'pairing')], ['pass', 'pass', false], why);
    validateHttpRunEvidence(closed, { expectedSuite: suiteOf(p) });
    // Open: a committed effect of the name outside the vocabulary (an unclassified send) breaks the closure, so the pin needs a twin.
    const open = await assess(p, [[OWNER_EDIT], [{ resource: 'GET *' }]], { resources: { [HOST]: VOCAB } });
    assert.deepEqual([clause(open, 'MEMBER-EDIT').matched, row(open, 'MEMBER-EDIT').status, clause(open, 'MEMBER-EDIT').pairing], [0, 'inconclusive', 'selector-unpaired'], why);
    validateHttpRunEvidence(open, { expectedSuite: suiteOf(p) });
  }
  // The narrowing: an off-vocabulary effect of the name under another operation does not fit a selector that gives its operation,
  // so the window stays closed for it, and open for a selector that gives none. The observer reports both operations, so the
  // insert is in its declared scope, and the evidence validator accepts both runs with the suite.
  const offOperation = [[OWNER_EDIT], [{ operation: 'insert', resource: 'GET *' }]], both = { resources: { [HOST]: VOCAB }, operations: ['send', 'insert'] };
  const narrowed = profile({ select: sel({ resource: 'refund new-destination' }), controls: ['OWNER-EDIT'] }), narrowedRun = await assess(narrowed, offOperation, both);
  assert.deepEqual([row(narrowedRun, 'MEMBER-EDIT').status, clause(narrowedRun, 'MEMBER-EDIT').verdict, Object.hasOwn(clause(narrowedRun, 'MEMBER-EDIT'), 'pairing')], ['pass', 'pass', false]);
  assert.deepEqual(row(narrowedRun, 'MEMBER-EDIT').trace[1].data.windows[0].scope.operations, ['send', 'insert']);
  validateHttpRunEvidence(narrowedRun, { expectedSuite: suiteOf(narrowed) });
  const unnarrowed = profile({ select: { name: HOST, resource: 'refund new-destination' }, controls: ['OWNER-EDIT'] }), unnarrowedRun = await assess(unnarrowed, offOperation, both);
  assert.deepEqual([row(unnarrowedRun, 'MEMBER-EDIT').status, clause(unnarrowedRun, 'MEMBER-EDIT').pairing], ['inconclusive', 'selector-unpaired']);
  validateHttpRunEvidence(unnarrowedRun, { expectedSuite: suiteOf(unnarrowed) });
});

// A resource the vocabulary vouches for excuses only the resource pin. An actor pin or a trace id pin on
// the same selector still needs its own twin; the only twin here is the owner's allowed edit, which shows neither (another principal,
// and no trace id). Each reads selector-unpaired, and the validator, which shares pairingFindings, accepts the run with the suite.
test('a vouched resource never excuses an actor pin or a trace id pin that has no twin', async () => {
  for (const [why, extra, pin] of [['an own actor pin', { actor: 'member-1' }, 'actor'], ['a trace id pin', { traceId: 't-404' }, 'traceId'], ['both', { actor: 'member-1', traceId: 't-404' }, 'actor']]) {
    const p = profile({ select: sel({ resource: 'refund new-destination', ...extra }), controls: ['OWNER-EDIT'] });
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    assert.ok(unpairedSelectors(p).some(u => u.checkId === 'MEMBER-EDIT' && u.pin === pin), why);
    const run = await assess(p, [[OWNER_EDIT], []], { resources: { [HOST]: VOCAB } });
    assert.deepEqual([clause(run, 'MEMBER-EDIT').matched, row(run, 'MEMBER-EDIT').status, clause(run, 'MEMBER-EDIT').pairing], [0, 'inconclusive', 'selector-unpaired'], why);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  }
  // The same resource pin alone is vouched for in the same window: only the extra pin withholds it.
  const alone = profile({ select: sel({ resource: 'refund new-destination' }), controls: ['OWNER-EDIT'] });
  assert.equal(clause(await assess(alone, [[OWNER_EDIT], []], { resources: { [HOST]: VOCAB } }), 'MEMBER-EDIT').verdict, 'pass');
});

// A committed effect of the name that carries no resource field is unclassified, so it breaks the closure
// as an off-vocabulary class does, for every selector shape. The pin then needs a twin: selector-unpaired, accepted by the validator.
test('a committed effect of the name with no resource breaks vouching', async () => {
  for (const [why, select] of [['source, operation and name', sel({ resource: 'refund new-destination' })], ['no operation', { source: 'http-egress', name: HOST, resource: 'refund new-destination' }], ['neither', { name: HOST, resource: 'refund new-destination' }]]) {
    const p = profile({ select, controls: ['OWNER-EDIT'] });
    const run = await assess(p, [[OWNER_EDIT], [{}]], { resources: { [HOST]: VOCAB } });
    const window = row(run, 'MEMBER-EDIT').trace[1].data.windows[0];
    assert.deepEqual([window.events.length, window.events[0].resource, window.events[0].outcome], [1, null, 'committed'], why);
    assert.deepEqual([clause(run, 'MEMBER-EDIT').matched, row(run, 'MEMBER-EDIT').status, clause(run, 'MEMBER-EDIT').pairing], [0, 'inconclusive', 'selector-unpaired'], why);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  }
  // Pure: a recorded effect with no resource (null, as makeEffect stores it) or one whose resource key is absent breaks the
  // closure; the same effect classified under a listed class leaves it closed.
  const w = { source: 'http-egress', instanceId: GATE, scope: { operations: ['send'], names: [HOST], actorAttribution: 'none', evidence: 'authoritative', resources: { [HOST]: VOCAB } }, coverage: 'complete', reason: null };
  const absence = { kind: 'effect.none', select: sel({ resource: 'refund new-destination' }), verdict: 'pass', basis: 'b' };
  const finding = events => pairingFindings([{ id: 'B', actorId: 'member', role: 'boundary', effects: [absence], windows: [{ ...w, events }] }], new Map([['B', [{ effect: 0, select: absence.select, pins: { resource: [] } }]]]))[0][0];
  const bare = makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: GATE }, seq: 1, operation: 'send', name: HOST, outcome: 'committed' });
  const { resource: _none, ...keyless } = bare;
  assert.deepEqual([bare.resource, Object.hasOwn(keyless, 'resource')], [null, false]);
  assert.deepEqual([finding([]), finding([bare]), finding([keyless]), finding([{ ...bare, resource: 'payout' }])], [null, 'selector-unpaired', 'selector-unpaired', null]);
});

// An actor-pin twin is the same principal and carries every key of the absence except its
// resource and trace id (source, operation, name) with the same value: attribution of this principal for this kind of effect.
test('actor-pin twins: an actor pin is shown only by a twin of the same principal with the same source, operation and name; the shipped example profiles still pair', async () => {
  const principals = { member: 'member-1', owner: 'owner-1' }, absence = sel({ actor: 'member-1', resource: 'POST /notes/n1/edit' });
  assert.equal(showsPin('actor', absence, 'member', sel(MEMBER_OWN), 'member', principals), true, 'the same kind of effect, another resource');
  assert.equal(showsPin('actor', absence, 'member', { ...sel(MEMBER_OWN), name: OTHER }, 'member', principals), false, 'another name');
  assert.equal(showsPin('actor', absence, 'member', { ...sel(MEMBER_OWN), operation: 'insert' }, 'member', principals), false, 'another operation');
  assert.equal(showsPin('actor', { ...absence, outcome: 'committed' }, 'member', sel(MEMBER_OWN), 'member', principals), false, 'a key of the absence the twin does not carry (every key but the resource and trace id must match)');
  assert.equal(showsPin('actor', sel({ actor: 'member-1', traceId: 't-1' }), 'member', sel({ actor: 'member-1', traceId: 't-2' }), 'member', principals), true, 'a trace id may differ');
  // In a run: the member's own allowed action recorded under another name no longer shows the actor pin.
  const p = profile(); p.checks.find(c => c.id === 'MEMBER-OWN-EDIT').effects[0].select = sel({ ...MEMBER_OWN, name: OTHER });
  assert.deepEqual(unpairedSelectors(p).map(u => [u.checkId, u.effect, u.pin]), [['MEMBER-EDIT', 1, 'actor']]);
  const run = await assess(p, [[OWNER_EDIT], [{ ...MEMBER_OWN, name: OTHER }], []], { names: [HOST, OTHER] });
  assert.deepEqual([row(run, 'MEMBER-OWN-EDIT').status, row(run, 'MEMBER-EDIT').status, clause(run, 'MEMBER-EDIT').pairing], ['pass', 'inconclusive', 'selector-unpaired']);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  // The shipped onboarding examples pair every pin, the actor pins included (each by the actor's own refund on the same source and name).
  const dir = new URL('../docs/profiles/', import.meta.url), files = (await readdir(dir)).filter(n => n.endsWith('.example.json'));
  assert.ok(files.length >= 5);
  let actorPins = 0;
  for (const name of files) {
    const target = JSON.parse(await readFile(new URL(name, dir), 'utf8')).targets[0];
    assert.deepEqual(unpairedSelectors(target), [], name);
    for (const entries of selectorPairs(target).values()) for (const e of entries) if (e.pins.actor) { actorPins++; assert.ok(e.pins.actor.length > 0, name); }
  }
  assert.ok(actorPins >= 4, `${actorPins} actor pins in the examples`);
});

// Resource and trace id pins stay as built. Their twin is the same selector but the actor, so it
// carries the absence's source, operation and name with the same value. Before this test only the evaluator-hash pin caught a twin
// on another destination name.
test('resource and trace id pins: a twin on another name, operation or source shows nothing, and the run reads selector-unpaired', async () => {
  const principals = { member: 'member-1', owner: 'owner-1' }, absence = sel({ actor: 'member-1', resource: 'POST /notes/n1/edit' });
  const without = (select, key) => Object.fromEntries(Object.entries(select).filter(([k]) => k !== key));
  assert.equal(showsPin('resource', absence, 'member', sel(OWNER_EDIT), 'owner', principals), true, 'resource: the same selector but the actor');
  for (const [why, twin] of [['another name', { ...sel(OWNER_EDIT), name: OTHER }], ['another operation', { ...sel(OWNER_EDIT), operation: 'insert' }], ['another source', { ...sel(OWNER_EDIT), source: 'sql-audit-table' }],
    ['no name', without(sel(OWNER_EDIT), 'name')], ['no operation', without(sel(OWNER_EDIT), 'operation')]]) {
    assert.equal(showsPin('resource', absence, 'member', twin, 'owner', principals), false, `resource: ${why}`);
  }
  const traced = sel({ actor: 'member-1', traceId: 't-1' });
  assert.equal(showsPin('traceId', traced, 'member', sel({ traceId: 't-1' }), 'owner', principals), true, 'trace id: the same selector but the actor');
  for (const [why, twin] of [['another name', sel({ traceId: 't-1', name: OTHER })], ['another operation', sel({ traceId: 't-1', operation: 'insert' })], ['no name', without(sel({ traceId: 't-1' }), 'name')], ['another trace id', sel({ traceId: 't-2' })]]) {
    assert.equal(showsPin('traceId', traced, 'member', twin, 'owner', principals), false, `trace id: ${why}`);
  }
  // In a run: the owner's allowed edit, the only resource twin, recorded under another name. It passes as a control and shows nothing.
  const p = profile(); p.checks.find(c => c.id === 'OWNER-EDIT').effects[0].select = sel({ ...OWNER_EDIT, name: OTHER });
  assert.deepEqual(unpairedSelectors(p).map(u => [u.checkId, u.effect, u.pin]), [['MEMBER-EDIT', 1, 'resource']]);
  const run = await assess(p, [[{ ...OWNER_EDIT, name: OTHER }], [MEMBER_OWN], []], { names: [HOST, OTHER] });
  assert.deepEqual([row(run, 'OWNER-EDIT').status, row(run, 'MEMBER-EDIT').status, clause(run, 'MEMBER-EDIT').pairing], ['pass', 'inconclusive', 'selector-unpaired']);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
});

// A twin control that was not sent (a capture it uses was unavailable) has no effect window. The connector
// paired from the profile and read selector-not-shown-to-match while the validator, pairing from the run's rows, read
// selector-unpaired, so an authentic run was refused as invalid evidence. Both now read selector-unpaired.
test('a twin that was not sent shows nothing, and the connector and the validator agree it reads selector-unpaired', async () => {
  // CREATE answers without an id, so OWNER-EDIT (the resource twin, which edits the created note) is not sent.
  const p = profile(), owner = p.checks.find(c => c.id === 'OWNER-EDIT');
  const create = { ...check('CREATE', 'control', 'owner', '/notes', []), capture: { note: { pointer: '/id', type: 'id' } } }; delete create.effects;
  Object.assign(owner, { path: '/notes/{{note}}/edit', precondition: [{ name: 'note', type: 'id', createdBy: 'owner' }] });
  p.checks.unshift(create); p.requiredControlIds.unshift('CREATE');
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  assert.deepEqual(unpairedSelectors(p), [], 'the profile has the twin; only the run shows it was not sent');
  const run = await assess(p, [[MEMBER_OWN], []]);
  assert.deepEqual([row(run, 'CREATE').trace[0].data.captures[0].outcome, row(run, 'OWNER-EDIT').trace[0].data.notSent, row(run, 'OWNER-EDIT').status], ['absent', 'capture-unavailable', 'inconclusive']);
  assert.deepEqual([row(run, 'MEMBER-EDIT').status, clause(run, 'MEMBER-EDIT').verdict, clause(run, 'MEMBER-EDIT').pairing], ['inconclusive', 'inconclusive', 'selector-unpaired']);
  validateHttpRunEvidence(run);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  // The gate reads the honest run as a failed control with an inconclusive clause, never as invalid evidence.
  const gate = summarizeGate({ candidate: run, expectedSuite: suiteOf(p) });
  assert.deepEqual([gate.exitCode, gate.reasons.includes('required-controls-not-passed'), gate.reasons.includes('invalid-run-evidence')], [1, true, false]);
  // The twin sent (CREATE answers an id) shows the pin as before.
  const sent = await runHttpAssessment(p, { env: {}, transport: async (origin, c) => ({ status: c.severity === 'control' ? 200 : 403, complete: true, jsonParsed: true, json: c.id === 'CREATE' ? { id: 'n1' } : {}, bytes: 2 }), observerFactory: fakeFactory(PLAN) });
  assert.deepEqual([row(sent, 'OWNER-EDIT').status, row(sent, 'MEMBER-EDIT').status, Object.hasOwn(clause(sent, 'MEMBER-EDIT'), 'pairing')], ['pass', 'pass', false]);
  validateHttpRunEvidence(sent, { expectedSuite: suiteOf(p) });
});

test('the validator recomputes the pairing: a removed finding, a restored pass or an edited principal is refused', async () => {
  const p = profile({ select: sel({ actor: 'member-1', resource: 'POST /notes/n9/edit' }) }), run = await assess(p);
  assert.equal(clause(run, 'MEMBER-EDIT').pairing, 'selector-unpaired');
  // The stored finding is what the validator recomputes: the run validates as saved.
  assert.doesNotThrow(() => validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) }));
  const edit = change => { const copy = structuredClone(run); change(copy); recount(copy); return copy; };
  // The finding dropped and the pass restored, resealed: the recompute withholds it again.
  const restored = edit(c => {
    const r = row(c, 'MEMBER-EDIT'), e = r.trace[1].data.effects[0];
    delete e.pairing; e.verdict = 'pass';
    r.assertions = r.assertions.map(a => a.name.startsWith('Observed effect') ? (({ pairing: _p, ...rest }) => ({ ...rest, status: 'pass', actual: rest.actual.replace(/^inconclusive/, 'pass').replace(/ Pairing: .*$/, '') }))(a) : a);
    r.status = 'pass'; r.decision = 'pass'; r.summary = 'Response predicates and observed effects passed.'; reseal(r);
  });
  assert.throws(() => validateHttpRunEvidence(restored), e => e.code === 'invalid-run-evidence' && e.detail === 'effect-verdict');
  // The reason swapped for the other one is refused as well.
  assert.throws(() => validateHttpRunEvidence(edit(c => { const r = row(c, 'MEMBER-EDIT'); r.trace[1].data.effects[0].pairing = 'selector-not-shown-to-match'; r.assertions.find(a => a.name.startsWith('Observed effect')).pairing = 'selector-not-shown-to-match'; reseal(r); })), e => e.detail === 'effect-verdict');
  // A paired run whose principals are edited so the twin no longer pairs: the stored pass no longer matches the recompute.
  const paired = await assess(profile());
  const renamed = structuredClone(paired); renamed.principals.owner = 'owner-2';
  assert.throws(() => validateHttpRunEvidence(renamed), e => e.detail === 'effect-verdict');
  // A run saved under the earlier rules (actor-identity/4) carried no pairing and no principals; it is not re-paired. Its
  // identity schema is bound to the suite and to the comparison instead (contracts.mjs, runner.mjs).
  assert.equal(validateHttpRunEvidence(paired).v2, true);
});
