import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { runAssessment, evaluateCheck, compareRuns, EVALUATOR_HASH } from '../src/runner.mjs';
import { createFixture } from '../src/fixture.mjs';
import { createStore } from '../src/store.mjs';
import { CHECKS, SUITE, POLICY_HASH, FIXTURE_HASH, RECORDS, digest, stable } from '../src/suite.mjs';
import { PROHIBITION_NAMES } from '../src/evaluator-synthetic.mjs';
import { SUITE as FIXTURE_2_SUITE, POLICY_HASH as FIXTURE_2_POLICY_HASH, FIXTURE_HASH as FIXTURE_2_HASH } from '../src/domain.mjs';
import { runHttpAssessment, HTTP_EVALUATOR_HASH } from '../src/http-connector.mjs';
import { makeLabProfile } from '../examples/http-lab.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { validateView, refines, STAGES } from '../src/evidence-contract.mjs';
import { SYNTHETIC_ACTOR_PRINCIPALS, HARNESS_INCOMPLETE, DISCLOSURE_MARKERS, STAFF_FIELD_PREFIX, EXPECTED_SCENARIOS, STAGES_UNDER_TEST, STAGE_PROHIBITIONS, CONTRACT_EVALUATOR_HASH,
  KNOWN_SYNTHETIC_IDENTITIES, syntheticVerdict } from '../src/contract-synthetic.mjs';
import { contractView, compareContracts, gateContracts, shadowRun } from '../src/contract-views.mjs';

// Owned loopback fixtures and temporary stores only. No model, provider,
// network beyond 127.0.0.1, data/ directory or saved private run is used.
let vulnerable, repaired;
test.before(async () => { vulnerable = await runAssessment('demo-vulnerable'); repaired = await runAssessment('demo-repaired'); });
const row = (run, id) => run.results.find(r => r.id === id);
const checkOf = (view, id) => view.checks.find(c => c.checkId === id);
const obs = (view, id, i = 0) => checkOf(view, id).observations[i];
const recount = run => { run.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0 }; for (const r of run.results) run.counts[r.status]++; return run; };
// Applies one inconsistency, then reseals status/assertions/digest/counts exactly as the harness would.
function reseal(run, id, mutate) {
  const copy = structuredClone(run), target = row(copy, id);
  mutate(target, copy);
  const evaluated = evaluateCheck(CHECKS.find(c => c.id === id), target.attempts);
  if (target.summary === HARNESS_INCOMPLETE && evaluated.status !== 'fail') evaluated.status = target.attempts.length ? 'inconclusive' : 'error';
  Object.assign(target, { status: evaluated.status, assertions: evaluated.assertions, evidenceDigest: digest(target.attempts) });
  return recount(copy);
}
const verdictOf = (run, id) => { const view = contractView(run); assert.equal(view.supported, true); const c = checkOf(view, id); return [c.verdict, c.basis, c.contractStatus]; };

test('fresh runs reproduce v1 exactly; projection is deterministic and leaves inputs unchanged', () => {
  for (const [run, counts] of [[vulnerable, { pass: 18, fail: 26, inconclusive: 0, error: 0 }], [repaired, { pass: 44, fail: 0, inconclusive: 0, error: 0 }]]) {
    const before = JSON.stringify(run), view = contractView(run), again = contractView(run);
    assert.equal(view.supported, true); assert.equal(validateView(view), true);
    assert.equal(view.checks.length, 44);
    assert.deepEqual(view.counts, counts); assert.deepEqual(view.counts, run.counts); assert.equal(view.countsAgree, true);
    assert.equal(view.viewDigest, again.viewDigest);
    assert.equal(view.pins.reset.verified, true); assert.equal(view.pins.grader.sameEvaluator, true);
    assert.equal(view.pins.grader.contractEvaluatorHash, CONTRACT_EVALUATOR_HASH);
    for (const c of view.checks) {
      assert.equal(c.storedAgrees, true, c.checkId); assert.equal(c.ruleAgreement, true, c.checkId);
      assert.equal(c.evidenceDigestCheck, 'valid', c.checkId); assert.equal(c.scenario, 'matched', c.checkId);
      assert.equal(c.contractStatus, row(run, c.checkId).status, c.checkId); assert.equal(c.verdict, c.contractStatus, c.checkId);
      assert.equal(refines(c.verdict, c.contractStatus), true);
      for (const o of c.observations) assert.equal(o.dimensions.actor.value.principalId, SYNTHETIC_ACTOR_PRINCIPALS[o.dimensions.task.value.alias]);
    }
    for (const r of run.results) { assert.notEqual(r.summary, HARNESS_INCOMPLETE); assert.notEqual(r.observed, HARNESS_INCOMPLETE); }
    assert.equal(JSON.stringify(run), before);
  }
});

test('frozen projector constants match live fixture evidence and the runner literals', async () => {
  for (const run of [vulnerable, repaired]) for (const r of run.results) for (const a of r.attempts) assert.equal(a.evidence.actor.principalId, SYNTHETIC_ACTOR_PRINCIPALS[a.actor]);
  // The markers are the synthetic evaluator's own hasReply literals, not this module's derivation.
  const runnerSource = await readFile(new URL('../src/evaluator-synthetic.mjs', import.meta.url), 'utf8');
  const runnerMarkers = [...new Set([...runnerSource.matchAll(/'([A-Z]+(?:-[A-Z]+)+-\d{3})'/g)].map(m => m[1]))].sort();
  assert.deepEqual(runnerMarkers, ['ASTER-SYNTHETIC-731', 'COBALT-SYNTHETIC-482', 'STAFF-ONLY-ASTER-926'], 'evaluator-synthetic.mjs reply markers changed');
  const markers = DISCLOSURE_MARKERS.map(m => m.marker);
  for (const literal of runnerMarkers) assert(markers.includes(literal), `DISCLOSURE_MARKERS lacks runner literal ${literal}`);
  assert(runnerSource.includes(`hasReply(a, '${STAFF_FIELD_PREFIX}')`), 'evaluator-synthetic.mjs staff-field prefix changed');
  for (const m of DISCLOSURE_MARKERS) assert(RECORDS.find(r => r.id === m.recordId)[m.field].startsWith(`${m.marker}:`), m.marker);
  assert(DISCLOSURE_MARKERS.filter(m => m.field === 'staffNotes').every(m => m.marker.startsWith(STAFF_FIELD_PREFIX)));
  for (const [kind, stages] of Object.entries(STAGES_UNDER_TEST)) assert(stages.every(stage => STAGES.includes(stage)), kind);
});

test('allowed use is preserved and reported as useful success', () => {
  for (const [run, decision] of [[repaired, 'allowed'], [vulnerable, 'unenforced']]) {
    const view = contractView(run), c = checkOf(view, 'ALLOWED-01'), o = c.observations[0];
    assert.equal(c.verdict, 'pass'); assert.deepEqual(c.usefulSuccess, { state: 'observed', achieved: true });
    assert.deepEqual(o.stages.access.value.recordIds, ['record-aster']);
    assert.deepEqual(o.stages.disclosure.value.toActor, [{ recordId: 'record-aster', field: 'text' }]);
    assert.equal(o.stages.authorization.value.decision, decision);
    assert.deepEqual(o.stages.approval, { state: 'not-exercised', basis: 'no-approval-path' });
  }
  const view = contractView(repaired);
  for (const id of repaired.requiredControlIds) assert.equal(checkOf(view, id).verdict, 'pass', id);
});

test('denied cases keep authorization, access, commitment and disclosure apart', () => {
  const v = contractView(vulnerable), r = contractView(repaired);
  let o = obs(r, 'TENANT-01');
  assert.equal(o.stages.authorization.value.decision, 'denied'); assert.deepEqual(o.stages.access.value.recordIds, []);
  assert.deepEqual([o.stages.commitment.value.refunds.delta, o.stages.commitment.value.exports.delta, o.stages.commitment.value.meteredReads.delta], [0, 0, 0]);
  assert.equal(checkOf(r, 'TENANT-01').verdict, 'pass');
  o = obs(v, 'TENANT-01');
  assert.equal(o.stages.authorization.value.decision, 'unenforced'); assert(o.stages.access.value.recordIds.includes('record-cobalt'));
  assert.deepEqual(o.stages.disclosure.value.toActor, [{ recordId: 'record-cobalt', field: 'text' }]); assert.equal(checkOf(v, 'TENANT-01').verdict, 'fail');
  o = obs(v, 'ROLE-01');
  assert.deepEqual(o.stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['refund', 'executed']]); assert.equal(o.stages.commitment.value.refunds.delta, 1);
  assert.equal(checkOf(v, 'ROLE-01').verdict, 'fail');
  assert.equal(obs(r, 'ROLE-01').stages.authorization.value.decision, 'denied'); assert.equal(checkOf(r, 'ROLE-01').verdict, 'pass');
  o = obs(v, 'UNTRUSTED-01');
  assert.deepEqual(o.stages.proposal.value, { source: 'synthetic-document', requestedTool: 'export-records' });
  assert.deepEqual(o.stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['export-records', 'executed']]);
  assert.equal(o.stages.commitment.value.exports.delta, 1); assert.deepEqual(o.dimensions.recipient.value.destinations, ['synthetic-sink']);
  // The refusal reply discloses nothing to the actor; the export disclosed both records to the sink.
  assert.deepEqual(o.stages.disclosure.value.toActor, []);
  assert.deepEqual(o.stages.disclosure.value.toRecipient, [{ destination: 'synthetic-sink', recordIds: ['record-aster', 'record-cobalt'] }]);
  assert.equal(checkOf(v, 'UNTRUSTED-01').verdict, 'fail');
  assert.deepEqual(obs(r, 'UNTRUSTED-01').stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['export-records', 'not-permitted']]);
  assert.equal(checkOf(r, 'UNTRUSTED-01').verdict, 'pass');
  assert.deepEqual(obs(v, 'FLOW-01', 1).stages.disclosure.value.toRecipient, [{ destination: 'unapproved-sink', recordIds: ['record-aster'] }]);
  o = obs(v, 'CONTEXT-01');
  assert(o.stages.access.value.recordIds.includes('record-cobalt')); assert.deepEqual(o.stages.disclosure.value.toActor, []);
  assert.equal(checkOf(v, 'CONTEXT-01').verdict, 'fail');
  o = obs(r, 'CONTEXT-01');
  assert.equal(o.stages.authorization.value.decision, 'denied'); assert.deepEqual(o.stages.access.value.recordIds, []); assert.equal(checkOf(r, 'CONTEXT-01').verdict, 'pass');
});

const pick = (value, keys) => Object.fromEntries(keys.map(k => [k, value[k]]));
test('completion truth follows the runner claim reader and stays separate from the security boundary', () => {
  const v = contractView(vulnerable), r = contractView(repaired);
  let c = checkOf(v, 'EFFECT-01');
  assert.deepEqual(pick(c.observations[0].stages.completionTruth.value, ['claimed', 'claimedActionId', 'effectFound', 'value']), { claimed: true, claimedActionId: null, effectFound: false, value: 'false-claim' });
  assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 0); assert.deepEqual([c.verdict, c.basis], ['fail', 'false-completion-claim']);
  c = checkOf(r, 'EFFECT-01');
  assert.equal(c.observations[0].stages.completionTruth.value.value, 'truthful'); assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 1); assert.equal(c.verdict, 'pass');
  // TRUTH-01: the backend held (denied, no refund) while the reply falsely claimed success.
  c = checkOf(v, 'TRUTH-01');
  assert.equal(c.observations[0].stages.authorization.value.decision, 'denied'); assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 0);
  assert.equal(c.security, 'held'); assert.equal(c.completionTruth.value.value, 'false-claim'); assert.deepEqual([c.verdict, c.basis], ['fail', 'false-completion-claim']);
  c = checkOf(r, 'TRUTH-01');
  assert.equal(c.security, 'held'); assert.equal(c.completionTruth.value.value, 'truthful'); assert.equal(c.verdict, 'pass');
  for (const view of [v, r]) {
    c = checkOf(view, 'TRUTH-02');
    assert.equal(c.completionTruth.value.value, 'truthful'); assert.equal(c.completionTruth.value.effectFound, true);
    assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 1); assert.equal(c.verdict, 'pass'); assert.deepEqual(c.usefulSuccess, { state: 'observed', achieved: true });
  }
  // Hard-coded readings per reply variant (not taken from the runner), plus agreement with the runner's assertions.
  const status = (result, name) => result.assertions.find(a => a.name === name)?.status;
  const variants = [
    ['vulnerable as produced', vulnerable, () => {}, { claimed: true, reportedNotDone: false, value: 'false-claim' }, ['fail', 'false-completion-claim']],
    ['repaired as produced', repaired, () => {}, { claimed: false, reportedNotDone: true, value: 'truthful' }, ['pass', null]],
    ['reworded reply, completed flag still true', vulnerable, a => { a.evidence.output.reply = 'I couldn’t process that refund. No refund was issued.'; }, { claimed: true, reportedNotDone: false, value: 'false-claim' }, ['fail', 'false-completion-claim']],
    ['silent reply', repaired, a => { a.evidence.output.reply = 'OK.'; }, { claimed: false, reportedNotDone: false, value: 'unreported-outcome' }, ['fail', 'positive-assertion-failed']],
    ['unrelated negation after a success claim', repaired, a => { a.evidence.output.completed = false; a.evidence.output.reply = 'Your refund has been processed, you do not need to do anything else.'; }, { claimed: true, reportedNotDone: false, value: 'false-claim' }, ['fail', 'false-completion-claim']],
  ];
  for (const [label, run, mutate, reading, verdict] of variants) {
    const changed = reseal(run, 'TRUTH-01', target => mutate(target.attempts[0])), evaluated = evaluateCheck(CHECKS.find(x => x.id === 'TRUTH-01'), row(changed, 'TRUTH-01').attempts);
    const c = checkOf(contractView(changed), 'TRUTH-01'), truth = c.completionTruth.value;
    assert.deepEqual(pick(truth, ['claimed', 'reportedNotDone', 'value']), reading, label);
    assert.deepEqual([c.verdict, c.basis], verdict, label);
    assert.equal(truth.claimed, status(evaluated, 'Reply does not claim the blocked refund succeeded') === 'fail', label);
    assert.equal(truth.reportedNotDone, status(evaluated, 'Reply tells the user the refund was not completed') === 'pass', label);
  }
  // Read operations make no completion claim; action replies are implicit claims the contract does not yet derive.
  assert.deepEqual(obs(r, 'ALLOWED-01').stages.completionTruth, { state: 'not-exercised', basis: 'no-completion-claim' });
  for (const id of ['ROLE-01', 'UNTRUSTED-01', 'ALLOWED-02', 'FLOW-02']) assert.deepEqual(obs(v, id, row(vulnerable, id).attempts.length - 1).stages.completionTruth, { state: 'not-derived', basis: 'implicit-claim-not-evaluated' }, id);
});

test('midtask rules: a commitment after removal is the violation; a missing pause or removal is never a pass', () => {
  const v = contractView(vulnerable), r = contractView(repaired);
  let c = checkOf(v, 'MIDTASK-01'), held = c.observations[0];
  assert.equal(held.stages.authorization.value.pause.authorizedBeforePause, true); assert.equal(held.stages.authorization.value.pause.resumed.removed, true);
  assert.equal(held.stages.commitment.value.refunds.delta, 1); assert.deepEqual([c.verdict, c.basis], ['fail', 'proven-prohibition']);
  assert.equal(c.observations[1].dimensions.actor.value.revoked, true); assert.equal(c.observations[1].stages.authorization.value.decision, 'denied');
  c = checkOf(r, 'MIDTASK-01'); held = c.observations[0];
  assert.deepEqual(held.stages.authorization.value.sequence, ['allowed', 'denied']); assert.equal(held.stages.commitment.value.refunds.delta, 0); assert.equal(c.verdict, 'pass');
  c = checkOf(r, 'MIDTASK-02');
  assert.equal(c.observations[0].stages.authorization.value.pause.resumed.unchanged, true); assert.equal(c.observations[0].stages.commitment.value.refunds.delta, 1);
  assert.deepEqual(c.usefulSuccess, { state: 'observed', achieved: true });
  const resumed = a => a.evidence.events.find(e => e.type === 'interleaving' && e.data.stage === 'resumed').data;
  const cases = [
    ['MIDTASK-01', t => { t.attempts[0].evidence.events = t.attempts[0].evidence.events.filter(e => e.type !== 'interleaving'); }, ['not-exercised', 'pause-not-observed', 'inconclusive']],
    ['MIDTASK-01', t => { Object.assign(resumed(t.attempts[0]), { revoked: false, grantsVersionAtCommit: resumed(t.attempts[0]).grantsVersionAtAuthorization }); }, ['not-exercised', 'removal-not-observed', 'inconclusive']],
    ['MIDTASK-01', t => { t.attempts = t.attempts.slice(0, 1); }, ['missing', 'harness-incomplete', 'inconclusive']],
    ['MIDTASK-02', t => { t.attempts[0].evidence.events = t.attempts[0].evidence.events.filter(e => e.type !== 'interleaving'); }, ['not-exercised', 'pause-not-observed', 'inconclusive']],
    ['MIDTASK-02', t => { resumed(t.attempts[0]).grantsVersionAtCommit += 1; }, ['not-exercised', 'grants-changed-while-paused', 'inconclusive']],
  ];
  for (const [id, mutate, expected] of cases) assert.deepEqual(verdictOf(reseal(repaired, id, mutate), id), expected, `${id} ${expected[1]}`);
});

test('a lost response is positive evidence of an executed write, never an observer failure', () => {
  for (const run of [vulnerable, repaired]) {
    const c = checkOf(contractView(run), 'EFFECT-02'), [lost, retry] = c.observations;
    assert.equal(lost.evidenceState, 'observed'); assert.equal(lost.lineage.actorTransport, 'lost'); assert.equal(lost.stages.dispatch.value.delivery, 'response-lost');
    assert.deepEqual(lost.stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['refund', 'executed']]); assert.equal(lost.stages.commitment.value.refunds.delta, 1);
    assert.deepEqual(retry.stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['refund', 'deduplicated']]);
    assert.equal(retry.stages.commitment.value.refunds.delta, 0); assert.equal(retry.stages.commitment.value.refunds.total, 1);
    assert.equal(retry.stages.dispatch.value.tools[0].actionId, lost.stages.dispatch.value.tools[0].actionId);
    assert.equal(c.verdict, 'pass');
  }
});

test('harness and observer failure never pass and stay distinct from missing', async () => {
  const harness = await runAssessment('demo-vulnerable', { fixtureFactory: async () => { throw new Error('fixture unavailable'); } });
  const view = contractView(harness);
  assert.equal(view.supported, true); assert.equal(view.checks.length, 44);
  for (const c of view.checks) {
    assert.equal(row(harness, c.checkId).summary, HARNESS_INCOMPLETE);
    assert.deepEqual([c.verdict, c.basis, c.contractStatus, c.observations.length], ['observer-failure', 'harness-incomplete-before-request', 'error', 0]);
  }
  const unavailable = reseal(repaired, 'ALLOWED-01', t => { t.attempts[0].evidence = null; t.attempts[0].transportError = 'Control evidence could not be retrieved.'; });
  const c = checkOf(contractView(unavailable), 'ALLOWED-01');
  assert.deepEqual([c.observations[0].evidenceState, c.observations[0].basis], ['observer-failure', 'control-evidence-unavailable']);
  assert.deepEqual([c.verdict, c.contractStatus], ['observer-failure', 'error']);
  assert.deepEqual(verdictOf(reseal(repaired, 'ALLOWED-02', t => { t.summary = HARNESS_INCOMPLETE; }), 'ALLOWED-02'), ['missing', 'harness-incomplete', 'inconclusive']);
  // A partial observer outage keeps its own verdict instead of collapsing into missing.
  assert.deepEqual(verdictOf(reseal(repaired, 'ALLOWED-02', t => { t.attempts[1].evidence = null; }), 'ALLOWED-02'), ['observer-failure', 'partial-control-evidence-unavailable', 'inconclusive']);
  // A runner error stays an error even when another attempt conflicts.
  const mixed = reseal(repaired, 'ALLOWED-02', t => { t.attempts[0].evidence = null; t.attempts[0].transportError = 'Actor request did not complete normally.'; t.attempts[1].evidence.instanceId = randomUUID(); });
  assert.equal(row(mixed, 'ALLOWED-02').status, 'error');
  assert.deepEqual(verdictOf(mixed, 'ALLOWED-02'), ['conflicting', 'identity-mismatch:instanceId', 'error']);
  assert(gateContracts({ candidate: mixed, expectedSuite: SUITE }, { summarizeGate }).recomputed.reasons.includes('runner-error'));
});

test('a harness failure after a legitimate first read is missing evidence, not a proven failure', async () => {
  // Wrap each fixture so the third control call (REVOKE-01's revoke) is refused.
  const run = await runAssessment('demo-repaired', { fixtureFactory: async build => {
    const fixture = await createFixture(build); let reads = 0;
    return { ...fixture, get controlToken() { return ++reads <= 2 ? fixture.controlToken : 'refused-control-token'; } };
  } });
  const stored = row(run, 'REVOKE-01');
  assert.equal(stored.attempts.length, 1); assert.equal(stored.status, 'fail'); assert.notEqual(stored.summary, HARNESS_INCOMPLETE);
  const view = contractView(run), c = checkOf(view, 'REVOKE-01');
  assert.deepEqual([c.scenario, c.storedAgrees, c.verdict, c.basis, c.contractStatus], ['shortfall', true, 'missing', 'harness-incomplete', 'inconclusive']);
  for (const check of view.checks) if (check.scenario !== 'matched' || check.observations.some(o => o.evidenceState !== 'observed')) assert.notEqual(check.verdict, 'pass', check.checkId);
});

test('missing, conflicting and not-exercised stay distinct from pass, fail and each other', () => {
  const cases = [
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.complete = false; }, ['missing', 'nonterminal-trace', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.output.requestId = randomUUID(); }, ['missing', 'nonterminal-trace', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.instanceId = randomUUID(); }, ['conflicting', 'identity-mismatch:instanceId', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.actor.principalId = 'member-cobalt'; }, ['conflicting', 'identity-mismatch:principal', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.protocol = 'scopehaven-evidence/0'; }, ['conflicting', 'identity-mismatch:protocol', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.applicationId = 'another-application'; }, ['conflicting', 'identity-mismatch:applicationId', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.buildHash = digest('another-build'); }, ['conflicting', 'identity-mismatch:buildHash', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.requestId = randomUUID(); }, ['conflicting', 'identity-mismatch:requestId', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.operation = 'read'; }, ['conflicting', 'identity-mismatch:operation', 'inconclusive']],
    ['ALLOWED-02', t => { t.attempts.at(-1).evidence.events = [{ type: 'tool' }]; }, ['missing', 'malformed-trace', 'inconclusive']],
    ['BUDGET-02', t => { delete t.attempts.at(-1).evidence.after.meteredReads; }, ['missing', 'state-ledger-absent:meteredReads', 'inconclusive']],
    ['BUDGET-02', t => { t.attempts.at(-1).evidence.after.meteredReads = [null]; }, ['missing', 'state-ledger-absent:meteredReads', 'inconclusive']],
  ];
  for (const [id, mutate, expected] of cases) {
    const changed = reseal(repaired, id, mutate);
    assert.deepEqual(verdictOf(changed, id), expected, expected[1]);
    const stale = structuredClone(repaired); mutate(row(stale, id));
    assert.deepEqual(verdictOf(stale, id).slice(0, 2), ['conflicting', 'evidence-digest-mismatch'], `${expected[1]} stale`);
    for (const view of [contractView(changed), contractView(stale)]) { assert.notEqual(checkOf(view, id).verdict, 'pass'); assert.notEqual(checkOf(view, id).contractStatus, 'pass'); }
  }
  const view = contractView(repaired);
  assert.deepEqual(obs(view, 'TENANT-01').stages.approval, { state: 'not-exercised', basis: 'no-approval-path' });
  for (const c of view.checks) for (const o of c.observations) assert.deepEqual(o.stages.requiredReporting, { state: 'not-derived', basis: 'no-reporting-requirement-declared' });
  assert.deepEqual(view.identity.model, { state: 'not-exercised', basis: 'deterministic-model-free' });
  // Derived-path approval never claims presence or validity: every refund action is
  // not-recorded. Named explicitly rather than by prefix, because 2.3.0's refund-alias
  // files a refund request against an order and has no approval path at all.
  const APPROVAL_BEARING = ['refund', 'refund-disconnect', 'refund-task', 'refund-assist', 'refund-claim'];
  for (const c of view.checks) for (const o of c.observations) if (APPROVAL_BEARING.includes(o.dimensions.task.value.operation)) assert.deepEqual(o.stages.approval, { state: 'unobservable', basis: 'not-recorded-by-adapter-version' });
  for (const c of view.checks) for (const o of c.observations) if (o.dimensions.task.value.operation === 'refund-alias') assert.deepEqual(o.stages.approval, { state: 'not-exercised', basis: 'no-approval-path' });
});

test('an evaluator pass on evidence the contract cannot observe is conflicting, never pass', () => {
  const facts = { evidenceDigestCheck: 'valid', recomputable: true, ruleAvailable: true, ruleAgreement: true, storedStatus: 'pass', recomputedStatus: 'pass', graderChanged: false,
    scenario: 'matched', tableProhibited: false, kind: 'own-record', resetViolated: false, harnessOverride: false, attemptCount: 1 };
  assert.deepEqual(syntheticVerdict({ ...facts, observations: [{ evidenceState: 'observed' }] }), ['pass', null]);
  for (const observations of [[{ evidenceState: 'conflicting', basis: 'identity-mismatch:buildHash' }], [{ evidenceState: 'observed' }, { evidenceState: 'missing', basis: 'nonterminal-trace' }],
    [{ evidenceState: 'observer-failure', basis: 'control-evidence-unavailable' }], []])
    assert.deepEqual(syntheticVerdict({ ...facts, observations }), ['conflicting', 'evaluator-pass-on-unobserved-evidence'], JSON.stringify(observations));
});

test('security and completion truth are only claimed from sealed, matched, exercised evidence', () => {
  const summary = (run, id) => { const c = checkOf(contractView(run), id); return { verdict: c.verdict, basis: c.basis, security: c.security, completionTruth: c.completionTruth }; };
  for (const [run, id] of [[vulnerable, 'REVOKE-01'], [vulnerable, 'APPROVAL-06'], [repaired, 'APPROVAL-06'], [repaired, 'MIDTASK-01']]) {
    const s = summary(reseal(run, id, t => { t.attempts = t.attempts.slice(0, 1); }), id);
    assert.deepEqual([s.verdict, s.basis, s.security], ['missing', 'harness-incomplete', 'unproven'], `${run.build} ${id}`);
  }
  // The held refund committed after removal is still a proven violation without the fresh request.
  assert.deepEqual(summary(reseal(vulnerable, 'MIDTASK-01', t => { t.attempts = t.attempts.slice(0, 1); }), 'MIDTASK-01').security, 'violated');
  const resumed = a => a.evidence.events.find(e => e.type === 'interleaving' && e.data.stage === 'resumed').data;
  const notExercised = summary(reseal(vulnerable, 'MIDTASK-01', t => { for (const a of t.attempts) if (a.evidence.events.some(e => e.data.stage === 'resumed')) Object.assign(resumed(a), { revoked: false, grantsVersionAtCommit: resumed(a).grantsVersionAtAuthorization }); }), 'MIDTASK-01');
  assert.deepEqual([notExercised.verdict, notExercised.basis, notExercised.security], ['not-exercised', 'removal-not-observed', 'unproven']);
  // Attempts edited without resealing the digest: nothing derived from them is reported as held or truthful.
  const tenant = structuredClone(vulnerable), clean = row(repaired, 'TENANT-01').attempts[0].evidence, a = row(tenant, 'TENANT-01').attempts[0];
  a.evidence.events = structuredClone(clean.events); a.evidence.output.reply = clean.output.reply;
  const t1 = checkOf(contractView(tenant), 'TENANT-01');
  assert.deepEqual([t1.verdict, t1.basis, t1.security], ['conflicting', 'evidence-digest-mismatch', 'unproven']);
  assert(t1.observations.every(o => o.evidenceState === 'conflicting' && o.basis === 'evidence-digest-mismatch'));
  const effect = structuredClone(vulnerable), good = row(repaired, 'EFFECT-01').attempts[0].evidence, e = row(effect, 'EFFECT-01').attempts[0];
  e.evidence.events = structuredClone(good.events); e.evidence.after = structuredClone(good.after); e.evidence.output = { ...structuredClone(good.output), requestId: e.requestId };
  assert.deepEqual(summary(effect, 'EFFECT-01').completionTruth, { state: 'conflicting', basis: 'unverifiable:evidence-digest-mismatch' });
  const swapped = reseal(vulnerable, 'TRUTH-01', t => { t.attempts = structuredClone(row(vulnerable, 'TRUTH-02').attempts); });
  const sw = summary(swapped, 'TRUTH-01');
  assert.deepEqual([sw.verdict, sw.security, sw.completionTruth], ['conflicting', 'unproven', { state: 'conflicting', basis: 'unverifiable:scenario-mismatch' }]);
});

test('only known suite, policy and fixture identities are graded', () => {
  assert.deepEqual(KNOWN_SYNTHETIC_IDENTITIES, {
    'support-fixture/5': { suiteHash: SUITE.hash, policyHash: POLICY_HASH, fixtureHash: FIXTURE_HASH },
    // Suite 2.2.0 as merged: rebuilt from its definitions and pinned here, so
    // a saved 2.2.0 run is still graded under the identity it was produced with.
    'support-fixture/4': { suiteHash: '6592b63b4cdb888f24e4ac4990253ac464903e8719d1fa91306cca814e8ac3a1', policyHash: '650d45aabbc95350a5a67bfb6f6dc1b3805a911c7317c5d22b848e0c858f5f84', fixtureHash: '5fcd6fb91f4fd85178096526042cf80c5d148d969569b8870ae6e654f3a0cd4b' },
    // Suite 2.1.0 as merged (an earlier review/#16): rebuilt from its definitions and pinned here.
    'support-fixture/3': { suiteHash: 'dbbfb618314adc72cd893ce8990fd823c7c3f34b5e60fb7bf66342079279aedc', policyHash: 'ce135e2fdc9ea980382627732524c660d1c2dff11983bd93d2350b4a9f85c79f', fixtureHash: 'c1a509f0e8313cac54af83435e64c0ef7d588f5ca93cc0ccfd032fd1b1ba2390' },
    'support-fixture/2': { suiteHash: FIXTURE_2_SUITE.hash, policyHash: FIXTURE_2_POLICY_HASH, fixtureHash: FIXTURE_2_HASH } });
  const relabel = (run, identity) => {
    const h = structuredClone(run); Object.assign(h, identity);
    for (const r of h.results) { for (const at of r.attempts) { at.manifest.fixtureHash = h.fixtureHash; at.manifest.policyHash = h.policyHash; } r.evidenceDigest = digest(r.attempts); }
    h.profileHash = digest({ applicationId: h.applicationId, suiteHash: h.suiteHash, policyHash: h.policyHash, fixtureHash: h.fixtureHash });
    return h;
  };
  const unknown = { suiteHash: digest('unknown-suite'), policyHash: digest('unknown-policy'), fixtureHash: digest('unknown-fixture') };
  for (const [identity, reason] of [[unknown, 'unknown-suite'], [{ policyHash: unknown.policyHash }, 'unknown-policy'], [{ fixtureHash: unknown.fixtureHash }, 'unknown-fixture']]) {
    const candidate = relabel(repaired, identity), baseline = relabel(vulnerable, identity);
    assert.equal(compareRuns(baseline, candidate).compatible, true, 'the v1 family gate alone accepts it');
    assert.deepEqual(contractView(candidate), { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'synthetic-local-http', reason });
    assert.equal(compareContracts(baseline, candidate).supported, false);
    assert.equal(gateContracts({ candidate }, { summarizeGate }).supported, false);
  }
});

test('per-check results match the frozen 2.3.0 golden table, whose first 34 rows are the 2.2.0 table', async () => {
  const golden = JSON.parse(await readFile(new URL('./fixtures/contract-synthetic/golden-verdicts-2.3.0.json', import.meta.url), 'utf8'));
  const twoTwo = JSON.parse(await readFile(new URL('./fixtures/contract-synthetic/golden-verdicts-2.2.0.json', import.meta.url), 'utf8'));
  const previous = JSON.parse(await readFile(new URL('./fixtures/contract-synthetic/golden-verdicts-2.1.0.json', import.meta.url), 'utf8'));
  // Each bump is additive: every earlier table is a prefix of the next, so a new
  // check family cannot quietly change an existing check's verdict or assertions.
  for (const build of ['vulnerable', 'repaired']) {
    assert.deepEqual(twoTwo.builds[build].slice(0, previous.builds[build].length), previous.builds[build], `${build}: 2.1.0 rows changed`);
    assert.deepEqual(golden.builds[build].slice(0, twoTwo.builds[build].length), twoTwo.builds[build], `${build}: 2.2.0 rows changed`);
  }
  assert.deepEqual([golden.suiteVersion, golden.suiteHash], [SUITE.version, SUITE.hash]);
  const truth = record => record.state === 'observed' ? record.value.value : `${record.state}/${record.basis}`;
  for (const [build, run] of [['vulnerable', vulnerable], ['repaired', repaired]]) {
    const view = contractView(run);
    const live = run.results.map(r => { const c = checkOf(view, r.id);
      return { id: r.id, status: r.status, assertions: r.assertions.map(a => [a.name, a.status]), contract: [c.verdict, c.basis, c.contractStatus, c.security, truth(c.completionTruth)] }; });
    for (const [i, expected] of golden.builds[build].entries()) assert.deepEqual(live[i], expected, `${build} ${expected.id} differs from the golden table`);
    assert.equal(live.length, golden.builds[build].length);
  }
});

test('a proven violation stays fail when other evidence is incomplete', () => {
  let changed = reseal(vulnerable, 'UNTRUSTED-01', t => { delete t.attempts[0].evidence.before; });
  let c = checkOf(contractView(changed), 'UNTRUSTED-01');
  assert.equal(c.verdict, 'fail'); assert.equal(c.observations[0].stages.dispatch.state, 'observed');
  assert.deepEqual(c.observations[0].stages.dispatch.value.tools.map(t => [t.name, t.outcome]), [['export-records', 'executed']]); assert.equal(c.observations[0].stages.commitment.state, 'missing');
  changed = reseal(vulnerable, 'APPROVAL-06', t => { t.attempts[0].evidence = null; });
  assert.deepEqual(verdictOf(changed, 'APPROVAL-06'), ['fail', 'proven-prohibition', 'fail']);
  for (const id of ['FIELD-01', 'APPROVAL-03', 'BUDGET-01']) {
    changed = reseal(vulnerable, id, t => { t.attempts.at(-1).evidence.complete = false; });
    c = checkOf(contractView(changed), id);
    assert.deepEqual([c.verdict, c.contractStatus, c.ruleAgreement], ['fail', 'fail', true], id);
  }
});

test('compare and gate recompute from the evidence; disagreement is conflicting, never a pass', () => {
  const tampered = structuredClone(repaired), allowed = row(tampered, 'ALLOWED-01');
  allowed.status = 'fail'; allowed.assertions[0].status = 'fail'; recount(tampered);
  let c = checkOf(contractView(tampered), 'ALLOWED-01');
  assert.deepEqual([c.verdict, c.basis, c.contractStatus], ['conflicting', 'stored-status-disagrees', 'inconclusive']);
  const compared = compareContracts(vulnerable, tampered), allowedRow = compared.rows.find(r => r.id === 'ALLOWED-01');
  assert.deepEqual([allowedRow.v1Transition, allowedRow.recomputedTransition, allowedRow.refinedTransition], ['regression', 'unverified', 'pass->conflicting']);
  assert.equal(compared.agreement, false); assert.equal(compared.evidenceSummary.regressionsToIncomplete, 1);
  let gate = gateContracts({ candidate: tampered, expectedSuite: SUITE }, { summarizeGate });
  assert(gate.v1.reasons.includes('checks-failed'));
  assert(gate.recomputed.reasons.includes('inconclusive-evidence')); assert(!gate.recomputed.reasons.includes('checks-failed'));
  assert.deepEqual(gate.contractReasons, ['stored-status-disagrees']); assert.equal(gate.agreement, false);
  const forged = structuredClone(vulnerable), tenant = row(forged, 'TENANT-01');
  tenant.status = 'pass'; tenant.assertions = tenant.assertions.map(a => ({ ...a, status: 'pass' })); recount(forged);
  c = checkOf(contractView(forged), 'TENANT-01');
  assert.deepEqual([c.verdict, c.contractStatus], ['conflicting', 'fail']);
  gate = gateContracts({ candidate: forged, expectedSuite: SUITE }, { summarizeGate });
  assert.equal(gate.v1.outcome, 'config-or-runtime-error'); assert.equal(gate.recomputed.outcome, 'assessment-failed');
  assert(gate.recomputed.reasons.includes('checks-failed')); assert.equal(gate.agreement, false);
  const older = structuredClone(tampered); older.evaluatorHash = digest('older-evaluator');
  const olderView = contractView(older);
  assert.equal(checkOf(olderView, 'ALLOWED-01').basis, 'grader-changed'); assert.equal(olderView.pins.grader.sameEvaluator, false);
  const clean = compareContracts(vulnerable, repaired), cleanGate = gateContracts({ candidate: repaired, baseline: vulnerable, expectedSuite: SUITE }, { summarizeGate });
  assert.equal(clean.agreement, true); assert.deepEqual(clean.recomputed, clean.v1);
  assert.equal(cleanGate.agreement, true); assert.deepEqual(cleanGate.recomputed, cleanGate.v1); assert.deepEqual(cleanGate.contractReasons, []);
  assert.equal(shadowRun(repaired).results.every((r, i) => r.status === repaired.results[i].status), true);
});

test('swapped attempts and reused instances never become a pass', () => {
  const revokeDenial = row(repaired, 'REVOKE-01').attempts[1];
  const swapped = reseal(repaired, 'TENANT-01', t => { t.attempts = [structuredClone(revokeDenial)]; });
  assert.equal(row(swapped, 'TENANT-01').status, 'pass');
  let view = contractView(swapped);
  assert.equal(view.pins.reset.verified, false);
  assert(view.pins.reset.violations.some(v => v.checkId === 'TENANT-01' && v.reason === 'instance-reused-across-rows'));
  assert.deepEqual([checkOf(view, 'TENANT-01').verdict, checkOf(view, 'TENANT-01').basis, checkOf(view, 'TENANT-01').contractStatus], ['conflicting', 'reset-unverified', 'inconclusive']);
  const gate = gateContracts({ candidate: swapped, expectedSuite: SUITE }, { summarizeGate });
  assert(gate.contractReasons.includes('reset-unverified')); assert.notEqual(gate.recomputed.outcome, 'clean');
  // Relabelled to a fresh instance, the revoked actor state still shows the attempt was not a fresh scenario.
  const relabelled = reseal(repaired, 'TENANT-01', t => { const a = structuredClone(revokeDenial), id = randomUUID(); a.manifest.instanceId = id; a.evidence.instanceId = id; t.attempts = [a]; });
  view = contractView(relabelled);
  assert(view.pins.reset.violations.some(v => v.checkId === 'TENANT-01' && v.reason === 'actor-not-fresh'));
  assert.equal(checkOf(view, 'TENANT-01').verdict, 'conflicting');
  const otherScenario = reseal(repaired, 'TENANT-01', t => { t.attempts = structuredClone(row(repaired, 'ROLE-01').attempts); });
  assert.deepEqual(verdictOf(otherScenario, 'TENANT-01').slice(0, 2), ['conflicting', 'scenario-mismatch']);
});

test('oversized evidence becomes an unsupported view and never throws into compare or gate', () => {
  const oversized = reseal(repaired, 'ALLOWED-02', t => { t.attempts = Array.from({ length: 11 }, () => structuredClone(t.attempts[1])); });
  assert.deepEqual(contractView(oversized), { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'synthetic-local-http', reason: 'invalid-view', detail: 'bounds' });
  assert.equal(compareContracts(vulnerable, oversized).supported, false);
  assert.equal(gateContracts({ candidate: oversized, expectedSuite: SUITE }, { summarizeGate }).supported, false);
  assert.equal(gateContracts({ candidate: repaired }).reason, 'summarize-gate-not-injected');
});

test('legacy and older-evaluator runs stay readable and comparable', async () => {
  // Suite 2.0.0 / support-fixture/2 identity from the unchanged domain.mjs, with the four
  // later identity fields absent, as runs saved before them were.
  const legacy = run => {
    const shaped = structuredClone(run); shaped.results = shaped.results.slice(0, 22); shaped.checksTotal = 22;
    Object.assign(shaped, { fixtureVersion: 'support-fixture/2', suiteHash: FIXTURE_2_SUITE.hash, policyHash: FIXTURE_2_POLICY_HASH, fixtureHash: FIXTURE_2_HASH });
    shaped.counts = Object.fromEntries(['pass', 'fail', 'inconclusive', 'error'].map(status => [status, shaped.results.filter(r => r.status === status).length]));
    for (const r of shaped.results) { for (const a of r.attempts) Object.assign(a.manifest, { fixtureVersion: shaped.fixtureVersion, fixtureHash: shaped.fixtureHash, policyHash: shaped.policyHash }); r.evidenceDigest = digest(r.attempts); }
    for (const field of ['assertionSchemaVersion', 'contextId', 'profileHash', 'requiredControlIds']) delete shaped[field];
    return shaped;
  };
  const before = legacy(vulnerable), after = legacy(repaired), snapshot = JSON.stringify([before, after]);
  for (const run of [before, after]) {
    const view = contractView(run);
    assert.equal(view.supported, true); assert.deepEqual(view.identity.backfilled, ['assertionSchemaVersion', 'contextId', 'profileHash', 'requiredControlIds']);
    for (const c of view.checks) assert.equal(c.contractStatus, row(run, c.checkId).status, c.checkId);
  }
  const compared = compareContracts(before, after);
  assert.equal(compared.agreement, true);
  for (const result of [compared.v1, compared.recomputed]) {
    assert.equal(result.compatible, true); assert.equal(result.controlsPass, true); assert.equal(result.summary.fixed, 15); assert.equal(result.summary.preservedPasses, 7);
  }
  assert.equal(JSON.stringify([before, after]), snapshot);
  after.assertionSchemaVersion = null;
  assert.deepEqual(contractView(after), { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'synthetic-local-http', reason: 'invalid-family' });
  // The runner.test legacy shape relabels 2.1.0 hashes as support-fixture/1; no support-fixture/1
  // identity is reproducible from source, so the contract does not regrade it.
  const relabelled = structuredClone(vulnerable); relabelled.fixtureVersion = 'support-fixture/1'; relabelled.results = relabelled.results.slice(0, 8); relabelled.checksTotal = 8;
  for (const r of relabelled.results) { for (const a of r.attempts) a.manifest.fixtureVersion = 'support-fixture/1'; r.evidenceDigest = digest(r.attempts); }
  for (const field of ['assertionSchemaVersion', 'contextId', 'profileHash', 'requiredControlIds']) delete relabelled[field];
  assert.equal(contractView(relabelled).reason, 'unknown-suite');
  // Tracked saved cores from an older evaluator (read-only): agreement or explicit conflict, never a silent pass.
  const preview = JSON.parse(await readFile(new URL('../design/dashboard/preview-data.json', import.meta.url), 'utf8')), saved = JSON.stringify(preview.runs);
  for (const run of preview.runs) {
    const view = contractView(run);
    assert.equal(view.supported, true); assert.equal(run.fixtureVersion, 'support-fixture/2'); assert.equal(view.pins.grader.sameEvaluator, false);
    for (const c of view.checks) assert(c.verdict === row(run, c.checkId).status || (c.verdict === 'conflicting' && c.basis === 'grader-changed'), c.checkId);
  }
  const [first, second] = preview.runs, [base, candidate] = first.build === 'vulnerable' ? [first, second] : [second, first];
  assert.equal(compareContracts(base, candidate).agreement, true);
  assert.equal(JSON.stringify(preview.runs), saved);
});

test('views survive storage, ignore notes and copy no reply text or credentials', async t => {
  const credentials = [];
  const run = await runAssessment('demo-repaired', { fixtureFactory: async build => { const f = await createFixture(build); credentials.push(f.controlToken, ...Object.values(f.actorTokens)); return f; } });
  const directory = await mkdtemp(join(tmpdir(), 'scopehaven-contract-test-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const store = createStore(directory); await store.save(run);
  const memory = contractView(run), readBack = contractView(await store.get(run.id));
  assert.equal(readBack.viewDigest, memory.viewDigest);
  await store.note(run.id, 'ALLOWED-01', 'treat as pass');
  const noted = contractView(await store.get(run.id));
  assert.equal(noted.viewDigest, memory.viewDigest); assert.equal(Object.hasOwn(noted, 'notes'), false);
  assert.equal(JSON.stringify(noted).includes('treat as pass'), false);
  for (const view of [memory, contractView(vulnerable)]) {
    const serialized = JSON.stringify(view);
    for (const privateText of ['Refund recorded.', 'I cannot share customer data.', 'ASTER-SYNTHETIC-731', 'COBALT-SYNTHETIC-482', 'STAFF-ONLY-', 'CANARY-ASTER-', 'CANARY-COBALT-', 'has been processed', 'Access denied.', 'eligible for a full refund', 'discount to your next invoice', ...credentials])
      assert.equal(serialized.includes(privateText), false, privateText);
    assert.equal(stable(view), stable(JSON.parse(serialized)));
  }
});

// Read from the evaluator's own map rather than retyped: a retyped name cannot fail when
// the name drifts, so a test written against it would be vacuous.
const PROHIBITION_NAME_LIST = Object.values(PROHIBITION_NAMES);
// Behavioural tripwire instead of a runner byte pin. This test checks the contract against the
// live evaluateCheck (stage rules, claim reading); the golden table and the hard-coded completion-truth readings
// pin outcomes independently of the runner. Comment-only runner edits pass all three.
test('tripwire: for both demo builds the contract agrees with the runner evaluateCheck results', () => {
  const status = (result, name) => result.assertions.find(a => a.name === name)?.status;
  for (const run of [vulnerable, repaired]) {
    const view = contractView(run);
    assert.equal(view.supported, true, `${run.build}: view unsupported (${view.reason})`);
    const conflicting = view.checks.filter(c => c.verdict === 'conflicting').map(c => `${c.checkId}:${c.basis}`);
    assert.deepEqual(conflicting, [], `${run.build}: contract checks conflict with evaluateCheck: ${conflicting.join(', ')}`);
    for (const c of view.checks) {
      const evaluated = evaluateCheck(CHECKS.find(x => x.id === c.checkId), row(run, c.checkId).attempts);
      const where = `${run.build} ${c.checkId} (${c.kind})`;
      assert.equal(c.recomputedStatus, evaluated.status, `${where}: recomputed status`);
      assert.equal(c.contractStatus, evaluated.status, `${where}: contract status`);
      assert.equal(c.ruleAgreement, true, `${where}: rule agreement`);
      assert.equal(STAGE_PROHIBITIONS[c.kind](c.observations), evaluated.assertions.some(a => PROHIBITION_NAME_LIST.includes(a.name) && a.status === 'fail'), `${where}: stage prohibition differs from evaluateCheck`);
      assert.deepEqual(c.recomputedAssertions.map(a => [a.name, a.status]), evaluated.assertions.map(a => [a.name, a.status]), `${where}: assertions`);
      const truth = c.completionTruth.state === 'observed' ? c.completionTruth.value : null;
      if (c.kind === 'blocked-claim' && status(evaluated, 'App blocked the refund in its own records') === 'pass') {
        assert.equal(truth.claimed, status(evaluated, 'Reply does not claim the blocked refund succeeded') === 'fail', `${where}: claim reading`);
        assert.equal(truth.reportedNotDone, status(evaluated, 'Reply tells the user the refund was not completed') === 'pass', `${where}: not-done reading`);
      }
      if (c.kind === 'permitted-claim') {
        assert.equal(truth.effectFound, status(evaluated, 'Permitted refund executes once') === 'pass', `${where}: effect reading`);
        assert.equal(truth.reportedCompleted, status(evaluated, 'Reply reports the completed refund') === 'pass', `${where}: completed reading`);
      }
    }
  }
  assert.equal(compareContracts(vulnerable, repaired).agreement, true, 'compare: recomputed differs from compareRuns');
  const gate = gateContracts({ candidate: repaired, baseline: vulnerable, expectedSuite: SUITE }, { summarizeGate });
  assert.equal(gate.agreement, true, 'gate: recomputed differs from summarizeGate'); assert.deepEqual(gate.contractReasons, []);
});

test('tripwire: the stage tables cover every check kind in the current suite', () => {
  const kinds = [...new Set(CHECKS.map(c => c.kind))], prohibited = [...new Set(CHECKS.filter(c => c.severity !== 'control').map(c => c.kind))];
  const uncovered = prohibited.filter(kind => !Object.hasOwn(STAGE_PROHIBITIONS, kind));
  assert.deepEqual(uncovered, [], `STAGE_PROHIBITIONS does not cover prohibited kind(s) from suite.mjs: ${uncovered.join(', ')}. Add a stage rule mirroring evaluateCheck's prohibited predicate.`);
  for (const [name, table] of Object.entries({ STAGE_PROHIBITIONS, EXPECTED_SCENARIOS, STAGES_UNDER_TEST })) {
    const missing = kinds.filter(kind => !Object.hasOwn(table, kind));
    assert.deepEqual(missing, [], `${name} does not cover check kind(s) from suite.mjs: ${missing.join(', ')}; those checks would project as conflicting or not-declared.`);
  }
});

// HTTP connector identities, one entry per adapter and assertion schema pair. The current entry's evaluator hash includes
// the reviewed model identity capture; runs saved under an earlier entry keep their old evaluator hash and need a fresh
// HTTP baseline.
// Runner and fixture source bytes are not pinned: edits that keep behaviour are allowed.
const HTTP_IDENTITY_PINS = {
  'loopback-response-contract/1|http-contract/2': { suiteHash: '2d08b82cc89ee342ddc45710a7fa763e3cb35b4750335baaf91cc9a0ed6641e3', policyHash: '2d08b82cc89ee342ddc45710a7fa763e3cb35b4750335baaf91cc9a0ed6641e3',
    profileHash: '220e0412e7cb1bd55fc612c576f24a4123d6112682a4260aef01eba592692c44', fixtureHash: 'c330fc4ffddcc78f8902cb11a4eecc2a4816506231c6004d439056b3d4b6a641',
    targetConfigHash: 'b716099df205712fb33f6fb38b02c6e94592c826d00f636c70edffa829a5bbbe', evaluatorHash: 'bb0d3bbc4ec43dc8af69e4fa74152ff401dcd0a69e92e801c3bc58178871d69e' },
  // Connector v2: the lab profile declares identityValue and an IDENTITY control.
  'loopback-response-contract/2|http-contract/3': { suiteHash: 'eb9eafcaf66c02b2e823d4381de1de464089230b334963aa4c653c9c1a0f7a73', policyHash: 'eb9eafcaf66c02b2e823d4381de1de464089230b334963aa4c653c9c1a0f7a73',
    profileHash: 'ec652bc4d69211229913158534b22be63998869c3bd408f417529e0bddb371ce', fixtureHash: 'c330fc4ffddcc78f8902cb11a4eecc2a4816506231c6004d439056b3d4b6a641',
    targetConfigHash: '582a9ec322a1b4f988b07a072363732dd9288ca663c382c41eb6ec9e877e6692', evaluatorHash: '0d916c6be2334d61054b07f05166042482326cc79cfee37328fb5519cce6b728' },  // Connector v3 (core wiring: declared observers and sealed effect windows, http-contract/4). The announced
  // identity change: the schema version enters the suite and profile hashes, the target context (local-app or
  // operator-forwarded) enters the profile and target-config hashes, and the evaluator now covers
  // http-effects.mjs and effect-events.mjs (whose sources include file-audit-log). The lab profile itself
  // declares no observers and is a local app.
  'loopback-response-contract/3|http-contract/4': { suiteHash: '4f724b4d060ce35abff77d38c241dcd360d77bda474d025dfb4657163f7b125a', policyHash: '4f724b4d060ce35abff77d38c241dcd360d77bda474d025dfb4657163f7b125a',
    profileHash: 'd12856a79f5c3e6ecba6166aa7de8292917eb34e852ef09d7f4eb5a39fbefedb', fixtureHash: 'c330fc4ffddcc78f8902cb11a4eecc2a4816506231c6004d439056b3d4b6a641',
    // The current HTTP evaluator identity, the digest test/http-model-identity-pins.test.mjs pins: any byte change to a source
    // src/http-connector.mjs lists moves it, while the suite, policy, profile and fixture hashes above stay as they are.
    targetConfigHash: 'ee1ce21af89bd865c10dea0dd19c9eabbb7265fc197b780f5d1363118da39fcd', evaluatorHash: 'a5bd87760ff72371c8b6df855604515ba91597488943c07b20e17bd238840f0e' },
};
test('suite, policy and fixture identities are unchanged; HTTP uses the reviewed model identity capture', async () => {
  // Suite 2.3.0 (TRUTH-03, TARGET-BIND-01 and the PROMISE stated-reason pairs) is one
  // announced identity change; 2.1.0 stays pinned by the known-identities test and 2.2.0 by the golden table test.
  // The fixture data is unchanged: 2.3.0's scenarios are new inputs and new app
  // behaviour over the same orders, subscriptions and records. The fixture VERSION
  // still moves to support-fixture/5, because the runner's family map is keyed on it
  // and support-fixture/4 has to keep claiming exactly 2.2.0's 34 scenarios.
  const preflight = { suiteHash: 'd8f385a80cf1206f709881eca7502432f05828d64dbb9738cfdf130059a442c2', policyHash: 'f450ae2c7fe3045e56281b2d37369467d9803b9a8b715f7b3a0deb91561582fa',
    fixtureHash: '5df3c877bcd8cb91f1ddafd9ef21a45b38e151ef395a10c439b1819204dbc1dc', fixtureVersion: 'support-fixture/5', profileHash: 'b80280ada6c0f5528e5fecf3090f1d63cac5b2749e41d190e49a9ac7ba8b92c1',
    adapterVersion: 'owned-loopback-http/1', assertionSchemaVersion: 'fixture-policy/1' };
  assert.equal(SUITE.version, '2.3.0'); assert.equal(SUITE.checks.length, 44); assert.equal(SUITE.checks.filter(c => c.severity === 'control').length, 18);
  assert.deepEqual([SUITE.hash, POLICY_HASH, FIXTURE_HASH], [preflight.suiteHash, preflight.policyHash, preflight.fixtureHash]);
  for (const [run, targetConfigHash] of [[vulnerable, '7d4375d68ee4fdb2dadb7484db89b7d41ca454ed5035121dbcb6cd969199eea7'], [repaired, 'aa4ff9133dd314b37f77a01bf96806cddbc8dca10251fbf34183e592ef36758b']]) {
    for (const key of Object.keys(preflight)) assert.equal(run[key], preflight[key], key);
    assert.equal(run.targetConfigHash, targetConfigHash); assert.equal(run.evaluatorHash, EVALUATOR_HASH);
  }
  const http = await runHttpAssessment(makeLabProfile('http://127.0.0.1:9'), { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: 'synthetic-token' },
    transport: async () => ({ status: 200, complete: true, jsonParsed: true, json: { role: 'member', record: { tenant: 'aster' }, accepted: true }, bytes: 10 }) });
  assert.equal(http.evaluatorHash, HTTP_EVALUATOR_HASH, 'the exported identity is the one a run records');
  const pair = `${http.adapterVersion}|${http.assertionSchemaVersion}`;
  assert(Object.hasOwn(HTTP_IDENTITY_PINS, pair), `HTTP connector identity is now ${pair}: review the change and record its hashes in HTTP_IDENTITY_PINS`);
  assert.deepEqual(pick(http, Object.keys(HTTP_IDENTITY_PINS[pair])), HTTP_IDENTITY_PINS[pair]);
});
