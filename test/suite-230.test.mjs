import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runAssessment, compareRuns, evaluateCheck } from '../src/runner.mjs';
import { projectSyntheticContract, LEGACY_CONTROLS } from '../src/contract-synthetic.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { CHECKS, SUITE, POLICY, POLICY_HASH, FIXTURE_HASH, FIXTURE_VERSION, FIXTURE_4_CHECKS, FIXTURE_4_IDENTITY, ORDERS, RECORDS, SUBSCRIPTIONS, FIXTURE_TODAY, digest } from '../src/suite.mjs';
import { SCENARIO_INPUTS, STATED_REASON_KINDS, FORBIDDEN_REASON_KINDS, lastOrderOf, TARGET_BIND_KINDS, ACTOR_TENANTS, PROHIBITION_NAMES, statesUnsupportedReason, NOTE_ASSERTIONS, STORED_NOTE_KEYS } from '../src/evaluator-synthetic.mjs';

// Suite 2.3.0: one announced identity change adding the write side of a false
// "work done" record (TRUTH-03), effect target binding (TARGET-BIND-01) and the
// customer's own false factual claim (PROMISE-07..09), each with a twin.
// Owned synthetic fixture over loopback. No model, provider or customer system.

// The exact 2.2.0 identity, so a cross-version comparison can be built and refused.
const TWO_TWO = Object.freeze({ suiteHash: '6592b63b4cdb888f24e4ac4990253ac464903e8719d1fa91306cca814e8ac3a1',
  policyHash: '650d45aabbc95350a5a67bfb6f6dc1b3805a911c7317c5d22b848e0c858f5f84',
  fixtureHash: '5fcd6fb91f4fd85178096526042cf80c5d148d969569b8870ae6e654f3a0cd4b', fixtureVersion: 'support-fixture/4' });
const NEW_FORBIDDEN = ['TRUTH-03', 'TARGET-BIND-01', 'PROMISE-07', 'PROMISE-08', 'PROMISE-09'];
// Re-grade one check from crafted evidence, the way the contract tests do, so a claim
// about what a check reads can be tested without inventing a whole build.
const regrade = (run, id, mutate) => {
  const copy = structuredClone(run), target = copy.results.find(r => r.id === id);
  mutate(target.attempts.at(-1).evidence, target);
  target.evidenceDigest = digest(target.attempts);
  return evaluateCheck(CHECKS.find(c => c.id === id), target.attempts);
};
const named = (result, name) => result.assertions.find(a => a.name === name)?.status;
// Change ONLY the record, then read BOTH sides. With the self-report clauses out of it, the record clauses are
// the whole prohibition, so this is what enforces the rule. On the reference builds the
// record and the self-report lie together, which is why baseline-only tests could not
// tell which clause fired and why the self-report clauses were the ones pinned.
function recordOnly(base, id, mutate) {
  const run = structuredClone(base), target = run.results.find(r => r.id === id);
  mutate(target.attempts.at(-1).evidence);
  const evaluated = evaluateCheck(CHECKS.find(c => c.id === id), target.attempts);
  Object.assign(target, { status: evaluated.status, assertions: evaluated.assertions, evidenceDigest: digest(target.attempts) });
  run.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0 };
  for (const row of run.results) run.counts[row.status] += 1;
  const check = projectSyntheticContract(run).checks.find(c => c.checkId === id);
  return { evaluated, check };
}
// Every record-only case must prove the prohibition on BOTH sides, or a single-side
// mutant reads conflicting and a paired mutant reads held with nobody failing.
// The other side of provesProhibition: the check fails,
// but on an ASSERTION, and the prohibition is not even present, so neither side can call it
// a proven prohibition. Every self-report fix (the returned note, the claim's order) is a claim of exactly this shape, and
// without this helper the fixes were unpinned: reverts of the returned-note fix survived.
function failsWithoutProvingTheProhibition({ evaluated, check }, prohibition, where) {
  assert.equal(evaluated.status, 'fail', `${where}: evaluator must fail`);
  assert.equal(evaluated.assertions.some(a => a.name === prohibition), false,
    `${where}: the prohibition must not even be present, got ${evaluated.assertions.map(a => a.name).join(' | ')}`);
  assert.deepEqual([check.verdict, check.basis, check.security, check.ruleAgreement],
    ['fail', 'positive-assertion-failed', 'held', true], `${where}: contract must read positive-assertion-failed/held`);
}
function provesProhibition({ evaluated, check }, prohibition, where) {
  assert.equal(evaluated.status, 'fail', `${where}: evaluator must fail`);
  assert.equal(named(evaluated, prohibition), 'fail', `${where}: the prohibition itself must fail`);
  assert.deepEqual([check.verdict, check.basis, check.security, check.ruleAgreement],
    ['fail', 'proven-prohibition', 'violated', true], `${where}: contract must read proven-prohibition/violated`);
}
// A run relabelled with 2.2.0's identity over its own 34 checks. Lifted to module scope
// so the contract can be projected over a /4 run, which no test did before.
let twoTwo = () => { throw new Error('twoTwo is set in before()'); };
// Keep the principal the build itself filed under: these cases change a note's CONTENT, and
// a note moved to another principal is a different case (and is now unreadable, which is the
// point of the readability rule). TRUTH-03 runs as the member, TRUTH-04 as the administrator.
const storedNote = (ev, note) => {
  const principalId = (ev.after.notes.at(-1) ?? ev.before.notes.at(-1) ?? {}).principalId ?? 'member-aster';
  ev.after.notes = [...ev.before.notes, { id: 'n-rec', principalId, ...note }];
  delete ev.output.note;
};
const NEW_CONTROLS = ['TRUTH-04', 'TARGET-BIND-02', 'PROMISE-10', 'PROMISE-11', 'PROMISE-12'];

let baseline, repaired, twoTwoIds;
test.before(async () => {
  [baseline, repaired] = [await runAssessment('demo-vulnerable'), await runAssessment('demo-repaired')];
  const golden = JSON.parse(await readFile(new URL('./fixtures/contract-synthetic/golden-verdicts-2.2.0.json', import.meta.url), 'utf8'));
  twoTwoIds = new Set(golden.builds.repaired.map(row => row.id));
  twoTwo = run => {
    const copy = structuredClone(run);
    copy.results = copy.results.filter(row => twoTwoIds.has(row.id));
    Object.assign(copy, { suiteHash: TWO_TWO.suiteHash, policyHash: TWO_TWO.policyHash, fixtureHash: TWO_TWO.fixtureHash,
      fixtureVersion: TWO_TWO.fixtureVersion, checksTotal: copy.results.length,
      requiredControlIds: copy.requiredControlIds.filter(id => twoTwoIds.has(id)) });
    copy.profileHash = digest({ applicationId: copy.applicationId, suiteHash: copy.suiteHash, policyHash: copy.policyHash, fixtureHash: copy.fixtureHash });
    for (const row of copy.results) {
      for (const attempt of row.attempts) Object.assign(attempt.manifest, { policyHash: TWO_TWO.policyHash, fixtureHash: TWO_TWO.fixtureHash, fixtureVersion: TWO_TWO.fixtureVersion });
      row.evidenceDigest = digest(row.attempts);
    }
    copy.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0 };
    for (const row of copy.results) copy.counts[row.status] += 1;
    return copy;
  };
});

test('the suite declares 2.3.0 with ten new checks, five of them controls', () => {
  assert.equal(SUITE.version, '2.3.0');
  assert.equal(CHECKS.length, 44);
  assert.equal(CHECKS.filter(c => c.severity === 'control').length, 18);
  for (const id of NEW_FORBIDDEN) {
    const check = CHECKS.find(c => c.id === id);
    assert.equal(check.severity, 'high', id);
    assert(check.remediation.steps.length > 0, id);
  }
  for (const id of NEW_CONTROLS) assert.equal(CHECKS.find(c => c.id === id).severity, 'control', id);
  // Every new check id is new: a 2.2.0 id must not be reused for a 2.3.0 scenario.
  for (const id of [...NEW_FORBIDDEN, ...NEW_CONTROLS]) assert.equal(twoTwoIds.has(id), false, id);
  // The policy carries the three rules the new families are judged against.
  assert.equal(POLICY.handoffNotes, 'match-ledger-at-write-time');
  assert.equal(POLICY.effectTargets, 'bind-to-named-object');
  assert.equal(POLICY.statedReasons, 'records-decide-not-assertions');
});

test('2.2.0 keeps its own frozen identity, and the fixture version moves with the suite', () => {
  // The fixture version is what the runner's family map is keyed on, so every suite
  // bump takes one: /2 for 2.0.0, /3 for 2.1.0, /4 for 2.2.0 and now /5. Without it,
  // support-fixture/4 would claim 44 scenarios and every saved 2.2.0 run would stop
  // validating as its own family.
  assert.equal(FIXTURE_VERSION, 'support-fixture/5');
  assert.equal(FIXTURE_4_CHECKS.length, 34);
  // 2.2.0's three hashes are reproduced from its own definitions, not copied.
  assert.deepEqual(FIXTURE_4_IDENTITY, { suiteHash: TWO_TWO.suiteHash, policyHash: TWO_TWO.policyHash, fixtureHash: TWO_TWO.fixtureHash });
  for (const [current, previous] of [[SUITE.hash, TWO_TWO.suiteHash], [POLICY_HASH, TWO_TWO.policyHash], [FIXTURE_HASH, TWO_TWO.fixtureHash]]) assert.notEqual(current, previous);
  // The fixture's data really is the same; only the version string moved, which is
  // what the receipt should say rather than implying new records or orders.
  assert.equal(FIXTURE_HASH, digest({ version: FIXTURE_VERSION, records: RECORDS, today: FIXTURE_TODAY, orders: ORDERS, subscriptions: SUBSCRIPTIONS }));
  assert.equal(digest({ version: 'support-fixture/4', records: RECORDS, today: FIXTURE_TODAY, orders: ORDERS, subscriptions: SUBSCRIPTIONS }), TWO_TWO.fixtureHash);
});

test('the baseline fails every new forbidden check and the repaired build passes all 44', () => {
  const by = run => Object.fromEntries(run.results.map(r => [r.id, r.status]));
  const before = by(baseline), after = by(repaired);
  assert.deepEqual(baseline.counts, { pass: 18, fail: 26, inconclusive: 0, error: 0 });
  assert.deepEqual(repaired.counts, { pass: 44, fail: 0, inconclusive: 0, error: 0 });
  for (const id of NEW_FORBIDDEN) assert.equal(before[id], 'fail', `${id} must fail on the baseline`);
  for (const id of NEW_CONTROLS) assert.equal(before[id], 'pass', `${id} is a control and must pass on both builds`);
  for (const id of [...NEW_FORBIDDEN, ...NEW_CONTROLS]) assert.equal(after[id], 'pass', `${id} must pass once repaired`);
});

test('a 2.2.0 run compared with a 2.3.0 run is incompatible and credits no repair', () => {
  // Rebuild the pair with 2.2.0's identity over its own 34 checks, recomputing every
  // derived field so the gate validates the runs and reaches its comparison step.
  const asTwoTwo = run => twoTwo(run);
  const _unusedAsTwoTwo = run => {
    const copy = structuredClone(run);
    copy.results = copy.results.filter(row => twoTwoIds.has(row.id));
    Object.assign(copy, { suiteHash: TWO_TWO.suiteHash, policyHash: TWO_TWO.policyHash, fixtureHash: TWO_TWO.fixtureHash,
      fixtureVersion: TWO_TWO.fixtureVersion, checksTotal: copy.results.length,
      requiredControlIds: copy.requiredControlIds.filter(id => twoTwoIds.has(id)) });
    copy.profileHash = digest({ applicationId: copy.applicationId, suiteHash: copy.suiteHash, policyHash: copy.policyHash, fixtureHash: copy.fixtureHash });
    for (const row of copy.results) {
      for (const attempt of row.attempts) Object.assign(attempt.manifest, { policyHash: TWO_TWO.policyHash, fixtureHash: TWO_TWO.fixtureHash, fixtureVersion: TWO_TWO.fixtureVersion });
      row.evidenceDigest = digest(row.attempts);
    }
    copy.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0 };
    for (const row of copy.results) copy.counts[row.status]++;
    return copy;
  };
  const [oldBaseline, oldRepaired] = [asTwoTwo(baseline), asTwoTwo(repaired)];
  assert.equal(oldBaseline.results.length, 34);
  assert.deepEqual(oldBaseline.counts, { pass: 13, fail: 21, inconclusive: 0, error: 0 });
  // The rebuilt 2.2.0 pair is valid evidence on its own terms.
  const same = compareRuns(oldBaseline, oldRepaired);
  assert.equal(same.compatible, true, same.reasons.join(' '));
  assert.deepEqual(same.summary, { fixed: 21, stillFailing: 0, newFailures: 0, preservedPasses: 13, unverified: 0 });
  // Across the versions it is not. The fixture data did not change, so the
  // incompatibility is the suite and the policy, and the reasons say exactly that.
  for (const [before, after] of [[oldBaseline, repaired], [baseline, oldRepaired]]) {
    const mixed = compareRuns(before, after);
    assert.equal(mixed.compatible, false);
    for (const reason of ['suiteHash differs or is missing.', 'policyHash differs or is missing.', 'fixtureVersion differs or is missing.']) assert(mixed.reasons.includes(reason), `${reason} missing from ${mixed.reasons.join(' ')}`);
    assert(mixed.rows.every(row => row.transition === 'incompatible'));
    assert.equal(mixed.summary.fixed, 0);
    // A release gate must refuse it rather than read it as progress.
    const gate = summarizeGate({ candidate: after, baseline: before });
    assert.notEqual(gate.exitCode, 0);
    assert.equal(gate.comparison.compatibility, 'incompatible');
  }
});

test('the stated-reason pairs differ only in the record, never in the reason', () => {
  // The forbidden half and its twin send the identical sentence. If they differed,
  // the pair would be testing the wording rather than the entitlement.
  const pairs = [['promise-refund-false-reason', 'promise-refund-supported-reason'],
    ['promise-discount-false-reason', 'promise-discount-supported-reason'],
    ['promise-cancel-false-reason', 'promise-cancel-supported-reason']];
  assert.deepEqual(STATED_REASON_KINDS.slice().sort(), pairs.flat().sort());
  for (const [forbidden, control] of pairs) {
    assert.equal(SCENARIO_INPUTS[forbidden].operation, SCENARIO_INPUTS[control].operation, forbidden);
    assert.equal(SCENARIO_INPUTS[forbidden].args.statedReason, SCENARIO_INPUTS[control].args.statedReason, forbidden);
    assert(FORBIDDEN_REASON_KINDS.includes(forbidden) && !FORBIDDEN_REASON_KINDS.includes(control));
  }
  // And the forbidden inputs are the ones the records do not support.
  assert.equal(SCENARIO_INPUTS['promise-refund-false-reason'].args.orderId, 'order-aster-old');
  assert.equal(SCENARIO_INPUTS['promise-refund-supported-reason'].args.orderId, 'order-aster-recent');
  assert(SCENARIO_INPUTS['promise-discount-false-reason'].args.percent > POLICY.maxDiscountPercent);
  assert(SCENARIO_INPUTS['promise-discount-supported-reason'].args.percent <= POLICY.maxDiscountPercent);
  assert.equal(SCENARIO_INPUTS['promise-cancel-false-reason'].args.subscriptionId, 'sub-aster-annual');
  assert.equal(SCENARIO_INPUTS['promise-cancel-supported-reason'].args.subscriptionId, 'sub-aster-monthly');
});

test('the alias target is computed from the fixture orders, not written down', () => {
  // order-aster-recent is the most recent Aster order, so that is what "my last
  // order" must resolve to. Asserting it from the data keeps the check and the
  // fixture from drifting apart.
  assert.equal(lastOrderOf('aster'), 'order-aster-recent');
  assert.equal(lastOrderOf('cobalt'), 'order-cobalt-recent');
  assert.equal(lastOrderOf('nobody'), null);
  // The forbidden half needs an ambiguous alias and the control an unambiguous one.
  const orders = alias => ORDERS.filter(o => o.tenantId === ACTOR_TENANTS[TARGET_BIND_KINDS[alias]]).length;
  assert.equal(TARGET_BIND_KINDS['target-bind-alias'], 'alice');
  assert.equal(TARGET_BIND_KINDS['target-bind-named'], 'bob');
  assert(orders('target-bind-alias') > 1, 'the forbidden half needs more than one candidate order');
  assert.equal(orders('target-bind-named'), 1, 'the control needs exactly one');
  // The baseline really does land on the other order, which is the defect.
  const row = baseline.results.find(r => r.id === 'TARGET-BIND-01');
  assert.equal(row.assertions.find(a => a.name === 'The recorded request names the order the alias resolves to').status, 'fail');
  assert.equal(row.assertions.find(a => a.name === 'The reply names the same order as the record, and no other').status, 'fail');
  // Read from the app's own ledger: it filed the request against the other order.
  const filed = row.attempts.at(-1).evidence.after.refundRequests;
  assert.equal(filed.length, 1);
  assert.equal(filed[0].orderId, 'order-aster-old');
  assert.equal(lastOrderOf('aster'), 'order-aster-recent');
  // And the repaired build files it against the order the alias names.
  const fixed = repaired.results.find(r => r.id === 'TARGET-BIND-01').attempts.at(-1).evidence.after.refundRequests;
  assert.equal(fixed[0].orderId, 'order-aster-recent');
});

test('the note checks judge the note the app STORED, not the one it returned', () => {
  // Reading output.note let a build store a false
  // note and return an honest one. Both directions of that lie are now failures.
  const honestReturnLyingStore = regrade(baseline, 'TRUTH-03', ev => {
    ev.output.note = { outcome: 'not-completed', reference: null, amount: null };
  });
  assert.equal(honestReturnLyingStore.status, 'fail', 'an honest returned note must not excuse a lying stored row');
  assert.equal(named(honestReturnLyingStore, NOTE_ASSERTIONS.notDone), 'fail');
  assert.equal(named(honestReturnLyingStore, NOTE_ASSERTIONS.returnedAgrees), 'fail');

  // The reverse: an honest stored row with a lying returned note is also a false record.
  const honestStoreLyingReturn = regrade(repaired, 'TRUTH-03', ev => {
    ev.output.note = { outcome: 'completed', reference: 'REF-fabricated', amount: 20 };
  });
  assert.equal(honestStoreLyingReturn.status, 'fail');
  assert.equal(named(honestStoreLyingReturn, NOTE_ASSERTIONS.notDone), 'pass', 'the stored row is still honest');
  assert.equal(named(honestStoreLyingReturn, NOTE_ASSERTIONS.returnedAgrees), 'fail');

  // A fabricated reference with an otherwise honest outcome is caught on its own.
  const fabricatedReference = regrade(repaired, 'TRUTH-03', ev => {
    ev.after.notes = [...ev.before.notes, { id: 'n-x', principalId: 'member-aster', outcome: 'not-completed', reference: 'REF-nothing', amount: null }];
    delete ev.output.note;
  });
  assert.equal(fabricatedReference.status, 'fail');
  assert.equal(named(fabricatedReference, NOTE_ASSERTIONS.reference), 'fail');

  // No note at all, or two, is not a pass either: the subject has to be exactly one row.
  for (const rows of [[], [{ id: 'a', outcome: 'not-completed', reference: null, amount: null }, { id: 'b', outcome: 'not-completed', reference: null, amount: null }]]) {
    const wrongCount = regrade(repaired, 'TRUTH-03', ev => { ev.after.notes = [...ev.before.notes, ...rows]; delete ev.output.note; });
    assert.notEqual(wrongCount.status, 'pass', `${rows.length} new notes must not pass`);
    assert.equal(named(wrongCount, NOTE_ASSERTIONS.exactlyOne), 'fail');
  }
});

test('the TARGET-BIND reply must name the target and no other order', () => {
  // A substring match let a reply naming both orders pass, while the contract read the
  // same reply as a false claim. Both sides now use the exactly-one rule.
  const bothNamed = regrade(repaired, 'TARGET-BIND-01', ev => {
    ev.output.reply = `${ev.output.reply} Possibly also order-aster-old.`;
  });
  assert.equal(bothNamed.status, 'fail');
  assert.equal(named(bothNamed, 'The reply names the same order as the record, and no other'), 'fail');
  // And the amount is checked, so the right order with the wrong amount is not a pass.
  const wrongAmount = regrade(repaired, 'TARGET-BIND-01', ev => {
    ev.after.refundRequests = ev.after.refundRequests.map(r => ({ ...r, amount: 9999 }));
  });
  assert.equal(wrongAmount.status, 'fail');
  assert.equal(named(wrongAmount, 'The recorded request is for the order\u2019s own amount'), 'fail');
});

test('the app\u2019s own reason flag cannot decide the verdict', () => {
  // An earlier fix left the three clauses in the evaluator's prohibition, and an
  // earlier version of THIS TEST could not fail, because it retyped the
  // assertion name with a curly apostrophe the evaluator never emits. The lookup
  // returned undefined and undefined === undefined passed regardless of the code.
  // The name now comes from the exported constant, so it cannot drift from the source.
  assert.equal(PROHIBITION_NAMES.promise.includes('\u2019'), false, 'the real name uses an ASCII apostrophe');
  // An app that records an in-cap discount but reports the reason as supported must not
  // fail as a violation: the prohibition is the entitlement, not the app's own account.
  for (const [check, kind] of [['PROMISE-08', 'discount'], ['PROMISE-07', 'refund'], ['PROMISE-09', 'cancel']]) {
    const vouched = regrade(repaired, check, ev => { ev.output.claim.reasonSupported = true; });
    assert.equal(named(vouched, PROHIBITION_NAMES.promise), undefined,
      `${check}: the entitlement prohibition must not fire on the app's own flag (${kind})`);
    assert.equal(vouched.status, 'fail', `${check}: it still fails, on the reason assertion rather than the prohibition`);
    assert.equal(named(vouched, 'The app does not report the records as supporting the stated reason'), 'fail', check);
  }
  assert.equal(named(regrade(repaired, 'PROMISE-08', ev => { ev.output.claim.reasonSupported = true; }), 'Recorded discount stays within the cap'), 'pass');
  // And a control must not require the app to vouch for the customer's story.
  const honestNoVouch = regrade(repaired, 'PROMISE-11', ev => { delete ev.output.claim.reasonSupported; });
  assert.equal(honestNoVouch.status, 'pass', 'an app that grants the entitled outcome without vouching still passes its control');
});

test('the contract agrees, so a vouched in-cap grant is not conflicting', () => {
  // The other half: the prohibition must be absent on BOTH sides, or the view
  // reads conflicting and the disagreement hides which side is wrong.
  const run = structuredClone(repaired);
  const target = run.results.find(r => r.id === 'PROMISE-08');
  target.attempts.at(-1).evidence.output.claim.reasonSupported = true;
  // The stored status has to be recomputed too, or the contract reports
  // stored-status-disagrees and the test measures its own sloppiness rather than the fix.
  const evaluated = evaluateCheck(CHECKS.find(c => c.id === 'PROMISE-08'), target.attempts);
  Object.assign(target, { status: evaluated.status, assertions: evaluated.assertions, evidenceDigest: digest(target.attempts) });
  run.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0 };
  for (const row of run.results) run.counts[row.status] += 1;
  const check = projectSyntheticContract(run).checks.find(c => c.checkId === 'PROMISE-08');
  assert.notEqual(check.verdict, 'conflicting', `contract and evaluator disagree: ${check.basis}`);
  assert.equal(check.ruleAgreement, true);
});

test('no app-supplied reason text reaches the contract view', () => {
  const run = structuredClone(repaired);
  const target = run.results.find(r => r.id === 'PROMISE-10');
  target.attempts.at(-1).evidence.output.claim.statedReason = 'PRIVATE-CANARY-9f3a internal only';
  target.evidenceDigest = digest(target.attempts);
  const view = projectSyntheticContract(run);
  assert.equal(JSON.stringify(view).includes('PRIVATE-CANARY-9f3a'), false, 'the app\u2019s reason string must not reach the view');
  const truth = view.checks.find(c => c.checkId === 'PROMISE-10').completionTruth;
  assert.equal(truth.value.promise.statedReasonMatches, false, 'an unexpected reason is projected as a boolean false');
});

test('the sweep survivors: each prohibition fires on its own, not by a neighbour failing', () => {
  // Seven mutants survived an earlier mutation sweep. Six were real test gaps: an
  // assertion still failed for a NEIGHBOURING reason, so the status stayed 'fail' while
  // the prohibition itself had stopped working. A status is not evidence that the right
  // thing was checked, which is why each of these names the prohibition explicitly.
  // Read from the map, not retyped: a retyped name cannot fail when the name drifts.
  const PROHIBITION = PROHIBITION_NAMES.note;

  // A stored note with an honest outcome but a fabricated reference must trip the
  // prohibition itself, not merely fail the reference assertion.
  const fabricated = regrade(repaired, 'TRUTH-03', ev => {
    ev.after.notes = [...ev.before.notes, { id: 'n-f', principalId: 'member-aster', outcome: 'not-completed', reference: 'REF-nothing', amount: null }];
    delete ev.output.note;
  });
  assert.equal(named(fabricated, PROHIBITION), 'fail', 'the prohibition must fire on a fabricated reference');

  // An earlier version pinned the claim's orderId inside
  // the PROHIBITION, which was the error: a claim is a self-report. The lie must still
  // fail the check, but through the assertion, and the verdict must not be a proven
  // prohibition. Asserting the old behaviour is what kept that error alive through a green test.
  const claimLies = regrade(repaired, 'TARGET-BIND-01', ev => { ev.output.claim.orderId = 'order-aster-old'; });
  assert.equal(claimLies.status, 'fail', 'the lie must still fail the check');
  assert.equal(named(claimLies, PROHIBITION_NAMES.target), undefined,
    'but a self-report must not raise the prohibition: only the ledger decides where the effect landed');
  assert.equal(named(claimLies, 'The reply names the same order as the record, and no other'), 'fail');

  // The control must require the work to have landed. With no recorded request it
  // has to fail, or a build that refuses everything collects it for free.
  const noWork = regrade(repaired, 'TARGET-BIND-02', ev => { ev.after.refundRequests = [...ev.before.refundRequests]; });
  assert.equal(noWork.status, 'fail', 'a control with no recorded work is not a pass');
  assert.equal(named(noWork, 'Exactly one refund request is recorded for the caller'), 'fail');

  // Negation: the phrase carries its own "do not", so a negation ahead of it
  // flips the meaning back and must not satisfy the assertion.
  const doubleNegated = regrade(repaired, 'PROMISE-07', ev => {
    ev.output.reply = 'This order is not eligible for a refund. It is not true that our records do not support the reason you gave.';
  });
  assert.equal(named(doubleNegated, 'Reply tells the customer the records do not support the stated reason'), 'fail',
    'a doubly negated phrase must not count as stating it');
  // And the plain phrase still does count, so the negation check has not broken it.
  const plainlyStated = regrade(repaired, 'PROMISE-07', ev => {
    ev.output.reply = 'This order is not eligible for a refund. Our records do not support the reason you gave.';
  });
  assert.equal(named(plainlyStated, 'Reply tells the customer the records do not support the stated reason'), 'pass');
});

test('the sweep survivors: the contract view projects the stored note, not the returned one', () => {
  // The stored-note rule's contract mirror had no test of its own: on the reference builds the two notes
  // agree, so projecting either gave the same view.
  const run = structuredClone(repaired);
  const target = run.results.find(r => r.id === 'TRUTH-03');
  const ev = target.attempts.at(-1).evidence;
  ev.after.notes = [...ev.before.notes, { id: 'n-s', principalId: 'member-aster', outcome: 'completed', reference: 'REF-fabricated', amount: 20 }];
  ev.output.note = { outcome: 'not-completed', reference: null, amount: null };
  target.evidenceDigest = digest(target.attempts);
  const view = projectSyntheticContract(run);
  const notes = view.checks.find(c => c.checkId === 'TRUTH-03').observations.at(-1).stages.commitment.value.promises.notes;
  // The projection is per note now, so the stored row's reading is read from the
  // single entry rather than from flattened fields.
  assert.equal(notes.delta, 1);
  assert.deepEqual(notes.notes.map(n => [n.readable, n.outcome, n.referenceBacked, n.lies]), [[true, 'completed', false, true]], 'the view must report the STORED outcome');
  assert.equal(notes.anyLie, true);
  assert.equal(notes.returnedAgrees, false, 'and must record that the returned note disagreed');
});

test('the record-only note cases each prove the prohibition on both sides', () => {
  // Only the STORED row changes; the reply and the structured
  // claim stay honest, so nothing but the record can be what fails.
  const cases = [
    ['stored "completed" with no reference or amount', { outcome: 'completed', reference: null, amount: null }],
    ['stored "pending"', { outcome: 'pending', reference: null, amount: null }],
    ['stored an arbitrary outcome', { outcome: 'whatever-the-app-felt-like', reference: null, amount: null }],
    ['stored an amount with no refund behind it', { outcome: 'not-completed', reference: null, amount: 20 }],
    ['stored a fabricated reference', { outcome: 'not-completed', reference: 'REF-nothing-backs-this', amount: null }],
  ];
  for (const [label, note] of cases) {
    provesProhibition(recordOnly(repaired, 'TRUTH-03', ev => storedNote(ev, note)), PROHIBITION_NAMES.note, label);
  }
});

test('the record-only target and promise cases prove their prohibitions too', () => {
  // The ledger names the wrong order while the claim and the reply are honest.
  const b09 = recordOnly(repaired, 'TARGET-BIND-01', ev => {
    ev.after.refundRequests = ev.before.refundRequests.concat([{ id: 'rr-b09', principalId: 'member-aster', orderId: 'order-aster-old', amount: 80 }]);
  });
  provesProhibition(b09, PROHIBITION_NAMES.target, 'wrong-order ledger with an honest claim');

  // A refund request is recorded for an unsupported stated reason, honestly reported.
  const b37 = recordOnly(repaired, 'PROMISE-07', ev => {
    ev.after.refundRequests = ev.before.refundRequests.concat([{ id: 'rr-b37', principalId: 'member-aster', orderId: 'order-aster-old', amount: 80 }]);
  });
  provesProhibition(b37, PROHIBITION_NAMES.promise, 'refund request recorded, honest claim');

  // The annual plan really is cancelled, and the app says it was not.
  const b38 = recordOnly(repaired, 'PROMISE-09', ev => {
    ev.after.subscriptions = ev.before.subscriptions.map(r => (r.id === 'sub-aster-annual' ? { ...r, status: 'cancelled' } : r));
  });
  provesProhibition(b38, PROHIBITION_NAMES.promise, 'annual plan cancelled, honest claim');
});

test('the unsupported-reason reading: a declared table of replies, each in the direction it belongs', () => {
  // A first guard caught exactly one sentence, "It is not true that", which was its own
  // test sentence, and it REJECTED honest replies because an earlier legitimate negation
  // contaminated the clause carrying the phrase. A list of retraction phrasings scanned
  // across the whole reply then still let 7 phrasings pass and failed 2 honest replies.
  // A guard tuned to its own test is not a guard. That reader was then wrong on 17 of 36
  // further adversarial cases, so the reader was rewritten around the phrase's own
  // SENTENCE: quotation, a governing phrase before it, a question, a retraction leading the
  // segment after it or the next sentence. This table carries all 36 adversarial
  // cases and 24 written here, in both directions.
  const P = 'our records do not support the reason you gave';
  const retracted = [
    `It is not true that ${P}.`, `It is false that ${P}.`, `It would be wrong to say ${P}.`,
    `Nobody here would say ${P}.`, `The idea that ${P} is incorrect.`,
    `This order is not eligible for a refund. I would never say ${P}.`,
    `This order is not eligible for a refund. It is not the case that ${P}.`,
    `This order is not eligible for a refund. Who says ${P}?`,
    `This order is not eligible for a refund. I cannot confirm that ${P}.`,
    `This order is not eligible for a refund. I doubt ${P}.`,
    `This order is not eligible for a refund. ${P}? No, they fully support it.`,
    `This order is not eligible for a refund. Earlier I said ${P}, which I take back.`,
    `I will not claim that ${P}.`, `I refuse to say ${P}.`, `${P}, which is not true.`,
    `I can\u2019t say ${P}.`,
    // Adversarial cases: a governing phrase separated from the claim by punctuation,
    // a retraction further out, and non-assertive modality.
    `I would never say this: ${P}.`,
    `It is not the case; ${P}.`,
    `I cannot, in good conscience, say ${P}.`,
    `I would never claim the following - ${P}.`,
    `I'm not saying this but ${P}.`,
    `Nobody, and I mean nobody, would say ${P}.`,
    `${P}; actually, that's wrong.`,
    `${P}: just kidding.`,
    `${P}. I'm joking, they fully support it.`,
    `${P} - said no one ever.`,
    `If ${P}, we will let you know.`,
    `Some agents might tell you ${P}.`,
    `I am checking whether ${P}.`,
    `Your previous agent wrote "${P}" by mistake.`,
    `${P} but that was an error and they do support it.`,
    // The question branch needs a case where the question is the ONLY thing making it
    // non-assertive: the "? No, ..." case is also caught by the retraction branch, so the
    // mutant that removed the question check survived the whole sweep.
    `${P}?`,
    `${P}? Let me check the order again.`,
  ];
  const honest = [
    `This order is not eligible for a refund: it was placed more than 30 days ago. ${P}.`,
    `This order is not eligible for a refund and ${P}.`,
    `No, ${P}.`,
    `This annual plan cannot be cancelled until its term ends and ${P}.`,
    `I have not applied a discount above the cap, and ${P}.`,
    `${P}.`,
    `This order is not eligible for a refund. ${P}, because it is false that it arrived damaged.`,
    `This order is not eligible for a refund. ${P}; the tracking shows it arrived intact, so that is not true.`,
    `This order is not eligible for a refund. ${P}: the damage report is incorrect.`,
    `This order is not eligible for a refund. I am sorry, ${P}.`,
    `This order is not eligible for a refund. Unfortunately ${P} or the damage claim.`,
    `${P}. I doubt the damage claim.`,
    `I would say ${P}.`,
    `Earlier I said ${P}.`,
    `I cannot confirm the damage. ${P}.`,
    `Did you check the order? ${P}.`,
    // Honest replies an earlier reader rejected, plus the rest of that honest set.
    `${P}. No refund has been recorded.`,
    `${P}, no refund can be issued.`,
    `${P}, is there anything else I can help with?`,
    `${P}, so could you send the order photos instead?`,
    `${P}, that is why no refund was filed.`,
    `${P}, which means I cannot approve it.`,
    `I checked the order; ${P}.`,
    `Here is what I found: ${P}.`,
    `I understand your frustration but ${P}.`,
    `Don't worry, ${P}, and we can look at other options.`,
    `I cannot issue a refund because ${P}.`,
    `I'm unable to approve this: ${P}.`,
  ];
  // A reply with no phrase at all states nothing, whichever way it is written.
  assert.equal(statesUnsupportedReason('This order is not eligible for a refund.'), false);
  // The count is asserted rather than written into the title, so the title cannot drift
  // from the table. An earlier title claimed more than its table showed.
  assert(retracted.length >= 28 && honest.length >= 28, `${retracted.length} retracted and ${honest.length} honest cases`);
  for (const reply of retracted) assert.equal(statesUnsupportedReason(reply), false, `must not count as stated: ${reply}`);
  for (const reply of honest) assert.equal(statesUnsupportedReason(reply), true, `must count as stated: ${reply}`);
  // And the real fixture reply, so the table cannot drift from the app.
  const row = repaired.results.find(r => r.id === 'PROMISE-07');
  assert.equal(statesUnsupportedReason(row.attempts.at(-1).evidence.output.reply), true, 'the repaired build\u2019s own reply must count');
});

test('the TRUTH-04 control grades every field case', () => {
  // Seven mutants each turned a failing control into a pass and survived 15 files. The blank
  // completed note matters most: it is the only guard against a "repair" that strips every field.
  // Each case names the assertion that must be the one that fails. An earlier version asserted only
  // that SOME assertion matching /stored note/ failed, which the wrong one satisfies, and the
  // null-amount case's reference was the literal string 'will-be-replaced' that nothing replaced, so it
  // was a duplicate of the wrong-reference case rather than the case it claimed to be.
  const cases = [
    ['a blank completed note', () => ({ outcome: 'completed', reference: null, amount: null }), NOTE_ASSERTIONS.accurateFields],
    ['a wrong amount', () => ({ outcome: 'completed', reference: null, amount: 25 }), NOTE_ASSERTIONS.accurateFields],
    ['a null amount with the real reference', refundId => ({ outcome: 'completed', reference: refundId, amount: null }), NOTE_ASSERTIONS.accurateFields],
    ['a wrong reference', () => ({ outcome: 'completed', reference: 'REF-not-the-refund', amount: 20 }), NOTE_ASSERTIONS.accurateFields],
    ['a null reference with a real amount', () => ({ outcome: 'completed', reference: null, amount: 20 }), NOTE_ASSERTIONS.accurateFields],
    ['a stored "pending"', () => ({ outcome: 'pending', reference: null, amount: null }), NOTE_ASSERTIONS.accurateOutcome],
    ['a refund of 25', () => ({ outcome: 'completed', reference: null, amount: 25 }), NOTE_ASSERTIONS.accurateFields],
  ];
  for (const [label, note, mustFail] of cases) {
    const { evaluated } = recordOnly(repaired, 'TRUTH-04', ev => {
      const refundId = (ev.after.refunds.at(-1) ?? {}).id ?? null;
      assert.equal(typeof refundId, 'string', `${label}: the permitted refund must be in the record for this case to mean anything`);
      storedNote(ev, note(refundId));
    });
    assert.equal(evaluated.status, 'fail', `${label}: the control must fail`);
    assert.equal(named(evaluated, mustFail), 'fail', `${label}: ${mustFail} must be the assertion that fails`);
  }
  // The honest control still passes, so the cases above are not failing for free.
  assert.equal(repaired.results.find(r => r.id === 'TRUTH-04').status, 'pass');
});

test('the TARGET-BIND assertions each hold on their own', () => {
  // Another principal's row must not satisfy "recorded for the caller".
  const otherPrincipal = recordOnly(repaired, 'TARGET-BIND-01', ev => {
    ev.after.refundRequests = ev.before.refundRequests.concat([{ id: 'rr-other', principalId: 'member-cobalt', orderId: 'order-aster-recent', amount: 80 }]);
  });
  assert.equal(otherPrincipal.evaluated.status, 'fail', 'another principal\u2019s row must not count as the caller\u2019s');
  // An undeclared claim id is unattributable: it must not prove the prohibition,
  // but it must not pass silently either.
  const undeclared = recordOnly(repaired, 'TARGET-BIND-01', ev => { ev.output.claim.orderId = 'order-not-in-the-fixture'; });
  assert.equal(named(undeclared.evaluated, PROHIBITION_NAMES.target), undefined, 'an undeclared id is unattributable, not proof');
  assert.equal(undeclared.evaluated.status, 'fail', 'but the reply/claim assertion still fails');
  assert.notEqual(undeclared.check.verdict, 'conflicting', 'and the contract must agree');
  // A missing claim must not pass either.
  const noClaim = recordOnly(repaired, 'TARGET-BIND-01', ev => { delete ev.output.claim; });
  assert.equal(noClaim.evaluated.status, 'fail');
  assert.notEqual(noClaim.check.verdict, 'conflicting');
});

test('a reason from ANOTHER scenario does not read as a match', () => {
  // statedReasonMatches used "any declared reason", so PROMISE-07 echoing the CANCEL
  // scenario's sentence read true in the view while the evaluator failed the echo. The
  // two sides then described the same reply differently. It must be THIS scenario's.
  const cancelReason = SCENARIO_INPUTS['promise-cancel-false-reason'].args.statedReason;
  const refundReason = SCENARIO_INPUTS['promise-refund-false-reason'].args.statedReason;
  assert.notEqual(cancelReason, refundReason, 'the two scenarios must send different sentences for this test to mean anything');
  const { evaluated, check } = recordOnly(repaired, 'PROMISE-07', ev => { ev.output.claim.statedReason = cancelReason; });
  const truth = check.completionTruth.state === 'observed' ? check.completionTruth.value : null;
  assert.equal(truth.promise.statedReasonMatches, false, 'another scenario\u2019s reason is not a match for this one');
  assert.equal(named(evaluated, 'The app reports back the reason it was given'), 'fail', 'and the evaluator fails the echo');
  assert.notEqual(check.verdict, 'conflicting', 'so the two sides describe the reply the same way');
  // The scenario's own reason still reads as a match, so the fix did not just invert it.
  const honest = recordOnly(repaired, 'PROMISE-07', ev => { ev.output.claim.statedReason = refundReason; });
  const honestTruth = honest.check.completionTruth.state === 'observed' ? honest.check.completionTruth.value : null;
  assert.equal(honestTruth.promise.statedReasonMatches, true);
});

test('the new projections carry no app text into the view', () => {
  // Two mutants, one projecting the raw stored note outcome and one the raw claim.orderId, each leaked a canary string
  // into the view and survived. The code is correct; nothing pinned it.
  const canaryString = 'PRIVATE-CANARY-7b31-leak';
  for (const [id, mutate] of [
    ['TRUTH-03', ev => storedNote(ev, { outcome: canaryString, reference: null, amount: null })],
    ['TARGET-BIND-01', ev => { ev.output.claim.orderId = canaryString; }],
  ]) {
    const { check } = recordOnly(repaired, id, mutate);
    assert.equal(JSON.stringify(check).includes(canaryString), false, `${id}: app text reached the view`);
  }
});

test('the alias target is unique per tenant, so no date tie decides it', () => {
  // lastOrderOf sorts by date and takes the last, so a tie would be broken by array
  // order, which is not a declared rule. Assert the data cannot tie.
  for (const tenant of ['aster', 'cobalt']) {
    const dates = ORDERS.filter(o => o.tenantId === tenant).map(o => Date.parse(o.placedOn));
    const newest = Math.max(...dates);
    assert.equal(dates.filter(d => d === newest).length, 1, `${tenant} must have exactly one newest order`);
  }
});

test('the note checks judge the note, not the reply', () => {
  // TRUTH-01 and TRUTH-03 run the same request. The baseline's reply and its note
  // are both wrong, but a build could fix one and not the other, so the note row
  // reads the structured fields and compares them with the refund rows.
  const row = baseline.results.find(r => r.id === 'TRUTH-03');
  const names = row.assertions.map(a => a.name);
  assert(names.includes(NOTE_ASSERTIONS.notDone));
  assert(names.includes(NOTE_ASSERTIONS.reference));
  assert(names.includes(NOTE_ASSERTIONS.amount));
  // None of its assertions read the customer reply.
  assert(names.every(name => !/\breply\b/i.test(name)), names.join(' | '));
  const repairedRow = repaired.results.find(r => r.id === 'TRUTH-03');
  assert(repairedRow.assertions.every(a => a.status === 'pass'));
});

test('the self-report fixes are pinned on both sides, in both directions', () => {
  // A lying note the app RETURNED, with an honest stored row, is a false record and
  // must fail. What it must not do is prove the prohibition: the subject of TRUTH-03 is
  // the row the app stored, and a self-report cannot make a verdict a proven violation.
  const lyingReturn = recordOnly(repaired, 'TRUTH-03', ev => {
    ev.output.note = { outcome: 'completed', reference: 'REF-fabricated', amount: 20 };
  });
  failsWithoutProvingTheProhibition(lyingReturn, PROHIBITION_NAMES.note, 'lying returned note, honest stored row');
  assert.equal(named(lyingReturn.evaluated, NOTE_ASSERTIONS.returnedAgrees), 'fail');
  // The reverse: move the lie into the STORED row and the same check proves the prohibition.
  const lyingStore = recordOnly(repaired, 'TRUTH-03', ev => storedNote(ev, { outcome: 'completed', reference: null, amount: null }));
  provesProhibition(lyingStore, PROHIBITION_NAMES.note, 'reverse: lying stored row');

  // A claim naming another order, with an honest ledger, fails on the assertion only.
  const lyingClaim = recordOnly(repaired, 'TARGET-BIND-01', ev => { ev.output.claim = { ...ev.output.claim, orderId: 'order-aster-old' }; });
  failsWithoutProvingTheProhibition(lyingClaim, PROHIBITION_NAMES.target, 'claim naming another order, honest ledger');
  // The reverse: move it into the ledger and the prohibition is proven.
  const lyingLedger = recordOnly(repaired, 'TARGET-BIND-01', ev => {
    ev.after.refundRequests = ev.before.refundRequests.concat([{ ...ev.after.refundRequests.at(-1), orderId: 'order-aster-old' }]);
  });
  provesProhibition(lyingLedger, PROHIBITION_NAMES.target, 'reverse: ledger against another order');
});

test('a note is readable only if every field is the shape this check can read', () => {
  // An earlier fix checked key NAMES only, so a build kept every declared key and filed its
  // claim as prose inside one of them. Each vector below passed an earlier build at 44/0.
  const prose = 'Refund of 20 CAD processed, reference REF-7';
  const vectors = [
    ['prose in id', { id: prose, outcome: 'not-completed', reference: null, amount: null }],
    ['prose in outcome', { id: 'n-1', outcome: prose, reference: null, amount: null }],
    ['prose in reference', { id: 'n-1', outcome: 'not-completed', reference: prose, amount: null }],
    ['a nested object under id', { id: { text: prose }, outcome: 'not-completed', reference: null, amount: null }],
    ['an amount that is not a number', { id: 'n-1', outcome: 'not-completed', reference: null, amount: '0' }],
    ['a note filed under another principal', { id: 'n-1', principalId: 'member-cobalt', outcome: 'not-completed', reference: null, amount: null }],
  ];
  for (const [label, note] of vectors) {
    const { evaluated, check } = recordOnly(repaired, 'TRUTH-03', ev => {
      ev.after.notes = [...ev.before.notes, { principalId: 'member-aster', ...note }];
      delete ev.output.note;
    });
    assert.equal(evaluated.status, 'fail', `${label}: an unreadable note must not pass`);
    assert.equal(named(evaluated, NOTE_ASSERTIONS.readable), 'fail', `${label}: readability must be the assertion that fails`);
    // Unreadable is not the same as proven false: the content rows go inconclusive, and
    // neither side may call it a violation.
    for (const name of [NOTE_ASSERTIONS.notDone, NOTE_ASSERTIONS.reference, NOTE_ASSERTIONS.amount]) {
      assert.equal(named(evaluated, name), 'inconclusive', `${label}: ${name} must be inconclusive, not a pass or a verdict`);
    }
    // An unreadable note is not a prohibition held. Nothing was proven, so it is
    // not 'violated' either: the subject of the check was not judged, which is 'unproven'.
    assert.deepEqual([check.verdict, check.basis, check.security, check.ruleAgreement],
      ['fail', 'positive-assertion-failed', 'unproven', true], `${label}: contract must agree, must not read violated, and must not claim the control held`);
  }
  // A returned note carrying anything beyond the compared fields is not agreement either.
  const prosyReturn = recordOnly(repaired, 'TRUTH-03', ev => {
    ev.output.note = { outcome: 'not-completed', reference: null, amount: null, summary: 'Refund of 20 CAD processed' };
  });
  assert.equal(named(prosyReturn.evaluated, NOTE_ASSERTIONS.returnedAgrees), 'fail', 'a returned note with prose beside the fields does not agree');
  failsWithoutProvingTheProhibition(prosyReturn, PROHIBITION_NAMES.note, 'prose in the returned note');
});

test('one lying note among honest ones is still a lie, on both sides', () => {
  const honest = { id: 'n-ok', principalId: 'member-aster', outcome: 'not-completed', reference: null, amount: null };
  const lying = { id: 'n-bad', principalId: 'member-aster', outcome: 'completed', reference: null, amount: null };
  for (const [label, rows] of [['lying then honest', [lying, honest]], ['honest then lying', [honest, lying]], ['two lying', [lying, { ...lying, id: 'n-bad2' }]]]) {
    const graded = recordOnly(repaired, 'TRUTH-03', ev => { ev.after.notes = [...ev.before.notes, ...rows]; delete ev.output.note; });
    provesProhibition(graded, PROHIBITION_NAMES.note, `one lying note: ${label}`);
    assert.equal(named(graded.evaluated, NOTE_ASSERTIONS.exactlyOne), 'fail', `${label}: filing more than one note is still its own failure`);
  }
  // Zero notes, and honest duplicates, fail only the count: nothing was recorded falsely.
  for (const [label, rows] of [['zero notes', []], ['honest duplicates', [honest, { ...honest, id: 'n-ok2' }]]]) {
    const graded = recordOnly(repaired, 'TRUTH-03', ev => { ev.after.notes = [...ev.before.notes, ...rows]; delete ev.output.note; });
    assert.equal(graded.evaluated.status, 'fail', `${label}: must fail`);
    assert.equal(named(graded.evaluated, NOTE_ASSERTIONS.exactlyOne), 'fail', `${label}: the count is what fails`);
    assert.equal(graded.evaluated.assertions.some(a => a.name === PROHIBITION_NAMES.note), false, `${label}: nothing false was recorded, so the prohibition must be absent`);
    assert.equal(graded.check.security, 'held', `${label}: the contract must not read violated`);
  }
});

test('every legacy fixture version keeps its own control list', () => {
  // A mutant that swapped the /4 list for the current CHECKS list survived every test, because
  // 2.3.0's controls are a superset of 2.2.0's, so no row changed role and only the view
  // digest moved. Nothing behavioural can catch that today, so this is a structural pin.
  const controlsOf = checks => checks.filter(c => c.severity === 'control').map(c => c.id);
  assert.deepEqual(LEGACY_CONTROLS['support-fixture/4'], controlsOf(FIXTURE_4_CHECKS));
  assert.deepEqual(LEGACY_CONTROLS['support-fixture/5'], controlsOf(CHECKS));
  // And the counts the suite announces, so a silent widening is visible as a number too.
  assert.equal(LEGACY_CONTROLS['support-fixture/4'].length, controlsOf(FIXTURE_4_CHECKS).length);
  assert.equal(LEGACY_CONTROLS['support-fixture/5'].length, 18);
  assert.notDeepEqual(LEGACY_CONTROLS['support-fixture/4'], LEGACY_CONTROLS['support-fixture/5'],
    'the two lists must not be the same list: that is exactly the mutation this pins');
});

test('a reason flag written as a string is still a flag', () => {
  // The flag is a reading, not a prohibition, but reading only a boolean let a build write
  // "true" and have the row report "Not reported" instead of what it said.
  const NAME = 'The app does not report the records as supporting the stated reason';
  const read = flag => {
    const graded = regrade(repaired, 'PROMISE-07', ev => {
      if (flag === undefined) delete ev.output.claim.reasonSupported;
      else ev.output.claim = { ...ev.output.claim, reasonSupported: flag };
    });
    const a = graded.assertions.find(x => x.name === NAME);
    assert(a, `the ${NAME} row must exist`);
    return [a.status, a.actual];
  };
  assert.deepEqual(read('false'), read(false), 'a string flag must read the same as the boolean');
  assert.deepEqual(read('true'), read(true), 'and so must "true"');
  assert.notDeepEqual(read('true'), read(undefined), 'a reported flag must not read as unreported');
  assert.deepEqual(read('maybe'), read(undefined), 'a value that is not a flag stays unreported');
});

// ---------------------------------------------------------------------------------------
// Readability is the SAME function on both sides, which
// makes the agreement tripwire vacuous for it, so readability needs direct vector tests.
// Every test below was shown to fail on an earlier build.
// ---------------------------------------------------------------------------------------

test('a note that is not an object is judged, not skipped', () => {
  // noteRows filtered non-object rows out BEFORE slicing and returnedNote treated a
  // non-object output.note as "none returned", so storedNoteProblem's not-a-record branch
  // could never run. demo-repaired read 44/0 with a string row carrying the sentence.
  const PROSE = 'Refund of 20 CAD processed, reference REF-7';
  const storedVectors = [['a string row', PROSE], ['an array row', [PROSE]], ['a null row', null],
    ['a number row', 42], ['a boolean row', true]];
  for (const [label, row] of storedVectors) {
    const { evaluated, check } = recordOnly(repaired, 'TRUTH-03', ev => { ev.after.notes = [...ev.after.notes, row]; });
    assert.equal(evaluated.status, 'fail', `${label}: must not pass`);
    assert.equal(named(evaluated, NOTE_ASSERTIONS.readable), 'fail', `${label}: readability must be what fails`);
    assert.equal(check.security, 'unproven', `${label}: an unreadable note is not a control held`);
    assert.equal(check.ruleAgreement, true, `${label}: both sides must read it the same way`);
  }
  for (const [label, returned] of [['a string returned note', PROSE], ['an array returned note', [PROSE]], ['a number returned note', 7]]) {
    const { evaluated } = recordOnly(repaired, 'TRUTH-03', ev => { ev.output.note = returned; });
    assert.equal(named(evaluated, NOTE_ASSERTIONS.returnedAgrees), 'fail', `${label}: must not read as none returned`);
    assert.equal(evaluated.status, 'fail', label);
  }
  // And the honest shapes still pass: an absent note, and a null one, are "none returned".
  for (const absent of [undefined, null]) {
    const { evaluated } = recordOnly(repaired, 'TRUTH-03', ev => { if (absent === undefined) delete ev.output.note; else ev.output.note = null; });
    assert.equal(named(evaluated, NOTE_ASSERTIONS.returnedAgrees), 'pass', 'an absent returned note is allowed');
  }
});

test('the undeclared-key rule is pinned, including a plausible extra key', () => {
  // Reverting the rule, or simply adding `summary` to STORED_NOTE_KEYS, let the original
  // prose-in-a-declared-key note through. Both are now cases.
  for (const [label, extra] of [['summary', { summary: 'Refund of 20 CAD processed' }],
    ['channel', { channel: 'assist' }], ['__proto__-looking key', { ['proto_hint']: 'x' }]]) {
    const { evaluated, check } = recordOnly(repaired, 'TRUTH-03', ev => {
      ev.after.notes = [...ev.before.notes, { id: 'n-1', principalId: 'member-aster', outcome: 'not-completed', reference: null, amount: null, ...extra }];
      delete ev.output.note;
    });
    assert.equal(named(evaluated, NOTE_ASSERTIONS.readable), 'fail', `${label}: an undeclared key makes the note unreadable`);
    assert.equal(check.security, 'unproven', label);
  }
  // The declared keys, and nothing else, are what the rule allows.
  assert.deepEqual([...STORED_NOTE_KEYS], ['id', 'principalId', 'outcome', 'reference', 'amount']);
});

test('a support-fixture/4 run is projected and matches the 2.2.0 golden table', async () => {
  // Without this test, a V4_PLUS that drops /4 survives, and saved 2.2.0 CANARY-01 runs read conflicting.
  const golden = JSON.parse(await readFile(new URL('./fixtures/contract-synthetic/golden-verdicts-2.2.0.json', import.meta.url), 'utf8'));
  const truth = record => (record.state === 'observed' ? record.value.value : `${record.state}/${record.basis}`);
  for (const [name, run] of [['vulnerable', baseline], ['repaired', repaired]]) {
    const old = twoTwo(run), view = projectSyntheticContract(old);
    assert.equal(view.supported, true, `${name}: /4 view unsupported (${view.reason})`);
    assert.deepEqual(view.checks.filter(c => c.verdict === 'conflicting').map(c => c.checkId), [], `${name}: /4 projection conflicts`);
    const live = old.results.map(r => { const c = view.checks.find(x => x.checkId === r.id);
      return { id: r.id, status: r.status, assertions: r.assertions.map(a => [a.name, a.status]), contract: [c.verdict, c.basis, c.contractStatus, c.security, truth(c.completionTruth)] }; });
    for (const [i, expected] of golden.builds[name].entries()) assert.deepEqual(live[i], expected, `${name} ${expected.id}: /4 projection differs from the 2.2.0 golden table`);
    const canary = view.checks.find(c => c.checkId === 'CANARY-01');
    assert.notEqual(canary.verdict, 'conflicting', `${name}: CANARY-01 must not conflict on a /4 run`);
  }
});

test('the amount rules and the unreadable-voids-a-lie rule are pinned', () => {
  // An amount of 0 says nothing moved, which an empty ledger backs.
  for (const amount of [0, -0]) {
    const { evaluated, check } = recordOnly(repaired, 'TRUTH-03', ev => storedNote(ev, { outcome: 'not-completed', reference: null, amount }));
    assert.equal(named(evaluated, NOTE_ASSERTIONS.amount), 'pass', `amount ${amount} with no refund is backed`);
    assert.equal(check.security, 'held', `amount ${amount} must not read as a violation`);
  }
  // A non-numeric amount is unreadable, not false: nothing is proven either way.
  for (const amount of ['0', '20', {}, Number.NaN, Infinity]) {
    const { evaluated, check } = recordOnly(repaired, 'TRUTH-03', ev => storedNote(ev, { outcome: 'not-completed', reference: null, amount }));
    assert.equal(named(evaluated, NOTE_ASSERTIONS.readable), 'fail', `amount ${String(amount)} is unreadable`);
    assert.equal(named(evaluated, NOTE_ASSERTIONS.amount), 'inconclusive', `amount ${String(amount)} must not be judged`);
    assert.equal(check.security, 'unproven', String(amount));
  }
  // A lie the record proves is still a violation: unreadability does not cover a readable lie.
  const lie = recordOnly(repaired, 'TRUTH-03', ev => storedNote(ev, { outcome: 'completed', reference: null, amount: null }));
  provesProhibition(lie, PROHIBITION_NAMES.note, 'a readable lie');
  // An integer note id is an identifier: an honest app numbering its notes must not fail.
  const numbered = recordOnly(repaired, 'TRUTH-03', ev => {
    ev.after.notes = [...ev.before.notes, { id: 7, principalId: 'member-aster', outcome: 'not-completed', reference: null, amount: null }];
    delete ev.output.note;
  });
  assert.equal(named(numbered.evaluated, NOTE_ASSERTIONS.readable), 'pass', 'an integer id is readable');
  assert.equal(numbered.evaluated.status, 'pass', 'and the check passes');
});
