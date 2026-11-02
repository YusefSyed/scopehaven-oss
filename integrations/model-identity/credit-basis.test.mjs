// Credit basis: what a repair credited to the application rests on, computed here from the check and the
// observations read from the application's records (in a hosted pilot, 17 of 55 same-model original-to-fixed
// credits rested on elimination, the model never attempting).
import test from 'node:test';
import assert from 'node:assert/strict';
import { attributeWithCreditBasis, CREDIT_BASES, CREDIT_BASIS_SCHEMA } from './credit-basis.mjs';
import { attributeComparison } from './attribute.mjs';
import { classifyLocus } from './locus.mjs';
import { attemptScript, scriptSha256, fixedRepliesSha256 } from './stand-in.mjs';
import { digest } from '../../src/domain.mjs';

const FIXED = 'f'.repeat(64), OTHER = 'e'.repeat(64), W = 'a'.repeat(64);
let sessions = 0;
const identity = () => ({ state: 'observed', strength: 'weights-digest', tapSession: `s${++sessions}`, upstream: 'http://127.0.0.1:11434', window: { from: 0, to: null },
  calls: { total: 2, succeeded: 2, failed: 0, abandoned: 0 }, models: [{ served: 'gemma4:latest', weightsDigest: W, fingerprints: [], strength: 'weights-digest' }] });
const unobserved = () => ({ state: 'not-observed', models: [], calls: { total: 0, succeeded: 0, failed: 0, abandoned: 0 } });
const action = id => ({ tool: 'update_seat', arguments: { confirmation_number: `ZK-${id}`, new_seat: '1A' } });
const check = id => ({ id, action: action(id) });
const refusal = kind => ({ refusal: { kind, reason: `refused (${kind})` } });
const model = (runId, outcome, build = FIXED, extra = {}) => ({ runId, appBuild: build, actor: { kind: 'model', identity: extra.identity ?? identity() }, outcome, recordsComplete: extra.recordsComplete ?? true,
  evidence: { outcome: 'app-state' }, ...(extra.refusal ? { refusal: extra.refusal } : {}) });
const standIn = (runId, id, outcome, build = FIXED, extra = {}) => {
  const script = attemptScript(action(id));
  return { runId, appBuild: build, actor: { kind: 'always-attempt-stand-in', script, scriptSha256: scriptSha256(script), delivered: extra.delivered ?? true, fixedRepliesSha256: fixedRepliesSha256({}), fixedReplies: [] },
    outcome, recordsComplete: true, evidence: { outcome: 'app-state', delivery: 'stand-in-log' }, ...(outcome === 'refused' ? { refusal: (extra.refusal ?? refusal('permission').refusal) } : {}) };
};
const twin = (runId, id, outcome, build = FIXED) => ({ runId, appBuild: build, actor: { kind: 'permitted-twin', role: 'owner', action: action(id) }, outcome, recordsComplete: true, evidence: { outcome: 'app-state' } });
const comparison = rows => ({ compatible: true, controlsPass: true, reasons: [], restorationLabel: 'Response contracts restored',
  rows: rows.map(([id, before, after, transition]) => ({ id, title: id, before, after, transition })) });
const repaired = comparison([['A', 'fail', 'pass', 'contract-restored'], ['B', 'fail', 'pass', 'contract-restored'], ['C', 'pass', 'pass', 'preserved']]);
const appChanged = { changed: true, evidence: 'build-hash', basis: 'differs:targetBuildHash' };
const credit = (locus, cmp = repaired, candidateBuild = FIXED) => attributeWithCreditBasis(cmp, { baselineIdentity: identity(), candidateIdentity: identity(), app: appChanged, locus, candidateBuild });
const basisA = observations => credit([{ check: check('A'), observations }]).rows.find(r => r.id === 'A').creditBasis;

test('each repair credited to the application says what the credit rests on, and cites its runs', () => {
  const cases = [
    ['enforced-by-app', [standIn('s', 'A', 'refused')]],
    ['app-refusal-recorded', [model('m', 'refused', FIXED, refusal('permission'))]],
    ['refusal-not-shown', [model('m', 'refused', FIXED, refusal('validation'))]],
    ['attempt-unrecorded', [standIn('s', 'A', 'none')]],
    ['by-elimination', [model('m', 'none')]],
    ['contradicted', [model('m1', 'none'), model('m2', 'committed')]],
    ['not-bound', [standIn('s', 'A', 'refused', OTHER)]],
    ['not-assessed', [model('m', 'unknown', FIXED, { recordsComplete: false })]],
  ];
  for (const [basis, observations] of cases) {
    const r = credit([{ check: check('A'), observations }]);
    const a = r.rows.find(x => x.id === 'A');
    assert.equal(a.creditBasis, basis, basis);
    // The basis cites the declared action and each run the reading weighed (bound readings only).
    if (basis !== 'not-bound') assert.deepEqual([a.creditEvidence.action.tool, a.creditEvidence.action.argumentsSha256, a.creditEvidence.runs.map(x => x.runId)], ['update_seat', digest(action('A').arguments), observations.map(o => o.runId)], basis);
    // The evidence cites each recorded refusal's kind.
    if (basis !== 'not-bound' && observations.some(o => o.refusal)) assert.deepEqual(a.creditEvidence.runs.filter(x => x.refusalKind).map(x => x.refusalKind), observations.filter(o => o.refusal).map(o => o.refusal.kind), basis);
    // The elimination caveat is said exactly when a credit rests on elimination.
    assert.equal(r.caveats.some(c => /rests on elimination/.test(c)), basis === 'by-elimination', basis);
    assert.equal(r.rows.find(x => x.id === 'B').creditBasis, 'not-assessed'); assert.equal(Object.hasOwn(r.rows.find(x => x.id === 'C'), 'creditBasis'), false);
    assert.deepEqual(Object.keys(r.creditBasis.counts), CREDIT_BASES); assert.equal(r.creditBasis.schema, CREDIT_BASIS_SCHEMA);
  }
  assert.equal(credit([{ check: check('A'), observations: [standIn('s', 'A', 'refused')] }], repaired, null).rows[0].creditBasis, 'not-bound');
});

// Mutants that once survived, one behaviour each. Readings are computed here, so the locus's own rules decide
// enforced-by-app.
test('survivors: enforced-by-app needs what the locus needs', () => {
  // A validation refusal blocks it, even beside a permission refusal.
  assert.equal(basisA([standIn('s1', 'A', 'refused'), standIn('s2', 'A', 'refused', FIXED, refusal('validation'))]), 'refusal-not-shown');
  // A set-aside run never shows it (the stand-in's attempt never arrived).
  assert.notEqual(basisA([standIn('s', 'A', 'refused', FIXED, { delivered: false })]), 'enforced-by-app');
  // The recorded-reason route needs an enforcing kind.
  assert.equal(basisA([standIn('s', 'A', 'refused', FIXED, refusal('other'))]), 'app-refusal-recorded');
  // A permitted twin that did not commit never lets a stand-in's reason stand in for it.
  assert.equal(basisA([standIn('s', 'A', 'refused'), twin('t', 'A', 'refused')]), 'app-refusal-recorded');
  assert.equal(basisA([standIn('s', 'A', 'refused', FIXED, refusal('other')), twin('t', 'A', 'committed')]), 'enforced-by-app');
  // Elimination only from observed model runs.
  assert.equal(basisA([model('m', 'none', FIXED, { identity: unobserved() })]), 'not-assessed');
  // A recorded refusal only from a usable run.
  assert.equal(basisA([model('m', 'refused', FIXED, { recordsComplete: false, ...refusal('permission') })]), 'not-assessed');
});

test('a validation refusal never raises the basis, and an unrecorded attempt is never hidden', () => {
  // The model's own malformed call, refused for its arguments, does not lift by-elimination to a recorded refusal.
  assert.equal(basisA([model('m1', 'none'), model('m2', 'refused', FIXED, refusal('validation'))]), 'refusal-not-shown');
  // A delivered attempt the app kept no record of outranks any refusal, and its caveat is said.
  const r = credit([{ check: check('A'), observations: [standIn('s', 'A', 'none'), model('m', 'refused', FIXED, refusal('validation'))] }]);
  assert.equal(r.rows[0].creditBasis, 'attempt-unrecorded'); assert.ok(r.caveats.some(c => /kept no record of it/.test(c)));
  assert.ok(credit([{ check: check('A'), observations: [model('m', 'refused', FIXED, refusal('validation'))] }]).caveats.some(c => /for the call's arguments \(validation\)/.test(c)));
});

test('a recorded commit withdraws the credit wherever it is; other builds are named, not counted', () => {
  const contradicted = credit([{ check: check('A'), observations: [standIn('s', 'A', 'committed')] }]);
  assert.equal(contradicted.repairCreditedToApp, false); assert.match(contradicted.restorationLabel, /^Not attributable to the application: an enforcement-locus reading recorded the action committing/);
  // A withdrawal withdraws every credit, so each credited repair row is marked and counted.
  assert.deepEqual(contradicted.rows.map(r => r.creditWithdrawn ?? false), [true, true, false]); assert.equal(contradicted.summary.creditWithdrawn, 2);
  // A commit in a run the locus set aside is still a commit.
  assert.equal(basisA([model('m', 'committed', FIXED, { recordsComplete: false })]), 'contradicted');
  // A commit on a row the comparison does not credit (preserved, or unverified) still withdraws every credit.
  for (const cmp of [repaired, comparison([['A', 'fail', 'pass', 'contract-restored'], ['C', 'inconclusive', 'pass', 'unverified']])]) {
    const outside = credit([{ check: check('A'), observations: [standIn('s', 'A', 'refused')] }, { check: check('C'), observations: [model('m', 'committed')] }], cmp);
    assert.deepEqual(outside.creditBasis.commitsOutsideCredit, ['C']); assert.equal(outside.repairCreditedToApp, false);
    assert.ok(outside.caveats.some(c => /for C \((pass)\), which the comparison does not show failing and does not credit as a repair/.test(c)));
  }
  // A commit on another build is named in a caveat; the candidate build's basis stands.
  const elsewhere = credit([{ check: check('A'), observations: [standIn('s', 'A', 'committed', OTHER)] }, { check: check('A'), observations: [standIn('s2', 'A', 'refused')] }]);
  assert.equal(elsewhere.rows[0].creditBasis, 'enforced-by-app'); assert.deepEqual(elsewhere.creditBasis.commitsOnOtherBuilds, ['A']);
  assert.equal(elsewhere.repairCreditedToApp, true); assert.ok(elsewhere.caveats.some(c => /for another build recorded the action committing for A/.test(c)));
});

test('only inputs are accepted: a computed reading, an unmatched check, a mixed build or a duplicate is refused', () => {
  const ready = classifyLocus(check('A'), [model('m', 'none')]);
  for (const bad of ['x', [ready], [{ ...ready, locus: 'enforced-by-app' }], [{ check: check('A'), observations: [model('m', 'none')], schema: ready.schema }], [{ check: check('A') }], [null]])
    assert.throws(() => credit(bad), /locus must be a list of \{ check, observations \}/, JSON.stringify(bad).slice(0, 60));
  assert.throws(() => credit([{ check: check('Z'), observations: [model('m', 'committed')] }]), /names no row/);
  assert.throws(() => credit([{ check: check('A'), observations: [model('m1', 'none'), model('m2', 'committed', OTHER)] }]), /spans application builds/);
  assert.throws(() => credit([{ check: check('A'), observations: [model('m', 'none')] }, { check: check('A'), observations: [model('n', 'none')] }]), /one build/);
  // An observation the locus cannot validate is refused by the locus itself.
  assert.throws(() => credit([{ check: check('A'), observations: [{ runId: 'x' }] }]));
});

test('the attribution itself is unchanged: no credit basis without this module', () => {
  const plain = attributeComparison(repaired, { baselineIdentity: identity(), candidateIdentity: identity(), app: appChanged });
  assert.equal(Object.hasOwn(plain, 'creditBasis'), false); assert.ok(plain.rows.every(r => !Object.hasOwn(r, 'creditBasis')));
  // A model swap credits nothing to the application, so no row gets a basis.
  const swapped = attributeWithCreditBasis(repaired, { baselineIdentity: identity(), candidateIdentity: { ...identity(), models: [{ served: 'qwen3.5:9b', weightsDigest: OTHER, fingerprints: [], strength: 'weights-digest' }] },
    app: appChanged, locus: [{ check: check('A'), observations: [standIn('s', 'A', 'refused')] }], candidateBuild: FIXED });
  assert.ok(swapped.rows.every(r => !Object.hasOwn(r, 'creditBasis'))); assert.equal(swapped.creditBasis.counts['enforced-by-app'], 0);
});

test('a commit on a check the candidate still fails agrees with the comparison and withdraws nothing', () => {
  for (const transition of [['fail', 'fail', 'still-failing'], ['pass', 'fail', 'regression']]) {
    const cmp = comparison([['A', 'fail', 'pass', 'contract-restored'], ['S', ...transition]]);
    const r = credit([{ check: check('A'), observations: [standIn('s', 'A', 'refused')] }, { check: check('S'), observations: [model('m', 'committed')] }], cmp);
    assert.equal(r.repairCreditedToApp, true, transition[2]); assert.equal(r.restorationLabel, 'Response contracts restored');
    assert.deepEqual([r.creditBasis.commitsOnFailingRows, r.creditBasis.commitsOutsideCredit], [['S'], []]);
    assert.ok(r.caveats.some(c => /for S, which the candidate also fails; this agrees with the comparison/.test(c)));
    assert.equal(r.summary.creditWithdrawn, 0);
  }
});

test('a commit on another build never withdraws; with no candidate hash it cannot be ruled out', () => {
  // Another build's commit on a row the comparison does not credit is not a commit outside the credit.
  const other = credit([{ check: check('A'), observations: [standIn('s', 'A', 'refused')] }, { check: check('C'), observations: [model('m', 'committed', OTHER)] }]);
  assert.deepEqual([other.repairCreditedToApp, other.creditBasis.commitsOutsideCredit, other.creditBasis.commitsOnOtherBuilds], [true, [], ['C']]);
  assert.ok(other.caveats.some(c => /for another build recorded the action committing for C; it is not evidence about the candidate build/.test(c)));
  // With no build hash on the candidate run, the same commit cannot be bound to it or ruled out.
  const unbound = credit([{ check: check('C'), observations: [model('m', 'committed')] }], repaired, null);
  assert.ok(unbound.caveats.some(c => /candidate run carries no build hash, so it cannot be bound to the candidate build or ruled out/.test(c)));
  assert.ok(!unbound.caveats.some(c => /not evidence about the candidate build/.test(c)));
});

test('a model-only refusal and every unrecorded stand-in attempt are named', () => {
  // Refusals recorded only for a model's own attempts, of any non-validation kind.
  for (const kind of ['permission', 'other', 'unavailable']) {
    const r = credit([{ check: check('A'), observations: [model('m', 'refused', FIXED, refusal(kind))] }]);
    assert.equal(r.rows[0].creditBasis, 'app-refusal-recorded'); assert.ok(r.caveats.some(c => /only recorded refusals are of a model's own attempts/.test(c)), kind);
  }
  // A stand-in's refusal beside the model's is not model-only.
  assert.ok(!credit([{ check: check('A'), observations: [standIn('s', 'A', 'refused', FIXED, refusal('other')), model('m', 'refused', FIXED, refusal('permission'))] }]).caveats.some(c => /model's own attempts/.test(c)));
  // An unrecorded attempt beside an enforced-by-app reading from another stand-in run is still named.
  const r = credit([{ check: check('A'), observations: [standIn('s1', 'A', 'refused'), standIn('s2', 'A', 'none')] }]);
  assert.equal(r.rows[0].creditBasis, 'enforced-by-app'); assert.ok(r.caveats.some(c => /For A, the always-attempt stand-in's attempt reached the application on the candidate build in at least one run/.test(c)));
});

test('a withdrawal keeps an existing not-attributable reason and marks every credited row', () => {
  // A model swap already reads not attributable; a commit on a passing row adds a caveat, not a new label.
  const swapped = attributeWithCreditBasis(repaired, { baselineIdentity: identity(), candidateIdentity: { ...identity(), models: [{ served: 'qwen3.5:9b', weightsDigest: OTHER, fingerprints: [], strength: 'weights-digest' }] },
    app: appChanged, locus: [{ check: check('C'), observations: [model('m', 'committed')] }], candidateBuild: FIXED });
  assert.match(swapped.restorationLabel, /^Not attributable to the application: the model changed/); assert.deepEqual(swapped.creditBasis.commitsOutsideCredit, ['C']);
  // A withdrawal from a commit outside the credit marks the credited rows and counts them.
  const outside = credit([{ check: check('A'), observations: [standIn('s', 'A', 'refused')] }, { check: check('C'), observations: [model('m', 'committed')] }]);
  assert.deepEqual([outside.rows[0].creditWithdrawn, outside.rows[1].creditWithdrawn, outside.summary.creditWithdrawn], [true, true, 2]);
});

// Two cases on the withholding side.
test('a label that makes no repair claim keeps its own reason when a commit withdraws the credit', () => {
  const committedOnC = [{ check: check('C'), observations: [model('m', 'committed')] }];
  const controlsFailed = { ...comparison([['A', 'fail', 'pass', 'blocked-by-controls'], ['C', 'pass', 'pass', 'preserved']]), controlsPass: false, restorationLabel: 'Unverified changes' };
  const noRepair = { ...comparison([['C', 'pass', 'pass', 'preserved'], ['D', 'fail', 'fail', 'still-failing']]), restorationLabel: 'No verified repair' };
  for (const [cmp, label] of [[controlsFailed, 'Unverified changes'], [noRepair, 'No verified repair']]) {
    const r = credit(committedOnC, cmp);
    assert.deepEqual([r.restorationLabel, r.repairCreditedToApp, r.creditBasis.commitsOutsideCredit], [label, false, ['C']], label);
  }
  // A label that stood for a credited repair is still replaced.
  assert.match(credit([{ check: check('A'), observations: [standIn('s', 'A', 'refused')] }, ...committedOnC]).restorationLabel, /^Not attributable to the application: an enforcement-locus reading recorded the action committing/);
});

test('the withdrawal caveat names each row\'s candidate verdict and never calls it passing', () => {
  const cmp = comparison([['A', 'fail', 'pass', 'contract-restored'], ['Q', 'pass', 'inconclusive', 'unverified'], ['N', 'pass', 'not_applicable', 'not-applicable']]);
  const r = credit([{ check: check('A'), observations: [standIn('s', 'A', 'refused')] }, { check: check('Q'), observations: [model('m', 'committed')] }, { check: check('N'), observations: [model('n', 'committed')] }], cmp);
  assert.deepEqual(r.creditBasis.commitsOutsideCredit, ['Q', 'N']); assert.equal(r.repairCreditedToApp, false);
  const caveat = r.caveats.find(c => /does not show failing/.test(c));
  assert.match(caveat, /for Q \(inconclusive\), N \(not_applicable\), which the comparison does not show failing and does not credit as a repair/);
  assert.ok(!r.caveats.some(c => /shows passing/.test(c)));
});
