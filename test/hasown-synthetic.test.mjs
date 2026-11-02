// The Object.hasOwn coercion sweep, on the synthetic side. Object.hasOwn coerces its key, so a fixture
// version that is an array or an object naming a known family read as that family in src/runner.mjs syntheticFamily, and an
// in-process run sharing that one value with every attempt manifest passed the manifests' === checks too. An earlier change required
// a string there and a later one reverted it; this change restores it. src/contract-synthetic.mjs:74 (unknownIdentity) and :679
// (LEGACY_CONTROLS) are reached only through projectSyntheticInternal's compareRuns(run, run), so the restored check guards them as
// well; the restoration moves neither the synthetic nor the contract evaluator. (contract-synthetic.mjs:311, attempt.actor, is another
// coercion, fixed by the contract evaluator's re-pin, which does move the contract evaluator.) A run recorded by the earlier build's
// own runner, before the restoration, still validates, compares, projects and renders as that build did.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runAssessment, compareRuns, EVALUATOR_HASH } from '../src/runner.mjs';
import { contractView } from '../src/contract-views.mjs';
import { CONTRACT_EVALUATOR_HASH } from '../src/contract-synthetic.mjs';
import { renderReport } from '../src/report.mjs';
import { validateRun } from '../integrations/regression-gate/gate.mjs';
import { digest } from '../src/suite.mjs';

const recorded = JSON.parse(await readFile(new URL('./fixtures/pre-hasown-sweep-synthetic-0de64259.json', import.meta.url), 'utf8'));
const FAMILY = 'Evidence origin does not match its producer family or observations.';

test('a fixture version that is not a string, shared with every attempt manifest and resealed, is no synthetic family: not comparable, not projected', async () => {
  const run = await runAssessment('demo-vulnerable');
  // Control: the string the runner writes compares with itself and projects.
  assert.equal(compareRuns(run, run).compatible, true);
  assert.equal(contractView(run).supported, true);
  for (const value of [[run.fixtureVersion], { toString: () => run.fixtureVersion }]) {
    const shaped = structuredClone(run);
    shaped.fixtureVersion = value;
    for (const row of shaped.results) { for (const attempt of row.attempts) attempt.manifest.fixtureVersion = value; row.evidenceDigest = digest(row.attempts); }
    const comparison = compareRuns(shaped, shaped);
    assert.equal(comparison.compatible, false, String(value));
    assert.ok(comparison.reasons.includes(FAMILY), JSON.stringify(comparison.reasons));
    // The earlier build graded the array form under other rules than the string's (not the /4+ reset pins: 23 fail, 18 pass, 3 conflicting).
    assert.deepEqual(contractView(shaped), { contractVersion: contractView(run).contractVersion, supported: false, origin: 'synthetic-local-http', reason: 'invalid-family' });
  }
  // The shape a stored file can hold: every row inconclusive with no attempt, so no manifest === runs at all. The earlier build compared this run
  // with itself and projected it (44 conflicting, the array in its view identity); the string control still does both.
  const stored = version => {
    const shaped = JSON.parse(JSON.stringify(run)); shaped.fixtureVersion = version;
    for (const row of shaped.results) { row.attempts = []; row.status = 'inconclusive'; row.evidenceDigest = digest(row.attempts); }
    return JSON.parse(JSON.stringify(shaped));
  };
  const control = stored(run.fixtureVersion);
  assert.equal(compareRuns(control, control).compatible, true);
  assert.equal(contractView(control).supported, true);
  const array = stored([run.fixtureVersion]);
  assert.equal(compareRuns(array, array).compatible, false);
  assert.equal(contractView(array).reason, 'invalid-family');
});

test('a synthetic run recorded and sealed before the sweep validates, compares, projects and renders at the head as it did then', async () => {
  const { recordedAt, run } = recorded;
  assert.equal(recordedAt, '0de64259');
  assert.equal(run.evaluatorHash, recorded.evaluatorHash);
  assert.equal(EVALUATOR_HASH, recorded.evaluatorHash, 'the synthetic evaluator does not move');
  assert.doesNotThrow(() => validateRun(run));
  assert.equal(compareRuns(run, run).compatible, true);
  const comparison = compareRuns(run, await runAssessment('demo-repaired'));
  assert.equal(comparison.compatible, true);
  assert.deepEqual(comparison.summary, recorded.comparedWithRepaired);
  const view = contractView(run);
  // The contract re-pin moved the contract evaluator (08166764 -> 51c7d84e), so this view's hash and the viewDigest over it are no
  // longer the recorded ones; test/hasown-contract.test.mjs compares the rest of this run's view with the recorded projection.
  assert.notEqual(CONTRACT_EVALUATOR_HASH, recorded.contractEvaluatorHash);
  assert.equal(view.pins.grader.contractEvaluatorHash, CONTRACT_EVALUATOR_HASH);
  assert.deepEqual(view.verdictCounts, recorded.verdictCounts);
  assert.equal(digest(renderReport(run)), recorded.reportDigest);
});
