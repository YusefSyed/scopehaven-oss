// The Object.hasOwn coercion sweep, in the contract evaluator. Object.hasOwn and a template coerce their key,
// so an attempt actor that is an array or an object naming a declared actor passed src/contract-synthetic.mjs's principal check while
// the scenario's === alias test never matched it, and HTTP versions given as arrays selected a known reader in src/contract-http.mjs.
// Each now requires a string first, so such a value reads as an undeclared string does.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runAssessment } from '../src/runner.mjs';
import { contractView } from '../src/contract-views.mjs';
import { CONTRACT_EVALUATOR_HASH } from '../src/contract-synthetic.mjs';
import sealedHttp from './fixtures/pre-hasown-sweep-run-96f15d25.mjs';
import { httpVersionOf } from '../src/contract-http.mjs';
import { digest } from '../src/suite.mjs';

const named = value => ({ toString: () => value });
const tally = view => view.checks.flatMap(check => check.observations).reduce((t, o) => ({ ...t, [o.evidenceState]: (t[o.evidenceState] ?? 0) + 1 }), {});

test('a synthetic attempt actor is a declared actor only as a string: an array or toString actor reads as an undeclared one', async () => {
  const run = await runAssessment('demo-vulnerable');
  const withActor = map => {
    const shaped = structuredClone(run);
    for (const row of shaped.results) { for (const attempt of row.attempts) attempt.actor = map(attempt.actor); row.evidenceDigest = digest(row.attempts); }
    return shaped;
  };
  const observations = view => view.checks.flatMap(check => check.observations.map(o => [o.evidenceState, o.dimensions?.actor?.basis ?? null]));
  // Control: the actors the runner writes are observed.
  assert.deepEqual(Object.keys(tally(contractView(run))), ['observed']);
  const undeclared = contractView(withActor(() => 'mallory'));
  assert.deepEqual(Object.keys(tally(undeclared)), ['conflicting']);
  for (const map of [actor => [actor], actor => named(actor)]) {
    const view = contractView(withActor(map));
    // The earlier build read every such observation as observed, with the declared actor's principal. (The check bases can still differ from the
    // undeclared actor's: the synthetic evaluator, outside this identity, recomputes ["alice"] as it recomputes "alice".)
    assert.deepEqual(tally(view), tally(undeclared));
    assert.deepEqual(observations(view), observations(undeclared));
    assert.ok(view.checks.every(c => c.verdict === 'conflicting'));
  }
});

test('HTTP versions select a contract reader only as strings: arrays read as an unknown version', () => {
  const known = { adapterVersion: 'loopback-response-contract/1', assertionSchemaVersion: 'http-contract/2' };
  assert.equal(httpVersionOf(known).reader, 'response-metadata/1');
  assert.equal(httpVersionOf({ ...known, adapterVersion: 'not-a-version' }), null);
  for (const value of [{ ...known, adapterVersion: [known.adapterVersion] }, { ...known, assertionSchemaVersion: [known.assertionSchemaVersion] },
    { ...known, adapterVersion: named(known.adapterVersion) }]) assert.equal(httpVersionOf(value), null, JSON.stringify(value));
});

test('a stored v1 HTTP run whose versions are not strings is projected as an unknown version, not graded', async () => {
  const { runs } = JSON.parse(await readFile(new URL('./fixtures/contract-http-v1/runs.json', import.meta.url), 'utf8'));
  for (const run of Object.values(runs)) {
    // Control: the stored strings project; a wrong string reads as an unknown version.
    assert.equal(contractView(run).supported, true, run.id);
    const unknown = contractView({ ...run, adapterVersion: 'not-a-version' });
    assert.equal(unknown.reason, 'http-version');
    // The earlier build graded the array form (every row conflicting) and refused the toString form as an invalid view.
    for (const shaped of [{ ...run, adapterVersion: [run.adapterVersion], assertionSchemaVersion: [run.assertionSchemaVersion] }, { ...run, adapterVersion: named(run.adapterVersion) }])
      assert.deepEqual(contractView(shaped), unknown, run.id);
  }
});

// The sealed runs these tests carry (the synthetic run, the three HTTP runs, the stored v1 HTTP runs), projected by the earlier build's
// own projector (test/fixtures/pre-hasown-contract-views-bdc48589.json): each view here equals that projection but for the two fields
// naming the contract evaluator, which moved.
test('runs sealed before the sweep project here exactly as the earlier build projected them, apart from the contract evaluator\'s own hash', async () => {
  const recorded = JSON.parse(await readFile(new URL('./fixtures/pre-hasown-contract-views-bdc48589.json', import.meta.url), 'utf8'));
  const synthetic = JSON.parse(await readFile(new URL('./fixtures/pre-hasown-sweep-synthetic-0de64259.json', import.meta.url), 'utf8')).run;
  const { runs: v1 } = JSON.parse(await readFile(new URL('./fixtures/contract-http-v1/runs.json', import.meta.url), 'utf8'));
  const runs = { synthetic, ...Object.fromEntries(['webhook', 'catalog', 'appLog'].map(k => [`http-${k}`, sealedHttp[k].run])), ...Object.fromEntries(Object.entries(v1).map(([k, r]) => [`v1-${k}`, r])) };
  assert.deepEqual(Object.keys(runs), Object.keys(recorded.views));
  // gradedWith names the Node that projected the view, outside its viewDigest (src/evidence-contract.mjs): the earlier build projected under 24.21.0.
  const stripped = view => { const { viewDigest: _d, ...rest } = structuredClone(view); if (rest.pins?.grader) delete rest.pins.grader.contractEvaluatorHash; if (rest.gradedWith) rest.gradedWith = { node: '24.21.0' }; return rest; };
  for (const [name, run] of Object.entries(runs)) {
    const view = contractView(run), main = recorded.views[name];
    if (view.gradedWith) assert.deepEqual(view.gradedWith, { node: process.versions.node }, name);
    assert.equal(view.supported, main.supported, name);
    assert.equal(digest(stripped(view)), main.strippedDigest, name);
    if (view.supported) assert.equal(view.pins.grader.contractEvaluatorHash, CONTRACT_EVALUATOR_HASH, name);
  }
  // Last, so that on the earlier build everything above runs and passes: the contract evaluator moved.
  assert.notEqual(CONTRACT_EVALUATOR_HASH, recorded.contractEvaluatorHash);
});
