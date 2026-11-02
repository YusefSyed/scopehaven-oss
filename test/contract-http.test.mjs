import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HTTP_ADAPTER_VERSION } from '../src/http-connector.mjs';
import { ASSERTION_SCHEMA_VERSION } from '../src/contracts.mjs';
import { runAssessment } from '../src/runner.mjs';
import { createStore } from '../src/store.mjs';
import { SUITE, digest } from '../src/suite.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { INPUT_CONTRACT, importPromptfooJson } from '../integrations/evaluation-import/import.mjs';
import { validateView } from '../src/evidence-contract.mjs';
import { HTTP_VERSION_TABLE, HTTP_V1_PAIR, HTTP_V2_PAIR, HTTP_CONNECTOR_V2_PENDING, recomputeHttpRow } from '../src/contract-http.mjs';
import { contractView, compareContracts, gateContracts } from '../src/contract-views.mjs';

// Frozen v1 runs (test/fixtures/contract-http-v1/runs.json), generated once from the v1
// connector with in-process stub transports. No socket or network is
// used, and a later connector version cannot change these inputs.
const FIXTURE = JSON.parse(await readFile(new URL('./fixtures/contract-http-v1/runs.json', import.meta.url), 'utf8'));
const frozen = name => structuredClone(FIXTURE.runs[name]);
const rowOf = (run, id) => run.results.find(r => r.id === id);
const checkOf = (view, id) => view.checks.find(c => c.checkId === id);
const verdictOf = (run, id) => { const view = contractView(run); assert.equal(view.supported, true, JSON.stringify(view)); const c = checkOf(view, id); return [c.verdict, c.basis, c.contractStatus]; };
const recount = run => { run.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const r of run.results) run.counts[r.status]++; return run; };
const reseal = row => { row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions }); };
const UNOBSERVABLE = ['approval', 'authorization', 'access', 'commitment', 'disclosure', 'completionTruth'];

test('the frozen inputs are v1 runs that carry no credential or response text', () => {
  assert.equal(FIXTURE.pair, HTTP_V1_PAIR);
  const serialized = JSON.stringify(FIXTURE);
  for (const privateText of ['synthetic-token', 'RESPONSE_TEXT_NOT_STORED', 'Access denied.']) assert.equal(serialized.includes(privateText), false, privateText);
  for (const run of Object.values(FIXTURE.runs)) {
    assert.equal(`${run.adapterVersion}|${run.assertionSchemaVersion}`, HTTP_V1_PAIR);
    // Unmodified rows recompute to their stored status with no problem.
    for (const row of run.results) { const facts = recomputeHttpRow(row); assert.deepEqual(facts.problems, [], row.id); assert.equal(facts.recomputedStatus, row.status, row.id); }
  }
});

test('response-only runs project without inferring backend stages', () => {
  const run = frozen('one'), before = JSON.stringify(run), view = contractView(run);
  assert.equal(view.supported, true); assert.equal(validateView(view), true); assert.equal(view.adapter, 'http-response/1');
  const expected = {
    WHOAMI: ['pass', null, 'pass'], 'OWN-RECORD': ['fail', 'response-contract-failed', 'fail'], 'FOREIGN-STATUS': ['pass', null, 'pass'],
    ANONYMOUS: ['observer-failure', 'transport-network', 'error'], 'BACKEND-UNVERIFIED': ['unobservable', 'backend-evidence-required-response-only', 'inconclusive'],
    ECHO: ['missing', 'response-not-json', 'inconclusive'], 'NOT-APPLICABLE': ['not-exercised', 'declared-not-applicable', 'not_applicable'],
  };
  for (const [id, verdict] of Object.entries(expected)) { const c = checkOf(view, id); assert.deepEqual([c.verdict, c.basis, c.contractStatus], verdict, id); }
  for (const c of view.checks) {
    const stored = rowOf(run, c.checkId), o = c.observations[0];
    assert.equal(c.contractStatus, stored.status, c.checkId); assert.equal(c.storedAgrees, true); assert.equal(o.lineage.observer, 'workbench-http-transport');
    assert.equal(o.lineage.independence, 'response-only-connector'); assert.equal(o.lineage.source, `/results/${run.results.indexOf(stored)}/trace/0`);
    if (stored.status === 'not_applicable') { for (const stage of Object.values(o.stages).slice(0, 8)) assert.equal(stage.state, 'not-exercised'); continue; }
    for (const stage of UNOBSERVABLE) assert.deepEqual(o.stages[stage], { state: 'unobservable', basis: 'response-only' }, `${c.checkId} ${stage}`);
    assert.deepEqual(o.stages.proposal, { state: 'not-exercised', basis: 'scripted-request' });
    assert.equal(o.dimensions.actor.value.principalId, null); assert.equal(o.dimensions.resource.value.requestPathHash, stored.trace[0].data.requestPathHash);
  }
  assert.deepEqual(checkOf(view, 'WHOAMI').observations[0].stages.dispatch.value, { requestAttempted: true, transportOutcome: 'complete', httpStatus: 200 });
  assert.deepEqual(view.counts, run.counts); assert.equal(view.countsAgree, true);
  assert.deepEqual(view.pins.reset, { mode: 'none-declared', verified: false, violations: [] });
  assert.deepEqual([view.pins.grader.ruleVersion, view.pins.grader.recomputeBasis, view.pins.grader.sameEvaluator], ['http-stage-rules/2', 'retained-evidence-recompute', 'not-checked']);
  assert.equal(JSON.stringify(run), before);
});

test('timeouts, oversized responses and an expired run budget are observer failures, never passes', () => {
  const failures = contractView(frozen('failures'));
  assert.deepEqual([checkOf(failures, 'WHOAMI').verdict, checkOf(failures, 'WHOAMI').basis, checkOf(failures, 'WHOAMI').contractStatus], ['observer-failure', 'transport-timeout', 'error']);
  assert.deepEqual([checkOf(failures, 'OWN-RECORD').verdict, checkOf(failures, 'OWN-RECORD').basis, checkOf(failures, 'OWN-RECORD').contractStatus], ['observer-failure', 'transport-too-large', 'error']);
  assert.equal(checkOf(failures, 'OWN-RECORD').observations[0].lineage.actorTransport, 'incomplete');
  const budget = contractView(frozen('budget'));
  for (const c of budget.checks.filter(c => c.checkId !== 'NOT-APPLICABLE')) assert.deepEqual([c.verdict, c.basis, c.contractStatus], ['observer-failure', 'run-budget-expired', 'error'], c.checkId);
});

test('stored assertion labels are recomputed from the retained evidence, never trusted', () => {
  // A status label flipped against the stored httpStatus, with the digest resealed.
  const label = frozen('one'), own = rowOf(label, 'OWN-RECORD');
  own.assertions[0] = { ...own.assertions[0], status: 'pass' }; reseal(own);
  assert.deepEqual(verdictOf(label, 'OWN-RECORD'), ['conflicting', 'stored-assertion-disagrees', 'fail']);
  // Every label and the row status flipped to pass: still never a pass or a restoration.
  const forged = frozen('one'), row = rowOf(forged, 'OWN-RECORD');
  row.assertions = row.assertions.map(a => ({ ...a, status: 'pass' })); row.status = 'pass'; reseal(row); recount(forged);
  assert.deepEqual(verdictOf(forged, 'OWN-RECORD'), ['conflicting', 'stored-assertion-disagrees', 'fail']);
  const compared = compareContracts(frozen('one'), forged), transition = compared.rows.find(r => r.id === 'OWN-RECORD');
  // The shared HTTP evidence validator (the gate's) rejects the resealed forgery, so even the plain v1 comparison is incompatible.
  assert.equal(transition.v1Transition, 'incompatible');
  assert.notEqual(transition.recomputedTransition, 'contract-restored'); assert.notEqual(transition.refinedTransition, 'contract-restored');
  assert.equal(compared.recomputed.summary.fixed, 0); assert.equal(compared.agreement, false);
  const gated = gateContracts({ candidate: forged }, { summarizeGate });
  assert(gated.contractReasons.includes('stored-assertion-disagrees')); assert(gated.contractReasons.includes('run-evidence-invalid'));
  // Run level: the forged row keeps its own basis; every other row is conflicting with run-evidence-invalid; nothing passes.
  const forgedView = contractView(forged);
  for (const c of forgedView.checks) {
    assert.equal(c.verdict, 'conflicting', c.checkId); assert.notEqual(c.contractStatus, 'pass', c.checkId);
    assert.equal(c.basis, c.checkId === 'OWN-RECORD' ? 'stored-assertion-disagrees' : 'run-evidence-invalid', c.checkId);
  }
  assert.equal(gateContracts({ candidate: frozen('one') }, { summarizeGate }).contractReasons.includes('run-evidence-invalid'), false, 'An untouched run is not flagged.');
  // Every row already conflicting with its own basis: the run-level reason is still reported.
  const allBroken = frozen('one'); for (const r of allBroken.results) r.evidenceDigest = '0'.repeat(64);
  const allView = contractView(allBroken);
  assert(allView.checks.every(c => c.verdict === 'conflicting' && c.basis !== 'run-evidence-invalid'), JSON.stringify(allView.checks.map(c => c.basis)));
  assert(gateContracts({ candidate: allBroken }, { summarizeGate }).contractReasons.includes('run-evidence-invalid'));
  // Only the row status changed: the stored-status guard (fix 8).
  const status = frozen('one'); rowOf(status, 'OWN-RECORD').status = 'pass'; recount(status);
  assert.deepEqual(verdictOf(status, 'OWN-RECORD'), ['conflicting', 'stored-status-disagrees', 'fail']);
});

test('missing evidence never passes', () => {
  const backend = frozen('one'), b = rowOf(backend, 'BACKEND-UNVERIFIED');
  b.assertions = b.assertions.map(a => ({ ...a, status: 'pass' })); b.status = 'pass'; reseal(b); recount(backend);
  assert.deepEqual(verdictOf(backend, 'BACKEND-UNVERIFIED'), ['conflicting', 'stored-assertion-disagrees', 'inconclusive']);
  const unattempted = frozen('one'), u = rowOf(unattempted, 'WHOAMI');
  Object.assign(u.trace[0].data, { requestAttempted: false, httpStatus: null }); u.observed.httpStatus = null; reseal(u);
  assert.deepEqual(verdictOf(unattempted, 'WHOAMI').slice(0, 2), ['conflicting', 'transport-facts-inconsistent']);
  assert(gateContracts({ candidate: unattempted }, { summarizeGate }).contractReasons.includes('run-evidence-invalid'), 'The shared validator also rejects the resealed transport edit.');
  const noStatus = frozen('one'), n = rowOf(noStatus, 'WHOAMI');
  n.trace[0].data.httpStatus = null; n.observed.httpStatus = null; n.assertions[0] = { ...n.assertions[0], status: 'inconclusive', actual: 'HTTP status unavailable' };
  n.status = 'inconclusive'; reseal(n); recount(noStatus);
  assert.deepEqual(verdictOf(noStatus, 'WHOAMI').slice(0, 2), ['conflicting', 'transport-facts-inconsistent']);
  const empty = frozen('one'), e = rowOf(empty, 'FOREIGN-STATUS');
  e.assertions = []; reseal(e);
  assert.deepEqual(verdictOf(empty, 'FOREIGN-STATUS'), ['conflicting', 'assertion-set-invalid', 'inconclusive']);
  for (const run of [backend, unattempted, noStatus, empty]) for (const c of contractView(run).checks) if (c.verdict === 'conflicting') assert.notEqual(c.contractStatus, 'pass');
  // A deleted or duplicated row is never silent.
  const deleted = frozen('one'); deleted.results = deleted.results.filter(r => r.id !== 'OWN-RECORD'); recount(deleted);
  assert.deepEqual(contractView(deleted), { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'local-http-response', reason: 'invalid-family', detail: 'check-set' });
  const duplicated = frozen('one'); duplicated.results.push(structuredClone(duplicated.results[0])); duplicated.checksTotal++; recount(duplicated);
  assert.equal(contractView(duplicated).reason, 'invalid-family');
  // An unparsed body is observed evidence for a status-only check.
  const statusOnly = frozen('one'), s = rowOf(statusOnly, 'FOREIGN-STATUS');
  Object.assign(s.trace[0].data, { transportOutcome: 'invalid-json', jsonParsed: false }); s.observed.jsonParsed = false; reseal(s);
  const c = checkOf(contractView(statusOnly), 'FOREIGN-STATUS');
  assert.deepEqual([c.verdict, c.observations[0].evidenceState], ['pass', 'observed']);
});

test('altered evidence is conflicting, comparisons refine scope rows and stay family-bound', async t => {
  const altered = frozen('one'); rowOf(altered, 'WHOAMI').trace[0].data.httpStatus = 201;
  const whoami = checkOf(contractView(altered), 'WHOAMI');
  assert.deepEqual([whoami.verdict, whoami.basis, whoami.observations[0].evidenceState], ['conflicting', 'evidence-digest-mismatch', 'conflicting']);
  const compared = compareContracts(frozen('one'), frozen('two'));
  assert.equal(compared.supported, true); assert.equal(compared.v1.compatible, true); assert.equal(compared.agreement, true);
  assert.equal(compared.rows.find(r => r.id === 'NOT-APPLICABLE').refinedTransition, 'not-exercised->not-exercised');
  assert.equal(compared.rows.find(r => r.id === 'BACKEND-UNVERIFIED').refinedTransition, 'unobservable->unobservable');
  const synthetic = await runAssessment('demo-repaired');
  for (const pair of [[synthetic, frozen('one')], [frozen('one'), synthetic]]) {
    const mixed = compareContracts(...pair);
    assert.equal(mixed.supported, true); assert.equal(mixed.v1.compatible, false); assert.equal(mixed.recomputed.compatible, false);
  }
  const directory = await mkdtemp(join(tmpdir(), 'scopehaven-contract-http-test-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const store = createStore(directory), run = frozen('one'); await store.save(run);
  assert.equal(contractView(await store.get(run.id)).viewDigest, contractView(run).viewDigest);
});

test('v2 stays pending, unknown pairs are unsupported and the v1 reader refuses downgrades', () => {
  assert(Object.hasOwn(HTTP_VERSION_TABLE, `${HTTP_ADAPTER_VERSION}|${ASSERTION_SCHEMA_VERSION}`), 'the current connector pair needs a version-table entry');
  assert.equal(HTTP_VERSION_TABLE[HTTP_V2_PAIR], HTTP_CONNECTOR_V2_PENDING);
  const relabel = ([adapterVersion, assertionSchemaVersion]) => contractView({ ...frozen('one'), adapterVersion, assertionSchemaVersion });
  assert.deepEqual(relabel(HTTP_V2_PAIR.split('|')), { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'local-http-response', reason: 'http-version-pending' });
  for (const pair of [['loopback-response-contract/2', 'http-contract/2'], ['loopback-response-contract/1', 'http-contract/9'], ['__proto__', 'x']])
    assert.deepEqual(relabel(pair), { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'local-http-response', reason: 'http-version' });
  const downgrade = { contractVersion: 'scopehaven-observation/1', supported: false, origin: 'local-http-response', reason: 'http-version-downgrade' };
  assert.deepEqual(contractView({ ...frozen('one'), identityEvidence: { schemaVersion: 'actor-identity/2', actors: [] } }), downgrade);
  for (const key of ['credentialMode', 'requestTimeoutMs']) {
    const run = frozen('one'); run.results[0].trace[0].data[key] = key === 'credentialMode' ? 'bearer' : 3000;
    assert.deepEqual(contractView(run), downgrade, key);
  }
});

test('imported results stay attributed; other families and non-runs are explicitly unsupported', async t => {
  const source = await readFile(new URL('../integrations/evaluation-import/fixtures/promptfoo-0.123.1-v3.synthetic.json', import.meta.url), 'utf8');
  const preview = importPromptfooJson(source, INPUT_CONTRACT);
  assert.equal(preview.ok, true);
  for (const input of [preview, preview.record, { ...preview.record, schemaVersion: 1, results: [] }]) {
    const view = contractView(input);
    assert.equal(view.supported, false); assert.equal(view.reason, 'external-attributed');
    for (const key of ['checks', 'counts', 'verdictCounts', 'status']) assert.equal(Object.hasOwn(view, key), false);
  }
  const native = await runAssessment('demo-repaired');
  for (const pair of [[preview.record, native], [native, preview.record]]) assert.equal(compareContracts(...pair).supported, false);
  assert.equal(gateContracts({ candidate: preview.record, expectedSuite: SUITE }, { summarizeGate }).supported, false);
  assert.equal(gateContracts({ candidate: native, baseline: preview.record, expectedSuite: SUITE }, { summarizeGate }).supported, false);
  for (const evidenceOrigin of ['reviewed-real-application-staging', 'unknown'])
    assert.deepEqual(contractView({ schemaVersion: 1, results: [], evidenceOrigin }), { contractVersion: 'scopehaven-observation/1', supported: false, origin: evidenceOrigin, reason: 'adapter-not-migrated' });
  for (const input of [null, undefined, 'run', [], { schemaVersion: 2 }, { schemaVersion: 1 }]) assert.equal(contractView(input).reason, 'not-native-run');
  const directory = await mkdtemp(join(tmpdir(), 'scopehaven-contract-import-test-')); t.after(() => rm(directory, { recursive: true, force: true }));
  await assert.rejects(createStore(directory).save(preview.record), error => error.status === 400);
});
