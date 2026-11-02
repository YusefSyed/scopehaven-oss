// The verified retest over framework records: compareRuns on two framework-mode runs (run-record.mjs).
// node:test, no Python and no network. The LangGraph reset-after-commit acceptance records (the real template, re-judged):
// the defect, its fix (the template's fixed-update variant, the same scripted persona) and a vacuous fix that must not read
// FIXED_VERIFIED. The Mastra acceptance records hold no application-side fix (only other personas), so the billing shape's
// fix is run end to end on the fake adapter's refund app through the CLI's own checks: the same blind-retry persona on the
// buggy, idempotent and refusing variants. Then each refusal rule.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { frameworkModeRun, frameworkModeComparisonReasons } from './run-record.mjs';
import { runFrameworkAssessment } from './assess.mjs';
import { fakeCheckout } from './fixtures/fake-checkout.mjs';
import { compareRuns, retestVerdict, frameworkModeMissing, RETEST_VERDICTS, REPAIR_LABELS, NO_VERIFIED_REPAIR } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const scenarioOf = name => JSON.parse(readFileSync(join(HERE, 'scenarios', `${name}.json`), 'utf8'));
const acceptance = (family, name) => {
  const dir = join(HERE, 'acceptance', family), file = readdirSync(dir).find(f => f.startsWith(`${name}.`) && /^\d+\.record\.json$/.test(f.slice(name.length + 1)));
  return JSON.parse(readFileSync(join(dir, file), 'utf8'));
};
let n = 0;
const run = (record, scenario) => frameworkModeRun(record, scenario, { id: `vr1-${++n}`, createdAt: `2026-10-24T00:00:${String(n).padStart(2, '0')}.000Z` });
const LANGGRAPH = 'langgraph-cs.reset-after-commit', MASTRA = 'mastra-billing.reset-after-commit';
const lg = name => run(acceptance('langgraph-cs', `${LANGGRAPH}.${name}`), scenarioOf(LANGGRAPH));
const ma = name => run(acceptance('mastra-billing', `${MASTRA}.${name}`), scenarioOf(MASTRA));
const row = (comparison, id) => comparison.rows.find(r => r.id === id);
// A consistent edit: the record changed, the run rebuilt from it, so it validates as its own record.
const rebuilt = (record, scenario, edit) => { const copy = structuredClone(record); edit(copy); return run(copy, scenario); };
const PERSONA = 'The scripted model persona differs between the runs: a change in the model\'s scripted behaviour is not a repair of the application.';

test('LangGraph: the reset-after-commit defect and its fix read FIXED_VERIFIED; a fix that refuses everything does not', () => {
  const defect = lg('checks-then-reports'), fixedRecord = acceptance('langgraph-cs', `${LANGGRAPH}.checks-then-reports.fixed-update`), fixed = run(fixedRecord, scenarioOf(LANGGRAPH));
  const comparison = compareRuns(defect, fixed);
  assert.deepEqual(comparison.reasons, []); assert.equal(comparison.compatible, true); assert.equal(comparison.controlsPass, true);
  assert.equal(row(comparison, 'COLLATERAL-01').transition, 'local-control-restored');
  assert.deepEqual(comparison.summary, { fixed: 1, stillFailing: 0, newFailures: 0, preservedPasses: 5, unverified: 0 });
  assert.equal(comparison.restorationLabel, 'Local controls restored');
  assert.equal(retestVerdict(comparison), 'FIXED_VERIFIED');
  // The vacuous fix, same persona: the update tool still runs and returns, but nothing persists (the AFTER snapshot is the BEFORE).
  const refuses = rebuilt(fixedRecord, scenarioOf(LANGGRAPH), record => { record.snapshots.after = { ...record.snapshots.after, state: record.snapshots.before.state }; });
  assert.equal(refuses.results.find(r => r.id === 'COLLATERAL-GOAL').status, 'fail');
  const vacuous = compareRuns(defect, refuses);
  assert.equal(vacuous.compatible, true); assert.equal(vacuous.controlsPass, false);
  assert.equal(row(vacuous, 'COLLATERAL-01').transition, 'blocked-by-controls', 'nothing collateral persisted, but that is not credited');
  assert.equal(row(vacuous, 'COLLATERAL-GOAL').transition, 'regression', 'the allowed use is observed failing');
  assert.equal(vacuous.restorationLabel, 'Unverified changes');
  assert.equal(retestVerdict(vacuous), 'NO_VERIFIED_REPAIR');
  // Another scripted persona is another model behaviour, never a repair: the doing-nothing and misreporting runs are not comparable.
  for (const persona of ['do-nothing.fixed-update', 'reports-failed.fixed-update', 'claims-done.fixed-update']) {
    const swap = compareRuns(defect, lg(persona));
    assert.ok(swap.reasons.includes(PERSONA), persona); assert.equal(retestVerdict(swap), 'INCONCLUSIVE', persona);
  }
});

test('Mastra: the acceptance records only swap the scripted persona, which is not a repair', () => {
  const defect = ma('blind-retry');
  for (const persona of ['checks-then-reports', 'do-nothing']) {
    const swap = compareRuns(defect, ma(persona));
    assert.equal(swap.compatible, false); assert.ok(swap.reasons.includes(PERSONA), persona);
    assert.ok(swap.reasons.includes('profileHash differs or is missing.'), 'the persona is in the stable identity too');
    assert.equal(swap.summary.fixed, 0); assert.equal(retestVerdict(swap), 'INCONCLUSIVE');
  }
  assert.equal(retestVerdict(compareRuns(defect, ma('blind-retry'))), 'NO_VERIFIED_REPAIR', 'the same run twice repairs nothing');
});

test('the billing shape end to end: the same blind-retry persona on the buggy, idempotent and refusing builds', async t => {
  const fake = fakeCheckout(); t.after(() => rmSync(fake.root, { recursive: true, force: true }));
  const assess = adapterArgs => runFrameworkAssessment({ scenario: fake.scenario, stub: 'blind-retry', runtime: fake.runtime, template: fake.template, out: fake.out, adapterArgs });
  const store = createStore(fake.out);
  const defect = await store.get((await assess([])).id), fixed = await store.get((await assess(['--variant', 'idempotent-refund'])).id), refusing = await store.get((await assess(['--variant', 'refuse-refund'])).id);
  assert.equal(defect.results.find(r => r.id === 'COLLATERAL-01').status, 'fail', 'a blind retry refunds twice');
  assert.equal(fixed.counts.pass, fixed.checksTotal, 'the idempotent build refunds once');
  const comparison = compareRuns(defect, fixed);
  assert.deepEqual(comparison.reasons, []); assert.notEqual(defect.targetBuildHash, fixed.targetBuildHash);
  assert.equal(retestVerdict(comparison), 'FIXED_VERIFIED');
  // Refusing every refund: the fault cannot fire on a body that raised, nothing persists, and the allowed-use control fails.
  assert.equal(refusing.results.find(r => r.id === 'COLLATERAL-GOAL').status, 'fail');
  const vacuous = compareRuns(defect, refusing);
  assert.equal(row(vacuous, 'COLLATERAL-GOAL').transition, 'regression');
  assert.equal(retestVerdict(vacuous), 'NO_VERIFIED_REPAIR');
});

test('a removed tool is not a repair: the pair is not comparable', () => {
  const scenario = scenarioOf(LANGGRAPH), fixedRecord = acceptance('langgraph-cs', `${LANGGRAPH}.checks-then-reports.fixed-update`);
  const defect = lg('checks-then-reports');
  const fewer = rebuilt(fixedRecord, scenario, record => { record.ready.tools = record.ready.tools.filter(tool => tool !== 'cancel_ticket'); });
  const comparison = compareRuns(defect, fewer);
  assert.equal(comparison.compatible, false);
  assert.ok(comparison.reasons.includes('The candidate agent no longer has 1 tool the baseline agent had (cancel_ticket): removing a tool is not a repair.'));
  assert.equal(retestVerdict(comparison), 'INCONCLUSIVE'); assert.equal(comparison.summary.fixed, 0);
  const noFaultTool = rebuilt(fixedRecord, scenario, record => { record.ready.tools = record.ready.tools.filter(tool => tool !== scenario.fault.tool); });
  assert.ok(compareRuns(defect, noFaultTool).reasons.includes('The candidate agent does not have the tool the planned fault targets, so the fault cannot test it.'));
  // An added tool is not refused.
  const more = rebuilt(fixedRecord, scenario, record => { record.ready.tools = [...record.ready.tools, 'check_ticket_status']; });
  assert.deepEqual(frameworkModeComparisonReasons(defect, more), []);
  const unreadable = 'A framework run does not record its agent\'s tools, so a removed tool cannot be ruled out.';
  assert.ok(frameworkModeComparisonReasons(defect, { scenarioEvidence: { record: { stub: defect.scenarioEvidence.record.stub, ready: {} } } }).includes(unreadable));
  assert.ok(frameworkModeComparisonReasons(defect, { scenarioEvidence: { record: { stub: defect.scenarioEvidence.record.stub, ready: { tools: [...fixedRecord.ready.tools, 7] } } } }).includes(unreadable), 'a tool that is not a name');
});

test('a changed request, scenario, commit or measuring side is another test: the pair is not comparable', () => {
  const scenario = scenarioOf(LANGGRAPH), fixedRecord = acceptance('langgraph-cs', `${LANGGRAPH}.checks-then-reports.fixed-update`);
  const defect = lg('checks-then-reports');
  // The request changed: another turn text gives another scenario digest (and the record no longer matches it).
  const asked = structuredClone(scenario); asked.turns = [...asked.turns.slice(0, -1), `${asked.turns.at(-1)} Please.`];
  const changed = compareRuns(defect, run(structuredClone(fixedRecord), asked));
  assert.equal(changed.compatible, false); assert.ok(changed.reasons.includes('suiteHash differs or is missing.'));
  assert.equal(retestVerdict(changed), 'INCONCLUSIVE');
  // Another template commit is another suite until the suite identity can flag a migration between runs.
  const moved = structuredClone(scenario); moved.template.commit = 'a'.repeat(40);
  const commit = rebuilt(fixedRecord, moved, record => { record.adapter.checkout.commit = moved.template.commit; record.scenarioDigest = null; });
  assert.ok(compareRuns(defect, commit).reasons.includes('suiteHash differs or is missing.'));
  // The measuring side: ScopeHaven's adapter file, the framework name, or the harness code digest.
  for (const edit of [record => { record.adapter.sha256 = 'f'.repeat(64); }, record => { record.ready.framework = 'langgraph-fork'; }, record => { record.adapter.measuring = 'e'.repeat(64); }])
    assert.ok(compareRuns(defect, rebuilt(fixedRecord, scenario, edit)).reasons.includes('adapterVersion differs or is missing.'));
  // A framework package version is part of the build, like the template variant: it may change in a fix.
  assert.deepEqual(compareRuns(defect, rebuilt(fixedRecord, scenario, record => { record.ready.template.versions = { ...record.ready.template.versions, langgraph: '9.9.9' }; })).reasons, []);
  // Other seed data is another fixture.
  const seeded = structuredClone(scenario); seeded.workdir.seed[0].sha256 = '0'.repeat(64);
  assert.ok(compareRuns(defect, run(structuredClone(fixedRecord), seeded)).reasons.includes('fixtureHash differs or is missing.'));
  // A framework run and an HTTP run are never compared.
  const http = { ...structuredClone(defect), evidenceOrigin: 'local-http-response' };
  assert.equal(retestVerdict(compareRuns(http, lg('checks-then-reports.fixed-update'))), 'INCONCLUSIVE');
});

test('partial evidence never verifies: an unusable candidate run or an unfired fault reads INCONCLUSIVE', () => {
  const scenario = scenarioOf(LANGGRAPH), fixedRecord = acceptance('langgraph-cs', `${LANGGRAPH}.checks-then-reports.fixed-update`);
  const defect = lg('checks-then-reports');
  const noAfter = rebuilt(fixedRecord, scenario, record => { record.snapshots.after = null; });
  assert.equal(noAfter.results.find(r => r.id === 'FW-EXEC').status, 'inconclusive');
  const comparison = compareRuns(defect, noAfter);
  assert.equal(comparison.summary.fixed, 0); assert.equal(comparison.summary.newFailures, 0); assert.ok(comparison.summary.unverified > 0);
  assert.equal(retestVerdict(comparison), 'INCONCLUSIVE', 'missing evidence is not a failed repair');
  // The ledger shows the planned tool never called: the fault did not fire, so the run tests nothing about it.
  const unfired = rebuilt(fixedRecord, scenario, record => { record.ledger.records = record.ledger.records.filter(r => r.tool !== scenario.fault.tool); });
  assert.equal(unfired.results.find(r => r.id === 'FW-FAULT').status, 'inconclusive');
  const unfiredComparison = compareRuns(defect, unfired);
  assert.equal(row(unfiredComparison, 'FW-FAULT').transition, 'unverified');
  assert.equal(retestVerdict(unfiredComparison), 'INCONCLUSIVE');
});

test('an edited stored run is refused before it is compared: a status turned pass is never a repair', () => {
  const defect = lg('checks-then-reports'), fixed = lg('checks-then-reports.fixed-update');
  const forged = structuredClone(defect); forged.results.find(r => r.id === 'COLLATERAL-01').status = 'pass';
  const asCandidate = structuredClone(defect); asCandidate.id = 'vr1-forged'; asCandidate.results.find(r => r.id === 'COLLATERAL-01').status = 'pass'; asCandidate.counts = { pass: 6, fail: 0, inconclusive: 0, error: 0 };
  const comparison = compareRuns(defect, asCandidate);
  assert.equal(comparison.compatible, false); assert.ok(comparison.reasons.includes('Evidence origin does not match its producer family or observations.'));
  assert.equal(retestVerdict(comparison), 'INCONCLUSIVE');
  assert.equal(compareRuns(forged, fixed).compatible, false);
});

test('retestVerdict reads only the comparison: three words, and FIXED_VERIFIED only on a repair label from the allowlist', () => {
  assert.deepEqual(RETEST_VERDICTS, ['FIXED_VERIFIED', 'NO_VERIFIED_REPAIR', 'INCONCLUSIVE']);
  const base = { compatible: true, controlsPass: true, restorationLabel: 'Local controls restored', summary: { fixed: 1, stillFailing: 0, newFailures: 0, preservedPasses: 1, unverified: 0 } };
  assert.equal(retestVerdict(base), 'FIXED_VERIFIED');
  for (const label of REPAIR_LABELS) assert.equal(retestVerdict({ ...base, restorationLabel: label }), 'FIXED_VERIFIED', label);
  assert.equal(retestVerdict({ ...base, compatible: false }), 'INCONCLUSIVE');
  assert.equal(retestVerdict({ ...base, controlsPass: false }), 'NO_VERIFIED_REPAIR');
  assert.equal(retestVerdict({ ...base, summary: { ...base.summary, unverified: 1 } }), 'INCONCLUSIVE');
  assert.equal(retestVerdict({ ...base, controlsPass: false, summary: { ...base.summary, unverified: 1, newFailures: 1 } }), 'NO_VERIFIED_REPAIR', 'an observed regression outweighs partial evidence');
  assert.equal(retestVerdict({ ...base, controlsPass: false, summary: { ...base.summary, unverified: 1 } }), 'INCONCLUSIVE', 'a control that is only undecided is partial evidence');
  assert.equal(retestVerdict({ ...base, summary: { ...base.summary, notApplicable: 1 } }), 'INCONCLUSIVE');
  assert.equal(retestVerdict({ ...base, summary: { ...base.summary, newFailures: 1 } }), 'NO_VERIFIED_REPAIR');
  assert.equal(retestVerdict({ ...base, summary: { ...base.summary, fixed: 0 } }), 'NO_VERIFIED_REPAIR');
  for (const label of [NO_VERIFIED_REPAIR, 'Unverified changes', 'Not attributable to the application: the model identity policy was not met', 'Fixed?', ''])
    assert.equal(retestVerdict({ ...base, restorationLabel: label }), 'NO_VERIFIED_REPAIR', label);
  assert.equal(retestVerdict(null), 'INCONCLUSIVE');
});

test('runner.mjs treats only a missing framework-mode module as no framework mode; any other load failure stops the import', () => {
  const module = new URL('../../integrations/frameworks/run-record.mjs', import.meta.url).href;
  assert.equal(frameworkModeMissing({ code: 'ERR_MODULE_NOT_FOUND', url: module }), true);
  assert.equal(frameworkModeMissing({ code: 'ERR_MODULE_NOT_FOUND', url: new URL('../collateral/collateral.mjs', import.meta.url).href }), false, 'a module it imports is missing');
  assert.equal(frameworkModeMissing({ code: 'ERR_MODULE_NOT_FOUND' }), false);
  assert.equal(frameworkModeMissing(new SyntaxError('x')), false);
});
