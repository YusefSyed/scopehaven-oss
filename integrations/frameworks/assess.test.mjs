// Framework mode from the CLI (assess.mjs, run-record.mjs). node:test. No Python and no network: the
// acceptance records of the real LangGraph and Mastra templates are mapped and re-judged; the end-to-end run uses the
// fake adapter (fixtures/fake-adapter.mjs, a real child process speaking the turn-runner contract) through the same
// template, seed and adapter checks the CLI uses, in a throwaway git checkout. Temp directories are removed after use.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fakeCheckout } from './fixtures/fake-checkout.mjs';
import { frameworkModeRun, validateFrameworkModeRun, allowedUseControlOf, FRAMEWORK_MODE_ORIGIN, FRAMEWORK_MODE_EVALUATOR_HASH, FRAMEWORK_MODE_FILES, FrameworkModeError } from './run-record.mjs';
import { frameworkScenario, parseFrameworkArgs, runFrameworkAssessment, checkAdapterArgs, exitFor, MEASURING_HASH } from './assess.mjs';
import { tmpdir as systemTemp } from 'node:os';
import { createStore } from '../../src/store.mjs';
import { renderReport } from '../../src/report.mjs';
import { serializeSarif } from '../../src/sarif.mjs';
import { compareRuns } from '../../src/runner.mjs';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const CLI = fileURLToPath(new URL('../../src/cli.mjs', import.meta.url));
const read = path => JSON.parse(readFileSync(join(HERE, path), 'utf8'));
const acceptance = (family, name) => {
  const dir = join(HERE, 'acceptance', family), file = readdirSync(dir).find(f => f.startsWith(`${name}.`) && f.endsWith('.record.json') && f.slice(name.length + 1).match(/^\d+\.record\.json$/));
  return JSON.parse(readFileSync(join(dir, file), 'utf8'));
};
const scenarioOf = name => read(`scenarios/${name}.json`);
const AT = '2026-10-24T00:00:00.000Z';
const mapped = (record, scenario, id = 'run-1') => frameworkModeRun(record, scenario, { id, createdAt: AT });
const statuses = run => Object.fromEntries(run.results.map(row => [row.id, row.status]));
const codeOf = fn => { try { fn(); } catch (error) { return error.code; } return null; };
const temp = (t, prefix) => { const dir = mkdtempSync(join(tmpdir(), prefix)); chmodSync(dir, 0o700); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; };

test('a reset-after-commit record of each real template maps to a core run whose rows are recomputed from the record', () => {
  const langgraph = scenarioOf('langgraph-cs.reset-after-commit'), mastra = scenarioOf('mastra-billing.reset-after-commit');
  const defect = mapped(acceptance('langgraph-cs', 'langgraph-cs.reset-after-commit.checks-then-reports'), langgraph);
  assert.equal(defect.evidenceOrigin, FRAMEWORK_MODE_ORIGIN); assert.equal(defect.evaluatorHash, FRAMEWORK_MODE_EVALUATOR_HASH);
  assert.deepEqual(defect.requiredControlIds, ['COLLATERAL-GOAL']);
  assert.deepEqual(statuses(defect), { 'FW-EXEC': 'pass', 'FW-FAULT': 'pass', 'COLLATERAL-01': 'fail', 'COLLATERAL-GOAL': 'pass', 'FW-CONTENT': 'pass', 'FW-SAID-DID': 'pass' });
  assert.deepEqual(defect.counts, { pass: 5, fail: 1, inconclusive: 0, error: 0 }); assert.equal(defect.checksTotal, 6);
  assert.equal(defect.results.find(row => row.id === 'COLLATERAL-GOAL').severity, 'control');
  assert.ok(!defect.results.some(row => row.id === 'COLLATERAL-02'), 'reported only in the kept verdict: two snapshots can never pass it');
  const fixed = mapped(acceptance('langgraph-cs', 'langgraph-cs.reset-after-commit.checks-then-reports.fixed-update'), langgraph);
  assert.deepEqual(fixed.counts, { pass: 6, fail: 0, inconclusive: 0, error: 0 });
  assert.notEqual(fixed.targetBuildHash, defect.targetBuildHash, 'the template variant is the build');
  assert.match(fixed.build, /fixed-update/);
  for (const key of ['suiteHash', 'policyHash', 'fixtureHash', 'adapterVersion', 'profileHash', 'contextId', 'assertionSchemaVersion']) assert.equal(fixed[key], defect[key], key);
  const nothing = mapped(acceptance('langgraph-cs', 'langgraph-cs.reset-after-commit.do-nothing.fixed-update'), langgraph);
  assert.equal(statuses(nothing)['COLLATERAL-GOAL'], 'fail', 'an agent that does nothing fails the allowed-use control');
  assert.equal(statuses(nothing)['FW-FAULT'], 'inconclusive');
  assert.equal(statuses(nothing)['COLLATERAL-01'], 'inconclusive', 'the fault never fired, so nothing it shows can pass');
  const blind = mapped(acceptance('mastra-billing', 'mastra-billing.reset-after-commit.blind-retry'), mastra);
  assert.equal(statuses(blind)['COLLATERAL-01'], 'fail');
  const checks = mapped(acceptance('mastra-billing', 'mastra-billing.reset-after-commit.checks-then-reports'), mastra);
  assert.deepEqual(checks.counts, { pass: 6, fail: 0, inconclusive: 0, error: 0 });
  assert.match(checks.limitations[1], /in-process/, 'the Mastra snapshot is read inside the agent\'s process, and the run says so');
  for (const run of [defect, fixed, nothing, blind, checks]) assert.equal(validateFrameworkModeRun(run), true);
  // The scripted model persona is in the stable identity: another persona is another model behaviour, not another build.
  assert.notEqual(blind.profileHash, checks.profileHash);
  assert.equal(defect.adapterVersion, fixed.adapterVersion); assert.match(defect.adapterVersion, / langgraph measuring-unrecorded$/);
});

test('a run that is not usable, or whose planned fault did not fire, can fail but never pass', () => {
  const scenario = scenarioOf('langgraph-cs.reset-after-commit'), record = structuredClone(acceptance('langgraph-cs', 'langgraph-cs.reset-after-commit.checks-then-reports.fixed-update'));
  record.quiet.afterExit = { ...record.quiet.afterExit, same: false };
  const moved = mapped(record, scenario);
  assert.equal(statuses(moved)['FW-EXEC'], 'inconclusive');
  assert.deepEqual(Object.values(statuses(moved)).filter(status => status === 'pass'), [], 'no pass from an unusable run');
  assert.match(moved.results.find(row => row.id === 'COLLATERAL-01').observed, /^Not counted: FW-EXEC did not pass/);
  assert.equal(JSON.parse(serializeSarif(moved)).runs[0].results.filter(row => row.kind === 'pass').length, 0);
  assert.equal(exitFor(moved), 1);
  // A fail stands: the blind retry's extra refund is still a fail when its fault row is not decided.
  const blind = structuredClone(acceptance('mastra-billing', 'mastra-billing.reset-after-commit.blind-retry'));
  blind.ledger.records = blind.ledger.records.map(r => ({ ...r, fault: undefined, status: r.status === 'fault-injected' ? 'returned' : r.status }));
  const unfired = mapped(blind, scenarioOf('mastra-billing.reset-after-commit'));
  assert.equal(statuses(unfired)['FW-FAULT'], 'inconclusive'); assert.equal(statuses(unfired)['COLLATERAL-01'], 'fail');
});

test('every row a scenario implies is present, and a status the mapping does not know is refused', () => {
  const scenario = scenarioOf('langgraph-cs.reset-after-commit'), record = structuredClone(acceptance('langgraph-cs', 'langgraph-cs.reset-after-commit.checks-then-reports'));
  record.scenarioDigest = '0'.repeat(64);
  const stopped = mapped(record, scenario);
  assert.deepEqual(statuses(stopped), { 'FW-EXEC': 'inconclusive', 'FW-FAULT': 'inconclusive', 'COLLATERAL-01': 'inconclusive', 'COLLATERAL-GOAL': 'inconclusive', 'FW-SAID-DID': 'inconclusive' });
  const fresh = acceptance('langgraph-cs', 'langgraph-cs.reset-after-commit.checks-then-reports');
  const odd = (record, s) => ({ rows: [{ check: 'FW-EXEC', status: 'pass', basis: '' }, { check: 'COLLATERAL-01', status: 'skipped', basis: '' }], overall: {} });
  assert.equal(codeOf(() => frameworkModeRun(fresh, scenario, { id: 'x', createdAt: AT }, { judge: odd })), 'verdict-unrecognized');
});

test('the report, SARIF and comparison read a framework-mode run unchanged', () => {
  const scenario = scenarioOf('langgraph-cs.reset-after-commit');
  const defect = mapped(acceptance('langgraph-cs', 'langgraph-cs.reset-after-commit.checks-then-reports'), scenario, 'run-defect');
  const html = renderReport(defect);
  assert.match(html, /Framework scenario run \(langgraph-cs\.reset-after-commit\)/);
  assert.match(html, /<article><h2>COLLATERAL-01 · No effect outside the declared set<\/h2><p><strong>FAIL<\/strong>/);
  assert.match(html, /1 failed/);
  const sarif = JSON.parse(serializeSarif(defect));
  const result = sarif.runs[0].results.find(row => row.ruleId === 'COLLATERAL-01');
  assert.equal(result.kind, 'fail'); assert.equal(result.level, 'error');
  assert.equal(sarif.runs[0].results.find(row => row.ruleId === 'COLLATERAL-GOAL').kind, 'pass');
  // The comparison reads the pair natively (the verified retest, vr1.test.mjs covers its refusal rules).
  const fixed = mapped(acceptance('langgraph-cs', 'langgraph-cs.reset-after-commit.checks-then-reports.fixed-update'), scenario, 'run-fixed');
  const comparison = compareRuns(defect, fixed);
  assert.equal(comparison.compatible, true); assert.equal(comparison.restorationLabel, 'Local controls restored');
  assert.equal(comparison.summary.fixed, 1);
});

test('a stored framework-mode run is refused unless its own record and scenario reproduce it exactly', () => {
  const scenario = scenarioOf('mastra-billing.reset-after-commit'), record = acceptance('mastra-billing', 'mastra-billing.reset-after-commit.blind-retry');
  const run = mapped(record, scenario);
  const edited = structuredClone(run); edited.results.find(row => row.id === 'COLLATERAL-01').status = 'pass'; edited.counts = { pass: 6, fail: 0, inconclusive: 0, error: 0 };
  assert.equal(codeOf(() => validateFrameworkModeRun(edited)), 'run-not-reproduced', 'a status edited with its counts');
  const relabelled = structuredClone(run); relabelled.requiredControlIds = ['FW-EXEC'];
  assert.equal(codeOf(() => validateFrameworkModeRun(relabelled)), 'run-not-reproduced');
  // A consistent edit of the kept record changes what the judge recomputes, so the stored rows no longer match it.
  const forged = structuredClone(run); forged.scenarioEvidence.record.snapshots.after = forged.scenarioEvidence.record.snapshots.before;
  assert.equal(codeOf(() => validateFrameworkModeRun(forged)), 'run-not-reproduced');
  const extra = { ...structuredClone(run), verdictOverride: 'pass' };
  assert.equal(codeOf(() => validateFrameworkModeRun(extra)), 'run-not-reproduced', 'an unknown key');
  assert.equal(codeOf(() => validateFrameworkModeRun({ ...structuredClone(run), evaluatorHash: '0'.repeat(64) })), 'evaluator-changed');
  assert.equal(codeOf(() => validateFrameworkModeRun({ ...structuredClone(run), evidenceOrigin: 'local-http-response' })), 'run-invalid');
  // The store's own fields and an authorization stamp are not part of the recomputation.
  assert.equal(validateFrameworkModeRun({ ...structuredClone(run), integrity: { sha256: 'x' }, notes: {} }), true);
});

test('only scenarios whose requested change should persist have an allowed-use control; the others are refused', () => {
  assert.equal(allowedUseControlOf(scenarioOf('langgraph-cs.reset-after-commit')), 'COLLATERAL-GOAL');
  assert.equal(allowedUseControlOf(scenarioOf('mastra-billing.duplicate-delivery')), 'COLLATERAL-GOAL');
  assert.equal(allowedUseControlOf(scenarioOf('langgraph-cs.return-leg')), 'COLLATERAL-GOAL', 'a goal scenario');
  // A timeout fires before the tool body: an honest "could not" with nothing persisted is right, so no persisted change can be required.
  assert.equal(allowedUseControlOf(scenarioOf('mastra-billing.s2-timeout')), null);
  const record = acceptance('mastra-billing', 'mastra-billing.s2-timeout.honest-failure');
  assert.equal(codeOf(() => mapped(record, scenarioOf('mastra-billing.s2-timeout'))), 'no-allowed-use-control');
  assert.equal(codeOf(() => frameworkScenario('mastra', 'mastra-billing.s2-timeout')), 'no-allowed-use-control');
  assert.equal(codeOf(() => frameworkScenario('langgraph', 'mastra-billing.reset-after-commit')), 'scenario-other-framework');
  assert.equal(codeOf(() => frameworkScenario('autogen')), 'framework-unsupported');
  assert.equal(codeOf(() => frameworkScenario('mastra', '../secrets')), 'invalid-options');
  assert.equal(frameworkScenario('langgraph').id, 'langgraph-cs.reset-after-commit', 'the default scenario');
  assert.equal(codeOf(() => mapped({ schema: 'other' }, scenarioOf('langgraph-cs.reset-after-commit'))), 'record-invalid');
  assert.equal(codeOf(() => mapped(acceptance('mastra-billing', 'mastra-billing.reset-after-commit.blind-retry'), scenarioOf('langgraph-cs.reset-after-commit'))), 'record-invalid', 'another scenario\'s record');
});

test('only the template\'s build switch passes to the adapter: no second --template, no other starting data', () => {
  assert.deepEqual(checkAdapterArgs([]), []); assert.deepEqual(checkAdapterArgs(['--variant', 'fixed-update']), ['--variant', 'fixed-update']);
  for (const args of [['--template', '/edited/checkout'], ['--passenger', 'X'], ['--variant', 'fixed-update', '--variant', 'x'], ['--variant', '../x'], ['--variant'], ['fixed-update']])
    assert.equal(codeOf(() => checkAdapterArgs(args)), 'adapter-arg-refused', args.join(' '));
  assert.equal(codeOf(() => checkAdapterArgs(['--variant', 'x'], { adapter: { args: ['--variant', 'y'] } })), 'adapter-arg-refused', 'the scenario already sets it');
  assert.equal(codeOf(() => parseFrameworkArgs(['--framework', 'langgraph', '--template', '/t', '--runtime', '/r', '--stub', 's', '--adapter-arg', '--template', '--adapter-arg', '/x'])), 'adapter-arg-refused');
  assert.equal(codeOf(() => parseFrameworkArgs(['--framework', 'langgraph', '--template', '/t', '--runtime', '/r', '--stub', 's', '--label', 'Not A Label'])), 'invalid-options');
});

test('the option parser takes one value per flag, repeats only --adapter-arg, and needs an absolute runtime', () => {
  const base = ['--framework', 'mastra', '--template', '/t', '--runtime', '/r', '--stub', 'blind-retry'];
  assert.deepEqual(parseFrameworkArgs([...base, '--adapter-arg', '--variant', '--adapter-arg', 'fixed-update', '--label', 'x']), { adapterArgs: ['--variant', 'fixed-update'], framework: 'mastra', template: '/t', runtime: '/r', stub: 'blind-retry', label: 'x' });
  for (const args of [[...base, '--stub', 'again'], [...base, '--unknown', 'x'], [...base, '--label'], base.slice(2), ['--framework', 'mastra', '--template', '/t', '--runtime', 'relative', '--stub', 's'], [...base, '--out', '--label']])
    assert.ok(['invalid-options', 'framework-unsupported'].includes(codeOf(() => parseFrameworkArgs(args))), args.join(' '));
  assert.equal(exitFor({ counts: { pass: 6, fail: 0, inconclusive: 0, error: 0 }, checksTotal: 6 }), 0);
  for (const counts of [{ pass: 5, fail: 1, inconclusive: 0, error: 0 }, { pass: 5, fail: 0, inconclusive: 1, error: 0 }, { pass: 5, fail: 0, inconclusive: 0, error: 1 }, { pass: 5, fail: 0, inconclusive: 0, error: 0 }])
    assert.equal(exitFor({ counts, checksTotal: 6 }), 1, JSON.stringify(counts));
  assert.equal(codeOf(() => parseFrameworkArgs(['--framework', 'crewai', ...base.slice(2)])), 'framework-unsupported');
});

// The fake adapter's refund app under a reset after commit, in a throwaway git checkout at a pinned commit (fixtures/fake-checkout.mjs).
const fakeCheckoutFor = t => { const fake = fakeCheckout(); t.after(() => rmSync(fake.root, { recursive: true, force: true })); return fake; };

test('end to end: a framework scenario runs through the CLI steps and saves a run the store, report and SARIF read', async t => {
  const fake = fakeCheckoutFor(t);
  const workdirs = () => readdirSync(systemTemp()).filter(name => name.startsWith(`scopehaven-${fake.scenario.id}-`)), before = new Set(workdirs());
  const defect = await runFrameworkAssessment({ scenario: fake.scenario, stub: 'blind-retry', runtime: fake.runtime, template: fake.template, out: fake.out });
  const fixed = await runFrameworkAssessment({ scenario: fake.scenario, stub: 'checks-then-reports', runtime: fake.runtime, template: fake.template, out: fake.out });
  const store = createStore(fake.out);
  const stored = await store.get(defect.id);
  assert.equal(validateFrameworkModeRun(stored), true, 'the stored run reproduces from its own record');
  assert.equal(statuses(stored)['COLLATERAL-01'], 'fail', 'a blind retry refunds twice');
  assert.equal(statuses(stored)['FW-FAULT'], 'pass');
  assert.deepEqual((await store.get(fixed.id)).counts, { pass: 6, fail: 0, inconclusive: 0, error: 0 });
  assert.equal(stored.scenarioEvidence.record.adapter.checkout.commit, fake.scenario.template.commit);
  assert.match(renderReport(stored), /Fake app: refund under a reset after commit/);
  assert.equal(JSON.parse(serializeSarif(stored)).runs[0].results.find(row => row.ruleId === 'COLLATERAL-01').kind, 'fail');
  assert.equal(readdirSync(join(fake.out, 'runs')).length, 2);
  assert.equal(stored.scenarioEvidence.record.adapter.measuring, MEASURING_HASH, 'the harness and adapter code that measured the run');
  assert.match(stored.adapterVersion, new RegExp(` fake-app measuring@${MEASURING_HASH.slice(0, 16)}$|measuring@${MEASURING_HASH.slice(0, 16)}$`));
  assert.ok((await store.list()).every(summary => !Object.hasOwn(summary, 'scenarioEvidence')), 'history pages do not carry the whole record');
  assert.deepEqual(workdirs().filter(name => !before.has(name)), [], 'every working directory this test made was removed');
  // Refusals before anything runs: an unknown stub, a seeded scenario without its data, and a template checkout with a local edit.
  await assert.rejects(runFrameworkAssessment({ scenario: { ...fake.scenario, workdir: { seed: [{ from: 'a.db', to: 'a.db', sha256: '0'.repeat(64) }] } }, stub: 'blind-retry', runtime: fake.runtime, template: fake.template, out: fake.out }), error => error.code === 'data-required');
  await assert.rejects(runFrameworkAssessment({ scenario: fake.scenario, stub: 'blind-retry', runtime: fake.runtime, template: fake.template, out: fake.out, adapterArgs: ['--template', fake.root] }), error => error.code === 'adapter-arg-refused');
  await assert.rejects(runFrameworkAssessment({ scenario: fake.scenario, stub: 'not-a-stub', runtime: fake.runtime, template: fake.template, out: fake.out }), error => error.code === 'stub-unknown');
  writeFileSync(join(fake.template, 'fixtures', 'app.txt'), 'edited\n');
  await assert.rejects(runFrameworkAssessment({ scenario: fake.scenario, stub: 'blind-retry', runtime: fake.runtime, template: fake.template, out: fake.out }), /Template files differ from the pinned commit/);
  assert.equal(readdirSync(join(fake.out, 'runs')).length, 2, 'nothing more was saved');
});

const cli = args => new Promise(resolve => {
  const child = spawn(process.execPath, [CLI, ...args], { env: { PATH: process.env.PATH } });
  let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
  child.on('close', code => resolve({ code, stdout, stderr }));
});

test('the CLI routes assess --framework to framework mode and refuses before any run', async t => {
  const dir = temp(t, 'scopehaven framework cli '), out = join(dir, 'out');
  for (const [args, code] of [
    [['--framework', 'autogen', '--template', dir, '--runtime', dir, '--stub', 'x', '--out', out], 'framework-unsupported'],
    [['--framework', 'mastra', '--scenario', 'mastra-billing.s2-timeout', '--template', dir, '--runtime', dir, '--stub', 'x', '--out', out], 'no-allowed-use-control'],
    [['--framework', 'langgraph', '--scenario', 'mastra-billing.reset-after-commit', '--template', dir, '--runtime', dir, '--stub', 'x', '--out', out], 'scenario-other-framework'],
    [['--framework', 'mastra', '--template', dir, '--runtime', dir, '--stub', 'not-a-stub', '--out', out], 'stub-unknown'],
  ]) {
    const result = await cli(args);
    assert.equal(result.code, 2, `${code}: ${result.stderr}`); assert.match(result.stderr, new RegExp(`could not run the framework scenario: ${code}`)); assert.equal(result.stdout, '');
  }
  // A template folder that is not the pinned checkout is refused by run.mjs's own check, and nothing is saved.
  const notPinned = await cli(['--framework', 'mastra', '--template', dir, '--runtime', dir, '--stub', 'blind-retry', '--out', out]);
  assert.equal(notPinned.code, 2); assert.doesNotMatch(notPinned.stderr, /^\s*$/);
  assert.equal(existsSync(out), false, 'the template is checked before the run store is opened');
});

test('the evaluator identity covers this module and the judge\'s whole static import closure', () => {
  // A broader scan (both quote styles, dynamic imports) over the closure finds no file outside it.
  const root = fileURLToPath(new URL('../../', import.meta.url)), found = new Set();
  for (const file of FRAMEWORK_MODE_FILES) {
    const text = readFileSync(join(root, file), 'utf8');
    for (const match of text.matchAll(/(?:from\s+|import\s*\(\s*)['"](\.{1,2}\/[^'"]+)['"]/g)) found.add(join(file, '..', match[1]).split('\\').join('/'));
  }
  assert.deepEqual([...found].filter(file => !FRAMEWORK_MODE_FILES.includes(file)), []);
  for (const file of ['integrations/frameworks/run-record.mjs', 'integrations/frameworks/judge.mjs', 'integrations/frameworks/claim-reader.mjs', 'integrations/frameworks/fault.mjs',
    'integrations/collateral/collateral.mjs', 'integrations/collateral/state-diff.mjs', 'integrations/observers/events.mjs', 'src/domain.mjs']) assert.ok(FRAMEWORK_MODE_FILES.includes(file), file);
  assert.ok(!FRAMEWORK_MODE_FILES.includes('integrations/frameworks/assess.mjs'), 'the driver is not part of the evaluator');
  assert.ok(FRAMEWORK_MODE_FILES.every(file => !file.startsWith('/') && !file.includes('..')), 'project-relative paths, so the identity does not depend on the checkout folder');
  assert.ok(new FrameworkModeError('x') instanceof Error);
});
