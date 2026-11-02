// Coverage in every export. From the run alone: for each actor with a boundary check, whether a required allowed-use
// control ran as that actor; an actor with none is a gap, shown in red, because a fix that refuses that actor everything would
// read as a fix. From the operator's files (--coverage-inventory, --coverage-contract, --coverage-targets): the pre-run coverage
// report of integrations/coverage-report. Coverage is presentation only: no verdict, count, comparison, gate outcome or hash moves.
// Owned synthetic data only: an injected transport for the HTTP runs and the owned loopback synthetic fixture for one run; no model,
// provider or observer; private temporary directories.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, contractDigest } from '../src/contracts.mjs';
import { compareRuns, runAssessment } from '../src/runner.mjs';
import { renderReport, comparisonDocument, renderComparisonReport, coverageOf, rowActorId, COVERAGE_GAP, COVERAGE_RULE, COVERAGE_NEEDS_FILES } from '../src/report.mjs';
import { renderSarif, serializeSarif } from '../src/sarif.mjs';
import { renderSummary } from '../src/report-summary.mjs';
import { residualDocument } from '../src/residual.mjs';
import { exportRun, main, COVERAGE_INPUTS, COVERAGE_PROFILE_WARNING } from '../src/export-cli.mjs';
import { createStore } from '../src/store.mjs';
import { coverageReport, coverageLines, DECLARED_INTENT_WARNING, COVERAGE_SCOPE } from '../integrations/coverage-report/coverage.mjs';

// Two actors. ops has a boundary check and a required allowed-use control; guest has a boundary check and, in the defective twin
// profile, no control at all. The fixed twin gives guest a required control. Neither actor has credentials, so no key is read. One
// check is declared not applicable: the connector runs nothing for it, so it has nothing to cover.
const check = (id, severity, actorId, path) => ({ id, title: id, category: severity === 'control' ? 'allowed-use' : 'tool-misuse', severity, actorId, method: 'GET', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] });
const profile = ({ guestControl = false, id = 'coverage-target' } = {}) => ({ id, name: 'Coverage app', applicationId: 'coverage-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-coverage',
  actors: { ops: { principalId: 'ops', role: 'member', tenantId: 't1' }, guest: { principalId: 'guest', role: 'member', tenantId: 't1' } },
  requiredControlIds: ['OPS-ALLOWED', ...(guestControl ? ['GUEST-ALLOWED'] : [])],
  checks: [check('OPS-BOUNDARY', 'high', 'ops', '/agent/orders'), check('OPS-ALLOWED', 'control', 'ops', '/me'), check('GUEST-BOUNDARY', 'high', 'guest', '/agent/tickets'), ...(guestControl ? [check('GUEST-ALLOWED', 'control', 'guest', '/me')] : []),
    { ...check('NOT-HERE', 'low', 'guest', '/agent/absent'), applicability: { applies: false, reason: 'Capability absent in this test application' } }] });
const transport = async () => ({ status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 });
const assess = async options => { const run = await runHttpAssessment(profile(options), { env: {}, transport }); validateHttpRunEvidence(run); return run; };
const gapRun = await assess(), gapAgain = await assess(), fixedRun = await assess({ guestControl: true }), fixedAgain = await assess({ guestControl: true });
// The owned synthetic fixture: its rows' traces are attempts, and two checks (a cross-tenant canary, a concurrency check) run as two principals.
const synthetic = await runAssessment('demo-vulnerable');
const fullCoverage = () => { const report = coverageReport({ inventory, contract: contract(), target: profile() }); return { report, warnings: [], lines: coverageLines(report) }; };
// The operator's files for the full report: an inventory of the four requests, and a stated contract (or one read from the
// application's own declarations, which carries the declared-intent warning).
const inventory = { schema: 'scopehaven-coverage-inventory/1', applicationId: 'coverage-app', tenants: ['t1'], roles: ['member'], members: { t1: ['member'] },
  operations: [{ id: 'GET /me', surface: 'api', method: 'GET', path: '/me', auth: 'session', tenantScoped: false }, { id: 'GET /agent/orders', surface: 'api', method: 'GET', path: '/agent/orders', auth: 'session', tenantScoped: false },
    { id: 'GET /agent/tickets', surface: 'api', method: 'GET', path: '/agent/tickets', auth: 'session', tenantScoped: false }, { id: 'DELETE /agent/tickets', surface: 'api', method: 'DELETE', path: '/agent/tickets', auth: 'session', tenantScoped: false }], datastores: [] };
const contract = (basis = 'stated-policy') => ({ schema: 'scopehaven-coverage-contract/1', applicationId: 'coverage-app', basis, crossTenant: 'deny',
  rules: [{ operation: 'GET /me', allow: ['member'] }, { operation: 'GET /agent/orders', allow: ['member'] }, { operation: 'GET /agent/tickets', allow: [] }, { operation: 'DELETE /agent/tickets', allow: [] }] });
// The design's sentence, spelled out here so a change to the constant is caught.
const GAP_SENTENCE = 'No allowed-use control for this actor: a fix that refuses this actor everything would read as a fix.';
const GAP_LINE = `<li class="coverage-gap">guest: 1 boundary check (GUEST-BOUNDARY); no allowed-use control. ${GAP_SENTENCE}</li>`;
const OPS_LINE = '<li>ops: 1 boundary check (OPS-BOUNDARY); allowed-use controls: OPS-ALLOWED.</li>';
const count = (text, needle) => text.split(needle).length - 1;

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven coverage '));
  t.after(() => rm(root, { recursive: true, force: true }));
  const data = join(root, 'store'), out = join(root, 'exports'), files = join(root, 'files');
  const store = createStore(data); await store.ready;
  await mkdir(out, { mode: 0o700 }); await mkdir(files, { mode: 0o700 });
  const write = async (name, value) => { const path = join(files, name); await writeFile(path, JSON.stringify(value)); return path; };
  const saved = { gap: await store.save(structuredClone(gapRun)), gapAgain: await store.save(structuredClone(gapAgain)), fixed: await store.save(structuredClone(fixedRun)), fixedAgain: await store.save(structuredClone(fixedAgain)) };
  const paths = { inventory: await write('inventory.json', inventory), contract: await write('contract.json', contract()), declared: await write('declared.json', contract('app-declaration')),
    targets: await write('targets.json', { schemaVersion: 1, targets: [profile()] }), fixedTargets: await write('fixed-targets.json', { schemaVersion: 1, targets: [profile({ guestControl: true })] }),
    otherTargets: await write('other-targets.json', { schemaVersion: 1, targets: [profile({ id: 'another-target' })] }),
    // The same profile written non-canonically (a trailing slash on the origin): the validator normalizes it, and the run's digest is of the normalized profile.
    slashTargets: await write('slash-targets.json', { schemaVersion: 1, targets: [{ ...profile(), origin: 'http://127.0.0.1:9/' }] }),
    movedTargets: await write('moved-targets.json', { schemaVersion: 1, targets: [{ ...profile(), checks: [...profile().checks, check('OPS-LATER', 'medium', 'ops', '/agent/later')] }] }) };
  const flags = (which = 'targets', basis = 'contract') => ({ coverageInventory: paths.inventory, coverageContract: paths[basis], coverageTargets: paths[which] });
  // Library calls sign only when asked, so these exports carry no envelope and no stamp.
  const exportText = async (name, options) => { await exportRun({ outputFile: join(out, name), dataDir: data, ...options }); return readFile(join(out, name), 'utf8'); };
  return { root, data, out, store, saved, paths, flags, exportText };
}

test('an actor without a required allowed-use control is red in the HTML and listed in the comparison JSON and SARIF; its twin with a control is not', async t => {
  assert.deepEqual([rowActorId(gapRun.results[0]), rowActorId(gapRun.results[2]), rowActorId({ trace: [] }), rowActorId(null)], ['ops', 'guest', null, null]);
  assert.equal(gapRun.results.find(r => r.id === 'NOT-HERE').status, 'not_applicable');
  assert.equal(COVERAGE_GAP, GAP_SENTENCE);
  const gap = coverageOf(gapRun), fixed = coverageOf(fixedRun);
  assert.deepEqual(gap, { basis: 'requiredControlIds', actors: [{ actorId: 'guest', boundaryChecks: ['GUEST-BOUNDARY'], allowedUseControls: [] }, { actorId: 'ops', boundaryChecks: ['OPS-BOUNDARY'], allowedUseControls: ['OPS-ALLOWED'] }],
    actorsWithoutAllowedUse: ['guest'], rowsWithoutActor: 0, gap: COVERAGE_GAP, rule: COVERAGE_RULE });
  assert.deepEqual(fixed.actorsWithoutAllowedUse, []); assert.deepEqual(fixed.actors.find(a => a.actorId === 'guest').allowedUseControls, ['GUEST-ALLOWED']);
  // A control that is not required does not cover its actor; a row with no actor is counted, not placed; a not-applicable row is no boundary check.
  const optional = structuredClone(gapRun); optional.results.push({ ...structuredClone(optional.results[1]), id: 'GUEST-OPTIONAL', severity: 'control' }); optional.results.at(-1).trace[0].data.actorId = 'guest';
  assert.deepEqual(coverageOf(optional).actorsWithoutAllowedUse, ['guest']);
  const unplaced = structuredClone(gapRun); delete unplaced.results[2].trace[0].data.actorId; unplaced.results[0].status = 'not_applicable';
  assert.deepEqual([coverageOf(unplaced).rowsWithoutActor, coverageOf(unplaced).actors], [1, []]);
  // The synthetic fixture: the actor is the one principal every attempt ran as; a row whose attempts ran as two principals is not placed,
  // never attributed to whichever came first. No gap: every synthetic actor with a boundary check has required controls.
  const canary = synthetic.results.find(r => r.id === 'CANARY-01');
  assert.deepEqual([...new Set(canary.trace.filter(e => e.data?.actor).map(e => e.data.actor.principalId))], ['member-cobalt', 'member-aster']);
  assert.equal(rowActorId(canary), null); assert.equal(rowActorId(synthetic.results.find(r => r.id === 'TENANT-01')), 'member-aster');
  const demo = coverageOf(synthetic);
  assert.deepEqual([demo.actorsWithoutAllowedUse, demo.rowsWithoutActor, demo.actors.map(a => [a.actorId, a.boundaryChecks.length, a.allowedUseControls.length])], [[], 2, [['admin-aster', 7, 7], ['member-aster', 17, 10]]]);
  assert.ok(demo.actors.every(a => !a.boundaryChecks.includes('CANARY-01') && !a.boundaryChecks.includes('CONCURRENT-01')));
  assert.ok(demo.actors.length >= 2 && demo.actors.every(a => a.allowedUseControls.length > 0 && a.boundaryChecks.length > 0), 'every synthetic actor with a boundary check has a required control (holds as the suite grows)');
  // A conversation row writes the same actorId field as the HTTP connector.
  assert.equal(rowActorId({ trace: [{ type: 'conversation-observation', label: '', data: { actorId: 'alice' } }] }), 'alice');
  const demoHtml = renderReport(synthetic);
  assert.equal(count(demoHtml, 'class="coverage-gap"'), 0); assert.ok(demoHtml.includes('<p><small>2 rows record no single actor and are not placed.</small></p>'));
  // HTML: the gap is red (class and colour rule), with the exact sentence; the covered actor is a plain line.
  const html = renderReport(gapRun), fixedHtml = renderReport(fixedRun);
  assert.ok(html.includes('.coverage-gap{color:#b91c1c}'), 'the red rule'); assert.ok(html.includes(GAP_LINE), 'the gap line'); assert.ok(html.includes(OPS_LINE), 'the covered line');
  assert.equal(count(html, 'class="coverage-gap"'), 1);
  assert.equal(count(fixedHtml, 'class="coverage-gap"'), 0); assert.ok(fixedHtml.includes('<li>guest: 1 boundary check (GUEST-BOUNDARY); allowed-use controls: GUEST-ALLOWED.</li>'));
  // The comparison JSON carries each side's gaps and their union (an actor neither run controls cannot be told fixed from refused).
  const same = comparisonDocument(gapRun, gapAgain, compareRuns(gapRun, gapAgain));
  assert.deepEqual([same.coverage.actorsWithoutAllowedUse, same.coverage.candidate.actorsWithoutAllowedUse, same.coverage.baseline.actorsWithoutAllowedUse, same.coverage.report, same.coverage.needs], [['guest'], ['guest'], ['guest'], null, COVERAGE_NEEDS_FILES]);
  assert.deepEqual(comparisonDocument(fixedRun, fixedAgain, compareRuns(fixedRun, fixedAgain)).coverage.actorsWithoutAllowedUse, []);
  const mixed = comparisonDocument(gapRun, fixedRun, compareRuns(gapRun, fixedRun));
  assert.deepEqual([mixed.coverage.actorsWithoutAllowedUse, mixed.coverage.candidate.actorsWithoutAllowedUse, mixed.coverage.baseline.actorsWithoutAllowedUse], [['guest'], [], ['guest']]);
  const cmpHtml = renderComparisonReport(same);
  assert.ok(cmpHtml.includes('.coverage-gap{color:#b91c1c}')); assert.ok(cmpHtml.includes(`<li class="coverage-gap">Candidate: guest: 1 boundary check (GUEST-BOUNDARY); no allowed-use control. ${GAP_SENTENCE}</li>`));
  assert.ok(cmpHtml.includes('<li>Candidate: ops: 1 boundary check (OPS-BOUNDARY); allowed-use controls: OPS-ALLOWED.</li>')); assert.equal(count(cmpHtml, 'class="coverage-gap"'), 2, 'candidate and baseline');
  assert.equal(count(renderComparisonReport(comparisonDocument(fixedRun, fixedAgain, compareRuns(fixedRun, fixedAgain))), 'class="coverage-gap"'), 0);
  // Through the exporter: the SARIF export names the gap in runs[0].properties.coverage and nothing else moves; the comparison JSON carries it.
  const w = await workspace(t);
  const sarif = JSON.parse(await w.exportText('gap.sarif', { runId: w.saved.gap.id, format: 'sarif' })).runs[0], fixedSarif = JSON.parse(await w.exportText('fixed.sarif', { runId: w.saved.fixed.id, format: 'sarif' })).runs[0];
  assert.deepEqual(sarif.properties.coverage, { actorsWithoutAllowedUse: ['guest'] }); assert.deepEqual(fixedSarif.properties.coverage, { actorsWithoutAllowedUse: [] });
  assert.equal(renderSarif(gapRun).runs[0].properties.coverage, undefined, 'src/sarif.mjs is unchanged: the exporter adds the property');
  const cmp = JSON.parse(await w.exportText('cmp.json', { runId: w.saved.gapAgain.id, baselineRunId: w.saved.gap.id, format: 'json' }));
  assert.deepEqual(cmp.coverage.actorsWithoutAllowedUse, ['guest']); assert.equal(cmp.coverage.gap, COVERAGE_GAP);
  assert.ok((await w.exportText('gap.html', { runId: w.saved.gap.id, format: 'html' })).includes(GAP_LINE));
});

test('with the inventory, contract and targets the exports carry the full pre-run report, its scope note and the declared-intent warning; without them the section says what it needs', async t => {
  const w = await workspace(t);
  const without = await w.exportText('plain.html', { runId: w.saved.gap.id, format: 'html' });
  assert.ok(without.includes(`<h3>Pre-run coverage report</h3><p>${COVERAGE_NEEDS_FILES.replace(/'/g, '&#39;')}</p>`)); assert.ok(!without.includes('Coverage report for coverage-app'));
  const withFiles = await w.exportText('full.html', { runId: w.saved.gap.id, format: 'html', ...w.flags() });
  assert.ok(withFiles.includes('<h3>Pre-run coverage report</h3><ul><li>Coverage report for coverage-app (coverage-target). Coverage, not findings:'), 'the report, from coverageLines');
  assert.ok(withFiles.includes(`<li>${COVERAGE_SCOPE.replace(/'/g, '&#39;')}</li>`), 'the scope note'); assert.ok(withFiles.includes('Suite reconciliation: 3 drafted and 1 declared not applicable of 4 suite checks (equal).'));
  assert.ok(withFiles.includes('Forbidden side: stated-deny cells with a forbidden check'));
  assert.ok(!withFiles.includes(COVERAGE_NEEDS_FILES.replace(/'/g, '&#39;'))); assert.ok(!withFiles.includes('Warning: The stated intent'), 'a stated contract carries no declared-intent warning'); assert.ok(!withFiles.includes(COVERAGE_PROFILE_WARNING.replace(/'/g, '&#39;')));
  assert.ok(withFiles.includes(GAP_LINE), 'the run-alone part is still there');
  // A contract read from the application's own declarations: the declared-intent warning, as coverageLines prints it.
  const declared = await w.exportText('declared.html', { runId: w.saved.gap.id, format: 'html', ...w.flags('targets', 'declared') });
  assert.ok(declared.includes(`<li>Warning: ${DECLARED_INTENT_WARNING.replace(/'/g, '&#39;')}</li>`));
  // A profile written non-canonically is digested as the validator normalizes it, like the run's: no warning.
  const slash = await w.exportText('slash.html', { runId: w.saved.gap.id, format: 'html', ...w.flags('slashTargets') });
  assert.ok(!slash.includes(COVERAGE_PROFILE_WARNING.replace(/'/g, '&#39;'))); assert.ok(slash.includes('Coverage report for coverage-app (coverage-target).'));
  // A profile that is not the run's (one more check): the report is of the profile as it is now, and says so.
  const moved = await w.exportText('moved.html', { runId: w.saved.gap.id, format: 'html', ...w.flags('movedTargets') });
  assert.ok(moved.includes(`<li>${COVERAGE_PROFILE_WARNING.replace(/'/g, '&#39;')}</li>`)); assert.ok(moved.includes('profile checks the suite leaves out: OPS-LATER'));
  // The comparison exports carry the same block.
  const cmp = JSON.parse(await w.exportText('cmp.json', { runId: w.saved.gapAgain.id, baselineRunId: w.saved.gap.id, format: 'json', ...w.flags() }));
  assert.equal(cmp.coverage.report.report.schema, 'scopehaven-coverage-report/1'); assert.equal(cmp.coverage.report.lines[1], COVERAGE_SCOPE); assert.deepEqual(cmp.coverage.report.warnings, []); assert.equal(cmp.coverage.needs, undefined);
  const cmpHtml = await w.exportText('cmp.html', { runId: w.saved.gapAgain.id, baselineRunId: w.saved.gap.id, format: 'html', ...w.flags() });
  assert.ok(cmpHtml.includes('<h3>Pre-run coverage report</h3><ul><li>Coverage report for coverage-app (coverage-target).'));
  const plainCmp = JSON.parse(await w.exportText('plain-cmp.json', { runId: w.saved.gapAgain.id, baselineRunId: w.saved.gap.id, format: 'json' }));
  assert.equal(plainCmp.coverage.report, null); assert.equal(plainCmp.coverage.needs, COVERAGE_NEEDS_FILES);
  // The three files come together, absolute, for the HTML report and the comparison exports only; the targets file must name this run's target.
  const base = { runId: w.saved.gap.id, dataDir: w.data };
  for (const options of [{ format: 'html', coverageInventory: w.paths.inventory }, { format: 'html', coverageInventory: w.paths.inventory, coverageContract: w.paths.contract }, { format: 'html', ...w.flags(), coverageTargets: 'targets.json' },
    { format: 'sarif', ...w.flags() }, { format: 'json', ...w.flags() }, { format: 'summary', ...w.flags() }, { format: 'residual', ...w.flags() }])
    await assert.rejects(exportRun({ ...base, ...options, outputFile: join(w.out, 'refused.html') }), /Invalid export options/, JSON.stringify(options));
  await assert.rejects(exportRun({ ...base, format: 'html', ...w.flags('otherTargets'), outputFile: join(w.out, 'refused.html') }), error => error.code === COVERAGE_INPUTS && /names no target "coverage-target"/.test(error.message));
  await assert.rejects(exportRun({ ...base, format: 'html', ...w.flags(), coverageContract: w.paths.targets, outputFile: join(w.out, 'refused.html') }), error => error.code === COVERAGE_INPUTS && /contract/.test(error.message));
  await assert.rejects(exportRun({ ...base, format: 'html', ...w.flags(), coverageInventory: join(w.root, 'missing.json'), outputFile: join(w.out, 'refused.html') }), /Invalid coverage inventory file/);
  await assert.rejects(exportRun({ ...base, format: 'html', ...w.flags(), coverageTargets: w.paths.inventory, outputFile: join(w.out, 'refused.html') }), error => error.code === COVERAGE_INPUTS && /not a valid target manifest/.test(error.message));
  assert.ok((await main(['--run', w.saved.gap.id, '--format', 'html', '--out', join(w.out, 'cli.html'), '--data', w.data, '--unsigned', '--coverage-inventory', w.paths.inventory, '--coverage-contract', w.paths.contract, '--coverage-targets', w.paths.targets], { signedByDefault: true })).saved);
  assert.ok((await readFile(join(w.out, 'cli.html'), 'utf8')).includes('Coverage report for coverage-app (coverage-target).'));
  assert.ok(!(await readFile(join(w.out, 'cli.html'), 'utf8')).includes(w.root), 'no path of this machine in the report');
});

test('coverage and residual are one section, exactly once, in the report and the comparison; the one-page summary keeps its residual heading', async t => {
  for (const [name, html] of [['report', renderReport(gapRun)], ['report with files', renderReport(gapRun, { coverage: fullCoverage() })]]) {
    assert.equal(count(html, '<h2>Coverage and residual</h2>'), 1, name); assert.equal(count(html, '<section class="residual">'), 1, name);
    assert.equal(count(html, '<h2>Residual</h2>'), 0, name); assert.equal(count(html, '<h2>Coverage</h2>'), 0, name); assert.equal(count(html, '<h3>Residual</h3>'), 1, name);
    const section = html.indexOf('<section class="residual">'), end = html.indexOf('</section>', section);
    for (const part of ['<h3>Coverage: allowed-use controls per actor</h3>', '<h3>Pre-run coverage report</h3>', '<h3>Residual</h3>', '<h3>Checks that read inconclusive</h3>', '<h3>Allowed-use controls not paired</h3>', '<h3>Observers not running or incomplete</h3>']) {
      const at = html.indexOf(part); assert.ok(at > section && at < end, `${name}: ${part} inside the one section`); assert.equal(count(html, part), 1, `${name}: ${part} once`);
    }
    assert.ok(html.indexOf('<h3>Pre-run coverage report</h3>') < html.indexOf('<h3>Residual</h3>'), `${name}: pre-run coverage first, then what the run did not show`);
    assert.ok(end < html.indexOf('<section class="limits">'), `${name}: before the limits`);
  }
  const cmp = renderComparisonReport(comparisonDocument(gapRun, gapAgain, compareRuns(gapRun, gapAgain)));
  assert.equal(count(cmp, '<h2>Coverage and residual</h2>'), 1); assert.equal(count(cmp, '<h2>Residual</h2>'), 0); assert.equal(count(cmp, '<h3>Residual</h3><ul><li>Candidate: Claims:'), 1);
  assert.ok(cmp.indexOf('<h2>Coverage and residual</h2>') < cmp.indexOf('<h3>Coverage: allowed-use controls per actor</h3>') && cmp.indexOf('<h3>Pre-run coverage report</h3>') < cmp.indexOf('<h3>Residual</h3>'));
  assert.ok(cmp.indexOf('<h3>Residual</h3>') < cmp.indexOf('<h2>Record custody</h2>') || !cmp.includes('<h2>Record custody</h2>'));
  // The one-page summary has no coverage part: its residual heading stays.
  const summary = renderSummary(gapRun, { residual: residualDocument(gapRun) });
  assert.equal(count(summary, '<h2>Residual</h2>'), 1); assert.ok(!summary.includes('Coverage and residual'));
});

test('coverage changes no verdict, count, comparison, gate input or hash, and is read by no verdict module', async t => {
  const src = name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
  for (const name of ['http-connector.mjs', 'contracts.mjs', 'runner.mjs', 'store.mjs', 'sarif.mjs', 'residual.mjs', 'allowed-use.mjs', 'channels.mjs', 'report.mjs']) assert.doesNotMatch(await src(name), /coverage-report\/coverage\.mjs/, `${name} imports nothing of the coverage report`);
  for (const name of ['http-connector.mjs', 'contracts.mjs', 'runner.mjs', 'store.mjs', 'sarif.mjs', 'residual.mjs', 'allowed-use.mjs', 'channels.mjs']) assert.doesNotMatch(await src(name), /coverageOf/, name);
  assert.doesNotMatch(/const evaluatorHash = digest\(\(await Promise\.all\(\[([^\]]+)\]/.exec(await src('http-connector.mjs'))[1], /report\.mjs|export-cli|coverage/);
  const w = await workspace(t), stored = await w.store.get(w.saved.gap.id), before = JSON.stringify(stored);
  const comparison = compareRuns(gapRun, gapAgain), snapshot = JSON.stringify(comparison);
  coverageOf(stored); renderReport(stored); renderReport(stored, { coverage: fullCoverage() });
  assert.equal(JSON.stringify(stored), before, 'the run is not changed'); assert.equal(JSON.stringify(compareRuns(gapRun, gapAgain)), snapshot, 'compareRuns is the same before and after');
  const plain = comparisonDocument(gapRun, gapAgain, comparison), full = comparisonDocument(gapRun, gapAgain, compareRuns(gapRun, gapAgain), { coverage: fullCoverage() });
  assert.equal(full.coverage.report.report.schema, 'scopehaven-coverage-report/1'); assert.equal(plain.coverage.report, null);
  const strip = doc => { const { coverage, ...rest } = doc; return rest; };
  assert.deepEqual(strip(full), strip(plain), 'the operator files change only the coverage block (a fresh compareRuns on the full side)'); assert.deepEqual([full.verdict, full.comparison.compatible], ['comparable-controls-passed', true]);
  assert.deepEqual(Object.keys(full).filter(k => !Object.keys(strip(full)).includes(k)), ['coverage'], 'the comparison document gains exactly one top-level key');
  // The gap does not touch the verdict: the defective twin's comparison is as comparable as the fixed twin's.
  assert.equal(comparisonDocument(fixedRun, fixedAgain, compareRuns(fixedRun, fixedAgain)).verdict, plain.verdict);
  // Exports: the run JSON is the record; the SARIF export is serializeSarif plus the one coverage property; the run's integrity hash is untouched.
  assert.equal(await w.exportText('run.json', { runId: w.saved.gap.id, format: 'json' }), `${JSON.stringify(stored, null, 2)}\n`);
  const sarif = JSON.parse(await w.exportText('run.sarif', { runId: w.saved.gap.id, format: 'sarif' })), expected = JSON.parse(serializeSarif(stored));
  assert.deepEqual(sarif.runs[0].properties.coverage, { actorsWithoutAllowedUse: ['guest'] }); delete sarif.runs[0].properties.coverage;
  assert.deepEqual(sarif, expected);
  const withFiles = JSON.parse(await w.exportText('cmp-full.json', { runId: w.saved.gapAgain.id, baselineRunId: w.saved.gap.id, format: 'json', ...w.flags() })), withoutFiles = JSON.parse(await w.exportText('cmp-plain.json', { runId: w.saved.gapAgain.id, baselineRunId: w.saved.gap.id, format: 'json' }));
  assert.deepEqual(strip(withFiles), strip(withoutFiles)); assert.equal((await w.store.get(w.saved.gap.id)).integrity.sha256, stored.integrity.sha256);
});
