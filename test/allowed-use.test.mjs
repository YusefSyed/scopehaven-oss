import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAssessment, compareRuns } from '../src/runner.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { createStore } from '../src/store.mjs';
import { startServer } from '../src/server.mjs';
import { SUITE, POLICY_HASH, FIXTURE_HASH } from '../src/suite.mjs';
import { renderReport, comparisonDocument, renderComparisonReport } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { exportRun } from '../src/export-cli.mjs';
import { allowedUse, allowedUseLabel, overBlockingPercent, comparisonAllowedUse, ALLOWED_USE_LIMITS } from '../src/allowed-use.mjs';
import { baselineRecord } from '../integrations/github-action/prepare.mjs';

// Owned synthetic fixture and one owned 127.0.0.1 HTTP server only. No model,
// provider, hosted service or real credential; files stay in private temp dirs.
const vulnerable = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const copy = value => structuredClone(value);
const CONTROL_IDS = SUITE.checks.filter(check => check.severity === 'control').map(check => check.id);
// Counts come from the current suite, so a suite change does not need a test edit here.
const N = CONTROL_IDS.length;
const escape = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const KEYS = ['controlsTotal', 'controlsPassed', 'controlsFailed', 'controlsInconclusive', 'controlsPossiblyOverBlocked', 'overBlockingRate', 'basis', 'meaning'];
async function dir(t) { const d = await mkdtemp(join(tmpdir(), 'scopehaven-allowed-use-')); t.after(() => rm(d, { recursive: true, force: true })); return d; }
// Remove only the added allowed-use HTML so the rest can be compared byte for byte.
const stripRunHtml = html => html.replace(/<p>Allowed use: [^<]*<small>[^<]*<\/small><\/p>/, '');
const stripComparisonHtml = html => html.replace(/<p>Candidate: Allowed use: .*?<\/small><\/p>/, '');

test('synthetic demo runs: every control passes in both, so over-blocking is 0%', () => {
  assert(N > 0);
  for (const run of [vulnerable, repaired]) {
    assert.deepEqual(run.requiredControlIds, CONTROL_IDS);
    const summary = allowedUse(run);
    assert.deepEqual(Object.keys(summary), KEYS);
    assert.deepEqual({ ...summary, meaning: undefined }, { controlsTotal: N, controlsPassed: N, controlsFailed: 0, controlsInconclusive: 0, controlsPossiblyOverBlocked: 0, overBlockingRate: 0, basis: 'requiredControlIds', meaning: undefined });
    assert.equal(allowedUseLabel(summary), `Allowed use: ${N} of ${N} allowed actions still work (over-blocking 0%). ${ALLOWED_USE_LIMITS}`);
  }
  // Older synthetic runs without requiredControlIds fall back to severity "control".
  const legacy = copy(repaired); delete legacy.requiredControlIds;
  assert.equal(allowedUse(legacy).basis, 'severity-control'); assert.equal(allowedUse(legacy).controlsPassed, N);
});

test('a failed control is over-blocking; inconclusive and error controls are reported separately', () => {
  const run = copy(repaired);
  run.results.find(row => row.id === 'FIELD-02').status = 'fail';
  run.results.find(row => row.id === 'FLOW-02').status = 'inconclusive';
  run.results.find(row => row.id === 'BUDGET-02').status = 'error';
  const summary = allowedUse(run);
  const percent = `${(100 / N).toFixed(1)}%`;
  assert.equal(summary.controlsTotal, N); assert.equal(summary.controlsPassed, N - 3); assert.equal(summary.controlsFailed, 1); assert.equal(summary.controlsInconclusive, 2);
  assert.equal(summary.overBlockingRate, 1 / N, 'exact value is stored');
  assert.equal(overBlockingPercent(summary.overBlockingRate), percent);
  assert.equal(allowedUseLabel(summary), `Allowed use: ${N - 3} of ${N} allowed actions still work (over-blocking ${percent}; 2 inconclusive, not counted as over-blocking). ${ALLOWED_USE_LIMITS}`);
  assert.match(renderReport(run), new RegExp(escape(`Allowed use: ${N - 3} of ${N} allowed actions still work (over-blocking ${percent}; 2 inconclusive`)));
  assert.equal(renderSarif(run).runs[0].properties.allowedUse.controlsFailed, 1);
  // Comparison: the regression is listed, and the core comparison is unchanged.
  const core = compareRuns(repaired, run), before = JSON.stringify(core);
  const doc = comparisonDocument(repaired, run, core);
  assert.equal(JSON.stringify(core), before, 'compareRuns output is not mutated');
  assert.deepEqual(doc.allowedUse.newlyOverBlocked, ['FIELD-02']);
  assert.equal(doc.allowedUse.candidate.controlsFailed, 1); assert.equal(doc.allowedUse.baseline.controlsFailed, 0);
  assert.equal(doc.verdict, 'not-verified'); assert.equal(doc.comparison.controlsPass, false);
  assert.match(renderComparisonReport(doc), /Newly over-blocked controls \(pass in baseline, fail in candidate[^)]*\): FIELD-02\./);
});

test('zero controls report a null rate and say over-blocking is not measured', () => {
  const run = copy(repaired); run.requiredControlIds = [];
  const summary = allowedUse(run);
  assert.equal(summary.controlsTotal, 0); assert.equal(summary.overBlockingRate, null);
  assert.equal(overBlockingPercent(null), null);
  assert.match(renderReport(run), /this run has no allowed-use controls, so over-blocking is not measured/);
  assert.equal(renderSarif(run).runs[0].properties.allowedUse.overBlockingRate, null);
  const none = copy(repaired); delete none.requiredControlIds; none.results = none.results.filter(row => row.severity !== 'control');
  assert.equal(allowedUse(none).controlsTotal, 0); assert.equal(allowedUse(none).overBlockingRate, null);
});

test('HTTP runs use requiredControlIds, not every control-severity check', async t => {
  let blocked = false;
  const instance = createServer((req, res) => {
    const send = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    if (req.url === '/own') return blocked ? send(403, {}) : send(200, { record: true });
    if (req.url === '/optional') return send(500, {});
    return send(403, {});
  });
  await new Promise((resolve, reject) => { instance.once('error', reject); instance.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => { instance.close(resolve); instance.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${instance.address().port}`;
  const target = { id: 'allowed-lab', name: 'Allowed-use lab', applicationId: 'allowed-lab-app', origin, buildLabel: 'baseline', contextId: 'synthetic-data',
    actors: { anonymous: { principalId: 'anonymous' } }, requiredControlIds: ['allowed'], checks: [
      { id: 'allowed', title: 'Permitted response', category: 'Access', severity: 'control', actorId: 'anonymous', method: 'GET', path: '/own', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'optional', title: 'Optional permitted response', category: 'Access', severity: 'control', actorId: 'anonymous', method: 'GET', path: '/optional', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'denied', title: 'Restricted response', category: 'Access', severity: 'high', actorId: 'anonymous', method: 'GET', path: '/foreign', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
    ] };
  const baseline = await runHttpAssessment(target, { env: {} });
  assert.equal(baseline.evidenceOrigin, 'local-http-response'); assert.deepEqual(baseline.requiredControlIds, ['allowed']);
  assert.equal(baseline.results.find(row => row.id === 'optional').status, 'fail', 'a non-required control fails');
  assert.deepEqual({ ...allowedUse(baseline), meaning: undefined }, { controlsTotal: 1, controlsPassed: 1, controlsFailed: 0, controlsInconclusive: 0, controlsPossiblyOverBlocked: 0, overBlockingRate: 0, basis: 'requiredControlIds', meaning: undefined });
  blocked = true;
  const candidate = await runHttpAssessment({ ...target, buildLabel: 'over-blocked' }, { env: {} });
  assert.equal(allowedUse(candidate).overBlockingRate, 1);
  assert.match(renderReport(candidate), /Allowed use: 0 of 1 allowed actions still work \(over-blocking 100%\)/);
  const core = compareRuns(baseline, candidate);
  assert.equal(core.controlsPass, false);
  const doc = comparisonDocument(baseline, candidate, core);
  assert.deepEqual(doc.allowedUse.newlyOverBlocked, ['allowed']); assert.equal(doc.allowedUse.comparable, core.compatible);
  assert.deepEqual(comparisonAllowedUse(baseline, candidate, core), doc.allowedUse);
});

test('additions leave every existing field, verdict and identity unchanged', () => {
  for (const run of [vulnerable, repaired]) {
    const before = JSON.stringify(run); allowedUse(run); renderReport(run); renderSarif(run);
    assert.equal(JSON.stringify(run), before, 'the run object is never mutated');
    assert.equal(run.suiteHash, SUITE.hash); assert.equal(run.policyHash, POLICY_HASH); assert.equal(run.fixtureHash, FIXTURE_HASH);
    // SARIF: only run.properties.allowedUse is new; no results or rules are added.
    const sarif = renderSarif(run).runs[0];
    assert.equal(sarif.results.length, run.results.length); assert.equal(sarif.tool.driver.rules.length, run.results.length);
    const props = Object.keys(sarif.properties);
    assert.equal(props[props.indexOf('counts') + 1], 'allowedUse');
    assert.deepEqual(sarif.properties.allowedUse, allowedUse(run));
  }
  const core = compareRuns(vulnerable, repaired), before = JSON.stringify(core);
  const doc = comparisonDocument(vulnerable, repaired, core);
  assert.equal(JSON.stringify(core), before);
  assert.equal(doc.verdict, 'comparable-controls-passed'); assert.equal(doc.comparison.summary.fixed, vulnerable.counts.fail);
  assert.deepEqual(doc.allowedUse.newlyOverBlocked, []); assert.equal(doc.allowedUse.candidate.overBlockingRate, 0); assert.equal(doc.allowedUse.comparable, true);
  // The typed claims and the residual (src/residual.mjs) join the document beside allowedUse; the core keys are unchanged.
  const { allowedUse: added, claims, residual, coverage, ...rest } = doc;
  assert.deepEqual(Object.keys(rest), ['schemaVersion', 'document', 'certification', 'interpretation', 'verdict', 'baseline', 'candidate', 'comparison']);
  assert.match(renderComparisonReport(doc), /No allowed-use control went from pass to fail\./);
  // The HTML additions are one paragraph each; everything else is unchanged.
  assert.equal(stripRunHtml(renderReport(repaired)).includes('Allowed use:'), false);
  assert.equal(stripComparisonHtml(renderComparisonReport(doc)).includes('Allowed use:'), false);
  assert.equal(stripComparisonHtml(renderComparisonReport(doc)), stripComparisonHtml(renderComparisonReport({ ...doc, allowedUse: undefined })));
  assert.match(renderReport(repaired), /inconclusive controls are not counted\. It is not a security score\. <small>Measures whether permitted users can still do permitted things\.<\/small>/);
});

test('SARIF, HTML and comparison exports carry allowedUse; the single-run JSON export stays byte-identical and re-importable', async t => {
  const root = await dir(t), data = join(root, 'store'), out = join(root, 'exports');
  await mkdir(out, { mode: 0o700 });
  const store = createStore(data); await store.ready;
  const baseline = await store.save(copy(vulnerable)), candidate = await store.save(copy(repaired));
  await exportRun({ runId: candidate.id, format: 'json', outputFile: join(out, 'run.json'), dataDir: data });
  await exportRun({ runId: candidate.id, format: 'sarif', outputFile: join(out, 'run.sarif'), dataDir: data });
  await exportRun({ runId: candidate.id, format: 'html', outputFile: join(out, 'run.html'), dataDir: data });
  await exportRun({ runId: candidate.id, baselineRunId: baseline.id, format: 'json', outputFile: join(out, 'cmp.json'), dataDir: data });
  await exportRun({ runId: candidate.id, baselineRunId: baseline.id, format: 'html', outputFile: join(out, 'cmp.html'), dataDir: data });
  // The run export is re-imported as a CI baseline by hashing every field except
  // integrity and notes, so it must not gain fields.
  const runText = await readFile(join(out, 'run.json'), 'utf8');
  assert.equal(runText, JSON.stringify(candidate, null, 2) + '\n');
  assert.equal(Object.hasOwn(JSON.parse(runText), 'allowedUse'), false);
  assert.equal(baselineRecord(JSON.parse(runText)).sha256, candidate.integrity.sha256);
  const sarifProps = JSON.parse(await readFile(join(out, 'run.sarif'), 'utf8')).runs[0].properties;
  assert.equal(sarifProps.allowedUse.controlsPassed, N); assert.equal(sarifProps.allowedUse.overBlockingRate, 0);
  assert.match(await readFile(join(out, 'run.html'), 'utf8'), new RegExp(escape(`Allowed use: ${N} of ${N} allowed actions still work (over-blocking 0%)`)));
  const cmp = JSON.parse(await readFile(join(out, 'cmp.json'), 'utf8'));
  assert.deepEqual(cmp.allowedUse.newlyOverBlocked, []); assert.equal(cmp.allowedUse.candidate.controlsTotal, N); assert.equal(cmp.verdict, 'comparable-controls-passed');
  assert.match(await readFile(join(out, 'cmp.html'), 'utf8'), new RegExp(`Candidate: Allowed use: ${N} of ${N} allowed actions still work`));

  const app = await startServer({ port: 0, dataDir: data, env: {} }); t.after(() => app.close());
  const headers = { Authorization: `Bearer ${app.accessToken}` };
  const download = await (await fetch(`${app.origin}/api/runs/${candidate.id}/export.json`, { headers })).json();
  assert.equal(Object.hasOwn(download, 'allowedUse'), false); assert.equal(baselineRecord(download).sha256, candidate.integrity.sha256);
  assert.match(await (await fetch(`${app.origin}/api/runs/${candidate.id}/report.html`, { headers })).text(), new RegExp(`Allowed use: ${N} of ${N} allowed actions still work`));
});

// A control answered with its declared status but a reply that is not a declared success (a control's claim rules
// declare success only, so an honest refusal reads ambiguous): inconclusive, reported as possibly over-blocked, never in the rate.
test('an inconclusive control whose status matched but whose claim was not a declared success is reported as possibly over-blocked', async () => {
  const sel = { source: 'http-egress', operation: 'send', name: 'payments.example.test' };
  const said = { trigger: { text: { pointer: '/reply', success: ['refund has been issued'] } }, select: sel };
  const observerFactory = configs => configs.map(c => { let mark = 0; return { kind: 'http-egress-recorder', instanceId: `${c.type}-${c.id}`, source: 'http-egress',
    scope: { operations: ['send'], names: ['payments.example.test'], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
    async start() {}, async stop() {}, async mark() { return { at: ++mark }; }, async collect() { return { events: [], coverage: 'complete', reason: null }; } }; });
  const profile = { id: 'refunds', name: 'Refunds', applicationId: 'refunds', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { u: { principalId: 'u-1' } },
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40998, routing: 'proxy', destinations: [{ host: 'payments.example.test' }], witness: { actorId: 'u', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 }],
    requiredControlIds: ['C', 'D'], checks: [
      { id: 'C', title: 'Refund own order', category: 'x', severity: 'control', actorId: 'u', method: 'POST', path: '/orders/1/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], claims: [said] },
      { id: 'D', title: 'Read own order', category: 'x', severity: 'control', actorId: 'u', method: 'GET', path: '/orders/1', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] };
  const run = await runHttpAssessment(profile, { env: {}, observerFactory, transport: async (origin, c) => ({ status: 200, complete: true, jsonParsed: true, json: c.path === '/orders/1/refund' ? { reply: 'Cannot issue a refund.' } : {}, bytes: 2 }) });
  assert.equal(run.results.find(r => r.id === 'C').status, 'inconclusive');
  const summary = allowedUse(run);
  assert.deepEqual({ ...summary, meaning: undefined }, { controlsTotal: 2, controlsPassed: 1, controlsFailed: 0, controlsInconclusive: 1, controlsPossiblyOverBlocked: 1, overBlockingRate: 0, basis: 'requiredControlIds', meaning: undefined });
  assert.equal(allowedUseLabel(summary), `Allowed use: 1 of 2 allowed actions still work (over-blocking 0%; 1 inconclusive, not counted as over-blocking, 1 of them answered without a declared success and may have been refused). ${ALLOWED_USE_LIMITS}`);
  // An inconclusive control without that reading (here a status that did not match) is inconclusive only.
  const other = structuredClone(run), row = other.results.find(r => r.id === 'C');
  row.assertions.find(a => a.name === 'HTTP status matches contract').status = 'fail';
  assert.equal(allowedUse(other).controlsPossiblyOverBlocked, 0);
});
