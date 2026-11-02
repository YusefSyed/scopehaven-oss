import test from 'node:test';
import assert from 'node:assert/strict';
import { runAssessment, compareRuns } from '../src/runner.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { renderReport, comparisonDocument, renderComparisonReport } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { allowedUseLabel } from '../src/allowed-use.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { createHttpLab, makeLabProfile } from '../examples/http-lab.mjs';

// Product output wording (productOutputWording):
// every allowed-use number carries its stated limits, a restoration count never says
// "fixed" outside the owned synthetic fixture and always travels with its scope
// description (in the gate summary, evidenceScope), and the SARIF tool
// description says nothing beyond its approved sentence.
// Owned synthetic fixture and owned loopback lab only.
const LIMITS = 'Counts only the declared allowed-use controls; inconclusive controls are not counted. It is not a security score.';
const RESPONSE_SCOPE = 'Response comparison only; backend effects remain unverified.';
const vulnerable = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');

async function labPair(t) {
  const lab = await createHttpLab({ build: 'baseline' }); t.after(() => lab.close());
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken };
  const before = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-baseline'), { env });
  lab.setBuild('repaired');
  const after = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-repaired'), { env });
  return { before, after };
}

test('the allowed-use label keeps the approved wording and carries its limits everywhere it is printed', () => {
  const label = allowedUseLabel({ controlsPassed: 9, controlsTotal: 9, overBlockingRate: 0, controlsInconclusive: 0 });
  assert.equal(label, `Allowed use: 9 of 9 allowed actions still work (over-blocking 0%). ${LIMITS}`);
  const partial = allowedUseLabel({ controlsPassed: 7, controlsTotal: 9, overBlockingRate: 1 / 9, controlsInconclusive: 1 });
  assert.match(partial, /^Allowed use: 7 of 9 allowed actions still work \(over-blocking [\d.]+%; 1 inconclusive, not counted as over-blocking\)\. Counts only/);
  assert.ok(partial.endsWith(LIMITS));
  const html = renderReport(repaired);
  assert.ok(html.includes(`allowed actions still work (over-blocking 0%). ${LIMITS}`), 'run report');
  const doc = comparisonDocument(vulnerable, repaired, compareRuns(vulnerable, repaired));
  assert.ok(renderComparisonReport(doc).includes(`(over-blocking 0%). ${LIMITS}`), 'comparison report');
  for (const side of ['baseline', 'candidate']) assert.ok(doc.allowedUse[side].meaning.endsWith(LIMITS), `comparison JSON ${side}`);
  assert.ok(renderSarif(repaired).runs[0].properties.allowedUse.meaning.endsWith(LIMITS), 'SARIF');
});

test('a restoration count prints its scope description, never "counted as fixed"; "fixed" stays with the synthetic fixture', async t => {
  const { before, after } = await labPair(t);
  const comparison = compareRuns(before, after);
  const doc = comparisonDocument(before, after, comparison);
  // The lab pair keeps one deliberately unverifiable row (fail to inconclusive), so the comparison is incomplete: it
  // restores a row but carries no repair label, as the gate's comparison-incomplete says.
  assert.ok(comparison.summary.fixed > 0 && comparison.summary.unverified > 0);
  assert.equal(doc.comparison.restorationLabel, 'No verified repair');
  assert.equal(doc.comparison.restorationDescription, RESPONSE_SCOPE);
  const html = renderComparisonReport(doc);
  assert.match(html, new RegExp(`<p>${comparison.summary.fixed} restored\\. No verified repair: this pair restored nothing, introduced a new failure, or left rows unverified or not applicable\\. · `));
  assert.doesNotMatch(html, /counted as fixed/i);
  // A complete response-level restoration prints its scoped label with the scope description.
  const complete = { ...doc, comparison: { ...doc.comparison, restorationLabel: 'Response contracts restored' } };
  assert.match(renderComparisonReport(complete), new RegExp(`<p>${comparison.summary.fixed} Response contracts restored\\. Response comparison only; backend effects remain unverified\\. · `));
  // The gate summary prints the runner's label and its scope description (evidenceScope) beside it.
  const gate = summarizeGate({ candidate: after, baseline: before, comparison });
  assert.equal(gate.comparison.restorationLabel, 'No verified repair');
  assert.ok(gate.reasons.includes('comparison-incomplete'));
  assert.equal(gate.comparison.evidenceScope, RESPONSE_SCOPE);
  const synthetic = renderComparisonReport(comparisonDocument(vulnerable, repaired, compareRuns(vulnerable, repaired)));
  assert.match(synthetic, /<p>\d+ fixed · /); assert.doesNotMatch(synthetic, /counted as fixed/i);
  const mixed = compareRuns(vulnerable, after);
  const mixedHtml = renderComparisonReport(comparisonDocument(vulnerable, after, mixed));
  assert.match(mixedHtml, /<p>0 Unverified changes · /); assert.doesNotMatch(mixedHtml, /counted as fixed/i);
});

test('an observed-backend restoration prints its own scoped label', () => {
  const base = comparisonDocument(repaired, repaired, compareRuns(repaired, repaired));
  const observed = { ...base, comparison: { ...base.comparison, restorationLabel: 'Response contracts restored; backend observed where marked',
    restorationDescription: 'Response contracts plus authoritative backend observation for rows marked observed; other backend effects remain unverified.' } };
  assert.match(renderComparisonReport(observed), /<p>\d+ Response contracts restored; backend observed where marked\. · /);
});

test('the SARIF tool description is the approved sentence', () => {
  const driver = renderSarif(repaired).runs[0].tool.driver;
  assert.equal(driver.name, 'Scopehaven');
  assert.equal(driver.fullName, 'Scopehaven: local checks that an AI agent stays inside its permissions and that a fix keeps allowed work working');
});
