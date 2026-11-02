// Scheduled re-runs with a drift summary. Owned synthetic fixture only (the
// built-in demo targets); no model, provider, customer system or network. The local runner runs
// in a private temporary directory; the workflow and launchd template are checked as text.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { runAssessment } from '../../src/runner.mjs';
import { summarizeGate } from '../regression-gate/gate.mjs';
import { driftOf, driftMarkdown, DRIFT_STATUSES } from './drift.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
let repaired, repairedAgain, vulnerable;
test.before(async () => { [repaired, repairedAgain, vulnerable] = [await runAssessment('demo-repaired'), await runAssessment('demo-repaired'), await runAssessment('demo-vulnerable')]; });

test('a planted regression reads regression with exit 1; an unchanged run reads no change, never fixed', () => {
  const regression = driftOf(summarizeGate({ candidate: vulnerable, baseline: repaired }));
  assert.deepEqual([regression.status, regression.exitCode, regression.regressed], ['regression', 1, 26]);
  assert.match(driftMarkdown(regression), /\*\*Regression:\*\* 26 checks regressed since the last successful run\./);
  const same = driftOf(summarizeGate({ candidate: repairedAgain, baseline: repaired }));
  assert.deepEqual([same.status, same.exitCode, same.restored, same.regressed], ['no-change', 0, 0, 0]);
  assert.doesNotMatch(driftMarkdown(same), /fixed|restored|improved/i);
  assert.match(driftMarkdown(same), /\*\*No change\*\* since the last successful run\./);
  // The reverse direction is an improvement, named by the comparison's own label.
  const better = driftOf(summarizeGate({ candidate: repairedAgain, baseline: vulnerable }));
  assert.deepEqual([better.status, better.exitCode, better.restored], ['improved', 0, 26]);
  assert.match(driftMarkdown(better), /\*\*Improved:\*\* 26 checks labelled "Fixed"/);
});

test('every other gate outcome has its own status, and nothing unreadable reads as no change', () => {
  assert.deepEqual([driftOf(summarizeGate({ candidate: repaired })).status, driftOf(summarizeGate({ candidate: repaired })).exitCode], ['no-baseline', 0]);
  const needsReview = { schemaVersion: 1, outcome: 'assessment-failed', exitCode: 1, reasons: ['comparison-incomplete'], current: { runId: 'r2', targetId: 't', counts: null },
    comparison: { requested: true, baselineRunId: 'r1', compatibility: 'compatible', labels: { preserved: 3, unverified: 1 } } };
  assert.deepEqual([driftOf(needsReview).status, driftOf(needsReview).exitCode], ['needs-review', 1]);
  const incomparable = { ...needsReview, comparison: { ...needsReview.comparison, compatibility: 'incompatible' } };
  assert.deepEqual([driftOf(incomparable).status, driftOf(incomparable).exitCode], ['incomparable', 2]);
  assert.deepEqual([driftOf({ schemaVersion: 1, exitCode: 2, reasons: ['unknown-target'] }).status, driftOf({ schemaVersion: 1, exitCode: 2, reasons: ['unknown-target'] }).exitCode], ['error', 2]);
  for (const odd of [null, {}, 'text', { schemaVersion: 1, exitCode: 7 }]) assert.deepEqual([driftOf(odd).status, driftOf(odd).exitCode], ['error', 2], JSON.stringify(odd));
  // A regression outranks an improvement in the same run.
  const mixed = { ...needsReview, comparison: { ...needsReview.comparison, labels: { fixed: 2, regression: 1 } } };
  assert.equal(driftOf(mixed).status, 'regression');
  for (const status of DRIFT_STATUSES) assert.doesNotMatch(driftMarkdown(status === 'error' ? { status, reason: 'x' } : { status, restored: 1, regressed: 1, needsReview: 1 }), /\b(secure|certif|guarantee)/i, status);
});

test('the local runner keeps a private baseline, writes the summary there, and keeps a regressed run out of it', t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven drift ')), data = join(dir, 'drift');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const run = target => spawnSync('bash', [join(here, 'run-local.sh'), target], { encoding: 'utf8', timeout: 120000,
    env: { PATH: process.env.PATH, HOME: dir, SCOPEHAVEN_NODE: process.execPath, SCOPEHAVEN_DRIFT_DIR: data } });
  const headline = () => readFileSync(join(data, 'latest-drift.md'), 'utf8').split('\n')[2];
  const baselineId = () => JSON.parse(readFileSync(join(data, 'last-run.json'), 'utf8')).core?.id ?? JSON.parse(readFileSync(join(data, 'last-run.json'), 'utf8')).id;
  let r = run('demo-repaired');
  assert.equal(r.status, 0, r.stderr); assert.match(headline(), /No baseline yet/);
  const first = baselineId();
  r = run('demo-repaired');
  assert.equal(r.status, 0, r.stderr); assert.match(headline(), /No change/);
  const second = baselineId();
  assert.notEqual(second, first, 'an unchanged run becomes the next baseline');
  r = run('demo-vulnerable');
  assert.equal(r.status, 1, r.stderr); assert.match(headline(), /^\*\*Regression:\*\* 26 checks regressed/);
  assert.equal(baselineId(), second, 'a regressed run is never kept as the baseline');
  r = run('demo-repaired');
  assert.equal(r.status, 0, r.stderr); assert.match(headline(), /No change/);
  for (const path of [data, join(data, 'last-run.json'), join(data, 'latest-drift.md')]) assert.equal(statSync(path).mode & 0o077, 0, `${path} is private`);
  const other = run('payments-prod');
  assert.equal(other.status, 2); assert.match(other.stderr, /runs a built-in target/, 'only a built-in target');
  assert.ok(!existsSync(join(dir, 'Library')), 'nothing is written outside the drift directory');
});

test('the scheduled workflow and the launchd template: schedule and dispatch, read-only, pinned, no secrets and no sends', () => {
  const workflow = readFileSync(join(here, '../../.github/workflows/scopehaven-drift.yml'), 'utf8');
  assert.match(workflow, /\n  schedule:\n    - cron: '[0-9*, ]+'\n/);
  assert.match(workflow, /\n  workflow_dispatch:\n/);
  assert.match(workflow, /\npermissions:\n  contents: read\n\n/);
  for (const uses of workflow.match(/uses: [^\n]+/g)) assert.match(uses, /@[0-9a-f]{40} # v\d+$/, uses);
  assert.doesNotMatch(workflow, /secrets\.|curl|wget|sendmail|smtp|slack|webhook|discord|https?:\/\//i);
  // Inputs reach the run step only through env, never interpolated into the script.
  const runBlock = workflow.slice(workflow.indexOf('        run: |'), workflow.indexOf('      - name: Keep this run'));
  assert.doesNotMatch(runBlock, /\$\{\{/);
  const script = readFileSync(join(here, 'run-local.sh'), 'utf8');
  assert.match(script, /\numask 077\n/);
  assert.doesNotMatch(script, /curl|wget|\bnc\b|sendmail|mail -s|osascript|https?:\/\//);
  const plist = readFileSync(join(here, 'com.scopehaven.drift.plist.template'), 'utf8');
  assert.match(plist, /<key>Label<\/key>\s*<string>com\.scopehaven\.drift<\/string>/);
  assert.match(plist, /<key>Umask<\/key>\s*<integer>63<\/integer>/, 'umask 077');
  assert.match(plist, /__SCOPEHAVEN_ROOT__\/integrations\/schedule\/run-local\.sh/);
  assert.deepEqual(plist.match(/https?:\/\/[^\s"]+/g), ['http://www.apple.com/DTDs/PropertyList-1.0.dtd'], 'only the plist DTD');
});
