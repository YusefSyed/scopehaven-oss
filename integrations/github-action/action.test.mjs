// Local tests for the Scopehaven GitHub Action. node:test, zero dependencies.
// Everything binds 127.0.0.1: the owned synthetic HTTP lab runs in-process and
// the action's bash steps are executed by a small local harness. `uses:` steps
// (setup-node, upload-artifact, upload-sarif) are not executed: nothing is
// uploaded, downloaded or sent, and no provider is called.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readdir, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { createModelTap, TapLog } from '../model-identity/tap.mjs';
import { OWNED_TAP_ENV } from '../../src/http-model-identity.mjs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHttpLab, makeLabProfile, makeLabAuthorization } from '../../examples/http-lab.mjs';
import { writeTestAuthorization } from '../../test/support/authorization.mjs';
import { checksumAuthorization } from '../../src/authorization.mjs';
import { buildReport, decide, decideReportOnly, escapeCell, normalizeGate, normalizeRun } from './summary.mjs';
import { buildMatrix, canonical, diffMatrices, sha256 } from '../policy-import/matrix.mjs';
import { parseLoopbackUrl, parseUntil, waitFor } from './wait-for.mjs';
import { GATE_MARKER, GATE_MARKER_TEXT, baselineRecord } from './prepare.mjs';
import { lockProfile } from '../packs-v2/expand.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const node = process.execPath;
const FAKE_SECRET = 'fake-target-secret-7Q2xVb9LmN4p';
const run = (file, args, options = {}) => new Promise(done => {
  execFile(file, args, { encoding: 'utf8', timeout: 60000, ...options }, (error, stdout, stderr) => done({ code: error ? (typeof error.code === 'number' ? error.code : -1) : 0, stdout, stderr }));
});

// ---- Minimal YAML subset parser (maps, lists of maps, block scalars, quoted scalars). ----
function scalar(text) {
  const value = text.trim();
  if (value.startsWith("'") && value.endsWith("'")) return value.slice(1, -1).replace(/''/g, "'");
  if (value.startsWith('"') && value.endsWith('"')) return JSON.parse(value);
  return value;
}
export function parseYamlSubset(source) {
  const lines = source.split('\n').map(raw => ({ raw, indent: raw.search(/\S/), text: raw.trim() }))
    .filter(line => line.indent >= 0 && !line.text.startsWith('#'));
  let i = 0;
  function block(indent) {
    if (i < lines.length && lines[i].indent === indent && lines[i].text.startsWith('- ')) {
      const list = [];
      while (i < lines.length && lines[i].indent === indent && lines[i].text.startsWith('- ')) {
        const line = lines[i];
        lines[i] = { raw: line.raw, indent: indent + 2, text: line.text.slice(2) };
        list.push(map(indent + 2));
      }
      return list;
    }
    return map(indent);
  }
  function map(indent) {
    const out = {};
    while (i < lines.length && lines[i].indent === indent && !lines[i].text.startsWith('- ')) {
      const { text } = lines[i];
      const match = /^([A-Za-z0-9_-]+):(?: (.*))?$/.exec(text);
      if (!match) throw new Error(`Unsupported YAML line: ${text}`);
      const [, key, rest = ''] = match;
      if (Object.hasOwn(out, key)) throw new Error(`Duplicate key ${key}`);
      i += 1;
      if (rest === '|') {
        const body = [];
        while (i < lines.length && lines[i].indent > indent) { body.push(lines[i].raw); i += 1; }
        const strip = Math.min(...body.filter(line => line.trim()).map(line => line.search(/\S/)));
        out[key] = body.map(line => line.slice(strip)).join('\n') + '\n';
      } else if (rest === '') out[key] = i < lines.length && lines[i].indent > indent ? block(lines[i].indent) : '';
      else out[key] = scalar(rest);
    }
    return out;
  }
  const result = block(0);
  if (i !== lines.length) throw new Error(`Unparsed YAML from line: ${lines[i].text}`);
  return result;
}

const actionText = await readFile(join(here, 'action.yml'), 'utf8');
const action = parseYamlSubset(actionText);
const launcherText = await readFile(join(here, '../../scopehaven'), 'utf8');

// ---- Local harness: evaluates ${{ inputs.* }} / ${{ steps.*.outputs.* }} / ${{ steps.*.outcome }} and runs bash steps. ----
function parseOutputs(text) {
  return Object.fromEntries(text.split('\n').filter(Boolean).map(line => { const at = line.indexOf('='); return [line.slice(0, at), line.slice(at + 1)]; }));
}
async function runAction(inputs, { workspace, runnerTemp, env }) {
  const values = Object.fromEntries(Object.entries(action.inputs).map(([key, spec]) => [key, spec.default ?? '']));
  Object.assign(values, inputs);
  const steps = {}, logs = [];
  const evaluate = text => String(text).replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_, expression) => {
    let match;
    if ((match = /^inputs\.([A-Za-z0-9_-]+)$/.exec(expression))) return values[match[1]] ?? '';
    if ((match = /^steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)$/.exec(expression))) return steps[match[1]]?.outputs?.[match[2]] ?? '';
    if ((match = /^steps\.([A-Za-z0-9_-]+)\.outcome$/.exec(expression))) return steps[match[1]]?.outcome ?? '';
    throw new Error(`Unsupported expression in a run step: ${expression}`);
  });
  const summaryFile = join(runnerTemp, `step-summary-${Date.now()}.md`);
  await writeFile(summaryFile, '');
  let failed = false, index = 0;
  for (const step of action.runs.steps) {
    index += 1;
    if (step.uses) { if (step.id) steps[step.id] = { outcome: 'skipped', outputs: {} }; continue; }
    if (step.if && step.if !== 'always()') throw new Error(`Harness supports only always() on run steps: ${step.name}`);
    if (failed && step.if !== 'always()') { if (step.id) steps[step.id] = { outcome: 'skipped', outputs: {} }; continue; }
    const outputFile = join(runnerTemp, `output-${index}-${Date.now()}`), script = join(runnerTemp, `step-${index}.sh`);
    await writeFile(outputFile, ''); await writeFile(script, step.run);
    const stepEnv = Object.fromEntries(Object.entries(step.env || {}).map(([key, value]) => [key, evaluate(value)]));
    const cwd = resolve(workspace, step['working-directory'] ? evaluate(step['working-directory']) : '.');
    const result = await run('bash', ['--noprofile', '--norc', '-eo', 'pipefail', script], { cwd,
      env: { ...env, ...stepEnv, GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: summaryFile, GITHUB_ACTION_PATH: here, GITHUB_WORKSPACE: workspace, RUNNER_TEMP: runnerTemp } });
    const outcome = result.code === 0 ? 'success' : 'failure';
    if (outcome === 'failure') failed = true;
    logs.push({ name: step.name, ...result });
    if (step.id) steps[step.id] = { outcome, outputs: parseOutputs(await readFile(outputFile, 'utf8')) };
    else steps[`#${index}`] = { outcome, outputs: {} };
  }
  const outputs = Object.fromEntries(Object.entries(action.outputs).map(([key, spec]) => [key, evaluate(spec.value)]));
  return { outputs, steps, logs, failed, summary: await readFile(summaryFile, 'utf8') };
}
// One run step on its own, with the given environment (the export step's marking is tested this way).
async function runStep(id, env) {
  const step = action.runs.steps.find(entry => entry.id === id), stamp = `${id}-${Date.now()}`;
  const script = join(runnerTemp, `step-${stamp}.sh`), outputFile = join(runnerTemp, `output-${stamp}`);
  await writeFile(script, step.run); await writeFile(outputFile, '');
  const result = await run('bash', ['--noprofile', '--norc', '-eo', 'pipefail', script], { timeout: 300000, env: { ...baseEnv, ...env, GITHUB_OUTPUT: outputFile, GITHUB_ACTION_PATH: here } });
  return { ...result, outputs: parseOutputs(await readFile(outputFile, 'utf8')) };
}
async function allFiles(directory) {
  const found = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...await allFiles(path)); else found.push(path);
  }
  return found;
}

let lab, scratch, workspace, runnerTemp, baseEnv, firstRun;
before(async () => {
  scratch = await mkdtemp(join(tmpdir(), 'scopehaven-action-test-'));
  await chmod(scratch, 0o700);
  workspace = join(scratch, 'workspace'); runnerTemp = join(scratch, 'runner-temp');
  await mkdir(join(workspace, 'profiles'), { recursive: true, mode: 0o700 }); await mkdir(runnerTemp, { mode: 0o700 });
  lab = await createHttpLab({ build: 'baseline' });
  await writeFile(join(workspace, 'profiles/lab-baseline.json'), JSON.stringify({ schemaVersion: 1, targets: [makeLabProfile(lab.origin, 'lab-baseline')] }));
  await writeFile(join(workspace, 'profiles/lab-repaired.json'), JSON.stringify({ schemaVersion: 1, targets: [makeLabProfile(lab.origin, 'lab-repaired')] }));
  // The lab's own authorization record covers these runs, as `./scopehaven lab` writes it.
  await writeFile(join(workspace, 'profiles/lab.authorization.json'), JSON.stringify(makeLabAuthorization(lab.origin)));
  // Minimal environment: the pinned node first on PATH (setup-node's role on GitHub), the launcher pinned via SCOPEHAVEN_NODE.
  baseEnv = { PATH: `${dirname(node)}:/usr/bin:/bin`, HOME: scratch, TMPDIR: scratch, SCOPEHAVEN_NODE: node,
    SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken, SCOPEHAVEN_TARGET_X: FAKE_SECRET };
});
after(async () => { await lab?.close(); if (scratch) await rm(scratch, { recursive: true, force: true }); });

test('action.yml is a composite action with the declared inputs, outputs and pinned third-party actions', () => {
  assert.equal(action.runs.using, 'composite');
  for (const key of ['profile', 'authorization', 'baseline-run', 'fail-on', 'upload-sarif', 'sarif-category', 'working-directory', 'wait-url', 'wait-timeout-seconds', 'policy-baseline-matrix', 'policy-matrix', 'fail-on-policy-diff'])
    assert.ok(Object.hasOwn(action.inputs, key), `input ${key}`);
  assert.equal(action.inputs.profile.required, 'true');
  assert.equal(action.inputs['fail-on'].default, 'fail');
  assert.equal(action.inputs['upload-sarif'].default, 'false');
  assert.equal(action.inputs['fail-on-policy-diff'].default, 'false', 'the policy diff only reports unless the operator opts in');
  for (const key of ['run-id', 'status-counts', 'gate-verdict', 'sarif-path', 'policy-diff']) assert.match(action.outputs[key].value, /^\$\{\{ steps\.summary\.outputs\.[a-z-]+ \}\}$/);
  const uses = action.runs.steps.filter(step => step.uses).map(step => step.uses);
  // Pinned to reviewed commit SHAs (upstream v4 tags on 2026-10-05).
  assert.deepEqual(uses.map(u => u.split(' #')[0]), ['actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020', 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02', 'github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2']);
  for (const u of uses) assert.match(u.split(' #')[0], /@[0-9a-f]{40}$/);
  // An exact Node, equal to the launcher's pinned download, and no lookup for a newer one.
  const launcherPin = /^scopehaven_pinned_node="\$scopehaven_root\/\.runtime\/node-v(\S+)-darwin-arm64\/bin\/node"$/m.exec(launcherText)?.[1];
  assert.equal(action.runs.steps[0].with['node-version'], '24.22.2');
  assert.equal(action.runs.steps[0].with['node-version'], launcherPin);
  assert.equal(action.runs.steps[0].with['check-latest'], 'false');
  const sarif = action.runs.steps.find(step => step.uses?.startsWith('github/codeql-action/upload-sarif'));
  assert.equal(sarif['continue-on-error'], 'true');
  assert.match(sarif.if, /inputs\.upload-sarif == 'true'/);
  for (const step of action.runs.steps.filter(step => step.run)) {
    assert.equal(step.shell, 'bash', step.name);
    assert.doesNotMatch(step.run, /\$\{\{/, `no expression interpolation inside run: ${step.name}`);
    assert.doesNotMatch(step.run, /set -x|curl|wget|https?:\/\/(?!127\.0\.0\.1)/, `no tracing or network tools: ${step.name}`);
  }
  // Exact launcher commands, verified against src/cli.mjs, gate.mjs parseArgs and src/export-cli.mjs.
  assert.match(actionText, /"\$SH_ROOT\/scopehaven" assess --config "\$SH_PROFILE" --target "\$SH_TARGET" --out "\$store"/);
  assert.match(actionText, /"\$SH_ROOT\/scopehaven" gate --target "\$SH_TARGET" --config "\$SH_PROFILE" --out "\$store" --baseline "\$baseline_id"/);
  assert.match(actionText, /"\$SH_ROOT\/scopehaven" export --run "\$SH_RUN_ID" --format sarif --out "\$out\/scopehaven.sarif" --data "\$SH_STORE"/);
  // Verified against integrations/policy-import/cli.mjs (diff BEFORE AFTER --out NEW_FILE) and the launcher's policy alias.
  assert.match(actionText, /"\$SH_ROOT\/scopehaven" policy diff "\$SH_POLICY_BEFORE" "\$SH_POLICY_AFTER" --out "\$SH_WORK\/export\/policy-diff.json"/);
});

test('the example workflow keeps read-only permissions and uses the in-repo action', async () => {
  const example = await readFile(join(here, 'example-workflow.yml'), 'utf8');
  const parsed = parseYamlSubset(example);
  assert.deepEqual(parsed.permissions, { contents: 'read' });
  assert.match(example, /^ {2}# security-events: write$/m);
  assert.match(example, /^ {2}# actions: read$/m);
  assert.ok(parsed.jobs.assess.steps.some(step => step.uses === './integrations/github-action'));
});

test('prepare.mjs writes the same gate marker that the regression gate expects', async () => {
  const gate = await readFile(join(root, 'integrations/regression-gate/gate.mjs'), 'utf8');
  assert.ok(gate.includes(`const marker = '${GATE_MARKER}';`));
  assert.ok(gate.includes(`const markerText = '${GATE_MARKER_TEXT.replace('\n', '\\n')}';`));
});

test('action steps run end to end against the loopback lab: baseline build fails on failed checks', async () => {
  const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-baseline.json', 'wait-url': `${lab.origin}/me`, 'wait-timeout-seconds': '10' },
    { workspace, runnerTemp, env: baseEnv });
  const byName = Object.fromEntries(result.logs.map(log => [log.name, log]));
  assert.equal(byName['Wait for the application under test'].code, 0);
  assert.equal(result.steps.assess.outputs['assess-exit'], '1');
  assert.match(result.outputs['run-id'], /^[0-9a-f-]{36}$/);
  assert.deepEqual(JSON.parse(result.outputs['status-counts']), { pass: 5, fail: 2, inconclusive: 0, error: 0, not_applicable: 0 });
  assert.equal(result.outputs['gate-verdict'], 'not-requested');
  assert.equal(result.outputs['policy-diff'], 'not-requested');
  assert.match(result.summary, /### Policy matrix diff\n\nNot requested/);
  assert.equal(result.steps.summary.outputs.decision, 'fail');
  assert.equal(result.steps.summary.outputs['decision-reason'], 'checks-failed');
  assert.equal(byName['Apply fail-on'].code, 1);
  const sarif = JSON.parse(await readFile(result.outputs['sarif-path'], 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.filter(row => row.kind === 'fail').length, 2);
  assert.match(result.summary, /Response-level evidence: HTTP response contracts only/);
  assert.match(result.summary, /\| FOREIGN-STATUS \| The foreign-record endpoint returns a denial \| high \| fail \|/);
  assert.match(result.summary, /Code scanning upload not requested/);
  const work = result.steps.prepare.outputs.work;
  assert.equal((await stat(work)).mode & 0o777, 0o700);
  const exported = (await readdir(join(work, 'export'))).sort();
  assert.deepEqual(exported, ['report.html', 'run.json', 'scopehaven.sarif', 'summary.md']);
  // No credential or response content anywhere: logs, summary, outputs, evidence and exports.
  const texts = [result.summary, JSON.stringify(result.outputs), ...result.logs.flatMap(log => [log.stdout, log.stderr])];
  for (const file of await allFiles(work)) texts.push(await readFile(file, 'utf8'));
  for (const text of texts) for (const secret of [lab.memberToken, FAKE_SECRET, 'SYNTHETIC_PRIVATE_RESPONSE_DO_NOT_STORE', 'COBALT_LAB_PRIVATE']) assert.ok(!text.includes(secret));
  firstRun = join(work, 'export/run.json');
});

test('action steps gate the repaired build against the saved baseline run', async () => {
  assert.ok(firstRun, 'depends on the end-to-end baseline test');
  lab.setBuild('repaired');
  try {
    const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', 'baseline-run': firstRun, 'wait-url': lab.origin.replace('127.0.0.1', 'localhost') },
      { workspace, runnerTemp, env: baseEnv });
    assert.equal(result.steps.assess.outputs['gate-exit'], '1');
    assert.equal(result.outputs['gate-verdict'], 'assessment-failed');
    assert.deepEqual(JSON.parse(result.outputs['status-counts']), { pass: 6, fail: 0, inconclusive: 1, error: 0, not_applicable: 0 });
    const work = result.steps.prepare.outputs.work;
    const gate = JSON.parse(await readFile(join(work, 'export/gate-summary.json'), 'utf8'));
    assert.equal(gate.comparison.compatibility, 'compatible');
    assert.equal(gate.comparison.baselineRunId, result.steps.assess.outputs['baseline-id']);
    assert.ok(gate.reasons.includes('inconclusive-evidence'));
    // fail-on=fail follows the gate: it exited 1 (a backend-required row is inconclusive), so CI fails.
    assert.equal(result.steps.summary.outputs.decision, 'fail');
    assert.equal(result.steps.summary.outputs['decision-reason'], 'gate-inconclusive-evidence');
    assert.equal(result.logs.find(log => log.name === 'Apply fail-on').code, 1);
    assert.match(result.summary, /Verdict: \*\*assessment-failed\*\* \(exit 1\)/);
    assert.match(result.summary, /\| BACKEND-UNVERIFIED \| .* \| critical \| inconclusive \|/);
    assert.ok((await readdir(join(work, 'export'))).includes('comparison.html'));
    for (const file of await allFiles(work)) {
      const text = await readFile(file, 'utf8');
      assert.ok(!text.includes(lab.memberToken) && !text.includes(FAKE_SECRET));
    }
    // The same evidence with fail-on=never only reports.
    const reportOnly = await run(node, [join(here, 'summary.mjs'), '--format', 'outputs', '--run', join(result.steps.assess.outputs.store, 'runs', `${result.outputs['run-id']}.json`),
      '--gate', join(work, 'export/gate-summary.json'), '--fail-on', 'never'], { env: baseEnv });
    assert.match(reportOnly.stdout, /^decision=pass$/m);
    assert.match(reportOnly.stdout, /^decision-reason=fail-on-never$/m);
  } finally { lab.setBuild('baseline'); }
});

test('a tampered baseline run is refused before any assessment', async () => {
  assert.ok(firstRun);
  const tampered = JSON.parse(await readFile(firstRun, 'utf8'));
  tampered.results.find(row => row.status === 'fail').status = 'pass';
  assert.throws(() => baselineRecord(tampered), /integrity/);
  const file = join(workspace, 'tampered.json'); await writeFile(file, JSON.stringify(tampered));
  const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-baseline.json', 'baseline-run': 'tampered.json' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(result.steps.assess.outcome, 'failure');
  assert.equal(result.steps.summary.outputs.decision, 'fail');
  assert.equal(result.outputs['gate-verdict'], 'unavailable');
});

// A loopback stand-in for the application under test. It records when every connection arrived, so "nothing was
// sent" is observed at the listener; status is what it answers (503 keeps a wait polling).
async function countingTarget(t, { status = 200 } = {}) {
  const arrivals = [];
  const server = createHttpServer((req, res) => { req.resume(); res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end('{}'); });
  server.on('connection', () => arrivals.push(Date.now()));
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  const origin = `http://127.0.0.1:${server.address().port}`, name = `counted-${server.address().port}`;
  await writeFile(join(workspace, `profiles/${name}.json`), JSON.stringify({ schemaVersion: 1, targets: [makeLabProfile(origin, 'lab-baseline')] }));
  // A record for this target: the lab's own, optionally edited and resealed.
  const record = (file, edit) => { const sealed = makeLabAuthorization(origin); let value = sealed; if (edit) { const draft = structuredClone(sealed); edit(draft); value = checksumAuthorization(draft); }
    return writeFile(join(workspace, `profiles/${name}.${file}`), JSON.stringify(value)).then(() => `profiles/${name}.${file}`); };
  return { origin, arrivals, profile: `profiles/${name}.json`, record, prefix: `profiles/${name}` };
}
const actionLog = result => result.logs.map(log => `${log.stdout ?? ''}${log.stderr ?? ''}`).join('\n');

test('a configured target without a covering authorization record stops in the prepare step, before the wait or any request', async t => {
  // The wait step used to send its GET before assess checked the record. The prepare step
  // now checks it, so with wait-url set and no covering record, nothing connects to the target.
  const target = await countingTarget(t), waitInputs = { 'wait-url': `${target.origin}/admin/purge-cache`, 'wait-timeout-seconds': '5' };
  const day = 86400000, at = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const edited = await target.record('edited.json');
  await writeFile(join(workspace, edited), JSON.stringify({ ...JSON.parse(await readFile(join(workspace, edited), 'utf8')), validUntil: at(Date.now() + 60 * day) }));
  const repeated = await target.record('repeated.json');
  await writeFile(join(workspace, repeated), (await readFile(join(workspace, repeated), 'utf8')).replace('"origins":', '"origins":["http://127.0.0.1:1"],"origins":'));
  for (const [name, authorization, code] of [
    ['no record', '', 'authorization-missing'],
    ['an expired record', await target.record('expired.json', r => { r.validFrom = at(Date.now() - 2 * day); r.validUntil = at(Date.now() - day); r.signedAt = r.validFrom; }), 'authorization-window'],
    ['a record edited without recomputing its checksum', edited, 'authorization-checksum'],
    ['a record for another origin', await target.record('other-origin.json', r => { r.origins = ['http://127.0.0.1:1']; }), 'authorization-origin'],
    ['a record that repeats a field name', repeated, 'authorization-duplicate-key'],
  ]) {
    const result = await runAction({ profile: target.profile, ...(authorization ? { authorization } : {}), ...waitInputs }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(result.steps.prepare.outcome, 'failure', name);
    assert.match(actionLog(result), new RegExp(`authorization refused \\(${code}\\)`), name);
    assert.deepEqual([result.steps.wait.outcome, result.steps.assess.outcome], ['skipped', 'skipped'], name);
    assert.equal(result.outputs['run-id'] ?? '', '', name);
    assert.equal(result.steps.summary.outputs.decision, 'fail', name);
  }
  assert.equal(target.arrivals.length, 0, 'no refused run connected to the target, the wait included');
  // With a covering record the wait still works: it reaches the target, and assess runs after it.
  const ok = await runAction({ profile: target.profile, authorization: await target.record('ok.json'), ...waitInputs, 'fail-on': 'never' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(ok.steps.prepare.outcome, 'success', actionLog(ok));
  assert.equal(ok.steps.wait.outcome, 'success', actionLog(ok));
  assert.match(actionLog(ok), /answered HTTP 200/);
  assert.notEqual(ok.steps.assess.outputs['assess-exit'], '2', actionLog(ok));
  assert.ok(target.arrivals.length >= 2, 'the wait and the run both reached the target');
  await symlink(join(workspace, 'profiles/lab.authorization.json'), join(workspace, 'profiles/link.authorization.json')).catch(error => { if (error.code !== 'EEXIST') throw error; });
  for (const [path, message] of [['profiles/missing.json', /authorization must be an existing regular file/], ['profiles', /authorization must be an existing regular file/], ['profiles/link.authorization.json', /not a symlink/]]) {
    const refused = await runAction({ authorization: path, profile: 'profiles/lab-baseline.json' }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(refused.steps.prepare.outcome, 'failure');
    assert.match(actionLog(refused), message);
  }
});

test('a wait-url whose origin the record does not cover is refused in the prepare step, before any request, even on another configured target', async t => {
  // The profile file holds two configured targets, http-lab at A (which the record covers) and
  // app-b at B (which no record covers). With wait-url at B, the wait would have sent its GET to B.
  const a = await countingTarget(t), b = await countingTarget(t);
  const profile = `${a.prefix}-and-b.json`;
  await writeFile(join(workspace, profile), JSON.stringify({ schemaVersion: 1, targets: [makeLabProfile(a.origin, 'lab-baseline'), { ...makeLabProfile(b.origin, 'lab-baseline'), id: 'app-b' }] }));
  const authorization = await a.record('wait-url.json');
  for (const url of [`${b.origin}/admin/purge-cache`, `${b.origin.replace('127.0.0.1', 'localhost')}/health`]) {
    const result = await runAction({ profile, target: 'http-lab', authorization, 'wait-url': url, 'wait-timeout-seconds': '5' }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(result.steps.prepare.outcome, 'failure', url);
    assert.match(actionLog(result), /authorization refused \(authorization-origin\)/, url);
    assert.deepEqual([result.steps.wait.outcome, result.steps.assess.outcome], ['skipped', 'skipped'], url);
  }
  assert.deepEqual([a.arrivals.length, b.arrivals.length], [0, 0], 'neither target was contacted');
  // The same record with wait-url on the target it covers: the wait reaches A, never B.
  const ok = await runAction({ profile, target: 'http-lab', authorization, 'wait-url': `${a.origin}/health`, 'wait-timeout-seconds': '5', 'fail-on': 'never' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(ok.steps.wait.outcome, 'success', actionLog(ok));
  assert.ok(a.arrivals.length >= 1);
  assert.equal(b.arrivals.length, 0);
});

test('a forwarded target\'s record is checked in the prepare step, before the wait, and one that does not name the destination contacts nothing', async t => {
  const target = await countingTarget(t), profile = `${target.prefix}-forwarded.json`;
  await writeFile(join(workspace, profile), JSON.stringify({ schemaVersion: 1, targets: [{ ...makeLabProfile(target.origin, 'lab-baseline'), targetContext: 'operator-forwarded', targetLabel: 'Lab staging (forwarded)' }] }));
  const waitInputs = { 'wait-url': `${target.origin}/health`, 'wait-timeout-seconds': '5' };
  const refused = await runAction({ profile, authorization: await target.record('no-destination.json'), ...waitInputs }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(refused.steps.prepare.outcome, 'failure', actionLog(refused));
  assert.match(actionLog(refused), /authorization refused \(authorization-forwarded\)/);
  assert.deepEqual([refused.steps.wait.outcome, refused.steps.assess.outcome], ['skipped', 'skipped']);
  assert.equal(target.arrivals.length, 0, 'neither the wait nor the run contacted the forwarder');
  // With the destination named, the wait reaches the forwarder and assess accepts the record.
  const ok = await runAction({ profile, authorization: await target.record('destination.json', r => { r.forwarded = { destination: 'https://staging.lab.example' }; }), ...waitInputs, 'fail-on': 'never' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(ok.steps.prepare.outcome, 'success', actionLog(ok));
  assert.equal(ok.steps.wait.outcome, 'success', actionLog(ok));
  assert.notEqual(ok.steps.assess.outputs['assess-exit'], '2', actionLog(ok));
  assert.ok(target.arrivals.length >= 2, 'the wait and the run both reached the forwarder');
});

test('the wait stops sending when the record\'s window ends: exit 2 (authorization-window-ended), and assess never runs', async t => {
  // The target never becomes ready (503), so the wait polls until the window ends. If the prepare step took longer than
  // the window just to start (a loaded machine), it refused the record and the attempt is repeated with a longer window.
  const target = await countingTarget(t, { status: 503 });
  for (const ms of [4000, 15000]) {
    const until = Date.now() + ms, before = target.arrivals.length;
    const authorization = await target.record(`until-${ms}.json`, r => { r.validUntil = new Date(until).toISOString(); });
    const result = await runAction({ profile: target.profile, authorization, 'wait-url': `${target.origin}/health`, 'wait-timeout-seconds': String(ms / 1000 + 4) }, { workspace, runnerTemp, env: baseEnv });
    if (result.steps.prepare.outcome === 'failure') { assert.match(actionLog(result), /authorization refused \(authorization-window\)/); continue; }
    const arrivals = target.arrivals.slice(before);
    assert.equal(result.steps.wait.outcome, 'failure', actionLog(result));
    assert.match(actionLog(result), /authorization refused \(authorization-window-ended\)/);
    assert.equal(result.steps.assess.outcome, 'skipped');
    assert.ok(arrivals.length >= 1, 'the wait polled inside the window');
    // A probe the check let through left before validUntil; one sent after it would arrive at least an interval later.
    assert.ok(arrivals.every(arrived => arrived < until + 200), `a probe arrived ${Math.max(...arrivals) - until} ms after validUntil`);
    return;
  }
  assert.fail('the prepare step never started inside the window');
});

test('wait-for sends nothing once --until has passed, and reads --until only as an ISO 8601 UTC instant', async t => {
  const target = await countingTarget(t);
  const result = await waitFor(`${target.origin}/health`, { timeoutSeconds: 2, until: '2026-01-01T00:00:00Z' });
  assert.deepEqual([result.ready, result.windowEnded, result.attempts], [false, true, 0]);
  const cli = await run(node, [join(here, 'wait-for.mjs'), '--url', `${target.origin}/health`, '--timeout-seconds', '2', '--until', '2026-01-01T00:00:00.000Z'], { env: baseEnv });
  assert.equal(cli.code, 2);
  assert.match(cli.stderr, /authorization refused \(authorization-window-ended\)/);
  assert.equal(target.arrivals.length, 0);
  assert.equal(parseUntil('2026-10-07T00:00:01.5Z'), Date.parse('2026-10-07T00:00:01.500Z'));
  // Read as the record's instants are: no 02-31 rolled over to March, no hour 24 read as the next day.
  for (const text of ['', 'now', '2026-10-07', '2026-10-07T00:00:00+00:00', '2026-10-07T00:00:00.1234Z', 1791331200000, '2026-02-31T00:00:00Z', '2026-10-07T24:00:00Z', '2026-10-07T23:60:00Z']) assert.throws(() => parseUntil(text), /--until must be/, String(text));
  assert.equal((await run(node, [join(here, 'wait-for.mjs'), '--url', `${target.origin}/health`, '--until', ''], { env: baseEnv })).code, 2);
  assert.equal(target.arrivals.length, 0);
});

test('invalid inputs stop in the prepare step and still produce a failing summary', async () => {
  const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-baseline.json', 'fail-on': 'sometimes' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(result.steps.prepare.outcome, 'failure');
  assert.equal(result.steps.assess.outcome, 'skipped');
  assert.equal(result.steps.summary.outputs.decision, 'fail');
  assert.match(result.summary, /No saved run is available/);
});

test('summary.mjs escapes markdown table cells', () => {
  assert.equal(escapeCell('a|b'), 'a\\|b');
  assert.equal(escapeCell('<script>alert(1)</script>'), '&lt;script&gt;alert\\(1\\)&lt;/script&gt;');
  assert.equal(escapeCell('line one\nline two\r\n| x'), 'line one line two \\| x');
  assert.equal(escapeCell('**bold** _it_ `code` [link](http://x) # ~ ! \\'), '\\*\\*bold\\*\\* \\_it\\_ \\`code\\` \\[link\\]\\(http://x\\) \\# \\~ \\! \\\\');
  assert.equal(escapeCell('x'.repeat(500)).length, 200);
  const run = { core: { schemaVersion: 1, id: '00000000-0000-4000-8000-000000000000', targetId: 't|1', evidenceOrigin: 'local-http-response',
    results: [{ id: 'C-1', title: 'Pipe | and\nnewline <b>', severity: 'high', status: 'fail' }] }, sha256: 'a'.repeat(64) };
  const { markdown } = buildReport({ runInput: run, env: {} });
  const row = markdown.split('\n').find(line => line.startsWith('| C-1 '));
  assert.equal(row, '| C-1 | Pipe \\| and newline &lt;b&gt; | high | fail |');
  assert.equal(row.replace(/\\\|/g, '').split('|').length - 2, 4, 'four columns');
});

test('summary.mjs never prints credentials, profile bodies or response content', async () => {
  const saved = JSON.parse(await readFile(firstRun, 'utf8'));
  // Plant the fake credential in a title (printed field) and in fields that must never be printed.
  const failing = saved.results.find(row => row.status === 'fail');
  failing.title = `Leaky title ${FAKE_SECRET}`;
  failing.assertions = [{ name: 'x', status: 'fail', expected: FAKE_SECRET, actual: 'RESPONSE_BODY_SENTINEL' }];
  saved.notes = { [failing.id]: { note: FAKE_SECRET } };
  saved.limitations = ['PROFILE_BODY_SENTINEL'];
  const file = join(scratch, 'leaky-run.json'); await writeFile(file, JSON.stringify(saved));
  for (const format of ['markdown', 'outputs']) {
    const result = await run(node, [join(here, 'summary.mjs'), '--format', format, '--run', file], { env: baseEnv });
    assert.equal(result.code, 0);
    for (const forbidden of [FAKE_SECRET, lab.memberToken, 'RESPONSE_BODY_SENTINEL', 'PROFILE_BODY_SENTINEL', 'credentialEnv', 'requestPathHash']) assert.ok(!result.stdout.includes(forbidden), `${format}: ${forbidden}`);
  }
  const markdown = (await run(node, [join(here, 'summary.mjs'), '--run', file], { env: baseEnv })).stdout;
  assert.match(markdown, /Leaky title REDACTED/);
  assert.equal(normalizeRun(saved).hashes.evidenceIntegrity, saved.integrity.sha256);
});

test('fail-on decisions', () => {
  const view = counts => ({ id: '00000000-0000-4000-8000-000000000000', counts: { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0, ...counts }, unrecognized: 0, requiredControlsPassed: true, unprovenActors: 0 });
  assert.equal(decide({ run: view({ fail: 1 }), failOn: 'fail' }).decision, 'fail');
  assert.equal(decide({ run: view({ fail: 1 }), failOn: 'never' }).decision, 'pass');
  // CI follows assess: an inconclusive check fails under the default.
  assert.deepEqual(decide({ run: view({ inconclusive: 1 }), failOn: 'fail' }), { decision: 'fail', reason: 'checks-inconclusive' });
  assert.equal(decide({ run: view({ pass: 3 }), failOn: 'fail', assessExit: 1 }).reason, 'assessment-not-clean');
  assert.equal(decide({ run: view({ pass: 3 }), failOn: 'fail', assessExit: 0 }).decision, 'pass');
  assert.equal(decide({ run: view({ inconclusive: 1 }), failOn: 'inconclusive' }).decision, 'fail');
  assert.equal(decide({ run: view({ error: 1 }), failOn: 'fail' }).reason, 'checks-errored');
  assert.equal(decide({ run: view({ pass: 3 }), gate: { reasons: ['identity-not-established'] }, gateRequested: true, failOn: 'fail' }).decision, 'fail');
  assert.equal(decide({ run: view({ pass: 3 }), gate: { reasons: ['some-future-reason'] }, gateRequested: true, failOn: 'fail' }).decision, 'fail');
  assert.equal(decide({ run: view({ pass: 3 }), gate: { exitCode: 1, reasons: ['comparison-incomplete'] }, gateRequested: true, failOn: 'fail' }).reason, 'gate-comparison-incomplete');
  assert.equal(decide({ run: view({ pass: 3 }), gate: { exitCode: 0, reasons: [] }, gateRequested: true, failOn: 'fail' }).decision, 'pass');
  assert.equal(decide({ run: null, failOn: 'never' }).decision, 'fail', 'setup errors fail even with never');
  assert.equal(decide({ run: view({}), assessExit: 2, failOn: 'never' }).decision, 'fail');
  assert.equal(decide({ run: view({}), gateRequested: true, gate: null, failOn: 'fail' }).reason, 'gate-unavailable');
  // Without a baseline, CI must still fail where the gate would (hard reasons computed from the run).
  const runOf = (results, extra = {}) => normalizeRun({ id: '00000000-0000-4000-8000-000000000001', requiredControlIds: ['ctl'], results, ...extra });
  const inconclusiveControl = runOf([{ id: 'ctl', severity: 'control', status: 'inconclusive' }, { id: 'idor', severity: 'critical', status: 'inconclusive' }]);
  assert.deepEqual(decide({ run: inconclusiveControl, failOn: 'fail', assessExit: 1 }), { decision: 'fail', reason: 'required-controls-not-passed' });
  const unproven = runOf([{ id: 'ctl', severity: 'control', status: 'pass' }], { identityEvidence: { actors: [{ actorId: 'a', established: false }] } });
  assert.deepEqual(decide({ run: unproven, failOn: 'fail' }), { decision: 'fail', reason: 'identity-not-established' });
  // Every security check inconclusive with a passing control still fails.
  const noEvidence = runOf([{ id: 'ctl', severity: 'control', status: 'pass' }, { id: 'idor', severity: 'critical', status: 'inconclusive' }], { identityEvidence: { actors: [{ actorId: 'a', established: true }] } });
  assert.equal(decide({ run: noEvidence, failOn: 'fail', assessExit: 1 }).decision, 'fail');
  // Required controls fail closed.
  assert.equal(normalizeRun({ id: '00000000-0000-4000-8000-000000000002', requiredControlIds: [], results: [{ id: 'x', severity: 'high', status: 'pass' }] }).requiredControlsPassed, false);
  assert.equal(normalizeRun({ id: '00000000-0000-4000-8000-000000000003', requiredControlIds: ['ctl'], results: [] }).requiredControlsPassed, false);
  assert.equal(normalizeRun({ id: '00000000-0000-4000-8000-000000000004', requiredControlIds: ['x'], results: [{ id: 'x', severity: 'high', status: 'pass' }] }).requiredControlsPassed, false);
  const clean = runOf([{ id: 'ctl', severity: 'control', status: 'pass' }, { id: 'idor', severity: 'critical', status: 'pass' }], { identityEvidence: { actors: [{ actorId: 'a', established: true }] } });
  assert.deepEqual(decide({ run: clean, failOn: 'fail', assessExit: 0 }), { decision: 'pass', reason: 'clean' });
});

test('wait-for enforces its overall deadline against a server that trickles headers', async () => {
  const sockets = new Set();
  const server = createServer(socket => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.write('HTTP/1.1 200 OK\r\n');
    const timer = setInterval(() => { if (!socket.destroyed) socket.write(`X-Slow-${Date.now()}: 1\r\n`); }, 300);
    socket.on('close', () => clearInterval(timer));
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  try {
    const started = Date.now();
    const result = await run(node, [join(here, 'wait-for.mjs'), '--url', `http://127.0.0.1:${server.address().port}/`, '--timeout-seconds', '1', '--interval-ms', '100'], { env: baseEnv });
    assert.equal(result.code, 1);
    assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`);
  } finally { for (const socket of sockets) socket.destroy(); await new Promise(r => server.close(r)); }
});

test('wait-for rejects non-loopback URLs without connecting', async () => {
  for (const url of ['http://example.com:80', 'https://127.0.0.1:443', 'http://10.0.0.1:8080', 'http://127.0.0.1', 'http://127.0.0.1.nip.io:80',
    'http://localhost@evil.test:80', 'http://user:pw@127.0.0.1:80', 'http://[::1]:80', 'http://127.0.0.1:0', 'http://127.0.0.1:70000', 'http://127.0.0.1:80/#x', 'file:///etc/passwd']) {
    assert.throws(() => parseLoopbackUrl(url), /wait-url must be/, url);
    const result = await run(node, [join(here, 'wait-for.mjs'), '--url', url, '--timeout-seconds', '1'], { env: baseEnv });
    assert.equal(result.code, 2, url);
  }
  assert.deepEqual(parseLoopbackUrl('http://localhost:4319/me?x=1'), { host: '127.0.0.1', port: 4319, path: '/me?x=1', display: 'http://localhost:4319' });
  assert.equal((await run(node, [join(here, 'wait-for.mjs'), '--url', 'http://127.0.0.1:4319', '--timeout-seconds', '0'], { env: baseEnv })).code, 2);
});

test('wait-for times out on a closed loopback port and succeeds on the lab', async () => {
  const port = await new Promise(done => { const server = createServer().listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => done(port)); }); });
  const started = Date.now();
  const closed = await run(node, [join(here, 'wait-for.mjs'), '--url', `http://127.0.0.1:${port}/`, '--timeout-seconds', '1', '--interval-ms', '100'], { env: baseEnv });
  assert.equal(closed.code, 1);
  assert.ok(Date.now() - started < 10000);
  assert.match(closed.stderr, /not ready within the timeout/);
  const ready = await run(node, [join(here, 'wait-for.mjs'), '--url', `${lab.origin}/me`, '--timeout-seconds', '5'], { env: baseEnv });
  assert.equal(ready.code, 0);
  assert.match(ready.stdout, /answered HTTP 401/);
});

// ---- Policy matrix diff (scopehaven policy diff, printed next to the Release Permission Diff). ----
const policyCell = (role, resource, action, decision, extra = {}) => ({ role, resource, action, decision, basis: 'b', citations: decision === 'undeclared' ? [] : ['0001.sql:1'], ...extra });
const policyBefore = (application = 'app') => buildMatrix({ application, layer: 'postgres-rls', sources: [], cells: [
  policyCell('member', 'notes', 'select', 'deny'), policyCell('member', 'notes', 'delete', 'deny'), policyCell('admin', 'notes', 'select', 'allow'),
  policyCell('member', 'files', 'select', 'conditional', { conditions: ['owner = current_user'] }), policyCell('member', 'audit', 'select', 'unknown', { computedDecision: 'deny' }),
  policyCell('member', 'old', 'select', 'deny')] });
const policyAfter = (extra = []) => buildMatrix({ application: 'app', layer: 'postgres-rls', sources: [], cells: [
  policyCell('member', 'notes', 'select', 'allow'), // widened
  policyCell('member', 'notes', 'delete', 'undeclared'), // became-undeclared
  policyCell('admin', 'notes', 'select', 'deny'), // narrowed: not gated
  policyCell('member', 'files', 'select', 'unknown'), // became-unknown
  policyCell('member', 'audit', 'select', 'unknown', { computedDecision: 'allow' }), // widened between two unknown cells
  policyCell('guest|x', 'notes', 'select', 'allow'), // added-open
  policyCell('guest|x', 'notes', 'delete', 'deny'), // added closed: not gated
  ...extra] }); // member/old/select removed: not gated
const GATED_ROWS = [
  '| widened | member | audit | select | unknown \\(computed deny\\) | unknown \\(computed allow\\) |',
  '| widened | member | notes | select | deny | allow |',
  '| added-open | guest\\|x | notes | select | absent | allow |',
  '| became-unknown | member | files | select | conditional | unknown |',
  '| became-undeclared | member | notes | delete | deny | undeclared |'];
const cleanRunInput = () => ({ id: '00000000-0000-4000-8000-000000000005', evidenceOrigin: 'local-http-response', requiredControlIds: ['ctl'],
  results: [{ id: 'ctl', title: 'Allowed use', severity: 'control', status: 'pass' }, { id: 'idor', title: 'Foreign record', severity: 'critical', status: 'pass' }],
  identityEvidence: { actors: [{ actorId: 'a', established: true }] } });
// The summary recomputes the diff from the two matrices; `diff` is the file the action's diff step wrote.
const policyReport = ({ before = policyBefore(), after = policyAfter(), diff = diffMatrices(before, after), exit, ...options }) => buildReport({ runInput: cleanRunInput(),
  policyBeforeInput: before, policyAfterInput: after, policyDiffInput: JSON.parse(JSON.stringify(diff)), policyDiffState: 'ok', policyDiffExit: exit, env: {}, ...options });

test('summary.mjs prints the gated policy-matrix cells and fails only when the operator opts in', () => {
  const diff = diffMatrices(policyBefore(), policyAfter());
  assert.equal(diff.gated, true);
  const reported = policyReport({ exit: 1 });
  assert.deepEqual([reported.decision, reported.reason, reported.policyDiff], ['pass', 'clean', 'gated'], 'default: reported only');
  const lines = reported.markdown.split('\n');
  const section = lines.slice(lines.indexOf('### Policy matrix diff'), lines.indexOf('### Action decision'));
  assert.ok(lines.indexOf('### Release permission diff') < lines.indexOf('### Policy matrix diff'), 'next to the Release Permission Diff');
  assert.deepEqual(section.filter(line => /^\| (widened|added-open|became-unknown|became-undeclared|narrowed|added|removed|conditions-changed|changed) \|/.test(line) && line.split('|').length > 5), GATED_ROWS);
  for (const [kind, count] of [['widened', 2], ['added-open', 1], ['became-unknown', 1], ['became-undeclared', 1], ['narrowed', 1], ['added', 1], ['removed', 1]])
    assert.ok(section.includes(`| ${kind} | ${count} |`), `count ${kind}`);
  assert.ok(section.includes('**Gated cells** (5): more access, or a declaration that became unknown or undeclared.'));
  assert.ok(section.some(line => line.includes(diff.beforeMatrixId) && line.includes(diff.afterMatrixId)));
  assert.ok(section.includes('fail-on-policy-diff `false`: reported only.'));
  assert.match(reported.outputs, /^policy-diff=gated$/m);
  assert.match(reported.outputs, /^decision=pass$/m);
  // Opted in: the same diff fails the job.
  const gated = policyReport({ exit: 1, failOnPolicyDiff: 'true' });
  assert.deepEqual([gated.decision, gated.reason], ['fail', 'policy-diff-gated']);
  assert.match(gated.markdown, /fail-on `fail`, fail-on-policy-diff `true`: \*\*fail\*\* \(`policy-diff-gated`\)/);
  // Opt-in is independent of fail-on, and never hides a failing assessment.
  assert.equal(policyReport({ exit: 1, failOnPolicyDiff: 'true', failOn: 'never' }).reason, 'policy-diff-gated');
  const failing = cleanRunInput(); failing.results[1].status = 'fail';
  assert.equal(policyReport({ exit: 1, failOnPolicyDiff: 'true', runInput: failing }).reason, 'checks-failed');
  // A diff with only ungated kinds (narrowed, added closed, removed) is clean, also when opted in.
  const narrowedAfter = buildMatrix({ application: 'app', layer: 'postgres-rls', sources: [], cells: [
    policyCell('member', 'notes', 'select', 'deny'), policyCell('member', 'notes', 'delete', 'deny'), policyCell('admin', 'notes', 'select', 'deny'),
    policyCell('member', 'files', 'select', 'conditional', { conditions: ['owner = current_user'] }), policyCell('member', 'audit', 'select', 'unknown', { computedDecision: 'deny' }),
    policyCell('member', 'new', 'select', 'deny')] });
  assert.equal(diffMatrices(policyBefore(), narrowedAfter).gated, false);
  const clean = policyReport({ after: narrowedAfter, exit: 0, failOnPolicyDiff: 'true' });
  assert.deepEqual([clean.decision, clean.reason, clean.policyDiff], ['pass', 'clean', 'clean']);
  assert.match(clean.markdown, /\*\*Gated cells\*\*: none/);
  // A valid matrix written without optional cell fields (no conditions): the diff the CLI saved as JSON still matches.
  const { matrixId: _id, ...bare } = policyAfter(); bare.cells = bare.cells.map(({ conditions: _c, ...rest }) => rest);
  const bareAfter = { ...bare, matrixId: sha256(canonical(bare)) };
  assert.ok(diffMatrices(policyBefore(), bareAfter).changes.some(change => Object.hasOwn(change, 'toConditions') && change.toConditions === undefined));
  assert.deepEqual([policyReport({ after: bareAfter, exit: 1 }).policyDiff, policyReport({ after: bareAfter, exit: 1 }).decision], ['gated', 'pass']);
  const unchanged = policyReport({ after: policyBefore(), exit: 0, failOnPolicyDiff: 'true' });
  assert.deepEqual([unchanged.decision, unchanged.policyDiff], ['pass', 'clean']);
  assert.match(unchanged.markdown, /No cells changed\./);
});

test('summary.mjs: a policy diff that is not comparable, missing, or not the diff of the two matrices is never clean', () => {
  const diff = diffMatrices(policyBefore(), policyAfter());
  const state = (options, failOnPolicyDiff = 'false') => { const r = policyReport({ ...options, failOnPolicyDiff }); return [r.policyDiff, r.decision, r.reason]; };
  // Not comparable: another application, or a matrix whose id does not verify.
  const otherApp = { before: policyBefore('other-app'), exit: 2 };
  assert.deepEqual(diffMatrices(otherApp.before, policyAfter()), { comparable: false, reason: 'application-differs' });
  assert.deepEqual(state(otherApp), ['not-comparable', 'pass', 'clean']);
  assert.deepEqual(state(otherApp, 'true'), ['not-comparable', 'fail', 'policy-diff-not-comparable']);
  assert.match(policyReport(otherApp).markdown, /\*\*Not comparable\*\* \(`application-differs`\): no per-cell diff is shown\./);
  // A baseline edited to hide the widening (deny -> allow) without a new matrix id.
  const tampered = policyBefore(); tampered.cells.find(c => c.role === 'member' && c.resource === 'notes' && c.action === 'select').decision = 'allow';
  assert.deepEqual(diffMatrices(tampered, policyAfter()), { comparable: false, reason: 'before-matrix-invalid' });
  assert.deepEqual(state({ before: tampered, exit: 2 }, 'true'), ['not-comparable', 'fail', 'policy-diff-not-comparable']);
  // The step's file must be exactly the diff of the two matrices, with the matching exit code.
  const edited = edit => { const copy = JSON.parse(JSON.stringify(diff)); edit(copy); return copy; };
  for (const [label, options] of [
    ['exit 0 with gated cells', { exit: 0 }], ['exit 2 with a comparable diff', { exit: 2 }], ['no exit code', { exit: null }], ['exit 1 when not comparable', { ...otherApp, exit: 1 }],
    ['gated flag cleared', { diff: edited(d => { d.gated = false; }), exit: 1 }],
    ['gated cells dropped', { diff: edited(d => { d.changes = d.changes.filter(c => !['widened', 'added-open', 'became-unknown', 'became-undeclared'].includes(c.kind)); d.gated = false; delete d.counts.widened; }), exit: 0 }],
    // Consistent with itself, but not the diff of these matrices: one widening relabelled as narrowed.
    ['a kind relabelled', { diff: edited(d => { d.changes[0].kind = 'narrowed'; d.counts.widened -= 1; d.counts.narrowed += 1; }), exit: 1 }],
    ['a cell renamed', { diff: edited(d => { d.changes[0].role = 'someone-else'; }), exit: 1 }],
    ['an older diff of other matrices', { diff: diffMatrices(policyBefore(), policyBefore()), exit: 0 }],
    ['a not-comparable file for comparable matrices', { diff: { comparable: false, reason: 'layer-differs' }, exit: 2 }],
    ['a matrix unreadable to the summary', { after: null, diff, exit: 1 }],
    ['not an object', { diff: [], exit: 1 }]]) {
    assert.deepEqual(state(options), ['unavailable', 'pass', 'clean'], `${label}: reported`);
    assert.deepEqual(state(options, 'true'), ['unavailable', 'fail', 'policy-diff-unavailable'], `${label}: opted in`);
  }
  for (const missingState of ['missing', 'invalid']) {
    const r = buildReport({ runInput: cleanRunInput(), policyBeforeInput: policyBefore(), policyAfterInput: policyAfter(), policyDiffState: missingState, policyDiffExit: 2, failOnPolicyDiff: 'true', env: {} });
    assert.deepEqual([r.policyDiff, r.reason], ['unavailable', 'policy-diff-unavailable']);
  }
  // Opting in without matrices, or an invalid opt-in value, fails rather than going green.
  assert.equal(buildReport({ runInput: cleanRunInput(), failOnPolicyDiff: 'true', env: {} }).reason, 'policy-diff-not-requested');
  assert.equal(buildReport({ runInput: cleanRunInput(), failOnPolicyDiff: 'yes', env: {} }).reason, 'invalid-fail-on-policy-diff');
  const absent = buildReport({ runInput: cleanRunInput(), env: {} });
  assert.deepEqual([absent.decision, absent.policyDiff], ['pass', 'not-requested']);
  assert.match(absent.markdown, /fail-on `fail`: \*\*pass\*\*/);
});

test('summary.mjs: policy cells are escaped, redacted and bounded', () => {
  const secret = 'policy-role-secret-Zk81';
  const many = Array.from({ length: 150 }, (_, i) => policyCell(`r${String(i).padStart(3, '0')}`, 'notes', 'select', 'allow'));
  const { markdown, outputs } = policyReport({ after: policyAfter([policyCell(`leak ${secret}`, '<b>t</b>', 'select', 'allow'), ...many]), exit: 1, env: { SCOPEHAVEN_TARGET_ROLE: secret } });
  assert.ok(!markdown.includes(secret) && !outputs.includes(secret));
  assert.ok(markdown.includes('| added-open | leak REDACTED | &lt;b&gt;t&lt;/b&gt; | select | absent | allow |'));
  const rows = markdown.split('\n').filter(line => /^\| (widened|added-open|became-unknown|became-undeclared) \| .* \| .* \|/.test(line) && line.split('|').length > 5);
  assert.equal(rows.length, 100);
  assert.match(markdown, /56 more gated cells are in policy-diff\.json in the evidence artifact\./);
});

// A new gap where every cell is already unknown: no cell changes, yet the diff is gated.
const standingGap = { source: '0001.sql', line: 3, scope: '*', reason: 'procedural code (a DO block, EXECUTE or a called function) is not evaluated', identity: { subject: 'do $$ begin perform refresh(); end $$' } };
const newGap = { source: '0002.sql', line: 1, scope: '*', reason: 'client_encoding is set other than UTF8', identity: { subject: "set client_encoding = 'SJIS'" } };
const gapMatrix = gaps => buildMatrix({ application: 'app', layer: 'postgres-rls', sources: [], gaps,
  cells: [policyCell('member', 'notes', 'select', 'unknown', { computedDecision: 'deny' }), policyCell('admin', 'notes', 'select', 'unknown', { computedDecision: 'allow' })] });
const asSchema1 = m => { const { matrixId: _id, ...body } = m; const old = { ...body, schema: 'scopehaven-policy-matrix/1', gaps: body.gaps.map(({ id: _g, ...g }) => g), cells: body.cells.map(({ unknownReasons: _r, ...c }) => c) }; return { ...old, matrixId: sha256(canonical(old)) }; };

test('summary.mjs: a new gap where every cell was already unknown is gated, the exit code must agree, and an old baseline says why', () => {
  const before = gapMatrix([standingGap]), after = gapMatrix([{ ...standingGap, line: 9 }, newGap]);
  const diff = diffMatrices(before, after);
  assert.deepEqual([diff.gated, diff.changes, diff.gapCounts], [true, [], { 'gap-added': 1 }]);
  const reported = policyReport({ before, after, exit: 1 });
  assert.deepEqual([reported.decision, reported.policyDiff], ['pass', 'gated'], 'reported only by default');
  assert.match(reported.markdown, /No cells changed\./);
  assert.match(reported.markdown, /\*\*Gated cells\*\*: none/);
  assert.match(reported.markdown, /\| gap-added \| 1 \|/);
  assert.match(reported.markdown, /Gaps compared by identity/);
  assert.ok(reported.markdown.includes(`**Gated gaps** (1)`));
  assert.ok(reported.markdown.includes(`| gap-added | \\* | 0002.sql | \`${diff.gapChanges[0].id.slice(0, 16)}\` |`));
  assert.ok(!reported.markdown.includes('client_encoding'), 'a gap reason is free text from the sources; it stays in policy-diff.json');
  assert.match(reported.outputs, /^policy-diff=gated$/m);
  const opted = policyReport({ before, after, exit: 1, failOnPolicyDiff: 'true' });
  assert.deepEqual([opted.decision, opted.reason], ['fail', 'policy-diff-gated']);
  assert.match(opted.markdown, /fail-on-policy-diff `true`: a gated cell or gap, or an unavailable diff, fails the job\./);
  // The step's exit code must say the same: exit 0 for a gap-only gate is not this diff, and never clean.
  const zero = policyReport({ before, after, exit: 0, failOnPolicyDiff: 'true' });
  assert.deepEqual([zero.policyDiff, zero.reason], ['unavailable', 'policy-diff-unavailable']);
  const dropped = JSON.parse(JSON.stringify(diff)); dropped.gapChanges = []; dropped.gapCounts = {}; dropped.gated = false;
  assert.deepEqual([policyReport({ before, after, diff: dropped, exit: 0, failOnPolicyDiff: 'true' }).policyDiff], ['unavailable'], 'a file without the gated gap does not match');
  // The same gap, only moved to another file and line: clean.
  const moved = policyReport({ before, after: gapMatrix([{ ...standingGap, source: '0009.sql', line: 40 }]), exit: 0, failOnPolicyDiff: 'true' });
  assert.deepEqual([moved.decision, moved.policyDiff], ['pass', 'clean']);
  assert.match(moved.markdown, /\*\*Gated gaps\*\*: none/);
  // A removed gap is counted, not gated.
  const removed = policyReport({ before: after, after: before, exit: 0, failOnPolicyDiff: 'true' });
  assert.deepEqual([removed.decision, removed.policyDiff], ['pass', 'clean']);
  assert.match(removed.markdown, /\| gap-removed \| 1 \|/);
  // An old (/1) baseline with gaps: every gap of the current matrix is gated, and the summary says why.
  const old = policyReport({ before: asSchema1(before), after, exit: 1, failOnPolicyDiff: 'true' });
  assert.deepEqual([old.policyDiff, old.reason], ['gated', 'policy-diff-gated']);
  assert.match(old.markdown, /Gaps not compared by identity: the previous matrix has gaps without identities/);
  assert.match(old.markdown, /\| gap-unidentified \| 2 \|/);
  assert.match(old.markdown, /\*\*Gated gaps\*\* \(2\)/);
});

test('summary.mjs: a cell that stays unknown but gains a reason is a gated became-unknown row, marked, without the reason text', () => {
  const reasons = list => buildMatrix({ application: 'app', layer: 'postgres-rls', sources: [], gaps: [standingGap],
    cells: [policyCell('member', 'notes', 'select', 'unknown', { computedDecision: 'conditional', basis: list.at(-1), unknownReasons: list })] });
  const before = reasons(['source-gap']), after = reasons(['table-owner-bypasses-rls (no FORCE ROW LEVEL SECURITY)', 'source-gap']);
  const opted = policyReport({ before, after, exit: 1, failOnPolicyDiff: 'true' });
  assert.deepEqual([opted.policyDiff, opted.reason], ['gated', 'policy-diff-gated']);
  assert.ok(opted.markdown.includes('| became-unknown | member | notes | select | unknown | unknown \\(new reason\\) |'));
  assert.ok(!opted.markdown.includes('table-owner-bypasses-rls'), 'reason codes stay in policy-diff.json');
  assert.deepEqual(policyReport({ before: after, after: before, exit: 0, failOnPolicyDiff: 'true' }).policyDiff, 'clean', 'a lost reason is not gated');
});

test('action steps run scopehaven policy diff on the two matrices and fail only when opted in', async () => {
  await mkdir(join(workspace, 'policy'), { recursive: true });
  await writeFile(join(workspace, 'policy/before.json'), JSON.stringify(policyBefore()));
  await writeFile(join(workspace, 'policy/after.json'), JSON.stringify(policyAfter()));
  const inputs = { authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-baseline.json', 'fail-on': 'never', 'policy-baseline-matrix': 'policy/before.json', 'policy-matrix': 'policy/after.json' };
  for (const [optIn, decision, reason, applyCode] of [['false', 'pass', 'fail-on-never', 0], ['true', 'fail', 'policy-diff-gated', 1]]) {
    const result = await runAction({ ...inputs, 'fail-on-policy-diff': optIn }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(result.steps['policy-diff'].outputs['policy-diff-exit'], '1', optIn);
    assert.equal(result.outputs['policy-diff'], 'gated');
    assert.deepEqual([result.steps.summary.outputs.decision, result.steps.summary.outputs['decision-reason']], [decision, reason], optIn);
    assert.equal(result.logs.find(log => log.name === 'Apply fail-on').code, applyCode, optIn);
    for (const row of GATED_ROWS) assert.ok(result.summary.includes(row), `${optIn}: ${row}`);
    // The full diff, ungated kinds included, is in the evidence artifact.
    const work = result.steps.prepare.outputs.work;
    const saved = JSON.parse(await readFile(join(work, 'export/policy-diff.json'), 'utf8'));
    assert.deepEqual(saved, diffMatrices(policyBefore(), policyAfter()));
    assert.equal((await stat(join(work, 'export/policy-diff.json'))).mode & 0o777, 0o600);
    assert.deepEqual((await readdir(join(work, 'export'))).sort(), ['policy-diff.json', 'report.html', 'run.json', 'scopehaven.sarif', 'summary.md']);
  }
  // An unreadable matrix: the diff exits 2 without writing a file, and the opted-in job fails as unavailable.
  await writeFile(join(workspace, 'policy/broken.json'), '{not json');
  const broken = await runAction({ ...inputs, 'policy-matrix': 'policy/broken.json', 'fail-on-policy-diff': 'true' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(broken.steps['policy-diff'].outputs['policy-diff-exit'], '2');
  assert.deepEqual([broken.outputs['policy-diff'], broken.steps.summary.outputs['decision-reason']], ['unavailable', 'policy-diff-unavailable']);
});

test('action steps fail the opted-in job on a new gap where every cell was already unknown, and pass when the gap only moved', async () => {
  await mkdir(join(workspace, 'policy'), { recursive: true });
  await writeFile(join(workspace, 'policy/gap-before.json'), JSON.stringify(gapMatrix([standingGap])));
  await writeFile(join(workspace, 'policy/gap-after.json'), JSON.stringify(gapMatrix([{ ...standingGap, line: 9 }, newGap])));
  await writeFile(join(workspace, 'policy/gap-moved.json'), JSON.stringify(gapMatrix([{ ...standingGap, source: '0009.sql', line: 40 }])));
  const inputs = { authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-baseline.json', 'fail-on': 'never', 'policy-baseline-matrix': 'policy/gap-before.json', 'fail-on-policy-diff': 'true' };
  const gated = await runAction({ ...inputs, 'policy-matrix': 'policy/gap-after.json' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(gated.steps['policy-diff'].outputs['policy-diff-exit'], '1', 'the diff step exits 1 on the new gap');
  assert.deepEqual([gated.outputs['policy-diff'], gated.steps.summary.outputs.decision, gated.steps.summary.outputs['decision-reason']], ['gated', 'fail', 'policy-diff-gated']);
  assert.equal(gated.logs.find(log => log.name === 'Apply fail-on').code, 1, 'the job fails');
  assert.ok(gated.summary.includes('**Gated gaps** (1)'));
  const saved = JSON.parse(await readFile(join(gated.steps.prepare.outputs.work, 'export/policy-diff.json'), 'utf8'));
  assert.deepEqual([saved.changes, saved.gapCounts], [[], { 'gap-added': 1 }]);
  const moved = await runAction({ ...inputs, 'policy-matrix': 'policy/gap-moved.json' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(moved.steps['policy-diff'].outputs['policy-diff-exit'], '0');
  assert.deepEqual([moved.outputs['policy-diff'], moved.steps.summary.outputs.decision], ['clean', 'pass']);
  assert.equal(moved.logs.find(log => log.name === 'Apply fail-on').code, 0);
});

test('policy matrix inputs are validated in the prepare step', async () => {
  await mkdir(join(workspace, 'policy'), { recursive: true });
  await writeFile(join(workspace, 'policy/before.json'), JSON.stringify(policyBefore()));
  await symlink(join(workspace, 'policy/before.json'), join(workspace, 'policy/link.json')).catch(error => { if (error.code !== 'EEXIST') throw error; });
  const base = { authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-baseline.json' };
  for (const [label, inputs, message] of [
    ['one matrix only', { 'policy-matrix': 'policy/before.json' }, /set policy-baseline-matrix and policy-matrix together/],
    ['invalid opt-in', { 'fail-on-policy-diff': 'yes' }, /fail-on-policy-diff must be true or false/],
    ['opt-in without matrices', { 'fail-on-policy-diff': 'true' }, /fail-on-policy-diff needs policy-baseline-matrix and policy-matrix/],
    ['a symlinked matrix', { 'policy-baseline-matrix': 'policy/before.json', 'policy-matrix': 'policy/link.json' }, /policy matrices must be existing regular files, not symlinks/],
    ['a missing matrix', { 'policy-baseline-matrix': 'policy/before.json', 'policy-matrix': 'policy/nope.json' }, /policy matrices must be existing regular files/],
    ['a directory', { 'policy-baseline-matrix': 'policy', 'policy-matrix': 'policy/before.json' }, /policy matrices must be existing regular files/]]) {
    const result = await runAction({ ...base, ...inputs }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(result.steps.prepare.outcome, 'failure', label);
    assert.match(result.logs[0].stdout, message, label);
    assert.equal(result.steps.assess.outcome, 'skipped', label);
    assert.equal(result.steps.summary.outputs.decision, 'fail', label);
  }
});

// No hosted actions, upload, provider or real model: the model responses below
// are fixed local stubs and the application under test is synthetic.
test('the minimal environment does not inherit the outer NODE_OPTIONS', () => {
  assert.equal(Object.hasOwn(baseEnv, 'NODE_OPTIONS'), false);
});

test('the README inputs table lists every action input, and no stale strict-mode claim remains', async () => {
  const readme = await readFile(join(here, 'README.md'), 'utf8');
  const table = readme.slice(readme.indexOf('## Inputs'), readme.indexOf('## Outputs'));
  for (const key of Object.keys(action.inputs)) assert.match(table, new RegExp(`^\\| \`${key}\` \\|`, 'm'), `input ${key}`);
  assert.doesNotMatch(readme, /cannot occur here|has no input for `--require-model-identity`/);
  for (const name of Object.values(OWNED_TAP_ENV)) assert.ok(readme.includes(name), name);
});

test('strict action validates its flag, with or without a baseline, and refuses a missing baseline', async () => {
  for (const flag of ['TRUE', 'yes', '1', 'true']) {
    const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', 'require-model-identity': flag }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(result.steps.prepare.outcome, 'failure', flag);
    assert.equal(result.steps.assess.outcome, 'skipped', flag);
    assert.equal(result.failed, true, flag);
  }
  // With a baseline present, only the flag check can refuse these values.
  for (const flag of ['TRUE', 'yes', '1']) {
    const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', 'baseline-run': firstRun, 'require-model-identity': flag }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(result.steps.prepare.outcome, 'failure', flag);
    assert.match(result.logs[0].stdout, /require-model-identity must be true or false/, flag);
    assert.equal(result.steps.assess.outcome, 'skipped', flag);
  }
});

test('strict action passes the gate flag and rejects absent identity even in report-only mode', async () => {
  const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', 'baseline-run': firstRun, 'require-model-identity': 'true', 'fail-on': 'never' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(result.steps.assess.outputs['gate-exit'], '1');
  assert.equal(result.steps.summary.outputs.decision, 'fail');
  assert.equal(result.steps.summary.outputs['decision-reason'], 'model-identity-not-recorded');
  assert.equal(result.failed, true);
  const summary = JSON.parse(await readFile(join(result.steps.prepare.outputs.work, 'export/gate-summary.json'), 'utf8'));
  assert.ok(summary.reasons.includes('model-identity-not-recorded'));
  assert.match(result.summary, /Model identity policy not met: baseline `identity-absent`, candidate `identity-absent`/);
});

// A free loopback port for the tap the gate starts. The application is configured with it
// before the gate runs, as an operator configures an application's model base URL.
async function freePort() {
  const probe = createServer();
  await new Promise(done => probe.listen(0, '127.0.0.1', done));
  const { port } = probe.address();
  await new Promise(done => probe.close(done));
  return port;
}
// The synthetic application calls its model through the tap port at /boundary, and nothing
// else: it never starts, stops, marks or reads the tap. The model stub's answer is fixed.
async function modelServedLab(t) {
  const state = { served: 'scopehaven-fixed-local-stub', fingerprint: 'fixed-stub-fingerprint', repaired: false };
  const model = createHttpServer(async (req, res) => {
    for await (const _chunk of req) {} // Discard synthetic request content.
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ model: state.served, system_fingerprint: state.fingerprint, choices: [{ message: { content: 'synthetic' } }] }));
  });
  await new Promise(done => model.listen(0, '127.0.0.1', done));
  t.after(() => new Promise(done => { model.close(done); model.closeAllConnections(); }));
  const tapPort = await freePort();
  const app = createHttpServer(async (req, res) => {
    let status = 200;
    if (req.url === '/boundary') {
      try { await postModel(tapPort); status = state.repaired ? 403 : 200; } catch { status = 502; }
    }
    res.writeHead(status, { 'Content-Type': 'application/json' }); res.end('{}');
  });
  await new Promise(done => app.listen(0, '127.0.0.1', done));
  t.after(() => new Promise(done => { app.close(done); app.closeAllConnections(); }));
  const target = buildLabel => ({ id: 'identity-stub', name: 'Synthetic identity action target', applicationId: 'identity-stub', origin: `http://127.0.0.1:${app.address().port}`, buildLabel, contextId: 'stub-context', actors: { anonymous: { principalId: 'anonymous' } }, requiredControlIds: ['allowed'], checks: [
    { id: 'allowed', title: 'Allowed', category: 'Synthetic', severity: 'control', actorId: 'anonymous', method: 'GET', path: '/allowed', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'boundary', title: 'Boundary', category: 'Synthetic', severity: 'high', actorId: 'anonymous', method: 'GET', path: '/boundary', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
  ] });
  const profile = async build => { const path = join(workspace, `stub-profile-${build}.json`); await writeFile(path, JSON.stringify({ schemaVersion: 1, targets: [target(build)] })); return path; };
  const tapEnv = { [OWNED_TAP_ENV.upstream]: `http://127.0.0.1:${model.address().port}`, [OWNED_TAP_ENV.port]: String(tapPort), [OWNED_TAP_ENV.ollamaTags]: 'false' };
  // The authorization record covers the application and the owned tap's model upstream, which the run forwards to.
  const authorization = writeTestAuthorization(join(workspace, `stub-authorization-${tapPort}.json`), target('any'), { origins: [tapEnv[OWNED_TAP_ENV.upstream]] });
  return { state, profile, tapEnv, tapPort, authorization, modelOrigin: `http://127.0.0.1:${model.address().port}` };
}
// One model call on a fresh connection (no pooled socket outlives a tap that stopped).
function postModel(port) {
  const body = JSON.stringify({ model: 'stub-request', messages: [{ role: 'user', content: 'synthetic' }], stream: false });
  return new Promise((done, fail) => {
    const req = httpRequest({ host: '127.0.0.1', port, path: '/v1/chat/completions', method: 'POST', agent: false, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => res.statusCode === 200 ? done(JSON.parse(Buffer.concat(chunks).toString('utf8'))) : fail(new Error(`model status ${res.statusCode}`))); res.on('error', fail);
    });
    req.on('error', fail); req.end(body);
  });
}

test('the gate the action runs holds the model tap itself: strict passes an unchanged model and fails a swap, with no app cooperation', async t => {
  const { state, profile, tapEnv, authorization } = await modelServedLab(t);
  const env = { ...baseEnv, ...tapEnv };
  // Baseline: scopehaven assess, unrepaired build. The launcher process starts, marks and stops the tap.
  const before = await runAction({ authorization, profile: await profile('before'), 'fail-on': 'never' }, { workspace, runnerTemp, env });
  assert.equal(before.failed, false);
  const baselinePath = join(before.steps.prepare.outputs.work, 'export/run.json');
  const baseline = JSON.parse(await readFile(baselinePath, 'utf8'));
  assert.deepEqual([baseline.modelIdentity.state, baseline.modelIdentity.strength, baseline.modelIdentity.custody], ['observed', 'vendor-fingerprint', 'tap-memory']);
  assert.equal(baseline.modelIdentity.models[0].served, 'scopehaven-fixed-local-stub');
  state.repaired = true;
  const after = await runAction({ authorization, profile: await profile('after'), 'baseline-run': baselinePath, 'require-model-identity': 'true' }, { workspace, runnerTemp, env });
  const saved = JSON.parse(await readFile(join(after.steps.prepare.outputs.work, 'export/run.json'), 'utf8'));
  assert.deepEqual([saved.modelIdentity.state, saved.modelIdentity.custody, saved.modelIdentity.calls.total], ['observed', 'tap-memory', 1]);
  assert.equal(after.steps.assess.outputs['gate-exit'], '0');
  assert.equal(after.steps.summary.outputs.decision, 'pass');
  assert.equal(after.failed, false);
  assert.match(after.summary, /Model identity policy: `true`\. Both HTTP runs need/);
  assert.match(after.summary, /as the model upstream reported it to the tap/);
  assert.doesNotMatch(after.summary, /Model identity policy not met/);
  // The model behind the same name and port changes; the application's build label changes too.
  state.served = 'scopehaven-other-local-stub'; state.fingerprint = 'other-stub-fingerprint';
  const swapped = await runAction({ authorization, profile: await profile('after-swap'), 'baseline-run': baselinePath, 'require-model-identity': 'true' }, { workspace, runnerTemp, env });
  assert.equal(swapped.steps.assess.outputs['gate-exit'], '1');
  const gate = JSON.parse(await readFile(join(swapped.steps.prepare.outputs.work, 'export/gate-summary.json'), 'utf8'));
  assert.deepEqual(gate.reasons, ['repair-not-attributable']);
  assert.deepEqual(gate.comparison.modelIdentityPolicy, { required: true, met: true, causes: [] });
  assert.equal(gate.comparison.modelAttribution.relation, 'different');
  assert.deepEqual([swapped.steps.summary.outputs.decision, swapped.steps.summary.outputs['decision-reason']], ['fail', 'gate-repair-not-attributable']);
  assert.equal(swapped.failed, true);
});

test('a tap log file read under the strict policy fails as subject-writable custody, and the summary says why', async t => {
  const { state, profile, tapPort, modelOrigin, authorization } = await modelServedLab(t);
  // An operator-run tap on the same port writing a log file: the file route.
  const runWithFileTap = async (build, inputs) => {
    const logPath = join(workspace, `stub-tap-${build}.jsonl`);
    const tap = createModelTap({ upstream: modelOrigin, port: tapPort, ollamaTags: false, log: new TapLog({ path: logPath }) });
    await tap.start();
    try { return await runAction({ authorization, profile: await profile(build), ...inputs }, { workspace, runnerTemp, env: { ...baseEnv, SCOPEHAVEN_MODEL_TAP_LOG: logPath } }); }
    finally { await tap.stop(); }
  };
  const before = await runWithFileTap('file-before', { 'fail-on': 'never' });
  const baselinePath = join(before.steps.prepare.outputs.work, 'export/run.json');
  const baseline = JSON.parse(await readFile(baselinePath, 'utf8'));
  // Nothing closes an operator-run tap before the run ends: the reading is partial and says why.
  assert.deepEqual([baseline.modelIdentity.state, baseline.modelIdentity.custody, baseline.modelIdentity.reasons], ['partial', 'tap-file', ['tap-log-not-closed-at-end']]);
  state.repaired = true;
  const after = await runWithFileTap('file-after', { 'baseline-run': baselinePath, 'require-model-identity': 'true' });
  assert.equal(after.steps.assess.outputs['gate-exit'], '1');
  assert.deepEqual([after.steps.summary.outputs.decision, after.steps.summary.outputs['decision-reason']], ['fail', 'model-identity-unverified']);
  assert.match(after.summary, /Model identity policy not met: baseline `subject-writable-custody`, baseline `model-partial`, baseline `tap-log-not-closed-at-end`, candidate `subject-writable-custody`/);
  const gate = JSON.parse(await readFile(join(after.steps.prepare.outputs.work, 'export/gate-summary.json'), 'utf8'));
  assert.equal(gate.comparison.modelIdentityPolicy.met, false);
  assert.ok(gate.comparison.modelIdentityPolicy.causes.some(c => c.side === 'candidate' && c.reason === 'subject-writable-custody'));
});

// ---- Report-only (the report-only and report-only-until inputs; ../regression-gate/report-only.mjs). ----
const utcDay = offset => new Date(Date.parse(`${new Date().toISOString().slice(0, 10)}T00:00:00Z`) + offset * 86400000).toISOString().slice(0, 10);
const RESULT_MARK = '[REPORT-ONLY run: not a pass] ';

test('report-only inputs are validated in the prepare step, before any request', async () => {
  for (const [inputs, message] of [
    [{ 'report-only': 'true' }, /report-only refused \(report-only-window-invalid\)/],
    [{ 'report-only': 'true', 'report-only-until': '2026-02-30' }, /report-only refused \(report-only-window-invalid\)/],
    [{ 'report-only': 'true', 'report-only-until': utcDay(91) }, /report-only refused \(report-only-window-too-long\)/],
    [{ 'report-only-until': utcDay(10) }, /report-only-until needs report-only: true/],
    [{ 'report-only': 'yes', 'report-only-until': utcDay(10) }, /report-only must be true or false/],
  ]) {
    const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-baseline.json', ...inputs }, { workspace, runnerTemp, env: baseEnv });
    const label = JSON.stringify(inputs);
    assert.equal(result.steps.prepare.outcome, 'failure', label);
    assert.match(result.logs[0].stdout, message, label);
    assert.equal(result.steps.assess.outcome, 'skipped', label);
    assert.equal(result.steps.summary.outputs.decision, 'fail', label);
    assert.equal(result.outputs['report-only'], 'off', label);
    assert.equal(result.failed, true, label);
  }
});

test('report-only on the assess path: failed checks keep the job green through the date, and every report says REPORT-ONLY', async () => {
  const until = utcDay(30);
  const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-baseline.json', 'report-only': 'true', 'report-only-until': until }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(result.steps.prepare.outputs['report-only'], 'applied');
  assert.equal(result.steps.assess.outputs['assess-exit'], '1');
  assert.equal(result.steps.export.outputs['report-only-marked'], 'true');
  assert.equal(result.steps.summary.outputs.decision, 'pass');
  assert.equal(result.steps.summary.outputs['decision-reason'], 'report-only');
  assert.equal(result.steps.summary.outputs['would-fail'], 'checks-failed');
  assert.equal(result.outputs['report-only'], 'applied');
  assert.equal(result.failed, false);
  const apply = result.logs.find(log => log.name === 'Apply fail-on');
  assert.equal(apply.code, 0);
  assert.match(apply.stdout, /^::warning::Scopehaven REPORT-ONLY run: without report-only this job would fail \(checks-failed\)\. Not a pass\.$/m);
  assert.match(result.summary, new RegExp(`^> \\*\\*REPORT-ONLY RUN\\*\\* through ${until} \\(UTC\\)\\. Until then this job does not fail on what the checks find, so a green job is not a pass: .* Without report-only this job would fail \\(\`checks-failed\`\\)\\.`, 'm'));
  assert.match(result.summary, /fail-on `fail`, report-only `applied`: \*\*pass\*\* \(`report-only`; would fail: `checks-failed`\)/);
  // The real results are shown as recorded.
  assert.match(result.summary, /^\| fail \| 2 \|$/m);
  assert.match(result.summary, /\| FOREIGN-STATUS \| The foreign-record endpoint returns a denial \| high \| fail \|/);
  const work = result.steps.prepare.outputs.work;
  assert.deepEqual((await readdir(join(work, 'export'))).sort(), ['report.html', 'run.json', 'scopehaven.sarif', 'summary.md']);
  const html = await readFile(join(work, 'export/report.html'), 'utf8');
  assert.match(html, /<title>REPORT-ONLY · Scopehaven assessment /);
  assert.match(html, new RegExp(`<div class="report-only" role="note">REPORT-ONLY RUN\\. Report-only run \\(through ${until} UTC\\)`));
  assert.equal(html.split('<article><p class="report-only-tag">REPORT-ONLY run: not a pass.</p>').length - 1, 7);
  const sarif = JSON.parse(await readFile(result.outputs['sarif-path'], 'utf8'));
  assert.ok(sarif.runs[0].results.every(row => row.message.text.startsWith(RESULT_MARK)));
  assert.equal(sarif.runs[0].results.filter(row => row.kind === 'fail').length, 2, 'kinds as recorded');
  assert.equal(sarif.runs[0].properties.reportOnly.until, until);
  // run.json is the recorded run: unmarked, and still a valid baseline.
  const recorded = await readFile(join(work, 'export/run.json'), 'utf8');
  assert.doesNotMatch(recorded, /REPORT-ONLY/);
  assert.equal(baselineRecord(JSON.parse(recorded)).core.counts.fail, 2);
});

test('report-only after its date: the same failed checks fail the job, and nothing is marked', async () => {
  const until = utcDay(-1);
  const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-baseline.json', 'report-only': 'true', 'report-only-until': until }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(result.steps.prepare.outputs['report-only'], 'ended');
  assert.equal(result.steps.export.outputs['report-only-marked'], undefined);
  assert.equal(result.steps.summary.outputs.decision, 'fail');
  assert.equal(result.steps.summary.outputs['decision-reason'], 'checks-failed');
  assert.equal(result.outputs['report-only'], 'ended');
  assert.equal(result.failed, true);
  assert.match(result.summary, new RegExp(`^> \\*\\*Report-only window ended\\*\\* \\(\`report-only-until\` ${until}\\): this job follows \`fail-on\` again\\.$`, 'm'));
  const apply = result.logs.find(log => log.name === 'Apply fail-on');
  assert.equal(apply.code, 1); assert.doesNotMatch(apply.stdout, /REPORT-ONLY/);
  const work = result.steps.prepare.outputs.work;
  assert.doesNotMatch(await readFile(join(work, 'export/report.html'), 'utf8'), /REPORT-ONLY/);
  assert.doesNotMatch(await readFile(join(work, 'export/scopehaven.sarif'), 'utf8'), /REPORT-ONLY/);
});

test('report-only on the gate path: the gate records its window beside the real verdict, and the comparison is marked', async () => {
  assert.ok(firstRun, 'depends on the end-to-end baseline test');
  lab.setBuild('repaired');
  try {
    const until = utcDay(30);
    const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', 'baseline-run': firstRun, 'report-only': 'true', 'report-only-until': until }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(result.steps.assess.outputs['gate-exit'], '0', 'the gate exits 0 for an assessment-failed verdict while the window applies');
    const work = result.steps.prepare.outputs.work;
    const gate = JSON.parse(await readFile(join(work, 'export/gate-summary.json'), 'utf8'));
    assert.equal(gate.outcome, 'assessment-failed'); assert.equal(gate.exitCode, 1); assert.ok(gate.reasons.includes('inconclusive-evidence'));
    assert.deepEqual([gate.reportOnly.state, gate.reportOnly.until, gate.reportOnly.exitCode], ['applied', until, 0]);
    assert.equal(result.outputs['gate-verdict'], 'assessment-failed');
    assert.equal(result.steps.summary.outputs.decision, 'pass');
    assert.equal(result.steps.summary.outputs['would-fail'], 'gate-inconclusive-evidence');
    assert.match(result.summary, /Verdict: \*\*assessment-failed\*\* \(exit 1\)/);
    assert.match(await readFile(join(work, 'export/comparison.html'), 'utf8'), /<title>REPORT-ONLY · Scopehaven comparison [\s\S]*<div class="report-only" role="note">REPORT-ONLY RUN\./);
    assert.match(await readFile(join(work, 'export/report.html'), 'utf8'), /<title>REPORT-ONLY · /);
    assert.ok(JSON.parse(await readFile(join(work, 'export/scopehaven.sarif'), 'utf8')).runs[0].results.every(row => row.message.text.startsWith(RESULT_MARK)));
    // The export step alone, on the same saved runs, when the gate's own window had ended (the date passed between the
    // steps): nothing is marked and report-only-marked is false, so the summary step does not relax the job.
    const again = join(runnerTemp, `export-again-${Date.now()}`);
    await mkdir(join(again, 'export'), { recursive: true, mode: 0o700 }); await chmod(again, 0o700);
    await writeFile(join(again, 'export/gate-summary.json'), JSON.stringify({ ...gate, reportOnly: { ...gate.reportOnly, state: 'ended', endedBy: 'date-passed', exitCode: 1 } }));
    const exportStep = await runStep('export', { SH_ROOT: root, SH_WORK: again, SH_STORE: result.steps.assess.outputs.store, SH_RUN_ID: result.outputs['run-id'],
      SH_BASELINE_ID: result.steps.assess.outputs['baseline-id'], SH_REPORT_ONLY: 'applied', SH_REPORT_ONLY_UNTIL: until });
    assert.equal(exportStep.code, 0);
    assert.equal(exportStep.outputs['report-only-marked'], 'false');
    assert.match(exportStep.stdout, /::warning::Scopehaven report-only: report\.html was not marked REPORT-ONLY, so fail-on applies to this job/);
    assert.doesNotMatch(await readFile(join(again, 'export/report.html'), 'utf8'), /REPORT-ONLY/);
    assert.doesNotMatch(await readFile(join(again, 'export/comparison.html'), 'utf8'), /REPORT-ONLY/);
  } finally { lab.setBuild('baseline'); }
});

// 6d: the strict policy on a real comparison under report-only (the gate's reasons are relaxed; the recomputed policy is not).
test('report-only never relaxes the strict model identity policy on a real gate comparison', async () => {
  assert.ok(firstRun, 'depends on the end-to-end baseline test');
  const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', 'baseline-run': firstRun, 'require-model-identity': 'true', 'report-only': 'true', 'report-only-until': utcDay(30) },
    { workspace, runnerTemp, env: baseEnv });
  assert.equal(result.steps.assess.outputs['gate-exit'], '0', 'the gate itself relaxes its exit under report-only');
  assert.equal(result.steps.summary.outputs.decision, 'fail');
  assert.equal(result.steps.summary.outputs['decision-reason'], 'model-identity-not-recorded');
  assert.equal(result.outputs['report-only'], 'applied');
  assert.equal(result.failed, true);
});

test('summary.mjs report-only never relaxes a setup error, an errored check, an unmarked report, a gate that did not apply it, or the strict policy', () => {
  const failed = { decision: 'fail', reason: 'checks-failed' }, on = { reportOnly: 'applied', marked: 'true' };
  for (const reason of ['checks-failed', 'required-controls-not-passed', 'identity-not-established', 'assessment-not-clean', 'checks-inconclusive'])
    assert.deepEqual(decideReportOnly({ decision: 'fail', reason }, on), { decision: 'pass', reason: 'report-only', wouldFail: reason, state: 'applied' }, reason);
  for (const reason of ['checks-errored', 'assessment-setup-error', 'evidence-unavailable', 'gate-unavailable', 'gate-setup-error', 'invalid-fail-on'])
    assert.deepEqual(decideReportOnly({ decision: 'fail', reason }, on), { decision: 'fail', reason, state: 'applied' }, reason);
  assert.deepEqual(decideReportOnly({ decision: 'pass', reason: 'clean' }, on), { decision: 'pass', reason: 'clean', state: 'applied' });
  // A gate reason is relaxed for a gate verdict of assessment-failed (exit 1) the gate applied the window to, never for exit 2.
  const gate = (exitCode, state = 'applied') => ({ exitCode, reasons: ['x'], reportOnly: state ? { state } : null });
  assert.equal(decideReportOnly({ decision: 'fail', reason: 'gate-checks-failed' }, { ...on, gateRequested: true, gate: gate(1) }).reason, 'report-only');
  assert.deepEqual(decideReportOnly({ decision: 'fail', reason: 'gate-runner-error' }, { ...on, gateRequested: true, gate: gate(2) }), { decision: 'fail', reason: 'gate-runner-error', state: 'applied' });
  for (const other of [gate(1, 'ended'), gate(1, 'unrecognized'), gate(1, null), null])
    assert.deepEqual(decideReportOnly({ decision: 'fail', reason: 'gate-checks-failed' }, { ...on, gateRequested: true, gate: other }), { decision: 'fail', reason: 'gate-checks-failed', state: 'not-applied' }, JSON.stringify(other));
  for (const marked of ['false', '', 'TRUE']) assert.deepEqual(decideReportOnly(failed, { reportOnly: 'applied', marked }), { ...failed, state: 'not-applied' }, marked);
  // A gate that exited 2, or an assess exit other than 0 or 1, is never relaxed, whatever the run-level reason.
  assert.deepEqual(decideReportOnly(failed, { ...on, gateRequested: true, gate: gate(2) }), { ...failed, state: 'applied' });
  assert.deepEqual(decideReportOnly(failed, { ...on, gateRequested: true, gate: gate(0) }), { ...failed, state: 'applied' });
  assert.deepEqual(decideReportOnly({ decision: 'fail', reason: 'assessment-not-clean' }, { ...on, assessExit: 137 }), { decision: 'fail', reason: 'assessment-not-clean', state: 'applied' });
  assert.equal(decideReportOnly(failed, { ...on, assessExit: 1 }).reason, 'report-only');
  assert.deepEqual(decideReportOnly(failed, { reportOnly: 'ended', marked: 'true' }), { ...failed, state: 'ended' });
  assert.deepEqual(decideReportOnly(failed, { reportOnly: 'off' }), { ...failed, state: 'off' });
  assert.deepEqual(decideReportOnly({ decision: 'pass', reason: 'clean' }, { reportOnly: 'on' }), { decision: 'fail', reason: 'invalid-report-only', state: 'invalid' });
  // buildReport: the strict model identity policy and the opted-in policy diff still fail a relaxed job.
  const runInput = { id: '00000000-0000-4000-8000-000000000009', requiredControlIds: ['ctl'], results: [{ id: 'ctl', severity: 'control', status: 'pass' }, { id: 'idor', severity: 'critical', status: 'fail' }] };
  const base = { runInput, reportOnly: 'applied', reportOnlyUntil: '2026-11-30', reportOnlyMarked: 'true', env: {} };
  const relaxed = buildReport(base);
  assert.equal(relaxed.reason, 'report-only'); assert.equal(relaxed.reportOnly, 'applied');
  assert.match(relaxed.outputs, /^report-only=applied\nwould-fail=checks-failed$/m);
  assert.match(relaxed.markdown, /^## Scopehaven assessment\n\n> \*\*REPORT-ONLY RUN\*\* through 2026-11-30 \(UTC\)\./);
  assert.equal(buildReport({ ...base, requireModelIdentity: 'true' }).reason, 'model-identity-baseline-required');
  assert.equal(buildReport({ ...base, failOnPolicyDiff: 'true' }).reason, 'policy-diff-not-requested');
  // The same case end to end: an errored baseline makes the gate exit 2 while the current run has a failed check.
  const gateExit2 = { schemaVersion: 1, reportOnly: { mode: 'report-only', state: 'applied' }, outcome: 'config-or-runtime-error', exitCode: 2, reasons: ['runner-error'], current: { runId: runInput.id }, comparison: null };
  assert.deepEqual([buildReport({ ...base, gateInput: gateExit2, gateState: 'ok' }).decision, buildReport({ ...base, gateInput: gateExit2, gateState: 'ok' }).reason], ['fail', 'checks-failed']);
  assert.equal(buildReport({ ...base, assessExit: 2 }).reason, 'assessment-setup-error');
  const unmarked = buildReport({ ...base, reportOnlyMarked: 'false' });
  assert.equal(unmarked.reason, 'checks-failed'); assert.match(unmarked.outputs, /^would-fail=$/m);
  assert.match(unmarked.markdown, /^> \*\*Report-only not applied\*\*: requested through 2026-11-30, but not every report and SARIF file was marked REPORT-ONLY, so this job follows `fail-on`\.$/m);
  // A date the summary cannot read is never printed.
  assert.match(buildReport({ ...base, reportOnlyUntil: '2026-11-30\n## injected' }).markdown, /through an unreadable date \(UTC\)/);
  assert.doesNotMatch(buildReport({ ...base, reportOnlyUntil: '2026-11-30\n## injected' }).markdown, /injected/);
  assert.equal(buildReport({ runInput, env: {} }).reportOnly, 'off');
  assert.doesNotMatch(buildReport({ runInput, env: {} }).markdown, /REPORT-ONLY|Report-only/);
});
// self-test: --self-test on assess and the gate (docs/SELF-TEST.md). A check that cannot fail fails the job though
// every check passed; the counts are unchanged and the report goes into the evidence artifact.
test('self-test: true runs the known-negative self-test first; a check that cannot fail fails the job, assess or gate, with unchanged counts', async () => {
  assert.equal(action.inputs['self-test'].default, 'false', 'off unless the operator opts in');
  lab.setBuild('repaired');
  try {
    const base = makeLabProfile(lab.origin, 'lab-repaired');
    const vacuous = { id: 'VACUOUS', title: 'The member page answers', category: 'Local application contracts', severity: 'high', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '', expected: true }] };
    await writeFile(join(workspace, 'profiles/lab-vacuous.json'), JSON.stringify({ schemaVersion: 1, targets: [{ ...base, checks: [...base.checks.filter(c => c.id !== 'BACKEND-UNVERIFIED'), vacuous] }] }));
    const inputs = { authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-vacuous.json' };
    const plain = await runAction(inputs, { workspace, runnerTemp, env: baseEnv });
    assert.deepEqual([plain.steps.assess.outputs['assess-exit'], plain.steps.summary.outputs.decision], ['0', 'pass'], 'every check passes without the self-test');
    assert.ok(!(await readdir(join(plain.steps.prepare.outputs.work, 'export'))).includes('assess.json'));
    const tested = await runAction({ ...inputs, 'self-test': 'true' }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(tested.steps.assess.outputs['assess-exit'], '1');
    assert.deepEqual(JSON.parse(tested.outputs['status-counts']), JSON.parse(plain.outputs['status-counts']));
    assert.deepEqual([tested.steps.summary.outputs.decision, tested.steps.summary.outputs['decision-reason']], ['fail', 'assessment-not-clean']);
    const printed = JSON.parse(await readFile(join(tested.steps.prepare.outputs.work, 'export/assess.json'), 'utf8'));
    assert.deepEqual(printed.selfTest.checks.filter(c => c.outcome === 'broken').map(c => c.id), ['VACUOUS']);
    for (const secret of [lab.memberToken, FAKE_SECRET, 'SYNTHETIC_PRIVATE_RESPONSE_DO_NOT_STORE']) assert.ok(!JSON.stringify(printed).includes(secret));
    // The gate path, against the run made without the self-test: the self-test's reason is the gate's only one.
    const baselineRun = join(plain.steps.prepare.outputs.work, 'export/run.json');
    const gated = await runAction({ ...inputs, 'self-test': 'true', 'baseline-run': baselineRun }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(gated.steps.assess.outputs['gate-exit'], '1');
    const gate = JSON.parse(await readFile(join(gated.steps.prepare.outputs.work, 'export/gate-summary.json'), 'utf8'));
    assert.deepEqual([gate.reasons, gate.selfTest.outcome, gate.comparison.compatibility], [['check-cannot-fail'], 'broken', 'compatible']);
    assert.deepEqual([gated.steps.summary.outputs.decision, gated.steps.summary.outputs['decision-reason']], ['fail', 'gate-check-cannot-fail']);
    assert.match(gated.summary, /Reasons: `check-cannot-fail`/);
    // A value other than true or false stops in the prepare step.
    const invalid = await runAction({ ...inputs, 'self-test': 'yes' }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(invalid.steps.prepare.outcome, 'failure');
    assert.match(invalid.logs[0].stdout, /self-test must be true or false/);
    assert.equal(invalid.steps.assess.outcome, 'skipped');
  } finally { lab.setBuild('baseline'); }
});

// single-identity (docs/ONBOARDING.md "Two identities by default"): assess refuses a tenant-scoped profile with
// fewer than two identities in distinct declared tenants (exit 2) before anything is sent, unless the input waives it.
test('single-identity: assess refuses a one-identity tenant-scoped profile unless the input waives it; an invalid value stops in prepare', async () => {
  assert.equal(action.inputs['single-identity'].default, 'false', 'off unless the operator opts in');
  lab.setBuild('repaired');
  try {
    const base = makeLabProfile(lab.origin, 'lab-repaired');
    const tenantValues = { tenants: { aster: { identifiers: ['ASTER-REC-1'] }, birch: { identifiers: ['BIRCH-REC-1'] } } };
    const scan = { id: 'OWN-SCAN', title: 'The member\'s own record names no other tenant', category: 'Local application contracts', severity: 'high', actorId: 'member', method: 'GET', path: '/records/own',
      evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '' }] };
    await writeFile(join(workspace, 'profiles/lab-one-identity.json'), JSON.stringify({ schemaVersion: 1, targets: [{ ...base, tenantValues, checks: [...base.checks, scan] }] }));
    const inputs = { authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-one-identity.json' };
    const refused = await runAction(inputs, { workspace, runnerTemp, env: baseEnv });
    assert.equal(refused.steps.assess.outputs['assess-exit'], '2', 'refused before anything is sent');
    const waived = await runAction({ ...inputs, 'single-identity': 'true' }, { workspace, runnerTemp, env: baseEnv });
    assert.notEqual(waived.steps.assess.outputs['assess-exit'], '2', 'the waiver lets assess run');
    assert.notEqual(waived.steps.assess.outputs['assess-exit'], undefined);
    const printed = JSON.parse(await readFile(join(waived.steps.prepare.outputs.work, 'assess.json'), 'utf8'));
    assert.equal(printed.singleIdentity, 'run with --single-identity: cross-tenant checks ran from one side only');
    const invalid = await runAction({ ...inputs, 'single-identity': 'yes' }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(invalid.steps.prepare.outcome, 'failure');
    assert.match(invalid.logs[0].stdout, /single-identity must be true or false/);
    assert.equal(invalid.steps.assess.outcome, 'skipped');
    // The gate takes no waiver: the input with baseline-run stops in the prepare step.
    const gated = await runAction({ ...inputs, 'single-identity': 'true', 'baseline-run': 'baseline.json' }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(gated.steps.prepare.outcome, 'failure');
    assert.match(gated.logs[0].stdout, /single-identity applies to the assess mode only/);
  } finally { lab.setBuild('baseline'); }
});

// ---- Repeated trials: the trials, pass-k and pass-k-floor inputs (gate --trials) ----
const TRIAL_RUNS = ['00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000a3'];
const trialsBlock = (extra = {}) => ({ schema: 'scopehaven-gate-trials/1', trials: 3, k: 1, floor: '9/10', runIds: TRIAL_RUNS,
  readings: { PASS: 1, 'FAIL-flaky': 1, FAIL: 0, 'NOT-PASSED': 0 },
  checks: [{ id: 'OWN-READ', role: 'control', trials: 3, passed: 3, failed: 0, undecided: 0, exact: '1', floor: '9/10', reading: 'PASS' },
    { id: 'FOREIGN-STATUS', role: 'security', trials: 3, passed: 2, failed: 1, undecided: 0, exact: '2/3', floor: '9/10', reading: 'FAIL-flaky' }],
  perTrial: TRIAL_RUNS.map((runId, i) => ({ runId, exitCode: i === 1 ? 1 : 0, reasons: i === 1 ? ['checks-failed'] : [] })),
  passK: {}, scope: ['SCOPE_TEXT_SENTINEL | **never printed**'], ...extra });
const gateWith = (trials, extra = {}) => ({ outcome: 'assessment-failed', exitCode: 1, reasons: ['checks-failed', 'checks-flaky'], current: { runId: TRIAL_RUNS[0] }, trials, ...extra });

test('trials inputs are declared and documented, and invalid ones stop in the prepare step before any request', async () => {
  assert.ok(firstRun, 'depends on the end-to-end baseline test');
  for (const key of ['trials', 'pass-k', 'pass-k-floor']) assert.equal(action.inputs[key].default, '', key);
  const cases = [
    [{ trials: '2' }, /trials needs baseline-run/],
    [{ trials: '2x', 'baseline-run': firstRun }, /trials must be a whole number/],
    [{ trials: '0', 'baseline-run': firstRun }, /trials must be a whole number/],
    [{ 'pass-k': '1' }, /pass-k needs trials/],
    [{ trials: '2', 'baseline-run': firstRun, 'pass-k': '-1' }, /pass-k must be a whole number/],
    [{ 'pass-k-floor': '1' }, /pass-k-floor needs trials/],
    [{ trials: '2', 'baseline-run': firstRun, 'pass-k-floor': '0.9' }, /pass-k-floor must be 1 or a fraction/],
  ];
  for (const [inputs, message] of cases) {
    const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', ...inputs }, { workspace, runnerTemp, env: baseEnv });
    assert.equal(result.steps.prepare.outcome, 'failure', JSON.stringify(inputs));
    assert.match(result.logs.find(log => log.name === 'Prepare Scopehaven workspace').stdout, message, JSON.stringify(inputs));
    assert.equal(result.steps.assess.outcome, 'skipped');
    assert.equal(result.steps.summary.outputs.decision, 'fail');
  }
  // A count of the right shape but out of range passes prepare; the gate refuses it itself (exit 2, trials-invalid) before
  // anything is sent, and the job fails.
  const refused = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', 'baseline-run': firstRun, trials: '101' }, { workspace, runnerTemp, env: baseEnv });
  assert.equal(refused.steps.prepare.outcome, 'success');
  assert.equal(refused.steps.assess.outputs['gate-exit'], '2');
  assert.ok(JSON.parse(await readFile(join(refused.steps.prepare.outputs.work, 'export/gate-summary.json'), 'utf8')).reasons.includes('trials-invalid'));
  assert.equal(refused.steps.summary.outputs.decision, 'fail');
});

test('trials with report-only: the gate\'s marked trials files are copied, the job is relaxed only with every file in the artifact, and a valid floor reaches the gate', async () => {
  assert.ok(firstRun, 'depends on the end-to-end baseline test');
  lab.setBuild('repaired');
  try {
    const until = utcDay(30);
    const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', 'baseline-run': firstRun, 'report-only': 'true', 'report-only-until': until, trials: '2', 'pass-k-floor': '1/2' },
      { workspace, runnerTemp, env: baseEnv });
    const work = result.steps.prepare.outputs.work, store = result.steps.assess.outputs.store, runId = result.outputs['run-id'];
    const gate = JSON.parse(await readFile(join(work, 'export/gate-summary.json'), 'utf8'));
    assert.equal(gate.trials.trials, 2); assert.equal(gate.trials.floor, '1/2'); assert.equal(gate.reportOnly.state, 'applied');
    assert.equal(result.steps.export.outputs['report-only-marked'], 'true');
    assert.equal(result.steps.summary.outputs['report-only'], 'applied');
    assert.equal(result.steps.summary.outputs.decision, 'pass');
    assert.match(result.steps.summary.outputs['would-fail'], /^gate-/);
    assert.notEqual(result.steps.summary.outputs['would-fail'], 'gate-trials-unavailable');
    assert.match(await readFile(join(work, 'export/trials.html'), 'utf8'), /REPORT-ONLY/, 'the gate marked its trials report');
    // The export step alone, with the gate's summary in place but one trials file missing: report-only-marked is false, so
    // the summary step does not relax the job.
    await rename(join(store, 'gate-summaries', `${runId}.trials.sarif`), join(store, 'gate-summaries', `${runId}.trials.sarif.moved`));
    const again = join(runnerTemp, `export-trials-${Date.now()}`);
    await mkdir(join(again, 'export'), { recursive: true, mode: 0o700 }); await chmod(again, 0o700);
    await writeFile(join(again, 'export/gate-summary.json'), JSON.stringify(gate));
    const exportStep = await runStep('export', { SH_ROOT: root, SH_WORK: again, SH_STORE: store, SH_RUN_ID: runId,
      SH_BASELINE_ID: result.steps.assess.outputs['baseline-id'], SH_REPORT_ONLY: 'applied', SH_REPORT_ONLY_UNTIL: until, SH_TRIALS: '2' });
    assert.equal(exportStep.code, 0);
    assert.equal(exportStep.outputs['report-only-marked'], 'false');
    // The missing trials file is the only cause: every other export and mark in the step succeeded, so its one warning is this.
    assert.deepEqual(exportStep.stdout.split('\n').filter(line => line.includes('::warning::')), ['::warning::Scopehaven trials sarif is missing from the evidence artifact (not written by the gate, or not copied)']);
    assert.ok((await readdir(join(again, 'export'))).includes('trials.html'));
  } finally { lab.setBuild('baseline'); }
});

test('trials on the gate path: the gate runs N trials, the summary shows the readings, and the artifact gets the trials report and SARIF', async () => {
  assert.ok(firstRun, 'depends on the end-to-end baseline test');
  lab.setBuild('repaired');
  try {
    const result = await runAction({ authorization: 'profiles/lab.authorization.json', profile: 'profiles/lab-repaired.json', 'baseline-run': firstRun, trials: '2', 'pass-k': '2' },
      { workspace, runnerTemp, env: baseEnv });
    const work = result.steps.prepare.outputs.work;
    const gate = JSON.parse(await readFile(join(work, 'export/gate-summary.json'), 'utf8'));
    assert.equal(gate.trials.trials, 2); assert.equal(gate.trials.k, 2); assert.equal(gate.trials.floor, '1');
    assert.equal(gate.trials.runIds.length, 2);
    assert.equal(gate.trials.runIds[0], result.outputs['run-id']);
    assert.equal(result.outputs['gate-verdict'], gate.outcome);
    // fail-on follows the gate over every trial: the repaired lab keeps a backend-required row inconclusive, so the job fails.
    assert.equal(result.steps.summary.outputs.decision, 'fail');
    assert.match(result.steps.summary.outputs['decision-reason'], /^gate-/);
    assert.notEqual(result.steps.summary.outputs['decision-reason'], 'gate-trials-unavailable');
    const r = gate.trials.readings;
    assert.match(result.summary, new RegExp(`### Repeated trials\\n\\n2 trials, k = 2, floor \`1\`\\. Readings: PASS ${r.PASS}, FAIL-flaky ${r['FAIL-flaky']}, FAIL ${r.FAIL}, NOT-PASSED ${r['NOT-PASSED']}\\.`));
    for (const runId of gate.trials.runIds) assert.ok(result.summary.includes(`\`${runId}\``), runId);
    assert.match(result.summary, /the readings cover every trial/);
    const exported = await readdir(join(work, 'export'));
    for (const file of ['trials.html', 'trials.sarif', 'scopehaven.sarif', 'comparison.html']) assert.ok(exported.includes(file), file);
    assert.equal(JSON.parse(await readFile(join(work, 'export/trials.sarif'), 'utf8')).version, '2.1.0');
    assert.match(await readFile(join(work, 'export/trials.html'), 'utf8'), /Repeated trials: pass\^k per check/);
    assert.equal(result.outputs['sarif-path'], join(work, 'export/scopehaven.sarif'), 'the code scanning upload stays the first trial\'s SARIF');
    for (const file of await allFiles(work)) {
      const text = await readFile(file, 'utf8');
      assert.ok(!text.includes(lab.memberToken) && !text.includes(FAKE_SECRET));
    }
  } finally { lab.setBuild('baseline'); }
});

test('summary.mjs: the trials block is an allowlisted projection; a missing or other-count block fails the job, and report-only never relaxes it', async () => {
  const gate = normalizeGate(gateWith(trialsBlock()));
  assert.deepEqual(gate.trials.readings, { PASS: 1, 'FAIL-flaky': 1, FAIL: 0, 'NOT-PASSED': 0 });
  assert.deepEqual(gate.trials.checks[1], { id: 'FOREIGN-STATUS', reading: 'FAIL-flaky', passed: 2, trials: 3, passK: '2/3', unpaired: false });
  assert.equal(JSON.stringify(gate).includes('SCOPE_TEXT_SENTINEL'), false, 'free text is never projected');
  const odd = normalizeGate(gateWith(trialsBlock({ checks: [{ id: 'x | **y**', reading: 'MAYBE', passed: 'two', trials: 3, exact: '<b>1</b>' }] })));
  assert.deepEqual(odd.trials.checks[0], { id: 'unrecognized', reading: 'unrecognized', passed: null, trials: 3, passK: null, unpaired: false });
  for (const bad of [{ schema: 'other/1' }, { trials: 1 }, { k: 4 }, { floor: '0.9' }, { readings: { PASS: 1 } }, { perTrial: [] }])
    assert.equal(normalizeGate(gateWith(trialsBlock(bad))).trials, null, JSON.stringify(bad));
  const view = { id: '00000000-0000-4000-8000-000000000000', counts: { pass: 3, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }, unrecognized: 0, requiredControlsPassed: true, unprovenActors: 0 };
  const clean = normalizeGate(gateWith(trialsBlock(), { outcome: 'clean', exitCode: 0, reasons: [] }));
  assert.deepEqual(decide({ run: view, gate: clean, gateRequested: true, trials: 3 }), { decision: 'pass', reason: 'clean' });
  assert.deepEqual(decide({ run: view, gate: clean, gateRequested: true, trials: 4 }), { decision: 'fail', reason: 'gate-trials-unavailable' });
  const without = normalizeGate(gateWith(undefined, { outcome: 'clean', exitCode: 0, reasons: [] }));
  assert.deepEqual(decide({ run: view, gate: without, gateRequested: true, trials: 3, failOn: 'never' }), { decision: 'fail', reason: 'gate-trials-unavailable' }, 'whatever fail-on says');
  assert.deepEqual(decide({ run: view, gate: without, gateRequested: true, trials: null }), { decision: 'pass', reason: 'clean' }, 'no trials requested, none needed');
  // A gate that stopped on a setup error is reported as its own reason, not as missing trials.
  const stopped = normalizeGate({ outcome: 'config-or-runtime-error', exitCode: 2, reasons: ['trials-invalid'], current: null });
  assert.deepEqual(decide({ run: view, gate: stopped, gateRequested: true, trials: 3 }), { decision: 'fail', reason: 'gate-trials-invalid' });
  const base = decide({ run: view, gate: { ...without, exitCode: 1, reasons: [], reportOnly: { state: 'applied' } }, gateRequested: true, trials: 3 });
  assert.equal(base.reason, 'gate-trials-unavailable');
  assert.equal(decideReportOnly(base, { reportOnly: 'applied', marked: 'true', gate: { exitCode: 1, reportOnly: { state: 'applied' } }, gateRequested: true, assessExit: null }).decision, 'fail');
  // The rendered section: counts, every trial, the checks that did not read PASS, and no free text.
  const runInput = { core: { schemaVersion: 1, id: TRIAL_RUNS[0], targetId: 'lab', evidenceOrigin: 'local-http-response', results: [{ id: 'FOREIGN-STATUS', title: 'Foreign record', severity: 'high', status: 'pass' }] }, sha256: 'a'.repeat(64) };
  const { markdown, decision, reason } = buildReport({ runInput, gateInput: gateWith(trialsBlock()), gateState: 'ok', trials: 3, env: {} });
  // This bare run declares no required controls, so the run-level check decides first; the trials block was found.
  assert.equal(decision, 'fail'); assert.notEqual(reason, 'gate-trials-unavailable');
  assert.match(markdown, /### Repeated trials\n\n3 trials, k = 1, floor `9\/10`\. Readings: PASS 1, FAIL-flaky 1, FAIL 0, NOT-PASSED 0\./);
  assert.ok(markdown.includes('| 2 | `00000000-0000-4000-8000-0000000000a2` | 1 | `checks-failed` |'));
  assert.ok(markdown.includes('| FOREIGN-STATUS | FAIL-flaky | 2 of 3 | `2/3` |'));
  assert.equal(markdown.includes('| OWN-READ | PASS'), false, 'only checks that did not read PASS are listed');
  assert.equal(markdown.includes('SCOPE_TEXT_SENTINEL'), false);
  const many = buildReport({ runInput, gateInput: gateWith(trialsBlock({ perTrial: TRIAL_RUNS.map(runId => ({ runId, exitCode: 1, reasons: Array.from({ length: 25 }, (_, i) => `r-${i}`) })) })), gateState: 'ok', trials: 3, env: {} });
  assert.ok(many.markdown.includes('`r-19` and 5 more |'), 'a long reason list says how many more');
  const missing = buildReport({ runInput, gateInput: gateWith(undefined), gateState: 'ok', trials: 3, env: {} });
  assert.equal(missing.reason, 'gate-trials-unavailable');
  assert.match(missing.markdown, /\*\*unavailable\*\*: 3 trials were requested, but the gate summary has no trials block for them\./);
  // From the command line: a malformed count is still a request, so the job fails.
  const gateFile = join(scratch, 'gate-without-trials.json'); await writeFile(gateFile, JSON.stringify(gateWith(undefined, { outcome: 'clean', exitCode: 0, reasons: [] })));
  const cli = await run(node, [join(here, 'summary.mjs'), '--format', 'outputs', '--run', firstRun, '--gate', gateFile, '--trials', 'abc'], { env: baseEnv });
  assert.match(cli.stdout, /^decision-reason=gate-trials-unavailable$/m);
});

// ---- Check packs: the pack-updates input (integrations/packs-v2/pull.mjs). The prepare step runs alone here: it reads local
// files only, and a pack profile's assessment is covered by packs-v2/packs.test.mjs. A real pull needs a shipped version newer
// than the pin, which packs.test.mjs makes with a copy of the shipped directory; here every pin is current. ----
const PREPARE_ENV = { SH_TARGET: '', SH_BASELINE_RUN: '', SH_FAIL_ON: 'fail', SH_REPORT_ONLY: 'false', SH_REPORT_ONLY_UNTIL: '', SH_REQUIRE_MODEL_IDENTITY: 'false', SH_SELF_TEST: 'false',
  SH_SINGLE_IDENTITY: 'false', SH_TRIALS: '', SH_PASS_K: '', SH_PASS_K_FLOOR: '', SH_UPLOAD_SARIF: 'false', SH_WAIT_URL: '', SH_WAIT_TIMEOUT: '60', SH_POLICY_BEFORE: '', SH_POLICY_AFTER: '', SH_FAIL_ON_POLICY: 'false',
  // CI mode (ci-mode.test.mjs), off as its defaults are.
  SH_SIGN: 'false', SH_SIGNING_KEY_DIR: '', SH_LEDGER_DIR: '', SH_LEDGER_KEY_DIR: '', SH_LEDGER_RUN_FILES: '', SH_BASELINE_FROM_LEDGER: 'false', SH_PACK_LOCK: '' };
async function packProfile() {
  const dir = await mkdtemp(join(scratch, 'pack profile '));
  const caseTarget = JSON.parse(await readFile(join(root, 'integrations/packs-v2/packs/revocation/cases.json'), 'utf8')).target;
  const whoami = id => ({ id, title: `agentB session is agentB (${id})`, category: 'Identity', severity: 'control', actorId: 'agentB', method: 'GET', path: '/api/me', evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: 'agent-b@globex.test' }] });
  const target = { ...caseTarget, id: 'pack-app', name: 'Pack app', applicationId: 'pack-app', buildLabel: 'pack app, local test build', requiredControlIds: ['B-WHOAMI', 'B-WHOAMI-AFTER'],
    checks: [whoami('B-WHOAMI'), { pack: 'TI' }, whoami('B-WHOAMI-AFTER')],
    packs: [{ name: 'tenant-isolation', version: '1.0.0', as: 'TI', params: { actor: 'agentB', foreignOwner: 'agentA', ownPath: '/api/orders/B-1', foreignPath: '/api/orders/A-1', leakPointer: '/order/customerEmail' } }] };
  const file = join(dir, 'pack-app.targets.json');
  await writeFile(file, JSON.stringify({ schemaVersion: 1, targets: [target] }));
  await lockProfile(file);
  return { file, authorization: writeTestAuthorization(join(dir, 'authorization.json'), target) };
}
const exists = path => stat(path).then(() => true, () => false);

test('pack-updates: report lists each pin and the shipped packs not used; pull with every pin current keeps the committed profile; a profile without packs is unaffected', async () => {
  assert.equal(action.inputs['pack-updates'].default, 'report', 'report unless the operator opts in to pull');
  const { file, authorization } = await packProfile();
  const env = (extra = {}) => ({ ...PREPARE_ENV, SH_PROFILE: file, SH_AUTHORIZATION: authorization, RUNNER_TEMP: runnerTemp, ...extra });
  const report = await runStep('prepare', env({ SH_PACK_UPDATES: 'report' }));
  assert.equal(report.code, 0, report.stdout + report.stderr);
  assert.equal(report.outputs.profile, file);
  const status = JSON.parse(await readFile(join(report.outputs.work, 'export/pack-status.json'), 'utf8'));
  assert.deepEqual(status.packs.map(p => [p.as, p.name, p.pinned, p.state]), [['TI', 'tenant-isolation', '1.0.0', 'current']]);
  assert.ok(status.unused.some(u => u.name === 'refund-window'));
  assert.equal(await exists(join(report.outputs.work, 'export/pack-pull.json')), false, 'report pulls nothing');
  const summaryArgs = ['--format', 'markdown', '--run', '', '--pack-status', join(report.outputs.work, 'export/pack-status.json')];
  const markdown = (await run(node, [join(here, 'summary.mjs'), ...summaryArgs])).stdout;
  assert.match(markdown, /### Check packs[\s\S]*\| `pack-app` \| `TI` \| `tenant-isolation` \| `1\.0\.0` \| `1\.0\.0` \| current \|/);
  assert.match(markdown, /Shipped packs this profile does not use: .*`refund-window@1\.0\.0`/);
  const pull = await runStep('prepare', env({ SH_PACK_UPDATES: 'pull' }));
  assert.equal(pull.code, 0, pull.stdout + pull.stderr);
  assert.equal(pull.outputs.profile, file, 'nothing to pull: the committed profile is assessed');
  assert.deepEqual(JSON.parse(await readFile(join(pull.outputs.work, 'export/pack-pull.json'), 'utf8')).pulled, []);
  const off = await runStep('prepare', env({ SH_PACK_UPDATES: 'off' }));
  assert.equal(off.code, 0);
  assert.equal(await exists(join(off.outputs.work, 'export/pack-status.json')), false);
  const plain = await runStep('prepare', env({ SH_PACK_UPDATES: 'pull', SH_PROFILE: join(workspace, 'profiles/lab-baseline.json'), SH_AUTHORIZATION: join(workspace, 'profiles/lab.authorization.json') }));
  assert.equal(plain.code, 0, plain.stdout + plain.stderr);
  assert.equal(await exists(join(plain.outputs.work, 'export/pack-status.json')), false, 'a profile without packs is unaffected');
  assert.doesNotMatch(plain.stdout, /::warning::/);
});

test('pack-updates: an invalid value, or pull with baseline-run, pack-lock or baseline-from-ledger, stops in the prepare step before any request', async () => {
  const { file, authorization } = await packProfile();
  // The lock path does not exist and no ledger is set: the pull refusal comes first, with the other input checks, before any file is read.
  const withLock = /pack-updates pull cannot be combined with pack-lock or baseline-from-ledger/;
  for (const [extra, message] of [[{ SH_PACK_UPDATES: 'latest' }, /pack-updates must be report, pull or off/], [{ SH_PACK_UPDATES: 'pull', SH_BASELINE_RUN: 'baseline.json' }, /pack-updates pull applies to the assess mode only/],
    [{ SH_PACK_UPDATES: 'pull', SH_PACK_LOCK: 'missing/scopehaven.lock' }, withLock], [{ SH_PACK_UPDATES: 'pull', SH_BASELINE_FROM_LEDGER: 'true' }, withLock]]) {
    const result = await runStep('prepare', { ...PREPARE_ENV, SH_PROFILE: file, SH_AUTHORIZATION: authorization, RUNNER_TEMP: runnerTemp, ...extra });
    assert.equal(result.code, 2);
    assert.match(result.stdout, message);
    assert.equal(result.outputs.work, undefined, 'no work directory reaches the later steps');
  }
});

test('summary.mjs: the check packs section is an allowlisted projection that never changes the decision', () => {
  const status = { schema: 'scopehaven-pack-status/1', packs: [{ target: 'pack-app', as: 'RW', name: 'refund-window', pinned: '1.0.0', shipped: '1.1.0', state: 'pull' },
    { target: 'pack-app', as: 'X', name: 'Bad Name | **x**', pinned: '1.0.0', shipped: '1.0.0', state: 'current' }, { target: 'pack-app', as: 'Y', name: 'discount-cap', pinned: '1.0.0', shipped: '2.0.0', state: 'invented' }],
    unused: [{ name: 'blocked-route-egress', version: '1.0.0' }, { name: '../x', version: '1.0.0' }] };
  const base = buildReport({ runState: 'absent' });
  const reported = buildReport({ runState: 'absent', packStatusInput: status });
  assert.deepEqual([reported.decision, reported.reason], [base.decision, base.reason]);
  assert.match(reported.markdown, /\| `pack-app` \| `RW` \| `refund-window` \| `1\.0\.0` \| `1\.1\.0` \| behind, same major \|/);
  assert.match(reported.markdown, /set `pack-updates: pull`/);
  // With an operator's own pack in the profile, pull would refuse (pack-pull-local), so it is not suggested.
  const withLocal = buildReport({ runState: 'absent', packStatusInput: { ...status, packs: [...status.packs, { target: 'pack-app', as: 'LR', name: 'local-rule', pinned: '1.0.0', shipped: null, state: 'local' }] } });
  assert.doesNotMatch(withLocal.markdown, /set `pack-updates: pull`/); assert.match(withLocal.markdown, /does not apply/);
  assert.doesNotMatch(reported.markdown, /Bad Name|invented|discount-cap|\.\.\/x/);
  assert.match(reported.markdown, /`blocked-route-egress@1\.0\.0`/);
  const pulled = buildReport({ runState: 'absent', packStatusInput: status, packPullInput: { schema: 'scopehaven-pack-pull/1', file: '/tmp/x', lockId: 'a'.repeat(64), pulled: [{ target: 'pack-app', as: 'RW', name: 'refund-window', from: '1.0.0', to: '1.1.0' }] } });
  assert.match(pulled.markdown, /behind, same major, pulled for this run/);
  assert.match(pulled.markdown, /Pulled for this run \(pack-updates: pull\): `refund-window` `1\.0\.0` to `1\.1\.0`/);
  assert.doesNotMatch(pulled.markdown, /\/tmp\/x/, 'no path is printed');
  assert.equal(buildReport({ runState: 'absent', packStatusInput: { schema: 'other', packs: [] } }).markdown.includes('### Check packs'), false);
});

test('pack-updates pull: a profile without packs whose load fails for another reason is refused with that reason, not as unreadable packs', async () => {
  const dir = await mkdtemp(join(scratch, 'drafted profile '));
  const profile = makeLabProfile(lab.origin, 'lab-drafted');
  profile.checks[0] = { ...profile.checks[0], drafted: 'observed', approved: false };
  const file = join(dir, 'targets.json');
  await writeFile(file, JSON.stringify({ schemaVersion: 1, targets: [profile] }));
  const result = await runStep('prepare', { ...PREPARE_ENV, SH_PROFILE: file, SH_AUTHORIZATION: join(workspace, 'profiles/lab.authorization.json'), RUNNER_TEMP: runnerTemp, SH_PACK_UPDATES: 'pull' });
  assert.equal(result.code, 2, result.stdout + result.stderr);
  assert.match(result.stdout, /pack-updates pull refused \(drafted-line-unapproved\): pack status could not read the profile; nothing was sent/);
  assert.doesNotMatch(result.stdout, /packs could not be read/);
  assert.equal(result.outputs.work, undefined);
});

// A stand-in launcher in a stand-in action folder, so the prepare step's handling of what `pack pull` prints can be
// driven directly: its stdout is the record, its stderr a stray warning, and the record's file what each case needs.
async function standInAction() {
  const fake = await mkdtemp(join(scratch, 'stand-in action '));
  await mkdir(join(fake, 'integrations/github-action'), { recursive: true });
  await writeFile(join(fake, 'integrations/github-action/prepare.mjs'), "process.stdout.write('pack-app\\n');\n");
  const launcher = join(fake, 'scopehaven');
  await writeFile(launcher, `#!/bin/bash
# pack status --config P | pack pull --config P --out DIR
if [ "$2" = status ]; then echo '{"schema":"scopehaven-pack-status/1","packs":[],"unused":[]}'; exit 0; fi
out=$6; mkdir -m 700 "$out"; printf '%s' "$out" > "$FAKE_LOG"
echo '(node:1) Warning: a stray line on stderr' >&2
if [ "$FAKE_PULL" = refused ]; then echo 'note: see /work/(pack-decoy)/x' >&2; echo 'pack: Check pack refused (pack-pull-major): refund-window 1.0.0 is a major behind' >&2; exit 2; fi
case "$FAKE_PULL" in
  none) file=null ;;
  ok) cp "$4" "$out/p.json"; file="\\"$out/p.json\\"" ;;
  outside) file="\\"$4\\"" ;;
  nested) mkdir "$out/sub"; cp "$4" "$out/sub/p.json"; file="\\"$out/sub/p.json\\"" ;;
  dotdot) cp "$4" "$out/p.json"; file="\\"$out/../pack-pull/p.json\\"" ;;
  symlink) ln -s "$4" "$out/p.json"; file="\\"$out/p.json\\"" ;;
  newline) file="\\"$out/p\\\\n.json\\"" ;;
esac
printf '{"schema":"scopehaven-pack-pull/1","file":%s,"lockId":null,"pulled":[]}\\n' "$file"
`, { mode: 0o700 });
  return join(fake, 'integrations/github-action');
}

test('pack-updates pull: the record is stdout only, and the pulled file must be one regular file directly under the work directory\'s pack-pull folder', async () => {
  const { file, authorization } = await packProfile();
  const actionPath = await standInAction();
  const prepare = async (mode, temp = runnerTemp) => {
    const step = action.runs.steps.find(entry => entry.id === 'prepare'), stamp = `stand-in-${mode}-${Date.now()}`;
    const script = join(runnerTemp, `step-${stamp}.sh`), outputFile = join(runnerTemp, `output-${stamp}`);
    await writeFile(script, step.run); await writeFile(outputFile, '');
    const result = await run('bash', ['--noprofile', '--norc', '-eo', 'pipefail', script], { timeout: 300000, env: { ...baseEnv, ...PREPARE_ENV, SH_PROFILE: file, SH_AUTHORIZATION: authorization,
      RUNNER_TEMP: temp, SH_PACK_UPDATES: 'pull', FAKE_PULL: mode, FAKE_LOG: join(runnerTemp, `${stamp}.out`), GITHUB_OUTPUT: outputFile, GITHUB_ACTION_PATH: actionPath } });
    const out = await readFile(join(runnerTemp, `${stamp}.out`), 'utf8');
    return { ...result, work: dirname(out), outputs: parseOutputs(await readFile(outputFile, 'utf8')) };
  };
  // A stray stderr line no longer reaches pack-pull.json. The stand-in path has no authorization CLI, so each accepted case then
  // stops at the authorization check (exit 2, nothing sent): what matters is what the pull step did before it.
  const none = await prepare('none');
  assert.deepEqual(JSON.parse(await readFile(join(none.work, 'export/pack-pull.json'), 'utf8')), { schema: 'scopehaven-pack-pull/1', file: null, lockId: null, pulled: [] }, none.stdout + none.stderr);
  assert.match(none.stdout, /authorization refused/);
  assert.doesNotMatch(none.stdout, /pack-pull-file-invalid|pulled copy/);
  // The refusal code comes only from the CLI's own refusal line, never from other stderr text such as a path.
  const refused = await prepare('refused');
  assert.equal(refused.code, 2); assert.match(refused.stdout, /pack-updates pull refused \(pack-pull-major\)/); assert.doesNotMatch(refused.stdout, /pack-decoy/);
  for (const mode of ['outside', 'nested', 'dotdot', 'symlink', 'newline']) {
    const result = await prepare(mode);
    assert.equal(result.code, 2, mode);
    assert.match(result.stdout, /pack-updates pull refused \(pack-pull-file-invalid\)/, mode);
    assert.equal(result.outputs.profile, undefined, mode);
    assert.equal(result.outputs.work, undefined, mode);
  }
  // A RUNNER_TEMP with a trailing or doubled slash: the work directory is normalized once, so a valid pull is still accepted.
  for (const temp of [`${runnerTemp}/`, `${dirname(runnerTemp)}//${basename(runnerTemp)}`]) {
    const slashed = await prepare('ok', temp);
    assert.match(slashed.stdout, /assessing the pulled copy of the profile[\s\S]*authorization refused/, `${temp}: ${slashed.stdout}${slashed.stderr}`);
    assert.doesNotMatch(slashed.stdout, /pack-pull-file-invalid/, temp);
    assert.equal(slashed.work, join(runnerTemp, basename(slashed.work)), `${temp}: the launcher was given the normalized path`);
  }
  const ok = await prepare('ok');
  assert.match(ok.stdout, /assessing the pulled copy of the profile[\s\S]*authorization refused/, ok.stdout + ok.stderr);
  assert.doesNotMatch(ok.stdout, /pack-pull-file-invalid/);
});
