import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, chmod, mkdir, stat, symlink, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { runAssessment, compareRuns } from '../src/runner.mjs';
import { createRegistry } from '../src/registry.mjs';
import { createStore } from '../src/store.mjs';
import { runHttpAssessment, HTTP_LIMITS } from '../src/http-connector.mjs';
import { digest } from '../src/domain.mjs';
import { IDENTITY_EXPECTED, withheldSummary } from '../src/contracts.mjs';
import { summarizeGate, validateRun, validateComparison, parseArgs, runGate } from '../integrations/regression-gate/gate.mjs';
import { writeTestAuthorization } from './support/authorization.mjs';

// Only owned ephemeral loopback fixtures and private test directories. No env
// credentials, provider calls, persistent server, existing data or root writes.
const baseline = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const clone = value => structuredClone(value);
const recount = run => { run.counts = Object.fromEntries(['pass', 'fail', 'inconclusive', 'error', 'not_applicable'].map(status => [status, run.results.filter(row => row.status === status).length])); run.checksTotal = run.results.length; return run; };
function changed(status, id = repaired.results.find(row => row.severity !== 'control').id) {
  const run = clone(repaired), row = run.results.find(row => row.id === id);
  row.status = status; row.assertions = status === 'error' ? [] : [{ status }]; return recount(run);
}
async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-gate-test-'));
  t.after(() => rm(dir, { recursive: true, force: true })); return dir;
}
async function cli(args) {
  const child = spawn(process.execPath, [fileURLToPath(new URL('../integrations/regression-gate/cli.mjs', import.meta.url)), ...args], { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  return { code, stderr, summary: JSON.parse(stdout) };
}

test('clean current run and compatible repair retain complete core labels and controls', () => {
  const single = summarizeGate({ candidate: repaired });
  assert.equal(single.exitCode, 0); assert.equal(single.comparison.compatibility, 'not-requested');
  const summary = summarizeGate({ candidate: repaired, baseline });
  assert.equal(summary.outcome, 'clean'); assert.equal(summary.exitCode, 0);
  assert.deepEqual(summary.comparison.summary, compareRuns(baseline, repaired).summary);
  assert.equal(summary.comparison.labels.fixed, baseline.counts.fail);
  assert.equal(summary.comparison.labels['contract-restored'], 0);
  assert.equal(summary.current.allowedControls.status, 'pass');
  assert.equal(summary.current.allowedControls.passed, repaired.requiredControlIds.length);
  assert.equal(summary.current.evidenceScope, 'owned-synthetic-backend');
  assert.equal(JSON.stringify(summary), JSON.stringify(summarizeGate({ candidate: clone(repaired), baseline: clone(baseline) })));
});

test('failed assessments, runner errors, inconclusive and N/A checks never pass', () => {
  assert.equal(summarizeGate({ candidate: baseline }).exitCode, 1);
  for (const [status, exitCode, reason] of [['error', 2, 'runner-error'], ['inconclusive', 1, 'inconclusive-evidence'], ['not_applicable', 1, 'not-applicable-is-not-pass']]) {
    const summary = summarizeGate({ candidate: changed(status) });
    assert.equal(summary.exitCode, exitCode); assert(summary.reasons.includes(reason));
  }
  assert.equal(summarizeGate({ baseline: changed('error'), candidate: repaired }).exitCode, 2);
  for (const status of ['inconclusive', 'not_applicable']) {
    const summary = summarizeGate({ baseline: changed(status), candidate: repaired });
    assert.equal(summary.exitCode, 1); assert(summary.reasons.includes('comparison-incomplete'));
  }
});

test('missing, failed, N/A and malformed required controls fail closed', () => {
  const missing = clone(repaired); missing.results = missing.results.filter(row => row.id !== missing.requiredControlIds[0]); recount(missing);
  assert.equal(summarizeGate({ candidate: missing }).current.allowedControls.status, 'not-passed');
  assert.equal(summarizeGate({ candidate: missing }).exitCode, 1);
  for (const status of ['fail', 'inconclusive', 'not_applicable']) {
    const summary = summarizeGate({ candidate: changed(status, repaired.requiredControlIds[0]), baseline });
    assert.equal(summary.exitCode, 1); assert.equal(summary.comparison.allowedControlsPass, false);
  }
  for (const requiredControlIds of [[], ['missing-control'], [...repaired.requiredControlIds, repaired.requiredControlIds[0]]]) {
    const summary = summarizeGate({ candidate: { ...repaired, requiredControlIds } });
    assert.notEqual(summary.exitCode, 0);
  }
});

test('malformed run shape, inflated counts and missing pass evidence are errors', () => {
  const mutations = [
    r => { r.counts.pass++; }, r => { r.checksTotal--; }, r => { r.counts.unexpected = 0; },
    r => { r.results[0].id = r.results[1].id; }, r => { r.results[0].status = 'unknown'; },
    r => { r.results[0].assertions = []; }, r => { r.results[0].assertions[0].status = 'inconclusive'; },
    r => { r.results[0].evidenceDigest = 'bad'; }, r => { r.suiteHash = 'bad'; },
    r => { r.results[0].attempts = []; }, r => { r.results[0].attempts[0].evidence.complete = false; },
    r => { r.results[0].attempts = [{ evidence: { complete: true } }]; r.results[0].evidenceDigest = digest(r.results[0].attempts); },
    r => { r.results[0].attempts[0].evidence.requestId = 'uncorrelated'; r.results[0].evidenceDigest = digest(r.results[0].attempts); },
    r => { r.evidenceOrigin = 'trusted-production'; }, r => { delete r.profileHash; }, r => { r.results = []; recount(r); },
  ];
  for (const mutate of mutations) { const run = clone(repaired); mutate(run); assert.equal(summarizeGate({ candidate: run }).exitCode, 2); }
  const omitted = clone(repaired); omitted.results.pop(); recount(omitted);
  assert.equal(summarizeGate({ candidate: omitted, expectedSuite: createRegistry().exportSuite('demo-repaired') }).exitCode, 2);
});

test('incompatible baselines and corrupted comparison shape cannot appear clean', () => {
  const before = clone(baseline); before.contextId += '-other';
  const incompatible = summarizeGate({ baseline: before, candidate: repaired });
  assert.equal(incompatible.exitCode, 1); assert.equal(incompatible.comparison.compatibility, 'incompatible');
  assert.equal(incompatible.comparison.labels.fixed, 0);
  for (const mutate of [c => c.summary.fixed++, c => c.rows.pop(), c => { c.rows[0].transition = 'fixed'; c.rows[0].before = 'pass'; },
    c => { c.candidateId = 'wrong'; }, c => { c.controlsPass = false; }, c => { c.evidenceScope = 'production verified'; }]) {
    const comparison = compareRuns(baseline, repaired); mutate(comparison);
    assert.equal(summarizeGate({ baseline, candidate: repaired, comparison }).exitCode, 2);
    assert.throws(() => validateComparison(comparison, baseline, repaired));
  }
  assert.equal(summarizeGate({ candidate: repaired, comparison: {} }).exitCode, 2);
});

test('summary excludes arbitrary names, notes, traces, bodies and error details', () => {
  const secret = 'DO_NOT_EMIT_SECRET_123', candidate = clone(repaired), before = clone(baseline);
  for (const run of [candidate, before]) {
    run.targetName = secret; run.scopeLabel = secret; run.notes = { note: secret }; run.limitations = [secret];
    for (const row of run.results) { row.title = secret; row.summary = secret; row.trace = [{ body: secret }]; row.error = secret; row.assertions.forEach(a => { a.actual = secret; a.expected = secret; }); }
  }
  const summary = summarizeGate({ baseline: before, candidate });
  assert.equal(summary.exitCode, 0); assert(!JSON.stringify(summary).includes(secret));
  assert(!JSON.stringify(summary).includes('attempts'));
  // The build is a producer identity, not free-form display text. Corrupting it
  // must fail closed while still keeping the marker out of error summaries.
  candidate.build = secret;
  const rejected = summarizeGate({ baseline: before, candidate });
  assert.notEqual(rejected.exitCode, 0); assert(!JSON.stringify(rejected).includes(secret));
});

test('explicit option parser rejects URL, duplicates, ambient defaults and relative paths', () => {
  assert.deepEqual(parseArgs(['--target', 'demo-repaired', '--out', '/private/tmp/gate']), { targetId: 'demo-repaired', outputDirectory: '/private/tmp/gate' });
  for (const args of [[], ['--target', 'demo-repaired'], ['--target', 'http://example.com', '--out', '/tmp/gate'],
    ['--target', 'demo-repaired', '--out', 'relative'], ['--target', 'demo-repaired', '--out', '/tmp/gate', '--url', 'http://example.com'],
    ['--target', 'demo-repaired', '--out', '/tmp/gate', '--target', 'demo-repaired'], ['--target', 'demo-repaired', '--out', '/tmp/gate', '--config', 'relative']]) assert.throws(() => parseArgs(args));
});

test('one-shot CLI stores immutable baseline/repaired evidence privately and returns distinct exits', async t => {
  const out = await directory(t);
  const failed = await cli(['--target', 'demo-vulnerable', '--out', out]);
  assert.equal(failed.code, 1); assert.equal(failed.stderr, '');
  const clean = await cli(['--target', 'demo-repaired', '--out', out, '--baseline', failed.summary.current.runId]);
  assert.equal(clean.code, 0); assert.equal(clean.stderr, ''); assert.equal(clean.summary.comparison.compatibility, 'compatible');
  const store = createStore(out), saved = await store.get(clean.summary.current.runId); validateRun(saved);
  assert.equal(saved.integrity.algorithm, 'SHA-256');
  const summaryPath = join(out, 'gate-summaries', `${saved.id}.json`);
  assert.deepEqual(JSON.parse(await readFile(summaryPath, 'utf8')), clean.summary);
  for (const dir of [out, join(out, 'runs'), join(out, 'notes'), join(out, 'gate-summaries')]) assert.equal((await stat(dir)).mode & 0o7777, 0o700);
  for (const path of [summaryPath, join(out, 'runs', `${saved.id}.json`)]) assert.equal((await stat(path)).mode & 0o7777, 0o600);
  assert(!(await readdir(out)).includes('.gate-lock'));
  const error = await cli(['--target', 'demo-repaired', '--out', out, '--baseline', 'no-such-run']);
  assert.equal(error.code, 2); assert.equal(error.stderr, ''); assert.deepEqual(error.summary.reasons, ['baseline-read-error']);
  assert.equal((await store.list()).length, 2);
});

test('output requires a dedicated private directory and preserves existing contents', async t => {
  const root = await directory(t), options = { targetId: 'demo-repaired', outputDirectory: root };
  await writeFile(join(root, 'unrelated.txt'), 'preserve me');
  assert.equal((await runGate(options)).reasons[0], 'output-directory-not-dedicated');
  assert.equal(await readFile(join(root, 'unrelated.txt'), 'utf8'), 'preserve me');
  const publicDir = join(root, 'public'); await mkdir(publicDir); await chmod(publicDir, 0o755);
  assert.equal((await runGate({ ...options, outputDirectory: publicDir })).reasons[0], 'output-directory-not-private');
  const alias = join(root, 'alias'); await symlink(publicDir, alias);
  assert.equal((await runGate({ ...options, outputDirectory: alias })).reasons[0], 'output-directory-not-private');
  const data = fileURLToPath(new URL('../data', import.meta.url));
  assert.equal((await runGate({ ...options, outputDirectory: data })).reasons[0], 'output-directory-is-project-data');
});

test('busy gate and malformed config fail before any assessment or unsafe error echo', async t => {
  const out = await directory(t);
  await writeFile(join(out, '.scopehaven-regression-gate'), 'scopehaven-regression-gate/1\n', { mode: 0o600 });
  await writeFile(join(out, '.gate-lock'), 'other writer', { mode: 0o600 });
  const summary = await runGate({ targetId: 'demo-repaired', outputDirectory: out });
  assert.equal(summary.exitCode, 2); assert.deepEqual(summary.reasons, ['output-directory-busy']);
  assert.equal(await readFile(join(out, '.gate-lock'), 'utf8'), 'other writer');
  const config = join(out, 'config.json'); await writeFile(config, 'SECRET_INVALID_JSON');
  const invalid = await cli(['--target', 'demo-repaired', '--config', config, '--out', out]);
  assert.equal(invalid.code, 2); assert.equal(invalid.stderr, ''); assert(!JSON.stringify(invalid.summary).includes('SECRET'));
});

test('configured owned response contract uses contract-restored and never claims backend effects', async t => {
  let repairedBuild = false, calls = 0;
  const server = createServer((req, res) => { calls++; res.writeHead(req.url === '/control' || repairedBuild ? 200 : 403, { 'Content-Type': 'application/json' }); res.end('{"body":"SECRET_RESPONSE_NOT_FOR_SUMMARY"}'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const root = await directory(t), out = join(root, 'output'), configFile = join(root, 'targets.json');
  const profile = { id: 'owned-contract', name: 'Local test', applicationId: 'owned-test', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'before', contextId: 'isolated-test',
    actors: { member: { principalId: 'member' } }, requiredControlIds: ['allowed'], checks: [
      { id: 'boundary', title: 'Response boundary', category: 'Response', severity: 'high', actorId: 'member', method: 'GET', path: '/check', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'allowed', title: 'Allowed use', category: 'Control', severity: 'control', actorId: 'member', method: 'GET', path: '/control', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    ] };
  const writeConfig = () => writeFile(configFile, JSON.stringify({ schemaVersion: 1, targets: [profile] }), { mode: 0o600 });
  await writeConfig();
  // The authorization record: a configured target runs under a record that covers it (test/authorization.test.mjs pins the refusals).
  const authorizationFile = writeTestAuthorization(join(root, 'authorization.json'), { ...profile, actors: { member: { principalId: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_TEST_ONLY' } } });
  const before = await runGate({ targetId: profile.id, configFile, authorizationFile, outputDirectory: out });
  assert.equal(before.exitCode, 1);
  repairedBuild = true; profile.buildLabel = 'after'; await writeConfig();
  const after = await runGate({ targetId: profile.id, configFile, authorizationFile, outputDirectory: out, baselineRunId: before.current.runId });
  assert.equal(after.exitCode, 0); assert.equal(after.current.evidenceScope, 'response-only');
  assert.equal(after.comparison.labels['contract-restored'], 1); assert.equal(after.comparison.labels.fixed, 0);
  assert.equal(after.comparison.restorationLabel, 'Response contracts restored');
  assert.equal(calls, 4); assert(!JSON.stringify(after).includes('SECRET_RESPONSE'));
  const stored = await createStore(out).get(after.current.runId);
  const malformed = clone(stored); malformed.results[0].trace = [];
  assert.equal(summarizeGate({ candidate: malformed }).exitCode, 2);
  profile.actors.member.credentialEnv = 'SCOPEHAVEN_TARGET_TEST_ONLY'; await writeConfig();
  const noCredential = await runGate({ targetId: profile.id, configFile, authorizationFile, outputDirectory: out });
  assert.equal(noCredential.exitCode, 2); assert.equal(calls, 4);
});

test('HTTP gate rejects rehashed contradictory observations and preserves complete status-only non-JSON checks', async t => {
  const server = createServer((req, res) => { res.writeHead(200); res.end(req.url === '/json' ? '{"ok":true}' : 'plain response'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const target = { id: 'consistency', name: 'Owned consistency test', applicationId: 'owned-consistency', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'test', contextId: 'isolated', actors: { member: { principalId: 'member' } }, requiredControlIds: ['allowed'], checks: [
    { id: 'allowed', title: 'JSON allowed control', category: 'Control', severity: 'control', actorId: 'member', method: 'GET', path: '/json', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/ok', expected: true }] },
    { id: 'status-only', title: 'Non-JSON status contract', category: 'Response', severity: 'high', actorId: 'member', method: 'GET', path: '/text', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
  ] };
  const registry = createRegistry({ profiles: [target], env: {} }), expectedSuite = registry.exportSuite(target.id);
  const run = await registry.run(target.id), statusOnly = run.results[1];
  assert.equal(statusOnly.status, 'pass'); assert.equal(statusOnly.observed.jsonParsed, false);
  assert.equal(statusOnly.trace[0].data.transportOutcome, 'invalid-json');
  assert.equal(summarizeGate({ candidate: run, expectedSuite }).exitCode, 0);
  const mutations = [
    row => { Object.assign(row.trace[0].data, { httpStatus: null, requestAttempted: false, transportOutcome: 'timeout', responseComplete: true, responseBytes: 0, jsonParsed: false }); Object.assign(row.observed, { httpStatus: null, complete: true, jsonParsed: false }); },
    row => { Object.assign(row.trace[0].data, { transportOutcome: 'invalid-json', jsonParsed: false }); row.observed.jsonParsed = false; },
    row => { row.observed.httpStatus = 201; },
    row => { row.trace[0].data.httpStatus = 201; row.observed.httpStatus = 201; },
    row => { row.observed.predicates[0].outcome = 'inconclusive'; },
    row => { row.observed.predicates = []; },
    row => { row.observed.predicates = []; row.assertions.pop(); },
    row => { row.trace[0].data.method = 'POST'; },
    row => { row.assertions.shift(); },
  ];
  for (const mutate of mutations) {
    const candidate = clone(run), row = candidate.results[0]; mutate(row);
    row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions });
    assert.equal(summarizeGate({ candidate, expectedSuite }).exitCode, 2);
  }
});

test('HTTP gate retains failure precedence, transport errors and unattempted run-budget errors', async () => {
  const target = { id: 'metadata-cases', name: 'Synthetic observation cases', applicationId: 'owned-metadata', origin: 'http://127.0.0.1:1', buildLabel: 'test', contextId: 'isolated', actors: { member: { principalId: 'member' } }, requiredControlIds: ['allowed'], checks: [
    { id: 'allowed', title: 'Control', category: 'Control', severity: 'control', actorId: 'member', method: 'GET', path: '/', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/ok', expected: true }] },
  ] };
  const expectedSuite = createRegistry({ profiles: [target], env: {} }).exportSuite(target.id);
  // Injected synthetic observations: no socket, DNS or provider is contacted.
  for (const [status, expected, exitCode] of [[403, 'fail', 1], [null, 'error', 2]]) {
    const run = await runHttpAssessment(target, { env: {}, transport: async () => ({ status, complete: false, jsonParsed: false, bytes: 0, error: 'network' }) });
    assert.equal(run.results[0].status, expected); assert.equal(summarizeGate({ candidate: run, expectedSuite }).exitCode, exitCode);
  }
  const skipped = await runHttpAssessment(target, { env: {}, limits: { ...HTTP_LIMITS, runTimeoutMs: 0 }, transport: async () => { throw new Error('Must not attempt a timed-out check.'); } });
  assert.equal(skipped.results[0].trace[0].data.requestAttempted, false);
  assert.equal(summarizeGate({ candidate: skipped, expectedSuite }).exitCode, 2);
});

// This is a real no-provider replay of the pinned, inspected local adapter,
// reused only for gate validation tests. Mutations below are negative receiver
// tests, never claimed as upstream findings or repaired application runs.
// HTTP connector v2 (loopback-response-contract/2, http-contract/3): accepted
// status sets and the actor-identity assertion. Injected observations only.
function httpV2Target(boundaryStatus = { kind: 'status.equals', expected: 403 }) {
  return { id: 'identity-cases', name: 'Synthetic identity cases', applicationId: 'owned-identity', origin: 'http://127.0.0.1:1', buildLabel: 'test', contextId: 'isolated', actors: { member: { principalId: 'member' }, anonymous: { principalId: 'anonymous' } }, requiredControlIds: ['whoami'], checks: [
    { id: 'whoami', title: 'Member identity', category: 'Control', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'member-denied', title: 'Member refused', category: 'Access', severity: 'high', actorId: 'member', method: 'GET', path: '/foreign', evidenceRequirement: 'response', assertions: [boundaryStatus] },
    { id: 'anonymous-denied', title: 'Anonymous refused', category: 'Access', severity: 'high', actorId: 'anonymous', method: 'GET', path: '/foreign', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 401 }] },
  ] };
}
const IDENTITY = 'Actor identity established by required controls';
const injected = statuses => async (_, check) => ({ status: statuses[check.path === '/me' ? 'me' : check.path === '/me-2' ? 'me2' : check.actorId], complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' });
const reseal = (run, row) => { row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions }); return recount(run); };
// Stored v1/v2 runs predate the v3 target context, so a relabelled copy drops it.
const relabel = (run, versions) => { const copy = clone(run); Object.assign(copy, versions); if (copy.adapterVersion !== 'loopback-response-contract/3') { delete copy.targetContext; delete copy.targetLabel; } return copy; };
const V1 = { adapterVersion: 'loopback-response-contract/1', assertionSchemaVersion: 'http-contract/2' };
const MIXED = [{ adapterVersion: 'loopback-response-contract/2', assertionSchemaVersion: 'http-contract/2' }, { adapterVersion: 'loopback-response-contract/1', assertionSchemaVersion: 'http-contract/3' }];
// v1 rows carried neither the identity assertion nor the v2 evidence fields.
function asV1Rows(run) {
  const copy = relabel(run, V1); delete copy.identityEvidence; delete copy.principals; // v1 runs predate actor-identity/5's principals and per-row decisions
  for (const row of copy.results) {
    delete row.decision;
    row.assertions = row.assertions.filter(a => a.name !== IDENTITY);
    if (row.status === 'inconclusive' && row.assertions.every(a => a.status === 'pass')) row.status = 'pass';
    delete row.trace[0].data.credentialMode; delete row.trace[0].data.requestTimeoutMs;
    delete row.trace[0].data.routeSegments; delete row.trace[0].data.controlScope; // actor-identity/6 fields
    row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions });
  }
  return recount(copy);
}

// Object.hasOwn coerces its key, so an evidence origin that is an array or an object holding a
// known origin's name passed the origin check while every origin-specific validator, which compares with ===, was skipped.
test('a run whose evidenceOrigin is not a string, or is not one this build registers, is refused by the gate and is not comparable', async t => {
  const out = await directory(t);
  const failed = await cli(['--target', 'demo-vulnerable', '--out', out]);
  const saved = await createStore(out).get(failed.summary.current.runId);
  assert.doesNotThrow(() => validateRun(saved));
  for (const origin of [[saved.evidenceOrigin], { toString: () => saved.evidenceOrigin }, 'no-longer-registered-local']) {
    assert.throws(() => validateRun({ ...saved, evidenceOrigin: origin }), /invalid-run-evidence/, JSON.stringify(origin));
    const comparison = compareRuns({ ...saved, evidenceOrigin: origin }, saved);
    assert.equal(comparison.compatible, false);
    assert.ok(comparison.reasons.includes('Evidence origin is not supported for native comparison.'), JSON.stringify(comparison.reasons));
  }
});

test('HTTP v1 runs keep the previous gate rules, including a failed control beside a passing boundary', async () => {
  const clean = asV1Rows(await runHttpAssessment(httpV2Target(), { env: {}, transport: injected({ me: 200, member: 403, anonymous: 401 }) }));
  assert.doesNotThrow(() => validateRun(clean));
  // The stored v1 shape the identity rule replaced: failed whoami, passing member boundary, no identity assertion.
  const broken = asV1Rows(await runHttpAssessment(httpV2Target(), { env: {}, transport: injected({ me: 401, member: 403, anonymous: 401 }) }));
  assert.deepEqual(broken.results.map(row => row.status), ['fail', 'pass', 'pass']);
  assert.doesNotThrow(() => validateRun(broken));
  const summary = summarizeGate({ candidate: broken });
  assert.equal(summary.exitCode, 1); assert.deepEqual(summary.reasons, ['checks-failed', 'required-controls-not-passed']);
  for (const versions of [V1, ...MIXED]) {
    const withSet = relabel(clean, versions), row = withSet.results[1]; row.assertions[0].expected = 'HTTP 401 or 403';
    assert.throws(() => validateRun(reseal(withSet, row)), /invalid-run-evidence/, JSON.stringify(versions));
    const withIdentity = relabel(clean, versions), forged = withIdentity.results[1];
    forged.assertions.push({ name: IDENTITY, status: 'inconclusive', expected: 'x', actual: 'y' }); forged.status = 'inconclusive';
    assert.throws(() => validateRun(reseal(withIdentity, forged)), /invalid-run-evidence/, JSON.stringify(versions));
  }
  // An array-valued v1 status label was coerced by the previous regular expression; it still is.
  const coerced = clone(clean), row = coerced.results[1]; row.assertions[0].expected = ['HTTP 403'];
  assert.doesNotThrow(() => validateRun(reseal(coerced, row)));
});

test('HTTP v2 status.in runs pass the gate on membership, fail on an outside status and reject malformed set labels', async () => {
  for (const expected of [[401, 403, 404], [300, 401, 403, 404, 599]]) {
    const target = httpV2Target({ kind: 'status.in', expected });
    const expectedSuite = createRegistry({ profiles: [target], env: {} }).exportSuite(target.id);
    const clean = await runHttpAssessment(target, { env: {}, transport: injected({ me: 200, member: 404, anonymous: 401 }) });
    assert.equal(summarizeGate({ candidate: clean, expectedSuite }).exitCode, 0, JSON.stringify(expected));
  }
  const target = httpV2Target({ kind: 'status.in', expected: [401, 403, 404] });
  const expectedSuite = createRegistry({ profiles: [target], env: {} }).exportSuite(target.id);
  const clean = await runHttpAssessment(target, { env: {}, transport: injected({ me: 200, member: 404, anonymous: 401 }) });
  assert.equal(clean.results[1].assertions[0].expected, 'HTTP 401, 403 or 404');
  const exposed = await runHttpAssessment(target, { env: {}, transport: injected({ me: 200, member: 200, anonymous: 401 }) });
  assert.equal(exposed.results[1].status, 'fail'); assert.equal(summarizeGate({ candidate: exposed, expectedSuite }).exitCode, 1);
  for (const label of ['HTTP 200 or 404', 'HTTP 404 or 404', 'HTTP 401, 403, 404, 405, 409 or 410', 'HTTP 401 and 404']) {
    const edited = clone(clean), row = edited.results[1]; row.assertions[0].expected = label;
    assert.equal(summarizeGate({ candidate: reseal(edited, row), expectedSuite }).exitCode, 2, label);
  }
  const relabelled = clone(clean), row = relabelled.results[1]; row.assertions[0].expected = 'HTTP 404';
  assert.equal(summarizeGate({ candidate: reseal(relabelled, row), expectedSuite }).exitCode, 2, 'A set check cannot be presented as a single-status check.');
});

test('HTTP v2 identity: a control that fails, errors or is inconclusive keeps the boundary from passing; partial edits of the assertion are rejected', async () => {
  const target = httpV2Target(), expectedSuite = createRegistry({ profiles: [target], env: {} }).exportSuite(target.id);
  const unreached = async (_, check) => check.path === '/me' ? { status: null, complete: false, jsonParsed: false, bytes: 0, error: 'timeout' } : injected({ member: 403, anonymous: 401 })(_, check);
  const cases = [
    [await runHttpAssessment(target, { env: {}, transport: injected({ me: 401, member: 403, anonymous: 401 }) }), 'fail', 1],
    [await runHttpAssessment(target, { env: {}, transport: unreached }), 'error', 2],
  ];
  const jsonControl = structuredClone(target); jsonControl.checks[0].assertions.push({ kind: 'json.exists', pointer: '/user', expected: true });
  cases.push([await runHttpAssessment(jsonControl, { env: {}, transport: injected({ me: 200, member: 403, anonymous: 401 }) }), 'inconclusive', 1]);
  for (const [run, control, exitCode] of cases) {
    assert.deepEqual(run.results.map(row => row.status), [control, 'inconclusive', 'pass'], control);
    assert.equal(run.results[1].assertions.at(-1).name, IDENTITY);
    const suite = run === cases[2]?.[0] ? createRegistry({ profiles: [jsonControl], env: {} }).exportSuite(jsonControl.id) : expectedSuite;
    assert.equal(summarizeGate({ candidate: run, expectedSuite: suite }).exitCode, exitCode, control);
  }
  const broken = cases[0][0];
  const dropped = clone(broken), row = dropped.results[1];
  row.assertions = row.assertions.filter(a => a.name !== IDENTITY); row.status = 'pass';
  assert.equal(summarizeGate({ candidate: reseal(dropped, row), expectedSuite }).exitCode, 2);
  const flipped = clone(broken), flippedRow = flipped.results[1];
  flippedRow.assertions.at(-1).status = 'pass'; flippedRow.status = 'pass';
  assert.equal(summarizeGate({ candidate: reseal(flipped, flippedRow), expectedSuite }).exitCode, 2, 'An identity assertion edited to pass is rejected.');
  const clean = await runHttpAssessment(target, { env: {}, transport: injected({ me: 200, member: 403, anonymous: 401 }) });
  assert.equal(summarizeGate({ candidate: clean, expectedSuite }).exitCode, 0);
  for (const index of [1, 2]) {
    const forged = clone(clean), forgedRow = forged.results[index];
    forgedRow.assertions.push({ name: IDENTITY, status: 'inconclusive', expected: 'x', actual: 'y' }); forgedRow.status = 'inconclusive';
    assert.equal(summarizeGate({ candidate: reseal(forged, forgedRow), expectedSuite }).exitCode, 2);
  }
});

test('HTTP v2 identity: an actor with two required controls needs both, and a credentialed actor without one is never established', async () => {
  const two = httpV2Target(); two.checks.splice(1, 0, { ...two.checks[0], id: 'whoami-2', path: '/me-2' }); two.requiredControlIds = ['whoami', 'whoami-2'];
  const twoSuite = createRegistry({ profiles: [two], env: {} }).exportSuite(two.id);
  const half = await runHttpAssessment(two, { env: {}, transport: injected({ me: 200, me2: 401, member: 403, anonymous: 401 }) });
  assert.deepEqual(half.results.map(row => row.status), ['pass', 'fail', 'inconclusive', 'pass']);
  assert.equal(summarizeGate({ candidate: half, expectedSuite: twoSuite }).exitCode, 1);
  const audited = httpV2Target(); audited.actors.auditor = { principalId: 'auditor', credentialEnv: 'SCOPEHAVEN_TARGET_AUDITOR_TOKEN' };
  audited.checks.push({ id: 'auditor-denied', title: 'Auditor refused', category: 'Access', severity: 'high', actorId: 'auditor', method: 'GET', path: '/foreign', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [302, 403] }] });
  const env = { SCOPEHAVEN_TARGET_AUDITOR_TOKEN: 'synthetic-auditor' }, suite = createRegistry({ profiles: [audited], env }).exportSuite(audited.id);
  const run = await runHttpAssessment(audited, { env, transport: injected({ me: 200, member: 403, anonymous: 401, auditor: 302 }) });
  assert.deepEqual(run.results.map(row => [row.id, row.status]), [['whoami', 'pass'], ['member-denied', 'pass'], ['anonymous-denied', 'pass'], ['auditor-denied', 'inconclusive']]);
  assert.equal(run.results[3].trace[0].data.credentialMode, 'bearer');
  const summary = summarizeGate({ candidate: run, expectedSuite: suite });
  // actor-identity/5: the boundary that observed its refusal while the actor was not established is the distinct third state.
  assert.equal(summary.exitCode, 1); assert.deepEqual(summary.reasons, ['inconclusive-evidence', 'prohibition-observed-identity-unproven', 'identity-not-established']);
  const dropped = clone(run), row = dropped.results[3];
  row.assertions = row.assertions.filter(a => a.name !== IDENTITY); row.status = 'pass';
  assert.equal(summarizeGate({ candidate: reseal(dropped, row), expectedSuite: suite }).exitCode, 2);
  const unmarked = clone(run), unmarkedRow = unmarked.results[3];
  unmarkedRow.trace[0].data.credentialMode = 'none';
  assert.equal(summarizeGate({ candidate: reseal(unmarked, unmarkedRow), expectedSuite: suite }).exitCode, 2, 'Relabelling the actor as uncredentialed cannot remove its identity assertion.');
});

// Connector v2 identity proof through the gate (actor-identity/2): injected observations only.
// The actor-identity/4 403 rule: the member also has a surface control, a required GET on a protected route
// ('member-own', last), so its refusal on 'member-denied' counts; without it that 403 reads inconclusive (surface-unproven).
function sessionTarget(controlAssertions = [{ kind: 'status.equals', expected: 200 }], { surface = true } = {}) {
  return { id: 'session-cases', name: 'Synthetic session cases', applicationId: 'owned-session', origin: 'http://127.0.0.1:1', buildLabel: 'test', contextId: 'isolated', actors: { member: { principalId: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_SESSION', identityValue: 'member@example.test' } }, requiredControlIds: ['whoami', ...(surface ? ['member-own'] : [])], checks: [
    { id: 'whoami', title: 'Member session', category: 'Control', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: controlAssertions },
    { id: 'member-denied', title: 'Member refused', category: 'Access', severity: 'high', actorId: 'member', method: 'GET', path: '/foreign', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [302, 403] }] },
    ...(surface ? [{ id: 'member-own', title: 'Member lists own records', category: 'Control', severity: 'control', actorId: 'member', method: 'GET', path: '/own', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] : []),
  ] };
}
// alive: the member's session is valid; publicControl: /me answers 200 to anyone;
// nullWhenSignedOut: /me answers 200 with JSON null to anyone signed out;
// expireAfterControl: the session dies right after /me first succeeds;
// anonymousStatus: what /me answers without a credential.
function sessionTransport({ alive = true, publicControl = false, nullWhenSignedOut = false, expireAfterControl = false, anonymousStatus } = {}) {
  let live = alive;
  return async (_, check, options) => {
    const signedIn = live && options.credential === 'synthetic-session';
    if (check.path === '/me') {
      if (signedIn && expireAfterControl) live = false;
      if (signedIn) return { status: 200, complete: true, jsonParsed: true, json: { user: { email: 'member@example.test' } }, bytes: 40 };
      if (options.credential === undefined && anonymousStatus) return { status: anonymousStatus, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
      if (nullWhenSignedOut) return { status: 200, complete: true, jsonParsed: true, json: null, bytes: 4 };
      return { status: publicControl ? 200 : 401, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
    }
    if (check.path === '/own') return signedIn ? { status: 200, complete: true, jsonParsed: true, json: { items: [] }, bytes: 12 } : { status: 302, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
    return { status: signedIn ? 403 : 302, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
  };
}
const sessionRun = (target, options) => runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session' }, transport: sessionTransport(options) });
const sessionSuite = target => createRegistry({ profiles: [target], env: {} }).exportSuite(target.id);
const identifyingControl = [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user/email', expected: 'member@example.test' }];

test('HTTP v2 identity proof: a public control, a null signed-out answer, an expiring session and an unrefused anonymous request never give a clean gate; a proven login does', async () => {
  // The failing cases need no surface control; the proven login has one, so its refusal counts.
  const plain = sessionTarget(undefined, { surface: false }), strict = sessionTarget(identifyingControl, { surface: false }), provenTarget = sessionTarget(identifyingControl);
  const cases = [
    ['public control', plain, { alive: false, publicControl: true }, 'no-identity-control'],
    ['null when signed out', plain, { alive: false, nullWhenSignedOut: true }, 'no-identity-control'],
    ['session expires after the control', strict, { expireAfterControl: true, nullWhenSignedOut: true }, 'bracket-not-passed'],
    ['anonymous 500', strict, { anonymousStatus: 500 }, 'not-refused-without-credential'],
    ['anonymous 429', strict, { anonymousStatus: 429 }, 'not-refused-without-credential'],
  ];
  for (const [label, target, options, reason] of cases) {
    const run = await sessionRun(target, options);
    // actor-identity/5: every row is withheld in every case. The other cases fail on the route itself. Re-pinned for the
    // other-principal rule: when the session expires, its identity probes answer 200 null, a complete 2xx that names no
    // one, which identityRefused counts as a refusal, so the identity control's own row is withheld too and the gate also reports
    // required-controls-not-passed (the control kept its pass on the route proof while only refusal statuses counted).
    assert.deepEqual(run.results.map(row => row.status), ['inconclusive', 'inconclusive'], label);
    assert.equal(run.identityEvidence.actors[0].reason, reason, label);
    const summary = summarizeGate({ candidate: run, expectedSuite: sessionSuite(target) });
    assert.equal(summary.exitCode, 1, label); assert.deepEqual(summary.reasons, ['inconclusive-evidence', 'prohibition-observed-identity-unproven', 'required-controls-not-passed', 'identity-not-established'], label);
  }
  const proven = await sessionRun(provenTarget, { nullWhenSignedOut: true });
  assert.deepEqual(proven.results.map(row => row.status), ['pass', 'pass', 'pass']); assert.equal(proven.identityEvidence.actors[0].reason, 'established');
  assert.equal(summarizeGate({ candidate: proven, expectedSuite: sessionSuite(provenTarget) }).exitCode, 0);
  // Without the surface control the same proven login does not make the 403 a refusal (actor-identity/4).
  const bare = await sessionRun(strict, { nullWhenSignedOut: true });
  assert.deepEqual(bare.results.map(row => row.status), ['pass', 'inconclusive']); assert.equal(bare.identityEvidence.actors[0].reason, 'established');
  // actor-identity/5: the refusal was observed but not attributed to a surface-proven login: the distinct third state.
  assert.deepEqual(summarizeGate({ candidate: bare, expectedSuite: sessionSuite(strict) }).reasons, ['inconclusive-evidence', 'prohibition-observed-identity-unproven']);
});

test('HTTP v2: a control-only actor whose login is not proven never gives a clean gate, even when every row passes', async () => {
  const target = sessionTarget(identifyingControl, { surface: false }); target.checks = [target.checks[0]];
  const run = await sessionRun(target, { anonymousStatus: 503 });
  assert.deepEqual(run.results.map(row => row.status), ['inconclusive'], 'The control answered, but the login was not proven, so it cannot read as a pass anywhere.');
  const summary = summarizeGate({ candidate: run, expectedSuite: sessionSuite(target) });
  // A control-only actor observes no prohibition, so the third state is not reported: the control is plainly inconclusive.
  assert.equal(summary.exitCode, 1); assert.deepEqual(summary.reasons, ['inconclusive-evidence', 'required-controls-not-passed', 'identity-not-established']);
});

test('HTTP v2 identity evidence is recomputed by the gate: probe outcomes come from status, transport and predicates', async () => {
  const strict = sessionTarget(identifyingControl), suite = sessionSuite(strict);
  const proven = await sessionRun(strict, { nullWhenSignedOut: true });
  const unproven = await sessionRun(sessionTarget(), { alive: false, publicControl: true });
  const unprovenInvalid = await runHttpAssessment(strict, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session' }, transport: async (origin, check, options) => sessionTransport({ nullWhenSignedOut: true })(origin, check, { ...options, credential: options.credential !== undefined && options.credential !== 'synthetic-session' ? 'synthetic-session' : options.credential }) }); // a target that accepts any credential
  assert.equal(unprovenInvalid.identityEvidence.actors[0].reason, 'accepted-invalid-credential');
  const edits = [
    ['anonymous outcome edited', proven, run => { run.identityEvidence.actors[0].anonymous[0].outcome = 'pass'; }],
    ['before status outcome edited', proven, run => { run.identityEvidence.actors[0].before[0].statusOutcome = 'fail'; }],
    ['after status edited without its outcome', proven, run => { run.identityEvidence.actors[0].after[0].httpStatus = 401; }],
    ['after transport edited to invalid-json while predicates passed', proven, run => { run.identityEvidence.actors[0].after[0].transportOutcome = 'invalid-json'; }],
    ['anonymous identity predicate edited to pass a refusal', proven, run => { const probe = run.identityEvidence.actors[0].anonymous[0]; probe.predicates[0].outcome = 'pass'; probe.outcome = 'pass'; }],
    ['probe kind edited', proven, run => { run.identityEvidence.actors[0].anonymous[0].kind = 'invalid'; }],
    ['identity marker removed', proven, run => { run.identityEvidence.actors[0].before[0].predicates[0].identity = false; }],
    ['refusal statuses widened', proven, run => { run.identityEvidence.actors[0].refusalStatuses = [401, 403, 500]; }],
    ['entry dropped', proven, run => { run.identityEvidence.actors = []; }],
    ['evidence missing', proven, run => { delete run.identityEvidence; }],
    ['old evidence schema', proven, run => { run.identityEvidence.schema = 'actor-identity/2'; }],
    ['loginProven flipped', proven, run => { run.identityEvidence.actors[0].loginProven = false; }],
    ['probe predicate added that the control does not declare', proven, run => { run.identityEvidence.actors[0].anonymous[0].predicates.push({ kind: 'json.equals', outcome: 'pass', identity: false }); }],
    ['required control list emptied', proven, run => { run.identityEvidence.actors[0].requiredControlIds = []; }],
    ['invalid-credential probe edited to a refusal it did not get', unprovenInvalid, run => { const probe = run.identityEvidence.actors[0].invalid[0]; Object.assign(probe, { httpStatus: 401, statusOutcome: 'fail', outcome: 'fail' }); probe.predicates.forEach(p => { p.outcome = 'inconclusive'; }); probe.transportOutcome = 'invalid-json'; }],
    ['unproven reason edited to established', unproven, run => { Object.assign(run.identityEvidence.actors[0], { reason: 'established', established: true }); }],
  ];
  for (const [label, source, edit] of edits) {
    const run = clone(source); edit(run);
    assert.equal(summarizeGate({ candidate: run, expectedSuite: source === unproven ? sessionSuite(sessionTarget()) : suite }).exitCode, 2, label);
  }
});

test('HTTP v2 integrity: one credential mode per actor, 2xx credentialed controls, matching identity text, and the suite\'s actor and credential mode', async () => {
  const strict = sessionTarget(identifyingControl), suite = sessionSuite(strict);
  const proven = await sessionRun(strict, { nullWhenSignedOut: true });
  const unproven = await sessionRun(strict, { anonymousStatus: 500 });
  const twoControls = sessionTarget(identifyingControl);
  twoControls.checks.splice(1, 0, { ...twoControls.checks[0], id: 'profile-page', path: '/profile', assertions: [{ kind: 'status.equals', expected: 200 }] });
  twoControls.requiredControlIds = ['whoami', 'profile-page'];
  const profileTransport = sessionTransport({ nullWhenSignedOut: true });
  const withProfile = await runHttpAssessment(twoControls, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session' }, transport: async (origin, check, options) => check.path === '/profile' ? { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 } : profileTransport(origin, check, options) });
  assert.equal(summarizeGate({ candidate: withProfile }).exitCode, 0);
  const resealed = (source, edit) => { const run = clone(source); edit(run); for (const row of run.results) row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions }); return recount(run); };
  const cases = [
    ['mixed credential modes for one actor', resealed(proven, run => { run.results[1].trace[0].data.credentialMode = 'none'; run.identityEvidence.actors = []; }), undefined],
    ['credentialed control consistently relabelled to a 302 pass', resealed(withProfile, run => { const row = run.results[1], data = row.trace[0].data; data.httpStatus = 302; row.observed.httpStatus = 302; Object.assign(row.assertions[0], { expected: 'HTTP 302', actual: 'HTTP 302', status: 'pass' }); }), undefined],
    ['identity assertion text does not match the reason', resealed(unproven, run => { run.results[1].assertions.at(-1).actual = 'A required control for this actor did not pass'; }), undefined],
    ['an unproven actor relabelled as uncredentialed, checked against the suite', resealed(unproven, run => { for (const row of run.results) row.trace[0].data.credentialMode = 'none'; run.identityEvidence.actors = []; run.results[1].assertions.pop(); run.results[1].status = 'pass'; }), suite],
  ];
  for (const [label, run, expectedSuite] of cases) assert.equal(summarizeGate({ candidate: run, expectedSuite }).exitCode, 2, label);
  assert.equal(summarizeGate({ candidate: proven, expectedSuite: suite }).exitCode, 0);
  assert.deepEqual(suite.checks.map(c => [c.id, c.actorId, c.credentialMode]), [['whoami', 'member', 'bearer'], ['member-denied', 'member', 'bearer'], ['member-own', 'member', 'bearer']]);
});

test('HTTP v1 labels on v2 evidence are a downgrade and are refused, alone and against the current suite', async () => {
  const strict = sessionTarget(identifyingControl), proven = await sessionRun(strict, { nullWhenSignedOut: true });
  const downgraded = relabel(proven, V1);
  assert.equal(summarizeGate({ candidate: downgraded }).exitCode, 2);
  assert.equal(summarizeGate({ candidate: downgraded, expectedSuite: sessionSuite(strict) }).exitCode, 2);
  const stripped = asV1Rows(proven);
  assert.equal(summarizeGate({ candidate: stripped }).exitCode, 2, 'Its status set label still needs v2 rules.');
  const exact = await runHttpAssessment(httpV2Target(), { env: {}, transport: injected({ me: 200, member: 403, anonymous: 401 }) });
  assert.equal(summarizeGate({ candidate: relabel(exact, V1) }).exitCode, 2, 'Exact statuses only: the v2 fields alone reveal the downgrade.');
  for (const strip of ['identityEvidence', 'credentialMode', 'requestTimeoutMs']) {
    const partial = relabel(exact, V1);
    if (strip === 'identityEvidence') delete partial.identityEvidence; else for (const row of partial.results) delete row.trace[0].data[strip];
    for (const row of partial.results) row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions });
    assert.equal(summarizeGate({ candidate: partial }).exitCode, 2, `Removing only ${strip} still leaves v2 fields.`);
  }
  assert.equal(summarizeGate({ candidate: asV1Rows(exact) }).exitCode, 0, 'A genuine v1-shaped run is still accepted alone.');
  assert.equal(summarizeGate({ candidate: asV1Rows(exact), expectedSuite: createRegistry({ profiles: [httpV2Target()], env: {} }).exportSuite('identity-cases') }).exitCode, 2, 'A v1 run never matches the current suite version.');
});

test('the gate refuses an HTTP run with an unsupported or mixed version pair even when gated alone', async () => {
  // Exact statuses, no credentials and no identity assertions: rows that the v1
  // rules would accept, so only the version check can refuse the relabelled runs.
  const run = await runHttpAssessment(httpV2Target(), { env: {}, transport: injected({ me: 200, member: 403, anonymous: 401 }) });
  assert.equal(summarizeGate({ candidate: run }).exitCode, 0);
  assert.equal(summarizeGate({ candidate: asV1Rows(run) }).exitCode, 0, 'A supported v1 pair is still accepted.');
  for (const versions of [...MIXED, { adapterVersion: 'loopback-response-contract/9' }, { assertionSchemaVersion: 'http-contract/4' }]) {
    const relabelled = relabel(asV1Rows(run), versions);
    assert.equal(summarizeGate({ candidate: relabelled }).exitCode, 2, JSON.stringify(versions));
  }
});

// The gate: baseline identity, identity binding to the suite and evidence origin.
test('HTTP v2: a baseline whose login was not proven gives baseline-identity-not-established and no restored rows', async () => {
  const strict = sessionTarget(identifyingControl), suite = sessionSuite(strict);
  const expired = await sessionRun(strict, { alive: false, nullWhenSignedOut: true });
  const fresh = await sessionRun(strict, { nullWhenSignedOut: true });
  assert.equal(expired.identityEvidence.actors[0].loginProven, false);
  const summary = summarizeGate({ candidate: fresh, baseline: expired, expectedSuite: suite });
  assert.equal(summary.exitCode, 1); assert.ok(summary.reasons.includes('baseline-identity-not-established'));
  assert.equal(summary.comparison.labels['contract-restored'], 0);
  assert.equal(summarizeGate({ candidate: fresh, baseline: fresh, expectedSuite: suite }).exitCode, 0);
});

test('HTTP v2: the identity predicate is fixed per control, consistent across probes and bound to the suite', async () => {
  const twoPredicates = [...identifyingControl, { kind: 'json.equals', pointer: '/user/team', expected: 'blue' }];
  const target = sessionTarget(twoPredicates), suite = sessionSuite(target);
  const transport = sessionTransport({ nullWhenSignedOut: true });
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session' }, transport: async (o, c, opts) => { const r = await transport(o, c, opts); return r.json?.user ? { ...r, json: { user: { ...r.json.user, team: 'blue' } } } : r; } });
  assert.equal(run.identityEvidence.actors[0].reason, 'established'); assert.equal(suite.checks[0].identityPredicate, 0);
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suite }).exitCode, 0);
  const moveFlag = probe => { probe.predicates[0].identity = false; probe.predicates[1].identity = true; };
  const partial = clone(run); moveFlag(partial.identityEvidence.actors[0].anonymous[0]);
  assert.equal(summarizeGate({ candidate: partial }).exitCode, 2, 'Moving the marker in one probe is inconsistent even without a suite.');
  const consistent = clone(run); const entry = consistent.identityEvidence.actors[0];
  // Only the identity control's probes carry an identity marker (the surface probes have none).
  [...entry.before, ...entry.after, ...entry.anonymous, ...entry.invalid, ...entry.cross].filter(p => p.controlId === 'whoami').forEach(moveFlag);
  assert.equal(summarizeGate({ candidate: consistent, expectedSuite: suite }).exitCode, 2, 'The suite names predicate 0 as the identity predicate.');
});

test('HTTP v2: identity controls, refusal statuses and evidence origin must match the expected suite', async () => {
  const target = sessionTarget(identifyingControl);
  target.checks.splice(1, 0, { ...target.checks[0], id: 'whoami-2', path: '/me-2' }); target.requiredControlIds = ['whoami', 'whoami-2', 'member-own'];
  const suite = sessionSuite(target), base = sessionTransport({ nullWhenSignedOut: true });
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session' }, transport: (o, c, opts) => base(o, c.path === '/me-2' ? { ...c, path: '/me' } : c, opts) });
  assert.deepEqual(run.identityEvidence.actors[0].identityControlIds, ['whoami', 'whoami-2']);
  assert.deepEqual(['before', 'after', 'anonymous', 'invalid'].map(kind => run.identityEvidence.actors[0][kind].map(p => p.controlId)), [['whoami', 'whoami-2', 'member-own'], ['whoami', 'whoami-2', 'member-own'], ['whoami', 'whoami-2'], ['whoami', 'whoami-2']], 'Every identity control is bracketed and probed, not only the first (the surface control is bracketed only).');
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suite }).exitCode, 0);
  // Dropping one identity control and all of its probes is internally consistent, but not what the suite declares.
  const subset = clone(run), entry = subset.identityEvidence.actors[0];
  entry.identityControlIds = ['whoami']; for (const kind of ['before', 'after', 'anonymous', 'invalid', 'cross']) entry[kind] = entry[kind].filter(p => p.controlId === 'whoami');
  // actor-identity/4 closes the documented limit: the dropped control is recomputed as a surface control, whose bracket
  // probes the edited evidence no longer carries, so the subset is refused even without the suite.
  assert.equal(summarizeGate({ candidate: subset }).exitCode, 2, 'A dropped identity control is refused without the suite (actor-identity/4).');
  assert.equal(summarizeGate({ candidate: subset, expectedSuite: suite }).exitCode, 2);
  // Refusal statuses widened with an undeclared redirect.
  const widened = clone(run); widened.identityEvidence.actors[0].refusalStatuses = [401, 403, 307];
  assert.equal(summarizeGate({ candidate: widened }).exitCode, 0, 'Consistent without the suite (no probe saw 307).');
  assert.equal(summarizeGate({ candidate: widened, expectedSuite: suite }).exitCode, 2);
  // An HTTP suite never accepts a run labelled with another evidence origin.
  const relabelled = clone(run); relabelled.evidenceOrigin = 'synthetic-local-http';
  assert.equal(summarizeGate({ candidate: relabelled, expectedSuite: suite }).exitCode, 2);
  assert.deepEqual(summarizeGate({ candidate: relabelled, expectedSuite: suite }).reasons, ['unexpected-suite-evidence']);
  assert.deepEqual(summarizeGate({ candidate: repaired, expectedSuite: suite }).reasons, ['unexpected-suite-evidence'], 'A genuine synthetic run never matches an HTTP suite.');
  assert.equal(suite.evidenceOrigin, 'local-http-response');
});

test('HTTP v2 probe lists and applied timeouts are recomputed: dropped, duplicated or self-credited probes and impossible timeouts are refused', async () => {
  const target = sessionTarget(identifyingControl);
  target.actors.other = { principalId: 'other', credentialEnv: 'SCOPEHAVEN_TARGET_SESSION_OTHER', identityValue: 'other@example.test' };
  target.checks.push({ ...target.checks[0], id: 'other-whoami', title: 'Other session', actorId: 'other', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user/email', expected: 'other@example.test' }] });
  target.requiredControlIds = ['whoami', 'other-whoami', 'member-own'];
  const transport = async (_, check, options) => {
    const email = { 'synthetic-session': 'member@example.test', 'other-session': 'other@example.test' }[options.credential];
    if (check.path === '/me') return email ? { status: 200, complete: true, jsonParsed: true, json: { user: { email } }, bytes: 40 } : { status: 401, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
    if (check.path === '/own') return email ? { status: 200, complete: true, jsonParsed: true, json: { items: [] }, bytes: 12 } : { status: 302, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
    return { status: email ? 403 : 302, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
  };
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session', SCOPEHAVEN_TARGET_SESSION_OTHER: 'other-session' }, transport });
  const suite = sessionSuite(target);
  assert.deepEqual(run.identityEvidence.actors.map(a => [a.actorId, a.reason, a.cross.map(p => p.crossActorId)]), [['member', 'established', ['other']], ['other', 'established', ['member']]]);
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suite }).exitCode, 0);
  const edits = [
    ['cross probe dropped', run => { run.identityEvidence.actors[0].cross = []; }],
    ['invalid probe dropped', run => { run.identityEvidence.actors[0].invalid = []; }],
    ['cross probe credited to the actor itself', run => { run.identityEvidence.actors[0].cross[0].crossActorId = 'member'; }],
    ['cross probe duplicated', run => { const entry = run.identityEvidence.actors[1]; entry.cross = [entry.cross[0], entry.cross[0]]; }],
    ['attempted probe with no applied timeout', run => { run.identityEvidence.actors[0].anonymous[0].requestTimeoutMs = 0; }],
    ['fractional applied timeout', run => { run.identityEvidence.actors[0].invalid[0].requestTimeoutMs = 1.5; }],
    ['applied timeout missing', run => { delete run.identityEvidence.actors[1].cross[0].requestTimeoutMs; }],
  ];
  for (const [label, edit] of edits) {
    const copy = clone(run); edit(copy);
    assert.equal(summarizeGate({ candidate: copy }).exitCode, 2, label); assert.equal(summarizeGate({ candidate: copy, expectedSuite: suite }).exitCode, 2, label);
  }
});

test('HTTP v2: an actor cannot claim another actor\'s control as its identity control, even with consistent probes', async () => {
  const target = sessionTarget(identifyingControl);
  target.actors.other = { principalId: 'other', credentialEnv: 'SCOPEHAVEN_TARGET_SESSION_OTHER', identityValue: 'other@example.test' };
  target.checks.push({ ...target.checks[0], id: 'other-whoami', title: 'Other session', actorId: 'other', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user/email', expected: 'other@example.test' }] });
  target.requiredControlIds = ['whoami', 'other-whoami', 'member-own'];
  const transport = async (_, check, options) => {
    const email = { 'synthetic-session': 'member@example.test', 'other-session': 'other@example.test' }[options.credential];
    if (check.path === '/me') return email ? { status: 200, complete: true, jsonParsed: true, json: { user: { email } }, bytes: 40 } : { status: 401, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
    if (check.path === '/own') return email ? { status: 200, complete: true, jsonParsed: true, json: { items: [] }, bytes: 12 } : { status: 302, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
    return { status: email ? 403 : 302, complete: true, jsonParsed: false, bytes: 0, error: 'invalid-json' };
  };
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session', SCOPEHAVEN_TARGET_SESSION_OTHER: 'other-session' }, transport });
  assert.equal(summarizeGate({ candidate: run }).exitCode, 0);
  const claimed = clone(run), member = claimed.identityEvidence.actors[0], other = claimed.identityEvidence.actors[1];
  const pass = kind => ({ controlId: 'other-whoami', kind, requestAttempted: true, requestTimeoutMs: 3000, httpStatus: 200, transportOutcome: 'complete', statusOutcome: 'pass', predicates: [{ kind: 'json.equals', outcome: 'pass', identity: true }], outcome: 'pass' });
  Object.assign(member, { identityControlIds: ['other-whoami'], before: [pass('before')], after: [pass('after')], anonymous: other.anonymous.map(p => ({ ...p })), invalid: other.invalid.map(p => ({ ...p })), cross: other.cross.map(p => ({ ...p, crossActorId: 'other' })) });
  assert.equal(summarizeGate({ candidate: claimed }).exitCode, 2);
});

test('HTTP v2 timed-out identity requests: a refusal status counts even if its body stalls; no status or an unfinished 2xx is incomplete; a stalled 5xx is not a refusal', async () => {
  const strict = sessionTarget(identifyingControl), suite = sessionSuite(strict);
  const cases = [
    [{ status: 401, complete: false, jsonParsed: false, bytes: 0, error: 'timeout' }, 'established', 0],
    [{ status: null, complete: false, jsonParsed: false, bytes: 0, error: 'timeout' }, 'identity-probe-incomplete', 1],
    [{ status: 200, complete: false, jsonParsed: false, bytes: 10, error: 'timeout' }, 'identity-probe-incomplete', 1],
    [{ status: 500, complete: false, jsonParsed: false, bytes: 0, error: 'timeout' }, 'not-refused-without-credential', 1],
  ];
  for (const [anonymous, reason, exitCode] of cases) {
    const base = sessionTransport({ nullWhenSignedOut: true });
    const run = await runHttpAssessment(strict, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session' }, transport: async (o, c, opts) => c.path === '/me' && opts.credential === undefined ? anonymous : base(o, c, opts) });
    assert.equal(run.identityEvidence.actors[0].reason, reason, JSON.stringify(anonymous));
    assert.equal(summarizeGate({ candidate: run, expectedSuite: suite }).exitCode, exitCode, JSON.stringify(anonymous));
  }
});

test('HTTP v2: a probe the run budget never sent must be recorded as an unattempted timeout', async () => {
  const strict = sessionTarget(identifyingControl, { surface: false }), base = sessionTransport({ nullWhenSignedOut: true });
  const slow = async (o, c, opts) => { if (c.path === '/foreign') await new Promise(resolve => setTimeout(resolve, 200)); return base(o, c, opts); };
  const run = await runHttpAssessment(strict, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session' }, transport: slow, limits: { requestTimeoutMs: 100, runTimeoutMs: 150, responseBytes: 1024 } });
  const after = run.identityEvidence.actors[0].after[0];
  assert.deepEqual([after.requestAttempted, after.requestTimeoutMs, after.httpStatus, after.transportOutcome, after.outcome], [false, 0, null, 'timeout', 'error']);
  assert.equal(run.identityEvidence.actors[0].reason, 'identity-probe-incomplete');
  assert.equal(summarizeGate({ candidate: run }).exitCode, 1);
  const relabelled = clone(run); relabelled.identityEvidence.actors[0].after[0].transportOutcome = 'network';
  assert.equal(summarizeGate({ candidate: relabelled }).exitCode, 2);
});

// A pair must agree on actors, login modes and identity controls, and a same-profile baseline is held to the suite.
test('an edited baseline that drops an unproven actor\'s identity binding never shows a fix', async () => {
  const target = sessionTarget(identifyingControl); target.checks[1].assertions = [{ kind: 'status.equals', expected: 403 }];
  const suite = sessionSuite(target);
  const expired = await sessionRun(target, { alive: false, nullWhenSignedOut: true }), fresh = await sessionRun(target, { nullWhenSignedOut: true });
  assert.deepEqual(summarizeGate({ candidate: fresh, baseline: expired, expectedSuite: suite }).reasons, ['baseline-identity-not-established', 'comparison-incomplete']);
  // Remove the actor's identity entry, relabel its rows uncredentialed and apply the uncredentialed-actor assertion rule, then reseal.
  const forged = clone(expired); forged.identityEvidence.actors = [];
  for (const row of forged.results) {
    row.trace[0].data.credentialMode = 'none'; row.assertions = row.assertions.filter(a => a.name !== IDENTITY);
    // actor-identity/6: the assertion's expected text, and a withheld row's summary naming its reason and the failed controls.
    if (row.id === 'member-denied') {
      row.assertions.push({ name: IDENTITY, status: 'inconclusive', expected: IDENTITY_EXPECTED, actual: 'A required control for this actor did not pass' });
      row.summary = withheldSummary('control-not-passed', ['whoami', 'member-own'], true);
    }
    row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions });
  }
  recount(forged);
  assert.equal(compareRuns(forged, fresh).compatible, false, 'Login modes differ across the pair.');
  assert.equal(compareRuns(forged, fresh).rows.filter(r => r.transition === 'contract-restored').length, 0);
  assert.deepEqual(summarizeGate({ candidate: fresh, baseline: forged, expectedSuite: suite }).reasons, ['unexpected-suite-evidence'], 'A same-profile baseline is held to the suite.');
  const unbound = summarizeGate({ candidate: fresh, baseline: forged });
  assert.equal(unbound.exitCode, 1); assert(unbound.reasons.includes('incompatible-baseline'));
});

test('without a suite, a candidate whose identity binding was edited never compares as restored', async () => {
  const target = sessionTarget(identifyingControl);
  target.checks.splice(1, 0, { ...target.checks[0], id: 'whoami-2', path: '/me-2' }); target.requiredControlIds = ['whoami', 'whoami-2', 'member-own'];
  const base = sessionTransport({ nullWhenSignedOut: true });
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_SESSION: 'synthetic-session' }, transport: (o, c, opts) => base(o, c.path === '/me-2' ? { ...c, path: '/me' } : c, opts) });
  const baseline = clone(run);
  assert.equal(compareRuns(baseline, run).compatible, true);
  const subset = clone(run), entry = subset.identityEvidence.actors[0];
  entry.identityControlIds = ['whoami']; for (const kind of ['before', 'after', 'anonymous', 'invalid', 'cross']) entry[kind] = entry[kind].filter(p => p.controlId === 'whoami');
  const widened = clone(run); widened.identityEvidence.actors[0].refusalStatuses = [401, 403, 307];
  // actor-identity/4: dropping an identity control is refused on its own (the dropped control's surface brackets are missing).
  assert.equal(summarizeGate({ candidate: subset }).exitCode, 2, 'identity control dropped: refused alone (actor-identity/4)');
  for (const [label, edited] of [['identity control dropped', subset], ['refusal status added', widened]]) {
    if (edited === widened) assert.equal(summarizeGate({ candidate: edited }).exitCode, 0, `${label}: consistent alone (documented limit)`);
    const comparison = compareRuns(baseline, edited);
    assert.equal(comparison.compatible, false, label); assert(comparison.reasons.includes('Actors, login modes or identity controls differ between the runs.'), label);
    assert.equal(comparison.rows.filter(r => r.transition === 'contract-restored').length, 0, label);
    assert.equal(comparison.restorationLabel, 'Unverified changes', `${label}: an incompatible pair never carries a restored label`);
  }
  // A compatible HTTP pair is never labelled like an incompatible one, and keeps its response-only scope.
  const honest = compareRuns(baseline, run);
  assert.equal(honest.compatible, true); assert.notEqual(honest.restorationLabel, 'Unverified changes', 'A compatible HTTP pair is not labelled as an incompatible one.');
  assert.match(honest.evidenceScope, /^Response comparison only/);
});

test('honest pairs are unchanged: same-profile v2 pairs stay comparable and another profile is incompatible, not invalid', async () => {
  const target = sessionTarget(identifyingControl), suite = sessionSuite(target);
  const a = await sessionRun(target, { nullWhenSignedOut: true }), b = await sessionRun(target, { nullWhenSignedOut: true });
  assert.equal(compareRuns(a, b).compatible, true); assert.equal(summarizeGate({ candidate: b, baseline: a, expectedSuite: suite }).exitCode, 0);
  const other = sessionTarget(identifyingControl); other.checks[1].assertions = [{ kind: 'status.equals', expected: 403 }];
  const old = await sessionRun(other, { nullWhenSignedOut: true });
  const summary = summarizeGate({ candidate: b, baseline: old, expectedSuite: suite });
  assert.equal(summary.exitCode, 1); assert(summary.reasons.includes('incompatible-baseline'));
});
