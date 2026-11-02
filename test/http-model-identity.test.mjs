// Synthetic local transports and hash-chained tap frames; no model/provider calls.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, rename, symlink, truncate } from 'node:fs/promises';
import { statSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { compareRuns, runAssessment } from '../src/runner.mjs';
import { createStore } from '../src/store.mjs';
import { summarizeGate, parseArgs, runGate } from '../integrations/regression-gate/gate.mjs';
import { buildReport } from '../integrations/github-action/summary.mjs';
import { TapLog, TAP_SCHEMA, createModelTap, CHAIN_START, chainHash } from '../integrations/model-identity/tap.mjs';
import { strictModelIdentity, beginModelIdentityCapture, finishModelIdentityCapture } from '../src/http-model-identity.mjs';

const profile = buildLabel => ({ id: 'stub-app', name: 'Synthetic transport', applicationId: 'stub-app', origin: 'http://127.0.0.1:4318',
  buildLabel, contextId: 'synthetic-stub-v1', actors: { anonymous: { principalId: 'anonymous' } }, requiredControlIds: ['allowed'], checks: [
    { id: 'allowed', title: 'Allowed', category: 'Synthetic', severity: 'control', actorId: 'anonymous', method: 'GET', path: '/allowed', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'boundary', title: 'Boundary', category: 'Synthetic', severity: 'high', actorId: 'anonymous', method: 'GET', path: '/boundary', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
  ] });
const observation = status => ({ status, complete: true, jsonParsed: true, json: {}, bytes: 2 });
async function scratch(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-model-capture-'));
  t.after(() => rm(dir, { recursive: true, force: true })); return dir;
}
function openLog(path, { ollamaTags = false } = {}) {
  const log = new TapLog({ path });
  log.push({ kind: 'open', schema: TAP_SCHEMA, session: log.session, upstream: 'http://127.0.0.1:11434', ollamaTags });
  return log;
}
function call(log, served = 'stub-model-A', fingerprints = ['stub-fingerprint']) {
  const conn = `stub-${log.seq}`;
  log.push({ kind: 'call', conn, api: 'openai-chat', requested: 'operator-requested-name', stream: false });
  log.push({ kind: 'result', conn, status: 200, served, fingerprints, reqSha256: 'a'.repeat(64), resSha256: 'b'.repeat(64) });
}
async function captured(t, { build = 'before', repaired = true, served = ['stub-model-A'], fingerprints = ['stub-fingerprint'], weights = null, extra, envCapture = false, noCalls = false, openAtEnd = false, liveTap = false, tapOverrides = {} } = {}) {
  const dir = await scratch(t), path = join(dir, 'tap.jsonl');
  const log = openLog(path, { ollamaTags: weights !== null }); t.after(() => log.close());
  if (weights) log.push({ kind: 'models', available: true, models: [{ name: 'stub-model-A:latest', digest: weights }] });
  call(log, ['old-unrelated-model']); // Must not appear in this assessment's window.
  const from = log.seq;
  const transport = async (_origin, check) => {
    if (check.path === '/boundary') {
      if (!noCalls) call(log, served, fingerprints);
      if (weights) log.push({ kind: 'models', available: true, models: [{ name: 'stub-model-A:latest', digest: weights }] });
      await extra?.(log, path);
      if (!openAtEnd && !liveTap) log.push({ kind: 'close', inflight: 0 });
    }
    return observation(check.path === '/boundary' ? repaired ? 403 : 200 : 200);
  };
  // tapOverrides keeps accessors (a changing in-flight count), so it is applied as property descriptors.
  const tap = Object.defineProperties({ log, inflight: 0, mark: async () => ({ seq: log.push({ kind: 'models', phase: 'mark', available: true, models: weights ? [{ name: 'stub-model-A:latest', digest: weights }] : [] }).seq }) }, Object.getOwnPropertyDescriptors(tapOverrides));
  const run = await runHttpAssessment(profile(build), { env: envCapture ? { SCOPEHAVEN_MODEL_TAP_LOG: path } : {}, ...(liveTap ? { modelTap: tap } : envCapture ? {} : { modelTapLog: path }), transport });
  return { run, from, dir };
}

test('HTTP producer brackets tap calls, retains provenance and persists identity via env configuration', async t => {
  const { run, from, dir } = await captured(t, { envCapture: true });
  assert.equal(run.modelIdentity.state, 'observed');
  assert.equal(run.modelIdentity.strength, 'vendor-fingerprint');
  assert.equal(run.modelIdentity.routing, 'declared-by-operator');
  assert.equal(run.modelIdentity.custody, 'tap-file');
  assert.deepEqual(run.modelIdentity.window, { from, to: from + 3 });
  assert.equal(run.modelIdentity.calls.total, 1);
  assert.equal(run.modelIdentity.models[0].served, 'stub-model-A');
  assert.equal(run.modelIdentity.models[0].weightsDigest, null);
  assert.match(run.modelIdentity.head, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(run.modelIdentity).includes('old-unrelated-model'));
  assert.ok(!JSON.stringify(run).includes('tap.jsonl'));
  const store = createStore(join(dir, 'store')); await store.ready;
  const saved = await store.save(run), loaded = await store.get(saved.id);
  assert.deepEqual(loaded.modelIdentity, run.modelIdentity);
});

test('same observed model and changed app credits the repair, at vendor-reported strength', async t => {
  const before = (await captured(t, { build: 'before', repaired: false, liveTap: true })).run;
  const after = (await captured(t, { build: 'after', liveTap: true })).run;
  assert.deepEqual([before.modelIdentity.custody, after.modelIdentity.custody], ['tap-memory', 'tap-memory']);
  const comparison = compareRuns(before, after);
  assert.equal(comparison.compatible, true);
  assert.equal(comparison.modelAttribution.relation, 'same');
  assert.equal(comparison.modelAttribution.flipCause, 'app');
  assert.match(comparison.restorationLabel, /vendor/);
  const gate = summarizeGate({ baseline: before, candidate: after, requireModelIdentity: true });
  assert.deepEqual(gate.reasons, []);
  assert.deepEqual(gate.comparison.modelIdentityPolicy, { required: true, met: true, causes: [] });
  assert.equal(buildReport({ baselineInput: before, baselineState: 'ok', runInput: after, gateInput: gate, gateState: 'ok', requireModelIdentity: 'true' }).decision, 'pass');
  // Without the switch the summary carries no policy field.
  assert.equal(Object.hasOwn(summarizeGate({ baseline: before, candidate: after }).comparison, 'modelIdentityPolicy'), false);
});

test('different served model does not earn an application repair; strict reads it comparable, not unverified', async t => {
  const before = (await captured(t, { repaired: false, liveTap: true })).run;
  const after = (await captured(t, { build: 'after', served: ['stub-model-B'], liveTap: true })).run;
  assert.equal(compareRuns(before, after).modelAttribution.relation, 'different');
  assert.deepEqual(summarizeGate({ baseline: before, candidate: after, requireModelIdentity: true }).reasons, ['repair-not-attributable']);
});

// L2: strict requires comparable identity, not identical models (the README's rule).
test('strict accepts a different or silently changed model when no verdict moved, and names nothing to fix', async t => {
  const before = (await captured(t, { build: 'before', liveTap: true })).run;
  for (const [label, options, relation] of [['different', { served: ['stub-model-B'] }, 'different'], ['silent change', { fingerprints: ['stub-fingerprint-2'] }, 'silent-change']]) {
    const after = (await captured(t, { build: 'after', liveTap: true, ...options })).run;
    const gate = summarizeGate({ baseline: before, candidate: after, requireModelIdentity: true });
    assert.equal(gate.comparison.modelAttribution.relation, relation, label);
    assert.deepEqual([gate.exitCode, gate.reasons], [0, []], label);
    assert.equal(buildReport({ baselineInput: before, baselineState: 'ok', runInput: after, gateInput: gate, gateState: 'ok', requireModelIdentity: 'true' }).decision, 'pass', label);
  }
});

test('strict leaves a subject no model serves unaffected', async () => {
  const [vulnerable, repaired] = [await runAssessment('demo-vulnerable'), await runAssessment('demo-repaired')];
  const comparison = compareRuns(vulnerable, repaired);
  assert.equal(Object.hasOwn(comparison, 'modelAttribution'), false);
  assert.deepEqual(strictModelIdentity(comparison, vulnerable, repaired), { reasons: [], causes: [] });
  assert.deepEqual(summarizeGate({ baseline: vulnerable, candidate: repaired, requireModelIdentity: true }), summarizeGate({ baseline: vulnerable, candidate: repaired }));
});

test('weights are recorded only with matching bracketing model-list evidence', async t => {
  const { run } = await captured(t, { weights: 'a'.repeat(64) });
  assert.equal(run.modelIdentity.strength, 'weights-digest');
  assert.equal(run.modelIdentity.models[0].weightsDigest, 'a'.repeat(64));
  const partial = (await captured(t, { extra: log => log.push({ kind: 'gap', reason: 'stub-observation-gap' }) })).run;
  assert.equal(partial.modelIdentity.state, 'partial');
});

test('legacy no-tap runs remain absent; default behavior is retained and strict fails closed', async () => {
  const transport = async (_o, c) => observation(c.path === '/boundary' ? 403 : 200);
  const run = await runHttpAssessment(profile('same'), { env: {}, transport });
  assert.equal(Object.hasOwn(run, 'modelIdentity'), false);
  assert.deepEqual(summarizeGate({ baseline: run, candidate: { ...run, id: '11111111-1111-4111-8111-111111111111' } }).reasons, []);
  assert.ok(summarizeGate({ baseline: run, candidate: run, requireModelIdentity: true }).reasons.includes('model-identity-not-recorded'));
  const report = buildReport({ runInput: run, baselineInput: run, baselineState: 'ok', failOn: 'never', requireModelIdentity: 'true' });
  assert.deepEqual([report.decision, report.reason], ['fail', 'model-identity-not-recorded']);
});

test('partial, mixed, requested-only and no-call identities fail strict even without a verdict flip', async t => {
  const observed = (await captured(t, { liveTap: true })).run;
  const partial = (await captured(t, { liveTap: true, extra: log => log.push({ kind: 'gap', reason: 'stub-gap' }) })).run;
  const mixed = (await captured(t, { liveTap: true, served: ['stub-model-A', 'stub-model-B'] })).run;
  const requestedOnly = (await captured(t, { liveTap: true, served: [], fingerprints: [] })).run;
  const noCalls = (await captured(t, { liveTap: true, noCalls: true })).run;
  assert.equal(noCalls.modelIdentity.state, 'not-observed');
  for (const candidate of [partial, mixed, requestedOnly, noCalls]) {
    const gate = summarizeGate({ baseline: observed, candidate, requireModelIdentity: true });
    assert.deepEqual(gate.reasons, ['model-identity-unverified']);
    assert.ok(gate.comparison.modelIdentityPolicy.causes.length > 0);
    const report = buildReport({ baselineInput: observed, baselineState: 'ok', runInput: candidate, failOn: 'never', requireModelIdentity: 'true' });
    assert.deepEqual([report.decision, report.reason], ['fail', 'model-identity-unverified']);
    assert.match(report.markdown, /Model identity policy not met: /);
  }
  const partialCauses = strictModelIdentity(compareRuns(observed, partial), observed, partial).causes;
  assert.deepEqual(partialCauses, [{ side: 'candidate', reason: 'model-partial' }, { side: 'candidate', reason: 'stub-gap' }, { side: 'pair', reason: 'candidate-model-partial' }]);
});

test('unreadable, replaced, truncated and broken-chain logs never become observed identity', async t => {
  const dir = await scratch(t);
  const legacyTransport = async (_o, c) => observation(c.path === '/boundary' ? 403 : 200);
  for (const path of [join(dir, 'missing'), 'relative-log']) {
    const run = await runHttpAssessment(profile('before'), { env: {}, modelTapLog: path, transport: legacyTransport });
    assert.equal(run.modelIdentity.state, 'partial'); assert.equal(run.modelIdentity.models.length, 0);
    // L4: a capture failure names only its own reason, claims no window, and keeps its custody.
    assert.deepEqual([run.modelIdentity.reasons, run.modelIdentity.window, run.modelIdentity.custody], [['tap-log-unavailable-at-start'], null, 'tap-file']);
  }
  for (const extra of [async (_l, path) => writeFile(path, ''), async (_l, path) => { _l.push({ kind: 'close', inflight: 0 }); const identical = await readFile(path); await rename(path, path + '.old'); await writeFile(path, identical); }, log => log.push({ kind: 'gap', reason: 'log-chain-break' })]) {
    const run = (await captured(t, { extra })).run;
    assert.equal(run.modelIdentity.state, 'partial');
  }
  const logPath = join(dir, 'symlink-log'), real = join(dir, 'real'); await writeFile(real, ''); await symlink(real, logPath);
  const run = await runHttpAssessment(profile('before'), { env: {}, modelTapLog: logPath, transport: legacyTransport });
  assert.equal(run.modelIdentity.state, 'partial');
});

test('malformed saved identity fails strict; invalid CI strict flag is a setup failure', async t => {
  const good = (await captured(t)).run;
  const bad = { ...good, modelIdentity: { state: 'observed', models: [null] } };
  // L3: as without the policy, a malformed identity keeps model-identity-not-recorded beside it.
  assert.deepEqual(summarizeGate({ baseline: good, candidate: bad, requireModelIdentity: true }).reasons, ['model-identity-malformed', 'model-identity-not-recorded']);
  assert.equal(buildReport({ baselineInput: good, baselineState: 'ok', runInput: bad, requireModelIdentity: 'true', failOn: 'never' }).reason, 'model-identity-malformed');
  assert.equal(buildReport({ runInput: good, requireModelIdentity: 'TRUE' }).reason, 'invalid-require-model-identity');
  assert.equal(buildReport({ runInput: good, requireModelIdentity: 'true', failOn: 'never' }).reason, 'model-identity-baseline-required');
});

test('open disk prefixes stay unknown, including when later writes fail in memory only', async t => {
  const open = (await captured(t, { openAtEnd: true })).run;
  assert.equal(open.modelIdentity.state, 'partial');
  assert.ok(open.modelIdentity.reasons.includes('tap-log-not-closed-at-end'));
  const failed = (await captured(t, { openAtEnd: true, extra: log => {
    // Simulate the exact TapLog disk-failure behavior: new records remain in
    // memory, but no later disk write (including close) is made.
    log.writeError = 'synthetic-write-failure';
    call(log, ['stub-model-B']);
  } })).run;
  assert.equal(failed.modelIdentity.state, 'partial');
  assert.equal(failed.modelIdentity.models.length, 0);
});

test('live tap marks support an open complete window and matching weights snapshots', async t => {
  for (const weights of [null, 'a'.repeat(64)]) {
    const { run } = await captured(t, { liveTap: true, weights });
    assert.equal(run.modelIdentity.state, 'observed');
    assert.equal(run.modelIdentity.strength, weights ? 'weights-digest' : 'vendor-fingerprint');
    assert.equal(run.modelIdentity.calls.total, 1);
    assert.equal(run.modelIdentity.custody, 'tap-memory');
  }
});

test('live capture refuses hidden disk failure, malformed marks and calls in flight', async t => {
  const failed = (await captured(t, { liveTap: true, extra: log => { log.writeError = 'synthetic-write-failure'; call(log, ['stub-model-A']); } })).run;
  assert.equal(failed.modelIdentity.state, 'partial');
  const transport = async (_o, c) => observation(c.path === '/boundary' ? 403 : 200);
  const dir = await scratch(t), log = openLog(join(dir, 'live.jsonl')); t.after(() => log.close());
  for (const modelTap of [{ log, inflight: 1, mark: async () => ({ seq: 1 }) }, { log, inflight: 0, mark: async () => ({ seq: -1 }) }, { log, inflight: 0, mark: async () => { throw new Error('synthetic'); } }]) {
    const run = await runHttpAssessment(profile('before'), { env: {}, modelTap, transport });
    assert.equal(run.modelIdentity.state, 'partial');
  }
  const both = await runHttpAssessment(profile('before'), { env: {}, modelTap: {}, modelTapLog: join(dir, 'live.jsonl'), transport });
  assert.equal(both.modelIdentity.state, 'partial');
  assert.ok(both.modelIdentity.reasons.includes('tap-capture-ambiguous-sources'));
});

test('strict policy rejects unsupported identity schema and unreadable strength', async t => {
  const good = (await captured(t)).run;
  for (const mutation of [{ schema: 'unknown-schema' }, { strength: 'invented-strength' }, { models: [{ ...good.modelIdentity.models[0], strength: 'invented-strength' }] }]) {
    const candidate = { ...good, modelIdentity: { ...good.modelIdentity, ...mutation } };
    assert.ok(summarizeGate({ baseline: good, candidate, requireModelIdentity: true }).reasons.includes('model-identity-malformed'));
    assert.equal(buildReport({ baselineInput: good, baselineState: 'ok', runInput: candidate, failOn: 'never', requireModelIdentity: 'true' }).reason, 'model-identity-malformed');
  }
});

test('the existing real tap can capture a live marked window over a fixed loopback stub', async t => {
  const upstream = createServer(async (req, res) => {
    for await (const _chunk of req) {}
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ model: 'fixed-loopback-stub', system_fingerprint: 'fixed-stub-fingerprint', choices: [] }));
  });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { upstream.close(resolve); upstream.closeAllConnections(); }));
  const tap = createModelTap({ upstream: `http://127.0.0.1:${upstream.address().port}`, ollamaTags: false });
  await tap.start(); t.after(() => tap.stop());
  const run = await runHttpAssessment(profile('before'), { env: {}, modelTap: tap, transport: async (_o, c) => {
    if (c.path === '/boundary') {
      const response = await fetch(`${tap.url}/v1/chat/completions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model: 'synthetic-request', stream: false, messages: [] }) });
      await response.json();
    }
    return observation(c.path === '/boundary' ? 403 : 200);
  } });
  assert.equal(tap.log.frames.some(f => f.kind === 'close'), false);
  assert.equal(run.modelIdentity.state, 'observed');
  assert.equal(run.modelIdentity.models[0].served, 'fixed-loopback-stub');
  assert.equal(run.modelIdentity.calls.total, 1);
});

// ---- L1: capture checks, one scenario per check ----
const plainTransport = async (_o, c) => observation(c.path === '/boundary' ? 403 : 200);
// A closed tap log in a file, written by this test as another process would.
function closedLog(path, { inflight = 0 } = {}) {
  const log = openLog(path); call(log, ['stub-model-A']); log.push({ kind: 'close', inflight }); log.close(); return log;
}

test('file capture: a close frame with a call still in flight is not a closed boundary', async t => {
  const dir = await scratch(t), path = join(dir, 'tap.jsonl'), log = openLog(path);
  const run = await runHttpAssessment(profile('x'), { env: {}, modelTapLog: path, transport: async (_o, c) => {
    if (c.path === '/boundary') { call(log, ['stub-model-A']); log.push({ kind: 'close', inflight: 1 }); log.close(); }
    return plainTransport(_o, c);
  } });
  assert.deepEqual([run.modelIdentity.state, run.modelIdentity.reasons], ['partial', ['tap-log-not-closed-at-end']]);
});

test('file capture: an in-place rewrite of the start prefix (same inode, re-chained) is refused', async t => {
  const dir = await scratch(t), path = join(dir, 'tap.jsonl'), log = openLog(path);
  let sameInode = null;
  const run = await runHttpAssessment(profile('x'), { env: {}, modelTapLog: path, transport: async (_o, c) => {
    if (c.path === '/boundary') {
      call(log, ['stub-model-B']); log.push({ kind: 'close', inflight: 0 }); log.close();
      const inode = statSync(path).ino;
      let head = CHAIN_START;
      const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean).map(line => { const { h, ...body } = JSON.parse(line); if (body.kind === 'open') body.upstream = 'http://127.0.0.1:22222'; head = chainHash(head, body); return JSON.stringify({ ...body, h: head }); });
      writeFileSync(path, `${lines.join('\n')}\n`); sameInode = statSync(path).ino === inode;
    }
    return plainTransport(_o, c);
  } });
  assert.equal(sameInode, true);
  assert.deepEqual([run.modelIdentity.state, run.modelIdentity.reasons, run.modelIdentity.upstream], ['partial', ['tap-log-replaced-or-truncated'], null]);
});

test('file capture: a symlink to a valid closed log is refused at open, not read as unclosed', async t => {
  const dir = await scratch(t), real = join(dir, 'real.jsonl'), link = join(dir, 'link.jsonl'), log = openLog(real);
  await symlink(real, link);
  const run = await runHttpAssessment(profile('x'), { env: {}, modelTapLog: link, transport: async (_o, c) => {
    if (c.path === '/boundary') { call(log, ['stub-model-A']); log.push({ kind: 'close', inflight: 0 }); log.close(); }
    return plainTransport(_o, c);
  } });
  // The same log read directly opens and reads (an empty window after its close frame).
  assert.equal((await runHttpAssessment(profile('x'), { env: {}, modelTapLog: real, transport: plainTransport })).modelIdentity.state, 'not-observed');
  assert.deepEqual([run.modelIdentity.state, run.modelIdentity.reasons], ['partial', ['tap-log-unavailable-at-start']]);
});

test('file capture: a log over 64 MiB is refused at open', async t => {
  const dir = await scratch(t), path = join(dir, 'tap.jsonl');
  closedLog(path);
  await truncate(path, 64 * 1024 * 1024 + 1); // Sparse: the bytes past the closed log are zeros.
  const run = await runHttpAssessment(profile('x'), { env: {}, modelTapLog: path, transport: plainTransport });
  assert.deepEqual([run.modelIdentity.state, run.modelIdentity.reasons], ['partial', ['tap-log-unavailable-at-start']]);
});

test('live capture: start and end marks must be the tap\'s own model-list frames, in order, with nothing in flight', async t => {
  // A start mark that names a frame other than a model list.
  let marks = 0;
  const notModels = (await captured(t, { liveTap: true, tapOverrides: { mark: async function () { marks++; return { seq: this.log.push({ kind: marks === 1 ? 'meta' : 'models', phase: 'mark', available: false, reason: 'not-requested' }).seq }; } } })).run;
  assert.deepEqual([notModels.modelIdentity.state, notModels.modelIdentity.reasons], ['partial', ['tap-live-unavailable-at-start']]);
  // A call in flight at the start (a valid mark), and at the end.
  let inflight = 1;
  const busyStart = (await captured(t, { liveTap: true, tapOverrides: { get inflight() { return inflight; } } })).run;
  assert.deepEqual([busyStart.modelIdentity.state, busyStart.modelIdentity.reasons], ['partial', ['tap-live-unavailable-at-start']]);
  let calls = 0;
  const busyEnd = (await captured(t, { liveTap: true, tapOverrides: { get inflight() { return calls++ === 0 ? 0 : 1; } } })).run;
  assert.deepEqual([busyEnd.modelIdentity.state, busyEnd.modelIdentity.reasons], ['partial', ['tap-live-unavailable-at-end']]);
  // An end mark that does not come after the start mark.
  let first = null;
  const backwards = (await captured(t, { liveTap: true, tapOverrides: { mark: async function () { const seq = this.log.push({ kind: 'models', phase: 'mark', available: false, reason: 'not-requested' }).seq; first ??= seq; return { seq: first }; } } })).run;
  assert.deepEqual([backwards.modelIdentity.state, backwards.modelIdentity.reasons], ['partial', ['tap-live-unavailable-at-end']]);
});

test('live capture: in-memory frames edited after the call break the chain and are refused', async t => {
  const run = (await captured(t, { liveTap: true, served: ['stub-model-B'], extra: log => { log.frames.findLast(f => f.kind === 'result').served = ['stub-model-A']; } })).run;
  assert.deepEqual([run.modelIdentity.state, run.modelIdentity.reasons, run.modelIdentity.models], ['partial', ['tap-live-unavailable-at-end'], []]);
});

// ---- L5: an empty configuration value is no configuration ----
test('empty tap configuration values leave modelIdentity absent', async () => {
  for (const env of [{ SCOPEHAVEN_MODEL_TAP_LOG: '' }, { SCOPEHAVEN_MODEL_TAP_UPSTREAM: '', SCOPEHAVEN_MODEL_TAP_PORT: '', SCOPEHAVEN_MODEL_TAP_OLLAMA_TAGS: '' }]) {
    const run = await runHttpAssessment(profile('x'), { env, transport: plainTransport });
    assert.equal(Object.hasOwn(run, 'modelIdentity'), false, JSON.stringify(env));
  }
  assert.equal(await beginModelIdentityCapture({ path: '' }), null);
  assert.equal(await finishModelIdentityCapture(null), undefined);
});

// ---- L7: the direct gate refuses the strict switch without a baseline, as the Action does ----
test('the direct gate refuses --require-model-identity without --baseline', async t => {
  assert.throws(() => parseArgs(['--target', 'x', '--out', '/abs/out', '--require-model-identity']), /invalid-options/);
  assert.equal(parseArgs(['--target', 'x', '--out', '/abs/out', '--baseline', 'b1', '--require-model-identity']).requireModelIdentity, true);
  const out = await scratch(t);
  assert.deepEqual((await runGate({ targetId: 'demo-repaired', outputDirectory: join(out, 'gate'), requireModelIdentity: true }, { env: {} })).reasons, ['invalid-options']);
});

// ---- M3: a rewritten tap log file never becomes a strict pass (the custody rule) ----
// The model really changes from model-a to model-b. After the run, a same-user process rewrites the
// closed log in place (same inode, prefix kept, the result edited, the tail re-chained) to say model-a.
test('strict reads a tap log file as subject-writable custody: an in-place rewrite cannot turn a model swap into a credited repair', async t => {
  const state = { served: 'model-a', fingerprint: 'fp-a' };
  const upstream = createServer(async (req, res) => { for await (const _chunk of req) {} res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ model: state.served, system_fingerprint: state.fingerprint, choices: [] })); });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { upstream.close(resolve); upstream.closeAllConnections(); }));
  const dir = await scratch(t);
  const inodes = [];
  const forge = path => {
    const inode = statSync(path).ino;
    let head = CHAIN_START, editing = false;
    const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean).map(line => {
      const { h, ...body } = JSON.parse(line);
      if (body.kind === 'result') { body.served = ['model-a']; body.fingerprints = ['fp-a']; editing = true; }
      head = editing ? chainHash(head, body) : h; return JSON.stringify({ ...body, h: head });
    });
    writeFileSync(path, `${lines.join('\n')}\n`); inodes.push(inode === statSync(path).ino);
  };
  const fileRun = async (build, repaired, rewrite) => {
    const logPath = join(dir, `tap-${build}.jsonl`);
    const tap = createModelTap({ upstream: `http://127.0.0.1:${upstream.address().port}`, ollamaTags: false, log: new TapLog({ path: logPath }) });
    await tap.start();
    try {
      return await runHttpAssessment(profile(build), { env: {}, modelTapLog: logPath, transport: async (_o, c) => {
        if (c.path === '/boundary') {
          await (await fetch(`${tap.url}/v1/chat/completions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model: 'requested', stream: false, messages: [] }) })).json();
          await tap.stop(); if (rewrite) forge(logPath);
        }
        return observation(c.path === '/boundary' ? repaired ? 403 : 200 : 200);
      } });
    } finally { await tap.stop(); }
  };
  const before = await fileRun('before', false);
  state.served = 'model-b'; state.fingerprint = 'fp-b';
  const forged = await fileRun('after-forged', true, true);
  assert.deepEqual(inodes, [true]);
  // The rewrite is not visible to the reader: the forged log reads observed model-a ...
  assert.deepEqual([forged.modelIdentity.state, forged.modelIdentity.models[0].served], ['observed', 'model-a']);
  // ... so the strict policy never counts a tap-file identity, and the run fails closed.
  const gate = summarizeGate({ baseline: before, candidate: forged, requireModelIdentity: true });
  assert.deepEqual([gate.exitCode, gate.reasons], [1, ['repair-not-attributable', 'model-identity-unverified']]);
  // Without the switch the forged file still credits nothing. Its reading says the model held,
  // and a tap-file reading of a held model never credits a repair.
  const loose = summarizeGate({ baseline: before, candidate: forged });
  assert.deepEqual([loose.exitCode, loose.reasons, loose.comparison.modelAttribution.flipCause, loose.comparison.modelAttribution.relation], [1, ['repair-not-attributable'], 'model-unverified', 'same']);
  assert.match(compareRuns(before, forged).restorationLabel, /^Not attributable to the application: a model identity was read from a tap log file/);
  // The strict summary marks the policy and credits nothing; the Action's diff says so.
  assert.deepEqual([gate.comparison.modelAttribution.repairCreditedToApp, gate.comparison.modelAttribution.policy], [false, 'not-met']);
  assert.equal(forged.modelIdentity.custody, 'tap-file');
  assert.deepEqual(gate.comparison.modelIdentityPolicy.causes, [{ side: 'baseline', reason: 'subject-writable-custody' }, { side: 'candidate', reason: 'subject-writable-custody' }]);
  const report = buildReport({ baselineInput: before, baselineState: 'ok', runInput: forged, gateInput: gate, gateState: 'ok', requireModelIdentity: 'true', failOn: 'fail' });
  assert.deepEqual([report.decision, report.reason], ['fail', 'model-identity-unverified']);
  assert.match(report.markdown, /Model identity policy not met: baseline `subject-writable-custody`, candidate `subject-writable-custody`\./);
  assert.match(report.markdown, /Model identity policy not met: no change below is credited to the application\./);
  assert.match(report.markdown, /\*\*Restored \(not credited to the application\)\*\*/);
  // M-A and M-B are stated where the policy is printed.
  assert.match(report.markdown, /the run digest is a checksum, not a signature/);
  assert.match(report.markdown, /The tap sees only calls sent to its port/);
  // The same identities read as tap-memory would pass: custody alone decides here.
  const held = run => ({ ...run, modelIdentity: { ...run.modelIdentity, custody: 'tap-memory' } });
  assert.deepEqual(summarizeGate({ baseline: held(before), candidate: held(forged), requireModelIdentity: true }).reasons, []);
  // An identity saved without custody is unverified too.
  const unmarked = run => ({ ...run, modelIdentity: (({ custody, ...rest }) => rest)(run.modelIdentity) });
  assert.deepEqual(strictModelIdentity(compareRuns(unmarked(before), held(forged)), unmarked(before), held(forged)).causes, [{ side: 'baseline', reason: 'custody-not-recorded' }]);
});

// ---- L6: no wording reads a weights digest as attested weights ----
test('the Action summary keeps the upstream caveat at every strength, a weights digest included', async t => {
  const before = (await captured(t, { liveTap: true, repaired: false, weights: 'a'.repeat(64) })).run;
  const after = (await captured(t, { build: 'after', liveTap: true, weights: 'a'.repeat(64) })).run;
  assert.equal(after.modelIdentity.strength, 'weights-digest');
  const gate = summarizeGate({ baseline: before, candidate: after, requireModelIdentity: true });
  const { markdown } = buildReport({ baselineInput: before, baselineState: 'ok', runInput: after, gateInput: gate, gateState: 'ok', requireModelIdentity: 'true' });
  assert.match(markdown, /at `weights-digest`, as the model upstream reported it to the tap/);
  assert.match(markdown, /a weights digest included, is what the model upstream reported to the tap; an upstream the application controls can report any model/);
  assert.doesNotMatch(markdown, /vendor reports do not pin weights/);
});
