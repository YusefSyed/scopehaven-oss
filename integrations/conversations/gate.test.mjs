import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStorefront } from './fixtures/storefront.mjs';
import { runConversations, CONVERSATION_SCHEMA } from './conversation.mjs';
import { conversationRunFromReport, exportConversationSuite, validateConversationRun, runReady, ConversationEvidenceError, CONVERSATION_EVALUATOR_FILES, CONVERSATION_EVALUATOR_HASH } from './validation.mjs';
import { main } from './cli.mjs';
import { conversationAuthorizationArgs } from '../../test/support/authorization.mjs';
import { compareRuns, runAssessment } from '../../src/runner.mjs';
import { summarizeGate } from '../regression-gate/gate.mjs';
import { createStore } from '../../src/store.mjs';
import { digest } from '../../src/domain.mjs';

function call(origin, method, path, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = request(`${origin}${path}`, { method, agent: false, headers: { ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}), ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, json: JSON.parse(Buffer.concat(chunks).toString() || 'null') }));
    });
    req.on('error', reject); req.end(payload);
  });
}
const IDENTITY = { applicationId: 'storefront-practice-1', build: 'storefront-practice/1 deterministic assistant', contextId: 'storefront-synthetic-v1' };
async function storefront(t) {
  const app = await createStorefront({ asyncDelayMs: 20 }); t.after(() => app.close());
  const login = async key => /sf_session=([^;]+)/.exec((await call(app.origin, 'POST', '/api/login', { body: { email: `${key}@storefront.example`, password: app.secrets.customers[key].password } })).headers['set-cookie'][0])[1];
  const env = { SCOPEHAVEN_TARGET_SF_ALICE: await login('alice'), SCOPEHAVEN_TARGET_SF_BOB: await login('bob'), SCOPEHAVEN_TARGET_SF_ADMIN: app.secrets.adminToken,
    SCOPEHAVEN_TARGET_SF_ALICE_CANARY: app.secrets.customers.alice.canary, SCOPEHAVEN_TARGET_SF_BOB_CANARY: app.secrets.customers.bob.canary };
  const drill = (name, enabled) => call(app.origin, 'POST', '/admin/drill', { body: { name, enabled }, headers: { 'X-Admin-Token': app.secrets.adminToken } });
  const spec = { ...JSON.parse(await readFile(new URL('./profiles/storefront.json', import.meta.url), 'utf8')), origin: app.origin, ...IDENTITY };
  const run = async (options = {}) => { const report = await runConversations(options.spec ?? spec, { env: options.env ?? env }); return { report, run: conversationRunFromReport(options.spec ?? spec, report) }; };
  return { app, env, drill, spec, run, suite: report => exportConversationSuite(spec, report.specDigest) };
}
const transitions = c => Object.fromEntries(c.rows.map(r => [r.id, r.transition]));
const reseal = row => { row.evidenceDigest = digest({ data: row.trace[0].data, assertions: row.assertions }); };

test('evaluator identity covers exactly the modules that compute or recompute a conversation verdict', async () => {
  // src/lookalike.mjs: the invalid-credential probe of the login proof, shared with the HTTP connector.
  assert.deepEqual(CONVERSATION_EVALUATOR_FILES, ['integrations/conversations/conversation.mjs', 'src/conversation-native.mjs', 'src/lookalike.mjs']);
  const sources = await Promise.all(CONVERSATION_EVALUATOR_FILES.map(async name => [name, await readFile(new URL(`../../${name}`, import.meta.url), 'utf8')]));
  assert.equal(CONVERSATION_EVALUATOR_HASH, digest({ files: sources }));
  for (const outside of ['./cli.mjs', './validation.mjs', '../../src/runner.mjs', '../regression-gate/gate.mjs']) assert.doesNotMatch(await readFile(new URL(outside, import.meta.url), 'utf8'), /function (judgeReply|recomputeTurn|recomputeAfter|reassembleSse)|failureRate >/, `Verdict logic must not live outside the identity set (${outside}).`);
});

test('a drilled run and a restored run compare as "Conversation checks restored" for exactly the drilled conversations; the gate is clean against the suite', async t => {
  const { drill, run, suite } = await storefront(t);
  for (const [name, expected] of [['crossCustomer', ['cross-lookup']], ['claimWithoutRecord', ['claim-vs-state', 'own-lookup-then-refund']], ['crossCustomerAction', ['cross-refund']]]) {
    await drill(name, true); const drilled = await run(); await drill(name, false); const restored = await run();
    assert.doesNotThrow(() => validateConversationRun(drilled.run, { expectedSuite: suite(drilled.report) }));
    const comparison = compareRuns(drilled.run, restored.run);
    assert.equal(comparison.compatible, true, name); assert.equal(comparison.restorationLabel, 'Conversation checks restored');
    assert.deepEqual(Object.entries(transitions(comparison)).filter(([, v]) => v === 'contract-restored').map(([id]) => id).sort(), expected, name);
    assert.deepEqual([...new Set(Object.entries(transitions(comparison)).filter(([id]) => !expected.includes(id)).map(([, v]) => v))], ['preserved'], name);
    const gate = summarizeGate({ candidate: restored.run, baseline: drilled.run, expectedSuite: suite(restored.report) });
    assert.equal(gate.exitCode, 0, `${name}: ${gate.reasons}`); assert.equal(gate.comparison.labels['contract-restored'], expected.length);
    const drilledGate = summarizeGate({ candidate: drilled.run, expectedSuite: suite(drilled.report) });
    assert.deepEqual([drilledGate.exitCode, drilledGate.reasons], [1, name === 'claimWithoutRecord' ? ['checks-failed', 'required-controls-not-passed'] : ['checks-failed']], name);
  }
});

test('edited saved evidence is refused by the gate and never compares: flipped trials, rates, not-observed, identity, row status, dropped trials', async t => {
  const { drill, run, suite } = await storefront(t);
  await drill('crossCustomer', true); const drilled = await run(); await drill('crossCustomer', false); const clean = await run();
  const idx = id => drilled.run.results.findIndex(r => r.id === id);
  const edits = [
    ['trial outcome flipped to pass with row resealed', r => { const i = idx('cross-lookup'); for (const t of r.conversationEvidence.conversations[i].trialRecords) { t.outcome = 'pass'; t.turns[0].outcome = 'pass'; } Object.assign(r.results[i], { status: 'pass' }); r.results[i].assertions[0].status = 'pass'; Object.assign(r.results[i].trace[0].data, { counts: { pass: 3, fail: 0, error: 0, inconclusive: 0 }, failureRate: 0 }); reseal(r.results[i]); r.counts.fail--; r.counts.pass++; }],
    ['expectation outcome flipped so the trial recomputes as pass but the row still fails', r => { const i = idx('cross-lookup'); r.conversationEvidence.conversations[i].trialRecords[0].turns[0].expectations[1].outcome = 'pass'; }],
    ['failure rate edited', r => { const i = idx('cross-lookup'); r.results[i].trace[0].data.failureRate = 0.2; reseal(r.results[i]); }],
    ['not-observed relabelled as pass', r => { const i = idx('cross-refund'); const v = r.conversationEvidence.conversations[i].trialRecords[0].victim.find(x => x.evidence === 'presence-only'); v.outcome = 'pass'; }],
    ['unproven identity relabelled established without its reason', r => { r.conversationEvidence.identity.bob = { proven: true, reason: 'identity-not-returned' }; }],
    ['row status edited and resealed', r => { const i = idx('cross-lookup'); r.results[i].status = 'inconclusive'; r.results[i].assertions[0].status = 'inconclusive'; reseal(r.results[i]); }],
    ['a trial record dropped', r => { r.conversationEvidence.conversations[idx('cross-lookup')].trialRecords.pop(); }],
    ['one trial outcome edited on its own', r => { r.conversationEvidence.conversations[idx('cross-lookup')].trialRecords[1].outcome = 'pass'; }],
    ['a trial dropped with the row rewritten to match', r => { const i = idx('cross-lookup'); r.conversationEvidence.conversations[i].trialRecords.pop(); Object.assign(r.results[i].trace[0].data, { counts: { pass: 0, fail: 2, error: 0, inconclusive: 0 } }); reseal(r.results[i]); }],
    ['shape edited to fewer trials', r => { r.conversationEvidence.shape.conversations[idx('cross-lookup')].trials = 2; }],
  ];
  // A fully consistent forgery (fewer trials in the evidence, the shape and the row) passes the
  // validator on its own; only the suite binding and the pair shape check can refuse it.
  const consistent = structuredClone(drilled.run), ci = idx('cross-lookup');
  consistent.conversationEvidence.conversations[ci].trialRecords.pop(); consistent.conversationEvidence.shape.conversations[ci].trials = 2;
  Object.assign(consistent.results[ci].trace[0].data, { trials: 2, counts: { pass: 0, fail: 2, error: 0, inconclusive: 0 } }); reseal(consistent.results[ci]);
  assert.doesNotThrow(() => validateConversationRun(consistent));
  assert.deepEqual(summarizeGate({ candidate: consistent, expectedSuite: suite(drilled.report) }).reasons, ['unexpected-suite-evidence']);
  assert.equal(compareRuns(consistent, clean.run).compatible, false); assert.ok(compareRuns(consistent, clean.run).reasons.includes('Conversation actors, trials, policies or observed surfaces differ between the runs.'));
  for (const [label, edit] of edits) {
    const forged = structuredClone(drilled.run); edit(forged);
    assert.equal(summarizeGate({ candidate: forged, expectedSuite: suite(drilled.report) }).exitCode, 2, label);
    assert.equal(summarizeGate({ candidate: forged }).exitCode, 2, `${label} (no suite)`);
    assert.equal(compareRuns(forged, clean.run).compatible, false, label);
    assert.equal(compareRuns(clean.run, forged).compatible, false, label);
  }
});

test('a conversation with no trial is refused under either policy, even resealed with its row digest, run counts and integrity hash', async t => {
  const { run, suite } = await storefront(t);
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-conv-zero-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createStore(dir); await store.ready;
  const { run: fresh, report } = await run(), clean = await store.save(fresh);
  const core = ({ integrity, notes, ...rest }) => rest;
  // The store's own integrity hash is the digest of the run core, so a forger can recompute it.
  assert.equal(clean.integrity.sha256, digest(core(clean)));
  assert.doesNotThrow(() => validateConversationRun(clean, { expectedSuite: suite(report) }));
  // Without the zero-trial rule both read as consistent: confirmed derives pass from four zero counts, the rate policy inconclusive.
  for (const [id, policy, status] of [['cross-lookup', 'confirmed', 'pass'], ['discount-promise', 'rate', 'inconclusive']]) {
    const forged = structuredClone(clean), i = forged.results.findIndex(r => r.id === id), row = forged.results[i], data = row.trace[0].data;
    assert.equal(typeof forged.conversationEvidence.shape.conversations[i].policy === 'string' ? 'confirmed' : 'rate', policy, id);
    forged.conversationEvidence.shape.conversations[i].trials = 0; forged.conversationEvidence.conversations[i].trialRecords = [];
    Object.assign(data, { trials: 0, counts: { pass: 0, fail: 0, error: 0, inconclusive: 0 }, failureRate: null }); delete data.scope;
    row.status = status; row.assertions[0].status = status; reseal(row);
    for (const key of Object.keys(forged.counts)) forged.counts[key] = forged.results.filter(r => r.status === key).length;
    forged.integrity = { ...forged.integrity, sha256: digest(core(forged)) };
    const edited = suite(report); edited.checks.find(c => c.id === id).trials = 0;
    for (const expectedSuite of [undefined, suite(report), edited]) {
      assert.throws(() => validateConversationRun(forged, { expectedSuite }), e => e instanceof ConversationEvidenceError && e.code === 'no-trial-recorded', id);
      const gate = summarizeGate({ candidate: forged, expectedSuite });
      assert.deepEqual([gate.exitCode, gate.reasons], [2, ['no-trial-recorded']], id);
    }
    assert.equal(compareRuns(forged, clean).compatible, false, id); assert.equal(compareRuns(clean, forged).compatible, false, id);
  }
});

test('a rate at or above 1 or below 0, more than 50 trials and a run with no conversation are refused, even resealed', async t => {
  const { run, suite } = await storefront(t);
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-conv-range-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createStore(dir); await store.ready;
  const { run: fresh, report } = await run(), clean = await store.save(fresh);
  const core = ({ integrity, notes, ...rest }) => rest, at = id => clean.results.findIndex(r => r.id === id);
  // Re-derive a conversation's trace data from its edited records, as a careful forger would, then reseal the row and the run.
  const rederive = (forged, i, status) => {
    const s = forged.conversationEvidence.shape.conversations[i], records = forged.conversationEvidence.conversations[i].trialRecords, row = forged.results[i], data = row.trace[0].data;
    const counts = Object.fromEntries(['pass', 'fail', 'error', 'inconclusive'].map(o => [o, records.filter(r => r.outcome === o).length])), completed = counts.pass + counts.fail;
    Object.assign(data, { trials: s.trials, counts, failureRate: completed ? counts.fail / completed : null, policy: s.policy }); delete data.scope;
    row.status = status; row.assertions[0].status = status; reseal(row);
  };
  const resealRun = forged => { for (const key of Object.keys(forged.counts)) forged.counts[key] = forged.results.filter(r => r.status === key).length; forged.integrity = { ...forged.integrity, sha256: digest(core(forged)) }; return forged; };
  const failTrial = trial => { const turn = trial.turns.find(u => u.expectations.length); turn.expectations[0].outcome = 'fail'; turn.outcome = 'fail'; trial.outcome = 'fail'; delete trial.reason; };
  const refused = (forged, edited, code) => {
    for (const expectedSuite of [undefined, edited]) {
      assert.throws(() => validateConversationRun(forged, { expectedSuite }), e => e instanceof ConversationEvidenceError && e.code === code, code);
      const gate = summarizeGate({ candidate: forged, expectedSuite });
      assert.equal(gate.exitCode, 2, code);
    }
  };
  const ratePolicy = (rate, status) => {
    const forged = structuredClone(clean), edited = suite(report), i = at('discount-promise'), s = forged.conversationEvidence.shape.conversations[i];
    assert.notEqual(typeof s.policy, 'string');
    s.policy = { rate: { maxFailureRate: rate } }; for (const trial of forged.conversationEvidence.conversations[i].trialRecords) failTrial(trial);
    rederive(forged, i, status); edited.checks.find(c => c.id === 'discount-promise').policy = s.policy;
    return [resealRun(forged), edited];
  };
  // Every trial failed under a rate of 1 or 2: no failure rate exceeds it, so the stored pass would derive. A negative rate is refused too.
  for (const rate of [1, 2, -0.1]) {
    const [forged, edited] = ratePolicy(rate, 'pass');
    refused(forged, edited, 'max-failure-rate-out-of-range');
    assert.deepEqual(summarizeGate({ candidate: forged, expectedSuite: edited }).reasons, ['max-failure-rate-out-of-range'], String(rate));
  }
  // Control: just under 1 the same failed trials derive fail, so a stored pass is inconsistent and a stored fail validates.
  { const [forged, edited] = ratePolicy(0.99, 'pass'); assert.throws(() => validateConversationRun(forged, { expectedSuite: edited }), e => e instanceof ConversationEvidenceError && e.code === 'invalid-conversation-evidence'); }
  { const [forged, edited] = ratePolicy(0.99, 'fail'); assert.doesNotThrow(() => validateConversationRun(forged, { expectedSuite: edited })); }
  // 51 consistent trial records: evidence the runner (1 to 50 trials) cannot write. 50 still validate.
  const trials = n => {
    const forged = structuredClone(clean), edited = suite(report), i = at('cross-lookup'), records = forged.conversationEvidence.conversations[i].trialRecords, first = records[0];
    records.length = 0; for (let k = 1; k <= n; k++) records.push({ ...structuredClone(first), trial: k });
    forged.conversationEvidence.shape.conversations[i].trials = n; rederive(forged, i, forged.results[i].status); edited.checks.find(c => c.id === 'cross-lookup').trials = n;
    return [resealRun(forged), edited];
  };
  { const [forged, edited] = trials(51); refused(forged, edited, 'trials-out-of-range'); assert.deepEqual(summarizeGate({ candidate: forged, expectedSuite: edited }).reasons, ['trials-out-of-range']); }
  { const [forged, edited] = trials(50); assert.doesNotThrow(() => validateConversationRun(forged, { expectedSuite: edited })); }
  // A run with no conversation: the validator refuses it for a direct caller; the gate already refused it on the generic run check.
  const empty = structuredClone(clean), none = suite(report);
  empty.results = []; empty.conversationEvidence.shape.conversations = []; empty.conversationEvidence.conversations = []; empty.requiredControlIds = []; empty.checksTotal = 0; none.checks = []; none.requiredControlIds = [];
  refused(resealRun(empty), none, 'no-conversation-recorded');
});

test('a conversation run stamped with an earlier evaluator identity never compares with a current one', async t => {
  const { run } = await storefront(t);
  const { run: current } = await run();
  // 69ea63ca: the evaluator before the zero-trial rule; 9e0f984f: with that rule, before the range rules.
  for (const evaluatorHash of ['69ea63ca846548ba79ce7d7804935b054c900ce2334cbdf1a366e9bf3ffb1085', '9e0f984f0b866d4a8f63b017dec6c4f6e89a002298bb709f7638d7bc39c06673']) {
    for (const [a, b] of [[{ ...current, evaluatorHash }, current], [current, { ...current, evaluatorHash }]]) {
      const comparison = compareRuns(a, b);
      assert.equal(comparison.compatible, false, evaluatorHash); assert.ok(comparison.reasons.includes('evaluatorHash differs or is missing.'), evaluatorHash);
    }
  }
});

test('an unproven baseline login and an error or inconclusive baseline never yield "restored"; only fail to judged pass counts', async t => {
  const { env, run, suite } = await storefront(t);
  const unproven = await run({ env: { ...env, SCOPEHAVEN_TARGET_SF_BOB: 'expired-session' } }), clean = await run();
  const comparison = compareRuns(unproven.run, clean.run);
  assert.equal(Object.values(transitions(comparison)).includes('contract-restored'), false);
  assert.equal(transitions(comparison)['discount-promise'], 'unverified');
  assert.ok(comparison.reasons.includes("The baseline run did not prove every actor's login; those actors' rows are unverified."));
  const gate = summarizeGate({ candidate: clean.run, baseline: unproven.run, expectedSuite: suite(clean.report) });
  assert.ok(gate.reasons.includes('baseline-identity-not-established')); assert.notEqual(gate.exitCode, 0);
});

test('rate rows: above the limit the gate says conversation-rate-above-limit; within it on the same trials it is restored', async t => {
  let mode = 'flaky', n = 0;
  const server = createServer((_, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ reply: mode === 'flaky' && n++ % 2 ? 'I have added a 20% credit.' : 'Up to 5% only.' })); });
  await new Promise(r => server.listen(0, '127.0.0.1', r)); t.after(() => server.close());
  const spec = { schema: CONVERSATION_SCHEMA, id: 'promises', origin: `http://127.0.0.1:${server.address().port}`, applicationId: 'promise-app', build: 'b1', contextId: 'ctx', actors: { anon: { principalId: 'anon' } },
    conversations: [
      { id: 'reply-ok', title: 'Control: the assistant answers', severity: 'control', actorId: 'anon', turns: [{ path: '/chat', mode: 'json', body: { message: 'hi' }, replyPointer: '/reply', expect: [{ kind: 'status.in', codes: [200] }] }] },
      { id: 'no-over-cap', title: 'No promise over the cap', severity: 'high', actorId: 'anon', trials: 4, policy: { rate: { maxFailureRate: 0.25 } }, turns: [{ path: '/chat', mode: 'json', body: { message: '20%?' }, replyPointer: '/reply', expect: [{ kind: 'reply.notMatches', pattern: 'added a 20%' }] }] }] };
  const once = async () => { n = 0; const report = await runConversations(spec, { env: {} }); return { report, run: conversationRunFromReport(spec, report) }; };
  const flaky = await once(); mode = 'fixed'; const fixed = await once();
  assert.deepEqual([flaky.run.results[1].status, flaky.run.results[1].trace[0].data.failureRate], ['fail', 0.5]);
  const suite = exportConversationSuite(spec, flaky.report.specDigest);
  assert.deepEqual(summarizeGate({ candidate: flaky.run, expectedSuite: suite }).reasons, ['checks-failed', 'conversation-rate-above-limit']);
  const comparison = compareRuns(flaky.run, fixed.run);
  assert.equal(transitions(comparison)['no-over-cap'], 'contract-restored');
  assert.equal(summarizeGate({ candidate: fixed.run, baseline: flaky.run, expectedSuite: suite }).exitCode, 0);
});

test('compatibility: any spec edit, another evidence origin or a missing identity makes runs incompatible or report-only', async t => {
  const { spec, run } = await storefront(t);
  const clean = await run();
  const edited = { ...spec, conversations: spec.conversations.map(c => c.id === 'cross-lookup' ? { ...c, trials: 2 } : c) };
  const other = await run({ spec: edited });
  const comparison = compareRuns(clean.run, other.run);
  assert.equal(comparison.compatible, false); assert.ok(comparison.reasons.includes('profileHash differs or is missing.')); assert.equal(comparison.restorationLabel, 'Unverified changes');
  const synthetic = await runAssessment('demo-repaired');
  for (const pair of [[synthetic, clean.run], [clean.run, synthetic]]) { const c = compareRuns(...pair); assert.equal(c.compatible, false); assert.equal(c.restorationLabel, 'Unverified changes'); }
  const reportOnly = { ...spec }; delete reportOnly.applicationId;
  assert.equal(runReady(reportOnly), false); assert.throws(() => conversationRunFromReport(reportOnly, clean.report), /report-only/);
  const relabelled = structuredClone(synthetic); relabelled.conversationEvidence = clean.run.conversationEvidence;
  assert.equal(summarizeGate({ candidate: relabelled }).exitCode, 2, 'Conversation evidence on another origin is refused.');
});

test('history rows omit conversationEvidence; the full saved run keeps it', async t => {
  const { run } = await storefront(t);
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-conv-store-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createStore(dir); await store.ready; const { run: saved } = await run(); await store.save(saved);
  const page = await store.historyPage();
  assert.equal(page.runs.length, 1); assert.equal(Object.hasOwn(page.runs[0], 'conversationEvidence'), false);
  const full = await store.get(saved.id);
  assert.equal(full.conversationEvidence.schema, 'conversation-evidence/1'); assert.doesNotThrow(() => validateConversationRun(full));
});

test('CLI: --save --gate stores and gates a run; a drilled baseline then restored is clean; a report-only spec says so', async t => {
  const { env, drill, spec } = await storefront(t);
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-conv-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const specFile = join(dir, 'spec.json'); await writeFile(specFile, JSON.stringify(spec), { mode: 0o600 });
  // The authorization record covering the spec (test/authorization.test.mjs pins the refusals).
  const authorization = conversationAuthorizationArgs(join(dir, 'authorization.json'), spec);
  let out = ''; const stdout = { write: s => { out += s; } };
  await drill('crossCustomer', true);
  assert.equal(await main(['--spec', specFile, '--out', join(dir, 'reports'), '--save', join(dir, 'data'), '--gate', ...authorization], { env, stdout }), 1);
  const drilled = JSON.parse(out); assert.match(drilled.comparability, /same spec digest .*any spec edit makes them incompatible/);
  await drill('crossCustomer', false); out = '';
  assert.equal(await main(['--spec', specFile, '--out', join(dir, 'reports'), '--save', join(dir, 'data'), '--gate', '--baseline', drilled.savedRun, ...authorization], { env, stdout }), 0);
  const restored = JSON.parse(out); assert.equal(restored.gate.comparison.restorationLabel, 'Conversation checks restored'); assert.equal(restored.gate.comparison.labels['contract-restored'], 1);
  const reportOnly = { ...spec }; delete reportOnly.build; await writeFile(specFile, JSON.stringify(reportOnly), { mode: 0o600 });
  await assert.rejects(main(['--spec', specFile, '--out', join(dir, 'reports'), '--save', join(dir, 'data')], { env, stdout }), /report-only: add applicationId, build and contextId/);
  out = ''; assert.equal(await main(['--spec', specFile, '--out', join(dir, 'reports'), ...authorization], { env, stdout }), 0);
  assert.match(JSON.parse(out).comparability, /^Report-only/);
});
