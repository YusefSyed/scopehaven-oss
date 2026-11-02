// Model-change attribution in the core comparison.
// A run may carry modelIdentity (integrations/model-identity). For evidence origins whose
// subject can be served by a model, compareRuns credits each verdict change to the application
// or puts it down to the model, so a model swap can no longer earn a repair label.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHttpLab, makeLabProfile } from '../examples/http-lab.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { compareRuns, runAssessment } from '../src/runner.mjs';
import { summarizeGate, parseArgs, runGate } from '../integrations/regression-gate/gate.mjs';
import { compareModelIdentities, attributeComparison, appChangedBetween } from '../integrations/model-identity/attribute.mjs';
import { comparisonDocument, renderComparisonReport } from '../src/report.mjs';
import { permissionDiff, normalizeGate, buildReport, SOFT_GATE_REASONS } from '../integrations/github-action/summary.mjs';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request } from 'node:http';
import { createObservedSupportApp, bindExampleProfile } from '../examples/observed-support-app.mjs';
import { createStorefront } from '../integrations/conversations/fixtures/storefront.mjs';
import { runConversations } from '../integrations/conversations/conversation.mjs';
import { conversationRunFromReport } from '../integrations/conversations/validation.mjs';

const A = 'a'.repeat(64), B = 'b'.repeat(64);
let sessions = 0;
const identity = (served, weightsDigest) => ({ schema: 'scopehaven-model-identity/2', state: 'observed', strength: 'weights-digest',
  tapSession: `session-${++sessions}`, upstream: 'http://127.0.0.1:11434', upstreamKind: 'loopback', window: { from: 0, to: null },
  calls: { total: 3, succeeded: 3, failed: 0, abandoned: 0 }, reasons: [],
  models: [{ served, requested: [served], fingerprints: [], weightsDigest, apis: ['ollama-chat'], calls: 3, strength: 'weights-digest' }] });

// The owned HTTP lab, before and after its repair: a real fail-to-pass comparison. HTTP runs carry
// no build hash, only the declared build label, so the label is what says whether the app changed.
async function labRuns(t) {
  const lab = await createHttpLab({ build: 'baseline' }); t.after(() => lab.close());
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken };
  const baseline = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  lab.setBuild('repaired');
  const sameLabel = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  const newLabel = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v2'), { env });
  const core = compareRuns(baseline, sameLabel);
  assert.equal(core.compatible, true); assert.ok(core.rows.some(r => r.transition === 'contract-restored'));
  assert.equal(baseline.targetBuildHash, null);
  return { baseline, sameLabel, newLabel, core };
}
const withModel = (run, modelIdentity) => ({ ...run, modelIdentity });

test('a model swap under the same build label never earns the repair label', async t => {
  const { baseline, sameLabel } = await labRuns(t);
  const c = compareRuns(withModel(baseline, identity('qwen3.5:9b', A)), withModel(sameLabel, identity('gemma4:latest', B)));
  assert.equal(c.modelAttribution.state, 'recorded'); assert.equal(c.modelAttribution.relation, 'different');
  // Only a declared label says the app did not change, so the model cannot take the blame alone.
  assert.equal(c.modelAttribution.flipCause, 'confounded'); assert.equal(c.modelAttribution.app.evidence, 'declared-label');
  assert.equal(c.modelAttribution.repairCreditedToApp, false);
  assert.match(c.restorationLabel, /^Not attributable to the application: the model changed and the application may have changed too/);
  // The lab pair keeps one deliberately backend-unverified row, so the core label is the incomplete one.
  assert.equal(c.modelAttribution.coreRestorationLabel, compareRuns(baseline, sameLabel).restorationLabel);
  assert.equal(c.modelAttribution.coreRestorationLabel, 'No verified repair');
  for (const row of c.rows.filter(r => r.transition === 'contract-restored')) assert.equal(row.attribution, 'confounded');
  // The core transitions themselves are unchanged: attribution is added, never substituted.
  assert.deepEqual(c.rows.map(({ attribution, ...row }) => row), compareRuns(baseline, sameLabel).rows);
  // A silent update: same name, new weights.
  const silent = compareRuns(withModel(baseline, identity('gemma4:latest', A)), withModel(sameLabel, identity('gemma4:latest', B)));
  assert.equal(silent.modelAttribution.relation, 'silent-change'); assert.match(silent.restorationLabel, /^Not attributable/);
});

test('with the model held constant and a new build label, the repair is the application\'s', async t => {
  const { baseline, newLabel, sameLabel } = await labRuns(t);
  const c = compareRuns(withModel(baseline, identity('gemma4:latest', A)), withModel(newLabel, identity('gemma4:latest', A)));
  assert.equal(c.compatible, true); assert.equal(c.modelAttribution.flipCause, 'app'); assert.equal(c.modelAttribution.repairCreditedToApp, true);
  // A credited repair passes the core label through unchanged (here the incomplete one: the lab keeps a
  // backend-unverified row, which the gate also reports as comparison-incomplete).
  assert.equal(c.restorationLabel, compareRuns(baseline, newLabel).restorationLabel); assert.doesNotMatch(c.restorationLabel, /^Not attributable/);
  for (const row of c.rows.filter(r => r.transition === 'contract-restored')) assert.equal(row.attribution, 'app');
  // Same model, same label: run-to-run variation, credited to nobody.
  const unexplained = compareRuns(withModel(baseline, identity('gemma4:latest', A)), withModel(sameLabel, identity('gemma4:latest', A)));
  assert.equal(unexplained.modelAttribution.flipCause, 'unexplained'); assert.match(unexplained.restorationLabel, /run-to-run variation/);
});

test('without model identity on both runs the comparison says so and keeps its behaviour', async t => {
  const { baseline, sameLabel: candidate, core } = await labRuns(t);
  for (const pair of [[baseline, candidate], [withModel(baseline, identity('gemma4:latest', A)), candidate], [baseline, withModel(candidate, identity('gemma4:latest', A))]]) {
    const c = compareRuns(...pair);
    assert.equal(c.modelAttribution.state, 'not-recorded'); assert.match(c.modelAttribution.note, /may come from the model/);
    assert.equal(c.restorationLabel, core.restorationLabel); assert.deepEqual(c.rows, core.rows);
  }
  // A malformed identity is not an identity.
  assert.equal(compareRuns(withModel(baseline, { models: 'x' }), withModel(candidate, identity('gemma4:latest', A))).modelAttribution.state, 'not-recorded');
});

test('comparisons whose subject no model serves are unchanged', async () => {
  const c = compareRuns(await runAssessment('demo-vulnerable'), await runAssessment('demo-repaired'));
  assert.equal(Object.hasOwn(c, 'modelAttribution'), false);
  assert.ok(c.rows.every(r => !Object.hasOwn(r, 'attribution')));
});

// The response-only onboarding example on its leaky and secure builds: a repair with every row decided,
// so the gate's exit code shows the attribution rule alone.
async function responseOnlyRuns(t) {
  const file = JSON.parse(await readFile(new URL('../docs/profiles/response-only.example.json', import.meta.url), 'utf8'));
  const app = await createObservedSupportApp({ build: 'leaky' }); t.after(() => app.close());
  const run = async label => { const bound = bindExampleProfile(file, app).targets[0]; if (label) bound.buildLabel = label; return runHttpAssessment(bound, { env: app.env }); };
  const leaky = await run();
  app.setBuild('secure');
  const secure = await run(), secureNewLabel = await run('example support app, local test build 2');
  return { leaky, secure, secureNewLabel };
}

test('the gate fails exactly on a repair the application is not credited with', async t => {
  const { leaky, secure, secureNewLabel } = await responseOnlyRuns(t);
  const plain = summarizeGate({ baseline: leaky, candidate: secure });
  assert.equal(plain.exitCode, 0); assert.deepEqual(plain.reasons, []); assert.deepEqual(plain.comparison.modelAttribution, { state: 'not-recorded' });
  assert.ok(compareRuns(leaky, secure).summary.fixed > 0);
  const swap = summarizeGate({ baseline: withModel(leaky, identity('qwen3.5:9b', A)), candidate: withModel(secure, identity('gemma4:latest', B)) });
  assert.equal(swap.exitCode, 1); assert.deepEqual(swap.reasons, ['repair-not-attributable']);
  assert.deepEqual(swap.comparison.modelAttribution, { state: 'recorded', flipCause: 'confounded', relation: 'different', strength: 'weights-digest', repairCreditedToApp: false });
  const credited = summarizeGate({ baseline: withModel(leaky, identity('gemma4:latest', A)), candidate: withModel(secureNewLabel, identity('gemma4:latest', A)) });
  assert.equal(credited.exitCode, 0); assert.deepEqual(credited.reasons, []); assert.equal(credited.comparison.modelAttribution.flipCause, 'app');
  // Same model, same label: run-to-run variation, not the app's repair.
  const unexplained = summarizeGate({ baseline: withModel(leaky, identity('gemma4:latest', A)), candidate: withModel(secure, identity('gemma4:latest', A)) });
  assert.deepEqual(unexplained.reasons, ['repair-not-attributable']); assert.equal(unexplained.comparison.modelAttribution.flipCause, 'unexplained');
  // A model swap with nothing repaired is no repair to credit.
  const noRepair = summarizeGate({ baseline: withModel(secure, identity('qwen3.5:9b', A)), candidate: withModel(secure, identity('gemma4:latest', B)) });
  assert.equal(compareRuns(secure, secure).summary.fixed, 0); assert.equal(noRepair.exitCode, 0); assert.deepEqual(noRepair.reasons, []);
});

test('a supplied comparison must carry the attribution the gate recomputes; one saved before attribution is accepted only where it reads not-recorded', async t => {
  const { leaky, secure } = await responseOnlyRuns(t);
  const swapped = [withModel(leaky, identity('qwen3.5:9b', A)), withModel(secure, identity('gemma4:latest', B))];
  const recorded = compareRuns(...swapped);
  const edited = { ...recorded, modelAttribution: { ...recorded.modelAttribution, flipCause: 'app', repairCreditedToApp: true } };
  assert.equal(summarizeGate({ baseline: swapped[0], candidate: swapped[1], comparison: edited }).exitCode, 2);
  const { modelAttribution: removed, ...stripped } = recorded;
  assert.equal(removed.state, 'recorded'); assert.equal(summarizeGate({ baseline: swapped[0], candidate: swapped[1], comparison: stripped }).exitCode, 2);
  // Saved before this change: no modelAttribution, and the fresh comparison reads not-recorded.
  const { modelAttribution: _note, ...preAttribution } = compareRuns(leaky, secure);
  assert.deepEqual(summarizeGate({ baseline: leaky, candidate: secure, comparison: preAttribution }), summarizeGate({ baseline: leaky, candidate: secure }));
  assert.equal(summarizeGate({ baseline: leaky, candidate: secure, comparison: { ...preAttribution, modelAttribution: null } }).exitCode, 2);
});

test('a malformed model identity is reported, never trusted and never throws', async t => {
  const { leaky, secure } = await responseOnlyRuns(t);
  const good = identity('gemma4:latest', A);
  const malformed = [
    { ...good, models: [] }, { ...good, models: [null] }, { ...good, models: ['gemma4:latest'] }, { ...good, models: [[]] },
    { ...good, models: [{ ...good.models[0], served: 7 }] }, { ...good, state: 'unknown' }, { ...good, models: 'gemma4:latest' }, 'observed', [good],
    // "observed" names exactly one model; two where only the second changed is not the same model.
    { ...good, models: [good.models[0], { ...good.models[0], served: 'other', weightsDigest: B }] },
    { ...good, state: 'mixed', models: [good.models[0]] },
  ];
  for (const bad of malformed) for (const pair of [[withModel(leaky, bad), withModel(secure, good)], [withModel(leaky, good), withModel(secure, bad)]]) {
    let c; assert.doesNotThrow(() => { c = compareRuns(...pair); }, JSON.stringify(bad));
    assert.equal(c.modelAttribution.state, 'not-recorded', JSON.stringify(bad)); assert.equal(c.modelAttribution.malformed.length, 1);
    // An identity that cannot be read never reads as "no identity": the repair label is withheld (review W6FU-UI-1).
    assert.equal(c.restorationLabel, 'Not attributable to the application: a model identity was present but could not be read');
    assert.equal(c.modelAttribution.coreRestorationLabel, compareRuns(leaky, secure).restorationLabel);
    assert.notEqual(summarizeGate({ baseline: pair[0], candidate: pair[1] }).exitCode, 2, JSON.stringify(bad));
  }
  // The attribution module refuses the same shapes on its own, whoever calls it.
  for (const bad of [{ ...good, models: [null] }, { ...good, models: [good.models[0], { ...good.models[0], served: 'other', weightsDigest: B }] }]) {
    const cmp = compareModelIdentities(bad, identity('gemma4:latest', A));
    assert.equal(cmp.relation, 'unverifiable'); assert.ok(cmp.reasons.includes('baseline-identity-malformed'));
  }
  // A recorded comparison carries the attribution's scope sentence.
  const scope = compareRuns(withModel(leaky, good), withModel(secure, identity('gemma4:latest', A))).modelAttribution.scope;
  assert.match(scope, /vendor model string or fingerprint is the vendor's reading/);
});

test('conversation repairs are not attributed until conversation runs carry a build identity outside the compatibility keys', async t => {
  const call = (origin, method, path, { body, headers = {} } = {}) => new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = request(`${origin}${path}`, { method, agent: false, headers: { ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}), ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
    });
    req.on('error', reject); req.end(payload);
  });
  const app = await createStorefront({ asyncDelayMs: 20 }); t.after(() => app.close());
  const login = async key => /sf_session=([^;]+)/.exec((await call(app.origin, 'POST', '/api/login', { body: { email: `${key}@storefront.example`, password: app.secrets.customers[key].password } })).headers['set-cookie'][0])[1];
  const env = { SCOPEHAVEN_TARGET_SF_ALICE: await login('alice'), SCOPEHAVEN_TARGET_SF_BOB: await login('bob'), SCOPEHAVEN_TARGET_SF_ADMIN: app.secrets.adminToken,
    SCOPEHAVEN_TARGET_SF_ALICE_CANARY: app.secrets.customers.alice.canary, SCOPEHAVEN_TARGET_SF_BOB_CANARY: app.secrets.customers.bob.canary };
  const spec = { ...JSON.parse(await readFile(new URL('../integrations/conversations/profiles/storefront.json', import.meta.url), 'utf8')), origin: app.origin,
    applicationId: 'storefront-practice-1', build: 'storefront-practice/1 deterministic assistant', contextId: 'storefront-synthetic-v1' };
  const drill = (name, enabled) => call(app.origin, 'POST', '/admin/drill', { body: { name, enabled }, headers: { 'X-Admin-Token': app.secrets.adminToken } });
  const run = async () => conversationRunFromReport(spec, await runConversations(spec, { env }));
  await drill('crossCustomer', true); const drilled = await run(); await drill('crossCustomer', false); const restored = await run();
  assert.equal(restored.evidenceOrigin, 'local-conversation');
  const core = compareRuns(drilled, restored);
  assert.ok(core.compatible && core.summary.fixed > 0);
  const c = compareRuns(withModel(drilled, identity('qwen3.5:9b', A)), withModel(restored, identity('gemma4:latest', B)));
  assert.equal(Object.hasOwn(c, 'modelAttribution'), false); assert.deepEqual(c, core);
});

// Follow-ups after an earlier review (review, pooled for model-change).
test('a model entry with unreadable fingerprints or weights digest is malformed, not attributed', async t => {
  const { leaky, secure } = await responseOnlyRuns(t);
  const good = identity('gemma4:latest', A), entry = good.models[0];
  const bad = [{ length: 1 }, ['fp', 7], 'fp_1', null].map(fingerprints => ({ ...good, models: [{ ...entry, fingerprints }] }))
    .concat([{}, 7, ['a'], true].map(weightsDigest => ({ ...good, models: [{ ...entry, weightsDigest }] })));
  for (const id of bad) {
    const c = compareRuns(withModel(leaky, id), withModel(secure, good));
    assert.deepEqual(c.modelAttribution.malformed, ['baseline'], JSON.stringify(id));
    const gate = summarizeGate({ baseline: withModel(leaky, id), candidate: withModel(secure, good) });
    assert.equal(gate.exitCode, 1); assert.deepEqual(gate.reasons, ['model-identity-malformed']);
    assert.deepEqual(gate.comparison.modelAttribution, { state: 'not-recorded', malformed: ['baseline'] });
  }
  // Fields the tap always writes but another writer may leave out read as "none reported".
  const { fingerprints: _f, weightsDigest: _w, ...bare } = entry;
  const sparseId = () => { const id = identity('gemma4:latest', A); id.models = [bare]; return id; };
  const sparse = compareRuns(withModel(leaky, sparseId()), withModel(secure, sparseId()));
  assert.equal(sparse.modelAttribution.state, 'recorded'); assert.equal(sparse.modelAttribution.strength, 'vendor-model-string');
});

test('an attribution that throws reads not-recorded with the failure named, and fails the gate', async t => {
  const { leaky, secure } = await responseOnlyRuns(t);
  // A models list the shape check accepts but that attribution cannot iterate.
  const hostile = identity('gemma4:latest', A); hostile.models[Symbol.iterator] = () => { throw new Error('not iterable'); };
  const c = compareRuns(withModel(leaky, hostile), withModel(secure, identity('gemma4:latest', A)));
  assert.deepEqual(c.modelAttribution, { state: 'not-recorded', note: c.modelAttribution.note, malformed: ['attribution-failed'], coreRestorationLabel: compareRuns(leaky, secure).restorationLabel });
  assert.match(c.restorationLabel, /^Not attributable to the application: a model identity was present but could not be read/);
  const gate = summarizeGate({ baseline: withModel(leaky, hostile), candidate: withModel(secure, identity('gemma4:latest', A)) });
  assert.deepEqual([gate.exitCode, gate.reasons], [1, ['model-identity-malformed']]);
  assert.deepEqual(gate.comparison.modelAttribution.malformed, ['attribution-failed']);
});

test('a null identity is absent, and a served-null pair is recorded but never credits the app (R04, N09)', async t => {
  const { leaky, secure, secureNewLabel } = await responseOnlyRuns(t);
  for (const pair of [[withModel(leaky, null), withModel(secure, identity('gemma4:latest', A))], [withModel(leaky, identity('gemma4:latest', A)), withModel(secure, null)]]) {
    const c = compareRuns(...pair);
    assert.equal(c.modelAttribution.state, 'not-recorded'); assert.equal(Object.hasOwn(c.modelAttribution, 'malformed'), false);
    assert.deepEqual(summarizeGate({ baseline: pair[0], candidate: pair[1] }).reasons, []);
  }
  // The tap observed calls whose replies named no model: comparable shape, unverifiable identity.
  const servedNull = () => { const id = identity(null, null); id.strength = 'requested-only'; id.models[0].strength = 'requested-only'; return id; };
  const c = compareRuns(withModel(leaky, servedNull()), withModel(secureNewLabel, servedNull()));
  assert.equal(c.modelAttribution.state, 'recorded'); assert.equal(c.modelAttribution.relation, 'unverifiable');
  assert.ok(c.modelAttribution.modelReasons.includes('baseline-served-model-not-reported'));
  assert.equal(c.modelAttribution.flipCause, 'model-unverified'); assert.equal(c.modelAttribution.repairCreditedToApp, false);
  assert.match(c.restorationLabel, /^Not attributable to the application: the model was not observed comparably/);
  const gate = summarizeGate({ baseline: withModel(leaky, servedNull()), candidate: withModel(secureNewLabel, servedNull()) });
  assert.deepEqual([gate.exitCode, gate.reasons], [1, ['repair-not-attributable']]);
});

test('an incompatible pair credits nobody (L4)', async t => {
  const { leaky, secure } = await responseOnlyRuns(t);
  const c = compareRuns(withModel(leaky, identity('gemma4:latest', A)), withModel({ ...secure, suiteHash: 'f'.repeat(64) }, identity('gemma4:latest', A)));
  assert.equal(c.compatible, false); assert.equal(c.modelAttribution.flipCause, null);
  assert.ok(c.rows.every(row => row.attribution === 'incompatible'));
});

test('--require-model-identity fails a model-served comparison without identity, and only that', async t => {
  assert.equal(parseArgs(['--target', 'demo-repaired', '--out', '/abs/out', '--baseline', 'b1', '--require-model-identity']).requireModelIdentity, true);
  // Without a baseline the switch decides nothing, so the gate refuses it, as the Action does.
  assert.throws(() => parseArgs(['--target', 'demo-repaired', '--out', '/abs/out', '--require-model-identity']), /invalid-options/);
  assert.equal(Object.hasOwn(parseArgs(['--target', 'demo-repaired', '--out', '/abs/out']), 'requireModelIdentity'), false);
  for (const bad of [['--target', 'x', '--out', '/abs', '--require-model-identity', '--require-model-identity'], ['--target', 'x', '--out', '/abs', '--require-model-identity', 'yes'], ['--target', 'x', '--require-model-identity', '--out', '/abs', '--baseline']])
    assert.throws(() => parseArgs(bad), /invalid-options/, JSON.stringify(bad));
  const { leaky, secure, secureNewLabel } = await responseOnlyRuns(t);
  const required = { requireModelIdentity: true };
  assert.deepEqual(summarizeGate({ baseline: leaky, candidate: secure, ...required }).reasons, ['model-identity-not-recorded']);
  assert.deepEqual(summarizeGate({ baseline: withModel(leaky, identity('gemma4:latest', A)), candidate: secure, ...required }).reasons, ['model-identity-not-recorded']);
  // The switch counts only an identity held in Scopehaven's custody (tap-memory).
  const held = id => ({ ...id, custody: 'tap-memory' });
  const credited = summarizeGate({ baseline: withModel(leaky, held(identity('gemma4:latest', A))), candidate: withModel(secureNewLabel, held(identity('gemma4:latest', A))), ...required });
  assert.deepEqual([credited.exitCode, credited.reasons], [0, []]);
  for (const custody of [undefined, 'tap-file']) {
    const unheld = id => custody === undefined ? id : { ...id, custody };
    const read = summarizeGate({ baseline: withModel(leaky, unheld(identity('gemma4:latest', A))), candidate: withModel(secureNewLabel, held(identity('gemma4:latest', A))), ...required });
    // A tap-file reading never credits a repair, so that pair also fails repair-not-attributable.
    assert.deepEqual([read.exitCode, read.reasons], [1, custody === undefined ? ['model-identity-unverified'] : ['repair-not-attributable', 'model-identity-unverified']], String(custody));
    assert.deepEqual(read.comparison.modelIdentityPolicy.causes, [{ side: 'baseline', reason: custody === undefined ? 'custody-not-recorded' : 'subject-writable-custody' }]);
    // The policy is not met, so the summary credits no repair and withholds a repair label that could stand.
    assert.equal(read.comparison.modelAttribution.repairCreditedToApp, false, String(custody));
    assert.equal(read.comparison.modelAttribution.policy, 'not-met', String(custody));
    if (read.comparison.compatibility === 'compatible' && read.comparison.allowedControlsPass) assert.equal(read.comparison.restorationLabel, 'Not attributable to the application: the model identity policy was not met', String(custody));
  }
  // The Action report recomputes the same: its diff credits no restored row when the policy is not met.
  {
    const baselineRun = withModel(leaky, identity('gemma4:latest', A)), candidateRun = withModel(secureNewLabel, held(identity('gemma4:latest', A)));
    const strictGate = summarizeGate({ baseline: baselineRun, candidate: candidateRun, ...required });
    const report = buildReport({ baselineInput: baselineRun, baselineState: 'ok', runInput: candidateRun, gateInput: strictGate, gateState: 'ok', requireModelIdentity: 'true' });
    assert.deepEqual([report.decision, report.reason], ['fail', 'model-identity-unverified']);
    assert.match(report.markdown, /Model identity policy not met: no change below is credited to the application\./);
    assert.match(report.markdown, /repairs credited to the application: \*\*no\*\*\./);
    assert.match(report.markdown, /\*\*Restored \(not credited to the application\)\*\*/);
    const plain = buildReport({ baselineInput: baselineRun, baselineState: 'ok', runInput: candidateRun, gateInput: summarizeGate({ baseline: baselineRun, candidate: candidateRun }), gateState: 'ok' });
    assert.match(plain.markdown, /repairs credited to the application: \*\*yes\*\*\./);
  }
  // Without the switch the custody-less pair is still credited; with it, the same pair is not (L-2 is the policy's doing).
  const loose = summarizeGate({ baseline: withModel(leaky, identity('gemma4:latest', A)), candidate: withModel(secureNewLabel, held(identity('gemma4:latest', A))) });
  assert.equal(loose.comparison.modelAttribution.repairCreditedToApp, true);
  assert.equal(Object.hasOwn(loose.comparison.modelAttribution, 'policy'), false);
  // Strict and not recorded: the not-recorded attribution is marked too.
  const unrecorded = summarizeGate({ baseline: leaky, candidate: secure, ...required });
  assert.equal(unrecorded.comparison.modelAttribution.policy, 'not-met');
  // No baseline means no repair claim; a subject no model serves has no identity to require.
  assert.deepEqual(summarizeGate({ candidate: secure, ...required }).reasons, []);
  const [vulnerable, repaired] = [await runAssessment('demo-vulnerable'), await runAssessment('demo-repaired')];
  assert.deepEqual(summarizeGate({ baseline: vulnerable, candidate: repaired, ...required }), summarizeGate({ baseline: vulnerable, candidate: repaired }));
  // Only an exact true enables it.
  assert.deepEqual(summarizeGate({ baseline: leaky, candidate: secure, requireModelIdentity: 'yes' }).reasons, []);
});

test('attribution is never applied twice (L3)', async t => {
  const { leaky, secure } = await responseOnlyRuns(t);
  const attributed = compareRuns(withModel(leaky, identity('qwen3.5:9b', A)), withModel(secure, identity('gemma4:latest', B)));
  assert.throws(() => attributeComparison(attributed, { baselineIdentity: identity('gemma4:latest', A), candidateIdentity: identity('gemma4:latest', A), app: appChangedBetween(leaky, secure) }), /already attributed/);
  // A not-recorded comparison carries the core label and can be attributed.
  const once = attributeComparison(compareRuns(leaky, secure), { baselineIdentity: identity('gemma4:latest', A), candidateIdentity: identity('gemma4:latest', A), app: appChangedBetween(leaky, secure) });
  assert.equal(once.coreRestorationLabel, 'Response contracts restored');
});

test('exports and the Action show attribution per row and the not-recorded note (L2)', async t => {
  const { leaky, secure } = await responseOnlyRuns(t);
  const swapped = [withModel(leaky, identity('qwen3.5:9b', A)), withModel(secure, identity('gemma4:latest', B))];
  const recorded = compareRuns(...swapped);
  const doc = comparisonDocument(...swapped, recorded);
  assert.deepEqual(doc.comparison.modelAttribution, recorded.modelAttribution); assert.notEqual(doc.comparison.modelAttribution, recorded.modelAttribution);
  assert.ok(doc.comparison.rows.some(row => row.attribution === 'confounded'));
  const html = renderComparisonReport(doc);
  assert.match(html, /<h2>Model attribution<\/h2><p>Verdict changes are attributed to: Model and application may both have changed\./);
  assert.match(html, /<th>Attribution<\/th>/); assert.match(html, /contract-restored \(not credited to the application\)<\/td><td>Model and application may both have changed<\/td>/);
  const plainDoc = comparisonDocument(leaky, secure, compareRuns(leaky, secure)), plain = renderComparisonReport(plainDoc);
  assert.equal(plainDoc.comparison.modelAttribution.state, 'not-recorded');
  assert.match(plain, /Model identity was not recorded for one or both runs/); assert.doesNotMatch(plain, /<th>Attribution<\/th>/);
  const [vulnerable, repaired] = [await runAssessment('demo-vulnerable'), await runAssessment('demo-repaired')];
  const synthetic = comparisonDocument(vulnerable, repaired, compareRuns(vulnerable, repaired));
  assert.equal(Object.hasOwn(synthetic.comparison, 'modelAttribution'), false); assert.doesNotMatch(renderComparisonReport(synthetic), /Model attribution/);
  // Action: the permission diff carries each restored row's attribution, and the gate projection keeps fixed codes only.
  const diff = permissionDiff(...swapped);
  assert.deepEqual(diff.modelAttribution, { state: 'recorded', flipCause: 'confounded', repairCreditedToApp: false });
  assert.ok(diff.restored.length > 0 && diff.restored.every(row => row.attribution === 'confounded'));
  assert.deepEqual(permissionDiff(leaky, secure).modelAttribution, { state: 'not-recorded' });
  const gate = normalizeGate(summarizeGate({ baseline: swapped[0], candidate: swapped[1] }));
  assert.deepEqual(gate.comparison.modelAttribution, { state: 'recorded', flipCause: 'confounded', relation: 'different', strength: 'weights-digest', repairCreditedToApp: false });
  assert.deepEqual(normalizeGate({ outcome: 'assessment-failed', exitCode: 1, reasons: [], comparison: { requested: true, modelAttribution: { state: 'recorded', flipCause: 'free text', relation: 'x y', strength: 1 } } }).comparison.modelAttribution,
    { state: 'recorded', flipCause: 'unrecognized', relation: 'unrecognized', strength: 'unrecognized', repairCreditedToApp: false });
  assert.ok(SOFT_GATE_REASONS.includes('model-identity-malformed') && !SOFT_GATE_REASONS.includes('repair-not-attributable'));
});

// Review W6FU-UI-1: an identity that cannot be read must not let a model swap read as a verified repair anywhere.
test('an unreadable identity on a model swap is never shown as a verified repair', async t => {
  const { leaky, secure } = await responseOnlyRuns(t);
  const bad = identity('qwen3.5:9b', A); bad.models[0].fingerprints = ['fp_1', 7];
  const pair = [withModel(leaky, bad), withModel(secure, identity('gemma4:latest', B))];
  const c = compareRuns(...pair);
  assert.ok(c.summary.fixed > 0); assert.deepEqual(c.modelAttribution.malformed, ['baseline']);
  assert.doesNotMatch(c.restorationLabel, /restored/i);
  const html = renderComparisonReport(comparisonDocument(...pair, c));
  assert.doesNotMatch(html, /Response contracts restored/); assert.match(html, /contract-restored \(not credited to the application\)<\/td>/);
  assert.match(html, /A model identity was present but could not be read \(baseline\)/);
  // Action: the gate's transition table marks the repair as not credited.
  const gateSummary = summarizeGate({ baseline: pair[0], candidate: pair[1] });
  assert.deepEqual(normalizeGate(gateSummary).comparison.modelAttribution, { state: 'not-recorded', malformed: ['baseline'] });
  const report = buildReport({ runInput: pair[1], gateInput: gateSummary, gateState: 'ok', baselineInput: pair[0], baselineState: 'ok', env: {} });
  const { markdown } = report;
  assert.match(markdown, /\| contract-restored \(not credited to the application\) \| \d+ \|/);
  assert.match(markdown, /identity present but unreadable: `baseline`/);
});

// An earlier review (w6-followups-r2): every "credited" mark is pinned, the Action's permission diff
// carries an unreadable identity, the override keeps incompatible labels, and the switch takes a boolean.
test('the credited marks hold only for a credited repair (M2), and the Action diff marks an uncredited Restored (M1)', async t => {
  const { leaky, secure, secureNewLabel } = await responseOnlyRuns(t);
  const unreadable = identity('qwen3.5:9b', A); unreadable.models[0].weightsDigest = {};
  const cases = {
    credited: [withModel(leaky, identity('gemma4:latest', A)), withModel(secureNewLabel, identity('gemma4:latest', A))],
    swap: [withModel(leaky, identity('qwen3.5:9b', A)), withModel(secure, identity('gemma4:latest', B))],
    unreadable: [withModel(leaky, unreadable), withModel(secure, identity('gemma4:latest', B))],
  };
  for (const [name, pair] of Object.entries(cases)) {
    const credited = name === 'credited';
    const html = renderComparisonReport(comparisonDocument(...pair, compareRuns(...pair)));
    if (credited) assert.match(html, /The repairs are credited to the application\./); else assert.doesNotMatch(html, /repairs are credited/, name);
    const { markdown } = buildReport({ runInput: pair[1], gateInput: summarizeGate({ baseline: pair[0], candidate: pair[1] }), gateState: 'ok', baselineInput: pair[0], baselineState: 'ok', env: {} });
    if (name !== 'unreadable') assert.ok(markdown.includes(`repairs credited to the application: **${credited ? 'yes' : 'no'}**`), name);
    if (credited) { assert.match(markdown, /\*\*Restored\*\* \(\d+\)/); assert.doesNotMatch(markdown, /not credited/); }
    else assert.match(markdown, /\*\*Restored \(not credited to the application\)\*\* \(\d+\)/, name);
  }
  const diff = permissionDiff(...cases.unreadable);
  assert.deepEqual(diff.modelAttribution, { state: 'not-recorded', malformed: ['baseline'] });
  const { markdown } = buildReport({ runInput: cases.unreadable[1], baselineInput: cases.unreadable[0], baselineState: 'ok', env: {} });
  assert.match(markdown, /Model identity present but unreadable \(`baseline`\): no change below is credited to the application\./);
});

test('an unreadable identity withholds the repair label only where one could stand (L1)', async t => {
  const { leaky, secure } = await responseOnlyRuns(t);
  const unreadable = identity('qwen3.5:9b', A); unreadable.models[0].fingerprints = [7];
  const incompatible = compareRuns(withModel(leaky, unreadable), withModel({ ...secure, suiteHash: 'f'.repeat(64) }, identity('gemma4:latest', B)));
  assert.equal(incompatible.compatible, false); assert.equal(incompatible.restorationLabel, 'Unverified changes');
  assert.deepEqual(incompatible.modelAttribution.malformed, ['baseline']);
  const compatible = compareRuns(withModel(leaky, unreadable), withModel(secure, identity('gemma4:latest', B)));
  assert.match(compatible.restorationLabel, /^Not attributable to the application: a model identity was present but could not be read/);
});

test('requireModelIdentity accepts a boolean, false included (L3)', async t => {
  const out = await mkdtemp(join(tmpdir(), 'w6 gate options ')); t.after(() => rm(out, { recursive: true, force: true }));
  for (const value of [false, true]) assert.deepEqual((await runGate({ targetId: 'no-such-target', outputDirectory: join(out, `g-${value}`), requireModelIdentity: value, ...(value ? { baselineRunId: 'b1' } : {}) })).reasons, ['unknown-target'], String(value));
  assert.deepEqual((await runGate({ targetId: 'no-such-target', outputDirectory: join(out, 'g-no-baseline'), requireModelIdentity: true })).reasons, ['invalid-options']);
  assert.deepEqual((await runGate({ targetId: 'no-such-target', outputDirectory: join(out, 'g-x'), requireModelIdentity: 'yes' })).reasons, ['invalid-options']);
});
