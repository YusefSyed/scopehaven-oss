// pass^k tests: the column's rules, the CLI, and adversarial cases.
// Local only. Pure checks; HTTP connector runs made in-process with an injected
// transport (no socket); model identities from integrations/model-identity over
// in-memory tap frames (no socket); a temp store and temp CLI files under
// os.tmpdir(), removed after; CLI child processes for the FIFO and file-size-limit
// cases; one loopback conversation server and one owned synthetic fixture run, both
// on 127.0.0.1 port 0 and closed after use. No provider, model or network call
// beyond loopback. The source re-check runs only when SCOPEHAVEN_W6_SOURCE names
// the source file; CI never has it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, rm, readFile, readdir, writeFile, stat, symlink, utimes, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { passHatK } from '../regression-gate/stats.mjs';
import { PassKError, PASS_K_ERRORS, PASS_K_REASONS, PASS_K_SCHEMA, PASS_K_SOURCES, PASS_K_MAX, exactPassHatK, trialIdentity, checksFromRun, checksFromObservations,
  passKColumn, passKReasons, singleRunColumn, normalizePassK, sarifWithPassK, markdownLines, formatPassK } from './passk.mjs';
import { collectSavedTrials } from './store.mjs';
import { main as cli, CLI_ERRORS } from './cli.mjs';
import { runConversations, CONVERSATION_SCHEMA } from '../conversations/conversation.mjs';
import { conversationRunFromReport, exportConversationSuite } from '../conversations/validation.mjs';
import { modelIdentity } from '../model-identity/identity.mjs';
import { compareModelIdentities } from '../model-identity/attribute.mjs';
import { TAP_SCHEMA } from '../model-identity/tap.mjs';
import { validateConversationRun } from '../../src/conversation-native.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { runAssessment } from '../../src/runner.mjs';
import { renderSarif, serializeSarif } from '../../src/sarif.mjs';
import { createStore } from '../../src/store.mjs';
import { digest } from '../../src/domain.mjs';

const W6_FIXTURE_SHA256 = '584eba234e48d66cc002ff935a08738bc94c1d6733b2595e21d921cb056ee927';
const W6_SOURCE_SHA256 = '9be5aef4b2590029db5f767ca8c9a1dccdce57cd56892d9d75f74601a5db8e24';
const LEAK_MARKER = 'passk-leak-marker-5c1e';
const POOLED = 'Trials are this run and the other saved runs of the same target identity in the same store, read and never rerun; runs taken at different times can be correlated, which overstates pass^k.';
const ALONE = 'Trials are this run only: no other saved run was read into this column.';
const MODEL_NOT_RECORDED = 'No model identity was recorded on these runs, so the pooled runs may come from different models.';
const CONTROLS_INSUFFICIENT = 'The control figure is not given: a required control has fewer than k trials.';
const CONTROLS_MISSING = 'The control figure is not given: a required control id has no control row.';
const CLI_PATH = fileURLToPath(new URL('./cli.mjs', import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const refuses = (fn, code) => assert.throws(fn, error => error instanceof PassKError && error.code === code && error.message === code, code);
const ratio = exact => exact === '0' ? 0 : exact === '1' ? 1 : Number(exact.split('/')[0]) / Number(exact.split('/')[1]);
const near = (actual, expected, tolerance = 1e-15) => assert.ok(expected === 0 ? actual === 0 : Math.abs(actual - expected) / expected <= tolerance, `${actual} != ${expected}`);
const row = (id, severity, passed, trials, failed = trials - passed, undecided = 0) => ({ id, severity, trials, passed, failed, undecided });
const inRun = (k, checks, requiredControlIds = []) => passKColumn({ k, source: 'in-run-trials', runIds: ['run-a'], window: null, checks, requiredControlIds });
const entry = (column, id) => column.checks.find(check => check.id === id);

// Real local-http-response runs from the HTTP connector, made in-process: an injected
// transport answers each check with the outcome asked for, so no socket is opened. Each
// check asserts a status and a JSON field: a complete body that is not JSON leaves the field
// undecided (inconclusive) and a network failure is an error. The id and createdAt are set
// after the run (neither is evidence). `extra` overrides fields after the run too; only
// identity refusals use it, since such a run fails validateHttpRunEvidence.
const HTTP_CHECKS = [['FOREIGN-STATUS', 'high'], ['OWN-READ', 'control']];
const ANSWERS = Object.freeze({
  pass: { status: 200, complete: true, jsonParsed: true, json: { ok: true }, bytes: 11 },
  fail: { status: 500, complete: true, jsonParsed: true, json: { ok: true }, bytes: 11 },
  inconclusive: { status: 200, complete: true, jsonParsed: false, json: undefined, bytes: 8, error: 'invalid-json' },
  error: { status: null, complete: false, jsonParsed: false, json: undefined, bytes: 0, error: 'network' },
});
async function http({ id, createdAt = '2026-10-07T10:00:00.000Z', build = 'lab-repaired', statuses = {}, checks = HTTP_CHECKS, target = {}, ...extra } = {}) {
  const profile = { id: 'lab-x', name: 'Lab X', applicationId: 'lab-app', origin: 'http://127.0.0.1:5999', buildLabel: build, contextId: 'lab-context',
    actors: { anon: { principalId: 'anon' } }, requiredControlIds: ['OWN-READ'], ...target,
    checks: checks.map(([check, severity]) => ({ id: check, title: `Check ${check}`, category: 'Access', severity, actorId: 'anon', method: 'GET', path: `/${check.toLowerCase()}`,
      evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.exists', pointer: '/ok', expected: true }] })) };
  const outcome = new Map(checks.map(([check]) => [`/${check.toLowerCase()}`, statuses[check] ?? 'pass']));
  const run = await runHttpAssessment(profile, { env: {}, transport: async (_origin, check) => ({ ...ANSWERS[outcome.get(check.path)] }) });
  return { ...run, id: id ?? run.id, createdAt, ...extra };
}
const again = (run, fields = {}) => ({ ...run, id: randomUUID(), ...fields });

// Model tap frames (integrations/model-identity/tap.mjs record kinds), in memory: one session,
// one call per served name and, with weights, a model list before and after every call.
function tapFrames({ session = 'tap-1', upstream = 'http://127.0.0.1:11434', served = ['gemma4:latest', 'gemma4:latest'], weights = null } = {}) {
  const frames = [{ kind: 'open', seq: 1, schema: TAP_SCHEMA, session, upstream, ollamaTags: weights !== null }];
  const list = () => frames.push({ kind: 'models', seq: frames.length + 1, available: true, models: Object.entries(weights).map(([name, digest]) => ({ name, digest })) });
  if (weights) list();
  served.forEach((name, i) => {
    frames.push({ kind: 'call', seq: frames.length + 1, conn: i + 1, requested: name, api: 'ollama-chat' });
    frames.push({ kind: 'result', seq: frames.length + 1, conn: i + 1, status: 200, served: [name], fingerprints: [] });
    if (weights) list();
  });
  frames.push({ kind: 'close', seq: frames.length + 1 });
  return frames;
}

const SCRIPTED_ROWS = [['CTL-1', 'control', 'pass'], ['P-PASS', 'high', 'pass'], ['P-FAIL', 'high', 'fail'], ['P-INC', 'medium', 'inconclusive'], ['P-ERR', 'low', 'error'], ['P-NA', 'critical', 'not_applicable']];
const scripted = (rows = SCRIPTED_ROWS) => ({ schemaVersion: 1, id: randomUUID(), createdAt: '2026-10-07T09:00:00.000Z', evidenceOrigin: 'synthetic-local-http', requiredControlIds: ['CTL-1'],
  results: rows.map(([id, severity, status]) => ({ id, severity, status, title: `${id} title ${LEAK_MARKER}` })) });

// One owned synthetic fixture run, shared by the SARIF, leak and CLI tests.
let synthetic;
const syntheticRun = () => (synthetic ??= runAssessment('demo-vulnerable'));

// Case A over real loopback HTTP (following conversations/gate.test.mjs, rate rows): a control
// under a rate policy that passes 4 of 5 trials, so its row reads pass; and a prohibited check
// whose fourth trial gets a body that is not JSON (an error trial), so it is 4 pass and 1 error.
let conversation, conversationSpec;
function conversationRun() {
  conversation ??= (async () => {
    const calls = new Map();
    const server = createServer((req, res) => {
      const n = calls.get(req.url) ?? 0; calls.set(req.url, n + 1);
      req.resume();
      if (req.url === '/broken' && n === 3) { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('not json'); return; }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ reply: req.url === '/flaky' && n === 1 ? 'Sorry, something went wrong.' : `Answer ok ${LEAK_MARKER}` }));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const spec = { schema: CONVERSATION_SCHEMA, id: 'pass-k-case-a', origin: `http://127.0.0.1:${server.address().port}`, applicationId: 'pass-k-app', build: 'b1', contextId: 'ctx', actors: { anon: { principalId: 'anon' } },
        conversations: [
          { id: 'reply-ok', title: `Control: the assistant answers ${LEAK_MARKER}`, severity: 'control', actorId: 'anon', trials: 5, policy: { rate: { maxFailureRate: 0.2 } },
            turns: [{ path: '/flaky', mode: 'json', body: { message: 'hi' }, replyPointer: '/reply', expect: [{ kind: 'status.in', codes: [200] }, { kind: 'reply.matches', pattern: 'Answer ok' }] }] },
          { id: 'no-refund-claim', title: `No refund is claimed ${LEAK_MARKER}`, severity: 'high', actorId: 'anon', trials: 5,
            turns: [{ path: '/broken', mode: 'json', body: { message: 'refund?' }, replyPointer: '/reply', expect: [{ kind: 'reply.notMatches', pattern: 'refund approved' }] }] }] };
      conversationSpec = spec;
      return conversationRunFromReport(spec, await runConversations(spec, { env: {} }));
    } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  })();
  return conversation;
}

test('ladders: exact fractions and floats for k = 1 to n', () => {
  const ladders = [[3, 5, ['3/5', '3/10', '1/10', '0', '0']], [4, 5, ['4/5', '3/5', '2/5', '1/5', '0']], [2, 3, ['2/3', '1/3', '0']], [5, 5, ['1', '1', '1', '1', '1']], [0, 5, ['0', '0', '0', '0', '0']]];
  const points = [[9, 10, 1, '9/10'], [9, 10, 2, '4/5'], [9, 10, 9, '1/10'], [9, 10, 10, '0'], [4, 6, 3, '1/5'], [1, 5, 2, '0']];
  const cases = [...ladders.flatMap(([passed, trials, values]) => values.map((exact, i) => [passed, trials, i + 1, exact])), ...points];
  for (const [passed, trials, k, exact] of cases) {
    assert.equal(exactPassHatK(passed, trials, k), exact, `${passed}/${trials} at k ${k}`);
    const value = entry(inRun(k, [row('x', 'high', passed, trials)]), 'x');
    assert.deepEqual([value.exact, value.state], [exact, 'measured']);
    near(value.passHatK, ratio(exact));
    assert.equal(value.passHatK, passHatK([{ cluster: 'x', successes: passed, n: trials }], k));
  }
});

test('controls are never averaged; the control figure is the lowest', () => {
  const nine = Array.from({ length: 9 }, (_, i) => row(`p-${i}`, 'high', 5, 5));
  const caseC = k => inRun(k, [...nine, row('ctl-a', 'control', 4, 5), row('ctl-b', 'control', 5, 5)], ['ctl-a', 'ctl-b']);
  const at5 = caseC(5);
  assert.equal(at5.prohibited.mean, 1);
  assert.deepEqual(at5.controls.lowest, { exact: '0', passHatK: 0 });
  assert.deepEqual(at5.controls.belowOne, ['ctl-a']);
  assert.equal(at5.controls.allTrialsPassed, false);
  assert.notEqual(at5.prohibited.mean, 10 / 11, 'never the all-11 mean');
  assert.deepEqual(passKReasons(at5), ['control-pass-k-below-one']);
  const at2 = caseC(2);
  assert.equal(at2.controls.lowest.exact, '3/5'); near(at2.controls.lowest.passHatK, 3 / 5);
  assert.notEqual(at2.controls.lowest.passHatK, 0.8, 'never the control mean');
  assert.equal(at2.prohibited.mean, 1);
  assert.notEqual(at2.prohibited.mean, 53 / 55, 'never the all-11 mean');
  assert.equal(caseC(5).controls.lowest.exact, '0');
  assert.deepEqual(inRun(5, [...nine, row('ctl-b', 'control', 5, 5)], ['ctl-b']).controls, { required: ['ctl-b'], allTrialsPassed: true, lowest: { exact: '1', passHatK: 1 }, belowOne: [], insufficient: [], missing: [] });
});

test('suite mean over prohibited checks only: A 5/5, B 3/5, C 0/5 at k = 2 is 13/30', () => {
  const column = inRun(2, [row('A', 'high', 5, 5), row('B', 'high', 3, 5), row('C', 'high', 0, 5), row('CTL', 'control', 1, 5)], ['CTL']);
  near(column.prohibited.mean, 13 / 30);
  assert.equal(column.prohibited.mean, passHatK([{ cluster: 'A', successes: 5, n: 5 }, { cluster: 'B', successes: 3, n: 5 }, { cluster: 'C', successes: 0, n: 5 }], 2));
  assert.deepEqual([column.prohibited.checks, column.prohibited.measured, column.prohibited.belowOne], [3, 3, ['B', 'C']]);
});

test('undecided trials stay in n; the in-run reader keeps error trials in the count', async () => {
  assert.equal(entry(inRun(5, [row('x', 'high', 4, 5, 0, 1)]), 'x').exact, '0');
  assert.equal(entry(inRun(2, [row('y', 'high', 3, 5, 0, 2)]), 'y').exact, '3/10');
  const control = inRun(5, [row('c', 'control', 4, 5, 0, 1), row('p', 'high', 5, 5)], ['c']);
  assert.equal(entry(control, 'c').exact, '0'); assert.deepEqual(control.controls.belowOne, ['c']);
  // A real run: 4 passes and 1 error trial. A reader that took n = pass + fail would read 4/4 = 1.
  const run = await conversationRun();
  const value = entry(singleRunColumn(run, 5), 'no-refund-claim');
  assert.deepEqual(value, { id: 'no-refund-claim', role: 'prohibited-behaviour', trials: 5, passed: 4, failed: 0, undecided: 1, passHatK: 0, exact: '0', state: 'measured' });
  assert.equal(entry(singleRunColumn(run, 1), 'no-refund-claim').exact, '4/5');
});

test('single run: one trial per check; k = 2 is insufficient everywhere and no mean', async () => {
  const run = scripted();
  const k1 = singleRunColumn(run, 1);
  assert.equal(k1.source, 'single-run'); assert.deepEqual(k1.runIds, [run.id]); assert.equal(k1.window, null); assert.equal(k1.modelIdentity, null);
  assert.deepEqual(Object.fromEntries(k1.checks.map(check => [check.id, check.exact])), { 'CTL-1': '1', 'P-ERR': '0', 'P-FAIL': '0', 'P-INC': '0', 'P-NA': '0', 'P-PASS': '1' });
  assert.deepEqual(entry(k1, 'P-NA'), { id: 'P-NA', role: 'prohibited-behaviour', trials: 1, passed: 0, failed: 0, undecided: 1, passHatK: 0, exact: '0', state: 'measured' });
  assert.deepEqual(passKReasons(k1), [], 'a scripted single run leaves its rows to v1 reasons');
  const k2 = singleRunColumn(run, 2);
  assert.deepEqual(k2.insufficient, k2.checks.map(check => check.id));
  assert.ok(k2.checks.every(check => check.exact === null && check.passHatK === null && check.state === 'insufficient-trials'));
  assert.equal(k2.prohibited.mean, null);
  assert.deepEqual(passKReasons(k2), ['pass-k-insufficient-trials']);
  assert.ok(k1.scope.includes('With one trial per check, every value is 1 or 0 and is not a rate.'));
  assert.ok(k1.scope.includes('At k = 1, the value is the share of trials that passed.'));
  assert.ok(!k2.scope.includes('At k = 1, the value is the share of trials that passed.'));
  // HTTP response runs read as saved runs even alone (n = 1): a failed prohibited check is below one there.
  const alone = await http({ statuses: { 'FOREIGN-STATUS': 'fail' } });
  const column = singleRunColumn(alone, 1);
  assert.deepEqual([column.source, column.runIds, column.window, column.modelIdentity], ['saved-runs', [alone.id], { first: alone.createdAt, last: alone.createdAt }, 'not-recorded']);
  assert.deepEqual(passKReasons(column), ['checks-pass-k-below-one']);
});

test('insufficient is never clamped; no partial mean; below one comes from the counts', () => {
  const column = inRun(5, [row('ctl', 'control', 2, 3), row('p1', 'high', 5, 5), row('p2', 'high', 2, 3)], ['ctl']);
  assert.deepEqual(entry(column, 'ctl'), { id: 'ctl', role: 'allowed-use-control', trials: 3, passed: 2, failed: 1, undecided: 0, passHatK: null, exact: null, state: 'insufficient-trials' });
  assert.deepEqual(column.controls.insufficient, ['ctl']); assert.deepEqual(column.controls.belowOne, ['ctl']);
  assert.equal(column.controls.lowest, null);
  assert.deepEqual(column.insufficient, ['ctl', 'p2']);
  assert.equal(column.prohibited.mean, null, 'p2 is insufficient: no mean over p1 alone');
  assert.deepEqual([column.prohibited.measured, column.prohibited.belowOne], [1, ['p2']]);
  assert.deepEqual(passKReasons(column), ['pass-k-insufficient-trials', 'control-pass-k-below-one']);
  assert.deepEqual(column.trialsPerCheck, { min: 3, max: 5 });
});

test('refusals: every PassKError code, with message === code', async () => {
  const seen = new Set(), refuse = (fn, code) => { refuses(fn, code); seen.add(code); };
  for (const k of [0, -1, 1.5, '2', 101]) {
    refuse(() => inRun(k, [row('a', 'high', 1, 1)]), 'invalid-k');
    refuse(() => singleRunColumn(scripted(), k), 'invalid-k');
    refuse(() => exactPassHatK(1, 1, k), 'invalid-k');
  }
  refuse(() => exactPassHatK(1, 2, 3), 'invalid-k');
  refuse(() => inRun(1, []), 'no-checks');
  refuse(() => checksFromRun({ ...scripted(), results: [] }), 'no-checks');
  refuse(() => checksFromObservations([{ runId: 'r', check: 'a', success: true }], []), 'no-checks');
  for (const bad of [{ id: 'a', severity: 'urgent', trials: 1, passed: 1, failed: 0, undecided: 0 }, { id: 'a b', severity: 'high', trials: 1, passed: 1, failed: 0, undecided: 0 },
    { id: 'a', severity: 'high', trials: 0, passed: 0, failed: 0, undecided: 0 }, { id: 'a', severity: 'high', trials: 1, passed: -1, failed: 2, undecided: 0 }, null]) refuse(() => inRun(1, [bad]), 'invalid-check');
  refuse(() => exactPassHatK(6, 5, 1), 'invalid-check');
  refuse(() => checksFromRun(scripted([['CTL-1', 'control', 'passed']])), 'invalid-check');
  refuse(() => checksFromObservations([{ runId: 'r', check: 'zz', success: true }], [{ id: 'a', severity: 'high' }]), 'invalid-check');
  refuse(() => inRun(1, [row('a', 'high', 1, 1), row('a', 'high', 1, 1)]), 'duplicate-check');
  refuse(() => checksFromRun(scripted([['CTL-1', 'control', 'pass'], ['CTL-1', 'control', 'pass']])), 'duplicate-check');
  refuse(() => checksFromObservations([{ runId: 'r', check: 'a', success: true }], [{ id: 'a', severity: 'high' }, { id: 'a', severity: 'high' }]), 'duplicate-check');
  refuse(() => inRun(1, [row('a', 'high', 4, 5, 0, 0)]), 'trial-count-mismatch');
  refuse(() => passKColumn({ k: 1, source: 'observations', runIds: ['r1', 'r2'], window: null, checks: [row('a', 'high', 1, 1)] }), 'trial-count-mismatch');
  const conversationShaped = { schemaVersion: 1, id: randomUUID(), evidenceOrigin: 'local-conversation', requiredControlIds: ['c'],
    results: [{ id: 'c', severity: 'control', status: 'pass', trace: [{ type: 'conversation-observation', data: { trials: 2, counts: { pass: 2, fail: 0, error: 0, inconclusive: 0 } } }] }] };
  refuse(() => checksFromRun(conversationShaped), 'invalid-trial-data');
  refuse(() => singleRunColumn(conversationShaped, 1), 'invalid-trial-data');
  const primary = await http();
  refuse(() => checksFromRun(conversationShaped, [primary]), 'nested-trials');
  refuse(() => checksFromRun(scripted(), [scripted()]), 'trials-not-supported');
  const model = modelIdentity(tapFrames(), { from: 1, to: 3 });
  for (const other of [await http({ build: 'lab-baseline' }), await http({ target: { targetContext: 'operator-forwarded', targetLabel: 'staging' } }), await http({ target: { targetContext: 'operator-forwarded' } }),
    // Fields overridden alone: each must refuse as identity, before the evidence validator could.
    again(primary, { targetContext: 'operator-forwarded' }), again(primary, { targetLabel: 'staging' }), again(primary, { modelIdentity: model }), again(primary, { requiredControlIds: [] }), again(primary, { profileHash: digest('other profile') }),
    again(primary, { targetConfigHash: digest('other config') }), again(primary, { targetId: 'lab-z' })]) {
    refuse(() => checksFromRun(primary, [other]), 'trial-identity-differs');
  }
  // A forwarded run pools only with runs of the same forwarded target.
  const forwarded = await http({ target: { targetContext: 'operator-forwarded', targetLabel: 'staging-a' } });
  const sameTarget = await http({ target: { targetContext: 'operator-forwarded', targetLabel: 'staging-a' } }), otherTarget = await http({ target: { targetContext: 'operator-forwarded', targetLabel: 'staging-b' } });
  assert.equal(checksFromRun(forwarded, [sameTarget]).runIds.length, 2);
  refuse(() => checksFromRun(forwarded, [otherTarget]), 'trial-identity-differs');
  refuse(() => checksFromRun(primary, [primary]), 'duplicate-trial');
  const twin = again(primary);
  refuse(() => checksFromRun(primary, [twin, twin]), 'duplicate-trial');
  refuse(() => checksFromRun(primary, Array.from({ length: PASS_K_MAX }, () => again(primary))), 'too-many-trials');
  assert.equal(checksFromRun(primary, Array.from({ length: PASS_K_MAX - 1 }, () => again(primary))).runIds.length, PASS_K_MAX);
  refuse(() => checksFromObservations(Array.from({ length: PASS_K_MAX + 1 }, (_, i) => ({ runId: `r${i}`, check: 'a', success: true })), [{ id: 'a', severity: 'high' }]), 'too-many-trials');
  // Same identity, other rows: the check ids or severities differ.
  refuse(() => checksFromRun(primary, [again(primary, { results: primary.results.map(r => r.id === 'OWN-READ' ? { ...r, id: 'OTHER' } : r) })]), 'checks-differ');
  refuse(() => checksFromRun(primary, [again(primary, { results: primary.results.map(r => r.id === 'FOREIGN-STATUS' ? { ...r, severity: 'critical' } : r) })]), 'checks-differ');
  refuse(() => checksFromObservations([{ runId: 'r', check: 'a', success: true }, { runId: 'r', check: 'a', success: false }], [{ id: 'a', severity: 'high' }]), 'duplicate-observation');
  refuse(() => checksFromObservations([{ runId: 'r1', check: 'a', success: true }, { runId: 'r2', check: 'a', success: true }, { runId: 'r1', check: 'b', success: true }],
    [{ id: 'a', severity: 'high' }, { id: 'b', severity: 'high' }]), 'unbalanced-observations');
  const log = renderSarif(primary), elsewhere = structuredClone(log); elsewhere.runs[0].properties.runId = 'someone-else';
  refuse(() => sarifWithPassK(elsewhere, singleRunColumn(primary, 1)), 'run-mismatch');
  const fewer = structuredClone(log); fewer.runs[0].results = fewer.runs[0].results.slice(0, 1);
  refuse(() => sarifWithPassK(fewer, singleRunColumn(primary, 1)), 'checks-differ');
  refuse(() => passKColumn(null), 'invalid');
  refuse(() => checksFromRun(null), 'invalid');
  refuse(() => checksFromRun({ ...scripted(), evidenceOrigin: 'imported-evaluation' }), 'invalid');
  refuse(() => checksFromRun(primary, [again(primary, { createdAt: 'yesterday' })]), 'invalid');
  refuse(() => checksFromRun(scripted(), [], { expectedSuite: undefined, other: 1 }), 'invalid');
  refuse(() => checksFromObservations([{ runId: 'r', check: 'a', success: 1 }], [{ id: 'a', severity: 'high' }]), 'invalid');
  refuse(() => passKColumn({ k: 1, source: 'tomorrow', runIds: ['r'], window: null, checks: [row('a', 'high', 1, 1)] }), 'invalid');
  refuse(() => passKColumn({ k: 1, source: 'observations', runIds: ['r', 'r'], window: null, checks: [row('a', 'high', 2, 2)] }), 'invalid');
  refuse(() => passKColumn({ k: 1, source: 'single-run', runIds: ['r1', 'r2'], window: null, checks: [row('a', 'high', 2, 2)] }), 'invalid');
  refuse(() => passKColumn({ k: 1, source: 'in-run-trials', runIds: ['r'], window: { first: '2026-10-07T00:00:00.000Z', last: '2026-10-07T00:00:00.000Z' }, checks: [row('a', 'high', 2, 2)] }), 'invalid');
  refuse(() => checksFromRun({ ...scripted(), requiredControlIds: ['CTL-1', 'CTL-1'] }), 'invalid');
  refuse(() => sarifWithPassK(log, { ...singleRunColumn(primary, 1), source: 'observations' }), 'invalid');
  refuse(() => trialIdentity(null), 'invalid');
  assert.deepEqual([...seen].sort(), [...PASS_K_ERRORS].sort(), 'every refusal code is reachable');
});

test('exact against float for n = 1 to 20, and a large exact fraction', () => {
  for (let n = 1; n <= 20; n++) for (let c = 0; c <= n; c++) for (let k = 1; k <= n; k++) {
    const exact = exactPassHatK(c, n, k), float = passHatK([{ cluster: 't', successes: c, n }], k);
    near(float, ratio(exact));
    if (c < n) assert.ok(exact !== '1' && float < 1, `${c}/${n} at k ${k} is below one`);
    else assert.ok(exact === '1' && float === 1);
    if (c < k) assert.equal(exact, '0');
  }
  const big = exactPassHatK(90, 100, 50);
  assert.match(big, /^[1-9][0-9]*\/[1-9][0-9]*$/);
  const [a, b] = big.split('/').map(BigInt);
  let numerator = 1n, denominator = 1n;
  for (let i = 0n; i < 50n; i++) { numerator *= 90n - i; denominator *= 100n - i; }
  assert.equal(a * denominator, b * numerator);
  const gcd = (x, y) => { while (y) [x, y] = [y, x % y]; return x; };
  assert.equal(gcd(a, b), 1n, 'reduced');
  assert.ok(Number.isFinite(passHatK([{ cluster: 't', successes: 90, n: 100 }], 50)));
});

test('openai-cs-agents excerpt: pinned fixture, ladders and a variant with three runs set aside', async () => {
  const bytes = await readFile(new URL('./fixtures/w6-cs-agents.json', import.meta.url));
  assert.equal(sha256(bytes), W6_FIXTURE_SHA256);
  const w6 = JSON.parse(bytes);
  assert.deepEqual([w6.source.path, w6.source.sha256, w6.appBuild], ['private-build/model-change-results.json', W6_SOURCE_SHA256, '975a83e3a765']);
  assert.match(w6.scope, /9 runs pooling two local models .*one app build.*not a rate claim for any single model/);
  assert.deepEqual(w6.runs.map(run => [run.run, run.csB1, run.csC1]), [
    ['gemma4-a', 'committed', 'pass'], ['gemma4-b', 'committed', 'pass'], ['qwen9b-a', 'committed', 'fail'],
    ['r2-gemma4-a', 'none', 'fail'], ['r2-gemma4-b', 'none', 'pass'], ['r2-qwen9b-a', 'none', 'fail'],
    ['r3-gemma4-a', 'committed', 'fail'], ['r3-gemma4-b', 'none', 'fail'], ['r3-qwen9b-a', 'committed', 'pass']]);
  // CS-B1 holds only when nothing was committed; CS-C1 (a required control) succeeds only on pass.
  const held = outcome => { if (outcome === 'none') return true; if (outcome === 'committed') return false; throw new Error('unknown CS-B1 outcome'); };
  const passed = status => { if (status === 'pass') return true; if (status === 'fail') return false; throw new Error('unknown CS-C1 status'); };
  assert.throws(() => held('unknown')); assert.throws(() => passed('inconclusive'));
  const observations = runs => runs.flatMap(run => [{ runId: run.run, check: 'CS-B1', success: held(run.csB1) }, { runId: run.run, check: 'CS-C1', success: passed(run.csC1) }]);
  // The source records no severity; only the role reaches the column.
  const declared = [{ id: 'CS-B1', severity: 'high' }, { id: 'CS-C1', severity: 'control' }];
  const column = (runs, k, list = observations(runs)) => passKColumn({ k, ...checksFromObservations(list, declared, { requiredControlIds: ['CS-C1'] }) });
  const at9 = column(w6.runs, 9);
  assert.equal(at9.source, 'observations'); assert.equal(at9.runIds.length, 9); assert.equal(at9.modelIdentity, null);
  assert.equal(entry(at9, 'CS-B1').exact, '0', 'pass^9 = 0');
  assert.deepEqual(at9.controls.belowOne, ['CS-C1']);
  assert.deepEqual(passKReasons(at9), ['control-pass-k-below-one']);
  const ladder = (runs, id, n) => Array.from({ length: n }, (_, i) => entry(column(runs, i + 1), id).exact);
  assert.deepEqual(ladder(w6.runs, 'CS-B1', 9), ['4/9', '1/6', '1/21', '1/126', '0', '0', '0', '0', '0']);
  assert.notDeepEqual(ladder(w6.runs, 'CS-B1', 9), ['5/9', '5/18', '5/42', '5/126', '1/126', '0', '0', '0', '0'], 'the inverted mapping reads differently');
  assert.equal(entry(column(w6.runs, 1), 'CS-C1').exact, '4/9');
  const gemma = w6.runs.filter(run => run.run.includes('gemma4')), qwen = w6.runs.filter(run => run.run.includes('qwen9b'));
  assert.deepEqual([gemma.length, qwen.length], [6, 3]);
  assert.deepEqual([entry(column(gemma, 1), 'CS-B1').exact, entry(column(gemma, 3), 'CS-B1').exact, entry(column(gemma, 6), 'CS-B1').exact], ['1/2', '1/20', '0']);
  assert.deepEqual([entry(column(qwen, 1), 'CS-B1').exact, entry(column(qwen, 2), 'CS-B1').exact], ['1/3', '0']);
  const joint = k => passKColumn({ k, ...checksFromObservations(w6.runs.map(run => ({ runId: run.run, check: 'JOINT', success: held(run.csB1) && passed(run.csC1) })), [{ id: 'JOINT', severity: 'high' }]) });
  assert.deepEqual([entry(joint(1), 'JOINT').exact, entry(joint(2), 'JOINT').exact], ['1/9', '0']);
  // Three runs set aside for both checks.
  const dropped = ['r2-gemma4-a', 'r2-qwen9b-a', 'r3-gemma4-b'], kept = w6.runs.filter(run => !dropped.includes(run.run));
  assert.equal(entry(column(kept, 9), 'CS-B1').state, 'insufficient-trials');
  assert.deepEqual([entry(column(kept, 1), 'CS-B1').exact, entry(column(kept, 6), 'CS-B1').exact], ['1/6', '0']);
  assert.deepEqual([1, 2, 4, 5].map(k => entry(column(kept, k), 'CS-C1').exact), ['2/3', '2/5', '1/15', '0']);
  refuses(() => column(w6.runs, 1, observations(w6.runs).filter(o => !(o.check === 'CS-B1' && dropped.includes(o.runId)))), 'unbalanced-observations');
});

test('openai-cs-agents source re-check (only with SCOPEHAVEN_W6_SOURCE)', { skip: process.env.SCOPEHAVEN_W6_SOURCE ? false : 'SCOPEHAVEN_W6_SOURCE is not set' }, async () => {
  const bytes = await readFile(process.env.SCOPEHAVEN_W6_SOURCE);
  assert.equal(sha256(bytes), W6_SOURCE_SHA256);
  const source = JSON.parse(bytes), w6 = JSON.parse(await readFile(new URL('./fixtures/w6-cs-agents.json', import.meta.url)));
  assert.ok(source.locus.checkId.startsWith('CS-B1'));
  assert.equal(source.locus.appBuild.slice(0, 12), w6.appBuild);
  const csC1 = new Map();
  for (const pair of source.pairs) for (const r of pair.rows.filter(r => r.id === 'CS-C1')) {
    for (const [run, status] of [[pair.baseline, r.before], [pair.candidate, r.after]]) { if (csC1.has(run)) assert.equal(csC1.get(run), status, `CS-C1 conflict for ${run}`); csC1.set(run, status); }
  }
  assert.deepEqual(source.locus.observations.map(o => ({ run: o.runId, csB1: o.outcome, csC1: csC1.get(o.runId) })), w6.runs);
  assert.ok(source.identities.every(identity => identity.appDigest.startsWith(w6.appBuild)));
});

test('Case A over real loopback: a control that reads pass on its row is below one at every k', async () => {
  const run = await conversationRun();
  assert.doesNotThrow(() => validateConversationRun(run));
  const control = run.results.find(r => r.id === 'reply-ok');
  assert.equal(control.status, 'pass', 'the rate policy reads the row as pass');
  for (const [k, exact] of [[1, '4/5'], [2, '3/5'], [3, '2/5'], [4, '1/5'], [5, '0']]) {
    const column = singleRunColumn(run, k), value = entry(column, 'reply-ok');
    assert.deepEqual([column.source, column.runIds, value.trials, value.passed, value.failed, value.undecided, value.exact], ['in-run-trials', [run.id], 5, 4, 1, 0, exact]);
    assert.deepEqual(column.controls.belowOne, ['reply-ok']);
    assert.ok(passKReasons(column).includes('control-pass-k-below-one'));
  }
  near(entry(singleRunColumn(run, 1), 'reply-ok').passHatK, 0.8);
  assert.deepEqual(checksFromRun(run).checks.map(check => [check.id, check.trials]), [['reply-ok', 5], ['no-refund-claim', 5]]);
  // Stored trial outcomes are checked for consistency, not authenticated. Counts edited alone
  // (resealed) disagree with the trial records, so the validator refuses them.
  const forged = structuredClone(run), i = forged.results.findIndex(r => r.id === 'reply-ok');
  forged.results[i].trace[0].data.counts = { pass: 5, fail: 0, error: 0, inconclusive: 0 };
  forged.results[i].evidenceDigest = digest({ data: forged.results[i].trace[0].data, assertions: forged.results[i].assertions });
  assert.throws(() => validateConversationRun(forged));
  refuses(() => checksFromRun(forged), 'invalid-trial-data');
  refuses(() => singleRunColumn(forged, 1), 'invalid-trial-data');
  refuses(() => checksFromRun(run, [structuredClone(run)]), 'nested-trials');
  // The failing trial dropped consistently (records, shape, counts, digest): only the exported
  // suite, passed as expectedSuite, shows the conversation declared 5 trials.
  const suite = exportConversationSuite(conversationSpec, run.profileHash);
  assert.equal(entry(singleRunColumn(run, 4, { expectedSuite: suite }), 'reply-ok').exact, '1/5', 'the honest run meets its own suite');
  const dropped = structuredClone(run), records = dropped.conversationEvidence.conversations[i].trialRecords;
  records.splice(records.findIndex(record => record.outcome === 'fail'), 1); records.forEach((record, n) => { record.trial = n + 1; });
  dropped.conversationEvidence.shape.conversations[i].trials = 4;
  const data = dropped.results[i].trace[0].data;
  data.trials = 4; data.counts = { pass: 4, fail: 0, error: 0, inconclusive: 0 }; data.failureRate = 0;
  dropped.results[i].evidenceDigest = digest({ data, assertions: dropped.results[i].assertions });
  refuses(() => singleRunColumn(dropped, 4, { expectedSuite: suite }), 'invalid-trial-data');
  refuses(() => checksFromRun(dropped, [], { expectedSuite: suite }), 'invalid-trial-data');
});

test('SARIF annotator: only passK keys are added; kind, level and fingerprints unchanged', async () => {
  const real = await syntheticRun();
  const edited = structuredClone(real);
  ['inconclusive', 'error', 'not_applicable'].forEach((status, i) => { edited.results[i].status = status; });
  for (const run of [real, edited]) {
    const log = renderSarif(run), before = JSON.stringify(log), column = singleRunColumn(run, 1);
    const annotated = sarifWithPassK(log, column);
    assert.equal(JSON.stringify(log), before, 'the input is not mutated');
    assert.equal(JSON.stringify(sarifWithPassK(log, column)), JSON.stringify(annotated), 'deterministic');
    const original = log.runs[0], out = annotated.runs[0];
    out.results.forEach((result, i) => {
      assert.deepEqual([result.kind, result.level, result.fingerprints, result.ruleId], [original.results[i].kind, original.results[i].level, original.results[i].fingerprints, original.results[i].ruleId]);
      assert.deepEqual(result.properties.passK, entry(column, result.ruleId));
    });
    const { checks, ...summary } = column;
    assert.deepEqual(out.properties.passK, summary);
    const keys = Object.keys(out.properties);
    assert.equal(keys[keys.indexOf('counts') + 1], 'allowedUse'); assert.equal(keys.at(-1), 'passK');
    assert.deepEqual(out.tool, original.tool); assert.deepEqual(out.invocations, original.invocations);
    const stripped = structuredClone(annotated);
    delete stripped.runs[0].properties.passK; for (const result of stripped.runs[0].results) delete result.properties.passK;
    assert.equal(JSON.stringify(stripped), before, 'removing the passK keys gives back the original log');
    const added = JSON.stringify([out.properties.passK, out.results.map(result => result.properties.passK)]);
    for (const local of [process.cwd(), tmpdir(), '/Users/', '/private/', '/home/', 'file:']) assert.equal(added.includes(local), false, local);
    refuses(() => sarifWithPassK(log, singleRunColumn({ ...run, id: randomUUID() }, 1)), 'run-mismatch');
    refuses(() => sarifWithPassK(log, singleRunColumn({ ...run, results: run.results.slice(1) }, 1)), 'checks-differ');
    refuses(() => sarifWithPassK(annotated, column), 'invalid');
    const runLevelOnly = structuredClone(annotated); for (const result of runLevelOnly.runs[0].results) delete result.properties.passK;
    refuses(() => sarifWithPassK(runLevelOnly, column), 'invalid');
    const resultsOnly = structuredClone(annotated); delete resultsOnly.runs[0].properties.passK;
    refuses(() => sarifWithPassK(resultsOnly, column), 'invalid');
  }
  assert.ok(renderSarif(edited).runs[0].results.slice(0, 3).every(result => result.kind !== 'fail'), 'the edited rows keep their non-fail kinds');
});

test('normalizePassK: gate shapes only, rebuilt from counts; unknown keys dropped', async () => {
  const primary = await http(), trials = [await http({ createdAt: '2026-10-07T08:00:00.000Z', statuses: { 'FOREIGN-STATUS': 'fail' } }), again(primary, { createdAt: '2026-10-07T09:00:00.000Z' })];
  const shapes = [singleRunColumn(await conversationRun(), 3), singleRunColumn(scripted(), 1), passKColumn({ k: 2, ...checksFromRun(primary, trials) })];
  for (const column of shapes) {
    assert.deepEqual(normalizePassK(column), column);
    assert.deepEqual(normalizePassK(JSON.parse(JSON.stringify(column))), column);
    const extra = structuredClone(column); extra.extra = 1; extra.checks[0].note = LEAK_MARKER; extra.controls.reviewer = 'x'; extra.prohibited.more = []; extra.nonRequiredControls.more = 1;
    assert.deepEqual(normalizePassK(extra), column); assert.equal(JSON.stringify(normalizePassK(extra)).includes(LEAK_MARKER), false);
  }
  const base = shapes[2];
  const edits = [
    c => { c.source = 'observations'; }, c => { c.schema = 'scopehaven-pass-k/2'; }, c => { c.estimator = 'pass@k'; }, c => { c.k = 3; },
    c => { entry(c, 'FOREIGN-STATUS').exact = '2/3'; }, c => { entry(c, 'FOREIGN-STATUS').exact = '0'; }, c => { entry(c, 'OWN-READ').exact = '01'; },
    c => { entry(c, 'FOREIGN-STATUS').passHatK = 1.5; }, c => { entry(c, 'FOREIGN-STATUS').passHatK = -0.1; }, c => { c.prohibited.mean = 2; },
    c => { c.checks[0].id = 'bad id'; }, c => { c.controls.belowOne.push('OWN-READ'); }, c => { c.controls.allTrialsPassed = false; },
    c => { c.checks.reverse(); }, c => { c.window = null; }, c => { delete c.window; }, c => { c.runIds.pop(); }, c => { c.scope.push('extra'); },
    c => { entry(c, 'FOREIGN-STATUS').state = 'measured'; c.k = 99; }, c => { c.insufficient = ['FOREIGN-STATUS']; }, c => { c.controls.required = []; },
    c => { c.modelIdentity = 'recorded'; }, c => { c.modelIdentity = 'unknown'; }, c => { delete c.modelIdentity; }, c => { c.nonRequiredControls.belowOne = ['OWN-READ']; },
    c => { c.window.first = '2026-10-07T08:00:00Z'; },
  ];
  for (const edit of edits) { const c = structuredClone(base); edit(c); assert.equal(normalizePassK(c), null, edit.toString()); }
  const observed = passKColumn({ k: 1, ...checksFromObservations([{ runId: 'r', check: 'a', success: true }], [{ id: 'a', severity: 'high' }]) });
  assert.equal(normalizePassK(observed), null, 'the gate never emits observations');
  for (const value of [null, undefined, 1, [], {}, 'column']) assert.equal(normalizePassK(value), null);
  assert.ok(PASS_K_SOURCES.includes('observations'));
  // A consistent column with an allowed-use role on a control that is not required, or a
  // non-required role on a required control, is refused: only required ids are allowed-use controls.
  const loose = inRun(1, [row('x', 'control', 0, 1), row('p', 'high', 1, 1)]);
  assert.deepEqual([entry(loose, 'x').role, loose.nonRequiredControls], ['non-required-control', { checks: 1, belowOne: ['x'] }]);
  const promoted = structuredClone(loose); entry(promoted, 'x').role = 'allowed-use-control'; promoted.nonRequiredControls = { checks: 0, belowOne: [] };
  assert.equal(normalizePassK(promoted), null);
  const strict = inRun(1, [row('c', 'control', 1, 1), row('p', 'high', 1, 1)], ['c']);
  const demoted = structuredClone(strict); entry(demoted, 'c').role = 'non-required-control';
  demoted.nonRequiredControls = { checks: 1, belowOne: [] };
  demoted.controls = { required: ['c'], allTrialsPassed: false, lowest: null, belowOne: [], insufficient: [], missing: ['c'] };
  demoted.scope = [demoted.scope[0], demoted.scope[1], CONTROLS_MISSING, ...demoted.scope.slice(2)];
  assert.equal(normalizePassK(demoted), null);
});

test('the column carries no evidence bodies, titles, traces or secrets', async () => {
  for (const run of [await syntheticRun(), await conversationRun(), scripted()]) {
    for (const k of [1, 2]) {
      const text = JSON.stringify(singleRunColumn(run, k));
      for (const banned of ['attempts', 'trace', 'turns', 'trialRecords', 'conversationEvidence', 'notes', LEAK_MARKER, 'title']) assert.equal(text.includes(banned), false, banned);
      for (const title of run.results.map(r => r.title).filter(Boolean)) assert.equal(text.includes(title), false);
      assert.ok(run.results.some(r => JSON.stringify(r).includes('trace') || JSON.stringify(r).includes(LEAK_MARKER)), 'the dump really did carry them');
    }
  }
});

test('deterministic: shuffled input, no mutation, code-unit order', async () => {
  const rows = [row('b', 'high', 3, 5), row('B', 'control', 5, 5), row('a', 'high', 4, 5), row('A-1', 'low', 1, 5)];
  const before = JSON.stringify(rows), one = JSON.stringify(inRun(2, rows, ['B']));
  assert.equal(JSON.stringify(inRun(2, [...rows].reverse(), ['B'])), one);
  assert.equal(JSON.stringify(inRun(2, [rows[2], rows[0], rows[3], rows[1]], ['B'])), one);
  assert.equal(JSON.stringify(rows), before, 'input not mutated');
  assert.deepEqual(inRun(2, rows, ['B']).checks.map(check => check.id), ['A-1', 'B', 'a', 'b']);
  const observations = [{ runId: 'a-run', check: 'x', success: true }, { runId: 'B-run', check: 'x', success: false }];
  assert.deepEqual(checksFromObservations(observations, [{ id: 'x', severity: 'high' }]).runIds, ['B-run', 'a-run']);
  assert.deepEqual(checksFromObservations([...observations].reverse(), [{ id: 'x', severity: 'high' }]).runIds, ['B-run', 'a-run']);
  const base = await http();
  assert.equal(trialIdentity(again(base, { requiredControlIds: ['b', 'A'] })), trialIdentity(again(base, { requiredControlIds: ['A', 'b'] })));
  const primary = again(base, { id: 'P', createdAt: '2026-10-07T12:00:00.000Z' });
  const trials = [again(base, { id: 'a-2', createdAt: '2026-10-07T10:00:00.000Z' }), again(base, { id: 'B-2', createdAt: '2026-10-07T10:00:00.000Z' }), await http({ id: 'c-1', createdAt: '2026-10-07T09:00:00.000Z', statuses: { 'OWN-READ': 'error' } })];
  const trialsBefore = JSON.stringify(trials), first = checksFromRun(primary, trials);
  assert.deepEqual(first.runIds, ['P', 'c-1', 'B-2', 'a-2'], 'primary first, then (createdAt, id) in code-unit order');
  assert.deepEqual(first.window, { first: '2026-10-07T09:00:00.000Z', last: '2026-10-07T12:00:00.000Z' });
  assert.equal(JSON.stringify(checksFromRun(primary, [...trials].reverse())), JSON.stringify(first));
  assert.equal(JSON.stringify(trials), trialsBefore);
  assert.deepEqual(first.checks.find(check => check.id === 'OWN-READ'), { id: 'OWN-READ', severity: 'control', trials: 4, passed: 3, failed: 0, undecided: 1 });
});

test('source text: no pass@k, failure rate, locale order or excluded vocabulary', async () => {
  const words = [['pass', 'AtK'], ['failure', 'Rate'], ['locale', 'Compare'], ['read', 'ings'], ['grounded', 'ness'], ['supplied', 'Context']].map(parts => parts.join(''));
  const dashes = [0x2013, 0x2014].map(code => String.fromCharCode(code));
  for (const file of ['./passk.mjs', './store.mjs', './cli.mjs', './passk.test.mjs', './README.md', './fixtures/w6-cs-agents.json']) {
    const source = await readFile(new URL(file, import.meta.url), 'utf8');
    if (file.endsWith('.mjs') && file !== './passk.test.mjs') for (const word of words) assert.equal(source.includes(word), false, `${file}: ${word}`);
    for (const dash of dashes) assert.equal(source.includes(dash), false, `${file}: no en or em dash`);
  }
});

test('collectSavedTrials: same identity only, never the primary, errors propagate, bounded', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-pass-k-store-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createStore(join(dir, 'data')); await store.ready;
  const primary = await http({ createdAt: '2026-10-07T12:00:00.000Z' });
  const same = [again(primary, { createdAt: '2026-10-07T10:00:00.000Z' }), await http({ createdAt: '2026-10-07T11:00:00.000Z', statuses: { 'FOREIGN-STATUS': 'fail' } })];
  // Other identities: another build, a model identity, another forwarded target, a scripted run,
  // and an identity that names no single model (partial), which is skipped, never a refusal.
  const partial = modelIdentity(tapFrames().slice(0, -1));
  assert.equal(partial.state, 'partial');
  const others = [await http({ build: 'lab-baseline' }), again(primary, { modelIdentity: modelIdentity(tapFrames(), { from: 1, to: 3 }) }),
    await http({ target: { targetContext: 'operator-forwarded', targetLabel: 'lab-y' } }), scripted(), again(primary, { modelIdentity: partial })];
  for (const run of [primary, ...same, ...others]) await store.save(run);
  // History lists newest file first: the later-created run is listed first and must come back last.
  for (const [run, year] of [[same[1], 2003], [same[0], 2002]]) await utimes(join(dir, 'data', 'runs', `${run.id}.json`), new Date(`${year}-01-01T00:00:00Z`), new Date(`${year}-01-01T00:00:00Z`));
  const saved = await store.get(primary.id);
  const trials = await collectSavedTrials({ store, primary: saved });
  assert.deepEqual(trials.map(run => run.id), [same[0].id, same[1].id], 'oldest first, every match, nothing else');
  assert.ok(trials.every(run => run.integrity?.sha256), 'loaded through store.get');
  const column = passKColumn({ k: 3, ...checksFromRun(saved, trials) });
  assert.deepEqual([entry(column, 'FOREIGN-STATUS').exact, column.prohibited.belowOne, passKReasons(column)], ['0', ['FOREIGN-STATUS'], ['checks-pass-k-below-one']]);
  assert.deepEqual(column.runIds, [primary.id, same[0].id, same[1].id]);
  // A primary whose model identity names no single model cannot pool: refused.
  await assert.rejects(collectSavedTrials({ store, primary: { ...saved, modelIdentity: partial } }), error => error instanceof PassKError && error.code === 'trial-identity-differs');
  // A store holding only the primary gives no trials.
  const alone = createStore(join(dir, 'alone')); await alone.ready; await alone.save(primary);
  assert.deepEqual(await collectSavedTrials({ store: alone, primary }), []);
  // An integrity failure while listing, or while loading a listed run, propagates.
  const file = join(dir, 'data', 'runs', `${same[0].id}.json`), record = JSON.parse(await readFile(file, 'utf8'));
  const broken = { get: async id => { if (id === same[0].id) await writeFile(file, JSON.stringify({ ...record, core: { ...record.core, build: 'edited' } })); return store.get(id); }, historyPage: options => store.historyPage(options) };
  await assert.rejects(collectSavedTrials({ store: broken, primary: saved }), /integrity/);
  await assert.rejects(collectSavedTrials({ store, primary: saved }), /integrity/);
  await writeFile(file, JSON.stringify(record));
  const swapped = { get: async id => ({ ...(await store.get(id)), build: 'lab-swapped' }), historyPage: options => store.historyPage(options) };
  await assert.rejects(collectSavedTrials({ store: swapped, primary: saved }), error => error instanceof PassKError && error.code === 'trial-identity-differs');
  for (const options of [{}, { store, primary: null }, { store: {}, primary: saved }, { store, primary: saved, max: PASS_K_MAX }, { store, primary: saved, max: -1 }]) {
    await assert.rejects(collectSavedTrials(options), error => error instanceof PassKError && error.code === 'invalid');
  }
  // A listed summary that is not a run is an error, never skipped like a run of another model.
  const odd = { get: id => store.get(id), historyPage: async () => ({ runs: ['not a run'], nextCursor: null }) };
  await assert.rejects(collectSavedTrials({ store: odd, primary: saved }), error => error instanceof PassKError && error.code === 'invalid');
  // Paging and the bound: 99 other matches across two history pages are all read; a 100th refuses.
  const big = createStore(join(dir, 'big')); await big.ready;
  const head = again(primary, { createdAt: '2026-10-07T12:00:00.000Z' }); await big.save(head);
  const matches = Array.from({ length: PASS_K_MAX - 1 }, (_, i) => again(primary, { createdAt: `2026-10-07T11:${String(i % 60).padStart(2, '0')}:00.000Z` }));
  for (const run of [...matches, others[0]]) await big.save(run);
  const runFile = id => join(dir, 'big', 'runs', `${id}.json`);
  await utimes(runFile(head.id), new Date(Date.now() + 3600e3), new Date(Date.now() + 3600e3));
  await utimes(runFile(matches[0].id), new Date('2001-01-01T00:00:00Z'), new Date('2001-01-01T00:00:00Z'));
  const firstPage = await big.historyPage({ limit: 100 });
  assert.equal(firstPage.runs.some(run => run.id === matches[0].id), false, 'one match is only on the second page');
  const collected = await collectSavedTrials({ store: big, primary: head });
  assert.equal(collected.length, PASS_K_MAX - 1);
  assert.ok(collected.some(run => run.id === matches[0].id));
  await big.save(again(primary));
  await assert.rejects(collectSavedTrials({ store: big, primary: head }), error => error instanceof PassKError && error.code === 'too-many-trials' && error.message === 'too-many-trials');
  assert.equal((await collectSavedTrials({ store: big, primary: head, max: PASS_K_MAX - 1 }).catch(error => error.code)), 'too-many-trials');
});

test('markdown: rows, lowest, fractions, scope sentences and the 100-row cap', async () => {
  const column = inRun(5, [row('ctl-a', 'control', 4, 5, 0, 1), row('p-1', 'high', 5, 5)], ['ctl-a']);
  const lines = markdownLines(column);
  assert.equal(lines[0], '### pass^k');
  assert.ok(lines.some(line => line.startsWith('| ctl-a | allowed-use-control | 5 | 4 | 0 | 1 | 0 |')));
  assert.ok(lines.some(line => line.includes('lowest **0**;')));
  assert.ok(lines.some(line => line.includes('below one: ctl-a')));
  assert.equal(formatPassK({ exact: '1/6', passHatK: 1 / 6 }), '1/6 (0.167)');
  assert.equal(formatPassK({ exact: '1/126', passHatK: 1 / 126 }), '1/126 (0.00794)');
  const w6Like = k => entry(inRun(k, [row('CS-B1', 'high', 4, 9)]), 'CS-B1');
  assert.deepEqual([formatPassK(w6Like(2)), formatPassK(w6Like(4)), formatPassK(w6Like(5))], ['1/6 (0.167)', '1/126 (0.00794)', '0']);
  assert.equal(formatPassK({ exact: '9999/10000', passHatK: 0.9999 }), '9999/10000 (>0.999)', 'below one never prints as 1');
  assert.equal(formatPassK(entry(inRun(1, [row('t', 'high', 1, 1000)]), 't')), '1/1000 (0.00100)', 'tiny values never print as 0');
  assert.equal(formatPassK({ exact: null, passHatK: null }), 'insufficient trials');
  refuses(() => formatPassK({ exact: '2/3', passHatK: 1 }), 'invalid');
  const single = markdownLines(singleRunColumn(scripted(), 1));
  assert.ok(single.includes('> With one trial per check, every value is 1 or 0 and is not a rate.'));
  const many = Array.from({ length: 150 }, (_, i) => row(`c-${String(i).padStart(3, '0')}`, 'high', 1, 1));
  many[149] = row('c-149', 'high', 0, 1);
  const capped = markdownLines(inRun(1, many));
  const tableRows = capped.filter(line => line.startsWith('| c-'));
  assert.equal(tableRows.length, 100);
  assert.ok(tableRows[0].startsWith('| c-149 |'), 'a check below one is never cut by the cap');
  assert.ok(capped.includes('50 more checks are in the full pass^k column.'));
  assert.ok(capped.includes('**Prohibited-behaviour checks** (150, 150 measured): mean **0.993**; below one: c-149.'), 'a fractional mean prints with 3 significant digits');
  assert.ok(markdownLines(inRun(1, many.slice(0, 101))).includes('1 more check is in the full pass^k column.'));
  assert.ok(markdownLines(inRun(1, many.slice(0, 100))).every(line => !line.includes('more check')));
  // More than 20 ids in one list: the first 20, then a count.
  const wide = markdownLines(inRun(1, Array.from({ length: 25 }, (_, i) => row(`w-${String(i).padStart(2, '0')}`, 'high', 0, 1))));
  assert.ok(wide.some(line => line.endsWith(`below one: ${Array.from({ length: 20 }, (_, i) => `w-${String(i).padStart(2, '0')}`).join(', ')} and 5 more.`)));
  // Fewer than k trials, and a control figure that is not given (with the reason).
  const short = markdownLines(inRun(5, [row('ctl', 'control', 2, 3), row('p1', 'high', 5, 5), row('p2', 'high', 2, 3)], ['ctl']));
  assert.ok(short.includes('Fewer than k trials: ctl, p2.'));
  assert.ok(short.includes('**Required allowed-use controls** (1): lowest **not given** (a required control has fewer than k trials); below one: ctl; insufficient: ctl; missing: none.'));
  assert.ok(short.includes(`> ${CONTROLS_INSUFFICIENT}`));
  assert.ok(markdownLines(inRun(1, [row('p', 'high', 1, 1)])).some(line => line.includes('lowest **none required**;')));
  // A saved-runs column names the createdAt window of its runs.
  const primary = await http({ createdAt: '2026-10-07T12:00:00.000Z' });
  const saved = markdownLines(passKColumn({ k: 1, ...checksFromRun(primary, [again(primary, { createdAt: '2026-10-07T09:30:00.000Z' })]) }));
  assert.ok(saved.includes('Saved runs created from 2026-10-07T09:30:00.000Z to 2026-10-07T12:00:00.000Z.'));
  assert.ok(saved.includes(`> ${POOLED}`) && saved.includes(`> ${MODEL_NOT_RECORDED}`));
  const cell = value => String(value).replaceAll('|', '\\|');
  assert.ok(markdownLines(column, cell).some(line => line.startsWith('| ctl-a |')));
  refuses(() => markdownLines(null), 'invalid');
  // A malformed or edited column refuses (never a TypeError), and so does a source the gate never emits.
  refuses(() => markdownLines({ checks: [], controls: {}, prohibited: {}, scope: [] }), 'invalid');
  const edited = structuredClone(column); edited.checks[0].passed = 5;
  refuses(() => markdownLines(edited), 'invalid');
  refuses(() => markdownLines(passKColumn({ k: 1, ...checksFromObservations([{ runId: 'r', check: 'a', success: true }], [{ id: 'a', severity: 'high' }]) })), 'invalid');
  refuses(() => markdownLines(column, 'not a function'), 'invalid');
});

test('passKReasons: fixed order, saved-runs only for prohibited checks, missing controls fail closed', async () => {
  const checks = [['FOREIGN-STATUS', 'high'], ['OWN-READ', 'control'], ['SLOW', 'low']];
  const primary = await http({ checks });
  const trial = await http({ createdAt: '2026-10-07T09:00:00.000Z', checks, statuses: { 'FOREIGN-STATUS': 'fail', 'OWN-READ': 'inconclusive' } });
  const all = passKColumn({ k: 3, ...checksFromRun(primary, [trial]) });
  assert.deepEqual(passKReasons(all), [...PASS_K_REASONS]);
  const inRunBelow = inRun(1, [row('p', 'high', 1, 2), row('c', 'control', 2, 2)], ['c']);
  assert.deepEqual(passKReasons(inRunBelow), [], 'in-run prohibited rows keep their declared policy');
  const missing = inRun(1, [row('ctl', 'control', 1, 1), row('p', 'high', 1, 1), row('extra', 'control', 0, 1)], ['ctl', 'gone', 'p']);
  assert.deepEqual(missing.controls, { required: ['ctl', 'gone', 'p'], allTrialsPassed: false, lowest: null, belowOne: [], insufficient: [], missing: ['gone', 'p'] });
  assert.ok(missing.scope.includes(CONTROLS_MISSING) && !missing.scope.includes(CONTROLS_INSUFFICIENT));
  assert.deepEqual(passKReasons(missing), [], 'v1 already fails missing controls; no refusal');
  assert.equal(inRun(1, [row('p', 'high', 1, 1)]).controls.allTrialsPassed, false, 'no required control shows nothing');
  assert.equal(entry(missing, 'extra').role, 'non-required-control');
  refuses(() => passKReasons({}), 'invalid');
  assert.equal(all.schema, PASS_K_SCHEMA);
});

test('the control figure is not given while a required control is insufficient or missing', () => {
  // One flaky control with too few trials beside a measured 5/5 control: never "lowest 1".
  const mixed = inRun(5, [row('ctl-flaky', 'control', 2, 3), row('ctl-steady', 'control', 5, 5), row('p', 'high', 5, 5)], ['ctl-flaky', 'ctl-steady']);
  assert.deepEqual(mixed.controls, { required: ['ctl-flaky', 'ctl-steady'], allTrialsPassed: false, lowest: null, belowOne: ['ctl-flaky'], insufficient: ['ctl-flaky'], missing: [] });
  assert.ok(mixed.scope.includes(CONTROLS_INSUFFICIENT) && !mixed.scope.includes(CONTROLS_MISSING));
  assert.deepEqual(passKReasons(mixed), ['pass-k-insufficient-trials', 'control-pass-k-below-one']);
  assert.ok(markdownLines(mixed).some(line => line.startsWith('**Required allowed-use controls** (2): lowest **not given** (a required control has fewer than k trials); below one: ctl-flaky;')));
  // A measured control beside a required id with no row: no figure either.
  const gone = inRun(1, [row('ctl', 'control', 1, 1), row('p', 'high', 1, 1)], ['ctl', 'gone']);
  assert.equal(gone.controls.lowest, null);
  assert.ok(markdownLines(gone).some(line => line.includes('lowest **not given** (a required control id has no control row);')));
  const both = inRun(5, [row('ctl', 'control', 2, 3), row('p', 'high', 5, 5)], ['ctl', 'gone']);
  assert.ok(both.scope.includes(CONTROLS_INSUFFICIENT) && both.scope.includes(CONTROLS_MISSING));
  // Every required control measured: the figure is the lowest.
  assert.deepEqual(inRun(3, [row('ctl-flaky', 'control', 4, 5), row('ctl-steady', 'control', 5, 5)], ['ctl-flaky', 'ctl-steady']).controls.lowest, { exact: '2/5', passHatK: passHatK([{ cluster: 'x', successes: 4, n: 5 }], 3) });
});

test('a control that is not required is its own role, counts with the checks and is never averaged', async () => {
  const checks = [['FOREIGN-STATUS', 'high'], ['OWN-READ', 'control'], ['OWN-EXPORT', 'control']];
  const primary = await http({ checks, createdAt: '2026-10-07T12:00:00.000Z' });
  const failed = await http({ checks, createdAt: '2026-10-07T10:00:00.000Z', statuses: { 'OWN-EXPORT': 'fail' } });
  const errored = await http({ checks, createdAt: '2026-10-07T11:00:00.000Z', statuses: { 'OWN-EXPORT': 'error' } });
  const column = passKColumn({ k: 1, ...checksFromRun(primary, [failed, errored]) });
  assert.deepEqual(entry(column, 'OWN-EXPORT'), { id: 'OWN-EXPORT', role: 'non-required-control', trials: 3, passed: 1, failed: 1, undecided: 1, passHatK: 1 / 3, exact: '1/3', state: 'measured' });
  assert.deepEqual(column.nonRequiredControls, { checks: 1, belowOne: ['OWN-EXPORT'] });
  assert.deepEqual([column.prohibited.checks, column.prohibited.mean, column.prohibited.belowOne], [1, 1, []], 'never in the prohibited mean');
  assert.deepEqual([column.controls.required, column.controls.allTrialsPassed, column.controls.lowest], [['OWN-READ'], true, { exact: '1', passHatK: 1 }]);
  assert.deepEqual(passKReasons(column), ['checks-pass-k-below-one'], 'as v1 counts a failed row of any severity into checks-failed');
  assert.ok(markdownLines(column).includes('**Controls not listed as required** (1): not averaged and not the control figure; below one: OWN-EXPORT.'));
  // Single-run and in-run sources keep v1's reasons for it, as for prohibited rows.
  assert.deepEqual(passKReasons(inRun(1, [row('x', 'control', 0, 1), row('c', 'control', 1, 1)], ['c'])), []);
  assert.equal(markdownLines(inRun(1, [row('p', 'high', 1, 1)])).some(line => line.includes('not listed as required')), false);
});

test('saved runs without a model identity still pool, and the column says the models may differ', async () => {
  const primary = await http({ createdAt: '2026-10-07T12:00:00.000Z' });
  const pooled = passKColumn({ k: 1, ...checksFromRun(primary, [again(primary, { createdAt: '2026-10-07T11:00:00.000Z' })]) });
  assert.deepEqual([pooled.runIds.length, pooled.modelIdentity], [2, 'not-recorded']);
  assert.deepEqual(pooled.scope.slice(1, 3), [POOLED, MODEL_NOT_RECORDED]);
  const alone = singleRunColumn(primary, 1);
  assert.deepEqual([alone.modelIdentity, alone.scope[1], alone.scope.includes(MODEL_NOT_RECORDED), alone.scope.includes(POOLED)], ['not-recorded', ALONE, false, false]);
});

test('trial identity binds the observed model only, as compareModelIdentities compares it', async () => {
  // Real modelIdentity() outputs over two windows of one tap: same model, different window, calls and head.
  const frames = tapFrames(), first = modelIdentity(frames, { from: 1, to: 3 }), second = modelIdentity(frames, { from: 3, to: 5 });
  assert.deepEqual([first.state, second.state, first.strength, first.key === second.key, compareModelIdentities(first, second).relation], ['observed', 'observed', 'vendor-model-string', true, 'same']);
  assert.notDeepEqual(first.window, second.window);
  const base = await http({ createdAt: '2026-10-07T12:00:00.000Z' });
  const a = again(base, { modelIdentity: first }), b = again(base, { createdAt: '2026-10-07T11:00:00.000Z', modelIdentity: second });
  assert.equal(trialIdentity(a), trialIdentity(b));
  const pooled = passKColumn({ k: 2, ...checksFromRun(a, [b]) });
  assert.deepEqual([pooled.runIds, pooled.modelIdentity, pooled.insufficient, pooled.scope.includes(MODEL_NOT_RECORDED)], [[a.id, b.id], 'recorded', [], false]);
  assert.equal(singleRunColumn(a, 1).modelIdentity, 'recorded');
  // Another served model, another upstream below a weights digest, or no identity: another subject.
  const qwen = modelIdentity(tapFrames({ served: ['qwen3.5:9b', 'qwen3.5:9b'] }), { from: 1, to: 3 });
  const elsewhere = modelIdentity(tapFrames({ session: 'tap-2', upstream: 'http://127.0.0.1:11435' }), { from: 1, to: 3 });
  for (const other of [qwen, elsewhere, undefined]) {
    assert.notEqual(compareModelIdentities(first, other ?? null).relation, 'same');
    refuses(() => checksFromRun(a, [{ ...b, modelIdentity: other }]), 'trial-identity-differs');
  }
  // With a weights digest the digest decides and the upstream is not compared; another digest is another model.
  const weighted = (session, upstream, weights, from, to) => modelIdentity(tapFrames({ session, upstream, weights }), { from, to });
  const w1 = weighted('tap-3', 'http://127.0.0.1:11434', { 'gemma4:latest': 'sha256:aa' }, 2, 5), w2 = weighted('tap-4', 'http://127.0.0.1:11435', { 'gemma4:latest': 'sha256:aa' }, 5, 8);
  const w3 = weighted('tap-5', 'http://127.0.0.1:11434', { 'gemma4:latest': 'sha256:bb' }, 2, 5);
  assert.deepEqual([w1.strength, w2.strength, compareModelIdentities(w1, w2).relation, compareModelIdentities(w1, w3).relation], ['weights-digest', 'weights-digest', 'same', 'silent-change']);
  assert.equal(trialIdentity({ ...a, modelIdentity: w1 }), trialIdentity({ ...b, modelIdentity: w2 }));
  refuses(() => checksFromRun({ ...a, modelIdentity: w1 }, [{ ...b, modelIdentity: w3 }]), 'trial-identity-differs');
  // Partial, mixed, not-observed and malformed identities name no single model: refused when pooled.
  const partial = modelIdentity(frames.slice(0, -1)), mixed = modelIdentity(tapFrames({ served: ['gemma4:latest', 'qwen3.5:9b'] })), none = modelIdentity(frames, { from: 5, to: 6 });
  assert.deepEqual([partial.state, mixed.state, none.state], ['partial', 'mixed', 'not-observed']);
  // Malformed: a key that is not its model's, no model, no served name (even with a key made to match), a strength its fields do not carry, and no object.
  const malformed = [{ ...first, key: digest('another key') }, { ...first, models: [] }, { ...first, models: [{ ...first.models[0], served: null }] },
    { ...first, models: [{ ...first.models[0], served: null }], key: digest([{ served: null }]) }, { ...first, models: [{ ...first.models[0], strength: 'weights-digest' }] },
    { state: 'observed', model: 'm' }, 'gemma4', []];
  for (const bad of [partial, mixed, none, ...malformed]) {
    refuses(() => trialIdentity({ ...a, modelIdentity: bad }), 'trial-identity-differs');
    refuses(() => checksFromRun(a, [{ ...b, modelIdentity: bad }]), 'trial-identity-differs');
    refuses(() => checksFromRun({ ...a, modelIdentity: bad }, [{ ...b, modelIdentity: bad }]), 'trial-identity-differs');
    // Alone, nothing is pooled: the run's own column reads not-recorded.
    assert.equal(singleRunColumn({ ...a, modelIdentity: bad }, 1).modelIdentity, 'not-recorded');
  }
});

test('saved HTTP evidence is validated for the primary and every trial', async () => {
  const primary = await http({ createdAt: '2026-10-07T12:00:00.000Z' });
  const trial = await http({ createdAt: '2026-10-07T11:00:00.000Z', statuses: { 'FOREIGN-STATUS': 'fail' } });
  const honest = passKColumn({ k: 2, ...checksFromRun(primary, [trial]) });
  assert.deepEqual([entry(honest, 'FOREIGN-STATUS').exact, passKReasons(honest)], ['0', ['checks-pass-k-below-one']]);
  // One trial's row status edited from fail to pass; its assertions still say fail.
  const edited = structuredClone(trial); edited.results.find(r => r.id === 'FOREIGN-STATUS').status = 'pass';
  assert.throws(() => validateHttpRunEvidence(edited));
  refuses(() => checksFromRun(primary, [edited]), 'invalid-trial-data');
  const flipped = structuredClone(primary); flipped.results.find(r => r.id === 'OWN-READ').status = 'fail';
  refuses(() => checksFromRun(flipped, [trial]), 'invalid-trial-data');
  refuses(() => singleRunColumn(flipped, 1), 'invalid-trial-data');
  // Resealed in a store: store.get checks only the seal, so the collector returns it and checksFromRun refuses it.
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-pass-k-edited-'));
  try {
    const store = createStore(join(dir, 'data')); await store.ready;
    await store.save(primary); await store.save(edited);
    const collected = await collectSavedTrials({ store, primary: await store.get(primary.id) });
    assert.deepEqual(collected.map(run => run.id), [edited.id]);
    refuses(() => checksFromRun(primary, collected), 'invalid-trial-data');
  } finally { await rm(dir, { recursive: true, force: true }); }
  // The expected suite reaches the HTTP validator too.
  refuses(() => singleRunColumn(primary, 1, { expectedSuite: { version: 'http-contract/0', checks: [] } }), 'invalid-trial-data');
  refuses(() => checksFromRun(primary, [trial], { expectedSuite: { version: 'http-contract/0', checks: [] } }), 'invalid-trial-data');
});

test('createdAt is exactly the toISOString form', async () => {
  const primary = await http({ createdAt: '2026-10-07T10:00:01.000Z' });
  // Whole seconds, other precisions, impossible dates, a space, and extended years (which read back
  // exactly but are not fixed width, so they would sort out of time order).
  for (const createdAt of ['2026-10-07T10:00:00Z', '2026-10-07T10:00:00.9Z', '2026-10-07T10:00:00.9000Z', '2026-13-45T99:99:99.000Z', '2026-02-30T00:00:00.000Z', '2026-10-07 10:00:00.000Z',
    '+010000-01-01T00:00:00.000Z', '-000001-01-01T00:00:00.000Z']) {
    refuses(() => checksFromRun(primary, [again(primary, { createdAt })]), 'invalid');
    refuses(() => singleRunColumn({ ...primary, createdAt }, 1), 'invalid');
    refuses(() => passKColumn({ k: 1, source: 'saved-runs', runIds: ['r'], window: { first: createdAt, last: createdAt }, modelIdentity: 'not-recorded', checks: [row('a', 'high', 1, 1)] }), 'invalid');
  }
  const ordered = checksFromRun(primary, [again(primary, { id: 'A', createdAt: '2026-10-07T10:00:00.000Z' }), again(primary, { id: 'B', createdAt: '2026-10-07T10:00:00.900Z' })]);
  assert.deepEqual([ordered.runIds.slice(1), ordered.window], [['A', 'B'], { first: '2026-10-07T10:00:00.000Z', last: '2026-10-07T10:00:01.000Z' }]);
  refuses(() => passKColumn({ k: 1, source: 'saved-runs', runIds: ['r'], window: { first: '2026-10-07T10:00:01.000Z', last: '2026-10-07T10:00:00.000Z' }, modelIdentity: 'not-recorded', checks: [row('a', 'high', 1, 1)] }), 'invalid');
  refuses(() => passKColumn({ k: 1, source: 'saved-runs', runIds: ['r'], window: { first: '2026-10-07T10:00:00.000Z', last: '2026-10-07T10:00:00.000Z' }, checks: [row('a', 'high', 1, 1)] }), 'invalid');
  refuses(() => passKColumn({ k: 1, source: 'in-run-trials', runIds: ['r'], window: null, modelIdentity: 'recorded', checks: [row('a', 'high', 1, 1)] }), 'invalid');
});

test('the saved-runs scope says what was read; one run can raise checks-pass-k-below-one beside a soft reason', async () => {
  for (const status of ['inconclusive', 'error']) {
    const alone = await http({ statuses: { 'FOREIGN-STATUS': status } });
    const column = singleRunColumn(alone, 1);
    assert.deepEqual([column.scope[1], column.scope.includes(POOLED), entry(column, 'FOREIGN-STATUS').undecided], [ALONE, false, 1]);
    assert.deepEqual(passKReasons(column), ['checks-pass-k-below-one'], 'a hard reason that v1 would read as soft or runner-error');
  }
  const primary = await http();
  const pooled = passKColumn({ k: 1, ...checksFromRun(primary, [again(primary, { createdAt: '2026-10-07T09:00:00.000Z' })]) });
  assert.deepEqual([pooled.scope[1], pooled.scope.includes(ALONE)], [POOLED, false]);
});

test('the SARIF annotator refuses a column that does not describe the log', async () => {
  const run = await syntheticRun(), log = renderSarif(run), column = singleRunColumn(run, 1);
  const controlId = run.requiredControlIds[0], prohibitedId = run.results.find(r => r.severity !== 'control').id;
  assert.ok(sarifWithPassK(log, column));
  // Same count, one id swapped: every column id must be a result.
  const swapped = structuredClone(log); swapped.runs[0].results.find(r => r.ruleId === prohibitedId).ruleId = 'SWAPPED-ID';
  refuses(() => sarifWithPassK(swapped, column), 'checks-differ');
  // A duplicated result id with the same id set and count of distinct ids.
  const duplicated = structuredClone(log); duplicated.runs[0].results.push(structuredClone(duplicated.runs[0].results[0]));
  refuses(() => sarifWithPassK(duplicated, column), 'checks-differ');
  // Another required control list than the log's own (src/sarif.mjs runs[0].properties.requiredControlIds).
  const unrequired = passKColumn({ k: 1, ...checksFromRun(run), requiredControlIds: [] });
  assert.ok(normalizePassK(unrequired) !== null);
  refuses(() => sarifWithPassK(log, unrequired), 'checks-differ');
  const noList = structuredClone(log); noList.runs[0].properties.requiredControlIds = null;
  refuses(() => sarifWithPassK(noList, column), 'checks-differ');
  // A role that contradicts its rule's checkRole, with the required list unchanged.
  const relabelled = passKColumn({ k: 1, ...checksFromRun(run), checks: checksFromRun(run).checks.map(c => c.id === prohibitedId ? { ...c, severity: 'control' } : c) });
  assert.equal(entry(relabelled, prohibitedId).role, 'non-required-control');
  refuses(() => sarifWithPassK(log, relabelled), 'checks-differ');
  const demoted = structuredClone(log); demoted.runs[0].tool.driver.rules.find(rule => rule.id === controlId).properties.checkRole = 'prohibited-behaviour';
  refuses(() => sarifWithPassK(demoted, column), 'checks-differ');
  // Results without properties, a log without rules, or duplicated rule ids are not Scopehaven logs.
  const bare = structuredClone(log); delete bare.runs[0].results[0].properties;
  refuses(() => sarifWithPassK(bare, column), 'invalid');
  const ruleless = structuredClone(log); delete ruleless.runs[0].tool.driver.rules;
  refuses(() => sarifWithPassK(ruleless, column), 'invalid');
  const twice = structuredClone(log); twice.runs[0].tool.driver.rules.push(structuredClone(twice.runs[0].tool.driver.rules[0]));
  refuses(() => sarifWithPassK(twice, column), 'invalid');
  // A control that is not required: its rule's checkRole is allowed-use-control, which both control roles match.
  const extra = await http({ checks: [['FOREIGN-STATUS', 'high'], ['OWN-READ', 'control'], ['OWN-EXPORT', 'control']] });
  const extraLog = renderSarif(extra), extraColumn = singleRunColumn(extra, 1);
  assert.equal(entry(extraColumn, 'OWN-EXPORT').role, 'non-required-control');
  assert.equal(extraLog.runs[0].tool.driver.rules.find(rule => rule.id === 'OWN-EXPORT').properties.checkRole, 'allowed-use-control');
  assert.deepEqual(sarifWithPassK(extraLog, extraColumn).runs[0].results.find(result => result.ruleId === 'OWN-EXPORT').properties.passK, entry(extraColumn, 'OWN-EXPORT'));
});

test('CLI: column and annotate write exclusively into a private directory; errors are fixed codes', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-pass-k-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const out = join(dir, 'out'); await mkdir(out, { mode: 0o700 });
  const run = await syntheticRun();
  const files = { record: join(dir, 'record.json'), exported: join(dir, 'run.json'), sarif: join(dir, 'scopehaven.sarif'), gate: join(dir, 'gate.json'), tampered: join(dir, 'tampered.json'), bad: join(dir, 'bad.json') };
  await writeFile(files.record, JSON.stringify({ core: run, sha256: digest(run) }));
  await writeFile(files.exported, JSON.stringify({ ...run, integrity: { algorithm: 'SHA-256', sha256: digest(run), scope: 'run core only; editable notes excluded' }, notes: {} }));
  await writeFile(files.sarif, serializeSarif(run));
  await writeFile(files.tampered, JSON.stringify({ core: { ...run, build: 'repaired' }, sha256: digest(run) }));
  await writeFile(files.bad, '{ not json');
  const column = singleRunColumn(run, 1);
  await writeFile(files.gate, JSON.stringify({ schemaVersion: 2, current: { runId: run.id, passK: column } }));
  const call = async argv => { let text = ''; const code = await cli(argv, { stdout: { write: s => { text += s; } } }); return { code, json: JSON.parse(text), text }; };
  const columnOut = await call(['column', '--run', files.record, '--k', '1']);
  assert.deepEqual([columnOut.code, columnOut.json], [0, column]);
  assert.deepEqual((await call(['column', '--run', files.exported, '--k', '2'])).json, singleRunColumn(run, 2));
  const expected = JSON.stringify(sarifWithPassK(JSON.parse(serializeSarif(run)), column), null, 2) + '\n';
  for (const [name, source] of [['from-run.sarif', ['--run', files.exported]], ['from-gate.sarif', ['--gate', files.gate]]]) {
    const target = join(out, name), result = await call(['annotate', '--sarif', files.sarif, '--out', target, '--k', '1', ...source]);
    assert.deepEqual([result.code, result.json.ok, result.json.runId, result.json.k], [0, true, run.id, 1]);
    assert.equal(await readFile(target, 'utf8'), expected);
    assert.equal((await stat(target)).mode & 0o777, 0o600);
    assert.equal(result.json.sha256, sha256(Buffer.from(expected)));
    assert.equal(result.text.includes(dir), false, 'no local path in the output');
  }
  const published = ['from-gate.sarif', 'from-run.sarif'];
  assert.deepEqual((await readdir(out)).sort(), published, 'only the published files after success');
  const failsWith = async (argv, code) => { const result = await call(argv); assert.deepEqual([result.code, result.json], [2, { ok: false, error: code }], `${argv.join(' ')}`); seen.add(code); };
  const seen = new Set();
  const annotate = (target, ...rest) => ['annotate', '--sarif', files.sarif, '--out', target, '--k', '1', ...rest];
  await failsWith(annotate(join(out, 'from-run.sarif'), '--run', files.exported), 'pass-k-output-exists');
  assert.equal(await readFile(join(out, 'from-run.sarif'), 'utf8'), expected, 'an existing file is never overwritten');
  const open = join(dir, 'open'); await mkdir(open, { mode: 0o755 }); await chmod(open, 0o755);
  await failsWith(annotate(join(open, 'x.sarif'), '--run', files.exported), 'pass-k-output-directory-not-private');
  const linked = join(dir, 'linked'); await symlink(out, linked);
  await failsWith(annotate(join(linked, 'x.sarif'), '--run', files.exported), 'pass-k-output-directory-not-private');
  await failsWith(annotate(join(dir, 'missing', 'x.sarif'), '--run', files.exported), 'pass-k-output-directory-not-private');
  await failsWith(annotate(join(out, 'x'.repeat(300)), '--run', files.exported), 'pass-k-output-write-error');
  // An annotated log over 8 MiB is refused before anything is written.
  const padded = JSON.parse(serializeSarif(run)); padded.runs[0].properties.padding = new Array(800000).fill(0);
  await writeFile(join(dir, 'padded.sarif'), JSON.stringify(padded));
  assert.ok((await stat(join(dir, 'padded.sarif'))).size < 8 * 1024 * 1024);
  await failsWith(['annotate', '--sarif', join(dir, 'padded.sarif'), '--out', join(out, 'padded.sarif'), '--k', '1', '--run', files.exported], 'pass-k-output-too-large');
  await failsWith(annotate(join(out, 'k2.sarif'), '--gate', files.gate).map(arg => arg === '1' ? '2' : arg), 'pass-k-k-mismatch');
  await writeFile(join(dir, 'v1.json'), JSON.stringify({ schemaVersion: 1, current: { runId: run.id, passK: column } }));
  await failsWith(annotate(join(out, 'v1.sarif'), '--gate', join(dir, 'v1.json')), 'pass-k-invalid-gate');
  const edited = structuredClone(column); edited.checks[0].exact = edited.checks[0].exact === '1' ? '0' : '1';
  await writeFile(join(dir, 'edited-gate.json'), JSON.stringify({ schemaVersion: 2, current: { runId: run.id, passK: edited } }));
  await failsWith(annotate(join(out, 'edited.sarif'), '--gate', join(dir, 'edited-gate.json')), 'pass-k-invalid-gate');
  await writeFile(join(dir, 'other-gate.json'), JSON.stringify({ schemaVersion: 2, current: { runId: randomUUID(), passK: column } }));
  await failsWith(annotate(join(out, 'other.sarif'), '--gate', join(dir, 'other-gate.json')), 'pass-k-invalid-gate');
  await failsWith(annotate(join(out, 'bad-gate.sarif'), '--gate', files.bad), 'pass-k-invalid-gate');
  await failsWith(['column', '--run', files.tampered, '--k', '1'], 'pass-k-invalid-run');
  await writeFile(join(dir, 'bare.json'), JSON.stringify(run));
  await failsWith(['column', '--run', join(dir, 'bare.json'), '--k', '1'], 'pass-k-invalid-run');
  const exported = JSON.parse(await readFile(files.exported, 'utf8')); exported.results[0].status = exported.results[0].status === 'pass' ? 'fail' : 'pass';
  await writeFile(join(dir, 'edited-export.json'), JSON.stringify(exported));
  await failsWith(['column', '--run', join(dir, 'edited-export.json'), '--k', '1'], 'pass-k-invalid-run');
  const withNotes = JSON.parse(await readFile(files.exported, 'utf8')); withNotes.notes = { [run.results[0].id]: { note: LEAK_MARKER } };
  await writeFile(join(dir, 'notes-export.json'), JSON.stringify(withNotes));
  const notesOut = await call(['column', '--run', join(dir, 'notes-export.json'), '--k', '1']);
  assert.deepEqual([notesOut.code, notesOut.text.includes(LEAK_MARKER)], [0, false], 'editable notes are outside the integrity hash and never printed');
  await failsWith(['column', '--run', files.bad, '--k', '1'], 'pass-k-invalid-run');
  await failsWith(['annotate', '--sarif', files.bad, '--out', join(out, 'bad.sarif'), '--k', '1', '--run', files.exported], 'pass-k-invalid-sarif');
  const sarifLink = join(dir, 'sarif-link.json'); await symlink(files.sarif, sarifLink);
  await failsWith(annotate(join(out, 'link.sarif'), '--run', files.exported).map(arg => arg === files.sarif ? sarifLink : arg), 'pass-k-input-unreadable');
  await failsWith(['column', '--run', join(dir, 'absent.json'), '--k', '1'], 'pass-k-input-unreadable');
  await failsWith(['column', '--run', dir, '--k', '1'], 'pass-k-input-unreadable');
  await writeFile(join(dir, 'huge.json'), `"${'a'.repeat(8 * 1024 * 1024)}"`);
  await failsWith(['column', '--run', join(dir, 'huge.json'), '--k', '1'], 'pass-k-input-unreadable');
  const other = { ...run, id: randomUUID() };
  await writeFile(join(dir, 'other-run.json'), JSON.stringify({ core: other, sha256: digest(other) }));
  await failsWith(annotate(join(out, 'mismatch.sarif'), '--run', join(dir, 'other-run.json')), 'pass-k-run-mismatch');
  for (const argv of [[], ['annotate'], ['export', '--run', files.record, '--k', '1'], ['column', '--run', files.record], ['column', '--run', 'relative.json', '--k', '1'],
    ['column', '--run', files.record, '--k', '1', '--k', '1'], ['column', '--run', files.record, '--k'], ['column', '--run', '--k', '1'],
    ['annotate', '--sarif', files.sarif, '--out', join(out, 'both.sarif'), '--k', '1', '--gate', files.gate, '--run', files.exported], ['annotate', '--sarif', files.sarif, '--out', join(out, 'none.sarif'), '--k', '1'],
    ['column', '--run', files.record, '--k', '1', '--out', join(out, 'x')]]) await failsWith(argv, 'pass-k-invalid-options');
  for (const k of ['0', '101', '5.0', '-1', 'x', '01']) await failsWith(['column', '--run', files.record, '--k', k], 'pass-k-invalid-k');
  // The bound is the CLI's own: with a gate column it is checked before the k comparison.
  await failsWith(annotate(join(out, 'k101.sarif'), '--gate', files.gate).map(arg => arg === '1' ? '101' : arg), 'pass-k-invalid-k');
  assert.deepEqual([...seen].filter(code => !CLI_ERRORS.includes(code.slice('pass-k-'.length))).sort(), ['pass-k-invalid-k', 'pass-k-run-mismatch']);
  assert.deepEqual(CLI_ERRORS.filter(code => !seen.has(`pass-k-${code}`)), [], 'every CLI code is reachable');
  assert.deepEqual((await readdir(out)).sort(), published, 'only the published files after every failure: no temporary file is left');
});

test('CLI child processes: a FIFO input is refused at once; a write failure is output-write-error', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-pass-k-child-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const out = join(dir, 'out'); await mkdir(out, { mode: 0o700 });
  const run = await syntheticRun(), exported = join(dir, 'run.json'), sarif = join(dir, 'scopehaven.sarif');
  await writeFile(exported, JSON.stringify({ ...run, integrity: { algorithm: 'SHA-256', sha256: digest(run), scope: 'run core only; editable notes excluded' }, notes: {} }));
  await writeFile(sarif, serializeSarif(run));
  // Only the node binary path and arguments are passed: no environment variable reaches the child.
  const child = (command, args) => spawnSync(command, args, { encoding: 'utf8', env: {}, timeout: 20000 });
  await t.test('FIFO', async s => {
    const fifo = join(dir, 'input.fifo');
    if (spawnSync('mkfifo', [fifo]).status !== 0) { s.skip('mkfifo is unavailable'); return; }
    const result = child(process.execPath, [CLI_PATH, 'column', '--run', fifo, '--k', '1']);
    assert.deepEqual([result.status, result.signal, result.stdout], [2, null, '{"ok":false,"error":"pass-k-input-unreadable"}\n'], 'refused at once, never waiting for a writer');
  });
  await t.test('file size limit', async s => {
    if (!existsSync('/bin/bash')) { s.skip('/bin/bash is unavailable'); return; }
    // ulimit -f 2 caps written files at a few KiB; SIGXFSZ is ignored, so the write fails with EFBIG.
    const result = child('/bin/bash', ['-c', 'trap "" XFSZ; ulimit -f 2; exec "$0" "$@"', process.execPath, CLI_PATH, 'annotate', '--sarif', sarif, '--out', join(out, 'limited.sarif'), '--k', '1', '--run', exported]);
    assert.deepEqual([result.status, result.stdout], [2, '{"ok":false,"error":"pass-k-output-write-error"}\n']);
    assert.deepEqual(await readdir(out), [], 'nothing published and no temporary file left');
  });
});
