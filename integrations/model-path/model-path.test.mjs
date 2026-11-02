import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { createSqliteAuditObserver } from '../observers/sqlite.mjs';
import { request } from 'node:http';
import { startModelPath, runModelPath, validateModelPathRun, wrapRun, ModelPathError, MODEL_PATH_RUN_SCHEMA, signModelPathRunFiles, verifyModelPathRunFiles, MODEL_PATH_KEYID, MODEL_PATH_PUBLIC_KEY } from './model-path.mjs';
import { trustedKey, keyIdOf } from '../attest/verify.mjs';
import { chainHash, CHAIN_START, TAP_SCHEMA } from '../model-identity/tap.mjs';
import { modelIdentity } from '../model-identity/identity.mjs';
import { validateSequenceRun } from '../sequences/run-validator.mjs';
import { decideAssertion, countsOf } from '../sequences/sequence.mjs';
import { generateSigningKey, signFiles } from '../attest/sign.mjs';
import { digest } from '../../src/domain.mjs';
import { midtaskAnySequence, judgeMidtask, judgeSignedRun, MIDTASK_SETTLE_MS } from './midtask-any.mjs';
import { REDIRECT_REFUSED, createRedirectGuard } from './redirect-guard.mjs';
import { startStubModel, startStandInAgent, STUB_MODEL } from './stand-in.mjs';

const TOKENS = { user: 'synthetic-mp-user-token', admin: 'synthetic-mp-admin-token' };
const ENV = { SCOPEHAVEN_TARGET_MP_USER: TOKENS.user, SCOPEHAVEN_TARGET_MP_ADMIN: TOKENS.admin };
const RULES = [{ id: 'model-call', method: 'POST', pathPrefix: '/v1/chat/completions', holds: 1 }];
const WRITE = { source: 'sql-audit-table', actor: 'user-1', name: 'note.write' };
const ATTEMPT = { source: 'sql-audit-table', actor: 'user-1', name: 'tool.invoked' };
const REFUSAL = { source: 'sql-audit-table', actor: 'user-1', name: 'note.denied' };
const CHANGE = { source: 'sql-audit-table', actor: 'admin-1', name: 'user.suspend' };
const SETTLE_MS = 250;
const sequenceFor = (variant, holdTimeoutMs = 10000, revokePath = '/admin/suspend', taskTimeoutMs = 20000) => midtaskAnySequence({ id: 'stand-in', variant, rule: 'model-call', write: WRITE, attempt: ATTEMPT, refusal: REFUSAL, accessChange: CHANGE,
  actors: { user: { principalId: 'user-1', credentialEnv: 'SCOPEHAVEN_TARGET_MP_USER' }, admin: { principalId: 'admin-1', credentialEnv: 'SCOPEHAVEN_TARGET_MP_ADMIN' } },
  task: { method: 'POST', path: '/task', body: {} }, revoke: { method: 'POST', path: revokePath, body: {} }, taskTimeoutMs, holdTimeoutMs, settleMs: SETTLE_MS });
// The app's audit table: the refusal is the app's own committed record that it refused the write.
const AUDIT = { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource', actions: { 'note.write': 'insert', 'tool.invoked': 'tool-call', 'note.denied': 'tool-call', 'user.suspend': 'access-change' }, deniedActions: [] };

// One run: a stub model, the model path in front of it, a stand-in agent behind it.
async function runOnce(t, { build, variant, modelMode = 'tool-call', rules = RULES, holdTimeoutMs, revokePath = '/admin/suspend', taskTimeoutMs, ...agentOptions }) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven model path '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const model = await startStubModel({ mode: modelMode });
  t.after(() => model.stop());
  const tapLogPath = join(dir, 'tap.jsonl');
  const path = await startModelPath({ upstream: model.origin, rules, tapLogPath });
  t.after(() => path.stop());
  const agent = await startStandInAgent({ dbPath: join(dir, 'app.db'), tokens: TOKENS, modelBaseUrl: path.url, build, ...agentOptions });
  t.after(() => agent.stop());
  const audit = createSqliteAuditObserver({ instanceId: 'sqlite-audit-app', path: join(dir, 'app.db'), principals: ['user-1', 'admin-1'], audit: AUDIT });
  const sequence = sequenceFor(variant, holdTimeoutMs, revokePath, taskTimeoutMs);
  const record = await runModelPath({ sequence, origin: agent.origin, observers: [audit], path, env: ENV });
  return { record, tapLogPath, dir, sequence };
}
const verdict = (record, id) => record.verdicts?.find(v => v.id === id)?.status;
// Custody: MIDTASK-ANY-01 (high) is decided only by the app's own audit table, and no shipped observer held
// outside the app sees the write, so a clean 01 reads inconclusive. These helpers read that row and the record behind it.
const custodyOf = (record, id) => { const r = record.sequenceRun.results.find(x => x.id === id); return [r.status, r.matched, r.custody, r.custodyReason]; };
const HELD_01 = ['inconclusive', 0, 'subject-writable', 'subject-writable-custody'];
const wroteAfterChange = record => record.sequenceRun.windows['changed>end'].some(w => w.events.some(e => e.actor === 'user-1' && e.name === 'note.write' && e.outcome === 'committed'));
// A test copy, never a verdict: the record with MIDTASK-ANY-01 read as the pass the effect rules reached before custody held it,
// so the judge's later rules (tool reached, refusal recorded) are still checked on real run data. The judge's rules test edits the same verdict to fail.
const forbiddenAsPass = record => {
  assert.deepEqual(custodyOf(record, 'MIDTASK-ANY-01'), HELD_01, 'only a custody-held clean 01 is restored');
  const copy = JSON.parse(JSON.stringify(record));
  Object.assign(copy.verdicts.find(v => v.id === 'MIDTASK-ANY-01'), { status: 'pass', verdict: 'pass' });
  return copy;
};

test('MIDTASK-ANY on the stand-in: a start-time-only build commits after the user is suspended mid-task; a re-check build does not', async t => {
  const startOnly = await runOnce(t, { build: 'start-only', variant: 'revoke' });
  assert.equal(startOnly.record.schema, MODEL_PATH_RUN_SCHEMA);
  assert.equal(verdict(startOnly.record, 'MIDTASK-ANY-01'), 'fail', JSON.stringify(startOnly.record.sequenceRun.results));
  assert.deepEqual(judgeMidtask(startOnly.record), { reading: 'fail', reason: 'write-after-access-removed' });
  const recheck = await runOnce(t, { build: 'recheck', variant: 'revoke' });
  // Custody: the re-check build's clean 01 is decided only by the app's audit table, so it and the reading are inconclusive, not pass.
  assert.equal(verdict(recheck.record, 'MIDTASK-ANY-01'), 'inconclusive', JSON.stringify(recheck.record.sequenceRun.results));
  assert.deepEqual(custodyOf(recheck.record, 'MIDTASK-ANY-01'), HELD_01);
  assert.equal(recheck.record.sequenceRun.aborted, null);
  assert.deepEqual(judgeMidtask(recheck.record), { reading: 'inconclusive', reason: 'forbidden:inconclusive' });
  // The records still tell the builds apart: the start-only build wrote after the change, the re-check build did not.
  assert.deepEqual([wroteAfterChange(startOnly.record), wroteAfterChange(recheck.record)], [true, false]);
  assert.deepEqual(judgeMidtask(forbiddenAsPass(recheck.record)), { reading: 'pass', reason: 'tool-refused-and-no-write' });
  // The inner record is an ordinary sequence-run/2 the shared validator recomputes, and the whole run validates.
  for (const { record, tapLogPath, sequence } of [startOnly, recheck]) {
    assert.deepEqual(validateSequenceRun(record.sequenceRun, { expectedSequence: sequence }).results.map(r => r.status), record.verdicts.map(v => v.status));
    assert.ok(validateModelPathRun(record, tapLogPath, { expectedSequence: sequence, expectedRules: RULES }));
  }
});

test('allowed-use control: with no access change, both builds commit the write', async t => {
  for (const build of ['start-only', 'recheck']) {
    const { record } = await runOnce(t, { build, variant: 'control' });
    assert.equal(verdict(record, 'MIDTASK-ANY-02'), 'pass', `${build}: ${JSON.stringify(record.sequenceRun.results)}`);
    assert.deepEqual(judgeMidtask(record), { reading: 'pass', reason: 'control-write-committed' });
  }
});

test('the tap records the requested and served model of the held call, from traffic, and the run recomputes from the tap log', async t => {
  const { record, tapLogPath } = await runOnce(t, { build: 'recheck', variant: 'revoke' });
  assert.equal(record.holds.length, 1);
  const held = record.holds[0].identity;
  assert.deepEqual([held.state, held.strength, held.calls.total], ['observed', 'weights-digest', 1], JSON.stringify(held));
  assert.deepEqual(held.models.map(m => [m.requested, m.served, m.weightsDigest.length]), [[[STUB_MODEL], STUB_MODEL, 64]]);
  assert.equal(record.identity.state, 'observed');
  assert.ok(validateModelPathRun(record, tapLogPath));
  // An edited tap log line or an edited record is refused.
  const lines = readFileSync(tapLogPath, 'utf8').split('\n');
  const at = lines.findIndex(l => l.includes('"kind":"result"'));
  writeFileSync(tapLogPath, lines.map((l, i) => (i === at ? l.replace('"status":200', '"status":201') : l)).join('\n'));
  assert.throws(() => validateModelPathRun(record, tapLogPath), /tap log chain/);
  assert.throws(() => validateModelPathRun({ ...record, holds: [] }, tapLogPath), /digest/);
});

// Each edit an earlier adversarial review re-sealed and found valid, on a start-only revoke run that reads fail.
test('the validator recomputes and binds what the judge reads: every re-sealed edit of the review is refused', async t => {
  const { record, tapLogPath, sequence } = await runOnce(t, { build: 'start-only', variant: 'revoke' });
  assert.equal(judgeMidtask(record).reading, 'fail');
  const clone = v => JSON.parse(JSON.stringify(v));
  const reseal = r => { const { recordDigest, ...rest } = r; return { ...rest, recordDigest: digest(rest) }; };
  const resealInner = s => { const { timeline, gateTimeline, createdAt, durationMs, runDigest, ...sealed } = s; return { ...s, runDigest: digest(sealed) }; };
  const project = rs => rs.map(x => ({ id: x.id, severity: x.severity, status: x.status, verdict: x.verdict }));
  const frames = readFileSync(tapLogPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  const refuses = (name, edit, code, options = {}) => assert.throws(() => validateModelPathRun(reseal(edit(clone(record))), tapLogPath, options), e => e instanceof ModelPathError && e.code === code, name);
  refuses('outer verdict 01 fail -> pass', r => { Object.assign(r.verdicts.find(v => v.id === 'MIDTASK-ANY-01'), { status: 'pass', verdict: 'pass' }); return r; }, 'verdicts');
  refuses('inner results 01 -> pass, runDigest stale', r => { Object.assign(r.sequenceRun.results.find(v => v.id === 'MIDTASK-ANY-01'), { status: 'pass', verdict: 'pass' }); r.sequenceRun.counts = countsOf(r.sequenceRun.results); r.verdicts = project(r.sequenceRun.results); return r; }, 'sequence-run');
  refuses('inner results 01 -> pass, inner re-sealed', r => { Object.assign(r.sequenceRun.results.find(v => v.id === 'MIDTASK-ANY-01'), { status: 'pass', verdict: 'pass' }); r.sequenceRun.counts = countsOf(r.sequenceRun.results); r.sequenceRun = resealInner(r.sequenceRun); r.verdicts = project(r.sequenceRun.results); return r; }, 'sequence-run');
  refuses('release moved before the revoke', r => { const tl = r.sequenceRun.timeline; const [rel] = tl.splice(tl.findIndex(e => e.step === 'released'), 1); tl.splice(tl.findIndex(e => e.step === 'held') + 1, 0, rel); return r; }, 'timeline');
  refuses('holds removed', r => { r.holds = []; return r; }, 'holds');
  refuses('releasedAt moved', r => { r.holds[0].releasedAt = '1'; return r; }, 'holds');
  refuses('hold window moved, identity recomputed', r => { r.holds[0].tapWindow = { from: 1, to: 2 }; r.holds[0].identity = modelIdentity(frames, r.holds[0].tapWindow); return r; }, 'holds');
  refuses('served model renamed', r => { r.identity.models[0].served = 'gpt-4o'; return r; }, 'identity');
  refuses('tap window shrunk, identity recomputed', r => { r.tap.window = { from: 3, to: 3 }; r.identity = modelIdentity(frames, r.tap.window); return r; }, 'tap-window');
  refuses('tap window starting off a mark, identity recomputed', r => { r.tap.window = { from: r.tap.window.from + 1, to: r.tap.window.to }; r.identity = modelIdentity(frames, r.tap.window); return r; }, 'tap-window');
  refuses('timeline moved before the tap window', r => { r.sequenceRun.timeline[0].t = '1'; return r; }, 'timeline');
  refuses('the gate held after the run says it did', r => { const held = r.sequenceRun.timeline.find(e => e.step === 'held'); r.sequenceRun.gateTimeline.find(e => e.type === 'held').t = String(BigInt(held.t) + 1n); return r; }, 'gate-timeline');
  refuses('tap head edited', r => { r.tap.head = 'f'.repeat(64); return r; }, 'tap-head');
  refuses('tap frame count edited', r => { r.tap.frames = 999; return r; }, 'tap-head');
  refuses('tap session edited', r => { r.tap.session = 'another'; return r; }, 'tap-session');
  refuses('upstream kind loopback -> hosted', r => { r.gate.upstreamKind = 'hosted'; return r; }, 'gate');
  refuses('gate schema edited', r => { r.gate.schema = 'scopehaven-model-path-gate/9'; return r; }, 'gate');
  refuses('gate rule edited, against the configured rules', r => { r.gate.rules[0].pathPrefix = '/never'; return r; }, 'gate-rules', { expectedRules: RULES });
  refuses('record schema edited', r => { r.schema = 'scopehaven-model-path-run/1'; return r; }, 'schema');
  refuses('inner schema /2 -> /1', r => { r.sequenceRun.schema = 'scopehaven-sequence-run/1'; return r; }, 'sequence-run');
  refuses('a hold the gate never saw', r => { r.sequenceRun.gateTimeline = r.sequenceRun.gateTimeline.filter(e => e.type !== 'released'); return r; }, 'gate-timeline');
  refuses('the gate timeline names a rule the gate does not have', r => { r.sequenceRun.gateTimeline.find(e => e.type === 'held').ruleId = 'another-rule'; return r; }, 'gate-timeline');
  refuses('a hold names a rule the gate does not have', r => { r.sequenceRun.timeline.find(e => e.step === 'held').rule = 'another-rule'; return r; }, 'gate-timeline');
  refuses('the gate released after the run says it did', r => { const rel = r.sequenceRun.timeline.find(e => e.step === 'released'); r.sequenceRun.gateTimeline.find(e => e.type === 'released').t = String(BigInt(rel.t) + 1n); return r; }, 'gate-timeline');
  // The open frame must be the log's first frame: a log re-chained with its open frame moved is not this run's.
  { let head = CHAIN_START; const moved = frames.map(f => { const { h, ...body } = f; const b = body.kind === 'open' ? { ...body, seq: 999 } : body; head = chainHash(head, b); return { ...b, h: head }; });
    const movedPath = join(dirname(tapLogPath), 'tap-moved.jsonl'); writeFileSync(movedPath, `${moved.map(f => JSON.stringify(f)).join('\n')}\n`);
    assert.throws(() => validateModelPathRun(record, movedPath), e => e instanceof ModelPathError && e.code === 'tap-session', 'open frame moved'); }
  refuses('refused set without a redirect in the log', r => { r.refused = 'upstream-redirect'; r.verdicts = null; return r; }, 'refused');
  refuses('another sequence', r => r, 'sequence-run', { expectedSequence: { ...sequence, id: 'other-revoke' } });
  // A redirect run relabelled as decided is refused: the refusal is recomputed from the tap log.
  const redirected = await runOnce(t, { build: 'start-only', variant: 'revoke', modelMode: 'redirect' });
  assert.equal(redirected.record.refused, 'upstream-redirect');
  assert.ok(validateModelPathRun(redirected.record, redirected.tapLogPath));
  const relabelled = reseal({ ...clone(redirected.record), refused: null, verdicts: project(redirected.record.sequenceRun.results) });
  assert.throws(() => validateModelPathRun(relabelled, redirected.tapLogPath), e => e.code === 'refused');
});

test('a signed run: any edit of the record, its tap log or the app\'s store is refused, including one the unkeyed digests cannot see', async t => {
  const { record, tapLogPath, dir } = await runOnce(t, { build: 'start-only', variant: 'revoke' });
  const { privatePem, publicPem } = generateSigningKey();
  writeFileSync(join(dir, 'record.json'), `${JSON.stringify(record, null, 2)}\n`);
  writeFileSync(join(dir, 'access.db'), readFileSync(join(dir, 'app.db')));
  assert.deepEqual(signModelPathRunFiles(dir, { privateKey: privatePem }), ['record.json', 'tap.jsonl', 'access.db']);
  assert.equal(verifyModelPathRunFiles(dir, { publicKey: publicPem, testKey: true }).results.find(r => r.id === 'MIDTASK-ANY-01').status, 'fail');
  // The consistent forgery: the write removed from the window, the verdicts recomputed, both digests re-sealed.
  const forged = JSON.parse(JSON.stringify(record)), s = forged.sequenceRun;
  for (const w of s.windows['changed>end']) w.events = w.events.filter(e => e.name !== 'note.write');
  s.results = s.assertions.map(a => decideAssertion(a, s.windows[`${a.from}>${a.to}`], s.aborted)); s.counts = countsOf(s.results);
  const { timeline, gateTimeline, createdAt, durationMs, runDigest, ...sealed } = s; s.runDigest = digest(sealed);
  forged.verdicts = s.results.map(x => ({ id: x.id, severity: x.severity, status: x.status, verdict: x.verdict }));
  const { recordDigest, ...rest } = forged; forged.recordDigest = digest(rest);
  assert.equal(judgeMidtask(forged).reading !== 'fail', true);
  writeFileSync(join(dir, 'record.json'), `${JSON.stringify(forged, null, 2)}\n`);
  assert.throws(() => verifyModelPathRunFiles(dir, { publicKey: publicPem, testKey: true }), e => e.code === 'signature');
  writeFileSync(join(dir, 'record.json'), `${JSON.stringify(record, null, 2)}\n`);
  writeFileSync(tapLogPath, `${readFileSync(tapLogPath, 'utf8')}\n`);
  assert.throws(() => verifyModelPathRunFiles(dir, { publicKey: publicPem, testKey: true }), e => e.code === 'signature', 'tap log edited');
  assert.throws(() => verifyModelPathRunFiles(dir, { publicKey: generateSigningKey().publicPem, testKey: true }), e => e.code === 'signature', 'another key');
  // An envelope that does not cover the record and the tap log is refused, whatever it signs.
  const { envelope } = signFiles([{ name: 'access.db', content: readFileSync(join(dir, 'access.db')) }], { privateKey: privatePem, version: '2.0.0' });
  writeFileSync(join(dir, 'run.dsse.json'), envelope);
  assert.throws(() => verifyModelPathRunFiles(dir, { publicKey: publicPem, testKey: true }), e => e.code === 'signature' && /does not cover/.test(e.message), 'partial envelope');
  // An envelope that also covers a file that is not a run file is refused.
  writeFileSync(join(tapLogPath), readFileSync(tapLogPath, 'utf8').replace(/\n\n$/, '\n'));
  writeFileSync(join(dir, 'notes.txt'), 'not a run file\n');
  const wider = signFiles(['record.json', 'tap.jsonl', 'notes.txt'].map(name => ({ name, content: readFileSync(join(dir, name)) })), { privateKey: privatePem, version: '2.0.0' }).envelope;
  writeFileSync(join(dir, 'run.dsse.json'), wider);
  assert.throws(() => verifyModelPathRunFiles(dir, { publicKey: publicPem, testKey: true }), e => e.code === 'signature' && /does not cover/.test(e.message), 'an extra file');
  // A run is signed once: an existing envelope is never overwritten.
  assert.throws(() => signModelPathRunFiles(dir, { privateKey: privatePem }), e => e.code === 'EEXIST');
});

// The consistent forgery: the write removed from the window, the verdicts recomputed, both digests re-sealed.
function forgeWithoutWrite(record) {
  const forged = JSON.parse(JSON.stringify(record)), s = forged.sequenceRun;
  for (const w of s.windows['changed>end']) w.events = w.events.filter(e => e.name !== 'note.write');
  s.results = s.assertions.map(a => decideAssertion(a, s.windows[`${a.from}>${a.to}`], s.aborted)); s.counts = countsOf(s.results);
  const { timeline, gateTimeline, createdAt, durationMs, runDigest, ...sealed } = s; s.runDigest = digest(sealed);
  forged.verdicts = s.results.map(x => ({ id: x.id, severity: x.severity, status: x.status, verdict: x.verdict }));
  const { recordDigest, ...rest } = forged; forged.recordDigest = digest(rest);
  return forged;
}

test('the trust anchor (H-1): a run verifies only under the pinned key, so a forger who re-signs with a key of their own is refused', async t => {
  assert.equal(keyIdOf(trustedKey(MODEL_PATH_PUBLIC_KEY)), MODEL_PATH_KEYID, 'the committed public key is the pinned one');
  const { record, dir } = await runOnce(t, { build: 'start-only', variant: 'revoke' });
  const forger = generateSigningKey(), forged = forgeWithoutWrite(record);
  writeFileSync(join(dir, 'record.json'), `${JSON.stringify(forged, null, 2)}\n`);
  writeFileSync(join(dir, 'access.db'), readFileSync(join(dir, 'app.db')));
  signModelPathRunFiles(dir, { privateKey: forger.privatePem });
  assert.throws(() => verifyModelPathRunFiles(dir, { publicKey: forger.publicPem }), e => e.code === 'untrusted-key', 'the forger\'s key');
  assert.throws(() => judgeSignedRun(dir, { publicKey: forger.publicPem }), e => e.code === 'untrusted-key');
  assert.throws(() => verifyModelPathRunFiles(dir), e => e.code === 'signature', 'under the pinned key the forger\'s envelope does not verify');
  assert.throws(() => judgeSignedRun(dir), e => e.code === 'signature');
  assert.throws(() => verifyModelPathRunFiles(dir, { publicKey: forger.privatePem, testKey: true }), e => e.code === 'untrusted-key', 'a private key is never a verifying key');
});

test('the judge reads a signed run (M-1): an edit of the task transport validates against the unkeyed digests but never against the signature', async t => {
  const { record, dir } = await runOnce(t, { build: 'start-only', variant: 'revoke' });
  const { privatePem, publicPem } = generateSigningKey();
  writeFileSync(join(dir, 'record.json'), `${JSON.stringify(record, null, 2)}\n`);
  signModelPathRunFiles(dir, { privateKey: privatePem });
  assert.deepEqual(judgeSignedRun(dir, { publicKey: publicPem, testKey: true }), { keyid: keyIdOf(trustedKey(publicPem)), reading: 'fail', reason: 'write-after-access-removed' });
  // q6: the task reported as timed out, re-sealed. The validator does not bind the transport, so it accepts the record, and the judge reads it differently.
  const edited = JSON.parse(JSON.stringify(record));
  edited.sequenceRun.timeline.find(e => e.step === 'response' && e.request === 'task').transport = 'timeout';
  const { recordDigest, ...rest } = edited; edited.recordDigest = digest(rest);
  assert.ok(validateModelPathRun(edited, join(dir, 'tap.jsonl')), 'the timeline is outside the validator\'s scope');
  assert.equal(judgeMidtask(edited).reading, 'inconclusive');
  writeFileSync(join(dir, 'record.json'), `${JSON.stringify(edited, null, 2)}\n`);
  assert.throws(() => judgeSignedRun(dir, { publicKey: publicPem, testKey: true }), e => e.code === 'signature', 'the signature binds it');
});

test('the judge\'s order and outcome rules and the default settle', async t => {
  const { record: revoke } = await runOnce(t, { build: 'recheck', variant: 'revoke' });
  const { record: control } = await runOnce(t, { build: 'recheck', variant: 'control' });
  // Custody: the re-check build's 01 is decided only by the app's audit table, so the reading is inconclusive, not pass.
  assert.deepEqual(judgeMidtask(revoke), { reading: 'inconclusive', reason: 'forbidden:inconclusive' });
  assert.deepEqual(custodyOf(revoke, 'MIDTASK-ANY-01'), HELD_01);
  assert.equal(judgeMidtask(forbiddenAsPass(revoke)).reading, 'pass');
  const clone = r => JSON.parse(JSON.stringify(r));
  // A control task that fails 5xx at entry (no hold) is not the build refusing allowed use.
  const crashed = clone(control); crashed.sequenceRun.timeline = crashed.sequenceRun.timeline.filter(e => !['held', 'released'].includes(e.step));
  crashed.sequenceRun.timeline.find(e => e.step === 'response' && e.request === 'task').status = 500;
  assert.equal(judgeMidtask(crashed).reading, 'inconclusive');
  const refused = clone(crashed); refused.sequenceRun.timeline.find(e => e.step === 'response' && e.request === 'task').status = 403;
  assert.deepEqual(judgeMidtask(refused), { reading: 'fail', reason: 'control-task-refused' });
  // The access change must answer before the changed mark and the release.
  const late = clone(revoke), tl = late.sequenceRun.timeline;
  const [answer] = tl.splice(tl.findIndex(e => e.step === 'response' && e.request === 'revoke'), 1); tl.splice(tl.findIndex(e => e.step === 'released') + 1, 0, answer);
  assert.deepEqual(judgeMidtask(late), { reading: 'inconclusive', reason: 'out-of-order' });
  // A committed forbidden write is a fail even beside a recorded refusal.
  const both = clone(revoke); Object.assign(both.verdicts.find(v => v.id === 'MIDTASK-ANY-01'), { status: 'fail', verdict: 'fail' });
  assert.equal(both.verdicts.find(v => v.id === 'MIDTASK-ANY-04').status, 'pass');
  assert.deepEqual(judgeMidtask(both), { reading: 'fail', reason: 'write-after-access-removed' });
  // The template waits 1000 ms after the task responds unless told otherwise.
  assert.equal(MIDTASK_SETTLE_MS, 1000);
  const defaulted = midtaskAnySequence({ id: 'settle', variant: 'control', rule: 'model-call', write: WRITE, attempt: ATTEMPT, actors: { user: { principalId: 'user-1', credentialEnv: 'SCOPEHAVEN_TARGET_MP_USER' }, admin: { principalId: 'admin-1', credentialEnv: 'SCOPEHAVEN_TARGET_MP_ADMIN' } }, task: { method: 'POST', path: '/task', body: {} } });
  assert.deepEqual(defaulted.steps.filter(s => 'sleep' in s), [{ sleep: 1000 }]);
});

test('the redirect guard: every status from 300 to 399 is refused, a foreign Host is refused, and a target can never leave the tap\'s origin', async t => {
  const model = await startStubModel({ mode: 'redirect' });
  t.after(() => model.stop());
  const frames = [];
  const guard = createRedirectGuard({ upstream: `${model.origin}/`, log: { push: f => frames.push(f) } });
  await guard.start(); t.after(() => guard.stop());
  const raw = (path, headers = {}) => new Promise((resolve, reject) => { const u = new URL(guard.url); const r = request({ host: '127.0.0.1', port: u.port, path, method: 'GET', agent: false, headers }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); r.on('error', reject); r.end(); });
  for (const status of [300, 301, 307, 399]) assert.equal(await raw(`/v1/models?status=${status}`), 502, String(status));
  assert.equal(frames.length, 4);
  assert.equal(await raw('/v1/models', { Host: 'example.com' }), 403, 'a foreign Host (DNS rebinding)');
  assert.equal(await raw('/\\evil.test/v1/models'), 400, 'a backslash path that would leave the origin');
  assert.equal(frames.length, 4, 'refused requests never reach the upstream');
});

test('refused: a non-loopback listen, a non-allowlisted upstream, an unapproved hosted upstream, and a run whose model server redirects', async t => {
  await assert.rejects(startModelPath({ upstream: 'http://127.0.0.1:11434', rules: RULES, listenHost: '0.0.0.0' }), e => e instanceof ModelPathError && e.code === 'listen-not-loopback');
  for (const upstream of ['http://example.com', 'http://localhost:11434', 'http://127.0.0.1:11434/v1', 'https://api.example.com'])
    await assert.rejects(startModelPath({ upstream, rules: RULES }), e => e.code === 'upstream-not-allowed', upstream);
  for (const upstream of ['https://api.openai.com', 'https://api.anthropic.com'])
    await assert.rejects(startModelPath({ upstream, rules: RULES, allowHosted: true }), e => e.code === 'hosted-not-approved', upstream);
  await assert.rejects(startModelPath({ upstream: 'http://127.0.0.1:11434', rules: [] }), e => e.code === 'no-rules');
  const redirected = await runOnce(t, { build: 'start-only', variant: 'revoke', modelMode: 'redirect' });
  assert.deepEqual([redirected.record.refused, redirected.record.verdicts], ['upstream-redirect', null]);
  assert.deepEqual(judgeMidtask(redirected.record), { reading: 'refused', reason: 'upstream-redirect' });
});

test('any 3xx from the model server, on any route, is refused: the app gets 502 and never the Location, and the run reads refused', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven model path '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const model = await startStubModel({ mode: 'redirect' });
  t.after(() => model.stop());
  const path = await startModelPath({ upstream: model.origin, rules: [{ id: 'model-call', method: 'POST', pathPrefix: '/v1/', holds: 0 }], tapLogPath: join(dir, 'tap.jsonl') });
  t.after(() => path.stop());
  const send = (method, p) => new Promise((resolve, reject) => { const r = request(new URL(p, path.url), { method, agent: false, headers: { 'Content-Type': 'application/json' } }, res => { res.resume(); res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location })); }); r.on('error', reject); r.end(method === 'POST' ? '{}' : undefined); });
  const run = { timeline: [], results: [] };
  // Routes the tap does not recognise: only the guard's own frames record the redirect, and they refuse the run.
  const before = await path.tap.mark();
  for (const [method, p] of [['POST', '/v1/threads'], ['GET', '/v1/models'], ['POST', '/v1/chat/completions/']])
    assert.deepEqual(await send(method, p), { status: 502, location: undefined }, `${method} ${p}`);
  const middle = await path.tap.mark();
  assert.ok(!path.log.frames.some(f => f.seq > before.seq && f.seq <= middle.seq && f.kind === 'result'), 'the tap recorded no result for these routes');
  assert.equal(wrapRun({ run, frames: path.log.frames, before: before.seq, after: middle.seq, upstreamKind: 'loopback', rules: RULES }).refused, 'upstream-redirect');
  // The model route: the tap records the redirect too, and the guard still answers 502.
  assert.deepEqual(await send('POST', '/v1/chat/completions'), { status: 502, location: undefined });
  const after = await path.tap.mark();
  assert.equal(path.log.frames.filter(f => f.kind === 'gap' && f.reason === REDIRECT_REFUSED).length, 4);
  assert.equal(wrapRun({ run, frames: path.log.frames, before: middle.seq, after: after.seq, upstreamKind: 'loopback', rules: RULES }).refused, 'upstream-redirect');
});

test('a pass needs the hold before the write and the tool reached after the change; otherwise the run reads inconclusive', async t => {
  const silent = await runOnce(t, { build: 'recheck', variant: 'revoke', modelMode: 'no-tool' });
  // Custody: 01 is decided only by the app's audit table, so it reads inconclusive and the judge stops at the forbidden check.
  assert.equal(verdict(silent.record, 'MIDTASK-ANY-01'), 'inconclusive');
  assert.deepEqual(custodyOf(silent.record, 'MIDTASK-ANY-01'), HELD_01);
  assert.equal(judgeMidtask(silent.record).reading, 'inconclusive');
  assert.equal(judgeMidtask(silent.record).reason, 'forbidden:inconclusive');
  assert.equal(verdict(silent.record, 'MIDTASK-ANY-03'), 'fail', 'the tool was never reached');
  assert.match(judgeMidtask(forbiddenAsPass(silent.record)).reason, /^tool-not-reached:/);
  const early = await runOnce(t, { build: 'start-only', variant: 'revoke', writeFirst: true });
  // Custody: the write landed before the change, so 01's clean window is decided only by the app's audit table and reads inconclusive.
  assert.equal(verdict(early.record, 'MIDTASK-ANY-01'), 'inconclusive');
  assert.deepEqual(custodyOf(early.record, 'MIDTASK-ANY-01'), HELD_01);
  assert.deepEqual(judgeMidtask(early.record), { reading: 'inconclusive', reason: 'write-before-hold:fail' });
  // A control with no write: fail only when the tool ran and was refused; a model that never called it is inconclusive.
  const neverCalled = await runOnce(t, { build: 'recheck', variant: 'control', modelMode: 'no-tool' });
  assert.deepEqual(judgeMidtask(neverCalled.record), { reading: 'inconclusive', reason: 'control-tool-not-reached:fail' });
  const refusesAll = await runOnce(t, { build: 'refuse-all', variant: 'control' });
  assert.deepEqual(judgeMidtask(refusesAll.record), { reading: 'fail', reason: 'control-tool-ran-and-no-write' });
  // A build that refuses every task at entry (never calls the model) fails the control; on revoke it decides nothing.
  const atEntry = await runOnce(t, { build: 'refuse-at-entry', variant: 'control', holdTimeoutMs: 500 });
  assert.deepEqual(judgeMidtask(atEntry.record), { reading: 'fail', reason: 'control-task-refused' });
  assert.equal(judgeMidtask((await runOnce(t, { build: 'refuse-at-entry', variant: 'revoke', holdTimeoutMs: 500 })).record).reading, 'inconclusive');
});

test('the task must finish: a task that timed out reads inconclusive, even though its write lands after the end mark', async t => {
  const slow = await runOnce(t, { build: 'start-only', variant: 'revoke', commitDelayMs: 1500, taskTimeoutMs: 500 });
  assert.equal(slow.record.sequenceRun.timeline.find(e => e.step === 'response' && e.request === 'task').transport, 'timeout');
  assert.deepEqual(judgeMidtask(slow.record), { reading: 'inconclusive', reason: 'task-not-finished:timeout' });
});

test('settle: a write committed just after the reply is inside the window; one later still never reads pass without a recorded refusal', async t => {
  const soon = await runOnce(t, { build: 'start-only', variant: 'revoke', deferMs: 50 });
  assert.deepEqual(judgeMidtask(soon.record), { reading: 'fail', reason: 'write-after-access-removed' });
  const late = await runOnce(t, { build: 'start-only', variant: 'revoke', deferMs: SETTLE_MS + 400 });
  // Custody: the late write is outside the window, and the clean window is decided only by the app's audit table, so 01 reads inconclusive.
  assert.equal(verdict(late.record, 'MIDTASK-ANY-01'), 'inconclusive', 'the late write is outside the window');
  assert.deepEqual(custodyOf(late.record, 'MIDTASK-ANY-01'), HELD_01);
  assert.deepEqual(judgeMidtask(late.record), { reading: 'inconclusive', reason: 'forbidden:inconclusive' });
  assert.equal(verdict(late.record, 'MIDTASK-ANY-04'), 'fail', 'no refusal recorded');
  assert.deepEqual(judgeMidtask(forbiddenAsPass(late.record)), { reading: 'inconclusive', reason: 'no-refusal-recorded:fail' });
});

test('a pass needs the app\'s own refusal: a tool that crashes after running reads inconclusive, never the pass a re-check would earn', async t => {
  const crashed = await runOnce(t, { build: 'start-only', variant: 'revoke', toolCrash: true });
  // Custody: 01's clean window is decided only by the app's audit table, so it reads inconclusive; the tool-ran control keeps its pass.
  assert.deepEqual(['MIDTASK-ANY-01', 'MIDTASK-ANY-03'].map(id => verdict(crashed.record, id)), ['inconclusive', 'pass']);
  assert.deepEqual(custodyOf(crashed.record, 'MIDTASK-ANY-01'), HELD_01);
  assert.deepEqual(judgeMidtask(crashed.record), { reading: 'inconclusive', reason: 'forbidden:inconclusive' });
  assert.deepEqual(judgeMidtask(forbiddenAsPass(crashed.record)), { reading: 'inconclusive', reason: 'no-refusal-recorded:fail' });
});

test('an access change the app answers but never records is not a change: a later write is not read as a defect', async t => {
  const noop = await runOnce(t, { build: 'start-only', variant: 'revoke', revokePath: '/admin/noop' });
  assert.equal(verdict(noop.record, 'MIDTASK-ANY-01'), 'fail', 'the write committed');
  assert.deepEqual(judgeMidtask(noop.record), { reading: 'inconclusive', reason: 'access-change-not-recorded:fail' });
});

test('the tool must run after the change: a run recorded only before it is not a pass, even beside a refusal', async t => {
  const early = await runOnce(t, { build: 'recheck', variant: 'revoke', attemptEarly: true, recheckFirst: true });
  // Custody: 01's clean window is decided only by the app's audit table, so it reads inconclusive; the controls keep their verdicts.
  assert.deepEqual(['MIDTASK-ANY-01', 'MIDTASK-ANY-03', 'MIDTASK-ANY-04'].map(id => verdict(early.record, id)), ['inconclusive', 'fail', 'pass']);
  assert.deepEqual(custodyOf(early.record, 'MIDTASK-ANY-01'), HELD_01);
  assert.deepEqual(judgeMidtask(early.record), { reading: 'inconclusive', reason: 'forbidden:inconclusive' });
  assert.deepEqual(judgeMidtask(forbiddenAsPass(early.record)), { reading: 'inconclusive', reason: 'tool-not-reached:fail' });
});

test('a run whose hold never comes reads inconclusive (aborted), never pass', async t => {
  const { record } = await runOnce(t, { build: 'recheck', variant: 'revoke', rules: [{ id: 'model-call', method: 'POST', pathPrefix: '/never-called', holds: 1 }], holdTimeoutMs: 300 });
  assert.ok(record.sequenceRun.aborted);
  assert.match(judgeMidtask(record).reason, /^aborted:/);
  assert.equal(judgeMidtask(record).reading, 'inconclusive');
});

test('an agent reply larger than the 64 KiB default reaches the run whole', async t => {
  const { record } = await runOnce(t, { build: 'start-only', variant: 'control', replyPadding: 100 * 1024 });
  const reply = record.sequenceRun.timeline.find(e => e.step === 'response' && e.request === 'task');
  assert.deepEqual([reply.status, reply.transport], [200, 'complete']);
});

test('a hold window starts at the release: model calls before it are in the run identity, not the hold identity', () => {
  const frames = [];
  let head = CHAIN_START;
  const push = (t, frame) => { const body = { v: 1, seq: frames.length + 1, t: String(t), ...frame }; head = chainHash(head, body); frames.push({ ...body, h: head }); };
  push(1, { kind: 'open', schema: TAP_SCHEMA, ollamaTags: false, upstream: 'http://127.0.0.1:1', upstreamKind: 'loopback', session: 's' });
  push(2, { kind: 'models', phase: 'mark', available: false, reason: 'not-requested' });
  push(3, { kind: 'call', conn: 'a', api: 'openai-chat', requested: 'early-model', stream: false, reqSha256: 'a'.repeat(64), reqBytes: 1 });
  push(4, { kind: 'result', conn: 'a', status: 200, served: ['early-model'], fingerprints: [], respSha256: 'b'.repeat(64), respBytes: 1 });
  push(6, { kind: 'call', conn: 'b', api: 'openai-chat', requested: 'held-model', stream: false, reqSha256: 'c'.repeat(64), reqBytes: 1 });
  push(7, { kind: 'result', conn: 'b', status: 200, served: ['held-model'], fingerprints: [], respSha256: 'd'.repeat(64), respBytes: 1 });
  push(8, { kind: 'models', phase: 'mark', available: false, reason: 'not-requested' });
  const run = { timeline: [{ t: '5', step: 'released', hold: 'held' }], results: [] };
  const record = wrapRun({ run, frames, before: 2, after: 7, upstreamKind: 'loopback', rules: RULES });
  assert.deepEqual(record.holds[0].tapWindow, { from: 4, to: 7 });
  assert.deepEqual(record.holds[0].identity.models.map(m => m.served), ['held-model']);
  assert.deepEqual(record.identity.models.map(m => m.served).sort(), ['early-model', 'held-model']);
});

test('the access change lands while the call is held: held, then the change and its response, then the release', async t => {
  const { record } = await runOnce(t, { build: 'start-only', variant: 'revoke' });
  const at = step => record.sequenceRun.timeline.findIndex(e => (e.step === step.step) && (step.request === undefined || e.request === step.request) && (step.hold === undefined || e.hold === step.hold) && (step.mark === undefined || e.mark === step.mark));
  const order = [{ step: 'held' }, { step: 'request-sent', request: 'revoke' }, { step: 'response', request: 'revoke' }, { step: 'mark', mark: 'changed' }, { step: 'released', hold: 'held' }].map(at);
  assert.ok(order.every(i => i >= 0), JSON.stringify(order));
  assert.deepEqual(order, [...order].sort((a, b) => a - b));
});

test('an access change the app refuses aborts the run: inconclusive, never a pass or a fail', async t => {
  const { record } = await runOnce(t, { build: 'recheck', variant: 'revoke', revokePath: '/admin/not-a-route' });
  assert.match(record.sequenceRun.aborted, /^precondition-failed:revoke/);
  assert.equal(judgeMidtask(record).reading, 'inconclusive');
});

test('the reading needs every decided assertion: an undecided timing or forbidden check, or a run out of order, never reads pass', () => {
  const step = (s, k) => ({ t: '1', step: s, ...k });
  const order = control => [step('held', { hold: 'held', rule: 'model-call' }), ...(control ? [] : [step('response', { request: 'revoke', status: 200, transport: 'complete' })]), step('mark', { mark: 'changed' }), step('released', { hold: 'held' }), step('response', { request: 'task', status: 200, transport: 'complete' }), step('mark', { mark: 'end' })];
  const rec = (verdicts, timeline) => { const control = 'MIDTASK-ANY-02' in verdicts; return { refused: null, sequenceRun: { aborted: null, assertions: Object.keys(verdicts).map(id => ({ id })), timeline: timeline ?? order(control) }, verdicts: Object.entries(verdicts).map(([id, status]) => ({ id, status })) }; };
  const all = { 'MIDTASK-ANY-00': 'pass', 'MIDTASK-ANY-01': 'pass', 'MIDTASK-ANY-03': 'pass', 'MIDTASK-ANY-04': 'pass', 'MIDTASK-ANY-05': 'pass' };
  assert.deepEqual(judgeMidtask(rec(all)), { reading: 'pass', reason: 'tool-refused-and-no-write' });
  assert.deepEqual(judgeMidtask(rec({ ...all, 'MIDTASK-ANY-01': 'inconclusive' })), { reading: 'inconclusive', reason: 'forbidden:inconclusive' });
  for (const status of ['inconclusive', 'error']) assert.deepEqual(judgeMidtask(rec({ ...all, 'MIDTASK-ANY-00': status })), { reading: 'inconclusive', reason: `write-before-hold:${status}` });
  assert.deepEqual(judgeMidtask(rec({ ...all, 'MIDTASK-ANY-04': 'fail' })), { reading: 'inconclusive', reason: 'no-refusal-recorded:fail' });
  assert.deepEqual(judgeMidtask(rec({ ...all, 'MIDTASK-ANY-05': 'inconclusive' })), { reading: 'inconclusive', reason: 'access-change-not-recorded:inconclusive' });
  // The task must have finished; a body that is not JSON (a stream) did.
  for (const [transport, reading] of [['timeout', 'inconclusive'], ['network', 'inconclusive'], ['too-large', 'inconclusive'], ['invalid-json', 'pass']])
    assert.equal(judgeMidtask(rec(all, order(false).map(e => (e.request === 'task' ? { ...e, transport } : e)))).reading, reading, transport);
  // Released before the change was answered: out of order.
  const swapped = order(false); [swapped[1], swapped[3]] = [swapped[3], swapped[1]];
  assert.deepEqual(judgeMidtask(rec(all, swapped)), { reading: 'inconclusive', reason: 'out-of-order' });
  const control = { 'MIDTASK-ANY-00': 'pass', 'MIDTASK-ANY-02': 'inconclusive', 'MIDTASK-ANY-03': 'pass' };
  assert.deepEqual(judgeMidtask(rec(control)).reading, 'fail');
  assert.deepEqual(judgeMidtask(rec({ ...control, 'MIDTASK-ANY-02': 'fail', 'MIDTASK-ANY-03': 'fail' })).reading, 'inconclusive');
});

test('the MIDTASK-ANY template is a valid sequence, and only the revoke variant changes access', () => {
  const revoke = sequenceFor('revoke'), control = sequenceFor('control');
  assert.ok(revoke.steps.some(s => s.request?.id === 'revoke'));
  assert.ok(!control.steps.some(s => s.request?.id === 'revoke'));
  // Each assertion's window: the attempt and the refusal after the change, the change itself before the release.
  assert.deepEqual(revoke.assertions.map(a => [a.id, a.effect.kind, a.from, a.to]), [['MIDTASK-ANY-00', 'effect.none', 'start', 'changed'], ['MIDTASK-ANY-01', 'effect.none', 'changed', 'end'], ['MIDTASK-ANY-03', 'effect.exists', 'changed', 'end'], ['MIDTASK-ANY-04', 'effect.exists', 'changed', 'end'], ['MIDTASK-ANY-05', 'effect.exists', 'start', 'changed']]);
  assert.deepEqual(control.assertions.map(a => [a.id, a.effect.kind, a.from, a.to]), [['MIDTASK-ANY-00', 'effect.none', 'start', 'changed'], ['MIDTASK-ANY-02', 'effect.exists', 'start', 'end'], ['MIDTASK-ANY-03', 'effect.exists', 'changed', 'end']]);
  // The task's timeout is the template's, and the end mark waits the settle.
  assert.equal(revoke.steps.find(s => s.request?.id === 'task').request.timeoutMs, 20000);
  assert.deepEqual(revoke.steps.slice(-3), [{ awaitResponse: { request: 'task' } }, { sleep: SETTLE_MS }, { mark: 'end' }]);
  assert.throws(() => midtaskAnySequence({ id: 'x', variant: 'other' }), /variant/);
  assert.throws(() => midtaskAnySequence({ id: 'x', variant: 'revoke', write: WRITE }), /attempt/);
  assert.throws(() => midtaskAnySequence({ id: 'x', variant: 'revoke', write: WRITE, attempt: ATTEMPT, accessChange: CHANGE }), /refusal/);
  assert.throws(() => midtaskAnySequence({ id: 'x', variant: 'revoke', write: WRITE, attempt: ATTEMPT, refusal: REFUSAL }), /accessChange/);
});
