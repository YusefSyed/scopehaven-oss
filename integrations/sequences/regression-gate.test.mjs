// The regression gate judges saved sequence runs (evidence origin local-sequence). The in-flight lifecycle case runs
// end to end through the shipped CLI path (--save, --regression-gate, --baseline) against the owned refund desk on
// loopback: an agent's refund is held at the hold gate, the agent is suspended, the refund is released.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main } from './cli.mjs';
import { runSequence, decideAssertion, countsOf, SEQUENCE_SCHEMA, SEQUENCE_RUN_SCHEMA_V2 } from './sequence.mjs';
import { sequenceNativeRun, nativeRunOf, exportSequenceSuite, validateSequenceNativeRun, compareSequenceRuns, SequenceNativeError, SEQUENCE_ORIGIN } from './native.mjs';
import { SEQUENCE_EVALUATOR_HASH } from './evaluator.mjs';
import { validateSequenceRun } from './run-validator.mjs';
import { startRefundDesk, startRefundTools, REFUND_DESK_USERS } from './fixtures/refund-desk.mjs';
import { summarizeGate, validateRun } from '../regression-gate/gate.mjs';
import { compareRuns, runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { makeEffect } from '../observers/events.mjs';
import { digest } from '../../src/domain.mjs';
import { sequenceAuthorizationArgs } from '../../test/support/authorization.mjs';

const freePort = () => new Promise(resolve => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
const env = { SCOPEHAVEN_TARGET_REFUND_AMY: 'synthetic-amy-token-7', SCOPEHAVEN_TARGET_REFUND_BEN: 'synthetic-ben-token-7', SCOPEHAVEN_TARGET_REFUND_OLGA: 'synthetic-olga-token-7' };
const tokens = { 'agent-amy': env.SCOPEHAVEN_TARGET_REFUND_AMY, 'agent-ben': env.SCOPEHAVEN_TARGET_REFUND_BEN, 'owner-olga': env.SCOPEHAVEN_TARGET_REFUND_OLGA };
// fileURLToPath, not .pathname: the checkout path has a space.
const SEQUENCE_FILE = fileURLToPath(new URL('./fixtures/inflight-refund.json', import.meta.url));
const transitions = summary => Object.fromEntries(Object.entries(summary.comparison.labels).filter(([, n]) => n > 0));

// One CLI run of the in-flight sequence on a fresh desk of one build. withGate: false runs it with no hold gate
// configured at all (the desk then calls its tools directly, and nothing on the request path records them).
async function deskRun(dir, build, { withGate = true, extra = [] } = {}) {
  const tools = await startRefundTools(), gatePort = await freePort(), work = mkdtempSync(join(dir, `${build}-`));
  const desk = await startRefundDesk({ dbPath: join(work, 'desk.db'), upstream: withGate ? `http://127.0.0.1:${gatePort}` : tools.url, build, tokens });
  try {
    writeFileSync(join(work, 'observers.json'), JSON.stringify([{ type: 'sqlite-audit', path: join(work, 'desk.db'), principals: Object.keys(REFUND_DESK_USERS),
      audit: { table: 'audit_log', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource', actions: { 'refund.request': 'insert' } } }]));
    writeFileSync(join(work, 'gate.json'), JSON.stringify({ upstream: tools.url, port: gatePort, rules: [{ id: 'approve', method: 'POST', pathPrefix: '/v1/approve' }, { id: 'refund', method: 'POST', pathPrefix: '/tool/refund', holds: 0 }] }));
    const lines = [];
    // The authorization record covering the sequence, the desk, its observer and (with the gate) the tools upstream.
    const authorization = sequenceAuthorizationArgs(join(work, 'authorization.json'), JSON.parse(readFileSync(SEQUENCE_FILE, 'utf8')), { origin: desk.origin, ...(withGate ? { gateUpstream: tools.url } : {}) });
    const code = await main(['--sequence', SEQUENCE_FILE, '--origin', desk.origin, '--observers', join(work, 'observers.json'), ...(withGate ? ['--gate', join(work, 'gate.json')] : []),
      '--out', join(work, 'runs'), '--save', join(dir, 'store'), '--build', build, ...authorization, ...extra], { env, log: s => lines.push(s) });
    const [file] = readdirSync(join(work, 'runs'));
    const run = JSON.parse(readFileSync(join(work, 'runs', file), 'utf8'));
    const stored = /^Stored run ([0-9a-f-]{36}) /m.exec(lines.join('\n'))?.[1];
    const summaryLine = lines.find(l => l.startsWith('Gate summary: '));
    return { code, lines, out: lines.join('\n'), run, stored, summary: summaryLine ? JSON.parse(summaryLine.slice('Gate summary: '.length)) : null, toolCalls: { ...tools.calls } };
  } finally { await desk.stop(); await tools.stop(); }
}
const row = (run, id) => run.results.find(r => r.id === id);

test('in-flight refund: the defect commits through the gated tool after suspension and fails on the hold gate\'s record; the repair passes; the gate decides it against the baseline', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seq-gate-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  // The defect checks permission when the refund starts, not when it commits.
  const defect = await deskRun(dir, 'unchecked-at-commit');
  assert.equal(defect.code, 1, defect.out);
  assert.equal(defect.toolCalls.refund, 2, 'Amy\'s held refund and Ben\'s both reached the refund tool');
  const inflight = row(defect.run, 'INFLIGHT-REFUND');
  // Decided by the hold gate's record, which the desk cannot write.
  assert.deepEqual([inflight.status, inflight.verdict, inflight.custody], ['fail', 'fail', 'independent']);
  assert.deepEqual(defect.run.results.map(r => [r.id, r.status]), [['INFLIGHT-REFUND', 'fail'], ['BEN-REFUND', 'pass'], ['AMY-LOGIN', 'pass'], ['AMY-HELD-REFUSED', 'fail'], ['BEN-REFUND-ACCEPTED', 'pass'], ['AMY-FRESH-REFUSED', 'pass']]);
  // A fresh request from the suspended agent is refused, so the fix looks done; the held one still committed.
  assert.match(defect.out, /PASS\s+AMY-FRESH-REFUSED.*\[answered: 401\]/);
  assert.match(defect.out, /FAIL\s+AMY-HELD-REFUSED.*\[answered: 200\]/);
  assert.ok(defect.stored, defect.out);
  // The demo pairs every refusal row with an earlier acceptance control by the same actor (reading a refusal as an
  // authorization change needs that pairing; a control by another actor cannot establish it).
  const demo = JSON.parse(readFileSync(SEQUENCE_FILE, 'utf8'));
  const requests = demo.steps.filter(step => step.request), actorOf = step => step.request.actorId;
  for (const [i, step] of requests.entries()) if (step.assertStatus?.in.every(code => code === 401 || code === 403))
    assert.ok(requests.slice(0, i).some(prior => actorOf(prior) === actorOf(step) && prior.assertStatus?.severity === 'control' && prior.assertStatus.in.every(code => code >= 200 && code < 300)), step.assertStatus.id);
  // The stored id is the run digest in UUID form: its first 12 characters name the run file too.
  assert.equal(defect.stored.replaceAll('-', '').slice(0, 12), defect.run.runDigest.slice(0, 12));

  // The repair re-reads the agent's status at commit: the held refund is refused at release, and every row passes.
  const repaired = await deskRun(dir, 'recheck-at-commit', { extra: ['--regression-gate', '--baseline', defect.stored] });
  assert.equal(repaired.code, 0, repaired.out);
  assert.equal(repaired.toolCalls.refund, 1, 'only Ben\'s refund reached the tool');
  assert.deepEqual([row(repaired.run, 'INFLIGHT-REFUND').status, row(repaired.run, 'INFLIGHT-REFUND').custody], ['pass', 'independent']);
  assert.deepEqual(repaired.run.results.map(r => r.status), ['pass', 'pass', 'pass', 'pass', 'pass', 'pass']);
  assert.deepEqual([repaired.summary.outcome, repaired.summary.reasons, repaired.summary.current.evidenceOrigin, repaired.summary.current.allowedControls], ['clean', [], SEQUENCE_ORIGIN, { required: 3, passed: 3, status: 'pass' }]);
  assert.equal(repaired.summary.comparison.compatibility, 'compatible');
  assert.equal(repaired.summary.comparison.restorationLabel, 'Observed effects and response status restored');
  // The effect row restored from the gate's record, the status row restored from the answer, the rest preserved.
  assert.deepEqual(transitions(repaired.summary), { 'local-control-restored': 1, 'contract-restored': 1, preserved: 4 });
  // The summary keeps no titles, reply text or credentials.
  const summaryText = JSON.stringify(repaired.summary);
  for (const secret of [...Object.values(env), 'refund is refused', 'Amy']) assert.ok(!summaryText.includes(secret), secret);

  // Over-blocking: halting every refund after any suspension passes the boundary rows but fails both of Ben's controls.
  const halted = await deskRun(dir, 'halt-all', { extra: ['--regression-gate', '--baseline', defect.stored] });
  assert.equal(halted.code, 1, halted.out);
  assert.deepEqual(halted.run.results.map(r => [r.id, r.status]), [['INFLIGHT-REFUND', 'pass'], ['BEN-REFUND', 'fail'], ['AMY-LOGIN', 'pass'], ['AMY-HELD-REFUSED', 'pass'], ['BEN-REFUND-ACCEPTED', 'fail'], ['AMY-FRESH-REFUSED', 'pass']]);
  // A fail-to-pass row behind failed controls is blocked, never restored, so the comparison is also incomplete.
  assert.deepEqual(halted.summary.reasons, ['checks-failed', 'required-controls-not-passed', 'comparison-incomplete']);
  assert.deepEqual([halted.summary.comparison.allowedControlsPass, halted.summary.comparison.restorationLabel], [false, 'Unverified changes']);
  assert.deepEqual(transitions(halted.summary), { 'blocked-by-controls': 2, regression: 2, preserved: 2 });

  // No hold gate configured: the sequence stops at its first hold, and nothing on the request path can decide the absence.
  const ungated = await deskRun(dir, 'recheck-at-commit', { withGate: false, extra: ['--regression-gate', '--baseline', defect.stored] });
  assert.equal(ungated.run.aborted, 'step-error');
  assert.deepEqual([row(ungated.run, 'INFLIGHT-REFUND').status, row(ungated.run, 'INFLIGHT-REFUND').verdict], ['inconclusive', 'unobservable']);
  assert.ok(ungated.run.results.every(r => r.status !== 'pass'), 'nothing passes without the observer');
  assert.equal(ungated.code, 1, ungated.out);
  // Another observer configuration is another identity: the comparison is refused, not read as a repair.
  assert.deepEqual(ungated.summary.reasons, ['inconclusive-evidence', 'required-controls-not-passed', 'incompatible-baseline', 'comparison-incomplete']);
  assert.deepEqual([ungated.summary.comparison.compatibility, ungated.summary.comparison.summary.fixed], ['incompatible', 0]);

  // The saved runs are core store runs: the store's integrity check holds, and the core comparison does not know the origin.
  const store = createStore(join(dir, 'store')); await store.ready;
  const [before, after] = [await store.get(defect.stored), await store.get(repaired.stored)];
  assert.equal(after.evidenceOrigin, SEQUENCE_ORIGIN);
  const core = compareRuns(before, after);
  assert.deepEqual([core.compatible, core.restorationLabel, core.summary.fixed], [false, 'Unverified changes', 0]);
  // A baseline that does not exist, or that is not valid evidence, stops before any request is sent.
  writeFileSync(join(dir, 'observers.json'), JSON.stringify([{ type: 'otel', port: 0, services: ['refund-desk'] }]));
  // A stored baseline that is not valid evidence (its sealed verdict edited and resealed) is refused before any request too.
  const forged = structuredClone(before); delete forged.integrity; delete forged.notes;
  Object.assign(forged.sequenceEvidence.run.results[0], { status: 'pass', verdict: 'pass' });
  forged.id = '11111111-2222-3333-4444-555555555555'; await store.save(forged);
  for (const [id, message] of [['00000000-0000-0000-0000-000000000000', 'Run not found.'], ['not-a-run-id', 'Invalid run identifier.'], [forged.id, 'invalid-sequence-evidence']]) {
    const out = [];
    assert.equal(await main(['--sequence', SEQUENCE_FILE, '--origin', 'http://127.0.0.1:1', '--observers', join(dir, 'observers.json'), '--save', join(dir, 'store'), '--build', 'b', '--regression-gate', '--baseline', id], { env, log: s => out.push(s) }), 2);
    assert.deepEqual(out, [`Configuration error: the baseline run was refused (${message})`]);
  }
  // --save refuses a sequence without an allowed-use control before anything binds or sends.
  const uncontrolled = JSON.parse(readFileSync(SEQUENCE_FILE, 'utf8'));
  uncontrolled.steps.forEach(step => { if (step.assertStatus) step.assertStatus.severity = 'high'; }); uncontrolled.assertions.forEach(a => { a.severity = 'high'; });
  writeFileSync(join(dir, 'uncontrolled.json'), JSON.stringify(uncontrolled));
  const out = [];
  assert.equal(await main(['--sequence', join(dir, 'uncontrolled.json'), '--origin', 'http://127.0.0.1:1', '--observers', join(dir, 'observers.json'), '--save', join(dir, 'store'), '--build', 'b'], { env, log: s => out.push(s) }), 2);
  assert.match(out.join('\n'), /^Configuration error: A sequence saved with --save needs at least one allowed-use control/);
});

// Runs without a network: the real runner with scripted observers and transport, saved as native runs.
const gateObserver = plan => { let at = 0; const observer = { kind: 'hold-gate', instanceId: 'gate-1' };
  return { kind: 'hold-gate', instanceId: 'gate-1', source: 'hold-proxy', scope: Object.freeze({ operations: ['tool-call'], names: ['approve', 'refund', 'ungated'], actorAttribution: 'none', evidence: 'authoritative' }),
    async start() {}, async stop() {}, async mark() { return { at: ++at }; },
    async collect(from) { const window = plan(from.at); return { events: window.events.map((name, i) => makeEffect({ source: 'hold-proxy', observer, seq: i + 1, observedAt: '2026-10-08T00:00:00.000Z', operation: 'tool-call', name, outcome: 'committed' })), coverage: window.coverage ?? 'complete', reason: window.coverage === 'partial' ? 'gate-timeline-full' : null }; } }; };
const SEQ = { schema: SEQUENCE_SCHEMA, id: 'INFLIGHT-UNIT', applicationId: 'refund-desk-fixture', contextId: 'refund-desk-synthetic-v1',
  actors: { amy: { principalId: 'agent-amy' }, ben: { principalId: 'agent-ben' } },
  // Amy's credential is accepted first (an unasserted request): her refusal row needs an earlier same-actor 2xx.
  steps: [{ request: { id: 'amy-login', actorId: 'amy', method: 'GET', path: '/whoami' } }, { mark: 'suspended' }, { request: { id: 'amy-refund', actorId: 'amy', method: 'POST', path: '/refund' }, assertStatus: { id: 'AMY-REFUSED', title: 'Amy is refused', severity: 'high', in: [401, 403] } },
    { mark: 'amy-done' }, { request: { id: 'ben-refund', actorId: 'ben', method: 'POST', path: '/refund' }, assertStatus: { id: 'BEN-ACCEPTED', title: 'Ben is accepted', severity: 'control', in: [200] } }, { mark: 'ben-done' }],
  assertions: [{ id: 'NO-REFUND', title: 'No refund after suspension', severity: 'critical', from: 'suspended', to: 'amy-done', effect: { kind: 'effect.none', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund' } } },
    { id: 'BEN-REFUND', title: 'Ben refunds once', severity: 'control', from: 'amy-done', to: 'ben-done', effect: { kind: 'effect.count', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund' }, expected: 1 } }] };
// windows: index 1 is the forbidden window (suspended to amy-done), index 2 the control window.
async function unitRun({ forbidden = { events: [] }, control = { events: ['refund'] }, sequence = SEQ, transport }) {
  const observer = gateObserver(at => at === 1 ? forbidden : control);
  const run = JSON.parse(JSON.stringify(await runSequence(sequence, { origin: 'http://127.0.0.1:1', observers: [observer], transport })));
  return { run, observers: [observer] };
}
// Amy's answer is scripted per run; Ben is always accepted.
const scripted = amyStatus => { let refunds = 0; return async (_o, check) => ({ status: check.path === '/refund' && refunds++ === 0 ? amyStatus : 200, complete: true }); };
async function native({ amyStatus = 403, forbidden, control, sequence = SEQ, build = 'b1' } = {}) {
  const { run, observers } = await unitRun({ forbidden, control, sequence, transport: scripted(amyStatus) });
  return { native: sequenceNativeRun({ sequence, run, build }), run, suite: exportSequenceSuite(sequence, observers) };
}
const defectBaseline = () => native({ amyStatus: 200, forbidden: { events: ['refund'] }, build: 'defect' });

test('a fix is never verified on an inconclusive row: a candidate whose forbidden window is incomplete reads unverified', async () => {
  const baseline = (await defectBaseline()).native;
  assert.deepEqual(baseline.results.map(r => r.status), ['fail', 'pass', 'fail', 'pass']);
  // The forbidden window is partial (the gate's timeline overflowed): its absence is missing, not a pass.
  const partial = await native({ forbidden: { events: [], coverage: 'partial' }, build: 'repaired' });
  assert.equal(partial.native.results[0].status, 'inconclusive');
  const gate = summarizeGate({ candidate: partial.native, baseline, expectedSuite: partial.suite });
  assert.equal(gate.exitCode, 1);
  assert.deepEqual(gate.reasons, ['inconclusive-evidence', 'comparison-incomplete']);
  assert.deepEqual(transitions(gate), { unverified: 1, 'contract-restored': 1, preserved: 2 });
  assert.equal(gate.comparison.restorationLabel, 'No verified repair');
  // Inconclusive in the baseline, pass in the candidate: unverified too, never restored.
  const comparison = compareSequenceRuns(partial.native, (await native({ build: 'repaired-2' })).native);
  assert.deepEqual(comparison.rows.map(r => [r.id, r.transition]), [['NO-REFUND', 'unverified'], ['BEN-REFUND', 'preserved'], ['AMY-REFUSED', 'preserved'], ['BEN-ACCEPTED', 'preserved']]);
  // A clean candidate against the defect: both rows restored, a different label for each kind.
  const clean = await native({ build: 'repaired-3' });
  const cleanGate = summarizeGate({ candidate: clean.native, baseline, expectedSuite: clean.suite });
  assert.deepEqual([cleanGate.exitCode, transitions(cleanGate)], [0, { 'local-control-restored': 1, 'contract-restored': 1, preserved: 2 }]);
  // Only the status row restored (the effect row still fails): its own label, and the gate still fails.
  const statusOnly = await native({ forbidden: { events: ['refund'] }, build: 'repaired-4' });
  const statusGate = summarizeGate({ candidate: statusOnly.native, baseline, expectedSuite: statusOnly.suite });
  assert.deepEqual([statusGate.exitCode, statusGate.reasons, statusGate.comparison.restorationLabel], [1, ['checks-failed'], 'Response status restored']);
});

test('a comparison refuses incompatible identities: evaluator, scenario, target and observers; the build label may change', async () => {
  const baseline = (await defectBaseline()).native;
  const reasonsOf = candidate => compareSequenceRuns(baseline, candidate).reasons;
  // The same sequence on another build compares.
  const candidate = await native({ build: 'repaired' });
  assert.equal(compareSequenceRuns(baseline, candidate.native).compatible, true);
  // Another evaluator: the run sealed a different evaluator hash.
  const { run } = await unitRun({ transport: scripted(403) });
  const foreign = structuredClone(run); foreign.evaluatorHash = 'f'.repeat(64);
  const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest: _r, ...sealed } = foreign; foreign.runDigest = digest(sealed);
  const foreignNative = sequenceNativeRun({ sequence: SEQ, run: foreign, build: 'repaired' });
  assert.ok(reasonsOf(foreignNative).includes('evaluatorHash differs or is missing.'));
  assert.deepEqual(summarizeGate({ candidate: foreignNative, baseline }).reasons, ['incompatible-baseline', 'comparison-incomplete']);
  // Bound to the current evaluator, the foreign run is not the expected suite's evidence.
  assert.deepEqual(summarizeGate({ candidate: foreignNative, expectedSuite: candidate.suite }).reasons, ['unexpected-suite-evidence']);
  // Another scenario: one more step changes the scenario hash.
  const longer = (await native({ sequence: { ...SEQ, steps: [...SEQ.steps.slice(0, 2), { sleep: 0 }, ...SEQ.steps.slice(2)] } })).native;
  assert.equal(compareSequenceRuns(baseline, longer).compatible, false);
  assert.ok(reasonsOf(longer).includes('suiteHash differs or is missing.'));
  // Another target: the same sequence written for another application or context.
  for (const key of ['applicationId', 'contextId']) {
    const other = (await native({ sequence: { ...SEQ, [key]: 'another-target' } })).native;
    assert.equal(compareSequenceRuns(baseline, other).compatible, false, key);
    assert.ok(reasonsOf(other).includes(`${key} differs or is missing.`), key);
  }
  const renamed = (await native({ sequence: { ...SEQ, id: 'INFLIGHT-OTHER' } })).native;
  assert.equal(compareSequenceRuns(baseline, renamed).compatible, false);
  assert.ok(reasonsOf(renamed).includes('targetId differs or is missing.'));
  // Other observers: a gate that declares one more rule is another observer configuration.
  const widened = await unitRun({ transport: scripted(403) });
  widened.run.observers[0].scope.names.push('extra');
  for (const ws of Object.values(widened.run.windows)) for (const w of ws) w.scope.names.push('extra');
  const { timeline: _t2, gateTimeline: _g2, createdAt: _c2, durationMs: _d2, runDigest: _r2, ...sealed2 } = widened.run; widened.run.runDigest = digest(sealed2);
  const widenedNative = sequenceNativeRun({ sequence: SEQ, run: widened.run, build: 'b' });
  assert.equal(compareSequenceRuns(baseline, widenedNative).compatible, false);
  assert.ok(reasonsOf(widenedNative).includes('profileHash differs or is missing.'));
  // A baseline carrying the candidate's scenario hash over other assertions (resealed consistently, which a run alone
  // cannot detect: the steps are not stored) is refused by the sealed definitions, never read as a repair.
  const other = { ...SEQ, assertions: [SEQ.assertions[0], { ...SEQ.assertions[1], effect: { ...SEQ.assertions[1].effect, expected: 2 } }] };
  const { run: otherRun } = await unitRun({ sequence: other, forbidden: { events: ['refund'] }, transport: scripted(200) });
  otherRun.sequenceHash = candidate.native.suiteHash;
  { const { timeline: _t3, gateTimeline: _g3, createdAt: _c3, durationMs: _d3, runDigest: _r3, ...sealed3 } = otherRun; otherRun.runDigest = digest(sealed3); }
  const relabelled = nativeRunOf({ applicationId: SEQ.applicationId, contextId: SEQ.contextId, build: 'relabelled' }, otherRun);
  assert.doesNotThrow(() => validateSequenceNativeRun(relabelled));
  assert.equal(relabelled.results.find(r => r.id === 'BEN-REFUND').status, 'fail', 'one refund against an expected 2');
  assert.deepEqual(['suiteHash', 'policyHash', 'profileHash'].map(key => relabelled[key] === candidate.native[key]), [true, true, true]);
  const relabelledComparison = compareSequenceRuns(relabelled, candidate.native);
  assert.deepEqual([relabelledComparison.compatible, relabelledComparison.reasons.includes('Sealed assertion definitions differ between the runs.'), relabelledComparison.summary.fixed], [false, true, 0]);
  assert.ok(summarizeGate({ candidate: candidate.native, baseline: relabelled, expectedSuite: candidate.suite }).reasons.includes('incompatible-baseline'));
  // A pair with another origin on one side is not a sequence pair.
  assert.ok(compareSequenceRuns(baseline, { ...baseline, evidenceOrigin: 'local-conversation' }).reasons.includes('Evidence is not a valid sequence run on both sides.'));
});

test('the gate refuses edited sequence evidence and binds a candidate to its suite', async () => {
  const { native: run, suite } = await native();
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suite }).exitCode, 0);
  const refused = (edit, code, detail) => { const x = structuredClone(run); edit(x); const g = summarizeGate({ candidate: x, expectedSuite: suite }); assert.deepEqual([g.exitCode, g.reasons, g.detail], [2, [code], detail], `${code} ${detail}`); };
  // A native row edited to pass, or a native field that disagrees with the sealed run.
  refused(x => { x.results[0].status = 'fail'; x.results[0].assertions[0].status = 'fail'; x.counts = { ...x.counts, pass: x.counts.pass - 1, fail: 1 }; }, 'invalid-sequence-evidence', 'native-run');
  refused(x => { x.requiredControlIds = ['BEN-ACCEPTED']; }, 'invalid-sequence-evidence', 'native-run');
  refused(x => { x.evaluatorHash = 'e'.repeat(64); }, 'invalid-sequence-evidence', 'native-run');
  // A sealed verdict edited and resealed: the recompute refuses it by the row's id.
  refused(x => { const inner = x.sequenceEvidence.run; Object.assign(inner.results[2], { status: 'fail', verdict: 'fail' }); const { runDigest: _r, createdAt: _c, durationMs: _d, ...s } = inner; inner.runDigest = digest(s); }, 'invalid-sequence-evidence', 'sequence-run:sequence-verdict:AMY-REFUSED');
  refused(x => { x.sequenceEvidence.run.results[0].basis = 'edited'; }, 'invalid-sequence-evidence', 'sequence-run:invalid-sequence-run:run-digest');
  refused(x => { x.sequenceEvidence.extra = true; }, 'invalid-sequence-evidence', 'evidence');
  refused(x => { x.adapterVersion = 'timed-sequence/0'; }, 'invalid-sequence-evidence', 'origin');
  refused(x => { x.build = 'bad\u001blabel'; }, 'invalid-sequence-evidence', 'identity');
  // Another sequence's suite.
  const other = exportSequenceSuite({ ...SEQ, assertions: [SEQ.assertions[0], { ...SEQ.assertions[1], effect: { ...SEQ.assertions[1].effect, expected: 2 } }] }, [gateObserver(() => ({ events: [] }))]);
  assert.deepEqual(summarizeGate({ candidate: run, expectedSuite: other }).reasons, ['unexpected-suite-evidence']);
  const otherObservers = exportSequenceSuite(SEQ, [{ ...gateObserver(() => ({ events: [] })), instanceId: 'gate-2' }]);
  assert.deepEqual(summarizeGate({ candidate: run, expectedSuite: otherObservers }).reasons, ['unexpected-suite-evidence']);
  // A forger who edits a sealed verdict, reseals it and rebuilds the whole native run consistently is still refused: the verdict is recomputed.
  const forgedInner = structuredClone(run.sequenceEvidence.run); Object.assign(forgedInner.results[0], { status: 'fail', verdict: 'fail' }); forgedInner.counts = { ...forgedInner.counts, pass: forgedInner.counts.pass - 1, fail: 1 };
  { const { runDigest: _r, createdAt: _c, durationMs: _d, ...sealed } = forgedInner; forgedInner.runDigest = digest(sealed); }
  const forgedNative = nativeRunOf({ applicationId: run.applicationId, contextId: run.contextId, build: run.build }, forgedInner);
  assert.deepEqual([summarizeGate({ candidate: forgedNative }).reasons, summarizeGate({ candidate: forgedNative }).detail], [['invalid-sequence-evidence'], 'sequence-run:sequence-verdict:NO-REFUND']);
  // Another origin cannot carry sequence evidence, and validateRun applies the same native validator.
  assert.throws(() => validateRun({ ...run, evidenceOrigin: 'local-conversation' }));
  const synthetic = await runAssessment('demo-repaired');
  assert.doesNotThrow(() => validateRun(synthetic));
  assert.throws(() => validateRun({ ...synthetic, sequenceEvidence: run.sequenceEvidence }), e => e.code === 'invalid-run-evidence');
  assert.throws(() => validateSequenceNativeRun({ ...run, sequenceEvidence: null }), SequenceNativeError);
  // A /2 run cannot be saved for the gate: it carries no evaluator identity.
  const { run: inner } = await unitRun({ transport: scripted(403) });
  const v2 = { ...SEQ, steps: SEQ.steps.map(({ assertStatus: _a, ...s }) => s) };
  const r2 = JSON.parse(JSON.stringify(await runSequence(v2, { origin: 'http://127.0.0.1:1', observers: [gateObserver(() => ({ events: [] }))], transport: scripted(403) })));
  r2.schema = SEQUENCE_RUN_SCHEMA_V2; delete r2.evaluatorHash; delete r2.statusAssertions; delete r2.requests; delete r2.responses;
  const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest: _r, ...s2 } = r2; r2.runDigest = digest(s2);
  assert.throws(() => sequenceNativeRun({ sequence: v2, run: r2, build: 'b' }), e => e.code === 'invalid-sequence-run' && e.detail === 'schema');
  // Assembled anyway, the gate refuses it: it has no evaluator hash, and given one, its schema is refused.
  const v2Native = nativeRunOf({ applicationId: run.applicationId, contextId: run.contextId, build: 'b' }, r2);
  assert.deepEqual(summarizeGate({ candidate: v2Native }).reasons, ['invalid-run-evidence']);
  v2Native.evaluatorHash = SEQUENCE_EVALUATOR_HASH;
  assert.deepEqual([summarizeGate({ candidate: v2Native }).reasons, summarizeGate({ candidate: v2Native }).detail], [['invalid-sequence-evidence'], 'sequence-run-schema']);
  // Saving needs the target identity and an allowed-use control.
  assert.throws(() => sequenceNativeRun({ sequence: { ...SEQ, applicationId: undefined }, run: inner, build: 'b' }), /applicationId/);
  const noControl = { ...SEQ, steps: SEQ.steps.map(s => s.assertStatus ? { ...s, assertStatus: { ...s.assertStatus, severity: 'high' } } : s), assertions: SEQ.assertions.map(a => ({ ...a, severity: 'high' })) };
  assert.throws(() => sequenceNativeRun({ sequence: noControl, run: inner, build: 'b' }), /allowed-use control/);
  assert.equal(SEQUENCE_EVALUATOR_HASH, run.evaluatorHash);
});

// Parity with the HTTP identity proof: a refusal row passes, or is
// restored, only after an earlier 2xx for the same actor in the same run; otherwise it reads inconclusive
// (identity-not-established) and earns no credit. A served request still fails, and rows answered otherwise are unaffected.
// Ben's accepted request (the window from amy-done to after, the second mark) records his refund: the gate needs an effect control
// beside an effect row that judges a boundary, since a status control alone passes on a target that does nothing.
const PAIRING_OBSERVER = () => gateObserver(at => ({ events: at === 2 ? ['refund'] : [] }));
const pairingSequence = ({ paired = true } = {}) => ({ schema: SEQUENCE_SCHEMA, id: 'PAIRING', applicationId: 'review-fixture', contextId: 'scripted-local',
  actors: { amy: { principalId: 'agent-amy' }, ben: { principalId: 'agent-ben' } },
  steps: [...(paired ? [{ request: { id: 'amy-accepted', actorId: 'amy', method: 'GET', path: '/amy-before' }, assertStatus: { id: 'AMY-ACCEPTED', title: 'Amy accepted before the change', severity: 'control', in: [200] } }] : []),
    { mark: 'before' },
    { request: { id: 'amy-refused', actorId: 'amy', method: 'GET', path: '/amy-after' }, assertStatus: { id: 'AMY-REFUSED', title: 'Amy refused after the change', severity: 'high', in: [403] } },
    { mark: 'amy-done' },
    { request: { id: 'ben-accepted', actorId: 'ben', method: 'GET', path: '/ben' }, assertStatus: { id: 'BEN-ACCEPTED', title: 'Ben accepted', severity: 'control', in: [200] } },
    { mark: 'after' }],
  assertions: [{ id: 'ABSENCE', title: 'No refund', severity: 'high', from: 'before', to: 'amy-done', effect: { kind: 'effect.none', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund' } } },
    { id: 'BEN-REFUND', title: 'Ben refunds', severity: 'control', from: 'amy-done', to: 'after', effect: { kind: 'effect.exists', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund' } } }] });
async function pairingRun(sequence, { after = 403, acceptance = 200, build = 'b' } = {}) {
  const run = JSON.parse(JSON.stringify(await runSequence(sequence, { origin: 'http://127.0.0.1:1', observers: [PAIRING_OBSERVER()],
    transport: async (_o, check) => ({ status: check.path === '/amy-after' ? after : check.path === '/amy-before' ? acceptance : 200, complete: true }) })));
  return { run, native: sequenceNativeRun({ sequence, run, build }), suite: exportSequenceSuite(sequence, [PAIRING_OBSERVER()]) };
}

test('a refusal row without an earlier same-actor acceptance never yields a clean gate or restoration credit', async () => {
  // Amy's refusal with only Ben's control was clean before this rule (exit 0, AMY-REFUSED contract-restored).
  const seq = pairingSequence({ paired: false });
  const [baseline, candidate] = [await pairingRun(seq, { after: 200, build: 'before' }), await pairingRun(seq, { after: 403, build: 'after' })];
  const row = candidate.run.results.find(r => r.id === 'AMY-REFUSED');
  assert.deepEqual([row.status, row.verdict, row.acceptedBy], ['inconclusive', 'identity-not-established', null]);
  const gate = summarizeGate({ candidate: candidate.native, baseline: baseline.native, expectedSuite: candidate.suite });
  assert.notEqual(gate.exitCode, 0);
  assert.deepEqual(gate.reasons, ['inconclusive-evidence', 'comparison-incomplete']);
  const comparison = compareSequenceRuns(baseline.native, candidate.native);
  assert.deepEqual([comparison.rows.find(r => r.id === 'AMY-REFUSED').transition, comparison.summary.fixed], ['unverified', 0]);
  // Paired with Amy's own earlier acceptance, the same refusal is clean; if that acceptance fails, no credit.
  const pairedSeq = pairingSequence();
  const pairedBaseline = await pairingRun(pairedSeq, { after: 200 });
  const paired = await pairingRun(pairedSeq);
  assert.equal(paired.run.results.find(r => r.id === 'AMY-REFUSED').acceptedBy, 'amy-accepted');
  assert.equal(summarizeGate({ candidate: paired.native, baseline: pairedBaseline.native, expectedSuite: paired.suite }).exitCode, 0);
  const denied = await pairingRun(pairedSeq, { acceptance: 403 });
  assert.deepEqual(denied.run.results.filter(r => r.kind === 'response-status').map(r => [r.id, r.status]), [['AMY-ACCEPTED', 'fail'], ['AMY-REFUSED', 'inconclusive'], ['BEN-ACCEPTED', 'pass']]);
  assert.equal(compareSequenceRuns(pairedBaseline.native, denied.native).summary.fixed, 0);
  assert.notEqual(summarizeGate({ candidate: denied.native, baseline: pairedBaseline.native, expectedSuite: denied.suite }).exitCode, 0);
});

test('which earlier response counts as the same actor\'s acceptance, and which rows the rule leaves alone', async () => {
  const req = (id, actorId, path, assertStatus) => ({ request: { id, actorId, method: 'GET', path }, ...(assertStatus ? { assertStatus } : {}) });
  const refusal = { id: 'REFUSED', title: 'refused', severity: 'high', in: [401, 403] };
  const answers = { '/ok': 200, '/no': 403, '/served': 200, '/partial': 200 };
  const verdictOf = async steps => {
    // Not saved for the gate: only the one absence row, over its own two marks.
    const seq = { ...pairingSequence(), steps: [{ mark: 'before' }, ...steps, { mark: 'after' }], assertions: [{ ...pairingSequence().assertions[0], to: 'after' }] };
    const run = JSON.parse(JSON.stringify(await runSequence(seq, { origin: 'http://127.0.0.1:1', observers: [PAIRING_OBSERVER()],
      transport: async (_o, check) => ({ status: answers[check.path], complete: check.path !== '/partial' }) })));
    validateSequenceRun(run, { expectedSequence: seq });
    const row = run.results.find(r => r.id === 'REFUSED' || r.id === 'OK');
    return [row.verdict, Object.hasOwn(row, 'acceptedBy') ? row.acceptedBy : '-'];
  };
  assert.deepEqual(await verdictOf([req('a1', 'amy', '/ok'), req('a2', 'amy', '/no', refusal)]), ['pass', 'a1'], 'an unasserted earlier 2xx by the same actor counts');
  assert.deepEqual(await verdictOf([req('b1', 'ben', '/ok'), req('a2', 'amy', '/no', refusal)]), ['identity-not-established', null], 'another actor\'s 2xx does not');
  assert.deepEqual(await verdictOf([req('a2', 'amy', '/no', refusal), req('a3', 'amy', '/ok')]), ['identity-not-established', null], 'a later 2xx does not');
  assert.deepEqual(await verdictOf([req('a1', 'amy', '/no'), req('a2', 'amy', '/no', refusal)]), ['identity-not-established', null], 'an earlier refusal does not');
  assert.deepEqual(await verdictOf([req('a2', 'amy', '/served', refusal)]), ['fail', '-'], 'a served request fails without pairing');
  assert.deepEqual(await verdictOf([req('a2', 'amy', '/ok', { ...refusal, id: 'OK', in: [200] })]), ['pass', '-'], 'a row expecting 2xx is unaffected');
  assert.deepEqual(await verdictOf([req('a2', 'amy', '/no', { ...refusal, in: [403, 404] })]), ['identity-not-established', null], 'the rule keys on the 401 or 403 answered, not only a pure refusal set');
  // An edited acceptance is recomputed: dropping the earlier 2xx makes the stored pass disagree.
  const seq = { ...pairingSequence(), steps: [{ mark: 'before' }, req('a1', 'amy', '/ok'), req('a2', 'amy', '/no', refusal), { mark: 'after' }], assertions: [{ ...pairingSequence().assertions[0], to: 'after' }] };
  const run = JSON.parse(JSON.stringify(await runSequence(seq, { origin: 'http://127.0.0.1:1', observers: [PAIRING_OBSERVER()], transport: async (_o, check) => ({ status: answers[check.path], complete: true }) })));
  delete run.responses.a1;
  { const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest: _r, ...sealed } = run; run.runDigest = digest(sealed); }
  assert.throws(() => validateSequenceRun(run), e => e.code === 'sequence-verdict' && e.detail === 'REFUSED');
});

// The gate reads a passing control as proof the target still does the allowed thing (README: "an absence could come from a target
// that does nothing"). An effect control with effect.none or a count of 0, or only a response-status control beside effect rows
// that judge boundaries, passes on a target that answers and does nothing, so the gate path refuses those sequences and runs.
test('the gate needs every effect control to prove its use, and an effect control wherever effect rows judge boundaries', async () => {
  const [forbidden, control] = SEQ.assertions;
  const absence = { ...SEQ, assertions: [forbidden, { ...control, effect: { kind: 'effect.none', select: control.effect.select } }] };
  const zero = { ...SEQ, assertions: [forbidden, { ...control, effect: { ...control.effect, expected: 0 } }] };
  const statusOnly = { ...SEQ, assertions: [forbidden, { ...control, severity: 'high' }] };
  for (const [sequence, message] of [[absence, /every effect control .* to prove its use happened/], [zero, /every effect control .* to prove its use happened/], [statusOnly, /needs at least one effect control/]]) {
    // The sequence itself is valid and runs (a model-path timing guard is one such control); only the gate path refuses it.
    const { run, observers } = await unitRun({ sequence, control: { events: [] }, transport: scripted(403) });
    assert.doesNotThrow(() => validateSequenceRun(run, { expectedSequence: sequence }));
    assert.throws(() => sequenceNativeRun({ sequence, run, build: 'b1' }), message);
    assert.throws(() => exportSequenceSuite(sequence, observers), message);
  }
  // A saved native run whose control assertion was turned into an absence, re-derived and resealed as a consistent forger would,
  // is refused as such by the gate's validator.
  const { native: saved } = await native();
  validateSequenceNativeRun(saved);
  const forged = JSON.parse(JSON.stringify(saved)), inner = forged.sequenceEvidence.run;
  inner.assertions[1].effect = { kind: 'effect.none', select: control.effect.select };
  const a = inner.assertions[1];
  inner.results[1] = JSON.parse(JSON.stringify(decideAssertion(a, inner.windows[`${a.from}>${a.to}`], inner.aborted)));
  inner.counts = countsOf(inner.results);
  const { timeline: _t, gateTimeline: _g, createdAt: _c, durationMs: _d, runDigest: _r, ...sealed } = inner; inner.runDigest = digest(sealed);
  assert.doesNotThrow(() => validateSequenceRun(inner), 'the forged inner run is consistent on its own');
  assert.throws(() => validateSequenceNativeRun(forged), e => e instanceof SequenceNativeError && e.code === 'invalid-sequence-evidence' && e.detail === 'control-no-positive-effect');
});
