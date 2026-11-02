import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { request, createServer } from 'node:http';
import { gzipSync } from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';
import { digest } from '../../src/domain.mjs';
import { createDecisionLogSink, decisionWindow, normalizeDecision, servedFromMetrics, coverageOf, engineServed, SENTINEL } from './decision-log.mjs';
import { startStandIn, startOpa, writeOpaConfig } from './engines.mjs';
import { startDecisionDesk, deskPolicy, deskRefunds } from './desk.mjs';
import { runDecisionEffect, validateDecisionEffectRun, judgeDecisionEffect, deskScenario, AUDIT_INSTANCE, SNAPSHOT_INSTANCE, SETTLE_MS } from './decision-effect.mjs';

const TOKENS = { 'desk-viewer': 'synthetic-desk-viewer', 'desk-agent': 'synthetic-desk-agent' };
const ENV = { SCOPEHAVEN_TARGET_DESK_VIEWER: TOKENS['desk-viewer'], SCOPEHAVEN_TARGET_DESK_AGENT: TOKENS['desk-agent'] };
const ACTORS = { viewer: { principalId: 'desk-viewer', credentialEnv: 'SCOPEHAVEN_TARGET_DESK_VIEWER' }, agent: { principalId: 'desk-agent', credentialEnv: 'SCOPEHAVEN_TARGET_DESK_AGENT' } };
const POLICY_DIR = fileURLToPath(new URL('./policy/', import.meta.url));
const OPA = process.env.SCOPEHAVEN_OPA_BIN;

async function deskRun(t, { build = 'checked', engine = 'stand-in', policy = deskPolicy, faults = {}, flushTimeoutMs, onSink } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven decision effect '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const sink = createDecisionLogSink(); await sink.start(); t.after(() => sink.stop());
  const eng = engine === 'opa'
    ? await startOpa({ bin: OPA, policyFiles: [join(POLICY_DIR, 'desk.rego'), join(POLICY_DIR, 'data.json')], sinkUrl: sink.url, sinkToken: sink.token, dir })
    : await startStandIn({ policy, sinkUrl: sink.url, sinkToken: sink.token, ...faults });
  t.after(() => eng.stop());
  const desk = await startDecisionDesk({ dbPath: join(dir, 'desk.db'), tokens: TOKENS, engineOrigin: eng.origin, build });
  t.after(() => desk.stop());
  if (onSink) await onSink(sink);
  return runDecisionEffect({ deskOrigin: desk.origin, dbPath: join(dir, 'desk.db'), engine: eng, sink, actors: ACTORS, env: ENV, target: { app: 'practice-desk', build }, ...(flushTimeoutMs ? { flushTimeoutMs } : {}) });
}
const statuses = record => Object.fromEntries([...record.run.results, ...record.results].map(r => [r.id, r.status]));
const replies = record => record.run.timeline.filter(e => e.step === 'response').map(e => [e.request, e.status]);
const reseal = record => { const { recordDigest: _d, ...rest } = record; return { ...rest, recordDigest: digest(rest) }; };
const validate = record => validateDecisionEffectRun(record, { actors: ACTORS });

test('the clean build: every effect was allowed on its own input, every forbidden attempt was denied, and the controls pass', async t => {
  const record = await deskRun(t);
  assert.deepEqual(statuses(record), { 'DE-C1': 'pass', 'DE-C2': 'pass', 'DE-R1': 'inconclusive', 'DE-01': 'pass', 'DE-02': 'pass' });
  // Custody: DE-R1 is judged from the application's records alone, which the app can write,
  // so its clean result reads inconclusive (subject-writable-custody), never a pass. DE-01 rests on the decision log.
  assert.equal(record.run.results.find(r => r.id === 'DE-R1').custodyReason, 'subject-writable-custody');
  assert.equal(record.decisions.coverage, 'complete');
  assert.deepEqual([record.decisions.served, record.decisions.logged, record.decisions.events.length], [5, 5, 4]);
  assert.deepEqual(record.refunds.map(r => [r.amount, r.auditId !== null, r.actor, r.ticket]), [[20, true, 'desk-agent', 'T-1']]);
  assert.deepEqual(record.refundsIssued, { start: 0, end: 1 });
  assert.equal(validate(record).valid, true);
});

test('the planted defects fail DE-01 from the decision log while the replies look fine, and the records alone either fail or read inconclusive under custody', async t => {
  const clean = await deskRun(t);
  const expected = {
    'cached-allow': { 'DE-01': ['fail', 'effect-without-decision'], 'DE-02': ['inconclusive', 'not-reached'], 'DE-R1': 'inconclusive' },
    'ignore-deny': { 'DE-01': ['fail', 'effect-after-deny'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'fail' },
    // A reviewer's variants: an allow for another input never covers the refund the desk made.
    preflight: { 'DE-01': ['fail', 'effect-after-deny'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'inconclusive' },
    'replay-cached': { 'DE-01': ['fail', 'effect-without-decision'], 'DE-02': ['inconclusive', 'not-reached'], 'DE-R1': 'inconclusive' },
    // The refund rows do not match the audit rows.
    'double-commit': { 'DE-01': ['fail', 'effect-without-decision'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'inconclusive' },
    'wrong-audit-row': { 'DE-01': ['fail', 'effect-unbound'], 'DE-02': ['inconclusive', 'not-reached'], 'DE-R1': 'inconclusive' },
    'split-one-audit': { 'DE-01': ['fail', 'effect-unbound'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'inconclusive' },
    'denied-audit': { 'DE-01': ['fail', 'effect-unbound'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'inconclusive' },
    unaudited: { 'DE-01': ['fail', 'effect-unbound'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'inconclusive' },
    // A refund row changed, removed, or written as another principal.
    'top-up': { 'DE-01': ['fail', 'effect-unbound'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'inconclusive', unbound: ['refund-row-update'] },
    'service-identity': { 'DE-01': ['fail', 'effect-unbound'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'inconclusive', unbound: ['refund-row-not-its-audit-row'] },
    'transient-row': { 'DE-01': ['fail', 'effect-unbound'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'inconclusive', unbound: ['refund-row-vanished', 'refund-row-vanished'] },
    // The stated net-change limit: a row inserted and edited in the window is judged by its end state.
    'edit-in-window': { 'DE-01': ['pass', 'every-effect-allowed-on-its-input'], 'DE-02': ['pass', 'denied'], 'DE-R1': 'inconclusive', unbound: [] },
  };
  for (const [build, want] of Object.entries(expected)) {
    const record = await deskRun(t, { build });
    assert.deepEqual(replies(record), replies(clean), `${build}: the replies are the clean build's`);
    const row = id => record.results.find(r => r.id === id);
    assert.deepEqual([row('DE-01').status, row('DE-01').reason], want['DE-01'], build);
    assert.deepEqual([row('DE-02').status, row('DE-02').reason], want['DE-02'], build);
    assert.equal(statuses(record)['DE-R1'], want['DE-R1'], build);
    assert.deepEqual([statuses(record)['DE-C1'], statuses(record)['DE-C2']], ['pass', 'pass'], build);
    if (want.unbound) assert.deepEqual(row('DE-01').unbound.map(u => u.reason), want.unbound, `${build}: why the refund rows are unbound`);
    if (['cached-allow', 'ignore-deny', 'preflight', 'replay-cached'].includes(build)) assert.deepEqual(row('DE-01').unmatched.filter(u => u.principal === 'desk-agent').map(u => [u.amount, u.effects]), [[500, 1]], `${build}: the 500 refund is the unmatched one`);
    validate(record);
  }
});

test('a policy that allows a forbidden attempt: the desk obeyed it (DE-01 pass), and DE-02 fails on the engine\'s allow first', async t => {
  const lax = (path, input) => path === 'desk/allow' && (input.action === 'read_ticket' || (input.action === 'refund' && input.principal === 'desk-agent'));
  const record = await deskRun(t, { policy: lax });
  assert.deepEqual([statuses(record)['DE-01'], statuses(record)['DE-02']], ['pass', 'fail']);
  assert.equal(record.results[1].reason, 'engine-allowed-a-forbidden-attempt');
});

test('a missing, late or short decision log never reads pass, and never fails what it cannot see', async t => {
  for (const [faults, extra] of [[{ noLog: true }, 'decision-log-late'], [{ flushDelayMs: 1500 }, 'decision-log-late'], [{ dropEvery: 2 }, 'decisions-not-logged:2'], [{ dropEvery: 4 }, 'decisions-not-logged:1']]) {
    const clean = await deskRun(t, { faults, flushTimeoutMs: 600 });
    assert.equal(clean.results[0].status, 'inconclusive', JSON.stringify(faults));
    assert.equal(clean.results[1].status, 'inconclusive', JSON.stringify(faults));
    assert.ok(clean.decisions.reasons.includes(extra), `${JSON.stringify(faults)}: ${clean.decisions.reasons}`);
    validate(clean);
  }
  const blind = await deskRun(t, { build: 'cached-allow', faults: { noLog: true }, flushTimeoutMs: 600 });
  assert.deepEqual([blind.results[0].status, blind.results[1].status], ['inconclusive', 'inconclusive']);
});

test('the sink: a forged upload without the window\'s token is refused, and one from another engine label makes the window partial', async t => {
  // forge-sink: cached-allow plus a forged allow for the over-limit refund, posted by another process.
  const forgedAllow = [{ labels: { id: 'forged', version: 'x' }, decision_id: 'f', path: 'desk/allow', input: { principal: 'desk-agent', action: 'refund', resource: 'tickets/T-1', amount: 500 }, result: true, timestamp: 't' }];
  const post = (sink, auth) => fetch(`${sink.url}/logs`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', ...(auth ? { Authorization: auth } : {}) }, body: gzipSync(JSON.stringify(forgedAllow)) }).then(r => r.status);
  let status;
  const refused = await deskRun(t, { build: 'cached-allow', onSink: async sink => { status = await post(sink); } });
  assert.equal(status, 401);
  assert.equal(refused.results[0].reason, 'effect-without-decision', 'the forged allow never reached the log');
  // Inside a window, an unauthenticated upload is a sink error, and a forged upload with a leaked
  // token carries another engine's label (and was never served): either way the window reads partial.
  const sink = createDecisionLogSink(); await sink.start(); t.after(() => sink.stop());
  const eng = await startStandIn({ policy: deskPolicy, sinkUrl: sink.url, sinkToken: sink.token }); t.after(() => eng.stop());
  const w = decisionWindow({ sink, engineOrigin: eng.origin, decisionPath: 'desk/allow' });
  await w.begin(); assert.equal(await post(sink), 401);
  const d = await w.end();
  assert.deepEqual([d.coverage, d.reasons], ['partial', ['unauthenticated']]);
  const w2 = decisionWindow({ sink, engineOrigin: eng.origin, decisionPath: 'desk/allow' });
  await w2.begin(); assert.equal(await post(sink, `Bearer ${sink.token}`), 200);
  const leaked = await w2.end();
  assert.equal(leaked.coverage, 'partial');
  assert.ok(leaked.reasons.includes('foreign-engine:1') && leaked.reasons.includes('decisions-not-served:1'), leaked.reasons.join(','));
});

test('a late sentinel from an earlier window is an ordinary logged decision: the counts stay consistent', async t => {
  const sink = createDecisionLogSink(); await sink.start(); t.after(() => sink.stop());
  const eng = await startStandIn({ policy: deskPolicy, sinkUrl: sink.url, sinkToken: sink.token }); t.after(() => eng.stop());
  const w = decisionWindow({ sink, engineOrigin: eng.origin, decisionPath: 'desk/allow' });
  await w.begin();
  await (await fetch(`${eng.origin}/v1/data/desk/allow`, { method: 'POST', body: JSON.stringify({ input: { ...SENTINEL, resource: 'an-earlier-nonce' } }) })).arrayBuffer();
  const d = await w.end();
  assert.equal(d.coverage, 'complete');
  assert.equal(d.logged, d.events.length + 1, 'only this window\'s sentinel is set aside');
  assert.ok(d.events.some(e => e.resource === 'an-earlier-nonce'));
  assert.notEqual(d.sentinel.resource, 'an-earlier-nonce');
});

test('the judge binds each effect to an allow on its own input, and each refund row to exactly one committed refund audit row', () => {
  const scenario = deskScenario({ actors: ACTORS });
  const sealed = 'a'.repeat(64);
  const audit = (seq, actor, name, outcome = 'committed') => ({ source: 'sql-audit-table', seq, actor, name, resource: 'tickets/T-1', outcome });
  const created = (id, contentDigest = sealed) => ({ source: 'sql-snapshot', name: 'refunds', operation: 'insert', resource: `refunds/${id}`, outcome: 'committed', contentDigest });
  const refundRow = (id, auditId, amount, actor = 'desk-agent', ticket = 'T-1') => ({ id, auditId, actor, ticket, amount, contentDigest: sealed });
  const dec = (input, result, { path = 'desk/allow', engine = 'e' } = {}) => ({ path, result, inputDigest: digest(input), principal: input.principal, action: input.action, resource: input.resource, engine: { id: engine } });
  const refund = amount => ({ principal: 'desk-agent', action: 'refund', resource: 'tickets/T-1', amount });
  const viewerRefund = { principal: 'desk-viewer', action: 'refund', resource: 'tickets/T-1', amount: 20 };
  const judge = ({ auditEvents = [], snap = [], refunds = [], issued = { start: 0, end: Math.max(0, ...refunds.map(r => r.id)) }, decisions = [], coverage = 'complete', snapCov = 'net-only', engineId = 'e' }) => judgeDecisionEffect({ issued, run: { aborted: null, windows: { 'start>end': [{ instanceId: AUDIT_INSTANCE, coverage: 'complete', events: auditEvents }, { instanceId: SNAPSHOT_INSTANCE, coverage: snapCov, events: snap }] } }, decisions: { coverage, events: decisions, sentinel: { logged: true, engineId } }, refunds, ...scenario });
  const read = r => [r[0].status, r[0].reason];
  const one = (amount, decisions, extra = {}) => judge({ auditEvents: [audit(1, 'desk-agent', 'refund')], snap: [created(1)], refunds: [refundRow(1, 1, amount)], decisions, ...extra });
  assert.deepEqual(read(one(20, [dec(refund(20), 'allow')])), ['pass', 'every-effect-allowed-on-its-input']);
  assert.deepEqual(read(one(500, [dec(refund(0), 'allow')])), ['fail', 'effect-without-decision'], 'preflight: an allow for amount 0');
  assert.deepEqual(read(one(500, [dec(refund(500), 'allow', { path: 'other/allow' })])), ['fail', 'effect-without-decision'], 'an allow on another path');
  assert.deepEqual(read(one(500, [dec(refund(500), 'allow', { engine: 'forged' })])), ['fail', 'effect-without-decision'], 'an allow from another engine does not count');
  assert.deepEqual(read(one(500, [dec(refund(500), 'deny')], { coverage: 'partial' })), ['inconclusive', 'decision-log-partial']);
  assert.deepEqual(read(one(20, [dec(refund(20), 'allow')], { snapCov: 'failed' })), ['inconclusive', 'snapshot-failed'], 'the refunds snapshot is needed for a pass');
  // Rows the snapshot did not seal, and audit rows no refund row names: the input is unknown.
  assert.deepEqual(read(judge({ auditEvents: [audit(1, 'desk-agent', 'refund')], snap: [created(1, 'b'.repeat(64))], refunds: [refundRow(1, 1, 20)], decisions: [dec(refund(20), 'allow')] })), ['inconclusive', 'effect-input-unknown'], 'the row changed after the snapshot');
  assert.deepEqual(read(judge({ auditEvents: [audit(1, 'desk-agent', 'refund')], decisions: [dec(refund(20), 'allow')] })), ['inconclusive', 'effect-input-unknown'], 'an audited refund with no refund row');
  // A refund row that names no audit row, a denied one, or one another row names fails, whatever the log says.
  assert.deepEqual(read(judge({ auditEvents: [audit(1, 'desk-agent', 'refund.denied', 'denied')], snap: [created(1)], refunds: [refundRow(1, null, 500)], decisions: [dec(refund(500), 'deny')] })), ['fail', 'effect-unbound'], 'unaudited');
  assert.deepEqual(read(judge({ auditEvents: [audit(1, 'desk-agent', 'refund.denied', 'denied')], snap: [created(1)], refunds: [refundRow(1, 1, 500)], decisions: [dec(refund(500), 'deny')] })), ['fail', 'effect-unbound'], 'denied-audit');
  const shared = judge({ auditEvents: [audit(1, 'desk-agent', 'refund')], snap: [created(1), created(2)], refunds: [refundRow(1, 1, 480), refundRow(2, 1, 20)], decisions: [dec(refund(20), 'allow')], coverage: 'partial' });
  assert.deepEqual(read(shared), ['fail', 'effect-unbound'], 'split-one-audit');
  assert.deepEqual(shared[0].unbound.map(u => u.reason), ['audit-row-shared', 'audit-row-shared']);
  assert.deepEqual(read(judge({ auditEvents: [audit(1, 'desk-agent', 'refund'), audit(2, 'desk-agent', 'refund')], snap: [created(1), created(2)], refunds: [refundRow(1, 1, 20), refundRow(2, 2, 20)], decisions: [dec(refund(20), 'allow')] })), ['fail', 'effect-without-decision'], 'one allow covers one effect');
  assert.deepEqual(read(judge({ auditEvents: [audit(1, 'desk-viewer', 'read_ticket'), audit(2, 'desk-agent', 'refund', 'denied')] , decisions: [dec({ principal: 'desk-viewer', action: 'read_ticket', resource: 'tickets/T-1' }, 'allow')] })), ['pass', 'every-effect-allowed-on-its-input'], 'a read is its audit row; a refused action is no effect');
  // A refund row updated or deleted in the window, or issued in it and gone, is unbound.
  const changed = (id, operation) => ({ ...created(id), operation });
  const ok20 = { auditEvents: [audit(1, 'desk-agent', 'refund')], snap: [created(2)], refunds: [refundRow(1, null, 520), refundRow(2, 1, 20)], decisions: [dec(refund(20), 'allow')], issued: { start: 1, end: 2 } };
  assert.deepEqual(read(judge(ok20)), ['pass', 'every-effect-allowed-on-its-input'], 'an earlier row left alone');
  for (const op of ['update', 'delete']) {
    const r = judge({ ...ok20, snap: [...ok20.snap, changed(1, op)] });
    assert.deepEqual([...read(r), r[0].unbound.map(u => [u.refund, u.reason])], ['fail', 'effect-unbound', [[1, `refund-row-${op}`]]], op);
  }
  const gone = judge({ ...ok20, issued: { start: 1, end: 3 } });
  assert.deepEqual([...read(gone), gone[0].unbound.map(u => [u.refund, u.reason])], ['fail', 'effect-unbound', [[3, 'refund-row-vanished']]], 'id 3 was issued in the window and is gone');
  // The refund row is the named audit row's principal's, on its ticket.
  for (const [actor, ticket] of [['desk-viewer', 'T-1'], ['desk-agent', 'T-2']]) {
    const r = judge({ ...ok20, refunds: [refundRow(1, null, 520), refundRow(2, 1, 20, actor, ticket)] });
    assert.deepEqual([...read(r), r[0].unbound[0].reason], ['fail', 'effect-unbound', 'refund-row-not-its-audit-row'], `${actor} ${ticket}`);
  }
  // A read is an effect too, and an unmatched effect fails even beside one whose input is unknown.
  const read1 = audit(2, 'desk-viewer', 'read_ticket');
  assert.deepEqual(read(judge({ auditEvents: [read1] })), ['fail', 'effect-without-decision'], 'a read with no allow');
  assert.deepEqual(read(judge({ auditEvents: [read1, audit(1, 'desk-agent', 'refund')] })), ['fail', 'effect-without-decision'], 'beside a refund with no refund row');
  // DE-02: an allow on a forbidden input fails first, even beside its deny; denies on a partial log do not pass.
  const de02 = (events, coverage = 'complete') => judge({ decisions: events, coverage })[1];
  const read2 = r => [r.status, r.reason];
  assert.deepEqual(read2(de02([dec(refund(500), 'deny'), dec(refund(500), 'allow'), dec(viewerRefund, 'deny')])), ['fail', 'engine-allowed-a-forbidden-attempt']);
  assert.deepEqual(read2(de02([dec(refund(500), 'deny'), dec(viewerRefund, 'deny')], 'partial')), ['inconclusive', 'decision-log-partial']);
  assert.deepEqual(read2(de02([dec(refund(500), 'deny')])), ['inconclusive', 'not-reached']);
  assert.deepEqual(read2(de02([dec(refund(500), 'deny'), dec(viewerRefund, 'deny')])), ['pass', 'denied']);
  assert.deepEqual(read2(de02([dec(refund(500), 'deny'), dec(refund(500), 'allow', { engine: 'forged' }), dec(viewerRefund, 'deny')])), ['pass', 'denied'], 'a forged allow is not blamed on the engine');
});

test('the scenario waits its settle, the OPA config is 0600 in a 0700 directory, an unlabelled decision is foreign, and the engine count never follows a redirect', async t => {
  assert.equal(SETTLE_MS, 300);
  const steps = deskScenario({ actors: ACTORS }).sequence.steps;
  assert.deepEqual(steps.at(-2), { sleep: SETTLE_MS }, 'the settle precedes the end mark');
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven opa config ')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = writeOpaConfig({ dir, sinkUrl: 'http://127.0.0.1:9/', sinkToken: 'synthetic' });
  assert.equal(statSync(config).mode & 0o777, 0o600);
  assert.equal(statSync(dirname(config)).mode & 0o777, 0o700);
  const base = { served: 2, logged: 2, sentinel: { logged: true, engineId: 'e' }, sentinelAnswered: true, sinkErrors: [], events: [{ engine: { id: null } }] };
  assert.deepEqual(coverageOf(base).reasons, ['foreign-engine:1'], 'an unlabelled decision is not the sentinel\'s engine');
  // /metrics redirects to a path that does serve metrics: following it would read 5.
  const redirect = createServer((req, res) => { if (req.url === '/metrics') res.writeHead(302, { Location: '/elsewhere' }).end(); else res.writeHead(200).end('# TYPE http_request_duration_seconds histogram\nhttp_request_duration_seconds_count{code="200",handler="v1/data",method="post"} 5\n'); });
  await new Promise(resolve => redirect.listen(0, '127.0.0.1', resolve)); t.after(() => redirect.close());
  assert.equal(await engineServed(`http://127.0.0.1:${redirect.address().port}`), null);
});

test('the validator recomputes the verdicts and the log coverage, and pins the scenario', async t => {
  const record = await deskRun(t, { build: 'cached-allow' });
  assert.throws(() => validate({ ...record, results: record.results.map(r => ({ ...r, status: 'pass' })) }), { code: 'record-digest' });
  assert.throws(() => validate(reseal({ ...record, results: record.results.map(r => ({ ...r, status: 'pass' })) })), { code: 'verdicts' });
  assert.throws(() => validate(reseal({ ...record, scenario: { ...record.scenario, governed: [] } })), { code: 'scenario' }, 'nothing governed would pass DE-01');
  assert.throws(() => validate(reseal({ ...record, refunds: record.refunds.map(r => ({ ...r, amount: 20 })) })), { code: 'verdicts' }, 'the over-limit refund relabelled');
  assert.throws(() => validate(reseal({ ...record, refunds: [{ id: 'x' }] })), { code: 'refunds' });
  assert.throws(() => validate(reseal({ ...record, refunds: [...record.refunds, record.refunds[0]] })), { code: 'refunds' }, 'a refund id twice');
  assert.throws(() => validate(reseal({ ...record, refunds: record.refunds.map(({ actor: _a, ...r }) => r) })), { code: 'refunds' }, 'a refund row without its actor');
  assert.throws(() => validate(reseal({ ...record, refundsIssued: { start: 0, end: 0 } })), { code: 'refunds-issued' }, 'a row the table never issued');
  assert.throws(() => validate(reseal({ ...record, refundsIssued: { ...record.refundsIssued, end: record.refundsIssued.end + 1 } })), { code: 'verdicts' }, 'a vanished row the verdicts leave out');
  const short = structuredClone(record); short.decisions.served++;
  assert.throws(() => validate(reseal(short)), { code: 'decision-coverage' });
  const uncounted = structuredClone(record); uncounted.decisions.logged--;
  assert.throws(() => validate(reseal(uncounted)), { code: 'decision-count' });
  const sinkError = structuredClone(record); sinkError.decisions.sinkErrors = ['made-up'];
  assert.throws(() => validate(reseal(sinkError)), { code: 'decision-log' });
  const inner = structuredClone(record); inner.run.results[0].status = 'fail';
  assert.throws(() => validate(reseal(inner)), e => e.name === 'SequenceRunError');
  assert.throws(() => validate(reseal({ ...record, schema: 'scopehaven-decision-effect-run/1' })), { code: 'schema' });
});

test('the decision log: results read allow only on true; OPA metrics count every served call but health and metrics, and none at all is unreadable; coverage needs every count and one engine label', () => {
  assert.deepEqual(['allow', 'deny', 'allow', 'deny', 'other', 'other'], [true, false, { allow: true }, { allow: false }, 'yes', null].map(result => normalizeDecision({ result, input: {} }, 1).result));
  const d = normalizeDecision({ decision_id: 'x', path: 'desk/allow', input: { principal: 'p', action: 'refund', resource: 'tickets/T-1', amount: 9 }, result: true, timestamp: 't', labels: { id: 'i', version: '1' } }, 7);
  assert.deepEqual([d.seq, d.principal, d.action, d.resource, d.result, d.engine.version, d.inputDigest], [7, 'p', 'refund', 'tickets/T-1', 'allow', '1', digest({ principal: 'p', action: 'refund', resource: 'tickets/T-1', amount: 9 })]);
  assert.equal('amount' in d, false, 'inputs are kept as a digest only');
  assert.equal(servedFromMetrics('http_request_duration_seconds_count{code="200",handler="v1/data",method="post"} 4\nhttp_request_duration_seconds_count{code="200",handler="health",method="get"} 9\nhttp_request_duration_seconds_count{code="400",handler="v1/data",method="post"} 1\nhttp_request_duration_seconds_count{code="200",handler="v1/policies",method="put"} 2\n'), 7);
  assert.equal(servedFromMetrics('nothing here'), null, 'not a metrics document');
  assert.equal(servedFromMetrics('# TYPE http_request_duration_seconds histogram\n'), 0, 'a metrics document with no call served yet');
  const base = { served: 3, logged: 3, sentinel: { logged: true, engineId: 'e' }, sentinelAnswered: true, sinkErrors: [], events: [{ engine: { id: 'e' } }, { engine: { id: 'e' } }] };
  assert.equal(coverageOf(base).coverage, 'complete');
  assert.equal(coverageOf({ ...base, served: null }).coverage, 'failed');
  assert.equal(coverageOf({ ...base, sentinelAnswered: false }).coverage, 'failed');
  assert.deepEqual(coverageOf({ ...base, sentinel: { logged: false, engineId: null } }).reasons, ['decision-log-late']);
  assert.deepEqual(coverageOf({ ...base, logged: 4 }).reasons, ['decisions-not-served:1']);
  assert.deepEqual(coverageOf({ ...base, events: [{ engine: { id: 'e' } }, { engine: { id: 'other' } }] }).reasons, ['foreign-engine:1']);
  assert.deepEqual(coverageOf({ ...base, sinkErrors: ['overflow'] }), { reasons: ['overflow'], coverage: 'partial' });
});

test('the sink takes authenticated loopback uploads on POST /logs only, within its size cap, and refuses a batch it cannot read', async t => {
  const sink = createDecisionLogSink({ limits: { events: 5000, bodyBytes: 64, field: 200 } }); await sink.start(); t.after(() => sink.stop());
  const auth = { Authorization: `Bearer ${sink.token}` };
  const post = async (body, headers = {}, path = '/logs') => (await fetch(`${sink.url}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body })).status;
  assert.equal(await post('[{"result":true,"input":{"principal":"p"}}]', auth), 200);
  assert.equal(await post('{"not":"a batch"}', auth), 400);
  assert.equal(await post('not json', auth), 400);
  assert.equal(await post('[]', auth, '/other'), 404);
  assert.equal(await post('[]', { Authorization: 'Bearer wrong' }), 401);
  const sameLength = sink.token.replace(/^./, c => (c === 'A' ? 'B' : 'A'));
  assert.equal(sameLength.length, sink.token.length);
  assert.equal(await post('[]', { Authorization: `Bearer ${sameLength}` }), 401, 'a wrong token of the same length (S3)');
  assert.equal(await post(`[${'1,'.repeat(40)}1]`, auth), 413);
  const foreign = await new Promise((resolve, reject) => { const u = new URL(sink.url); request({ host: '127.0.0.1', port: u.port, path: '/logs', method: 'POST', headers: { Host: 'example.com', ...auth } }, res => { res.resume(); resolve(res.statusCode); }).on('error', reject).end('[]'); });
  assert.equal(foreign, 403);
  assert.deepEqual([sink.events.length, sink.errors], [1, ['not-a-batch', 'unreadable-batch', 'unauthenticated', 'unauthenticated', 'body-too-large']]);
  // The engines run on, and log to, loopback only; OPA refuses to start without the sink token.
  await assert.rejects(startStandIn({ policy: deskPolicy, sinkUrl: 'http://example.com/', sinkToken: 't' }), /loopback/);
  await assert.rejects(startOpa({ bin: process.execPath, policyFiles: [], sinkUrl: sink.url, sinkToken: '', dir: tmpdir() }), /bearer token/);
});

test('the real engine (OPA): clean passes; cached-allow, ignore-deny, preflight and replay-cached fail from the decision log', { skip: !(OPA && existsSync(OPA)) && 'set SCOPEHAVEN_OPA_BIN to run against OPA' }, async t => {
  const clean = await deskRun(t, { engine: 'opa' });
  assert.deepEqual(statuses(clean), { 'DE-C1': 'pass', 'DE-C2': 'pass', 'DE-R1': 'inconclusive', 'DE-01': 'pass', 'DE-02': 'pass' });
  assert.match(clean.engine.version, /^\d+\.\d+\.\d+$/);
  const reasons = [];
  for (const build of ['cached-allow', 'ignore-deny', 'preflight', 'replay-cached']) reasons.push((await deskRun(t, { engine: 'opa', build })).results[0].reason);
  assert.deepEqual(reasons, ['effect-without-decision', 'effect-after-deny', 'effect-after-deny', 'effect-without-decision']);
});

test('the refunds are read from a copy, so a lock the app holds never blocks the read, and the sentinel question never follows a redirect', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven desk copy ')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const live = join(dir, 'desk.db'), app = new DatabaseSync(live);
  app.exec("CREATE TABLE refunds (id INTEGER PRIMARY KEY AUTOINCREMENT, audit_id INTEGER, actor TEXT, ticket TEXT, amount REAL); INSERT INTO refunds (audit_id, actor, ticket, amount) VALUES (1, 'desk-agent', 'T-1', 20);");
  app.exec('BEGIN EXCLUSIVE');
  t.after(() => { app.exec('ROLLBACK'); app.close(); });
  assert.deepEqual(deskRefunds(live).rows.map(r => [r.id, r.amount]), [[1, 20]]);
  assert.equal(deskRefunds(live).issued, 1);
  // The engine origin redirects the sentinel question (307 keeps the POST) to a real engine.
  const sink = createDecisionLogSink(); await sink.start(); t.after(() => sink.stop());
  const eng = await startStandIn({ policy: deskPolicy, sinkUrl: sink.url, sinkToken: sink.token }); t.after(() => eng.stop());
  const redirect = createServer((req, res) => { req.resume(); res.writeHead(307, { Location: `${eng.origin}${req.url}` }).end(); });
  await new Promise(resolve => redirect.listen(0, '127.0.0.1', resolve)); t.after(() => redirect.close());
  const w = decisionWindow({ sink, engineOrigin: `http://127.0.0.1:${redirect.address().port}`, decisionPath: 'desk/allow', flushTimeoutMs: 200 });
  await w.begin();
  const d = await w.end();
  assert.deepEqual([d.sentinelAnswered, d.coverage], [false, 'failed']);
});
