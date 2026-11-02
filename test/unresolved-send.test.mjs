// An effect whose outcome no observer decided (started at the window end, or unknown) may have committed. Before this rule,
// an honest export-file feed's send stamped before its window read unknown, and because a presence-only window opens no coverage gap,
// effect.none and effect.only dropped it and passed on another observer's silence (3 false passes in 8 runs at load average 7 to 12).
// From any relevant window, presence-only included, such a send now holds an absence, a count it could still reach and an effect.only
// pass at missing: never a pass, never an absence fail. Decided outcomes, sends the clause cannot select, and every earlier verdict
// (a committed fail, a gap, an unobservable clause) are unchanged.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeEffect, evaluateEffectAssertion, collectWindow } from '../src/effect-events.mjs';
import { validateIdempotencyDeclaration } from '../src/idempotency.mjs';
import { judgeOnly } from '../integrations/collateral/only.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { startStub } from '../integrations/observers/fixtures/provider-stub.mjs';
import { createEgressRecorder } from '../integrations/observers/egress-recorder.mjs';
import { onFreePorts } from '../integrations/observers/fixtures/free-port.mjs';

const EXT = 'mail.example.test', PRINCIPAL = 'ops';
// A: an authoritative egress window that covered the check and recorded nothing. B: a presence-only window of the same destination.
const SCOPE = Object.freeze({ operations: ['send'], names: [EXT], actorAttribution: 'none', evidence: 'authoritative', capture: { [EXT]: ['/template'] } });
const PRESENCE = Object.freeze({ ...SCOPE, evidence: 'presence-only' });
let seq = 0;
const send = (instanceId, outcome, extra = {}) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, observedAt: '2026-10-19T00:00:00.000Z',
  operation: 'send', name: EXT, resource: 'POST /v1/send', outcome, ...extra });
const win = (instanceId, scope, events, coverage) => ({ source: 'http-egress', instanceId, scope, coverage, reason: coverage === 'complete' ? null : 'synthetic', events });
const A = (events = [], { scope = SCOPE, coverage = 'complete' } = {}) => win('egress-recorder-a', scope, events, coverage);
const B = (events = [], { scope = PRESENCE } = {}) => win('egress-recorder-b', scope, events, 'partial');
const inB = (outcome, extra) => send('egress-recorder-b', outcome, extra);
const inA = (outcome, extra) => send('egress-recorder-a', outcome, extra);
const sel = Object.freeze({ source: 'http-egress', operation: 'send', name: EXT });
const NONE = Object.freeze({ kind: 'effect.none', select: sel }), EXISTS = Object.freeze({ kind: 'effect.exists', select: sel });
const count = (expected, select = sel) => ({ kind: 'effect.count', select, expected });
const judge = (clause, windows, opts) => evaluateEffectAssertion(clause, windows, opts);
const verdict = (clause, windows, opts) => judge(clause, windows, opts).verdict;
const UNRESOLVED = /outcome no observer decided/;

test('effect.none: a matching send whose outcome no observer decided, in a presence-only window, holds the absence at missing', () => {
  for (const outcome of ['unknown', 'started']) {
    const d = judge(NONE, [A(), B([inB(outcome)])]);
    assert.deepEqual([d.verdict, UNRESOLVED.test(d.basis)], ['missing', true], outcome);
  }
  assert.equal(verdict(NONE, [A(), B()]), 'pass', 'the control: nothing in B, A silent and complete');
  // A decided outcome that is not a commit, and a send the clause does not select, leave the absence to A.
  for (const outcome of ['denied', 'error']) assert.equal(verdict(NONE, [A(), B([inB(outcome)])]), 'pass', outcome);
  assert.equal(verdict(NONE, [A(), B([inB('unknown', { name: 'other.example.test' })])]), 'pass', 'another destination');
  // Earlier verdicts come first: a committed send fails, a failed authoritative window is an observer failure, and with no
  // authoritative observer the clause stays unobservable.
  assert.equal(verdict(NONE, [A(), B([inB('unknown'), inB('committed')])]), 'fail');
  assert.equal(verdict(NONE, [A([], { coverage: 'failed' }), B([inB('unknown')])]), 'observer-failure');
  assert.equal(verdict(NONE, [B([inB('unknown')])]), 'unobservable');
});

test('effect.exists: an undecided matching send keeps a fail from being claimed; a committed one still passes', () => {
  const d = judge(EXISTS, [A(), B([inB('unknown')])]);
  assert.deepEqual([d.verdict, UNRESOLVED.test(d.basis)], ['missing', true]);
  assert.equal(verdict(EXISTS, [A(), B([inB('started')])]), 'missing');
  assert.equal(verdict(EXISTS, [A(), B()]), 'fail', 'the control: no send anywhere');
  assert.equal(verdict(EXISTS, [A([inA('committed')]), B([inB('unknown')])]), 'pass');
});

test('effect.count: an undecided send holds a count it could still reach at missing; a count it cannot change keeps its fail', () => {
  assert.equal(verdict(count(1), [A([inA('committed')]), B()]), 'pass', 'the control');
  const d = judge(count(1), [A([inA('committed')]), B([inB('unknown')])]);
  assert.deepEqual([d.verdict, d.matched, UNRESOLVED.test(d.basis)], ['missing', 1, true], 'the count holds and one more may have committed');
  assert.equal(verdict(count(0), [A(), B([inB('unknown')])]), 'missing');
  assert.equal(verdict(count(2), [A([inA('committed')]), B([inB('unknown')])]), 'missing', 'one short, and the undecided send could be the second');
  assert.equal(verdict(count(1), [A([inA('committed'), inA('committed')]), B([inB('unknown')])]), 'fail', 'already over the count');
  assert.equal(verdict(count(3), [A(), B([inB('unknown')])]), 'fail', 'every undecided send together cannot reach the count');
  // Under a pin that declares absent: "fails", a count the absent field decides fails only when the decided matches, the sends still
  // undecided and the sends whose outcome no observer decided together fall short of it.
  const declared = { ...sel, fields: [{ pointer: '/template', equals: 'refund', absent: 'fails' }] };
  const absent = inA('committed', { captured: { status: 'captured', values: { '/template': { type: 'absent' } } } }), unread = inA('committed');
  assert.equal(verdict(count(3, declared), [A([absent, unread]), B()]), 'fail', 'the control: one send ruled out, one undecided, three expected');
  assert.equal(verdict(count(3, declared), [A([absent, unread]), B([inB('unknown')])]), 'fail', 'one more undecided outcome still cannot reach three');
  assert.equal(verdict(count(3, declared), [A([absent, unread]), B([inB('unknown'), inB('unknown')])]), 'missing', 'two more could');
});

test('effect.count by applications: an undecided send holds a keyed count it could still reach at missing; one its applications decide keeps its fail', () => {
  const decl = validateIdempotencyDeclaration({ header: 'idempotency-key' });
  const keyed = { ...SCOPE, idempotency: { [EXT]: decl } };
  const key = { status: 'keyed', key: 'a'.repeat(64), fold: 'a'.repeat(64), head: 'a'.repeat(64) };
  // A send and its exact keyed replay: one application.
  const s1 = send('egress-recorder-a', 'committed', { content: { c: 'c' }, idempotency: { ...key, firstSeq: seq + 1 } });
  const s2 = send('egress-recorder-a', 'committed', { content: { c: 'c' }, idempotency: { ...key, firstSeq: s1.seq } });
  const clause = { ...count(1), countBy: 'idempotency-key' };
  assert.equal(verdict(clause, [A([s1, s2], { scope: keyed })], { countBy: true }), 'pass', 'the control: two sends, one application');
  assert.equal(verdict(clause, [A([s1, s2], { scope: keyed }), B([inB('unknown')])], { countBy: true }), 'missing', 'the undecided send may be a second application');
  // An undecided send can add an application, or replay one, never take one away.
  const app = c => send('egress-recorder-a', 'committed', { content: { c: 'c' }, idempotency: { status: 'keyed', key: c.repeat(64), fold: c.repeat(64), head: c.repeat(64), firstSeq: seq + 1 } });
  const by = n => ({ ...count(n), countBy: 'idempotency-key' });
  const three = ['a', 'b', 'c'].map(app);
  assert.equal(verdict(by(1), [A(three, { scope: keyed })], { countBy: true }), 'fail', 'the control: three applications, one expected');
  assert.equal(verdict(by(1), [A(three, { scope: keyed }), B([inB('unknown')])], { countBy: true }), 'fail', 'already over by applications');
  const two = ['a', 'b'].map(app);
  assert.equal(verdict(by(2), [A(two, { scope: keyed })], { countBy: true }), 'pass', 'the control');
  assert.equal(verdict(by(2), [A(two, { scope: keyed }), B([inB('unknown')])], { countBy: true }), 'missing', 'it could become three');
  const one = [app('a')];
  assert.equal(verdict(by(3), [A(one, { scope: keyed }), B([inB('unknown')])], { countBy: true }), 'fail', 'one more application cannot reach three');
  assert.equal(verdict(by(3), [A(one, { scope: keyed }), B([inB('unknown'), inB('started')])], { countBy: true }), 'missing', 'two more could');
});

test('actor and fields: an undecided send that could be the selected one holds the clause; one its own record rules out does not', () => {
  const actorScope = { ...SCOPE, actorAttribution: 'principal' }, actorPresence = { ...actorScope, evidence: 'presence-only' };
  const pinned = { kind: 'effect.none', select: { ...sel, actor: PRINCIPAL } };
  assert.equal(verdict(pinned, [A([], { scope: actorScope }), B([inB('unknown', { actor: null })], { scope: actorPresence })]), 'missing', 'an unknown actor could be the pinned one');
  assert.equal(verdict(pinned, [A([], { scope: actorScope }), B([inB('unknown', { actor: PRINCIPAL })], { scope: actorPresence })]), 'missing');
  assert.equal(verdict(pinned, [A([], { scope: actorScope }), B([inB('unknown', { actor: 'billing' })], { scope: actorPresence })]), 'pass', 'another declared principal');
  const template = { kind: 'effect.none', select: { ...sel, fields: [{ pointer: '/template', equals: 'refund' }] } };
  const captured = value => ({ captured: { status: 'captured', values: { '/template': { type: 'string', value } } } });
  assert.equal(verdict(template, [A(), B([inB('unknown', captured('refund'))])]), 'missing');
  assert.equal(verdict(template, [A(), B([inB('unknown')])]), 'missing', 'no captured record: the field could be the pinned value');
  assert.equal(verdict(template, [A(), B([inB('unknown', captured('welcome'))])]), 'pass', 'its record names another template');
  // A window blind to the pinned field (it declares no capture) sees the destination: its undecided send could be the selected one.
  const blind = { operations: ['send'], names: [EXT], actorAttribution: 'none', evidence: 'presence-only' };
  assert.equal(verdict(template, [A(), B([inB('unknown')], { scope: blind })]), 'missing');
  assert.equal(verdict(template, [A(), B([inB('unknown', { name: 'other.example.test' })], { scope: { ...blind, names: [EXT, 'other.example.test'] } })]), 'pass', 'another destination');
});

test('effect.only: an undecided judged send no allow fits holds the pass at missing; an allowed one, or another operation, does not', () => {
  const only = (windows, allow = [], operations = ['send']) => judgeOnly({ kind: 'effect.only', allow, operations }, windows);
  assert.equal(only([A(), B()]).verdict, 'pass', 'the control');
  for (const outcome of ['unknown', 'started']) {
    const d = only([A(), B([inB(outcome)])]);
    assert.deepEqual([d.verdict, UNRESOLVED.test(d.basis)], ['missing', true], outcome);
  }
  assert.equal(only([A(), B([inB('unknown')])], [{ operation: 'send', name: EXT }]).verdict, 'pass', 'allowed whatever its outcome');
  assert.equal(only([A(), B([inB('denied')])]).verdict, 'pass', 'a decided outcome that is not a commit');
  const both = { ...PRESENCE, operations: ['send', 'insert'] };
  assert.equal(only([A(), B([inB('unknown', { operation: 'insert' })], { scope: both })]).verdict, 'pass', 'an operation the clause does not judge');
  assert.equal(only([A(), B([inB('unknown'), inB('committed')])]).verdict, 'fail', 'a committed send outside the set still fails');
});

// The deterministic regression: an honest export file. Vendor A is a stub whose witnessed endpoint feed is silent; vendor B is a
// stub declared as such whose export file really records every send the app makes through it. B's clock runs a minute behind
// ScopeHaven's, so every entry it writes is stamped before its check's start mark and reads unknown (no skew on the file route): the
// open edge above, forced instead of left to a same-millisecond race. Before this change CLEAN and ONLY passed and SENT-B failed.
test('end to end: an honest export file behind the clock holds a forbidden send at inconclusive, never a pass on the other vendor\'s silence', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'sh-unresolved-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const VIP = `vip@${EXT}`, WITNESS = 'witness.scopehaven.invalid';
  const pinned = { source: 'provider-feed', operation: 'send', name: EXT, resource: VIP };
  const check = (id, path, effects, severity = 'high') => ({ id, title: id, category: 'mail', severity, actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects });
  const runWith = async ({ lagMs, mails }) => {
    const a = await startStub(t, { feedId: 'vendor-a' }), b = await startStub(t, { feedId: 'vendor-b', journal: join(dir, `b-${lagMs}-${mails}.jsonl`), lagMs });
    const server = createServer((req, res) => {
      const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
      req.resume();
      if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
      const url = new URL(req.url, 'http://127.0.0.1');
      if (url.pathname === '/me') return reply(200, { user: 'ops' });
      if (url.pathname === '/ping-a') { a.accept([`${url.searchParams.get('scopehaven_witness')}@${WITNESS}`]); return reply(200, {}); }
      if (url.pathname === '/notify') { a.accept([VIP]); return reply(200, {}); }
      if (url.pathname === '/noop' || url.pathname === '/mail-b') { if (mails) b.accept([VIP]); return reply(200, {}); } // the app mails VIP through vendor B
      return reply(404, {});
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
    const p = { id: 'f1', name: 'Mail, vendor B by export file', applicationId: 'f1', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'b1', contextId: 'synthetic-mail',
      actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'SENDS'],
      observers: [{ id: 'a', type: 'provider-feed', feedId: a.feedId, feed: { endpoint: { port: a.port, path: a.path } }, publicKey: a.publicKey, domains: [{ domain: EXT, addresses: [VIP] }],
        routing: 'provider', witness: { actorId: 'ops', method: 'GET', path: '/ping-a', domain: WITNESS }, witnessWaitMs: 2000, quietMs: 300, pollMs: 25, settleMs: 250, keySource: 'stub' },
      { id: 'b', type: 'provider-feed', feedId: b.feedId, feed: { file: { path: join(dir, `b-${lagMs}-${mails}.jsonl`) } }, publicKey: b.publicKey, domains: [{ domain: EXT, addresses: [VIP] }], settleMs: 250, keySource: 'stub' }],
      checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
        check('SENDS', '/notify', [{ kind: 'effect.exists', select: pinned }], 'control'), check('CLEAN', '/noop', [{ kind: 'effect.none', select: pinned }]),
        check('ONLY', '/noop', [{ kind: 'effect.only', allow: [], operations: ['send'] }]), check('SENT-B', '/mail-b', [{ kind: 'effect.exists', select: pinned }])] };
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    const r = await runHttpAssessment(p, { env: { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' } });
    validateHttpRunEvidence(r);
    return r;
  };
  const row = (r, id) => r.results.find(x => x.id === id);
  const bOf = (r, id) => row(r, id).trace[1].data.windows.find(w => w.instanceId === 'provider-feed-b');
  const behind = await runWith({ lagMs: 60000, mails: true });
  assert.equal(row(behind, 'SENDS').status, 'pass');
  for (const id of ['CLEAN', 'ONLY', 'SENT-B']) {
    // B is presence-only, holds the send, and read it unknown because of its stamp: the run records the edge, and the clause waits.
    const w = bOf(behind, id);
    assert.deepEqual([w.scope.evidence, w.scope.feed.route, w.events.map(e => e.outcome), w.reason], ['presence-only', 'file', ['unknown'], 'provider-feed-time-outside-window'], id);
    assert.deepEqual([row(behind, id).status, row(behind, id).trace[1].data.effects[0].verdict], ['inconclusive', 'missing'], id);
  }
  // The honest pass beside it: the same lagged file, and the app mails nothing through B. CLEAN and ONLY pass on A's witnessed silence.
  const quiet = await runWith({ lagMs: 60000, mails: false });
  assert.deepEqual(['CLEAN', 'ONLY', 'SENT-B'].map(id => row(quiet, id).status), ['pass', 'pass', 'fail']);
});

// With declared aliases (egress-recorder/11): a send to a declared alias is recorded under its destination's name,
// so an open one in a presence-only recorder holds the destination's absence beside an authoritative recorder that saw nothing (an
// earlier build passed it). A sibling host keeps its own name, so the rule does not see it, and a presence-only recorder opens no gap: an
// open or committed sibling send there holds nothing, the limit docs/KNOWN-LIMITS.md states. Over real loopback HTTP; hosts are names only.
test('aliases: an aborted send to a declared alias in a presence-only recorder holds the destination\'s absence; a sibling send there does not (the stated limit)', async t => {
  const PAY = 'api.pay.example', ALIAS = 'api-eu.pay.example', SIBLING = 'files.pay.example', WITNESS = 'witness.scopehaven.invalid', CHARGES = 'POST /v1/charges';
  const destinations = [{ host: PAY, paths: ['/v1/charges'], aliases: [ALIAS] }];
  const start = cfg => onFreePorts(1, async port => { const o = createEgressRecorder({ port, destinations, ...cfg }); await o.start(); t.after(() => o.stop()); return o; });
  const a = await start({ instanceId: 'egress-recorder-a', routing: 'proxy', witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150 });
  const b = await start({ instanceId: 'egress-recorder-b' });
  // The app's charge through B; aborted mid-body, it leaves B's send with an undecided outcome.
  const post = (host, { abort = false } = {}) => new Promise(resolve => {
    const req = request({ host: '127.0.0.1', port: b.port, method: 'POST', path: `http://${host}/v1/charges`, agent: false, headers: { host, 'content-type': 'application/json', 'content-length': abort ? '64' : '15' } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', () => resolve());
    if (abort) { req.write('{"amount":'); setTimeout(() => { req.destroy(); setTimeout(resolve, 300); }, 50); } else req.end('{"amount":4200}');
  });
  const round = async during => {
    const fa = await a.mark(), fb = await b.mark();
    await during();
    a.markWitnessRequest(fa);
    await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: a.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(fa.witnessNonce)}`, agent: false, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
    const wa = await collectWindow(a, fa, await a.mark()), wb = await collectWindow(b, fb, await b.mark());
    assert.deepEqual([wa.scope.evidence, wa.coverage, wa.events.length, wb.scope.evidence], ['authoritative', 'complete', 0, 'presence-only'], 'A covered the window and saw nothing; B is presence-only');
    return { b: wb.events.map(e => [e.name, e.resource, e.outcome]), verdict: evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: PAY, resource: CHARGES } }, [wa, wb]).verdict };
  };
  assert.deepEqual(await round(async () => {}), { b: [], verdict: 'pass' }, 'the control');
  assert.deepEqual(await round(() => post(ALIAS, { abort: true })), { b: [[PAY, CHARGES, 'unknown']], verdict: 'missing' }, 'an open alias send, under its destination');
  assert.deepEqual(await round(() => post(ALIAS)), { b: [[PAY, CHARGES, 'committed']], verdict: 'fail' });
  assert.deepEqual(await round(() => post(SIBLING)), { b: [[SIBLING, 'POST *', 'committed']], verdict: 'pass' }, 'the stated limit: a sibling in a presence-only recorder');
  assert.deepEqual(await round(() => post(SIBLING, { abort: true })), { b: [[SIBLING, 'POST *', 'unknown']], verdict: 'pass' }, 'the stated limit, open too');
});
