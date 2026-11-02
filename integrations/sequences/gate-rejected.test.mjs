// SEQ-REJ: a hold gate rule may declare the statuses its upstream answers only when it did not apply the call
// (rules[].rejected, opt-in). A call under that rule answered a declared status reads denied, so it leaves its window
// complete and an effect.none over it can pass; every other answer reads as before (2xx committed; an undeclared 4xx,
// a 5xx, a reset or an upstream error unknown; no answer yet started). Without a declaration the gate equals main's
// (test/fixtures/seq-gate-main-6a35f50/gate.mjs) in its scope and every window it collects, byte for byte.
// Everything runs on loopback with synthetic users; no model, provider or network outside 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createHoldGate } from './gate.mjs';
import { createHoldGate as createMainGate } from '../../test/fixtures/seq-gate-main-6a35f50/gate.mjs';
import { runSequence, SEQUENCE_SCHEMA } from './sequence.mjs';
import { validateSequenceRun } from './run-validator.mjs';
import { exitCodeOf } from './cli.mjs';
import { sequenceNativeRun, compareSequenceRuns } from './native.mjs';
import { collectWindow, evaluateEffectAssertion } from '../observers/events.mjs';
import { digest } from '../../src/domain.mjs';

const listen = async handler => { const s = createServer(handler); await new Promise(r => s.listen(0, '127.0.0.1', r)); return { url: `http://127.0.0.1:${s.address().port}`, close: () => new Promise(r => { s.close(r); s.closeAllConnections(); }) }; };
// Node frames a body for POST and PUT but not for GET or DELETE: a DELETE sent with one would end with bytes the gate reads as a
// broken next request, so the client sees a reset while the gate still forwards the DELETE, and the next call can overtake it.
// A call settles with its status once its reply closes, whole or cut off by the gate.
const call = (url, path, method = 'POST', signal) => new Promise((resolve, reject) => { const r = request(`${url}${path}`, { method, agent: false, signal }, res => { res.resume(); res.on('close', () => resolve(res.statusCode)); }); r.on('error', reject); r.end(['GET', 'DELETE'].includes(method) ? undefined : '{}'); });
// The status a client gets and whether its reply arrived in full: a reply cut off never ends, so it settles on close.
const reply = (url, path) => new Promise((resolve, reject) => { const r = request(`${url}${path}`, { method: 'POST', agent: false }, res => { res.resume(); res.on('error', () => {}); res.on('close', () => resolve([res.statusCode, res.complete])); }); r.on('error', reject); r.end('{}'); });
const none = { kind: 'effect.none', select: { source: 'hold-proxy', name: 'refund' } };
const shape = ({ instanceId, source, kind, scope }) => JSON.parse(JSON.stringify({ instanceId, source, kind, scope }));

// An upstream that answers each call with the next scripted answer: a status, 'reset' (before any answer), 'silent' (no answer)
// or { cut: status } (the status line and part of a body, then the connection reset).
async function scriptedUpstream() {
  const script = [], silent = [];
  const up = await listen((req, res) => { req.resume(); req.on('end', () => {
    const next = script.shift() ?? 200;
    if (next === 'reset') { req.socket.destroy(); return; }
    if (next === 'silent') { silent.push(res); return; }
    if (typeof next === 'object') { res.writeHead(next.cut, { 'content-length': '100' }); res.write('{"partial":'); setTimeout(() => req.socket.destroy(), 50); return; }
    res.writeHead(next).end('{}');
  }); });
  return { ...up, script };
}

test('SEQ-REJ validation: rules[].rejected takes up to 16 distinct 4xx statuses, never 408, 425, 429 or 499, checked when the gate is built', { timeout: 60000 }, () => {
  const build = (rejected, extra = []) => createHoldGate({ upstream: 'http://127.0.0.1:9', rules: [{ id: 'refund', pathPrefix: '/tool/refund', rejected }, ...extra] });
  const refused = [[200], [204], [302], [399], [500], [503], [600], [408], [425], [429], [499], ['403'], [403.5], [NaN], [null], [[403]], [403, 403], [403, 409, 403],
    Array.from({ length: 17 }, (_, i) => 400 + i + (i >= 8 ? 1 : 0)), 403, '403', {}, null, { 0: 403, length: 1 }];
  for (const rejected of refused) assert.throws(() => build(rejected), /"rejected" lists up to 16 distinct 4xx statuses/, JSON.stringify(rejected) ?? String(rejected));
  // A hole in a list built in code reads as a missing status, never skipped.
  const holed = [403]; holed[2] = 409;
  assert.throws(() => build(holed), /"rejected" lists/);
  // Sixteen distinct rejectable statuses are accepted, and every rejectable 4xx is.
  const sixteen = [400, 401, 402, 403, 404, 405, 406, 407, 409, 410, 411, 412, 413, 414, 415, 416];
  assert.deepEqual(build(sixteen).observer().scope.rejected, { refund: sixteen });
  for (let status = 400; status <= 499; status++) if (![408, 425, 429, 499].includes(status)) assert.deepEqual(build([status]).observer().scope.rejected, { refund: [status] });
  // Normalized ascending in the scope.
  assert.deepEqual(build([409, 403]).observer().scope.rejected, { refund: [403, 409] });
  // A declaring rule's id is its own; without a declaration (or with an empty one) a shared id is accepted as on main.
  assert.throws(() => build([403], [{ id: 'refund', pathPrefix: '/tool/other' }]), /declares "rejected", so no other rule may use its id/);
  assert.doesNotThrow(() => build([], [{ id: 'refund', pathPrefix: '/tool/other' }]));
  assert.doesNotThrow(() => createHoldGate({ upstream: 'http://127.0.0.1:9', rules: [{ id: 'refund', pathPrefix: '/a' }, { id: 'refund', pathPrefix: '/b' }] }));
  // "ungated" names the calls no rule matches: a declaring rule cannot take it, so a sealed ungated:denied always means a declaring
  // rule. Without a declaration (or with an empty one) the id is accepted as on main.
  assert.throws(() => createHoldGate({ upstream: 'http://127.0.0.1:9', rules: [{ id: 'ungated', pathPrefix: '/tool/refund', rejected: [403] }] }), /"ungated" names the calls no rule matches/);
  for (const rule of [{ id: 'ungated', pathPrefix: '/tool/refund' }, { id: 'ungated', pathPrefix: '/tool/refund', rejected: [] }])
    assert.equal(Object.hasOwn(createHoldGate({ upstream: 'http://127.0.0.1:9', rules: [rule] }).observer().scope, 'rejected'), false);
});

test('SEQ-REJ: a held call answered a declared 403 reads denied, its window is complete and effect.none passes; without the declaration it stays inconclusive', { timeout: 60000 }, async () => {
  for (const rejected of [[403], undefined]) {
    const up = await scriptedUpstream();
    const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'refund', pathPrefix: '/tool/refund', ...(rejected ? { rejected } : {}) }] }); await gate.start();
    const o = gate.observer();
    try {
      const pending = call(gate.url, '/tool/refund');
      const hold = await gate.awaitHold('refund', 5000);
      // The access change happens here; the window starts after it, with the call still held.
      const from = await o.mark();
      up.script.push(403);
      gate.release(hold);
      assert.equal(await pending, 403);
      const w = await collectWindow(o, from, await o.mark());
      assert.deepEqual(w.events.map(e => [e.name, e.outcome]), [['refund', rejected ? 'denied' : 'unknown']]);
      const verdict = evaluateEffectAssertion(none, [w]).verdict;
      if (rejected) { assert.equal(w.coverage, 'complete'); assert.equal(w.reason, null); assert.equal(verdict, 'pass'); }
      else { assert.equal(w.coverage, 'partial'); assert.equal(w.reason, 'action-in-flight-at-window-end'); assert.equal(verdict, 'missing'); }
    } finally { await up.close(); await gate.stop(); }
  }
});

test('SEQ-REJ: under a rule that declares 403, a 2xx is committed, an undeclared 4xx, a 5xx, a reset, a cut-off 403 and an unanswered call keep today\'s handling, and other rules are untouched', { timeout: 60000 }, async () => {
  const up = await scriptedUpstream();
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'refund', pathPrefix: '/tool/refund', holds: 0, rejected: [403] }, { id: 'approve', pathPrefix: '/v1/approve', holds: 0 }] }); await gate.start();
  const o = gate.observer();
  // One call per window. A call with no answer, or a cut-off reply (which the gate cuts off for the client too), is collected after
  // a pause, then aborted.
  const windowOf = async (path, answer) => {
    const from = await o.mark(); up.script.push(answer);
    const abort = new AbortController(), sent = call(gate.url, path, 'POST', abort.signal).catch(() => null);
    if (answer === 'silent' || typeof answer === 'object') await new Promise(r => setTimeout(r, 300));
    else await sent;
    const w = await collectWindow(o, from, await o.mark());
    abort.abort(); await sent;
    return { w };
  };
  try {
    // 2xx: committed, so effect.none fails.
    let { w } = await windowOf('/tool/refund', 200);
    assert.deepEqual([w.events.map(e => e.outcome), w.coverage, evaluateEffectAssertion(none, [w]).verdict], [['committed'], 'complete', 'fail']);
    // Undeclared 4xx, 5xx and a reset: unknown, the window partial, never a pass.
    for (const answer of [409, 401, 404, 500, 502, 503, 'reset']) {
      ({ w } = await windowOf('/tool/refund', answer));
      assert.deepEqual([w.events.map(e => e.outcome), w.coverage], [['unknown'], 'partial'], `answer ${answer}`);
      assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass', `answer ${answer}`);
    }
    // The declared status under the declaring rule, on a call that was never held: denied, complete, pass.
    ({ w } = await windowOf('/tool/refund', 403));
    assert.deepEqual([w.events.map(e => e.outcome), w.coverage, evaluateEffectAssertion(none, [w]).verdict], [['denied'], 'complete', 'pass']);
    // The declared status cut off after its status line (the reply never arrived in full): unknown, as a reset.
    ({ w } = await windowOf('/tool/refund', { cut: 403 }));
    assert.deepEqual([w.events.map(e => e.outcome), w.coverage], [['unknown'], 'partial']);
    assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass');
    // The same 403 under another rule, or ungated, is unknown.
    for (const path of ['/v1/approve', '/elsewhere']) {
      ({ w } = await windowOf(path, 403));
      assert.deepEqual([w.events.map(e => [e.name, e.outcome]), w.coverage], [[[path === '/v1/approve' ? 'approve' : 'ungated', 'unknown']], 'partial'], path);
    }
    // No answer by the window end (a timeout): started, the window partial.
    const { w: open } = await windowOf('/tool/refund', 'silent');
    assert.deepEqual([open.events.map(e => e.outcome), open.coverage, evaluateEffectAssertion(none, [open]).verdict], [['started'], 'partial', 'missing']);
  } finally { await up.close(); await gate.stop(); }
});

// A raw TCP upstream that answers every request with an HTTP/1.0 reply that has no length (its body ends when the connection
// closes): the status line, part of a body, then a reset ('rst') or a clean close ('fin').
async function closeDelimitedUpstream(status, close) {
  const s = createTcpServer(sock => {
    let head = '';
    sock.on('error', () => {});
    sock.on('data', d => { head += d; if (!sock.answered && head.includes('\r\n\r\n')) { sock.answered = true; sock.write(`HTTP/1.0 ${status} Refused\r\nContent-Type: application/json\r\n\r\n{"partial":`); setTimeout(() => close === 'rst' ? sock.resetAndDestroy() : sock.end(), 50); } });
  });
  await new Promise(r => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${s.address().port}`, close: () => new Promise(r => s.close(r)) };
}

test('rejected sequence send: a declared 403 without a length, reset mid-body, notes response, upstream-error and response-end and stays unknown; a clean close ends it', { timeout: 60000 }, async () => {
  for (const close of ['rst', 'fin']) {
    const up = await closeDelimitedUpstream(403, close);
    const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'refund', pathPrefix: '/tool/refund', holds: 0, rejected: [403] }] }); await gate.start();
    const o = gate.observer();
    try {
      const from = await o.mark();
      // The client gets the 403 cut off as the upstream cut it (an earlier review): a reset never reaches it as a whole reply.
      assert.deepEqual(await reply(gate.url, '/tool/refund'), [403, close === 'fin'], close);
      await new Promise(r => setTimeout(r, 100));
      const to = await o.mark(), w = await collectWindow(o, from, to);
      const after = gate.timeline.filter(e => e.seq > from.seq && e.seq <= to.seq).map(e => e.type);
      if (close === 'rst') {
        // Node's parser ends a reply without a length when its socket errors, so the reply reads complete and response-end is
        // noted; the upstream error noted for the same request still decides unknown.
        assert.deepEqual(after, ['forwarded', 'response', 'upstream-error', 'response-end']);
        assert.deepEqual([w.events.map(e => e.outcome), w.coverage, w.reason], [['unknown'], 'partial', 'action-in-flight-at-window-end']);
        assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass');
      } else {
        // A clean close is the end HTTP gives such a reply, as for forward.rejected: the declared status reads denied.
        assert.deepEqual(after, ['forwarded', 'response', 'response-end']);
        assert.deepEqual([w.events.map(e => e.outcome), w.coverage, evaluateEffectAssertion(none, [w]).verdict], [['denied'], 'complete', 'pass']);
      }
    } finally { await up.close(); await gate.stop(); }
  }
});

test('SEQ-REJ review m4: a declaration covers every call its rule names: another method, a call past its holds, a longer path under its prefix, an encoded path', { timeout: 60000 }, async () => {
  const up = await scriptedUpstream();
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'refund', method: 'POST', pathPrefix: '/tool/refund', holds: 1, rejected: [403] }] }); await gate.start();
  const o = gate.observer();
  try {
    // The one hold is used first and released, answered 403.
    up.script.push(403);
    const first = call(gate.url, '/tool/refund');
    gate.release(await gate.awaitHold('refund', 5000)); assert.equal(await first, 403);
    for (const [method, path] of [['GET', '/tool/refund'], ['POST', '/tool/refund'], ['POST', '/tool/refund-bulk'], ['POST', '/TOOL/%72efund']]) {
      const from = await o.mark(); up.script.push(403);
      assert.equal(await call(gate.url, path, method), 403, `${method} ${path}`);
      const w = await collectWindow(o, from, await o.mark());
      assert.deepEqual([w.events.map(e => [e.name, e.outcome]), w.coverage, evaluateEffectAssertion(none, [w]).verdict], [[['refund', 'denied']], 'complete', 'pass'], `${method} ${path}`);
    }
  } finally { await up.close(); await gate.stop(); }
});

// The held tool call of IC1: the app forwards Amy's refund to the tool service through the gate, which holds it; Amy is
// suspended; the call is released, and the tool service authorizes at commit. toolMode:
//   'commit-check'  refuses (403) a suspended agent and applies nothing (the repaired build)
//   'no-check'      applies every call and answers 200 (the defect)
//   'lies'          applies every call, and still answers 403 to a suspended agent (an upstream the declaration misdescribes)
const env = { SCOPEHAVEN_TARGET_SEQREJ_AMY: 'synthetic-amy-token-9', SCOPEHAVEN_TARGET_SEQREJ_BEN: 'synthetic-ben-token-9', SCOPEHAVEN_TARGET_SEQREJ_OLGA: 'synthetic-olga-token-9' };
const USERS = { [env.SCOPEHAVEN_TARGET_SEQREJ_AMY]: 'agent-amy', [env.SCOPEHAVEN_TARGET_SEQREJ_BEN]: 'agent-ben', [env.SCOPEHAVEN_TARGET_SEQREJ_OLGA]: 'owner-olga' };
const SEQ = Object.freeze({ schema: SEQUENCE_SCHEMA, id: 'HELD-TOOL-REFUSED', applicationId: 'seq-rej-fixture', contextId: 'seq-rej-synthetic-v1',
  actors: { amy: { principalId: 'agent-amy', credentialEnv: 'SCOPEHAVEN_TARGET_SEQREJ_AMY' }, ben: { principalId: 'agent-ben', credentialEnv: 'SCOPEHAVEN_TARGET_SEQREJ_BEN' }, olga: { principalId: 'owner-olga', credentialEnv: 'SCOPEHAVEN_TARGET_SEQREJ_OLGA' } },
  steps: [
    { request: { id: 'amy-refund', actorId: 'amy', method: 'POST', path: '/api/refunds', body: { ticket: 'T-1' }, timeoutMs: 15000 }, background: true },
    { awaitHold: { rule: 'refund', as: 'held' } },
    { request: { id: 'suspend-amy', actorId: 'olga', method: 'POST', path: '/api/admin/suspend', body: { userId: 'agent-amy' } } },
    { expectStatus: { request: 'suspend-amy', in: [200] } },
    { mark: 'suspended' },
    { release: { hold: 'held' } },
    { awaitResponse: { request: 'amy-refund' } },
    { mark: 'amy-done' },
    { request: { id: 'ben-refund', actorId: 'ben', method: 'POST', path: '/api/refunds', body: { ticket: 'T-2' }, timeoutMs: 15000 } },
    { mark: 'ben-done' }],
  assertions: [
    { id: 'INFLIGHT-REFUND', title: 'No refund applies through the tool after Amy is suspended', severity: 'critical', from: 'suspended', to: 'amy-done',
      effect: { kind: 'effect.none', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund' } } },
    { id: 'BEN-REFUND', title: 'Ben\'s refund applies through the tool exactly once', severity: 'control', from: 'amy-done', to: 'ben-done',
      effect: { kind: 'effect.count', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund' }, expected: 1 } }] });
const gateConfigOf = (upstream, rejected) => ({ upstream, rules: [{ id: 'refund', method: 'POST', pathPrefix: '/tool/refund', ...(rejected === undefined ? {} : { rejected }) }] });

async function heldToolRun({ toolMode, rejected, makeGate = createHoldGate }) {
  const suspended = new Set(), applied = { refund: 0 };
  const tools = await listen((req, res) => { req.resume(); req.on('end', () => {
    if (req.method !== 'POST' || req.url !== '/tool/refund') return res.writeHead(404).end();
    const actor = req.headers['x-actor'];
    if (toolMode === 'commit-check' && suspended.has(actor)) return res.writeHead(403).end('{}');
    applied.refund++;
    res.writeHead(toolMode === 'lies' && suspended.has(actor) ? 403 : 200).end('{}');
  }); });
  const gateConfig = gateConfigOf(tools.url, rejected), gate = makeGate(gateConfig);
  await gate.start();
  const app = await listen((req, res) => {
    const chunks = []; req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const user = USERS[/^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1]];
      if (!user || suspended.has(user)) return res.writeHead(401).end();
      const body = JSON.parse(Buffer.concat(chunks).toString() || '{}');
      if (req.method === 'POST' && req.url === '/api/admin/suspend' && user === 'owner-olga') { suspended.add(body.userId); return res.writeHead(200).end('{}'); }
      if (req.method !== 'POST' || req.url !== '/api/refunds') return res.writeHead(404).end();
      // The app itself does not re-check at commit: the tool service does.
      const out = request(`${gate.url}/tool/refund`, { method: 'POST', agent: false, headers: { 'x-actor': user, 'content-type': 'application/json' } }, up => { up.resume(); up.on('end', () => res.writeHead(up.statusCode).end('{}')); });
      out.on('error', () => res.writeHead(502).end());
      out.end(JSON.stringify({ ticket: body.ticket }));
    });
  });
  try {
    const run = await runSequence(SEQ, { origin: app.url, observers: [gate.observer()], gate, env });
    return { run, applied: { ...applied }, gateConfig };
  } finally { await app.close(); await tools.close(); await gate.stop(); }
}
const rowOf = (run, id) => run.results.find(r => r.id === id);

test('SEQ-REJ end to end: a tool service that refuses the held call at commit passes under a declared 403 and stays inconclusive without it; the defect still fails', { timeout: 60000 }, async () => {
  const repaired = await heldToolRun({ toolMode: 'commit-check', rejected: [403] });
  assert.equal(repaired.applied.refund, 1, 'only Ben\'s refund applied');
  const inflight = rowOf(repaired.run, 'INFLIGHT-REFUND');
  assert.deepEqual([inflight.status, inflight.verdict, inflight.custody, inflight.window.coverage[0].coverage], ['pass', 'pass', 'independent', 'complete']);
  assert.deepEqual(repaired.run.windows['suspended>amy-done'][0].events.map(e => [e.name, e.outcome]), [['refund', 'denied']]);
  assert.equal(rowOf(repaired.run, 'BEN-REFUND').status, 'pass');
  assert.equal(exitCodeOf(repaired.run), 0);
  // The declaration is sealed with the run: in the declared observer and in every window's scope.
  assert.deepEqual(repaired.run.observers[0].scope.rejected, { refund: [403] });
  assert.ok(Object.values(repaired.run.windows).every(ws => ws[0].scope.rejected?.refund?.[0] === 403));

  // The same repaired build without the declaration: today's reading, inconclusive (exit 3).
  const undeclared = await heldToolRun({ toolMode: 'commit-check' });
  const held = rowOf(undeclared.run, 'INFLIGHT-REFUND');
  assert.deepEqual([held.status, held.verdict, held.window.coverage[0].coverage, held.window.coverage[0].reason], ['inconclusive', 'missing', 'partial', 'action-in-flight-at-window-end']);
  assert.equal(exitCodeOf(undeclared.run), 3);
  assert.equal(Object.hasOwn(undeclared.run.observers[0].scope, 'rejected'), false);
  // A declaration that does not list the status answered decides nothing either.
  assert.equal(rowOf((await heldToolRun({ toolMode: 'commit-check', rejected: [409] })).run, 'INFLIGHT-REFUND').status, 'inconclusive');

  // The defect applies the held refund and answers 200: it still fails, declaration or not.
  for (const rejected of [[403], undefined]) {
    const defect = await heldToolRun({ toolMode: 'no-check', rejected });
    assert.equal(defect.applied.refund, 2);
    assert.deepEqual([rowOf(defect.run, 'INFLIGHT-REFUND').status, exitCodeOf(defect.run)], ['fail', 1]);
  }
});

test('SEQ-REJ end to end: a saved run validates bound to its gate configuration, the declaration is part of that binding, and runs with and without it never compare', { timeout: 60000 }, async () => {
  const declared = await heldToolRun({ toolMode: 'commit-check', rejected: [403] });
  const plain = await heldToolRun({ toolMode: 'commit-check' });
  const expected = config => [shape(createHoldGate(config).observer())];
  validateSequenceRun(declared.run, { expectedSequence: SEQ, expectedObservers: expected(declared.gateConfig) });
  validateSequenceRun(plain.run, { expectedSequence: SEQ, expectedObservers: expected(plain.gateConfig) });
  // A run recorded under the declaration is not one recorded without it, and the other way round.
  assert.throws(() => validateSequenceRun(declared.run, { expectedObservers: expected(gateConfigOf(declared.gateConfig.upstream)) }), e => e.code === 'unexpected-observers');
  assert.throws(() => validateSequenceRun(plain.run, { expectedObservers: expected(gateConfigOf(plain.gateConfig.upstream, [403])) }), e => e.code === 'unexpected-observers');
  assert.throws(() => validateSequenceRun(declared.run, { expectedObservers: expected(gateConfigOf(declared.gateConfig.upstream, [403, 409])) }), e => e.code === 'unexpected-observers');
  // As native runs for the regression gate: the observers (scope included) are part of the profile identity.
  const native = (run, build) => sequenceNativeRun({ sequence: SEQ, run, build });
  const across = compareSequenceRuns(native(plain.run, 'commit-check'), native(declared.run, 'commit-check-declared'));
  assert.ok(across.rows.every(r => r.transition === 'incompatible'), JSON.stringify(across.rows.map(r => r.transition)));
  assert.ok(across.reasons.some(r => r.startsWith('profileHash differs')), JSON.stringify(across.reasons));
  const again = await heldToolRun({ toolMode: 'commit-check', rejected: [403] });
  const same = compareSequenceRuns(native(declared.run, 'a'), native(again.run, 'b'));
  assert.ok(!same.reasons.some(r => r.startsWith('profileHash')), JSON.stringify(same.reasons));
});

test('SEQ-REJ residual (operator trust): an upstream that applies the call and still answers a declared status reads denied, so the gate passes what was applied', { timeout: 60000 }, async () => {
  // The gate cannot see what the upstream did, only what it answered. Declaring 403 asserts the upstream never answers 403
  // after applying; this upstream breaks that assertion, and the row passes while the refund applied. Documented in the
  // sequences README and KNOWN-LIMITS; without the declaration the same run reads inconclusive.
  const lying = await heldToolRun({ toolMode: 'lies', rejected: [403] });
  assert.equal(lying.applied.refund, 2, 'Amy\'s held refund applied');
  // Custody follows the gate's record, not who chose the answer: the row still reads independent.
  assert.deepEqual([rowOf(lying.run, 'INFLIGHT-REFUND').status, rowOf(lying.run, 'INFLIGHT-REFUND').custody], ['pass', 'independent']);
  assert.equal(rowOf((await heldToolRun({ toolMode: 'lies' })).run, 'INFLIGHT-REFUND').status, 'inconclusive');
});

test('SEQ-REJ inert: the frozen main copy is main\'s gate.mjs at 6a35f50 with only its imports re-pointed', { timeout: 60000 }, async () => {
  const frozen = await readFile(new URL('../../test/fixtures/seq-gate-main-6a35f50/gate.mjs', import.meta.url), 'utf8');
  const restored = frozen.split('\n').slice(3).join('\n').replace("from '../../../src/domain.mjs'", "from '../../src/domain.mjs'").replace("from '../../../integrations/observers/events.mjs'", "from '../observers/events.mjs'");
  assert.equal(createHash('sha256').update(restored).digest('hex'), '46e70410736f3c02a8ce5750efc83205838e835292c9c3a43edfeeea56756396');
});

// A synthetic gate timeline covering every status from 100 to 599 under a declaring rule, another rule and no rule, plus
// held, released, dropped, abandoned, failed and unanswered calls, declared statuses cut off after their status line, and
// answers that land in a later window. A reply that arrived in full is followed by its response-end entry (the real gate notes
// one only for a declared status under the declaring rule; main and an undeclared gate ignore them). `entries` is main's
// shape; `recorded` is the same timeline as the live gate records it, each held and forwarded entry with a method and method
// overrides (an earlier review, Minor 2), so an observer that read either would fail the byte-for-byte tests below.
const VERBS = ['POST', 'PUT', 'PATCH', 'DELETE', 'GET', 'OPTIONS', 'PROPFIND'], OVERRIDES = [[], ['DELETE'], ['patch', 'GET']];
function syntheticTimeline() {
  const entries = []; let seq = 0, t = 1760000000000000000n, n = 0;
  const add = e => { entries.push({ seq: ++seq, t: String(t += 1000003n), ...e }); return seq; };
  const ids = () => { n++; return { reqId: `req-${n}`, pathDigest: digest(`/tool/${n}`) }; };
  const answer = (reqId, ruleId, holdId, status, pathDigest, full = true) => { add({ type: 'response', reqId, ruleId, holdId, status, pathDigest }); if (full) add({ type: 'response-end', reqId, ruleId, holdId, pathDigest }); };
  for (let status = 100; status <= 599; status++) for (const ruleId of ['refund', 'approve', null]) {
    const { reqId, pathDigest } = ids();
    add({ type: 'forwarded', reqId, ruleId, holdId: null, pathDigest });
    answer(reqId, ruleId, null, status, pathDigest);
  }
  for (const [status, full] of [[403, true], [409, true], [200, true], [500, true], [403, false], [409, false]]) {
    const { reqId, pathDigest } = ids(), holdId = `hold-${n}`;
    add({ type: 'held', reqId, ruleId: 'refund', holdId, pathDigest, bodyDigest: digest('e30=') });
    add({ type: 'released', ruleId: 'refund', holdId });
    add({ type: 'forwarded', reqId, ruleId: 'refund', holdId, pathDigest });
    answer(reqId, 'refund', holdId, status, pathDigest, full);
  }
  for (const status of [403, 409]) { const { reqId, pathDigest } = ids(); add({ type: 'forwarded', reqId, ruleId: 'refund', holdId: null, pathDigest }); answer(reqId, 'refund', null, status, pathDigest, false); }
  // An upstream error beside a response-end (a reply without a length reset mid-body, and the reverse order): unknown either way.
  const errored = [];
  for (const [status, order] of [[403, ['response', 'upstream-error', 'response-end']], [409, ['response', 'response-end', 'upstream-error']]]) {
    const { reqId, pathDigest } = ids(); errored.push(reqId);
    add({ type: 'forwarded', reqId, ruleId: 'refund', holdId: null, pathDigest });
    for (const type of order) add({ type, reqId, ruleId: 'refund', holdId: null, ...(type === 'response' ? { status } : {}), pathDigest });
  }
  { const { reqId, pathDigest } = ids(); add({ type: 'forwarded', reqId, ruleId: 'refund', holdId: null, pathDigest }); add({ type: 'upstream-error', reqId, ruleId: 'refund', holdId: null, pathDigest }); }
  { const { reqId, pathDigest } = ids(), holdId = `hold-${n}`; add({ type: 'held', reqId, ruleId: 'refund', holdId, pathDigest, bodyDigest: digest('') }); add({ type: 'dropped', ruleId: 'refund', holdId }); }
  { const { reqId, pathDigest } = ids(), holdId = `hold-${n}`; add({ type: 'held', reqId, ruleId: 'refund', holdId, pathDigest, bodyDigest: digest('') }); add({ type: 'client-closed-while-held', ruleId: 'refund', holdId }); }
  // Sent before the split, answered in full after it (403, 200 and 409), and one never answered.
  const split = [];
  for (const status of [403, 200, 409]) { const { reqId, pathDigest } = ids(); add({ type: 'forwarded', reqId, ruleId: 'refund', holdId: null, pathDigest }); split.push({ reqId, pathDigest, status }); }
  const mid = seq;
  for (const { reqId, pathDigest, status } of split) answer(reqId, 'refund', null, status, pathDigest);
  { const { reqId, pathDigest } = ids(); add({ type: 'forwarded', reqId, ruleId: 'refund', holdId: null, pathDigest }); }
  const recorded = entries.map((e, i) => e.type === 'held' || e.type === 'forwarded' ? { ...e, method: VERBS[i % VERBS.length], methodOverrides: OVERRIDES[i % OVERRIDES.length] } : e);
  return { entries, recorded, mid, last: seq, errored };
}
// The live gate is fed the timeline it records; main, the same timeline without the fields main never wrote.
const asRecorded = timeline => ({ ...timeline, entries: timeline.recorded });
const RULES = [{ id: 'refund', pathPrefix: '/tool/refund' }, { id: 'approve', pathPrefix: '/v1/approve' }];
async function collectAll(make, rules, { entries, mid, last }) {
  const gate = make({ upstream: 'http://127.0.0.1:9', rules }); await gate.start();
  try {
    gate.timeline.length = 0; gate.timeline.push(...entries.map(e => ({ ...e })));
    const o = gate.observer(), out = { scope: shape(o) };
    // Whole, split at the late answers, the late answers alone, a window that ends between a declared 403 and its reply's end, and a slice.
    for (const [from, to] of [[0, last], [0, mid], [mid, last], [mid, mid + 6], [mid, mid + 1], [3, 9]]) {
      out[`${from}>${to}`] = { raw: await o.collect({ seq: from }, { seq: to }), window: await collectWindow(o, { seq: from }, { seq: to }) };
    }
    return out;
  } finally { await gate.stop(); }
}

test('SEQ-REJ inert: with no declaration, or an empty one, the gate\'s scope and every window it collects equal main\'s byte for byte', { timeout: 60000 }, async () => {
  const timeline = syntheticTimeline();
  assert.ok(timeline.recorded.filter(e => Object.hasOwn(e, 'method')).length > 1500 && new Set(timeline.recorded.map(e => e.method)).size === VERBS.length + 1);
  const main = JSON.stringify(await collectAll(createMainGate, RULES, timeline));
  assert.equal(JSON.stringify(await collectAll(createHoldGate, RULES, asRecorded(timeline))), main);
  assert.equal(JSON.stringify(await collectAll(createHoldGate, RULES.map(r => ({ ...r, rejected: [] })), asRecorded(timeline))), main);
  // Main itself ignores a "rejected" key: the declaration is new, so a config written for it reads unknown on main.
  assert.equal(JSON.stringify(await collectAll(createMainGate, RULES.map(r => r.id === 'refund' ? { ...r, rejected: [403] } : r), timeline)), main);
  // A real gate's scope without a declaration: exactly main's four keys.
  assert.deepEqual(Object.keys(createHoldGate({ upstream: 'http://127.0.0.1:9', rules: RULES }).observer().scope), ['operations', 'names', 'actorAttribution', 'evidence']);
});

test('SEQ-REJ: with a declaration the only differences from main are the scope\'s rejected map and declared refusals under the declaring rule reading denied', { timeout: 60000 }, async () => {
  const timeline = syntheticTimeline();
  const main = await collectAll(createMainGate, RULES, timeline);
  const declared = await collectAll(createHoldGate, RULES.map(r => r.id === 'refund' ? { ...r, rejected: [409, 403] } : r), asRecorded(timeline));
  const { rejected, ...scope } = declared.scope.scope;
  assert.deepEqual(rejected, { refund: [403, 409] });
  assert.deepEqual({ ...declared.scope, scope }, main.scope);
  // The oracle: the answer that ends each event's request within the window, and whether that reply ended in full there (the
  // test's own record, not the gate's).
  const statusIn = (from, to) => { const end = new Map(); for (const e of timeline.entries) if (e.seq > from && e.seq <= to && (e.type === 'response' || e.type === 'upstream-error')) end.set(e.reqId, e); return end; };
  const fullIn = (from, to) => new Set(timeline.entries.filter(e => e.seq > from && e.seq <= to && e.type === 'response-end').map(e => e.reqId));
  const reqAt = new Map(timeline.entries.map(e => [e.seq, e.reqId]));
  let flipped = 0;
  for (const key of Object.keys(main).filter(k => k !== 'scope')) {
    const [from, to] = key.split('>').map(Number), end = statusIn(from, to), full = fullIn(from, to);
    for (const part of ['raw', 'window']) {
      const a = main[key][part], b = declared[key][part];
      assert.equal(b.events.length, a.events.length, key);
      b.events.forEach((e, i) => {
        const before = a.events[i], stop = end.get(reqAt.get(e.seq));
        const flips = before.name === 'refund' && stop?.type === 'response' && [403, 409].includes(stop.status) && full.has(stop.reqId);
        assert.deepEqual({ ...e, outcome: null }, { ...before, outcome: null }, `${key} ${part} event ${i}`);
        assert.equal(e.outcome, flips ? 'denied' : before.outcome, `${key} ${part} event ${i}`);
        if (flips) { assert.equal(before.outcome, 'unknown'); flipped++; }
      });
    }
    // The window keeps main's coverage unless every unknown or started event it had was a declared refusal.
    const remaining = declared[key].window.events.some(e => e.outcome === 'unknown' || e.outcome === 'started');
    assert.equal(declared[key].window.coverage, remaining ? main[key].window.coverage : 'complete', key);
  }
  assert.ok(flipped >= 8, `declared refusals flipped: ${flipped}`);
  // The late answers alone (a declared 403, a 200 and a declared 409, each in full, to calls sent before the window): main reads
  // the window partial, the declaration complete.
  const late = `${timeline.mid}>${timeline.mid + 6}`;
  assert.deepEqual(declared[late].window.events.map(e => e.outcome), ['denied', 'committed', 'denied']);
  assert.deepEqual([main[late].window.coverage, declared[late].window.coverage], ['partial', 'complete']);
  // A window that ends after a declared 403's status line but before its reply ended: unknown, partial.
  const cut = `${timeline.mid}>${timeline.mid + 1}`;
  assert.deepEqual([declared[cut].window.events.map(e => e.outcome), declared[cut].window.coverage], [['unknown'], 'partial']);
  // The declared statuses cut off in the whole window stay unknown: two held and two direct.
  const whole = `0>${timeline.last}`, cutOff = declared[whole].raw.events.filter(e => e.name === 'refund' && e.outcome === 'unknown');
  assert.ok(cutOff.length >= 5, `refund events still unknown: ${cutOff.length}`);
  // Review M1: an upstream error beside a response-end decides unknown, in either order.
  const seqOf = new Map(timeline.entries.filter(e => e.type === 'forwarded').map(e => [e.reqId, e.seq]));
  for (const reqId of timeline.errored) assert.equal(declared[whole].raw.events.find(e => e.seq === seqOf.get(reqId))?.outcome, 'unknown', reqId);
});

test('SEQ-REJ inert on the wire: without a declaration the gate records the same timeline as main for the same traffic, plus each request\'s method and method overrides; with one it adds only response-end entries', { timeout: 60000 }, async () => {
  // The held call is answered 200; then [path, answer, method] in turn (POST unless named).
  const calls = [['/tool/refund', 403], ['/tool/refund', 409, 'PUT'], ['/tool/refund', 500], ['/tool/refund', 'reset'], ['/elsewhere', 403, 'DELETE'], ['/tool/refund', 201]];
  const record = async (make, rejected) => {
    const up = await scriptedUpstream();
    const gate = make({ upstream: up.url, rules: [{ id: 'refund', pathPrefix: '/tool/refund', holds: 1, ...(rejected ? { rejected } : {}) }] }); await gate.start();
    try {
      // One held call, released, then forwarded calls; each answered in turn.
      up.script.push(200, ...calls.map(([, answer]) => answer));
      const first = call(gate.url, '/tool/refund').catch(() => null);
      gate.release(await gate.awaitHold('refund', 5000)); await first;
      for (const [path, , method] of calls) await call(gate.url, path, method).catch(() => null);
    } finally { await up.close(); await gate.stop(); }
    // Times and random ids differ between runs; everything else is compared.
    return gate.timeline.map(({ t: _t, reqId: _r, holdId, ...e }) => ({ ...e, holdId: holdId === undefined ? undefined : holdId === null ? null : 'hold' }));
  };
  const main = await record(createMainGate);
  // The live gate records each held and forwarded request's method and method overrides (none here), which main does not;
  // every other field is main's.
  const withoutMethod = timeline => timeline.map(({ method: _m, methodOverrides: _o, ...e }) => e);
  const live = await record(createHoldGate);
  assert.deepEqual(live.filter(e => Object.hasOwn(e, 'method')).map(e => [e.type, e.method]), [['held', 'POST'], ['forwarded', 'POST'], ...calls.map(([, , method]) => ['forwarded', method ?? 'POST'])]);
  assert.deepEqual(live.filter(e => Object.hasOwn(e, 'methodOverrides')).map(e => [e.type, e.methodOverrides]), live.filter(e => Object.hasOwn(e, 'method')).map(e => [e.type, []]));
  assert.deepEqual(withoutMethod(live), main);
  assert.deepEqual(withoutMethod(await record(createHoldGate, [])), main);
  const declared = withoutMethod(await record(createHoldGate, [403, 409]));
  const ends = declared.filter(e => e.type === 'response-end');
  assert.deepEqual(declared.filter(e => e.type !== 'response-end').map(({ seq: _s, ...e }) => e), main.map(({ seq: _s, ...e }) => e));
  // One response-end per declared refusal under the declaring rule: the 403 and the 409 to /tool/refund (the 403 to /elsewhere is ungated).
  assert.deepEqual(ends.map(e => e.ruleId), ['refund', 'refund']);
  assert.deepEqual(declared.filter((e, i) => declared[i + 1]?.type === 'response-end').map(e => [e.type, e.status]), [['response', 403], ['response', 409]]);
});
