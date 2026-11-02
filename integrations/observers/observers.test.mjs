import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { connect } from 'node:net';
import { gzipSync } from 'node:zlib';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, statSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir, loadavg, cpus } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { makeEffect, evaluateEffectAssertion, validateEffect, validateWindow, collectWindow, validateEffectAssertion, EffectError } from './events.mjs';
import { createOtelObserver, toolSpan, normalizeId } from './otel.mjs';
import { createMcpHttpProxy, createMcpObserver, framesOf, FrameLog } from './mcp.mjs';
import { createSqliteSnapshotObserver, createSqliteAuditObserver } from './sqlite.mjs';
import { createHttpAuditObserver } from './audit-http.mjs';
import { digest } from '../../src/domain.mjs';

const N = process.execPath;
const observer = { kind: 'test', instanceId: 't-1' };
const AUDIT_SCOPE = { operations: ['insert', 'update', 'delete', 'tool-call', 'access-change'], names: ['note.create', 'refund.request'], actorAttribution: 'principal', evidence: 'authoritative' };
const ev = (seq, over = {}) => makeEffect({ source: 'sql-audit-table', observer, seq, actor: 'agent-sam', operation: 'insert', name: 'note.create', outcome: 'committed', ...over });
const win = (coverage, events = [], over = {}) => ({ source: 'sql-audit-table', instanceId: over.instanceId ?? 't-1', scope: AUDIT_SCOPE, coverage, events, ...over });
const snapWin = (coverage, events = []) => ({ source: 'sql-snapshot', instanceId: 'snap', scope: { operations: ['insert', 'update', 'delete'], names: ['notes'], actorAttribution: 'none', evidence: 'authoritative' }, coverage, events });
const none = { kind: 'effect.none', select: { actor: 'agent-sam', name: 'note.create' } };

function post(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
    const r = request(url, { method: 'POST', agent: false, headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length, ...headers } }, res => { const c = []; res.on('data', d => c.push(d)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(c).toString() })); });
    r.on('error', reject); r.end(payload);
  });
}
const listen = async handler => { const s = createServer(handler); await new Promise(r => s.listen(0, '127.0.0.1', r)); return { url: `http://127.0.0.1:${s.address().port}`, close: () => new Promise(r => { s.close(r); s.closeAllConnections(); }) } };

// ---- verdict rules ----------------------------------------------------------
test('effect.none passes only when every observer that can see the effect is complete', () => {
  assert.equal(evaluateEffectAssertion(none, [win('complete')]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(none, [win('partial')]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion(none, [win('failed')]).verdict, 'observer-failure');
  assert.equal(evaluateEffectAssertion(none, []).verdict, 'unobservable');
  assert.equal(evaluateEffectAssertion(none, [win('partial', [ev(1)])]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(none, [win('complete', [ev(1, { outcome: 'denied' })])]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(none, [win('complete', [ev(1, { actor: 'owner-olga' })])]).verdict, 'pass');
});
test('a complete observer that cannot see the effect does not hide a failed or partial one that can', () => {
  // The snapshot watches notes only and cannot attribute actors; the audit observer can see the effect.
  assert.equal(evaluateEffectAssertion(none, [snapWin('net-only'), win('failed', [], { instanceId: 'audit' })]).verdict, 'observer-failure');
  assert.equal(evaluateEffectAssertion(none, [snapWin('net-only'), win('partial', [], { instanceId: 'audit' })]).verdict, 'missing');
  // Two observers that both see it: one complete, one partial, still not a pass.
  assert.equal(evaluateEffectAssertion(none, [win('complete', [], { instanceId: 'a' }), win('partial', [], { instanceId: 'b' })]).verdict, 'missing');
  // Only the snapshot, which cannot attribute actors: unobservable, never pass.
  assert.equal(evaluateEffectAssertion(none, [snapWin('net-only')]).verdict, 'unobservable');
});
test('a net-only snapshot never supports "did not happen", and unwatched tables are unobservable', () => {
  const insert = { kind: 'effect.none', select: { source: 'sql-snapshot', name: 'notes', operation: 'insert' } };
  assert.equal(evaluateEffectAssertion(insert, [snapWin('net-only')]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'refunds' } }, [snapWin('net-only')]).verdict, 'unobservable');
  const seen = makeEffect({ source: 'sql-snapshot', observer: { kind: 'x', instanceId: 'snap' }, seq: 1, operation: 'insert', name: 'notes', outcome: 'committed' });
  assert.equal(evaluateEffectAssertion(insert, [snapWin('net-only', [seen])]).verdict, 'fail');
});
test('effect.exists and effect.count need complete coverage, and a count needs one named source', () => {
  const exists = { kind: 'effect.exists', select: { name: 'note.create' } };
  assert.equal(evaluateEffectAssertion(exists, [win('partial', [ev(1)])]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(exists, [win('partial')]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion(exists, [win('complete')]).verdict, 'fail');
  const count = { kind: 'effect.count', select: { source: 'sql-audit-table', name: 'note.create' }, expected: 2 };
  assert.equal(evaluateEffectAssertion(count, [win('complete', [ev(1), ev(2)])]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(count, [win('complete', [ev(1)])]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(count, [win('partial', [ev(1), ev(2)])]).verdict, 'missing');
  assert.throws(() => validateEffectAssertion({ kind: 'effect.count', select: { name: 'note.create' }, expected: 1 }), /effect-count-needs-source/);
});
test('events reject content-bearing or malformed fields; windows reject bad scope, order or foreign events', () => {
  assert.throws(() => validateEffect({ ...ev(1), body: 'secret' }), EffectError);
  assert.throws(() => validateEffect({ ...ev(1), contentDigest: 'not-a-digest' }), EffectError);
  assert.throws(() => validateEffect({ ...ev(1), name: 'a\nb' }), EffectError);
  assert.throws(() => validateWindow(win('complete', [ev(2), ev(1)])), /seq-order/);
  assert.throws(() => validateWindow({ ...win('complete', [ev(1)]), source: 'otel-genai', scope: { ...AUDIT_SCOPE, evidence: 'presence-only' } }), /source-mismatch/);
  assert.throws(() => validateWindow({ ...win('complete'), scope: { operations: [], names: null, actorAttribution: 'principal' } }), /scope/);
  assert.equal(makeEffect({ source: 'mcp-jsonrpc', observer, seq: 1, operation: 'tool-call', name: 'x', outcome: 'committed', content: { password: 'p' } }).contentDigest.length, 64);
});
test('collectWindow: a throwing observer is failed, and an action in flight at the window end makes it partial', async () => {
  const bad = { source: 'sql-audit-table', instanceId: 'b', scope: AUDIT_SCOPE, collect: async () => ({ events: [{ nonsense: true }], coverage: 'complete' }) };
  assert.equal((await collectWindow(bad, {}, {})).coverage, 'failed');
  const inflight = { source: 'sql-audit-table', instanceId: 't-1', scope: AUDIT_SCOPE, collect: async () => ({ events: [ev(1, { outcome: 'started' })], coverage: 'complete' }) };
  const w = await collectWindow(inflight, {}, {});
  assert.equal(w.coverage, 'partial'); assert.equal(w.reason, 'action-in-flight-at-window-end');
});

// ---- OpenTelemetry ----------------------------------------------------------
const attr = (key, value) => ({ key, value: { stringValue: value } });
const spanOf = (attributes, over = {}) => ({ traceId: '0af7651916cd43dd8448eb211c80319c', spanId: 'b7ad6b7169203331', startTimeUnixNano: '1000', endTimeUnixNano: '2000', status: { code: 1 }, attributes, ...over });
const tool = (name, actor) => [attr('gen_ai.operation.name', 'execute_tool'), attr('gen_ai.tool.name', name), attr('enduser.id', actor)];
const otlp = (service, spans) => ({ resourceSpans: [{ resource: { attributes: [attr('service.name', service)] }, scopeSpans: [{ spans }] }] });
const hex = (n, i) => String(i).padStart(n * 2, '0');
const marker = (spanId, at) => spanOf([{ key: 'scopehaven.quiescent', value: { boolValue: true } }], { spanId, startTimeUnixNano: String(at), endTimeUnixNano: String(at) });
test('tool spans are recognised across GenAI, OpenInference, Vercel legacy and MCP naming; other spans are ignored', () => {
  assert.equal(toolSpan(spanOf(tool('refund', 'u1')), {}).name, 'refund');
  assert.equal(toolSpan(spanOf([attr('openinference.span.kind', 'TOOL'), attr('tool.name', 'refund'), attr('user.id', 'u1')]), {}).actor, 'u1');
  assert.equal(toolSpan(spanOf([attr('ai.toolCall.name', 'refund')]), {}).name, 'refund');
  assert.equal(toolSpan(spanOf([attr('mcp.method.name', 'tools/call'), attr('gen_ai.tool.name', 'refund')]), {}).name, 'refund');
  assert.equal(toolSpan(spanOf([attr('gen_ai.operation.name', 'chat')]), {}), null);
  assert.equal(toolSpan(spanOf(tool('x', 'u'), { status: { code: 2 } }), {}).outcome, 'error');
  assert.equal(normalizeId(Buffer.from('0af7651916cd43dd8448eb211c80319c', 'hex').toString('base64'), 16), '0af7651916cd43dd8448eb211c80319c');
  assert.throws(() => createOtelObserver({}), /services/);
});
test('OTLP receiver: JSON and gzip accepted, protobuf and junk rejected, coverage only from the declared service flushing past the window', async () => {
  const o = createOtelObserver({ services: ['app'], principals: ['agent-sam'], settleMs: 100 }); await o.start();
  try {
    const from = await o.mark(), at = n => String(from.at + BigInt(n));
    assert.equal((await post(o.endpoint, otlp('app', [spanOf(tool('add_note', 'agent-sam'), { spanId: hex(8, 1), startTimeUnixNano: at(10), endTimeUnixNano: at(20) })]))).status, 200);
    const to = { at: from.at + 1000000n, seq: 0 };
    let w = await collectWindow(o, from, to);
    assert.equal(w.coverage, 'partial'); assert.equal(w.events.length, 1); assert.equal(w.events[0].actor, 'agent-sam');
    // Tool spans from a service that is not the target are not the target's effects.
    await post(o.endpoint, otlp('other-tenant', [spanOf(tool('refund', 'mallory'), { spanId: hex(8, 4), startTimeUnixNano: at(30), endTimeUnixNano: at(40) })]));
    assert.ok(!(await collectWindow(o, from, to)).events.some(e => e.actor === 'mallory'));
    // Another service flushing past the window proves nothing about the target.
    await post(o.endpoint, otlp('other-tenant', [spanOf([attr('gen_ai.operation.name', 'chat')], { spanId: hex(8, 2), startTimeUnixNano: String(to.at + 5n), endTimeUnixNano: String(to.at + 6n) })]));
    assert.equal((await collectWindow(o, from, to)).coverage, 'partial');
    // An ordinary span ending after the window proves nothing about spans still open.
    await post(o.endpoint, otlp('app', [spanOf([attr('gen_ai.operation.name', 'chat')], { spanId: hex(8, 5), startTimeUnixNano: String(to.at + 5n), endTimeUnixNano: String(to.at + 6n) })]));
    assert.equal((await collectWindow(o, from, to)).coverage, 'partial');
    // The declared exporter's quiescence marker, started after the window end, does.
    const late = otlp('app', [marker(hex(8, 3), to.at + 7n)]);
    assert.equal((await post(o.endpoint, gzipSync(JSON.stringify(late)), { 'Content-Encoding': 'gzip' })).status, 200);
    w = await collectWindow(o, from, to);
    assert.equal(w.coverage, 'complete');
    // Rejected exports (protobuf, junk) may have carried target spans: windows become partial.
    assert.equal((await post(o.endpoint, Buffer.from('x'), { 'Content-Type': 'application/x-protobuf' })).status, 415);
    assert.equal((await post(o.endpoint, Buffer.from('{not json'))).status, 400);
    assert.equal(o.stats().rejectedRequests, 2);
    assert.equal((await collectWindow(o, from, to)).reason, 'rejected-trace-export');
  } finally { await o.stop(); }
});
// A malformed request target is answered, never thrown out of the listener.
const rawRequest = (port, head) => new Promise((resolve, reject) => {
  const socket = connect(port, '127.0.0.1', () => socket.end(`${head}\r\nHost: 127.0.0.1:${port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`));
  const chunks = []; socket.on('data', c => chunks.push(c)); socket.on('error', reject); socket.on('close', () => resolve(Buffer.concat(chunks).toString('latin1').split('\r\n')[0]));
});
test('OTLP receiver answers a target that is no URL (//%zz) or names another authority with 404, and still takes /v1/traces', async () => {
  const o = createOtelObserver({ services: ['app'], settleMs: 50 }); await o.start();
  try {
    const port = Number(new URL(o.endpoint).port);
    for (const target of ['//%zz', '//', '//evil/v1/traces', '/\\%zz', 'http://127.0.0.1/v1/traces']) assert.equal(await rawRequest(port, `POST ${target} HTTP/1.1`), 'HTTP/1.1 404 Not Found', target);
    const from = await o.mark();
    const span = (i, at) => otlp('app', [spanOf(tool('add_note', 'agent-sam'), { spanId: hex(8, i), startTimeUnixNano: String(from.at + at), endTimeUnixNano: String(from.at + at + 1n) })]);
    assert.equal((await post(o.endpoint, span(1, 10n))).status, 200);
    assert.equal((await post(`${o.endpoint}?exporter=1`, span(2, 20n))).status, 200, 'a query string still names /v1/traces');
    assert.equal((await collectWindow(o, from, { at: from.at + 1000n, seq: 0 })).events.length, 2);
    assert.equal(o.stats().rejectedRequests, 0);
  } finally { await o.stop(); }
});
test('a future-dated span is rejected and cannot complete later windows', async () => {
  const o = createOtelObserver({ services: ['app'], settleMs: 50 }); await o.start();
  try {
    const now = await o.mark();
    await post(o.endpoint, otlp('app', [marker(hex(8, 9), now.at + 10n ** 15n)]));
    // A marker even one second ahead of its arrival is rejected (cap 250 ms).
    await post(o.endpoint, otlp('app', [marker(hex(8, 10), now.at + 10n ** 9n)]));
    assert.equal(o.stats().skewedSpans, 2);
    const a = await o.mark(), b = await o.mark();
    assert.equal((await collectWindow(o, a, b)).coverage, 'partial');
  } finally { await o.stop(); }
});
test('duplicate spans are counted once; span overflow is partial', async () => {
  const o = createOtelObserver({ services: ['app'], tools: ['refund', 't'], settleMs: 50, maxSpans: 3 }); await o.start();
  try {
    const from = await o.mark(), at = n => String(from.at + BigInt(n));
    const once = spanOf(tool('refund', 'sam'), { spanId: '2222222222222222', startTimeUnixNano: at(1), endTimeUnixNano: at(2) });
    await post(o.endpoint, otlp('app', [once])); await post(o.endpoint, otlp('app', [once]));
    const mid = await o.mark();
    await post(o.endpoint, otlp('app', [marker(hex(8, 7), mid.at + 1n)]));
    let w = await collectWindow(o, from, mid);
    assert.equal(w.events.length, 1); assert.equal(o.stats().duplicateSpans, 1);
    // Traces are presence-only: they can never decide an exact count.
    assert.equal(evaluateEffectAssertion({ kind: 'effect.count', select: { source: 'otel-genai', name: 'refund' }, expected: 2 }, [w]).verdict, 'unobservable');
    const spans = [1, 2, 3, 4].map(i => spanOf(tool('t', 'sam'), { spanId: hex(8, 100 + i), startTimeUnixNano: String(mid.at + 10n), endTimeUnixNano: String(mid.at + 20n) }));
    await post(o.endpoint, otlp('app', spans));
    const to = await o.mark();
    await post(o.endpoint, otlp('app', [marker(hex(8, 200), to.at + 1n)]));
    w = await collectWindow(o, mid, to);
    assert.equal(w.coverage, 'partial'); assert.equal(w.reason, 'span-limit-reached');
  } finally { await o.stop(); }
});
test('a tool span still open at the window end is in flight, so the window is partial', async () => {
  const o = createOtelObserver({ services: ['app'], settleMs: 50 }); await o.start();
  try {
    const from = await o.mark(), to = await o.mark();
    await post(o.endpoint, otlp('app', [spanOf(tool('refund', 'sam'), { spanId: hex(8, 11), startTimeUnixNano: String(from.at + 1n), endTimeUnixNano: String(to.at + 5n) })]));
    const w = await collectWindow(o, from, to);
    assert.equal(w.events[0].outcome, 'started'); assert.equal(w.coverage, 'partial');
  } finally { await o.stop(); }
});
test('listeners refuse foreign Host and cross-origin requests (DNS rebinding)', async () => {
  const o = createOtelObserver({ services: ['app'] }); await o.start();
  try {
    const port = new URL(o.endpoint).port;
    assert.equal((await post(o.endpoint, otlp('app', []), { Host: `attacker.example:${port}` })).status, 403);
    assert.equal((await post(o.endpoint, otlp('app', []), { Origin: `http://attacker.example:${port}` })).status, 403);
    assert.equal((await post(o.endpoint, otlp('app', []), { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await post(o.endpoint, otlp('app', []))).status, 200);
  } finally { await o.stop(); }
});

// ---- MCP --------------------------------------------------------------------
test('JSON-RPC frames keep tool names, ids and error flags, never arguments', () => {
  const [call] = framesOf({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'refund', arguments: { amount: 20, card: '4111' } } }, 'c2s', { conn: 'c', actor: 'a' });
  assert.equal(call.tool, 'refund'); assert.equal(call.id, '7'); assert.ok(!JSON.stringify(call).includes('4111'));
  assert.equal(framesOf({ jsonrpc: '2.0', id: 7, result: { isError: true, content: [] } }, 's2c', { conn: 'c' })[0].isError, true);
  assert.equal(framesOf({ jsonrpc: '2.0', method: 'notifications/progress' }, 'c2s').length, 0);
});
async function mcpUpstream(handler) {
  return listen((req, res) => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => handler(JSON.parse(Buffer.concat(c).toString()), req, res)); });
}
test('Streamable HTTP proxy: calls per actor, JSON and SSE, credentials kept as digests only', async () => {
  const upstream = await mcpUpstream((m, _req, res) => {
    if (m.params?.name === 'sse_tool') { res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [] } })}\n\n`); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { isError: m.params?.name === 'broken', content: [] } }));
  });
  const env = { SCOPEHAVEN_TARGET_SAM: 'synthetic-mcp-token' };
  const proxy = createMcpHttpProxy({ upstream: `${upstream.url}/mcp`, actors: [{ actorId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM' }], env });
  await proxy.start();
  const o = createMcpObserver({ log: proxy.log });
  try {
    const from = await o.mark();
    const call = (id, name, auth) => post(proxy.url, { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: { x: 1 } } }, auth ? { Authorization: auth } : {});
    assert.equal((await call(1, 'add_note', 'Bearer synthetic-mcp-token')).status, 200);
    // Recorded before forwarded: the result is already in the log when the client has the reply.
    assert.ok(proxy.log.frames.some(f => f.kind === 'result' && f.id === '1'));
    await call(2, 'broken', 'Bearer synthetic-mcp-token');
    assert.match((await call(3, 'sse_tool', 'Bearer someone-else')).body, /data:/);
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(w.coverage, 'complete');
    assert.deepEqual(w.events.map(e => [e.name, e.actor?.startsWith('unlisted:') ? 'unlisted' : e.actor, e.outcome]), [['add_note', 'agent-sam', 'committed'], ['broken', 'agent-sam', 'error'], ['sse_tool', 'unlisted', 'committed']]);
    assert.ok(!JSON.stringify(proxy.log.frames).includes('synthetic-mcp-token'));
    const port = new URL(proxy.url).port;
    assert.equal((await post(proxy.url, {}, { Host: `attacker.example:${port}` })).status, 403);
  } finally { await proxy.stop(); await upstream.close(); }
  assert.throws(() => createMcpHttpProxy({ upstream: 'http://example.com/mcp' }), /loopback/);
  assert.throws(() => createMcpHttpProxy({ upstream: 'http://127.0.0.1:9/mcp', actors: [{ actorId: 'x', credentialEnv: 'GITHUB_TOKEN' }], env: { GITHUB_TOKEN: 'x' } }), /SCOPEHAVEN_TARGET_/);
});
test('the same JSON-RPC id from two actors is never cross-paired', async () => {
  const upstream = await mcpUpstream((m, req, res) => {
    if (req.headers.authorization === 'Bearer alice') { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: { code: -32001, message: 'no' } })); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [] } }));
  });
  const env = { SCOPEHAVEN_TARGET_M: 'mallory', SCOPEHAVEN_TARGET_A: 'alice' };
  const proxy = createMcpHttpProxy({ upstream: `${upstream.url}/mcp`, actors: [{ actorId: 'mallory', credentialEnv: 'SCOPEHAVEN_TARGET_M' }, { actorId: 'alice', credentialEnv: 'SCOPEHAVEN_TARGET_A' }], env });
  await proxy.start();
  const o = createMcpObserver({ log: proxy.log, tools: ['refund'] });
  try {
    const from = await o.mark();
    const call = auth => post(proxy.url, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'refund', arguments: {} } }, { Authorization: auth });
    await call('Bearer mallory'); await call('Bearer alice');
    const w = await collectWindow(o, from, await o.mark());
    assert.deepEqual(w.events.map(e => [e.actor, e.outcome]), [['mallory', 'committed'], ['alice', 'denied']]);
    assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'mcp-jsonrpc', actor: 'mallory', name: 'refund' } }, [w]).verdict, 'fail');
  } finally { await proxy.stop(); await upstream.close(); }
});
test('an unparsed oversized response leaves the call in flight and the window partial', async () => {
  const upstream = await mcpUpstream((m, _req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: 'x'.repeat(5 * 1024 * 1024) }] } })); });
  const proxy = createMcpHttpProxy({ upstream: `${upstream.url}/mcp` }); await proxy.start();
  const o = createMcpObserver({ log: proxy.log, tools: ['export_all'] });
  try {
    const from = await o.mark();
    const r = await post(proxy.url, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'export_all', arguments: {} } });
    assert.equal(r.status, 200); assert.ok(r.body.length > 5 * 1024 * 1024);
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(w.coverage, 'partial');
    assert.notEqual(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'mcp-jsonrpc', name: 'export_all' } }, [w]).verdict, 'pass');
  } finally { await proxy.stop(); await upstream.close(); }
});
test('a result after the window end does not complete a call inside it', async () => {
  const log = new FrameLog(); log.push({ kind: 'open' });
  const o = createMcpObserver({ log, tools: ['refund'] });
  const from = await o.mark();
  log.push({ kind: 'call', conn: 'c', id: '1', tool: 'refund', actor: 'm', argsDigest: null });
  const to = await o.mark();
  log.push({ kind: 'result', conn: 'c', id: '1', isError: false, rpcErrorCode: null, httpStatus: 200 });
  const w = await collectWindow(o, from, to);
  assert.equal(w.events[0].outcome, 'started'); assert.equal(w.coverage, 'partial');
});
test('frame overflow is written to the log, and a file-backed window becomes partial', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-mcp-'));
  try {
    const path = join(dir, 'f.jsonl'), log = new FrameLog({ path, maxFrames: 4 });
    log.push({ kind: 'open', conn: 'c' });
    const o = createMcpObserver({ path });
    const from = await o.mark();
    for (let i = 0; i < 5; i++) log.push({ kind: 'call', conn: 'c', id: String(i), tool: 'refund', actor: 'm', argsDigest: null });
    assert.ok(readFileSync(path, 'utf8').includes('"overflow"'));
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(w.coverage, 'partial'); assert.equal(w.reason, 'recorder-gap-in-window');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
async function withRecorder(dir, run) {
  const server = join(dir, 'server.mjs'), log = join(dir, 'frames.jsonl');
  writeFileSync(server, `process.stdin.setEncoding('utf8'); let b=''; process.stdin.on('data', d => { b += d; let i; while ((i = b.indexOf('\\n')) >= 0) { const m = JSON.parse(b.slice(0, i)); b = b.slice(i + 1); process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [] } }) + '\\n'); } }); process.stdin.on('end', () => process.exit(0));`);
  const child = spawn(N, [fileURLToPath(new URL('./mcp.mjs', import.meta.url)), 'record', '--log', log, '--actor', 'agent-sam', '--', N, server], { stdio: ['pipe', 'pipe', 'inherit'] });
  try {
    // Wait until the recorder has written its open frame (not a fixed delay).
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) { try { if (readFileSync(log, 'utf8').includes('"open"')) break; } catch {} await new Promise(r => setTimeout(r, 20)); }
    await new Promise(r => setTimeout(r, 5));
    return await run({ child, o: createMcpObserver({ path: log, tools: ['add_note', 'upload_file'] }) });
  }
  finally { child.kill('SIGTERM'); await new Promise(r => child.exitCode !== null || child.signalCode !== null ? r() : child.once('exit', r)); }
}
const replyFrom = child => new Promise(resolve => { let b = ''; const on = d => { b += d; if (b.includes('\n')) { child.stdout.off('data', on); resolve(b); } }; child.stdout.on('data', on); });
test('the stdio recorder tees a real MCP server process; a closed recorder makes later windows partial', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-mcp-'));
  try {
    await withRecorder(dir, async ({ child, o }) => {
      const from = await o.mark();
      const reply = replyFrom(child);
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'add_note', arguments: {} } }) + '\n');
      assert.match(await reply, /"id":1/);
      const to = await o.mark();
      const w = await collectWindow(o, from, to);
      assert.equal(w.coverage, 'complete', `${w.reason} ${readFileSync(join(dir, 'frames.jsonl'), 'utf8')}`); assert.equal(w.events.length, 1); assert.equal(w.events[0].actor, 'agent-sam'); assert.equal(w.events[0].outcome, 'committed');
      child.stdin.end(); await new Promise(r => child.once('exit', r));
      assert.equal((await collectWindow(o, from, await o.mark())).coverage, 'partial');
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('a tools/call line over the size limit is recorded as a gap, so the window is partial', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-mcp-'));
  try {
    await withRecorder(dir, async ({ child, o }) => {
      const from = await o.mark();
      const reply = replyFrom(child);
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'upload_file', arguments: { data: 'x'.repeat(1200000) } } }) + '\n');
      await reply;
      const w = await collectWindow(o, from, await o.mark());
      assert.equal(w.coverage, 'partial');
      assert.notEqual(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'mcp-jsonrpc', name: 'upload_file' } }, [w]).verdict, 'pass');
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- SQLite -----------------------------------------------------------------
test('snapshot observer: net-only changes with no actor; audit observer: declared principals only; neither writes', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    const db = new DatabaseSync(path);
    db.exec(`PRAGMA journal_mode=WAL; CREATE TABLE notes (id INTEGER PRIMARY KEY, author TEXT, body TEXT); CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, what TEXT, target TEXT);
      INSERT INTO notes VALUES (1, 'alice', 'a'), (2, 'owner-olga', 'b');`);
    const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 'notes', key: 'id' }] });
    const audit = createSqliteAuditObserver({ path, principals: ['agent-sam'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what', resourceColumn: 'target', actions: { 'note.create': 'insert', 'note.delete': 'delete' }, deniedActions: ['note.denied'] } });
    await snap.start(); await audit.start();
    const [s0, a0] = [await snap.mark(), await audit.mark()];
    // Mallory deletes Alice's note: the snapshot must not blame Alice.
    db.exec(`INSERT INTO notes VALUES (3, 'agent-sam', 'c'); UPDATE notes SET body = 'z' WHERE id = 2; DELETE FROM notes WHERE id = 1;
      INSERT INTO audit (who, what, target) VALUES ('agent-sam', 'note.create', 'notes/3'), ('carol@example.test', 'note.denied', 'notes/4');`);
    const before = statSync(path).mtimeMs;
    const [s1, a1] = [await snap.mark(), await audit.mark()];
    const sw = await collectWindow(snap, s0, s1), aw = await collectWindow(audit, a0, a1);
    assert.equal(sw.coverage, 'net-only');
    assert.deepEqual(sw.events.map(e => [e.operation, e.resource, e.actor]), [['update', 'notes/2', null], ['insert', 'notes/3', null], ['delete', 'notes/1', null]]);
    assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-snapshot', actor: 'mallory', operation: 'delete' } }, [sw]).verdict, 'unobservable');
    assert.deepEqual(aw.events.map(e => [e.name, e.outcome, e.operation]), [['note.create', 'committed', 'insert'], ['note.denied', 'denied', 'update']]);
    assert.ok(!JSON.stringify([sw, aw]).includes('carol@example.test') && !JSON.stringify(sw).includes('"z"'));
    assert.equal(statSync(path).mtimeMs, before);
    db.close();
    assert.throws(() => createSqliteSnapshotObserver({ path, tables: [{ table: 'notes; DROP TABLE notes', key: 'id' }] }), /identifier/);
    assert.throws(() => createSqliteSnapshotObserver({ path, tables: [{ table: 'notes', key: 'id', actorColumn: 'author' }] }), /audit-table/);
    const gone = createSqliteSnapshotObserver({ path: join(dir, 'missing.db'), tables: [{ table: 'notes', key: 'id' }] });
    const m0 = await gone.mark(), m1 = await gone.mark();
    assert.equal((await collectWindow(gone, m0, m1)).coverage, 'failed');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('an audit window over the row limit is partial', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    const db = new DatabaseSync(path);
    db.exec(`CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, what TEXT);`);
    const audit = createSqliteAuditObserver({ path, maxRowsPerWindow: 2, audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what' } });
    const a0 = await audit.mark();
    db.exec(`INSERT INTO audit (who, what) VALUES ('a','x'), ('a','x'), ('a','x');`);
    const w = await collectWindow(audit, a0, await audit.mark());
    assert.equal(w.coverage, 'partial'); assert.equal(w.events.length, 2);
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('sqlite-snapshot and sqlite-audit read an INTEGER past 2^53 exactly instead of failing the mark', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db'), auditFile = join(dir, 'stamp-audit.txt');
  writeFileSync(auditFile, 'every UPDATE of t sets stamp = int(time.time())\n');
  try {
    const db = new DatabaseSync(path);
    // events.ts holds nanosecond timestamps; v has no type affinity, so it keeps TEXT and INTEGER apart.
    db.exec(`CREATE TABLE events (id INTEGER PRIMARY KEY, ts INTEGER, v); CREATE TABLE small (id INTEGER PRIMARY KEY, n INTEGER, note TEXT);
      CREATE TABLE t (id INTEGER PRIMARY KEY, stamp INTEGER, body TEXT);
      CREATE TABLE audit (id INTEGER PRIMARY KEY, who, what TEXT, target);
      INSERT INTO events VALUES (1, 1761700000123456789, '9007199254740993'); INSERT INTO small VALUES (1, 5, 'a');
      INSERT INTO t VALUES (1, -9007199254740993, 'x'), (2, 100, 'y');`);
    const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 'events', key: 'id' }, { table: 'small', key: 'id' }] });
    await snap.start();
    const s0 = await snap.mark();
    db.exec(`UPDATE events SET ts = 1761700000123456790 WHERE id = 1; INSERT INTO events VALUES (9007199254740993, 1761700000999999999, NULL);
      UPDATE small SET note = 'b'`);
    const s1 = await snap.mark();
    const w = await collectWindow(snap, s0, s1);
    assert.equal(w.coverage, 'net-only', JSON.stringify(w));
    // The key keeps its exact digits (9007199254740993 is not 9007199254740992).
    assert.deepEqual(w.events.map(e => [e.operation, e.resource]), [['update', 'events/1'], ['insert', 'events/9007199254740993'], ['update', 'small/1']]);
    // A row with integers inside the safe range digests exactly as before the fix (number values, column order).
    assert.equal(w.events[2].contentDigest, digest(digest([['id', 1], ['n', 5], ['note', 'b']])));
    // TEXT and INTEGER holding the same digits past 2^53 are different contents: the rewrite is an update.
    db.exec('UPDATE events SET v = 9007199254740993 WHERE id = 1');
    const w2 = await collectWindow(snap, s1, await snap.mark());
    assert.deepEqual(w2.events.map(e => [e.operation, e.resource]), [['update', 'events/1']]);
    // A change-column stamp past 2^53 is no whole-second reading: its row is ambiguous, never exact.
    const stamped = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id', changeColumn: { column: 'stamp', unit: 'seconds', audit: auditFile } }],
      changeColumnSkewMs: 1000, maxCommitLagMs: 0, watchedResources: ['t/1', 't/2'] });
    await stamped.start();
    const t0 = await stamped.mark();
    const tw = await collectWindow(stamped, t0, await stamped.mark());
    assert.equal(tw.coverage, 'net-only', JSON.stringify(tw));
    assert.deepEqual([tw.exact[0].ambiguousResources, tw.exact[0].violated], [['t/1'], false]);
    // The audit table: an actor and a resource past 2^53 keep their digits; an id past 2^53 fails the mark, never a rounded cursor.
    const audit = createSqliteAuditObserver({ path, principals: ['9007199254740993'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what', resourceColumn: 'target', actions: { 'refund.send': 'insert' } } });
    await audit.start();
    const a0 = await audit.mark();
    db.exec(`INSERT INTO audit VALUES (1, 9007199254740993, 'refund.send', 1761700000123456789), (2, 9007199254740995, 'refund.send', 7)`);
    const aw = await collectWindow(audit, a0, await audit.mark());
    assert.equal(aw.coverage, 'complete');
    assert.deepEqual(aw.events.map(e => [e.seq, e.actor, e.resource]), [[1, '9007199254740993', '1761700000123456789'], [2, aw.events[1].actor, '7']]);
    assert.match(aw.events[1].actor, /^unlisted:[0-9a-f]{16}$/);
    const a1 = await audit.mark();
    db.exec(`INSERT INTO audit VALUES (9007199254740993, 'agent', 'refund.send', NULL)`);
    const past = await audit.mark();
    assert.equal(past.ok, false);
    assert.equal((await collectWindow(audit, a1, past)).coverage, 'failed');
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('sqlite-snapshot reads a table past the old 200,000-row limit, keyed by rowid when its primary key spans columns', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    const db = new DatabaseSync(path);
    // Ticket legs just past the old limit, whose primary key spans two columns, and their tickets. Booking B1 has three tickets.
    db.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE ticket_flights (ticket_no TEXT, flight_id INTEGER, book_ref TEXT, fare TEXT, PRIMARY KEY (ticket_no, flight_id));
      CREATE TABLE tickets (id INTEGER PRIMARY KEY, book_ref TEXT);
      WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 200010)
        INSERT INTO ticket_flights SELECT printf('T%07d', x), 100 + x % 7, printf('B%d', (x + 2) / 3), 'Economy' FROM c;
      WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 1000) INSERT INTO tickets SELECT x, printf('B%d', (x + 2) / 3) FROM c;`);
    const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 'ticket_flights', key: 'rowid' }, { table: 'tickets', key: 'id' }] });
    await snap.start();
    const m0 = await snap.mark();
    // Rebooking one passenger's ticket moves every leg on the booking, and one ticket is added.
    db.exec("UPDATE ticket_flights SET flight_id = 900 WHERE book_ref = 'B1'; INSERT INTO tickets VALUES (1001, 'B334'); DELETE FROM tickets WHERE id = 5");
    const w = await collectWindow(snap, m0, await snap.mark());
    assert.equal(w.coverage, 'net-only', JSON.stringify({ coverage: w.coverage, reason: w.reason }));
    assert.deepEqual(w.events.map(e => `${e.operation} ${e.resource}`), ['update ticket_flights/1', 'update ticket_flights/2', 'update ticket_flights/3', 'insert tickets/1001', 'delete tickets/5']);
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('the row bounds, the scan-order digest of a large unlisted table and the rowid key, at test-seam sizes', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  const rowLimits = { rowsPerTable: 20, sortedRows: 5 };
  try {
    const db = new DatabaseSync(path);
    db.exec(`CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT); CREATE TABLE small (v TEXT); CREATE TABLE big (v TEXT); CREATE TABLE huge (v TEXT);
      CREATE TABLE wr (a TEXT, b TEXT, PRIMARY KEY (a, b)) WITHOUT ROWID; CREATE TABLE own (rowid TEXT, v TEXT);
      WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 20) INSERT INTO orders SELECT x, 'open' FROM c;
      INSERT INTO small VALUES ('s1'), ('s2'), ('s3');
      WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 8) INSERT INTO big SELECT printf('b%d', x) FROM c;
      WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 21) INSERT INTO huge SELECT 'h' FROM c;
      INSERT INTO wr VALUES ('x', 'y'); INSERT INTO own VALUES ('k2', 'a'), ('k1', 'b');`);
    // The observer's own collect, as the background-writer tests read it: collectWindow keeps no background record.
    const win = async (o, between) => { const from = await o.mark(); between(); return o.collect(from, await o.mark()); };
    // A declared table at the bound reads; one row past it fails the mark (row-limit).
    const o = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], ignore: ['huge', 'wr', 'own'], rowLimits });
    await o.start();
    assert.equal((await win(o, () => {})).coverage, 'net-only');
    const past = await win(o, () => db.exec("INSERT INTO orders VALUES (21, 'open')"));
    assert.deepEqual([past.coverage, past.reason], ['failed', 'row-limit']);
    db.exec('DELETE FROM orders WHERE id = 21');
    // An unlisted table past sortedRows is read whole, in scan order: a change in its first rows or its last reads, and
    // the same rows in another order read as changed. Up to sortedRows the digest stays order-free.
    assert.equal((await win(o, () => {})).coverage, 'net-only');
    for (const change of ["UPDATE big SET v = 'b1x' WHERE v = 'b1'", "UPDATE big SET v = 'b8x' WHERE v = 'b8'",
      "DELETE FROM big WHERE v = 'b2'; INSERT INTO big VALUES ('b2')"]) {
      const changed = await win(o, () => db.exec(change));
      assert.deepEqual([changed.coverage, changed.reason, changed.background.unlisted], ['partial', 'unlisted-table-changed', ['big']], change);
    }
    const reordered = await win(o, () => db.exec("DELETE FROM small WHERE v = 's1'; INSERT INTO small VALUES ('s1')"));
    assert.deepEqual([reordered.coverage, reordered.background.unlisted], ['net-only', []]);
    // An unlisted table past rowsPerTable cannot be shown unchanged.
    const huge = createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], ignore: ['wr', 'own'], rowLimits });
    await huge.start();
    const h = await win(huge, () => {});
    assert.deepEqual([h.coverage, h.reason, h.background.unlisted], ['partial', 'unlisted-table-changed', ['huge']]);
    // key "rowid": a WITHOUT ROWID table has none (the mark fails); a table with its own rowid column keys on that column.
    const wr = createSqliteSnapshotObserver({ path, tables: [{ table: 'wr', key: 'rowid' }], rowLimits });
    assert.deepEqual([(await win(wr, () => {})).coverage], ['failed']);
    const own = createSqliteSnapshotObserver({ path, tables: [{ table: 'own', key: 'rowid' }], rowLimits });
    const ow = await win(own, () => db.exec("UPDATE own SET v = 'c' WHERE rowid = 'k1'"));
    assert.deepEqual(ow.events.map(e => `${e.operation} ${e.resource}`), ['update own/k1']);
    for (const bad of [{ rowsPerTable: 2000001, sortedRows: 5 }, { rowsPerTable: 4, sortedRows: 5 }, { rowsPerTable: 20, sortedRows: 0 }, { rowsPerTable: 1.5, sortedRows: 1 }])
      assert.throws(() => createSqliteSnapshotObserver({ path, tables: [{ table: 'orders', key: 'id' }], rowLimits: bad }), /rowLimits/, JSON.stringify(bad));
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
// A rollback-journal database with 60k rows and a writer that commits every
// pauseMs (0 = a commit storm) with busy timeout 0, so any lock shows up as busy.
async function rollbackWriterRun({ pauseMs, lockFallback }) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    const db = new DatabaseSync(path);
    db.exec(`PRAGMA journal_mode=DELETE; CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); CREATE TABLE app_writes (id INTEGER PRIMARY KEY AUTOINCREMENT);`);
    const ins = db.prepare('INSERT INTO t (v) VALUES (?)'); db.exec('BEGIN'); for (let i = 0; i < 60000; i++) ins.run(`row-${i}`); db.exec('COMMIT'); db.close();
    const writer = join(dir, 'writer.mjs');
    writeFileSync(writer, `import { DatabaseSync } from 'node:sqlite'; const db = new DatabaseSync(${JSON.stringify(path)}, { timeout: 0 }); let ok = 0, busy = 0; const end = Date.now() + 1500;
      while (Date.now() < end) { try { db.exec('INSERT INTO app_writes DEFAULT VALUES'); ok++; } catch { busy++; } if (${pauseMs}) await new Promise(r => setTimeout(r, ${pauseMs})); }
      process.stdout.write(JSON.stringify({ ok, busy }));`);
    const child = spawn(N, [writer], { stdio: ['ignore', 'pipe', 'inherit'] });
    // Listen now, not after the marks: see walWriterRun.
    const closed = new Promise(r => child.once('close', r));
    let out = ''; child.stdout.on('data', d => { out += d; });
    const marks = [];
    try {
      const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id' }], lockFallback });
      // At least two marks, so there is always a window: under load one mark can outlast the 1,300 ms on its own.
      const end = Date.now() + 1300;
      while (Date.now() < end || marks.length < 2) marks.push(await snap.mark());
      await closed;
      const windows = [];
      for (let i = 1; i < marks.length; i++) windows.push(await collectWindow(snap, marks[i - 1], marks[i]));
      return { ...JSON.parse(out), windows };
    } finally { if (child.exitCode === null) child.kill(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
// The same database with a writer that commits only when asked and acknowledges
// each commit (busy timeout 0, so any observer lock would show up as busy).
// Marks interleave with commits by explicit handshakes, not wall-clock pauses:
// whether a 2 MB copy fits between two timed commits depends on machine load,
// which made the earlier timed version flaky.
async function lockstepWriterRun({ commits }) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    const db = new DatabaseSync(path);
    db.exec(`PRAGMA journal_mode=DELETE; CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); CREATE TABLE app_writes (id INTEGER PRIMARY KEY AUTOINCREMENT);`);
    const ins = db.prepare('INSERT INTO t (v) VALUES (?)'); db.exec('BEGIN'); for (let i = 0; i < 60000; i++) ins.run(`row-${i}`); db.exec('COMMIT'); db.close();
    const writer = join(dir, 'writer.mjs');
    writeFileSync(writer, `import { DatabaseSync } from 'node:sqlite'; import { createInterface } from 'node:readline';
      const db = new DatabaseSync(${JSON.stringify(path)}, { timeout: 0 }); let ok = 0, busy = 0;
      for await (const line of createInterface({ input: process.stdin })) {
        if (line !== 'commit') break;
        try { db.exec('INSERT INTO app_writes DEFAULT VALUES'); ok++; } catch { busy++; }
        process.stdout.write('ack\\n');
      }
      db.close(); process.stdout.write(JSON.stringify({ ok, busy }) + '\\n');`);
    const child = spawn(N, [writer], { stdio: ['pipe', 'pipe', 'inherit'] });
    const queue = [], waiting = []; let buffered = '';
    child.stdout.on('data', d => { buffered += d; let i; while ((i = buffered.indexOf('\n')) >= 0) { const line = buffered.slice(0, i); buffered = buffered.slice(i + 1); waiting.length ? waiting.shift()(line) : queue.push(line); } });
    const nextLine = () => queue.length ? Promise.resolve(queue.shift()) : new Promise(resolve => waiting.push(resolve));
    try {
      const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id' }, { table: 'app_writes', key: 'id' }] });
      const marks = [await snap.mark()];
      for (let i = 0; i < commits; i++) {
        child.stdin.write('commit\n'); assert.equal(await nextLine(), 'ack');
        marks.push(await snap.mark());
      }
      child.stdin.end('end\n');
      const result = JSON.parse(await nextLine());
      const windows = [];
      for (let i = 1; i < marks.length; i++) windows.push(await collectWindow(snap, marks[i - 1], marks[i]));
      return { ...result, windows };
    } finally { if (child.exitCode === null) child.kill(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
test('rollback-journal databases are copied without any SQLite lock: the writer is never blocked, even by a commit storm', async () => {
  const storm = await rollbackWriterRun({ pauseMs: 0, lockFallback: false });
  assert.ok(storm.ok > 0 && storm.busy === 0, `storm writer ok=${storm.ok} busy=${storm.busy}`);
  // Under a storm a consistent copy may be impossible: those windows fail, never compare torn data.
  for (const w of storm.windows) assert.ok(w.coverage === 'net-only' || (w.coverage === 'failed' && ['no-consistent-copy', 'read-failed'].includes(w.reason)), JSON.stringify(w.reason));
  // Between commits a consistent copy is always possible: every mark compares, and each
  // window holds exactly the one commit made inside it.
  const steady = await lockstepWriterRun({ commits: 10 });
  assert.deepEqual([steady.ok, steady.busy], [10, 0], `lockstep writer ok=${steady.ok} busy=${steady.busy}`);
  assert.equal(steady.windows.length, 10);
  for (const w of steady.windows) {
    assert.equal(w.coverage, 'net-only', JSON.stringify(w.reason));
    assert.deepEqual(w.events.map(e => [e.name, e.operation]), [['app_writes', 'insert']]);
  }
});
test('opt-in lockFallback observes a commit storm with one short lock per failed mark', async t => {
  const loadBefore = loadavg()[0];
  const run = await rollbackWriterRun({ pauseMs: 0, lockFallback: true });
  assert.ok(run.windows.length > 0 && run.windows.every(w => w.coverage === 'net-only'), `every window compares: ${JSON.stringify(run.windows.map(w => w.reason))}`);
  assert.ok(run.ok > 0, `writer ok=${run.ok} busy=${run.busy}`);
  // How often the writer meets a lock depends on how many marks need the fallback in this wall-clock window, which a
  // loaded host changes (about 12% was seen under load on the shared runner). The 10% tightness is a quiet-host
  // property: asserted when the 1-minute load stayed below the core count, recorded otherwise. That the lock is held
  // only for the copy is asserted on every run by the test below, which does not depend on timing.
  const busy = run.busy / (run.ok + run.busy), load = Math.max(loadBefore, loadavg()[0]), cores = cpus().length;
  const reading = `writer ok=${run.ok} busy=${run.busy} (${(100 * busy).toFixed(1)}%) at 1-minute load ${load.toFixed(1)} on ${cores} cores`;
  if (load < cores) assert.ok(busy < 0.1, reading);
  else t.diagnostic(`${reading}: the 10% tightness is not asserted on a loaded host`);
});
test('opt-in lockFallback holds its shared lock only while it copies: a writer mid-transaction commits right after the mark', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    const db = new DatabaseSync(path);
    db.exec(`PRAGMA journal_mode=DELETE; CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1, 'a');`); db.close();
    // The writer holds its transaction open, so its rollback journal is on disk and every unlocked copy attempt
    // refuses: the mark has to take the fallback lock. Busy timeout 0, so a lock still held makes its commit fail.
    const writer = new DatabaseSync(path, { timeout: 0 });
    try {
      writer.exec('BEGIN'); writer.exec(`INSERT INTO t VALUES (2, 'b')`);
      const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id' }], lockFallback: true });
      const before = await snap.mark();
      writer.exec('COMMIT');
      const w = await collectWindow(snap, before, await snap.mark());
      assert.equal(w.coverage, 'net-only', JSON.stringify(w.reason));
      assert.deepEqual(w.events.map(e => [e.resource, e.operation]), [['t/2', 'insert']], 'the copy taken under the lock predates the commit');
    } finally { writer.close(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('a hot rollback journal (a commit in progress) fails the mark instead of copying a torn database', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    const db = new DatabaseSync(path);
    db.exec(`PRAGMA journal_mode=DELETE; CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1, 'a');`); db.close();
    const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id' }] });
    const good = await snap.mark();
    writeFileSync(`${path}-journal`, 'x'.repeat(512));
    const hot = await snap.mark();
    const w = await collectWindow(snap, good, hot);
    assert.equal(w.coverage, 'failed'); assert.equal(w.reason, 'no-consistent-copy');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// WAL databases (found on a live pilot: a container's WAL index is not shared
// with a host-side reader across Docker's VM file share, which read a stale
// snapshot). The observer copies the database and its log instead of opening them.
test('WAL databases are read from a private copy: commits still only in the log are seen, and no file of the app is created or opened for writing', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    const setup = new DatabaseSync(path);
    setup.exec(`PRAGMA journal_mode=WAL; CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t VALUES (1, 'a');`); setup.close();
    const files = () => readdirSync(dir).sort();
    assert.deepEqual(files(), ['app.db'], 'the closed writer checkpointed and removed its log');
    const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id' }] });
    const m0 = await snap.mark();
    assert.deepEqual(files(), ['app.db'], 'marking a WAL database never creates its -wal or -shm');
    // A writer that keeps its connection open: its commits stay in the log, never checkpointed.
    const app = new DatabaseSync(path); app.exec('PRAGMA wal_autocheckpoint=0;');
    app.exec(`INSERT INTO t VALUES (2, 'b'); UPDATE t SET v = 'a2' WHERE id = 1;`);
    const shm = readFileSync(`${path}-shm`), wal = readFileSync(`${path}-wal`);
    const m1 = await snap.mark();
    assert.ok(readFileSync(`${path}-shm`).equals(shm) && readFileSync(`${path}-wal`).equals(wal), 'the app\'s log and index are untouched');
    const w = await collectWindow(snap, m0, m1);
    assert.equal(w.coverage, 'net-only');
    assert.deepEqual(w.events.map(e => [e.operation, e.resource]).sort(), [['insert', 't/2'], ['update', 't/1']]);
    app.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
// A WAL writer that appends rows every pauseMs (0 = a commit storm) and restarts the log every 25 commits.
async function walWriterRun({ pauseMs }) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    const setup = new DatabaseSync(path);
    setup.exec(`PRAGMA journal_mode=WAL; CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);`);
    const ins = setup.prepare('INSERT INTO t (v) VALUES (?)'); setup.exec('BEGIN'); for (let i = 0; i < 20000; i++) ins.run(`row-${i}`); setup.exec('COMMIT'); setup.close();
    const writer = join(dir, 'writer.mjs');
    writeFileSync(writer, `import { DatabaseSync } from 'node:sqlite'; const db = new DatabaseSync(${JSON.stringify(path)}, { timeout: 0 }); db.exec('PRAGMA wal_autocheckpoint=4'); let ok = 0, busy = 0; const end = Date.now() + 1500;
      while (Date.now() < end) { try { db.exec("INSERT INTO t (v) VALUES ('w')"); ok++; } catch { busy++; } if (ok % 25 === 0) try { db.exec('PRAGMA wal_checkpoint(RESTART)'); } catch {} if (${pauseMs}) await new Promise(r => setTimeout(r, ${pauseMs})); }
      db.close(); process.stdout.write(JSON.stringify({ ok, busy }));`);
    const child = spawn(N, [writer], { stdio: ['ignore', 'pipe', 'inherit'] });
    // Listen now: under load the writer can finish while a mark is still copying, and an
    // 'exit' that fired before a later listener is attached would be waited for forever.
    // 'close' also waits for the writer's stdout to be fully read.
    const closed = new Promise(r => child.once('close', r));
    let out = ''; child.stdout.on('data', d => { out += d; });
    try {
      const snap = createSqliteSnapshotObserver({ path, tables: [{ table: 't', key: 'id' }] });
      const marks = [], end = Date.now() + 1300;
      while (Date.now() < end) marks.push(await snap.mark());
      await closed;
      const windows = [];
      for (let i = 1; i < marks.length; i++) windows.push(await collectWindow(snap, marks[i - 1], marks[i]));
      return { ...JSON.parse(out), windows };
    } finally { if (child.exitCode === null) child.kill(); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
test('WAL commits with frequent log restarts never yield a torn snapshot: marks compare a committed state or fail', async () => {
  for (const pauseMs of [0, 20]) {
    const run = await walWriterRun({ pauseMs });
    assert.ok(run.ok > 0 && run.busy === 0, `writer ok=${run.ok} busy=${run.busy}`);
    for (const w of run.windows) {
      if (w.coverage === 'failed') { assert.ok(['no-consistent-copy', 'read-failed'].includes(w.reason), w.reason); continue; }
      assert.equal(w.coverage, 'net-only');
      // A committed state only ever gains appended rows: a delete or update would be a torn or stale copy.
      assert.ok(w.events.every(e => e.operation === 'insert'), JSON.stringify(w.events.filter(e => e.operation !== 'insert').slice(0, 3)));
    }
    if (pauseMs) assert.ok(run.windows.some(w => w.coverage === 'net-only'), 'a writer committing every 20 ms still allows consistent snapshots');
  }
});

// Every SQLite open the observer makes, on every path, recorded by running it in a
// child process whose imports of node:sqlite and node:fs (from sqlite.mjs only)
// resolve to recording wrappers. The fs wrapper can also bump the live file's
// change counter after each copy, forcing every copy attempt to fail so the
// lockFallback branch runs. The only permitted open of the live file is that
// opt-in fallback on a rollback-journal database, read-only.
test('the observer never opens the application\'s database with SQLite, on any path: WAL and rollback, snapshot and audit, with and without lockFallback', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  try {
    const sqliteSpy = join(dir, 'spy-sqlite.mjs'), fsSpy = join(dir, 'spy-fs.mjs'), harness = join(dir, 'harness.mjs');
    writeFileSync(sqliteSpy, `import * as real from 'node:sqlite'; export * from 'node:sqlite';
      export const opens = globalThis.__opens ??= [];
      export class DatabaseSync extends real.DatabaseSync { constructor(path, options) { opens.push({ path, readOnly: options?.readOnly === true }); if (options === undefined) super(path); else super(path, options); } }`);
    writeFileSync(fsSpy, `import * as real from 'node:fs'; export * from 'node:fs';
      export const force = globalThis.__force ??= { live: null };
      export function copyFileSync(source, target, mode) {
        real.copyFileSync(source, target, mode);
        if (force.live && source === force.live) { const fd = real.openSync(source, 'r+'), b = Buffer.alloc(4); real.readSync(fd, b, 0, 4, 24); b.writeUInt32BE((b.readUInt32BE(0) + 1) >>> 0); real.writeSync(fd, b, 0, 4, 24); real.closeSync(fd); }
      }`);
    const observer = fileURLToPath(new URL('./sqlite.mjs', import.meta.url)), events = fileURLToPath(new URL('./events.mjs', import.meta.url));
    writeFileSync(harness, `import { registerHooks } from 'node:module'; import { pathToFileURL } from 'node:url'; import { DatabaseSync } from 'node:sqlite'; import { readdirSync } from 'node:fs'; import { join } from 'node:path';
      const [sqliteSpy, fsSpy, observer, events, root] = JSON.parse(process.argv[2]);
      const OBSERVER = pathToFileURL(observer).href, SPIES = { 'node:sqlite': pathToFileURL(sqliteSpy).href, 'node:fs': pathToFileURL(fsSpy).href };
      registerHooks({ resolve: (specifier, context, next) => context.parentURL === OBSERVER && SPIES[specifier] ? { url: SPIES[specifier], shortCircuit: true } : next(specifier, context) });
      const { createSqliteSnapshotObserver, createSqliteAuditObserver } = await import(OBSERVER);
      const { collectWindow } = await import(pathToFileURL(events).href);
      const { opens } = await import(SPIES['node:sqlite']), { force } = await import(SPIES['node:fs']);
      const report = [];
      for (const mode of ['wal', 'delete']) {
        const path = join(root, mode + '.db');
        const app = new DatabaseSync(path);
        app.exec(\`PRAGMA journal_mode=\${mode}; PRAGMA wal_autocheckpoint=0; CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, what TEXT); INSERT INTO t VALUES (1, 'a');\`);
        const run = async (label, observer, write, forced = false) => {
          const before = opens.length, m0 = await observer.mark(); write();
          force.live = forced ? path : null; const m1 = await observer.mark(); force.live = null;
          const w = await collectWindow(observer, m0, m1);
          report.push({ mode, label, coverage: w.coverage, reason: w.reason ?? null, events: w.events.length, opens: opens.slice(before).map(o => ({ live: o.path === path, readOnly: o.readOnly, private: o.path.includes('scopehaven-sqlite-') })) });
        };
        const tables = [{ table: 't', key: 'id' }];
        // Live: the app keeps its connection open, so WAL commits stay in the log.
        await run('snapshot', createSqliteSnapshotObserver({ path, tables }), () => app.exec("INSERT INTO t (v) VALUES ('b')"));
        await run('snapshot+lockFallback', createSqliteSnapshotObserver({ path, tables, lockFallback: true }), () => app.exec("INSERT INTO t (v) VALUES ('c')"));
        await run('audit', createSqliteAuditObserver({ path, principals: ['u'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what' } }), () => app.exec("INSERT INTO audit (who, what) VALUES ('u', 'x')"));
        app.close();
        // Every copy attempt fails: only lockFallback on a rollback journal may open the live file.
        await run('snapshot forced-fail', createSqliteSnapshotObserver({ path, tables }), () => {}, true);
        await run('snapshot+lockFallback forced-fail', createSqliteSnapshotObserver({ path, tables, lockFallback: true }), () => {}, true);
        report.push({ mode, files: readdirSync(root).filter(f => f.startsWith(mode + '.db')).sort() });
      }
      process.stdout.write(JSON.stringify(report));`);
    const child = spawn(N, [harness, JSON.stringify([sqliteSpy, fsSpy, observer, events, dir])], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; child.stdout.on('data', d => { out += d; }); child.stderr.on('data', d => { err += d; });
    // 'close', not 'exit': the report is read only after the child's stdout has ended.
    const code = await new Promise(r => child.once('close', r));
    assert.equal(code, 0, err.split('\n').filter(l => !/ExperimentalWarning|--trace-warnings/.test(l)).join('\n'));
    const report = JSON.parse(out), runs = report.filter(r => r.label);
    assert.equal(runs.length, 10);
    for (const r of runs) {
      const liveOpens = r.opens.filter(o => o.live);
      assert.ok(r.opens.every(o => o.live || o.private), `${r.mode} ${r.label}: every other open is a private copy`);
      if (r.mode === 'delete' && r.label === 'snapshot+lockFallback forced-fail') {
        // The documented opt-in exception: one read-only open to hold a shared lock while copying.
        assert.deepEqual(liveOpens, [{ live: true, readOnly: true, private: false }], JSON.stringify(r));
        assert.equal(r.coverage, 'net-only');
      } else assert.deepEqual(liveOpens, [], `${r.mode} ${r.label} opened the live database`);
      if (r.label.endsWith('forced-fail') && !(r.mode === 'delete' && r.label.includes('lockFallback'))) assert.deepEqual([r.coverage, r.reason], ['failed', 'no-consistent-copy'], `${r.mode} ${r.label}`);
      if (!r.label.endsWith('forced-fail')) assert.ok(r.coverage !== 'failed' && r.events === 1, `${r.mode} ${r.label}: ${JSON.stringify(r)}`);
    }
    // No -wal or -shm was ever created beside the application's files by the observer.
    assert.deepEqual(report.find(r => r.mode === 'wal' && r.files).files, ['wal.db']);
    assert.deepEqual(report.find(r => r.mode === 'delete' && r.files).files, ['delete.db']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---- HTTP audit log ---------------------------------------------------------
test('HTTP audit observer: id ranges through the loopback client, gaps are partial, credentials only from the namespace', async () => {
  let entries = [{ id: 1, user: 'agent-sam', action: 'login' }];
  const app = await listen((req, res) => {
    if (req.headers.authorization !== 'Bearer synthetic-admin') { res.writeHead(401).end('{}'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ data: { items: entries } }));
  });
  try {
    const config = { origin: app.url, path: '/admin/audit', pageLimit: 100, credentialEnv: 'SCOPEHAVEN_TARGET_ADMIN', itemsPointer: '/data/items', fields: { id: '/id', actor: '/user', action: '/action' }, actions: { 'note.create': 'insert' }, principals: ['agent-sam'] };
    const o = createHttpAuditObserver({ ...config, env: { SCOPEHAVEN_TARGET_ADMIN: 'synthetic-admin' } });
    await o.start();
    const from = await o.mark();
    entries = [...entries, { id: 2, user: 'agent-sam', action: 'note.create' }, { id: 3, user: 'x@example.test', action: 'note.create' }];
    const to = await o.mark();
    const w = await collectWindow(o, from, to);
    assert.equal(w.coverage, 'complete');
    assert.deepEqual(w.events.map(e => [e.seq, e.operation, e.actor.startsWith('unlisted:') ? 'unlisted' : e.actor]), [[2, 'insert', 'agent-sam'], [3, 'insert', 'unlisted']]);
    // A row the endpoint stopped returning between two marks means entries may be hidden.
    entries = entries.filter(e => e.id !== 1);
    assert.equal((await collectWindow(o, from, await o.mark())).reason, 'audit-rows-vanished');
    const denied = createHttpAuditObserver({ ...config, env: { SCOPEHAVEN_TARGET_ADMIN: 'wrong' } });
    const d0 = await denied.mark();
    assert.equal(d0.ok, false);
    assert.equal((await collectWindow(denied, d0, d0)).coverage, 'failed');
    assert.throws(() => createHttpAuditObserver({ ...config, credentialEnv: 'AWS_SECRET_ACCESS_KEY', env: { AWS_SECRET_ACCESS_KEY: 'awsFAKE' } }), /SCOPEHAVEN_TARGET_/);
  } finally { await app.close(); }
});

// ---- attribution, name vocabularies and window edges ----------------------
test('an actor-scoped check never passes on a matching effect with no known actor', async () => {
  const noActor = ev(1, { actor: null }), unlisted = ev(2, { actor: 'unlisted:0123456789abcdef' });
  assert.equal(evaluateEffectAssertion(none, [win('complete', [noActor])]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion(none, [win('complete', [unlisted])]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: { actor: 'agent-sam', name: 'note.create' } }, [win('complete', [noActor])]).verdict, 'missing');
  // An OTel tool span with no user attribute.
  const o = createOtelObserver({ services: ['app'], tools: ['refund'], settleMs: 50 }); await o.start();
  try {
    const from = await o.mark();
    await post(o.endpoint, otlp('app', [spanOf([attr('gen_ai.operation.name', 'execute_tool'), attr('gen_ai.tool.name', 'refund')], { spanId: hex(8, 21), startTimeUnixNano: String(from.at + 1n), endTimeUnixNano: String(from.at + 2n) })]));
    const to = await o.mark();
    await post(o.endpoint, otlp('app', [marker(hex(8, 22), to.at + 1n)]));
    const w = await collectWindow(o, from, to);
    assert.equal(w.coverage, 'complete');
    assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'otel-genai', actor: 'mallory', name: 'refund' } }, [w]).verdict, 'missing');
  } finally { await o.stop(); }
});
test('an MCP proxy call without Authorization is unattributed; the recorder requires --actor', async () => {
  const upstream = await mcpUpstream((m, _req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [] } })); });
  const proxy = createMcpHttpProxy({ upstream: `${upstream.url}/mcp` }); await proxy.start();
  const o = createMcpObserver({ log: proxy.log, tools: ['refund'] });
  try {
    const from = await o.mark();
    await post(proxy.url, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'refund', arguments: {} } });
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(w.events[0].actor, null);
    assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'mcp-jsonrpc', actor: 'mallory', name: 'refund' } }, [w]).verdict, 'missing');
    // Non-message methods are refused or logged, never forwarded silently.
    const put = await new Promise((resolve, reject) => { const r = request(proxy.url, { method: 'PUT', agent: false }, res => { res.resume(); resolve(res.statusCode); }); r.on('error', reject); r.end(); });
    assert.equal(put, 405);
  } finally { await proxy.stop(); await upstream.close(); }
  const usage = spawn(N, [fileURLToPath(new URL('./mcp.mjs', import.meta.url)), 'record', '--log', join(tmpdir(), 'unused.jsonl'), '--', N, '-e', '0'], { stdio: 'ignore' });
  assert.equal(await new Promise(r => usage.once('exit', r)), 2);
});
test('an observer without a name vocabulary cannot vouch for a specific name', () => {
  const undeclared = { ...win('complete'), scope: { ...AUDIT_SCOPE, names: null } };
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { name: 'drop_tables' } }, [undeclared]).verdict, 'unobservable');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { name: 'drop_tables' } }, [win('complete')]).verdict, 'unobservable');
  // A name-free selector can only show presence, never absence.
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { actor: 'agent-sam', operation: 'delete' } }, [undeclared]).verdict, 'unobservable');
});
test('effect.count needs exactly one observer instance', () => {
  const count = { kind: 'effect.count', select: { source: 'sql-audit-table', name: 'note.create' }, expected: 1 };
  assert.equal(evaluateEffectAssertion(count, [win('complete', [ev(1)], { instanceId: 'a' }), win('complete', [ev(1)], { instanceId: 'b' })]).verdict, 'missing');
});
test('declared instances must each send a marker; spans from other instances are a gap', async () => {
  const o = createOtelObserver({ services: [{ name: 'app', instanceIds: ['i1', 'i2'] }], settleMs: 50 }); await o.start();
  const withInstance = (instance, spans) => ({ resourceSpans: [{ resource: { attributes: [attr('service.name', 'app'), attr('service.instance.id', instance)] }, scopeSpans: [{ spans }] }] });
  try {
    const from = await o.mark(), to = await o.mark();
    await post(o.endpoint, withInstance('i1', [marker(hex(8, 31), to.at + 1n)]));
    assert.equal((await collectWindow(o, from, to)).reason, 'no-quiescence-marker-after-window'); // i2 never reported
    await post(o.endpoint, withInstance('i2', [marker(hex(8, 32), to.at + 1n)]));
    assert.equal((await collectWindow(o, from, to)).coverage, 'complete');
    await post(o.endpoint, withInstance('i3', [marker(hex(8, 33), to.at + 2n)]));
    assert.equal((await collectWindow(o, from, to)).reason, 'span-from-undeclared-instance');
  } finally { await o.stop(); }
});
test('malformed spans from the target are a gap, not silently deduplicated away', async () => {
  const o = createOtelObserver({ services: ['app'], settleMs: 50 }); await o.start();
  try {
    const from = await o.mark(), to = await o.mark();
    await post(o.endpoint, otlp('app', [spanOf(tool('refund', 'sam'), { traceId: 'zz', spanId: 'zz', startTimeUnixNano: String(from.at + 1n), endTimeUnixNano: String(from.at + 2n) }), marker(hex(8, 41), to.at + 1n)]));
    const w = await collectWindow(o, from, to);
    assert.equal(w.coverage, 'partial'); assert.equal(w.reason, 'malformed-span-from-target');
    assert.equal(o.stats().malformedSpans, 1);
  } finally { await o.stop(); }
});
test('MCP windows are log positions, so recorder clock skew cannot move a call out of its window', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-mcp-'));
  try {
    const path = join(dir, 'f.jsonl');
    // A recorder whose clock is an hour behind the evaluator's.
    const line = f => writeFileSync(path, `${JSON.stringify({ v: 1, t: String(BigInt(Date.now() - 3600000) * 1000000n), ...f })}\n`, { flag: 'a' });
    line({ seq: 1, kind: 'open', conn: 'c' });
    const o = createMcpObserver({ path, tools: ['refund'] });
    const from = await o.mark();
    line({ seq: 2, kind: 'call', conn: 'c', id: '1', tool: 'refund', actor: 'mallory', argsDigest: null });
    line({ seq: 3, kind: 'result', conn: 'c', id: '1', isError: false, rpcErrorCode: null, httpStatus: null });
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(w.coverage, 'complete');
    assert.deepEqual(w.events.map(e => [e.actor, e.outcome]), [['mallory', 'committed']]);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('a call made before the window whose result lands inside it is included', async () => {
  const log = new FrameLog(); log.push({ kind: 'open' });
  log.push({ kind: 'call', conn: 'c', id: '9', tool: 'refund', actor: 'mallory', argsDigest: null });
  const o = createMcpObserver({ log, tools: ['refund'] });
  const from = await o.mark();
  log.push({ kind: 'result', conn: 'c', id: '9', isError: false, rpcErrorCode: null, httpStatus: 200 });
  const w = await collectWindow(o, from, await o.mark());
  assert.deepEqual(w.events.map(e => [e.actor, e.outcome]), [['mallory', 'committed']]);
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'mcp-jsonrpc', actor: 'mallory', name: 'refund' } }, [w]).verdict, 'fail');
});
test('concurrent same-id calls from two actors pair correctly', async () => {
  const upstream = await mcpUpstream((m, req, res) => {
    // Answer alice first even though mallory's request may arrive first.
    const delay = req.headers.authorization === 'Bearer mallory' ? 40 : 0;
    setTimeout(() => {
      if (req.headers.authorization === 'Bearer alice') { res.writeHead(403, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: { code: -32001, message: 'no' } })); return; }
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [] } }));
    }, delay);
  });
  const env = { SCOPEHAVEN_TARGET_M: 'mallory', SCOPEHAVEN_TARGET_A: 'alice' };
  const proxy = createMcpHttpProxy({ upstream: `${upstream.url}/mcp`, actors: [{ actorId: 'mallory', credentialEnv: 'SCOPEHAVEN_TARGET_M' }, { actorId: 'alice', credentialEnv: 'SCOPEHAVEN_TARGET_A' }], env });
  await proxy.start();
  const o = createMcpObserver({ log: proxy.log, tools: ['refund'] });
  try {
    const from = await o.mark();
    const call = auth => post(proxy.url, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'refund', arguments: {} } }, { Authorization: auth });
    await Promise.all([call('Bearer mallory'), call('Bearer alice'), call('Bearer mallory'), call('Bearer alice')]);
    const w = await collectWindow(o, from, await o.mark());
    const outcomes = Object.groupBy(w.events, e => e.actor);
    assert.deepEqual(outcomes.mallory.map(e => e.outcome), ['committed', 'committed']);
    assert.deepEqual(outcomes.alice.map(e => e.outcome), ['denied', 'denied']);
  } finally { await proxy.stop(); await upstream.close(); }
});

// ---- telemetry proves presence, not absence ---------------------------------
const traceWin = (coverage, events = []) => ({ source: 'otel-genai', instanceId: 'otel', scope: { operations: ['tool-call'], names: ['refund'], actorAttribution: 'principal', evidence: 'presence-only' }, coverage, events });
const span = (seq, over = {}) => makeEffect({ source: 'otel-genai', observer: { kind: 'x', instanceId: 'otel' }, seq, actor: 'mallory', operation: 'tool-call', name: 'refund', outcome: 'committed', ...over });
test('presence-only telemetry can fail effect.none or pass effect.exists, but never prove absence', () => {
  const none = { kind: 'effect.none', select: { source: 'otel-genai', actor: 'mallory', name: 'refund' } };
  assert.equal(evaluateEffectAssertion(none, [traceWin('complete', [span(1)])]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(none, [traceWin('complete')]).verdict, 'unobservable');
  const exists = { kind: 'effect.exists', select: { source: 'otel-genai', actor: 'mallory', name: 'refund' } };
  assert.equal(evaluateEffectAssertion(exists, [traceWin('complete', [span(1)])]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(exists, [traceWin('complete')]).verdict, 'unobservable');
  // With an authoritative audit observer as well, absence comes from the audit window only.
  const both = { kind: 'effect.none', select: { actor: 'mallory', operation: 'tool-call', name: 'refund' } };
  const audit = { ...win('complete'), scope: { ...AUDIT_SCOPE, operations: ['tool-call'], names: ['refund'] } };
  assert.equal(evaluateEffectAssertion(both, [traceWin('partial'), audit]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(both, [traceWin('complete'), { ...audit, coverage: 'partial' }]).verdict, 'missing');
});
test('effect.count reports unattributed matches as missing', () => {
  const count = { kind: 'effect.count', select: { source: 'sql-audit-table', actor: 'agent-sam', name: 'note.create' }, expected: 1 };
  assert.equal(evaluateEffectAssertion(count, [win('complete', [ev(1)])]).verdict, 'pass');
  assert.equal(evaluateEffectAssertion(count, [win('complete', [ev(1), ev(2, { actor: null })])]).verdict, 'missing');
});
test('OTel maps actors to declared principals, names unnamed tool spans, and a rejected export taints coverage', async () => {
  const o = createOtelObserver({ services: ['app'], principals: ['agent-sam'], settleMs: 50 }); await o.start();
  try {
    const from = await o.mark();
    await post(o.endpoint, otlp('app', [
      spanOf([attr('gen_ai.operation.name', 'execute_tool'), attr('enduser.id', 'carol@example.test')], { name: 'execute_tool refund', spanId: hex(8, 51), startTimeUnixNano: String(from.at + 1n), endTimeUnixNano: String(from.at + 2n) }),
      spanOf(tool('add_note', 'agent-sam'), { spanId: hex(8, 52), startTimeUnixNano: String(from.at + 3n), endTimeUnixNano: String(from.at + 4n) })]));
    const to = await o.mark();
    await post(o.endpoint, otlp('app', [marker(hex(8, 53), to.at + 1n)]));
    let w = await collectWindow(o, from, to);
    assert.equal(w.coverage, 'complete');
    assert.deepEqual(w.events.map(e => [e.name, e.actor.startsWith('unlisted:') ? 'unlisted' : e.actor]), [['refund', 'unlisted'], ['add_note', 'agent-sam']]);
    assert.ok(!JSON.stringify(w).includes('carol@example.test'));
    // A rejected export may have carried target spans: later windows are partial.
    assert.equal((await post(o.endpoint, Buffer.from('{"resourceSpans": [truncated'))).status, 400);
    w = await collectWindow(o, from, to);
    assert.equal(w.coverage, 'partial'); assert.equal(w.reason, 'rejected-trace-export');
  } finally { await o.stop(); }
});
test('a quiescence marker started before the window end does not complete it', async () => {
  const o = createOtelObserver({ services: ['app'], settleMs: 50 }); await o.start();
  try {
    const from = await o.mark(), to = await o.mark();
    await post(o.endpoint, otlp('app', [marker(hex(8, 61), to.at - 1n)]));
    assert.equal((await collectWindow(o, from, to)).reason, 'no-quiescence-marker-after-window');
  } finally { await o.stop(); }
});
test('an MCP recorder that opened after the window began is partial; a shrunken log fails', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-mcp-'));
  try {
    const path = join(dir, 'f.jsonl');
    writeFileSync(path, '');
    const o = createMcpObserver({ path, tools: ['refund'] });
    const from = await o.mark();
    writeFileSync(path, `${JSON.stringify({ v: 1, seq: 1, t: '1', kind: 'open', conn: 'c' })}\n`, { flag: 'a' });
    const to = await o.mark();
    assert.equal((await collectWindow(o, from, to)).reason, 'recorder-not-open-before-window');
    writeFileSync(path, '');
    assert.equal((await collectWindow(o, from, to)).coverage, 'failed');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test('an MCP result without a recorded call (an oversized call dropped before the window) is a gap', async () => {
  const log = new FrameLog(); log.push({ kind: 'open' });
  log.push({ kind: 'gap', conn: 'c', reason: 'c2s-line-too-large' });
  const o = createMcpObserver({ log, tools: ['refund'] });
  const from = await o.mark();
  log.push({ kind: 'result', conn: 'c', id: '1', isError: false, rpcErrorCode: null, httpStatus: null });
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.coverage, 'partial'); assert.equal(w.reason, 'result-without-call');
});
test('the MCP proxy refuses absolute-form targets and bodies on GET/DELETE', async () => {
  let reached = 0;
  const upstream = await listen((req, res) => { reached++; req.resume(); req.on('end', () => res.writeHead(200).end('{}')); });
  const proxy = createMcpHttpProxy({ upstream: `${upstream.url}/mcp` }); await proxy.start();
  try {
    const port = new URL(proxy.url).port;
    const raw = (method, target, headers = {}, body = '') => new Promise((resolve, reject) => {
      const r = request({ host: '127.0.0.1', port, method, path: target, agent: false, headers: { Host: `127.0.0.1:${port}`, ...headers } }, res => { res.resume(); resolve(res.statusCode); });
      r.on('error', reject); r.end(body);
    });
    assert.equal(await raw('POST', 'http://127.0.0.1:9/mcp', { 'Content-Type': 'application/json', Authorization: 'Bearer x' }, '{}'), 400);
    assert.equal(await raw('POST', '//evil.example/mcp', { 'Content-Type': 'application/json' }, '{}'), 400);
    // Even an absolute-form target naming the upstream itself is refused: only origin-form paths are forwarded.
    assert.equal(await raw('POST', `${upstream.url}/mcp`, { 'Content-Type': 'application/json' }, '{}'), 400);
    assert.equal(await raw('GET', '/mcp', { 'Content-Length': '2' }, '{}'), 400);
    assert.equal(reached, 0);
    assert.equal(await raw('GET', '/mcp'), 200);
  } finally { await proxy.stop(); await upstream.close(); }
});

// ---- authoritative vocabularies and audit id order -------------------------
test('absence needs an exact name from an authoritative vocabulary; prefix and name-free selectors only show presence', () => {
  const prefix = { kind: 'effect.none', select: { actor: 'agent-sam', name: { prefix: 'note.' } } };
  assert.equal(evaluateEffectAssertion(prefix, [win('complete')]).verdict, 'unobservable');
  assert.equal(evaluateEffectAssertion(prefix, [win('complete', [ev(1)])]).verdict, 'fail'); // presence still fails
  assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: { name: { prefix: 'note.' } } }, [win('complete')]).verdict, 'unobservable');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.count', select: { source: 'sql-audit-table', name: { prefix: 'note.' } }, expected: 0 }, [win('complete')]).verdict, 'unobservable');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { actor: 'agent-sam', name: 'note.create' } }, [win('complete')]).verdict, 'pass');
});
test('telemetry sources cannot be declared authoritative', () => {
  assert.throws(() => validateWindow({ source: 'otel-genai', instanceId: 'o', scope: { operations: ['tool-call'], names: ['refund'], actorAttribution: 'principal', evidence: 'authoritative' }, coverage: 'complete', events: [] }), /scope-evidence-source/);
  assert.throws(() => validateWindow({ source: 'mcp-jsonrpc', instanceId: 'm', scope: { operations: ['tool-call'], names: ['refund'], actorAttribution: 'principal', evidence: 'authoritative' }, coverage: 'complete', events: [] }), /scope-evidence-source/);
});
test('the HTTP audit observer catches late lower ids, backward ids and truncated pages', async () => {
  let entries = [{ id: 1, user: 'agent-sam', action: 'login' }, { id: 3, user: 'agent-sam', action: 'login' }];
  const app = await listen((req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ items: entries })); });
  try {
    const config = { origin: app.url, path: '/audit', pageLimit: 100, itemsPointer: '/items', fields: { id: '/id', actor: '/user', action: '/action' }, actions: { 'refund.request': 'insert' }, principals: ['agent-sam'] };
    const o = createHttpAuditObserver(config);
    const from = await o.mark();
    // Id 2 commits late, below the start mark's maximum; id 4 is new.
    entries = [...entries, { id: 2, user: 'agent-sam', action: 'refund.request' }, { id: 4, user: 'agent-sam', action: 'login' }];
    const to = await o.mark();
    const w = await collectWindow(o, from, to);
    assert.deepEqual(w.events.map(e => e.seq), [2, 4]);
    assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'http-audit-log', actor: 'agent-sam', name: 'refund.request' } }, [w]).verdict, 'fail');
    // Ids going backward means the endpoint is not showing the same log.
    entries = [{ id: 1, user: 'agent-sam', action: 'login' }];
    assert.equal((await collectWindow(o, to, await o.mark())).reason, 'audit-id-went-backward');
    // A full page may omit the newest rows: the mark fails.
    // The page size is required, so an oldest-first page cannot look complete.
    const { pageLimit: _p, ...noLimit } = config;
    assert.throws(() => createHttpAuditObserver(noLimit), /pageLimit/);
    entries = [{ id: 1, user: 'agent-sam', action: 'login' }, { id: 2, user: 'agent-sam', action: 'login' }];
    const paged = createHttpAuditObserver({ ...config, pageLimit: 2 });
    const m = await paged.mark();
    assert.equal(m.ok, false);
    assert.equal((await collectWindow(paged, m, m)).coverage, 'failed');
  } finally { await app.close(); }
});

// An audit store reset or replaced
// during the window (ids restart) can never read complete and empty.
test('an audit id that went backward fails the window', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-sql-'));
  const path = join(dir, 'app.db');
  try {
    let db = new DatabaseSync(path);
    db.exec(`CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, what TEXT); INSERT INTO audit (who, what) VALUES ('a','x'),('a','x'),('a','x'),('a','x'),('a','x'),('a','x');`); db.close();
    const audit = createSqliteAuditObserver({ path, principals: ['a'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what', actions: { 'note.update': 'update' } } });
    const from = await audit.mark();
    rmSync(path); db = new DatabaseSync(path); // replaced by a fresh store holding the forbidden action as id 1
    db.exec(`CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, what TEXT); INSERT INTO audit (who, what) VALUES ('a','note.update');`); db.close();
    const w = await collectWindow(audit, from, await audit.mark());
    assert.deepEqual([w.coverage, w.reason], ['failed', 'audit-id-went-backward']);
    assert.notEqual(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'sql-audit-table', name: 'note.update' } }, [w]).verdict, 'pass');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// An unlisted actor (and an audit row or entry that names it) is a digest keyed per
// observer instance, so nobody holding a run can confirm a guessed email, user id or token by hashing it.
const unkeyed = value => `unlisted:${digest(String(value)).slice(0, 16)}`;
const keyedActor = (events, guess, label) => {
  assert.match(events[0].actor, /^unlisted:[0-9a-f]{16}$/, label);
  assert.notEqual(events[0].actor, unkeyed(guess), `${label}: not the plain SHA-256 of the value`);
  assert.equal(events[1].actor, events[0].actor, `${label}: one value reads alike within an observer`);
};
test('SQLite and HTTP audit observers key unlisted actors and their rows per instance; declared principals stay', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-f5-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'app.db'), db = new DatabaseSync(path);
  db.exec('CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, what TEXT);');
  const cfg = { path, principals: ['agent-sam'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'what' } };
  const [a, b] = [createSqliteAuditObserver(cfg), createSqliteAuditObserver(cfg)];
  const [a0, b0] = [await a.mark(), await b.mark()];
  db.exec("INSERT INTO audit (who, what) VALUES ('carol@example.test', 'note.create'), ('carol@example.test', 'note.create'), ('agent-sam', 'note.create');"); db.close();
  const [aw, bw] = [await collectWindow(a, a0, await a.mark()), await collectWindow(b, b0, await b.mark())];
  keyedActor(aw.events, 'carol@example.test', 'sqlite');
  assert.notEqual(bw.events[0].actor, aw.events[0].actor, 'another observer instance keys it differently');
  assert.equal(aw.events[2].actor, 'agent-sam');
  assert.notEqual(aw.events[0].contentDigest, digest(digest({ id: 1, who: 'carol@example.test', what: 'note.create' })), 'the row digest cannot confirm a guessed actor');

  let items = [];
  const httpAudit = () => createHttpAuditObserver({ origin: 'http://127.0.0.1:9', path: '/audit', pageLimit: 100, itemsPointer: '/items', fields: { id: '/id', actor: '/user', action: '/action' },
    actions: { 'note.create': 'insert' }, principals: ['agent-sam'], transport: async () => ({ status: 200, jsonParsed: true, json: { items } }) });
  const [http, http2] = [httpAudit(), httpAudit()];
  const [h0, h20] = [await http.mark(), await http2.mark()];
  items = [{ id: 1, user: 'carol@example.test', action: 'note.create' }, { id: 2, user: 'carol@example.test', action: 'note.create' }, { id: 3, user: 'agent-sam', action: 'note.create' }];
  const hw = await collectWindow(http, h0, await http.mark());
  keyedActor(hw.events, 'carol@example.test', 'http audit');
  assert.notEqual((await collectWindow(http2, h20, await http2.mark())).events[0].actor, hw.events[0].actor, 'another observer instance keys it differently');
  assert.equal(hw.events[2].actor, 'agent-sam');
  assert.notEqual(hw.events[0].contentDigest, digest(digest(items[0])), 'the entry digest cannot confirm a guessed actor');
});
test('OTel and the MCP proxy key unlisted actors per instance; declared principals stay', async () => {
  const otel = createOtelObserver({ services: ['app'], principals: ['agent-sam'], settleMs: 50 }), otel2 = createOtelObserver({ services: ['app'], settleMs: 50 });
  await otel.start(); await otel2.start();
  try {
    const from = await otel.mark(), at = n => String(from.at + BigInt(n));
    const s = (i, actor) => spanOf(tool('refund', actor), { spanId: hex(8, i), startTimeUnixNano: at(10 * i), endTimeUnixNano: at(10 * i + 1) });
    const body = otlp('app', [s(1, 'carol@example.test'), s(2, 'carol@example.test'), s(3, 'agent-sam')]);
    assert.equal((await post(otel.endpoint, body)).status, 200);
    assert.equal((await post(otel2.endpoint, body)).status, 200);
    const w = await collectWindow(otel, from, { at: from.at + 1000n, seq: 0 });
    keyedActor(w.events, 'carol@example.test', 'otel');
    assert.equal(w.events[2].actor, 'agent-sam');
    assert.notEqual((await collectWindow(otel2, from, { at: from.at + 1000n, seq: 0 })).events[0].actor, w.events[0].actor, 'another observer instance keys it differently');
  } finally { await otel.stop(); await otel2.stop(); }

  const upstream = await mcpUpstream((m, _req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [] } })); });
  const mcpProxy = () => createMcpHttpProxy({ upstream: `${upstream.url}/mcp`, actors: [{ actorId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM' }], env: { SCOPEHAVEN_TARGET_SAM: 'synthetic-mcp-token' } });
  const proxy = mcpProxy(), proxy2 = mcpProxy();
  await proxy.start(); await proxy2.start();
  try {
    const o = createMcpObserver({ log: proxy.log }), from = await o.mark();
    const call = (id, auth) => post(proxy.url, { jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'refund', arguments: {} } }, { Authorization: auth });
    for (const [id, auth] of [[1, 'Bearer guessable-token'], [2, 'Bearer guessable-token'], [3, 'Bearer synthetic-mcp-token']]) assert.equal((await call(id, auth)).status, 200);
    const w = await collectWindow(o, from, await o.mark());
    keyedActor(w.events, 'Bearer guessable-token', 'mcp');
    assert.equal(w.events[2].actor, 'agent-sam');
    assert.ok(!JSON.stringify(proxy.log.frames).includes(unkeyed('Bearer guessable-token')));
    const o2 = createMcpObserver({ log: proxy2.log }), from2 = await o2.mark();
    assert.equal((await post(proxy2.url, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'refund', arguments: {} } }, { Authorization: 'Bearer guessable-token' })).status, 200);
    assert.notEqual((await collectWindow(o2, from2, await o2.mark())).events[0].actor, w.events[0].actor, 'another proxy keys it differently');
  } finally { await proxy.stop(); await proxy2.stop(); await upstream.close(); }
});
