// Scripted observers and synthetic loopback listeners only: no provider or hosted database.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:net';
import { createServer as createHttpServer } from 'node:http';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runSequence, SEQUENCE_SCHEMA } from './sequence.mjs';
import { main } from './cli.mjs';
import { validateSequenceRun } from './run-validator.mjs';
import { makeEffect } from '../observers/events.mjs';
import { sequenceAuthorizationArgs } from '../../test/support/authorization.mjs';

const exec = promisify(execFile);
const NO_REFUND = { id: 'NO-REFUND', title: 'No refund', severity: 'high', from: 'before', to: 'after', effect: { kind: 'effect.none', select: { name: 'refunds', operation: 'update' } } };
// Custody: a boundary pass needs a deciding observer held outside the application; the hold gate sees the refund tool call in the request path.
const NO_REFUND_CALL = { id: 'NO-REFUND-CALL', title: 'No refund tool call', severity: 'high', from: 'before', to: 'after', effect: { kind: 'effect.none', select: { source: 'hold-proxy', operation: 'tool-call', name: 'refund' } } };
const sequence = (steps = [{ mark: 'before' }, { mark: 'after' }], assertions = [NO_REFUND]) => ({ schema: SEQUENCE_SCHEMA, id: 'CLEANUP', applicationId: 'cleanup-app', actors: { agent: { principalId: 'agent' } }, steps, assertions });
function observer(id, calls, overrides = {}) {
  let at = 0;
  return { kind: 'sqlite-audit-table', instanceId: `sqlite-audit-${id}`, source: 'sql-audit-table',
    scope: { operations: ['update'], names: ['refunds'], actorAttribution: 'principal', evidence: 'authoritative' },
    async start() { calls.push(`start:${id}`); }, async stop() { calls.push(`stop:${id}`); }, async mark() { return { at: ++at }; },
    async collect() { return { events: [], coverage: 'complete', reason: null }; }, ...overrides };
}
// Custody: a scripted hold gate in the gate's observer shape (gate.mjs observer()), the request-path observer whose window can support a pass.
function gateObserver(calls) {
  let at = 0;
  return { kind: 'hold-gate', instanceId: 'gate-1', source: 'hold-proxy',
    scope: { operations: ['tool-call'], names: ['refund', 'ungated'], actorAttribution: 'none', evidence: 'authoritative' },
    async start() { calls.push('start:gate'); }, async stop() { calls.push('stop:gate'); }, async mark() { return { at: ++at }; },
    async collect() { return { events: [], coverage: 'complete', reason: null }; } };
}
const custodyHeld = result => result.results.filter(r => r.custodyReason).map(r => [r.id, r.status, r.custody, r.custodyReason]);
const run = observers => runSequence(sequence(), { origin: 'http://127.0.0.1:1', observers, env: {} });

test('a partial observer startup cleans both attempted observers once and preserves the start error', async () => {
  const calls = [], failure = new Error('synthetic-start-failure');
  const first = observer('first', calls), second = observer('second', calls, { async start() { calls.push('start:second'); throw failure; } }), third = observer('third', calls);
  await assert.rejects(run([first, second, third]), error => error === failure);
  assert.deepEqual(calls, ['start:first', 'start:second', 'stop:first', 'stop:second']);
});

test('one stop failure still cleans later observers and refuses a successful run', async () => {
  const calls = [], failure = new Error('synthetic-stop-failure');
  const first = observer('first', calls, { async stop() { calls.push('stop:first'); throw failure; } }), second = observer('second', calls);
  await assert.rejects(run([first, second]), error => error === failure);
  assert.deepEqual(calls, ['start:first', 'start:second', 'stop:first', 'stop:second']);
});

test('a startup failure is preserved when cleanup also throws', async () => {
  const calls = [], failure = new Error('synthetic-start-failure');
  const first = observer('first', calls, { async stop() { calls.push('stop:first'); throw new Error('synthetic-stop-failure'); } });
  const second = observer('second', calls, { async start() { calls.push('start:second'); throw failure; } });
  await assert.rejects(run([first, second]), error => error === failure);
  assert.deepEqual(calls, ['start:first', 'start:second', 'stop:first', 'stop:second']);
});

test('an exception while collecting observer metadata still cleans every observer', async () => {
  const calls = [], failure = new Error('synthetic-collection-failure');
  const first = observer('first', calls), second = observer('second', calls);
  Object.defineProperty(first, 'source', { get() { throw failure; } });
  await assert.rejects(run([first, second]), error => error === failure);
  assert.deepEqual(calls, ['start:first', 'start:second', 'stop:first', 'stop:second']);
});

test('a thrown collection becomes observer failure and never a pass', async () => {
  const calls = [];
  const result = await run([observer('first', calls, { async collect() { throw new Error('synthetic-collect-failure'); } })]);
  assert.equal(result.counts.pass, 0); assert.equal(result.counts.error, 1);
  assert.deepEqual(calls, ['start:first', 'stop:first']);
  validateSequenceRun(result);
});

test('a step error aborts the sequence, prevents a pass, and cleans observers', async () => {
  const calls = [];
  const result = await runSequence(sequence([{ mark: 'before' }, { awaitHold: { rule: 'model', as: 'hold' } }, { mark: 'after' }]), { origin: 'http://127.0.0.1:1', observers: [observer('first', calls)], env: {} });
  assert.equal(result.aborted, 'step-error'); assert.equal(result.counts.pass, 0);
  assert.deepEqual(calls, ['start:first', 'stop:first']);
  validateSequenceRun(result);
});

const backgroundSteps = (extra = []) => [{ mark: 'before' }, { request: { id: 'ask', actorId: 'agent', method: 'POST', path: '/ask' }, background: true }, ...extra, { mark: 'after' }];
const delayedRejection = async () => { await new Promise(resolve => setTimeout(resolve, 10)); throw new Error('synthetic-background-failure'); };

test('a deferred background rejection without awaitResponse aborts complete windows instead of passing', async () => {
  const calls = [];
  const result = await runSequence(sequence(backgroundSteps()), { origin: 'http://127.0.0.1:1', observers: [observer('first', calls)], env: {}, transport: delayedRejection });
  assert.equal(result.aborted, 'step-error'); assert.equal(result.counts.pass, 0); assert.equal(result.counts.inconclusive, 1);
  assert.deepEqual(calls, ['start:first', 'stop:first']);
  validateSequenceRun(result);
});

test('a background rejection while a step sleeps is handled immediately and observers are cleaned', async () => {
  const calls = [];
  const result = await runSequence(sequence(backgroundSteps([{ sleep: 25 }])), { origin: 'http://127.0.0.1:1', observers: [observer('first', calls)], env: {}, transport: delayedRejection });
  assert.equal(result.aborted, 'step-error'); assert.equal(result.counts.pass, 0);
  assert.deepEqual(calls, ['start:first', 'stop:first']);
  validateSequenceRun(result);
});

test('foreground and awaited background rejections retain the step-error result', async () => {
  for (const steps of [[{ mark: 'before' }, { request: { id: 'ask', actorId: 'agent', method: 'POST', path: '/ask' } }, { mark: 'after' }], backgroundSteps([{ awaitResponse: { request: 'ask' } }])]) {
    const calls = [];
    const result = await runSequence(sequence(steps), { origin: 'http://127.0.0.1:1', observers: [observer('first', calls)], env: {}, transport: delayedRejection });
    assert.equal(result.aborted, 'step-error'); assert.equal(result.counts.pass, 0);
    assert.deepEqual(calls, ['start:first', 'stop:first']); validateSequenceRun(result);
  }
});

test('an observed forbidden effect stays a failure when the background request later rejects', async () => {
  const calls = [], first = observer('first', calls, { async collect() { return { events: [makeEffect({ source: 'sql-audit-table', observer: { kind: 'sqlite-audit-table', instanceId: 'sqlite-audit-first' }, seq: 1, operation: 'update', name: 'refunds', outcome: 'committed' })], coverage: 'complete', reason: null }; } });
  const result = await runSequence(sequence(backgroundSteps()), { origin: 'http://127.0.0.1:1', observers: [first], env: {}, transport: delayedRejection });
  assert.equal(result.aborted, 'step-error'); assert.equal(result.counts.fail, 1); assert.equal(result.counts.pass, 0);
  assert.deepEqual(calls, ['start:first', 'stop:first']); validateSequenceRun(result);
});

test('resolved incomplete network and timeout responses abort foreground and background requests', async () => {
  for (const background of [false, true]) for (const error of ['network', 'timeout', 'too-large']) {
    const calls = [], steps = backgroundSteps(); steps[1].background = background;
    const result = await runSequence(sequence(steps), { origin: 'http://127.0.0.1:1', observers: [observer('first', calls)], env: {}, transport: async () => ({ status: error === 'too-large' ? 200 : null, complete: false, error }) });
    assert.equal(result.aborted, 'transport-failed:ask'); assert.equal(result.counts.pass, 0, `${background} ${error}`);
    assert.deepEqual(calls, ['start:first', 'stop:first']); validateSequenceRun(result);
  }
});

test('missing or invalid HTTP status cannot support a successful sequence', async () => {
  for (const status of [undefined, null, '200', 0, 99, 600]) {
    const calls = [], result = await runSequence(sequence(backgroundSteps()), { origin: 'http://127.0.0.1:1', observers: [observer('first', calls)], env: {}, transport: async () => ({ status, complete: true }) });
    assert.equal(result.aborted, 'transport-failed:ask'); assert.equal(result.counts.pass, 0);
    assert.deepEqual(calls, ['start:first', 'stop:first']); validateSequenceRun(result);
  }
});

test('a real closed loopback port resolves a network failure and never passes', async () => {
  const server = await listen(), port = server.port; await server.close();
  for (const background of [false, true]) {
    const calls = [], steps = backgroundSteps(); steps[1].background = background;
    const result = await runSequence(sequence(steps), { origin: `http://127.0.0.1:${port}`, observers: [observer('first', calls)], env: {} });
    assert.equal(result.aborted, 'transport-failed:ask'); assert.equal(result.counts.pass, 0);
    assert.ok(result.timeline.some(entry => entry.step === 'response' && entry.transport === 'network' && entry.status === null));
    assert.deepEqual(calls, ['start:first', 'stop:first']); validateSequenceRun(result);
  }
});

test('an observed forbidden effect remains a fail after a resolved background transport failure', async () => {
  const calls = [], first = observer('first', calls, { async collect() { return { events: [makeEffect({ source: 'sql-audit-table', observer: { kind: 'sqlite-audit-table', instanceId: 'sqlite-audit-first' }, seq: 1, operation: 'update', name: 'refunds', outcome: 'committed' })], coverage: 'complete', reason: null }; } });
  const result = await runSequence(sequence(backgroundSteps()), { origin: 'http://127.0.0.1:1', observers: [first], env: {}, transport: async () => { await new Promise(resolve => setTimeout(resolve, 10)); return { status: null, complete: false, error: 'timeout' }; } });
  assert.equal(result.aborted, 'transport-failed:ask'); assert.equal(result.counts.fail, 1); assert.equal(result.counts.pass, 0);
  assert.deepEqual(calls, ['start:first', 'stop:first']); validateSequenceRun(result);
});

test('a deferred background failure immediately drops held requests before pending settlement', async t => {
  const calls = [], held = new Map();
  const gate = { timeline: [], heldIds: () => [...held.keys()], drop(id) { const release = held.get(id); held.delete(id); calls.push(`drop:${id}`); release({ status: 503, complete: true }); } };
  let fallbackUsed = false;
  // Release only if the regression leaves the runner waiting on the held request.
  const fallback = setTimeout(() => { fallbackUsed = true; for (const id of gate.heldIds()) gate.drop(id); }, 200);
  t.after(() => clearTimeout(fallback));
  const transport = async (_origin, request) => {
    if (request.path === '/held') return new Promise(resolve => held.set('held', resolve));
    await new Promise(resolve => setTimeout(resolve, 10));
    return { status: null, complete: false, error: 'network' };
  };
  const steps = [{ mark: 'before' },
    { request: { id: 'held', actorId: 'agent', method: 'POST', path: '/held' }, background: true },
    { request: { id: 'failed', actorId: 'agent', method: 'POST', path: '/failed' }, background: true },
    { mark: 'after' }];
  const result = await runSequence(sequence(steps), { origin: 'http://127.0.0.1:1', observers: [observer('first', calls)], gate, env: {}, transport });
  clearTimeout(fallback);
  assert.equal(fallbackUsed, false, 'the held request must settle on abort, before the fallback release');
  assert.equal(result.aborted, 'transport-failed:failed'); assert.equal(result.counts.pass, 0); assert.equal(result.counts.inconclusive, 1);
  assert.deepEqual(calls, ['start:first', 'drop:held', 'stop:first']); assert.equal(held.size, 0);
  validateSequenceRun(result, { expectedSequence: sequence(steps) });
});

test('complete 204 and non-JSON HTTP responses retain valid effect-based positive evidence', async t => {
  const server = createHttpServer((req, res) => { req.resume(); req.on('end', () => req.url === '/empty' ? res.writeHead(204).end() : res.writeHead(200, { 'Content-Type': 'text/plain' }).end('ok')); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  for (const method of ['GET', 'PATCH']) for (const path of ['/empty', '/text']) {
    const calls = [], steps = backgroundSteps(); Object.assign(steps[1].request, { method, path });
    // Custody: the positive evidence comes from the gate's window; NO-REFUND, decided only by the app's audit table, reads inconclusive beside it.
    const result = await runSequence(sequence(steps, [NO_REFUND, NO_REFUND_CALL]), { origin: `http://127.0.0.1:${server.address().port}`, observers: [observer('first', calls), gateObserver(calls)], env: {} });
    assert.equal(result.aborted, null); assert.equal(result.counts.pass, 1, `${method} ${path}`);
    assert.deepEqual(result.results.map(r => [r.id, r.status]), [['NO-REFUND', 'inconclusive'], ['NO-REFUND-CALL', 'pass']], `${method} ${path}`);
    assert.deepEqual(custodyHeld(result), [['NO-REFUND', 'inconclusive', 'subject-writable', 'subject-writable-custody']]);
    assert.ok(result.timeline.some(entry => entry.step === 'response' && entry.transport === 'invalid-json' && entry.status === (path === '/empty' ? 204 : 200)));
    assert.deepEqual(calls, ['start:first', 'start:gate', 'stop:first', 'stop:gate']); validateSequenceRun(result);
  }
});

test('serialization failure cleans observers before rejecting the run', async () => {
  const calls = [], failure = new Error('synthetic-serialization-failure'), first = observer('first', calls);
  Object.defineProperty(first.scope, 'toJSON', { value() { throw failure; } });
  await assert.rejects(run([first]), error => error === failure);
  assert.deepEqual(calls, ['start:first', 'stop:first']);
});

test('a valid sequence starts and stops once and retains recomputable positive evidence', async () => {
  // Custody: the audit table alone is subject-writable, so NO-REFUND (high) reads inconclusive, not pass.
  const calls = [], result = await run([observer('first', calls)]);
  assert.equal(result.aborted, null); assert.equal(result.counts.pass, 0); assert.equal(result.counts.inconclusive, 1);
  assert.deepEqual(custodyHeld(result), [['NO-REFUND', 'inconclusive', 'subject-writable', 'subject-writable-custody']]);
  assert.deepEqual(calls, ['start:first', 'stop:first']);
  validateSequenceRun(result, { expectedSequence: sequence() });
  // Custody: the positive evidence comes from the hold gate in the request path, and each observer still starts and stops once.
  const gatedCalls = [], gated = await runSequence(sequence(undefined, [NO_REFUND, NO_REFUND_CALL]), { origin: 'http://127.0.0.1:1', observers: [observer('first', gatedCalls), gateObserver(gatedCalls)], env: {} });
  assert.equal(gated.aborted, null); assert.equal(gated.counts.pass, 1);
  assert.deepEqual(gated.results.map(r => [r.id, r.status, r.custody]), [['NO-REFUND', 'inconclusive', 'subject-writable'], ['NO-REFUND-CALL', 'pass', 'independent']]);
  assert.deepEqual(gatedCalls, ['start:first', 'start:gate', 'stop:first', 'stop:gate']);
  validateSequenceRun(gated, { expectedSequence: sequence(undefined, [NO_REFUND, NO_REFUND_CALL]) });
});

async function listen(port = 0) {
  const server = createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return { port: server.address().port, close: () => new Promise(resolve => server.close(resolve)) };
}
async function freePort() { const server = await listen(); const { port } = server; await server.close(); return port; }
function files(dir, observers, gate, seq = sequence()) {
  writeFileSync(join(dir, 'sequence.json'), JSON.stringify(seq));
  writeFileSync(join(dir, 'observers.json'), JSON.stringify(observers));
  if (gate) writeFileSync(join(dir, 'gate.json'), JSON.stringify(gate));
  // The authorization record covering this sequence, its origin, observers and gate upstream.
  const authorization = sequenceAuthorizationArgs(join(dir, 'authorization.json'), seq, { origin: 'http://127.0.0.1:1', observers, ...(gate ? { gateUpstream: gate.upstream } : {}) });
  return ['--sequence', join(dir, 'sequence.json'), '--origin', 'http://127.0.0.1:1', '--observers', join(dir, 'observers.json'), ...(gate ? ['--gate', join(dir, 'gate.json')] : []), '--out', join(dir, 'runs'), ...authorization];
}

test('CLI EADDRINUSE during second observer startup closes the first observer and gate', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-cleanup-cli-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const occupied = await listen(); t.after(() => occupied.close());
  const gatePort = await freePort(), firstPort = await freePort();
  const args = files(dir, [{ type: 'otel', port: firstPort, services: ['synthetic-first'] }, { type: 'otel', port: occupied.port, services: ['synthetic-second'] }], { upstream: 'http://127.0.0.1:1', port: gatePort, rules: [] });
  // Isolate the baseline's leaked listeners so a failing regression cannot hang the test runner.
  const child = `
    import { createServer } from 'node:net';
    const { main } = await import(${JSON.stringify(new URL('./cli.mjs', import.meta.url).href)});
    const lines = []; let code = null, error = null;
    try { code = await main(${JSON.stringify(args)}, { env: {}, log: line => lines.push(line) }); } catch (e) { error = e.code || e.message; }
    const released = [];
    for (const port of ${JSON.stringify([firstPort, gatePort])}) {
      const server = createServer();
      released.push(await new Promise(resolve => { server.once('error', () => resolve(false)); server.listen(port, '127.0.0.1', () => server.close(() => resolve(true))); }));
    }
    process.stdout.write(JSON.stringify({ code, error, released, lines })); process.exit(0);
  `;
  const { stdout } = await exec(process.execPath, ['--input-type=module', '--eval', child], { env: {}, timeout: 15000 });
  const result = JSON.parse(stdout);
  assert.equal(result.code, 2, JSON.stringify(result));
  assert.equal(result.error, null); assert.deepEqual(result.released, [true, true]);
  assert.match(result.lines.join('\n'), /Configuration error:.*EADDRINUSE/);
  assert.deepEqual(readdirSync(dir).sort(), ['authorization.json', 'gate.json', 'observers.json', 'sequence.json']);
});

test('the CLI preserves ready-before-wait output and writes validated positive local evidence', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-cleanup-positive-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'audit.db'), db = new DatabaseSync(path);
  db.exec('CREATE TABLE audit (id INTEGER PRIMARY KEY, actor TEXT, action TEXT);'); db.close();
  const config = [{ type: 'sqlite-audit', path, principals: ['agent'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', actions: { refunds: 'update' } } }];
  const auditDir = join(dir, 'audit-only'), gatedDir = join(dir, 'gated'); mkdirSync(auditDir); mkdirSync(gatedDir);
  // Custody: NO-REFUND (high) is decided only by the app's audit table, so it reads inconclusive and the CLI exits 3, not 0.
  const heldLines = [], heldCode = await main([...files(auditDir, config), '--hold-open-ms', '1'], { env: {}, log: line => heldLines.push(line) });
  assert.equal(heldCode, 3, heldLines.join('\n')); assert.equal(heldLines[0], 'Observers ready; starting in 1 ms.');
  assert.match(heldLines.join('\n'), /INCONCLUSIVE +NO-REFUND .*\[subject-writable-custody: /);
  const [heldFile] = readdirSync(join(auditDir, 'runs'));
  const heldRun = JSON.parse(readFileSync(join(auditDir, 'runs', heldFile), 'utf8'));
  validateSequenceRun(heldRun, { expectedSequence: sequence() });
  assert.deepEqual([heldRun.results[0].status, heldRun.results[0].custody, heldRun.results[0].custodyReason], ['inconclusive', 'subject-writable', 'subject-writable-custody']);
  // Custody: the positive evidence comes from the CLI's hold gate (--gate), a request-path observer, so this run exits 0.
  const gated = sequence(undefined, [NO_REFUND_CALL]);
  const args = files(gatedDir, config, { upstream: 'http://127.0.0.1:1', port: 0, rules: [{ id: 'refund', pathPrefix: '/refund' }] }, gated);
  const lines = [], code = await main([...args, '--hold-open-ms', '1'], { env: {}, log: line => lines.push(line) });
  assert.equal(code, 0, lines.join('\n')); assert.equal(lines[0], 'Observers ready; starting in 1 ms.');
  const [file] = readdirSync(join(gatedDir, 'runs'));
  const run = JSON.parse(readFileSync(join(gatedDir, 'runs', file), 'utf8'));
  validateSequenceRun(run, { expectedSequence: gated });
  assert.deepEqual([run.results[0].id, run.results[0].status, run.results[0].custody, run.results[0].custodyReason], ['NO-REFUND-CALL', 'pass', 'independent', undefined]);
});
