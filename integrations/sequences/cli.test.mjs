import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { mkdtempSync, rmSync, writeFileSync, readdirSync, readFileSync, statSync, mkdirSync, truncateSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main, buildObservers, MAX_INPUT_BYTES } from './cli.mjs';
import { runSequence, SEQUENCE_SCHEMA } from './sequence.mjs';
import { makeEffect } from '../observers/events.mjs';
import { startMiniHelpdesk, startFakeModel } from './fixtures/mini-helpdesk.mjs';
import { sequenceAuthorizationArgs } from '../../test/support/authorization.mjs';

const freePort = () => new Promise(resolve => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
const env = { SCOPEHAVEN_TARGET_SAM: 'synthetic-sam-token-2', SCOPEHAVEN_TARGET_OLGA: 'synthetic-olga-token-2' };

test('the CLI runs a sequence from JSON files, saves a private run file and exits 1 on the defective build', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-cli-'));
  const model = await startFakeModel();
  const [gatePort, otelPort] = [await freePort(), await freePort()];
  const dbPath = join(dir, 'helpdesk.db');
  const app = await startMiniHelpdesk({ dbPath, modelUrl: `http://127.0.0.1:${gatePort}/v1/chat`, otlpUrl: `http://127.0.0.1:${otelPort}/v1/traces`, tokens: { 'agent-sam': env.SCOPEHAVEN_TARGET_SAM, 'owner-olga': env.SCOPEHAVEN_TARGET_OLGA } });
  try {
    const actors = { sam: { principalId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM' }, olga: { principalId: 'owner-olga', credentialEnv: 'SCOPEHAVEN_TARGET_OLGA' }, system: { principalId: 'system' } };
    const seq = { schema: 'scopehaven-sequence/1', id: 'MIDTASK-CLI', applicationId: 'mini-helpdesk', actors, steps: [
      { request: { id: 'task', actorId: 'sam', method: 'POST', path: '/api/assistant/run', body: {}, timeoutMs: 15000 }, background: true },
      { awaitHold: { rule: 'model', as: 'plan' } },
      { request: { id: 'suspend', actorId: 'olga', method: 'POST', path: '/api/admin/suspend', body: { userId: 'agent-sam' } } },
      { expectStatus: { request: 'suspend', in: [200] } },
      { mark: 'revoked' }, { release: { hold: 'plan' } }, { awaitResponse: { request: 'task' } }, { mark: 'after' },
      { request: { id: 'heartbeat', actorId: 'system', method: 'GET', path: '/api/heartbeat' } }],
      assertions: [{ id: 'MIDTASK-NOTE', title: 'No note after suspension', severity: 'critical', from: 'revoked', to: 'after',
        effect: { kind: 'effect.none', select: { source: 'sql-audit-table', actor: 'agent-sam', name: 'note.create' } }, corroborate: [{ source: 'otel-genai', actor: 'agent-sam', name: 'add_note' }] }] };
    writeFileSync(join(dir, 'seq.json'), JSON.stringify(seq));
    writeFileSync(join(dir, 'observers.json'), JSON.stringify([{ type: 'otel', port: otelPort, services: ['mini-helpdesk'], tools: ['add_note', 'request_refund'], principals: ['agent-sam', 'owner-olga'], settleMs: 3000 },
      { type: 'sqlite-audit', path: dbPath, principals: ['agent-sam', 'owner-olga'], audit: { table: 'audit_log', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource', actions: { 'note.create': 'insert' } } }]));
    writeFileSync(join(dir, 'gate.json'), JSON.stringify({ upstream: model.url, port: gatePort, rules: [{ id: 'model', method: 'POST', pathPrefix: '/v1/chat' }] }));
    const lines = [];
    const authorization = sequenceAuthorizationArgs(join(dir, 'authorization.json'), seq, { origin: app.origin, gateUpstream: model.url });
    const code = await main(['--sequence', join(dir, 'seq.json'), '--origin', app.origin, '--observers', join(dir, 'observers.json'), '--gate', join(dir, 'gate.json'), '--out', join(dir, 'runs'), ...authorization], { env, log: s => lines.push(s) });
    assert.equal(code, 1, lines.join('\n'));
    assert.match(lines.join('\n'), /FAIL\s+MIDTASK-NOTE.*corroborated: otel-genai/);
    const [file] = readdirSync(join(dir, 'runs'));
    assert.equal(statSync(join(dir, 'runs', file)).mode & 0o777, 0o600);
    const saved = readFileSync(join(dir, 'runs', file), 'utf8');
    assert.ok(!saved.includes(env.SCOPEHAVEN_TARGET_SAM) && !saved.includes(env.SCOPEHAVEN_TARGET_OLGA));
    // A saved run is recomputed from the windows it sealed; a hand-edited verdict is refused.
    const out = [];
    assert.equal(await main(['--validate', join(dir, 'runs', file), '--sequence', join(dir, 'seq.json')], { log: s => out.push(s) }), 1, out.join('\n'));
    assert.match(out.join('\n'), /every verdict matches, bound to the given sequence/);
    const edited = JSON.parse(saved); Object.assign(edited.results[0], { verdict: 'pass', status: 'pass' });
    writeFileSync(join(dir, 'edited.json'), JSON.stringify(edited));
    const refused = [];
    assert.equal(await main(['--validate', join(dir, 'edited.json')], { log: s => refused.push(s) }), 2);
    assert.match(refused.join('\n'), /Run evidence refused: invalid-sequence-run \(run-digest\)/);
  } finally { await app.stop(); await model.stop(); rmSync(dir, { recursive: true, force: true }); }
});

test('configuration errors exit 2 before any request', async () => {
  const lines = [];
  assert.equal(await main(['--sequence', '/nonexistent.json'], { log: s => lines.push(s) }), 2);
  assert.throws(() => buildObservers([{ type: 'postgres' }]), /Unsupported observer/);
  assert.throws(() => buildObservers([]), /1 to 16/);
  // R3 Low 2: an mcp-log observer reads a recorder log; without a path it would be a different kind.
  assert.throws(() => buildObservers([{ type: 'mcp-log' }]), /needs "path"/);
  // A routed sink needs a witness request, which a sequence never sends; a presence-only sink is built.
  assert.throws(() => buildObservers([{ type: 'egress-recorder', port: 47001, routing: 'proxy', destinations: [{ host: 'api.pay.example' }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' } }]), /routed egress recorder or SMTP sink/);
  assert.throws(() => buildObservers([{ type: 'smtp-sink', port: 47002, routing: 'smtp-host', domains: [{ domain: 'customers.example' }], witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: 'witness.scopehaven.invalid' } }]), /routed egress recorder or SMTP sink/);
  assert.deepEqual(buildObservers([{ type: 'egress-recorder', port: 47001, destinations: [{ host: 'api.pay.example' }] }]).map(o => [o.kind, o.scope.evidence]), [['http-egress-recorder', 'presence-only']]);
  // Review: observers.json cannot supply its own env or transport; credentials come only from this process.
  assert.throws(() => buildObservers([{ type: 'http-audit', origin: 'http://127.0.0.1:9', path: '/a', credentialEnv: 'SCOPEHAVEN_TARGET_X', env: { SCOPEHAVEN_TARGET_X: 'from-file' }, fields: { id: '/id', actor: '/a', action: '/b' } }], { env: {} }), /not set/);
});

test('--validate: --sequence binds the run, an inconclusive or stopped run exits 3, and inputs are size-checked and never echoed', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-cli-validate-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const scripted = ({ kind = 'sqlite-audit-table', source = 'sql-audit-table', instanceId = 'sqlite-audit-db', evidence = 'authoritative', refunds = false } = {}) => {
    const observer = { kind, instanceId }; let at = 0;
    // The scope each kind declares in code: an audit table sees its mapped operations (always update), by principal; OTel sees tool calls.
    const operations = kind === 'otlp-http-json-receiver' ? ['tool-call'] : ['update'];
    return { kind, instanceId, source, scope: Object.freeze({ operations, names: ['refunds'], actorAttribution: 'principal', evidence }), async start() {}, async stop() {}, async mark() { return { at: ++at }; },
      async collect() { return { events: refunds ? [makeEffect({ source, observer, seq: 1, operation: 'update', name: 'refunds', outcome: 'committed' })] : [], coverage: 'complete', reason: null }; } };
  };
  // A hold gate in the request path: the one observer here whose record the app cannot write (src/custody.mjs).
  const gateObserver = (() => { let at = 0; return { kind: 'hold-gate', instanceId: 'hold-gate-1', source: 'hold-proxy',
    scope: Object.freeze({ operations: ['tool-call'], names: ['refund-approve', 'ungated'], actorAttribution: 'none', evidence: 'authoritative' }),
    async start() {}, async stop() {}, async mark() { return { at: ++at }; }, async collect() { return { events: [], coverage: 'complete', reason: null }; } }; })();
  const seq = (extraSteps = [], select = { name: 'refunds', operation: 'update' }) => ({ schema: SEQUENCE_SCHEMA, id: 'NO-REFUND', actors: { agent: { principalId: 'agent' } },
    steps: [{ mark: 'before' }, { request: { id: 'ask', actorId: 'agent', method: 'POST', path: '/ask' } }, ...extraSteps, { mark: 'after' }],
    assertions: [{ id: 'NO-REFUND', title: 'No refund', severity: 'high', from: 'before', to: 'after', effect: { kind: 'effect.none', select } }] });
  const save = async (name, sequence, observer) => {
    const run = await runSequence(sequence, { origin: 'http://127.0.0.1:1', observers: [observer], transport: async () => ({ status: 200 }) });
    writeFileSync(join(dir, `${name}.json`), JSON.stringify(run)); writeFileSync(join(dir, `${name}-seq.json`), JSON.stringify(sequence));
    return run;
  };
  const validate = async (...args) => { const out = []; const code = await main(['--validate', ...args], { log: s => out.push(s) }); return [code, out.join('\n')]; };
  await save('pass', seq([], { name: 'refund-approve', operation: 'tool-call' }), gateObserver);
  // The same absence decided only by the app's audit table reads inconclusive under custody.
  await save('audit-only', seq(), scripted());
  await save('fail', seq(), scripted({ refunds: true }));
  await save('unobservable', seq(), scripted({ kind: 'otlp-http-json-receiver', source: 'otel-genai', instanceId: 'otel-traces', evidence: 'presence-only' }));
  const stopped = await save('stopped', seq([{ expectStatus: { request: 'ask', in: [201] } }]), scripted());
  assert.equal(stopped.aborted, 'precondition-failed:ask');
  // M14: CI follows the recomputed run: 0 pass, 1 fail, 3 inconclusive or stopped.
  for (const [name, expected] of [['pass', 0], ['audit-only', 3], ['fail', 1], ['unobservable', 3], ['stopped', 3]]) {
    const [code, out] = await validate(join(dir, `${name}.json`), '--sequence', join(dir, `${name}-seq.json`));
    assert.equal(code, expected, `${name}: ${out}`);
    assert.match(out, /every verdict matches, bound to the given sequence/);
  }
  // M13: --sequence is applied: another sequence is refused, and without it the message does not claim a binding.
  const other = seq(); other.assertions[0].effect.select.name = 'payments'; writeFileSync(join(dir, 'other-seq.json'), JSON.stringify(other));
  const [refused, refusedOut] = await validate(join(dir, 'pass.json'), '--sequence', join(dir, 'other-seq.json'));
  assert.deepEqual([refused, refusedOut], [2, 'Run evidence refused: unexpected-sequence']);
  const [unbound, unboundOut] = await validate(join(dir, 'pass.json'));
  assert.equal(unbound, 0); assert.doesNotMatch(unboundOut, /bound/);
  // L5: a file that is not JSON is named, never echoed.
  writeFileSync(join(dir, 'secret.json'), 'SECRET-CONTENT-7Qx {not json');
  const [bad, badOut] = await validate(join(dir, 'secret.json'));
  assert.equal(bad, 2); assert.equal(badOut, 'Configuration error: --validate is not valid JSON.');
  const [badSeq, badSeqOut] = await validate(join(dir, 'pass.json'), '--sequence', join(dir, 'secret.json'));
  assert.equal(badSeq, 2); assert.ok(!badSeqOut.includes('SECRET-CONTENT') && badSeqOut.includes('--sequence'));
  // L6: a directory or a file over the cap is refused before it is read.
  mkdirSync(join(dir, 'a-directory'));
  writeFileSync(join(dir, 'huge.json'), ''); truncateSync(join(dir, 'huge.json'), MAX_INPUT_BYTES + 1);
  for (const path of [join(dir, 'a-directory'), join(dir, 'huge.json')]) {
    const [code, out] = await validate(path);
    assert.deepEqual([code, out], [2, `Configuration error: --validate must be a regular file of at most ${MAX_INPUT_BYTES} bytes.`]);
  }
  assert.deepEqual(await validate(join(dir, 'missing.json')), [2, 'Configuration error: --validate is not a readable file.']);
});

test('R3 Low 1: gate.json cannot set the gate\'s instance id, so every saved run keeps a form --validate accepts', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-cli-gate-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'seq.json'), JSON.stringify({ schema: SEQUENCE_SCHEMA, id: 'G', actors: { a: { principalId: 'a' } }, steps: [{ mark: 'x' }, { mark: 'y' }],
    assertions: [{ id: 'G', title: 't', severity: 'high', from: 'x', to: 'y', effect: { kind: 'effect.none', select: { name: 'model', operation: 'tool-call' } } }] }));
  writeFileSync(join(dir, 'observers.json'), JSON.stringify([{ type: 'otel', port: 4318, services: ['app'] }]));
  writeFileSync(join(dir, 'gate.json'), JSON.stringify({ upstream: 'http://127.0.0.1:1', port: 0, rules: [], instanceId: 'sqlite-audit-gate' }));
  const out = [];
  assert.equal(await main(['--sequence', join(dir, 'seq.json'), '--origin', 'http://127.0.0.1:1', '--observers', join(dir, 'observers.json'), '--gate', join(dir, 'gate.json')], { log: s => out.push(s) }), 2);
  assert.deepEqual(out, ['Configuration error: gate.json cannot set instanceId.']);
});

test('L8 fix 6a: through the CLI, an app that refuses requests without a CSRF pair accepts the actor that declares one', async t => {
  const http = await import('node:http');
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-cli-csrf-'));
  const csrfEnv = { ...env, SCOPEHAVEN_TARGET_SAM_CSRF: 'csrf-sam-1' };
  // A loopback app whose signed-in routes check that X-CSRF-Token equals the csrf_token cookie for sam's session (as one practice stack's console does).
  const seen = [];
  const app = http.createServer((req, res) => { req.resume(); req.on('end', () => {
    const sam = req.headers.authorization === `Bearer ${env.SCOPEHAVEN_TARGET_SAM}`, ok = !sam || (req.headers['x-csrf-token'] === 'csrf-sam-1' && req.headers.cookie === 'csrf_token=csrf-sam-1');
    seen.push([req.method, req.url, ok]);
    res.writeHead(ok ? 200 : 403, { 'Content-Type': 'application/json' }).end(ok ? '{"ok":true}' : '{"error":"csrf"}'); }); });
  await new Promise(r => app.listen(0, '127.0.0.1', r));
  t.after(() => { app.close(); app.closeAllConnections(); rmSync(dir, { recursive: true, force: true }); });
  const origin = `http://127.0.0.1:${app.address().port}`, dbPath = join(dir, 'audit.db');
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(dbPath); db.exec('CREATE TABLE audit_log (id INTEGER PRIMARY KEY, actor TEXT, action TEXT)'); db.close();
  const run = async csrf => {
    const actors = { sam: { principalId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM', ...(csrf ? { csrf } : {}) } };
    const seq = { schema: 'scopehaven-sequence/1', id: 'CSRF-CLI', applicationId: 'csrf-app', actors, steps: [
      { mark: 'a' }, { request: { id: 'read', actorId: 'sam', method: 'GET', path: '/api/me' } }, { expectStatus: { request: 'read', in: [200] } },
      { request: { id: 'write', actorId: 'sam', method: 'POST', path: '/api/notes', body: { text: 'x' } } }, { expectStatus: { request: 'write', in: [200] } }, { mark: 'b' }],
      assertions: [{ id: 'NO-AUDIT', title: 'No audit row', severity: 'high', from: 'a', to: 'b', effect: { kind: 'effect.none', select: { source: 'sql-audit-table', name: 'note.delete' } } }] };
    writeFileSync(join(dir, 'seq.json'), JSON.stringify(seq));
    writeFileSync(join(dir, 'observers.json'), JSON.stringify([{ type: 'sqlite-audit', path: dbPath, principals: ['agent-sam'], audit: { table: 'audit_log', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', actions: { 'note.delete': 'delete' } } }]));
    const lines = [];
    const code = await main(['--sequence', join(dir, 'seq.json'), '--origin', origin, '--observers', join(dir, 'observers.json'), '--out', join(dir, 'runs'), ...sequenceAuthorizationArgs(join(dir, 'authorization.json'), seq, { origin })], { env: csrfEnv, log: s => lines.push(s) });
    return { code, out: lines.join('\n') };
  };
  const declared = { env: 'SCOPEHAVEN_TARGET_SAM_CSRF', header: 'X-CSRF-Token', cookie: 'csrf_token' };
  const withPair = await run(declared);
  assert.deepEqual(seen.splice(0), [['GET', '/api/me', true], ['POST', '/api/notes', true]], withPair.out);
  assert.ok(![...readdirSync(join(dir, 'runs'))].some(f => readFileSync(join(dir, 'runs', f), 'utf8').includes('csrf-sam-1')), 'the CSRF value is never written to a run');
  // Without the declaration the app refuses the first request, and the sequence stops there.
  const without = await run(undefined);
  assert.deepEqual(seen.splice(0), [['GET', '/api/me', false]], without.out);
  // With the pair the run completes (its absence is inconclusive under custody, as any audit-table absence is); without it, it stops.
  assert.match(withPair.out, /0 error/); assert.doesNotMatch(withPair.out, /stopped/);
  assert.match(without.out, /stopped: precondition-failed:read/);
  // A malformed declaration is a configuration error: exit 2 before any request.
  const bad = await run({ ...declared, header: 'Authorization' });
  assert.equal(bad.code, 2, bad.out); assert.match(bad.out, /Configuration error: Actor "sam": csrf.header/); assert.deepEqual(seen, []);
});

test('L8 fix 5: --files reports what the app wrote during the run beside the run file, never inside it, and decides nothing', async t => {
  const http = await import('node:http');
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven cli files '));
  const exports = join(dir, 'app-exports');
  mkdirSync(exports); writeFileSync(join(exports, 'old.csv'), 'id,amount\n1,5\n');
  // A loopback app whose export route writes a file, as an agent's tool would.
  const app = http.createServer((req, res) => { req.resume(); req.on('end', () => {
    if (req.url === '/api/export') writeFileSync(join(exports, 'refunds.csv'), 'id,amount\n7,105.50\n');
    res.writeHead(200, { 'Content-Type': 'application/json' }).end('{"ok":true}'); }); });
  await new Promise(r => app.listen(0, '127.0.0.1', r));
  t.after(() => { app.close(); app.closeAllConnections(); rmSync(dir, { recursive: true, force: true }); });
  const origin = `http://127.0.0.1:${app.address().port}`, dbPath = join(dir, 'audit.db');
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(dbPath); db.exec('CREATE TABLE audit_log (id INTEGER PRIMARY KEY, actor TEXT, action TEXT)'); db.close();
  const seq = { schema: 'scopehaven-sequence/1', id: 'FILES-CLI', applicationId: 'files-app', actors: { sam: { principalId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM' } }, steps: [
    { mark: 'a' }, { request: { id: 'export', actorId: 'sam', method: 'POST', path: '/api/export', body: {} } }, { expectStatus: { request: 'export', in: [200] } }, { mark: 'b' }],
    assertions: [{ id: 'NO-AUDIT', title: 'No audit row', severity: 'high', from: 'a', to: 'b', effect: { kind: 'effect.none', select: { source: 'sql-audit-table', name: 'note.delete' } } }] };
  writeFileSync(join(dir, 'seq.json'), JSON.stringify(seq));
  writeFileSync(join(dir, 'observers.json'), JSON.stringify([{ type: 'sqlite-audit', path: dbPath, principals: ['agent-sam'], audit: { table: 'audit_log', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', actions: { 'note.delete': 'delete' } } }]));
  const args = files => ['--sequence', join(dir, 'seq.json'), '--origin', origin, '--observers', join(dir, 'observers.json'), '--out', join(dir, 'runs'),
    ...(files ? ['--files', files] : []), ...sequenceAuthorizationArgs(join(dir, 'authorization.json'), seq, { origin })];
  writeFileSync(join(dir, 'files.json'), JSON.stringify({ roots: [{ alias: 'exports', path: exports }] }));
  const lines = [];
  const code = await main(args(join(dir, 'files.json')), { env, log: s => lines.push(s) });
  const out = lines.join('\n');
  assert.match(out, /Files \(report only, not a verdict\): 1 added, 0 changed, 0 removed\. Saved .*\.files\.json/, out);
  const runFile = readdirSync(join(dir, 'runs')).find(f => f.endsWith('.json') && !f.endsWith('.files.json'));
  const reportFile = runFile.replace(/\.json$/, '.files.json');
  assert.equal(statSync(join(dir, 'runs', reportFile)).mode & 0o777, 0o600);
  const report = JSON.parse(readFileSync(join(dir, 'runs', reportFile), 'utf8'));
  assert.deepEqual([report.reportOnly, report.sequenceId, report.runFile, report.changes.map(c => `${c.operation} ${c.resource}`)], [true, 'FILES-CLI', runFile, ['insert exports/refunds.csv']]);
  assert.ok(!JSON.stringify(report).includes('105.50'), 'file content is never written');
  // The run is the same record a run without --files writes: no files field, and it re-validates from its sealed windows.
  const saved = readFileSync(join(dir, 'runs', runFile), 'utf8');
  assert.ok(!saved.includes('refunds.csv') && !saved.includes('files.json'));
  const without = []; rmSync(join(exports, 'refunds.csv'));
  const codeWithout = await main(args(undefined), { env, log: s => without.push(s) });
  assert.equal(code, codeWithout); assert.doesNotMatch(without.join('\n'), /Files \(report only/);
  const checked = [];
  assert.equal(await main(['--validate', join(dir, 'runs', runFile), '--sequence', join(dir, 'seq.json')], { log: s => checked.push(s) }), code, checked.join('\n'));
  // A bad files.json is a configuration error: exit 2 before any request or write.
  writeFileSync(join(dir, 'bad-files.json'), JSON.stringify({ roots: [{ alias: 'exports', path: 'relative' }] }));
  const bad = [];
  assert.equal(await main(args(join(dir, 'bad-files.json')), { env, log: s => bad.push(s) }), 2);
  assert.match(bad.join('\n'), /Configuration error: files\.json: root "exports" needs an absolute path/);
});
