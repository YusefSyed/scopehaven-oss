// Regression tests from an earlier adversarial review. Each test pins one finding, and each was written to fail on
// the reviewed code first.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { mkdtemp, readFile, writeFile, rm, chmod } from 'node:fs/promises';
import { closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createModelTap, TapLog, createResponseReader } from './tap.mjs';
import { readTapLog, modelIdentity } from './identity.mjs';
import { compareModelIdentities, attributeComparison, appChangedBetween } from './attribute.mjs';
import { main } from './cli.mjs';
import { runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';

const DIGEST = { q: 'a'.repeat(64), g: 'b'.repeat(64), r: 'c'.repeat(64) };
const tags = list => JSON.stringify({ models: list.map(([name, digest]) => ({ name, model: name, digest })) });

// A loopback upstream whose behaviour each test supplies.
async function upstream(t, handler) {
  const server = createServer((req, res) => { const chunks = []; req.on('data', c => chunks.push(c)); req.on('end', () => handler(req, res, Buffer.concat(chunks))); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections?.(); server.close(resolve); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const json = (res, status, obj, headers = {}) => { const text = JSON.stringify(obj); res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text), ...headers }); res.end(text); };
const ollama = (served = 'q:latest', list = [['q:latest', DIGEST.q]]) => (req, res, body) => {
  if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tags(list)); }
  let model = served; try { model = JSON.parse(body.toString()).model ?? served; } catch {}
  json(res, 200, { model, message: { content: 'ok' }, done: true });
};
async function startTap(t, origin, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'w6 review r1 ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'tap.jsonl');
  const tap = createModelTap({ upstream: origin, log: new TapLog({ path }), ...options });
  await tap.start(); t.after(() => tap.stop());
  return { tap, path, dir };
}
function send(base, path, body, { method = 'POST', headers = {}, onResponse } = {}) {
  const url = new URL(path, base);
  const data = body === undefined ? null : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  return new Promise(resolve => {
    const started = Date.now();
    const req = request(url, { method, agent: false, headers: { host: url.host, ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}), ...headers } }, res => {
      const firstByte = { at: null }; onResponse?.(res);
      const chunks = []; res.on('data', c => { if (firstByte.at === null) firstByte.at = Date.now() - started; chunks.push(c); });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, rawHeaders: res.rawHeaders, trailers: res.trailers, body: Buffer.concat(chunks), firstByteMs: firstByte.at, totalMs: Date.now() - started }));
    });
    req.on('error', error => resolve({ status: 0, error }));
    if (data) req.write(data); req.end();
  });
}
const chat = model => ({ model, messages: [{ role: 'user', content: 'hi' }], stream: false });
let sessions = 0;
const ident = (served, extra = {}) => ({ state: 'observed', tapSession: extra.tapSession ?? `session-${++sessions}`, upstream: extra.upstream ?? 'http://127.0.0.1:1', window: extra.window ?? { from: 0, to: null },
  models: [{ served, requested: [served], fingerprints: extra.fingerprints ?? [], weightsDigest: extra.weightsDigest ?? null, strength: extra.weightsDigest ? 'weights-digest' : extra.fingerprints?.length ? 'vendor-fingerprint' : 'vendor-model-string' }] });
const cmp = rows => ({ compatible: true, controlsPass: true, reasons: [], baselineId: 'b', candidateId: 'c', restorationLabel: 'Core label', rows: rows.map(([id, before, after, transition]) => ({ id, title: id, before, after, transition })) });

test('two windows of one tap session are never compared as two runs', async t => {
  const origin = await upstream(t, ollama());
  const { tap, path } = await startTap(t, origin);
  const m0 = await tap.mark(); await send(tap.url, '/api/chat', chat('q')); const m1 = await tap.mark(); await send(tap.url, '/api/chat', chat('q')); const m2 = await tap.mark();
  await tap.stop();
  const frames = readTapLog(path);
  const whole = modelIdentity(frames);
  assert.equal(typeof whole.tapSession, 'string'); assert.ok(whole.tapSession.length >= 16);
  assert.deepEqual(compareModelIdentities(whole, whole).reasons, ['same-tap-window']);
  assert.equal(compareModelIdentities(whole, whole).relation, 'unverifiable');
  // Non-overlapping windows of one session are fine.
  const w1 = modelIdentity(frames, { from: m0.seq, to: m1.seq }), w2 = modelIdentity(frames, { from: m1.seq, to: m2.seq });
  assert.equal(compareModelIdentities(w1, w2).relation, 'same');
  assert.equal(compareModelIdentities(w1, modelIdentity(frames, { from: m0.seq, to: m2.seq })).relation, 'unverifiable');
  // The CLI refuses one log for both runs unless separate windows are given.
  const storeDir = await mkdtemp(join(tmpdir(), 'w6 r1 store ')); t.after(() => rm(storeDir, { recursive: true, force: true })); await chmod(storeDir, 0o700);
  const store = createStore(storeDir);
  const base = await store.save(await runAssessment('demo-vulnerable')), cand = await store.save(await runAssessment('demo-repaired'));
  const sink = () => { const s = { text: '', write(x) { s.text += x; } }; return s; };
  const err = sink();
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', cand.id, '--baseline-log', path, '--candidate-log', path], { stdout: sink(), stderr: err }), 2);
  assert.match(err.text, /same tap log/);
  const ok = sink();
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', cand.id, '--baseline-log', path, '--candidate-log', path, '--baseline-window', `${m0.seq}:${m1.seq}`, '--candidate-window', `${m1.seq}:${m2.seq}`], { stdout: ok, stderr: sink() }), 0);
  assert.equal(JSON.parse(ok.text).model.relation, 'same');
  // Failing controls: exit 1 even with every flip credited to the application.
  const broken = await runAssessment('demo-repaired');
  const control = broken.results.find(r => r.severity === 'control'); control.status = 'fail';
  broken.id = (await import('node:crypto')).randomUUID();
  const brokenSaved = await store.save(broken);
  const out = sink();
  assert.equal(await main(['attribute', '--store', storeDir, '--baseline', base.id, '--candidate', brokenSaved.id, '--baseline-log', path, '--candidate-log', path, '--baseline-window', `${m0.seq}:${m1.seq}`, '--candidate-window', `${m1.seq}:${m2.seq}`], { stdout: out, stderr: sink() }), 1);
  assert.equal(JSON.parse(out.text).controlsPass, false);
});

test('a different upstream is a model change unless the weights match', () => {
  const a = ident('q', { upstream: 'http://127.0.0.1:1' }), b = ident('q', { upstream: 'http://127.0.0.1:2' });
  const r = compareModelIdentities(a, b);
  assert.equal(r.relation, 'different'); assert.deepEqual(r.changes[0], { kind: 'upstream', before: 'http://127.0.0.1:1', after: 'http://127.0.0.1:2' });
  const same = compareModelIdentities(ident('q', { upstream: 'http://127.0.0.1:1', weightsDigest: DIGEST.q }), ident('q', { upstream: 'http://127.0.0.1:2', weightsDigest: DIGEST.q }));
  assert.equal(same.relation, 'same'); assert.equal(same.strength, 'weights-digest');
});

test('a model list that was asked for and failed makes the window partial', async t => {
  const origin = await upstream(t, (req, res, body) => req.url === '/api/tags' ? json(res, 500, { error: 'boom' }) : ollama()(req, res, body));
  const { tap, path } = await startTap(t, origin);
  await send(tap.url, '/api/chat', chat('q')); await tap.stop();
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('model-list-unavailable'), String(id.reasons));
  // Declared not to be an Ollama-style server: no list, no gap, a weaker reading.
  const origin2 = await upstream(t, ollama());
  const off = await startTap(t, origin2, { ollamaTags: false });
  await send(off.tap.url, '/api/chat', chat('q')); await off.tap.stop();
  const declared = modelIdentity(readTapLog(off.path));
  assert.equal(declared.state, 'observed'); assert.equal(declared.strength, 'vendor-model-string');
});

test('same name and vendor reading only: the app is credited, with the weakness stated', () => {
  const r = attributeComparison(cmp([['x', 'fail', 'pass', 'contract-restored']]), { baselineIdentity: ident('q'), candidateIdentity: ident('q'), app: { changed: true, basis: 't', evidence: 'build-hash' } });
  assert.equal(r.flipCause, 'app'); assert.ok(r.caveats.some(c => /weights not verified/.test(c)));
});

test('mixed whole-window identities are never compared as sets', () => {
  const mixed = (a, b) => ({ state: 'mixed', tapSession: `s-${a}${b}`, upstream: 'u', window: { from: 0, to: null }, models: [{ served: 'q', calls: a, requested: ['q'], fingerprints: [], weightsDigest: DIGEST.q, strength: 'weights-digest' }, { served: 'g', calls: b, requested: ['g'], fingerprints: [], weightsDigest: DIGEST.g, strength: 'weights-digest' }] });
  const r = compareModelIdentities(mixed(9, 1), mixed(1, 9));
  assert.equal(r.relation, 'unverifiable'); assert.ok(r.reasons.includes('mixed-models'));
});

test('Ollama aliases with one weights digest are one model', () => {
  const r = compareModelIdentities(ident('x', { weightsDigest: DIGEST.q }), ident('x:latest', { weightsDigest: DIGEST.q }));
  assert.equal(r.relation, 'same'); assert.equal(r.strength, 'weights-digest');
  assert.equal(compareModelIdentities(ident('x', { weightsDigest: DIGEST.q }), ident('x:latest', { weightsDigest: DIGEST.g })).relation, 'silent-change');
});

test('fingerprints are compared as whole sets', () => {
  const r = compareModelIdentities(ident('g', { fingerprints: ['fp1', 'fp2'] }), ident('g', { fingerprints: ['fp1', 'fp3'] }));
  assert.equal(r.relation, 'silent-change');
});

test('an explicit window that runs past the end of the log is partial', async t => {
  const origin = await upstream(t, ollama());
  const { tap, path, dir } = await startTap(t, origin);
  const m0 = await tap.mark(); await send(tap.url, '/api/chat', chat('q')); const m1 = await tap.mark(); await send(tap.url, '/api/chat', chat('g')); const m2 = await tap.mark();
  await tap.stop();
  const lines = (await readFile(path, 'utf8')).trim().split('\n');
  const cut = join(dir, 'cut.jsonl'); await writeFile(cut, `${lines.slice(0, m1.seq + 2).join('\n')}\n`);
  const id = modelIdentity(readTapLog(cut), { from: m0.seq, to: m2.seq });
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('window-end-missing'), String(id.reasons));
  assert.ok(modelIdentity(readTapLog(path), { from: 9999, to: 10000 }).reasons.includes('window-start-missing'));
});

test('a call that started before the window and answered inside it is visible', async t => {
  const origin = await upstream(t, (req, res, body) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tags([['a:latest', DIGEST.q], ['b:latest', DIGEST.g]])); }
    const j = JSON.parse(body.toString());
    if (j.model === 'a') { res.writeHead(200, { 'content-type': 'application/x-ndjson' }); res.write(`${JSON.stringify({ model: 'a', done: false })}\n`); setTimeout(() => res.end(`${JSON.stringify({ model: 'a', done: true })}\n`), 250); return; }
    json(res, 200, { model: j.model, done: true });
  });
  const { tap } = await startTap(t, origin);
  const slow = send(tap.url, '/api/chat', { model: 'a', messages: [] });
  await new Promise(resolve => setTimeout(resolve, 60));
  const m1 = await tap.mark();
  await send(tap.url, '/api/chat', chat('b')); await slow;
  const m2 = await tap.mark();
  const id = modelIdentity(tap.log.frames, { from: m1.seq, to: m2.seq });
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('call-started-before-window'), String(id.reasons));
});

test('a window in which no model was identified is never observed', async t => {
  const origin = await upstream(t, (req, res) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tags([])); }
    if (req.headers['x-case'] === 'sse-typed-json') { res.writeHead(200, { 'content-type': 'text/event-stream' }); return res.end(JSON.stringify({ model: 'real', choices: [] })); }
    if (req.headers['x-case'] === 'long-name') return json(res, 200, { model: 'm'.repeat(201), choices: [] });
    if (req.headers['x-case'] === 'object-name') return json(res, 200, { model: { id: 'm' }, choices: [] });
    json(res, 200, { id: 'x', choices: [] });
  });
  const cases = [
    [url => send(url, '/v1/chat/completions', gzipSync(JSON.stringify(chat('gpt-x'))), { headers: { 'content-encoding': 'gzip' } }), 'model-not-identified'],
    [url => send(url, '/v1/chat/completions', { model: { id: 'gpt-x' }, messages: [] }), 'model-not-identified'],
    [url => send(url, '/v1/chat/completions', chat('gpt-x'), { headers: { 'x-case': 'sse-typed-json' } }), 'no-events-parsed'],
    [url => send(url, '/v1/chat/completions', chat('gpt-x'), { headers: { 'x-case': 'long-name' } }), 'served-model-unreadable'],
    [url => send(url, '/v1/chat/completions', chat('gpt-x'), { headers: { 'x-case': 'object-name' } }), 'served-model-unreadable'],
  ];
  for (const [go, reason] of cases) {
    const { tap, path } = await startTap(t, origin, { ollamaTags: false });
    await go(tap.url); await tap.stop();
    const id = modelIdentity(readTapLog(path));
    assert.equal(id.state, 'partial', reason); assert.ok(id.reasons.includes(reason), `${reason}: ${id.reasons}`);
  }
});

test('blocked-by-controls is a flip, never a repair credited to the app', () => {
  const r = attributeComparison({ ...cmp([['x', 'fail', 'pass', 'blocked-by-controls']]), controlsPass: false }, { baselineIdentity: ident('q', { weightsDigest: DIGEST.q }), candidateIdentity: ident('q', { weightsDigest: DIGEST.q, tapSession: 'other' }), app: { changed: true, basis: 't', evidence: 'build-hash' } });
  assert.equal(r.repairCreditedToApp, false); assert.equal(r.rows[0].attribution, 'app');
  const app = { changed: true, basis: 't', evidence: 'build-hash' };
  // Not a repair even with controls passing, and a real repair is not credited when controls fail.
  assert.equal(attributeComparison(cmp([['x', 'fail', 'pass', 'blocked-by-controls']]), { baselineIdentity: ident('q'), candidateIdentity: ident('q'), app }).repairCreditedToApp, false);
  assert.equal(attributeComparison(cmp([['x', 'fail', 'pass', 'contract-restored']]), { baselineIdentity: ident('q'), candidateIdentity: ident('q'), app }).repairCreditedToApp, true);
  assert.equal(attributeComparison({ ...cmp([['x', 'fail', 'pass', 'contract-restored']]), controlsPass: false }, { baselineIdentity: ident('q'), candidateIdentity: ident('q'), app }).repairCreditedToApp, false);
  const local = attributeComparison(cmp([['x', 'fail', 'pass', 'local-control-restored']]), { baselineIdentity: ident('q'), candidateIdentity: ident('g'), app: { changed: false, basis: 't', evidence: 'build-hash' } });
  assert.equal(local.rows[0].attribution, 'model'); assert.equal(local.repairCreditedToApp, false); assert.match(local.restorationLabel, /^Not attributable/);
});

test('an unverified row that moved is attributed, and any flip not credited to the app replaces the label', () => {
  const r = attributeComparison(cmp([['x', 'pass', 'fail', 'unverified'], ['y', 'pass', 'fail', 'regression']]), { baselineIdentity: ident('q'), candidateIdentity: ident('g'), app: { changed: false, basis: 't', evidence: 'build-hash' } });
  assert.equal(r.rows[0].attribution, 'model'); assert.equal(r.rows[1].attribution, 'model');
  assert.match(r.restorationLabel, /^Not attributable to the application/);
  const still = attributeComparison(cmp([['x', 'pass', 'pass', 'unverified']]), { baselineIdentity: ident('q'), candidateIdentity: ident('g'), app: { changed: false, basis: 't', evidence: 'build-hash' } });
  assert.equal(still.rows[0].attribution, 'no-change'); assert.equal(still.restorationLabel, 'Core label');
});

test('null build fields are unknown, and a label alone never lets the model take the blame', () => {
  assert.equal(appChangedBetween({ targetBuildHash: null }, { targetBuildHash: null }).changed, true);
  assert.equal(appChangedBetween({ targetBuildHash: null, targetConfigHash: null, build: null }, { targetBuildHash: null, targetConfigHash: null, build: null }).evidence, 'unknown');
  const label = appChangedBetween({ targetBuildHash: null, targetConfigHash: 'h', build: 'lab-v1' }, { targetBuildHash: null, targetConfigHash: 'h', build: 'lab-v1' });
  assert.deepEqual([label.changed, label.evidence], [false, 'declared-label']);
  const hash = appChangedBetween({ targetBuildHash: 'x' }, { targetBuildHash: 'x' });
  assert.deepEqual([hash.changed, hash.evidence], [false, 'build-hash']);
  const rows = cmp([['x', 'fail', 'pass', 'contract-restored']]);
  assert.equal(attributeComparison(rows, { baselineIdentity: ident('q'), candidateIdentity: ident('g'), app: label }).flipCause, 'confounded');
  assert.equal(attributeComparison(rows, { baselineIdentity: ident('q'), candidateIdentity: ident('g'), app: hash }).flipCause, 'model');
  assert.equal(attributeComparison(rows, { baselineIdentity: ident('q'), candidateIdentity: ident('g'), app: { changed: false, basis: 'x' } }).flipCause, 'confounded');
});

test('a log that can no longer be written never takes the tap down', async t => {
  const origin = await upstream(t, ollama());
  const { tap, path } = await startTap(t, origin);
  await send(tap.url, '/api/chat', chat('q'));
  // The next write fails with EBADF, as a full disk fails a write: the descriptor number is
  // one no socket can reuse (closing the real one would let a socket take its number).
  const real = tap.log.fd; tap.log.fd = 1_000_000; t.after(() => { try { closeSync(real); } catch {} });
  const res = await send(tap.url, '/api/chat', chat('q'));
  assert.equal(res.status, 200);
  assert.ok(tap.log.writeError);
  await tap.stop();
  assert.equal(modelIdentity(readTapLog(path)).state, 'partial');
  assert.ok(tap.log.frames.some(f => f.reason === 'log-write-failed'));
  assert.ok(modelIdentity(tap.log.frames).reasons.includes('log-write-failed'));
});

test('the CLI tap exits 2 when its log could not be written', async t => {
  const origin = await upstream(t, ollama('gemma4', [['gemma4:latest', DIGEST.g]]));
  const dir = await mkdtemp(join(tmpdir(), 'w6 r1 efbig ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const log = join(dir, 'tap.jsonl'), cli = new URL('./cli.mjs', import.meta.url);
  // A 512-byte file-size limit (SIGXFSZ ignored) makes write(2) fail with EFBIG, standing in for a full disk.
  const child = spawn('/bin/bash', ['-c', `trap '' XFSZ; ulimit -f 1; exec "${process.execPath}" "${fileURLToPath(cli)}" tap --upstream ${origin} --log "${log}"`], { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  let stderr = ''; child.stderr.on('data', d => { stderr += d; });
  const exited = new Promise(resolve => child.on('exit', code => resolve(code)));
  const line = await new Promise(resolve => { let buf = ''; child.stdout.on('data', d => { buf += d; if (buf.includes('\n')) resolve(buf.split('\n')[0]); }); });
  for (let i = 0; i < 3; i++) assert.equal((await send(JSON.parse(line).tap, '/api/chat', chat('gemma4'))).status, 200);
  child.kill('SIGTERM');
  assert.equal(await exited, 2); assert.match(stderr, /could not be written/);
});

test('a stream the request asked for is never held, whatever its content type', async t => {
  const origin = await upstream(t, (req, res) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tags([])); }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{"model":"x",'); setTimeout(() => res.end('"choices":[]}'), 400);
  });
  const { tap } = await startTap(t, origin, { ollamaTags: false });
  const r = await send(tap.url, '/v1/chat/completions', { model: 'x', messages: [], stream: true });
  assert.ok(r.firstByteMs < 300, `first byte after ${r.firstByteMs} ms`);
  const held = await send(tap.url, '/v1/chat/completions', { model: 'x', messages: [], stream: false });
  assert.ok(held.firstByteMs >= 350, `non-stream first byte after ${held.firstByteMs} ms`);
});

test('duplicate headers and trailers pass through', async t => {
  const origin = await upstream(t, (req, res) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tags([])); }
    res.writeHead(200, [['content-type', 'application/json'], ['x-dup', 'one'], ['x-dup', 'two'], ['trailer', 'x-done']].flat());
    res.addTrailers({ 'x-done': 'yes' }); res.end(JSON.stringify({ model: 'x' }));
  });
  const { tap } = await startTap(t, origin, { ollamaTags: false });
  const r = await send(tap.url, '/v1/chat/completions', chat('x'));
  const dups = []; for (let i = 0; i < r.rawHeaders.length; i += 2) if (r.rawHeaders[i].toLowerCase() === 'x-dup') dups.push(r.rawHeaders[i + 1]);
  assert.deepEqual(dups, ['one', 'two']); assert.equal(r.trailers['x-done'], 'yes');
});

test('multibyte names split across chunks and a leading BOM are read correctly', () => {
  const r = createResponseReader('openai-chat', 'text/event-stream');
  const bytes = Buffer.from(`data: ${JSON.stringify({ model: 'modèle-1' })}\n\n`);
  const cut = bytes.indexOf(Buffer.from('è')) + 1;
  r.push(bytes.subarray(0, cut)); r.push(bytes.subarray(cut));
  assert.deepEqual(r.end().served, ['modèle-1']);
  const bom = createResponseReader('openai-chat', 'application/json');
  bom.push(Buffer.from(`﻿${JSON.stringify({ model: 'b' })}`));
  const out = bom.end(); assert.deepEqual(out.served, ['b']); assert.equal(out.unparsable, 0);
});

test('a model list that trickles is cut off at the deadline', async t => {
  const origin = await upstream(t, (req, res) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); const timer = setInterval(() => { if (!res.destroyed) res.write(' '); }, 100); res.on('close', () => clearInterval(timer)); return; }
    json(res, 200, { model: 'x' });
  });
  const dir = await mkdtemp(join(tmpdir(), 'w6 r1 trickle ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const tap = createModelTap({ upstream: origin, log: new TapLog({ path: join(dir, 'tap.jsonl') }), tagsTimeoutMs: 400 });
  const started = Date.now();
  await tap.start(); await tap.stop();
  assert.ok(Date.now() - started < 3000, `took ${Date.now() - started} ms`);
  assert.equal(readTapLog(join(dir, 'tap.jsonl')).find(f => f.kind === 'models').reason, 'tags-timeout');
});

test('a redirect from the model server is a gap', async t => {
  const origin = await upstream(t, (req, res) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tags([])); }
    json(res, 307, { model: 'x' }, { location: 'http://127.0.0.1:9/v1/chat/completions' });
  });
  const { tap, path } = await startTap(t, origin, { ollamaTags: false });
  assert.equal((await send(tap.url, '/v1/chat/completions', chat('x'))).status, 307);
  await tap.stop();
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('redirect'));
});

test('log integrity: duplicate, backward, edited and openless logs are caught', async t => {
  const origin = await upstream(t, ollama());
  const { tap, path, dir } = await startTap(t, origin);
  await send(tap.url, '/api/chat', chat('q')); await send(tap.url, '/api/chat', chat('q'));
  await tap.stop();
  const lines = (await readFile(path, 'utf8')).trim().split('\n');
  assert.equal(modelIdentity(readTapLog(path)).state, 'observed');
  const variant = async (name, list) => { const p = join(dir, `${name}.jsonl`); await writeFile(p, `${list.join('\n')}\n`); return modelIdentity(readTapLog(p)); };
  assert.ok((await variant('dup', [...lines.slice(0, 4), lines[3], ...lines.slice(4)])).reasons.includes('log-seq-break'));
  assert.ok((await variant('back', [...lines.slice(0, 4), lines[1], ...lines.slice(4)])).reasons.includes('log-seq-break'));
  // An edited line that keeps its sequence number breaks the hash chain.
  const edited = lines.map(l => { const f = JSON.parse(l); if (f.kind === 'result') f.served = ['g']; return JSON.stringify(f); });
  assert.ok((await variant('edited', edited)).reasons.includes('log-chain-break'));
  const openless = await variant('openless', lines.slice(1));
  assert.ok(openless.reasons.includes('tap-not-open-before-window'));
  const id = modelIdentity(readTapLog(path));
  assert.match(id.head, /^[0-9a-f]{64}$/);
});

test('the model list: a model joining mid-window, an unlisted served model and bad digests are gaps', async t => {
  let list = [['q:latest', DIGEST.q]];
  const origin = await upstream(t, (req, res, body) => ollama('q', list)(req, res, body));
  const joined = await startTap(t, origin);
  list = [];
  const m0 = await joined.tap.mark(); list = [['q:latest', DIGEST.q]]; await send(joined.tap.url, '/api/chat', chat('q')); const m1 = await joined.tap.mark();
  assert.ok(modelIdentity(joined.tap.log.frames, { from: m0.seq, to: m1.seq }).reasons.includes('model-list-changed-in-window'));
  list = [['other:latest', DIGEST.g]];
  const unlisted = await startTap(t, origin);
  await send(unlisted.tap.url, '/api/chat', chat('q')); await unlisted.tap.stop();
  assert.ok(modelIdentity(readTapLog(unlisted.path)).reasons.includes('served-model-not-listed'));
  list = [['q:latest', `sha256:${DIGEST.q}`]];
  const bad = await startTap(t, origin);
  await send(bad.tap.url, '/api/chat', chat('q')); await bad.tap.stop();
  const badId = modelIdentity(readTapLog(bad.path));
  assert.equal(badId.models[0].weightsDigest, null); assert.equal(badId.state, 'partial');
});

test('a result in the window with no call before it is a gap', () => {
  const frames = [{ kind: 'open', schema: 'scopehaven-model-tap/2', ollamaTags: false }, { kind: 'models', phase: 'start', available: false, reason: 'not-requested' },
    { kind: 'result', conn: 'ghost', status: 200, served: ['q'], fingerprints: [] }, { kind: 'models', phase: 'mark', available: false, reason: 'not-requested' }].map((f, i) => ({ v: 1, seq: i + 1, ...f }));
  assert.ok(modelIdentity(frames, { from: 2, to: 4 }).reasons.includes('result-without-call'));
});

// Seen in the live pilot (openai-cs-agents, 2026-10-06): the Agents SDK runs two guardrail calls
// beside the agent call and cancels the second when the first answers. The cancelled call's
// held JSON never reached the application, so it carried no model output into the run.
test('a call abandoned before any answer arrived is counted, not a gap; one abandoned mid-answer is a gap', async t => {
  const origin = await upstream(t, (req, res, body) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tags([['q:latest', DIGEST.q]])); }
    const j = JSON.parse(body.toString());
    if (j.model === 'slow') { const timer = setTimeout(() => json(res, 200, { model: 'q', done: true }), 400); res.on('close', () => clearTimeout(timer)); return; }
    json(res, 200, { model: j.model, done: true });
  });
  const { tap } = await startTap(t, origin);
  const m0 = await tap.mark();
  await new Promise(resolve => {
    const data = Buffer.from(JSON.stringify({ model: 'slow', messages: [], stream: false })), url = new URL('/api/chat', tap.url);
    const req = request(url, { method: 'POST', agent: false, headers: { host: url.host, 'content-type': 'application/json', 'content-length': data.length } });
    req.on('error', () => {}); req.end(data); setTimeout(() => { req.destroy(); setTimeout(resolve, 50); }, 100);
  });
  await send(tap.url, '/api/chat', chat('q'));
  const m1 = await tap.mark();
  const id = modelIdentity(tap.log.frames, { from: m0.seq, to: m1.seq });
  assert.equal(id.state, 'observed', String(id.reasons)); assert.equal(id.strength, 'weights-digest');
  assert.deepEqual(id.calls, { total: 2, succeeded: 1, failed: 0, abandoned: 1 });
  assert.equal(tap.log.frames.find(f => f.reason === 'client-closed').delivered, 0);
});

test('every /api/blobs route is a model-admin call', async t => {
  const origin = await upstream(t, (req, res) => json(res, 200, {}));
  const { tap, path } = await startTap(t, origin, { ollamaTags: false });
  await send(tap.url, `/api/blobs/sha256:${DIGEST.q}`, 'x'); await tap.stop();
  assert.ok(modelIdentity(readTapLog(path)).reasons.includes('model-admin-call'));
});
