// Regression tests from a second adversarial review. The enforcement-locus findings are pinned in locus.test.mjs;
// these cover the tap and identity.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createModelTap, TapLog, chainHash, CHAIN_START } from './tap.mjs';
import { readTapLog, modelIdentity } from './identity.mjs';

const tagsBody = list => JSON.stringify({ models: list.map(([name, digest]) => ({ name, model: name, digest })) });
async function upstream(t, handler) {
  const server = createServer((req, res) => { const chunks = []; req.on('data', c => chunks.push(c)); req.on('end', () => handler(req, res, Buffer.concat(chunks))); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections?.(); server.close(resolve); }));
  return `http://127.0.0.1:${server.address().port}`;
}
async function startTap(t, origin, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'w6 review r2 ')); t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, 'tap.jsonl');
  const tap = createModelTap({ upstream: origin, log: new TapLog({ path }), ...options });
  await tap.start(); t.after(() => tap.stop());
  return { tap, path, dir };
}
function raw(base, path, headerPairs, body) {
  const url = new URL(path, base);
  return new Promise(resolve => {
    const req = request(url, { method: 'POST', agent: false, headers: [['Host', url.host], ['Content-Type', 'application/json'], ['Content-Length', String(Buffer.byteLength(body))], ...headerPairs].flat() }, res => {
      const chunks = []; res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, rawHeaders: res.rawHeaders, body: Buffer.concat(chunks), aborted: false }));
      res.on('error', () => resolve({ status: res.statusCode, aborted: true }));
      res.on('aborted', () => resolve({ status: res.statusCode, aborted: true }));
    });
    req.on('error', error => resolve({ status: 0, aborted: true, error: error.code }));
    req.end(body);
  });
}
const A = 'a'.repeat(64), B = 'b'.repeat(64);

test('a model list taken inside the window that disagrees makes the window partial', async t => {
  let list = [['q:latest', A]];
  const origin = await upstream(t, (req, res) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tagsBody(list)); }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ model: 'q', done: true }));
  });
  const { tap, path } = await startTap(t, origin);
  await raw(tap.url, '/api/chat', [], JSON.stringify({ model: 'q', stream: false }));
  list = [['q:latest', B]]; await tap.mark();
  list = [['q:latest', A]];
  await raw(tap.url, '/api/chat', [], JSON.stringify({ model: 'q', stream: false }));
  await tap.stop();
  const id = modelIdentity(readTapLog(path));
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('model-replaced-in-window'), String(id.reasons));
});

test('hop-by-hop and Connection-named headers stop at the tap; duplicate request headers pass', async t => {
  let seen = null;
  const origin = await upstream(t, (req, res) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tagsBody([])); }
    seen = req.rawHeaders;
    res.writeHead(200, [['Content-Type', 'application/json'], ['Connection', 'close, x-hop-down'], ['X-Hop-Down', 'secret'], ['X-Keep', 'yes']].flat());
    res.end(JSON.stringify({ model: 'x' }));
  });
  const { tap } = await startTap(t, origin, { ollamaTags: false });
  const r = await raw(tap.url, '/v1/chat/completions', [['Connection', 'x-hop-up'], ['X-Hop-Up', 'secret'], ['X-Dup', 'one'], ['X-Dup', 'two']], JSON.stringify({ model: 'x' }));
  const names = list => { const out = []; for (let i = 0; i < list.length; i += 2) out.push(list[i].toLowerCase()); return out; };
  const values = (list, name) => { const out = []; for (let i = 0; i < list.length; i += 2) if (list[i].toLowerCase() === name) out.push(list[i + 1]); return out; };
  assert.ok(!names(seen).includes('x-hop-up')); assert.deepEqual(values(seen, 'x-dup'), ['one', 'two']);
  assert.ok(!names(r.rawHeaders).includes('x-hop-down')); assert.deepEqual(values(r.rawHeaders, 'x-keep'), ['yes']);
  assert.deepEqual(values(seen, 'accept-encoding'), ['identity']); assert.equal(values(seen, 'host').length, 1);
});

test('a window whose lines were re-chained up to its end is still partial', async t => {
  const origin = await upstream(t, (req, res) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tagsBody([['q:latest', A], ['g:latest', B]])); }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ model: JSON.parse(req.headers['x-m'] ?? '"q"'), done: true }));
  });
  const { tap, path, dir } = await startTap(t, origin);
  const m0 = await tap.mark(); await raw(tap.url, '/api/chat', [], JSON.stringify({ model: 'q', stream: false })); const m1 = await tap.mark();
  await raw(tap.url, '/api/chat', [], JSON.stringify({ model: 'q', stream: false }));
  await tap.stop();
  // Change the served model inside window 1 and re-chain every line up to the window's end.
  const frames = (await readFile(path, 'utf8')).trim().split('\n').map(l => JSON.parse(l));
  let head = CHAIN_START;
  const edited = frames.map(f => {
    const { h, ...body } = f;
    if (body.seq > m1.seq) return f;
    if (body.kind === 'result' && body.seq > m0.seq) body.served = ['g'];
    head = chainHash(head, body); return { ...body, h: head };
  });
  const forged = join(dir, 'forged.jsonl'); await writeFile(forged, `${edited.map(f => JSON.stringify(f)).join('\n')}\n`);
  const id = modelIdentity(readTapLog(forged), { from: m0.seq, to: m1.seq });
  assert.equal(id.state, 'partial'); assert.ok(id.reasons.includes('log-chain-break'), String(id.reasons));
});

test('a model is graded by fingerprint only when every call carried one', async t => {
  let n = 0;
  const origin = await upstream(t, (req, res) => {
    if (req.url === '/api/tags') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(tagsBody([])); }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ model: 'v', ...(n++ === 0 ? { system_fingerprint: 'fp_1' } : {}) }));
  });
  const { tap, path } = await startTap(t, origin, { ollamaTags: false });
  await raw(tap.url, '/v1/chat/completions', [], JSON.stringify({ model: 'v' })); await raw(tap.url, '/v1/chat/completions', [], JSON.stringify({ model: 'v' }));
  await tap.stop();
  assert.equal(modelIdentity(readTapLog(path)).strength, 'vendor-model-string');
});

test('an upstream failure after the headers reaches the application as an abort', async t => {
  // A chunked reply whose trailer holds a byte the HTTP parser rejects: the error comes after the headers went out.
  const server = createNetServer(sock => { let buf = ''; sock.on('data', d => { buf += d; if (!buf.includes('\r\n\r\n')) return;
    const json = JSON.stringify({ model: 'm' });
    sock.end(Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n${json.length.toString(16)}\r\n${json}\r\n0\r\nX-T: a\x0bb\r\n\r\n`, 'latin1')); }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => server.close(resolve)));
  const { tap, path } = await startTap(t, `http://127.0.0.1:${server.address().port}`, { ollamaTags: false });
  const r = await raw(tap.url, '/v1/chat/completions', [], JSON.stringify({ model: 'm', stream: false }));
  assert.equal(r.aborted, true, 'the application must not receive a clean, complete reply');
  await new Promise(resolve => setTimeout(resolve, 50)); await tap.stop();
  assert.equal(modelIdentity(readTapLog(path)).state, 'partial');
});
