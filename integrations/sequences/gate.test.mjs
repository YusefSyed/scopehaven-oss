import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { gzipSync, deflateSync } from 'node:zlib';
import { createHoldGate } from './gate.mjs';
import { collectWindow, evaluateEffectAssertion } from '../observers/events.mjs';

const listen = async handler => { const s = createServer(handler); await new Promise(r => s.listen(0, '127.0.0.1', r)); return { url: `http://127.0.0.1:${s.address().port}`, close: () => new Promise(r => { s.close(r); s.closeAllConnections(); }) }; };
const call = (url, path, headers = {}) => new Promise((resolve, reject) => { const r = request(`${url}${path}`, { method: 'POST', agent: false, headers }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); r.on('error', reject); r.end('{}'); });

test('the gate holds a matching request until release and records it as one committed effect', async () => {
  const up = await listen((req, res) => { req.resume(); req.on('end', () => res.writeHead(200).end('{}')); });
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'model', pathPrefix: '/v1/chat' }] }); await gate.start();
  const o = gate.observer();
  try {
    const from = await o.mark();
    const pending = call(gate.url, '/v1/chat');
    const hold = await gate.awaitHold('model', 5000);
    // Still held at this mark: in flight, so the window is partial.
    const mid = await o.mark();
    const w1 = await collectWindow(o, from, mid);
    assert.equal(w1.coverage, 'partial'); assert.equal(w1.events[0].outcome, 'started');
    gate.release(hold);
    assert.equal(await pending, 200);
    const w2 = await collectWindow(o, from, await o.mark());
    assert.equal(w2.coverage, 'complete');
    assert.deepEqual(w2.events.map(e => [e.name, e.outcome]), [['model', 'committed']]);
  } finally { await gate.stop(); await up.close(); }
});

test('a full gate timeline makes later windows partial, never a silent pass', async () => {
  const up = await listen((req, res) => { req.resume(); req.on('end', () => res.writeHead(200).end('{}')); });
  const gate = createHoldGate({ upstream: up.url, rules: [], timelineLimit: 6 }); await gate.start();
  const o = gate.observer();
  try {
    for (let i = 0; i < 3; i++) await call(gate.url, '/noise');
    const from = await o.mark();
    assert.equal(await call(gate.url, '/tools/refund'), 200);
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(w.coverage, 'partial'); assert.equal(w.reason, 'gate-timeline-full');
    assert.notEqual(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'hold-proxy', name: 'ungated' } }, [w]).verdict, 'pass');
  } finally { await gate.stop(); await up.close(); }
});

test('the gate refuses foreign Host and cross-origin requests and never forwards them', async () => {
  let reached = 0;
  const up = await listen((req, res) => { reached++; req.resume(); req.on('end', () => res.writeHead(200).end('{}')); });
  const gate = createHoldGate({ upstream: up.url, rules: [] }); await gate.start();
  try {
    const port = new URL(gate.url).port;
    assert.equal(await call(gate.url, '/x', { Host: `attacker.example:${port}` }), 403);
    assert.equal(await call(gate.url, '/x', { Origin: `http://attacker.example:${port}` }), 403);
    assert.equal(reached, 0);
    assert.equal(await call(gate.url, '/x'), 200);
    assert.equal(reached, 1);
  } finally { await gate.stop(); await up.close(); }
  assert.throws(() => createHoldGate({ upstream: 'http://example.com:80' }), /loopback/);
});

test('a container reaches the gate as host.docker.internal; only the Host is widened', async () => {
  const hosts = [];
  const up = await listen((req, res) => { hosts.push(req.headers.host); req.resume(); req.on('end', () => res.writeHead(200).end('{}')); });
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'model', pathPrefix: '/v1/chat' }] }); await gate.start();
  const o = gate.observer();
  try {
    const port = new URL(gate.url).port, docker = `host.docker.internal:${port}`;
    assert.equal(gate.containerUrl, `http://host.docker.internal:${port}`);
    const from = await o.mark();
    // Held and released like any loopback call; the upstream sees its own Host, never the container's name.
    const pending = call(gate.url, '/v1/chat', { Host: docker });
    gate.release(await gate.awaitHold('model', 5000));
    assert.equal(await pending, 200);
    assert.equal(await call(gate.url, '/x', { Host: `HOST.Docker.Internal:${port}` }), 200);
    assert.equal(await call(gate.url, '/x', { Host: docker, Origin: `http://127.0.0.1:${port}`, 'Sec-Fetch-Site': 'same-origin' }), 200);
    assert.deepEqual(hosts, [new URL(up.url).host, new URL(up.url).host, new URL(up.url).host]);
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(w.coverage, 'complete');
    assert.deepEqual(w.events.map(e => [e.name, e.outcome]), [['model', 'committed'], ['ungated', 'committed'], ['ungated', 'committed']]);
    // Refused and never forwarded: another port, a longer name, a name the gate does not admit, a foreign Origin, a cross-site fetch, a repeated Host.
    for (const headers of [{ Host: `host.docker.internal:${Number(port) + 1}` }, { Host: `host.docker.internal.attacker.example:${port}` }, { Host: 'host.docker.internal' },
      { Host: `localhost:${port}` }, { Host: `gateway.docker.internal:${port}` }, { Host: docker, Origin: `http://host.docker.internal:${port}` },
      { Host: docker, Origin: 'http://attacker.example' }, { Host: docker, 'Sec-Fetch-Site': 'cross-site' }]) {
      assert.equal(await call(gate.url, '/x', headers), 403, JSON.stringify(headers));
    }
    const twice = await new Promise((resolve, reject) => { const r = request({ host: '127.0.0.1', port, method: 'POST', path: '/x', agent: false, headers: [['Host', docker], ['Host', docker]].flat() }, res => { res.resume(); resolve(res.statusCode); }); r.on('error', reject); r.end('{}'); });
    assert.equal(twice, 403);
    assert.equal(hosts.length, 3);
  } finally { await gate.stop(); await up.close(); }
});

test('a request matching a rule after its hold budget keeps the rule id and counts as an effect', async () => {
  const up = await listen((req, res) => { req.resume(); req.on('end', () => res.writeHead(200).end('{}')); });
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'refund', pathPrefix: '/tools/refund', holds: 1 }] }); await gate.start();
  const o = gate.observer();
  try {
    const first = call(gate.url, '/tools/refund');
    gate.release(await gate.awaitHold('refund', 5000));
    assert.equal(await first, 200);
    const from = await o.mark();
    assert.equal(await call(gate.url, '/tools/refund'), 200); // budget used: forwarded, not held
    const w = await collectWindow(o, from, await o.mark());
    assert.deepEqual(w.events.map(e => [e.name, e.outcome]), [['refund', 'committed']]);
    assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: { source: 'hold-proxy', name: 'refund' } }, [w]).verdict, 'fail');
  } finally { await gate.stop(); await up.close(); }
});

test('gate rules match the decoded, case-folded path, keep the rule id on another method, and refuse non-path targets', async () => {
  let reached = 0;
  const up = await listen((req, res) => { reached++; req.resume(); req.on('end', () => res.writeHead(200).end('{}')); });
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'refund', method: 'POST', pathPrefix: '/tools/refund', holds: 0 }] }); await gate.start();
  const o = gate.observer();
  try {
    const from = await o.mark();
    assert.equal(await call(gate.url, '/TOOLS/%72efund'), 200);
    const get = await new Promise((resolve, reject) => { const r = request(`${gate.url}/tools/refund`, { method: 'GET', agent: false }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); r.on('error', reject); r.end(); });
    assert.equal(get, 200);
    const w = await collectWindow(o, from, await o.mark());
    assert.deepEqual(w.events.map(e => e.name), ['refund', 'refund']);
    const port = new URL(gate.url).port;
    const raw = target => new Promise((resolve, reject) => { const r = request({ host: '127.0.0.1', port, method: 'POST', path: target, agent: false, headers: { Host: `127.0.0.1:${port}` } }, res => { res.resume(); resolve(res.statusCode); }); r.on('error', reject); r.end('{}'); });
    const before = reached;
    assert.equal(await raw('http://127.0.0.1:9/tools/refund'), 400);
    assert.equal(await raw('//evil.example/tools/refund'), 400);
    assert.equal(await raw(`${up.url}/tools/refund`), 400); // absolute form, even naming the upstream
    assert.equal(reached, before);
  } finally { await gate.stop(); await up.close(); }
});

test('the gate proves only what it never forwarded; a denied, failed or broken forward is unknown', async () => {
  let mode = 403;
  const up = await listen((req, res) => {
    req.resume();
    req.on('end', () => { if (mode === 'reset') { req.socket.destroy(); return; } res.writeHead(mode).end('{}'); });
  });
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'refund', pathPrefix: '/tools/refund', holds: 0 }] }); await gate.start();
  const o = gate.observer();
  const none = { kind: 'effect.none', select: { source: 'hold-proxy', name: 'refund' } };
  try {
    for (const m of [403, 500, 'reset']) {
      mode = m;
      const from = await o.mark();
      await call(gate.url, '/tools/refund').catch(() => {});
      const w = await collectWindow(o, from, await o.mark());
      assert.equal(w.events.length, 1, `mode ${m}`);
      assert.equal(w.coverage, 'partial', `mode ${m}`);
      assert.notEqual(evaluateEffectAssertion(none, [w]).verdict, 'pass', `mode ${m}`);
    }
    // Nothing forwarded at all: a complete window proves the refund did not go through the gate.
    const from = await o.mark();
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(evaluateEffectAssertion(none, [w]).verdict, 'pass');
  } finally { await gate.stop(); await up.close(); }
});

test('a held request that was dropped never reached upstream and is not an effect', async () => {
  let reached = 0;
  const up = await listen((req, res) => { reached++; req.resume(); req.on('end', () => res.writeHead(200).end('{}')); });
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'refund', pathPrefix: '/tools/refund' }] }); await gate.start();
  const o = gate.observer();
  try {
    const from = await o.mark();
    const pending = call(gate.url, '/tools/refund');
    gate.drop(await gate.awaitHold('refund', 5000));
    assert.equal(await pending, 503);
    const w = await collectWindow(o, from, await o.mark());
    assert.equal(reached, 0); assert.equal(w.events.length, 0); assert.equal(w.coverage, 'complete');
  } finally { await gate.stop(); await up.close(); }
});

test('the gate records the method overrides each request carries, as sent, and forwards the request unchanged', async () => {
  const received = [];
  const up = await listen((req, res) => { const c = []; req.on('data', x => c.push(x)); req.on('end', () => { received.push([req.method, req.headers['x-http-method-override'] ?? null, Buffer.concat(c).toString()]); res.writeHead(200).end('{}'); }); });
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'b', pathPrefix: '/tool/b' }] }); await gate.start();
  const send = (path, { method = 'POST', headers = {}, body = '' }) => new Promise((resolve, reject) => { const r = request(`${gate.url}${path}`, { method, agent: false, headers: { 'content-length': Buffer.byteLength(body), ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); r.on('error', reject); r.end(body); });
  const json = { 'content-type': 'application/json' }, form = { 'content-type': 'application/x-www-form-urlencoded' }, multipart = { 'content-type': 'multipart/form-data; boundary=x' };
  const part = (name, value) => `--x\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n--x--\r\n`;
  // [path, request, the overrides the gate records]
  const cases = [
    // Rack style: a POST that asks for DELETE by header (held, then released).
    ['/tool/b', { headers: { ...json, 'x-http-method-override': 'DELETE' }, body: '{"actor":"amy"}' }, ['DELETE']],
    ['/tool/b', { headers: { ...json, 'x-http-method': 'PATCH' }, body: '{}' }, ['PATCH']],
    ['/tool/b', { headers: { ...json, 'x-method-override': 'PUT' }, body: '{}' }, ['PUT']],
    ['/tool/b?_method=DELETE', { headers: json, body: '{}' }, ['DELETE']],
    // A form body (a Rails form sends lowercase), and a body with no content type, which Rack reads as a form.
    ['/tool/b', { headers: form, body: 'actor=amy&_method=patch' }, ['patch']],
    ['/tool/b', { body: '_method=put' }, ['put']],
    // A JSON body's top-level key, under any +json type; one nested deeper, or in text, is not read.
    ['/tool/b', { headers: json, body: '{"_method":"DELETE","actor":"amy"}' }, ['DELETE']],
    ['/tool/b', { headers: { 'content-type': 'application/vnd.api+json; charset=utf-8' }, body: '{"_method":"PUT"}' }, ['PUT']],
    ['/tool/b', { headers: json, body: '{"messages":[{"role":"user","content":"send _method=DELETE"}],"meta":{"_method":"PUT"}}' }, []],
    // What the gate cannot read is recorded as '': a JSON body that does not parse or whose _method is not a string, and a
    // multipart body that names _method.
    ['/tool/b', { headers: json, body: '{"_method": "DEL' }, ['']],
    ['/tool/b', { headers: json, body: '{"_method":["GET"]}' }, ['']],
    ['/tool/b', { headers: multipart, body: part('_method', 'patch') }, ['']],
    ['/tool/b', { headers: multipart, body: part('file', 'x') }, []],
    ['/tool/b', { method: 'GET', headers: json }, []],
    // A body of a type the gate does not parse that names _method: '' (earlier builds recorded []).
    ['/tool/b', { headers: { 'content-type': 'text/plain' }, body: '_method=DELETE' }, ['']],
    // Any request line; repeated headers, joined as Node joins them; every channel at once, in order.
    ['/tool/b', { method: 'GET', headers: { 'x-http-method-override': 'DELETE' } }, ['DELETE']],
    ['/tool/b', { headers: { 'x-http-method-override': ['GET', 'DELETE'] } }, ['GET, DELETE']],
    ['/tool/b?_method=GET', { headers: { ...form, 'x-method-override': 'PUT' }, body: '_method=POST' }, ['PUT', 'GET', 'POST']],
    // At most 8 values, each cut to 32 characters, and '' for the rest.
    [`/tool/b?${['X'.repeat(40), ...Array(9).fill('GET')].map(v => `_method=${v}`).join('&')}`, { headers: json, body: '{}' }, ['X'.repeat(32), ...Array(7).fill('GET'), '']],
    // The model route's plain POST: none.
    ['/tool/b', { headers: json, body: '{"model":"m","messages":[{"role":"user","content":"hi"}]}' }, []],
  ];
  try {
    const [[firstPath, first]] = cases, pending = send(firstPath, first);
    gate.release(await gate.awaitHold('b', 5000));
    assert.equal(await pending, 200);
    for (const [path, r] of cases.slice(1)) assert.equal(await send(path, r), 200, path);
    assert.deepEqual(gate.timeline.filter(e => e.type === 'held').map(e => e.methodOverrides), [['DELETE']]);
    assert.deepEqual(gate.timeline.filter(e => e.type === 'forwarded').map(e => e.methodOverrides), cases.map(([, , recorded]) => recorded));
    // The upstream receives each request as sent: its method, its override header and its body.
    assert.deepEqual(received, cases.map(([, { method = 'POST', headers = {}, body = '' }]) => [method, [headers['x-http-method-override']].flat().filter(Boolean).join(', ') || null, body]));
  } finally { await gate.stop(); await up.close(); }
});

test('the gate reads an override in the bodies and spellings the frameworks read, and records what it cannot read as \'\'', { timeout: 60000 }, async () => {
  const received = [];
  const up = await listen((req, res) => { const c = []; req.on('data', x => c.push(x)); req.on('end', () => { received.push(Buffer.concat(c)); res.writeHead(200).end('{}'); }); });
  const gate = createHoldGate({ upstream: up.url, rules: [{ id: 'b', pathPrefix: '/tool/b' }] }); await gate.start();
  const send = (path, { headers = {}, body = '' }) => new Promise((resolve, reject) => { const r = request(`${gate.url}${path}`, { method: 'POST', agent: false, headers: { 'content-length': Buffer.byteLength(body), ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); }); r.on('error', reject); r.end(body); });
  const type = t => ({ 'content-type': t }), form = type('application/x-www-form-urlencoded');
  const part = (name, value) => `--x\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n--x--\r\n`;
  const pair = '_method=DELETE', doc = '{"_method":"DELETE"}';
  // [probe, path, request, the overrides the gate records]
  const cases = [
    // A compressed body, which Express's body-parser inflates before method-override reads it. Identity, and an
    // encoded request with no body, are read as before.
    ['form, gzip', '/tool/b', { headers: { ...form, 'content-encoding': 'gzip' }, body: gzipSync(pair) }, ['']],
    ['form, deflate', '/tool/b', { headers: { ...form, 'content-encoding': 'deflate' }, body: deflateSync(pair) }, ['']],
    ['JSON, gzip', '/tool/b', { headers: { ...type('application/json'), 'content-encoding': 'gzip' }, body: gzipSync(doc) }, ['']],
    ['form, identity', '/tool/b', { headers: { ...form, 'content-encoding': 'Identity' }, body: pair }, ['DELETE']],
    ['gzip, no body', '/tool/b?_method=GET', { headers: { ...form, 'content-encoding': 'gzip' } }, ['GET']],
    // The media type ends at ',' or whitespace too (Rack, PHP).
    ['form, then a comma', '/tool/b', { headers: type('application/x-www-form-urlencoded, text/plain'), body: pair }, ['DELETE']],
    ['form, then a space', '/tool/b', { headers: type('application/x-www-form-urlencoded x'), body: pair }, ['DELETE']],
    // Any multipart type (Rack parses multipart/mixed and multipart/related too), and any type with /json or +json
    // in it, as Laravel reads it.
    ['multipart/mixed', '/tool/b', { headers: type('multipart/mixed; boundary=x'), body: part('_method', 'DELETE') }, ['']],
    ['multipart/related', '/tool/b', { headers: type('multipart/related; boundary=x'), body: part('_method', 'DELETE') }, ['']],
    ['multipart/form-data, then a comma', '/tool/b', { headers: type('multipart/form-data, x; boundary=x'), body: part('_method', 'DELETE') }, ['']],
    ['text/json', '/tool/b', { headers: type('text/json'), body: doc }, ['DELETE']],
    ['JSON, then a comma', '/tool/b', { headers: type('application/json, text/plain'), body: doc }, ['DELETE']],
    // Any body the gate does not parse that names _method or .method; one that names neither is not read.
    ['text/plain, .method', '/tool/b', { headers: type('text/plain'), body: '.method=DELETE' }, ['']],
    ['multipart, .method', '/tool/b', { headers: type('multipart/form-data; boundary=x'), body: part('.method', 'DELETE') }, ['']],
    ['text/plain, method', '/tool/b', { headers: type('text/plain'), body: 'method=DELETE' }, []],
    // Controls on the same gate: each read as before.
    ['form', '/tool/b', { headers: form, body: pair }, ['DELETE']],
    ['form, charset', '/tool/b', { headers: type('application/x-www-form-urlencoded; charset=UTF-8'), body: pair }, ['DELETE']],
    ['mixed case', '/tool/b', { headers: type('Application/X-WWW-Form-URLEncoded'), body: pair }, ['DELETE']],
    ['percent-encoded key', '/tool/b', { headers: form, body: '%5Fmethod=DELETE' }, ['DELETE']],
    ['invalid UTF-8 around the pair', '/tool/b', { headers: form, body: Buffer.concat([Buffer.from([0xff]), Buffer.from(`&${pair}&`), Buffer.from([0xfe])]) }, ['DELETE']],
    ['JSON, charset', '/tool/b', { headers: type('application/json; charset=utf-8'), body: doc }, ['DELETE']],
    // A header spelled with '_', which a CGI server gives the same name.
    ['X_HTTP_METHOD_OVERRIDE', '/tool/b', { headers: { ...type('application/json'), X_HTTP_METHOD_OVERRIDE: 'DELETE' }, body: '{}' }, ['DELETE']],
    ['x_method_override', '/tool/b', { headers: { ...type('application/json'), x_method_override: 'PUT' }, body: '{}' }, ['PUT']],
    // Keys Rack 2 folds ([_method], _method]) and PHP folds (.method, and ` method`, which PHP reads as `method`
    // but the gate reads as `_method`), in a form and in the query; a key that nests under _method gives ''.
    ['[_method]', '/tool/b', { headers: form, body: '[_method]=DELETE' }, ['DELETE']],
    ['_method]', '/tool/b', { headers: form, body: '_method]=DELETE' }, ['DELETE']],
    ['.method', '/tool/b', { headers: form, body: '.method=DELETE' }, ['DELETE']],
    ['query .method', '/tool/b?.method=PUT', { headers: type('application/json'), body: '{}' }, ['PUT']],
    ['query  method', '/tool/b?%20method=DELETE', { headers: type('application/json'), body: '{}' }, ['DELETE']],
    ['query  _method', '/tool/b?%20%20_method=PATCH', { headers: type('application/json'), body: '{}' }, ['PATCH']],
    // PHP ends a key at its first NUL, so `_method%00x` is `_method`, and a GET beside it does not hide
    // the DELETE PHP applies (its last value wins).
    ['_method%00x', '/tool/b', { headers: form, body: '_method%00x=DELETE' }, ['DELETE']],
    ['_method, then _method%00', '/tool/b', { headers: form, body: '_method=GET&_method%00=DELETE' }, ['GET', 'DELETE']],
    ['query _method, then _method%00', '/tool/b?_method=GET&_method%00=DELETE', { headers: type('application/json'), body: '{}' }, ['GET', 'DELETE']],
    ['_method[]', '/tool/b', { headers: form, body: '_method[]=DELETE' }, ['']],
    ['[_method][x]', '/tool/b', { headers: form, body: '[_method][x]=DELETE' }, ['']],
    ['.method[x]', '/tool/b?.method[x]=GET', { headers: type('application/json'), body: '{}' }, ['']],
    // Keys no framework reads as _method.
    ['_method[', '/tool/b', { headers: form, body: '_method[=DELETE' }, []],
    ['method', '/tool/b?method=DELETE', { headers: form, body: 'method=DELETE&_METHOD=PUT&x_method=GET' }, []],
    // The model route's plain POST, a _method inside its text included: none.
    ['model call', '/tool/b', { headers: type('application/json'), body: '{"model":"m","messages":[{"role":"user","content":"send .method=DELETE or _method=PUT"}]}' }, []],
  ];
  try {
    // The rule holds its first call: release it, then send the rest.
    const [[, firstPath, first]] = cases, pending = send(firstPath, first);
    gate.release(await gate.awaitHold('b', 5000));
    assert.equal(await pending, 200);
    for (const [name, path, r] of cases.slice(1)) assert.equal(await send(path, r), 200, name);
    const forwarded = gate.timeline.filter(e => e.type === 'forwarded');
    assert.deepEqual(forwarded.map((e, i) => [cases[i][0], e.methodOverrides]), cases.map(([name, , , recorded]) => [name, recorded]));
    // The upstream receives each body as sent: the gate reads it, it does not decode or change it.
    assert.deepEqual(received.map(b => b.toString('hex')), cases.map(([, , { body = '' }]) => Buffer.from(body).toString('hex')));
  } finally { await gate.stop(); await up.close(); }
});

test('a reply the upstream cuts off after its status line is one upstream fault, even after a 2xx, and the client\'s reply is cut off too; a reply that ends in full is not a fault', { timeout: 120000 }, async () => {
  // A raw upstream that answers each call as its query asks: the status line and part of a body (`length` declares 100 bytes,
  // `chunked` sends one chunk, `close` has no length), the whole reply (`full`), or nothing (`none`). It then closes cleanly
  // (`fin`) or resets (`rst`): before any answer for `none`, once the client has the partial body, or once the full reply is over.
  const heads = {
    length: 'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial-',
    chunked: 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\npartial-\r\n',
    close: 'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\npartial-',
    full: 'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\npartial-',
  };
  const cuts = new Map(), sockets = new Set();
  const up = createTcpServer(sock => {
    let head = '';
    sockets.add(sock);
    sock.on('error', () => {});
    sock.on('data', d => {
      head += d;
      if (sock.answered || !head.includes('\r\n\r\n')) return;
      sock.answered = true;
      const q = new URL(head.split(' ')[1], 'http://127.0.0.1').searchParams;
      const cut = () => q.get('cut') === 'rst' ? sock.resetAndDestroy() : sock.destroy();
      if (q.get('shape') === 'none') { cut(); return; }
      cuts.set(q.get('id'), cut);
      sock.write(heads[q.get('shape')]);
    });
  });
  await new Promise(r => up.listen(0, '127.0.0.1', r));
  const gate = createHoldGate({ upstream: `http://127.0.0.1:${up.address().port}`, rules: [{ id: 'tool', pathPrefix: '/tool', holds: 0 }] }); await gate.start();
  const o = gate.observer();
  // What the gate's client gets: [status, whether its reply arrived in full, its body], or 'hung' if it never settles.
  const exchange = (id, shape, cut) => new Promise(resolve => {
    let got = false;
    const timer = setTimeout(() => { r.destroy(); resolve('hung'); }, 10000);
    const r = request(`${gate.url}/tool/x?id=${id}&shape=${shape}&cut=${cut}`, { method: 'POST', agent: false }, res => {
      got = true; let body = '';
      res.on('error', () => {});
      res.on('data', d => { body += d; if (shape !== 'full' && body === 'partial-') cuts.get(`${id}`)(); });
      res.on('close', () => { clearTimeout(timer); resolve([res.statusCode, res.complete, body]); if (shape === 'full') cuts.get(`${id}`)(); });
    });
    r.on('error', () => { if (!got) { clearTimeout(timer); resolve('error'); } });
    r.end('{}');
  });
  const none = { kind: 'effect.none', select: { source: 'hold-proxy', name: 'tool' } }, exists = { kind: 'effect.exists', select: { source: 'hold-proxy', name: 'tool' } };
  try {
    const cases = [
      // Cut off after the status line, with a length, chunked, or (by a reset) with no length: the gate notes one upstream error after
      // the 200 response, so the call is unknown and neither a prohibition nor a control can pass on it; the client's reply is cut off
      // too, never ended (no clean last chunk) and never left hanging.
      ...[['length', 'fin'], ['length', 'rst'], ['chunked', 'fin'], ['chunked', 'rst'], ['close', 'rst']].map(([shape, cut]) => [shape, cut, [200, false, 'partial-'], ['forwarded', 'response', 'upstream-error'], 'unknown']),
      // A reply that ended in full, a reset after it, and a reply with no length ended by a clean close (its end in HTTP): committed.
      ...[['full', 'fin'], ['full', 'rst'], ['close', 'fin']].map(([shape, cut]) => [shape, cut, [200, true, 'partial-'], ['forwarded', 'response'], 'committed']),
      // No answer at all: one upstream error, and the client gets 502.
      ...[['none', 'fin'], ['none', 'rst']].map(([shape, cut]) => [shape, cut, [502, true, ''], ['forwarded', 'upstream-error'], 'unknown']),
    ];
    for (const [i, [shape, cut, client, types, outcome]] of cases.entries()) {
      const label = `${shape} ${cut}`, from = await o.mark();
      assert.deepEqual(await exchange(i, shape, cut), client, label);
      await new Promise(r => setTimeout(r, 200));
      const to = await o.mark(), w = await collectWindow(o, from, to);
      assert.deepEqual(gate.timeline.filter(e => e.seq > from.seq && e.seq <= to.seq).map(e => e.type), types, label);
      assert.deepEqual(w.events.map(e => e.outcome), [outcome], label);
      if (outcome === 'committed') assert.deepEqual([evaluateEffectAssertion(none, [w]).verdict, evaluateEffectAssertion(exists, [w]).verdict], ['fail', 'pass'], label);
      else { assert.equal(w.coverage, 'partial', label); for (const a of [none, exists]) assert.notEqual(evaluateEffectAssertion(a, [w]).verdict, 'pass', label); }
    }
  } finally { for (const sock of sockets) sock.destroy(); await gate.stop(); await new Promise(r => up.close(r)); }
});
