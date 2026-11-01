// DNS stub (integrations/observers/dns-stub.mjs, dns-wire.mjs): a loopback DNS server that records every name the app looks up
// and never recurses or forwards. Every query here goes to 127.0.0.1 or [::1], from Node's own resolver (c-ares, pointed at the
// stub with setServers) or from raw UDP and TCP clients; the names are synthetic and never resolved anywhere else.
//
// Load (2026-10-23). These tests run on loaded machines and on hosted CI, so no assertion depends on how fast the machine runs
// or on how many datagrams the kernel hands the stub in time. Every wait for the stub ends on the event itself (a reply, the
// count of a burst's queries the stub has read, a socket closing, a query seen in flight) and is capped far above an idle run
// (LOAD_CAP_MS), so a slow machine waits longer instead of failing. The safety properties stay hard on any machine: a window
// over a burst that lost or may have lost a query never reads complete (it reads partial, or it recorded every query sent),
// and a lost name is never scanned. Lower bounds on time (a wait lasted at least quietMs) hold on any machine and are always
// checked. Upper bounds (a wait ended within so many ms) are checked only with SCOPEHAVEN_PERF=1, on an idle machine; without
// it each such test checks the same guard by its structure (it returned before its own cap, or while the sender still sent).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createSocket } from 'node:dgram';
import { connect } from 'node:net';
import { Resolver } from 'node:dns/promises';
import { createDnsStub, validateDnsStubConfig, DNS_STUB_COLLECTOR, DNS_STUB_FILES, DNS_STUB_LIMITS } from './dns-stub.mjs';
import { parseQuery, encodeQuery, encodeResponse, parseResponse, presentLabel } from './dns-wire.mjs';
import { collectorDigest } from '../../src/collector-identity.mjs';
import { onFreePorts } from './fixtures/free-port.mjs';

// PERF: the opt-in upper bounds above. LOAD_CAP_MS: the cap on every event-driven wait (and on the drains that must become
// quiescent), far above an idle run's milliseconds. NO_REPLY_MS: how long an exchange that must get no answer is watched.
const PERF = process.env.SCOPEHAVEN_PERF === '1', LOAD_CAP_MS = 30000, NO_REPLY_MS = 300;
const WITNESS = 'witness.scopehaven.invalid', PAY = 'api.pay.example', HOOKS = 'hooks.chat.example';
const config = extra => ({ port: 47000, routing: 'resolver', names: [{ name: PAY, answer: 'loopback' }, { name: HOOKS, subdomains: true }],
  witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: WITNESS }, witnessWaitMs: 1500, quietMs: 150, ...extra });
function stub(t, extra = {}, options = {}) {
  return onFreePorts(1, async port => {
    const o = createDnsStub({ instanceId: 'dns-stub-dns', ...options, ...config({ port, ...extra }) });
    await o.start(); t.after(() => o.stop());
    return o;
  });
}
// Every lookup here is answered, so a long timeout costs nothing on an idle machine; on a loaded one it keeps a slow answer from
// reading as a timeout (and the query from landing after the witness request).
const resolver = (o, host = '127.0.0.1') => { const r = new Resolver({ timeout: LOAD_CAP_MS, tries: 1 }); r.setServers([host === '::1' ? `[::1]:${o.port}` : `${host}:${o.port}`]); return r; };
const code = async promise => { try { await promise; return 'ok'; } catch (error) { return error.code; } };
// One raw UDP exchange: the reply bytes, or null when none came within waitMs (NO_REPLY_MS where no answer must come).
function udp(o, message, { host = '127.0.0.1', waitMs = LOAD_CAP_MS } = {}) {
  return new Promise(resolve => {
    const s = createSocket(host === '::1' ? 'udp6' : 'udp4');
    const done = value => { clearTimeout(timer); s.close(); resolve(value); };
    const timer = setTimeout(() => done(null), waitMs);
    s.on('message', reply => done(reply));
    s.send(message, o.port, host);
  });
}
function tcpSession(o, host = '127.0.0.1') {
  const socket = connect(o.port, host);
  let buf = Buffer.alloc(0);
  const replies = [];
  socket.on('data', d => { buf = Buffer.concat([buf, d]); while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) { replies.push(buf.subarray(2, 2 + buf.readUInt16BE(0))); buf = buf.subarray(2 + buf.readUInt16BE(0)); } });
  socket.on('error', () => {});
  return {
    connected: new Promise(resolve => socket.once('connect', resolve)),
    write(bytes) { socket.write(bytes); },
    framed(message) { const p = Buffer.alloc(2); p.writeUInt16BE(message.length, 0); socket.write(Buffer.concat([p, message])); },
    replies, close() { socket.destroy(); }, closed: new Promise(resolve => socket.once('close', resolve)),
  };
}
const lookupWitness = (o, from, { nonce = from.witnessNonce, family = 4 } = {}) => code(family === 4 ? resolver(o).resolve4(`${nonce}.${WITNESS}`) : resolver(o).resolve6(`${nonce}.${WITNESS}`));
async function window(o, between, { withWitness = true } = {}) {
  const from = await o.mark();
  await between();
  o.markWitnessRequest(from);
  if (withWitness) await lookupWitness(o, from);
  return o.collect(from, await o.mark());
}
const settle = ms => new Promise(resolve => setTimeout(resolve, ms));
// n turns of the event loop; of two, the second always follows a fresh poll (as in the stub's own waits).
const turns = async n => { for (let k = 0; k < n; k++) await new Promise(resolve => setImmediate(resolve)); };
// Until condition() holds, looked at every 10 ms for at most capMs; returns its last value.
async function until(condition, capMs = LOAD_CAP_MS) {
  const began = performance.now();
  for (;;) { const value = await condition(); if (value || performance.now() - began >= capMs) return value; await settle(10); }
}
// Until count() reaches n, or stops growing: unchanged for idleMs and still unchanged two turns later, the second after a fresh
// poll, so a stall of this process never reads as the kernel having dropped the rest. Returns the last count.
async function readAll(count, n, idleMs = 2000) {
  let last = await count(), since = performance.now();
  while (last < n) {
    await settle(10);
    let now = await count();
    if (now === last && performance.now() - since >= idleMs) { await turns(2); now = await count(); if (now === last) break; }
    if (now !== last) { last = now; since = performance.now(); }
  }
  return last;
}
// The replies a TCP session has read, once it has read n of them (a reply proves the stub read its query).
const answered = async (s, n = 1) => { await until(() => s.replies.length >= n); return s.replies; };
// An upper bound on elapsed time, checked only with SCOPEHAVEN_PERF=1 (the header).
const perfBelow = (ms, limit, label) => { if (PERF) assert.ok(ms < limit, `${label} (${Math.round(ms)} ms, limit ${limit} ms)`); };

test('dns-stub config: a loopback stub of declared names; routing and witness together; nothing answers outside loopback', () => {
  const ok = validateDnsStubConfig(config({}), { ops: {} });
  assert.deepEqual(ok.names, [{ name: PAY, answer: 'loopback', subdomains: false }, { name: HOOKS, answer: 'nxdomain', subdomains: true }]);
  assert.equal(validateDnsStubConfig({ port: 47000, names: [] }).routing, null, 'presence-only without routing');
  const refused = [
    [{ port: 0 }, /"port"/], [{ port: 53 }, /"port"/], [{ names: [{ name: 'API.pay.example' }] }, /lowercase host name/], [{ names: [{ name: 'localhost' }] }, /two or more labels/],
    [{ names: [{ name: 'pay.example.' }] }, /no trailing dot/], [{ names: [{ name: PAY, answer: '10.0.0.5' }] }, /never answers outside loopback/],
    [{ names: [{ name: PAY }, { name: PAY }] }, /declared once/], [{ routing: undefined }, /go together/], [{ routing: 'proxy' }, /"resolver"/],
    [{ witness: { actorId: 'ops', method: 'POST', path: '/ping', domain: WITNESS } }, /GET/], [{ witness: { actorId: 'nobody', method: 'GET', path: '/ping', domain: WITNESS } }, /declared actor/],
    [{ witness: { actorId: 'ops', method: 'GET', path: '/ping?scopehaven_witness=1', domain: WITNESS } }, /own witness parameter/],
    [{ witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: 'pay.example' } }, /not, does not contain and is not under a declared name/],
    [{ witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: `x.${PAY}` } }, /not under a declared name/], [{ upstream: '8.8.8.8' }, /a dns-stub observer is/],
  ];
  for (const [extra, message] of refused) assert.throws(() => validateDnsStubConfig(config(extra), { ops: {} }), message, JSON.stringify(extra));
  assert.throws(() => createDnsStub({ ...config({}), scanner: { find() {} } }), /a scanner is/);
});

test('dns-stub: holds its port on 127.0.0.1 and [::1], UDP and TCP; does not start, and leaves nothing bound, unless all four bind', async t => {
  const o = await stub(t);
  for (const host of ['127.0.0.1', '::1']) {
    assert.deepEqual(await resolver(o, host).resolve4(PAY), ['127.0.0.1'], `UDP on ${host}`);
    const s = tcpSession(o, host); await s.connected; s.framed(encodeQuery({ id: 7, labels: ['api', 'pay', 'example'], qtype: 28 }));
    const replies = await answered(s); s.close();
    assert.equal(parseResponse(replies[0]).answers[0].type, 'AAAA', `TCP on ${host}`);
  }
  // Another process (here, a socket of this one) holding [::1] UDP at the port: the stub refuses to start.
  await onFreePorts(1, async port => {
    const holder = createSocket({ type: 'udp6', ipv6Only: true });
    await new Promise((resolve, reject) => { holder.once('error', reject); holder.bind({ port, address: '::1' }, resolve); });
    t.after(() => holder.close());
    const blocked = createDnsStub(config({ port }));
    await assert.rejects(blocked.start(), e => e.code === 'EADDRINUSE');
    // Nothing it bound before the failure is left listening.
    const probe = createSocket('udp4');
    await new Promise((resolve, reject) => { probe.once('error', reject); probe.bind({ port, address: '127.0.0.1' }, resolve); });
    probe.close();
  });
});

test('dns-stub: answers declared names as declared (loopback A/AAAA, TTL 0), NXDOMAIN for the rest, and records every lookup', async t => {
  const o = await stub(t);
  const w = await window(o, async () => {
    const r = resolver(o);
    assert.deepEqual(await r.resolve4(PAY), ['127.0.0.1']);
    assert.deepEqual(await r.resolve6(PAY), ['::1']);
    assert.equal(await code(r.resolve4(HOOKS)), 'ENOTFOUND', 'a declared nxdomain name');
    assert.equal(await code(r.resolve4('team-a.hooks.chat.example')), 'ENOTFOUND', 'under a declared parent with subdomains');
    assert.equal(await code(r.resolve4('elsewhere.example')), 'ENOTFOUND');
    assert.equal(await code(r.resolveTxt(PAY)), 'ENODATA', 'NODATA for another type of a loopback name');
  });
  assert.deepEqual([w.coverage, w.reason], ['complete', null]);
  assert.deepEqual(w.lookups.map(l => [l.type, l.name, l.exact]), [['A', PAY, true], ['AAAA', PAY, true], ['A', HOOKS, true], ['A', HOOKS, false], ['A', '*', false], ['TXT', PAY, true]]);
  const answer = parseResponse(await udp(o, encodeQuery({ id: 9, labels: ['api', 'pay', 'example'], qtype: 255 })));
  assert.deepEqual([answer.id, answer.qr, answer.aa, answer.rcode, answer.answers.map(a => [a.type, a.ttl])], [9, 1, 1, 'noerror', [['A', 0], ['AAAA', 0]]]);
  const nx = await udp(o, encodeQuery({ id: 10, labels: ['nowhere', 'example'] }));
  assert.deepEqual([parseResponse(nx).rcode, nx.readUInt16BE(8)], ['nxdomain', 0], 'no SOA in the authority section, so nothing caches the negative answer');
});

test('dns-stub: nothing secret is stored; an undeclared name is a salted digest, a label count and a length only', async t => {
  const o = await stub(t), other = await stub(t);
  const secret = 'acct-77-routing-z9q4';
  const w = await window(o, async () => { await code(resolver(o).resolve4(`${secret}.drop.attacker.example`)); await code(resolver(o).resolve4(`${secret}.team-a.${HOOKS}`)); });
  const text = JSON.stringify(w);
  for (const part of [secret, 'attacker', 'drop', 'team-a']) assert.ok(!text.includes(part), `the record never holds "${part}"`);
  // Wire length: the presentation length (secret, a dot, the rest) plus the first length byte and the root byte.
  assert.deepEqual(w.lookups.map(l => [l.name, l.labels, l.bytes]), [['*', 4, secret.length + 'drop.attacker.example'.length + 3], [HOOKS, 5, secret.length + `team-a.${HOOKS}`.length + 3]]);
  const again = await window(other, async () => { await code(resolver(other).resolve4(`${secret}.drop.attacker.example`)); });
  assert.match(w.lookups[0].digest, /^[a-f0-9]{64}$/);
  assert.notEqual(again.lookups[0].digest, w.lookups[0].digest, 'salted per stub: digests do not join across stubs');
});

test('dns-stub: without this window\'s witness lookup, silence is never complete; the witness and its repeats are never lookups', async t => {
  const o = await stub(t);
  const silent = await window(o, async () => {}, { withWitness: false });
  assert.deepEqual([silent.coverage, silent.reason], ['partial', 'dns-witness-not-received']);
  // A resolver asks A and AAAA (and may retry): the first lookup is the witness, the rest repeat it.
  const from = await o.mark(); o.markWitnessRequest(from);
  await lookupWitness(o, from); await lookupWitness(o, from, { family: 6 }); await lookupWitness(o, from);
  const both = await o.collect(from, await o.mark());
  assert.deepEqual([both.coverage, both.reason, both.lookups.length], ['complete', null, 0]);
  const foreign = await (async () => { const f = await o.mark(); o.markWitnessRequest(f); await lookupWitness(o, f, { nonce: '00000000-0000-4000-8000-000000000000' }); return o.collect(f, await o.mark()); })();
  assert.match(foreign.reason, /dns-foreign-witness/); assert.match(foreign.reason, /dns-witness-not-received/);
  const odd = await window(o, async () => { await code(resolver(o).resolve4(`extra.label.${WITNESS}`)); });
  assert.deepEqual([odd.coverage, odd.reason, odd.lookups.length], ['partial', 'dns-witness-malformed-query', 0]);
});

test('dns-stub: a lookup after the witness request is never attributed to the check, and the window is partial', async t => {
  const o = await stub(t);
  const from = await o.mark(); o.markWitnessRequest(from);
  await code(resolver(o).resolve4('late.example')); await lookupWitness(o, from);
  const w = await o.collect(from, await o.mark());
  assert.deepEqual([w.coverage, w.lookups.length], ['partial', 0]); assert.match(w.reason, /dns-query-after-witness-request/);
});

test('dns-stub: presence-only without routing; a listener that went down fails the window', async t => {
  const o = await stub(t, { routing: undefined, witness: undefined });
  const w = await window(o, async () => { await code(resolver(o).resolve4('a.example')); }, { withWitness: false });
  assert.deepEqual([w.coverage, w.lookups.length, o.scope.evidence], ['complete', 1, 'presence-only']);
  const from = await o.mark();
  await o.stop();
  assert.equal((await o.collect(from, await o.mark())).coverage, 'failed');
});

test('dns-stub: unreadable and non-query messages leave the window partial; responses and headerless bytes get no answer', async t => {
  const o = await stub(t);
  const cases = [
    ['truncated header', Buffer.from([1, 2, 3]), null, 'dns-malformed-query'],
    ['a response', encodeResponse(parseQuery(encodeQuery({ id: 3, labels: ['x', 'example'] })), { rcode: 'nxdomain' }), null, 'dns-not-a-query'],
    ['two questions', (() => { const q = encodeQuery({ id: 4, labels: ['x', 'example'] }); q.writeUInt16BE(2, 4); return q; })(), 'formerr', 'dns-multi-question-query'],
    ['a looping pointer', Buffer.concat([encodeQuery({ id: 5, labels: [] }).subarray(0, 12), Buffer.from([0xc0, 12, 0, 1, 0, 1])]), 'formerr', 'dns-malformed-query'],
    ['a forward pointer', Buffer.concat([encodeQuery({ id: 5, labels: [] }).subarray(0, 12), Buffer.from([0xc0, 20, 0, 1, 0, 1, 0, 0, 1, 97, 0])]), 'formerr', 'dns-malformed-query'],
    ['an UPDATE', (() => { const q = encodeQuery({ id: 6, labels: ['zone', 'example'] }); q.writeUInt16BE(5 << 11, 2); return q; })(), 'notimp', 'dns-opcode-query'],
    ['a name over 255 bytes', encodeQuery({ id: 8, labels: Array(5).fill('a'.repeat(60)) }), 'formerr', 'dns-malformed-query'],
  ];
  for (const [label, bytes, rcode, reason] of cases) {
    const w = await window(o, async () => {
      const reply = await udp(o, bytes, rcode === null ? { waitMs: NO_REPLY_MS } : {});
      assert.equal(reply === null ? null : parseResponse(reply).rcode, rcode, label);
    });
    assert.deepEqual([w.coverage, w.reason, w.lookups.length], ['partial', reason, 0], label);
  }
  // Another class is still a lookup (recorded and scanned), answered REFUSED.
  const chaos = await window(o, async () => { assert.equal(parseResponse(await udp(o, encodeQuery({ id: 11, labels: ['version', 'bind'], qtype: 16, qclass: 3 }))).rcode, 'refused'); });
  assert.deepEqual([chaos.coverage, chaos.lookups.map(l => [l.type, l.class, l.name])], ['complete', [['TXT', 3, '*']]]);
});

test('dns-stub: over TCP, pipelined queries are each answered; a query cut off, or still arriving at collect, is never complete', async t => {
  const o = await stub(t);
  const piped = await window(o, async () => {
    const s = tcpSession(o); await s.connected;
    s.framed(encodeQuery({ id: 21, labels: ['api', 'pay', 'example'] })); s.framed(encodeQuery({ id: 22, labels: ['b', 'example'] }));
    await answered(s, 2); s.close(); await s.closed;
    assert.deepEqual(s.replies.map(r => [parseResponse(r).id, parseResponse(r).rcode]), [[21, 'noerror'], [22, 'nxdomain']]);
  });
  assert.deepEqual([piped.coverage, piped.lookups.map(l => l.name)], ['complete', [PAY, '*']]);
  const cut = await window(o, async () => { const s = tcpSession(o); await s.connected; s.write(Buffer.from([0, 40, 1, 2, 3])); await settle(50); s.close(); await s.closed; await settle(50); });
  assert.deepEqual([cut.coverage, cut.reason, cut.lookups.length], ['partial', 'dns-incomplete-query', 0]);
  const s = tcpSession(o); await s.connected;
  const from = await o.mark();
  s.write(Buffer.from([0]));
  o.markWitnessRequest(from); await lookupWitness(o, from);
  const open = await o.collect(from, await o.mark());
  s.close();
  assert.match(open.reason, /dns-query-in-flight/);
});

test('dns-stub: an operator scanner reads each query name as it arrives (case kept); the record keeps only its canary id and channel', async t => {
  const seen = [];
  const scanner = { canaries: [{ id: 'tenant-b' }, { id: 'tenant-c' }, { id: 'unset' }], unavailable: [{ canary: 'unset', reason: 'value-unavailable' }],
    scan(view) { seen.push(view); return { hits: view.labels.some(l => l === 'Zq7Kc0de') ? [{ canary: 'tenant-b', channel: 'verbatim', value: 'never kept' }, { canary: 'tenant-c', channel: 'folded', via: 'base32' }] : [], complete: !view.labels.includes('huge') }; } };
  const o = await stub(t, {}, { scanner });
  const w = await window(o, async () => { await udp(o, encodeQuery({ id: 31, labels: ['Zq7Kc0de', 'exfil', 'example'] })); await code(resolver(o).resolve4('plain.example')); await code(resolver(o).resolve4('huge.example')); });
  assert.deepEqual(w.lookups.map(l => [l.canaries, l.scanned]), [[[{ canary: 'tenant-b', channel: 'verbatim' }, { canary: 'tenant-c', channel: 'folded', via: 'base32' }], true], [[], true], [[], false]]);
  assert.deepEqual(o.scope.scannedCanaries, ['tenant-b', 'tenant-c'], 'an unavailable canary is never listed as scanned');
  assert.ok(!JSON.stringify(w).includes('never kept') && !JSON.stringify(w).includes('Zq7Kc0de'));
  assert.deepEqual(seen.map(v => [v.labels, v.name, v.where]), [[['Zq7Kc0de', 'exfil', 'example'], 'zq7kc0de.exfil.example', 'dns-qname'], [['plain', 'example'], 'plain.example', 'dns-qname'], [['huge', 'example'], 'huge.example', 'dns-qname']], 'never the witness');
  assert.equal(o.scope.scanned, true);
  assert.throws(() => createDnsStub({ ...config({}), scanner: { scan() { return { hits: [], complete: true }; } } }), /a scanner is/, 'a scanner must say which canaries it reads');
});

test('dns-stub: names are compared label by label; a label holding a dot is never a declared name, a declared parent or the witness', async t => {
  const o = await stub(t);
  const w = await window(o, async () => {
    for (const labels of [['x.api', 'pay', 'example'], ['api.pay', 'example'], ['team.a', 'hooks', 'chat', 'example'], ['x.witness', 'scopehaven', 'invalid']]) await udp(o, encodeQuery({ id: 41, labels }));
  });
  assert.deepEqual(w.lookups.map(l => [l.name, l.exact]), [['*', false], ['*', false], ['hooks.chat.example', false], ['*', false]]);
  assert.deepEqual([w.coverage, w.reason], ['complete', null], 'a dotted label under the witness domain is an ordinary lookup, never a malformed witness');
  const answer = parseResponse(await udp(o, encodeQuery({ id: 42, labels: ['x.api', 'pay', 'example'] })));
  assert.equal(answer.rcode, 'nxdomain', 'never answered as the declared loopback name');
});

test('dns-wire: presentation escapes keep every label boundary; the question is echoed with its case', () => {
  assert.equal(presentLabel('Ab-_9'), 'ab-_9');
  assert.equal(presentLabel('a.b'), 'a\\.b', 'a dot inside a label never reads as two labels');
  assert.equal(presentLabel('a\u0000\u00ff\\'), 'a\\000\\255\\\\');
  const q = parseQuery(encodeQuery({ id: 2, labels: ['MiXeD', 'Example'], edns: true }));
  assert.deepEqual([q.question.labels, q.question.name, q.question.type, q.error], [['MiXeD', 'Example'], 'mixed.example', 'A', undefined]);
  const echoed = encodeResponse(q, { records: [{ type: 'AAAA', address: '::1' }] });
  assert.equal(echoed.subarray(12, 12 + 15).toString('latin1'), '\u0005MiXeD\u0007Example\u0000');
  assert.deepEqual([...parseResponse(echoed).answers[0].data], [...Buffer.alloc(15), 1]);
});

test('dns-stub: never forwards; the collector record digests the stub\'s files', async () => {
  const source = await readFile(new URL('./dns-stub.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /from 'node:(dns|http|https|tls)'/);
  assert.equal(source.match(/\.send\(/g).length, 1, 'one send only');
  assert.ok(source.includes('s.send(reply, rinfo.port, rinfo.address, () => {})'), 'the only send is the answer to the query\'s own sender');
  assert.doesNotMatch(source, /\bconnect\(/);
  assert.deepEqual(DNS_STUB_COLLECTOR, { label: 'dns-stub/1', digest: await collectorDigest(DNS_STUB_FILES), node: process.versions.node });
});

// Review fixes (2026-10-23). Each test below is the reviewed defect's own input, now recorded as incomplete or late.
const framed = message => { const p = Buffer.alloc(2); p.writeUInt16BE(message.length, 0); return Buffer.concat([p, message]); };
const closedWithin = (socket, ms) => new Promise(resolve => { if (socket.destroyed) return resolve(true); const timer = setTimeout(() => resolve(false), ms); socket.once('close', () => { clearTimeout(timer); resolve(true); }); });

test('dns-stub H1: a scanner that throws or returns anything else never reads as a clean scan; the lookup is kept and the stub keeps serving', async t => {
  const scanner = { canaries: [{ id: 'tenant-b' }],
    scan(view) {
      if (view.labels.some(l => l.includes('\u0000'))) throw new TypeError('scanner: unexpected byte');
      if (view.labels[0] === 'odd') return 'not a result';
      if (view.labels[0] === 'stray') return { hits: [{ canary: 'tenant-b', channel: 'verbatim' }, { canary: 'tenant-z', channel: 'verbatim' }, { canary: 'tenant-b', channel: 'folded', via: 'acct-77-routing-z9q4' }, { canary: 'tenant-b', channel: 'Zq7Kc0de' }], complete: true };
      return { hits: [], complete: true };
    } };
  const o = await stub(t, {}, { scanner });
  const w = await window(o, async () => { assert.notEqual(await udp(o, encodeQuery({ id: 61, labels: ['a\u0000b', 'example'] })), null, 'answered'); });
  assert.deepEqual([w.coverage, w.reason, w.scanned], ['partial', 'dns-scan-failed', false]);
  assert.deepEqual(w.lookups.map(l => [l.name, l.canaries, l.scanned, l.scanProblem]), [['*', null, false, 'dns-scan-failed']]);
  // Still serving after the throw, and a later lookup in a later window reads complete.
  const after = await window(o, async () => { assert.deepEqual(await resolver(o).resolve4(PAY), ['127.0.0.1']); });
  assert.deepEqual([after.coverage, after.scanned, after.lookups.map(l => [l.canaries, l.scanned])], ['complete', true, [[[], true]]]);
  // L4: only a hit naming a canary the scanner holds, a known channel and a known decoding is kept; nothing else is stored.
  const odd = await window(o, async () => { await udp(o, encodeQuery({ id: 62, labels: ['odd', 'example'] })); await udp(o, encodeQuery({ id: 63, labels: ['stray', 'example'] })); });
  assert.deepEqual([odd.coverage, odd.reason, odd.scanned], ['partial', 'dns-scan-invalid', false]);
  assert.deepEqual(odd.lookups.map(l => [l.canaries, l.scanned, l.scanProblem]), [[null, false, 'dns-scan-invalid'], [[{ canary: 'tenant-b', channel: 'verbatim' }], false, 'dns-scan-invalid']]);
  for (const part of ['tenant-z', 'acct-77', 'Zq7Kc0de']) assert.ok(!JSON.stringify(odd).includes(part), `never stored: ${part}`);
});

test('dns-stub M1: a TCP client that never reads is dropped once its unread replies pass the bound, and the drop leaves the window partial', async t => {
  const o = await onFreePorts(1, async port => { const s = createDnsStub({ instanceId: 'dns-stub-dns', retained: 200000, ...config({ port }) }); await s.start(); t.after(() => s.stop()); return s; });
  const from = await o.mark();
  const socket = connect(o.port, '127.0.0.1'); socket.on('error', () => {});
  await new Promise(resolve => socket.once('connect', resolve));
  socket.pause();
  const batch = Buffer.concat(Array.from({ length: 1000 }, (_, i) => framed(encodeQuery({ id: i, labels: ['api', 'pay', 'example'], qtype: 255 }))));
  let sent = 0;
  // The stub drops the connection once it has answered enough to pass the bound, however long that takes a loaded machine; a
  // stub that never drops it holds it until its own idle timeout, and the window below then lacks the backlog record.
  const dropWaitMs = PERF ? 2000 : LOAD_CAP_MS;
  while (!socket.destroyed && sent < 6 * 1024 * 1024) {
    sent += batch.length;
    if (!socket.write(batch)) await Promise.race([new Promise(resolve => socket.once('drain', resolve)), closedWithin(socket, dropWaitMs)]);
  }
  assert.equal(await closedWithin(socket, dropWaitMs), true, `dropped after ${sent} bytes sent, never read`);
  o.markWitnessRequest(from); await lookupWitness(o, from);
  const w = await o.collect(from, await o.mark());
  assert.equal(w.coverage, 'partial'); assert.match(w.reason, /dns-backlog-query/);
});

test('dns-stub M1: a TCP query longer than tcpQueryBytes is never buffered (dropped, partial); one of exactly that length is read', async t => {
  const o = await stub(t);
  const big = await window(o, async () => {
    const socket = connect(o.port, '127.0.0.1'); socket.on('error', () => {});
    await new Promise(resolve => socket.once('connect', resolve));
    socket.write(Buffer.concat([Buffer.from([0xff, 0xff]), Buffer.alloc(100)]));
    // At once: well before the stub's own idle timeout could close a connection that waits for the rest (1000 ms with PERF).
    assert.equal(await closedWithin(socket, PERF ? 1000 : DNS_STUB_LIMITS.idleMs / 2), true, 'dropped at once');
  });
  assert.deepEqual([big.coverage, big.reason, big.lookups.length], ['partial', 'dns-oversize-query', 0]);
  const edge = await window(o, async () => {
    const s = tcpSession(o); await s.connected;
    const q = encodeQuery({ id: 71, labels: ['api', 'pay', 'example'] });
    s.write(framed(Buffer.concat([q, Buffer.alloc(DNS_STUB_LIMITS.tcpQueryBytes - q.length)])));
    const replies = await answered(s); s.close(); await s.closed;
    assert.equal(parseResponse(replies[0]).rcode, 'noerror');
  });
  assert.deepEqual([edge.coverage, edge.lookups.map(l => l.name)], ['complete', [PAY]]);
});

test('dns-stub M1: at most maxConnections TCP connections across both addresses; one more is dropped and recorded', async t => {
  const o = await stub(t);
  const from = await o.mark();
  const open = [];
  for (let i = 0; i <= DNS_STUB_LIMITS.maxConnections; i++) { const s = tcpSession(o, i % 2 ? '::1' : '127.0.0.1'); open.push(s); await s.connected; }
  await settle(100);
  o.markWitnessRequest(from); await lookupWitness(o, from);
  const w = await o.collect(from, await o.mark());
  for (const s of open) s.close();
  assert.deepEqual([w.coverage, w.reason], ['partial', 'dns-dropped-query']);
});

test('dns-stub M2: a lookup after the final mark leaves the run-end window partial; the adjacent quiet window is complete', async t => {
  const o = await stub(t);
  const from = await o.mark();
  await code(resolver(o).resolve4('before.example'));
  const to = await o.mark();
  await code(resolver(o).resolve4('exfil-at-shutdown.example'));
  const late = await o.collect(from, to, { gap: true, final: true });
  assert.deepEqual([late.coverage, late.reason, late.lookups.length], ['partial', 'dns-query-after-final-mark', 1]);
  // Without final, the same range is an exact gap: the later lookup belongs to a later window.
  assert.equal((await o.collect(from, to, { gap: true })).coverage, 'complete');
  const quiet = await (async () => { const f = await o.mark(); await code(resolver(o).resolve4('before.example')); const e = await o.mark(); return o.collect(f, e, { gap: true, final: true }); })();
  assert.deepEqual([quiet.coverage, quiet.reason], ['complete', null]);
  // A late repeat of an earlier window's witness (the AAAA after the A) carries nothing of the app's: it is not a late lookup.
  const checked = await o.mark(); o.markWitnessRequest(checked); await lookupWitness(o, checked); await o.collect(checked, await o.mark());
  const g = await o.mark(), h = await o.mark();
  await lookupWitness(o, checked, { family: 6 });
  assert.deepEqual((await o.collect(g, h, { gap: true, final: true })).coverage, 'complete');
  // A lookup that arrives while the run-end window is being collected, within quietMs of its end mark, still leaves it partial.
  // The mark taken as the collect returns (no poll between) says whether the stub had read the tail by then.
  const f = await o.mark(), e = await o.mark();
  const collecting = o.collect(f, e, { gap: true, final: true }).then(w => ({ w, returnedAt: performance.now(), m: o.mark() }));
  await settle(30); await udp(o, encodeQuery({ id: 81, labels: ['tail', 'example'] }));
  const { w: tail, returnedAt, m } = await collecting;
  const tailRead = (await o.collect(e, await m, { gap: true })).lookups.length > 0;
  // On any machine the wait lasts at least quietMs past the end mark, and a tail it read leaves the window partial. A loaded
  // machine may hand the stub the tail only after the wait was judged; a lookup read after the wait is in no window
  // (DNS-STUB.md), and only then may the window read complete. On an idle machine (PERF) the tail is always read in time.
  assert.ok(returnedAt - e.at >= 150, `the run-end wait lasted ${Math.round(returnedAt - e.at)} ms past its end mark (quietMs 150)`);
  if (tailRead || PERF) assert.deepEqual([tail.coverage, tail.reason], ['partial', 'dns-query-after-final-mark']);
  // A stub that stops while its run-end window waits for quiet fails the window: nothing it missed can read complete.
  const x = await o.mark(), y = await o.mark();
  const stopping = o.collect(x, y, { gap: true, final: true });
  await o.stop();
  assert.deepEqual(await stopping.then(w => [w.coverage, w.reason]), ['failed', 'dns-listener-down']);
});

test('dns-stub M2: the run-end drain waits for TCP queries in flight and quiet, looks again after one turn; markClear', async t => {
  let turns = 0, sentAt = 0, stubRef = null;
  const drainTurn = async () => { turns++; if (turns === 1) { sentAt = performance.now(); await code(resolver(stubRef).resolve4('turn.example')); } };
  const o = stubRef = await stub(t, {}, { drainTurn });
  assert.equal(o.markClear(await o.mark()), true, 'idle at the mark');
  assert.equal((await o.drain({ capMs: 0 })).quiescent, false, 'no time, no drain');
  // Drains that must become quiescent are capped at LOAD_CAP_MS (they return at quiet); the old 3000 ms caps hold with PERF.
  const d = await o.drain({ capMs: LOAD_CAP_MS });
  const since = performance.now() - sentAt;
  assert.deepEqual([d.quiescent, d.closedAfterCollect, turns >= 2], [true, false, true]);
  assert.ok(since >= 150, `quiescent ${Math.round(since)} ms after a lookup recorded in its last turn (quietMs 150)`);
  perfBelow(d.waitedMs, 3000, 'quiescent after the lookup in its first turn');
  // The partial query is in flight once a gap window from before it reads it so (the stub has read its bytes): never a fixed wait.
  const beforeWrite = await o.mark();
  const s = tcpSession(o); await s.connected; s.write(Buffer.from([0, 40, 1]));
  assert.ok(await until(async () => /dns-query-in-flight/.test((await o.collect(beforeWrite, await o.mark(), { gap: true })).reason ?? '')), 'the stub read the partial query');
  assert.equal(o.markClear(await o.mark()), false, 'a TCP query in flight at the mark');
  assert.equal((await o.drain({ capMs: 400 })).quiescent, false, 'a TCP query in flight');
  assert.equal(o.markClear({ ...(await o.mark()) }), false, 'a mark this stub did not make');
  s.close(); await s.closed;
  const cut = await o.drain({ capMs: LOAD_CAP_MS });
  assert.equal(cut.quiescent, true, 'the cut query recorded, then quiet');
  perfBelow(cut.waitedMs, 3000, 'quiescent after the cut query');
  await o.stop();
  // A stopped stub is said at once: always before the drain's own cap (a drain that missed the stop waits for it), and within
  // 1000 ms with PERF.
  const stopped = await o.drain({ capMs: 10000 });
  assert.deepEqual([stopped.quiescent, stopped.waitedMs < 10000], [false, true], 'a stopped stub, said before its cap');
  perfBelow(stopped.waitedMs, 1000, 'a stopped stub, said at once');
  assert.equal(o.markClear(await o.mark()), false);
});

test('dns-stub M3: with no scanner, a lookup reads canaries null and the window scanned false, never a clean scan', async t => {
  const o = await stub(t);
  const w = await window(o, async () => { await code(resolver(o).resolve4('Zq7Kc0de.exfil.example')); });
  assert.deepEqual([w.coverage, w.scanned, w.scannedCanaries, w.lookups.map(l => [l.canaries, l.scanned])], ['complete', false, [], [[null, false]]]);
  const silent = await window(o, async () => {});
  assert.deepEqual([silent.coverage, silent.lookups.length, silent.scanned], ['complete', 0, false], 'a silent window of a stub with no scanner is not scanned either');
  const scanned = await stub(t, {}, { scanner: { canaries: [{ id: 'tenant-b' }], scan: () => ({ hits: [], complete: true }) } });
  const s = await window(scanned, async () => { await code(resolver(scanned).resolve4('Zq7Kc0de.exfil.example')); });
  assert.deepEqual([s.coverage, s.scanned, s.scannedCanaries, s.lookups.map(l => [l.canaries, l.scanned])], ['complete', true, ['tenant-b'], [[[], true]]]);
});

test('dns-stub L1: only a nonce one of the stub\'s own marks issued is remembered; any other reads foreign every time', async t => {
  const o = await stub(t);
  const stranger = '11111111-2222-4333-8444-555555555555';
  const first = await window(o, async () => { await lookupWitness(o, null, { nonce: stranger }); });
  assert.deepEqual([first.coverage, first.reason], ['partial', 'dns-foreign-witness']);
  const again = await window(o, async () => { await lookupWitness(o, null, { nonce: stranger }); });
  assert.deepEqual([again.coverage, again.reason], ['partial', 'dns-foreign-witness'], 'never a repeat of a nonce it did not issue');
});

test('dns-stub L2 and L3: only A to Z fold, so distinct bytes keep distinct names and digests; each lookup carries its transport and arrival time', async t => {
  assert.deepEqual([presentLabel('À'), presentLabel('à'), presentLabel('API')], ['\\192', '\\224', 'api']);
  assert.equal(parseQuery(encodeQuery({ labels: ['À', 'x', 'example'] })).question.name, '\\192.x.example');
  const o = await stub(t);
  const before = Date.now();
  const w = await window(o, async () => {
    await udp(o, encodeQuery({ id: 91, labels: ['À', 'x', 'example'] })); await udp(o, encodeQuery({ id: 92, labels: ['à', 'x', 'example'] }), { host: '::1' });
    for (const host of ['127.0.0.1', '::1']) { const s = tcpSession(o, host); await s.connected; s.framed(encodeQuery({ id: 93, labels: ['API', 'PAY', 'EXAMPLE'] })); await answered(s); s.close(); await s.closed; }
  });
  const after = Date.now();
  assert.notEqual(w.lookups[0].digest, w.lookups[1].digest, '0xC0 and 0xE0 are different names');
  assert.deepEqual(w.lookups.map(l => [l.transport, l.name]), [['udp4', '*'], ['udp6', '*'], ['tcp4', PAY], ['tcp6', PAY]]);
  for (const l of w.lookups) assert.ok(Date.parse(l.arrivedAt) >= before && Date.parse(l.arrivedAt) <= after, l.arrivedAt);
});

// Round 2 review fixes (2026-10-23).
test('dns-stub M4: a UDP burst that may overflow the receive buffer reads partial, never complete with a loss; a small one reads complete', async t => {
  // Marks taken in the turn that read a given query of the burst, after the stub's own check, each with how many of the burst
  // the stub had read by then: b100 before the busy period reaches its limit, b3000 after, and b4999, its last query, before
  // the turn that finds the socket empty (so the window after it holds only the busy period's end). A mark whose query the
  // kernel dropped (Linux at its default rmem_max) is never taken. read: the queries of each burst (by tag) the stub has read.
  const at = {}, watched = new Set(['b100', 'b3000', 'b4999']), read = { s: 0, b: 0, a: 0 };
  let stubRef = null;
  const scanner = { canaries: [{ id: 'tenant-b' }], scan(view) {
    const label = view.labels[0];
    if (view.labels[1] === 'burst' && Object.hasOwn(read, label[0])) read[label[0]]++;
    if (watched.has(label)) setImmediate(() => { at[label] = { mark: stubRef.mark(), read: read.b }; });
    return { hits: [], complete: true };
  } };
  const o = stubRef = await stub(t, {}, { scanner });
  const client = createSocket('udp4'); client.on('error', () => {}); t.after(() => client.close());
  await new Promise(resolve => client.connect(o.port, '127.0.0.1', resolve));
  // Sent while the stub cannot read (this loop holds the event loop), then held 50 ms more, as a busy connector or a GC would.
  // The whole burst is queued (or dropped) before the stub reads any of it, so it reads it in one busy period.
  const burst = (n, tag) => { for (let i = 0; i < n; i++) client.send(encodeQuery({ id: 1, labels: [`${tag}${i}`, 'burst', 'example'] })); const began = performance.now(); while (performance.now() - began < 50); };
  // The witness request waits until the stub has read every query of the burst the kernel kept, never a fixed time: a loaded
  // machine can take longer than any fixed wait to read 5,000, and a query read after the witness request is never attributed.
  const readBurst = (tag, n) => readAll(() => read[tag], n);
  // The safety property, on any machine and however many datagrams the kernel delivered: a window that reads complete recorded
  // every query sent, and one that recorded fewer reads partial and never says scanned.
  const neverSilentLoss = (w, sent, label) => {
    if (w.coverage === 'complete') assert.equal(w.lookups.length, sent, `${label}: complete only with all ${sent} recorded`);
    if (w.lookups.length < sent) assert.deepEqual([w.coverage, w.scanned], ['partial', false], `${label}: ${w.lookups.length} of ${sent} recorded`);
  };
  const small = await window(o, async () => { burst(100, 's'); await readBurst('s', 100); });
  neverSilentLoss(small, 100, 'small');
  // 100 small queries fit any receive buffer, far under the limit: complete, each recorded and scanned.
  assert.deepEqual([small.coverage, small.reason, small.lookups.length, small.scanned], ['complete', null, 100, true]);
  // The reviewer's case, scaled: 5000 queries at once. With the OS default buffer (786,896 bytes on macOS) about 900 were lost
  // and the window read complete.
  const from = await o.mark();
  burst(5000, 'b');
  const bigRead = await readBurst('b', 5000);
  o.markWitnessRequest(from); await lookupWitness(o, from);
  const big = await o.collect(from, await o.mark());
  neverSilentLoss(big, 5000, 'big');
  // Read in one busy period past half the granted buffer (or the kernel dropped part of it, which needs a full buffer, read in
  // that same period): partial, and never scanned. Every query the stub read came before the witness request: all are in it.
  assert.deepEqual([big.coverage, big.reason, big.scanned], ['partial', 'dns-possible-drop-query', false], 'loss was possible: partial, and a lost name was never scanned');
  assert.equal(big.lookups.length, bigRead, 'every query read is in the window');
  // Its first queries were read before the period reached the limit: once it did, they were marked too.
  if (at.b100) {
    const head = await o.collect(from, await at.b100.mark, { gap: true });
    assert.ok(head.lookups.length > 0 && head.lookups.length < 1000, `${head.lookups.length} queries before the mid mark`);
    assert.equal(head.lookups.length, at.b100.read, 'the queries read by the mid mark');
    assert.deepEqual([head.coverage, head.reason], ['partial', 'dns-possible-drop-query']);
  }
  const granted = o.udpRecvBuffer();
  assert.equal(granted.requested, 4 * 1024 * 1024);
  for (const k of ['udp4', 'udp6']) assert.ok(Number.isInteger(granted[k]) && granted[k] > 0, `${k} granted ${granted[k]}`);
  // macOS grants it (kern.ipc.maxsockbuf is 8 MiB by default) and charges a small query about 192 bytes, so 4 MiB holds about
  // 21,800 and none of these is lost. Linux caps it at net.core.rmem_max without an error, and its charge is not measured, so
  // there only the safety property above is checked.
  if (process.platform === 'darwin') assert.equal(granted.udp4, granted.requested);
  if (process.platform === 'darwin' && granted.udp4 >= granted.requested) assert.equal(big.lookups.length, 5000, 'the buffer the stub asked for holds the whole burst');
  assert.deepEqual(big.udpRecvBuffer, granted, 'each window reports the granted buffer');
  // Its queries read after it reached the limit are marked as they come, and its end is a problem record of its own: a window
  // after its last query still reads partial.
  if (at.b3000 && at.b4999) {
    const later = await o.collect(await at.b3000.mark, await at.b4999.mark, { gap: true });
    // The b3000 mark lands after the rest of the batch read in its turn: every query read between the two marks, all past the
    // limit; about 1,999 when none was lost.
    assert.deepEqual([later.coverage, later.reason, later.lookups.length], ['partial', 'dns-possible-drop-query', at.b4999.read - at.b3000.read], `${later.lookups.length} queries`);
    if (bigRead === 5000) assert.ok(later.lookups.length > 1900 && later.lookups.length <= 1999, `${later.lookups.length} queries`);
    assert.deepEqual(await o.collect(await at.b4999.mark, await o.mark(), { gap: true }).then(w => [w.coverage, w.reason, w.lookups.length]), ['partial', 'dns-possible-drop-query', bigRead - at.b4999.read]);
  }
  // Once the socket was found empty again, a small burst reads complete.
  const after = await window(o, async () => { burst(100, 'a'); await readBurst('a', 100); });
  neverSilentLoss(after, 100, 'after');
  assert.deepEqual([after.coverage, after.reason, after.lookups.length], ['complete', null, 100]);
});

test('dns-stub L5: an async scanner that rejects never ends the process; the lookup reads dns-scan-invalid and the stub keeps serving', async t => {
  const scanner = { canaries: [{ id: 'tenant-b' }], async scan(view) { if (view.labels.some(l => l.includes('\u0000'))) throw new TypeError('scanner: unexpected byte'); return { hits: [], complete: true }; } };
  const o = await stub(t, {}, { scanner });
  const w = await window(o, async () => { assert.notEqual(await udp(o, encodeQuery({ id: 64, labels: ['a\u0000b', 'example'] })), null, 'answered'); await settle(50); });
  assert.deepEqual([w.coverage, w.reason, w.scanned, w.lookups.map(l => [l.canaries, l.scanned, l.scanProblem])], ['partial', 'dns-scan-invalid', false, [[null, false, 'dns-scan-invalid']]]);
  assert.ok(!JSON.stringify(w).includes('unexpected byte'));
  assert.deepEqual(await resolver(o).resolve4(PAY), ['127.0.0.1'], 'still serving');
});

test('dns-stub L6: a window holding a name the scanner never read (another opcode, two questions, the witness domain) never says scanned', async t => {
  const seen = [];
  const scanner = { canaries: [{ id: 'tenant-b' }], scan(view) { seen.push(view.name); return { hits: view.labels.includes('CANARY') ? [{ canary: 'tenant-b', channel: 'verbatim' }] : [], complete: true }; } };
  const o = await stub(t, {}, { scanner });
  const query = (id, labels, edit = q => q) => edit(encodeQuery({ id, labels }));
  const cases = [
    ['opcode 2', query(65, ['CANARY', 'x', 'example'], q => { q.writeUInt16BE((2 << 11) | 0x0100, 2); return q; }), 'dns-opcode-query'],
    ['two questions', query(66, ['CANARY', 'x', 'example'], q => { q.writeUInt16BE(2, 4); return q; }), 'dns-multi-question-query'],
    ['a name under the witness domain', query(67, ['CANARY', ...WITNESS.split('.')]), 'dns-witness-malformed-query'],
    ['a foreign nonce', query(69, ['00000000-0000-4000-8000-000000000000', ...WITNESS.split('.')]), 'dns-foreign-witness'],
  ];
  for (const [label, bytes, reason] of cases) {
    const w = await window(o, async () => { await udp(o, bytes); });
    assert.deepEqual([w.coverage, w.reason, w.scanned], ['partial', reason, false], label);
  }
  // The same name as a lookup is scanned, and its hit kept.
  const plain = await window(o, async () => { await udp(o, query(68, ['CANARY', 'x', 'example'])); });
  assert.deepEqual([plain.coverage, plain.scanned, plain.lookups.map(l => l.canaries)], ['complete', true, [[{ canary: 'tenant-b', channel: 'verbatim' }]]]);
  assert.deepEqual(seen, ['canary.x.example'], 'the scanner read only the lookup');
});

test('dns-stub L7: the run-end wait stops at its cap while the app keeps looking up; no time is no drain, even idle; a late lookup\'s scan counts', async t => {
  const o = await stub(t, { witnessWaitMs: 0, quietMs: 100 });
  const client = createSocket('udp4'); client.on('error', () => {}); t.after(() => client.close());
  await new Promise(resolve => client.connect(o.port, '127.0.0.1', resolve));
  const from = await o.mark(), to = await o.mark();
  // A lookup at once (sent before the wait starts, so it is read during it on any machine) and every 40 ms (quietMs 100) for
  // 20 times the wait's cap (0 + 10 * 100 ms): without its cap the wait would last as long as the sender.
  const send = () => client.send(encodeQuery({ id: 1, labels: ['chat', 'example'] }));
  const began = performance.now(), sendMs = 20 * (0 + 10 * 100);
  let sending = true;
  const timer = setInterval(() => { if (performance.now() - began > sendMs) { clearInterval(timer); sending = false; } else send(); }, 40);
  t.after(() => clearInterval(timer));
  send();
  const w = await o.collect(from, to, { gap: true, final: true });
  const waited = performance.now() - began, stillSending = sending;
  clearInterval(timer);
  assert.deepEqual([w.coverage, w.reason], ['partial', 'dns-query-after-final-mark']);
  // It stopped at its cap (or at a quiet gap a loaded machine left in the stream), never at the sender's end; with PERF, by
  // 2500 ms.
  assert.ok(stillSending, `the final wait returned while the sender still sent (${Math.round(waited)} ms)`);
  perfBelow(waited, 2500, 'the final wait stopped at its 1000 ms cap');
  // An idle stub with no drainTurn hook: no time is never quiescent; with time it is.
  const idle = await stub(t);
  assert.equal((await idle.drain({ capMs: 0 })).quiescent, false, 'no time, no drain');
  assert.equal((await idle.drain({ capMs: 1000 })).quiescent, true);
  // A lookup after the witness request is never attributed, but its scan still decides whether the window was scanned.
  const scanned = await stub(t, {}, { scanner: { canaries: [{ id: 'tenant-b' }], scan: view => ({ hits: [], complete: view.labels[0] !== 'huge' }) } });
  const f = await scanned.mark(); scanned.markWitnessRequest(f);
  await code(resolver(scanned).resolve4('huge.example')); await lookupWitness(scanned, f);
  const late = await scanned.collect(f, await scanned.mark());
  assert.deepEqual([late.coverage, late.reason, late.scanned], ['partial', 'dns-query-after-witness-request', false]);
});

// Round 3 review fix (2026-10-23).
test('dns-stub L8: a stall right after the final mark never lets the run-end window, or the drain, pass with queued queries unread', async t => {
  // quietMs 150, so the final wait's cap (1500 + 10 * 150 ms) is far off. Each burst is sent while the stub cannot read (this code
  // holds the event loop), so every query is still queued in the kernel at the mark; then the event loop is held quietMs + 100 ms
  // more, as a GC pause or the connector's own work would, before the collect or the drain.
  const o = await stub(t);
  const client = createSocket('udp4'); client.on('error', () => {}); t.after(() => client.close());
  await new Promise(resolve => client.connect(o.port, '127.0.0.1', resolve));
  const hold = ms => { const began = performance.now(); while (performance.now() - began < ms); };
  const query = (tag, i) => encodeQuery({ id: 1, labels: [`${tag}${i}`, 'stall', 'example'] });
  const send = (n, tag) => { for (let i = 0; i < n; i++) client.send(query(tag, i)); };
  // The receive buffer the OS reports for the stub's 4 MiB request. Where it is at least that, none of these bursts can be
  // dropped: macOS grants 4 MiB and charges a small query about 192 bytes; Linux, where net.core.rmem_max allows (hosted CI),
  // sets 4 MiB and reports twice that, the limit it charges each datagram against (about 900 bytes for a small query).
  const granted = o.udpRecvBuffer().udp4, full = granted >= DNS_STUB_LIMITS.udpRecvBufferBytes;
  // The fewest queries of a burst whose weight in one busy period, as the stub counts it (UDP loss, dns-stub.mjs: each query's
  // length plus udpDatagramCost), reaches half the reported buffer: from there the stub must read the period as a possible drop.
  // The big burst is sized from it, a tenth past: 2,176 queries where 4 MiB is reported (macOS), 4,351 where 8 MiB is (Linux).
  // A fixed count is past half on one and under it on the other (3,000 was, and read complete on Linux, correctly).
  const limitOf = tag => { let n = 0; for (let sum = 0; 2 * sum < granted; n++) sum += query(tag, n).length + DNS_STUB_LIMITS.udpDatagramCost; return n; };
  const bursts = [[500, 's'], [Math.ceil(1.1 * limitOf('b')), 'b']];
  t.diagnostic(`udp4 receive buffer: ${granted} bytes reported; bursts of ${bursts.map(([n]) => n).join(' and ')}`);
  // The lookups the stub has recorded since a mark (a gap window reads them without waiting).
  const readSince = async mark => (await o.collect(mark, await o.mark(), { gap: true })).lookups.length;
  for (const [n, tag] of bursts) {
    const past = n >= limitOf(tag), label = `${n} (${past ? 'past' : 'under'} half of ${granted} bytes)`;
    const from = await o.mark();
    send(n, tag);
    const to = await o.mark();
    hold(150 + 100);
    const w = await o.collect(from, to, { gap: true, final: true });
    assert.deepEqual([w.coverage, w.reason, w.lookups.length], ['partial', 'dns-query-after-final-mark', 0], `${label} queued at the final mark`);
    // The wait read them, and each was counted in its socket's busy period: the next window holds them, and a burst past half
    // the granted buffer still reads as a possible drop. A loaded machine may still be reading them when the wait reaches its
    // cap, so the next window is taken once the stub has read every one the kernel kept.
    await readAll(() => readSince(to), n);
    const next = await o.collect(to, await o.mark(), { gap: true });
    if (next.coverage === 'complete') assert.equal(next.lookups.length, n, `${label}: complete only with every one recorded`);
    if (full) assert.equal(next.lookups.length, n, `${label} read after the mark`);
    if (past) assert.deepEqual([next.coverage, next.reason], ['partial', 'dns-possible-drop-query'], `${label} in one busy period`);
    else if (full) assert.deepEqual([next.coverage, next.reason], ['complete', null], `${label} in one busy period`);
  }
  // The drain, resumed in an I/O callback (the reply to a lookup was just read) right after a stall: before it says quiescent it
  // reads what was queued, where one turn would have looked before any fresh poll.
  const from = await o.mark();
  assert.notEqual(await udp(o, encodeQuery({ id: 2, labels: ['before', 'example'] })), null);
  send(500, 'd');
  hold(150 + 100);
  // Capped at LOAD_CAP_MS (it returns at quiet; by 3000 ms with PERF). The mark right after it (no poll between) is what the
  // stub had read when it said quiescent.
  const d = await o.drain({ capMs: LOAD_CAP_MS });
  const drained = await o.collect(from, await o.mark(), { gap: true });
  assert.equal(d.quiescent, true);
  perfBelow(d.waitedMs, 3000, 'the drain after the stall');
  if (full) assert.equal(drained.lookups.length, 501, 'every queued query read before the drain said quiescent');
  else assert.ok(drained.lookups.length > 1, `${drained.lookups.length} read before the drain said quiescent`);
});
