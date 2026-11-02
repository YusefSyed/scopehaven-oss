// SMTP sink (integrations/observers/smtp-sink.mjs): a loopback mail server that
// never relays. Every connection here goes to 127.0.0.1; recipient domains are
// names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { createServer } from 'node:http';
import { createSmtpSink } from './smtp-sink.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { validateSmtpConfig } from '../../src/smtp-rules.mjs';
import { runHttpAssessment, credentialReadiness } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { decideEffects, effectTrace, recomputeEffectTrace } from '../../src/http-effects.mjs';
import { createHash } from 'node:crypto';
import { digest } from '../../src/domain.mjs';
import { onFreePorts, watchingBinds } from './fixtures/free-port.mjs';
import { buildObservers } from './factory.mjs';

const EXT = 'customers.example', INT = 'acme.example', WITNESS = 'witness.scopehaven.invalid';
// The port is a placeholder for configuration-only tests; a sink that listens gets a free one (fixtures/free-port.mjs).
const config = extra => ({ port: 47000, routing: 'smtp-host', domains: [{ domain: EXT, addresses: [`vip@${EXT}`] }, { domain: INT }],
  witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: WITNESS }, witnessWaitMs: 1500, quietMs: 150, ...extra });
function sink(t, extra = {}, options = {}) {
  return onFreePorts(1, async port => {
    const o = createSmtpSink({ instanceId: 'smtp-sink-mail', ...options, ...config({ port, ...extra }) });
    await o.start(); t.after(() => o.stop());
    return o;
  });
}
// A scripted SMTP client: each step is a line to send (or a raw chunk), answered by one reply.
function session(port) {
  const socket = connect(port, '127.0.0.1');
  let buf = '', waiting = null;
  const take = () => { const m = /(?:^|\n)(\d{3}) [^\n]*\r\n/.exec(buf); if (!m || !waiting) return; const end = m.index + m[0].length; const text = buf.slice(0, end); buf = buf.slice(end); const w = waiting; waiting = null; w(text); };
  socket.on('data', d => { buf += d; take(); });
  socket.on('error', () => {});
  const reply = () => new Promise(resolve => { waiting = resolve; take(); socket.once('close', () => { if (waiting === resolve) { waiting = null; resolve(''); } }); });
  const greeting = reply();
  return {
    greeting,
    async send(line) { socket.write(`${line}\r\n`); return reply(); },
    async raw(chunk) { socket.write(chunk); },
    close() { socket.destroy(); },
    closed: new Promise(resolve => socket.once('close', resolve)),
  };
}
async function mail(o, { to, from = 'app@acme.example', body = 'Subject: hello\r\n\r\nhi', auth } = {}) {
  const s = session(o.port); await s.greeting;
  await s.send('EHLO app.local');
  if (auth) await s.send(auth);
  await s.send(`MAIL FROM:<${from}>`);
  for (const rcpt of [].concat(to)) await s.send(`RCPT TO:<${rcpt}>`);
  await s.send('DATA');
  const done = await s.send(`${body}\r\n.`);
  await s.send('QUIT'); s.close();
  return done;
}
const witness = (o, from, nonce = from.witnessNonce) => mail(o, { to: `${nonce}@${WITNESS}`, body: 'Subject: scopehaven witness\r\n\r\nw' });
async function window(o, between, { withWitness = true, nonce } = {}) {
  const from = await o.mark();
  await between();
  o.markWitnessRequest(from);
  if (withWitness) await witness(o, from, nonce);
  return collectWindow(o, from, await o.mark());
}
const none = select => ({ kind: 'effect.none', select: { source: 'smtp-capture', operation: 'send', ...select } });

test('smtp: a forbidden mail is caught by recipient domain and declared address; a clean window with its witness proves absence', async t => {
  const o = await sink(t);
  const sent = await window(o, async () => assert.match(await mail(o, { to: [`vip@${EXT}`, `someone@${EXT}`] }), /^250 /));
  assert.deepEqual([sent.coverage, sent.reason], ['complete', null]);
  assert.deepEqual(sent.events.map(e => [e.operation, e.name, e.resource, e.outcome]), [['send', EXT, `vip@${EXT}`, 'committed'], ['send', EXT, '*', 'committed']]);
  assert.equal(evaluateEffectAssertion(none({ name: EXT }), [sent]).verdict, 'fail');
  assert.equal(evaluateEffectAssertion(none({ name: INT }), [sent]).verdict, 'pass');
  const clean = await window(o, async () => {});
  assert.deepEqual([clean.coverage, clean.events.length], ['complete', 0]);
  assert.equal(evaluateEffectAssertion(none({ name: EXT }), [clean]).verdict, 'pass');
});

test('smtp: without this window\'s witness message, absence is never claimed (missing, foreign, duplicate, nonce-less)', async t => {
  const o = await sink(t);
  const silent = await window(o, async () => {}, { withWitness: false });
  assert.deepEqual([silent.coverage, silent.reason], ['partial', 'smtp-witness-not-received']);
  assert.equal(evaluateEffectAssertion(none({ name: EXT }), [silent]).verdict, 'missing');
  const foreign = await window(o, async () => {}, { nonce: '00000000-0000-4000-8000-000000000000' });
  assert.match(foreign.reason, /smtp-foreign-witness/);
  const bare = await window(o, async () => {}, { nonce: 'no-nonce-here' });
  assert.match(bare.reason, /smtp-foreign-witness/);
  const from = await o.mark(); o.markWitnessRequest(from); await witness(o, from); await witness(o, from);
  assert.match((await collectWindow(o, from, await o.mark())).reason, /smtp-duplicate-witness/);
});

test('smtp: a message started after the witness request was sent is never an effect, and the window is partial', async t => {
  const o = await sink(t);
  const from = await o.mark(); o.markWitnessRequest(from);
  await mail(o, { to: `x@${EXT}` }); await witness(o, from);
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.events.length, 0); assert.match(w.reason, /smtp-message-after-witness-request/);
  assert.notEqual(evaluateEffectAssertion(none({ name: EXT }), [w]).verdict, 'pass');
});

test('smtp: a witness message that also goes to another recipient is never a witness, and that recipient is never hidden', async t => {
  const o = await sink(t);
  // As the connector runs it, the witness request is marked first: the mixed message is after it, so it is not attributed.
  const from = await o.mark(); o.markWitnessRequest(from);
  await mail(o, { to: [`${from.witnessNonce}@${WITNESS}`, `leak@${EXT}`] });
  const w = await collectWindow(o, from, await o.mark());
  assert.match(w.reason, /smtp-message-after-witness-request/); assert.match(w.reason, /smtp-witness-not-received/);
  assert.notEqual(evaluateEffectAssertion(none({ name: EXT }), [w]).verdict, 'pass');
  // Without that mark, the mixed message is flagged and its other recipient is still an event.
  const a = await o.mark();
  await mail(o, { to: [`${a.witnessNonce}@${WITNESS}`, `leak@${EXT}`] });
  const mixed = await collectWindow(o, a, await o.mark());
  assert.match(mixed.reason, /smtp-witness-mixed/);
  assert.equal(evaluateEffectAssertion(none({ name: EXT }), [mixed]).verdict, 'fail');
});

test('smtp: an over-limit message, a cut-off transaction and one still open at collect are gaps, never committed', async t => {
  const o = await sink(t, { maxMessageBytes: 1024 });
  const big = await window(o, async () => assert.match(await mail(o, { to: `a@${EXT}`, body: `Subject: big\r\n\r\n${'x'.repeat(4000)}` }), /^552 /));
  assert.match(big.reason, /smtp-message-over-limit/); assert.deepEqual(big.events.map(e => e.outcome), ['unknown']);
  const cut = await window(o, async () => { const s = session(o.port); await s.greeting; await s.send('HELO a'); await s.send(`MAIL FROM:<a@${INT}>`); await s.send(`RCPT TO:<b@${EXT}>`); await s.send('DATA'); await s.raw('Subject: half\r\n'); s.close(); await s.closed; });
  assert.match(cut.reason, /smtp-message-incomplete/); assert.ok(cut.events.every(e => e.outcome !== 'committed'));
  assert.notEqual(evaluateEffectAssertion(none({ name: EXT }), [cut]).verdict, 'pass');
  const s = session(o.port); await s.greeting;
  const from = await o.mark();
  await s.send('HELO a'); await s.send(`MAIL FROM:<a@${INT}>`); await s.send(`RCPT TO:<c@${EXT}>`); await s.send('DATA'); await s.raw('Subject: pending\r\n');
  o.markWitnessRequest(from); await witness(o, from);
  const open = await collectWindow(o, from, await o.mark());
  s.close();
  assert.match(open.reason, /smtp-message-in-flight/);
});

test('smtp: RSET before DATA sends nothing; dot-stuffed lines never end a message early', async t => {
  const o = await sink(t);
  const reset = await window(o, async () => { const s = session(o.port); await s.greeting; await s.send('HELO a'); await s.send(`MAIL FROM:<a@${INT}>`); await s.send(`RCPT TO:<b@${EXT}>`); assert.match(await s.send('RSET'), /^250 /); await s.send('QUIT'); s.close(); });
  assert.deepEqual([reset.coverage, reset.events.length], ['complete', 0]);
  const stuffed = await window(o, async () => assert.match(await mail(o, { to: `d@${EXT}`, body: 'Subject: dots\r\n\r\nline\r\n..\r\n...more\r\nend' }), /^250 /));
  assert.deepEqual([stuffed.coverage, stuffed.events.length], ['complete', 1]);
});

test('smtp: malformed and unrecognized commands, too many recipients and dropped connections leave the window partial', async t => {
  const o = await sink(t);
  const odd = await window(o, async () => { const s = session(o.port); await s.greeting; assert.match(await s.send('GET / HTTP/1.1'), /^502 /); s.close(); });
  assert.match(odd.reason, /smtp-unrecognized-message/); assert.notEqual(evaluateEffectAssertion(none({ name: EXT }), [odd]).verdict, 'pass');
  const bad = await window(o, async () => { const s = session(o.port); await s.greeting; await s.send('HELO a'); assert.match(await s.send('MAIL FROM:not-an-address'), /^501 /); s.close(); });
  assert.match(bad.reason, /smtp-malformed-message/);
  const many = await window(o, async () => { const s = session(o.port); await s.greeting; await s.send('HELO a'); await s.send(`MAIL FROM:<a@${INT}>`);
    for (let i = 0; i < 101; i++) await s.send(`RCPT TO:<r${i}@${EXT}>`); await s.send('DATA'); await s.send('Subject: many\r\n\r\nx\r\n.'); await s.send('QUIT'); s.close(); });
  assert.match(many.reason, /smtp-too-many-recipients/); assert.equal(many.events.length, 100);
});

test('smtp: AUTH is accepted and nothing of it, the addresses, subject or body is stored', async t => {
  const o = await sink(t);
  const secret = Buffer.from('\u0000app\u0000hunter2-smtp-secret').toString('base64');
  const w = await window(o, async () => assert.match(await mail(o, { to: `private.person@${EXT}`, auth: `AUTH PLAIN ${secret}`, body: 'Subject: Quarterly secret plan\r\n\r\nbody-text-should-not-appear' }), /^250 /));
  assert.equal(w.events.length, 1); assert.equal(w.events[0].resource, '*');
  for (const needle of [secret, 'hunter2', 'private.person', 'Quarterly secret plan', 'body-text-should-not-appear']) assert.doesNotMatch(JSON.stringify(w), new RegExp(needle.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')), needle);
  const s = session(o.port); await s.greeting; await s.send('EHLO a');
  assert.match(await s.send('AUTH LOGIN'), /^334 VXNlcm5hbWU6/); assert.match(await s.send('dXNlcg=='), /^334 UGFzc3dvcmQ6/); assert.match(await s.send('cGFzcw=='), /^235 /);
  assert.match(await s.send('STARTTLS'), /^454 /); s.close();
});

test('smtp: recipient domains are normalized (case, trailing dot)', async t => {
  const o = await sink(t);
  const w = await window(o, () => mail(o, { to: `VIP@Customers.Example.` }));
  assert.deepEqual(w.events.map(e => [e.name, e.resource]), [[EXT, `vip@${EXT}`]]);
});

test('smtp: without declared routing the sink is presence-only', async t => {
  const o = await sink(t, { routing: undefined, witness: undefined });
  assert.equal(o.scope.evidence, 'presence-only'); assert.equal(o.witnessRequest, undefined);
  const from = await o.mark(); await mail(o, { to: `x@${EXT}` });
  assert.equal(evaluateEffectAssertion(none({ name: EXT }), [await collectWindow(o, from, await o.mark())]).verdict, 'fail');
  const a = await o.mark();
  assert.equal(evaluateEffectAssertion(none({ name: EXT }), [await collectWindow(o, a, await o.mark())]).verdict, 'unobservable');
});

test('smtp: a listener that went down after the end mark fails the window; evicted records fail; a late collect is partial', async t => {
  const o = await sink(t);
  const from = await o.mark(); o.markWitnessRequest(from); await witness(o, from); const to = await o.mark();
  await o.stop();
  assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await collectWindow(o, from, to)), ['failed', 'smtp-listener-down']);
  const small = await sink(t, {}, { retainedMessages: 2 });
  const a = await small.mark();
  for (let i = 0; i < 3; i++) await mail(small, { to: `n${i}@${INT}` });
  small.markWitnessRequest(a); await witness(small, a);
  assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await collectWindow(small, a, await small.mark())), ['failed', 'smtp-records-evicted']);
  const p = await sink(t);
  const b = await p.mark(); p.markWitnessRequest(b); await witness(p, b); const c = await p.mark();
  await new Promise(r => setTimeout(r, 400)); await mail(p, { to: `late@${INT}` });
  assert.match((await collectWindow(p, b, c)).reason, /smtp-collect-late/);
});

test('smtp: a sink restarted between the marks fails the window (its earlier records belong to another listener)', async t => {
  // The restart binds the same port again; if another process took it in between, the test runs again on a new port.
  await onFreePorts(1, async port => {
    const o = createSmtpSink({ instanceId: 'smtp-sink-mail', ...config({ port }) });
    await o.start(); t.after(() => o.stop());
    const from = await o.mark();
    await o.stop(); await o.start();
    o.markWitnessRequest(from); await witness(o, from);
    assert.deepEqual((({ coverage, reason }) => [coverage, reason])(await collectWindow(o, from, await o.mark())), ['failed', 'smtp-listener-down']);
  });
});

test('an SMTPUTF8 recipient is compared by its A-label, a source route is dropped, and bytes that are not UTF-8 are malformed', async t => {
  const IDN = 'xn--bcher-kva.example';
  const o = await sink(t, { domains: [{ domain: IDN, addresses: [`vip@${IDN}`] }, { domain: EXT, addresses: [`vip@${EXT}`] }] });
  // The U-label form of a declared domain.
  const idn = await window(o, () => mail(o, { to: 'vip@bücher.example' }));
  assert.deepEqual([idn.coverage, idn.events.map(e => `${e.name} ${e.resource}`)], ['complete', [`${IDN} vip@${IDN}`]]);
  assert.equal(evaluateEffectAssertion(none({ name: IDN }), [idn]).verdict, 'fail');
  // A source-routed recipient is the mailbox after the route.
  const routed = await window(o, () => mail(o, { to: `@relay.example,@other.example:vip@${EXT}` }));
  assert.deepEqual(routed.events.map(e => `${e.name} ${e.resource}`), [`${EXT} vip@${EXT}`]);
  assert.equal(evaluateEffectAssertion(none({ name: EXT, resource: `vip@${EXT}` }), [routed]).verdict, 'fail');
  // A command that is not UTF-8.
  const bad = await window(o, async () => {
    const s = session(o.port); await s.greeting; await s.send('EHLO app.local');
    await s.raw(Buffer.concat([Buffer.from('RCPT TO:<vip@'), Buffer.from([0xff, 0xfe]), Buffer.from('.example>\r\n')])); await s.closed;
  });
  assert.equal(bad.coverage, 'partial'); assert.match(bad.reason, /smtp-malformed-message/);
});

test('a recipient at an address literal (IPv4 or IPv6) leaves the window partial; a named recipient does not', async t => {
  const o = await sink(t);
  for (const literal of ['[198.51.100.9]', '[IPv6:2001:db8::1]']) {
    const w = await window(o, () => mail(o, { to: `vip@${literal}` }));
    assert.deepEqual([w.coverage, w.reason], ['partial', 'smtp-address-literal'], literal);
    assert.notEqual(evaluateEffectAssertion(none({ name: EXT }), [w]).verdict, 'pass', literal);
  }
  const named = await window(o, () => mail(o, { to: `vip@${EXT}` }));
  assert.deepEqual([named.coverage, named.reason], ['complete', null]);
});

test('QUIT inside an open transaction sends nothing; a nonce in a mail to another domain is still a send; the body digest is of the unstuffed message', async t => {
  const o = await sink(t);
  const quit = await window(o, async () => { const s = session(o.port); await s.greeting; await s.send('EHLO a'); await s.send('MAIL FROM:<app@acme.example>'); await s.send(`RCPT TO:<vip@${EXT}>`); await s.send('QUIT'); await s.closed; });
  assert.deepEqual([quit.coverage, quit.reason, quit.events.map(e => e.outcome)], ['partial', 'smtp-message-incomplete', ['unknown']]);
  assert.notEqual(evaluateEffectAssertion(none({ name: EXT }), [quit]).verdict, 'pass');
  const from = await o.mark();
  await mail(o, { to: `${from.witnessNonce}@${EXT}` });
  o.markWitnessRequest(from); await witness(o, from);
  const carried = await collectWindow(o, from, await o.mark());
  assert.deepEqual([carried.coverage, carried.events.map(e => e.name)], ['complete', [EXT]]);
  assert.equal(evaluateEffectAssertion(none({ name: EXT }), [carried]).verdict, 'fail');
  // "..hidden" on the wire is the line ".hidden" (RFC 5321 dot-stuffing); the digest is of what the app sent.
  const stuffed = await window(o, () => mail(o, { to: `vip@${EXT}`, body: '..hidden' }));
  const sha = v => createHash('sha256').update(v).digest('hex');
  assert.equal(stuffed.events[0].contentDigest, digest({ from: sha('app@acme.example'), to: sha(`vip@${EXT}`), data: sha('.hidden\r\n'), bytes: 9 }));
});

test('smtp configuration: routing needs a witness, domains are plain, addresses belong to their domain', () => {
  const actors = { ops: {} }, base = { id: 'mail', type: 'smtp-sink', ...config() };
  validateSmtpConfig(base, actors);
  const reject = (edit, pattern) => { const o = structuredClone(base); edit(o); assert.throws(() => validateSmtpConfig(o, actors), pattern); };
  reject(o => { delete o.witness; }, /"routing" and "witness" go together/);
  reject(o => { o.routing = 'relay'; }, /"routing" must be "smtp-host"/);
  reject(o => { o.witness.domain = EXT; }, /not a destination/);
  reject(o => { o.witness.method = 'POST'; }, /witness must be a GET/);
  reject(o => { o.witness.actorId = 'nobody'; }, /declared actor/);
  reject(o => { o.domains = [{ domain: 'Customers.Example' }]; }, /lowercase domain/);
  reject(o => { o.domains = [{ domain: EXT, addresses: [`x@${INT}`] }]; }, /addresses/);
  reject(o => { o.domains = [{ domain: EXT }, { domain: EXT }]; }, /declared once/);
  reject(o => { o.port = 25; }, /"port" must be an integer from 1024/);
  reject(o => { o.relayTo = 'smtp.example'; }, /an smtp-sink observer is/);
});

// End to end: an app whose /notify route mails through its SMTP host (the sink) and whose /ping route mails the witness.
async function app(t, sinkPort, { leaks }) {
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    const port = { port: sinkPort };
    if (url.pathname === '/ping') { await mail(port, { to: `${url.searchParams.get('scopehaven_witness')}@${WITNESS}` }); return reply(200, { ok: true }); }
    if (url.pathname === '/notify') { await mail(port, { to: `team@${INT}` }); if (leaks) await mail(port, { to: `vip@${EXT}`, body: 'Subject: internal ticket\r\n\r\nsynthetic' }); return reply(200, { sent: true }); }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const profile = (origin, sinkPort) => ({ id: 'mail-app', name: 'Mail app', applicationId: 'mail-app', origin, buildLabel: 'b1', contextId: 'synthetic-mail',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'mail', type: 'smtp-sink', port: sinkPort, routing: 'smtp-host', domains: [{ domain: EXT }, { domain: INT }], witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: WITNESS }, settleMs: 250, quietMs: 150 }],
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
    { id: 'NO-EXTERNAL-MAIL', title: 'An internal notification never mails a customer', category: 'data-exfiltration', severity: 'high', actorId: 'ops', method: 'GET', path: '/notify', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: { source: 'smtp-capture', name: EXT, operation: 'send' } }, { kind: 'effect.exists', select: { source: 'smtp-capture', name: INT, operation: 'send' } }] },
  ] });
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
// The profile's sink binds its port when the run starts. Only a start that lost the port to another process
// (EADDRINUSE) is retried on a fresh port; a window that fails for any other reason stands.
const profileRun = (t, leaks, { shape = p => p, runEnv = env, build = buildObservers, attempts = [] } = {}) => onFreePorts(1, async port => {
  const p = shape(profile(await app(t, port, { leaks }), port)), watch = watchingBinds(build);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  attempts.push(port);
  return { p, run: await runHttpAssessment(p, { env: runEnv, observerFactory: watch.factory }), lostBind: watch.state.lostBind };
}, result => result.lostBind);
const inUse = () => Object.assign(new Error('listen EADDRINUSE'), { code: 'EADDRINUSE' });
// A product failure (every collect throws) and a sink whose first start loses its port.
const collectFails = (configs, options) => buildObservers(configs, options).map(o => Object.assign(o, { collect: async () => { throw new Error('synthetic collect failure'); } }));
const firstStartLoses = () => { let first = true; return (configs, options) => buildObservers(configs, options).map(o => { const start = o.start.bind(o); o.start = async () => { if (first) { first = false; throw inUse(); } return start(); }; return o; }); };

test('an SMTP sink witness actor with no check of its own needs its credential too', () => {
  const p = profile('http://127.0.0.1:4000', 47000);
  const asBob = { ...p, actors: { ...p.actors, bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } }, checks: p.checks.map(c => ({ ...c, actorId: 'bob' })) };
  assert.deepEqual(credentialReadiness(asBob, { SCOPEHAVEN_TARGET_BOB: 'synthetic-bob-token' }), { ready: false, missingCredentialRefs: ['SCOPEHAVEN_TARGET_OPS'] });
});

test('a profile run is retried only when a sink lost its port; a window that fails for another reason stands', async t => {
  const once = [];
  const { run } = await profileRun(t, false, { build: collectFails, attempts: once });
  assert.deepEqual([run.results.find(x => x.id === 'NO-EXTERNAL-MAIL').trace[1].data.windows[0].coverage, once.length], ['failed', 1]);
  const twice = [];
  const retried = await profileRun(t, false, { build: firstStartLoses(), attempts: twice });
  assert.deepEqual([retried.run.results.find(x => x.id === 'NO-EXTERNAL-MAIL').status, twice.length], ['pass', 2]);
});

test('smtp in a profile: a mail to a customer fails the check; a clean app passes with backend observed (end to end, suite-valid)', async t => {
  for (const [leaks, status] of [[true, 'fail'], [false, 'pass']]) {
    const { p, run } = await profileRun(t, leaks);
    const r = run.results.find(x => x.id === 'NO-EXTERNAL-MAIL'), w = r.trace[1].data.windows[0];
    assert.deepEqual([r.status, r.backendEvidence, w.coverage, w.lineage.observer, w.lineage.independence], [status, 'observed', 'complete', 'smtp-sink-recorder', 'request-path'], JSON.stringify({ reason: w.reason, a: r.assertions }));
    validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
    assert.ok(run.limitations.some(l => l.startsWith('SMTP sinks (mail: smtp-host routing')));
    // The addressing limit, pinned.
    assert.ok(run.limitations.find(l => l.startsWith('SMTP sinks (mail:')).includes('A recipient at an address literal leaves the window partial'));
  }
});

test('smtp: a sealed window is bound to its observer type (a relabelled source is refused on recompute)', async t => {
  const o = await sink(t);
  const w = await window(o, () => mail(o, { to: `x@${EXT}` }));
  const effects = [{ kind: 'effect.none', select: { name: EXT, operation: 'send' } }];
  const meta = new Map([[w.instanceId, { kind: 'smtp-sink-recorder', settleMs: 250 }]]), declared = [{ id: 'mail', type: 'smtp-sink', settleMs: 250 }];
  recomputeEffectTrace(effectTrace(decideEffects(effects, [w]), [w], meta), effects, declared);
  const forged = { ...structuredClone(w), source: 'http-egress' }; for (const e of forged.events) e.source = 'http-egress';
  assert.equal(decideEffects(effects, [forged])[0].verdict, decideEffects(effects, [w])[0].verdict);
  assert.throws(() => recomputeEffectTrace(effectTrace(decideEffects(effects, [forged]), [forged], meta), effects, declared), /effect-trace/);
});

test('smtp profiles: refused before any request when the configuration is unsound', () => {
  const reject = (edit, pattern) => { const p = profile('http://127.0.0.1:4000', 47000); edit(p.observers[0]); assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), pattern); };
  reject(o => { o.witness.actorId = 'ghost'; }, /declared actor/);
  reject(o => { delete o.routing; }, /"routing" and "witness" go together/);
});

test('smtp: a recipient written another way than a declared address never passes a pinned effect.none: unusable and alias forms read partial', async t => {
  const o = await sink(t);
  const pinned = none({ name: EXT, resource: `vip@${EXT}` });
  // A quoted, commented, escaped or non-ASCII local part is another written form of a mailbox; a second trailing dot on
  // the host could reach another name.
  for (const form of [`"vip"@${EXT}`, `vip(x)@${EXT}`, `v\\ip@${EXT}`, `vïp@${EXT}`, `Kvip@${EXT}`, `vip@${EXT}..`]) {
    const w = await window(o, () => mail(o, { to: form }));
    assert.equal(w.coverage, 'partial', form);
    assert.match(w.reason, /smtp-recipient-unusable/, form);
    assert.equal(w.events.length, 1, `${form} stays a send`);
    assert.equal(w.events[0].resource, '*', form);
    assert.equal(evaluateEffectAssertion(pinned, [w]).verdict, 'missing', form);
  }
  // A relay route ("%") names the relay's domain, never the declared one: it is unusable at any domain.
  const routed = await window(o, () => mail(o, { to: `vip%${EXT}@${INT}` }));
  assert.deepEqual([routed.coverage, routed.reason, routed.events.map(e => [e.name, e.resource])], ['partial', 'smtp-recipient-unusable', [[INT, '*']]]);
  assert.equal(evaluateEffectAssertion(none({ name: EXT }), [routed]).verdict, 'missing', 'a relay route to the declared domain is never absence there');
  // A "+" or "-" subaddress, the dotted form or a Proton-style form of a declared address may be the same mailbox.
  for (const form of [`vip+refund@${EXT}`, `vip-refund@${EXT}`, `v.ip@${EXT}`, `v_ip@${EXT}`]) {
    const w = await window(o, () => mail(o, { to: form }));
    assert.deepEqual([w.coverage, w.reason, w.events.map(e => [e.name, e.resource])], ['partial', 'smtp-recipient-ambiguous', [[EXT, '*']]], form);
    assert.equal(evaluateEffectAssertion(pinned, [w]).verdict, 'missing', form);
  }
  // Plain addresses are unchanged: the declared one in any case names itself, a different real address is a complete "*".
  const declared = await window(o, () => mail(o, { to: `VIP@Customers.Example` }));
  assert.deepEqual([declared.coverage, declared.events.map(e => e.resource)], ['complete', [`vip@${EXT}`]]);
  assert.equal(evaluateEffectAssertion(pinned, [declared]).verdict, 'fail');
  const other = await window(o, () => mail(o, { to: [`vipp@${EXT}`, `other+tag@${EXT}`] }));
  assert.deepEqual([other.coverage, other.reason, other.events.map(e => e.resource)], ['complete', null, ['*', '*']]);
  assert.equal(evaluateEffectAssertion(pinned, [other]).verdict, 'pass');
});

test('smtp: a recipient domain over 128 characters is unusable and never an event, never shortened into a declared domain', async t => {
  const LONG = `${'a'.repeat(63)}.${'b'.repeat(56)}.example`, LONGER = `${'c'.repeat(63)}.${'d'.repeat(63)}.${'e'.repeat(14)}.example`;
  assert.deepEqual([LONG.length, LONGER.length], [128, 150]);
  const o = await sink(t, { domains: [{ domain: LONG, addresses: [`vip@${LONG}`] }, { domain: INT }] });
  const exists = name => ({ kind: 'effect.exists', select: { source: 'smtp-capture', operation: 'send', name } });
  // An undeclared domain whose first 128 characters are a declared one: cut to 128 it read as a send to the declared domain.
  const evil = await window(o, () => mail(o, { to: `vip@${LONG}.evil` }));
  assert.deepEqual([evil.coverage, evil.reason, evil.events], ['partial', 'smtp-recipient-unusable', []]);
  assert.notEqual(evaluateEffectAssertion(exists(LONG), [evil]).verdict, 'pass', 'no send to the declared domain is shown');
  assert.equal(evaluateEffectAssertion(none({ name: LONG }), [evil]).verdict, 'missing');
  // A declared domain over 128 characters cannot be a window's scope name, so every window of such a sink fails (unchanged).
  const tooLong = await sink(t, { domains: [{ domain: LONGER }] });
  const failed = await window(tooLong, () => mail(tooLong, { to: `x@${LONGER}` }));
  assert.deepEqual([failed.coverage, failed.events], ['failed', []]);
  // Adjacent: a domain of exactly 128 characters is an event named by it, and the window is complete.
  const exact = await window(o, () => mail(o, { to: [`vip@${LONG}`, `ops@${INT}`] }));
  assert.deepEqual([exact.coverage, exact.reason, exact.events.map(e => [e.name, e.resource])], ['complete', null, [[LONG, `vip@${LONG}`], [INT, '*']]]);
  assert.equal(evaluateEffectAssertion(exists(LONG), [exact]).verdict, 'pass');
  // An over-long recipient beside the witness makes the message mixed, never a witness; the named recipient beside it stays an event.
  const a = await o.mark();
  await mail(o, { to: [`${a.witnessNonce}@${WITNESS}`, `x@${LONG}.evil`, `ops@${INT}`] });
  const mixed = await collectWindow(o, a, await o.mark());
  assert.match(mixed.reason, /smtp-witness-mixed/); assert.match(mixed.reason, /smtp-recipient-unusable/);
  assert.deepEqual(mixed.events.map(e => e.name), [INT]);
});

test('smtp: two declared addresses that alias each other are ambiguous: a send to either never passes a pin on the other', async t => {
  const o = await sink(t, { domains: [{ domain: EXT, addresses: [`vip@${EXT}`, `vip+refund@${EXT}`] }, { domain: INT }] });
  const w = await window(o, () => mail(o, { to: `vip+refund@${EXT}` }));
  assert.deepEqual([w.coverage, w.reason, w.events.map(e => e.resource)], ['partial', 'smtp-recipient-ambiguous', [`vip+refund@${EXT}`]]);
  assert.equal(evaluateEffectAssertion(none({ name: EXT, resource: `vip@${EXT}` }), [w]).verdict, 'missing');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.exists', select: { source: 'smtp-capture', operation: 'send', name: EXT, resource: `vip+refund@${EXT}` } }, [w]).verdict, 'pass');
  // A declared address that is not canonical is refused when the profile loads: it could never name itself.
  assert.throws(() => createSmtpSink({ ...config({ domains: [{ domain: EXT, addresses: [`v..ip@${EXT}`] }] }) }), /canonical/);
});
