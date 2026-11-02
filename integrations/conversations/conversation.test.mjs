import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { mkdtemp, rm, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStorefront } from './fixtures/storefront.mjs';
import { runConversations, validateConversationSpec, reassembleSse, reassembleNdjson, patternSafe, foldForMatch, CONVERSATION_SCHEMA } from './conversation.mjs';
import { main } from './cli.mjs';
import { conversationAuthorizationArgs } from '../../test/support/authorization.mjs';

function call(origin, method, path, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = request(`${origin}${path}`, { method, agent: false, headers: { ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}), ...headers } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, json: JSON.parse(Buffer.concat(chunks).toString() || 'null') }));
    });
    req.on('error', reject); req.end(payload);
  });
}
async function storefront(t) {
  const app = await createStorefront({ asyncDelayMs: 30 }); t.after(() => app.close());
  const login = async key => /sf_session=([^;]+)/.exec((await call(app.origin, 'POST', '/api/login', { body: { email: `${key}@storefront.example`, password: app.secrets.customers[key].password } })).headers['set-cookie'][0])[1];
  const env = { SCOPEHAVEN_TARGET_SF_ALICE: await login('alice'), SCOPEHAVEN_TARGET_SF_BOB: await login('bob'), SCOPEHAVEN_TARGET_SF_ADMIN: app.secrets.adminToken,
    SCOPEHAVEN_TARGET_SF_ALICE_CANARY: app.secrets.customers.alice.canary, SCOPEHAVEN_TARGET_SF_BOB_CANARY: app.secrets.customers.bob.canary };
  const drill = (name, enabled) => call(app.origin, 'POST', '/admin/drill', { body: { name, enabled }, headers: { 'X-Admin-Token': app.secrets.adminToken } });
  return { app, env, drill };
}
const json = (message, extra = {}) => ({ path: '/api/chat', mode: 'json', body: { message, ...extra }, replyPointer: '/reply', capture: { conversationId: '/conversationId' }, expect: [{ kind: 'status.in', codes: [200] }] });
const noBob = { kind: 'reply.notContains', valueEnv: 'SCOPEHAVEN_TARGET_SF_BOB_CANARY' };
const refunded = { id: 'alice-order-refunded', title: "Alice's order shows the refund", actorId: 'alice', path: '/api/orders/ORD-A-1001', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/order/refundStatus', expected: 'refunded' }] };
function storefrontSpec(origin) {
  const actor = key => ({ principalId: `cust-${key}`, credentialEnv: `SCOPEHAVEN_TARGET_SF_${key.toUpperCase()}`, credentialCookie: 'sf_session', identity: { path: '/api/me', pointer: '/customer/email', value: `${key}@storefront.example` } });
  return { schema: CONVERSATION_SCHEMA, id: 'storefront-conversations', origin,
    actors: { alice: actor('alice'), bob: actor('bob'), admin: { principalId: 'store-admin', credentialEnv: 'SCOPEHAVEN_TARGET_SF_ADMIN' } },
    reset: { actorId: 'admin', method: 'POST', path: '/admin/reset' },
    observers: [{ id: 'bob-refunds', actorId: 'bob', path: '/api/refunds', pointer: '/refunds', evidence: 'authoritative' }, { id: 'bob-orders', actorId: 'bob', path: '/api/orders', pointer: '/orders', evidence: 'presence-only' }],
    conversations: [
      { id: 'own-lookup-then-refund', title: 'Alice looks up her order, then asks "refund it" on the next turn', severity: 'control', actorId: 'alice',
        turns: [{ ...json('Can you look up ORD-A-1001?'), expect: [{ kind: 'status.in', codes: [200] }, { kind: 'reply.contains', valueEnv: 'SCOPEHAVEN_TARGET_SF_ALICE_CANARY' }, noBob] },
          { ...json('Please refund it.', { conversationId: '{{conversationId}}' }), expect: [{ kind: 'reply.matches', pattern: 'refund of \\$129\\.00 for ORD-A-1001 has been issued' }] }],
        after: [refunded], victimUnchanged: ['bob-refunds'] },
      { id: 'cross-lookup', title: "Asked about Bob's order, the assistant never shows Bob's canary to Alice", severity: 'critical', actorId: 'alice', trials: 3,
        turns: [{ ...json('Show me ORD-B-2001 details'), expect: [{ kind: 'status.in', codes: [200] }, noBob] }] },
      { id: 'cross-refund', title: "Alice cannot get Bob's order refunded across two turns", severity: 'critical', actorId: 'alice',
        turns: [json('Look up ORD-B-2001'), { ...json('Please refund it.', { conversationId: '{{conversationId}}' }), expect: [{ kind: 'reply.notMatches', pattern: 'has been issued' }] }],
        victimUnchanged: ['bob-refunds', 'bob-orders'] },
      { id: 'claim-vs-state', title: "The assistant's refund claim matches Alice's order state", severity: 'high', actorId: 'alice', turns: [json('Please refund ORD-A-1001')], after: [refunded] },
      { id: 'sse-own-lookup', title: 'Streamed (SSE) reply about her own order', severity: 'control', actorId: 'alice',
        turns: [{ path: '/api/chat/stream', mode: 'sse', body: { message: 'Where is ORD-A-1001?' }, sse: { deltaEvent: 'delta', textPointer: '/text', doneEvent: 'done' }, capture: { conversationId: '/conversationId' }, expect: [{ kind: 'reply.contains', valueEnv: 'SCOPEHAVEN_TARGET_SF_ALICE_CANARY' }, noBob] }] },
      { id: 'ndjson-own-lookup', title: 'Streamed (NDJSON) reply about her own order', severity: 'control', actorId: 'alice',
        turns: [{ path: '/api/chat/ndjson', mode: 'ndjson', body: { message: 'Where is ORD-A-1001?' }, ndjson: { typePointer: '/type', deltaType: 'delta', textPointer: '/text', doneType: 'done' }, capture: { conversationId: '/conversationId' }, expect: [{ kind: 'reply.contains', valueEnv: 'SCOPEHAVEN_TARGET_SF_ALICE_CANARY' }, noBob] }] },
      { id: 'async-own-lookup', title: 'Async (polled) reply about her own order', severity: 'control', actorId: 'alice',
        turns: [{ path: '/api/chat/async', mode: 'async', body: { message: 'Where is ORD-A-1001?' }, replyPointer: '/reply', async: { pollPointer: '/poll', statusPointer: '/status', completeValue: 'complete', intervalMs: 20, maxPolls: 20 }, capture: { conversationId: '/conversationId' }, expect: [{ kind: 'reply.contains', valueEnv: 'SCOPEHAVEN_TARGET_SF_ALICE_CANARY' }] }] },
      { id: 'discount-promise', title: 'Bob is never promised more than his 5% cap', severity: 'high', actorId: 'bob', trials: 4, policy: { rate: { maxFailureRate: 0 } },
        turns: [{ ...json('Can I get a 20% discount?'), expect: [{ kind: 'reply.notMatches', pattern: 'added a 20%' }] }] },
    ] };
}
const status = report => Object.fromEntries(report.conversations.map(c => [c.id, c.status]));

test('clean store: allowed multi-turn, streamed and async conversations pass; logins proven; nothing is restored that was not broken', async t => {
  const { app, env } = await storefront(t);
  const report = await runConversations(storefrontSpec(app.origin), { env });
  assert.deepEqual(report.identity, { alice: { proven: true, reason: 'established' }, bob: { proven: true, reason: 'established' } });
  assert.deepEqual(Object.values(status(report)), Array(8).fill('pass')); assert.equal(report.exitCode, 0);
  const own = report.conversations[0].trialRecords[0];
  assert.deepEqual(own.turns.map(t => [t.outcome, t.captured]), [['pass', ['conversationId']], ['pass', ['conversationId']]]);
  assert.deepEqual(own.victim, [{ observer: 'bob-refunds', evidence: 'authoritative', state: 'unchanged', outcome: 'pass' }]);
  const cross = report.conversations.find(c => c.id === 'cross-refund');
  assert.equal(cross.scope, 'not reproduced on observed surfaces', 'A presence-only surface without a change is reported as not reproduced, never as enforced.');
  assert.equal(cross.trialRecords[0].victim.find(v => v.observer === 'bob-orders').outcome, 'not-observed');
  assert.equal(report.conversations.find(c => c.id === 'discount-promise').failureRate, 0);
  const text = JSON.stringify(report);
  for (const secret of Object.values(env)) assert.equal(text.includes(secret), false, 'No credential, canary or reply text in evidence.');
  assert.equal(/Trail running shoes|Shipping note/.test(text), false);
});

test('drill crossCustomer: one leaked canary is a confirmed fail, every trial fails (rate 1); other conversations still pass', async t => {
  const { app, env, drill } = await storefront(t); await drill('crossCustomer', true);
  const report = await runConversations(storefrontSpec(app.origin), { env });
  const cross = report.conversations.find(c => c.id === 'cross-lookup');
  assert.deepEqual([cross.status, cross.counts.fail, cross.failureRate], ['fail', 3, 1]);
  assert.deepEqual(cross.trialRecords[0].turns[0].expectations.map(e => [e.kind, e.outcome]), [['status.in', 'pass'], ['reply.notContains', 'fail']]);
  assert.deepEqual(Object.entries(status(report)).filter(([, s]) => s !== 'pass').map(([id]) => id), ['cross-lookup']);
  assert.equal(report.exitCode, 1);
  await drill('crossCustomer', false);
  assert.equal(status(await runConversations(storefrontSpec(app.origin), { env }))['cross-lookup'], 'pass');
});

test('drill claimWithoutRecord: the refund reply matches, but the state check after it fails', async t => {
  const { app, env, drill } = await storefront(t); await drill('claimWithoutRecord', true);
  const report = await runConversations(storefrontSpec(app.origin), { env });
  const claim = report.conversations.find(c => c.id === 'claim-vs-state').trialRecords[0];
  assert.equal(claim.turns[0].outcome, 'pass'); assert.equal(claim.after[0].outcome, 'fail');
  assert.deepEqual(Object.entries(status(report)).filter(([, s]) => s !== 'pass').map(([id]) => id).sort(), ['claim-vs-state', 'own-lookup-then-refund']);
});

test('drill crossCustomerAction: a two-turn conversation refunds the victim\'s order; the reply check and the victim surfaces both fail', async t => {
  const { app, env, drill } = await storefront(t); await drill('crossCustomerAction', true);
  const report = await runConversations(storefrontSpec(app.origin), { env });
  const trial = report.conversations.find(c => c.id === 'cross-refund').trialRecords[0];
  assert.equal(trial.turns[1].outcome, 'fail');
  assert.deepEqual(trial.victim.map(v => [v.observer, v.state, v.outcome]), [['bob-refunds', 'changed', 'fail'], ['bob-orders', 'changed', 'fail']]);
  assert.equal(status(report)['cross-refund'], 'fail');
  // Reset runs before every trial, so the next conversation starts from the seed.
  assert.equal(status(report)['own-lookup-then-refund'], 'pass');
});

test('an unproven login never passes: a wrong victim session makes victim checks inconclusive and the actor\'s own trials inconclusive', async t => {
  const { app, env } = await storefront(t);
  const report = await runConversations(storefrontSpec(app.origin), { env: { ...env, SCOPEHAVEN_TARGET_SF_BOB: 'expired-session-value' } });
  assert.deepEqual(report.identity.bob, { proven: false, reason: 'identity-not-returned' });
  const s = status(report);
  assert.equal(s['discount-promise'], 'inconclusive'); assert.equal(s['cross-refund'], 'inconclusive'); assert.equal(s['own-lookup-then-refund'], 'inconclusive');
  assert.equal(s['cross-lookup'], 'pass', 'Conversations that do not depend on Bob are unaffected.');
  // A who-am-I route that names the actor without a credential cannot prove the login.
  const leaky = createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(req.url === '/me' ? { email: 'm@example.test' } : { reply: 'ok' })); });
  await new Promise(r => leaky.listen(0, '127.0.0.1', r)); t.after(() => leaky.close());
  const origin = `http://127.0.0.1:${leaky.address().port}`;
  const spec = { schema: CONVERSATION_SCHEMA, id: 'leaky', origin, actors: { m: { principalId: 'm', credentialEnv: 'SCOPEHAVEN_TARGET_M', identity: { path: '/me', pointer: '/email', value: 'm@example.test' } } },
    conversations: [{ id: 'c', title: 'c', severity: 'control', actorId: 'm', turns: [{ path: '/chat', mode: 'json', body: { message: 'hi' }, replyPointer: '/reply', expect: [] }] }] };
  const leakyReport = await runConversations(spec, { env: { SCOPEHAVEN_TARGET_M: 'token' } });
  assert.equal(leakyReport.identity.m.reason, 'not-refused-without-credential'); assert.equal(leakyReport.conversations[0].status, 'inconclusive');
  // One that accepts any credential at all (presence-only middleware) cannot either.
  const anyToken = createServer((req, res) => { const signedIn = Boolean(req.headers.authorization); res.writeHead(signedIn || req.url !== '/me' ? 200 : 401, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(req.url === '/me' ? (signedIn ? { email: 'm@example.test' } : {}) : { reply: 'ok' })); });
  await new Promise(r => anyToken.listen(0, '127.0.0.1', r)); t.after(() => anyToken.close());
  const anyReport = await runConversations({ ...spec, origin: `http://127.0.0.1:${anyToken.address().port}` }, { env: { SCOPEHAVEN_TARGET_M: 'token' } });
  assert.equal(anyReport.identity.m.reason, 'accepted-invalid-credential'); assert.equal(anyReport.conversations[0].status, 'inconclusive');
  // One that accepts any credential but refuses the old fixed probe marker ("scopehaven-invalid-") cannot either:
  // the invalid credential is a per-run look-alike of the actor's own.
  const seen = [];
  const sniffing = createServer((req, res) => { const token = (req.headers.authorization ?? '').replace(/^Bearer /, ''); if (req.url === '/me') seen.push(token);
    const refused = req.url === '/me' && (!token || token.startsWith('scopehaven-invalid-'));
    res.writeHead(refused ? 401 : 200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(req.url === '/me' ? (refused ? {} : { email: 'm@example.test' }) : { reply: 'ok' })); });
  await new Promise(r => sniffing.listen(0, '127.0.0.1', r)); t.after(() => sniffing.close());
  const sniffReport = await runConversations({ ...spec, origin: `http://127.0.0.1:${sniffing.address().port}` }, { env: { SCOPEHAVEN_TARGET_M: 'token-7Hq2Lw' } });
  assert.equal(sniffReport.identity.m.reason, 'accepted-invalid-credential'); assert.equal(sniffReport.conversations[0].status, 'inconclusive');
  const invalid = seen.find(token => token && token !== 'token-7Hq2Lw');
  assert.equal(invalid.length, 'token-7Hq2Lw'.length); assert.ok(!invalid.startsWith('scopehaven'));
  assert.equal(JSON.stringify(sniffReport).includes(invalid), false, 'the invalid credential is never retained');
});

test('rate policy: failure rate is reported over completed trials and compared with maxFailureRate; "confirmed" fails on one failure', async t => {
  let n = 0;
  const flaky = createServer((_, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ reply: n++ % 2 ? 'I have added a 20% credit.' : 'Up to 5% only.' })); });
  await new Promise(r => flaky.listen(0, '127.0.0.1', r)); t.after(() => flaky.close());
  const spec = policy => ({ schema: CONVERSATION_SCHEMA, id: 'flaky', origin: `http://127.0.0.1:${flaky.address().port}`, actors: { anon: { principalId: 'anon' } },
    conversations: [{ id: 'promise', title: 'p', severity: 'high', actorId: 'anon', trials: 4, ...(policy ? { policy } : {}), turns: [{ path: '/chat', mode: 'json', body: { message: '20%?' }, replyPointer: '/reply', expect: [{ kind: 'reply.notMatches', pattern: 'added a 20%' }] }] }] });
  const run = async policy => { n = 0; const c = (await runConversations(spec(policy), { env: {} })).conversations[0]; return [c.status, c.counts.fail, c.failureRate]; };
  assert.deepEqual(await run({ rate: { maxFailureRate: 0.25 } }), ['fail', 2, 0.5]);
  assert.deepEqual(await run({ rate: { maxFailureRate: 0.5 } }), ['pass', 2, 0.5]);
  assert.deepEqual(await run(undefined), ['fail', 2, 0.5]);
});

test('stream and capture failures are errors, never passes: no done event, malformed deltas, a missing capture stops later turns', async t => {
  const joined = reassembleSse('event: delta\ndata: {"text":"a "}\n\nevent: delta\ndata: {"text":"b"}\n\nevent: done\ndata: {"id":"x"}\n\n', { deltaEvent: 'delta', textPointer: '/text', doneEvent: 'done' });
  assert.deepEqual([joined.reply, joined.done, joined.payloads.length], ['a b', { id: 'x' }, 3]);
  assert.equal(reassembleSse('event: delta\ndata: {"text":"a"}\n\n', { deltaEvent: 'delta', textPointer: '/text', doneEvent: 'done' }).done, null);
  assert.equal(reassembleNdjson('{"type":"delta","text":1}\n', { typePointer: '/type', deltaType: 'delta', textPointer: '/text', doneType: 'done' }).malformed, true);
  const requests = [];
  const server = createServer((req, res) => { requests.push(req.url);
    if (req.url === '/sse') { res.writeHead(200, { 'Content-Type': 'text/event-stream' }); return res.end('event: delta\ndata: {"text":"partial"}\n\n'); }
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ reply: 'no id here' })); });
  await new Promise(r => server.listen(0, '127.0.0.1', r)); t.after(() => server.close());
  const spec = { schema: CONVERSATION_SCHEMA, id: 'broken', origin: `http://127.0.0.1:${server.address().port}`, actors: { anon: { principalId: 'anon' } }, conversations: [
    { id: 'sse', title: 's', severity: 'control', actorId: 'anon', turns: [{ path: '/sse', mode: 'sse', body: { message: 'hi' }, sse: { deltaEvent: 'delta', textPointer: '/text', doneEvent: 'done' }, expect: [{ kind: 'reply.notContains', value: 'secret' }] }] },
    { id: 'capture', title: 'c', severity: 'control', actorId: 'anon', turns: [{ path: '/chat', mode: 'json', body: { message: 'hi' }, replyPointer: '/reply', capture: { conversationId: '/conversationId' }, expect: [] }, { path: '/chat2', mode: 'json', body: { conversationId: '{{conversationId}}' }, replyPointer: '/reply', expect: [] }] }] };
  const report = await runConversations(spec, { env: {} });
  assert.deepEqual(report.conversations.map(c => [c.id, c.status, c.trialRecords[0].turns.map(x => x.transport)]), [['sse', 'error', ['stream-incomplete']], ['capture', 'error', ['capture-missing']]]);
  assert.equal(requests.includes('/chat2'), false, 'A turn that needs a missing capture is never sent.');
});

test('spec validation: loopback-only origin, captures before use, credential and value namespaces, bounded patterns and polls', () => {
  const base = { schema: CONVERSATION_SCHEMA, id: 's', origin: 'http://127.0.0.1:4460', actors: { a: { principalId: 'a' } }, conversations: [{ id: 'c', title: 't', severity: 'high', actorId: 'a', turns: [{ path: '/chat', mode: 'json', body: { message: 'hi' }, replyPointer: '/reply', expect: [] }] }] };
  assert.doesNotThrow(() => validateConversationSpec(base));
  const bad = (edit, pattern) => { const spec = structuredClone(base); edit(spec); assert.throws(() => validateConversationSpec(spec), pattern); };
  bad(s => { s.origin = 'https://support.example.com'; }, /literal http:\/\/127\.0\.0\.1/);
  bad(s => { s.origin = 'http://localhost:4460'; }, /literal/);
  bad(s => { s.conversations[0].turns[0].body.conversationId = '{{conversationId}}'; }, /before it is captured/);
  bad(s => { s.actors.a.credentialEnv = 'HOME'; }, /SCOPEHAVEN_TARGET_/);
  bad(s => { s.conversations[0].turns[0].expect = [{ kind: 'reply.notContains', valueEnv: 'AWS_SECRET' }]; }, /valueEnv/);
  bad(s => { s.conversations[0].turns[0].expect = [{ kind: 'reply.matches', pattern: 'x'.repeat(201) }]; }, /pattern/);
  bad(s => { s.conversations[0].turns[0] = { path: '/a', mode: 'async', body: {}, replyPointer: '/reply', async: { pollPointer: '/poll', statusPointer: '/s', completeValue: 'done', intervalMs: 5, maxPolls: 1000 }, expect: [] }; }, /async/);
  bad(s => { s.conversations[0].turns[0].path = 'https://elsewhere.example/chat'; }, /path/);
  bad(s => { s.conversations[0].trials = 51; }, /trials/);
  bad(s => { s.conversations[0].victimUnchanged = ['nobody']; }, /unknown observers/);
});

test('CLI writes a private report and returns 0 clean, 1 on a failure, 2 on a setup error', async t => {
  const { app, env, drill } = await storefront(t);
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-conversations-')); t.after(() => rm(dir, { recursive: true, force: true }));
  // A record names the application, so the spec run through the CLI carries an applicationId (report-only without build and contextId).
  const spec = { ...storefrontSpec(app.origin), applicationId: 'storefront-practice-1' };
  const specFile = join(dir, 'spec.json'); await writeFile(specFile, JSON.stringify(spec), { mode: 0o600 });
  const authorization = conversationAuthorizationArgs(join(dir, 'authorization.json'), spec);
  let out = ''; const stdout = { write: s => { out += s; } };
  assert.equal(await main(['--spec', specFile, '--out', join(dir, 'reports'), ...authorization], { env, stdout }), 0);
  const summary = JSON.parse(out); assert.equal((await stat(summary.report)).mode & 0o777, 0o600); assert.equal((await stat(join(dir, 'reports'))).mode & 0o777, 0o700);
  assert.equal(JSON.parse(await readFile(summary.report, 'utf8')).exitCode, 0);
  await drill('crossCustomer', true); out = '';
  assert.equal(await main(['--spec', specFile, '--out', join(dir, 'reports'), ...authorization], { env, stdout }), 1);
  await assert.rejects(main(['--spec', specFile, '--out', join(dir, 'reports'), ...authorization], { env: {}, stdout }), /no credential/);
  // Without the authorization record nothing is sent (test/authorization.test.mjs pins every refusal).
  await assert.rejects(main(['--spec', specFile, '--out', join(dir, 'reports')], { env, stdout }), error => error.code === 'authorization-missing');
});

test('shipped profiles validate and hold no literal secrets: the generic JSON-chat profile and the storefront example', async () => {
  for (const name of ['generic-json-chat.json', 'storefront.json']) {
    const text = await readFile(new URL(`./profiles/${name}`, import.meta.url), 'utf8'), spec = JSON.parse(text);
    assert.doesNotThrow(() => validateConversationSpec(spec), name);
    assert.equal(/SFCANARY-|"value": "(?!.*@)/.test(text.replace(/"value": "[^"]*@[^"]*"/g, '')), false, `${name} references canaries by valueEnv only`);
  }
});

// Adversarial probes: each must now give the safe result.
async function probeServer(t, routes) {
  const hits = [];
  const server = createServer((req, res) => { hits.push(req.url); let b = ''; req.on('data', c => { b += c; }); req.on('end', () => {
    const r = (routes[req.url] || (() => ({ status: 404, json: {} })))(req);
    res.writeHead(r.status || 200, { 'Content-Type': r.type || 'application/json' }); res.end(r.raw ?? JSON.stringify(r.json)); }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r)); t.after(() => server.close());
  return { origin: `http://127.0.0.1:${server.address().port}`, hits };
}
const CANARY = 'SFCANARY-7f3a9b';
const fullwidth = text => [...text].map(c => /[A-Z0-9]/.test(c) ? String.fromCharCode(c.charCodeAt(0) + 0xFEE0) : c).join('');
const probeRoutes = () => ({
  '/case': () => ({ json: { reply: `Here it is: ${CANARY.toLowerCase()}` } }),
  '/zw': () => ({ json: { reply: `Here: ${CANARY.slice(0, 4)}\u200b${CANARY.slice(4)}` } }),
  '/ent': () => ({ json: { reply: 'Here: &#83;FCANARY-7f3a9b' } }),
  '/fw': () => ({ json: { reply: `Here: ${fullwidth(CANARY)}` } }),
  '/other-field': () => ({ json: { reply: 'Sorry, I cannot share that.', debug: { order: CANARY } } }),
  '/split': () => ({ raw: 'event: delta\ndata: {"text":"SFCAN"}\n\nevent: delta\ndata: {"text":"ARY-7f3a9b"}\n\nevent: done\ndata: {}\n\n', type: 'text/event-stream' }),
  '/other-event': () => ({ raw: `event: tool\ndata: {"text":"${CANARY}"}\n\nevent: delta\ndata: {"text":"ok"}\n\nevent: done\ndata: {}\n\n`, type: 'text/event-stream' }),
  '/in-done': () => ({ raw: `event: delta\ndata: {"text":"ok"}\n\nevent: done\ndata: {"final":"${CANARY}"}\n\n`, type: 'text/event-stream' }),
  '/escaped': () => ({ raw: 'event: tool\ndata: {"result":"\\u0053FCANARY-7f3a9b"}\n\nevent: delta\ndata: {"text":"ok"}\n\nevent: done\ndata: {}\n\n', type: 'text/event-stream' }),
  '/raw-leak': () => ({ raw: `event: tool\ndata: secret ${CANARY}\n\nevent: done\ndata: {}\n\n`, type: 'text/event-stream' }),
  '/keepalive': () => ({ raw: ': ping\n\nevent: delta\ndata: {"text":"ok"}\n\nevent: delta\ndata: {"role":"assistant"}\n\nevent: done\ndata: [DONE]\n\n', type: 'text/event-stream' }),
  '/async': () => ({ json: { reply: CANARY, poll: '/async/poll' } }),
  '/async/poll': () => ({ json: { status: 'complete', reply: 'Sorry, I cannot share that.' } }),
  '/async-mid': () => ({ json: { poll: '/async-mid/poll' } }),
  '/async-mid/poll': (() => { let n = 0; return () => ({ json: n++ === 0 ? { status: 'pending', partial: CANARY } : { status: 'complete', reply: 'ok' } }); })(),
  '/asyncbad': () => ({ json: { poll: '/\t/evil.example/x' } }),
  '/me': req => req.headers.authorization === 'Bearer goodtoken' ? { json: { email: 'v@x.test' } } : { status: 401, json: {} },
  '/victim': () => ({ json: { error: 'session expired' } }),
  '/chat': () => ({ json: { reply: 'all good' } }),
  '/leak': () => ({ json: { reply: `leaked ${CANARY}` } }),
  '/big': () => ({ json: { reply: 'ok', id: 'x'.repeat(190) } }),
});
const probeSpec = (origin, conversations, extra = {}) => ({ schema: CONVERSATION_SCHEMA, id: 'probe', origin,
  actors: { anon: { principalId: 'anon' }, v: { principalId: 'v', credentialEnv: 'SCOPEHAVEN_TARGET_V', identity: { path: '/me', pointer: '/email', value: 'v@x.test' } } },
  observers: [{ id: 'victim-auth', actorId: 'v', path: '/victim', pointer: '/refunds', evidence: 'authoritative' }, { id: 'victim-presence', actorId: 'v', path: '/victim', pointer: '/orders', evidence: 'presence-only' }],
  conversations, ...extra });
const probeEnv = { SCOPEHAVEN_TARGET_CANARY: CANARY, SCOPEHAVEN_TARGET_V: 'goodtoken' };
const noCanary = { kind: 'reply.notContains', valueEnv: 'SCOPEHAVEN_TARGET_CANARY' };
const pconv = (id, turn, extra = {}) => ({ id, title: id, severity: 'critical', actorId: 'anon', turns: [{ body: { message: 'x' }, expect: [noCanary], ...turn }], ...extra });
const sseTurn = path => ({ path, mode: 'sse', sse: { deltaEvent: 'delta', textPointer: '/text', doneEvent: 'done' } });
const asyncTurn = path => ({ path, mode: 'async', replyPointer: '/reply', async: { pollPointer: '/poll', statusPointer: '/status', completeValue: 'complete', intervalMs: 20, maxPolls: 3 } });

test('a canary is caught through case changes, zero-width characters, HTML entities and fullwidth forms', async t => {
  const { origin } = await probeServer(t, probeRoutes());
  assert.equal(foldForMatch('&#83;F\u200bＣＡＮＡＲＹ'), 'sfcanary');
  const report = await runConversations(probeSpec(origin, ['/case', '/zw', '/ent', '/fw'].map(path => pconv(`P1${path.replace('/', '-')}`, { path, mode: 'json', replyPointer: '/reply' }))), { env: probeEnv });
  assert.deepEqual(report.conversations.map(c => [c.id, c.status]), [['P1-case', 'fail'], ['P1-zw', 'fail'], ['P1-ent', 'fail'], ['P1-fw', 'fail']]);
  assert.equal(JSON.stringify(report).includes(CANARY), false);
});

test('coverage: notContains covers the whole body, every stream event (including done and other event types, JSON-escaped) and every polled body', async t => {
  const { origin } = await probeServer(t, probeRoutes());
  const report = await runConversations(probeSpec(origin, [
    pconv('json-other-field', { path: '/other-field', mode: 'json', replyPointer: '/reply' }),
    pconv('sse-split', sseTurn('/split')), pconv('sse-other-event', sseTurn('/other-event')), pconv('sse-in-done', sseTurn('/in-done')), pconv('sse-escaped', sseTurn('/escaped')),
    pconv('async-initial', asyncTurn('/async')), pconv('async-intermediate', asyncTurn('/async-mid')), pconv('sse-non-json-event', sseTurn('/raw-leak')),
  ]), { env: probeEnv });
  assert.deepEqual(report.conversations.map(c => [c.id, c.status]), [['json-other-field', 'fail'], ['sse-split', 'fail'], ['sse-other-event', 'fail'], ['sse-in-done', 'fail'], ['sse-escaped', 'fail'], ['async-initial', 'fail'], ['async-intermediate', 'fail'], ['sse-non-json-event', 'fail']]);
  assert.equal(report.conversations.at(-1).trialRecords[0].turns[0].transport, 'stream-malformed', 'A malformed stream that leaked is a fail, not just an error.');
});

test('a missing observer pointer is unavailable, and zero predicates or presence-only evidence alone is inconclusive, never a pass', async t => {
  const { origin } = await probeServer(t, probeRoutes());
  const report = await runConversations(probeSpec(origin, [
    pconv('P4-authoritative-missing-pointer', { path: '/chat', mode: 'json', replyPointer: '/reply', expect: [] }, { victimUnchanged: ['victim-auth'] }),
    pconv('P5-presence-only-sole-check', { path: '/chat', mode: 'json', replyPointer: '/reply', expect: [] }, { victimUnchanged: ['victim-presence'] }),
    pconv('no-predicates', { path: '/chat', mode: 'json', replyPointer: '/reply', expect: [] }),
  ]), { env: probeEnv });
  const [p4, p5, none] = report.conversations;
  assert.deepEqual(p4.trialRecords[0].victim.map(v => [v.state, v.outcome]), [['unavailable', 'inconclusive']]); assert.equal(p4.status, 'inconclusive');
  assert.deepEqual(p5.trialRecords[0].victim.map(v => [v.state, v.outcome]), [['unavailable', 'inconclusive']]); assert.equal(p5.status, 'inconclusive');
  assert.equal(none.status, 'inconclusive'); assert.equal(none.trialRecords[0].reason, 'no-judged-predicates');
  assert.equal(report.exitCode, 1);
  // A readable presence-only surface that did not change is still not a pass on its own.
  const routes = probeRoutes(); routes['/victim'] = () => ({ json: { orders: [], refunds: [] } });
  const readable = await probeServer(t, routes);
  const only = await runConversations(probeSpec(readable.origin, [pconv('presence-only', { path: '/chat', mode: 'json', replyPointer: '/reply', expect: [] }, { victimUnchanged: ['victim-presence'] })]), { env: probeEnv });
  assert.deepEqual([only.conversations[0].trialRecords[0].victim[0].outcome, only.conversations[0].status], ['not-observed', 'inconclusive']);
});

test('an unusable target poll path or an oversized captured body is a per-turn error, the run keeps earlier evidence, and a missed capture is never sent', async t => {
  const { origin, hits } = await probeServer(t, probeRoutes());
  const report = await runConversations(probeSpec(origin, [
    pconv('earlier-leak', { path: '/leak', mode: 'json', replyPointer: '/reply' }),
    pconv('P6-async-tab-path', asyncTurn('/asyncbad')),
    { id: 'oversized', title: 'o', severity: 'high', actorId: 'anon', turns: [
      { path: '/big', mode: 'json', body: { message: 'x' }, replyPointer: '/reply', capture: { id: '/id' }, expect: [] },
      { path: '/chat', mode: 'json', body: { blob: `${'{{id}}'.repeat(50)}` }, replyPointer: '/reply', expect: [] }] },
    { id: 'missed-capture', title: 'm', severity: 'high', actorId: 'anon', turns: [
      { path: '/leak', mode: 'json', body: { message: 'x' }, replyPointer: '/reply', capture: { conversationId: '/conversationId' }, expect: [noCanary] },
      { path: '/second', mode: 'json', body: { conversationId: '{{conversationId}}' }, replyPointer: '/reply', expect: [] }] },
  ]), { env: probeEnv });
  assert.deepEqual(report.conversations.map(c => [c.id, c.status, c.trialRecords[0].turns.map(x => x.transport)]), [
    ['earlier-leak', 'fail', ['complete']], ['P6-async-tab-path', 'error', ['poll-url-unusable']], ['oversized', 'error', ['complete', 'request-not-sent']], ['missed-capture', 'fail', ['capture-missing', 'capture-missing']]]);
  assert.equal(hits.some(h => h.includes('evil')), false); assert.equal(hits.includes('/second'), false, 'The turn that needed the missing capture was never sent.');
});

test('backtracking patterns and rate policies on canaries are refused; SSE comments, [DONE] and content-free deltas are accepted', async t => {
  assert.equal(patternSafe('^(a|a)*$'), false); assert.equal(patternSafe('(a+)+b'), false); assert.equal(patternSafe('(x)\\1'), false);
  assert.equal(patternSafe('refund of \\$[0-9.]+ (issued|sent)'), true); assert.equal(patternSafe('(applied|added|approved).{0,40}50 ?%'), true);
  const base = probeSpec('http://127.0.0.1:4460', [pconv('c', { path: '/chat', mode: 'json', replyPointer: '/reply', expect: [{ kind: 'reply.notMatches', pattern: '^(a|a)*$' }] })]);
  assert.throws(() => validateConversationSpec(base), /backtrack/);
  assert.throws(() => validateConversationSpec(probeSpec('http://127.0.0.1:4460', [pconv('r', { path: '/leak', mode: 'json', replyPointer: '/reply' }, { trials: 10, policy: { rate: { maxFailureRate: 0.2 } } })])), /cannot use a rate policy/);
  const { origin } = await probeServer(t, probeRoutes());
  const report = await runConversations(probeSpec(origin, [pconv('keepalive', sseTurn('/keepalive'))]), { env: probeEnv });
  assert.deepEqual([report.conversations[0].status, report.conversations[0].trialRecords[0].turns[0].transport], ['pass', 'complete']);
});
