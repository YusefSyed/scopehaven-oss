// In-doubt resolution by read-back end to end on loopback: a real egress recorder (egress-recorder/9) whose crm.example destination declares
// read-back, a loopback system of record (test/fixtures/read-back-stub.mjs) that applies a note (or not) and then resets the connection, so the
// write is in doubt, and a small app that sends each task's notes through the recorder with the app's own bearer token. runHttpAssessment and
// the shared validator, with the exported suite. The fault injection:
// reset after apply is confirmed and reset before apply refuted; a commit inside the bound is confirmed and one after S2 is in doubt
// (never refuted); an incomplete list, a pre-image item deleted outside the recorder, a recorded delete or another note to the same ticket, and a
// pre-image inside the settle bound of the recorder's start are in doubt; a pre-existing identical note never confirms; another credential's
// identical note is not the write's; the keyed-retry shape (a reset, then a same-key retry proven 201) is decided, its defective twin
// fails; the same app without read-back keeps the earlier reading. Each sealed run holds no note id, token or proof secret. Loopback only: 127.0.0.1, owned
// synthetic names and dummy secrets in an env object (never the process environment). No real provider, no hosted write, no spend.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { createReadBackStub } from './fixtures/read-back-stub.mjs';
import * as C from './fixtures/in-doubt-r2-cases.mjs';

const ENV = Object.freeze({ SCOPEHAVEN_TARGET_CRM_PROOF: 'synthetic-proof-secret-crm-0000000000000000', SCOPEHAVEN_TARGET_ALT_PROOF: 'synthetic-proof-secret-alt-0000000000000000',
  SCOPEHAVEN_TARGET_CRM_READ: 'tok-read-0000', SCOPEHAVEN_TARGET_CRM_APP: 'tok-app-0000', SCOPEHAVEN_TARGET_CRM_JOBS: 'tok-jobs-0000' });
const TOKENS = { 'tok-app-0000': 'app', 'tok-jobs-0000': 'jobs' };
const listen = async (t, server) => { await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); })); return server.address().port; };
// The app: /task/1 runs its actions through the recorder (its proxy): { note: text, token, key } posts a note to T-1, { remove: true } sends a
// DELETE of a note, { wait: ms } pauses; /ping sends the witness; /me names the member.
async function appOf(t, sinkPort, actions) {
  const outbound = (method, target, headers = {}, body) => new Promise(resolve => {
    const url = new URL(target);
    const req = request({ host: '127.0.0.1', port: sinkPort, method, path: target, headers: { host: url.host, ...headers, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); });
    req.on('error', resolve); req.end(body);
  });
  return `http://127.0.0.1:${await listen(t, createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, {});
    if (url.pathname === '/ping') { await outbound('GET', `http://${C.WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, {}); }
    if (url.pathname !== '/task/1') return reply(404, {});
    for (const a of actions) {
      if (a.wait) await new Promise(resolve => setTimeout(resolve, a.wait));
      else if (a.remove) await outbound('DELETE', `http://${C.CRM}/tickets/T-1/notes/old`, { authorization: 'Bearer tok-app-0000' });
      else await outbound('POST', `http://${C.CRM}/tickets/T-1/notes`, { authorization: `Bearer ${a.token ?? 'tok-app-0000'}`, 'idempotency-key': a.key ?? 'k-1' }, JSON.stringify({ body: a.note }));
    }
    return reply(201, { posted: true });
  }))}`;
}
const verdictsOf = row => row.trace[1].data.effects.map(e => e.verdict);
const byOf = row => row.trace[1].data.effects[0].resolution?.attempts?.map(a => a.by) ?? null;
const PAST = { wait: 300 };   // past the route's settle bound after the recorder's start

// One run with one task. actions: the app's; plan and readHook: the stub's; seed(stub) before the run.
async function scenario(t, { actions = [PAST, { note: 'hello' }], effects = [C.EXISTS, C.count(1)], plan = () => ({ reply: 'reset' }), readHook = () => ({}), seed = () => {}, readBack = true } = {}) {
  const stub = await createReadBackStub({ secret: ENV.SCOPEHAVEN_TARGET_CRM_PROOF, tokens: TOKENS, readToken: ENV.SCOPEHAVEN_TARGET_CRM_READ });
  t.after(() => stub.close());
  stub.seed('T-CTRL', { text: 'seed', author: 'app' });
  seed(stub);
  stub.plan(plan); stub.readHook(info => readHook(info, stub));
  return onFreePorts(1, async port => {
    const p = { ...C.profileOf([effects], { readBack }), origin: await appOf(t, port, actions) };
    p.observers = [C.declaration({ port, upstream: stub.port, altUpstream: 47999, readBack })];
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    const watch = watchingBinds(buildObservers);
    const run = await runHttpAssessment(p, { env: ENV, observerFactory: watch.factory });
    const suite = createRegistry({ profiles: [p], env: ENV }).exportSuite(p.id);
    validateHttpRunEvidence(run, { expectedSuite: suite });
    validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suite });
    const row = run.results.find(r => r.id === 'TASK1');
    // Nothing identifying: no note id, token, proof secret or read path.
    const text = JSON.stringify(run);
    for (const secret of [...Object.values(ENV), ...['T-1', 'T-CTRL'].flatMap(k => stub.notes(k).map(x => x.id))]) assert.ok(!text.includes(secret), `the run holds no "${secret}"`);
    return { run, row, stub, lostBind: watch.state.lostBind };
  }, x => x.lostBind);
}
// The read number a hook sees counts reads of every ticket; on T-1 alone: 1 the pre-image, 2 S1, 3 S2, 4 S3.
const onT1 = fn => { let k = 0; return (info, stub) => (info.ticket === 'T-1' ? fn(++k, stub) : {}); };

test('1. reset after apply is confirmed, reset before apply refuted; a commit inside the bound is confirmed, one after S2 is in doubt and never refuted', async t => {
  const ra = await scenario(t), rb = await scenario(t, { plan: () => ({ reply: 'reset-before' }) });
  assert.deepEqual([verdictsOf(ra.row), ra.row.status, ra.row.backendEvidence, byOf(ra.row)], [['pass', 'pass'], 'pass', 'observed', ['r2']], 'reset after apply: confirmed');
  assert.deepEqual([verdictsOf(rb.row), rb.row.status, byOf(rb.row)], [['fail', 'fail'], 'fail', ['r2']], 'reset before apply: refuted');
  const e1 = ra.row.trace[1].data.windows[0].events[0];
  assert.deepEqual([e1.upstream.readBack.preImage, e1.upstream.readBack.route, Object.keys(e1.upstream.transport).sort()], ['first', 0, ['connected', 'mono', 'wall']]);
  assert.deepEqual([ra.run.observers[0].collector.label, Object.keys(ra.run.observers[0].readBack.hosts)], ['egress-recorder/13', [C.CRM]]);
  assert.ok(ra.run.limitations.some(l => /Read-back/.test(l)));
  // A late commit inside the settle bound (100 ms of 200): the reads after the bound see it.
  const inside = await scenario(t, { plan: () => ({ reply: 'reset', commitAfterMs: 100 }) });
  assert.deepEqual([verdictsOf(inside.row), byOf(inside.row)], [['pass', 'pass'], ['r2']], 'a commit within the bound');
  // A commit after S2 (held until the stub has answered S2): S3 shows a note nothing later explains, so the group fails: in doubt.
  const beyond = await scenario(t, { plan: () => ({ reply: 'reset', commitAfterMs: Infinity }), readHook: onT1((k, stub) => (k === 3 ? { after: () => stub.commit('T-1') } : {})) });
  assert.deepEqual([verdictsOf(beyond.row), beyond.row.trace[1].data.effects[0].resolution.attempts[0].reason], [['missing', 'missing'], 'read-late-item'], 'a commit beyond the bound is never refuted');
});

test('2. what reads in doubt: an incomplete list, a pre-image note deleted outside the recorder, a recorded delete or another note to the ticket, a pre-image inside the settle bound of the recorder\'s start', async t => {
  const paged = await scenario(t, { readHook: onT1(k => (k === 2 ? { complete: false } : {})) });
  assert.deepEqual([verdictsOf(paged.row), paged.row.trace[1].data.effects[0].resolution.attempts[0].reason], [['missing', 'missing'], 'read-s1-incomplete']);
  // A pre-existing note deleted between the pre-image and S1 (outside the recorder): S0 is not within S1, so the reset-before write is not refuted.
  const deleted = await scenario(t, { plan: () => ({ reply: 'reset-before' }), seed: stub => stub.seed('T-1', { id: 'note_pre', text: 'older', author: 'jobs' }), readHook: onT1((k, stub) => (k === 1 ? { after: () => stub.remove('T-1', 'note_pre') } : {})) });
  assert.deepEqual(verdictsOf(deleted.row), ['missing', 'missing'], 'a deletion between send and read');
  // The app's own recorded DELETE on the ticket after the write: a backend write the route does not declare, so it intervenes.
  const removed = await scenario(t, { plan: () => ({ reply: 'reset-before' }), actions: [PAST, { note: 'hello' }, { remove: true }] });
  assert.deepEqual(verdictsOf(removed.row), ['missing', 'missing'], 'a recorded delete intervenes');
  // A second note (another body: another group) to the same ticket in the window: it touches the same read, so neither group decides.
  const two = await scenario(t, { plan: () => ({ reply: 'reset-before' }), actions: [PAST, { note: 'hello' }, { note: 'other text', key: 'k-2' }] });
  assert.deepEqual(verdictsOf(two.row), ['missing', 'missing'], 'another write to the object intervenes');
  // No wait after the recorder started: the pre-image is within the route's settle of its start, so an earlier send could still commit (m5).
  const early = await scenario(t, { plan: () => ({ reply: 'reset-before' }), actions: [{ note: 'hello' }] });
  assert.deepEqual(verdictsOf(early.row), ['missing', 'missing'], 'a pre-image too close to the recorder\'s start');
});

test('3. identical notes: a pre-existing one never confirms the write; another credential\'s, written outside the recorder, is not the write\'s, and a recorded one intervenes', async t => {
  const preRB = await scenario(t, { plan: () => ({ reply: 'reset-before' }), seed: stub => stub.seed('T-1', { text: 'hello', author: 'app' }) });
  const preRA = await scenario(t, { seed: stub => stub.seed('T-1', { text: 'hello', author: 'app' }) });
  assert.deepEqual([verdictsOf(preRB.row), verdictsOf(preRA.row)], [['fail', 'fail'], ['pass', 'pass']], 'the pre-image holds the old note: RB refuted, RA confirmed by the new one');
  // The jobs component's identical note, written while the app's write was being applied (the stub writes it; no send of the run carries it).
  const foreign = await scenario(t, { plan: () => ({ reply: 'reset-before' }), readHook: onT1((k, stub) => (k === 1 ? { after: () => stub.inject('T-1', { text: 'hello', author: 'jobs' }) } : {})) });
  assert.deepEqual([verdictsOf(foreign.row), byOf(foreign.row)], [['fail', 'fail'], ['r2']], 'not confirmed by another identity\'s note: refuted by the exact count');
  // The same note sent by the jobs component through the recorder in the window: another group, which intervenes.
  const recorded = await scenario(t, { plan: ({ identity }) => (identity === 'jobs' ? {} : { reply: 'reset-before' }), actions: [PAST, { note: 'hello' }, { note: 'hello', token: 'tok-jobs-0000', key: 'k-j' }] });
  // The jobs note's own proven 201 matches the clauses (selectors read no credential), as before; the app's write stays in doubt.
  const attempts = recorded.row.trace[1].data.effects[1].resolution.attempts;
  assert.deepEqual([verdictsOf(recorded.row), attempts.map(a => [a.fate, a.by])], [['pass', 'missing'], [['in-doubt', 'none'], ['applied', 'proof']]], 'a recorded write by another credential to the object intervenes');
});

test('4. the keyed-retry shape (a reset, then a same-key same-body retry proven 201) is decided by read-back on a backend that dedupes the key, stays in doubt on one that does not, and its defective twin fails; without read-back it stays in doubt', async t => {
  const effects = [C.EXISTS, C.count(1), C.KEYED_COUNT(1)];
  // Reset after apply, then the retry is replayed under its key (the same note id): one application.
  let n = 0;
  const after = await scenario(t, { effects, actions: [PAST, { note: 'hello', key: 'k-1' }, { note: 'hello', key: 'k-1' }], plan: () => (++n === 1 ? { keyed: true, reply: 'reset' } : { keyed: true }) });
  assert.deepEqual([verdictsOf(after.row), after.row.status], [['pass', 'pass', 'pass'], 'pass'], 'one application');
  // Reset before apply, then the retry applies: one application.
  let m = 0;
  const before = await scenario(t, { effects, actions: [PAST, { note: 'hello', key: 'k-1' }, { note: 'hello', key: 'k-1' }], plan: () => (++m === 1 ? { keyed: true, reply: 'reset-before' } : { keyed: true }) });
  assert.deepEqual([verdictsOf(before.row), before.row.status], [['pass', 'pass', 'pass'], 'pass'], 'one application');
  // A backend that does not dedupe the key: the same-key, same-body retry writes a second note. Read-back could confirm the reset
  // only as a second application of one key identity, which the key collapse would read as one, so it confirms nothing: the earlier reading.
  let u = 0;
  const notDeduped = await scenario(t, { effects, actions: [PAST, { note: 'hello', key: 'k-1' }, { note: 'hello', key: 'k-1' }], plan: () => (++u === 1 ? { reply: 'reset' } : {}) });
  assert.deepEqual([verdictsOf(notDeduped.row), notDeduped.stub.notes('T-1').length, notDeduped.row.trace[1].data.effects[1].resolution.attempts.map(a => a.by)], [['pass', 'missing', 'missing'], 2, ['none', 'proof']], 'in doubt, never one application');
  // The defective twin: the retry under a new key applies again (two notes): exactly one fails.
  let d = 0;
  const twice = await scenario(t, { effects: [C.EXISTS, C.count(1)], actions: [PAST, { note: 'hello', key: 'k-1' }, { note: 'hello', key: 'k-2' }], plan: () => (++d === 1 ? { reply: 'reset' } : {}) });
  assert.deepEqual(verdictsOf(twice.row), ['pass', 'fail'], 'two applications');
  // Without read-back: the earlier reading, in doubt.
  let q = 0;
  const plain = await scenario(t, { effects, readBack: false, actions: [PAST, { note: 'hello', key: 'k-1' }, { note: 'hello', key: 'k-1' }], plan: () => (++q === 1 ? { keyed: true, reply: 'reset' } : { keyed: true }) });
  assert.deepEqual(verdictsOf(plain.row), ['pass', 'missing', 'missing']);
  assert.equal(plain.stub.log.reads.length, 0, 'no read without read-back');
  assert.ok(plain.run.results.every(r => !Object.hasOwn(r.trace?.[1]?.data ?? {}, 'resolutions')));
  assert.equal(Object.hasOwn(plain.run.observers[0], 'readBack'), false);
});
