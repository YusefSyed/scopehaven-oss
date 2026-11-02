// Boundary sweep (sweep/) runs against the owned relay desk (sweep/fixtures/relay-desk.mjs): one fresh desk per run, a real hold gate
// on loopback, every run saved and re-checked. Each build's verdict is compared with the desk's own ledger.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, readdirSync, writeFileSync, statSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runSweep, recheckRun } from './sweep/runner.mjs';
import { commandWorld } from './sweep/launcher.mjs';
import { main } from './sweep/cli.mjs';
import { relayWorld, relaySpec, relayOtherTwinSpec } from './sweep/fixtures/relay-desk.mjs';

const RELAY = fileURLToPath(new URL('./sweep/fixtures/relay-desk.mjs', import.meta.url));
function scratch(t) { const dir = mkdtempSync(join(tmpdir(), 'scopehaven sweep-')); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; }
async function sweep(t, build, { script, spec, desk = {} } = {}) {
  const desks = [], secrets = [], outDir = join(scratch(t), 'out');
  const fresh = relayWorld({ build, ...(script ? { script } : {}), ...desk }, desks);
  const startWorld = async gateFor => { const world = await fresh(gateFor); secrets.push(...Object.values(world.credentials)); return world; };
  const report = await runSweep({ spec: spec ?? relaySpec(`relay-${build}`), startWorld, outDir });
  return { report, desks, secrets, outDir };
}
const byResult = (report, result) => report.outcomes.filter(o => o.result === result).map(o => o.id);
const filesUnder = dir => readdirSync(dir, { recursive: true }).map(f => join(dir, f)).filter(f => statSync(f).isFile());

test('the IC1-24 shape: a queued email in the second step is flagged at model call 3 and the delivery, which a fixed three-boundary list never holds', async t => {
  // Model call 3 shows the defect only if the queued email is delivered after the access change. With the desk's 120 ms
  // queue, a loaded machine can deliver it before or during the change (just after the drain's 100 ms quiet), and that
  // execution honestly reads PASS on a desk that applied nothing after the suspension, or INCONCLUSIVE. So the queue
  // waits 800 ms, well past the drain and the change, and the settle 1500 ms, well past the queue.
  const { report, desks } = await sweep(t, 'queue_no_recheck', { desk: { queueMs: 800 }, spec: relaySpec('relay-queue_no_recheck', { settleMs: 1500 }) });
  assert.equal(report.verdict, 'FLAG');
  assert.deepEqual(report.baseline.calls.map(c => `${c.rule}${c.k}:${c.status}`), ['model1:200', 'tool1:201', 'model2:200', 'tool2:202', 'model3:200', 'deliver1:201']);
  assert.deepEqual(byResult(report, 'FAIL'), ['model3', 'deliver1']);
  // The fixed list IC1 used (model call 1, model call 2, the first tool call) passes on this build.
  assert.deepEqual(report.outcomes.filter(o => ['model1', 'model2', 'tool1'].includes(o.id)).map(o => o.result), ['PASS', 'PASS', 'PASS']);
  assert.deepEqual(report.plan.executions.find(e => e.id === 'model3').origins, ['boundary', 'signal:202']);
  // The report lists every passive call, how it was sent and what it answered.
  assert.deepEqual(report.baseline.passiveCalls, [1, 2, 3].map(k => ({ rule: 'model', k, method: 'POST', overrides: [], status: 200 })));
  assert.ok(report.outcomes.every(o => Array.isArray(o.passiveCalls) && o.passiveCalls.length && o.passiveCalls.every(c => c.rule === 'model' && c.method === 'POST' && c.overrides.length === 0 && c.status === 200)));
  // The desk's ledger agrees: an action applied after the suspension in exactly the failing executions (desk 0 is the baseline).
  assert.equal(desks.length, 1 + report.outcomes.length, 'a fresh desk per run');
  assert.deepEqual(desks.slice(1).map(d => d.exposed() > 0), report.outcomes.map(o => o.result === 'FAIL'));
});

test('the clean build reads NO_FLAG: every execution fired, passed and showed its twin, and every saved run re-checks', async t => {
  const { report, desks, secrets, outDir } = await sweep(t, 'per_step_validating');
  assert.equal(report.verdict, 'NO_FLAG', report.reasons.join());
  assert.equal(report.baseline.allowedUse, true);
  assert.deepEqual(report.baseline.allowedActions, ['tool', 'deliver']);
  assert.deepEqual(report.outcomes.map(o => [o.id, o.result, o.fired, o.validated]), ['model1', 'tool1', 'model2', 'tool2', 'model3', 'deliver1'].map(id => [id, 'PASS', true, true]));
  assert.ok(desks.every(d => d.exposed() === 0));
  // Each run re-checks from its sealed windows, bound to its sequence and gate configuration; an edited verdict does not.
  for (const o of report.outcomes) {
    const dir = join(o.runFile, '..'), run = JSON.parse(readFileSync(o.runFile, 'utf8'));
    const sequence = JSON.parse(readFileSync(join(dir, 'seq.json'), 'utf8')), gateConfig = JSON.parse(readFileSync(join(dir, 'gate.json'), 'utf8'));
    assert.equal(recheckRun({ run, sequence, gateConfig }), true);
    assert.equal((statSync(o.runFile).mode & 0o777), 0o600);
    // The gate timeline records each held and forwarded request's method and method overrides (the desk sends POST, with
    // none), outside the run digest.
    const sent = run.gateTimeline.filter(e => e.type === 'held' || e.type === 'forwarded');
    assert.ok(sent.some(e => e.type === 'held') && sent.every(e => e.method === 'POST' && Array.isArray(e.methodOverrides) && !e.methodOverrides.length), o.id);
  }
  const edited = JSON.parse(readFileSync(report.outcomes[0].runFile, 'utf8'));
  edited.results[0].status = 'fail';
  const dir0 = join(report.outcomes[0].runFile, '..');
  assert.throws(() => recheckRun({ run: edited, sequence: JSON.parse(readFileSync(join(dir0, 'seq.json'), 'utf8')), gateConfig: JSON.parse(readFileSync(join(dir0, 'gate.json'), 'utf8')) }), e => e.code === 'invalid-sequence-run' && e.detail === 'run-digest');
  // The world's credentials reach the sequences as their environment only: no saved file holds one.
  assert.ok(secrets.length >= 2);
  for (const file of filesUnder(outDir)) { const text = readFileSync(file, 'utf8'); assert.ok(secrets.every(s => !text.includes(s)), `${file} holds a credential`); }
});

test('builds that check only at the start, or never at commit, read FLAG', async t => {
  const start = await sweep(t, 'start_only', { script: 'two_steps' });
  assert.equal(start.report.verdict, 'FLAG');
  assert.deepEqual(byResult(start.report, 'FAIL'), ['model1', 'tool1', 'model2', 'tool2']);
  const trusting = await sweep(t, 'per_step_trusting', { script: 'two_steps' });
  assert.equal(trusting.report.verdict, 'FLAG');
  assert.deepEqual(byResult(trusting.report, 'FAIL'), ['tool1', 'tool2']);
});

test('an application that does nothing, or stops acting for good, never reads NO_FLAG', async t => {
  const nothing = await sweep(t, 'do_nothing');
  assert.deepEqual([nothing.report.verdict, nothing.report.reasons], ['ABSTAIN', ['no-allowed-use', 'no-boundary']]);
  const modelOnly = await sweep(t, 'model_only');
  assert.deepEqual([modelOnly.report.verdict, modelOnly.report.reasons], ['ABSTAIN', ['no-allowed-use', 'model1:INCONCLUSIVE']]);
  assert.equal(modelOnly.report.outcomes[0].reason, 'no-allowed-use-twin', 'its prohibitions held, and still no pass');
  // Over-blocking: it never applies anything after a suspension, so every prohibition holds; only the twin tells.
  const halt = await sweep(t, 'halt_all', { script: 'one_call' });
  assert.equal(halt.report.verdict, 'ABSTAIN');
  assert.deepEqual(halt.report.outcomes.map(o => [o.id, o.result, o.reason]), [['model1', 'INCONCLUSIVE', 'twin-not-shown:TWIN-tool'], ['tool1', 'INCONCLUSIVE', 'twin-not-shown:TWIN-tool'], ['model2', 'INCONCLUSIVE', 'twin-not-shown:TWIN-tool']]);
});

test('with the twin as another actor\'s turn and no restore, the clean build still reads NO_FLAG and the over-blocking build ABSTAIN', async t => {
  const clean = await sweep(t, 'per_step_validating', { script: 'one_call', spec: relayOtherTwinSpec('relay-other-clean') });
  assert.equal(clean.report.verdict, 'NO_FLAG', clean.report.reasons.join());
  assert.ok(clean.desks.slice(1).every(d => d.ledger.some(row => row.actor === 'ben')), 'every twin ran as Ben');
  const halt = await sweep(t, 'halt_all', { script: 'one_call', spec: relayOtherTwinSpec('relay-other-halt') });
  assert.deepEqual([halt.report.verdict, [...new Set(halt.report.outcomes.map(o => o.reason))]], ['ABSTAIN', ['twin-not-shown:TWIN-tool']]);
  const defect = await sweep(t, 'per_step_trusting', { script: 'one_call', spec: relayOtherTwinSpec('relay-other-defect') });
  assert.deepEqual([defect.report.verdict, defect.report.reasons], ['FLAG', ['tool1:FAIL']]);
});

test('parallel tool calls answered late do not read as applied after the change; late effects the settle misses never read NO_FLAG', async t => {
  // A clean build that sends both tool calls at once and answers each 60 ms after applying it: the sweep waits for
  // every forwarded call to be answered before it changes access, so no call straddles the change. The settle is well
  // past the 60 ms reply, so a loaded machine cannot push a reply past it.
  const parallel = await sweep(t, 'per_step_validating', { script: 'parallel_pair', desk: { parallel: true, replyMs: 60 }, spec: relaySpec('relay-parallel', { settleMs: 1500 }) });
  assert.equal(parallel.report.verdict, 'NO_FLAG', parallel.report.reasons.join());
  assert.ok(parallel.desks.every(d => d.exposed() === 0));
  // The queue defect with a settle shorter than its queue delay: the delivery the queued answer announced is never
  // seen in the baseline, so the signal is unreachable and the case abstains instead of passing.
  const short = await sweep(t, 'queue_no_recheck', { desk: { queueMs: 300 }, spec: relaySpec('relay-short-settle', { settleMs: 50 }) });
  assert.equal(short.report.verdict, 'ABSTAIN');
  assert.ok(short.report.reasons.includes('unreachable:signal:202'), short.report.reasons.join());
  // An app that makes one more call after the settle: its baseline is not quiet, so nothing is planned.
  const late = await sweep(t, 'per_step_validating', { script: 'one_call', desk: { lateCallMs: 600 } });
  assert.deepEqual([late.report.verdict, late.report.baseline.reasons], ['ABSTAIN', ['timeline-window-mismatch', 'baseline-not-quiet']]);
});

test('a stalled upstream cannot hang the cleanup, and the CLI exits 2 when the sweep cannot finish', async t => {
  const out = scratch(t);
  // An app whose every turn asks the model through the gate and waits, in front of an upstream that never answers.
  const stalledWorld = async gateFor => {
    const upstream = createServer(() => {});
    await new Promise(r => upstream.listen(0, '127.0.0.1', r));
    const gate = await gateFor(`http://127.0.0.1:${upstream.address().port}`);
    const app = createServer((req, res) => {
      req.resume();
      const ask = request(new URL('/v1/chat/completions', gate), { method: 'POST', agent: false }, () => {});
      ask.on('error', () => { if (!res.headersSent) res.writeHead(502).end(); });
      ask.end('{}');
    });
    await new Promise(r => app.listen(0, '127.0.0.1', r));
    return { origin: `http://127.0.0.1:${app.address().port}`, credentials: { SCOPEHAVEN_TARGET_SWEEP_USER: 'u', SCOPEHAVEN_TARGET_SWEEP_OTHER: 'o', SCOPEHAVEN_TARGET_SWEEP_ADMIN: 'a' },
      stop: async () => { for (const s of [app, upstream]) { s.closeAllConnections(); await new Promise(r => s.close(r)); } } };
  };
  const started = Date.now();
  const report = await runSweep({ spec: relaySpec('relay-stalled', { turn: { ...relaySpec('x').turn, timeoutMs: 500 } }), startWorld: stalledWorld, outDir: join(out, 'a') });
  assert.equal(report.verdict, 'ABSTAIN');
  assert.ok(Date.now() - started < 4000, 'the world is stopped before the gate, so the cleanup does not wait on the stalled request');
  writeFileSync(join(out, 'not-a-folder'), '');
  const specFile = join(out, 'spec.json'), lines = [];
  writeFileSync(specFile, JSON.stringify(relaySpec('cli-crash', { world: { command: [process.execPath, RELAY, '--build', 'per_step_validating'] } })));
  assert.equal(await main(['--spec', specFile, '--out', join(out, 'not-a-folder', 'x')], { log: s => lines.push(s) }), 2);
  assert.match(lines.at(-1), /^Sweep error: /);
});

test('a delivery path the spec leaves out, or a queue slower than the settle, never reads NO_FLAG', async t => {
  // The queued credit is delivered on /deliver/, which this spec does not declare: its calls are undeclared, so abstain.
  const undeclared = await sweep(t, 'queue_no_recheck', { script: 'two_steps', desk: { queued: ['issue_credit'] },
    spec: relaySpec('relay-undeclared', { actions: [{ id: 'tool', pathPrefix: '/tool/', rejected: [403] }] }) });
  assert.equal(undeclared.report.verdict, 'ABSTAIN');
  assert.deepEqual(undeclared.report.baseline.reasons, ['undeclared-call']);
  // The same desk with /deliver/ declared: FLAG, at the boundaries the queued credit is delivered after the change. With the
  // desk's 120 ms queue, a loaded machine can fire the delivery while access is being changed (just after the drain's
  // 100 ms quiet), and that execution honestly reads INCONCLUSIVE (answered-after-change) on an exposed desk. So the queue
  // waits 800 ms, well past the drain and the change, and the settle 1500 ms, well past the queue: each boundary then
  // reads FAIL exactly when the desk applied the credit after the suspension.
  const declared = await sweep(t, 'queue_no_recheck', { script: 'two_steps', desk: { queued: ['issue_credit'], queueMs: 800 }, spec: relaySpec('relay-declared', { settleMs: 1500 }) });
  assert.equal(declared.report.verdict, 'FLAG');
  assert.deepEqual(declared.desks.slice(1).map(d => d.exposed() > 0), declared.report.outcomes.map(o => o.result === 'FAIL'));
  // The queued credit delivered 3 s later, past both settles, with another tool call after it: that call is the turn's
  // next step, not the delivery, so the queued answer is unpaired and the case abstains.
  const slow = await sweep(t, 'queue_no_recheck', { script: 'two_steps', desk: { queued: ['issue_credit'], queueMs: 3000 }, spec: { ...relayOtherTwinSpec('relay-slow-queue'), settleMs: 400 } });
  assert.equal(slow.report.verdict, 'ABSTAIN');
  assert.deepEqual(slow.report.plan.unreachable, [{ signal: 'signal:202', after: 'tool1' }]);
});

// A two-tool world: the backend refuses /tool/a for a suspended user but applies
// /tool/b for anyone (201); the app checks the user only when the turn starts. Options: the
// app sends /tool/b with `method`, the backend answers it `status`, and with `writes: false` it only reads. Overrides:
// the app adds `headers` and a `query` to /tool/b, or sends it a `form` body, and the backend reads
// a POST's method override as Rack does (the X-HTTP-Method-Override header, or `_method` in a form body) and Symfony does
// (also `_method` in the query); its ledger records the method b was applied as.
function twoToolWorld(ledgers, { method = 'POST', status = 201, writes = true, headers = {}, query = '', form = null } = {}) {
  const reply = (res, status) => { res.writeHead(status, { 'content-type': 'application/json', 'content-length': 2, connection: 'close' }); res.end('{}'); };
  const textOf = req => new Promise(done => { const c = []; req.on('data', x => c.push(x)); req.on('end', () => done(Buffer.concat(c).toString())); });
  const fieldsOf = (req, text) => { if (/urlencoded/.test(req.headers['content-type'] ?? '')) return Object.fromEntries(new URLSearchParams(text)); try { return JSON.parse(text || '{}'); } catch { return {}; } };
  const post = (base, path, body, verb = 'POST', extra = {}) => new Promise(done => { const p = typeof body === 'string' ? body : JSON.stringify(body); const r = request(new URL(path, base), { method: verb, agent: false, headers: { 'content-type': typeof body === 'string' ? 'application/x-www-form-urlencoded' : 'application/json', 'content-length': Buffer.byteLength(p), connection: 'close', ...extra } }, res => { res.resume(); res.on('end', () => done(res.statusCode)); }); r.on('error', () => done(null)); r.end(p); });
  const listen = server => new Promise(ok => server.listen(0, '127.0.0.1', () => ok(`http://127.0.0.1:${server.address().port}`)));
  return async gateFor => {
    const suspended = new Set(), ledger = [];
    ledgers.push(ledger);
    const backend = createServer(async (req, res) => {
      const url = new URL(req.url, 'http://x'), path = url.pathname, body = fieldsOf(req, await textOf(req));
      const seen = req.method === 'POST' ? String(req.headers['x-http-method-override'] ?? body._method ?? url.searchParams.get('_method') ?? 'POST').toUpperCase() : req.method;
      if (path === '/v1/chat') return reply(res, 200);
      if (path === '/tool/a') { if (suspended.has(body.actor)) return reply(res, 403); ledger.push({ tool: 'a', suspended: false }); return reply(res, 201); }
      if (path === '/tool/b') { if (writes) ledger.push({ tool: 'b', suspended: suspended.has(body.actor), method: seen }); return reply(res, status); }
      return reply(res, 404);
    });
    const gate = await gateFor(await listen(backend));
    const app = createServer(async (req, res) => {
      await textOf(req);
      const path = new URL(req.url, 'http://x').pathname, auth = req.headers.authorization ?? '';
      if (path === '/api/admin/suspend' && auth === 'Bearer admin-token') { suspended.add('amy'); return reply(res, 200); }
      if (path === '/api/admin/restore' && auth === 'Bearer admin-token') { suspended.delete('amy'); return reply(res, 200); }
      if (path === '/api/agent' && auth === 'Bearer amy-token' && !suspended.has('amy')) {
        for (const [p, b, verb, extra] of [['/v1/chat', {}], ['/tool/a', { actor: 'amy' }], ['/v1/chat', {}], [`/tool/b${query}`, form ?? { actor: 'amy' }, method, headers], ['/v1/chat', {}]]) await post(gate, p, b, verb, extra);
        return reply(res, 200);
      }
      return reply(res, 401);
    });
    const origin = await listen(app);
    return { origin, credentials: { SCOPEHAVEN_TARGET_P_AMY: 'amy-token', SCOPEHAVEN_TARGET_P_ADMIN: 'admin-token' },
      stop: async () => { for (const server of [app, backend]) { server.closeAllConnections(); await new Promise(r => server.close(r)); } } };
  };
}
const twoToolSpec = (id, actions, passive) => ({ schema: 'scopehaven-sweep-spec/1', id, actors: { amy: { principalId: 'amy', credentialEnv: 'SCOPEHAVEN_TARGET_P_AMY' }, admin: { principalId: 'admin', credentialEnv: 'SCOPEHAVEN_TARGET_P_ADMIN' } },
  turn: { actorId: 'amy', method: 'POST', path: '/api/agent', body: {}, timeoutMs: 10000 }, condition: { actorId: 'admin', method: 'POST', path: '/api/admin/suspend', body: {}, expect: [200] },
  restore: { actorId: 'admin', method: 'POST', path: '/api/admin/restore', body: {}, expect: [200] }, actions, passive, settleMs: 200, holdTimeoutMs: 5000 });

test('a write behind a passive path, or a catch-all passive, never reads NO_FLAG', async t => {
  const out = scratch(t), a = { id: 'a', pathPrefix: '/tool/a', rejected: [403] }, chat = { id: 'model', pathPrefix: '/v1/chat' };
  // b as an action: FLAG, in exactly the executions whose ledger shows b applied while suspended.
  const asAction = [], flagged = await runSweep({ spec: twoToolSpec('two-b-action', [a, { id: 'b', pathPrefix: '/tool/b', rejected: [403] }], [chat]), startWorld: twoToolWorld(asAction), outDir: join(out, 'a') });
  assert.equal(flagged.verdict, 'FLAG');
  assert.deepEqual(asAction.slice(1).map(l => l.some(r => r.tool === 'b' && r.suspended)), flagged.outcomes.map(o => o.result === 'FAIL'));
  // b declared passive: its baseline call answered 201, so the case abstains, and the report shows that call.
  const passive = await runSweep({ spec: twoToolSpec('two-b-passive', [a], [chat, { id: 'b', pathPrefix: '/tool/b' }]), startWorld: twoToolWorld([]), outDir: join(out, 'b') });
  assert.deepEqual([passive.verdict, passive.baseline.reasons], ['ABSTAIN', ['passive-call-wrote']]);
  assert.deepEqual(passive.baseline.passiveCalls.filter(c => c.rule === 'b'), [{ rule: 'b', k: 1, method: 'POST', overrides: [], status: 201 }]);
  // Everything passive: refused before anything runs.
  await assert.rejects(runSweep({ spec: twoToolSpec('two-root', [a], [{ id: 'rest', pathPrefix: '/' }]), startWorld: twoToolWorld([]), outDir: join(out, 'c') }), /passive path rest is "\/"/);
});

test('a passive call sent as PUT, PATCH or DELETE never reads NO_FLAG, whatever its answer; a write answered 200 and sent as POST or GET is the documented residual', async t => {
  const out = scratch(t), a = { id: 'a', pathPrefix: '/tool/a', rejected: [403] }, chat = { id: 'model', pathPrefix: '/v1/chat' }, b = { id: 'b', pathPrefix: '/tool/b' };
  // b passive and sent as PUT (before this rule: NO_FLAG, b applied while suspended in 4 of 5 runs), PATCH or
  // DELETE, each answered 200: the method the gate recorded shows the write, so the baseline is not observed.
  for (const method of ['PUT', 'PATCH', 'DELETE']) {
    const report = await runSweep({ spec: twoToolSpec(`two-b-${method}`, [a], [chat, b]), startWorld: twoToolWorld([], { method, status: 200 }), outDir: join(out, method) });
    assert.deepEqual([report.verdict, report.baseline.reasons, report.outcomes], ['ABSTAIN', ['passive-call-wrote'], []], method);
    assert.deepEqual(report.baseline.passiveCalls.filter(c => c.rule === 'b'), [{ rule: 'b', k: 1, method, overrides: [], status: 200 }]);
  }
  // A read-only route sent as GET is not a write: with b only reading, the desk (whose tool service refuses a suspended
  // user's /tool/a) reads NO_FLAG, and the report shows each passive call's method.
  const reads = await runSweep({ spec: twoToolSpec('two-b-get', [a], [chat, b]), startWorld: twoToolWorld([], { method: 'GET', status: 200, writes: false }), outDir: join(out, 'get') });
  assert.equal(reads.verdict, 'NO_FLAG', reads.reasons.join());
  assert.deepEqual(reads.baseline.passiveCalls.map(c => `${c.rule}${c.k}:${c.method}:${c.status}`), ['model1:POST:200', 'model2:POST:200', 'b1:GET:200', 'model3:POST:200']);
  assert.deepEqual(reads.baseline.calls.map(c => `${c.rule}${c.k}:${c.method}`), ['model1:POST', 'a1:POST', 'model2:POST', 'b1:GET', 'model3:POST']);
  // The residual the README states: the same write sent as POST, or as a GET with side effects, and answered 200 is
  // trusted as the operator's passive statement, so the case reads NO_FLAG while b applied after the suspension. The
  // report carries that limit.
  for (const method of ['POST', 'GET']) {
    const ledgers = [], residual = await runSweep({ spec: twoToolSpec(`two-b-${method}-200`, [a], [chat, b]), startWorld: twoToolWorld(ledgers, { method, status: 200 }), outDir: join(out, `${method}-200`) });
    assert.equal(residual.verdict, 'NO_FLAG', `${method}: ${residual.reasons.join()}`);
    assert.ok(ledgers.slice(1).some(ledger => ledger.some(r => r.tool === 'b' && r.suspended)), `${method}: b applied after the suspension`);
    assert.ok(residual.limitations.some(l => l.includes('a write answered 200 and sent as POST with no override, or as a safe method misused for a write, is not')));
  }
});

test('a passive POST that asks for DELETE by a method override never reads NO_FLAG, whatever its answer; an override to GET on a read-only route is not a write', async t => {
  const out = scratch(t), a = { id: 'a', pathPrefix: '/tool/a', rejected: [403] }, chat = { id: 'model', pathPrefix: '/v1/chat' }, b = { id: 'b', pathPrefix: '/tool/b' };
  // An override in the b-passive world (Rack-style backend): b sent as a POST with
  // X-HTTP-Method-Override: DELETE and answered 200 read NO_FLAG (before this rule) with b applied while suspended in 4 of 5 runs. The same
  // override as `_method` in the query or a form body (a Rails form's lowercase value) reads the same way.
  for (const [label, how, overrides] of [['header', { headers: { 'x-http-method-override': 'DELETE' } }, ['DELETE']], ['query', { query: '?_method=DELETE' }, ['DELETE']], ['form', { form: 'actor=amy&_method=delete' }, ['delete']]]) {
    const ledgers = [], report = await runSweep({ spec: twoToolSpec(`two-b-override-${label}`, [a], [chat, b]), startWorld: twoToolWorld(ledgers, { status: 200, ...how }), outDir: join(out, label) });
    assert.deepEqual([report.verdict, report.baseline.reasons, report.outcomes], ['ABSTAIN', ['passive-call-wrote'], []], label);
    assert.deepEqual(report.baseline.passiveCalls.filter(c => c.rule === 'b'), [{ rule: 'b', k: 1, method: 'POST', overrides, status: 200 }], label);
    assert.deepEqual(report.baseline.calls.filter(c => c.rule === 'b'), [{ rule: 'b', k: 1, method: 'POST', overrides, status: 200 }], label);
    assert.deepEqual(ledgers[0].filter(r => r.tool === 'b').map(r => r.method), ['DELETE'], `${label}: the backend applied b as a DELETE`);
  }
  // An override to GET on a route that only reads is not a write: the desk reads NO_FLAG, and the report lists the override.
  const reads = await runSweep({ spec: twoToolSpec('two-b-override-get', [a], [chat, b]), startWorld: twoToolWorld([], { status: 200, writes: false, headers: { 'x-http-method-override': 'GET' } }), outDir: join(out, 'get') });
  assert.equal(reads.verdict, 'NO_FLAG', reads.reasons.join());
  assert.deepEqual(reads.baseline.passiveCalls.map(c => `${c.rule}${c.k}:${c.method}:${c.overrides.join('+')}:${c.status}`), ['model1:POST::200', 'model2:POST::200', 'b1:POST:GET:200', 'model3:POST::200']);
  assert.deepEqual(reads.baseline.calls.map(c => `${c.rule}${c.k}:${c.overrides.join('+')}`), ['model1:', 'a1:', 'model2:', 'b1:GET', 'model3:']);
  assert.ok(reads.limitations.some(l => l.includes('a write answered 200 and sent as POST with no override, or as a safe method misused for a write, is not')));
});

test('a queued answer in a spec that splits actions per tool needs deliveredBy, or the case abstains', async t => {
  const split = [{ id: 'credit', pathPrefix: '/tool/issue_credit', rejected: [403] }, { id: 'close', pathPrefix: '/tool/close_ticket', rejected: [403] }, { id: 'deliver', pathPrefix: '/deliver/', rejected: [403] }];
  const desk = { queued: ['issue_credit'], queueMs: 3000 };
  // A slow queue with actions split per tool: the later close is not the credit's delivery, which the settle never sees.
  const ambiguous = await sweep(t, 'queue_no_recheck', { script: 'two_steps', desk, spec: { ...relayOtherTwinSpec('relay-split'), actions: split } });
  assert.equal(ambiguous.report.verdict, 'ABSTAIN');
  assert.deepEqual(ambiguous.report.plan.unreachable, [{ signal: 'signal:202', after: 'credit1', why: 'delivery-ambiguous' }]);
  const declared = await sweep(t, 'queue_no_recheck', { script: 'two_steps', desk, spec: { ...relayOtherTwinSpec('relay-split-db'), actions: split, signals: [{ status: 202, deliveredBy: 'deliver' }] } });
  assert.deepEqual([declared.report.verdict, declared.report.plan.unreachable], ['ABSTAIN', [{ signal: 'signal:202', after: 'credit1' }]]);
});

test('a deliveredBy that names the answering rule never reads NO_FLAG', async t => {
  // A deliveredBy that names the answering rule: the slow defective queue, where the next tool call would pose as the delivery.
  const desk = { queued: ['issue_credit'], queueMs: 3000 };
  await assert.rejects(sweep(t, 'queue_no_recheck', { script: 'two_steps', desk, spec: { ...relayOtherTwinSpec('relay-self'), signals: [{ status: 202, action: 'tool', deliveredBy: 'tool' }] } }),
    /deliveredBy "tool" is the signal's own action/, 'refused before anything runs');
  // Without the action, the default signal matches the tool's 202, and the same-rule delivery is ambiguous at run time.
  const self = await sweep(t, 'queue_no_recheck', { script: 'two_steps', desk, spec: { ...relayOtherTwinSpec('relay-self-default'), signals: [{ status: 202, deliveredBy: 'tool' }] } });
  assert.deepEqual([self.report.verdict, self.report.plan.unreachable], ['ABSTAIN', [{ signal: 'signal:202', after: 'tool1', why: 'delivery-ambiguous' }]]);
});

test('a world that never puts the gate in front of its upstream, or hands back bad credentials, decides nothing', async t => {
  const out = scratch(t);
  const noGate = async () => ({ origin: 'http://127.0.0.1:9', credentials: {}, stop: async () => {} });
  const report = await runSweep({ spec: relaySpec('relay-no-gate'), startWorld: noGate, outDir: join(out, 'a') });
  assert.deepEqual([report.verdict, report.reasons, report.baseline.error], ['ABSTAIN', ['baseline-error', 'no-allowed-use', 'no-boundary'], 'The world never asked for a hold gate, so its upstream calls cannot be observed.']);
  const fresh = relayWorld({ build: 'per_step_validating' });
  const badNames = async gateFor => ({ ...(await fresh(gateFor)), credentials: { API_KEY: 'x' } });
  const bad = await runSweep({ spec: relaySpec('relay-bad-credentials'), startWorld: badNames, outDir: join(out, 'b') });
  assert.deepEqual([bad.verdict, bad.baseline.error], ['ABSTAIN', 'A world\'s credentials must map SCOPEHAVEN_TARGET_ names to strings.']);
  const twoGates = async gateFor => { await gateFor('http://127.0.0.1:9'); await gateFor('http://127.0.0.1:9'); return { origin: 'http://127.0.0.1:9', credentials: {}, stop: async () => {} }; };
  const two = await runSweep({ spec: relaySpec('relay-two-gates'), startWorld: twoGates, outDir: join(out, 'c') });
  assert.deepEqual([two.verdict, two.baseline.error], ['ABSTAIN', 'A world asks for one hold gate.']);
});

test('a run that does not re-check from its sealed windows never counts', async t => {
  const out = scratch(t);
  const onlyBaseline = ({ sequence, ...rest }) => sequence.id.endsWith('-baseline') ? recheckRun({ sequence, ...rest }) : false;
  const executions = await runSweep({ spec: relaySpec('relay-recheck'), startWorld: relayWorld({ build: 'per_step_validating', script: 'one_call' }), outDir: join(out, 'a'), recheck: onlyBaseline });
  assert.equal(executions.verdict, 'ABSTAIN');
  assert.deepEqual(executions.outcomes.map(o => [o.id, o.result, o.reason, o.validated]), ['model1', 'tool1', 'model2'].map(id => [id, 'INCONCLUSIVE', 'run-not-revalidated', false]));
  const baseline = await runSweep({ spec: relaySpec('relay-recheck-b'), startWorld: relayWorld({ build: 'per_step_validating', script: 'one_call' }), outDir: join(out, 'b'), recheck: () => { throw new Error('refused'); } });
  assert.deepEqual([baseline.verdict, baseline.baseline.reasons, baseline.outcomes], ['ABSTAIN', ['baseline-not-revalidated'], []]);
});

test('the CLI starts a fresh world per run from the spec\'s launcher command and exits by verdict', async t => {
  const dir = scratch(t);
  const run = async (build, name) => {
    const specFile = join(dir, `${name}.json`), lines = [];
    writeFileSync(specFile, JSON.stringify(relaySpec(name, { world: { command: [process.execPath, RELAY, '--build', build, '--script', 'one_call'] } })));
    const code = await main(['--spec', specFile, '--out', join(dir, name)], { log: s => lines.push(s) });
    return { code, lines, report: JSON.parse(readFileSync(join(dir, name, 'report.json'), 'utf8')) };
  };
  const clean = await run('per_step_validating', 'cli-clean');
  assert.equal(clean.code, 0, clean.lines.join('\n'));
  assert.match(clean.lines.at(-2), /^Sweep cli-clean: NO_FLAG; 3 boundaries from 3 observed calls; 3 pass, 0 fail, 0 inconclusive$/);
  const defect = await run('per_step_trusting', 'cli-defect');
  assert.equal(defect.code, 1);
  assert.deepEqual(defect.report.reasons, ['tool1:FAIL']);
  const specFile = join(dir, 'no-world.json'), lines = [];
  writeFileSync(specFile, JSON.stringify(relaySpec('no-world')));
  assert.equal(await main(['--spec', specFile, '--out', join(dir, 'x')], { log: s => lines.push(s) }), 2);
  assert.match(lines[0], /needs "world"/);
  assert.equal(await main(['--spec', join(dir, 'cli-clean.json'), '--out', join(dir, 'y'), '--concurrency', '0'], { log: s => lines.push(s) }), 2);
  assert.match(lines.at(-1), /--concurrency must be 1 to 8/);
});

test('the world launcher protocol refuses a non-loopback upstream or origin, bad credential names, an early exit and a slow start', async () => {
  const launcher = (code, startTimeoutMs) => commandWorld({ command: [process.execPath, '-e', code], ...(startTimeoutMs ? { startTimeoutMs } : {}) })(async () => 'http://127.0.0.1:9');
  const answer = reply => `process.stdin.on('data', () => console.log(JSON.stringify(${JSON.stringify(reply)}))); console.log(JSON.stringify({ upstream: 'http://127.0.0.1:9' }));`;
  await assert.rejects(launcher(`console.log(JSON.stringify({ upstream: 'http://10.0.0.1:80' })); setInterval(() => {}, 1000);`), /upstream must be literal loopback/);
  await assert.rejects(launcher(`console.log(JSON.stringify({ upstream: 'http://127.0.0.1:70000' })); setInterval(() => {}, 1000);`), /upstream must be literal loopback/);
  await assert.rejects(launcher(answer({ origin: 'http://localhost:3000', credentials: {} })), /origin must be literal loopback/);
  await assert.rejects(launcher(answer({ origin: 'http://127.0.0.1:3000', credentials: { API_KEY: 'x' } })), /SCOPEHAVEN_TARGET_ names/);
  await assert.rejects(launcher('process.exit(0)'), /exited before it was ready/);
  const slow = Date.now();
  await assert.rejects(launcher('setInterval(() => {}, 1000)', 300), /not ready within 300 ms/);
  assert.ok(Date.now() - slow < 4000, 'the start timeout is the declared one');
  const world = await launcher(answer({ origin: 'http://127.0.0.1:3000', credentials: { SCOPEHAVEN_TARGET_SWEEP_USER: 'u' } }));
  assert.deepEqual([world.origin, world.credentials], ['http://127.0.0.1:3000', { SCOPEHAVEN_TARGET_SWEEP_USER: 'u' }]);
  await world.stop();
  // A launcher that ignores its closed stdin is stopped with SIGTERM, not left to the kill timer.
  const stubborn = await launcher(`${answer({ origin: 'http://127.0.0.1:3000', credentials: {} })} setInterval(() => {}, 1000);`);
  const stopping = Date.now();
  await stubborn.stop();
  assert.ok(Date.now() - stopping < 2500, 'stopped promptly');
  // A shell launcher that leaves a background process holding its output: the stop signals the whole group.
  const shell = await commandWorld({ command: ['/bin/sh', '-c', `sleep 31.7 & echo '{"upstream": "http://127.0.0.1:9"}'; read line; echo '{"origin": "http://127.0.0.1:3000", "credentials": {}}'; wait`] })(async () => 'http://127.0.0.1:9');
  const before = Date.now();
  await shell.stop();
  assert.ok(Date.now() - before < 2500, 'the stop waits for the command, not for every holder of its output');
  await new Promise(r => setTimeout(r, 200));
  assert.notEqual(spawnSync('/usr/bin/pgrep', ['-f', 'sleep 31.7']).status, 0, 'the background process is gone');
});
