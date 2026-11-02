// The mirror phase (src/two-identities.mjs, src/http-connector.mjs, src/contracts.mjs): generated mirrors run after every declared
// check, the final mark, the observers' stop and every actor's identity-refusal probes, outside the identity brackets, between probe
// points of their own. So nothing a mirror sends reaches a declared check's request, window, probe or verdict, and a mirror a per-user
// limit answers reads inconclusive as produced, which the evidence validator recomputes. The app is an owned two-tenant stand-in on
// 127.0.0.1 with a per-user request cap; one test adds a scripted observer over the stand-in's own alert log. No model, provider or
// database.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runHttpAssessment, observeHttp } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile, contractDigest, identityControlPlan, requestPlan, MIRROR_LIMIT_ASSERTION, mirrorLimitActual, IDENTITY_UNPROVEN_DECISION } from '../src/contracts.mjs';
import { mirrorPlan, mirrorReport } from '../src/two-identities.mjs';
import { createRegistry } from '../src/registry.mjs';
import { compareRuns } from '../src/runner.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { digest } from '../src/domain.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { createSuspendDetector, SUSPEND_STOPPED } from '../src/suspend-clock.mjs';
import recordedAtMain from './fixtures/pre-mirror-phase-run-7134a8e9.mjs';

const TOKENS = { ana: 'synthetic-ana-token', gil: 'synthetic-gil-token' };
// One predicate key for every run here (src/contracts.mjs predicate records): runs with mirrors on and off compare their digests.
const ENV = { SCOPEHAVEN_TARGET_ANA: TOKENS.ana, SCOPEHAVEN_TARGET_GIL: TOKENS.gil, SCOPEHAVEN_PREDICATE_KEY: '5c'.repeat(32) };
const control = (id, actorId, path, assertions, extra = {}) => ({ id, title: id, category: 'Identity', severity: 'control', actorId, method: 'GET', path, evidenceRequirement: 'response', assertions, ...extra });
const boundary = (id, actorId, method, path, assertions, extra = {}) => ({ id, title: id, category: 'Tenant', severity: 'high', actorId, method, path, evidenceRequirement: 'response', assertions, ...extra });
const REFUSED = [{ kind: 'status.in', expected: [403, 404] }, { kind: 'json.noForeignValues', pointer: '' }];
const ANSWERED = [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '/reply' }];
const MIRRORS = Object.freeze({ counterparts: [['ORD-1001', 'ORD-2002']], readOnlyRoutes: ['POST /api/chat'] });
// The desk of test/two-identities.test.mjs, with a turn of gil's that is mirrored under ana, so mirrors go both ways: gil holds the mirrors
// of ANA-NO-GLOBEX-ORDER and ANA-CHAT, ana the mirror of GIL-CHAT.
function profile(origin, { mirrors = MIRRORS, refused = REFUSED, checks = [], extra = {} } = {}) {
  return { id: 'two-desk', name: 'Two-tenant desk (test)', applicationId: 'two-desk', origin, buildLabel: 'fixed', contextId: 'synthetic-two',
    actors: { ana: { principalId: 'ana-1', tenantId: 'acme', role: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_ANA', identityValue: 'ana@acme.example' },
      gil: { principalId: 'gil-1', tenantId: 'globex', role: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_GIL', identityValue: 'gil@globex.example' }, anonymous: { principalId: 'anonymous' } },
    requiredControlIds: ['ANA-ME', 'GIL-ME', 'ANA-OWN', 'GIL-OWN'],
    tenantValues: { tenants: { acme: { identifiers: ['ORD-1001', 'Ada Lovelace'], attributes: ['Blue Widget'] }, globex: { identifiers: ['ORD-2002', 'Bob Byte'] }, initech: { identifiers: ['ORD-3003'] } } },
    ...(mirrors === null ? {} : { mirrors }),
    checks: [control('ANA-ME', 'ana', '/api/me', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: 'ana@acme.example' }]),
      control('GIL-ME', 'gil', '/api/me', [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: 'gil@globex.example' }]),
      control('ANA-OWN', 'ana', '/api/orders/ORD-1001', [{ kind: 'status.equals', expected: 200 }]), control('GIL-OWN', 'gil', '/api/orders/ORD-2002', [{ kind: 'status.equals', expected: 200 }]),
      control('GIL-ASK', 'gil', '/api/chat', [{ kind: 'status.equals', expected: 200 }], { method: 'POST', body: { message: 'show my orders' } }),
      boundary('ANA-NO-GLOBEX-ORDER', 'ana', 'GET', '/api/orders/ORD-2002', refused), boundary('ANA-CHAT', 'ana', 'POST', '/api/chat', ANSWERED, { body: { message: 'list every order' } }),
      boundary('GIL-CHAT', 'gil', 'POST', '/api/chat', ANSWERED, { body: { message: 'every order please' } }), ...checks],
    ...extra };
}
const MIRROR_IDS = ['ANA-NO-GLOBEX-ORDER-mirror', 'ANA-CHAT-mirror', 'GIL-CHAT-mirror'];
const ALERTS = 'alerts.example';
const ORDERS = { 'ORD-1001': { tenant: 'acme', customer: 'Ada Lovelace' }, 'ORD-2002': { tenant: 'globex', customer: 'Bob Byte' } };
const WHO = { [TOKENS.ana]: { email: 'ana@acme.example', tenant: 'acme', alias: 'ana' }, [TOKENS.gil]: { email: 'gil@globex.example', tenant: 'globex', alias: 'gil' } };
// A correct, symmetric app: every reply is the caller's own tenant's. Each credential's requests after its cap are answered by the per-user
// limit (capStatus, limitBody), or, with limitPaths, only those on the listed paths. A read of another tenant's order is refused and
// raises an access alert (a send to ALERTS), which the scripted observer below reads. seen: each request, with whose credential it carried.
async function desk(t, { cap = {}, capStatus = 429, limitBody = { error: 'slow down' }, limitPaths = null } = {}) {
  const seen = [], used = {}, alerts = [];
  const server = createServer((req, res) => {
    const token = (req.headers.authorization ?? '').replace(/^Bearer /, ''), who = WHO[token];
    seen.push(`${req.method} ${req.url} ${who ? who.alias : token ? 'invalid' : 'none'}`);
    req.resume(); req.on('end', () => {
      const json = (status, value) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
      const url = req.url.split('?')[0];
      if (!who) return json(401, { error: 'sign in' });
      used[who.alias] = (used[who.alias] ?? 0) + 1;
      if (Number.isInteger(cap[who.alias]) && used[who.alias] > cap[who.alias] && (limitPaths === null || limitPaths.includes(url))) return json(capStatus, limitBody);
      if (url === '/api/me') return json(200, { email: who.email });
      const mine = id => ORDERS[id].tenant === who.tenant;
      const order = /^\/api\/orders\/(ORD-\d{4})$/.exec(url);
      if (order && ORDERS[order[1]] && mine(order[1])) return json(200, { id: order[1], customer: ORDERS[order[1]].customer });
      if (order && ORDERS[order[1]]) alerts.push({ name: ALERTS, resource: 'POST /v1/alerts' });
      if (order) return json(404, { error: 'not found' });
      if (req.method === 'POST' && url === '/api/chat') return json(200, { reply: `Your orders: ${Object.keys(ORDERS).filter(mine).join(' ')}`, user: who.email });
      json(404, { error: 'not found' });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { origin: `http://127.0.0.1:${server.address().port}`, seen, used, alerts };
}
const validated = p => validateTargetFile({ schemaVersion: 1, targets: [p] })[0];
const suiteOf = p => createRegistry({ profiles: [p], env: ENV }).exportSuite(p.id);
const rowOf = (run, id) => run.results.find(r => r.id === id);
const gateOf = (run, p) => { const g = summarizeGate({ candidate: run, expectedSuite: suiteOf(p) }); return { exitCode: g.exitCode, reasons: g.reasons }; };
const valid = (run, p) => { validateHttpRunEvidence(run); validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) }); return true; };
// What a row decided, and an actor's identity evidence, without the per-run noise (request ids, keyed route digests, seals, durations).
const decided = row => ({ id: row.id, status: row.status, decision: row.decision, summary: row.summary, assertions: row.assertions, observed: row.observed, requestTimeoutMs: row.trace[0].data.requestTimeoutMs });
const probeView = probe => ({ controlId: probe.controlId, kind: probe.kind, httpStatus: probe.httpStatus, outcome: probe.outcome, statusOutcome: probe.statusOutcome, predicates: probe.predicates, crossActorId: probe.crossActorId, requestTimeoutMs: probe.requestTimeoutMs });
const identityView = run => run.identityEvidence.actors.map(({ mirrorPhase: _phase, ...entry }) => ({ ...entry, ...Object.fromEntries(['before', 'after', 'anonymous', 'invalid', 'cross'].map(k => [k, entry[k].map(probeView)])),
  between: entry.between.map(point => ({ afterCheckId: point.afterCheckId, probes: point.probes.map(probeView) })) }));
// The declared profile's own request count per credential, measured on an uncapped desk with mirrors off.
async function ownCount(t) { const d = await desk(t); await runHttpAssessment(profile(d.origin, { mirrors: 'off' }), { env: ENV }); return { ...d.used }; }

test('a per-user cap at the declared profile\'s own request count: with mirrors on every declared check, both identities and the gate\'s reasons stay as with mirrors off, and the mirrors read inconclusive (rate-limited), never FAIL', async t => {
  const cap = await ownCount(t);
  const offApp = await desk(t, { cap }), off = await runHttpAssessment(profile(offApp.origin, { mirrors: 'off' }), { env: ENV });
  assert.deepEqual(off.results.map(r => [r.id, r.status]).filter(([, s]) => s !== 'pass'), [], 'green with mirrors off');
  assert.deepEqual(gateOf(off, profile(offApp.origin, { mirrors: 'off' })), { exitCode: 0, reasons: [] });
  const app = await desk(t, { cap }), p = profile(app.origin), run = await runHttpAssessment(p, { env: ENV });
  // Every declared row, and each identity's whole declared evidence (its reason, every bracket and refusal probe), as with mirrors off.
  assert.deepEqual(run.results.filter(r => !MIRROR_IDS.includes(r.id)).map(decided), off.results.map(decided));
  assert.deepEqual(identityView(run), identityView(off));
  assert.deepEqual(run.identityEvidence.actors.map(a => [a.actorId, a.reason]), [['ana', 'established'], ['gil', 'established']]);
  // The app saw the declared profile's requests in the same order, refusal probes included, and only then the mirror phase.
  assert.deepEqual(app.seen.slice(0, offApp.seen.length), offApp.seen);
  assert.deepEqual(app.seen.slice(offApp.seen.length).map(s => s.split(' ').at(-1)), [...Array(8).fill('gil'), ...Array(5).fill('ana')], 'gil\'s two mirrors and points, then ana\'s one');
  // check-config's extraRequests is what the mirror phase sent.
  assert.deepEqual(mirrorReport(validated(p), identityControlPlan(validated(p))).extraRequests.map(e => [e.actorId, e.requests]), [['ana', 5], ['gil', 8]]);
  assert.deepEqual([app.used.ana - cap.ana, app.used.gil - cap.gil], [5, 8]);
  for (const id of MIRROR_IDS) {
    const row = rowOf(run, id), status = row.assertions.find(a => a.name === 'HTTP status matches contract'), limit = row.assertions.find(a => a.name === MIRROR_LIMIT_ASSERTION);
    assert.deepEqual([row.status, row.decision, status.status, status.actual], ['inconclusive', 'inconclusive', 'inconclusive', 'HTTP 429'], id);
    assert.deepEqual([limit.status, limit.actual], ['inconclusive', mirrorLimitActual(429)], id);
    assert.equal(row.trace[0].data.mirrorOf, id.replace(/-mirror$/, ''));
  }
  assert.deepEqual(run.mirrorPhase, { rateLimitStatuses: [429] });
  assert.equal(valid(run, p), true, 'the rate-limited rows are accepted as produced, with and without the suite');
  assert.deepEqual(gateOf(run, p), { exitCode: 1, reasons: ['inconclusive-evidence'] }, 'only the mirrors\' inconclusive rows, never identity-not-established');
  // The request bound counts the mirror phase the same way: gil's 2 mirrors take 3 points of 2 controls, ana's 1 mirror 2 points of 2.
  const bound = requestPlan(validated(p)).probePointRequests - requestPlan(validated(profile(app.origin, { mirrors: 'off' }))).probePointRequests;
  assert.equal(bound, 3 * 2 + 2 * 2);
});

test('a limit that answers 403 is a boundary status: the declared checks still stay as with mirrors off, a mirror-phase point it refuses withholds only mirror rows, and a success mirror\'s 403 stays a FAIL (docs/KNOWN-LIMITS.md)', async t => {
  const cap = await ownCount(t);
  const offApp = await desk(t, { cap, capStatus: 403 }), off = await runHttpAssessment(profile(offApp.origin, { mirrors: 'off' }), { env: ENV });
  const app = await desk(t, { cap, capStatus: 403 }), p = profile(app.origin), run = await runHttpAssessment(p, { env: ENV });
  assert.deepEqual(run.results.filter(r => !MIRROR_IDS.includes(r.id)).map(decided), off.results.map(decided));
  assert.deepEqual(identityView(run), identityView(off));
  // The refusal mirror's 403 matched its contract, but the points around it were refused with gil's own credential: withheld, never a pass.
  assert.deepEqual([rowOf(run, 'ANA-NO-GLOBEX-ORDER-mirror').status, rowOf(run, 'ANA-NO-GLOBEX-ORDER-mirror').decision], ['inconclusive', IDENTITY_UNPROVEN_DECISION]);
  // A 403 cannot be declared a limit answer (a refusal mirror expects it), so the success mirrors read FAIL on it: the documented limit.
  assert.deepEqual(['ANA-CHAT-mirror', 'GIL-CHAT-mirror'].map(id => rowOf(run, id).status), ['fail', 'fail']);
  assert.equal(valid(run, p), true);
  // Room for gil's first mirror and the point after it: that mirror is answered by the app (404) between two passing points, and the
  // limit refuses the point after gil's last mirror. A refusal at any mirror-phase point withholds every mirror row of the actor.
  const roomApp = await desk(t, { cap: { ...cap, gil: cap.gil + 5 }, capStatus: 403 }), room = await runHttpAssessment(profile(roomApp.origin), { env: ENV });
  const gil = room.identityEvidence.actors.find(a => a.actorId === 'gil').mirrorPhase;
  assert.deepEqual([gil.before.map(x => x.outcome), gil.between[0].probes.map(x => x.outcome), gil.after.map(x => x.httpStatus)], [['pass', 'pass'], ['pass', 'pass'], [403, 403]]);
  const first = rowOf(room, 'ANA-NO-GLOBEX-ORDER-mirror');
  assert.deepEqual([first.trace[0].data.httpStatus, first.status, first.decision], [404, 'inconclusive', IDENTITY_UNPROVEN_DECISION]);
  assert.deepEqual(room.results.filter(r => !MIRROR_IDS.includes(r.id)).map(decided), off.results.map(decided));
  assert.equal(valid(room, profile(roomApp.origin)), true);
  // The same room, the limit answering only the identity route, or only the surface route: a refusal of either probe at a point that does
  // not cover gil's first mirror still withholds it (each half of the rule alone).
  for (const [route, refusedControl] of [['/api/me', 'GIL-ME'], ['/api/orders/ORD-2002', 'GIL-OWN']]) {
    const halfApp = await desk(t, { cap: { ...cap, gil: cap.gil + 5 }, capStatus: 403, limitPaths: [route] }), half = await runHttpAssessment(profile(halfApp.origin), { env: ENV });
    const after = half.identityEvidence.actors.find(a => a.actorId === 'gil').mirrorPhase.after;
    assert.deepEqual(after.map(x => [x.controlId, x.httpStatus]), [['GIL-ME', refusedControl === 'GIL-ME' ? 403 : 200], ['GIL-OWN', refusedControl === 'GIL-OWN' ? 403 : 200]], route);
    assert.deepEqual([rowOf(half, 'ANA-NO-GLOBEX-ORDER-mirror').trace[0].data.httpStatus, rowOf(half, 'ANA-NO-GLOBEX-ORDER-mirror').decision], [404, IDENTITY_UNPROVEN_DECISION], route);
    assert.deepEqual(half.results.filter(r => !MIRROR_IDS.includes(r.id)).map(decided), off.results.map(decided), route);
    assert.equal(valid(half, profile(halfApp.origin)), true);
  }
  assert.deepEqual(gateOf(off, profile(offApp.origin, { mirrors: 'off' })), { exitCode: 0, reasons: [] });
  assert.equal(gateOf(run, p).reasons.includes('identity-not-established'), false);
});

test('a declared rate-limit status, a limit\'s body that names the other tenant, and a refusal\'s own body predicate', async t => {
  const cap = await ownCount(t);
  // Declared: a 503 limit answer reads as 429 does, and the run and its suite carry the statuses it was read under.
  const declared = { ...MIRRORS, rateLimitStatuses: [503] };
  const app = await desk(t, { cap, capStatus: 503 }), p = profile(app.origin, { mirrors: declared }), run = await runHttpAssessment(p, { env: ENV });
  assert.deepEqual(MIRROR_IDS.map(id => rowOf(run, id).status), ['inconclusive', 'inconclusive', 'inconclusive']);
  assert.equal(rowOf(run, 'ANA-CHAT-mirror').assertions.find(a => a.name === MIRROR_LIMIT_ASSERTION).actual, mirrorLimitActual(503));
  assert.deepEqual([run.mirrorPhase, suiteOf(p).mirrorPhase], [{ rateLimitStatuses: [429, 503] }, { rateLimitStatuses: [429, 503] }]);
  assert.equal(valid(run, p), true);
  // Control: the same 503 without the declaration is not a limit answer.
  const plainApp = await desk(t, { cap, capStatus: 503 }), plain = await runHttpAssessment(profile(plainApp.origin), { env: ENV });
  assert.deepEqual(MIRROR_IDS.map(id => rowOf(plain, id).status), ['fail', 'fail', 'fail']);
  // A limit answer that names the other tenant's record is still a leak: json.noForeignValues fails, and the mirror reads FAIL.
  const leakApp = await desk(t, { cap, limitBody: { error: 'slow down', reply: 'ORD-1001 Ada Lovelace' } }), leak = await runHttpAssessment(profile(leakApp.origin), { env: ENV });
  assert.deepEqual(['ANA-NO-GLOBEX-ORDER-mirror', 'ANA-CHAT-mirror'].map(id => rowOf(leak, id).status), ['fail', 'fail'], 'gil\'s mirrors read acme\'s values in the limit\'s body');
  assert.equal(rowOf(leak, 'ANA-CHAT-mirror').assertions.find(a => a.name.startsWith('json.noForeignValues')).status, 'fail');
  assert.equal(valid(leak, profile(leakApp.origin)), true);
  // A refusal mirror keeps its refusal's own body predicate; on a limit's body it fails, and the mirror still reads inconclusive.
  const withError = [{ kind: 'status.in', expected: [403, 404] }, { kind: 'json.exists', pointer: '/error', expected: true }, { kind: 'json.noForeignValues', pointer: '' }];
  const bodyApp = await desk(t, { cap, limitBody: { message: 'slow down' } }), q = profile(bodyApp.origin, { refused: withError }), body = await runHttpAssessment(q, { env: ENV });
  const mirror = rowOf(body, 'ANA-NO-GLOBEX-ORDER-mirror');
  assert.equal(mirror.assertions.find(a => a.name === 'json.exists predicate 1').status, 'fail');
  assert.equal(mirror.status, 'inconclusive');
  assert.equal(rowOf(body, 'ANA-NO-GLOBEX-ORDER').status, 'pass', 'the declared refusal answered with its own body');
  assert.equal(valid(body, q), true);
});

test('the declared checks keep the budget they have with mirrors off, and the mirror phase has its own after it', async t => {
  // A virtual run clock on which every request takes 2.3 s, so the declared run's 60 s deadline shows in the timeouts the last requests get.
  const timed = () => { let now = 0; return { clock: { now: () => now, sleep: async ms => { now += ms; } }, transport: async (origin, check, options) => { now += 2300; return observeHttp(origin, check, options); } }; };
  const offApp = await desk(t), offTimed = timed(), off = await runHttpAssessment(profile(offApp.origin, { mirrors: 'off' }), { env: ENV, ...offTimed });
  const app = await desk(t), onTimed = timed(), run = await runHttpAssessment(profile(app.origin), { env: ENV, ...onTimed });
  const shortened = off.identityEvidence.actors.flatMap(a => [...a.anonymous, ...a.invalid, ...a.cross]).filter(probe => probe.requestTimeoutMs < 3000);
  assert(shortened.length > 0, 'the deadline is visible: the last refusal probes got less than a full request budget');
  assert.deepEqual(run.results.filter(r => !MIRROR_IDS.includes(r.id)).map(decided), off.results.map(decided));
  assert.deepEqual(identityView(run), identityView(off));
  // Every mirror and mirror-phase probe was sent with its full budget, although the clock was past the declared deadline by then.
  for (const id of MIRROR_IDS) assert.deepEqual([rowOf(run, id).trace[0].data.requestAttempted, rowOf(run, id).trace[0].data.requestTimeoutMs], [true, 3000], id);
  assert.equal(run.identityEvidence.actors.flatMap(a => [...a.mirrorPhase.before, ...a.mirrorPhase.between.flatMap(p => p.probes), ...a.mirrorPhase.after]).every(probe => probe.requestTimeoutMs === 3000), true);
  assert.equal(valid(run, profile(app.origin)), true);
});

test('mirrors that declare their own timeouts take nothing from the declared budget', async t => {
  // The chat checks declare 20 s, so their mirrors do too; on a virtual clock at 4 s a request the declared run's deadline is reached.
  const slow = p => ({ ...p, checks: p.checks.map(c => (c.path === '/api/chat' && c.severity !== 'control' ? { ...c, timeoutMs: 20000 } : c)) });
  const timed = () => { let now = 0; return { clock: { now: () => now, sleep: async ms => { now += ms; } }, transport: async (origin, check, options) => { now += 4000; return observeHttp(origin, check, options); } }; };
  const offApp = await desk(t), off = await runHttpAssessment(slow(profile(offApp.origin, { mirrors: 'off' })), { env: ENV, ...timed() });
  const app = await desk(t), p = slow(profile(app.origin)), run = await runHttpAssessment(p, { env: ENV, ...timed() });
  assert.equal(rowOf(run, 'ANA-CHAT-mirror').trace[0].data.requestTimeoutMs, 20000, 'the mirror carries its source\'s timeout');
  assert(off.identityEvidence.actors.flatMap(a => [...a.anonymous, ...a.invalid, ...a.cross]).some(probe => probe.requestTimeoutMs < 3000 || !probe.requestAttempted), 'the deadline is visible');
  assert.deepEqual(run.results.filter(r => !MIRROR_IDS.includes(r.id)).map(decided), off.results.map(decided));
  assert.deepEqual(identityView(run), identityView(off));
  assert.equal(valid(run, p), true);
});

// An in-process app on a virtual host whose first wait a host suspend overlaps (the virtual host of test/suspend-f4d.test.mjs), with an
// observed check first, so its settle extension is where the run's later time is kept.
function sleepyHost(asleepMs) {
  const v = { now: 1000, suspended: 0, sleeps: 0 };
  v.awake = () => v.now - v.suspended;
  v.clock = { now: () => v.now, sleep: async ms => { v.sleeps++; if (v.sleeps === 1) { v.now += Math.max(ms, 500 + asleepMs); v.suspended += asleepMs; } else v.now += ms; await null; } };
  v.transport = async (_origin, check, { credential }) => {
    v.now += 20;
    const who = WHO[credential], url = check.path.split('?')[0], ok = (status, json) => ({ status, complete: true, jsonParsed: true, json, bytes: JSON.stringify(json).length });
    if (!who) return ok(401, { error: 'sign in' });
    if (url === '/api/me') return ok(200, { email: who.email });
    const order = /^\/api\/orders\/(ORD-\d{4})$/.exec(url);
    if (order && ORDERS[order[1]]?.tenant === who.tenant) return ok(200, { id: order[1] });
    if (order) return ok(404, { error: 'not found' });
    if (check.method === 'POST' && url === '/api/chat') return ok(200, { reply: `Your orders: ${Object.keys(ORDERS).filter(id => ORDERS[id].tenant === who.tenant).join(' ')}` });
    return ok(404, { error: 'not found' });
  };
  v.observers = configs => configs.map(c => ({ kind: OBSERVER_OUTPUT[c.type].kind, instanceId: `${c.type}-${c.id}`, source: OBSERVER_OUTPUT[c.type].source, scope: { operations: ['send'], names: [ALERTS], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
    async start() {}, async stop() {}, async mark() { return { at: v.awake() }; }, async collect() { return { events: [], coverage: 'complete', reason: null }; } }));
  v.suspendClock = createSuspendDetector({ wall: () => 1.7e12 + v.now, awake: v.awake, elapsed: () => v.now, timersCountSuspend: true });
  return v;
}
test('a host suspend in a declared settle stops the run where it would with mirrors off: no declared wait keeps time for mirrors', async () => {
  const sleepy = (mirrors, asleepMs) => {
    const p = profile('http://127.0.0.1:9', { mirrors, extra: { observers: [{ ...SINK, settleMs: 5000 }] } });
    p.checks = [...p.checks.slice(0, 4), NO_ALERT, ...p.checks.slice(4)];
    const v = sleepyHost(asleepMs);
    return runHttpAssessment(p, { env: ENV, clock: v.clock, transport: v.transport, observerFactory: v.observers, suspendClock: v.suspendClock }).then(run => ({ p, run }));
  };
  const stoppedAt = run => run.results.filter(r => r.trace?.[0]?.data?.notSent === SUSPEND_STOPPED).map(r => r.id);
  // Swept across the range where a settle's spare budget sits between its owed time and that plus the mirrors' requests.
  for (const asleepMs of [6000, 9000, 12000, 13500, 15000, 16500, 18000, 19500, 21000, 30000]) {
    const off = await sleepy('off', asleepMs), on = await sleepy(undefined, asleepMs);
    assert.deepEqual(on.run.results.filter(r => !MIRROR_IDS.includes(r.id)).map(decided), off.run.results.map(decided), `asleep ${asleepMs} ms`);
    assert.equal(valid(on.run, on.p), true);
    // Once a suspend has stopped the run, every mirror is not sent either (the connector's not-sent mirror row, which records mirrorOf).
    if (stoppedAt(off.run).length) assert.deepEqual(stoppedAt(on.run), [...stoppedAt(off.run), ...MIRROR_IDS], `asleep ${asleepMs} ms`);
  }
  assert((await sleepy('off', 30000)).run.results.some(r => r.trace?.[0]?.data?.notSent === SUSPEND_STOPPED), 'the longest suspend stops the run');
});

test('a declared check a per-user limit answers still reads as it does with mirrors off, and the run validates', async t => {
  const own = await ownCount(t), cap = { ...own, gil: own.gil - 4 };
  const offApp = await desk(t, { cap }), off = await runHttpAssessment(profile(offApp.origin, { mirrors: 'off' }), { env: ENV });
  const app = await desk(t, { cap }), p = profile(app.origin), run = await runHttpAssessment(p, { env: ENV });
  const limited = run.results.filter(r => !MIRROR_IDS.includes(r.id) && r.trace[0].data.httpStatus === 429);
  assert(limited.length > 0 && limited.every(r => r.status === 'fail' && !r.assertions.some(a => a.name === MIRROR_LIMIT_ASSERTION)), 'a declared row answered 429 is never read as rate-limited');
  assert.deepEqual(run.results.filter(r => !MIRROR_IDS.includes(r.id)).map(decided), off.results.map(decided));
  assert.equal(valid(run, p), true);
});

test('a limit that runs out just after a mirror the app answered: that mirror is withheld, and the gate adds prohibition-observed-identity-unproven, and comparison-incomplete against a baseline', async t => {
  // One desk for both runs (the same origin, so the baseline is comparable): no limit for the baseline, then room for gil's first mirror only.
  const own = await ownCount(t), cap = {}, app = await desk(t, { cap }), p = profile(app.origin);
  const baseline = await runHttpAssessment(p, { env: ENV });
  for (const key of Object.keys(app.used)) delete app.used[key];
  Object.assign(cap, { ...own, gil: own.gil + 3 });
  const run = await runHttpAssessment(p, { env: ENV });
  assert.deepEqual([rowOf(run, 'ANA-NO-GLOBEX-ORDER-mirror').trace[0].data.httpStatus, rowOf(run, 'ANA-NO-GLOBEX-ORDER-mirror').decision], [404, IDENTITY_UNPROVEN_DECISION]);
  assert.deepEqual(run.results.filter(r => !MIRROR_IDS.includes(r.id)).map(r => [r.id, r.status]), baseline.results.filter(r => !MIRROR_IDS.includes(r.id)).map(r => [r.id, r.status]));
  assert.deepEqual(gateOf(baseline, p), { exitCode: 0, reasons: [] });
  assert.deepEqual(gateOf(run, p), { exitCode: 1, reasons: ['inconclusive-evidence', 'prohibition-observed-identity-unproven'] });
  const compared = summarizeGate({ candidate: run, baseline, expectedSuite: suiteOf(p) });
  assert.deepEqual([compared.exitCode, compared.reasons], [1, ['inconclusive-evidence', 'prohibition-observed-identity-unproven', 'comparison-incomplete']]);
});

// A row resealed after an edit, as the connector seals it (no effect trace on these rows).
const reseal = row => { row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions }); };
const edited = (run, edit) => { const copy = structuredClone(run); edit(copy); return copy; };
test('the evidence validator recomputes the mirror phase: the rate-limited row as produced, and every edit of it refused', async t => {
  const cap = await ownCount(t), app = await desk(t, { cap }), p = profile(app.origin), run = await runHttpAssessment(p, { env: ENV }), suite = suiteOf(p);
  const refused = (copy, code = /invalid-run-evidence|unexpected-suite-evidence/, withSuite = false) => assert.throws(() => validateHttpRunEvidence(copy, withSuite ? { expectedSuite: suite } : {}), code);
  // Control first: the run as produced.
  assert.equal(valid(run, p), true);
  // Each property, one edit at a time.
  refused(edited(run, r => { const m = rowOf(r, 'ANA-CHAT-mirror'); m.assertions.find(a => a.name === 'HTTP status matches contract').status = 'fail'; m.status = 'fail'; m.decision = 'fail'; reseal(m); }));
  refused(edited(run, r => { const m = rowOf(r, 'ANA-CHAT-mirror'); m.assertions = m.assertions.filter(a => a.name !== MIRROR_LIMIT_ASSERTION); reseal(m); }));
  refused(edited(run, r => { const m = rowOf(r, 'ANA-CHAT-mirror'); m.assertions.find(a => a.name === MIRROR_LIMIT_ASSERTION).actual = mirrorLimitActual(503); reseal(m); }));
  refused(edited(run, r => { const d = rowOf(r, 'ANA-NO-GLOBEX-ORDER'); d.assertions.push(structuredClone(rowOf(r, 'ANA-CHAT-mirror').assertions.find(a => a.name === MIRROR_LIMIT_ASSERTION))); d.status = 'inconclusive'; d.decision = 'inconclusive'; reseal(d); }), /invalid-run-evidence/);
  refused(edited(run, r => { const m = rowOf(r, 'ANA-CHAT-mirror'); delete m.trace[0].data.mirrorOf; reseal(m); }), /invalid-run-evidence/);
  refused(edited(run, r => { const m = rowOf(r, 'GIL-CHAT-mirror'); m.trace[0].data.mirrorOf = 'ANA-CHAT'; reseal(m); }), /invalid-run-evidence/);
  refused(edited(run, r => { delete r.mirrorPhase; }), /invalid-run-evidence/);
  refused(edited(run, r => { r.mirrorPhase.rateLimitStatuses = [503]; }), /invalid-run-evidence/);
  refused(edited(run, r => { r.mirrorPhase.rateLimitStatuses = [429, 403]; }), /invalid-run-evidence/);
  refused(edited(run, r => { r.mirrorPhase.rateLimitStatuses = [429, 503]; }), /unexpected-suite-evidence/, true);
  refused(edited(run, r => { const gil = r.identityEvidence.actors.find(a => a.actorId === 'gil'); gil.between.push(gil.mirrorPhase.between.shift()); }), /invalid-run-evidence/);
  refused(edited(run, r => { delete r.identityEvidence.actors.find(a => a.actorId === 'ana').mirrorPhase; }), /invalid-run-evidence/);
  // gil's mirror-phase points edited to pass: its mirror rows' recomputed identity no longer matches the identity assertion they carry.
  const passed = probe => Object.assign(probe, { outcome: 'pass', statusOutcome: 'pass', httpStatus: 200, predicates: probe.predicates.map(x => ({ ...x, outcome: 'pass' })) });
  refused(edited(run, r => { const phase = r.identityEvidence.actors.find(a => a.actorId === 'gil').mirrorPhase; [...phase.before, ...phase.between.flatMap(point => point.probes), ...phase.after].forEach(passed); }), /invalid-run-evidence/);
  // The suite binds which checks are mirrors.
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: { ...suite, checks: suite.checks.map(({ mirrorOf: _m, ...c }) => c) } }), /unexpected-suite-evidence/);
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: { ...suite, mirrorPhase: undefined } }), /unexpected-suite-evidence/);
  assert.deepEqual(suite.checks.filter(c => c.mirrorOf).map(c => [c.id, c.mirrorOf]), MIRROR_IDS.map(id => [id, id.replace(/-mirror$/, '')]));
});

// A scripted egress observer over the desk's own alert log: each mark is the log's length, each window the alerts between two marks.
const scriptedSink = app => configs => configs.map(c => {
  const out = OBSERVER_OUTPUT[c.type], instanceId = `${c.type}-${c.id}`;
  return { kind: out.kind, instanceId, source: out.source, scope: { operations: ['send'], names: [ALERTS], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
    async start() {}, async stop() {}, async mark() { return { at: app.alerts.length }; },
    async collect(from, to) { return { events: app.alerts.slice(from.at, to.at).map((e, i) => makeEffect({ source: out.source, observer: { kind: out.kind, instanceId }, seq: from.at + i + 1, outcome: 'committed', actor: null, operation: 'send', ...e })), coverage: 'complete', reason: null }; } };
});
const SINK = { id: 'sink', type: 'egress-recorder', port: 40997, destinations: [{ host: ALERTS }], settleMs: 250, quietMs: 150 };
// The last declared check: a refusal of a record no tenant holds, which must raise no alert. Its effect.none reads every later gap.
const NO_ALERT = boundary('ANA-NO-INITECH', 'ana', 'GET', '/api/orders/ORD-3003', [{ kind: 'status.equals', expected: 404 }], { effects: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: ALERTS } }] });
test('a mirror\'s request never lands in a declared window: a read that writes, sent in the mirror phase, is after the final mark', async t => {
  const observed = (origin, mirrors, checks = []) => profile(origin, { mirrors, checks: [NO_ALERT, ...checks], extra: { observers: [SINK] } });
  const assess = async (mirrors, checks) => { const app = await desk(t), p = observed(app.origin, mirrors, checks); return { app, p, run: await runHttpAssessment(p, { env: ENV, observerFactory: scriptedSink(app) }) }; };
  const runEndAlerts = run => run.settlement.gaps.at(-1).windows.flatMap(w => w.events).length;
  // Control first: a declared read that writes, sent after the observed check, lands in the run-end gap and unsettles its absence.
  const control = await assess('off', [boundary('GIL-READS-ACME', 'gil', 'GET', '/api/orders/ORD-1001', REFUSED)]);
  assert.equal(runEndAlerts(control.run), 1);
  assert.equal(rowOf(control.run, 'ANA-NO-INITECH').status, 'inconclusive');
  const off = await assess('off'), on = await assess(undefined);
  assert.equal(rowOf(off.run, 'ANA-NO-INITECH').status, 'pass');
  // With mirrors on, the same read is the mirror of ANA-NO-GLOBEX-ORDER: sent, and alerted, after the observers stopped.
  assert(on.app.seen.includes('GET /api/orders/ORD-1001 gil'), 'the mirror was sent');
  assert.equal(on.app.alerts.length, off.app.alerts.length + 1, 'and it raised its alert');
  assert.equal(runEndAlerts(on.run), 0);
  assert.deepEqual(on.run.results.filter(r => !MIRROR_IDS.includes(r.id)).map(decided), off.run.results.map(decided));
  assert.deepEqual(on.run.settlement.gaps.map(g => g.windows.flatMap(w => w.events).length), off.run.settlement.gaps.map(g => g.windows.flatMap(w => w.events).length));
  assert.equal(valid(on.run, on.p), true);
});

test('a run recorded and sealed by an earlier build before the mirror phase still validates at the head and compares', () => {
  const { recordedAt, declared, undeclared } = structuredClone(recordedAtMain);
  assert.equal(recordedAt, '7134a8e9');
  for (const { run, suite } of [declared, undeclared]) {
    assert.equal(run.evaluatorHash.slice(0, 8), 'f228ce9b');
    validateHttpRunEvidence(run);
    validateHttpRunEvidence(run, { expectedSuite: suite });
    assert.equal(compareRuns(run, run).compatible, true);
  }
  // The earlier build ran the declared target's mirrors as ordinary bracketed checks, which its rows record nothing about.
  assert.equal(declared.run.results.some(r => Object.hasOwn(r.trace[0].data, 'mirrorOf')), false);
  assert.equal(declared.run.identityEvidence.actors.find(a => a.actorId === 'gil').between.length, 3);
  // This head's suite for the declared target binds its mirrors (mirrorOf and the rate-limit statuses), so the earlier build's run is refused against
  // it, as against any suite after an identity rule change; the undeclared target's suite is the earlier build's, and the earlier build's run validates against it.
  const here = suiteOf(declared.profile);
  assert.deepEqual(Object.keys(here).filter(k => JSON.stringify(here[k]) !== JSON.stringify(declared.suite[k])), ['checks', 'mirrorPhase']);
  assert.deepEqual(here.checks.map(({ mirrorOf: _m, ...c }) => c), declared.suite.checks);
  assert.throws(() => validateHttpRunEvidence(declared.run, { expectedSuite: here }), /unexpected-suite-evidence/);
  validateHttpRunEvidence(undeclared.run, { expectedSuite: suiteOf(undeclared.profile) });
});

const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const spawned = args => new Promise(resolve => {
  const child = spawn(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH, ...ENV } });
  let stdout = '', stderr = ''; child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
  child.on('close', status => resolve({ status, stdout, stderr }));
});
// Fields of a run that differ between any two runs, or with the origin's port, or with the evaluator identity.
const VOLATILE = new Set(['id', 'createdAt', 'durationMs', 'requestId', 'routeSegments', 'sentRoute', 'bodyKeys', 'evidenceDigest', 'profileHash', 'targetConfigHash', 'evaluatorHash']);
const steady = run => JSON.parse(JSON.stringify(run, (key, value) => (VOLATILE.has(key) ? '<volatile>' : value)));
test('a target without "mirrors" stays byte for byte the earlier build\'s: its checks, order, digest, suite, requests, CLI output and run, apart from evaluatorHash', async t => {
  const main = structuredClone(recordedAtMain.undeclared), v = validated(main.profile);
  assert.deepEqual(v.checks, main.checks);
  assert.equal(contractDigest(v), main.contractDigest);
  assert.equal(main.run.profileHash, main.contractDigest);
  assert.deepEqual(suiteOf(main.profile), main.suite);
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven mirror phase ')); chmodSync(dir, 0o700);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'profiles.json'), JSON.stringify({ schemaVersion: 1, targets: [main.profile] }));
  for (const flag of ['--check-config', '--list']) {
    const r = await spawned(['--config', join(dir, 'profiles.json'), flag]);
    assert.deepEqual({ status: r.status, stderr: r.stderr, target: JSON.parse(r.stdout).targets.find(x => x.id === 'two-desk') }, main.cli[flag], flag);
  }
  // The same target on a fresh desk: the app sees the earlier build's requests in the earlier build's order, and the run differs only in the evaluator identity
  // and per-run noise (ids, times, keyed digests, and the origin's port in the profile and target-configuration hashes).
  // The earlier build's predicates kept their outcome only; the predicate record mode that writes that record (src/contracts.mjs predicate records) is 'outcome'.
  const app = await desk(t), run = await runHttpAssessment({ ...main.profile, origin: app.origin }, { env: ENV, predicateRecord: 'outcome' });
  assert.deepEqual(app.seen, main.seen);
  assert.deepEqual(steady(run), steady(main.run));
  assert.notEqual(run.evaluatorHash, main.run.evaluatorHash);
});

test('mirrorPlan returns before its precomputation for a target that declares no mirrors; a hand-declared mirror is refused without the old "off" advice', () => {
  // A tenant declaration the precomputation cannot read: an undeclared target never reaches it, a declared one does.
  const target = { actors: {}, checks: [{ id: 'X', severity: 'high', assertions: [] }], tenantValues: { tenants: { a: { identifiers: 7 } } } };
  assert.deepEqual(mirrorPlan(target, new Map()).plan, [{ checkId: 'X', reason: 'mirrors-undeclared' }]);
  assert.deepEqual(mirrorPlan({ ...target, mirrors: 'off' }, new Map()).plan, [{ checkId: 'X', reason: 'mirrors-off' }]);
  assert.throws(() => mirrorPlan({ ...target, mirrors: { counterparts: [] } }, new Map()));
  // A target that declares no "mirrors" gets none, so the advice is to remove the hand-declared check.
  const p = profile('http://127.0.0.1:5001'), withMirror = validated(p), hand = profile('http://127.0.0.1:5001', { mirrors: null });
  hand.checks.push(withMirror.checks.find(c => c.id === 'ANA-CHAT-mirror'));
  assert.throws(() => validated(hand), error => /a check that declares "mirrorOf" must be exactly the mirror ScopeHaven generates from it; remove it \(mirrors are generated from the target's "mirrors" declaration, and a target without one gets none\)/.test(error.message) && !/"mirrors": "off"/.test(error.message));
});
