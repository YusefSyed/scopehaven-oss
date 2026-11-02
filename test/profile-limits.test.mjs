// Profile size caps (PROFILE_LIMITS) and the load-time request bound (requestPlan), which counts what
// the connector would send before it sends anything.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateTargetFile, PROFILE_LIMITS, requestPlan, identityControlPlan } from '../src/contracts.mjs';
import { identityProbeBound } from '../src/http-timing.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';

const control = (id, actorId, extra = {}) => ({ id, title: id, category: 'Synthetic', severity: 'control', actorId, method: 'GET', path: `/${id}`, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], ...extra });
const boundary = (id, actorId, extra = {}) => ({ id, title: id, category: 'Synthetic', severity: 'high', actorId, method: 'POST', path: `/${id}`, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], ...extra });
const anonProfile = checks => ({ id: 'limits', name: 'Limits', applicationId: 'limits', origin: 'http://127.0.0.1:4318', buildLabel: 'b1', contextId: 'limits', actors: { anon: { principalId: 'anonymous' } }, requiredControlIds: ['C'], checks: [control('C', 'anon'), ...checks] });
const load = p => validateTargetFile({ schemaVersion: 1, targets: [p] })[0];
// Credentialed actors, each with one identity control (a required GET naming its identity) and `surface` more required controls.
const actorsProfile = ({ actors, checksPerActor, surface = 0 }) => {
  const names = Array.from({ length: actors }, (_, i) => `a${i}`);
  const checks = [], required = [];
  for (const a of names) {
    checks.push(control(`${a}-me`, a, { path: `/${a}/me`, assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: a }] })); required.push(`${a}-me`);
    for (let s = 0; s < surface; s++) { checks.push(control(`${a}-s${s}`, a)); required.push(`${a}-s${s}`); }
    for (let c = 0; c < checksPerActor; c++) checks.push(boundary(`${a}-c${c}`, a));
  }
  return { id: 'plan', name: 'Plan', applicationId: 'plan', origin: 'http://127.0.0.1:4318', buildLabel: 'b1', contextId: 'plan',
    actors: Object.fromEntries(names.map(a => [a, { principalId: a, credentialEnv: `SCOPEHAVEN_TARGET_${a.toUpperCase()}`, identityValue: a }])), requiredControlIds: required, checks };
};

test('PROFILE_LIMITS: 200 checks, 32 assertions (31 predicates), 32 effects, 1000 clauses, 64 captures, 50 required controls', () => {
  assert.deepEqual({ ...PROFILE_LIMITS }, { checks: 200, requiredControls: 50, assertions: 32, predicates: 31, effects: 32, clauses: 1000, captures: 64, plannedRequests: 2500, crossProbes: 1000 });
});

test('checks and assertions: accepted at the cap, refused one past it', () => {
  const many = n => Array.from({ length: n }, (_, i) => boundary(`b${i}`, 'anon'));
  assert.equal(load(anonProfile(many(199))).checks.length, 200);
  assert.throws(() => load(anonProfile(many(200))), /invalid check set/);
  const predicates = n => [{ kind: 'status.equals', expected: 200 }, ...Array.from({ length: n }, (_, i) => ({ kind: 'json.equals', pointer: `/f${i}`, expected: i }))];
  assert.doesNotThrow(() => load(anonProfile([boundary('p', 'anon', { assertions: predicates(31) })])));
  assert.throws(() => load(anonProfile([boundary('p', 'anon', { assertions: predicates(32) })])), /invalid assertion set/);
});

test('the profile-wide clause cap: at most 1000 effect clauses and claim rules', () => {
  const observers = [{ id: 'sink', type: 'egress-recorder', port: 47001, destinations: [{ host: 'pay.example.test' }] }];
  const effects = n => Array.from({ length: n }, () => ({ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: 'pay.example.test' } }));
  const withClauses = (checks, perCheck) => ({ ...anonProfile(Array.from({ length: checks }, (_, i) => boundary(`b${i}`, 'anon', { effects: effects(perCheck) }))), observers });
  assert.doesNotThrow(() => load(withClauses(31, 32)), '992 clauses');
  assert.doesNotThrow(() => load(withClauses(40, 25)), '1000 clauses');
  assert.throws(() => load(withClauses(41, 25)), /clause-limit: 1025/);
});

test('request plan: probe points and cross probes counted from the connector\'s own plan, refused past their caps', () => {
  const small = actorsProfile({ actors: 2, checksPerActor: 3, surface: 1 });
  // Per actor, the identity and surface controls are re-sent at (bracketed checks + 1) probe points; required surface controls are bracketed too.
  const plan = requestPlan(load(small));
  assert.equal(plan.checkRequests, small.checks.length);
  assert.equal(plan.crossProbes, 2 * 1 * (2 + 1), 'each identity control: anonymous, look-alike, the other actor');
  assert.equal(plan.total, plan.checkRequests + plan.probePointRequests + plan.crossProbes + plan.witnessRequests);
  // n actors x 1 identity control x (2 + n - 1) cross probes: 31 actors read 992, accepted; 32 read 1056, refused.
  assert.doesNotThrow(() => load(actorsProfile({ actors: 31, checksPerActor: 1 })));
  assert.throws(() => load(actorsProfile({ actors: 32, checksPerActor: 1 })), /request-plan: crossProbes 1056 over 1000/);
  // One actor, 1 identity + 11 surface controls bracketing 188 checks: (1 + 11) x (188 + 11 + 1) = 2400 probe-point requests, 2602 in all.
  assert.throws(() => load(actorsProfile({ actors: 1, checksPerActor: 188, surface: 11 })), /request-plan: total 2602 over 2500/);
  assert.doesNotThrow(() => load(actorsProfile({ actors: 1, checksPerActor: 150, surface: 4 })));
  // The connector's probes are also bounded by the timing plan's own formula: the two never disagree upward.
  for (const shape of [{ actors: 1, checksPerActor: 150, surface: 4 }, { actors: 5, checksPerActor: 30, surface: 3 }, { actors: 31, checksPerActor: 1 }]) {
    const t = load(actorsProfile(shape)), p = requestPlan(t);
    assert.ok(p.probePointRequests + p.crossProbes <= identityProbeBound(t, identityControlPlan(t)), JSON.stringify(shape));
  }
});

test('the connector never sends more requests than requestPlan counted', async () => {
  for (const shape of [{ actors: 1, checksPerActor: 4, surface: 1 }, { actors: 3, checksPerActor: 2, surface: 2 }]) {
    const profile = actorsProfile(shape), env = Object.fromEntries(Object.keys(profile.actors).map(a => [`SCOPEHAVEN_TARGET_${a.toUpperCase()}`, `synthetic-token-${a}`]));
    const tokens = new Map(Object.keys(profile.actors).map(a => [`synthetic-token-${a}`, a]));
    let sent = 0;
    const transport = async (_origin, check, { credential }) => {
      sent++;
      const who = tokens.get(credential);
      if (check.path.endsWith('/me')) return who ? { status: 200, complete: true, jsonParsed: true, json: { user: who }, bytes: 20 } : { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
      return { status: who ? (check.method === 'GET' ? 200 : 403) : 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    };
    await runHttpAssessment(profile, { env, transport });
    const plan = requestPlan(load(profile));
    assert.ok(sent > 0 && sent <= plan.total, `sent ${sent}, planned ${plan.total} (${JSON.stringify(shape)})`);
    assert.ok(sent >= plan.checkRequests + plan.probePointRequests, `the probe points the plan counts are sent (${sent})`);
  }
});

for (const [R, K] of [[200, 5], [31, 32]]) test(`bench at the caps: settlement and pairing over ${R} checks x ${K} clauses (the 1000-clause cap) with distinct selectors stay under 10 s`, async () => {
  const { settlementFindings } = await import('../src/http-settlement.mjs');
  const { selectorPairs, pairingFindings } = await import('../src/http-pairing.mjs');
  const { makeEffect } = await import('../src/effect-events.mjs');
  const HOST = 'pay.example.test', H = Math.ceil(K / 2);
  const scope = { operations: ['send'], names: [HOST], actorAttribution: 'principal', evidence: 'authoritative' };
  let seq = 0;
  const window = (r, n) => ({ source: 'http-egress', instanceId: 'sink', coverage: 'complete', reason: null, scope,
    events: Array.from({ length: n }, (_, i) => makeEffect({ source: 'http-egress', observer: { kind: 'test', instanceId: 'sink' }, seq: ++seq, actor: 'p0', operation: 'send', name: HOST, resource: `POST /r${r}/c${i % K}`, outcome: 'committed' })) });
  // Every row: half exists clauses that pass on their own sends and half absence clauses on resources nobody sends; every selector distinct.
  const rows = Array.from({ length: R }, (_, r) => ({ windows: [window(r, 32)], effects: Array.from({ length: K }, (_, c) => c < H
    ? { kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: HOST, resource: `POST /r${r}/c${c}` }, verdict: 'pass' }
    : { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: HOST, resource: `POST /r${r}/never${c}` }, verdict: 'pass' }) }));
  const gaps = Array.from({ length: R + 1 }, () => []);
  let started = performance.now();
  const findings = settlementFindings(rows, gaps);
  const settlementMs = performance.now() - started;
  assert.equal(findings.length, R);
  // Pairing: half the checks are controls with positive clauses, half boundaries whose absence clauses pin an actor.
  const actors = { u: { principalId: 'p0' } };
  const checks = Array.from({ length: R }, (_, r) => ({ id: `k${r}`, actorId: 'u', severity: r % 2 ? 'control' : 'high', effects: Array.from({ length: K }, (_, c) => r % 2
    ? { kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: HOST, resource: `POST /r${r}/c${c}`, actor: 'p0' } }
    : { kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: HOST, resource: `POST /r${r}/c${c}`, actor: 'p0' } }) }));
  started = performance.now();
  const pairs = selectorPairs({ actors, checks });
  const pairRows = checks.map((check, r) => ({ id: check.id, role: check.severity === 'control' ? 'control' : 'boundary', windows: rows[r].windows, effects: check.effects.map(e => ({ ...e, verdict: 'pass' })) }));
  pairingFindings(pairRows, pairs);
  const pairingMs = performance.now() - started;
  assert.ok(settlementMs + pairingMs < 10000, `settlement ${Math.round(settlementMs)} ms, pairing ${Math.round(pairingMs)} ms`);
  console.log(`bench ${R}x${K}: settlement ${Math.round(settlementMs)} ms, pairing ${Math.round(pairingMs)} ms`);
});

test('witness requests count: one per observed check for each observer that sends one', () => {
  const observers = [{ id: 'audit', type: 'audit-file', path: '/tmp/never-read.log', format: 'jsonl', rules: [{ match: { action: 'x' }, effect: { operation: 'insert', name: 'x' } }], witness: { actorId: 'anon', method: 'GET', path: '/ping' } }];
  const effect = { kind: 'effect.exists', select: { source: 'file-audit-log', operation: 'insert', name: 'x' } };
  const profile = { ...anonProfile([boundary('b1', 'anon', { effects: [effect] }), boundary('b2', 'anon', { effects: [effect] }), boundary('b3', 'anon')]), observers };
  let plan;
  try { plan = requestPlan(load(profile)); } catch { plan = requestPlan(profile); }
  assert.equal(plan.witnessRequests, 2, 'two observed checks x one witnessing observer');
});
