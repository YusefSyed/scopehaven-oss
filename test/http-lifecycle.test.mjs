// Lifecycle phase (src/http-lifecycle.mjs): an account change in the middle of a run. Owned loopback
// practice app (integrations/core-practice/app.mjs) with synthetic users, an in-memory note store and a
// loopback egress recorder for its webhooks; no model, no provider, no network beyond 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, contractDigest, PRECONDITION_ASSERTION, IDENTITY_ASSERTION } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { createCorePracticeApp } from '../integrations/core-practice/app.mjs';
import { lifecycleProfile } from '../integrations/core-practice/profiles.mjs';
import { freePorts } from '../integrations/observers/fixtures/free-port.mjs';
import { LIFECYCLE_LIMITATION } from '../src/http-scope-text.mjs';

const row = (run, id) => run.results.find(r => r.id === id);
const carol = run => run.identityEvidence.actors.find(a => a.actorId === 'carol');
const suiteOf = (profile, env) => createRegistry({ profiles: [profile], env }).exportSuite(profile.id);
async function assess(t, build = {}, { observers = true, edit = p => p } = {}) {
  const [sinkPort] = await freePorts(1);
  const app = await createCorePracticeApp({ sinkPort, ...build }); t.after(() => app.close());
  const profile = edit(lifecycleProfile({ origin: app.origin, sinkPort, observers }));
  const run = await runHttpAssessment(profile, { env: app.env });
  return { app, profile, run };
}
const reseal = r => { r.evidenceDigest = digest(r.trace.length === 2 ? { evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions } : { evidence: r.trace[0].data, assertions: r.assertions }); };

test('lifecycle validation: the entry names an existing change control, a known credentialed actor, and post-change checks that expect the refusal with an effect clause', () => {
  const base = lifecycleProfile({ origin: 'http://127.0.0.1:9', sinkPort: 40999 });
  validateTargetFile({ schemaVersion: 1, targets: [base] });
  const refuse = (edit, pattern) => { const p = structuredClone(base); edit(p); assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), pattern); };
  refuse(p => { p.lifecycle[0].changeCheckId = 'NO-SUCH-CHECK'; }, /"changeCheckId" must name a check of this profile/);
  refuse(p => { p.lifecycle[0].actorId = 'mallory'; }, /"actorId" must name a declared actor/);
  refuse(p => { p.lifecycle[0].after = 'until-expiry'; }, /"after" must be "refused"/);
  refuse(p => { p.lifecycle[0].extra = 1; }, /each entry is \{ changeCheckId, actorId, after \}/);
  refuse(p => { p.lifecycle = []; }, /"lifecycle" lists 1 to 10/);
  refuse(p => { p.lifecycle.push({ ...p.lifecycle[0] }); }, /an actor changes standing once per profile/);
  refuse(p => { delete p.actors.carol.credentialEnv; delete p.actors.carol.identityValue; }, /needs a "credentialEnv"/);
  // The change must be another actor's required allowed-use control.
  refuse(p => { p.requiredControlIds = p.requiredControlIds.filter(id => id !== 'ADMIN-SUSPEND-CAROL'); }, /the change check must be an applicable required allowed-use control/);
  // The changed actor may make the change herself (a self-change, test/http-lifecycle-self.test.mjs), but never with a GET:
  // a required GET of hers is a surface control, re-sent at every probe point.
  refuse(p => { p.lifecycle[0].changeCheckId = 'CAROL-NOTES'; }, /a self-change check \(sent by the changed actor\) must use POST, PUT, PATCH or DELETE/);
  // The bracket: a check of the changed actor after the change that expects success would be refused after the change.
  refuse(p => { const { capture: _c, ...note } = p.checks.find(c => c.id === 'CAROL-NOTE-2'); p.checks.push({ ...note, id: 'CAROL-NOTE-LATE' }); p.requiredControlIds.push('CAROL-NOTE-LATE'); }, /post-change check "CAROL-NOTE-LATE" must expect the refusal, so it cannot be an allowed-use control/);
  refuse(p => { const c = p.checks.find(x => x.id === 'CAROL-REUSE-ME'); c.assertions = [{ kind: 'status.equals', expected: 200 }]; }, /must expect only the declared refusal \(401, 403\)/);
  refuse(p => { const c = p.checks.find(x => x.id === 'CAROL-REUSE-ME'); c.assertions = [{ kind: 'status.in', expected: [401, 404] }]; }, /must expect only the declared refusal/);
  refuse(p => { const c = p.checks.find(x => x.id === 'CAROL-REUSE-ME'); c.effects = [{ kind: 'effect.exists', select: c.effects[0].select }]; }, /must pair its refusal with at least one effect\.none clause/);
  refuse(p => { p.checks = p.checks.filter(c => !c.id.startsWith('CAROL-REUSE')); }, /declare at least one post-change check/);
  refuse(p => { p.observers[0].witness.actorId = 'carol'; }, /an observer witness cannot use the changed actor/);
  // The same-actor acceptance a post-change refusal rests on: a surface control (a required GET on a protected route) before the change.
  refuse(p => { p.requiredControlIds = p.requiredControlIds.filter(id => id !== 'CAROL-NOTES'); Object.assign(p.checks.find(c => c.id === 'CAROL-NOTES'), { severity: 'low' }); }, /needs a surface control before the change/);
  refuse(p => { p.requiredControlIds = p.requiredControlIds.filter(id => id !== 'CAROL-WHOAMI'); Object.assign(p.checks.find(c => c.id === 'CAROL-WHOAMI'), { severity: 'low', evidenceRequirement: 'response' }); }, /needs an identity control before the change/);
  // A declared sign-in redirect is part of the actor's refusal set.
  const redirect = structuredClone(base); redirect.actors.carol.signInRedirectStatus = 302; redirect.checks.find(c => c.id === 'CAROL-REUSE-ME').assertions = [{ kind: 'status.in', expected: [302, 401] }];
  validateTargetFile({ schemaVersion: 1, targets: [redirect] });
  // The declaration is part of the contract identity, and the exported suite binds it.
  const without = structuredClone(base); delete without.lifecycle;
  assert.notEqual(contractDigest(base), contractDigest(without));
  assert.deepEqual(suiteOf(base, {}).lifecycle, [{ changeCheckId: 'ADMIN-SUSPEND-CAROL', actorId: 'carol', after: 'refused' }]);
});

test('lifecycle allowed: the clean twin passes; carol\'s identity is proven strictly before the change, her pre-change credential is refused after it, and unchanged actors keep passing', async t => {
  const { app, profile, run } = await assess(t);
  assert.deepEqual(run.counts, { pass: 12, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }, JSON.stringify(run.results.map(r => [r.id, r.status])));
  const entry = carol(run);
  assert.equal(entry.reason, 'established');
  assert.deepEqual(entry.lifecycle, { changeCheckId: 'ADMIN-SUSPEND-CAROL', after: 'refused', changeConfirmed: true, changerLoginProven: true, postChangeCheckIds: ['CAROL-REUSE-ME', 'CAROL-REUSE-DELETE'] });
  // The post-change rows are decided from the harness's own response (401) and the egress record, with independent custody.
  for (const id of ['CAROL-REUSE-ME', 'CAROL-REUSE-DELETE']) {
    const r = row(run, id);
    assert.deepEqual([r.trace[0].data.httpStatus, r.status, r.trace[1].data.effects[0].custody], [401, 'pass', 'independent'], id);
  }
  // Every request carrying carol's credential, except the two post-change checks, was sent before the suspension:
  // her brackets, her anonymous, invalid and cross probes, and the other actors' cross probes that carry her credential.
  const at = app.requests.findIndex(r => r.method === 'POST' && r.path === '/api/admin/users/u-carol/suspend');
  assert.ok(at > 0);
  assert.deepEqual(app.requests.slice(at + 1).filter(r => r.user === 'carol').map(r => `${r.method} ${r.path}`), ['GET /api/me', `POST /api/notes/${'n-2'}/delete`]);
  assert.ok(app.requests.slice(0, at).filter(r => r.user === 'carol' && r.path === '/api/me').length >= 4, 'whoami, bracket and the cross probes in admin\'s and bob\'s slots');
  // Unchanged actors: bob's controls after the change pass, and his identity proof is unaffected.
  assert.deepEqual(['BOB-WHOAMI-AFTER', 'BOB-NOTE-AFTER'].map(id => row(run, id).status), ['pass', 'pass']);
  assert.ok(run.limitations.includes(LIFECYCLE_LIMITATION));
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) }).exitCode, 0);
});

test('lifecycle forbidden: a pre-change credential that still works fails from the harness\'s own records', async t => {
  const { app, profile, run } = await assess(t, { staleSession: true });
  const me = row(run, 'CAROL-REUSE-ME'), del = row(run, 'CAROL-REUSE-DELETE');
  assert.deepEqual([me.trace[0].data.httpStatus, me.status], [200, 'fail']);
  assert.deepEqual([del.trace[0].data.httpStatus, del.status, del.assertions.find(a => a.name.startsWith('Observed effect')).status], [200, 'fail', 'fail']);
  assert.equal(carol(run).reason, 'established', 'the identity proof closed before the change, so the failure is attributed to carol');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  const gate = summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) });
  assert.equal(gate.exitCode, 1); assert.ok(gate.reasons.includes('checks-failed'));
});

test('lifecycle missing observer: a refusal with nothing to observe the effect behind it is never a pass', async t => {
  const { app, profile, run } = await assess(t, {}, { observers: false });
  for (const id of ['CAROL-REUSE-ME', 'CAROL-REUSE-DELETE']) {
    const r = row(run, id);
    assert.equal(r.trace[0].data.httpStatus, 401, id);
    assert.equal(r.status, 'inconclusive', id);
    assert.match(r.assertions.find(a => a.name.startsWith('Observed effect')).actual, /^unobservable/);
  }
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  assert.notEqual(summarizeGate({ candidate: run }).exitCode, 0);
});

test('lifecycle failed control: when the change does not pass, no pre-change credential is re-sent and the post-change rows are inconclusive', async t => {
  const { app, profile, run } = await assess(t, { suspendBroken: true });
  assert.equal(row(run, 'ADMIN-SUSPEND-CAROL').status, 'fail');
  assert.equal(carol(run).lifecycle.changeConfirmed, false);
  for (const id of ['CAROL-REUSE-ME', 'CAROL-REUSE-DELETE']) {
    const r = row(run, id);
    assert.deepEqual([r.status, r.trace[0].data.transportOutcome, r.trace[0].data.notSent, r.trace.length], ['inconclusive', 'not-sent', 'change-not-confirmed', 1], id);
    assert.match(r.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual, /declared account change did not pass/);
  }
  const at = app.requests.findIndex(r => r.path === '/api/admin/users/u-carol/suspend');
  assert.deepEqual(app.requests.slice(at + 1).filter(r => r.user === 'carol'), [], 'nothing carried carol\'s credential after the failed change');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  const gate = summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) });
  assert.equal(gate.exitCode, 1); assert.ok(gate.reasons.includes('required-controls-not-passed') && gate.reasons.includes('inconclusive-evidence'));
});

test('without the lifecycle declaration the same run cannot pass the refusals: the probe points after the suspension refuse carol\'s credential, so no check of hers is credited', async t => {
  const { run } = await assess(t, {}, { edit: p => { delete p.lifecycle; return p; } });
  assert.equal(carol(run).reason, 'bracket-not-passed');
  // The points after the suspension refused carol's identity control and her surface control (401). A probe refused with her own
  // credential is route-level (the surface- and identity-refusal rules): every row of hers reads bracket-not-passed, the reason an identity
  // refusal gives and the one identityReason ranks above surface-refused. The identity control and the checks whose own points
  // came before the suspension are included, since a credential refused once may have been refused between two accepting points.
  const points = [...carol(run).before, ...carol(run).between.flatMap(b => b.probes), ...carol(run).after];
  assert.ok(['CAROL-WHOAMI', 'CAROL-NOTES'].every(id => points.some(p => p.controlId === id && p.httpStatus === 401)), 'both refusals are in the stored probes');
  const identity = id => row(run, id).assertions.find(a => a.name === IDENTITY_ASSERTION)?.actual;
  for (const id of ['CAROL-WHOAMI', 'CAROL-NOTES', 'CAROL-NOTE-1', 'CAROL-NOTE-2', 'CAROL-DELETE-OWN']) assert.deepEqual([row(run, id).status, identity(id)], ['inconclusive', IDENTITY_REASONS['bracket-not-passed']], id);
  // The refusal after it observed the expected status: the distinct third state, never a pass.
  assert.deepEqual([row(run, 'CAROL-REUSE-ME').status, row(run, 'CAROL-REUSE-ME').decision, identity('CAROL-REUSE-ME')], ['inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS['bracket-not-passed']]);
  // The values carol captured have no proven creator either (creator-login-unproven): the delete that uses one is plainly inconclusive
  // (a precondition withholds it as well as identity), and so is the administrator's suspension, which uses her captured id.
  const creator = id => row(run, id).assertions.find(a => a.name === PRECONDITION_ASSERTION)?.actual;
  assert.deepEqual([row(run, 'CAROL-REUSE-DELETE').status, row(run, 'CAROL-REUSE-DELETE').decision, identity('CAROL-REUSE-DELETE')], ['inconclusive', 'inconclusive', IDENTITY_REASONS['bracket-not-passed']]);
  for (const id of ['CAROL-REUSE-DELETE', 'ADMIN-SUSPEND-CAROL']) assert.match(creator(id) ?? '', /login of the actor that created a captured value was not proven/, id);
  validateHttpRunEvidence(run);
});

test('lifecycle evidence is recomputed: an edited confirmation, post-change list or not-sent reason is refused, and the suite binds the declaration', async t => {
  const { app, profile, run } = await assess(t);
  const suite = suiteOf(profile, app.env);
  const edit = change => { const copy = structuredClone(run); change(copy); return copy; };
  assert.throws(() => validateHttpRunEvidence(edit(c => { carol(c).lifecycle.changeConfirmed = false; })), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(edit(c => { carol(c).lifecycle.postChangeCheckIds = ['CAROL-REUSE-ME']; })), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(edit(c => { carol(c).lifecycle.changeCheckId = 'ADMIN-WHOAMI'; })), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(edit(c => { carol(c).lifecycle.changeCheckId = 'CAROL-DELETE-OWN'; })), /invalid-run-evidence/);
  // Moving the change to another control with the same post-change rows is internally consistent; the suite refuses it.
  const moved = edit(c => { carol(c).lifecycle.changeCheckId = 'BOB-NOTE-AFTER'; });
  validateHttpRunEvidence(moved);
  assert.throws(() => validateHttpRunEvidence(moved, { expectedSuite: suite }), e => e.code === 'unexpected-suite-evidence');
  // Stripping the declaration from the evidence: the suite still names it.
  const stripped = edit(c => { delete carol(c).lifecycle; });
  assert.throws(() => validateHttpRunEvidence(stripped, { expectedSuite: suite }), e => e.code === 'unexpected-suite-evidence');
  // A post-change row relabelled as not sent while the change was confirmed.
  const unsent = edit(c => { const r = row(c, 'CAROL-REUSE-DELETE'); r.trace[0].data.notSent = 'change-not-confirmed'; reseal(r); });
  assert.throws(() => validateHttpRunEvidence(unsent), /invalid-run-evidence/);
  // Hiding a stale session's failures: the post-change rows of a run whose change failed, transplanted into a run whose change
  // passed, with the confirmation turned off. Every row is genuine; only the recomputed confirmation refuses it.
  const stale = (await assess(t, { staleSession: true })).run, failed = (await assess(t, { suspendBroken: true })).run;
  const hidden = structuredClone(stale);
  hidden.results = hidden.results.map(r => r.id.startsWith('CAROL-REUSE') ? structuredClone(row(failed, r.id)) : r);
  carol(hidden).lifecycle.changeConfirmed = false;
  // Its settlement record too (with the post-change rows unsent, only CAROL-DELETE-OWN has an effect window), and the
  // capture digest the transplanted row uses, restated from this run and resealed.
  hidden.settlement = structuredClone(failed.settlement);
  const transplanted = row(hidden, 'CAROL-REUSE-DELETE'); transplanted.trace[0].data.captureUses = structuredClone(row(stale, 'CAROL-REUSE-DELETE').trace[0].data.captureUses); reseal(transplanted);
  // The stale run's later delete webhook tagged carol's own delete (an allowed-use control) effect-outside-window; drop the tag.
  const own = row(hidden, 'CAROL-DELETE-OWN');
  assert.equal(own.trace[1].data.effects[0].settlement, 'effect-outside-window');
  delete own.trace[1].data.effects[0].settlement; own.assertions = own.assertions.map(({ settlement: _s, ...a }) => a); reseal(own);
  hidden.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const r of hidden.results) hidden.counts[r.status]++;
  assert.equal(hidden.counts.fail, 0, 'the forged run hides both failures');
  assert.throws(() => validateHttpRunEvidence(hidden), /invalid-run-evidence/);
});

test('a declared sign-in redirect is the post-change refusal, not a lost login', async () => {
  // Injected transport and observer: no socket. Carol's credential is redirected to sign-in after the suspension.
  let suspended = false;
  const transport = async (origin, check, { credential }) => {
    const who = { 'tok-admin': 'admin', 'tok-carol': 'carol' }[credential];
    if (!who) return { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (who === 'carol' && suspended) return { status: 302, complete: true, jsonParsed: false, json: undefined, bytes: 0, error: 'invalid-json' };
    if (check.path.endsWith('/suspend')) { suspended = true; return { status: 200, complete: true, jsonParsed: true, json: { status: 'suspended' }, bytes: 10 }; }
    return { status: 200, complete: true, jsonParsed: true, json: { user: who }, bytes: 10 };
  };
  const factory = configs => configs.map(c => ({ kind: 'http-egress-recorder', instanceId: `egress-recorder-${c.id}`, source: 'http-egress', scope: { operations: ['send'], names: ['hooks.desk.example'], actorAttribution: 'none', evidence: 'authoritative' },
    witnessRequest: null, async start() {}, async stop() {}, async mark() { return {}; }, async collect() { return { events: [], coverage: 'complete', reason: null }; } }));
  const select = { source: 'http-egress', operation: 'send', name: 'hooks.desk.example' };
  const profile = { id: 'redirecting', name: 'Redirecting app', applicationId: 'redirecting-app', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { admin: { principalId: 'admin', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, carol: { principalId: 'carol', credentialEnv: 'SCOPEHAVEN_TARGET_C', identityValue: 'carol', signInRedirectStatus: 302 } },
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40998, destinations: [{ host: 'hooks.desk.example' }], settleMs: 250 }],
    requiredControlIds: ['ADMIN-ME', 'CAROL-ME', 'CAROL-NOTES', 'SUSPEND'], lifecycle: [{ changeCheckId: 'SUSPEND', actorId: 'carol', after: 'refused' }],
    checks: [
      { id: 'ADMIN-ME', title: 'a', category: 'Identity', severity: 'control', actorId: 'admin', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'admin' }] },
      { id: 'CAROL-ME', title: 'c', category: 'Identity', severity: 'control', actorId: 'carol', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'carol' }] },
      { id: 'CAROL-NOTES', title: 'n', category: 'Allowed use', severity: 'control', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'SUSPEND', title: 's', category: 'Account change', severity: 'control', actorId: 'admin', method: 'POST', path: '/users/carol/suspend', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'REUSE', title: 'r', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [302, 401] }], effects: [{ kind: 'effect.none', select }] },
    ] };
  const run = await runHttpAssessment(profile, { env: { SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_C: 'tok-carol' }, transport, observerFactory: factory });
  const reuse = row(run, 'REUSE');
  // The egress observer here is presence-only (no routing): the absence is unobservable, so the row is inconclusive, but never for a lost login.
  assert.equal(reuse.trace[0].data.httpStatus, 302);
  assert.ok(!reuse.assertions.some(a => a.name === IDENTITY_ASSERTION), JSON.stringify(reuse.assertions));
  assert.equal(carol(run).reason, 'established');
  validateHttpRunEvidence(run);
});

// ---------------------------------------------------------------------------
// actor-identity/5: a change is attributed only when the changer's login was proven for the change check, a change check
// needs a changer with an identity control, and the validator refuses a lifecycle run whose changed actor has no surface
// control. Injected transport and an injected empty authoritative sink: no socket.
import { IDENTITY_REASONS, IDENTITY_UNPROVEN_DECISION } from '../src/contracts.mjs';
const SINK_HOST = 'hooks.desk.example', SINK_SELECT = { source: 'http-egress', operation: 'send', name: SINK_HOST };
const sinkConfig = witness => ({ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: SINK_HOST }], witness: { actorId: witness, method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150 });
// An authoritative fake sink that records nothing: every window is empty and complete.
const emptySink = configs => configs.map(c => ({ kind: 'http-egress-recorder', instanceId: `${c.type}-${c.id}`, source: 'http-egress', scope: { operations: ['send'], names: [SINK_HOST], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
  async start() {}, async stop() {}, async mark() { return {}; }, async collect() { return { events: [], coverage: 'complete', reason: null }; } }));
const reply = (status, json = {}) => ({ status, complete: true, jsonParsed: true, json, bytes: 2 });
const ctl = (id, actorId, path, extra = []) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId, method: 'GET', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, ...extra] });
const me = (id, actorId) => ctl(id, actorId, '/me', [{ kind: 'json.equals', pointer: '/user', expected: actorId }]);
const ENV = { SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_C: 'tok-carol' };
function changerProfile() {
  return { id: 'changer', name: 'Changer', applicationId: 'changer', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { admin: { principalId: 'admin', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, carol: { principalId: 'carol', credentialEnv: 'SCOPEHAVEN_TARGET_C', identityValue: 'carol' } },
    observers: [sinkConfig('admin')], requiredControlIds: ['ADMIN-ME', 'CAROL-ME', 'CAROL-NOTES', 'SUSPEND'], lifecycle: [{ changeCheckId: 'SUSPEND', actorId: 'carol', after: 'refused' }],
    checks: [me('ADMIN-ME', 'admin'), me('CAROL-ME', 'carol'), ctl('CAROL-NOTES', 'carol', '/notes'), { ...ctl('SUSPEND', 'admin', '/users/carol/suspend'), method: 'POST', body: {} },
      { id: 'REUSE', title: 'r', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: SINK_SELECT }] }] };
}
// state.adminAcceptsAnonymous: the administrator's identity route answers the administrator's identity without a credential.
function changerApp(state) {
  let suspended = false;
  return async (origin, check, { credential }) => {
    const who = { 'tok-admin': 'admin', 'tok-carol': 'carol' }[credential] ?? null;
    if (check.path === '/me') {
      if (check.id === 'ADMIN-ME' && state.adminAcceptsAnonymous && credential === undefined) return reply(200, { user: 'admin' });
      return who && !(who === 'carol' && suspended) ? reply(200, { user: who }) : reply(401);
    }
    if (!who) return reply(401);
    if (check.path.endsWith('/suspend')) { if (who !== 'admin') return reply(403); suspended = true; return reply(200); }
    if (who === 'carol' && suspended) return reply(401);
    return reply(200, { items: [] });
  };
}
const recount = run => { run.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const r of run.results) run.counts[r.status]++; };

test('a change confirms the post-change refusals only when the changer\'s login was proven for the change check; otherwise they are the third state (changer-login-unproven)', async () => {
  const proven = await runHttpAssessment(changerProfile(), { env: ENV, transport: changerApp({}), observerFactory: emptySink });
  assert.deepEqual([carol(proven).lifecycle.changeConfirmed, carol(proven).lifecycle.changerLoginProven, row(proven, 'REUSE').status], [true, true, 'pass']);
  validateHttpRunEvidence(proven, { expectedSuite: suiteOf(changerProfile(), ENV) });
  const unproven = await runHttpAssessment(changerProfile(), { env: ENV, transport: changerApp({ adminAcceptsAnonymous: true }), observerFactory: emptySink });
  const admin = unproven.identityEvidence.actors.find(a => a.actorId === 'admin');
  assert.deepEqual([admin.reason, admin.loginProven, row(unproven, 'SUSPEND').status, row(unproven, 'SUSPEND').decision], ['not-refused-without-credential', false, 'inconclusive', 'inconclusive']);
  // The change passed when it was sent, so the post-change row was sent; it is not attributed to a proven login.
  assert.deepEqual([carol(unproven).lifecycle.changeConfirmed, carol(unproven).lifecycle.changerLoginProven, carol(unproven).reason], [true, false, 'established']);
  const reuse = row(unproven, 'REUSE');
  assert.deepEqual([reuse.trace[0].data.httpStatus, reuse.status, reuse.decision, reuse.assertions.find(a => a.name === IDENTITY_ASSERTION)?.actual], [401, 'inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS['changer-login-unproven']]);
  validateHttpRunEvidence(unproven, { expectedSuite: suiteOf(changerProfile(), ENV) });
  assert.ok(summarizeGate({ candidate: unproven }).reasons.includes('prohibition-observed-identity-unproven'));
  // The flag and the row are recomputed: attributing the change, or restoring the refusal's pass, is refused.
  const flagged = structuredClone(unproven); carol(flagged).lifecycle.changerLoginProven = true;
  assert.throws(() => validateHttpRunEvidence(flagged), /invalid-run-evidence/);
  const restored = structuredClone(unproven), r = row(restored, 'REUSE');
  r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.decision = 'pass'; reseal(r); recount(restored);
  assert.throws(() => validateHttpRunEvidence(restored), /invalid-run-evidence/);
  // Both edited consistently (the flag attributed and the row restored): only the flag's recompute from the change row refuses it.
  const consistent = structuredClone(restored); carol(consistent).lifecycle.changerLoginProven = true;
  assert.throws(() => validateHttpRunEvidence(consistent), /invalid-run-evidence/);
  // A /5 record without the flag is refused as such.
  const unflagged = structuredClone(proven); delete carol(unflagged).lifecycle.changerLoginProven;
  assert.throws(() => validateHttpRunEvidence(unflagged), /invalid-run-evidence/);
});

test('static: the change check must be sent by a credentialed actor with an identity control, so a change by an actor with no identity control never confirms one', () => {
  validateTargetFile({ schemaVersion: 1, targets: [changerProfile()] });
  const noIdentity = changerProfile(); noIdentity.checks = noIdentity.checks.filter(c => c.id !== 'ADMIN-ME'); noIdentity.requiredControlIds = noIdentity.requiredControlIds.filter(id => id !== 'ADMIN-ME');
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [noIdentity] }), /the change check must be sent by a credentialed actor with an identity control/);
  const anonymousAdmin = structuredClone(noIdentity); delete anonymousAdmin.actors.admin.credentialEnv; delete anonymousAdmin.actors.admin.identityValue; anonymousAdmin.observers = [];
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [anonymousAdmin] }), /the change check must be sent by a credentialed actor with an identity control/);
});

test('the validator refuses a lifecycle run whose changed actor has no surface control, even when every other field is consistent', async () => {
  const run = await runHttpAssessment(changerProfile(), { env: ENV, transport: changerApp({}), observerFactory: emptySink });
  assert.equal(row(run, 'REUSE').status, 'pass');
  validateHttpRunEvidence(run);
  // Remove the surface control everywhere, consistently: the row, the required list, carol's entry and her probe points. With
  // no other pre-change row left, the connector would send no points at all: an identity-only proof.
  const forged = structuredClone(run), c = carol(forged);
  forged.results = forged.results.filter(r => r.id !== 'CAROL-NOTES'); forged.requiredControlIds = forged.requiredControlIds.filter(id => id !== 'CAROL-NOTES'); forged.checksTotal = forged.results.length;
  c.requiredControlIds = c.requiredControlIds.filter(id => id !== 'CAROL-NOTES'); c.surfaceControlIds = []; c.before = []; c.between = []; c.after = []; recount(forged);
  assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence', 'a post-change refusal without an earlier accepted surface is refused');
});

// The two points covering the change check are ranked together, not by position, so a changer whose
// login failed at the later point (an identity probe that did not pass) is never attributed the change because the earlier point
// failed only as surface-not-passed (a surface 500, login proven).
test('a change is attributed only when both points covering the change check proved the changer\'s login, whichever failed first', async () => {
  // The administrator gains a surface control before the change. SUSPEND is covered by the point after ADMIN-NOTES (its surface
  // probe, the third /admin-notes call, answers 500) and the closing point after SUSPEND (its identity probe answers 500: not a
  // refusal, so it binds only the checks that point covers, and only the ranking of the two points decides SUSPEND).
  const withNotes = () => { const p = changerProfile(); p.checks.splice(3, 0, ctl('ADMIN-NOTES', 'admin', '/admin-notes')); p.requiredControlIds.push('ADMIN-NOTES'); return p; };
  const app = state => {
    let suspended = false, notes = 0;
    return async (origin, check, { credential }) => {
      const who = { 'tok-admin': 'admin', 'tok-carol': 'carol' }[credential] ?? null;
      if (check.path === '/me') return who === 'admin' && suspended && state.adminMeAfter ? reply(state.adminMeAfter) : who && !(who === 'carol' && suspended) ? reply(200, { user: who }) : reply(401);
      if (!who) return reply(401);
      if (check.path === '/admin-notes') return who === 'admin' && ++notes === state.notesFailAt ? reply(500) : reply(200, { items: [] });
      if (check.path.endsWith('/suspend')) { if (who !== 'admin') return reply(403); suspended = true; return reply(200); }
      if (who === 'carol' && suspended) return reply(401);
      return reply(200, { items: [] });
    };
  };
  const run = await runHttpAssessment(withNotes(), { env: ENV, transport: app({ notesFailAt: 3, adminMeAfter: 500 }), observerFactory: emptySink });
  const admin = run.identityEvidence.actors.find(a => a.actorId === 'admin');
  assert.deepEqual([admin.reason, row(run, 'SUSPEND').status, row(run, 'SUSPEND').assertions.find(a => a.name === IDENTITY_ASSERTION)?.actual], ['bracket-not-passed', 'inconclusive', IDENTITY_REASONS['bracket-not-passed']]);
  assert.deepEqual([carol(run).lifecycle.changeConfirmed, carol(run).lifecycle.changerLoginProven, carol(run).reason], [true, false, 'established']);
  const reuse = row(run, 'REUSE');
  assert.deepEqual([reuse.status, reuse.decision, reuse.assertions.find(a => a.name === IDENTITY_ASSERTION)?.actual], ['inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS['changer-login-unproven']]);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(withNotes(), ENV) });
  // The surface 500 alone leaves the changer's login proven for the change check: the change is attributed and the refusal passes.
  const attributed = await runHttpAssessment(withNotes(), { env: ENV, transport: app({ notesFailAt: 3 }), observerFactory: emptySink });
  assert.deepEqual([attributed.identityEvidence.actors.find(a => a.actorId === 'admin').reason, row(attributed, 'SUSPEND').status, carol(attributed).lifecycle.changerLoginProven, row(attributed, 'REUSE').status], ['surface-not-passed', 'pass', true, 'pass']);
  validateHttpRunEvidence(attributed);
});

// The other-principal rule: the changer's identity probe at a point that does not cover the change check answers
// a complete 2xx naming another principal, or null. identityRefused counts that as a refusal, so it withholds every row of the
// administrator route-wide: the change is not attributed, and the post-change refusal is the third state (changer-login-unproven).
test('other principal (changer): a 2xx identity answer for another principal or none at any point of the changer leaves the change unattributed', async () => {
  const withNotes = () => { const p = changerProfile(); p.checks.splice(3, 0, ctl('ADMIN-NOTES', 'admin', '/admin-notes')); p.requiredControlIds.push('ADMIN-NOTES'); return p; };
  // ADMIN-ME with the administrator's credential, in order: the control row (1), the opening point before ADMIN-NOTES (2), the
  // point after ADMIN-NOTES (3), the closing point after SUSPEND (4). SUSPEND is covered by points 3 and 4 only.
  const app = adminMe => {
    let suspended = false, n = 0;
    return async (origin, check, { credential }) => {
      const who = { 'tok-admin': 'admin', 'tok-carol': 'carol' }[credential] ?? null;
      if (check.path === '/me') {
        if (check.id === 'ADMIN-ME' && who === 'admin' && adminMe && ++n === adminMe.at) return reply(200, adminMe.json);
        return who && !(who === 'carol' && suspended) ? reply(200, { user: who }) : reply(401);
      }
      if (!who) return reply(401);
      if (check.path.endsWith('/suspend')) { if (who !== 'admin') return reply(403); suspended = true; return reply(200); }
      if (who === 'carol' && suspended) return reply(401);
      return reply(200, { items: [] });
    };
  };
  const suite = suiteOf(withNotes(), ENV);
  const clean = await runHttpAssessment(withNotes(), { env: ENV, transport: app(null), observerFactory: emptySink });
  assert.deepEqual([row(clean, 'SUSPEND').status, carol(clean).lifecycle.changerLoginProven, row(clean, 'REUSE').status], ['pass', true, 'pass']);
  for (const [why, json] of [['200 naming another principal', { user: 'mallory' }], ['200 null', null]]) {
    const run = await runHttpAssessment(withNotes(), { env: ENV, transport: app({ at: 2, json }), observerFactory: emptySink });
    const admin = run.identityEvidence.actors.find(a => a.actorId === 'admin');
    assert.deepEqual([admin.reason, admin.before[0].httpStatus, admin.before[0].predicates.find(p => p.identity).outcome], ['bracket-not-passed', 200, 'fail'], why);
    assert.deepEqual([row(run, 'SUSPEND').status, row(run, 'SUSPEND').assertions.find(a => a.name === IDENTITY_ASSERTION)?.actual, row(run, 'ADMIN-ME').status], ['inconclusive', IDENTITY_REASONS['bracket-not-passed'], 'inconclusive'], why);
    assert.deepEqual([carol(run).lifecycle.changeConfirmed, carol(run).lifecycle.changerLoginProven, carol(run).reason], [true, false, 'established'], why);
    const reuse = row(run, 'REUSE');
    assert.deepEqual([reuse.status, reuse.decision, reuse.assertions.find(a => a.name === IDENTITY_ASSERTION)?.actual], ['inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS['changer-login-unproven']], why);
    validateHttpRunEvidence(run); validateHttpRunEvidence(run, { expectedSuite: suite });
    // The attribution forged (the flag set, and REUSE restored to a pass and resealed) is refused, with and without the suite.
    const forged = structuredClone(run), r = row(forged, 'REUSE');
    carol(forged).lifecycle.changerLoginProven = true; r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.decision = 'pass'; reseal(r); recount(forged);
    assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/, why);
    assert.throws(() => validateHttpRunEvidence(forged, { expectedSuite: suite }), /invalid-run-evidence/, why);
  }
});
