// actor-identity/4 (src/contracts.mjs): the identity proof must hold on the protected surface it vouches
// for, and a credentialed 401 is an authentication failure unless the actor
// declares that the app answers denials with 401. Injected transport only:
// no socket, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile, identityReason, IDENTITY_ASSERTION, IDENTITY_REASONS, LOGIN_PROVEN_REASONS } from '../src/contracts.mjs';
import { digest } from '../src/domain.mjs';
import { createRegistry } from '../src/registry.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';

const env = { SCOPEHAVEN_TARGET_MEMBER: 'tok-member' };
// An app whose identity route checks only that a token decodes; its protected routes also check expiry.
// state.surface: 'ok' | 'expired-from-start' | 'expires-after' (protected routes reject once state.calls passes it).
function app(state) {
  return async (origin, check, { credential }) => {
    const ok = credential === 'tok-member';
    // Only protected-route calls count toward the expiry.
    const protectedOk = () => ok && !(state.surface === 'expired-from-start' || (state.surface === 'expires-after' && ++state.calls > state.after));
    const reply = (status, json = {}) => ({ status, complete: true, jsonParsed: true, json, bytes: 2 });
    if (check.path === '/me') return ok ? reply(200, { user: 'member' }) : reply(401);
    if (check.path === '/own') return protectedOk() ? reply(200, { items: [] }) : reply(state.expiredStatus ?? 401);
    if (check.path === '/foreign') return !ok ? reply(401) : !protectedOk() ? reply(state.expiredStatus ?? 401) : reply(state.denial ?? 403);
    return reply(404);
  };
}
const control = (id, path, extra = []) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId: 'member', method: 'GET', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, ...extra] });
function profile({ surface = true, refusesWith401 = false, expect = [403] } = {}) {
  const checks = [control('WHOAMI', '/me', [{ kind: 'json.equals', pointer: '/user', expected: 'member' }]), ...(surface ? [control('OWN', '/own')] : []),
    { id: 'FOREIGN', title: 'Member cannot read a foreign record', category: 'Object access', severity: 'high', actorId: 'member', method: 'GET', path: '/foreign', evidenceRequirement: 'response',
      assertions: [expect.length === 1 ? { kind: 'status.equals', expected: expect[0] } : { kind: 'status.in', expected: expect }] }];
  return { id: 'surface-app', name: 'Surface app', applicationId: 'surface-app', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { member: { principalId: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member', ...(refusesWith401 ? { refusesWith401: true } : {}) } },
    requiredControlIds: checks.filter(c => c.severity === 'control').map(c => c.id), checks };
}
const assess = async (p, state) => runHttpAssessment(p, { env, transport: app(state) });
const row = (run, id) => run.results.find(r => r.id === id);
const member = run => run.identityEvidence.actors[0];
const suiteOf = p => createRegistry({ profiles: [p], env }).exportSuite(p.id);

test('surface controls: a required GET control on a protected route is re-sent in the brackets with the identity control', async () => {
  const run = await assess(profile(), { surface: 'ok' });
  assert.equal(run.identityEvidence.schema, 'actor-identity/6');
  assert.deepEqual([member(run).surfaceControlIds, member(run).refusesWith401, member(run).reason], [['OWN'], false, 'established']);
  assert.deepEqual(member(run).after.map(p => p.controlId), ['WHOAMI', 'OWN']);
  // actor-identity/5: one intermediate probe point after each bracketed check but the last (here, after OWN).
  assert.deepEqual(member(run).between.map(b => [b.afterCheckId, b.probes.map(p => p.controlId)]), [['OWN', ['WHOAMI', 'OWN']]]);
  assert.equal(row(run, 'FOREIGN').status, 'pass');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile()) });
  assert.equal(suiteOf(profile()).identitySchema, 'actor-identity/6');
});

test('route mismatch from the start: the identity route accepts a credential the protected routes reject, so no row passes as that actor', async () => {
  const run = await assess(profile(), { surface: 'expired-from-start', expiredStatus: 403 });
  assert.equal(row(run, 'WHOAMI').trace[0].data.httpStatus, 200);
  assert.equal(member(run).reason, 'surface-refused');
  assert.equal(member(run).loginProven, false);
  // The foreign read answered 403 to an expired credential: never a pass.
  assert.equal(row(run, 'FOREIGN').status, 'inconclusive');
  assert.equal(row(run, 'FOREIGN').assertions.at(-1).actual, IDENTITY_REASONS['surface-refused']);
  validateHttpRunEvidence(run);
  assert.ok(summarizeGate({ candidate: run }).reasons.includes('identity-not-established'));
});

test('route mismatch mid-run: protected routes stop accepting the credential while the identity route still does; the closing surface bracket withholds the row', async () => {
  // Protected calls: the opening surface probe and the surface control are accepted; the foreign read (403, from the
  // expired credential) and the closing surface probe are not.
  const run = await assess(profile(), { surface: 'expires-after', after: 2, calls: 0, expiredStatus: 403 });
  assert.equal(row(run, 'OWN').trace[0].data.httpStatus, 200, 'the surface control itself was accepted');
  assert.deepEqual(member(run).after.map(p => [p.controlId, p.httpStatus]), [['WHOAMI', 200], ['OWN', 403]]);
  assert.equal(member(run).reason, 'surface-refused');
  assert.equal(row(run, 'FOREIGN').status, 'inconclusive');
  validateHttpRunEvidence(run);
});

test('a credentialed 401 is an authentication failure, not a refusal, unless the actor declares that the app answers denials with 401', async () => {
  // Undeclared: the boundary expects 401 or 403 and gets 401 for an authenticated member: withheld.
  const undeclared = await assess(profile({ expect: [401, 403] }), { surface: 'ok', denial: 401 });
  assert.equal(member(undeclared).reason, 'established');
  assert.equal(row(undeclared, 'FOREIGN').status, 'inconclusive');
  assert.equal(row(undeclared, 'FOREIGN').assertions.find(a => a.name === IDENTITY_ASSERTION).actual, IDENTITY_REASONS['unauthenticated-401']);
  validateHttpRunEvidence(undeclared);
  // A 403 stays an authorization refusal.
  assert.equal(row(await assess(profile({ expect: [401, 403] }), { surface: 'ok', denial: 403 }), 'FOREIGN').status, 'pass');
  // Declared and bracketed by a surface control: the 401 counts as the refusal.
  const declared = await assess(profile({ expect: [401, 403], refusesWith401: true }), { surface: 'ok', denial: 401 });
  assert.equal(row(declared, 'FOREIGN').status, 'pass');
  validateHttpRunEvidence(declared, { expectedSuite: suiteOf(profile({ expect: [401, 403], refusesWith401: true })) });
  // Declared without a surface control: the identity proof does not show the credential authenticated on the protected routes.
  const unbracketed = await assess(profile({ surface: false, expect: [401, 403], refusesWith401: true }), { surface: 'ok', denial: 401 });
  assert.equal(row(unbracketed, 'FOREIGN').assertions.find(a => a.name === IDENTITY_ASSERTION).actual, IDENTITY_REASONS['surface-unproven']);
  validateHttpRunEvidence(unbracketed);
  // Declared, but the protected routes reject the credential mid-run: the 401 is the expired credential, and the bracket says so.
  const expiring = await assess(profile({ expect: [401, 403], refusesWith401: true }), { surface: 'expires-after', after: 2, calls: 0 });
  assert.equal(row(expiring, 'FOREIGN').trace[0].data.httpStatus, 401);
  assert.deepEqual([member(expiring).reason, row(expiring, 'FOREIGN').status], ['surface-refused', 'inconclusive']);
  // The declaration is profile-level: an actor without a credential cannot carry it.
  const bad = profile(); bad.actors.anon = { principalId: 'anon', refusesWith401: true };
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [bad] }), /"refusesWith401" is true on an actor with a "credentialEnv"/);
});

// The 403 identity-route rule: a refusal counts only after the same actor's earlier
// complete 2xx on a protected route. Without a surface control the login was proven only on the identity route, so a
// 403 (or a 404, or any answer outside 2xx) on a boundary row reads inconclusive, whether the app refused the request
// or rejected the credential. This replaces the earlier pinned limit, where the expired credential's 403 passed.
test('403 rule: without a surface control, a refusal on a boundary row reads inconclusive (surface-unproven); with one it counts', async () => {
  for (const [why, state, expect] of [['a credential the protected routes reject (403)', { surface: 'expired-from-start', expiredStatus: 403 }, [403]],
    ['an app that refuses the request (403)', { surface: 'ok', denial: 403 }, [403]], ['an app that hides the record (404)', { surface: 'ok', denial: 404 }, [404]]]) {
    const run = await assess(profile({ surface: false, expect }), state);
    assert.deepEqual([member(run).surfaceControlIds, member(run).reason], [[], 'established'], why);
    assert.equal(row(run, 'FOREIGN').status, 'inconclusive', why);
    assert.equal(row(run, 'FOREIGN').assertions.find(a => a.name === IDENTITY_ASSERTION).actual, IDENTITY_REASONS['surface-unproven'], why);
    assert.equal(row(run, 'WHOAMI').status, 'pass', `${why}: the identity control keeps its own verdict`);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile({ surface: false, expect })) });
    assert.ok(summarizeGate({ candidate: run }).reasons.includes('inconclusive-evidence'), why);
  }
  // The same refusal with a surface control that passed in the brackets is a refusal.
  for (const [denial, expect] of [[403, [403]], [404, [404]]]) assert.equal(row(await assess(profile({ expect }), { surface: 'ok', denial }), 'FOREIGN').status, 'pass', String(denial));
  // A 2xx row of an actor without a surface control is not affected (it is not a refusal).
  const open = await assess(profile({ surface: false, expect: [200] }), { surface: 'ok', denial: 200 });
  assert.equal(row(open, 'FOREIGN').status, 'pass');
});

test('403 rule is versioned: an actor-identity/3 run keeps its earlier rule, where the 403 counted without a surface control', async () => {
  const p = profile({ surface: false }), run = await assess(p, { surface: 'ok', denial: 403 });
  assert.equal(row(run, 'FOREIGN').status, 'inconclusive');
  // The same evidence under the /3 rules: no surface list, no intermediate points, no per-row decision, no principals, no
  // identity assertion on the 403 row, resealed.
  const old = structuredClone(run), r = row(old, 'FOREIGN');
  old.identityEvidence.schema = 'actor-identity/3'; delete member(old).surfaceControlIds; delete member(old).refusesWith401; delete member(old).between; delete old.principals;
  for (const x of old.results) delete x.decision;
  dropRouteSegments(old); // actor-identity/6 fields go with the relabel
  r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.summary = 'Configured response predicates passed.';
  r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions });
  old.counts = { ...old.counts, pass: old.counts.pass + 1, inconclusive: old.counts.inconclusive - 1 };
  validateHttpRunEvidence(old);
  // Left as a /4 record, the restored pass is refused: the /4 recompute withholds it.
  const forged = structuredClone(old); forged.identityEvidence.schema = 'actor-identity/4'; Object.assign(member(forged), { surfaceControlIds: [], refusesWith401: false });
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
});

// Every surface probe in a bracket must pass in full, its status and every
// predicate. The earlier rule counted a surface bracket as held unless it was refused, so a 500, a 404, a failing 200 or an
// inconclusive 200 left the actor established and its boundary 403 passing.
function bracketApp(closing) {
  const calls = { own: 0 };
  return async (origin, check, { credential }) => {
    const ok = credential === 'tok-member', reply = (status, json = {}, extra = {}) => ({ status, complete: true, jsonParsed: true, json, bytes: 2, ...extra });
    if (check.path === '/me') return ok ? reply(200, { user: 'member' }) : reply(401);
    // /own calls in order: the opening surface probe, the surface control itself, the probe point after it (actor-identity/5),
    // the closing surface probe.
    if (check.path === '/own') return !ok ? reply(401) : ++calls.own === 4 ? closing() : reply(200, { items: [] });
    if (check.path === '/foreign') return ok ? reply(403) : reply(401);
    return reply(404);
  };
}
const surfaceProfile = () => { const p = profile(); p.checks.find(c => c.id === 'OWN').assertions.push({ kind: 'json.exists', pointer: '/items', expected: true }); return p; };
test('a surface bracket that does not pass in full (500, 404, failing 200, inconclusive 200) leaves the actor not established', async () => {
  for (const [why, closing, outcome] of [['500', () => ({ status: 500, complete: true, jsonParsed: true, json: {}, bytes: 2 }), 'fail'],
    ['404', () => ({ status: 404, complete: true, jsonParsed: true, json: {}, bytes: 2 }), 'fail'],
    ['failing 200', () => ({ status: 200, complete: true, jsonParsed: true, json: { error: 'session expired' }, bytes: 2 }), 'fail'],
    ['inconclusive 200', () => ({ status: 200, complete: true, jsonParsed: false, json: undefined, bytes: 9, error: 'invalid-json' }), 'inconclusive']]) {
    const p = surfaceProfile(), run = await runHttpAssessment(p, { env, transport: bracketApp(closing) });
    assert.deepEqual(member(run).after.map(probe => [probe.controlId, probe.outcome]), [['WHOAMI', 'pass'], ['OWN', outcome]], why);
    assert.deepEqual([member(run).reason, member(run).established, member(run).loginProven], ['surface-not-passed', false, true], why);
    assert.equal(row(run, 'OWN').status, 'pass', `${why}: the surface control row itself passed and keeps its verdict (login proven)`);
    assert.equal(row(run, 'FOREIGN').status, 'inconclusive', `${why}: the boundary 403 never passes`);
    assert.equal(row(run, 'FOREIGN').assertions.find(a => a.name === IDENTITY_ASSERTION).actual, IDENTITY_REASONS['surface-not-passed'], why);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
    assert.ok(summarizeGate({ candidate: run }).reasons.includes('identity-not-established'), why);
    // The validator recomputes the reason from the stored probes: a record that says "established" is refused.
    const forged = structuredClone(run), entry = member(forged), r = row(forged, 'FOREIGN');
    Object.assign(entry, { reason: 'established', established: true });
    r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass';
    r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions });
    forged.counts = { ...forged.counts, pass: forged.counts.pass + 1, inconclusive: forged.counts.inconclusive - 1 };
    assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/, why);
  }
  // A refused surface bracket still leaves the login unproven (surface-refused), as before.
  const refused = await runHttpAssessment(surfaceProfile(), { env, transport: bracketApp(() => ({ status: 403, complete: true, jsonParsed: true, json: {}, bytes: 2 })) });
  assert.deepEqual([member(refused).reason, member(refused).loginProven], ['surface-refused', false]);
});

test('identityReason (pure) withholds a required surface bracket that is 500, 404, a failing 200 or an inconclusive 200, after the credential probes', () => {
  const identity = { controlId: 'identity', httpStatus: 200, outcome: 'pass' }, refusal = { controlId: 'identity', httpStatus: 401, outcome: 'fail', requestAttempted: true };
  const base = { identityControls: ['identity'], identityControlsPassed: true, requiredPassed: true, anonymous: [refusal], invalid: [refusal], cross: [], refusalStatuses: [401, 403], surfaceControls: ['surface'] };
  for (const [httpStatus, outcome] of [[500, 'fail'], [404, 'fail'], [200, 'fail'], [200, 'inconclusive']]) {
    const surface = { controlId: 'surface', httpStatus, outcome };
    assert.equal(identityReason({ ...base, before: [identity, surface], after: [identity, { ...surface, outcome: 'pass' }] }), 'surface-not-passed', `${httpStatus}/${outcome} opening`);
    assert.equal(identityReason({ ...base, before: [identity, { ...surface, outcome: 'pass' }], after: [identity, surface] }), 'surface-not-passed', `${httpStatus}/${outcome} closing`);
  }
  const passing = { controlId: 'surface', httpStatus: 200, outcome: 'pass' };
  assert.equal(identityReason({ ...base, before: [identity, passing], after: [identity, passing] }), 'established');
  // A credential probe that was not refused still outranks it: the login is unproven, not merely not established.
  const accepted = { controlId: 'identity', httpStatus: 200, outcome: 'pass', requestAttempted: true, transportOutcome: 'complete', predicates: [{ identity: true, outcome: 'pass' }] };
  assert.equal(identityReason({ ...base, invalid: [accepted], before: [identity, { ...passing, httpStatus: 500, outcome: 'fail' }], after: [identity, passing] }), 'accepted-invalid-credential');
  assert.equal(LOGIN_PROVEN_REASONS.includes('surface-not-passed'), true);
});

test('the validator recomputes the surface control list: an extra, a missing or a reordered id is refused', async () => {
  const p = profile(), run = await assess(p, { surface: 'ok' });
  assert.doesNotThrow(() => validateHttpRunEvidence(run));
  const second = control('OWN-2', '/own'); p.checks.splice(2, 0, second); p.requiredControlIds.push('OWN-2');
  const two = await assess(p, { surface: 'ok' });
  assert.deepEqual(member(two).surfaceControlIds, ['OWN', 'OWN-2']);
  for (const [why, list] of [['extra id', ['OWN', 'OWN-2', 'WHOAMI']], ['missing id', ['OWN']], ['reordered', ['OWN-2', 'OWN']]]) {
    const edited = structuredClone(two); member(edited).surfaceControlIds = list;
    assert.throws(() => validateHttpRunEvidence(edited), /invalid-run-evidence/, why);
  }
});

test('an exported suite binds the identity rule version on its own (only identitySchema differs)', async () => {
  const p = profile(), run = await assess(p, { surface: 'ok' }), suite = suiteOf(p);
  validateHttpRunEvidence(run, { expectedSuite: suite });
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: { ...suite, identitySchema: 'actor-identity/3' } }), e => e.code === 'unexpected-suite-evidence');
});

test('the rules are versioned: actor-identity/3 evidence keeps the earlier rules, and the suite binds the version', async () => {
  const run = await assess(profile({ expect: [401, 403] }), { surface: 'ok', denial: 401 });
  const relabelled = structuredClone(run), entry = member(relabelled);
  relabelled.identityEvidence.schema = 'actor-identity/3';
  delete entry.surfaceControlIds; delete entry.refusesWith401;
  // The /5-only fields go too (its points, its principals, each row's decision), so the only thing left to refuse is the 401 row.
  delete entry.between; delete relabelled.principals; for (const x of relabelled.results) delete x.decision;
  dropRouteSegments(relabelled); // actor-identity/6 fields go with the relabel
  for (const side of ['before', 'after']) entry[side] = entry[side].filter(p => p.controlId !== 'OWN');
  // Under the earlier rules the 401 needs no identity assertion, so the /4 row no longer matches its recompute.
  assert.throws(() => validateHttpRunEvidence(relabelled), /invalid-run-evidence/);
  // That recompute is what refuses it: with the 401 row's identity assertion dropped and its pass restored, the same relabel validates.
  const consistent = structuredClone(relabelled), r = row(consistent, 'FOREIGN');
  r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); recountRun(consistent);
  validateHttpRunEvidence(consistent);
  assert.throws(() => validateHttpRunEvidence(relabelled, { expectedSuite: suiteOf(profile({ expect: [401, 403] })) }), /unexpected-suite-evidence|invalid-run-evidence/);
  // A /4 entry without its surface list, or one that drops a surface bracket, is refused.
  const dropped = structuredClone(run); delete member(dropped).surfaceControlIds;
  assert.throws(() => validateHttpRunEvidence(dropped), /invalid-run-evidence/);
  const unbracketed = structuredClone(run); member(unbracketed).after = member(unbracketed).after.filter(p => p.controlId !== 'OWN');
  assert.throws(() => validateHttpRunEvidence(unbracketed), /invalid-run-evidence/);
});

// ---------------------------------------------------------------------------
// actor-identity/5: identity provenance per check.
// One unprovable login used to invalidate every check of its actor, because identity was proven per actor by
// a bracket re-sent after the actor's last check. Now the identity and surface controls are re-sent at a probe point after
// every bracketed check, each check is bound to the two points covering it, and a boundary row whose own refusal was
// observed while its identity or allowed use was not established for it is the distinct state "prohibition observed,
// identity or allowed use not established" (its decision string stays prohibition-observed-identity-unproven).
import { compareRuns } from '../src/runner.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { renderReport } from '../src/report.mjs';
import { IDENTITY_UNPROVEN_DECISION, IDENTITY_UNPROVEN_SUMMARY, ROW_DECISIONS, pointReason, coveringPoints, rowDecision, rowIdentityReason, surfaceRefusedAnywhere, identityRefusedAnywhere, PRECONDITION_ASSERTION, PRECONDITION_REASONS, withheldSummary } from '../src/contracts.mjs';

// Protected /own calls in order: the opening point, the OWN control, then the point after each bracketed check. state.failAt
// names the /own call (1-based) that answers state.failStatus (403 by default); state.own and state.me map a /own or /me call
// made with the member's credential (1-based) to the status it answers instead ('error': no response at all; an object
// { status, json } answers that status with that JSON body, as a 200 naming another principal or null). /me calls in
// order: the WHOAMI control, then the identity probe of each point. state.acceptAnonymous makes the identity route answer the
// member's identity without a credential; state.denials maps a boundary path to its status (403 by default).
function pointApp(state) {
  let own = 0, me = 0;
  return async (origin, check, { credential }) => {
    const ok = credential === 'tok-member', reply = (status, json = {}) => status === 'error' ? { status: null, complete: false, jsonParsed: false, json: undefined, bytes: 0, error: 'network' } : { status, complete: true, jsonParsed: true, json, bytes: 2 };
    if (check.path === '/me') {
      if (!ok) return state.acceptAnonymous && credential === undefined ? reply(200, { user: 'member' }) : reply(401);
      const status = state.me?.[++me];
      if (status !== null && typeof status === 'object') return reply(status.status, status.json);
      return status === undefined ? reply(200, { user: 'member' }) : reply(status);
    }
    if (check.path === '/own') {
      if (!ok) return reply(401);
      const n = ++own, status = n === state.failAt ? state.failStatus ?? 403 : state.own?.[n];
      return status === undefined ? reply(200, { items: [] }) : reply(status);
    }
    if (check.path.startsWith('/foreign')) return !ok ? reply(401) : reply(state.denials?.[check.path] ?? 403);
    return reply(404);
  };
}
const boundary = (id, path) => ({ id, title: id, category: 'Object access', severity: 'high', actorId: 'member', method: 'GET', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] });
const pointProfile = () => ({ ...profile(), id: 'points-app', applicationId: 'points-app', checks: [control('WHOAMI', '/me', [{ kind: 'json.equals', pointer: '/user', expected: 'member' }]), control('OWN', '/own'), boundary('F1', '/foreign/1'), boundary('F2', '/foreign/2'), boundary('F3', '/foreign/3')] });
const pointAssess = state => runHttpAssessment(pointProfile(), { env, transport: pointApp(state) });
const identityOf = r => r.assertions.find(a => a.name === IDENTITY_ASSERTION)?.actual;

test('per-check identity: an identity failure invalidates only the checks its probe point covers; a later failure never demotes an earlier check whose own points passed', async () => {
  // /own calls: p0 (1), OWN (2), p1 after OWN (3), p2 after F1 (4), p3 after F2 (5), p4 after F3 (6). /me calls: WHOAMI (1),
  // then the identity probe of p0 (2), p1 (3), p2 (4), p3 (5) and p4 (6). The identity probe of the point after F2 answers 500:
  // it did not pass, and it is not a refusal. (A probe refused with the actor's own credential, identity or surface, withholds
  // every row of the actor instead: the surface- and identity-refusal rules, tested below.)
  const run = await pointAssess({ me: { 5: 500 } }), m = member(run);
  assert.equal(run.identityEvidence.schema, 'actor-identity/6');
  assert.deepEqual(m.between.map(b => [b.afterCheckId, b.probes.map(p => [p.controlId, p.httpStatus, p.kind])]), [['OWN', [['WHOAMI', 200, 'between'], ['OWN', 200, 'between']]], ['F1', [['WHOAMI', 200, 'between'], ['OWN', 200, 'between']]], ['F2', [['WHOAMI', 500, 'between'], ['OWN', 200, 'between']]]]);
  assert.deepEqual([m.reason, m.loginProven, m.established], ['bracket-not-passed', false, false], 'the actor-level summary still reads every point');
  // The checks covered by passing points keep their own status; the two the failed point covers are the third state.
  assert.deepEqual(run.results.map(r => [r.id, r.status, r.decision]), [['WHOAMI', 'pass', 'pass'], ['OWN', 'pass', 'pass'], ['F1', 'pass', 'pass'], ['F2', 'inconclusive', IDENTITY_UNPROVEN_DECISION], ['F3', 'inconclusive', IDENTITY_UNPROVEN_DECISION]]);
  assert.deepEqual([identityOf(row(run, 'F1')), identityOf(row(run, 'F2')), identityOf(row(run, 'F3'))], [undefined, IDENTITY_REASONS['bracket-not-passed'], IDENTITY_REASONS['bracket-not-passed']]);
  // actor-identity/6: the summary keeps the third state's sentence and names the reason that fired.
  assert.equal(row(run, 'F2').summary, withheldSummary('bracket-not-passed', [], true));
  assert.deepEqual(run.counts, { pass: 3, fail: 0, inconclusive: 2, error: 0, not_applicable: 0 });
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(pointProfile()) });
  // Only the closing point failed: only the last check is withheld.
  const closing = await pointAssess({ me: { 6: 500 } });
  assert.deepEqual(closing.results.map(r => r.status), ['pass', 'pass', 'pass', 'pass', 'inconclusive']);
  assert.deepEqual([member(closing).reason, row(closing, 'F3').decision], ['bracket-not-passed', IDENTITY_UNPROVEN_DECISION]);
  validateHttpRunEvidence(closing);
  // The opening point failed: only OWN, the check it covers (a required control, its login not proven for it), is withheld;
  // every boundary rests on later points that passed. A control in that position is plainly inconclusive: no prohibition was observed.
  const opening = await pointAssess({ me: { 2: 500 } });
  assert.deepEqual(opening.results.map(r => [r.id, r.status]), [['WHOAMI', 'pass'], ['OWN', 'inconclusive'], ['F1', 'pass'], ['F2', 'pass'], ['F3', 'pass']]);
  assert.deepEqual([row(opening, 'OWN').decision, identityOf(row(opening, 'OWN')), member(opening).reason], ['inconclusive', IDENTITY_REASONS['bracket-not-passed'], 'bracket-not-passed']);
  validateHttpRunEvidence(opening);
  // The surface-refusal rule: the opening point's surface probe refused instead. The refusal withholds every row of the
  // actor, the identity control and the checks whose own points accepted included (this case read point-level before).
  const refused = await pointAssess({ failAt: 1 });
  assert.deepEqual(refused.results.map(r => [r.id, r.status, r.decision, identityOf(r)]), [['WHOAMI', 'inconclusive', 'inconclusive', IDENTITY_REASONS['surface-refused']], ['OWN', 'inconclusive', 'inconclusive', IDENTITY_REASONS['surface-refused']],
    ...['F1', 'F2', 'F3'].map(id => [id, 'inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS['surface-refused']])]);
  assert.equal(member(refused).reason, 'surface-refused');
  validateHttpRunEvidence(refused, { expectedSuite: suiteOf(pointProfile()) });
  // A surface probe that fails for another reason (500) withholds its checks as not established, and leaves the login proven.
  const broken = await pointAssess({ failAt: 4, failStatus: 500 });
  assert.deepEqual([member(broken).reason, member(broken).loginProven, broken.results.map(r => r.status)], ['surface-not-passed', true, ['pass', 'pass', 'inconclusive', 'inconclusive', 'pass']]);
  assert.equal(identityOf(row(broken, 'F1')), IDENTITY_REASONS['surface-not-passed']);
  validateHttpRunEvidence(broken);
});

test('the evidence requirement is kept: an identity route that does not refuse an anonymous request invalidates every check of the actor', async () => {
  const run = await pointAssess({ acceptAnonymous: true });
  assert.deepEqual([member(run).reason, member(run).loginProven], ['not-refused-without-credential', false]);
  assert.deepEqual(run.results.map(r => r.status), ['inconclusive', 'inconclusive', 'inconclusive', 'inconclusive', 'inconclusive']);
  assert.deepEqual(run.results.map(r => r.decision), ['inconclusive', 'inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_UNPROVEN_DECISION, IDENTITY_UNPROVEN_DECISION]);
  validateHttpRunEvidence(run);
  assert.ok(summarizeGate({ candidate: run }).reasons.includes('identity-not-established'));
});

test('the third state is distinct in the run record and in the exports, and never a pass: the gate reports it and credits no repair on it', async () => {
  // The identity probe of the point after F2 answered 500 (point-level: F2 and F3 are withheld, F1 keeps its pass).
  const run = await pointAssess({ me: { 5: 500 } }), third = row(run, 'F2');
  assert.deepEqual([third.status, third.decision, ROW_DECISIONS.includes(third.decision), third.decision === 'inconclusive'], ['inconclusive', IDENTITY_UNPROVEN_DECISION, true, false]);
  const sarif = renderSarif(run), result = id => sarif.runs[0].results.find(r => r.ruleId === id);
  assert.deepEqual([result('F2').properties.scopehavenStatus, result('F2').properties.scopehavenDecision, result('F2').kind, result('F1').properties.scopehavenDecision], ['inconclusive', IDENTITY_UNPROVEN_DECISION, 'open', 'pass']);
  assert.match(renderReport(run), /F2 · F2<\/h2><p><strong>INCONCLUSIVE<\/strong> · prohibition-observed-identity-unproven · high/);
  // The gate: not a pass, reported as the third state beside the inconclusive evidence.
  const gate = summarizeGate({ candidate: run });
  assert.deepEqual([gate.exitCode, gate.reasons], [1, ['inconclusive-evidence', 'prohibition-observed-identity-unproven', 'identity-not-established']]);
  // No repair is credited on it: a leaky baseline (F2 answered 200) is not restored by a third-state candidate.
  const leaky = await pointAssess({ denials: { '/foreign/2': 200 } });
  assert.equal(row(leaky, 'F2').status, 'fail');
  const comparison = compareRuns(leaky, run);
  assert.deepEqual([comparison.compatible, comparison.rows.find(r => r.id === 'F2').transition, comparison.summary.fixed], [true, 'unverified', 0]);
  assert.notEqual(summarizeGate({ candidate: run, baseline: leaky }).exitCode, 0);
  // A baseline whose F2 was the third state cannot show a fix on F2, but its other rows still verify.
  const fixedF1 = await pointAssess({});
  const fromThird = compareRuns(run, fixedF1);
  assert.deepEqual([fromThird.rows.find(r => r.id === 'F2').transition, fromThird.rows.find(r => r.id === 'F1').transition], ['unverified', 'preserved']);
  // A baseline row that failed while its identity was not proven for it (a 200 behind a failed point) cannot show a fix
  // either, while the same actor's rows with proven points still can: identity binds the baseline per row.
  const leakyUnproven = await pointAssess({ me: { 5: 500 }, denials: { '/foreign/2': 200, '/foreign/1': 200 } });
  assert.deepEqual([row(leakyUnproven, 'F2').status, identityOf(row(leakyUnproven, 'F2')), row(leakyUnproven, 'F1').status, identityOf(row(leakyUnproven, 'F1'))], ['fail', IDENTITY_REASONS['bracket-not-passed'], 'fail', undefined]);
  const perRow = compareRuns(leakyUnproven, fixedF1);
  assert.deepEqual([perRow.rows.find(r => r.id === 'F2').transition, perRow.rows.find(r => r.id === 'F1').transition, perRow.summary.fixed], ['unverified', 'contract-restored', 1]);
});

test('the validator binds the third state: it cannot be edited into a pass, hidden as plain inconclusive, or claimed on a control', async () => {
  // The identity probe of the point after F2 answered 500: F2 and F3 are the third state, F1 keeps its pass.
  const run = await pointAssess({ me: { 5: 500 } });
  validateHttpRunEvidence(run);
  const edit = change => { const copy = structuredClone(run); change(copy); recountRun(copy); return copy; };
  const resealRow = r => { r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); };
  // Into a pass, assertion dropped and resealed: the identity reason is recomputed from the stored points.
  assert.throws(() => validateHttpRunEvidence(edit(c => { const r = row(c, 'F2'); r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.decision = 'pass'; resealRow(r); })), e => e.code === 'invalid-run-evidence');
  // The decision alone edited, status and assertions kept.
  assert.throws(() => validateHttpRunEvidence(edit(c => { row(c, 'F2').decision = 'pass'; })), e => e.code === 'invalid-run-evidence');
  assert.throws(() => validateHttpRunEvidence(edit(c => { row(c, 'F2').decision = 'inconclusive'; })), e => e.code === 'invalid-run-evidence');
  assert.throws(() => validateHttpRunEvidence(edit(c => { delete row(c, 'F2').decision; })), e => e.code === 'invalid-run-evidence');
  // The third state claimed on a passing row, or on the control the refused point also covers.
  assert.throws(() => validateHttpRunEvidence(edit(c => { row(c, 'F1').decision = IDENTITY_UNPROVEN_DECISION; })), e => e.code === 'invalid-run-evidence');
  const opening = await pointAssess({ failAt: 1 });
  assert.throws(() => validateHttpRunEvidence((() => { const c = structuredClone(opening); row(c, 'OWN').decision = IDENTITY_UNPROVEN_DECISION; return c; })()), e => e.code === 'invalid-run-evidence');
  // The probe point dropped from the record (the actor relabelled as proven): the between list is recomputed from the rows.
  assert.throws(() => validateHttpRunEvidence(edit(c => { member(c).between.pop(); })), e => e.code === 'invalid-run-evidence');
  // The failed probe edited into a consistent pass (status, predicates and outcome): the reasons recomputed from it no longer match.
  assert.throws(() => validateHttpRunEvidence(edit(c => { const p = member(c).between[2].probes[0]; Object.assign(p, { httpStatus: 200, statusOutcome: 'pass', outcome: 'pass', predicates: p.predicates.map(x => ({ ...x, outcome: 'pass' })) }); })), e => e.code === 'invalid-run-evidence');
  assert.throws(() => validateHttpRunEvidence(edit(c => { member(c).between[2].afterCheckId = 'F1'; })), e => e.code === 'invalid-run-evidence');
  // Each intermediate probe is validated like a bracket probe: an attempted probe with no applied timeout is malformed.
  assert.throws(() => validateHttpRunEvidence(edit(c => { member(c).between[0].probes[0].requestTimeoutMs = 0; })), e => e.code === 'invalid-run-evidence');
  // A clean run whose last intermediate point is dropped: every remaining point is consistent and the reason unchanged, so
  // only the count of points (one after every bracketed check but the last) refuses it.
  const clean = await pointAssess({}); validateHttpRunEvidence(clean);
  assert.throws(() => validateHttpRunEvidence((() => { const c = structuredClone(clean); member(c).between.pop(); return c; })()), e => e.code === 'invalid-run-evidence');
  // Pure: the point and the covering points. The probes carry requestAttempted, transportOutcome and predicates as a stored
  // probe does, since identityRefusedAnywhere reads them through identityRefused (the other-principal rule); the identity predicate passes.
  const pass = { controlId: 'WHOAMI', requestAttempted: true, transportOutcome: 'complete', httpStatus: 200, outcome: 'pass', predicates: [{ kind: 'json.equals', outcome: 'pass', identity: true }] };
  const surfacePass = { controlId: 'OWN', requestAttempted: true, transportOutcome: 'complete', httpStatus: 200, outcome: 'pass', predicates: [] };
  assert.equal(pointReason([pass, surfacePass], ['OWN'], [401, 403]), null);
  assert.equal(pointReason([pass, { ...surfacePass, httpStatus: 403, outcome: 'fail' }], ['OWN'], [401, 403]), 'surface-refused');
  assert.equal(pointReason([pass, { ...surfacePass, httpStatus: 500, outcome: 'fail' }], ['OWN'], [401, 403]), 'surface-not-passed');
  assert.equal(pointReason([{ ...pass, httpStatus: 401, outcome: 'fail' }, surfacePass], ['OWN'], [401, 403]), 'bracket-not-passed');
  assert.equal(pointReason([{ ...pass, outcome: 'error' }, surfacePass], ['OWN'], [401, 403]), 'identity-probe-incomplete');
  const entry = { before: ['b'], between: [{ afterCheckId: 'OWN', probes: ['p1'] }, { afterCheckId: 'F1', probes: ['p2'] }], after: ['a'] };
  assert.deepEqual([coveringPoints(entry, ['OWN', 'F1', 'F2'], 'OWN'), coveringPoints(entry, ['OWN', 'F1', 'F2'], 'F1'), coveringPoints(entry, ['OWN', 'F1', 'F2'], 'F2'), coveringPoints(entry, ['OWN', 'F1', 'F2'], 'WHOAMI')], [[['b'], ['p1']], [['p1'], ['p2']], [['p2'], ['a']], null]);
  assert.deepEqual([rowDecision({ severity: 'high', status: 'pass' }, 'surface-refused'), rowDecision({ severity: 'control', status: 'pass' }, 'surface-refused'), rowDecision({ severity: 'high', status: 'pass' }, null), rowDecision({ severity: 'high', status: 'fail' }, 'surface-refused')], [IDENTITY_UNPROVEN_DECISION, 'pass', 'pass', 'fail']);
  // Pure: a check's two covering points are ranked together with the actor-level precedence, so a surface 500 at the earlier
  // point (surface-not-passed, login proven) never hides an identity probe that did not pass or did not finish at the later one.
  // The identity probe answers 500 here, not a refusal: a refused one is route-level (the identity-refusal rule, below) whatever the ranking.
  const s500 = { ...surfacePass, httpStatus: 500, outcome: 'fail' }, id401 = { ...pass, httpStatus: 401, outcome: 'fail' }, id500 = { ...pass, httpStatus: 500, outcome: 'fail' }, idError = { ...pass, httpStatus: null, outcome: 'error' };
  const entryOf = (before, between, after) => ({ before, between, after, surfaceControlIds: ['OWN'], refusalStatuses: [401, 403], refusesWith401: false, established: false });
  for (const [later, reason] of [[id500, 'bracket-not-passed'], [idError, 'identity-probe-incomplete'], [pass, 'surface-not-passed']]) {
    const e = entryOf([pass, s500], [{ afterCheckId: 'OWN', probes: [later, surfacePass] }], [pass, surfacePass]), points = coveringPoints(e, ['OWN', 'F1'], 'OWN');
    const judge = required => rowIdentityReason({ credentialed: true, required, control: required, entry: e, httpStatus: required ? 200 : 403, controlFailed: false, rules: 5, route: 'established', points });
    // A required control is withheld only for a login-level reason; a boundary check carries the more severe reason either way.
    assert.deepEqual([judge(true), judge(false)], [reason === 'surface-not-passed' ? null : reason, reason], reason);
    // Either order: the reason does not depend on which point comes first.
    assert.equal(rowIdentityReason({ credentialed: true, required: false, control: false, entry: e, httpStatus: 403, controlFailed: false, rules: 5, route: 'established', points: [points[1], points[0]] }), reason, `${reason} reversed`);
  }
  // The surface-refusal rule (pure): a refused surface probe at any point, read from the probes (not the actor-level reason).
  const s403 = { ...surfacePass, httpStatus: 403, outcome: 'fail' };
  assert.deepEqual([surfaceRefusedAnywhere(entryOf([pass, surfacePass], [{ afterCheckId: 'OWN', probes: [pass, s403] }], [pass, surfacePass])), surfaceRefusedAnywhere(entryOf([pass, s403], [], [pass, surfacePass])),
    surfaceRefusedAnywhere(entryOf([pass, surfacePass], [], [id401, s403])), surfaceRefusedAnywhere(entryOf([pass, surfacePass], [{ afterCheckId: 'OWN', probes: [id401, s500] }], [pass, surfacePass]))], [true, true, true, false]);
  // The identity-refusal rule (pure): an identity probe that answered a refusal status at any point (before, between or after), read from the
  // probes; an identity 500, an unfinished identity probe or a refused surface probe is not one, nor is an undeclared redirect.
  const id403 = { ...pass, httpStatus: 403, outcome: 'fail' }, id302 = { ...pass, httpStatus: 302, outcome: 'fail' };
  assert.deepEqual([identityRefusedAnywhere(entryOf([id401, surfacePass], [], [pass, surfacePass])), identityRefusedAnywhere(entryOf([pass, surfacePass], [{ afterCheckId: 'OWN', probes: [id401, surfacePass] }], [pass, surfacePass])),
    identityRefusedAnywhere(entryOf([pass, surfacePass], [], [id403, surfacePass])), identityRefusedAnywhere(entryOf([pass, surfacePass], [{ afterCheckId: 'OWN', probes: [id500, s403] }], [idError, surfacePass])),
    identityRefusedAnywhere({ ...entryOf([id302, surfacePass], [], [pass, surfacePass]), refusalStatuses: [401, 403, 302] }), identityRefusedAnywhere(entryOf([id302, surfacePass], [], [pass, surfacePass]))], [true, true, true, false, true, false]);
  // Both refused: bracket-not-passed, which identityReason ranks above surface-refused, on every row of the actor (a check whose
  // own points accepted, the identity control, a required control).
  const bothRefused = entryOf([pass, s403], [{ afterCheckId: 'OWN', probes: [id401, surfacePass] }, { afterCheckId: 'F1', probes: [pass, surfacePass] }], [pass, surfacePass]), bracketed = ['OWN', 'F1', 'F2'];
  const judgeBoth = (required, control, points) => rowIdentityReason({ credentialed: true, required, control, entry: bothRefused, httpStatus: control ? 200 : 403, controlFailed: false, rules: 5, route: 'established', points });
  assert.deepEqual(coveringPoints(bothRefused, bracketed, 'F2'), [[pass, surfacePass], [pass, surfacePass]], 'F2\'s own two points accepted in full');
  assert.deepEqual([judgeBoth(false, false, coveringPoints(bothRefused, bracketed, 'F2')), judgeBoth(true, true, null), judgeBoth(true, true, coveringPoints(bothRefused, bracketed, 'OWN'))], ['bracket-not-passed', 'bracket-not-passed', 'bracket-not-passed']);
  assert.equal(identityReason({ identityControls: ['WHOAMI'], identityControlsPassed: true, requiredPassed: true, before: bothRefused.before, between: bothRefused.between.flatMap(p => p.probes), after: bothRefused.after, anonymous: [], invalid: [], cross: [], refusalStatuses: [401, 403], surfaceControls: ['OWN'] }), 'bracket-not-passed', 'the actor-level order the row reason follows');
  // The other-principal rule (pure): an identity probe is refused as identityRefused judges it, so a complete 2xx whose identity predicate
  // fails (it names another principal, or null) is refused at any point too; a 2xx that did not finish, one whose identity
  // predicate is inconclusive, or a 2xx naming the actor is not. A surface probe still needs a refusal status.
  const failing = { ...pass, outcome: 'fail', predicates: [{ kind: 'json.equals', outcome: 'fail', identity: true }] };
  const idOther = failing, idNull = { ...failing }, idStalled = { ...pass, transportOutcome: 'timeout', outcome: 'error', predicates: [{ kind: 'json.equals', outcome: 'inconclusive', identity: true }] };
  const idUnsure = { ...pass, outcome: 'inconclusive', predicates: [{ kind: 'json.equals', outcome: 'inconclusive', identity: true }] }, surface200Fail = { ...surfacePass, outcome: 'fail', predicates: [{ kind: 'json.equals', outcome: 'fail', identity: true }] };
  assert.deepEqual([identityRefusedAnywhere(entryOf([pass, surfacePass], [{ afterCheckId: 'OWN', probes: [idOther, surfacePass] }], [pass, surfacePass])), identityRefusedAnywhere(entryOf([idNull, surfacePass], [], [pass, surfacePass])),
    identityRefusedAnywhere(entryOf([pass, surfacePass], [], [idOther, surfacePass])), identityRefusedAnywhere(entryOf([pass, surfacePass], [{ afterCheckId: 'OWN', probes: [idStalled, surfacePass] }], [pass, surfacePass])),
    identityRefusedAnywhere(entryOf([pass, surfacePass], [{ afterCheckId: 'OWN', probes: [idUnsure, surfacePass] }], [pass, surfacePass])), identityRefusedAnywhere(entryOf([pass, surface200Fail], [], [pass, surfacePass]))], [true, true, true, false, false, false]);
  const inner200 = entryOf([pass, surfacePass], [{ afterCheckId: 'OWN', probes: [idOther, surfacePass] }, { afterCheckId: 'F1', probes: [pass, surfacePass] }], [pass, surfacePass]);
  const judge200 = (required, control, points) => rowIdentityReason({ credentialed: true, required, control, entry: inner200, httpStatus: control ? 200 : 403, controlFailed: false, rules: 5, route: 'established', points });
  assert.deepEqual([judge200(false, false, coveringPoints(inner200, bracketed, 'F2')), judge200(true, true, null), judge200(true, true, coveringPoints(inner200, bracketed, 'OWN'))], ['bracket-not-passed', 'bracket-not-passed', 'bracket-not-passed'], 'a 2xx naming another principal at an inner point withholds every row');
});
// actor-identity/6: route segments, controlScope and restsOn are /6 fields, so a relabel to an earlier rule set drops them from every row and reseals it.
const dropRouteSegments = run => {
  for (const r of run.results) {
    if (r.trace?.[0]?.type !== 'http-observation') continue;
    delete r.trace[0].data.routeSegments; delete r.trace[0].data.controlScope; delete r.trace[0].data.restsOn;
    r.evidenceDigest = digest(r.trace.length === 2 ? { evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions } : { evidence: r.trace[0].data, assertions: r.assertions });
  }
  return run;
};
const recountRun = run => { run.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const r of run.results) run.counts[r.status]++; };

test('the identity rule set is part of the comparison signature, so a run relabelled from one schema to another never compares', async () => {
  const p = profile(), current = await assess(p, { surface: 'ok' }), leaky = await assess(p, { surface: 'ok', denial: 200 });
  assert.deepEqual([row(leaky, 'FOREIGN').status, row(current, 'FOREIGN').status], ['fail', 'pass']);
  assert.equal(compareRuns(leaky, current).compatible, true);
  // The schema label alone changed: incompatible, whatever else the record says.
  const relabelled = structuredClone(current); relabelled.identityEvidence.schema = 'actor-identity/4';
  const laundered = compareRuns(leaky, relabelled);
  assert.equal(laundered.compatible, false); assert.ok(laundered.reasons.includes('Actors, login modes or identity controls differ between the runs.'));
  assert.deepEqual([laundered.summary.fixed, laundered.rows.find(r => r.id === 'FOREIGN').transition, laundered.restorationLabel], [0, 'incompatible', 'Unverified changes']);
  // Laundering by relabel, under these rules: a consistent relabel to the earlier schema (its fields dropped and the
  // 403 row resealed as a pass) validates alone, but can never be labelled restored against a baseline under the current rules.
  const bare = await assess(profile({ surface: false }), { denial: 403 });
  assert.equal(row(bare, 'FOREIGN').status, 'inconclusive');
  const old = structuredClone(bare), r = row(old, 'FOREIGN');
  old.identityEvidence.schema = 'actor-identity/3'; delete member(old).surfaceControlIds; delete member(old).refusesWith401; delete member(old).between; delete old.principals;
  for (const x of old.results) delete x.decision;
  dropRouteSegments(old); // actor-identity/6 fields go with the relabel
  r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); recountRun(old);
  validateHttpRunEvidence(old);
  const leakyBare = await assess(profile({ surface: false }), { denial: 200 });
  assert.deepEqual([compareRuns(leakyBare, old).compatible, compareRuns(leakyBare, old).summary.fixed], [false, 0]);
  assert.equal(summarizeGate({ candidate: old, baseline: leakyBare }).exitCode, 1);
});

// ---------------------------------------------------------------------------
// Point ranking and route-level refusals. Injected transport only.
// The two points covering a check are ranked together with the actor-level precedence, not by position, so a login-level
// failure at the later point (an identity probe that did not pass, or did not finish) is never hidden behind a surface probe
// that failed for another reason (a 500, surface-not-passed, login proven) at the earlier point.
test('a required control covered by a surface 500 and then a login-level failure is withheld, never a pass', async () => {
  // OWN is covered by p0 (its surface probe, /own call 1, answers 500) and p1 (its identity probe, /me call 3, answers 500 or does
  // not finish). Neither is a refusal: a refused identity probe withholds every row (the identity-refusal rule), which would hide the ranking.
  for (const [why, me, reason] of [['identity probe failed (500)', 500, 'bracket-not-passed'], ['identity probe unfinished', 'error', 'identity-probe-incomplete']]) {
    const run = await pointAssess({ own: { 1: 500 }, me: { 3: me } });
    assert.deepEqual([member(run).reason, member(run).loginProven], [reason, false], why);
    // OWN rests on p0 and p1: their more severe reason is its own; F1 (p1 and p2) is the third state; F2 and F3 rest on passing points.
    assert.deepEqual(run.results.map(r => [r.id, r.status, r.decision]), [['WHOAMI', 'pass', 'pass'], ['OWN', 'inconclusive', 'inconclusive'], ['F1', 'inconclusive', IDENTITY_UNPROVEN_DECISION], ['F2', 'pass', 'pass'], ['F3', 'pass', 'pass']], why);
    assert.deepEqual([identityOf(row(run, 'OWN')), identityOf(row(run, 'F1'))], [IDENTITY_REASONS[reason], IDENTITY_REASONS[reason]], why);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(pointProfile()) });
    // The validator recomputes it: OWN restored to a pass is refused.
    const forged = structuredClone(run), r = row(forged, 'OWN');
    r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.decision = 'pass'; r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); recountRun(forged);
    assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence', why);
    // A comparison does not count it as a passing control.
    assert.equal(compareRuns(await pointAssess({ denials: { '/foreign/2': 200 } }), run).controlsPass, false, why);
  }
  // The same surface 500 with the later point passing leaves the login proven for OWN: it keeps its pass (surface-not-passed).
  const proven = await pointAssess({ own: { 1: 500 } });
  assert.deepEqual([member(proven).reason, row(proven, 'OWN').status, identityOf(row(proven, 'OWN'))], ['surface-not-passed', 'pass', undefined]);
});

test('a failing baseline row covered by a surface 500 and then a login-level failure is unverified, so compare credits no restored contract', async () => {
  // [WHOAMI, OWN, F1]: F1 is covered by p1 (its surface probe, /own call 3, answers 500) and the closing point (its identity probe,
  // /me call 4, answers 500: not a refusal, so the failure stays point-level and only the ranking decides F1).
  const short = () => ({ ...pointProfile(), checks: pointProfile().checks.slice(0, 3) });
  const shortAssess = state => runHttpAssessment(short(), { env, transport: pointApp(state) });
  const baseline = await shortAssess({ own: { 3: 500 }, me: { 4: 500 }, denials: { '/foreign/1': 200 } }), clean = await shortAssess({});
  assert.deepEqual([row(baseline, 'F1').status, identityOf(row(baseline, 'F1')), member(baseline).reason], ['fail', IDENTITY_REASONS['bracket-not-passed'], 'bracket-not-passed']);
  assert.deepEqual(clean.results.map(r => r.status), ['pass', 'pass', 'pass']);
  const comparison = compareRuns(baseline, clean);
  assert.deepEqual([comparison.compatible, comparison.controlsPass, comparison.rows.find(r => r.id === 'F1').transition, comparison.summary.fixed, comparison.restorationLabel], [true, true, 'unverified', 0, 'No verified repair']);
  const gate = summarizeGate({ candidate: clean, baseline });
  assert.deepEqual([gate.exitCode, gate.reasons.includes('baseline-identity-not-established'), gate.reasons.includes('comparison-incomplete')], [1, true, true]);
  // With the later point passing, the baseline row's login was proven for it (surface-not-passed), so the repair still verifies.
  const notEstablished = await shortAssess({ own: { 3: 500 }, denials: { '/foreign/1': 200 } });
  assert.deepEqual([identityOf(row(notEstablished, 'F1')), compareRuns(notEstablished, clean).rows.find(r => r.id === 'F1').transition], [IDENTITY_REASONS['surface-not-passed'], 'contract-restored']);
});

test('the creator of a captured value is judged on both points covering the capturing check, so a dependent row never passes on a hidden login failure', async () => {
  const envAB = { SCOPEHAVEN_TARGET_ALICE: 'tok-alice', SCOPEHAVEN_TARGET_BOB: 'tok-bob' };
  const as = (c, actorId) => ({ ...c, actorId });
  const creator = () => ({ id: 'creator-points', name: 'Creator points', applicationId: 'creator-points', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { alice: { principalId: 'alice', credentialEnv: 'SCOPEHAVEN_TARGET_ALICE', identityValue: 'alice' }, bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } },
    requiredControlIds: ['ALICE-ME', 'ALICE-OWN', 'ALICE-CREATE', 'BOB-ME', 'BOB-OWN'],
    checks: [as(control('ALICE-ME', '/me', [{ kind: 'json.equals', pointer: '/user', expected: 'alice' }]), 'alice'), as(control('ALICE-OWN', '/own'), 'alice'),
      { id: 'ALICE-CREATE', title: 'Alice creates a note', category: 'Setup', severity: 'control', actorId: 'alice', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], capture: { note: { pointer: '/id', type: 'id' } } },
      as(control('BOB-ME', '/me', [{ kind: 'json.equals', pointer: '/user', expected: 'bob' }]), 'bob'), as(control('BOB-OWN', '/own'), 'bob'),
      { id: 'BOB-USE', title: 'Bob cannot delete alice\'s note', category: 'Object access', severity: 'high', actorId: 'bob', method: 'DELETE', path: '/notes/{{note}}', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], precondition: [{ name: 'note', type: 'id', createdBy: 'alice' }] }] });
  // Alice's /own calls: p0 (1), ALICE-OWN (2), p1 (3), the closing point (4); her /me calls: ALICE-ME (1), p0 (2), p1 (3), the closing point (4).
  // ALICE-CREATE is covered by p1 (surface 500) and the closing point (identity 500: not a refusal, so it stays point-level).
  const app = state => {
    const calls = { me: 0, own: 0 };
    return async (origin, check, { credential }) => {
      const who = { 'tok-alice': 'alice', 'tok-bob': 'bob' }[credential], reply = (status, json = {}) => ({ status, complete: true, jsonParsed: true, json, bytes: 2 });
      if (check.path === '/me') { if (!who) return reply(401); const status = who === 'alice' ? state.aliceMe?.[++calls.me] : undefined; return status === undefined ? reply(200, { user: who }) : reply(status); }
      if (!who) return reply(401);
      if (check.path === '/own') { const status = who === 'alice' ? state.aliceOwn?.[++calls.own] : undefined; return status === undefined ? reply(200, { items: [] }) : reply(status); }
      return check.method === 'POST' ? reply(201, { id: 'n-1' }) : reply(403);
    };
  };
  const run = await runHttpAssessment(creator(), { env: envAB, transport: app({ aliceOwn: { 3: 500 }, aliceMe: { 4: 500 } }) });
  const alice = run.identityEvidence.actors.find(a => a.actorId === 'alice');
  assert.deepEqual([alice.reason, alice.loginProven, row(run, 'ALICE-CREATE').status, identityOf(row(run, 'ALICE-CREATE'))], ['bracket-not-passed', false, 'inconclusive', IDENTITY_REASONS['bracket-not-passed']]);
  assert.equal(run.identityEvidence.actors.find(a => a.actorId === 'bob').reason, 'established');
  const use = row(run, 'BOB-USE');
  assert.deepEqual([use.trace[0].data.httpStatus, use.status, use.decision, use.assertions.find(a => a.name === PRECONDITION_ASSERTION)?.actual, identityOf(use)], [403, 'inconclusive', 'inconclusive', PRECONDITION_REASONS['creator-login-unproven'], undefined]);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [creator()], env: envAB }).exportSuite('creator-points') });
  // With alice's closing point passing, her login was proven for the capturing check: the dependent row passes.
  const proven = await runHttpAssessment(creator(), { env: envAB, transport: app({ aliceOwn: { 3: 500 } }) });
  assert.deepEqual([proven.identityEvidence.actors.find(a => a.actorId === 'alice').reason, row(proven, 'ALICE-CREATE').status, row(proven, 'BOB-USE').status], ['surface-not-passed', 'pass', 'pass']);
});

// The mirrored orientation: the login-level failure at the EARLIER covering point and the surface 500
// at the later one. A merge that read the later point first (pointReason(points[1]) ?? pointReason(points[0])) would return the
// later point's surface-not-passed (login proven) and give the required control back its pass.
test('the mirrored order: a required control covered by a login-level failure and then a surface 500 is withheld, never a pass', async () => {
  // OWN is covered by p0 (its identity probe, /me call 2, answers 500 or does not finish: not a refusal) and p1 (its surface probe,
  // /own call 3, answers 500).
  for (const [why, me, reason] of [['identity probe failed (500)', 500, 'bracket-not-passed'], ['identity probe unfinished', 'error', 'identity-probe-incomplete']]) {
    const run = await pointAssess({ me: { 2: me }, own: { 3: 500 } });
    assert.deepEqual([member(run).reason, member(run).loginProven], [reason, false], why);
    // OWN carries p0's more severe reason; F1 (p1 and p2) carries p1's surface-not-passed (the third state); F2 and F3 rest on
    // passing points, and the identity control on the route proof.
    assert.deepEqual(run.results.map(r => [r.id, r.status, r.decision]), [['WHOAMI', 'pass', 'pass'], ['OWN', 'inconclusive', 'inconclusive'], ['F1', 'inconclusive', IDENTITY_UNPROVEN_DECISION], ['F2', 'pass', 'pass'], ['F3', 'pass', 'pass']], why);
    assert.deepEqual([identityOf(row(run, 'OWN')), identityOf(row(run, 'F1'))], [IDENTITY_REASONS[reason], IDENTITY_REASONS['surface-not-passed']], why);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(pointProfile()) });
    // The validator recomputes it: OWN restored to a pass is refused.
    const forged = structuredClone(run), r = row(forged, 'OWN');
    r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.decision = 'pass'; r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); recountRun(forged);
    assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence', why);
    // A comparison does not count it as a passing control.
    assert.equal(compareRuns(await pointAssess({ denials: { '/foreign/2': 200 } }), run).controlsPass, false, why);
  }
});

// The surface-refusal rule (route-level surface-refused): a credential that flaps (an intermittent session store, a rate
// limiter) can be refused for a check between two accepting points. A refused surface probe at any point withholds every row of
// the actor, required and identity controls included, and the refusal is read from the probes, not from the actor-level reason.
test('surface refusal: a surface probe refused at one point withholds every row of the actor, a check accepted on both sides of it included', async () => {
  // The surface probe of p1 (after OWN, /own call 3) refused; p2 and p3, around F2, accepted.
  const run = await pointAssess({ own: { 3: 403 } });
  assert.deepEqual(member(run).between.map(b => b.probes.map(p => p.httpStatus)), [[200, 403], [200, 200], [200, 200]]);
  assert.deepEqual(run.results.map(r => [r.id, r.status, r.decision, identityOf(r)]), [['WHOAMI', 'inconclusive', 'inconclusive', IDENTITY_REASONS['surface-refused']], ['OWN', 'inconclusive', 'inconclusive', IDENTITY_REASONS['surface-refused']],
    ...['F1', 'F2', 'F3'].map(id => [id, 'inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS['surface-refused']])]);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(pointProfile()) });
  assert.ok(summarizeGate({ candidate: run }).reasons.includes('required-controls-not-passed'));
  // F2 restored to a pass is refused: the validator reads the refusal from the stored probes.
  const forged = structuredClone(run), r = row(forged, 'F2');
  r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.decision = 'pass'; r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); recountRun(forged);
  assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence');
  // An identity probe that did not pass at another point for a reason other than a refusal (a 500) outranks surface-refused in the
  // actor-level reason (bracket-not-passed); the surface refusal still withholds every row, the identity control included, because it
  // is read from the probes, not from that reason.
  const otherwise = await pointAssess({ own: { 3: 403 }, me: { 5: 500 } });
  assert.equal(member(otherwise).reason, 'bracket-not-passed');
  assert.deepEqual(otherwise.results.map(r => [r.id, r.status, identityOf(r)]), run.results.map(r => [r.id, 'inconclusive', IDENTITY_REASONS['surface-refused']]));
  validateHttpRunEvidence(otherwise);
  // An identity probe refused as well (the identity-refusal rule): both refusals are route-level, and every row reads bracket-not-passed, the
  // reason identityReason ranks first.
  const both = await pointAssess({ own: { 3: 403 }, me: { 5: 401 } });
  assert.equal(member(both).reason, 'bracket-not-passed');
  assert.deepEqual(both.results.map(r => [r.id, r.status, identityOf(r)]), run.results.map(r => [r.id, 'inconclusive', IDENTITY_REASONS['bracket-not-passed']]));
  validateHttpRunEvidence(both);
  // A surface probe that fails otherwise (a 500) stays point-level: only the checks that point covers are withheld.
  const broken = await pointAssess({ own: { 3: 500 } });
  assert.deepEqual(broken.results.map(r => r.status), ['pass', 'pass', 'inconclusive', 'pass', 'pass']);
});

// The identity-refusal rule: an identity probe that answered a refusal status with the actor's own credential, at any
// probe point, is the same direct evidence of a refusal as a refused surface probe. It withholds every row of the actor, route-level,
// with the reason bracket-not-passed. An identity probe that did not pass for another reason (a 500, an unfinished probe) stays
// point-level. The rule is in rowIdentityReason, which the connector and the validator share.
test('identity refusal: an identity probe refused at one point withholds every row of the actor, a check accepted on both sides of it included; a 500 stays point-level', async () => {
  const leaky = await pointAssess({ denials: { '/foreign/2': 200 } });
  // The identity route flaps: the identity probe of p1 (after OWN, /me call 3) is refused, while every surface probe accepts and
  // p2 and p3, the two points around F2, pass in full.
  for (const status of [401, 403]) {
    const why = `identity probe ${status}`, run = await pointAssess({ me: { 3: status } });
    assert.deepEqual(member(run).between.map(b => b.probes.map(p => p.httpStatus)), [[status, 200], [200, 200], [200, 200]], why);
    assert.deepEqual([member(run).reason, member(run).loginProven], ['bracket-not-passed', false], why);
    assert.deepEqual(run.results.map(r => [r.id, r.status, r.decision, identityOf(r)]), [['WHOAMI', 'inconclusive', 'inconclusive', IDENTITY_REASONS['bracket-not-passed']], ['OWN', 'inconclusive', 'inconclusive', IDENTITY_REASONS['bracket-not-passed']],
      ...['F1', 'F2', 'F3'].map(id => [id, 'inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS['bracket-not-passed']])], why);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(pointProfile()) });
    const gate = summarizeGate({ candidate: run });
    assert.deepEqual([gate.exitCode, gate.reasons.includes('required-controls-not-passed'), gate.reasons.includes('identity-not-established')], [1, true, true], why);
    // No repair is credited on F2, although its own two points passed.
    const comparison = compareRuns(leaky, run);
    assert.deepEqual([comparison.rows.find(r => r.id === 'F2').transition, comparison.summary.fixed], ['unverified', 0], why);
    // The validator recomputes it from the stored probes: F2, or the identity control, restored to a pass and resealed is refused.
    for (const id of ['F2', 'WHOAMI']) {
      const forged = structuredClone(run), r = row(forged, id);
      r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.decision = 'pass'; r.summary = 'Configured response predicates passed.';
      r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); recountRun(forged);
      assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence', `${why}: ${id}`);
      assert.throws(() => validateHttpRunEvidence(forged, { expectedSuite: suiteOf(pointProfile()) }), e => e.code === 'invalid-run-evidence', `${why}: ${id}, with the suite`);
    }
  }
  // A refusal at the opening point (p0, /me call 2) or at the closing point (p4, /me call 6) withholds every row as well.
  for (const me of [{ 2: 401 }, { 6: 401 }]) {
    const run = await pointAssess({ me }), rows = run.results.map(r => [r.status, identityOf(r)]);
    assert.deepEqual(rows, rows.map(() => ['inconclusive', IDENTITY_REASONS['bracket-not-passed']]), JSON.stringify(me));
    validateHttpRunEvidence(run);
  }
  // The same identity probe answering 500 (it did not pass, and it is not a refusal) stays point-level: only OWN (p0 and p1) and
  // F1 (p1 and p2) are withheld. F2 keeps its pass: a comparison blocks its repair label only on the withheld control.
  const broken = await pointAssess({ me: { 3: 500 } });
  assert.deepEqual([member(broken).reason, broken.results.map(r => [r.id, r.status, r.decision])], ['bracket-not-passed', [['WHOAMI', 'pass', 'pass'], ['OWN', 'inconclusive', 'inconclusive'], ['F1', 'inconclusive', IDENTITY_UNPROVEN_DECISION], ['F2', 'pass', 'pass'], ['F3', 'pass', 'pass']]]);
  validateHttpRunEvidence(broken, { expectedSuite: suiteOf(pointProfile()) });
  assert.equal(compareRuns(leaky, broken).rows.find(r => r.id === 'F2').transition, 'blocked-by-controls');
  // An unfinished identity probe stays point-level too.
  const unfinished = await pointAssess({ me: { 3: 'error' } });
  assert.deepEqual([member(unfinished).reason, unfinished.results.map(r => r.status)], ['identity-probe-incomplete', ['pass', 'inconclusive', 'inconclusive', 'pass', 'pass']]);
  validateHttpRunEvidence(unfinished);
});

// The other-principal rule: an identity probe at a probe point is refused as identityRefused judges it, so a
// complete 2xx JSON response that names another principal, or null (the Auth.js signed-out shape), is the same direct evidence
// of a refusal as a 401 and withholds every row of the actor route-wide as bracket-not-passed, compare credit and the creator of
// a captured value included. The connector and the validator share rowIdentityReason.
test('other principal: an identity probe answering a complete 2xx that names another principal or null at an inner point withholds every row of the actor', async () => {
  const leaky = await pointAssess({ denials: { '/foreign/2': 200 } });
  // The identity probe of p2 (after F1, /me call 4) answers 200 naming mallory, or 200 null; every surface probe accepts, and
  // p3 and p4, the two points around F3, pass in full, as p1 and p2's surface probes do.
  for (const [why, me4] of [['200 naming another principal', { status: 200, json: { user: 'mallory' } }], ['200 null', { status: 200, json: null }]]) {
    const run = await pointAssess({ me: { 4: me4 } }), m = member(run);
    assert.deepEqual(m.between.map(b => b.probes.map(p => [p.httpStatus, p.outcome])), [[[200, 'pass'], [200, 'pass']], [[200, 'fail'], [200, 'pass']], [[200, 'pass'], [200, 'pass']]], why);
    assert.equal(m.between[1].probes[0].predicates.find(p => p.identity).outcome, 'fail', why);
    assert.deepEqual([m.reason, m.loginProven], ['bracket-not-passed', false], why);
    assert.deepEqual(run.results.map(r => [r.id, r.status, r.decision, identityOf(r)]), [['WHOAMI', 'inconclusive', 'inconclusive', IDENTITY_REASONS['bracket-not-passed']], ['OWN', 'inconclusive', 'inconclusive', IDENTITY_REASONS['bracket-not-passed']],
      ...['F1', 'F2', 'F3'].map(id => [id, 'inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS['bracket-not-passed']])], why);
    validateHttpRunEvidence(run); validateHttpRunEvidence(run, { expectedSuite: suiteOf(pointProfile()) });
    const gate = summarizeGate({ candidate: run });
    assert.deepEqual([gate.exitCode, gate.reasons.includes('required-controls-not-passed'), gate.reasons.includes('identity-not-established')], [1, true, true], why);
    // No repair is credited on F2 (covered by p2, the refused point) or on F3, whose own two points passed in full.
    const comparison = compareRuns(leaky, run);
    assert.deepEqual([comparison.rows.find(r => r.id === 'F2').transition, comparison.summary.fixed], ['unverified', 0], why);
    // Forged back to a pass and resealed, with and without the suite: refused, on a check whose own points accepted and on the
    // identity control.
    for (const id of ['F3', 'WHOAMI', 'OWN']) {
      const forged = structuredClone(run), r = row(forged, id);
      r.assertions = r.assertions.filter(a => a.name !== IDENTITY_ASSERTION); r.status = 'pass'; r.decision = 'pass'; r.summary = 'Configured response predicates passed.';
      r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); recountRun(forged);
      assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence', `${why}: ${id}`);
      assert.throws(() => validateHttpRunEvidence(forged, { expectedSuite: suiteOf(pointProfile()) }), e => e.code === 'invalid-run-evidence', `${why}: ${id}, with the suite`);
    }
  }
  // A leak on F3 in the baseline: against a candidate whose p2 answered 200 null, F3 (own points accepted) is unverified, not restored.
  const leakyF3 = await pointAssess({ denials: { '/foreign/3': 200 } }), nullAtP2 = await pointAssess({ me: { 4: { status: 200, json: null } } });
  assert.deepEqual([compareRuns(leakyF3, nullAtP2).rows.find(r => r.id === 'F3').transition, compareRuns(leakyF3, nullAtP2).summary.fixed], ['unverified', 0]);
  // The same point answering a 2xx that names the member is a plain pass: nothing is withheld.
  const named = await pointAssess({ me: { 4: { status: 200, json: { user: 'member' } } } });
  assert.deepEqual(named.results.map(r => r.status), ['pass', 'pass', 'pass', 'pass', 'pass']);
});

// The other-principal rule and the creator of a captured value: alice's identity probe at her opening point (which does not cover the capturing
// check) answers 200 naming mallory, or 200 null; the capture is not attributed, so bob's dependent row is plainly inconclusive.
test('other principal (creator): a 2xx identity answer for another principal or none at a point that does not cover the capturing check still leaves the creator unproven', async () => {
  const envAB = { SCOPEHAVEN_TARGET_ALICE: 'tok-alice', SCOPEHAVEN_TARGET_BOB: 'tok-bob' };
  const as = (c, actorId) => ({ ...c, actorId });
  const creator = () => ({ id: 'creator-3b', name: 'Creator 3b', applicationId: 'creator-3b', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { alice: { principalId: 'alice', credentialEnv: 'SCOPEHAVEN_TARGET_ALICE', identityValue: 'alice' }, bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } },
    requiredControlIds: ['ALICE-ME', 'ALICE-OWN', 'ALICE-CREATE', 'BOB-ME', 'BOB-OWN'],
    checks: [as(control('ALICE-ME', '/me', [{ kind: 'json.equals', pointer: '/user', expected: 'alice' }]), 'alice'), as(control('ALICE-OWN', '/own'), 'alice'),
      { id: 'ALICE-CREATE', title: 'Alice creates a note', category: 'Setup', severity: 'control', actorId: 'alice', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], capture: { note: { pointer: '/id', type: 'id' } } },
      as(control('BOB-ME', '/me', [{ kind: 'json.equals', pointer: '/user', expected: 'bob' }]), 'bob'), as(control('BOB-OWN', '/own'), 'bob'),
      { id: 'BOB-USE', title: 'Bob cannot delete alice\'s note', category: 'Object access', severity: 'high', actorId: 'bob', method: 'DELETE', path: '/notes/{{note}}', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], precondition: [{ name: 'note', type: 'id', createdBy: 'alice' }] }] });
  // ALICE-ME with alice's credential, in order: the control row (1), her opening point p0 (2), p1 (3), the closing point (4).
  // ALICE-CREATE is covered by p1 and the closing point; p0 covers only ALICE-OWN.
  const app = aliceMe => {
    let n = 0;
    return async (origin, check, { credential }) => {
      const who = { 'tok-alice': 'alice', 'tok-bob': 'bob' }[credential], reply = (status, json = {}) => ({ status, complete: true, jsonParsed: true, json, bytes: 2 });
      if (check.path === '/me') { if (!who) return reply(401); if (check.id === 'ALICE-ME' && who === 'alice' && ++n === 2 && aliceMe) return reply(200, aliceMe.json); return reply(200, { user: who }); }
      if (!who) return reply(401);
      return check.path === '/own' ? reply(200, { items: [] }) : check.method === 'POST' ? reply(201, { id: 'n-1' }) : reply(403);
    };
  };
  const suite = createRegistry({ profiles: [creator()], env: envAB }).exportSuite('creator-3b');
  const clean = await runHttpAssessment(creator(), { env: envAB, transport: app(null) });
  assert.deepEqual([row(clean, 'ALICE-CREATE').status, row(clean, 'BOB-USE').status], ['pass', 'pass']);
  for (const [why, json] of [['200 naming another principal', { user: 'mallory' }], ['200 null', null]]) {
    const run = await runHttpAssessment(creator(), { env: envAB, transport: app({ json }) });
    const alice = run.identityEvidence.actors.find(a => a.actorId === 'alice');
    assert.deepEqual([alice.reason, alice.before[0].httpStatus, row(run, 'ALICE-CREATE').status, identityOf(row(run, 'ALICE-CREATE'))], ['bracket-not-passed', 200, 'inconclusive', IDENTITY_REASONS['bracket-not-passed']], why);
    const use = row(run, 'BOB-USE');
    assert.deepEqual([use.status, use.decision, use.assertions.find(a => a.name === PRECONDITION_ASSERTION)?.actual], ['inconclusive', 'inconclusive', PRECONDITION_REASONS['creator-login-unproven']], why);
    validateHttpRunEvidence(run, { expectedSuite: suite });
    // Bob's row restored to a pass (precondition dropped, resealed) is refused: the creator is recomputed from alice's probes.
    const forged = structuredClone(run), r = row(forged, 'BOB-USE');
    r.assertions = r.assertions.filter(a => a.name !== PRECONDITION_ASSERTION); r.status = 'pass'; r.decision = 'pass'; r.summary = 'Configured response predicates passed.';
    r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); recountRun(forged);
    assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence', `${why}: BOB-USE`);
    assert.throws(() => validateHttpRunEvidence(forged, { expectedSuite: suite }), e => e.code === 'invalid-run-evidence', `${why}: BOB-USE, with the suite`);
  }
});

test('a not-applicable row carries no decision, under every rule set, so none is exported as if it had been decided', async () => {
  const p = pointProfile(); p.checks.push({ ...boundary('F9', '/foreign/9'), applicability: { applies: false, reason: 'Not offered by this build.' } });
  const run = await runHttpAssessment(p, { env, transport: pointApp({}) }), na = row(run, 'F9');
  assert.deepEqual([na.status, Object.hasOwn(na, 'decision')], ['not_applicable', false]);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  const decided = structuredClone(run); row(decided, 'F9').decision = 'pass';
  assert.throws(() => validateHttpRunEvidence(decided), e => e.code === 'invalid-run-evidence');
  assert.throws(() => validateHttpRunEvidence(decided, { expectedSuite: suiteOf(p) }), e => e.code === 'invalid-run-evidence');
  // The same edit on a run relabelled to the earlier rules (no per-row decisions at all) is refused too.
  const older = structuredClone(run); older.identityEvidence.schema = 'actor-identity/4'; delete member(older).between; delete older.principals;
  for (const x of older.results) delete x.decision;
  dropRouteSegments(older); // actor-identity/6 fields go with the relabel
  validateHttpRunEvidence(older);
  row(older, 'F9').decision = 'pass';
  assert.throws(() => validateHttpRunEvidence(older), e => e.code === 'invalid-run-evidence');
});

test('the third state names identity or allowed use not established, which also covers a proven login whose allowed use failed', async () => {
  assert.match(IDENTITY_UNPROVEN_SUMMARY, /identity or allowed use not established/);
  assert.doesNotMatch(IDENTITY_UNPROVEN_SUMMARY, /login was not proven/);
  // The OWN control itself (/own call 2) answers 500: the login is proven, a required allowed-use control failed, and each boundary
  // row that observed its refusal is the third state with that reason (no verdict changes: status inconclusive, never a pass).
  const run = await pointAssess({ own: { 2: 500 } });
  assert.deepEqual([member(run).reason, member(run).loginProven, row(run, 'OWN').status], ['control-not-passed', true, 'fail']);
  for (const id of ['F1', 'F2', 'F3']) assert.deepEqual([row(run, id).status, row(run, id).decision, identityOf(row(run, id)), row(run, id).summary], ['inconclusive', IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS['control-not-passed'], withheldSummary('control-not-passed', ['OWN'], true)], id);
  // actor-identity/6: the summary keeps the third state's sentence, names the reason and the control that did not pass.
  assert.match(row(run, 'F1').summary, /^Prohibition observed, identity or allowed use not established: .* Reason: A required control for this actor did not pass \(OWN\)\.$/);
  validateHttpRunEvidence(run);
});
