// The operator-forwarded mode through a forwarder that can be misconfigured.
// A loopback notes app stands in for staging; a loopback forwarder in front of it plays the
// operator's proxy, in four modes applied to every request (clean, cookie-rewrite,
// strip-authorization, redirect-signin) and two that answer requests themselves
// (deny-admin on one route, deny-all): the limits those expose, and their mitigations.
// One bearer actor, one cookie actor, one anonymous actor. No network beyond 127.0.0.1, no model,
// provider or customer system. The live run against a TLS staging copy of the Open WebUI practice
// app is recorded in README.md; this file pins the same behaviour without Docker.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';
import { compareRuns } from '../../src/runner.mjs';
import { renderReport, comparisonDocument, renderComparisonReport } from '../../src/report.mjs';
import { renderSarif } from '../../src/sarif.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { summarizeGate } from '../regression-gate/gate.mjs';
import { unpairedForwardedPasses, forwardedPairingGaps } from '../../src/forwarded-pairing.mjs';

const TOKENS = { 'tok-member': 'member-1', 'tok-owner': 'owner-1', 'tok-admin': 'admin-1' };
const env = { SCOPEHAVEN_TARGET_FWD_MEMBER: 'tok-member', SCOPEHAVEN_TARGET_FWD_OWNER: 'tok-owner', SCOPEHAVEN_TARGET_FWD_ADMIN: 'tok-admin' };
const LABEL = 'Notes staging (forwarded)', PREFIX = `operator-forwarded target: ${LABEL}.`;
const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const closing = (t, server) => t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));

// The app. secure: members read their own notes, the owner reads the owner note, nobody reads
// the admin settings except the administrator. do-nothing refuses every read (the login still works);
// dump-everything answers every read; owner-admin lets the owner read the admin settings too (a
// vulnerable build for OWNER-ADMIN). The member and the administrator authenticate with a bearer
// token, the owner with a cookie.
async function notesApp(t, mode = 'secure') {
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization ?? '')?.[1];
    const cookie = /(?:^|;\s*)session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
    const user = TOKENS[bearer] ?? TOKENS[cookie] ?? null;
    if (req.url === '/public') return mode === 'do-nothing' ? json(res, 403, {}) : json(res, 200, { page: 'public' });
    if (req.url === '/me') return user ? json(res, 200, { user }) : json(res, 401, {});
    if (!user) return json(res, 401, {});
    if (mode === 'do-nothing') return json(res, 403, {});
    if (mode === 'dump-everything') return json(res, 200, { note: 'everything' });
    if (req.url === '/notes/own') return json(res, 200, { notes: [] });
    if (req.url === '/notes/owner-secret') return user === 'owner-1' ? json(res, 200, { note: 'owner' }) : json(res, 403, {});
    if (req.url === '/admin/settings') return user === 'admin-1' || (mode === 'owner-admin' && user === 'owner-1') ? json(res, 200, { settings: {} }) : json(res, 403, {});
    return json(res, 403, {});
  }); });
  const port = await listen(server); closing(t, server);
  return port;
}
// The operator's forwarder, in one of four modes (as the live practice forwarder). A function mode is read per request,
// so one forwarder (one origin, one profile) can change its rules between a baseline and a candidate run.
async function forwarder(t, upstreamPort, modeOf) {
  const server = createServer((req, res) => {
    const mode = typeof modeOf === 'function' ? modeOf() : modeOf;
    if (mode === 'redirect-signin') { req.resume(); res.writeHead(302, { Location: '/sign-in', Connection: 'close' }); res.end(); return; }
    // The forwarder answers itself: a deny rule on one route, or an auth gate in front of everything.
    if ((mode === 'deny-admin' && req.url.startsWith('/admin/')) || mode === 'deny-all') { req.resume(); json(res, mode === 'deny-all' ? 401 : 403, { error: 'forwarder' }); return; }
    const headers = { ...req.headers, host: `staging.example.test:${upstreamPort}` };
    if (mode === 'strip-authorization') delete headers.authorization;
    if (mode === 'cookie-rewrite' && headers.cookie) headers.cookie = headers.cookie.split(/;\s*/).map(c => `rewritten_${c}`).join('; ');
    const upstream = request({ host: '127.0.0.1', port: upstreamPort, method: req.method, path: req.url, headers }, up => { res.writeHead(up.statusCode, up.headers); up.pipe(res); });
    upstream.on('error', () => { if (!res.headersSent) { res.writeHead(502); res.end(); } });
    req.pipe(upstream);
  });
  const port = await listen(server); closing(t, server);
  return `http://127.0.0.1:${port}`;
}
// adminControl: an administrator with a required positive control on the admin route (the mitigation
// for a route-scoped forwarder rule); anonymousControl: the signed-out actor's required public-page control.
const profile = (origin, { forwarded = true, adminControl = false, anonymousControl = true } = {}) => withOptions({ id: 'notes-staging', name: 'Notes staging', applicationId: 'notes-app', origin, buildLabel: 'b1', contextId: 'notes-staging',
  ...(forwarded ? { targetContext: 'operator-forwarded', targetLabel: LABEL } : {}),
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_FWD_MEMBER', identityValue: 'member-1' },
    owner: { principalId: 'owner-1', credentialEnv: 'SCOPEHAVEN_TARGET_FWD_OWNER', credentialCookie: 'session', identityValue: 'owner-1' }, anonymous: { principalId: 'anonymous' } },
  requiredControlIds: ['WHOAMI-MEMBER', 'WHOAMI-OWNER', 'OWN-NOTES', 'OWNER-NOTE', 'ANON-PUBLIC'], observers: [],
  checks: [
    { id: 'ANON-PUBLIC', title: 'Anyone reads the public page', category: 'public', severity: 'control', actorId: 'anonymous', method: 'GET', path: '/public', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'WHOAMI-MEMBER', title: 'The member token resolves to the member', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] },
    { id: 'WHOAMI-OWNER', title: 'The owner session resolves to the owner', category: 'identity', severity: 'control', actorId: 'owner', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'owner-1' }] },
    { id: 'OWN-NOTES', title: 'A member reads their own notes', category: 'notes', severity: 'control', actorId: 'member', method: 'GET', path: '/notes/own', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'OWNER-NOTE', title: 'The owner reads the owner note', category: 'notes', severity: 'control', actorId: 'owner', method: 'GET', path: '/notes/owner-secret', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
    { id: 'MEMBER-READS-OWNER', title: 'A member cannot read the owner note', category: 'notes', severity: 'high', actorId: 'member', method: 'GET', path: '/notes/owner-secret', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [401, 403, 404] }] },
    { id: 'OWNER-ADMIN', title: 'The owner cannot read the admin settings', category: 'admin', severity: 'high', actorId: 'owner', method: 'GET', path: '/admin/settings', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [401, 403, 404] }] },
    { id: 'ANON-NOTES', title: 'Nobody signed out reads notes', category: 'notes', severity: 'high', actorId: 'anonymous', method: 'GET', path: '/notes/own', evidenceRequirement: 'response', assertions: [{ kind: 'status.in', expected: [401, 403] }] },
  ] }, { adminControl, anonymousControl });
function withOptions(target, { adminControl, anonymousControl }) {
  if (adminControl) {
    target.actors.admin = { principalId: 'admin-1', credentialEnv: 'SCOPEHAVEN_TARGET_FWD_ADMIN', identityValue: 'admin-1' };
    target.checks.push({ id: 'WHOAMI-ADMIN', title: 'The administrator token resolves to the administrator', category: 'identity', severity: 'control', actorId: 'admin', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'admin-1' }] });
    target.requiredControlIds.push('WHOAMI-ADMIN');
    target.checks.push({ id: 'ADMIN-SETTINGS', title: 'The administrator reads the admin settings', category: 'admin', severity: 'control', actorId: 'admin', method: 'GET', path: '/admin/settings', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] });
    target.requiredControlIds.push('ADMIN-SETTINGS');
  }
  if (!anonymousControl) { target.checks = target.checks.filter(c => c.id !== 'ANON-PUBLIC'); target.requiredControlIds = target.requiredControlIds.filter(id => id !== 'ANON-PUBLIC'); }
  return target;
}
const statuses = run => Object.fromEntries(run.results.map(r => [r.id, r.status]));
const identity = run => Object.fromEntries((run.identityEvidence?.actors ?? []).map(a => [a.actorId, a.reason]));
async function assess(t, { mode = 'clean', app = 'secure', forwarded = true, adminControl = false, anonymousControl = true } = {}) {
  const origin = await forwarder(t, await notesApp(t, app), mode);
  const target = profile(origin, { forwarded, adminControl, anonymousControl });
  const run = await runHttpAssessment(target, { env });
  const expectedSuite = createRegistry({ profiles: [target], env: {} }).exportSuite(target.id);
  validateHttpRunEvidence(run, { expectedSuite });
  return { run, expectedSuite, gate: summarizeGate({ candidate: run, expectedSuite }) };
}

test('through a clean forwarder: both logins are proven (bearer and cookie), every check holds, and the run says it was forwarded', async t => {
  // Each boundary pass needs a passing required control on the same route, so OWNER-ADMIN needs the administrator's.
  const { run, gate } = await assess(t, { adminControl: true });
  assert.ok(Object.values(statuses(run)).every(s => s === 'pass'), JSON.stringify(statuses(run)));
  assert.deepEqual(identity(run), { member: 'established', owner: 'established', admin: 'established' });
  assert.deepEqual(unpairedForwardedPasses(run), []);
  assert.deepEqual([run.targetContext, run.targetLabel], ['operator-forwarded', LABEL]);
  assert.ok(run.scopeLabel.startsWith(PREFIX));
  assert.ok(renderReport(run).includes(PREFIX)); assert.ok(JSON.stringify(renderSarif(run)).includes(PREFIX));
  assert.deepEqual([gate.exitCode, gate.current.targetContext, gate.current.targetLabel], [0, 'operator-forwarded', LABEL]);
  assert.ok(gate.current.interpretation.startsWith(PREFIX), 'the gate states the forwarded target first');
});

test('a forwarded boundary pass with no passing same-route required control keeps the gate from reading clean; a local-app run is unaffected', async t => {
  // OWNER-ADMIN (GET /admin/settings) has no required control on its route: check-config names it before any run.
  assert.deepEqual(forwardedPairingGaps(profile('http://127.0.0.1:1')), ['OWNER-ADMIN']);
  assert.deepEqual(forwardedPairingGaps(profile('http://127.0.0.1:1', { adminControl: true })), []);
  assert.deepEqual(forwardedPairingGaps(profile('http://127.0.0.1:1', { forwarded: false })), [], 'only forwarded targets');
  const { run, gate } = await assess(t);
  assert.ok(Object.values(statuses(run)).every(s => s === 'pass'), 'every row keeps its verdict');
  assert.deepEqual(unpairedForwardedPasses(run), ['OWNER-ADMIN']);
  assert.deepEqual([gate.exitCode, gate.reasons], [1, ['forwarded-pass-unpaired']]);
  assert.match(renderReport(run), /Not clean through the forwarder:<\/strong> OWNER-ADMIN passed with no required control on the same route/);
  const local = await assess(t, { forwarded: false });
  assert.doesNotMatch(renderReport(local.run), /Not clean through the forwarder/);
  assert.deepEqual([unpairedForwardedPasses(local.run), local.gate.exitCode, local.gate.reasons], [[], 0, []]);
  // Pairing reads the run's own recorded method and route: another method, a longer route or a failed control does not pair.
  const edited = structuredClone(run), owner = edited.results.find(r => r.id === 'OWNER-NOTE');
  assert.deepEqual(unpairedForwardedPasses(edited), ['OWNER-ADMIN']);
  owner.status = 'fail';
  assert.deepEqual(unpairedForwardedPasses(edited), ['MEMBER-READS-OWNER', 'OWNER-ADMIN']);
  owner.status = 'pass'; owner.trace[0].data.method = 'POST';
  assert.deepEqual(unpairedForwardedPasses(edited), ['MEMBER-READS-OWNER', 'OWNER-ADMIN']);
  owner.trace[0].data.method = 'GET'; owner.trace[0].data.routeSegments = [...owner.trace[0].data.routeSegments, owner.trace[0].data.routeSegments[0]];
  assert.deepEqual(unpairedForwardedPasses(edited), ['MEMBER-READS-OWNER', 'OWNER-ADMIN']);
  edited.requiredControlIds = edited.requiredControlIds.filter(id => id !== 'OWN-NOTES');
  assert.ok(unpairedForwardedPasses(edited).includes('ANON-NOTES'), 'a control that is not required does not pair');
  // A route of one record position (also how a path the route reader cannot split reads, one with a query for example)
  // pairs only with the identical path.
  const lone = structuredClone(run), member = lone.results.find(r => r.id === 'MEMBER-READS-OWNER').trace[0].data, note = lone.results.find(r => r.id === 'OWNER-NOTE').trace[0].data;
  member.routeSegments = note.routeSegments = [{ record: 'a'.repeat(64), id: false }];
  member.requestPathHash = 'b'.repeat(64); note.requestPathHash = 'c'.repeat(64);
  assert.ok(unpairedForwardedPasses(lone).includes('MEMBER-READS-OWNER'), 'two different lone paths do not pair');
  note.requestPathHash = member.requestPathHash;
  assert.ok(!unpairedForwardedPasses(lone).includes('MEMBER-READS-OWNER'), 'the identical lone path pairs');
  assert.deepEqual(forwardedPairingGaps({ targetContext: 'operator-forwarded', requiredControlIds: ['C'], checks: [
    { id: 'C', severity: 'control', method: 'GET', path: '/search?q=own' }, { id: 'B', severity: 'high', method: 'GET', path: '/search?q=other' }, { id: 'S', severity: 'high', method: 'GET', path: '/search?q=own' }] }), ['B']);
});

test('through the forwarder, a build that refuses everything and one that answers everything both fail the gate', async t => {
  const nothing = await assess(t, { app: 'do-nothing' });
  assert.deepEqual([statuses(nothing.run)['OWN-NOTES'], statuses(nothing.run)['OWNER-NOTE']], ['fail', 'fail']);
  // The logins work, but each actor's required allowed-use control failed: its refusals are not read as holds.
  // actor-identity/4: refusing everything also refuses each actor's surface control in its brackets (surface-refused).
  assert.deepEqual(identity(nothing.run), { member: 'surface-refused', owner: 'surface-refused' });
  assert.deepEqual([statuses(nothing.run)['MEMBER-READS-OWNER'], statuses(nothing.run)['OWNER-ADMIN']], ['inconclusive', 'inconclusive']);
  // The same for the signed-out actor: its public-page control failed, so its 401 is not read as a hold.
  assert.deepEqual([statuses(nothing.run)['ANON-PUBLIC'], statuses(nothing.run)['ANON-NOTES']], ['fail', 'inconclusive']);
  assert.equal(nothing.gate.exitCode, 1);
  const everything = await assess(t, { app: 'dump-everything' });
  assert.deepEqual([statuses(everything.run)['MEMBER-READS-OWNER'], statuses(everything.run)['OWNER-ADMIN']], ['fail', 'fail']);
  assert.equal(everything.gate.exitCode, 1);
});

test('a forwarder that rewrites cookies: the cookie actor\'s login is not proven and its forbidden check is never a pass; the bearer actor is unaffected', async t => {
  const { run, gate } = await assess(t, { mode: 'cookie-rewrite' });
  assert.deepEqual(identity(run), { member: 'established', owner: 'identity-control-not-passed' });
  assert.notEqual(statuses(run)['OWNER-ADMIN'], 'pass');
  assert.equal(statuses(run)['MEMBER-READS-OWNER'], 'pass');
  assert.equal(gate.exitCode, 1);
});

test('a forwarder that strips Authorization: the bearer actor\'s login is not proven and its forbidden check is never a pass; the cookie actor is unaffected', async t => {
  const { run, gate } = await assess(t, { mode: 'strip-authorization' });
  assert.deepEqual(identity(run), { member: 'identity-control-not-passed', owner: 'established' });
  // Without its token the member would get the 401 this check accepts: the unproven login keeps it from reading pass.
  assert.notEqual(statuses(run)['MEMBER-READS-OWNER'], 'pass');
  assert.equal(statuses(run)['OWNER-ADMIN'], 'pass');
  assert.equal(gate.exitCode, 1);
});

test('a forwarder that redirects every request to sign-in: no login is proven and no forbidden check reads pass (they read fail: 302 is outside the statuses they accept)', async t => {
  const { run, gate } = await assess(t, { mode: 'redirect-signin' });
  assert.deepEqual(identity(run), { member: 'identity-control-not-passed', owner: 'identity-control-not-passed' });
  const s = statuses(run);
  assert.deepEqual([s['MEMBER-READS-OWNER'], s['OWNER-ADMIN'], s['ANON-NOTES']], ['fail', 'fail', 'fail']);
  assert.ok(Object.values(s).every(x => x !== 'pass'));
  assert.equal(gate.exitCode, 1);
});

test('a forwarded run is never compared with a local-app run of the same app, and the gate refuses the pair', async t => {
  const forwarded = await assess(t), local = await assess(t, { forwarded: false });
  assert.deepEqual([local.run.targetContext, local.run.targetLabel], ['local-app', null]);
  const compared = compareRuns(local.run, forwarded.run);
  assert.equal(compared.compatible, false);
  assert.ok(compared.reasons.some(r => /^Target context differs/.test(r)), JSON.stringify(compared.reasons));
  const gate = summarizeGate({ candidate: forwarded.run, baseline: local.run, expectedSuite: forwarded.expectedSuite });
  assert.equal(gate.exitCode, 1); assert.ok(gate.reasons.includes('incompatible-baseline'));
  assert.equal(gate.comparison.compatibility, 'incompatible');
});

// Identity proof covers the identity route only:
// a forwarder that answers or alters one route itself, and leaves /me alone, is not seen by it.
test('a forwarder that denies /admin/* itself makes OWNER-ADMIN read pass on a build that leaks it, and the gate is not clean', async t => {
  const through = await assess(t, { app: 'owner-admin' });
  assert.equal(statuses(through.run)['OWNER-ADMIN'], 'fail', 'through a clean forwarder the leak shows');
  const denied = await assess(t, { app: 'owner-admin', mode: 'deny-admin' });
  assert.deepEqual(identity(denied.run), { member: 'established', owner: 'established' });
  assert.equal(statuses(denied.run)['OWNER-ADMIN'], 'pass', 'the row: the forwarder’s own 403 reads as a hold');
  // Before same-route pairing this gate exited 0. No required control passed on that route, so the pass does not count.
  assert.deepEqual([denied.gate.exitCode, denied.gate.reasons], [1, ['forwarded-pass-unpaired']]);
});

test('the comparison and SARIF read the forwarder\'s own answer the way the gate does, never as a repair', async t => {
  // One forwarder in front of the leaking build: the baseline passes /admin/* through, the candidate denies it in the forwarder.
  const state = { mode: 'clean' };
  const origin = await forwarder(t, await notesApp(t, 'owner-admin'), () => state.mode);
  const target = profile(origin), expectedSuite = createRegistry({ profiles: [target], env: {} }).exportSuite(target.id);
  const baseline = await runHttpAssessment(target, { env });
  state.mode = 'deny-admin';
  const candidate = await runHttpAssessment(target, { env });
  assert.deepEqual([statuses(baseline)['OWNER-ADMIN'], statuses(candidate)['OWNER-ADMIN'], unpairedForwardedPasses(candidate)], ['fail', 'pass', ['OWNER-ADMIN']]);
  const compared = compareRuns(baseline, candidate);
  assert.equal(compared.compatible, true, JSON.stringify(compared.reasons));
  const row = compared.rows.find(r => r.id === 'OWNER-ADMIN');
  assert.deepEqual([row.before, row.after, row.transition, row.transitionReason], ['fail', 'pass', 'unverified', 'candidate-forwarded-pass-unpaired']);
  assert.ok(!compared.rows.some(r => r.transition === 'contract-restored'), 'nothing reads restored');
  assert.equal(compared.summary.fixed, 0);
  assert.notEqual(compared.restorationLabel, 'Response contracts restored');
  assert.ok(compared.reasons.some(r => r.includes('forwarded-pass-unpaired: OWNER-ADMIN')), JSON.stringify(compared.reasons));
  // A paired pass (MEMBER-READS-OWNER, paired by OWNER-NOTE) keeps its preserved transition.
  assert.equal(compared.rows.find(r => r.id === 'MEMBER-READS-OWNER').transition, 'preserved');
  const html = renderComparisonReport(comparisonDocument(baseline, candidate, compared));
  assert.doesNotMatch(html, /contract-restored/);
  assert.match(html, /forwarded-pass-unpaired: OWNER-ADMIN/);
  // A pass that stays unpaired in both runs is not a preserved pass either.
  const again = compareRuns(candidate, candidate).rows.find(r => r.id === 'OWNER-ADMIN');
  assert.deepEqual([again.transition, again.transitionReason], ['unverified', 'candidate-forwarded-pass-unpaired']);
  // SARIF: the unpaired pass is kind review with a note, and the run lists it; a paired pass stays kind pass.
  const sarif = renderSarif(candidate).runs[0], result = id => sarif.results.find(r => r.ruleId === id);
  assert.deepEqual([result('OWNER-ADMIN').kind, result('OWNER-ADMIN').level, result('OWNER-ADMIN').properties.scopehavenUnpaired], ['review', 'none', 'forwarded-pass-unpaired']);
  assert.match(result('OWNER-ADMIN').message.text, /^PASS, NOT CLEAN THROUGH THE FORWARDER: .*the forwarder may have answered this route itself\.$/);
  assert.equal(result('MEMBER-READS-OWNER').kind, 'pass');
  assert.deepEqual([sarif.properties.unpairedPasses.reason, sarif.properties.unpairedPasses.checks], ['forwarded-pass-unpaired', ['OWNER-ADMIN']]);
  assert.equal(renderSarif(baseline).runs[0].properties.unpairedPasses, undefined, 'present only when a pass is unpaired');
  // The gate with the baseline: still not clean, and it credits no fix.
  const gate = summarizeGate({ candidate, baseline, expectedSuite });
  assert.equal(gate.exitCode, 1);
  assert.ok(gate.reasons.includes('forwarded-pass-unpaired') && gate.reasons.includes('comparison-incomplete'), JSON.stringify(gate.reasons));
});

test('a required positive control on the same route turns the gate red when the forwarder answers that route itself', async t => {
  const clean = await assess(t, { adminControl: true });
  assert.deepEqual([statuses(clean.run)['ADMIN-SETTINGS'], clean.gate.exitCode], ['pass', 0], 'the control passes through a clean forwarder');
  const denied = await assess(t, { app: 'owner-admin', mode: 'deny-admin', adminControl: true });
  assert.equal(statuses(denied.run)['ADMIN-SETTINGS'], 'fail');
  assert.equal(denied.gate.exitCode, 1);
  assert.ok(denied.gate.reasons.includes('required-controls-not-passed'), JSON.stringify(denied.gate.reasons));
  // The row itself still reads pass: the control makes the run fail, it does not re-grade the row.
  assert.equal(statuses(denied.run)['OWNER-ADMIN'], 'pass');
});

test('a forwarder that answers everything with 401 reads the signed-out forbidden row as pass without an anonymous control, and never with one', async t => {
  const without = await assess(t, { mode: 'deny-all', anonymousControl: false });
  assert.equal(statuses(without.run)['ANON-NOTES'], 'pass', 'the known limit: nothing reached the app');
  assert.equal(without.gate.exitCode, 1, 'the gate is red for the unproven logins');
  assert.ok(without.gate.reasons.includes('forwarded-pass-unpaired'), 'and for the pass: the same-route control (OWN-NOTES) failed');
  const withControl = await assess(t, { mode: 'deny-all' });
  assert.equal(statuses(withControl.run)['ANON-PUBLIC'], 'fail');
  assert.notEqual(statuses(withControl.run)['ANON-NOTES'], 'pass');
  assert.equal(withControl.gate.exitCode, 1);
});
