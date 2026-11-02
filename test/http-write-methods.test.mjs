// pool-http-write-methods: HTTP checks may use PUT, PATCH and DELETE as well as GET
// and POST. A write method changes what is sent, never how the response is judged.
// Owned loopback servers and synthetic data only: no model, no provider, no database.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { observeHttp, runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, identityControlPlan, HttpEvidenceError, HTTP_CHECK_METHODS, HTTP_WRITE_METHODS, HTTP_EVIDENCE_VERSIONS, MUTATION_EFFECTS } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { compareRuns } from '../src/runner.mjs';
import { projectHttpContract } from '../src/contract-http.mjs';
import { digest } from '../src/domain.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';

const WRITES = ['PUT', 'PATCH', 'DELETE'];
// Other HTTP methods, wrong case, padded or look-alike spellings and non-strings: refused at profile validation,
// at send time and in saved evidence. 'P\u0410TCH' has a Cyrillic capital A.
const REFUSED = ['TRACE', 'CONNECT', 'HEAD', 'OPTIONS', 'PROPFIND', 'patch', 'Delete', ' PATCH', 'PATCH ', 'PATCH\n', 'P\u0410TCH', '', null, 1];
// One predicate key for every run here (src/contracts.mjs predicate records): a write method's run and the POST run compare their digests.
const TOKEN = 'synthetic-write-token', ENV = { SCOPEHAVEN_TARGET_WRITE_MEMBER: TOKEN, SCOPEHAVEN_PREDICATE_KEY: '3e'.repeat(32) };
const BODY = { status: 'closed', note: 'synthetic' };

// An owned loopback app. Writes answer by path, whatever the write method, so a run
// with PATCH checks and the same run with POST checks see the same responses.
async function app(t) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, type: req.headers['content-type'] ?? null, body: Buffer.concat(chunks).toString() });
      const send = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
      if (req.headers.authorization !== `Bearer ${TOKEN}`) return send(401, { error: 'sign in' });
      if (req.method === 'GET' && req.url === '/me') return send(200, { user: 'member-one' });
      if (req.method === 'GET' && req.url === '/orders/mine') return send(200, { orders: [] });
      if (req.method === 'GET') return send(404, {});
      if (req.url === '/orders/own') return send(200, { updated: true });
      if (req.url === '/orders/foreign') return send(403, { error: 'forbidden' });
      if (req.url === '/orders/leaky') return send(200, { updated: true });
      if (req.url === '/orders/empty') { res.writeHead(204); return res.end(); }
      send(404, {});
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${server.address().port}`, seen };
}
const status = expected => ({ kind: 'status.equals', expected });
function profile(origin, method) {
  const write = (id, severity, path, assertions, extra = {}) => ({ id, title: id, category: 'Writes', severity, actorId: 'member', method, path, evidenceRequirement: 'response', assertions, ...extra });
  return { id: 'write-lab', name: 'Write methods lab', applicationId: 'write-lab', origin, buildLabel: 'b1', contextId: 'synthetic-writes',
    actors: { member: { principalId: 'member-one', credentialEnv: 'SCOPEHAVEN_TARGET_WRITE_MEMBER', identityValue: 'member-one' } },
    requiredControlIds: ['WHOAMI', 'OWN-WRITE'],
    checks: [
      { id: 'WHOAMI', title: 'Member session', category: 'Identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [status(200), { kind: 'json.equals', pointer: '/user', expected: 'member-one' }] },
      write('OWN-WRITE', 'control', '/orders/own', [status(200), { kind: 'json.equals', pointer: '/updated', expected: true }], { body: BODY }),
      write('FOREIGN-WRITE', 'high', '/orders/foreign', [{ kind: 'status.in', expected: [403, 404] }, { kind: 'json.exists', pointer: '/updated', expected: false }], { body: BODY }),
      write('LEAKY-WRITE', 'high', '/orders/leaky', [{ kind: 'status.in', expected: [403, 404] }, { kind: 'json.exists', pointer: '/updated', expected: false }], { body: BODY }),
      write('NO-BODY', 'medium', '/orders/foreign', [status(403)]),
      write('EMPTY-REPLY', 'low', '/orders/empty', [status(204), { kind: 'json.exists', pointer: '/updated', expected: false }], { body: BODY }),
    ] };
}
const manifest = target => ({ schemaVersion: 1, targets: [target] });
const refusal = target => { try { validateTargetFile(manifest(target)); } catch (error) { return error.message; } assert.fail('expected the profile to be refused'); };
const suiteOf = target => createRegistry({ profiles: [target], env: ENV }).exportSuite(target.id);
const reseal = row => { row.evidenceDigest = digest(row.trace.length === 2 ? { evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions } : { evidence: row.trace[0].data, assertions: row.assertions }); };
const evidenceCode = (run, options) => { try { validateHttpRunEvidence(run, options); } catch (error) { assert.ok(error instanceof HttpEvidenceError); return error.detail ? `${error.code}:${error.detail}` : error.code; } return null; };
// Everything a write method may not change: per-row verdicts, assertions and retained evidence, less the method and request ids.
const judged = run => run.results.map(r => ({ ...r, durationMs: 0, evidenceDigest: null, trace: r.trace.map(t => t.type === 'http-observation' ? { ...t, data: { ...t.data, requestId: null, method: null, routeSegments: null, controlScope: null } } : t) }));

test('the method sets: GET reads, POST, PUT, PATCH and DELETE write, nothing else', () => {
  assert.deepEqual([...HTTP_CHECK_METHODS], ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']);
  assert.deepEqual([...HTTP_WRITE_METHODS], ['POST', 'PUT', 'PATCH', 'DELETE']);
  assert.ok(Object.isFrozen(HTTP_CHECK_METHODS) && Object.isFrozen(HTTP_WRITE_METHODS));
});

test('profile validation: PUT, PATCH and DELETE checks validate with or without a JSON body; GET takes no body; other methods are refused', () => {
  const origin = 'http://127.0.0.1:9';
  for (const method of ['POST', ...WRITES]) {
    const [target] = validateTargetFile(manifest(profile(origin, method)));
    assert.deepEqual(target.checks.filter(c => c.id !== 'WHOAMI').map(c => c.method), Array(5).fill(method));
    assert.deepEqual(target.checks.find(c => c.id === 'OWN-WRITE').body, BODY);
    assert.equal(Object.hasOwn(target.checks.find(c => c.id === 'NO-BODY'), 'body'), false);
    for (const body of [[], 'text', null, 1]) assert.match(refusal({ ...profile(origin, method), checks: profile(origin, method).checks.map(c => c.id === 'OWN-WRITE' ? { ...c, body } : c) }), /check "OWN-WRITE" > "body": body requires POST, PUT, PATCH or DELETE and a JSON object/);
  }
  const getBody = profile(origin, 'PATCH'); getBody.checks[0] = { ...getBody.checks[0], body: {} };
  assert.match(refusal(getBody), /check "WHOAMI" > "body": body requires POST, PUT, PATCH or DELETE and a JSON object/);
  for (const method of REFUSED) assert.match(refusal(profile(origin, method)), /check "OWN-WRITE": invalid check configuration \("method" must be GET, POST, PUT, PATCH or DELETE\)/, String(method));
  // The method is part of the profile and suite identity.
  const hashes = ['POST', ...WRITES].map(method => createRegistry({ profiles: [profile(origin, method)], env: ENV }).exportSuite('write-lab').hash);
  assert.equal(new Set(hashes).size, 4);
});

test('identity controls stay GET only: a write control naming the actor never proves its login', () => {
  for (const method of ['POST', ...WRITES]) {
    const target = profile('http://127.0.0.1:9', method);
    target.checks[1].assertions.push({ kind: 'json.equals', pointer: '/user', expected: 'member-one' });
    target.requiredControlIds = ['OWN-WRITE'];
    target.checks = target.checks.filter(c => c.id !== 'WHOAMI');
    const [valid] = validateTargetFile(manifest(target));
    assert.deepEqual(identityControlPlan(valid).get('member').identityControls, [], method);
  }
});

test('observeHttp sends PUT, PATCH and DELETE over loopback with their JSON body, DELETE also without one, and never sends another method', async t => {
  const { origin, seen } = await app(t);
  for (const method of WRITES) {
    const observed = await observeHttp(origin, { method, path: '/orders/own', body: BODY }, { credential: TOKEN });
    assert.deepEqual([observed.status, observed.complete, observed.jsonParsed, observed.json], [200, true, true, { updated: true }], method);
    assert.deepEqual(seen.at(-1), { method, url: '/orders/own', auth: `Bearer ${TOKEN}`, type: 'application/json', body: JSON.stringify(BODY) });
  }
  for (const method of WRITES) {
    await observeHttp(origin, { method, path: '/orders/foreign' }, { credential: TOKEN });
    assert.deepEqual([seen.at(-1).method, seen.at(-1).type, seen.at(-1).body], [method, null, ''], method);
  }
  const empty = await observeHttp(origin, { method: 'DELETE', path: '/orders/empty' }, { credential: TOKEN });
  assert.deepEqual([empty.status, empty.complete, empty.jsonParsed, empty.error], [204, true, false, 'invalid-json']);
  const before = seen.length;
  for (const method of REFUSED) assert.throws(() => observeHttp(origin, { method, path: '/orders/own', body: BODY }, { credential: TOKEN }), /Unsupported request method/, String(method));
  assert.equal(seen.length, before, 'a refused method never reaches the target');
});

// actor-identity/4: the member's refusals count only after its earlier complete 2xx on a protected route,
// so the end-to-end runs give it a surface control (a required GET of its own orders).
const withOwnOrders = target => { target.checks.push({ id: 'OWN-ORDERS', title: 'OWN-ORDERS', category: 'Writes', severity: 'control', actorId: 'member', method: 'GET', path: '/orders/mine', evidenceRequirement: 'response', assertions: [status(200)] }); target.requiredControlIds.push('OWN-ORDERS'); return target; };
test('end to end: a PUT, PATCH or DELETE run decides status and JSON assertions exactly as the same POST run, and each write is sent once', async t => {
  const { origin, seen } = await app(t);
  const post = await runHttpAssessment(withOwnOrders(profile(origin, 'POST')), { env: ENV });
  assert.deepEqual(Object.fromEntries(post.results.map(r => [r.id, r.status])), { 'WHOAMI': 'pass', 'OWN-WRITE': 'pass', 'FOREIGN-WRITE': 'pass', 'LEAKY-WRITE': 'fail', 'NO-BODY': 'pass', 'EMPTY-REPLY': 'inconclusive', 'OWN-ORDERS': 'pass' });
  const postGate = summarizeGate({ candidate: post, expectedSuite: suiteOf(withOwnOrders(profile(origin, 'POST'))) });
  for (const method of WRITES) {
    const from = seen.length, target = withOwnOrders(profile(origin, method));
    const run = await runHttpAssessment(target, { env: ENV });
    const sent = seen.slice(from);
    // Five write checks, each sent once with its body (none for NO-BODY); only the GET identity and surface controls are re-sent.
    assert.deepEqual(sent.filter(r => r.method !== 'GET').map(r => [r.method, r.url, r.body]), [
      [method, '/orders/own', JSON.stringify(BODY)], [method, '/orders/foreign', JSON.stringify(BODY)], [method, '/orders/leaky', JSON.stringify(BODY)], [method, '/orders/foreign', ''], [method, '/orders/empty', JSON.stringify(BODY)]]);
    assert.deepEqual(judged(run), judged(post), method);
    assert.deepEqual(run.counts, post.counts);
    assert.deepEqual(run.identityEvidence.actors.map(a => [a.reason, a.identityControlIds]), [['established', ['WHOAMI']]]);
    for (const row of run.results) {
      const evidence = row.trace[0].data;
      const read = ['WHOAMI', 'OWN-ORDERS'].includes(row.id);
      assert.equal(evidence.method, read ? 'GET' : method);
      assert.equal(evidence.mutationEffects, read ? 'Not independently observed.' : 'Not independently observed; a timeout does not undo an action.', row.id);
    }
    assert.ok(run.limitations.some(l => l.includes('A timed-out POST, PUT, PATCH or DELETE may still have executed')));
    // Every reader of saved evidence accepts it: the shared validator (alone and with the exported suite), the gate and compare.
    const suite = suiteOf(target), saved = JSON.parse(JSON.stringify(run));
    assert.equal(evidenceCode(saved), null); assert.equal(evidenceCode(saved, { expectedSuite: suite }), null);
    const gate = summarizeGate({ candidate: saved, expectedSuite: suite });
    assert.deepEqual([gate.exitCode, gate.reasons, gate.current.counts], [postGate.exitCode, postGate.reasons, postGate.current.counts]);
    assert.equal(compareRuns(run, saved).compatible, true);
    // A method change is a profile change: the POST and PATCH runs never compare as one subject.
    assert.ok(compareRuns(post, run).reasons.includes('profileHash differs or is missing.'));
  }
});

test('saved evidence: any other method is refused even when resealed, and a PATCH edited to POST fails the exported suite', async t => {
  const { origin } = await app(t);
  const target = profile(origin, 'PATCH'), suite = suiteOf(target);
  const run = await runHttpAssessment(target, { env: ENV });
  const edit = (method, sealed = true) => { const copy = structuredClone(run), row = copy.results.find(r => r.id === 'FOREIGN-WRITE'); row.trace[0].data.method = method; if (sealed) reseal(row); return copy; };
  for (const method of REFUSED) {
    assert.equal(evidenceCode(edit(method)), 'invalid-run-evidence', String(method));
    assert.equal(summarizeGate({ candidate: edit(method), expectedSuite: suite }).exitCode, 2, String(method));
  }
  // Unsealed, any change of method breaks the row's evidence digest.
  for (const method of ['POST', 'PUT', 'DELETE', 'GET']) assert.equal(evidenceCode(edit(method, false)), 'invalid-run-evidence', method);
  // Resealed PATCH -> POST, PUT or DELETE: the exported suite binds every check's method.
  for (const method of ['POST', 'PUT', 'DELETE']) {
    assert.equal(evidenceCode(edit(method), { expectedSuite: suite }), 'unexpected-suite-evidence', method);
    const gate = summarizeGate({ candidate: edit(method), expectedSuite: suite });
    assert.deepEqual([gate.exitCode, gate.reasons], [2, ['unexpected-suite-evidence']], method);
  }
  // Resealed PATCH -> GET keeps the write text, which a GET never carries: refused with or without the suite.
  assert.equal(evidenceCode(edit('GET')), 'invalid-run-evidence');
  assert.deepEqual(summarizeGate({ candidate: edit('GET'), expectedSuite: suite }).reasons, ['invalid-run-evidence']);
  // The other way: a POST run edited to PATCH fails the POST suite.
  const postTarget = profile(origin, 'POST'), posted = await runHttpAssessment(postTarget, { env: ENV });
  const forged = structuredClone(posted), row = forged.results.find(r => r.id === 'OWN-WRITE'); row.trace[0].data.method = 'PATCH'; reseal(row);
  assert.equal(evidenceCode(forged, { expectedSuite: suiteOf(postTarget) }), 'unexpected-suite-evidence');
  // The evidence text must match the method: write text on a write, read text on a GET; rewritten or deleted is refused, resealed or not.
  const effects = (id, value) => { const copy = structuredClone(run), r = copy.results.find(x => x.id === id); if (value === undefined) delete r.trace[0].data.mutationEffects; else r.trace[0].data.mutationEffects = value; reseal(r); return copy; };
  for (const value of [MUTATION_EFFECTS.read, 'Not observed.', undefined]) assert.equal(evidenceCode(effects('FOREIGN-WRITE', value)), 'invalid-run-evidence', String(value));
  for (const value of [MUTATION_EFFECTS.write, undefined]) assert.equal(evidenceCode(effects('WHOAMI', value)), 'invalid-run-evidence', String(value));
  // Without a suite, compare refuses a resealed method relabel: the row method is part of the actor signature.
  const relabelled = edit('POST');
  assert.equal(evidenceCode(relabelled), null, 'the validator alone cannot tell a consistent relabel');
  assert.equal(compareRuns(run, relabelled).compatible, false);
  assert.ok(compareRuns(run, relabelled).reasons.includes('Actors, login modes or identity controls differ between the runs.'));
});

test('saved evidence: connector v1 and v2 sent only GET and POST, so a v2-labelled row with PUT, PATCH or DELETE is refused', async t => {
  const { origin } = await app(t);
  const run = await runHttpAssessment(profile(origin, 'POST'), { env: ENV });
  // Relabel the run as connector v2 evidence: v2 carries identity evidence but no target context or observers.
  const v2 = structuredClone(run);
  Object.assign(v2, { adapterVersion: HTTP_EVIDENCE_VERSIONS[1].adapterVersion, assertionSchemaVersion: HTTP_EVIDENCE_VERSIONS[1].assertionSchemaVersion });
  for (const key of ['targetContext', 'targetLabel', 'observers']) delete v2[key];
  assert.equal(evidenceCode(v2), null, 'the relabelled POST run is consistent v2 evidence');
  // The method-matched evidence text holds on every connector version.
  for (const [id, value] of [['FOREIGN-WRITE', MUTATION_EFFECTS.read], ['WHOAMI', MUTATION_EFFECTS.write]]) {
    const copy = structuredClone(v2), row = copy.results.find(r => r.id === id); row.trace[0].data.mutationEffects = value; reseal(row);
    assert.equal(evidenceCode(copy), 'invalid-run-evidence', id);
  }
  for (const method of WRITES) {
    const copy = structuredClone(v2), row = copy.results.find(r => r.id === 'FOREIGN-WRITE');
    row.trace[0].data.method = method; reseal(row);
    assert.equal(evidenceCode(copy), 'invalid-run-evidence', method);
    // The same edit on the v3 label is accepted: the method set depends on the connector version only.
    const v3 = structuredClone(run), same = v3.results.find(r => r.id === 'FOREIGN-WRITE');
    same.trace[0].data.method = method; reseal(same);
    assert.equal(evidenceCode(v3), null, method);
  }
});

test('the contract view still reads connector v1 runs only: a PATCH run reads http-version-pending, never a pass', async t => {
  const { origin } = await app(t);
  const run = await runHttpAssessment(profile(origin, 'PATCH'), { env: ENV });
  const view = projectHttpContract(run);
  assert.deepEqual([view.supported, view.reason], [false, 'http-version-pending']);
});

test('not_applicable must match the exported suite: a failing row relabelled not_applicable is refused, declared ones still validate', async t => {
  const { origin } = await app(t);
  const target = profile(origin, 'PATCH');
  target.checks.push({ ...target.checks[2], id: 'NOT-HERE', applicability: { applies: false, reason: 'This build has no order archive.' } });
  const suite = suiteOf(target), run = await runHttpAssessment(target, { env: ENV });
  assert.equal(run.results.find(r => r.id === 'NOT-HERE').status, 'not_applicable');
  assert.equal(evidenceCode(run, { expectedSuite: suite }), null, 'a declared not_applicable row validates');
  // The regression (LEAKY-WRITE fails) relabelled not_applicable, with the counts kept consistent.
  const relabelled = structuredClone(run), row = relabelled.results.find(r => r.id === 'LEAKY-WRITE');
  assert.equal(row.status, 'fail');
  row.status = 'not_applicable'; relabelled.counts.fail--; relabelled.counts.not_applicable++;
  assert.equal(evidenceCode(relabelled, { expectedSuite: suite }), 'unexpected-suite-evidence:applicability-mismatch');
  const gate = summarizeGate({ candidate: relabelled, expectedSuite: suite });
  assert.deepEqual([gate.exitCode, gate.reasons, gate.detail], [2, ['unexpected-suite-evidence'], 'applicability-mismatch']);
  // A suite that declares the relabelled check applicable refuses it whatever the row carries; one that never names it does too.
  const undeclared = structuredClone(suite); delete undeclared.checks.find(c => c.id === 'NOT-HERE').applicability;
  assert.equal(evidenceCode(run, { expectedSuite: undeclared }), 'unexpected-suite-evidence:applicability-mismatch');
});

// A write is a real change on the target. An owned app holds one record, A-4, owned by
// alice; the vulnerable build lets bob DELETE it. Nothing resets the app between the two runs unless reset() is called.
async function orderApp(t) {
  // B-1 is bob's own order: his surface control reads it (actor-identity/4), so his refusals count.
  const seed = () => new Map([['A-4', 'alice'], ['B-1', 'bob']]);
  let records = seed();
  const users = { 'Bearer tok-alice-synthetic': 'alice', 'Bearer tok-bob-synthetic': 'bob' };
  const server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const send = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
      const user = users[req.headers.authorization];
      if (!user) return send(401, {});
      if (req.method === 'GET' && req.url === '/me') return send(200, { user });
      const id = /^\/orders\/([A-Za-z0-9-]+)$/.exec(req.url)?.[1];
      if (!id || !records.has(id)) return send(404, { error: 'not found' });
      if (req.method === 'GET') return records.get(id) === user ? send(200, { id }) : send(403, {});
      if (req.method === 'DELETE') { records.delete(id); return send(200, { deleted: true }); } // the defect: no owner check
      send(405, {});
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${server.address().port}`, reset: () => { records = seed(); } };
}
const ORDER_ENV = { SCOPEHAVEN_TARGET_WM_ALICE: 'tok-alice-synthetic', SCOPEHAVEN_TARGET_WM_BOB: 'tok-bob-synthetic' };
function deleteProfile(origin, twin) {
  const c = (id, severity, actorId, method, path, assertions) => ({ id, title: id, category: 'Orders', severity, actorId, method, path, evidenceRequirement: 'response', assertions });
  const who = ['alice', 'bob'].map(user => c(`WHO-${user}`, 'control', user, 'GET', '/me', [status(200), { kind: 'json.equals', pointer: '/user', expected: user }]));
  const ownerRead = c('ALICE-READS-A4', 'control', 'alice', 'GET', '/orders/A-4', [status(200)]);
  const probe = c('BOB-DELETES-A4', 'high', 'bob', 'DELETE', '/orders/A-4', [{ kind: 'status.in', expected: [403, 404] }]);
  const bobOwn = c('BOB-READS-B1', 'control', 'bob', 'GET', '/orders/B-1', [status(200)]);
  return { id: twin ? 'del-twin' : 'del-plain', name: 'DELETE probe', applicationId: 'wm-app', origin, buildLabel: 'vulnerable-unchanged', contextId: 'wm',
    actors: { alice: { principalId: 'alice', credentialEnv: 'SCOPEHAVEN_TARGET_WM_ALICE', identityValue: 'alice' }, bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_WM_BOB', identityValue: 'bob' } },
    requiredControlIds: ['WHO-alice', 'WHO-bob', 'BOB-READS-B1', ...(twin ? ['ALICE-READS-A4'] : [])], checks: [...who, bobOwn, ...(twin ? [ownerRead] : []), probe] };
}
async function gateTwice(target, between = () => {}) {
  const first = await runHttpAssessment(target, { env: ORDER_ENV });
  between();
  const second = await runHttpAssessment(target, { env: ORDER_ENV });
  return { first, gate: summarizeGate({ candidate: second, baseline: first, expectedSuite: createRegistry({ profiles: [target], env: ORDER_ENV }).exportSuite(target.id) }) };
}
test('a DELETE uses up the record the next run probes: without a reset the unchanged build reads restored; an owner-read control blocks that', async t => {
  // The hazard: the same vulnerable build, run twice with no reset. Run 1 deletes A-4 and fails; in run 2 A-4 is gone, the 404 reads as a refusal.
  const plain = await orderApp(t), hazard = await gateTwice(deleteProfile(plain.origin, false));
  assert.equal(hazard.first.results.find(r => r.id === 'BOB-DELETES-A4').status, 'fail');
  assert.deepEqual([hazard.gate.exitCode, hazard.gate.comparison.compatibility, hazard.gate.comparison.labels['contract-restored'], hazard.gate.comparison.restorationLabel], [0, 'compatible', 1, 'Response contracts restored']);
  // The control: the owner reads A-4 (a required control) before the destructive probe, so the used-up record fails it and blocks the comparison.
  const twin = await orderApp(t), blocked = await gateTwice(deleteProfile(twin.origin, true));
  assert.equal(blocked.gate.exitCode, 1);
  assert.ok(blocked.gate.reasons.includes('required-controls-not-passed'), JSON.stringify(blocked.gate.reasons));
  assert.deepEqual([blocked.gate.comparison.labels['contract-restored'], blocked.gate.comparison.labels['blocked-by-controls']], [0, 1]);
  assert.notEqual(blocked.gate.comparison.restorationLabel, 'Response contracts restored');
  // With a reset to the same seed between the runs, the unchanged build fails again: still failing, controls pass, nothing restored.
  const reset = await orderApp(t), fair = await gateTwice(deleteProfile(reset.origin, true), reset.reset);
  assert.deepEqual([fair.gate.exitCode, fair.gate.reasons, fair.gate.comparison.labels['still-failing'], fair.gate.comparison.labels['contract-restored']], [1, ['checks-failed'], 1, 0]);
});
