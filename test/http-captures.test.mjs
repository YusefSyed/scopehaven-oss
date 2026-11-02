// Typed captures (src/http-captures.mjs): creator versus actor without application-specific ids in core.
// Owned loopback practice app (integrations/core-practice/app.mjs) with synthetic users and notes and a
// loopback egress recorder; one injected-transport case with no socket. No model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, contractDigest, PRECONDITION_ASSERTION } from '../src/contracts.mjs';
import { captureValueValid, fillCaptures, captureUsesOf } from '../src/http-captures.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { createCorePracticeApp } from '../integrations/core-practice/app.mjs';
import { creatorProfile } from '../integrations/core-practice/profiles.mjs';
import { freePorts } from '../integrations/observers/fixtures/free-port.mjs';
import { CAPTURE_LIMITATION } from '../src/http-scope-text.mjs';

const row = (run, id) => run.results.find(r => r.id === id);
const CELLS = ['CELL-MEMBER-BY-OWNER', 'CELL-ADMIN-BY-ADMIN', 'CELL-MEMBER-BY-ADMIN', 'CELL-MEMBER-BY-OTHER', 'CELL-ADMIN-BY-MEMBER'];
const suiteOf = (profile, env) => createRegistry({ profiles: [profile], env }).exportSuite(profile.id);
async function assess(t, build = {}, { observers = true } = {}) {
  const [sinkPort] = await freePorts(1);
  const app = await createCorePracticeApp({ sinkPort, ...build }); t.after(() => app.close());
  const profile = creatorProfile({ origin: app.origin, sinkPort, observers });
  return { app, profile, run: await runHttpAssessment(profile, { env: app.env }) };
}
const reseal = r => { r.evidenceDigest = digest(r.trace.length === 2 ? { evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions } : { evidence: r.trace[0].data, assertions: r.assertions }); };

test('capture validation: names, types, placement and preconditions are checked before any request', () => {
  const base = creatorProfile({ origin: 'http://127.0.0.1:9', sinkPort: 40999 });
  validateTargetFile({ schemaVersion: 1, targets: [base] });
  const check = (p, id) => p.checks.find(c => c.id === id);
  const refuse = (edit, pattern) => { const p = structuredClone(base); edit(p); assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), pattern); };
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').path = '/api/notes/{{nobodyCaptured}}/delete'; delete check(p, 'CELL-MEMBER-BY-OWNER').precondition; }, /"\{\{nobodyCaptured\}\}" needs an earlier applicable check that captures "nobodyCaptured"/);
  // The capture comes first: a later capture does not serve an earlier use.
  refuse(p => { const i = p.checks.findIndex(c => c.id === 'ALICE-NOTE-A'); p.checks.push(p.checks.splice(i, 1)[0]); p.requiredControlIds = [...p.requiredControlIds]; }, /needs an earlier applicable check that captures "aliceNoteA"/);
  refuse(p => { check(p, 'ALICE-NOTE-B').capture = { aliceNoteA: { pointer: '/id', type: 'id' } }; }, /"aliceNoteA" is captured once per profile/);
  refuse(p => { check(p, 'ALICE-NOTE-A').capture.aliceNoteA.type = 'uuid'; }, /type id, string, integer/);
  refuse(p => { check(p, 'ALICE-NOTE-A').capture = { 'bad-name': { pointer: '/id', type: 'id' } }; }, /a capture name is a letter/);
  refuse(p => { check(p, 'ALICE-NOTE-A').applicability = { applies: false, reason: 'synthetic exclusion' }; p.requiredControlIds = p.requiredControlIds.filter(id => id !== 'ALICE-NOTE-A'); }, /never sent, so it cannot capture/);
  // Placement: a whole path segment or query value, never a key; no malformed braces.
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').path = '/api/notes/x{{aliceNoteA}}/delete'; }, /must be a whole path segment/);
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').path = '/api/notes/delete?{{aliceNoteA}}=1'; }, /never a parameter name/);
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').path = '/api/notes/{{1aliceNoteA}}/delete'; }, /malformed \{\{name\}\} placeholder/);
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').body = { '{{aliceNoteA}}': true }; }, /never in a key/);
  // Preconditions: type, creator and use.
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').precondition = [{ name: 'aliceNoteA', type: 'integer', createdBy: 'alice' }]; }, /captured as id/);
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').precondition = [{ name: 'aliceNoteA', type: 'id', createdBy: 'admin' }]; }, /created by another actor than check "ALICE-NOTE-A"/);
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').precondition = [{ name: 'aliceNoteB', type: 'id', createdBy: 'alice' }]; }, /which this check does not use/);
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').precondition = [{ name: 'aliceNoteA', type: 'id' }]; }, /\{ name, type, createdBy \} and nothing else/);
  // Identity controls are re-sent by the identity proof, so they cannot use a capture.
  refuse(p => { p.checks.push({ ...check(p, 'BOB-WHOAMI'), id: 'BOB-WHOAMI-LATE', path: '/api/me?note={{aliceNoteA}}' }); p.requiredControlIds.push('BOB-WHOAMI-LATE'); }, /an identity control is re-sent/);
  // A filled body stays within the request limit.
  refuse(p => { check(p, 'CELL-MEMBER-BY-OWNER').body = { many: Array.from({ length: 41 }, () => '{{aliceNoteA}}') }; }, /could exceed 8192 bytes/);
  // Captures are part of the contract identity; the suite binds names, types, creators and preconditions, never pointers or values.
  const renamed = structuredClone(base); check(renamed, 'ALICE-NOTE-A').capture.aliceNoteA.pointer = '/note/id';
  assert.notEqual(contractDigest(base), contractDigest(renamed));
  const suite = suiteOf(base, {});
  assert.deepEqual(suite.checks.find(c => c.id === 'ALICE-NOTE-A').captures, [{ name: 'aliceNoteA', type: 'id' }]);
  assert.deepEqual(suite.checks.find(c => c.id === 'CELL-ADMIN-BY-MEMBER').captureUses, [{ name: 'adminNoteB', type: 'id', createdBy: 'admin', captureCheckId: 'ADMIN-NOTE-B' }]);
  assert.doesNotMatch(JSON.stringify(suite), /"\/id"|pointer/);
});

test('capture values: plain identifiers of the declared type only, filled as whole segments; a body value keeps its JSON type', () => {
  for (const [value, type, ok] of [['n-12', 'id', true], [12, 'id', true], [-1, 'id', false], ['..', 'id', false], ['a/b', 'id', false], ['a%2F', 'string', false], [12, 'string', false],
    ['x'.repeat(201), 'string', false], [12, 'integer', true], ['12', 'integer', false], [1.5, 'integer', false], [null, 'id', false], [{ id: 1 }, 'id', false]]) assert.equal(captureValueValid(value, type), ok, `${JSON.stringify(value)} ${type}`);
  const check = { path: '/api/notes/{{a}}/delete?by={{b}}', body: { note: '{{a}}', text: 'about {{a}}', count: '{{n}}', nested: ['{{b}}'] } };
  assert.deepEqual(captureUsesOf(check), ['a', 'b', 'n']);
  const filled = fillCaptures(check, new Map([['a', 'n-1'], ['b', 'u-bob'], ['n', 7]]));
  assert.deepEqual([filled.path, filled.body], ['/api/notes/n-1/delete?by=u-bob', { note: 'n-1', text: 'about n-1', count: 7, nested: ['u-bob'] }]);
});

test('creator versus actor allowed: every (creator role, actor role) cell of the clean build passes on values captured from their creators, which never enter the capture records', async t => {
  const { app, profile, run } = await assess(t);
  assert.deepEqual(CELLS.map(id => row(run, id).status), ['pass', 'pass', 'pass', 'pass', 'pass'], JSON.stringify(run.results.map(r => [r.id, r.status])));
  const capture = row(run, 'ADMIN-NOTE-B').trace[0].data.captures[0];
  assert.deepEqual([capture.name, capture.type, capture.createdBy, capture.outcome], ['adminNoteB', 'id', 'admin', 'captured']);
  assert.match(capture.valueDigest, /^[a-f0-9]{64}$/);
  const use = row(run, 'CELL-ADMIN-BY-MEMBER').trace[0].data.captureUses[0];
  assert.deepEqual(use, { name: 'adminNoteB', type: 'id', createdBy: 'admin', captureCheckId: 'ADMIN-NOTE-B', valueDigest: capture.valueDigest });
  // The request path hash is the declared template's, and no note id the app issued appears anywhere in the run.
  assert.equal(row(run, 'CELL-ADMIN-BY-MEMBER').trace[0].data.requestPathHash, digest('/api/notes/{{adminNoteB}}/delete'));
  assert.doesNotMatch(JSON.stringify(run), /"n-\d+"|\/n-\d+\//);
  assert.ok(run.limitations.includes(CAPTURE_LIMITATION));
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) }).exitCode, 0);
});

test('creator versus actor forbidden: a creator-dependent guard bypass fails from records, and only in its own cell', async t => {
  const { app, profile, run } = await assess(t, { creatorBypass: true });
  const bypass = row(run, 'CELL-ADMIN-BY-MEMBER');
  assert.deepEqual([bypass.trace[0].data.httpStatus, bypass.status, bypass.assertions.find(a => a.name.startsWith('Observed effect')).status], [200, 'fail', 'fail']);
  assert.deepEqual(CELLS.filter(id => id !== 'CELL-ADMIN-BY-MEMBER').map(id => row(run, id).status), ['pass', 'pass', 'pass', 'pass']);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) }).exitCode, 1);
});

test('creator versus actor missing observer: without an observer for the effect, no cell passes', async t => {
  const { app, profile, run } = await assess(t, {}, { observers: false });
  assert.deepEqual(CELLS.map(id => row(run, id).status), ['inconclusive', 'inconclusive', 'inconclusive', 'inconclusive', 'inconclusive']);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
});

test('creator versus actor failed control: a missed capture leaves every dependent check unsent and inconclusive, never pass', async t => {
  const { app, profile, run } = await assess(t, { createBroken: true });
  assert.equal(row(run, 'ADMIN-NOTE-B').status, 'fail');
  assert.equal(row(run, 'ADMIN-NOTE-B').trace[0].data.captures[0].outcome, 'absent');
  for (const id of CELLS) {
    const r = row(run, id);
    assert.deepEqual([r.status, r.trace[0].data.transportOutcome, r.trace[0].data.notSent], ['inconclusive', 'not-sent', 'capture-unavailable'], id);
    assert.match(r.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual, /was not captured/);
    assert.equal(r.trace[0].data.captureUses[0].valueDigest, null);
  }
  assert.equal(app.requests.filter(r => /\/delete$/.test(r.path)).length, 0, 'no dependent request was sent');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  assert.notEqual(summarizeGate({ candidate: run }).exitCode, 0);
});

test('a value created by an actor whose login is not proven cannot pass a dependent check', async () => {
  // Injected transport, no socket: the who-am-I route names the admin even without a credential, so the admin's login is not proven.
  const transport = async (origin, check, { credential }) => {
    const who = { 'tok-admin': 'admin', 'tok-bob': 'bob' }[credential];
    if (check.path === '/me') return { status: 200, complete: true, jsonParsed: true, json: { user: who ?? 'admin' }, bytes: 10 };
    if (check.path === '/notes') return { status: 201, complete: true, jsonParsed: true, json: { id: 'n-9' }, bytes: 10 };
    if (check.path === '/mine') return { status: credential ? 200 : 401, complete: true, jsonParsed: true, json: { items: [] }, bytes: 12 };
    return { status: 403, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  // BOB-MINE is bob's surface control (a protected-route GET): under the actor-identity/4 403 rule his refusal counts only after it.
  const profile = { id: 'unproven-creator', name: 'Unproven creator', applicationId: 'unproven', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { admin: { principalId: 'admin', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_B', identityValue: 'bob' } },
    requiredControlIds: ['ADMIN-ME', 'BOB-ME', 'BOB-MINE', 'ADMIN-NOTE'],
    checks: [
      { id: 'BOB-MINE', title: 'm', category: 'Allowed use', severity: 'control', actorId: 'bob', method: 'GET', path: '/mine', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'ADMIN-ME', title: 'a', category: 'Identity', severity: 'control', actorId: 'admin', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'admin' }] },
      { id: 'BOB-ME', title: 'b', category: 'Identity', severity: 'control', actorId: 'bob', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'bob' }] },
      { id: 'ADMIN-NOTE', title: 'n', category: 'Setup', severity: 'control', actorId: 'admin', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], capture: { note: { pointer: '/id', type: 'id' } } },
      { id: 'BOB-DELETE', title: 'd', category: 'Object access', severity: 'high', actorId: 'bob', method: 'POST', path: '/notes/{{note}}/delete', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], precondition: [{ name: 'note', type: 'id', createdBy: 'admin' }] },
    ] };
  const run = await runHttpAssessment(profile, { env: { SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_B: 'tok-bob' }, transport });
  assert.equal(run.identityEvidence.actors.find(a => a.actorId === 'admin').reason, 'not-refused-without-credential');
  assert.equal(run.identityEvidence.actors.find(a => a.actorId === 'bob').reason, 'established');
  const r = row(run, 'BOB-DELETE');
  assert.deepEqual(r.assertions.filter(a => a.status !== 'pass').map(a => a.name), [PRECONDITION_ASSERTION], 'only the creator rule withholds it');
  assert.equal(r.status, 'inconclusive');
  assert.match(r.assertions.find(a => a.name === PRECONDITION_ASSERTION).actual, /login of the actor that created a captured value was not proven/);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, {}) });
  // Dropping that assertion and restoring the pass is refused: the reason is recomputed from the identity evidence.
  const forged = structuredClone(run), f = row(forged, 'BOB-DELETE');
  f.assertions = f.assertions.filter(a => a.name !== PRECONDITION_ASSERTION); f.status = 'pass'; reseal(f);
  forged.counts = { ...forged.counts, pass: forged.counts.pass + 1, inconclusive: forged.counts.inconclusive - 1 };
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
});

test('capture evidence is recomputed: an edited digest, outcome, creator or not-sent reason is refused, and the suite binds captures and uses', async t => {
  const { app, profile, run } = await assess(t);
  const suite = suiteOf(profile, app.env);
  const edit = change => { const copy = structuredClone(run); change(copy); return copy; };
  const refused = (copy, why) => assert.throws(() => validateHttpRunEvidence(copy), /invalid-run-evidence/, why);
  refused(edit(c => { const r = row(c, 'CELL-ADMIN-BY-MEMBER'); r.trace[0].data.captureUses[0].valueDigest = digest('another value'); reseal(r); }), 'use digest');
  refused(edit(c => { const r = row(c, 'CELL-ADMIN-BY-MEMBER'); r.trace[0].data.captureUses[0].createdBy = 'alice'; reseal(r); }), 'use creator');
  refused(edit(c => { const r = row(c, 'ADMIN-NOTE-B'); Object.assign(r.trace[0].data.captures[0], { outcome: 'absent', valueDigest: null }); reseal(r); }), 'capture outcome');
  refused(edit(c => { const r = row(c, 'ADMIN-NOTE-B'); r.trace[0].data.captures[0].outcome = 'response-unavailable'; reseal(r); }), 'outcome against a complete response');
  refused(edit(c => { const r = row(c, 'ADMIN-NOTE-B'); delete r.trace[0].data.captures; reseal(r); }), 'capture dropped');
  refused(edit(c => { const r = row(c, 'CELL-ADMIN-BY-MEMBER'); r.trace[0].data.notSent = 'capture-unavailable'; reseal(r); }), 'a sent row relabelled not sent');
  // Removing the use from a sent row is internally consistent; the suite still names it.
  const unbound = edit(c => { const r = row(c, 'CELL-ADMIN-BY-MEMBER'); delete r.trace[0].data.captureUses; reseal(r); });
  validateHttpRunEvidence(unbound);
  assert.throws(() => validateHttpRunEvidence(unbound, { expectedSuite: suite }), e => e.code === 'unexpected-suite-evidence');
});

test('a capture is taken only from a response whose status assertion passed: an id in a refusal body is never used', async () => {
  // Injected transport, no socket: the create route refuses (403) but still names an id.
  const transport = async (origin, check) => check.path === '/notes' ? { status: 403, complete: true, jsonParsed: true, json: { id: 'n-7' }, bytes: 10 } : { status: 403, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  const profile = { id: 'refused-create', name: 'Refused create', applicationId: 'refused', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { anon: { principalId: 'anon' } }, requiredControlIds: ['CREATE'],
    checks: [
      { id: 'CREATE', title: 'c', category: 'Setup', severity: 'control', actorId: 'anon', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], capture: { note: { pointer: '/id', type: 'id' } } },
      { id: 'USE', title: 'u', category: 'Object access', severity: 'high', actorId: 'anon', method: 'DELETE', path: '/notes/{{note}}', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
    ] };
  const run = await runHttpAssessment(profile, { env: {}, transport });
  assert.deepEqual([row(run, 'CREATE').trace[0].data.captures[0].outcome, row(run, 'CREATE').trace[0].data.captures[0].valueDigest], ['status-not-matched', null]);
  assert.deepEqual([row(run, 'USE').status, row(run, 'USE').trace[0].data.notSent, row(run, 'USE').trace[0].data.method], ['inconclusive', 'capture-unavailable', 'DELETE']);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, {}) });
});

// ---------------------------------------------------------------------------
// A malformed capture pointer once passed profile validation, and the creating
// request was sent before it threw. Pointers are now parsed with the connector's own parser when the profile loads.
const pointerProfile = pointer => ({ id: 'pointer-check', name: 'Pointer check', applicationId: 'pointer', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { anon: { principalId: 'anon' } }, requiredControlIds: ['CREATE'],
  checks: [
    { id: 'CREATE', title: 'c', category: 'Setup', severity: 'control', actorId: 'anon', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], capture: { note: { pointer, type: 'id' } } },
    { id: 'USE', title: 'u', category: 'Object access', severity: 'high', actorId: 'anon', method: 'DELETE', path: '/notes/{{note}}', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] },
  ] });
test('a malformed capture pointer is refused when the profile loads, before any request is sent', async () => {
  for (const pointer of ['not-a-pointer', 'id', '/a~2b', '/a~', '/__proto__', '/x/constructor', `/${'a'.repeat(512)}`]) {
    assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [pointerProfile(pointer)] }), /check "CREATE": capture "note" needs a valid JSON pointer/, pointer);
    let calls = 0;
    await assert.rejects(runHttpAssessment(pointerProfile(pointer), { env: {}, transport: async () => { calls++; return { status: 201, complete: true, jsonParsed: true, json: { id: 'n-1' }, bytes: 8 }; } }), /needs a valid JSON pointer/, pointer);
    assert.equal(calls, 0, `${pointer}: no request was sent`);
  }
  for (const pointer of ['/id', '', '/a~1b', '/a~0b', '/items/0/id']) validateTargetFile({ schemaVersion: 1, targets: [pointerProfile(pointer)] });
});

// The capture digest key is fresh for every run, so the same captured value
// gives unrelated digests in two runs, and none of them is a keyless digest of the value.
test('the capture digest key is fresh per run: the same value never gives the same digest twice', async () => {
  const transport = async (origin, check) => ({ status: check.method === 'POST' ? 201 : 403, complete: true, jsonParsed: true, json: { id: 'n-1' }, bytes: 8 });
  const digests = [];
  for (let i = 0; i < 3; i++) {
    const run = await runHttpAssessment(pointerProfile('/id'), { env: {}, transport });
    const capture = row(run, 'CREATE').trace[0].data.captures[0];
    assert.equal(capture.outcome, 'captured');
    assert.equal(row(run, 'USE').trace[0].data.captureUses[0].valueDigest, capture.valueDigest, 'within one run the use matches its capture');
    digests.push(capture.valueDigest);
  }
  assert.equal(new Set(digests).size, 3);
  for (const keyless of [digest({ name: 'note', value: 'n-1' }), digest('n-1'), digest({ key: '00'.repeat(32), name: 'note', value: 'n-1' }), digest({ key: '', name: 'note', value: 'n-1' })]) assert.ok(!digests.includes(keyless));
});

// Privacy claim scope: the capture records never hold a captured value, but observer
// evidence keeps the resource identifiers the application reports, which can be that value. The claim is narrowed
// (docs, run limitation and module header) rather than tokenizing observer resources: matching a pinned resource
// and the observers' own unkeyed content digests would still carry the value.
test('the narrowed claim: capture records hold only a keyed digest, and every statement says observer evidence can hold the value', async () => {
  const { makeEffect } = await import('../src/effect-events.mjs');
  const { sealWindows } = await import('../src/http-effects.mjs');
  const { readFile } = await import('node:fs/promises');
  // The stated limit, pinned: an audit-file event keeps the literal request path it logged.
  const event = makeEffect({ source: 'file-audit-log', observer: { kind: 'audit-log-file', instanceId: 'audit-file-a' }, seq: 1, operation: 'delete', name: 'note.delete', resource: '/notes/n-1', outcome: 'committed' });
  const sealed = sealWindows([{ source: 'file-audit-log', instanceId: 'audit-file-a', scope: { operations: ['delete'], names: ['note.delete'], actorAttribution: 'principal', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [event] }], new Map([['audit-file-a', { kind: 'audit-log-file', settleMs: 300 }]]));
  assert.equal(sealed[0].events[0].resource, '/notes/n-1');
  const read = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  const statements = { 'docs/ONBOARDING.md': await read('docs/ONBOARDING.md'), 'SECURITY.md': await read('SECURITY.md'), 'src/http-captures.mjs': await read('src/http-captures.mjs'), CAPTURE_LIMITATION };
  for (const [where, text] of Object.entries(statements)) {
    assert.doesNotMatch(text, /A value is never stored|It never\s*(\/\/\s*)?enters evidence|The value is never stored/, where);
    assert.match(text.replace(/\s*\/\/\s*/g, ' '), /captured value|captured id/, where);
  }
  assert.match(statements['docs/ONBOARDING.md'], /Observer evidence is separate: an observer's events keep the resource identifiers the application reports/);
  assert.match(statements['SECURITY.md'], /but not out of observer evidence/);
  assert.match(CAPTURE_LIMITATION, /observer windows keep the resource identifiers the application reports/);
  assert.match(statements['src/http-captures.mjs'], /Observer evidence is separate and keeps what the application reports/);
});

// ---------------------------------------------------------------------------
// Probes shipped as assertions (a captured value's length, a query placeholder's place, a dependent row's creator login),
// and a surface control cannot use a captured value. Injected transport only.
import { PRECONDITION_REASONS, IDENTITY_ASSERTION } from '../src/contracts.mjs';
const reply2 = (status, json = {}) => ({ status, complete: true, jsonParsed: true, json, bytes: 2 });
const ctl2 = (id, actorId, path, extra = []) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId, method: 'GET', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, ...extra] });
const me2 = (id, actorId, value) => ctl2(id, actorId, '/me', [{ kind: 'json.equals', pointer: '/user', expected: value }]);
const base2 = id => ({ id, name: 'n', applicationId: id, origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic' });

test('a captured value longer than 200 characters is invalid, so its dependent check is not sent', async () => {
  assert.equal(captureValueValid('x'.repeat(200), 'id'), true);
  assert.equal(captureValueValid('x'.repeat(201), 'id'), false);
  assert.equal(captureValueValid('x'.repeat(201), 'string'), false);
  const p = { ...base2('rv-long'), actors: { anon: { principalId: 'anon' } }, requiredControlIds: ['CREATE'],
    checks: [{ id: 'CREATE', title: 'c', category: 'Setup', severity: 'control', actorId: 'anon', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], capture: { note: { pointer: '/id', type: 'id' } } },
      { id: 'USE', title: 'u', category: 'Boundary', severity: 'high', actorId: 'anon', method: 'DELETE', path: '/notes/{{note}}', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }] };
  const log = [];
  const run = await runHttpAssessment(p, { env: {}, transport: async (o, check) => { log.push(check.path); return check.id === 'CREATE' ? reply2(201, { id: 'x'.repeat(201) }) : reply2(403); } });
  assert.deepEqual([row(run, 'CREATE').trace[0].data.captures[0].outcome, row(run, 'USE').trace[0].data.transportOutcome, row(run, 'USE').status, log.length], ['invalid', 'not-sent', 'inconclusive', 1]);
  validateHttpRunEvidence(run);
});

test('a query placeholder must be a whole query value; one embedded in a value or used as a parameter name is refused when the profile loads', () => {
  const p = path => ({ ...base2('rv-query'), actors: { anon: { principalId: 'anon' } }, requiredControlIds: ['CREATE'],
    checks: [{ id: 'CREATE', title: 'c', category: 'Setup', severity: 'control', actorId: 'anon', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], capture: { note: { pointer: '/id', type: 'id' } } },
      { id: 'USE', title: 'u', category: 'Boundary', severity: 'high', actorId: 'anon', method: 'GET', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }] });
  validateTargetFile({ schemaVersion: 1, targets: [p('/notes?id={{note}}')] });
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p('/notes?id=x{{note}}')] }), /whole query value/);
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p('/notes?id={{note}}y')] }), /whole query value/);
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p('/notes?{{note}}=1')] }), /never a parameter name/);
});

test('an authentic run whose dependent row carries creator-login-unproven validates, the validator recomputes that reason, and restoring the pass is refused', async () => {
  const env = { SCOPEHAVEN_TARGET_ALICE: 'tok-alice', SCOPEHAVEN_TARGET_BOB: 'tok-bob' };
  const p = { ...base2('rv-creator2'), actors: { alice: { principalId: 'alice', credentialEnv: 'SCOPEHAVEN_TARGET_ALICE', identityValue: 'alice' }, bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } },
    requiredControlIds: ['ALICE-ME', 'ALICE-CREATE', 'BOB-ME', 'BOB-OWN'],
    checks: [me2('ALICE-ME', 'alice', 'alice'),
      { id: 'ALICE-CREATE', title: 'c', category: 'Setup', severity: 'control', actorId: 'alice', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }], capture: { note: { pointer: '/id', type: 'id' } } },
      me2('BOB-ME', 'bob', 'bob'), ctl2('BOB-OWN', 'bob', '/own'),
      { id: 'BOB-USE', title: 'u', category: 'Boundary', severity: 'high', actorId: 'bob', method: 'DELETE', path: '/notes/{{note}}', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }] };
  // Alice's identity route accepts any credential: her login is not proven (accepted-invalid-credential), a reason that holds for
  // every check of hers, the capturing check included (actor-identity/5 judges the creator at the capturing check).
  const run = await runHttpAssessment(p, { env, transport: async (origin, check, { credential }) => {
    if (check.path === '/me') return reply2(200, { user: credential === 'tok-bob' ? 'bob' : 'alice' });
    if (!['tok-alice', 'tok-bob'].includes(credential)) return reply2(401);
    if (check.method === 'POST') return reply2(201, { id: 7 });
    if (check.path.startsWith('/notes/')) return reply2(403);
    return reply2(200, { items: [] });
  } });
  assert.equal(run.identityEvidence.actors.find(a => a.actorId === 'alice').loginProven, false);
  const use = row(run, 'BOB-USE');
  assert.equal(use.assertions.find(a => a.name === PRECONDITION_ASSERTION)?.actual, PRECONDITION_REASONS['creator-login-unproven']);
  assert.deepEqual([use.status, use.decision, use.assertions.some(a => a.name === IDENTITY_ASSERTION)], ['inconclusive', 'inconclusive', false], 'the creator rule alone withholds it; bob\'s own identity is proven');
  assert.doesNotThrow(() => validateHttpRunEvidence(run, { expectedSuite: suiteOf(p, env) }));
  const forged = structuredClone(run), fu = row(forged, 'BOB-USE');
  fu.assertions = fu.assertions.filter(a => a.name !== PRECONDITION_ASSERTION); fu.status = 'pass'; fu.decision = 'pass'; reseal(fu);
  forged.counts = { ...forged.counts, pass: forged.counts.pass + 1, inconclusive: forged.counts.inconclusive - 1 };
  assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence');
});

test('a surface control cannot use a captured value (its probe points would re-send the raw placeholder), as an identity control cannot; a control that is not re-sent may', () => {
  const p = { ...base2('surface-capture'), actors: { member: { principalId: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member' } }, requiredControlIds: ['WHOAMI', 'OWN'],
    checks: [{ ...me2('WHOAMI', 'member', 'member'), capture: { who: { pointer: '/user', type: 'id' } } }, ctl2('OWN', 'member', '/notes/{{who}}'),
      { id: 'FOREIGN', title: 'f', category: 'Object access', severity: 'high', actorId: 'member', method: 'GET', path: '/foreign', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] }] };
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [p] }), /a surface control \(a required GET allowed-use control of a credentialed actor\) is re-sent by the identity proof, so it cannot use a captured value/);
  // Not required, so not a surface control: accepted.
  const plain = structuredClone(p); plain.requiredControlIds = ['WHOAMI'];
  validateTargetFile({ schemaVersion: 1, targets: [plain] });
  // Its identity-control counterpart is still refused with its own message.
  const identity = structuredClone(p); identity.checks[1] = me2('WHOAMI-2', 'member', 'member'); identity.checks[1].path = '/me/{{who}}'; identity.requiredControlIds = ['WHOAMI', 'WHOAMI-2'];
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [identity] }), /an identity control is re-sent by the identity proof/);
});
