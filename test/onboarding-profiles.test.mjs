// The onboarding example profiles (docs/profiles/) are real: each one validates,
// runs against the synthetic example app (examples/observed-support-app.mjs)
// and shows exactly what its evidence can and cannot establish, including the
// drills that a weaker profile would pass. Loopback, synthetic data and a
// fixed-text assistant only; no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateTargetFile, validateHttpRunEvidence, HTTP_WRITE_METHODS } from '../src/contracts.mjs';
import { compareRuns } from '../src/runner.mjs';
import { createObservedSupportApp, bindExampleProfile, MASKING_BUILDS } from '../examples/observed-support-app.mjs';

const DIR = new URL('../docs/profiles/', import.meta.url);
const load = async name => JSON.parse(await readFile(new URL(`${name}.example.json`, DIR), 'utf8'));
const row = (run, id) => run.results.find(r => r.id === id);
const effect = (r, n) => r.assertions.find(a => a.name.startsWith(`Observed effect ${n} `));
const AUDITED = ['sqlite-audit', 'http-audit'];
// The egress recorder reads the app's payment calls on the request path, a record the app cannot write.
const REQUEST_PATH = ['egress-recorder'];
const OBSERVED = [...AUDITED, 'sqlite-snapshot', ...REQUEST_PATH];
const ALL = [...OBSERVED, 'response-only'];
const B_PROHIBITIONS = ['B-NO-A-ORDER', 'B-NO-A-REFUND', 'AST-B-NO-A-DETAILS', 'AST-B-NO-A-REFUND'];
// Stated limit, pinned: a table snapshot cannot prove absence.
const ABSENCE_UNPROVEN = { 'sqlite-snapshot': ['B-NO-A-REFUND', 'AST-B-NO-A-REFUND'] };
// Custody (src/custody.mjs): an audit log is a record the app writes, so a refund prohibition whose
// absence only the app's own audit decides reads inconclusive (subject-writable-custody), never pass.
const CUSTODY_HELD = { 'sqlite-audit': ['B-NO-A-REFUND', 'AST-B-NO-A-REFUND'], 'http-audit': ['B-NO-A-REFUND', 'AST-B-NO-A-REFUND'] };
// Settlement (src/http-settlement.mjs): the egress example's host-wide clause (effect 1, no payment call
// at all) cannot be settled, because the same-action twins after each prohibition make payment calls that fit it, so
// either could be the prohibition's late effect. That clause reads inconclusive (effect-outside-window, custody still
// independent); the per-order clause (effect 2) passes. Correlation is by selector, not by request.
const SETTLEMENT_HELD = { 'egress-recorder': ['B-NO-A-REFUND', 'AST-B-NO-A-REFUND'] };
// Rows restored from the leaky build to the secure one. For the record-based examples, the disclosure only: the two
// refund prohibitions go from fail to inconclusive (custody holds the audit examples' at inconclusive; a snapshot cannot
// confirm a refund's absence), so those pairs are incomplete and carry no repair label. The egress recorder decides
// both payment calls on the request path, so they pass with independent custody (backend observed where marked). A
// refund row written without a payment call is not seen.
// Since settlement, the egress example's two refund prohibitions read inconclusive too (SETTLEMENT_HELD), so it restores the disclosure only.
const SECURE_FIXED = { 'sqlite-audit': 1, 'http-audit': 1, 'sqlite-snapshot': 1, 'egress-recorder': 1, 'response-only': 1 };
const SECURE_LABEL = { 'sqlite-audit': 'No verified repair', 'http-audit': 'No verified repair', 'sqlite-snapshot': 'No verified repair',
  'egress-recorder': 'No verified repair', 'response-only': 'Response contracts restored' };
const surface = c => c.path === '/api/assistant/chat' ? 'assistant' : 'direct';
// Write-shaped: any write method (POST, PUT, PATCH or DELETE) on a direct route, or an assistant turn that asks for a refund.
const writes = c => HTTP_WRITE_METHODS.includes(c.method) && (surface(c) === 'direct' || c.body?.action === 'refund');

// The app calls its payments API through an egress recorder only for a profile that declares one.
async function app(t, build, name = null) {
  const a = await createObservedSupportApp({ build, egress: REQUEST_PATH.includes(name) }); t.after(() => a.close());
  return a;
}
async function runOn(a, name) {
  const result = await runHttpAssessment(bindExampleProfile(await load(name), a).targets[0], { env: a.env });
  validateHttpRunEvidence(result);
  return result;
}

test('the write-shaped rule counts every write method on a direct route, and an assistant turn only when it asks for an action', () => {
  for (const method of HTTP_WRITE_METHODS) assert.equal(writes({ method, path: '/api/orders/1' }), true, method);
  assert.equal(writes({ method: 'GET', path: '/api/orders/1' }), false);
  assert.equal(writes({ method: 'POST', path: '/api/assistant/chat', body: { message: 'Order status?' } }), false);
  assert.equal(writes({ method: 'POST', path: '/api/assistant/chat', body: { action: 'refund' } }), true);
});

test('every example validates, is introduced in ONBOARDING and brackets each prohibition with same-action twins before and after it', async () => {
  assert.deepEqual((await readdir(DIR)).filter(n => n.endsWith('.example.json')).sort(), ALL.map(n => `${n}.example.json`).sort());
  const onboarding = await readFile(new URL('../docs/ONBOARDING.md', import.meta.url), 'utf8');
  for (const name of ALL) {
    const file = await load(name); validateTargetFile(file);
    const target = file.targets[0], checks = target.checks;
    assert.ok(onboarding.includes(`docs/profiles/${name}.example.json`), `${name} is introduced in ONBOARDING.md`);
    const twins = checks.filter(c => target.requiredControlIds.includes(c.id) && c.category !== 'Identity');
    const prohibitions = checks.filter(c => c.severity !== 'control' && c.actorId !== 'anonymous');
    for (const p of prohibitions) {
      // A twin of the same action (same actor, surface and kind) before AND after each
      // prohibition, so a refusal of that action that starts or stops partway through the
      // run still fails a required control.
      const same = twins.filter(c => c.actorId === p.actorId && surface(c) === surface(p) && writes(c) === writes(p)).map(c => checks.indexOf(c));
      assert.ok(same.some(i => i < checks.indexOf(p)), `${name} ${p.id}: a twin before it`);
      assert.ok(same.some(i => i > checks.indexOf(p)), `${name} ${p.id}: a twin after it`);
    }
    // Each pinned write twin has its own record, so one twin's late commit cannot satisfy another's.
    const pins = twins.flatMap(c => (c.effects ?? []).filter(e => e.select.resource !== undefined).map(e => `${e.select.actor}|${e.select.resource}`));
    assert.equal(new Set(pins).size, pins.length, `${name}: distinct twin pins`);
    // An assistant twin asserts a value only a real answer carries, not an echoed request field.
    for (const c of twins.filter(c => surface(c) === 'assistant')) assert.ok(c.assertions.some(a => a.kind === 'json.equals' && a.pointer === '/reply'), `${name} ${c.id}`);
    assert.ok(checks.filter(c => surface(c) === 'assistant').every(c => c.timeoutMs >= 1000), `${name}: a model turn gets its own request budget`);
    if (name === 'response-only') { assert.equal(target.observers, undefined); assert.ok(checks.every(c => !c.effects)); continue; }
    // Every write-shaped check declares effects.
    for (const c of checks.filter(writes)) assert.ok(c.effects?.length, `${name} ${c.id}`);
    const principals = target.observers[0].principals ?? [];
    for (const c of checks) {
      for (const [i, e] of (c.effects ?? []).entries()) {
        // A selector actor must be one of the observer's principal values, never a profile alias.
        if (e.select.actor !== undefined) assert.ok(principals.includes(e.select.actor), `${name} ${c.id} effect ${i + 1}`);
        // A presence check naming neither actor nor resource is table-wide. Placing it right
        // after a check that writes nothing rules out only that check: any earlier write that
        // commits after its own settle can still land in this window and satisfy it.
        if (e.kind !== 'effect.none' && e.select.actor === undefined && e.select.resource === undefined) assert.ok(!writes(checks[checks.indexOf(c) - 1]), `${name} ${c.id}`);
      }
    }
  }
});

test('secure build: every check passes except the stated limits; effect rows are backend observed only where an observer decided them', async t => {
  for (const name of ALL) {
    const result = await runOn(await app(t, 'secure', name), name);
    const unproven = ABSENCE_UNPROVEN[name] ?? [], held = CUSTODY_HELD[name] ?? [], settled = SETTLEMENT_HELD[name] ?? [];
    assert.deepEqual(result.results.filter(r => r.status !== 'pass').map(r => r.id).sort(), [...unproven, ...held, ...settled].sort(), name);
    for (const id of unproven) assert.match(effect(row(result, id), 1).actual, /^missing: .*net-only/);
    for (const id of held) {
      assert.equal(row(result, id).status, 'inconclusive', `${name} ${id}`);
      for (const a of row(result, id).assertions.filter(x => x.name.startsWith('Observed effect'))) assert.deepEqual([a.status, a.custody, a.custodyReason], ['inconclusive', 'subject-writable', 'subject-writable-custody'], `${name} ${id} ${a.name}`);
    }
    for (const r of result.results) {
      const declared = r.trace.some(x => x.type === 'effect-observation');
      assert.equal(r.backendEvidence, declared && !unproven.includes(r.id) ? 'observed' : 'unavailable', `${name} ${r.id}`);
    }
    // On the request path every clause that decided the refund prohibitions is independent of the app. The per-order clause
    // passes; the host-wide one is withheld by settlement (a twin after it makes a payment call that fits it), never failed.
    if (REQUEST_PATH.includes(name)) for (const id of ['B-NO-A-REFUND', 'AST-B-NO-A-REFUND']) {
      const effects = row(result, id).assertions.filter(x => x.name.startsWith('Observed effect'));
      assert.deepEqual(effects.map(a => [a.status, a.custody, a.custodyReason, a.settlement]), [['inconclusive', 'independent', undefined, 'effect-outside-window'], ['pass', 'independent', undefined, undefined]], `${name} ${id}`);
    }
    if (name !== 'response-only') for (const id of ['A-OWN-REFUND', 'B-OWN-REFUND', 'B-OWN-REFUND-AFTER', 'AST-B-OWN-REFUND-BEFORE', 'AST-B-OWN-REFUND']) assert.equal(row(result, id).backendEvidence, 'observed', `${name} ${id}`);
  }
});

test('leaky build: the observed profiles fail the refund the reply denied; response-only passes it on the response alone', async t => {
  for (const name of ALL) {
    const a = await app(t, 'leaky', name), result = await runOn(a, name);
    assert.equal(row(result, 'AST-B-NO-A-DETAILS').status, 'fail', name);
    assert.equal(row(result, 'B-NO-A-ORDER').status, 'pass', name);
    const direct = row(result, 'B-NO-A-REFUND');
    assert.equal(direct.assertions.find(x => x.name === 'HTTP status matches contract').status, 'pass', `${name}: the app answered 404`);
    assert.ok(a.refundCount() > 3, 'the leaky build committed the cross-company refunds');
    if (OBSERVED.includes(name)) {
      for (const id of ['B-NO-A-REFUND', 'AST-B-NO-A-REFUND']) {
        assert.equal(row(result, id).status, 'fail', `${name} ${id}`);
        assert.equal(effect(row(result, id), 1).status, 'fail', `${name} ${id}: effect 1 fails on its own`);
      }
    } else {
      assert.equal(direct.status, 'pass', name); assert.equal(direct.backendEvidence, 'unavailable', name);
      assert.equal(row(result, 'AST-B-NO-A-REFUND'), undefined, `${name} does not claim to observe the assistant's refund`);
    }
  }
});

test('leaky build audited under the order owner: the resource-scoped prohibition catches what the actor-scoped one misses', async t => {
  for (const name of AUDITED) {
    const result = await runOn(await app(t, 'leaky-owner-audit', name), name);
    for (const id of ['B-NO-A-REFUND', 'AST-B-NO-A-REFUND']) {
      const r = row(result, id);
      // No audit row names agent B, so the effect rules reach a pass; that absence rests on the app's own audit, so custody holds it.
      assert.deepEqual([effect(r, 1).status, effect(r, 1).custodyReason], ['inconclusive', 'subject-writable-custody'], `${name} ${id}: no audit row names agent B`);
      assert.equal(effect(r, 2).status, 'fail', `${name} ${id}: the Acme order was refunded`);
      assert.equal(r.status, 'fail', `${name} ${id}`);
    }
  }
});

// Compare candidates against one leaky baseline on the same app instance, so the pair is comparable.
async function compareFromLeaky(t, name, builds, check) {
  const a = await app(t, 'leaky', name), baseline = await runOn(a, name);
  for (const build of builds) {
    a.setBuild(build);
    const candidate = await runOn(a, name), comparison = compareRuns(baseline, candidate);
    assert.equal(comparison.compatible, true, `${name} ${build}: ${comparison.reasons.join(' ')}`);
    check(build, candidate, comparison);
  }
}

test('a refusal that starts partway through the run and hides a still-open leak is never reported as a fix', async t => {
  for (const name of ALL) await compareFromLeaky(t, name, MASKING_BUILDS, (build, candidate, comparison) => {
    assert.equal(comparison.controlsPass, false, `${name} ${build}`); assert.equal(comparison.summary.fixed, 0, `${name} ${build}`);
  });
});

test('on one app instance, a real repair compares as fixed and every lockout or hidden write compares as nothing fixed', async t => {
  const lockouts = name => ['refuse-b', 'assistant-refund-locked', 'suspend-b-writes', ...(AUDITED.includes(name) ? ['assistant-unaudited'] : [])];
  for (const name of ALL) await compareFromLeaky(t, name, ['secure', ...lockouts(name)], (build, candidate, comparison) => {
    if (build === 'secure') {
      assert.equal(comparison.controlsPass, true, name); assert.equal(comparison.summary.fixed, SECURE_FIXED[name], name);
      // The label says "backend observed" only when at least one restored row was observed, and a repair label only on a complete comparison.
      assert.equal(comparison.restorationLabel, SECURE_LABEL[name], name);
      return;
    }
    assert.equal(comparison.controlsPass, false, `${name} ${build}`); assert.equal(comparison.summary.fixed, 0, `${name} ${build}`);
    if (build === 'refuse-b') for (const id of B_PROHIBITIONS) if (row(candidate, id)) assert.notEqual(row(candidate, id).status, 'pass', `${name} ${id}`);
  });
});

test('an assistant that refuses everything but echoes the order id fails the assistant twins', async t => {
  for (const name of ALL) {
    const result = await runOn(await app(t, 'echo-refusal', name), name);
    for (const id of ['AST-A-OWN-ORDER', 'AST-B-OWN-ORDER', 'AST-B-OWN-REFUND-BEFORE', 'AST-B-OWN-ORDER-AFTER', 'AST-B-OWN-REFUND']) assert.equal(row(result, id).status, 'fail', `${name} ${id}`);
  }
});

test('the example app refuses foreign hosts and origins before logging, and bounds and checks request bodies', async t => {
  const { request } = await import('node:http');
  const a = await app(t, 'secure');
  const port = Number(new URL(a.origin).port), token = a.env.SCOPEHAVEN_TARGET_EXAMPLE_AGENT_A;
  const send = (path, { method = 'GET', headers = {}, body } = {}) => new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, headers: { Authorization: `Bearer ${token}`, ...headers } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject); req.end(body);
  });
  const logged = async () => (await readFile(a.auditLogPath, 'utf8')).split('\n').filter(Boolean).length;
  const before = await logged();
  assert.equal(await send('/api/me', { headers: { Host: 'evil.test' } }), 403);
  assert.equal(await send('/api/me', { headers: { Origin: 'http://evil.test' } }), 403);
  assert.equal(await logged(), before, 'refused before the request log');
  const json = { 'Content-Type': 'application/json' };
  assert.equal(await send('/api/assistant/chat', { method: 'POST', headers: json, body: 'null' }), 400);
  assert.equal(await send('/api/assistant/chat', { method: 'POST', headers: json, body: JSON.stringify({ message: 'x'.repeat(9000) }) }), 413);
  assert.equal(await send('/api/assistant/chat', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' }), 415);
  assert.equal(await send('/api/me'), 200, 'the app is still serving');
});

test('the egress example needs the app\'s payment client, and its pinned clauses catch a call to the wrong order or an undeclared path', async t => {
  // Binding the profile to an app without a payment client is refused before any run.
  const plain = await app(t, 'secure'), file = await load('egress-recorder');
  assert.throws(() => bindExampleProfile(file, plain), /create the app with \{ egress: true \}/);
  // A Globex refund that pays the next Globex order: the twins' per-order clauses fail, so the controls do not pass.
  const wrong = await runOn(await app(t, 'pay-wrong-order', 'egress-recorder'), 'egress-recorder');
  for (const id of ['B-OWN-REFUND', 'B-OWN-REFUND-AFTER']) assert.equal(effect(row(wrong, id), 1).status, 'fail', id);
  assert.equal(row(wrong, 'A-OWN-REFUND').status, 'pass', 'the only Acme order still pays itself');
  // A leaky build whose payment calls go to an undeclared path: the per-order clause sees nothing for A-1, and the
  // host-wide clause (no payment call at all in the window) is what fails the prohibition. The per-order clause does not
  // pass either: its twin (A-OWN-REFUND, the same selector) matched nothing in this build, so the selector was not shown
  // to select anything (src/http-pairing.mjs, selector-not-shown-to-match). A fail stays a fail.
  const offPath = await runOn(await app(t, 'leaky-off-path', 'egress-recorder'), 'egress-recorder');
  for (const id of ['B-NO-A-REFUND', 'AST-B-NO-A-REFUND']) {
    assert.deepEqual([effect(row(offPath, id), 1).status, effect(row(offPath, id), 2).status, effect(row(offPath, id), 2).pairing, row(offPath, id).status], ['fail', 'inconclusive', 'selector-not-shown-to-match', 'fail'], id);
  }
});
