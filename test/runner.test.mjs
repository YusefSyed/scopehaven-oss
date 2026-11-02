import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, request } from 'node:http';
import { randomUUID } from 'node:crypto';
import { runAssessment, compareRuns, evaluateCheck, boundedJSON } from '../src/runner.mjs';
import { createFixture } from '../src/fixture.mjs';
import { createStore } from '../src/store.mjs';
import { CHECKS, SUITE, digest } from '../src/suite.mjs';
import { startServer } from '../src/server.mjs';
import { renderReport } from '../src/report.mjs';

// Every target created below is owned loopback HTTP. There are no model,
// provider, hosted database, production or external network dependencies.
const baseline = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const definition = id => CHECKS.find(c => c.id === id);
const result = (run, id) => run.results.find(c => c.id === id);
const copy = value => structuredClone(value);
function laterAttempt(previous, template) {
  const attempt = copy(template), requestId = randomUUID();
  attempt.requestId = requestId; attempt.manifest = copy(previous.manifest);
  Object.assign(attempt.evidence, { requestId, instanceId: attempt.manifest.instanceId, buildHash: attempt.manifest.buildHash,
    before: copy(previous.evidence.after), after: copy(previous.evidence.after) });
  attempt.evidence.output.requestId = requestId;
  return attempt;
}
async function dir(t) { const d = await mkdtemp(join(tmpdir(), 'scopehaven-test-')); t.after(() => rm(d, { recursive: true, force: true })); return d; }
async function localServer(t, handler) {
  const server = createServer(handler); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const accessForOrigin = new Map();
function raw(origin, path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(`${origin}${path}`, { method, headers: { ...(accessForOrigin.has(origin) ? { Authorization: `Bearer ${accessForOrigin.get(origin)}` } : {}), ...headers, ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}) } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString('utf8') }));
    }); req.on('error', reject); req.setTimeout(5000, () => req.destroy(new Error('Local test timeout.'))); req.end(body);
  });
}
const postHeaders = { 'Content-Type': 'application/json', 'X-Scopehaven-Request': '1' };

test('real HTTP baseline exposes twenty-one flaws; repaired build preserves all thirteen permitted controls', () => {
  assert.deepEqual(baseline.counts, { pass: 18, fail: 26, inconclusive: 0, error: 0 });
  assert.deepEqual(repaired.counts, { pass: 44, fail: 0, inconclusive: 0, error: 0 });
  for (const r of repaired.results) assert.equal(r.attempts.every(a => a.evidence.complete), true);
  const compare = compareRuns(baseline, repaired);
  assert.equal(compare.compatible, true); assert.equal(compare.controlsPass, true);
  assert.deepEqual(compare.summary, { fixed: 26, stillFailing: 0, newFailures: 0, preservedPasses: 18, unverified: 0 });
  assert.notEqual(baseline.targetBuildHash, repaired.targetBuildHash);
});
test('a refusal message cannot hide an executed export', () => {
  const r = result(baseline, 'UNTRUSTED-01');
  assert.equal(r.attempts[0].evidence.output.reply, 'I cannot share customer data.');
  assert.equal(r.attempts[0].evidence.after.exports.length, 1);
  assert.equal(r.status, 'fail');
});
test('trajectory retains a confirmed export after later denial, refusal or unavailable evidence', async t => {
  const first = copy(result(baseline, 'UNTRUSTED-01').attempts[0]);
  assert.equal(first.evidence.after.exports.length, 1);
  assert(first.evidence.events.some(e => e.type === 'tool' && e.data.name === 'export-records' && e.data.executed === true));
  const endings = [
    ['denial', a => { a.evidence.output.reply = 'Access denied.'; }],
    ['refusal', () => {}],
    ['missing evidence', a => { a.evidence = null; }],
    ['incomplete evidence', a => { a.evidence.complete = false; }],
    ['unmatched evidence', a => { a.evidence.requestId = randomUUID(); }],
    ['transport failure', a => { a.evidence = null; a.transportError = 'Synthetic timeout after earlier export.'; }],
  ];
  for (const [name, mutate] of endings) await t.test(name, () => {
    const later = laterAttempt(first, result(repaired, 'UNTRUSTED-01').attempts[0]);
    assert.notEqual(later.requestId, first.requestId);
    assert.deepEqual(later.evidence.before, first.evidence.after);
    assert.deepEqual(later.evidence.after, first.evidence.after);
    mutate(later);
    assert.equal(evaluateCheck(definition('UNTRUSTED-01'), [first, later]).status, 'fail');
  });
});
test('trajectory permits consecutive clean export denials without an earlier effect', () => {
  const first = copy(result(repaired, 'UNTRUSTED-01').attempts[0]);
  const later = laterAttempt(first, first);
  assert.equal(first.evidence.after.exports.length, 0);
  assert.equal(evaluateCheck(definition('UNTRUSTED-01'), [first, later]).status, 'pass');
});
test('trajectory preserves earlier prohibited observations across the other named checks', async t => {
  for (const id of ['TENANT-01', 'ROLE-01', 'APPROVAL-01', 'FIELD-01', 'CONTEXT-01', 'APPROVAL-03', 'APPROVAL-04', 'APPROVAL-05', 'FLOW-01', 'BUDGET-01', 'REVOKE-01', 'APPROVAL-06']) {
    await t.test(id, () => {
      const attempts = copy(result(baseline, id).attempts);
      assert.equal(evaluateCheck(definition(id), attempts).status, 'fail');
      const later = laterAttempt(attempts.at(-1), result(repaired, id).attempts.at(-1));
      later.evidence = null; attempts.push(later);
      assert.equal(evaluateCheck(definition(id), attempts).status, 'fail');
    });
  }
});
test('trajectory exempts only the initial permitted warm read and approved refund', () => {
  for (const id of ['REVOKE-01', 'APPROVAL-06']) {
    const attempts = copy(result(repaired, id).attempts);
    if (id === 'REVOKE-01') assert.match(attempts[0].evidence.output.reply, /ASTER-SYNTHETIC-731/);
    else assert.equal(attempts[0].evidence.after.refunds.length, 1);
    attempts.push(laterAttempt(attempts.at(-1), attempts.at(-1)));
    assert.equal(evaluateCheck(definition(id), attempts).status, 'pass', id);
    // A subsequent correlated prohibited event must survive even if the final
    // denial's snapshot does not independently expose the earlier effect.
    const prohibited = laterAttempt(attempts[0], result(baseline, id).attempts.at(-1));
    attempts.splice(1, 0, prohibited);
    assert.equal(evaluateCheck(definition(id), attempts).status, 'fail', id);
  }
});
test('missing, stale, nonterminal and wrong-actor evidence cannot pass', () => {
  for (const mutate of [a => { a.evidence = null; }, a => { a.evidence.instanceId = randomUUID(); }, a => { a.evidence.requestId = randomUUID(); }, a => { a.evidence.actor.principalId = 'admin-aster'; }, a => { a.evidence.complete = false; }]) {
    const attempts = copy(result(repaired, 'TENANT-01').attempts); mutate(attempts[0]);
    assert.equal(evaluateCheck(definition('TENANT-01'), attempts).status, 'inconclusive');
  }
});
test('confirmed prohibited effects remain failures after incomplete evidence or a transport error', () => {
  const attempts = copy(result(baseline, 'UNTRUSTED-01').attempts);
  attempts[0].evidence.complete = false; attempts[0].transportError = 'Synthetic timeout after effect.';
  assert.equal(evaluateCheck(definition('UNTRUSTED-01'), attempts).status, 'fail');
});
test('missing evidence with only a transport failure is an error, not a pass', () => {
  const attempts = copy(result(repaired, 'TENANT-01').attempts); attempts[0].evidence = null; attempts[0].transportError = 'Synthetic transport failure.';
  assert.equal(evaluateCheck(definition('TENANT-01'), attempts).status, 'error');
});
test('changed suite, policy, fixture, evaluator and application prevent verified closure', () => {
  for (const key of ['suiteHash', 'policyHash', 'fixtureHash', 'evaluatorHash', 'applicationId', 'adapterVersion']) {
    const candidate = copy(repaired); candidate[key] += '-changed'; const comparison = compareRuns(baseline, candidate);
    assert.equal(comparison.compatible, false); assert.equal(comparison.summary.fixed, 0);
    assert(comparison.rows.every(r => r.transition === 'incompatible'));
  }
});
test('unsupported evidence origins cannot inherit synthetic repair or backend labels', () => {
  for (const evidenceOrigin of ['unregistered-local-adapter', 'external-tool-claims', '__proto__', 'constructor']) {
    const before = { ...copy(baseline), evidenceOrigin }, after = { ...copy(repaired), evidenceOrigin };
    const comparison = compareRuns(before, after);
    assert.equal(comparison.compatible, false);
    assert.equal(comparison.summary.fixed, 0);
    assert(comparison.rows.every(row => row.transition === 'incompatible'));
    assert.equal(comparison.restorationLabel, 'Unverified changes');
    assert.match(comparison.evidenceScope, /Unsupported evidence origin/);
    assert.doesNotMatch(comparison.evidenceScope, /Owned synthetic backend/);
  }
});
test('matching contradictory producer metadata and cross-family payloads cannot authorize comparisons', () => {
  const mutations = [
    run => { run.applicationId = 'another-producer'; },
    run => { run.runtimeMode = 'configured-local-application'; },
    run => { run.adapterVersion = 'another-adapter'; },
    run => { run.assertionSchemaVersion = null; },
    run => { run.contextId = null; },
    run => { run.profileHash = null; },
    run => { run.requiredControlIds = ['ALLOWED-01']; },
    run => { run.fixtureVersion = 'support-fixture/99'; },
    run => { run.targetId = 'unknown-target'; },
    run => { run.provenance = {}; },
    run => { delete run.results[0].attempts; },
    run => { run.results[0].attempts = []; },
    run => { run.results[0].attempts[0].manifest.applicationId = 'another-producer'; },
  ];
  for (const mutate of mutations) {
    const before = copy(baseline), after = copy(repaired); mutate(before); mutate(after);
    const comparison = compareRuns(before, after);
    assert.equal(comparison.compatible, false); assert.equal(comparison.summary.fixed, 0);
    assert.equal(comparison.restorationLabel, 'Unverified changes');
  }
});
// Object.hasOwn coerces its key, so a fixture version that is an array or an object naming a known family
// would be treated as that family by the synthetic lookup. The family check now requires a string; the pair stays incompatible
// either way (the producer-family check already refuses it), and this pins both the refusal and its reason.
test('a non-string fixture version is never a recognized synthetic family and the pair is not comparable', () => {
  for (const fixtureVersion of [[baseline.fixtureVersion], { toString: () => baseline.fixtureVersion }]) {
    const before = { ...copy(baseline), fixtureVersion }, after = { ...copy(repaired), fixtureVersion };
    const comparison = compareRuns(before, after);
    assert.equal(comparison.compatible, false); assert.equal(comparison.summary.fixed, 0);
    assert.equal(comparison.restorationLabel, 'Unverified changes');
    assert.ok(comparison.reasons.includes('Evidence origin does not match its producer family or observations.'), JSON.stringify(comparison.reasons));
    assert.equal(comparison.evidenceScope.includes('Owned synthetic backend'), false);
  }
});
test('recognized legacy-shaped comparison records use the three version-one controls without rewriting inputs', () => {
  const legacy = run => {
    const shaped = copy(run); shaped.fixtureVersion = 'support-fixture/1'; shaped.results = shaped.results.slice(0, 8); shaped.checksTotal = 8;
    shaped.counts = Object.fromEntries(['pass', 'fail', 'inconclusive', 'error'].map(status => [status, shaped.results.filter(row => row.status === status).length]));
    for (const row of shaped.results) {
      for (const attempt of row.attempts) attempt.manifest.fixtureVersion = shaped.fixtureVersion;
      row.evidenceDigest = digest(row.attempts);
    }
    for (const field of ['assertionSchemaVersion', 'contextId', 'profileHash', 'requiredControlIds']) delete shaped[field];
    return shaped;
  };
  const before = legacy(baseline), after = legacy(repaired), snapshot = JSON.stringify([before, after]);
  const comparison = compareRuns(before, after);
  assert.equal(comparison.compatible, true); assert.equal(comparison.controlsPass, true);
  assert.equal(comparison.summary.fixed, 5); assert.equal(comparison.summary.preservedPasses, 3);
  assert.equal(JSON.stringify([before, after]), snapshot);
  after.assertionSchemaVersion = null; assert.equal(compareRuns(before, after).compatible, false);
});
test('deny-all controls block verification even when forbidden cases appear repaired', () => {
  const candidate = copy(repaired); result(candidate, 'ALLOWED-01').status = 'fail';
  const comparison = compareRuns(baseline, candidate);
  assert.equal(comparison.compatible, true); assert.equal(comparison.controlsPass, false); assert.equal(comparison.summary.fixed, 0);
  assert.equal(comparison.summary.newFailures, 1); assert.equal(comparison.rows.find(r => r.id === 'TENANT-01').transition, 'blocked-by-controls');
});
test('inconclusive-to-pass is new evidence, not a verified repair', () => {
  const before = copy(baseline); result(before, 'TENANT-01').status = 'inconclusive';
  assert.equal(compareRuns(before, repaired).rows.find(r => r.id === 'TENANT-01').transition, 'unverified');
});
test('tokens never enter saved run evidence', async () => {
  const credentials = [];
  const run = await runAssessment('demo-repaired', { fixtureFactory: async build => { const f = await createFixture(build); credentials.push(f.controlToken, ...Object.values(f.actorTokens)); return f; } });
  const serialized = JSON.stringify(run); for (const credential of credentials) assert.equal(serialized.includes(credential), false);
});
test('append-only runs survive restart; note edits do not mutate evidence or verdicts', async t => {
  const directory = await dir(t); const store = createStore(directory); const saved = await store.save(baseline);
  await assert.rejects(store.save(baseline));
  await Promise.all([store.note(baseline.id, 'TENANT-01', '<script>alert(1)</script>'), store.note(baseline.id, 'ROLE-01', 'Second note')]);
  const loaded = await createStore(directory).get(baseline.id);
  assert.equal(loaded.integrity.sha256, saved.integrity.sha256); assert.equal(loaded.results[0].status, 'fail');
  assert.equal(loaded.notes['ROLE-01'].note, 'Second note'); assert.match(loaded.notes['TENANT-01'].note, /<script>/);
  const html = renderReport(loaded); assert(!html.includes('<script>alert(1)</script>')); assert(html.includes('&lt;script&gt;'));
  await assert.rejects(store.note(baseline.id, '__proto__', 'bad'));
  await assert.rejects(store.note(baseline.id, 'TENANT-01', 'x'.repeat(5001)));
});
test('tampered run and unknown schema fail integrity validation; unpublished temp file is ignored', async t => {
  const directory = await dir(t); const store = createStore(directory); await store.save(baseline);
  await writeFile(join(directory, 'runs', '.interrupted.tmp'), '{'); assert.equal((await store.list()).length, 1);
  const file = join(directory, 'runs', `${baseline.id}.json`); const original = JSON.parse(await readFile(file, 'utf8'));
  original.core.results[0].status = 'pass'; await writeFile(file, JSON.stringify(original));
  await assert.rejects(store.get(baseline.id), /integrity/);
  original.core = { ...baseline, schemaVersion: 99 }; original.sha256 = digest(original.core);
  await writeFile(file, JSON.stringify(original)); await assert.rejects(store.get(baseline.id), /integrity/);
});
test('bounded HTTP adapter rejects remote URLs, redirects, oversized and malformed evidence', async t => {
  await assert.rejects(boundedJSON('https://example.com/', { credential: 'synthetic' }), /loopback/);
  let destinationHits = 0; const destination = await localServer(t, (_, res) => { destinationHits++; res.end('{}'); });
  const source = await localServer(t, (req, res) => {
    if (req.url === '/redirect') { res.writeHead(302, { Location: destination }); return res.end(); }
    if (req.url === '/large') return res.end('x'.repeat(20000));
    if (req.url === '/never') return;
    res.end('not-json');
  });
  await assert.rejects(boundedJSON(`${source}/redirect`, { credential: 'synthetic' })); assert.equal(destinationHits, 0);
  await assert.rejects(boundedJSON(`${source}/large`, { credential: 'synthetic', maxBytes: 1024 }), /limit/);
  await assert.rejects(boundedJSON(`${source}/broken`, { credential: 'synthetic' }), /malformed/);
  await assert.rejects(boundedJSON(`${source}/never`, { credential: 'synthetic', timeout: 20 }));
});
test('web API persists runs, compares, exports and protects local boundaries', async t => {
  const app = await startServer({ port: 0, dataDir: await dir(t) }); t.after(() => app.close()); accessForOrigin.set(app.origin, app.accessToken);
  const first = await raw(app.origin, '/api/bootstrap'); assert.equal(first.status, 200); assert.deepEqual(JSON.parse(first.text).runs, []);
  assert.match(first.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.equal((await raw(app.origin, '/api/bootstrap', { headers: { Host: 'attacker.example' } })).status, 403);
  assert.equal((await raw(app.origin, '/api/bootstrap', { headers: { Origin: 'https://attacker.example' } })).status, 403);
  assert.equal((await raw(app.origin, '/api/runs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 403);
  assert.equal((await raw(app.origin, '/api/runs', { method: 'POST', headers: postHeaders, body: JSON.stringify({ targetId: 'demo-repaired', url: 'https://example.com' }) })).status, 400);
  assert.equal((await raw(app.origin, '/api/runs', { method: 'POST', headers: postHeaders, body: JSON.stringify({ targetId: 'demo-repaired', extra: 'x'.repeat(20000) }) })).status, 413);
  const a = JSON.parse((await raw(app.origin, '/api/runs', { method: 'POST', headers: postHeaders, body: '{"targetId":"demo-vulnerable"}' })).text);
  const b = JSON.parse((await raw(app.origin, '/api/runs', { method: 'POST', headers: postHeaders, body: '{"targetId":"demo-repaired"}' })).text);
  assert.equal(a.counts.fail, 26); assert.equal(b.counts.pass, 44);
  const compare = JSON.parse((await raw(app.origin, `/api/compare?baseline=${a.id}&candidate=${b.id}`)).text); assert.equal(compare.summary.fixed, 26);
  assert.equal((await raw(app.origin, `/api/runs/${a.id}/notes`, { method: 'POST', headers: postHeaders, body: '{"caseId":"TENANT-01","note":"Reviewed","status":"pass"}' })).status, 400);
  const exported = await raw(app.origin, `/api/runs/${b.id}/export.json`); assert.equal(exported.status, 200); assert.match(exported.headers['content-disposition'], /attachment/);
  assert.equal(JSON.parse(exported.text).integrity.sha256, b.integrity.sha256);
  const report = await raw(app.origin, `/api/runs/${b.id}/report.html`); assert(report.text.includes('No live language model')); assert(!report.text.includes('<script'));
  assert.equal(JSON.parse((await raw(app.origin, '/api/suite/export.json')).text).hash, SUITE.hash);
  assert.equal((await raw(app.origin, '/api/runs/%2e%2e%2f%2e%2e%2fAGENTS.md')).status, 400);
});
test('concurrent web assessments cannot overlap and failure releases the slot', async t => {
  let release, entered; const barrier = new Promise(resolve => { release = resolve; }); const started = new Promise(resolve => { entered = resolve; }); let calls = 0;
  const app = await startServer({ port: 0, dataDir: await dir(t), assess: async () => { calls++; entered(); await barrier; throw new Error('Synthetic harness failure.'); } }); t.after(() => app.close()); accessForOrigin.set(app.origin, app.accessToken);
  const pending = raw(app.origin, '/api/runs', { method: 'POST', headers: postHeaders, body: '{"targetId":"demo-repaired"}' });
  await started;
  const overlap = await raw(app.origin, '/api/runs', { method: 'POST', headers: postHeaders, body: '{"targetId":"demo-repaired"}' }); assert.equal(overlap.status, 409);
  release(); assert.equal((await pending).status, 500);
  const next = await raw(app.origin, '/api/runs', { method: 'POST', headers: postHeaders, body: '{"targetId":"demo-repaired"}' }); assert.equal(next.status, 500); assert.equal(calls, 2);
});
