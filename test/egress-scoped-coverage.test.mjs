// Destination-scoped egress partial reasons, the follow rule, and the collector record.
// Over real loopback HTTP; destination hosts are names only and are never resolved or contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { createEgressRecorder } from '../integrations/observers/egress-recorder.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { collectWindow, evaluateEffectAssertion, coverageFor, unfollowedLate, admitScoped, markUnfollowed } from '../src/effect-events.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { COLLECTOR_RECORDS, COLLECTOR_FILES, collectorDigest } from '../src/collector-identity.mjs';

const PAY = 'pay.example.test', HOOK = 'hooks.example.test', WITNESS = 'witness.scopehaven.invalid';
const sink = (t, extra = {}) => onFreePorts(1, async port => {
  const o = createEgressRecorder({ instanceId: 'egress-recorder-sink', port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1'] }, { host: HOOK }],
    witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, ...extra });
  await o.start(); t.after(() => o.stop()); return o;
});
const send = (port, host, path, headers = {}) => new Promise(resolve => {
  const req = request({ host: '127.0.0.1', port, method: 'POST', path: `http://${host}${path}`, headers: { host, 'content-type': 'application/json', ...headers } }, res => { res.resume(); res.on('end', resolve); });
  req.on('error', resolve); req.end('{}');
});
// One check window: `during` before the witness request, `late` after it; collected scoped (as the connector does) or v1.
async function windowOf(o, { during = async () => {}, late = async () => {}, scoped = true } = {}) {
  const from = await o.mark(); await during(); o.markWitnessRequest(from);
  await late();
  await new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'GET', path: `http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(from.witnessNonce)}`, headers: { host: WITNESS } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(); });
  return collectWindow(o, from, await o.mark(), { scoped });
}
const none = name => ({ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name } });
const exists = name => ({ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name } });
const judge = (assertion, w, scoped = true) => evaluateEffectAssertion(assertion, [w], { scoped }).verdict;

test('an after-witness send to another declared host is scoped to that host: absence and fails decide elsewhere once followed, never through a fitting entry', async t => {
  const o = await sink(t);
  const w = await windowOf(o, { late: () => send(o.port, HOOK, '/x') });
  assert.deepEqual([w.coverage, w.reason, w.scoped], ['partial', 'egress-request-after-witness-request', [{ name: HOOK, resource: 'POST *', codes: ['egress-request-after-witness-request'] }]]);
  assert.equal(judge(none(PAY), w), 'pass', 'the late send cannot be a send to PAY');
  assert.equal(judge(none(HOOK), w), 'missing', 'a fitting entry keeps the window partial');
  // A fail reads through a non-fitting late entry too, once the follow rule found it followed; unfollowed, it does not.
  assert.equal(judge(exists(PAY), w), 'fail', 'a fail reads through a followed late entry on another host');
  assert.equal(judge(exists(PAY), markUnfollowed(admitScoped({ ...w }))), 'missing', 'adjacent: the same window unfollowed');
  assert.equal(judge(exists(HOOK), w), 'missing', 'adjacent: a fail on the late entry\'s own host');
  assert.equal(coverageFor(w, { source: 'http-egress', operation: 'send' }, { outcome: 'pass' }), 'partial', 'a nameless selector is fitted by every entry');
  assert.equal(judge(none(PAY), w, false), 'missing', 'without the opt-in the window is window-wide');
  const count = expected => ({ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: PAY }, expected });
  assert.equal(judge(count(0), w), 'pass', 'a count that would pass reads through the late entry on another host');
  assert.equal(judge(count(1), w), 'fail', 'a count that would fail reads through the followed late entry on another host');
  assert.equal(judge(count(1), markUnfollowed(admitScoped({ ...w }))), 'missing', 'adjacent: unfollowed');
  const v1 = await windowOf(o, { late: () => send(o.port, HOOK, '/x'), scoped: false });
  assert.equal(Object.hasOwn(v1, 'scoped'), false, 'v1 collect is unchanged');
  assert.equal(v1.reason, 'egress-request-after-witness-request');
});

test('ineligible units stay window-wide: an undeclared host, a host mismatch, a close in the window', async t => {
  const o = await sink(t, { replies: [{ host: PAY, path: '/v1/declined', status: 402, json: { error: 'declined' } }] });
  const undeclared = await windowOf(o, { late: () => send(o.port, 'other.example.test', '/x') });
  assert.equal(Object.hasOwn(undeclared, 'scoped'), false);
  assert.match(undeclared.reason, /egress-scope-ineligible/);
  assert.equal(judge(none(PAY), undeclared), 'missing');
  const mismatch = await windowOf(o, { late: () => new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'POST', path: `http://${HOOK}/x`, headers: { host: PAY } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end('{}'); }) });
  assert.match(mismatch.reason, /egress-host-mismatch/);
  assert.equal(judge(none(PAY), mismatch), 'missing');
  // A 402 reply closes its connection (Connection: close): bytes written after it could be lost, so nothing in the window is scoped.
  const closed = await windowOf(o, { during: () => send(o.port, PAY, '/v1/declined'), late: () => send(o.port, HOOK, '/x') });
  assert.match(closed.reason, /egress-scope-ineligible/);
  assert.equal(judge(none(HOOK), closed), 'missing');
});

test('a path whose raw and decoded forms disagree is scoped with resource null: its host reads partial, other hosts decide', async t => {
  const o = await sink(t);
  const w = await windowOf(o, { during: () => send(o.port, PAY, '/v1%2Fx/%ZZ') });
  if (w.scoped) {
    assert.deepEqual(w.scoped.map(e => [e.name, e.resource, e.codes]), [[PAY, null, ['egress-path-ambiguous']]]);
    assert.equal(judge({ ...none(PAY), select: { ...none(PAY).select, resource: 'POST /v1' } }, w), 'missing', 'any resource on the host');
    assert.equal(judge(none(HOOK), w), 'pass');
  } else assert.equal(w.coverage === 'complete' || /egress-path-ambiguous|egress-scope-ineligible/.test(w.reason), true, JSON.stringify(w.reason));
});

test('coverageFor reads only admitted windows; a copy or a forged field is window-wide', async t => {
  const o = await sink(t);
  const w = await windowOf(o, { late: () => send(o.port, HOOK, '/x') });
  assert.equal(coverageFor(w, none(PAY).select, { outcome: 'pass' }), 'complete');
  assert.equal(coverageFor({ ...w }, none(PAY).select, { outcome: 'pass' }), 'partial', 'a spread copy is not admitted');
  const forged = { ...w, scoped: [{ name: HOOK, resource: 'POST *', codes: ['egress-request-after-witness-request'] }] };
  assert.equal(coverageFor(forged, none(PAY).select, { outcome: 'pass' }), 'partial');
  assert.equal(coverageFor(admitScoped({ ...w, reason: 'egress-request-after-witness-request,egress-collect-late' }), none(PAY).select, { outcome: 'pass' }), 'partial', 'reason must equal the entries exactly');
  // An entry is what the recorder writes, a declared host of the window and "METHOD /path" or "METHOD *", in its order.
  const after = 'egress-request-after-witness-request', entry = (name, resource) => ({ name, resource, codes: [after] });
  assert.equal(coverageFor(admitScoped({ ...w, scoped: [entry(HOOK, 'POST *')] }), none(PAY).select, { outcome: 'pass' }), 'complete', 'the adjacent allowed entry');
  for (const [scoped, why] of [[[entry('elsewhere.example.test', 'POST *')], 'an undeclared host'], [[entry(HOOK, 'post *')], 'a lower-case method'], [[entry(HOOK, 'POST v1')], 'a path without a slash'],
    [[entry(HOOK, 'POST /a b')], 'white space in the path'], [[entry(PAY, 'POST /v1'), entry(HOOK, 'POST *')], 'out of the recorder\'s order'], [[entry(HOOK, 'POST /x'), entry(HOOK, 'POST *')], 'resources out of order']])
    assert.equal(coverageFor(admitScoped({ ...w, scoped }), none('third.example.test').select, { outcome: 'pass' }), 'partial', why);
});

test('the follow rule: an after-witness entry is followed by a later collected window of the same recorder; an in-flight entry never', () => {
  const late = (id, code) => ({ source: 'http-egress', instanceId: id, coverage: 'partial', reason: code, scoped: [{ name: HOOK, resource: 'POST *', codes: [code] }], events: [] });
  const clean = id => ({ source: 'http-egress', instanceId: id, coverage: 'complete', reason: null, events: [] });
  const after = 'egress-request-after-witness-request', inflight = 'egress-request-in-flight';
  assert.deepEqual(unfollowedLate([[late('a', after)], [clean('a')]]).map(s => [...s]), [[], []]);
  assert.deepEqual(unfollowedLate([[late('a', after)]]).map(s => [...s]), [['a']], 'the last check');
  assert.deepEqual(unfollowedLate([[late('a', after)], [clean('b')]]).map(s => [...s]), [['a'], []], 'another recorder does not follow');
  assert.deepEqual(unfollowedLate([[late('a', after)], [{ ...clean('a'), coverage: 'failed' }]]).map(s => [...s]), [['a'], []], 'a failed window does not follow');
  assert.deepEqual(unfollowedLate([[late('a', inflight)], [clean('a')]]).map(s => [...s]), [['a'], []], 'a pending forward needs a drain');
});

test('collector record: a digest of the collector files, recomputable, and it changes with them', async () => {
  assert.equal(COLLECTOR_RECORDS['egress-recorder'].digest, await collectorDigest(COLLECTOR_FILES['egress-recorder']));
  assert.equal(COLLECTOR_RECORDS['egress-recorder'].label, 'egress-recorder/13', 'the run-end drain moved the label to /3, captured late entries to /4, verified signature headers to /5, object-route target flags to /6, in-doubt transport records to /7, the request feed to /8, read-back to /9, both loopback binds to /10, aliases and undeclared sibling hosts to /11, the drain\'s quiet recheck to /12, the run\'s other recorders\' destinations to /13');
  assert.equal(COLLECTOR_RECORDS['egress-recorder'].node, process.versions.node);
  const { mkdtemp, copyFile, appendFile } = await import('node:fs/promises'), { tmpdir } = await import('node:os'), { join } = await import('node:path');
  const dir = await mkdtemp(join(tmpdir(), 'collector digest '));
  for (const name of COLLECTOR_FILES['egress-recorder']) await copyFile(new URL(`../integrations/observers/${name}`, import.meta.url), join(dir, name));
  const base = new URL(`file://${encodeURI(dir)}/`);
  assert.equal(await collectorDigest(COLLECTOR_FILES['egress-recorder'], base), COLLECTOR_RECORDS['egress-recorder'].digest, 'path-independent');
  await appendFile(join(dir, 'sink-ledger.mjs'), '\n// edited\n');
  assert.notEqual(await collectorDigest(COLLECTOR_FILES['egress-recorder'], base), COLLECTOR_RECORDS['egress-recorder'].digest);
});

// An app whose /charge/late route answers 403 and leaves a send to HOOK pending, which it makes when the witness ping arrives:
// after the witness request, so it is a late unit of that check's window.
async function lateApp(t, sinkPort) {
  let pendingLate = false;
  const outbound = (target, body) => new Promise(resolve => { const url = new URL(target); const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: target, headers: { host: url.host, ...(body === undefined ? {} : { 'content-type': 'application/json' }) } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(body); });
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { if (pendingLate) { pendingLate = false; await outbound(`http://${HOOK}/audit`, '{}'); } await outbound(`http://${WITNESS}/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (url.pathname === '/charge/late') { pendingLate = true; return reply(403, {}); }
    if (url.pathname === '/charge/quiet') return reply(403, {});
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token', SCOPEHAVEN_TARGET_PAY_UPSTREAM_PROOF: 'synthetic-upstream-proof-secret-0123456789abcdef' };
const check = (id, path, extra = {}) => ({ id, title: id, category: 'payments', severity: 'high', actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], ...extra });
// observersOf: { count, build(port, ...more) } for a run with its own observer list (more: further free ports).
const run = (t, checks, extra = {}, wrap = f => f, observersOf = null) => onFreePorts(observersOf?.count ?? 1, async (port, ...more) => {
  const p = { id: 'late', name: 'Late', applicationId: 'late', origin: await lateApp(t, port), buildLabel: 'b1', contextId: 'synthetic-late',
    actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
    observers: observersOf ? observersOf.build(port, ...more) : [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1'] }, { host: HOOK }], witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] }, ...checks], ...extra };
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const watch = watchingBinds(buildObservers);
  return { p, run: await runHttpAssessment(p, { env, observerFactory: wrap(watch.factory) }), lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('connector: a late send to another host leaves an earlier absence pass standing when a later window follows it, and missing when nothing does', async t => {
  const noPay = { effects: [none(PAY)] };
  const followed = await run(t, [check('LATE', '/charge/late', noPay), check('NEXT', '/charge/quiet', noPay)]);
  const lateRow = followed.run.results.find(x => x.id === 'LATE');
  const window = lateRow.trace[1].data.windows[0];
  assert.deepEqual(window.scoped?.map(e => [e.name, e.codes]), [[HOOK, ['egress-request-after-witness-request']]], JSON.stringify(window.reason));
  // The row's identity reads inconclusive (no surface control in this minimal profile); the effect clause is what scoped coverage decides.
  const effectOf = row => row.assertions.find(a => a.name === 'Observed effect 1 (effect.none)');
  assert.equal(effectOf(lateRow).status, 'pass', JSON.stringify(lateRow.assertions));
  const suite = createRegistry({ profiles: [followed.p], env }).exportSuite(followed.p.id);
  validateHttpRunEvidence(followed.run, { expectedSuite: suite });
  // Forged: the entry moved onto PAY, resealed. The recompute now reads missing for LATE, so the stored pass is refused.
  const forged = structuredClone(followed.run), fx = forged.results.find(x => x.id === 'LATE');
  fx.trace[1].data.windows[0].scoped[0].name = PAY; fx.trace[1].data.windows[0].scoped[0].resource = 'POST /v1';
  fx.evidenceDigest = digest({ evidence: fx.trace[0].data, effects: fx.trace[1].data, assertions: fx.assertions });
  assert.throws(() => validateHttpRunEvidence(forged), error => error.code === 'invalid-run-evidence');
  // The same check last in the run: nothing follows its late entry, so the row is decided again window-wide.
  const alone = await run(t, [check('LATE', '/charge/late', noPay)]);
  const aloneRow = alone.run.results.find(x => x.id === 'LATE');
  assert.equal(effectOf(aloneRow).status, 'inconclusive', JSON.stringify(aloneRow.assertions));
  validateHttpRunEvidence(alone.run, { expectedSuite: createRegistry({ profiles: [alone.p], env }).exportSuite(alone.p.id) });
  assert.equal(aloneRow.backendEvidence, 'unavailable', 'the re-decided row no longer claims backend evidence');
});

test('end to end: a followed late send to another host lets a fail and an allowed-only effect.only pass (under the judge) decide; unfollowed, both read inconclusive', async t => {
  const hookAny = { source: 'http-egress', operation: 'send', name: HOOK, resource: 'POST *' };
  const effects = { effects: [exists(PAY), { kind: 'effect.only', expect: [], allow: [hookAny], sources: ['http-egress'] }] };
  const judged = { settlement: { mode: 'run', outsideWindow: 'judge' } };
  const statusOf = (row, n, kind) => row.assertions.find(a => a.name === `Observed effect ${n} (${kind})`).status;
  const validated = r => validateHttpRunEvidence(r.run, { expectedSuite: createRegistry({ profiles: [r.p], env }).exportSuite(r.p.id) });
  const followed = await run(t, [check('LATE', '/charge/late', effects), check('NEXT', '/charge/quiet', { effects: [none(PAY)] })], judged);
  const row = followed.run.results.find(x => x.id === 'LATE');
  assert.deepEqual(row.trace[1].data.windows[0].scoped?.map(e => [e.name, e.resource, e.codes]), [[HOOK, 'POST *', ['egress-request-after-witness-request']]]);
  assert.equal(statusOf(row, 1, 'effect.exists'), 'fail', 'no send to PAY, decided on the followed window');
  assert.equal(statusOf(row, 2, 'effect.only'), 'pass', 'the late HOOK send is allowed; the judge counts its gap event as the check\'s own');
  assert.equal(row.trace[1].data.effects[1].settlementNote, 'effect-outside-window-judged');
  validated(followed);
  // Adjacent: without the judge the late HOOK send, recorded in the gap after the check, withholds the effect.only pass; the
  // fail is unchanged.
  const plain = await run(t, [check('LATE', '/charge/late', effects), check('NEXT', '/charge/quiet', { effects: [none(PAY)] })]);
  const plainRow = plain.run.results.find(x => x.id === 'LATE');
  assert.deepEqual([statusOf(plainRow, 1, 'effect.exists'), statusOf(plainRow, 2, 'effect.only')], ['fail', 'inconclusive']);
  assert.equal(plainRow.trace[1].data.effects[1].settlement, 'effect-outside-window');
  validated(plain);
  // Adjacent: the same check last in the run, nothing follows its late entry: the connector decides it again window-wide, so the
  // first-pass fail and pass both become missing, and the validator recomputes the same.
  const alone = await run(t, [check('LATE', '/charge/late', effects)], judged);
  const aloneRow = alone.run.results.find(x => x.id === 'LATE');
  assert.deepEqual([statusOf(aloneRow, 1, 'effect.exists'), statusOf(aloneRow, 2, 'effect.only')], ['inconclusive', 'inconclusive'], JSON.stringify(aloneRow.assertions));
  assert.deepEqual(aloneRow.trace[1].data.effects.map(d => d.verdict), ['missing', 'missing']);
  validated(alone);
});

test('run-end drain: with attribution declared, a quiescent run-end drain follows the last check\'s late entry, and the pass stands', async t => {
  const noPay = { effects: [none(PAY)] }, attribution = { background: [{ id: 'nightly', select: { operation: 'send', name: HOOK, actor: 'svc-nightly' } }] };
  const effectOf = row => row.assertions.find(a => a.name === 'Observed effect 1 (effect.none)');
  const drained = await run(t, [check('LATE', '/charge/late', noPay)], { attribution });
  const row = drained.run.results.find(x => x.id === 'LATE');
  assert.deepEqual(row.trace[1].data.windows[0].scoped?.map(e => [e.name, e.codes]), [[HOOK, ['egress-request-after-witness-request']]]);
  const [d] = drained.run.settlement.drains;
  assert.deepEqual([d.instanceId, d.quiescent, d.markClear, d.closedAfterCollect], ['egress-recorder-sink', true, true, false], JSON.stringify(d));
  assert.equal(effectOf(row).status, 'pass', JSON.stringify(row.assertions));
  const suite = createRegistry({ profiles: [drained.p], env }).exportSuite(drained.p.id);
  validateHttpRunEvidence(drained.run, { expectedSuite: suite });
  // A drain that did not follow (edited): the recompute leaves the entry unfollowed, reads missing, and the stored pass is refused.
  const forged = structuredClone(drained.run); forged.settlement.drains[0].markClear = false;
  assert.throws(() => validateHttpRunEvidence(forged), error => error.code === 'invalid-run-evidence');
  // A drains record on a run that declares neither attribution nor a forward is refused.
  const plain = await run(t, [check('LATE', '/charge/late', noPay)]);
  assert.equal(Object.hasOwn(plain.run.settlement, 'drains'), false, 'no drain without attribution or a forward');
  assert.equal(effectOf(plain.run.results.find(x => x.id === 'LATE')).status, 'inconclusive');
  // (A drain that follows nothing, so the refusal is the record's own: settlement-drains.)
  // A recorder that cannot drain (here an injected wrapper without drain) still gets its record, which follows nothing.
  const strip = factory => (configs, options) => factory(configs, options).map(o => { const { drain, ...rest } = o; return Object.assign(Object.create(Object.getPrototypeOf(o)), rest); });
  const undrained = await run(t, [check('LATE', '/charge/late', noPay)], { attribution }, strip);
  assert.deepEqual(undrained.run.settlement.drains.map(x => [x.instanceId, x.quiescent]), [['egress-recorder-sink', false]]);
  assert.equal(effectOf(undrained.run.results.find(x => x.id === 'LATE')).status, 'inconclusive');
  validateHttpRunEvidence(undrained.run, { expectedSuite: createRegistry({ profiles: [undrained.p], env }).exportSuite(undrained.p.id) });
  const added = structuredClone(plain.run); added.settlement.drains = structuredClone(drained.run.settlement.drains); added.settlement.drains[0].quiescent = false;
  assert.throws(() => validateHttpRunEvidence(added), error => error.code === 'invalid-run-evidence' && error.detail === 'settlement-drains');
});

// The drain with a forward declared and no attribution, with two
// recorders, and an edited drain over a failed run-end window.
const recorder = (id, port, destinations) => ({ id, type: 'egress-recorder', port, routing: 'proxy', destinations, witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 });
test('run-end drain: a forwarded destination alone declares it, two recorders each get their record in order, and a quiescent record over a failed run-end window is refused', async t => {
  const noPay = { effects: [none(PAY)] }, effectOf = row => row.assertions.find(a => a.name === 'Observed effect 1 (effect.none)');
  // Forward only (no attribution): PAY forwards to a loopback upstream the app never reaches here.
  const forwardOnly = { count: 2, build: (port, up) => [recorder('sink', port, [{ host: PAY, paths: ['/v1'], forward: { upstream: `http://127.0.0.1:${up}`, proofEnv: 'SCOPEHAVEN_TARGET_PAY_UPSTREAM_PROOF' } }, { host: HOOK }])] };
  const f = await run(t, [check('LATE', '/charge/late', noPay)], {}, f => f, forwardOnly);
  assert.deepEqual(f.run.settlement.drains.map(d => [d.instanceId, d.quiescent, d.markClear, d.closedAfterCollect]), [['egress-recorder-sink', true, true, false]]);
  assert.equal(effectOf(f.run.results.find(x => x.id === 'LATE')).status, 'pass', 'the drain follows the last check\'s late entry');
  validateHttpRunEvidence(f.run, { expectedSuite: createRegistry({ profiles: [f.p], env }).exportSuite(f.p.id) });
  // Two recorders, attribution declared: one record each, in declaration order, the idle one quiescent too.
  const attribution = { background: [{ id: 'nightly', select: { operation: 'send', name: HOOK, actor: 'svc-nightly' } }] };
  const two = { count: 2, build: (port, second) => [recorder('sink', port, [{ host: PAY, paths: ['/v1'] }, { host: HOOK }]), recorder('mail', second, [{ host: 'mail.example.test' }])] };
  const both = await run(t, [check('LATE', '/charge/late', noPay)], { attribution }, f => f, two);
  assert.deepEqual(both.run.settlement.drains.map(d => [d.instanceId, d.quiescent]), [['egress-recorder-sink', true], ['egress-recorder-mail', true]]);
  validateHttpRunEvidence(both.run, { expectedSuite: createRegistry({ profiles: [both.p], env }).exportSuite(both.p.id) });
  // A drain that reads quiescent over a run-end window its recorder failed is not one the connector makes.
  const failed = structuredClone(f.run), last = failed.settlement.gaps.at(-1).windows.find(w => w.instanceId === 'egress-recorder-sink');
  Object.assign(last, { coverage: 'failed', reason: 'egress-listener-down', events: [] });
  assert.throws(() => validateHttpRunEvidence(failed), e => e.code === 'invalid-run-evidence' && e.detail === 'settlement-drains');
  failed.settlement.drains[0].quiescent = false; failed.settlement.drains[0].markClear = false;
  assert.throws(() => validateHttpRunEvidence(failed), e => e.code === 'invalid-run-evidence' && e.detail !== 'settlement-drains', 'the adjacent case reads past the drain check');
});

test('an ambiguous path that is also ineligible still names egress-path-ambiguous on the window (a resource pin reads it)', async t => {
  const o = await sink(t, { maxBodyBytes: 1024 });
  const big = () => new Promise(resolve => { const req = request({ host: '127.0.0.1', port: o.port, method: 'POST', path: `http://${PAY}/v%31/charge`, headers: { host: PAY, 'content-type': 'application/json' } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(JSON.stringify({ pad: 'x'.repeat(2000) })); });
  const w = await windowOf(o, { during: big });
  assert.equal(Object.hasOwn(w, 'scoped'), false);
  assert.deepEqual(w.reason.split(',').filter(c => ['egress-body-over-limit', 'egress-path-ambiguous'].includes(c)).sort(), ['egress-body-over-limit', 'egress-path-ambiguous'], w.reason);
  // The window's events are also resource-uncertain, so they fit every background resource pin.
  const { resourceUncertain } = await import('../src/http-attribution.mjs');
  const uncertain = resourceUncertain([w]);
  assert.ok(w.events.length > 0 && w.events.every(e => uncertain.has(e)), JSON.stringify(w.events.map(e => e.resource)));
  // The adjacent eligible case keeps its scoped entry (resource null) and no window-wide code.
  const ok = await sink(t);
  const scoped = await windowOf(ok, { during: () => send(ok.port, PAY, '/v%31/charge') });
  assert.deepEqual(scoped.scoped?.map(e => [e.name, e.resource, e.codes]), [[PAY, null, ['egress-path-ambiguous']]], JSON.stringify(scoped.reason));
  assert.ok(scoped.events.every(e => resourceUncertain([scoped]).has(e)), 'the eligible case is uncertain through its scoped entry');
});
