// Postgres read-back in HTTP checks (src/http-readback.mjs), end to end through runHttpAssessment and the shared validator,
// against the scripted fake Postgres's typed model (no real database). The app mimics a reply route whose send helper
// answers a reused request id as sent without sending (an owned app's confirmed said-did
// defect): the reply says sent, and no outbound message row is written. Synthetic data, loopback only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { runHttpAssessment, HTTP_EVALUATOR_HASH } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { COLLECTOR_RECORDS } from '../src/collector-identity.mjs';
import { recomputeReadBack } from '../src/http-readback.mjs';
import { pgModel, scriptedDb, USER, PASSWORD } from '../integrations/observers/fixtures/fake-postgres.mjs';
import recordedAtMain from './fixtures/pre-readback-run-42a10d62.mjs';

const TOKEN = 'synthetic-alice-token', PHONE = '+15550001111';
const env = { SCOPEHAVEN_TARGET_ALICE: TOKEN, SCOPEHAVEN_TARGET_DB_READER: `${USER}:${PASSWORD}` };
const MESSAGES = () => ({ table: 'messages', key: 'id', columns: [{ name: 'direction', type: '25' }, { name: 'thread_id', type: '25' }, { name: 'to_phone', type: '25' }, { name: 'status', type: '25' }],
  rows: [{ id: 'm-000', direction: 'inbound', thread_id: 'thread-a1', to_phone: PHONE, status: 'received' }] });

// POST /api/owner/reply { thread_id, request_id }: a request id seen before answers sent without sending (the defect).
// touch: also rewrite the seeded inbound row (a write outside the declared values).
async function replyApp(t, model, { touch = false } = {}) {
  const seen = new Set(); let n = 0;
  const server = createServer((req, res) => { let body = ''; req.on('data', c => { body += c; }); req.on('end', () => {
    const reply = (status, json) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(json)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return reply(401, {});
    if (req.method === 'GET' && req.url === '/me') return reply(200, { user: 'alice' });
    if (req.method === 'POST' && req.url === '/api/owner/reply') {
      const { thread_id: thread, request_id: id } = JSON.parse(body || '{}');
      if (seen.has(id)) return reply(200, { sent: true, duplicate: true });
      seen.add(id);
      model.write('messages', `m-${String(++n).padStart(3, '0')}`, { direction: 'outbound', thread_id: thread, to_phone: PHONE, status: 'sent' });
      if (touch) model.write('messages', 'm-000', { status: 'read' });
      return reply(200, { sent: true });
    }
    reply(404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const READ_BACK = { columns: ['direction', 'thread_id', 'to_phone'], sensitive: ['to_phone'], inserts: 1, remainder: 'may-change' };
const pgObserver = (port, readBack = READ_BACK, extra = {}) => Object.fromEntries(Object.entries({ id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER',
  tables: [{ table: 'messages', key: 'id', readBack }], settleMs: 250, ...extra }).filter(([, v]) => v !== undefined));
const reply = (id, title, severity, thread, requestId, more = {}) => ({ id, title, category: 'action-claim', severity, actorId: 'alice', method: 'POST', path: '/api/owner/reply', evidenceRequirement: 'response',
  body: { thread_id: thread, request_id: requestId }, assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/sent', expected: true }], readBack: [{ observer: 'db', table: 'messages' }], ...more });
const profile = (origin, observers, checks) => ({ id: 'replies', name: 'Replies', applicationId: 'replies-app', origin, buildLabel: 'b1', contextId: 'synthetic-replies',
  actors: { alice: { principalId: 'alice', credentialEnv: 'SCOPEHAVEN_TARGET_ALICE', identityValue: 'alice' } }, requiredControlIds: ['WHOAMI'], observers,
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'alice', method: 'GET', path: '/me', evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'alice' }] }, ...checks] });
const LIVE = () => reply('T-ALICE-REPLY-LIVE', "Alice's live reply writes one outbound message", 'control', 'thread-a1', 'req-1');
const SAME_ID = () => reply('SD-SAME-ID-A2', "The reply's sent claim matches the message record (same request id, other thread)", 'high', 'thread-a2', 'req-1');
const row = (run, id) => run.results.find(r => r.id === id);
const readBackRow = r => r.assertions.find(a => /^Read-back 1 \(messages\)$/.test(a.name));
// Reseals a row after a test edits its sealed trace, so only the edit is under test.
const reseal = r => { r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions }); };
async function runOn(t, { observer = READ_BACK, extra = {}, checks = [LIVE(), SAME_ID()], touch = false } = {}) {
  const model = pgModel([MESSAGES()]);
  const db = await scriptedDb(t, [], [], { beginState: () => model.state() });
  const origin = await replyApp(t, model, { touch });
  const p = profile(origin, [pgObserver(db.port, observer, extra)], checks);
  return { p, run: await runHttpAssessment(p, { env }) };
}

test('the said-did pair: the live reply (allowed-use control) meets its read-back; the reused request id reads FAIL from the record', async t => {
  const { p, run } = await runOn(t);
  const live = row(run, 'T-ALICE-REPLY-LIVE'), same = row(run, 'SD-SAME-ID-A2');
  assert.deepEqual([live.status, readBackRow(live).status, readBackRow(live).custody], ['pass', 'pass', 'subject-writable'], JSON.stringify(live.assertions));
  // The reply says sent (its own contract holds); the record says no message was inserted.
  assert.equal(same.assertions.find(a => a.name === 'json.equals predicate 1').status, 'pass');
  assert.deepEqual([same.status, readBackRow(same).status], ['fail', 'fail'], JSON.stringify(same.assertions));
  assert.match(readBackRow(same).actual, /^fail: .*inserts-mismatch/);
  const sealed = same.trace[1].data.readBack[0];
  assert.deepEqual([sealed.instanceId, sealed.table, sealed.judged, sealed.verdict, sealed.record.tables[0].counts.inserted], ['pg-snapshot-db', 'messages', 'fail', 'fail', 0]);
  validateHttpRunEvidence(run);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
  // The suite binds each declaration by digest: a suite exported for another declaration refuses this run.
  const other = structuredClone(p); other.observers[0].tables[0].readBack = { ...READ_BACK, inserts: 2 };
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [other], env }).exportSuite(other.id) }), /unexpected-suite-evidence/);
  // The suite binds a digest of the sealed view only; no digest of the whole declaration is written anywhere.
  assert.ok(!JSON.stringify(run).includes('declarationDigest'));
  // The sensitive column is kept only as sealed digests: the planted phone number appears nowhere in the run.
  assert.ok(!JSON.stringify(run).includes(PHONE), 'no sensitive value in clear');
  const liveRow = live.trace[1].data.readBack[0].record.tables[0].rows.find(r => r.after?.direction === 'outbound');
  assert.match(liveRow.after.to_phone.sealed, /^[0-9a-f]{64}$/);
  assert.equal(liveRow.after.thread_id, 'thread-a1');
});

test('fail-only on a boundary: a judged pass reads inconclusive under subject-writable custody, and the validator holds it there', async t => {
  // An expectation on the sensitive column too (the seeded inbound row keeps its number): sealed in the record like the values.
  const { p, run } = await runOn(t, { observer: { ...READ_BACK, expect: [{ key: 'm-000', values: { to_phone: PHONE } }] }, checks: [reply('B-FRESH-REPLY', 'A fresh reply in a boundary check', 'high', 'thread-a2', 'req-9')] });
  const r = row(run, 'B-FRESH-REPLY'), a = readBackRow(r), sealed = r.trace[1].data.readBack[0];
  assert.match(sealed.record.tables[0].expect[0].to.sealed, /^[0-9a-f]{64}$/);
  // The sealed view names the expectation on the sensitive column but never its value, in clear or as an unsalted digest.
  assert.deepEqual(sealed.view.expect, [{ key: 'm-000', column: 'to_phone', mode: 'value' }]);
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  assert.ok(!JSON.stringify(suite).includes(PHONE));
  assert.deepEqual(Object.keys(suite.checks.find(c => c.id === 'B-FRESH-REPLY').readBack[0]), ['instanceId', 'table', 'viewDigest']);
  // The profile and suite hashes read the declaration through its view: a different sealed expected value gives the same hashes, so the
  // planted value sits in no unsalted digest; a clear one (or anything else in the view) changes them.
  const other = structuredClone(p), clear = structuredClone(p);
  other.observers[0].tables[0].readBack.expect[0].values.to_phone = '+15550002222';
  clear.observers[0].tables[0].readBack.inserts = 2;
  const hashOf = q => createRegistry({ profiles: [q], env }).exportSuite(q.id).hash;
  assert.equal(hashOf(other), suite.hash); assert.equal(run.profileHash, suite.hash);
  assert.notEqual(hashOf(clear), suite.hash);
  assert.ok(!JSON.stringify(run.results).includes(PHONE), 'no sensitive value in clear, in the values or the expectation');
  assert.deepEqual([sealed.judged, sealed.verdict, a.status, a.custodyReason, r.status], ['pass', 'inconclusive', 'inconclusive', 'subject-writable-custody', 'inconclusive']);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
  // Forged into a pass (sealed verdict, assertion and status), the row is refused.
  const forged = structuredClone(run), fr = row(forged, 'B-FRESH-REPLY'), fs = fr.trace[1].data.readBack[0];
  fs.verdict = 'pass'; delete fs.custodyReason;
  fr.assertions = fr.assertions.map(x => (x.name === a.name ? { ...x, status: 'pass', custodyReason: undefined } : x)).map(x => JSON.parse(JSON.stringify(x)));
  fr.status = 'pass'; reseal(fr);
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
});

test('a window the observer could not follow, or a forbidden remainder change, never passes', async t => {
  // No settle declared: the connector caps the window at partial, which blocks the read-back even where the record would fail.
  const { run: unsettled } = await runOn(t, { extra: { settleMs: undefined } });
  for (const id of ['T-ALICE-REPLY-LIVE', 'SD-SAME-ID-A2']) {
    const a = readBackRow(row(unsettled, id));
    assert.equal(a.status, 'inconclusive', `${id}: ${a.actual}`); assert.match(a.actual, /no-post-response-settle/);
  }
  validateHttpRunEvidence(unsettled);
  // The sealed record re-stamped as followed (status ok) under a partial window is refused.
  const forged = structuredClone(unsettled), fr = row(forged, 'SD-SAME-ID-A2'), fs = fr.trace[1].data.readBack[0];
  fs.record.status = 'ok'; reseal(fr);
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
  // remainder "unchanged": the app also rewrites a row outside the declared values, so the control's pass reads inconclusive.
  const { run: touched } = await runOn(t, { observer: { ...READ_BACK, remainder: 'unchanged' }, checks: [LIVE()], touch: true });
  const a = readBackRow(row(touched, 'T-ALICE-REPLY-LIVE'));
  assert.equal(a.status, 'inconclusive'); assert.match(a.actual, /remainder-changed/);
  validateHttpRunEvidence(touched);
});

test('sealed values: a sensitive column written in clear, or a verdict that differs from the sealed record, is refused', async t => {
  const { run } = await runOn(t);
  const clear = structuredClone(run), cr = row(clear, 'T-ALICE-REPLY-LIVE'), rows = cr.trace[1].data.readBack[0].record.tables[0].rows;
  rows.find(r => r.after?.direction === 'outbound').after.to_phone = '+15559990000';
  reseal(cr);
  assert.throws(() => validateHttpRunEvidence(clear), /invalid-run-evidence/);
  // The FAIL turned into a pass by editing the count it was decided on.
  const counted = structuredClone(run), sr = row(counted, 'SD-SAME-ID-A2');
  sr.trace[1].data.readBack[0].record.tables[0].counts.inserted = 1; reseal(sr);
  assert.throws(() => validateHttpRunEvidence(counted), /invalid-run-evidence/);
  // The sealed entry's own verdict edited (its assertion left as it was) no longer says what the record gives: refused.
  const relabelled = structuredClone(run), lr = row(relabelled, 'SD-SAME-ID-A2');
  Object.assign(lr.trace[1].data.readBack[0], { judged: 'pass', verdict: 'pass' }); reseal(lr);
  assert.throws(() => validateHttpRunEvidence(relabelled), /invalid-run-evidence/);
  // An error value for a sealed column must be one the reader emits: a clear value dressed as an error is refused.
  const dressed = structuredClone(run), xr = row(dressed, 'T-ALICE-REPLY-LIVE');
  xr.trace[1].data.readBack[0].record.tables[0].rows.find(r => r.after?.direction === 'outbound').after.to_phone = { error: '+15559990000' };
  reseal(xr);
  assert.throws(() => validateHttpRunEvidence(dressed), /invalid-run-evidence/);
  // Dropped: the sealed record removed from a row that declares read-back (its assertion left in place) is refused.
  const dropped = structuredClone(run), dr = row(dropped, 'SD-SAME-ID-A2');
  delete dr.trace[1].data.readBack; reseal(dr);
  assert.throws(() => validateHttpRunEvidence(dropped), /invalid-run-evidence/);
});

test('profiles: readBack names a declared read-back table; a declaration the observer would refuse is refused at load', () => {
  const load = (observer, checks) => validateTargetFile({ schemaVersion: 1, targets: [profile('http://127.0.0.1:4000', [observer], checks)] });
  load(pgObserver(5432), [SAME_ID()]);
  assert.throws(() => load(pgObserver(5432), [{ ...SAME_ID(), readBack: [{ observer: 'db', table: 'threads' }] }]), /names a pg-snapshot observer of this target and one of its tables that declares a valid "readBack"/);
  assert.throws(() => load(pgObserver(5432), [{ ...SAME_ID(), readBack: [{ observer: 'db', table: 'messages' }, { observer: 'db', table: 'messages' }] }]), /named once per check/);
  // A column whose name reads as personal data must be listed as sensitive (src/pg-readback.mjs).
  assert.throws(() => load(pgObserver(5432, { columns: ['to_phone'], inserts: 1 }), [SAME_ID()]), /invalid readBack on messages/);
  assert.throws(() => load({ ...pgObserver(5432), tables: [{ table: 'messages', key: 'id', readBack: { columns: ['id'] } }] }, [SAME_ID()]), /invalid readBack on messages/);
});

// No readBack, no change: a run recorded and sealed by an earlier build's own connector validates here, with and without
// the suite that build exported, and this head exports the same suite for its profile. Only the evaluator identity moved.
test('a run recorded by an earlier build before read-back validates unchanged, and this head exports the same suite for its profile', () => {
  const { recordedAt, profile: recordedProfile, suite, run } = structuredClone(recordedAtMain);
  assert.equal(recordedAt, '42a10d62');
  validateHttpRunEvidence(run);
  validateHttpRunEvidence(run, { expectedSuite: suite });
  // Passing each recorder the other recorders' destinations moved the collector records (egress-recorder/13, and every collector's
  // files' digest, since factory.mjs is in each list): the suite comes out as that build's with this build's records in their place,
  // and nothing else differs.
  const exported = createRegistry({ profiles: [recordedProfile], env: { SCOPEHAVEN_TARGET_BOB: 'x', SCOPEHAVEN_TARGET_DB_READER: 'u:p' } }).exportSuite(recordedProfile.id);
  assert.ok(exported.observers.every(o => o.collector === undefined || digest(o.collector) === digest(COLLECTOR_RECORDS[o.type])));
  assert.equal(digest({ ...exported, observers: exported.observers.map((o, i) => o.collector === undefined ? o : { ...o, collector: suite.observers[i]?.collector }) }), digest(suite));
  assert.ok(run.results.every(r => !Object.hasOwn(r.trace?.[1]?.data ?? {}, 'readBack') && !r.assertions.some(a => /^Read-back /.test(a.name))));
  assert.equal(run.evaluatorHash, 'd563a9f71ab83e4e798df807b3fb793b6101525f6113e95ac2a76c56d7e4ecb6');
  assert.notEqual(HTTP_EVALUATOR_HASH, run.evaluatorHash);
});

test("an expectation in clear is bound: a control's FAIL cannot be turned into a pass by editing what the record was judged against", async t => {
  const observer = { columns: ['direction', 'status', 'to_phone'], sensitive: ['to_phone'], inserts: 1, remainder: 'may-change', expect: [{ key: 'm-000', values: { status: 'received' } }] };
  // The app also marks the seeded inbound row read: the control's expectation (it stays received) fails.
  const { p, run } = await runOn(t, { observer, checks: [LIVE()], touch: true });
  const r = row(run, 'T-ALICE-REPLY-LIVE'), a = readBackRow(r), sealed = r.trace[1].data.readBack[0];
  assert.deepEqual([a.status, r.status], ['fail', 'fail']); assert.match(a.actual, /value-mismatch/);
  assert.deepEqual(sealed.view.expect, [{ key: 'm-000', column: 'status', mode: 'value', to: 'received' }]);
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  validateHttpRunEvidence(run, { expectedSuite: suite });
  // Forged: the record's expectation set to what the row became, the assertion and row made to pass.
  const forged = structuredClone(run), fr = row(forged, 'T-ALICE-REPLY-LIVE'), fs = fr.trace[1].data.readBack[0];
  fs.record.tables[0].expect[0].to = 'read'; fs.judged = 'pass'; fs.verdict = 'pass';
  fr.assertions = fr.assertions.map(x => (x.name === a.name ? { ...x, status: 'pass', actual: x.actual.replace(/^fail: .*$/, 'pass: forged') } : x)); fr.status = 'pass'; reseal(fr);
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
  // With the view edited to match and the assertion rewritten exactly as the validator recomputes it, only the suite (which binds
  // the view by digest) can refuse it: without a suite the forgery is as unbound as an edited effect clause would be.
  const inputs = { observers: forged.observers, windows: fr.trace[1].data.windows };
  // The record's expectation no longer reads as the view's declared value: refused at the record itself.
  assert.throws(() => recomputeReadBack(fr.trace[1].data.readBack, 'control', inputs), /effect-trace/);
  fs.view.expect[0].to = 'read';
  assert.equal(recomputeReadBack(fr.trace[1].data.readBack, 'control', inputs).rows[0].status, 'pass');
  const declared = suite.checks.find(c => c.id === 'T-ALICE-REPLY-LIVE').readBack;
  assert.throws(() => recomputeReadBack(fr.trace[1].data.readBack, 'control', { ...inputs, declared }), /unexpected-suite-evidence/);
});
