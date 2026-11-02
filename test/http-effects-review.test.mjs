// Core effect wiring: one test per guarded case.
// Genuine runs through runHttpAssessment against a loopback app; tamper cases
// edit saved evidence and reseal it the way a forger would.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, appendFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, targetConfigDigest } from '../src/contracts.mjs';
import { FORWARDER_LIMITATION } from '../src/http-scope-text.mjs';
import { decideEffects, effectAssertionRows, backendObserved } from '../src/http-effects.mjs';
import { compareRuns } from '../src/runner.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { buildReport } from '../integrations/github-action/summary.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { buildObservers as buildSequenceObservers } from '../integrations/sequences/cli.mjs';

const TOKEN = 'synthetic-member-token', env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN };
const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
// A probe app with an append-only audit table and its own MCP tool-call log.
//   /refund         logs an MCP tool call only (presence-only telemetry)
//   /refund-audited logs the tool call and writes an audit row (authoritative)
//   /notes/other/edit answers 403 at once, then (mode 'late') commits the edit 300 ms later
async function probeApp(t, { mode = 'late' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-review-'));
  const dbPath = join(dir, 'app.db'), mcpLog = join(dir, 'mcp.log');
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode=WAL; CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, action TEXT, target TEXT);');
  let seq = 0; const now = () => String(BigInt(Date.now()) * 1000000n);
  const mcp = frame => appendFileSync(mcpLog, `${JSON.stringify({ v: 1, seq: ++seq, t: now(), ...frame })}\n`);
  writeFileSync(mcpLog, `${JSON.stringify({ v: 1, seq: ++seq, t: now(), kind: 'open', conn: 'c1' })}\n`, { mode: 0o600 });
  const timers = new Set();
  const server = createServer((req, res) => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => {
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(res, 401, {});
    if (req.url === '/me') return json(res, 200, { user: 'member-1' });
    if (req.method === 'POST' && req.url.startsWith('/refund')) {
      const id = String(seq + 1); mcp({ kind: 'call', conn: 'c1', id, tool: 'issue_refund', actor: 'member-1', argsDigest: null }); mcp({ kind: 'result', conn: 'c1', id, isError: false, rpcErrorCode: null, httpStatus: null });
      if (req.url === '/refund-audited') db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run('member-1', 'refund.issue', 'refunds/r1');
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && req.url === '/notes/other/edit') {
      json(res, 403, { error: 'forbidden' });
      if (mode === 'late') { const timer = setTimeout(() => { timers.delete(timer); db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run('member-1', 'note.update', 'notes/other'); }, 300); timers.add(timer); }
      return;
    }
    if (req.url === '/ping') return json(res, 200, { ok: true });
    json(res, 404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { for (const timer of timers) clearTimeout(timer); await new Promise(r => { server.close(r); server.closeAllConnections(); }); db.close(); rmSync(dir, { recursive: true, force: true }); });
  return { origin: `http://127.0.0.1:${server.address().port}`, dbPath, mcpLog, db };
}
const audit = (app, extra = {}) => ({ id: 'audit', type: 'sqlite-audit', path: app.dbPath, principals: ['member-1'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'action', resourceColumn: 'target', actions: { 'note.update': 'update', 'refund.issue': 'insert' } }, ...extra });
const whoami = { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] };
const editOther = { id: 'EDIT-OTHER', title: 'Cannot edit another note', category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/notes/other/edit', body: {}, evidenceRequirement: 'backend',
  assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: { source: 'sql-audit-table', name: 'note.update' } }] };
// The next check watches the same action: a late commit from EDIT-OTHER must not land in its window.
const next = { id: 'NEXT', title: 'A later check', category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/ping', body: {}, evidenceRequirement: 'backend',
  assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: { source: 'sql-audit-table', name: 'note.update' } }] };
const profile = (app, observers, checks, overrides = {}) => ({ id: 'probe', name: 'Probe app', applicationId: 'probe-app', origin: app.origin, buildLabel: 'b1', contextId: 'synthetic-probe',
  actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' } }, requiredControlIds: ['WHOAMI'], observers, checks: [whoami, ...checks], ...overrides });
const row = (run, id) => run.results.find(r => r.id === id);
const assertion = (r, prefix) => r.assertions.find(a => a.name.startsWith(prefix));
const recount = run => { run.counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 }; for (const r of run.results) run.counts[r.status]++; };
// A forger's reseal of one effect row after editing its windows: recompute decisions, rows, status and digest.
function resealEffects(r) {
  const data = r.trace[1].data, windows = data.windows.map(({ lineage, settleMs, ...w }) => w);
  const decisions = decideEffects(data.effects.map(({ kind, select, expected }) => ({ kind, select, ...(expected === undefined ? {} : { expected }) })), windows);
  // A thorough forger also restates the custody tags the recompute checks (src/custody.mjs).
  data.effects = data.effects.map(({ custody: _c, custodyReason: _r, custodyUpgrade: _u, ...e }, i) => ({ ...e, verdict: decisions[i].verdict, matched: decisions[i].matched, custody: decisions[i].custody,
    ...(decisions[i].custodyReason ? { custodyReason: decisions[i].custodyReason, custodyUpgrade: decisions[i].custodyUpgrade } : {}) }));
  const effectRows = effectAssertionRows(decisions), observed = backendObserved(decisions);
  r.assertions = [...r.assertions.filter(a => !a.name.startsWith('Observed effect')).map(a => a.name === 'Trusted backend observation available' ? (observed ? { ...a, status: 'pass', actual: 'Authoritative observers decided every declared effect' } : { ...a, status: 'inconclusive', actual: 'Backend evidence unavailable' }) : a), ...effectRows];
  r.backendEvidence = observed ? 'observed' : 'unavailable';
  r.status = r.assertions.some(a => a.status === 'fail') ? 'fail' : r.assertions.some(a => a.status === 'inconclusive') ? 'inconclusive' : 'pass';
  r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions });
}

test('REFUND: presence-only telemetry alone shows the effect happened but never makes backend evidence observed', async t => {
  const app = await probeApp(t, { mode: 'none' });
  const refund = (id, path, select) => ({ id, title: 'Refund is really issued', category: 'allowed-use', severity: 'high', actorId: 'member', method: 'POST', path, body: {}, evidenceRequirement: 'backend',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select }] });
  const p = profile(app, [{ id: 'mcp', type: 'mcp-log', path: app.mcpLog, tools: ['issue_refund'] }, audit(app, { settleMs: 250 })],
    [refund('REFUND', '/refund', { name: 'issue_refund' }), refund('REFUND-AUDITED', '/refund-audited', { source: 'sql-audit-table', name: 'refund.issue' })]);
  const run = await runHttpAssessment(p, { env });
  const presence = row(run, 'REFUND');
  // The telemetry match still shows the refund happened (matched 1), but MCP logs are the target's own
  // instrumentation: under custody (src/custody.mjs) a boundary clause it alone decided reads inconclusive.
  assert.equal(presence.trace[1].data.effects[0].matched, 1, 'the telemetry match still shows the refund happened');
  assert.deepEqual([assertion(presence, 'Observed effect 1').status, assertion(presence, 'Observed effect 1').custodyReason], ['inconclusive', 'subject-writable-custody']);
  assert.equal(presence.backendEvidence, 'unavailable');
  assert.equal(assertion(presence, 'Trusted backend observation').status, 'inconclusive');
  assert.equal(presence.status, 'inconclusive');
  const recorded = row(run, 'REFUND-AUDITED');
  // Backend observed (an authoritative observer decided it), but the audit row is the app's own record: inconclusive.
  assert.deepEqual([recorded.status, recorded.backendEvidence, assertion(recorded, 'Observed effect 1').custodyReason], ['inconclusive', 'observed', 'subject-writable-custody'], JSON.stringify(recorded.assertions));
  validateHttpRunEvidence(run);
  // A forger cannot restore the old reading: the validator recomputes authority from the windows.
  const forged = structuredClone(run), r = row(forged, 'REFUND');
  r.backendEvidence = 'observed'; r.assertions = r.assertions.map(a => a.name.startsWith('Trusted') ? { ...a, status: 'pass' } : a); r.status = 'pass';
  r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions });
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
  const gate = summarizeGate({ candidate: run, expectedSuite: createRegistry({ profiles: [p], env }).exportSuite('probe') });
  assert.equal(gate.exitCode, 1); assert.ok(gate.reasons.includes('inconclusive-evidence'));
});

test('EDIT-OTHER: an effect committed 300 ms after a 403 is caught inside a declared settle; without one, absence reads partial', async t => {
  const app = await probeApp(t, { mode: 'late' });
  const settled = await runHttpAssessment(profile(app, [audit(app, { settleMs: 1000 })], [editOther, next]), { env });
  const caught = row(settled, 'EDIT-OTHER');
  assert.equal(assertion(caught, 'HTTP status').status, 'pass');
  assert.equal(assertion(caught, 'Observed effect 1').status, 'fail', JSON.stringify(caught.assertions));
  assert.deepEqual([caught.status, caught.backendEvidence], ['fail', 'observed']);
  // Windows do not overlap: the late commit is in EDIT-OTHER's window, not the next check's.
  assert.equal(row(settled, 'NEXT').trace[1].data.windows[0].events.length, 0);
  // Its absence rests only on the app's audit table: inconclusive under custody, never a fail.
  assert.deepEqual([row(settled, 'NEXT').status, assertion(row(settled, 'NEXT'), 'Observed effect 1').custodyReason], ['inconclusive', 'subject-writable-custody']);
  // Settlement (src/http-settlement.mjs): the run is marked before its first check and after its last plus the settle.
  assert.match(settled.scopeLabel, /Each run marks every declared observer before its first check and again after its last check plus the largest declared settleMs \(settleMs: audit 1000 ms\), and seals the gaps between the checks' windows\./);
  assert.match(settled.scopeLabel, /Effects committed after the final mark are outside every window and every claim\. Pin a resource or actor on each clause/);
  assert.ok(settled.limitations.some(l => l.startsWith('Each run marks every declared observer')));
  validateHttpRunEvidence(settled);
  await new Promise(r => setTimeout(r, 400));

  const unsettled = await runHttpAssessment(profile(app, [audit(app)], [editOther]), { env });
  const open = row(unsettled, 'EDIT-OTHER');
  assert.equal(open.status, 'inconclusive', JSON.stringify(open.assertions));
  assert.match(assertion(open, 'Observed effect 1').actual, /^missing: .*audit: partial, no-post-response-settle/);
  assert.equal(open.trace[1].data.windows[0].coverage, 'partial');
  assert.match(unsettled.scopeLabel, /Observers without a declared settle cannot show absence \(audit\)\./);
  validateHttpRunEvidence(unsettled);
  // An unsettled window cannot be restated as complete, even fully resealed.
  const forged = structuredClone(unsettled), r = row(forged, 'EDIT-OTHER');
  r.trace[1].data.windows[0].coverage = 'complete'; r.trace[1].data.windows[0].reason = null; r.trace[1].data.windows[0].events = [];
  resealEffects(r); recount(forged);
  // The forger reached the effect rules' pass; custody alone holds it at inconclusive, and the settle rule refuses the window.
  assert.deepEqual([r.status, assertion(r, 'Observed effect 1').custodyReason], ['inconclusive', 'subject-writable-custody'], 'the forger produced a pass the custody rule holds');
  assert.throws(() => validateHttpRunEvidence(forged), /invalid-run-evidence/);
  await new Promise(r => setTimeout(r, 400));
});

test('sealed windows are bound to the declared observers, by instance, source, kind, settle and reason', async t => {
  const app = await probeApp(t, { mode: 'none' });
  const p = profile(app, [audit(app, { settleMs: 250 }), audit(app, { id: 'gone', path: join(app.dbPath, '..', 'missing.db'), settleMs: 250 })], [editOther]);
  const run = await runHttpAssessment(p, { env });
  const genuine = row(run, 'EDIT-OTHER');
  assert.equal(genuine.status, 'inconclusive'); assert.match(assertion(genuine, 'Observed effect 1').actual, /^observer-failure:/);
  assert.deepEqual(run.observers, [{ id: 'audit', type: 'sqlite-audit', settleMs: 250 }, { id: 'gone', type: 'sqlite-audit', settleMs: 250 }]);
  assert.deepEqual(genuine.trace[1].data.windows.map(w => w.instanceId), ['sqlite-audit-audit', 'sqlite-audit-gone']);
  validateHttpRunEvidence(run);
  const suite = createRegistry({ profiles: [p], env }).exportSuite('probe');
  assert.deepEqual(suite.observers, run.observers);
  const forge = edit => { const copy = structuredClone(run); edit(copy, row(copy, 'EDIT-OTHER')); return copy; };
  // Drop the failed observer's window and reseal: the verdict would become a pass.
  const dropped = forge((c, r) => { r.trace[1].data.windows = r.trace[1].data.windows.filter(w => w.instanceId !== 'sqlite-audit-gone'); resealEffects(r); recount(c); });
  // Without custody the drop would read pass; custody holds it at inconclusive, and the observer binding refuses it.
  assert.deepEqual([row(dropped, 'EDIT-OTHER').status, assertion(row(dropped, 'EDIT-OTHER'), 'Observed effect 1').custodyReason], ['inconclusive', 'subject-writable-custody']);
  assert.throws(() => validateHttpRunEvidence(dropped), /invalid-run-evidence/);
  // Also drop the observer from run.observers; consistent without the suite, refused with it.
  const undeclared = forge((c, r) => { r.trace[1].data.windows = r.trace[1].data.windows.filter(w => w.instanceId !== 'sqlite-audit-gone'); resealEffects(r); recount(c); c.observers = c.observers.slice(0, 1); });
  assert.throws(() => validateHttpRunEvidence(undeclared, { expectedSuite: suite }), /unexpected-suite-evidence/);
  assert.equal(summarizeGate({ candidate: undeclared, expectedSuite: suite }).exitCode, 2);
  // A window no declared observer could produce, a relabelled kind, a free-text reason, a changed settle.
  for (const edit of [w => { w.source = 'http-audit-log'; w.lineage.independence = 'application-store'; }, w => { w.lineage.observer = 'hold-gate'; },
    w => { w.reason = 'Trust me, this observer was fine'; }, w => { w.settleMs = 5000; }, w => { w.instanceId = 'sqlite-audit-other'; }])
    assert.throws(() => validateHttpRunEvidence(forge((c, r) => { edit(r.trace[1].data.windows[1]); resealEffects(r); recount(c); })), /invalid-run-evidence/);
});

test('compareRuns refuses a pair whose declared effects, evidence requirements or observers differ', async t => {
  const app = await probeApp(t, { mode: 'late' });
  const lying = await runHttpAssessment(profile(app, [audit(app, { settleMs: 1000 })], [editOther]), { env });
  assert.equal(row(lying, 'EDIT-OTHER').status, 'fail');
  await new Promise(r => setTimeout(r, 400));
  // The forger strips the effect trace from a later run of the same build and calls it a response-only pass.
  const forged = structuredClone(lying), r = row(forged, 'EDIT-OTHER');
  r.trace = [r.trace[0]]; r.evidenceRequirement = 'response'; r.backendEvidence = 'unavailable'; r.observed.evidenceScope = 'response-only';
  r.assertions = r.assertions.filter(a => a.name === 'HTTP status matches contract'); r.status = 'pass';
  r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); recount(forged);
  forged.id = '00000000-0000-4000-8000-000000000001';
  const compared = compareRuns(lying, forged);
  assert.equal(compared.compatible, false);
  assert.ok(compared.reasons.includes('Declared effects, evidence requirements or observers differ between the runs.'), compared.reasons.join(' '));
  assert.equal(compared.rows.find(x => x.id === 'EDIT-OTHER').transition === 'contract-restored', false);
  const gate = summarizeGate({ candidate: forged, baseline: lying });
  assert.notEqual(gate.exitCode, 0); assert.ok(gate.reasons.includes('incompatible-baseline') || gate.exitCode === 2, JSON.stringify(gate.reasons));
  // Observer sets must agree too (here: a different declared settle).
  const resettled = await runHttpAssessment(profile(app, [audit(app, { settleMs: 2000 })], [editOther]), { env });
  assert.ok(compareRuns(lying, resettled).reasons.includes('Declared effects, evidence requirements or observers differ between the runs.'));
  await new Promise(r => setTimeout(r, 400));
});

test('target context is bound to the target-config digest and limitations, and to the exported suite', async t => {
  const app = await probeApp(t, { mode: 'none' });
  const p = profile(app, [], [], { targetContext: 'operator-forwarded', targetLabel: 'Acme staging' });
  const forwarded = await runHttpAssessment(p, { env });
  const suite = createRegistry({ profiles: [p], env }).exportSuite('probe');
  assert.deepEqual([suite.targetContext, suite.targetLabel], ['operator-forwarded', 'Acme staging']);
  validateHttpRunEvidence(forwarded, { expectedSuite: suite });
  const prefix = 'operator-forwarded target: Acme staging. ';
  const relabel = (context, label, { hash = false, limitations = false } = {}) => { const c = structuredClone(forwarded);
    c.targetContext = context; c.targetLabel = label; c.scopeLabel = `${context === 'operator-forwarded' ? `operator-forwarded target: ${label}. ` : ''}${c.scopeLabel.slice(prefix.length)}`;
    if (limitations) c.limitations = c.limitations.filter(l => l !== FORWARDER_LIMITATION);
    if (hash) c.targetConfigHash = targetConfigDigest({ profileHash: c.profileHash, build: c.build, targetContext: context, targetLabel: label });
    return c; };
  // Forwarded to local-app. Refused unless every field is rewritten; the fully consistent forge is refused by the suite.
  assert.throws(() => validateHttpRunEvidence(relabel('local-app', null)), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(relabel('local-app', null, { hash: true })), /invalid-run-evidence/, 'limitations still name the forwarder');
  const consistent = relabel('local-app', null, { hash: true, limitations: true });
  validateHttpRunEvidence(consistent);
  assert.throws(() => validateHttpRunEvidence(consistent, { expectedSuite: suite }), /unexpected-suite-evidence/);
  assert.equal(summarizeGate({ candidate: consistent, expectedSuite: suite }).exitCode, 2);
  // A renamed target.
  assert.throws(() => validateHttpRunEvidence(relabel('operator-forwarded', 'Acme production')), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(relabel('operator-forwarded', 'Acme production', { hash: true }), { expectedSuite: suite }), /unexpected-suite-evidence/);
});

test('v3 exports say "response contracts plus authoritative backend observation"; v1/v2 gate summaries carry no target context', async t => {
  const app = await probeApp(t, { mode: 'none' });
  const run = await runHttpAssessment(profile(app, [audit(app, { settleMs: 250 })], [editOther]), { env });
  const gate = summarizeGate({ candidate: run, baseline: run });
  assert.equal(gate.current.evidenceScope, 'response-plus-observed-backend');
  assert.match(gate.current.interpretation, /^HTTP response contracts plus authoritative backend observation for rows marked observed/);
  assert.equal(gate.current.targetContext, 'local-app');
  // The run compared with itself restores nothing, so it carries no repair label; its scope is the interpretation above.
  assert.equal(gate.comparison.restorationLabel, 'No verified repair');
  const compared = compareRuns(run, run);
  assert.match(compared.evidenceScope, /^Response contracts plus authoritative backend observation for rows marked observed/);
  assert.match(buildReport({ runInput: run, env: {} }).markdown, /\*\*Scope:\*\* Response contracts plus authoritative backend observation for rows marked observed/);
  // A v1-labelled run of the same shape (no effects, no context fields) keeps the earlier gate summary keys.
  const bare = profile(app, [], []); delete bare.observers;
  const plain = await runHttpAssessment(bare, { env });
  const v1 = structuredClone(plain);
  Object.assign(v1, { adapterVersion: 'loopback-response-contract/1', assertionSchemaVersion: 'http-contract/2' });
  for (const key of ['targetContext', 'targetLabel', 'identityEvidence', 'principals']) delete v1[key];
  for (const r of v1.results) { delete r.decision; r.assertions = r.assertions.filter(a => a.name !== 'Actor identity established'); if (r.status === 'inconclusive' && r.assertions.every(a => a.status === 'pass')) r.status = 'pass'; delete r.trace[0].data.credentialMode; delete r.trace[0].data.routeSegments; delete r.trace[0].data.controlScope; delete r.trace[0].data.requestTimeoutMs; r.evidenceDigest = digest({ evidence: r.trace[0].data, assertions: r.assertions }); }
  recount(v1);
  const v1Gate = summarizeGate({ candidate: v1 });
  assert.notEqual(v1Gate.current, null, JSON.stringify(v1Gate.reasons));
  assert.ok(!Object.hasOwn(v1Gate.current, 'targetContext') && !Object.hasOwn(v1Gate.current, 'targetLabel'));
  assert.equal(v1Gate.current.evidenceScope, 'response-only');
});

test('the factory derives instance ids, refuses duplicate ids and never takes lockFallback from a configuration', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-factory-'));
  try {
    const db = join(dir, 'a.db'); new DatabaseSync(db).close();
    assert.deepEqual(buildObservers([{ id: 'app', type: 'sqlite-snapshot', path: db, tables: [{ table: 'sqlite_master', key: 'name' }] }, { type: 'sqlite-snapshot', path: db, tables: [{ table: 'sqlite_master', key: 'name' }] }]).map(o => o.instanceId), ['sqlite-snapshot-app', 'sqlite-snapshot-2']);
    assert.throws(() => buildObservers([{ id: 'a', type: 'sqlite-snapshot', path: db, tables: [] }, { id: 'a', type: 'sqlite-audit', path: db }]), /unique "id"/);
    assert.throws(() => buildObservers([{ id: '../x', type: 'sqlite-snapshot', path: db, tables: [] }]), /unique "id"/);
    assert.throws(() => buildObservers([{ id: 'a', type: 'sqlite-snapshot', path: db, tables: [], lockFallback: true }]), /lockFallback cannot be set/);
    // Sequence configurations go through the same factory.
    assert.throws(() => buildSequenceObservers([{ id: 'x', type: 'otel', port: 0, services: ['s'] }, { id: 'x', type: 'otel', port: 0, services: ['s'] }]), /unique "id"/);
    assert.throws(() => buildSequenceObservers([{ type: 'sqlite-snapshot', path: db, tables: [], lockFallback: true }]), /lockFallback cannot be set/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a commit later than settleMs can land in the next check\'s window; pinning a resource keeps effect.exists honest', async t => {
  const app = await probeApp(t, { mode: 'none' });
  // LATE-EDIT answers 403 and commits note.update for notes/other 800 ms later; the settle is only 500 ms.
  const lateEdit = { ...editOther, id: 'LATE-EDIT', path: '/late-edit' };
  const ownEdit = select => ({ id: 'OWN-EDIT', title: 'An allowed edit is committed', category: 'allowed-use', severity: 'high', actorId: 'member', method: 'POST', path: '/ping', body: {}, evidenceRequirement: 'backend',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select }] });
  const timers = new Set();
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(res, 401, {});
    if (req.url === '/me') return json(res, 200, { user: 'member-1' });
    if (req.url === '/late-edit') { json(res, 403, {}); const timer = setTimeout(() => { timers.delete(timer); app.db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run('member-1', 'note.update', 'notes/other'); }, 800); timers.add(timer); return; }
    json(res, 200, { ok: true }); // the allowed edit: the app does nothing
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { for (const timer of timers) clearTimeout(timer); await new Promise(r => { server.close(r); server.closeAllConnections(); }); });
  const origin = `http://127.0.0.1:${server.address().port}`;
  const run = select => runHttpAssessment({ ...profile(app, [audit(app, { settleMs: 500 })], [lateEdit, ownEdit(select)]), origin }, { env });
  const unpinned = await run({ source: 'sql-audit-table', name: 'note.update' });
  assert.match(unpinned.scopeLabel, /withholds the pass as inconclusive \(effect-outside-window\); so does an effect\.exists or effect\.count pass whose matched effect also fits an earlier check's selector \(effect-ambiguous-attribution\)/);
  // The disclosed mis-attribution: the late commit decides OWN-EDIT's effect.exists (matched 1). The audit row is the
  // app's own record and OWN-EDIT is a boundary check (severity high), so custody holds it at inconclusive.
  assert.equal(row(unpinned, 'OWN-EDIT').trace[1].data.effects[0].matched, 1, 'the disclosed mis-attribution');
  assert.deepEqual([row(unpinned, 'OWN-EDIT').status, assertion(row(unpinned, 'OWN-EDIT'), 'Observed effect 1').custodyReason], ['inconclusive', 'subject-writable-custody']);
  await new Promise(r => setTimeout(r, 900));
  const pinned = await run({ source: 'sql-audit-table', name: 'note.update', resource: 'notes/own' });
  assert.equal(row(pinned, 'OWN-EDIT').status, 'fail');
  await new Promise(r => setTimeout(r, 900));
});
