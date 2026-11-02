// The Supabase identity rules wired into the run: a target's "supabaseRules" (src/contracts.mjs), the rules' resolver
// passed by the factory to the actor capture, the service-role note on a pinned clause, and rls-zero-row judged per allowed-use control
// after its window, FAIL-only (src/http-effects.mjs). End to end through runHttpAssessment and the shared validator, against a scripted
// fake Postgres whose actor capture is answered through scriptedDb's answer hook (no real database).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile, withheldAfterSend, PRECONDITION_ASSERTION, PRECONDITION_REASONS } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { ZERO_ROW_SCHEMA, zeroRowFinding, decideEffects, serviceRoleToolsSeen, recomputeEffectTrace, responseContractSucceeded } from '../src/http-effects.mjs';
import { installSql, verifyAtInstall, parseLedger, PG_ACTOR_SCHEMA } from '../integrations/observers/pg-actor.mjs';
import { ZERO_ROW_FACTS_SCHEMA, zeroRowFacts, rlsZeroRow, supabaseResolver } from '../integrations/observers/supabase-rules.mjs';
import { scriptedDb, USER, PASSWORD } from '../integrations/observers/fixtures/fake-postgres.mjs';

const TOKEN = 'synthetic-bob-token', BOB = 'b0b00000-0000-4000-8000-000000000002', EVE = 'e0e00000-0000-4000-8000-000000000005';
const env = { SCOPEHAVEN_TARGET_BOB: TOKEN, SCOPEHAVEN_TARGET_DB_READER: `${USER}:${PASSWORD}` };
const BLOCK = Object.freeze({ testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', tables: [{ table: 'orders', key: 'id' }], actor: { from: 'jwt-claims' }, principals: { [BOB]: 'bob', [EVE]: 'eve' } });
const RULES = Object.freeze({ tool: 'refund-agent', allowedWrites: { REFUND: { table: 'public.orders', op: 'UPDATE' } } });
// The capture's definitions as an intact installation answers them (the shape pg-actor.test.mjs uses), and their installation digest.
const NAMES = installSql(BLOCK).filter(s => s.startsWith('CREATE TRIGGER')).map(s => [s.split(' ')[2], s.split(' ')[6].replaceAll('"', '')]);
const INTACT = [
  [['supabase_admin:true', '{supabase_admin=UC/supabase_admin}', PG_ACTOR_SCHEMA, '900']],
  [['capture', '', 'true', '{"search_path=pg_catalog, pg_temp"}', 'f1', 'supabase_admin:true', '{supabase_admin=X/supabase_admin}', '901', 'v'], ['ledger', 'after_seq bigint, max_rows integer', 'true', '{"search_path=pg_catalog, pg_temp"}', 'f2', 'supabase_admin:true', '{supabase_admin=X/supabase_admin}', '902', 's']],
  NAMES.map(([name, table]) => [table, name, 'O', '29', '6964', '', '', 'true', '', 'capture', '903']).sort((x, y) => (`${x[0]}|${x[1]}` < `${y[0]}|${y[1]}` ? -1 : 1)),
  [['true', 'false', 'p', 'r', '0', '0', '0', 'supabase_admin:true', '{supabase_admin=arwdDxtm/supabase_admin}']],
  'seq,txid,tbl,key,op,rowcount,depth,row_xmin,claims_sub,claims_role,legacy_sub,header_sub,set_role,session_role,app_actor,at'.split(',').map(c => [c, 'text']),
];
const SHA = verifyAtInstall(INTACT.map(rows => ({ rows })), BLOCK).sha256;
const VERIFY = ['SELECT (SELECT r.rolname'];
// One ledger row, as PostgREST binds a signed-in user's request (an authenticator login, SET ROLE authenticated).
let seq = 0;
const entry = (over = {}) => { seq += 1; const r = { seq: String(seq), txid: String(4294968396 + seq), xid32: String(1100 + seq), tbl: 'public.orders', key: 'o1', op: 'UPDATE', rowcount: null, depth: '1', row_xmin: String(1100 + seq),
  claims_sub: BOB, claims_role: 'authenticated', legacy_sub: null, header_sub: undefined, set_role: 'authenticated', session_role: 'authenticator', app_actor: null, ...over };
  if (r.header_sub === undefined) r.header_sub = r.claims_sub; return Object.values(r); };
const zeroRowOf = (over = {}) => entry({ key: null, rowcount: '0', row_xmin: null, ...over });
const serviceWrite = (over = {}) => entry({ claims_sub: null, claims_role: 'service_role', header_sub: null, set_role: 'service_role', ...over });

// A scripted database: the orders table (its row version in db.xmin), every mark a new snapshot (never quiescent, so a table-wide
// absence is never decided), and the capture answered as intact (or not) with db.ledger. db.write() commits a new row version between
// the last mark and the next (inside the check's window) and returns it.
async function database(t, { intact = true } = {}) {
  const db = { ledger: [], xmin: '700', marks: 0, write() { db.xmin = String(1000 + 100 * db.marks + 50); return db.xmin; } };
  const server = await scriptedDb(t, [], [], { beginState: mark => { db.marks = mark; return { snapshot: `${1000 + 100 * mark}:${1000 + 100 * mark}:`, tables: { orders: [['o1', db.xmin, 'h1']] } }; },
    // The capture's definitions arrive as one statement list (pg-actor verifySql): five result sets, or none of its objects.
    answer: statement => { if (statement.startsWith(VERIFY[0])) return { results: intact ? INTACT : INTACT.map(() => []) }; if (statement.includes('l.seq::pg_catalog.text')) return [...db.ledger]; return undefined; } });
  return Object.assign(db, { port: server.port });
}
async function app(t, onRefund, refundBody = { ok: true }) {
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return reply(401, {});
    if (req.url === '/me') return reply(200, { user: 'bob' });
    if (req.method === 'PATCH' && req.url === '/orders/o1') { onRefund(); return reply(200, refundBody); }
    reply(404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const observer = (port, extra = {}) => ({ id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables: [{ table: 'orders', key: 'id' }], settleMs: 250,
  actorCapture: { block: structuredClone(BLOCK), installedSha256: SHA }, ...extra });
const refund = (effects = [{ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'orders', operation: 'update', actor: 'bob' } }]) => ({ id: 'REFUND', title: 'Bob refunds his own order', category: 'allowed-use', severity: 'control', actorId: 'bob',
  method: 'PATCH', path: '/orders/o1', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/ok', expected: true }], effects });
const profile = (origin, observers, { rules = RULES, checks = [refund()] } = {}) => ({ id: 'refunds', name: 'Refunds', applicationId: 'refunds-app', origin, buildLabel: 'b1', contextId: 'synthetic-refunds',
  actors: { bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' }, eve: { principalId: 'eve' } }, requiredControlIds: ['WHOAMI'], observers, ...(rules ? { supabaseRules: rules } : {}),
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'bob', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'bob' }] }, ...checks] });
const load = target => validateTargetFile({ schemaVersion: 1, targets: [target] })[0];
const rowOf = (run, id) => run.results.find(r => r.id === id);
async function runWith(t, onRefund, { intact, rules, checks, refundBody } = {}) {
  const db = await database(t, { intact }), origin = await app(t, () => onRefund(db), refundBody);
  const p = profile(origin, [observer(db.port)], { rules, checks });
  const run = await runHttpAssessment(p, { env });
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
  return { run, p, db };
}
// A sealed run edited in a test is resealed (its row digest recomputed), so only the validator's recompute can refuse it.
const reseal = row => { row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); };

test('supabaseRules: a tool, service roles, a pass-through and allowed writes, over a declared actor capture', () => {
  const ok = load(profile('http://127.0.0.1:4000', [observer(5432)]));
  assert.deepEqual(ok.supabaseRules, RULES);
  const reject = (edit, pattern) => { const p = profile('http://127.0.0.1:4000', [observer(5432)], { rules: structuredClone(RULES) }); edit(p); assert.throws(() => load(p), pattern); };
  reject(p => { p.supabaseRules.extra = 1; }, /"supabaseRules": is \{ tool, serviceRoles\?, passThrough\?, allowedWrites\? \}/);
  reject(p => { p.supabaseRules.tool = 'refund agent'; }, /"tool" names the server-side identity/);
  reject(p => { p.supabaseRules.serviceRoles = ['service_role', 'service_role']; }, /"serviceRoles" lists 1 to 8 distinct role names/);
  reject(p => { p.supabaseRules.passThrough = { from: 'header' }; }, /"passThrough" is/);
  reject(p => { p.supabaseRules.passThrough = { from: 'column' }; }, /needs every captured table's "actorColumn"/);
  reject(p => { delete p.observers[0].actorCapture; }, /declare "actorCapture" on a pg-snapshot or pg-wal observer/);
  reject(p => { p.supabaseRules.allowedWrites = { WHOAMI: { table: 'public.orders', op: 'UPDATE' } }; }, /an allowed-use control that writes/);
  reject(p => { p.supabaseRules.allowedWrites = { NOPE: { table: 'public.orders', op: 'UPDATE' } }; }, /an allowed-use control that writes/);
  reject(p => { p.supabaseRules.allowedWrites.REFUND.op = 'INSERT'; }, /"op": "UPDATE" \| "DELETE"/);
  reject(p => { p.supabaseRules.allowedWrites.REFUND.table = 'orders'; }, /"table": "schema.table"/);
  reject(p => { p.supabaseRules.allowedWrites.REFUND.table = 'billing.orders'; }, /captured by exactly one pg-snapshot observer's actor capture/);
  reject(p => { p.observers[0].tables = [{ table: 'orders', key: 'id', schema: 'billing' }]; }, /one its capturing observer reads/);
  reject(p => { p.checks[1].effects = [{ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'orders', operation: 'delete' } }]; }, /declares a positive clause on its write/);
  reject(p => { p.checks[1].effects = [{ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'orders', operation: 'insert' } }, { kind: 'effect.count', select: { source: 'sql-snapshot', name: 'orders', operation: 'update' }, expected: 0 }]; }, /positive clause|positive/);
  // Declarations under which the rule could never fire are refused: an actor read from an app column (a statement
  // that changed no row records none), a control actor without a credential, a control principal the capture does not map.
  reject(p => { p.observers[0].actorCapture.block = { ...p.observers[0].actorCapture.block, actor: { from: 'column' }, tables: [{ table: 'orders', key: 'id', actorColumn: 'made_by' }] }; }, /names its actors from "jwt-claims" or "current-user"/);
  reject(p => { p.actors.bob = { principalId: 'bob' }; }, /control's actor is credentialed/);
  reject(p => { p.observers[0].actorCapture.block = { ...p.observers[0].actorCapture.block, principals: { [EVE]: 'eve' } }; }, /control's principal is one its capture maps/);
  // The rules are in the profile's digest when declared, and only then.
  const hashOf = target => createRegistry({ profiles: [load(target)], env }).exportSuite(target.id).hash;
  const base = profile('http://127.0.0.1:4000', [observer(5432)]), without = profile('http://127.0.0.1:4000', [observer(5432)], { rules: null });
  const other = profile('http://127.0.0.1:4000', [observer(5432)], { rules: { ...RULES, tool: 'refund-desk' } });
  assert.equal(new Set([hashOf(base), hashOf(without), hashOf(other)]).size, 3);
  // The exported suite names the declared write and its capturing observer on that control only.
  const suite = createRegistry({ profiles: [ok], env }).exportSuite(ok.id);
  assert.deepEqual(suite.checks.map(c => [c.id, c.zeroRow ?? null]), [['WHOAMI', null], ['REFUND', { table: 'public.orders', op: 'UPDATE', instanceId: 'pg-snapshot-db' }]]);
});

test('rls-zero-row: the control\'s own UPDATE changed no row although the app reported success, so its positive clause fails', async t => {
  const { run } = await runWith(t, db => { db.ledger.push(zeroRowOf()); });
  const r = rowOf(run, 'REFUND'), [clause] = r.trace[1].data.effects, sealed = r.trace[1].data.zeroRow;
  assert.equal(r.status, 'fail');
  assert.deepEqual([clause.verdict, clause.zeroRow.finding, clause.zeroRow.priorVerdict, clause.zeroRow.table, clause.zeroRow.op], ['fail', 'rls-zero-row', 'missing', 'public.orders', 'UPDATE']);
  assert.match(r.assertions.find(a => a.name.startsWith('Observed effect 1')).actual, /rls-zero-row: the allowed-use control's declared UPDATE on public\.orders changed no row/);
  assert.deepEqual(sealed.expect, { table: 'public.orders', op: 'UPDATE' });
  assert.equal(sealed.instanceId, 'pg-snapshot-db');
  assert.deepEqual([sealed.facts.schema, sealed.facts.capture, sealed.facts.statements, sealed.facts.writes], [ZERO_ROW_SCHEMA, 'intact', [{ table: 'public.orders', op: 'UPDATE', actor: 'bob', serviceRole: false, depth: 1 }], []]);
  // The rule is FAIL-only: the window alone read missing, never a pass. The failed control is not a required one, so the identity
  // control still passes.
  assert.equal(rowOf(run, 'WHOAMI').status, 'pass');
  // A control that requires backend evidence: its backend assertion is not part of the response contract the rule reads.
  const backend = await runWith(t, db => { db.ledger.push(zeroRowOf()); }, { checks: [{ ...refund(), evidenceRequirement: 'backend' }] });
  assert.deepEqual([rowOf(backend.run, 'REFUND').status, rowOf(backend.run, 'REFUND').trace[1].data.effects[0].zeroRow?.finding], ['fail', 'rls-zero-row']);
});

test('rls-zero-row never fails a write that happened, a refusal the app surfaced, another actor\'s or a service-role statement, or an unverified capture', async t => {
  // The write happened: a row version moved and bob's UPDATE changed it, so the clause passes on the window, as without the rules.
  const made = await runWith(t, db => { db.ledger.push(zeroRowOf(), entry({ row_xmin: db.write() })); });
  assert.deepEqual(rowOf(made.run, 'REFUND').trace[1].data.windows[0].events.map(e => [e.operation, e.resource, e.actor]), [['update', 'orders/o1', 'bob']]);
  assert.deepEqual([rowOf(made.run, 'REFUND').trace[1].data.effects[0].verdict, rowOf(made.run, 'REFUND').trace[1].data.effects[0].zeroRow, rowOf(made.run, 'REFUND').status], ['pass', undefined, 'pass']);
  // The app answered without the success the contract declares: the response decided nothing, so the clause stays as the window read it.
  const refused = await runWith(t, db => { db.ledger.push(zeroRowOf()); }, { refundBody: { ok: false } });
  assert.deepEqual([rowOf(refused.run, 'REFUND').trace[1].data.effects[0].verdict, rowOf(refused.run, 'REFUND').trace[1].data.effects[0].zeroRow], ['missing', undefined]);
  // Another principal's zero-row statement, and the tool's (service role), are not bob's write.
  for (const statement of [() => zeroRowOf({ claims_sub: EVE, header_sub: EVE }), () => serviceWrite({ key: null, rowcount: '0', row_xmin: null })]) {
    const other = await runWith(t, db => { db.ledger.push(statement()); });
    assert.deepEqual([rowOf(other.run, 'REFUND').trace[1].data.effects[0].verdict, rowOf(other.run, 'REFUND').trace[1].data.effects[0].zeroRow], ['missing', undefined]);
  }
  // The tool made the write (bob's statement matched nothing, the service role's changed the row): not a refusal.
  const tool = await runWith(t, db => { db.ledger.push(zeroRowOf(), serviceWrite({ row_xmin: db.write() })); });
  assert.equal(rowOf(tool.run, 'REFUND').trace[1].data.effects[0].zeroRow, undefined);
  // A write no one is named for (a backend session that is not a declared service role, claims unbound) may be the control's own: no
  // FAIL.
  const backend = await runWith(t, db => { db.ledger.push(zeroRowOf(), entry({ claims_sub: null, claims_role: null, header_sub: null, set_role: 'none', session_role: 'app_backend', row_xmin: db.write() })); });
  assert.deepEqual(rowOf(backend.run, 'REFUND').trace[1].data.zeroRow.facts.writes, [{ table: 'public.orders', op: 'UPDATE', actor: null, serviceRole: false }]);
  assert.equal(rowOf(backend.run, 'REFUND').trace[1].data.effects[0].zeroRow, undefined);
  // A capture that did not verify: nothing is attributed and nothing fails on it.
  const blind = await runWith(t, db => { db.ledger.push(zeroRowOf()); }, { intact: false });
  assert.deepEqual([rowOf(blind.run, 'REFUND').trace[1].data.zeroRow.facts.capture, rowOf(blind.run, 'REFUND').trace[1].data.effects[0].verdict], ['absent', 'missing']);
});

test('service-role writes: the tool\'s write is never bob\'s, and the pinned clause says so', async t => {
  const { run } = await runWith(t, db => { db.ledger.push(serviceWrite({ row_xmin: db.write() })); });
  const r = rowOf(run, 'REFUND'), w = r.trace[1].data.windows[0];
  assert.deepEqual(w.events.map(e => [e.operation, e.resource, e.actor]), [['update', 'orders/o1', 'unlisted:tool:refund-agent']]);
  assert.equal(r.trace[1].data.effects[0].verdict, 'missing');
  assert.match(r.assertions.find(a => a.name.startsWith('Observed effect 1')).actual, /made with a service role by refund-agent, which carries no end user, so it is never bob's \(service-role-write\)/);
  // Without the rules the same write is unlisted (the capture's own resolver reads the service role's claims as no user).
  const plain = await runWith(t, db => { db.ledger.push(serviceWrite({ row_xmin: db.write() })); }, { rules: null });
  assert.equal(rowOf(plain.run, 'REFUND').trace[1].data.windows[0].events[0].actor, null);
  assert.doesNotMatch(rowOf(plain.run, 'REFUND').assertions.find(a => a.name.startsWith('Observed effect 1')).actual, /service role/);
});

test('the validator recomputes the stage from the sealed record: a dropped, forged or misplaced finding is refused', async t => {
  const { run, p } = await runWith(t, db => { db.ledger.push(zeroRowOf()); });
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  const forge = edit => { const copy = structuredClone(run), row = rowOf(copy, 'REFUND'); edit(row, copy); reseal(row); return copy; };
  // The finding dropped from the clause (and its text), the facts emptied, or the record moved to a boundary row: refused.
  assert.throws(() => validateHttpRunEvidence(forge(row => { const c = row.trace[1].data.effects[0]; delete c.zeroRow; c.verdict = 'missing'; }), { expectedSuite: suite }), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(forge(row => { row.trace[1].data.zeroRow.facts.statements = []; }), { expectedSuite: suite }), /invalid-run-evidence/);
  // The verdict kept and only the finding's record rewritten (what it names, or the verdict the window had reached): refused.
  assert.throws(() => validateHttpRunEvidence(forge(row => { row.trace[1].data.effects[0].zeroRow.alsoWrittenBy = ['eve']; }), { expectedSuite: suite }), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(forge(row => { row.trace[1].data.effects[0].zeroRow.priorVerdict = 'pass'; }), { expectedSuite: suite }), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(forge(row => { row.trace[1].data.zeroRow.facts.capture = 'altered'; }), { expectedSuite: suite }), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(forge(row => { row.trace[1].data.zeroRow.instanceId = 'pg-snapshot-other'; }), { expectedSuite: suite }), /invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(forge((row, copy) => { const who = rowOf(copy, 'WHOAMI'); who.trace = [...who.trace, structuredClone(row.trace[1])]; reseal(who); }), { expectedSuite: suite }), /invalid-run-evidence/);
  validateHttpRunEvidence(run, { expectedSuite: suite });
  // The record bound to the declaration: in a run where the write happened (no finding), dropping the record
  // changes no decision, so only the suite binding refuses it; and facts that contradict the window (bob's write left out) are refused.
  const made = await runWith(t, db => { db.ledger.push(zeroRowOf(), entry({ row_xmin: db.write() })); });
  const madeSuite = createRegistry({ profiles: [made.p], env }).exportSuite(made.p.id);
  const strip = edit => { const copy = structuredClone(made.run), row = rowOf(copy, 'REFUND'); edit(row); reseal(row); return copy; };
  assert.throws(() => validateHttpRunEvidence(strip(row => { delete row.trace[1].data.zeroRow; }), { expectedSuite: madeSuite }), /unexpected-suite-evidence|invalid-run-evidence/);
  assert.throws(() => validateHttpRunEvidence(strip(row => { row.trace[1].data.zeroRow.facts.writes = []; }), { expectedSuite: madeSuite }), /invalid-run-evidence/);
  validateHttpRunEvidence(made.run, { expectedSuite: madeSuite });
  // Only eve wrote in the window (no statement of bob's): dropping her write from the facts changes no decision, so only the check
  // against the window refuses it.
  const evesOnly = await runWith(t, db => { db.ledger.push(entry({ claims_sub: EVE, header_sub: EVE, row_xmin: db.write() })); });
  assert.deepEqual(rowOf(evesOnly.run, 'REFUND').trace[1].data.windows[0].events.map(e => e.actor), ['eve']);
  const dropped = structuredClone(evesOnly.run), dr = rowOf(dropped, 'REFUND'); dr.trace[1].data.zeroRow.facts.writes = []; reseal(dr);
  assert.throws(() => validateHttpRunEvidence(dropped, { expectedSuite: createRegistry({ profiles: [evesOnly.p], env }).exportSuite(evesOnly.p.id) }), /invalid-run-evidence/);
  // The trace's own recompute compares the stage's record: the clause's tag rewritten, its verdict kept, reads effect-verdict there.
  const row = rowOf(run, 'REFUND'), context = { principal: 'bob', method: 'PATCH', succeeded: responseContractSucceeded(row) };
  assert.doesNotThrow(() => recomputeEffectTrace(row.trace[1], refund().effects, run.observers, { role: 'control', zeroRow: context }));
  const tagged = structuredClone(row.trace[1]); tagged.data.effects[0].zeroRow.priorVerdict = 'inconclusive';
  assert.throws(() => recomputeEffectTrace(tagged, refund().effects, run.observers, { role: 'control', zeroRow: context }), /effect-verdict/);
});

test('without supabaseRules nothing is sealed and nothing is judged; the collector facts and the evaluator agree with the rules module', async t => {
  const { run } = await runWith(t, db => { db.ledger.push(zeroRowOf()); }, { rules: null });
  const r = rowOf(run, 'REFUND');
  assert.deepEqual([r.trace[1].data.zeroRow, r.trace[1].data.effects[0].verdict], [undefined, 'missing']);
  assert.equal(ZERO_ROW_SCHEMA, ZERO_ROW_FACTS_SCHEMA);
  // Parity with rlsZeroRow over the same window: the facts the collector seals and the evaluator's finding reach its verdict.
  const entries = parseLedger([zeroRowOf(), entry({ claims_sub: EVE, header_sub: EVE })]), resolve = supabaseResolver(RULES);
  const facts = zeroRowFacts({ entries, block: BLOCK, capture: 'intact', resolve });
  const check = refund(), row = { assertions: [{ name: 'HTTP status matches contract', status: 'pass' }], observed: { complete: true } };
  const reading = rlsZeroRow({ check, row, entries, block: BLOCK, capture: 'intact', actors: { bob: { principalId: 'bob' } }, decl: RULES });
  const finding = zeroRowFinding({ instanceId: 'pg-snapshot-db', expect: RULES.allowedWrites.REFUND, facts }, { principal: 'bob', role: 'control', method: 'PATCH', succeeded: true });
  assert.deepEqual([reading.verdict, finding?.finding, finding?.alsoWrittenBy], ['fail', 'rls-zero-row', ['eve']]);
  // A write no one is named for suppresses the FAIL in both.
  const unnamed = parseLedger([zeroRowOf(), entry({ claims_sub: null, claims_role: null, header_sub: null, set_role: 'none', session_role: 'app_backend' })]);
  const unnamedFacts = zeroRowFacts({ entries: unnamed, block: BLOCK, capture: 'intact', resolve });
  assert.notEqual(rlsZeroRow({ check, row, entries: unnamed, block: BLOCK, capture: 'intact', actors: { bob: { principalId: 'bob' } }, decl: RULES }).verdict, 'fail');
  assert.equal(zeroRowFinding({ instanceId: 'pg-snapshot-db', expect: RULES.allowedWrites.REFUND, facts: unnamedFacts }, { principal: 'bob', role: 'control', method: 'PATCH', succeeded: true }), null);
});

test('the service-role note: only on a pinned clause that reads missing, only from Postgres windows that name principals', () => {
  const window = (instanceId, events, attribution = 'principal') => ({ source: 'sql-snapshot', instanceId, scope: { operations: ['insert', 'update', 'delete'], names: ['orders'], actorAttribution: attribution, evidence: 'authoritative' },
    coverage: 'partial', reason: 'shared-database', events });
  const event = (actor, seq = 1) => ({ schema: 'scopehaven-effect/1', source: 'sql-snapshot', observer: { kind: 'postgres-snapshot-diff', instanceId: 'pg-snapshot-db' }, seq, observedAt: '2026-10-25T00:00:00.000Z', actor, operation: 'update', name: 'orders', resource: 'orders/o1', outcome: 'committed', content: null, correlation: {} });
  const pinned = { kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'orders', operation: 'update', actor: 'bob' } };
  const tool = event('unlisted:tool:refund-agent');
  assert.deepEqual(serviceRoleToolsSeen(pinned.select, [window('pg-snapshot-db', [tool])]), ['refund-agent']);
  // Not from an instance that is not a Postgres observer's, nor from one that names no principal; never for an unpinned clause.
  assert.deepEqual(serviceRoleToolsSeen(pinned.select, [window('app-log-actions', [tool])]), []);
  assert.deepEqual(serviceRoleToolsSeen(pinned.select, [window('pg-snapshot-db', [tool], 'none')]), []);
  assert.deepEqual(serviceRoleToolsSeen({ ...pinned.select, actor: undefined }, [window('pg-snapshot-db', [tool])]), []);
  // Through decideEffects: a missing pinned clause carries it; one its own actor's write decides carries none.
  const [missing] = decideEffects([pinned], [window('pg-snapshot-db', [tool])], { role: 'control' });
  assert.deepEqual([missing.verdict, missing.serviceRoleSeen], ['missing', ['refund-agent']]);
  const [decided] = decideEffects([pinned], [window('pg-snapshot-db', [tool, event('bob', 2)])], { role: 'control' });
  assert.deepEqual([decided.verdict, decided.serviceRoleSeen], ['pass', undefined]);
});

test('the zero-row facts: an upsert or a MERGE that changed another row of the table in the same transaction is no refusal; an unverified capture lists nothing', () => {
  const resolve = supabaseResolver(RULES);
  const txid = '4294969999', xid32 = String(4294969999 % 4294967296);
  const upsert = parseLedger([zeroRowOf({ txid, xid32 }), entry({ op: 'INSERT', key: 'o2', txid, xid32 })]);
  assert.deepEqual(zeroRowFacts({ entries: upsert, block: BLOCK, capture: 'intact', resolve }).statements, []);
  const apart = parseLedger([zeroRowOf(), entry({ op: 'INSERT', key: 'o2' })]);
  assert.equal(zeroRowFacts({ entries: apart, block: BLOCK, capture: 'intact', resolve }).statements.length, 1);
  for (const capture of ['absent', 'altered', 'unreadable', 'bogus']) {
    const facts = zeroRowFacts({ entries: apart, block: BLOCK, capture, resolve });
    assert.deepEqual([facts.capture, facts.statements, facts.writes], [capture === 'bogus' ? 'unreadable' : capture, [], []], capture);
  }
  // The evaluator never fails on facts a capture did not verify, even if a record listed some.
  const listed = zeroRowFacts({ entries: apart, block: BLOCK, capture: 'intact', resolve });
  assert.equal(zeroRowFinding({ instanceId: 'pg-snapshot-db', expect: RULES.allowedWrites.REFUND, facts: { ...listed, capture: 'altered' } }, { principal: 'bob', role: 'control', method: 'PATCH', succeeded: true }), null);
  // Nor when a write it would have to rule out was left unlisted.
  assert.equal(zeroRowFinding({ instanceId: 'pg-snapshot-db', expect: RULES.allowedWrites.REFUND, facts: { ...listed, omitted: { statements: 0, writes: 1 } } }, { principal: 'bob', role: 'control', method: 'PATCH', succeeded: true }), null);
});

// A lifecycle change check whose declared write changed no row although another write matched its clause passed
// when sent, so its post-change check was sent; the stage then fails it at run end, the post-change check reads change-not-attributed,
// and the validator accepts the run.
async function suspension(t, { otherWrite }) {
  const EVE_TOKEN = 'synthetic-eve-token', db = await database(t);
  let suspended = false;
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    const who = req.headers.authorization === `Bearer ${TOKEN}` ? 'bob' : req.headers.authorization === `Bearer ${EVE_TOKEN}` ? 'eve' : null;
    if (!who || (who === 'eve' && suspended && req.url === '/notes')) return reply(403, {});
    if (req.url === '/me') return reply(200, { user: who });
    if (req.method === 'PATCH' && req.url === '/users/eve/suspend') {
      // bob's own UPDATE matches no row; eve's own write of an order commits in the same window, so the unpinned clause matches it.
      suspended = true; db.ledger.push(zeroRowOf(), ...(otherWrite ? [entry({ claims_sub: EVE, header_sub: EVE, row_xmin: db.write() })] : []));
      return reply(200, { ok: true });
    }
    reply(200, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  const me = (id, actorId) => ({ id, title: id, category: 'identity', severity: 'control', actorId, method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: actorId }] });
  const p = { id: 'suspends', name: 'Suspends', applicationId: 'suspends-app', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'b1', contextId: 'synthetic-suspends',
    actors: { bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' }, eve: { principalId: 'eve', credentialEnv: 'SCOPEHAVEN_TARGET_EVE', identityValue: 'eve' } },
    observers: [observer(db.port)], supabaseRules: { tool: 'refund-agent', allowedWrites: { SUSPEND: { table: 'public.orders', op: 'UPDATE' } } },
    requiredControlIds: ['BOB-ME', 'EVE-ME', 'EVE-NOTES', 'SUSPEND'], lifecycle: [{ changeCheckId: 'SUSPEND', actorId: 'eve', after: 'refused' }],
    checks: [me('BOB-ME', 'bob'), me('EVE-ME', 'eve'),
      { id: 'EVE-NOTES', title: 'Eve reads her notes', category: 'allowed-use', severity: 'control', actorId: 'eve', method: 'GET', path: '/notes', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'SUSPEND', title: 'Bob suspends eve', category: 'allowed-use', severity: 'control', actorId: 'bob', method: 'PATCH', path: '/users/eve/suspend', evidenceRequirement: 'response',
        assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/ok', expected: true }], effects: [{ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'orders', operation: 'update' } }] },
      { id: 'REUSE', title: 'Eve is refused after the suspension', category: 'lifecycle', severity: 'high', actorId: 'eve', method: 'GET', path: '/notes', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [401, 403] }],
        effects: [{ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'orders', operation: 'update', resource: 'orders/o1' } }] }] };
  const env2 = { ...env, SCOPEHAVEN_TARGET_EVE: EVE_TOKEN };
  const run = await runHttpAssessment(p, { env: env2 });
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: env2 }).exportSuite(p.id) });
  return run;
}
test('a lifecycle change check failed by rls-zero-row keeps the run valid; its post-change check reads change-not-attributed', async t => {
  const run = await suspension(t, { otherWrite: true });
  const suspend = rowOf(run, 'SUSPEND');
  assert.deepEqual([suspend.status, suspend.trace[1].data.effects[0].zeroRow?.finding, suspend.trace[1].data.effects[0].zeroRow?.priorVerdict, suspend.trace[1].data.effects[0].zeroRow?.alsoWrittenBy], ['fail', 'rls-zero-row', 'pass', ['eve']]);
  const reuse = rowOf(run, 'REUSE');
  assert.ok(reuse.assertions.some(a => a.name === PRECONDITION_ASSERTION && a.actual === PRECONDITION_REASONS['change-not-attributed']), JSON.stringify(reuse.assertions.map(a => [a.name, a.status])));
});
// The rule's main case. The change check's own UPDATE matched nothing and no other write matched its clause, so it read
// missing when sent: never confirmed, its post-change check was not sent (change-not-confirmed), and the stage's FAIL keeps the run valid.
test('a lifecycle change check that read missing when sent and then fails on rls-zero-row keeps the run valid; its post-change check was not sent', async t => {
  const run = await suspension(t, { otherWrite: false });
  const suspend = rowOf(run, 'SUSPEND');
  assert.deepEqual([suspend.status, suspend.trace[1].data.effects[0].zeroRow?.priorVerdict], ['fail', 'missing']);
  const reuse = rowOf(run, 'REUSE');
  assert.equal(reuse.trace[0].data.notSent, 'change-not-confirmed');
});
// The predicate alone: a zero-row FAIL counts as passed when sent only over a prior pass, or a prior inconclusive that an
// attribution, settlement or later-outcome tag withheld after a pass. A prior missing or an untagged inconclusive was never confirmed.
test('a zero-row FAIL is passed-when-sent only over a prior pass or a tagged inconclusive', () => {
  const row = (priorVerdict, tag = {}) => ({ status: 'fail', assertions: [{ name: 'Response contract', status: 'pass' },
    { name: 'Observed effect 1 (effect.exists)', status: 'fail', zeroRow: { finding: 'rls-zero-row', priorVerdict }, ...tag }] });
  assert.deepEqual([row('pass'), row('missing'), row('inconclusive'), row('inconclusive', { attribution: 'effect-shared-window' }),
    row('inconclusive', { settlement: 'effect-correlated-elsewhere' }), row('inconclusive', { settlement: 'settled' }), row('inconclusive', { later: 'email-bounced' })].map(withheldAfterSend),
  [true, false, false, true, true, false, true]);
});
