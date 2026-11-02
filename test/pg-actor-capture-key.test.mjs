// The actor capture's profile key: a pg-snapshot observer's "actorCapture" ({ block, installedSha256 }), checked when the
// profile loads, passed by the factory, and read end to end through runHttpAssessment against a scripted fake Postgres (no real
// database). Without the key the observer is exactly as before (pinned in integrations/observers/pg.test.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { COLLECTOR_RECORDS } from '../src/collector-identity.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { PLATFORM_SCHEMAS } from '../integrations/observers/pg-actor.mjs';
import { ACTOR_PLATFORM_SCHEMAS } from '../src/contracts.mjs';
import { scriptedDb, USER, PASSWORD } from '../integrations/observers/fixtures/fake-postgres.mjs';

const TOKEN = 'synthetic-bob-token', env = { SCOPEHAVEN_TARGET_BOB: TOKEN, SCOPEHAVEN_TARGET_DB_READER: `${USER}:${PASSWORD}` };
const SHA = 'a'.repeat(64);
const block = (patch = {}) => ({ testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', tables: [{ table: 'Chat', key: 'id' }],
  actor: { from: 'jwt-claims' }, principals: { 'b0b00000-0000-4000-8000-000000000002': 'bob' }, ...patch });
const pgObserver = (port, extra = {}) => ({ id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables: [{ table: 'Chat', key: 'id' }], settleMs: 250, ...extra });
const profile = (origin, observers, extraChecks = []) => ({ id: 'chatbot', name: 'Chatbot', applicationId: 'chatbot-app', origin, buildLabel: 'b1', contextId: 'synthetic-chatbot',
  actors: { bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } }, requiredControlIds: ['WHOAMI'], observers,
  checks: [
    { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'bob', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'bob' }] },
    { id: 'BOB-ALICE-CHAT', title: "Bob cannot write alice's chat", category: 'object-access', severity: 'high', actorId: 'bob', method: 'GET', path: '/chats/c1/messages', evidenceRequirement: 'backend',
      assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', resource: 'Chat/c1' } },
        { kind: 'effect.none', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', resource: 'Chat/c1', actor: 'bob' } }] },
    ...extraChecks,
  ] });
const load = target => validateTargetFile({ schemaVersion: 1, targets: [target] })[0];
async function app(t) {
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return reply(401, {});
    if (req.url === '/me') return reply(200, { user: 'bob' });
    if (req.url === '/chats/c1/messages') return reply(403, { error: 'forbidden' });
    reply(404, {});
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const rows = xmin => [['c1', xmin, 'h1'], ['c2', '701', 'h2']];
const states = (startXmin, endXmin) => [{ snapshot: '800:800:', tables: { Chat: rows(startXmin) } }, { snapshot: '800:800:', tables: { Chat: rows(startXmin) } }, { snapshot: '800:800:', tables: { Chat: rows(startXmin) } },
  { snapshot: '805:805:', tables: { Chat: rows(endXmin) } }, { snapshot: '805:805:', tables: { Chat: rows(endXmin) } }];

test('actorCapture: the installed capture\'s block and its installation digest; principals are declared actors, the install credential its own', () => {
  const ok = load(profile('http://127.0.0.1:4000', [pgObserver(5432, { actorCapture: { block: block(), installedSha256: SHA } })]));
  assert.deepEqual(ok.observers[0].actorCapture, { block: block(), installedSha256: SHA });
  const reject = (capture, pattern) => assert.throws(() => load(profile('http://127.0.0.1:4000', [pgObserver(5432, { actorCapture: capture })])), pattern, JSON.stringify(capture).slice(0, 120));
  reject(block(), /"actorCapture" is \{ block, installedSha256 \}/);
  reject({ block: block(), installedSha256: SHA, resolve: 'x' }, /"actorCapture" is \{ block, installedSha256 \}/);
  reject({ block: [], installedSha256: SHA }, /"actorCapture" is \{ block, installedSha256 \}/);
  for (const sha of [undefined, 'A'.repeat(64), 'a'.repeat(63), 7]) reject({ block: block(), installedSha256: sha }, /"installedSha256" is the 64 lowercase hex digest/);
  reject({ block: block({ principals: { 'some-sub': 'alice' } }), installedSha256: SHA }, /"principals" maps each value its source reads to the principalId of a declared actor/);
  reject({ block: block({ principals: {} }), installedSha256: SHA }, /"principals" maps/);
  reject({ block: block({ installCredentialEnv: 'PGPASSWORD' }), installedSha256: SHA }, /names a SCOPEHAVEN_TARGET_ variable/);
  reject({ block: block({ installCredentialEnv: 'SCOPEHAVEN_TARGET_DB_READER' }), installedSha256: SHA }, /never the observer's or an actor's credential/);
  reject({ block: block({ installCredentialEnv: 'SCOPEHAVEN_TARGET_BOB' }), installedSha256: SHA }, /never the observer's or an actor's credential/);
  // Three of the capture's own rules, refused at load too, so check-config refuses what assess would.
  reject({ block: block({ testCopy: false }), installedSha256: SHA }, /"testCopy": true is required/);
  for (const schema of ['public', 'Auth', 'pg_temp', 'two words']) reject({ block: block({ schema }), installedSha256: SHA }, /"schema" is a plain identifier of a schema of its own/);
  reject({ block: block({ actor: { from: 'column' } }), installedSha256: SHA }, /"actor" from "column" needs every table's "actorColumn"/);
});

test('the factory passes actorCapture to a caller that reads it: the observer then names principals; without it, it names none; a block the capture refuses never builds', () => {
  const [plain] = buildObservers([pgObserver(5432)], { env });
  assert.equal(plain.scope.actorAttribution, 'none');
  const [captured] = buildObservers([pgObserver(5432, { actorCapture: { block: block(), installedSha256: SHA } })], { env, actorCapture: true });
  assert.equal(captured.scope.actorAttribution, 'principal');
  // A caller whose validators fix the snapshot's scope (sequences) is refused the key, never given a scope it then refuses.
  assert.throws(() => buildObservers([pgObserver(5432, { actorCapture: { block: block(), installedSha256: SHA } })], { env }), /actorCapture is read only by an HTTP assessment's observers/);
  assert.throws(() => buildObservers([pgObserver(5432, { actorCapture: null })], { env, actorCapture: true }), /actorCapture is \{ block, installedSha256 \}/);
  // The capture's own rules (./pg-actor.mjs validateActorCapture) run when the observer is built, before any request.
  assert.throws(() => buildObservers([pgObserver(5432, { actorCapture: { block: block({ actor: { from: 'column' } }), installedSha256: SHA } })], { env, actorCapture: true }), /actorCapture: "actor" from "column" needs every table's "actorColumn"/);
  assert.throws(() => buildObservers([pgObserver(5432, { actorCapture: { block: block({ principals: { x: 'bob', y: 'bob', z: 7 } }), installedSha256: SHA } })], { env, actorCapture: true }), /actorCapture: each "principals" entry names a principal id/);
});

test('through the connector: a capture that does not verify attributes no one; an actor-pinned absence never decides on a snapshot, and the unpinned one is held by custody', async t => {
  // The scripted database answers the capture's definition and ledger reads with nothing: the capture reads absent at every mark.
  const origin = await app(t), db = await scriptedDb(t, states('700', '700'));
  const p = profile(origin, [pgObserver(db.port, { actorCapture: { block: block(), installedSha256: SHA } })]);
  const run = await runHttpAssessment(p, { env });
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env }).exportSuite(p.id) });
  assert.deepEqual(run.observers[0].collector, COLLECTOR_RECORDS['pg-snapshot']);
  // pg-snapshot/3 is the first label whose reader joins the capture (later labels keep the join).
  assert.match(run.observers[0].collector.label, /^pg-snapshot\/([3-9]|[1-9]\d)$/);
  const r = run.results.find(x => x.id === 'BOB-ALICE-CHAT'), [plainClause, pinned] = r.trace[1].data.effects;
  // No row changed: the unpinned absence holds on the window and custody holds its boundary pass on the app's own store, as without the
  // key. The pinned one never decides on a net-only snapshot (src/effect-events.mjs exactFor): a write the capture never saw by that
  // actor could hide behind a captured one.
  assert.deepEqual([plainClause.verdict, plainClause.custodyReason, pinned.verdict], ['inconclusive', 'subject-writable-custody', 'missing']);
  assert.equal(r.trace[1].data.windows[0].scope.actorAttribution, 'principal');
  assert.notEqual(r.status, 'pass');
});

test('through the connector: an unattributed write still fails an unpinned prohibition (the capture never hides a write)', async t => {
  const origin = await app(t), db = await scriptedDb(t, states('700', '804'));
  const run = await runHttpAssessment(profile(origin, [pgObserver(db.port, { actorCapture: { block: block(), installedSha256: SHA } })]), { env });
  const r = run.results.find(x => x.id === 'BOB-ALICE-CHAT');
  assert.equal(r.status, 'fail');
  assert.equal(r.trace[1].data.effects[0].verdict, 'fail');
  // The write has no actor (the capture read absent), so the clause pinned to bob cannot fail or pass on it.
  assert.equal(r.trace[1].data.effects[1].verdict, 'missing');
  assert.deepEqual(r.trace[1].data.windows[0].events.map(e => [e.operation, e.resource, e.actor]), [['update', 'Chat/c1', null]]);
  validateHttpRunEvidence(run);
});

test('the validator\'s platform schemas are the capture\'s own list', () => assert.deepEqual(ACTOR_PLATFORM_SCHEMAS, PLATFORM_SCHEMAS));
