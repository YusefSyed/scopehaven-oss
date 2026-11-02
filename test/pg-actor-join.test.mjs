// The actor capture's joins through the observers, scripted: pg-snapshot driven over the
// scripted fake Postgres with an intact capture answered through its connect seam (the capture's definitions as an intact installation
// returns them, and a scripted ledger), so the net join's attributions, and what they decide, are checked without a database.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createPgSnapshotObserver } from '../integrations/observers/pg-snapshot.mjs';
import { pgConnect } from '../integrations/observers/pg-wire.mjs';
import { verifySql, verifyAtInstall, PG_ACTOR_SCHEMA } from '../integrations/observers/pg-actor.mjs';
import { scriptedDb, USER, PASSWORD } from '../integrations/observers/fixtures/fake-postgres.mjs';
import { decideEffects } from '../src/http-effects.mjs';

const BLOCK = Object.freeze({ testCopy: true, installCredentialEnv: 'SCOPEHAVEN_TARGET_PG_SUPERUSER', tables: [{ table: 'Chat', key: 'id' }], actor: { from: 'jwt-claims' }, principals: { 'sub-alice': 'alice', 'sub-bob': 'bob' } });
const h = createHash('sha256').update(`${PG_ACTOR_SCHEMA}\nscopehaven_actor`).digest('hex').slice(0, 10), owner = 'supabase_admin:true', path = '{search_path=pg_catalog, pg_temp}';
const definitions = (enabled = 'O') => [
  { rows: [[owner, null, PG_ACTOR_SCHEMA, '900']] },
  { rows: [['capture', '', 'true', path, 'md5a', owner, null, '901', 'v'], ['ledger', 'after_seq bigint, max_rows integer', 'true', path, 'md5b', owner, null, '902', 's']] },
  { rows: ['insert', 'update', 'delete'].map((op, i) => ['public.Chat', `sh_actor_${h}_${op}`, op === 'update' ? enabled : 'O', '0', '', '', '', 'true', '', 'capture', String(903 + i)]) },
  { rows: [['true', 'false', 'p', 'r', '0', '0', '0', owner, null]] },
  { rows: 'seq,txid,tbl,key,op,rowcount,depth,row_xmin,claims_sub,claims_role,legacy_sub,header_sub,set_role,session_role,app_actor,at'.split(',').map(c => [c, 'text']) },
];
const INSTALLED = verifyAtInstall(definitions(), BLOCK);
// A PostgREST-bound write by sub: an authenticator login, SET ROLE authenticated, the bearer's sub the claims' own.
const entry = (seq, txid, key, op, sub, rowXmin) => [String(seq), String(txid), String(txid), 'public.Chat', key, op, null, '1', rowXmin, sub, 'authenticated', null, sub, 'authenticated', 'authenticator', null];
const S = (snapshot, rows) => ({ snapshot, tables: { Chat: rows } });
const START = [['c1', '700', 'h1'], ['c2', '701', 'h2']];
// One window over two marks: the ledger and definitions each mark reads, then the window collected and its events decided.
async function windowOf(t, { states, ledgers, definitionsAt = [definitions(), definitions()] }) {
  let at = 0;
  const server = await scriptedDb(t, states);
  const connect = async opts => { const c = await pgConnect(opts), q = c.query.bind(c);
    return Object.assign(Object.create(c), { query: (sql, o) => (sql === verifySql(BLOCK) ? Promise.resolve(definitionsAt[at]) : /^SELECT l\.seq::pg_catalog\.text/.test(sql) ? Promise.resolve([{ rows: ledgers[at] }]) : q(sql, o)), close: () => c.close() }); };
  const o = createPgSnapshotObserver({ env: { SCOPEHAVEN_TARGET_DB_READER: `${USER}:${PASSWORD}` }, host: '127.0.0.1', port: server.port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER',
    tables: [{ table: 'Chat', key: 'id' }], watchedResources: ['Chat/c1', 'Chat/c2', 'Chat/c3'], actorCapture: { block: BLOCK, installedSha256: INSTALLED.sha256 }, connect });
  await o.start();
  const a = await o.mark(); at = 1; const b = await o.mark();
  const raw = await o.collect(a, b);
  return { raw, window: { ...raw, source: o.source, instanceId: o.instanceId, scope: o.scope }, events: raw.events.map(e => [e.operation, e.resource, e.actor]) };
}
const clause = (kind, operation, resource, actor) => ({ kind, select: { source: 'sql-snapshot', name: 'Chat', operation, resource, actor } });
const verdicts = (w, clauses, role) => decideEffects(clauses, [w.window], { role }).map(d => d.verdict);

test('an intact capture names the one actor who wrote a row; two actors, or a last write it never saw, name no one', async t => {
  const changed = rows => [S('800:800:', START), S('800:800:', START), S('805:805:', rows), S('805:805:', rows)];
  const one = await windowOf(t, { states: changed([['c1', '804', 'h9'], ['c2', '701', 'h2']]), ledgers: [[], [entry(1, 804, 'c1', 'UPDATE', 'sub-alice', '804')]] });
  assert.deepEqual(one.events, [['update', 'Chat/c1', 'alice']]);
  assert.deepEqual(one.raw.actors, { schema: PG_ACTOR_SCHEMA, capture: { start: 'intact', end: 'intact' }, attributed: 1, unattributed: 0, ambiguous: 0 });
  assert.deepEqual(verdicts(one, [clause('effect.exists', 'update', 'Chat/c1', 'alice')], 'control'), ['pass']);
  const two = await windowOf(t, { states: changed([['c1', '804', 'h9'], ['c2', '701', 'h2']]), ledgers: [[], [entry(1, 803, 'c1', 'UPDATE', 'sub-bob', '803'), entry(2, 804, 'c1', 'UPDATE', 'sub-alice', '804')]] });
  assert.deepEqual([two.events, two.raw.actors.ambiguous], [[['update', 'Chat/c1', null]], 1]);
  // alice's captured UPDATE (xmin 802), then a write it never saw left the row at xmin 803: the last write is not in the ledger.
  const unseen = await windowOf(t, { states: changed([['c1', '803', 'h9'], ['c2', '701', 'h2']]), ledgers: [[], [entry(1, 802, 'c1', 'UPDATE', 'sub-alice', '802')]] });
  assert.equal(unseen.raw.coverage, 'net-only');
  assert.deepEqual(unseen.events, [['update', 'Chat/c1', null]]);
});

test('the net join accounts for the net operation: a write the capture never saw is never credited to the captured writer', async t => {
  // A: alice's captured UPDATE of c1, then a DELETE the capture never saw (a replica-role session, a write sent to a partition).
  const gone = [['c2', '701', 'h2']];
  const a = await windowOf(t, { states: [S('800:800:', START), S('800:800:', START), S('805:805:', gone), S('805:805:', gone)], ledgers: [[], [entry(1, 802, 'c1', 'UPDATE', 'sub-alice', '802')]] });
  assert.deepEqual(a.events, [['delete', 'Chat/c1', null]]);
  assert.deepEqual(verdicts(a, [clause('effect.none', 'delete', 'Chat/c1', 'alice')], 'boundary'), ['missing'], 'never a false FAIL against the app');
  assert.notEqual(verdicts(a, [clause('effect.exists', 'delete', 'Chat/c1', 'alice')], 'control')[0], 'pass', 'never a false PASS on a control');
  // B: an INSERT of c3 the capture never saw, then alice's captured UPDATE of it.
  const grown = [...START, ['c3', '804', 'h3']];
  const b = await windowOf(t, { states: [S('800:800:', START), S('800:800:', START), S('805:805:', grown), S('805:805:', grown)], ledgers: [[], [entry(1, 804, 'c3', 'UPDATE', 'sub-alice', '804')]] });
  assert.deepEqual(b.events, [['insert', 'Chat/c3', null]]);
  assert.notEqual(verdicts(b, [clause('effect.exists', 'insert', 'Chat/c3', 'alice')], 'control')[0], 'pass');
  // C: an UPDATE the capture never saw, then alice's captured UPDATE: the row's net change is alice's, but no snapshot can rule out the
  // earlier write, so an absence pinned to another actor never decides (src/effect-events.mjs exactFor): never a pass, in either role.
  const moved = [['c1', '804', 'h9'], ['c2', '701', 'h2']];
  const c = await windowOf(t, { states: [S('800:800:', START), S('800:800:', START), S('805:805:', moved), S('805:805:', moved)], ledgers: [[], [entry(1, 804, 'c1', 'UPDATE', 'sub-alice', '804')]] });
  assert.deepEqual(c.events, [['update', 'Chat/c1', 'alice']]);
  for (const role of ['boundary', 'control']) assert.deepEqual(verdicts(c, [clause('effect.none', 'update', 'Chat/c1', 'bob'), clause('effect.exists', 'update', 'Chat/c1', 'bob')], role), ['missing', 'missing'], role);
  // The same row without a pin still decides exactly, as without the capture.
  assert.deepEqual(verdicts(c, [{ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'Chat', operation: 'update', resource: 'Chat/c1' } }], 'control'), ['pass']);
  // Controls: alice's own captured DELETE and INSERT are hers.
  const deleted = await windowOf(t, { states: [S('800:800:', START), S('800:800:', START), S('805:805:', gone), S('805:805:', gone)], ledgers: [[], [entry(1, 802, 'c1', 'UPDATE', 'sub-alice', '802'), entry(2, 803, 'c1', 'DELETE', 'sub-alice', null)]] });
  assert.deepEqual(deleted.events, [['delete', 'Chat/c1', 'alice']]);
  const inserted = await windowOf(t, { states: [S('800:800:', START), S('800:800:', START), S('805:805:', grown), S('805:805:', grown)], ledgers: [[], [entry(1, 803, 'c3', 'INSERT', 'sub-alice', '803'), entry(2, 804, 'c3', 'UPDATE', 'sub-alice', '804')]] });
  assert.deepEqual(inserted.events, [['insert', 'Chat/c3', 'alice']]);
});

test('a capture altered at the end mark names no one in that window', async t => {
  const moved = [['c1', '804', 'h9'], ['c2', '701', 'h2']];
  const w = await windowOf(t, { states: [S('800:800:', START), S('800:800:', START), S('805:805:', moved), S('805:805:', moved)], ledgers: [[], [entry(1, 804, 'c1', 'UPDATE', 'sub-alice', '804')]],
    definitionsAt: [definitions(), definitions('D')] });
  assert.deepEqual([w.events, w.raw.actors.capture], [[['update', 'Chat/c1', null]], { start: 'intact', end: 'absent' }]);
});
