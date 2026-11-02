// A sequence's end mark taken right after a forbidden request must not give an absence pass on a commit that lands
// 300 ms later.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { runSequence, SEQUENCE_SCHEMA } from './sequence.mjs';
import { validateSequenceRun } from './run-validator.mjs';
// Every run a test produces is also recomputed from the windows it sealed, as a saved run would be.
const recheck = (run, seq) => assert.deepEqual(validateSequenceRun(JSON.parse(JSON.stringify(run)), { expectedSequence: seq }).results.map(r => r.verdict), run.results.map(r => r.verdict));
import { buildObservers } from './cli.mjs';

const env = { SCOPEHAVEN_TARGET_MEMBER: 'synthetic-member-token' };
async function lateApp(t) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-seq-settle-'));
  const dbPath = join(dir, 'app.db'), db = new DatabaseSync(dbPath);
  db.exec('PRAGMA journal_mode=WAL; CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, who TEXT, action TEXT, target TEXT);');
  const timers = new Set();
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    res.writeHead(403, { 'Content-Type': 'application/json', Connection: 'close' }); res.end('{"error":"forbidden"}');
    // Answers 403, then a background job commits the forbidden edit 300 ms later.
    const timer = setTimeout(() => { timers.delete(timer); db.prepare('INSERT INTO audit (who, action, target) VALUES (?, ?, ?)').run('member-1', 'note.update', 'notes/other'); }, 300); timers.add(timer);
  }); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { for (const timer of timers) clearTimeout(timer); await new Promise(r => { server.close(r); server.closeAllConnections(); }); db.close(); rmSync(dir, { recursive: true, force: true }); });
  return { origin: `http://127.0.0.1:${server.address().port}`, dbPath };
}
const sequence = { schema: SEQUENCE_SCHEMA, id: 'late-commit', actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER' } },
  steps: [{ mark: 'a' }, { request: { id: 'edit', actorId: 'member', method: 'POST', path: '/notes/other/edit', body: {} } }, { mark: 'b' }],
  assertions: [{ id: 'NO-EDIT', title: 'The edit is not committed', severity: 'high', from: 'a', to: 'b', effect: { kind: 'effect.none', select: { source: 'sql-audit-table', name: 'note.update' } } }] };
const auditConfig = (app, extra = {}) => ({ id: 'audit', type: 'sqlite-audit', path: app.dbPath, principals: ['member-1'], audit: { table: 'audit', idColumn: 'id', actorColumn: 'who', actionColumn: 'action', resourceColumn: 'target', actions: { 'note.update': 'update' } }, ...extra });

test('a sequence waits the declared settleMs before an end mark, so a late commit fails the absence check', async t => {
  const app = await lateApp(t);
  const settled = await runSequence(sequence, { origin: app.origin, observers: buildObservers([auditConfig(app, { settleMs: 1000 })], { env }), env });
  recheck(settled, sequence);
  assert.equal(settled.results[0].verdict, 'fail', settled.results[0].basis);
  assert.ok(settled.limitations.some(l => /^Effects committed after an assertion's end mark are not observed \(each end mark is taken 1000 ms after/.test(l)));
  await new Promise(r => setTimeout(r, 400));
  // Without a declared settle the limitation says so; the operator places end marks.
  const unsettled = await runSequence(sequence, { origin: app.origin, observers: buildObservers([auditConfig(app)], { env }), env });
  recheck(unsettled, sequence);
  assert.ok(unsettled.limitations.some(l => /no observer declares a settleMs, so place end marks after the action has settled/.test(l)));
  await new Promise(r => setTimeout(r, 400));
});
