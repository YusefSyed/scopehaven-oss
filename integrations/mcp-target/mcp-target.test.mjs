import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runSequence, sequenceHashOf } from '../sequences/sequence.mjs';
import { startMcpServer } from './server.mjs';
import { startMcpTarget, mcpGrantSequence } from './mcp-target.mjs';

const TOKENS = { 'mcp-viewer': 'synthetic-mcp-viewer', 'mcp-agent': 'synthetic-mcp-agent' }, ADMIN = { principal: 'mcp-admin', token: 'synthetic-mcp-admin' };
const ENV = { SCOPEHAVEN_TARGET_MCP_VIEWER: TOKENS['mcp-viewer'], SCOPEHAVEN_TARGET_MCP_AGENT: TOKENS['mcp-agent'], SCOPEHAVEN_TARGET_MCP_ADMIN: ADMIN.token };
const ACTORS = { viewer: { principalId: 'mcp-viewer', credentialEnv: 'SCOPEHAVEN_TARGET_MCP_VIEWER' }, agent: { principalId: 'mcp-agent', credentialEnv: 'SCOPEHAVEN_TARGET_MCP_AGENT' }, admin: { principalId: 'mcp-admin', credentialEnv: 'SCOPEHAVEN_TARGET_MCP_ADMIN' } };
const GRANTS = { 'mcp-viewer': ['read_ticket', 'export'], 'mcp-agent': ['read_ticket', 'refund', 'export'] };

async function runOn(t, mode, { only, upgrade, auditRuns } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven mcp target '));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const server = await startMcpServer({ dbPath: join(dir, 'server.db'), tokens: TOKENS, admin: ADMIN, grants: GRANTS, mode, ...(auditRuns === undefined ? {} : { auditRuns }) });
  t.after(() => server.stop());
  const target = await startMcpTarget({ serverOrigin: server.origin, actors: ACTORS, env: ENV, dbPath: join(dir, 'server.db') });
  t.after(() => target.stop());
  const observers = only ? target.observers.filter(o => o.source === only) : target.observers;
  return runSequence(mcpGrantSequence({ actors: ACTORS, ...(upgrade ? { upgrade } : {}) }), { origin: target.origin, observers, env: ENV });
}
const statuses = run => Object.fromEntries(run.results.map(r => [r.id, r.status]));
const custodyOf = (run, id) => { const r = run.results.find(x => x.id === id); return [r.status, r.custody, r.custodyReason]; };
const HELD = ['inconclusive', 'subject-writable', 'subject-writable-custody'];

test('a clean server (grants bound to the tool descriptor): the forbidden calls never run, and the paired controls pass', async t => {
  const run = await runOn(t, 'bound');
  assert.equal(run.aborted, null);
  // Custody: only the server's own audit table can decide these absences (the traffic is presence-only), so MCP-01 and MCP-02 read inconclusive.
  assert.deepEqual(statuses(run), { 'MCP-01': 'inconclusive', 'MCP-02': 'inconclusive', 'MCP-C1': 'pass', 'MCP-C2': 'pass', 'MCP-C3': 'pass', 'MCP-C4': 'pass' });
  for (const id of ['MCP-01', 'MCP-02']) assert.deepEqual(custodyOf(run, id), HELD, id);
  // The records still show the forbidden calls never ran: neither record has a committed viewer refund before the change or a committed viewer export after it.
  for (const [key, name] of [['start>before-change', 'refund'], ['changed>end', 'export']]) for (const w of run.windows[key]) assert.ok(!w.events.some(e => e.actor === 'mcp-viewer' && e.name === name && e.outcome === 'committed'), `${key} ${w.source}`);
});

test('a descriptor change mid-session: grants by tool name let the old grant run the new capability, judged from the records', async t => {
  const run = await runOn(t, 'by-name');
  // Custody: MCP-01's absence is decided only by the server's audit table, so it reads inconclusive; MCP-02's fail stays a fail.
  assert.deepEqual(statuses(run), { 'MCP-01': 'inconclusive', 'MCP-02': 'fail', 'MCP-C1': 'pass', 'MCP-C2': 'pass', 'MCP-C3': 'pass', 'MCP-C4': 'pass' });
  assert.deepEqual(custodyOf(run, 'MCP-01'), HELD);
  assert.equal(custodyOf(run, 'MCP-02')[2], undefined);
  // Both records show it: the server's audit table and the MCP traffic, each naming the viewer.
  const after = run.windows['changed>end'];
  const audit = after.find(w => w.source === 'sql-audit-table'), traffic = after.find(w => w.source === 'mcp-jsonrpc');
  assert.ok(audit.events.some(e => e.actor === 'mcp-viewer' && e.name === 'export' && e.outcome === 'committed' && e.resource === 'tickets/*'));
  assert.ok(traffic.events.some(e => e.actor === 'mcp-viewer' && e.name === 'export' && e.outcome === 'committed'));
  const open = await runOn(t, 'open');
  assert.deepEqual([statuses(open)['MCP-01'], statuses(open)['MCP-02']], ['fail', 'fail']);
});

test('per-identity credentials: the proxy names each call\'s identity, and the server\'s refusals are recorded as denied', async t => {
  const run = await runOn(t, 'bound');
  const before = run.windows['start>before-change'];
  const traffic = before.find(w => w.source === 'mcp-jsonrpc');
  assert.deepEqual(traffic.events.map(e => [e.actor, e.name, e.outcome]), [['mcp-viewer', 'read_ticket', 'committed'], ['mcp-viewer', 'refund', 'denied'], ['mcp-agent', 'refund', 'committed'], ['mcp-viewer', 'export', 'committed']]);
  const audit = before.find(w => w.source === 'sql-audit-table');
  assert.ok(audit.events.some(e => e.actor === 'mcp-viewer' && e.name === 'refund.denied' && e.outcome === 'denied'));
});

test('the MCP traffic alone is presence-only: it can fail a forbidden call, never pass one', async t => {
  const clean = await runOn(t, 'bound', { only: 'mcp-jsonrpc' });
  assert.ok(!['pass'].includes(statuses(clean)['MCP-01']), JSON.stringify(statuses(clean)));
  const open = await runOn(t, 'open', { only: 'mcp-jsonrpc' });
  assert.equal(statuses(open)['MCP-01'], 'fail');
});

test('the controls are decided by the server\'s audit table: a server that never records the calls it runs fails them, so the pair is red', async t => {
  const silent = await runOn(t, 'bound', { auditRuns: false });
  assert.deepEqual(['MCP-C1', 'MCP-C2', 'MCP-C3', 'MCP-C4'].map(id => statuses(silent)[id]), ['fail', 'fail', 'fail', 'fail']);
  // That server audits its refusals only: the viewer's refused refund is there, the calls it ran are not.
  const audit = silent.windows['start>before-change'].find(w => w.source === 'sql-audit-table');
  assert.deepEqual(audit.events.filter(e => e.actor !== 'mcp-admin').map(e => [e.actor, e.name, e.outcome]), [['mcp-viewer', 'refund.denied', 'denied']]);
});

test('MCP-02 is judged from every record: when only the traffic shows the old grant running the new export, it fails', async t => {
  const run = await runOn(t, 'by-name', { auditRuns: false });
  assert.equal(statuses(run)['MCP-02'], 'fail');
  const after = run.windows['changed>end'];
  assert.ok(!after.find(w => w.source === 'sql-audit-table').events.some(e => e.actor === 'mcp-viewer' && e.name === 'export'), 'the audit is silent');
});

test('a grant is bound to the whole descriptor: changing only the description or only the input schema voids an old grant', async t => {
  for (const [only, resource] of [['description', 'tickets/*'], ['inputSchema', 'tickets/mcp-viewer']]) {
    const boundRun = await runOn(t, 'bound', { upgrade: { only } }), bound = statuses(boundRun);
    // Custody: the bound server's MCP-02 absence is decided only by its own audit table, so it reads inconclusive; the control keeps its pass.
    assert.deepEqual([bound['MCP-02'], bound['MCP-C4']], ['inconclusive', 'pass'], only);
    assert.deepEqual(custodyOf(boundRun, 'MCP-02'), HELD, only);
    const byName = await runOn(t, 'by-name', { upgrade: { only } });
    assert.equal(statuses(byName)['MCP-02'], 'fail', only);
    // The upgrade was partial: only a changed description makes export cover every tenant.
    const audit = byName.windows['changed>end'].find(w => w.source === 'sql-audit-table');
    assert.deepEqual(audit.events.filter(e => e.actor === 'mcp-viewer' && e.name === 'export').map(e => e.resource), [resource], only);
  }
});

test('the same sequence always hashes the same (the JSON-RPC id is the step id), and each variant has its own id', () => {
  assert.equal(sequenceHashOf(mcpGrantSequence({ actors: ACTORS })), sequenceHashOf(mcpGrantSequence({ actors: ACTORS })));
  const ids = [{}, { only: 'description' }, { only: 'inputSchema' }].map(upgrade => mcpGrantSequence({ actors: ACTORS, upgrade }).id);
  assert.equal(ids[0], 'mcp-grants-and-descriptor-change');
  assert.equal(new Set(ids).size, 3);
});
