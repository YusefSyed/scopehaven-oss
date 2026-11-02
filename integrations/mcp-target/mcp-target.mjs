// MCP server as a target: several identities call tools on a loopback
// MCP server, each with its own credential, and allowed and forbidden tool calls are judged
// from records:
//   - the server's own audit table (sqlite audit observer, authoritative), and
//   - the existing mcp-jsonrpc observer (integrations/observers/mcp.mjs) through its
//     loopback HTTP proxy, which records every tools/call and its result per identity
//     (presence-only: it can show a forbidden call ran, never that none did).
// A scenario is an ordinary sequence (scopehaven-sequence/1) whose requests are JSON-RPC
// tools/call messages sent through the proxy; the judgement is core's effect rules.
// The descriptor check: an admin changes a tool's descriptor mid-session; a forbidden
// assertion over the window after the change asks that no call under the old grant ran.
import { createMcpHttpProxy, createMcpObserver, FrameLog } from '../observers/mcp.mjs';
import { createSqliteAuditObserver } from '../observers/sqlite.mjs';
import { validateSequence, SEQUENCE_SCHEMA } from '../sequences/sequence.mjs';
import { DENIED_CODE, TOOL_NAMES } from './server.mjs';

// The proxy in front of the server's /mcp endpoint, and both observers.
// actors: { alias: { principalId, credentialEnv } }; dbPath: the server's audit database.
export async function startMcpTarget({ serverOrigin, actors, env, dbPath }) {
  const log = new FrameLog();
  const proxy = createMcpHttpProxy({ upstream: `${serverOrigin}/mcp`, actors: Object.values(actors).map(a => ({ actorId: a.principalId, credentialEnv: a.credentialEnv })), env, log });
  await proxy.start();
  const principals = Object.values(actors).map(a => a.principalId);
  const observers = [
    createMcpObserver({ instanceId: 'mcp-proxy', log, deniedRpcCodes: [DENIED_CODE], tools: [...TOOL_NAMES] }),
    createSqliteAuditObserver({ instanceId: 'mcp-server-audit', path: dbPath, principals,
      audit: { table: 'audit', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource',
        actions: { ...Object.fromEntries(TOOL_NAMES.map(t => [t, 'tool-call'])), 'server.upgrade': 'access-change', grant: 'access-change' }, deniedActions: TOOL_NAMES.map(t => `${t}.denied`) } }),
  ];
  return { origin: new URL(proxy.url).origin, observers, log, async stop() { await proxy.stop(); } };
}

// One tools/call request step. Its JSON-RPC id is the step id, so the same sequence always hashes the same.
export const toolCall = (id, actorId, tool, args = {}) => ({ request: { id, actorId, method: 'POST', path: '/mcp', body: { jsonrpc: '2.0', id, method: 'tools/call', params: { name: tool, arguments: args } } } });
const by = (actor, name) => ({ actor, name, operation: 'tool-call' });
// A control is decided by the server's own audit table: the traffic record alone can show a
// call was answered, not that the server ran it.
const audited = (actor, name) => ({ source: 'sql-audit-table', ...by(actor, name) });

// The standard pairs and the descriptor check, for a viewer, an agent and an admin:
//   allowed:   the viewer reads a ticket; the agent issues a refund; the viewer exports its
//              own tickets (export v1); after the change, the agent re-granted export v2 exports
//   forbidden: the viewer issues a refund; after the change, the viewer's old export grant
//              runs the new export
// upgrade: the admin upgrade's body ({} replaces the whole export descriptor; { only: 'description' }
// or { only: 'inputSchema' } changes one part). The default id names the variant, so two
// variants never share an id.
export function mcpGrantSequence({ actors, id, upgrade = {} }) {
  id ??= upgrade.only ? `mcp-grants-and-descriptor-change-${upgrade.only}-only` : 'mcp-grants-and-descriptor-change';
  const steps = [
    { mark: 'start' },
    toolCall('viewer-read', 'viewer', 'read_ticket', { ticket: 'T-1' }), { expectStatus: { request: 'viewer-read', in: [200] } },
    toolCall('viewer-refund', 'viewer', 'refund', { ticket: 'T-1', amount: 20 }), { expectStatus: { request: 'viewer-refund', in: [200] } },
    toolCall('agent-refund', 'agent', 'refund', { ticket: 'T-1', amount: 20 }), { expectStatus: { request: 'agent-refund', in: [200] } },
    toolCall('viewer-export-v1', 'viewer', 'export'), { expectStatus: { request: 'viewer-export-v1', in: [200] } },
    { mark: 'before-change' },
    { request: { id: 'upgrade', actorId: 'admin', method: 'POST', path: '/admin/upgrade', body: upgrade } }, { expectStatus: { request: 'upgrade', in: [200] } },
    { request: { id: 'regrant', actorId: 'admin', method: 'POST', path: '/admin/grant', body: { principal: actors.agent.principalId, tool: 'export' } } }, { expectStatus: { request: 'regrant', in: [200] } },
    { mark: 'changed' },
    toolCall('viewer-export-v2', 'viewer', 'export'), { expectStatus: { request: 'viewer-export-v2', in: [200] } },
    toolCall('agent-export-v2', 'agent', 'export'), { expectStatus: { request: 'agent-export-v2', in: [200] } },
    { mark: 'end' },
  ];
  const viewer = actors.viewer.principalId, agent = actors.agent.principalId;
  const assertions = [
    { id: 'MCP-01', title: 'The viewer cannot issue a refund', severity: 'high', from: 'start', to: 'before-change', effect: { kind: 'effect.none', select: by(viewer, 'refund') } },
    { id: 'MCP-02', title: 'After the export tool changed, the viewer\'s old grant runs nothing', severity: 'high', from: 'changed', to: 'end', effect: { kind: 'effect.none', select: by(viewer, 'export') } },
    { id: 'MCP-C1', title: 'The viewer reads a ticket', severity: 'control', from: 'start', to: 'before-change', effect: { kind: 'effect.exists', select: audited(viewer, 'read_ticket') } },
    { id: 'MCP-C2', title: 'The agent issues a refund', severity: 'control', from: 'start', to: 'before-change', effect: { kind: 'effect.exists', select: audited(agent, 'refund') } },
    { id: 'MCP-C3', title: 'Before the change, the viewer exports its own tickets', severity: 'control', from: 'start', to: 'before-change', effect: { kind: 'effect.exists', select: audited(viewer, 'export') } },
    { id: 'MCP-C4', title: 'After the change, the re-granted agent exports', severity: 'control', from: 'changed', to: 'end', effect: { kind: 'effect.exists', select: audited(agent, 'export') } },
  ];
  return validateSequence({ schema: SEQUENCE_SCHEMA, id, actors: { viewer: actors.viewer, agent: actors.agent, admin: actors.admin }, steps, assertions });
}
