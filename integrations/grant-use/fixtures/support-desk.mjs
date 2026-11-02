// Owned synthetic fixture for the grant-versus-use tests: a two-actor support desk whose agent can send mail, call a
// payments API and a webhook host, and write three tables. Runs are real HTTP connector runs (runHttpAssessment) over an
// injected transport (the fake application below) and injected in-memory observers driven by a virtual clock, so every
// window, gap and seq is the connector's own and the run validator accepts the record. No socket, database, model or
// provider is used.
import { createHash } from 'node:crypto';
import { makeEffect } from '../../../src/effect-events.mjs';
import { OBSERVER_OUTPUT } from '../../../src/http-effects.mjs';
import { runHttpAssessment, HTTP_LIMITS } from '../../../src/http-connector.mjs';
import { runSequence } from '../../sequences/sequence.mjs';
import { declaredObservers } from '../../sequences/cli.mjs';

export const PAY = 'api.pay.example', HOOKS = 'hooks.chat.example', CRM = 'crm.example', EXFIL = 'exfil.example';
export const SINK = 'egress-recorder-sink', MAIL = 'smtp-sink-mail', DB = 'sqlite-snapshot-db', AUDIT = 'sqlite-audit-audit';
export const ENV = Object.freeze({ SCOPEHAVEN_TARGET_GU_MEMBER: 'tok-member', SCOPEHAVEN_TARGET_GU_OPS: 'tok-ops' });
const WHO = { 'tok-member': 'member', 'tok-ops': 'ops' }, EMAIL = { member: 'member@acme.test', ops: 'ops@acme.test' };
// The principals the audit observer may name as they are (its declared principals list); any other value it records only as
// "unlisted:" and a digest, as integrations/observers/sqlite.mjs does.
export const AUDIT_PRINCIPALS = Object.freeze(['member-1', 'ops-1', 'svc-agent']);

const check = (id, actorId, severity, method, path, status, effects) => ({ id, title: id, category: severity === 'control' ? 'Allowed use' : 'Access', severity, actorId, method, path,
  ...(method === 'POST' ? { body: {} } : {}), evidenceRequirement: effects && severity !== 'control' ? 'backend' : 'response', assertions: [{ kind: 'status.equals', expected: status }], ...(effects ? { effects } : {}) });
const send = (name, resource) => ({ source: 'http-egress', operation: 'send', name, ...(resource ? { resource } : {}) });

// The profile: three actors, an egress recorder, an SMTP sink, a table snapshot and an audit table. The declared reach is
// 6 destinations (4 egress, 2 mail), 3 tables and 3 audit actions. attribution declares crm.example a background source;
// responseOnly drops every effect, so no check is observed.
export function supportDeskTarget({ attribution = false, responseOnly = false } = {}) {
  const target = {
    id: 'support-desk', name: 'Support desk (synthetic)', applicationId: 'support-desk', origin: 'http://127.0.0.1:9', buildLabel: 'support-desk synthetic', contextId: 'synthetic-support-desk',
    actors: {
      member: { principalId: 'member-1', role: 'member', tenantId: 'acme', credentialEnv: 'SCOPEHAVEN_TARGET_GU_MEMBER', identityValue: EMAIL.member },
      ops: { principalId: 'ops-1', role: 'ops', tenantId: 'acme', credentialEnv: 'SCOPEHAVEN_TARGET_GU_OPS', identityValue: EMAIL.ops },
      visitor: { principalId: 'visitor' },
    },
    observers: [
      { id: 'sink', type: 'egress-recorder', port: 40991, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/charges'] }, { host: HOOKS }, { host: CRM }],
        witness: { actorId: 'ops', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250 },
      { id: 'mail', type: 'smtp-sink', port: 40992, routing: 'smtp-host', domains: [{ domain: 'customers.example' }, { domain: 'acme.example' }],
        witness: { actorId: 'ops', method: 'GET', path: '/mail-ping', domain: 'witness.scopehaven.invalid' }, settleMs: 250 },
      { id: 'db', type: 'sqlite-snapshot', path: '/synthetic/support-desk.db', tables: [{ table: 'tickets', key: 'id' }, { table: 'refunds', key: 'id' }, { table: 'payouts', key: 'id' }], settleMs: 250 },
      { id: 'audit', type: 'sqlite-audit', path: '/synthetic/support-desk.db', audit: { table: 'audit', actions: { 'ticket.update': 'update', 'refund.create': 'insert', 'payout.create': 'insert' }, deniedActions: ['refund.refused'] },
        principals: [...AUDIT_PRINCIPALS], settleMs: 250 },
    ],
    ...(attribution ? { attribution: { background: [{ id: 'crm-sync', select: { operation: 'send', name: CRM } }] } } : {}),
    requiredControlIds: ['MEMBER-ME', 'OPS-ME', 'MEMBER-TICKETS', 'OPS-QUEUE'],
    checks: [
      { ...check('MEMBER-ME', 'member', 'control', 'GET', '/api/me', 200), assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: EMAIL.member }] },
      { ...check('OPS-ME', 'ops', 'control', 'GET', '/api/me', 200), assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: EMAIL.ops }] },
      check('MEMBER-TICKETS', 'member', 'control', 'GET', '/api/tickets', 200),
      check('OPS-QUEUE', 'ops', 'control', 'GET', '/api/queue', 200),
      check('MEMBER-REPLY', 'member', 'control', 'POST', '/api/tickets/t-1/reply', 200, [{ kind: 'effect.exists', select: { source: 'smtp-capture', operation: 'send', name: 'customers.example' } }]),
      check('MEMBER-SUMMARIZE', 'member', 'high', 'POST', '/api/agent/summarize', 200, [{ kind: 'effect.none', select: send(PAY) }]),
      check('OPS-REFUND', 'ops', 'control', 'POST', '/api/refunds', 200, [{ kind: 'effect.exists', select: send(PAY, 'POST /v1/refunds') }]),
      check('VISITOR-STATUS', 'visitor', 'control', 'GET', '/api/status', 200),
      check('MEMBER-NO-REFUND', 'member', 'high', 'POST', '/api/refunds', 403, [{ kind: 'effect.none', select: send(PAY) }]),
      check('OPS-NOTIFY', 'ops', 'control', 'POST', '/api/notify', 200, [{ kind: 'effect.exists', select: send(HOOKS) }]),
    ],
  };
  if (responseOnly) target.checks = target.checks.map(({ effects, ...c }) => ({ ...c, evidenceRequirement: 'response' }));
  return target;
}

// The stated policy for the coverage report's cells (integrations/coverage-report): which operations each role may call.
export const INVENTORY = Object.freeze({
  schema: 'scopehaven-coverage-inventory/1', applicationId: 'support-desk', source: 'Synthetic fixture for the grant-versus-use tests.',
  tenants: ['acme', 'globex'], roles: ['member', 'ops'], members: { acme: ['member', 'ops'], globex: ['member'] },
  operations: [
    { id: 'GET /api/me', surface: 'api', method: 'GET', path: '/api/me', auth: 'session', tenantScoped: false },
    { id: 'GET /api/tickets', surface: 'api', method: 'GET', path: '/api/tickets', auth: 'session', tenantScoped: true },
    { id: 'POST /api/tickets/:id/reply', surface: 'api', method: 'POST', path: '/api/tickets/:id/reply', object: 'tickets', auth: 'session', tenantScoped: true },
    { id: 'DELETE /api/tickets/:id', surface: 'api', method: 'DELETE', path: '/api/tickets/:id', object: 'tickets', auth: 'session', tenantScoped: true },
    { id: 'POST /api/agent/summarize', surface: 'api', method: 'POST', path: '/api/agent/summarize', auth: 'session', tenantScoped: false },
    { id: 'GET /api/queue', surface: 'api', method: 'GET', path: '/api/queue', auth: 'session', tenantScoped: false },
    { id: 'GET /api/reports', surface: 'api', method: 'GET', path: '/api/reports', auth: 'session', tenantScoped: false },
    { id: 'POST /api/refunds', surface: 'api', method: 'POST', path: '/api/refunds', auth: 'session', tenantScoped: false },
    { id: 'POST /api/notify', surface: 'api', method: 'POST', path: '/api/notify', auth: 'session', tenantScoped: false },
    { id: 'GET /api/status', surface: 'api', method: 'GET', path: '/api/status', auth: 'none', tenantScoped: false },
  ],
  datastores: [{ name: 'tickets' }, { name: 'refunds' }, { name: 'payouts' }],
  objects: { tickets: { 't-1': 'acme', 'g-1': 'globex' } },
});
export const CONTRACT = Object.freeze({
  schema: 'scopehaven-coverage-contract/1', applicationId: 'support-desk', basis: 'stated-policy', source: 'Synthetic fixture for the grant-versus-use tests.', crossTenant: 'deny',
  rules: [
    { operation: 'GET /api/me', allow: ['member', 'ops'] }, { operation: 'GET /api/tickets', allow: ['member', 'ops'] },
    { operation: 'POST /api/tickets/:id/reply', allow: ['member', 'ops'] }, { operation: 'DELETE /api/tickets/:id', allow: ['ops'] },
    { operation: 'POST /api/agent/summarize', allow: ['member'] }, { operation: 'GET /api/queue', allow: ['ops'] }, { operation: 'GET /api/reports', allow: ['ops'] },
    { operation: 'POST /api/refunds', allow: ['ops'] }, { operation: 'POST /api/notify', allow: ['ops'] }, { operation: 'GET /api/status', allow: 'anyone' },
  ],
});

// A virtual clock and an event log the fake application writes and the fake observers read by mark time.
export function createWorld() {
  let now = 0;
  const events = [], seqs = new Map(), degraded = [], late = [];
  const nextSeq = instance => { const seq = (seqs.get(instance) ?? 0) + 1; seqs.set(instance, seq); return seq; };
  return {
    clock: { now: () => now, sleep: async ms => { now += ms; } },
    tick() { now += 10; },
    nextSeq,
    emit(instance, spec) { events.push({ at: now, instance, seq: nextSeq(instance), spec }); },
    // The next window of this observer that covers now reads with this coverage (a missing snapshot, a partial window).
    degrade(instance, coverage, reason) { degraded.push({ at: now, instance, coverage, reason }); },
    // The window of this observer that covers now carries a scoped entry: a send it could not place.
    carry(instance, entry) { late.push({ at: now, instance, entry }); },
    windowOf(instance, from, to) {
      const inside = e => e.instance === instance && e.at > from.at && e.at <= to.at;
      return { events: events.filter(inside), degraded: degraded.find(inside) ?? null, scoped: late.filter(inside).map(l => l.entry) };
    },
  };
}

const scopeOf = c => {
  if (c.type === 'egress-recorder') return { operations: ['send'], names: c.destinations.map(d => d.host), actorAttribution: 'none', evidence: c.routing ? 'authoritative' : 'presence-only' };
  if (c.type === 'smtp-sink') return { operations: ['send'], names: c.domains.map(d => d.domain), actorAttribution: 'none', evidence: c.routing ? 'authoritative' : 'presence-only' };
  if (c.type === 'sqlite-snapshot') return { operations: ['insert', 'update', 'delete'], names: c.tables.map(t => t.table), actorAttribution: 'none', evidence: 'authoritative' };
  return { operations: ['insert', 'update'], names: [...Object.keys(c.audit.actions), ...(c.audit.deniedActions ?? [])], actorAttribution: 'principal', evidence: 'authoritative' };
};
const principalOf = (value, principals) => value === null || value === undefined ? null : principals.includes(value) ? value : `unlisted:${createHash('sha256').update(`fixture:${value}`).digest('hex').slice(0, 16)}`;
// In-memory observers in the connector's observer shape, reading the world's events by mark time. inject puts an event into
// the nth check window an observer collects ({ instance, window, spec }), whatever the application did meanwhile (a background
// job's send in the window of a row whose request was never attempted, say).
export const observerFactory = (world, { inject = [] } = {}) => configs => configs.map(c => {
  const { source, kind } = OBSERVER_OUTPUT[c.type], instanceId = `${c.type}-${c.id}`, scope = Object.freeze(scopeOf(c));
  let checkWindows = 0;
  return { kind, instanceId, source, scope, witnessRequest: null, async start() {}, async stop() {}, async mark() { return { at: world.clock.now() }; },
    async collect(from, to, options) {
      const found = world.windowOf(instanceId, from, to), degraded = found.degraded, scoped = found.scoped;
      const nth = options?.gap ? null : ++checkWindows;
      const events = [...found.events, ...inject.filter(x => x.instance === instanceId && x.window === nth).map(x => ({ seq: world.nextSeq(instanceId), spec: x.spec }))];
      if (degraded?.coverage === 'failed') return { events: [], coverage: 'failed', reason: degraded.reason };
      const made = events.map(e => makeEffect({ source, observer: { kind, instanceId }, seq: e.seq, outcome: 'committed', ...e.spec, actor: c.type === 'sqlite-audit' ? principalOf(e.spec.actor, c.principals ?? []) : null }));
      if (degraded) return { events: made, coverage: degraded.coverage, reason: degraded.reason };
      if (source === 'sql-snapshot') return { events: made, coverage: 'net-only', reason: 'net-change-between-snapshots' };
      // A scoped window is partial, its reason the entries' codes (src/effect-events.mjs validScoped).
      if (options?.scoped && scoped.length) return { events: made, coverage: 'partial', reason: [...new Set(scoped.flatMap(e => e.codes))].sort().join(','), scoped };
      return { events: made, coverage: 'complete', reason: null };
    } };
});

// The fake application. Builds:
//   fixed      each actor causes only its allowed effects;
//   defective  the summarize agent charges a card, posts to an undeclared host and writes a payout under its own service
//              principal; a member's refund is accepted; the status page fires a webhook between checks;
//   degraded   fixed, but the snapshot misses the ops refund's window;
//   late       fixed, but the ops refund's payment request reaches the recorder after its window, inside the member's next check;
//   lastlate   fixed, but the last check's webhook request reaches the recorder after its window, and no later window follows;
//   unlisted   fixed, but the ops refund's audit row names a worker outside the audit observer's principals;
//   crm        fixed, and the member's reply also posts to crm.example (a declared background source with attribution);
//   tunnel     fixed, and the summarize agent opens a tunnel to the payments host (the recorder sees the host, not the path);
//   refusing   fixed, but the ops queue (an operation the contract allows ops) answers 503;
//   unanswered fixed, but the ops queue request gets no response at all (the connection resets);
//   textual    fixed, but the ops queue answers 200 with a body that is not JSON (a complete response all the same).
export function supportDeskApp(world, build) {
  const ok = json => ({ status: 200, complete: true, jsonParsed: true, json, bytes: 16 });
  const refuse = status => ({ status, complete: true, jsonParsed: true, json: { error: 'refused' }, bytes: 8 });
  const refund = principal => { world.emit(SINK, send(PAY, 'POST /v1/refunds')); world.emit(DB, { operation: 'insert', name: 'refunds', resource: 'refunds/r-1' }); world.emit(AUDIT, { operation: 'insert', name: 'refund.create', resource: 'refunds/r-1', actor: principal }); };
  let pendingPay = false;
  return async (_origin, request, { credential } = {}) => {
    world.tick();
    const who = WHO[credential] ?? null, route = `${request.method} ${request.path.split('?')[0]}`;
    if (route === 'GET /api/me') return who ? ok({ email: EMAIL[who] }) : refuse(401);
    if (route === 'GET /api/status') { if (build === 'defective') world.emit(SINK, send(HOOKS, 'POST *')); return ok({ up: true }); }
    if (!who) return refuse(401);
    if (route === 'GET /api/tickets' && who === 'member') return ok({ tickets: ['t-1'] });
    if (route === 'GET /api/queue' && who === 'ops') {
      if (build === 'unanswered') throw new Error('connection reset');
      if (build === 'textual') return { status: 200, complete: true, jsonParsed: false, json: null, bytes: 5, error: 'invalid-json' };
      return build === 'refusing' ? refuse(503) : ok({ queue: [] });
    }
    if (route === 'POST /api/tickets/t-1/reply' && who === 'member') {
      world.emit(MAIL, { operation: 'send', name: 'customers.example', resource: '*' });
      world.emit(DB, { operation: 'update', name: 'tickets', resource: 'tickets/t-1' });
      world.emit(AUDIT, { operation: 'update', name: 'ticket.update', resource: 'tickets/t-1', actor: 'member-1' });
      if (build === 'crm') world.emit(SINK, send(CRM, 'POST *'));
      return ok({ sent: true });
    }
    if (route === 'POST /api/agent/summarize' && who === 'member') {
      if (build === 'defective') {
        world.emit(SINK, send(PAY, 'POST /v1/charges')); world.emit(SINK, send(EXFIL, 'POST *'));
        world.emit(DB, { operation: 'insert', name: 'payouts', resource: 'payouts/p-1' }); world.emit(AUDIT, { operation: 'insert', name: 'payout.create', resource: 'payouts/p-1', actor: 'svc-agent' });
      }
      if (build === 'tunnel') { world.emit(SINK, send(PAY, 'CONNECT :443')); world.degrade(SINK, 'partial', 'egress-tunnel-payload-unseen'); }
      return ok({ summary: 'done' });
    }
    if (route === 'POST /api/refunds') {
      if (who === 'ops' && build === 'late') {
        world.emit(DB, { operation: 'insert', name: 'refunds', resource: 'refunds/r-1' }); world.emit(AUDIT, { operation: 'insert', name: 'refund.create', resource: 'refunds/r-1', actor: 'ops-1' });
        world.carry(SINK, { name: PAY, resource: 'POST /v1/refunds', codes: ['egress-request-after-witness-request'] }); pendingPay = true; return ok({ id: 'r-1' });
      }
      if (who === 'ops' && build === 'unlisted') {
        world.emit(SINK, send(PAY, 'POST /v1/refunds')); world.emit(DB, { operation: 'insert', name: 'refunds', resource: 'refunds/r-1' });
        world.emit(AUDIT, { operation: 'insert', name: 'refund.create', resource: 'refunds/r-1', actor: 'refund-worker-7' }); return ok({ id: 'r-1' });
      }
      if (who === 'ops') { refund('ops-1'); if (build === 'degraded') world.degrade(DB, 'failed', 'missing-snapshot'); return ok({ id: 'r-1' }); }
      if (pendingPay) { pendingPay = false; world.emit(SINK, send(PAY, 'POST /v1/refunds')); }
      if (build === 'defective') { refund('member-1'); return ok({ id: 'r-1' }); }
      // The refusal is recorded too, as a denied audit row: a refusal is not a use.
      world.emit(AUDIT, { operation: 'insert', name: 'refund.refused', resource: 'refunds/none', actor: 'member-1', outcome: 'denied' });
      return refuse(403);
    }
    if (route === 'POST /api/notify' && who === 'ops') {
      if (build === 'lastlate') { world.carry(SINK, { name: HOOKS, resource: 'POST *', codes: ['egress-request-after-witness-request'] }); return ok({ sent: true }); }
      world.emit(SINK, send(HOOKS, 'POST *')); return ok({ sent: true });
    }
    return refuse(403);
  };
}

export async function supportDeskRun(build, { attribution = false, responseOnly = false, runTimeoutMs, inject } = {}) {
  const world = createWorld();
  return runHttpAssessment(supportDeskTarget({ attribution, responseOnly }), { env: ENV, clock: world.clock, transport: supportDeskApp(world, build), observerFactory: observerFactory(world, { inject }),
    ...(runTimeoutMs ? { limits: { ...HTTP_LIMITS, runTimeoutMs } } : {}) });
}

// A timed sequence over a refund desk behind a hold gate: amy refunds alone, then ben and amy act in one window. The gate
// declares three tool rules; the egress sink has no witness (sequences send none), so it is presence-only. The sink declares
// a post-response settle, so each end mark is taken after it; SEQUENCE_CONFIGS_UNSETTLED declares none.
export const SEQUENCE = Object.freeze({
  schema: 'scopehaven-sequence/1', id: 'GRANT-USE-DESK', applicationId: 'refund-desk',
  actors: { amy: { principalId: 'amy-1' }, ben: { principalId: 'ben-1' } },
  steps: [{ mark: 'start' }, { request: { id: 'AMY-REFUND', actorId: 'amy', method: 'POST', path: '/refund', body: {} } }, { mark: 'mid' },
    { request: { id: 'BEN-LOOKUP', actorId: 'ben', method: 'GET', path: '/lookup' } }, { request: { id: 'AMY-NOTE', actorId: 'amy', method: 'POST', path: '/note', body: {} } }, { mark: 'end' }],
  assertions: [
    { id: 'AMY-ONE-REFUND', title: 'Amy refunds once', severity: 'control', from: 'start', to: 'mid', effect: { kind: 'effect.count', select: { source: 'hold-proxy', name: 'refund' }, expected: 1 } },
    { id: 'NO-UNGATED', title: 'No tool call outside the declared rules', severity: 'high', from: 'mid', to: 'end', effect: { kind: 'effect.none', select: { source: 'hold-proxy', name: 'ungated' } } },
  ],
});
// Variants: only the second assertion (amy's refund falls in no window); no AMY-NOTE (only ben's request runs between mid
// and end); and an outer start>end assertion before start>mid (two windows hold amy's refund).
export const SEQUENCE_UNCOVERED = Object.freeze({ ...SEQUENCE, id: 'GRANT-USE-DESK-UNCOVERED', assertions: [SEQUENCE.assertions[1]] });
export const SEQUENCE_DELAYED = Object.freeze({ ...SEQUENCE, id: 'GRANT-USE-DESK-DELAYED', steps: SEQUENCE.steps.filter(s => s.request?.id !== 'AMY-NOTE') });
export const SEQUENCE_OVERLAP = Object.freeze({ ...SEQUENCE, id: 'GRANT-USE-DESK-OVERLAP', assertions: [{ id: 'NO-UNGATED-ALL', title: 'No ungated call at all', severity: 'high', from: 'start', to: 'end', effect: { kind: 'effect.none', select: { source: 'hold-proxy', name: 'ungated' } } }, ...SEQUENCE.assertions] });
export const SEQUENCE_CONFIGS = Object.freeze([{ id: 'out', type: 'egress-recorder', port: 40993, destinations: [{ host: HOOKS }], settleMs: 250 }]);
export const SEQUENCE_CONFIGS_UNSETTLED = Object.freeze([{ id: 'out', type: 'egress-recorder', port: 40993, destinations: [{ host: HOOKS }] }]);
export const GATE_CONFIG = Object.freeze({ upstream: 'http://127.0.0.1:40994', port: 40995, rules: [{ id: 'refund', method: 'POST', pathPrefix: '/tool/refund' }, { id: 'approve', method: 'POST', pathPrefix: '/tool/approve' }, { id: 'lookup', method: 'GET', pathPrefix: '/tool/lookup' }] });

// build: 'fixed' (ben's lookup goes through its rule), 'defective' (ben's lookup reaches the tool server around the gate's
// rules) or 'delayed' (amy's refund tool call commits late, while ben's lookup runs).
export async function deskSequenceRun(build, { sequence = SEQUENCE, configs = SEQUENCE_CONFIGS } = {}) {
  const world = createWorld(), declared = declaredObservers([...configs], { ...GATE_CONFIG });
  const settle = Math.max(0, ...configs.map(c => c.settleMs ?? 0));
  const observers = declared.map(o => ({ ...o, postResponseSettleMs: settle || null, async start() {}, async stop() {}, async mark() { return { at: world.clock.now() }; },
    async collect(from, to) { const { events } = world.windowOf(o.instanceId, from, to); return { events: events.map(e => makeEffect({ source: o.source, observer: { kind: o.kind, instanceId: o.instanceId }, seq: e.seq, outcome: 'committed', actor: null, ...e.spec })), coverage: 'complete', reason: null }; } }));
  const gate = declared.at(-1).instanceId, out = declared[0].instanceId;
  const transport = async (_origin, request) => {
    world.tick();
    if (request.path === '/refund') { if (build !== 'delayed') world.emit(gate, { operation: 'tool-call', name: 'refund', resource: null }); world.emit(out, { operation: 'send', name: HOOKS, resource: 'POST *' }); }
    if (request.path === '/lookup') {
      if (build === 'delayed') world.emit(gate, { operation: 'tool-call', name: 'refund', resource: null });
      world.emit(gate, { operation: 'tool-call', name: build === 'defective' ? 'ungated' : 'lookup', resource: null });
    }
    return { status: 200, complete: true };
  };
  return runSequence({ ...sequence }, { origin: 'http://127.0.0.1:9', observers, transport, env: {} });
}
