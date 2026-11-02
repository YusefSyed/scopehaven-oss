// Grant versus use. Owned synthetic records only: every HTTP run is a real connector run over the support-desk
// fixture (an injected transport and in-memory observers on a virtual clock, fixtures/support-desk.mjs), and every sequence
// run a real sequence run over in-memory observers. No socket, database, model or provider is used.
//
// The properties below are each tested on the shipped reader and then on one mutant of it that breaks that property alone:
// the mutant must fail the same check (the mutation sweep at the end).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as reader from './grant-use.mjs';
import { renderGrantUseMarkdown } from './render.mjs';
import { main } from './cli.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';
import { supportDeskRun, supportDeskTarget, deskSequenceRun, SEQUENCE, SEQUENCE_UNCOVERED, SEQUENCE_DELAYED, SEQUENCE_OVERLAP, SEQUENCE_CONFIGS, SEQUENCE_CONFIGS_UNSETTLED, GATE_CONFIG, INVENTORY, CONTRACT, PAY, CRM, SINK } from './fixtures/support-desk.mjs';

const RUNS = {
  fixed: await supportDeskRun('fixed'), defective: await supportDeskRun('defective'), degraded: await supportDeskRun('degraded'), late: await supportDeskRun('late'),
  lastlate: await supportDeskRun('lastlate'), unlisted: await supportDeskRun('unlisted'), tunnel: await supportDeskRun('tunnel'), refusing: await supportDeskRun('refusing'),
  undrained: await supportDeskRun('fixed', { attribution: true }), crm: await supportDeskRun('crm', { attribution: true }), unanswered: await supportDeskRun('unanswered'), textual: await supportDeskRun('textual'),
  // The short budget leaves OPS-REFUND unattempted; a background send lands in its window (the third the recorder collects).
  budget: await supportDeskRun('fixed', { runTimeoutMs: 600, inject: [{ instance: SINK, window: 3, spec: { operation: 'send', name: CRM, resource: 'POST *' } }] }),
  seqFixed: await deskSequenceRun('fixed'), seqDefective: await deskSequenceRun('defective'), seqUncovered: await deskSequenceRun('fixed', { sequence: SEQUENCE_UNCOVERED }),
  seqDelayed: await deskSequenceRun('delayed', { sequence: SEQUENCE_DELAYED }), seqOverlap: await deskSequenceRun('fixed', { sequence: SEQUENCE_OVERLAP }),
  seqUnsettled: await deskSequenceRun('fixed', { configs: SEQUENCE_CONFIGS_UNSETTLED }),
};
const target = options => supportDeskTarget(options);
const http = (mod, runs, extra = {}) => mod.grantUseReport({ target: target(), runs, inventory: INVENTORY, contract: CONTRACT, ...extra });
const seq = (mod, runs, sequence = SEQUENCE) => mod.sequenceGrantUseReport({ sequence: { ...sequence }, runs, configs: [...SEQUENCE_CONFIGS], gateConfig: { ...GATE_CONFIG } });
const actor = (report, alias) => report.actors.find(a => a.alias === alias);
const keys = list => list.map(x => (typeof x === 'string' ? x : x.key)).sort();
const sorted = list => [...list].sort();
const DESTINATIONS = ['egress api.pay.example /v1/refunds', 'egress api.pay.example /v1/charges', 'egress hooks.chat.example', 'egress crm.example', 'mail customers.example', 'mail acme.example'];
const TABLES = ['table tickets', 'table refunds', 'table payouts'], ACTIONS = ['action ticket.update', 'action refund.create', 'action payout.create'];
const REACH = [...DESTINATIONS, ...TABLES, ...ACTIONS];
const OWN_RECORDS = ['application-records-only'], SNAPSHOT = ['application-records-only', 'net-change-only'];

test('every fixture run is a valid connector record (the reader reads real records)', () => {
  for (const name of ['fixed', 'defective', 'degraded', 'late', 'lastlate', 'unlisted', 'tunnel', 'refusing', 'unanswered', 'textual', 'undrained', 'crm', 'budget']) assert.doesNotThrow(() => validateHttpRunEvidence(RUNS[name]), name);
  assert.equal(RUNS.defective.results.find(r => r.id === 'MEMBER-SUMMARIZE').status, 'fail');
  assert.equal(RUNS.defective.results.find(r => r.id === 'MEMBER-NO-REFUND').status, 'fail');
  assert.equal(RUNS.seqDefective.results.find(r => r.id === 'NO-UNGATED').status, 'fail');
  assert.ok(RUNS.budget.results.some(r => r.trace[0].data.requestAttempted === false), 'the short budget leaves rows unattempted');
  assert.ok(RUNS.unlisted.results.find(r => r.id === 'OPS-REFUND').trace[1].data.windows.find(w => w.source === 'sql-audit-table').events[0].actor.startsWith('unlisted:'));
});

// The properties. Each check takes a reader module (the shipped one, or a mutant) and asserts one rule.
const PROPERTIES = [];
const property = (name, check, mutation) => { PROPERTIES.push({ name, check, mutation }); test(name, () => check(reader)); };

property('fixed build: the known grant, the uses per actor, and the clean excess held outside the application', mod => {
  const r = http(mod, [RUNS.fixed]);
  assert.deepEqual(r.headline, { runs: 1, status: 'complete', granted: { destination: 6, table: 3, action: 13 }, used: { destination: 3, table: 2, action: 10 }, possiblyUsed: { destination: 0, table: 0, action: 0 },
    refused: { destination: 0, table: 0, action: 0 }, excess: { destination: 3, table: 0, action: 0 }, qualified: { destination: 0, table: 1, action: 1 }, unobservable: { destination: 0, table: 0, action: 2 }, usedNotGranted: 0 });
  const member = actor(r, 'member'), ops = actor(r, 'ops'), visitor = actor(r, 'visitor');
  assert.deepEqual(keys(member.used), sorted(['mail customers.example', 'table tickets', 'action ticket.update', 'operation GET /api/me none', 'operation GET /api/tickets own', 'operation POST /api/tickets/:id/reply own', 'operation POST /api/agent/summarize none']));
  assert.deepEqual(member.excess, { status: 'complete', entries: ['egress api.pay.example /v1/refunds', 'egress api.pay.example /v1/charges', 'egress hooks.chat.example', 'egress crm.example', 'mail acme.example'],
    qualified: [{ key: 'table refunds', basis: SNAPSHOT }, { key: 'table payouts', basis: SNAPSHOT }, { key: 'action refund.create', basis: OWN_RECORDS }, { key: 'action payout.create', basis: OWN_RECORDS }] });
  assert.deepEqual(keys(ops.used), sorted(['egress api.pay.example /v1/refunds', 'egress hooks.chat.example', 'table refunds', 'action refund.create', 'operation GET /api/me none', 'operation GET /api/queue none', 'operation POST /api/refunds none', 'operation POST /api/notify none']));
  assert.deepEqual(ops.excess.entries, ['egress api.pay.example /v1/charges', 'egress crm.example', 'mail customers.example', 'mail acme.example']);
  assert.deepEqual(keys(visitor.used), ['operation GET /api/status none']);
  assert.deepEqual(visitor.excess.entries, DESTINATIONS);
  assert.deepEqual(keys(visitor.excess.qualified), sorted([...TABLES, ...ACTIONS]));
  for (const a of r.actors) { assert.deepEqual(a.usedNotGranted, [], a.alias); assert.deepEqual(a.possiblyUsed, [], a.alias); assert.deepEqual(a.refused, [], a.alias); }
}, ['const accepted = data => answered(data) && data.httpStatus >= 200 && data.httpStatus < 300;', 'const accepted = data => answered(data);']);

property('a use is a committed event only: a refused (denied) audit row is not a use', mod => {
  const member = actor(http(mod, [RUNS.fixed]), 'member');
  assert.deepEqual(member.usedNotGranted, []);
  assert.ok(member.excess.qualified.some(q => q.key === 'action refund.create'));
}, ["if (ev.outcome === 'committed' && READ_SOURCES.includes(ev.source))", 'if (READ_SOURCES.includes(ev.source))']);

property('every use cites its run, record, observer, seq and custody class', mod => {
  const member = actor(http(mod, [RUNS.fixed]), 'member');
  const mail = member.used.find(u => u.key === 'mail customers.example').uses[0], table = member.used.find(u => u.key === 'table tickets').uses[0];
  assert.deepEqual({ ...mail, run: null }, { run: null, record: 'check-window', checkId: 'MEMBER-REPLY', observer: 'smtp-sink-mail', source: 'smtp-capture', seq: 1, operation: 'send', name: 'customers.example', resource: '*', custody: 'independent', windowActors: ['member'], attributedBy: 'check-window' });
  assert.equal(mail.run, RUNS.fixed.id);
  assert.equal(table.custody, 'subject-writable');
  const audit = member.used.find(u => u.key === 'action ticket.update').uses[0];
  assert.deepEqual([audit.principal, audit.attributedBy, audit.custody], ['member-1', 'record-principal', 'subject-writable']);
  const op = member.used.find(u => u.key === 'operation GET /api/me none').uses[0];
  assert.deepEqual([op.record, op.checkId, op.httpStatus, op.custody], ['http-response', 'MEMBER-ME', 200, 'subject-writable']);
}, ["const custodyOf = w => (w.source === 'provider-feed' ? feedKeyCustody(w.scope?.feed) : CUSTODY_BY_SOURCE[w.source] ?? 'subject-writable');", "const custodyOf = () => 'independent';"]);

property('a snapshot\'s net change does not make the records incomplete', mod => {
  assert.ok(http(mod, [RUNS.fixed]).actors.every(a => a.excess.status === 'complete'));
}, ["const SETTLED = Object.freeze(['complete', 'net-only']);", "const SETTLED = Object.freeze(['complete']);"]);

property('a table only snapshots see is never clean excess: it is qualified as net change only', mod => {
  const member = actor(http(mod, [RUNS.fixed]), 'member');
  assert.deepEqual(member.excess.qualified.find(q => q.key === 'table payouts'), { key: 'table payouts', basis: SNAPSHOT });
  assert.match(renderGrantUseMarkdown(http(mod, [RUNS.fixed])), /a table is never listed as never exercised/);
}, ["if (deciding.every(w => w.source === 'sql-snapshot')) why.push('net-change-only');", "if (false) why.push('net-change-only');"]);

property('an entry only the application\'s own records could show is qualified, never clean excess (the application can hide a use there)', mod => {
  const member = actor(http(mod, [RUNS.fixed]), 'member');
  assert.ok(!member.excess.entries.includes('action payout.create'));
  assert.deepEqual(member.excess.qualified.find(q => q.key === 'action payout.create'), { key: 'action payout.create', basis: OWN_RECORDS });
}, ["if (deciding.every(w => custodyOf(w) === 'subject-writable')) why.push('application-records-only');", "if (false) why.push('application-records-only');"]);

property('defective twin: an undeclared host is used but not granted, linked to the row that already fails on it', mod => {
  const member = actor(http(mod, [RUNS.fixed, RUNS.defective]), 'member');
  const host = member.usedNotGranted.find(n => n.key === 'egress exfil.example');
  assert.equal(host.kind, 'host-undeclared');
  assert.deepEqual(host.findings, [{ run: RUNS.defective.id, id: 'MEMBER-SUMMARIZE' }]);
  assert.equal(host.unchecked, undefined);
  assert.equal(host.uses[0].custody, 'independent');
}, ["failing: r.status === 'fail' ? [r.id] : [], wide: wide[k] }", 'failing: [], wide: wide[k] }']);

property('defective twin: a send is credited to the declared path it names, never to another path of the host', mod => {
  const member = actor(http(mod, [RUNS.defective]), 'member');
  assert.equal(member.used.find(u => u.key === 'egress api.pay.example /v1/charges').uses[0].resource, 'POST /v1/charges');
  assert.equal(member.used.find(u => u.key === 'egress api.pay.example /v1/refunds').uses[0].checkId, 'MEMBER-NO-REFUND');
}, ['const hit = paths.find(e => e.path === path);', 'const hit = paths[0];']);

property('defective twin: an operation the contract denies the role is used but not granted, linked to its failing row', mod => {
  const member = actor(http(mod, [RUNS.defective]), 'member');
  assert.ok(!member.granted.includes('operation POST /api/refunds none'));
  const denied = member.usedNotGranted.find(n => n.key === 'operation POST /api/refunds none');
  assert.equal(denied.kind, 'operation-denied');
  assert.deepEqual(denied.findings, [{ run: RUNS.defective.id, id: 'MEMBER-NO-REFUND' }]);
}, ["const mine = coverage.cells.filter(c => ['allow', 'conditional'].includes(c.stated) &&", 'const mine = coverage.cells.filter(c => c.stated !== null &&']);

property('the record\'s own principal decides who used it: a service principal inside a member\'s check is not the member\'s use', mod => {
  const r = http(mod, [RUNS.defective]), member = actor(r, 'member');
  assert.ok(!keys(member.used).includes('action payout.create') && !keys(member.possiblyUsed).includes('action payout.create'));
  assert.deepEqual(r.undeclaredPrincipals.map(p => [p.principalId, keys(p.uses)]), [['svc-agent', ['action payout.create']]]);
  assert.equal(r.undeclaredPrincipals[0].uses[0].uses[0].attributedBy, 'record-principal');
}, ['const named = principalScope && !unknownPrincipal(ev.actor) ? ev.actor : null;', 'const named = null;']);

property('a principal the record names only as "unlisted:" is unknown: possibly the window\'s actor, never another principal', mod => {
  const r = http(mod, [RUNS.unlisted]), ops = actor(r, 'ops');
  assert.ok(!keys(ops.used).includes('action refund.create'));
  assert.deepEqual(keys(ops.possiblyUsed), ['action refund.create']);
  assert.equal(ops.possiblyUsed[0].uses[0].attributedBy, 'principal-unknown');
  assert.ok(!ops.excess.entries.includes('action refund.create') && !ops.excess.qualified.some(q => q.key === 'action refund.create'));
  assert.deepEqual(r.undeclaredPrincipals, []);
}, ['const named = principalScope && !unknownPrincipal(ev.actor) ? ev.actor : null;', 'const named = principalScope && ev.actor !== null ? ev.actor : null;']);

property('delegated authority (F-03): an effect recorded under another principal inside an actor\'s own check is listed for that actor', mod => {
  const member = actor(http(mod, [RUNS.defective]), 'member');
  assert.deepEqual(member.delegated.map(d => [d.principalId, d.keys, d.use.checkId]), [['svc-agent', ['action payout.create'], 'MEMBER-SUMMARIZE']]);
  assert.match(renderGrantUseMarkdown(http(mod, [RUNS.defective])), /During member's MEMBER-SUMMARIZE \(run [0-9a-f]{8}\), sql-audit-table recorded `action payout\.create` under `svc-agent`, a principal no actor declares/);
}, ['if (by !== actor && books.has(by))', 'if (false)']);

property('a declared background source is attributed to no check: possibly used by the window\'s actor, never used', mod => {
  const member = actor(mod.grantUseReport({ target: target({ attribution: true }), runs: [RUNS.crm] }), 'member');
  assert.ok(!keys(member.used).includes('egress crm.example'));
  assert.deepEqual(member.possiblyUsed.map(p => [p.key, p.uses[0].attributedBy, p.uses[0].checkId]), [['egress crm.example', 'background-source', 'MEMBER-REPLY']]);
}, ['const fitsBackground = background.some(s => fitsSelector(ev, s.select));', 'const fitsBackground = false;']);

property('an event between checks is possibly used by every actor who could have caused it, and never excess for them', mod => {
  const r = http(mod, [RUNS.defective]), visitor = actor(r, 'visitor'), member = actor(r, 'member');
  assert.deepEqual(keys(visitor.possiblyUsed), ['egress hooks.chat.example']);
  assert.equal(visitor.possiblyUsed[0].uses[0].attributedBy, 'gap-window-shared');
  assert.ok(!visitor.excess.entries.includes('egress hooks.chat.example'));
  assert.ok(!keys(member.used).includes('egress hooks.chat.example') && keys(member.possiblyUsed).includes('egress hooks.chat.example'));
}, ['const ownHolders = holders.filter(h => h.p.own)', 'const ownHolders = holders']);

property('a gap\'s candidates include the effect row before it (its late sends land there)', mod => {
  assert.deepEqual(actor(http(mod, [RUNS.defective]), 'visitor').possiblyUsed[0].uses[0].windowActors, ['member', 'ops', 'visitor']);
}, ['results.slice(after === null ? 0 : order.get(after),', 'results.slice(after === null ? 0 : order.get(after) + 1,']);

property('a gap\'s candidates include the effect row after it (its identity probe point comes first)', mod => {
  assert.deepEqual(actor(http(mod, [RUNS.defective]), 'visitor').possiblyUsed[0].uses[0].windowActors, ['member', 'ops', 'visitor']);
}, ['next === null ? results.length : order.get(next) + 1)', 'next === null ? results.length : order.get(next))']);

property('a tunnel names a host and no path: possibly any declared path of it, never one path, never undeclared', mod => {
  const member = actor(http(mod, [RUNS.tunnel]), 'member');
  assert.deepEqual(keys(member.possiblyUsed), ['egress api.pay.example /v1/charges', 'egress api.pay.example /v1/refunds']);
  assert.ok(member.possiblyUsed.every(p => p.uses[0].pathUnknown === true));
  assert.deepEqual(member.usedNotGranted, []);
}, ["if (method === 'CONNECT' || ambiguous.has(host) || ambiguous.has('*'))", "if (ambiguous.has(host) || ambiguous.has('*'))"]);

property('incomplete records: a missing snapshot makes that actor\'s excess inconclusive, with no excess list', mod => {
  const r = http(mod, [RUNS.degraded]), ops = actor(r, 'ops');
  assert.equal(ops.excess.status, 'inconclusive');
  assert.equal(Object.hasOwn(ops.excess, 'entries'), false);
  assert.ok(ops.excess.notSeen.includes('table payouts') && ops.excess.notSeen.includes('table refunds'));
  assert.deepEqual(ops.excess.reasons, [{ run: RUNS.degraded.id, record: 'check-window', at: 'OPS-REFUND', observer: 'sqlite-snapshot-db', coverage: 'failed', reason: 'missing-snapshot' }]);
  assert.equal(actor(r, 'member').excess.status, 'complete');
  assert.equal(r.headline.status, 'inconclusive');
  assert.equal(r.headline.excess, undefined);
}, ['if (!SETTLED.includes(w.coverage) && !scoped.length) reasons.push(', 'if (false) reasons.push(']);

property('an inconclusive excess carries only what the records did not show, never an excess list', mod => {
  const ops = actor(http(mod, [RUNS.degraded]), 'ops');
  assert.deepEqual(Object.keys(ops.excess).sort(), ['notSeen', 'reasons', 'status', 'undetermined']);
}, ["{ status: 'inconclusive', notSeen: open, reasons: dedupe(reasons) }", "{ status: 'inconclusive', entries: open, notSeen: open, reasons: dedupe(reasons) }"]);

property('a recorder that did not drain at the run end leaves every actor that acted inconclusive', mod => {
  const r = mod.grantUseReport({ target: target({ attribution: true }), runs: [RUNS.undrained] });
  assert.deepEqual(RUNS.undrained.settlement.drains.map(d => d.quiescent), [false]);
  for (const a of r.actors) {
    assert.equal(a.excess.status, 'inconclusive', a.alias);
    assert.deepEqual(a.excess.reasons, [{ run: RUNS.undrained.id, reason: 'collector-not-drained', observer: 'egress-recorder-sink' }]);
    assert.ok(a.excess.undetermined.every(u => u.key.startsWith('egress ')), a.alias);
  }
}, ['if (!(d.quiescent === true && d.markClear === true && d.closedAfterCollect === false)) {', 'if (false) {']);

property('a send its recorder carried late is shared between the window that carried it and the one it landed in', mod => {
  const r = http(mod, [RUNS.late]), member = actor(r, 'member'), ops = actor(r, 'ops');
  assert.ok(!keys(member.used).includes('egress api.pay.example /v1/refunds'));
  assert.deepEqual(keys(member.possiblyUsed), ['egress api.pay.example /v1/refunds']);
  assert.equal(member.possiblyUsed[0].uses[0].attributedBy, 'late-entry');
  assert.deepEqual(keys(ops.possiblyUsed), ['egress api.pay.example /v1/refunds']);
}, ['l.name === lower(ev.name) && l.order < p.order', 'l.name === lower(ev.name) && false']);

property('a followed late entry casts doubt only on the entry its send could be (its own path)', mod => {
  const ops = actor(http(mod, [RUNS.late]), 'ops');
  assert.equal(ops.excess.status, 'complete');
  assert.ok(ops.excess.entries.includes('egress api.pay.example /v1/charges') && ops.excess.entries.includes('egress crm.example'));
}, ["s.resource.split(' ')[1] === e.path);", 'true);']);

property('a followed scoped window is judged per entry, not window-wide', mod => {
  assert.equal(actor(http(mod, [RUNS.late]), 'ops').excess.status, 'complete');
}, ['if (!SETTLED.includes(w.coverage) && !scoped.length)', 'if (!SETTLED.includes(w.coverage))']);

property('a late entry nothing later followed is read window-wide, as src reads it: every entry its recorder sees is in doubt', mod => {
  const ops = actor(http(mod, [RUNS.lastlate]), 'ops');
  assert.equal(ops.excess.status, 'inconclusive');
  const crm = ops.excess.undetermined.find(u => u.key === 'egress crm.example');
  assert.deepEqual(crm.reasons, [{ run: RUNS.lastlate.id, record: 'check-window', at: 'OPS-NOTIFY', observer: 'egress-recorder-sink', coverage: 'partial', reason: 'egress-request-after-witness-request', unfollowed: true }]);
}, ['const scoped = validScoped(w) && !p.wide.has(w.instanceId) ? w.scoped : [];', 'const scoped = validScoped(w) ? w.scoped : [];']);

property('an actor no run sent a request as reads inconclusive, never a clean statement', mod => {
  for (const a of http(mod, []).actors) { assert.equal(a.excess.status, 'inconclusive', a.alias); assert.deepEqual(a.excess.reasons, [{ reason: 'actor-not-in-runs' }]); }
}, ["(acted ? [] : [{ reason: 'actor-not-in-runs' }])", '[]']);

property('a row whose request was never attempted (the run budget ran out) is not the actor\'s: it neither acts nor owns its window', mod => {
  const visitor = actor(http(mod, [RUNS.budget]), 'visitor');
  assert.equal(RUNS.budget.results.find(r => r.id === 'VISITOR-STATUS').trace[0].data.requestAttempted, false);
  assert.equal(visitor.excess.status, 'inconclusive');
  assert.deepEqual(visitor.excess.reasons, [{ reason: 'actor-not-in-runs' }]);
}, ['&& r.trace?.[0]?.data?.requestAttempted !== false;', ';']);

property('a row whose request was never attempted owns no window: what lands there is possibly any earlier actor\'s', mod => {
  const ops = actor(http(mod, [RUNS.budget]), 'ops');
  assert.equal(RUNS.budget.results.find(r => r.id === 'OPS-REFUND').trace[0].data.requestAttempted, false);
  assert.ok(!keys(ops.used).includes('egress crm.example'));
  assert.deepEqual(ops.possiblyUsed.map(p => [p.key, p.uses[0].checkId, p.uses[0].attributedBy, p.uses[0].windowActors]), [['egress crm.example', 'OPS-REFUND', 'check-window-shared', ['member', 'ops']]]);
}, ['own: mine, candidates: mine ? [byId.get(r.id).actorId] : before(r.id),', 'own: true, candidates: [byId.get(r.id).actorId],']);

property('operations are never excess: one no check requests as the actor is not observable here', mod => {
  const member = actor(http(mod, [RUNS.fixed]), 'member');
  assert.ok(member.excess.entries.every(k => !k.startsWith('operation ')));
  assert.deepEqual(member.unobservable, [{ key: 'operation GET /api/status none', reason: 'no-check-requests-it' }]);
}, ['granted.filter(k => !used.has(k) && !possibly.has(k) && !blind.has(k) && !isOperation(k))', 'granted.filter(k => !used.has(k) && !possibly.has(k) && !blind.has(k))']);

property('an allowed operation the actor requested and the application refused is listed as refused, never as unused', mod => {
  const r = http(mod, [RUNS.refusing]), ops = actor(r, 'ops');
  assert.deepEqual(ops.refused.map(x => [x.key, x.uses[0].checkId, x.uses[0].httpStatus]), [['operation GET /api/queue none', 'OPS-QUEUE', 503]]);
  assert.ok(!ops.unobservable.some(u => u.key === 'operation GET /api/queue none'));
  assert.deepEqual(r.headline.refused, { destination: 0, table: 0, action: 1 });
}, ['} else if (permitted && u.answered) for (const target of [l, app])', '} else if (false) for (const target of [l, app])']);

property('an allowed request that got no complete response (a reset) is neither refused nor unused: it is not observable', mod => {
  const r = http(mod, [RUNS.unanswered]), ops = actor(r, 'ops');
  assert.equal(RUNS.unanswered.results.find(x => x.id === 'OPS-QUEUE').trace[0].data.httpStatus, null);
  assert.deepEqual(ops.refused, []);
  assert.ok(ops.unobservable.some(u => u.key === 'operation GET /api/queue none' && u.reason === 'request-unanswered'));
  assert.deepEqual(r.headline.refused, { destination: 0, table: 0, action: 0 });
}, ['} else if (permitted && u.answered) for (const target of [l, app])', '} else if (permitted) for (const target of [l, app])']);

property('a complete response whose body is not JSON is still an answer: a 200 with a text body is a use', mod => {
  const ops = actor(http(mod, [RUNS.textual]), 'ops');
  assert.equal(RUNS.textual.results.find(x => x.id === 'OPS-QUEUE').trace[0].data.transportOutcome, 'invalid-json');
  assert.ok(keys(ops.used).includes('operation GET /api/queue none'));
  assert.ok(!ops.unobservable.some(u => u.key === 'operation GET /api/queue none'));
}, ["data.responseComplete === true && ['complete', 'invalid-json'].includes(data.transportOutcome)", "data.responseComplete === true && data.transportOutcome === 'complete'"]);

property('sequence: with no declared settle the end marks follow the last request at once, so the excess is qualified, never clean', mod => {
  const r = mod.sequenceGrantUseReport({ sequence: { ...SEQUENCE }, runs: [RUNS.seqUnsettled], configs: [...SEQUENCE_CONFIGS_UNSETTLED], gateConfig: { ...GATE_CONFIG } });
  assert.deepEqual(actor(r, 'amy').excess, { status: 'complete', entries: [], qualified: [{ key: 'tool approve', basis: ['no-settle-declared'] }] });
  assert.deepEqual(actor(seq(mod, [RUNS.seqFixed]), 'amy').excess.entries, ['tool approve']);
}, ['if (!configs.some(c => c?.type !== \'otel\' && settleDeclared(c?.settleMs))) for', 'if (false) for']);

property('sequence: hold-gate rules are actions; a window only one actor could have caused is that actor\'s, a shared one is possibly either\'s', mod => {
  const r = seq(mod, [RUNS.seqFixed]), amy = actor(r, 'amy'), ben = actor(r, 'ben');
  assert.deepEqual(r.headline.granted, { destination: 1, table: 0, action: 3 });
  assert.deepEqual(keys(amy.used), ['egress hooks.chat.example', 'tool refund']);
  assert.equal(amy.used.find(u => u.key === 'tool refund').uses[0].attributedBy, 'sequence-single-actor');
  assert.deepEqual([keys(amy.possiblyUsed), keys(ben.possiblyUsed)], [['tool lookup'], ['tool lookup']]);
  assert.deepEqual([amy.excess, ben.excess], [{ status: 'complete', entries: ['tool approve'], qualified: [] }, { status: 'complete', entries: ['tool refund', 'tool approve'], qualified: [] }]);
}, ['own: candidates.length === 1, candidates, windows,', 'own: true, candidates, windows,']);

property('sequence: an earlier request\'s effect can commit in a later window, so the later window is shared with its actor', mod => {
  const r = seq(mod, [RUNS.seqDelayed], SEQUENCE_DELAYED), amy = actor(r, 'amy'), ben = actor(r, 'ben');
  assert.ok(!keys(ben.used).includes('tool refund'));
  assert.ok(keys(ben.possiblyUsed).includes('tool refund') && keys(amy.possiblyUsed).includes('tool refund'));
  assert.ok(!amy.excess.entries.includes('tool refund'));
}, ['requests.filter(s => s.i < marks.get(to))', 'requests.filter(s => s.i < marks.get(to) && s.i > marks.get(to) - 2)']);

property('sequence: a request no window spans leaves its actor inconclusive', mod => {
  const r = seq(mod, [RUNS.seqUncovered], SEQUENCE_UNCOVERED), amy = actor(r, 'amy');
  assert.deepEqual(Object.keys(RUNS.seqUncovered.windows), ['mid>end']);
  assert.equal(amy.excess.status, 'inconclusive');
  assert.deepEqual(amy.excess.reasons, [{ run: RUNS.seqUncovered.runDigest, reason: 'request-unobserved', at: 'AMY-REFUND' }]);
  assert.equal(actor(r, 'ben').excess.status, 'complete');
}, ['if (actedHere.has(s.v.actorId) || run.responses === undefined) runFacts.push(', 'if (false) runFacts.push(']);

property('sequence: a use held by overlapping windows cites the window that decided it', mod => {
  const amy = actor(seq(mod, [RUNS.seqOverlap], SEQUENCE_OVERLAP), 'amy'), refund = amy.used.find(u => u.key === 'tool refund').uses[0];
  assert.deepEqual(Object.keys(RUNS.seqOverlap.windows), ['start>end', 'start>mid', 'mid>end']);
  assert.deepEqual([refund.window, refund.windowActors, refund.attributedBy], ['start>mid', ['amy'], 'sequence-single-actor']);
}, ['decisive = ownHolders[0]; actor = decisive.p.candidates[0];', 'decisive = holders[0]; actor = ownHolders[0].p.candidates[0];']);

property('sequence: an ungated tool call is used but not granted, linked to its failing assertion, shared by the window\'s actors', mod => {
  const r = seq(mod, [RUNS.seqDefective]);
  assert.deepEqual(r.application.usedNotGranted.map(n => [n.key, n.kind, n.findings]), [['tool ungated', 'tool-ungated', [{ run: RUNS.seqDefective.runDigest, id: 'NO-UNGATED' }]]]);
  for (const alias of ['amy', 'ben']) assert.equal(actor(r, alias).usedNotGranted[0].shared, true, alias);
}, ["if (a.status === 'fail' && a.window) push(failing,", 'if (false) push(failing,']);

property('presence-only telemetry can show a use but never an absence: its unused entries are unobservable, not excess', mod => {
  const ben = actor(seq(mod, [RUNS.seqFixed]), 'ben');
  assert.deepEqual(ben.unobservable, [{ key: 'egress hooks.chat.example', reason: 'presence-only' }]);
  assert.ok(!ben.excess.entries.includes('egress hooks.chat.example'));
}, ['const deciding = windows.filter(w => authoritative(w) && seesEntry(w, e));', 'const deciding = windows.filter(w => seesEntry(w, e));']);

property('runs of another version of the profile are refused (their rows answer other declarations)', mod => {
  const other = { ...target(), observers: target().observers.map(o => o.id === 'sink' ? { ...o, destinations: [...o.destinations, { host: 'api2.pay.example' }] } : o) };
  assert.throws(() => mod.grantUseReport({ target: other, runs: [RUNS.fixed] }), /recorded under another version of this profile/);
}, ['if (run.profileHash !== profileHash) fail(', 'if (false) fail(']);

property('a run the shared validator refuses is refused (an edited event)', mod => {
  const edited = structuredClone(RUNS.fixed);
  edited.results.find(r => r.id === 'MEMBER-REPLY').trace[1].data.windows.find(w => w.source === 'smtp-capture').events[0].name = 'acme.example';
  assert.throws(() => mod.grantUseReport({ target: target(), runs: [edited] }), /does not pass the run validator/);
}, ['try { validateRun(run); } catch', 'try { void validateRun; } catch']);

property('a sequence run recorded under another observer configuration is refused', mod => {
  assert.throws(() => mod.sequenceGrantUseReport({ sequence: { ...SEQUENCE }, runs: [RUNS.seqFixed], configs: [{ ...SEQUENCE_CONFIGS[0], destinations: [{ host: PAY }] }], gateConfig: { ...GATE_CONFIG } }), /does not pass the sequence run validator/);
}, ['try { validateSequenceRun(run, { expectedSequence: seq, expectedObservers: expected }); }', 'try { void validateSequenceRun; }']);

test('fixed and defective together: the union across runs and the per-run sets', () => {
  const r = http(reader, [RUNS.fixed, RUNS.defective]), member = actor(r, 'member');
  assert.equal(member.used.find(u => u.key === 'mail customers.example').runs, 2);
  assert.equal(member.used.find(u => u.key === 'table payouts').runs, 1);
  const [fixed, defective] = member.perRun;
  assert.deepEqual([fixed.run, defective.run], [RUNS.fixed.id, RUNS.defective.id]);
  assert.ok(!fixed.used.includes('table payouts') && defective.used.includes('table payouts'));
  assert.deepEqual(defective.usedNotGranted, ['egress exfil.example', 'operation POST /api/refunds none']);
  assert.deepEqual(fixed.usedNotGranted, []);
  // Per run, the sets: the fixed run alone leaves the charges path unused; the defective run used it.
  assert.equal(fixed.excess.status, 'complete');
  assert.ok(fixed.excess.entries.includes('egress api.pay.example /v1/charges') && !defective.excess.entries.includes('egress api.pay.example /v1/charges'));
  assert.deepEqual(fixed.excess, actor(http(reader, [RUNS.fixed]), 'member').excess);
  // Each run is read alone: the degraded run's missing snapshot leaves ops inconclusive there and nowhere else.
  const mixed = reader.grantUseReport({ target: target(), runs: [RUNS.fixed, RUNS.degraded] });
  assert.deepEqual(actor(mixed, 'ops').perRun.map(p => p.excess.status), ['complete', 'inconclusive']);
  assert.deepEqual(actor(mixed, 'member').perRun.map(p => p.excess.status), ['complete', 'complete']);
  assert.deepEqual(r.headline, { runs: 2, status: 'complete', granted: { destination: 6, table: 3, action: 13 }, used: { destination: 4, table: 3, action: 11 }, possiblyUsed: { destination: 0, table: 0, action: 0 },
    refused: { destination: 0, table: 0, action: 0 }, excess: { destination: 2, table: 0, action: 0 }, qualified: { destination: 0, table: 0, action: 0 }, unobservable: { destination: 0, table: 0, action: 2 }, usedNotGranted: 2 });
});

test('without an inventory and contract the grant is the declared reach alone', () => {
  const r = reader.grantUseReport({ target: target(), runs: [RUNS.fixed] });
  assert.deepEqual(r.headline.granted, { destination: 6, table: 3, action: 3 });
  assert.deepEqual(actor(r, 'member').granted, REACH);
  assert.equal(r.grant.contract, null);
});

test('the reach every other observer kind declares: audit endpoint and log rules, Postgres and MySQL tables, provider-feed domains', () => {
  const t = { ...target(), observers: [
    { id: 'ha', type: 'http-audit', origin: 'http://127.0.0.1:9', path: '/audit', actions: { 'note.create': 'insert' }, deniedActions: ['note.refused'] },
    { id: 'log', type: 'audit-file', path: '/synthetic/audit.log', origin: 'http://127.0.0.1:9', rules: [{ name: 'knowledge.update', method: 'POST', path: '/k/{id}' }, { name: 'witness.status', method: 'GET', path: '/status', operation: 'read' }], witness: { rule: 'witness.status', actorId: 'ops', method: 'GET', path: '/status' } },
    { id: 'pg', type: 'pg-snapshot', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_GU_DB', tables: [{ table: 'Chat', key: 'id' }] },
    { id: 'my', type: 'mysql-snapshot', host: '127.0.0.1', port: 3306, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_GU_DB', tables: [{ table: 'notes', key: 'id' }] },
    { id: 'feed', type: 'provider-feed', feedId: 'f', feed: { endpoint: { port: 4471, path: '/feed' } }, domains: [{ domain: 'Customers.Example' }] }] };
  const r = reader.grantUseReport({ target: t, runs: [] });
  assert.deepEqual(r.grant.entries.map(e => [e.key, e.declaredBy]), [['action note.create', ['http-audit-ha']], ['action knowledge.update', ['audit-file-log']], ['table Chat', ['pg-snapshot-pg']], ['table notes', ['mysql-snapshot-my']], ['mail customers.example', ['provider-feed-feed']]]);
  assert.ok(r.actors.every(a => a.unobservable.length === 5 && a.excess.status === 'inconclusive'));
});

test('refusals: other targets, duplicates, sequence runs, half the coverage inputs, a bad contract', () => {
  assert.throws(() => reader.grantUseReport({ target: target(), runs: [{ ...RUNS.fixed, targetId: 'other' }] }), /is of target "other"/);
  assert.throws(() => reader.grantUseReport({ target: target(), runs: [RUNS.fixed, RUNS.fixed] }), /listed twice/);
  assert.throws(() => reader.grantUseReport({ target: target(), runs: [RUNS.seqFixed] }), /each run is a stored run|not an HTTP run/);
  assert.throws(() => reader.grantUseReport({ target: target(), runs: [], inventory: INVENTORY }), /together, or neither/);
  assert.throws(() => reader.grantUseReport({ target: target(), runs: [], inventory: INVENTORY, contract: { ...CONTRACT, applicationId: 'other' } }), /inventory or contract is not valid/);
  assert.throws(() => reader.sequenceGrantUseReport({ sequence: { ...SEQUENCE }, runs: [RUNS.seqFixed, RUNS.seqFixed], configs: [...SEQUENCE_CONFIGS], gateConfig: { ...GATE_CONFIG } }), /listed twice/);
});

test('Markdown: the headline sentences, the caveat line, the per-actor table and the sections', () => {
  const md = renderGrantUseMarkdown(http(reader, [RUNS.fixed, RUNS.defective]));
  assert.ok(md.startsWith('# Grant versus use: target `support-desk`\n\nGranted 6 destinations, 3 tables and 13 actions; used 4, 3 and 11 across 2 runs; 2 destinations, 0 tables and 0 actions were never exercised. 2 actions could not be observed, so they are neither used nor excess.\n'), md.slice(0, 400));
  assert.ok(md.includes(`${reader.CAVEAT} ${reader.SCOPE}`));
  assert.ok(md.includes('| Actor | Role, tenant | Destinations used | Tables used | Actions used | Possibly used | Excess | Not seen, own records only |\n|---|---|---|---|---|---|---|---|\n'));
  assert.ok(md.includes('| member | member, acme | 3 of 6 | 3 of 3 | 6 of 8 | 1 | 2 destinations, 0 tables and 0 actions | 1 |'), md);
  assert.ok(md.includes('| visitor | none | 0 of 6 | 0 of 3 | 1 of 4 | 1 | 5 destinations, 0 tables and 0 actions | 6 |'));
  assert.match(md, /- `egress exfil\.example` \(a host no destination declares\): 1 use, first in run [0-9a-f]{8}, MEMBER-SUMMARIZE check window \(http-egress, custody independent\), by member\. Already a finding: MEMBER-SUMMARIZE in run [0-9a-f]{8}\./);
  assert.match(md, /### visitor\n\n[^#]*- Possibly used \(a record that names no path or no known principal, a declared background source, or a window several actors could have caused; shared with member and ops\): `egress hooks\.chat\.example`\./);
  assert.match(md, /- Not seen, but only in records that cannot show a grant went unused: `table tickets` \(the application's own records and net change only\)/);
  assert.match(md, /## What this report cannot say\n\n- Nothing about grants ScopeHaven does not see: database roles and row-level policies, cloud IAM, provider API key scopes, OAuth scopes/);
  const fixed = renderGrantUseMarkdown(http(reader, [RUNS.fixed]));
  assert.match(fixed, /^# Grant versus use: target `support-desk`\n\nGranted 6 destinations, 3 tables and 13 actions; used 3, 2 and 10 across 1 run; 3 destinations, 0 tables and 0 actions were never exercised\. 1 table and 1 action more were not seen, but only in records that cannot show a grant went unused \(the application's own, or a snapshot's net change, or end marks taken with no declared settle\)\. 2 actions could not be observed, so they are neither used nor excess\./);
  const degraded = renderGrantUseMarkdown(http(reader, [RUNS.degraded]));
  assert.match(degraded, /were not seen in the records, but the records are incomplete \(below\), so this is not a least-privilege statement\./);
  assert.match(degraded, /\| ops \| ops, acme \| [^\n]*\| inconclusive \| not judged \|/);
  assert.match(degraded, /- Excess: inconclusive\. Not seen in the records: [^\n]*; the records could have missed a use \(the sqlite-snapshot-db window read failed \(a snapshot was missing\) at OPS-REFUND in run [0-9a-f]{8}\)\./);
  assert.match(degraded, /## Incomplete records\n\n- The sqlite-snapshot-db window read failed \(a snapshot was missing\) at OPS-REFUND in run [0-9a-f]{8}\./);
  assert.doesNotMatch(degraded.split('### ops')[1].split('###')[0], /Never exercised/);
  assert.match(renderGrantUseMarkdown(http(reader, [RUNS.refusing])), /- Requested and refused \(the allowed use did not work, which is not excess\): `operation GET \/api\/queue none` \(HTTP 503 in OPS-QUEUE\)\./);
  const sequence = renderGrantUseMarkdown(seq(reader, [RUNS.seqDefective]));
  assert.match(sequence, /^# Grant versus use: sequence `GRANT-USE-DESK`\n\nGranted 1 destination and 3 actions; used 1 and 1 across 1 run; 0 destinations and 2 actions were never exercised\./);
  assert.match(sequence.split('### ben')[1], /- Not observable: `egress hooks\.chat\.example` \(only presence-only telemetry could see it\)\./);
  assert.match(sequence, /`tool ungated` \(a tool call no gate rule names\): 1 use, first in run [0-9a-f]{8}, sequence window mid>end \(hold-proxy, custody independent\), in a window several actors could have caused\. Already a finding: NO-UNGATED/);
});

test('Markdown: a profile that declares nothing observable still renders a well-formed table', () => {
  const bare = { ...target(), observers: [] };
  const md = renderGrantUseMarkdown(reader.grantUseReport({ target: bare, runs: [] }));
  assert.match(md, /^# Grant versus use: target `support-desk`\n\nThe declarations grant nothing ScopeHaven observes\.\n/);
  const table = md.split('\n').filter(l => l.startsWith('|'));
  assert.deepEqual(table.slice(0, 2), ['| Actor | Role, tenant | Possibly used | Excess | Not seen, own records only |', '|---|---|---|---|---|']);
  assert.ok(table.slice(2).every(l => l.split(' | ').length === 5), table.join('\n'));
});

test('CLI: profile and sequence reports from files in a spaced folder; exit 0 for a report, 2 for a refusal', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'grant use cli '));
  try {
    const file = async (name, value) => { const path = join(dir, name); await writeFile(path, JSON.stringify(value)); return path; };
    const targets = await file('targets.json', { schemaVersion: 1, targets: [target()] }), runs = await file('runs.json', [RUNS.fixed, RUNS.defective]);
    const inventory = await file('inventory.json', INVENTORY), contract = await file('contract.json', CONTRACT);
    const lines = [], log = s => lines.push(s);
    assert.equal(main(['--targets', targets, '--runs', runs, '--inventory', inventory, '--contract', contract], { log }), 0);
    assert.match(lines[0], /^# Grant versus use: target `support-desk`\n\nGranted 6 destinations, 3 tables and 13 actions;/);
    lines.length = 0;
    assert.equal(main(['--targets', targets, '--runs', await file('one.json', RUNS.degraded), '--json'], { log }), 0);
    assert.equal(JSON.parse(lines[0]).headline.status, 'inconclusive');
    lines.length = 0;
    assert.equal(main(['--sequence', await file('seq.json', SEQUENCE), '--observers', await file('observers.json', SEQUENCE_CONFIGS), '--gate', await file('gate.json', GATE_CONFIG), '--runs', await file('seq-runs.json', [RUNS.seqDefective]), '--json'], { log }), 0);
    assert.equal(JSON.parse(lines[0]).application.usedNotGranted[0].key, 'tool ungated');
    for (const argv of [[], ['--targets', targets], ['--targets', targets, '--runs', runs, '--inventory', inventory], ['--targets', targets, '--runs', await file('seqs.json', [RUNS.seqFixed])],
      ['--sequence', await file('s.json', SEQUENCE), '--runs', runs], ['--targets', targets, '--sequence', targets, '--runs', runs]]) {
      lines.length = 0;
      assert.equal(main(argv, { log }), 2, JSON.stringify(argv));
      assert.match(lines[0], /^Configuration error: /);
    }
    // Run directly from its real path (the folder has a space).
    const direct = spawnSync(process.execPath, [fileURLToPath(new URL('./cli.mjs', import.meta.url)), '--targets', targets, '--runs', runs, '--json'], { encoding: 'utf8' });
    assert.equal(direct.status, 0, direct.stderr);
    assert.equal(JSON.parse(direct.stdout).targetId, 'support-desk');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

// The mutation sweep: each property's mutant (one source change) must fail that property's check. Imports are rewritten to
// the shipped modules so a mutant differs from the reader in the one change only.
test('mutation sweep: one mutation per property, each caught by its own check', async () => {
  const source = fileURLToPath(new URL('./grant-use.mjs', import.meta.url)), text = await readFile(source, 'utf8');
  const dir = await mkdtemp(join(tmpdir(), 'grant use mutants '));
  const missed = [];
  try {
    let n = 0;
    for (const p of PROPERTIES) {
      const [find, replace] = p.mutation;
      assert.equal(text.split(find).length, 2, `the mutation site for "${p.name}" occurs exactly once`);
      const mutated = text.replace(find, replace).replace(/from '(\.\.?\/[^']+)'/g, (_m, rel) => `from '${new URL(rel, pathToFileURL(source)).href}'`);
      const file = join(dir, `mutant-${++n}.mjs`);
      await writeFile(file, mutated);
      const mutant = await import(pathToFileURL(file).href);
      let caught = false;
      try { await p.check(mutant); } catch { caught = true; }
      if (!caught) missed.push(p.name);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
  assert.deepEqual(missed, [], 'every mutant is caught by its property');
  assert.equal(PROPERTIES.length, 41);
});
