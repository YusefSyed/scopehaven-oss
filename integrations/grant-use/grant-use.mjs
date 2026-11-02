// Grant versus use: for each actor, what it was granted, what the run
// records show it actually used across a set of runs, and the excess (granted and never used in those runs), plus what
// it used that it was never granted. Presentation only, like the coverage report: it never feeds a verdict, a count,
// compareRuns, a gate outcome or any identity hash, and it reads src/ without changing it.
//
// The grant comes from declarations, never from what the application under test did:
//   - the reach the profile's observers declare (or, for a sequence, its observers.json and gate.json): egress destinations
//     (each declared path of a host, or the whole host when it declares none), mail domains (SMTP sink, provider feed),
//     snapshot tables, audit-table and audit-endpoint actions, audit-log rules and the hold gate's tool rules. The
//     declarations name this reach for the application, not per actor, so every actor is held against all of it;
//   - with an inventory and a stated contract, the operations the contract permits each actor's role and tenant, read from
//     the coverage report's own cells (integrations/coverage-report), never re-derived here.
// The use comes from the records: committed effect events in the sealed observer windows of validated runs, and, for
// operations, the actor's own requests that the application answered with a complete 2xx. Every use cites its run, its
// record (check, gap, barrier or sequence window, or the HTTP response), the observer and event seq, and its custody class.
//
// Attribution is conservative:
//   - used: the record names the actor's principal (an observer with actorAttribution "principal"), or the event sits in
//     the actor's own check window (an HTTP effect row) and fits no declared background source, or in a sequence window
//     that only that actor's requests could have caused;
//   - possibly used: anything else (a settlement gap or barrier between checks, a sequence window several actors could
//     have caused, a principal the record does not name or names "unlisted:", a declared background source, a send a
//     recorder carried late into a later window, a tunnel or ambiguous path that names no declared path). It is shared by
//     the actors who could have caused it, and it is never excess for any of them;
//   - excess: granted, neither used nor possibly used, and observable by an authoritative observer. A clean excess entry
//     rests on a request-path record held outside the application (an egress or SMTP sink, the hold gate, a provider feed
//     whose key the application does not hold); one only the application's own tables or audit records could have shown
//     is listed apart as qualified (the application can hide a use there, and a snapshot reads net change only). Operations
//     are never excess: the actor's requests are the suite's, so an operation is used, refused, or not requested;
//   - inconclusive: an actor whose records could have missed a use (a window that is partial or failed, a missing
//     snapshot, a recorder that did not drain, a late entry nothing followed, a check or request no window covered, a
//     stopped sequence, or no request at all) carries only the entries the records did not show (notSeen) and why, never a
//     list of excess entries.
// Only the runs given count: an unused grant is excess for these runs, not proof that it is unneeded.
import { digest } from '../../src/domain.mjs';
import { contractDigest } from '../../src/contracts.mjs';
import { validateWindow, windowSees, custodyWindows, validScoped, unfollowedLate, LATE_CODES } from '../../src/effect-events.mjs';
import { observerInstanceId, settleDeclared } from '../../src/http-effects.mjs';
import { fitsSelector } from '../../src/http-settlement.mjs';
import { followedDrains } from '../../src/run-end-drain.mjs';
import { CUSTODY_BY_SOURCE, feedKeyCustody } from '../../src/custody.mjs';
import { validateRun } from '../regression-gate/gate.mjs';
import { coverageReport } from '../coverage-report/coverage.mjs';
import { validateSequence, sequenceHashOf, stepActions, requestsOf } from '../sequences/sequence.mjs';
import { validateSequenceRun } from '../sequences/run-validator.mjs';
import { declaredObservers } from '../sequences/cli.mjs';

export const GRANT_USE_SCHEMA = 'scopehaven-grant-use/1';
export const GROUPS = Object.freeze(['destination', 'table', 'action']);
export const CAVEAT = 'Only the runs given count: an unused grant is excess for these runs, not proof that it is unneeded.';
export const SCOPE = 'Scope: computed only from the given declarations (the profile or the sequence configuration, and the stated contract when given) and the given validated runs; it sends no request and observes nothing itself. A grant ScopeHaven does not see (database roles, cloud IAM, provider key scopes, OAuth scopes) is outside it.';
export const NOTE = 'Presentation only: it never feeds a verdict, a count, a comparison, a gate outcome or an identity hash. A use not granted is listed with the failing rows that already hold it; when no failing row holds it, this report is where it shows.';

export class GrantUseError extends Error { constructor(message) { super(message); this.name = 'GrantUseError'; } }
const fail = message => { throw new GrantUseError(message); };
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (record, key) => (plain(record) && Object.hasOwn(record, key) ? record[key] : undefined);
const lower = s => String(s).toLowerCase();
const dedupe = list => { const out = new Map(); for (const x of list) out.set(digest(x), x); return [...out.values()]; };
const push = (map, key, item) => { const list = map.get(key) ?? []; list.push(item); map.set(key, list); };

// Grant entries. A key is the entry's identity across runs and actors.
const egressEntry = (host, path) => ({ key: `egress ${lower(host)}${path === null ? '' : ` ${path}`}`, group: 'destination', channel: 'egress', host: lower(host), path });
const mailEntry = domain => ({ key: `mail ${lower(domain)}`, group: 'destination', channel: 'mail', domain: lower(domain) });
const tableEntry = table => ({ key: `table ${table}`, group: 'table', channel: 'table', table });
const actionEntry = name => ({ key: `action ${name}`, group: 'action', channel: 'action', name });
const toolEntry = rule => ({ key: `tool ${rule}`, group: 'action', channel: 'tool', rule });
const operationEntry = cell => ({ key: `operation ${cell.operation} ${cell.scope}`, group: 'action', channel: 'operation', operation: cell.operation, scope: cell.scope, surface: cell.surface });
const isOperation = key => key.startsWith('operation ');
const MAIL_SOURCES = ['smtp-capture', 'provider-feed'], AUDIT_SOURCES = ['sql-audit-table', 'http-audit-log', 'file-audit-log'];
// What an observer would have to see to show the entry's use (src/effect-events.mjs windowSees).
const selectorsOf = e => e.channel === 'egress' ? [{ source: 'http-egress', operation: 'send', name: e.host }]
  : e.channel === 'mail' ? MAIL_SOURCES.map(source => ({ source, operation: 'send', name: e.domain }))
  : e.channel === 'table' ? ['insert', 'update', 'delete'].map(operation => ({ source: 'sql-snapshot', operation, name: e.table }))
  : e.channel === 'action' ? AUDIT_SOURCES.map(source => ({ source, name: e.name }))
  : e.channel === 'tool' ? [{ source: 'hold-proxy', operation: 'tool-call', name: e.rule }] : [];
const seesEntry = (w, e) => selectorsOf(e).some(s => windowSees(w, s));
// Could a scoped entry (a send its window could not place) be a use of this grant entry? Same name, and for an egress path, the
// same path or one the entry does not name (an ambiguous path).
const entryFits = (e, s) => selectorsOf(e).some(sel => lower(sel.name) === lower(s.name)) && (e.channel !== 'egress' || e.path === null || s.resource === null || s.resource.split(' ')[1] === e.path);
const authoritative = w => w.scope?.evidence === 'authoritative';
// A window's custody class: the lineage table of src/custody.mjs, a provider feed read through its declared key source.
const custodyOf = w => (w.source === 'provider-feed' ? feedKeyCustody(w.scope?.feed) : CUSTODY_BY_SOURCE[w.source] ?? 'subject-writable');
// Coverage that can show the records missed nothing of a kind: complete, or a snapshot's net change. Net change is the best a
// snapshot gives (a write undone inside one window is not seen), so an entry only snapshots see is qualified, never clean.
const SETTLED = Object.freeze(['complete', 'net-only']);
// Telemetry and the application's own action log are the application's account of itself: their events are not read as uses.
const READ_SOURCES = Object.freeze(['http-egress', 'smtp-capture', 'provider-feed', 'sql-snapshot', ...AUDIT_SOURCES, 'hold-proxy']);
// A principal the record does not name: null, or "unlisted:" (a value outside the observer's declared principals), which
// src/effect-events.mjs reads as possibly the selected actor.
const unknownPrincipal = actor => actor === null || actor.startsWith('unlisted:');

// The reach a list of observer configurations declares (a profile's observers, or a sequence's observers.json and gate.json),
// each entry with the observer instances that declare it. A witness host or domain is the harness's own and never a grant;
// the sinks never record the test's own witness units as effects (integrations/observers/sink-ledger.mjs).
function declaredReach(configs, gateConfig, instanceIds) {
  const entries = new Map();
  const add = (e, by) => { const kept = entries.get(e.key) ?? { ...e, declaredBy: [] }; if (!kept.declaredBy.includes(by)) kept.declaredBy.push(by); entries.set(e.key, kept); };
  configs.forEach((o, i) => {
    const by = instanceIds[i];
    if (o.type === 'egress-recorder') for (const d of o.destinations ?? []) { for (const p of Array.isArray(d.paths) && d.paths.length ? d.paths : [null]) add(egressEntry(d.host, p), by); }
    else if (o.type === 'smtp-sink' || o.type === 'provider-feed') for (const d of o.domains ?? []) add(mailEntry(typeof d === 'string' ? d : d.domain), by);
    else if (['sqlite-snapshot', 'pg-snapshot', 'mysql-snapshot'].includes(o.type)) for (const t of o.tables ?? []) add(tableEntry(t.table), by);
    // Declared denial names (deniedActions) name refusals, never a grant.
    else if (o.type === 'sqlite-audit') for (const name of Object.keys(o.audit?.actions ?? {})) add(actionEntry(name), by);
    else if (o.type === 'http-audit') for (const name of Object.keys(o.actions ?? {})) add(actionEntry(name), by);
    else if (o.type === 'audit-file') for (const r of o.rules ?? []) { if (r.name !== o.witness?.rule) add(actionEntry(r.name), by); }
  });
  // "ungated" names the gate's calls that no rule matches: never a grant.
  if (plain(gateConfig)) for (const r of gateConfig.rules ?? []) if (r.id !== 'ungated') add(toolEntry(r.id), instanceIds.at(-1));
  return { entries };
}

// The egress hosts a window could not place on a path: a scoped entry coded egress-path-ambiguous names its host, and a
// window read window-wide with that reason could hold such a send for any host ('*').
const ambiguousHosts = w => w.source !== 'http-egress' ? new Set()
  : new Set([...(Array.isArray(w.scoped) ? w.scoped.filter(s => s.codes.includes('egress-path-ambiguous')).map(s => lower(s.name)) : []), ...(String(w.reason ?? '').split(',').includes('egress-path-ambiguous') ? ['*'] : [])]);

// Which grant entries a committed event used (keys), may have used (possibly), or what it used that nothing grants.
function placeEvent(ev, reach, ambiguous) {
  const has = key => reach.entries.has(key);
  if (ev.source === 'http-egress') {
    const host = lower(ev.name), paths = [...reach.entries.values()].filter(e => e.channel === 'egress' && e.host === host);
    if (has(`egress ${host}`)) return { keys: [`egress ${host}`] };
    if (!paths.length) return { notGranted: { key: `egress ${host}`, kind: 'host-undeclared' } };
    // A tunnel ("CONNECT :443") shows the host and never the path, and a send whose path read ambiguously is named by one decoded
    // reading of it: either may be any of the host's declared paths.
    const [method, path] = String(ev.resource).split(' ');
    if (method === 'CONNECT' || ambiguous.has(host) || ambiguous.has('*')) return { possibly: paths.map(e => e.key) };
    const hit = paths.find(e => e.path === path);
    return hit ? { keys: [hit.key] } : { notGranted: { key: `egress ${host} *`, kind: 'path-undeclared' } };
  }
  if (MAIL_SOURCES.includes(ev.source)) return has(`mail ${lower(ev.name)}`) ? { keys: [`mail ${lower(ev.name)}`] } : { notGranted: { key: `mail ${lower(ev.name)}`, kind: 'domain-undeclared' } };
  if (ev.source === 'sql-snapshot') return has(`table ${ev.name}`) ? { keys: [`table ${ev.name}`] } : { notGranted: { key: `table ${ev.name}`, kind: 'table-undeclared' } };
  if (AUDIT_SOURCES.includes(ev.source)) return has(`action ${ev.name}`) ? { keys: [`action ${ev.name}`] } : { notGranted: { key: `action ${ev.name}`, kind: 'action-undeclared' } };
  if (ev.source === 'hold-proxy') return ev.name !== 'ungated' && has(`tool ${ev.name}`) ? { keys: [`tool ${ev.name}`] } : { notGranted: { key: `tool ${ev.name}`, kind: ev.name === 'ungated' ? 'tool-ungated' : 'tool-undeclared' } };
  return {};
}

// One actor's (or the application's, or an undeclared principal's) findings across the run set.
const ledger = () => ({ used: new Map(), possibly: new Map(), notGranted: new Map(), unstated: new Map(), refused: new Map(), unanswered: new Set(), undetermined: new Map(), delegated: [], runs: new Map() });
const runSlot = (l, run) => { if (!l.runs.has(run)) l.runs.set(run, { used: new Set(), possibly: new Set(), notGranted: new Set(), refused: new Set(), undetermined: [] }); return l.runs.get(run); };

// The shared core. places: where events were recorded and who could have caused them, each
//   { run, record, id, own, candidates: [alias], windows, order, failing: [check or assertion id], wide: Set(instance id) };
//   wide names the instances whose late entries nothing followed, so their window is read window-wide (src's follow rule).
// operationUses: every sent request of an actor placed in a contract cell; runFacts: run-level reasons a use could be missing;
// background: the profile's declared background sources (src/http-attribution.mjs), attributed to no check.
function assemble({ reach, principals, aliases, places, operationUses, runFacts, background }) {
  const aliasOf = new Map(Object.entries(principals).map(([alias, p]) => [p, alias]));
  const books = new Map(aliases.map(a => [a, ledger()])), app = ledger(), undeclared = new Map();
  const held = new Map(); // run|instance|seq -> every place that holds the event (sequence windows can overlap)
  const late = []; // sends a recorder carried past its window: { run, instance, name, order, candidates }
  for (const p of places) for (const w of p.windows) {
    for (const ev of w.events) if (ev.outcome === 'committed' && READ_SOURCES.includes(ev.source)) push(held, `${p.run}|${w.instanceId}|${ev.seq}`, { p, w, ev });
    for (const s of Array.isArray(w.scoped) ? w.scoped : []) if (s.codes.some(c => LATE_CODES.includes(c))) late.push({ run: p.run, instance: w.instanceId, name: lower(s.name), order: p.order, candidates: p.candidates });
  }
  for (const holders of held.values()) {
    const { p, w, ev } = holders[0];
    const carried = late.filter(l => l.run === p.run && l.instance === w.instanceId && l.name === lower(ev.name) && l.order < p.order);
    const ownHolders = holders.filter(h => h.p.own), principalScope = w.scope.actorAttribution === 'principal';
    const named = principalScope && !unknownPrincipal(ev.actor) ? ev.actor : null;
    const fitsBackground = background.some(s => fitsSelector(ev, s.select));
    // Who: the record's own principal; else the one actor whose own window holds it, when the record names no other
    // principal and no declared background source fits it; else the actors who could have caused it.
    let actor = null, shared = [], how, decisive = holders[0];
    if (named !== null) { actor = aliasOf.get(named) ?? null; how = 'record-principal'; decisive = ownHolders[0] ?? holders[0]; }
    else if (!principalScope && !fitsBackground && ownHolders.length && !carried.length && new Set(ownHolders.map(h => h.p.candidates[0])).size === 1) {
      decisive = ownHolders[0]; actor = decisive.p.candidates[0]; how = decisive.p.record === 'check-window' ? 'check-window' : 'sequence-single-actor';
    } else {
      const sets = holders.map(h => h.p.candidates), common = sets[0].filter(a => sets.every(s => s.includes(a)));
      shared = [...new Set([...(common.length ? common : sets.flat()), ...carried.flatMap(l => l.candidates)])].sort();
      decisive = holders.find(h => h.p.candidates.length === Math.min(...sets.map(s => s.length))) ?? holders[0];
      how = carried.length ? 'late-entry' : fitsBackground ? 'background-source' : principalScope ? 'principal-unknown' : `${p.record}-shared`;
    }
    const at = decisive.p, placed = placeEvent(ev, reach, ambiguousHosts(decisive.w));
    const use = { run: at.run, record: at.record, ...(at.record === 'check-window' ? { checkId: at.id } : { window: at.id }), observer: w.instanceId, source: ev.source, seq: ev.seq,
      operation: ev.operation, name: ev.name, resource: ev.resource, ...(principalScope && ev.actor !== null ? { principal: ev.actor } : {}), custody: custodyOf(w),
      ...(at.candidates.length ? { windowActors: [...at.candidates] } : {}), attributedBy: how };
    const failing = [...new Set(holders.flatMap(h => h.p.failing))];
    const record = (l, kind) => {
      const slot = runSlot(l, p.run);
      if (placed.notGranted) { push(l.notGranted, placed.notGranted.key, { ...use, kind: placed.notGranted.kind, failing }); slot.notGranted.add(placed.notGranted.key); return; }
      for (const key of placed.keys ?? []) { push(kind === 'used' ? l.used : l.possibly, key, use); slot[kind === 'used' ? 'used' : 'possibly'].add(key); }
      for (const key of placed.possibly ?? []) { push(l.possibly, key, { ...use, pathUnknown: true }); slot.possibly.add(key); }
    };
    // The application used it, whoever caused it.
    record(app, 'used');
    if (named !== null && actor === null) { if (!undeclared.has(named)) undeclared.set(named, ledger()); record(undeclared.get(named), 'used'); }
    else if (actor !== null) record(books.get(actor), 'used');
    else for (const a of shared) if (books.has(a)) record(books.get(a), 'possibly');
    // Delegated authority (FORESIGHT F-03): the record names another principal for an effect inside this actor's own window.
    if (named !== null) for (const h of ownHolders) { const by = h.p.candidates[0]; if (by !== actor && books.has(by)) books.get(by).delegated.push({ principalId: named, ...(actor !== null ? { actor } : {}), keys: placed.keys ?? (placed.notGranted ? [placed.notGranted.key] : placed.possibly ?? []), use }); }
  }
  // Operations: the actor's own requests (the run's own record of what it sent as that actor). Accepted (a complete 2xx) is a
  // use, of a denied cell a use not granted; an allowed request the application answered otherwise (a complete response with
  // another status) is listed as refused, never as unused; one that got no complete response (a reset, a timeout) is neither.
  for (const u of operationUses) {
    const use = { run: u.run, record: 'http-response', checkId: u.checkId, httpStatus: u.httpStatus, custody: 'subject-writable', attributedBy: 'request' };
    const permitted = u.stated === 'allow' || u.stated === 'conditional', l = books.get(u.actor);
    if (u.accepted) {
      for (const target of [l, app]) { if (permitted || target === app) { push(target.used, u.key, use); runSlot(target, u.run).used.add(u.key); } }
      if (u.stated === 'deny') for (const target of [l, app]) { push(target.notGranted, u.key, { ...use, kind: 'operation-denied', failing: u.failing ? [u.checkId] : [] }); runSlot(target, u.run).notGranted.add(u.key); }
      if (!permitted && u.stated !== 'deny') push(l.unstated, u.key, use);
    } else if (permitted && u.answered) for (const target of [l, app]) { push(target.refused, u.key, use); runSlot(target, u.run).refused.add(u.key); }
    else if (permitted) for (const target of [l, app]) target.unanswered.add(u.key);
  }
  // Incomplete records: where a use could be missing from an actor's (and the application's) view.
  const note = (l, key, reason) => { push(l.undetermined, key, reason); runSlot(l, reason.run).undetermined.push({ key, ...reason }); };
  const reachEntries = [...reach.entries.values()];
  for (const p of places) for (const w of p.windows) {
    if (!authoritative(w)) continue;
    // A scoped window is partial only because of its entries, each a send it could not place (late, in flight, an
    // ambiguous path, a sibling host): only an entry that send could be may be missing from it, unless nothing later followed
    // its late entries, when it is read window-wide as src reads it. Any other partial or failed window could be missing
    // anything it sees.
    const scoped = validScoped(w) && !p.wide.has(w.instanceId) ? w.scoped : [];
    for (const e of reachEntries) {
      if (!seesEntry(w, e)) continue;
      const reasons = [];
      if (!SETTLED.includes(w.coverage) && !scoped.length) reasons.push({ run: p.run, record: p.record, at: p.id, observer: w.instanceId, coverage: w.coverage, reason: w.reason ?? null, ...(p.wide.has(w.instanceId) ? { unfollowed: true } : {}) });
      for (const s of scoped) if (entryFits(e, s)) reasons.push({ run: p.run, record: p.record, at: p.id, observer: w.instanceId, coverage: w.coverage, reason: s.codes.join(',') });
      for (const r of reasons) { note(app, e.key, r); for (const a of p.candidates) if (books.has(a)) note(books.get(a), e.key, r); }
    }
  }
  for (const f of runFacts) for (const e of reachEntries) {
    if (f.sees && !f.sees.includes(e.key)) continue;
    const r = { run: f.run, reason: f.reason, ...(f.observer ? { observer: f.observer } : {}), ...(f.at ? { at: f.at } : {}) };
    note(app, e.key, r); for (const a of f.actors) if (books.has(a)) note(books.get(a), e.key, r);
  }
  // What each entry's "not seen" rests on: the authoritative observers that could have shown its use. One held outside the
  // application (custody independent) on complete coverage supports a clean statement; the application's own tables and
  // audit records (custody subject-writable) and a snapshot's net change do not, so such an entry is qualified.
  const windows = places.flatMap(p => p.windows), basis = new Map();
  for (const e of reachEntries) {
    const deciding = windows.filter(w => authoritative(w) && seesEntry(w, e));
    if (!deciding.length) continue;
    const why = [];
    if (deciding.every(w => custodyOf(w) === 'subject-writable')) why.push('application-records-only');
    if (deciding.every(w => w.source === 'sql-snapshot')) why.push('net-change-only');
    basis.set(e.key, why);
  }
  const unobservable = reachEntries.filter(e => !basis.has(e.key)).map(e => ({ key: e.key, reason: windows.some(w => seesEntry(w, e)) ? 'presence-only' : 'no-observer-window' }));
  return { books, app, undeclared, unobservable, basis };
}

// One ledger's sets: used, possibly used, refused, excess (complete, with qualified entries apart, or inconclusive),
// unobservable, used but not granted; across the run set and per run (a run's excess reads that run alone, so it is
// inconclusive in a run that sent no request as the actor).
function summarize(l, granted, unobservable, basis, { acted, actedIn, runIds }) {
  const blind = new Set(unobservable.map(u => u.key));
  const settle = (open, reasons) => {
    if (reasons.length) return { status: 'inconclusive', notSeen: open, reasons: dedupe(reasons) };
    const qualified = open.filter(k => basis.get(k)?.length);
    return { status: 'complete', entries: open.filter(k => !basis.get(k)?.length), qualified: qualified.map(k => ({ key: k, basis: basis.get(k) })) };
  };
  // Operations are never excess: an allowed operation the actor never requested is not observable here, one it requested
  // and was refused is listed as refused.
  const notRequested = granted.filter(k => isOperation(k) && !l.used.has(k) && !l.refused.has(k) && !blind.has(k)).map(k => ({ key: k, reason: l.unanswered.has(k) ? 'request-unanswered' : 'no-check-requests-it' }));
  const unseen = [...unobservable.filter(u => granted.includes(u.key) && !l.used.has(u.key) && !l.possibly.has(u.key)), ...notRequested];
  const open = (used, possibly) => granted.filter(k => !used.has(k) && !possibly.has(k) && !blind.has(k) && !isOperation(k));
  const candidates = open(l.used, l.possibly);
  const undetermined = candidates.filter(k => l.undetermined.has(k)).map(k => ({ key: k, reasons: dedupe(l.undetermined.get(k)) }));
  const reasons = [...(acted ? [] : [{ reason: 'actor-not-in-runs' }]), ...undetermined.flatMap(u => u.reasons)];
  const excess = settle(candidates, reasons);
  return {
    granted,
    used: granted.filter(k => l.used.has(k)).map(k => ({ key: k, runs: new Set(l.used.get(k).map(u => u.run)).size, uses: l.used.get(k) })),
    possiblyUsed: granted.filter(k => !l.used.has(k) && l.possibly.has(k)).map(k => ({ key: k, uses: l.possibly.get(k) })),
    refused: granted.filter(k => !l.used.has(k) && l.refused.has(k)).map(k => ({ key: k, uses: l.refused.get(k) })),
    excess: excess.status === 'inconclusive' ? { ...excess, undetermined } : excess,
    unobservable: unseen,
    // shared: no use of it is this ledger's own (each came from a window several actors could have caused).
    usedNotGranted: [...l.notGranted.entries()].map(([key, uses]) => ({ key, kind: uses[0].kind, uses: uses.map(({ kind, failing, ...u }) => u),
      findings: dedupe(uses.flatMap(u => u.failing.map(id => ({ run: u.run, id })))), ...(uses.every(u => !u.failing.length) ? { unchecked: true } : {}),
      ...(uses.every(u => !OWN_ATTRIBUTION.includes(u.attributedBy)) ? { shared: true } : {}) })),
    ...(l.delegated.length ? { delegated: l.delegated } : {}),
    ...(l.unstated.size ? { usedUnstated: [...l.unstated.entries()].map(([key, uses]) => ({ key, uses })) } : {}),
    perRun: runIds.map(id => {
      const s = l.runs.get(id) ?? { used: new Set(), possibly: new Set(), notGranted: new Set(), refused: new Set(), undetermined: [] };
      const here = open(s.used, s.possibly);
      const why = [...(actedIn(id) ? [] : [{ reason: 'actor-not-in-run' }]), ...s.undetermined.filter(u => here.includes(u.key)).map(({ key, ...r }) => r)];
      return { run: id, used: granted.filter(k => s.used.has(k)), possiblyUsed: granted.filter(k => !s.used.has(k) && s.possibly.has(k)), refused: granted.filter(k => !s.used.has(k) && s.refused.has(k)),
        excess: settle(here, why), usedNotGranted: [...s.notGranted].sort() };
    }),
  };
}
const OWN_ATTRIBUTION = Object.freeze(['record-principal', 'check-window', 'sequence-single-actor', 'request']);
const groupCounts = (keys, entries) => { const unique = [...new Set(keys)]; return Object.fromEntries(GROUPS.map(g => [g, unique.filter(k => entries.get(k)?.group === g).length])); };

function finish({ kind, identity, reach, actors, joined, runIds, acted, actedRuns, operationsGranted, operationUnobservable, contract }) {
  const { books, app, undeclared, unobservable, basis } = joined;
  const operations = [...operationsGranted.values()].flat();
  const entries = new Map([...reach.entries, ...operations.map(e => [e.key, e])]);
  const grantOf = alias => [...reach.entries.keys(), ...(operationsGranted.get(alias) ?? []).map(e => e.key)];
  const blindOf = alias => [...unobservable, ...(operationUnobservable.get(alias) ?? [])];
  const actorRows = Object.entries(actors).map(([alias, a]) => ({ alias, principalId: a.principalId, ...(a.role !== undefined ? { role: a.role } : {}), ...(a.tenantId !== undefined ? { tenantId: a.tenantId } : {}),
    ...summarize(books.get(alias), grantOf(alias), blindOf(alias), basis, { acted: acted.has(alias), actedIn: run => actedRuns.get(run)?.has(alias) === true, runIds }) }));
  // The application: every actor's grant, and every use whoever caused it. An operation is unobservable for it only when it
  // is unobservable for every actor granted it.
  const appGranted = [...new Set([...reach.entries.keys(), ...operations.map(e => e.key)])];
  const holders = key => Object.keys(actors).filter(a => grantOf(a).includes(key));
  const appBlind = [...unobservable, ...dedupe([...operationUnobservable.values()].flat()).filter((u, i, all) => all.findIndex(x => x.key === u.key) === i && holders(u.key).every(a => blindOf(a).some(x => x.key === u.key)))];
  const application = summarize(app, appGranted, appBlind, basis, { acted: acted.size > 0, actedIn: run => (actedRuns.get(run)?.size ?? 0) > 0, runIds });
  const x = application.excess;
  const headline = { runs: runIds.length, status: x.status, granted: groupCounts(appGranted, entries), used: groupCounts(application.used.map(u => u.key), entries),
    possiblyUsed: groupCounts(application.possiblyUsed.map(u => u.key), entries), refused: groupCounts(application.refused.map(u => u.key), entries),
    ...(x.status === 'complete' ? { excess: groupCounts(x.entries, entries), qualified: groupCounts(x.qualified.map(q => q.key), entries) } : { notSeen: groupCounts(x.notSeen, entries) }),
    unobservable: groupCounts(application.unobservable.map(u => u.key), entries), usedNotGranted: application.usedNotGranted.length };
  return { schema: GRANT_USE_SCHEMA, kind, ...identity, runs: runIds, headline,
    grant: { contract: contract ? { basis: contract.basis ?? null } : null, entries: [...entries.values()] },
    application, actors: actorRows,
    // Uses a record names under a principal no actor declares (a service identity, say): never credited to an actor.
    undeclaredPrincipals: [...undeclared.entries()].map(([principalId, l]) => ({ principalId, uses: [...l.used.entries()].map(([key, uses]) => ({ key, uses })),
      usedNotGranted: [...l.notGranted.entries()].map(([key, uses]) => ({ key, uses: uses.map(({ kind, failing, ...u }) => u) })) })),
    caveat: CAVEAT, scope: SCOPE, note: NOTE };
}

const runIdOf = run => run.id ?? run.runId;
// A complete response, whatever its body: src counts a body that is not JSON (an empty 204, an HTML page) as complete too.
const answered = data => Number.isInteger(data?.httpStatus) && data.responseComplete === true && ['complete', 'invalid-json'].includes(data.transportOutcome);
const accepted = data => answered(data) && data.httpStatus >= 200 && data.httpStatus < 300;
// A row whose request was sent: not declared not applicable, not left unsent, and attempted (a run whose budget ran out still
// collects the row's windows, src/http-connector.mjs requestAttempted).
const sentRow = r => r.status !== 'not_applicable' && r.trace?.[0]?.data?.transportOutcome !== 'not-sent' && r.trace?.[0]?.data?.requestAttempted !== false;

// The report for a profile target and its stored HTTP runs. Each run must be an HTTP run of this target under this exact
// profile digest, pass the regression gate's run validator (as the coverage report's runFindings does) and carry rows that
// are this profile's checks (actor, method and path digest). inventory and contract (the coverage report's inputs) add the
// operations the contract permits each actor; without them the grant is the declared reach alone.
export function grantUseReport({ target, runs = [], inventory = null, contract = null } = {}) {
  if (!plain(target) || !Array.isArray(target.checks) || !plain(target.actors)) fail('a validated target profile with actors and checks is required');
  if (!Array.isArray(runs)) fail('runs is a list of stored HTTP runs');
  if ((inventory === null) !== (contract === null)) fail('give the inventory and the stated contract together, or neither');
  const profileHash = contractDigest(target), byId = new Map(target.checks.map(c => [c.id, c])), configs = target.observers ?? [];
  const reach = declaredReach(configs, null, configs.map(o => observerInstanceId(o.type, o.id)));
  const credentialed = Object.entries(target.actors).filter(([, a]) => a.credentialEnv !== undefined).map(([alias]) => alias);
  // Operations: the coverage report's cells, each check placed once (its own reading of the declared side).
  const operationsGranted = new Map(), operationUnobservable = new Map(), cellOfCheck = new Map();
  if (inventory !== null) {
    let coverage;
    try { coverage = coverageReport({ inventory, contract, target }); } catch (error) { fail(`the inventory or contract is not valid (${error.message})`); }
    for (const cell of coverage.cells) for (const d of cell.drafts) cellOfCheck.set(d.checkId, cell);
    for (const [alias, a] of Object.entries(target.actors)) {
      const anonymous = a.credentialEnv === undefined && a.credentialCookie === undefined;
      const mine = coverage.cells.filter(c => ['allow', 'conditional'].includes(c.stated) && (anonymous ? c.role === 'anonymous' : c.role === 'signed-in' || (c.role === a.role && c.tenant === (a.tenantId ?? null))));
      operationsGranted.set(alias, dedupe(mine.map(operationEntry)));
      // A cell no request of the profile can reach (no other tenant's object, a model turn's tool, a method the connector does not send).
      operationUnobservable.set(alias, dedupe(mine.filter(c => ['unreachable', 'not-judgeable'].includes(c.mark)).map(c => ({ key: operationEntry(c).key, reason: c.reason ?? c.mark }))));
    }
  }
  const places = [], operationUses = [], runFacts = [], acted = new Set(), actedRuns = new Map(), runIds = [];
  for (const input of runs) {
    const run = plain(input) && plain(input.core) ? input.core : input;
    if (!plain(run) || !Array.isArray(run.results) || !runIdOf(run)) fail('each run is a stored run with its id and results');
    const id = String(runIdOf(run));
    if (runIds.includes(id)) fail(`run ${id} is listed twice`);
    runIds.push(id);
    if (run.evidenceOrigin !== 'local-http-response') fail(`run ${id}: evidence origin ${JSON.stringify(run.evidenceOrigin ?? null)} is not an HTTP run`);
    if (run.targetId !== target.id) fail(`run ${id} is of target ${JSON.stringify(run.targetId)}, not ${JSON.stringify(target.id)}`);
    if (run.profileHash !== profileHash) fail(`run ${id} was recorded under another version of this profile (its profile digest differs), so its rows answer other declarations`);
    try { validateRun(run); } catch (error) { fail(`run ${id} does not pass the run validator (${[error.code, error.detail, error.message].filter(Boolean).join(': ')})`); }
    const results = run.results, order = new Map(results.map((r, i) => [r.id, i])), actedHere = new Set();
    actedRuns.set(id, actedHere);
    for (const r of results) {
      const check = byId.get(r.id), data = r.trace?.[0]?.data;
      if (!check) fail(`run ${id}: row ${r.id} is not a check of this profile`);
      if (!sentRow(r)) continue;
      // A belt behind the validator and the profile digest, which already bind each row to its check.
      if (data?.actorId !== check.actorId || data.method !== check.method || data.requestPathHash !== digest(check.path)) fail(`run ${id}: row ${r.id} does not match its profile check (actor, method or path)`);
      acted.add(check.actorId); actedHere.add(check.actorId);
      const cell = cellOfCheck.get(r.id);
      if (cell) operationUses.push({ run: id, actor: check.actorId, checkId: r.id, key: operationEntry(cell).key, stated: cell.stated, accepted: accepted(data), answered: answered(data), httpStatus: data.httpStatus ?? null, failing: r.status === 'fail' });
    }
    const sealed = (list, where) => custodyWindows(list.map((w, i) => validateWindow(w, `run ${id} ${where} window ${i + 1}`)), 'grantUseReport');
    const effectRows = results.filter(r => r.trace?.[1]?.type === 'effect-observation'), position = rowId => effectRows.findIndex(r => r.id === rowId);
    const rowWindows = effectRows.map(r => sealed(r.trace[1].data.windows, r.id));
    // src's follow rule: a check window whose late entries no later row window (or quiescent drain) of its observer follows.
    const wide = unfollowedLate(rowWindows, { followed: followedDrains(run.settlement?.drains) });
    const before = rowId => [...new Set(results.slice(0, order.get(rowId)).filter(sentRow).map(r => byId.get(r.id).actorId))].sort();
    effectRows.forEach((r, k) => {
      // A row whose request was never attempted owns no window: anything there came from earlier requests or the background.
      const mine = sentRow(r);
      places.push({ run: id, record: 'check-window', id: r.id, own: mine, candidates: mine ? [byId.get(r.id).actorId] : before(r.id), windows: rowWindows[k], order: k, failing: r.status === 'fail' ? [r.id] : [], wide: wide[k] });
    });
    // A gap runs from one effect row's end to the next one's start (src/http-connector.mjs): an event there could come from any
    // actor whose sent row lies in that stretch, the effect row before it (its late sends land there) and the one after it
    // (its identity probe point comes first) included. Under a timing plan the run-end probes of every credentialed actor are
    // sent inside the last gap, and with lifecycle entries the cross probes before a change check send other actors'
    // credentials, so every credentialed actor is a candidate there.
    const everyone = (target.lifecycle ?? []).length > 0;
    const between = (after, next) => [...new Set([...results.slice(after === null ? 0 : order.get(after), next === null ? results.length : order.get(next) + 1).filter(sentRow).map(r => byId.get(r.id).actorId),
      ...((next === null && run.timing) || everyone ? credentialed : [])])].sort();
    for (const g of run.settlement?.gaps ?? []) places.push({ run: id, record: 'gap-window', id: `${g.after ?? 'start'}>${g.before ?? 'end'}`, own: false, candidates: between(g.after, g.before), windows: sealed(g.windows, 'gap'), order: g.before === null ? Infinity : position(g.before) - 0.5, failing: [], wide: new Set() });
    for (const b of run.settlement?.barriers ?? []) places.push({ run: id, record: 'barrier-window', id: `after ${b.after}`, own: false, candidates: [byId.get(b.after).actorId], windows: sealed(b.windows, 'barrier'), order: position(b.after) + 0.25, failing: [], wide: new Set() });
    // A run that declares observers and has no settlement record observed only its effect rows: any other sent row ran unobserved.
    if (configs.length && !run.settlement) for (const r of results) if (sentRow(r) && r.trace?.[1]?.type !== 'effect-observation') runFacts.push({ run: id, reason: 'check-unobserved', at: r.id, actors: [byId.get(r.id).actorId] });
    // A recorder that did not drain at the run's end may have missed late sends.
    for (const d of run.settlement?.drains ?? []) if (!(d.quiescent === true && d.markClear === true && d.closedAfterCollect === false)) {
      const w = rowWindows.flat().find(x => x.instanceId === d.instanceId);
      runFacts.push({ run: id, reason: 'collector-not-drained', observer: d.instanceId, sees: w ? [...reach.entries.values()].filter(e => seesEntry(w, e)).map(e => e.key) : [], actors: [...actedHere] });
    }
  }
  const principals = Object.fromEntries(Object.entries(target.actors).map(([alias, a]) => [alias, a.principalId]));
  const joined = assemble({ reach, principals, aliases: Object.keys(target.actors), places, operationUses, runFacts, background: target.attribution?.background ?? [] });
  return finish({ kind: 'http', identity: { targetId: target.id, applicationId: target.applicationId, profileHash }, reach, actors: target.actors, joined, runIds, acted, actedRuns, operationsGranted, operationUnobservable, contract });
}

// The steps of a sequence, in order, and what its windows can and cannot show about who acted.
function sequenceSteps(seq) {
  const steps = seq.steps.map((s, i) => { const [kind] = stepActions(s); return { i, kind, v: s[kind], background: s.background === true }; });
  const marks = new Map(steps.filter(s => s.kind === 'mark').map(s => [s.v, s.i]));
  const awaited = new Map(steps.filter(s => s.kind === 'awaitResponse').map(s => [s.v.request, s.i]));
  const requests = steps.filter(s => s.kind === 'request');
  return {
    // Who could have caused what a window recorded: every actor whose request was sent before its end mark. A request's effect
    // can commit after its response (a slow write, a held call released later), so an earlier request is never ruled out.
    actorsOf: to => [...new Set(requests.filter(s => s.i < marks.get(to)).map(s => s.v.actorId))].sort(),
    // The requests no window spans: sent after a window's first mark and done (answered, or awaited when in the background)
    // before its end mark. What such a request caused may be in no window at all.
    uncovered: keys => requests.filter(s => !keys.some(([a, b]) => marks.get(a) < s.i && (s.background ? (awaited.get(s.v.id) ?? Infinity) < marks.get(b) : s.i < marks.get(b)))),
  };
}

// The report for a timed sequence (integrations/sequences) and its sealed runs. configs is the observers.json list and
// gateConfig the gate.json (or null) the runs used: they declare the reach, and each run is bound to them and to the
// sequence by the sequence run validator. A sequence sends no witness, so its egress and mail sinks are presence-only:
// they can show a use, never that something went unused. An effect that commits after a window's end mark is in no window;
// when no observer declares a post-response settle, the end marks are taken right after the last request, so every entry
// is qualified (no-settle-declared), never clean. The run seals each observer's scope but not its settle, so the settle is
// read from the configuration given: it must be the one the runs used.
export function sequenceGrantUseReport({ sequence, runs = [], configs, gateConfig = null } = {}) {
  let seq, expected;
  try { seq = validateSequence(sequence); } catch (error) { fail(error.message); }
  if (!Array.isArray(runs)) fail('runs is a list of sealed sequence runs');
  try { expected = declaredObservers(configs, gateConfig); } catch (error) { fail(`the observer configuration is not valid (${error.message})`); }
  const reach = declaredReach(configs, gateConfig, expected.map(o => o.instanceId)), steps = sequenceSteps(seq);
  const places = [], runFacts = [], acted = new Set(), actedRuns = new Map(), runIds = [];
  runs.forEach((run, n) => {
    try { validateSequenceRun(run, { expectedSequence: seq, expectedObservers: expected }); } catch (error) { fail(`sequence run ${n + 1} does not pass the sequence run validator (${[error.code, error.detail].filter(Boolean).join(': ')})`); }
    const id = run.runDigest;
    if (runIds.includes(id)) fail(`sequence run ${n + 1} is listed twice`);
    runIds.push(id);
    // A /2 record keeps no responses: a run that did not stop sent every request.
    const requests = run.requests ?? (run.aborted ? [] : requestsOf(seq)), actedHere = new Set();
    for (const r of requests) if (run.responses === undefined || own(run.responses, r.id)) { acted.add(r.actorId); actedHere.add(r.actorId); }
    actedRuns.set(id, actedHere);
    const failing = new Map();
    for (const a of run.results) if (a.status === 'fail' && a.window) push(failing, `${a.window.from}>${a.window.to}`, a.id);
    const keys = Object.keys(run.windows);
    keys.forEach((key, k) => {
      const candidates = steps.actorsOf(key.split('>')[1]);
      const windows = custodyWindows(run.windows[key].map((w, i) => validateWindow(w, `sequence run ${n + 1} window ${key} ${i + 1}`)), 'sequenceGrantUseReport');
      places.push({ run: id, record: 'sequence-window', id: key, own: candidates.length === 1, candidates, windows, order: k, failing: failing.get(key) ?? [], wide: new Set() });
    });
    for (const s of steps.uncovered(keys.map(key => key.split('>')))) if (actedHere.has(s.v.actorId) || run.responses === undefined) runFacts.push({ run: id, reason: 'request-unobserved', at: s.v.id, actors: [s.v.actorId] });
    if (run.aborted) runFacts.push({ run: id, reason: `sequence-stopped:${run.aborted}`, actors: [...new Set(requestsOf(seq).map(r => r.actorId))] });
  });
  const principals = Object.fromEntries(Object.entries(seq.actors).map(([alias, a]) => [alias, a.principalId]));
  const joined = assemble({ reach, principals, aliases: Object.keys(seq.actors), places, operationUses: [], runFacts, background: [] });
  if (!configs.some(c => c?.type !== 'otel' && settleDeclared(c?.settleMs))) for (const why of joined.basis.values()) why.push('no-settle-declared');
  return finish({ kind: 'sequence', identity: { sequenceId: seq.id, sequenceHash: sequenceHashOf(seq), applicationId: seq.applicationId ?? null }, reach, actors: seq.actors, joined, runIds, acted, actedRuns,
    operationsGranted: new Map(), operationUnobservable: new Map(), contract: null });
}
