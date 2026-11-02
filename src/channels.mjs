// The declared-channel rule for absence. A clean window from the observers a row names says only that
// nothing matching was seen there: an effect that left the application by another channel (a cache, a file, a direct API call, a
// queue) is in no window, and the bypass corpus's route misses are exactly such undeclared channels.
//
// So a target may declare its channels (docs/ONBOARDING.md, "Declare the target's channels"):
//   { "confinement": "confined" | "unconfined",
//     "list": [{ "id": "orders-db", "kind": "store", "observedBy": ["pg"], "names": ["orders", "refunds"], "port": 5432 }, ...] }
// kind: store (database tables or stores), outbox, egress (destinations the app calls), files (files or directories), queue
// (queues or jobs). observedBy names the declared observers that hold that channel's records (an empty list declares a
// channel nothing observes); names are what the channel is in its observers' vocabulary (tables for a snapshot, action names
// for an audit table, hosts for an egress recorder, domains for an SMTP sink), each in some observing window's vocabulary;
// port, optional and only on a store watched by a pg-snapshot, mysql-snapshot or pg-wal that connects to it on this machine, is the
// allowlisted port of a confined launch the app reaches that database by.
//
// When the run declares channels, a boundary row's absence pass (effect.none, effect.only, any effect.count, since an exact
// count also says no more happened, or a claim rule's such clause) counts only when, in that row's own window:
//   - every declared channel was observed: a sealed window from one of its observedBy observers (of a type that can hold that
//     kind of channel), authoritative, not report-only, with complete coverage (a store may also read net change: a write undone
//     between two snapshots is invisible, which the residual states), whose vocabulary holds every declared name; otherwise the
//     row reads channel-unobserved:<channel>;
//   - and carried no effect that happened or may have (committed, or still open: started or unknown) that none of the row's
//     bounding clauses (a passing effect.count or effect.only) selects, in any window of a declared observer of a type that can
//     observe a channel, whatever that window's coverage: an effect on a channel's names belongs to that channel, one on no
//     channel's names to the channels whose observer recorded it; any of them could be the effect the absence is about, sent
//     that way instead; otherwise channel-unaccounted:<channel> (until per-platform ignore lists land, a background write
//     withholds the pass too). An observer no channel lists that records such an effect on no channel's names may show a
//     channel the declaration leaves out (or an ordinary row the rule cannot tell apart): channels-undeclared;
//   - and the run's confinement shows no undeclared way out: the declaration says "confined", the target is a local app, and
//     the run carries a valid confinement record (./scopehaven assess --confine, src/confinement-record.mjs) whose every sink is
//     an observer of a declared channel and every allowlisted port a store channel's port, whose kernel log was
//     read through (the self-test's denial and the closing marker seen) and logged no refused connection while the app ran (each
//     one is the app trying a way out nothing declares). "unconfined", a forwarded or remote target, a missing or invalid record,
//     an undeclared sink or allowlisted port, a logged denial or a log not read through, or a declaration the run carries but
//     that does not read, gives channels-undeclared. The record calls its denial count informative: no row verdict reads it, but
//     this rule, and so the gate, the comparison and the reports, do.
// Otherwise the pass reads inconclusive: the report, SARIF, the comparison and the regression gate read it so, with those
// reasons. A fail, an allowed-use control and every other row are untouched, and a run without a declaration reads as before
// (its report states "channels undeclared").
//
// Like src/forwarded-pairing.mjs, this module is outside the HTTP evaluator identity and never changes a row: the sealed status
// stays what the effect rules decided, so every existing suite keeps its verdicts and hashes. Confinement is sealed into a run
// only after its rows are decided (src/cli.mjs), so the rule can only be read from the saved run. Confinement covers outbound
// network connections; a file, a local store or IPC that the declaration leaves out is not shown absent by anything here.
//
// Pure: no I/O.
import { REPORT_ONLY_SOURCES, matches } from './effect-events.mjs';
import { custodyOf, INDEPENDENT_CUSTODY } from './custody.mjs';
import { confinementOf } from './confinement-record.mjs';

export const CHANNEL_KINDS = Object.freeze(['store', 'outbox', 'egress', 'files', 'queue']);
export const CHANNEL_CONFINEMENT = Object.freeze(['confined', 'unconfined']);
// The observer types that read a channel of each kind itself (its table, its entries, the wire), never a report about it: the
// application's telemetry (otel, mcp-log), its own audit endpoint (http-audit) and its own request log (audit-file) observe no
// channel, and a store is observed by its tables (a snapshot), not by the action log the application writes beside them (an
// audit table). An outbox or a queue is consumed by design (an entry is written, then sent or run and deleted or marked), so
// only a record of every entry observes one (an audit table, as complete as the application's logging); a snapshot reads net
// change and would miss the very entry the absence is about, and an SMTP sink or a provider feed records what was delivered,
// which is egress, not what was queued. No shipped observer reads files or directories the application writes, so a files
// channel is declared unobserved.
export const CHANNEL_OBSERVERS = Object.freeze({
  // pg-wal: every committed write to its declared tables, so it holds a store channel's records too.
  store: Object.freeze(['sqlite-snapshot', 'pg-snapshot', 'mysql-snapshot', 'pg-wal']),
  outbox: Object.freeze(['sqlite-audit']),
  egress: Object.freeze(['egress-recorder', 'smtp-sink', 'provider-feed']),
  files: Object.freeze([]),
  queue: Object.freeze(['sqlite-audit']),
});
// Kinds a net-change window observes (a store's final state; its residual says a write undone within the window is invisible).
const NET_CHANGE_KINDS = Object.freeze(['store']);
// The observer types that can observe some channel: a declared one no channel lists is read for effects all the same.
const CHANNEL_CAPABLE = Object.freeze([...new Set(Object.values(CHANNEL_OBSERVERS).flat())]);
// The outcomes of an effect that happened or may have: the effect clauses read a started or unknown one as possibly committed.
const HAPPENED = Object.freeze(['committed', 'started', 'unknown']);
export const CHANNEL_BOUNDS = Object.freeze({ channels: 32, observedBy: 8, names: 32, nameChars: 200 });
const port = value => Number.isInteger(value) && value >= 1 && value <= 65535;
export const CHANNEL_UNOBSERVED = 'channel-unobserved', CHANNEL_UNACCOUNTED = 'channel-unaccounted', CHANNELS_UNDECLARED = 'channels-undeclared';
// A port belongs to a store watched by a networked database snapshot: the database the app reaches at that allowlisted port. Any
// other port (an egress relay, a queue broker no observer reads) would be a way out no sink sees.
const PORT_KINDS = Object.freeze(['store']), PORT_OBSERVERS = Object.freeze(['pg-snapshot', 'mysql-snapshot', 'pg-wal']);
const LOOPBACK_HOSTS = Object.freeze(['127.0.0.1', 'localhost', '::1']);
const CHANNEL_ID = /^[A-Za-z0-9_-]{1,48}$/;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const onlyKeys = (value, required, optional = []) => required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
const unique = list => new Set(list).size === list.length;

// The problem with a channel declaration, or null when it is well formed against the target's declared observers. For the
// profile validator (src/contracts.mjs) and for reading a saved run, which re-checks it against the run's own observers.
export function channelDeclarationProblem(channels, observers = []) {
  if (!plain(channels) || !onlyKeys(channels, [], ['confinement', 'list'])) return 'channels-shape: "channels" is { "confinement", "list" } and nothing else';
  if (!CHANNEL_CONFINEMENT.includes(channels.confinement)) return 'channels-confinement: "confinement" is "confined" (the run must be a confined launch, --confine) or "unconfined" (absence passes then read inconclusive)';
  const list = channels.list;
  if (!Array.isArray(list) || list.length < 1 || list.length > CHANNEL_BOUNDS.channels) return `channels-list: "list" declares 1 to ${CHANNEL_BOUNDS.channels} channels`;
  const declared = Array.isArray(observers) ? observers.filter(plain) : [];
  const ids = new Set();
  for (const [index, channel] of list.entries()) {
    const at = `channel ${index + 1}`;
    if (!plain(channel) || !onlyKeys(channel, ['id', 'kind', 'observedBy', 'names'], ['port'])) return `channels-shape: ${at} is { "id", "kind", "observedBy", "names" } with optional "port"`;
    if (typeof channel.id !== 'string' || !CHANNEL_ID.test(channel.id) || ids.has(channel.id)) return `channels-id: ${at} needs a unique "id" (1-48 letters, digits, "_" or "-")`;
    ids.add(channel.id);
    if (!CHANNEL_KINDS.includes(channel.kind)) return `channels-kind: channel "${channel.id}" has "kind" one of ${CHANNEL_KINDS.join(', ')}`;
    const by = channel.observedBy;
    if (!Array.isArray(by) || by.length > CHANNEL_BOUNDS.observedBy || !by.every(id => typeof id === 'string') || !unique(by)) return `channels-observed-by: channel "${channel.id}" lists at most ${CHANNEL_BOUNDS.observedBy} distinct observer ids in "observedBy" (an empty list declares a channel nothing observes)`;
    for (const id of by) {
      const observer = declared.find(o => o.id === id);
      if (!observer) return `channels-observer-undeclared: channel "${channel.id}" names observer "${id}", which the target does not declare`;
      if (!CHANNEL_OBSERVERS[channel.kind].includes(observer.type)) return `channels-observer-kind: observer "${id}" (${observer.type}) does not hold a ${channel.kind} channel's records; ${CHANNEL_OBSERVERS[channel.kind].length ? `one of ${CHANNEL_OBSERVERS[channel.kind].join(', ')} does` : 'no shipped observer does, so declare it with an empty "observedBy"'}`;
    }
    const names = channel.names;
    if (!Array.isArray(names) || names.length < 1 || names.length > CHANNEL_BOUNDS.names || !names.every(n => typeof n === 'string' && n.length >= 1 && n.length <= CHANNEL_BOUNDS.nameChars) || !unique(names))
      return `channels-names: channel "${channel.id}" lists 1 to ${CHANNEL_BOUNDS.names} distinct names of 1-${CHANNEL_BOUNDS.nameChars} characters in "names"`;
    if (Object.hasOwn(channel, 'port') && (!PORT_KINDS.includes(channel.kind) || !port(channel.port) || list.some((other, j) => j !== index && plain(other) && other.port === channel.port)))
      return `channels-port: channel "${channel.id}" has a "port" from 1 to 65535 that no other channel declares, and only on a store channel (an egress or queue port would be a way out no sink sees)`;
    // The port is the one its database snapshot connects to on this machine. A saved run's observer records carry no port, so this is
    // checked where the profile is loaded (src/contracts.mjs passes the declared observers); the gate binds the run to that profile.
    if (Object.hasOwn(channel, 'port')) {
      const dbs = by.map(id => declared.find(o => o.id === id)).filter(o => PORT_OBSERVERS.includes(o.type));
      if (!dbs.length) return `channels-port: channel "${channel.id}" names a port, so it is observed by a ${PORT_OBSERVERS.join(' or ')} observer that connects to it`;
      const configured = dbs.filter(o => Object.hasOwn(o, 'port'));
      if (configured.length && !configured.some(o => o.port === channel.port && (!Object.hasOwn(o, 'host') || LOOPBACK_HOSTS.includes(o.host))))
        return `channels-port: channel "${channel.id}" declares port ${channel.port}, but none of its database snapshot observers connects to that port on this machine`;
    }
  }
  return null;
}

// The run's declaration: null when it declares none, MALFORMED when it carries one that does not read against its own observers.
const MALFORMED = Symbol('malformed channel declaration');
function declarationOf(run) {
  if (!plain(run) || !Object.hasOwn(run, 'channels')) return null;
  try { return channelDeclarationProblem(run.channels, run.observers) === null ? run.channels : MALFORMED; } catch { return MALFORMED; }
}
// Whether this run's profile could declare channels: the HTTP connector's runs (src/http-connector.mjs).
const declarable = run => plain(run) && run.evidenceOrigin === 'local-http-response';

// A clause whose pass says something did not happen: effect.none, effect.only, and effect.count of any number (exactly N also says
// no more than N happened, so a duplicate sent by an unwatched channel would make it false).
export const absenceBearing = kind => kind === 'effect.none' || kind === 'effect.only' || kind === 'effect.count';
const effectData = row => (Array.isArray(row?.trace) && plain(row.trace[1]?.data) ? row.trace[1].data : null);
const windowsOf = row => (Array.isArray(effectData(row)?.windows) ? effectData(row).windows : []);
// A row of any severity that passed with at least one such clause (or claim rule clause) that passed.
export function absenceBearingPass(row) {
  if (!plain(row) || row.status !== 'pass') return false;
  const data = effectData(row);
  if (!data) return false;
  const effects = Array.isArray(data.effects) ? data.effects : [], claims = Array.isArray(data.claims) ? data.claims : [];
  return effects.some(e => plain(e) && e.verdict === 'pass' && absenceBearing(e.kind)) || claims.some(c => plain(c) && c.verdict === 'pass' && absenceBearing(c.clause));
}
// The readers withhold only a boundary row's pass: an allowed-use control keeps its verdict (its claim type still reads the rule).
const boundaryAbsencePass = row => absenceBearingPass(row) && row.severity !== 'control';

// The selectors of a row's own clauses that bound what happened: a passing effect.count (exactly N, so no other match) and a
// passing effect.only (its expected and allowed effects, everything else ruled out), and a claim rule's passing count. A committed
// effect on a declared channel that one of them selects is accounted for by the row itself. An effect.exists bounds nothing (one
// match does not rule out a second), and an untriggered or unsettled clause decided nothing, so neither accounts for an effect.
function rowSelectors(row) {
  const data = effectData(row), one = item => (plain(item?.select) ? [item.select] : plain(item) ? [item] : []);
  return [...(Array.isArray(data?.effects) ? data.effects : []).filter(e => plain(e) && e.verdict === 'pass').flatMap(e => e.kind === 'effect.count' && plain(e.select) ? [e.select]
    : e.kind === 'effect.only' ? [...(Array.isArray(e.expect) ? e.expect.flatMap(one) : []), ...(Array.isArray(e.allow) ? e.allow.flatMap(one) : [])] : []),
    ...(Array.isArray(data?.claims) ? data.claims : []).filter(c => plain(c) && c.verdict === 'pass' && c.clause === 'effect.count' && plain(c.select)).map(c => c.select)];
}
// The instance ids of the declared observers that may watch one channel.
const channelInstances = (channel, observers) => new Set(channel.observedBy.flatMap(id => {
  const observer = observers.find(o => plain(o) && o.id === id);
  return observer && CHANNEL_OBSERVERS[channel.kind].includes(observer.type) ? [`${observer.type}-${observer.id}`] : [];
}));
// The windows of one row that observed one channel: authoritative, complete (or net change for a store), with a readable events list.
function observingWindows(channel, windows, observers) {
  const instances = channelInstances(channel, observers);
  return windows.filter(w => plain(w) && instances.has(w.instanceId) && !REPORT_ONLY_SOURCES.includes(w.source) && w.scope?.evidence === 'authoritative' && Array.isArray(w.events)
    && (w.coverage === 'complete' || (w.coverage === 'net-only' && NET_CHANGE_KINDS.includes(channel.kind))));
}
// One channel in one row's window: observed when every declared name is in an observing window's vocabulary; netChange when some
// name is covered only by net-change windows; independent when every name is covered by a window held outside the application.
function channelInRow(channel, windows, observers) {
  const seen = observingWindows(channel, windows, observers);
  const covering = name => seen.filter(w => Array.isArray(w.scope?.names) && w.scope.names.includes(name));
  const observed = seen.length > 0 && channel.names.every(name => covering(name).length > 0);
  return { id: channel.id, observed, unaccounted: 0, custody: [...new Set(seen.map(w => custodyOf(w)))].sort(),
    netChange: observed && channel.names.some(name => covering(name).every(w => w.coverage === 'net-only')),
    independent: observed && channel.names.every(name => covering(name).some(w => INDEPENDENT_CUSTODY.includes(custodyOf(w)))) };
}
// The effects in a row's window that happened or may have and that none of its bounding clauses selects (a bounding clause
// selects only committed effects, so an open one is never accounted for), from every window of a declared observer of a type that
// can observe a channel, whatever that window's coverage (a partial window's committed effect still happened). Each belongs to the
// channels that name it, or, when no channel names it, to the channels whose observer recorded it: any of them could be the effect
// the absence is about, sent that way instead. One recorded by an observer no channel lists, on no channel's names, may have
// gone by a channel the declaration leaves out. Returns { counts } per channel index and { unlisted: [{ observer, type, count }] }.
function unaccountedByChannel(list, windows, observers, selectors) {
  const instancesOf = list.map(channel => channelInstances(channel, observers)), counts = list.map(() => 0);
  const listed = new Set(list.flatMap(channel => channel.observedBy));
  const unlistedOf = new Map(observers.filter(o => plain(o) && !listed.has(o.id) && CHANNEL_CAPABLE.includes(o.type)).map(o => [`${o.type}-${o.id}`, o])), unlisted = new Map();
  const selected = e => selectors.some(s => { try { return matches(e, { ...s, outcome: 'committed' }); } catch { return false; } });
  for (const w of windows) {
    if (!plain(w) || REPORT_ONLY_SOURCES.includes(w.source) || !Array.isArray(w.events)) continue;
    const owners = instancesOf.map((set, i) => (set.has(w.instanceId) ? i : -1)).filter(i => i >= 0), stray = unlistedOf.get(w.instanceId);
    if (!owners.length && !stray) continue;
    for (const e of w.events) {
      if (!plain(e) || !HAPPENED.includes(e.outcome) || selected(e)) continue;
      const named = list.map((c, i) => (c.names.includes(e.name) ? i : -1)).filter(i => i >= 0);
      if (named.length || owners.length) for (const i of named.length ? named : owners) counts[i]++;
      else unlisted.set(stray, (unlisted.get(stray) ?? 0) + 1);
    }
  }
  return { counts, unlisted: [...unlisted].map(([o, count]) => ({ observer: o.id, type: o.type, count })) };
}

// Why the run's confinement does not show that no undeclared channel exists, or null when it does.
export function confinementGap(run) {
  const declaration = declarationOf(run);
  if (declaration === null) return null;
  if (declaration === MALFORMED) return 'the run carries a channel declaration that does not read against its declared observers';
  if (declaration.confinement === 'unconfined') return 'the profile declares the run unconfined, so nothing shows the application had no other way out';
  // A forwarded or remote target's application runs elsewhere: a confined launch here confines the forwarder, not the application.
  if ((run.targetContext ?? 'local-app') !== 'local-app') return 'the target is not a local application, so a confined launch here does not confine it';
  const record = confinementOf(run);
  if (!record) return 'the profile declares a confined run, but the run carries no valid confinement record (run it with --confine)';
  const declaredPorts = new Set(declaration.list.filter(c => Object.hasOwn(c, 'port')).map(c => c.port));
  const loose = record.allow.filter(a => !declaredPorts.has(a.port)).map(a => a.port);
  if (loose.length) return `the confinement allowlists port${loose.length === 1 ? '' : 's'} ${loose.join(', ')} that no declared channel names, a way out no sink sees`;
  // Every sink the confinement lets the application reach is a way out too: one no declared channel's observers include is undeclared.
  const named = new Set(declaration.list.flatMap(c => c.observedBy));
  const unnamed = record.sinks.filter(sink => !named.has(sink.observerId)).map(sink => `${sink.type} ${sink.observerId}`);
  if (unnamed.length) return `the confinement lets the application reach ${unnamed.join(', ')}, which no declared channel's observers include`;
  const d = record.denials;
  if (!d.collected || !d.selfTestSeen || !d.markerSeen) return 'the kernel log of refused connections was not read through (the self-test\'s denial and the closing marker), so a way out the application tried may be unseen';
  if (d.count > 0) return `the kernel refused ${d.count} outbound connection${d.count === 1 ? '' : 's'} the application tried while it ran, a way out nothing declares`;
  return null;
}

// One row against the run's declared channels, whatever its severity: null for a run that declares none; otherwise { reasons,
// channels, unlisted, gap }, where reasons are channel-unobserved:<channel> or channel-unaccounted:<channel> per channel (declaration
// order), then channels-undeclared for an effect an observer no channel lists recorded, the confinement gap, or a carried
// declaration that does not read.
export function rowChannelState(run, row) {
  const declaration = declarationOf(run);
  if (declaration === null) return null;
  const gap = confinementGap(run);
  if (declaration === MALFORMED) return { reasons: [CHANNELS_UNDECLARED], channels: [], unlisted: [], gap };
  const observers = Array.isArray(run.observers) ? run.observers : [], windows = windowsOf(row);
  const { counts, unlisted } = unaccountedByChannel(declaration.list, windows, observers, rowSelectors(row));
  const channels = declaration.list.map((channel, i) => ({ ...channelInRow(channel, windows, observers), unaccounted: counts[i] }));
  return { reasons: [...channels.flatMap(c => !c.observed ? [`${CHANNEL_UNOBSERVED}:${c.id}`] : c.unaccounted ? [`${CHANNEL_UNACCOUNTED}:${c.id}`] : []),
    ...(gap !== null || unlisted.length ? [CHANNELS_UNDECLARED] : [])], channels, unlisted, gap };
}

// The boundary absence passes of a run that declares channels which do not count, in row order: [{ id, reasons }]. [] for a run
// that declares none.
export function channelReadings(run) {
  if (declarationOf(run) === null || !Array.isArray(run.results)) return [];
  return run.results.filter(boundaryAbsencePass).map(row => ({ id: row.id, reasons: rowChannelState(run, row).reasons })).filter(reading => reading.reasons.length);
}
export const channelWithheldPasses = run => channelReadings(run).map(reading => reading.id);
// The regression gate's reasons for a run (unique, in the order the readings first give them).
export const channelGateReasons = run => [...new Set(channelReadings(run).flatMap(reading => reading.reasons))];

export const CHANNELS_UNDECLARED_NOTE = 'Channels undeclared: this profile declares no channels, so each absence pass rests only on the observers that decided it. An effect that left the application by a way none of them watches (a cache, a file, a direct API call, a queue) is in no window. Declare the target\'s channels to make every absence pass show each one observed.';
export const CHANNEL_RULE = 'An absence or count pass in a boundary check counts only when, in that check\'s window, every channel the profile declares was observed by an observer that holds that channel\'s records (complete coverage; a store may read net change), and no window of a declared observer that can observe a channel, listed or not, carried an effect that happened or may have (committed, started or unknown) that the check\'s bounding clauses (a passing exact count or effect.only) do not select, and the run is a confined launch of a local app whose every sink and allowlisted port is a declared channel\'s, with its kernel log read through and no refused connection. Otherwise it reads inconclusive (channel-unobserved:<channel>, channel-unaccounted:<channel>, channels-undeclared). Confinement covers outbound network connections only: a file, a local store or IPC the declaration leaves out is not shown absent. The sealed row keeps the status the effect rules decided.';

// What a run states about its channels, for the report, SARIF, the comparison and the residual: null for a run whose profile
// cannot declare channels; { declared: false, note } for one that declares none; otherwise the declaration, how each channel was
// observed across the run's boundary absence passes, the observers no channel lists that recorded an effect in one (unlisted), the
// confinement gap and the withheld rows.
export function channelStatement(run) {
  if (!declarable(run)) return null;
  const declaration = declarationOf(run);
  if (declaration === null) return { declared: false, reason: CHANNELS_UNDECLARED, note: CHANNELS_UNDECLARED_NOTE };
  const withheld = channelReadings(run), gap = confinementGap(run);
  if (declaration === MALFORMED) return { declared: true, readable: false, confinement: null, tier: null, gap, channels: [], unlisted: [], withheld, rule: CHANNEL_RULE };
  const passes = (Array.isArray(run.results) ? run.results : []).filter(boundaryAbsencePass).map(row => ({ id: row.id, state: rowChannelState(run, row) }));
  const channels = declaration.list.map((channel, i) => {
    const inRows = passes.map(p => ({ id: p.id, c: p.state.channels[i] }));
    return { id: channel.id, kind: channel.kind, observedBy: [...channel.observedBy], names: [...channel.names], ...(Object.hasOwn(channel, 'port') ? { port: channel.port } : {}),
      unobservedIn: inRows.filter(r => !r.c.observed).map(r => r.id), unaccountedIn: inRows.filter(r => r.c.observed && r.c.unaccounted).map(r => r.id),
      custody: [...new Set(inRows.flatMap(r => r.c.custody))].sort(), netChange: inRows.some(r => r.c.netChange) };
  });
  const strays = new Map();
  for (const p of passes) for (const u of p.state.unlisted) (strays.get(u.observer) ?? strays.set(u.observer, { observer: u.observer, type: u.type, rows: [] }).get(u.observer)).rows.push(p.id);
  return { declared: true, readable: true, confinement: declaration.confinement, tier: confinementOf(run) ? 'confined' : 'declared', gap, channels, unlisted: [...strays.values()], withheld, rule: CHANNEL_RULE };
}

// One sentence per declared channel, for the HTML report and the comparison.
export function channelSentence(entry) {
  const by = entry.observedBy.length ? `observed by ${entry.observedBy.join(', ')}` : 'observed by nothing';
  const names = entry.names ? ` (${entry.names.join(', ')})` : '';
  const port = entry.port ? `, reached at allowlisted port ${entry.port}` : '';
  const missed = entry.unobservedIn.length ? ` Not observed in the window of ${entry.unobservedIn.join(', ')}.` : '';
  const unaccounted = entry.unaccountedIn?.length ? ` Carried an effect (committed or still open) the check's clauses do not select in ${entry.unaccountedIn.join(', ')}.` : '';
  const custody = entry.custody.length ? ` Custody of the observing windows: ${entry.custody.join(', ')}.` : '';
  const net = entry.netChange ? ' Read from net change between snapshots: a write undone within a window is invisible.' : '';
  return `${entry.id}: ${entry.kind}${names}${port}, ${by}.${missed}${unaccounted}${custody}${net}`;
}
// One sentence per declared observer no channel lists that recorded an effect in a boundary absence pass's window. The effect may
// be one that went by a channel the declaration leaves out, or an ordinary row (the app's own log of the request, say): the rule
// cannot tell them apart, so it withholds either way.
export const unlistedSentence = entry => `${entry.observer} (${entry.type}), which no declared channel lists, recorded an effect the check's clauses do not select in the window of ${entry.rows.join(', ')}; it may have gone by a channel the declaration leaves out, so ${entry.rows.length === 1 ? 'that pass reads' : 'those passes read'} channels-undeclared.`;
