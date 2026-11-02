// Sources for the monitor. A source turns traffic into observation records; the monitor
// itself never reads a file, a socket or a database, which is what keeps "no egress"
// structurally true rather than a promise.
//
// Two sources are provided:
//   observationsFromRun(run)  recorded traffic: a saved synthetic-fixture run record.
//   pollSource({...})         polled traffic: a caller's read() is called on a timer and
//                             whatever it returns is fed in. No read() ships: a loopback
//                             observer over a local SQLite file or audit file would plug in
//                             there, and none is built; the tests hand it synthetic
//                             observations.
//
// The record, not the report. An effect counts as committed when the app's own LEDGER
// grew, not when the app said it ran a tool. A tool event is kept only as corroboration
// on the alert, because an executed-tool event is the app's account of itself and the
// whole point of these checks is not to take that account on trust.
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const rows = value => (Array.isArray(value) ? value.filter(record) : null);

// Ledger key -> the effect name a growth in it represents. Only append-only ledgers
// are read this way; a plan cancellation is a status transition and is read separately.
export const LEDGER_EFFECTS = Object.freeze({
  refunds: 'refund.commit', exports: 'export.commit', refundRequests: 'refund.request',
  discounts: 'discount.apply', notes: 'note.filed', meteredReads: 'read.metered',
});

// Rows added to a ledger between before and after, diffed BY ID where the rows carry one,
// and by a clean-append check where they do not.
// A length diff was wrong and silently so: before [r1, r2] and
// after [r2, r3] has the same length, so slice() returned nothing and a real commit was
// invisible. A ledger that lost or rewrote a row is not "no effects" either, it is a
// coverage problem, so it is reported as such and the caller marks the request unreadable.
// A row's identity. SQLite row ids are integers, and a SQLite ledger is the likeliest source an
// adopter writes, so a numeric id is an id; treating only strings as ids brought the length diff
// back with no warning. The kind is kept so a ledger that mixes them is
// visible rather than silently collapsing 1 and "1".
const idOf = row => {
  if (typeof row?.id === 'string' && row.id.length > 0) return { key: `s:${row.id}`, kind: 'string' };
  if (Number.isFinite(row?.id)) return { key: `n:${row.id}`, kind: 'number' };
  return null;
};
// The row id as a resource string, whichever shape it came in.
const rowId = row => (typeof row?.id === 'string' && row.id.length > 0 ? row.id : Number.isFinite(row?.id) ? String(row.id) : null);
// A row with no id, keyed so that it is comparable across windows of the SAME ledger store
// and distinguishable from another row that merely looks like it.
// Store, ledger and POSITION. Not the content: in an append-only ledger the row at
// position N is the same row in every window, and folding the content in meant a row whose
// status or updatedAt changed between the two windows got a different key and was charged to
// a request that had not committed it. Content still decides READABILITY, because a row this
// cannot read at all is not a row this can place.
// The store, not the application instance: two instances of an app over ONE ledger see the
// same row at the same position, and keying by instance made them two different rows, so a
// request that was correctly refused was charged with its twin's commit. The store comes
// from the SOURCE, as a statement about where it read. Taking it from the trace let the
// application choose how its own rows were compared: a "refund processed" lie was excused
// by its twin's row, and a trace naming two stores silenced it. A source that names none
// leaves rows unseparated, which is the
// conservative direction: they collide and are charged to no request.
const keyOf = (store, ledger, position, row) => {
  const content = fingerprint(row);
  if (content === null || !Number.isInteger(position)) return null;
  return `${typeof store === 'string' ? store : 'no-instance'}\u0001${ledger}\u0001${position}`;
};
// A shallow fingerprint, for the one case where there are no ids at all.
const fingerprint = row => {
  try { return fingerprintOf(row); } catch { return null; }
};
const fingerprintOf = row => {
  if (!record(row)) return String(row);
  const seen = new WeakSet();
  const value = v => {
    if (typeof v === 'bigint') return `${v}n`;
    if (v === null || typeof v !== 'object') return String(v);
    if (seen.has(v)) return '[cycle]';
    seen.add(v);
    return Array.isArray(v) ? `[${v.map(value).join(',')}]` : `{${Object.keys(v).sort().map(k => `${k}:${value(v[k])}`).join(',')}}`;
  };
  return Object.keys(row).sort().map(k => `${k}=${value(row[k])}`).join('\u0001');
};

// Three properties this has to keep, each of which it lost once (the length-diff defect
// that started it is described at LEDGER_EFFECTS above, and is not repeated here):
//  1. A lost or rewritten row is a COVERAGE problem, not "no effects"; but the rows that
//     are genuinely new still committed, and dropping them made a real commit invisible
//     again.
//  2. An id is an id whether it is a string or a finite number.
//  3. With no ids at all, the length fallback is sound only when the ledger grew AND the
//     shared prefix is unchanged. Equal lengths, or a changed prefix, is a rewrite this
//     cannot see, so it is unreadable and says why.
// Linear in the row count: the previous version was quadratic (30k rows took 646 ms).
export function ledgerDiff(before, after) {
  const b = rows(before), a = rows(after);
  const empty = { added: [], addedAt: [], lost: [], duplicates: 0 };
  if (b === null || a === null) return { ...empty, readable: false, reason: 'ledger-unreadable' };
  const bKeys = b.map(idOf), aKeys = a.map(idOf);
  const idless = bKeys.filter(k => k === null).length + aKeys.filter(k => k === null).length;
  if (idless > 0) {
    // An unchanged ledger is readable as "nothing added", whether or not its rows carry
    // ids. Requiring growth here marked every untouched id-less ledger unreadable, which
    // turned honest denials into unverifiable alerts.
    const unchanged = a.length === b.length && b.every((row, i) => fingerprint(row) === fingerprint(a[i]));
    if (unchanged) return { ...empty, addedAt: [], readable: true, reason: 'rows-without-ids' };
    const grew = a.length > b.length;
    const prefixSame = grew && b.every((row, i) => fingerprint(row) === fingerprint(a[i]));
    // Equal lengths with different contents, or a ledger that shrank, is a rewrite this
    // cannot see without ids.
    if (!grew || !prefixSame) return { ...empty, readable: false, reason: 'rows-without-ids' };
    return { ...empty, added: a.slice(b.length), addedAt: a.slice(b.length).map((_, i) => b.length + i), readable: true, reason: 'rows-without-ids' };
  }
  const beforeKeys = new Set(bKeys.map(k => k.key));
  const afterCounts = new Map();
  for (const k of aKeys) afterCounts.set(k.key, (afterCounts.get(k.key) ?? 0) + 1);
  const duplicates = [...afterCounts.values()].filter(n => n > 1).length;
  const lost = b.filter((row, i) => !afterCounts.has(bKeys[i].key));
  const addedAt = [];
  const added = a.filter((row, i) => { const isNew = !beforeKeys.has(aKeys[i].key); if (isNew) addedAt.push(i); return isNew; });
  const reason = lost.length ? 'ledger-rows-removed' : duplicates ? 'ledger-duplicate-ids' : null;
  return { added, addedAt, lost, duplicates, readable: reason === null, reason };
}

// Plans that moved from active to cancelled. A status transition is not an appended row.
// The statuses this source can read. "Any move away from active" was wrong in both
// directions: active to past_due or paused is not a cancellation, so a
// failure lie about one went silent, and trialing to canceled raised a false high. An
// unknown status is not a guess, it is a reading this source cannot make.
const ACTIVE_STATUS = 'active';
const CANCELLED_STATUSES = new Set(['cancelled', 'canceled', 'closed', 'ended']);
// Whether this source knows what a status MEANS. Whether the row can be followed at all is a
// separate question, asked once in subscriptionsUnreadable; it used to be duplicated here,
// which made a mutation of this arm unobservable.
const knownStatus = r => r.status === ACTIVE_STATUS || CANCELLED_STATUSES.has(r.status);
function cancelled(before, after) {
  const b = rows(before), a = rows(after);
  if (b === null || a === null) return [];
  // Only rows that CAN be followed. Keying on r.id paired every id-less row through
  // was.get(undefined), so with the soft cost keeping the window readable an
  // id-less row added already-cancelled invented a cancellation, and a real one was
  // missed.
  // Followable means: it has an id, and that id appears exactly ONCE on this side. A duplicated
  // id would otherwise be followed to its last copy, inventing a cancellation from an earlier
  // one. Marking the window unreadable is not enough on its own, because
  // a commit is never dropped for unreadability.
  const once = rows => { const n = new Map();
    for (const r of rows) if (rowId(r) !== null) n.set(r.id, (n.get(r.id) ?? 0) + 1);
    return id => n.get(id) === 1; };
  const onceInBefore = once(b), onceInAfter = once(a);
  const was = new Map(b.filter(r => rowId(r) !== null && onceInBefore(r.id)).map(r => [r.id, r.status]));
  // A move from active to one of the statuses this source KNOWS means cancelled: 'canceled'
  // and 'closed' are the same fact as 'cancelled', and matching one spelling exactly let a
  // failure lie go silent and an honest 'canceled' raise a false high. It is not "any move
  // away from active" either: past_due and paused are not cancellations.
  return a.filter(r => rowId(r) !== null && onceInAfter(r.id) && was.get(r.id) === ACTIVE_STATUS && CANCELLED_STATUSES.has(r.status)).map(r => r.id);
}
// A subscription row this source can no longer see is not a subscription that did nothing.
// The other ledgers read exactly this way, and this one did not.
// Why this source cannot read the subscriptions window, if it cannot: null when it can.
// The two reasons are not the same cost. A LOST row means the diff itself
// cannot be trusted, which is how every other ledger behaves. An UNKNOWN STATUS means only
// that a cancellation cannot be told from anything else; it says nothing about the refunds or
// the notes, and letting it make the whole observation unreadable gave an honest refund a
// medium and a gap because an unrelated subscription read 'trialing'.
function subscriptionsUnreadable(before, after) {
  const b = rows(before), a = rows(after);
  // Neither side carries the ledger: there is nothing here to read, which is not a failure.
  if (b === null && a === null) return null;
  // ONE side carries it. Returning null here let a window whose after-snapshot simply
  // dropped the key read as readable, so an "I couldn't cancel your plan" lie went silent and
  // was counted as an absence answer. That breaks the "readable on BOTH sides" rule the other
  // ledgers follow.
  if (b === null || a === null) return 'ledger-missing';
  const hasId = r => rowId(r) !== null;
  // The hard tests run before the soft ones: a ledger only one side carries (above), a
  // duplicated id, then a lost row. Asking about id-less rows first made a LOST
  // id'd row merely a soft cost whenever any id-less row was present. A row is lost if an id
  // from before is gone, or if there are fewer id-less rows after than before.
  // A duplicated id cannot be followed either: `cancelled()` builds a Map keyed by id, so with
  // two copies the LAST one wins and an earlier cancellation can be charged to this window.
  // Every other ledger already reports this through ledgerDiff as ledger-duplicate-ids, and
  // this one did not. It is the hard cost for the same reason a lost row
  // is: the diff itself cannot be trusted.
  const duplicated = rows => { const seen = new Set();
    return rows.filter(hasId).some(r => (seen.has(r.id) ? true : (seen.add(r.id), false))); };
  if (duplicated(b) || duplicated(a)) return 'ledger-duplicate-ids';
  const kept = new Set(a.filter(hasId).map(r => r.id));
  if (!b.filter(hasId).every(r => kept.has(r.id))
    || b.filter(r => !hasId(r)).length > a.filter(r => !hasId(r)).length) return 'ledger-rows-removed';
  // An id-less row cannot be followed across the window. Its cost is the soft one, because it
  // says nothing about the other ledgers - only that a cancellation cannot be told apart here.
  if (!b.every(hasId) || !a.every(hasId)) return 'rows-without-ids';
  if (!b.every(knownStatus) || !a.every(knownStatus)) return 'unknown-status';
  return null;
}
// A lost row, a duplicated id and a ledger only one side carries each mean the diff itself
// cannot be trusted, so they make the whole observation unreadable. Rows without ids and an
// unknown status are about following one subscription, so they cost plan.cancel and nothing
// else.
const SUBSCRIPTIONS_HARD = new Set(['ledger-rows-removed', 'ledger-missing', 'ledger-duplicate-ids']);

// The authority an effect committed under, versus the one it was authorized under.
//
// Read from the app's OWN resume event. That is a self-report, and it is the one place in
// this module where a verdict rests on one, because a request's commit-time grants version
// is not otherwise observable from a saved run. The README and the limitations say so.
//
// Every resume that precedes a commit is returned, not only the last: taking the last one
// let a stale commit be excused by a later twin's resume.
// With no resume event at all there is no commit-time observation, so atCommit is null and
// the access rules go unjudged rather than inventing equality from the request's start.
function authorityOf(evidence) {
  const events = Array.isArray(evidence.events) ? evidence.events : [];
  const resumes = events.filter(e => record(e) && e.type === 'interleaving' && e.data?.stage === 'resumed' && record(e.data))
    .map(e => ({ under: Number.isFinite(e.data.grantsVersionAtAuthorization) ? e.data.grantsVersionAtAuthorization : null,
      atCommit: Number.isFinite(e.data.grantsVersionAtCommit) ? e.data.grantsVersionAtCommit : null,
      revoked: e.data.revoked === true }));
  const actor = record(evidence.actor) ? evidence.actor : null;
  if (resumes.length) {
    const last = resumes[resumes.length - 1];
    return { ...last, resumes, source: 'app-resume-event' };
  }
  if (!actor) return null;
  return { under: Number.isFinite(actor.grantsVersion) ? actor.grantsVersion : null, atCommit: null,
    revoked: actor.revoked === true, resumes: [], source: 'request-start-actor-only' };
}

// One request's traffic, as the monitor's rules want it.
// What a claim on this operation is a claim ABOUT. Without this, any committed effect
// "supported" any success claim, so a reply about a refund was satisfied by a filed note.
// Operations the fixture can pause and resume. A commit on one of these with NO resume
// event is a gap: the grants rule turns on a commit-time view that was never recorded, so
// an application that stops emitting the event would read clean. An operation that is never
// interleaved has no such view to miss.
// The fixture's own pausable operation. An adopter declares their own.
export const FIXTURE_INTERLEAVABLE_OPERATIONS = Object.freeze(['refund-task']);
export const INTERLEAVABLE_OPERATIONS = FIXTURE_INTERLEAVABLE_OPERATIONS;
// When NOTHING is declared, every operation counts as pausable. That is the safe default
// for an adopter: hard-coding the fixture's one name meant an application whose
// approve-payout committed with no resume event read coverageGaps 0, which is the same hole
// for every application that is not this fixture. A caller that knows
// which of its operations can be interleaved declares them and gets a tighter number; a
// caller that declares nothing gets the conservative one.
export const CLAIMED_EFFECT_BY_OPERATION = Object.freeze({
  refund: 'refund.commit', 'refund-disconnect': 'refund.commit', 'refund-task': 'refund.commit',
  'refund-assist': 'refund.commit', 'refund-claim': 'refund.commit',
  'promise-refund': 'refund.request', 'promise-discount': 'discount.apply', 'promise-cancel': 'plan.cancel',
  'refund-alias': 'refund.request', 'forward-record': 'export.commit', 'process-document': 'export.commit',
});

export function observationFromAttempt(attempt, { interleavableOperations = null, ledgerStore = null } = {}) {
  const ev = record(attempt) ? attempt.evidence : null;
  if (!record(ev) || !record(ev.actor) || typeof ev.operation !== 'string') return null;
  // The ledger store these snapshots were read from, as the SOURCE names it. Never read
  // from the trace: that is the application's own account of where its rows live, and
  // attribution may not rest on it.
  const store = typeof ledgerStore === 'string' && ledgerStore.length > 0 ? ledgerStore : null;
  const storeKey = store ?? 'unnamed-store';
  const committed = [], notes = [], knownResources = [];
  // A snapshot has to BE a snapshot. before = after = null, a non-object snapshot, or one
  // carrying none of the declared ledgers all read as "this fixture does not carry these
  // ledgers", so a truncated trace came out clean and invented three success-claim alerts
  // on top of it.
  const snapshotOf = side => (record(side) ? side : null);
  const before = snapshotOf(ev.before), after = snapshotOf(ev.after);
  const carries = snap => snap !== null && Object.keys(LEDGER_EFFECTS).some(key => Array.isArray(snap[key]));
  const completeAttempt = ev.complete !== false;
  const note = reason => { if (!notes.includes(reason)) notes.push(reason); };
  let ledgerReadable = true;
  if (before === null || after === null) { ledgerReadable = false; note('snapshot-missing'); }
  // A snapshot carrying NONE of the declared ledgers is a window that was never seen. Every
  // real fixture snapshot carries all six, so requiring it costs nothing on honest traffic
  // and closes the case where a truncated trace read as "this app has no ledgers".
  else if (!carries(before) || !carries(after)) { ledgerReadable = false; note('snapshot-carries-no-declared-ledger'); }
  if (!completeAttempt) { ledgerReadable = false; note('attempt-marked-incomplete'); }
  // Which effect names this window could have answered for: the ledger that would carry
  // the name was an array on both sides, so its absence from `committed` is a fact rather
  // than a gap in the reading. An adopter's own name, a differently-cased one, or a ledger
  // that only one snapshot carries are all outside this.
  const answerable = [];
  // What each window saw of each ledger, as fingerprints. The position key assumes every
  // window of a store sees one shared append-only order; left unchecked, a per-user filtered
  // view silently charged a refused request with another request's row. attributeEffects
  // reads these to check it.
  const ledgerWindows = {};
  for (const [key, name] of Object.entries(LEDGER_EFFECTS)) {
    const diff = ledgerDiff(before?.[key], after?.[key]);
    // A ledger neither snapshot carries is absent; one only a single side carries is not.
    const present = Array.isArray(before?.[key]) || Array.isArray(after?.[key]);
    if (present && !diff.readable) { ledgerReadable = false; note(`${key}: ${diff.reason}`); }
    // Even when the window is unreadable, the rows that ARE new still committed. Dropping
    // them made a real commit invisible again.
    // A row with no id still has content, and the fingerprint already in this file can key
    // it. Sending every id-less effect to unattributableByShape was wrong twice over: a row
    // only one window shows IS attributable, and the counter sat outside coverageGaps, so a
    // lone stale commit on an id-less ledger read as 0 alerts and 0 gaps.
    diff.added.forEach((row, n) => {
      const id = rowId(row);
      // Instance, ledger, position, content. Position is what tells two identical rows apart
      // without an exemption: these ledgers are append-only, so the Nth row of notes is a
      // specific row, and two identical metered reads in two requests sit at two positions.
      const content = id === null ? keyOf(store, key, diff.addedAt[n], row) : null;
      committed.push({ name, resource: id, contentKey: content, store, ledger: key });
    });
    if (Array.isArray(before?.[key]) && Array.isArray(after?.[key]) && diff.readable) answerable.push(name);
    // Only id-less ledgers need the check: rows with ids are placed by their id.
    if (present && diff.readable && [before?.[key], after?.[key]].some(rows => Array.isArray(rows) && rows.some(r => rowId(r) === null))) {
      const sideOf = rows => (Array.isArray(rows) ? rows.map(fingerprint) : null);
      ledgerWindows[key] = { store: storeKey, declared: store !== null,
        before: sideOf(before?.[key]), after: sideOf(after?.[key]) };
    }
    // Ids already in `before`: an idempotent retry naming one of these is not a false
    // success claim, it is a report about work that already landed.
    for (const row of Array.isArray(before?.[key]) ? before[key] : []) { const id = rowId(row); if (id !== null) knownResources.push(id); }
  }
  // Answerable only when both sides are there, no id is duplicated, no row went missing between
  // them, every row has an id and every status is one this source knows. The note names WHICH
  // of those failed. A missing side, a duplicated id and a lost row make the whole observation
  // unreadable (SUBSCRIPTIONS_HARD); the other two cost plan.cancel only.
  const subsPresent = Array.isArray(before?.subscriptions) || Array.isArray(after?.subscriptions);
  const subsWhy = subscriptionsUnreadable(before?.subscriptions, after?.subscriptions);
  if (subsWhy === null && subsPresent) answerable.push('plan.cancel');
  else if (subsPresent) {
    note(`subscriptions: ${subsWhy ?? 'ledger-missing'}`);
    if (SUBSCRIPTIONS_HARD.has(subsWhy ?? 'ledger-missing')) ledgerReadable = false;
  }
  for (const id of cancelled(before?.subscriptions, after?.subscriptions)) committed.push({ name: 'plan.cancel', resource: id, contentKey: null, store, ledger: 'subscriptions' });
  const events = Array.isArray(ev.events) ? ev.events : [];
  const auth = events.findLast(e => record(e) && e.type === 'authorization');
  // Corroboration only: what the app says it executed, never the trigger for an alert.
  const toolsReported = events.filter(e => record(e) && e.type === 'tool' && e.data?.executed === true).map(e => e.data.name).filter(n => typeof n === 'string');
  const output = record(ev.output) ? ev.output : null;
  return {
    principalId: ev.actor.principalId, operation: ev.operation, requestId: typeof ev.requestId === 'string' ? ev.requestId : null,
    ledgerReadable, ledgerNotes: notes, ledgerNote: notes[0] ?? null,
    // Object.hasOwn, so an operation named "constructor" cannot inherit a claimed effect.
    claimedEffect: Object.hasOwn(CLAIMED_EFFECT_BY_OPERATION, ev.operation) ? CLAIMED_EFFECT_BY_OPERATION[ev.operation] : null,
    authorized: record(auth?.data) && typeof auth.data.allowed === 'boolean' ? auth.data.allowed : null,
    authority: authorityOf(ev), committed, unattributed: [], unattributableByShape: [], knownResources, ledgerWindows,
    // The effect names whose absence this window can answer for, and where the ledger
    // readings came from. The snapshots are the application's own, which the report says.
    answerableEffects: [...new Set(answerable)], ledgerSource: 'target-snapshots',
    // No attribution exemption. An earlier version labelled this source 'per-request' to stop identical
    // id-less rows colliding, and the label was FALSE: the fixture snapshots the whole shared
    // state (src/fixture.mjs: one `state` object, `snapshot()` clones all of it), so the
    // collision check was skipped exactly where it was needed. Position in the append-only
    // ledger does that job instead, and the collision check now applies to every source.
    interleavable: interleavableOperations === null ? true : interleavableOperations.includes(ev.operation),
    claim: output ? { completed: output.completed, reply: output.reply, actionId: output.actionId, status: output.status } : null,
    identifiers: [typeof output?.actionId === 'string' ? output.actionId : null].filter(Boolean),
    toolsReported,
  };
}

// Recorded traffic: every attempt of every check in a saved run, in order. checkOf maps
// an observation back to the check it came from, so an alert can be attributed.
// The saved synthetic-fixture run declares the fixture's own pausable operation, so a clean
// run is not full of conservative gaps. A caller reading some other application passes its
// own list, or none at all.
export function observationsFromRun(run, { interleavableOperations = FIXTURE_INTERLEAVABLE_OPERATIONS } = {}) {
  if (!record(run) || !Array.isArray(run.results)) throw new TypeError('observationsFromRun needs a run record with results.');
  const out = [];
  let dropped = 0;
  for (const [index, row] of (Array.isArray(run.results) ? run.results : []).entries()) {
    // A null or non-object row is itself a gap, not something to step over silently.
    if (!record(row)) { dropped += 1; continue; }
    // THIS reader's statement about where it read, not the run's. A saved run builds a
    // fresh fixture per check, so each check's attempts are one store and a seeded id
    // repeated in the next check is a different row. The index comes from the run's own
    // ordering, which this reader walks; nothing in the trace chooses it.
    const ledgerStore = `run-check:${index}`;
    for (const attempt of Array.isArray(row.attempts) ? row.attempts : []) {
      const obs = observationFromAttempt(attempt, { interleavableOperations, ledgerStore });
      // An attempt whose evidence could not be read is a gap in coverage, not a quiet
      // nothing. Dropping these silently made a run where every attempt failed report
      // 0 observations and 0 alerts.
      if (obs) out.push({ ...obs, checkId: typeof row.id === 'string' ? row.id : null });
      else dropped += 1;
    }
  }
  const attributed = attributeEffects(out);
  return Object.assign(attributed, { dropped });
}

// Attribution fails in two different ways, and lumping them together makes one of them
// useless as a signal.
//
//  1. A COLLISION: two requests' windows both show the same IDENTIFIED row. One of them did
//     not commit it and a source diffing global snapshots cannot say which. That is a gap in
//     this run, so it goes into coverageGaps. On a repaired build this is what made a
//     correctly refused request raise two critical alerts and a high on its twin's row.
//  2. A SHAPE limit: the effect has NOTHING that places it, neither a row id nor a position
//     key, so this source could never attribute it in any run. An id-less row that does have
//     a position key is not this case; it is placed, unless its store's windows do not fit
//     one order, and then it is charged to no request as case 1. Charging it to a request brought that same false alarm back on id-less
//     ledgers; counting it as a gap would make coverageGaps non-zero on every clean run and
//     stop it meaning anything. It is counted and named on its own.
//
// The key is the effect NAME plus whatever places the row, because a row id is unique only
// within its own table: integer ids from two ledgers collided under an id-only key. What
// places a row is its id, or failing that its position, carried in contentKey. Only
// an effect with neither is unattributable by shape.
// A row id is unique inside the STORE that issued it, not across stores. Leaving the store
// out meant two checks of one run, each with its own fixture instance and the same seeded
// subscription id, collided: suite 2.3.0 added a second promise-cancel case and the
// honest build started reporting two coverage gaps on rows nothing was wrong with.
const effectKey = e => (typeof e.store === 'string' && e.store.length > 0 ? `${e.store}\u0001` : '') + rowKey(e);
// The row a key is about, with no store: what two effects must share to be one row.
const rowKey = e => `${e.name}\u0001${e.resource ?? e.contentKey ?? ''}`;
const identified = e => e.resource !== null || (typeof e.contentKey === 'string' && e.contentKey.length > 0);
// The one-order check. The position key is only meaningful if every window of a store sees
// one shared append-only order, so the windows have to fit together: sorted by length, each
// must be a prefix of the next, and two windows of the same length must be identical. A
// per-user filtered view breaks this (one window holds three rows the other never shows),
// and so does a reused position after a deletion. Where it breaks, a position places
// nothing, and the rows are charged to no request rather than to the wrong one.
export function oneSharedOrder(snapshots) {
  const rows = snapshots.filter(Array.isArray).map(s => s.slice());
  if (rows.some(s => s.some(fp => fp === null))) return false;
  rows.sort((a, b) => a.length - b.length);
  for (let i = 1; i < rows.length; i++) {
    const short = rows[i - 1], long = rows[i];
    for (let k = 0; k < short.length; k++) if (short[k] !== long[k]) return false;
  }
  return true;
}
// Every window's view of every id-less ledger, grouped by the store and ledger its rows
// would be keyed under.
const orderOf = observations => {
  const windows = new Map(), storesOf = new Map(), undeclared = new Set();
  for (const obs of observations) {
    for (const [ledger, w] of Object.entries(record(obs?.ledgerWindows) ? obs.ledgerWindows : {})) {
      const key = `${w.store}\u0001${ledger}`;
      if (!windows.has(key)) windows.set(key, []);
      windows.get(key).push(w.before, w.after);
      if (!storesOf.has(ledger)) storesOf.set(ledger, new Set());
      storesOf.get(ledger).add(w.store);
      if (!w.declared) undeclared.add(ledger);
    }
  }
  const broken = new Set([...windows.entries()].filter(([, snaps]) => !oneSharedOrder(snaps)).map(([key]) => key));
  // And the case one store's windows cannot show: SEVERAL stores over what may be one
  // ledger. Two instances of an app sharing a ledger key the same row under two stores, so
  // each window looks like the only one that saw it and a refused request is charged with
  // its twin's commit. A source that NAMES its stores is believed,
  // because saying they are different is then a statement the source made; a window with no
  // store named is not, so a ledger reached through more than one unnamed store is unplaceable.
  for (const [ledger, stores] of storesOf) {
    if (stores.size > 1 && undeclared.has(ledger)) for (const store of stores) broken.add(`${store}\u0001${ledger}`);
  }
  return broken;
};
// attributeEffects used to iterate obs.committed unguarded, so a VALID
// observation that omits it threw, and the live path's catch then observed the whole batch
// unattributed: a refused request was charged 2 critical and 1 high, and a lie went silent.
const effectsOf = obs => (Array.isArray(obs?.committed) ? obs.committed.filter(record) : []);
export function attributeEffects(observations) {
  const seen = new Map();
  // Stores whose windows do not fit one order, so a position key places nothing there.
  const broken = orderOf(observations);
  // A row id is unique inside the store that issued it, so the same id from the same store
  // in two windows is one row. Content identifies nothing here: an id-less row is placed by
  // its POSITION, and no source is exempt from the check, because the one source that
  // claimed an exemption was wrong about itself.
  // Grouped twice: by the store-qualified key, and by the name and id alone. Within a
  // name-and-id group, a member with no store named makes the WHOLE group one row, because
  // nothing says they are different ledgers.
  const byRow = new Map();
  for (const obs of observations) for (const e of effectsOf(obs)) if (identified(e)) {
    seen.set(effectKey(e), (seen.get(effectKey(e)) ?? 0) + 1);
    const row = rowKey(e);
    if (!byRow.has(row)) byRow.set(row, { total: 0, unnamed: 0 });
    const group = byRow.get(row);
    group.total += 1;
    if (typeof e.store !== 'string' || e.store.length === 0) group.unnamed += 1;
  }
  const collided = new Set([...seen.entries()].filter(([, n]) => n > 1).map(([key]) => key));
  const ambiguousRows = new Set([...byRow.entries()].filter(([, g]) => g.total > 1 && g.unnamed > 0).map(([row]) => row));
  const list = observations.map(obs => {
    const already = Array.isArray(obs.unattributed) ? obs.unattributed : [];
    const alreadyShape = Array.isArray(obs.unattributableByShape) ? obs.unattributableByShape : [];
    const mine = [], theirs = [], shapeless = [];
    for (const e of effectsOf(obs)) {
      // Identified and in one window only: this request's. Identified and in more than one:
      // a collision, charged to neither. Nothing to identify it by at all: a shape limit,
      // and even that is a coverage gap once access has changed.
      if (!identified(e)) shapeless.push(e);
      else if (collided.has(effectKey(e)) || ambiguousRows.has(rowKey(e))) theirs.push(e);
      // A position key from a store whose windows do not fit one order places nothing, so the
      // row is charged to no request, whether or not access changed. What it costs is stated
      // as a coverage gap, not hidden.
      else if (e.resource === null && broken.has(`${e.store ?? 'unnamed-store'}\u0001${e.ledger ?? ''}`)) theirs.push(e);
      else mine.push(e);
    }
    if (!theirs.length && !shapeless.length) return obs;
    // What the rebuild filtered out of the effects list, so a caller can count it.
    const dropped = (Array.isArray(obs.committed) ? obs.committed.length : 0) - (mine.length + theirs.length + shapeless.length);
    return { ...obs, committed: mine, unattributed: [...already, ...theirs], unattributableByShape: [...alreadyShape, ...shapeless],
      ...(dropped > 0 ? { droppedEffects: dropped } : {}) };
  });
  return Object.assign(list, { collidedEffects: [...collided] });
}
// What a rebuild says it dropped from one observation. attributeEffects only sets a whole number
// above zero; an observation can carry the field itself, and a negative one used to be added,
// which lowered the invalid count and cancelled real gaps. So only a count above zero is counted.
export const droppedEffectsOf = obs => (Number.isInteger(obs?.droppedEffects) && obs.droppedEffects > 0 ? obs.droppedEffects : 0);

// Live traffic. read() is the caller's local source; it is called ticks times and
// everything it returns is observed. The monitor is handed no transport, so a source that
// reaches off the machine would have to be written by the caller on purpose. What read()
// could not deliver is counted and handed to the monitor through noteSource, so a poll that
// failed every tick cannot read as a quiet clean run.
export async function pollSource({ monitor, read, ticks = 1, intervalMs = 50 }) {
  if (!record(monitor) || typeof monitor.observe !== 'function') throw new TypeError('pollSource needs a monitor.');
  if (typeof read !== 'function') throw new TypeError('pollSource needs a read() returning observations.');
  if (!Number.isInteger(ticks) || ticks < 1 || ticks > 1000) throw new TypeError('ticks must be 1 to 1000.');
  if (!Number.isInteger(intervalMs) || intervalMs < 0 || intervalMs > 60000) throw new TypeError('intervalMs must be 0 to 60000.');
  const raised = [];
  // Counted, not swallowed. A read() that threw and a batch entry the monitor refused are
  // both gaps in what was watched; reporting neither let a source that failed every tick
  // read as a quiet clean run.
  let readErrors = 0, invalid = 0, batches = 0;
  for (let tick = 0; tick < ticks; tick++) {
    if (tick > 0 && intervalMs > 0) await new Promise(done => setTimeout(done, intervalMs).unref?.());
    let batch;
    try { batch = await read(tick); batches += 1; } catch { readErrors += 1; continue; }
    // One malformed observation used to end the whole poll; now it is counted and the
    // rest of the batch is still watched.
    const rows = Array.isArray(batch) ? batch.filter(record) : [];
    const malformed = (Array.isArray(batch) ? batch.length : 0) - rows.length;
    // And the malformed ENTRIES inside an observation's own effects list. attributeEffects
    // filters them out, so whether one was counted depended on whether that observation also
    // collided and was therefore rebuilt: alone it reached the monitor and counted 1, beside a
    // collision it vanished with no count at all.
    invalid += malformed;
    // Attributed across the windows this batch delivered together. A row two of them share
    // is charged to neither, exactly as on a saved run; windows that arrive in separate
    // ticks are never compared, and the limitations say so.
    let attributed = rows;
    // A failure to attribute is not a batch of unattributed observations: charging the
    // batch to nobody invented verdicts both ways. It is counted invalid and skipped.
    try { attributed = attributeEffects(rows); } catch { invalid += rows.length; continue; }
    // A malformed entry inside an observation's own effects list. Where the observation is
    // returned untouched the monitor refuses it and counts it; where attributeEffects REBUILDS
    // it the entry is filtered away and the monitor never sees it, so whether it cost anything
    // depended on whether that observation happened to collide. The
    // rebuild reports what it dropped, and that is what is counted here.
    invalid += attributed.reduce((n, obs) => n + droppedEffectsOf(obs), 0);
    for (const obs of attributed) {
      try { raised.push(...monitor.observe(obs)); } catch { invalid += 1; }
    }
  }
  if (typeof monitor.noteSource === 'function') monitor.noteSource({ readErrors, invalid, batches, ticks });
  return Object.assign(raised, { readErrors, invalid, batches, ticks });
}
