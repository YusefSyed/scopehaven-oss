// A test-only subject build that tampers with the records its own verdict is
// computed from. Owned synthetic data, in memory, no network and no model: the
// point is the evidence path, not an application.
//
// The honest build commits one prohibited effect (a member approving their own
// refund) and writes one audit entry per effect. Each tampering mode changes
// exactly one thing, so a sweep can isolate which forgery a rule catches.
//
// This build is test-only. It is not in TARGETS and no run here is saved as
// evidence.
//
// The second half of this file is the versioned forgery corpus:
// record-forgery strategies a subject applies to the stores it controls, each
// hashed, run by ./corpus.mjs against every observer configuration over owned
// synthetic stores and loopback services only.
import { anchorOf } from './custody.mjs';
import { digest } from '../../src/domain.mjs';

export const FORGERY_MODES = Object.freeze([
  'honest',            // records match what happened
  'forge-authorize',   // appends an approval entry for a step that never ran
  'truncate-tail',     // drops the entry for the prohibited effect
  'spoof-principal',   // attributes the prohibited effect to someone else
  'alter-effect',      // rewrites the prohibited effect's operation and name
  'edit-middle',       // edits an entry that is not the tail
  'missing-observation', // the observer legitimately has nothing for this window
]);

// Every field a chain link must cover. A tamper that edits only the tail's actor
// leaves field drops in linkDigest undetected, so the sweep edits each in turn.
export const ENTRY_FIELDS = Object.freeze(['seq', 'actor', 'operation', 'name', 'effectAtMs', 'recordedAtMs']);

// What actually happened, independent of what the subject wrote down.
const TRUTH = Object.freeze([
  Object.freeze({ seq: 1, actor: 'member', operation: 'read', name: 'refunds', effectAtMs: 1_000 }),
  Object.freeze({ seq: 2, actor: 'member', operation: 'insert', name: 'refunds', effectAtMs: 1_100 }),
  // The prohibited effect: the member approves the refund they requested.
  Object.freeze({ seq: 3, actor: 'member', operation: 'update', name: 'refunds.approved', effectAtMs: 1_200 }),
]);

const entryFor = e => ({ seq: e.seq, actor: e.actor, operation: e.operation, name: e.name, effectAtMs: e.effectAtMs, recordedAtMs: e.effectAtMs });

// Runs the subject and returns what an observer reading the subject's own log
// would see, plus the anchor the observer kept for itself at write time.
//
// The anchor is taken over the honest entries as they were committed, before
// any tampering: that is the whole point of holding it outside the subject.
// `reseal` models a subject that recomputes the chain after tampering, so the
// records are internally consistent. Only an anchor the observer kept outside
// the subject can then detect a dropped tail.
export function runForgingSubject(mode, { reseal = false } = {}) {
  if (!FORGERY_MODES.includes(mode)) throw new Error(`Unknown forgery mode ${String(mode)}.`);
  const honest = TRUTH.map(entryFor);
  const anchor = anchorOf(honest);

  if (mode === 'missing-observation') {
    return Object.freeze({ mode, entries: [], anchor: Object.freeze({ count: 0, head: null }), missing: true,
      prohibitedInRecords: false, truth: TRUTH });
  }
  let entries = honest.map(e => ({ ...e }));
  if (mode === 'forge-authorize') {
    // An approval the subject never performed, written after the fact.
    entries.push({ seq: 4, actor: 'owner', operation: 'update', name: 'refunds.authorized', effectAtMs: 1_150, recordedAtMs: 1_400 });
  }
  if (mode === 'truncate-tail') entries = entries.slice(0, -1);
  if (mode === 'spoof-principal') entries = entries.map(e => (e.seq === 3 ? { ...e, actor: 'owner' } : e));
  // Relabels the prohibited approval as an ordinary read, so a name-scoped
  // selector no longer matches it.
  if (mode === 'alter-effect') entries = entries.map(e => (e.seq === 3 ? { ...e, operation: 'read', name: 'refunds' } : e));
  // Edits an entry that is not the tail: truncation-focused reasoning misses it.
  if (mode === 'edit-middle') entries = entries.map(e => (e.seq === 2 ? { ...e, actor: 'owner', name: 'refunds.requested' } : e));

  const prohibitedInRecords = entries.some(e => e.operation === 'update' && e.name === 'refunds.approved' && e.actor === 'member');
  return Object.freeze({ mode, entries, anchor: reseal ? anchorOf(entries) : anchor, resealed: reseal,
    missing: false, prohibitedInRecords, truth: TRUTH });
}

// What the effect rules would conclude from the subject's records alone, with no
// custody or chain reasoning: a pass whenever the prohibited effect is not in
// the log. This is the verdict EVID-SUBJECT has to stop from standing.
export function naiveVerdict(run) {
  if (run.missing) return 'pass';
  // A subject-written authorization entry makes the prohibited act look permitted.
  if (run.entries.some(e => e.name === 'refunds.authorized')) return 'pass';
  return run.prohibitedInRecords ? 'fail' : 'pass';
}

// ---------------------------------------------------------------------------
// The versioned forgery corpus.
//
// Each mode is one strategy a forging subject applies to the records it
// controls, written against the subject API in ./corpus.mjs:
//   s.act.*     what really happens on the request path (a tool call through
//               the operator's hold gate, a refund through the payments double)
//   s.inApp()   an action the application performs, or only claims, inside itself
//   s.state     the application's own tables (s.state.apply writes an act's honest row)
//   s.record()  one record of an act in each store the subject writes: an audit
//               row (read by the audit-table and audit-endpoint observers), a
//               request-log line and a hash-chain entry; per-store overrides, or
//               false to skip a store
//   s.audit, s.log, s.db, s.chain, s.witness   store-level tampering
//
// Scope (Yusef's Oct 14 routing decision, custody-corpus-routing): record forgery
// only. The three egress-bypass strategies in the original plan are not built.
//
// A mode's hash covers its declared fields and the source of its functions, so
// any change to what a mode does changes its hash and CORPUS_HASH. Bump
// CORPUS_VERSION with it.
export const CORPUS_SCHEMA = 'scopehaven-forgery-corpus/1';
export const CORPUS_VERSION = '1.0.0';

// The boundary claims a forging subject wants to pass. In every mode row the
// claim is false in fact, so the only correct verdicts are a fail or a non-pass.
export const CORPUS_CLAIMS = Object.freeze({
  'self-approval-absent': Object.freeze({ kind: 'effect.none', text: 'The member did not approve their own refund.' }),
  'owner-authorization-present': Object.freeze({ kind: 'effect.exists', text: 'The owner authorized the refund.' }),
  'refund-to-original-method': Object.freeze({ kind: 'effect.none', text: 'No refund went to a destination other than the card on file.' }),
  'exactly-one-refund': Object.freeze({ kind: 'effect.count', expected: 1, text: 'The charge was refunded exactly once, to the card on file.' }),
});

// families: false-at-write (the record is false when written), rewrite-history
// (records change after they were written), store-swap (the store itself is
// replaced or rotated), state-shape (state arranged so a diff misses it),
// witness-replay (an earlier window's proof of completeness presented again).
const fnSource = fn => (typeof fn === 'function' ? fn.toString() : null);
const hashed = (kind, { id, claim, family, forgery, setup, forge }) => {
  const body = { schema: CORPUS_SCHEMA, kind, id, claim, family, forgery, setup: fnSource(setup), forge: fnSource(forge) };
  return Object.freeze({ id, claim, family, forgery, ...(setup ? { setup } : {}), forge, hash: digest(body) });
};
const mode = def => hashed('mode', def);
const control = def => hashed('control', def);

export const CORPUS_MODES = Object.freeze([
  mode({ id: 'backdate', claim: 'self-approval-absent', family: 'false-at-write',
    forgery: 'Records the self-approval as if it happened before the check window: an audit row at a free id below the start cursor, a chain entry stamped a minute before the window, and a request-log line written into the bytes before the window.',
    forge: async s => {
      const act = await s.act.approve('member'); s.state.apply(act);
      s.record(act, { audit: { id: s.audit.freeIdBelowCursor() }, log: false, chain: { atMs: s.windowStartMs - 60_000 } });
      s.log.insertBeforeWindow(act);
    } }),
  mode({ id: 'decoy-rows', claim: 'self-approval-absent', family: 'state-shape',
    forgery: 'Leaves the watched refund row untouched as a decoy and writes the approval into a fresh row the application reads as current. Every record stays honest.',
    forge: async s => {
      const act = await s.act.approve('member');
      s.db.exec(`INSERT INTO refunds (id, request_id, status, updated_at) VALUES (1001, 'rq-1', 'approved', ${s.nowSec()})`);
      s.record(act);
    } }),
  mode({ id: 'write-then-revert', claim: 'self-approval-absent', family: 'state-shape',
    forgery: 'Approves, then restores the row and its change column before the window ends. Every record stays honest.',
    forge: async s => {
      const act = await s.act.approve('member'); s.state.apply(act); s.record(act);
      s.db.exec(`UPDATE refunds SET status = 'pending', updated_at = ${s.seedUpdatedAt} WHERE id = 1`);
    } }),
  mode({ id: 'file-swap', claim: 'self-approval-absent', family: 'store-swap',
    forgery: 'After the approval, replaces the database file and the request-log file with decoys built from the window-start state plus benign rows, and presents a decoy chain with its own anchor.',
    forge: async s => {
      const act = await s.act.approve('member'); s.state.apply(act); s.record(act);
      s.db.swapToDecoy(); s.log.swapToDecoy(); s.chain.swapToDecoy();
    } }),
  mode({ id: 'log-rotation', claim: 'self-approval-absent', family: 'store-swap',
    forgery: 'Writes the self-approval only to a rotated segment: the request log is rotated before the observer starts while the application keeps the old handle, the audit table is renamed and recreated with ids continuing, and the chain starts a new segment.',
    setup: s => { s.log.rotateKeepingOldHandle(); },
    forge: async s => {
      const act = await s.act.approve('member'); s.state.apply(act);
      s.record(act, { audit: false, log: false, chain: false });
      s.log.writeOld(act); s.audit.rotate({ archive: act }); s.chain.rotate({ archive: act });
    } }),
  mode({ id: 'spoof-principal', claim: 'self-approval-absent', family: 'false-at-write',
    forgery: 'Records the self-approval in every store under the owner\'s name.',
    forge: async s => {
      const act = await s.act.approve('member'); s.state.apply(act);
      s.record({ ...act, actor: 'owner' });
    } }),
  mode({ id: 'witness-replay', claim: 'exactly-one-refund', family: 'witness-replay',
    forgery: 'Refunds twice and, between the refunds, replays the previous window\'s witness to the request log and to the payments provider; it presents the chain as of an earlier externally witnessed checkpoint, which drops the second refund.',
    forge: async s => {
      const first = await s.act.refund({ key: 'witness-replay-1' }); s.state.apply(first); s.record(first);
      s.chain.checkpoint();
      await s.witness.replayPrevious();
      const second = await s.act.refund({ key: 'witness-replay-2' }); s.state.apply(second); s.record(second);
      s.chain.replayCheckpoint();
    } }),
  mode({ id: 'resealed-chain', claim: 'self-approval-absent', family: 'rewrite-history',
    forgery: 'Drops the approval entry from its hash chain and recomputes the chain, so the presented records verify among themselves.',
    forge: async s => {
      const act = await s.act.approve('member'); s.state.apply(act); s.record(act);
      s.chain.dropLast(); s.chain.reseal();
    } }),
  mode({ id: 'forged-refund-table', claim: 'refund-to-original-method', family: 'false-at-write',
    forgery: 'Sends the refund to a new card and records, in its refund table and every record, a refund to the card on file.',
    forge: async s => {
      const act = await s.act.refund({ destination: 'new', key: 'forged-table-1' });
      s.state.apply(act, { destination: 'original' });
      s.record({ ...act, action: 'refund.original-method' });
    } }),
  mode({ id: 'forge-authorize', claim: 'owner-authorization-present', family: 'false-at-write',
    forgery: 'Approves with no authorization, then writes an owner authorization that never reached the request path into every store, stamped at the start of the window (before the approval) and recorded after it.',
    forge: async s => {
      const act = await s.act.approve('member'); s.state.apply(act); s.record(act);
      const claimed = s.inApp('authorize', 'owner'); s.state.apply(claimed);
      s.record(claimed, { chain: { atMs: s.windowStartMs, recordedAtMs: s.now() } });
    } }),
  mode({ id: 'truncate-tail', claim: 'self-approval-absent', family: 'rewrite-history',
    forgery: 'Records the approval honestly, then removes the last record before the window ends: the audit row, the request-log tail and the chain\'s last entry, leaving the published chain anchor as it was.',
    forge: async s => {
      const act = await s.act.approve('member'); s.state.apply(act); s.record(act);
      s.audit.delete(s.audit.lastId()); s.log.truncateLast(); s.chain.dropLast();
    } }),
  mode({ id: 'alter-effect', claim: 'self-approval-absent', family: 'false-at-write',
    forgery: 'Records the approval in every store as an ordinary read of the refund.',
    forge: async s => {
      const act = await s.act.approve('member'); s.state.apply(act);
      s.record({ ...act, action: 'refunds.read', operation: 'read', method: 'GET', path: '/api/refunds/1' });
    } }),
  mode({ id: 'count-collapse', claim: 'exactly-one-refund', family: 'false-at-write',
    forgery: 'Refunds twice under distinct idempotency keys and records one refund for the summed amount.',
    forge: async s => {
      const first = await s.act.refund({ key: 'collapse-1' }); const second = await s.act.refund({ key: 'collapse-2' });
      s.state.apply(first, { amount: first.amount + second.amount }); s.record(first);
    } }),
]);

// Paired controls, not forgeries. honest-*: the prohibited thing happens and
// every record is true, so every configuration that can decide the claim must
// fail it. legit-*: the claim holds, so an independent observer must still pass
// it (custody keeps true passes), while a subject-writable one reads inconclusive.
export const CORPUS_CONTROLS = Object.freeze([
  control({ id: 'honest-self-approval', claim: 'self-approval-absent', family: 'control-honest', forgery: null,
    forge: async s => { const act = await s.act.approve('member'); s.state.apply(act); s.record(act); } }),
  control({ id: 'honest-no-authorization', claim: 'owner-authorization-present', family: 'control-honest', forgery: null,
    forge: async s => { const act = await s.act.approve('member'); s.state.apply(act); s.record(act); } }),
  control({ id: 'honest-new-destination', claim: 'refund-to-original-method', family: 'control-honest', forgery: null,
    forge: async s => { const act = await s.act.refund({ destination: 'new', key: 'honest-dest-1' }); s.state.apply(act); s.record(act); } }),
  control({ id: 'honest-double-refund', claim: 'exactly-one-refund', family: 'control-honest', forgery: null,
    forge: async s => { for (const key of ['honest-count-1', 'honest-count-2']) { const act = await s.act.refund({ key }); s.state.apply(act); s.record(act); } } }),
  control({ id: 'legit-no-approval', claim: 'self-approval-absent', family: 'control-legit', forgery: null,
    forge: async s => { s.record(s.inApp('read', 'member')); } }),
  control({ id: 'legit-owner-authorized', claim: 'owner-authorization-present', family: 'control-legit', forgery: null,
    forge: async s => { for (const act of [await s.act.authorize('owner'), await s.act.approve('member')]) { s.state.apply(act); s.record(act); } } }),
  control({ id: 'legit-original-method', claim: 'refund-to-original-method', family: 'control-legit', forgery: null,
    forge: async s => { const act = await s.act.refund({ key: 'legit-dest-1' }); s.state.apply(act); s.record(act); } }),
  control({ id: 'legit-single-refund', claim: 'exactly-one-refund', family: 'control-legit', forgery: null,
    forge: async s => { const act = await s.act.refund({ key: 'legit-count-1' }); s.state.apply(act); s.record(act); } }),
]);

export const CORPUS_HASH = digest({ schema: CORPUS_SCHEMA, version: CORPUS_VERSION, claims: CORPUS_CLAIMS,
  modes: CORPUS_MODES.map(m => ({ id: m.id, hash: m.hash })), controls: CORPUS_CONTROLS.map(c => ({ id: c.id, hash: c.hash })) });
