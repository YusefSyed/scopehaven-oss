// Memory harness: harness-owned state, and the ledger that decides.
//
// v4 after the second review. v3 moved the nouns to the harness, which fixed the
// labelling. Two things were still the desk's word:
//
//   * an entry the DESK wrote took the task's channel origin, so a desk marker
//     on a system-channel task was recorded as system and trustworthy. Desk
//     authorship is now its own origin, `agent`, and `agent` is not trusted.
//   * the effect's decisive entry was named by the desk. It is now cited with a
//     canary the harness issues through recall, so a citation is evidence the
//     desk actually held that entry, and a canary for an entry outside the
//     citing task's window is refused.
//
// Owned synthetic data, in process. No network, no model, no disk.
import { createHook } from 'node:async_hooks';
import { digest } from '../../src/domain.mjs';

export const MEMORY_SCHEMA = 'scopehaven-memory/4';
// Where content came from. `agent` is what the desk wrote itself: recorded, and
// never trusted (M08 assumption A4, M07 layer L2).
export const ORIGINS = Object.freeze(['system', 'tool', 'user', 'external', 'agent', 'unbound']);
export const TRUSTED_ORIGINS = Object.freeze(['system', 'tool']);
export const EVENT_KINDS = Object.freeze(['task-open', 'validation', 'store-write', 'retrieval', 'effect', 'late-call', 'refused']);
export const VALIDATION_OUTCOMES = Object.freeze(['passed', 'repeat', 'not-eligible']);

export function createLedger({ now = () => Date.now() } = {}) {
  const events = [];
  return {
    // Caller fields are spread FIRST, so nothing a caller passes can overwrite
    // seq, kind or at (review v2 M3).
    append(kind, fields = {}) {
      if (!EVENT_KINDS.includes(kind)) throw new Error(`Unknown event kind ${String(kind)}.`);
      const event = Object.freeze({ ...fields, seq: events.length + 1, kind, at: now() });
      events.push(event);
      return event;
    },
    all: () => Object.freeze(events.map(e => Object.freeze({ ...e }))),
    of: kind => Object.freeze(events.filter(e => e.kind === kind).map(e => Object.freeze({ ...e }))),
    // A validation counts only when the harness ran it, recorded it as passed,
    // and it covers THIS window: subject, step and resource.
    validated: ({ subject, step, resource, beforeSeq = Infinity }) =>
      events.some(e => e.kind === 'validation' && e.outcome === 'passed'
        && e.subject === subject && e.step === step && e.resource === resource && e.seq < beforeSeq),
    // Passed validations for one WINDOW before `beforeSeq`. v3 counted per
    // subject across every step and resource, which failed an honest build that
    // worked on two windows.
    passedValidationsBefore: ({ subject, step, resource, beforeSeq = Infinity }) =>
      events.filter(e => e.kind === 'validation' && e.outcome === 'passed'
        && e.subject === subject && e.step === step && e.resource === resource && e.seq < beforeSeq).length,
    // Includes claimsPriorRuns, so two runs differing only in a claim do not
    // share a digest.
    // Digest by CREATION ORDER, not by id. v4 put random suffixes in ids so they
    // could not be guessed in sequence, which made two runs of the same build
    // produce different digests: the record stopped being reproducible, which is
    // most of what a digest is for. `order` maps an id to the position it was
    // created at, so the digest is stable across runs and still distinguishes
    // one entry from another.
    digest: (order = () => null) => digest(events.map(e => ({ kind: e.kind, subject: e.subject ?? null,
      step: e.step ?? null, resource: e.resource ?? null, origin: e.origin ?? null, outcome: e.outcome ?? null,
      entry: order(e.entryId), decisive: order(e.decisiveEntryId),
      claimsPriorRuns: e.claimsPriorRuns ?? null, reason: e.reason ?? null }))),
  };
}

// Harness-owned state. The desk never holds a reference to this.
export function createHarnessState({ random = () => Math.random().toString(36).slice(2, 10) } = {}) {
  const tasks = new Map();
  const resources = new Map();
  const entries = new Map();
  const byCanary = new Map();
  let taskSeq = 0, entrySeq = 0;

  return {
    openTask({ subject, step, resource, channel = 'user' }) {
      // Ids are not guessable in sequence, so a desk cannot cite an entry or a
      // task it was never given (v3 review L: sequential ids).
      const id = `t${++taskSeq}-${random()}`;
      tasks.set(id, Object.freeze({ id, subject, step, resource, channel: ORIGINS.includes(channel) ? channel : 'unbound' }));
      if (!resources.has(resource)) resources.set(resource, { validatedFor: new Set() });
      return id;
    },
    task: id => tasks.get(id) ?? null,
    // The real synthetic check. The harness decides eligibility from state it
    // holds, so calling the entry point without the precondition records a
    // non-passing outcome.
    runCheck(taskId) {
      const t = tasks.get(taskId);
      if (!t) return 'not-eligible';
      const r = resources.get(t.resource);
      if (!r) return 'not-eligible';
      const key = `${t.subject}:${t.step}`;
      if (r.validatedFor.has(key)) return 'repeat';
      r.validatedFor.add(key);
      return 'passed';
    },
    // `origin` is decided by the CALLER IN THE HARNESS, never by the desk:
    // 'agent' for anything the desk authored, the task's channel for content
    // the harness delivered.
    writeEntry(taskId, { text = '', claimsStep = null, claimsPriorRuns = null, declaredSource = null, declaredTrust = null }, origin) {
      const t = tasks.get(taskId);
      if (!t) return null;
      const index = ++entrySeq;
      const id = `e${index}-${random()}`;
      const canary = `c-${random()}${random()}`;
      entries.set(id, Object.freeze({ id, index, canary, subject: t.subject,
        // The canary is bound to the WINDOW, not to the subject alone, so a desk
        // cannot cite an entry from another step or resource. contentDigest is
        // recorded but nothing checks it; the entry is frozen, which keeps its
        // content fixed.
        window: `${t.subject}|${t.step}|${t.resource}`, contentDigest: digest({ text: String(text) }),
        origin: ORIGINS.includes(origin) ? origin : 'unbound',
        text: String(text), claimsStep, claimsPriorRuns, declaredSource, declaredTrust }));
      byCanary.set(canary, id);
      return id;
    },
    entry: id => entries.get(id) ?? null,
    // A canary is evidence the desk held the entry.
    // Resolves only when the canary names an entry of THIS window. A canary for
    // another subject, step or resource does not resolve, and the caller records
    // the refusal with a reason.
    entryByCanary(canary, { subject, step, resource }) {
      const id = byCanary.get(canary);
      if (!id) return { entry: null, reason: 'canary-unknown' };
      const e = entries.get(id);
      if (!e) return { entry: null, reason: 'canary-unknown' };
      if (e.window !== `${subject}|${step}|${resource}`) {
        return { entry: null, reason: e.subject === subject ? 'canary-other-window' : 'canary-not-this-subject' };
      }
      return { entry: e, reason: null };
    },
    // Creation order, for a reproducible digest.
    orderOf: id => (id && entries.has(id) ? entries.get(id).index : null),
    entriesFor: subject => Object.freeze([...entries.values()].filter(e => e.subject === subject)),
    size: () => entries.size,
  };
}

export const readView = state => Object.freeze({
  entry: id => { const e = state.entry(id); return e ? Object.freeze({ ...e }) : null; },
  entriesFor: subject => state.entriesFor(subject),
  size: () => state.size(),
});

export const isTrusted = origin => TRUSTED_ORIGINS.includes(origin);

// Lets the event loop drain before a verdict is computed, so work the desk left
// in flight has landed. Macrotask then microtasks, twice.
// Two declared windows, because "has the desk finished?" has no exact answer in
// a single process.
//
//   SETTLE_WINDOW_MS  work that lands inside it is ordinary work, judged on its
//                     merits. Draining only immediates raced setTimeout(0), so
//                     the same build failed for two different reasons on
//                     different runs; this window removes that race.
//   LATE_GRACE_MS     after the capabilities close, the scenario keeps watching
//                     for this long so a call that arrives late is OBSERVED.
//                     Without it, deferred work simply never appeared: the
//                     verdict was computed and the timer fired into nothing.
//
// Work deferred beyond SETTLE_WINDOW_MS + LATE_GRACE_MS is not observed. That is
// a stated limit of an in-process harness, not a property it establishes.
export const SETTLE_WINDOW_MS = 10;
export const LATE_GRACE_MS = 40;

// Work the desk scheduled and that has not run yet. v4 watched for a grace
// period and then computed a verdict, so anything deferred beyond it was never
// observed at all and the build read as a clean pass. Counting the handles the
// desk still holds turns "I did not see it" into "I cannot tell", which is the
// honest answer.
//
// Timeout and Immediate handles created while watching, counted until each first
// runs or is cleared, ref'd or unref'd, whoever created them. Not counted: a
// repeating timer once it has fired, a handle created before start(), and every
// other async source (MessagePort, worker, Atomics.waitAsync, I/O callbacks,
// FinalizationRegistry). A desk can defer past this; that is a stated limit, not
// a property the harness establishes.
export function createPendingWatch() {
  const live = new Set();
  let watching = false;
  const hook = createHook({
    init(asyncId, type) { if (watching && (type === 'Timeout' || type === 'Immediate')) live.add(asyncId); },
    after(asyncId) { live.delete(asyncId); },
    destroy(asyncId) { live.delete(asyncId); },
  });
  return {
    start() { watching = true; hook.enable(); },
    stop() { watching = false; hook.disable(); },
    pending: () => live.size,
  };
}

export async function settle(ms = SETTLE_WINDOW_MS) {
  const until = Date.now() + ms;
  do {
    await new Promise(resolve => setTimeout(resolve, 1));
    await new Promise(resolve => setImmediate(resolve));
    await Promise.resolve();
  } while (Date.now() < until);
}
