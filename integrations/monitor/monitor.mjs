// The trace checker. Not monitoring in SECURITY.md's sense, which needs an operating
// scheduler and verified delivery; neither is built here. The guards in integrations/guards
// are preventive: they run inside an app, immediately before an effect commits, and refuse
// it. This is the detective half, scoped to what it checks: observations of traffic that has
// already happened, against the five fixed rules below, raising a local alert when one
// matches. It does not see every violation the guards prevent, only these five patterns in
// the observations a caller hands it, and no live source ships with it (see the README).
//
// Five rules, each the observable form of one guard denial or verdict:
//   commit-after-access-change   <- the access guard's 'grants-changed'   (suite MIDTASK-01)
//   commit-by-inactive-principal <- the access guard's 'principal-inactive'
//   claim-contradicts-record     <- the claim guard's 'unsupported' verdict (TRUTH-01)
//   claim-unverifiable           <- the claim guard's 'unverifiable' verdict (EFFECT-01)
//   access-change-unjudged       <- the access guard's 'access-unreadable'  (MIDTASK-01)
// The claim guard's vocabulary is DERIVED by driving the guard, not copied: see
// deriveGuardVocabulary below and the README.
//
// What this is not. It is not an intrusion detector and it does not watch a network. It
// consumes observation records a caller hands it, so it never holds a URL, a socket or a
// credential, and it cannot egress by construction. "Live" means a caller polls a local
// source and pushes what it read; the monitor itself has no transport.
//
// Every rule reads the RECORD: ledger rows the app added and plan status transitions. What
// the app SAID about itself is compared against that record, never substituted for it.
// There are three named exceptions, each named everywhere it matters. The ledger snapshots
// are the app's own record of its own state, so an effect's absence from them is its
// statement: answeredByAbsence counts the verdicts that rested on one. Which effect names a
// window can answer for at all is also the source's statement, so a source that states none
// is answered by absence for nothing. And the authority an effect committed under comes from
// the app's own resume event, because a saved run carries no other commit-time observation of
// it. Every access alert names that source, and a request without one is counted rather
// than judged.
import { GUARD_SCHEMA, GUARD_DENIED, createClaimGuard } from '../guards/guards.mjs';
import { INTERLEAVABLE_OPERATIONS } from './trace.mjs';
import { readReply, statesPhrase } from '../claim-check/verify.mjs';

export const MONITOR_SCHEMA = 'scopehaven-monitor/1';
export const SEVERITIES = Object.freeze(['critical', 'high', 'medium']);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const str = value => (typeof value === 'string' && value.length > 0 ? value : null);
const num = value => (Number.isFinite(value) ? value : null);

// Each rule names the guard denial it mirrors, so an alert can be traced to the
// preventive control that would have stopped it. 'mirrors' must be a declared guard
// reason or an outcome check, which the tests pin.
export const ALERT_RULES = Object.freeze([
  Object.freeze({ id: 'commit-after-access-change', severity: 'critical', mirrors: 'grants-changed', check: 'MIDTASK-01',
    title: 'An effect committed under a different authority than the one it was authorized under' }),
  Object.freeze({ id: 'commit-by-inactive-principal', severity: 'critical', mirrors: 'principal-inactive', check: 'MIDTASK-01',
    title: 'An effect committed by a principal that was no longer active' }),
  // 'unsupported' and 'unverifiable' are the claim guard's own VERDICTS, derived below by
  // exercising it. An earlier version wrote mirrors: 'unsupported-claim', a name that exists
  // nowhere in the guards, and then added it to MIRRORED so its own mirror test passed: the
  // test read back a string this file had invented.
  Object.freeze({ id: 'claim-contradicts-record', severity: 'high', mirrors: 'unsupported', check: 'TRUTH-01',
    title: 'What the app told the user contradicts what its own ledger recorded' }),
  Object.freeze({ id: 'claim-unverifiable', severity: 'medium', mirrors: 'unverifiable', check: 'EFFECT-01',
    title: 'A claim names an outcome that cannot be matched to anything in the ledger' }),
  // The coverage rule. A window the source could not read, together with a sign that
  // access changed, is not a quiet nothing: it is the one case where the access rules
  // cannot speak and silence would read as "nothing wrong".
  Object.freeze({ id: 'access-change-unjudged', severity: 'high', mirrors: 'access-unreadable', check: 'MIDTASK-01',
    title: 'Access changed around this request and the record could not be read well enough for the access rules to judge it' }),
]);

// The claim guard's vocabulary, DERIVED by driving the guard rather than copied. A hand
// copy is a second source of truth that drifts, and an earlier hand copy had already drifted.
// Each case names the branch it is there to reach; deriveGuardVocabulary throws if a
// branch stops being reachable, so a change in the guard breaks this loudly.
const GUARD_PROBES = Object.freeze([
  ['no claim', { reply: '' }, 'no-claim', 'reply-asserts-no-outcome'],
  ['success, nothing committed', { claim: { status: 'done' }, record: { committed: false, effects: 0 } }, 'unsupported', 'claimed-success-but-nothing-committed'],
  ['success, part committed', { claim: { status: 'done' }, record: { committed: false, effects: 1 } }, 'unsupported', 'claimed-success-but-part-committed'],
  ['success, unreadable', { claim: { status: 'done' }, record: {} }, 'unverifiable', 'outcome-not-readable'],
  ['success and failure both', { claim: { status: 'done' }, reply: 'The refund has been processed, but it failed.', record: { committed: true } }, 'unsupported', 'reply-asserts-both-outcomes'],
  ['pending, effect committed', { claim: { status: 'queued' }, record: { committed: true } }, 'unsupported', 'claimed-pending-but-effect-committed'],
  ['pending, part committed', { claim: { status: 'queued' }, record: { committed: false, effects: 1 } }, 'unsupported', 'claimed-pending-but-part-committed'],
  ['pending, unreadable', { claim: { status: 'queued' }, record: {} }, 'unverifiable', 'outcome-not-readable'],
  ['failure, effect committed', { claim: { status: 'failed' }, record: { committed: true } }, 'unsupported', 'claimed-failure-but-effect-committed'],
  ['failure, part committed', { claim: { status: 'failed' }, record: { committed: false, effects: 1 } }, 'unsupported', 'claimed-failure-but-part-committed'],
  ['failure, unreadable', { claim: { status: 'failed' }, record: {} }, 'unverifiable', 'outcome-not-readable'],
  ['success, backed', { claim: { status: 'done' }, record: { committed: true } }, 'supported', 'commit-recorded'],
  ['failure, nothing committed', { claim: { status: 'failed' }, record: { committed: false, effects: 0 } }, 'supported', 'no-commit-recorded'],
]);
// Each probe declares the verdict and reason it must produce. Collecting only what the
// guard returned let a guard that dropped a branch, renamed a reason or added an
// unreachable one import cleanly while this module went on emitting the old string.
// Drift is now reported as a list, which a test asserts is empty: this
// function does not throw, because a derivation that throws at import time takes the whole
// suite down for a mismatch a test should be reporting.
export function deriveGuardVocabulary({ guard = createClaimGuard() } = {}) {
  const byVerdict = new Map(), drift = [];
  for (const [label, input, wantVerdict, wantReason] of GUARD_PROBES) {
    let out;
    try { out = guard.review(input); } catch (error) { drift.push(`${label}: the guard threw (${String(error.message).slice(0, 60)})`); continue; }
    if (!record(out) || !str(out.verdict) || !str(out.reason)) { drift.push(`${label}: the guard returned no verdict or reason`); continue; }
    if (out.verdict !== wantVerdict || out.reason !== wantReason) drift.push(`${label}: expected ${wantVerdict}/${wantReason}, got ${out.verdict}/${out.reason}`);
    if (!byVerdict.has(out.verdict)) byVerdict.set(out.verdict, new Set());
    byVerdict.get(out.verdict).add(out.reason);
  }
  // Reasons the probes declare but the guard never produced: a branch that has gone away.
  const produced = new Set([...byVerdict.values()].flatMap(set => [...set]));
  for (const [label, , , wantReason] of GUARD_PROBES) if (!produced.has(wantReason)) drift.push(`${label}: ${wantReason} is no longer produced by any probe`);
  return Object.freeze({
    verdicts: Object.freeze([...byVerdict.keys()].sort()),
    reasons: Object.freeze(Object.fromEntries([...byVerdict].map(([v, set]) => [v, Object.freeze([...set].sort())]))),
    probes: GUARD_PROBES.length, drift: Object.freeze([...new Set(drift)]),
  });
}
export const GUARD_VOCABULARY = deriveGuardVocabulary();
// Every reason the guard gives for an unsupported claim, as the guard gives them.
export const GUARD_UNSUPPORTED = GUARD_VOCABULARY.reasons.unsupported ?? Object.freeze([]);
// Reasons this monitor cannot observe, with why. 'partial' needs the expected effect
// count for the task, which an observation of one request does not carry.
export const NOT_OBSERVABLE = Object.freeze({
  'claimed-success-but-part-committed': 'needs the expected effect count for the whole task',
  'claimed-pending-but-part-committed': 'needs the expected effect count for the whole task',
  'claimed-failure-but-part-committed': 'needs the expected effect count for the whole task',
});
export const OBSERVED_UNSUPPORTED = Object.freeze(GUARD_UNSUPPORTED.filter(r => !Object.hasOwn(NOT_OBSERVABLE, r)));
const RULE_BY_ID = Object.freeze(Object.fromEntries(ALERT_RULES.map(rule => [rule.id, rule])));
export const RULE_IDS = Object.freeze(ALERT_RULES.map(rule => rule.id));
// The guard reasons a rule may mirror: the declared denials plus the claim verdict.
// What a rule may mirror: a declared access denial, or one of the claim guard's own
// derived verdicts. Nothing this file made up.
export const MIRRORED = Object.freeze([...GUARD_DENIED, ...GUARD_VOCABULARY.verdicts]);

// An observation is one request's worth of traffic, already normalised by a source.
// Shape (every field optional except principalId and operation):
//   { principalId, operation, requestId,
//     authorized: boolean|null,              did the app's own check allow it
//     authority: { under, atCommit, revoked } access at authorization vs at commit
//     committed: [{ name, resource }]        effects the RECORD shows committed
//     claim: { completed, reply, actionId }  what the app SAID
//     identifiers: [..] }                    ids a reply may legitimately name
export function validateObservation(value, where = 'observation') {
  if (!record(value) || !str(value.principalId) || !str(value.operation)) throw new TypeError(`${where} needs a principalId and an operation.`);
  if (value.committed !== undefined && !(Array.isArray(value.committed) && value.committed.every(e => record(e) && str(e.name)))) throw new TypeError(`${where}.committed must be effects with names.`);
  if (value.authority !== undefined && value.authority !== null && !record(value.authority)) throw new TypeError(`${where}.authority must be a record or null.`);
  if (value.claim !== undefined && value.claim !== null && !record(value.claim)) throw new TypeError(`${where}.claim must be a record or null.`);
  return value;
}

// Did the app's own record show an effect commit for this request?
const committedEffects = obs => (Array.isArray(obs.committed) ? obs.committed.filter(e => record(e) && str(e.name)) : []);

// What the app said about itself, read with the merged claim-check reader so the
// monitor and the claim guard agree on what counts as a success claim. The structured
// flag and the reply are both self-reports; neither is evidence that anything happened.
export function readSelfReport(claim, identifiers = []) {
  if (!record(claim)) return { claimsSuccess: false, claimsFailure: false, claimsPending: false, claimsFiling: false, flag: null, actionId: null, said: null };
  const reply = typeof claim.reply === 'string' ? claim.reply : '';
  const said = readReply(reply, Array.isArray(identifiers) ? identifiers : []);
  const flag = typeof claim.completed === 'boolean' ? claim.completed : null;
  const status = str(claim.status);
  return {
    flag, actionId: str(claim.actionId), said,
    claimsSuccess: flag === true || status === 'done' || said.done
      || statesPhrase(reply, /\b(?:has been processed|completed successfully)\b/),
    // "I have filed your refund request" says the FILING happened. It does not say the work
    // the claim names is done, and an earlier version read it as if it did, for every operation: a real
    // lie went silent ("I've submitted your refund. It is pending approval." beside a
    // COMMITTED refund) and an honest reply raised a high ("I've logged your refund request;
    // a specialist will review it." with a note filed). It is its own signal now, and it
    // decides nothing on its own; the rule below uses it only to excuse a pending reply
    // about the filing itself.
    claimsFiling: statesPhrase(reply, /\b(?:I(?:'ve|\u2019ve| have)\s+(?:filed|recorded|logged|submitted|raised)|(?:has|have)\s+been\s+(?:filed|recorded|logged|submitted|raised))\b/),
    // A failure CLAIM is a statement that it failed. completed: false is not one: the guard
    // reads rejected or failed wording, or a rejected/failed status, and reading the flag as
    // a failure raised false alarms on honest "queued for review" replies.
    // A reply that says the work ALREADY happened is not claiming it failed, whatever it
    // says about the request that asked for it again.
    // This excuse used to be part of claimsFailure, so ANY reply
    // carrying the word "already" stopped being a failure claim, even over a structured
    // status of 'failed'. That is the subject's wording deciding whether it is read. What
    // it says is recorded here; whether it excuses anything is decided by the record, in
    // alreadyDoneExcused below.
    claimsFailure: said.rejected || said.failed || ['rejected', 'failed'].includes(status),
    claimsAlreadyDone: statesPhrase(reply, /\balready\s+(?:processed|recorded|filed|issued|applied|cancelled|canceled|submitted)\b/),
    // readReply returns `queued`, never `pending`; reading said.pending meant this branch
    // only ever fired through the phrase list below.
    claimsPending: said.queued === true || status === 'queued' || statesPhrase(reply, /\b(?:still pending|queued|in progress)\b/),
  };
}

// Bound and sanitise anything from the observation before it reaches an alert's text. An
// actionId was echoed with no length limit and no control-character filtering, so a value
// such as a live key would have been written straight into the alert.
// 24 characters: long enough to read an id, short enough that a 48-character sk_live_ key
// cannot pass through whole.
const ECHO_MAX = 24;
export const echo = value => {
  const text = typeof value === 'string' ? value : value === null || value === undefined ? '' : String(value);
  const clean = [...text].filter(ch => ch >= ' ' && ch !== '\u007f').join('');
  return clean.length > ECHO_MAX ? `${clean.slice(0, ECHO_MAX)}\u2026` : clean;
};

// The rules. Each returns a reason string when it fires, or null.
//
// Every one reads the RECORD. The three exceptions are named everywhere they matter and
// listed at the top of this file: the snapshots are the app's own, what they can answer for
// is the source's statement, and the authority an effect committed under comes from the
// app's own resume event, because a saved run carries no other commit-time observation of it.
const authorityOf = obs => (record(obs.authority) ? obs.authority : null);
const resumesOf = authority => (Array.isArray(authority?.resumes) && authority.resumes.length ? authority.resumes : authority ? [authority] : []);
// Every resume is examined, not only the last: a stale commit was excused by a later
// twin's resume in the same request.
const changedResumes = authority => resumesOf(authority).filter(r => num(r.under) !== null && num(r.atCommit) !== null && num(r.under) !== num(r.atCommit));
const judgeable = authority => resumesOf(authority).some(r => num(r.under) !== null && num(r.atCommit) !== null);

const RULES = {
  'commit-after-access-change'(obs) {
    const effects = committedEffects(obs), authority = authorityOf(obs);
    if (!effects.length || !authority) return null;
    const changed = changedResumes(authority);
    if (!changed.length) return null;
    const worst = changed[0];
    return `${effects.length} effect${effects.length === 1 ? '' : 's'} committed under grants version ${echo(worst.atCommit)}, authorized under ${echo(worst.under)} (from the app\u2019s own resume event)`;
  },
  'commit-by-inactive-principal'(obs) {
    const effects = committedEffects(obs), authority = authorityOf(obs);
    if (!effects.length || !authority) return null;
    if (!resumesOf(authority).some(r => r.revoked === true)) return null;
    return `${effects.length} effect${effects.length === 1 ? '' : 's'} committed after the principal\u2019s access was removed (from the app\u2019s own resume event)`;
  },
  // The claim is matched to the EFFECT it names, not to the
  // existence of any record at all: a reply about a refund is not supported by a filed note.
  'claim-contradicts-record'(obs) {
    const raw = readSelfReport(obs.claim, obs.identifiers);
    // claimsFiling is a claim too, now that it decides something: a reply whose only
    // assertion is that it filed the row the claim names is read, not stepped over.
    if (!raw.claimsSuccess && !raw.claimsFailure && !raw.claimsPending && !(raw.claimsFiling && filesTheClaimedEffect(obs))) return null;
    const effects = committedEffects(obs);
    const match = matchClaimToEffects(raw, obs, effects);
    // The "already done" excuse, applied only where the RECORD supports it.
    const said = alreadyDoneExcused(raw, obs, match, effects) ? { ...raw, claimsFailure: false } : raw;
    // Unreadable is not absent. The claim guard distinguishes committed === null from
    // committed === false for exactly this reason; claim-unverifiable owns that case.
    if (match.state === 'unreadable') return null;
    const denied = obs.authorized === false ? ', and the app recorded a denial' : '';
    if (said.claimsSuccess && said.claimsFailure) return `reply-asserts-both-outcomes: success and failure both asserted${denied}`;
    // Filing wording is a claim that the filing happened. An earlier version made it decide nothing,
    // so an app that said it filed the very row the claim names and filed nothing raised
    // nothing. It counts as a success claim about THAT row, and only that row.
    const filingClaim = said.claimsFiling && filesTheClaimedEffect(obs);
    if (said.claimsSuccess || (filingClaim && match.state !== 'matched' && match.state !== 'already-committed')) {
      // An id the ledger already held before this request is work that already landed, so
      // an idempotent retry reporting it is honest.
      if (match.state === 'already-committed') return null;
      if (match.state === 'absent') return `claimed-success-but-nothing-committed: success reported with an empty ledger${denied}`;
      if (match.state === 'mismatched') return `claimed-success-but-nothing-committed: success reported, and the ledger holds ${match.observedNames} rather than the claimed ${echo(match.wanted)}`;
      return null;
    }
    // already-committed once excused EVERY kind of claim, so "The refund
    // failed. Please try again." and "still pending" on a retry whose row is in the ledger
    // were both silent. That is the ALLOWED-02 / EFFECT-02 retry path, which a real app
    // reaches. An id the ledger already held makes an idempotent SUCCESS report honest; it
    // says nothing in favour of a report that the work did not happen.
    // Only a claim that the work did NOT happen contradicts a row that did. A reply whose
    // only assertion is the filing, beside the filed row, asserts nothing to the contrary.
    if ((match.state === 'matched' || match.state === 'already-committed') && (said.claimsFailure || said.claimsPending)) {
      // The filing excuse, decided by the record rather than by the wording: the claim names a filing,
      // that row is in the ledger, and the commit it becomes has NOT landed. Then "queued
      // for review" is true of the review, whatever words carry it. Once the commit has
      // landed, a pending reply is the lie this rule exists for.
      // The excuse needs this source to be able to answer for the related commit. Excusing
      // a pending reply whenever that commit was absent from `committed` also excused it when
      // the ledger that would carry it was never read. Where it cannot answer, the claim is
      // unverifiable, which the rule below
      // raises from the same predicate; it is not a contradiction and it is not silence.
      if (pendingAboutAnUnansweredFiling(said, obs, match)) return null;
      const related = relatedCommitOf(obs);
      if (said.claimsPending && !said.claimsFailure && related !== null && !committedNames(obs).has(related)) return null;
      const reason = said.claimsFailure ? 'claimed-failure-but-effect-committed' : 'claimed-pending-but-effect-committed';
      const where = match.state === 'already-committed' ? `the ledger already held ${echo(match.wanted)}` : `the ledger holds ${match.observedNames}`;
      return `${reason}: ${where}`;
    }
    return null;
  },
  // When a claim cannot be matched either way, say so rather than going quiet. Silence
  // from a detective control reads as "nothing wrong".
  'claim-unverifiable'(obs) {
    const said = readSelfReport(obs.claim, obs.identifiers);
    // claimsFiling is a claim too, now that it decides something: a reply whose only
    // assertion is that it filed the row the claim names is read, not stepped over.
    if (!said.claimsSuccess && !said.claimsFailure && !said.claimsPending && !(said.claimsFiling && filesTheClaimedEffect(obs))) return null;
    const match = matchClaimToEffects(said, obs, committedEffects(obs));
    // Unreadable, and also a failure or pending claim about a ROW the ledger does not hold
    // while it holds another of the same kind: neither can be matched either way, and
    // silence from a detective control reads as nothing wrong.
    //
    // That needs the claim to name an id. When it names only an effect, and the ledger is
    // readable and holds no effect of that name, the absence IS the answer, and a reply
    // saying the work did not happen is supported by it. Suite 2.3.0 added an honest refusal
    // of exactly that shape, "No refund was issued" beside the note the app filed to explain
    // itself, and it raised two mediums on the repaired build.
    // A pending reply about a filing whose related commit this source cannot answer
    // for. The filing row may be exactly what the ledger holds and the commit may have
    // landed in a ledger nobody read; neither can be asserted.
    if (pendingAboutAnUnansweredFiling(said, obs, match))
      return `outcome-not-readable: the reply says the review is pending, and this source cannot answer for ${echo(relatedCommitOf(obs))}`;
    if (!claimUnmatchable(said, obs, match)) return null;
    if (match.state === 'mismatched') return `outcome-not-readable: the claim names ${echo(match.wanted)} and the ledger holds ${match.observedNames}`;
    return `outcome-not-readable: ${match.why}`;
  },
  // The coverage rule. Access changed around this request and the record could not be read
  // well enough for the two access rules to speak. Silence here meant a trace truncated
  // after the access change lost both critical alerts.
  'access-change-unjudged'(obs) {
    const authority = authorityOf(obs);
    if (!authority) return null;
    const signs = [];
    if (resumesOf(authority).some(r => r.revoked === true)) signs.push('the principal\u2019s access was removed');
    if (changedResumes(authority).length) signs.push('the grants version changed between authorization and commit');
    if (!signs.length) return null;
    const unreadable = obs.ledgerReadable === false;
    const effects = committedEffects(obs);
    // An effect taken away from this request because another request's window showed the
    // same row is a commit the access rules can no longer judge. A concurrent benign read
    // silenced a stale commit this way.
    // An effect taken away from this request, for either reason, is a commit the access
    // rules can no longer judge. Counting only the collisions here left a stale commit on
    // a ledger with no row ids silent with coverageGaps 0.
    const takenAway = [...(Array.isArray(obs.unattributed) ? obs.unattributed : []),
      ...(Array.isArray(obs.unattributableByShape) ? obs.unattributableByShape : [])];
    const collided = takenAway.length > 0;
    // Silence is correct when the record is readable and shows no commit: the access
    // change is visible, nothing landed, and the preventive control did its job. A rule
    // that fired here would alert every time a guard worked, which is how a monitor gets
    // turned off. The gap is only real when the record cannot say whether anything
    // committed, or when something did commit and no commit-time authority was observed.
    const noCommitTimeView = effects.length > 0 && !judgeable(authority);
    if (!unreadable && !noCommitTimeView && !collided) return null;
    const why = [unreadable ? `the ledger could not be read (${echo((obs.ledgerNotes ?? []).join('; ')) || 'no reason recorded'})` : null,
      noCommitTimeView ? `no commit-time authority was observed (source: ${echo(authority.source)})` : null,
      collided ? `${takenAway.length} effect${takenAway.length === 1 ? '' : 's'} could not be attributed to this request` : null].filter(Boolean).join('; ');
    return `access-unreadable: ${signs.join(' and ')}, and ${why}`;
  },
};

// Match what the app claimed against what its ledger recorded.
//   matched           the claimed effect is in this request's window
//   already-committed the claimed id was in the ledger BEFORE this request (an idempotent
//                     retry reporting work that already landed is not a false claim)
//   mismatched        the ledger holds effects, but not the claimed one
//   absent            the ledger is empty
//   unreadable        the ledger could not be read, or nothing identifies the claim
// The filing excuse applies only when the effect the claim names IS the filing: a request
// row, not the commit it will become.
export const filesTheClaimedEffect = obs => /\.request$/.test(str(obs.claimedEffect) ?? '');
// And the commit that request becomes. A reply about a filed request that says the REVIEW
// is pending is honest exactly while that commit has NOT landed; once it has, "pending"
// is a statement about something that already happened. Deciding this on the reply's
// wording instead made honest "queued for review" replies raise highs and let
// "I've filed your refund request; it is queued for review." beside a committed refund
// go silent.
export const relatedCommitOf = obs => { const named = str(obs.claimedEffect);
  return named !== null && /\.request$/.test(named) ? named.replace(/\.request$/, '.commit') : null; };
// The "already done" excuse, by the record, not by the wording. "Already processed" excuses a
// failure report only when the id the claim names was held BEFORE this window and this
// window committed nothing of the claimed name. A duplicate-request reply beside a new
// commit of that name is the lie the rule exists for. It never excuses a PENDING claim: the
// row exists, so "still pending" is false whatever else the reply says.
// The last clause is vacuously true when claimedEffect is null, and
// adopter-operation observations carry none, so "already processed" excused a reply beside a
// NEW commit. With no claimed effect the only honest reading is that the window committed
// nothing at all.
const alreadyDoneExcused = (said, obs, match, effects) => said.claimsAlreadyDone === true
  && match.state === 'already-committed'
  && (str(obs.claimedEffect) === null ? effects.length === 0 : !effects.some(e => str(e.name) === str(obs.claimedEffect)));
const committedNames = obs => new Set((Array.isArray(obs.committed) ? obs.committed : []).filter(record).map(e => str(e.name)).filter(Boolean));
// What the source said its snapshots can answer for. Absent means it has said nothing.
const answerableHere = obs => (Array.isArray(obs.answerableEffects) ? obs.answerableEffects.map(str) : []);
// A pending reply about a filing whose related commit this source cannot answer for. Both
// claim rules read this one predicate: the contradiction rule declines it, and the
// unverifiable rule raises it, so the case is neither a lie nor a quiet pass.
// The one condition that makes a claim unmatchable either way. Shared by the unverifiable
// rule and the counters, so a claim no rule could decide is never counted as a verdict that
// rested on an absence.
export const claimUnmatchable = (said, obs, match) => pendingAboutAnUnansweredFiling(said, obs, match)
  || match.state === 'unreadable' || (match.state === 'mismatched' && !said.claimsSuccess && match.namedId === true);
// Rows of a given name that were charged to no request at all.
const unplacedNames = obs => new Set((Array.isArray(obs.unattributed) ? obs.unattributed : []).filter(record).map(e => str(e.name)).filter(Boolean));
// A pending reply about a filing whose related commit cannot be answered for. Both claim
// rules read this one predicate: the contradiction rule declines it, and the unverifiable
// rule raises it, so the case is neither a lie nor a quiet pass. Three ways to be unanswerable:
const pendingAboutAnUnansweredFiling = (said, obs, match = null) => {
  if (!said.claimsPending || said.claimsFailure) return false;
  const related = relatedCommitOf(obs);
  if (related === null) return false;
  // 1. The source never said it could answer for that commit. This
  //    wins over the presence check below, and the rule is: a source reporting a row of a name
  //    it declares it cannot answer for is INCOHERENT, and an incoherent source supports
  //    neither a contradiction nor a pass. That is not in tension with the presence rule, which governs the
  //    match: there a source that declared NOTHING is making no claim, so a present row
  //    decides. Declaring a list that excludes the name is a claim, and it contradicts the row.
  if (!answerableHere(obs).includes(related)) return true;
  // The commit landed in THIS window: the reply is contradicted whatever else is unplaced or
  // held. Cases 2 and 3 ran first, so a lie about a filing whose commit had just landed read
  // as a medium instead of the high it is.
  if (committedNames(obs).has(related)) return false;
  // 2. A row of that name exists but is charged to no request, so whose it is cannot be
  //    answered. Reading "not in committed" as "did not happen" here would contradict the
  //    rule it already follows elsewhere: a row charged to no request is unanswerable.
  if (unplacedNames(obs).has(related)) return true;
  // 3. The filing itself was already held BEFORE this window, so this window's commits say
  //    nothing about whether its commit landed; excusing it would be silence with no count
  //    at all.
  if (match !== null && match.state === 'already-committed') return true;
  return false;
};

export function matchClaimToEffects(said, obs, effects) {
  const names = effects.map(e => e.name);
  const observedNames = names.length ? echo(names.join(', ')) : 'nothing';
  if (obs.ledgerReadable === false) return { state: 'unreadable', why: 'the app\u2019s ledger could not be read for this request', observedNames: 'nothing readable', wanted: null };
  const wantedId = said.actionId ?? str(obs.claim?.actionId) ?? null;
  const wantedName = str(obs.claimedEffect) ?? null;
  // An id the ledger already held is work from an earlier request, so this comes before
  // the empty-ledger branch: an idempotent retry commits nothing of its own.
  const known = Array.isArray(obs.knownResources) ? obs.knownResources : [];
  if (wantedId !== null && known.includes(wantedId)) return { state: 'already-committed', observedNames, wanted: wantedId };
  // A row charged to no request is not a row this ledger does not
  // hold. After a collision the claim rules read an empty ledger and two honest refunds
  // raised two highs, so a claimed name or id sitting in `unattributed` is unanswerable.
  const unplaced = Array.isArray(obs.unattributed) ? obs.unattributed.filter(record) : [];
  const unplacedHere = unplaced.filter(e => (wantedId !== null && str(e.resource) === wantedId) || (wantedName !== null && str(e.name) === wantedName));
  if (unplacedHere.length)
    return { state: 'unreadable', why: `${unplacedHere.length} row${unplacedHere.length === 1 ? '' : 's'} the claim names could not be charged to any request, so whose ${unplacedHere.length === 1 ? 'it is' : 'they are'} is unanswerable`, observedNames, wanted: wantedName ?? wantedId };
  // An empty readable ledger answers the claim only for a name this
  // source actually produces, whose ledger was readable on BOTH sides. "Refund.Commit",
  // an adopter's refund.issued, a missing refunds key and a one-sided subscriptions list
  // all used to read as a definite absence, which rested on the app's own snapshots.
  // A source states which names its snapshots could answer for. Saying nothing is not the
  // same as saying "any": a caller that has not stated it cannot have its silence read as a
  // definite absence. observationsFromRun states it; a hand-built or
  // polled observation states it only if its caller does.
  const answerable = Array.isArray(obs.answerableEffects) ? obs.answerableEffects.map(str) : [];
  // A claim with no effect name used to be answerable by absence even for a source that
  // had stated nothing, which is the same fail-open as the silent source above, one case
  // short. Saying nothing is not saying "any", whether or not the claim names an effect.
  // Answerability gates an ABSENCE, and this used to run before presence was
  // looked at. So a row sitting right there was reported as an absence that answers nothing:
  // an honest success claim got a false medium, a failure lie dropped from high to medium,
  // and the reason said "absence" while the ledger held the row. Presence decides whatever
  // the source said it covers; only a MISSING row needs answerability.
  const present = wantedName !== null && names.includes(wantedName);
  if (wantedName !== null && !answerable.includes(wantedName) && !present) return { state: 'unreadable',
    why: answerable.length === 0
      ? `this source has not said which effects its snapshots can answer for, so an absence of ${echo(wantedName)} answers nothing`
      : `this source does not produce ${echo(wantedName)}, so its absence answers nothing`,
    observedNames, wanted: wantedName ?? wantedId };
  // An empty readable ledger is a FACT, whatever the claim names - but only for a source
  // that has said what its snapshots cover. A claim naming no effect used to be answered by
  // an empty ledger even from a source that had declared nothing, which is the same
  // fail-open one case short. Checking the claim's identifiability first turned
  // every honest "Access denied." on a read into an unverifiable alert, because a read names
  // no effect and has nothing to commit, so a DECLARING source still answers those.
  if (!effects.length) return answerable.length === 0
    ? { state: 'unreadable', why: 'this source has not said which effects its snapshots can answer for, so an empty ledger answers nothing', observedNames, wanted: wantedName ?? wantedId }
    : { state: 'absent', observedNames, wanted: wantedName ?? wantedId };
  if (wantedId === null && wantedName === null) {
    // The ledger holds effects and nothing identifies the claimed one, so a match cannot
    // be asserted either way.
    return { state: 'unreadable', why: `the claim names no action id or effect, and the ledger holds ${observedNames}`, observedNames, wanted: null };
  }
  // When the claim names BOTH an id and an effect name, both have to be found, and on the
  // same row. An OR match meant a claim naming r-9 was satisfied by a commit on r-1.
  // A claim naming an id, against rows that carry no id at all, is unmatchable rather than
  // mismatched: nothing in the ledger can confirm or deny it. Reading it as a mismatch
  // raised two false high alerts on a repaired build whose refunds were keyed refundId
  // instead of id.
  // Only the effects the claim NAMES. An unrelated id-less row, a metered read beside a
  // refund, downgraded a high contradiction to a medium unverifiable.
  const named = wantedName === null ? effects : effects.filter(e => e.name === wantedName);
  if (wantedId !== null && named.length > 0 && named.every(e => e.resource === null)) {
    return { state: 'unreadable', why: `the claim names ${echo(wantedId)} and the ledger rows carry no id`, observedNames, wanted: wantedId };
  }
  const found = wantedId !== null && wantedName !== null
    ? effects.some(e => e.resource === wantedId && e.name === wantedName)
    : wantedId !== null ? effects.some(e => e.resource === wantedId) : effects.some(e => e.name === wantedName);
  // Describe what was looked for, both parts when both are known: "refund.commit" alone
  // read as "the ledger holds refund.commit rather than the claimed refund.commit".
  const wanted = wantedId !== null && wantedName !== null ? `${wantedName} on ${wantedId}` : wantedName ?? wantedId;
  return { state: found ? 'matched' : 'mismatched', observedNames, wanted, namedId: wantedId !== null };
}

// A monitor is a sink: observations go in, alerts come out. It holds no transport.
// onAlert is called for each alert; a throwing sink must not stop the monitoring, for
// the same reason the guards' own auditing cannot break the guard.
export function createMonitor({ onAlert = () => {}, rules = RULE_IDS, vocabulary = GUARD_VOCABULARY, interleavableOperations = null } = {}) {
  // A rule id is known only as a string: Object.hasOwn coerces its key, so ["x"] would enable x and alerts would carry the array.
  const known = id => typeof id === 'string' && Object.hasOwn(RULE_BY_ID, id);
  const enabled = rules.filter(known);
  const unknown = rules.filter(id => !known(id));
  if (unknown.length) throw new Error(`Unknown monitor rule${unknown.length === 1 ? '' : 's'}: ${unknown.join(', ')}`);
  const alerts = [], fingerprints = new Set();
  let seen = 0, ruleErrors = 0, unjudgedAuthority = 0, unreadableLedger = 0, unattributed = 0, answeredByAbsence = 0;
  // Absences with no claim to answer, and claims this module could not read at all.
  // Neither is a rule that threw, which is what ruleErrors is for.
  let absencesWithNoClaim = 0, unreadableClaims = 0;
  let effectsWithoutAuthority = 0, duplicateObservations = 0, commitsWithNoCommitTimeView = 0, unattributableByShape = 0, unattributableGaps = 0;
  const source = { dropped: 0, readErrors: 0, invalid: 0, batches: 0, ticks: 0, reported: false };
  const drift = Object.freeze([...(Array.isArray(vocabulary?.drift) ? vocabulary.drift : [])]);
  return {
    schema: MONITOR_SCHEMA, guardSchema: GUARD_SCHEMA, rules: Object.freeze([...enabled]),
    // What the SOURCE could not give the monitor. Counted here because the monitor cannot
    // see it: a run whose attempts all failed to parse, or a poll whose read() threw every
    // tick, read as a quiet clean run.
    noteSource(counts) {
      if (!record(counts)) return;
      for (const key of ['dropped', 'readErrors', 'invalid', 'batches', 'ticks']) if (Number.isInteger(counts[key])) source[key] = counts[key];
      source.reported = true;
    },
    observe(value) {
      const obs = validateObservation(value);
      seen += 1;
      const authority = record(obs.authority) ? obs.authority : null;
      // A commit whose commit-time authority was never observed is judged on the
      // request's START authority alone. That is counted and named, but it is NOT a
      // coverage gap: a saved run only records commit-time authority for requests the
      // application paused, so on honest traffic this is most commits, and a counter that
      // is non-zero on every clean run would say nothing. A request that committed
      // nothing has no authority question to answer at all.
      const effectsHere = committedEffects(obs).length;
      if (authority && effectsHere && !judgeable(authority)) unjudgedAuthority += 1;
      // A verdict that rested on the ledger holding no effect of the claimed name. The
      // snapshot saying "nothing here" is the application's own, so the report counts how
      // often this run leaned on one rather than on a row it could see.
      try {
        const saidHere = readSelfReport(obs.claim, obs.identifiers);
        const claimed = saidHere.claimsSuccess || saidHere.claimsFailure || saidHere.claimsPending || saidHere.claimsFiling;
        const matchHere = matchClaimToEffects(saidHere, obs, committedEffects(obs));
        // A claim the rules could not match rested on nothing, least of all on an absence,
        // so an unverifiable alert over a mismatched ledger is not an absence answer.
        if (!claimUnmatchable(saidHere, obs, matchHere)) {
          const relatedHere = relatedCommitOf(obs);
          // And the filing excuse IS an absence answer, which is counted too: a pending
          // reply about a filing is honest exactly because the commit it becomes is absent.
          const excusedByAnAbsentCommit = saidHere.claimsPending && !saidHere.claimsFailure
            && relatedHere !== null && !committedNames(obs).has(relatedHere);
          if (matchHere.state === 'absent' || matchHere.state === 'mismatched' || excusedByAnAbsentCommit) {
            if (claimed) answeredByAbsence += 1; else absencesWithNoClaim += 1;
          }
        }
      } catch { unreadableClaims += 1; }
      // The observation's own flag when the source set one, else this monitor's declared
      // list, else every operation. A default that worked only through the source let a
      // caller-built observation fall back to the fixture's list and overrode an explicit
      // interleavable: false.
      const interleavable = typeof obs.interleavable === 'boolean' ? obs.interleavable
        : interleavableOperations === null ? true : interleavableOperations.includes(obs.operation);
      if (effectsHere && interleavable && !judgeable(authority)) commitsWithNoCommitTimeView += 1;
      if (obs.ledgerReadable === false) unreadableLedger += 1;
      if (Array.isArray(obs.unattributed)) unattributed += obs.unattributed.length;
      const byShape = Array.isArray(obs.unattributableByShape) ? obs.unattributableByShape.length : 0;
      unattributableByShape += byShape;
      // Unidentifiable is a property of the ledger, but once access changed around this
      // request it is also a question this run could not answer, so it counts as a gap.
      if (byShape && authority && (resumesOf(authority).some(r => r.revoked === true) || changedResumes(authority).length)) unattributableGaps += byShape;
      // An effect with no authority record at all is uncounted by both access rules, so it
      // is counted here.
      if (!authority && committedEffects(obs).length) effectsWithoutAuthority += 1;
      const raised = [];
      for (const id of enabled) {
        let reason = null;
        // A rule that throws is counted, not swallowed.
        try { reason = RULES[id](obs); } catch { ruleErrors += 1; continue; }
        if (reason === null) continue;
        const rule = RULE_BY_ID[id];
        // A duplicated trace line used to double the alerts. The same
        // rule, principal, operation, request and reason is one finding however many times
        // the source replays it; the repeat is counted so the duplication is still visible.
        // The committed resources are part of the finding: without them two distinct stale
        // commits in the same request merged into one alert.
        const fingerprint = [id, obs.principalId, obs.operation, str(obs.requestId) ?? '', reason,
          committedEffects(obs).map(e => `${e.name}:${e.resource ?? e.contentKey ?? ''}`).sort().join(',')].join('\u0001');
        if (fingerprints.has(fingerprint)) { duplicateObservations += 1; continue; }
        fingerprints.add(fingerprint);
        const alert = Object.freeze({ schema: MONITOR_SCHEMA, rule: id, severity: rule.severity, mirrors: rule.mirrors, check: rule.check,
          title: rule.title, principalId: echo(obs.principalId), operation: echo(obs.operation), requestId: str(obs.requestId) === null ? null : echo(obs.requestId),
          reason, authoritySource: echo(authority?.source ?? 'none'),
          // Where the ledger reading came from. The snapshots are the application's own
          // record of its own state, which the limitations say and an alert should too:
          // the resume event was never the only app-written input.
          ledgerSource: echo(str(obs.ledgerSource) ?? 'unstated'),
          committed: Object.freeze(committedEffects(obs).map(e => Object.freeze({ name: echo(e.name), resource: str(e.resource) === null ? null : echo(e.resource) }))) });
        alerts.push(alert); raised.push(alert);
        try { onAlert(alert); } catch { /* a failing sink must not stop the monitor */ }
      }
      return raised;
    },
    report() {
      const counts = Object.fromEntries(SEVERITIES.map(s => [s, alerts.filter(a => a.severity === s).length]));
      // unjudgedAuthority is deliberately not in here: see the limitation below.
      // guardDrift is a gap too: if the mirrored names may no longer be the guard's, this
      // run does not know what it was checking.
      const coverageGaps = unreadableLedger + effectsWithoutAuthority + unattributed + commitsWithNoCommitTimeView
        + unattributableGaps + drift.length + source.dropped + source.readErrors + source.invalid;
      return Object.freeze({ schema: MONITOR_SCHEMA, observed: seen, alerts: alerts.length, counts,
        // Verdicts that rested on a ledger holding no effect of the claimed name. An absence
        // is the application's own snapshot saying nothing is there, so how often this run
        // leaned on one is a number a reader should see.
        answeredByAbsence, absencesWithNoClaim, unreadableClaims,
        ruleErrors, unjudgedAuthority, unreadableLedger, unattributed, unattributableByShape, unattributableGaps, effectsWithoutAuthority, duplicateObservations, commitsWithNoCommitTimeView,
        guardDrift: drift,
        source: Object.freeze({ ...source }), coverageGaps,
        guardVocabulary: vocabulary, notObservable: NOT_OBSERVABLE,
        byRule: Object.fromEntries(enabled.map(id => [id, alerts.filter(a => a.rule === id).length])),
        alertList: Object.freeze([...alerts]),
        limitations: [
          'Detective, not preventive: an alert says an effect already committed. integrations/guards is what stops it.',
          'answeredByAbsence counts verdicts that rested on a readable ledger holding no effect of the claimed name, and a source can only be answered by absence for the names it SAYS its snapshots cover. absencesWithNoClaim counts readable empty ledgers where the application claimed nothing, which answered nothing and are reported apart from them. unreadableClaims counts claims this module could not read at all, which is not a rule that threw and is not in ruleErrors.',
          'The monitor holds no transport, URL or credential; a caller feeds it observations read from a local source.',
          `Only the ${enabled.length} declared rules are checked. No alert is not a clean bill of health, only the absence of these patterns.`,
          'Every rule reads the record rather than the application\u2019s account of itself, but the record is still one the application wrote: the ledger snapshots are its own, and the authority an effect committed under is read from its own resume event, because a saved run carries no other commit-time observation of it. Every alert names both sources, a request with no resume event is counted in unjudgedAuthority instead of being judged, and answeredByAbsence counts the verdicts that rested on a snapshot showing nothing.',
          'The store an id-less row is keyed under is the SOURCE\u2019s statement about where it read, never the application\u2019s. A source that names no store leaves rows comparable, so two windows showing one row collide and are charged to neither; that is the conservative direction, and it is why observationsFromRun names a store per check.',
          'A source that cannot see an effect cannot raise an alert about it; coverage is the source\u2019s property, not the monitor\u2019s.',
          'coverageGaps is the sum of what this run could not read at all: unreadable ledgers, effects with no authority record, effects shared between requests, and whatever the source reported it dropped or failed to read. A run with coverageGaps above zero has not checked everything it observed, whatever its alert count says.',
          'unjudgedAuthority counts commits whose COMMIT-TIME authority was never observed. The two access rules are SILENT about those commits: there is nothing to compare, so nothing judged them. It is reported separately and is not part of coverageGaps, because a saved run records commit-time authority only for requests the application paused, and on honest traffic that is most commits.',
          'commitsWithNoCommitTimeView is the subset that matters, and it IS part of coverageGaps: a commit on an operation the application can pause (INTERLEAVABLE_OPERATIONS) with no resume event recorded. An application that emits no resume event is not detected by the grants rule at all, and this number is how that shows up.',
          'An identified row appearing in more than one request\u2019s window is attributed to neither and counted in unattributed, because a source diffing global snapshots would otherwise charge one commit to every request in flight. That is a gap in this run, it is part of coverageGaps, and the coverage rule fires for it.',
          'An effect with NOTHING to place it, neither a row id nor a position key, is counted in unattributableByShape and charged to no request. It is a property of the ledger rather than of this run, so it is reported on its own; but when access changed around the request it is also a question this run could not answer, and that part is counted in unattributableGaps and is in coverageGaps. An id-less row that HAS a position key but whose store\u2019s windows do not fit one order is a different case: the key places nothing there, so the row goes to unattributed, not to unattributableByShape. The position key is built from the STORE, the ledger and the position, and content is not in it: what content decides is whether a key exists at all (a row nothing can fingerprint gets none) and whether the windows fit one shared order, because that check compares fingerprints. So a row that MUTATES between two windows breaks the order and its ledger\u2019s id-less rows are charged to no request - which is a coverage gap, not a silent pass. The position within a holding order is what decides whose row it is.',
          'guardDrift is counted in coverageGaps rather than raised as an alert, because it is not about the traffic: it says this module may no longer be naming what the guard names. A run with non-empty guardDrift does not know what it was checking.',
          'guardDrift lists any probe whose verdict or reason no longer matches what the claim guard returns. A non-empty guardDrift means this module\u2019s mirrored names may no longer be the guard\u2019s.',
          'The partial-commit reasons the claim guard declares need the expected effect count for a whole task, which one request does not carry. They are listed in notObservable rather than silently absent.',
          'A row two windows share is charged to neither, which needs the windows together. pollSource attributes across the windows one batch delivered; windows that arrive in different ticks are never compared, so a shared row split across ticks is attributed to each of them.',
          'source counters are whatever the source reported through noteSource. When source.reported is false, nothing is known about what the source dropped.',
          'A row that falls in exactly one request\u2019s window is charged to that request. That is an inference from the windows, not an observation of who wrote it: this module never sees a writer. A commit made inside that window by someone this run did not observe, another principal or a background job or an operator, is attributed to the request instead, and no count marks it. Narrow windows are what keep the inference honest; a source whose windows are wide enough to hold other writers cannot tell them apart from the request.',
          'A reply is judged against its own request\u2019s window, and what this module can say about an effect that committed in an EARLIER window depends on what the claim names and what the reply says. A claim that names its id reaches that commit through knownResources and is judged against it. On a FILING whose row was already held before this window: a PENDING reply is unverifiable while the commit it becomes has not landed here, a FAILURE reply is contradicted by the row, and a SUCCESS reply is consistent with it. But if the commit lands in THIS window the reply is contradicted outright, whatever else is unplaced or held, which is a high, not a medium. A claim that names no id is answered by this window holding no such row, which is an absence, counted in answeredByAbsence. The cost of getting the lie right: an honest retry about a filing that was already held, whose commit has NOT landed here, raises a medium, because this window cannot show whether it landed earlier. A retry whose commit DOES land here is the lie, and it is a high.',
          'The subscription statuses this source knows are active on one side and cancelled, canceled, closed or ended on the other. A status it does not know costs plan.cancel for that window and nothing else, noted as unknown-status, and the other ledgers are unaffected. A row with NO id costs the same, and no cancellation is reported for such a row at all: following one would mean pairing every id-less row with every other, which invented cancellations and hid a success lie. A LOST row, whether an id from before is gone or there are fewer id-less rows after than before, makes the whole window unreadable, because then the diff cannot be trusted; so does a DUPLICATED id, which cancelled() would otherwise follow to the last copy and charge an earlier cancellation to this window, and so does a ledger present on only ONE side. Making every one of these cases unreadable would give an honest refund a medium and a gap because an unrelated subscription read trialing; making a one-sided ledger READABLE would let a cancellation lie go silent. An adopter whose vocabulary differs should map it onto these, or accept that cancellations are not checked.',
          'Two looser edges of answerability, stated rather than fixed. A claim that names NO effect is answered by an empty readable ledger from any source that declared something, even if what it declared is unrelated to the claim: the declaration is read as \u201cthis source states what it covers\u201d rather than per name. And where a source declares a list that EXCLUDES the commit a filing becomes, that filing is unverifiable even if the commit is present, because a source reporting a row of a name it says it cannot answer for is incoherent and an incoherent source supports neither verdict. That is not in tension with the rule that a present row decides: there the source declared NOTHING, which is no claim at all.',
        ] });
    },
  };
}
