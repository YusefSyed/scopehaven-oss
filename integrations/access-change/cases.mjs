// Access-change cases: does work that was legitimately started still produce
// an effect after the authority behind it changed? Each case is a declared
// timed sequence (integrations/sequences) and has a permitted twin with no
// access change, which must still commit. Nothing here edits the sequence
// runner or the observers; it composes them over the owned access desk.
//
// How a row is judged:
//   - Sequence assertions read the app's audit table (authoritative, complete
//     coverage). A forbidden refund is selected by action and ticket, not by
//     actor, so a commit under any principal counts. Permitted controls use
//     other tickets, so every count is unambiguous.
//   - After a bounded settle, a final-state check reads the desk's own refunds
//     and jobs tables. More refunds than declared on any ticket is a fail even
//     when the audit table missed it. Fewer is a failed control. A job not in
//     a terminal state (done or denied) means the work did not settle, which is
//     inconclusive. A forbidden commit the audit table reports on a ticket the
//     refunds table holds nothing for is conflicting evidence: inconclusive.
//   - Request-level refusals (a suspended caller, another user's approval) are
//     results of their own, read from the run's response timeline, so an app
//     that fails one is reported as a fail, not an aborted run.
//   This final-state check is possible because the desk is owned. A customer
//   app needs an equivalent observer on its own effect tables.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { digest } from '../../src/domain.mjs';
import { createHoldGate } from '../sequences/gate.mjs';
import { runSequence, SEQUENCE_SCHEMA } from '../sequences/sequence.mjs';
import { createSqliteAuditObserver } from '../observers/sqlite.mjs';
import { startAccessDesk, startFakePayments, REVOKE_ACTION, TERMINAL_JOB_STATUSES } from './desk.mjs';
import { CONTROL_CUSTODY_LIMIT, CUSTODY_BASIS, CUSTODY_REASON } from '../../src/custody.mjs';

export const ACCESS_CHANGE_SCHEMA = 'scopehaven-access-change/1';
export const SETTLE_MS = 300;
const ENV = Object.freeze({ SCOPEHAVEN_TARGET_SAM: 'synthetic-sam-token-ac', SCOPEHAVEN_TARGET_TIA: 'synthetic-tia-token-ac', SCOPEHAVEN_TARGET_OLGA: 'synthetic-olga-token-ac', SCOPEHAVEN_TARGET_WORKER: 'synthetic-worker-token-ac' });
const TOKENS = Object.freeze({ 'agent-sam': ENV.SCOPEHAVEN_TARGET_SAM, 'agent-tia': ENV.SCOPEHAVEN_TARGET_TIA, 'owner-olga': ENV.SCOPEHAVEN_TARGET_OLGA, 'worker-svc': ENV.SCOPEHAVEN_TARGET_WORKER });
const PRINCIPALS = Object.keys(TOKENS);
const ACTORS = Object.freeze({
  sam: { principalId: 'agent-sam', credentialEnv: 'SCOPEHAVEN_TARGET_SAM' }, tia: { principalId: 'agent-tia', credentialEnv: 'SCOPEHAVEN_TARGET_TIA' },
  olga: { principalId: 'owner-olga', credentialEnv: 'SCOPEHAVEN_TARGET_OLGA' }, worker: { principalId: 'worker-svc', credentialEnv: 'SCOPEHAVEN_TARGET_WORKER' },
});

// Step builders. Every access change, approval and drain is followed by an
// expectStatus precondition, so a change that did not take effect aborts the
// run (and an aborted run never passes). Refund responses accept a denial, so
// an over-blocking build is judged by its failed controls, not aborted.
const req = (id, actorId, path, body, extra = {}) => ({ request: { id, actorId, method: 'POST', path, body, timeoutMs: 15000 }, ...extra });
const expect = (request, codes) => ({ expectStatus: { request, in: codes } });
const target = (ticket = 'T-1', extra = {}) => ({ ticket, amount: 20, recipient: 'cust-a', ...extra });
const approve = (approvalId, userId, t = target()) => [req(`approve-${approvalId}`, 'olga', '/api/admin/approve', { approvalId, userId, ...t }), expect(`approve-${approvalId}`, [200])];
const admin = (verb, userId) => [req(`${verb}-${userId}`, 'olga', `/api/admin/${verb}`, { userId }), expect(`${verb}-${userId}`, [200])];
const ANSWERED = [200, 403, 409];
const refund = (id, actorId, approvalId, t = target(), extra = {}) => req(id, actorId, '/api/assistant/refund', { ...t, approvalId }, extra);
const queue = (id, actorId, approvalId, t = target()) => [req(id, actorId, '/api/assistant/queue-refund', { ...t, approvalId }), expect(id, [202])];
const drain = (id, codes = [200]) => [req(id, 'worker', '/api/worker/drain', {}), expect(id, codes)];
const settle = [{ sleep: SETTLE_MS }, { mark: 'after' }];
const commitsOn = ticket => ({ source: 'sql-audit-table', name: 'refund.commit', resource: `tickets/${ticket}` });
const forbid = (id, title, ticket = 'T-1') => ({ id, title, severity: 'critical', from: 'changed', to: 'after', effect: { kind: 'effect.none', select: commitsOn(ticket) } });
const count = (id, title, ticket, expected = 1, severity = 'control') => ({ id, title, severity, from: 'changed', to: 'after', effect: { kind: 'effect.count', select: commitsOn(ticket), expected } });
const PAYMENTS_RULE = holds => [{ id: 'payments', method: 'POST', pathPrefix: '/v1/payments', holds }];
const awaitPay = as => ({ awaitHold: { rule: 'payments', as, timeoutMs: 10000 } });

// guards: the server-side repairs whose removal must make the forbidden variant fail.
// expect: the refunds per ticket the desk must hold at the end of each variant.
export const CASES = Object.freeze([
  { id: 'AC-LATE-REVOKE', title: 'Access removed after the payment step starts, before commit', guards: ['commitRecheck'], gateRules: PAYMENTS_RULE(1),
    steps: twin => [...approve('APR-1', 'agent-sam'), ...approve('APR-9', 'agent-sam', target('T-9')), refund('refund', 'sam', 'APR-1', target(), { background: true }), awaitPay('pay'),
      ...(twin ? [] : [...admin('suspend', 'agent-sam'),
        // Request-level check: a fresh request after the suspension is refused in every build.
        refund('fresh', 'sam', 'APR-9', target('T-9'))]),
      { mark: 'changed' }, { release: { hold: 'pay' } }, { awaitResponse: { request: 'refund' } }, expect('refund', ANSWERED), ...settle],
    assertions: twin => twin ? [count('AC-LATE-REVOKE-TWIN', 'With access unchanged, the paused refund commits once', 'T-1')]
      : [forbid('AC-LATE-REVOKE', 'No refund commits after access is removed inside the payment step'), forbid('AC-LATE-REVOKE-FRESH-EFFECT', 'The refused fresh request commits nothing', 'T-9')],
    refusals: twin => twin ? [] : [{ id: 'AC-LATE-REVOKE-FRESH', title: 'A fresh request after the suspension is refused (request-level check, every build)', request: 'fresh', codes: [401] }],
    expect: twin => twin ? { 'T-1': 1 } : {} },
  { id: 'AC-INFLIGHT-REGRANT', title: 'Access revoked and regranted while the refund is paused: the old authorization does not carry over', guards: ['commitRecheck'], gateRules: PAYMENTS_RULE(1),
    steps: twin => [...approve('APR-1', 'agent-sam'), refund('refund', 'sam', 'APR-1', target(), { background: true }), awaitPay('pay'),
      ...(twin ? [] : [...admin('suspend', 'agent-sam'), ...admin('regrant', 'agent-sam')]),
      { mark: 'changed' }, { release: { hold: 'pay' } }, { awaitResponse: { request: 'refund' } }, expect('refund', ANSWERED), ...settle],
    assertions: twin => twin ? [count('AC-INFLIGHT-REGRANT-TWIN', 'With grants unchanged, the paused refund commits once', 'T-1')]
      : [forbid('AC-INFLIGHT-REGRANT', 'A refund authorized before a revoke and regrant does not commit')],
    expect: twin => twin ? { 'T-1': 1 } : {} },
  { id: 'AC-REGRANT', title: 'An approval issued before a revoke does not revive after a regrant', guards: ['grantsVersionBinding'], gateRules: [],
    steps: twin => twin ? [...approve('APR-1', 'agent-sam'), { mark: 'changed' }, refund('refund', 'sam', 'APR-1'), expect('refund', ANSWERED), ...settle]
      : [...approve('APR-1', 'agent-sam'), ...admin('suspend', 'agent-sam'), ...admin('regrant', 'agent-sam'), ...approve('APR-2', 'agent-sam', target('T-2')), { mark: 'changed' },
        refund('refund-old', 'sam', 'APR-1'), expect('refund-old', ANSWERED), refund('refund-new', 'sam', 'APR-2', target('T-2')), expect('refund-new', ANSWERED), ...settle],
    assertions: twin => twin ? [count('AC-REGRANT-TWIN', 'Without a revoke, the same approval commits once', 'T-1')]
      : [forbid('AC-REGRANT', 'A pre-revoke approval cannot commit a refund after the regrant'), count('AC-REGRANT-FRESH', 'A fresh approval after the regrant still commits once', 'T-2')],
    expect: twin => twin ? { 'T-1': 1 } : { 'T-2': 1 } },
  { id: 'AC-TARGET', title: 'An approval covers only the exact ticket, recipient and amount it named', guards: ['approvalBinding'], gateRules: [],
    steps: twin => twin ? [...approve('APR-1', 'agent-sam'), { mark: 'changed' }, refund('refund', 'sam', 'APR-1'), expect('refund', ANSWERED), ...settle]
      : [...approve('APR-1', 'agent-sam'), ...approve('APR-2', 'agent-sam'), ...approve('APR-3', 'agent-sam'), ...approve('APR-4', 'agent-sam'), ...approve('APR-5', 'agent-sam'), { mark: 'changed' },
        refund('to-recipient', 'sam', 'APR-1', target('T-1', { recipient: 'cust-b' })), expect('to-recipient', ANSWERED),
        refund('more-amount', 'sam', 'APR-2', target('T-1', { amount: 50 })), expect('more-amount', ANSWERED),
        refund('less-amount', 'sam', 'APR-3', target('T-1', { amount: 10 })), expect('less-amount', ANSWERED),
        refund('other-ticket', 'sam', 'APR-4', target('T-9')), expect('other-ticket', ANSWERED),
        refund('other-user', 'tia', 'APR-5'),
        // The queued path is held to the same binding: the worker must not commit what the approval did not cover.
        ...approve('APR-6', 'agent-sam'), ...approve('APR-7', 'agent-sam'),
        req('queue-recipient', 'sam', '/api/assistant/queue-refund', { ...target('T-1', { recipient: 'cust-b' }), approvalId: 'APR-6' }), expect('queue-recipient', [202, 403]),
        req('queue-other-user', 'tia', '/api/assistant/queue-refund', { ...target(), approvalId: 'APR-7' }),
        ...drain('drain'), ...settle],
    assertions: twin => twin ? [count('AC-TARGET-TWIN', 'A refund matching its approval commits once', 'T-1')]
      : [forbid('AC-TARGET', 'No refund commits for a target the approval did not cover', 'T-1'), forbid('AC-TARGET-TICKET', 'No refund commits on a ticket the approval did not name', 'T-9')],
    refusals: twin => twin ? [] : [
      { id: 'AC-TARGET-OTHER-USER', title: 'Another user cannot spend this user\'s approval (request-level check, every build)', request: 'other-user', codes: [403] },
      { id: 'AC-TARGET-OTHER-USER-QUEUED', title: 'Another user cannot queue work under this user\'s approval (request-level check, every build)', request: 'queue-other-user', codes: [403] }],
    expect: twin => twin ? { 'T-1': 1 } : {} },
  { id: 'AC-QUEUED', title: 'Queued work does not commit after its requester loses access', guards: ['commitRecheck'], gateRules: [],
    steps: twin => [...approve('APR-1', 'agent-sam'), ...approve('APR-2', 'agent-tia', target('T-2')), ...queue('queue-sam', 'sam', 'APR-1'), ...queue('queue-tia', 'tia', 'APR-2', target('T-2')),
      ...(twin ? [] : admin('suspend', 'agent-sam')), { mark: 'changed' }, ...drain('drain'), ...settle],
    assertions: twin => twin ? [count('AC-QUEUED-TWIN', 'With access unchanged, the queued refund commits once', 'T-1'), count('AC-QUEUED-TWIN-OTHER', 'The other user\'s queued refund commits once', 'T-2')]
      : [forbid('AC-QUEUED', 'A queued refund does not commit after its requester is suspended'), count('AC-QUEUED-OTHER', 'A queued refund from a user who kept access still commits once', 'T-2')],
    expect: twin => twin ? { 'T-1': 1, 'T-2': 1 } : { 'T-2': 1 } },
  { id: 'AC-QUEUED-REGRANT', title: 'Queued work does not commit under authority that was revoked and regranted', guards: ['commitRecheck'], gateRules: [],
    steps: twin => [...approve('APR-1', 'agent-sam'), ...queue('queue', 'sam', 'APR-1'), ...(twin ? [] : [...admin('suspend', 'agent-sam'), ...admin('regrant', 'agent-sam')]),
      { mark: 'changed' }, ...drain('drain'), ...settle],
    assertions: twin => twin ? [count('AC-QUEUED-REGRANT-TWIN', 'With grants unchanged, the queued refund commits once', 'T-1')]
      : [forbid('AC-QUEUED-REGRANT', 'A refund queued before a revoke and regrant does not commit')],
    expect: twin => twin ? { 'T-1': 1 } : {} },
  { id: 'AC-RETRY', title: 'A retry after a failed acknowledgement does not commit a second refund', guards: ['idempotentRetry', 'commitRecheck'], gateRules: [], failAfterCommitOnce: twin => !twin, failBeforeCommitOnce: twin => twin,
    steps: twin => twin
      // The twin's first drain fails before committing, so the retry must commit;
      // two distinct jobs on one ticket also show deduplication is per job, not per ticket.
      ? [...approve('APR-1', 'agent-sam'), ...approve('APR-2', 'agent-sam'), ...queue('queue-1', 'sam', 'APR-1'), ...queue('queue-2', 'sam', 'APR-2'), { mark: 'changed' }, ...drain('drain-1', [500]), ...drain('drain-2'), ...settle]
      : [...approve('APR-1', 'agent-sam'), ...queue('queue', 'sam', 'APR-1'), { mark: 'changed' }, ...drain('drain-1', [500]), ...drain('drain-2'), ...settle],
    assertions: twin => twin ? [count('AC-RETRY-TWIN', 'A retry after a failure before commit commits, and two distinct jobs on one ticket both commit', 'T-1', 2)]
      : [count('AC-RETRY', 'A retried job leaves exactly one refund', 'T-1', 1, 'critical')],
    expect: twin => twin ? { 'T-1': 2 } : { 'T-1': 1 } },
  // AC-RETRY's crash comes after the approval is marked used. Its retry is deduplicated by
  // idempotentRetry, but with that guard removed the commit-time recheck still refuses it (the
  // approval is used), so the guard is redundant there and AC-RETRY reads the same either way.
  // Here the crash loses the approval mark, the recheck passes the retry, and only the job's
  // idempotency key stops the second refund. Another user's job on another ticket in the same
  // drain is the same-run control: deduplication must not swallow other work in that drain.
  { id: 'AC-RETRY-UNMARKED', title: 'A retry after a crash that lost the approval mark does not commit a second refund', guards: ['idempotentRetry'], gateRules: [],
    failMidCommitOnce: twin => !twin, failBeforeCommitOnce: twin => twin,
    steps: twin => twin
      // The twin's first drain fails before anything is written, so the retry must commit.
      ? [...approve('APR-1', 'agent-sam'), ...queue('queue', 'sam', 'APR-1'), { mark: 'changed' }, ...drain('drain-1', [500]), ...drain('drain-2'), ...settle]
      : [...approve('APR-1', 'agent-sam'), ...approve('APR-2', 'agent-tia', target('T-2')), ...queue('queue', 'sam', 'APR-1'), ...queue('queue-other', 'tia', 'APR-2', target('T-2')),
        { mark: 'changed' }, ...drain('drain-1', [500]), ...drain('drain-2'), ...settle],
    assertions: twin => twin ? [count('AC-RETRY-UNMARKED-TWIN', 'A retry after a failure before commit commits once', 'T-1')]
      : [count('AC-RETRY-UNMARKED', 'A job retried after a partial commit leaves exactly one refund', 'T-1', 1, 'critical'),
        count('AC-RETRY-UNMARKED-OTHER', 'Another user\'s job in the same drain still commits once', 'T-2')],
    expect: twin => twin ? { 'T-1': 1 } : { 'T-1': 1, 'T-2': 1 } },
  { id: 'AC-CONCURRENT', title: 'Two users at once: only the revoked user loses the in-flight refund', guards: ['commitRecheck'], gateRules: PAYMENTS_RULE(2),
    steps: twin => [...approve('APR-1', 'agent-sam'), ...approve('APR-2', 'agent-tia', target('T-2')),
      refund('refund-sam', 'sam', 'APR-1', target(), { background: true }), refund('refund-tia', 'tia', 'APR-2', target('T-2'), { background: true }), awaitPay('p1'), awaitPay('p2'),
      ...(twin ? [] : admin('suspend', 'agent-sam')), { mark: 'changed' }, { release: { hold: 'p1' } }, { release: { hold: 'p2' } },
      { awaitResponse: { request: 'refund-sam' } }, { awaitResponse: { request: 'refund-tia' } }, expect('refund-sam', ANSWERED), expect('refund-tia', ANSWERED), ...settle],
    assertions: twin => twin ? [count('AC-CONCURRENT-TWIN', 'Without a revoke, the first user commits once', 'T-1'), count('AC-CONCURRENT-TWIN-OTHER', 'Without a revoke, the second user commits once', 'T-2')]
      : [forbid('AC-CONCURRENT', 'The revoked user commits no refund while the other user is in flight'), count('AC-CONCURRENT-OTHER', 'The user who kept access still commits once', 'T-2')],
    expect: twin => twin ? { 'T-1': 1, 'T-2': 1 } : { 'T-2': 1 } },
]);

export function caseSequence(def, { twin = false } = {}) {
  return { schema: SEQUENCE_SCHEMA, id: twin ? `${def.id}-TWIN` : def.id, actors: ACTORS, steps: [{ mark: 'start' }, ...def.steps(twin)], assertions: def.assertions(twin) };
}
const definitionOf = def => ({ id: def.id, guards: def.guards, gateRules: def.gateRules, failAfterCommitOnce: [false, true].map(t => Boolean(def.failAfterCommitOnce?.(t))),
  failBeforeCommitOnce: [false, true].map(t => Boolean(def.failBeforeCommitOnce?.(t))),
  // Only a case that uses the hook names it, so the cases written before it keep their hash (the guard coverage matrix's d2c637169da8).
  ...(def.failMidCommitOnce ? { failMidCommitOnce: [false, true].map(t => Boolean(def.failMidCommitOnce(t))) } : {}), refusals: [false, true].map(t => def.refusals?.(t) ?? []),
  expect: [false, true].map(t => def.expect(t)), forbidden: caseSequence(def), twin: caseSequence(def, { twin: true }) });
export const casesHash = (cases = CASES) => digest(cases.map(definitionOf));

// Compare the desk's final refunds per ticket with the declared expectation. TWO rows, because
// the comparison answers two different questions and they are not the same KIND of claim:
// "no MORE refunds than declared" is a prohibition, a boundary
// claim, and "the declared refunds all happened" is an allowed-use control. An earlier version answered
// both in one row and took its severity from whichever way it turned out, so a missing allowed
// refund on a forbidden run was reported as a CRITICAL fail, and a passing boundary row called
// itself a control and kept a pass that rested on the desk's own tables.
function finalStateResults(def, twin, state, aborted) {
  const declared = def.expect(twin), tickets = [...new Set([...Object.keys(declared), ...Object.keys(state.refunds)])].sort();
  const over = tickets.filter(t => (state.refunds[t] ?? 0) > (declared[t] ?? 0));
  const under = tickets.filter(t => (state.refunds[t] ?? 0) < (declared[t] ?? 0));
  const summary = tickets.map(t => `${t}: ${state.refunds[t] ?? 0} of ${declared[t] ?? 0}`).join(', ') || 'no refunds, none declared';
  const prefix = twin ? `${def.id}-TWIN` : def.id;
  // A run that did not reach its access change, approval or drain cannot answer either question.
  const stopped = aborted ? `The run stopped early (${aborted}); refunds: ${summary}.` : null;
  // Every reading here is the desk's OWN refunds and jobs tables, so both rows are
  // subject-writable. The boundary row's pass is held; the control keeps its verdict and states
  // what that costs.
  const boundary = (() => {
    const id = `${prefix}-FINAL-STATE`, title = 'The desk\'s own refunds table holds no refund the declared outcome did not allow';
    if (over.length) return { id, title, severity: 'critical', status: 'fail', verdict: 'fail', custody: 'subject-writable',
      basis: `More refunds than declared (${summary}).` };
    if (stopped) return { id, title, severity: 'critical', status: 'inconclusive', verdict: 'inconclusive', custody: 'subject-writable', basis: stopped };
    return { id, title, severity: 'critical', status: 'inconclusive', verdict: 'inconclusive', custody: 'subject-writable',
      custodyReason: CUSTODY_REASON, basis: `No refund beyond the declared outcome (${summary}). ${CUSTODY_BASIS}` };
  })();
  const control = (() => {
    const id = `${prefix}-FINAL-STATE-WORK`, title = 'The declared refunds all happened and the jobs settled';
    if (stopped) return { id, title, severity: 'control', status: 'inconclusive', verdict: 'inconclusive', custody: 'subject-writable', basis: stopped };
    if (state.pendingJobs) return { id, title, severity: 'control', status: 'inconclusive', verdict: 'inconclusive', custody: 'subject-writable',
      basis: `${state.pendingJobs} job${state.pendingJobs === 1 ? '' : 's'} not in a terminal state after the settle; the work did not finish.` };
    if (under.length) return { id, title, severity: 'control', status: 'fail', verdict: 'fail', custody: 'subject-writable',
      basis: `Fewer refunds than declared (${summary}).` };
    return { id, title, severity: 'control', status: 'pass', verdict: 'pass', custody: 'subject-writable',
      basis: `No declared refund is missing and every job reached a terminal state (${summary}). ${CONTROL_CUSTODY_LIMIT}` };
  })();
  return [boundary, control];
}

// Revocation closure (Root-Scoped Quiescence, arXiv 2609.21284). A revocation is CLOSED only
// when no carrier still holds the authority it retired - which is a different claim from "no
// late commit was seen", and the harness folded the two together: a parked job landed in
// pendingJobs and read `inconclusive`, the same as a reading we could not take.
//
// Both halves rest on POSITIVE evidence, per the paper's Def. 5 (p.13): a verified open carrier
// is Not-Quiescent, while missing evidence is Indeterminate, and only QUIESCENT certifies
// release (p.8). So "we saw no commit" is never an input here.
//
//   revoked   the desk logged REVOKE_ACTION for the principal AND its grants counter moved.
//   carrier   an open job (any status outside TERMINAL_JOB_STATUSES) belonging to that
//             principal whose own grants_version is BELOW the principal's current one. That
//             comparison is what makes it retired authority rather than merely open work, and
//             it is per-identity, not a count (p.17: tokens are exact identities).
//
// Whether a revoke was attempted comes from the sequence THIS harness sent, never from the
// app's account of itself: a build that logs nothing must read inconclusive, not "nothing to
// close". Both tables are the application's own, so a FAIL stands and a PASS is held.
const declaresRevoke = (def, twin) => def.steps(twin).some(step => step?.request?.path === '/api/admin/suspend');

export function revokeClosureResults(def, twin, state, aborted) {
  if (!declaresRevoke(def, twin)) return [];
  const id = `${twin ? `${def.id}-TWIN` : def.id}-REVOKE-CLOSE`;
  const title = 'No open job still carries authority the revoke retired';
  const base = { id, title, severity: 'critical', custody: 'subject-writable' };
  const indeterminate = basis => [{ ...base, status: 'inconclusive', verdict: 'inconclusive', basis }];
  if (aborted) return indeterminate(`The run stopped early (${aborted}); closure cannot be read.`);
  const closure = state.closure ?? null;
  if (closure === null) return indeterminate('The desk returned no closure reading, so nothing here is established.');
  if (closure.unreadTables.length) return indeterminate(`Could not read ${closure.unreadTables.join(', ')}, so whether the revoke closed is unknown.`);
  // The sequence revoked, so the desk must say so. A silent revoke is a missing fence record.
  const revoked = closure.revocations.filter(r => r.action === REVOKE_ACTION).map(r => r.resource.replace(/^users\//, ''));
  if (!revoked.length) return indeterminate(`The sequence revoked access, but the desk recorded no ${REVOKE_ACTION}; a missing fence record is not closure.`);
  const byId = new Map(closure.users.map(user => [user.id, user]));
  // Logged a revoke but the counter never moved: two of the app's own records disagree.
  const conflicting = revoked.filter(principal => (byId.get(principal)?.grantsVersion ?? 1) <= 1);
  if (conflicting.length) return indeterminate(`${conflicting.join(', ')}: a ${REVOKE_ACTION} is recorded but the grants counter never moved, so the two records conflict.`);
  const carriers = closure.openJobs.filter(job => revoked.includes(job.userId) && job.grantsVersion < byId.get(job.userId).grantsVersion);
  if (carriers.length) {
    const named = carriers.map(job => `job ${job.id} (${job.userId}, status ${job.status}, grants v${job.grantsVersion} < v${byId.get(job.userId).grantsVersion})`).join('; ');
    return [{ ...base, status: 'fail', verdict: 'fail',
      basis: `Revocation is not closed: ${named}. Work rooted at a revoked principal is still able to run.` }];
  }
  return [{ ...base, status: 'inconclusive', verdict: 'inconclusive', custodyReason: CUSTODY_REASON,
    basis: `No open job carries authority retired from ${revoked.join(', ')} (${closure.openJobs.length === 1 ? '1 job still open, not a carrier' : `${closure.openJobs.length} jobs still open, none of them carriers`}). ${CUSTODY_BASIS}` }];
}

// A forbidden commit the audit table reports, on a ticket the refunds table
// holds nothing for, is conflicting evidence, judged per ticket.
function reconcile(results, assertions, state) {
  const ticketOf = id => assertions.find(a => a.id === id && a.effect.kind === 'effect.none')?.effect.select.resource?.replace(/^tickets\//, '');
  return results.map(r => { const ticket = ticketOf(r.id);
    return r.status === 'fail' && ticket && !(state.refunds[ticket] > 0)
      ? { ...r, status: 'inconclusive', verdict: 'conflicting', basis: `${r.basis} The desk's refunds table holds nothing on ${ticket}, so the evidence conflicts.` } : r; });
}
// Request-level refusals, read from the run's own response timeline.
function refusalResults(def, twin, run) {
  return (def.refusals?.(twin) ?? []).map(({ id, title, request, codes }) => {
    const response = run.timeline.find(e => e.step === 'response' && e.request === request);
    const status = !response ? 'inconclusive' : codes.includes(response.status) ? 'pass' : 'fail';
    // The status is the application's own answer, observed first-hand on
    // the request path. It decides a RESPONSE CONTRACT, pass or fail, exactly as a core HTTP
    // status check does, and never that no effect happened - so the row keeps its verdict, is
    // tagged subject-writable rather than independent, and says in its own basis that what
    // changed is decided elsewhere. It is never a clean headline on its own.
    const answered = response ? `Answered ${response.status}; expected ${codes.join(' or ')}.` : 'The request was never answered.';
    return { id, title, severity: 'critical', status, verdict: status, custody: 'subject-writable', decides: 'response-contract',
      basis: `${answered} Response level: whether anything CHANGED is decided by the effect and final-state rows.` };
  });
}

// One fresh database, payment stub, gate and app per run, so no run sees another run's state.
// Desk hooks (overBlock, auditCommits, insertRefunds, parkRevokedJobs) are test-only; see desk.mjs.
export async function runCase(def, { twin = false, recheckAtCommit = false, repairs = {}, hooks = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-access-change-'));
  let payments, gate, app;
  try {
    const dbPath = join(dir, 'desk.db');
    payments = await startFakePayments();
    gate = createHoldGate({ upstream: payments.url, rules: def.gateRules });
    await gate.start();
    app = await startAccessDesk({ dbPath, paymentsUrl: gate.url, tokens: TOKENS, recheckAtCommit, repairs, ...hooks,
      failAfterCommitOnce: Boolean(def.failAfterCommitOnce?.(twin)), failBeforeCommitOnce: Boolean(def.failBeforeCommitOnce?.(twin)),
      failMidCommitOnce: Boolean(def.failMidCommitOnce?.(twin)) });
    const observers = [
      createSqliteAuditObserver({ path: dbPath, principals: PRINCIPALS, audit: { table: 'audit_log', idColumn: 'id', actorColumn: 'actor', actionColumn: 'action', resourceColumn: 'resource',
        actions: { 'refund.commit': 'insert', 'refund.queue': 'insert', 'refund.dedupe': 'update', 'approval.create': 'access-change', 'user.suspend': 'access-change', 'user.regrant': 'access-change' }, deniedActions: ['refund.denied'] } }),
      gate.observer(),
    ];
    const run = await runSequence(caseSequence(def, { twin }), { origin: app.origin, observers, gate, env: ENV });
    const state = app.finalState(), finals = finalStateResults(def, twin, state, run.aborted);
    const closure = revokeClosureResults(def, twin, state, run.aborted);
    return { ...run, results: [...reconcile(run.results, def.assertions(twin), state), ...refusalResults(def, twin, run), ...finals, ...closure], desk: { address: app.address, repairs: app.repairs } };
  } finally {
    for (const resource of [gate, app, payments]) if (resource) await resource.stop().catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
}

// Every case and its twin against one build. A case passes only when its
// forbidden variant and its twin both pass; anything else stays visible.
export async function runAccessChangeCases({ recheckAtCommit = false, repairs = {}, hooks = {}, cases = CASES } = {}) {
  const rows = [];
  for (const def of cases) {
    const options = { recheckAtCommit, repairs, hooks };
    const [forbidden, twin] = [await runCase(def, options), await runCase(def, { ...options, twin: true })];
    const statuses = [...forbidden.results, ...twin.results].map(r => r.status);
    // A confirmed fail outranks an observer or harness error; neither is ever a pass.
    const status = statuses.includes('fail') ? 'fail' : statuses.includes('error') ? 'error' : statuses.every(s => s === 'pass') ? 'pass' : 'inconclusive';
    rows.push({ id: def.id, title: def.title, guards: def.guards, status, aborted: { forbidden: forbidden.aborted, twin: twin.aborted },
      // custody and custodyReason travel with the row. The projection dropped them, so a tag the
      // sequence assertions already carried and the one the final-state row now carries were both
      // invisible in the report, which is where a reader looks for whose record decided a verdict.
      results: [...forbidden.results, ...twin.results].map(({ id, title, severity, status: s, verdict, basis, custody = null, custodyReason, decides }) =>
        ({ id, title, severity, status: s, verdict, basis, custody, ...(custodyReason ? { custodyReason } : {}), ...(decides ? { decides } : {}) })),
      runDigests: { forbidden: forbidden.runDigest, twin: twin.runDigest }, desk: forbidden.desk });
  }
  const counts = { pass: 0, fail: 0, inconclusive: 0, error: 0 }; for (const r of rows) counts[r.status]++;
  return { schema: ACCESS_CHANGE_SCHEMA, build: { repairs: rows[0]?.desk.repairs ?? null, hooks }, casesHash: casesHash(cases), counts, rows,
    limitations: ['Owned synthetic access desk on loopback with synthetic users; no customer system, model or payment provider.',
      `Sequence assertions read the app's audit table. A final-state check of the desk's own refunds and jobs tables, after a ${SETTLE_MS} ms settle, catches unaudited or late commits and unsettled jobs. A commit later than the settle is not seen.`,
     'Each case\u2019s final state is answered by TWO rows on every run, because the comparison answers two different KINDS of claim, and both rows are tagged custody subject-writable: the refunds and jobs tables they read are the application\u2019s own. The boundary row (-FINAL-STATE) asserts a prohibition, that the refunds table holds no refund the declared outcome did not allow. It is critical; MORE refunds than declared is a fail; and its PASS is HELD at inconclusive, because nothing outside the application witnesses it. The control row (-FINAL-STATE-WORK) asserts allowed use, that the declared refunds all happened and the jobs settled. It is a control; FEWER refunds than declared is a fail; a job still not terminal after the settle is inconclusive; and it KEEPS its pass, with custody stated as a limit rather than withheld. So a forbidden run reports a held boundary row beside a passing control row, and the two are not in conflict: one says nothing extra was committed, the other says nothing declared went missing. An earlier version answered both questions in one row and took that row\u2019s severity from how it turned out, so a missing allowed refund on a forbidden run was reported as a CRITICAL fail, and a passing boundary row called itself a control and kept a pass it had not earned. Fails are unchanged either way: custody withholds passes, it never excuses a fail.',
      'A run that did not reach its access change, approval or drain is aborted and never passes.',
      'On the repaired build these nine declared cases read inconclusive, because only the app\'s own records decide them (custody) and no shipped observer held outside the app sees these writes. They cover these nine cases only, not every interleaving or every contract for "revoked".'] };
}
