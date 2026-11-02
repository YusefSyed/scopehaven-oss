// Typed claims and the residual. An auditor reads a report's scope and its limitations first: what each
// verdict rests on, and what the run did not show. Offline verification has identifiability limits (two runs, one safe and one
// harmful, can leave the same visible evidence), so every row says how strong its claim is and every export lists what is left.
//
// Each row carries one claim type:
//   exact        decided from records held outside the application: a request-path observer (custody independent or
//                observer-held) that recorded the forbidden effect, or the response ScopeHaven itself received, and, for a verdict
//                decided by absence (an absence or count pass, or a fail because a required effect did not appear), with the
//                profile's declared channels all observed (src/channels.mjs) from complete windows
//   risk-bound   decided from records the application can write (custody subject-writable, its own action log, or no custody
//                recorded), or a sampled property (a conversation judged over trials), or a verdict decided by absence whose
//                channels are undeclared or were read from net change: it is only as good as the risk that those records or that
//                sample are wrong, or that the effect went a way no observer watched
//   descriptive  decides nothing: inconclusive, error or not applicable, or a pass the readers do not count (declared channels
//                not observed, a forwarded or remote pass with no same-route control)
// Evidence origins that record no per-clause custody (the owned fixtures, the pinned handler and framework runs) are risk-bound
// whenever they decide a row: their records are the subject's own.
//
// The residual: the channels not observed (src/channels.mjs), the checks that read inconclusive with their reasons, the
// allowed-use pairing that did not hold (required controls that did not pass, forwarded or remote passes with no same-route
// control, absence selectors with no allowed-use twin), and the declared observers that did not run in a row's window (an HTTP
// run's from its windows, a sequence's from its sealed evidence), or that none is declared; for any other origin it says its
// observers are not read.
//
// Presentation only: it reads the saved run, never changes a row, and is outside every hash. The run's JSON export is the sealed
// record itself and carries neither; the HTML report, SARIF, the comparison exports and the compact summary state both, and
// ./scopehaven export --format residual writes them alone.
//
// Pure: no I/O.
import { INDEPENDENT_CUSTODY } from './custody.mjs';
import { ADMISSION_FINDING } from './app-log-verdicts.mjs';
import { unpairedForwardedPasses, unpairedReasonOf } from './forwarded-pairing.mjs';
import { allowedUseControlIds } from './allowed-use.mjs';
import { channelReadings, channelStatement, rowChannelState, absenceBearing, absenceBearingPass } from './channels.mjs';
import { EFFECT_ASSERTION_PATTERN, BACKEND_ASSERTION } from './http-effects.mjs';
import { CLAIM_ASSERTION_PATTERN } from './http-claims.mjs';
import { IDENTITY_ASSERTION, IDENTITY_REASONS, PRECONDITION_ASSERTION, PRECONDITION_REASONS } from './contracts.mjs';

export const CLAIM_TYPES = Object.freeze(['exact', 'risk-bound', 'descriptive']);
export const RESIDUAL_SCHEMA = 'scopehaven-residual/1';
export const CLAIM_RULE = 'Claim types: exact is decided from records held outside the application (a request-path observer that recorded the forbidden effect, or the response ScopeHaven received), and for a verdict decided by absence (an absence or count pass, or a fail because a required effect did not appear) only with every declared channel observed in its window by records held outside the application, nothing unaccounted on them, in a confined run; risk-bound is decided from records the application can write (or with no custody recorded), from a sampled property (a conversation judged over trials), or from a verdict decided by absence whose channels are undeclared, read from net change or watched only through the application\'s own records; descriptive decides nothing (inconclusive, error, not applicable, or a pass the gate does not count). A claim type says what a verdict rests on, not whether the record is accurate.';
export const RESIDUAL_NOTE = 'The residual is what this run did not show: channels not observed or carrying an unaccounted effect, checks that read inconclusive and why, allowed-use pairing that did not hold, and declared observers that did not run or ran incomplete. Nothing listed here is a pass.';
export const SEQUENCE_CHANNELS_NOTE = 'Channels undeclared: a sequence declares no channels, so each absence pass rests only on the observers that decided it.';
// The HTTP connector's rows carry custody per clause (effect and claim assertions); their other assertions are the response
// ScopeHaven itself received. A sequence row carries its one verdict's custody in its trace (integrations/sequences/native.mjs).
const HTTP_ORIGIN = 'local-http-response', SEQUENCE_ORIGIN = 'local-sequence', CONVERSATION_ORIGIN = 'local-conversation';
const UNPASSED = Object.freeze(['inconclusive', 'error', 'not_applicable']);
const TAGS = Object.freeze(['custodyReason', 'settlement', 'pairing', 'attribution', 'later']);
const PAIRING = Object.freeze(['selector-unpaired', 'selector-not-shown-to-match', 'allowed-use-not-declared']);

const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const rowsOf = run => (Array.isArray(run?.results) ? run.results.filter(plain) : []);
const assertionsOf = row => (Array.isArray(row?.assertions) ? row.assertions.filter(plain) : []);
const tagged = a => Object.hasOwn(a, 'custody');
// An effect or claim clause: it is decided from observer windows, so its custody, not the response, says what it rests on.
const clauseOf = a => typeof a.name === 'string' && (EFFECT_ASSERTION_PATTERN.test(a.name) || CLAIM_ASSERTION_PATTERN.test(a.name));
const uncustodied = a => clauseOf(a) && !tagged(a);
const independent = a => INDEPENDENT_CUSTODY.includes(a.custody) && a.appLog?.finding !== ADMISSION_FINDING;
const effectData = row => (Array.isArray(row?.trace) && plain(row.trace[1]?.data) ? row.trace[1].data : null);
const sampleOf = row => (Number.isInteger(row?.trace?.[0]?.data?.trials) ? row.trace[0].data.trials : null);
// The record behind one effect or claim assertion ("Observed effect N (...)" is effects[N-1], "Observed claim N (...)" claims[N-1]).
function clauseRecord(row, a) {
  const data = effectData(row), effect = EFFECT_ASSERTION_PATTERN.exec(a.name ?? ''), claim = CLAIM_ASSERTION_PATTERN.exec(a.name ?? '');
  const list = effect ? data?.effects : claim ? data?.claims : null, index = Number((effect ?? claim)?.[1]) - 1;
  return Array.isArray(list) && plain(list[index]) ? list[index] : null;
}
// Which way a failing clause was decided: 'presence' when a record shows an effect the clause forbids (effect.none, effect.only,
// which fails only with an effect outside its set, a count above its number), 'absence' when the windows held no effect the clause
// required (effect.exists, a count below its number, a success claim). A count by applications (countBy) is decided by its
// applications (sealed as applications.low and .high; a fail has its number outside that interval, so low above it is a double),
// not its sends: replays under one key raise the sends only. Anything else, including a record that cannot be read (a countBy
// record without readable applications among them), reads absence, the weaker reading.
function failDirection(kind, matched, expected, applications, countBy) {
  if (kind === 'effect.none') return 'presence';
  if (kind === 'effect.count') {
    const readable = plain(applications) && Number.isInteger(applications.low);
    if (countBy !== undefined && !readable) return 'absence';
    const n = readable ? applications.low : matched;
    return Number.isInteger(n) && Number.isInteger(expected) && n > expected ? 'presence' : 'absence';
  }
  if (kind === 'effect.only') return Number.isInteger(matched) && matched > 0 ? 'presence' : 'absence';
  return 'absence';
}
const assertionDirection = (row, a) => {
  if (a.absenceDecided === true) return 'absence';
  const record = clauseRecord(row, a);
  return failDirection(record?.kind ?? record?.clause, record?.matched, record?.expected, record?.applications, record?.countBy);
};
// A verdict decided by absence, read against the run's declared channels (src/channels.mjs): exact only when every declared
// channel was observed in the row's window by records held outside the application, nothing unaccounted, in a confined run.
const ABSENCE_SUBJECT = Object.freeze({ pass: 'An absence or count pass', fail: 'A fail decided by absence' });
function channelClaim(run, row, kind) {
  const state = rowChannelState(run, row), subject = ABSENCE_SUBJECT[kind];
  if (state === null) return { type: 'risk-bound', basis: kind === 'pass' ? 'An absence or count pass with channels undeclared: an effect that left the application by a way no observer watches is in no window.'
    : 'A fail decided by absence (no matching effect where one was required) with channels undeclared: the effect may have happened by a way no observer watches.' };
  if (state.reasons.length) return { type: 'risk-bound', basis: kind === 'pass' ? `An allowed-use control keeps this pass, but the declared channels do not support its absence (${state.reasons.join(', ')}).`
    : `A fail decided by absence, but the declared channels do not show the effect could not have happened another way (${state.reasons.join(', ')}).` };
  const net = state.channels.filter(c => c.netChange).map(c => c.id), weak = state.channels.filter(c => !c.independent).map(c => c.id);
  if (net.length) return { type: 'risk-bound', basis: `${subject} whose declared store channel${net.length === 1 ? '' : 's'} (${net.join(', ')}) ${net.length === 1 ? 'was' : 'were'} read from net change in its window: a write undone within the window is invisible.` };
  if (weak.length) return { type: 'risk-bound', basis: `${subject} whose declared channel${weak.length === 1 ? '' : 's'} (${weak.join(', ')}) ${weak.length === 1 ? 'was' : 'were'} watched only through records the application can write: they show what the application recorded.` };
  return { type: 'exact', basis: kind === 'pass' ? 'An absence or count pass with every declared channel observed in its window by records held outside the application, nothing unaccounted on them, in a confined run.'
    : 'A fail decided by absence: no matching effect appeared where one was required, with every declared channel observed in its window by records held outside the application, nothing unaccounted on them, in a confined run.' };
}
const UNCUSTODIED_BASIS = 'An effect or claim clause of this row carries no custody record (a run saved before per-clause custody), so it is read as resting on records the application can write.';

// The run-wide readings a row's claim depends on, computed once per run.
function contextOf(run) {
  const withheld = new Map(channelReadings(run).map(r => [r.id, r.reasons]));
  const unpaired = new Set(unpairedForwardedPasses(run));
  const statement = channelStatement(run);
  // A sequence assertion's declared effect and its sealed result, by row id (its verdict fields are in the row, its declaration and
  // window coverage in the evidence).
  const inner = plain(run?.sequenceEvidence?.run) ? run.sequenceEvidence.run : null;
  const sequenceEffects = new Map((Array.isArray(inner?.assertions) ? inner.assertions : []).filter(plain).map(a => [a.id, plain(a.effect) ? a.effect : null]));
  const sequenceResults = new Map((Array.isArray(inner?.results) ? inner.results : []).filter(plain).map(r => [r.id, r]));
  return { withheld, unpaired, unpairedReason: unpairedReasonOf(run?.targetContext), statement, sequenceEffects, sequenceResults };
}

// One row's claim type and the sentence that says what it rests on.
function claimWith(row, run, ctx) {
  if (!plain(row)) return { type: 'descriptive', basis: 'An unrecognized row decides nothing.' };
  if (UNPASSED.includes(row.status)) return { type: 'descriptive', basis: `Decides nothing: the row is ${row.status === 'not_applicable' ? 'not applicable' : row.status}.` };
  if (!['pass', 'fail'].includes(row.status)) return { type: 'descriptive', basis: 'Decides nothing: the row has no recognized status.' };
  if (ctx.withheld.has(row.id)) return { type: 'descriptive', basis: `Decides nothing: the pass reads inconclusive on the declared channels (${ctx.withheld.get(row.id).join(', ')}).` };
  if (ctx.unpaired.has(row.id)) return { type: 'descriptive', basis: `Decides nothing: the gate does not count this pass (${ctx.unpairedReason}).` };
  const assertions = assertionsOf(row);
  // A conversation is judged over trials from its replies, other actors' views and customer-visible state the application serves,
  // and the row does not say which of them decided it: a sampled property, whichever way it went.
  if (run?.evidenceOrigin === CONVERSATION_ORIGIN) {
    const trials = sampleOf(row), rate = plain(row.trace?.[0]?.data?.policy?.rate);
    return { type: 'risk-bound', basis: `A sampled property: judged over ${trials ?? 'an unrecorded number of'} trial${trials === 1 ? '' : 's'} of the conversation${rate ? ' against a failure-rate limit' : ''}, from replies and from views and state the application serves; another sample may differ.` };
  }
  if (run?.evidenceOrigin === SEQUENCE_ORIGIN) return sequenceClaim(row, ctx);
  if (run?.evidenceOrigin !== HTTP_ORIGIN && !assertions.some(tagged))
    return { type: 'risk-bound', basis: 'This evidence origin records no custody per clause: the verdict rests on records the subject under test keeps.' };
  if (row.status === 'fail') {
    const failing = assertions.filter(a => a.status === 'fail'), clauses = failing.filter(clauseOf);
    // A record held outside the application shows an effect the check forbids: exact. A fail because a required effect did not
    // appear rests on the same premise as an absence pass (it could not have gone a way no observer watched).
    const shown = clauses.filter(a => tagged(a) && independent(a) && assertionDirection(row, a) === 'presence');
    if (shown.length) return { type: 'exact', basis: `A record held outside the application shows the forbidden effect (${[...new Set(shown.map(a => a.custody))].join(', ')} custody).` };
    if (failing.some(a => !clauseOf(a))) return { type: 'exact', basis: 'The response ScopeHaven received fails the declared contract.' };
    if (clauses.some(uncustodied)) return { type: 'risk-bound', basis: UNCUSTODIED_BASIS };
    const absent = clauses.filter(a => independent(a));
    if (!absent.length) return { type: 'risk-bound', basis: clauses.some(a => a.appLog?.finding === ADMISSION_FINDING)
      ? 'Decided by the application\'s own action log (an admission): a record the application can write.' : 'Decided only by records the application can write (subject-writable custody).' };
    if (absent.some(a => a.absenceDecided === true)) return { type: 'risk-bound', basis: 'A fail decided by a declared field absent from the request body: the receiver may have applied a default or an alias.' };
    return channelClaim(run, row, 'fail');
  }
  if (assertions.some(uncustodied)) return { type: 'risk-bound', basis: UNCUSTODIED_BASIS };
  const weak = assertions.filter(a => tagged(a) && !independent(a));
  if (weak.length) return { type: 'risk-bound', basis: 'A clause of this pass rests on a record the application can write (custody subject-writable, or no observer decided it); an allowed-use control keeps such a pass as a tag.' };
  // An absence or count pass of any severity is read against the declared channels here (the readers withhold only boundary rows).
  if (absenceBearingPass(row)) return channelClaim(run, row, 'pass');
  return { type: 'exact', basis: assertions.some(tagged) ? 'Every clause rests on records held outside the application, and the response met the declared contract.' : 'The response ScopeHaven received meets the declared contract; that is all this row shows.' };
}

// A sequence row: a response-status row is the status ScopeHaven received; an effect row is decided by its observers' custody.
function sequenceClaim(row, ctx) {
  const data = plain(row.trace?.[0]?.data) ? row.trace[0].data : null;
  if (data?.kind === 'response-status') return { type: 'exact', basis: `The status ScopeHaven received ${row.status === 'pass' ? 'meets' : 'fails'} the declared expectation; that is all this row shows.` };
  if (data?.kind !== 'effect') return { type: 'risk-bound', basis: 'A sequence row whose verdict fields could not be read: no custody is recorded for it.' };
  const held = INDEPENDENT_CUSTODY.includes(data.custody), effect = ctx.sequenceEffects.get(row.id);
  if (row.status === 'fail') {
    if (!held) return { type: 'risk-bound', basis: 'Decided only by records the application can write (subject-writable custody).' };
    return failDirection(effect?.kind, ctx.sequenceResults.get(row.id)?.matched, effect?.expected) === 'presence' ? { type: 'exact', basis: `A record held outside the application shows the forbidden effect (${data.custody} custody).` }
      : { type: 'risk-bound', basis: 'A fail decided by absence (no matching effect where one was required); a sequence declares no channels, so the effect may have happened by a way no observer watches.' };
  }
  if (!held) return { type: 'risk-bound', basis: 'This pass rests on a record the application can write; an allowed-use control keeps such a pass as a tag.' };
  if (absenceBearing(effect?.kind)) return { type: 'risk-bound', basis: 'An absence or count pass with channels undeclared (a sequence declares none): an effect that left the application by a way no observer watches is in no window.' };
  return { type: 'exact', basis: `Decided by a record held outside the application (${data.custody} custody).` };
}

export const claimOf = (row, run) => claimWith(row, run, contextOf(run));
// Every row's claim, in row order: [{ id, type, basis }].
export function claimTypes(run) {
  const ctx = contextOf(run);
  return rowsOf(run).map(row => ({ id: row.id, ...claimWith(row, run, ctx) }));
}
export const claimCounts = claims => Object.fromEntries(CLAIM_TYPES.map(type => [type, claims.filter(c => c.type === type).length]));

// The reasons a row reads inconclusive: tag codes, its decision, the reason an identity, precondition or backend assertion records,
// the windows that ran partial or failed, a sequence row's inner verdict and custody reason, and the readings that withhold a pass.
const windowCause = w => `window-${w.coverage}:${String(w.instanceId)}`;
// A sequence row's window coverage is sealed per observer in its evidence (integrations/sequences/native.mjs).
const sequenceWindows = (row, ctx) => { const coverage = ctx.sequenceResults?.get(row.id)?.window?.coverage; return Array.isArray(coverage) ? coverage.filter(plain) : []; };
const windowCauses = (row, ctx) => [...(Array.isArray(effectData(row)?.windows) ? effectData(row).windows : []), ...sequenceWindows(row, ctx)]
  .filter(w => plain(w) && ['partial', 'failed'].includes(w.coverage)).map(windowCause);
const keyOf = (reasons, text, fallback) => (typeof text === 'string' && Object.keys(reasons).find(key => text.startsWith(reasons[key]))) || fallback;
function assertionReasons(a, unsettled) {
  if (a.name === IDENTITY_ASSERTION) return [keyOf(IDENTITY_REASONS, a.actual, 'identity-not-established')];
  if (a.name === PRECONDITION_ASSERTION) return [keyOf(PRECONDITION_REASONS, a.actual, 'precondition-not-established')];
  // The backend assertion names the reason only when it is all that is unsettled (src/contract-http.mjs reads it the same way).
  if (a.name === BACKEND_ASSERTION) return unsettled.every(x => x.name === BACKEND_ASSERTION) ? ['backend-evidence-required-response-only'] : [];
  return TAGS.filter(key => typeof a[key] === 'string').map(key => a[key]);
}
function inconclusiveEntry(row, ctx) {
  const unsettled = assertionsOf(row).filter(a => ['inconclusive', 'error'].includes(a.status));
  // A sequence row's verdict fields (integrations/sequences/native.mjs): an effect row's or a response-status row's inner verdict.
  const sequence = plain(row.trace?.[0]?.data) && ['effect', 'response-status'].includes(row.trace[0].data.kind) ? row.trace[0].data : null;
  const reasons = [...(typeof row.decision === 'string' && row.decision !== row.status ? [row.decision] : []),
    ...(sequence && typeof sequence.verdict === 'string' && ![row.status, 'pass', 'fail'].includes(sequence.verdict) ? [sequence.verdict] : []),
    ...(sequence && typeof sequence.custodyReason === 'string' ? [sequence.custodyReason] : []),
    ...unsettled.flatMap(a => assertionReasons(a, unsettled)), ...windowCauses(row, ctx),
    ...(ctx.withheld.get(row.id) ?? []), ...(ctx.unpaired.has(row.id) ? [ctx.unpairedReason] : [])];
  return { id: row.id, status: row.status, reads: row.status === 'error' ? 'error' : 'inconclusive', reasons: reasons.length ? [...new Set(reasons)] : ['unverified'],
    assertions: unsettled.map(a => String(a.name ?? 'unnamed assertion')) };
}

// The run's declared observers, each with its instance id and the windows of each row it had one in: an HTTP run's (v3) from the
// rows' sealed windows, a sequence's from its sealed evidence (observers and each effect result's per-observer coverage). null for
// any other origin, whose observers (a conversation's victim views, say) the residual does not read.
function declaredObservers(run, ctx) {
  if (![HTTP_ORIGIN, SEQUENCE_ORIGIN].includes(run?.evidenceOrigin)) return null;
  if (run?.evidenceOrigin === SEQUENCE_ORIGIN) {
    const inner = run?.sequenceEvidence?.run, effectRows = rowsOf(run).filter(row => row.trace?.[0]?.data?.kind === 'effect');
    return (Array.isArray(inner?.observers) ? inner.observers.filter(o => plain(o) && typeof o.instanceId === 'string') : [])
      .map(o => ({ id: o.instanceId, type: typeof o.kind === 'string' ? o.kind : 'observer', instance: o.instanceId, rows: effectRows, windowsOf: row => sequenceWindows(row, ctx) }));
  }
  const sealed = rowsOf(run).filter(row => Array.isArray(effectData(row)?.windows));
  return (Array.isArray(run?.observers) ? run.observers.filter(o => plain(o) && typeof o.id === 'string' && typeof o.type === 'string') : [])
    .map(o => ({ id: o.id, type: o.type, instance: `${o.type}-${o.id}`, rows: sealed, windowsOf: row => effectData(row).windows }));
}
// Declared observers that did not run in a row's window (no window from them, or a window that could not report), or ran there
// incomplete (a partial window).
function observersNotRunning(declared) {
  return declared.map(o => {
    const mine = row => o.windowsOf(row).filter(w => plain(w) && w.instanceId === o.instance);
    return { id: o.id, type: o.type, failedIn: o.rows.filter(row => mine(row).some(w => w.coverage === 'failed')).map(row => row.id), missingIn: o.rows.filter(row => !mine(row).length).map(row => row.id),
      partialIn: o.rows.filter(row => mine(row).some(w => w.coverage === 'partial')).map(row => row.id) };
  }).filter(o => o.failedIn.length || o.missingIn.length || o.partialIn.length);
}

// What the run did not show.
export function residualOf(run) {
  const ctx = contextOf(run), rows = rowsOf(run), statement = ctx.statement;
  const channels = statement === null ? (run?.evidenceOrigin === SEQUENCE_ORIGIN ? { declared: false, note: SEQUENCE_CHANNELS_NOTE } : null) : !statement.declared ? { declared: false, note: statement.note }
    : { declared: true, readable: statement.readable, confinement: statement.confinement, tier: statement.tier, gap: statement.gap,
      unobserved: statement.channels.filter(c => c.unobservedIn.length).map(c => ({ id: c.id, kind: c.kind, rows: [...c.unobservedIn] })),
      unaccounted: statement.channels.filter(c => c.unaccountedIn.length).map(c => ({ id: c.id, kind: c.kind, rows: [...c.unaccountedIn] })),
      unlisted: statement.unlisted.map(u => ({ observer: u.observer, type: u.type, rows: [...u.rows] })),
      // Allowed-use controls keep their passes, but one whose absence the declared channels do not support is listed here.
      controls: rows.filter(row => row.severity === 'control' && absenceBearingPass(row)).map(row => ({ id: row.id, reasons: rowChannelState(run, row)?.reasons ?? [] })).filter(c => c.reasons.length),
      netChange: statement.channels.filter(c => c.netChange).map(c => c.id), withheld: statement.withheld.map(r => ({ id: r.id, reasons: [...r.reasons] })) };
  const inconclusive = rows.filter(row => ['inconclusive', 'error'].includes(row.status) || ctx.withheld.has(row.id) || ctx.unpaired.has(row.id)).map(row => inconclusiveEntry(row, ctx));
  const required = allowedUseControlIds(run).ids;
  const notPassed = required.filter(id => rows.find(row => row.id === id)?.status !== 'pass');
  const unpairedSelectors = rows.flatMap(row => assertionsOf(row).filter(a => PAIRING.includes(a.pairing)).map(a => ({ id: row.id, assertion: String(a.name ?? 'unnamed assertion'), reason: a.pairing })));
  const declared = declaredObservers(run, ctx);
  return { schema: RESIDUAL_SCHEMA, channels, inconclusive,
    controls: { required: required.length, notPassed, unpairedPasses: ctx.unpaired.size ? { reason: ctx.unpairedReason, checks: [...ctx.unpaired] } : null, unpairedSelectors },
    observersDeclared: declared === null ? null : declared.length, observers: observersNotRunning(declared ?? []), note: RESIDUAL_NOTE };
}

// The residual export (./scopehaven export --format residual): the run's identity, every row's claim and the residual.
export function residualDocument(run) {
  const claims = claimTypes(run);
  return { schemaVersion: 1, document: RESIDUAL_SCHEMA, runId: run?.id ?? null, targetId: run?.targetId ?? null, evidenceOrigin: run?.evidenceOrigin ?? null,
    evidenceIntegritySha256: run?.integrity?.sha256 ?? null, certification: 'These are observed checks, not a safety certification.',
    claims, claimCounts: claimCounts(claims), claimRule: CLAIM_RULE, residual: residualOf(run) };
}
