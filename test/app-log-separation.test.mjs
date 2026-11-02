// App logs never reach a custody decision (src/app-log-rules.mjs). Three layers, each pinned:
//   1. structural: app logs are declared under "appLogs", never "observers"; the connector keeps them in their own list and
//      seals their windows as data.appLogWindows; the validator binds them apart from the observer windows;
//   2. one choke point, src/effect-events.mjs custodyWindows, called first by every custody entry point: it refuses a window
//      from a report-only source. This file enumerates the entry points (S1) and scans the source for new ones (S2);
//   3. the belt in src/custody.mjs: a pass with a report-only window among its windows reads inconclusive in every role (S3).
// It also pins the connector's ordering (S6): the app-log start mark after every custody start mark, the cut before any
// witness request, the collect after every custody collect, and no request of its own. Synthetic data, injected transport and
// observers, a temporary file: no socket, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, appendFileSync, writeFileSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { digest } from '../src/domain.mjs';
import { makeEffect, evaluateEffectAssertion, otherActorCommit, unfollowedLate, collectWindow, custodyWindows, REPORT_ONLY_SOURCES, PRESENCE_ONLY_SOURCES, validateWindow } from '../src/effect-events.mjs';
import { decideEffects, decideSealed, decideClause, recomputeEffectTrace, bindSealedWindows, redecideResolved, OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { laterFindings } from '../src/later-outcome.mjs';
import { settlementFindings } from '../src/http-settlement.mjs';
import { attributionFindings, resourceUncertain, backgroundUnseen } from '../src/http-attribution.mjs';
import { closureOwners } from '../src/id-closure.mjs';
import { pairingFindings } from '../src/http-pairing.mjs';
import { failureAdmitted } from '../src/http-rests-on.mjs';
import { subjectIntegrityVerdict, clauseCustody, onlyClauseCustody, decidingWindows, decidesAbsence, decidesPresence, custodyOf } from '../src/custody.mjs';
import { verifyClaim, observedOutcome } from '../integrations/claim-check/verify.mjs';
import { verifyCoverageClaim } from '../integrations/claim-check/coverage.mjs';
import { evaluateCollateral } from '../integrations/collateral/collateral.mjs';
import { decideAssertion } from '../integrations/sequences/sequence.mjs';
import { runEvidSubjectCases } from '../integrations/evid-subject/cases.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { compareRuns } from '../src/runner.mjs';
import { admissionsFor, admissionRows } from '../src/app-log-verdicts.mjs';
import { serviceRoleNotes } from '../integrations/observers/supabase-rules.mjs';

const PAY = 'pay.example';
const APP_EVENT = (seq, spec = {}) => makeEffect({ source: 'app-log', observer: { kind: 'app-action-log', instanceId: 'app-log-actions' }, seq, actor: 'member-1', operation: 'send', name: PAY, resource: 'POST *', outcome: 'committed', ...spec });
// An app-log window crafted to make a pass: a committed send the clause wants, named by the actor it pins.
const W = () => ({ source: 'app-log', instanceId: 'app-log-actions', scope: { operations: ['send'], names: [PAY], actorAttribution: 'principal', evidence: 'presence-only' }, coverage: 'complete', reason: null, events: [APP_EVENT(128)] });
const SELECT = { operation: 'send', name: PAY };
const isGuard = error => error?.code === 'app-log-in-custody-path';
const ROW = () => ({ effects: [{ kind: 'effect.exists', select: SELECT, verdict: 'pass' }], windows: [W()] });

// S1: every guarded custody entry point refuses a report-only window, at its own call site: each guard names its entry point
// (custodyWindows' where), so removing one guard is caught even when a guard further down would also refuse the window.
// [label, call]: the label is the entry point whose own guard must refuse (a thin wrapper names the guard it relies on).
const GUARDED = {
  'src/effect-events.mjs#evaluateEffectAssertion': ['evaluateEffectAssertion', () => evaluateEffectAssertion({ kind: 'effect.exists', select: SELECT }, [W()])],
  'src/effect-events.mjs#otherActorCommit': ['otherActorCommit', () => otherActorCommit({ kind: 'effect.exists', select: { ...SELECT, actor: 'member-1' } }, [W()], 'member-1')],
  'src/effect-events.mjs#unfollowedLate': ['unfollowedLate', () => unfollowedLate([[W()]])],
  'src/effect-events.mjs#collectWindow': ['collectWindow', () => collectWindow({ source: 'app-log', instanceId: 'app-log-actions', scope: W().scope, collect: async () => ({ events: [], coverage: 'complete' }) }, {}, {})],
  'src/http-effects.mjs#decideEffects': ['decideEffects', () => decideEffects([{ kind: 'effect.exists', select: SELECT }], [W()])],
  'src/http-effects.mjs#decideSealed': ['decideEffects', () => decideSealed({ effects: [{ kind: 'effect.exists', select: SELECT }] }, [W()], 'boundary')],
  'src/http-effects.mjs#decideClause': ['evaluateEffectAssertion', () => decideClause({ kind: 'effect.exists', select: SELECT }, [W()], 'boundary')],
  // In-doubt resolution: the run-end re-decide stage guards every row's windows before it binds or decides anything.
  'src/http-effects.mjs#redecideResolved': ['redecideResolved', () => redecideResolved([{ effects: [{ kind: 'effect.exists', select: SELECT }], claims: [], readings: [], role: 'boundary', windows: [W()] }], [])],
  'src/later-outcome.mjs#laterFindings': ['laterFindings', () => laterFindings({ rows: [{ raw: [], settled: [], paired: [], windows: [W()], role: 'boundary' }], gaps: [[], []], readingOf: () => null })],
  'src/http-settlement.mjs#settlementFindings': ['settlementFindings', () => settlementFindings([ROW()], [[], []], null)],
  'src/http-attribution.mjs#attributionFindings': ['attributionFindings', () => attributionFindings([ROW()], [[], []], undefined, { background: [{ id: 'bg', select: { operation: 'send' } }] })],
  'src/http-attribution.mjs#resourceUncertain': ['resourceUncertain', () => resourceUncertain([W()])],
  'src/http-attribution.mjs#backgroundUnseen': ['backgroundUnseen', () => backgroundUnseen([{ id: 'bg', select: { operation: 'send' } }], [W()])],
  'src/id-closure.mjs#closureOwners': ['closureOwners', () => closureOwners([ROW()], [[], []], undefined, () => true)],
  'src/http-pairing.mjs#pairingFindings': ['pairingFindings', () => pairingFindings([{ id: 'C', actorId: 'member', role: 'control', ...ROW() }], [])],
  'src/http-rests-on.mjs#failureAdmitted': ['failureAdmitted', () => failureAdmitted({ assertions: [], trace: [{}, { data: { effects: [{ kind: 'effect.exists', select: SELECT }] } }] }, [W()], 'member-1')],
  'src/custody.mjs#subjectIntegrityVerdict': ['subjectIntegrityVerdict', () => subjectIntegrityVerdict({ proposed: 'pass', support: [W()], select: SELECT })],
  'integrations/evid-subject/cases.mjs#runEvidSubjectCases': ['subjectIntegrityVerdict', () => runEvidSubjectCases({ support: [W()] })],
  'integrations/claim-check/verify.mjs#observedOutcome': ['observedOutcome', () => observedOutcome([W()], 'T-1')],
  'integrations/claim-check/verify.mjs#verifyClaim': ['verifyClaim', () => verifyClaim({ claim: { status: 'done' }, reply: 'done', windows: [W()] })],
  'integrations/claim-check/coverage.mjs#verifyCoverageClaim': ['verifyCoverageClaim', () => verifyCoverageClaim({ task: {}, claim: {}, reply: '', windows: [W()] })],
  'integrations/collateral/collateral.mjs#evaluateCollateral': ['evaluateCollateral', () => evaluateCollateral({}, [W()])],
  'integrations/sequences/sequence.mjs#decideAssertion': ['decideAssertion', () => decideAssertion({ effect: { kind: 'effect.exists', select: SELECT } }, [W()], false)],
  // Admissions read app-log windows apart; their custody windows argument is guarded like any other.
  'src/app-log-verdicts.mjs#admissionsFor': ['admissionsFor', () => admissionsFor([{ kind: 'effect.none', select: SELECT }], { windows: [W()], appLogWindows: [], records: [] })],
  'src/app-log-verdicts.mjs#admissionRows': ['admissionRows', () => admissionRows([{ id: 'c', principal: 'p', requestId: null, decisions: [], windows: [W()], appLogWindows: [] }])],
  // The Supabase service-role notes read a pinned clause over the check's windows through evaluateEffectAssertion first
  // (a thin wrapper of its guard), and write notes only, never a verdict.
  'integrations/observers/supabase-rules.mjs#serviceRoleNotes': ['evaluateEffectAssertion', () => serviceRoleNotes({ effects: [{ kind: 'effect.exists', select: { ...SELECT, actor: 'member-1' } }] }, [W()], { principals: ['member-1'] })],
};
// The binders refuse an app-log window by binding observer windows to declared observers (tested below, not by label).
const BINDERS = ['src/http-effects.mjs#bindSealedWindows', 'src/http-effects.mjs#recomputeEffectTrace', 'src/http-settlement.mjs#validateSettlementRecord', 'src/app-log-verdicts.mjs#bindAppLogWindows'];
// The belt (S3): these read custody or deciding windows; a report-only window never decides or passes there.
const BELTED = ['src/custody.mjs#clauseCustody', 'src/custody.mjs#onlyClauseCustody', 'src/custody.mjs#decidingWindows', 'src/custody.mjs#decidesAbsence', 'src/custody.mjs#decidesPresence'];
// Reviewed exemptions, by why each decides no custody verdict over windows it was handed.
const EXEMPT = {
  'the choke point itself': ['src/effect-events.mjs#custodyWindows', 'src/effect-events.mjs#custodyRunWindows'],
  // Read-back (src/http-readback.mjs): reads only the coverage and reason of the check's window for its own pg-snapshot instance id, to
  // block the sealed record when that window is not net-only (a missing window blocks it too); never an event, never a pass from a window.
  'reads one pg-snapshot window\'s coverage to block a read-back; decides nothing from windows': ['src/http-readback.mjs#decideReadBack', 'src/http-readback.mjs#recomputeReadBack'],
  'seals what a guarded path decided, or records declarations': ['src/app-log-verdicts.mjs#sealAppLogWindows', 'src/http-effects.mjs#effectTrace', 'src/http-effects.mjs#sealWindows', 'src/http-effects.mjs#declaredObserverRecord',
    // Checks a pg-wal window's declaration shape (keys, sorted distinct names, refused a subset of declared); called only from
    // validateWindow and the tests, it decides nothing over windows.
    'src/effect-events.mjs#validWireDeclaration'],
  'reads custody of windows a guarded caller chose': ['src/custody.mjs#bestCustody', 'src/custody.mjs#weakestCustody', 'src/custody.mjs#custodyOf'],
  'a window helper reached only from guarded callers': ['src/in-doubt.mjs#admitInDoubt', 'src/in-doubt.mjs#inDoubtAdmitted', 'src/in-doubt.mjs#carryInDoubt', 'src/effect-events.mjs#admitScoped', 'src/effect-events.mjs#admitTemplateLift', 'src/effect-events.mjs#templateLiftCount', 'src/effect-events.mjs#blindToFields', 'src/effect-events.mjs#coverageFor', 'src/effect-events.mjs#exactFor', 'src/effect-events.mjs#lateEntries',
    'src/effect-events.mjs#markUnfollowed', 'src/effect-events.mjs#onlyCoverageFor', 'src/effect-events.mjs#validScoped', 'src/effect-events.mjs#windowSees', 'src/effect-events.mjs#crossSeen', 'src/effect-events.mjs#seesThroughCross', 'src/egress-rules.mjs#crossSeenOf', 'src/effect-events.mjs#decidedByGaps', 'src/http-effects.mjs#applySettle',
    'src/http-settlement.mjs#matchedLocated', 'src/effect-events.mjs#withoutEvents', 'src/idempotency.mjs#countApplications', 'src/idempotency.mjs#keyedReplays', 'src/effect-outcome.mjs#upstreamBound',
    // Suspend-aware custody time: the connector applies these to the windows it collected, and the binder (bindSealedWindows) reads a
    // sealed window as their fixed point; they only ever mark a window partial, never decide a clause.
    'src/suspend-clock.mjs#applySuspendShort', 'src/suspend-clock.mjs#carriesSuspendShort',
    'integrations/collateral/only.mjs#judgeOnly', 'integrations/collateral/only.mjs#evaluateOnly', 'integrations/collateral/only.mjs#onlyScopedComplete', 'integrations/collateral/only.mjs#validateSpans', 'integrations/collateral/only.mjs#outcomeJudgedSends',
    'integrations/collateral/only.mjs#composeSnapshots', 'integrations/collateral/only.mjs#reconcile', 'integrations/collateral/only.mjs#bySource', 'integrations/collateral/only.mjs#quiescent', 'integrations/collateral/only.mjs#instanceOf',
    // In-doubt resolution: late records are normalized, bound onto (and read back from) the events of admitted egress windows only
    // (an app-log window is never admitted, so no record binds there); the stage (redecideResolved) and the validator's binders call them.
    'src/in-doubt.mjs#lateEntriesFor', 'src/in-doubt.mjs#bindResolutions', 'src/in-doubt.mjs#sealedResolutions', 'src/http-effects.mjs#bindSealedResolutions',
    // The request feed: bindResolutions derives a request-feed read's result over the admitted egress window it binds onto.
    'src/request-feed-rules.mjs#deriveRequestFeed',
    // The key collapse's identity and retention rule: countApplications, keyedReplays and the request feed's
    // deriveRequestFeed read a key group through it; it reads one window's published declaration and decides nothing.
    'src/key-identity.mjs#keyGroupIdentity',
    // Read-back: bindResolutions derives a read-back read's result over the admitted egress window it binds onto.
    'src/read-back-rules.mjs#deriveReadBack',
    // Names the undeclared hosts of a clause's egress windows for its text (decideEffects, guarded, calls it); it reads
    // only http-egress windows and decides nothing. The connector and the binder admit those windows for it, as for gate B.
    'src/http-effects.mjs#undeclaredHostsSeen', 'src/effect-events.mjs#admitDisclosure', 'src/effect-events.mjs#disclosureAdmitted',
    // Names the service-role tools whose writes a pinned clause selects, for its text (decideEffects, guarded, calls it); it
    // reads only pg-snapshot and pg-wal windows that name principals (an app-log window's instance never qualifies) and decides nothing.
    'src/http-effects.mjs#serviceRoleToolsSeen'],
  // The outbound canary sink: it judges seeded-canary units ({ destination, canaries, scanned }), never effect events. A pass
  // needs authoritative: true on every required collector's window, which no presence-only or app-written record carries, so an
  // app-log window can only ever leave it inconclusive.
  'judges seeded-canary windows, never effect windows; a pass needs authoritative evidence': ['integrations/observers/canary-sink.mjs#judgeCanaries'],
  // zeroRowAgreesWithWindow checks a sealed zero-row record against its observer's bound window inside the binder
  // (recomputeEffectTrace); it only ever refuses a record, never decides a clause.
  'validates a window or event; decides nothing': ['src/http-effects.mjs#zeroRowAgreesWithWindow', 'src/effect-events.mjs#validateWindow', 'src/effect-events.mjs#consistentScopedCaptures', 'src/idempotency.mjs#consistentIdempotencyRun', 'src/idempotency.mjs#consistentSigningRun', 'src/request-feed-rules.mjs#consistentRequestFeedRun', 'src/read-back-rules.mjs#consistentReadBackRun', 'src/effect-events.mjs#makeEffect',
    'src/effect-events.mjs#validateEffect', 'src/effect-events.mjs#validateScope'],
  'takes no windows (selectors, assertions, decisions, records, text)': [
    ...['absentFieldBasis', 'baseSelector', 'credentialFrom', 'definitelyAbsent', 'formDecimalBasis', 'formDecimalSends', 'loopbackRequestAllowed', 'matchState', 'matches', 'originForm', 'validateEffectAssertion', 'validateSelector', 'wallNs'].map(n => `src/effect-events.mjs#${n}`),
    ...['absenceFields', 'applyLater', 'laterFields', 'backendObserved', 'claimDecisionsOf', 'declaredClaim', 'declaredEffect', 'effectAssertionName', 'effectAssertionRows', 'effectDecisionsOf', 'effectStatus', 'observerInstanceId', 'roleOfSeverity', 'sealedClaims', 'settleDeclared',
      'validateDeclaredClaims', 'validateDeclaredEffect', 'validateCheckEffects', 'outcomeJudgedProfileProblem', 'forbiddenSelectors', 'recordedDestinations',
      // rls-zero-row: a sealed zero-row record, a row's own assertions and the decisions after every other stage; no window.
      'applyZeroRow', 'responseContractSucceeded', 'validZeroRowRecord', 'zeroRowClause', 'zeroRowFields', 'zeroRowFinding'].map(n => `src/http-effects.mjs#${n}`),
    // feedKeyCustody reads one provider feed's declaration (a window's scope.feed, or a run record's feed), never a window.
    ...['anchorOf', 'custodyUpgrade', 'feedKeyCustody', 'linkDigest', 'onlyCustodyUpgrade', 'roleOfSeverity', 'verifyChain'].map(n => `src/custody.mjs#${n}`),
    ...['applySettlement', 'correlationDeclared', 'finalSettleMs', 'fitsSelector', 'onlyDeclared', 'selectorsOf', 'settlementFields', 'settlementTokens'].map(n => `src/http-settlement.mjs#${n}`),
    ...['applyAttribution', 'attributionDeclarationProblem', 'attributionFields', 'attributionRecord', 'backgroundClassifier', 'backgroundProblem', 'fitsWide', 'validateAttributionRecord'].map(n => `src/http-attribution.mjs#${n}`),
    ...['absenceClause', 'acceptsSuccess', 'allowedUseGuards', 'applyPairing', 'needsPairing', 'pairingFields', 'pinsOf', 'positiveClause', 'selectorPairs', 'showsPin', 'unguardedAbsences', 'unpairedSelectors'].map(n => `src/http-pairing.mjs#${n}`),
    // restsOnReleases reads rows whose failed controls failureAdmitted (guarded) admitted; the rest read routes and records.
    ...['anchorCandidate', 'anchored', 'captureTypes', 'carriedByRequest', 'cleanObject', 'controlScopeEvidence', 'controlScopeShape', 'declaredPartners', 'outcomeText', 'pathSegments', 'recordClasses', 'recordEntryShape', 'recordForm',
      'recordPredicate', 'recordPredicates', 'recordText', 'recordedRouteShape', 'refusalLike', 'relatedByRoute', 'requestTexts', 'restsOnProblem', 'restsOnReleases', 'restsOnView', 'routeSegments', 'sentRoute', 'separated', 'servedRecords',
      'singular', 'staticRecordPartners', 'staticRestsOnRelated', 'stemKeys'].map(n => `src/http-rests-on.mjs#${n}`),
    ...['allocate', 'allocateOptions', 'expectedOf', 'netChange', 'validateOnlyAssertion', 'outcomeJudgedOverlap', 'outcomeJudgedProfileProblem'].map(n => `integrations/collateral/only.mjs#${n}`),
    'src/egress-rules.mjs#objectRecordOf',
    ...['collateralRows', 'collateralStatus', 'validateCollateralSpec'].map(n => `integrations/collateral/collateral.mjs#${n}`),
    ...['readReply', 'statesPhrase'].map(n => `integrations/claim-check/verify.mjs#${n}`),
    ...['coverageStatus', 'namedRecords', 'readCoverageClaim', 'readReply', 'recordDigest', 'validateCoverageTask'].map(n => `integrations/claim-check/coverage.mjs#${n}`),
    ...['acceptanceFor', 'checkAssertion', 'checkStatusAssertion', 'countsOf', 'decideStatusAssertion', 'decideStatusRows', 'requestsOf', 'sequenceHashOf', 'statusAssertionsOf', 'stepActions', 'validateSequence', 'capturesOf', 'runSchemaOf', 'websocketRecord', 'websocketsOf'].map(n => `integrations/sequences/sequence.mjs#${n}`),
    'integrations/evid-subject/cases.mjs#evidSubjectSummary',
  ],
  'builds its observers from observer configs, and an app log is never an observer': ['integrations/sequences/sequence.mjs#runSequence', 'integrations/sequences/sequence.mjs#runDelaySweep',
    'integrations/evaluation-import/verdict-service.mjs#startVerdictService', 'integrations/model-path/model-path.mjs#runModelPath', 'integrations/multiturn/multiturn.mjs#runScenario', 'integrations/core-practice/run-cli.mjs#runCase'],
  'reads observer configuration or run data, not windows': ['src/collector-identity.mjs#collectorDigest', 'src/idempotency.mjs#signingSecretValueClash', 'src/http-scope-text.mjs#signingUnusableLimitation', 'src/egress-rules.mjs#correlationRecorded', 'src/effect-outcome.mjs#forwardRecordOf', 'src/http-timing.mjs#maxDeclaredSettle',
    // Confined launch (src/confine.mjs): the declared observers' provider-side ports, which may not be allowlisted; configuration only, no windows.
    'src/confine.mjs#providerSidePorts',
    // The declared-channel rule (src/channels.mjs): checks a channel declaration's observer ids and types against the declared
    // observers; configuration only, no windows. The module's readers take a saved run, skip report-only windows and decide no clause.
    'src/channels.mjs#channelDeclarationProblem',
    'src/http-timing.mjs#witnessCloseMs', 'src/fixture.mjs#suppliedContext', 'integrations/coverage-report/coverage.mjs#datastoreCoverage', 'integrations/policy-import/matrix.mjs#buildMatrix',
    'integrations/revocation-clock/arrival.mjs#arrivalBrackets', 'integrations/sequences/native.mjs#exportSequenceSuite', 'integrations/claim-check/coverage-cases.mjs#withLogFailures',
    'integrations/core-practice/profiles.mjs#lifecycleProfile', 'integrations/core-practice/profiles.mjs#selfLifecycleProfile', 'integrations/core-practice/profiles.mjs#creatorProfile', 'integrations/core-practice/profiles.mjs#settlementProfile',
    // Later outcomes: the run record's provider feeds that declare outcomes under a later-outcome label (observer records, no windows).
    'src/provider-feed-rules.mjs#laterFeedsOf', 'src/later-outcome.mjs#laterReadings',
    // The request feed: whether a profile's or a run's recorders declare a request feed (observer configs or records, no windows).
    'src/request-feed-rules.mjs#requestFeedsDeclared',
    // Read-back: a recorder's read-back record, and whether and how long a profile's or a run's recorders read back (observer
    // configs or records, no windows).
    'src/read-back-rules.mjs#readBackRecordOf', 'src/read-back-rules.mjs#readBacksDeclared', 'src/read-back-rules.mjs#readBackReserveMs', 'src/read-back-rules.mjs#readBackMaxSettleMs',
    // Other names of a declared provider: a recorder's declared aliases (an observer config or record, no windows).
    'src/egress-rules.mjs#aliasRecordOf',
    // Another recorder's destinations: the destinations a profile's other egress recorders declare (observer configs, no windows).
    'src/egress-rules.mjs#crossDestinationsOf'],
  // The authorization record's window (src/authorization.mjs): guardObserver wraps an observer object so no observer call
  // starts after the record's window ends, and windowRefusal names that ended window as the run's error. Both take the authorization
  // window or an observer, never an evidence window, and decide no clause.
  'takes the authorization window or an observer object, not evidence windows': ['src/authorization.mjs#guardObserver', 'src/authorization.mjs#windowRefusal'],
  // Stripe (integrations/payments-stripe/): judge reads the Stripe read-back observer's own ledger reads (scopehaven-stripe-ledger/1) and its
  // row specs; anything that is not such a read (an evidence or app-log window included) throws or reads read-not-accepted. Its only
  // app-written input is rows.match-ledger's copied refund rows, which pass only when equal to the ledger read.
  'judges its own observer\'s ledger reads, never evidence windows': ['integrations/payments-stripe/verdict.mjs#judge'],
  // The actor capture (integrations/observers/pg-actor.mjs): parseLedger turns the actor capture's own SQL ledger read (ledgerSql's result
  // rows, a fixed column list) into ledger entries; a row of any other shape throws. It takes no evidence or app-log window and
  // decides nothing.
  'parses its own capture\'s SQL ledger rows, never evidence windows': ['integrations/observers/pg-actor.mjs#parseLedger']
};
// Every export of these modules is classified, whatever its parameters are named or however it is exported.
const CUSTODY_MODULES = ['src/effect-events.mjs', 'src/http-effects.mjs', 'src/custody.mjs', 'src/http-settlement.mjs', 'src/http-attribution.mjs', 'src/id-closure.mjs', 'src/http-pairing.mjs', 'src/http-rests-on.mjs',
  'integrations/collateral/only.mjs', 'integrations/collateral/collateral.mjs', 'integrations/claim-check/verify.mjs', 'integrations/claim-check/coverage.mjs', 'integrations/sequences/sequence.mjs', 'integrations/evid-subject/cases.mjs',
  'integrations/evaluation-import/verdict-service.mjs'];

test('S1: every custody entry point refuses an app-log window at its own call site (custodyWindows)', async () => {
  for (const [name, [label, call]] of Object.entries(GUARDED)) {
    let error = null;
    try { await call(); } catch (e) { error = e; }
    assert.ok(isGuard(error), `${name} must refuse an app-log window (got ${error?.code ?? error?.message ?? 'no error'})`);
    assert.ok(error.message.endsWith(` at ${label}.`), `${name} must refuse at its own guard (${label}), not a later one: ${error.message}`);
  }
  // The choke point passes custody windows through unchanged.
  const custody = [{ source: 'http-egress', events: [] }];
  assert.equal(custodyWindows(custody), custody);
  assert.deepEqual(REPORT_ONLY_SOURCES, ['app-log']);
  assert.ok(PRESENCE_ONLY_SOURCES.includes('app-log'));
});

test('S1: the validator binds observer windows to declared observers, so an app-log window in data.windows is refused', () => {
  const declared = [{ id: 'sink', type: 'egress-recorder', settleMs: 500 }];
  const sealed = [{ ...W(), settleMs: 500, lineage: { observer: 'app-action-log', independence: 'application-report' } }];
  assert.throws(() => bindSealedWindows(sealed, declared), /effect-trace/);
  assert.throws(() => recomputeEffectTrace({ type: 'effect-observation', data: { schema: 'scopehaven-effect-evidence/1', effects: [{ kind: 'effect.exists', select: SELECT, verdict: 'pass', matched: 1, custody: null }], windows: sealed } }, undefined, declared));
  // No observer type produces the source.
  assert.ok(!Object.values(OBSERVER_OUTPUT).some(o => o.source === 'app-log'));
});

test('S2: every export of the custody modules, and every exported function elsewhere that takes windows, is classified', async () => {
  const root = fileURLToPath(new URL('..', import.meta.url));
  const classified = new Set([...Object.keys(GUARDED), ...BINDERS, ...BELTED, ...Object.values(EXEMPT).flat()]);
  // (a) The custody modules, enumerated from their live exports: any export syntax, any parameter names.
  const exported = [];
  for (const module of CUSTODY_MODULES) {
    const ns = await import(new URL(`../${module}`, import.meta.url));
    for (const [name, value] of Object.entries(ns)) if (typeof value === 'function' && !/^class\b/.test(Function.prototype.toString.call(value))) exported.push(`${module}#${name}`);
  }
  assert.ok(exported.length >= 170, `the custody modules export ${exported.length} functions`);
  assert.deepEqual(exported.filter(name => !classified.has(name)), [], 'a new export of a custody module must be guarded with custodyWindows (GUARDED), belted, a binder, or reviewed into EXEMPT');
  // (b) Every other module: an exported function or function-valued const whose parameters name windows, rows, gaps, barriers,
  // support, observers or sealed records.
  const NAMES = /\b(windows|window|gaps|barriers|rows|rowsWindows|support|claimWindows|observers|observer|sealed)\b/;
  async function* walk(dir) {
    for (const e of await readdir(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) { if (!['fixtures', 'node_modules'].includes(e.name)) yield* walk(p); }
      else if (e.name.endsWith('.mjs') && !e.name.endsWith('.test.mjs')) yield p;
    }
  }
  const found = [];
  for (const base of ['src', 'integrations']) for await (const file of walk(join(root, base))) {
    const text = await readFile(file, 'utf8');
    for (const m of text.matchAll(/^export (?:async )?function\*? ?([A-Za-z0-9_$]+)\s*\(([^)]*)\)|^export const ([A-Za-z0-9_$]+) = (?:async )?(?:function\*? ?[A-Za-z0-9_$]*\s*\(([^)]*)\)|\(([^)]*)\)|([A-Za-z0-9_$]+)) =>?/gm)) {
      const name = m[1] ?? m[3], params = m[2] ?? m[4] ?? m[5] ?? m[6] ?? '';
      if (NAMES.test(params)) found.push(`${file.slice(root.length)}#${name}`);
    }
  }
  assert.ok(found.length >= 80, 'the scan found the known entry points');
  assert.deepEqual(found.filter(name => !classified.has(name)), [], 'a new function that takes windows must be guarded (GUARDED), belted, a binder, or reviewed into EXEMPT');
});

test('S3: the custody belt reads a pass inconclusive in every role when a report-only window is among its windows', () => {
  const egress = { source: 'http-egress', instanceId: 'egress-recorder-sink', scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] };
  // Mixed: the custody window decided nothing, the match is only in the app log.
  for (const role of ['control', 'boundary']) {
    const held = clauseCustody({ kind: 'effect.exists', select: SELECT, verdict: 'pass', windows: [egress, W()], role });
    assert.equal(held.verdict, 'inconclusive', role);
    assert.equal(held.custody, 'subject-writable');
  }
  // A fail is never touched.
  assert.equal(clauseCustody({ kind: 'effect.none', select: SELECT, verdict: 'fail', windows: [W()], role: 'control' }).verdict, 'fail');
  assert.equal(onlyClauseCustody({ result: { verdict: 'pass', observers: ['app-log-actions'], claimedOperations: ['send'] }, windows: [W()], role: 'control' }).verdict, 'inconclusive');
  // A report-only window never decides presence or absence.
  assert.deepEqual(decidingWindows([W()], { kind: 'effect.exists', select: SELECT, verdict: 'pass' }), []);
  assert.equal(decidesPresence(W(), SELECT), false);
  assert.equal(decidesAbsence({ ...W(), scope: { ...W().scope, evidence: 'authoritative' } }, SELECT), false);
  // Custody of the source is the application's.
  assert.equal(custodyOf({ source: 'app-log' }), 'subject-writable');
  assert.throws(() => validateWindow({ ...W(), scope: { ...W().scope, evidence: 'authoritative' } }), /scope-evidence-source/);
});

// S6: the connector's ordering, shown through the file. The application appends a line at each step; only the request's line
// may land in the check's app-log window.
const LINES = ['refund.create', 'custody.start', 'custody.end', 'custody.collect', 'witness.side'];
function orderingProfile(path) {
  return { id: 'app-log-order', name: 'App log order', applicationId: 'app-log-order', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-app-log',
    actors: { member: { principalId: 'member-1' } }, requiredControlIds: ['WHOAMI'],
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds'] }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250 }],
    appLogs: [{ id: 'actions', use: 'record', log: { file: { path } }, fields: { action: '/event', outcome: '/result', actor: '/actor' }, outcomes: { committed: ['ok'] },
      rules: LINES.map(action => ({ action, operation: 'insert', vocabulary: 'named', name: action })), logActors: { 'member-1': 'member-1' } }],
    checks: [
      { id: 'WHOAMI', title: 'whoami', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'REFUND', title: 'refund', category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/refunds', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 200 }],
        effects: [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: PAY } }] },
    ] };
}
async function orderingRun(t) {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-app-log-order-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'actions.jsonl'); writeFileSync(path, '');
  const line = event => appendFileSync(path, `${JSON.stringify({ event, actor: 'member-1', result: 'ok' })}\n`);
  const calls = [];
  const transport = async (origin, check) => {
    calls.push(check.path.split('?')[0]);
    if (check.path === '/refunds') line('refund.create');
    if (check.path.startsWith('/ping')) line('witness.side');
    return { status: 200, complete: true, jsonParsed: true, json: { ok: true }, bytes: 10 };
  };
  // The egress recorder double: it writes a line at its start mark, its end mark (after the witness) and its collect.
  const factory = configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type];
    let marks = 0;
    return { kind: out.kind, instanceId: `${c.type}-${c.id}`, source: out.source, scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' },
      witnessRequest: { actorId: 'member', method: 'GET', path: '/ping' }, async markWitnessRequest() {},
      async start() {}, async stop() {}, async mark() { line(++marks % 2 ? 'custody.start' : 'custody.end'); return { at: marks, witnessNonce: `nonce-${marks}` }; },
      async collect() { line('custody.collect'); return { events: [makeEffect({ source: out.source, observer: { kind: out.kind, instanceId: `${c.type}-${c.id}` }, seq: 1, actor: null, operation: 'send', name: PAY, resource: 'POST /v1/refunds', outcome: 'committed' })], coverage: 'complete', reason: null }; } };
  });
  const run = await runHttpAssessment(orderingProfile(path), { env: {}, transport, observerFactory: factory });
  return { run, calls };
}

test('S6: the app-log window holds only the check\'s own lines: start after custody starts, cut before the witness, no request of its own', async t => {
  const { run, calls } = await orderingRun(t);
  validateHttpRunEvidence(run);
  const row = run.results.find(r => r.id === 'REFUND');
  const [window] = row.trace[1].data.appLogWindows;
  assert.equal(window.source, 'app-log');
  assert.equal(window.coverage, 'complete');
  assert.deepEqual(window.events.map(e => e.name), ['refund.create'], 'the custody start mark, the witness, the custody end mark and its collect are outside the window');
  // Requests: the two checks and the egress witness only; the app log sends none.
  assert.deepEqual(calls, ['/me', '/refunds', '/ping']);
  // The custody verdict is the egress recorder's (verdict-neutral).
  assert.equal(row.status, 'pass');
  assert.equal(row.trace[1].data.effects[0].custody, 'independent');
  assert.deepEqual(run.appLogs.map(r => [r.id, r.use, r.route, r.collector.label]), [['actions', 'record', 'file', 'app-log/2']]);
  assert.ok(run.limitations.some(l => l.startsWith('App action logs (actions)')));
});

test('a run stripped of its app log never compares as the declared run\'s peer (effects signature)', async t => {
  const { run } = await orderingRun(t);
  const stripped = structuredClone(run);
  delete stripped.appLogs;
  for (const row of stripped.results) if (row.trace[1]) { delete row.trace[1].data.appLogWindows; row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); }
  validateHttpRunEvidence(stripped);
  const comparison = compareRuns(run, stripped);
  assert.equal(comparison.compatible, false);
  assert.ok(comparison.reasons.includes('Declared effects, evidence requirements or observers differ between the runs.'));
  assert.equal(compareRuns(run, structuredClone(run)).compatible, true, 'the declared run compares with itself');
});

test('the validator refuses app-log windows a run does not declare, a declared log without them, and forged ones', async t => {
  const { run } = await orderingRun(t);
  const reseal = r => { for (const row of r.results) if (row.trace[1]) row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); return r; };
  const refused = (mutate, label) => { const copy = structuredClone(run); mutate(copy); assert.throws(() => validateHttpRunEvidence(reseal(copy)), undefined, label); };
  validateHttpRunEvidence(reseal(structuredClone(run)));
  const effectRow = r => r.results.find(x => x.id === 'REFUND');
  refused(r => { delete r.appLogs; }, 'windows without a declaration');
  refused(r => { delete effectRow(r).trace[1].data.appLogWindows; }, 'a declaration without windows');
  refused(r => { effectRow(r).trace[1].data.appLogWindows[0].scope.evidence = 'authoritative'; }, 'an authoritative app-log window');
  refused(r => { effectRow(r).trace[1].data.appLogWindows[0].instanceId = 'app-log-other'; }, 'another instance');
  refused(r => { effectRow(r).trace[1].data.appLogWindows[0].source = 'http-egress'; }, 'relabelled as an observer window');
  refused(r => { effectRow(r).trace[1].data.appLogWindows.push(structuredClone(effectRow(r).trace[1].data.appLogWindows[0])); }, 'two windows for one log');
  refused(r => { r.appLogs[0].use = 'admission+report'; }, 'a use this version does not have');
  // Each event is one the reader could have written.
  refused(r => { effectRow(r).trace[1].data.appLogWindows[0].events[0].operation = 'delete'; }, 'an operation outside the window scope');
  refused(r => { effectRow(r).trace[1].data.appLogWindows[0].events[0].actor = 'unlisted:not-a-digest'; }, 'an unlisted actor that is not a digest');
  refused(r => { r.appLogs[0].collector.label = 'app-log/0'; }, 'an unknown collector');
  // An app-log window moved into the observer windows.
  refused(r => { const d = effectRow(r).trace[1].data; d.windows.push({ ...d.appLogWindows[0], settleMs: 250, lineage: { observer: 'app-action-log', independence: 'application-report' } }); }, 'an app-log window in data.windows');
});
