// Sequence runs as native saved runs (evidence origin local-sequence), so the regression gate can judge
// them and compare a run with a baseline. The regression gate (integrations/regression-gate/gate.mjs) loads
// this module for that origin; the core comparison (src/runner.mjs) does not know it and reads such a pair
// as unsupported, never as a repair.
//
// A native run is fully derived from one sealed scopehaven-sequence-run/3 (or /4) record plus the operator's target
// identity (applicationId and contextId from the sequence, the build label from --build). The validator
// rebuilds it from that record after recomputing every verdict (run-validator.mjs), so a native field that
// disagrees with the sealed run is refused. Nothing here decides a verdict: rows copy the recomputed ones.
//
// Identity a comparison needs on both sides: the sequence evaluator hash (evaluator.mjs), the scenario hash
// (the sequence's steps, assertions and actors), the target (sequence id, applicationId, contextId) and the
// declared observers. The build label may differ: that is the change being judged.
import { digest } from '../../src/domain.mjs';
import { isAuthorizationStamp } from '../../src/authorization.mjs';
import { NO_VERIFIED_REPAIR } from '../../src/runner.mjs';
import { validateSequenceRun, SequenceRunError } from './run-validator.mjs';
import { validateSequence, sequenceHashOf, statusAssertionsOf, requestsOf, runSchemaOf, SEQUENCE_RUN_SCHEMA, SEQUENCE_RUN_SCHEMA_V4, SEQUENCE_ID } from './sequence.mjs';
import { SEQUENCE_EVALUATOR_HASH } from './evaluator.mjs';

export const SEQUENCE_ORIGIN = 'local-sequence';
export const SEQUENCE_ADAPTER_VERSION = 'timed-sequence/1';
export const SEQUENCE_EVIDENCE_SCHEMA = 'sequence-evidence/1';
export const EFFECT_ASSERTION = 'Effect assertion holds over its observer window';
export const STATUS_ASSERTION = 'Response status is one of the expected statuses';
// A build label: printable ASCII, as the gate's identity fields allow (at most 200 characters).
export const BUILD_LABEL = /^[\x20-\x7e]{1,200}$/;
export const SEQUENCE_SCOPE = 'Loopback timed sequence: effect rows are decided from the declared observers, where a boundary pass needs a deciding observer held outside the application (hold gate, egress recorder or SMTP sink); response-status rows are the status codes the application answered, never its reply text. Application state no observer sees is not assessed.';
const LIMITATIONS = Object.freeze([
  'Derived from one sealed sequence run (sequenceEvidence.run); every row is recomputed from its observer windows and responses when the run is read.',
  'A response-status row shows what the application answered, not what it did. Pair a refusal row with a control showing the same actor is accepted before the change, so a broken credential cannot read as a refusal.',
  'The build label is the operator\'s declaration, not a build hash.',
  'The timeline and gate timeline of the sequence run are not kept here; they stay in the run file the sequence CLI writes.',
]);

export class SequenceNativeError extends Error { constructor(code, detail) { super(code); this.name = 'SequenceNativeError'; this.code = code; if (detail !== undefined) this.detail = detail; } }
const need = (ok, code, detail) => { if (!ok) throw new SequenceNativeError(code, detail); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const ID = SEQUENCE_ID;

// A sequence can be saved for the gate only with its target identity and at least one allowed-use control.
export const sequenceRunReady = seq => ID.test(seq?.applicationId || '') && ID.test(seq?.contextId || '');
export const sequenceControlIds = seq => [...seq.assertions, ...statusAssertionsOf(seq)].filter(a => a.severity === 'control').map(a => a.id);
// The gate reads a passing control as proof the target still does the allowed thing, so an absence cannot come from a target
// that does nothing (README). An effect control proves its use only with effect.exists or effect.count expecting at least one;
// effect.none and effect.count 0 pass when nothing happened. And a response-status control passes on any target that answers,
// so a sequence whose effect rows judge boundaries needs at least one effect control. Other sequences (a model-path timing
// guard, for one) are not saved for the gate and are unaffected.
export const controlProvesEffect = effect => plain(effect) && (effect.kind === 'effect.exists' || (effect.kind === 'effect.count' && Number.isSafeInteger(effect.expected) && effect.expected >= 1));
export function gateControlProblem(assertions) {
  const controls = assertions.filter(a => a?.severity === 'control');
  if (controls.some(a => !controlProvesEffect(a.effect))) return 'control-no-positive-effect';
  if (assertions.some(a => a?.severity !== 'control') && !controls.length) return 'no-effect-control';
  return null;
}
const GATE_CONTROL_TEXT = Object.freeze({
  'control-no-positive-effect': 'A sequence saved for the regression gate needs every effect control (severity "control") to prove its use happened: effect.exists, or effect.count expecting at least 1 (effect.none and effect.count 0 pass on a target that does nothing).',
  'no-effect-control': 'A sequence saved for the regression gate whose effect assertions judge boundaries needs at least one effect control (severity "control" with effect.exists or effect.count of at least 1): a response-status control alone passes on a target that answers and does nothing.',
});
const gateControlsReady = seq => { const problem = gateControlProblem(seq.assertions); if (problem) throw new Error(GATE_CONTROL_TEXT[problem]); };
// The native id is the sequence run's digest in UUID form: one sealed run is stored once.
const uuidOf = d => `${d.slice(0, 8)}-${d.slice(8, 12)}-${d.slice(12, 16)}-${d.slice(16, 20)}-${d.slice(20, 32)}`;
const observerShape = observers => JSON.parse(JSON.stringify(observers.map(({ instanceId, source, kind, scope }) => ({ instanceId, source, kind, scope }))));

// One native row from one recomputed result: the verdict is copied, never decided here.
function rowOf(r) {
  const response = r.kind === 'response-status';
  const data = response
    ? { kind: 'response-status', verdict: r.verdict, request: r.request, expected: r.expected, observedStatus: r.observed?.status ?? null, ...(Object.hasOwn(r, 'acceptedBy') ? { acceptedBy: r.acceptedBy } : {}) }
    : { kind: 'effect', verdict: r.verdict, window: { from: r.window.from, to: r.window.to }, custody: r.custody ?? null, ...(r.custodyReason ? { custodyReason: r.custodyReason } : {}), corroboratedBy: r.corroboratedBy };
  const assertions = [{ name: response ? STATUS_ASSERTION : EFFECT_ASSERTION, status: r.status }];
  return { id: r.id, title: r.title, category: 'Sequence checks', severity: r.severity, status: r.status,
    evidenceRequirement: response ? 'response' : 'backend', backendEvidence: !response && (r.status === 'pass' || r.status === 'fail') ? 'observed' : 'unavailable',
    assertions, trace: [{ type: 'sequence-observation', label: 'Verdict fields only; the observer windows and responses are sealed in sequenceEvidence', data }], evidenceDigest: digest({ data, assertions }) };
}

// The native run for one sealed sequence run and one target identity. Deterministic: the validator rebuilds it.
// Exported for callers that hold an already validated run; it validates nothing itself.
export function nativeRunOf(identity, inner) { return assemble(identity, JSON.parse(JSON.stringify(inner))); }
function assemble({ applicationId, contextId, build }, inner) {
  const { timeline: _t, gateTimeline: _g, ...kept } = inner;
  const results = inner.results.map(rowOf);
  const counts = { pass: 0, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 };
  for (const row of results) counts[row.status]++;
  return { schemaVersion: 1, id: uuidOf(inner.runDigest), createdAt: inner.createdAt ?? null, targetId: inner.sequenceId, targetName: inner.sequenceId, build, applicationId, contextId,
    suiteId: `${inner.sequenceId}-sequence`, suiteHash: inner.sequenceHash, policyHash: inner.sequenceHash, profileHash: digest({ sequenceHash: inner.sequenceHash, observers: inner.observers }),
    fixtureVersion: 'operator-declared-context/1', fixtureHash: digest(contextId), targetConfigHash: digest({ build }), targetBuildHash: null,
    adapterVersion: SEQUENCE_ADAPTER_VERSION, assertionSchemaVersion: inner.schema, evaluatorHash: inner.evaluatorHash,
    runtimeMode: 'configured-local-application', evidenceOrigin: SEQUENCE_ORIGIN, scopeLabel: SEQUENCE_SCOPE,
    requiredControlIds: results.filter(row => row.severity === 'control').map(row => row.id), checksTotal: results.length, counts, durationMs: inner.durationMs ?? null, results,
    limitations: [...LIMITATIONS], sequenceEvidence: { schema: SEQUENCE_EVIDENCE_SCHEMA, run: kept } };
}

// The run the sequence CLI saves with --save: the sequence run must validate against its own sequence first.
export function sequenceNativeRun({ sequence, run, build }) {
  const seq = validateSequence(sequence);
  if (!sequenceRunReady(seq)) throw new Error('A sequence saved for the regression gate needs "applicationId" and "contextId" (1 to 80 letters, digits, "_" or "-").');
  if (!sequenceControlIds(seq).length) throw new Error('A sequence saved for the regression gate needs at least one allowed-use control (severity "control").');
  gateControlsReady(seq);
  if (typeof build !== 'string' || !BUILD_LABEL.test(build)) throw new Error('--build must be 1 to 200 printable characters.');
  validateSequenceRun(run, { expectedSequence: seq });
  if (run.schema !== runSchemaOf(seq)) throw new SequenceRunError('invalid-sequence-run', 'schema');
  return assemble({ applicationId: seq.applicationId, contextId: seq.contextId, build }, JSON.parse(JSON.stringify(run)));
}

// What the gate binds a candidate to: the sequence (scenario hash, assertions, status assertions), the target,
// the evaluator this process runs and the observers the run was given. Definition summary only: no request
// paths or bodies and no credentials.
export function exportSequenceSuite(sequence, observers) {
  const seq = validateSequence(sequence);
  gateControlsReady(seq);
  const statusAssertions = statusAssertionsOf(seq);
  const checks = [...seq.assertions.map(a => ({ id: a.id, title: a.title, severity: a.severity, kind: 'effect' })), ...statusAssertions.map(s => ({ id: s.id, title: s.title, severity: s.severity, kind: 'response-status' }))];
  return { id: `${seq.id}-sequence`, targetId: seq.id, applicationId: seq.applicationId ?? null, contextId: seq.contextId ?? null, version: runSchemaOf(seq), evidenceOrigin: SEQUENCE_ORIGIN,
    hash: sequenceHashOf(seq), evaluatorHash: SEQUENCE_EVALUATOR_HASH, requiredControlIds: sequenceControlIds(seq), checks,
    assertions: JSON.parse(JSON.stringify(seq.assertions)), statusAssertions, requests: requestsOf(seq), observers: observerShape(observers),
    scope: 'Definition summary only: no request paths, bodies or credentials.' };
}

// The native validator the gate applies. It returns what validateRun reads (sequences prove no login, so
// no actor is listed as unproven: pair refusal rows with a control instead).
export function validateSequenceNativeRun(run, { expectedSuite } = {}) {
  need(plain(run) && run.evidenceOrigin === SEQUENCE_ORIGIN && run.adapterVersion === SEQUENCE_ADAPTER_VERSION, 'invalid-sequence-evidence', 'origin');
  const evidence = run.sequenceEvidence;
  need(plain(evidence) && Object.keys(evidence).length === 2 && evidence.schema === SEQUENCE_EVIDENCE_SCHEMA && plain(evidence.run), 'invalid-sequence-evidence', 'evidence');
  // Only /3 and /4 runs carry the evaluator identity a comparison needs.
  need([SEQUENCE_RUN_SCHEMA, SEQUENCE_RUN_SCHEMA_V4].includes(evidence.run.schema), 'invalid-sequence-evidence', 'sequence-run-schema');
  try { validateSequenceRun(evidence.run); }
  catch (error) { throw new SequenceNativeError('invalid-sequence-evidence', error instanceof SequenceRunError ? `sequence-run:${error.code}${error.detail ? `:${error.detail}` : ''}` : 'sequence-run'); }
  // A run saved before the gate needed its controls to prove their use is refused as such.
  const problem = gateControlProblem(evidence.run.assertions);
  need(problem === null, 'invalid-sequence-evidence', problem);
  const identity = { applicationId: run.applicationId, contextId: run.contextId, build: run.build };
  need(ID.test(identity.applicationId ?? '') && ID.test(identity.contextId ?? '') && typeof identity.build === 'string' && BUILD_LABEL.test(identity.build), 'invalid-sequence-evidence', 'identity');
  // The store adds integrity and notes when it reads a run, and the CLI the authorization stamp and the build
  // that made the run (src/producer.mjs), both outside the sealed run, so neither changes a verdict; everything else must be
  // what the sealed run derives.
  const { integrity: _i, notes: _n, authorization, producer: _p, ...core } = run;
  need(authorization === undefined || isAuthorizationStamp(authorization), 'invalid-sequence-evidence', 'authorization');
  need(digest(assemble(identity, evidence.run)) === digest(core), 'invalid-sequence-evidence', 'native-run');
  if (expectedSuite !== undefined) {
    need(plain(expectedSuite) && expectedSuite.evidenceOrigin === SEQUENCE_ORIGIN && expectedSuite.version === run.assertionSchemaVersion && expectedSuite.hash === run.suiteHash
      && expectedSuite.evaluatorHash === run.evaluatorHash && expectedSuite.targetId === run.targetId && expectedSuite.applicationId === run.applicationId && expectedSuite.contextId === run.contextId
      && digest(expectedSuite.assertions ?? null) === digest(evidence.run.assertions) && digest(expectedSuite.statusAssertions ?? null) === digest(evidence.run.statusAssertions)
      && digest(expectedSuite.requests ?? null) === digest(evidence.run.requests)
      && digest(expectedSuite.observers ?? null) === digest(evidence.run.observers), 'unexpected-suite-evidence');
  }
  return { unprovenActors: [], loginUnprovenActors: [], rateFailures: [] };
}

// The keys a comparable pair shares. The build label (and its targetConfigHash) is free to change.
export const SEQUENCE_IDENTITY_KEYS = Object.freeze(['schemaVersion', 'evidenceOrigin', 'adapterVersion', 'assertionSchemaVersion', 'evaluatorHash', 'targetId', 'applicationId', 'contextId',
  'suiteId', 'suiteHash', 'policyHash', 'profileHash', 'fixtureVersion', 'fixtureHash', 'runtimeMode']);
export const SEQUENCE_EVIDENCE_SCOPE = 'Timed sequence evidence: effect rows decided from the declared observers (a boundary pass needs a deciding observer held outside the application); response-status rows are the codes the application answered. Reply text and state no observer sees are not assessed.';
const kindOf = row => row?.trace?.[0]?.data?.kind;

// A comparison in the core's shape (compatible, reasons, summary, rows, controlsPass, restorationLabel,
// evidenceScope). A restored effect row reads local-control-restored and a restored status row
// contract-restored; anything inconclusive on either side reads unverified, never restored.
export function compareSequenceRuns(baseline, candidate) {
  const reasons = [];
  const valid = [baseline, candidate].every(run => { try { validateSequenceNativeRun(run); return true; } catch { return false; } });
  if (!valid) reasons.push('Evidence is not a valid sequence run on both sides.');
  const b = plain(baseline) ? baseline : {}, c = plain(candidate) ? candidate : {};
  for (const key of SEQUENCE_IDENTITY_KEYS) if (b[key] === undefined || c[key] === undefined || b[key] !== c[key]) reasons.push(`${key} differs or is missing.`);
  const rowsOf = run => Array.isArray(run.results) ? run.results.filter(plain) : [];
  const ids = run => rowsOf(run).map(row => row.id).sort();
  if (digest(ids(b)) !== digest(ids(c)) || [b, c].some(run => new Set(ids(run)).size !== (Array.isArray(run.results) ? run.results.length : -1))) reasons.push('Scenario coverage differs or contains duplicates.');
  // The sealed definitions themselves, not only the scenario hash each run states: a run cannot recompute its
  // sequence hash (the steps are not stored), so the assertions and status assertions must also be equal.
  const definitions = run => digest({ assertions: run.sequenceEvidence?.run?.assertions ?? null, statusAssertions: run.sequenceEvidence?.run?.statusAssertions ?? null, requests: run.sequenceEvidence?.run?.requests ?? null });
  if (definitions(b) !== definitions(c)) reasons.push('Sealed assertion definitions differ between the runs.');
  const controlIds = c.requiredControlIds;
  if (!Array.isArray(controlIds) || !controlIds.length || !Array.isArray(b.requiredControlIds) || digest(controlIds) !== digest(b.requiredControlIds)) reasons.push('Required permitted-use controls differ or are missing.');
  const compatible = reasons.length === 0;
  const controlsPass = valid && Array.isArray(controlIds) && controlIds.length > 0 && controlIds.every(id => rowsOf(c).some(row => row.id === id && row.severity === 'control' && row.status === 'pass'));
  if (!controlsPass) reasons.push('Required allowed-behaviour controls did not all pass; repairs cannot be verified.');
  const summary = { fixed: 0, stillFailing: 0, newFailures: 0, preservedPasses: 0, unverified: 0 };
  const rows = rowsOf(b).map(before => {
    const after = rowsOf(c).find(row => row.id === before.id);
    let transition = 'unverified';
    if (!compatible) transition = 'incompatible';
    else if (before.status === 'fail' && after?.status === 'pass') transition = !controlsPass ? 'blocked-by-controls' : kindOf(after) === 'response-status' ? 'contract-restored' : 'local-control-restored';
    else if (before.status === 'pass' && after?.status === 'fail') transition = 'regression';
    else if (before.status === 'fail' && after?.status === 'fail') transition = 'still-failing';
    else if (before.status === 'pass' && after?.status === 'pass') transition = 'preserved';
    summary[({ 'contract-restored': 'fixed', 'local-control-restored': 'fixed', regression: 'newFailures', 'still-failing': 'stillFailing', preserved: 'preservedPasses' })[transition] || 'unverified']++;
    return { id: before.id, title: before.title, before: before.status, after: after?.status || 'inconclusive', transition };
  });
  const restored = new Set(rows.filter(row => ['contract-restored', 'local-control-restored'].includes(row.transition)).map(row => row.transition));
  const label = restored.size === 2 ? 'Observed effects and response status restored' : restored.has('contract-restored') ? 'Response status restored' : 'Observed effects restored';
  return { compatible, reasons, baselineId: b.id, candidateId: c.id, summary, rows, controlsPass,
    // As the core labels a pair: a repair label only for a compatible, controls-passing, complete pair that restored a row and broke none.
    restorationLabel: !(compatible && controlsPass) ? 'Unverified changes' : summary.fixed > 0 && summary.newFailures === 0 && !summary.unverified ? label : NO_VERIFIED_REPAIR,
    evidenceScope: SEQUENCE_EVIDENCE_SCOPE };
}
