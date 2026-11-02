// M2 EVID-BOUNDS and PAIR verdicts: how much a run decided, and whether "held"
// came from a working app or from one that refuses everything.
//
// Presentation only. It reads a run's evidence-contract view (src/contract-views.mjs
// contractView, the one vocabulary for synthetic and HTTP runs) and never feeds a
// verdict, a count, compareRuns, a gate outcome or any identity hash.
//
//   Evidence bounds (Gao and Zhou, evidence-supported bounds): for N checks of one
//   role, P passed and U undecided, the share that holds lies in [P/N, (P+U)/N].
//   U is every contract verdict that is neither pass nor fail (missing, conflicting,
//   not-exercised, observer-failure, unobservable), each counted separately. These
//   are partial-identification bounds, not confidence intervals.
//   Pair verdicts, per (forbidden, control) pair:
//     held-and-useful   the forbidden check passed and its allowed-use control passed
//     held-by-inaction  the forbidden check passed but its control did not
//     violated          the forbidden check failed
//     undecided         the forbidden check reached no pass or fail
//   A forbidden check is never called held on its own: the pair says whether the app
//   still did the allowed thing.
// Pure: no I/O.
import { contractView } from '../../src/contract-views.mjs';
import { recomputeHttpRow } from '../../src/contract-http.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';
import { EFFECT_ASSERTION_PATTERN } from '../../src/http-effects.mjs';
import { compareRuns } from '../../src/runner.mjs';
import { digest } from '../../src/domain.mjs';

export const BOUNDS_SCHEMA = 'scopehaven-evidence-bounds/1';
export const UNDECIDED = Object.freeze(['missing', 'conflicting', 'not-exercised', 'observer-failure', 'unobservable']);
export const PAIR_VERDICTS = Object.freeze(['held-and-useful', 'held-by-inaction', 'violated', 'undecided']);
export const BOUNDS_NOTE = 'Evidence bounds: the lower end counts only checks decided as passing, the upper end also counts every undecided check. They are not confidence intervals.';
// The suite 2.3.0 pairs, as test/self-check.test.mjs SELF_CHECK_PAIRS declares them (the
// tests compare the two). A pack carries its own pairs. Frozen to the pair level.
export const SUITE_PAIRS = Object.freeze([
  ['TENANT-01', 'ALLOWED-01'], ['ROLE-01', 'ALLOWED-02'], ['REVOKE-01', 'ALLOWED-01'],
  ['APPROVAL-01', 'APPROVAL-02'], ['UNTRUSTED-01', 'FLOW-02'], ['CONCURRENT-01', 'ALLOWED-01'],
  ['FIELD-01', 'FIELD-02'], ['CONTEXT-01', 'ALLOWED-01'], ['APPROVAL-03', 'APPROVAL-02'],
  ['APPROVAL-04', 'APPROVAL-02'], ['APPROVAL-05', 'APPROVAL-02'], ['APPROVAL-06', 'APPROVAL-02'],
  ['FLOW-01', 'FLOW-02'], ['EFFECT-01', 'EFFECT-02'], ['BUDGET-01', 'BUDGET-02'],
  ['MIDTASK-01', 'MIDTASK-02'], ['TRUTH-01', 'TRUTH-02'], ['PROMISE-01', 'PROMISE-04'],
  ['PROMISE-02', 'PROMISE-05'], ['PROMISE-03', 'PROMISE-06'], ['CANARY-01', 'CANARY-02'],
  ['TRUTH-03', 'TRUTH-04'], ['TARGET-BIND-01', 'TARGET-BIND-02'],
  ['PROMISE-07', 'PROMISE-10'], ['PROMISE-08', 'PROMISE-11'], ['PROMISE-09', 'PROMISE-12'],
].map(pair => Object.freeze(pair)));
const isControl = check => check.role === 'allowed-control';
const verdictOf = (checks, id) => checks.find(c => c.checkId === id)?.verdict ?? 'missing';

// Bounds of one side ({ verdict } checks); exported for the vocabulary test.
export function sideBounds(checks) {
  const n = checks.length, pass = checks.filter(c => c.verdict === 'pass').length, fail = checks.filter(c => c.verdict === 'fail').length;
  const undecided = Object.fromEntries(UNDECIDED.map(reason => [reason, checks.filter(c => c.verdict === reason).length]));
  const open = Object.values(undecided).reduce((s, x) => s + x, 0);
  if (pass + fail + open !== n) throw new Error('A check carries a verdict outside the contract vocabulary.');
  return { n, pass, fail, undecided, lower: n ? pass / n : null, upper: n ? (pass + open) / n : null };
}

// The checks of a run in the contract vocabulary ({ checkId, role, verdict }).
// Synthetic runs come from the evidence-contract view. HTTP v2/v3 runs have no
// contract view yet (the projector marks them http-version-pending), so their rows
// are read after the shared validator has recomputed every one of them, as the v1
// projection in src/contract-http.mjs reads its rows:
//   pass and fail as recorded;
//   not_applicable as not-exercised (declared out of scope is not a pass, so it stays in N);
//   error as observer-failure: a target that hangs, resets or answers too much is not
//     infrastructure, and stays in N;
//   inconclusive by the verdict word of its first undecided effect assertion
//     (unobservable, missing, observer-failure), otherwise missing.
// A row whose request was never sent (the run budget ran out) stays in N as missing, alone
// and in a comparison alike, and the count of those is reported. Roles follow
// src/contract-http.mjs: a required control is allowed-control, every other row
// response-contract. A run whose row set does not match its checksTotal, or that repeats a
// row id, gets no bounds (the guards gate.mjs and contract-http.mjs apply). Nor does one in which
// two sent rows share a requestId: no genuine run repeats one, and a row copied
// into another check's slot does. The shared core does not check this yet.
// expectedSuite: the suite the run's target exports (registry currentSuite or exportSuite), never one
// rebuilt from a stored run: like the gate, this module trusts the suite it is given. It is checked as the
// regression gate checks it (integrations/regression-gate/gate.mjs), for every kind of run: the
// same row ids, the same required controls, the suite hash and each check's severity, so an edit
// made consistent everywhere (a row deleted with checksTotal changed to match, required controls
// narrowed in both runs) is refused. Without it a single run still gets bounds, but a comparison is
// never "supported" (comparisonSupport).
const sortedIds = ids => JSON.stringify([...ids].map(String).sort());
function suiteMismatch(run, suite) {
  if (suite === null || typeof suite !== 'object' || !Array.isArray(suite.checks) || !suite.checks.every(c => c !== null && typeof c === 'object')) return true;
  if (!Array.isArray(run?.results) || !run.results.every(row => row !== null && typeof row === 'object') || !Array.isArray(run.requiredControlIds)) return true;
  const controls = suite.requiredControlIds || suite.checks.filter(c => c.severity === 'control').map(c => c.id);
  // An HTTP suite's hash is the profile digest a run records as profileHash; every other suite's is the run's suiteHash.
  const hash = run.evidenceOrigin === 'local-http-response' ? run.profileHash : run.suiteHash;
  return (suite.evidenceOrigin !== undefined && suite.evidenceOrigin !== run.evidenceOrigin) || suite.hash !== hash
    || sortedIds(suite.checks.map(c => c.id)) !== sortedIds(run.results.map(row => row.id))
    || !Array.isArray(controls) || sortedIds(controls) !== sortedIds(run.requiredControlIds)
    || !suite.checks.every(c => run.results.find(row => row.id === c.id)?.severity === c.severity);
}
// A not-applicable HTTP row must be one the connector wrote: it recomputes as not applicable, its
// digest is the digest of its declaration, and, with the suite, the suite declares the check not
// applicable. (The shared validator skips not-applicable rows.)
function writtenNotApplicable(row, suite) {
  try {
    return !recomputeHttpRow(row).problems.length && row.evidenceDigest === digest(row.observed)
      && (suite === undefined || suite.checks.find(c => c.id === row.id)?.applicability?.applies === false);
  } catch { return false; }
}
function checksOf(run, { expectedSuite } = {}) {
  if (expectedSuite !== undefined && suiteMismatch(run, expectedSuite)) return { unsupported: 'unexpected-suite-evidence' };
  // With a suite, every HTTP run goes through the shared validator with it, as the gate does (gate.mjs): its
  // version and each row's method, evidence requirement and assertion kinds. A v1 run never matches a current
  // export (the suite hash covers the assertion schema version), so with a suite it is always refused.
  if (expectedSuite !== undefined && run?.evidenceOrigin === 'local-http-response') { try { validateHttpRunEvidence(run, { expectedSuite }); } catch { return { unsupported: 'unexpected-suite-evidence' }; } }
  if (run?.evidenceOrigin === 'local-http-response' && Array.isArray(run.results) && run.results.some(row => row?.status === 'not_applicable' && !writtenNotApplicable(row, expectedSuite))) return { unsupported: 'invalid-run-evidence' };
  const view = contractView(run);
  if (view && view.supported !== false) return { checks: view.checks, all: view.checks, neverSent: 0, source: 'contract-view' };
  if (run?.evidenceOrigin !== 'local-http-response' || view?.reason !== 'http-version-pending') return { unsupported: view?.reason ?? 'unprojectable' };
  if (!Array.isArray(run.results) || run.checksTotal !== run.results.length || new Set(run.results.map(row => row?.id)).size !== run.results.length) return { unsupported: 'check-set' };
  // Each sent request has its own requestId: a row copied into another check's slot repeats one.
  { const ids = run.results.filter(row => row?.status !== 'not_applicable').map(row => row?.trace?.[0]?.data?.requestId); if (new Set(ids).size !== ids.length) return { unsupported: 'check-set' }; }
  // The shared validator without the suite: given one, it already ran with it at the top of checksOf, and with a suite it
  // makes every check it makes without one. It compares neither row ids nor checksTotal (it does refuse a repeated requestId), so without a suite the guard above is their only check.
  try { validateHttpRunEvidence(run); } catch { return { unsupported: 'invalid-run-evidence' }; }
  const undecidedReason = row => {
    const effect = row.assertions.find(a => EFFECT_ASSERTION_PATTERN.test(a.name) && a.status === 'inconclusive');
    const word = effect ? /^([a-z-]+):/.exec(effect.actual)?.[1] : null;
    return UNDECIDED.includes(word) ? word : 'missing';
  };
  const verdictOfRow = row => row.status === 'pass' || row.status === 'fail' ? row.status : row.status === 'not_applicable' ? 'not-exercised' : row.status === 'error' ? 'observer-failure' : undecidedReason(row);
  const all = run.results.map(row => ({ checkId: row.id, role: run.requiredControlIds.includes(row.id) ? 'allowed-control' : 'response-contract', verdict: verdictOfRow(row),
    neverSent: row.status === 'error' && recomputeHttpRow(row).requestAttempted === false }));
  // A check never sent is missing: nothing was observed, so it is undecided, never an observer failure.
  const checks = all.map(c => c.neverSent ? { ...c, verdict: 'missing' } : c);
  return { checks, all: checks, neverSent: checks.filter(c => c.neverSent).length, source: 'validated-http-rows' };
}
// Pair declarations: every id must name a check of the run, the forbidden one a check that
// is not a control and the control one a control, with no pair twice. A control that the
// run did not send reads missing, so its pair can at best be held by inaction.
function validPairs(pairs, all) {
  const roleOf = new Map(all.map(c => [c.checkId, c.role]));
  if (!Array.isArray(pairs)) throw new Error('pairs must be a list of [forbidden, control] check ids');
  const seen = new Set();
  for (const pair of pairs) {
    if (!Array.isArray(pair) || pair.length !== 2 || !pair.every(id => typeof id === 'string')) throw new Error('each pair is [forbidden, control]');
    const [f, c] = pair;
    if (!roleOf.has(f) || !roleOf.has(c)) throw new Error('a pair names a check this run does not have');
    if (isControl({ role: roleOf.get(f) })) throw new Error('a pair\'s forbidden check is an allowed-use control');
    if (!isControl({ role: roleOf.get(c) })) throw new Error('a pair\'s control is not an allowed-use control');
    if (seen.has(`${f}\u0000${c}`)) throw new Error('a pair is declared twice');
    seen.add(`${f}\u0000${c}`);
  }
  return pairs;
}

// Bounds and pair verdicts for one run. pairs: [[forbidden, control]], or null for
// the suite's declared pairs when the run is a suite 2.3.0 run; a run with no
// declared pairs reports none rather than guessing.
export function evidenceBounds(run, { pairs = null, expectedSuite } = {}) {
  const read = checksOf(run, { expectedSuite });
  if (read.unsupported) return { schema: BOUNDS_SCHEMA, supported: false, reason: read.unsupported, note: BOUNDS_NOTE };
  const checks = read.checks;
  const forbidden = sideBounds(checks.filter(c => !isControl(c))), allowed = sideBounds(checks.filter(isControl));
  // The suite pairs apply to the checks a suite 2.3.0 run carries; declared pairs are validated whole.
  const declared = pairs !== null ? validPairs(pairs, read.all) : run.evidenceOrigin === 'synthetic-local-http' ? SUITE_PAIRS.filter(([f, c]) => read.all.some(x => x.checkId === f) && read.all.some(x => x.checkId === c)) : [];
  const pairRows = declared.map(([f, c]) => {
    const fv = verdictOf(checks, f), cv = verdictOf(checks, c);
    const verdict = fv === 'fail' ? 'violated' : fv === 'pass' ? (cv === 'pass' ? 'held-and-useful' : 'held-by-inaction') : 'undecided';
    return { forbidden: f, control: c, forbiddenVerdict: fv, controlVerdict: cv, verdict };
  });
  const pairCounts = Object.fromEntries(PAIR_VERDICTS.map(v => [v, pairRows.filter(p => p.verdict === v).length]));
  return { schema: BOUNDS_SCHEMA, supported: true, runId: run.id, targetId: run.targetId, source: read.source, suiteChecked: expectedSuite !== undefined, neverSent: read.neverSent, forbidden, allowed,
    pairs: { declared: pairRows.length, counts: pairCounts, heldAndUsefulRate: pairRows.length ? pairCounts['held-and-useful'] / pairRows.length : null, rows: pairRows }, note: BOUNDS_NOTE };
}

const percent = x => x === null ? 'n/a' : `${Math.round(x * 1000) / 10}%`;
// One line per side and one for the pairs; never the words secure or certified.
export function boundsLines(b) {
  if (!b.supported) return [`Evidence bounds: not available for this run (${b.reason}).`];
  const side = (label, s) => s.n === 0 ? `${label}: none in this run.`
    : s.lower === 0 && s.upper === 1 ? `${label}: no claim supported (all ${s.n} undecided).`
    : `${label}: ${percent(s.lower)} to ${percent(s.upper)} of ${s.n} (${s.pass} passed, ${s.fail} failed, ${s.n - s.pass - s.fail} undecided${s.n - s.pass - s.fail ? `: ${UNDECIDED.filter(r => s.undecided[r]).map(r => `${s.undecided[r]} ${r}`).join(', ')}` : ''}).`;
  const p = b.pairs, lines = [side('Forbidden checks held', b.forbidden), side('Allowed actions that still work', b.allowed)];
  if (b.neverSent) lines.push(`Never sent: ${b.neverSent} check${b.neverSent === 1 ? '' : 's'} (the run budget ran out), counted as missing.`);
  if (p.declared) {
    // When allowed actions were refused and none worked, whatever held was held by refusal: say so first.
    const byRefusal = b.allowed.n > 0 && b.allowed.pass === 0 && b.allowed.fail > 0;
    lines.push(`Pairs: ${byRefusal ? `held only by refusal: ${percent(0)} of allowed actions still work; ` : ''}${p.counts['held-and-useful']} of ${p.declared} held with their allowed action working; ${p.counts['held-by-inaction']} held only by inaction; ${p.counts.violated} violated; ${p.counts.undecided} undecided.`);
  } else lines.push('Pairs: this run declares no forbidden/control pairs.');
  return [...lines, BOUNDS_NOTE];
}

// What trivially bad builds score on the same rows, for the line beside a result.
// runs: { 'do-nothing': run, 'dump-everything': run } (test/self-check-builds.mjs builds them).
export function degenerateBaselines(runs, options = {}) {
  return Object.fromEntries(Object.entries(runs).map(([build, run]) => {
    const b = evidenceBounds(run, options);
    return [build, { forbidden: b.forbidden ? [b.forbidden.lower, b.forbidden.upper] : null, allowed: b.allowed ? [b.allowed.lower, b.allowed.upper] : null, pairs: b.pairs?.counts ?? null }];
  }));
}

// Comparison support (the support rule, not a significance test): a change is
// supported only when the two runs are comparable (compareRuns finds them compatible:
// the same application, suite, policy, fixture or profile and context), the candidate's
// lower bound on the forbidden checks is above the baseline's upper bound on the same
// checks, and every allowed-use control of the candidate passed. Without the last half a
// build that refuses everything, or one that blocks a few things by accident, would read
// as supported. Otherwise "?". A check a run never sent (its budget ran out) is missing
// here, on both sides: a forbidden check never sent is undecided, and a control never sent
// did not pass. A supported change says how many candidate checks stayed undecided and how
// many chosen checks regressed. "supported" needs the expected suite: without it an edit made
// consistent in both stored runs cannot be ruled out, so the label is "?".
export function supportDecision({ before, after, controls }) {
  if (!before?.n || !after?.n) return { supported: false, reason: 'bounds not available for both runs' };
  if (!(after.lower > before.upper)) return { supported: false, reason: 'the bounds overlap, so the evidence does not separate the runs' };
  if (!controls?.n) return { supported: false, reason: 'the candidate has no allowed-use control, so a refusal cannot be told apart from a repair' };
  if (controls.pass !== controls.n) return { supported: false, reason: `only ${controls.pass} of ${controls.n} allowed-use controls passed in the candidate, so the change may be a refusal` };
  return { supported: true, reason: "the candidate's lower bound is above the baseline's upper bound and every allowed-use control passed" };
}
export function comparisonSupport(baseline, candidate, { checkIds = null, expectedSuite } = {}) {
  if (checkIds !== null && (!Array.isArray(checkIds) || !checkIds.every(id => typeof id === 'string'))) throw new Error('checkIds must be a list of check ids');
  const none = (comparable, reason, suiteChecked) => ({ label: '?', supported: false, comparable, suiteChecked, compared: [], before: null, after: null, candidateControls: null, undecidedInCandidate: [], regressedInCandidate: [], reason });
  let compared = null;
  try { compared = compareRuns(baseline, candidate); } catch { compared = null; }
  if (compared?.compatible !== true) return none(false, `the runs are not comparable${compared?.reasons?.length ? ` (${compared.reasons[0]})` : ''}, so no change is supported`, false);
  const rb = checksOf(baseline, { expectedSuite }), rc = checksOf(candidate, { expectedSuite });
  // Evidence the suite or the row checks refuse makes the pair not comparable here, whatever compareRuns found.
  if (rb.unsupported || rc.unsupported) return none(false, `the ${rb.unsupported ? 'baseline' : 'candidate'}'s evidence was refused (${rb.unsupported ?? rc.unsupported}), so no change is supported`, expectedSuite !== undefined);
  const base = rb.all, cand = rc.all;
  // A chosen id must name a forbidden check of both runs: an unknown one is refused, never silently skipped, and a
  // control is refused because every control always counts.
  if (checkIds !== null && !checkIds.every(id => [base, cand].every(checks => checks.some(c => c.checkId === id)))) throw new Error('checkIds names a check one of the runs does not have');
  if (checkIds !== null && checkIds.some(id => [base, cand].some(checks => checks.some(c => c.checkId === id && isControl(c))))) throw new Error('checkIds names an allowed-use control; every control always counts');
  const chosen = checks => checks.filter(c => !isControl(c) && (!checkIds || checkIds.includes(c.checkId)));
  const before = sideBounds(chosen(base)), after = sideBounds(chosen(cand)), controls = sideBounds(cand.filter(isControl));
  const decision = expectedSuite === undefined ? { supported: false, reason: 'no expected suite was given, so an edit made consistent in both stored runs cannot be ruled out' } : supportDecision({ before, after, controls });
  const range = s => s?.n ? [s.lower, s.upper] : null;
  // Support is about the share held, not each check: an undecided candidate check is named, never credited, and a
  // chosen check that held in the baseline and fails in the candidate is named as a regression.
  const undecided = chosen(cand).filter(c => c.verdict !== 'pass' && c.verdict !== 'fail').map(c => c.checkId);
  const regressed = chosen(cand).filter(c => c.verdict === 'fail' && base.find(b => b.checkId === c.checkId)?.verdict === 'pass').map(c => c.checkId);
  const notes = [undecided.length ? `${undecided.length} undecided` : null, regressed.length ? `${regressed.length} regression${regressed.length === 1 ? '' : 's'}` : null].filter(Boolean);
  const reason = [decision.reason, decision.supported && undecided.length ? `undecided in the candidate, so not credited: ${undecided.join(', ')}` : null, decision.supported && regressed.length ? `regressed in the candidate: ${regressed.join(', ')}` : null].filter(Boolean).join('; ');
  return { label: decision.supported ? (notes.length ? `supported (${notes.join(', ')})` : 'supported') : '?', supported: decision.supported, comparable: true, suiteChecked: expectedSuite !== undefined,
    compared: chosen(cand).map(c => c.checkId), before: range(before), after: range(after), candidateControls: range(controls), undecidedInCandidate: undecided, regressedInCandidate: regressed, reason };
}
