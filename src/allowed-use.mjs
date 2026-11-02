// Allowed-use (over-blocking) summary of a saved run. Presentation only: it reads
// recorded row statuses and never feeds verdicts, counts, compareRuns, gate
// outcomes, notes or any suite, policy, fixture, evaluator or profile hash.
//
// Controls are the run's requiredControlIds when that array is present (every
// current producer records it: synthetic and HTTP runs),
// otherwise checks with severity "control" (older synthetic runs). A control
// counts as passed or failed only when its recorded status is exactly pass or
// fail; inconclusive, error, not_applicable or a missing row are reported as
// inconclusive and are never counted as over-blocking.
// Of those inconclusive controls, controlsPossiblyOverBlocked counts the ones whose HTTP status matched but whose claim rule did
// not read as a declared success (ambiguous, unreadable or untriggered): the app answered as if it allowed the use, and its reply
// may be a refusal in undeclared words. A control's claim rules declare success only, so an honest refusal reads that way. It is
// reported beside the rate and never counted in it: the reading cannot tell a refusal from a success in other words.
// The allowed-use number always travels with its limits: every label and the meaning field carry them.
import { restsOnAdmissions } from './app-log-verdicts.mjs';

// A control whose fail rests only on app-log admissions (src/app-log-verdicts.mjs: the application's own action log records a
// forbidden action in its window) still counts as failed, but it is not over-blocking: it is reported beside the rate as
// controlsFailedByAdmission (only when nonzero) and left out of the rate and of newlyOverBlocked.
export const ALLOWED_USE_LIMITS = 'Counts only the declared allowed-use controls; inconclusive controls are not counted. It is not a security score.';
export const ALLOWED_USE_PURPOSE = 'Measures whether permitted users can still do permitted things.';
export const ALLOWED_USE_MEANING = `${ALLOWED_USE_PURPOSE} ${ALLOWED_USE_LIMITS}`;

const POSSIBLE_REFUSAL = /^Observed claim [1-5] \((ambiguous|unreadable|untriggered)\)$/;
const possiblyOverBlocked = row => row?.status === 'inconclusive' && Array.isArray(row.assertions)
  && row.assertions.some(a => a?.name === 'HTTP status matches contract' && a.status === 'pass')
  && row.assertions.some(a => typeof a?.name === 'string' && POSSIBLE_REFUSAL.test(a.name) && a.status === 'inconclusive');
const rowsOf = run => Array.isArray(run?.results) ? run.results.filter(row => row !== null && typeof row === 'object') : [];

export function allowedUseControlIds(run) {
  if (Array.isArray(run?.requiredControlIds)) return { basis: 'requiredControlIds', ids: [...new Set(run.requiredControlIds.filter(id => typeof id === 'string'))] };
  return { basis: 'severity-control', ids: [...new Set(rowsOf(run).filter(row => row.severity === 'control' && typeof row.id === 'string').map(row => row.id))] };
}

export function allowedUse(run) {
  const { basis, ids } = allowedUseControlIds(run), rows = rowsOf(run);
  let controlsPassed = 0, controlsFailed = 0, controlsPossiblyOverBlocked = 0, controlsFailedByAdmission = 0;
  for (const id of ids) {
    const row = rows.find(r => r.id === id), status = row?.status;
    if (status === 'pass') controlsPassed++;
    else if (status === 'fail') { controlsFailed++; if (restsOnAdmissions(row)) controlsFailedByAdmission++; }
    else if (possiblyOverBlocked(row)) controlsPossiblyOverBlocked++;
  }
  const controlsTotal = ids.length;
  return { controlsTotal, controlsPassed, controlsFailed, controlsInconclusive: controlsTotal - controlsPassed - controlsFailed, controlsPossiblyOverBlocked,
    overBlockingRate: controlsTotal ? (controlsFailed - controlsFailedByAdmission) / controlsTotal : null, ...(controlsFailedByAdmission ? { controlsFailedByAdmission } : {}), basis, meaning: ALLOWED_USE_MEANING };
}

/** Rate shown with at most 3 decimals (as a fraction) in display text only; stored values stay exact. */
export function overBlockingPercent(rate) {
  if (typeof rate !== 'number' || !Number.isFinite(rate)) return null;
  return `${Number((Math.round(rate * 1000) / 10).toFixed(1))}%`;
}

export function allowedUseLabel(summary) {
  if (!summary.controlsTotal) return 'Allowed use: this run has no allowed-use controls, so over-blocking is not measured.';
  const possibly = summary.controlsPossiblyOverBlocked ? `, ${summary.controlsPossiblyOverBlocked} of them answered without a declared success and may have been refused` : '';
  const admitted = summary.controlsFailedByAdmission ? `; ${summary.controlsFailedByAdmission} failed by an app-log admission (the application's own action log records a forbidden action), not counted as over-blocking` : '';
  const inconclusive = summary.controlsInconclusive ? `; ${summary.controlsInconclusive} inconclusive, not counted as over-blocking${possibly}` : '';
  return `Allowed use: ${summary.controlsPassed} of ${summary.controlsTotal} allowed actions still work (over-blocking ${overBlockingPercent(summary.overBlockingRate)}${admitted}${inconclusive}). ${ALLOWED_USE_LIMITS}`;
}

// The single-run JSON export (export-cli --format json and /api/runs/<id>/export.json)
// is deliberately unchanged: it is re-imported as a baseline (integrations/github-action
// prepare.mjs baselineRecord) by hashing every field except integrity and notes, so an
// added top-level field would fail that integrity check and change gate outcomes.

/**
 * Comparison addendum built from the two runs and the core compareRuns rows.
 * newlyOverBlocked lists candidate controls recorded pass in the baseline and
 * fail in the candidate. It is observational: when the pair is not comparable it
 * is not a verified regression, and it never changes the comparison verdict.
 */
export function comparisonAllowedUse(baseline, candidate, comparison) {
  const controls = new Set(allowedUseControlIds(candidate).ids);
  const rows = Array.isArray(comparison?.rows) ? comparison.rows : [];
  const flipped = rows.filter(row => controls.has(row.id) && row.before === 'pass' && row.after === 'fail');
  const admitted = new Set(flipped.filter(row => restsOnAdmissions(rowsOf(candidate).find(r => r.id === row.id))).map(row => row.id));
  return { baseline: allowedUse(baseline), candidate: allowedUse(candidate), comparable: comparison?.compatible === true,
    newlyOverBlocked: flipped.filter(row => !admitted.has(row.id)).map(row => row.id).sort(), ...(admitted.size ? { newlyFailedByAdmission: [...admitted].sort() } : {}) };
}
