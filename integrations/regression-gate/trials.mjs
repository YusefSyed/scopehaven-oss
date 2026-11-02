// Repeated trials for the regression gate (`gate --trials N`). The gate runs an HTTP contract target N times
// under one lock and one authorization window, saves every run, and reads a pass^k column per check over those N runs
// with the pass-k module (../pass-k/passk.mjs, read only: its estimator, trial identity and validators). Each check gets
// a reading against the declared floor: PASS only when every trial passed (and, on a forwarded or remote target, every
// trial's pass was paired with a passing same-route control); FAIL-flaky when some trials passed and pass^k is below the
// floor; otherwise FAIL (a trial failed) or NOT-PASSED (no trial failed, but not every trial passed cleanly). A floor
// below 1 never makes a check PASS and never relaxes the verdict: every trial's own gate reasons still count.
// The k and floor are gate options, not profile keys: the profile schema (src/contracts.mjs) feeds the HTTP evaluator
// hash, so a profile key would move that pin. This module is imported only when --trials is given.
import { checksFromRun, passKColumn, sarifWithPassK, formatPassK, PASS_K_MAX } from '../pass-k/passk.mjs';
import { escape, renderReport } from '../../src/report.mjs';
import { serializeSarif } from '../../src/sarif.mjs';
import { unpairedForwardedPasses } from '../../src/forwarded-pairing.mjs';
import { NO_VERIFIED_REPAIR } from '../../src/runner.mjs';

export const TRIALS_SCHEMA = 'scopehaven-gate-trials/1';
export const TRIALS_MIN = 2;
export const TRIALS_MAX = PASS_K_MAX;
export const READINGS = Object.freeze(['PASS', 'FAIL-flaky', 'FAIL', 'NOT-PASSED']);
// The reason the gate adds when a check reads FAIL-flaky. The trials' own reasons (checks-failed and the rest) come first.
export const FLAKY_REASON = 'checks-flaky';
const FLOOR_DENOMINATOR_MAX = 1000000;
const SCOPE = Object.freeze([
  'Trials are fresh runs of one target made by this gate invocation, one after another under one lock; they are only as independent as the application and its state between runs, and correlated trials overstate pass^k.',
  'PASS needs every trial to pass. A check that passed some trials and whose pass^k is below the floor reads FAIL-flaky. A floor below 1 never makes a check PASS: every trial is judged by the gate as a single run would be, and its reasons count.',
  'The summary\'s current block, the comparison and the per-check report articles are the first trial\'s; the pass^k column and the readings cover all trials. With a baseline, the restoration label is withheld unless every check reads PASS.',
]);
export class TrialsError extends Error { constructor(code) { super(code); this.name = 'TrialsError'; this.code = code; } }
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const gcd = (a, b) => { while (b) [a, b] = [b, a % b]; return a; };
const fraction = exact => exact.includes('/') ? exact.split('/').map(BigInt) : [BigInt(exact), 1n];
const atLeast = (exact, floor) => { const [an, ad] = fraction(exact), [bn, bd] = fraction(floor); return an * bd >= bn * ad; };

/** The floor as written: '1', or a reduced fraction 'a/b' with 0 < a < b <= 1000000. */
export function parseFloor(text) {
  if (text === '1') return '1';
  const match = typeof text === 'string' ? /^([1-9][0-9]{0,6})\/([1-9][0-9]{0,6})$/.exec(text) : null;
  const [a, b] = match ? [Number(match[1]), Number(match[2])] : [0, 0];
  if (!match || a >= b || b > FLOOR_DENOMINATOR_MAX || gcd(a, b) !== 1) throw new TrialsError('trials-floor-invalid');
  return `${a}/${b}`;
}

/** The declared trials, k and floor, checked before anything is read or sent. k defaults to 1 and the floor to '1'. */
export function checkTrials({ trials, k = null, floor = null } = {}) {
  if (!(Number.isSafeInteger(trials) && trials >= TRIALS_MIN && trials <= TRIALS_MAX)) throw new TrialsError('trials-invalid');
  const declaredK = k === null ? 1 : k;
  if (!(Number.isSafeInteger(declaredK) && declaredK >= 1 && declaredK <= trials)) throw new TrialsError('trials-k-invalid');
  return { trials, k: declaredK, floor: floor === null ? '1' : parseFloor(floor) };
}

/** One check's reading from its counts, its exact pass^k and the floor. unpaired: a trial's pass on a forwarded or remote
 * target had no passing same-route control (src/forwarded-pairing.mjs), so the gate is not clean on it. */
export function readingOf(check, floor, { unpaired = false } = {}) {
  const floorMet = check.exact !== null && atLeast(check.exact, floor);
  if (check.passed === check.trials) return { floorMet, reading: unpaired ? 'NOT-PASSED' : 'PASS' };
  if (check.passed > 0 && !floorMet) return { floorMet, reading: 'FAIL-flaky' };
  return { floorMet, reading: check.failed > 0 ? 'FAIL' : 'NOT-PASSED' };
}

/**
 * The pass^k column over the trials (the first is the primary) and each check's reading. checksFromRun validates every
 * run's HTTP evidence against the expected suite and refuses runs of another trial identity (pass-k-<code>). The gate
 * reads it before any trial is stamped or saved.
 */
export function trialColumn(runs, { k, floor, expectedSuite }) {
  if (!Array.isArray(runs) || runs.length < TRIALS_MIN) throw new TrialsError('trials-invalid');
  let column;
  try { column = passKColumn({ k, ...checksFromRun(runs[0], runs.slice(1), { expectedSuite }) }); }
  catch (error) { throw new TrialsError(typeof error?.code === 'string' ? `pass-k-${error.code}` : 'pass-k-invalid'); }
  const unpaired = new Set(runs.flatMap(run => unpairedForwardedPasses(run)));
  const checks = column.checks.map(check => ({ id: check.id, role: check.role, trials: check.trials, passed: check.passed, failed: check.failed, undecided: check.undecided,
    k, floor, exact: check.exact, passHatK: check.passHatK, unpaired: unpaired.has(check.id), ...readingOf(check, floor, { unpaired: unpaired.has(check.id) }) }));
  return { column, checks };
}

/**
 * The gate summary with the trials beside the verdict. The primary trial's summary (with its comparison) is kept; every
 * other trial's reasons are added after it, in trial order, then checks-flaky. An error in any trial is an error (exit 2).
 * A trial summary that is itself a refusal (no current block) makes the whole result that refusal.
 */
export function applyTrials(primary, others, { trials, k, floor }, { column, checks }) {
  const refused = [primary, ...others].find(summary => summary.current === null);
  if (refused) return refused;
  const reasons = [...primary.reasons];
  for (const summary of others) for (const reason of summary.reasons) if (!reasons.includes(reason)) reasons.push(reason);
  if (checks.some(check => check.reading === 'FAIL-flaky')) reasons.push(FLAKY_REASON);
  const exitCode = [primary, ...others].some(summary => summary.exitCode === 2) || reasons.includes('runner-error') ? 2 : reasons.length ? 1 : 0;
  const { checks: _, ...passK } = column;
  // A repair the first trial shows is not credited when any check is not PASS over the trials.
  const withheld = primary.comparison?.requested === true && checks.some(check => check.reading !== 'PASS');
  const comparison = withheld ? { ...primary.comparison, restorationLabel: NO_VERIFIED_REPAIR, restorationWithheld: 'not-every-check-passed-every-trial' } : primary.comparison;
  return { ...primary, outcome: exitCode === 0 ? 'clean' : exitCode === 1 ? 'assessment-failed' : 'config-or-runtime-error', exitCode, reasons, comparison,
    trials: { schema: TRIALS_SCHEMA, trials, k, floor, runIds: [...column.runIds],
      readings: Object.fromEntries(READINGS.map(reading => [reading, checks.filter(check => check.reading === reading).length])),
      checks, perTrial: [primary, ...others].map(summary => ({ runId: summary.current.runId, exitCode: summary.exitCode, reasons: [...summary.reasons] })),
      passK, scope: [...SCOPE] } };
}

const once = (text, token) => text.indexOf(token) !== -1 && text.indexOf(token) === text.lastIndexOf(token);
const valueText = check => check.exact === null ? 'insufficient trials' : formatPassK(check);
const readingLine = (check, trials) => `Across ${trials.trials} trials: ${check.reading} (passed ${check.passed} of ${check.trials}; pass^${trials.k} ${valueText(check)}; floor ${check.floor}${check.unpaired ? '; a pass with no passing same-route control in a trial' : ''}).`;
const TRIALS_CSS = '.trials{border:2px solid #1d4f6e;background:#f2f7fa;padding:10px 14px;margin:18px 0}.trials-tag{font-weight:600}.trials-tag.not-pass{color:#9a3412}';

/** The first trial's report (as `scopehaven export` renders it) with a pass^k section before the limits and each check's reading in its article. */
export function trialsReport(run, summary) {
  const trials = summary?.trials, html = renderReport(run);
  if (!object(trials) || !once(html, '</style>') || !once(html, '<section class="limits">') || !once(html, '<title>')) throw new TrialsError('trials-report-failed');
  const rows = trials.checks.map(check => `<tr><td>${escape(check.id)}</td><td>${escape(check.role)}</td><td>${escape(check.trials)}</td><td>${escape(check.passed)}</td><td>${escape(check.failed)}</td><td>${escape(check.undecided)}</td><td>${escape(valueText(check))}</td><td>${escape(check.floor)}</td><td><strong>${escape(check.reading)}</strong></td></tr>`).join('');
  const section = `<section class="trials"><h2>Repeated trials: pass^k per check</h2><p>${escape(trials.trials)} trials · k = ${escape(trials.k)} · floor ${escape(trials.floor)} · gate outcome ${escape(summary.outcome)}${summary.reasons.length ? ` (${escape(summary.reasons.join(', '))})` : ''}.</p><p>Runs: ${escape(trials.runIds.join(', '))}.</p><table><thead><tr><th>Check</th><th>Role</th><th>Trials</th><th>Passed</th><th>Failed</th><th>Undecided</th><th>pass^k</th><th>Floor</th><th>Reading</th></tr></thead><tbody>${rows}</tbody></table><ul>${trials.scope.map(sentence => `<li>${escape(sentence)}</li>`).join('')}</ul></section>`;
  let out = html.replace('<title>', () => `<title>${escape(trials.trials)} trials · `).replace('</style>', () => `${TRIALS_CSS}</style>`).replace('<section class="limits">', () => `${section}<section class="limits">`);
  for (const check of trials.checks) {
    const token = `<article><h2>${escape(check.id)} · `;
    if (!once(out, token)) throw new TrialsError('trials-report-failed');
    const end = out.indexOf('</h2>', out.indexOf(token)) + '</h2>'.length;
    out = `${out.slice(0, end)}<p class="trials-tag${check.reading === 'PASS' ? '' : ' not-pass'}">${escape(readingLine(check, trials))}</p>${out.slice(end)}`;
  }
  return out;
}

/**
 * The first trial's SARIF with the column from trialColumn (sarifWithPassK) and, on each result and the run, properties.passKGate: the
 * k, the floor and the reading. A result whose reading is not PASS is never kind pass: kind fail (level from the rule)
 * when any trial failed it, otherwise a recorded pass becomes kind review when a trial's pass was unpaired (as src/sarif.mjs
 * projects one) or kind open. Its message starts with the reading, then the first trial's own message.
 */
export function trialsSarif(run, summary, column) {
  const trials = summary?.trials;
  if (!object(trials)) throw new TrialsError('trials-sarif-failed');
  let log;
  try { log = sarifWithPassK(JSON.parse(serializeSarif(run)), column); } catch { throw new TrialsError('trials-sarif-failed'); }
  const sarifRun = log.runs[0], byId = new Map(trials.checks.map(check => [check.id, check]));
  const levels = new Map(sarifRun.tool.driver.rules.map(rule => [rule.id, rule.defaultConfiguration?.level ?? 'warning']));
  for (const result of sarifRun.results) {
    const check = byId.get(result.ruleId);
    result.properties = { ...result.properties, passKGate: { k: trials.k, floor: check.floor, reading: check.reading, floorMet: check.floorMet, unpaired: check.unpaired } };
    if (check.reading === 'PASS') continue;
    if (check.failed > 0) { result.kind = 'fail'; result.level = levels.get(result.ruleId); }
    else if (result.kind === 'pass') { result.kind = check.unpaired ? 'review' : 'open'; result.level = 'none'; }
    result.message = { ...result.message, text: `[${readingLine(check, trials)}] First trial: ${typeof result.message?.text === 'string' ? result.message.text : ''}` };
  }
  sarifRun.properties = { ...sarifRun.properties, passKGate: { schema: TRIALS_SCHEMA, trials: trials.trials, k: trials.k, floor: trials.floor, runIds: [...trials.runIds], readings: { ...trials.readings }, outcome: summary.outcome } };
  return `${JSON.stringify(log, null, 2)}\n`;
}
