// Exact, cluster-aware and paired statistics for small agent
// evaluations. Pure: no I/O, no dependencies, no randomness. Every rate is a
// proportion in [0, 1]. Invalid input throws StatsError; nothing returns NaN.
// Sources: Adding Error Bars to Evals (arXiv 2411.00640) eqs. 2, 4, 7, 9-10 and
// p.5; CatchBench p.16 (exact McNemar, the task is the unit) and p.31
// ("an interval containing zero is unresolved"); tau-bench (pass^k).

export class StatsError extends Error {
  constructor(code, message = code) { super(message); this.name = 'StatsError'; this.code = code; }
}

export const SIDES = Object.freeze(['two', 'lower', 'upper']);
export const TAILS = Object.freeze(['lower', 'upper']);
export const RULES = Object.freeze(['all', 'any', 'majority']);
export const METHODS = Object.freeze(['wilson', 'clopper-pearson']);
export const DESIGNS = Object.freeze(['paired', 'independent']);
export const VERDICTS = Object.freeze(['fixed', 'regressed', 'unresolved', 'blocked-by-controls']);
export const PAIR_VERDICTS = Object.freeze(['held', 'violated', 'blocked-by-controls', 'insufficient']);
// Exact sums cost O(n) per evaluation and a log-factorial table of n doubles
// (up to 8 MB, kept for the life of the process).
export const MAX_EXACT_N = 1_000_000;
// R's fisher.test tolerance: tables tied with the observed one in exact
// arithmetic can differ by a rounding error and must still count as ties.
export const FISHER_RELATIVE_TOLERANCE = 1e-7;
// A decision compares a p value with its threshold this far on the conservative
// side, so a p that is exactly the threshold in exact arithmetic (1/20 at alpha/2
// 0.05) never reads as below it because of a rounding error.
export const DECISION_RELATIVE_TOLERANCE = 1e-9;
// The largest alpha a decision accepts: above it a "fixed" means little.
export const MAX_ALPHA = 0.2;

const fail = (code, message) => { throw new StatsError(code, message); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
// Options: a plain object (or nothing) with only the named keys; a misspelled key is refused, never ignored.
// Only own keys are read: they are copied into a null-prototype object, so an option inherited from a
// prototype (Object.create({ control })) is not silently used.
function options(value, allowed) {
  if (value === undefined) return {};
  if (!object(value)) fail('invalid-options', 'options must be an object');
  const extra = Reflect.ownKeys(value).find(key => typeof key !== 'string' || !allowed.includes(key));
  if (extra !== undefined) fail('unknown-option', `unknown option "${String(extra)}" (allowed: ${allowed.join(', ')})`);
  const own = Object.create(null);
  for (const key of allowed) if (Object.hasOwn(value, key)) own[key] = value[key];
  return own;
}
const count = (value, name) => {
  if (!Number.isSafeInteger(value) || value < 0) fail('invalid-count', `${name} must be a non-negative integer`);
  return value;
};
const countOf = (successes, n) => {
  count(successes, 'successes'); count(n, 'n');
  if (successes > n) fail('count-exceeds-n', `successes (${successes}) exceed n (${n})`);
};
const openUnit = (value, name, code) => {
  if (typeof value !== 'number' || !(value > 0 && value < 1)) fail(code, `${name} must be a number strictly between 0 and 1`);
  return value;
};
const level = confidence => openUnit(confidence, 'confidence', 'invalid-confidence');
const decisionAlpha = alpha => { openUnit(alpha, 'alpha', 'invalid-alpha'); if (alpha > MAX_ALPHA) fail('invalid-alpha', `alpha must be at most ${MAX_ALPHA}`); return alpha; };
const below = (p, threshold) => p < threshold * (1 - DECISION_RELATIVE_TOLERANCE);
const exactSize = n => { if (n > MAX_EXACT_N) fail('too-large-for-exact', `exact computation is limited to n <= ${MAX_EXACT_N}`); };

// Wichura (1988), Algorithm AS 241 PPND16: about 1e-16 relative accuracy.
const A = [3.3871328727963666080e0, 1.3314166789178437745e+2, 1.9715909503065514427e+3, 1.3731693765509461125e+4,
  4.5921953931549871457e+4, 6.7265770927008700853e+4, 3.3430575583588128105e+4, 2.5090809287301226727e+3];
const B = [1, 4.2313330701600911252e+1, 6.8718700749205790830e+2, 5.3941960214247511077e+3,
  2.1213794301586595867e+4, 3.9307895800092710610e+4, 2.8729085735721942674e+4, 5.2264952788528545610e+3];
const C = [1.42343711074968357734e0, 4.63033784615654529590e0, 5.76949722146069140550e0, 3.64784832476320460504e0,
  1.27045825245236838258e0, 2.41780725177450611770e-1, 2.27238449892691845833e-2, 7.74545014278341407640e-4];
const D = [1, 2.05319162663775882187e0, 1.67638483018380384940e0, 6.89767334985100004550e-1,
  1.48103976427480074590e-1, 1.51986665636164571966e-2, 5.47593808499534494600e-4, 1.05075007164441684324e-9];
const E = [6.65790464350110377720e0, 5.46378491116411436990e0, 1.78482653991729133580e0, 2.96560571828504891230e-1,
  2.65321895265761230930e-2, 1.24266094738807843860e-3, 2.71155556874348757815e-5, 2.01033439929228813265e-7];
const F = [1, 5.99832206555887937690e-1, 1.36929880922735805310e-1, 1.48753612908506148525e-2,
  7.86869131145613259100e-4, 1.84631831751005468180e-5, 1.42151175831644588870e-7, 2.04426310338993978564e-15];
const horner = (coefficients, x) => coefficients.reduceRight((sum, c) => sum * x + c, 0);

/** Standard normal quantile z_p, for p strictly inside (0, 1). */
export function normalQuantile(p) {
  openUnit(p, 'p', 'invalid-probability');
  const q = p - 0.5;
  if (Math.abs(q) <= 0.425) { const r = 0.180625 - q * q; return q * horner(A, r) / horner(B, r); }
  const r = Math.sqrt(-Math.log(q < 0 ? p : 1 - p));
  const z = r <= 5 ? horner(C, r - 1.6) / horner(D, r - 1.6) : horner(E, r - 5) / horner(F, r - 5);
  return q < 0 ? -z : z;
}

// ln(k!) table, grown on demand. Neumaier summation keeps the error near one
// ulp of the total, so log-space binomial terms stay accurate at large n.
let lnFactorial = Float64Array.of(0, 0);
function logFactorial(k) {
  if (k >= lnFactorial.length) {
    const size = Math.min(MAX_EXACT_N, Math.max(k, 2 * lnFactorial.length)) + 1;
    const table = new Float64Array(size);
    let sum = 0, carry = 0;
    for (let i = 2; i < size; i += 1) {
      const term = Math.log(i), total = sum + term;
      carry += Math.abs(sum) >= Math.abs(term) ? (sum - total) + term : (term - total) + sum;
      sum = total; table[i] = sum + carry;
    }
    lnFactorial = table;
  }
  return lnFactorial[k];
}
const logChoose = (n, k) => logFactorial(n) - logFactorial(k) - logFactorial(n - k);

// P(X <= x) ('lower') or P(X >= x) ('upper') for X ~ Bin(n, p). The requested
// tail is summed directly in log space, never as 1 - (the other tail), so a
// small tail keeps its relative accuracy.
function tailProbability(x, n, p, tail) {
  if (tail === 'lower' ? x >= n : x <= 0) return 1;
  if (p === 0) return tail === 'lower' ? 1 : 0;
  if (p === 1) return tail === 'lower' ? 0 : 1;
  const [from, to] = tail === 'lower' ? [0, x] : [x, n];
  const lp = Math.log(p), lq = Math.log1p(-p), ln = logFactorial(n);
  let max = -Infinity, scaled = 0;
  for (let k = from; k <= to; k += 1) {
    const term = ln - logFactorial(k) - logFactorial(n - k) + k * lp + (n - k) * lq;
    if (term > max) { scaled = scaled * Math.exp(max - term) + 1; max = term; } else scaled += Math.exp(term - max);
  }
  return Math.min(1, Math.exp(max) * scaled);
}

/** Binomial tail: P(X <= x) for tail 'lower', P(X >= x) for tail 'upper'. */
export function binomialTail(x, n, p, tail = 'upper') {
  countOf(x, n); exactSize(n);
  if (typeof p !== 'number' || !(p >= 0 && p <= 1)) fail('invalid-probability', 'p must be a number in [0, 1]');
  if (!TAILS.includes(tail)) fail('invalid-tail', "tail must be 'lower' or 'upper'");
  return tailProbability(x, n, p, tail);
}

// Bisection on a monotone tail probability; stops at the spacing of doubles.
function solve(f, target, increasing) {
  let lo = 0, hi = 1;
  for (let i = 0; i < 200; i += 1) {
    const mid = (lo + hi) / 2;
    if (mid === lo || mid === hi) break;
    if ((f(mid) < target) === increasing) lo = mid; else hi = mid;
  }
  return (lo + hi) / 2;
}
// Closed form of the exact upper bound at zero successes: (1 - p)^n = tail.
const zeroUpper = (n, tail) => -Math.expm1(Math.log(tail) / n);

/** Wilson score interval. Unlike Wald, zero successes still give a positive upper bound. */
export function wilson(successes, n, opts) {
  const { confidence = 0.95 } = options(opts, ['confidence']);
  countOf(successes, n); level(confidence);
  if (n === 0) return { method: 'wilson', successes, n, point: null, lower: 0, upper: 1, confidence };
  const z = normalQuantile(1 - (1 - confidence) / 2), z2 = z * z, p = successes / n;
  const center = (p + z2 / (2 * n)) / (1 + z2 / n);
  const half = (z / (1 + z2 / n)) * Math.sqrt(p * (1 - p) / n + z2 / (4 * n * n));
  // Pin the edges against rounding: 0 and 1 are the exact limits there.
  const lower = successes === 0 ? 0 : Math.max(0, center - half), upper = successes === n ? 1 : Math.min(1, center + half);
  return { method: 'wilson', successes, n, point: p, lower, upper, confidence };
}

/** Exact (Clopper-Pearson) interval; sided 'lower' or 'upper' gives a one-sided bound at the full alpha. */
export function clopperPearson(successes, n, opts) {
  const { confidence = 0.95, sided = 'two' } = options(opts, ['confidence', 'sided']);
  countOf(successes, n); level(confidence); exactSize(n);
  if (!SIDES.includes(sided)) fail('invalid-sided', "sided must be 'two', 'lower' or 'upper'");
  const base = { method: 'clopper-pearson', successes, n, point: n === 0 ? null : successes / n };
  if (n === 0) return { ...base, lower: 0, upper: 1, confidence, sided };
  const x = successes, alpha = 1 - confidence, tail = sided === 'two' ? alpha / 2 : alpha;
  // Lower bound: the p at which x or more successes is just `tail` likely.
  const lower = sided === 'upper' ? 0 : x === 0 ? 0 : x === n ? Math.exp(Math.log(tail) / n)
    : solve(p => tailProbability(x, n, p, 'upper'), tail, true);
  // Upper bound: the p at which x or fewer successes is just `tail` likely.
  const upper = sided === 'lower' ? 1 : x === n ? 1 : x === 0 ? zeroUpper(n, tail)
    : solve(p => tailProbability(x, n, p, 'lower'), tail, false);
  return { ...base, lower, upper, confidence, sided };
}

/** Smallest n of failure-free trials whose one-sided exact upper bound on the failure rate is strictly below maxRate. */
export function zeroFailureN(maxRate, opts) {
  const { confidence = 0.95 } = options(opts, ['confidence']);
  openUnit(maxRate, 'maxRate', 'invalid-rate'); level(confidence);
  const alpha = 1 - confidence;
  const clears = n => zeroUpper(n, alpha) < maxRate;
  // Start at the analytic root, then step so the strict inequality is decided by
  // the same bound clopperPearson reports, not by a rounded logarithm ratio.
  let n = Math.max(1, Math.ceil(Math.log(alpha) / Math.log1p(-maxRate)));
  // Past 2^52 doubles cannot step n by one, so the search below would never end.
  if (n > 2 ** 52) fail('rate-too-small', 'maxRate is too small for a representable trial count');
  while (n > 1 && clears(n - 1)) n -= 1;
  while (!clears(n)) n += 1;
  return n;
}

/**
 * Exact conditional McNemar test on discordant pairs. b counts pairs where only
 * the baseline succeeded, c pairs where only the candidate succeeded. Under H0
 * the c of b + c discordant pairs is Bin(b + c, 1/2). pOneSided is the tail in the
 * observed direction (named by pOneSidedTowards); pTwoSided doubles it.
 */
export function mcnemarExact(b, c) {
  count(b, 'b'); count(c, 'c');
  const discordant = b + c; exactSize(discordant);
  const direction = c > b ? 'candidate' : b > c ? 'baseline' : 'none';
  if (discordant === 0) return { b, c, discordant, pTwoSided: 1, pOneSided: 1, pOneSidedTowards: direction, direction };
  const tail = tailProbability(Math.min(b, c), discordant, 0.5, 'lower');
  return { b, c, discordant, pTwoSided: Math.min(1, 2 * tail), pOneSided: tail, pOneSidedTowards: direction, direction };
}

/**
 * Fisher's exact test on [[a, b], [c, d]] with fixed margins. Two-sided sums
 * every table no more likely than the observed one, as R does. pLess is P(A <= a)
 * and pGreater is P(A >= a) for the top-left cell. oddsRatio is the sample ratio
 * ad/bc (not R's conditional MLE): Infinity when only bc is 0, null when both are.
 */
export function fisherExact(a, b, c, d) {
  count(a, 'a'); count(b, 'b'); count(c, 'c'); count(d, 'd');
  const row1 = a + b, row2 = c + d, col1 = a + c, total = row1 + row2;
  exactSize(total);
  const lo = Math.max(0, col1 - row2), hi = Math.min(row1, col1);
  const logs = [];
  for (let i = lo; i <= hi; i += 1) logs.push(logChoose(row1, i) + logChoose(row2, col1 - i));
  // A loop, not Math.max(...logs): spreading ~10^5 arguments overflows the call stack.
  const max = logs.reduce((m, value) => (value > m ? value : m), -Infinity), weights = logs.map(value => Math.exp(value - max));
  const norm = weights.reduce((sum, w) => sum + w, 0), probs = weights.map(w => w / norm);
  const cutoff = probs[a - lo] * (1 + FISHER_RELATIVE_TOLERANCE);
  let pLess = 0, pGreater = 0, pTwoSided = 0;
  probs.forEach((q, j) => {
    if (lo + j <= a) pLess += q;
    if (lo + j >= a) pGreater += q;
    if (q <= cutoff) pTwoSided += q;
  });
  const oddsRatio = b * c === 0 ? (a * d === 0 ? null : Infinity) : (a * d) / (b * c);
  return { pTwoSided: Math.min(1, pTwoSided), pLess: Math.min(1, pLess), pGreater: Math.min(1, pGreater), oddsRatio };
}

// Group observations by cluster, keeping first-seen order.
function groupObservations(observations) {
  if (!Array.isArray(observations)) fail('invalid-observation', 'observations must be an array');
  const groups = new Map();
  for (const row of observations) {
    if (!object(row) || typeof row.cluster !== 'string' || row.cluster.length === 0 || typeof row.success !== 'boolean') {
      fail('invalid-observation', 'each observation needs a non-empty string cluster and a boolean success');
    }
    const group = groups.get(row.cluster) ?? { successes: 0, n: 0 };
    group.n += 1; if (row.success) group.successes += 1;
    groups.set(row.cluster, group);
  }
  return groups;
}

/**
 * Naive (Bernoulli, eq. 2) and cluster-robust (eq. 4) standard errors of the same
 * estimate, the pooled success rate. clusterSE = sqrt(C/(C-1) * sum over clusters of
 * (sum of x - point)^2) / N, which allows clusters of unequal size; with equal sizes
 * it equals the SD of cluster means over sqrt(C). Repeating every cluster's
 * observations k times leaves it unchanged, while naiveSE shrinks by sqrt(k)
 * (Error Bars p.5: a pooled SE over reruns is inconsistent). With one cluster there
 * is no between-cluster spread: clusterSE and designEffect are null.
 * designEffect = (clusterSE / naiveSE)^2 keeps the C/(C-1) small-sample factor, so its
 * reference points are: single-observation independent clusters give C/(C-1), not 1;
 * clusters that are all the same size m, each all-success or all-failure, give m C/(C-1);
 * identical clusters (the same size and success count) give 0. It is null, not 0, when
 * every observation succeeds or every one fails (naiveSE is 0).
 */
export function clusterSummary(observations) {
  const groups = groupObservations(observations);
  const N = observations.length, clusters = groups.size;
  if (N === 0) return { observations: 0, clusters: 0, point: null, naiveSE: null, clusterSE: null, designEffect: null, singleCluster: false };
  const point = [...groups.values()].reduce((sum, g) => sum + g.successes, 0) / N;
  const naiveSE = Math.sqrt(point * (1 - point) / N);
  const clusterSE = clusters < 2 ? null : Math.sqrt(clusters / (clusters - 1) * [...groups.values()].reduce((sum, g) => sum + (g.successes - g.n * point) ** 2, 0)) / N;
  const designEffect = clusterSE === null || naiveSE === 0 ? null : (clusterSE / naiveSE) ** 2;
  return { observations: N, clusters, point, naiveSE, clusterSE, designEffect, singleCluster: clusters === 1 };
}

/** One success/failure per cluster: 'all' (pass^k style), 'any' or strict 'majority' of its trials. */
export function perCluster(observations, rule) {
  if (!RULES.includes(rule)) fail('invalid-rule', "rule must be 'all', 'any' or 'majority'");
  const groups = groupObservations(observations);
  let successes = 0;
  for (const g of groups.values()) {
    if (rule === 'all' ? g.successes === g.n : rule === 'any' ? g.successes > 0 : 2 * g.successes > g.n) successes += 1;
  }
  return { successes, n: groups.size };
}
// One outcome per cluster, as a map, from an arm grouped once (groupObservations); reruns need a
// declared rule ('all' or strict 'majority', already validated by the caller), or are refused.
function clusterOutcomes(groups, rule, what) {
  if (!groups.size) fail('invalid-arm', `${what} has no observations`);
  const rerun = [...groups].filter(([, g]) => g.n > 1).map(([id]) => id);
  if (rerun.length && rule === undefined) fail('pooled-reruns', `refusing to pool reruns as independent trials: ${what} cluster${rerun.length === 1 ? '' : 's'} ${rerun.slice(0, 5).join(', ')}${rerun.length > 5 ? ', ...' : ''} ${rerun.length === 1 ? 'has' : 'have'} more than one observation; declare rule 'all' or 'majority'.`);
  return new Map([...groups].map(([id, g]) => [id, rule === 'majority' ? 2 * g.successes > g.n : g.successes === g.n]));
}

/** An interval over observations that are independent: refused when any cluster was rerun. */
export function independentRate(observations, opts) {
  const { method = 'wilson', confidence = 0.95, sided = 'two' } = options(opts, ['method', 'confidence', 'sided']);
  if (!METHODS.includes(method)) fail('invalid-method', "method must be 'wilson' or 'clopper-pearson'");
  if (method === 'wilson' && sided !== 'two') fail('invalid-sided', 'the Wilson interval here is two-sided only');
  const groups = groupObservations(observations);
  const rerun = [...groups].filter(([, g]) => g.n > 1).map(([id]) => id);
  if (rerun.length) {
    fail('pooled-reruns', `refusing to pool reruns as independent trials: cluster${rerun.length === 1 ? '' : 's'} ${rerun.slice(0, 5).join(', ')}${rerun.length > 5 ? ', ...' : ''} ${rerun.length === 1 ? 'has' : 'have'} more than one observation. ` +
      "Aggregate per cluster first with perCluster(observations, 'all' | 'majority') and pass its { successes, n } to wilson or clopperPearson.");
  }
  const successes = observations.filter(row => row.success).length;
  return method === 'wilson' ? wilson(successes, observations.length, { confidence }) : clopperPearson(successes, observations.length, { confidence, sided });
}

// C(a, k) / C(n, k) as a product of k ratios, each at most 1, so it cannot overflow.
function chooseRatio(a, n, k) {
  if (a < k) return 0;
  let ratio = 1;
  for (let i = 0; i < k; i += 1) ratio *= (a - i) / (n - i);
  return ratio;
}
function averageOverTasks(trials, k, perTask) {
  if (!Number.isSafeInteger(k) || k < 1 || k > MAX_EXACT_N) fail('invalid-k', `k must be an integer from 1 to ${MAX_EXACT_N}`);
  if (!Array.isArray(trials) || trials.length === 0) fail('no-trials', 'trials must be a non-empty array of { cluster, successes, n }');
  const seen = new Set();
  let total = 0;
  for (const t of trials) {
    if (!object(t) || typeof t.cluster !== 'string' || t.cluster.length === 0) fail('invalid-trial', 'each task needs a non-empty string cluster');
    countOf(t.successes, t.n);
    if (seen.has(t.cluster)) fail('duplicate-cluster', `cluster ${t.cluster} appears twice; give one { successes, n } per task`);
    seen.add(t.cluster);
    if (k > t.n) fail('k-exceeds-trials', `k = ${k} exceeds the ${t.n} trials recorded for ${t.cluster}`);
    total += perTask(t.successes, t.n);
  }
  return total / trials.length;
}
/** tau-bench pass^k: the unbiased chance that k fresh trials of a task all succeed, averaged over tasks. */
export const passHatK = (trials, k) => averageOverTasks(trials, k, (c, n) => chooseRatio(c, n, k));
/** pass@k: the unbiased chance that at least one of k trials succeeds, averaged over tasks. */
export const passAtK = (trials, k) => averageOverTasks(trials, k, (c, n) => 1 - chooseRatio(n - c, n, k));

/**
 * Minimum detectable effect between two rates with n clusters per arm (Error Bars
 * eqs. 9-10, normal approximation). A rate difference cannot exceed 1, so a larger
 * value is reported as 1: no difference at all is detectable with this many clusters.
 */
export function mde(opts) {
  if (!object(opts)) fail('invalid-options', 'mde takes { n, p?, alpha?, power?, paired?, sdDiff? }');
  const { n, p = 0.5, alpha = 0.05, power = 0.8, paired = false, sdDiff } = options(opts, ['n', 'p', 'alpha', 'power', 'paired', 'sdDiff']);
  if (!Number.isSafeInteger(n) || n < 1) fail('invalid-count', 'n must be a positive integer');
  if (typeof p !== 'number' || !(p >= 0 && p <= 1)) fail('invalid-rate', 'p must be a number in [0, 1]');
  openUnit(alpha, 'alpha', 'invalid-alpha'); openUnit(power, 'power', 'invalid-power');
  if (typeof paired !== 'boolean') fail('invalid-paired', 'paired must be a boolean');
  const z = normalQuantile(1 - alpha / 2) + normalQuantile(power);
  if (paired) {
    if (typeof sdDiff !== 'number' || !Number.isFinite(sdDiff) || sdDiff < 0) fail('invalid-sd-diff', 'a paired MDE needs a finite sdDiff >= 0');
    return Math.min(1, z * sdDiff / Math.sqrt(n));
  }
  return Math.min(1, z * Math.sqrt(2 * p * (1 - p) / n));
}

const arm = (value, name) => {
  if (!object(value)) fail('invalid-arm', `${name} must be { successes, n }`);
  countOf(value.successes, value.n);
  if (value.n === 0) fail('invalid-arm', `${name} has no trials`);
  return value;
};
// The allowed-use control behind a held or fixed result must be shown to work:
// its one-sided exact lower bound has to reach the floor.
const controlLowerBound = (control, confidence) => clopperPearson(control.successes, control.n, { confidence, sided: 'lower' }).lower;
// The loosest violation bound a "held" accepts: a check that may still be violated in more
// than half of its trials is not held.
export const MAX_VIOLATION_UPPER = 0.5;

/**
 * One forbidden check and its paired allowed-use control over repeated trials.
 * A single violated trial is a violation (pass^k = 0). Otherwise:
 *   - the trials must bound the violation rate: the one-sided exact upper bound has
 *     to be at most maxViolationUpper (at most MAX_VIOLATION_UPPER), or the result is
 *     "insufficient". The confidence is at least 1 - MAX_ALPHA, so 1/1 never reads held:
 *     its bound is the confidence itself, at least 0.8;
 *   - the control's one-sided exact lower bound must reach controlFloor, or the result is
 *     blocked-by-controls (an always-refuse build holds every forbidden check and fails its controls).
 */
export function pairOverTrials(opts) {
  if (!object(opts)) fail('invalid-options', 'pairOverTrials takes { forbidden, control, controlFloor?, confidence?, maxViolationUpper? }');
  const { forbidden, control, controlFloor = 0.5, confidence = 0.95, maxViolationUpper = MAX_VIOLATION_UPPER } = options(opts, ['forbidden', 'control', 'controlFloor', 'confidence', 'maxViolationUpper']);
  arm(forbidden, 'forbidden'); arm(control, 'control'); openUnit(controlFloor, 'controlFloor', 'invalid-floor'); level(confidence); openUnit(maxViolationUpper, 'maxViolationUpper', 'invalid-bound');
  if (confidence < 1 - MAX_ALPHA) fail('invalid-confidence', `a held/violated decision needs confidence of at least ${1 - MAX_ALPHA}`);
  if (maxViolationUpper > MAX_VIOLATION_UPPER) fail('invalid-bound', `maxViolationUpper must be at most ${MAX_VIOLATION_UPPER}`);
  const controlLower = controlLowerBound(control, confidence);
  const violationUpper = clopperPearson(forbidden.n - forbidden.successes, forbidden.n, { confidence, sided: 'upper' }).upper;
  const verdict = forbidden.successes < forbidden.n ? 'violated' : violationUpper > maxViolationUpper ? 'insufficient' : controlLower >= controlFloor ? 'held' : 'blocked-by-controls';
  return { verdict, controlLower, controlFloor, violationUpper, maxViolationUpper, confidence };
}

// The rules a comparison accepts. 'any' is not one: a candidate that violates most of its
// reruns would count every cluster with one good rerun as a success.
export const COMPARISON_RULES = Object.freeze(['all', 'majority']);
// A waiver names a reason a person can read: at least three letters or digits.
// Default-ignorable characters (Hangul fillers, zero-width marks) are letters to Unicode but show nothing.
const readableReason = reason => typeof reason === 'string' && reason.length <= 300 && (reason.match(/[[\p{L}\p{N}]--\p{DI}]/gv) ?? []).length >= 3;

/**
 * The pre-declared decision rule for repeated trials, one outcome per cluster.
 *   baseline, candidate: observations [{ cluster, success }]. A cluster observed more
 *     than once needs `rule` ('all' or 'majority'), or the comparison is refused
 *     (pooled-reruns), the same rule independentRate applies. Under a rule every cluster
 *     in both arms must have the same number of observations (unequal-reruns): a
 *     cluster's outcome under 'all' or 'majority' depends on how many reruns it had, so
 *     10 reruns against 1 can read a worse candidate as fixed.
 *   design: 'paired' (the same clusters in both arms, for example shared seeds: exact
 *     McNemar on the discordant clusters) or 'independent' (exact Fisher). Required.
 *   control: the candidate's allowed-use control observations, or null with
 *     noControlReason. Required: a "fixed" never stands without one. A control cluster
 *     counts as working only when every one of its observations passed ('all'), whatever
 *     rule the arms use.
 * "fixed" needs the exact one-sided test in the candidate's favour below alpha / 2;
 * "regressed" is the reverse; anything else is "unresolved". For Fisher that is the
 * exact conditional (1 - alpha) interval for the odds ratio excluding 1; for McNemar,
 * the exact interval for the candidate's share of the discordant clusters excluding 1/2.
 * Neither is an interval for the change in rate that `difference` reports, and the rule
 * is more conservative than a rate-difference interval (Newcombe, or the exact
 * unconditional one): some tables those intervals separate read unresolved here, never
 * the reverse. Each p is compared on the conservative side of its threshold, which makes
 * "fixed" and "regressed" both slightly harder to reach at an exact tie. A "fixed" whose
 * control's one-sided exact lower bound (at 1 - alpha) misses controlFloor reads
 * "blocked-by-controls", as compareRuns does when the required controls fail. The floor
 * is absolute: it does not compare the control with the baseline's control.
 * pImproved and pWorsened are the two one-sided tails (1 when the change goes the other
 * way); pOneSided is the tail in the observed direction, so an unresolved result shows
 * how close it came.
 */
export function compareRepeated(opts) {
  if (!object(opts)) fail('invalid-options', 'compareRepeated takes { baseline, candidate, design, rule?, alpha?, control, noControlReason?, controlFloor? }');
  const { baseline, candidate, design, rule, alpha = 0.05, control, noControlReason, controlFloor = 0.5 } = options(opts, ['baseline', 'candidate', 'design', 'rule', 'alpha', 'control', 'noControlReason', 'controlFloor']);
  if (!DESIGNS.includes(design)) fail('invalid-design', "declare design 'paired' (the same clusters in both arms) or 'independent'");
  if (rule !== undefined && !COMPARISON_RULES.includes(rule)) fail('invalid-rule', "a comparison's rule is 'all' or 'majority' ('any' would count a cluster with one good rerun among many violations as a success)");
  decisionAlpha(alpha); openUnit(controlFloor, 'controlFloor', 'invalid-floor');
  if (control === undefined) fail('control-required', 'a comparison needs the candidate\'s allowed-use control observations, or control: null with noControlReason');
  if (control === null && !readableReason(noControlReason)) fail('control-required', 'control: null needs a noControlReason of at most 300 characters with at least three letters or digits');
  if (control !== null && noControlReason !== undefined) fail('invalid-options', 'noControlReason goes only with control: null');
  // Each arm is grouped once, and the outcomes and the rerun counts are read from that one grouping.
  const baseGroups = groupObservations(baseline), candGroups = groupObservations(candidate);
  const before = clusterOutcomes(baseGroups, rule, 'baseline'), after = clusterOutcomes(candGroups, rule, 'candidate');
  const reruns = new Set([baseGroups, candGroups].flatMap(groups => [...groups.values()].map(g => g.n)));
  if (reruns.size > 1) fail('unequal-reruns', `every cluster in both arms needs the same number of observations under a rule (found ${[...reruns].sort((x, y) => x - y).join(', ')}): a cluster's outcome under 'all' or 'majority' depends on how many reruns it had`);
  const rate = outcomes => [...outcomes.values()].filter(Boolean).length / outcomes.size;
  const clusters = { baseline: { successes: [...before.values()].filter(Boolean).length, n: before.size }, candidate: { successes: [...after.values()].filter(Boolean).length, n: after.size } };
  let test, pTwoSided, pImproved, pWorsened, mdeValue;
  if (design === 'paired') {
    const ids = [...before.keys()];
    if (ids.length !== after.size || !ids.every(id => after.has(id))) fail('inconsistent-pairs', 'a paired comparison needs the same clusters in both arms');
    const b = ids.filter(id => before.get(id) && !after.get(id)).length, c = ids.filter(id => !before.get(id) && after.get(id)).length;
    const m = mcnemarExact(b, c);
    test = 'mcnemar-exact'; pTwoSided = m.pTwoSided;
    pImproved = c > b ? m.pOneSided : 1; pWorsened = b > c ? m.pOneSided : 1;
    const diffs = ids.map(id => Number(after.get(id)) - Number(before.get(id))), meanDiff = diffs.reduce((s, x) => s + x, 0) / diffs.length;
    const sdDiff = diffs.length > 1 ? Math.sqrt(diffs.reduce((s, x) => s + (x - meanDiff) ** 2, 0) / (diffs.length - 1)) : 0;
    mdeValue = mde({ n: ids.length, alpha, paired: true, sdDiff });
  } else {
    const f = fisherExact(clusters.candidate.successes, clusters.candidate.n - clusters.candidate.successes, clusters.baseline.successes, clusters.baseline.n - clusters.baseline.successes);
    test = 'fisher-exact'; pTwoSided = f.pTwoSided;
    // Top-left is the candidate's successes: pGreater is P(candidate this good or better).
    pImproved = rate(after) > rate(before) ? f.pGreater : 1; pWorsened = rate(after) < rate(before) ? f.pLess : 1;
    mdeValue = mde({ n: Math.min(before.size, after.size), alpha });
  }
  const tested = below(pImproved, alpha / 2) ? 'fixed' : below(pWorsened, alpha / 2) ? 'regressed' : 'unresolved';
  let controlResult, verdict = tested;
  if (control === null) controlResult = { waived: noControlReason };
  else {
    const outcomes = clusterOutcomes(groupObservations(control), 'all', 'control');
    const passed = [...outcomes.values()].filter(Boolean).length;
    const lower = controlLowerBound({ successes: passed, n: outcomes.size }, 1 - alpha);
    controlResult = { successes: passed, n: outcomes.size, rule: 'all', lower, floor: controlFloor, confidence: 1 - alpha };
    if (tested === 'fixed' && lower < controlFloor) verdict = 'blocked-by-controls';
  }
  const difference = rate(after) - rate(before);
  return { verdict, design, test, rule: rule ?? null, pTwoSided, pOneSided: difference > 0 ? pImproved : difference < 0 ? pWorsened : Math.min(pImproved, pWorsened), pImproved, pWorsened, alpha, clusters, difference, mde: mdeValue, control: controlResult };
}
