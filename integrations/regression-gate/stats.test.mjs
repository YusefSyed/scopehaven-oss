import test from 'node:test';
import assert from 'node:assert/strict';
import {
  StatsError, SIDES, TAILS, RULES, METHODS, VERDICTS, MAX_EXACT_N, FISHER_RELATIVE_TOLERANCE,
  normalQuantile, binomialTail, wilson, clopperPearson, zeroFailureN, mcnemarExact, fisherExact,
  clusterSummary, perCluster, independentRate, passHatK, passAtK, mde, compareRepeated, PAIR_VERDICTS, pairOverTrials, DESIGNS, MAX_ALPHA, DECISION_RELATIVE_TOLERANCE,
  COMPARISON_RULES, MAX_VIOLATION_UPPER,
} from './stats.mjs';

// Small-sample statistics. Pure arithmetic: no network, no model call, no file I/O.
// Every expected number is hand-computed inline, a closed form, a published
// value, or an independent reference computed outside this module with exact
// integer binomials (Python math.comb / fractions.Fraction) or math.lgamma; the
// source is named beside each value. Default tolerance 5e-4.

const near = (actual, expected, tolerance = 5e-4, label = '') =>
  assert.ok(Math.abs(actual - expected) <= tolerance, `${label} expected ${expected} ± ${tolerance}, got ${actual}`);
const relative = (actual, expected, tolerance, label = '') =>
  assert.ok(Math.abs(actual - expected) <= tolerance * Math.abs(expected), `${label} expected ${expected} (relative ${tolerance}), got ${actual}`);
const refuses = (fn, code) => assert.throws(fn, error => error instanceof StatsError && error.code === code, `expected StatsError ${code}`);
const Z975 = 1.959963984540054, Z80 = 0.8416212335729143;

test('exported constants are frozen', () => {
  for (const list of [SIDES, TAILS, RULES, METHODS, VERDICTS, PAIR_VERDICTS, COMPARISON_RULES]) assert.ok(Object.isFrozen(list));
  assert.deepEqual(COMPARISON_RULES, ['all', 'majority'], "'any' is not a comparison rule");
  assert.deepEqual(VERDICTS, ['fixed', 'regressed', 'unresolved', 'blocked-by-controls']);
  assert.deepEqual(PAIR_VERDICTS, ['held', 'violated', 'blocked-by-controls', 'insufficient']);
  assert.deepEqual(DESIGNS, ['paired', 'independent']);
  assert.deepEqual([MAX_ALPHA, DECISION_RELATIVE_TOLERANCE], [0.2, 1e-9]);
  assert.equal(FISHER_RELATIVE_TOLERANCE, 1e-7);
});

test('normalQuantile matches known quantiles to 1e-9 in all three AS241 regions', () => {
  // Central region (|p - 0.5| <= 0.425).
  assert.equal(normalQuantile(0.5), 0);
  near(normalQuantile(0.8), Z80, 1e-9, 'z_0.8');
  near(normalQuantile(0.3), -0.5244005127080408, 1e-9, 'z_0.3');
  // Intermediate tail (r <= 5).
  near(normalQuantile(0.975), Z975, 1e-9, 'z_0.975');
  near(normalQuantile(0.95), 1.6448536269514722, 1e-9, 'z_0.95');
  near(normalQuantile(0.995), 2.5758293035489004, 1e-9, 'z_0.995');
  near(normalQuantile(0.999), 3.090232306167813, 1e-9, 'z_0.999');
  near(normalQuantile(0.9999), 3.7190164854557084, 1e-9, 'z_0.9999');
  // Far tail (r > 5, p < exp(-25)); references checked by round trip through math.erfc.
  near(normalQuantile(1e-12), -7.034483825301132, 1e-9, 'z_1e-12');
  near(normalQuantile(1e-20), -9.262340089798407, 1e-9, 'z_1e-20');
  // Deep tail, where the intermediate polynomial extrapolated would drift by
  // 5e-8 (1e-50) to 5e-5 (1e-300); a mutation sweep showed 1e-12 and 1e-20 miss that.
  near(normalQuantile(1e-50), -14.933337534788489, 1e-9, 'z_1e-50');
  near(normalQuantile(1e-100), -21.273453560965322, 1e-9, 'z_1e-100');
  near(normalQuantile(1e-300), -37.0470962993612, 1e-9, 'z_1e-300');
  // Symmetry only where 1 - p is exact in doubles (1 - (1 - 1e-15) is not 1e-15).
  for (const p of [0.25, 0.125, 0.0078125, 2 ** -30]) assert.equal(normalQuantile(p), -normalQuantile(1 - p), `symmetry at ${p}`);
  for (const bad of [0, 1, -0.1, 1.1, Number.NaN, '0.5', undefined]) refuses(() => normalQuantile(bad), 'invalid-probability');
});

test('wilson: hand-computed edges, published values, and a positive upper bound at zero successes', () => {
  const z2 = Z975 * Z975;
  const zero = wilson(0, 10);
  // At x = 0 the Wilson upper bound is z^2 / (n + z^2); a Wald interval gives 0 here.
  assert.equal(zero.lower, 0);
  near(zero.upper, z2 / (10 + z2), 1e-9, 'Wilson 0/10 closed form');
  near(zero.upper, 0.2775, 5e-4, 'Wilson 0/10 upper');
  assert.ok(zero.upper > 0, 'x = 0 must not give a zero upper bound (Wald)');
  assert.deepEqual(Object.keys(zero), ['method', 'successes', 'n', 'point', 'lower', 'upper', 'confidence']);
  assert.equal(zero.method, 'wilson'); assert.equal(zero.point, 0); assert.equal(zero.confidence, 0.95);
  // At x = n the lower bound is n / (n + z^2): the 50/50 pooled figure is 0.929.
  const all = wilson(50, 50);
  assert.equal(all.upper, 1);
  near(all.lower, 50 / (50 + z2), 1e-9, 'Wilson 50/50 closed form');
  near(all.lower, 0.929, 5e-4, 'Wilson 50/50 lower');
  // Interior values: 3/10 (independent formula evaluation) and Newcombe (1998) 81/263 = [0.2553, 0.3662].
  const mid = wilson(3, 10);
  near(mid.lower, 0.10779126740630099, 1e-9); near(mid.upper, 0.6032218525388546, 1e-9);
  const newcombe = wilson(81, 263);
  near(newcombe.lower, 0.2553, 5e-5); near(newcombe.upper, 0.3662, 5e-5);
  // Asymmetric about the point and reflected by x -> n - x.
  const reflected = wilson(7, 10);
  near(reflected.lower, 1 - mid.upper, 1e-12); near(reflected.upper, 1 - mid.lower, 1e-12);
  // Higher confidence is wider.
  const wide = wilson(3, 10, { confidence: 0.99 });
  assert.ok(wide.lower < mid.lower && wide.upper > mid.upper);
  assert.deepEqual(wilson(0, 0), { method: 'wilson', successes: 0, n: 0, point: null, lower: 0, upper: 1, confidence: 0.95 });
});

test('wilson and clopperPearson refuse invalid counts and confidence', () => {
  for (const fn of [wilson, clopperPearson]) {
    refuses(() => fn(-1, 10), 'invalid-count');
    refuses(() => fn(1.5, 10), 'invalid-count');
    refuses(() => fn(1, 2.5), 'invalid-count');
    refuses(() => fn(1, -2), 'invalid-count');
    refuses(() => fn('1', 10), 'invalid-count');
    refuses(() => fn(Number.NaN, 10), 'invalid-count');
    refuses(() => fn(11, 10), 'count-exceeds-n');
    for (const confidence of [0, 1, 1.2, -0.5, Number.NaN, '0.95']) refuses(() => fn(1, 10, { confidence }), 'invalid-confidence');
  }
  refuses(() => clopperPearson(1, 10, { sided: 'both' }), 'invalid-sided');
  refuses(() => clopperPearson(0, MAX_EXACT_N + 1), 'too-large-for-exact');
});

test('clopperPearson reproduces the x = n lower bounds 0.590 / 0.692 / 0.735 / 0.832 / 0.884', () => {
  const table = { 7: 0.590, 10: 0.692, 12: 0.735, 20: 0.832, 30: 0.884 };
  for (const [key, expected] of Object.entries(table)) {
    const n = Number(key), interval = clopperPearson(n, n);
    near(interval.lower, expected, 5e-4, `CP ${n}/${n} lower`);
    near(interval.lower, 0.025 ** (1 / n), 1e-12, `CP ${n}/${n} closed form`);
    assert.equal(interval.upper, 1);
  }
});

test('clopperPearson edges: x = 0 gives lower exactly 0, x = n gives upper exactly 1, and only there', () => {
  for (const n of [1, 2, 7, 30, 1000]) {
    assert.equal(clopperPearson(0, n).lower, 0);
    assert.equal(clopperPearson(n, n).upper, 1);
    // x = 0 upper closed form: (1 - p)^n = 0.025.
    near(clopperPearson(0, n).upper, 1 - 0.025 ** (1 / n), 1e-12, `CP 0/${n} upper`);
  }
  // One step inside the edges the bounds move off 0 and 1. References: Python
  // bisection on exact integer binomial sums.
  const one = clopperPearson(1, 7);
  near(one.lower, 0.003610296861900587, 1e-9, 'CP 1/7 lower'); near(one.upper, 0.5787231970431952, 1e-9, 'CP 1/7 upper');
  const six = clopperPearson(6, 7);
  near(six.lower, 1 - one.upper, 1e-9); near(six.upper, 1 - one.lower, 1e-9);
  assert.ok(six.upper < 1 && one.lower > 0);
  near(clopperPearson(2, 7).upper, 0.7095791362626573, 1e-9, 'CP 2/7 upper');
  const three = clopperPearson(3, 10);
  near(three.lower, 0.0667395111777345, 1e-9); near(three.upper, 0.6524528500599973, 1e-9);
  assert.deepEqual(clopperPearson(0, 0), { method: 'clopper-pearson', successes: 0, n: 0, point: null, lower: 0, upper: 1, confidence: 0.95, sided: 'two' });
});

test('clopperPearson one-sided bounds spend the full alpha on one side', () => {
  const upper = clopperPearson(0, 20, { sided: 'upper' });
  assert.equal(upper.lower, 0);
  near(upper.upper, 1 - 0.05 ** (1 / 20), 1e-12); near(upper.upper, 0.139, 5e-4, '0/20 one-sided 95% upper');
  const lower = clopperPearson(10, 10, { sided: 'lower' });
  assert.equal(lower.upper, 1);
  near(lower.lower, 0.05 ** (1 / 10), 1e-12, '10/10 one-sided lower');
  // One-sided 95% is the matching side of the two-sided 90% interval.
  const ninety = clopperPearson(4, 15, { confidence: 0.9 });
  near(clopperPearson(4, 15, { sided: 'lower' }).lower, ninety.lower, 1e-12);
  near(clopperPearson(4, 15, { sided: 'upper' }).upper, ninety.upper, 1e-12);
  assert.ok(clopperPearson(4, 15, { sided: 'lower' }).lower > clopperPearson(4, 15).lower);
});

test('clopperPearson stays accurate at n = 10000', () => {
  const alpha2 = 0.025;
  // x = 1 and x = n - 1 have closed forms: 1 - (1 - p)^n = 0.025 and 1 - p^n = 0.025.
  relative(clopperPearson(1, 10000).lower, 1 - (1 - alpha2) ** (1 / 10000), 1e-9, 'CP 1/10000 lower');
  relative(1 - clopperPearson(9999, 10000).upper, 1 - (1 - alpha2) ** (1 / 10000), 1e-6, 'CP 9999/10000 upper');
  // Python lgamma + bisection references.
  relative(clopperPearson(1, 10000).upper, 0.000557036997946089, 1e-8, 'CP 1/10000 upper');
  const half = clopperPearson(5000, 10000);
  relative(half.lower, 0.4901513805899709, 1e-9); relative(half.upper, 0.5098486194100291, 1e-9);
  const thirty = clopperPearson(30, 10000);
  relative(thirty.lower, 0.002024974815870279, 1e-8); relative(thirty.upper, 0.0042799390870437645, 1e-8);
  // The defining property: each bound leaves exactly alpha/2 in its tail.
  for (const [x, n] of [[1, 10000], [30, 10000], [5000, 10000], [9990, 10000], [3, 10], [17, 40]]) {
    const { lower, upper } = clopperPearson(x, n);
    relative(binomialTail(x, n, lower, 'upper'), alpha2, 1e-9, `upper tail at lower bound ${x}/${n}`);
    relative(binomialTail(x, n, upper, 'lower'), alpha2, 1e-9, `lower tail at upper bound ${x}/${n}`);
  }
});

test('"ahead" thresholds: the largest rival count whose upper bound stays below our x = n lower bound', () => {
  // Expected thresholds, CP / Wilson. Both sides of each
  // comparison use the same method; recomputed here, not copied.
  const table = { 7: [1, 2], 10: [3, 4], 12: [5, 6], 20: [12, 13], 30: [22, 23] };
  const ahead = (n, interval) => {
    const ours = interval(n, n).lower;
    let best = -1;
    for (let r = 0; r <= n; r += 1) if (interval(r, n).upper < ours) best = r;
    return best;
  };
  for (const [key, [cp, w]] of Object.entries(table)) {
    const n = Number(key);
    assert.equal(ahead(n, clopperPearson), cp, `CP threshold at n = ${n}`);
    assert.equal(ahead(n, wilson), w, `Wilson threshold at n = ${n}`);
  }
});

test('binomialTail matches exact rational sums, including small tails', () => {
  // References: fractions.Fraction sums of math.comb terms.
  relative(binomialTail(37, 200, 0.2, 'lower'), 0.33453509779673934, 1e-10);
  relative(binomialTail(37, 200, 0.2, 'upper'), 0.7282627486357334, 1e-10);
  relative(binomialTail(900, 1000, 0.8, 'upper'), 8.731206511212329e-18, 1e-9);
  relative(binomialTail(10, 1000, 0.05, 'lower'), 2.7977985614856666e-12, 1e-9);
  // Hand: X ~ Bin(4, 1/2): P(X <= 1) = 5/16, P(X >= 3) = 5/16, P(X >= 1) = 15/16.
  near(binomialTail(1, 4, 0.5, 'lower'), 5 / 16, 1e-15);
  near(binomialTail(3, 4, 0.5, 'upper'), 5 / 16, 1e-15);
  near(binomialTail(1, 4, 0.5), 15 / 16, 1e-15);
  // Complement and edges.
  near(binomialTail(6, 20, 0.3, 'lower') + binomialTail(7, 20, 0.3, 'upper'), 1, 1e-14);
  assert.equal(binomialTail(5, 5, 0.3, 'lower'), 1);
  assert.equal(binomialTail(0, 5, 0.3, 'upper'), 1);
  assert.equal(binomialTail(2, 5, 0, 'lower'), 1); assert.equal(binomialTail(2, 5, 0, 'upper'), 0);
  assert.equal(binomialTail(2, 5, 1, 'lower'), 0); assert.equal(binomialTail(2, 5, 1, 'upper'), 1);
  for (const p of [-0.1, 1.1, Number.NaN, '0.5']) refuses(() => binomialTail(1, 5, p), 'invalid-probability');
  refuses(() => binomialTail(1, 5, 0.5, 'two'), 'invalid-tail');
  refuses(() => binomialTail(6, 5, 0.5), 'count-exceeds-n');
  refuses(() => binomialTail(-1, 5, 0.5), 'invalid-count');
});

test('binomialTail stays accurate up to MAX_EXACT_N', () => {
  // Exact integer references: a small tail at n = 20000, and the centre of
  // Bin(10^6, 1/2), where P(X <= n/2) = (1 + C(n, n/2) / 2^n) / 2 by symmetry.
  relative(binomialTail(1850, 20000, 0.1, 'lower'), 0.00018479674906300348, 1e-9);
  // At n = 10^6 the floor is the double spacing of ln(10^6!) ~ 1.28e7 (1.9e-9);
  // measured error 5.9e-10. Without compensated summation it is 2.7e-7.
  relative(binomialTail(500000, 1000000, 0.5, 'lower'), 0.5003989421806658, 5e-9);
  relative(binomialTail(500000, 1000000, 0.5, 'upper'), 0.5003989421806658, 5e-9);
  assert.equal(MAX_EXACT_N, 1000000);
  refuses(() => binomialTail(0, MAX_EXACT_N + 1, 0.5), 'too-large-for-exact');
});

test('zeroFailureN: 59 clean trials bound a failure rate below 5%, 58 do not', () => {
  assert.equal(zeroFailureN(0.05), 59);
  const bound = n => clopperPearson(0, n, { sided: 'upper' }).upper;
  near(bound(58), 0.05033933833042015, 1e-12); assert.ok(bound(58) >= 0.05, '58 is not enough');
  near(bound(59), 0.049507609888227, 1e-12); assert.ok(bound(59) < 0.05);
  near(bound(20), 0.139, 5e-4, '0/20 upper');
  // Strictly below: a target equal to the 59-trial bound itself needs 60.
  assert.equal(zeroFailureN(bound(59)), 60);
  assert.equal(zeroFailureN(bound(59) + 1e-12), 59);
  // Hand: n > ln(alpha) / ln(1 - maxRate). ln 0.01 / ln 0.95 = 89.78 -> 90; ln 0.05 / ln 0.99 = 298.07 -> 299.
  assert.equal(zeroFailureN(0.05, { confidence: 0.99 }), 90);
  assert.equal(zeroFailureN(0.01), 299);
  assert.equal(zeroFailureN(0.99), 1);
  for (const bad of [0, 1, -0.1, 1.5, Number.NaN, '0.05']) refuses(() => zeroFailureN(bad), 'invalid-rate');
  // Tiny rates: ln(20) / 1e-12 = 2.9957e12 trials is still exact; 1e-17 needs more than 2^52 and is refused, not looped on.
  relative(zeroFailureN(1e-12), Math.log(20) / 1e-12, 1e-9);
  refuses(() => zeroFailureN(1e-17), 'rate-too-small');
  refuses(() => zeroFailureN(0.05, { confidence: 1 }), 'invalid-confidence');
});

test('mcnemarExact: exact conditional binomial on discordant pairs', () => {
  // 5 discordant all one way: 2 * 0.5^5 = 0.0625; 6: 2 * 0.5^6 = 0.03125.
  const five = mcnemarExact(5, 0);
  assert.deepEqual(Object.keys(five), ['b', 'c', 'discordant', 'pTwoSided', 'pOneSided', 'pOneSidedTowards', 'direction']);
  // The one-sided tail names the direction it tests.
  assert.equal(five.pOneSidedTowards, five.direction);
  near(five.pTwoSided, 0.0625, 1e-12); near(five.pOneSided, 0.03125, 1e-12);
  assert.equal(five.discordant, 5); assert.equal(five.direction, 'baseline');
  const six = mcnemarExact(0, 6);
  near(six.pTwoSided, 0.03125, 1e-12); assert.equal(six.direction, 'candidate');
  assert.ok(six.pTwoSided < 0.05 && five.pTwoSided > 0.05, '6 one-way discordant pairs is the minimum for p < 0.05');
  // Hand: Bin(7, 1/2), P(X <= 1) = 8/128; Bin(10, 1/2), P(X <= 2) = 56/1024.
  near(mcnemarExact(1, 6).pTwoSided, 16 / 128, 1e-12); near(mcnemarExact(1, 6).pOneSided, 8 / 128, 1e-12);
  near(mcnemarExact(6, 1).pTwoSided, 16 / 128, 1e-12);
  near(mcnemarExact(8, 2).pTwoSided, 112 / 1024, 1e-12);
  // Balanced discordance is capped at 1, and no discordance carries no evidence.
  assert.equal(mcnemarExact(3, 3).pTwoSided, 1); assert.equal(mcnemarExact(3, 3).direction, 'none');
  assert.deepEqual(mcnemarExact(0, 0), { b: 0, c: 0, discordant: 0, pTwoSided: 1, pOneSided: 1, pOneSidedTowards: 'none', direction: 'none' });
  refuses(() => mcnemarExact(-1, 2), 'invalid-count');
  refuses(() => mcnemarExact(1, 2.5), 'invalid-count');
});

// Independent exact reference: BigInt hypergeometric weights, no floating point
// until the final division.
const chooseBig = (n, k) => { let r = 1n; for (let i = 1; i <= k; i += 1) r = r * BigInt(n - k + i) / BigInt(i); return r; };
function exactFisher(a, b, c, d) {
  const row1 = a + b, row2 = c + d, col1 = a + c, lo = Math.max(0, col1 - row2), hi = Math.min(row1, col1);
  const weights = []; for (let i = lo; i <= hi; i += 1) weights.push([i, chooseBig(row1, i) * chooseBig(row2, col1 - i)]);
  const total = chooseBig(row1 + row2, col1), observed = weights.find(([i]) => i === a)[1];
  const sum = keep => weights.reduce((s, [i, w]) => (keep(i, w) ? s + w : s), 0n);
  const ratio = num => Number(num) / Number(total);
  return { pTwoSided: ratio(sum((_, w) => w <= observed)), pLess: ratio(sum(i => i <= a)), pGreater: ratio(sum(i => i >= a)) };
}

test('fisherExact: tea tasting and a hand-enumerated asymmetric table', () => {
  // Tea tasting [[3,1],[1,3]]: weights C(4,a)^2 = 1, 16, 36, 16, 1 over 70.
  const tea = fisherExact(3, 1, 1, 3);
  near(tea.pTwoSided, 0.4857, 5e-5); near(tea.pTwoSided, 34 / 70, 1e-12);
  near(tea.pGreater, 0.2429, 5e-5); near(tea.pGreater, 17 / 70, 1e-12);
  near(tea.pLess, 69 / 70, 1e-12); assert.equal(tea.oddsRatio, 9);
  // [[2,3],[6,1]]: rows 5 and 7, first column 8, a in 1..5. Terms C(5,a) * C(7,8-a):
  const terms = { 1: 5 * 1, 2: 10 * 7, 3: 10 * 21, 4: 5 * 35, 5: 1 * 35 }; // 5, 70, 210, 175, 35
  const total = Object.values(terms).reduce((s, t) => s + t, 0);
  assert.equal(total, 495, 'C(12, 8)');
  const table = fisherExact(2, 3, 6, 1);
  near(table.pLess, (terms[1] + terms[2]) / total, 1e-12);
  near(table.pGreater, (terms[2] + terms[3] + terms[4] + terms[5]) / total, 1e-12);
  // Two-sided: tables no more likely than 70/495 are a = 1, 2, 5 -> 110/495, not 2 * min(one-sided) = 150/495.
  near(table.pTwoSided, (terms[1] + terms[2] + terms[5]) / total, 1e-12);
  near(table.oddsRatio, (2 * 1) / (3 * 6), 1e-15);
  // [[1,9],[11,3]]: p two-sided 0.002759 (the dieting example).
  near(fisherExact(1, 9, 11, 3).pTwoSided, 7462 / 2704156, 1e-12);
});

test('fisherExact agrees with exact BigInt enumeration on every small table, ties included', () => {
  // Symmetric margins create exact ties; R's 1e-7 relative tolerance keeps
  // rounding from dropping a tied table from the two-sided sum.
  let checked = 0;
  for (let a = 0; a <= 7; a += 1) for (let b = 0; b <= 7; b += 1) for (let c = 0; c <= 7; c += 1) for (let d = 0; d <= 7; d += 1) {
    const got = fisherExact(a, b, c, d), want = exactFisher(a, b, c, d);
    for (const key of ['pTwoSided', 'pLess', 'pGreater']) near(got[key], want[key], 1e-12, `${key} [[${a},${b}],[${c},${d}]]`);
    checked += 1;
  }
  assert.equal(checked, 4096);
  for (const [a, b, c, d] of [[12, 8, 8, 12], [20, 5, 5, 20], [15, 15, 15, 15], [30, 10, 10, 30]]) {
    const got = fisherExact(a, b, c, d), want = exactFisher(a, b, c, d);
    near(got.pTwoSided, want.pTwoSided, 1e-12, `tie table [[${a},${b}],[${c},${d}]]`);
  }
});

test('fisherExact edges and refusals', () => {
  assert.deepEqual(fisherExact(0, 0, 0, 0), { pTwoSided: 1, pLess: 1, pGreater: 1, oddsRatio: null });
  const perfect = fisherExact(5, 0, 0, 5);
  near(perfect.pTwoSided, 2 / 252, 1e-12); assert.equal(perfect.oddsRatio, Infinity);
  assert.equal(fisherExact(0, 5, 5, 0).oddsRatio, 0);
  refuses(() => fisherExact(1, -1, 2, 3), 'invalid-count');
  refuses(() => fisherExact(1, 2, 3.5, 3), 'invalid-count');
  refuses(() => fisherExact(MAX_EXACT_N, 1, 0, 0), 'too-large-for-exact');
  // A table inside MAX_EXACT_N with ~3e5 possible tables computes instead of throwing a RangeError.
  const large = fisherExact(150000, 150000, 150000, 150000);
  near(large.pTwoSided, 1, 1e-9, 'the observed table is the mode'); assert.equal(large.oddsRatio, 1);
  near(large.pLess, large.pGreater, 1e-12, 'symmetric margins');
});

const obs = (cluster, ...outcomes) => outcomes.map(success => ({ cluster, success }));

test('clusterSummary: one cluster has no between-cluster spread, so the cluster SE is null, not 0', () => {
  const once = obs('task-a', true, false, true, true, false);
  const tenTimes = Array.from({ length: 10 }, () => once.map(row => ({ ...row }))).flat();
  const before = clusterSummary(once), after = clusterSummary(tenTimes);
  assert.equal(before.observations, 5); assert.equal(after.observations, 50);
  assert.equal(after.point, before.point);
  near(before.naiveSE / after.naiveSE, Math.sqrt(10), 1e-12, 'naive SE ratio');
  near(before.naiveSE, Math.sqrt(0.6 * 0.4 / 5), 1e-15);
  assert.equal(before.clusterSE, null); assert.equal(before.singleCluster, true); assert.equal(before.designEffect, null);
});

test('clusterSummary: the cluster-robust SE of the pooled rate (eq. 4), for equal and unequal cluster sizes', () => {
  // Equal sizes: clusters 1/1, 0/1 ... as three clusters of 2: means 1, 0, 0.5, pooled 0.5.
  const equal = [...obs('a', true, true), ...obs('b', false, false), ...obs('c', true, false)];
  const s = clusterSummary(equal);
  assert.deepEqual(Object.keys(s), ['observations', 'clusters', 'point', 'naiveSE', 'clusterSE', 'designEffect', 'singleCluster']);
  assert.equal(s.point, 0.5);
  near(s.naiveSE, Math.sqrt(0.25 / 6), 1e-15);
  // Deviation sums 1, -1, 0: sqrt(3/2 * 2) / 6 = sqrt(3) / 6, which is the SD of the cluster means (0.5) over sqrt(3).
  near(s.clusterSE, Math.sqrt(3) / 6, 1e-15); near(s.clusterSE, 0.5 / Math.sqrt(3), 1e-15);
  near(s.designEffect, (3 / 36) / (0.25 / 6), 1e-12, 'design effect 2');
  // Unequal sizes: 100/100 and 0/1. Eq. 4 with C/(C-1): sqrt(2 * 2 * (100/101)^2) / 101.
  const unequal = clusterSummary([...Array.from({ length: 100 }, () => ({ cluster: 'big', success: true })), { cluster: 'small', success: false }]);
  near(unequal.point, 100 / 101, 1e-15, 'the pooled rate, not the mean of the two cluster means (0.5)');
  near(unequal.clusterSE, 0.019605920988138428, 1e-12, 'reference computed outside the module');
  // Every observation a success: the naive SE is 0 and the design effect is null, never NaN.
  const perfect = clusterSummary([...obs('a', true, true), ...obs('b', true)]);
  assert.deepEqual([perfect.naiveSE, perfect.clusterSE, perfect.designEffect], [0, 0, null]);
  near(unequal.designEffect, 3.9603960396039612, 1e-9);
  // Repeating every cluster's observations ten times: naive SE shrinks by sqrt(10), the cluster SE does not move.
  const tenfold = clusterSummary(Array.from({ length: 10 }, () => equal.map(row => ({ ...row }))).flat());
  near(s.naiveSE / tenfold.naiveSE, Math.sqrt(10), 1e-12);
  near(tenfold.clusterSE, s.clusterSE, 1e-15);
  near(tenfold.designEffect, 10 * s.designEffect, 1e-9);
  assert.deepEqual(clusterSummary([]), { observations: 0, clusters: 0, point: null, naiveSE: null, clusterSE: null, designEffect: null, singleCluster: false });
  for (const bad of [null, 'x', [{ cluster: 'a', success: 1 }], [{ cluster: '', success: true }], [{ success: true }], [null]]) {
    refuses(() => clusterSummary(bad), 'invalid-observation');
  }
});

test('perCluster aggregates reruns to one outcome per cluster', () => {
  const data = [...obs('a', true, true, true), ...obs('b', true, false, true), ...obs('c', false, false, true), ...obs('d', false, false), ...obs('e', true, false)];
  assert.deepEqual(perCluster(data, 'all'), { successes: 1, n: 5 });
  assert.deepEqual(perCluster(data, 'any'), { successes: 4, n: 5 });
  // Strict majority: 'e' at 1 of 2 is not a majority.
  assert.deepEqual(perCluster(data, 'majority'), { successes: 2, n: 5 });
  assert.deepEqual(perCluster([], 'all'), { successes: 0, n: 0 });
  refuses(() => perCluster(data, 'mean'), 'invalid-rule');
  refuses(() => perCluster([{ cluster: 'a' }], 'all'), 'invalid-observation');
});

test('independentRate refuses pooled reruns; the per-cluster interval is the honest one', () => {
  // 10 planted defects x 5 reruns, all caught. Pooled as 50 trials Wilson says 0.929.
  const reruns = Array.from({ length: 10 }, (_, i) => obs(`defect-${i}`, true, true, true, true, true)).flat();
  assert.throws(() => independentRate(reruns), error => error instanceof StatsError && error.code === 'pooled-reruns' &&
    /aggregate per cluster first/i.test(error.message) && /perCluster/.test(error.message) &&
    // It suggests only the rules a comparison accepts.
    error.message.includes("'all' | 'majority'") && !error.message.includes("'any'"));
  assert.throws(() => independentRate(reruns, { method: 'clopper-pearson' }), error => error.code === 'pooled-reruns');
  near(wilson(50, 50).lower, 0.929, 5e-4, 'the anti-conservative pooled figure');
  const perDefect = perCluster(reruns, 'all');
  assert.deepEqual(perDefect, { successes: 10, n: 10 });
  near(wilson(perDefect.successes, perDefect.n).lower, 0.7225, 5e-4);
  near(clopperPearson(perDefect.successes, perDefect.n).lower, 0.692, 5e-4);
  // One observation per cluster is accepted and matches the direct interval.
  const single = [...obs('a', true), ...obs('b', false), ...obs('c', true)];
  assert.deepEqual(independentRate(single), wilson(2, 3));
  assert.deepEqual(independentRate(single, { method: 'clopper-pearson', sided: 'lower' }), clopperPearson(2, 3, { sided: 'lower' }));
  refuses(() => independentRate(single, { method: 'wald' }), 'invalid-method');
  refuses(() => independentRate(single, { sided: 'upper' }), 'invalid-sided');
  // Two observations of one cluster are already a rerun.
  refuses(() => independentRate([...obs('a', true, true), ...obs('b', false)]), 'pooled-reruns');
  // The confidence is passed through, for both methods.
  assert.deepEqual(independentRate(single, { confidence: 0.9 }), wilson(2, 3, { confidence: 0.9 }));
  assert.notDeepEqual(independentRate(single, { confidence: 0.9 }), wilson(2, 3));
  assert.deepEqual(independentRate(single, { method: 'clopper-pearson', confidence: 0.9 }), clopperPearson(2, 3, { confidence: 0.9 }));
  assert.notDeepEqual(independentRate(single, { method: 'clopper-pearson', confidence: 0.9 }), clopperPearson(2, 3));
  refuses(() => independentRate(single, { methd: 'wilson' }), 'unknown-option');
});

test('Wilson endpoints are pinned only at 0 and n, and one-sided Clopper-Pearson reports the bound asked for', () => {
  // References computed outside the module (closed-form Wilson; exact binomial bisection).
  const one = wilson(1, 10), nine = wilson(9, 10);
  near(one.lower, 0.017876213095072868, 1e-12); near(one.upper, 0.4041500267952385, 1e-12);
  near(nine.lower, 0.5958499732047615, 1e-12); near(nine.upper, 0.9821237869049271, 1e-12);
  const lower = clopperPearson(3, 10, { sided: 'lower' }), upper = clopperPearson(3, 10, { sided: 'upper' });
  near(lower.lower, 0.08726443391415031, 1e-10); assert.equal(lower.upper, 1);
  assert.equal(upper.lower, 0); near(upper.upper, 0.6066242161054134, 1e-10);
  // A reference value: 4/5 one-sided 95% lower bound is 0.34259.
  near(clopperPearson(4, 5, { sided: 'lower' }).lower, 0.34259168199886125, 1e-10);
});

test('options are objects with known keys only; a misspelled or null option is a StatsError', () => {
  refuses(() => wilson(1, 2, null), 'invalid-options');
  refuses(() => wilson(1, 2, { confidance: 0.9 }), 'unknown-option');
  refuses(() => clopperPearson(1, 2, { side: 'lower' }), 'unknown-option');
  refuses(() => zeroFailureN(0.05, { conf: 0.9 }), 'unknown-option');
  refuses(() => mde(null), 'invalid-options');
  refuses(() => mde({ n: 3, alfa: 0.05 }), 'unknown-option');
  refuses(() => pairOverTrials(null), 'invalid-options');
  refuses(() => compareRepeated(null), 'invalid-options');
  // mde can never exceed a whole rate.
  assert.equal(mde({ n: 1 }), 1);
});

test('passHatK and passAtK: unbiased per-task estimators with hand-computed fixtures', () => {
  const task = [{ cluster: 't1', successes: 3, n: 5 }];
  // C(3,2) / C(5,2) = 3/10, not (3/5)^2 = 9/25.
  near(passHatK(task, 2), 3 / 10, 1e-15);
  // 1 - C(2,2) / C(5,2) = 9/10.
  near(passAtK(task, 2), 9 / 10, 1e-15);
  // C(4,3) / C(6,3) = 4/20; 1 - C(2,3) / C(6,3) = 1.
  near(passHatK([{ cluster: 'x', successes: 4, n: 6 }], 3), 1 / 5, 1e-15);
  assert.equal(passAtK([{ cluster: 'x', successes: 4, n: 6 }], 3), 1);
  const suite = [{ cluster: 'a', successes: 3, n: 5 }, { cluster: 'b', successes: 5, n: 5 }, { cluster: 'c', successes: 0, n: 5 }];
  near(passHatK(suite, 2), (3 / 10 + 1 + 0) / 3, 1e-15);
  near(passAtK(suite, 2), (9 / 10 + 1 + 0) / 3, 1e-15);
  near(passHatK(suite, 1), (3 / 5 + 1 + 0) / 3, 1e-15, 'k = 1 is the mean success rate');
  near(passAtK(suite, 1), (3 / 5 + 1 + 0) / 3, 1e-15);
  near(passHatK(suite, 5), 1 / 3, 1e-15, 'k = n counts only perfect tasks');
  assert.equal(passHatK([{ cluster: 'a', successes: 1, n: 5 }], 2), 0);
  // Large counts stay finite: each ratio is at most 1.
  const big = passHatK([{ cluster: 'big', successes: 900, n: 1000 }], 500);
  assert.ok(Number.isFinite(big) && big > 0 && big < 0.9 ** 500);
  refuses(() => passHatK(suite, 6), 'k-exceeds-trials');
  refuses(() => passAtK([{ cluster: 'a', successes: 1, n: 2 }, { cluster: 'b', successes: 3, n: 8 }], 3), 'k-exceeds-trials');
  for (const k of [0, -1, 1.5, '2']) refuses(() => passHatK(suite, k), 'invalid-k');
  refuses(() => passHatK([], 1), 'no-trials');
  refuses(() => passHatK([{ cluster: 'a', successes: 1, n: 3 }, { cluster: 'a', successes: 2, n: 3 }], 1), 'duplicate-cluster');
  refuses(() => passHatK([{ cluster: 'a', successes: 4, n: 3 }], 1), 'count-exceeds-n');
  refuses(() => passHatK([{ successes: 1, n: 3 }], 1), 'invalid-trial');
});

test('mde: (z_{1-alpha/2} + z_power) times the standard error of a difference', () => {
  const zSum = Z975 + Z80;
  near(mde({ n: 4 }), zSum * Math.sqrt(2 * 0.25 / 4), 1e-9, 'n = 4, p = 0.5');
  // n = 3 gives 1.1437 by the formula, more than any rate difference: reported as 1.
  assert.equal(zSum * Math.sqrt(2 * 0.25 / 3) > 1, true); assert.equal(mde({ n: 3 }), 1);
  near(mde({ n: 100, p: 0.2 }), zSum * Math.sqrt(2 * 0.2 * 0.8 / 100), 1e-9);
  near(mde({ n: 25, paired: true, sdDiff: 0.5 }), zSum * 0.5 / 5, 1e-9, 'paired');
  near(mde({ n: 50, alpha: 0.01, power: 0.9 }), 3.857380869093501 * Math.sqrt(0.5 / 50), 1e-9, 'alpha 0.01, power 0.9');
  assert.equal(mde({ n: 10, p: 0 }), 0);
  for (const n of [0, -1, 2.5, undefined]) refuses(() => mde({ n }), 'invalid-count');
  refuses(() => mde({ n: 3, p: 1.5 }), 'invalid-rate');
  refuses(() => mde({ n: 3, alpha: 0 }), 'invalid-alpha');
  refuses(() => mde({ n: 3, power: 1 }), 'invalid-power');
  refuses(() => mde({ n: 3, paired: 'yes' }), 'invalid-paired');
  refuses(() => mde({ n: 3, paired: true }), 'invalid-sd-diff');
  refuses(() => mde({ n: 3, paired: true, sdDiff: -1 }), 'invalid-sd-diff');
});

// Observations for compareRepeated: one per cluster unless repeated on purpose.
const arm = (prefix, outcomes) => outcomes.map((success, i) => ({ cluster: `${prefix}${i}`, success }));
const repeat = (list, times) => Array.from({ length: times }, () => list.map(row => ({ ...row }))).flat();
const WORKING = arm('ctl-', Array(10).fill(true));
test('compareRepeated: a 3-scenario suite moving from 1/3 to 0/3 failing is unresolved', () => {
  const base = arm('s', [true, true, false]), cand = arm('s', [true, true, true]);
  const result = compareRepeated({ baseline: base, candidate: cand, design: 'independent', control: WORKING });
  assert.equal(result.verdict, 'unresolved'); assert.equal(result.test, 'fisher-exact'); assert.equal(result.pTwoSided, 1);
  near(result.difference, 1 / 3, 1e-15);
  assert.equal(result.mde, 1); assert.ok(result.mde > result.difference, 'the MDE shows why three scenarios cannot resolve this');
  const paired = compareRepeated({ baseline: base, candidate: cand, design: 'paired', control: WORKING });
  assert.equal(paired.verdict, 'unresolved'); assert.equal(paired.test, 'mcnemar-exact'); assert.equal(paired.pTwoSided, 1);
});

test('pooled reruns never reach "fixed": 3 tasks x 10 reruns from 0/30 to 30/30 is refused, or unresolved per task', () => {
  const base = repeat(arm('task-', [false, false, false]), 10), cand = repeat(arm('task-', [true, true, true]), 10);
  for (const design of ['independent', 'paired']) refuses(() => compareRepeated({ baseline: base, candidate: cand, design, control: WORKING }), 'pooled-reruns');
  const independent = compareRepeated({ baseline: base, candidate: cand, design: 'independent', rule: 'all', control: WORKING });
  assert.deepEqual([independent.verdict, independent.clusters], ['unresolved', { baseline: { successes: 0, n: 3 }, candidate: { successes: 3, n: 3 } }]);
  near(independent.pTwoSided, 0.1, 1e-12);
  const paired = compareRepeated({ baseline: base, candidate: cand, design: 'paired', rule: 'all', control: WORKING });
  assert.equal(paired.verdict, 'unresolved'); near(paired.pTwoSided, 0.25, 1e-12);
  // The rule decides each cluster: one failed rerun of three fails 'all' and passes 'majority' (two of three).
  const mixed = [...obs('m0', true, true, false), ...obs('m1', true, true, true), ...obs('m2', false, false, true), ...obs('m3', true, false, false)];
  const counts = rule => compareRepeated({ baseline: mixed, candidate: mixed, design: 'paired', rule, control: WORKING }).clusters.candidate.successes;
  assert.deepEqual([counts('all'), counts('majority')], [1, 2]);
  // 'any' is not a comparison rule (perCluster still offers it for description).
  refuses(() => counts('any'), 'invalid-rule');
  // Unequal independent arms: the MDE is for the smaller arm's cluster count.
  near(compareRepeated({ baseline: arm('b', [true, false, false, false]), candidate: arm('c', Array(10).fill(true)), design: 'independent', control: WORKING }).mde, mde({ n: 4 }), 1e-15);
  // McNemar's exact sum is size-guarded like every exact method.
  refuses(() => mcnemarExact(MAX_EXACT_N, 1), 'too-large-for-exact');
});

test('the control and the design are required, and a misspelled option is refused, never ignored', () => {
  const base = arm('t', Array(10).fill(false)), cand = arm('t', Array(10).fill(true));
  refuses(() => compareRepeated({ baseline: base, candidate: cand, design: 'independent' }), 'control-required');
  refuses(() => compareRepeated({ baseline: base, candidate: cand, design: 'independent', controls: arm('c', [false]) }), 'unknown-option');
  refuses(() => compareRepeated({ baseline: base, candidate: cand, control: WORKING }), 'invalid-design');
  refuses(() => compareRepeated({ baseline: base, candidate: cand, design: 'independent', control: null }), 'control-required');
  refuses(() => compareRepeated({ baseline: base, candidate: cand, design: 'independent', control: WORKING, noControlReason: 'x' }), 'invalid-options');
  // An always-refuse candidate (its allowed-use control fails every time) is blocked by its controls.
  assert.equal(compareRepeated({ baseline: base, candidate: cand, design: 'independent', control: arm('c', Array(10).fill(false)) }).verdict, 'blocked-by-controls');
  // A declared waiver keeps the verdict and says so.
  const waived = compareRepeated({ baseline: base, candidate: cand, design: 'independent', control: null, noControlReason: 'This capability has no allowed use to test.' });
  assert.deepEqual([waived.verdict, waived.control], ['fixed', { waived: 'This capability has no allowed use to test.' }]);
});

test('compareRepeated: fixed and regressed need the exact one-sided test below alpha / 2 in the right direction', () => {
  const zero = arm('t', Array(10).fill(false)), ten = arm('t', Array(10).fill(true));
  // Fisher [[10,0],[0,10]]: one-sided 1 / C(20,10), two-sided 2 / C(20,10).
  const fixed = compareRepeated({ baseline: zero, candidate: ten, design: 'independent', control: WORKING });
  assert.equal(fixed.verdict, 'fixed'); near(fixed.pTwoSided, 2 / 184756, 1e-15); near(fixed.pOneSided, 1 / 184756, 1e-15);
  const regressed = compareRepeated({ baseline: ten, candidate: zero, design: 'independent', control: WORKING });
  assert.equal(regressed.verdict, 'regressed'); near(regressed.pOneSided, 1 / 184756, 1e-15);
  // Shared seeds: 6 one-way discordant clusters reject (two-sided 0.03125), 5 do not (0.0625)...
  const pairedArms = (b, c, both = 0, neither = 0) => {
    const ids = Array.from({ length: b + c + both + neither }, (_, i) => `seed-${i}`);
    const base = ids.map((id, i) => ({ cluster: id, success: i < b || (i >= b + c && i < b + c + both) }));
    const cand = ids.map((id, i) => ({ cluster: id, success: (i >= b && i < b + c) || (i >= b + c && i < b + c + both) }));
    return { baseline: base, candidate: cand };
  };
  const six = compareRepeated({ ...pairedArms(0, 6, 4), design: 'paired', control: WORKING });
  assert.equal(six.verdict, 'fixed'); assert.equal(six.test, 'mcnemar-exact'); near(six.pTwoSided, 0.03125, 1e-12);
  assert.equal(compareRepeated({ ...pairedArms(6, 0, 4), design: 'paired', control: WORKING }).verdict, 'regressed');
  const five = compareRepeated({ ...pairedArms(0, 5, 5), design: 'paired', control: WORKING });
  assert.equal(five.verdict, 'unresolved'); near(five.pTwoSided, 0.0625, 1e-12);
  // The same clusters declared independent go to Fisher (one-sided 252/15504 = 0.0163 < 0.025): the caller must say which design it is.
  const asIndependent = compareRepeated({ ...pairedArms(0, 5, 5), design: 'independent', control: WORKING });
  assert.equal(asIndependent.test, 'fisher-exact'); near(asIndependent.pTwoSided, 504 / 15504, 1e-12); assert.equal(asIndependent.verdict, 'fixed');
  // A stricter alpha leaves the same evidence unresolved.
  assert.equal(compareRepeated({ ...pairedArms(0, 5, 5), design: 'independent', alpha: 0.01, control: WORKING }).verdict, 'unresolved');
  assert.ok(VERDICTS.includes(fixed.verdict) && VERDICTS.includes(five.verdict));
});

test('"fixed" is the interval rule: Fisher two-sided p < alpha is not enough when the one-sided test misses alpha / 2', () => {
  // The edge case: 0/24 to 3/15. Two-sided Fisher 0.0498 < 0.05, but one-sided P = C(15,3)/C(39,3) = 455/9139 = 0.0498 >= 0.025.
  const r = compareRepeated({ baseline: arm('b', Array(24).fill(false)), candidate: arm('c', [...Array(3).fill(true), ...Array(12).fill(false)]), design: 'independent', control: WORKING });
  near(r.pTwoSided, 0.049786628733997154, 1e-12); near(r.pOneSided, 455 / 9139, 1e-12);
  assert.equal(r.verdict, 'unresolved');
});

test('a p exactly at the threshold in exact arithmetic never reads below it because of rounding', () => {
  // 0/1 to 19/19: exact one-sided p = 1/20. At alpha 0.1 (threshold alpha/2 = 0.05) it is not below.
  const r = compareRepeated({ baseline: arm('b', [false]), candidate: arm('c', Array(19).fill(true)), design: 'independent', alpha: 0.1, control: WORKING });
  near(r.pOneSided, 1 / 20, 1e-15); assert.equal(r.verdict, 'unresolved');
  // Alpha is capped.
  refuses(() => compareRepeated({ baseline: arm('b', [false]), candidate: arm('c', [true]), design: 'independent', alpha: 0.5, control: WORKING }), 'invalid-alpha');
});

test('pairOverTrials: held needs every trial held and a control shown to work; degenerate builds never read held', () => {
  // A working pair over k = 5: the control's one-sided 95% lower bound for 5/5 is 0.05^(1/5) = 0.5493.
  const good = pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 5, n: 5 } });
  assert.equal(good.verdict, 'held'); near(good.controlLower, 0.05 ** (1 / 5), 1e-9);
  // ...and the violation rate the 5 clean trials still leave open: 1 - 0.05^(1/5) = 0.4507.
  near(good.violationUpper, 1 - 0.05 ** (1 / 5), 1e-9);
  // Always-refuse (do-nothing): every forbidden trial held, every control failed.
  assert.equal(pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 0, n: 5 } }).verdict, 'blocked-by-controls');
  // Dump-everything: the control works, the forbidden check is violated.
  assert.equal(pairOverTrials({ forbidden: { successes: 0, n: 5 }, control: { successes: 5, n: 5 } }).verdict, 'violated');
  // One violated trial in five is a violation, whatever the control did (pass^k = 0).
  assert.equal(pairOverTrials({ forbidden: { successes: 4, n: 5 }, control: { successes: 5, n: 5 } }).verdict, 'violated');
  assert.equal(pairOverTrials({ forbidden: { successes: 4, n: 5 }, control: { successes: 0, n: 5 } }).verdict, 'violated');
  // A flaky control (4/5) lowers its bound below the floor: 0.34259 < 0.5, so nothing is held.
  const flaky = pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 4, n: 5 } });
  assert.equal(flaky.verdict, 'blocked-by-controls'); near(flaky.controlLower, 0.34259168199886125, 1e-10);
  // The default floor is 0.5: a 4/4 control (0.05^(1/4) = 0.4729) does not reach it; a floor of 0.45 does.
  const fourOfFour = pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 4, n: 4 } });
  assert.deepEqual([fourOfFour.verdict, fourOfFour.controlFloor], ['blocked-by-controls', 0.5]); near(fourOfFour.controlLower, 0.4728708045015879, 1e-12);
  assert.equal(pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 4, n: 4 }, controlFloor: 0.45 }).verdict, 'held');
  // Confidence moves both bounds: at 90%, 5/5 gives 0.1^(1/5) = 0.6310 and a violation bound of 0.3690.
  const ninety = pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 5, n: 5 }, confidence: 0.9, controlFloor: 0.6 });
  near(ninety.controlLower, 0.6309573444801932, 1e-12); near(ninety.violationUpper, 0.36904265551980675, 1e-12); assert.equal(ninety.verdict, 'held');
  assert.equal(pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 5, n: 5 }, controlFloor: 0.6 }).verdict, 'blocked-by-controls', 'at 95% the same control misses 0.6');
  // Too few trials to bound the violation rate read insufficient, never held: 1/1 leaves 0.95 open, 3/3 leaves 0.63.
  for (const n of [1, 3]) assert.equal(pairOverTrials({ forbidden: { successes: n, n }, control: { successes: 10, n: 10 } }).verdict, 'insufficient', `${n}/${n}`);
  // At the lowest confidence a decision takes (0.8), 3/3 leaves 1 - 0.2^(1/3) = 0.415 open and holds.
  const lowest = pairOverTrials({ forbidden: { successes: 3, n: 3 }, control: { successes: 10, n: 10 }, confidence: 0.8 });
  assert.equal(lowest.verdict, 'held'); near(lowest.violationUpper, 1 - 0.2 ** (1 / 3), 1e-12);
  // The floor is reached, not exceeded: a control bound equal to the floor holds.
  // (The floor is the very bound returned, so no rounding step can separate them.)
  const atFloor = pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 5, n: 5 }, controlFloor: good.controlLower });
  assert.equal(atFloor.verdict, 'held');
  assert.ok(PAIR_VERDICTS.includes(good.verdict));
  refuses(() => pairOverTrials({ forbidden: { successes: 5, n: 5 } }), 'invalid-arm');
  refuses(() => pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 5, n: 5 }, controlFloor: 1 }), 'invalid-floor');
});

test('compareRepeated with a control: an always-refuse candidate is blocked by its controls, never fixed', () => {
  const arms = { baseline: arm('t', Array(10).fill(false)), candidate: arm('t', Array(10).fill(true)), design: 'independent' };
  const refusing = compareRepeated({ ...arms, control: arm('c', Array(10).fill(false)) });
  assert.equal(refusing.verdict, 'blocked-by-controls'); assert.deepEqual([refusing.control.lower, refusing.control.floor], [0, 0.5]);
  const working = compareRepeated({ ...arms, control: WORKING });
  assert.equal(working.verdict, 'fixed'); near(working.control.lower, 0.05 ** (1 / 10), 1e-9);
  // The control bound is taken at 1 - alpha: at alpha 0.1 a 5/5 control reaches a 0.6 floor (0.1^(1/5) = 0.631); at 0.05 it does not (0.549).
  const five = arm('c', Array(5).fill(true));
  const at10 = compareRepeated({ ...arms, control: five, controlFloor: 0.6, alpha: 0.1 });
  assert.equal(at10.verdict, 'fixed'); near(at10.control.lower, 0.6309573444801932, 1e-12); assert.equal(at10.control.confidence, 0.9);
  assert.equal(compareRepeated({ ...arms, control: five, controlFloor: 0.6 }).verdict, 'blocked-by-controls');
  // The floor is applied as given: a control just under it is blocked, just over it is not.
  const flaky = arm('c', [true, true, true, true, false]);
  assert.equal(compareRepeated({ ...arms, control: flaky }).verdict, 'blocked-by-controls', '4/5 reaches 0.34259 at 95%');
  assert.equal(compareRepeated({ ...arms, control: flaky, controlFloor: 0.34 }).verdict, 'fixed');
  // The control gate only withholds a fix: a regression or an unresolved result is reported as it is.
  assert.equal(compareRepeated({ baseline: arms.candidate, candidate: arms.baseline, design: 'independent', control: arm('c', Array(10).fill(false)) }).verdict, 'regressed');
  assert.equal(compareRepeated({ baseline: arm('s', [true, false, false]), candidate: arm('s', [true, true, true]), design: 'independent', control: arm('c', [false]) }).verdict, 'unresolved');
  // A control bound equal to the floor reaches it (the floor is the very bound returned).
  assert.equal(compareRepeated({ ...arms, control: five, controlFloor: compareRepeated({ ...arms, control: five }).control.lower }).verdict, 'fixed');
  // The MDE is taken at the comparison's alpha.
  near(compareRepeated({ ...arms, control: WORKING, alpha: 0.1 }).mde, mde({ n: 10, alpha: 0.1 }), 1e-15);
  // Control reruns are aggregated with 'all', whatever the arms' rule: a control cluster works
  // only when every one of its reruns did. Two working clusters of two reruns reach 0.05^(1/2) = 0.224.
  const twoByTwo = compareRepeated({ ...arms, control: repeat(arm('c', [true, true]), 2) });
  assert.deepEqual([twoByTwo.verdict, twoByTwo.control.successes, twoByTwo.control.n, twoByTwo.control.rule], ['blocked-by-controls', 2, 2, 'all']);
  assert.equal(compareRepeated({ ...arms, control: repeat(WORKING, 3) }).verdict, 'fixed');
});

test('unequal rerun counts are refused: a worse candidate read as fixed, and the 10-vs-1 case', () => {
  // A worse candidate: 20 tasks; the baseline reruns each 10 times at 9 of 10, the candidate runs each once, 14 of 20 succeeding (worse per trial).
  const ids = Array.from({ length: 20 }, (_, i) => `task-${i}`);
  const base = ids.flatMap(id => [...obs(id, ...Array(9).fill(true)), ...obs(id, false)]);
  const cand = ids.map((id, i) => ({ cluster: id, success: i < 14 }));
  for (const design of ['paired', 'independent']) for (const rule of ['all', 'majority']) refuses(() => compareRepeated({ baseline: base, candidate: cand, design, rule, control: WORKING }), 'unequal-reruns');
  // The same set of counts ({1, 10}) in both arms, but not cluster by cluster. The same case with task 19 swapped:
  // the baseline reruns 19 tasks 10 times and runs task 19 once; the candidate runs 19 tasks once and reruns task 19
  // 10 times. Comparing the set of counts per arm would call this worse candidate fixed. The rule is stronger: every
  // cluster has one rerun count, the same in both arms (the next test pins it against its neighbours).
  const swappedBase = [...ids.slice(0, 19).flatMap(id => [...obs(id, ...Array(9).fill(true)), ...obs(id, false)]), ...obs('task-19', false)];
  const swappedCand = [...ids.slice(0, 19).map((id, i) => ({ cluster: id, success: i < 14 })), ...obs('task-19', ...Array(9).fill(true), false)];
  for (const design of ['paired', 'independent']) for (const rule of ['all', 'majority']) refuses(() => compareRepeated({ baseline: swappedBase, candidate: swappedCand, design, rule, control: WORKING }), 'unequal-reruns');
  // Unequal counts within one arm are refused the same way.
  refuses(() => compareRepeated({ baseline: [...obs('a', true, true), ...obs('b', true, true, true)], candidate: [...obs('a', true, true), ...obs('b', true, true)], design: 'paired', rule: 'all', control: WORKING }), 'unequal-reruns');
  // Equal counts are accepted.
  assert.equal(compareRepeated({ baseline: repeat(arm('t', Array(10).fill(false)), 3), candidate: repeat(arm('t', Array(10).fill(true)), 3), design: 'paired', rule: 'all', control: WORKING }).verdict, 'fixed');
});


test('every cluster in both arms has the same count: disjoint ids, a balanced swap, and per-pair counts that vary', () => {
  const runs = (id, s, k) => Array.from({ length: k }, (_, i) => ({ cluster: id, success: i < s }));
  const ids = (p, n) => Array.from({ length: n }, (_, i) => `${p}${i}`);
  // A: the independent design's natural input, disjoint ids. The worse candidate above, renamed: 20 x 10 reruns at 9/10 against 20 single
  // runs with 14 successes (worse per trial). Checking only clusters seen in both arms would call this fixed.
  const aBase = ids('b', 20).flatMap(id => runs(id, 9, 10)), aCand = ids('c', 20).map((id, i) => ({ cluster: id, success: i < 14 }));
  for (const rule of ['all', 'majority']) refuses(() => compareRepeated({ baseline: aBase, candidate: aCand, design: 'independent', rule, control: WORKING }), 'unequal-reruns');
  // B: the same multiset of counts (20 x 10 and 20 x 1) in both arms, swapped cluster by cluster. Comparing count
  // multisets or proportions would call this candidate (180/220 -> 16/220 per trial) fixed.
  const X = ids('x', 20), Y = ids('y', 20);
  const bBase = [...X.flatMap(id => runs(id, 9, 10)), ...Y.flatMap(id => runs(id, 0, 1))];
  const bCand = [...X.map((id, i) => ({ cluster: id, success: i < 16 })), ...Y.flatMap(id => runs(id, 0, 10))];
  for (const design of ['paired', 'independent']) refuses(() => compareRepeated({ baseline: bBase, candidate: bCand, design, rule: 'all', control: WORKING }), 'unequal-reruns');
  // C: paired, each pair equal but counts differ across clusters (2 and 4): the rule asks for one count everywhere.
  const T = ids('t', 12);
  refuses(() => compareRepeated({ baseline: T.flatMap((id, i) => runs(id, 0, i < 6 ? 2 : 4)), candidate: T.flatMap((id, i) => runs(id, i < 6 ? 2 : 4, i < 6 ? 2 : 4)), design: 'paired', rule: 'all', control: WORKING }), 'unequal-reruns');
});

test('one count everywhere also when the candidate is rerun more than the baseline, and when the control is waived', () => {
  const runs = (id, s, k) => Array.from({ length: k }, (_, i) => ({ cluster: id, success: i < s }));
  const T = Array.from({ length: 20 }, (_, i) => `task-${i}`);
  const once = s => T.map((id, i) => ({ cluster: id, success: i < s }));
  // The direction every earlier case leaves out: the baseline runs each task once and the candidate reruns it 10
  // times. Under 'majority' a worse candidate (13/20 -> 120/200 per trial) would read fixed; under 'all' a better
  // one (14/20 -> 180/200) would read regressed. Refusing only when the baseline has more reruns misses both.
  for (const design of ['paired', 'independent']) {
    refuses(() => compareRepeated({ baseline: once(13), candidate: T.flatMap(id => runs(id, 6, 10)), design, rule: 'majority', control: WORKING }), 'unequal-reruns');
    refuses(() => compareRepeated({ baseline: once(14), candidate: T.flatMap(id => runs(id, 9, 10)), design, rule: 'all', control: WORKING }), 'unequal-reruns');
  }
  // A waived control does not skip the check: the worse candidate with control: null and a readable reason.
  const n1Base = T.flatMap(id => runs(id, 9, 10));
  for (const design of ['paired', 'independent']) for (const rule of ['all', 'majority']) {
    refuses(() => compareRepeated({ baseline: n1Base, candidate: once(14), design, rule, control: null, noControlReason: 'No allowed use exists.' }), 'unequal-reruns');
  }
});

test('the control gate holds in the paired design too, and a caller\'s stricter maxViolationUpper is applied', () => {
  // Every control case above uses the independent design. Shared seeds, 0/10 -> 10/10 (McNemar one-sided
  // 2^-10): with an always-refuse control (0/10) or a flaky one (4/5, lower bound 0.34259) it is blocked, never fixed.
  const ids = Array.from({ length: 10 }, (_, i) => `seed-${i}`);
  const paired = { baseline: ids.map(id => ({ cluster: id, success: false })), candidate: ids.map(id => ({ cluster: id, success: true })), design: 'paired' };
  assert.equal(compareRepeated({ ...paired, control: WORKING }).verdict, 'fixed');
  for (const control of [arm('c', Array(10).fill(false)), arm('c', [true, true, true, true, false])]) {
    assert.equal(compareRepeated({ ...paired, control }).verdict, 'blocked-by-controls');
  }
  // The same with 3 reruns per seed under 'all', and control clusters passing 2 of 3 (0 of 10 work under 'all').
  const twoOfThree = Array.from({ length: 10 }, (_, i) => obs(`c${i}`, true, true, false)).flat();
  assert.equal(compareRepeated({ baseline: repeat(paired.baseline, 3), candidate: repeat(paired.candidate, 3), design: 'paired', rule: 'all', control: twoOfThree }).verdict, 'blocked-by-controls');
  // maxViolationUpper is the caller's bound, not only a cap. 5/5 clean trials leave 1 - 0.05^(1/5) = 0.4507
  // open: held at the default 0.5, insufficient at 0.45 or 0.3.
  const five = { forbidden: { successes: 5, n: 5 }, control: { successes: 20, n: 20 } };
  assert.equal(pairOverTrials(five).verdict, 'held');
  for (const maxViolationUpper of [0.45, 0.3]) assert.equal(pairOverTrials({ ...five, maxViolationUpper }).verdict, 'insufficient', String(maxViolationUpper));
});

test('one table over compareRepeated and pairOverTrials; every expected verdict is written by hand from the documented rules', () => {
  // Hand values (closed forms; the documented rule names the threshold):
  //   paired 0/10 -> 10/10: McNemar b = 0, c = 10, one-sided p = 2^-10 = 0.000977 (below alpha/2 = 0.025, above 0.0005);
  //   paired 0/10 -> 4/10: c = 4, b = 0, p = 2^-4 = 0.0625 (above 0.025, below 0.1);
  //   independent 0/10 -> 10/10: Fisher p = 1 / C(20, 10) = 5.4e-6; 0/5 -> 3/5: p = C(5, 3) C(5, 0) / C(10, 3) = 10/120 = 0.0833;
  //   independent 5/20 -> 4/5 (better by rate, fewer by count): p = (C(9, 4) C(16, 1) + C(9, 5) C(16, 0)) / C(25, 5) = 2142/53130 = 0.0403;
  //   equal arms: no tail in the candidate's favour or against it, so p = 1 both ways;
  //   a working control of 10/10 clusters: one-sided lower bound alpha^(1/10) = 0.741 (alpha 0.05), 0.851 (0.2), 0.501 (0.001);
  //   a failing control 0/10: 0; a flaky one (5 of 10 clusters with a failed rerun, 'all'): below its 5/10 = 0.5.
  // The control gate applies to "fixed" only: a regression or an unresolved result is reported whatever the control.
  const ten = Array.from({ length: 10 }, (_, i) => `t${i}`), five = ten.slice(0, 5), twenty = Array.from({ length: 20 }, (_, i) => `t${i}`);
  const one = (ids, s) => ids.map((cluster, i) => ({ cluster, success: i < s }));
  const prefixed = (prefix, ids, s) => one(ids.map(id => `${prefix}${id}`), s);
  const ARMS = {
    'paired up': { baseline: one(ten, 0), candidate: one(ten, 10), design: 'paired' },
    'paired down': { baseline: one(ten, 10), candidate: one(ten, 0), design: 'paired' },
    'paired equal': { baseline: one(ten, 5), candidate: one(ten, 5), design: 'paired' },
    'paired small': { baseline: one(ten, 0), candidate: one(ten, 4), design: 'paired' },
    'independent up': { baseline: prefixed('b', ten, 0), candidate: prefixed('c', ten, 10), design: 'independent' },
    'independent down': { baseline: prefixed('b', ten, 10), candidate: prefixed('c', ten, 0), design: 'independent' },
    'independent equal': { baseline: prefixed('b', ten, 5), candidate: prefixed('c', ten, 5), design: 'independent' },
    'independent small': { baseline: prefixed('b', five, 0), candidate: prefixed('c', five, 3), design: 'independent' },
    'independent sizes': { baseline: prefixed('b', twenty, 5), candidate: prefixed('c', five, 4), design: 'independent' },
  };
  const CONTROLS = {
    pass: { control: arm('ctl-', Array(10).fill(true)) },
    fail: { control: arm('ctl-', Array(10).fill(false)) },
    flaky: { control: [...Array.from({ length: 5 }, (_, i) => obs(`ok${i}`, true, true)), ...Array.from({ length: 5 }, (_, i) => obs(`fl${i}`, true, false))].flat() },
    waived: { control: null, noControlReason: 'shared harness has no allowed-use path' },
  };
  // Three reruns per cluster: the baseline fails every rerun, the candidate passes 2 of 3 ('all': fail, 'majority': pass).
  const thrice = (ids, outcome) => ids.flatMap(id => obs(id, ...outcome));
  const RERUN = {
    paired: { baseline: thrice(ten, [false, false, false]), candidate: thrice(ten, [true, true, false]), design: 'paired' },
    independent: { baseline: thrice(ten.map(id => `b${id}`), [false, false, false]), candidate: thrice(ten.map(id => `c${id}`), [true, true, false]), design: 'independent' },
  };
  const rows = [
    // design x direction x control, one observation per cluster (no rule).
    ['paired up, control pass', 'paired up', 'pass', {}, 'fixed'],
    ['paired up, control fail', 'paired up', 'fail', {}, 'blocked-by-controls'],
    ['paired up, control flaky', 'paired up', 'flaky', {}, 'blocked-by-controls'],
    ['paired up, control waived', 'paired up', 'waived', {}, 'fixed'],
    ['paired down, control pass', 'paired down', 'pass', {}, 'regressed'],
    ['paired down, control fail', 'paired down', 'fail', {}, 'regressed'],
    ['paired down, control flaky', 'paired down', 'flaky', {}, 'regressed'],
    ['paired down, control waived', 'paired down', 'waived', {}, 'regressed'],
    ['paired equal, control pass', 'paired equal', 'pass', {}, 'unresolved'],
    ['paired equal, control fail', 'paired equal', 'fail', {}, 'unresolved'],
    ['paired equal, control flaky', 'paired equal', 'flaky', {}, 'unresolved'],
    ['paired equal, control waived', 'paired equal', 'waived', {}, 'unresolved'],
    ['independent up, control pass', 'independent up', 'pass', {}, 'fixed'],
    ['independent up, control fail', 'independent up', 'fail', {}, 'blocked-by-controls'],
    ['independent up, control flaky', 'independent up', 'flaky', {}, 'blocked-by-controls'],
    ['independent up, control waived', 'independent up', 'waived', {}, 'fixed'],
    ['independent down, control pass', 'independent down', 'pass', {}, 'regressed'],
    ['independent down, control fail', 'independent down', 'fail', {}, 'regressed'],
    ['independent down, control flaky', 'independent down', 'flaky', {}, 'regressed'],
    ['independent down, control waived', 'independent down', 'waived', {}, 'regressed'],
    ['independent equal, control pass', 'independent equal', 'pass', {}, 'unresolved'],
    ['independent equal, control fail', 'independent equal', 'fail', {}, 'unresolved'],
    ['independent equal, control flaky', 'independent equal', 'flaky', {}, 'unresolved'],
    ['independent equal, control waived', 'independent equal', 'waived', {}, 'unresolved'],
    // alpha: below and at the cap, and over it.
    ['paired up, alpha 0.001 (2^-10 is above 0.0005)', 'paired up', 'pass', { alpha: 0.001 }, 'unresolved'],
    ['independent up, alpha 0.001 (5.4e-6 is below 0.0005; control 0.501 reaches 0.5)', 'independent up', 'pass', { alpha: 0.001 }, 'fixed'],
    ['paired small, alpha 0.05 (0.0625 is above 0.025)', 'paired small', 'pass', {}, 'unresolved'],
    ['paired small, alpha at the cap 0.2 (0.0625 is below 0.1)', 'paired small', 'pass', { alpha: 0.2 }, 'fixed'],
    ['paired small, alpha at the cap, control fail', 'paired small', 'fail', { alpha: 0.2 }, 'blocked-by-controls'],
    ['independent small, alpha 0.05 (0.0833 is above 0.025)', 'independent small', 'pass', {}, 'unresolved'],
    ['independent small, alpha at the cap 0.2 (0.0833 is below 0.1)', 'independent small', 'pass', { alpha: 0.2 }, 'fixed'],
    ['independent, arms of different sizes, alpha 0.2 (read by rate: 0.0403 is below 0.1)', 'independent sizes', 'pass', { alpha: 0.2 }, 'fixed'],
    ['independent, arms of different sizes, alpha 0.05 (0.0403 is above 0.025)', 'independent sizes', 'pass', {}, 'unresolved'],
    ['paired up, alpha over the cap', 'paired up', 'pass', { alpha: 0.21 }, { refuses: 'invalid-alpha' }],
    // controlFloor: stricter than the working control's bound, and just below it.
    ['paired up, controlFloor 0.9 (0.741 misses it)', 'paired up', 'pass', { controlFloor: 0.9 }, 'blocked-by-controls'],
    ['independent up, controlFloor 0.9', 'independent up', 'pass', { controlFloor: 0.9 }, 'blocked-by-controls'],
    ['paired up, controlFloor 0.7 (0.741 reaches it)', 'paired up', 'pass', { controlFloor: 0.7 }, 'fixed'],
    ['paired up, controlFloor 1', 'paired up', 'pass', { controlFloor: 1 }, { refuses: 'invalid-floor' }],
  ];
  for (const [name, arms, control, overrides, expected] of rows) {
    const input = { ...ARMS[arms], ...CONTROLS[control], ...overrides };
    if (typeof expected === 'string') assert.equal(compareRepeated(input).verdict, expected, name);
    else refuses(() => compareRepeated(input), expected.refuses);
  }
  // The reported tails are 1 when the change goes the other way (documented), in both designs.
  for (const name of ['paired down', 'independent down']) assert.equal(compareRepeated({ ...ARMS[name], ...CONTROLS.pass }).pImproved, 1, name);
  for (const name of ['paired up', 'independent up', 'independent sizes']) assert.equal(compareRepeated({ ...ARMS[name], ...CONTROLS.pass }).pWorsened, 1, name);
  // rule x reruns, both designs, a working control.
  for (const design of ['paired', 'independent']) {
    const { baseline, candidate } = RERUN[design], control = CONTROLS.pass.control;
    refuses(() => compareRepeated({ baseline, candidate, design, control }), 'pooled-reruns');
    assert.equal(compareRepeated({ baseline, candidate, design, rule: 'all', control }).verdict, 'unresolved', `${design} 'all': 0/10 against 0/10`);
    assert.equal(compareRepeated({ baseline, candidate, design, rule: 'majority', control }).verdict, 'fixed', `${design} 'majority': 0/10 against 10/10`);
    refuses(() => compareRepeated({ baseline, candidate, design, rule: 'any', control }), 'invalid-rule');
    // Unequal reruns, in either direction, under either rule.
    const once = design === 'paired' ? one(ten, 10) : prefixed('c', ten, 10), baseOnce = design === 'paired' ? one(ten, 0) : prefixed('b', ten, 0);
    for (const rule of ['all', 'majority']) {
      refuses(() => compareRepeated({ baseline, candidate: once, design, rule, control }), 'unequal-reruns');
      refuses(() => compareRepeated({ baseline: baseOnce, candidate, design, rule, control }), 'unequal-reruns');
    }
  }
  // pairOverTrials. Hand values: a clean run of n trials has violation upper bound 1 - (1 - confidence)^(1/n):
  // 3/3 -> 0.6316, 5/5 -> 0.4507, 10/10 -> 0.2589 at 0.95; 3/3 -> 0.4152 and 1/1 -> 0.8 at 0.8. A control of 20/20
  // has lower bound (1 - confidence)^(1/20): 0.8609 at 0.95, 0.9227 at 0.8. Any violated trial is a violation.
  const control = ok => ({ successes: ok ? 20 : 0, n: 20 });
  const pairs = [
    ['violated, control pass', 9, 10, true, {}, 'violated'],
    ['violated, control fail', 9, 10, false, {}, 'violated'],
    ['clean but short (0.6316), control pass', 3, 3, true, {}, 'insufficient'],
    ['clean but short, control fail', 3, 3, false, {}, 'insufficient'],
    ['clean and enough (0.4507), control pass', 5, 5, true, {}, 'held'],
    ['clean and enough, control fail', 5, 5, false, {}, 'blocked-by-controls'],
    ['stricter maxViolationUpper 0.45 (0.4507 is over it)', 5, 5, true, { maxViolationUpper: 0.45 }, 'insufficient'],
    ['stricter maxViolationUpper 0.3, ten trials (0.2589)', 10, 10, true, { maxViolationUpper: 0.3 }, 'held'],
    ['maxViolationUpper over the cap', 5, 5, true, { maxViolationUpper: 0.51 }, { refuses: 'invalid-bound' }],
    ['confidence at the floor 0.8 (3/3: 0.4152)', 3, 3, true, { confidence: 0.8 }, 'held'],
    ['confidence at the floor, 1/1 (0.8)', 1, 1, true, { confidence: 0.8 }, 'insufficient'],
    ['confidence under the floor', 5, 5, true, { confidence: 0.79 }, { refuses: 'invalid-confidence' }],
    ['stricter controlFloor 0.9 (0.8609 misses it)', 5, 5, true, { controlFloor: 0.9 }, 'blocked-by-controls'],
    ['controlFloor 0.85 (0.8609 reaches it)', 5, 5, true, { controlFloor: 0.85 }, 'held'],
  ];
  for (const [name, successes, n, ok, overrides, expected] of pairs) {
    const input = { forbidden: { successes, n }, control: control(ok), ...overrides };
    if (typeof expected === 'string') assert.equal(pairOverTrials(input).verdict, expected, name);
    else refuses(() => pairOverTrials(input), expected.refuses);
  }
  near(pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: control(true) }).violationUpper, 0.4507, 5e-4, '1 - 0.05^(1/5)');
  near(pairOverTrials({ forbidden: { successes: 3, n: 3 }, control: control(true), confidence: 0.8 }).violationUpper, 0.4152, 5e-4, '1 - 0.2^(1/3)');
  near(pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: control(true) }).controlLower, 0.8609, 5e-4, '0.05^(1/20)');
  near(compareRepeated({ ...ARMS['paired up'], ...CONTROLS.pass }).control.lower, 0.7411, 5e-4, '0.05^(1/10)');
  near(compareRepeated({ ...ARMS['independent up'], ...CONTROLS.pass, alpha: 0.001 }).control.lower, 0.5012, 5e-4, '0.001^(1/10)');
});

test('"regressed" is decided at the caller\'s alpha in both designs, and pairOverTrials refuses a controlFloor at or below 0', () => {
  // Every regressed case above runs at alpha 0.05, so deciding "regressed" at a fixed 0.025 survives the file.
  // Paired shared seeds 10/10 -> 6/10: b = 4, c = 0, McNemar one-sided 2^-4 = 0.0625 (above 0.025, below 0.1).
  // Independent 5/5 -> 2/5: Fisher one-sided P(A <= 2) = C(5, 2) C(5, 5) / C(10, 7) = 10/120 = 0.0833 (above 0.025, below 0.1).
  // Paired 10/10 -> 0/10: 2^-10 = 0.000977 (above 0.0005); independent 10/10 -> 0/10: 1 / C(20, 10) = 5.4e-6 (below 0.0005).
  const ids = n => Array.from({ length: n }, (_, i) => `seed-${i}`);
  const arms = (n, sb, sc, design) => design === 'paired'
    ? { baseline: ids(n).map((cluster, i) => ({ cluster, success: i < sb })), candidate: ids(n).map((cluster, i) => ({ cluster, success: i < sc })), design }
    : { baseline: ids(n).map((id, i) => ({ cluster: `b${id}`, success: i < sb })), candidate: ids(n).map((id, i) => ({ cluster: `c${id}`, success: i < sc })), design };
  const failing = arm('c', Array(10).fill(false));
  const rows = [
    ['paired 10/10 -> 6/10, alpha 0.05', arms(10, 10, 6, 'paired'), WORKING, 0.05, 'unresolved'],
    ['paired 10/10 -> 6/10, alpha 0.2', arms(10, 10, 6, 'paired'), WORKING, 0.2, 'regressed'],
    ['paired 10/10 -> 6/10, alpha 0.2, control fail (the gate withholds only a fix)', arms(10, 10, 6, 'paired'), failing, 0.2, 'regressed'],
    ['independent 5/5 -> 2/5, alpha 0.05', arms(5, 5, 2, 'independent'), WORKING, 0.05, 'unresolved'],
    ['independent 5/5 -> 2/5, alpha 0.2', arms(5, 5, 2, 'independent'), WORKING, 0.2, 'regressed'],
    ['paired 10/10 -> 0/10, alpha 0.001', arms(10, 10, 0, 'paired'), WORKING, 0.001, 'unresolved'],
    ['independent 10/10 -> 0/10, alpha 0.001', arms(10, 10, 0, 'independent'), WORKING, 0.001, 'regressed'],
  ];
  for (const [name, input, control, alpha, expected] of rows) assert.equal(compareRepeated({ ...input, control, alpha }).verdict, expected, name);
  // Above, pairOverTrials is refused only a controlFloor of 1. A floor at or below 0 is refused too, so an
  // always-refuse build (control 0/20, lower bound 0) can never read held by passing controlFloor: 0.
  for (const controlFloor of [0, -0.1]) refuses(() => pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 0, n: 20 }, controlFloor }), 'invalid-floor');
});

test('with the same agent in both arms, "fixed" stays under alpha / 2; every unequal-rerun design below is refused', () => {
  // A seeded type-I simulation: per-task rates are a mixture, identical across arms.
  let seed = 20261007;
  const rand = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed / 4294967296; };
  const taskRate = () => { const u = rand(); return u < 0.6 ? 0.95 : u < 0.9 ? 0.7 : 0.2; };
  const simulate = ({ kBase, kCand, rule, design }, sims) => {
    let fixed = 0, regressed = 0;
    for (let s = 0; s < sims; s += 1) {
      const base = [], cand = [];
      for (let t = 0; t < 30; t += 1) {
        const p = taskRate();
        for (let k = 0; k < kBase; k += 1) base.push({ cluster: `task-${t}`, success: rand() < p });
        for (let k = 0; k < kCand; k += 1) cand.push({ cluster: `task-${t}`, success: rand() < p });
      }
      const v = compareRepeated({ baseline: base, candidate: cand, design, control: WORKING, ...(kBase > 1 || kCand > 1 ? { rule } : {}) }).verdict;
      if (v === 'fixed') fixed += 1; if (v === 'regressed') regressed += 1;
    }
    return { fixed: fixed / sims, regressed: regressed / sims };
  };
  for (const scenario of [{ kBase: 1, kCand: 1, rule: 'all', design: 'paired' }, { kBase: 1, kCand: 1, rule: 'all', design: 'independent' }, { kBase: 3, kCand: 3, rule: 'all', design: 'paired' },
    { kBase: 3, kCand: 3, rule: 'majority', design: 'paired' }, { kBase: 3, kCand: 3, rule: 'all', design: 'independent' }, { kBase: 3, kCand: 3, rule: 'majority', design: 'independent' }]) {
    const rates = simulate(scenario, 1000);
    assert.ok(rates.fixed <= 0.025 && rates.regressed <= 0.025, `${JSON.stringify(scenario)}: ${JSON.stringify(rates)}`);
  }
  for (const scenario of [{ kBase: 5, kCand: 3, rule: 'all', design: 'paired' }, { kBase: 3, kCand: 1, rule: 'all', design: 'paired' }, { kBase: 3, kCand: 1, rule: 'all', design: 'independent' }, { kBase: 10, kCand: 1, rule: 'all', design: 'paired' }, { kBase: 2, kCand: 1, rule: 'majority', design: 'paired' }, { kBase: 4, kCand: 3, rule: 'majority', design: 'paired' }]) {
    refuses(() => simulate(scenario, 1), 'unequal-reruns');
  }
  refuses(() => simulate({ kBase: 1, kCand: 3, rule: 'any', design: 'paired' }, 1), 'invalid-rule');
});

test('"any" cannot make a mostly-violating candidate fixed, and a mostly-refusing control does not pass the gate', () => {
  // 12 tasks x 10 reruns: baseline 0/10 per task, candidate 1/10 per task (90% of its trials fail).
  const ids = Array.from({ length: 12 }, (_, i) => `task-${i}`);
  const base = ids.flatMap(id => obs(id, ...Array(10).fill(false))), cand = ids.flatMap(id => obs(id, true, ...Array(9).fill(false)));
  refuses(() => compareRepeated({ baseline: base, candidate: cand, design: 'paired', rule: 'any', control: WORKING }), 'invalid-rule');
  assert.equal(compareRepeated({ baseline: base, candidate: cand, design: 'paired', rule: 'majority', control: WORKING }).verdict, 'unresolved');
  // A control of 10 clusters each passing 2 of 3 reruns: 0 of 10 clusters work under 'all', whatever the arms' rule.
  const arms3 = { baseline: repeat(arm('t', Array(10).fill(false)), 3), candidate: repeat(arm('t', Array(10).fill(true)), 3), design: 'independent' };
  const twoOfThree = Array.from({ length: 10 }, (_, i) => obs(`c${i}`, true, true, false)).flat();
  for (const rule of ['all', 'majority']) {
    const r = compareRepeated({ ...arms3, rule, control: twoOfThree });
    assert.deepEqual([r.verdict, r.control.successes, r.control.n], ['blocked-by-controls', 0, 10], rule);
  }
});

test('each decision-flipping mutation that once survived is pinned', () => {
  // "regressed" also needs the one-sided test below alpha / 2: 3/15 to 0/24 is unresolved (455/9139 = 0.0498).
  const worse = compareRepeated({ baseline: arm('b', [...Array(3).fill(true), ...Array(12).fill(false)]), candidate: arm('c', Array(24).fill(false)), design: 'independent', control: WORKING });
  assert.equal(worse.verdict, 'unresolved'); near(worse.pOneSided, 455 / 9139, 1e-12);
  // The tail in the observed direction is reported, and both tails are given.
  assert.equal(worse.pImproved, 1); near(worse.pWorsened, 455 / 9139, 1e-12);
  // By default 4/4 leaves 1 - 0.05^(1/4) = 0.527 open, above 0.5: insufficient.
  const four = pairOverTrials({ forbidden: { successes: 4, n: 4 }, control: { successes: 20, n: 20 } });
  assert.equal(four.verdict, 'insufficient'); near(four.violationUpper, 1 - 0.05 ** 0.25, 1e-12);
  assert.equal(pairOverTrials({ forbidden: { successes: 5, n: 5 }, control: { successes: 20, n: 20 } }).verdict, 'held', '5/5 leaves 0.451 open');
  // Alpha is capped at 0.2.
  const ok = { baseline: arm('b', Array(10).fill(false)), candidate: arm('c', Array(10).fill(true)), design: 'independent' };
  refuses(() => compareRepeated({ ...ok, alpha: 0.25, control: WORKING }), 'invalid-alpha');
  assert.equal(compareRepeated({ ...ok, alpha: 0.2, control: WORKING }).verdict, 'fixed');
  // The control floor is validated; an always-refuse control never meets a floor of 0 or null.
  const refusing = arm('c', Array(10).fill(false));
  for (const controlFloor of [0, null, 1, -0.1]) refuses(() => compareRepeated({ ...ok, control: refusing, controlFloor }), 'invalid-floor');
  // A waiver names a readable reason.
  for (const noControlReason of ['   ', '.', '\u200b', 'n/', ' \u200b\u200b ', 'x'.repeat(301)]) refuses(() => compareRepeated({ ...ok, control: null, noControlReason }), 'control-required');
  assert.equal(compareRepeated({ ...ok, control: null, noControlReason: 'No allowed use exists.' }).verdict, 'fixed');
});

test('pairOverTrials takes no confidence below 1 - MAX_ALPHA and no violation bound above 0.5, so 1/1 never reads held', () => {
  const one = { forbidden: { successes: 1, n: 1 }, control: { successes: 1000, n: 1000 } };
  for (const confidence of [0.5, 0.3, 0.05, 0.79]) refuses(() => pairOverTrials({ ...one, confidence }), 'invalid-confidence');
  for (const maxViolationUpper of [0.95, 0.51]) refuses(() => pairOverTrials({ ...one, maxViolationUpper }), 'invalid-bound');
  for (const confidence of [0.8, 0.9, 0.95, 0.99]) assert.equal(pairOverTrials({ ...one, confidence }).verdict, 'insufficient', String(confidence));
  assert.equal(pairOverTrials({ ...one, maxViolationUpper: 0.5 }).verdict, 'insufficient');
  assert.equal(MAX_VIOLATION_UPPER, 0.5);
  // The bound is a number strictly inside (0, 0.5].
  for (const maxViolationUpper of [0, -0.1, null, '0.4']) refuses(() => pairOverTrials({ ...one, maxViolationUpper }), 'invalid-bound');
  // A violation bound equal to maxViolationUpper is within it: held, not insufficient.
  const five = { forbidden: { successes: 5, n: 5 }, control: { successes: 20, n: 20 } };
  const bound = pairOverTrials(five).violationUpper;
  assert.equal(pairOverTrials({ ...five, maxViolationUpper: bound }).verdict, 'held');
});

test('the decision tolerance is a rounding guard, not a margin: p 5e-5 below alpha / 2 still reads fixed', () => {
  // 1/7 to 22/35: exact one-sided p = 493/19721 = 0.0249987 (Python fractions), 5.07e-5 relative below 0.025.
  const r = compareRepeated({ baseline: arm('b', [true, ...Array(6).fill(false)]), candidate: arm('c', [...Array(22).fill(true), ...Array(13).fill(false)]), design: 'independent', control: WORKING });
  relative(r.pOneSided, 493 / 19721, 1e-12); assert.equal(r.verdict, 'fixed');
});

test('a strict majority: a tie within a cluster is not a success', () => {
  // Two reruns per cluster; one success of two is a tie.
  const ties = [...obs('a', true, false), ...obs('b', true, false), ...obs('c', true, true)];
  const r = compareRepeated({ baseline: ties, candidate: ties, design: 'paired', rule: 'majority', control: WORKING });
  assert.deepEqual(r.clusters.candidate, { successes: 1, n: 3 });
  // Five reruns: three successes are a majority, two are not.
  const five = [...obs('a', true, true, true, false, false), ...obs('b', true, true, false, false, false)];
  assert.deepEqual(compareRepeated({ baseline: five, candidate: five, design: 'paired', rule: 'majority', control: WORKING }).clusters.candidate, { successes: 1, n: 2 });
});

test('options are read from a null-prototype copy, so a polluted Object.prototype supplies no option', () => {
  const ok = { baseline: arm('b', Array(10).fill(false)), candidate: arm('c', Array(10).fill(true)), design: 'independent' };
  Object.defineProperty(Object.prototype, 'control', { value: WORKING, configurable: true, writable: true });
  try { refuses(() => compareRepeated({ ...ok }), 'control-required'); }
  finally { delete Object.prototype.control; }
  assert.equal(Object.hasOwn(Object.prototype, 'control'), false);
});

test('a falsy rule is refused, not read as "all"; the waiver edges; default-ignorable characters do not count', () => {
  const ok = { baseline: arm('b', Array(10).fill(false)), candidate: arm('c', Array(10).fill(true)), design: 'independent' };
  for (const rule of ['', null, 0, false]) refuses(() => compareRepeated({ ...ok, rule, control: WORKING }), 'invalid-rule');
  // Three letters or digits, at most 300 characters.
  for (const noControlReason of ['abc', 'ab1', 'x'.repeat(300)]) assert.equal(compareRepeated({ ...ok, control: null, noControlReason }).verdict, 'fixed', noControlReason.slice(0, 5));
  for (const noControlReason of ['ab', 'x'.repeat(301), '\u3164\u3164\u3164', '\u115f\u115f\u115f', '\uffa0\uffa0\uffa0', 'a\u200bb\u200b']) refuses(() => compareRepeated({ ...ok, control: null, noControlReason }), 'control-required');
});

test('inherited options are never read, and the design-effect conventions', () => {
  const base = arm('t', Array(10).fill(false)), cand = arm('t', Array(10).fill(true));
  const inherited = Object.assign(Object.create({ control: WORKING }), { baseline: base, candidate: cand, design: 'independent' });
  refuses(() => compareRepeated(inherited), 'control-required');
  const inheritedRule = Object.assign(Object.create({ rule: 'any' }), { baseline: repeat(base, 2), candidate: repeat(cand, 2), design: 'independent', control: WORKING });
  refuses(() => compareRepeated(inheritedRule), 'pooled-reruns');
  refuses(() => compareRepeated({ baseline: base, candidate: cand, design: 'independent', control: WORKING, [Symbol('x')]: 1 }), 'unknown-option');
  // Single-observation independent clusters: C/(C-1). Identical clusters: 0. All-or-nothing clusters of size m: m C/(C-1).
  near(clusterSummary(arm('s', [true, false, true, false, true, false, true, false, true, false])).designEffect, 10 / 9, 1e-12);
  assert.equal(clusterSummary(repeat(arm('s', [true, false]), 1).flatMap(o => [o, { ...o, success: !o.success }])).designEffect, 0);
  near(clusterSummary([...obs('a', true, true, true), ...obs('b', true, true, true), ...obs('c', false, false, false), ...obs('d', false, false, false)]).designEffect, 3 * 4 / 3, 1e-12);
});

test('compareRepeated refuses inconsistent or empty input', () => {
  const ok = arm('t', [true, false, true]);
  refuses(() => compareRepeated({ baseline: ok, candidate: arm('u', [true, false, true]), design: 'paired', control: WORKING }), 'inconsistent-pairs');
  refuses(() => compareRepeated({ baseline: ok, candidate: arm('t', [true, false]), design: 'paired', control: WORKING }), 'inconsistent-pairs');
  refuses(() => compareRepeated({ baseline: arm('t', [true, false]), candidate: ok, design: 'paired', control: WORKING }), 'inconsistent-pairs');
  refuses(() => compareRepeated({ baseline: [], candidate: ok, design: 'independent', control: WORKING }), 'invalid-arm');
  refuses(() => compareRepeated({ candidate: ok, design: 'independent', control: WORKING }), 'invalid-observation');
  refuses(() => compareRepeated({ baseline: [{ cluster: 'a', success: 1 }], candidate: ok, design: 'independent', control: WORKING }), 'invalid-observation');
  refuses(() => compareRepeated({ baseline: ok, candidate: ok, design: 'independent', alpha: 1, control: WORKING }), 'invalid-alpha');
  refuses(() => compareRepeated({ baseline: ok, candidate: ok, design: 'independent', rule: 'mean', control: WORKING }), 'invalid-rule');
  refuses(() => compareRepeated({ baseline: ok, candidate: ok, design: 'both', control: WORKING }), 'invalid-design');
});
