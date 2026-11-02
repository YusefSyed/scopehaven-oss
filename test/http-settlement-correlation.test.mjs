// Correlated and per-check settlement (src/http-settlement.mjs): pure decisions over synthetic
// windows, scripted end-to-end runs, and full runs against the owned practice app with its loopback egress recorder
// (integrations/core-practice/app.mjs, fixture options forwardCorrelation and correlationContext). No model, no provider.
// Every allowed behaviour below sits beside the forbidden or fail-closed behaviour next to it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile, contractDigest } from '../src/contracts.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { decideEffects, OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { settlementFindings, applySettlement, settlementTokens, correlationDeclared, SETTLEMENT_BASIS, SETTLEMENT_REASONS } from '../src/http-settlement.mjs';
import { createRegistry } from '../src/registry.mjs';
import { selectorPairs, pairingFindings } from '../src/http-pairing.mjs';
import { evaluateEffectAssertion } from '../src/effect-events.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { createCorePracticeApp, HOOK_HOST } from '../integrations/core-practice/app.mjs';
import { settlementProfile, LATE_TRIGGERS } from '../integrations/core-practice/profiles.mjs';
import { freePorts } from '../integrations/observers/fixtures/free-port.mjs';
import { correlationLimitation } from '../src/http-scope-text.mjs';

// ---------------------------------------------------------------------------
// Pure rules. One declared pair (the hooks recorder, HOOK_HOST); tokens for effect rows 0, 1, 2 and one sent row
// without an effect window (OTHER).
const INST = 'egress-recorder-hooks', OTHER_INST = 'egress-recorder-other';
const SINK = { operations: ['send'], names: [HOOK_HOST], actorAttribution: 'none', evidence: 'authoritative' };
const PRESENCE = { ...SINK, evidence: 'presence-only' };
const T = i => (i + 1).toString(16).padStart(2, '0').repeat(16);
const OTHER = 'ab'.repeat(16), STRANGER = 'cd'.repeat(16);
const tokens = new Map([[T(0), 0], [T(1), 1], [T(2), 2], [OTHER, null]]);
const declared = new Set([`${INST}\n${HOOK_HOST}`]);
let seq = 0;
const ev = (resource, token, instanceId = INST) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, operation: 'send', name: HOOK_HOST, resource, outcome: 'committed', correlation: token ? { settlementToken: token } : {} });
const win = (events = [], coverage = 'complete') => ({ source: 'http-egress', instanceId: INST, scope: SINK, coverage, reason: coverage === 'complete' ? null : 'synthetic', events });
const otherWin = (events = []) => ({ source: 'http-egress', instanceId: OTHER_INST, scope: PRESENCE, coverage: 'complete', reason: null, events });
const sel = resource => ({ source: 'http-egress', operation: 'send', name: HOOK_HOST, ...(resource ? { resource } : {}) });
const none = resource => ({ kind: 'effect.none', select: sel(resource) });
const exists = resource => ({ kind: 'effect.exists', select: sel(resource) });
const count = (resource, expected) => ({ kind: 'effect.count', select: sel(resource), expected });
const only = (resource, allow = []) => ({ kind: 'effect.only', expect: [{ select: sel(resource), count: 1 }], allow, sources: ['http-egress'] });
const rowOf = (effects, windows, role = 'boundary') => ({ effects: decideEffects(effects, windows, { role }), windows });
const gapsFor = rows => Array.from({ length: rows.length + 1 }, () => [win()]);
const barriersFor = rows => rows.map(() => [win()]);
const perCheck = (rows, { barriers = barriersFor(rows), declaredPairs = declared } = {}) => ({ mode: 'per-check', barriers, tokens, declared: declaredPairs });
const runMode = { mode: 'run', tokens, declared };
const A = 'POST /hooks/bob/admin', B = 'POST /hooks/alice/member';

test('forbidden: a later check\'s own exact count over its own-token send releases nothing; per-check and run-mode correlation read as run-level settlement', () => {
  const same = rows => {
    const legacy = settlementFindings(rows, gapsFor(rows));
    assert.deepEqual(settlementFindings(rows, gapsFor(rows), perCheck(rows)), legacy);
    assert.deepEqual(settlementFindings(rows, gapsFor(rows), runMode), legacy);
    return legacy;
  };
  const rows = [rowOf([none()], [win()]), rowOf([count(null, 1)], [win([ev(B, T(1))])])];
  assert.deepEqual(rows.map(r => r.effects[0].verdict), ['pass', 'pass']);
  assert.deepEqual(same(rows), [['effect-outside-window'], ['effect-ambiguous-attribution']]);
  // An earlier check with an exact positive count that passed: the later count's own send still withholds both.
  const counted = [rowOf([count(A, 1)], [win([ev(A, T(0))])]), rowOf([count(null, 1)], [win([ev(A, T(1))])])];
  assert.deepEqual(same(counted), [['effect-outside-window'], ['effect-ambiguous-attribution']]);
  // An exact count of 2 that saw exactly its two tagged sends releases nothing either.
  const two = [rowOf([none()], [win()]), rowOf([count(null, 2)], [win([ev(B, T(1)), ev(B, T(1))])])];
  assert.deepEqual(same(two), [['effect-outside-window'], ['effect-ambiguous-attribution']]);
});

test('forbidden: a later effect.only expected entry (an upper bound) never releases an earlier absence, nor does an exact count beside it', () => {
  const k = () => rowOf([none()], [win()]);
  const onlyN = (resource, n) => ({ kind: 'effect.only', expect: [{ select: sel(resource), count: n }], allow: [], sources: ['http-egress'] });
  const findings = rows => settlementFindings(rows, gapsFor(rows), perCheck(rows));
  // Count 1: the later window holds one send tagged to the later check. It may be k's deferred send stamped
  // with the flushing request's token while the later check sent nothing (0 is within "at most 1"), so k stays withheld.
  const one = [k(), rowOf([onlyN(B, 1)], [win([ev(B, T(1))])])];
  assert.equal(one[1].effects[0].verdict, 'pass');
  assert.deepEqual(findings(one), [['effect-outside-window'], [null]]);
  // Count 3: the later check's own send plus k's late send, both stamped with the later token. The later check
  // skipped nothing it was required to send, and its entry still passes (2 is within "at most 3"): no release.
  const genuine = ev(B, T(1)), stale = ev(B, T(1));
  const adv1 = [k(), rowOf([onlyN(B, 3)], [win([genuine, stale])])];
  assert.equal(adv1[1].effects[0].verdict, 'pass');
  assert.deepEqual(findings(adv1), [['effect-outside-window'], [null]]);
  // Count 2 with exactly two tagged sends, host-wide entry and a bare-selector entry: saturation is not exactness either.
  const full = [k(), rowOf([onlyN(null, 2)], [win([ev(B, T(1)), ev(A, T(1))])])];
  assert.equal(full[1].effects[0].verdict, 'pass');
  assert.equal(findings(full)[0][0], 'effect-outside-window');
  const bare = [k(), rowOf([only(B)], [win([ev(B, T(1))])])];
  assert.equal(findings(bare)[0][0], 'effect-outside-window');
  // The same shapes with an exact count: the genuine send plus the stamped one exceed expected 1, so the count fails and
  // nothing is accounted; a count of 2 over three tagged sends fails the same way.
  const exact = [k(), rowOf([count(B, 1)], [win([ev(B, T(1)), ev(B, T(1))])])];
  assert.equal(exact[1].effects[0].verdict, 'fail');
  assert.equal(findings(exact)[0][0], 'effect-outside-window');
  const over = [k(), rowOf([count(null, 2)], [win([ev(B, T(1)), ev(B, T(1)), ev(A, T(1))])])];
  assert.equal(over[1].effects[0].verdict, 'fail');
  assert.equal(findings(over)[0][0], 'effect-outside-window');
  // An effect.only beside a passing exact count in the same later check: neither releases the earlier absence.
  const beside = [k(), rowOf([count(B, 1), onlyN(null, 3)], [win([ev(B, T(1)), ev(A, T(1))])])];
  assert.deepEqual(beside[1].effects.map(d => d.verdict), ['pass', 'pass']);
  assert.equal(findings(beside)[0][0], 'effect-outside-window', 'the send to A is only inside the effect.only bound');
  const besideB = [rowOf([none(B)], [win()]), rowOf([count(B, 1), onlyN(null, 3)], [win([ev(B, T(1))])])];
  assert.deepEqual(findings(besideB)[0], ['effect-outside-window'], 'the exact count\'s own-token send releases nothing');
});

test('forbidden: a later count unsettled by its own later records releases nothing (its own late tagged send, an untagged later fit, another row\'s token, an unobserved later window)', () => {
  // k: an absence on B. j: a host-wide exact count of 1 that passed in its own window over one send to B carrying j's token.
  const findings = (rows, gaps = gapsFor(rows), barriers) => settlementFindings(rows, gaps, perCheck(rows, barriers ? { barriers } : {}));
  const setup = () => [rowOf([none(B)], [win()]), rowOf([count(null, 1)], [win([ev(B, T(1))])])];
  // j's own token on a later send to A, in the tail. Judged with it, j's count is 2, not 1:
  // the send to B may be k's late send stamped with j's token while j's genuine send came late. k must stay withheld.
  const late = setup();
  assert.deepEqual(late.map(r => r.effects[0].verdict), ['pass', 'pass']);
  assert.deepEqual(findings(late, [[win()], [win()], [win([ev(A, T(1))])]]), [['effect-outside-window'], ['effect-correlated-late']]);
  // The same late j send inside j's own horizon (its barrier) or in the next check's window.
  const inBarrier = setup();
  assert.deepEqual(findings(inBarrier, gapsFor(inBarrier), [[win()], [win([ev(A, T(1))])]]), [['effect-outside-window'], ['effect-correlated-late']]);
  const next = [...setup(), rowOf([none('POST /hooks/carol/x')], [win([ev(A, T(1))])])];
  assert.deepEqual(findings(next).slice(0, 2), [['effect-outside-window'], ['effect-correlated-late']]);
  // An untagged later send that fits j's count (j's own late send without a token, as far as the run can tell).
  const untagged = setup();
  assert.deepEqual(findings(untagged, [[win()], [win()], [win([ev(A)])]]), [['effect-outside-window'], ['effect-outside-window']]);
  // j's count rests on a send carrying another row's token; k is withheld by the send to B and j by that token (another check's token
  // is read before ambiguity on a positive clause: it is the one reason that also withholds a control's pass).
  const elsewhere = [rowOf([none(B)], [win()]), rowOf([count(null, 2)], [win([ev(B, T(1)), ev(A, OTHER)])])];
  assert.equal(elsewhere[1].effects[0].verdict, 'pass');
  assert.deepEqual(findings(elsewhere), [['effect-outside-window'], ['effect-correlated-elsewhere']]);
  // A later window of the observer that decided j's count is partial, so one more of j's sends could have been missed. (k is
  // decided by another authoritative observer here, so k's own settlement-unobserved does not already cover it.)
  const otherAuth = () => ({ ...otherWin(), scope: SINK });
  const unseen = [rowOf([none(B)], [otherAuth()]), rowOf([count(null, 1)], [win([ev(B, T(1))])])];
  assert.deepEqual(unseen.map(r => r.effects[0].verdict), ['pass', 'pass']);
  assert.deepEqual(findings(unseen, [[win()], [win()], [win([], 'partial')]]), [['effect-outside-window'], ['effect-ambiguous-attribution']]);
});

test('forbidden: later counts that settled themselves do not chain a release back to an earlier absence; a settled count beside an unsettled clause releases nothing', () => {
  const findings = rows => settlementFindings(rows, gapsFor(rows), perCheck(rows));
  // k, then j and m each with an exact count of 1 over its own tagged send: every later send still withholds what it fits.
  const chain = [rowOf([none()], [win()]), rowOf([count(null, 1)], [win([ev(B, T(1))])]), rowOf([count(null, 1)], [win([ev(A, T(2))])])];
  assert.deepEqual(chain.map(r => r.effects[0].verdict), ['pass', 'pass', 'pass']);
  assert.deepEqual(findings(chain), [['effect-outside-window'], ['effect-outside-window'], ['effect-ambiguous-attribution']]);
  assert.deepEqual(findings(chain), settlementFindings(chain, gapsFor(chain)));
  // m's own late send names the reason for m (withheld, not failed); j and k stay withheld.
  const broken = [rowOf([none()], [win()]), rowOf([count(null, 1)], [win([ev(B, T(1))])]), rowOf([count(null, 1)], [win([ev(A, T(2))])])];
  const tail = [[win()], [win()], [win()], [win([ev(A, T(2))])]];
  assert.deepEqual(settlementFindings(broken, tail, perCheck(broken)), [['effect-outside-window'], ['effect-outside-window'], ['effect-correlated-late']]);
  // j's exact count on B, beside j's absence on A that an untagged later send to A unsettles: k stays withheld.
  const mixed = [rowOf([none(B)], [win()]), rowOf([count(B, 1), none(A)], [win([ev(B, T(1))])])];
  assert.deepEqual(settlementFindings(mixed, [[win()], [win()], [win([ev(A)])]], perCheck(mixed)), [['effect-outside-window'], ['effect-ambiguous-attribution', 'effect-outside-window']]);
});

test('forbidden: nothing is released by an untagged, unattributed or undeclared send, one inside the horizon or outside the later check\'s own window, or one no passing clause counted exactly', () => {
  const k = () => rowOf([none()], [win()]);
  const withLater = (events, clause = count(null, 1)) => [k(), rowOf([clause], [win(events)])];
  const firstFinding = (rows, options) => settlementFindings(rows, options?.gaps ?? gapsFor(rows), options?.correlation ?? perCheck(rows))[0][0];
  // (iii) not counted: untagged, a token of no row, an undeclared pair, a count that failed, an effect.exists with no bound.
  assert.equal(firstFinding(withLater([ev(B)])), 'effect-outside-window', 'untagged');
  assert.equal(firstFinding(withLater([ev(B, STRANGER)])), 'effect-outside-window', 'unattributed token');
  const rows = withLater([ev(B, T(1))]);
  assert.equal(firstFinding(rows, { correlation: perCheck(rows, { declaredPairs: new Set() }) }), 'effect-outside-window', 'undeclared pair');
  assert.equal(firstFinding(withLater([ev(B, T(1)), ev(B, T(1))])), 'effect-outside-window', 'the later count failed (2, expected 1)');
  const unbounded = withLater([ev(B, T(1))], exists());
  assert.deepEqual(settlementFindings(unbounded, gapsFor(unbounded), perCheck(unbounded)), [['effect-outside-window'], ['effect-ambiguous-attribution']], 'exists does not release, and the event it rests on withholds the earlier pass, so it stays ambiguous');
  // (ii) a token of an earlier row, in a later window (and that earlier row's count, judged with it, fails).
  const three = [rowOf([count(A, 1)], [win([ev(A, T(0))])]), k(), rowOf([count(null, 1)], [win([ev(A, T(0))])])];
  const found = settlementFindings(three, gapsFor(three), perCheck(three));
  // The later count rests on the earlier row's token: another check's token, read before ambiguity on a positive clause.
  assert.deepEqual(found, [['effect-correlated-late'], ['effect-outside-window'], ['effect-correlated-elsewhere']]);
  // (i) inside k's horizon (its barrier), or in a gap after it instead of the later check's own window.
  const own = withLater([ev(B, T(1))]);
  assert.equal(firstFinding(own, { correlation: perCheck(own, { barriers: [[win([ev(B, T(1))])], [win()]] }) }), 'effect-outside-window', 'a later token inside the barrier');
  assert.equal(firstFinding(own, { gaps: [[win()], [win([ev(B, T(1))])], [win()]] }), 'effect-outside-window', 'a later token in the gap after the barrier');
  // The same event object handed in twice (in the later check's own window and in k's barrier) is still inside k's horizon.
  const shared = ev(B, T(1)), twice = [k(), rowOf([count(null, 1)], [win([shared])])];
  assert.equal(firstFinding(twice, { correlation: perCheck(twice, { barriers: [[win([shared])], [win()]] }) }), 'effect-outside-window', 'one event in the barrier and the later window');
  // Mixed: the later check's tagged send plus one untagged send it also counted, or one from an undeclared observer.
  const mixed = [k(), rowOf([count(null, 2)], [win([ev(B, T(1)), ev(B)])])];
  assert.equal(mixed[1].effects[0].verdict, 'pass');
  assert.equal(firstFinding(mixed), 'effect-outside-window', 'an untagged send beside the tagged one');
  const second = [rowOf([none()], [win(), otherWin()]), rowOf([count(null, 1)], [win([ev(B, T(1))]), otherWin([ev(B, T(1), OTHER_INST)])])];
  assert.deepEqual(second.map(r => r.effects[0].verdict), ['pass', 'pass']);
  assert.equal(firstFinding(second), 'effect-outside-window', 'a send recorded by an undeclared observer');
  // Forged or stale token: a later check's token on an event that check has no exact count for.
  const stale = [k(), rowOf([none(B)], [win([ev(A, T(1))])])];
  assert.equal(firstFinding(stale), 'effect-outside-window');
});

test('late own token: a send carrying a check\'s own token after its window withholds a decided absence (boundary, never a fail) and only tags a control; in its horizon too; a fit that cannot fail withholds', () => {
  const rows = () => [rowOf([none(A)], [win()]), rowOf([none(B)], [win()])];
  // In the next check's window, a gap, the tail, or (per check) the barrier: the clause judged with it would fail.
  for (const [where, place] of [['next window', r => { r[1] = rowOf([none(B)], [win([ev(A, T(0))])]); }], ['gap', (r, g) => { g[1] = [win([ev(A, T(0))])]; }], ['tail', (r, g) => { g[2] = [win([ev(A, T(0))])]; }]]) {
    const r = rows(), g = gapsFor(r); place(r, g);
    assert.deepEqual(settlementFindings(r, g, runMode)[0], ['effect-correlated-late'], `run mode, ${where}`);
    assert.deepEqual(settlementFindings(r, g, perCheck(r))[0], ['effect-correlated-late'], `per check, ${where}`);
  }
  const r = rows();
  assert.deepEqual(settlementFindings(r, gapsFor(r), perCheck(r, { barriers: [[win([ev(A, T(0))])], [win()]] }))[0], ['effect-correlated-late'], 'inside the horizon');
  // The finding withholds a boundary pass (the token alone never fails), tags a control,
  // and never touches a fail.
  const decided = decideEffects([none(A)], [win()]);
  const boundary = applySettlement(decided, ['effect-correlated-late'], 'boundary'), control = applySettlement(decided, ['effect-correlated-late'], 'control');
  assert.deepEqual([boundary[0].verdict, boundary[0].settlement], ['inconclusive', 'effect-correlated-late']);
  assert.ok(boundary[0].basis.endsWith(SETTLEMENT_BASIS['effect-correlated-late']));
  assert.deepEqual([control[0].verdict, control[0].settlement], ['pass', 'effect-correlated-late'], 'a control gets the tag only');
  for (const reason of ['effect-correlated-late-unsettled', 'effect-correlated-elsewhere']) assert.deepEqual(applySettlement(decided, [reason], 'boundary')[0].verdict, 'inconclusive', `${reason} withholds, never fails`);
  const failed = decideEffects([none(A)], [win([ev(A)])]);
  assert.deepEqual(applySettlement(failed, ['effect-correlated-late'], 'boundary'), failed);
  // A count over its expected number with a late own send would fail (named late); one seen only by a presence-only
  // declared observer is named unsettled. Both withhold.
  const counted = [rowOf([count(B, 1)], [win([ev(B, T(0))])])];
  assert.deepEqual(settlementFindings(counted, [[win()], [win([ev(B, T(0))])]], runMode), [['effect-correlated-late']]);
  const both = new Set([...declared, `${OTHER_INST}\n${HOOK_HOST}`]);
  const presence = [rowOf([count(B, 1)], [win([ev(B, T(0))]), otherWin()])];
  assert.deepEqual(settlementFindings(presence, [[win(), otherWin()], [win(), otherWin([ev(B, T(0), OTHER_INST)])]], { ...runMode, declared: both }), [['effect-correlated-late-unsettled']]);
  // effect.only: a late own send outside the declared set is named late; one inside the expected set unsettled.
  const onlyRow = () => [rowOf([only(B)], [win([ev(B, T(0))])])];
  assert.deepEqual(settlementFindings(onlyRow(), [[win()], [win([ev(A, T(0))])]], runMode), [['effect-correlated-late']]);
  assert.deepEqual(settlementFindings(onlyRow(), [[win()], [win([ev(B, T(0))])]], runMode), [['effect-correlated-late-unsettled']]);
  // A control row's late own-token finding is a tag only, recomputed the same way.
  const ctl = [rowOf([none(A)], [win()], 'control')];
  assert.deepEqual(settlementFindings(ctl, [[win()], [win([ev(A, T(0))])]], runMode), [['effect-correlated-late']]);
});

test('another check\'s token and ambiguity: a pass resting on another check\'s token is withheld; a later send that fits an earlier check\'s selector stays ambiguous whatever its token', () => {
  assert.deepEqual(settlementFindings([rowOf([exists()], [win([ev(B, OTHER)])])], [[win()], [win()]], runMode), [['effect-correlated-elsewhere']]);
  assert.deepEqual(settlementFindings([rowOf([exists()], [win([ev(B, OTHER), ev(B, T(0))])])], [[win()], [win()]], runMode), [[null]], 'one own send keeps an exists');
  assert.deepEqual(settlementFindings([rowOf([exists()], [win([ev(B)])])], [[win()], [win()]], runMode), [[null]], 'an untagged send never counts as elsewhere');
  assert.deepEqual(settlementFindings([rowOf([count(null, 2)], [win([ev(B, T(0)), ev(B, OTHER)])])], [[win()], [win()]], runMode), [['effect-correlated-elsewhere']]);
  const later = [rowOf([exists()], [win([ev(B, T(1))])]), rowOf([none(A)], [win()])];
  assert.deepEqual(settlementFindings(later, gapsFor(later), perCheck(later))[0], ['effect-correlated-elsewhere'], 'a later check\'s token on an earlier exists');
  // An earlier positive clause that failed in its own window may have sent late, so its fitting selector stays ambiguous.
  const unmet = [rowOf([exists(A)], [win()]), rowOf([exists()], [win([ev(A, T(1))])])];
  assert.equal(unmet[0].effects[0].verdict, 'fail');
  assert.deepEqual(settlementFindings(unmet, gapsFor(unmet), perCheck(unmet))[1], ['effect-ambiguous-attribution']);
  // One that passed may have sent twice, its second send stamped late with the later check's token (no token
  // makes a fitting send unambiguous).
  const met = [rowOf([exists(A)], [win([ev(A, T(0))])]), rowOf([count(null, 1)], [win([ev(A, T(1))])])];
  assert.deepEqual(settlementFindings(met, gapsFor(met), perCheck(met)), [[null], ['effect-ambiguous-attribution']]);
  // Another check's token (OTHER) is read first and withholds too, also on a control; no token releases the pass.
  for (const token of [undefined, OTHER, STRANGER, T(1)]) {
    const passedFirst = [rowOf([exists(A)], [win([ev(A, T(0))])]), rowOf([count(null, 1)], [win([ev(A, token)])])];
    assert.equal(settlementFindings(passedFirst, gapsFor(passedFirst), perCheck(passedFirst))[1][0], token === OTHER ? 'effect-correlated-elsewhere' : 'effect-ambiguous-attribution', `token ${token}`);
  }
  // Adjacent allowed: an own-token send that fits no earlier selector is not ambiguous.
  const apart = [rowOf([exists(A)], [win([ev(A, T(0))])]), rowOf([count(B, 1)], [win([ev(B, T(1))])])];
  assert.deepEqual(settlementFindings(apart, gapsFor(apart), perCheck(apart)), [[null], [null]]);
  const notOwn = [rowOf([none()], [win()]), rowOf([count(null, 1)], [win([ev(B)])])];
  assert.deepEqual(settlementFindings(notOwn, gapsFor(notOwn), perCheck(notOwn))[1], ['effect-ambiguous-attribution']);
});

test('fail closed: a partial or failed window after the barrier, or the barrier itself, still withholds (settlement-unobserved); malformed options are refused', () => {
  const rows = [rowOf([none(A)], [win()])];
  for (const coverage of ['partial', 'failed']) {
    assert.deepEqual(settlementFindings(rows, [[win()], [win([], coverage)]], perCheck(rows)), [['settlement-unobserved']], `tail ${coverage}`);
    assert.deepEqual(settlementFindings(rows, gapsFor(rows), perCheck(rows, { barriers: [[win([], coverage)]] })), [['settlement-unobserved']], `barrier ${coverage}`);
  }
  assert.throws(() => settlementFindings(rows, gapsFor(rows), { mode: 'per-check', tokens, declared }), /settlement-barriers/);
  assert.throws(() => settlementFindings(rows, gapsFor(rows), { ...runMode, barriers: [[win()]] }), /settlement-barriers/);
  assert.throws(() => settlementFindings(rows, gapsFor(rows), { mode: 'later', tokens, declared }), /settlement-correlation/);
  assert.throws(() => settlementFindings(rows, [[win()]], runMode), /settlement-gaps/);
  assert.deepEqual(SETTLEMENT_REASONS.slice(0, 3), ['effect-outside-window', 'effect-ambiguous-attribution', 'settlement-unobserved']);
});

// With no tag on any event, correlated settlement (run mode, or per check with clean barriers) reads exactly as
// run-level settlement does, over generated rows, clauses, events and coverage.
test('property: without tags, correlated settlement equals run-level settlement (run mode and per check)', () => {
  let state = 20261010;
  const rand = n => { state = (state * 1103515245 + 12345) % 2147483648; return state % n; };
  const resources = [A, B, 'POST /hooks/carol/member'];
  const clauses = [() => none(resources[rand(3)]), () => none(), () => exists(), () => exists(resources[rand(3)]), () => count(resources[rand(3)], 1 + rand(2)), () => count(null, 1), () => only(resources[rand(3)])];
  const events = () => Array.from({ length: rand(3) }, () => ev(resources[rand(3)], rand(3) === 0 ? STRANGER : undefined));
  const window = () => win(events(), ['complete', 'complete', 'complete', 'partial'][rand(4)]);
  for (let trial = 0; trial < 300; trial++) {
    const rows = Array.from({ length: 1 + rand(4) }, () => rowOf(Array.from({ length: 1 + rand(2) }, () => clauses[rand(clauses.length)]()), [window()], rand(4) === 0 ? 'control' : 'boundary'));
    const gaps = Array.from({ length: rows.length + 1 }, () => [window()]);
    const legacy = settlementFindings(rows, gaps);
    assert.deepEqual(settlementFindings(rows, gaps, null), legacy);
    assert.deepEqual(settlementFindings(rows, gaps, runMode), legacy, `run mode, trial ${trial}`);
    assert.deepEqual(settlementFindings(rows, gaps, perCheck(rows)), legacy, `per check, trial ${trial}`);
  }
});

test('tokens: sent rows only, effect rows by run order; a row that was not sent or timed out before sending has none', () => {
  const sent = (id, requestId, extra = {}) => ({ id, status: 'pass', trace: [{ data: { requestId, requestAttempted: true, transportOutcome: 'complete', ...extra } }] });
  const a = sent('A', '11111111-2222-4333-8444-555555555555'), b = sent('B', 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'), c = sent('C', 'ffffffff-ffff-4fff-8fff-ffffffffffff', { requestAttempted: false, transportOutcome: 'not-sent' });
  const t = settlementTokens([a, b, c, { id: 'N', status: 'not_applicable', trace: [{ data: {} }] }], [b]);
  assert.deepEqual([...t], [['11111111222243338444555555555555', null], ['aaaaaaaabbbb4ccc8dddeeeeeeeeeeee', 0]]);
  assert.deepEqual([...correlationDeclared([{ observer: 'hooks', names: [HOOK_HOST] }])], [`${INST}\n${HOOK_HOST}`]);
});

// ---------------------------------------------------------------------------
// Profile validation.
const PAY = 'api.pay.example';
const sinkObserver = (extra = {}) => ({ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/coupons'], correlation: { header: 'traceparent' } }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150, ...extra });
const refundSel = { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' };
function scriptedProfile({ correlation = { header: 'traceparent' }, settlement = { mode: 'per-check' }, observers = [sinkObserver()], extraChecks = [] } = {}) {
  return { id: 'w2-scripted', name: 'W2 scripted', applicationId: 'w2-scripted', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { member: { principalId: 'member-1' } },
    requiredControlIds: ['PING', 'REFUND-OWN'], observers, ...(correlation ? { correlation } : {}), ...(settlement ? { settlement } : {}),
    checks: [
      { id: 'PING', title: 'Ping', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'GET', path: '/ping', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'NO-SEND', title: 'Nothing is sent to the provider', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/quiet', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }],
        effects: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: PAY } }] },
      { id: 'REFUND-OWN', title: 'One refund (allowed)', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }],
        capture: { refundId: { pointer: '/id', type: 'id' } }, effects: [{ kind: 'effect.count', select: refundSel, expected: 1 }] },
      ...extraChecks,
    ] };
}
const invalid = (profile, pattern) => assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [profile] }), pattern);
test('profile validation: correlation needs a recording destination and the same header; per-check needs correlation and a bounded barrier total', () => {
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [scriptedProfile()] }));
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [scriptedProfile({ settlement: { mode: 'run' } })] }));
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [scriptedProfile({ correlation: { header: 'x-request-id' }, observers: [sinkObserver({ destinations: [{ host: PAY, correlation: { header: 'x-request-id' } }] })] })] }));
  invalid(scriptedProfile({ correlation: null }), /settlement-per-check-needs-correlation|destination "correlation" needs the target/);
  invalid(scriptedProfile({ correlation: null, observers: [sinkObserver({ destinations: [{ host: PAY }] })] }), /settlement-per-check-needs-correlation/);
  invalid(scriptedProfile({ settlement: null, observers: [sinkObserver({ destinations: [{ host: PAY }] })] }), /needs at least one egress-recorder destination that records it/);
  invalid(scriptedProfile({ settlement: null, correlation: null }), /destination "correlation" needs the target's own "correlation" header/);
  invalid(scriptedProfile({ correlation: { header: 'x-request-id' } }), /every destination "correlation" names the target's correlation header/);
  for (const header of ['authorization', 'x-scopehaven-run', 'X-Request-Id', 'x-', 'content-type', 'cookie', `x-${'a'.repeat(41)}`]) invalid(scriptedProfile({ correlation: { header } }), /correlation is \{ header \}/);
  invalid(scriptedProfile({ observers: [sinkObserver({ destinations: [{ host: PAY, correlation: { header: 'host' } }] })] }), /"correlation" is \{ header \}/);
  invalid(scriptedProfile({ settlement: { mode: 'per-request' } }), /"mode" must be one of run, per-check/);
  invalid(scriptedProfile({ settlement: { mode: 'per-check', horizonMs: 1 } }), /settlement/);
  // The budget: the largest settle times the applicable effect checks, at most 600000 ms.
  const many = Array.from({ length: 21 }, (_, i) => ({ id: `QUIET-${i}`, title: 'Quiet', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/quiet', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }], effects: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: PAY } }] }));
  invalid(scriptedProfile({ observers: [sinkObserver({ settleMs: 30000 })], extraChecks: many }), /per-check barriers .* exceed 600000 ms/);
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [scriptedProfile({ observers: [sinkObserver({ settleMs: 30000 })], extraChecks: many.slice(0, 17) })] }));
  // The contract digest carries correlation and the mode only when declared, so the modes never compare.
  const plain = scriptedProfile({ correlation: null, settlement: null, observers: [sinkObserver({ destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/coupons'] }] })] });
  const digests = [plain, scriptedProfile({ settlement: null }), scriptedProfile({ settlement: { mode: 'run' } }), scriptedProfile()].map(p => contractDigest(validateTargetFile({ schemaVersion: 1, targets: [p] })[0]));
  assert.equal(new Set(digests).size, 4);
  const { correlation: _c, settlement: _s, ...stripped } = plain;
  assert.equal(contractDigest(validateTargetFile({ schemaVersion: 1, targets: [stripped] })[0]), digests[0]);
});

// ---------------------------------------------------------------------------
// Scripted runs: the transport records the header each check carries; the scripted observer reports events that
// carry the tokens it saw (queue entries are functions of those tokens, in collect order).
function scripted(queue, { marks } = {}) {
  const seen = new Map(), headers = [];
  const transport = async (origin, check, options) => {
    if (options.correlationHeader) { seen.set(check.path, options.correlationHeader.value); headers.push([check.path, options.correlationHeader.name]); } else headers.push([check.path, null]);
    return { status: check.method === 'GET' ? 200 : 201, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  const tokenOf = path => { const v = seen.get(path); return v.startsWith('00-') ? v.slice(3, 35) : v.replace(/-/g, ''); };
  const factory = configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type], instanceId = `${c.type}-${c.id}`, pending = [...queue];
    let n = 0;
    return { kind: out.kind, instanceId, source: out.source, scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { marks?.push(performance.now()); return { at: ++n }; },
      async collect() {
        const next = (pending.shift() ?? (() => ({ events: [] })))(tokenOf), coverage = next.coverage ?? 'complete';
        return { events: next.events.map((e, i) => makeEffect({ source: out.source, observer: { kind: out.kind, instanceId }, seq: 1000 + i + n * 10, outcome: 'committed', actor: null, operation: 'send', name: PAY, ...e })), coverage, reason: coverage === 'complete' ? null : 'synthetic' };
      } };
  });
  return { transport, factory, headers };
}
const refund = tokenPath => t => ({ events: [{ resource: 'POST /v1/refunds', ...(tokenPath ? { correlation: { settlementToken: t(tokenPath) } } : {}) }] });
const empty = () => ({ events: [] });
test('scripted: every sent check carries the header and probes do not; a barrier is marked at least the largest settle after each effect check; the /2 record is recomputed', async () => {
  const p = scriptedProfile(), suite = createRegistry({ profiles: [p], env: {} }).exportSuite(p.id), marks = [];
  // Collect order: NO-SEND's window, REFUND-OWN's window, then the three gaps, then the two barriers.
  const s = scripted([empty, refund('/refund'), empty, empty, empty, empty, empty], { marks });
  const run = await runHttpAssessment(p, { env: {}, transport: s.transport, observerFactory: s.factory });
  // The refund carries REFUND-OWN's token, and the token releases nothing: NO-SEND is withheld as in run mode.
  assert.deepEqual(run.results.map(r => [r.id, r.status]), [['PING', 'pass'], ['NO-SEND', 'inconclusive'], ['REFUND-OWN', 'pass']]);
  assert.equal(run.results[1].trace[1].data.effects[0].settlement, 'effect-outside-window');
  assert.ok(s.headers.every(([, name]) => name === 'traceparent'), 'every sent check carries the header (no credentialed actor, so no probes)');
  assert.deepEqual([run.settlement.schema, run.settlement.mode, run.settlement.correlation, run.settlement.barriers.map(b => b.after)], ['scopehaven-settlement/2', 'per-check', { header: 'traceparent', recorded: [{ observer: 'sink', names: [PAY] }] }, ['NO-SEND', 'REFUND-OWN']]);
  assert.deepEqual(suite.correlation, { header: 'traceparent', recorded: [{ observer: 'sink', names: [PAY] }], mode: 'per-check' });
  // Marks: initial; NO-SEND start, end, barrier; REFUND-OWN start, end, barrier; final.
  assert.equal(marks.length, 8);
  assert.ok(marks[3] - marks[2] >= 240 && marks[6] - marks[5] >= 240, 'each barrier follows its end mark by the settle');
  validateHttpRunEvidence(run, { expectedSuite: suite });
  assert.ok(run.limitations.some(l => l.startsWith('Correlation: every sent check request carried a per-request token in the traceparent header') && l.includes('Per-check settlement')));
  // Run mode: the same events withhold the earlier absence the same way (the refund could be its late effect).
  const pr = scriptedProfile({ settlement: { mode: 'run' } });
  const sr = scripted([empty, refund('/refund'), empty, empty, empty]);
  const runLevel = await runHttpAssessment(pr, { env: {}, transport: sr.transport, observerFactory: sr.factory });
  assert.deepEqual([runLevel.results[1].status, runLevel.results[1].trace[1].data.effects[0].settlement, runLevel.settlement.mode, Object.hasOwn(runLevel.settlement, 'barriers')], ['inconclusive', 'effect-outside-window', 'run', false]);
  validateHttpRunEvidence(runLevel, { expectedSuite: createRegistry({ profiles: [pr], env: {} }).exportSuite(pr.id) });
  assert.ok(runLevel.limitations.some(l => l.startsWith('Correlation:') && !l.includes('Per-check settlement')));
  // An untagged refund (the app did not forward the header) keeps today's withholding in per-check mode too.
  const su = scripted([empty, refund(null), empty, empty, empty, empty, empty]);
  const untagged = await runHttpAssessment(p, { env: {}, transport: su.transport, observerFactory: su.factory });
  assert.deepEqual([untagged.results[1].status, untagged.results[1].trace[1].data.effects[0].settlement], ['inconclusive', 'effect-outside-window']);
  validateHttpRunEvidence(untagged, { expectedSuite: suite });
  // Without correlation the request carries no header and the record stays /1.
  const plainProfile = scriptedProfile({ correlation: null, settlement: null, observers: [sinkObserver({ destinations: [{ host: PAY }] })] });
  const sp = scripted([empty, refund(null), empty, empty, empty]);
  const plainRun = await runHttpAssessment(plainProfile, { env: {}, transport: sp.transport, observerFactory: sp.factory });
  assert.ok(sp.headers.every(([, name]) => name === null));
  assert.deepEqual(Object.keys(plainRun.settlement), ['schema', 'settleMs', 'gaps']);
  assert.ok(!plainRun.limitations.some(l => l.startsWith('Correlation:')));
});

test('scripted tamper: a dropped barrier, an edited record or mode, a /1 relabel, a malformed token and a token of a row that was not sent are refused', async () => {
  const use = { id: 'USE-REFUND', title: 'Acts on the refund', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/refunds/{{refundId}}/note', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }],
    precondition: [{ name: 'refundId', type: 'id', createdBy: 'member' }], effects: [{ kind: 'effect.none', select: refundSel }] };
  const p = scriptedProfile({ extraChecks: [use] }), suite = createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
  const s = scripted([empty, refund('/refund'), empty, empty, empty, empty, empty]);
  const run = await runHttpAssessment(p, { env: {}, transport: s.transport, observerFactory: s.factory });
  const notSent = run.results.find(r => r.id === 'USE-REFUND');
  assert.equal(notSent.trace[0].data.transportOutcome, 'not-sent');
  validateHttpRunEvidence(run, { expectedSuite: suite });
  const edit = change => { const copy = structuredClone(run); change(copy); return copy; };
  const refused = (copy, detail, options) => assert.throws(() => validateHttpRunEvidence(copy, options), e => e.code === (detail === 'unexpected-suite-evidence' ? 'unexpected-suite-evidence' : 'invalid-run-evidence') && (detail === 'unexpected-suite-evidence' || e.detail === detail), detail);
  refused(edit(c => { c.settlement.barriers.pop(); }), 'settlement-record');
  refused(edit(c => { delete c.settlement.correlation; }), 'settlement-record');
  refused(edit(c => { c.settlement.schema = 'scopehaven-settlement/1'; }), 'settlement-record');
  refused(edit(c => { c.settlement.mode = 'run'; }), 'settlement-record');
  refused(edit(c => { c.settlement.correlation.recorded[0].observer = 'elsewhere'; }), 'settlement-correlation');
  refused(edit(c => { c.settlement.correlation.header = 'Authorization'; }), 'settlement-correlation');
  // Relabelled to run mode with the barriers dropped, or a recorded host the run did not declare: correlation releases
  // nothing, so these empty-barrier records recompute the same findings, and the suite (which pins the header, the recorded
  // pairs and the mode) refuses them.
  const relabelled = edit(c => { c.settlement.mode = 'run'; delete c.settlement.barriers; });
  refused(relabelled, 'unexpected-suite-evidence', { expectedSuite: suite });
  const moved = edit(c => { c.settlement.correlation.recorded[0].names = ['api.other.example']; });
  refused(moved, 'unexpected-suite-evidence', { expectedSuite: suite });
  // A barrier that decided something: NO-SEND's barrier window is partial, so its pass is withheld (settlement-unobserved).
  // Dropping the barriers to relabel the run changes that finding, and the stored verdict is refused without the suite.
  const partialBarrier = () => ({ events: [], coverage: 'partial' });
  const sb = scripted([empty, empty, empty, empty, empty, partialBarrier, empty]);
  const barred = await runHttpAssessment(p, { env: {}, transport: sb.transport, observerFactory: sb.factory });
  assert.deepEqual([barred.results[1].status, barred.results[1].trace[1].data.effects[0].settlement], ['inconclusive', 'settlement-unobserved']);
  validateHttpRunEvidence(barred, { expectedSuite: suite });
  const unbarred = structuredClone(barred); unbarred.settlement.mode = 'run'; delete unbarred.settlement.barriers;
  refused(unbarred, 'effect-verdict');
  // Events from a declared pair carry 32 lowercase hex or nothing; the token of a row that was not sent cannot occur.
  const refundEvent = c => c.results.find(r => r.id === 'REFUND-OWN').trace[1].data.windows[0].events[0];
  refused(edit(c => { refundEvent(c).correlation.settlementToken = 'NOT-A-TOKEN'; }), 'settlement-correlation');
  refused(edit(c => { refundEvent(c).correlation.settlementToken = notSent.trace[0].data.requestId.replace(/-/g, ''); }), 'settlement-correlation');
  // A token on an event from a pair that does not record one is refused (the recorder never writes it there).
  // The refund send carries its own token; once the record stops declaring its pair, that token is refused before any suite check.
  assert.match(refundEvent(run).correlation.settlementToken ?? '', /^[0-9a-f]{32}$/);
  refused(moved, 'settlement-correlation');
  refused(edit(c => { c.settlement.correlation.recorded[0].names = ['api.other.example']; delete refundEvent(c).correlation.settlementToken; }), 'unexpected-suite-evidence', { expectedSuite: suite });
});

// ---------------------------------------------------------------------------
// The owned practice app: the clean build, a deferred refusal whose webhook carries its own token (origin context)
// or the flushing request's (current context), and a build that forwards nothing.
const correlate = (header = 'traceparent', mode = 'per-check') => p => {
  p.correlation = { header };
  if (mode) p.settlement = { mode };
  p.observers[0].destinations[0].correlation = { header };
  return p;
};
const HOST_WIDE = { source: 'http-egress', operation: 'send', name: HOOK_HOST };
// BOB-DELETE-ADMIN-NOTE forbids any webhook at all, and ALICE-DELETE-OWN (her allowed delete) runs right after it.
const hostWide = p => {
  const k = p.checks.find(c => c.id === 'BOB-DELETE-ADMIN-NOTE'), own = p.checks.find(c => c.id === 'ALICE-DELETE-OWN');
  k.effects = [{ kind: 'effect.none', select: HOST_WIDE }];
  p.checks = p.checks.filter(c => c !== own);
  p.checks.splice(p.checks.indexOf(k) + 1, 0, own);
  return p;
};
const compose = (...edits) => p => edits.reduce((acc, f) => f(acc), p);
const suiteOf = (profile, env) => createRegistry({ profiles: [profile], env }).exportSuite(profile.id);
async function assess(t, build = {}, edit = p => p) {
  const [sinkPort] = await freePorts(1);
  const app = await createCorePracticeApp({ sinkPort, ...build }); t.after(() => app.close());
  const profile = edit(settlementProfile({ origin: app.origin, sinkPort }));
  return { app, profile, run: await runHttpAssessment(profile, { env: app.env }) };
}
const row = (run, id) => run.results.find(r => r.id === id);
const clause = (run, id, i = 0) => row(run, id).trace[1].data.effects[i];

for (const header of ['traceparent', 'x-request-id']) {
  test(`practice forbidden (${header}): a forwarded token does not release a host-wide prohibition before an allowed send; per-check reads as run-level settlement, and the validator and gate agree`, async t => {
    const { app, profile, run } = await assess(t, { forwardCorrelation: header }, compose(hostWide, correlate(header)));
    assert.deepEqual(run.counts, { pass: 13, fail: 0, inconclusive: 1, error: 0, not_applicable: 0 });
    assert.deepEqual([row(run, 'BOB-DELETE-ADMIN-NOTE').status, clause(run, 'BOB-DELETE-ADMIN-NOTE').settlement], ['inconclusive', 'effect-outside-window']);
    assert.deepEqual([row(run, 'ALICE-DELETE-OWN').status, clause(run, 'ALICE-DELETE-OWN').settlement], ['pass', 'effect-ambiguous-attribution']);
    const aliceSend = row(run, 'ALICE-DELETE-OWN').trace[1].data.windows[0].events[0];
    assert.equal(aliceSend.correlation.settlementToken, row(run, 'ALICE-DELETE-OWN').trace[0].data.requestId.replace(/-/g, ''));
    assert.equal(run.settlement.barriers.length, 4);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
    assert.equal(summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) }).exitCode, 1);
  });
  test(`practice allowed (${header}): with checks' effects pinned apart, the clean build passes every check under per-check correlation, and the validator and gate agree`, async t => {
    const { app, profile, run } = await assess(t, { forwardCorrelation: header }, correlate(header));
    assert.deepEqual(run.counts, { pass: 14, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 });
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
    assert.equal(summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) }).exitCode, 0);
  });
}

test('practice forbidden: without forwarding, or in run mode, the same clean build keeps today\'s withholding', async t => {
  const silent = await assess(t, { forwardCorrelation: false }, compose(hostWide, correlate()));
  assert.deepEqual([row(silent.run, 'BOB-DELETE-ADMIN-NOTE').status, clause(silent.run, 'BOB-DELETE-ADMIN-NOTE').settlement], ['inconclusive', 'effect-outside-window']);
  assert.deepEqual([row(silent.run, 'ALICE-DELETE-OWN').status, clause(silent.run, 'ALICE-DELETE-OWN').settlement], ['pass', 'effect-ambiguous-attribution']);
  validateHttpRunEvidence(silent.run, { expectedSuite: suiteOf(silent.profile, silent.app.env) });
  const runLevel = await assess(t, { forwardCorrelation: 'traceparent' }, compose(hostWide, correlate('traceparent', 'run')));
  assert.deepEqual([row(runLevel.run, 'BOB-DELETE-ADMIN-NOTE').status, clause(runLevel.run, 'BOB-DELETE-ADMIN-NOTE').settlement], ['inconclusive', 'effect-outside-window']);
  validateHttpRunEvidence(runLevel.run, { expectedSuite: suiteOf(runLevel.profile, runLevel.app.env) });
});

test('practice late send: a refused delete whose deferred webhook carries its own token is withheld, never failed on the token; a later check whose own absence it fits fails in its own window', async t => {
  const build = { refusedCommit: LATE_TRIGGERS['next-window'], forwardCorrelation: 'traceparent' };
  const { app, profile, run } = await assess(t, build, correlate());
  assert.equal(row(run, 'BOB-DELETE-ADMIN-NOTE').trace[1].data.windows[0].events.length, 0, 'nothing in its own window');
  assert.deepEqual([row(run, 'BOB-DELETE-ADMIN-NOTE').status, clause(run, 'BOB-DELETE-ADMIN-NOTE').settlement, clause(run, 'BOB-DELETE-ADMIN-NOTE').verdict], ['inconclusive', 'effect-correlated-late', 'inconclusive']);
  assert.match(row(run, 'BOB-DELETE-ADMIN-NOTE').assertions.find(a => a.name.startsWith('Observed effect')).actual, /effect-correlated-late/);
  assert.equal(row(run, 'BOB-DELETE-MEMBER-NOTE').status, 'pass', 'its exact route is not the late webhook');
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  const gate = summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) });
  assert.equal(gate.exitCode, 1);
  // Pinned to bob's prefix, the later check sees the late webhook in its own window and fails there, unchanged by settlement:
  // that fail rests on the observer's record in the check's own window, not on the token.
  const prefix = await assess(t, build, compose(correlate(), p => { p.checks.find(c => c.id === 'BOB-DELETE-MEMBER-NOTE').effects = [{ kind: 'effect.none', select: { ...HOST_WIDE, resource: { prefix: 'POST /hooks/bob/' } } }]; return p; }));
  assert.deepEqual([row(prefix.run, 'BOB-DELETE-ADMIN-NOTE').status, row(prefix.run, 'BOB-DELETE-MEMBER-NOTE').status, Object.hasOwn(clause(prefix.run, 'BOB-DELETE-MEMBER-NOTE'), 'settlement')], ['inconclusive', 'fail', false]);
  validateHttpRunEvidence(prefix.run);
});

test('practice stale token: a deferred webhook stamped with the flushing request\'s token never releases the refused check; an exact count that sees it fails', async t => {
  const stale = await assess(t, { refusedCommit: LATE_TRIGGERS['next-window'], forwardCorrelation: 'traceparent', correlationContext: 'current' }, correlate());
  assert.deepEqual([row(stale.run, 'BOB-DELETE-ADMIN-NOTE').status, clause(stale.run, 'BOB-DELETE-ADMIN-NOTE').settlement], ['inconclusive', 'effect-outside-window']);
  validateHttpRunEvidence(stale.run, { expectedSuite: suiteOf(stale.profile, stale.app.env) });
  // Flushed inside alice's allowed delete, whose host-wide exact count then sees two sends.
  const aliceCount = p => { p.checks.find(c => c.id === 'ALICE-DELETE-OWN').effects = [{ kind: 'effect.count', select: HOST_WIDE, expected: 1 }]; return p; };
  const counted = await assess(t, { refusedCommit: { method: 'POST', pathPrefix: '/api/notes/', user: 'alice', creatorRole: 'admin' }, forwardCorrelation: 'traceparent', correlationContext: 'current' }, compose(hostWide, aliceCount, correlate()));
  assert.equal(row(counted.run, 'ALICE-DELETE-OWN').status, 'fail');
  assert.deepEqual([row(counted.run, 'BOB-DELETE-ADMIN-NOTE').status, clause(counted.run, 'BOB-DELETE-ADMIN-NOTE').settlement], ['inconclusive', 'effect-outside-window']);
  validateHttpRunEvidence(counted.run, { expectedSuite: suiteOf(counted.profile, counted.app.env) });
});

// ---------------------------------------------------------------------------
// A rule that releases a withheld result needs positive,
// unambiguous evidence, and the token the application writes is never that evidence on its own. Correlation can only
// make settlement stricter: it never fails a pass and never releases what run-level settlement withholds.
test('a token never releases: an earlier absence that failed or was inconclusive keeps a later check\'s own-token send ambiguous', () => {
  const findings = rows => settlementFindings(rows, gapsFor(rows), perCheck(rows));
  const failed = [rowOf([none(A)], [win([ev(A, T(0))])]), rowOf([count(null, 1)], [win([ev(A, T(1))])])];
  assert.deepEqual(failed.map(r => r.effects[0].verdict), ['fail', 'pass']);
  assert.deepEqual(findings(failed), [[null], ['effect-ambiguous-attribution']]);
  // Not a pass: a partial window (missing), only a presence-only observer (unobservable), or a pass already withheld
  // (inconclusive, as custody, pairing or settlement leave it).
  const withheld = () => { const r = rowOf([none(A)], [win()]); r.effects[0] = { ...r.effects[0], verdict: 'inconclusive' }; return r; };
  for (const [verdict, first] of [['missing', () => rowOf([none(A)], [win([], 'partial')])], ['unobservable', () => rowOf([none(A)], [{ ...otherWin(), instanceId: INST }])], ['inconclusive', withheld]]) {
    const unsure = [first(), rowOf([count(null, 1)], [win([ev(A, T(1))])])];
    assert.deepEqual(unsure.map(r => r.effects[0].verdict), [verdict, 'pass']);
    assert.deepEqual(findings(unsure), [[null], ['effect-ambiguous-attribution']], verdict);
  }
  // Adjacent allowed: a later own-token send that fits no earlier selector is not ambiguous, and its count passes.
  const apart = [rowOf([none(A)], [win([ev(A, T(0))])]), rowOf([count(B, 1)], [win([ev(B, T(1))])])];
  assert.deepEqual(findings(apart), [[null], [null]]);
});

test('a token never releases: an earlier check with only a positive clause keeps a later own-token send ambiguous (a stale-stamped duplicate of its send)', () => {
  const findings = rows => settlementFindings(rows, gapsFor(rows), perCheck(rows));
  for (const first of [exists(A), count(A, 1)]) {
    const rows = [rowOf([first], [win([ev(A, T(0))])]), rowOf([count(null, 1)], [win([ev(A, T(1))])])];
    assert.deepEqual(rows.map(r => r.effects[0].verdict), ['pass', 'pass']);
    assert.equal(findings(rows)[1][0], 'effect-ambiguous-attribution', first.kind);
  }
});

test('a token never fails: a late send carrying a check\'s own token withholds its boundary pass and never fails it; a control only carries the tag', () => {
  const rows = [rowOf([none(A)], [win()]), rowOf([none(B)], [win()])];
  const gaps = [[win()], [win([ev(A, T(0))])], [win()]];
  assert.deepEqual(settlementFindings(rows, gaps, runMode)[0], ['effect-correlated-late']);
  const decided = decideEffects([none(A)], [win()]);
  const boundary = applySettlement(decided, ['effect-correlated-late'], 'boundary');
  assert.deepEqual([boundary[0].verdict, boundary[0].settlement], ['inconclusive', 'effect-correlated-late']);
  assert.ok(boundary[0].basis.endsWith(SETTLEMENT_BASIS['effect-correlated-late']));
  assert.doesNotMatch(SETTLEMENT_BASIS['effect-correlated-late'], /\bfails\b/);
  assert.deepEqual(applySettlement(decided, ['effect-correlated-late'], 'control')[0].verdict, 'pass');
  // Every settlement reason withholds a boundary pass; none fails it, and a fail or inconclusive is never touched.
  for (const reason of SETTLEMENT_REASONS) assert.equal(applySettlement(decided, [reason], 'boundary')[0].verdict, 'inconclusive', reason);
  const failedClause = decideEffects([none(A)], [win([ev(A)])]);
  for (const reason of SETTLEMENT_REASONS) assert.deepEqual(applySettlement(failedClause, [reason], 'boundary'), failedClause, reason);
});

test('a token never releases: a later check\'s exact count over its own-token send never releases an earlier absence', () => {
  const findings = rows => settlementFindings(rows, gapsFor(rows), perCheck(rows));
  const rows = [rowOf([none()], [win()]), rowOf([count(null, 1)], [win([ev(B, T(1))])])];
  assert.deepEqual(findings(rows), [['effect-outside-window'], ['effect-ambiguous-attribution']]);
  const chain = [rowOf([none()], [win()]), rowOf([count(null, 1)], [win([ev(B, T(1))])]), rowOf([count(null, 1)], [win([ev(A, T(2))])])];
  assert.deepEqual(findings(chain).map(r => r[0]), ['effect-outside-window', 'effect-outside-window', 'effect-ambiguous-attribution']);
  // Adjacent allowed: with nothing after it, a per-check absence pass stays a pass; so does the later count on its own selector.
  const quiet = [rowOf([none(A)], [win()]), rowOf([count(B, 1)], [win([ev(B, T(1))])])];
  assert.deepEqual(findings(quiet), [[null], [null]]);
});

// Over generated rows, clauses, events (own, later, earlier, other-row, unknown and missing tokens; declared and
// undeclared observers) and coverage, in run mode and per check (barriers with events too): every clause that run-level
// settlement withholds is withheld, and correlation never turns a finding into a fail.
test('property: correlated settlement is never more permissive than run-level settlement', () => {
  // mulberry32 (exact 32-bit integer steps), so every draw uses well-mixed bits.
  let state = 20261010;
  const rand = n => { state = (state + 0x6d2b79f5) | 0; let t = Math.imul(state ^ (state >>> 15), 1 | state); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return (((t ^ (t >>> 14)) >>> 0) % n); };
  const seen = new Map();
  const resources = [A, B, 'POST /hooks/carol/member'];
  const tokenPool = [undefined, T(0), T(1), T(2), OTHER, STRANGER];
  const clauses = [() => none(resources[rand(3)]), () => none(), () => exists(), () => exists(resources[rand(3)]), () => count(resources[rand(3)], 1 + rand(2)), () => count(null, 1), () => count(null, 0), () => only(resources[rand(3)]), () => only(null, [sel(resources[rand(3)])])];
  const events = () => Array.from({ length: rand(4) }, () => ev(resources[rand(3)], tokenPool[rand(tokenPool.length)]));
  const window = () => win(events(), ['complete', 'complete', 'complete', 'partial'][rand(4)]);
  const windows = () => rand(3) === 0 ? [window(), { ...otherWin(), scope: SINK, events: events() }] : [window()];
  for (let trial = 0; trial < 600; trial++) {
    const rows = Array.from({ length: 1 + rand(3) }, () => rowOf(Array.from({ length: 1 + rand(2) }, () => clauses[rand(clauses.length)]()), windows(), rand(4) === 0 ? 'control' : 'boundary'));
    const gaps = Array.from({ length: rows.length + 1 }, () => windows());
    const barriers = rows.map(() => windows());
    const legacy = settlementFindings(rows, gaps);
    const both = new Set([...declared, `${OTHER_INST}\n${HOOK_HOST}`]);
    for (const [label, correlation] of [['run', runMode], ['run, both declared', { ...runMode, declared: both }], ['per check', perCheck(rows, { barriers })], ['per check, clean barriers', perCheck(rows)]]) {
      const found = settlementFindings(rows, gaps, correlation);
      found.forEach((clauseFindings, k) => clauseFindings.forEach((reason, c) => {
        if (rows[k].effects[c].verdict === 'pass') seen.set(`${label}: ${legacy[k][c]} -> ${reason}`, (seen.get(`${label}: ${legacy[k][c]} -> ${reason}`) ?? 0) + 1);
        if (legacy[k][c] !== null) assert.notEqual(reason, null, `${label}, trial ${trial}, row ${k}, clause ${c}: run level withholds (${legacy[k][c]})`);
        if (reason !== null) assert.notEqual(applySettlement(rows[k].effects, clauseFindings, 'boundary')[c].verdict, 'fail', `${label}, trial ${trial}: ${reason}`);
      }));
    }
  }
  // Not vacuous: the generator reaches every correlated reason, and the cases earlier, more permissive rules decided.
  const reached = [...seen.keys()].join('\n');
  for (const reason of ['effect-correlated-late', 'effect-correlated-late-unsettled', 'effect-correlated-elsewhere']) assert.match(reached, new RegExp(`per check: [a-z-]+ -> ${reason}$`, 'm'), reason);
  assert.match(reached, /^per check: effect-outside-window -> effect-outside-window$/m);
  assert.match(reached, /^per check: effect-ambiguous-attribution -> effect-ambiguous-attribution$/m);
  assert.match(reached, /^per check: null -> null$/m);
});

test('late own-token events read out of time order (a later barrier before a gap) or repeated in two windows are judged without throwing, and withhold', () => {
  // An effect.only clause is judged again over its windows plus its late own-token events (only.mjs validates seq order).
  const onlyFirst = () => rowOf([only(B)], [win([ev(B, T(0))])]);
  // later(0) reads B(0), row 1's window, B(1), then the gaps: B(1)'s event (higher seq) comes before the gap's (lower seq).
  const rows = [onlyFirst(), rowOf([none(B)], [win()])];
  const early = ev(A, T(0)), lateInBarrier = ev(A, T(0));
  assert.equal(rows[0].effects[0].verdict, 'pass');
  const gaps = [[win()], [win([early])], [win()]];
  assert.deepEqual(settlementFindings(rows, gaps, perCheck(rows, { barriers: [[win()], [win([lateInBarrier])]] }))[0], ['effect-correlated-late']);
  // The same event object in B(0) and in row 1's window is counted once.
  const first = onlyFirst(), shared = ev(A, T(0)), twice = [first, rowOf([none(B)], [win([shared])])];
  assert.deepEqual(settlementFindings(twice, gapsFor(twice), perCheck(twice, { barriers: [[win([shared])], [win()]] }))[0], ['effect-correlated-late']);
  // A late event whose seq is not after the clause's own window (no observer records that) cannot form a valid window: the
  // clause is still withheld, under the other name.
  const stale = ev(A, T(0)), recent = onlyFirst(), backwards = [recent, rowOf([none(B)], [win()])];
  assert.deepEqual(settlementFindings(backwards, [[win()], [win([stale])], [win()]], perCheck(backwards))[0], ['effect-correlated-late-unsettled']);
  // Adjacent allowed: a send carrying row 1's token in the gap before row 1's window is not after that window, so it is not
  // late for row 1 (and fits nothing of row 0): both passes stand, in run mode and per check.
  const before = [rowOf([none(A)], [win()]), rowOf([none(B)], [win()])];
  const early1 = [[win()], [win([ev(B, T(1))])], [win()]];
  assert.deepEqual(settlementFindings(before, early1, runMode), [[null], [null]]);
  assert.deepEqual(settlementFindings(before, early1, perCheck(before)), [[null], [null]]);
  // Adjacent: a passed count of 1 whose own late send would make it 2 is named late and withheld, not failed.
  const one = [rowOf([count(A, 1)], [win([ev(A, T(0))])])];
  const found = settlementFindings(one, [[win()], [win([ev(A, T(0))])]], runMode);
  assert.deepEqual(found, [['effect-correlated-late']]);
  assert.equal(applySettlement(one[0].effects, found[0], 'boundary')[0].verdict, 'inconclusive');
});

// ---------------------------------------------------------------------------
// The token the application forwards is its own value, so it is stored in
// event.correlation.settlementToken, which no selector or pairing pin reads. A traceId-pinned clause reads the same with
// or without it, pairing never releases a withheld absence on it, and a correlated target refuses a traceId selector an
// egress recorder could see. APP is a well-formed value the application chose (derived, never a connector token).
const APP = [...T(5)].reverse().join('').replace(/^./, 'e');
test('forbidden (pairing): an app-forwarded value never shows a traceId pin, so a withheld absence stays withheld', () => {
  const pinned = { ...sel(), traceId: APP };
  const target = { actors: { member: { principalId: 'member-1' } }, checks: [
    { id: 'CTRL', severity: 'control', actorId: 'member', effects: [{ kind: 'effect.exists', select: pinned }] },
    { id: 'BND', severity: 'high', actorId: 'member', effects: [{ kind: 'effect.none', select: pinned }] },
  ] };
  const pairs = selectorPairs(target);
  assert.deepEqual(pairs.get('BND')?.[0]?.pins?.traceId?.map(t => t.checkId), ['CTRL'], 'the control is the twin of the trace id pin');
  // The app forwards APP on the control's send; the boundary's real send carries no value.
  for (const [why, ctrlEvents] of [['the app forwards its own value', [ev('POST /hooks/x', APP)]], ['no value at all', [ev('POST /hooks/x')]]]) {
    const ctrlWindows = [win(ctrlEvents)], bndWindows = [win([ev('POST /hooks/y')])];
    const ctrl = { id: 'CTRL', actorId: 'member', role: 'control', effects: decideEffects([{ kind: 'effect.exists', select: pinned }], ctrlWindows, { role: 'control' }), windows: ctrlWindows };
    const bnd = { id: 'BND', actorId: 'member', role: 'boundary', effects: decideEffects([{ kind: 'effect.none', select: pinned }], bndWindows, { role: 'boundary' }), windows: bndWindows };
    assert.equal(ctrl.effects[0].verdict, 'fail', `${why}: the control's pinned exists is not passed by the value`);
    assert.equal(bnd.effects[0].verdict, 'pass', `${why}: the pinned absence selects nothing (decided, vacuous)`);
    assert.deepEqual(pairingFindings([ctrl, bnd], pairs), [[null], ['selector-not-shown-to-match']], `${why}: the vacuous absence stays withheld`);
  }
  // The value never fails a pinned absence either: the same boundary send carrying APP leaves the clause a (withheld) pass.
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: pinned }, [win([ev('POST /hooks/y', APP)])]).verdict, 'pass');
  // Allowed, adjacent: an unpinned control that matched a committed send in the deciding observer still shows a resource pin.
  const resPinned = sel(A), rt = { actors: target.actors, checks: [
    { id: 'CTRL', severity: 'control', actorId: 'member', effects: [{ kind: 'effect.exists', select: resPinned }] },
    { id: 'BND', severity: 'high', actorId: 'member', effects: [{ kind: 'effect.none', select: resPinned }] },
  ] };
  const cw = [win([ev(A, APP)])], bw = [win([ev(B)])];
  const rows = [{ id: 'CTRL', actorId: 'member', role: 'control', effects: decideEffects([{ kind: 'effect.exists', select: resPinned }], cw, { role: 'control' }), windows: cw },
    { id: 'BND', actorId: 'member', role: 'boundary', effects: decideEffects([{ kind: 'effect.none', select: resPinned }], bw, { role: 'boundary' }), windows: bw }];
  assert.deepEqual(pairingFindings(rows, selectorPairs(rt)), [[null], [null]]);
});
test('forbidden (selectors): a traceId pin reads the same with or without the app value, in settlement too', () => {
  const pinned = { ...sel(), traceId: APP };
  for (const kind of ['effect.exists', 'effect.count']) {
    const clause = kind === 'effect.count' ? { kind, select: pinned, expected: 1 } : { kind, select: pinned };
    assert.equal(evaluateEffectAssertion(clause, [win([ev(A, APP)])]).verdict, evaluateEffectAssertion(clause, [win([ev(A)])]).verdict, kind);
    assert.equal(evaluateEffectAssertion(clause, [win([ev(A, APP)])]).verdict, 'fail', kind);
  }
  // A token-carrying event is still read by settlement (by its own key): an own-token late send withholds the absence pass.
  const rows = [rowOf([none()], [win()]), rowOf([none(B)], [win()])];
  rows[1].windows = [win([ev(A, T(0))])];
  assert.equal(settlementFindings(rows, gapsFor(rows), runMode)[0][0], 'effect-correlated-late');
});
test('forbidden (contract): a correlated target refuses a traceId selector an egress recorder could see; the same clause without correlation is accepted', () => {
  const traced = (select, kind = 'effect.none') => ({ id: 'TRACED', title: 'Traced', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/traced', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }],
    effects: [kind === 'effect.only' ? { kind, allow: [select], sources: ['http-egress'] } : { kind, select }] });
  const egressSel = { ...refundSel, traceId: APP }, noSource = { operation: 'send', name: PAY, traceId: APP };
  for (const [why, check] of [['source http-egress', traced(egressSel)], ['no source', traced(noSource)], ['exists', traced(egressSel, 'effect.exists')], ['effect.only allow', traced(egressSel, 'effect.only')]]) {
    invalid(scriptedProfile({ extraChecks: [check] }), /correlation-token-not-selectable/);
    invalid(scriptedProfile({ settlement: { mode: 'run' }, extraChecks: [check] }), /correlation-token-not-selectable/);
    assert.ok(why);
  }
  // Allowed, adjacent: the same clause on a target without correlation (it selects nothing there, and pairing withholds it).
  const plainObserver = sinkObserver({ destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/coupons'] }] });
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [scriptedProfile({ correlation: null, settlement: null, observers: [plainObserver], extraChecks: [traced(egressSel)] })] }));
  // And a correlated target without a traceId selector is accepted (profile validation above).
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [scriptedProfile()] }));
});

test('exported text matches the code: a late own-token send withholds an absence clause only when it fits that clause; one that fits none withholds nothing on its token', () => {
  // An effect.none on A passed in its own window; the tail holds one committed send to B carrying T(0).
  for (const [label, opts] of [['run mode', () => runMode], ['per check', r => perCheck(r)]]) {
    const apart = [rowOf([none(A)], [win()])];
    assert.equal(apart[0].effects[0].verdict, 'pass');
    assert.deepEqual(settlementFindings(apart, [[win()], [win([ev(B, T(0))])]], opts(apart)), [[null]], `${label}: own token, outside the clause`);
    // Adjacent: the same own-token send to the resource the clause names withholds it.
    const fits = [rowOf([none(A)], [win()])];
    assert.deepEqual(settlementFindings(fits, [[win()], [win([ev(A, T(0))])]], opts(fits)), [['effect-correlated-late']], `${label}: own token, fits the clause`);
    // A count on B: an own-token late send to A is outside it; one to B fits it.
    const counted = () => [rowOf([count(B, 1)], [win([ev(B, T(0))])])];
    assert.deepEqual(settlementFindings(counted(), [[win()], [win([ev(A, T(0))])]], opts(counted())), [[null]], `${label}: count, outside`);
    assert.deepEqual(settlementFindings(counted(), [[win()], [win([ev(B, T(0))])]], opts(counted())), [['effect-correlated-late']], `${label}: count, fits`);
  }
  // effect-correlated-elsewhere as worded: every matching send of an exists, any counted send of a count.
  assert.deepEqual(settlementFindings([rowOf([exists()], [win([ev(B, OTHER), ev(B, T(0))])])], [[win()], [win()]], runMode), [[null]]);
  assert.deepEqual(settlementFindings([rowOf([exists()], [win([ev(B, OTHER)])])], [[win()], [win()]], runMode), [['effect-correlated-elsewhere']]);
  assert.deepEqual(settlementFindings([rowOf([count(null, 2)], [win([ev(B, T(0)), ev(B, OTHER)])])], [[win()], [win()]], runMode), [['effect-correlated-elsewhere']]);
  for (const mode of ['run', 'per-check']) {
    const text = correlationLimitation({ header: 'traceparent', mode });
    assert.ok(text.includes("A send carrying a check's own token after its window withholds that check's absence clause only when the send fits that clause"), mode);
    assert.ok(text.includes("A late send carrying the check's own token that fits none of its absence clauses withholds nothing on its token."), mode);
    assert.ok(text.includes("An effect.exists pass whose every matching send carries another check's token, or an effect.count pass any of whose counted sends does, is withheld (effect-correlated-elsewhere)."), mode);
    assert.ok(!text.includes("withholds that check's absence clause (effect-correlated-late"), `${mode}: the unqualified sentence is gone`);
    assert.ok(!text.includes('a pass resting on another check'), `${mode}: the loose elsewhere sentence is gone`);
    assert.ok(!/[\u2013\u2014]/.test(text), `${mode}: no en or em dash`);
  }
});
