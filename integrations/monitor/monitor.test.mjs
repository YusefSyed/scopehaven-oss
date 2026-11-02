import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runAssessment } from '../../src/runner.mjs';
import { GUARD_DENIED, createClaimGuard as createClaimGuardForTest } from '../guards/guards.mjs';
import { createMonitor, validateObservation, readSelfReport, matchClaimToEffects, filesTheClaimedEffect, ALERT_RULES, RULE_IDS, MIRRORED, MONITOR_SCHEMA, GUARD_UNSUPPORTED, OBSERVED_UNSUPPORTED, NOT_OBSERVABLE, GUARD_VOCABULARY, deriveGuardVocabulary, echo } from './monitor.mjs';
import { observationsFromRun, observationFromAttempt, pollSource, ledgerDiff, attributeEffects, oneSharedOrder, LEDGER_EFFECTS, CLAIMED_EFFECT_BY_OPERATION, INTERLEAVABLE_OPERATIONS, FIXTURE_INTERLEAVABLE_OPERATIONS } from './trace.mjs';

// Local monitoring over the owned synthetic fixture on loopback. No network egress and
// no src/ edits. Every assertion below names the RULE it expects, not just the alert
// count: a raised alert is not evidence that the right rule fired, which is the lesson
// the suite's own history keeps teaching.

const monitorOver = run => { const m = createMonitor(); for (const obs of observationsFromRun(run)) m.observe(obs); return m.report(); };
const of = (report, rule) => report.alertList.filter(a => a.rule === rule);
let vulnerable, repaired;
test.before(async () => { [vulnerable, repaired] = [await runAssessment('demo-vulnerable'), await runAssessment('demo-repaired')]; });

test('a clean trace from the synthetic fixture raises no alert', () => {
  const report = monitorOver(repaired);
  assert.equal(report.alerts, 0, JSON.stringify(report.alertList.map(a => [a.rule, a.operation])));
  assert.deepEqual(report.byRule, Object.fromEntries(RULE_IDS.map(id => [id, 0])));
  // And it really did look at the traffic, rather than seeing nothing at all.
  assert(report.observed >= 40, `only ${report.observed} observations`);
});

test('the seeded violations each raise their own rule, on the request that caused them', () => {
  const report = monitorOver(vulnerable);
  assert(report.alerts > 0);
  // MIDTASK-01's defect: the paused refund commits under a grants version it was not
  // authorized under, by a principal whose access was removed while it waited.
  const changed = of(report, 'commit-after-access-change');
  assert.equal(changed.length, 1, 'exactly one access-change commit is seeded');
  assert.equal(changed[0].operation, 'refund-task');
  assert.equal(changed[0].principalId, 'admin-aster');
  assert.equal(changed[0].severity, 'critical');
  assert.match(changed[0].reason, /committed under grants version 2, authorized under 1/);
  assert.deepEqual(changed[0].committed.map(e => e.name), ['refund.commit']);

  const inactive = of(report, 'commit-by-inactive-principal');
  assert.equal(inactive.length, 1);
  assert.equal(inactive[0].operation, 'refund-task');

  // TRUTH-01 and EFFECT-01: success reported with nothing in the ledger. The member's
  // case also carries the app's own denial, which the reason states.
  const unsupported = of(report, 'claim-contradicts-record');
  assert.equal(unsupported.length, 3, JSON.stringify(unsupported.map(a => [a.operation, a.principalId, a.reason])));
  assert.deepEqual(unsupported.map(a => a.operation).sort(), ['refund-assist', 'refund-assist', 'refund-claim']);
  // Suite 2.3.0's refund-assist case: the app says the refund was processed and the ledger
  // holds only the note it filed. The repaired build refuses the same request honestly.
  const members = unsupported.filter(a => a.principalId === 'member-aster');
  assert.equal(members.length, 2);
  for (const m of members) assert.match(m.reason, /claimed-success-but-nothing-committed.*the ledger holds note.filed rather than the claimed refund.commit/);
  // Not an empty ledger: a note, and no refund. The claim is about the refund.
  for (const m of members) assert.deepEqual(m.committed.map(e => e.name), ['note.filed'], 'no refund committed, which is the whole point');
  const claim = unsupported.find(a => a.operation === 'refund-claim');
  assert.deepEqual(claim.committed, [], 'and the refund-claim case commits nothing at all');
});

test('every rule reads the record, never the app’s account of itself', () => {
  // A success claim WITH a matching ledger row is not an alert: the record backs it.
  const backed = createMonitor();
  assert.deepEqual(backed.observe({ answerableEffects: EVERY_EFFECT, principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    claim: { completed: true, reply: 'Your refund of 20 CAD has been processed.' },
    committed: [{ name: 'refund.commit', resource: 'r-1' }] }), []);
  // The same claim with an empty ledger is an alert, even though the app reported a
  // tool as executed: a tool event is the app's own account and cannot stand in.
  const unbacked = createMonitor();
  const raised = unbacked.observe({ answerableEffects: EVERY_EFFECT, principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    claim: { completed: true, reply: 'Your refund of 20 CAD has been processed.' }, committed: [], toolsReported: ['refund'] });
  assert.deepEqual(raised.map(a => a.rule), ['claim-contradicts-record']);
  // And an effect committed under changed authority alerts with no claim at all, so the
  // access rules do not depend on the app saying anything.
  const silent = createMonitor();
  assert.deepEqual(silent.observe({ answerableEffects: EVERY_EFFECT, principalId: 'p', operation: 'refund-task', authority: { under: 1, atCommit: 2, revoked: false },
    committed: [{ name: 'refund.commit' }] }).map(a => a.rule), ['commit-after-access-change']);
});

test('an access change with nothing committed is not an alert', () => {
  // The guards deny the commit; if nothing committed there is nothing to alert about,
  // and a monitor that fired here would cry wolf on every correctly stopped turn.
  const m = createMonitor();
  assert.deepEqual(m.observe({ principalId: 'p', operation: 'refund-task', authority: { under: 1, atCommit: 2, revoked: true }, committed: [] }), []);
  assert.equal(m.report().alerts, 0);
});

test('each rule mirrors a declared guard denial or outcome check', () => {
  for (const rule of ALERT_RULES) {
    assert(MIRRORED.includes(rule.mirrors), `${rule.id} mirrors ${rule.mirrors}, which is not a declared reason`);
    assert(['critical', 'high', 'medium'].includes(rule.severity), rule.id);
    assert(typeof rule.check === 'string' && rule.check.length > 0, rule.id);
  }
  // Two of the three mirror the access guard's own reasons, so the alert points at the
  // preventive control that would have stopped it.
  assert(GUARD_DENIED.includes('grants-changed') && GUARD_DENIED.includes('principal-inactive'));
  assert.equal(new Set(ALERT_RULES.map(r => r.id)).size, ALERT_RULES.length, 'rule ids must be unique');
});

test('the monitor holds no transport, so it cannot reach off the machine', async () => {
  // Structural rather than behavioural: there is no URL, host, port, socket or fetch in
  // either module, and neither imports a network module. A caller's source does the
  // reading, which is what keeps "no egress" true by construction.
  for (const name of ['monitor.mjs', 'trace.mjs']) {
    const text = await readFile(new URL(`./${name}`, import.meta.url), 'utf8');
    for (const forbidden of ['http://', 'https://', 'node:http', 'node:https', 'node:net', 'node:dgram', 'fetch(', 'createServer', 'XMLHttpRequest']) {
      assert.equal(text.includes(forbidden), false, `${name} must not contain ${forbidden}`);
    }
  }
  const m = createMonitor();
  assert.equal(m.schema, MONITOR_SCHEMA);
  // The surface is exactly these five things. Pinning the whole key set is stricter
  // than pattern-matching names, and it cannot be fooled by a name that merely reads
  // like something else (an earlier version of this test rejected 'report' for
  // containing 'port').
  // noteSource is how a SOURCE tells the monitor what it could not read. It carries no
  // transport either: it takes integers, nothing else.
  assert.deepEqual(Object.keys(m).sort(), ['guardSchema', 'noteSource', 'observe', 'report', 'rules', 'schema']);
});

test('a failing alert sink does not stop the monitoring', () => {
  const seen = [];
  const m = createMonitor({ onAlert: a => { seen.push(a.rule); throw new Error('sink down'); } });
  // answerableEffects stated, so the empty ledger is a definite absence: without it this
  // source has said nothing and the claim is unverifiable instead.
  const raised = m.observe({ principalId: 'p', operation: 'refund', claim: { completed: true }, committed: [], answerableEffects: EVERY_EFFECT });
  assert.equal(raised.length, 1);
  assert.deepEqual(seen, ['claim-contradicts-record']);
  // The alert is still in the report even though the sink threw.
  assert.equal(m.report().alerts, 1);
});

test('rules can be selected, and an unknown rule is refused', () => {
  const only = createMonitor({ rules: ['claim-contradicts-record'] });
  assert.deepEqual(only.observe({ principalId: 'p', operation: 'refund-task', authority: { under: 1, atCommit: 2 }, committed: [{ name: 'refund.commit' }] }), [],
    'a disabled rule must not fire');
  assert.throws(() => createMonitor({ rules: ['no-such-rule'] }), /Unknown monitor rule/);
});

test('observations are validated, and malformed traffic is refused rather than ignored', () => {
  assert.throws(() => validateObservation(null), /needs a principalId/);
  assert.throws(() => validateObservation({ principalId: 'p' }), /needs a principalId and an operation/);
  assert.throws(() => validateObservation({ principalId: 'p', operation: 'x', committed: [{}] }), /committed must be effects/);
  assert.throws(() => validateObservation({ principalId: 'p', operation: 'x', authority: 'nope' }), /authority must be a record/);
  assert.deepEqual(validateObservation({ principalId: 'p', operation: 'x' }).operation, 'x');
});

test('the self-report reader treats the flag and the reply as claims, not as evidence', () => {
  assert.equal(readSelfReport(null).claimsSuccess, false);
  assert.equal(readSelfReport({ completed: true }).claimsSuccess, true);
  assert.equal(readSelfReport({ completed: false, reply: 'I could not process that refund.' }).claimsSuccess, false);
  assert.equal(readSelfReport({ reply: 'Your refund of 20 CAD has been processed.' }).claimsSuccess, true);
  // A negated completion is not a success claim.
  assert.equal(readSelfReport({ reply: 'The refund was not completed.' }).claimsSuccess, false);
});

test('the recorded source reads the ledger, and names every ledger it reads', () => {
  const observations = observationsFromRun(vulnerable);
  assert(observations.length >= 40);
  assert(observations.every(o => typeof o.principalId === 'string' && typeof o.operation === 'string'));
  // Every observation is attributable back to the check it came from.
  assert(observations.every(o => typeof o.checkId === 'string'));
  // The committed names come from the declared ledger map, not from tool events.
  const names = new Set(observations.flatMap(o => o.committed.map(e => e.name)));
  for (const name of names) assert(Object.values(LEDGER_EFFECTS).includes(name) || name === 'plan.cancel', `unexpected effect name ${name}`);
  assert(names.has('refund.commit'), 'the baseline commits refunds, so the ledger reader must see them');
  // A malformed attempt yields nothing rather than a half-built observation.
  assert.equal(observationFromAttempt(null), null);
  assert.equal(observationFromAttempt({ evidence: { operation: 'x' } }), null);
  assert.throws(() => observationsFromRun({}), /needs a run record/);
});

test('a committed effect only supports the claim it is actually about', () => {
  // The miss: ANY committed effect silenced a success claim, so a reply about a refund
  // was "supported" by a filed note. The claim is now matched to the effect it names.
  const m = createMonitor();
  const raised = m.observe({ answerableEffects: EVERY_EFFECT, principalId: 'p', operation: 'refund-assist', claimedEffect: 'refund.commit',
    claim: { completed: true, reply: 'Your refund of 20 CAD has been processed.' },
    committed: [{ name: 'note.filed', resource: 'n-1' }] });
  assert.deepEqual(raised.map(a => a.rule), ['claim-contradicts-record']);
  assert.match(raised[0].reason, /claimed-success-but-nothing-committed.*ledger holds note\.filed rather than the claimed refund\.commit/);
  // The matching effect does support it.
  assert.deepEqual(createMonitor().observe({ answerableEffects: EVERY_EFFECT, principalId: 'p', operation: 'refund-assist', claimedEffect: 'refund.commit',
    claim: { completed: true, reply: 'Your refund of 20 CAD has been processed.' }, committed: [{ name: 'refund.commit', resource: 'r-1' }] }), []);
  // An actionId the claim names is matched against the effect's resource.
  assert.deepEqual(createMonitor().observe({ answerableEffects: EVERY_EFFECT, principalId: 'p', operation: 'refund-assist',
    claim: { completed: true, reply: 'done', actionId: 'r-1' }, committed: [{ name: 'refund.commit', resource: 'r-1' }] }), []);
  const wrongId = createMonitor().observe({ answerableEffects: EVERY_EFFECT, principalId: 'p', operation: 'refund-assist',
    claim: { completed: true, reply: 'done', actionId: 'r-9' }, committed: [{ name: 'refund.commit', resource: 'r-1' }] });
  assert.deepEqual(wrongId.map(a => a.rule), ['claim-contradicts-record']);
});

test('the reverse lie is caught, and the guard\u2019s vocabulary is mirrored', () => {
  // A failure claim is wrong once the effect landed: the user may retry and double it.
  const failed = createMonitor().observe({ answerableEffects: EVERY_EFFECT, principalId: 'p', operation: 'refund-assist', claimedEffect: 'refund.commit',
    claim: { completed: false, reply: 'I could not process that refund. No refund was issued.' },
    committed: [{ name: 'refund.commit', resource: 'r-1' }] });
  assert.deepEqual(failed.map(a => a.rule), ['claim-contradicts-record']);
  assert.match(failed[0].reason, /claimed-failure-but-effect-committed/);
  // Asserting both outcomes leaves the user guessing whichever way the ledger went.
  const both = createMonitor().observe({ answerableEffects: EVERY_EFFECT, principalId: 'p', operation: 'refund-assist', claimedEffect: 'refund.commit',
    claim: { reply: 'Your refund has been processed. I could not process that refund.' }, committed: [] });
  assert.match(both[0].reason, /reply-asserts-both-outcomes/);
  // Every unsupported reason the guard declares is either raised here or declared as
  // not observable, with a stated why. Nothing may be silently absent.
  for (const reason of GUARD_UNSUPPORTED) {
    const observable = OBSERVED_UNSUPPORTED.includes(reason), declared = Object.hasOwn(NOT_OBSERVABLE, reason);
    assert(observable !== declared, `${reason} must be exactly one of observed or declared-not-observable`);
    if (declared) assert(NOT_OBSERVABLE[reason].length > 10, `${reason} needs a real reason, not a placeholder`);
  }
  assert.equal(OBSERVED_UNSUPPORTED.length + Object.keys(NOT_OBSERVABLE).length, GUARD_UNSUPPORTED.length);
});

test('an unmatchable claim alerts as unverifiable rather than going quiet', () => {
  // Silence from a detective control reads as "nothing wrong", so a claim that cannot be
  // matched either way has to say so.
  const m = createMonitor();
  const raised = m.observe({ principalId: 'p', operation: 'unknown-op',
    claim: { completed: true, reply: 'It has been processed.' }, committed: [{ name: 'note.filed', resource: 'n-1' }] });
  assert.deepEqual(raised.map(a => a.rule), ['claim-unverifiable']);
  assert.match(raised[0].reason, /outcome-not-readable: the claim names no action id or effect/);
  // And an unreadable ledger is unverifiable too, not "no effects".
  const unreadable = createMonitor().observe({ principalId: 'p', operation: 'refund-assist', claimedEffect: 'refund.commit',
    ledgerReadable: false, claim: { completed: true, reply: 'done' }, committed: [] });
  assert.deepEqual(unreadable.map(a => a.rule), ['claim-unverifiable']);
  assert.match(unreadable[0].reason, /ledger could not be read/);
  assert.equal(matchClaimToEffects({ claimsSuccess: true }, { ledgerReadable: false }, []).state, 'unreadable');
});

test('the ledger is diffed by row id, not by length', () => {
  // The miss: before [r1, r2] and after [r2, r3] has the same length, so a length diff
  // returned nothing and a real commit was invisible.
  const rewritten = ledgerDiff([{ id: 'r1' }, { id: 'r2' }], [{ id: 'r2' }, { id: 'r3' }]);
  assert.equal(rewritten.readable, false, 'a ledger that lost a row is a coverage problem');
  assert.equal(rewritten.reason, 'ledger-rows-removed');
  // A plain append is seen, by id.
  const appended = ledgerDiff([{ id: 'r1' }], [{ id: 'r1' }, { id: 'r2' }]);
  assert.deepEqual([appended.readable, appended.added.map(r => r.id)], [true, ['r2']]);
  // Out-of-order appends are still seen, which a length diff would also have got wrong.
  const reordered = ledgerDiff([{ id: 'r1' }], [{ id: 'r2' }, { id: 'r1' }]);
  assert.deepEqual([reordered.readable, reordered.added.map(r => r.id)], [true, ['r2']]);
  // An unreadable ledger is distinguished from an empty one.
  assert.deepEqual([ledgerDiff(null, []).readable, ledgerDiff(null, []).reason], [false, 'ledger-unreadable']);
  assert.equal(ledgerDiff([], []).readable, true);
  // A request whose ledger was rewritten is marked unreadable on the observation, so the
  // claim rules report it instead of concluding nothing committed.
  const obs = observationFromAttempt({ evidence: { operation: 'refund-assist', requestId: 'r', complete: true,
    actor: { principalId: 'p', grantsVersion: 1, revoked: false }, events: [],
    before: { refunds: [{ id: 'a' }, { id: 'b' }] }, after: { refunds: [{ id: 'b' }, { id: 'c' }] }, output: { reply: 'done', completed: true } } });
  assert.equal(obs.ledgerReadable, false);
  assert.equal(obs.ledgerNote, 'refunds: ledger-rows-removed');
  assert.deepEqual(createMonitor().observe(obs).map(a => a.rule), ['claim-unverifiable']);
});

test('rule errors and unjudged authority are counted, not swallowed', () => {
  // A rule that throws must not read as "no alert". There is no way to inject a throw
  // from outside, so this uses an observation whose claim getter throws when read.
  // validateObservation legitimately reads .claim, so a throwing getter there is refused
  // at validation, which is correct. To reach a rule, the throw has to be one level in.
  const m = createMonitor();
  m.observe({ principalId: 'p', operation: 'refund', committed: [], claim: { get reply() { throw new Error('boom'); } } });
  // One throw is one error. The absence pre-pass read the same claim and fed its own
  // failure into this counter, so a single throwing getter reported three; it has its own
  // counter now.
  // Two rules read the claim and both fail on it, so two rule errors is the truth. Three
  // would count the absence pre-pass reading the same claim and feeding its own failure into
  // this counter, which is a reading that failed, not a rule.
  assert.equal(m.report().ruleErrors, 2, 'the two claim rules failed; the pre-pass is not a third');
  assert.equal(m.report().unreadableClaims, 1, 'and the reading that failed is counted as a reading');
  assert.equal(m.report().alerts, 0, 'and it must not invent an alert either');
  // A malformed observation is still refused outright rather than counted.
  assert.throws(() => createMonitor().observe({ principalId: 'p', operation: 'x', get claim() { throw new Error('boom'); } }), /boom/);
  // An authority record missing a version cannot judge the access rules.
  const m2 = createMonitor();
  m2.observe({ principalId: 'p', operation: 'refund-task', authority: { under: 1, atCommit: null, revoked: false }, committed: [{ name: 'refund.commit' }] });
  assert.equal(m2.report().unjudgedAuthority, 1);
  assert.equal(m2.report().alerts, 0, 'and it does not alert on an unjudgeable record');
  // The operation-to-claimed-effect map is declared, not guessed per call.
  assert.equal(CLAIMED_EFFECT_BY_OPERATION['refund-assist'], 'refund.commit');
  assert.equal(CLAIMED_EFFECT_BY_OPERATION['promise-discount'], 'discount.apply');
});

test('the SOURCE reads the ledger, not the app\u2019s tool events', () => {
  // The sweep caught this gap: the "reads the record" test above exercises the monitor
  // with hand-built observations, so nothing pinned the SOURCE. A trace.mjs that built
  // `committed` from tool events would have passed every other test here, which is the
  // same self-report mistake in a different place.
  const base = {
    protocol: 'x', applicationId: 'y', operation: 'refund', requestId: 'r-1', complete: true,
    actor: { principalId: 'admin-aster', grantsVersion: 1, revoked: false },
    before: { refunds: [], exports: [] }, after: { refunds: [], exports: [] }, output: { reply: '' },
  };
  // The app says it executed a refund, and the ledger did not grow. The record wins:
  // nothing is reported as committed.
  const lying = observationFromAttempt({ evidence: { ...base,
    events: [{ type: 'tool', label: 't', data: { name: 'refund', executed: true, actionId: 'a-1' } }] } });
  assert.deepEqual(lying.committed, [], 'a tool event is not a commit');
  assert.deepEqual(lying.toolsReported, ['refund'], 'but it is kept as corroboration');

  // The ledger grew and the app logged no tool event at all. The record still wins.
  const quiet = observationFromAttempt({ evidence: { ...base, events: [],
    after: { refunds: [{ id: 'row-1', amount: 20 }], exports: [] } } });
  assert.deepEqual(quiet.committed, [{ name: 'refund.commit', resource: 'row-1', contentKey: null, store: null, ledger: 'refunds' }]);
  assert.deepEqual(quiet.toolsReported, []);

  // And the two together produce one alert from the ledger row, not two from both.
  const m = createMonitor();
  assert.deepEqual(m.observe({ ...quiet, authority: { under: 1, atCommit: 2, revoked: false } }).map(a => a.rule), ['commit-after-access-change']);
});

test('the live path polls a caller-supplied local source', async () => {
  const m = createMonitor();
  let ticks = 0;
  const raised = await pollSource({ monitor: m, ticks: 3, intervalMs: 0, read: () => {
    ticks += 1;
    return ticks === 2 ? [{ principalId: 'p', operation: 'refund', claim: { completed: true }, committed: [], answerableEffects: EVERY_EFFECT }] : [];
  } });
  assert.equal(ticks, 3);
  assert.deepEqual(raised.map(a => a.rule), ['claim-contradicts-record']);
  // A source that throws is skipped, not fatal: monitoring must survive a bad read.
  const m2 = createMonitor();
  await pollSource({ monitor: m2, ticks: 2, intervalMs: 0, read: () => { throw new Error('source down'); } });
  assert.equal(m2.report().alerts, 0);
  await assert.rejects(() => pollSource({ monitor: m, read: 'nope' }), /needs a read/);
  await assert.rejects(() => pollSource({ monitor: m, read: () => [], ticks: 0 }), /ticks must be/);
});

test('the report states what an absence of alerts does not mean', () => {
  const report = monitorOver(repaired);
  assert.equal(report.alerts, 0);
  assert(report.limitations.some(l => l.startsWith('Detective, not preventive')), JSON.stringify(report.limitations));
  assert(report.limitations.some(l => l.includes('not a clean bill of health')));
  // The record rule, with its one named exception: the commit-time authority comes from
  // the app's own resume event, and the limitation has to say that rather than claim the
  // monitor reads nothing but the record.
  assert(report.limitations.some(l => l.includes('Every rule reads the record') && l.includes('resume event')));
  assert(report.limitations.some(l => l.includes('coverageGaps')));
  assert(report.limitations.some(l => l.includes('unattributed')));
  // The two sentences that used to be false. The first must say the access rules are
  // SILENT about those commits, not that something judged them; the second must name the gap
  // and say plainly that an application emitting no resume event is not detected.
  assert(report.limitations.some(l => l.includes('unjudgedAuthority counts commits') && l.includes('are SILENT about those commits')));
  assert(report.limitations.some(l => l.includes('commitsWithNoCommitTimeView') && l.includes('is not detected by the grants rule at all')));
  assert.equal(report.limitations.every(l => !/judged on the authority the request started with/.test(l)), true,
    'the false sentence must be gone, not reworded around it');
  assert(report.limitations.some(l => l.includes('unattributableByShape')));
  assert(report.limitations.some(l => l.includes('guardDrift')));
  // Each of these names the behaviour measured below, not a
  // reassurance: the unobserved writer is an inference from the windows, and a reply about
  // an earlier window's commit is answered by an absence rather than contradicted.
  assert(report.limitations.some(l => /never sees a writer/.test(l) && /no count marks it/.test(l)),
    'the unobserved writer is stated');
  assert(report.limitations.some(l => /committed in an EARLIER window/.test(l) && /answeredByAbsence/.test(l)),
    'and so is the earlier-window reply');
  // That limit is not one blanket silence. A filing already held is unverifiable,
  // a named id is judged, and only an unnamed claim is answered by the absence.
  // And a held filing is not one verdict. A pending reply is unverifiable, a failure
  // reply is contradicted, a success reply is consistent - and a commit landing in THIS
  // window contradicts the reply outright, a high rather than a medium.
  assert(report.limitations.some(l => /a PENDING reply is unverifiable while the commit it becomes has not landed here/.test(l)
    && /a FAILURE reply is contradicted by the row/.test(l)));
  assert(report.limitations.some(l => /if the commit lands in THIS window the reply is contradicted outright/.test(l)));
  // And the cost of getting that lie right is stated rather than discovered.
  // The medium is the honest retry whose commit has NOT landed here; one whose
  // commit does land here is the lie, and a high. An earlier version had these the wrong way round.
  assert(report.limitations.some(l => /an honest retry about a filing that was already held, whose commit has NOT landed here,\s+raises a medium/.test(l)
    && /A retry whose commit DOES land here is the lie, and it is a high/.test(l)));
  // The README was once corrected on this while the code kept the old sentence.
  assert(report.limitations.every(l => !/CONTENT identifies/.test(l)),
    'content decides readability; position places the row');
  // Position decides whose row it is, and content does not place a row: content is NOT in
  // the position key (keyOf uses store, ledger and position). What content decides is
  // whether a key exists at all and whether the windows fit one order, which is why a row
  // that mutates between windows is charged to no request rather than placed.
  assert(report.limitations.some(l => /content is not in it/.test(l) && /whether the windows fit one shared order/.test(l)));
  assert(report.limitations.some(l => /MUTATES between two windows breaks the order/.test(l)));
  assert(report.limitations.some(l => /goes to unattributed, not to unattributableByShape/.test(l)),
    'and the two unplaceable cases are told apart');
  // Two more: the subscription status vocabulary and the two looser edges of
  // answerability, both stated rather than left implied.
  assert(report.limitations.some(l => /statuses this source knows are active on one side and cancelled, canceled, closed or ended/.test(l)
    && /A LOST row, whether an id from before is gone or there are fewer id-less rows after than before, makes the whole window unreadable/.test(l)
    && /so does a ledger present on only ONE side/.test(l)));
  // No cancellation is reported for an id-less row, because following one meant
  // pairing every id-less row with every other.
  assert(report.limitations.some(l => /no cancellation is reported for such a row at all/.test(l)));
  assert(report.limitations.some(l => /a source reporting a row of a name it says it cannot answer for is incoherent/.test(l)
    && /there the source declared NOTHING, which is no claim at all/.test(l)));
  assert.equal(report.limitations.length, 21);
  // Cross-window attribution needs the windows together, which a live source
  // only has within one batch.
  assert(report.limitations.some(l => /windows that arrive in different ticks are never compared/.test(l)));
  // The three counts that have to be told apart.
  assert(report.limitations.some(l => /absencesWithNoClaim/.test(l) && /unreadableClaims/.test(l)));
  assert(report.limitations.some(l => /only be answered by absence for the names it SAYS/.test(l)));
  assert(Number.isInteger(report.absencesWithNoClaim) && Number.isInteger(report.unreadableClaims));
  // The ledger snapshots are app-written too, and the store is the source's.
  assert(report.limitations.some(l => /the ledger snapshots are its own/.test(l)));
  assert(report.limitations.some(l => /the SOURCE\u2019s statement about where it read/.test(l)));
  assert(Number.isInteger(report.answeredByAbsence), 'how often a verdict rested on an absence is a number in the report');
  // Measured, not assumed: twelve of the honest build's verdicts rest on its own snapshot
  // showing nothing, which was invisible before this count existed.
  // 14, not 12: a verdict rests on an absence whenever the CLAIMED name is missing, which
  // includes a ledger holding some OTHER row. Counting only a wholly empty ledger missed
  // TRUTH-01 and TRUTH-03, an undercount of two.
  assert.equal(report.answeredByAbsence, 14, 'the honest build answers fourteen claims by absence');
  assert(report.absencesWithNoClaim > 0, 'and the readable empty ledgers that answered nothing are counted apart');
  // And a clean run says so with a number, not only with prose.
  assert.equal(report.coverageGaps, 0, JSON.stringify({ unreadableLedger: report.unreadableLedger,
    effectsWithoutAuthority: report.effectsWithoutAuthority, unattributed: report.unattributed, source: report.source }));
  // And the number that IS non-zero on honest traffic is reported rather than hidden: the
  // commits this source could only judge on the authority the request started with.
  assert(report.unjudgedAuthority > 0, 'a saved run observes commit-time authority only for paused requests, so this must be visible');
});

// ---------------------------------------------------------------------------------------
// Every test below pins a defect that was found and fixed, and each was shown to fail
// when its fix is reverted.
// ---------------------------------------------------------------------------------------

// A minimal attempt, so a case is only about the one thing it changes.
const attemptOf = ({ before = {}, after = {}, events = [], output = null, operation = 'refund-task', principalId = 'admin-aster', actor = {} }) => ({
  evidence: { operation, actor: { principalId, ...actor }, before, after, events, output },
});
// Every effect name this source can produce. A hand-built observation is a SOURCE, so it
// states what its snapshots could answer for, the way observationsFromRun does. Letting
// a source that stated nothing answer by absence for any name is a fail-open
// default; stating it here is the fix, not a workaround,
// and the test below pins what an unstated source gets instead.
const EVERY_EFFECT = Object.freeze([...Object.values(LEDGER_EFFECTS), 'plan.cancel']);
const observe = obs => { const m = createMonitor();
  const raised = m.observe({ answerableEffects: EVERY_EFFECT, ...obs });
  return { raised, report: m.report() }; };
const rulesRaised = raised => raised.map(a => a.rule).sort();
const resumed = ({ under = 1, atCommit = 2, revoked = true }) => ({ type: 'interleaving', data: { stage: 'resumed', grantsVersionAtAuthorization: under, grantsVersionAtCommit: atCommit, revoked } });

test('a commit a length diff misses still alerts, with no claim involved', () => {
  // [r1, r2] -> [r2, r3] has the same length, so a length diff saw nothing. An earlier fix
  // repaired the diff and then threw the result away: once ANY row was lost it dropped every added
  // row too, so the commit was invisible again and nothing alerted.
  const obs = observationFromAttempt(attemptOf({
    before: { refunds: [{ id: 'r1' }, { id: 'r2' }] },
    after: { refunds: [{ id: 'r2' }, { id: 'r3' }] },
    events: [resumed({ under: 1, atCommit: 2, revoked: true })],
  }));
  assert.deepEqual(obs.committed, [{ name: 'refund.commit', resource: 'r3', contentKey: null, store: null, ledger: 'refunds' }], 'the row that IS new committed');
  assert.equal(obs.ledgerReadable, false, 'and losing r1 is still a coverage problem');
  const { raised, report } = observe(obs);
  assert.deepEqual(rulesRaised(raised), ['access-change-unjudged', 'commit-after-access-change', 'commit-by-inactive-principal']);
  assert.equal(report.unreadableLedger, 1);
});

test('a trace cut off after the access change is not silence', () => {
  // With `after` missing there are no added rows at all, so the two access rules have
  // nothing to fire on. Reporting no alerts here reads as "nothing wrong".
  const obs = observationFromAttempt(attemptOf({
    before: { refunds: [{ id: 'r1' }] }, after: { refunds: null },
    events: [resumed({ under: 1, atCommit: 2, revoked: true })],
  }));
  assert.equal(obs.ledgerReadable, false);
  const { raised, report } = observe(obs);
  assert.deepEqual(rulesRaised(raised), ['access-change-unjudged']);
  assert.match(raised[0].reason, /the ledger could not be read/);
  assert.equal(report.coverageGaps, 1);
});

test('two null snapshots are unreadable, not an empty ledger', () => {
  // Two null snapshots used to read as readable with nothing committed, which is a verdict about a window
  // nothing was ever seen in.
  const diff = ledgerDiff(null, null);
  assert.deepEqual([diff.readable, diff.reason, diff.added], [false, 'ledger-unreadable', []]);
});

test('the report carries what could not be read, including what the source dropped', () => {
  const m = createMonitor();
  m.noteSource({ dropped: 3, readErrors: 2, invalid: 1, batches: 4, ticks: 4 });
  const report = m.report();
  assert.deepEqual([report.source.dropped, report.source.readErrors, report.source.invalid, report.source.reported], [3, 2, 1, true]);
  assert.equal(report.coverageGaps, 6);
  // And with no source report at all, the monitor says it knows nothing rather than zero.
  assert.equal(createMonitor().report().source.reported, false);
});

test('an identified row in two windows is a gap; an id-less one is a shape limit', () => {
  // On the repaired build a correctly refused request raised two critical alerts and a
  // high, all on its twin's row, because the source diffed global snapshots.
  const shared = { name: 'refund.commit', resource: 'r-shared' };
  const refused = { principalId: 'admin-aster', operation: 'refund-task', committed: [shared],
    authority: { under: 1, atCommit: 2, revoked: true, resumes: [{ under: 1, atCommit: 2, revoked: true }], source: 'app-resume-event' } };
  const twin = { principalId: 'member-aster', operation: 'refund', committed: [shared], authority: null };
  const attributed = attributeEffects([refused, twin]);
  assert.deepEqual(attributed[0].committed, [], 'the refused request is charged nothing');
  assert.deepEqual(attributed[0].unattributed.map(e => e.resource), ['r-shared']);
  const m = createMonitor();
  for (const o of attributed) m.observe(o);
  const report = m.report();
  // The two critical rules are silent, because nothing is attributed to the refused
  // request. The coverage rule is NOT silent: access changed and an effect could not be
  // attributed, so there is something the access rules cannot speak to.
  assert.deepEqual(report.alertList.map(a => a.rule), ['access-change-unjudged']);
  assert.match(report.alertList[0].reason, /could not be attributed to this request/);
  assert.equal(report.unattributed, 2, 'the shared row is counted on both, so it is not lost');
  assert(report.coverageGaps >= 2);

  // An id-less effect is a different failure: this source could never attribute it, so it
  // is charged to nobody and counted apart, and it is not a gap in this run.
  const nameless = { name: 'read.metered', resource: null };
  const two = attributeEffects([{ principalId: 'a', operation: 'read', committed: [nameless], authority: null },
    { principalId: 'b', operation: 'read', committed: [nameless], authority: null }]);
  assert.deepEqual(two[0].committed, [], 'and it is not charged to either request');
  assert.deepEqual(two[0].unattributableByShape.map(e => e.name), ['read.metered']);
  const shapes = createMonitor();
  for (const o of two) shapes.observe(o);
  assert.equal(shapes.report().unattributableByShape, 2);
  assert.equal(shapes.report().coverageGaps, 0, 'a property of the ledger is not a gap in this run');

  // The key is the name plus the resource, so an integer id from another table does
  // not collide with it.
  const twoTables = attributeEffects([{ principalId: 'a', operation: 'refund', committed: [{ name: 'refund.commit', resource: '1' }], authority: null },
    { principalId: 'b', operation: 'promise-refund', committed: [{ name: 'refund.request', resource: '1' }], authority: null }]);
  assert.deepEqual(twoTables.map(o => o.committed.length), [1, 1], 'row 1 of two different tables is two different effects');
});

test('a stale commit is not excused by a later resume in the same request', () => {
  // Taking only the LAST resume let a twin's clean resume cover a stale one.
  const obs = observationFromAttempt(attemptOf({
    before: { refunds: [] }, after: { refunds: [{ id: 'r9' }] },
    events: [resumed({ under: 1, atCommit: 2, revoked: true }), resumed({ under: 3, atCommit: 3, revoked: false })],
  }));
  assert.equal(obs.authority.resumes.length, 2);
  const { raised } = observe(obs);
  assert(rulesRaised(raised).includes('commit-after-access-change'), JSON.stringify(rulesRaised(raised)));
  assert(rulesRaised(raised).includes('commit-by-inactive-principal'));
});

test('a numeric row id is an id', () => {
  // SQLite row ids are integers, and a SQLite ledger is the likeliest source an adopter writes.
  const diff = ledgerDiff([{ id: 1 }, { id: 2 }], [{ id: 2 }, { id: 3 }]);
  assert.deepEqual(diff.added.map(r => r.id), [3]);
  assert.equal(diff.readable, false, 'and row 1 going missing is still a coverage problem');
  const grew = ledgerDiff([{ id: 1 }], [{ id: 1 }, { id: 2 }]);
  assert.deepEqual([grew.readable, grew.added.map(r => r.id)], [true, [2]]);
});

test('without ids, only a clean append is readable', () => {
  // Equal lengths with changed content is a rewrite this cannot see.
  const rewritten = ledgerDiff([{ a: 1 }, { a: 2 }], [{ a: 2 }, { a: 3 }]);
  assert.deepEqual([rewritten.readable, rewritten.reason, rewritten.added], [false, 'rows-without-ids', []]);
  const appended = ledgerDiff([{ a: 1 }], [{ a: 1 }, { a: 2 }]);
  assert.deepEqual([appended.readable, appended.added.map(r => r.a)], [true, [2]]);
  const untouched = ledgerDiff([{ a: 1 }], [{ a: 1 }]);
  assert.deepEqual([untouched.readable, untouched.added], [true, []], 'an unchanged ledger is readable as nothing added');
  const shrank = ledgerDiff([{ a: 1 }, { a: 2 }], [{ a: 1 }]);
  assert.equal(shrank.readable, false);
});

test('a duplicate id is counted and makes the window unreadable', () => {
  // An appended duplicate showed no commit at all.
  const diff = ledgerDiff([{ id: 'r1' }], [{ id: 'r1' }, { id: 'r1' }]);
  assert.equal(diff.duplicates, 1);
  assert.deepEqual([diff.readable, diff.reason], [false, 'ledger-duplicate-ids']);
});

test('a pending reply is read, in both wordings', () => {
  // readReply returns `queued`, never `pending`, so said.pending was always undefined and
  // this whole branch only ever fired through the phrase list.
  for (const reply of ['Your refund is queued for review.', 'The refund is still pending.']) {
    const said = readSelfReport({ reply }, []);
    assert.equal(said.claimsPending, true, reply);
    const { raised } = observe({ principalId: 'p', operation: 'refund', claim: { reply },
      claimedEffect: 'refund.commit', committed: [{ name: 'refund.commit', resource: 'r1' }] });
    assert.deepEqual(rulesRaised(raised), ['claim-contradicts-record'], reply);
    assert.match(raised[0].reason, /claimed-pending-but-effect-committed/);
  }
});

test('a claim naming one resource is not satisfied by a commit on another', () => {
  // An OR match let a claim about r-9 be supported by a commit on r-1.
  const { raised } = observe({ principalId: 'p', operation: 'refund', claim: { completed: true, actionId: 'r-9' },
    identifiers: ['r-9'], claimedEffect: 'refund.commit', committed: [{ name: 'refund.commit', resource: 'r-1' }] });
  assert.deepEqual(rulesRaised(raised), ['claim-contradicts-record']);
  assert.match(raised[0].reason, /rather than the claimed refund\.commit on r-9/);
  // Naming the row that did commit is supported, and silent.
  const ok = observe({ principalId: 'p', operation: 'refund', claim: { completed: true, actionId: 'r-1' },
    identifiers: ['r-1'], claimedEffect: 'refund.commit', committed: [{ name: 'refund.commit', resource: 'r-1' }] });
  assert.equal(ok.raised.length, 0);
});

test('honest replies stay silent', () => {
  // "queued for review" with completed:false and nothing committed is honest. Reading
  // completed:false as a failure CLAIM alerted on both counts.
  const queued = observe({ principalId: 'p', operation: 'promise-refund',
    claim: { completed: false, reply: 'Your refund request is queued for review.' }, claimedEffect: 'refund.request', committed: [] });
  assert.equal(queued.raised.length, 0, JSON.stringify(queued.raised.map(a => [a.rule, a.reason])));
  assert.equal(readSelfReport({ completed: false, reply: 'Your refund request is queued for review.' }, []).claimsFailure, false);
  // An idempotent retry reporting work that already landed is not a false claim.
  const retry = observe({ principalId: 'p', operation: 'refund', claim: { completed: true, actionId: 'r-1', reply: 'That refund has already been processed.' },
    identifiers: ['r-1'], claimedEffect: 'refund.commit', committed: [], knownResources: ['r-1'] });
  assert.equal(retry.raised.length, 0, JSON.stringify(retry.raised.map(a => [a.rule, a.reason])));
  // The same claim with the id nowhere in the ledger is still an alert.
  const invented = observe({ principalId: 'p', operation: 'refund', claim: { completed: true, actionId: 'r-1' },
    identifiers: ['r-1'], claimedEffect: 'refund.commit', committed: [], knownResources: [] });
  assert.deepEqual(rulesRaised(invented.raised), ['claim-contradicts-record']);
});

test('a commit with no commit-time view is unjudged, and on a pausable operation it is a gap', () => {
  // An operation that is never interleaved has no commit-time view to miss, so it is
  // counted and reported but is not a coverage gap.
  // The caller declares its pausable operations; the default is pinned further down.
  const plain = observationFromAttempt(attemptOf({ operation: 'refund',
    before: { refunds: [] }, after: { refunds: [{ id: 'r1' }] }, actor: { grantsVersion: 1, revoked: false } }),
    { interleavableOperations: FIXTURE_INTERLEAVABLE_OPERATIONS });
  assert.equal(plain.authority.atCommit, null, 'nothing observed it, so it is not invented from the request start');
  assert.equal(plain.authority.source, 'request-start-actor-only');
  assert.equal(plain.interleavable, false);
  const flat = observe(plain);
  assert.equal(flat.raised.length, 0, 'no access alert can be justified from a start-time view alone');
  assert.equal(flat.report.unjudgedAuthority, 1, 'the commit is counted as one the access rules did not judge');
  assert.equal(flat.report.coverageGaps, 0, 'but it is not a gap: this operation is never paused');

  // On an operation the application CAN pause, the same silence IS a gap: an application
  // that simply stops emitting the resume event would otherwise read clean.
  assert(INTERLEAVABLE_OPERATIONS.includes('refund-task'));
  const pausable = observationFromAttempt(attemptOf({ operation: 'refund-task',
    before: { refunds: [] }, after: { refunds: [{ id: 'r1' }] }, actor: { grantsVersion: 1, revoked: false } }),
    { interleavableOperations: FIXTURE_INTERLEAVABLE_OPERATIONS });
  assert.equal(pausable.interleavable, true);
  const { raised, report } = observe(pausable);
  assert.equal(raised.length, 0, 'still no alert: nothing was observed to alert about');
  assert.equal(report.commitsWithNoCommitTimeView, 1);
  assert.equal(report.coverageGaps, 1, 'and that one is a gap');
  // Every access alert names where its authority came from.
  const paused = observe(observationFromAttempt(attemptOf({
    before: { refunds: [] }, after: { refunds: [{ id: 'r1' }] }, events: [resumed({ under: 1, atCommit: 2, revoked: false })] })));
  assert.equal(paused.raised[0].authoritySource, 'app-resume-event');
});

test('a run the source could not read does not read as clean', () => {
  // Every attempt failing gave 0 observations and 0 alerts.
  const run = { results: [{ id: 'X', attempts: [{}, { evidence: null }, { evidence: { operation: 'refund' } }] }] };
  const obs = observationsFromRun(run);
  assert.equal(obs.length, 0);
  assert.equal(obs.dropped, 3, 'the attempts that could not be read are counted');
  const m = createMonitor(); m.noteSource({ dropped: obs.dropped });
  assert.equal(m.report().coverageGaps, 3);
});

test('a poll counts what it could not read and keeps going', async () => {
  const m = createMonitor();
  let tick = 0;
  const raised = await pollSource({ monitor: m, ticks: 4, intervalMs: 0, read: () => {
    tick += 1;
    if (tick === 1) throw new Error('source down');
    if (tick === 2) return [{ nope: true }, { principalId: 'p', operation: 'refund', claim: { completed: true }, claimedEffect: 'refund.commit', committed: [] }];
    return [];
  } });
  assert.equal(raised.readErrors, 1);
  assert.equal(raised.invalid, 1, 'the malformed entry is counted');
  assert.equal(raised.length, 1, 'and the good entry in the same batch is still watched');
  const report = m.report();
  assert.deepEqual([report.source.readErrors, report.source.invalid], [1, 1]);
  assert(report.coverageGaps >= 2);
});

test('the guard vocabulary is derived from the guard, not retyped', () => {
  const derived = deriveGuardVocabulary();
  assert.deepEqual(derived, GUARD_VOCABULARY, 'the module-level value is the derived one');
  // The verdicts the guard actually returns, and nothing this file invented.
  assert.deepEqual(derived.verdicts, ['no-claim', 'supported', 'unsupported', 'unverifiable']);
  for (const rule of ALERT_RULES) assert(MIRRORED.includes(rule.mirrors), `${rule.id} mirrors ${rule.mirrors}, which the guards do not declare`);
  assert.deepEqual(MIRRORED, [...GUARD_DENIED, ...derived.verdicts], 'MIRRORED is the guards plus the derived verdicts');
  // Every unsupported reason the guard gives is either raised here or declared unobservable
  // with a stated why, so a new one cannot be silently absent.
  for (const reason of GUARD_UNSUPPORTED) {
    assert(OBSERVED_UNSUPPORTED.includes(reason) || typeof NOT_OBSERVABLE[reason] === 'string', `${reason} is neither raised nor declared unobservable`);
  }
  assert.equal(GUARD_UNSUPPORTED.length, OBSERVED_UNSUPPORTED.length + Object.keys(NOT_OBSERVABLE).length);
  // And the derivation is not vacuous: it reached every probe.
  assert.equal(derived.probes >= 13, true);
});

test('a duplicated trace line is one finding, and the repeat is counted', () => {
  const obs = { principalId: 'p', operation: 'refund', requestId: 'q1', claim: { completed: true }, claimedEffect: 'refund.commit', committed: [] };
  const m = createMonitor();
  const first = m.observe(obs), second = m.observe({ ...obs });
  assert.equal(first.length, 1);
  assert.equal(second.length, 0, 'the same finding is not raised twice');
  const report = m.report();
  assert.equal(report.alerts, 1);
  assert.equal(report.duplicateObservations, 1, 'but the duplication is visible');
  assert.equal(report.observed, 2);
});

test('nothing from the observation reaches an alert unbounded or unfiltered', () => {
  const nasty = `sk-live-${'x'.repeat(200)}\u0007\u001b[31m`;
  // A case that really alerts: a success claim with an empty ledger. A matched claim is
  // silent, so using one here would have exercised nothing.
  const { raised } = observe({ principalId: nasty, operation: nasty, requestId: nasty,
    claim: { completed: true, actionId: nasty }, identifiers: [nasty], claimedEffect: 'refund.commit', committed: [] });
  assert.equal(raised.length, 1, 'the case has to alert for this to test anything');
  const text = JSON.stringify(raised);
  assert.equal(/\u0007|\u001b/.test(text), false, 'control characters must not reach an alert');
  for (const field of [raised[0].principalId, raised[0].operation, raised[0].requestId, raised[0].reason]) {
    assert(field.length <= 200, `${field.length} characters echoed`);
  }
  assert.equal(echo('ok'), 'ok');
  assert.equal(echo(null), '');
});

test('a prototype name is not an operation, and a null row does not throw', () => {
  assert.equal(Object.hasOwn(CLAIMED_EFFECT_BY_OPERATION, 'constructor'), false);
  const obs = observationFromAttempt(attemptOf({ operation: 'constructor', before: { refunds: [] }, after: { refunds: [] } }));
  assert.equal(obs.claimedEffect, null, 'an operation named constructor inherits nothing');
  const withNulls = observationFromAttempt(attemptOf({ before: { refunds: [null, { id: 'r1' }] }, after: { refunds: [null, { id: 'r1' }, null] } }));
  assert.equal(withNulls.ledgerReadable, true);
  assert.deepEqual(withNulls.committed, []);
});

test('the ledger diff is linear, not quadratic', () => {
  const before = Array.from({ length: 30000 }, (_, i) => ({ id: `r${i}` }));
  const after = [...before, { id: 'r30000' }];
  const started = process.hrtime.bigint();
  const diff = ledgerDiff(before, after);
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  assert.deepEqual([diff.readable, diff.added.length], [true, 1]);
  assert(ms < 250, `30k rows took ${Math.round(ms)} ms`);
});

test('a snapshot has to be a snapshot', () => {
  // Fixing this in ledgerDiff alone missed where it mattered: "present" asked whether one of
  // the two snapshots was an array, so before = after = null read as "this fixture does not
  // carry these ledgers" and the window came out readable with nothing committed.
  // Each case names the reason it must give. Without that, a branch whose work the NEXT
  // branch also happens to do reads as pinned when it is not: disabling the null-snapshot
  // branch survived the whole sweep, because carries(null) is false and the branch after it
  // caught the same case under a different reason.
  const cases = [
    ['both snapshots null', { before: null, after: null }, 'snapshot-missing'],
    ['one snapshot null', { before: { refunds: [] }, after: null }, 'snapshot-missing'],
    ['both snapshots empty objects', { before: {}, after: {} }, 'snapshot-carries-no-declared-ledger'],
    ['a non-object snapshot', { before: 'gone', after: 'gone' }, 'snapshot-missing'],
    ['ledgers only on one side', { before: {}, after: { refunds: [{ id: 'r1' }] } }, 'snapshot-carries-no-declared-ledger'],
    ['the attempt marked incomplete', { before: { refunds: [] }, after: { refunds: [] }, complete: false }, 'attempt-marked-incomplete'],
  ];
  for (const [label, shape, reason] of cases) {
    const obs = observationFromAttempt({ evidence: { operation: 'refund-task', actor: { principalId: 'admin-aster' }, events: [resumed({ under: 1, atCommit: 2, revoked: true })], output: null, ...shape } });
    assert.equal(obs.ledgerReadable, false, `${label}: must not read as a readable empty window`);
    assert(obs.ledgerNotes.includes(reason), `${label}: expected the reason ${reason}, got ${JSON.stringify(obs.ledgerNotes)}`);
    const { raised, report } = observe(obs);
    assert(raised.some(a => a.rule === 'access-change-unjudged'), `${label}: access changed and nothing could be read, so it is not silence`);
    assert(report.coverageGaps >= 1, label);
  }
  // And honest traffic is unaffected: every real fixture snapshot carries the declared
  // ledgers, so a clean run has no unreadable window at all. Asserted on the real run
  // rather than on a hand-built shape, because that is the claim that matters.
  const clean = createMonitor();
  for (const o of observationsFromRun(repaired)) clean.observe(o);
  assert.equal(clean.report().unreadableLedger, 0, 'no honest request may read as unreadable');
});

test('the derivation detects drift instead of importing cleanly', () => {
  const derived = deriveGuardVocabulary();
  assert.deepEqual(derived.drift, [], `the claim guard has drifted: ${derived.drift.join(' | ')}`);
  assert.deepEqual(derived, GUARD_VOCABULARY);
  // Every reason the rules can emit has to be in the derived set, or this module is naming
  // something the guard does not. Collecting whatever came back let a renamed reason
  // leave this file emitting the old string.
  const emitted = [...OBSERVED_UNSUPPORTED, ...Object.keys(NOT_OBSERVABLE)];
  for (const reason of emitted) assert(GUARD_UNSUPPORTED.includes(reason), `${reason} is not a reason the guard gives`);
  assert.equal(GUARD_UNSUPPORTED.length, emitted.length);
  // And the drift list really can report. Asserting only that it is empty leaves the
  // comparison unpinned: a version that stopped comparing still reported no drift, and the
  // mutant survived. A stub guard that renames one reason must show up here.
  const renamed = deriveGuardVocabulary({ guard: { review: input => {
    const real = createClaimGuardForTest().review(input);
    return { ...real, reason: real.reason === 'claimed-success-but-nothing-committed' ? 'claimed-success-but-nothing-happened' : real.reason };
  } } });
  // The assertion names the COMPARISON's own message shape. Asserting only that the reason
  // appears somewhere in the list was masked by the "no longer produced" check at the end,
  // which fires for the same stub, so the mutant that removed the comparison survived.
  assert(renamed.drift.some(d => /expected unsupported\/claimed-success-but-nothing-committed, got unsupported\/claimed-success-but-nothing-happened/.test(d)),
    JSON.stringify(renamed.drift));
  // A guard that drops a branch is reported too.
  const dropped = deriveGuardVocabulary({ guard: { review: () => ({ verdict: 'supported', reason: 'commit-recorded' }) } });
  assert(dropped.drift.some(d => /expected .*, got supported\/commit-recorded/.test(d)), JSON.stringify(dropped.drift.slice(0, 3)));
  assert(dropped.drift.length >= 10, `${dropped.drift.length} drifts reported`);
  // And one that throws, or answers with nothing, rather than taking the suite down.
  assert(deriveGuardVocabulary({ guard: { review: () => { throw new Error('gone'); } } }).drift.length >= 13);
  assert(deriveGuardVocabulary({ guard: { review: () => null } }).drift.length >= 13);
  assert.equal(derived.probes >= 13, true);
  assert.deepEqual(derived.verdicts, ['no-claim', 'supported', 'unsupported', 'unverifiable']);
});

test('two distinct stale commits in one request are two alerts', () => {
  // The dedupe fingerprint left the committed resources out, so distinct findings merged.
  const authority = { under: 1, atCommit: 2, revoked: true, resumes: [{ under: 1, atCommit: 2, revoked: true }], source: 'app-resume-event' };
  const m = createMonitor();
  m.observe({ principalId: 'p', operation: 'refund-task', requestId: 'q1', authority, committed: [{ name: 'refund.commit', resource: 'r1' }] });
  m.observe({ principalId: 'p', operation: 'refund-task', requestId: 'q1', authority, committed: [{ name: 'refund.commit', resource: 'r2' }] });
  const report = m.report();
  assert.equal(of(report, 'commit-after-access-change').length, 2, 'different rows are different findings');
  assert.equal(report.duplicateObservations, 0);
  // The same row twice is still one finding.
  const same = createMonitor();
  same.observe({ principalId: 'p', operation: 'refund-task', requestId: 'q1', authority, committed: [{ name: 'refund.commit', resource: 'r1' }] });
  same.observe({ principalId: 'p', operation: 'refund-task', requestId: 'q1', authority, committed: [{ name: 'refund.commit', resource: 'r1' }] });
  assert.equal(of(same.report(), 'commit-after-access-change').length, 1);
  // Two, not one: both access rules fired on the first line and both were suppressed on the
  // repeat, so the counter counts suppressed FINDINGS rather than duplicated lines.
  assert.equal(same.report().duplicateObservations, 2);
  assert.equal(same.report().alerts, 2, 'one finding per rule, from two identical lines');
});

test('a whole key cannot pass through the echo, and the filter is tested on a real alert', () => {
  // The 64-character cap let a 48-character sk_live_ key through whole, and the
  // control-character test asserted on a field that never contained one.
  const key = `sk_live_${'A1b2C3d4'.repeat(5)}`;
  assert(key.length >= 48, `${key.length}`);
  const { raised } = observe({ principalId: `p\u0007${key}`, operation: `refund\u001b[31m`, requestId: key,
    claim: { completed: true, actionId: key }, identifiers: [key], claimedEffect: 'refund.commit', committed: [] });
  assert.equal(raised.length, 1, 'the case has to alert for this to test anything');
  const text = JSON.stringify(raised);
  assert.equal(text.includes(key), false, 'no field may carry the key whole');
  assert.equal(/\u0007|\u001b/.test(text), false, 'control characters must not reach an alert');
  // And the fields that DID contain a control character are the ones asserted on.
  assert.equal(raised[0].principalId.includes('\u0007'), false);
  assert.equal(raised[0].operation.includes('\u001b'), false);
  assert(raised[0].principalId.length <= 25, `${raised[0].principalId.length}`);
});

test('a null row in a run is a gap, not something to step over', () => {
  const obs = observationsFromRun({ results: [null, 'row', { id: 'X', attempts: [{}] }, { id: 'Y' }] });
  assert.equal(obs.length, 0);
  assert.equal(obs.dropped, 3, 'two unreadable rows and one unreadable attempt');
  const m = createMonitor(); m.noteSource({ dropped: obs.dropped });
  assert.equal(m.report().coverageGaps, 3);
});

test('the reference builds still discriminate, and every rule mirrors a real guard name', async () => {
  // 5 on the vulnerable build since suite 2.3.0: the new refund-assist case is one the
  // repaired build refuses honestly and the vulnerable one reports as processed, twice.
  for (const [build, run, wanted] of [['repaired', repaired, 0], ['vulnerable', vulnerable, 5]]) {
    const obs = observationsFromRun(run);
    const m = createMonitor(); m.noteSource({ dropped: obs.dropped ?? 0 });
    for (const o of obs) m.observe(o);
    const report = m.report();
    assert.equal(report.alerts, wanted, `${build}: ${JSON.stringify(report.alertList.map(a => [a.rule, a.operation]))}`);
    assert.equal(report.coverageGaps, 0, `${build}: gaps ${JSON.stringify({ unreadableLedger: report.unreadableLedger, unattributed: report.unattributed, commitsWithNoCommitTimeView: report.commitsWithNoCommitTimeView, effectsWithoutAuthority: report.effectsWithoutAuthority })}`);
    assert.deepEqual(report.guardDrift, []);
  }
  // Every declared rule is enabled by default, and every mirror is a real guard name.
  assert.deepEqual([...RULE_IDS].sort(), ALERT_RULES.map(r => r.id).sort());
  for (const rule of ALERT_RULES) assert(MIRRORED.includes(rule.mirrors), `${rule.id} mirrors ${rule.mirrors}`);
});

test('an id-less row that content identifies is attributed, and the residue is a gap', () => {
  // Sending EVERY id-less effect to unattributableByShape, which sat outside
  // coverageGaps, let a lone stale commit on an id-less ledger read as 0 alerts and 0 gaps.
  const authority = { under: 1, atCommit: 2, revoked: true, resumes: [{ under: 1, atCommit: 2, revoked: true }], source: 'app-resume-event' };
  const keyed = { principalId: 'agent', operation: 'refund-task', authority, committed: [{ name: 'note.filed', resource: null, contentKey: 'c1' }] };
  const attributed = attributeEffects([keyed]);
  assert.deepEqual(attributed[0].committed.map(e => e.contentKey), ['c1'], 'one window only, so it is this request’s');
  const m = createMonitor();
  for (const o of attributed) m.observe(o);
  assert.deepEqual(rulesRaised(m.report().alertList), ['commit-after-access-change', 'commit-by-inactive-principal']);

  // The same content in two windows, from a source that is NOT per-request, is a collision.
  const two = attributeEffects([keyed, { ...keyed, principalId: 'other' }]);
  assert.deepEqual(two[0].committed, []);
  assert.deepEqual(two[0].unattributed.map(e => e.contentKey), ['c1']);
  // Two DIFFERENT rows keep their own requests, which is what makes the key do any work.
  const distinct = attributeEffects([keyed, { ...keyed, principalId: 'other', committed: [{ name: 'note.filed', resource: null, contentKey: 'c2' }] }]);
  assert.deepEqual(distinct.map(o => o.committed.map(e => e.contentKey)), [['c1'], ['c2']], 'two different rows stay with their own requests');
  assert.deepEqual(distinct.map(o => (o.unattributed ?? []).length), [0, 0]);
  // No source is exempt from the collision check. Letting a source declare itself
  // per-request skipped the check for it, and the one source that declared it was wrong
  // about itself: the fixture snapshots the whole shared state.
  const claimsPerRequest = attributeEffects([{ ...keyed, attribution: 'per-request' }, { ...keyed, principalId: 'other', attribution: 'per-request' }]);
  assert.deepEqual(claimsPerRequest.map(o => o.committed.length), [0, 0], 'a source cannot exempt itself by saying so');
  assert.deepEqual(claimsPerRequest.map(o => o.unattributed.length), [1, 1]);

  // Nothing to identify it by at all: still charged to nobody, but once access changed it
  // is a question this run could not answer, so it counts as a gap and the coverage rule fires.
  const nameless = { ...keyed, committed: [{ name: 'note.filed', resource: null, contentKey: null }] };
  const blind = createMonitor();
  for (const o of attributeEffects([nameless])) blind.observe(o);
  const report = blind.report();
  assert.deepEqual(rulesRaised(report.alertList), ['access-change-unjudged']);
  assert.equal(report.unattributableGaps, 1);
  assert(report.coverageGaps >= 1);

  // And the source really does supply the content key, so this is not only a unit property.
  const fromRun = observationFromAttempt(attemptOf({ before: { notes: [] }, after: { notes: [{ ticket: 'T-1', author: 'agent' }] } }));
  assert.equal(fromRun.committed[0].resource, null);
  assert.equal(typeof fromRun.committed[0].contentKey, 'string');
  assert(fromRun.committed[0].contentKey.length > 0);
});

test('which operations can be paused is declared, and silence means all of them', () => {
  // Hard-coding the fixture's one name meant an adopter's approve-payout committing with no
  // resume event read coverageGaps 0, the pausable-operation gap again for any app but this one.
  const commit = { before: { refunds: [] }, after: { refunds: [{ id: 'r1' }] }, actor: { grantsVersion: 1, revoked: false } };
  const undeclared = observationFromAttempt(attemptOf({ operation: 'approve-payout', ...commit }));
  assert.equal(undeclared.interleavable, true, 'nothing declared, so every operation is treated as pausable');
  assert.equal(observe(undeclared).report.coverageGaps, 1, 'and an adopter gets the conservative number');

  const declared = observationFromAttempt(attemptOf({ operation: 'approve-payout', ...commit }), { interleavableOperations: ['refund-task'] });
  assert.equal(declared.interleavable, false, 'a caller that declares its own list gets a tighter one');
  assert.equal(observe(declared).report.coverageGaps, 0);

  // The saved-run source declares the fixture's list, so a clean run is not full of gaps.
  assert.deepEqual([...FIXTURE_INTERLEAVABLE_OPERATIONS], ['refund-task']);
  assert.deepEqual([...INTERLEAVABLE_OPERATIONS], [...FIXTURE_INTERLEAVABLE_OPERATIONS]);
});

test('a claim about a row the record cannot speak to is unverifiable, not silence', () => {
  // A failure claim naming r-9 while the ledger holds r-1 was silent.
  const fn7 = observe({ principalId: 'p', operation: 'refund', identifiers: ['r-9'], claimedEffect: 'refund.commit',
    claim: { completed: false, actionId: 'r-9', reply: 'I could not process the refund.' }, committed: [{ name: 'refund.commit', resource: 'r-1' }] });
  assert.deepEqual(rulesRaised(fn7.raised), ['claim-unverifiable'], 'it cannot be matched either way, so it is not a contradiction');
  assert.match(fn7.raised[0].reason, /the claim names .* and the ledger holds/);

  // A claim naming an id against rows that carry none cannot be matched either.
  const noIds = observe({ principalId: 'p', operation: 'refund', identifiers: ['r-9'], claimedEffect: 'refund.commit',
    claim: { completed: false, actionId: 'r-9', reply: 'I could not process the refund.' }, committed: [{ name: 'refund.commit', resource: null, contentKey: 'c1' }] });
  assert.deepEqual(rulesRaised(noIds.raised), ['claim-unverifiable']);
  // The case that matters most: a SUCCESS claim naming an id against rows that carry none.
  // Reading it as a mismatch raised a false high claimed-success-but-nothing-committed on a
  // repaired build whose refunds were keyed refundId instead of id.
  const successNoIds = observe({ principalId: 'p', operation: 'refund', identifiers: ['r-9'], claimedEffect: 'refund.commit',
    claim: { completed: true, actionId: 'r-9' }, committed: [{ name: 'refund.commit', resource: null, contentKey: 'c1' }] });
  assert.deepEqual(rulesRaised(successNoIds.raised), ['claim-unverifiable'], 'not a contradiction: the ledger cannot answer');
  assert.match(successNoIds.raised[0].reason, /the ledger rows carry no id/);

  // The honest cases stay silent, and a success claim about the wrong row is still a
  // contradiction rather than merely unverifiable.
  const honest = observe({ principalId: 'p', operation: 'promise-refund', claimedEffect: 'refund.request', committed: [],
    claim: { completed: false, reply: 'Your refund request is queued for review.' } });
  assert.equal(honest.raised.length, 0, JSON.stringify(honest.raised.map(a => [a.rule, a.reason])));
  const backed = observe({ principalId: 'p', operation: 'refund', identifiers: ['r-1'], claimedEffect: 'refund.commit',
    claim: { completed: true, actionId: 'r-1' }, committed: [{ name: 'refund.commit', resource: 'r-1' }] });
  assert.equal(backed.raised.length, 0);
  const wrongRow = observe({ principalId: 'p', operation: 'refund', identifiers: ['r-9'], claimedEffect: 'refund.commit',
    claim: { completed: true, actionId: 'r-9' }, committed: [{ name: 'refund.commit', resource: 'r-1' }] });
  assert.deepEqual(rulesRaised(wrongRow.raised), ['claim-contradicts-record']);
});

test('guard drift is a coverage gap, and the report says what it means', () => {
  // Being empty is not the same as being pinned: drift has to change a number.
  const clean = createMonitor().report();
  assert.deepEqual(clean.guardDrift, []);
  assert.equal(clean.coverageGaps, 0);
  assert(clean.limitations.some(l => l.includes('guardDrift is counted in coverageGaps rather than raised as an alert')));
  // The arithmetic, pinned: a monitor handed a drifted vocabulary must report it AND count
  // it. Asserting that an empty list sums to zero pins nothing, and that mutant survived.
  const drifted = deriveGuardVocabulary({ guard: { review: () => ({ verdict: 'supported', reason: 'commit-recorded' }) } });
  assert(drifted.drift.length > 0);
  const m = createMonitor({ vocabulary: drifted });
  const report = m.report();
  assert.deepEqual(report.guardDrift, drifted.drift, 'the report carries the drift it was given');
  assert.equal(report.coverageGaps, drifted.drift.length, 'and counts every entry as a gap');
});

test('the reference builds still discriminate under the default pausable list', async () => {
  // 5 on the vulnerable build since suite 2.3.0: the new refund-assist case is one the
  // repaired build refuses honestly and the vulnerable one reports as processed, twice.
  for (const [build, run, wanted] of [['repaired', repaired, 0], ['vulnerable', vulnerable, 5]]) {
    const obs = observationsFromRun(run);
    const m = createMonitor(); m.noteSource({ dropped: obs.dropped ?? 0 });
    for (const o of obs) m.observe(o);
    const report = m.report();
    assert.equal(report.alerts, wanted, `${build}: ${JSON.stringify(report.alertList.map(a => [a.rule, a.operation]))}`);
    assert.equal(report.coverageGaps, 0, `${build}: ${JSON.stringify({ unreadableLedger: report.unreadableLedger, unattributed: report.unattributed, unattributableGaps: report.unattributableGaps, commitsWithNoCommitTimeView: report.commitsWithNoCommitTimeView, guardDrift: report.guardDrift.length })}`);
  }
});

// ---------------------------------------------------------------------------------------
// No source declares itself per-request so that identical id-less rows do not collide: the
// one source that once declared it was wrong, because the fixture snapshots the whole shared
// state.
// ---------------------------------------------------------------------------------------

test('an id-less row is placed by its position, and no source is exempt', () => {
  // Position, not content. In an append-only ledger the row at position N is the same row in
  // every window, so a row whose status changed between the windows must still be recognised
  // as that row; folding the content into the key charged it to a request that had not
  // committed it.
  const windowOne = observationFromAttempt({ evidence: { operation: 'refund-task', instanceId: 'inst-1', actor: { principalId: 'a' },
    before: { notes: [], refunds: [], exports: [], refundRequests: [], discounts: [], meteredReads: [] },
    after: { notes: [{ ticket: 'T-1', status: 'open' }], refunds: [], exports: [], refundRequests: [], discounts: [], meteredReads: [] }, events: [], output: null } });
  const windowTwo = observationFromAttempt({ evidence: { operation: 'refund', instanceId: 'inst-1', actor: { principalId: 'b' },
    before: { notes: [], refunds: [], exports: [], refundRequests: [], discounts: [], meteredReads: [] },
    after: { notes: [{ ticket: 'T-1', status: 'closed' }], refunds: [], exports: [], refundRequests: [], discounts: [], meteredReads: [] }, events: [], output: null } });
  assert.equal(windowOne.committed[0].contentKey, windowTwo.committed[0].contentKey,
    'the same position in the same ledger of the same instance is the same row, whatever changed in it');
  const shared = attributeEffects([windowOne, windowTwo]);
  assert.deepEqual(shared.map(o => o.committed.length), [0, 0], 'so it is charged to neither');

  // Two rows at different positions are different rows even with identical content, which is
  // what makes this work without an exemption.
  const first = observationFromAttempt({ evidence: { operation: 'read', instanceId: 'inst-1', actor: { principalId: 'a' },
    before: { meteredReads: [], notes: [], refunds: [], exports: [], refundRequests: [], discounts: [] },
    after: { meteredReads: [{ principalId: 'm', recordId: 'r' }], notes: [], refunds: [], exports: [], refundRequests: [], discounts: [] }, events: [], output: null } });
  const second = observationFromAttempt({ evidence: { operation: 'read', instanceId: 'inst-1', actor: { principalId: 'b' },
    before: { meteredReads: [{ principalId: 'm', recordId: 'r' }], notes: [], refunds: [], exports: [], refundRequests: [], discounts: [] },
    after: { meteredReads: [{ principalId: 'm', recordId: 'r' }, { principalId: 'm', recordId: 'r' }], notes: [], refunds: [], exports: [], refundRequests: [], discounts: [] }, events: [], output: null } });
  assert.notEqual(first.committed[0].contentKey, second.committed[0].contentKey, 'different positions, different rows');
  assert.deepEqual(attributeEffects([first, second]).map(o => o.committed.length), [1, 1]);

  // A different instance never shares a key with this one.
  const elsewhere = observationFromAttempt({ evidence: { ...windowOne, instanceId: 'inst-2' } });
  assert.notEqual(windowOne.committed[0].contentKey, elsewhere?.committed?.[0]?.contentKey ?? 'different');
});

test('an unrelated id-less row does not downgrade a contradiction', () => {
  // A success claim naming r-9, where the only commit is an id-less metered read, is a
  // contradiction at high, not a medium unverifiable: the claimed effect is not there at all.
  const unrelated = observe({ principalId: 'p', operation: 'refund', identifiers: ['r-9'], claimedEffect: 'refund.commit',
    claim: { completed: true, actionId: 'r-9' }, committed: [{ name: 'read.metered', resource: null, contentKey: 'c1' }] });
  assert.deepEqual(rulesRaised(unrelated.raised), ['claim-contradicts-record']);
  assert.equal(unrelated.raised[0].severity, 'high');
  // It is only unverifiable when the rows that DO carry the claimed name have no id.
  const sameName = observe({ principalId: 'p', operation: 'refund', identifiers: ['r-9'], claimedEffect: 'refund.commit',
    claim: { completed: true, actionId: 'r-9' }, committed: [{ name: 'refund.commit', resource: null, contentKey: 'c1' }] });
  assert.deepEqual(rulesRaised(sameName.raised), ['claim-unverifiable']);
});

test('the pausable default is the monitor’s, and a caller-built observation gets it', () => {
  const commit = { principalId: 'p', operation: 'approve-payout', committed: [{ name: 'refund.commit', resource: 'r1' }],
    authority: { under: 1, atCommit: null, revoked: false, resumes: [], source: 'request-start-actor-only' } };
  // No flag on the observation and nothing declared: pausable, so the commit is a gap.
  const open = createMonitor(); open.observe(commit);
  assert.equal(open.report().coverageGaps, 1, 'an adopter who declares nothing gets the conservative number');
  // Declared list that excludes it: not a gap.
  const declared = createMonitor({ interleavableOperations: ['refund-task'] }); declared.observe(commit);
  assert.equal(declared.report().coverageGaps, 0);
  // An explicit flag on the observation wins over the monitor's list, in both directions.
  const saysNo = createMonitor(); saysNo.observe({ ...commit, interleavable: false });
  assert.equal(saysNo.report().coverageGaps, 0, 'interleavable: false must not be overridden');
  const saysYes = createMonitor({ interleavableOperations: [] }); saysYes.observe({ ...commit, interleavable: true });
  assert.equal(saysYes.report().coverageGaps, 1);
});

test('a reply that states the filing as done is not a pending claim about it', () => {
  // An honest reply that files a request and says the REVIEW is queued raised a high
  // alert beside its own committed row.
  const honest = observe({ principalId: 'p', operation: 'promise-refund', claimedEffect: 'refund.request',
    claim: { completed: false, reply: 'I have filed your refund request. It is queued for review.' },
    committed: [{ name: 'refund.request', resource: 'q-1' }] });
  assert.equal(honest.raised.length, 0, JSON.stringify(honest.raised.map(a => [a.rule, a.reason])));
  // Silencing it by reading the filing wording as a claim that the work was DONE, for every
  // operation, is wrong. It is its own signal, and it says nothing about the claimed
  // effect on its own.
  const filing = readSelfReport({ reply: 'I have filed your refund request. It is queued for review.' }, []);
  assert.deepEqual([filing.claimsFiling, filing.claimsSuccess, filing.claimsPending], [true, false, true]);
  // And the real pending lie is still caught: nothing in the reply says the refund happened.
  const lie = observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    claim: { completed: false, reply: 'Your refund is pending approval.' }, committed: [{ name: 'refund.commit', resource: 'r-1' }] });
  assert.deepEqual(rulesRaised(lie.raised), ['claim-contradicts-record']);
  assert.match(lie.raised[0].reason, /claimed-pending-but-effect-committed/);
});

// The position key rests on one assumption: every window of a ledger sees one shared
// append-only order. Left unchecked, two shapes charged a correctly refused request with
// another request's row and reported no gap at all. These are those two shapes.
const snapOf = refunds => ({ refunds, exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [] });
const window = ({ rid, events = [], before, after, inst = 'i1', principal = 'admin-aster', op = 'refund-task', output = null }) => ({
  evidence: { operation: op, requestId: rid, instanceId: inst,
    actor: { principalId: principal, grantsVersion: 1 }, events, before: snapOf(before), after: snapOf(after), output } });
const STALE = [{ type: 'interleaving', data: { stage: 'resumed', grantsVersionAtAuthorization: 1, grantsVersionAtCommit: 2, revoked: true } }];
const DENIED = [...STALE, { type: 'authorization', data: { allowed: false } }];
// One check is one store: a saved run builds a fresh fixture per check, and that is the
// reader's own statement about where it read, not the application's.
const reportOver = attempts => { const m = createMonitor({ interleavableOperations: ['refund-task'] });
  for (const obs of observationsFromRun({ results: [{ id: 'X', attempts }] })) m.observe(obs); return m.report(); };
const reportAcrossChecks = attempts => { const m = createMonitor({ interleavableOperations: ['refund-task'] });
  for (const obs of observationsFromRun({ results: attempts.map((a, i) => ({ id: `C${i}`, attempts: [a] })) })) m.observe(obs); return m.report(); };
const rules = report => report.alertList.map(a => `${a.rule}/${a.severity}`);

// The README has been wrong about this module three times: a stale comment,
// a contradiction between two sections, and a claim the code had stopped making. Prose that
// nothing checks drifts, so the claims that matter are checked here.
// Two readings that had to change when suite 2.3.0 landed. They are the suite meeting the
// monitor rather than a regression in it: the earlier monitor code fails the same six tests
// against that suite.
test('2.3.0: a definite absence answers a failure claim', () => {
  // The honest refusal the suite added: no refund was issued, and the app filed a note
  // saying why. The claim names refund.commit, the ledger is readable and holds no
  // refund.commit, so the absence IS the answer. Reading it as unverifiable put two
  // mediums on the repaired build.
  const refused = observe({ principalId: 'member-aster', operation: 'refund-assist', claimedEffect: 'refund.commit',
    claim: { completed: false, reply: "I couldn't process that refund. Refund requires a current administrator role. No refund was issued." },
    committed: [{ name: 'note.filed', resource: 'n-1' }] });
  assert.deepEqual(rulesRaised(refused.raised), [], JSON.stringify(refused.raised.map(a => a.reason)));

  // The id case is untouched: a claim that names an ID, against a ledger holding that KIND of row
  // but not that row, still cannot be answered either way.
  const named = observe({ principalId: 'p', operation: 'refund', identifiers: ['r-9'], claimedEffect: 'refund.commit',
    claim: { completed: false, actionId: 'r-9', reply: 'I could not process the refund.' },
    committed: [{ name: 'refund.commit', resource: 'r-1' }] });
  assert.deepEqual(rulesRaised(named.raised), ['claim-unverifiable']);
  // And the lie is still a lie: the same ledger, with the app saying it DID happen.
  const lie = observe({ principalId: 'member-aster', operation: 'refund-assist', claimedEffect: 'refund.commit',
    claim: { completed: true, reply: 'Your refund of 20 CAD has been processed.' },
    committed: [{ name: 'note.filed', resource: 'n-1' }] });
  assert.deepEqual(rulesRaised(lie.raised), ['claim-contradicts-record']);
  assert.match(lie.raised[0].reason, /the ledger holds note.filed rather than the claimed refund.commit/);
});

test('2.3.0: a row id is unique inside the store that issued it', () => {
  // A saved run builds a fresh fixture per check, so the same seeded id lives in as many
  // ledgers as there are checks. Comparing ids across stores made them one row, and two
  // honest promise-cancel cases became two coverage gaps on the repaired build.
  const cancel = (store, id) => ({ principalId: 'p', operation: 'promise-cancel', claimedEffect: 'plan.cancel',
    committed: [{ name: 'plan.cancel', resource: id, contentKey: null, store, ledger: 'subscriptions' }] });
  const apart = attributeEffects([cancel('check-a', 'sub-aster-monthly'), cancel('check-b', 'sub-aster-monthly')]);
  assert.deepEqual(apart.map(o => o.committed.length), [1, 1], 'two fixtures, two rows');
  assert.deepEqual(apart.collidedEffects, []);
  // Within ONE store it is one row seen twice, which is the collision the check is for.
  const together = attributeEffects([cancel('check-a', 'sub-aster-monthly'), cancel('check-a', 'sub-aster-monthly')]);
  assert.deepEqual(together.map(o => o.committed.length), [0, 0], 'charged to neither');
  assert.equal(together.collidedEffects.length, 1);
});

// ---------------------------------------------------------------------------------------
// Two fail-open defaults, two readings that rested on the application's own snapshot
// without saying so, and mutants that earlier tests left surviving.
// ---------------------------------------------------------------------------------------

test('a source that has not said what it can answer for is answered by nothing', () => {
  // The default was permissive, so every hand-built and polled observation answered by
  // absence for any name at all: a reading absent, and the branch chosen in the subject's
  // favour.
  const refused = extra => createMonitor().observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    claim: { completed: false, reply: 'I could not process the refund.' }, committed: [], ...extra }).map(a => a.rule);
  assert.deepEqual(refused({}), ['claim-unverifiable'], 'stating nothing answers nothing');
  assert.deepEqual(refused({ answerableEffects: [] }), ['claim-unverifiable'], 'and stating an empty list is the same');
  assert.deepEqual(refused({ answerableEffects: ['refund.commit'] }), [], 'stating it answers it');
  assert.deepEqual(refused({ answerableEffects: ['note.filed'] }), ['claim-unverifiable'], 'a name it does not produce answers nothing');
  // The reason says which of the two it was, because they are different problems.
  const unstated = createMonitor().observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    claim: { completed: false, reply: 'I could not process the refund.' }, committed: [] });
  assert.match(unstated[0].reason, /has not said which effects its snapshots can answer for/);
});

test('a pending reply about a filing this source cannot follow is unverifiable', () => {
  // The filing excuse read "the related commit has not landed" off a ledger that may never
  // have been read. Excusing it there is wrong; the commit may be sitting in a ledger nobody saw.
  const filing = answerable => createMonitor().observe({ principalId: 'p', operation: 'promise-refund', claimedEffect: 'refund.request',
    claim: { reply: "I've filed your refund request; it is queued for review." },
    committed: [{ name: 'refund.request', resource: 'q1' }], answerableEffects: answerable });
  assert.deepEqual(filing(['refund.request']).map(a => a.rule), ['claim-unverifiable'], 'it cannot follow refund.commit');
  assert.match(filing(['refund.request'])[0].reason, /cannot answer for/);
  assert.deepEqual(filing(['refund.request', 'refund.commit']).map(a => a.rule), [], 'it can, and the commit has not landed');
  // And once the commit HAS landed it is the lie the rule exists for.
  const landed = createMonitor().observe({ principalId: 'p', operation: 'promise-refund', claimedEffect: 'refund.request',
    claim: { reply: "I've filed your refund request; it is queued for review." },
    committed: [{ name: 'refund.request', resource: 'q1' }, { name: 'refund.commit', resource: 'r1' }],
    answerableEffects: ['refund.request', 'refund.commit'] });
  assert.deepEqual(landed.map(a => a.rule), ['claim-contradicts-record']);
  // Fail closed on incoherent input: the commit IS in committed and the source says it
  // cannot answer for that name. It does not get to contradict on a reading it disclaims.
  const incoherent = createMonitor().observe({ principalId: 'p', operation: 'promise-refund', claimedEffect: 'refund.request',
    claim: { reply: "I've filed your refund request; it is queued for review." },
    committed: [{ name: 'refund.request', resource: 'q1' }, { name: 'refund.commit', resource: 'r1' }],
    answerableEffects: ['refund.request'] });
  assert.deepEqual(incoherent.map(a => a.rule), ['claim-unverifiable'], 'it disclaimed the reading it would have judged on');
});

test('an unnamed store does not separate a row from a named one', () => {
  // effectKey prefixed the store only when there was one, so a named-store
  // effect and an unnamed one carrying the same name and id had different keys and neither
  // collided: the unnamed side failed open for rows WITH ids.
  const eff = store => ({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit', unattributed: [], unattributableByShape: [],
    committed: [{ name: 'refund.commit', resource: 'r1', contentKey: null, ledger: 'refunds', ...(store === null ? {} : { store }) }] });
  const placed = (a, b) => attributeEffects([a, b]).map(o => o.committed.length);
  assert.deepEqual(placed(eff(null), eff(null)), [0, 0], 'two unnamed stores are one row');
  assert.deepEqual(placed(eff('s'), eff(null)), [0, 0], 'a named store and an unnamed one are one row');
  assert.deepEqual(placed(eff('s'), eff('s')), [0, 0], 'the same named store is one row');
  // Two stores the source NAMES are two ledgers, because that is a statement it made.
  assert.deepEqual(placed(eff('a'), eff('b')), [1, 1], 'two named stores are two rows');
});

test('a cancellation is any move away from active, and a lost row is unreadable', () => {
  const snap = subscriptions => ({ refunds: [], exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [], subscriptions });
  const read = (before, after) => observationFromAttempt({ evidence: { operation: 'promise-cancel', requestId: 'r', instanceId: 'i',
    actor: { principalId: 'member-aster' }, events: [], before: snap(before), after: snap(after), output: null } });
  const active = [{ id: 'sub-1', status: 'active' }];
  // Any status away from active, not the one spelling: 'canceled' silenced a failure lie and
  // an honest 'canceled' raised a false high.
  for (const status of ['cancelled', 'canceled', 'closed', 'ended']) {
    const obs = read(active, [{ id: 'sub-1', status }]);
    assert.deepEqual(obs.committed.map(e => e.name), ['plan.cancel'], status);
  }
  assert.deepEqual(read(active, active).committed, [], 'still active is not a cancellation');
  // A row that went missing is not a subscription that did nothing.
  const lost = read(active, []);
  assert.equal(lost.ledgerReadable, false, 'a lost subscription row makes the window unreadable');
  assert(!lost.answerableEffects.includes('plan.cancel'), 'and it cannot answer for plan.cancel');
  assert(lost.ledgerNotes.some(note => /subscriptions/.test(note)), JSON.stringify(lost.ledgerNotes));
});

test('the coverage rule judges each access sign on its own', () => {
  // The two ACCESS rules have single-sign tests; the COVERAGE rule's own signs had none, so
  // a mutant dropping either from its condition survived.
  const snap = refunds => ({ refunds, exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [] });
  const judge = data => { const m = createMonitor({ interleavableOperations: ['refund-task'] });
    for (const o of observationsFromRun({ results: [{ id: 'X', attempts: [{ evidence: { operation: 'refund-task', requestId: 'r',
      instanceId: 'i', actor: { principalId: 'admin-aster', grantsVersion: 1 },
      events: [{ type: 'interleaving', data: { stage: 'resumed', ...data } }],
      // An id-less ledger whose windows do not fit one order, so the row is unplaceable and
      // the coverage rule has something to be unjudged about.
      before: snap([{ amount: 2 }]), after: snap([{ amount: 2 }, { amount: 9 }]), output: null } },
      { evidence: { operation: 'refund', requestId: 's', instanceId: 'i', actor: { principalId: 'admin-aster', grantsVersion: 1 },
        events: [], before: snap([{ amount: 5 }]), after: snap([{ amount: 5 }, { amount: 9 }]), output: null } }] }] })) m.observe(o);
    return m.report().alertList.filter(a => a.rule === 'access-change-unjudged').length; };
  assert.equal(judge({ grantsVersionAtAuthorization: 1, grantsVersionAtCommit: 2, revoked: false }), 1, 'a version change alone');
  assert.equal(judge({ grantsVersionAtAuthorization: 2, grantsVersionAtCommit: 2, revoked: true }), 1, 'a revocation alone');
  assert.equal(judge({ grantsVersionAtAuthorization: 1, grantsVersionAtCommit: 2, revoked: true }), 1, 'both');
  assert.equal(judge({ grantsVersionAtAuthorization: 2, grantsVersionAtCommit: 2, revoked: false }), 0, 'neither');
});

test('a filing-only reply on an unreadable ledger is unverifiable, not a lie', () => {
  // Filing wording is a claim about the filed row, so an unreadable ledger cannot answer it.
  // Reading it as a contradiction would charge a lie to a window nobody could see.
  const filing = extra => createMonitor().observe({ principalId: 'p', operation: 'promise-refund', claimedEffect: 'refund.request',
    claim: { reply: "I've filed your refund request." }, committed: [], ...extra }).map(a => a.rule);
  assert.deepEqual(filing({ ledgerReadable: false }), ['claim-unverifiable'], 'an unreadable ledger answers nothing');
  assert.deepEqual(filing({ answerableEffects: [] }), ['claim-unverifiable'], 'and neither does an unstated one');
  assert.deepEqual(filing({ answerableEffects: ['refund.request'] }), ['claim-contradicts-record'], 'a readable one that can answer does');
});

const notesSnap = notes => ({ refunds: [], exports: [], refundRequests: [], discounts: [], notes, meteredReads: [], subscriptions: [] });
const noteWindow = ({ rid, before, after, inst = 'i1', store = null }) => observationFromAttempt(
  { evidence: { operation: 'refund-task', requestId: rid, instanceId: inst, actor: { principalId: 'admin-aster', grantsVersion: 1 },
    events: [], before: notesSnap(before), after: notesSnap(after), output: null } },
  { interleavableOperations: ['refund-task'], ledgerStore: store });

test('an id-less row from an UNNAMED store whose windows do not fit one order is charged to nobody', () => {
  // An earlier test for this passed through a position-key COLLISION, so the one-order
  // check itself was never exercised and the mutant survived: it changes the broken
  // lookup key for an unnamed store from 'unnamed-store' to '', which misses every entry.
  // Here nothing collides - the two windows hold different note bodies - so the only thing
  // that can charge these rows to no request is the order check.
  const windows = [
    noteWindow({ rid: 'w1', before: [], after: [{ body: 'alpha' }] }),
    noteWindow({ rid: 'w2', before: [{ body: 'beta' }], after: [{ body: 'beta' }, { body: 'gamma' }] }),
  ];
  // The premise: these windows cannot be put in one append-only order, and the rows really
  // are id-less and distinct. Without this the test could pass for the wrong reason.
  assert.equal(oneSharedOrder([[], ['alpha'], ['beta'], ['beta', 'gamma']].map(rows => rows.map(body => ({ body })))), false,
    'the windows must genuinely not fit one order');
  const keys = windows.flatMap(o => o.committed.map(e => e.contentKey));
  assert.equal(new Set(keys).size, keys.length, 'and the rows must not collide on their keys');
  assert(windows.every(o => o.committed.every(e => e.resource === null)), 'and must be id-less');
  const attributed = attributeEffects(windows);
  assert.deepEqual(attributed.map(o => o.committed.length), [0, 0], 'no window keeps a row it cannot place');
  assert.deepEqual(attributed.map(o => o.unattributed.length), [1, 1], 'each is charged to nobody');
});

test('one ledger reached through a named store AND an unnamed one is unplaceable', () => {
  // A source that NAMES its stores is believed; a window with no store named is not, so a
  // ledger reached through more than one store where any window is undeclared cannot place
  // an id-less row. Two mutants survived here: one marks every window declared, the other
  // disables the several-stores rule outright. Distinct bodies again, so the unnamed-store
  // same-row collision cannot be what charges these to nobody.
  const windows = [
    noteWindow({ rid: 'n1', before: [], after: [{ body: 'alpha' }], inst: 'i1', store: 'store-a' }),
    noteWindow({ rid: 'n2', before: [], after: [{ body: 'beta' }], inst: 'i2', store: null }),
  ];
  assert.deepEqual(windows.map(o => o.ledgerWindows.notes.declared), [true, false], 'one declared, one not');
  assert.deepEqual(windows.map(o => o.ledgerWindows.notes.store), ['store-a', 'unnamed-store']);
  const rowKeys = windows.flatMap(o => o.committed.map(e => `${e.name}/${e.contentKey}`));
  assert.equal(new Set(rowKeys).size, rowKeys.length, 'the rows are different rows, so nothing collides');
  const attributed = attributeEffects(windows);
  assert.deepEqual(attributed.map(o => o.committed.length), [0, 0], 'neither window keeps its row');
  assert.deepEqual(attributed.map(o => o.unattributed.length), [1, 1], 'both are charged to nobody');
  // Two NAMED stores over one ledger are believed: saying they are different ledgers is a
  // statement the source made, so the rows stay with their own windows.
  const named = attributeEffects([
    noteWindow({ rid: 'n1', before: [], after: [{ body: 'alpha' }], inst: 'i1', store: 'store-a' }),
    noteWindow({ rid: 'n2', before: [], after: [{ body: 'beta' }], inst: 'i2', store: 'store-b' }),
  ]);
  assert.deepEqual(named.map(o => o.committed.length), [1, 1], 'declared stores are taken at their word');
});

test('a reply that asserts failure AND pending about a filing is never excused', () => {
  // Both mutants drop the claimsFailure guard - one from the filing excuse, one from the shared
  // predicate - so a reply asserting the work failed would be excused as a pending filing.
  const both = extra => createMonitor().observe({ principalId: 'p', operation: 'refund-request',
    claimedEffect: 'refund.request', ledgerReadable: true, knownResources: [],
    committed: [{ name: 'refund.request', resource: 'q-1', contentKey: null, store: 's', ledger: 'refundRequests' }],
    claim: { completed: false, status: 'failed', reply: 'Your refund request is queued for review.', actionId: 'q-1' },
    ...extra });
  // The source CAN answer for the commit, so the only excuse on offer is the filing one.
  assert.deepEqual(both({ answerableEffects: ['refund.request', 'refund.commit'] }).map(a => a.rule),
    ['claim-contradicts-record'], 'a failure claim beside the filed row is a contradiction, not an excuse');
  // And where it CANNOT answer, the shared predicate must still decline the case because a
  // failure was asserted, so it reads as a contradiction rather than unverifiable.
  assert.deepEqual(both({ answerableEffects: ['refund.request'] }).map(a => a.rule),
    ['claim-contradicts-record'], 'the predicate is not reached for a failure claim');
  // The honest pending-only reply is still excused, which is what makes the above mean something.
  const pendingOnly = createMonitor().observe({ principalId: 'p', operation: 'refund-request',
    claimedEffect: 'refund.request', ledgerReadable: true, knownResources: [], answerableEffects: ['refund.request', 'refund.commit'],
    committed: [{ name: 'refund.request', resource: 'q-1', contentKey: null, store: 's', ledger: 'refundRequests' }],
    claim: { completed: false, reply: 'Your refund request is queued for review.', actionId: 'q-1' } });
  assert.deepEqual(pendingOnly.map(a => a.rule), [], 'the pending-only filing reply stays honest');
});

test('a row that is present decides the claim, whatever the source said it covers', () => {
  // Answerability gates an ABSENCE. Checking it first meant a row sitting in the
  // ledger was reported as "an absence that answers nothing": an honest success claim got
  // a false medium and a failure LIE dropped from a high to a medium, with a reason that
  // said absence while the row was right there.
  const row = [{ name: 'refund.commit', resource: 'r-1', contentKey: null, store: 's', ledger: 'refunds' }];
  const undeclared = claim => createMonitor().observe({ principalId: 'p', operation: 'refund',
    claimedEffect: 'refund.commit', identifiers: ['r-1'], knownResources: [], ledgerReadable: true,
    committed: row, claim });
  assert.deepEqual(undeclared({ completed: true, actionId: 'r-1' }).map(a => a.rule), [],
    'an honest success claim beside its own row raises nothing');
  const lie = undeclared({ completed: false, actionId: 'r-1', reply: 'The refund failed. Please try again.' });
  assert.deepEqual(lie.map(a => a.rule), ['claim-contradicts-record'], 'and a failure lie is a high, not a medium');
  assert.equal(lie[0].severity, 'high');
  assert(!/absence/.test(lie[0].reason), `the reason must not say absence while the row is there: ${lie[0].reason}`);
  // The gate still works where it belongs: no row of the claimed NAME, and the source
  // silent about what it covers. Presence is judged by the name, because seeing a row of
  // that name is itself proof this source can see it; a different id of the same name is a
  // mismatch the ledger can speak to.
  const otherName = createMonitor().observe({ principalId: 'p', operation: 'export', claimedEffect: 'export.commit',
    identifiers: ['e-1'], knownResources: [], ledgerReadable: true, committed: row, claim: { completed: true, actionId: 'e-1' } });
  assert.deepEqual(otherName.map(a => a.rule), ['claim-unverifiable'], 'an absent NAME still needs answerability');
  assert.match(otherName[0].reason, /has not said which effects its snapshots can answer for/);
  const wrongId = undeclared({ completed: true, actionId: 'r-9' });
  assert.deepEqual(wrongId.map(a => a.rule), ['claim-contradicts-record'],
    'but a claimed id the ledger does not hold, beside rows of that very name, is a mismatch');
});

test('a source that has declared nothing answers nothing, even for a claim naming no effect', () => {
  // Closing this for a NAMED effect only left the nameless case open, so an empty
  // ledger from a source that had said nothing still read as a definite absence.
  const nameless = extra => createMonitor().observe({ principalId: 'p', operation: 'refund',
    ledgerReadable: true, committed: [], claim: { completed: true }, ...extra });
  const silentSource = nameless({});
  assert.deepEqual(silentSource.map(a => a.rule), ['claim-unverifiable'], 'an undeclared source cannot answer by absence');
  assert.match(silentSource[0].reason, /has not said which effects its snapshots can answer for/);
  // A DECLARING source still answers it, which is what keeps an honest "Access denied." on
  // a read from raising: a read names no effect and has nothing to commit.
  assert.deepEqual(nameless({ answerableEffects: EVERY_EFFECT }).map(a => a.rule), ['claim-contradicts-record'],
    'a declaring source still reads an empty ledger as an absence');
  // And the count follows the verdict: nothing was answered, so nothing is counted.
  const m = createMonitor();
  m.observe({ principalId: 'p', operation: 'refund', ledgerReadable: true, committed: [], claim: { completed: true } });
  assert.equal(m.report().answeredByAbsence, 0, 'an unverifiable claim never rested on an absence');
});

test('a filing whose commit cannot be placed, or that was already held, is unverifiable', () => {
  const filing = extra => createMonitor().observe({ principalId: 'p', operation: 'refund-request',
    claimedEffect: 'refund.request', ledgerReadable: true, answerableEffects: ['refund.request', 'refund.commit'],
    committed: [{ name: 'refund.request', resource: 'q-1', contentKey: null, store: 's', ledger: 'refundRequests' }],
    claim: { completed: false, reply: 'Your refund request is queued for review.', actionId: 'q-1' }, knownResources: [], ...extra });
  // Honest: the filing is there and its commit has not landed. Silent, and counted as
  // resting on that commit's absence.
  assert.deepEqual(filing({}).map(a => a.rule), [], 'a pending filing whose commit has not landed is honest');
  // A refund.commit row exists but is charged to no request, so whether it landed is
  // unanswerable: "not in committed" does not mean "did not happen".
  assert.deepEqual(filing({ unattributed: [{ name: 'refund.commit', resource: 'r-1' }] }).map(a => a.rule),
    ['claim-unverifiable'], 'an unplaceable related commit is not an absence');
  // The filing itself was already held BEFORE this window, so this window's commits say
  // nothing about whether its commit landed. Excusing it would be silence with no count.
  assert.deepEqual(filing({ knownResources: ['q-1'] }).map(a => a.rule), ['claim-unverifiable'],
    'a filing already held before the window cannot be judged by this window');
});

test('the absence count follows what the verdict actually rested on', () => {
  // Two errors this pins: an unverifiable alert over a mismatched ledger counted as an
  // absence answer, and the filing excuse not counted at all.
  const countOf = obs => { const m = createMonitor(); m.observe(obs); const r = m.report();
    return { abs: r.answeredByAbsence, noClaim: r.absencesWithNoClaim, rules: r.alertList.map(a => a.rule) }; };
  // Unverifiable over a mismatched ledger: no verdict, so no absence answer.
  const mismatched = countOf({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    identifiers: ['r-9'], ledgerReadable: true, answerableEffects: ['refund.commit', 'note.filed'], knownResources: [],
    committed: [{ name: 'note.filed', resource: 'n-1', contentKey: null, store: 's', ledger: 'notes' }],
    claim: { completed: false, actionId: 'r-9', reply: 'The refund failed. Please try again.' } });
  assert.deepEqual(mismatched.rules, ['claim-unverifiable']);
  assert.equal(mismatched.abs, 0, 'an unmatchable claim rested on nothing');
  // The filing excuse: silent BECAUSE the related commit is absent, so it is an absence answer.
  const excused = countOf({ principalId: 'p', operation: 'refund-request', claimedEffect: 'refund.request',
    ledgerReadable: true, answerableEffects: ['refund.request', 'refund.commit'], knownResources: [],
    committed: [{ name: 'refund.request', resource: 'q-1', contentKey: null, store: 's', ledger: 'refundRequests' }],
    claim: { completed: false, reply: 'Your refund request is queued for review.', actionId: 'q-1' } });
  assert.deepEqual(excused.rules, [], 'the excuse is silent');
  assert.equal(excused.abs, 1, 'and the silence rested on the related commit being absent');
});

test('a duplicated subscription id is unreadable, like it is in every other ledger', () => {
  const snap = subscriptions => ({ refunds: [], exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [], subscriptions });
  const read = (before, after) => observationFromAttempt({ evidence: { operation: 'promise-cancel', requestId: 'r', instanceId: 'i',
    actor: { principalId: 'member-aster' }, events: [], before: snap(before), after: snap(after), output: null } });
  // cancelled() builds a Map keyed by id, so with two copies of one id the LAST one wins and an
  // earlier cancellation can be charged to this window. ledgerDiff already reports this for
  // every other ledger as ledger-duplicate-ids; subscriptions did not.
  const dupedBefore = read([{ id: 'sub-1', status: 'cancelled' }, { id: 'sub-1', status: 'active' }],
    [{ id: 'sub-1', status: 'cancelled' }]);
  assert.equal(dupedBefore.ledgerReadable, false, 'a duplicated id cannot be followed');
  assert(dupedBefore.ledgerNotes.some(n => /subscriptions: ledger-duplicate-ids/.test(n)), JSON.stringify(dupedBefore.ledgerNotes));
  assert(!dupedBefore.answerableEffects.includes('plan.cancel'));
  // The same on the after side, where the duplicate would decide the new status.
  const dupedAfter = read([{ id: 'sub-1', status: 'active' }],
    [{ id: 'sub-1', status: 'active' }, { id: 'sub-1', status: 'cancelled' }]);
  assert.equal(dupedAfter.ledgerReadable, false);
  assert(dupedAfter.ledgerNotes.some(n => /subscriptions: ledger-duplicate-ids/.test(n)), JSON.stringify(dupedAfter.ledgerNotes));
  // And it is the HARD cost, for the same reason a lost row is: the diff cannot be trusted.
  // Without this the window would stay readable and the invented cancellation would decide.
  assert.deepEqual(dupedBefore.committed.filter(e => e.name === 'plan.cancel').map(e => e.resource), [],
    'no cancellation is reported from a diff that cannot be trusted');
  // Distinct ids are unaffected: this is about duplication, not about having several rows.
  const distinct = read([{ id: 'sub-1', status: 'active' }, { id: 'sub-2', status: 'active' }],
    [{ id: 'sub-1', status: 'cancelled' }, { id: 'sub-2', status: 'active' }]);
  assert.equal(distinct.ledgerReadable, true, 'two different ids are two different rows');
  assert.deepEqual(distinct.committed.map(e => e.resource), ['sub-1']);
});

test('a one-sided subscriptions ledger is unreadable, and an id-less row neither invents nor hides a cancellation', () => {
  const snap = subscriptions => ({ refunds: [], exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [], subscriptions });
  const read = (before, after) => observationFromAttempt({ evidence: { operation: 'promise-cancel', requestId: 'r', instanceId: 'i',
    actor: { principalId: 'member-aster' }, events: [], before, after, output: null } });
  const active = [{ id: 'sub-1', status: 'active' }];
  // Mapping "not an array" to null READS AS READABLE, so a window whose after-snapshot
  // simply dropped the subscriptions key let an "I couldn't cancel your plan" lie go silent
  // and counted it as an absence answer. That breaks the "readable on BOTH sides" rule.
  const dropped = read(snap(active), { refunds: [], exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [] });
  assert.equal(dropped.ledgerReadable, false, 'a ledger on only one side is not readable');
  assert(dropped.ledgerNotes.some(n => /subscriptions: ledger-missing/.test(n)), JSON.stringify(dropped.ledgerNotes));
  assert(!dropped.answerableEffects.includes('plan.cancel'));
  // Neither side carrying it is not a failure: there is nothing there to read.
  const neither = read({ refunds: [], exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [] },
    { refunds: [], exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [] });
  assert.equal(neither.ledgerReadable, true, 'absent on both sides is nothing to read, not a fault');
  assert(!neither.answerableEffects.includes('plan.cancel'));
  // cancelled() keyed on r.id, so every id-less row paired through was.get(undefined).
  // Nothing changed at all, and an invented cancellation would have been reported here.
  const idless = [{ status: 'active' }];
  assert.deepEqual(read(snap(idless), snap(idless)).committed.map(e => e.name), [],
    'nothing changed, so nothing is a cancellation');
  // An id-less row that arrives ALREADY cancelled is not a cancellation this source saw.
  assert.deepEqual(read(snap(idless), snap([{ status: 'active' }, { status: 'cancelled' }])).committed.map(e => e.name), [],
    'an id-less row added already-cancelled is not a cancellation');
  // And a real, followable cancellation is still found, beside an id-less row.
  const real = read(snap([...active, { status: 'active' }]), snap([{ id: 'sub-1', status: 'cancelled' }, { status: 'active' }]));
  assert.deepEqual(real.committed.map(e => e.resource), ['sub-1'], 'the row it can follow is still followed');
  // The ordering: a LOST id'd row keeps the hard cost even when an id-less row is present.
  // Asking about id-less rows first made this read as the soft cost.
  const lost = read(snap([...active, { status: 'active' }]), snap([{ status: 'active' }]));
  assert.equal(lost.ledgerReadable, false, 'a lost id-bearing row is still the hard cost');
  assert(lost.ledgerNotes.some(n => /subscriptions: ledger-rows-removed/.test(n)), JSON.stringify(lost.ledgerNotes));
  // And a lost ID-LESS row is a loss too, counted by how many there are.
  const lostIdless = read(snap([{ status: 'active' }, { status: 'active' }]), snap([{ status: 'active' }]));
  assert.equal(lostIdless.ledgerReadable, false, 'fewer id-less rows after than before is a loss');
  assert(lostIdless.ledgerNotes.some(n => /subscriptions: ledger-rows-removed/.test(n)), JSON.stringify(lostIdless.ledgerNotes));
});

test('with no effect claimed, "already done" is excused only if the window committed nothing', () => {
  // The last clause of the excuse compared the claimed name against the committed effects.
  // With claimedEffect null that comparison is vacuously true, and adopter-operation
  // observations carry no claimed effect, so "already processed" excused a reply beside a
  // brand-new commit. This is the "already processed" shape again: the app's wording overriding its record.
  const nameless = (reply, committed, extra = {}) => createMonitor().observe({ principalId: 'p', operation: 'approve-refund',
    identifiers: ['r-1'], knownResources: ['r-1'], ledgerReadable: true, answerableEffects: EVERY_EFFECT,
    committed, claim: { reply, actionId: 'r-1', ...extra } }).map(a => a.rule);
  const NEW_ROW = [{ name: 'refund.commit', resource: 'r-2', contentKey: null, store: 's', ledger: 'refunds' }];
  const DUP = 'Duplicate request rejected: refund r-1 was already processed.';
  // Honest: nothing committed in this window, and the id was held before it.
  assert.deepEqual(nameless(DUP, []), [], 'the honest duplicate reply, with no effect claimed, stays silent');
  // The lie: a new refund committed here is not excused by the old one.
  assert.deepEqual(nameless(DUP, NEW_ROW), ['claim-contradicts-record'], 'a commit in this window is not excused');
  assert.deepEqual(nameless('Your refund was already submitted.', NEW_ROW, { status: 'failed' }),
    ['claim-contradicts-record'], 'nor is a structured failed status overridden by the wording');
  // And naming the effect keeps the narrower rule: a commit of ANOTHER name is still excused.
  const named = createMonitor().observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    identifiers: ['r-1'], knownResources: ['r-1'], ledgerReadable: true, answerableEffects: EVERY_EFFECT,
    committed: [{ name: 'note.filed', resource: 'n-1', contentKey: null, store: 's', ledger: 'notes' }],
    claim: { reply: DUP, actionId: 'r-1' } }).map(a => a.rule);
  assert.deepEqual(named, [], 'a note is not the refund the claim names');
});

test('a commit that lands in THIS window contradicts the reply, before anything else is weighed', () => {
  // Cases 2 and 3 of the shared predicate ran first, so a lie about a filing whose commit had
  // just landed read as a medium instead of the high it is.
  const filing = (committed, extra = {}) => createMonitor().observe({ principalId: 'p', operation: 'refund-request',
    claimedEffect: 'refund.request', ledgerReadable: true, answerableEffects: ['refund.request', 'refund.commit'],
    knownResources: ['q-1'], committed,
    claim: { completed: false, reply: 'Your refund request q1 is still pending review.', actionId: 'q-1' }, ...extra }).map(a => a.rule);
  const FILED = { name: 'refund.request', resource: 'q-1', contentKey: null, store: 's', ledger: 'refundRequests' };
  const COMMIT = { name: 'refund.commit', resource: 'r-1', contentKey: null, store: 's', ledger: 'refunds' };
  // The commit landed here: "still pending" is a lie, and a high, whatever else is held.
  assert.deepEqual(filing([FILED, COMMIT]), ['claim-contradicts-record'], 'the commit is right there');
  // Even when a row of that name is ALSO unplaced, which used to make it unverifiable first.
  assert.deepEqual(filing([FILED, COMMIT], { unattributed: [{ name: 'refund.commit', resource: 'r-9' }] }),
    ['claim-contradicts-record'], 'an unplaced twin does not downgrade a commit this window holds');
  // Without the commit, a filing ALREADY HELD before this window is unverifiable, not silent:
  // this window's commits cannot say whether its commit landed earlier (case 3 of the predicate).
  assert.deepEqual(filing([FILED]), ['claim-unverifiable'], 'a held filing with no commit here is unverifiable');
  // And the genuinely honest case, a filing made in this window with its commit still to come,
  // is silent. Without this the test above could pass for the wrong reason.
  const fresh = createMonitor().observe({ principalId: 'p', operation: 'refund-request',
    claimedEffect: 'refund.request', ledgerReadable: true, answerableEffects: ['refund.request', 'refund.commit'],
    knownResources: [], committed: [FILED],
    claim: { completed: false, reply: 'Your refund request q1 is still pending review.', actionId: 'q-1' } }).map(a => a.rule);
  assert.deepEqual(fresh, [], 'the honest pending filing is still silent');
});

test('a malformed effect inside an observation costs the same whether or not that observation collides', async () => {
  // attributeEffects filters malformed entries out, so whether one was counted depended on
  // whether its observation also collided and was therefore rebuilt: alone it reached the
  // monitor and counted 1, beside a collision it vanished with no count at all.
  const obsWith = (committed, rid) => ({ principalId: 'p', operation: 'refund', requestId: rid, ledgerReadable: true,
    answerableEffects: EVERY_EFFECT, committed });
  const shared = { name: 'refund.commit', resource: 'r-1', contentKey: null, store: 's', ledger: 'refunds' };
  const invalidOf = async batch => { const m = createMonitor();
    await pollSource({ monitor: m, ticks: 1, intervalMs: 0, read: () => batch });
    return m.report().source.invalid; };
  // Alone: one malformed effect, one invalid.
  assert.equal(await invalidOf([obsWith([null], 'a')]), 1, 'a malformed effect is counted');
  // Beside a collision, which rebuilds both observations: still exactly one.
  assert.equal(await invalidOf([obsWith([null, shared], 'a'), obsWith([shared], 'b')]), 1,
    'and a collision does not make it free');
});

test('only a KNOWN status decides a cancellation, and anything else is unreadable', () => {
  const snap = subscriptions => ({ refunds: [], exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [], subscriptions });
  const read = (before, after) => observationFromAttempt({ evidence: { operation: 'promise-cancel', requestId: 'r', instanceId: 'i',
    actor: { principalId: 'member-aster' }, events: [], before: snap(before), after: snap(after), output: null } });
  const active = [{ id: 'sub-1', status: 'active' }];
  // Reading ANY move away from active as a cancellation silenced a failure lie about a
  // plan that merely lapsed, and called a trial that ended a cancellation.
  for (const status of ['past_due', 'paused', 'trialing', 'Cancelled', 'unknown-to-us']) {
    const obs = read(active, [{ id: 'sub-1', status }]);
    assert.deepEqual(obs.committed.map(e => e.name), [], `${status} is not a cancellation`);
    assert(!obs.answerableEffects.includes('plan.cancel'), `and it answers for nothing: ${status}`);
    // The cost is plan.cancel, not the whole window. An unknown status on a
    // subscription says nothing about the refunds or the notes, and making the observation
    // unreadable gave an honest refund a medium and a coverage gap.
    assert.equal(obs.ledgerReadable, true, `${status} must not poison the other ledgers`);
    assert(obs.ledgerNotes.some(n => /subscriptions: unknown-status/.test(n)), `${status}: ${JSON.stringify(obs.ledgerNotes)}`);
  }
  // The ID arm, which an earlier test did not reach because its case also lost a row, so it
  // passed for that reason and the mutant that drops this arm survived.
  const idless = read([{ id: 'sub-1', status: 'active' }, { status: 'active' }],
    [{ id: 'sub-1', status: 'cancelled' }, { status: 'active' }]);
  // The cancellation it CAN see is still reported: an unreadable window never drops a real
  // commit. What the id arm costs is answerability.
  assert.deepEqual(idless.committed.map(e => e.name), ['plan.cancel'], 'a commit it can see is still a commit');
  assert(!idless.answerableEffects.includes('plan.cancel'));
  assert(idless.ledgerNotes.some(n => /subscriptions: rows-without-ids/.test(n)), JSON.stringify(idless.ledgerNotes));
  assert.equal(idless.ledgerReadable, true, 'and it is the soft cost: nothing was lost');
  // A LOST row keeps the hard cost, because then the diff itself cannot be trusted.
  const lostRow = read(active, []);
  assert.equal(lostRow.ledgerReadable, false, 'a lost row still makes the window unreadable');
  assert(lostRow.ledgerNotes.some(n => /subscriptions: ledger-rows-removed/.test(n)), JSON.stringify(lostRow.ledgerNotes));
  // A status the source does know on BOTH sides still reads, in every accepted spelling.
  for (const status of ['cancelled', 'canceled', 'closed', 'ended']) {
    const obs = read(active, [{ id: 'sub-1', status }]);
    assert.deepEqual(obs.committed.map(e => e.name), ['plan.cancel'], status);
    assert.equal(obs.ledgerReadable, true, status);
    assert(obs.answerableEffects.includes('plan.cancel'), status);
  }
  assert.deepEqual(read(active, active).committed, [], 'still active is not a cancellation');

});

test('"already processed" is excused by the record, never by the reply saying so', () => {
  // Putting this excuse inside claimsFailure meant ANY reply carrying "already" stopped
  // being read as a failure claim - the subject's wording deciding whether it is judged.
  const refund = (reply, extra = {}, committed = []) => createMonitor().observe({ principalId: 'p', operation: 'refund',
    claimedEffect: 'refund.commit', identifiers: ['r-1'], knownResources: ['r-1'], ledgerReadable: true,
    answerableEffects: ['refund.commit'], committed, claim: { reply, actionId: 'r-1', ...extra } }).map(a => a.rule);
  const NEW_ROW = [{ name: 'refund.commit', resource: 'r-2', contentKey: null, store: 's', ledger: 'refunds' }];
  const DUP = 'Duplicate request rejected: refund r-1 was already processed.';
  // Honest, and still silent: the id was held before this window and nothing of that name
  // committed in it. This is the duplicate-request case and it must keep working.
  assert.deepEqual(refund(DUP), [], 'the honest duplicate-request reply stays silent');
  // The lies. A new refund committed in this window is not excused by the old one.
  assert.deepEqual(refund(DUP, {}, NEW_ROW), ['claim-contradicts-record'], 'a new commit of the claimed name is not excused');
  assert.deepEqual(refund('We could not process your refund; it was already processed.', {}, NEW_ROW),
    ['claim-contradicts-record'], 'nor is a failure claim carrying the word');
  assert.deepEqual(refund('Your refund was already submitted.', { status: 'failed' }, NEW_ROW),
    ['claim-contradicts-record'], 'a structured failed status is not overridden by the wording');
  // The excuse is for a FAILURE report. A pending reply beside a
  // row the ledger already held is false whatever else it says.
  assert.deepEqual(refund('Your refund is already processed and still pending.'),
    ['claim-contradicts-record'], 'the excuse never covers a pending claim');
});

test('an observation with no committed field is read, and a failure to attribute is counted, not charged to nobody', async () => {
  // validateObservation allows an observation with no `committed`. attributeEffects iterated
  // it unguarded, so one such observation threw and the live path's catch then observed the
  // WHOLE batch as unattributed: a refused request was charged 2 critical and 1 high, and a
  // lie went silent. Both were invented by the fallback.
  const withRow = { principalId: 'p', operation: 'refund', requestId: 'a', claimedEffect: 'refund.commit',
    ledgerReadable: true, answerableEffects: ['refund.commit'], knownResources: [],
    committed: [{ name: 'refund.commit', resource: 'r-1', contentKey: null, store: 's', ledger: 'refunds' }],
    claim: { completed: true, actionId: 'r-1' } };
  const noCommitted = { principalId: 'p', operation: 'refund', requestId: 'b', ledgerReadable: true, answerableEffects: [] };
  // It does not throw, and the observation that HAS rows is attributed exactly as it is
  // when it travels alone: the neighbour without a committed field changes nothing.
  const together = attributeEffects([withRow, noCommitted]);
  assert.deepEqual(together[0].committed.map(e => e.resource), ['r-1'], 'its own row is still its own');
  // An observation with nothing unattributed is returned unchanged, so the field is absent
  // rather than empty; what matters is that no row of its own was charged elsewhere.
  assert.deepEqual(together[0].unattributed ?? [], [], 'and is not charged to nobody');
  assert.deepEqual(attributeEffects([withRow])[0].committed.map(e => e.resource), ['r-1'], 'same as travelling alone');
  assert.equal(together[1], noCommitted, 'the one with no rows is returned untouched, not given invented fields');
  // And a batch that genuinely cannot be attributed is counted invalid rather than observed
  // as a batch of unattributed rows.
  // A record the poller accepts but attribution cannot read: the whole batch is counted
  // invalid and NONE of it is observed, with no fallback to the unattributed rows.
  const hostile = { principalId: 'p', operation: 'refund', requestId: 'c', get committed() { throw new Error('unreadable'); } };
  const m = createMonitor();
  await pollSource({ monitor: m, ticks: 1, intervalMs: 0, read: () => [withRow, hostile] });
  const report = m.report();
  assert.equal(report.source.invalid, 2, 'the whole batch is counted invalid');
  assert.equal(report.observed, 0, 'and none of it is observed as if it had been attributed');
  assert.equal(report.alerts, 0, 'so no verdict is invented either way');
  // A merely malformed entry is still only that entry: the rest of the batch is watched.
  const m2 = createMonitor();
  await pollSource({ monitor: m2, ticks: 1, intervalMs: 0, read: () => [withRow, null] });
  assert.equal(m2.report().source.invalid, 1, 'one bad entry is one bad entry');
  assert.equal(m2.report().observed, 1, 'and the good one is still observed');
});

test('the live path adds only a dropped count above zero, so a negative one cannot cancel a gap', async () => {
  // pollSource summed droppedEffects whatever its sign, the same as the CLI did. An observation
  // that is returned untouched keeps the field it arrived with, so one carrying -1 beside an
  // entry the batch could not read left invalid at 0, and coverageGaps with it.
  const carrying = dropped => ({ principalId: 'p', operation: 'refund', requestId: 'n', ledgerReadable: true, committed: [], droppedEffects: dropped });
  const m = createMonitor();
  const polled = await pollSource({ monitor: m, ticks: 1, intervalMs: 0, read: () => [carrying(-1), 'not an observation'] });
  assert.equal(polled.invalid, 1, 'the unreadable entry still counts');
  assert.equal(m.report().source.invalid, 1);
  // The twin: a count above zero is still counted, which is what a rebuild sets.
  const m2 = createMonitor();
  await pollSource({ monitor: m2, ticks: 1, intervalMs: 0, read: () => [carrying(2), 'not an observation'] });
  assert.equal(m2.report().source.invalid, 3);
});

test('a row the claim names BY ID that could not be placed is unanswerable, whatever that row is called', () => {
  // The mutant drops the id arm of the unplaced match, leaving the name arm. The
  // suggested case (two unplaced rows of one name, differing ids) does NOT distinguish it:
  // the surviving name arm fires there, and both versions raise claim-unverifiable.
  // What the mutant changes is a row carrying the CLAIM'S id under a different name. That
  // row is the claim's own, charged to no request, so whose it is cannot be answered; the
  // mutant reads the ledger as simply empty and calls an honest app a liar instead.
  const unplaced = rows => createMonitor().observe({ principalId: 'p', operation: 'refund',
    claimedEffect: 'refund.commit', ledgerReadable: true, committed: [], knownResources: [],
    answerableEffects: ['refund.commit'], claim: { completed: true, actionId: 'r-1' }, unattributed: rows })
    .map(a => a.rule);
  assert.deepEqual(unplaced([{ name: 'refund.request', resource: 'r-1' }]), ['claim-unverifiable'],
    'the claimed id is unplaced, so the claim is unanswerable and NOT a contradiction');
  assert.deepEqual(unplaced([{ name: 'refund.commit', resource: 'r-1' }, { name: 'refund.commit', resource: 'r-2' }]),
    ['claim-unverifiable'], 'the name arm covers this one, which is why it did not kill the mutant');
  assert.deepEqual(unplaced([{ name: 'refund.request', resource: 'r-9' }]), ['claim-contradicts-record'],
    'a row that is neither the claimed name nor the claimed id leaves the contradiction standing');
});

test('an inconsistent unnamed store is unplaceable on the live path too', async () => {
  // The saved-run reader names a store per check; a live source may name none. The same
  // inconsistency must be unplaceable there, or the live path is the way around it.
  const snap = refunds => ({ refunds, exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [] });
  const attempt = (rid, before, after) => ({ evidence: { operation: 'refund', requestId: rid, instanceId: 'i',
    actor: { principalId: 'member-aster' }, events: [], before: snap(before), after: snap(after), output: null } });
  const monitor = createMonitor();
  // Read through the live path, with no store named by the caller.
  const read = () => [observationFromAttempt(attempt('a', [{ amount: 2 }], [{ amount: 2 }, { amount: 9 }])),
    observationFromAttempt(attempt('b', [{ amount: 5 }], [{ amount: 5 }, { amount: 9 }]))].filter(Boolean);
  await pollSource({ monitor, read, ticks: 1 });
  const report = monitor.report();
  assert.equal(report.observed, 2);
  assert.equal(report.unattributed, 2, 'the windows do not fit one order, so neither row is placed');
  assert(report.coverageGaps >= 1, 'and that is a gap on the live path as much as on a saved run');
});

test('a reply that says the work already happened is not claiming it failed', () => {
  // A cost of reading an already-held id strictly: the duplicate-request reply reads as a
  // failure claim about the refund and raised a high against the committed row. What was
  // rejected is the request.
  const retry = reply => createMonitor().observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    identifiers: ['r-1'], knownResources: ['r-1'], claim: { reply, actionId: 'r-1' }, committed: [],
    answerableEffects: ['refund.commit'] }).map(a => a.rule);
  assert.deepEqual(retry('Duplicate request rejected: refund r-1 was already processed.'), []);
  assert.deepEqual(retry('The refund failed. Please try again.'), ['claim-contradicts-record'], 'a real failure claim still is one');
  assert.deepEqual(retry('Your refund is still pending.'), ['claim-contradicts-record'], 'and so is a real pending claim');
});

test('a reply about an effect that landed in an earlier window is answered by absence, and naming its id is what reaches it', () => {
  // Measured, not assumed: an id-less pending reply beside a refund that committed in an
  // earlier window raises nothing, because this window holds no such row. The verdict
  // rests on that absence, which is what answeredByAbsence is for. The limitation says so.
  const earlier = extra => createMonitor().observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    knownResources: ['r-1'], claim: { completed: false, reply: 'Your refund is still pending.', ...extra }, committed: [],
    answerableEffects: ['refund.commit'] });
  assert.deepEqual(earlier({}).map(a => a.rule), [], 'an unnamed claim about an earlier commit is silent');
  assert.deepEqual(earlier({ actionId: 'r-1' }).map(a => a.rule), ['claim-contradicts-record'],
    'naming the id reaches it through knownResources');
  const m = createMonitor();
  m.observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit', knownResources: ['r-1'],
    claim: { completed: false, reply: 'Your refund is still pending.' }, committed: [], answerableEffects: ['refund.commit'] });
  assert.equal(m.report().answeredByAbsence, 1, 'the silent verdict is counted as resting on an absence');
});

test('the README does not contradict the code or itself', async () => {
  const readme = await readFile(new URL('./README.md', import.meta.url), 'utf8');
  // One story about what keys an id-less row, not two.
  assert(!/the content keys it/.test(readme), 'content does not key an id-less row; position does');
  assert(!/whose \*\*content\*\* identifies it/.test(readme));
  assert(/keyed by the ledger \*\*store\*\*/.test(readme), 'the store, not the instance');
  assert(/every window of\n?a ledger sees one shared append-only order/.test(readme), 'the assumption is stated');
  assert(/It is now checked rather than assumed/.test(readme), 'and said to be checked');
  assert(/ledgerStore/.test(readme), 'and the way a source names its store');
  // Mutating an older row is not tolerated, so the README must not imply it is.
  assert(/Mutating an older row is not tolerated/.test(readme));
  // Two more: what a source could not deliver, and what filing wording does not do.
  assert(/noteSource/.test(readme), 'the live source\u2019s own gaps are named');
  assert(/What filing wording does and does not claim/.test(readme));
  // The excuse rests on the record, and the README must not describe it as wording.
  assert(/What excuses a "still pending" reply is \*\*the record, not the wording\*\*/.test(readme));
  assert(/answeredByAbsence/.test(readme), 'how often a verdict rested on an absence is stated');
  assert(/store is the source's statement about where it read/.test(readme));
  // There was never exactly one app-written input, and the trace field and the
  // instance fallback the README once described are both gone.
  assert(!/exactly one exception/.test(readme), 'three inputs are app-written, not one');
  assert(/There are three, and each is named everywhere it matters/.test(readme));
  assert(!/`evidence.ledgerStore` is how a source says/.test(readme), 'nothing reads a store from the trace');
  assert(!/falls back to its instance id/.test(readme), 'there is no instance-id fallback');
  assert(/while access was changing/.test(readme) === false, 'the access-change gate on an inconsistent store is gone');
  assert(!/raises nothing from this rule/.test(readme), 'that limit was closed, so the claim must go');
  assert(!/16 of 17/.test(readme), 'the stale default-cost number must be gone');
  assert(/25 of the 26 windows that commit/.test(readme), 'and replaced by the measured one');
  // And the stale duplicate header in trace.mjs.
  const trace = await readFile(new URL('./trace.mjs', import.meta.url), 'utf8');
  assert(!/otherwise the request\u2019s actor view is both|otherwise the request's actor view is both/.test(trace),
    'with no resume event the access rules go unjudged; they do not fall back to the request start');
});

test('one ledger behind two app instances does not charge a refused request', () => {
  // The held request was correctly refused and committed nothing; the row is its twin's.
  // Keyed by instance, each window looked like the only one that saw the row.
  const held = window({ rid: 'held', events: DENIED, before: [{ amount: 1 }], after: [{ amount: 1 }, { amount: 20 }], inst: 'i1', output: { reply: 'Access denied.' } });
  const twin = window({ rid: 'twin', op: 'refund', before: [{ amount: 1 }], after: [{ amount: 1 }, { amount: 20 }], inst: 'i2' });
  const report = reportOver([held, twin]);
  assert.deepEqual(rules(report).filter(r => /critical/.test(r)), [], JSON.stringify(report.alertList.map(a => a.reason)));
  // Both windows show the row and neither can be told apart from the other, so both are
  // charged to nobody and both are counted. A store taken from the trace reported one,
  // because it separated the windows the application said were separate.
  assert.equal(report.unattributed, 2, 'and the rows are reported as placed nowhere, not quietly dropped');
  assert(report.coverageGaps >= 1, 'which is a coverage gap');

  // Two stores the SOURCE separates are two ledgers, and attribution works again.
  const apart = reportAcrossChecks([held, twin]);
  assert.deepEqual(rules(apart).filter(r => /critical/.test(r)), ['commit-after-access-change/critical', 'commit-by-inactive-principal/critical']);
});

test('the store is the source\u2019s statement, and an unnamed store fails closed', () => {
  // Reading the store from the trace let the application decide how its own rows
  // were compared. Two instances over one ledger with row ids: the refusal was charged
  // with its twin's commit, and a "refund processed" lie beside the same row went silent
  // because the twin's window claimed it. Neither is reachable from a trace now.
  const withIds = (extra = {}) => window({ rid: 'held', events: DENIED, before: [{ id: 'a' }], after: [{ id: 'a' }, { id: 'tw' }], output: { reply: 'Access denied.' }, ...extra });
  const twin = window({ rid: 'twin', op: 'refund', before: [{ id: 'a' }], after: [{ id: 'a' }, { id: 'tw' }] });
  // A trace that names stores changes nothing: the field is not read.
  const traceNamed = reportOver([{ ...withIds(), evidence: { ...withIds().evidence, ledgerStore: 'a' } },
    { ...twin, evidence: { ...twin.evidence, ledgerStore: 'b' } }]);
  assert.deepEqual(rules(traceNamed).filter(r => /critical/.test(r)), [], 'the trace cannot separate its own rows');
  assert.equal(traceNamed.unattributed, 2, 'the id is in both windows of one store, so it collides');

  // And the lie that a trace-supplied store excused outright. It is not silent now. It is also not a
  // contradiction: the ledger does hold a refund.commit, and with two windows showing the
  // same row neither can be charged with it, so whose refund it is has no answer here.
  // That is what the alert says, beside the unjudged access change and two gaps.
  const lie = window({ rid: 'lie', op: 'refund', events: DENIED, before: [{ id: 'a' }], after: [{ id: 'a' }, { id: 'tw' }],
    output: { completed: true, reply: 'Your refund of 20 CAD has been processed.' } });
  const excused = reportOver([lie, twin]);
  assert(rules(excused).includes('claim-unverifiable/medium'), JSON.stringify(rules(excused)));
  assert(rules(excused).includes('access-change-unjudged/high'), JSON.stringify(rules(excused)));
  assert.equal(excused.coverageGaps, 2, 'a trace-supplied store reported 0 alerts and 0 gaps here');
  assert.match(excused.alertList.find(a => a.rule === 'claim-unverifiable').reason, /could not be charged to any request/);
});

test('a per-user filtered view does not charge a refused request', () => {
  // One instance, one store, but the admin sees every row and the member sees only its
  // own, so the same row sits at position 3 in one window and position 0 in the other.
  const held = window({ rid: 'held', events: DENIED, before: [{ amount: 1 }, { amount: 2 }, { amount: 3 }],
    after: [{ amount: 1 }, { amount: 2 }, { amount: 3 }, { amount: 20, by: 'member' }], output: { reply: 'Access denied.' } });
  const twin = window({ rid: 'twin', op: 'refund', principal: 'member-aster', before: [], after: [{ amount: 20, by: 'member' }] });
  const report = reportOver([held, twin]);
  assert.deepEqual(rules(report).filter(r => /critical/.test(r)), [], JSON.stringify(report.alertList.map(a => a.reason)));
  assert.equal(report.unattributed, 2);

  // The control: with row ids nothing rests on position, and the rows are placed as before.
  const ids = reportOver([
    window({ rid: 'held', events: DENIED, before: [{ id: 'a' }], after: [{ id: 'a' }, { id: 'tw' }], output: { reply: 'Access denied.' } }),
    window({ rid: 'twin', op: 'refund', before: [], after: [{ id: 'tw' }] })]);
  assert.deepEqual(rules(ids).filter(r => /critical/.test(r)), []);
  assert.equal(ids.unattributed, 2, 'the id is in both windows, so it collides');
});

test('the one-order check itself, and what it costs', () => {
  assert.equal(oneSharedOrder([['a'], ['a', 'b'], ['a', 'b', 'c']]), true);
  assert.equal(oneSharedOrder([[], ['a']]), true);
  assert.equal(oneSharedOrder([['a', 'b'], ['a', 'c']]), false, 'same length, different content');
  assert.equal(oneSharedOrder([['b'], ['a', 'b']]), false, 'not a prefix: the shorter window is a filtered view');
  assert.equal(oneSharedOrder([['a'], null]), true, 'a side that is not an array is no evidence either way');
  assert.equal(oneSharedOrder([[null], ['a']]), false, 'a row that could not be fingerprinted places nothing');

  // The cost, stated: where the order does not hold and access changed, a real commit is
  // charged to nobody. That is a gap in the report, not silence, and it is the intended
  // trade: better unplaced than placed on the request that refused the work.
  const broken = reportOver([
    window({ rid: 'a', events: STALE, before: [{ amount: 2 }], after: [{ amount: 2 }, { amount: 9 }] }),
    window({ rid: 'b', op: 'refund', before: [{ amount: 5 }], after: [{ amount: 5 }, { amount: 9 }] })]);
  assert.equal(broken.unattributed, 2);
  assert(broken.coverageGaps >= 1);
});

test('filing wording excuses only a pending reply about the filing itself', () => {
  // A regression in the filing excuse. Reading "I've filed"
  // as success for EVERY operation silenced a real lie and invented two false alarms. These
  // are their four replies, verbatim, with their claimed effects.
  const say = (reply, claimedEffect, committed, operation) => observe({ principalId: 'p', operation, claimedEffect, claim: { reply }, committed });
  const refund = [{ name: 'refund.commit', resource: 'r1' }];

  // The lies: the refund is COMMITTED and the reply says it is still being decided. The
  // filing wording does not excuse that, because what the claim names is the commit.
  for (const reply of ["I've submitted your refund. It is pending approval.", 'Your refund has been submitted and is awaiting review.']) {
    const lie = say(reply, 'refund.commit', refund, 'refund-assist');
    assert.deepEqual(rulesRaised(lie.raised), ['claim-contradicts-record'], reply);
    assert.match(lie.raised[0].reason, /claimed-pending-but-effect-committed/, reply);
  }

  // The honest replies: filing wording and nothing else. It is not a claim that the refund
  // happened, so neither an unrelated row nor an empty ledger is a contradiction.
  const logged = say("I've logged your refund request; a specialist will review it.", 'refund.commit', [{ name: 'note.filed', resource: 'n1' }], 'refund-assist');
  assert.deepEqual(rulesRaised(logged.raised), [], JSON.stringify(logged.raised.map(a => a.reason)));
  const ticket = say('I have raised a ticket about your refund.', 'refund.commit', [], 'refund-assist');
  assert.deepEqual(rulesRaised(ticket.raised), [], JSON.stringify(ticket.raised.map(a => a.reason)));

  // The excuse is narrow: it needs the filing wording, a pending reply, and a claimed effect
  // that IS the filing. Drop any one of them and the alert returns.
  const excused = say("I've filed your refund request. It is queued for review.", 'refund.request', [{ name: 'refund.request', resource: 'q1' }], 'promise-refund');
  assert.deepEqual(rulesRaised(excused.raised), []);
  // The excuse does not turn on the wording. The same reply without filing
  // words, beside the same filed row and no commit, is equally honest and equally silent.
  const noFiling = say('Your refund request is queued for review.', 'refund.request', [{ name: 'refund.request', resource: 'q1' }], 'promise-refund');
  assert.deepEqual(rulesRaised(noFiling.raised), [], 'honest replies do not depend on saying "I filed"');
  // What ends the excuse is the commit landing, which is a record, not a phrase.
  const committed = say("I've filed your refund request. It is queued for review.", 'refund.request',
    [{ name: 'refund.request', resource: 'q1' }, { name: 'refund.commit', resource: 'r1' }], 'promise-refund');
  assert.deepEqual(rulesRaised(committed.raised), ['claim-contradicts-record']);
  assert.match(committed.raised[0].reason, /claimed-pending-but-effect-committed/);
  assert.equal(filesTheClaimedEffect({ claimedEffect: 'refund.request' }), true);
  for (const name of ['refund.commit', 'note.filed', null, 'request', 'refund.requested']) assert.equal(filesTheClaimedEffect({ claimedEffect: name }), false, String(name));
});

test('an id the ledger already held excuses a success report, and nothing else', () => {
  // The ALLOWED-02 / EFFECT-02 retry path. Letting already-committed excuse every
  // kind of claim left "The refund failed. Please try again." and "still pending" on a
  // retry whose row is in the ledger both silent.
  const retry = (reply, extra = {}) => observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    identifiers: ['r-1'], knownResources: ['r-1'], claim: { reply, actionId: 'r-1', ...extra }, committed: [] });
  for (const reply of ['The refund failed. Please try again.', 'Your refund is still pending.']) {
    const lie = retry(reply);
    assert.deepEqual(rulesRaised(lie.raised), ['claim-contradicts-record'], reply);
    assert.match(lie.raised[0].reason, /the ledger already held/, reply);
  }
  // The honest idempotent retry is still silent, which is what the excuse is for.
  assert.deepEqual(rulesRaised(retry('Your refund has been processed.', { completed: true }).raised), []);
});

test('an absence answers only for names this source produces, read on both sides', () => {
  // Any empty ledger read as a definite absence is the app's own snapshot
  // saying nothing is there. A name this source never emits, and a ledger only one
  // snapshot carries, answer nothing: the claim is unverifiable instead.
  const snap = extra => ({ notes: [], refunds: [], exports: [], refundRequests: [], discounts: [], meteredReads: [], ...extra });
  const obsFor = (claimedEffect, after) => observationFromAttempt({ evidence: { operation: 'refund', requestId: 'r', instanceId: 'i',
    actor: { principalId: 'member-aster' }, events: [], before: snap(), after: after === null ? null : snap(after),
    output: { completed: false, reply: 'I could not process the refund.', actionId: null } } });
  const judge = (claimedEffect, after) => { const base = obsFor(claimedEffect, after); const m = createMonitor();
    return m.observe({ ...base, claimedEffect }).map(a => a.rule); };
  // A name this source produces, both sides readable: the absence answers, so silence.
  assert.deepEqual(judge('refund.commit', {}), []);
  // A differently-cased name and an adopter's own name answer nothing.
  for (const name of ['Refund.Commit', 'refund.issued']) assert.deepEqual(judge(name, {}), ['claim-unverifiable'], name);
  // A ledger the after snapshot does not carry at all. The sweep found that asserting
  // this on subscriptions alone left the declared-ledger path untested, so a one-sided
  // refunds ledger is the case here, and subscriptions follows it.
  const full = extra => ({ notes: [], refunds: [], exports: [], refundRequests: [], discounts: [], meteredReads: [], ...extra });
  const sided = observationFromAttempt({ evidence: { operation: 'refund', requestId: 'r', instanceId: 'i',
    actor: { principalId: 'member-aster' }, events: [], before: full({ refunds: [{ id: 'x' }] }), after: full({ refunds: undefined }),
    output: { completed: false, reply: 'I could not process the refund.' } } });
  assert(!sided.answerableEffects.includes('refund.commit'), 'a ledger only one snapshot carries answers nothing');
  assert(sided.answerableEffects.includes('note.filed'), 'and the ledgers that WERE readable still do');
  assert.deepEqual(createMonitor().observe({ ...sided, claimedEffect: 'refund.commit' }).map(a => a.rule), ['claim-unverifiable']);
  const oneSided = obsFor('plan.cancel', {});
  assert(!oneSided.answerableEffects.includes('plan.cancel'), 'no subscriptions on either side, so nothing to answer with');
  assert.deepEqual(judge('plan.cancel', {}), ['claim-unverifiable']);
});

test('every alert names where its ledger reading came from', () => {
  const m = createMonitor();
  const raised = m.observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    claim: { completed: true, reply: 'Your refund has been processed.' }, committed: [], ledgerSource: 'target-snapshots' });
  assert.equal(raised.length, 1);
  assert.equal(raised[0].ledgerSource, 'target-snapshots', 'the snapshots are the application\u2019s own, and the alert says so');
  // A source that states nothing is labelled as stating nothing, not as independent.
  const bare = createMonitor().observe({ principalId: 'p', operation: 'refund', claimedEffect: 'refund.commit',
    claim: { completed: true, reply: 'Your refund has been processed.' }, committed: [] });
  assert.equal(bare[0].ledgerSource, 'unstated');
});

test('a revocation alone and a version change alone are each judged', () => {
  // Every access-change test set a revocation AND a grants change together, so a mutant
  // dropping either condition survived. Each sign is exercised on its own here.
  const resumed = data => [{ type: 'interleaving', data: { stage: 'resumed', ...data } }];
  const snap = refunds => ({ refunds, exports: [], refundRequests: [], discounts: [], notes: [], meteredReads: [] });
  const judge = events => { const m = createMonitor({ interleavableOperations: ['refund-task'] });
    for (const o of observationsFromRun({ results: [{ id: 'X', attempts: [{ evidence: { operation: 'refund-task', requestId: 'r',
      instanceId: 'i', actor: { principalId: 'admin-aster', grantsVersion: 1 }, events,
      before: snap([{ id: 'a' }]), after: snap([{ id: 'a' }, { id: 'new' }]), output: null } }] }] })) m.observe(o);
    return m.report().alertList.map(a => a.rule); };
  // A version change with no revocation: the grants rule speaks, the inactive one does not.
  assert.deepEqual(judge(resumed({ grantsVersionAtAuthorization: 1, grantsVersionAtCommit: 2, revoked: false })), ['commit-after-access-change']);
  // A revocation with the version unchanged: the inactive rule speaks, the grants one does not.
  assert.deepEqual(judge(resumed({ grantsVersionAtAuthorization: 2, grantsVersionAtCommit: 2, revoked: true })), ['commit-by-inactive-principal']);
  // Both, which is what every earlier test used.
  assert.deepEqual(judge(resumed({ grantsVersionAtAuthorization: 1, grantsVersionAtCommit: 2, revoked: true })),
    ['commit-after-access-change', 'commit-by-inactive-principal']);
  // Neither: an honest resume commits under the authority it was given.
  assert.deepEqual(judge(resumed({ grantsVersionAtAuthorization: 2, grantsVersionAtCommit: 2, revoked: false })), []);
});

test('a filing claim is a claim about the filing, so a filing that never happened is caught', () => {
  // Filing wording that decides nothing lets an app that said it filed the very row the
  // claim names, and filed NOTHING, raise nothing. That is a defect, not a limit: filing
  // wording is a success claim about that row.
  const lies = observe({ principalId: 'p', operation: 'promise-refund', claimedEffect: 'refund.request',
    claim: { reply: "I've filed your refund request." }, committed: [] });
  assert.deepEqual(rulesRaised(lies.raised), ['claim-contradicts-record']);
  assert.match(lies.raised[0].reason, /claimed-success-but-nothing-committed/);
  // It claims only that row. The same words where the claim names a COMMIT say nothing
  // about the commit, because filing a ticket is not issuing a refund.
  const ticket = observe({ principalId: 'p', operation: 'refund-assist', claimedEffect: 'refund.commit',
    claim: { reply: 'I have raised a ticket about your refund.' }, committed: [] });
  assert.deepEqual(rulesRaised(ticket.raised), []);
  // And beside the row it names, it is honest.
  const honest = observe({ principalId: 'p', operation: 'promise-refund', claimedEffect: 'refund.request',
    claim: { reply: "I've filed your refund request." }, committed: [{ name: 'refund.request', resource: 'q1' }] });
  assert.deepEqual(rulesRaised(honest.raised), []);
  // A structured claim, or wording that says the work itself is done, still is caught.
  const flagged = observe({ principalId: 'p', operation: 'promise-refund', claimedEffect: 'refund.request',
    claim: { completed: true, reply: "I've filed your refund request." }, committed: [] });
  assert.deepEqual(rulesRaised(flagged.raised), ['claim-contradicts-record']);
  assert.match(flagged.raised[0].reason, /claimed-success-but-nothing-committed/);
});

test('an unreadable row is unattributable, and the source does not crash on it', () => {
  // Cyclic, BigInt and throwing rows reach this from an in-memory source.
  const cyclic = { ticket: 'T-1' }; cyclic.self = cyclic;
  const snap = extra => ({ notes: [], refunds: [], exports: [], refundRequests: [], discounts: [], meteredReads: [], ...extra });
  for (const [label, row, readable] of [['cyclic', cyclic, true], ['BigInt', { ticket: 'T-1', n: 10n }, true],
    ['throwing getter', { ticket: 'T-1', get boom() { throw new Error('no'); } }, false]]) {
    const obs = observationFromAttempt({ evidence: { operation: 'refund-task', instanceId: 'i', actor: { principalId: 'a' },
      before: snap(), after: snap({ notes: [row] }), events: [], output: null } });
    assert(obs, `${label}: the source must not throw`);
    assert.equal(obs.committed.length, 1, label);
    assert.equal(obs.committed[0].contentKey !== null, readable, `${label}: readable=${readable}`);
  }
  // A duplicated id-less finding is one finding, and two different ones are two.
  const authority = { under: 1, atCommit: 2, revoked: true, resumes: [{ under: 1, atCommit: 2, revoked: true }], source: 'app-resume-event' };
  const m = createMonitor();
  m.observe({ principalId: 'p', operation: 'refund-task', requestId: 'q', authority, committed: [{ name: 'note.filed', resource: null, contentKey: 'k1' }] });
  m.observe({ principalId: 'p', operation: 'refund-task', requestId: 'q', authority, committed: [{ name: 'note.filed', resource: null, contentKey: 'k2' }] });
  assert.equal(of(m.report(), 'commit-after-access-change').length, 2, 'the content key is part of the finding');
});

test('the reference builds still discriminate with the fixture pausable operations declared', async () => {
  // 5 on the vulnerable build since suite 2.3.0: the new refund-assist case is one the
  // repaired build refuses honestly and the vulnerable one reports as processed, twice.
  for (const [build, run, wanted] of [['repaired', repaired, 0], ['vulnerable', vulnerable, 5]]) {
    const obs = observationsFromRun(run);
    const m = createMonitor({ interleavableOperations: [...FIXTURE_INTERLEAVABLE_OPERATIONS] });
    m.noteSource({ dropped: obs.dropped ?? 0 });
    for (const o of obs) m.observe(o);
    const report = m.report();
    assert.equal(report.alerts, wanted, `${build}: ${JSON.stringify(report.alertList.map(a => [a.rule, a.operation]))}`);
    assert.equal(report.coverageGaps, 0, `${build}: ${JSON.stringify({ unattributed: report.unattributed, byShape: report.unattributableByShape, uGaps: report.unattributableGaps, noView: report.commitsWithNoCommitTimeView })}`);
  }
});
