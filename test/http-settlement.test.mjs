// Settlement and correlation across one HTTP run (src/http-settlement.mjs). Pure decisions over
// synthetic windows, the loopback sink ledger, and full runs against the owned practice app with its
// loopback egress recorder (integrations/core-practice/app.mjs). No model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { decideEffects, effectAssertionRows, OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { settlementFindings, applySettlement, fitsSelector, finalSettleMs, SETTLEMENT_BASIS } from '../src/http-settlement.mjs';
import { createSinkLedger } from '../integrations/observers/sink-ledger.mjs';
import { createRegistry } from '../src/registry.mjs';
import { digest } from '../src/domain.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { createCorePracticeApp, HOOK_HOST } from '../integrations/core-practice/app.mjs';
import { settlementProfile, LATE_TRIGGERS } from '../integrations/core-practice/profiles.mjs';
import { freePorts } from '../integrations/observers/fixtures/free-port.mjs';

const SINK = { operations: ['send'], names: [HOOK_HOST], actorAttribution: 'none', evidence: 'authoritative' };
let seq = 0;
const send = (resource, extra = {}) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: 'egress-recorder-hooks' }, seq: ++seq, operation: 'send', name: HOOK_HOST, resource, outcome: 'committed', ...extra });
const win = (events = [], coverage = 'complete') => ({ source: 'http-egress', instanceId: 'egress-recorder-hooks', scope: SINK, coverage, reason: coverage === 'complete' ? null : 'synthetic', events });
const sel = resource => ({ source: 'http-egress', operation: 'send', name: HOOK_HOST, ...(resource ? { resource } : {}) });
const none = resource => ({ kind: 'effect.none', select: sel(resource) });
const exists = resource => ({ kind: 'effect.exists', select: sel(resource) });
const count = (resource, expected) => ({ kind: 'effect.count', select: sel(resource), expected });
const rowOf = (effects, windows, role = 'boundary') => ({ effects: decideEffects(effects, windows, { role }), windows });
const findings = (rows, gaps) => settlementFindings(rows, gaps ?? Array.from({ length: rows.length + 1 }, () => [win()]));

test('settlement rules: a later matching effect withholds an absence or count pass; an earlier selector that fits every matched effect withholds a presence pass', () => {
  const A = 'POST /hooks/bob/admin', B = 'POST /hooks/alice/member';
  // effect-outside-window: in the next check's window, in a gap and in the tail.
  assert.deepEqual(findings([rowOf([none(A)], [win()]), rowOf([none(B)], [win([send(A)])])]), [['effect-outside-window'], [null]]);
  assert.deepEqual(findings([rowOf([none(A)], [win()])], [[win()], [win([send(A)])]]), [['effect-outside-window']], 'tail');
  assert.deepEqual(findings([rowOf([none(A)], [win()]), rowOf([none(B)], [win()])], [[win()], [win([send(A)])], [win()]]), [['effect-outside-window'], [null]], 'gap');
  assert.deepEqual(findings([rowOf([count(B, 1)], [win([send(B)])]), rowOf([none(A)], [win([send(B)])])]), [['effect-outside-window'], [null]], 'count');
  // An effect recorded before the window never unsettles it; a non-matching later effect neither.
  assert.deepEqual(findings([rowOf([none(A)], [win()])], [[win([send(A)])], [win([send(B)])]]), [[null]]);
  // An actor-scoped selector also takes a later effect with no known actor.
  const scoped = { kind: 'effect.none', select: { source: 'sql-audit-table', name: 'note.update', actor: 'bob' } };
  const audit = { source: 'sql-audit-table', instanceId: 'a', scope: { operations: ['update'], names: ['note.update'], actorAttribution: 'principal', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] };
  const anon = makeEffect({ source: 'sql-audit-table', observer: { kind: 'sqlite-audit-table', instanceId: 'a' }, seq: 1, operation: 'update', name: 'note.update', outcome: 'committed', actor: null });
  assert.equal(fitsSelector(anon, scoped.select), true);
  assert.deepEqual(findings([rowOf([scoped], [audit], 'control')], [[audit], [{ ...audit, events: [anon] }]]), [['effect-outside-window']]);
  // effect-ambiguous-attribution: every matched effect also fits an earlier check's selector.
  assert.deepEqual(findings([rowOf([none(A)], [win()]), rowOf([exists()], [win([send(A)])])]).at(-1), ['effect-ambiguous-attribution']);
  // One matched effect that only this check's selector fits keeps the exists pass.
  assert.deepEqual(findings([rowOf([none(A)], [win()]), rowOf([exists()], [win([send(A), send(B)])])]).at(-1), [null]);
  // A count is ambiguous as soon as one counted effect fits an earlier selector.
  assert.deepEqual(findings([rowOf([none(A)], [win()]), rowOf([count(null, 2)], [win([send(A), send(B)])])]).at(-1), ['effect-ambiguous-attribution']);
  // settlement-unobserved: an observer that decided an absence could not report a later window.
  assert.deepEqual(findings([rowOf([none(A)], [win()])], [[win()], [win([], 'failed')]]), [['settlement-unobserved']]);
  // Only passes are unsettled: a fail stays a fail.
  assert.deepEqual(findings([rowOf([none(A)], [win([send(A)])]), rowOf([none(B)], [win([send(A)])])]), [[null], [null]]);
  assert.throws(() => settlementFindings([rowOf([none(A)], [win()])], [[win()]]), /settlement-gaps/);
});

test('settlement applies after custody and never upgrades: a boundary pass becomes inconclusive with its reason; an allowed-use control keeps its verdict and carries the tag', () => {
  const decided = decideEffects([none('POST /hooks/bob/admin')], [win()]);
  assert.equal(decided[0].verdict, 'pass');
  const boundary = applySettlement(decided, ['effect-outside-window'], 'boundary'), control = applySettlement(decided, ['effect-outside-window'], 'control');
  assert.deepEqual([boundary[0].verdict, boundary[0].settlement], ['inconclusive', 'effect-outside-window']);
  assert.ok(boundary[0].basis.endsWith(SETTLEMENT_BASIS['effect-outside-window']));
  assert.deepEqual([control[0].verdict, control[0].settlement], ['pass', 'effect-outside-window']);
  assert.deepEqual(effectAssertionRows(boundary).map(r => [r.status, r.settlement]), [['inconclusive', 'effect-outside-window']]);
  assert.deepEqual(applySettlement(decided, [null], 'boundary'), decided);
  assert.throws(() => applySettlement(decided, ['made-up-reason'], 'boundary'), /settlement-reason/);
});

// A control establishes its actor only on its own effect (allowlist for pass). When the effect that decided its positive pass
// carries another check's correlation token, the pass is withheld, as attribution withholds it (src/http-attribution.mjs). Its
// absence passes and the other reasons stay tags, selector-only ambiguity included (a documented residual: withholding on it
// made the onboarding secure build read 5 more rows inconclusive and stopped a real repair verifying).
test('a control\'s positive pass whose effect carries another check\'s token is withheld; absence passes and other reasons stay tags', () => {
  const refund = send('POST /hooks/refund');
  for (const clause of [exists('POST /hooks/refund'), count('POST /hooks/refund', 1)]) {
    const decided = decideEffects([clause], [win([refund])], { role: 'control' });
    assert.equal(decided[0].verdict, 'pass', clause.kind);
    const [d] = applySettlement(decided, ['effect-correlated-elsewhere'], 'control');
    assert.deepEqual([d.verdict, d.settlement], ['inconclusive', 'effect-correlated-elsewhere'], clause.kind);
    assert.ok(d.basis.endsWith(SETTLEMENT_BASIS['effect-correlated-elsewhere']));
    for (const reason of ['effect-ambiguous-attribution', 'effect-outside-window', 'effect-correlated-late', 'effect-correlated-late-unsettled'])
      assert.deepEqual(applySettlement(decided, [reason], 'control').map(d => [d.verdict, d.settlement]), [['pass', reason]], `${clause.kind} ${reason} stays a tag`);
  }
  const absence = decideEffects([none('POST /hooks/bob/admin')], [win()], { role: 'control' });
  assert.deepEqual(applySettlement(absence, ['effect-ambiguous-attribution'], 'control').map(d => [d.verdict, d.settlement]), [['pass', 'effect-ambiguous-attribution']]);
});

test('sink ledger: a record that arrives after a window stopped attributing, or after its collect, lands in the gap window that follows, never in no window', async () => {
  const ledger = createSinkLedger({ prefix: 'egress', unit: 'request' });
  ledger.started();
  const item = (extra = {}) => ledger.record({ kind: 'item', done: true, witnessNonces: [], ...extra });
  const start = ledger.position();
  item({ name: 'in-window' });
  ledger.markWitnessRequest(start);
  item({ name: 'after-witness-request' });
  item({ witnessNonces: [start.witnessNonce] });
  const end = ledger.position();
  const window = await ledger.window(start, end, { witness: true, witnessWaitMs: 0, quietMs: 100 });
  assert.deepEqual(window.items.map(r => r.name), ['in-window']);
  assert.ok(window.problems.has('egress-request-after-witness-request'));
  item({ name: 'after-collect' });
  const next = ledger.position();
  const gap = await ledger.window(end, next, { witness: true, witnessWaitMs: 0, quietMs: 100, gap: true });
  assert.deepEqual(gap.items.map(r => r.name), ['after-witness-request', 'after-collect'], 'the witness itself is skipped');
  assert.equal(gap.problems.size, 0);
  // A window that is not a gap still starts at its own mark.
  assert.deepEqual((await ledger.window(end, next, { witness: false, witnessWaitMs: 0, quietMs: 100 })).items.map(r => r.name), ['after-collect']);
});

const suiteOf = (profile, env) => createRegistry({ profiles: [profile], env }).exportSuite(profile.id);
async function assess(t, build = {}, { observers = true, edit = p => p } = {}) {
  const [sinkPort] = await freePorts(1);
  const app = await createCorePracticeApp({ sinkPort, ...build }); t.after(() => app.close());
  const profile = edit(settlementProfile({ origin: app.origin, sinkPort, observers }));
  return { app, profile, run: await runHttpAssessment(profile, { env: app.env }) };
}
const row = (run, id) => run.results.find(r => r.id === id);
const clause = (run, id) => row(run, id).trace[1].data.effects[0];
const gapEvents = run => run.settlement.gaps.map(g => g.windows.flatMap(w => w.events.map(e => e.resource)));

test('settlement allowed: the clean twin passes, with gap windows sealed before, between and after the effect checks', async t => {
  const { app, profile, run } = await assess(t);
  assert.deepEqual(run.counts, { pass: 14, fail: 0, inconclusive: 0, error: 0, not_applicable: 0 });
  assert.deepEqual(run.settlement.gaps.map(g => [g.after, g.before]), [[null, 'BOB-DELETE-OWN'], ['BOB-DELETE-OWN', 'ALICE-DELETE-OWN'], ['ALICE-DELETE-OWN', 'BOB-DELETE-ADMIN-NOTE'], ['BOB-DELETE-ADMIN-NOTE', 'BOB-DELETE-MEMBER-NOTE'], ['BOB-DELETE-MEMBER-NOTE', null]]);
  assert.deepEqual([run.settlement.schema, run.settlement.settleMs], ['scopehaven-settlement/1', 300]);
  assert.ok(run.settlement.gaps.every(g => g.windows.every(w => w.coverage === 'complete')));
  assert.match(run.scopeLabel, /Effects committed after the final mark are outside every window and every claim\./);
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
  assert.equal(summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) }).exitCode, 0);
});

for (const [where, gapIndex] of [['gap', 3], ['next-window', null], ['tail', 4]]) {
  test(`settlement forbidden (${where}): a refused delete whose webhook goes out after its window reads inconclusive, never pass`, async t => {
    const { app, profile, run } = await assess(t, { refusedCommit: LATE_TRIGGERS[where] });
    const late = row(run, 'BOB-DELETE-ADMIN-NOTE');
    assert.equal(late.trace[0].data.httpStatus, 403);
    assert.equal(late.trace[1].data.windows[0].events.length, 0, 'nothing in its own window');
    assert.deepEqual([late.status, clause(run, 'BOB-DELETE-ADMIN-NOTE').settlement], ['inconclusive', 'effect-outside-window']);
    assert.match(late.assertions.find(a => a.name.startsWith('Observed effect')).actual, /effect-outside-window/);
    if (gapIndex !== null) assert.deepEqual(gapEvents(run)[gapIndex], ['POST /hooks/bob/admin']);
    else assert.deepEqual(row(run, 'BOB-DELETE-MEMBER-NOTE').trace[1].data.windows[0].events.map(e => e.resource), ['POST /hooks/bob/admin']);
    // The later check pinned to its own resource keeps its pass: the late effect does not fit its selector.
    assert.equal(row(run, 'BOB-DELETE-MEMBER-NOTE').status, 'pass');
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(profile, app.env) });
    const gate = summarizeGate({ candidate: run, expectedSuite: suiteOf(profile, app.env) });
    assert.equal(gate.exitCode, 1); assert.ok(gate.reasons.includes('inconclusive-evidence'));
  });
}

test('settlement stated limit: an effect committed after the final mark is outside every window and every claim', async t => {
  const { run } = await assess(t, { refusedCommit: { timer: true, creatorRole: 'admin' }, lateMs: 8000 });
  assert.equal(row(run, 'BOB-DELETE-ADMIN-NOTE').status, 'pass');
  assert.ok(run.limitations.some(l => l.includes('Effects committed after the final mark are outside every window and every claim.')));
  validateHttpRunEvidence(run);
});

test('settlement: an earlier check\'s late effect in a later boundary check\'s window cannot make its unpinned effect.exists pass', async t => {
  // ALICE-DELETE-OWN does nothing in this build; BOB-DELETE-ADMIN-NOTE's late webhook lands in its window.
  const reorder = pin => p => {
    const own = p.checks.find(c => c.id === 'ALICE-DELETE-OWN');
    Object.assign(own, { severity: 'high', category: 'Object access', evidenceRequirement: 'backend', effects: [{ kind: 'effect.exists', select: pin ? sel('POST /hooks/alice/member') : sel() }] });
    p.requiredControlIds = p.requiredControlIds.filter(id => id !== 'ALICE-DELETE-OWN');
    p.checks = [...p.checks.filter(c => c !== own), own];
    return p;
  };
  const trigger = { method: 'POST', pathPrefix: '/api/notes/', user: 'alice', creatorRole: 'admin' };
  // Only alice's own delete does nothing ('alice'): bob's allowed delete still pairs his prohibition, so the settlement is what withholds it.
  const unpinned = await assess(t, { refusedCommit: trigger, ownDeleteNoop: 'alice' }, { edit: reorder(false) });
  const own = row(unpinned.run, 'ALICE-DELETE-OWN');
  assert.equal(own.trace[1].data.effects[0].matched, 1, 'the mis-attribution the effect rules alone would pass');
  assert.equal(own.trace[1].data.effects[0].custody, 'independent');
  assert.deepEqual([own.status, own.trace[1].data.effects[0].settlement], ['inconclusive', 'effect-ambiguous-attribution']);
  assert.deepEqual([row(unpinned.run, 'BOB-DELETE-OWN').status, row(unpinned.run, 'BOB-DELETE-ADMIN-NOTE').status, clause(unpinned.run, 'BOB-DELETE-ADMIN-NOTE').settlement, Object.hasOwn(clause(unpinned.run, 'BOB-DELETE-ADMIN-NOTE'), 'pairing')], ['pass', 'inconclusive', 'effect-outside-window', false]);
  validateHttpRunEvidence(unpinned.run, { expectedSuite: suiteOf(unpinned.profile, unpinned.app.env) });
  // Pinned to its own resource, the allowed delete that did nothing fails.
  const pinned = await assess(t, { refusedCommit: trigger, ownDeleteNoop: 'alice' }, { edit: reorder(true) });
  assert.equal(row(pinned.run, 'ALICE-DELETE-OWN').status, 'fail');
  validateHttpRunEvidence(pinned.run);
});

test('settlement missing observer and failed control: nothing unobservable passes, and a failed allowed-use control fails', async t => {
  const missing = await assess(t, {}, { observers: false });
  for (const id of ['ALICE-DELETE-OWN', 'BOB-DELETE-ADMIN-NOTE', 'BOB-DELETE-MEMBER-NOTE']) assert.equal(row(missing.run, id).status, 'inconclusive', id);
  assert.deepEqual(missing.run.settlement.gaps.map(g => g.windows), [[], [], [], [], []]);
  validateHttpRunEvidence(missing.run);
  const noop = await assess(t, { ownDeleteNoop: true });
  assert.equal(row(noop.run, 'ALICE-DELETE-OWN').status, 'fail');
  const gate = summarizeGate({ candidate: noop.run, expectedSuite: suiteOf(noop.profile, noop.app.env) });
  assert.ok(gate.reasons.includes('required-controls-not-passed'));
});

test('settlement evidence is recomputed: a dropped record, a restored pass, an edited gap or settle, and a run saved before settlement are refused', async t => {
  const { run } = await assess(t, { refusedCommit: LATE_TRIGGERS.gap });
  validateHttpRunEvidence(run);
  const edit = change => { const copy = structuredClone(run); change(copy); return copy; };
  const reseal = r => { r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions }); };
  // Before settlement existed (evaluator cc13de98 and earlier): refused with a stated reason.
  const old = edit(c => { delete c.settlement; });
  assert.throws(() => validateHttpRunEvidence(old), e => e.code === 'invalid-run-evidence' && e.detail === 'effect-pre-settlement');
  assert.deepEqual([summarizeGate({ candidate: old }).exitCode, summarizeGate({ candidate: old }).detail], [2, 'effect-pre-settlement']);
  // Dropping the late record from the gap: the stored withholding no longer matches the recompute.
  assert.throws(() => validateHttpRunEvidence(edit(c => { c.settlement.gaps[3].windows[0].events = []; })), e => e.detail === 'effect-verdict');
  // Restoring the pass on the row (resealed, tag removed): the recompute withholds it again.
  const restored = edit(c => {
    const r = row(c, 'BOB-DELETE-ADMIN-NOTE'), e = r.trace[1].data.effects[0];
    delete e.settlement; e.verdict = 'pass';
    r.assertions = r.assertions.map(a => a.name.startsWith('Observed effect') ? (({ settlement: _s, ...rest }) => ({ ...rest, status: 'pass', actual: rest.actual.replace(/^inconclusive/, 'pass').replace(/ Settlement: .*$/, '') }))(a) : a);
    r.status = 'pass'; r.summary = 'Response predicates and observed effects passed.'; reseal(r);
    c.counts = { ...c.counts, pass: c.counts.pass + 1, inconclusive: c.counts.inconclusive - 1 };
  });
  assert.throws(() => validateHttpRunEvidence(restored), e => e.detail === 'effect-verdict');
  for (const [why, change] of [['gap labels', c => { c.settlement.gaps[1].before = 'BOB-DELETE-ADMIN-NOTE'; }], ['gap count', c => { c.settlement.gaps.pop(); }],
    ['settle', c => { c.settlement.settleMs = 250; }], ['schema', c => { c.settlement.schema = 'scopehaven-settlement/0'; }]]) {
    assert.throws(() => validateHttpRunEvidence(edit(change)), e => e.code === 'invalid-run-evidence' && e.detail === 'settlement-record', why);
  }
  // A gap window from an observer that was not declared.
  assert.throws(() => validateHttpRunEvidence(edit(c => { c.settlement.gaps[0].windows[0].instanceId = 'egress-recorder-other'; })), e => e.detail === 'effect-trace');
});

// ---------------------------------------------------------------------------
// A deciding observer's later window has to be able to decide absence
// itself. An earlier version withheld only on a failed later window, so complete coverage followed by a partial tail kept the pass.
test('a partial later window of a deciding observer withholds an absence or count pass (settlement-unobserved); a fail stays a fail', () => {
  const A = 'POST /hooks/bob/admin', B = 'POST /hooks/alice/member';
  for (const coverage of ['partial', 'failed']) {
    assert.deepEqual(findings([rowOf([none(A)], [win()])], [[win()], [win([], coverage)]]), [['settlement-unobserved']], `tail ${coverage}`);
    assert.deepEqual(findings([rowOf([none(A)], [win()]), rowOf([none(B)], [win([], coverage)])]), [['settlement-unobserved'], [null]], `next window ${coverage}`);
    assert.deepEqual(findings([rowOf([count(B, 1)], [win([send(B)])])], [[win()], [win([], coverage)]]), [['settlement-unobserved']], `count ${coverage}`);
  }
  // Complete later coverage keeps the pass; a fail is never touched; an earlier partial window is not "later".
  assert.deepEqual(findings([rowOf([none(A)], [win()])], [[win([], 'partial')], [win()]]), [[null]]);
  assert.deepEqual(findings([rowOf([none(A)], [win([send(A)])])], [[win()], [win([], 'partial')]]), [[null]]);
  // A presence-only observer did not decide the absence: its partial later window changes nothing.
  const otel = { source: 'otel-genai', instanceId: 'otel-trace', scope: { operations: ['send'], names: null, actorAttribution: 'none', evidence: 'presence-only' }, coverage: 'complete', reason: null, events: [] };
  assert.deepEqual(findings([rowOf([none(A)], [win(), otel])], [[win(), otel], [win(), { ...otel, coverage: 'partial', reason: 'synthetic' }]]), [[null]]);
  // A net-only snapshot later window that is not exact for the selector cannot exclude a late delete.
  const snapScope = { operations: ['insert', 'update', 'delete'], names: ['notes'], actorAttribution: 'none', evidence: 'authoritative' };
  const snap = (coverage, extra = {}) => ({ source: 'sql-snapshot', instanceId: 'sqlite-snapshot-db', scope: snapScope, coverage, reason: null, events: [], ...extra });
  const deleteNone = { kind: 'effect.none', select: { source: 'sql-snapshot', operation: 'delete', name: 'notes', resource: 'notes/7' } };
  // (An allowed-use control, so custody keeps the snapshot's pass as a tag and settlement can be read on it.)
  assert.deepEqual(findings([rowOf([deleteNone], [snap('complete')], 'control')], [[snap('complete')], [snap('net-only')]]), [['settlement-unobserved']]);
  assert.deepEqual(findings([rowOf([deleteNone], [snap('complete')], 'control')], [[snap('complete')], [snap('complete')]]), [[null]]);
});

// The effect.only settlement rule: an effect.only pass is an absence claim, so a matching or offending
// effect recorded after its window (in a later check's window, a gap or the tail) withholds it, and a deciding observer
// that cannot cover a later window withholds it too.
const onlySpec = (extra = {}) => ({ kind: 'effect.only', expect: [{ select: sel('POST /hooks/alice/member'), count: 1 }], allow: [], ...extra });
test('effect.only settlement: a later matching or offending effect, or a later window its deciding observer could not cover, withholds the pass', () => {
  const own = 'POST /hooks/alice/member', other = 'POST /hooks/bob/admin';
  const passed = () => rowOf([onlySpec()], [win([send(own)])]);
  assert.equal(passed().effects[0].verdict, 'pass');
  assert.deepEqual(findings([passed()]), [[null]], 'nothing later: the pass stands');
  assert.deepEqual(findings([passed()], [[win()], [win([send(other)])]]), [['effect-outside-window']], 'offending effect in the tail');
  assert.deepEqual(findings([passed()], [[win()], [win([send(own)])]]), [['effect-outside-window']], 'a second matching effect in the tail');
  assert.deepEqual(findings([passed(), rowOf([none(other)], [win([send(other)])])]), [['effect-outside-window'], [null]], 'in the next check\'s window');
  assert.deepEqual(findings([passed()], [[win()], [win([], 'partial')]]), [['settlement-unobserved']], 'partial tail');
  assert.deepEqual(findings([passed()], [[win()], [win([], 'failed')]]), [['settlement-unobserved']], 'failed tail');
  // An effect recorded before the window, or by an observer outside its declared sources, does not unsettle it.
  assert.deepEqual(findings([passed()], [[win([send(other)])], [win()]]), [[null]]);
  const audit = { source: 'sql-audit-table', instanceId: 'sqlite-audit-db', scope: { operations: ['insert'], names: ['note.create'], actorAttribution: 'principal', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] };
  const insert = makeEffect({ source: 'sql-audit-table', observer: { kind: 'sqlite-audit-table', instanceId: 'sqlite-audit-db' }, seq: 1, operation: 'insert', name: 'note.create', outcome: 'committed', actor: 'alice' });
  const scoped = rowOf([onlySpec({ sources: ['http-egress'] })], [win([send(own)]), audit]);
  assert.equal(scoped.effects[0].verdict, 'pass');
  assert.deepEqual(findings([scoped], [[win(), audit], [win(), { ...audit, events: [insert] }]]), [[null]]);
  // A fail stays a fail.
  assert.deepEqual(findings([rowOf([onlySpec()], [win([send(own), send(other)])])], [[win()], [win([send(other)])]]), [[null]]);
  // An earlier effect.only clause's expected and allowed selectors count as earlier selectors for a later presence pass.
  assert.deepEqual(findings([rowOf([onlySpec()], [win([send(own)])]), rowOf([exists()], [win([send(own)])])]).at(-1), ['effect-ambiguous-attribution']);
  assert.deepEqual(findings([rowOf([onlySpec()], [win([send(own)])]), rowOf([exists(other)], [win([send(other)])])]).at(-1), [null]);
});

// An end-to-end run with scripted observer windows (in collect order: each effect check's window, then the gaps).
const PAY = 'api.pay.example';
function scriptedFactory(queues, { marks = null } = {}) {
  return configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type], queue = [...(queues[c.id] ?? [])];
    let n = 0;
    return { kind: out.kind, instanceId: `${c.type}-${c.id}`, source: out.source, scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { marks?.push(performance.now()); return { at: ++n }; },
      async collect() {
        const next = queue.shift() ?? { events: [] }, coverage = next.coverage ?? 'complete';
        return { events: next.events.map((e, i) => makeEffect({ source: out.source, observer: { kind: out.kind, instanceId: `${c.type}-${c.id}` }, seq: 1000 + i + n * 10, outcome: 'committed', actor: null, operation: 'send', name: PAY, ...e })), coverage, reason: coverage === 'complete' ? null : 'synthetic' };
      } };
  });
}
const sinkObserver = (id = 'sink', settleMs = 250) => ({ id, type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/coupons'] }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs, quietMs: 150 });
// couponFirst: the allowed coupon check runs before the effect.only check (the documented order), so its send is earlier, not later.
function onlyRunProfile(observers = [sinkObserver()], { couponFirst = false } = {}) {
  const profile = { id: 'only-settle', name: 'Only settle', applicationId: 'only-settle', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { member: { principalId: 'member-1' } },
    requiredControlIds: ['PING', 'COUPON'], observers,
    checks: [
      { id: 'PING', title: 'Ping', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'GET', path: '/ping', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'TASK', title: 'Refund and nothing else', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }],
        effects: [{ kind: 'effect.only', expect: [{ select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' }, count: 1 }], allow: [], sources: ['http-egress'] }] },
      { id: 'COUPON', title: 'Coupon (allowed)', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'POST', path: '/coupon', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }],
        effects: [{ kind: 'effect.count', select: { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/coupons' }, expected: 1 }] },
    ] };
  if (couponFirst) profile.checks = [profile.checks[0], profile.checks[2], profile.checks[1]];
  return profile;
}
const scriptedTransport = async (origin, check) => ({ status: check.method === 'GET' ? 200 : 201, complete: true, jsonParsed: true, json: {}, bytes: 2 });
const refund = { resource: 'POST /v1/refunds' }, coupon = { resource: 'POST /v1/coupons' };
test('effect.only settlement end to end: a coupon sent after the refund check\'s window withholds its effect.only pass; the validator recomputes it', async () => {
  const p = onlyRunProfile(), suite = createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
  const runWith = queue => runHttpAssessment(p, { env: {}, transport: scriptedTransport, observerFactory: scriptedFactory({ sink: queue }) });
  // TASK before COUPON: the refund in TASK's window and the allowed coupon in COUPON's window, which is later. The coupon
  // could be TASK's late effect (correlation is by observer, not by request), so TASK's "nothing else" pass is withheld.
  // In collect order: TASK's window, COUPON's window, then the gaps before TASK, between them, and the tail.
  const nextWindow = await runWith([{ events: [refund] }, { events: [coupon] }, { events: [] }, { events: [] }, { events: [] }]);
  const task = nextWindow.results.find(r => r.id === 'TASK');
  assert.deepEqual([task.status, task.trace[1].data.effects[0].settlement], ['inconclusive', 'effect-outside-window']);
  assert.match(task.assertions.find(a => a.name.startsWith('Observed effect')).actual, /effect-outside-window/);
  assert.equal(nextWindow.results.find(r => r.id === 'COUPON').status, 'pass');
  // The validator recomputes the same finding from the sealed windows, so the authentic record is accepted as it is.
  assert.doesNotThrow(() => validateHttpRunEvidence(nextWindow, { expectedSuite: suite }));
  // Late in the tail, or a partial tail: withheld; nothing later: the pass stands.
  const tail = await runWith([{ events: [refund] }, { events: [coupon] }, { events: [] }, { events: [] }, { events: [coupon] }]);
  assert.equal(tail.results.find(r => r.id === 'TASK').trace[1].data.effects[0].settlement, 'effect-outside-window');
  // COUPON before TASK (the documented order): the coupon is earlier, so a clean TASK passes; a partial tail still withholds it.
  const first = onlyRunProfile(undefined, { couponFirst: true }), firstSuite = createRegistry({ profiles: [first], env: {} }).exportSuite(first.id);
  const runFirst = queue => runHttpAssessment(first, { env: {}, transport: scriptedTransport, observerFactory: scriptedFactory({ sink: queue }) });
  const clean = await runFirst([{ events: [coupon] }, { events: [refund] }, { events: [] }, { events: [] }, { events: [] }]);
  assert.deepEqual(clean.results.map(r => [r.id, r.status]), [['PING', 'pass'], ['COUPON', 'pass'], ['TASK', 'pass']]);
  validateHttpRunEvidence(clean, { expectedSuite: firstSuite });
  const partial = await runFirst([{ events: [coupon] }, { events: [refund] }, { events: [] }, { events: [] }, { events: [], coverage: 'partial' }]);
  assert.deepEqual([partial.results.find(r => r.id === 'TASK').status, partial.results.find(r => r.id === 'TASK').trace[1].data.effects[0].settlement], ['inconclusive', 'settlement-unobserved']);
  validateHttpRunEvidence(partial, { expectedSuite: firstSuite });
  // Restoring the withheld pass in the record (resealed) is refused: the validator recomputes the finding.
  const forged = structuredClone(nextWindow), r = forged.results.find(x => x.id === 'TASK'), e = r.trace[1].data.effects[0];
  delete e.settlement; e.verdict = 'pass';
  r.assertions = r.assertions.map(a => a.name.startsWith('Observed effect') ? (({ settlement: _s, ...rest }) => ({ ...rest, status: 'pass', actual: rest.actual.replace(/^inconclusive/, 'pass').replace(/ Settlement: .*$/, '') }))(a) : a);
  r.status = 'pass'; r.evidenceDigest = digest({ evidence: r.trace[0].data, effects: r.trace[1].data, assertions: r.assertions });
  forged.counts = { ...forged.counts, pass: forged.counts.pass + 1, inconclusive: forged.counts.inconclusive - 1 };
  assert.throws(() => validateHttpRunEvidence(forged), e => e.code === 'invalid-run-evidence' && e.detail === 'effect-verdict');
});

// Mutation gaps: the final mark follows the largest settle after the last check,
// and the sealed record's settle is the largest declared one, whatever the observers' order.
test('the final mark is taken at least the largest declared settle after the last check\'s end mark', async () => {
  const marks = [], p = onlyRunProfile();
  p.checks = p.checks.filter(c => c.id !== 'COUPON'); p.requiredControlIds = ['PING'];
  const run = await runHttpAssessment(p, { env: {}, transport: scriptedTransport, observerFactory: scriptedFactory({ sink: [{ events: [refund] }] }, { marks }) });
  // Marks: the initial mark, TASK's start and end marks, the final mark.
  assert.equal(marks.length, 4);
  assert.ok(marks[3] - marks[2] >= 240, `final mark ${Math.round(marks[3] - marks[2])} ms after the last end mark`);
  assert.equal(run.settlement.settleMs, 250);
});
test('the settlement record\'s settle is the largest declared, independent of observer order', async () => {
  assert.equal(finalSettleMs([{ settleMs: 250 }, { settleMs: 900 }, { settleMs: 300 }]), 900);
  assert.equal(finalSettleMs([{ settleMs: 900 }, { settleMs: 250 }]), 900);
  assert.equal(finalSettleMs([{ settleMs: null }, { settleMs: 300 }]), 300);
  assert.equal(finalSettleMs([]), 0);
  const p = onlyRunProfile([sinkObserver('fast', 250), sinkObserver('slow', 600)]);
  p.observers[1].port = 40998;
  const run = await runHttpAssessment(p, { env: {}, transport: scriptedTransport, observerFactory: scriptedFactory({ fast: [{ events: [refund] }], slow: [{ events: [refund] }] }) });
  assert.equal(run.settlement.settleMs, 600);
  validateHttpRunEvidence(run);
  const edited = structuredClone(run); edited.settlement.settleMs = 250;
  assert.throws(() => validateHttpRunEvidence(edited), e => e.detail === 'settlement-record');
});

// applySettlement settles a pass only. A finding handed in for a fail or an undecided clause
// (which settlementFindings never computes, but a caller or an edited record could hand in) leaves it exactly as decided.
test('applySettlement withholds a pass only; a fail or an undecided clause handed a finding is left as decided', () => {
  const failed = decideEffects([none()], [win([send('r-1')])]);
  assert.equal(failed[0].verdict, 'fail');
  assert.deepEqual(applySettlement(failed, ['effect-outside-window'], 'boundary'), failed);
  assert.deepEqual(applySettlement(failed, ['effect-outside-window'], 'control'), failed);
  const undecided = decideEffects([none()], [win([], 'partial')]);
  assert.equal(undecided[0].verdict, 'missing');
  assert.deepEqual(applySettlement(undecided, ['settlement-unobserved'], 'boundary'), undecided);
  const passed = decideEffects([none()], [win()]);
  assert.deepEqual([applySettlement(passed, ['effect-outside-window'], 'boundary')[0].verdict, applySettlement(passed, ['effect-outside-window'], 'boundary')[0].settlement], ['inconclusive', 'effect-outside-window']);
  assert.deepEqual([applySettlement(passed, ['effect-outside-window'], 'control')[0].verdict, applySettlement(passed, ['effect-outside-window'], 'control')[0].settlement], ['pass', 'effect-outside-window']);
});
