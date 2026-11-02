// In-doubt resolution, the run-end re-decide stage, exercised with late records. This build's later resolvers, the request feed (r1)
// and read-back (r2), apply only in request-feed and read-back windows (test/in-doubt-r1.test.mjs,
// test/in-doubt-r2.test.mjs). This file installs a
// stub "rx" that applies to every in-doubt attempt to crm.example that connected (as any later resolver must); its sealed
// record is a read { result } and its derivation reads that result back (a later resolver seals reads, never bare results, and brings
// a derive), through a test-only load hook that rewrites the one marker line of src/in-doubt.mjs in this test process. Nothing else is
// patched: the connector, the stage and the validator run as built.
// Checked: the overlay survives markUnfollowed and window copies, and fails closed on an event copy; entry normalization and binding
// refusals; the stage's semantics; parity between the connector side and the validator's recompute over thousands of seeded runs (unfollowed
// windows, host-suspend-short windows and keyed groups included); only opted-in clauses that read a changed attempt move; degrading any late
// record never turns a non-pass into a pass; a re-decided verdict is never more lenient than a frozen earlier evaluator reading each
// attempt's strict fate as a proven reply; tampering is refused; and end to end through runHttpAssessment and validateHttpRunEvidence.
// Owned synthetic data only. No socket is opened: observers, clocks and transports are injected.
import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MARKER = 'const LATER_RESOLVERS = Object.freeze({ r1: R1, r2: R2 });';
// Design-faithful: it applies only to an in-doubt attempt that connected; one that never connected has only r0, the transport record.
const STUB = "const LATER_RESOLVERS = Object.freeze({ r1: R1, r2: R2, rx: Object.freeze({ applies: e => inDoubtAttempt(e) && e.name === 'crm.example' && e.upstream.transport?.connected === true, "
  + "readValid: r => plain(r) && Object.keys(r).join() === 'result' && RESOLVER_RESULTS.includes(r.result), derive: ({ reads }) => new Map([...reads].map(([e, r]) => [e, { resolver: 'rx', status: 'succeeded', result: r.result }])) }) });";
const IN_DOUBT = new URL('../src/in-doubt.mjs', import.meta.url).href;
let patched = 0;
registerHooks({ load(url, context, nextLoad) {
  const result = nextLoad(url, context);
  if (url !== IN_DOUBT) return result;
  const source = Buffer.from(result.source).toString('utf8');
  if (source.split(MARKER).length !== 2) throw new Error('src/in-doubt.mjs: the later-resolver marker is not there exactly once');
  patched++;
  return { ...result, source: source.replace(MARKER, STUB) };
} });

const { RESOLVER_TABLE, LATER_RESOLVER_NAMES, applicableResolvers, fateOf, sealedRecordsOf: boundRecords, bindResolutions, lateEntriesFor, sealedResolutions, admitInDoubt, inDoubtAttempt, attemptResolution } = await import('../src/in-doubt.mjs');
const { makeEffect, admitScoped, markUnfollowed, withoutEvents } = await import('../src/effect-events.mjs');
const { decideEffects, effectTrace, recomputeEffectTrace, redecideResolved, bindSealedResolutions, effectAssertionRows, backendObserved, declaredObserverRecord, BACKEND_ASSERTION } = await import('../src/http-effects.mjs');
const { runHttpAssessment } = await import('../src/http-connector.mjs');
const { validateHttpRunEvidence } = await import('../src/contracts.mjs');
const { createRegistry } = await import('../src/registry.mjs');
const { digest } = await import('../src/domain.mjs');
const { createSuspendDetector } = await import('../src/suspend-clock.mjs');
const C = await import('./fixtures/in-doubt-redecide-cases.mjs');
const frozenOf = name => import(fileURLToPath(new URL(`./fixtures/in-doubt-main-8eaa589/${name}`, import.meta.url)));
const main = { effects: await frozenOf('http-effects.mjs'), events: await frozenOf('effect-events.mjs'), inDoubt: await frozenOf('in-doubt.mjs') };
const { CRM, ALT, INST, CLOSE, UP, EXISTS, ONLY, KEYED_ONLY, CLOSE_SEL, count, opted } = C;

let seq = 0;
const send = (upstream, { host = CRM, resource = CLOSE, key, firstSeq } = {}) => { seq++; return makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq, observedAt: '2026-10-16T00:00:00.000Z',
  operation: 'send', name: host, resource, outcome: 'committed', content: { resource, n: key ?? seq }, upstream: { ...structuredClone(upstream), target: { exact: true, query: false } },
  ...(key ? { idempotency: { status: 'keyed', key: key.repeat(64), fold: key.repeat(64), head: 'a'.repeat(64), firstSeq: firstSeq ?? seq } } : {}) }); };
const win = (events, extra = {}) => admitInDoubt({ source: 'http-egress', instanceId: INST, scope: { operations: ['send'], names: [ALT, CRM], actorAttribution: 'none', evidence: 'authoritative', forward: C.RECORDS.plain.forward }, coverage: 'complete', reason: null, events, ...extra });
// A record as supplied and sealed: a read { result }, or a failed record. eff: the record the derivation gives (what attempts read).
const rec = (result, reason) => (reason ? { resolver: 'rx', status: 'failed', reason } : { resolver: 'rx', read: { result } });
const eff = (result, reason) => (reason ? { resolver: 'rx', status: 'failed', reason } : { resolver: 'rx', status: 'succeeded', result });
const entry = (e, ...records) => ({ observer: INST, seq: e.seq, records });
const verdicts = decisions => decisions.map(d => d.verdict);

// ---------------------------------------------------------------------------------------------------------------------------------
test('1. the stub later resolver comes from this test\'s load hook only; the source on disk has none', () => {
  assert.equal(patched, 1);
  assert.deepEqual(LATER_RESOLVER_NAMES, ['r1', 'r2', 'rx']);
  assert.deepEqual(Object.keys(RESOLVER_TABLE), ['r0', 'r1', 'r2', 'rx']);
  assert.equal(typeof RESOLVER_TABLE.rx.read, 'undefined');
  assert.equal(readFileSync(fileURLToPath(IN_DOUBT), 'utf8').split(MARKER).length, 2, 'production source keeps the empty table');
  // A later resolver applies only to an attempt that connected. At seal time it has no record, which is failed, so a connected attempt
  // is in doubt; one that never connected has only the transport record (r0), which refutes it exactly as with no later resolver.
  assert.deepEqual([applicableResolvers(send(UP.reset)), applicableResolvers(send(UP.server))], [['r0', 'rx'], ['r0', 'rx']]);
  assert.deepEqual(applicableResolvers(send(UP.refused)), ['r0'], 'never connected');
  assert.deepEqual(applicableResolvers(send(UP.missing)), ['r0'], 'no transport record: not known to have connected');
  assert.deepEqual(applicableResolvers(send(UP.reset, { host: ALT })), ['r0'], 'rx does not apply to alt.example');
  assert.deepEqual([fateOf(send(UP.reset)), fateOf(send(UP.refused)), fateOf(send(UP.missing))], ['in-doubt', 'refuted', 'in-doubt']);
});

test('2. markUnfollowed only marks the window, so the event-keyed overlay survives; window copies keep it, event copies fail closed', () => {
  const reset = send(UP.reset), applied = send(UP.applied);
  const w = win([reset, applied], { coverage: 'partial', reason: C.AFTER, scoped: [{ name: CRM, resource: 'POST /tickets/T-1/close', codes: [C.AFTER] }] });
  admitScoped(w);
  bindResolutions([w], [entry(reset, rec('confirms'))]);
  assert.equal(fateOf(reset), 'applied');
  const events = w.events, marked = markUnfollowed(w);
  assert.equal(marked, w, 'the same window object');
  assert.equal(marked.events, events, 'the same events array');
  assert.ok(marked.events.every((e, i) => e === [reset, applied][i]), 'the same event objects');
  assert.deepEqual(boundRecords(reset), [rec('confirms')], 'the overlay survives');
  assert.equal(fateOf(reset), 'applied');
  assert.deepEqual(sealedResolutions([w]), [entry(reset, rec('confirms'))]);
  // The unfollowed window is decided with the late fate: a confirmed attempt is a match (presence decides on any coverage).
  const [d] = decideEffects([EXISTS], [w]);
  assert.deepEqual([d.verdict, d.resolution.redecided, d.resolution.attempts.map(a => a.by)], ['pass', true, ['rx', 'proof']]);
  // withoutEvents (the later-outcome stage's copy) keeps event identity, so the overlay; an event copy has none and reads in doubt.
  const copy = withoutEvents(w, new Set([applied]));
  assert.equal(copy.events[0], reset);
  assert.equal(fateOf(copy.events[0]), 'applied');
  assert.equal(fateOf(structuredClone(reset)), 'in-doubt', 'an event copy: rx record-missing, failed, in doubt');
  bindResolutions([w], []);
  assert.equal(fateOf(reset), 'in-doubt', 'unbinding leaves nothing');
});

test('3. entries: one record per later resolver that applies, malformed and doubled ones failed, everything else dropped; binding refuses any other shape', () => {
  const reset = send(UP.reset), refused = send(UP.refused), server = send(UP.server), alt = send(UP.reset, { host: ALT }), get = send(UP.reset, { resource: 'GET /tickets/T-1' }), applied = send(UP.applied);
  const w = win([reset, refused, server, alt, get, applied]);
  const supplied = [entry(reset, rec('refutes'), { resolver: 'r0', status: 'succeeded', result: 'confirms' }), entry(refused, rec('confirms')), entry(server, rec('confirms'), rec('refutes')), entry(alt, rec('confirms')),
    entry(get, rec('confirms')), entry(applied, rec('refutes')), { observer: INST, seq: 99, records: [rec('refutes')] }, { observer: 'egress-recorder-other', seq: reset.seq, records: [rec('confirms')] }, null, 'x'];
  assert.deepEqual(lateEntriesFor([w], supplied), [entry(reset, rec('refutes')), entry(server, rec(null, 'record-duplicate'))], 'the never-connected attempt takes no record');
  assert.deepEqual(lateEntriesFor([w], [entry(reset, { resolver: 'rx', read: { result: 'maybe' } })]), [entry(reset, rec(null, 'record-invalid'))]);
  assert.deepEqual(lateEntriesFor([w], [entry(reset, { resolver: 'rx', status: 'failed', reason: 'Not A Label' })]), [entry(reset, rec(null, 'record-invalid'))]);
  assert.deepEqual(lateEntriesFor([w], [entry(reset, { resolver: 'rx', read: { result: 'refutes' }, extra: 1 })]), [entry(reset, rec('refutes'))], 'normalized to the sealed shape');
  // A later resolver's record is its read; a bare result is never taken, whatever it says.
  assert.deepEqual(lateEntriesFor([w], [entry(reset, eff('refutes'))]), [entry(reset, rec(null, 'record-invalid'))], 'a bare result is a failed record');
  assert.throws(() => bindResolutions([w], [entry(reset, eff('refutes'))]), /resolution-record/, 'and is refused when bound');
  assert.deepEqual(lateEntriesFor([{ ...w }], [entry(reset, rec('refutes'))]), [], 'a window that is not admitted (gate B) takes no record');
  const refuses = (entries, why) => assert.throws(() => bindResolutions([w], entries), /resolution-record/, why);
  for (const [entries, why] of [[[entry(alt, rec('confirms'))], 'rx does not apply'], [[entry(refused, rec('confirms'))], 'an attempt that never connected has only r0'], [[entry(get, rec('confirms'))], 'a safe method is not in doubt'], [[entry(applied, rec('confirms'))], 'a proven reply'],
    [[entry(reset, { resolver: 'r0', status: 'succeeded', result: 'refutes' })], 'r0 reads its own event'], [[entry(reset)], 'no record'], [[entry(reset, rec('refutes'), rec('refutes'))], 'one record per resolver'],
    [[entry(reset, rec('refutes')), entry(reset, rec('confirms'))], 'one entry per attempt'], [[{ ...entry(reset, rec('refutes')), extra: 1 }], 'exact keys'], [[entry(reset, { ...rec('refutes'), note: 'x' })], 'exact record keys'],
    [[{ observer: INST, seq: 99, records: [rec('refutes')] }], 'no such attempt'], [[{ observer: 'other', seq: reset.seq, records: [rec('refutes')] }], 'another observer'], ['x', 'not a list']]) refuses(entries, why);
  bindResolutions([w], [entry(reset, rec('refutes'))]);
  assert.throws(() => bindResolutions([w], [entry(alt, rec('confirms'))]));
  assert.equal(fateOf(reset), 'in-doubt', 'a refused binding leaves nothing bound');
  assert.throws(() => bindResolutions([{ ...w, events: w.events }], [entry(reset, rec('refutes'))]), /resolution-record/, 'only admitted windows');
  // The validator's binding: absent clears; an empty or reordered list, or any refused entry, is effect-trace.
  bindSealedResolutions([w], [entry(reset, rec('refutes')), entry(server, rec('confirms'))]);
  assert.deepEqual([fateOf(reset), fateOf(refused), fateOf(server)], ['refuted', 'refuted', 'applied'], 'rx decides the connected attempts; r0 alone the refused one');
  assert.throws(() => bindSealedResolutions([w], [entry(server, rec('confirms')), entry(reset, rec('refutes'))]), /effect-trace/, 'not in the order the row seals them');
  assert.throws(() => bindSealedResolutions([w], [entry(refused, rec('refutes'))]), /effect-trace/, 'a sealed record for a never-connected attempt');
  assert.throws(() => bindSealedResolutions([w], []), /effect-trace/);
  assert.equal(fateOf(reset), 'in-doubt', 'a refused sealed list leaves nothing bound');
  bindSealedResolutions([w], undefined);
  assert.deepEqual(sealedResolutions([w]), []);
});

test('4. the stage: a late refutation or confirmation decides a clause again; no record, a failed or silent one keeps it in doubt; a never-connected attempt keeps the transport record\'s refutation; other clauses are untouched', () => {
  const row = (effects, events, kind) => ({ effects, claims: [], readings: [], role: 'boundary', windows: [win(events, kind ?? {})] });
  const decide = r => decideEffects(r.effects, r.windows, { role: r.role });
  const stage = (r, supplied) => redecideResolved([r], supplied)[0];
  // A late refutation of a reset close: exactly-0 and the outcome-judged effect.only move from missing to pass.
  { const reset = send(UP.reset), r = row([count(0), ONLY, { kind: 'effect.none', select: { source: 'http-egress', name: ALT } }], [reset]);
    assert.deepEqual(verdicts(decide(r)), ['missing', 'missing', 'pass']);
    const before = decide(r), again = stage(r, [entry(reset, rec('refutes'))]);
    assert.deepEqual(verdicts(again), ['pass', 'pass', 'pass']);
    assert.deepEqual([again[0].resolution.redecided, again[0].resolution.operation, again[0].resolution.attempts[0].by], [true, 'refuted', 'rx']);
    assert.deepEqual(again[2], before[2], 'a clause with no opt-in is byte-identical');
    assert.deepEqual(sealedResolutions(r.windows), [entry(reset, rec('refutes'))]); }
  // A late confirmation: exists passes, exactly-0 fails.
  { const reset = send(UP.reset), r = row([EXISTS, count(0)], [reset]);
    assert.deepEqual(verdicts(stage(r, [entry(reset, rec('confirms'))])), ['pass', 'fail']); }
  // No record (the read never ran: the run was cut before it), a failed record or a silent one: in doubt, as before.
  { const reset = send(UP.reset), r = row([EXISTS, count(0)], [reset]);
    assert.equal(stage(r, []), null, 'no record: the row is unchanged');
    assert.equal(sealedResolutions(r.windows).length, 0);
    const failed = stage(r, [entry(reset, rec(null, 'read-not-run'))]);
    assert.deepEqual([verdicts(failed), failed[0].resolution.attempts[0].reason], [['missing', 'missing'], 'read-not-run']);
    assert.deepEqual(verdicts(stage(r, [entry(reset, rec('silent'))])), ['missing', 'missing']); }
  // A never-connected attempt keeps the transport record's refutation from seal time; a late record for it is dropped, and the row is unchanged.
  { const refused = send(UP.refused), r = row([count(0), EXISTS], [refused]);
    assert.deepEqual(verdicts(decide(r)), ['pass', 'fail']);
    assert.equal(stage(r, [entry(refused, rec('confirms'))]), null);
    assert.deepEqual(boundRecords(refused), []); }
  // Records only on sends no opted-in clause reads: the row is not decided again, and nothing is bound or sealed.
  { const reset = send(UP.reset), r = row([{ kind: 'effect.exists', select: C.sel(CRM, CLOSE, 'applied') }, { kind: 'effect.none', select: { source: 'http-egress', name: ALT } }], [reset]);
    assert.equal(stage(r, [entry(reset, rec('refutes'))]), null);
    assert.deepEqual([sealedResolutions(r.windows), boundRecords(reset)], [[], []]); }
  // Another resource: an opted-in clause that selects nothing changed keeps its bytes, the one that does is decided again.
  { const t2 = send(UP.reset, { resource: 'POST /tickets/T-2/close' }), t1 = send(UP.reset);
    const r = row([count(0), { ...count(0), select: C.sel(CRM, 'POST /tickets/T-2/close', 'resolved') }], [t1, t2]);
    const before = decide(r), again = stage(r, [entry(t2, rec('refutes'))]);
    assert.deepEqual(again[0], before[0]);
    assert.deepEqual([again[1].verdict, again[1].resolution.redecided], ['pass', true]); }
});

// --- Parity: the connector's side and the validator's recompute ----------------------------------------------------------------
const LIVE = { scoped: [admitScoped], inDoubt: [admitInDoubt] };
// The connector, as it decides one row: at seal time, again under the follow rule when the window is unfollowed, then the run-end stage.
function connectorSide(c, supplied) {
  const w = C.buildWindow(c, { mark: LIVE }), windows = [w], opts = { role: c.role, claims: c.claims, readings: c.readings };
  let decisions = decideEffects(c.effects, windows, opts);
  if (c.kind === 'unfollowed') { markUnfollowed(w); decisions = decideEffects(c.effects, windows, opts); }
  const before = decisions;
  const [again] = redecideResolved([{ effects: c.effects, claims: c.claims, readings: c.readings, role: c.role, windows }], supplied);
  if (again) decisions = again;
  return { windows, before, decisions, changed: Boolean(again), trace: effectTrace(decisions, windows, C.META) };
}
// The validator, from the sealed trace alone (a fresh copy: no event object, overlay or mark carries over).
const validatorSide = (c, trace) => recomputeEffectTrace(JSON.parse(JSON.stringify(trace)), undefined, [C.recordOf(c)], { role: c.role, unfollowed: C.unfollowedOf(c) });
const RUNS = 3000;

test('5a. a late record on a keyed send that is not outcome-judged moves effect.only\'s replay hint, so the clause is flagged', () => {
  // Four closes under one key fold: #1 reset (connected) with key 1, another body and a sub-path target, so not outcome-judged; #2 and #4 the
  // same applied keyed send; #3 applied with no key. Refuting #1 late drops it from the key group, so #2 and #4 collapse and the hint changes.
  const sub = { exact: false, query: false }, exact = { exact: true, query: false };
  const c = { keyed: true, kind: 'complete', role: 'boundary', effects: [C.ONLY_ONCE], claims: [], readings: [], events: [
    { host: CRM, outcome: 'reset', resource: CLOSE, target: sub, key: '1', firstSeq: 1, content: 'd', seq: 1 },
    { host: CRM, outcome: 'applied', resource: CLOSE, target: exact, key: '1', firstSeq: 1, content: 'k1', seq: 2 },
    { host: CRM, outcome: 'applied', resource: CLOSE, target: exact, content: 'c', seq: 3 },
    { host: CRM, outcome: 'applied', resource: CLOSE, target: exact, key: '1', firstSeq: 1, content: 'k1', seq: 4 }] };
  const side = connectorSide(c, [{ observer: INST, seq: 1, records: [rec('refutes')] }]);
  assert.notEqual(side.decisions[0].basis, side.before[0].basis, 'the replay hint moved');
  assert.deepEqual([side.before[0].verdict, side.decisions[0].verdict, side.decisions[0].resolution.redecided, side.changed], ['fail', 'fail', true, true]);
  assert.deepEqual(validatorSide(c, side.trace).rows, effectAssertionRows(side.decisions));
});

test('5. parity: for every seeded run the validator recomputes the connector\'s verdicts, rows, records and backend reading (unfollowed, host-suspend-short and keyed included); only clauses that read a changed attempt move', t => {
  const n = { runs: 0, clauses: 0, changed: 0, redecided: 0, moved: 0, gained: 0, complete: 0, partial: 0, scoped: 0, unfollowed: 0, short: 0, keyed: 0 };
  // Seed 55001 at 6,000 runs holds test 5a's case (run 4745: an unflagged effect.only whose replay hint moved).
  for (const [seed, runs] of [[20261016, RUNS], [55001, 6000], [55002, RUNS], [66001, RUNS]]) for (let i = 0, g = C.rng(seed); i < runs; i++) {
    const c = C.randomCase(g), side = connectorSide(c, c.supplied);
    const again = validatorSide(c, side.trace);
    assert.deepEqual(again.decisions.map(d => d.verdict), side.decisions.map(d => d.verdict));
    assert.deepEqual(again.rows, effectAssertionRows(side.decisions));
    assert.equal(again.backendObserved, backendObserved(side.decisions));
    assert.equal(Object.hasOwn(side.trace.data, 'resolutions'), side.changed, 'records are sealed exactly on a row decided again');
    side.decisions.forEach((d, k) => {
      const clause = k < c.effects.length ? c.effects[k] : c.claims[k - c.effects.length];
      if (!opted(clause)) assert.equal(d.resolution?.redecided, undefined, 'a clause with no opt-in never reads a late record');
      if (d.resolution?.redecided) { n.redecided++; if (d.verdict !== side.before[k].verdict) n.moved++; if (d.verdict === 'pass' && side.before[k].verdict !== 'pass') n.gained++; }
      else assert.deepEqual(d, side.before[k], 'a clause that read no changed attempt is byte-identical');
      n.clauses++;
    });
    n.runs++;
    if (side.changed) { n.changed++; n[c.kind]++; if (c.keyed) n.keyed++; }
  }
  t.diagnostic(`parity: ${JSON.stringify(n)}`);
  assert.ok(n.changed > 800 && n.moved > 300 && n.gained > 100 && n.unfollowed > 100 && n.short > 50 && n.keyed > 200 && n.scoped > 50, `exercised: ${JSON.stringify(n)}`);
});

test('6. property: removing or failing any late record never turns a non-pass into a pass; with none, every row is as it was before the stage', t => {
  const g = C.rng(777);
  let checked = 0, fullOnly = 0;
  for (let i = 0; i < RUNS; i++) {
    const c = C.randomCase(g), full = connectorSide(c, c.supplied);
    const degraded = c.supplied.flatMap(x => { const r = g(); return r < 0.3 ? [] : r < 0.55 ? [{ ...x, records: x.records.map(y => ({ resolver: y?.resolver, status: 'failed', reason: 'read-not-run' })) }] : [x]; });
    const less = connectorSide(c, degraded), none = connectorSide(c, []);
    assert.deepEqual(none.decisions, none.before, 'no record: the stage changes nothing');
    assert.equal(Object.hasOwn(none.trace.data, 'resolutions'), false);
    full.decisions.forEach((d, k) => {
      const clause = k < c.effects.length ? c.effects[k] : c.claims[k - c.effects.length];
      if (!opted(clause)) { assert.equal(less.decisions[k].verdict, d.verdict, 'a clause with no opt-in never depends on the records'); return; }
      if (less.decisions[k].verdict === 'pass') assert.equal(d.verdict, 'pass', `degraded pass needs a full pass: ${JSON.stringify({ c, degraded })}`);
      if (none.decisions[k].verdict === 'pass') assert.equal(d.verdict, 'pass');
      if (d.verdict === 'pass' && less.decisions[k].verdict !== 'pass') fullOnly++;
      checked++;
    });
  }
  t.diagnostic(`missing evidence: ${checked} opted-in clauses checked, ${fullOnly} passes only with every record`);
  assert.ok(checked > 5000 && fullOnly > 100, `exercised: ${checked} opted-in clauses, ${fullOnly} passes only with every record`);
});

test('7. property: a re-decided verdict is never more lenient than the strict combination: every re-decided pass and fail is one the frozen earlier evaluator gives reading each attempt\'s strict fate as a proven reply', t => {
  const g = C.rng(4711);
  const MAIN = { scoped: [admitScoped, main.events.admitScoped], inDoubt: [main.inDoubt.admitInDoubt] };
  let passes = 0, fails = 0, equal = 0, compared = 0;
  for (let i = 0; i < RUNS; i++) {
    const c = C.randomCase(g), side = connectorSide(c, c.supplied);
    if (!side.changed) continue;
    // Each attempt as the strict combination left it: confirmed as a proven 201, refuted as a proven declared 409, in doubt as unknown;
    // no transport record anywhere, so the frozen evaluator's r0 decides nothing on its own.
    const fates = new Map(side.windows[0].events.map(e => [e.seq, inDoubtAttempt(e) ? fateOf(e) : null]));
    const oracleUp = s => { const f = fates.get(s.seq); const { transport: _t, ...up } = C.UP[s.outcome]; return f === 'applied' ? C.UP.applied : f === 'refuted' ? C.UP.rejected : f === 'in-doubt' ? C.UP.missing : up; };
    const w = C.buildWindow(c, { mark: MAIN, upstreamOf: oracleUp });
    if (c.kind === 'unfollowed') { markUnfollowed(w); main.events.markUnfollowed(w); }
    const oracle = main.effects.decideEffects(c.effects, [w], { role: c.role, claims: c.claims, readings: c.readings });
    side.decisions.forEach((d, k) => {
      if (!d.resolution?.redecided) return;
      compared++;
      if (d.verdict === 'pass') { assert.equal(oracle[k].verdict, 'pass', `a pass the strict fates do not give: ${JSON.stringify(c)}`); passes++; }
      if (d.verdict === 'fail') { assert.equal(oracle[k].verdict, 'fail', `a fail the strict fates do not give: ${JSON.stringify(c)}`); fails++; }
      if (d.verdict === oracle[k].verdict) equal++;
    });
  }
  t.diagnostic(`strict-fate oracle: compared ${compared}, equal ${equal}, passes ${passes}, fails ${fails}`);
  assert.ok(passes > 200 && fails > 100, `exercised: ${passes} re-decided passes, ${fails} fails of ${compared}`);
});

test('8. tamper: an edited verdict, late record or re-decide flag, a dropped, reordered or added record list, all refused on recompute', () => {
  const g = C.rng(99);
  let edits = 0;
  for (let i = 0; i < 600 && edits < 400; i++) {
    const c = C.randomCase(g), side = connectorSide(c, c.supplied);
    if (!side.changed) continue;
    const refused = (edit, why) => { const t = JSON.parse(JSON.stringify(side.trace)); edit(t.data); assert.throws(() => validatorSide(c, t), /effect-(trace|verdict)/, why); edits++; };
    const k = side.decisions.findIndex(d => d.resolution?.redecided);
    const where = k < c.effects.length ? d => d.effects[k] : d => d.claims[k - c.effects.length];
    refused(d => { where(d).verdict = where(d).verdict === 'pass' ? 'fail' : 'pass'; }, 'a verdict');
    refused(d => { delete where(d).resolution.redecided; }, 'the re-decide flag dropped');
    refused(d => { where(d).resolution.redecided = false; }, 'the re-decide flag edited');
    // A record edited so that the strict fate of an attempt some clause lists changes. A record no clause reads, or an edit that changes no
    // fate, reason or flag, changes nothing a verdict reads, as for any other sealed field; the evidence digest refuses it unless the run
    // is resealed (test 11).
    const listed = new Set(side.decisions.flatMap(d => d.resolution?.attempts ?? []).map(a => a.seq));
    side.trace.data.resolutions.forEach((x, j) => {
      const e = side.windows[0].events.find(ev => ev.seq === x.seq), result = fateOf(e) === 'refuted' ? 'confirms' : 'refutes', flip = rec(result);
      if (!listed.has(x.seq) || attemptResolution(e, [eff(result)]).verdict === attemptResolution(e).verdict) return;
      refused(d => { d.resolutions[j].records = [flip]; }, 'a record');
    });
    refused(d => { const r = d.resolutions[0].records[0]; r.status = r.status === 'failed' ? 'succeeded' : 'failed'; }, 'a record shape');
    refused(d => { delete d.resolutions; }, 'the records dropped');
    refused(d => { d.resolutions[0].seq = 98; }, 'a record moved to another attempt');
    if (side.trace.data.resolutions.length > 1) refused(d => { d.resolutions.reverse(); }, 'reordered');
  }
  // Records added to a row no stage decided again: refused (the connector seals records only on a row it decided again).
  const reset = send(UP.reset), w = win([reset]), trace = effectTrace(decideEffects([{ kind: 'effect.exists', select: C.sel(CRM, CLOSE, 'applied') }], [w]), [w], C.META);
  trace.data.resolutions = [entry(reset, rec('refutes'))];
  assert.throws(() => recomputeEffectTrace(JSON.parse(JSON.stringify(trace)), undefined, [C.RECORDS.plain]), /effect-trace/);
  assert.ok(edits >= 300, `${edits} edits`);
});

// --- End to end: the connector and the shared validator -------------------------------------------------------------------------
const { recorderFactory, transport, profileOf, suiteOf, runOf, rowOf, clauseVerdicts } = C;
const lateFor = (pickRecord) => sent => sent.filter(e => e.name === CRM && e.upstream.outcome === 'unknown').map(e => ({ seq: e.seq, records: [pickRecord(e)] })).filter(x => x.records[0]);

test('9. end to end: a late refutation or confirmation is decided again before settlement, sealed, and recomputed by the shared validator', async () => {
  const p = profileOf([[EXISTS, ONLY]]);
  const events = () => [send(UP.reset)];
  const without = await runOf(p, recorderFactory([events]));
  assert.deepEqual([clauseVerdicts(rowOf(without)), rowOf(without).status, Object.hasOwn(rowOf(without).trace[1].data, 'resolutions')], [['missing', 'missing'], 'inconclusive', false]);
  const refuted = await runOf(p, recorderFactory([events], { reads: lateFor(() => rec('refutes')) }));
  const row = rowOf(refuted), data = row.trace[1].data;
  assert.deepEqual([clauseVerdicts(row), data.resolutions.map(x => x.records)], [['fail', 'pass'], [[rec('refutes')]]]);
  assert.deepEqual([data.effects[0].resolution.redecided, data.effects[1].resolution.redecided], [true, true]);
  const confirmed = rowOf(await runOf(p, recorderFactory([events], { reads: lateFor(() => rec('confirms')) })));
  assert.deepEqual([clauseVerdicts(confirmed), confirmed.status, confirmed.backendEvidence, confirmed.assertions.find(a => a.name === BACKEND_ASSERTION).status], [['pass', 'fail'], 'fail', 'observed', 'pass']);
  // Positive only: the confirmed close passes the row, backend observed, through the stage and then settlement, pairing and the identity rules.
  const ok = rowOf(await runOf(profileOf([[EXISTS]]), recorderFactory([events], { reads: lateFor(() => rec('confirms')) })));
  assert.deepEqual([ok.status, ok.backendEvidence], ['pass', 'observed']);
  // A run cut before the run-end read (no record) and a read that failed: in doubt in both the connector and the validator.
  for (const reads of [() => [], lateFor(() => rec(null, 'read-not-run'))]) assert.deepEqual(clauseVerdicts(rowOf(await runOf(p, recorderFactory([events], { reads })))), ['missing', 'missing']);
  // A record for a host the later resolver does not cover, or for r0, binds nothing and seals nothing.
  const noise = rowOf(await runOf(p, recorderFactory([events], { reads: sent => sent.map(e => ({ seq: e.seq, records: [{ resolver: 'r0', status: 'succeeded', result: 'refutes' }, ...(e.name === ALT ? [rec('confirms')] : [])] })) })));
  assert.equal(Object.hasOwn(noise.trace[1].data, 'resolutions'), false);
});

test('10. end to end: an unfollowed window, a keyed group, a host-suspend-short window and settlement gaps across two checks all agree with the validator', async () => {
  // Unfollowed: the last check's window has a late after-witness entry nothing follows; the follow rule marks it, then the stage decides again.
  const p = profileOf([[EXISTS, count(1)]]);
  const unfollowed = await runOf(p, recorderFactory([() => [send(UP.reset)]], { late: [true], reads: lateFor(() => rec('confirms')) }));
  const u = rowOf(unfollowed);
  assert.deepEqual([u.trace[1].data.windows[0].coverage, Boolean(u.trace[1].data.windows[0].scoped), clauseVerdicts(u)], ['partial', true, ['pass', 'missing']], 'unfollowed: read window-wide, a count cannot be decided');
  // Keyed group: an exact same-key retry, both attempts reset. Both refuted late: nothing applied, so nothing-expected passes, and so does
  // expected-once (effect.only's count is a maximum: presence is effect.exists's or effect.count's job). The first refuted and the retry confirmed: the applied retry stands and nothing-expected fails; expected-once
  // passes: the key collapse (src/idempotency.mjs keyedSends) reads a refuted attempt as a declared rejection and a confirmed
  // one as applied, as a proven applied reply reads (it read unknown, so missing, while no confirming resolver existed).
  // The task's effect.only clauses pin nothing and it has no positive clause, so a required allowed-use twin guards them; the
  // twin's applied close (under its own key, as the keyed destination records every send) is the first window, and the resolver reads
  // the task's two in-doubt attempts.
  const kp = profileOf([[KEYED_ONLY([]), KEYED_ONLY([{ select: CLOSE_SEL, count: 1 }])]], { keyed: true, twin: [EXISTS], requiredTwin: true });
  const keyed = () => { const first = send(UP.reset, { key: '1' }); return [first, send(UP.reset, { key: '1', firstSeq: first.seq })]; };
  const keyedRun = results => runOf(kp, recorderFactory([() => [send(UP.applied, { key: '9' })], keyed], { reads: sent => sent.filter(e => e.upstream?.outcome === 'unknown').map((e, i) => ({ seq: e.seq, records: [rec(results[i])] })) }));
  assert.deepEqual(clauseVerdicts(rowOf(await keyedRun(['refutes', 'refutes']))), ['pass', 'pass']);
  assert.deepEqual(clauseVerdicts(rowOf(await keyedRun(['refutes', 'confirms']))), ['fail', 'pass']);
  assert.deepEqual(clauseVerdicts(rowOf(await runOf(kp, recorderFactory([() => [send(UP.applied, { key: '9' })], keyed])))), ['missing', 'missing'], 'no record');
  // Unguarded (the twin not required), the same passes read inconclusive (allowed-use-not-declared).
  const unguarded = profileOf([[KEYED_ONLY([]), KEYED_ONLY([{ select: CLOSE_SEL, count: 1 }])]], { keyed: true });
  const both = rowOf(await runOf(unguarded, recorderFactory([keyed], { reads: sent => sent.map(e => ({ seq: e.seq, records: [rec('refutes')] })) })));
  assert.deepEqual([clauseVerdicts(both), both.trace[1].data.effects.map(e => e.pairing)], [['inconclusive', 'inconclusive'], ['allowed-use-not-declared', 'allowed-use-not-declared']]);
  // Settlement and pairing read the stage's output. A control twin applies the close; the task's own attempt is refuted late, so exactly-0
  // passes and the positive-match pairing finds its twin; with no twin, pairing holds that re-decided pass; without the record it is
  // missing. The validator recomputes the gaps, the pairing and every row.
  const paired = await runOf(profileOf([[count(0)]], { twin: [EXISTS] }), recorderFactory([() => [send(UP.applied)], () => [send(UP.reset)]], { reads: lateFor(() => rec('refutes')) }));
  assert.deepEqual([clauseVerdicts(rowOf(paired, 'TWIN')), clauseVerdicts(rowOf(paired)), rowOf(paired).status, rowOf(paired).backendEvidence], [['pass'], ['pass'], 'pass', 'observed']);
  const unpaired = rowOf(await runOf(profileOf([[count(0)]]), recorderFactory([() => [send(UP.reset)]], { reads: lateFor(() => rec('refutes')) })));
  assert.deepEqual([clauseVerdicts(unpaired), Object.hasOwn(unpaired.trace[1].data.effects[0], 'pairing')], [['inconclusive'], true], 'no twin: pairing holds the re-decided pass');
  const unread = await runOf(profileOf([[count(0)]], { twin: [EXISTS] }), recorderFactory([() => [send(UP.applied)], () => [send(UP.reset)]]));
  assert.deepEqual(clauseVerdicts(rowOf(unread)), ['missing']);
  // Host suspend left the settle short: the window reads partial with host-suspend-wait-short; a late refutation cannot pass an
  // absence there, a late confirmation still decides presence; the validator recomputes both.
  const WALL0 = Date.parse('2026-10-16T00:00:00.000Z');
  const virtual = () => {
    const v = { now: 1000, suspended: 0, cut: false };
    v.clock = { now: () => v.now, sleep: async ms => { if (ms === 250 && !v.cut) { v.cut = true; v.now += 70100; v.suspended += 70000; } else v.now += ms; await null; } };
    v.detector = createSuspendDetector({ wall: () => WALL0 + v.now, awake: () => v.now - v.suspended, elapsed: () => v.now, timersCountSuspend: true });
    v.transport = async (...args) => { v.now += 20; return transport(...args); };
    return v;
  };
  for (const [clauses, result, expected] of [[[count(0)], 'refutes', ['missing']], [[EXISTS], 'confirms', ['pass']]]) {
    const v = virtual(), sp = profileOf([clauses]);
    const run = await runHttpAssessment(sp, { env: {}, transport: v.transport, clock: v.clock, suspendClock: v.detector, observerFactory: recorderFactory([() => [send(UP.reset)]], { reads: lateFor(() => rec(result)) }) });
    const w = rowOf(run).trace[1].data.windows[0];
    assert.deepEqual([w.coverage, w.reason.split(',').includes('host-suspend-wait-short'), w.suspend.shortMs > 0, clauseVerdicts(rowOf(run)), Object.hasOwn(rowOf(run).trace[1].data, 'resolutions')], ['partial', true, true, expected, true]);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(sp) });
    validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suiteOf(sp) });
  }
});

test('11. end to end: tampering with a sealed late record, the re-decide flag or a verdict is refused by the shared validator', async () => {
  const p = profileOf([[EXISTS, ONLY]]);
  const run = await runOf(p, recorderFactory([() => [send(UP.reset), send(UP.reset)]], { reads: sent => sent.map((e, i) => ({ seq: e.seq, records: [rec(i ? 'refutes' : 'confirms')] })) }));
  assert.deepEqual(clauseVerdicts(rowOf(run)), ['pass', 'fail']);
  const reseal = edit => { const x = structuredClone(run), row = rowOf(x); edit(row.trace[1].data, row); row.evidenceDigest = digest({ evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions }); return x; };
  const refused = (copy, why) => assert.throws(() => validateHttpRunEvidence(copy), error => error.code === 'invalid-run-evidence', why);
  validateHttpRunEvidence(reseal(() => {}));
  refused(reseal(d => { d.resolutions[0].records[0].result = 'refutes'; }), 'a record flipped');
  refused(reseal(d => { d.resolutions.reverse(); }), 'reordered');
  refused(reseal(d => { delete d.resolutions; }), 'dropped');
  refused(reseal(d => { delete d.effects[0].resolution.redecided; }), 'the re-decide flag');
  refused(reseal(d => { d.effects[1].verdict = 'pass'; }), 'a verdict');
  refused(reseal(d => { d.resolutions[0].records.push({ resolver: 'r0', status: 'succeeded', result: 'confirms' }); }), 'an r0 record');
  const unsealed = structuredClone(run); rowOf(unsealed).trace[1].data.resolutions[1].records[0].result = 'confirms'; refused(unsealed, 'the evidence digest');
});

// --- Identity option B (actor-identity/6) reads the late records too -----------------------------------------------------------------
// The test/http-identity-rests-on.test.mjs fixture, with its host forwarded (crm.example, which the stub covers): the failed control I1 opts in (agent-write over a
// partial window) and its one send was reset after the connect. In doubt, that send could be a commit by an unknown actor, so I1's failure is
// not admitted and X, which rests on N4, stays withheld. Refuted late, the send is no commit at all, so the gap-only missing is admitted and X
// is released. The connector reads failureAdmitted over the row's bound windows; the validator agrees only because src/contracts.mjs binds
// the row's sealed records there too (without that binding it reads the send in doubt and refuses the run).
test('12. identity option B: a failed control admitted only through a late refutation releases the check resting on it, and the validator binds the row\'s records to agree', async () => {
  const LEDGER = CRM, env = { SCOPEHAVEN_TARGET_MEMBER: 'tok-member' };   // the host the stub resolver covers
  const TITLE = { I1: 'Alpha ledger', I2: 'Bravo ledger', N3: 'Charlie folder', N4: 'Delta folder' };
  const control = (id, path, extra = {}) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId: 'member', method: 'GET', path, evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/title', expected: TITLE[id] }], ...extra });
  const observer = { id: 'gate', type: 'egress-recorder', port: 40998, routing: 'proxy', settleMs: 250, quietMs: 150, witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' },
    destinations: [{ host: LEDGER, paths: ['/api/invoices/1'], forward: { upstream: 'http://127.0.0.1:47105', rejected: [409], proofEnv: 'SCOPEHAVEN_TARGET_LEDGER_PROOF' } }] };
  const p = { id: 'rests-app', name: 'Rests app', applicationId: 'rests-app', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
    actors: { member: { principalId: 'member', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member' } }, observers: [observer], requiredControlIds: ['WHOAMI', 'I1', 'I2', 'N3', 'N4'],
    checks: [control('WHOAMI', '/api/me', { assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member' }] }),
      control('I1', '/api/invoices/1', { method: 'POST', effects: [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: LEDGER, upstream: 'resolved' }, semantics: 'agent-write' }] }),
      control('I2', '/api/invoices/2', { method: 'POST' }), control('N3', '/api/notes/3'),
      { id: 'X', title: 'X', category: 'Object access', severity: 'high', actorId: 'member', method: 'GET', path: '/api/notes/9', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 404 }], restsOn: ['N4'] },
      control('N4', '/api/notes/4')] };
  const forward = declaredObserverRecord([observer])[0].forward;
  const factory = reads => configs => configs.map(cfg => {
    const instanceId = `${cfg.type}-${cfg.id}`, sent = [];
    let mark = 0, k = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [LEDGER], actorAttribution: 'none', evidence: 'authoritative', forward }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect(from, to, options) {
        const events = !options?.gap && k++ === 0 ? [makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, observedAt: '2026-10-16T00:00:00.000Z', operation: 'send', name: LEDGER,
          resource: 'POST /api/invoices/1', outcome: 'committed', content: { n: 1 }, upstream: { ...structuredClone(UP.reset), target: { exact: true, query: false } } })] : [];
        sent.push(...events);
        return { events, coverage: 'partial', reason: 'synthetic' };
      },
      async resolutionRecords() { return reads(sent); } };
  });
  const app = async (_origin, check, { credential }) => {
    const reply = (status, json = {}) => ({ status, complete: true, jsonParsed: true, json, bytes: 2 });
    if (credential !== 'tok-member') return reply(401);
    if (check.id === 'WHOAMI') return reply(200, { user: 'member' });
    return check.severity === 'control' ? reply(200, { title: TITLE[check.id] }) : reply(404);
  };
  const suite = createRegistry({ profiles: [p], env }).exportSuite(p.id);
  const runWith = async reads => {
    const run = await runHttpAssessment(p, { env, transport: app, observerFactory: factory(reads) });
    validateHttpRunEvidence(run, { expectedSuite: suite });
    validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suite });
    return run;
  };
  const i1Of = run => run.results.find(r => r.id === 'I1');
  const refuted = await runWith(sent => sent.map(e => ({ seq: e.seq, records: [rec('refutes')] })));
  const inDoubt = await runWith(() => []);
  assert.deepEqual([i1Of(refuted).trace[1].data.effects[0].verdict, i1Of(refuted).trace[1].data.effects[0].resolution.redecided, Object.hasOwn(i1Of(refuted).trace[1].data, 'resolutions')], ['missing', true, true]);
  assert.deepEqual([i1Of(inDoubt).trace[1].data.effects[0].verdict, Object.hasOwn(i1Of(inDoubt).trace[1].data, 'resolutions')], ['missing', false]);
  assert.equal(refuted.results.find(r => r.id === 'X').status, 'pass', 'released: I1 failed only on a gap once its send was refuted');
  assert.equal(inDoubt.results.find(r => r.id === 'X').status, 'inconclusive', 'withheld: the send in doubt could be an unknown actor\'s commit');
});

test('13. a late record for a send in a settlement gap binds nothing: only check-window attempts take records (gap sends keep the transport record alone), and the run validates', async () => {
  const p = profileOf([[EXISTS], [EXISTS]]);
  // Gap 0 is before the first check, gap 1 between the checks, gap 2 the run-end tail: a reset close in the middle gap, between the checks.
  const run = await runOf(p, recorderFactory([() => [send(UP.reset)], () => [send(UP.applied)]], { gaps: [() => [], () => [send(UP.reset)]], reads: lateFor(() => rec('confirms')) }));
  const gapSend = run.settlement.gaps[1].windows[0].events;
  assert.equal(gapSend.length, 1, 'the gap holds the send');
  const sealed = run.results.filter(r => r.trace?.[1]).flatMap(r => r.trace[1].data.resolutions ?? []);
  assert.deepEqual(sealed.map(x => x.seq), [rowOf(run).trace[1].data.windows[0].events[0].seq], 'only the first check\'s own attempt is sealed');
  assert.equal(Object.hasOwn(run.settlement.gaps[1].windows[0], 'resolutions'), false);
  // TASK1 passes on its own confirmed attempt. TASK2's pass is then read by settlement against the gap send (still in doubt, the transport record alone),
  // and the validator recomputes that reading too (runOf validated the run).
  assert.deepEqual(clauseVerdicts(rowOf(run)), ['pass']);
});

// --- With the suspend-aware lead-in and stop: a sleep-partial window and a stopped check -----------------------------------------------
// TASK1's settle is cut by a host sleep the budget cannot restore: its window reads partial (host-suspend-wait-short) and the run stops, so
// TASK2 is not sent (host-suspend-run-stopped). The stage keeps the stopped row as it is (no window, no attempt, no record), and on the
// sleep-partial window a late refutation is read exactly as the transport record's: it decides no pass and no operation, as that record
// (a keyed effect.only can still reach the fail an earlier evaluator and the transport record reach, when a refuted member leaves its key
// group). A late confirmation is read
// as a proven applied reply would be on that window: a recorded application decides presence (exists passes, and effect.only, which
// expects nothing, fails), while a count still needs complete coverage.
test('14. a sleep-partial window decides nothing through a late refutation, and a check the run stopped stays without a window, attempt or record', async () => {
  const WALL0 = Date.parse('2026-10-16T20:14:00.000Z');
  const virtual = () => {
    const v = { now: 1000, suspended: 0, cut: false };
    v.clock = { now: () => v.now, sleep: async ms => { if (ms === 250 && !v.cut) { v.cut = true; v.now += 70100; v.suspended += 70000; } else v.now += ms; await null; } };
    v.detector = createSuspendDetector({ wall: () => WALL0 + v.now, awake: () => v.now - v.suspended, elapsed: () => v.now, timersCountSuspend: true });
    v.transport = async (...args) => { v.now += 20; return transport(...args); };
    return v;
  };
  const p = profileOf([[EXISTS, count(1), ONLY], [EXISTS]]);
  const runWith = async result => {
    const v = virtual();
    const run = await runHttpAssessment(p, { env: {}, transport: v.transport, clock: v.clock, suspendClock: v.detector,
      observerFactory: recorderFactory([() => [send(UP.reset)], () => [send(UP.reset)]], { reads: sent => sent.map(e => ({ seq: e.seq, records: [rec(result)] })) }) });
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
    validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suiteOf(p) });
    return run;
  };
  for (const [result, verdicts, operations] of [['refutes', ['missing', 'missing', 'missing'], ['in-doubt', 'in-doubt', 'in-doubt']], ['confirms', ['pass', 'missing', 'fail'], ['confirmed', 'confirmed', 'confirmed']]]) {
    const run = await runWith(result), t1 = rowOf(run), t2 = rowOf(run, 'TASK2'), w = t1.trace[1].data.windows[0];
    assert.deepEqual([w.coverage, w.reason.split(',').includes('host-suspend-wait-short'), w.suspend.shortMs > 0], ['partial', true, true], result);
    assert.deepEqual([t1.trace[1].data.effects.map(e => e.verdict), t1.trace[1].data.effects.map(e => e.resolution.operation), t1.trace[1].data.effects.every(e => e.resolution.redecided)], [verdicts, operations, true], result);
    assert.deepEqual([t2.trace.length, t2.trace[0].data.notSent, t2.status], [1, 'host-suspend-run-stopped', 'inconclusive'], `${result}: the stopped check`);
    assert.deepEqual(run.results.flatMap(r => r.trace[1]?.data?.resolutions ?? []).map(x => x.seq), [w.events[0].seq], `${result}: only TASK1's own attempt takes a record`);
  }
});

// Suspend follow-ups beside the stage: without a timing plan a settle the spare budget could not restore goes on into the time kept
// for later checks (its windows' record carries reserveMs), and the run stops after it either way. The stage reads no suspend record, so a
// window restored that way is re-decided exactly as an awake window and as one the spare budget restored, and the check the run stopped
// has no window, attempt or record. TASK2's own window holds no send, so nothing after TASK1 can settle TASK1's clauses differently.
test('15. a window restored from the later checks\' time is re-decided exactly as an awake complete window, and the check the run stopped stays without a window, attempt or record', async () => {
  const WALL0 = Date.parse('2026-10-16T21:10:00.000Z');
  // asleep: 100 ms of awake time into TASK1's 250 ms settle (the first 250 ms wait), then asleep for that long.
  const virtual = asleep => {
    const v = { now: 1000, suspended: 0, cut: false };
    v.clock = { now: () => v.now, sleep: async ms => { if (asleep && ms === 250 && !v.cut) { v.cut = true; v.now += asleep + 100; v.suspended += asleep; } else v.now += ms; await null; } };
    v.detector = createSuspendDetector({ wall: () => WALL0 + v.now, awake: () => v.now - v.suspended, elapsed: () => v.now, timersCountSuspend: true });
    v.transport = async (...args) => { v.now += 20; return transport(...args); };
    return v;
  };
  const p = profileOf([[EXISTS, count(1), ONLY], [EXISTS]]);
  const runWith = async (result, asleep) => {
    const v = virtual(asleep);
    seq = 0; // each run's attempt gets the same seq, so the three runs compare byte for byte
    const run = await runHttpAssessment(p, { env: {}, transport: v.transport, clock: v.clock, suspendClock: v.detector,
      observerFactory: recorderFactory([() => [send(UP.reset)], () => []], { reads: sent => sent.map(e => ({ seq: e.seq, records: [rec(result)] })) }) });
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
    validateHttpRunEvidence(JSON.parse(JSON.stringify(run)), { expectedSuite: suiteOf(p) });
    return run;
  };
  // What the stage decided for TASK1: each clause's verdict and resolution record, and the row's sealed late records.
  const stageOf = run => ({ effects: rowOf(run).trace[1].data.effects.map(e => ({ verdict: e.verdict, resolution: e.resolution })), resolutions: rowOf(run).trace[1].data.resolutions.map(x => x.records), status: rowOf(run).status });
  for (const result of ['refutes', 'confirms']) {
    // Awake; 3 s asleep, restored within the spare budget; 58 s asleep, past the spare budget (laterNeedMs keeps TASK2's 3,250 ms) and
    // restored from the later checks' time.
    const [awake, spare, reserve] = [await runWith(result, 0), await runWith(result, 3000), await runWith(result, 58000)];
    const w = run => rowOf(run).trace[1].data.windows[0];
    assert.deepEqual([w(awake).coverage, Object.hasOwn(w(awake), 'suspend')], ['complete', false], result);
    assert.deepEqual([w(spare).coverage, Object.hasOwn(w(spare).suspend, 'reserveMs'), Object.hasOwn(w(spare).suspend, 'shortMs')], ['complete', false, false], result);
    assert.deepEqual([w(reserve).coverage, w(reserve).suspend.reserveMs, Object.hasOwn(w(reserve).suspend, 'shortMs'), w(reserve).reason], ['complete', 250, false, null], result);
    // The stage ran (every clause re-decided) and decided the same on all three windows.
    assert.ok(stageOf(awake).effects.every(e => e.resolution.redecided === true), result);
    assert.deepEqual(stageOf(spare), stageOf(awake), `${result}: restored within the spare budget`);
    assert.deepEqual(stageOf(reserve), stageOf(awake), `${result}: restored from the later checks' time`);
    // TASK2 is sent on the other two; on the restored run it is not sent, and has no window, attempt or record.
    for (const run of [awake, spare]) assert.equal(rowOf(run, 'TASK2').trace.length, 2, result);
    const t2 = rowOf(reserve, 'TASK2');
    assert.deepEqual([t2.trace.length, t2.trace[0].data.notSent, t2.trace[0].data.requestAttempted, t2.status], [1, 'host-suspend-run-stopped', false, 'inconclusive'], `${result}: the stopped check`);
    assert.deepEqual(reserve.results.flatMap(r => r.trace[1]?.data?.resolutions ?? []).map(x => x.seq), [w(reserve).events[0].seq], `${result}: only TASK1's own attempt takes a record`);
  }
});
