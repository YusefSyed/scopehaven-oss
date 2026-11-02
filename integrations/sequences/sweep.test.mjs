// Boundary sweep (sweep/): the spec, the generator and the verdict rules, each with its allowed and forbidden case.
// Pure: no process, no socket. The runs against the owned relay desk are in sweep-run.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateSequence } from './sequence.mjs';
import { validateSweepSpec, gateRules, passiveWrote, OTHER_RULE } from './sweep/spec.mjs';
import { baselineSequence, observeBaseline, planSweep, executionSequence, stepsFor } from './sweep/plan.mjs';
import { conditionFired, executionOutcome, caseVerdict, passiveCalls } from './sweep/aggregate.mjs';
import { relaySpec, relayOtherTwinSpec } from './sweep/fixtures/relay-desk.mjs';
import { ic1Spec, oracleBoundaries, score } from './sweep/ic1/run.mjs';
import { drainingGate } from './sweep/runner.mjs';

const SPEC = relaySpec('unit');
// "model" is the relay spec's passive path; "other" is the catch-all for undeclared paths.
const IC1_24_SHAPE = [['model', 200], ['tool', 201], ['model', 200], ['tool', 202], ['model', 200], ['deliver', 201]];
const invalid = (mutate, pattern, message) => { const spec = structuredClone(SPEC); mutate(spec); assert.throws(() => validateSweepSpec(spec), pattern, message); };

// A baseline run as runSequence records it: the gate's timeline, the sealed start>end window and the control rows. Each
// call is [rule, status, method, overrides], sent as POST with no method override unless it names them (the gate records
// each forwarded request's method and method overrides).
const QUIET = ['tool', 'deliver', 'model', 'other'];
const quietRows = (quiet = {}) => QUIET.map(id => ({ id: `QUIET-${id}`, status: quiet[id] ?? 'pass' }));
function baselineRun({ calls = IC1_24_SHAPE, aborted = null, turn = { status: 200, complete: true }, allowed = { tool: 'pass', deliver: 'pass' }, quiet = {}, sealed = null, coverage = 'complete', answerOrder = null } = {}) {
  let seq = 0;
  const timeline = [], forwarded = calls.map(([ruleId, , method = 'POST', methodOverrides = []], i) => { const e = { seq: ++seq, type: 'forwarded', reqId: `r${i}`, ruleId, method, methodOverrides }; timeline.push(e); return e; });
  for (const i of answerOrder ?? calls.map((_, i) => i)) { const [ruleId, status] = calls[i]; if (status !== null) timeline.push({ seq: ++seq, type: 'response', reqId: forwarded[i].reqId, ruleId, status }); }
  const names = sealed ?? calls.map(([name]) => name);
  return { aborted, responses: { turn }, gateTimeline: timeline, windows: { 'start>end': [{ source: 'hold-proxy', coverage, events: names.map(name => ({ name })) }] },
    results: [...Object.entries(allowed).map(([id, status]) => ({ id: `ALLOWED-${id}`, status })), ...quietRows(quiet)] };
}
// Calls answered in order, each right after it was forwarded (the order a sequential agent loop makes them in).
function interleaved(calls) {
  let seq = 0;
  const run = baselineRun({ calls });
  run.gateTimeline = calls.flatMap(([ruleId, status, method = 'POST', methodOverrides = []], i) => [{ seq: ++seq, type: 'forwarded', reqId: `r${i}`, ruleId, method, methodOverrides }, { seq: ++seq, type: 'response', reqId: `r${i}`, ruleId, status }]);
  return run;
}
// An execution run: its timeline steps in the given order, the access change's answer and its rows. A row's evidence
// names a gate entry: a request forwarded inside the window (seq 2), or, "early", only the answer of a request
// forwarded before the window (seq 1). The run's one passive call (model) is sent as modelMethod with modelOverrides and
// answered modelStatus (null: never answered).
const STEP = { held: { step: 'held', hold: 'held' }, condition: { step: 'response', request: 'condition', status: 200 }, suspended: { step: 'mark', mark: 'suspended' }, released: { step: 'released', hold: 'held' } };
const ev = early => [{ source: 'hold-proxy', seq: early ? 1 : 2 }];
function executionRun({ order = ['held', 'condition', 'suspended', 'released'], condition = { status: 200, complete: true }, rows = { tool: 'pass', deliver: 'pass' }, twins = { tool: 'pass', deliver: 'pass' }, quiet = {}, change = {}, undeclared = 'pass', aborted = null, answeredBefore = false, twinEarly = false, modelStatus = 200, modelMethod = 'POST', modelOverrides = [] } = {}) {
  return { aborted, timeline: order.map(k => STEP[k]), responses: { condition },
    gateTimeline: [{ seq: 1, type: 'response', reqId: 'early', status: 201 }, { seq: 2, type: 'forwarded', reqId: 'late', method: 'POST', methodOverrides: [] }, { seq: 3, type: 'forwarded', reqId: 'm', ruleId: 'model', method: modelMethod, methodOverrides: modelOverrides },
      ...(modelStatus === null ? [] : [{ seq: 4, type: 'response', reqId: 'm', ruleId: 'model', status: modelStatus }])],
    results: [...Object.entries(rows).map(([id, status]) => ({ id: `NO-${id}-AFTER`, status, verdict: status, ...(status === 'fail' ? { evidence: ev(answeredBefore) } : {}) })),
      ...['tool', 'deliver'].map(id => ({ id: `CHANGE-${id}`, status: change[id] ?? 'pass' })), { id: 'UNDECLARED', status: undeclared },
      ...quietRows(quiet), ...Object.entries(twins).map(([id, status]) => ({ id: `TWIN-${id}`, status, verdict: status, ...(status === 'pass' ? { evidence: ev(twinEarly) } : {}) }))] };
}
const BOTH = { twins: ['tool', 'deliver'] };
const observedPlan = (calls, spec = SPEC) => planSweep(spec, observeBaseline(interleaved(calls), spec));
const signalled = plan => plan.executions.filter(e => e.origins.length > 1).map(e => e.id);

test('spec: the relay spec is valid, and each required declaration is refused when missing or malformed', () => {
  assert.equal(validateSweepSpec(structuredClone(SPEC)).id, 'unit');
  invalid(s => { s.schema = 'scopehaven-sweep-spec/2'; }, /schema/);
  invalid(s => { s.actors.user.credentialEnv = 'API_KEY'; }, /SCOPEHAVEN_TARGET_/);
  invalid(s => { delete s.condition.expect; }, /condition\.expect/);
  invalid(s => { delete s.restore; }, /needs "restore", or a "twinTurn"/);
  invalid(s => { delete s.restore; s.twinTurn = { ...s.turn }; }, /needs "restore", or a "twinTurn"/, 'a twin by the changed actor, never restored, could not apply anything');
  invalid(s => { s.restore.expect = []; }, /restore\.expect/);
  invalid(s => { s.twinTurn = { ...s.turn, actorId: 'nobody' }; }, /twinTurn needs an actorId/);
  assert.equal(validateSweepSpec(relayOtherTwinSpec('other-twin')).twinTurn.actorId, 'other');
  invalid(s => { s.actions[0].id = OTHER_RULE; }, /reserved/);
  invalid(s => { s.actions[1].id = s.actions[0].id; }, /declared twice/);
  invalid(s => { s.actions[0].id = 'a'.repeat(17); }, /1 to 16/);
  invalid(s => { s.actions[0].method = 'POST'; }, /declares a method/, 'the gate names every method on a prefix, so a method-limited action would number other requests');
  invalid(s => { s.world = { command: ['node', 'launch.mjs'] }; }, /absolute path/);
  assert.equal(validateSweepSpec({ ...structuredClone(SPEC), world: { command: ['/usr/bin/true'] } }).world.command[0], '/usr/bin/true');
});

test('spec: passive paths are declared like actions, never as actions, and signals name only actions', () => {
  invalid(s => { s.passive[0].id = 'tool'; }, /declared twice/, 'a passive path cannot reuse an action id');
  invalid(s => { s.passive[0].id = OTHER_RULE; }, /reserved/);
  invalid(s => { s.passive[0].pathPrefix = 'v1'; }, /passive path needs/);
  invalid(s => { s.passive[0].rejected = [403]; }, /only an action can/, 'a declared refusal belongs to an action');
  invalid(s => { s.passive[0].method = 'POST'; }, /declares a method/);
  invalid(s => { s.passive = 'model'; }, /passive lists/);
  invalid(s => { s.signals = [{ status: 202, deliveredBy: 'model' }]; }, /deliveredBy from actions/, 'a delivery is an action');
  invalid(s => { s.signals = [{ status: 202, action: 'model' }]; }, /an action and a deliveredBy from actions/);
  invalid(s => { s.signals = [{ status: 202, action: 'tool', deliveredBy: 'tool' }]; }, /deliveredBy "tool" is the signal's own action/, 'its next call is the turn\'s next step');
  assert.equal(validateSweepSpec({ ...structuredClone(SPEC), signals: [{ status: 202, action: 'tool', deliveredBy: 'deliver' }] }).signals[0].deliveredBy, 'deliver');
  const { passive: _passive, ...bare } = structuredClone(SPEC);
  assert.equal(validateSweepSpec(bare).id, 'unit', 'passive is optional: without it, every non-action call is undeclared');
});

test('spec: a passive path may not be "/" nor cover or fall inside an action\'s prefix, compared case-folded', () => {
  invalid(s => { s.passive = [{ id: 'rest', pathPrefix: '/' }]; }, /passive path rest is "\/"/, 'a catch-all passive would hide every action');
  invalid(s => { s.passive.push({ id: 'to', pathPrefix: '/to' }); }, /passive path to overlaps action tool/, 'it covers /tool/');
  invalid(s => { s.passive.push({ id: 'b', pathPrefix: '/tool/close_ticket' }); }, /passive path b overlaps action tool/, 'it falls inside /tool/');
  invalid(s => { s.actions[0].pathPrefix = '/Tool/'; s.passive.push({ id: 'b', pathPrefix: '/tool/close_ticket' }); }, /overlaps action tool/, 'the gate matches paths case-folded');
  assert.equal(validateSweepSpec({ ...structuredClone(SPEC), passive: [...SPEC.passive, { id: 'lookup', pathPrefix: '/lookup/' }] }).passive.length, 2, 'a read-only path beside the actions is fine');
});

test('spec: no declared prefix may hold "%" or a dot segment, because the gate matches decoded, dot-resolved paths', () => {
  invalid(s => { s.actions[0].pathPrefix = '/tool/%62'; }, /action tool has "%" in its prefix/, 'an encoded action');
  invalid(s => { s.passive.push({ id: 'b', pathPrefix: '/lookup/%61' }); }, /passive path b has "%" in its prefix/);
  invalid(s => { s.actions[0].pathPrefix = '/tool/x/../b'; }, /action tool has a dot segment/);
  invalid(s => { s.passive.push({ id: 'b', pathPrefix: '/lookup/./b' }); }, /passive path b has a dot segment/);
  invalid(s => { s.actions[1].pathPrefix = '/deliver/..'; }, /action deliver has a dot segment/, 'a trailing dot segment too');
  assert.equal(validateSweepSpec({ ...structuredClone(SPEC), passive: [...SPEC.passive, { id: 'v', pathPrefix: '/v1.2/.well-known/' }] }).passive.length, 2, 'dots inside a segment are not dot segments');
});

test('spec: gate rules put the declared actions first, then the passive paths, then a catch-all that never holds', () => {
  const plain = gateRules(SPEC);
  assert.deepEqual(plain.map(r => [r.id, r.pathPrefix]), [['tool', '/tool/'], ['deliver', '/deliver/'], ['model', '/v1/chat/completions'], [OTHER_RULE, '/']]);
  assert.ok(plain.every(r => r.holds === 0), 'a baseline holds nothing');
  assert.deepEqual(plain[0].rejected, [403], 'declared refusals reach the gate');
  assert.equal(Object.hasOwn(plain[2], 'rejected') || Object.hasOwn(plain[3], 'rejected'), false, 'passive paths and the catch-all declare no refusal');
  assert.deepEqual(gateRules(SPEC, { rule: 'deliver', k: 2 }).map(r => r.holds), [0, 2, 0, 0]);
  assert.deepEqual(gateRules(SPEC, { rule: 'model', k: 3 }).map(r => r.holds), [0, 0, 3, 0]);
  assert.deepEqual(gateRules(SPEC, { rule: OTHER_RULE, k: 3 }).map(r => r.holds), [0, 0, 0, 0], 'an undeclared path is never a boundary');
});

test('generator: the baseline holds nothing, carries one allowed-use control per action, and waits a quiet window after the settle', () => {
  const seq = validateSequence(baselineSequence(SPEC));
  assert.equal(seq.steps.some(s => s.awaitHold), false);
  assert.deepEqual(seq.assertions.map(a => [a.id, a.severity, a.effect.kind, a.effect.select.name, a.from, a.to]), [['ALLOWED-tool', 'control', 'effect.exists', 'tool', 'start', 'end'], ['ALLOWED-deliver', 'control', 'effect.exists', 'deliver', 'start', 'end'],
    ...QUIET.map(id => [`QUIET-${id}`, 'control', 'effect.none', id, 'end', 'quiet'])]);
  assert.deepEqual(seq.steps.map(s => Object.keys(s)[0]), ['mark', 'request', 'sleep', 'mark', 'sleep', 'mark']);
  assert.deepEqual([seq.steps[2].sleep, seq.steps[3].mark, seq.steps[4].sleep, seq.steps[5].mark], [SPEC.settleMs, 'end', SPEC.settleMs, 'quiet'], 'the settle, then the settle again as the quiet window');
});

test('generator: the baseline lists every forwarded call in order, numbered within its rule', () => {
  const o = observeBaseline(baselineRun(), SPEC);
  assert.equal(o.observed, true, o.reasons.join());
  assert.equal(o.allowedUse, true);
  assert.deepEqual(o.allowedActions, ['tool', 'deliver']);
  assert.deepEqual(o.calls.map(c => `${c.rule}${c.k}:${c.status}`), ['model1:200', 'tool1:201', 'model2:200', 'tool2:202', 'model3:200', 'deliver1:201']);
});

test('generator: a baseline that stopped, was refused, missed a call or disagrees with its sealed window is not observed', () => {
  const reasons = run => observeBaseline(run, SPEC).reasons;
  assert.deepEqual(reasons(baselineRun({ aborted: 'step-error' })), ['baseline-stopped:step-error']);
  assert.deepEqual(reasons(baselineRun({ turn: { status: 401, complete: true } })), ['turn-not-accepted']);
  assert.deepEqual(reasons(baselineRun({ turn: { status: 200, complete: false } })), ['turn-not-accepted']);
  assert.deepEqual(reasons(baselineRun({ calls: [['model', 200], [null, 200]], sealed: ['model', 'ungated'] })), ['ungated-call']);
  assert.deepEqual(reasons(baselineRun({ calls: [['model', 200], ['tool', 201], ['deliver', null]] })), ['call-without-answer']);
  assert.deepEqual(reasons(baselineRun({ sealed: ['model', 'tool', 'model', 'tool', 'model'] })), ['timeline-window-mismatch']);
  assert.deepEqual(reasons(baselineRun({ coverage: 'partial' })), ['gate-window-incomplete']);
  assert.deepEqual(reasons({ ...baselineRun(), gateTimeline: null }), ['no-gate-timeline', 'timeline-window-mismatch']);
  assert.deepEqual(reasons(baselineRun({ quiet: { model: 'fail' } })), ['baseline-not-quiet'], 'a call after the settle: the settle is too short for this turn');
  assert.deepEqual(reasons(baselineRun({ quiet: { deliver: 'inconclusive' } })), ['baseline-not-quiet']);
  assert.equal(observeBaseline(baselineRun({ aborted: 'step-error' }), SPEC).observed, false);
});

test('generator: a call on a path the spec declares neither as an action nor as passive makes the baseline unobserved', () => {
  // A delivery path the spec left out: its calls fall to the catch-all, where no prohibition would judge them.
  const o = observeBaseline(baselineRun({ calls: [['model', 200], ['tool', 202], ['model', 200], ['other', 201]] }), SPEC);
  assert.deepEqual([o.observed, o.reasons], [false, ['undeclared-call']]);
  assert.deepEqual(planSweep(SPEC, o).executions, []);
  assert.equal(observeBaseline(baselineRun({ calls: [['model', 200], ['tool', 201], ['model', 200]] }), SPEC).observed, true);
});

test('generator: a passive call answered 201, 202 or 204 wrote something, so the baseline is not observed', () => {
  assert.deepEqual(observeBaseline(baselineRun({ calls: [['model', 201], ['tool', 201], ['model', 200]] }), SPEC).reasons, ['passive-call-wrote'], 'a created resource');
  assert.deepEqual(observeBaseline(baselineRun({ calls: [['model', 200], ['tool', 201], ['model', 202]] }), SPEC).reasons, ['passive-call-wrote'], 'an accepted job');
  assert.deepEqual(observeBaseline(baselineRun({ calls: [['model', 204], ['tool', 201], ['model', 200]] }), SPEC).reasons, ['passive-call-wrote'], 'a write with no body (the usual answer to a PUT or DELETE)');
  assert.deepEqual(observeBaseline(baselineRun({ calls: [['model', 200], ['tool', 202], ['model', 203], ['deliver', 204]] }), SPEC).reasons, [], 'other statuses, and an action\'s 202 or 204, are not a passive write');
});

test('generator: a passive call sent with PUT, PATCH, DELETE or any method but GET, HEAD, OPTIONS, TRACE or POST wrote, whatever its answer', () => {
  const reasons = (method, status = 200) => observeBaseline(baselineRun({ calls: [['model', 200], ['tool', 201], ['model', status, method]] }), SPEC).reasons;
  // A PUT answered 200, and the other write methods: each read as a write from its method alone.
  for (const method of ['PUT', 'PATCH', 'DELETE']) assert.deepEqual(reasons(method), ['passive-call-wrote'], `${method} answered 200`);
  assert.deepEqual(reasons('DELETE', 404), ['passive-call-wrote'], 'whatever the answer');
  assert.deepEqual(reasons('MOVE'), ['passive-call-wrote'], 'a WebDAV write is not a read either: the methods are an allowlist');
  assert.deepEqual(reasons(null), ['passive-call-wrote'], 'a call whose method the timeline does not record counts as a write');
  // The model route's POST and RFC 9110's safe methods are not a write when answered 200 (a write sent so is the documented residual).
  for (const method of ['POST', 'GET', 'HEAD', 'OPTIONS', 'TRACE']) assert.deepEqual(reasons(method), [], method);
  assert.deepEqual(reasons('POST', 201), ['passive-call-wrote'], 'a POST is still judged by its answer');
  // An action's method is never a passive write: every method on an action's prefix is judged by its rows.
  assert.deepEqual(observeBaseline(baselineRun({ calls: [['model', 200], ['tool', 200, 'PUT'], ['model', 200], ['deliver', 204, 'DELETE']] }), SPEC).reasons, []);
  // The baseline lists each call's method.
  assert.deepEqual(observeBaseline(baselineRun({ calls: [['model', 200, 'GET'], ['tool', 201, 'PATCH'], ['model', 200]] }), SPEC).calls.map(c => `${c.rule}${c.k}:${c.method}:${c.status}`), ['model1:GET:200', 'tool1:PATCH:201', 'model2:POST:200']);
  assert.deepEqual([passiveWrote({ method: 'POST', overrides: [], status: 200 }), passiveWrote({ method: 'PUT', overrides: [], status: 200 }), passiveWrote({ method: 'GET', overrides: [], status: 204 })], [false, true, true]);
});

test('generator: a passive call whose method override is not GET, HEAD, OPTIONS, TRACE or POST wrote, whatever its request line and answer', () => {
  const reasons = (overrides, method = 'POST') => observeBaseline(baselineRun({ calls: [['model', 200], ['tool', 201], ['model', 200, method, overrides]] }), SPEC).reasons;
  // A Rack-style POST that asks for DELETE, answered 200, and the other write methods an override can name.
  for (const override of ['DELETE', 'PUT', 'PATCH', 'MOVE']) assert.deepEqual(reasons([override]), ['passive-call-wrote'], override);
  // Compared as sent: a Rails form's lowercase "patch" is a write, and so are a lowercase "get", an empty value (one the gate
  // could not read) and two values joined.
  for (const override of ['patch', 'get', '', 'DELETE, GET']) assert.deepEqual(reasons([override]), ['passive-call-wrote'], JSON.stringify(override));
  assert.deepEqual(reasons(['GET', 'DELETE']), ['passive-call-wrote'], 'every override must be allowed, not only the first');
  assert.deepEqual(reasons(['DELETE'], 'GET'), ['passive-call-wrote'], 'whatever the request line says');
  assert.deepEqual(reasons(null), ['passive-call-wrote'], 'a call whose overrides the timeline does not record counts as a write');
  // An override to an allowed method, or none, is not a write.
  for (const override of ['GET', 'HEAD', 'OPTIONS', 'TRACE', 'POST']) assert.deepEqual(reasons([override]), [], override);
  assert.deepEqual(reasons([]), []);
  // An action's override is never a passive write: every call on an action's prefix is judged by its rows.
  assert.deepEqual(observeBaseline(baselineRun({ calls: [['model', 200], ['tool', 200, 'POST', ['DELETE']], ['model', 200]] }), SPEC).reasons, []);
  // The baseline lists each call's overrides.
  assert.deepEqual(observeBaseline(baselineRun({ calls: [['model', 200], ['tool', 201, 'POST', ['PUT']], ['model', 200]] }), SPEC).calls.map(c => c.overrides), [[], ['PUT'], []]);
  assert.deepEqual([passiveWrote({ method: 'POST', overrides: [], status: 200 }), passiveWrote({ method: 'POST', overrides: ['DELETE'], status: 200 }), passiveWrote({ method: 'POST', status: 200 })], [false, true, true]);
});

test('generator: allowed use needs a passing allowed-use row of a declared action', () => {
  assert.equal(observeBaseline(baselineRun({ allowed: { tool: 'fail', deliver: 'pass' } }), SPEC).allowedUse, true, 'one action applied is allowed use');
  assert.deepEqual(observeBaseline(baselineRun({ allowed: { tool: 'fail', deliver: 'pass' } }), SPEC).allowedActions, ['deliver'], 'only the actions applied get twins');
  assert.equal(observeBaseline(baselineRun({ allowed: { tool: 'fail', deliver: 'fail' } }), SPEC).allowedUse, false);
  assert.equal(observeBaseline(baselineRun({ allowed: { other: 'pass' } }), SPEC).allowedUse, false, 'a row of an undeclared action is not allowed use');
});

test('generator: one execution per observed call, not a fixed list, with the 202 signal on the first call after the queued answer', () => {
  const plan = observedPlan(IC1_24_SHAPE);
  assert.deepEqual(plan.executions.map(e => e.id), ['model1', 'tool1', 'model2', 'tool2', 'model3', 'deliver1']);
  assert.deepEqual(plan.executions.map(e => e.k), [1, 1, 2, 2, 3, 1]);
  assert.deepEqual(plan.executions.filter(e => e.origins.length > 1).map(e => [e.id, e.origins]), [['model3', ['boundary', 'signal:202']]]);
  assert.deepEqual(plan.unreachable, []);
  const longer = observedPlan([['model', 200], ['tool', 201], ['tool', 201], ['model', 200], ['tool', 201], ['model', 200]]);
  assert.deepEqual(longer.executions.map(e => e.id), ['model1', 'tool1', 'tool2', 'model2', 'tool3', 'model3']);
});

test('generator: a signal attaches strictly after its answer, to the first answered match, and only to actions by default', () => {
  // The queued answer arrives after a later call was already forwarded: the signal names the next call forwarded after the answer.
  const run = baselineRun({ calls: [['model', 200], ['tool', 202], ['model', 200], ['deliver', 201]] });
  run.gateTimeline = [['forwarded', 'r0', 'model'], ['response', 'r0', 'model', 200], ['forwarded', 'r1', 'tool'], ['forwarded', 'r2', 'model'], ['response', 'r2', 'model', 200],
    ['response', 'r1', 'tool', 202], ['forwarded', 'r3', 'deliver'], ['response', 'r3', 'deliver', 201]].map(([type, reqId, ruleId, status], i) => ({ seq: i + 1, type, reqId, ruleId, ...(status ? { status } : { method: 'POST', methodOverrides: [] }) }));
  assert.deepEqual(signalled(planSweep(SPEC, observeBaseline(run, SPEC))), ['deliver1']);
  // Two queued answers: the signal follows the first one answered.
  assert.deepEqual(signalled(observedPlan([['model', 200], ['tool', 202], ['model', 200], ['tool', 202], ['model', 200], ['deliver', 201], ['deliver', 201]])), ['model2']);
  // An answer from a non-action call raises no signal. (A passive 202 already stops the baseline as a passive write, so
  // this uses a signal status that is not a write.)
  const by203 = { ...SPEC, signals: [{ status: 203 }] };
  const fromModel = observedPlan([['model', 203], ['tool', 201], ['model', 200]], by203);
  assert.deepEqual([signalled(fromModel), fromModel.unreachable], [[], []], 'neither attached nor unreachable: no signal at all');
  assert.deepEqual(signalled(observedPlan([['model', 200], ['tool', 203], ['model', 200], ['deliver', 201]], by203)), ['model2'], 'the same status from an action does');
  // A signal restricted to one action ignores the others' queued answers.
  const onlyDeliver = { ...SPEC, signals: [{ status: 202, action: 'deliver' }] };
  assert.deepEqual(signalled(planSweep(onlyDeliver, observeBaseline(interleaved(IC1_24_SHAPE), onlyDeliver))), []);
});

test('generator: a queued answer pairs only with a later call of its delivery rule; without one the signal is unreachable', () => {
  assert.deepEqual(observedPlan([['model', 200], ['tool', 201], ['model', 200], ['tool', 202]]).unreachable, [{ signal: 'signal:202', after: 'tool2' }]);
  // Followed only by a model call: the delivery it announced was never seen, so the settle missed it.
  assert.deepEqual(observedPlan([['model', 200], ['tool', 202], ['model', 200]]).unreachable, [{ signal: 'signal:202', after: 'tool1' }]);
  // An action before the queued answer is not its delivery.
  assert.deepEqual(observedPlan([['model', 200], ['tool', 201], ['model', 200], ['tool', 202], ['model', 200]]).unreachable, [{ signal: 'signal:202', after: 'tool2' }]);
  // The next call of the same rule is the turn's next step, not this answer's delivery (a slow queue).
  assert.deepEqual(observedPlan([['model', 200], ['tool', 202], ['model', 200], ['tool', 201], ['model', 200]]).unreachable, [{ signal: 'signal:202', after: 'tool1' }]);
  // Another rule's queued call is not a delivery either.
  const queueAndExport = { ...SPEC, actions: [{ id: 'tool', pathPrefix: '/tool/', rejected: [403] }, { id: 'export', pathPrefix: '/export/', rejected: [403] }] };
  const queues = interleaved([['model', 200], ['tool', 202], ['model', 200], ['export', 202], ['model', 200]]);
  queues.results = [{ id: 'ALLOWED-tool', status: 'pass' }, ...['tool', 'export', 'model', 'other'].map(id => ({ id: `QUIET-${id}`, status: 'pass' }))];
  const queued = observeBaseline(queues, queueAndExport);
  assert.equal(queued.observed, true, queued.reasons.join());
  assert.deepEqual(planSweep(queueAndExport, queued).unreachable, [{ signal: 'signal:202', after: 'tool1' }]);
  // Two queued answers need two deliveries: one is not enough.
  assert.deepEqual(observedPlan([['model', 200], ['tool', 202], ['model', 200], ['tool', 202], ['model', 200], ['deliver', 201]]).unreachable, [{ signal: 'signal:202', after: 'tool2' }]);
  // A declared delivery rule: only its calls deliver; another action does not.
  const byDeliver = { ...SPEC, signals: [{ status: 202, deliveredBy: 'deliver' }] }, byTool = { ...SPEC, signals: [{ status: 202, deliveredBy: 'tool' }] };
  const shape = [['model', 200], ['tool', 202], ['model', 200], ['tool', 201], ['model', 200], ['deliver', 201]];
  assert.deepEqual([observedPlan(shape, byDeliver).unreachable, signalled(observedPlan(shape, byDeliver))], [[], ['model2']]);
  // A deliveredBy naming a third action: the other action's later call does not deliver.
  const three = { ...SPEC, actions: [...SPEC.actions, { id: 'export', pathPrefix: '/export/', rejected: [403] }], signals: [{ status: 202, deliveredBy: 'export' }] };
  const viaDeliver = interleaved([['model', 200], ['tool', 202], ['model', 200], ['deliver', 201]]);
  viaDeliver.results.push({ id: 'QUIET-export', status: 'pass' });
  assert.deepEqual(planSweep(three, observeBaseline(viaDeliver, three)).unreachable, [{ signal: 'signal:202', after: 'tool1' }]);
  // A deliveredBy that is the answering rule (the default signal matches any action's 202): the next call of that rule
  // is the turn's next step, so the delivery is ambiguous.
  assert.deepEqual(observedPlan(shape, byTool).unreachable, [{ signal: 'signal:202', after: 'tool1', why: 'delivery-ambiguous' }]);
  assert.deepEqual(observedPlan([['model', 200], ['tool', 202], ['model', 200], ['deliver', 201]], byTool).unreachable, [{ signal: 'signal:202', after: 'tool1', why: 'delivery-ambiguous' }]);
});

test('generator: with two or more other actions and no deliveredBy the delivery is ambiguous, so the signal is unreachable', () => {
  // A split spec: a later close is an unrelated step, not the queued credit's delivery.
  const split = { ...SPEC, actions: [{ id: 'credit', pathPrefix: '/tool/issue_credit', rejected: [403] }, { id: 'close', pathPrefix: '/tool/close_ticket', rejected: [403] }, { id: 'deliver', pathPrefix: '/deliver/', rejected: [403] }] };
  const run = calls => { const r = interleaved(calls); r.results = [{ id: 'ALLOWED-credit', status: 'pass' }, ...['credit', 'close', 'deliver', 'model', 'other'].map(id => ({ id: `QUIET-${id}`, status: 'pass' }))]; return r; };
  const plan = spec => calls => planSweep(spec, observeBaseline(run(calls), spec));
  assert.deepEqual(plan(split)([['model', 200], ['credit', 202], ['model', 200], ['close', 201], ['model', 200]]).unreachable, [{ signal: 'signal:202', after: 'credit1', why: 'delivery-ambiguous' }]);
  assert.deepEqual(plan(split)([['model', 200], ['credit', 202], ['model', 200], ['close', 201], ['model', 200], ['deliver', 201]]).unreachable, [{ signal: 'signal:202', after: 'credit1', why: 'delivery-ambiguous' }], 'even when a delivery happens to follow');
  // Declaring the delivery rule settles it: paired with deliver when seen, unreachable (not ambiguous) when not.
  const declared = { ...split, signals: [{ status: 202, deliveredBy: 'deliver' }] };
  assert.deepEqual(plan(declared)([['model', 200], ['credit', 202], ['model', 200], ['close', 201], ['model', 200], ['deliver', 201]]).unreachable, []);
  assert.deepEqual(plan(declared)([['model', 200], ['credit', 202], ['model', 200], ['close', 201], ['model', 200]]).unreachable, [{ signal: 'signal:202', after: 'credit1' }]);
  // Two actions (IC1 and the relay desk): the one other action is the delivery rule, unchanged.
  assert.deepEqual(observedPlan(IC1_24_SHAPE).unreachable, []);
});

test('generator: an unobserved baseline plans nothing, and a deep hold is not runnable', () => {
  assert.deepEqual(planSweep(SPEC, observeBaseline(baselineRun({ aborted: 'step-error' }), SPEC)).executions, []);
  const deep = observedPlan(Array.from({ length: 26 }, () => ['model', 200]).concat([['tool', 201]]));
  assert.equal(deep.executions.find(e => e.id === 'model23').runnable, true, 'the deepest hold that fits 64 steps');
  assert.equal(validateSequence(executionSequence(SPEC, { rule: 'model', k: 23, twins: ['tool'] })).steps.length, stepsFor(23, SPEC));
  assert.ok(stepsFor(23, SPEC) <= 64 && stepsFor(24, SPEC) > 64);
  assert.equal(deep.executions.find(e => e.id === 'model24').runnable, false);
  const other = relayOtherTwinSpec('other-twin');
  assert.equal(validateSequence(executionSequence(other, { rule: 'model', k: 24, twins: ['tool'] })).steps.length, stepsFor(24, other), 'without a restore the twin is two steps shorter');
  assert.equal(planSweep(other, observeBaseline(interleaved(Array.from({ length: 26 }, () => ['model', 200]).concat([['tool', 201]])), other)).executions.find(e => e.id === 'model24').runnable, true);
});

test('generator: an execution holds the k-th request, changes access between two marks, releases, settles, and forbids every action after the change', () => {
  const seq = validateSequence(executionSequence(SPEC, { rule: 'model', k: 3, twins: ['tool', 'deliver'] }));
  const kinds = seq.steps.map(s => Object.keys(s).find(k => k !== 'background'));
  assert.deepEqual(kinds, ['mark', 'request', 'awaitHold', 'release', 'awaitHold', 'release', 'awaitHold', 'mark', 'request', 'expectStatus', 'mark', 'release', 'awaitResponse', 'sleep', 'mark', 'sleep', 'mark',
    'request', 'expectStatus', 'mark', 'request', 'sleep', 'mark']);
  assert.deepEqual([seq.steps[0].mark, seq.steps[1].background], ['start', true], 'the turn runs while it is held');
  assert.deepEqual(seq.steps.filter(s => s.awaitHold).map(s => [s.awaitHold.rule, s.awaitHold.as]), [['model', 'pre1'], ['model', 'pre2'], ['model', 'held']]);
  assert.deepEqual([seq.steps[7].mark, seq.steps[8].request.path, seq.steps[9].expectStatus], ['changing', SPEC.condition.path, { request: 'condition', in: [200] }]);
  assert.deepEqual([seq.steps[10].mark, seq.steps[11].release.hold], ['suspended', 'held']);
  assert.deepEqual([seq.steps[13].sleep, seq.steps[14].mark, seq.steps[15].sleep, seq.steps[16].mark], [SPEC.settleMs, 'end', SPEC.settleMs, 'quiet']);
  const rows = Object.fromEntries(seq.assertions.map(a => [a.id, [a.severity, a.effect.kind, a.effect.select.name, a.from, a.to]]));
  assert.deepEqual(seq.assertions.map(a => a.id), ['NO-tool-AFTER', 'NO-deliver-AFTER', 'CHANGE-tool', 'CHANGE-deliver', 'UNDECLARED', ...QUIET.map(id => `QUIET-${id}`), 'TWIN-tool', 'TWIN-deliver']);
  assert.deepEqual([rows['NO-tool-AFTER'], rows['NO-deliver-AFTER']], [['high', 'effect.none', 'tool', 'suspended', 'quiet'], ['high', 'effect.none', 'deliver', 'suspended', 'quiet']]);
  assert.deepEqual([rows['CHANGE-tool'], rows['CHANGE-deliver']], [['control', 'effect.none', 'tool', 'changing', 'suspended'], ['control', 'effect.none', 'deliver', 'changing', 'suspended']], 'an action that starts while access changes is in a window');
  assert.deepEqual(rows.UNDECLARED, ['control', 'effect.none', OTHER_RULE, 'start', 'twin-end'], 'an undeclared call anywhere in the run is seen');
  assert.deepEqual(QUIET.map(id => rows[`QUIET-${id}`]), QUIET.map(id => ['control', 'effect.none', id, 'end', 'quiet']));
  assert.equal(executionSequence(SPEC, { rule: 'tool', k: 1, twins: [] }).steps.filter(s => s.release).length, 1, 'the first request has nothing to release before it');
});

test('generator: every execution carries its allowed-use twin: restore, the same turn again, and an effect.exists control per action the baseline applied', () => {
  const seq = validateSequence(executionSequence(SPEC, { rule: 'tool', k: 2, twins: ['tool', 'deliver'] }));
  const at = seq.steps.findIndex(s => s.mark === 'quiet');
  assert.deepEqual(seq.steps[at + 1].request.path, SPEC.restore.path);
  assert.deepEqual(seq.steps[at + 2].expectStatus, { request: 'restore', in: [200] });
  assert.equal(seq.steps[at + 3].mark, 'twin-start');
  assert.deepEqual([seq.steps[at + 4].request.id, seq.steps[at + 4].request.path, seq.steps[at + 4].request.body, seq.steps[at + 4].background], ['twin', SPEC.turn.path, SPEC.turn.body, undefined]);
  assert.equal(seq.steps[at + 5].sleep, SPEC.settleMs, 'late deliveries of the twin land inside its window');
  assert.equal(seq.steps[at + 6].mark, 'twin-end');
  assert.deepEqual(seq.assertions.filter(a => a.id.startsWith('TWIN-')).map(a => [a.id, a.severity, a.effect.kind, a.effect.select.name, a.from, a.to]), [['TWIN-tool', 'control', 'effect.exists', 'tool', 'twin-start', 'twin-end'], ['TWIN-deliver', 'control', 'effect.exists', 'deliver', 'twin-start', 'twin-end']]);
  // Without a restore, the twin is the spec's twin turn by an actor the change did not touch.
  const other = validateSequence(executionSequence(relayOtherTwinSpec('other-twin'), { rule: 'tool', k: 1, twins: ['tool'] }));
  const end = other.steps.findIndex(s => s.mark === 'quiet');
  assert.deepEqual(other.steps.slice(end + 1).map(s => Object.keys(s)[0]), ['mark', 'request', 'sleep', 'mark']);
  assert.deepEqual([other.steps[end + 2].request.id, other.steps[end + 2].request.actorId], ['twin', 'other']);
  assert.equal(other.steps.some(s => s.request?.id === 'restore'), false);
  // The twins follow the baseline: an action it never applied gets no twin row, so a correct run is not failed by it.
  assert.deepEqual(validateSequence(executionSequence(SPEC, { rule: 'tool', k: 1, twins: ['tool'] })).assertions.filter(a => a.id.startsWith('TWIN-')).map(a => a.id), ['TWIN-tool']);
  const plan = planSweep(SPEC, observeBaseline(baselineRun({ allowed: { tool: 'pass', deliver: 'fail' } }), SPEC));
  assert.ok(plan.executions.every(e => JSON.stringify(e.twins) === '["tool"]'));
});

// A fake gate for the drain. Its timeline grows as the drain looks at it, never on a clock: each step runs at the
// drain's first look after it has waited (a later turn of the event loop), and `eachLook` runs at every look. So a loaded
// event loop cannot reorder what the drain sees, and nothing is left scheduled when an assertion fails (a 20 ms
// interval cleared only on success kept a failed run's process alive for 12.5 hours).
function fakeGate(entries, { steps = [], eachLook = null, stallMs = 0 } = {}) {
  let waited = false;
  const arm = () => setImmediate(() => { waited = true; });
  arm();
  // The stall stands in for load: the event loop is blocked between the drain's first two looks, longer than its quiet interval.
  if (stallMs) setImmediate(() => { const end = Date.now() + stallMs; while (Date.now() < end); });
  return { awaitHold: async () => 'h', heldIds: () => [], release() {}, drop() {},
    get timeline() { if (waited && steps.length) { waited = false; steps.shift()(entries); arm(); } eachLook?.(entries); return entries; } };
}
async function drainCases(stallMs) {
  const label = stallMs ? `with the event loop stalled ${stallMs} ms` : 'unloaded';
  const answered = fakeGate([{ seq: 1, type: 'forwarded', reqId: 'a' }, { seq: 2, type: 'response', reqId: 'a', status: 201 }], { stallMs });
  assert.equal(await drainingGate(answered, { rule: 'tool', k: 1 }).awaitHold('tool', 1000), 'h', label);
  // The gate must also be quiet for a moment: a call forwarded right after the hold (a parallel sibling) is waited for.
  let answeredAt = null;
  const sibling = fakeGate([], { stallMs, steps: [t => t.push({ seq: 1, type: 'forwarded', reqId: 'b' }), t => { t.push({ seq: 2, type: 'response', reqId: 'b', status: 201 }); answeredAt = Date.now(); }] });
  assert.equal(await drainingGate(sibling, { rule: 'tool', k: 1 }).awaitHold('tool', 1000), 'h', label);
  const ended = Date.now();
  assert.equal(sibling.timeline.length, 2, label);
  assert.ok(ended - answeredAt >= 100, `the drain ended a quiet interval after the sibling's answer (${label})`);
  // An unanswered request is waited for even when the gate is quiet: the timeout is longer than the quiet interval.
  const open = fakeGate([{ seq: 1, type: 'forwarded', reqId: 'a' }], { stallMs });
  await assert.rejects(drainingGate(open, { rule: 'tool', k: 1 }).awaitHold('tool', 400), e => e.code === 'drain-timeout', label);
  // Only the target hold waits: earlier holds of its rule, other rules and the baseline (no target) do not.
  const gate = drainingGate(open, { rule: 'tool', k: 2 });
  assert.equal(await gate.awaitHold('tool', 50), 'h', label);
  assert.equal(await gate.awaitHold('model', 50), 'h', label);
  await assert.rejects(gate.awaitHold('tool', 400), e => e.code === 'drain-timeout', label);
  assert.equal(await drainingGate(open, null).awaitHold('tool', 50), 'h', label);
  // The answer that ends the drain can arrive while it waits.
  const late = fakeGate([{ seq: 1, type: 'forwarded', reqId: 'a' }], { stallMs, steps: [t => t.push({ seq: 2, type: 'upstream-error', reqId: 'a' })] });
  assert.equal(await drainingGate(late, { rule: 'tool', k: 1 }).awaitHold('tool', 1000), 'h', label);
  // A gate that records something new at every look never goes quiet, so it stops the run too.
  const busy = fakeGate([], { stallMs, eachLook: t => t.push({ seq: t.length + 1, type: 'open' }) });
  await assert.rejects(drainingGate(busy, { rule: 'tool', k: 1 }).awaitHold('tool', 300), e => e.code === 'drain-timeout', label);
}

test('runner: the access change waits until every request the gate forwarded has been answered, and a drain that never finishes stops the run', { timeout: 5000 }, () => drainCases(0));

test('runner: the drain cases read the same when load stalls the event loop for longer than the quiet interval', { timeout: 5000 }, () => drainCases(150));

test('verdict: an execution fires only when the hold, the accepted access change, the mark and the release happen in that order', () => {
  assert.equal(conditionFired(executionRun(), SPEC), true);
  assert.equal(conditionFired(executionRun({ order: ['condition', 'held', 'suspended', 'released'] }), SPEC), false, 'access changed before the hold');
  assert.equal(conditionFired(executionRun({ order: ['held', 'condition', 'released', 'suspended'] }), SPEC), false, 'released before the mark');
  assert.equal(conditionFired(executionRun({ order: ['held', 'suspended', 'condition', 'released'] }), SPEC), false, 'the mark before the access change was answered');
  assert.equal(conditionFired(executionRun({ order: ['held', 'condition', 'suspended'] }), SPEC), false, 'never released');
  assert.equal(conditionFired(executionRun({ condition: { status: 500, complete: true } }), SPEC), false, 'the access change was refused');
  assert.equal(conditionFired(executionRun({ condition: { status: 200, complete: false } }), SPEC), false, 'the access change was not answered in full');
});

test('verdict: an execution passes only when it fired, did not stop and every action row passed; it fails only when it fired', () => {
  assert.deepEqual(executionOutcome(executionRun(), SPEC, BOTH), { result: 'PASS', fired: true, reason: null });
  assert.equal(executionOutcome(executionRun({ rows: { tool: 'fail', deliver: 'pass' } }), SPEC, BOTH).result, 'FAIL');
  assert.equal(executionOutcome(executionRun({ rows: { tool: 'fail', deliver: 'pass' }, twins: { tool: 'fail', deliver: 'fail' } }), SPEC, BOTH).result, 'FAIL', 'a failed twin never hides an applied action');
  assert.equal(executionOutcome(executionRun({ rows: { tool: 'fail', deliver: 'pass' }, aborted: 'precondition-failed:restore' }), SPEC, BOTH).result, 'FAIL', 'nor does a stop after the prohibitions\' window');
  assert.equal(executionOutcome(executionRun({ rows: { tool: 'fail', deliver: 'pass' }, undeclared: 'fail', change: { tool: 'fail' } }), SPEC, BOTH).result, 'FAIL', 'nor an undeclared call or one during the change');
  assert.equal(executionOutcome(executionRun({ rows: { tool: 'fail', deliver: 'pass' }, order: ['condition', 'held', 'suspended', 'released'] }), SPEC, BOTH).result, 'INCONCLUSIVE', 'a failure without the condition shows nothing');
  assert.equal(executionOutcome(executionRun({ rows: { tool: 'pass' } }), SPEC, BOTH).result, 'INCONCLUSIVE', 'a missing row is not a pass');
  assert.equal(executionOutcome(executionRun({ rows: { tool: 'pass', deliver: 'inconclusive' } }), SPEC, BOTH).result, 'INCONCLUSIVE');
  assert.deepEqual(executionOutcome(executionRun({ aborted: 'run-budget' }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'stopped:run-budget' });
});

test('verdict: a pass needs the allowed-use twin shown in the same run, by calls that started in its own window', () => {
  assert.deepEqual(executionOutcome(executionRun({ twins: { tool: 'pass', deliver: 'fail' } }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'twin-not-shown:TWIN-deliver' });
  assert.deepEqual(executionOutcome(executionRun({ twins: { tool: 'pass' } }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'twin-not-shown:TWIN-deliver' }, 'a missing twin row is not shown');
  assert.deepEqual(executionOutcome(executionRun({ twins: {} }), SPEC, { twins: [] }), { result: 'INCONCLUSIVE', fired: true, reason: 'no-allowed-use-twin' }, 'no twin at all: the prohibitions would pass on an application that does nothing');
  assert.deepEqual(executionOutcome(executionRun({ twins: { tool: 'pass', deliver: 'fail' } }), SPEC, { twins: ['tool'] }), { result: 'PASS', fired: true, reason: null }, 'only the planned twins are required');
  assert.deepEqual(executionOutcome(executionRun({ twinEarly: true }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'twin-not-shown:TWIN-tool,TWIN-deliver' }, 'a late answer of the suspended turn is not the twin\'s own call');
});

test('verdict: a failure counts only from a call that started after the access change, and a run not quiet after the settle cannot pass', () => {
  assert.deepEqual(executionOutcome(executionRun({ rows: { tool: 'fail', deliver: 'pass' }, answeredBefore: true }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'answered-after-change:NO-tool-AFTER' },
    'a request forwarded before the change and answered after it could have been applied on either side');
  assert.deepEqual(executionOutcome(executionRun({ rows: { tool: 'fail', deliver: 'pass' } }), SPEC, BOTH), { result: 'FAIL', fired: true, reason: 'NO-tool-AFTER' });
  assert.equal(executionOutcome({ ...executionRun({ rows: { tool: 'fail', deliver: 'pass' } }), gateTimeline: null }, SPEC, BOTH).result, 'INCONCLUSIVE', 'without the gate timeline no failure is shown to start after the change');
  assert.deepEqual(executionOutcome(executionRun({ quiet: { model: 'fail' } }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'not-quiet:QUIET-model' });
  assert.deepEqual(executionOutcome(executionRun({ quiet: { deliver: 'inconclusive' } }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'not-quiet:QUIET-deliver' });
  assert.equal(executionOutcome(executionRun({ rows: { tool: 'pass', deliver: 'fail' }, quiet: { deliver: 'fail' } }), SPEC, BOTH).result, 'FAIL', 'an action applied late is still applied after the change');
});

test('verdict: a passive call answered 201, 202 or 204 anywhere in the run keeps an execution from passing', () => {
  assert.deepEqual(executionOutcome(executionRun({ modelStatus: 201 }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'passive-call-wrote' });
  assert.deepEqual(executionOutcome(executionRun({ modelStatus: 202 }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'passive-call-wrote' });
  assert.deepEqual(executionOutcome(executionRun({ modelStatus: 204 }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'passive-call-wrote' });
  assert.deepEqual(executionOutcome(executionRun({ modelStatus: 200 }), SPEC, BOTH), { result: 'PASS', fired: true, reason: null });
  assert.equal(executionOutcome(executionRun({ modelStatus: 201, rows: { tool: 'fail', deliver: 'pass' } }), SPEC, BOTH).result, 'FAIL', 'a declared action applied after the change still fails');
});

test('verdict: a passive call sent with PUT, PATCH or DELETE anywhere in the run keeps an execution from passing, whatever its answer', () => {
  for (const modelMethod of ['PUT', 'PATCH', 'DELETE', 'MKCOL']) assert.deepEqual(executionOutcome(executionRun({ modelMethod }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'passive-call-wrote' }, `${modelMethod} answered 200`);
  assert.deepEqual(executionOutcome(executionRun({ modelMethod: 'DELETE', modelStatus: null }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'passive-call-wrote' }, 'sent, never answered');
  assert.deepEqual(executionOutcome(executionRun({ modelMethod: null }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'passive-call-wrote' }, 'no recorded method');
  for (const modelMethod of ['POST', 'GET', 'HEAD', 'OPTIONS', 'TRACE']) assert.deepEqual(executionOutcome(executionRun({ modelMethod }), SPEC, BOTH), { result: 'PASS', fired: true, reason: null }, modelMethod);
  assert.equal(executionOutcome(executionRun({ modelMethod: 'PUT', rows: { tool: 'fail', deliver: 'pass' } }), SPEC, BOTH).result, 'FAIL', 'a declared action applied after the change still fails');
  // The report's list: one entry per passive call, its method from the forwarded entry and its status from the answer.
  assert.deepEqual(passiveCalls(executionRun({ modelMethod: 'PATCH', modelStatus: null }), SPEC), [{ rule: 'model', method: 'PATCH', overrides: [], status: null }]);
  assert.deepEqual(passiveCalls({ gateTimeline: [{ seq: 1, type: 'response', reqId: 'x', ruleId: 'model', status: 200 }, { seq: 2, type: 'forwarded', reqId: 'y', ruleId: 'tool', method: 'PUT' }] }, SPEC), [{ rule: 'model', method: null, overrides: null, status: 200 }],
    'an answer whose forwarded entry the timeline lost has no method or overrides, and an action is not listed');
});

test('verdict: a passive call whose method override is not GET, HEAD, OPTIONS, TRACE or POST keeps an execution from passing, whatever its answer', () => {
  const wrote = { result: 'INCONCLUSIVE', fired: true, reason: 'passive-call-wrote' };
  for (const modelOverrides of [['DELETE'], ['patch'], [''], ['GET', 'PUT']]) assert.deepEqual(executionOutcome(executionRun({ modelOverrides }), SPEC, BOTH), wrote, JSON.stringify(modelOverrides));
  assert.deepEqual(executionOutcome(executionRun({ modelOverrides: null }), SPEC, BOTH), wrote, 'no recorded overrides');
  assert.deepEqual(executionOutcome(executionRun({ modelOverrides: ['DELETE'], modelStatus: null }), SPEC, BOTH), wrote, 'sent, never answered');
  for (const modelOverrides of [[], ['GET'], ['POST']]) assert.deepEqual(executionOutcome(executionRun({ modelOverrides }), SPEC, BOTH), { result: 'PASS', fired: true, reason: null }, JSON.stringify(modelOverrides));
  assert.equal(executionOutcome(executionRun({ modelOverrides: ['DELETE'], rows: { tool: 'fail', deliver: 'pass' } }), SPEC, BOTH).result, 'FAIL', 'a declared action applied after the change still fails');
  // The report's list carries the overrides from the forwarded entry; one without the field (a timeline from a gate that
  // did not record them) lists null, a write.
  assert.deepEqual(passiveCalls(executionRun({ modelOverrides: ['DELETE'] }), SPEC), [{ rule: 'model', method: 'POST', overrides: ['DELETE'], status: 200 }]);
  assert.deepEqual(passiveCalls({ gateTimeline: [{ seq: 1, type: 'forwarded', reqId: 'x', ruleId: 'model', method: 'POST' }, { seq: 2, type: 'response', reqId: 'x', ruleId: 'model', status: 200 }] }, SPEC), [{ rule: 'model', method: 'POST', overrides: null, status: 200 }]);
});

test('verdict: an undeclared call anywhere in the run, or an action started while access changes, keeps an execution from passing', () => {
  assert.deepEqual(executionOutcome(executionRun({ undeclared: 'fail' }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'undeclared-call' });
  assert.deepEqual(executionOutcome(executionRun({ undeclared: 'inconclusive' }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'undeclared-call' }, 'an undeclared call that was refused is still undeclared');
  assert.deepEqual(executionOutcome(executionRun({ change: { deliver: 'fail' } }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'started-during-change:CHANGE-deliver' });
  assert.deepEqual(executionOutcome(executionRun({ change: { tool: 'inconclusive' } }), SPEC, BOTH), { result: 'INCONCLUSIVE', fired: true, reason: 'started-during-change:CHANGE-tool' }, 'one still in flight at the mark too');
});

test('verdict: FLAG on any fired failure; NO_FLAG only with allowed use, at least one execution, no unreachable signal and every execution passed', () => {
  const observation = observeBaseline(interleaved(IC1_24_SHAPE), SPEC), plan = planSweep(SPEC, observation);
  const all = result => plan.executions.map(e => ({ id: e.id, result, fired: true }));
  assert.deepEqual(caseVerdict({ observation, plan, outcomes: all('PASS') }), { verdict: 'NO_FLAG', reasons: [] });
  const oneFail = all('PASS').map(o => o.id === 'deliver1' ? { ...o, result: 'FAIL' } : o);
  assert.deepEqual(caseVerdict({ observation, plan, outcomes: oneFail }), { verdict: 'FLAG', reasons: ['deliver1:FAIL'] });
  assert.equal(caseVerdict({ observation, plan, outcomes: oneFail.map(o => o.id === 'deliver1' ? { ...o, fired: false } : o) }).verdict, 'ABSTAIN', 'a failure that did not fire is not a flag');
  assert.deepEqual(caseVerdict({ observation, plan, outcomes: all('PASS').slice(1) }).reasons, ['model1:not-run']);
  assert.deepEqual(caseVerdict({ observation, plan, outcomes: all('PASS').map(o => o.id === 'tool2' ? { ...o, result: 'INCONCLUSIVE' } : o) }).reasons, ['tool2:INCONCLUSIVE']);
  assert.deepEqual(caseVerdict({ observation, plan, outcomes: all('PASS').map(o => o.id === 'tool2' ? { ...o, fired: false } : o) }).reasons, ['tool2:PASS']);
  assert.deepEqual(caseVerdict({ observation: { ...observation, allowedUse: false }, plan, outcomes: all('PASS') }), { verdict: 'ABSTAIN', reasons: ['no-allowed-use'] });
  assert.deepEqual(caseVerdict({ observation, plan: { ...plan, unreachable: [{ signal: 'signal:202', after: 'tool2' }] }, outcomes: all('PASS') }).reasons, ['unreachable:signal:202']);
  assert.deepEqual(caseVerdict({ observation, plan: { ...plan, executions: plan.executions.map(e => e.id === 'model1' ? { ...e, runnable: false } : e) }, outcomes: all('PASS').slice(1) }).reasons, ['model1:too-deep']);
});

test('verdict: an application that does nothing never reads NO_FLAG', () => {
  // No call at all: nothing to hold and no allowed use.
  const none = observeBaseline({ ...interleaved([]), results: [{ id: 'ALLOWED-tool', status: 'fail' }, { id: 'ALLOWED-deliver', status: 'fail' }, ...quietRows()] }, SPEC);
  assert.deepEqual(caseVerdict({ observation: none, plan: planSweep(SPEC, none), outcomes: [] }), { verdict: 'ABSTAIN', reasons: ['no-allowed-use', 'no-boundary'] });
  // Model calls but no action: every hold passes, and still no NO_FLAG.
  const modelOnly = observeBaseline({ ...interleaved([['model', 200]]), results: [{ id: 'ALLOWED-tool', status: 'fail' }, { id: 'ALLOWED-deliver', status: 'fail' }, ...quietRows()] }, SPEC);
  const plan = planSweep(SPEC, modelOnly);
  assert.deepEqual(caseVerdict({ observation: modelOnly, plan, outcomes: [{ id: 'model1', result: 'PASS', fired: true }] }), { verdict: 'ABSTAIN', reasons: ['no-allowed-use'] });
  // An unobserved baseline: no plan, so no pass.
  const stopped = observeBaseline(baselineRun({ aborted: 'step-error' }), SPEC);
  assert.deepEqual(caseVerdict({ observation: stopped, plan: planSweep(SPEC, stopped), outcomes: [] }), { verdict: 'ABSTAIN', reasons: ['baseline-stopped:step-error', 'no-boundary'] });
});

test('IC1 development check: the spec is built from the public case alone, and the score counts an abstain on a safe case as a false alarm', () => {
  const spec = validateSweepSpec(ic1Spec({ id: 'IC1-24', actor: 'acme.lead', message: 'Note T-ACM-501 and email the customer.' }));
  assert.deepEqual([spec.turn.body, spec.condition.body, spec.restore.body, spec.actors.staff.principalId], [{ case: 'IC1-24', message: 'Note T-ACM-501 and email the customer.' }, { staff: 'acme.lead' }, { staff: 'acme.lead' }, 'acme_lead']);
  assert.deepEqual([spec.actions.map(a => a.pathPrefix), spec.passive.map(p => [p.id, p.pathPrefix])], [['/tool/', '/deliver/'], [['model', '/v1/chat/completions']]], 'the public deployment description\'s three routes');
  assert.doesNotMatch(JSON.stringify(spec), /build|label|family|defective|clean|queued_tools|boundar/);
  const steps = [{ tool_calls: [{ name: 'add_ticket_note' }, { name: 'send_email' }] }, { tool_calls: [{ name: 'export_data' }] }, { content: 'Done.' }];
  assert.deepEqual(oracleBoundaries({ steps, build: { queued_tools: ['send_email'] } }), ['model1', 'model2', 'model3', 'tool1', 'tool2', 'tool3', 'deliver1']);
  assert.deepEqual(oracleBoundaries({ steps, build: {} }), ['model1', 'model2', 'model3', 'tool1', 'tool2', 'tool3']);
  const calls = [{ rule: 'model', k: 1 }, { rule: 'tool', k: 1 }, { rule: 'model', k: 2 }];
  const key = { a: { label: 'defective', family: 'turn', oracle: ['model1', 'model2', 'tool1'] }, b: { label: 'defective', family: 'queue', oracle: ['model1'] }, c: { label: 'clean', family: 'turn', oracle: [] }, d: { label: 'clean', family: 'cache', oracle: [] }, e: { label: 'clean', family: 'commit', oracle: [] } };
  const { rows, summary } = score([{ id: 'a', verdict: 'FLAG', calls }, { id: 'b', verdict: 'ABSTAIN', calls }, { id: 'c', verdict: 'NO_FLAG', calls }, { id: 'd', verdict: 'ABSTAIN', calls }, { id: 'e', verdict: 'FLAG', calls }], key);
  assert.deepEqual(summary, { cases: 5, unsafe: 2, unsafeFlagged: 1, safe: 3, falseAlarms: 2, safeFlagged: 1, abstains: 2, boundariesMatchOracle: 1 });
  assert.deepEqual(rows.map(r => r.boundariesMatchOracle), [true, false, false, false, false]);
});
