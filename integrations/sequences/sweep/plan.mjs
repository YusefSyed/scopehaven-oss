// Boundary sweep generator. From one observed baseline turn (a sequence run through a hold gate that holds nothing),
// it lists every upstream call the turn made, in order, and plans one hold, condition, release execution per call:
// hold the k-th request of that call's rule, make the access change, release, wait for the turn and the declared
// settle, then judge that no action was applied after the change. A call on a path the spec declares neither as an
// action nor as passive could be an action no prohibition judges, so the baseline is then not observed. Signals add no
// new hold point of their own: a signal (for example the first 202 queued answer) names the first call after that
// answer, which the sweep already holds. Each such answer announces a later action, so each needs its own later call
// of its delivery rule in the baseline: the signal's "deliveredBy", or, when the spec has exactly one other action, that
// action. One without it, or one whose delivery rule is ambiguous (two or more other actions and no "deliveredBy", or a
// "deliveredBy" that is the answering rule itself), is recorded as unreachable, because the effect it announced could
// then happen where no hold gate (or no settle) can see it. A passive call answered 201, 202 or 204, or sent with a
// method, or a method override, other than GET, HEAD, OPTIONS, TRACE or POST, wrote something the spec says it does not,
// so the baseline is not observed. Every run waits the settle once more after its end mark: the quiet window, where any call
// shows the turn was not over. Every execution then runs its allowed-use twin: access restored and the same
// turn again, or the spec's twin turn by an actor the change did not touch, with an effect.exists control on each
// action the baseline applied, in the same run and through the same gate, so a prohibition never passes on an
// application that has stopped acting. The generator reads the spec and the baseline run only: never a label, a build
// or a hand-written boundary list.
import { SEQUENCE_SCHEMA, SEQUENCE_LIMITS } from '../sequence.mjs';
import { gateRules, signalsOf, holdTimeoutOf, boundaryRules, passiveOf, passiveWrote, OTHER_RULE } from './spec.mjs';

export const BASELINE_WINDOW = 'start>end';
const select = name => ({ source: 'hold-proxy', operation: 'tool-call', name });
const requestOf = (id, r) => ({ id, actorId: r.actorId, method: r.method, path: r.path, ...(r.body === undefined ? {} : { body: r.body }), ...(r.timeoutMs === undefined ? {} : { timeoutMs: r.timeoutMs }) });
const turnTimeout = spec => spec.turn.timeoutMs ?? 120000;
const target = spec => ({ ...(spec.applicationId ? { applicationId: spec.applicationId } : {}), ...(spec.contextId ? { contextId: spec.contextId } : {}) });
const control = (id, title, from, to, kind, name) => ({ id, title, severity: 'control', from, to, effect: { kind, select: select(name) } });
// The quiet window's rows: no call of any rule, the catch-all included, between the end mark and the quiet mark.
const quietRows = spec => [...boundaryRules(spec), OTHER_RULE].map(id => control(`QUIET-${id}`, `No ${id} call after the settle`, 'end', 'quiet', 'effect.none', id));
export const quietIds = spec => quietRows(spec).map(r => r.id);
// An execution's rows for the access change itself: no action may start while the change is being made.
export const changeIds = spec => spec.actions.map(a => `CHANGE-${a.id}`);
export const UNDECLARED_ROW = 'UNDECLARED';

// The baseline: the turn with access unchanged, the settle, then the quiet window. Each action has an allowed-use
// control row: an absence after the access change means something only if the same turn applies actions when nothing changes.
export function baselineSequence(spec) {
  return { schema: SEQUENCE_SCHEMA, id: `${spec.id}-baseline`, ...target(spec), actors: spec.actors,
    steps: [{ mark: 'start' }, { request: requestOf('turn', { ...spec.turn, timeoutMs: turnTimeout(spec) }) }, { sleep: spec.settleMs }, { mark: 'end' }, { sleep: spec.settleMs }, { mark: 'quiet' }],
    assertions: [...spec.actions.map(a => control(`ALLOWED-${a.id}`, `The turn applies ${a.id} calls when access is unchanged`, 'start', 'end', 'effect.exists', a.id)), ...quietRows(spec)] };
}
export const baselineGate = spec => ({ rules: gateRules(spec) });

// What the baseline run shows: every forwarded upstream call in order, with its rule, its occurrence number within
// that rule, the method it was sent with, the method overrides it carried and the status it was answered. Read from the gate's timeline and checked
// against the sealed window.
export function observeBaseline(run, spec) {
  const reasons = [];
  if (run?.aborted) reasons.push(`baseline-stopped:${run.aborted}`);
  const turn = run?.responses?.turn;
  if (!(turn?.complete === true && turn.status >= 200 && turn.status < 300)) reasons.push('turn-not-accepted');
  const timeline = Array.isArray(run?.gateTimeline) ? [...run.gateTimeline].sort((a, b) => a.seq - b.seq) : null;
  if (!timeline) reasons.push('no-gate-timeline');
  const ended = new Map((timeline ?? []).filter(e => e.type === 'response' || e.type === 'upstream-error').map(e => [e.reqId, e]));
  const counts = {}, calls = [];
  for (const f of (timeline ?? []).filter(e => e.type === 'forwarded')) {
    const rule = f.ruleId ?? 'ungated', end = ended.get(f.reqId);
    counts[rule] = (counts[rule] ?? 0) + 1;
    calls.push({ rule, k: counts[rule], method: f.method ?? null, overrides: f.methodOverrides ?? null, status: end?.type === 'response' ? end.status : null, forwardedSeq: f.seq, answeredSeq: end?.seq ?? null });
  }
  if (counts.ungated) reasons.push('ungated-call');
  // A call on a path the spec declares neither as an action nor as passive: it could be an action nothing judges.
  if (counts[OTHER_RULE]) reasons.push('undeclared-call');
  // A passive path is the operator's statement that the route applies nothing: an answer, a method or a method override
  // that reports a write refutes it.
  const passive = new Set(passiveOf(spec).map(p => p.id));
  if (calls.some(c => passive.has(c.rule) && passiveWrote(c))) reasons.push('passive-call-wrote');
  // A call still unanswered at the end of the settle means the settle is too short for this turn.
  if (calls.some(c => c.status === null)) reasons.push('call-without-answer');
  // The sealed gate window must hold exactly the calls the timeline lists (a call after the end mark is outside it).
  const gateWindow = (run?.windows?.[BASELINE_WINDOW] ?? []).find(w => w.source === 'hold-proxy');
  if (!gateWindow || gateWindow.coverage !== 'complete') reasons.push('gate-window-incomplete');
  else {
    const sealed = {};
    for (const e of gateWindow.events) sealed[e.name] = (sealed[e.name] ?? 0) + 1;
    const names = new Set([...Object.keys(sealed), ...Object.keys(counts)]);
    if ([...names].some(n => sealed[n] !== counts[n])) reasons.push('timeline-window-mismatch');
  }
  // After the settle the turn must be over: nothing in the quiet window, so the settle covers the turn's late calls.
  if (!quietIds(spec).every(id => (run?.results ?? []).some(r => r.id === id && r.status === 'pass'))) reasons.push('baseline-not-quiet');
  // The actions the turn applied with access unchanged: each gets its twin in every execution.
  const allowedActions = spec.actions.map(a => a.id).filter(id => (run?.results ?? []).some(r => r.id === `ALLOWED-${id}` && r.status === 'pass'));
  return { observed: reasons.length === 0, allowedUse: allowedActions.length > 0, allowedActions, calls, counts, reasons };
}

// One execution per observed call; signals attach to the first call after the answer that raised them.
// The steps an execution for the k-th request needs (a sequence allows 64): the start mark, the turn, k - 1 pre-holds
// and their releases, the hold and the access change (11 steps to the quiet mark), then the twin (4 steps, 6 with a restore).
export const stepsFor = (k, spec) => 2 * k + 15 + (spec.restore ? 2 : 0);
export function planSweep(spec, observation) {
  if (!observation.observed) return { executions: [], unreachable: [], reasons: [...observation.reasons] };
  const actions = new Set(spec.actions.map(a => a.id)), byForward = (a, b) => a.forwardedSeq - b.forwardedSeq;
  const executions = observation.calls.map(c => ({ id: `${c.rule}${c.k}`, rule: c.rule, k: c.k, origins: ['boundary'], twins: [...observation.allowedActions], runnable: stepsFor(c.k, spec) <= SEQUENCE_LIMITS.steps }));
  const unreachable = [];
  for (const s of signalsOf(spec)) {
    const name = `signal:${s.status}${s.action ? `:${s.action}` : ''}`;
    const hits = observation.calls.filter(c => c.status === s.status && (s.action ? c.rule === s.action : actions.has(c.rule))).sort((a, b) => a.answeredSeq - b.answeredSeq);
    if (!hits.length) continue;
    // Each answer announces a later action: pair it with its own call of the delivery rule, forwarded after it and not
    // itself such an answer. The delivery rule is the signal's deliveredBy, or the one action other than the one that
    // answered: a later call of the same rule is the next step of the turn, and with two or more other actions a later
    // call of any of them could be an unrelated step, so without deliveredBy the delivery is ambiguous. A deliveredBy
    // that is the answering rule itself is ambiguous too (the default signal matches any action's 202).
    const delivers = (c, h) => actions.has(c.rule) && c.status !== s.status && c.forwardedSeq > h.answeredSeq && (s.deliveredBy ? c.rule === s.deliveredBy : c.rule !== h.rule);
    const ambiguous = h => s.deliveredBy === h.rule || (!s.deliveredBy && spec.actions.filter(a => a.id !== h.rule).length > 1);
    const used = new Set();
    let gap = null;
    for (const h of hits) {
      if (ambiguous(h)) { gap = { signal: name, after: `${h.rule}${h.k}`, why: 'delivery-ambiguous' }; break; }
      const later = observation.calls.filter(c => !used.has(c) && delivers(c, h)).sort(byForward)[0];
      if (!later) { gap = { signal: name, after: `${h.rule}${h.k}` }; break; }
      used.add(later);
    }
    if (gap) { unreachable.push(gap); continue; }
    const next = observation.calls.filter(c => c.forwardedSeq > hits[0].answeredSeq).sort(byForward)[0];
    executions.find(e => e.rule === next.rule && e.k === next.k).origins.push(name);
  }
  return { executions, unreachable, reasons: [] };
}

// The hold, condition, release execution for the k-th request of `rule`: the prohibitions cover everything from the
// access change to the end of the quiet window, the change rows the access change itself, and the undeclared row the
// whole run. Then its allowed-use twin: restore access (when the spec declares how), run the twin turn, settle, and
// require each of `twins` (the actions the baseline applied).
export function executionSequence(spec, { rule, k, twins }) {
  const timeoutMs = holdTimeoutOf(spec), turn = requestOf('turn', { ...spec.turn, timeoutMs: turnTimeout(spec) }), steps = [{ mark: 'start' }, { request: turn, background: true }];
  for (let j = 1; j < k; j++) steps.push({ awaitHold: { rule, as: `pre${j}`, timeoutMs } }, { release: { hold: `pre${j}` } });
  const { expect, ...condition } = spec.condition;
  steps.push({ awaitHold: { rule, as: 'held', timeoutMs } }, { mark: 'changing' }, { request: requestOf('condition', condition) }, { expectStatus: { request: 'condition', in: [...expect] } },
    { mark: 'suspended' }, { release: { hold: 'held' } }, { awaitResponse: { request: 'turn' } }, { sleep: spec.settleMs }, { mark: 'end' }, { sleep: spec.settleMs }, { mark: 'quiet' });
  if (spec.restore) { const { expect: restored, ...restore } = spec.restore; steps.push({ request: requestOf('restore', restore) }, { expectStatus: { request: 'restore', in: [...restored] } }); }
  const twin = spec.twinTurn ? requestOf('twin', { ...spec.twinTurn, timeoutMs: spec.twinTurn.timeoutMs ?? turnTimeout(spec) }) : { ...turn, id: 'twin' };
  steps.push({ mark: 'twin-start' }, { request: twin }, { sleep: spec.settleMs }, { mark: 'twin-end' });
  return { schema: SEQUENCE_SCHEMA, id: `${spec.id}-${rule}${k}`, ...target(spec), actors: spec.actors, steps,
    assertions: [...spec.actions.map(a => ({ id: `NO-${a.id}-AFTER`, title: `No ${a.id} call is applied after the access change`, severity: 'high', from: 'suspended', to: 'quiet', effect: { kind: 'effect.none', select: select(a.id) } })),
      ...spec.actions.map(a => control(`CHANGE-${a.id}`, `No ${a.id} call while the access change is made`, 'changing', 'suspended', 'effect.none', a.id)),
      control(UNDECLARED_ROW, 'No call on an undeclared path', 'start', 'twin-end', 'effect.none', OTHER_RULE),
      ...quietRows(spec),
      ...twins.map(id => control(`TWIN-${id}`, `The allowed-use twin applies ${id} calls`, 'twin-start', 'twin-end', 'effect.exists', id))] };
}
export const executionGate = (spec, { rule, k }) => ({ rules: gateRules(spec, { rule, k }) });
