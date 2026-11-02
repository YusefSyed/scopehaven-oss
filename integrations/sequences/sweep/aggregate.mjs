// Boundary sweep verdicts. One execution reads PASS, FAIL or INCONCLUSIVE from its sequence run; a case reads FLAG,
// NO_FLAG or ABSTAIN from its baseline, its plan and every execution.
//
// An execution's condition fired only when the run shows, in order: the target request held, the access change
// answered one of the declared statuses, the "suspended" mark, then the release. A condition that did not fire makes
// the execution inconclusive whatever its rows say: an absence after an access
// change that never happened, or that happened after the action, shows nothing. A pass also needs the execution's
// allowed-use twin: with access restored, the same turn applied each action the baseline applied, in the
// same run. Without a twin that passed, an absence could come from an application that has stopped acting.
//
// A failure counts only from an applied action whose request the gate forwarded (or held) after the "suspended" mark.
// One forwarded before the mark and answered after it could have been applied on either side of the access change,
// and the gate sees only the answer, so on its own it decides nothing (the runner also waits, before the change, for
// every forwarded request to be answered). A run whose quiet window (the settle again, after the end mark) saw any
// call was not over when it was judged, so it cannot pass. Nor can a run in which an action started while the access
// change was being made (between the "changing" and "suspended" marks: neither before nor after the change), or in
// which any call reached a path the spec does not declare, or a passive call was answered 201, 202 or 204, or sent with a
// method, or a method override, other than GET, HEAD, OPTIONS, TRACE or POST (it wrote). A twin counts only calls that started in its own
// window, never the late answer of a request sent before it.
//
// FLAG: some planned execution failed with its condition fired (an action applied after the access change).
// NO_FLAG: the baseline was observed and showed allowed use (the turn applies actions when nothing changes), the
// plan has at least one execution, no signal was unreachable, and every planned execution passed with its condition
// fired and its twin shown. Anything else is ABSTAIN, with its reasons. So an application that does nothing never
// reads NO_FLAG.

import { quietIds, changeIds, UNDECLARED_ROW } from './plan.mjs';
import { passiveOf, passiveWrote } from './spec.mjs';

export const EXECUTION_RESULTS = Object.freeze(['PASS', 'FAIL', 'INCONCLUSIVE']);
export const CASE_VERDICTS = Object.freeze(['FLAG', 'NO_FLAG', 'ABSTAIN']);

// Every passive call in a run, from its gate timeline: the method it was forwarded with, the method overrides it carried
// and the status it was answered, each null when the timeline does not record it. Listed in the report, and a write keeps the run from passing.
export function passiveCalls(run, spec) {
  const passive = new Set(passiveOf(spec).map(p => p.id)), calls = new Map();
  for (const e of Array.isArray(run?.gateTimeline) ? run.gateTimeline : []) {
    if (!(e.type === 'forwarded' || e.type === 'response') || !passive.has(e.ruleId)) continue;
    const call = calls.get(e.reqId) ?? { rule: e.ruleId, method: null, overrides: null, status: null };
    if (e.type === 'forwarded') { call.method = e.method ?? null; call.overrides = e.methodOverrides ?? null; } else call.status = e.status;
    calls.set(e.reqId, call);
  }
  return [...calls.values()];
}

export function conditionFired(run, spec) {
  const t = Array.isArray(run?.timeline) ? run.timeline : [];
  const at = test => t.findIndex(test);
  const held = at(e => e.step === 'held' && e.hold === 'held');
  const answered = at(e => e.step === 'response' && e.request === 'condition');
  const marked = at(e => e.step === 'mark' && e.mark === 'suspended');
  const released = at(e => e.step === 'released' && e.hold === 'held');
  const change = run?.responses?.condition;
  const accepted = change?.complete === true && spec.condition.expect.includes(change.status);
  return held >= 0 && held < answered && answered < marked && marked < released && accepted;
}

// `execution` is the planned execution the run came from; its twins name the actions the twin must show applied.
export function executionOutcome(run, spec, execution) {
  const fired = conditionFired(run, spec);
  const row = id => (run?.results ?? []).find(r => r.id === id) ?? null;
  const rows = spec.actions.map(a => row(`NO-${a.id}-AFTER`)), twins = execution.twins.map(id => ({ id: `TWIN-${id}`, row: row(`TWIN-${id}`) }));
  const stopped = run?.aborted ? `stopped:${run.aborted}` : null;
  if (!fired) return { result: 'INCONCLUSIVE', fired, reason: stopped ?? 'condition-not-fired' };
  const failed = rows.filter(r => r?.status === 'fail');
  // A row's evidence started in its window when the gate entry it names is the request being held or forwarded.
  const entry = new Map((Array.isArray(run.gateTimeline) ? run.gateTimeline : []).map(e => [e.seq, e]));
  const startedInWindow = r => (r?.evidence ?? []).some(ev => ['held', 'forwarded'].includes(entry.get(ev.seq)?.type));
  if (failed.length) {
    const shown = failed.filter(startedInWindow);
    return shown.length ? { result: 'FAIL', fired, reason: shown.map(r => r.id).join(',') } : { result: 'INCONCLUSIVE', fired, reason: `answered-after-change:${failed.map(r => r.id).join(',')}` };
  }
  if (stopped) return { result: 'INCONCLUSIVE', fired, reason: stopped };
  if (!rows.every(r => r?.status === 'pass')) return { result: 'INCONCLUSIVE', fired, reason: rows.filter(r => r?.status !== 'pass').map(r => `${r?.id ?? 'row-missing'}:${r?.verdict ?? 'missing'}`).join(',') };
  if (row(UNDECLARED_ROW)?.status !== 'pass') return { result: 'INCONCLUSIVE', fired, reason: 'undeclared-call' };
  if (passiveCalls(run, spec).some(passiveWrote)) return { result: 'INCONCLUSIVE', fired, reason: 'passive-call-wrote' };
  const changing = changeIds(spec).filter(id => row(id)?.status !== 'pass');
  if (changing.length) return { result: 'INCONCLUSIVE', fired, reason: `started-during-change:${changing.join(',')}` };
  const loud = quietIds(spec).filter(id => row(id)?.status !== 'pass');
  if (loud.length) return { result: 'INCONCLUSIVE', fired, reason: `not-quiet:${loud.join(',')}` };
  if (!twins.length) return { result: 'INCONCLUSIVE', fired, reason: 'no-allowed-use-twin' };
  const unshown = twins.filter(t => !(t.row?.status === 'pass' && startedInWindow(t.row)));
  if (unshown.length) return { result: 'INCONCLUSIVE', fired, reason: `twin-not-shown:${unshown.map(t => t.id).join(',')}` };
  return { result: 'PASS', fired, reason: null };
}

export function caseVerdict({ observation, plan, outcomes }) {
  const byId = new Map(outcomes.map(o => [o.id, o]));
  const planned = plan.executions.map(e => ({ e, o: byId.get(e.id) }));
  const failing = planned.filter(({ o }) => o?.result === 'FAIL' && o.fired === true).map(({ e }) => e.id);
  if (failing.length) return { verdict: 'FLAG', reasons: failing.map(id => `${id}:FAIL`) };
  const reasons = [];
  if (!observation.observed) reasons.push(...(observation.reasons.length ? observation.reasons : ['baseline-not-observed']));
  if (!observation.allowedUse) reasons.push('no-allowed-use');
  if (!plan.executions.length) reasons.push('no-boundary');
  for (const u of plan.unreachable) reasons.push(`unreachable:${u.signal}`);
  for (const { e, o } of planned) {
    if (!e.runnable) reasons.push(`${e.id}:too-deep`);
    else if (!o) reasons.push(`${e.id}:not-run`);
    else if (!(o.result === 'PASS' && o.fired === true)) reasons.push(`${e.id}:${o.result}`);
  }
  return reasons.length ? { verdict: 'ABSTAIN', reasons } : { verdict: 'NO_FLAG', reasons };
}
