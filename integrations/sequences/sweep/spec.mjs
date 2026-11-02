// Boundary sweep app spec (scopehaven-sweep-spec/1): what an operator declares about the application under test,
// and nothing about where to hold it. The sweep reads the boundaries from one observed baseline turn instead.
//
// {
//   "schema": "scopehaven-sweep-spec/1", "id", "applicationId"?, "contextId"?,
//   "actors": { alias: { "principalId", "credentialEnv"? } },               as in a sequence
//   "turn": { "actorId", "method", "path", "body"?, "timeoutMs"? },          the request that starts one agent turn
//   "condition": { "actorId", "method", "path", "body"?, "expect": [codes] }, the access change the app's own admin API makes
//   "restore"?: { "actorId", "method", "path", "body"?, "expect": [codes] },  the request that undoes it
//   "twinTurn"?: { "actorId", "method", "path", "body"?, "timeoutMs"? },      the allowed-use twin's turn (default: "turn")
//   "actions": [{ "id", "pathPrefix", "rejected"? }],                        the upstream paths whose 2xx is an applied action
//   "passive"?: [{ "id", "pathPrefix" }],                                     the upstream paths that are not actions (the model, a lookup)
//   "settleMs": ms,                                                           wait after the turn for late deliveries
//   "holdTimeoutMs"?: ms, "signals"?: [{ "status", "action"?, "deliveredBy"? }], "observers"?: [observer configs]
//   "world"?: { "command": [absolute argv], "startTimeoutMs"? }              (CLI) starts one fresh app per execution
// }
// A call on an action or a passive path is a boundary. The sweep adds a last rule, "other", for every other path: a
// call there could be an action nobody declared, which no prohibition would judge, so it makes the case abstain.
// "passive" is the operator's statement that a route applies nothing, like "rejected": it is for read-only paths. A
// passive prefix may not be "/", nor cover or fall inside an action's prefix (compared case-folded, as the gate matches),
// and a passive call answered 201, 202 or 204 (a created resource, an accepted job, a write with no body), or sent with a
// method other than GET, HEAD, OPTIONS, TRACE or POST (a PUT, PATCH or DELETE, whatever its answer), makes the case
// abstain. No declared prefix may hold "%" or a dot segment: the gate matches decoded, dot-resolved paths, so such a
// prefix would never match what it says, and the overlap check could not see what it covers.
// An action names every method on its path prefix: the hold gate names every request a rule's prefix matches with that
// rule's id, whatever its method, so a rule limited to one method would hold, number and judge different requests.
// Every execution carries an allowed-use twin: after the prohibitions' window, the twin turn runs through the
// same gate and must apply the actions the baseline applied. With "restore", access is restored first and the twin is
// the same turn by the same actor; without it, "twinTurn" must name an actor the access change does not touch (as the
// sequences README's in-flight example pairs Amy's held refund with Ben's).
// "rejected" is the hold gate's declared-refusal list (integrations/sequences/README.md); the gate validates it.
// It is the operator's statement, and it must not be declared for an upstream inside the application's trust domain
// (the same codebase or deployment, or one sharing its credentials or data): there the application chooses the status.
// Signals (default: a 202 answer to any action) mark answers after which an effect is still pending, such as a queued job;
// "deliveredBy" names the action that delivers it (default: the one other action, when there is exactly one); it may
// not be the signal's own action, because that rule's next call is the turn's next step, not the delivery.
// "observers" are built, started and sealed with every run, but no row selects them: they are recorded, never judged.
import { SEQUENCE_ID, SEQUENCE_LIMITS } from '../sequence.mjs';
import { SEQUENCE_METHODS } from '../transport.mjs';
import { CREDENTIAL_ENV } from '../../observers/events.mjs';

export const SWEEP_SPEC_SCHEMA = 'scopehaven-sweep-spec/1';
// The catch-all rule's id. "ungated" is the gate's own name for calls no rule matches.
export const OTHER_RULE = 'other';
export const RESERVED_RULES = Object.freeze([OTHER_RULE, 'ungated']);
export const DEFAULT_SIGNALS = Object.freeze([Object.freeze({ status: 202 })]);
export const SWEEP_LIMITS = Object.freeze({ specId: 60, actions: 16, signals: 8, settleMs: SEQUENCE_LIMITS.sleepMs, holdTimeoutMs: 120000, turnTimeoutMs: 300000, startTimeoutMs: 120000 });
// Short enough that "<spec id>-<rule><k>" stays a sequence id (80 characters).
const ACTION_ID = /^[A-Za-z0-9_-]{1,16}$/;
const SPEC_ID = new RegExp(`^[A-Za-z0-9_-]{1,${SWEEP_LIMITS.specId}}$`);
const isObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const intIn = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;

function checkRequest(r, where, actors, bad) {
  // A string actorId first: Object.hasOwn coerces its key, so ["amy"] would run as amy while the twin-actor test below, which
  // compares strictly, reads another actor.
  if (!isObject(r) || typeof r.actorId !== 'string' || !Object.hasOwn(actors, r.actorId) || !SEQUENCE_METHODS.includes(r.method) || typeof r.path !== 'string' || !r.path.startsWith('/')) bad(`${where} needs an actorId from actors, a method (${SEQUENCE_METHODS.join(', ')}) and a path starting with "/"`);
  if (r.timeoutMs !== undefined && !intIn(r.timeoutMs, 1, SWEEP_LIMITS.turnTimeoutMs)) bad(`${where}.timeoutMs must be 1 to ${SWEEP_LIMITS.turnTimeoutMs}`);
}

export function validateSweepSpec(spec) {
  const bad = reason => { throw new Error(`Invalid sweep spec: ${reason}.`); };
  if (!isObject(spec) || spec.schema !== SWEEP_SPEC_SCHEMA || !SPEC_ID.test(spec.id || '')) bad(`needs schema ${SWEEP_SPEC_SCHEMA} and an id of 1 to ${SWEEP_LIMITS.specId} letters, digits, "_" or "-"`);
  for (const key of ['applicationId', 'contextId']) if (spec[key] !== undefined && !SEQUENCE_ID.test(spec[key])) bad(`${key} must be 1 to 80 letters, digits, "_" or "-"`);
  if (!isObject(spec.actors) || !Object.keys(spec.actors).length) bad('needs actors');
  for (const [alias, actor] of Object.entries(spec.actors)) {
    if (!SEQUENCE_ID.test(alias) || !isObject(actor) || !SEQUENCE_ID.test(actor.principalId || '')) bad(`actor ${alias.slice(0, 40)} needs a principalId`);
    if (actor.credentialEnv !== undefined && !CREDENTIAL_ENV.test(actor.credentialEnv)) bad(`actor ${alias} credential references must use the SCOPEHAVEN_TARGET_ namespace`);
  }
  checkRequest(spec.turn, 'turn', spec.actors, bad);
  // The access change, and the request that undoes it, must each be shown to have worked before anything after it is judged.
  for (const key of ['condition', 'restore']) {
    if (key === 'restore' && spec.restore === undefined) continue;
    checkRequest(spec[key], key, spec.actors, bad);
    if (!(Array.isArray(spec[key].expect) && spec[key].expect.length >= 1 && spec[key].expect.length <= 16 && spec[key].expect.every(c => intIn(c, 100, 599)))) bad(`${key}.expect needs 1 to 16 status codes`);
  }
  if (spec.twinTurn !== undefined) checkRequest(spec.twinTurn, 'twinTurn', spec.actors, bad);
  // Without a restore, a twin by the changed actor could never apply anything: the twin needs another actor.
  if (spec.restore === undefined && !(spec.twinTurn !== undefined && spec.twinTurn.actorId !== spec.turn.actorId)) bad('needs "restore", or a "twinTurn" by an actor the access change does not touch, for the allowed-use twin');
  if (!Array.isArray(spec.actions) || !spec.actions.length || spec.actions.length > SWEEP_LIMITS.actions) bad(`needs 1 to ${SWEEP_LIMITS.actions} actions`);
  if (spec.passive !== undefined && !(Array.isArray(spec.passive) && spec.passive.length <= SWEEP_LIMITS.actions)) bad(`passive lists up to ${SWEEP_LIMITS.actions} paths`);
  const ids = new Set(), rule = (a, kind) => {
    if (!isObject(a) || !ACTION_ID.test(a.id || '') || typeof a.pathPrefix !== 'string' || !a.pathPrefix.startsWith('/')) bad(`each ${kind} needs an id of 1 to 16 letters, digits, "_" or "-" and a pathPrefix starting with "/"`);
    if (RESERVED_RULES.includes(a.id) || ids.has(a.id)) bad(`${kind} id "${a.id}" is reserved or declared twice`);
    if (Object.hasOwn(a, 'method')) bad(`${kind} ${a.id} declares a method, but a rule names every request on its path prefix`);
    // The gate matches decoded, dot-resolved paths: a prefix must already be in that form.
    if (a.pathPrefix.includes('%')) bad(`${kind} ${a.id} has "%" in its prefix: write the decoded path, as the gate matches it`);
    if (a.pathPrefix.split('/').some(segment => segment === '.' || segment === '..')) bad(`${kind} ${a.id} has a dot segment in its prefix: write the resolved path, as the gate matches it`);
    ids.add(a.id);
  };
  for (const a of spec.actions) rule(a, 'action');
  const actionIds = new Set(ids);
  for (const p of spec.passive ?? []) {
    rule(p, 'passive path');
    if (Object.hasOwn(p, 'rejected')) bad(`passive path ${p.id} declares "rejected", which only an action can`);
    const pp = p.pathPrefix.toLowerCase();
    if (pp === '/') bad(`passive path ${p.id} is "/", which would hide every action: declare the read-only paths one by one`);
    const over = spec.actions.find(a => { const ap = a.pathPrefix.toLowerCase(); return ap.startsWith(pp) || pp.startsWith(ap); });
    if (over) bad(`passive path ${p.id} overlaps action ${over.id}: a passive prefix may not cover or fall inside an action's prefix`);
  }
  if (!intIn(spec.settleMs, 0, SWEEP_LIMITS.settleMs)) bad(`settleMs must be 0 to ${SWEEP_LIMITS.settleMs}`);
  if (spec.holdTimeoutMs !== undefined && !intIn(spec.holdTimeoutMs, 1, SWEEP_LIMITS.holdTimeoutMs)) bad(`holdTimeoutMs must be 1 to ${SWEEP_LIMITS.holdTimeoutMs}`);
  if (spec.signals !== undefined) {
    if (!Array.isArray(spec.signals) || spec.signals.length > SWEEP_LIMITS.signals) bad(`signals lists up to ${SWEEP_LIMITS.signals} signals`);
    for (const s of spec.signals) {
      if (!isObject(s) || !intIn(s.status, 100, 599) || (s.action !== undefined && !actionIds.has(s.action)) || (s.deliveredBy !== undefined && !actionIds.has(s.deliveredBy))) bad('each signal needs a status code and, optionally, an action and a deliveredBy from actions');
      if (s.action !== undefined && s.deliveredBy === s.action) bad(`signal deliveredBy "${s.deliveredBy}" is the signal's own action: its next call is the turn's next step, not the delivery`);
    }
  }
  if (spec.observers !== undefined && !(Array.isArray(spec.observers) && spec.observers.length <= 15)) bad('observers lists up to 15 observer configurations (the hold gate is added to them)');
  if (spec.world !== undefined) {
    if (!isObject(spec.world) || !Array.isArray(spec.world.command) || !spec.world.command.length || spec.world.command.length > 64 || !spec.world.command.every(a => typeof a === 'string' && a.length <= 4096) || !spec.world.command[0].startsWith('/')) bad('world.command must be an argv list whose program is an absolute path');
    if (spec.world.startTimeoutMs !== undefined && !intIn(spec.world.startTimeoutMs, 1, SWEEP_LIMITS.startTimeoutMs)) bad(`world.startTimeoutMs must be 1 to ${SWEEP_LIMITS.startTimeoutMs}`);
  }
  return spec;
}

export const signalsOf = spec => spec.signals ?? DEFAULT_SIGNALS;
export const holdTimeoutOf = spec => spec.holdTimeoutMs ?? 60000;
export const passiveOf = spec => spec.passive ?? [];
// The answers that report a write (a created resource, an accepted job, a write with no body): on a passive path they
// make the case abstain.
export const PASSIVE_WRITE_STATUSES = Object.freeze([201, 202, 204]);
// The methods a passive call may be sent with: RFC 9110's safe methods, and POST, which the model route uses (an
// OpenAI-compatible chat completion). Any other method (PUT, PATCH, DELETE, a WebDAV write) is a write whatever it was
// answered, and so is a call whose method the gate timeline does not record.
export const PASSIVE_METHODS = Object.freeze(['GET', 'HEAD', 'OPTIONS', 'TRACE', 'POST']);
// A passive call ({ method, overrides, status }) wrote when its answer, its method or a method override says so. The
// overrides are the values the gate read from the request's override headers and `_method` parameters (gate.mjs,
// methodOverridesOf), compared as sent: each must be one of the methods above too, and a call whose overrides the
// timeline does not record counts as a write. A write answered 200 and sent as POST with no override, or as a safe method
// the application misuses for a write (a GET with side effects), is not caught.
export const passiveWrote = call => PASSIVE_WRITE_STATUSES.includes(call.status) || !PASSIVE_METHODS.includes(call.method)
  || !Array.isArray(call.overrides) || !call.overrides.every(m => PASSIVE_METHODS.includes(m));
// The rules a call can be a boundary of: the declared actions and passive paths, never the catch-all.
export const boundaryRules = spec => [...spec.actions, ...passiveOf(spec)].map(r => r.id);
// The gate rules for one run: the declared actions first (rules match first), then the passive paths, then the
// catch-all, which never holds. `held` names the rule that holds and how many of its requests.
export function gateRules(spec, held = null) {
  const rules = spec.actions.map(a => ({ id: a.id, pathPrefix: a.pathPrefix, holds: held?.rule === a.id ? held.k : 0, ...(a.rejected?.length ? { rejected: [...a.rejected] } : {}) }));
  for (const p of passiveOf(spec)) rules.push({ id: p.id, pathPrefix: p.pathPrefix, holds: held?.rule === p.id ? held.k : 0 });
  rules.push({ id: OTHER_RULE, pathPrefix: '/', holds: 0 });
  return rules;
}
