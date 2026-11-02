// Write plan (scopehaven-write-plan/1), stage 1: the inventory of variants and their classification. Every
// statement rule, write-binding route and matrix cell is expanded over relation, creator and state; a variant whose
// deciding rule has a limit is expanded over its under, at and over points, and one whose rule has a lifecycle over its
// phases. Every variant gets either its stated decision (a case can be drafted for it) or exactly one reason it cannot. Only a statement rule creates a case: a matrix cell or a route alone
// adds variants to the inventory, never intent. Above the inventory limit, generation refuses and names the dimension;
// it never truncates. Nothing here reads an application or sends a request.
import { cellKey, canonical, isMatrix, sha256 } from './matrix.mjs';
import { RELATIONS, checkStatement, statedDecision, verifyStatement } from './statement.mjs';
import { absenceDecidable, effectFor, objectFor, routeFor, validateWriteBinding } from './write-binding.mjs';

export const WRITE_PLAN_SCHEMA = 'scopehaven-write-plan/1';
// The relation variants of a request on an existing object. A create on a collection has one variant, "none".
export const VARIANT_RELATIONS = Object.freeze(RELATIONS.filter(r => r !== 'any'));
export const LIMIT_POINTS = Object.freeze(['under', 'at', 'over']);
// In-flight and queued work is a variant too; it stays unexecuted (needs-hold-gate) until a hold gate lands on the path.
export const LIFECYCLE_PHASES = Object.freeze(['before', 'after', 'in-flight']);
export const DIMENSIONS = Object.freeze(['relation', 'creator', 'state', 'point', 'phase']);
// The cell's own dimensions. Points and phases are not: they belong to the rule that decides a variant.
const BASE_DIMENSIONS = Object.freeze(['relation', 'creator', 'state']);
// The order reasons are checked in: the first that applies is the variant's one reason.
export const CLASSIFY_ORDER = Object.freeze(['not-stated', 'candidate-only', 'unknown-gap', 'no-route-bound', 'role-not-mapped', 'needs-second-actor', 'no-allowed-use-on-route',
  'silent-refusal-without-observer', 'prefix-effect-name', 'insufficient-observation', 'no-declared-revert', 'needs-hold-gate']);

const fail = message => { throw new Error(`write plan: ${message}`); };
const byCode = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const uniq = list => [...new Set(list)].sort(byCode);
// The bound actors and routes in id and name order, so a binding's key order never changes who plays a part or which
// route is used.
const actorList = binding => Object.entries(binding.actors).map(([id, a]) => ({ id, ...a })).sort((a, b) => byCode(a.id, b.id));
const entriesByName = o => Object.entries(o ?? {}).sort(([x], [y]) => byCode(x, y));
const routeList = binding => entriesByName(binding.routes).flatMap(([resource, byAction]) => entriesByName(byAction).map(([action, r]) => [{ resource, action }, r]));

// The cells the inventory starts from, with where each came from.
function baseCells(statement, binding, matrices) {
  const cells = new Map();
  const add = (role, resource, action, from, extra = {}) => {
    const key = cellKey({ role, resource, action });
    const c = cells.get(key) ?? { role, resource, action, from: new Set(), matrix: [] };
    c.from.add(from);
    if (extra.matrix) c.matrix.push(extra.matrix);
    cells.set(key, c);
  };
  for (const r of statement.rules) add(r.role, r.resource, r.action, 'statement');
  for (const [resource, byAction] of Object.entries(binding.routes)) for (const action of Object.keys(byAction)) for (const role of statement.roles) add(role, resource, action, 'binding');
  for (const m of matrices) for (const c of m.cells) add(c.role, c.resource, c.action, 'matrix', { matrix: { matrixId: m.matrixId, decision: c.decision } });
  return [...cells.values()].sort((a, b) => byCode(cellKey(a), cellKey(b)));
}

// The cell's dimension values. Relation variants need a bound request on an existing object; a create on a collection
// has the one variant "none", and an unbound cell varies over the relations its rules name (or is one "any" variant).
// Creators and states come from the rules.
function dimensionsOf(cell, statement, binding) {
  const rules = statement.rules.filter(r => cellKey(r) === cellKey(cell));
  const route = routeFor(binding, cell.resource, cell.action);
  const named = uniq(rules.map(r => r.relation));
  const relation = !route ? (named.length ? named : ['any']) : route.object === null ? ['none'] : VARIANT_RELATIONS.filter(r => r !== 'cross-tenant' || statement.tenants.length >= 2);
  const creators = uniq(rules.flatMap(r => r.creators ?? []));
  const states = uniq(rules.flatMap(r => (r.state === undefined ? [] : [r.state])));
  return { relation, creator: creators.length ? creators : [null], state: states.length ? states : [null] };
}
const sizeOf = dims => BASE_DIMENSIONS.reduce((n, d) => n * dims[d].length, 1);
// What the statement is asked for a variant: a create or an unbound cell reads relation "any".
const queryOf = v => ({ role: v.role, resource: v.resource, action: v.action, relation: ['none', 'any'].includes(v.relation) ? 'any' : v.relation,
  ...(v.state !== null ? { state: v.state } : {}), ...(v.creator !== null ? { creator: v.creator } : {}) });
// A base variant's points and phases: the limit's three points only when the rule that decides it has a limit, and the
// lifecycle's three phases only when it has a lifecycle. A plain rule beside them in the same cell gets neither.
function pointsAndPhases(statement, base) {
  const d = statedDecision(statement, queryOf(base));
  return { point: d?.limit ? [...LIMIT_POINTS] : [null], phase: d?.lifecycle ? [...LIFECYCLE_PHASES] : [null] };
}

// The stated decision for one variant, with the limit's points and the lifecycle's phases applied, or null.
function variantDecision(statement, v) {
  const d = statedDecision(statement, queryOf(v));
  if (!d) return null;
  let decision = d.decision;
  if (d.limit && v.point !== null) {
    // Under the cap is the allowance, over it the prohibition; at the cap follows the stated inclusivity, and stays unstated without it.
    if (v.point === 'over') decision = 'deny';
    else if (v.point === 'at') { if (d.limit.inclusive === undefined) return null; decision = d.limit.inclusive ? 'allow' : 'deny'; }
  }
  if (d.lifecycle && v.phase === 'after') decision = d.lifecycle.after;
  return { decision, confidence: d.confidence, ruleId: d.ruleId, ...(d.category ? { category: d.category } : {}) };
}

// Who can play each part of a variant: an attacker of the variant's role, and an owner the relation needs.
function actorsFor(binding, v) {
  const actors = actorList(binding);
  const attackers = actors.filter(a => a.role === v.role);
  if (!attackers.length) return { reason: 'role-not-mapped' };
  const ownerRole = v.creator ?? v.role;
  const owners = attacker => actors.filter(o => {
    if (v.relation === 'own') return o.id === attacker.id;
    if (v.relation === 'other-same-role') return o.id !== attacker.id && o.role === v.role && o.tenant === attacker.tenant;
    if (v.relation === 'other-role') return o.role !== v.role && o.tenant === attacker.tenant && (v.creator === null || o.role === v.creator);
    if (v.relation === 'cross-tenant') return o.tenant !== attacker.tenant && o.tenant !== null && (v.creator === null || o.role === v.creator);
    // A create, or an unbound cell: an owner only when a creator is named.
    return v.creator === null || o.role === ownerRole;
  });
  const pair = attackers.find(a => owners(a).length);
  return pair ? { attacker: pair.id, owner: owners(pair)[0].id } : { reason: 'needs-second-actor' };
}

// The GET routes a case can pad with, in order: the object type's precheck, then GETs on the resource's collection.
function paddingRoutes(binding, route, resource) {
  const pre = route.object !== null ? objectFor(binding, route.object)?.precheck : undefined;
  const preRoute = pre && routeFor(binding, pre.resource, pre.action);
  const list = entriesByName(binding.routes[resource]).filter(([, r]) => r.method === 'GET' && r.object === null).map(([action, r]) => ({ resource, action, route: r }));
  return [...(preRoute ? [{ resource: pre.resource, action: pre.action, route: preRoute }] : []), ...list];
}
export const paddingRoute = (binding, route, resource) => paddingRoutes(binding, route, resource)[0] ?? null;
// A padding read expects the allowed status in every phase of the case, so it must be one the statement neither refuses
// the actor nor ties to a lifecycle. An unstated read pads as before.
function padsFor(statement, actor, pad) {
  const d = statedDecision(statement, { role: actor.role, resource: pad.resource, action: pad.action, relation: pad.route.object !== null ? 'own' : 'any' });
  return !d || (d.decision === 'allow' && !d.lifecycle);
}

// A prohibition needs its paired allowed-use control. At a limit point it is the same actor under the cap, and in a
// lifecycle phase the same actor in the other phase; the statement allows both by construction (a limit caps an allow,
// and lifecycle.after differs from the rule's decision). Otherwise it is the actor buildCase pairs with (pairActorFor),
// so the classifier and the case never disagree.
function hasPair(statement, binding, v, cast, route) {
  if (v.phase !== null || v.point !== null) return true;
  return pairActorFor(statement, binding, v, cast, route.object !== null) !== null;
}

function classify(statement, binding, cell, v) {
  const stated = variantDecision(statement, v);
  if (!stated) {
    const candidate = (statement.candidates ?? []).some(c => cellKey(c) === cellKey(cell));
    const unknown = cell.matrix.some(m => m.decision === 'unknown');
    return { stated: null, reason: candidate ? 'candidate-only' : unknown ? 'unknown-gap' : 'not-stated' };
  }
  const route = routeFor(binding, v.resource, v.action);
  if (!route) return { stated, reason: 'no-route-bound' };
  const cast = actorsFor(binding, v);
  if (cast.reason) return { stated, reason: cast.reason };
  if (stated.decision === 'deny' && !hasPair(statement, binding, v, cast, route)) return { stated, reason: 'no-allowed-use-on-route' };
  const effect = effectFor(binding, v.resource, v.action);
  if (route.refusal.kind === 'silent' && !effect) return { stated, reason: 'silent-refusal-without-observer' };
  if (effect && typeof effect.name !== 'string') return { stated, reason: 'prefix-effect-name' };
  // Every case is decided from records (effect clauses only), a read as much as a write: a read needs an observer that
  // records reads. Response-level read checks are what draft.mjs drafts from binding /1. A prohibition is an absence,
  // so its observer must decide absence for the acting principal (absenceDecidable).
  if (!effect) return { stated, reason: 'insufficient-observation' };
  if (stated.decision === 'deny' && !absenceDecidable(effect)) return { stated, reason: 'insufficient-observation' };
  if (route.object !== null && route.method !== 'GET' && !objectFor(binding, route.object)?.revert) return { stated, reason: 'no-declared-revert' };
  if (v.phase === 'in-flight') return { stated, reason: 'needs-hold-gate' };
  // Every judged identity is padded to three turns with GET requests: the object type's precheck, or a GET on the collection.
  if (!paddingRoute(binding, route, v.resource)) return { stated, reason: 'no-route-bound' };
  return { stated, reason: null, cast };
}

// The variant key, stable across input order: the cell and every dimension.
export const variantKey = v => JSON.stringify([v.role, v.resource, v.action, v.relation, v.creator, v.state, v.point, v.phase]);
const levelOf = v => (v.point !== null ? `limit-${v.point}` : v.phase !== null ? `lifecycle-${v.phase}` : 'base');

// The inventory: every variant with its stated decision or its one reason. `matrices` add cells; they never add intent.
export function writeInventory({ statement, binding, matrices = [] }) {
  if (!verifyStatement(statement)) fail('the plan needs a sealed, unedited statement');
  checkStatement(statement); // re-validates the sealed body; an id recomputed over an edited body is refused
  const b = validateWriteBinding(binding);
  if (b.application !== statement.application) fail(`the binding is for ${b.application}, the statement for ${statement.application}`);
  if (!Array.isArray(matrices) || matrices.some(m => !isMatrix(m))) fail('a matrix is missing or was edited after import (its matrixId no longer matches)');
  const cells = baseCells(statement, b, matrices).map(cell => ({ cell, dims: dimensionsOf(cell, statement, b) }));
  // Each base variant's points and phases: one statement lookup each, bounded by the statement's own rules.
  for (const c of cells) {
    c.bases = [];
    for (const relation of c.dims.relation) for (const creator of c.dims.creator) for (const state of c.dims.state) {
      const base = { role: c.cell.role, resource: c.cell.resource, action: c.cell.action, relation, creator, state };
      c.bases.push({ base, ...pointsAndPhases(statement, base) });
    }
    c.size = c.bases.reduce((n, x) => n + x.point.length * x.phase.length, 0);
  }
  const total = cells.reduce((n, c) => n + c.size, 0);
  if (total > b.budget.inventoryLimit) {
    // Name the dimension that multiplies the inventory most: the one whose single value would shrink it the most.
    const without = d => cells.reduce((n, c) => n + (d === 'point' ? c.bases.reduce((m, x) => m + x.phase.length, 0) : d === 'phase' ? c.bases.reduce((m, x) => m + x.point.length, 0)
      : c.size / c.dims[d].length), 0);
    const [worst] = [...DIMENSIONS].sort((x, y) => without(x) - without(y));
    fail(`the inventory has ${total} variants, above the inventory limit of ${b.budget.inventoryLimit}; the "${worst}" dimension multiplies it most. Raise budget.inventoryLimit or narrow the rules; nothing is truncated`);
  }
  const variants = [];
  for (const { cell, bases, size } of cells) {
    const before = variants.length;
    for (const { base, point: points, phase: phases } of bases) for (const point of points) for (const phase of phases) {
      const v = { ...base, point, phase };
      const c = classify(statement, b, cell, v);
      variants.push({ key: variantKey(v), cellKey: cellKey(cell), ...v, from: [...cell.from].sort(byCode), level: c.stated ? levelOf(v) : 'not-stated',
        stated: c.stated, reason: c.reason, ...(c.cast ? { cast: c.cast } : {}) });
    }
    // A cell's variants: the product of its own dimensions, each base variant times its own points and phases (a test pins this).
    if (variants.length - before !== size) fail(`internal: ${cellKey(cell)} enumerated ${variants.length - before} of ${size} variants`);
  }
  const reasons = {};
  for (const v of variants) if (v.reason) reasons[v.reason] = (reasons[v.reason] ?? 0) + 1;
  return { statementId: statement.statementId, bindingDigest: b.bindingDigest, matrixIds: uniq(matrices.map(m => m.matrixId)), total, variants,
    draftable: variants.filter(v => v.stated && !v.reason).length, reasons, binding: b };
}

// Accounting cells for the inventory, the shape ../coverage-report/accounting.mjs reads: one per
// variant, keyed by the variant key. A variant with a reason carries it; a draftable one carries none (the accounting
// reads it as not drafted until a case is).
export function inventoryCells(inventory) {
  return inventory.variants.map(v => ({ key: v.key, role: v.role, tenant: null, surface: routeFor(inventory.binding, v.resource, v.action) ? 'http' : 'not-bound',
    resource: v.resource, action: v.action, relation: v.relation, level: v.level, side: v.stated?.decision === 'allow' ? 'allowed' : 'forbidden', reachable: true,
    stated: v.stated ? { confidence: v.stated.confidence, ruleId: v.stated.ruleId } : null, ...(v.reason ? { reason: v.reason } : {}) }));
}

// The inventory's identity, for the plan: what was enumerated from what.
export const inventoryDigest = inventory => sha256(canonical({ statementId: inventory.statementId, bindingDigest: inventory.bindingDigest, matrixIds: inventory.matrixIds,
  variants: inventory.variants.map(v => [v.key, v.stated?.decision ?? null, v.stated?.ruleId ?? null, v.reason]) }));

// ---- Stage 2: cases, selection and the plan --------------------------------------------------------------------------
// A case is a template filled for one draftable variant: who acts on which object, in which order, what each request
// expects and which effect assertions judge it. Every prohibition carries its paired allowed-use control, which selects
// the same effect in every field but the actor (the multiturn SAME_EFFECT rule), so a system that refuses everything
// cannot pass. A plan holds nothing above drafted: nothing here sends a request.
export const TEMPLATES = Object.freeze({ T1: 'owner or tenant write prohibition', T2: 'create prohibition', T3: 'boundary', T4: 'creator', T5: 'lifecycle', T6: 'allowed-side twin' });
export const PRIORITY = Object.freeze(['base-prohibition', 'allowed-twin', 'ownership', 'creator', 'boundary', 'lifecycle']);
export const CASE_LIMITS = Object.freeze({ turns: 21, judgedTurns: 3 });
export const SELECTION_RULE = 'Priority: one base prohibition with its pair per stated deny rule, allowed-side twins, ownership, creators, boundary points, lifecycle. Within a rank: round-robin over operations, then the canonical variant key. Cut at budget.maxCases; the rest are over-budget, counted, never dropped. The selection never reads a defect.';
const RELATION_ORDER = ['other-role', 'other-same-role', 'cross-tenant', 'own', 'none', 'any'];
const VEHICLE_OF = { T4: 'P', T5: 'S' };

const templateOf = (v, route) => (v.phase !== null ? 'T5' : v.point !== null ? 'T3' : v.creator !== null ? 'T4' : v.stated.decision === 'allow' ? 'T6' : route.object === null ? 'T2' : 'T1');
const refusalOf = route => (route.refusal.kind === 'status' ? [...route.refusal.statuses] : [route.refusal.status]);
const relationBetween = (a, owner) => (a.id === owner.id ? 'own' : a.tenant !== owner.tenant ? 'cross-tenant' : a.role === owner.role ? 'other-same-role' : 'other-role');
// A turn: one request by one actor, from a bound route, on an object of the case (or the collection).
function turnOf(part, actor, ref, routeRef, route, expect, body) {
  return { part, actor, resource: routeRef.resource, action: routeRef.action, method: route.method, pathTemplate: route.pathTemplate,
    ...(body !== undefined ? { body } : route.bodyTemplate ? { body: route.bodyTemplate } : {}), ...(ref ? { object: ref } : {}), expect };
}
const selectorOf = (effect, actorRef, objectRef) => ({ source: effect.source, operation: effect.operation, name: effect.name, actorRef,
  ...(effect.resourceTemplate ? { resourceTemplate: effect.resourceTemplate, ...(objectRef ? { object: objectRef } : {}) } : {}) });
// A JSON body with the value at a pointer set (the limit's field), built on a copy of the route's body template.
function bodyWith(template, pointer, value) {
  const body = structuredClone(template ?? {});
  const keys = pointer.split('/').slice(1).map(k => k.replace(/~1/g, '/').replace(/~0/g, '~'));
  let at = body;
  keys.slice(0, -1).forEach(k => { if (at[k] === null || typeof at[k] !== 'object') at[k] = {}; at = at[k]; });
  at[keys.at(-1)] = value;
  return body;
}
const pointValue = (cap, point) => (Number.isInteger(cap) ? { under: cap - 1, at: cap, over: cap + 1 }[point] : { under: cap / 2, at: cap, over: cap * 2 }[point]);

// The actor that runs a prohibition's paired control: the owner when it may act on its own object, else another actor
// the statement allows for its relation to the owner (or, on a collection, any actor allowed to create).
function pairActorFor(statement, binding, v, cast, onObject) {
  const actors = actorList(binding), owner = actors.find(a => a.id === cast.owner);
  const allowed = a => statedDecision(statement, { role: a.role, resource: v.resource, action: v.action, relation: onObject ? relationBetween(a, owner) : 'any',
    ...(v.state !== null ? { state: v.state } : {}), ...(v.creator !== null ? { creator: v.creator } : {}) })?.decision === 'allow';
  const ordered = onObject ? [owner, ...actors.filter(a => a.id !== owner.id)] : actors;
  return ordered.find(a => a.id !== cast.attacker && allowed(a))?.id ?? null;
}

// Pad every judged identity to three turns with GET requests on objects it owns (or the collection). The order is the
// design's: forbidden attempts, then non-consuming controls and padding, the attacker's liveness control late (so the
// prohibition's window stays open as long as it can), and at most one consuming control at the end.
// Each actor pads with the first padding read it may make (padOf); an actor that needs padding and has none leaves the
// case unpadded (null).
function padded(turns, judged, padOf, objectsOwned) {
  const liveness = turns.filter(t => t.part === 'liveness');
  const out = turns.filter(t => t.part !== 'liveness');
  const lastConsuming = out.length && out.at(-1).consumes ? out.pop() : null;
  for (const actor of judged) {
    while (out.filter(t => t.actor === actor).length + liveness.filter(t => t.actor === actor).length + (lastConsuming?.actor === actor ? 1 : 0) < CASE_LIMITS.judgedTurns) {
      const pad = padOf(actor);
      if (!pad) return null;
      out.push(turnOf('padding', actor, pad.route.object !== null ? objectsOwned[actor] ?? null : null, pad, pad.route, [pad.route.allowStatus]));
    }
  }
  out.push(...liveness);
  if (lastConsuming) out.push(lastConsuming);
  return out.map(({ consumes, ...t }) => t);
}

function buildCase(statement, binding, v) {
  const route = routeFor(binding, v.resource, v.action), effect = effectFor(binding, v.resource, v.action), routeRef = { resource: v.resource, action: v.action };
  const template = templateOf(v, route), onObject = route.object !== null, pads = paddingRoutes(binding, route, v.resource);
  const { attacker, owner } = v.cast;
  const objects = [], turns = [], assertions = [], judged = new Set();
  const own = {};
  const object = (ref, ownerId) => { if (!onObject) return null; if (!objects.some(o => o.ref === ref)) objects.push({ ref, type: route.object, owner: ownerId }); own[ownerId] ??= ref; return ref; };
  // The object a variant's actor acts on: its own (W) for "own" or a create, else the owner's (V).
  const target = () => (['own', 'none', 'any'].includes(v.relation) ? object('W', attacker) : object('V', owner));
  const F = { id: 'F', title: `${v.role} may not ${v.action} ${v.resource} (${v.relation})`, severity: 'high', kind: 'effect.none' };
  const C = { id: 'C', title: `${v.action} ${v.resource} is allowed (paired control)`, severity: 'control', kind: 'effect.exists' };
  let reason = null;
  const prohibition = (attemptTurn, attemptRef, pairActor, pairRef, pairBody) => {
    turns.push({ ...attemptTurn, consumes: false });
    if (pairActor === null) { reason = 'no-allowed-use-on-route'; return; }
    turns.push({ ...turnOf('pair', pairActor, pairRef, routeRef, route, [route.allowStatus], pairBody), consumes: route.consumes });
    judged.add(attacker); judged.add(pairActor);
    assertions.push({ ...F, actor: attacker, select: selectorOf(effect, attacker, attemptRef), control: 'C' }, { ...C, actor: pairActor, select: selectorOf(effect, pairActor, pairRef) });
  };
  if (template === 'T1' || (template === 'T4' && v.stated.decision === 'deny' && onObject)) {
    const V = object('V', owner);
    const pairActor = pairActorFor(statement, binding, v, v.cast, true);
    prohibition(turnOf('attempt', attacker, V, routeRef, route, refusalOf(route)), V, pairActor, V);
    // The attacker's liveness control on its own W, when V is someone else's and the attacker may act on its own:
    // required, not the pair. On its own object (relation own) there is no W.
    const me = actorList(binding).find(a => a.id === attacker);
    if (pairActor !== null && owner !== attacker && statedDecision(statement, { role: me.role, resource: v.resource, action: v.action, relation: 'own' })?.decision === 'allow') {
      const W = object('W', attacker);
      turns.splice(1, 0, { ...turnOf('liveness', attacker, W, routeRef, route, [route.allowStatus]), consumes: false });
      assertions.push({ id: 'L', title: `${v.role} may ${v.action} its own ${v.resource} (liveness)`, severity: 'control', kind: 'effect.exists', actor: attacker, select: selectorOf(effect, attacker, W) });
    }
  } else if (template === 'T2' || (template === 'T4' && v.stated.decision === 'deny')) {
    const pairActor = pairActorFor(statement, binding, v, v.cast, false);
    prohibition(turnOf('attempt', attacker, null, routeRef, route, refusalOf(route)), null, pairActor, null);
  } else if (template === 'T3') {
    const { limit } = statedDecision(statement, queryOf(v));
    const ref = target();
    const at = point => bodyWith(route.bodyTemplate, limit.pointer, pointValue(limit.cap, point));
    if (v.stated.decision === 'deny') prohibition(turnOf('attempt', attacker, ref, routeRef, route, refusalOf(route), at(v.point)), ref, attacker, ref, at('under'));
    else { turns.push({ ...turnOf('control', attacker, ref, routeRef, route, [route.allowStatus], at(v.point)), consumes: route.consumes }); judged.add(attacker);
      assertions.push({ ...C, title: `${v.role} may ${v.action} ${v.resource} at the ${v.point} point`, actor: attacker, select: selectorOf(effect, attacker, ref) }); }
  } else if (template === 'T5') {
    // The variant's object, created only where a turn acts on it (a consuming allowed-first case acts on two others).
    const refName = ['own', 'none', 'any'].includes(v.relation) ? 'W' : 'V', refOwner = refName === 'W' ? attacker : owner;
    const rule = statement.rules.find(r => r.ruleId === v.stated.ruleId), { transition, subject } = rule.lifecycle;
    // The rule's decision holds before the transition and lifecycle.after after it; they always differ.
    const allowedFirst = rule.decision === 'allow';
    const control = when => { const ref = object(refName, refOwner); turns.push({ ...turnOf('control', attacker, ref, routeRef, route, [route.allowStatus]), consumes: route.consumes }); judged.add(attacker);
      assertions.push({ ...C, title: `${v.role} may ${v.action} ${v.resource} ${when} ${transition}`, actor: attacker, select: selectorOf(effect, attacker, ref) }); };
    if (v.phase === 'before' && allowedFirst) control('before');
    else {
      // Every other phase needs the transition performed, on the route that names it, by an actor the statement allows
      // to perform it there: never the attacker or the peer twin.
      const [tRef, tRoute] = routeList(binding).find(([, r]) => typeof r.transition === 'string' && r.transition === transition) ?? [];
      const actors = actorList(binding), me = actors.find(a => a.id === attacker);
      // The peer twin (allowed first only) is an actor the transition leaves alone, by its subject: any other actor when
      // the actor is the subject, another tenant when the tenant is, another role when the role is. A same-role peer
      // first where the subject allows it, and only one the statement allows on this route.
      const unaffected = a => a.id !== attacker && (subject === 'actor' || (subject === 'tenant' ? a.tenant !== me.tenant : a.role !== me.role));
      const allowedOwn = a => statedDecision(statement, { role: a.role, resource: v.resource, action: v.action, relation: 'own' })?.decision === 'allow';
      const peer = allowedFirst ? [...actors.filter(a => a.role === me.role), ...actors.filter(a => a.role !== me.role)].find(a => unaffected(a) && allowedOwn(a)) ?? null : null;
      const mayPerform = a => statedDecision(statement, { role: a.role, resource: tRef.resource, action: tRef.action, relation: tRoute.object !== null ? relationBetween(a, me) : 'any' })?.decision === 'allow';
      const performer = tRoute ? actors.find(a => a.id !== attacker && a.id !== peer?.id && mayPerform(a)) : undefined;
      const transitionTurn = () => {
        turns.push({ ...turnOf('transition', performer.id, tRoute.object !== null ? 'S' : null, tRef, tRoute, [tRoute.allowStatus]), consumes: false });
        if (tRoute.object !== null) objects.push({ ref: 'S', type: tRoute.object, owner: attacker, subject: true });
      };
      if (!tRoute) reason = 'no-route-bound';
      else if ((allowedFirst && !peer) || !performer) reason = 'needs-second-actor';
      else if (!allowedFirst && v.phase === 'before') {
        // Refused before the transition, allowed after it: the attempt, the transition, then the same actor's control on
        // the same object, which pairs with the attempt (the prohibition's window ends before it).
        const ref = object(refName, refOwner);
        turns.push({ ...turnOf('attempt', attacker, ref, routeRef, route, refusalOf(route)), consumes: false });
        assertions.push({ ...F, title: `${v.role} may not ${v.action} ${v.resource} before ${transition}`, actor: attacker, select: selectorOf(effect, attacker, ref), control: 'C' });
        transitionTurn();
        control('after');
      } else if (!allowedFirst) {
        // Allowed after the transition: the transition, then the control.
        transitionTurn();
        control('after');
      } else {
        // Allowed before the transition, refused after it. On a consuming route the before-control uses its object up, so
        // the after-attempt acts on a second one. The attacker pads on its own base object, which no turn consumes (or on
        // its W when the objects are another's); the peer, whose twin consumes P, pads on another.
        const ref = route.consumes && refOwner !== attacker ? (onObject ? refName : null) : object(refName, refOwner);
        const beforeRef = route.consumes && ref ? object(`${ref}1`, refOwner) : ref, attemptRef = route.consumes && ref ? object(`${ref}2`, refOwner) : ref;
        const peerRef = object('P', peer.id);
        if (route.consumes && peerRef) own[peer.id] = object(`O-${peer.id}`, peer.id);
        turns.push({ ...turnOf('before-control', attacker, beforeRef, routeRef, route, [route.allowStatus]), consumes: false });
        transitionTurn();
        turns.push({ ...turnOf('attempt', attacker, attemptRef, routeRef, route, refusalOf(route)), consumes: false });
        turns.push({ ...turnOf('peer-twin', peer.id, peerRef, routeRef, route, [route.allowStatus]), consumes: false });
        judged.add(attacker); judged.add(peer.id);
        assertions.push({ ...F, title: `${v.role} may not ${v.action} ${v.resource} after ${transition}`, actor: attacker, select: selectorOf(effect, attacker, attemptRef), control: 'C' },
          { ...C, title: `${v.role} may ${v.action} ${v.resource} before ${transition}`, actor: attacker, select: selectorOf(effect, attacker, beforeRef), window: 'before-control' },
          { id: 'P', title: `a peer the ${transition} leaves alone may still ${v.action} ${v.resource}`, severity: 'control', kind: 'effect.exists', actor: peer.id, select: selectorOf(effect, peer.id, peerRef) });
      }
    }
  } else {
    // T6, and T4 with an allowed creator: one control, the actor acting where the statement allows it.
    const ref = target();
    turns.push({ ...turnOf('control', attacker, ref, routeRef, route, [route.allowStatus]), consumes: route.consumes }); judged.add(attacker);
    assertions.push({ ...C, title: `${v.role} may ${v.action} ${v.resource} (${v.relation})`, actor: attacker, select: selectorOf(effect, attacker, ref) });
  }
  if (reason) return { reason };
  // A state-conditioned variant names the state the objects it acts on must be in, so setup can tell them from the rest.
  if (v.state !== null) for (const o of objects) if (turns.some(t => ['attempt', 'pair', 'control', 'before-control', 'peer-twin'].includes(t.part) && t.object === o.ref)) o.state = v.state;
  if (!objects.some(o => o.owner === attacker) && onObject) object('W', attacker);
  for (const a of judged) if (onObject && !own[a]) object(`O-${a}`, a);
  const byId = new Map(actorList(binding).map(a => [a.id, a]));
  const ordered = padded(turns, [...judged].sort(byCode), id => pads.find(p => padsFor(statement, byId.get(id), p)) ?? null, own);
  if (!ordered) return { reason: 'no-route-bound' };
  if (ordered.length > CASE_LIMITS.turns) return { reason: 'over-budget' };
  // Windows: a prohibition watches from its attempt to the end of the case, so a late effect still lands in it; a
  // control watches its own turn.
  const indexOf = part => ordered.findIndex(t => t.part === part) + 1;
  const fromOf = a => (a.window === 'before-control' ? indexOf('before-control') : a.kind === 'effect.none' ? indexOf('attempt') : a.id === 'P' ? indexOf('peer-twin') : a.id === 'L' ? indexOf('liveness') : ordered.findIndex(t => ['pair', 'control'].includes(t.part)) + 1);
  const windowed = assertions.map(a => {
    const from = fromOf(a), { window: _w, ...rest } = a;
    if (a.kind !== 'effect.none') return { ...rest, window: [from, from] };
    // ...but stops before any later turn by the same actor whose bound effect the prohibition's selector could also
    // match (a same-actor control, its liveness, or padding that reads what a read prohibition watches), unless an
    // object resource tells them apart. An allowed request never fails the prohibition.
    const key = x => (x ? canonical([x.source, x.operation, x.name]) : null);
    const mine = key(a.select);
    const distinct = t => a.select.resourceTemplate && a.select.object && t.object && t.object !== a.select.object;
    const later = ordered.map((t, i) => ({ t, at: i + 1 })).filter(({ t, at }) => at > from && t.actor === a.actor && key(effectFor(binding, t.resource, t.action)) === mine && !distinct(t)).map(x => x.at);
    return { ...rest, window: [from, later.length ? Math.min(...later) - 1 : ordered.length] };
  });
  const rule = statement.rules.find(r => r.ruleId === v.stated.ruleId);
  const ruleDigest = sha256(canonical(rule ?? { ruleId: v.stated.ruleId, defaults: statement.defaults }));
  const caseId = `WC-${sha256(canonical([v.cellKey, v.key, v.stated.decision, ruleDigest, template])).slice(0, 12).toUpperCase()}`;
  const revert = [...new Set(objects.map(o => objectFor(binding, o.type)?.revert).filter(Boolean).map(r => canonical(r)))].map(r => JSON.parse(r));
  return { case: { caseId, key: v.key, cellKey: v.cellKey, template, vehicle: VEHICLE_OF[template] ?? 'P', decision: v.stated.decision, ruleId: v.stated.ruleId,
    confidence: v.stated.confidence, ...(v.stated.category ? { category: v.stated.category } : {}),
    variant: { role: v.role, resource: v.resource, action: v.action, relation: v.relation, creator: v.creator, state: v.state, point: v.point, phase: v.phase },
    objects, turns: ordered, assertions: windowed, revert, ...(route.consumes ? { consumes: true } : {}),
    ...(template === 'T2' || (template === 'T4' && !onObject) ? { residue: 'A create that is not refused leaves a record: reset to the seed before the next run.' } : {}), confirmed: false } };
}

const rankOf = (template, v, baseKeys) => ({ T1: baseKeys.has(v.key) ? 'base-prohibition' : 'ownership', T2: baseKeys.has(v.key) ? 'base-prohibition' : 'ownership',
  T6: 'allowed-twin', T4: 'creator', T3: 'boundary', T5: 'lifecycle' })[template];

// The write plan: the inventory, a case for every selected draftable variant, and every other variant with its reason.
export function buildWritePlan({ statement, binding, matrices = [] }) {
  const inventory = writeInventory({ statement, binding, matrices });
  const b = inventory.binding;
  const built = [], reasons = new Map(inventory.variants.filter(v => v.reason).map(v => [v.key, v.reason]));
  for (const v of inventory.variants.filter(x => !x.reason)) {
    const r = buildCase(statement, b, v);
    if (r.reason) reasons.set(v.key, r.reason); else built.push({ v, c: r.case });
  }
  // One base prohibition per stated deny rule: its first variant by relation, then key.
  const baseKeys = new Set();
  const byRule = new Map();
  for (const { v, c } of built.filter(x => ['T1', 'T2'].includes(x.c.template))) byRule.set(v.stated.ruleId, [...(byRule.get(v.stated.ruleId) ?? []), v]);
  for (const list of byRule.values()) baseKeys.add(list.sort((a, b2) => RELATION_ORDER.indexOf(a.relation) - RELATION_ORDER.indexOf(b2.relation) || byCode(a.key, b2.key))[0].key);
  // Rank, then round-robin over operations within a rank, then the variant key.
  const ordered = [];
  for (const rank of PRIORITY) {
    const groups = new Map();
    for (const x of built.filter(y => rankOf(y.c.template, y.v, baseKeys) === rank)) { const op = JSON.stringify([x.v.resource, x.v.action]); groups.set(op, [...(groups.get(op) ?? []), x]); }
    const queues = [...groups.keys()].sort(byCode).map(op => groups.get(op).sort((a, b2) => byCode(a.v.key, b2.v.key)));
    for (let i = 0; queues.some(q => i < q.length); i++) for (const q of queues) if (i < q.length) ordered.push({ ...q[i], rank });
  }
  const selected = ordered.slice(0, b.budget.maxCases), over = ordered.slice(b.budget.maxCases);
  for (const x of over) reasons.set(x.v.key, 'over-budget');
  const warnings = [];
  if (over.length) warnings.push(`over-budget: ${selected.length} of ${ordered.length} draftable cases selected; raise budget.maxCases to draft the rest`);
  for (const x of selected) if (x.c.residue) warnings.push(`${x.c.caseId}: ${x.c.residue}`);
  const cases = selected.map(x => ({ ...x.c, rank: x.rank }));
  const caseOf = new Map(cases.map(c => [c.key, c.caseId]));
  const observerScope = sha256(canonical({ observers: b.observers, effects: b.effects }));
  const body = { schema: WRITE_PLAN_SCHEMA, confirmed: false, application: statement.application, statementId: statement.statementId, matrixIds: inventory.matrixIds,
    bindingDigest: b.bindingDigest, inventoryDigest: inventoryDigest(inventory), observerScopeDigest: { P: observerScope, S: observerScope }, budget: b.budget, selectionRule: SELECTION_RULE,
    cases, variants: inventory.variants.map(v => ({ key: v.key, stated: v.stated, reason: reasons.get(v.key) ?? null, ...(caseOf.has(v.key) ? { caseId: caseOf.get(v.key) } : {}) })), warnings };
  return { ...body, planId: sha256(canonical(body)) };
}

export function verifyPlanId(plan) {
  if (plan === null || typeof plan !== 'object' || typeof plan.planId !== 'string') return false;
  const { planId, ...body } = plan;
  return plan.schema === WRITE_PLAN_SCHEMA && planId === sha256(canonical(body));
}

// Accounting input for a plan (read by the coverage accounting): one cell per variant (with the plan's
// reason), and one drafted, unconfirmed case per case.
export function planAccounting(plan, inventory) {
  const reasonOf = new Map(plan.variants.map(v => [v.key, v.reason]));
  const cells = inventoryCells(inventory).map(c => { const r = reasonOf.get(c.key); const { reason: _r, ...rest } = c; return { ...rest, ...(r ? { reason: r } : {}) }; });
  return { cells, cases: plan.cases.map(c => ({ caseId: c.caseId, key: c.key, confirmed: false, vehicle: c.vehicle, artifactDigest: null, contextId: null })) };
}
