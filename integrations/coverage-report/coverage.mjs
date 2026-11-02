// Coverage report: which actor-action-object-surface cells an
// application has, what the stated policy says about each, and which of them the compiled suite
// actually drafts a check for, on both the forbidden and the allowed side. Presentation only:
// it never feeds a verdict, a count, compareRuns, a gate outcome or any identity hash. It is not
// a ledger (integrations/ledger/ is the evidence-ledger workstream).
//
// Inputs, all read, never written:
//   - an inventory (scopehaven-coverage-inventory/1): the operations the application exposes, its
//     tenants and roles, which roles have a user in each tenant, its datastores and which tenant
//     owns each fixture object. Route tables, schemas and tool manifests belong here: inventory.
//   - a stated policy contract (scopehaven-coverage-contract/1): who may do what. Intent comes from a
//     stated contract, never from the implementation under test; a contract whose
//     basis is the application's own declarations, and checks drafted by policy import, are reported
//     with that warning.
//   - a validated target profile (its actors, checks, requiredControlIds and observers), and
//     optionally the exported suite's check ids, to reconcile against.
// No row carries a severity: a coverage cell is about whether a check exists, not how bad a miss is.
import { compareRuns } from '../../src/runner.mjs';
import { contractDigest, ASSERTION_SCHEMA_VERSION, HTTP_CHECK_METHODS } from '../../src/contracts.mjs';
import { CONTROL_CUSTODY_LIMIT } from '../../src/custody.mjs';
import { validateRun } from '../regression-gate/gate.mjs';

export const INVENTORY_SCHEMA = 'scopehaven-coverage-inventory/1';
export const CONTRACT_SCHEMA = 'scopehaven-coverage-contract/1';
export const COVERAGE_SCHEMA = 'scopehaven-coverage-report/1';
// What a profile check can send today: the HTTP connector's own method set (src/contracts.mjs), never a copy
// that can fall behind it. A sequence can send more.
export const CONNECTOR_METHODS = HTTP_CHECK_METHODS;
export const MARKS = Object.freeze(['drafted', 'stated-only', 'unstated', 'needs-actor', 'not-judgeable', 'unreachable']);
// The held-out bar: an application with more than this fraction of its reachable cells not judgeable fails. The report
// computes the fraction for whatever application it is given; whether that application is in the holdout pool is not known here.
export const NOT_JUDGEABLE_BAR = 0.5;
// compareRuns' stable identity keys (src/runner.mjs). A test pins this list against compareRuns' own reasons.
export const COMPARISON_KEYS = Object.freeze(['schemaVersion', 'applicationId', 'suiteId', 'suiteHash', 'policyHash', 'fixtureHash', 'fixtureVersion', 'adapterVersion',
  'evaluatorHash', 'runtimeMode', 'evidenceOrigin', 'profileHash', 'assertionSchemaVersion', 'contextId']);
export const COVERAGE_NOTE = 'Coverage, not findings: a drafted cell has a check, not a verdict, and no row carries a severity. A finding count, when a run is given, comes from that run\'s own grading and is printed beside the not-judgeable count, never added to it.';
export const DECLARED_INTENT_WARNING = 'The stated intent is read from the application\'s own declarations: a defect the declaration shares cannot show up as a miss.';
// What the report reads and does: it observes nothing itself.
export const COVERAGE_SCOPE = 'Scope: computed only from the given inventory, contract, profile and, when given, exported suite and stored runs; it sends no request and observes nothing, so it says which cells have a check, not what the application does.';
// Run row statuses a stored HTTP run can carry (src/http-connector.mjs counts).
export const RUN_STATUSES = Object.freeze(['pass', 'fail', 'inconclusive', 'error', 'not_applicable']);
// Stored runs whose rows this report can read: only those the shared HTTP validator recomputes.
export const RUN_ORIGINS = Object.freeze(['local-http-response']);
export const POLICY_IMPORT_WARNING = 'These checks were drafted by policy import from the application\'s own declarations: a defect the declaration shares cannot show up as a miss, and a cell the declarations leave undeclared never became a check (policy import: "undeclared never becomes deny").';

const ANONYMOUS = 'anonymous';
// An operation anyone may call without a session has one cell per caller class, not one per role and tenant.
const SIGNED_IN = 'signed-in';
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const TABLE_OBSERVERS = ['sqlite-snapshot', 'pg-snapshot', 'mysql-snapshot'];
const fail = message => { throw new Error(`coverage-report: ${message}`); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const strings = (value, label) => { if (!Array.isArray(value) || !value.every(v => typeof v === 'string' && v.length)) fail(`${label} lists non-empty strings`); return value; };
const requestOp = op => (op.reach ?? 'request') === 'request';
const pathsOf = op => op.paths ?? [op.path];
const decoded = value => { try { return decodeURIComponent(value); } catch { return value; } };
// Own keys only: an id or name such as "constructor" or "__proto__" never resolves to a built-in.
const own = (map, key) => (map !== null && typeof map === 'object' && Object.hasOwn(map, key) ? map[key] : undefined);
// One rule for what an allowed-use control is: a check the profile gives severity "control".
const isControl = check => check?.severity === 'control';

// Path templates: literal segments and ':name' parameters, matched with or without one trailing slash.
function parseTemplate(template, label) {
  if (typeof template !== 'string' || !template.startsWith('/')) fail(`${label}: a path template starts with "/"`);
  const params = [];
  let literals = 0;
  const source = template.split('/').slice(1).map(part => {
    if (part.startsWith(':')) {
      const name = part.slice(1);
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || params.includes(name)) fail(`${label}: parameters are distinct ":name" segments`);
      params.push(name);
      return `/(?<${name}>[^/]+)`;
    }
    if (/[{}*]/.test(part)) fail(`${label}: write a parameter as ":name"; "{name}" and wildcards are not supported`);
    if (part) literals++;
    return `/${part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`;
  }).join('');
  return { regex: new RegExp(`^${source === '/' ? '' : source}/?$`), params, literals };
}

export function validateInventory(inv) {
  if (!plain(inv) || inv.schema !== INVENTORY_SCHEMA) fail(`the inventory must have schema ${INVENTORY_SCHEMA}`);
  if (typeof inv.applicationId !== 'string' || !inv.applicationId) fail('the inventory names its applicationId');
  const tenants = strings(inv.tenants, 'tenants'), roles = strings(inv.roles, 'roles');
  if (roles.includes(ANONYMOUS) || roles.includes(SIGNED_IN)) fail(`"${ANONYMOUS}" and "${SIGNED_IN}" are caller classes, not roles; do not list them`);
  if (!Array.isArray(inv.operations) || !inv.operations.length) fail('the inventory lists its operations');
  const datastores = new Set();
  for (const d of inv.datastores ?? []) { if (!plain(d) || typeof d.name !== 'string' || !d.name || datastores.has(d.name)) fail('datastores are { name } with distinct names'); datastores.add(d.name); }
  const ids = new Set();
  for (const op of inv.operations) {
    if (!plain(op) || typeof op.id !== 'string' || !op.id || ids.has(op.id)) fail(`operation ids are unique non-empty strings (${JSON.stringify(op?.id)})`);
    ids.add(op.id);
    if (typeof op.surface !== 'string' || !op.surface) fail(`${op.id}: names its surface`);
    if (!['none', 'session'].includes(op.auth)) fail(`${op.id}: auth is "none" or "session"`);
    if (typeof op.tenantScoped !== 'boolean') fail(`${op.id}: tenantScoped is true or false`);
    if (op.object !== undefined && op.object !== null && (typeof op.object !== 'string' || !op.object)) fail(`${op.id}: object names a fixture object type`);
    if (op.writes !== undefined && !(Array.isArray(op.writes) && op.writes.every(store => datastores.has(store)))) fail(`${op.id}: writes lists declared datastores`);
    if (requestOp(op)) {
      if (!METHODS.includes(op.method)) fail(`${op.id}: a request operation's method is one of ${METHODS.join(', ')}, in upper case`);
      const templates = pathsOf(op).map(p => parseTemplate(p, op.id));
      if (op.addressable !== undefined || op.via !== undefined) fail(`${op.id}: addressable and via belong to model-turn operations`);
      const refs = op.refs ?? [];
      if (!Array.isArray(refs) || !refs.every(r => plain(r) && ['query', 'body'].includes(r.in) && typeof r.field === 'string' && r.field && typeof r.object === 'string' && r.object)) fail(`${op.id}: refs are { in: "query" | "body", field, object }`);
      if (refs.some(r => r.in === 'body') && !['POST', 'PUT', 'PATCH'].includes(op.method)) fail(`${op.id}: a body reference needs POST, PUT or PATCH`);
      if (op.tenantScoped) for (const t of templates.filter(t => t.params.length)) {
        if (op.idParam === undefined && t.params.length > 1) fail(`${op.id}: a template with several parameters names its idParam`);
        if (op.idParam !== undefined && !t.params.includes(op.idParam)) fail(`${op.id}: idParam ${JSON.stringify(op.idParam)} is not a parameter of every template`);
        if (!op.object) fail(`${op.id}: names the object its path parameter refers to`);
      }
    } else if (op.reach === 'model-turn') {
      if (op.tenantScoped && typeof op.addressable !== 'boolean') fail(`${op.id}: a tenant-scoped model-turn operation says whether it takes an object id (addressable)`);
      if (op.addressable && !op.object) fail(`${op.id}: an addressable model-turn operation names its object`);
      if (op.refs !== undefined || op.idParam !== undefined) fail(`${op.id}: refs and idParam belong to request operations`);
    } else fail(`${op.id}: reach is "request" or "model-turn"`);
  }
  for (const op of inv.operations) if (op.via !== undefined && !inv.operations.some(o => o.id === op.via && requestOp(o))) fail(`${op.id}: via names a request operation of this inventory`);
  for (const [tenant, members] of Object.entries(inv.members ?? {})) { if (!tenants.includes(tenant)) fail(`members names an undeclared tenant ${tenant}`); strings(members, `members.${tenant}`); }
  for (const [type, owners] of Object.entries(inv.objects ?? {})) { if (!plain(owners)) fail(`objects.${type} maps ids to tenants`); for (const owner of Object.values(owners)) if (!tenants.includes(owner)) fail(`objects.${type} names an undeclared tenant ${owner}`); }
  return inv;
}

export function validateContract(contract, inv) {
  if (!plain(contract) || contract.schema !== CONTRACT_SCHEMA) fail(`the contract must have schema ${CONTRACT_SCHEMA}`);
  if (contract.applicationId !== inv.applicationId) fail('the contract and the inventory name the same application');
  if (!['stated-policy', 'app-declaration'].includes(contract.basis)) fail('the contract basis is "stated-policy" or "app-declaration"');
  if (contract.crossTenant !== 'deny') fail('crossTenant is "deny": no other cross-tenant rule is supported');
  const ops = new Set(inv.operations.map(op => op.id)), seen = new Set();
  for (const rule of contract.rules ?? []) {
    if (!plain(rule) || !ops.has(rule.operation) || seen.has(rule.operation)) fail(`each rule names one inventory operation once (${JSON.stringify(rule?.operation)})`);
    seen.add(rule.operation);
    if (rule.allow !== 'anyone' && !(Array.isArray(rule.allow) && rule.allow.every(r => inv.roles.includes(r)))) fail(`${rule.operation}: allow is "anyone" or a list of inventory roles`);
    if (!(rule.conditional ?? []).every(r => Array.isArray(rule.allow) && rule.allow.includes(r))) fail(`${rule.operation}: a conditional role must also be allowed`);
  }
  return contract;
}

// A tenant-scoped operation a caller can point at another tenant's object has a cross-tenant cell: an id in its path, an
// object id in its query or body (refs), or a model-turn tool the inventory marks addressable. A plain listing, a search
// or the caller's own record has none; a leak through it is checked on the own cell.
const pathAddressable = op => pathsOf(op).some(p => p.includes('/:'));
const addressable = op => op.tenantScoped && (requestOp(op) ? pathAddressable(op) || (op.refs ?? []).length > 0 : op.addressable === true);
const objectTypes = op => [...(op.object && (requestOp(op) ? pathAddressable(op) : op.addressable) ? [op.object] : []), ...(op.refs ?? []).map(r => r.object)];
function fieldOf(check, ref) {
  if (ref.in === 'query') return new URLSearchParams(check.path.split('?')[1] ?? '').get(ref.field) ?? undefined;
  const value = own(check.body, ref.field);
  return value === undefined || value === null ? undefined : String(value);
}

// The operation a request names: the most specific matching template (more literal segments, then fewer parameters).
// Two different operations matching equally well is an ambiguity, not a placement.
function matchOperation(check, matchers) {
  const path = check.path.split('?')[0];
  const hits = matchers.filter(m => m.method === check.method && m.regex.test(path)).sort((a, b) => b.literals - a.literals || a.params.length - b.params.length);
  if (!hits.length) return { reason: 'operation-not-in-inventory' };
  if (hits.length > 1 && hits[1].op !== hits[0].op && hits[1].literals === hits[0].literals && hits[1].params.length === hits[0].params.length) return { reason: 'operation-ambiguous' };
  return { hit: hits[0], groups: hits[0].regex.exec(path).groups ?? {} };
}

const anonymousActor = actor => actor.credentialEnv === undefined && actor.credentialCookie === undefined;
const collapsed = (op, rule) => op.auth === 'none' && !op.tenantScoped && rule?.allow === 'anyone';

// The cell a check exercises, or the reason it fits none.
function placeCheck(check, target, inv, matchers, rules) {
  const actor = own(target.actors, check.actorId);
  if (!plain(actor)) return { reason: 'unknown-actor' };
  const anonymous = anonymousActor(actor);
  if (!anonymous && (typeof actor.role !== 'string' || !inv.roles.includes(actor.role))) return { reason: 'actor-role-not-in-inventory' };
  const tenant = anonymous ? null : actor.tenantId ?? null;
  if (!anonymous && !inv.tenants.includes(tenant)) return { reason: 'actor-tenant-not-in-inventory' };
  const matched = matchOperation(check, matchers);
  if (!matched.hit) return { reason: matched.reason };
  const { op } = matched.hit;
  if (collapsed(op, rules.get(op.id))) return { op, key: cellKey(anonymous ? ANONYMOUS : SIGNED_IN, null, op.surface, op.id, 'none') };
  let scope = 'none';
  if (!anonymous && op.tenantScoped) {
    // The objects the request names: the id in its path (the idParam, or the template's only parameter) and its refs.
    const named = [];
    const param = op.idParam ?? (matched.hit.params.length === 1 ? matched.hit.params[0] : undefined);
    if (param !== undefined && matched.groups[param] !== undefined) named.push({ object: op.object, id: decoded(matched.groups[param]) });
    for (const ref of op.refs ?? []) { const id = fieldOf(check, ref); if (id !== undefined) named.push({ object: ref.object, id }); }
    const owners = named.map(({ object, id }) => own(own(inv.objects, object), id));
    if (owners.some(owner => owner === undefined)) return { reason: 'object-owner-unknown' };
    scope = owners.some(owner => owner !== tenant) ? 'cross' : 'own';
  }
  return { op, key: cellKey(anonymous ? ANONYMOUS : actor.role, tenant, op.surface, op.id, scope) };
}
const cellKey = (role, tenant, surface, operation, scope) => JSON.stringify([role, tenant, surface, operation, scope]);

function statedFor(rule, role, scope, contract) {
  if (!rule) return null;
  if (role === ANONYMOUS || role === SIGNED_IN) return rule.allow === 'anyone' ? 'allow' : 'deny';
  if (scope === 'cross') return contract.crossTenant;
  if (rule.allow !== 'anyone' && !rule.allow.includes(role)) return 'deny';
  return (rule.conditional ?? []).includes(role) ? 'conditional' : 'allow';
}

// The coverage report. suiteCheckIds: the exported suite's check ids (defaults to the profile's checks).
export function coverageReport({ inventory, contract, target, suiteCheckIds = null, connectorMethods = CONNECTOR_METHODS }) {
  const inv = validateInventory(inventory);
  validateContract(contract, inv);
  if (!plain(target) || !Array.isArray(target.checks)) fail('a target profile with checks is required');
  const rules = new Map((contract.rules ?? []).map(rule => [rule.operation, rule]));
  const matchers = inv.operations.filter(requestOp).flatMap(op => pathsOf(op).map(p => ({ op, method: op.method, ...parseTemplate(p, op.id) })));
  // Request operations a model turn starts from, and the tools reached through each.
  const toolsVia = new Map();
  for (const op of inv.operations) if (op.via) toolsVia.set(op.via, [...(toolsVia.get(op.via) ?? []), op.id]);
  // Who the profile can act as: (role, tenant) pairs, an actor without credentials, and any signed-in actor.
  const actors = Object.values(target.actors ?? {}).filter(plain);
  const actorCells = new Set(actors.map(a => anonymousActor(a) ? JSON.stringify([ANONYMOUS, null]) : JSON.stringify([a.role, a.tenantId ?? null])));
  if (actors.some(a => !anonymousActor(a))) actorCells.add(JSON.stringify([SIGNED_IN, null]));
  // Every cell: each operation for each role in each tenant (own and, where a caller can name another tenant's object,
  // cross), and the anonymous caller. An operation anyone may call without a session has an anonymous and a signed-in cell.
  const cells = new Map();
  const addCell = (op, role, tenant, scope) => cells.set(cellKey(role, tenant, op.surface, op.id, scope), { role, tenant, surface: op.surface, operation: op.id, scope, stated: statedFor(rules.get(op.id), role, scope, contract), drafts: [], op });
  for (const op of inv.operations) {
    addCell(op, ANONYMOUS, null, 'none');
    if (collapsed(op, rules.get(op.id))) { addCell(op, SIGNED_IN, null, 'none'); continue; }
    for (const role of inv.roles) for (const tenant of inv.tenants) for (const scope of !op.tenantScoped ? ['none'] : addressable(op) ? ['own', 'cross'] : ['own']) addCell(op, role, tenant, scope);
  }
  // Each check of the compiled suite lands in exactly one cell, is declared not applicable, or is listed outside the
  // inventory with its reason. An id the suite lists twice is placed once and listed as a duplicate.
  const suiteIds = suiteCheckIds ?? target.checks.map(c => c.id);
  const checksById = new Map(target.checks.map(c => [c.id, c]));
  const outsideInventory = [], declaredNotApplicable = [], duplicates = [], seen = new Set();
  let draftedChecks = 0;
  for (const id of suiteIds) {
    if (seen.has(id)) { duplicates.push(id); continue; }
    seen.add(id);
    const check = checksById.get(id);
    if (!check) { outsideInventory.push({ checkId: id, reason: 'not-in-profile' }); continue; }
    if (check.applicability?.applies === false) { declaredNotApplicable.push(id); continue; }
    const placed = placeCheck(check, target, inv, matchers, rules);
    if (!placed.key) { outsideInventory.push({ checkId: id, reason: placed.reason }); continue; }
    draftedChecks++;
    cells.get(placed.key).drafts.push({ checkId: id, side: isControl(check) ? 'allowed' : 'forbidden', ...(toolsVia.has(placed.op.id) ? { throughModelTurn: true } : {}) });
  }
  // Which tools a check sent through a model turn reaches is the model's choice, so the tool cells stay not judgeable;
  // each names the checks of its role and tenant that could have reached it.
  const probes = new Map();
  for (const cell of cells.values()) for (const d of cell.drafts) if (d.throughModelTurn) for (const tool of toolsVia.get(cell.operation)) {
    const k = JSON.stringify([tool, cell.role, cell.tenant]); probes.set(k, [...(probes.get(k) ?? []), d.checkId]);
  }
  const memberRoles = inv.members ? new Set(Object.values(inv.members).flat()) : null;
  const otherTenantObject = (op, tenant) => objectTypes(op).some(type => Object.values(own(inv.objects, type) ?? {}).some(owner => owner !== tenant));
  // Marks: drafted, then unreachable, then not judgeable, then needs an actor, then stated-only or unstated.
  const rows = [...cells.values()].map(({ op, ...cell }) => {
    let mark, reason = null;
    const probedBy = probes.get(JSON.stringify([cell.operation, cell.role, cell.tenant]));
    if (cell.drafts.length) mark = 'drafted';
    else if (cell.role === SIGNED_IN && memberRoles && !memberRoles.size) { mark = 'unreachable'; reason = 'no-user-in-any-tenant'; }
    else if (![ANONYMOUS, SIGNED_IN].includes(cell.role) && inv.members && !(own(inv.members, cell.tenant) ?? []).includes(cell.role)) { mark = 'unreachable'; reason = 'no-user-with-this-role-in-this-tenant'; }
    else if (cell.scope === 'cross' && !otherTenantObject(op, cell.tenant)) { mark = 'unreachable'; reason = 'no-other-tenant-object'; }
    else if (!requestOp(op)) { mark = 'not-judgeable'; reason = 'reached-only-through-a-model-turn'; }
    else if (!connectorMethods.includes(op.method)) { mark = 'not-judgeable'; reason = `connector-sends-${connectorMethods.join('-and-').toLowerCase()}-only`; }
    else if (!actorCells.has(JSON.stringify([cell.role, cell.tenant]))) { mark = 'needs-actor'; reason = 'no-actor-for-this-role-and-tenant'; }
    else mark = cell.stated ? 'stated-only' : 'unstated';
    return { ...cell, mark, ...(reason ? { reason } : {}), ...(probedBy && mark === 'not-judgeable' ? { probedThroughModelTurn: probedBy } : {}) };
  });
  // Both directions: a profile check the suite leaves out is listed too, so an edited export never reconciles as equal.
  const missingFromSuite = target.checks.map(c => c.id).filter(id => !seen.has(id));
  const reconciliation = { suiteChecks: suiteIds.length, draftedChecks, declaredNotApplicable, outsideInventory: outsideInventory.length, duplicates, missingFromSuite,
    equal: draftedChecks + declaredNotApplicable.length === suiteIds.length && duplicates.length === 0 && outsideInventory.length === 0 && missingFromSuite.length === 0 };
  const reachable = rows.filter(r => r.mark !== 'unreachable');
  // A side counts its reachable cells; its breakdowns also show unreachable cells, so a tenant or role with none reachable still prints.
  const side = (statedCells, coveredBy) => {
    const cellsOfSide = statedCells.filter(r => r.mark !== 'unreachable');
    const counts = list => { const live = list.filter(r => r.mark !== 'unreachable'); return { cells: live.length, covered: live.filter(coveredBy).length, notJudgeable: live.filter(r => !coveredBy(r) && r.mark === 'not-judgeable').length, needsActor: live.filter(r => !coveredBy(r) && r.mark === 'needs-actor').length, unreachable: list.length - live.length }; };
    // A Map, so a tenant or role named like a built-in ("constructor") is grouped like any other.
    const tally = key => { const groups = new Map(); for (const r of statedCells) { const k = String(r[key]); groups.set(k, [...(groups.get(k) ?? []), r]); } return Object.fromEntries([...groups].map(([k, list]) => [k, counts(list)])); };
    // The plan's role-action-surface count: a (role, operation, surface) is covered when any of its tenant and scope cells is.
    const triples = new Map();
    for (const r of cellsOfSide) { const k = JSON.stringify([r.role, r.operation, r.surface]); triples.set(k, triples.get(k) === true || coveredBy(r)); }
    const { unreachable, ...total } = counts(statedCells);
    return { ...total, unreachable, roleActionSurface: { cells: triples.size, covered: [...triples.values()].filter(Boolean).length }, byRole: tally('role'), bySurface: tally('surface'), byTenant: tally('tenant') };
  };
  const permitted = r => r.stated === 'allow' || r.stated === 'conditional';
  // Allowed side: N of M legitimate cells have a twin (an allowed-use control drafted to exercise them).
  const allowed = side(rows.filter(permitted), r => r.drafts.some(d => d.side === 'allowed'));
  // Forbidden side: N of M stated-deny cells have a forbidden check.
  const forbidden = side(rows.filter(r => r.stated === 'deny'), r => r.drafts.some(d => d.side === 'forbidden'));
  const draftsWhere = (test, keep) => rows.filter(test).flatMap(r => r.drafts.filter(keep).map(d => d.checkId));
  const marks = Object.fromEntries(MARKS.map(m => [m, rows.filter(r => r.mark === m).length]));
  const reasons = {};
  for (const r of rows) if (r.reason) reasons[r.reason] = (reasons[r.reason] ?? 0) + 1;
  const policyImported = target.checks.filter(c => c.category === 'Declared policy').map(c => c.id);
  return {
    schema: COVERAGE_SCHEMA, applicationId: inv.applicationId, targetId: target.id ?? null,
    contractBasis: contract.basis, ...(contract.basis === 'app-declaration' ? { warning: DECLARED_INTENT_WARNING } : {}),
    ...(policyImported.length ? { policyImport: { checks: policyImported, warning: POLICY_IMPORT_WARNING } } : {}),
    reconciliation, outsideInventory, marks, reasons,
    notJudgeable: { cells: marks['not-judgeable'], needsActor: marks['needs-actor'], reachable: reachable.length, bar: NOT_JUDGEABLE_BAR,
      fraction: reachable.length ? marks['not-judgeable'] / reachable.length : null, fractionWithNeedsActor: reachable.length ? (marks['not-judgeable'] + marks['needs-actor']) / reachable.length : null },
    allowedSide: allowed, forbiddenSide: forbidden,
    // Forbidden checks on permitted cells (a leak through a listing, a boundary on a conditional approval): counted, never as cell coverage.
    forbiddenChecksOnPermittedCells: draftsWhere(r => r.mark !== 'unreachable' && permitted(r), d => d.side === 'forbidden' && !d.throughModelTurn),
    // Allowed-use controls on stated-deny cells: the contract and the profile disagree about that cell.
    allowedControlsOnDeniedCells: draftsWhere(r => r.stated === 'deny', d => d.side === 'allowed'),
    // Checks on cells no rule covers: they count on neither side.
    draftsOnUnstatedCells: draftsWhere(r => r.stated === null, () => true),
    modelTurnChecks: rows.flatMap(r => r.drafts.filter(d => d.throughModelTurn).map(d => ({ checkId: d.checkId, side: d.side, role: r.role, tenant: r.tenant, operation: r.operation, scope: r.scope, tools: toolsVia.get(r.operation) }))),
    unstatedOperations: inv.operations.filter(op => !rules.has(op.id)).map(op => op.id),
    datastores: datastoreCoverage(inv, target, rows),
    cells: rows, note: COVERAGE_NOTE, scope: COVERAGE_SCOPE,
  };
}

// Per datastore: which declared observers read its table. A store no table-mapped observer reads leaves backend effects
// there inconclusive unless an observer of the application's own record (an audit endpoint or log) decides them; those
// observers are listed apart, since they are not mapped to a table here.
export function datastoreCoverage(inv, target, rows = null) {
  const by = new Map((inv.datastores ?? []).map(d => [d.name, []]));
  const otherObservers = [];
  for (const o of target.observers ?? []) {
    if (TABLE_OBSERVERS.includes(o.type)) { for (const t of o.tables ?? []) by.get(t.table)?.push({ observer: o.id ?? null, type: o.type, mode: 'snapshot' }); }
    else if (o.type === 'sqlite-audit' && o.audit?.table) by.get(o.audit.table)?.push({ observer: o.id ?? null, type: o.type, mode: 'audit-table' });
    else otherObservers.push({ observer: o.id ?? null, type: o.type ?? null });
  }
  const writesDeclared = inv.operations.some(op => Array.isArray(op.writes));
  const draftedOn = new Map();
  for (const r of rows ?? []) if (r.drafts.length) draftedOn.set(r.operation, (draftedOn.get(r.operation) ?? 0) + r.drafts.length);
  const result = [...by.entries()].map(([name, observers]) => {
    const writers = inv.operations.filter(op => (op.writes ?? []).includes(name)).map(op => op.id);
    return { name, observed: observers.length > 0, observers, ...(writesDeclared ? { writtenBy: writers, draftedChecksOnWriters: writers.reduce((n, id) => n + (draftedOn.get(id) ?? 0), 0) } : {}) };
  });
  const onlyUnobserved = op => op.writes?.length > 0 && op.writes.every(store => !by.get(store).length);
  return { total: result.length, observed: result.filter(r => r.observed).length, writesDeclared,
    ...(writesDeclared ? { draftedChecksWritingOnlyUnobservedStores: inv.operations.filter(onlyUnobserved).reduce((n, op) => n + (draftedOn.get(op.id) ?? 0), 0) } : {}),
    otherObservers, rows: result };
}

const storedRun = run => (plain(run) && plain(run.core) ? run.core : run);
const runIdOf = run => run.id ?? run.runId;

// What a stored run of this profile found, from its own grading: shown beside the not-judgeable count, never added to it.
// The run must be of an evidence origin this report reads (HTTP), be of this target and carry exactly the suite's check
// ids, once each, with known statuses; a row reads not applicable exactly when its profile check declares applies: false;
// and the run must pass the regression gate's own run validator (validateRun: the shared HTTP evidence validator plus its
// shape and count checks). Whether a row is a control comes from the profile, never from the row. A profile digest that
// moved is reported.
export function runFindings(input, target, suiteIds = target.checks.map(c => c.id)) {
  const run = storedRun(input);
  if (!plain(run) || !Array.isArray(run.results) || !runIdOf(run)) fail('a stored run with its id and results is required');
  if (!RUN_ORIGINS.includes(run.evidenceOrigin)) fail(`the run's evidence origin ${JSON.stringify(run.evidenceOrigin ?? null)} is not one this report reads (${RUN_ORIGINS.join(', ')})`);
  // This report's own checks come first, so each refusal names its reason; the shared validator then recomputes the evidence.
  if (run.targetId !== target.id) fail(`the run is of target ${JSON.stringify(run.targetId)}, not ${JSON.stringify(target.id)}`);
  const ids = run.results.map(r => r?.id);
  if (new Set(ids).size !== ids.length) fail('the run lists a check more than once');
  const expected = [...new Set(suiteIds)].sort(), sorted = [...ids].sort();
  if (sorted.length !== expected.length || sorted.some((id, i) => id !== expected[i])) fail('the run\'s results are not exactly this suite\'s checks');
  const unknown = run.results.filter(r => !RUN_STATUSES.includes(r?.status)).map(r => r?.id);
  if (unknown.length) fail(`unknown run statuses for ${unknown.join(', ')} (known: ${RUN_STATUSES.join(', ')})`);
  const byId = new Map(target.checks.map(c => [c.id, c]));
  // A row reads not applicable exactly when the profile declares its check not applicable, so a failing row relabelled
  // not_applicable is refused here rather than counted.
  const misread = run.results.filter(r => (r.status === 'not_applicable') !== (byId.get(r.id)?.applicability?.applies === false)).map(r => r.id);
  if (misread.length) fail(`run rows whose not-applicable status disagrees with the profile's applicability: ${misread.join(', ')}`);
  try { validateRun(run); } catch (error) { fail(`the run does not pass the run validator (${[error.code, error.detail, error.message].filter(Boolean).join(': ')})`); }
  const control = r => isControl(byId.get(r.id));
  const count = test => run.results.filter(test).length;
  // A control pass decided by records the application can write still counts as passed, with custody's stated limit.
  const appRecordControls = run.results.filter(r => control(r) && r.status === 'pass' && (r.assertions ?? []).some(a => a.custody === 'subject-writable')).map(r => r.id);
  const profileMatches = run.profileHash === contractDigest(target);
  return { runId: runIdOf(run), createdAt: run.createdAt ?? null, profileMatches,
    findings: count(r => r.status === 'fail' && !control(r)), failedControls: count(r => r.status === 'fail' && control(r)),
    inconclusive: count(r => r.status === 'inconclusive'), errors: count(r => r.status === 'error'), notApplicable: count(r => r.status === 'not_applicable'), passed: count(r => r.status === 'pass'),
    ...(appRecordControls.length ? { controlPassesOnAppRecords: appRecordControls, controlLimit: CONTROL_CUSTODY_LIMIT } : {}),
    ...(profileMatches ? {} : { warning: `This run's profile digest differs from the profile's current digest (the run records assertion schema ${run.assertionSchemaVersion ?? 'none'}; this code is ${ASSERTION_SCHEMA_VERSION}), so its rows were graded under another identity.` }) };
}

// Stored runs compare only within one application and target, and only where compareRuns would compare them. A run that is
// not comparable with the one before it starts a new series, or continues an earlier series it is comparable with; the
// operator is told which, rather than shown one broken line. Full stored runs are compared with compareRuns itself;
// summaries without results (GET /api/history) are compared on compareRuns' identity keys only, and the report says so.
export function runComparability(runs, { target = null } = {}) {
  if (!Array.isArray(runs)) fail('runs is a list of stored runs');
  const all = runs.map(storedRun);
  if (!all.every(r => plain(r) && typeof runIdOf(r) === 'string' && runIdOf(r) && typeof r.createdAt === 'string' && Number.isFinite(Date.parse(r.createdAt)))) fail('each stored run names its id and a createdAt date');
  const mine = target ? all.filter(r => r.targetId === target.id) : all;
  const bases = new Set();
  const pair = (a, b) => {
    if (Array.isArray(a.results) && Array.isArray(b.results)) {
      bases.add('compareRuns');
      try { const c = compareRuns(a, b); return { compatible: c.compatible, reasons: c.reasons }; }
      catch { return { compatible: false, reasons: ['compareRuns could not read this pair.'] }; }
    }
    bases.add('identity-keys');
    const reasons = COMPARISON_KEYS.filter(k => a[k] === undefined || b[k] === undefined || a[k] !== b[k]).map(k => `${k} differs or is missing.`);
    if (!Array.isArray(a.requiredControlIds) || !a.requiredControlIds.length || JSON.stringify(a.requiredControlIds) !== JSON.stringify(b.requiredControlIds)) reasons.push('Required permitted-use controls differ or are missing.');
    return { compatible: reasons.length === 0, reasons };
  };
  const partitions = new Map();
  for (const run of mine) { const k = JSON.stringify([run.applicationId ?? null, run.targetId ?? null]); partitions.set(k, [...(partitions.get(k) ?? []), run]); }
  const series = [], breaks = [];
  for (const list of partitions.values()) {
    const local = [];
    let current = null;
    // Ordered by time (parsed, so precision and offsets compare correctly), then by id.
    for (const run of [...list].sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt) || runIdOf(a).localeCompare(runIdOf(b)))) {
      const last = current?.runs.at(-1), withLast = last && pair(last, run);
      if (withLast?.compatible) { current.runs.push(run); continue; }
      const earlier = local.find(s => s !== current && pair(s.runs.at(-1), run).compatible);
      if (last) {
        const evaluator = typeof last.evaluatorHash === 'string' && typeof run.evaluatorHash === 'string' && last.evaluatorHash !== run.evaluatorHash ? ` The evaluator identity changed (${last.evaluatorHash.slice(0, 8)} to ${run.evaluatorHash.slice(0, 8)}).` : '';
        const continues = earlier ? runIdOf(earlier.runs.at(-1)) : null;
        breaks.push({ before: runIdOf(last), after: runIdOf(run), reasons: withLast.reasons, continues,
          message: `Run ${runIdOf(run)} is not comparable with run ${runIdOf(last)} before it: ${withLast.reasons.join(' ')}${evaluator} ${continues ? `It is comparable with run ${continues} and continues that earlier series.` : 'A new series starts here; no trend is drawn across this point.'}` });
      }
      current = earlier ?? { runs: [run] };
      if (earlier) earlier.runs.push(run); else { local.push(current); series.push(current); }
    }
  }
  return {
    series: series.map(s => ({ applicationId: s.runs[0].applicationId ?? null, targetId: s.runs[0].targetId ?? null, identity: Object.fromEntries(COMPARISON_KEYS.map(k => [k, s.runs[0][k] ?? null])), runIds: s.runs.map(runIdOf) })),
    breaks, otherTargets: all.length - mine.length, bases: [...bases].sort(),
    ...(bases.has('identity-keys') ? { note: 'Some runs carry no results, so they were compared on compareRuns\' identity keys only: the full comparison (results, actors, effects, controls) was not run, and compareRuns may still refuse a pair shown here as one series.' } : {}),
  };
}

const pct = (n, d) => d ? `${(100 * n / d).toFixed(1)}%` : 'n/a';
const keyLabel = k => k === 'null' ? '(none)' : k;
const extra = v => { const parts = [...(v.notJudgeable ? [`${v.notJudgeable} not judgeable`] : []), ...(v.needsActor ? [`${v.needsActor} need an actor`] : []), ...(v.unreachable ? [`${v.unreachable} unreachable`] : [])]; return parts.length ? ` (${parts.join(', ')})` : ''; };
export function coverageLines(report, { run = null, comparability = null } = {}) {
  const lines = [`Coverage report for ${report.applicationId}${report.targetId ? ` (${report.targetId})` : ''}. ${COVERAGE_NOTE}`, COVERAGE_SCOPE];
  if (report.warning) lines.push(`Warning: ${report.warning}`);
  if (report.policyImport) lines.push(`Warning: ${report.policyImport.checks.length} check${report.policyImport.checks.length === 1 ? '' : 's'} came from policy import (${report.policyImport.checks.join(', ')}). ${report.policyImport.warning}`);
  const r = report.reconciliation, na = r.declaredNotApplicable.length;
  lines.push(`Suite reconciliation: ${r.draftedChecks} drafted${na ? ` and ${na} declared not applicable` : ''} of ${r.suiteChecks} suite checks${r.equal ? ' (equal)' : ''}${r.outsideInventory ? `; outside the inventory: ${report.outsideInventory.map(o => `${o.checkId} (${o.reason})`).join(', ')}` : ''}${r.duplicates.length ? `; listed more than once: ${r.duplicates.join(', ')}` : ''}${r.missingFromSuite.length ? `; profile checks the suite leaves out: ${r.missingFromSuite.join(', ')}` : ''}.`);
  lines.push(`Cells: ${MARKS.map(m => `${report.marks[m]} ${m}`).join(', ')}.${Object.keys(report.reasons).length ? ` Reasons: ${Object.entries(report.reasons).map(([k, v]) => `${k} ${v}`).join(', ')}.` : ''}`);
  const nj = report.notJudgeable;
  lines.push(`Not judgeable: ${nj.cells} of ${nj.reachable} reachable cells (${pct(nj.cells, nj.reachable)}); with the ${nj.needsActor} that need an actor, ${pct(nj.cells + nj.needsActor, nj.reachable)}. C8's held-out validation fails a holdout application above ${nj.bar * 100}%; whether this application is in the holdout pool is not known here.`);
  for (const [label, s] of [['Allowed side: legitimate cells with a twin (an allowed-use control)', report.allowedSide], ['Forbidden side: stated-deny cells with a forbidden check', report.forbiddenSide]]) {
    lines.push(`${label}: ${s.covered} of ${s.cells} (${pct(s.covered, s.cells)}); ${s.notJudgeable} not judgeable, ${s.needsActor} need an actor. By role, operation and surface: ${s.roleActionSurface.covered} of ${s.roleActionSurface.cells}.`);
    for (const [dim, key] of [['role', 'byRole'], ['surface', 'bySurface'], ['tenant', 'byTenant']]) {
      lines.push(`  by ${dim}: ${Object.entries(s[key]).map(([k, v]) => `${keyLabel(k)} ${v.covered}/${v.cells}${extra(v)}`).join(', ') || 'none'}`);
    }
  }
  const list = ids => ids.length ? `: ${ids.join(', ')}` : '';
  lines.push(`Forbidden checks on permitted cells (leaks through permitted actions, boundaries), counted apart from cell coverage: ${report.forbiddenChecksOnPermittedCells.length}${list(report.forbiddenChecksOnPermittedCells)}.`);
  if (report.modelTurnChecks.length) lines.push(`Checks sent through a model turn (which tool they reach is the model's choice, so the tool cells stay not judgeable): ${report.modelTurnChecks.map(m => m.checkId).join(', ')}.`);
  if (report.allowedControlsOnDeniedCells.length) lines.push(`Allowed-use controls on stated-deny cells (the contract and the profile disagree): ${report.allowedControlsOnDeniedCells.join(', ')}.`);
  if (report.draftsOnUnstatedCells.length) lines.push(`Checks on cells no rule covers (counted on neither side): ${report.draftsOnUnstatedCells.join(', ')}.`);
  if (report.unstatedOperations.length) lines.push(`Operations with no rule in this contract (whether the application guards them is not observed here; the CWE-862 shape to look for): ${report.unstatedOperations.join(', ')}.`);
  const ds = report.datastores;
  lines.push(`Datastores with a table-mapped observer: ${ds.observed} of ${ds.total}${ds.total ? `: ${ds.rows.map(row => `${row.name} ${row.observed ? row.observers.map(o => o.mode).join('+') : '(none)'}`).join(', ')}` : ''}.`);
  if (ds.otherObservers.length) lines.push(`Observers of the application's own record, not mapped to a datastore here: ${ds.otherObservers.map(o => `${o.observer ?? '(unnamed)'} (${o.type})`).join(', ')}.`);
  lines.push(ds.writesDeclared
    ? `Drafted checks on operations that write only stores no table-mapped observer reads: ${ds.draftedChecksWritingOnlyUnobservedStores}${ds.otherObservers.length ? ' (an application-record observer above may still decide them)' : '; their backend effects can only read inconclusive'}.`
    : 'Which operations write which datastore is not declared in this inventory.');
  if (run) {
    lines.push(`Run ${run.runId}, from its own grading: ${run.findings} findings, ${run.failedControls} failed controls, ${run.inconclusive} inconclusive, ${run.errors} errors, ${run.notApplicable} not applicable, ${run.passed} passed. The ${nj.cells} not-judgeable cells are a separate number and are not added to these.`);
    if (run.controlPassesOnAppRecords) lines.push(`Control passes decided by records the application can write (${run.controlPassesOnAppRecords.join(', ')}): ${run.controlLimit}`);
    if (run.warning) lines.push(`Warning: ${run.warning}`);
  }
  for (const b of comparability?.breaks ?? []) lines.push(b.message);
  if (comparability?.note) lines.push(comparability.note);
  return lines;
}
