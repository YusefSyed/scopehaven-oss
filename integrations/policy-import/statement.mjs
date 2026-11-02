// Operator policy statement (goal 03, scopehaven-policy-statement/1): what the operator says should happen, per
// role, resource and action. It is the only source of intent (R9). A matrix is inventory, citations and agreement
// data: it can propose candidates, and a named person can adopt one of its declarations (counted apart, with the R9
// warning), but a matrix never states a rule by itself, and an undeclared cell never becomes deny. A deny for what
// the statement leaves unlisted comes only from an explicit defaults.unlisted: "deny" (stated-default).
// Sealed with the matrix module's canonical sha256, which detects careless edits only: anyone can recompute it.
// Local files only; nothing here reads an application or sends a request.
import { canonical, cellKey, DECISIONS as MATRIX_DECISIONS, isMatrix, sha256 } from './matrix.mjs';

export const STATEMENT_SCHEMA = 'scopehaven-policy-statement/1';
export const RULE_DECISIONS = Object.freeze(['allow', 'deny']);
export const RELATIONS = Object.freeze(['any', 'own', 'other-same-role', 'other-role', 'cross-tenant']);
export const CREATOR_RULES = Object.freeze(['actor-must-differ', 'actor-must-equal']);
export const CONFIDENCE = Object.freeze(['stated', 'stated-default', 'adopted-declaration']);
export const LIFECYCLE_SUBJECTS = Object.freeze(['actor', 'role', 'tenant']);
// The rule id a stated-default decision names: the statement's own defaults, never a matrix.
export const DEFAULT_RULE_ID = 'defaults.unlisted';
// An adopted declaration keeps the importer's category, so the coverage report shows its declared-intent warning.
export const ADOPTED_CATEGORY = 'Declared policy';
export const MAX_CREATORS = 5;
// How the statement reads beside a matrix's declaration for the same cell (checkStatement). A declaration of allow or deny
// covers the whole cell, so every stated part of the cell compares with it: each rule, a limit's over-cap prohibition, a
// lifecycle's after phase, and the rest of the cell the defaults cover.
//   agrees               every stated part matches, and the stated parts cover the whole cell
//   agrees-where-stated  every stated part matches, but part of the cell is unstated (no defaults.unlisted)
//   stated-stricter      some stated part refuses what the declaration allows
//   stated-wider         some stated part allows what the declaration refuses
//                        (against one allow or deny, every disagreeing part disagrees the same way)
//   unresolved           the declaration is conditional and no single stated decision covers the cell: not evaluated
//   declared-only, stated-only, neither: only one side, or neither, says anything about the cell
export const AGREEMENT = Object.freeze(['agrees', 'agrees-where-stated', 'stated-stricter', 'stated-wider', 'unresolved', 'declared-only', 'stated-only', 'neither']);
export const DISAGREEMENTS = Object.freeze(['stated-stricter', 'stated-wider']);

const IDENT = /^[A-Za-z0-9_.-]{1,80}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const STATEMENT_KEYS = ['schema', 'application', 'statedBy', 'statedAt', 'roles', 'tenants', 'sources', 'defaults', 'rules', 'candidates', 'matrices', 'statementId'];
const RULE_KEYS = ['ruleId', 'role', 'resource', 'action', 'relation', 'creators', 'creatorRule', 'state', 'limit', 'lifecycle', 'decision', 'source', 'confidence'];
const CANDIDATE_KEYS = ['candidateId', 'role', 'resource', 'action', 'decision', 'layer', 'basis', 'adoptedFrom'];

const fail = message => { throw new Error(`policy statement: ${message}`); };
const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
// Names as matrices spell them (an OpenAPI role can be "requirement:..."): any text without control characters, and
// never the NUL that cellKey uses as its separator.
const name = (v, max = 200) => typeof v === 'string' && v.length >= 1 && v.length <= max && !/[\u0000-\u001f\u007f]/.test(v);
const onlyKeys = (o, keys, where) => { const extra = Object.keys(o).filter(k => !keys.includes(k)); if (extra.length) fail(`${where} has unknown field${extra.length === 1 ? '' : 's'} ${extra.join(', ')}`); };
const byCode = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
export const candidateIdFor = (matrixId, key) => `C-${sha256(`${matrixId}\u0000${key}`).slice(0, 12).toUpperCase()}`;

function validMatrices(matrices) {
  if (!Array.isArray(matrices)) fail('matrices is a list');
  const byId = new Map();
  for (const m of matrices) {
    if (!isMatrix(m)) fail('a matrix is missing or was edited after import (its matrixId no longer matches)');
    byId.set(m.matrixId, m);
  }
  return byId;
}

// A proposal from the application's own declarations: no rules, only candidates. Each declared allow or deny cell is a
// candidate a named person may adopt; conditional, undeclared and unknown cells are listed as not proposed.
export function proposeStatement({ application, matrices }) {
  if (!name(application, 120)) fail('application names the application');
  const byId = validMatrices(matrices);
  if (!byId.size) fail('propose needs at least one matrix');
  const candidates = [], notProposed = [], warnings = [];
  for (const m of byId.values()) {
    if (m.application !== application) warnings.push(`matrix ${m.matrixId.slice(0, 12)} names application ${m.application}, not ${application}`);
    for (const c of m.cells) {
      if (RULE_DECISIONS.includes(c.decision)) candidates.push({ candidateId: candidateIdFor(m.matrixId, cellKey(c)), role: c.role, resource: c.resource, action: c.action,
        decision: c.decision, layer: m.layer, basis: c.basis, adoptedFrom: { matrixId: m.matrixId, cellKey: cellKey(c) } });
      else notProposed.push({ role: c.role, resource: c.resource, action: c.action, layer: m.layer, decision: c.decision,
        reason: c.decision === 'conditional' ? 'conditional: state the rule and its condition yourself' : `${c.decision}: the application declares nothing to adopt` });
    }
  }
  const roles = [...new Set([...byId.values()].flatMap(m => m.roles))].sort(byCode);
  return { schema: STATEMENT_SCHEMA, application, statedBy: null, statedAt: null, roles, tenants: [], sources: [], defaults: {}, rules: [],
    candidates: candidates.sort((a, b) => byCode(a.candidateId, b.candidateId)), matrices: [...byId.values()].map(m => ({ matrixId: m.matrixId, layer: m.layer, application: m.application })),
    notProposed, warnings,
    note: 'A proposal states nothing. Write rules (confidence "stated", citing your own source), or adopt a candidate as a rule (confidence "adopted-declaration", source { adoptedFrom }), then seal it with a named person.' };
}

function validateRule(r, roles, tenants, sourceIds, matrixById, verifyAdoptions) {
  if (!plain(r)) fail('each rule is an object');
  if (Object.hasOwn(r, 'candidate')) fail(`rule ${r.ruleId ?? '?'} is still a candidate; a candidate never becomes a rule until a person adopts it (confidence "adopted-declaration", source { adoptedFrom })`);
  onlyKeys(r, RULE_KEYS, `rule ${r.ruleId ?? '?'}`);
  if (typeof r.ruleId !== 'string' || !IDENT.test(r.ruleId) || r.ruleId === DEFAULT_RULE_ID) fail(`a rule needs a ruleId (letters, digits, . _ -, at most 80; not "${DEFAULT_RULE_ID}")`);
  const where = `rule ${r.ruleId}`;
  if (!roles.has(r.role)) fail(`${where}: role ${JSON.stringify(r.role)} is not one of the statement's roles`);
  if (!name(r.resource, 400)) fail(`${where}: resource is a name`);
  if (!name(r.action, 40)) fail(`${where}: action is a name`);
  if (!RULE_DECISIONS.includes(r.decision)) fail(`${where}: decision is ${RULE_DECISIONS.join(' or ')} (a conditional grant is stated as rules for its variants)`);
  const relation = r.relation ?? 'any';
  if (!RELATIONS.includes(relation)) fail(`${where}: relation is ${RELATIONS.join(', ')}`);
  if (relation === 'cross-tenant' && tenants.size < 2) fail(`${where}: a cross-tenant rule needs at least two tenants in the statement`);
  if (r.creators !== undefined || r.creatorRule !== undefined) {
    if (!Array.isArray(r.creators) || !r.creators.length || r.creators.length > MAX_CREATORS || new Set(r.creators).size !== r.creators.length || !r.creators.every(c => roles.has(c)))
      fail(`${where}: creators lists 1 to ${MAX_CREATORS} distinct statement roles`);
    if (!CREATOR_RULES.includes(r.creatorRule)) fail(`${where}: creators need a creatorRule (${CREATOR_RULES.join(' or ')})`);
  }
  if (r.state !== undefined && !(typeof r.state === 'string' && IDENT.test(r.state))) fail(`${where}: state is a name`);
  if (r.limit !== undefined) {
    const l = r.limit;
    if (!plain(l)) fail(`${where}: limit is { pointer, cap, unit, inclusive?, roles? }`);
    onlyKeys(l, ['pointer', 'cap', 'unit', 'inclusive', 'roles'], `${where} limit`);
    if (r.decision !== 'allow') fail(`${where}: a limit caps an allowance, so its rule is an allow (over the cap is the prohibition)`);
    if (typeof l.pointer !== 'string' || !/^(\/[^/\u0000-\u001f]+)+$/.test(l.pointer) || l.pointer.length > 200) fail(`${where}: limit.pointer is a JSON pointer such as /amount`);
    if (typeof l.cap !== 'number' || !Number.isFinite(l.cap)) fail(`${where}: limit.cap is a finite number`);
    if (!name(l.unit, 40)) fail(`${where}: limit.unit is a name`);
    // Unstated inclusivity leaves the at-the-cap point unstated; it is never guessed.
    if (l.inclusive !== undefined && typeof l.inclusive !== 'boolean') fail(`${where}: limit.inclusive is true or false, or left out (then at-the-cap stays unstated)`);
    if (l.roles !== undefined && !(Array.isArray(l.roles) && l.roles.length && new Set(l.roles).size === l.roles.length && l.roles.every(x => roles.has(x)))) fail(`${where}: limit.roles lists distinct statement roles`);
  }
  if (r.lifecycle !== undefined) {
    const l = r.lifecycle;
    if (!plain(l)) fail(`${where}: lifecycle is { transition, subject, after }`);
    onlyKeys(l, ['transition', 'subject', 'after'], `${where} lifecycle`);
    if (typeof l.transition !== 'string' || !IDENT.test(l.transition)) fail(`${where}: lifecycle.transition is a name`);
    if (!LIFECYCLE_SUBJECTS.includes(l.subject)) fail(`${where}: lifecycle.subject is ${LIFECYCLE_SUBJECTS.join(', ')}`);
    if (!RULE_DECISIONS.includes(l.after) || l.after === r.decision) fail(`${where}: lifecycle.after is the decision after the transition, and differs from the rule's`);
    // A capped allowance that also changes at a transition has no single reading for each limit point and phase (the
    // comparison reads such a rule as its limit alone), so it is refused rather than read one way.
    if (r.limit !== undefined) fail(`${where}: a rule carries a limit or a lifecycle, not both`);
  }
  if (!plain(r.source)) fail(`${where}: source is { sourceId, locator } or { adoptedFrom: { matrixId, cellKey } }`);
  if (r.confidence === 'stated-default') fail(`${where}: stated-default comes only from the statement's defaults.unlisted, never from a rule`);
  if (r.confidence === 'stated') {
    onlyKeys(r.source, ['sourceId', 'locator'], `${where} source`);
    if (!sourceIds.has(r.source.sourceId)) fail(`${where}: source.sourceId names one of the statement's sources`);
    if (!name(r.source.locator, 200)) fail(`${where}: source.locator says where in the source (a section, line or anchor)`);
  } else if (r.confidence === 'adopted-declaration') {
    onlyKeys(r.source, ['adoptedFrom'], `${where} source`);
    const a = r.source.adoptedFrom;
    if (!plain(a) || !DIGEST.test(a.matrixId ?? '') || typeof a.cellKey !== 'string') fail(`${where}: source.adoptedFrom is { matrixId, cellKey }`);
    onlyKeys(a, ['matrixId', 'cellKey'], `${where} source.adoptedFrom`);
    // A matrix cell has no relation, state, creators, limit or lifecycle: narrowing a declaration is the operator's own rule.
    for (const k of ['state', 'creators', 'creatorRule', 'limit', 'lifecycle']) if (r[k] !== undefined) fail(`${where}: an adoption keeps the declaration as declared, with no ${k}; state a rule of your own to narrow it`);
    if (relation !== 'any') fail(`${where}: an adoption keeps the declaration as declared, with no relation; state a rule of your own to narrow it`);
    if (a.cellKey !== cellKey(r)) fail(`${where}: an adoption keeps the declaration's role, resource and action`);
    // Checked against the matrix when sealing; a sealed statement keeps the adoption as recorded.
    if (verifyAdoptions) {
      const m = matrixById.get(a.matrixId);
      if (!m) fail(`${where}: adopts from matrix ${a.matrixId.slice(0, 12)}, which was not given; give the matrix to seal an adoption`);
      const cell = m.cells.find(c => cellKey(c) === a.cellKey);
      if (!cell) fail(`${where}: the adopted cell is not in matrix ${a.matrixId.slice(0, 12)}`);
      if (!RULE_DECISIONS.includes(cell.decision)) fail(`${where}: the adopted cell is ${cell.decision}; only an allow or deny declaration can be adopted`);
      if (cell.decision !== r.decision) fail(`${where}: an adoption keeps the declared decision (${cell.decision}); state a rule of your own to say otherwise`);
    }
  } else fail(`${where}: confidence is stated or adopted-declaration`);
  return { ...r, relation };
}

// Two rules overlap when some variant matches both: the same role, resource and action, and each of relation, state and
// creators either equal or left open on one side. Overlapping rules must agree; the same variant twice is refused.
const overlaps = (a, b) => a.role === b.role && a.resource === b.resource && a.action === b.action
  && (a.relation === b.relation || a.relation === 'any' || b.relation === 'any')
  && (a.state === undefined || b.state === undefined || a.state === b.state)
  && (a.creators === undefined || b.creators === undefined || a.creators.some(c => b.creators.includes(c)));
const variantOf = r => canonical({ role: r.role, resource: r.resource, action: r.action, relation: r.relation, state: r.state ?? null, creators: r.creators ? [...r.creators].sort(byCode) : null,
  limit: r.limit ? { pointer: r.limit.pointer } : null, lifecycle: r.lifecycle ? { transition: r.lifecycle.transition, subject: r.lifecycle.subject } : null });

// The statement's body, validated and in canonical order. Used by seal and verify.
function normalize(s, { matrices = [], requireSeal, verifyAdoptions = true }) {
  if (!plain(s) || s.schema !== STATEMENT_SCHEMA) fail(`a statement needs schema "${STATEMENT_SCHEMA}"`);
  if (requireSeal === false) { for (const k of ['notProposed', 'warnings', 'note']) if (Object.hasOwn(s, k)) { s = { ...s }; delete s[k]; } }
  onlyKeys(s, STATEMENT_KEYS, 'the statement');
  if (!name(s.application, 120)) fail('application names the application');
  if (typeof s.statedBy !== 'string' || !s.statedBy.trim() || s.statedBy.length > 120 || /[\u0000-\u001f\u007f]/.test(s.statedBy)) fail('statedBy names the person who states this policy (1 to 120 characters)');
  if (typeof s.statedAt !== 'string' || Number.isNaN(Date.parse(s.statedAt)) || new Date(s.statedAt).toISOString() !== s.statedAt) fail('statedAt is an ISO time (toISOString form)');
  const list = (v, label, ok) => { if (!Array.isArray(v) || new Set(v).size !== v.length || !v.every(ok)) fail(`${label} lists distinct names`); return new Set(v); };
  const roles = list(s.roles, 'roles', x => name(x)), tenants = list(s.tenants ?? [], 'tenants', x => typeof x === 'string' && IDENT.test(x));
  if (!roles.size) fail('roles lists at least one role');
  if (!Array.isArray(s.sources)) fail('sources is a list of { sourceId, label, sha256? }');
  const sourceIds = new Set();
  for (const src of s.sources) {
    if (!plain(src)) fail('each source is an object');
    onlyKeys(src, ['sourceId', 'label', 'sha256'], 'a source');
    if (typeof src.sourceId !== 'string' || !IDENT.test(src.sourceId) || sourceIds.has(src.sourceId)) fail('each source has a distinct sourceId');
    if (!name(src.label, 200)) fail(`source ${src.sourceId}: label is a name`);
    if (src.sha256 !== undefined && !DIGEST.test(src.sha256)) fail(`source ${src.sourceId}: sha256 is 64 lowercase hex characters`);
    sourceIds.add(src.sourceId);
  }
  const defaults = s.defaults ?? {};
  if (!plain(defaults)) fail('defaults is an object');
  onlyKeys(defaults, ['unlisted'], 'defaults');
  if (defaults.unlisted !== undefined && defaults.unlisted !== 'deny') fail('defaults.unlisted is "deny" or left out; an unlisted allow is never a default');
  const matrixById = validMatrices(matrices);
  if (!Array.isArray(s.rules)) fail('rules is a list');
  const ids = new Set(), rules = [];
  for (const raw of s.rules) {
    const r = validateRule(raw, roles, tenants, sourceIds, matrixById, verifyAdoptions);
    if (ids.has(r.ruleId)) fail(`rule ${r.ruleId} is listed twice`);
    ids.add(r.ruleId);
    for (const other of rules) {
      if (!overlaps(r, other)) continue;
      if (variantOf(r) === variantOf(other)) fail(`rules ${other.ruleId} and ${r.ruleId} state the same variant`);
      if (r.decision !== other.decision) fail(`rules ${other.ruleId} and ${r.ruleId} overlap and disagree (${other.decision} vs ${r.decision}); narrow one by relation, state or creators`);
    }
    rules.push(r);
  }
  // Candidates stay listed (the accounting counts them as candidate-only); an adopted one becomes a rule, never both.
  if (!Array.isArray(s.candidates ?? [])) fail('candidates is a list');
  const adopted = new Set(rules.filter(r => r.confidence === 'adopted-declaration').map(r => candidateIdFor(r.source.adoptedFrom.matrixId, r.source.adoptedFrom.cellKey)));
  const candidates = [], candidateIds = new Set();
  for (const c of s.candidates ?? []) {
    if (!plain(c)) fail('each candidate is an object');
    onlyKeys(c, CANDIDATE_KEYS, `candidate ${c.candidateId ?? '?'}`);
    if (!plain(c.adoptedFrom) || !DIGEST.test(c.adoptedFrom.matrixId ?? '') || typeof c.adoptedFrom.cellKey !== 'string' || c.candidateId !== candidateIdFor(c.adoptedFrom.matrixId, c.adoptedFrom.cellKey))
      fail(`candidate ${c.candidateId ?? '?'} does not carry its declaration's id`);
    if (!RULE_DECISIONS.includes(c.decision) || ![c.role, c.resource, c.action].every(x => name(x, 400)) || cellKey(c) !== c.adoptedFrom.cellKey) fail(`candidate ${c.candidateId} is not an allow or deny declaration of its own cell`);
    if (!name(c.layer, 80) || typeof c.basis !== 'string') fail(`candidate ${c.candidateId} names its layer and basis`);
    if (candidateIds.has(c.candidateId)) fail(`candidate ${c.candidateId} is listed twice`);
    candidateIds.add(c.candidateId);
    if (!adopted.has(c.candidateId)) candidates.push(c);
  }
  if (!Array.isArray(s.matrices ?? []) || !(s.matrices ?? []).every(m => plain(m) && DIGEST.test(m.matrixId ?? '') && name(m.layer, 80) && name(m.application, 120)))
    fail('matrices lists { matrixId, layer, application } for each matrix the statement was proposed from or adopts from');
  return { schema: STATEMENT_SCHEMA, application: s.application, statedBy: s.statedBy.trim(), statedAt: s.statedAt, roles: [...roles].sort(byCode), tenants: [...tenants].sort(byCode),
    sources: [...s.sources].sort((a, b) => byCode(a.sourceId, b.sourceId)), defaults, rules: rules.sort((a, b) => byCode(a.ruleId, b.ruleId)),
    candidates: candidates.sort((a, b) => byCode(a.candidateId, b.candidateId)),
    matrices: [...new Map([...(s.matrices ?? []), ...[...matrixById.values()].map(m => ({ matrixId: m.matrixId, layer: m.layer, application: m.application }))].map(m => [m.matrixId, { matrixId: m.matrixId, layer: m.layer, application: m.application }])).values()]
      .sort((a, b) => byCode(a.matrixId, b.matrixId)) };
}

// Seal a written statement under a statedBy label. The label is free text the caller supplies: nothing authenticates it or
// shows a person approved the statement. Adoptions are checked against the matrices they name.
export function sealStatement(statement, { statedBy, now = new Date(), matrices = [] } = {}) {
  if (!plain(statement)) fail('seal needs a statement');
  if (Object.hasOwn(statement, 'statementId')) fail('this statement is already sealed; edit a copy without its statementId to restate it');
  const body = normalize({ ...statement, statedBy, statedAt: now.toISOString() }, { matrices, requireSeal: false });
  return { ...body, statementId: sha256(canonical(body)) };
}

export function verifyStatement(statement) {
  if (!plain(statement) || typeof statement.statementId !== 'string') return false;
  const { statementId, ...body } = statement;
  return statementId === sha256(canonical(body));
}

// The stated decision for one variant, or null when the statement says nothing (not-stated). Only a sealed, unedited
// statement states intent; a proposal, a matrix or an edited statement never does.
export function statedDecision(statement, { role, resource, action, relation = 'any', state, creator }) {
  if (!verifyStatement(statement)) fail('only a sealed, unedited statement states intent (its statementId no longer matches, or it was never sealed)');
  if (!statement.roles.includes(role)) return null;
  const matches = statement.rules.filter(r => r.role === role && r.resource === resource && r.action === action
    && (r.relation === 'any' || r.relation === relation) && (r.state === undefined || r.state === state)
    && (r.creators === undefined || (creator !== undefined && r.creators.includes(creator))));
  if (matches.length) {
    // Overlapping rules agree (seal refuses otherwise), so any match gives the decision. Name the most specific.
    const specificity = r => (r.relation !== 'any') + (r.state !== undefined) + (r.creators !== undefined);
    const [r] = matches.sort((a, b) => specificity(b) - specificity(a) || byCode(a.ruleId, b.ruleId));
    return { decision: r.decision, confidence: r.confidence, ruleId: r.ruleId, ...(r.confidence === 'adopted-declaration' ? { category: ADOPTED_CATEGORY } : {}),
      ...(r.limit ? { limit: r.limit } : {}), ...(r.lifecycle ? { lifecycle: r.lifecycle } : {}) };
  }
  return statement.defaults.unlisted === 'deny' ? { decision: 'deny', confidence: 'stated-default', ruleId: DEFAULT_RULE_ID } : null;
}

// The stated parts of one cell, each with the decision a whole-cell declaration compares with, and what the rest of the
// cell (what no rule names) reads: covered (null), the default's deny, or unstated. The rest is empty only when rules with no
// state or creators cover every relation.
function cellParts(statement, cell) {
  const rules = statement.rules.filter(r => cellKey(r) === cellKey(cell));
  const parts = [];
  for (const r of rules) {
    const where = { ruleId: r.ruleId, confidence: r.confidence, relation: r.relation, ...(r.state !== undefined ? { state: r.state } : {}),
      ...(r.creators ? { creators: r.creators, creatorRule: r.creatorRule } : {}) };
    if (r.limit) parts.push({ ...where, part: 'within-limit', limit: r.limit, decision: r.decision }, { ...where, part: 'over-limit', limit: r.limit, decision: 'deny' });
    else if (r.lifecycle) parts.push({ ...where, part: 'before-transition', lifecycle: r.lifecycle, decision: r.decision }, { ...where, part: 'after-transition', lifecycle: r.lifecycle, decision: r.lifecycle.after });
    else parts.push({ ...where, part: 'rule', decision: r.decision });
  }
  const open = rules.filter(r => r.state === undefined && r.creators === undefined);
  const relations = ['own', 'other-same-role', 'other-role', ...(statement.tenants.length >= 2 ? ['cross-tenant'] : [])];
  const covered = open.some(r => r.relation === 'any') || relations.every(rel => open.some(r => r.relation === rel));
  const rest = covered ? null : statement.roles.includes(cell.role) && statement.defaults.unlisted === 'deny' ? 'default-deny' : 'unstated';
  if (rest === 'default-deny') parts.push({ ruleId: DEFAULT_RULE_ID, confidence: 'stated-default', part: 'rest-of-cell', decision: 'deny' });
  return { parts, rest };
}

// Compare the stated parts with one declaration. Each part gets its comparison; the row gets one agreement.
function compareParts(declared, parts, rest) {
  if (!parts.length) return { agreement: RULE_DECISIONS.includes(declared) || declared === 'conditional' ? 'declared-only' : 'neither', parts };
  if (declared === 'undeclared' || declared === 'unknown') return { agreement: 'stated-only', parts: parts.map(p => ({ ...p, comparison: 'not-declared' })) };
  if (declared === 'conditional') {
    // The declaration's condition is not evaluated. Only one decision over the whole cell compares: deny refuses what the
    // condition allows (stricter), allow grants what it withholds (wider).
    const one = rest !== 'unstated' && parts.every(p => p.decision === parts[0].decision) ? parts[0].decision : null;
    const comparison = one === 'deny' ? 'stricter' : one === 'allow' ? 'wider' : 'unresolved';
    return { agreement: one === null ? 'unresolved' : `stated-${comparison}`, parts: parts.map(p => ({ ...p, comparison })) };
  }
  const compared = parts.map(p => ({ ...p, comparison: p.decision === declared ? 'agrees' : p.decision === 'deny' ? 'stricter' : 'wider' }));
  const differs = compared.find(p => p.comparison !== 'agrees');
  const agreement = differs ? `stated-${differs.comparison}` : rest === 'unstated' ? 'agrees-where-stated' : 'agrees';
  return { agreement, parts: compared };
}

// Line a sealed statement up with matrices of the same application: where the operator and the application's own
// declarations agree, where the statement is stricter or wider, and what only one of them says. Agreement data only:
// a matrix never changes a stated decision, and a disagreement is a question for a test, not a verdict.
export function checkStatement(statement, { matrices = [] } = {}) {
  if (!verifyStatement(statement)) fail('the statement is not sealed or was edited after sealing (its statementId no longer matches)');
  normalize(statement, { requireSeal: true, verifyAdoptions: false }); // re-validate the sealed body; adoptions were checked at seal
  const byId = validMatrices(matrices);
  const rows = [], warnings = [];
  // A matrixId names its content, so an adoption's own matrix still says what was adopted. A later import is another
  // matrix: its rows below compare the adopted rule with what the application declares now.
  for (const r of statement.rules.filter(x => x.confidence === 'adopted-declaration'))
    if (!byId.has(r.source.adoptedFrom.matrixId)) warnings.push(`rule ${r.ruleId} adopts from matrix ${r.source.adoptedFrom.matrixId.slice(0, 12)}, which was not given`);
  for (const m of byId.values()) {
    if (m.application !== statement.application) warnings.push(`matrix ${m.matrixId.slice(0, 12)} names application ${m.application}, not ${statement.application}`);
    for (const c of m.cells) {
      const declared = MATRIX_DECISIONS.includes(c.decision) ? c.decision : 'unknown';
      const { parts, rest } = cellParts(statement, c);
      const { agreement, parts: compared } = compareParts(declared, parts, rest);
      // stated: the whole-cell reading, from a rule that covers the whole cell, or from the defaults when no rule names the
      // cell at all. When only narrower rules state the cell there is no single whole-cell reading: null, and the parts say it.
      const cellRules = statement.rules.filter(r => cellKey(r) === cellKey(c));
      const coversCell = r => r.relation === 'any' && r.state === undefined && r.creators === undefined;
      const stated = !cellRules.length || cellRules.some(coversCell) ? statedDecision(statement, { role: c.role, resource: c.resource, action: c.action }) : null;
      rows.push({ matrixId: m.matrixId, layer: m.layer, role: c.role, resource: c.resource, action: c.action, declared,
        stated: stated ? { decision: stated.decision, confidence: stated.confidence, ruleId: stated.ruleId, ...(stated.limit ? { limit: stated.limit } : {}), ...(stated.lifecycle ? { lifecycle: stated.lifecycle } : {}) } : null,
        parts: compared, rest, agreement });
    }
  }
  const counts = Object.fromEntries(AGREEMENT.map(k => [k, rows.filter(r => r.agreement === k).length]));
  const disagreements = rows.filter(r => DISAGREEMENTS.includes(r.agreement));
  return { statementId: statement.statementId, application: statement.application, statedBy: statement.statedBy, verified: true,
    rules: statement.rules.length, adopted: statement.rules.filter(r => r.confidence === 'adopted-declaration').length, candidates: statement.candidates.length,
    defaultUnlisted: statement.defaults.unlisted ?? null, counts, disagreements, warnings, rows };
}
