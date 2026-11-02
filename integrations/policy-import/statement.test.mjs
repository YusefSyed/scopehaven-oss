// The operator policy statement (scopehaven-policy-statement/1). Local and synthetic: matrices are built
// in memory, the CLI writes only into a temporary directory, and nothing reads an application or sends a request.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildMatrix, canonical, cellKey, sha256 } from './matrix.mjs';
import { ADOPTED_CATEGORY, AGREEMENT, DEFAULT_RULE_ID, STATEMENT_SCHEMA, checkStatement, proposeStatement, sealStatement, statedDecision, verifyStatement } from './statement.mjs';
import { main } from './cli.mjs';

const NOW = new Date('2026-10-08T10:00:00.000Z');
const cite = [{ source: 'm.sql', line: 1 }];
const matrixOf = (cells, application = 'app') => buildMatrix({ application, layer: 'postgres-rls', sources: [{ id: 'm.sql', kind: 'sql', label: 'm.sql', bytes: 1, sha256: '0'.repeat(64) }],
  cells: cells.map(([role, resource, action, decision, conditions]) => ({ role, resource, action, decision, basis: `${decision} by fixture`, conditions: conditions ?? [], citations: decision === 'undeclared' ? [] : cite })) });
const MATRIX = matrixOf([
  ['authenticated', 'public.notes', 'SELECT', 'allow'],
  ['authenticated', 'public.notes', 'UPDATE', 'conditional', ['(owner = auth.uid())']],
  ['anon', 'public.notes', 'SELECT', 'deny'],
  ['anon', 'public.notes', 'UPDATE', 'undeclared'],
  ['authenticated', 'public.audit', 'SELECT', 'unknown'],
]);
const key = (role, resource, action) => cellKey({ role, resource, action });
const stated = (ruleId, role, resource, action, decision, extra = {}) => ({ ruleId, role, resource, action, decision, source: { sourceId: 'policy', locator: `section ${ruleId}` }, confidence: 'stated', ...extra });
const adopted = (ruleId, role, resource, action, decision, matrix = MATRIX) => ({ ruleId, role, resource, action, decision, source: { adoptedFrom: { matrixId: matrix.matrixId, cellKey: key(role, resource, action) } }, confidence: 'adopted-declaration' });
const written = (rules = [], extra = {}) => ({ ...proposeStatement({ application: 'app', matrices: [MATRIX] }), tenants: ['t1', 't2'], sources: [{ sourceId: 'policy', label: 'Support policy v3' }], rules, ...extra });
const seal = (rules, extra, matrices = [MATRIX]) => sealStatement(written(rules, extra), { statedBy: 'Operator Name', now: NOW, matrices });
const refuse = (rules, pattern, extra) => assert.throws(() => seal(rules, extra), pattern);
const scratch = async t => { const dir = await mkdtemp(join(tmpdir(), 'scopehaven policy statement ')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };

test('propose: a proposal states nothing; declared allow and deny cells are candidates and the rest are listed', () => {
  const p = proposeStatement({ application: 'app', matrices: [MATRIX] });
  assert.equal(p.schema, STATEMENT_SCHEMA);
  assert.deepEqual(p.rules, []);
  assert.deepEqual(p.candidates.map(c => [c.role, c.action, c.decision]).sort(), [['anon', 'SELECT', 'deny'], ['authenticated', 'SELECT', 'allow']]);
  assert.deepEqual(p.notProposed.map(c => c.decision).sort(), ['conditional', 'undeclared', 'unknown']);
  assert.match(p.notProposed.find(c => c.decision === 'conditional').reason, /state the rule and its condition yourself/);
  assert.deepEqual(p.roles, ['anon', 'authenticated']);
  assert.throws(() => statedDecision(p, { role: 'anon', resource: 'public.notes', action: 'SELECT' }), /only a sealed, unedited statement states intent/);
  // Sealed as proposed, it still states nothing: a declaration is never intent, and undeclared never becomes deny.
  const s = sealStatement(p, { statedBy: 'Operator Name', now: NOW });
  for (const c of MATRIX.cells) assert.equal(statedDecision(s, c), null, cellKey(c));
  assert.equal(s.candidates.length, 2);
  assert.ok(!Object.hasOwn(s, 'notProposed') && !Object.hasOwn(s, 'note'), 'proposal notes are not sealed');
  assert.match(proposeStatement({ application: 'other', matrices: [MATRIX] }).warnings[0], /names application app, not other/);
  assert.throws(() => proposeStatement({ application: 'app', matrices: [] }), /at least one matrix/);
  assert.throws(() => proposeStatement({ application: 'app', matrices: [{ ...MATRIX, cells: [] }] }), /edited after import/);
});

test('seal: a named person, an id that detects edits, and canonical order', () => {
  const rules = [stated('r1', 'authenticated', 'public.notes', 'SELECT', 'allow'), stated('r2', 'anon', 'public.notes', 'SELECT', 'deny')];
  const s = seal(rules);
  assert.ok(verifyStatement(s));
  assert.equal(s.statedAt, NOW.toISOString());
  assert.equal(s.statedBy, 'Operator Name');
  const shuffled = sealStatement(written([...rules].reverse(), { roles: ['authenticated', 'anon'], candidates: [...written().candidates].reverse() }), { statedBy: ' Operator Name ', now: NOW, matrices: [MATRIX] });
  assert.equal(shuffled.statementId, s.statementId, 'order and padding do not change the id');
  const edited = structuredClone(s); edited.rules[0].decision = 'deny';
  assert.equal(verifyStatement(edited), false);
  assert.throws(() => statedDecision(edited, { role: 'anon', resource: 'public.notes', action: 'SELECT' }), /sealed, unedited/);
  assert.throws(() => checkStatement(edited), /edited after sealing/);
  assert.throws(() => sealStatement(written(rules), { now: NOW }), /statedBy names the person/);
  assert.throws(() => sealStatement(written(rules), { statedBy: '   ', now: NOW }), /statedBy names the person/);
  assert.throws(() => sealStatement(s, { statedBy: 'Operator Name', now: NOW }), /already sealed/);
  assert.equal(verifyStatement(null), false);
});

test('an unlisted or undeclared cell is not stated; only defaults.unlisted "deny" makes it stated-default', () => {
  const none = seal([stated('r1', 'authenticated', 'public.notes', 'SELECT', 'allow')]);
  assert.equal(statedDecision(none, { role: 'anon', resource: 'public.notes', action: 'UPDATE' }), null);
  const dflt = seal([stated('r1', 'authenticated', 'public.notes', 'SELECT', 'allow')], { defaults: { unlisted: 'deny' } });
  assert.deepEqual(statedDecision(dflt, { role: 'anon', resource: 'public.notes', action: 'UPDATE' }), { decision: 'deny', confidence: 'stated-default', ruleId: DEFAULT_RULE_ID });
  assert.equal(statedDecision(dflt, { role: 'service', resource: 'public.notes', action: 'UPDATE' }), null, 'a role the statement does not list is not stated');
  assert.equal(statedDecision(dflt, { role: 'authenticated', resource: 'public.notes', action: 'SELECT' }).confidence, 'stated');
  refuse([], /defaults.unlisted is "deny" or left out/, { defaults: { unlisted: 'allow' } });
  refuse([], /defaults has unknown field/, { defaults: { other: 'deny' } });
  refuse([stated('r1', 'anon', 'public.notes', 'SELECT', 'deny', { confidence: 'stated-default' })], /stated-default comes only from the statement's defaults/);
  refuse([stated(DEFAULT_RULE_ID, 'anon', 'public.notes', 'SELECT', 'deny')], /a rule needs a ruleId/);
});

test('adoption: a named person adopts a declaration as declared, counted apart with its category; anything else is refused', () => {
  const s = seal([adopted('anon-read', 'anon', 'public.notes', 'SELECT', 'deny')]);
  assert.deepEqual(statedDecision(s, { role: 'anon', resource: 'public.notes', action: 'SELECT' }), { decision: 'deny', confidence: 'adopted-declaration', ruleId: 'anon-read', category: ADOPTED_CATEGORY });
  assert.deepEqual(s.candidates.map(c => c.role), ['authenticated'], 'the adopted candidate is a rule now, never both');
  refuse([adopted('flip', 'anon', 'public.notes', 'SELECT', 'allow')], /an adoption keeps the declared decision \(deny\)/);
  assert.throws(() => seal([adopted('a', 'anon', 'public.notes', 'SELECT', 'deny')], {}, []), /which was not given/);
  assert.throws(() => seal([adopted('a', 'anon', 'public.notes', 'SELECT', 'deny')], {}, [{ ...MATRIX, cells: MATRIX.cells.slice(1) }]), /edited after import/);
  refuse([adopted('cond', 'authenticated', 'public.notes', 'UPDATE', 'allow')], /the adopted cell is conditional/);
  refuse([adopted('undeclared', 'anon', 'public.notes', 'UPDATE', 'deny')], /the adopted cell is undeclared/);
  const moved = adopted('moved', 'anon', 'public.notes', 'SELECT', 'deny'); moved.source.adoptedFrom.cellKey = key('authenticated', 'public.notes', 'SELECT');
  refuse([moved], /keeps the declaration's role, resource and action/);
  const ghost = adopted('ghost', 'anon', 'public.other', 'SELECT', 'deny');
  refuse([ghost], /the adopted cell is not in matrix/);
  refuse([{ ...adopted('c', 'anon', 'public.notes', 'SELECT', 'deny'), candidate: true }], /is still a candidate/);
  const [candidate] = written().candidates.filter(c => c.role === 'anon');
  refuse([{ ...candidate, ruleId: 'pasted', confidence: 'adopted-declaration', source: { adoptedFrom: candidate.adoptedFrom } }], /unknown fields candidateId/);
  refuse([{ ...adopted('x', 'anon', 'public.notes', 'SELECT', 'deny'), confidence: 'stated' }], /unknown field adoptedFrom/);
  // Candidates are checked, never trusted: a candidate edited to another cell or decision is refused.
  const forged = written(); forged.candidates[0].decision = 'conditional';
  assert.throws(() => sealStatement(forged, { statedBy: 'Operator Name', now: NOW }), /not an allow or deny declaration/);
  const layerless = written(); layerless.candidates[0].layer = '';
  assert.throws(() => sealStatement(layerless, { statedBy: 'Operator Name', now: NOW }), /names its layer and basis/);
  const twice = written(); twice.candidates.push({ ...twice.candidates[0] });
  assert.throws(() => sealStatement(twice, { statedBy: 'Operator Name', now: NOW }), /is listed twice/);
  const renamed = written(); renamed.candidates[0].candidateId = 'C-000000000000';
  assert.throws(() => sealStatement(renamed, { statedBy: 'Operator Name', now: NOW }), /does not carry its declaration's id/);
});

test('rules: overlapping rules must agree, a variant is stated once, and the most specific rule is named', () => {
  const own = stated('own', 'authenticated', 'public.notes', 'UPDATE', 'allow', { relation: 'own' });
  const other = stated('other', 'authenticated', 'public.notes', 'UPDATE', 'deny', { relation: 'other-role' });
  const s = seal([own, other]);
  assert.equal(statedDecision(s, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE', relation: 'own' }).ruleId, 'own');
  assert.equal(statedDecision(s, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE', relation: 'other-role' }).decision, 'deny');
  assert.equal(statedDecision(s, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE', relation: 'cross-tenant' }), null);
  refuse([stated('any', 'authenticated', 'public.notes', 'UPDATE', 'deny'), own], /rules any and own overlap and disagree/);
  const both = seal([stated('any', 'authenticated', 'public.notes', 'UPDATE', 'deny'), { ...other, ruleId: 'other' }]);
  assert.equal(statedDecision(both, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE', relation: 'other-role' }).ruleId, 'other', 'the specific rule is named');
  assert.equal(statedDecision(both, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE', relation: 'own' }).ruleId, 'any');
  refuse([own, { ...own, ruleId: 'own-again' }], /state the same variant/);
  refuse([own, { ...other, ruleId: 'own' }], /rule own is listed twice/);
  const draft = seal([stated('draft', 'authenticated', 'public.notes', 'UPDATE', 'allow', { state: 'draft' })]);
  assert.equal(statedDecision(draft, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE' }), null);
  assert.equal(statedDecision(draft, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE', state: 'draft' }).ruleId, 'draft');
  refuse([stated('a', 'authenticated', 'public.notes', 'UPDATE', 'allow', { state: 'draft' }), stated('b', 'authenticated', 'public.notes', 'UPDATE', 'deny')], /overlap and disagree/);
  seal([stated('a', 'authenticated', 'public.notes', 'UPDATE', 'allow', { state: 'draft' }), stated('b', 'authenticated', 'public.notes', 'UPDATE', 'deny', { state: 'posted' })]);
  const made = seal([stated('m', 'authenticated', 'public.notes', 'UPDATE', 'deny', { creators: ['authenticated'], creatorRule: 'actor-must-differ' })]);
  assert.equal(statedDecision(made, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE' }), null, 'a creator rule needs the variant to name its creator');
  assert.equal(statedDecision(made, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE', creator: 'authenticated' }).ruleId, 'm');
  assert.equal(statedDecision(made, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE', creator: 'anon' }), null);
  refuse([stated('c1', 'authenticated', 'public.notes', 'UPDATE', 'deny', { creators: ['anon', 'authenticated'], creatorRule: 'actor-must-differ' }),
    stated('c2', 'authenticated', 'public.notes', 'UPDATE', 'allow', { creators: ['anon'], creatorRule: 'actor-must-equal' })], /overlap and disagree/);
  seal([stated('c1', 'authenticated', 'public.notes', 'UPDATE', 'deny', { creators: ['authenticated'], creatorRule: 'actor-must-differ' }),
    stated('c2', 'authenticated', 'public.notes', 'UPDATE', 'allow', { creators: ['anon'], creatorRule: 'actor-must-equal' })]);
  // An adopted rule keeps the declaration whole: narrowing it is the operator's own rule.
  for (const extra of [{ relation: 'own' }, { state: 'draft' }, { creators: ['anon'], creatorRule: 'actor-must-differ' }, { lifecycle: { transition: 'suspend', subject: 'actor', after: 'allow' } }])
    refuse([{ ...adopted('narrowed', 'anon', 'public.notes', 'SELECT', 'deny'), ...extra }], /an adoption keeps the declaration as declared/);
  // The most specific rule is named; between equally specific rules, the lower ruleId.
  const tie = seal([stated('b-rule', 'authenticated', 'public.notes', 'UPDATE', 'deny', { relation: 'own' }), stated('a-rule', 'authenticated', 'public.notes', 'UPDATE', 'deny', { state: 'posted' })]);
  assert.equal(statedDecision(tie, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE', relation: 'own', state: 'posted' }).ruleId, 'a-rule');
});

test('rule fields: relation, creators, tenants, limits, lifecycle and sources are checked', () => {
  const r = (extra, decision = 'allow') => stated('r', 'authenticated', 'public.notes', 'UPDATE', decision, extra);
  refuse([r({ relation: 'mine' })], /relation is any, own/);
  refuse([r({ relation: 'cross-tenant' })], /needs at least two tenants/, { tenants: ['t1'] });
  seal([r({ relation: 'cross-tenant' })]);
  refuse([r({ creators: ['anon', 'authenticated', 'a3', 'a4', 'a5', 'a6'], creatorRule: 'actor-must-differ' })], /creators lists 1 to 5 distinct statement roles/, { roles: ['anon', 'authenticated', 'a3', 'a4', 'a5', 'a6'] });
  refuse([r({ creators: ['anon'] })], /creators need a creatorRule/);
  refuse([r({ creatorRule: 'actor-must-differ' })], /creators lists 1 to 5/);
  refuse([r({ creators: ['ghost'], creatorRule: 'actor-must-differ' })], /creators lists 1 to 5 distinct statement roles/);
  refuse([r({ limit: { pointer: '/amount', cap: 100, unit: 'USD' } }, 'deny')], /a limit caps an allowance/);
  refuse([r({ limit: { pointer: 'amount', cap: 100, unit: 'USD' } })], /limit.pointer is a JSON pointer/);
  refuse([r({ limit: { pointer: '/amount', cap: Infinity, unit: 'USD' } })], /limit.cap is a finite number/);
  refuse([r({ limit: { pointer: '/amount', cap: 100, unit: 'USD', inclusive: 'yes' } })], /limit.inclusive is true or false/);
  refuse([r({ limit: { pointer: '/amount', cap: 100, unit: 'USD', over: 'deny' } })], /limit has unknown field over/);
  refuse([r({ limit: { pointer: '/amount', cap: 100, unit: 'USD', roles: ['ghost'] } })], /limit.roles lists distinct statement roles/);
  const capped = seal([r({ limit: { pointer: '/amount', cap: 100, unit: 'USD' } })]);
  assert.deepEqual(statedDecision(capped, { role: 'authenticated', resource: 'public.notes', action: 'UPDATE' }).limit, { pointer: '/amount', cap: 100, unit: 'USD' }, 'unstated inclusivity stays unstated');
  refuse([r({ lifecycle: { transition: 'suspend', subject: 'actor', after: 'allow' } })], /lifecycle.after is the decision after the transition, and differs/);
  refuse([r({ lifecycle: { transition: 'suspend', subject: 'owner', after: 'deny' } })], /lifecycle.subject is actor, role, tenant/);
  refuse([r({ lifecycle: { transition: 'sus pend', subject: 'actor', after: 'deny' } })], /lifecycle.transition is a name/);
  refuse([r({ limit: { pointer: '/amount', cap: 100, unit: 'USD' }, lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } })], /a rule carries a limit or a lifecycle, not both/);
  assert.deepEqual(statedDecision(seal([r({ lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } })]), { role: 'authenticated', resource: 'public.notes', action: 'UPDATE' }).lifecycle,
    { transition: 'suspend', subject: 'actor', after: 'deny' });
  refuse([r({ source: { sourceId: 'elsewhere', locator: 'x' } })], /source.sourceId names one of the statement's sources/);
  refuse([r({ source: { sourceId: 'policy' } })], /source.locator says where/);
  refuse([r({ notes: 'x' })], /rule r has unknown field notes/);
  refuse([r({ decision: 'conditional' })], /decision is allow or deny/);
  refuse([r({ confidence: 'inferred' })], /confidence is stated or adopted-declaration/);
  refuse([r({ role: 'ghost' })], /role "ghost" is not one of the statement's roles/);
  refuse([r({ resource: 'a\u0000b' })], /resource is a name/);
  refuse([r({ action: '' })], /action is a name/);
  refuse([r({ state: 'has space' })], /state is a name/);
  refuse([r({ limit: { pointer: '/amount', cap: 100, unit: '' } })], /limit.unit is a name/);
  refuse([{ ...adopted('bad', 'anon', 'public.notes', 'SELECT', 'deny'), source: { adoptedFrom: { matrixId: 'abc', cellKey: key('anon', 'public.notes', 'SELECT') } } }], /source.adoptedFrom is \{ matrixId, cellKey \}/);
  refuse([], /matrices lists \{ matrixId, layer, application \}/, { matrices: [{ matrixId: 'x' }] });
  refuse([], /the statement has unknown field extra/, { extra: 1 });
  refuse([], /each source has a distinct sourceId/, { sources: [{ sourceId: 'p', label: 'a' }, { sourceId: 'p', label: 'b' }] });
  refuse([], /sha256 is 64 lowercase hex/, { sources: [{ sourceId: 'p', label: 'a', sha256: 'abc' }] });
  refuse([], /roles lists at least one role/, { roles: [] });
  refuse([], /tenants lists distinct names/, { tenants: ['t1', 't1'] });
});

test('check: agreement with the application\'s declarations, part by part; a conditional declaration beside variant rules stays unresolved', () => {
  const s = seal([
    adopted('anon-read', 'anon', 'public.notes', 'SELECT', 'deny'),
    stated('auth-read', 'authenticated', 'public.notes', 'SELECT', 'deny'),
    stated('own', 'authenticated', 'public.notes', 'UPDATE', 'allow', { relation: 'own' }),
  ], { defaults: { unlisted: 'deny' } });
  const result = checkStatement(s, { matrices: [MATRIX] });
  const byCell = Object.fromEntries(result.rows.map(r => [`${r.role} ${r.resource} ${r.action}`, r]));
  assert.equal(byCell['anon public.notes SELECT'].agreement, 'agrees');
  assert.equal(byCell['authenticated public.notes SELECT'].agreement, 'stated-stricter');
  // The declaration is conditional and the cell has two decisions (own allow, the default's deny elsewhere): not evaluated.
  assert.equal(byCell['authenticated public.notes UPDATE'].agreement, 'unresolved');
  assert.deepEqual(byCell['authenticated public.notes UPDATE'].parts.map(p => [p.part, p.ruleId, p.decision, p.comparison]),
    [['rule', 'own', 'allow', 'unresolved'], ['rest-of-cell', DEFAULT_RULE_ID, 'deny', 'unresolved']]);
  assert.equal(byCell['authenticated public.notes UPDATE'].rest, 'default-deny');
  assert.equal(byCell['anon public.notes UPDATE'].agreement, 'stated-only', 'an undeclared cell is stated only by the default');
  assert.equal(byCell['anon public.notes UPDATE'].stated.confidence, 'stated-default');
  assert.equal(byCell['authenticated public.audit SELECT'].agreement, 'stated-only');
  assert.deepEqual(Object.keys(result.counts), [...AGREEMENT]);
  assert.equal(result.disagreements.length, 1);
  assert.deepEqual([result.rules, result.adopted, result.candidates, result.defaultUnlisted], [3, 1, 1, 'deny']);
  // A later import that widens the adopted cell is another matrix: the adoption is not re-checked against it, and its row shows the difference.
  const later = matrixOf([['anon', 'public.notes', 'SELECT', 'allow']]);
  const again = checkStatement(s, { matrices: [later] });
  assert.equal(again.rows[0].agreement, 'stated-stricter');
  assert.match(again.warnings[0], /rule anon-read adopts from matrix [a-f0-9]{12}, which was not given/);
  const wider = checkStatement(seal([stated('w', 'anon', 'public.notes', 'SELECT', 'allow')]), { matrices: [MATRIX] });
  assert.equal(wider.rows.find(r => r.role === 'anon' && r.action === 'SELECT').agreement, 'stated-wider');
  assert.equal(wider.disagreements.length, 1, 'a wider statement is a disagreement too');
  const byState = checkStatement(seal([stated('draft', 'authenticated', 'public.notes', 'SELECT', 'deny', { state: 'draft' })]), { matrices: [MATRIX] });
  const draftRow = byState.rows.find(r => r.role === 'authenticated' && r.resource === 'public.notes' && r.action === 'SELECT');
  assert.deepEqual([draftRow.agreement, draftRow.rest], ['stated-stricter', 'unstated'], 'an allow declared for the whole cell covers the draft state too');
  // A sealed body is re-validated, so recomputing the id over an invalid body does not pass check.
  const reseal = (statement, edit) => { const { statementId: _id, ...body } = structuredClone(statement); edit(body); return { ...body, statementId: sha256(canonical(body)) }; };
  const clash = reseal(s, b => b.rules.push({ ...b.rules.find(r => r.ruleId === 'auth-read'), ruleId: 'auth-read-2', decision: 'allow', relation: 'own' }));
  assert.ok(verifyStatement(clash));
  assert.throws(() => checkStatement(clash, { matrices: [MATRIX] }), /overlap and disagree/);
  assert.throws(() => checkStatement(reseal(s, b => { b.statedAt = '2026-10-08T10:00:00Z'; }), { matrices: [MATRIX] }), /statedAt is an ISO time/);
  const silent = checkStatement(seal([]), { matrices: [MATRIX] });
  assert.deepEqual(silent.rows.map(r => r.agreement).sort(), ['declared-only', 'declared-only', 'declared-only', 'neither', 'neither']);
  assert.throws(() => checkStatement(s, { matrices: [{ ...MATRIX, layer: 'edited' }] }), /edited after import/);
  assert.match(checkStatement(s, { matrices: [matrixOf([['anon', 'public.notes', 'SELECT', 'deny']], 'other-app')] }).warnings.join('\n'), /names application other-app, not app/);
});

test('CLI: statement propose, seal and check in a path with spaces; new files, mode 0600; check exits 1 on a disagreement', async t => {
  const dir = await scratch(t), at = n => join(dir, n), quiet = { out: () => {} };
  await writeFile(at('matrix.json'), JSON.stringify(MATRIX));
  const second = matrixOf([['service', 'public.jobs', 'SELECT', 'allow']]);
  await writeFile(at('second.json'), JSON.stringify(second));
  assert.equal(await main(['statement', 'propose', at('matrix.json'), at('second.json'), '--app', 'app', '--out', at('both.json')], quiet), 0);
  assert.deepEqual(JSON.parse(await readFile(at('both.json'), 'utf8')).matrices.map(m => m.matrixId).sort(), [MATRIX.matrixId, second.matrixId].sort(), 'every matrix given is read');
  assert.equal(await main(['statement', 'propose', at('matrix.json'), '--app', 'app', '--out', at('proposal.json')], quiet), 0);
  const proposal = JSON.parse(await readFile(at('proposal.json'), 'utf8'));
  assert.deepEqual(proposal.rules, []);
  assert.equal((await stat(at('proposal.json'))).mode & 0o777, 0o600);
  const [anon] = proposal.candidates.filter(c => c.role === 'anon');
  await writeFile(at('written.json'), JSON.stringify({ ...proposal, sources: [{ sourceId: 'policy', label: 'Support policy v3' }], rules: [
    { ruleId: 'anon-read', role: 'anon', resource: anon.resource, action: anon.action, decision: anon.decision, source: { adoptedFrom: anon.adoptedFrom }, confidence: 'adopted-declaration' }] }));
  await assert.rejects(main(['statement', 'seal', at('written.json'), '--stated-by', 'Operator Name', '--out', at('sealed.json')], quiet), /which was not given/);
  const lines = [];
  assert.equal(await main(['statement', 'seal', at('written.json'), at('matrix.json'), '--stated-by', 'Operator Name', '--out', at('sealed.json')], { out: l => lines.push(l) }), 0);
  assert.equal(JSON.parse(lines[0]).adopted, 1);
  const sealed = JSON.parse(await readFile(at('sealed.json'), 'utf8'));
  assert.ok(verifyStatement(sealed));
  assert.equal((await stat(at('sealed.json'))).mode & 0o777, 0o600);
  await assert.rejects(main(['statement', 'seal', at('written.json'), at('matrix.json'), '--stated-by', 'Operator Name', '--out', at('sealed.json')], quiet), /EEXIST/);
  assert.equal(await main(['statement', 'check', at('sealed.json'), at('matrix.json'), '--out', at('check.json')], quiet), 0);
  assert.equal(JSON.parse(await readFile(at('check.json'), 'utf8')).counts.agrees, 1);
  const { statementId: _sealedId, ...unsealed } = sealed;
  const stricter = sealStatement({ ...unsealed, rules: [...unsealed.rules, { ruleId: 'auth-read', role: 'authenticated', resource: 'public.notes', action: 'SELECT', decision: 'deny', source: { sourceId: 'policy', locator: 'section 2' }, confidence: 'stated' }] },
    { statedBy: 'Operator Name', now: NOW, matrices: [MATRIX] });
  await writeFile(at('stricter.json'), JSON.stringify(stricter));
  assert.equal(await main(['statement', 'check', at('stricter.json'), at('matrix.json')], quiet), 1);
  await assert.rejects(main(['statement', 'check'], quiet), /Usage/);
  await assert.rejects(main(['statement', 'rewrite', at('sealed.json')], quiet), /Usage/);
});

// A declaration of allow or deny covers every variant of its cell, so each stated part compares with it, through the
// CLI's exit status. Six probe inputs, plus agreeing controls.
test('check: every stated part compares with a whole-cell declaration, and the CLI exits 1 on any disagreement', async t => {
  const dir = await scratch(t), at = n => join(dir, n), quiet = { out: () => {} };
  const one = decision => matrixOf([['authenticated', 'public.notes', 'SELECT', decision]]);
  const r = (decision, extra = {}) => stated('R1', 'authenticated', 'public.notes', 'SELECT', decision, extra);
  const cases = [
    ['own allow vs deny', 'deny', [r('allow', { relation: 'own' })], {}, 1, 'stated-wider'],
    ['own deny vs allow', 'allow', [r('deny', { relation: 'own' })], {}, 1, 'stated-stricter'],
    ['state deny vs allow', 'allow', [r('deny', { state: 'archived' })], {}, 1, 'stated-stricter'],
    ['creator deny vs allow', 'allow', [r('deny', { creators: ['authenticated'], creatorRule: 'actor-must-equal' })], {}, 1, 'stated-stricter'],
    ['default deny beside a state allow, vs allow', 'allow', [r('allow', { state: 'active' })], { defaults: { unlisted: 'deny' } }, 1, 'stated-stricter'],
    ['capped allow vs allow', 'allow', [r('allow', { limit: { pointer: '/amount', cap: 100, unit: 'units', inclusive: true } })], {}, 1, 'stated-stricter'],
    ['capped allow vs deny', 'deny', [r('allow', { limit: { pointer: '/amount', cap: 100, unit: 'units' } })], {}, 1, 'stated-wider'],
    ['lifecycle after vs allow', 'allow', [r('allow', { lifecycle: { transition: 'suspend', subject: 'actor', after: 'deny' } })], {}, 1, 'stated-stricter'],
    ['own allow vs allow', 'allow', [r('allow', { relation: 'own' })], {}, 0, 'agrees-where-stated'],
    ['every relation allow vs allow', 'allow', ['own', 'other-same-role', 'other-role', 'cross-tenant'].map((relation, i) => ({ ...r('allow', { relation }), ruleId: `R${i}` })), {}, 0, 'agrees'],
    ['state deny and default deny vs deny', 'deny', [r('deny', { state: 'archived' })], { defaults: { unlisted: 'deny' } }, 0, 'agrees'],
    ['own allow vs conditional', 'conditional', [r('allow', { relation: 'own' })], {}, 3, 'unresolved'],
  ];
  for (const [label, declared, rules, extra, exit, agreement] of cases) {
    const file = at(`${label.replace(/ /g, '-')}.json`), mfile = at(`${label.replace(/ /g, '-')}.matrix.json`), report = at(`${label.replace(/ /g, '-')}.report.json`);
    await writeFile(file, JSON.stringify(seal(rules, extra)));
    await writeFile(mfile, JSON.stringify(one(declared)));
    assert.equal(await main(['statement', 'check', file, mfile, '--out', report], quiet), exit, label);
    const row = JSON.parse(await readFile(report, 'utf8')).rows[0];
    assert.equal(row.agreement, agreement, label);
    if (label.startsWith('capped')) {
      assert.ok(row.parts.some(p => p.part === 'over-limit' && p.limit.cap === 100 && p.decision === 'deny'), 'the limit is kept in the output');
      assert.equal(row.stated.limit.cap, 100, 'and on the whole-cell reading');
    }
  }
  // A state-only allow covers its state, not the cell.
  assert.equal(checkStatement(seal([r('allow', { state: 'active' })]), { matrices: [one('allow')] }).rows[0].agreement, 'agrees-where-stated');
  // With one tenant there is no cross-tenant variant, so the three other relations cover the cell.
  const local = seal(['own', 'other-same-role', 'other-role'].map((relation, i) => ({ ...r('allow', { relation }), ruleId: `L${i}` })), { tenants: ['acme'] });
  assert.equal(checkStatement(local, { matrices: [one('allow')] }).rows[0].agreement, 'agrees');
  assert.equal(checkStatement(seal(['own', 'other-same-role', 'other-role'].map((relation, i) => ({ ...r('allow', { relation }), ruleId: `L${i}` }))), { matrices: [one('allow')] }).rows[0].agreement,
    'agrees-where-stated', 'with two tenants the cross-tenant variant is unstated');
  // The default covers the statement's roles only: a matrix role the statement does not list stays declared-only.
  const outsider = checkStatement(seal([], { defaults: { unlisted: 'deny' } }), { matrices: [matrixOf([['service', 'public.jobs', 'SELECT', 'allow']])] });
  assert.deepEqual([outsider.rows[0].agreement, outsider.disagreements.length], ['declared-only', 0]);
});

// Kept apart so each runs even when an earlier refusal in the adoption test fails first.
test('adoption and source edges: a stated source never names an adoption; an adoption never moves to another cell', () => {
  // A stated source that also names an adoption is refused, even with a valid source and locator.
  refuse([{ ...stated('y', 'anon', 'public.notes', 'SELECT', 'deny'), source: { sourceId: 'policy', locator: 'y', adoptedFrom: { matrixId: MATRIX.matrixId, cellKey: key('anon', 'public.notes', 'SELECT') } } }], /source has unknown field adoptedFrom/);
  // An adoption that points at another cell is refused even when that cell declares the same decision.
  const twoAllow = matrixOf([['authenticated', 'public.notes', 'SELECT', 'allow'], ['authenticated', 'public.files', 'SELECT', 'allow']]);
  const shifted = adopted('shifted', 'authenticated', 'public.notes', 'SELECT', 'allow', twoAllow); shifted.source.adoptedFrom.cellKey = key('authenticated', 'public.files', 'SELECT');
  assert.throws(() => seal([shifted], {}, [twoAllow]), /keeps the declaration's role, resource and action/);
});

// The whole-cell summary agrees with the parts, an unresolved comparison has its
// own exit status, and the CLI's own help says the labels authenticate no one.
test('check: the whole-cell reading agrees with the parts, and unresolved exits 3 (2 > 1 > 3 > 0)', async t => {
  const dir = await scratch(t), at = n => join(dir, n), quiet = { out: () => {} };
  const r = (decision, extra = {}) => stated('R1', 'authenticated', 'public.notes', 'SELECT', decision, extra);
  // Every concrete relation allows and the default denies the rest, but no rest is left: the row agrees, and its
  // whole-cell reading is not the default (no rule covers the whole cell, so it is null).
  const exhaustive = seal(['own', 'other-same-role', 'other-role', 'cross-tenant'].map((relation, i) => ({ ...r('allow', { relation }), ruleId: `R${i}` })), { defaults: { unlisted: 'deny' } });
  const s1 = checkStatement(exhaustive, { matrices: [matrixOf([['authenticated', 'public.notes', 'SELECT', 'allow']])] }).rows[0];
  assert.deepEqual([s1.agreement, s1.rest, s1.stated], ['agrees', null, null]);
  assert.ok(s1.parts.every(p => p.decision === 'allow'));
  // A whole-cell rule, or the default alone, still gives the reading.
  assert.equal(checkStatement(seal([r('allow')]), { matrices: [matrixOf([['authenticated', 'public.notes', 'SELECT', 'allow']])] }).rows[0].stated.ruleId, 'R1');
  assert.equal(checkStatement(seal([], { defaults: { unlisted: 'deny' } }), { matrices: [matrixOf([['authenticated', 'public.notes', 'SELECT', 'allow']])] }).rows[0].stated.confidence, 'stated-default');
  // U1-U4 through the CLI: an opposed or a matching conditional is unresolved (3), a whole-cell agreement 0, a uniform deny 1.
  const conditional = matrixOf([['authenticated', 'public.notes', 'SELECT', 'conditional', ["state = 'active'"]]]);
  const cases = [
    ['U1 opposed conditional', seal([r('deny', { state: 'active' }), { ...r('allow', { state: 'archived' }), ruleId: 'R2' }], { defaults: { unlisted: 'deny' } }), conditional, 3, 'unresolved'],
    ['U2 matching conditional', seal([r('allow', { state: 'active' })], { defaults: { unlisted: 'deny' } }), conditional, 3, 'unresolved'],
    ['U3 whole-cell agreement', seal([r('allow')]), matrixOf([['authenticated', 'public.notes', 'SELECT', 'allow']]), 0, 'agrees'],
    ['U4 uniform deny vs conditional', seal([r('deny')]), conditional, 1, 'stated-stricter'],
  ];
  for (const [label, statement, matrix, exit, agreement] of cases) {
    const f = at(`${label.slice(0, 2)}.json`), m = at(`${label.slice(0, 2)}.matrix.json`), o = at(`${label.slice(0, 2)}.out.json`);
    await writeFile(f, JSON.stringify(statement)); await writeFile(m, JSON.stringify(matrix));
    assert.equal(await main(['statement', 'check', f, m, '--out', o], quiet), exit, label);
    const row = JSON.parse(await readFile(o, 'utf8')).rows[0];
    assert.equal(row.agreement, agreement, label);
    // A state-only rule never covers the whole cell, even beside a default: no whole-cell reading.
    if (label.startsWith('U2')) assert.equal(row.stated, null, label);
  }
  // A difference wins over an unresolved cell: one of each exits 1.
  const both = at('both.json'), bm = at('both.matrix.json');
  await writeFile(both, JSON.stringify(seal([r('deny', { state: 'active' }), stated('D', 'anon', 'public.notes', 'SELECT', 'allow')])));
  await writeFile(bm, JSON.stringify(matrixOf([['authenticated', 'public.notes', 'SELECT', 'conditional', ["state = 'active'"]], ['anon', 'public.notes', 'SELECT', 'deny']])));
  assert.equal(await main(['statement', 'check', both, bm], quiet), 1);
  // The CLI's own help and usage say the labels authenticate no one.
  const lines = [];
  assert.equal(await main(['--help'], { out: l => lines.push(l) }), 0);
  assert.match(lines.join('\n'), /--stated-by and --confirmed-by are free-text labels the caller supplies; they authenticate no one/);
  await assert.rejects(main(['statement', 'nothing'], quiet), /authenticate no one/);
  await assert.rejects(main(['bogus'], quiet), /authenticate no one/);
});

test('guards on the check path and the JS API: a malformed adoption id is refused even with a recomputed id; a hidden candidate flag is refused', () => {
  // check does not look adoptions up, so the structural guard is what refuses a malformed matrix id there.
  const s = seal([adopted('anon-read', 'anon', 'public.notes', 'SELECT', 'deny')]);
  const { statementId: _id, ...body } = structuredClone(s);
  body.rules[0].source.adoptedFrom.matrixId = 'not-a-matrix-id';
  const forged = { ...body, statementId: sha256(canonical(body)) };
  assert.ok(verifyStatement(forged));
  assert.throws(() => checkStatement(forged), /source.adoptedFrom is \{ matrixId, cellKey \}/);
  // CAND: a candidate flag the JSON form cannot carry (non-enumerable) is still refused through the exported API.
  const hidden = stated('h', 'anon', 'public.notes', 'SELECT', 'deny');
  Object.defineProperty(hidden, 'candidate', { value: true, enumerable: false });
  assert.throws(() => seal([hidden]), /is still a candidate/);
});

