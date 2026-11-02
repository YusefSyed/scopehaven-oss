// Check packs (scopehaven-pack/1): a directory of check templates with parameters, so the next engagement starts from the
// last one's checks. A pack directory holds
//   manifest.json  name, version, the behaviour it checks, its parameters, and a sha256 per file it ships
//   checks.json    the check templates (scopehaven-pack-checks/1) and the required controls they add
//   cases.json     its known-negative self-test cases (scopehaven-pack-cases/1): parameter sets, each with the outcome
//                  src/known-negative.mjs must give every check, so the pack's own checks are shown able to fail
// Packs are named by the behaviour they check, never by a regulation, until a mapping is approved
// ("regulation": null in every shipped manifest).
// A template is plain profile JSON. A string that is exactly "{{name}}" becomes the parameter's value (any type); a
// string with "{{name}}" inside it takes a string or integer value in place; "{{actor.principalId}}" reads a field of the
// actor a parameter names, from the profile. "when": "name" on a check, an assertion or an effect keeps it only when that
// optional parameter is given. "{{as}}" is the instance's id prefix. Nothing else is evaluated. A pack may also add target
// lifecycle entries ("lifecycle" in checks.json: an account change mid-run, such as a session the user revokes).
// Pure apart from readPack, which reads one pack directory (regular files only, size-bounded).
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { canonical } from '../policy-import/matrix.mjs';

export const PACK_SCHEMA = 'scopehaven-pack/1';
export const PACK_CHECKS_SCHEMA = 'scopehaven-pack-checks/1';
export const PACK_CASES_SCHEMA = 'scopehaven-pack-cases/1';
export const PACK_FILES = Object.freeze(['checks.json', 'cases.json']);
export const PACK_LIMITS = Object.freeze({ fileBytes: 256 * 1024, checks: 32, parameters: 24 });
// statuses: 2 to 5 distinct 4xx statuses; refusals: 2 to 5 distinct 3xx or 4xx (a sign-in redirect counts as a refusal).
export const PARAMETER_TYPES = Object.freeze(['actor', 'path', 'string', 'integer', 'status', 'statuses', 'refusals', 'pointer']);
// The fields a check template may carry: a check's own fields, never applicability (a check declared not applicable is never
// sent, so it could never fail) or any other field the gate cannot see through.
export const TEMPLATE_CHECK_FIELDS = Object.freeze(['id', 'title', 'category', 'severity', 'actorId', 'method', 'path', 'evidenceRequirement', 'assertions', 'body', 'timeoutMs', 'effects', 'when']);
const NAME = /^[a-z][a-z0-9-]{1,47}$/, VERSION = /^\d{1,3}\.\d{1,3}\.\d{1,3}$/, AS = /^[A-Z][A-Z0-9-]{0,23}$/, PARAM = /^[a-z][A-Za-z0-9]{0,31}$/;
const SAFE_PATH = /^\/(?!\/)[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export const sha256Hex = bytes => createHash('sha256').update(bytes).digest('hex');

export class PackError extends Error {
  constructor(code, detail) { super(`Check pack refused (${code}): ${detail}`); this.name = 'PackError'; this.code = code; }
}
const refuse = (code, detail) => { throw new PackError(code, detail); };

/** One regular file, opened without following a link or blocking on a pipe, read up to its limit from the same descriptor
 * it was checked on (as src/registry.mjs loadProfiles reads a profile). */
export async function readRegular(path, { limit = PACK_LIMITS.fileBytes, missing = 'pack-file-missing', invalid = 'pack-file-invalid' } = {}) {
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { refuse(error?.code === 'ENOENT' ? missing : invalid, error?.code === 'ENOENT' ? `${path} does not exist` : error?.code === 'ELOOP' ? `${path} is a link; a pack file, lock or profile must be the file itself` : `${path} cannot be opened (${error?.code ?? 'error'})`); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) refuse(invalid, `${path} must be a regular file`);
    if (stat.size > limit) refuse(invalid, `${path} is larger than ${limit} bytes`);
    const bytes = Buffer.alloc(limit + 1); let size = 0;
    while (size < bytes.length) { const { bytesRead } = await handle.read(bytes, size, bytes.length - size, size); if (!bytesRead) break; size += bytesRead; }
    if (size > limit) refuse(invalid, `${path} is larger than ${limit} bytes`);
    return bytes.subarray(0, size);
  } finally { await handle.close(); }
}
const readBounded = path => readRegular(path);
const parse = (bytes, path) => { try { return JSON.parse(bytes.toString('utf8')); } catch { refuse('pack-file-invalid', `${path} is not valid JSON`); } };

/** Reads one pack directory and checks it against its own manifest: every listed file present with the sha256 the
 * manifest gives, and nothing unlisted relied on. Returns { manifest, checks, cases, digests: { manifest, files } }. */
export async function readPack(dir) {
  const manifestBytes = await readBounded(join(dir, 'manifest.json'));
  const manifest = validateManifest(parse(manifestBytes, join(dir, 'manifest.json')));
  const files = {}, parsed = {};
  for (const name of PACK_FILES) {
    const bytes = await readBounded(join(dir, name));
    files[name] = sha256Hex(bytes);
    if (files[name] !== manifest.files[name]) refuse('pack-digest-mismatch', `${manifest.name}@${manifest.version} ${name} has sha256 ${files[name].slice(0, 12)}..., its manifest says ${manifest.files[name].slice(0, 12)}...`);
    parsed[name] = parse(bytes, join(dir, name));
  }
  const checks = validateTemplates(parsed['checks.json'], manifest), cases = validateCases(parsed['cases.json'], manifest);
  return { manifest, checks, cases, digests: { manifest: sha256Hex(manifestBytes), files } };
}

export function validateManifest(m) {
  if (!plain(m) || m.schema !== PACK_SCHEMA) refuse('pack-manifest-invalid', `a manifest needs schema "${PACK_SCHEMA}"`);
  const extra = Object.keys(m).find(k => !['schema', 'name', 'version', 'behaviour', 'derivedFrom', 'parameters', 'constraints', 'files', 'regulation'].includes(k));
  if (extra) refuse('pack-manifest-invalid', `a manifest has no field "${extra}"`);
  if (typeof m.name !== 'string' || !NAME.test(m.name)) refuse('pack-manifest-invalid', 'name is 2-48 lower-case letters, digits or "-"');
  if (typeof m.version !== 'string' || !VERSION.test(m.version)) refuse('pack-manifest-invalid', `${m.name}: version is MAJOR.MINOR.PATCH`);
  if (typeof m.behaviour !== 'string' || !m.behaviour.trim() || m.behaviour.length > 400) refuse('pack-manifest-invalid', `${m.name}: behaviour is one sentence`);
  // Named by behaviour: a regulation mapping waits for approval.
  if (m.regulation !== null) refuse('pack-manifest-invalid', `${m.name}: "regulation" stays null until a mapping is approved`);
  if (!Array.isArray(m.derivedFrom) || !m.derivedFrom.length || !m.derivedFrom.every(s => typeof s === 'string' && s.length <= 300)) refuse('pack-manifest-invalid', `${m.name}: derivedFrom names the checks it was built from`);
  if (!plain(m.parameters) || Object.keys(m.parameters).length > PACK_LIMITS.parameters) refuse('pack-manifest-invalid', `${m.name}: parameters is an object of at most ${PACK_LIMITS.parameters}`);
  for (const [name, p] of Object.entries(m.parameters)) {
    if (!PARAM.test(name) || name === 'as') refuse('pack-manifest-invalid', `${m.name}: parameter "${name}" is not a valid name`);
    if (!plain(p) || !PARAMETER_TYPES.includes(p.type) || Object.keys(p).some(k => !['type', 'description', 'default', 'optional'].includes(k)) || typeof p.description !== 'string') refuse('pack-manifest-invalid', `${m.name}: parameter "${name}" needs a type (${PARAMETER_TYPES.join(', ')}) and a description`);
    if (Object.hasOwn(p, 'default')) checkValue(m.name, name, p, p.default);
  }
  // different-tenant: two actor parameters whose actors must declare different tenants.
  if (!Array.isArray(m.constraints ?? []) || !(m.constraints ?? []).every(c => Array.isArray(c) && ['different', 'greater', 'different-tenant'].includes(c[0]) && c.length === 3 && c.slice(1).every(n => Object.hasOwn(m.parameters, n)) && (c[0] !== 'different-tenant' || c.slice(1).every(n => m.parameters[n].type === 'actor')))) refuse('pack-manifest-invalid', `${m.name}: constraints are ["different" | "greater" | "different-tenant", parameter, parameter]`);
  if (!plain(m.files) || Object.keys(m.files).sort().join() !== [...PACK_FILES].sort().join() || !Object.values(m.files).every(h => /^[0-9a-f]{64}$/.test(h))) refuse('pack-manifest-invalid', `${m.name}: files gives a sha256 for exactly ${PACK_FILES.join(' and ')}`);
  return m;
}

function checkValue(pack, name, p, v) {
  const bad = why => refuse('pack-parameter-invalid', `${pack}: parameter "${name}" ${why}`);
  if (p.type === 'actor' || p.type === 'string') { if (typeof v !== 'string' || !v.length || v.length > 200 || /[\u0000-\u001f\u007f]/.test(v)) bad('is a non-empty string'); }
  else if (p.type === 'path') { if (typeof v !== 'string' || !SAFE_PATH.test(v) || v.length > 512) bad('is a safe absolute path'); }
  else if (p.type === 'pointer') { if (typeof v !== 'string' || !/^(\/[^/]*)+$/.test(v)) bad('is a JSON pointer below the root, such as /order/email'); }
  else if (p.type === 'integer') { if (!Number.isSafeInteger(v)) bad('is an integer'); }
  else if (p.type === 'status') { if (!Number.isInteger(v) || v < 100 || v > 599) bad('is an HTTP status'); }
  else if (p.type === 'statuses' || p.type === 'refusals') { const low = p.type === 'refusals' ? 300 : 400; if (!Array.isArray(v) || v.length < 2 || v.length > 5 || new Set(v).size !== v.length || !v.every(s => Number.isInteger(s) && s >= low && s <= 499)) bad(`is 2 to 5 distinct ${p.type === 'refusals' ? '3xx or 4xx' : '4xx'} statuses`); }
}

export function validateTemplates(doc, manifest) {
  if (!plain(doc) || doc.schema !== PACK_CHECKS_SCHEMA || !Array.isArray(doc.checks) || !doc.checks.length || doc.checks.length > PACK_LIMITS.checks || !Array.isArray(doc.requiredControlIds) || !Array.isArray(doc.lifecycle ?? [])) refuse('pack-checks-invalid', `${manifest.name}: checks.json is { schema "${PACK_CHECKS_SCHEMA}", checks, requiredControlIds, lifecycle? }`);
  if (Object.keys(doc).some(k => !['schema', 'checks', 'requiredControlIds', 'lifecycle'].includes(k))) refuse('pack-checks-invalid', `${manifest.name}: checks.json has an unknown field`);
  const used = new Set();
  JSON.stringify(doc, (k, v) => { if (typeof v === 'string') for (const m of v.matchAll(/\{\{([A-Za-z0-9.]+)\}\}/g)) used.add(m[1].split('.')[0]); return v; });
  // "when" is read on a check, an assertion or an effect only; anywhere else it is an ordinary key.
  for (const check of doc.checks) for (const item of [check, ...(Array.isArray(check?.assertions) ? check.assertions : []), ...(Array.isArray(check?.effects) ? check.effects : [])]) if (plain(item) && Object.hasOwn(item, 'when')) used.add(item.when);
  // A string first: a "when" of ["opt"] would pass this lookup, which coerces its key, while keep() gates only a string "when".
  for (const name of used) if (name !== 'as' && !(typeof name === 'string' && Object.hasOwn(manifest.parameters, name))) refuse('pack-checks-invalid', `${manifest.name}: a template names "{{${name}}}", which is not a parameter`);
  for (const check of doc.checks) {
    if (!plain(check) || typeof check.id !== 'string' || !check.id.startsWith('{{as}}-')) refuse('pack-checks-invalid', `${manifest.name}: every check id starts with "{{as}}-", so two instances never share an id`);
    const extra = Object.keys(check).find(k => !TEMPLATE_CHECK_FIELDS.includes(k));
    if (extra) refuse('pack-checks-invalid', `${manifest.name}: check ${check.id} has field "${extra}", which a pack check may not carry (a pack check is always applicable and judged as written)`);
  }
  const ids = new Set(doc.checks.map(c => c.id));
  for (const id of doc.requiredControlIds) if (!ids.has(id)) refuse('pack-checks-invalid', `${manifest.name}: required control ${JSON.stringify(id)} is not one of the pack's checks`);
  for (const entry of doc.lifecycle ?? []) if (!plain(entry) || !ids.has(entry.changeCheckId) || typeof entry.actorId !== 'string' || !/^\{\{[a-z][A-Za-z0-9]*\}\}$/.test(entry.actorId) || manifest.parameters[entry.actorId.slice(2, -2)]?.type !== 'actor') refuse('pack-checks-invalid', `${manifest.name}: a lifecycle entry names one of the pack's own checks and an actor parameter`);
  return doc;
}

export function validateCases(doc, manifest) {
  if (!plain(doc) || doc.schema !== PACK_CASES_SCHEMA || !plain(doc.target) || !Array.isArray(doc.cases) || !doc.cases.length) refuse('pack-cases-invalid', `${manifest.name}: cases.json is { schema "${PACK_CASES_SCHEMA}", target, cases }`);
  for (const c of doc.cases) if (!plain(c) || typeof c.id !== 'string' || typeof c.as !== 'string' || !plain(c.params) || !plain(c.expect) || !Object.keys(c.expect).length) refuse('pack-cases-invalid', `${manifest.name}: each case is { id, as, params, expect: { checkId: outcome } }`);
  return doc;
}

/** The pack's checks for one reference ({ name, version, as, params }) in one target: parameters checked against the
 * manifest (types, defaults, constraints, actors the target declares), templates filled. Returns { checks, requiredControlIds,
 * lifecycle }: lifecycle holds the target lifecycle entries the pack adds (an account change mid-run, src/contracts.mjs). */
export function instantiate(pack, ref, target) {
  const { manifest } = pack;
  if (typeof ref.as !== 'string' || !AS.test(ref.as)) refuse('pack-reference-invalid', `${manifest.name}: "as" is the instance's id prefix, 1-24 upper-case letters, digits or "-", starting with a letter`);
  if (!plain(ref.params ?? {})) refuse('pack-reference-invalid', `${manifest.name}: params is an object`);
  const given = ref.params ?? {};
  const unknown = Object.keys(given).find(k => !Object.hasOwn(manifest.parameters, k));
  if (unknown) refuse('pack-parameter-invalid', `${manifest.name}: no parameter "${unknown}"`);
  const values = { as: ref.as };
  for (const [name, p] of Object.entries(manifest.parameters)) {
    const v = Object.hasOwn(given, name) ? given[name] : p.default;
    if (v === undefined) { if (p.optional) continue; refuse('pack-parameter-invalid', `${manifest.name}: parameter "${name}" is required`); }
    checkValue(manifest.name, name, p, v);
    if (p.type === 'actor' && !Object.hasOwn(target.actors ?? {}, v)) refuse('pack-parameter-invalid', `${manifest.name}: parameter "${name}" names actor "${v}", which the target does not declare`);
    values[name] = v;
  }
  for (const [rule, a, b] of manifest.constraints ?? []) {
    if (!Object.hasOwn(values, a) || !Object.hasOwn(values, b)) continue;
    if (rule === 'different' && canonical(values[a]) === canonical(values[b])) refuse('pack-parameter-invalid', `${manifest.name}: "${a}" and "${b}" must differ`);
    if (rule === 'greater' && !(values[a] > values[b])) refuse('pack-parameter-invalid', `${manifest.name}: "${a}" must be greater than "${b}"`);
    if (rule === 'different-tenant') { const ta = target.actors[values[a]]?.tenantId, tb = target.actors[values[b]]?.tenantId; if (typeof ta !== 'string' || typeof tb !== 'string' || ta === tb) refuse('pack-parameter-invalid', `${manifest.name}: "${a}" and "${b}" must be actors of two declared, different tenants`); }
  }
  const lookup = expr => {
    if (expr.split('.').length > 2) refuse('pack-checks-invalid', `${manifest.name}: "{{${expr}}}" reads at most one field`);
    const [name, field] = expr.split('.');
    if (!Object.hasOwn(values, name)) return { missing: true };
    if (field === undefined) return { value: values[name] };
    if (manifest.parameters[name]?.type !== 'actor' || !['principalId', 'tenantId', 'identityValue'].includes(field)) refuse('pack-checks-invalid', `${manifest.name}: "{{${expr}}}" reads principalId, tenantId or identityValue of an actor parameter only`);
    const actorField = target.actors[values[name]]?.[field];
    if (typeof actorField !== 'string') refuse('pack-parameter-invalid', `${manifest.name}: actor "${values[name]}" declares no ${field}`);
    return { value: actorField };
  };
  const fill = node => {
    if (typeof node === 'string') {
      const whole = /^\{\{([A-Za-z0-9.]+)\}\}$/.exec(node);
      if (whole) { const r = lookup(whole[1]); if (r.missing) refuse('pack-checks-invalid', `${manifest.name}: "${node}" is used without the optional parameter (mark its line "when")`); return structuredClone(r.value); }
      return node.replace(/\{\{([A-Za-z0-9.]+)\}\}/g, (_, expr) => { const r = lookup(expr); if (r.missing || !['string', 'number'].includes(typeof r.value)) refuse('pack-checks-invalid', `${manifest.name}: "{{${expr}}}" inside a string needs a string or integer value`); return String(r.value); });
    }
    if (Array.isArray(node)) return node.map(fill);
    if (plain(node)) return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, fill(v)]));
    return node;
  };
  // "when" on a check, an assertion or an effect: kept with its optional parameter (the key removed), dropped without it.
  // Anywhere else, such as inside a request body, "when" is an ordinary key and is filled like any other.
  const keep = item => !(plain(item) && typeof item.when === 'string' && !Object.hasOwn(values, item.when));
  const strip = item => { if (!plain(item) || !Object.hasOwn(item, 'when')) return item; const { when, ...rest } = item; return rest; };
  const chosen = pack.checks.checks.filter(keep).map(strip).map(c => ({ ...c, ...(Array.isArray(c.assertions) ? { assertions: c.assertions.filter(keep).map(strip) } : {}), ...(Array.isArray(c.effects) ? { effects: c.effects.filter(keep).map(strip) } : {}) }));
  const checks = fill(chosen);
  const ids = new Set(checks.map(c => c.id));
  // A required control a "when" dropped is dropped with it; validateTemplates refused any that names no template check.
  const requiredControlIds = fill(pack.checks.requiredControlIds).filter(id => ids.has(id));
  const lifecycle = fill(pack.checks.lifecycle ?? []);
  for (const entry of lifecycle) if (!ids.has(entry.changeCheckId) || !Object.hasOwn(target.actors ?? {}, entry.actorId)) refuse('pack-checks-invalid', `${manifest.name}: a lifecycle entry names a check this instance does not have, or an actor the target does not declare`);
  return { checks, requiredControlIds, lifecycle };
}
