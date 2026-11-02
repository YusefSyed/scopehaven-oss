// Check packs: the four shipped packs (manifests, digests, their own known-negative self-test cases), the lockfile every
// profile load checks, the self-test gate at load, and a run of all four on the pack app's fixed and defective builds.
// Loopback, synthetic data, no model, no provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readPack, instantiate, validateManifest, validateTemplates, sha256Hex, PackError } from './pack.mjs';
import { expandPacks, lockProfile, runCases, SHIPPED_PACKS, LOCK_FILE } from './expand.mjs';
import { main } from './cli.mjs';
import { packStatus, pullProfile, compareVersions, stateOf } from './pull.mjs';
import { loadProfiles } from '../../src/registry.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { createPackApp, bindPackProfile, PACK_APP_BUILDS } from './fixtures/pack-app.mjs';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const CLI = fileURLToPath(new URL('../../src/cli.mjs', import.meta.url));
const SHIPPED = ['discount-cap', 'refund-window', 'revocation', 'tenant-isolation'];
// Packs from the weekly incident intake, checked in integrations/class-templates/intake-packs.test.mjs.
const INTAKE_PACKS = ['blocked-route-egress'];
const whoami = (id, actor, email) => ({ id, title: `${actor} session is ${actor} (${id})`, category: 'Identity', severity: 'control', actorId: actor, method: 'GET', path: '/api/me', evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: email }] });
const REFS = {
  TI: { name: 'tenant-isolation', version: '1.0.0', as: 'TI', params: { actor: 'agentB', foreignOwner: 'agentA', ownPath: '/api/orders/B-1', foreignPath: '/api/orders/A-1', leakPointer: '/order/customerEmail' } },
  RW: { name: 'refund-window', version: '1.0.0', as: 'RW', params: { actor: 'agentB', recentPath: '/api/orders/B-1/refunds', stalePath: '/api/orders/B-9/refunds', effectName: 'payments.example', resourcePrefix: 'POST /v1/refunds/' } },
  DC: { name: 'discount-cap', version: '1.0.0', as: 'DC', params: { actor: 'agentB', capPath: '/api/orders/B-3/discounts', overCapPath: '/api/orders/B-2/discounts', capPercent: 20, overCapPercent: 35, effectName: 'payments.example', resourcePrefix: 'POST /v1/discounts/' } },
  RV: { name: 'revocation', version: '1.0.0', as: 'RV', params: { actor: 'agentR', readPath: '/api/orders/B-1', revokePath: '/api/sessions/revoke', writeBeforePath: '/api/orders/B-1/notes', writePath: '/api/orders/B-2/notes', effectName: 'crm.example', resourcePrefix: 'POST /v1/notes/' } },
};
let caseTarget;
const profileWith = (refs = Object.values(REFS), checks = null) => ({ schemaVersion: 1, targets: [{ ...structuredClone(caseTarget), id: 'pack-app', name: 'Pack app', applicationId: 'pack-app', buildLabel: 'pack app, local test build',
  requiredControlIds: ['B-WHOAMI', 'B-WHOAMI-AFTER'],
  checks: checks ?? [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), ...refs.filter(r => r.as !== 'RV').map(r => ({ pack: r.as })), whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test'), ...refs.filter(r => r.as === 'RV').map(() => ({ pack: 'RV' }))],
  packs: structuredClone(refs) }] });
async function dirWith(t, name = 'scopehaven packs ') { const dir = await mkdtemp(join(tmpdir(), name)); t.after(() => rm(dir, { recursive: true, force: true })); return dir; }
async function written(t, profile, { lock = true } = {}) {
  const dir = await dirWith(t), file = join(dir, 'pack-app.targets.json');
  await writeFile(file, JSON.stringify(profile));
  if (lock) await lockProfile(file);
  return { dir, file };
}
const code = async promise => { try { await promise; return 'loaded'; } catch (e) { return e instanceof PackError ? e.code : `other: ${e.message}`; } };
test.before(async () => { caseTarget = JSON.parse(await readFile(join(SHIPPED_PACKS, 'revocation', 'cases.json'), 'utf8')).target; });

test('the four shipped packs match their manifests, are named by behaviour, and their own self-test cases read proven', async () => {
  for (const name of SHIPPED) {
    const pack = await readPack(join(SHIPPED_PACKS, name));
    assert.equal(pack.manifest.name, name);
    assert.equal(pack.manifest.version, '1.0.0');
    assert.equal(pack.manifest.regulation, null, `${name}: no regulation mapping until one is approved`);
    assert.doesNotMatch(name, /(^|-)(gdpr|hipaa|pci|sox|ccpa|dora|iso\d*|nist|eu-ai|soc\d*)(-|$)/i);
    for (const file of ['checks.json', 'cases.json']) assert.equal(sha256Hex(await readFile(join(SHIPPED_PACKS, name, file))), pack.manifest.files[file]);
    assert.ok(pack.manifest.derivedFrom.some(d => /owned fixture suite: [A-Z]+-\d+/.test(d)), `${name} cites the owned fixture checks it was built from`);
    const results = runCases(pack);
    assert.ok(results.length >= 1);
    for (const r of results) { assert.ok(r.ok, `${name} ${r.id}: ${JSON.stringify(r.outcomes)}`); assert.ok(Object.values(r.outcomes).every(o => o === 'proven')); }
  }
});

test('locked and loaded, the packs expand in place into ordinary checks, controls and the revocation lifecycle entry', async t => {
  const { file, dir } = await written(t, profileWith());
  const lock = JSON.parse(await readFile(join(dir, LOCK_FILE), 'utf8'));
  assert.deepEqual(lock.packs.map(p => [p.name, p.version, p.from, p.selfTest]), SHIPPED.map(n => [n, '1.0.0', null, { cases: n === 'tenant-isolation' ? 2 : 1, passed: n === 'tenant-isolation' ? 2 : 1 }]));
  assert.equal((await stat(join(dir, LOCK_FILE))).mode & 0o777, 0o600);
  const [target] = await loadProfiles(file);
  assert.deepEqual(target.checks.map(c => c.id), ['B-WHOAMI', 'TI-OWN', 'TI-OWNER-ID', 'TI-FOREIGN-OWNER', 'TI-OWNER-ID-CLOSE', 'TI-FOREIGN', 'RW-IN-WINDOW', 'RW-OUT-OF-WINDOW', 'DC-AT-CAP', 'DC-OVER-CAP', 'B-WHOAMI-AFTER', 'RV-ID', 'RV-BEFORE', 'RV-WRITE-BEFORE', 'RV-ID-CLOSE', 'RV-REVOKE', 'RV-AFTER']);
  assert.deepEqual(target.requiredControlIds, ['B-WHOAMI', 'B-WHOAMI-AFTER', 'TI-OWN', 'TI-OWNER-ID', 'TI-FOREIGN-OWNER', 'TI-OWNER-ID-CLOSE', 'RW-IN-WINDOW', 'DC-AT-CAP', 'RV-ID', 'RV-BEFORE', 'RV-WRITE-BEFORE', 'RV-ID-CLOSE', 'RV-REVOKE']);
  assert.deepEqual(target.lifecycle, [{ changeCheckId: 'RV-REVOKE', actorId: 'agentR', after: 'refused' }]);
  const over = target.checks.find(c => c.id === 'DC-OVER-CAP');
  assert.deepEqual([over.body, over.assertions, over.effects], [{ percent: 35 }, [{ kind: 'status.in', expected: [400, 403, 422] }], [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: 'payments.example', resource: { prefix: 'POST /v1/discounts/' } } }]]);
  assert.equal(target.checks.find(c => c.id === 'RV-ID').assertions[1].expected, 'agent-r@globex.test', '{{actor.identityValue}} reads the profile actor');
  // Without a placeholder, an instance goes after the target's own checks.
  const appended = await written(t, profileWith([REFS.TI], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')]));
  assert.deepEqual((await loadProfiles(appended.file))[0].checks.map(c => c.id), ['B-WHOAMI', 'B-WHOAMI-AFTER', 'TI-OWN', 'TI-OWNER-ID', 'TI-FOREIGN-OWNER', 'TI-OWNER-ID-CLOSE', 'TI-FOREIGN']);
});

test('on the pack app, each pack fails only the build that breaks its rule, and over-blocking fails the controls', async t => {
  const { file } = await written(t, profileWith());
  const [loaded] = await loadProfiles(file);
  const PROHIBITIONS = { 'cross-tenant': 'TI-FOREIGN', 'no-window': 'RW-OUT-OF-WINDOW', 'no-cap': 'DC-OVER-CAP', 'revocation-ignored': 'RV-AFTER' };
  for (const build of PACK_APP_BUILDS) {
    const app = await createPackApp({ build });
    try {
      const run = await runHttpAssessment(bindPackProfile({ schemaVersion: 1, targets: [loaded] }, app).targets[0], { env: app.env });
      const status = Object.fromEntries(run.results.map(r => [r.id, r.status]));
      if (build === 'refuse-all') {
        // Every control on an order route fails (identity and the revocation route are not order routes).
        for (const id of ['TI-OWN', 'TI-FOREIGN-OWNER', 'RW-IN-WINDOW', 'DC-AT-CAP', 'RV-BEFORE', 'RV-WRITE-BEFORE']) assert.equal(status[id], 'fail', `${build} ${id}`);
        for (const id of Object.values(PROHIBITIONS)) assert.notEqual(status[id], 'pass', `${build} ${id}: refusing everything never passes a prohibition`);
        continue;
      }
      const failed = Object.entries(status).filter(([, s]) => s !== 'pass').map(([id, s]) => `${id}=${s}`);
      assert.deepEqual(failed, build === 'secure' ? [] : [`${PROHIBITIONS[build]}=fail`], build);
    } finally { await app.close(); }
  }
});

test('a load refuses a pack the lock does not pin, whose files changed, or whose lock was edited', async t => {
  // No lock at all.
  assert.equal(await code(loadProfiles((await written(t, profileWith(), { lock: false })).file)), 'pack-lock-missing');
  // A reference added after locking.
  const late = await written(t, profileWith([REFS.TI]));
  const added = profileWith([REFS.TI, { ...REFS.RW }]);
  await writeFile(late.file, JSON.stringify(added));
  assert.equal(await code(loadProfiles(late.file)), 'pack-not-locked');
  // An operator's own pack ("from"), locked, then edited: an edit the manifest does not cover, then one re-sealed into it.
  const { dir, file } = await written(t, profileWith(), { lock: false });
  await cp(join(SHIPPED_PACKS, 'tenant-isolation'), join(dir, 'packs', 'tenant-isolation'), { recursive: true });
  const own = profileWith([{ ...REFS.TI, from: 'packs' }], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), { pack: 'TI' }, whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')]);
  await writeFile(file, JSON.stringify(own)); await lockProfile(file);
  assert.equal(await code(loadProfiles(file)), 'loaded');
  const checksPath = join(dir, 'packs', 'tenant-isolation', 'checks.json'), original = await readFile(checksPath, 'utf8');
  await writeFile(checksPath, original.replace('"expected": 200', '"expected": 202'));
  assert.equal(await code(loadProfiles(file)), 'pack-digest-mismatch', 'a file that no longer matches its manifest');
  assert.equal(await code(lockProfile(file, { replace: true })), 'pack-digest-mismatch', 'and pack lock refuses to pin a file its manifest does not cover');
  assert.equal(await main(['seal', join(dir, 'packs', 'tenant-isolation')], { log: () => {} }), 0);
  assert.equal(await code(loadProfiles(file)), 'pack-digest-mismatch', 'a re-sealed pack no longer matches the lock');
  assert.equal(await main(['lock', '--config', file, '--update'], { log: () => {} }), 0);
  assert.equal(await code(loadProfiles(file)), 'loaded', 'relocking takes the change in, on purpose');
  const lock = JSON.parse(await readFile(join(dir, LOCK_FILE), 'utf8')); lock.packs[0].manifest = '0'.repeat(64);
  await writeFile(join(dir, LOCK_FILE), JSON.stringify(lock));
  assert.equal(await code(loadProfiles(file)), 'pack-lock-invalid', 'an edited lock');
  // A version the directory does not hold.
  const wrong = await written(t, profileWith([REFS.TI]), { lock: false });
  await writeFile(wrong.file, JSON.stringify(profileWith([{ ...REFS.TI, version: '1.1.0' }])));
  assert.equal(await code(lockProfile(wrong.file)), 'pack-version-mismatch');
});

test('a pack cannot load a check that is not shown able to fail, with this profile\'s own observers', async t => {
  const { dir, file } = await written(t, profileWith(), { lock: false });
  const pdir = join(dir, 'packs', 'tenant-isolation');
  await cp(join(SHIPPED_PACKS, 'tenant-isolation'), pdir, { recursive: true });
  const own = [{ ...REFS.TI, from: 'packs' }];
  const reseal = async edit => {
    const checks = JSON.parse(await readFile(join(SHIPPED_PACKS, 'tenant-isolation', 'checks.json'), 'utf8')); edit(checks);
    await writeFile(join(pdir, 'checks.json'), JSON.stringify(checks));
    const cases = JSON.parse(await readFile(join(pdir, 'cases.json'), 'utf8'));
    for (const c of cases.cases) c.expect = Object.fromEntries(Object.keys(c.expect).map(k => [k, 'proven']));
    await writeFile(join(pdir, 'cases.json'), JSON.stringify(cases));
    return main(['seal', pdir], { log: () => {} });
  };
  // A refusal whose only response predicate is "a JSON value exists at the root": it cannot fail.
  const foreign = c => c.checks.find(x => x.id === '{{as}}-FOREIGN');
  // Its own cases say every check is proven, and the planted one is not: seal refuses and writes nothing, so the edited file
  // no longer matches the manifest and the lock refuses it.
  assert.equal(await reseal(c => { foreign(c).assertions = [{ kind: 'status.in', expected: [403, 404] }, { kind: 'json.exists', pointer: '', expected: true }]; }), 2);
  await writeFile(file, JSON.stringify(profileWith(own)));
  await assert.rejects(lockProfile(file), e => e.code === 'pack-digest-mismatch');
  // Its own cases updated to say so, seal accepts it, and the lock still refuses: the profile's expansion goes through the same gate as a load.
  const cases = JSON.parse(await readFile(join(pdir, 'cases.json'), 'utf8'));
  for (const c of cases.cases) c.expect[`${c.as}-FOREIGN`] = 'broken';
  await writeFile(join(pdir, 'cases.json'), JSON.stringify(cases)); assert.equal(await main(['seal', pdir], { log: () => {} }), 0);
  await assert.rejects(lockProfile(file), e => e.code === 'pack-check-cannot-fail' && /TI-FOREIGN \(tenant-isolation as TI\) reads broken in the known-negative self-test: json\.exists cannot-fail/.test(e.message));
  // An effect clause no declared observer can record: unprovable here, so refused rather than run blind.
  await reseal(c => { foreign(c).effects = [{ kind: 'effect.none', select: { source: 'smtp-capture', operation: 'send', name: 'mail.example' } }]; foreign(c).evidenceRequirement = 'backend'; });
  const cases2 = JSON.parse(await readFile(join(pdir, 'cases.json'), 'utf8'));
  for (const c of cases2.cases) c.expect[`${c.as}-FOREIGN`] = 'partial';
  await writeFile(join(pdir, 'cases.json'), JSON.stringify(cases2)); await main(['seal', pdir], { log: () => {} });
  await assert.rejects(lockProfile(file), e => e.code === 'pack-check-cannot-fail' && /TI-FOREIGN .* effect\.none unprovable \(no-observer\)/.test(e.message));
});

test('parameters are checked against the manifest: types, required, defaults, constraints, declared actors, instance ids', async () => {
  const pack = await readPack(join(SHIPPED_PACKS, 'discount-cap'));
  const target = { actors: caseTarget.actors };
  const params = REFS.DC.params;
  const refusal = (ref, re) => assert.throws(() => instantiate(pack, ref, target), e => e instanceof PackError && re.test(e.message));
  refusal({ as: 'DC', params: { ...params, extra: 1 } }, /no parameter "extra"/);
  refusal({ as: 'DC', params: { ...params, capPercent: undefined } }, /"capPercent" is an integer|"capPercent" is required/);
  const { capPercent, ...missing } = params; refusal({ as: 'DC', params: missing }, /"capPercent" is required/);
  refusal({ as: 'DC', params: { ...params, overCapPercent: 20 } }, /"overCapPercent" must be greater than "capPercent"/);
  refusal({ as: 'DC', params: { ...params, actor: 'nobody' } }, /names actor "nobody", which the target does not declare/);
  refusal({ as: 'DC', params: { ...params, capPath: 'https://elsewhere.example/x' } }, /safe absolute path/);
  refusal({ as: 'DC', params: { ...params, refusalStatuses: [422] } }, /2 to 5 distinct 4xx/);
  refusal({ as: 'dc', params }, /"as" is the instance's id prefix/);
  assert.deepEqual(instantiate(pack, { as: 'DC', params }, target).checks.find(c => c.id === 'DC-AT-CAP').assertions, [{ kind: 'status.equals', expected: 201 }], 'a default fills an unset parameter');
  assert.equal(instantiate(await readPack(join(SHIPPED_PACKS, 'tenant-isolation')), { as: 'TS', params: { actor: 'agentB', foreignOwner: 'agentA', ownPath: '/a', foreignPath: '/b' } }, target).checks.find(c => c.id === 'TS-FOREIGN').assertions.length, 1, 'a "when" line is dropped without its optional parameter');
  refusal({ as: 'DC', params: { ...params, refusalStatuses: [302, 422] } }, /2 to 5 distinct 4xx/);
  const rv = await readPack(join(SHIPPED_PACKS, 'revocation'));
  assert.deepEqual(instantiate(rv, { as: 'RV', params: { ...REFS.RV.params, refusalStatuses: [302, 401] } }, target).checks.find(c => c.id === 'RV-AFTER').assertions[0].expected, [302, 401], 'a sign-in redirect can be a revocation refusal');
});

test('manifests and templates are read exactly: no regulation mapping, no unknown placeholder, ids prefixed per instance', async () => {
  const base = JSON.parse(await readFile(join(SHIPPED_PACKS, 'tenant-isolation', 'manifest.json'), 'utf8'));
  assert.throws(() => validateManifest({ ...base, regulation: 'a regulation' }), /"regulation" stays null/);
  assert.throws(() => validateManifest({ ...base, files: { 'checks.json': base.files['checks.json'] } }), /a sha256 for exactly/);
  assert.throws(() => validateManifest({ ...base, extra: true }), /no field "extra"/);
  const pack = await readPack(join(SHIPPED_PACKS, 'tenant-isolation'));
  const { validateTemplates } = await import('./pack.mjs');
  assert.throws(() => validateTemplates({ ...pack.checks, checks: [{ ...pack.checks.checks[0], path: '{{secretPath}}' }] }, pack.manifest), /names "\{\{secretPath\}\}", which is not a parameter/);
  assert.throws(() => validateTemplates({ ...pack.checks, checks: [{ ...pack.checks.checks[0], id: 'FIXED-ID' }] }, pack.manifest), /starts with "\{\{as\}\}-"/);
});

test('a profile without packs loads exactly as before, and duplicate or unknown instance names are refused', async t => {
  const plain = profileWith([]); delete plain.targets[0].packs;
  plain.targets[0].checks = [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')];
  assert.equal(await expandPacks(plain, { profileFile: '/nonexistent' }), plain);
  const { file } = await written(t, plain, { lock: false });
  assert.deepEqual((await loadProfiles(file))[0].checks.map(c => c.id), ['B-WHOAMI', 'B-WHOAMI-AFTER']);
  assert.equal(await code(lockProfile((await written(t, profileWith([REFS.TI, REFS.TI]), { lock: false })).file)), 'pack-reference-invalid');
  const unknown = profileWith([REFS.TI]); unknown.targets[0].checks.push({ pack: 'NOPE' });
  assert.equal(await code(lockProfile((await written(t, unknown, { lock: false })).file)), 'pack-reference-invalid');
});

test('check-config and the pack CLI: a locked profile loads, a tampered one exits 2 with the code, the lock is never overwritten', async t => {
  const { dir, file } = await written(t, profileWith([REFS.TI], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), { pack: 'TI' }, whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')]));
  const run = args => new Promise(resolve => execFile(process.execPath, [CLI, ...args], { env: { PATH: process.env.PATH } }, (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr })));
  const ok = await run(['--check-config', '--config', file]);
  assert.equal(ok.code, 0, ok.stderr);
  assert.equal(JSON.parse(ok.stdout).targets.find(x => x.id === 'pack-app').checks, 7);
  await assert.rejects(main(['lock', '--config', file], { log: () => {} }), /EEXIST/);
  const out = [];
  assert.equal(await main(['verify', '--config', file], { log: s => out.push(s) }), 0);
  assert.deepEqual(JSON.parse(out.at(-1)), { verified: true, targets: [{ id: 'pack-app', checks: 7 }] });
  assert.equal(await main(['list'], { log: s => out.push(s) }), 0);
  assert.deepEqual(JSON.parse(out.at(-1)).packs.map(p => [p.name, p.selfTest.every(s => s.endsWith('as expected'))]), [...SHIPPED, ...INTAKE_PACKS].sort().map(n => [n, true]));
  await writeFile(join(dir, LOCK_FILE), '{}');
  const bad = await run(['--check-config', '--config', file]);
  assert.equal(bad.code, 2);
  assert.match(bad.stderr, /Check pack refused \(pack-lock-invalid\)/);
});

test('no model, provider or outside host anywhere in the module: the product, policy-import\'s digest helpers, the watch-first line gate and node built-ins only', async () => {
  for (const name of ['pack.mjs', 'expand.mjs', 'cli.mjs', 'fixtures/pack-app.mjs']) {
    const source = await readFile(join(HERE, name), 'utf8');
    const imports = [...source.matchAll(/^import [^;]* from '([^']+)';$/gm), ...source.matchAll(/\bimport\('([^']+)'\)/g)].map(m => m[1]);
    for (const spec of imports) assert.match(spec, /^(node:(crypto|fs\/promises|fs|buffer|path|url|http)|\.\/[a-z-]+\.mjs|(\.\.\/)+src\/[a-z-]+\.mjs|\.\.\/policy-import\/matrix\.mjs|\.\.\/watch-first\/lines\.mjs)$/, `${name} imports ${spec}`);
    assert.doesNotMatch(source, /\bfetch\(|https:\/\/|net\.connect/i, name);
  }
});

test('a watch-first profile with packs locks and loads once its drafted lines are approved, and not before', async t => {
  const drafted = profileWith([REFS.TI], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), { pack: 'TI' },
    { ...whoami('WF-T9-ID', 'agentB', 'agent-b@globex.test'), drafted: 'observed', approved: false, observed: { record: 'r', turn: 'T9' } }, whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')]);
  const { file } = await written(t, drafted, { lock: false });
  await assert.rejects(lockProfile(file), /drafted line\(s\) no one has approved .*WF-T9-ID/);
  const approved = structuredClone(drafted); Object.assign(approved.targets[0].checks[2], { approved: true, approvedBy: 'A Person' });
  await writeFile(file, JSON.stringify(approved));
  await lockProfile(file);
  const out = [];
  assert.equal(await main(['verify', '--config', file], { log: s => out.push(s) }), 0);
  assert.deepEqual((await loadProfiles(file))[0].checks.map(c => c.id), ['B-WHOAMI', 'TI-OWN', 'TI-OWNER-ID', 'TI-FOREIGN-OWNER', 'TI-OWNER-ID-CLOSE', 'TI-FOREIGN', 'WF-T9-ID', 'B-WHOAMI-AFTER']);
});

test('a pack check cannot carry applicability or other fields, and its controls and lifecycle stay inside the instance', async () => {
  const pack = await readPack(join(SHIPPED_PACKS, 'revocation')), m = pack.manifest, doc = pack.checks;
  const edited = edit => { const d = structuredClone(doc); edit(d); return () => validateTemplates(d, m); };
  assert.throws(edited(d => { d.checks[5].applicability = { applies: false, reason: 'x' }; }), /has field "applicability", which a pack check may not carry/);
  assert.throws(edited(d => { d.checks[0].restsOn = []; }), /has field "restsOn"/);
  assert.throws(edited(d => { d.requiredControlIds.push('USER-CHECK'); }), /required control "USER-CHECK" is not one of the pack's checks/);
  assert.throws(edited(d => { d.lifecycle[0].changeCheckId = 'USER-CHECK'; }), /a lifecycle entry names one of the pack's own checks and an actor parameter/);
  assert.throws(edited(d => { d.lifecycle[0].actorId = 'agentB'; }), /a lifecycle entry names one of the pack's own checks and an actor parameter/);
  assert.throws(() => instantiate({ ...pack, checks: { ...doc, checks: [{ ...doc.checks[0], path: '{{actor.identityValue.x}}' }, ...doc.checks.slice(1)] } }, { as: 'RV', params: REFS.RV.params }, { actors: caseTarget.actors }), /reads at most one field/);
  // "when" is a key like any other inside a request body: validation reads it on checks, assertions and effects only.
  const bodyDoc = { ...doc, checks: doc.checks.map(c => c.id === '{{as}}-REVOKE' ? { ...c, body: { when: 'now', items: [{ when: 'identityPath', qty: 1 }] } } : c) };
  validateTemplates(bodyDoc, m);
  assert.deepEqual(instantiate({ ...pack, checks: bodyDoc }, { as: 'RV', params: REFS.RV.params }, { actors: caseTarget.actors }).checks.find(c => c.id === 'RV-REVOKE').body, { when: 'now', items: [{ when: 'identityPath', qty: 1 }] });
  assert.throws(edited(d => { d.checks[0].when = 'nothing'; }), /names "\{\{nothing\}\}", which is not a parameter/);
});

test('after locking, a profile edit that leaves a pack check unable to fail is refused at load, as are linked locks and pack files', async t => {
  const { dir, file } = await written(t, profileWith([REFS.RW], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), { pack: 'RW' }, whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')]));
  assert.equal(await code(loadProfiles(file)), 'loaded');
  const p = JSON.parse(await readFile(file, 'utf8')); delete p.targets[0].observers[0].settleMs; await writeFile(file, JSON.stringify(p));
  await assert.rejects(loadProfiles(file), e => e.code === 'pack-check-cannot-fail' && /RW-IN-WINDOW|RW-OUT-OF-WINDOW/.test(e.message));
  // A lock that is a link is refused, even to a valid lock.
  const linked = await dirWith(t), real = join(linked, 'real.lock');
  const second = await written(t, profileWith([REFS.TI]));
  await cp(join(second.dir, LOCK_FILE), real); await rm(join(second.dir, LOCK_FILE)); await symlink(real, join(second.dir, LOCK_FILE));
  assert.equal(await code(loadProfiles(second.file)), 'pack-lock-invalid');
  // A pack file that is a link is refused.
  const own = await written(t, profileWith([{ ...REFS.TI, from: 'packs' }]), { lock: false });
  await cp(join(SHIPPED_PACKS, 'tenant-isolation'), join(own.dir, 'packs', 'tenant-isolation'), { recursive: true });
  await cp(join(own.dir, 'packs', 'tenant-isolation', 'checks.json'), join(own.dir, 'checks.copy.json'));
  await rm(join(own.dir, 'packs', 'tenant-isolation', 'checks.json')); await symlink(join(own.dir, 'checks.copy.json'), join(own.dir, 'packs', 'tenant-isolation', 'checks.json'));
  assert.equal(await code(lockProfile(own.file)), 'pack-file-invalid');
  // A name that is not a pack name is refused before it is used in a path.
  assert.equal(await code(lockProfile((await written(t, profileWith([{ ...REFS.TI, name: '../tenant-isolation' }]), { lock: false })).file)), 'pack-reference-invalid');
});

test('one lock serves every profile in its directory: relocking one keeps the others pinned; verify needs packs', async t => {
  const dir = await dirWith(t), a = join(dir, 'a.targets.json'), b = join(dir, 'b.targets.json');
  await writeFile(a, JSON.stringify(profileWith([REFS.TI]))); await writeFile(b, JSON.stringify(profileWith([REFS.DC], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), { pack: 'DC' }, whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')])));
  await lockProfile(a); await lockProfile(b, { replace: true });
  assert.equal(await code(loadProfiles(a)), 'loaded'); assert.equal(await code(loadProfiles(b)), 'loaded');
  const plainFile = join(dir, 'plain.json'), plainProfile = profileWith([]); delete plainProfile.targets[0].packs;
  await writeFile(plainFile, JSON.stringify(plainProfile));
  await assert.rejects(main(['verify', '--config', plainFile], { log: () => {} }), /references no packs/);
});

test('a foreign path that answers 404 to everyone fails the owner\'s control instead of passing the refusal', async t => {
  const { file } = await written(t, profileWith([{ ...REFS.TI, params: { ...REFS.TI.params, foreignPath: '/api/orders/A-7' } }], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), { pack: 'TI' }, whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')]));
  const [loaded] = await loadProfiles(file);
  const app = await createPackApp({ build: 'cross-tenant' });
  try {
    const run = await runHttpAssessment(bindPackProfile({ schemaVersion: 1, targets: [loaded] }, app).targets[0], { env: app.env });
    const status = Object.fromEntries(run.results.map(r => [r.id, r.status]));
    assert.equal(status['TI-FOREIGN-OWNER'], 'fail', 'the owner cannot read a record that does not exist');
  } finally { await app.close(); }
});

test('a pack\'s account change may reach only its own checks, its owner must be another tenant, and its refusals obey the lifecycle rule', async t => {
  const userAfter = { id: 'R-NO-A-NOTE', title: 'Agent R cannot note an Acme order', category: 'Tenant isolation', severity: 'high', actorId: 'agentR', method: 'POST', path: '/api/orders/A-1/notes', body: {}, evidenceRequirement: 'backend',
    assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: 'crm.example', resource: { prefix: 'POST /v1/notes/' } } }] };
  const over = profileWith([REFS.RV], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test'), { pack: 'RV' }, userAfter]);
  await assert.rejects(lockProfile((await written(t, over, { lock: false })).file), e => e.code === 'pack-reference-invalid' && /would make R-NO-A-NOTE post-change checks of agentR/.test(e.message));
  // The owner must be of another tenant: agentR is Globex, as agentB is.
  assert.equal(await code(lockProfile((await written(t, profileWith([{ ...REFS.TI, params: { ...REFS.TI.params, foreignOwner: 'agentR' } }]), { lock: false })).file)), 'pack-parameter-invalid');
  // A sign-in redirect is a refusal only when the actor declares it.
  const redirect = refs => profileWith(refs, [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test'), { pack: 'RV' }]);
  const rv302 = { ...REFS.RV, params: { ...REFS.RV.params, refusalStatuses: [302, 401] } };
  await assert.rejects(lockProfile((await written(t, redirect([rv302]), { lock: false })).file), /refus|status/i);
  const declared = redirect([rv302]); declared.targets[0].actors.agentR.signInRedirectStatus = 302;
  const ok = await written(t, declared);
  assert.deepEqual((await loadProfiles(ok.file))[0].checks.find(c => c.id === 'RV-AFTER').assertions[0].expected, [302, 401]);
});

// Pack updates in CI (pull.mjs): the shipped directory is a copy here, with manifests bumped (the files are unchanged, so their
// digests still hold), because one version of each pack ships at a time and every shipped pack is at its first version.
async function shippedCopy(t, versions) {
  const shipped = await dirWith(t, 'scopehaven shipped ');
  await cp(SHIPPED_PACKS, shipped, { recursive: true });
  for (const [name, version] of Object.entries(versions)) {
    const path = join(shipped, name, 'manifest.json'), manifest = JSON.parse(await readFile(path, 'utf8'));
    await writeFile(path, JSON.stringify({ ...manifest, version }));
  }
  return shipped;
}

test('pack status reads each pin against the shipped version; pull takes a newer same-major version into a new locked copy and never writes the committed profile or lock', async t => {
  assert.deepEqual([compareVersions('1.0.0', '1.0.10'), compareVersions('1.2.0', '1.10.0'), compareVersions('2.0.0', '1.9.9'), compareVersions('1.0.0', '1.0.0')], [-1, -1, 1, 0]);
  assert.deepEqual([stateOf('1.0.0', '1.1.0'), stateOf('1.0.0', '2.0.0'), stateOf('1.1.0', '1.0.0'), stateOf('1.0.0', '1.0.0'), stateOf('1.0.0', null)], ['pull', 'major', 'older', 'current', 'missing']);
  const shipped = await shippedCopy(t, { 'refund-window': '1.1.0', 'discount-cap': '2.0.0' });
  const { dir, file } = await written(t, profileWith([REFS.TI, REFS.RW]));
  const before = [await readFile(file, 'utf8'), await readFile(join(dir, LOCK_FILE), 'utf8')];
  const status = await packStatus(file, { shipped });
  assert.deepEqual(status.packs.map(p => [p.target, p.as, p.pinned, p.shipped, p.state]), [['pack-app', 'TI', '1.0.0', '1.0.0', 'current'], ['pack-app', 'RW', '1.0.0', '1.1.0', 'pull']]);
  const unused = status.unused.map(u => `${u.name}@${u.version}`);
  assert.ok(unused.includes('discount-cap@2.0.0') && unused.includes('revocation@1.0.0') && !unused.some(u => /^(tenant-isolation|refund-window)@/.test(u)), 'the shipped packs the profile does not use are listed, not added');
  const out = join(dir, 'pulled'), pulled = await pullProfile(file, out, { shipped });
  assert.deepEqual(pulled.pulled, [{ target: 'pack-app', as: 'RW', name: 'refund-window', from: '1.0.0', to: '1.1.0' }]);
  assert.deepEqual(JSON.parse(await readFile(pulled.file, 'utf8')).targets[0].packs.map(r => `${r.as}@${r.version}`), ['TI@1.0.0', 'RW@1.1.0']);
  const lock = JSON.parse(await readFile(join(out, LOCK_FILE), 'utf8'));
  assert.equal(lock.lockId, pulled.lockId);
  assert.deepEqual(lock.packs.map(p => `${p.name}@${p.version}`), ['refund-window@1.1.0', 'tenant-isolation@1.0.0']);
  assert.ok(lock.packs.every(p => p.selfTest.passed === p.selfTest.cases && p.selfTest.cases >= 1), 'the pull ran each pack\'s own cases');
  assert.deepEqual([await readFile(file, 'utf8'), await readFile(join(dir, LOCK_FILE), 'utf8')], before, 'the committed profile and lock are untouched');
  assert.equal(await code(pullProfile(file, out, { shipped })), 'pack-pull-out-not-empty', 'the copy goes in a new, empty directory');
});

test('pack pull writes nothing when every pin is current (beside an operator\'s own pack too), and refuses a newer major, an older checkout and a missing pack', async t => {
  const current = await written(t, profileWith([REFS.TI]));
  assert.deepEqual(await pullProfile(current.file, join(current.dir, 'pulled')), { schema: 'scopehaven-pack-pull/1', file: null, lockId: null, pulled: [] });
  await assert.rejects(stat(join(current.dir, 'pulled')), { code: 'ENOENT' }, 'no directory is made');
  const shipped = await shippedCopy(t, { 'discount-cap': '2.0.0', 'refund-window': '0.9.0' });
  for (const [ref, state] of [[REFS.DC, 'major'], [REFS.RW, 'older']]) {
    const p = await written(t, profileWith([REFS.TI, ref]));
    assert.equal((await packStatus(p.file, { shipped })).packs.find(x => x.as === ref.as).state, state);
    assert.equal(await code(pullProfile(p.file, join(p.dir, 'pulled'), { shipped })), `pack-pull-${state}`);
  }
  await rm(join(shipped, 'tenant-isolation'), { recursive: true });
  assert.equal((await packStatus(current.file, { shipped })).packs[0].state, 'missing');
  assert.equal(await code(pullProfile(current.file, join(current.dir, 'pulled'), { shipped })), 'pack-pull-missing');
  const { dir, file } = await written(t, profileWith(), { lock: false });
  await cp(join(SHIPPED_PACKS, 'tenant-isolation'), join(dir, 'packs', 'tenant-isolation'), { recursive: true });
  await writeFile(file, JSON.stringify(profileWith([{ ...REFS.TI, from: 'packs' }], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), { pack: 'TI' }, whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')])));
  assert.equal((await packStatus(file)).packs[0].state, 'local');
  // An operator's own pack with nothing else to pull: no refusal, and nothing is written.
  assert.deepEqual(await pullProfile(file, join(dir, 'pulled')), { schema: 'scopehaven-pack-pull/1', file: null, lockId: null, pulled: [] });
  await assert.rejects(stat(join(dir, 'pulled')), { code: 'ENOENT' }, 'no directory is made beside a local pack');
  // The CLI prints the same reading and writes nothing.
  const lines = [];
  assert.equal(await main(['status', '--config', current.file], { log: s => lines.push(s) }), 0);
  assert.deepEqual(JSON.parse(lines[0]).packs.map(p => p.state), ['current']);
  await assert.rejects(main(['pull', '--config', current.file]), /Usage/);
});

test('pack pull refuses an operator\'s own pack only when another pin would be pulled, and an output directory that is a symlink', async t => {
  const shipped = await shippedCopy(t, { 'refund-window': '1.1.0' });
  // A local pack beside a pin that would be pulled: the copy could not reach the operator's directory, so it is refused.
  const { dir, file } = await written(t, profileWith([{ ...REFS.TI, from: 'packs' }, REFS.RW]), { lock: false });
  await cp(join(SHIPPED_PACKS, 'tenant-isolation'), join(dir, 'packs', 'tenant-isolation'), { recursive: true });
  assert.deepEqual((await packStatus(file, { shipped })).packs.map(p => [p.as, p.state]), [['TI', 'local'], ['RW', 'pull']]);
  assert.equal(await code(pullProfile(file, join(dir, 'pulled'), { shipped })), 'pack-pull-local');
  await assert.rejects(stat(join(dir, 'pulled')), { code: 'ENOENT' }, 'refused before a directory is made');
  // An existing --out that is a symlink is refused, and nothing is written through it.
  const plainPull = await written(t, profileWith([REFS.TI, REFS.RW]));
  const real = await dirWith(t, 'scopehaven link target '), link = join(plainPull.dir, 'pulled');
  await symlink(real, link);
  assert.equal(await code(pullProfile(plainPull.file, link, { shipped })), 'pack-pull-out-symlink');
  assert.deepEqual(await readdir(real), [], 'nothing written through the link');
});

test('relocking with --update refuses an existing lock it cannot read, and says which entries it kept for other profiles', async t => {
  const dir = await dirWith(t), a = join(dir, 'a.targets.json'), b = join(dir, 'b.targets.json');
  await writeFile(a, JSON.stringify(profileWith([REFS.TI]))); await writeFile(b, JSON.stringify(profileWith([REFS.DC], [whoami('B-WHOAMI', 'agentB', 'agent-b@globex.test'), { pack: 'DC' }, whoami('B-WHOAMI-AFTER', 'agentB', 'agent-b@globex.test')])));
  await lockProfile(a);
  assert.deepEqual((await lockProfile(b, { replace: true })).kept, ['tenant-isolation@1.0.0']);
  await writeFile(join(dir, LOCK_FILE), '{"schema":"scopehaven-pack-lock/1","packs":[],"lockId":"0"}');
  await assert.rejects(lockProfile(b, { replace: true }), e => e.code === 'pack-lock-invalid' && /remove it to lock from scratch/.test(e.message));
});
