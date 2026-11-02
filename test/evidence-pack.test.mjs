// One signed evidence pack: `./scopehaven evidence-pack` writes every export of one run into a new 0700 folder, each
// with its DSSE envelope, plus the signer's public key, a copy of the Python verifier, a VERIFY.md with the exact commands and one
// envelope over the whole folder; all or nothing. The exports are made by the existing exporters, so each file here is compared with
// what `export` (or `payments export`) writes. Owned synthetic data only: the synthetic fixture, an injected transport for the HTTP
// runs, and the checked-in payments sample runs; no socket, model or provider. Every file is under a fresh private temporary
// directory, and every key directory is --signing-key-dir or a temporary HOME, never this user's ~/.config.
import test, { after as afterAll } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, readlink, rename, rm, stat, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { runAssessment } from '../src/runner.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { createStore } from '../src/store.mjs';
import { COVERAGE_NEEDS_FILES, escape } from '../src/report.mjs';
import { exportRun, loadSigningKey, defaultSigningKeyDir, signerVersion, KEY_FILE, PUBLIC_KEY_FILE, SIGNATURE_MEANING, SIGNING_KEY_UNSAFE, COVERAGE_INPUTS } from '../src/export-cli.mjs';
import { evidencePack, PACK_ENVELOPE, VERIFIER_FILE, CHECKER_FILE, VERIFY_FILE, EVIDENCE_PACK_FAILED } from '../src/evidence-pack.mjs';
import { initLedger, appendEnvelope } from '../integrations/ledger/ledger.mjs';
import { main as retestLedger, HISTORY_FILE, HISTORY_ENVELOPE } from '../integrations/retest-ledger/cli.mjs';
import { DECLARATIONS_VERSION, HISTORY_VERSION } from '../integrations/retest-ledger/history.mjs';
import { signFiles } from '../integrations/attest/sign.mjs';
import { verifyEnvelope, subjectNames, keyIdOf, trustedKey } from '../integrations/attest/verify.mjs';
import { exportPaymentsRun, PAYMENTS_RUN_REFUSED } from '../integrations/payments-pack/output.mjs';
import { comparePaymentsRuns } from '../integrations/payments-pack/pack.mjs';

const REAL_KEY_DIR = defaultSigningKeyDir();
const keyDirState = () => lstat(REAL_KEY_DIR).then(s => ({ ino: s.ino, mtimeMs: s.mtimeMs, mode: s.mode }), error => error.code);
const realBefore = await keyDirState();
// From here on this process's HOME is a temporary folder, so even a regression that reached for the default key directory could
// not touch the real one (whose state was taken above and is compared at the end of each test).
const TEMPORARY_HOME = mkdtempSync(join(tmpdir(), 'scopehaven evidence pack home '));
process.env.HOME = TEMPORARY_HOME;
afterAll(() => rmSync(TEMPORARY_HOME, { recursive: true, force: true }));
const CHECKOUT = fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, '');
const quote = value => `'${value.replace(/'/g, `'\\''`)}'`;
const CLI = fileURLToPath(new URL('../src/evidence-pack.mjs', import.meta.url));
const VERIFIER_SOURCE = fileURLToPath(new URL('../integrations/attest/verify_envelope.py', import.meta.url));
const CHECKER_SOURCE = fileURLToPath(new URL('../integrations/verdict-check/verify_verdicts.py', import.meta.url));
const SAMPLE = name => fileURLToPath(new URL(`../integrations/payments-pack/sample/${name}`, import.meta.url));
const python = spawnSync('python3', ['--version'], { encoding: 'utf8' }).status === 0;
const copy = value => structuredClone(value);
const vulnerable = await runAssessment('demo-vulnerable'), repaired = await runAssessment('demo-repaired');
const before = JSON.parse(await readFile(SAMPLE('before-vulnerable.json'), 'utf8')), afterSaved = JSON.parse(await readFile(SAMPLE('after-repaired.json'), 'utf8'));
const { comparison: _stored, ...after } = afterSaved;
const RUN_NAMES = ['run.json', 'run.html', 'run.sarif', 'summary.html', 'residual.json'], COMPARISON_NAMES = ['comparison.json', 'comparison.html'];
const FORMAT = { 'run.json': 'json', 'run.html': 'html', 'run.sarif': 'sarif', 'summary.html': 'summary', 'residual.json': 'residual', 'comparison.json': 'json', 'comparison.html': 'html' };
const EXTRAS = [PUBLIC_KEY_FILE, VERIFIER_FILE, CHECKER_FILE, VERIFY_FILE, PACK_ENVELOPE];
const expectedNames = exports => [...exports, ...exports.map(n => `${n}.dsse.json`), ...EXTRAS].sort();

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven evidence pack '));
  t.after(() => rm(root, { recursive: true, force: true }));
  const data = join(root, 'store'), packs = join(root, 'packs'), keys = join(root, 'keys'), direct = join(root, 'direct'), inputs = join(root, 'inputs');
  const store = createStore(data); await store.ready;
  const baseline = await store.save(copy(vulnerable)), candidate = await store.save(copy(repaired));
  // The packs' parent need not be private (the pack folder is made 0700); the direct exports' directory must be, as for `export`.
  await mkdir(packs, { mode: 0o755 }); await chmod(packs, 0o755); await mkdir(direct, { mode: 0o700 }); await mkdir(inputs, { mode: 0o700 });
  return { root, data, packs, keys, direct, inputs, store, baseline, candidate };
}
const mode = async path => (await stat(path)).mode & 0o777;
const exists = path => lstat(path).then(() => true, () => false);
// Every envelope in a folder, verified by the Node verifier from the bytes on disk, against the folder's own public key.
async function verifyFolder(dir) {
  const names = await readdir(dir), publicKey = await readFile(join(dir, PUBLIC_KEY_FILE), 'utf8');
  const verdicts = {};
  for (const name of names.filter(n => n.endsWith('.dsse.json'))) {
    const envelope = await readFile(join(dir, name)), files = new Map();
    for (const subject of subjectNames(envelope)) files.set(subject, await readFile(join(dir, subject)));
    verdicts[name] = verifyEnvelope({ envelope, publicKey, files }).verdict;
  }
  return verdicts;
}
// The commands VERIFY.md prints, run as printed from the pack folder.
const verifyLines = text => text.split('\n').filter(line => line.startsWith(`    python3 -I ${VERIFIER_FILE} `)).map(line => line.trim());
// The commands for a reader's own checkout, run as printed with CHECKOUT filled in (this checkout's path has a space, inside the
// printed quotes) and `node` the pinned runtime.
const checkoutLines = text => text.split('\n').filter(line => line.includes('"CHECKOUT/integrations/')).map(line => line.trim()
  .replace('CHECKOUT', CHECKOUT).replace(/^node /, `${quote(process.execPath)} `));
const runInFolder = (dir, command) => spawnSync('sh', ['-c', command], { cwd: dir, encoding: 'utf8' });

test('a run pack holds every export with its envelope, the public key, the verifier, VERIFY.md and one folder envelope; every printed command verifies', async t => {
  const w = await workspace(t), out = join(w.packs, 'pack one');
  const result = await evidencePack({ runId: w.candidate.id, baselineRunId: w.baseline.id, dataDir: w.data, outputDir: out, signingKeyDir: w.keys });
  const exports = [...RUN_NAMES, ...COMPARISON_NAMES], names = expectedNames(exports);
  assert.deepEqual((await readdir(out)).sort(), names);
  assert.deepEqual(await readdir(w.packs), ['pack one'], 'no staging folder is left beside the pack');
  assert.equal(await mode(out), 0o700);
  for (const name of names) assert.equal(await mode(join(out, name)), 0o600, name);
  assert.equal(result.saved, true); assert.equal(result.out, out); assert.equal(result.runId, w.candidate.id); assert.equal(result.baselineRunId, w.baseline.id); assert.equal(result.kind, 'run');
  assert.deepEqual(result.files.map(f => f.name).sort(), names);
  for (const file of result.files) assert.equal(file.bytes, (await readFile(join(out, file.name))).length, file.name);
  // The public key is the signer's (the key directory's), and nothing private is in the folder.
  const publicPem = await readFile(join(out, PUBLIC_KEY_FILE), 'utf8');
  assert.equal(publicPem, await readFile(join(w.keys, PUBLIC_KEY_FILE), 'utf8'));
  assert.equal(keyIdOf(trustedKey(publicPem)), result.keyid);
  for (const name of names) assert.doesNotMatch(await readFile(join(out, name), 'utf8'), /PRIVATE KEY/, name);
  assert.deepEqual(await readFile(join(out, VERIFIER_FILE)), await readFile(VERIFIER_SOURCE), 'the verifier is an exact copy');
  assert.deepEqual(await readFile(join(out, CHECKER_FILE)), await readFile(CHECKER_SOURCE), 'the verdict checker is an exact copy');
  // The folder envelope names every other file; every envelope verifies from the bytes on disk.
  assert.deepEqual(subjectNames(await readFile(join(out, PACK_ENVELOPE))).sort(), names.filter(n => n !== PACK_ENVELOPE));
  const verdicts = await verifyFolder(out);
  assert.equal(Object.keys(verdicts).length, exports.length + 1); assert.ok(Object.values(verdicts).every(v => v === 'verified'), JSON.stringify(verdicts));
  // Each export is what `export` writes with the same key and name.
  for (const name of exports) {
    const direct = await exportRun({ runId: w.candidate.id, ...(COMPARISON_NAMES.includes(name) ? { baselineRunId: w.baseline.id } : {}), format: FORMAT[name], outputFile: join(w.direct, name), dataDir: w.data, signingKeyDir: w.keys });
    assert.equal(direct.signature.keyid, result.keyid);
    assert.deepEqual(await readFile(join(out, name)), await readFile(join(w.direct, name)), name);
  }
  // VERIFY.md: the key id, the runs, the signature-meaning sentence, one command per envelope, and no path of this machine.
  const text = await readFile(join(out, VERIFY_FILE), 'utf8');
  assert.ok(text.includes(SIGNATURE_MEANING)); assert.ok(text.includes(result.keyid)); assert.ok(text.includes(w.candidate.id)); assert.ok(text.includes(w.baseline.id));
  // Trust rests on the key id the verifiers print, matched against the signer's word over another channel; never on this folder.
  assert.ok(text.includes('over a separate channel, not from this folder'));
  assert.ok(text.includes('print a `keyid` equal to the id you got from the signer'));
  assert.ok(text.includes("SHA-256 of the public key's DER SubjectPublicKeyInfo (not of the .pem file)"));
  assert.ok(text.includes('confirm that sha256 with the signer, or use your own copy (below), never this file\'s word alone'));
  assert.ok(!/compare its sha256 with the one above/.test(text));
  for (const name of exports) assert.ok(text.includes(`\`${name}\``), name);
  assert.ok(!text.includes(w.root) && !/\/Users\/|\/home\/|\/tmp\/|\/private\//.test(text), 'no path of this machine');
  const lines = verifyLines(text);
  assert.deepEqual(lines, [PACK_ENVELOPE, ...exports.map(n => `${n}.dsse.json`)].map(e => `python3 -I ${VERIFIER_FILE} --key ${PUBLIC_KEY_FILE} --envelope ${e} --dir .`));
  if (python) for (const line of lines) {
    const ran = runInFolder(out, line), printed = JSON.parse(ran.stdout);
    assert.equal(ran.status, 0, `${line}: ${ran.stdout} ${ran.stderr}`); assert.equal(printed.verdict, 'verified'); assert.equal(printed.keyid, result.keyid);
  } else t.diagnostic('python3 not found: the printed Python commands were not run');
  // The commands for a reader's own checkout run as printed, from this folder (Node always; Python when it is installed).
  const own = checkoutLines(text), checks = own.filter(l => l.includes(`/verdict-check/${CHECKER_FILE}`));
  assert.equal(own.length, 3); assert.equal(checks.length, 1);
  for (const line of own.filter(l => !checks.includes(l) && (python || !l.startsWith('python3')))) {
    const ran = runInFolder(out, line);
    assert.equal(ran.status, 0, `${line}: ${ran.stdout} ${ran.stderr}`); assert.equal(JSON.parse(ran.stdout).keyid, result.keyid);
  }
  // The verdict checker, from the copy here and from the checkout as printed: the signature verified under this key, every run.json
  // verdict re-derived, and the reports and the comparison listed as files it does not judge (exit 4, as VERIFY.md says). The run
  // record alone, against its own envelope, exits 0.
  const inFolder = text.split('\n').filter(line => line.startsWith(`    python3 -I ${CHECKER_FILE} `)).map(line => line.trim());
  const runOnly = `python3 -I ${CHECKER_FILE} --key ${PUBLIC_KEY_FILE} --envelope run.json.dsse.json run.json --text`;
  assert.deepEqual(inFolder, [`python3 -I ${CHECKER_FILE} --key ${PUBLIC_KEY_FILE} --envelope ${PACK_ENVELOPE} --dir . --text`, runOnly]);
  assert.ok(text.includes('Over this folder it exits 4 even when every verdict was re-derived'));
  if (python) for (const line of [...inFolder, ...checks]) {
    const ran = runInFolder(out, line);
    assert.equal(ran.status, line === runOnly ? 0 : 4, `${line}: ${ran.stdout} ${ran.stderr}`);
    assert.ok(ran.stdout.includes(`keyid ${result.keyid}`) && ran.stdout.includes('run.json: synthetic-fixture run') && ran.stdout.includes('44 of 44 verdicts re-derived'), ran.stdout);
    assert.ok(ran.stdout.includes(line === runOnly ? 'Verdict: rederived. All 44 verdicts' : 'Verdict: rederived-in-part. All 44 verdicts re-derived from the kept observations; not vouched for:'), ran.stdout);
  }
  // A changed or removed file fails the folder envelope.
  await writeFile(join(out, 'summary.html'), 'changed');
  if (python) assert.equal(runInFolder(out, lines[0]).status, 1);
  assert.equal((await verifyFolder(out))[PACK_ENVELOPE], 'rejected');
  assert.deepEqual(await keyDirState(), realBefore, 'the real key directory is untouched');
});

test('a folder re-signed with another key still verifies but prints that key\'s id, which is why VERIFY.md anchors trust on the printed id', async t => {
  const w = await workspace(t), real = join(w.packs, 'real'), forged = join(w.packs, 'forged'), otherKeys = join(w.root, 'other keys');
  const genuine = await evidencePack({ paymentsRun: copy(afterSaved), outputDir: real, signingKeyDir: w.keys });
  const other = await evidencePack({ paymentsRun: copy(afterSaved), outputDir: forged, signingKeyDir: otherKeys });
  assert.notEqual(other.keyid, genuine.keyid);
  // The forger copies the genuine VERIFY.md (showing the genuine key id) and signs the folder again with their own key.
  await rm(join(forged, VERIFY_FILE)); await writeFile(join(forged, VERIFY_FILE), await readFile(join(real, VERIFY_FILE)), { mode: 0o600 });
  const files = [];
  for (const name of (await readdir(forged)).filter(n => n !== PACK_ENVELOPE).sort()) files.push({ name, content: await readFile(join(forged, name)) });
  const { envelope } = signFiles(files, { privateKey: (await loadSigningKey(otherKeys)).privateKey, version: await signerVersion() });
  await rm(join(forged, PACK_ENVELOPE)); await writeFile(join(forged, PACK_ENVELOPE), envelope, { mode: 0o600 });
  const text = await readFile(join(forged, VERIFY_FILE), 'utf8');
  assert.ok(text.includes(genuine.keyid) && !text.includes(other.keyid), 'the folder shows the genuine id');
  // Every check passes on the forged folder, but each prints the forger's key id: only the instruction to compare it with the id
  // the signer gave over another channel catches the swap.
  assert.equal((await verifyFolder(forged))[PACK_ENVELOPE], 'verified');
  if (python) for (const line of verifyLines(text)) {
    const printed = JSON.parse(runInFolder(forged, line).stdout);
    assert.equal(printed.verdict, 'verified'); assert.equal(printed.keyid, other.keyid); assert.notEqual(printed.keyid, genuine.keyid);
  } else t.diagnostic('python3 not found: the printed Python commands were not run');
  assert.ok(text.includes('print a `keyid` equal to the id you got from the signer') && text.includes('anyone who can make a key can write any id here'));
});

// The coverage inputs of test/export-coverage.test.mjs, in brief: two actors, guest without an allowed-use control.
const check = (id, severity, actorId, path) => ({ id, title: id, category: severity === 'control' ? 'allowed-use' : 'tool-misuse', severity, actorId, method: 'GET', path, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] });
const profile = { id: 'coverage-target', name: 'Coverage app', applicationId: 'coverage-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-coverage',
  actors: { ops: { principalId: 'ops', role: 'member', tenantId: 't1' }, guest: { principalId: 'guest', role: 'member', tenantId: 't1' } }, requiredControlIds: ['OPS-ALLOWED'],
  checks: [check('OPS-BOUNDARY', 'high', 'ops', '/agent/orders'), check('OPS-ALLOWED', 'control', 'ops', '/me'), check('GUEST-BOUNDARY', 'high', 'guest', '/agent/tickets')] };
const inventory = { schema: 'scopehaven-coverage-inventory/1', applicationId: 'coverage-app', tenants: ['t1'], roles: ['member'], members: { t1: ['member'] },
  operations: [{ id: 'GET /me', surface: 'api', method: 'GET', path: '/me', auth: 'session', tenantScoped: false }, { id: 'GET /agent/orders', surface: 'api', method: 'GET', path: '/agent/orders', auth: 'session', tenantScoped: false },
    { id: 'GET /agent/tickets', surface: 'api', method: 'GET', path: '/agent/tickets', auth: 'session', tenantScoped: false }], datastores: [] };
const contract = { schema: 'scopehaven-coverage-contract/1', applicationId: 'coverage-app', basis: 'stated-policy', crossTenant: 'deny',
  rules: [{ operation: 'GET /me', allow: ['member'] }, { operation: 'GET /agent/orders', allow: ['member'] }, { operation: 'GET /agent/tickets', allow: [] }] };
const assess = async () => { const run = await runHttpAssessment(copy(profile), { env: {}, transport: async () => ({ status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 }) }); validateHttpRunEvidence(run); return run; };

test('the coverage files reach the HTML report and both comparison exports exactly as `export` takes them; the other exports do not change', async t => {
  const w = await workspace(t), write = async (name, value) => { const path = join(w.inputs, name); await writeFile(path, JSON.stringify(value)); return path; };
  const first = await w.store.save(await assess()), second = await w.store.save(await assess());
  const coverage = { coverageInventory: await write('inventory.json', inventory), coverageContract: await write('contract.json', contract), coverageTargets: await write('targets.json', { schemaVersion: 1, targets: [profile] }) };
  const out = join(w.packs, 'covered');
  const result = await evidencePack({ runId: second.id, baselineRunId: first.id, dataDir: w.data, outputDir: out, signingKeyDir: w.keys, ...coverage });
  assert.deepEqual((await readdir(out)).sort(), expectedNames([...RUN_NAMES, ...COMPARISON_NAMES]));
  for (const name of [...RUN_NAMES, ...COMPARISON_NAMES]) {
    const withCoverage = name === 'run.html' || COMPARISON_NAMES.includes(name);
    await exportRun({ runId: second.id, ...(COMPARISON_NAMES.includes(name) ? { baselineRunId: first.id } : {}), format: FORMAT[name], outputFile: join(w.direct, name), dataDir: w.data, signingKeyDir: w.keys, ...(withCoverage ? coverage : {}) });
    assert.deepEqual(await readFile(join(out, name)), await readFile(join(w.direct, name)), name);
  }
  const html = await readFile(join(out, 'run.html'), 'utf8');
  assert.ok(!html.includes(escape(COVERAGE_NEEDS_FILES)), 'the full coverage report is in the HTML report'); assert.match(html, /coverage-gap/);
  assert.ok(Object.values(await verifyFolder(out)).every(v => v === 'verified'));
  assert.match(result.keyid, /^[0-9a-f]{64}$/);
});

test('a payments pack holds the run json, html and sarif signed, and with a baseline the comparison recomputed from both runs', async t => {
  const w = await workspace(t), out = join(w.packs, 'payments'), bare = join(w.packs, 'payments-alone');
  const result = await evidencePack({ paymentsRun: copy(afterSaved), paymentsBaseline: copy(before), outputDir: out, signingKeyDir: w.keys });
  const exports = ['payments-run.json', 'payments-run.html', 'payments-run.sarif', 'payments-comparison.json'];
  assert.deepEqual((await readdir(out)).sort(), expectedNames(exports));
  assert.equal(result.kind, 'payments'); assert.equal(result.runId, after.id); assert.equal(result.baselineRunId, before.id);
  assert.equal(await readFile(join(out, 'payments-run.json'), 'utf8'), `${JSON.stringify(after, null, 2)}\n`, 'the run record, without the comparison stored beside it');
  assert.deepEqual(JSON.parse(await readFile(join(out, 'payments-comparison.json'), 'utf8')), comparePaymentsRuns(before, after));
  assert.match(await readFile(join(out, 'payments-run.html'), 'utf8'), /Before and after <span class="badge" style="background:#1f7a3a">verified repair<\/span>/);
  // Each export is what `payments export` writes with the same key and name.
  const direct = { 'payments-run.json': { format: 'json' }, 'payments-run.html': { format: 'html', baseline: copy(before) }, 'payments-run.sarif': { format: 'sarif' }, 'payments-comparison.json': { format: 'json', baseline: copy(before) } };
  for (const [name, options] of Object.entries(direct)) {
    await exportPaymentsRun({ run: copy(afterSaved), ...options, outputFile: join(w.direct, name), signingKeyDir: w.keys });
    assert.deepEqual(await readFile(join(out, name)), await readFile(join(w.direct, name)), name);
  }
  assert.ok(Object.values(await verifyFolder(out)).every(v => v === 'verified'));
  const text = await readFile(join(out, VERIFY_FILE), 'utf8');
  assert.match(text, /one ScopeHaven payments run/); assert.ok(text.includes(before.id)); assert.ok(text.includes(SIGNATURE_MEANING));
  if (python) for (const line of verifyLines(text)) assert.equal(runInFolder(out, line).status, 0, line);
  // Without a baseline: three exports, no comparison section.
  await evidencePack({ paymentsRun: copy(before), outputDir: bare, signingKeyDir: w.keys });
  assert.deepEqual((await readdir(bare)).sort(), expectedNames(['payments-run.json', 'payments-run.html', 'payments-run.sarif']));
  assert.doesNotMatch(await readFile(join(bare, 'payments-run.html'), 'utf8'), /Before and after/);
  assert.deepEqual(await keyDirState(), realBefore);
});

test('all or nothing: a refusal makes nothing, a failure part-way leaves no folder, and an existing path is never touched', async t => {
  const w = await workspace(t), out = join(w.packs, 'pack'), base = { runId: w.candidate.id, dataDir: w.data, signingKeyDir: w.keys };
  const invalid = [
    { ...base, outputDir: 'relative/pack' }, { ...base, outputDir: `${out}/` }, { ...base, outputDir: `${w.packs}/../packs/pack` }, { ...base, outputDir: out, dataDir: undefined },
    { ...base, outputDir: out, baselineRunId: 'not-a-run' }, { ...base, outputDir: out, coverageInventory: join(w.inputs, 'a.json') }, { ...base, outputDir: out, signingKeyDir: 'keys' },
    { ...base, outputDir: out, paymentsRun: copy(before) }, { paymentsRun: copy(before), dataDir: w.data, outputDir: out, signingKeyDir: w.keys }, { ...base, outputDir: out, paymentsBaseline: copy(before) },
    { ...base, outputDir: join(w.root, 'missing', 'pack') },
    // The store must already exist (the exporter would create a missing one); the key never lives at, in or around the pack.
    { ...base, outputDir: out, dataDir: join(w.root, 'no such store', 'deeper') },
    { ...base, outputDir: out, signingKeyDir: out }, { ...base, outputDir: out, signingKeyDir: join(out, 'keys') }, { ...base, signingKeyDir: w.inputs, outputDir: join(w.inputs, 'pack') },
    { paymentsRun: copy(after), outputDir: out, signingKeyDir: join(out, 'keys') },
    // The same place spelled with other case or another Unicode normalization (one name on the default macOS volume).
    { ...base, outputDir: join(w.packs, 'Pack Case'), signingKeyDir: join(w.packs, 'pack case', 'keys') },
    { ...base, outputDir: join(w.packs, 'café'), signingKeyDir: join(w.packs, 'café', 'keys') },
  ];
  for (const options of invalid) await assert.rejects(evidencePack(options), /Invalid evidence-pack options/, JSON.stringify(options));
  assert.equal(await exists(join(w.root, 'no such store')), false, 'a missing store is not created');
  await symlink(w.packs, join(w.root, 'linked'));
  await assert.rejects(evidencePack({ ...base, outputDir: join(w.root, 'linked', 'pack') }), /Invalid evidence-pack options/);
  // The same key folder spelled through a symlink is still the key folder.
  await assert.rejects(evidencePack({ ...base, outputDir: out, signingKeyDir: join(w.root, 'linked', 'pack', 'keys') }), /Invalid evidence-pack options/);
  // A refused payments run: nothing is made, not even the key.
  const edited = copy(before); edited.rows.find(r => r.status === 'fail').status = 'pass';
  await assert.rejects(evidencePack({ paymentsRun: edited, outputDir: out, signingKeyDir: w.keys }), error => error.code === PAYMENTS_RUN_REFUSED);
  await assert.rejects(evidencePack({ paymentsRun: copy(after), paymentsBaseline: edited, outputDir: out, signingKeyDir: w.keys }), error => error.code === PAYMENTS_RUN_REFUSED);
  // A run the store does not hold: the staging folder is removed, nothing is at --out, and no key was made.
  await assert.rejects(evidencePack({ ...base, runId: '00000000-0000-4000-8000-000000000000', outputDir: out }));
  assert.deepEqual(await readdir(w.packs), []); assert.equal(await exists(w.keys), false, 'no key was made');
  // An existing folder or file at --out is never touched.
  await mkdir(out, { mode: 0o700 }); const inode = (await lstat(out)).ino;
  await assert.rejects(evidencePack({ ...base, outputDir: out }), error => error.code === 'EEXIST');
  assert.deepEqual(await readdir(out), []); assert.equal((await lstat(out)).ino, inode); await rm(out, { recursive: true });
  await writeFile(out, 'someone else\'s file');
  await assert.rejects(evidencePack({ ...base, outputDir: out }), error => error.code === 'EEXIST');
  assert.equal(await readFile(out, 'utf8'), 'someone else\'s file'); await rm(out);
  // A symlink at --out, to a folder or to nothing, is never followed or replaced.
  for (const target of [w.inputs, join(w.root, 'nowhere')]) {
    await symlink(target, out);
    await assert.rejects(evidencePack({ ...base, outputDir: out }), error => error.code === 'EEXIST');
    assert.equal(await readlink(out), target); await rm(out);
  }
  assert.equal(await exists(join(w.root, 'nowhere')), false);
  assert.equal(await exists(w.keys), false, 'an existing --out is refused before anything is built, so no key was made');
  // Staging, then the claim: a finished build stopped just before the claim has every file in the staging folder and nothing at
  // --out, and the stop removes the staging folder.
  let staged;
  await assert.rejects(evidencePack({ ...base, outputDir: out }, { beforeClaim: async staging => {
    staged = { out: await exists(out), names: (await readdir(staging)).sort(), mode: await mode(staging) }; throw new Error('stopped before the claim');
  } }), /stopped before the claim/);
  assert.equal(staged.out, false, 'nothing at --out while the pack is built'); assert.equal(staged.mode, 0o700);
  assert.deepEqual(staged.names, expectedNames(RUN_NAMES));
  assert.deepEqual(await readdir(w.packs), [], 'the staging folder is removed');
  // A failure after the claim (here the staging folder is gone when the rename comes) removes the claim: nothing is at --out.
  const moved = join(w.root, 'moved staging');
  await assert.rejects(evidencePack({ ...base, outputDir: out }, { beforeClaim: staging => rename(staging, moved) }), error => error.code === 'ENOENT');
  assert.equal(await exists(out), false, 'the claim is removed'); assert.deepEqual(await readdir(w.packs), []);
  await rm(moved, { recursive: true, force: true });
  // Part-way: run.json is made, then the HTML report's coverage targets file is refused. Nothing is left in the packs folder.
  const bad = join(w.inputs, 'bad.json'); await writeFile(bad, JSON.stringify({ schemaVersion: 1, targets: [] }));
  await assert.rejects(evidencePack({ ...base, outputDir: out, coverageInventory: bad, coverageContract: bad, coverageTargets: bad }), error => error.code === COVERAGE_INPUTS);
  assert.deepEqual(await readdir(w.packs), [], 'no folder and no staging folder after a failure part-way');
  // An unsafe key directory: refused, never repaired, and nothing is left.
  const unsafe = join(w.root, 'unsafe keys'); await mkdir(unsafe, { mode: 0o755 }); await chmod(unsafe, 0o755);
  await assert.rejects(evidencePack({ ...base, outputDir: out, signingKeyDir: unsafe }), error => error.code === SIGNING_KEY_UNSAFE);
  assert.equal(await mode(unsafe), 0o755); assert.deepEqual(await readdir(unsafe), []); assert.deepEqual(await readdir(w.packs), []);
  assert.deepEqual(await keyDirState(), realBefore);
});

test('the evidence-pack command signs with ~/.config/scopehaven/signing (a temporary HOME here) and exits 2 on a refusal, leaving nothing', async t => {
  const w = await workspace(t), home = join(w.root, 'home'); await mkdir(home, { mode: 0o700 });
  const run = (args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, HOME: home, ...env } });
  const out = join(w.packs, 'from the command');
  const made = run(['--payments-run', SAMPLE('after-repaired.json'), '--payments-baseline', SAMPLE('before-vulnerable.json'), '--out', out]);
  assert.equal(made.status, 0, made.stderr);
  const result = JSON.parse(made.stdout), keys = join(home, '.config', 'scopehaven', 'signing');
  assert.equal(await mode(keys), 0o700); assert.equal(await mode(join(keys, KEY_FILE)), 0o600);
  assert.equal(result.keyid, keyIdOf(trustedKey(await readFile(join(keys, PUBLIC_KEY_FILE), 'utf8'))));
  assert.ok(Object.values(await verifyFolder(out)).every(v => v === 'verified'));
  const http = run(['--run', w.candidate.id, '--data', w.data, '--out', join(w.packs, 'http')]);
  assert.equal(http.status, 0, http.stderr); assert.equal(JSON.parse(http.stdout).keyid, result.keyid, 'the same local key');
  const edited = copy(before); edited.rows.find(r => r.status === 'fail').status = 'pass';
  await writeFile(join(w.inputs, 'edited.json'), JSON.stringify(edited));
  const listed = (await readdir(w.packs)).sort();
  for (const [args, pattern] of [
    [['--payments-run', SAMPLE('after-repaired.json'), '--out', out], /--out already exists/],
    [['--payments-run', SAMPLE('after-repaired.json'), '--out', 'relative'], /Invalid evidence-pack options/],
    [['--payments-run', join(w.inputs, 'edited.json'), '--out', join(w.packs, 'edited')], /payments-run-refused/],
    [['--payments-baseline', SAMPLE('before-vulnerable.json'), '--out', join(w.packs, 'x')], /Invalid evidence-pack options/],
    [['--payments-run', 'integrations/payments-pack/sample/after-repaired.json', '--out', join(w.packs, 'w')], /Invalid evidence-pack options/],
    [['--run', w.candidate.id, '--data', w.data, '--out', join(w.packs, 'y'), '--unsigned'], /Invalid evidence-pack options/],
    [['--run', w.candidate.id, '--data', w.data, '--out', join(w.packs, 'z'), '--signing-key-dir', join(w.root, 'k'), '--signing-key-dir', join(w.root, 'k')], /Invalid evidence-pack options/],
  ]) {
    const refused = run(args);
    assert.equal(refused.status, 2, `${args.join(' ')}: ${refused.stdout}`); assert.match(refused.stderr, pattern); assert.equal(refused.stdout, '');
  }
  assert.deepEqual((await readdir(w.packs)).sort(), listed, 'no refusal left anything');
  assert.deepEqual(await keyDirState(), realBefore, 'the real key directory is untouched');
});

test('a command that fails after its first export leaves nothing at --out, keeps the key that export made, and says so', async t => {
  const w = await workspace(t), run = args => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, HOME: TEMPORARY_HOME } });
  const bad = join(w.inputs, 'bad.json'); await writeFile(bad, JSON.stringify({ schemaVersion: 1, targets: [] }));
  const reversed = [SAMPLE('before-vulnerable.json'), SAMPLE('after-repaired.json')];
  // run.json is signed (making the key in a fresh key directory), then the HTML report's coverage targets file is refused; and a
  // payments baseline that finished after the run is refused at the HTML report, after payments-run.json was signed.
  for (const [name, args, code] of [['coverage', ['--run', w.candidate.id, '--data', w.data, '--coverage-inventory', bad, '--coverage-contract', bad, '--coverage-targets', bad], COVERAGE_INPUTS],
    ['baseline', ['--payments-run', reversed[0], '--payments-baseline', reversed[1]], PAYMENTS_RUN_REFUSED]]) {
    const keys = join(w.root, `fresh keys ${name}`), out = join(w.packs, name);
    const failed = run([...args, '--out', out, '--signing-key-dir', keys]);
    assert.equal(failed.status, 2, `${name}: ${failed.stderr}`); assert.equal(failed.stdout, ''); assert.match(failed.stderr, new RegExp(code), name);
    assert.equal(await exists(out), false, name); assert.deepEqual(await readdir(w.packs), [], `${name}: no pack and no staging folder`);
    assert.deepEqual((await readdir(keys)).sort(), [KEY_FILE, PUBLIC_KEY_FILE].sort(), `${name}: the key made on first use stays`);
    assert.doesNotMatch(failed.stderr, /Nothing was left behind|Nothing was written/, name);
    assert.ok(failed.stderr.includes('No pack and no partial pack was left at --out; a signing key made on first use stays in its key directory.'), name);
    assert.doesNotMatch(failed.stderr, /BEGIN|PRIVATE KEY/, `${name}: no key material`);
  }
  assert.deepEqual(await keyDirState(), realBefore, 'the real key directory is untouched');
});

// A retest history as an operator makes one: the workspace's two runs exported and signed with `keys`, appended to a new ledger in
// the order they were made, and the history exported by integrations/retest-ledger/cli.mjs with the same key. Owned fixture runs only.
async function retestHistoryFolder(w, keys, name) {
  const base = join(w.root, `history ${name}`), ledger = join(base, 'ledger'), exports = join(base, 'exports'), out = join(base, 'history');
  await mkdir(exports, { recursive: true, mode: 0o700 }); await mkdir(ledger, { mode: 0o700 }); await chmod(base, 0o700); await chmod(exports, 0o700);
  await initLedger(ledger);
  for (const saved of [w.baseline, w.candidate]) {
    const file = join(exports, `${saved.id}.json`);
    const exported = await exportRun({ runId: saved.id, format: 'json', outputFile: file, dataDir: w.data, signingKeyDir: keys, sign: true });
    await appendEnvelope(ledger, { envelope: await readFile(exported.signature.envelope), files: new Map([[`${saved.id}.json`, await readFile(file)]]),
      evidenceKey: await readFile(join(keys, PUBLIC_KEY_FILE), 'utf8'), privateKey: await readFile(join(keys, KEY_FILE), 'utf8') });
  }
  const declarations = join(base, 'declarations.json');
  await writeFile(declarations, JSON.stringify({ schema: DECLARATIONS_VERSION, customer: 'Owned fixture', findings: [] }));
  const made = await retestLedger(['export', '--ledger', ledger, '--key', join(keys, PUBLIC_KEY_FILE), '--run-files', exports, '--declarations', declarations, '--out', out, '--signing-key-dir', keys]);
  assert.equal(made.code, 0, JSON.stringify(made.output));
  return out;
}
// A folder holding the given files (name to bytes, or to a symlink target), as someone might hand one over.
async function handedFolder(w, name, entries) {
  const dir = join(w.root, `handed ${name}`); await mkdir(dir, { mode: 0o700 });
  for (const [file, value] of Object.entries(entries)) {
    const path = join(dir, file);
    if (value?.symlink) await symlink(value.symlink, path);
    else if (value?.fifo) assert.equal(spawnSync('mkfifo', [path]).status, 0, 'mkfifo');
    // A sparse file one byte over the limit: its size is refused before anything is read.
    else if (value?.size) { await writeFile(path, ''); await truncate(path, value.size); }
    else await writeFile(path, value, { mode: 0o600 });
  }
  return dir;
}

test('--retest-history: a history retest-ledger signed with the pack\'s key is copied in, listed in VERIFY.md and verified by both envelopes', async t => {
  const w = await workspace(t), history = await retestHistoryFolder(w, w.keys, 'own'), out = join(w.packs, 'with history');
  const result = await evidencePack({ runId: w.candidate.id, dataDir: w.data, outputDir: out, signingKeyDir: w.keys, retestHistory: history });
  const names = [...expectedNames(RUN_NAMES), HISTORY_FILE, HISTORY_ENVELOPE].sort();
  assert.deepEqual((await readdir(out)).sort(), names);
  assert.deepEqual(await readdir(w.packs), ['with history'], 'no staging folder is left beside the pack');
  for (const name of [HISTORY_FILE, HISTORY_ENVELOPE]) {
    assert.deepEqual(await readFile(join(out, name)), await readFile(join(history, name)), `${name} is copied byte for byte`);
    assert.equal(await mode(join(out, name)), 0o600, name);
  }
  const carried = JSON.parse(await readFile(join(out, HISTORY_FILE), 'utf8'));
  assert.equal(carried.schema, HISTORY_VERSION);
  assert.ok(carried.findings.some(f => f.applicationId === w.candidate.applicationId && f.suiteId === (w.candidate.suiteId ?? null)), 'the history has a finding on the pack run');
  assert.deepEqual(result.files.map(f => f.name).sort(), names);
  // The folder envelope covers the history and its envelope; every envelope, the history's included, verifies from disk.
  assert.deepEqual(subjectNames(await readFile(join(out, PACK_ENVELOPE))).sort(), names.filter(n => n !== PACK_ENVELOPE));
  assert.deepEqual(subjectNames(await readFile(join(out, HISTORY_ENVELOPE))), [HISTORY_FILE]);
  const verdicts = await verifyFolder(out);
  assert.equal(Object.keys(verdicts).length, RUN_NAMES.length + 2); assert.ok(Object.values(verdicts).every(v => v === 'verified'), JSON.stringify(verdicts));
  const text = await readFile(join(out, VERIFY_FILE), 'utf8');
  assert.ok(text.includes(`\`${HISTORY_FILE}\``), 'VERIFY.md lists the history');
  // Its row says only what the pack checked: a finding on this run's application and suite, possibly older than the run.
  assert.match(text, /It has a finding on this run's application and suite and may also cover the operator's other applications; it may predate this run/);
  // The opening sentence says the folder carries the history too, not only the exports of one run.
  const opening = text.split('\n').find(line => line.startsWith('This folder holds'));
  assert.match(opening, /^This folder holds the exports of one ScopeHaven run, made by ScopeHaven [^,]+, and also carries the operator's retest history \(`retest-history\.json`\)/);
  assert.match(opening, /Each export and the history is signed into a DSSE envelope/);
  const plainPack = join(w.packs, 'without history');
  await evidencePack({ runId: w.candidate.id, dataDir: w.data, outputDir: plainPack, signingKeyDir: w.keys });
  assert.match((await readFile(join(plainPack, VERIFY_FILE), 'utf8')).split('\n').find(line => line.startsWith('This folder holds')),
    /^This folder holds the exports of one ScopeHaven run, made by ScopeHaven [^,]+\. Each export is signed into a DSSE envelope/);
  const lines = verifyLines(text);
  assert.ok(lines.includes(`python3 -I ${VERIFIER_FILE} --key ${PUBLIC_KEY_FILE} --envelope ${HISTORY_ENVELOPE} --dir .`));
  assert.equal(lines.length, RUN_NAMES.length + 2);
  if (python) for (const line of lines) {
    const ran = runInFolder(out, line);
    assert.equal(ran.status, 0, `${line}: ${ran.stdout} ${ran.stderr}`); assert.equal(JSON.parse(ran.stdout).keyid, result.keyid);
  } else t.diagnostic('python3 not found: the printed Python commands were not run');
  assert.deepEqual(await keyDirState(), realBefore, 'the real key directory is untouched');
});

test('--retest-history refusals: another key, other or extra subjects, another application, a wrong schema, an edited, missing, symlinked, FIFO or oversized file, a payments pack, a path not in plain form; nothing is left at --out', async t => {
  const w = await workspace(t), out = join(w.packs, 'pack'), base = { runId: w.candidate.id, dataDir: w.data, outputDir: out, signingKeyDir: w.keys };
  const own = await retestHistoryFolder(w, w.keys, 'own'), foreign = await retestHistoryFolder(w, join(w.root, 'other keys'), 'foreign');
  const bytes = await readFile(join(own, HISTORY_FILE)), envelope = await readFile(join(own, HISTORY_ENVELOPE));
  const { privateKey } = await loadSigningKey(w.keys), version = await signerVersion();
  const signed = files => Buffer.from(signFiles(files, { privateKey, version }).envelope);
  const refusals = {
    'another key': foreign,
    'another subject': await handedFolder(w, 'another subject', { [HISTORY_FILE]: bytes, 'other.json': bytes, [HISTORY_ENVELOPE]: signed([{ name: 'other.json', content: bytes }]) }),
    'two subjects': await handedFolder(w, 'two subjects', { [HISTORY_FILE]: bytes, 'extra.json': bytes, [HISTORY_ENVELOPE]: signed([{ name: HISTORY_FILE, content: bytes }, { name: 'extra.json', content: bytes }]) }),
    'edited history': await handedFolder(w, 'edited', { [HISTORY_FILE]: Buffer.concat([bytes, Buffer.from(' ')]), [HISTORY_ENVELOPE]: envelope }),
    'missing history': await handedFolder(w, 'no history', { [HISTORY_ENVELOPE]: envelope }),
    'missing envelope': await handedFolder(w, 'no envelope', { [HISTORY_FILE]: bytes }),
    'symlinked history': await handedFolder(w, 'linked history', { [HISTORY_FILE]: { symlink: join(own, HISTORY_FILE) }, [HISTORY_ENVELOPE]: envelope }),
    'symlinked envelope': await handedFolder(w, 'linked envelope', { [HISTORY_FILE]: bytes, [HISTORY_ENVELOPE]: { symlink: join(own, HISTORY_ENVELOPE) } }),
    'FIFO history': await handedFolder(w, 'fifo history', { [HISTORY_FILE]: { fifo: true }, [HISTORY_ENVELOPE]: envelope }),
    'FIFO envelope': await handedFolder(w, 'fifo envelope', { [HISTORY_FILE]: bytes, [HISTORY_ENVELOPE]: { fifo: true } }),
    'oversized history': await handedFolder(w, 'big history', { [HISTORY_FILE]: { size: 64 * 1024 * 1024 + 1 }, [HISTORY_ENVELOPE]: envelope }),
    'oversized envelope': await handedFolder(w, 'big envelope', { [HISTORY_FILE]: bytes, [HISTORY_ENVELOPE]: { size: 2 * 1024 * 1024 + 1 } }),
  };
  // Signed with the pack's own key, but not this run's history: another customer's application, a wrong schema, not JSON.
  const parsed = JSON.parse(bytes.toString('utf8'));
  assert.ok(parsed.findings.length > 0);
  const foreignApp = Buffer.from(`${JSON.stringify({ ...parsed, customer: 'Another customer', findings: parsed.findings.map(f => ({ ...f, applicationId: 'another-application' })) }, null, 2)}\n`);
  const noFindings = Buffer.from(`${JSON.stringify({ ...parsed, findings: [] }, null, 2)}\n`);
  const otherSuite = Buffer.from(`${JSON.stringify({ ...parsed, findings: parsed.findings.map(f => ({ ...f, suiteId: 'another-suite' })) }, null, 2)}\n`);
  const wrongSchema = Buffer.from(`${JSON.stringify({ ...parsed, schema: 'scopehaven-retest-history/2' }, null, 2)}\n`), notJson = Buffer.from('not json\n');
  const sameKey = async (name, content) => handedFolder(w, name, { [HISTORY_FILE]: content, [HISTORY_ENVELOPE]: signed([{ name: HISTORY_FILE, content }]) });
  const named = {
    'another application': [await sameKey('foreign app', foreignApp), /no finding on this run's application and suite/],
    'another suite': [await sameKey('other suite', otherSuite), /no finding on this run's application and suite/],
    'no findings': [await sameKey('no findings', noFindings), /no finding on this run's application and suite/],
    'wrong schema': [await sameKey('wrong schema', wrongSchema), /not a scopehaven-retest-history\/1 document/],
    'not JSON': [await sameKey('not json', notJson), /not a scopehaven-retest-history\/1 document/],
  };
  for (const [name, retestHistory] of Object.entries(refusals)) {
    await assert.rejects(evidencePack({ ...base, retestHistory }), error => error.code === EVIDENCE_PACK_FAILED && error.retestHistory === true, name);
    assert.equal(await exists(out), false, name); assert.deepEqual(await readdir(w.packs), [], `${name}: no pack and no staging folder`);
  }
  for (const [name, [retestHistory, reason]] of Object.entries(named)) {
    await assert.rejects(evidencePack({ ...base, retestHistory }), error => error.code === EVIDENCE_PACK_FAILED && reason.test(error.message), name);
    assert.equal(await exists(out), false, name); assert.deepEqual(await readdir(w.packs), [], `${name}: no pack and no staging folder`);
  }
  // A payments pack takes no history, even a good one.
  await assert.rejects(evidencePack({ paymentsRun: copy(afterSaved), outputDir: out, signingKeyDir: w.keys, retestHistory: own }), error => error.code === EVIDENCE_PACK_FAILED && /a payments pack takes no retest history/.test(error.message));
  assert.equal(await exists(out), false); assert.deepEqual(await readdir(w.packs), []);
  // Plain form only, as for --out: a trailing slash or a .. segment is refused.
  for (const retestHistory of ['relative/history', '', 7, `${own}/`, `${dirname(own)}/../${basename(dirname(own))}/${basename(own)}`, `${own}/.`]) {
    await assert.rejects(evidencePack({ ...base, retestHistory }), /Invalid evidence-pack options/, String(retestHistory));
    assert.deepEqual(await readdir(w.packs), []);
  }
  // The folders handed in are read, never changed.
  assert.deepEqual(await readFile(join(own, HISTORY_FILE)), bytes); assert.deepEqual(await readFile(join(own, HISTORY_ENVELOPE)), envelope);
  assert.deepEqual(await keyDirState(), realBefore, 'the real key directory is untouched');
});

test('the evidence-pack command parses --retest-history, and a refused history exits 2 with evidence-pack-failed, leaving nothing', async t => {
  const w = await workspace(t), run = args => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, HOME: TEMPORARY_HOME } });
  const own = await retestHistoryFolder(w, w.keys, 'own'), foreign = await retestHistoryFolder(w, join(w.root, 'other keys'), 'foreign');
  const common = ['--run', w.candidate.id, '--data', w.data, '--signing-key-dir', w.keys];
  const made = run([...common, '--out', join(w.packs, 'from the command'), '--retest-history', own]);
  assert.equal(made.status, 0, made.stderr);
  assert.ok(JSON.parse(made.stdout).files.some(f => f.name === HISTORY_FILE));
  assert.ok((await readdir(join(w.packs, 'from the command'))).includes(HISTORY_ENVELOPE));
  const HINT = 'A --retest-history folder must be one integrations/retest-ledger/cli.mjs export';
  for (const [args, pattern, hint] of [[['--retest-history', foreign], /evidence-pack-failed: the retest history was refused/, true],
    [['--retest-history', 'relative/history'], /Invalid evidence-pack options/, false], [['--retest-history', `${own}/`], /Invalid evidence-pack options/, false],
    [['--retest-history', own, '--retest-history', own], /Invalid evidence-pack options/, false], [['--retest-history'], /Invalid evidence-pack options/, false]]) {
    const refused = run([...common, '--out', join(w.packs, 'refused'), ...args]);
    assert.equal(refused.status, 2, `${args.join(' ')}: ${refused.stdout}`); assert.match(refused.stderr, pattern); assert.equal(refused.stdout, '');
    assert.doesNotMatch(refused.stderr, /BEGIN|PRIVATE KEY/);
    // The history hint only for a refused history; every other failure keeps the usage line.
    assert.equal(refused.stderr.includes(HINT), hint, args.join(' ')); assert.equal(refused.stderr.includes('Use --run UUID'), !hint, args.join(' '));
  }
  const payments = run(['--payments-run', SAMPLE('after-repaired.json'), '--out', join(w.packs, 'refused'), '--signing-key-dir', w.keys, '--retest-history', own]);
  assert.equal(payments.status, 2); assert.match(payments.stderr, /a payments pack takes no retest history/); assert.ok(payments.stderr.includes(HINT));
  assert.deepEqual(await readdir(w.packs), ['from the command'], 'no refusal left anything');
  assert.deepEqual(await keyDirState(), realBefore, 'the real key directory is untouched');
});
