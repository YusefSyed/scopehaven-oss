// The build a run and a signed file name (src/producer.mjs): a release copy's commit, a checkout's HEAD, or
// `unknown`; the running and the packing build printed apart by every verifier; no evaluator identity or contract view digest moved;
// and runs and packs saved before the field still verify. A real tarball's copy is exercised in test/build-release.test.mjs. Local only:
// git, python3, a loopback lab and the owned synthetic fixture, under private temporary folders with their own signing keys.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PRODUCER_RELEASE, readRelease, stampProducer } from '../src/producer.mjs';
import { createRegistry } from '../src/registry.mjs';
import { createStore } from '../src/store.mjs';
import { digest } from '../src/domain.mjs';
import { runAssessment, compareRuns, EVALUATOR_HASH } from '../src/runner.mjs';
import { HTTP_EVALUATOR_HASH, runHttpAssessment } from '../src/http-connector.mjs';
import { contractView } from '../src/contract-views.mjs';
import { exportRun } from '../src/export-cli.mjs';
import { evidencePack, PACK_ENVELOPE, CHECKER_FILE, VERIFY_FILE } from '../src/evidence-pack.mjs';
import { generateSigningKey, signFiles, signStatement, buildStatement } from '../integrations/attest/sign.mjs';
import { verifyEnvelope } from '../integrations/attest/verify.mjs';
import { exportPaymentsRun, savedPaymentsRun } from '../integrations/payments-pack/output.mjs';
import { MANIFEST_NAME, MANIFEST_SCHEMA } from '../packaging/build-release.mjs';
import { createHttpLab, makeLabProfile } from '../examples/http-lab.mjs';

const PROJECT = fileURLToPath(new URL('../', import.meta.url));
const VERIFIER = join(PROJECT, 'integrations/attest/verify_envelope.py'), NODE_CLI = join(PROJECT, 'integrations/attest/cli.mjs');
const SAMPLE_PACK = join(PROJECT, 'examples/sample-evidence-pack/pack');
const PAYMENTS_SAMPLE = join(PROJECT, 'integrations/payments-pack/sample/before-vulnerable.json');
const python = spawnSync('python3', ['--version'], { encoding: 'utf8' }).status === 0;
const hasGit = spawnSync('git', ['--version'], { encoding: 'utf8' }).status === 0;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const COMMIT_A = 'a'.repeat(40), COMMIT_B = 'b'.repeat(40);
const RUNNING = { source: 'release-manifest', version: '0.6.0', commit: COMMIT_A, manifestSha256: 'c'.repeat(64) };
const PACKING = { source: 'git', version: '0.7.0', commit: COMMIT_B, manifestSha256: null };
const UNKNOWN = version => ({ source: 'unknown', version, commit: 'unknown', manifestSha256: null });

async function folder(t, label = 'scopehaven producer ') {
  const dir = await realpath(await mkdtemp(join(tmpdir(), label)));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
const gitIn = (cwd, ...args) => {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  const done = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd, env, encoding: 'utf8' });
  assert.equal(done.status, 0, done.stderr);
  return done.stdout.trim();
};
const manifestText = fields => JSON.stringify({ schema: MANIFEST_SCHEMA, name: 'scopehaven', version: '1.2.3', commit: COMMIT_A, files: [], ...fields });
const packageFile = root => writeFile(join(root, 'package.json'), JSON.stringify({ name: 'scopehaven', version: '9.9.9' }));
// A saved run's export, as a build other than this one would have written it.
async function exported(t, run, label = 'run.json') {
  const root = await folder(t), data = join(root, 'store'), out = join(root, 'out');
  const store = createStore(data); await store.ready;
  await mkdir(out, { mode: 0o700 });
  const saved = await store.save(run);
  await exportRun({ runId: saved.id, format: 'json', outputFile: join(out, label), dataDir: data, sign: false });
  return { saved, data, content: await readFile(join(out, label)) };
}
const asRun = (run, release) => { run.producer = { release }; return run; };
// Both verifiers from the command line, on one envelope and a folder of files; their exit codes and `builds` must agree.
async function bothVerifiers(t, envelope, publicPem, files) {
  const dir = await folder(t);
  for (const [name, content] of files) await writeFile(join(dir, name), content);
  await writeFile(join(dir, 'e.json.tmp'), envelope); await writeFile(join(dir, 'k.pem.tmp'), publicPem);
  const args = ['--key', join(dir, 'k.pem.tmp'), '--envelope', join(dir, 'e.json.tmp'), ...files.map(([name]) => join(dir, name))];
  const node = spawnSync(process.execPath, [NODE_CLI, 'verify', ...args], { encoding: 'utf8' });
  const results = { node: { code: node.status, output: JSON.parse(node.stdout) } };
  if (python) { const py = spawnSync('python3', ['-I', VERIFIER, ...args], { encoding: 'utf8' }); results.python = { code: py.status, output: JSON.parse(py.stdout) }; }
  if (results.python) {
    assert.equal(results.python.code, results.node.code, results.python.output.detail);
    assert.equal(results.python.output.reason ?? null, results.node.output.reason ?? null);
    assert.deepEqual(results.python.output.builds, results.node.output.builds);
    assert.deepEqual(results.python.output.producer, results.node.output.producer);
  }
  return results;
}

test('readRelease: a release copy names its manifest, the file\'s sha256 and the manifest\'s version', async t => {
  assert.equal(MANIFEST_NAME, 'RELEASE-MANIFEST.json');
  const root = await folder(t), text = manifestText();
  await packageFile(root); await writeFile(join(root, MANIFEST_NAME), text);
  assert.deepEqual(readRelease(root), { source: 'release-manifest', version: '1.2.3', commit: COMMIT_A, manifestSha256: sha256(text) });
  if (!hasGit) return;
  // A manifest wins over a repository around or at the folder: the copy is a release, whatever it was unpacked into.
  gitIn(root, 'init', '-q'); gitIn(root, 'add', 'package.json'); gitIn(root, 'commit', '-qm', 'x');
  assert.equal(readRelease(root).commit, COMMIT_A);
});

test('readRelease: a broken manifest reads unknown, never another commit and never an error', async t => {
  const bad = { 'not JSON': '{', 'another schema': manifestText({ schema: 'other/1' }), 'a short commit': manifestText({ commit: 'abc123' }), 'a commit with a newline': manifestText({ commit: `${COMMIT_A}\n` }), 'no version': manifestText({ version: 'latest' }), 'an array': '[]', 'null': 'null' };
  for (const [what, text] of Object.entries(bad)) {
    const root = await folder(t);
    await packageFile(root); await writeFile(join(root, MANIFEST_NAME), text);
    if (hasGit) { gitIn(root, 'init', '-q'); gitIn(root, 'add', 'package.json'); gitIn(root, 'commit', '-qm', 'x'); }
    assert.deepEqual(readRelease(root), UNKNOWN('9.9.9'), what);
  }
  const root = await folder(t), elsewhere = await folder(t);
  await writeFile(join(elsewhere, 'm.json'), manifestText()); await packageFile(root);
  await symlink(join(elsewhere, 'm.json'), join(root, MANIFEST_NAME));
  assert.deepEqual(readRelease(root), UNKNOWN('9.9.9'), 'a symlinked manifest is not read through');
  const directory = await folder(t);
  await mkdir(join(directory, MANIFEST_NAME));
  assert.deepEqual(readRelease(directory), UNKNOWN('unknown'), 'a directory at the name, and no package.json');
});

test('readRelease: no manifest and no git reads unknown rather than failing', async t => {
  const root = await folder(t);
  assert.deepEqual(readRelease(root), UNKNOWN('unknown'));
  assert.deepEqual(readRelease(join(root, 'not', 'there')), UNKNOWN('unknown'));
  await packageFile(root);
  assert.deepEqual(readRelease(root), UNKNOWN('9.9.9'));
});

test('readRelease: a checkout names its HEAD, from the folder inside the repository too', { skip: !hasGit && 'no git' }, async t => {
  const repo = await folder(t), root = join(repo, 'scopehaven');
  await mkdir(root); await packageFile(root);
  gitIn(repo, 'init', '-q');
  assert.deepEqual(readRelease(root), UNKNOWN('9.9.9'), 'a repository with no commit has no HEAD to name');
  gitIn(repo, 'add', '.'); gitIn(repo, 'commit', '-qm', 'one');
  const head = gitIn(repo, 'rev-parse', 'HEAD');
  assert.deepEqual(readRelease(root), { source: 'git', version: '9.9.9', commit: head, manifestSha256: null });
  // A git hook's environment must not point the read at another repository.
  const other = await folder(t);
  gitIn(other, 'init', '-q'); await writeFile(join(other, 'package.json'), '{}'); gitIn(other, 'add', '.'); gitIn(other, 'commit', '-qm', 'other');
  process.env.GIT_DIR = join(other, '.git');
  t.after(() => { delete process.env.GIT_DIR; });
  assert.equal(readRelease(root).commit, head);
  delete process.env.GIT_DIR;
});

test('readRelease: a copy unpacked untracked inside another project does not name that project\'s commit', { skip: !hasGit && 'no git' }, async t => {
  const project = await folder(t), root = join(project, 'vendor', 'scopehaven');
  await writeFile(join(project, 'README'), 'theirs\n');
  gitIn(project, 'init', '-q'); gitIn(project, 'add', '.'); gitIn(project, 'commit', '-qm', 'theirs');
  await mkdir(root, { recursive: true }); await packageFile(root);
  assert.deepEqual(readRelease(root), UNKNOWN('9.9.9'));
});

test('readRelease: reading the build runs no command the repository configures', { skip: !hasGit && 'no git' }, async t => {
  // No space in this folder's name: git would not start a hook at a path holding one, and this test would pass unfixed.
  const repo = await folder(t, 'scopehaven-producer-'), marker = join(repo, 'ran'), hook = join(repo, 'hook.sh');
  await packageFile(repo);
  gitIn(repo, 'init', '-q'); gitIn(repo, 'add', '.'); gitIn(repo, 'commit', '-qm', 'one');
  await writeFile(hook, `#!/bin/sh\ntouch '${marker}'\n`, { mode: 0o755 });
  gitIn(repo, 'config', 'core.fsmonitor', hook);
  assert.equal(readRelease(repo).source, 'git');
  assert.equal(existsSync(marker), false);
});

test('a run made from a checkout names its HEAD, in its saved core, on the synthetic and the HTTP path', { skip: !hasGit && 'no git' }, async t => {
  const head = spawnSync('git', ['-C', PROJECT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim();
  assert.deepEqual(PRODUCER_RELEASE, { source: 'git', version: JSON.parse(await readFile(join(PROJECT, 'package.json'), 'utf8')).version, commit: head, manifestSha256: null });
  const lab = await createHttpLab({ build: 'repaired' });
  t.after(() => lab.close());
  const registry = createRegistry({ profiles: [makeLabProfile(lab.origin, 'lab-repaired')], env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken } });
  const root = await folder(t), store = createStore(join(root, 'store')); await store.ready;
  for (const [id, hash] of [['demo-repaired', EVALUATOR_HASH], ['http-lab', HTTP_EVALUATOR_HASH]]) {
    const saved = await store.save(await registry.run(id));
    assert.equal(saved.evaluatorHash, hash);
    assert.deepEqual(saved.producer, { release: PRODUCER_RELEASE }, id);
    assert.equal(saved.producer.release.commit, head);
  }
});

test('naming a build moves no digest: a run graded by two builds of different commits has one view digest, and they compare', async t => {
  // A frozen run's view too, so the projection cannot pick the field up unnoticed.
  const fixture = JSON.parse(await readFile(new URL('./fixtures/contract-http-v1/runs.json', import.meta.url), 'utf8')).runs.one;
  assert.equal(Object.hasOwn(fixture, 'producer'), false);
  const synthetic = await runAssessment('demo-repaired'), lab = await createHttpLab({ build: 'repaired' });
  t.after(() => lab.close());
  const http = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-repaired'), { env: { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken } });
  for (const [label, run] of [['synthetic', synthetic], ['http', http], ['frozen http', fixture]]) {
    assert.equal(Object.hasOwn(run, 'producer'), false, `${label}: the producers stay out of evaluator files; the seam stamps`);
    const plain = contractView(run), one = contractView(asRun(structuredClone(run), RUNNING)), two = contractView(asRun(structuredClone(run), PACKING));
    // A current connector's run has no projector yet (HTTP_CONNECTOR_V2_PENDING), so its view is the unsupported record: still unmoved.
    assert.equal(plain.supported, label !== 'http', label);
    assert.equal(one.viewDigest, plain.viewDigest, label); assert.equal(two.viewDigest, plain.viewDigest, label);
    assert.deepEqual(two, plain, `${label}: the whole view, not only its digest`);
  }
  const baseline = asRun(await runAssessment('demo-vulnerable'), RUNNING), candidate = asRun(await runAssessment('demo-repaired'), PACKING);
  const comparison = compareRuns(baseline, candidate);
  assert.deepEqual(comparison.reasons ?? [], [], JSON.stringify(comparison.reasons));
  assert.equal(comparison.compatible, true);
  const bare = compareRuns(await runAssessment('demo-vulnerable'), await runAssessment('demo-repaired'));
  assert.deepEqual(comparison.summary, bare.summary);
  // Inside the core, the build is covered by the run's integrity hash like every other field.
  const { saved, content } = await exported(t, asRun(await runAssessment('demo-repaired'), RUNNING));
  const { integrity, notes, ...core } = saved;
  assert.equal(digest(core), integrity.sha256);
  const edited = JSON.parse(content.toString()); edited.producer.release.commit = COMMIT_B;
  const key = generateSigningKey();
  assert.throws(() => signFiles([{ name: 'run.json', content: Buffer.from(JSON.stringify(edited)) }], { privateKey: key.privatePem, version: '0.7.0' }), /edited after export/);
});

test('verify_envelope.py and the Node verifier print the running and the packing build apart', async t => {
  const key = generateSigningKey(), { content } = await exported(t, asRun(await runAssessment('demo-repaired'), RUNNING));
  const files = [{ name: 'run.json', content }, { name: 'note.txt', content: Buffer.from('not a run') }];
  const { envelope } = signFiles(files, { privateKey: key.privatePem, version: '0.7.0', release: PACKING });
  const results = await bothVerifiers(t, envelope, key.publicPem, files.map(f => [f.name, f.content]));
  for (const { code, output } of Object.values(results)) {
    assert.equal(code, 0); assert.equal(output.verdict, 'verified');
    assert.deepEqual(output.builds, { packing: PACKING, running: [{ subject: 'run.json', release: RUNNING }] });
    assert.deepEqual(output.producer.release, PACKING);
  }
  // The default is this process's build.
  const statement = buildStatement(files, { version: '0.7.0' });
  assert.deepEqual(statement.predicate.producer, { name: 'scopehaven', version: '0.7.0', attest: 'scopehaven-attest/1', release: PRODUCER_RELEASE });
});

test('an evidence pack keeps a run made by another build apart from the build packing it, in every verifier and in VERIFY.md', { skip: !python && 'no python3' }, async t => {
  const { saved, data } = await exported(t, asRun(await runAssessment('demo-repaired'), RUNNING));
  const root = await folder(t), out = join(root, 'pack');
  await evidencePack({ runId: saved.id, dataDir: data, outputDir: out, signingKeyDir: join(root, 'keys') });
  for (const envelope of [PACK_ENVELOPE, 'run.json.dsse.json']) {
    const py = spawnSync('python3', ['-I', join(out, 'verify_envelope.py'), '--key', 'scopehaven-signing-key.pub.pem', '--envelope', envelope, '--dir', '.'], { cwd: out, encoding: 'utf8' });
    assert.equal(py.status, 0, py.stdout);
    const node = spawnSync(process.execPath, [NODE_CLI, 'verify', '--key', 'scopehaven-signing-key.pub.pem', '--envelope', envelope, '--dir', '.'], { cwd: out, encoding: 'utf8' });
    assert.equal(node.status, 0, node.stdout);
    for (const { builds } of [JSON.parse(py.stdout), JSON.parse(node.stdout)]) {
      assert.deepEqual(builds.packing, PRODUCER_RELEASE, envelope);
      assert.deepEqual(builds.running.find(b => b.subject === 'run.json').release, RUNNING, envelope);
    }
  }
  const text = await readFile(join(out, VERIFY_FILE), 'utf8');
  assert.match(text, new RegExp(`Build that ran it: ScopeHaven 0\\.6\\.0, commit ${COMMIT_A} \\(release-manifest, sha256 ${'c'.repeat(64)}\\)`));
  assert.match(text, new RegExp(`Build that made this pack: ScopeHaven ${PRODUCER_RELEASE.version}, commit ${PRODUCER_RELEASE.commit}`));
  const checker = spawnSync('python3', ['-I', join(out, CHECKER_FILE), '--key', 'scopehaven-signing-key.pub.pem', '--envelope', PACK_ENVELOPE, '--dir', '.', '--text'], { cwd: out, encoding: 'utf8' });
  assert.match(checker.stdout, new RegExp(`Packed by: ScopeHaven ${PRODUCER_RELEASE.version}, commit ${PRODUCER_RELEASE.commit}`), checker.stdout);
  assert.match(checker.stdout, new RegExp(`run\\.json was run by: ScopeHaven 0\\.6\\.0, commit ${COMMIT_A} \\(release-manifest\\)`), checker.stdout);
});

test('saved before this change: the sample pack still verifies in both verifiers, and reads not recorded', { skip: !existsSync(SAMPLE_PACK) && 'no sample pack' }, async t => {
  const publicPem = await readFile(join(SAMPLE_PACK, 'scopehaven-signing-key.pub.pem'), 'utf8');
  const envelopes = (await readdir(SAMPLE_PACK)).filter(name => name.endsWith('.dsse.json') && !name.includes('countersign'));
  assert.ok(envelopes.length >= 7);
  for (const name of envelopes) {
    const envelope = await readFile(join(SAMPLE_PACK, name));
    const subjects = JSON.parse(Buffer.from(JSON.parse(envelope).payload, 'base64').toString()).subject.map(s => s.name);
    const files = await Promise.all(subjects.map(async subject => [subject, await readFile(join(SAMPLE_PACK, subject))]));
    const results = await bothVerifiers(t, envelope, publicPem, files);
    for (const { code, output } of Object.values(results)) {
      assert.equal(code, 0, `${name}: ${output.detail}`);
      assert.equal(Object.hasOwn(output.producer, 'release'), false, name);
      assert.equal(output.builds.packing, null, name);
      for (const entry of output.builds.running) assert.equal(entry.release, null, name);
    }
  }
});

test('across versions: an older signer over a newer run, and this signer over an older run or payments run', async t => {
  const key = generateSigningKey(), newer = await exported(t, asRun(await runAssessment('demo-repaired'), RUNNING));
  // An older build's statement has no release, and its run identities are the same as this build's, so it still matches a newer run.
  const statement = buildStatement([{ name: 'run.json', content: newer.content }], { version: '0.6.0' });
  delete statement.predicate.producer.release;
  let results = await bothVerifiers(t, signStatement(statement, key.privatePem), key.publicPem, [['run.json', newer.content]]);
  for (const { code, output } of Object.values(results)) { assert.equal(code, 0, output.detail); assert.deepEqual(output.builds, { packing: null, running: [{ subject: 'run.json', release: RUNNING }] }); }

  const older = await exported(t, await runAssessment('demo-repaired'));
  assert.equal(Object.hasOwn(JSON.parse(older.content), 'producer'), false);
  const signed = signFiles([{ name: 'run.json', content: older.content }], { privateKey: key.privatePem, version: '0.7.0', release: PACKING });
  results = await bothVerifiers(t, signed.envelope, key.publicPem, [['run.json', older.content]]);
  for (const { code, output } of Object.values(results)) { assert.equal(code, 0, output.detail); assert.deepEqual(output.builds, { packing: PACKING, running: [{ subject: 'run.json', release: null }] }); }

  // A payments run saved before the field, and one made with it: both are payments runs by every reader's rules.
  const sampleText = await readFile(PAYMENTS_SAMPLE), { comparison: _, ...sample } = JSON.parse(sampleText);
  assert.equal(Object.hasOwn(sample, 'producer'), false);
  savedPaymentsRun(sample);
  const { sha256: _sum, ...body } = sample, reseal = fields => { const run = { ...body, ...fields }; return { ...run, sha256: digest(run) }; };
  const stamped = reseal({ producer: { release: RUNNING } });
  savedPaymentsRun(stamped);
  const bytes = Buffer.from(JSON.stringify(stamped));
  const paid = signFiles([{ name: 'payments-run.json', content: bytes }, { name: 'old-payments.json', content: Buffer.from(JSON.stringify(sample)) }], { privateKey: key.privatePem, version: '0.7.0', release: PACKING });
  results = await bothVerifiers(t, paid.envelope, key.publicPem, [['payments-run.json', bytes], ['old-payments.json', Buffer.from(JSON.stringify(sample))]]);
  for (const { code, output } of Object.values(results)) {
    assert.equal(code, 0, output.detail);
    assert.deepEqual(output.builds, { packing: PACKING, running: [{ subject: 'payments-run.json', release: RUNNING }, { subject: 'old-payments.json', release: null }] });
  }
  // The field set stays closed: one more field than a run has is still refused.
  assert.throws(() => savedPaymentsRun(reseal({ producer: { release: RUNNING }, extra: 1 })), /exactly the fields/);
  const root = await folder(t); await exportPaymentsRun({ run: stamped, format: 'json', outputFile: join(root, 'p.json'), sign: false });
  assert.equal(JSON.parse(await readFile(join(root, 'p.json'), 'utf8')).producer.release.commit, COMMIT_A);
});

test('a signed release of the wrong form is rejected by both verifiers; an unreadable one in a run reads not recorded', async t => {
  const key = generateSigningKey(), { content } = await exported(t, await runAssessment('demo-repaired')), files = [['run.json', content]];
  const forged = change => { const s = buildStatement([{ name: 'run.json', content }], { version: '0.7.0', release: PACKING }); change(s.predicate.producer); return signStatement(s, key.privatePem); };
  const wrong = {
    'a string': p => { p.release = 'unknown'; }, null: p => { p.release = null; }, 'an extra field': p => { p.release = { ...PACKING, note: 'x' }; }, 'a missing field': p => { const { commit, ...rest } = PACKING; p.release = rest; },
    'a short commit': p => { p.release = { ...PACKING, commit: 'abc' }; }, 'uppercase hex': p => { p.release = { ...PACKING, commit: COMMIT_A.toUpperCase() }; }, 'a newline after the commit': p => { p.release = { ...PACKING, commit: `${COMMIT_A}\n` }; },
    'a manifest hash on a checkout': p => { p.release = { ...PACKING, manifestSha256: 'c'.repeat(64) }; }, 'no manifest hash on a release': p => { p.release = { ...RUNNING, manifestSha256: null }; },
    'a commit on unknown': p => { p.release = { ...UNKNOWN('0.7.0'), commit: COMMIT_A }; }, 'another source': p => { p.release = { ...PACKING, source: 'tag' }; }, 'a bad version': p => { p.release = { ...PACKING, version: 'v1' }; }, 'a non-ASCII digit': p => { p.release = { ...PACKING, version: '١.0.0' }; },
    'another field beside it': p => { p.extra = 1; },
  };
  for (const [what, change] of Object.entries(wrong)) {
    const results = await bothVerifiers(t, forged(change), key.publicPem, files);
    for (const { code, output } of Object.values(results)) { assert.equal(code, 1, what); assert.equal(output.reason, 'predicate-shape', what); }
  }
  for (const release of [UNKNOWN('unknown'), UNKNOWN('0.7.0'), RUNNING, PACKING]) {
    const results = await bothVerifiers(t, forged(p => { p.release = release; }), key.publicPem, files);
    for (const { code, output } of Object.values(results)) { assert.equal(code, 0, output.detail); assert.deepEqual(output.builds.packing, release); }
  }
  // A run file is covered by its digest, so its build is only read: an odd one reads not recorded, and the run still verifies.
  for (const producer of ['x', 7, null, {}, { release: 'unknown' }, { release: { ...RUNNING, commit: 'abc' } }]) {
    const odd = await exported(t, Object.assign(await runAssessment('demo-repaired'), { producer }));
    const signed = signFiles([{ name: 'run.json', content: odd.content }], { privateKey: key.privatePem, version: '0.7.0', release: PACKING });
    const results = await bothVerifiers(t, signed.envelope, key.publicPem, [['run.json', odd.content]]);
    for (const { code, output } of Object.values(results)) { assert.equal(code, 0, output.detail); assert.deepEqual(output.builds.running, [{ subject: 'run.json', release: null }]); }
  }
});

test('stampProducer copies the frozen record, and verifyEnvelope with no run lists none', async () => {
  const run = stampProducer({}); run.producer.release.commit = 'changed';
  assert.notEqual(PRODUCER_RELEASE.commit, 'changed');
  assert.equal(Object.isFrozen(PRODUCER_RELEASE), true);
  const key = generateSigningKey(), files = [{ name: 'a.txt', content: Buffer.from('a') }], { envelope } = signFiles(files, { privateKey: key.privatePem, version: '0.7.0' });
  const { builds } = verifyEnvelope({ envelope, publicKey: key.publicPem, files: new Map([['a.txt', files[0].content]]) });
  assert.deepEqual(builds, { packing: PRODUCER_RELEASE, running: [] });
});
