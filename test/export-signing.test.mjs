// Signed by default: `scopehaven export` signs every export into a DSSE envelope beside it (integrations/attest)
// with a local Ed25519 key made on first use, unless --unsigned. Owned synthetic fixture over loopback only; every file is
// written under a fresh private temporary directory, and the key directory is always --signing-key-dir or a temporary HOME,
// never this user's ~/.config. The signed-by-default promise is the command's: library callers of exportRun() and main() sign only
// when asked, so the other test files that export make no key.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createPrivateKey } from 'node:crypto';
import { runAssessment } from '../src/runner.mjs';
import { createStore } from '../src/store.mjs';
import { renderReport } from '../src/report.mjs';
import { renderSummary } from '../src/report-summary.mjs';
import { residualDocument } from '../src/residual.mjs';
import { exportRun, main, defaultSigningKeyDir, KEY_FILE, PUBLIC_KEY_FILE, SIGNING_KEY_UNSAFE, SIGNING_FAILED, signedEvidenceText } from '../src/export-cli.mjs';
import { verifyEnvelope, keyIdOf, trustedKey } from '../integrations/attest/verify.mjs';

const vulnerable = await runAssessment('demo-vulnerable'), repaired = await runAssessment('demo-repaired');
// The real default key directory of whoever runs this file: its state is taken now and must be the same at the end.
const REAL_KEY_DIR = defaultSigningKeyDir();
const keyDirState = () => lstat(REAL_KEY_DIR).then(s => ({ ino: s.ino, mtimeMs: s.mtimeMs, mode: s.mode }), error => error.code);
const realBefore = await keyDirState();
const copy = value => structuredClone(value);
const CLI = fileURLToPath(new URL('../src/export-cli.mjs', import.meta.url));
const PYTHON_VERIFIER = fileURLToPath(new URL('../integrations/attest/verify_envelope.py', import.meta.url));
const NODE_VERIFIER = fileURLToPath(new URL('../integrations/attest/cli.mjs', import.meta.url));
const python = spawnSync('python3', ['--version'], { encoding: 'utf8' }).status === 0;
const KEYID = /^[0-9a-f]{64}$/;
// Every export format of a run, and both comparison formats.
const RUN_FILES = { json: 'run.json', html: 'run.html', sarif: 'run.sarif', summary: 'summary.html', residual: 'residual.json' };
const COMPARISON_FILES = { json: 'comparison.json', html: 'comparison.html' };

// A fresh workspace: a store with both demo builds, a private export directory and a private key directory (not yet created).
async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven signing '));
  t.after(() => rm(root, { recursive: true, force: true }));
  const data = join(root, 'store'), out = join(root, 'exports'), keys = join(root, 'keys');
  const store = createStore(data); await store.ready;
  const baseline = await store.save(copy(vulnerable)), candidate = await store.save(copy(repaired));
  await mkdir(out, { mode: 0o700 });
  return { root, data, out, keys, store, baseline, candidate };
}
async function exportAll(w, extra = {}) {
  const results = {};
  for (const [format, name] of Object.entries(RUN_FILES)) results[name] = await exportRun({ runId: w.candidate.id, format, outputFile: join(w.out, name), dataDir: w.data, signingKeyDir: w.keys, ...extra });
  for (const [format, name] of Object.entries(COMPARISON_FILES)) results[name] = await exportRun({ runId: w.candidate.id, baselineRunId: w.baseline.id, format, outputFile: join(w.out, name), dataDir: w.data, signingKeyDir: w.keys, ...extra });
  return results;
}
const nodeVerify = async (publicKeyPath, envelopePath, dir) => {
  const name = envelopePath.slice(envelopePath.lastIndexOf('/') + 1, -'.dsse.json'.length);
  return verifyEnvelope({ envelope: await readFile(envelopePath), publicKey: await readFile(publicKeyPath, 'utf8'), files: new Map([[name, await readFile(join(dir, name))]]) });
};
const pythonVerify = (publicKeyPath, envelopePath, dir) => spawnSync('python3', ['-I', PYTHON_VERIFIER, '--key', publicKeyPath, '--envelope', envelopePath, '--dir', dir], { encoding: 'utf8' });
const run = (args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
// The printed verify commands name `node` and `python3`: run them through sh with the pinned runtime first on PATH.
const sh = command => spawnSync('sh', ['-c', command], { encoding: 'utf8', env: { ...process.env, PATH: `${dirname(process.execPath)}:${process.env.PATH ?? ''}` } });
const mode = async path => (await stat(path)).mode & 0o777;

test('every export is signed by default with one local key: an envelope beside each file, the same key id throughout, both verifiers accept, and --unsigned writes none', async t => {
  const w = await workspace(t), results = await exportAll(w);
  const names = Object.keys(results);
  assert.deepEqual((await readdir(w.out)).sort(), [...names, ...names.map(n => `${n}.dsse.json`)].sort(), 'exactly one envelope beside each export, nothing else');
  const keyids = new Set();
  for (const [name, result] of Object.entries(results)) {
    assert.equal(result.saved, true); assert.equal(result.signature.envelope, join(w.out, `${name}.dsse.json`)); assert.equal(result.signature.publicKey, join(w.keys, PUBLIC_KEY_FILE));
    assert.match(result.signature.keyid, KEYID); keyids.add(result.signature.keyid);
    assert.equal(await mode(result.signature.envelope), 0o600, 'the envelope is as private as the export');
    // The script path is quoted only when it needs it (this checkout has a space; a hosted runner's does not); the files always are.
    assert.match(result.signature.verify.python, /^python3 '?\S.*verify_envelope\.py'? --key '.*\.pub\.pem' --envelope '.*\.dsse\.json' --dir '.*'$/);
    assert.match(result.signature.verify.node, /^node '?\S.*cli\.mjs'? verify --key '.*\.pub\.pem' --envelope '.*\.dsse\.json' --dir '.*'$/);
    // Node: the module verifier, then the exact command the result prints (its paths have spaces, so it is run through sh).
    assert.equal((await nodeVerify(result.signature.publicKey, result.signature.envelope, w.out)).verdict, 'verified', name);
    const command = sh(result.signature.verify.node);
    assert.equal(command.status, 0, `${name}: ${command.stdout} ${command.stderr}`);
    if (python) {
      const checked = pythonVerify(result.signature.publicKey, result.signature.envelope, w.out);
      assert.equal(checked.status, 0, `${name}: ${checked.stdout}`); assert.equal(JSON.parse(checked.stdout).verdict, 'verified');
      assert.equal(sh(result.signature.verify.python).status, 0, `${name}: the printed Python command`);
    } else t.diagnostic('python3 is missing: the Python verifier was skipped');
  }
  assert.equal(keyids.size, 1, 'one key id across every export');
  assert.equal([...keyids][0], keyIdOf(trustedKey(await readFile(join(w.keys, PUBLIC_KEY_FILE), 'utf8'))), 'the key id is the fingerprint of the written public key');
  // --unsigned on the signed-by-default command: no envelope, a null signature, the same bytes as the signed run JSON (the JSON
  // record never carries a stamp). A library caller that asks for nothing gets the same: the promise is the command's.
  const plain = await main(['--run', w.candidate.id, '--format', 'json', '--out', join(w.out, 'plain.json'), '--data', w.data, '--unsigned'], { signedByDefault: true });
  assert.equal(plain.signature, null); assert.equal(plain.sha256, results['run.json'].sha256);
  const library = await exportRun({ runId: w.candidate.id, format: 'html', outputFile: join(w.out, 'library.html'), dataDir: w.data });
  assert.equal(library.signature, null); assert.equal((await main(['--run', w.candidate.id, '--format', 'sarif', '--out', join(w.out, 'library.sarif'), '--data', w.data])).signature, null);
  assert.deepEqual((await readdir(w.out)).filter(n => n.startsWith('plain') || n.startsWith('library')).sort(), ['library.html', 'library.sarif', 'plain.json']);
  assert.equal(await readFile(join(w.out, 'library.html'), 'utf8'), renderReport(await w.store.get(w.candidate.id)), 'an unsigned report carries no stamp');
  // By the command's default (the process entry), the same export is signed with the key under --signing-key-dir.
  const command = run(['--run', w.candidate.id, '--format', 'json', '--out', join(w.out, 'command.json'), '--data', w.data, '--signing-key-dir', w.keys]);
  assert.equal(command.status, 0, command.stderr); assert.equal(JSON.parse(command.stdout).signature.keyid, [...keyids][0]);
  // A repeat SARIF export under another name is still byte-identical: the signing property names no file name.
  const again = await exportRun({ runId: w.candidate.id, format: 'sarif', outputFile: join(w.out, 'again.sarif'), dataDir: w.data, signingKeyDir: w.keys });
  assert.equal(again.sha256, results['run.sarif'].sha256);
});

test('any tampered byte of a signed export is rejected by both verifiers, and the untouched copy still verifies', async t => {
  const w = await workspace(t), results = await exportAll(w);
  for (const name of ['run.html', 'run.sarif', 'run.json']) {
    const path = join(w.out, name), original = await readFile(path), { envelope, publicKey } = results[name].signature;
    assert.equal((await nodeVerify(publicKey, envelope, w.out)).verdict, 'verified', `${name} control`);
    for (const at of [0, Math.floor(original.length / 2), original.length - 1]) {
      const tampered = Buffer.from(original); tampered[at] ^= 0x01;
      await writeFile(path, tampered);
      const result = await nodeVerify(publicKey, envelope, w.out);
      assert.equal(result.verdict, 'rejected', `${name} byte ${at}`); assert.equal(result.verified, false);
      if (python) assert.equal(pythonVerify(publicKey, envelope, w.out).status, 1, `${name} byte ${at} (python)`);
    }
    await writeFile(path, original);
    assert.equal((await nodeVerify(publicKey, envelope, w.out)).verdict, 'verified', `${name} restored`);
  }
});

test('the key: 0600 in a 0700 directory made on first use (--signing-key-dir, or ~/.config/scopehaven/signing under HOME); a key or directory with a wrong mode is refused, never repaired, and no export is left', async t => {
  const w = await workspace(t);
  assert.equal(await lstat(w.keys).catch(e => e.code), 'ENOENT', 'the key directory does not exist before first use');
  const firstKeyId = (await exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'first.json'), dataDir: w.data, signingKeyDir: w.keys })).signature.keyid;
  assert.equal(await mode(w.keys), 0o700); assert.equal(await mode(join(w.keys, KEY_FILE)), 0o600); assert.equal(await mode(join(w.keys, PUBLIC_KEY_FILE)), 0o644);
  // The private key is a PKCS#8 PEM Ed25519 key (its header is spelled in two parts so a secret scanner does not read this test as a key).
  const privatePem = await readFile(join(w.keys, KEY_FILE), 'utf8');
  assert.ok(privatePem.startsWith(['-----BEGIN', 'PRIVATE KEY-----\n'].join(' '))); assert.equal(createPrivateKey(privatePem).asymmetricKeyType, 'ed25519');
  assert.match(await readFile(join(w.keys, PUBLIC_KEY_FILE), 'utf8'), /^-----BEGIN PUBLIC KEY-----\n/);
  // The default directory, through a temporary HOME in a child process: created 0700 under ~/.config/scopehaven/signing.
  const home = join(w.root, 'home'); await mkdir(home, { mode: 0o700 });
  const first = run(['--run', w.candidate.id, '--format', 'html', '--out', join(w.out, 'home.html'), '--data', w.data], { HOME: home });
  assert.equal(first.status, 0, first.stderr);
  const defaultDir = join(home, '.config', 'scopehaven', 'signing');
  assert.equal(JSON.parse(first.stdout).signature.publicKey, join(defaultDir, PUBLIC_KEY_FILE));
  assert.equal(await mode(defaultDir), 0o700); assert.equal(await mode(join(defaultDir, KEY_FILE)), 0o600);
  // A second export under that HOME reuses the key: the same key id, no new key.
  const second = run(['--run', w.candidate.id, '--format', 'sarif', '--out', join(w.out, 'home.sarif'), '--data', w.data], { HOME: home });
  assert.equal(second.status, 0, second.stderr); assert.equal(JSON.parse(second.stdout).signature.keyid, JSON.parse(first.stdout).signature.keyid);
  // An existing key readable by others is refused with signing-key-unsafe: nothing is exported and the key is not repaired.
  await chmod(join(w.keys, KEY_FILE), 0o644);
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'refused.json'), dataDir: w.data, signingKeyDir: w.keys }), error => error.code === SIGNING_KEY_UNSAFE && /signing-key-unsafe/.test(error.message));
  assert.equal(await mode(join(w.keys, KEY_FILE)), 0o644, 'never repaired');
  const refused = run(['--run', w.candidate.id, '--format', 'json', '--out', join(w.out, 'refused-cli.json'), '--data', w.data, '--signing-key-dir', w.keys]);
  assert.equal(refused.status, 2); assert.match(refused.stderr, /signing-key-unsafe/); assert.equal(refused.stdout, '');
  assert.doesNotMatch(refused.stderr + refused.stdout, /PRIVATE KEY|MC4CAQAw/, 'no key material in the error output');
  await chmod(join(w.keys, KEY_FILE), 0o600);
  // A key directory that is not 0700, or is a symlink, is refused the same way.
  await chmod(w.keys, 0o755);
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'refused-dir.json'), dataDir: w.data, signingKeyDir: w.keys }), error => error.code === SIGNING_KEY_UNSAFE);
  await chmod(w.keys, 0o700);
  const alias = join(w.root, 'alias'); await symlink(w.keys, alias);
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'refused-link.json'), dataDir: w.data, signingKeyDir: w.keys.replace(/keys$/, 'alias') }), error => error.code === SIGNING_KEY_UNSAFE);
  // A missing public key file is written again from the private key (same key id); a public key file that does not match the private key is refused.
  await rm(join(w.keys, PUBLIC_KEY_FILE));
  assert.equal((await exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'republished.json'), dataDir: w.data, signingKeyDir: w.keys })).signature.keyid, firstKeyId);
  assert.equal(await mode(join(w.keys, PUBLIC_KEY_FILE)), 0o644);
  const publicPem = await readFile(join(w.keys, PUBLIC_KEY_FILE), 'utf8');
  await writeFile(join(w.keys, PUBLIC_KEY_FILE), (await readFile(join(defaultDir, PUBLIC_KEY_FILE), 'utf8')));
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'refused-pub.json'), dataDir: w.data, signingKeyDir: w.keys }), error => error.code === SIGNING_KEY_UNSAFE);
  await writeFile(join(w.keys, PUBLIC_KEY_FILE), publicPem);
  // An orphaned public key (no private key beside it) in an otherwise empty directory: first use refuses it and keeps no new private key.
  const orphan = join(w.root, 'orphan'); await mkdir(orphan, { mode: 0o700 }); await writeFile(join(orphan, PUBLIC_KEY_FILE), await readFile(join(defaultDir, PUBLIC_KEY_FILE)), { mode: 0o644 });
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'refused-orphan.json'), dataDir: w.data, signingKeyDir: orphan }), error => error.code === SIGNING_KEY_UNSAFE && /exists without its private key/.test(error.message));
  assert.deepEqual(await readdir(orphan), [PUBLIC_KEY_FILE], 'no private key and no temporary file left beside the orphan');
  assert.deepEqual((await readdir(w.out)).filter(n => n.startsWith('refused') || n.startsWith('.')), [], 'a refused key leaves no export and no temporary file');
  // After the refusals, the untouched key signs again with the same id.
  const after = await exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'after.json'), dataDir: w.data, signingKeyDir: w.keys });
  assert.equal(after.signature.keyid, keyIdOf(trustedKey(publicPem))); assert.equal(after.signature.keyid, firstKeyId);
});

test('no key material in any export or envelope; the run JSON stays the sealed record and the summary keeps its bytes', async t => {
  const w = await workspace(t); await exportAll(w);
  const privatePem = await readFile(join(w.keys, KEY_FILE), 'utf8'), publicPem = await readFile(join(w.keys, PUBLIC_KEY_FILE), 'utf8');
  const body = pem => pem.split('\n').filter(line => line && !line.startsWith('-----')).join('');
  assert.ok(body(privatePem).length > 40 && body(publicPem).length > 40);
  for (const name of await readdir(w.out)) {
    const text = await readFile(join(w.out, name), 'utf8');
    assert.doesNotMatch(text, /PRIVATE KEY/, name); assert.equal(text.includes(body(privatePem)), false, name);
    assert.equal(text.includes(body(publicPem)), false, `${name}: the public key travels as its own file, not inside the evidence`);
  }
  const stored = await w.store.get(w.candidate.id);
  assert.equal(await readFile(join(w.out, 'run.json'), 'utf8'), `${JSON.stringify(stored, null, 2)}\n`, 'the signed run JSON is byte-for-byte the record: no key, key id or signature field');
  assert.equal(JSON.stringify(await w.store.get(w.candidate.id)), JSON.stringify(stored), 'the stored run did not change');
  assert.equal(await readFile(join(w.out, 'summary.html'), 'utf8'), renderSummary(stored, { residual: residualDocument(stored) }), 'the summary export keeps renderSummary\'s bytes (its Verify section already names both verifiers)');
  assert.equal(await readFile(join(w.out, 'residual.json'), 'utf8'), `${JSON.stringify(residualDocument(stored), null, 2)}\n`);
});

test('the HTML report and comparison name the key id and the verify command inside the signed bytes; SARIF names the key id and its envelope rule', async t => {
  const w = await workspace(t), results = await exportAll(w);
  const keyid = results['run.html'].signature.keyid;
  for (const [name, envelopeName] of [['run.html', 'run.html.dsse.json'], ['comparison.html', 'comparison.html.dsse.json']]) {
    const html = await readFile(join(w.out, name), 'utf8');
    const stamps = html.match(/<p class="signed-evidence">/g) ?? [];
    assert.equal(stamps.length, 1, `${name}: exactly one stamp`);
    assert.ok(html.endsWith(`</p></html>`), `${name}: the stamp closes the document`);
    const expected = signedEvidenceText(keyid, envelopeName);
    assert.ok(html.includes(`key id ${keyid}; the envelope is ${envelopeName} beside it.`), `${name}: key id and envelope`);
    assert.ok(html.includes(`python3 integrations/attest/verify_envelope.py --key DIR/${PUBLIC_KEY_FILE} --envelope ${envelopeName} --dir DIR`), `${name}: the verify line names the key where DIR holds it`);
    assert.ok(html.includes('node integrations/attest/cli.mjs verify with the same arguments'), `${name}: the Node verifier`);
    assert.ok(html.includes('not that the results are correct.'), `${name}: what a signature does not show`);
    assert.doesNotMatch(expected, /\/Users\/|\/home\/|\/private\/|\/var\/folders\//, 'the stamp names no path of this machine');
    assert.doesNotMatch(html, /\/var\/folders\/|\/private\/var\//, `${name}: no path of this machine`);
  }
  // The stamp is inside the signed bytes: the unstamped report does not verify against the envelope.
  const stored = await w.store.get(w.candidate.id), { envelope, publicKey } = results['run.html'].signature;
  const unstamped = verifyEnvelope({ envelope: await readFile(envelope), publicKey: await readFile(publicKey, 'utf8'), files: new Map([['run.html', Buffer.from(renderReport(stored))]]) });
  assert.equal(unstamped.verdict, 'rejected');
  // SARIF: runs[0].properties.signing names the key id and where the envelope is; results, rules and run identities are as before.
  const sarif = JSON.parse(await readFile(join(w.out, 'run.sarif'), 'utf8')).runs[0];
  assert.deepEqual(sarif.properties.signing, { attest: 'scopehaven-attest/1', keyid, envelope: 'This file name with .dsse.json appended, beside this file.', meaning: 'A valid signature shows that the key holder produced these exact bytes, not that the results are correct.' });
  assert.doesNotMatch(JSON.stringify(sarif.properties.signing), /\/Users\/|\/var\/folders\//);
  const plain = await main(['--run', w.candidate.id, '--format', 'sarif', '--out', join(w.out, 'plain.sarif'), '--data', w.data, '--unsigned'], { signedByDefault: true });
  assert.equal(plain.signature, null);
  const unsigned = JSON.parse(await readFile(join(w.out, 'plain.sarif'), 'utf8')).runs[0];
  assert.equal(unsigned.properties.signing, undefined);
  const { signing, ...signedProps } = sarif.properties;
  assert.deepEqual(signedProps, unsigned.properties, 'signing is the only property the signed SARIF adds');
  assert.deepEqual(sarif.results, unsigned.results); assert.deepEqual(sarif.tool, unsigned.tool);
});

test('a failed sign leaves no export file, and a signed export is refused before writing when its name cannot be a subject', async t => {
  const w = await workspace(t);
  // The envelope's name is taken: the export is published, signing fails to publish beside it, and the export is removed again.
  const taken = join(w.out, 'report.html.dsse.json'); await writeFile(taken, 'not an envelope\n', { mode: 0o600 });
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'html', outputFile: join(w.out, 'report.html'), dataDir: w.data, signingKeyDir: w.keys }), error => error.code === SIGNING_FAILED && /report\.html\.dsse\.json already exists/.test(error.message));
  assert.equal(await lstat(join(w.out, 'report.html')).catch(e => e.code), 'ENOENT', 'the export file was removed');
  assert.equal(await readFile(taken, 'utf8'), 'not an envelope\n', 'the file in the way is untouched');
  const cli = run(['--run', w.candidate.id, '--format', 'html', '--out', join(w.out, 'report.html'), '--data', w.data, '--signing-key-dir', w.keys]);
  assert.equal(cli.status, 2); assert.match(cli.stderr, /signing-failed/); assert.equal(await lstat(join(w.out, 'report.html')).catch(e => e.code), 'ENOENT');
  // A name the envelope cannot carry as a subject (a space) is refused before any file or key is touched; --unsigned takes it.
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'my run.json'), dataDir: w.data, signingKeyDir: join(w.root, 'never') }), /Invalid export options/);
  assert.equal(await lstat(join(w.root, 'never')).catch(e => e.code), 'ENOENT', 'no key directory was made for a refused export');
  assert.equal((await exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'my run.json'), dataDir: w.data, sign: false })).signature, null);
  // A wrong run id makes no key either: the runs are read before the key.
  await assert.rejects(exportRun({ runId: '00000000-0000-4000-8000-0000000000ff', format: 'json', outputFile: join(w.out, 'missing.json'), dataDir: w.data, signingKeyDir: join(w.root, 'never') }), /not found/);
  assert.equal(await lstat(join(w.root, 'never')).catch(e => e.code), 'ENOENT');
  // --unsigned with --signing-key-dir is contradictory; a non-boolean sign, sign false with a key directory, or a relative key directory is refused.
  await assert.rejects(main(['--run', w.candidate.id, '--format', 'json', '--out', join(w.out, 'x.json'), '--data', w.data, '--unsigned', '--signing-key-dir', w.keys]), /Invalid export options/);
  await assert.rejects(main(['--run', w.candidate.id, '--format', 'json', '--out', join(w.out, 'x.json'), '--data', w.data, '--unsigned', '--unsigned']), /Invalid export options/);
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'x.json'), dataDir: w.data, signingKeyDir: 'keys' }), /Invalid export options/);
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'x.json'), dataDir: w.data, sign: 'yes' }), /Invalid export options/);
  await assert.rejects(exportRun({ runId: w.candidate.id, format: 'json', outputFile: join(w.out, 'x.json'), dataDir: w.data, sign: false, signingKeyDir: w.keys }), /Invalid export options/);
  assert.deepEqual((await readdir(w.out)).sort(), ['my run.json', 'report.html.dsse.json']);
});

test('no test here, and no library call to exportRun or main, wrote under the real ~/.config/scopehaven/signing', async () => {
  assert.ok(REAL_KEY_DIR.endsWith('/.config/scopehaven/signing'));
  assert.deepEqual(await keyDirState(), realBefore, `the real key directory ${typeof realBefore === 'string' ? 'still does not exist' : 'is unchanged'}`);
});
