import { constants } from 'node:fs';
import { lstat, mkdir, open, link, readFile, unlink } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { homedir } from 'node:os';
import { createHash, createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import { createStore } from './store.mjs';
import { escape, renderReport, comparisonDocument, renderComparisonReport, coverageOf } from './report.mjs';
import { renderSarif, validateSuppliedStandardsMap } from './sarif.mjs';
import { renderSummary } from './report-summary.mjs';
import { residualDocument } from './residual.mjs';
import { compareRuns } from './runner.mjs';
import { assertRuntime } from './runtime.mjs';
import { idValid } from './http.mjs';
// Coverage in every export: the operator's pre-run coverage report when its files are given (read only), and the
// per-actor allowed-use coverage read from the run (src/report.mjs coverageOf). Presentation only: outside every verdict and hash.
import { coverageReport, coverageLines } from '../integrations/coverage-report/coverage.mjs';
import { validateTargetFile, contractDigest } from './contracts.mjs';
// Signed by default: the `scopehaven export` command signs every export into a DSSE envelope beside it with a local
// Ed25519 key (integrations/attest), unless --unsigned. The signer verifies its own envelope before the envelope is written; a
// failed sign removes the export it would have covered. Library callers of exportRun() and main() sign only when asked
// (sign: true, a signing key directory, or main's signedByDefault), so a test or a tool that signs with its own key makes no key.
import { generateSigningKey, signFiles } from '../integrations/attest/sign.mjs';
import { ATTEST_VERSION, SUBJECT_NAME, keyIdOf } from '../integrations/attest/verify.mjs';
import { KEY_FILE, PUBLIC_KEY_FILE } from '../integrations/attest/cli.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const RUN_FORMATS = Object.freeze(['json', 'html', 'sarif', 'summary', 'residual']);
export const COMPARISON_FORMATS = Object.freeze(['json', 'html']);

// Supported file-save fallback for browsers that cannot deliver Blob downloads.
// Local operator only: never mount the filesystem path argument on the web API.
// A saved run is exported as JSON, HTML, SARIF 2.1.0, a compact HTML summary, or its residual (src/residual.mjs: every row's claim
// type and what the run did not show, as JSON; the JSON export stays the sealed record and carries neither). With --baseline, the
// saved runs are compared exactly as the local API does and the core result is
// exported without upgrading any label. A SARIF export may name the operator's own reviewed standards map
// (--standards-file), for suites whose check IDs come from the operator's profile; it replaces the bundled map for
// that export only, is validated like it, and never feeds a run hash.
const STANDARDS_FILE_LIMIT = 1024 * 1024, COVERAGE_FILE_LIMIT = 4 * 1024 * 1024;
// One open (no symlink, no blocking on a FIFO), checked through the handle, read to at most the limit plus one byte.
const readStandardsFile = path => readJsonFile(path, STANDARDS_FILE_LIMIT, 'Invalid standards file.');
async function readJsonFile(path, limit, failure) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (!(await handle.stat()).isFile()) throw new Error('not a regular file');
    const buffer = Buffer.alloc(limit + 1);
    let size = 0;
    while (size < buffer.length) {
      const { bytesRead } = await handle.read(buffer, size, buffer.length - size, size);
      if (bytesRead === 0) break;
      size += bytesRead;
    }
    if (size > limit) throw new Error('over the limit');
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size)));
  } catch { throw new Error(failure); } finally { await handle?.close().catch(() => {}); }
}
// The pre-run coverage report of the run's target from the operator's inventory, stated contract and target manifest, reconciled
// against the checks this run ran. The manifest is validated like any profile and must name the run's target; a profile whose
// digest is not the run's is reported with the coverage, since the coverage is then of the profile as it is now.
export const COVERAGE_INPUTS = 'coverage-inputs';
export const COVERAGE_PROFILE_WARNING = 'Warning: the exported run\'s profile digest (the candidate\'s, for a comparison) differs from the given profile\'s digest, so this coverage is of the given profile as it is now, not necessarily of the suite that run ran.';
async function coverageFor(run, { inventory, contract, targets }) {
  const read = async (path, label) => { try { return await readJsonFile(path, COVERAGE_FILE_LIMIT, label); } catch (error) { throw coded(COVERAGE_INPUTS, error.message); } };
  const files = { inventory: await read(inventory, 'Invalid coverage inventory file.'), contract: await read(contract, 'Invalid coverage contract file.'), targets: await read(targets, 'Invalid coverage targets file.') };
  // The validated, normalized targets: the connector digests the normalized profile, so the digest below compares like with like.
  let validated;
  try { validated = validateTargetFile(files.targets); } catch (error) { throw coded(COVERAGE_INPUTS, `the targets file is not a valid target manifest (${error.message})`); }
  const target = validated.find(t => t.id === run.targetId);
  if (!target) throw coded(COVERAGE_INPUTS, `the targets file names no target ${JSON.stringify(run.targetId ?? null)}`);
  let report;
  try { report = coverageReport({ inventory: files.inventory, contract: files.contract, target, suiteCheckIds: (Array.isArray(run.results) ? run.results : []).map(r => r?.id) }); }
  catch (error) { throw coded(COVERAGE_INPUTS, error.message); }
  return { report, lines: coverageLines(report), warnings: run.profileHash === contractDigest(target) ? [] : [COVERAGE_PROFILE_WARNING] };
}

// The signing key: a local Ed25519 key generated on first use in a private directory outside the repository (default
// ~/.config/scopehaven/signing/, or --signing-key-dir). The directory is mode 0700, owned by the user and not a symlink; the
// private key is written 0600 with O_CREAT|O_EXCL|O_NOFOLLOW and is never printed, logged or placed in an export; the public key
// is written 0644 beside it. An existing key or directory with a wrong mode or owner is refused (signing-key-unsafe), never
// repaired. The key and its id never enter a run record or its integrity hash: the run JSON export is byte-for-byte the record.
// Key files are published like exports (a 0600 temporary name, then a hard link), so the final name only ever exists complete; a
// process killed between the two leaves an unreferenced `.<uuid>.export.tmp` in the 0700 key directory, which nothing reads.
export { KEY_FILE, PUBLIC_KEY_FILE };
export const SIGNING_KEY_UNSAFE = 'signing-key-unsafe';
export const SIGNING_FAILED = 'signing-failed';
const KEY_FILE_LIMIT = 16384;
export const defaultSigningKeyDir = () => join(homedir(), '.config', 'scopehaven', 'signing');
const coded = (code, detail) => Object.assign(new Error(`${code}: ${detail}`), { code });
const unsafe = detail => coded(SIGNING_KEY_UNSAFE, detail);
const owned = stat => stat.uid === process.getuid();

async function privateDirectory(dir) {
  let stat = await lstat(dir).catch(error => { if (error.code !== 'ENOENT') throw error; return null; });
  if (!stat) { await mkdir(dir, { recursive: true, mode: 0o700 }); stat = await lstat(dir); }
  if (!stat.isDirectory() || stat.isSymbolicLink() || !owned(stat) || (stat.mode & 0o7777) !== 0o700) throw unsafe('the signing key directory must be a directory of mode 0700, owned by you and not a symlink');
}
// Opens without following a symlink and without blocking on a FIFO; checks the file through its handle. `secret` demands the
// private key's mode (nothing for group or others) and owner. Returns null when the file does not exist.
async function readKeyFile(path, { secret }) {
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch (error) { if (error.code === 'ENOENT') return null; if (error.code === 'ELOOP') throw unsafe(`${basename(path)} is a symlink`); throw error; }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || !owned(stat) || stat.size > KEY_FILE_LIMIT) throw unsafe(`${basename(path)} must be a regular file of yours, at most ${KEY_FILE_LIMIT} bytes`);
    if (secret && (stat.mode & 0o077) !== 0) throw unsafe(`${basename(path)} must be readable only by you (mode 0600)`);
    const content = await handle.readFile();
    if (content.length > KEY_FILE_LIMIT) throw unsafe(`${basename(path)} grew past ${KEY_FILE_LIMIT} bytes while being read`);
    return content.toString('utf8');
  } finally { await handle.close(); }
}
// Exclusive publication of new bytes: written to a private temporary file in the same directory, then hard-linked into place, so
// the final name only ever exists complete. Nothing is ever overwritten (EEXIST).
export async function publish(outputFile, content, mode = 0o600) {
  const parent = dirname(outputFile), temporary = join(parent, `.${randomUUID()}.export.tmp`);
  try {
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, mode);
    try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
    await link(temporary, outputFile); // Exclusive publication; never overwrite.
  } finally { await unlink(temporary).catch(() => {}); }
}
const pemTrim = pem => String(pem).replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
// Reads the key, or generates it on first use. The public key file is written when missing and must match the private key.
export async function loadSigningKey(dir) {
  await privateDirectory(dir);
  const privatePath = join(dir, KEY_FILE), publicPath = join(dir, PUBLIC_KEY_FILE);
  for (let attempt = 0; attempt < 2; attempt++) {
    const pem = await readKeyFile(privatePath, { secret: true });
    if (pem === null) {
      // First use. The key is linked into place complete, so a concurrent first use that loses the exclusive link reads the
      // winner's whole key on the next attempt.
      const key = generateSigningKey();
      try { await publish(privatePath, key.privatePem, 0o600); } catch (error) { if (error.code === 'EEXIST') continue; throw error; }
      try { await publish(publicPath, key.publicPem, 0o644); }
      catch (error) {
        // A public key file already there is ours only if a concurrent first use derived it from the private key just linked (it
        // read that key and found no public file); any other content is an orphan of a key that no longer exists. The private key
        // is unlinked only in the orphan case, never while another process may already hold it.
        const written = error.code === 'EEXIST' ? await readKeyFile(publicPath, { secret: false }) : null;
        if (written !== null && pemTrim(written) === pemTrim(key.publicPem)) return { privateKey: key.privatePem, keyid: key.keyid, publicKeyPath: publicPath };
        await unlink(privatePath).catch(() => {});
        throw error.code === 'EEXIST' ? unsafe(`${PUBLIC_KEY_FILE} exists without its private key`) : error;
      }
      return { privateKey: key.privatePem, keyid: key.keyid, publicKeyPath: publicPath };
    }
    let key;
    try { key = createPrivateKey(pem); } catch { throw unsafe(`${KEY_FILE} is not a readable private key`); }
    if (key.asymmetricKeyType !== 'ed25519') throw unsafe(`${KEY_FILE} is not an Ed25519 key`);
    const publicKey = createPublicKey(key), publicPem = publicKey.export({ type: 'spki', format: 'pem' });
    const written = await readKeyFile(publicPath, { secret: false });
    if (written === null) {
      // A concurrent first use may publish the same public key first: accept it when it is the same key, refuse any other.
      try { await publish(publicPath, publicPem, 0o644); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const again = await readKeyFile(publicPath, { secret: false });
        if (again === null || pemTrim(again) !== pemTrim(publicPem)) throw unsafe(`${PUBLIC_KEY_FILE} does not match ${KEY_FILE}`);
      }
    } else if (pemTrim(written) !== pemTrim(publicPem)) throw unsafe(`${PUBLIC_KEY_FILE} does not match ${KEY_FILE}`);
    return { privateKey: key, keyid: keyIdOf(publicKey), publicKeyPath: publicPath };
  }
  throw unsafe(`${KEY_FILE} could not be created or read`);
}

// The "Signed evidence" stamps: placed before signing, so they are inside the signed bytes. They name what a reader needs to
// verify (the key id, the envelope beside the file, both verifiers) and never a key, a path of this machine or a verdict.
const VERIFY_SCRIPTS = Object.freeze({ python: 'integrations/attest/verify_envelope.py', node: 'integrations/attest/cli.mjs' });
export const SIGNATURE_MEANING = 'A valid signature shows that the key holder produced these exact bytes, not that the results are correct.';
export const signedEvidenceText = (keyid, envelopeName) => `Signed evidence: this file is signed (${ATTEST_VERSION}, Ed25519) with key id ${keyid}; the envelope is ${envelopeName} beside it. `
  + `Verify from a ScopeHaven checkout with python3 ${VERIFY_SCRIPTS.python} --key DIR/${PUBLIC_KEY_FILE} --envelope ${envelopeName} --dir DIR, or node ${VERIFY_SCRIPTS.node} verify with the same arguments, `
  + `where DIR holds this file and the signer's public key, whose key id you confirmed with the signer over a separate channel. ${SIGNATURE_MEANING}`;
export function stampHtml(html, keyid, envelopeName) {
  if (typeof html !== 'string' || !html.endsWith('</html>')) throw coded(SIGNING_FAILED, 'the HTML export could not be stamped');
  return `${html.slice(0, -'</html>'.length)}<p class="signed-evidence">${escape(signedEvidenceText(keyid, envelopeName))}</p></html>`;
}
// SARIF names the key id and where its envelope is. The envelope entry is a rule, not this file's name, so a repeat export under
// another name stays byte-identical (the exporter's existing property).
export const sarifSigning = keyid => ({ attest: ATTEST_VERSION, keyid, envelope: 'This file name with .dsse.json appended, beside this file.', meaning: SIGNATURE_MEANING });
const shellQuote = value => /^[A-Za-z0-9_./:=-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
const verifyCommands = (publicKeyPath, envelopePath, dir) => {
  const args = `--key ${shellQuote(publicKeyPath)} --envelope ${shellQuote(envelopePath)} --dir ${shellQuote(dir)}`;
  return { python: `python3 ${shellQuote(join(root, VERIFY_SCRIPTS.python))} ${args}`, node: `node ${shellQuote(join(root, VERIFY_SCRIPTS.node))} verify ${args}` };
};
let producerVersion;
const version = async () => (producerVersion ??= JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')).version);
// The evidence pack (src/evidence-pack.mjs) quotes the signature's meaning in VERIFY.md and signs its folder envelope with this version.
export { version as signerVersion };

// Shared with the payments export (integrations/payments-pack/output.mjs), so every signed export is made one way.
// An export's parent: an existing directory of mode 0700, owned by this user and not a symlink.
export async function assertExportDirectory(parent) {
  const stat = await lstat(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) throw new Error('Export directory must be private, owned and not a symlink.');
}
// Signs a file just published (its exact bytes) into NAME.dsse.json beside it, published the same exclusive way, and returns the
// signature block an export reports. If signing fails, the file is unlinked: a signed-by-default export never leaves an unsigned
// file that looks like the signed kind.
export async function signBeside(outputFile, content, signer) {
  const parent = dirname(outputFile), name = basename(outputFile), envelopeName = `${name}.dsse.json`, envelopePath = join(parent, envelopeName);
  try {
    const { envelope } = signFiles([{ name, content }], { privateKey: signer.privateKey, version: await version() });
    await publish(envelopePath, Buffer.from(envelope));
  } catch (error) {
    await unlink(outputFile).catch(() => {});
    throw error.code === SIGNING_KEY_UNSAFE ? error : coded(SIGNING_FAILED, error.code === 'EEXIST' ? `${envelopeName} already exists` : error.message);
  }
  return { envelope: envelopePath, keyid: signer.keyid, publicKey: signer.publicKeyPath, verify: verifyCommands(signer.publicKeyPath, envelopePath, parent) };
}

export async function exportRun({ runId, format, outputFile, dataDir = join(root, 'data'), baselineRunId, standardsFile, signingKeyDir, sign = signingKeyDir !== undefined, coverageInventory, coverageContract, coverageTargets }) {
  assertRuntime();
  const comparing = baselineRunId !== undefined;
  if (!idValid(runId) || !(comparing ? COMPARISON_FORMATS : RUN_FORMATS).includes(format) || (comparing && !idValid(baselineRunId)) || !isAbsolute(outputFile || '') || !isAbsolute(dataDir)) throw new Error('Invalid export options.');
  if (standardsFile !== undefined && (format !== 'sarif' || typeof standardsFile !== 'string' || !isAbsolute(standardsFile))) throw new Error('Invalid export options.');
  if (typeof sign !== 'boolean' || (signingKeyDir !== undefined && (!sign || typeof signingKeyDir !== 'string' || !isAbsolute(signingKeyDir)))) throw new Error('Invalid export options.');
  // The three coverage files come together, as absolute paths, for the formats that carry the full report (the HTML report and the
  // comparison exports). The run JSON stays the record; SARIF, the summary and the residual read coverage from the run alone.
  const coverageFiles = [coverageInventory, coverageContract, coverageTargets];
  if (coverageFiles.some(f => f !== undefined) && (coverageFiles.some(f => typeof f !== 'string' || !isAbsolute(f)) || !(format === 'html' || comparing))) throw new Error('Invalid export options.');
  const name = basename(outputFile), envelopeName = `${name}.dsse.json`;
  // A signed file needs a plain name (the envelope's subject name): refused before anything is written.
  if (sign && (!SUBJECT_NAME.test(name) || !SUBJECT_NAME.test(envelopeName))) throw new Error('Invalid export options.');
  const standardsMap = standardsFile === undefined ? undefined : validateSuppliedStandardsMap(await readStandardsFile(standardsFile));
  await assertExportDirectory(dirname(outputFile));
  const store = createStore(dataDir); await store.ready;
  const run = await store.get(runId), baseline = comparing ? await store.get(baselineRunId) : null;
  const coverage = coverageInventory === undefined ? undefined : await coverageFor(run, { inventory: coverageInventory, contract: coverageContract, targets: coverageTargets });
  // The key is read (or made) once the runs and the coverage inputs are known to be good and before any export bytes exist: a
  // wrong run id or a refused coverage file makes no key, and a refused key leaves no file behind.
  const signer = sign ? await loadSigningKey(signingKeyDir ?? defaultSigningKeyDir()) : null;
  let text;
  if (comparing) {
    const document = comparisonDocument(baseline, run, compareRuns(baseline, run), { coverage });
    text = format === 'json' ? JSON.stringify(document, null, 2) + '\n' : renderComparisonReport(document);
  } else {
    // The summary never reads traces, so it is given the residual this exporter computes from the run.
    const residual = format === 'summary' || format === 'residual' ? residualDocument(run) : null;
    if (format === 'sarif') {
      const log = renderSarif(run, standardsMap ? { standardsMap } : undefined);
      log.runs[0].properties.coverage = { actorsWithoutAllowedUse: coverageOf(run).actorsWithoutAllowedUse };
      if (signer) log.runs[0].properties.signing = sarifSigning(signer.keyid);
      text = `${JSON.stringify(log, null, 2)}\n`;
    } else text = format === 'json' ? JSON.stringify(run, null, 2) + '\n'
      : format === 'summary' ? renderSummary(run, { residual }) : format === 'residual' ? JSON.stringify(residual, null, 2) + '\n' : renderReport(run, { coverage });
  }
  // The run JSON stays the sealed record (re-imported as a CI baseline by its integrity hash); the summary keeps renderSummary's
  // bytes (its Verify section already names both verifiers). The HTML report and the comparison report carry the stamp.
  if (signer && format === 'html') text = stampHtml(text, signer.keyid, envelopeName);
  const content = Buffer.from(text);
  if (content.length > 8 * 1024 * 1024) throw new Error('Export exceeds its limit.');
  await publish(outputFile, content);
  const signature = signer ? await signBeside(outputFile, content, signer) : null;
  return { saved: true, runId, ...(comparing ? { baselineRunId, document: 'comparison' } : {}), format, bytes: content.length, sha256: createHash('sha256').update(content).digest('hex'), signature };
}

// The command line. The `scopehaven export` process passes signedByDefault, so it signs unless --unsigned; a caller of main()
// in another process signs only with --signing-key-dir or its own signedByDefault.
export async function main(args, { signedByDefault = false } = {}) {
  const names = { '--run': 'runId', '--format': 'format', '--out': 'outputFile', '--data': 'dataDir', '--baseline': 'baselineRunId', '--standards-file': 'standardsFile', '--signing-key-dir': 'signingKeyDir',
    '--coverage-inventory': 'coverageInventory', '--coverage-contract': 'coverageContract', '--coverage-targets': 'coverageTargets' }, options = {};
  let unsigned = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--unsigned') { if (unsigned) throw new Error('Invalid export options.'); unsigned = true; continue; }
    const key = names[args[i]], value = args[i + 1];
    if (!key || Object.hasOwn(options, key) || !value || value.startsWith('--')) throw new Error('Invalid export options.');
    options[key] = value; i++;
  }
  if (unsigned && Object.hasOwn(options, 'signingKeyDir')) throw new Error('Invalid export options.');
  return exportRun({ ...options, sign: !unsigned && (signedByDefault || Object.hasOwn(options, 'signingKeyDir')) });
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { console.log(JSON.stringify(await main(process.argv.slice(2), { signedByDefault: true }), null, 2)); }
  catch (error) {
    // A key or signing problem is named by its code; everything else prints the usage. No message carries key material.
    if ([SIGNING_KEY_UNSAFE, SIGNING_FAILED].includes(error?.code)) console.error(`Export failed (${error.message}). The export file was not left behind. The signing key lives in ~/.config/scopehaven/signing (or --signing-key-dir ABSOLUTE_DIR); fix its mode or owner yourself, or pass --unsigned.`);
    else if (error?.code === COVERAGE_INPUTS) console.error(`Export failed (${error.message}). Nothing was written. --coverage-inventory, --coverage-contract and --coverage-targets are the operator's files for integrations/coverage-report, and the targets file must name this run's target.`);
    else console.error('Export failed. Use --run UUID --format json|html|sarif|summary|residual --out ABSOLUTE_NEW_FILE [--data ABSOLUTE_STORE] [--standards-file ABSOLUTE_MAP_JSON, sarif only] [--unsigned | --signing-key-dir ABSOLUTE_DIR] [--coverage-inventory ABS --coverage-contract ABS --coverage-targets ABS, html and comparison exports], or add --baseline UUID with --format json|html to export a comparison (--run is the candidate). The output parent must exist with mode0700 and belong to you. Existing files are preserved. Exports are signed into NAME.dsse.json beside the file unless --unsigned.');
    process.exitCode = 2;
  }
}
