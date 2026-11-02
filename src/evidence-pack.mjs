// One signed evidence pack: every export of one run in one new private folder, the thing a buyer hands on.
//   ./scopehaven evidence-pack --run UUID --data ABSOLUTE_STORE --out ABSOLUTE_NEW_DIR [--baseline UUID]
//       [--coverage-inventory ABS --coverage-contract ABS --coverage-targets ABS] [--signing-key-dir ABSOLUTE_DIR]
//   ./scopehaven evidence-pack --payments-run ABSOLUTE_RUN.json --out ABSOLUTE_NEW_DIR [--payments-baseline ABSOLUTE_RUN.json] [--signing-key-dir ABSOLUTE_DIR]
//   A run pack also takes [--retest-history ABSOLUTE_DIR]: a folder made by integrations/retest-ledger (cli.mjs export). Its
//   retest-history.json and envelope are copied in only when that envelope verifies under the pack's own signing key and the
//   history has a finding on the run's application and suite. A payments pack refuses it.
// The folder (mode 0700) holds the run's json, html, sarif, summary and residual exports (a payments run's json, html and sarif),
// each with its DSSE envelope beside it; with a baseline, the comparison exports too. Then the signer's public key, a copy of
// integrations/attest/verify_envelope.py, a copy of integrations/verdict-check/verify_verdicts.py (which re-derives the verdicts
// from what the run kept), a VERIFY.md with the exact commands, what a signature does and does not show and what the run's
// predicate records let a reviewer recompute, and evidence-pack.dsse.json, one envelope over every other file in the folder. Every export is made by the existing exporters
// (src/export-cli.mjs exportRun, integrations/payments-pack/output.mjs exportPaymentsRun) with one key: ~/.config/scopehaven/signing,
// or --signing-key-dir. A pack is always signed. No key material is printed, logged or placed in the folder but the public key.
//
// All or nothing: an existing path at --out (of any kind) is refused and never touched; the files are built in a private staging
// folder beside it and every envelope is verified again from the bytes on disk; only then is the name claimed (an empty directory
// made exclusively) and the staging folder renamed over the claim in one step. On any failure the staging folder (and the claim,
// once made) are removed. A process killed mid-way leaves at most a hidden .<uuid>.evidence-pack.tmp folder (and, killed between the
// last two steps, an empty folder at --out), never a partial pack. The key directory may not be or hold --out, nor sit inside it,
// and the store must already exist, so neither a key nor a store is ever made in or beside the pack by this command.
import { constants } from 'node:fs';
import { lstat, mkdir, open, chmod, readdir, readFile, realpath, rename, rm, rmdir } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, createPublicKey, randomUUID } from 'node:crypto';
import { assertRuntime } from './runtime.mjs';
import { idValid } from './http.mjs';
import { exportRun, loadSigningKey, publish, defaultSigningKeyDir, signerVersion, SIGNATURE_MEANING, PUBLIC_KEY_FILE, SIGNING_KEY_UNSAFE, SIGNING_FAILED, COVERAGE_INPUTS } from './export-cli.mjs';
import { exportPaymentsRun, readPaymentsJson, savedPaymentsRun, PAYMENTS_RUN_REFUSED } from '../integrations/payments-pack/output.mjs';
import { signFiles } from '../integrations/attest/sign.mjs';
import { PRODUCER_RELEASE } from './producer.mjs';
import { ATTEST_VERSION, CLOCK, MEANING, subjectNames, verifyEnvelope } from '../integrations/attest/verify.mjs';
import { HISTORY_FILE, HISTORY_ENVELOPE } from '../integrations/retest-ledger/cli.mjs';
import { HISTORY_VERSION } from '../integrations/retest-ledger/history.mjs';

export const PACK_ENVELOPE = 'evidence-pack.dsse.json';
export const VERIFIER_FILE = 'verify_envelope.py';
export const CHECKER_FILE = 'verify_verdicts.py';
export const VERIFY_FILE = 'VERIFY.md';
export const EVIDENCE_PACK_FAILED = 'evidence-pack-failed';
const VERIFIER_SOURCE = fileURLToPath(new URL('../integrations/attest/verify_envelope.py', import.meta.url));
const VERIFIER_LIMIT = 256 * 1024;
const CHECKER_SOURCE = fileURLToPath(new URL('../integrations/verdict-check/verify_verdicts.py', import.meta.url));
const CHECKER_LIMIT = 1024 * 1024;
// The exports of each kind of pack: [format, file name, what it is]. With a baseline, the comparison files are added.
const RUN_FILES = Object.freeze([['json', 'run.json', 'The run record as the store returns it: the run core, its integrity hash (over the core only) and any notes, which that hash does not cover.'],
  ['html', 'run.html', 'The HTML report.'], ['sarif', 'run.sarif', 'SARIF 2.1.0, for code-scanning tools.'], ['summary', 'summary.html', 'A one-page summary.'],
  ['residual', 'residual.json', "Each row's claim type and what the run did not show."]]);
const COMPARISON_FILES = Object.freeze([['json', 'comparison.json', 'The before-and-after comparison with the baseline run, as the workbench computes it.'], ['html', 'comparison.html', 'The comparison as an HTML report.']]);
const PAYMENTS_FILES = Object.freeze([['json', 'payments-run.json', 'The payments run record as produced, without any comparison stored beside it (its sha256 field is an unkeyed checksum of the rest).'],
  ['html', 'payments-run.html', 'The HTML report.'], ['sarif', 'payments-run.sarif', 'SARIF 2.1.0, for code-scanning tools.']]);
const PAYMENTS_COMPARISON_FILES = Object.freeze([['json', 'payments-comparison.json', 'The before-and-after comparison with the baseline run, recomputed from both runs.']]);
const HISTORY_ABOUT = 'The retest history (scopehaven-retest-history/1): what happened to each finding across the runs of the operator\'s evidence ledger, read with core\'s compareRuns. Rebuild it with integrations/retest-ledger/cli.mjs verify, given the same ledger, run files and declarations. It has a finding on this run\'s application and suite and may also cover the operator\'s other applications; it may predate this run, so check its ledger size and events before reading it as covering this run.';
const HISTORY_LIMIT = 64 * 1024 * 1024;
const coded = (code, detail) => Object.assign(new Error(`${code}: ${detail}`), { code });
// A refused --retest-history: the same code, marked so the command names the history in its hint and no other failure does.
const historyRefused = detail => Object.assign(coded(EVIDENCE_PACK_FAILED, `the retest history was refused: ${detail}`), { retestHistory: true });
const invalid = () => new Error('Invalid evidence-pack options.');
const outExists = () => Object.assign(new Error('--out already exists'), { code: 'EEXIST', outExists: true });
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

// An existing directory of yours, not a symlink: the folder's parent, and the store.
async function ownedDirectory(dir) {
  const stat = await lstat(dir).catch(() => null);
  if (!stat || !stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()) throw invalid();
}
// A path with its nearest existing ancestor resolved through any symlinks, so two spellings of one place compare equal.
async function realish(path) {
  let head = path, tail = [];
  for (;;) {
    try { return join(await realpath(head), ...tail); }
    catch (error) { if (error.code !== 'ENOENT' || dirname(head) === head) throw error; tail = [basename(head), ...tail]; head = dirname(head); }
  }
}
// Compared with case and Unicode normalization folded, since the default macOS volume treats `Acme` and `acme` (and both
// encodings of `café`) as one name; on a case-sensitive volume this only refuses more.
const fold = path => path.normalize('NFC').toLowerCase();
const within = (child, parent) => { const c = fold(child), p = fold(parent); return c === p || c.startsWith(p.endsWith(sep) ? p : `${p}${sep}`); };
// A history file: a regular file, not a symlink or FIFO, of at most `limit` bytes; a missing one is refused by name, not a raw errno.
async function readHistoryFile(path, limit) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
    .catch(error => { throw historyRefused(`${basename(path)} could not be opened as a regular file (${error.code ?? 'error'})`); });
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw historyRefused(`${basename(path)} is not a regular file of at most ${limit} bytes`);
    return await handle.readFile();
  } finally { await handle.close(); }
}
async function readSource(source, name, limit) {
  const handle = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > limit) throw coded(EVIDENCE_PACK_FAILED, `${name} is not a regular file of at most ${limit} bytes`);
    return await handle.readFile();
  } finally { await handle.close(); }
}
const readVerifier = () => readSource(VERIFIER_SOURCE, VERIFIER_FILE, VERIFIER_LIMIT);
const readChecker = () => readSource(CHECKER_SOURCE, CHECKER_FILE, CHECKER_LIMIT);
// What the HTTP contract run's JSON predicates keep (src/contracts.mjs predicate records), counted from run.json: { digest, value, outcome },
// or null for a run of another origin.
export function predicateRecordCounts(run) {
  if (run?.evidenceOrigin !== 'local-http-response' || !Array.isArray(run.results)) return null;
  const counts = { digest: 0, value: 0, outcome: 0 };
  for (const row of run.results) for (const p of Array.isArray(row?.observed?.predicates) ? row.observed.predicates : [])
    if (['json.equals', 'json.exists', 'json.notContains'].includes(p?.kind)) counts[['digest', 'value'].includes(p.record) ? p.record : 'outcome']++;
  return counts;
}

const ARGUMENTS = envelope => `--key ${PUBLIC_KEY_FILE} --envelope ${envelope} --dir .`;
const verifyCommand = envelope => `python3 -I ${VERIFIER_FILE} ${ARGUMENTS(envelope)}`;
const checkCommand = `python3 -I ${CHECKER_FILE} ${ARGUMENTS(PACK_ENVELOPE)} --text`;
const RUN_RECORD = 'run.json';
const runCheckCommand = `python3 -I ${CHECKER_FILE} --key ${PUBLIC_KEY_FILE} --envelope ${RUN_RECORD}.dsse.json ${RUN_RECORD} --text`;
// VERIFY.md's account of what the checker can recompute in this pack, from the run's own predicate records.
function rederiveText(kind, predicates) {
  const modes = predicates === null ? [] : [
    predicates.digest ? `${predicates.digest} in digest mode (the default): each keeps the field's JSON pointer, json.exists its expected true or false, and json.equals and json.notContains a SHA-256 of the configured value keyed with 32 random bytes of this run; json.equals also keeps one of the value the response held there, under the same key. Equal digests are equal values, so json.equals and json.exists are recomputed without either value being in this pack. A json.notContains over a present string is not (no digest shows containment), and is listed. The key is not in this pack or the run, so a short or guessable value (an amount, a boolean, a short id) cannot be found by trying candidates against its digest. If the operator set the key to share it, whoever holds it can test candidate values against every digest of this run.` : null,
    predicates.value ? `${predicates.value} in value mode (\`SCOPEHAVEN_PREDICATE_RECORD=value\`, opt-in): the pointer, the configured value and the value the response held there, in clear, so every one is recomputed and a failure reads with the field, the expected value and the actual one. These values can be the application's data: value mode is for synthetic data, or for runs whose data owner agreed to share them.` : null,
    predicates.outcome ? `${predicates.outcome} keep their outcome only (a run made before predicate records, or with \`SCOPEHAVEN_PREDICATE_RECORD=outcome\`): nothing to recompute them from, so a row resting on one is listed, not re-derived, unless another of its assertions already fails it.` : null,
  ].filter(Boolean);
  return [
    '## Re-deriving the verdicts', '',
    `A signature shows the files are unchanged since signing; it does not show the verdicts follow from what the run observed. \`${CHECKER_FILE}\` checks that: it runs \`${VERIFIER_FILE}\` first and reads only the bytes that signature covers, recomputes each verdict it can from what the run kept under rules written out in the file, refuses the pack when a stored verdict disagrees, and lists every verdict it could not recompute, by id, with its reason. A failed JSON predicate it recomputes is printed with the field compared, the expected value and the actual one, as far as the record keeps them. Standard-library Python 3.8 or newer.`, '',
    `    ${checkCommand}`, '',
    `With your own ScopeHaven checkout at CHECKOUT, from this folder (the checkout's copy runs the checkout's own \`integrations/attest/${VERIFIER_FILE}\`):`, '',
    `    python3 -I "CHECKOUT/integrations/verdict-check/${CHECKER_FILE}" ${ARGUMENTS(PACK_ENVELOPE)} --text`, '',
    'It exits 1 when a stored verdict or record disagrees (rejected), 2 on a usage or file error, and 3 when its own negative controls failed (then do not rely on it). It exits 4 when the files are consistent but the checker did not vouch for everything it was given: verdicts it left out, stored inputs a verdict rests on, or files it did not check. Read `summary` and the listing to see which. Over this folder it exits 4 even when every verdict was re-derived, because the reports, SARIF and any comparison here are listed as files it did not check: they can state verdicts of their own, and nothing compares those with the run. It exits 0 only when it vouched for everything it was given.', '',
    ...(kind === 'payments' ? ['A payments run is not one of the run kinds the checker carries rules for: it names the file and says so.', '']
      : [`To check the run record alone, against its own envelope:`, '', `    ${runCheckCommand}`, '',
        `It exits 0 when every verdict in ${RUN_RECORD} was re-derived and none rests on a stored input, and 4 when some are listed (each with its reason).`, '',
        ...(predicates === null ? ['What it re-derives for each run kind, and why the rest cannot be, is in integrations/verdict-check/SCOPE.md of a ScopeHaven checkout.', '']
      : [`This is an HTTP contract run. Its status assertions, json.noForeignValues counts and roll-ups are recomputed. Its JSON predicates (json.equals, json.exists, json.notContains) are recorded as follows:`, '',
        ...modes.map(m => `- ${m}`), '',
        'Effect, claim and read-back clauses are decided from sealed observer windows under rules the checker does not carry, so a row with one is listed unless another assertion already fails it. Whether a row should carry the identity assertion is recomputed for actors without a credential, for credentialed actors whose login the run established, and for an actor with no identity control. Otherwise it is read as recorded and listed as a stored input (it always reads inconclusive, so it can only hold a row below pass), and a row its absence would leave at pass is listed.', ''])]),
    'A re-derived verdict follows from what the run recorded. It does not show the recorded observations are true or that the application is safe; the signature is what ties them to the signer.', '',
  ];
}
// One build, for VERIFY.md (src/producer.mjs); `not recorded` for a run older than the field.
const buildText = release => !release ? 'not recorded (the run is older than this field)'
  : `ScopeHaven ${release.version}, commit ${release.commit}${release.source === 'release-manifest' ? ` (${release.source}, sha256 ${release.manifestSha256})` : ` (${release.source})`}`;
// VERIFY.md. Trust rests on the key id the verifiers print, matched against the id the signer gave over another channel; nothing
// written in this folder (the id shown here, the verifier's sha256) can stand in for that, since whoever replaces a file here can
// rewrite this text too.
export function verifyText({ kind, runId, baselineRunId, keyid, version, verifierSha256, checkerSha256, files, history = false, predicates = null, runBuild = null, packBuild = PRODUCER_RELEASE }) {
  const exported = files.filter(f => f.envelope), envelopes = [PACK_ENVELOPE, ...exported.map(f => `${f.name}.dsse.json`)];
  return [
    '# Verifying this evidence pack', '',
    history ? `This folder holds the exports of one ScopeHaven run, made by ScopeHaven ${version}, and also carries the operator's retest history (\`${HISTORY_FILE}\`) across the runs of their evidence ledger, signed with the same key. Each export and the history is signed into a DSSE envelope beside it (${ATTEST_VERSION}, Ed25519), and ${PACK_ENVELOPE} signs every other file in this folder at once.`
    : `This folder holds the exports of one ScopeHaven ${kind === 'payments' ? 'payments run' : 'run'}, made by ScopeHaven ${version}. Each export is signed into a DSSE envelope beside it (${ATTEST_VERSION}, Ed25519), and ${PACK_ENVELOPE} signs every other file in this folder at once.`, '',
    `- Run: \`${runId}\``, ...(baselineRunId ? [`- Baseline run: \`${baselineRunId}\``] : []),
    `- Key id the signer wrote here: \`${keyid}\``,
    `- Build that ran it: ${buildText(runBuild)}`, `- Build that made this pack: ${buildText(packBuild)}`, '',
    '## Before you rely on it', '',
    '1. Get the signer\'s key id from the signer over a separate channel, not from this folder. A key id is the SHA-256 of the public key\'s DER SubjectPublicKeyInfo (not of the .pem file), and both verifiers print it as `keyid`.',
    `2. Run the commands below. Each must exit 0, print \`"verdict": "verified"\`, and print a \`keyid\` equal to the id you got from the signer. The id written above is only a convenience: anyone who can make a key can write any id here, put their own public key in ${PUBLIC_KEY_FILE} and sign a folder that verifies.`, '',
    '## What a signature does and does not show', '',
    `${SIGNATURE_MEANING} ${MEANING}`, '',
    `- It does not show that the application is safe, that every behaviour was checked, or that a fix holds beyond the runs named here. What each run checked, and its limits, is stated inside the files.`,
    `- The signed time is the ${CLOCK.charAt(0).toLowerCase()}${CLOCK.slice(1)}`,
    `- ${PACK_ENVELOPE} shows that no file it names was changed or removed; a file added to the folder later is not covered by it.`,
    `- The two builds above can differ, since a pack can be made by another version than the run. Both verifiers print them as \`builds\`: \`packing\` from the signed statement, and \`running\` from each run's own file. Each is what that install said of itself, so neither shows which code ran. On a release copy, \`./scopehaven doctor\` checks the files against its manifest.`, '',
    '## Files', '',
    '| File | What it is |', '| --- | --- |',
    ...exported.map(f => `| \`${f.name}\` | ${f.about} Its envelope is \`${f.name}.dsse.json\`. |`),
    `| \`${PUBLIC_KEY_FILE}\` | The signer's public key. Verification needs only this key, never a private key. It came with the evidence: the key id check above is what ties it to the signer. |`,
    `| \`${VERIFIER_FILE}\` | A copy of ScopeHaven's verifier (integrations/attest/${VERIFIER_FILE}), standard-library Python 3.8 or newer, sha256 \`${verifierSha256}\`. It came with the evidence: confirm that sha256 with the signer, or use your own copy (below), never this file's word alone. |`,
    `| \`${CHECKER_FILE}\` | A copy of ScopeHaven's verdict checker (integrations/verdict-check/${CHECKER_FILE}), standard-library Python 3.8 or newer, sha256 \`${checkerSha256}\`. The same caution applies: confirm that sha256 with the signer, or use your own copy. |`,
    `| \`${VERIFY_FILE}\` | This file. |`,
    `| \`${PACK_ENVELOPE}\` | One envelope over every file above and their envelopes. |`, '',
    '## Commands', '',
    'From this folder, with the verifier copy here:', '',
    ...envelopes.map(envelope => `    ${verifyCommand(envelope)}`), '',
    `With your own ScopeHaven checkout at CHECKOUT, from this folder, for each envelope above. Use these unless you confirmed the copy's sha256 with the signer (\`shasum -a 256 ${VERIFIER_FILE}\` prints it): a copy that came with the evidence could have been changed by the sender or on the way.`, '',
    `    python3 -I "CHECKOUT/integrations/attest/${VERIFIER_FILE}" ${ARGUMENTS(PACK_ENVELOPE)}`,
    `    node "CHECKOUT/integrations/attest/cli.mjs" verify ${ARGUMENTS(PACK_ENVELOPE)}`, '',
    'Each prints a JSON result and exits 0 when verified, 1 when rejected, 2 on a usage or file error, and 3 when the verifier\'s own self-check failed (then do not rely on it). `-I` keeps Python from importing anything from this folder.', '',
    ...rederiveText(kind, predicates),
  ].join('\n');
}

// Library entry. One of runId (with dataDir) or paymentsRun (a parsed run file). Throws before anything is made when the options,
// the paths or a payments run are refused; afterwards a failure removes everything it made at and beside --out (a signing key the
// first export made stays in its key directory). `beforeClaim` is replaceable only so a
// test can stop a finished build just before the claim and show that nothing is at --out until then.
export async function evidencePack({ runId, dataDir, baselineRunId, coverageInventory, coverageContract, coverageTargets, paymentsRun, paymentsBaseline, retestHistory, outputDir, signingKeyDir }, { beforeClaim = async () => {} } = {}) {
  assertRuntime();
  const payments = paymentsRun !== undefined, coverage = [coverageInventory, coverageContract, coverageTargets];
  if (typeof outputDir !== 'string' || !isAbsolute(outputDir) || resolve(outputDir) !== outputDir || outputDir === dirname(outputDir)) throw invalid();
  if (signingKeyDir !== undefined && (typeof signingKeyDir !== 'string' || !isAbsolute(signingKeyDir))) throw invalid();
  if (retestHistory !== undefined && (typeof retestHistory !== 'string' || !isAbsolute(retestHistory) || resolve(retestHistory) !== retestHistory)) throw invalid();
  // A retest history reads native run exports only, so a payments pack never carries one (refused before anything is made).
  if (payments && retestHistory !== undefined) throw historyRefused('a payments pack takes no retest history; the history reads run exports only');
  if (payments ? (runId !== undefined || dataDir !== undefined || baselineRunId !== undefined || coverage.some(f => f !== undefined))
    : (!idValid(runId) || typeof dataDir !== 'string' || !isAbsolute(dataDir) || paymentsBaseline !== undefined || (baselineRunId !== undefined && !idValid(baselineRunId))
      || (coverage.some(f => f !== undefined) && coverage.some(f => typeof f !== 'string' || !isAbsolute(f))))) throw invalid();
  // A payments run is refused here, before anything exists (exportPaymentsRun checks it again).
  const paymentsRecord = payments ? savedPaymentsRun(paymentsRun, 'the run') : null;
  if (payments && paymentsBaseline !== undefined) savedPaymentsRun(paymentsBaseline, 'the baseline run');
  const parent = dirname(outputDir), keyDir = signingKeyDir ?? defaultSigningKeyDir();
  await ownedDirectory(parent);
  if (!payments) await ownedDirectory(dataDir); // The store must exist: a missing one would be created by the exporter.
  if (await lstat(outputDir).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; })) throw outExists();
  // The key never lives in or around the pack: not --out itself, not inside it, and --out not inside the key directory.
  const [realOut, realKey] = await Promise.all([realish(outputDir), realish(keyDir)]);
  if (within(realKey, realOut) || within(realOut, realKey)) throw invalid();
  const staging = join(parent, `.${randomUUID()}.evidence-pack.tmp`);
  let claimed = false;
  try {
    await mkdir(staging, { mode: 0o700 }); await chmod(staging, 0o700);
    const files = [], keyids = new Set();
    const add = (name, about, result) => { files.push({ name, about, envelope: true }); keyids.add(result.signature?.keyid); };
    if (payments) {
      const comparing = paymentsBaseline !== undefined;
      for (const [format, name, about] of PAYMENTS_FILES)
        add(name, format === 'html' && comparing ? 'The HTML report, with the before-and-after section recomputed from both runs.' : about,
          await exportPaymentsRun({ run: paymentsRun, ...(format === 'html' && comparing ? { baseline: paymentsBaseline } : {}), format, outputFile: join(staging, name), signingKeyDir: keyDir, sign: true }));
      if (comparing) for (const [format, name, about] of PAYMENTS_COMPARISON_FILES)
        add(name, about, await exportPaymentsRun({ run: paymentsRun, baseline: paymentsBaseline, format, outputFile: join(staging, name), signingKeyDir: keyDir, sign: true }));
    } else {
      const coverageFiles = coverageInventory === undefined ? {} : { coverageInventory, coverageContract, coverageTargets };
      for (const [format, name, about] of RUN_FILES)
        add(name, about, await exportRun({ runId, format, outputFile: join(staging, name), dataDir, signingKeyDir: keyDir, sign: true, ...(format === 'html' ? coverageFiles : {}) }));
      if (baselineRunId !== undefined) for (const [format, name, about] of COMPARISON_FILES)
        add(name, about, await exportRun({ runId, baselineRunId, format, outputFile: join(staging, name), dataDir, signingKeyDir: keyDir, sign: true, ...coverageFiles }));
    }
    // One key signed every export, and it is the key that signs the folder.
    const signer = await loadSigningKey(keyDir);
    if (keyids.size !== 1 || !keyids.has(signer.keyid)) throw coded(SIGNING_FAILED, 'the signing key changed while the pack was being made');
    const publicPem = createPublicKey(signer.privateKey).export({ type: 'spki', format: 'pem' });
    // The retest history: copied in only when its envelope names exactly that file and verifies under this pack's key, it is a
    // scopehaven-retest-history/1 document, and it has a finding on this run's application and suite (so a history kept for
    // another application, signed with the same key, never ships in this pack).
    if (retestHistory !== undefined) {
      const [bytes, envelope] = await Promise.all([readHistoryFile(join(retestHistory, HISTORY_FILE), HISTORY_LIMIT), readHistoryFile(join(retestHistory, HISTORY_ENVELOPE), 2 * 1024 * 1024)]);
      const check = JSON.stringify(subjectNames(envelope)) === JSON.stringify([HISTORY_FILE]) ? verifyEnvelope({ envelope, publicKey: publicPem, files: new Map([[HISTORY_FILE, bytes]]) }) : { verified: false, verdict: 'rejected', reason: 'envelope-subjects' };
      if (!check.verified) throw historyRefused(`it did not verify under the pack's signing key (${check.verdict}: ${check.reason})`);
      let history = null;
      try { history = JSON.parse(bytes.toString('utf8')); } catch {}
      if (history === null || typeof history !== 'object' || Array.isArray(history) || history.schema !== HISTORY_VERSION || !Array.isArray(history.findings)) throw historyRefused(`it is not a ${HISTORY_VERSION} document`);
      const run = JSON.parse((await readFile(join(staging, 'run.json'))).toString('utf8'));
      if (typeof run.applicationId !== 'string' || !history.findings.some(f => f && f.applicationId === run.applicationId && f.suiteId === (run.suiteId ?? null))) throw historyRefused("it has no finding on this run's application and suite");
      await publish(join(staging, HISTORY_FILE), bytes); await publish(join(staging, HISTORY_ENVELOPE), envelope);
      files.push({ name: HISTORY_FILE, about: HISTORY_ABOUT, envelope: true });
    }
    await publish(join(staging, PUBLIC_KEY_FILE), Buffer.from(publicPem));
    const [verifier, checker] = await Promise.all([readVerifier(), readChecker()]);
    await publish(join(staging, VERIFIER_FILE), verifier);
    await publish(join(staging, CHECKER_FILE), checker);
    const version = await signerVersion();
    const savedRecord = JSON.parse((await readFile(join(staging, payments ? 'payments-run.json' : 'run.json'))).toString('utf8'));
    const predicates = payments ? null : predicateRecordCounts(savedRecord);
    await publish(join(staging, VERIFY_FILE), Buffer.from(verifyText({ kind: payments ? 'payments' : 'run', runId: payments ? paymentsRecord.id : runId,
      baselineRunId: payments ? (paymentsBaseline === undefined ? undefined : paymentsBaseline.id) : baselineRunId, keyid: signer.keyid, version, verifierSha256: sha256(verifier), checkerSha256: sha256(checker), files, history: retestHistory !== undefined, predicates, runBuild: savedRecord.producer?.release ?? null })));
    // The folder envelope, over every file now in the folder (sorted by name), then every envelope verified from the bytes on disk.
    const contents = new Map();
    for (const name of (await readdir(staging)).sort()) contents.set(name, await readFile(join(staging, name)));
    const { envelope } = signFiles([...contents].map(([name, content]) => ({ name, content })), { privateKey: signer.privateKey, version });
    await publish(join(staging, PACK_ENVELOPE), Buffer.from(envelope));
    contents.set(PACK_ENVELOPE, await readFile(join(staging, PACK_ENVELOPE)));
    const envelopes = [...contents.keys()].filter(name => name.endsWith('.dsse.json'));
    for (const name of envelopes) {
      const check = verifyEnvelope({ envelope: contents.get(name), publicKey: publicPem, files: new Map(subjectNames(contents.get(name)).filter(s => contents.has(s)).map(s => [s, contents.get(s)])) });
      if (!check.verified) throw coded(SIGNING_FAILED, `${name} did not verify (${check.verdict}: ${check.reason})`);
    }
    if (envelopes.length !== files.length + 1) throw coded(SIGNING_FAILED, 'the folder holds an unexpected envelope');
    await beforeClaim(staging);
    // Claimed only now, so a build that fails or is killed leaves nothing at --out; the rename then replaces the empty claim in one
    // step (a folder someone filled meanwhile fails ENOTEMPTY, and is left as it is).
    await mkdir(outputDir, { mode: 0o700 }).catch(error => { throw error.code === 'EEXIST' ? outExists() : error; });
    claimed = true;
    await rename(staging, outputDir);
    return { saved: true, out: outputDir, kind: payments ? 'payments' : 'run', runId: payments ? paymentsRecord.id : runId,
      ...(payments ? (paymentsBaseline === undefined ? {} : { baselineRunId: paymentsBaseline.id }) : (baselineRunId === undefined ? {} : { baselineRunId })),
      keyid: signer.keyid, publicKey: join(outputDir, PUBLIC_KEY_FILE),
      files: [...contents].sort(([a], [b]) => a.localeCompare(b)).map(([name, content]) => ({ name, bytes: content.length, sha256: sha256(content) })),
      verify: { directory: outputDir, command: verifyCommand(PACK_ENVELOPE) } };
  } catch (error) {
    await rm(staging, { recursive: true, force: true }).catch(() => {});
    if (claimed) await rmdir(outputDir).catch(() => {});
    throw error;
  }
}

const USAGE = 'Use --run UUID --data ABSOLUTE_STORE --out ABSOLUTE_NEW_DIR [--baseline UUID] [--coverage-inventory ABS --coverage-contract ABS --coverage-targets ABS] [--signing-key-dir ABSOLUTE_DIR] [--retest-history ABSOLUTE_DIR], '
  + 'or --payments-run ABSOLUTE_RUN.json --out ABSOLUTE_NEW_DIR [--payments-baseline ABSOLUTE_RUN.json] [--signing-key-dir ABSOLUTE_DIR]. The --out parent and the store must exist and be yours; --out must not exist, '
  + 'and the key directory may not be, hold or sit inside it. The pack is always signed.';
export async function main(args) {
  const names = { '--run': 'runId', '--data': 'dataDir', '--baseline': 'baselineRunId', '--out': 'outputDir', '--signing-key-dir': 'signingKeyDir', '--payments-run': 'paymentsRunFile', '--retest-history': 'retestHistory',
    '--payments-baseline': 'paymentsBaselineFile', '--coverage-inventory': 'coverageInventory', '--coverage-contract': 'coverageContract', '--coverage-targets': 'coverageTargets' }, options = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = names[args[i]], value = args[i + 1];
    if (!key || Object.hasOwn(options, key) || !value || value.startsWith('--')) throw invalid();
    options[key] = value;
  }
  const { paymentsRunFile, paymentsBaselineFile, ...rest } = options;
  // Run files are absolute too: the launcher runs from its own folder, so a relative path would name a file there.
  if ((paymentsBaselineFile !== undefined && paymentsRunFile === undefined) || [paymentsRunFile, paymentsBaselineFile].some(f => f !== undefined && !isAbsolute(f))) throw invalid();
  const paymentsRun = paymentsRunFile === undefined ? undefined : await readPaymentsJson(paymentsRunFile, 'The payments run (--payments-run)');
  const paymentsBaseline = paymentsBaselineFile === undefined ? undefined : await readPaymentsJson(paymentsBaselineFile, 'The baseline run (--payments-baseline)');
  return evidencePack({ ...rest, ...(paymentsRun === undefined ? {} : { paymentsRun }), ...(paymentsBaseline === undefined ? {} : { paymentsBaseline }) });
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { console.log(JSON.stringify(await main(process.argv.slice(2)), null, 2)); }
  catch (error) {
    // Named by code where there is one; no message carries key material. No pack or partial pack is left at --out either way, but
    // a failure after the first export (a refused coverage file, a baseline that did not finish first) keeps the key that export made.
    const left = 'No pack and no partial pack was left at --out; a signing key made on first use stays in its key directory.';
    if ([SIGNING_KEY_UNSAFE, SIGNING_FAILED].includes(error?.code)) console.error(`Evidence pack failed (${error.message}). ${left} The signing key lives in ~/.config/scopehaven/signing (or --signing-key-dir ABSOLUTE_DIR); fix its mode or owner yourself.`);
    else if (error?.code === COVERAGE_INPUTS) console.error(`Evidence pack failed (${error.message}). ${left} The three coverage files are the operator's files for integrations/coverage-report, and the targets file must name this run's target.`);
    else if (error?.code === PAYMENTS_RUN_REFUSED) console.error(`Evidence pack refused (${error.message}). ${left}`);
    else if (error?.retestHistory) console.error(`Evidence pack failed (${error.message}). ${left} A --retest-history folder must be one integrations/retest-ledger/cli.mjs export made with this pack's signing key.`);
    else console.error(`Evidence pack failed (${error?.message ?? 'unknown error'}). ${left} ${USAGE}`);
    process.exitCode = 2;
  }
}
