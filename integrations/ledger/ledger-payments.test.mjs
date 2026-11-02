// Payments-pack runs in the evidence ledger. An envelope that names a payments run's identity is
// recorded with the run's rows as its verdicts, read only through attest's payments checks (the pack's own reader rules),
// in the writer and in both verifiers. Every ledger recorded before this change still verifies: fixtures/ledger-main-0de64259
// was recorded by an earlier build's own exporters, signer and ledger writer, with throwaway keys whose private halves were never
// written: a run export alone, a payments run alone (named by no identity in that build) and a run export with a payments run.
// Owned synthetic data only: the synthetic fixture over loopback and the checked-in payments sample runs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { exportRun } from '../../src/export-cli.mjs';
import { digest } from '../../src/domain.mjs';
import { exportPaymentsRun } from '../payments-pack/output.mjs';
import { buildStatement, generateSigningKey, signFiles, signStatement } from '../attest/sign.mjs';
import { PAYMENTS_RUN_SCHEMA } from '../attest/verify.mjs';
import * as L from './ledger.mjs';
import * as V from './verify.mjs';
import { main as cli } from './cli.mjs';
import { permissionHistory } from './history.mjs';

const PY = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3', '/opt/homebrew/bin/python3', '/usr/bin/python3'].find(path => existsSync(path));
const SCRIPT = fileURLToPath(new URL('./verify_ledger.py', import.meta.url));
const FIXTURE = name => fileURLToPath(new URL(`./fixtures/ledger-main-0de64259/${name}`, import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const at = m => new Date(Date.parse('2026-10-26T06:00:00.000Z') + m * 60000);
const nested = depth => `${'['.repeat(depth)}1${']'.repeat(depth)}`;
const work = await mkdtemp(join(tmpdir(), 'scopehaven ledger payments '));
process.on('exit', () => rmSync(work, { recursive: true, force: true }));
const python = (args, input) => new Promise(resolve => {
  const child = execFile(PY, ['-B', ...args], { maxBuffer: 64 << 20, timeout: 300000 }, (error, stdout, stderr) => resolve({ code: error ? (error.code ?? 'signal') : 0, stdout, stderr }));
  if (input !== undefined) child.stdin.end(input);
});

// Run exports through the product's export path, and the payments sample runs through the pack's (which drops a stored comparison).
const exportsDir = join(work, 'exports'), dataDir = join(work, 'data'), files = {};
await mkdir(exportsDir, { mode: 0o700 });
const store = createStore(dataDir);
for (const [name, target] of [['run-vulnerable.json', 'demo-vulnerable'], ['run-repaired.json', 'demo-repaired']]) {
  const run = await runAssessment(target); await store.save(run);
  await exportRun({ runId: run.id, format: 'json', outputFile: join(exportsDir, name), dataDir });
  files[name] = await readFile(join(exportsDir, name));
}
const SAMPLE = name => fileURLToPath(new URL(`../payments-pack/sample/${name}`, import.meta.url));
const payments = { before: JSON.parse(await readFile(SAMPLE('before-vulnerable.json'), 'utf8')), after: JSON.parse(await readFile(SAMPLE('after-repaired.json'), 'utf8')) };
for (const [name, run] of [['payments-before.json', payments.before], ['payments-after.json', payments.after]]) {
  await exportPaymentsRun({ run, format: 'json', outputFile: join(exportsDir, name) });
  files[name] = await readFile(join(exportsDir, name));
}
const rowsOf = run => run.rows.map(r => [r.id, r.status]);
// A payments run edited and resealed: its unkeyed sha256 recomputed over the edit, as anyone can.
const reseal = (run, edit) => {
  const copy = structuredClone(run); edit(copy);
  const { sha256: _, comparison: __, ...body } = copy;
  return Buffer.from(`${JSON.stringify({ ...body, sha256: digest(body) }, null, 2)}\n`);
};
// A failing row read as passing, with the counts made to agree, so only the rule that a status is the worst of its assertions refuses it.
const flipStatus = run => { run.rows.find(r => r.status === 'fail').status = 'pass'; for (const s of ['pass', 'fail', 'inconclusive']) run.counts[s] = run.rows.filter(r => r.status === s).length; };

// A payments run holding a 4301-digit integer, past Python 3.11+'s default parse limit: both languages read it as a double, so it digests as null.
const BIG = (() => { const copy = structuredClone(payments.before); copy.rows[0].request.big = null; const { sha256: _, ...body } = copy;
  return Buffer.from(`${JSON.stringify({ ...body, sha256: digest(body) }, null, 2)}\n`.replace('"big": null', `"big": ${'9'.repeat(4301)}`)); })();
// A payments run whose first row's request holds these JSON literals, written as raw text and resealed over what JavaScript reads.
const withLiterals = literals => {
  const copy = structuredClone(payments.before);
  for (const key of Object.keys(literals)) copy.rows[0].request[key] = `@@${key}@@`;
  let text = `${JSON.stringify(copy, null, 2)}\n`;
  for (const [key, literal] of Object.entries(literals)) text = text.replace(`"@@${key}@@"`, literal);
  const { sha256: stale, ...body } = JSON.parse(text);
  return Buffer.from(text.replace(stale, digest(body)));
};
// Every guard of the Python rewrite at once: integers at 309 and 310 digits, a long fraction, a long exponent, and digits in a string.
const GUARDS = withLiterals({ p309: `1${'0'.repeat(308)}`, n309: `-1${'0'.repeat(308)}`, p310: `1${'0'.repeat(309)}`, n310: `-1${'0'.repeat(309)}`,
  f: `1.${'0'.repeat(4400)}`, e: `1e-${'0'.repeat(4400)}1`, s: `"${'9'.repeat(4301)}"` });
// Not JSON in either language: a long integer with a leading zero, positive or negative, and an unterminated string of escaped quotes.
const leadingZero = sign => Buffer.from(JSON.stringify(payments.after).replace('"comparison":{', `"comparison":{"x":${sign}0${'9'.repeat(4301)},`));
const UNTERMINATED = Buffer.from(`{"a":"${'\\"'.repeat(500000)}`);
// A payments run whose stored comparison has an all-digit key past 4300 digits: never read as a number, in either language.
const LONG_KEY = Buffer.from(JSON.stringify({ ...payments.after, comparison: { [`${'9'.repeat(4301)}`]: 1 } }));
// A run export changed and its integrity recomputed, as anyone can.
const resealNative = (bytes, edit) => { const run = JSON.parse(bytes); edit(run); const { integrity, notes, ...core } = run; return Buffer.from(`${JSON.stringify({ ...run, integrity: { ...integrity, sha256: digest(core) } }, null, 2)}\n`); };
const KEY = generateSigningKey(), LED = generateSigningKey(), keyDir = join(work, 'keys');
await mkdir(keyDir, { mode: 0o700 });
await writeFile(join(keyDir, 'evidence.pub'), KEY.publicPem); await writeFile(join(keyDir, 'ledger.pub'), LED.publicPem);
const sign = (named, m) => Buffer.from(signFiles(named.map(([name, content]) => ({ name, content })), { privateKey: KEY.privatePem, version: '0.7.0', now: at(m) }).envelope);
const statementOf = (named, m) => buildStatement(named.map(([name, content]) => ({ name, content })), { version: '0.7.0', now: at(m) });
// Signed as envelopes were before payments runs had identities: the statement names no payments run.
const signUnnamed = (named, m) => { const s = statementOf(named, m); s.predicate.runs = s.predicate.runs.filter(r => r.schema !== PAYMENTS_RUN_SCHEMA); return Buffer.from(signStatement(s, KEY.privatePem)); };
async function newLedger(name) { const dir = join(work, name); await mkdir(dir, { mode: 0o700 }); await L.initLedger(dir, { now: at(0) }); return dir; }
const append = (dir, envelope, named, m) => L.appendEnvelope(dir, { envelope, files: new Map(named), evidenceKey: KEY.publicPem, privateKey: LED.privatePem, now: at(m + 0.5) });
async function runFilesDir(list) { const dir = await mkdtemp(join(work, 'run-files-')); for (const [i, bytes] of list.entries()) await writeFile(join(dir, `f${i}.json`), bytes); return dir; }
// A ledger folder from its parts, as a key holder can write one.
async function ledgerFolder({ metadata, entries, checkpoints, envelopes }) {
  const dir = await mkdtemp(join(work, 'held-')); await mkdir(join(dir, 'envelopes'));
  await writeFile(join(dir, 'ledger.json'), metadata); await writeFile(join(dir, 'entries.jsonl'), entries); await writeFile(join(dir, 'checkpoints.jsonl'), checkpoints);
  for (const [digest, bytes] of envelopes) await writeFile(join(dir, 'envelopes', `${digest}.json`), bytes);
  return dir;
}
// Every file in a ledger folder, hidden ones included, with its digest.
async function snapshot(dir) {
  const out = [];
  for (const entry of await readdir(dir, { recursive: true, withFileTypes: true })) if (entry.isFile()) out.push([join(entry.parentPath, entry.name).slice(dir.length), sha(await readFile(join(entry.parentPath, entry.name)))]);
  return out.sort();
}
// Both verifiers' CLIs on one folder: the fields both report, which must be equal.
const COMMON = ['verdict', 'reason', 'detail', 'size', 'covered', 'unsignedTail', 'runs', 'verdictsCheckedAgainstRunFiles', 'checkpoints'];
async function bothCli(dir, { runFiles, ledgerKey = join(keyDir, 'ledger.pub'), evidenceKey = join(keyDir, 'evidence.pub') } = {}) {
  const extra = runFiles ? ['--run-files', runFiles] : [];
  const node = await cli(['verify', '--ledger', dir, '--key', ledgerKey, '--evidence-key', evidenceKey, ...extra]);
  const nodeView = { code: node.code, ...Object.fromEntries(COMMON.map(key => [key, node.output[key] ?? null])) };
  if (!PY) return { node: nodeView, selfChecks: node.output.selfChecks };
  const p = await python([SCRIPT, 'log', '--key', ledgerKey, '--evidence-key', evidenceKey, '--ledger', dir, ...extra]);
  const printed = JSON.parse(p.stdout);
  return { node: nodeView, python: { code: p.code, ...Object.fromEntries(COMMON.map(key => [key, printed[key] ?? null])) }, selfChecks: node.output.selfChecks };
}

test('a ledger recorded on an earlier private build still verifies in both verifiers, with and without its run files', async () => {
  const keys = { ledgerKey: FIXTURE('ledger-key.pub.pem'), evidenceKey: FIXTURE('evidence-key.pub.pem') };
  for (const [runFiles, checked] of [[undefined, 0], [FIXTURE('run-files'), 2]]) {
    const { node, python: py, selfChecks } = await bothCli(FIXTURE('ledger'), { ...keys, runFiles });
    assert.deepEqual([node.code, node.verdict, node.size, node.covered, node.unsignedTail, node.runs, node.verdictsCheckedAgainstRunFiles], [0, 'verified', 3, 3, 0, 2, checked]);
    assert.ok(selfChecks.length && selfChecks.every(c => c.observed === 'rejected'));
    if (PY) assert.deepEqual(py, node);
  }
  // As that build recorded it: the payments run in entry 1 and the one beside a run export in entry 2 were named by no identity.
  const result = V.verifyLedger({ ...(await L.readLedgerFiles(FIXTURE('ledger'))), ledgerKey: await readFile(keys.ledgerKey, 'utf8'), evidenceKey: await readFile(keys.evidenceKey, 'utf8') });
  assert.deepEqual(result.entries.map(e => e.runs.map(r => r.subject)), [['run-vulnerable.json'], [], ['run-repaired.json']]);
  assert.deepEqual(permissionHistory(result).segments.map(s => s.runs.map(r => r.entry)), [[0, 2]]);
});

test('a payments run is recorded with its rows as verdicts, alone or beside a run export, and both verifiers agree byte for byte', { timeout: 120000 }, async () => {
  const dir = await newLedger('rows');
  const sets = [[['run-vulnerable.json', files['run-vulnerable.json']]], [['payments-before.json', files['payments-before.json']]],
    [['run-repaired.json', files['run-repaired.json']], ['payments-after.json', files['payments-after.json']]]];
  for (const [i, named] of sets.entries()) assert.equal((await append(dir, sign(named, i + 1), named, i + 1)).runs, named.length);
  // An envelope signed as before payments runs had identities is still recorded as before: its payments run is in no entry.
  const unnamed = [['payments-before.json', files['payments-before.json']]];
  assert.equal((await append(dir, signUnnamed(unnamed, 4), unnamed, 4)).runs, 0);
  const ledger = await L.readLedgerFiles(dir), entries = ledger.entries.toString().trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(entries.map(e => e.runs.map(r => r.subject)), [['run-vulnerable.json'], ['payments-before.json'], ['run-repaired.json', 'payments-after.json'], []]);
  assert.deepEqual(entries[1].runs[0].verdicts, rowsOf(payments.before)); assert.deepEqual(entries[2].runs[1].verdicts, rowsOf(payments.after));
  assert.equal(entries[1].runs[0].verdictDigest, sha(JSON.stringify(rowsOf(payments.before))));
  // The recorded identity is the one attest recomputed and the statement names.
  assert.deepEqual([entries[1].runs[0].schema, entries[1].runs[0].id, entries[1].runs[0].coreSha256], [PAYMENTS_RUN_SCHEMA, payments.before.id, payments.before.sha256]);
  const { node, python: py, selfChecks } = await bothCli(dir, { runFiles: await runFilesDir(Object.values(files)) });
  assert.deepEqual([node.code, node.verdict, node.size, node.covered, node.runs, node.verdictsCheckedAgainstRunFiles], [0, 'verified', 4, 4, 4, 4]);
  assert.ok(selfChecks.every(c => c.observed === 'rejected'));
  if (PY) assert.deepEqual(py, node);
  // The [id, status] list each verifier reads from a file as a payments run, byte for byte: null for any the pack's reader refuses.
  const cases = [files['payments-before.json'], files['payments-after.json'], await readFile(SAMPLE('after-repaired.json')), reseal(payments.before, flipStatus),
    reseal(payments.before, run => { run.rows[0].reach.reached = 1; }), files['run-vulnerable.json'], Buffer.from(JSON.stringify(payments.after).replace('"comparison":{', `"comparison":{"deep":${nested(300)},`)),
    Buffer.from(JSON.stringify(payments.before).replace('"counts":{"pass":2,', '"counts":{"pass":2.0e0,').replace('"settleMs":150', '"settleMs":1.5e2')), Buffer.from([0xff, 0xfe]), BIG,
    GUARDS, leadingZero(''), leadingZero('-'), UNTERMINATED, LONG_KEY];
  const node8 = cases.map(bytes => Buffer.from(JSON.stringify(V.runFileVerdicts(bytes, { payments: true }))).toString('hex'));
  assert.deepEqual(node8.map(h => Buffer.from(h, 'hex').toString() === 'null'), [false, false, false, true, true, true, true, false, true, false, false, true, true, true, false]);
  if (PY) {
    const program = `import sys, json; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_ledger as v
print(json.dumps([v.attest._canonical_json(v._run_results(bytes.fromhex(h), True)).hex() for h in json.loads(sys.stdin.read())]))`;
    const { code, stdout, stderr } = await python(['-c', program], JSON.stringify(cases.map(bytes => bytes.toString('hex'))));
    assert.equal(code, 0, stderr); assert.deepEqual(JSON.parse(stdout), node8);
  }
  // History: one segment per kind, so the run exports' runs on across the payments runs, and the payments rows change within their target and pack.
  const history = permissionHistory(V.verifyLedger({ ...ledger, ledgerKey: LED.publicPem, evidenceKey: KEY.publicPem }));
  assert.deepEqual(history.segments.map(s => s.runs.map(r => r.entry)), [[0, 2], [1, 2]]);
  assert.deepEqual(history.segments[1].identity, { schema: PAYMENTS_RUN_SCHEMA, targetId: payments.before.targetId, packSha256: payments.before.packSha256 });
  assert.deepEqual(history.segments[1].changes.map(c => [c.check, c.from, c.to]), payments.before.rows.filter(r => r.status === 'fail').map(r => [r.id, 'fail', 'pass']));
});

test('payments rows are compared only within one target and pack', async () => {
  const dir = await newLedger('packs');
  const other = reseal(payments.before, run => { run.packSha256 = '0'.repeat(64); run.id = 'pay-20261024090854-0000bbbb'; });
  const sets = [[['payments-before.json', files['payments-before.json']]], [['other-pack.json', other]], [['payments-after.json', files['payments-after.json']]]];
  for (const [i, named] of sets.entries()) await append(dir, sign(named, i + 1), named, i + 1);
  const history = permissionHistory(V.verifyLedger({ ...(await L.readLedgerFiles(dir)), ledgerKey: LED.publicPem, evidenceKey: KEY.publicPem }));
  // A change of pack starts a new segment, never compared with the one before it.
  assert.deepEqual(history.segments.map(s => [s.identity.packSha256, s.runs.map(r => r.entry), s.changes.length]), [[payments.before.packSha256, [0], 0], ['0'.repeat(64), [1], 0], [payments.before.packSha256, [2], 0]]);
  // A target or pack that is not text (the pack's reader puts no type on them) compares with no other run: not one with the same
  // pack, not one in the same entry, and not one with the same target and the same pack value.
  const oddTarget = (run, id, targetId) => reseal(run, r => { r.targetId = targetId; r.id = id; }), numberPack = (run, id) => reseal(run, r => { r.packSha256 = 5; r.id = id; });
  const oddSets = [[['odd-1.json', oddTarget(payments.before, 'pay-20261024090854-0000cccc', { odd: true })]],
    [['odd-2.json', oddTarget(payments.after, 'pay-20261024090856-0000dddd', { other: 1 })], ['pack-number-1.json', numberPack(payments.before, 'pay-20261024090854-0000eeee')]],
    [['pack-number-2.json', numberPack(payments.after, 'pay-20261024090856-0000ffff')]]];
  const oddDir = await newLedger('odd-targets');
  for (const [i, named] of oddSets.entries()) await append(oddDir, sign(named, i + 1), named, i + 1);
  const oddHistory = permissionHistory(V.verifyLedger({ ...(await L.readLedgerFiles(oddDir)), ledgerKey: LED.publicPem, evidenceKey: KEY.publicPem }));
  assert.deepEqual(oddHistory.segments.map(s => [s.runs.map(r => r.entry), s.changes.length]), [[[0], 0], [[1], 0], [[1], 0], [[2], 0]]);
});

test('run exports alone keep the history they had: a change of identity starts a segment, never compared across', async () => {
  const dir = await newLedger('native-history');
  const other = resealNative(files['run-vulnerable.json'], run => { run.id = 'other-policy-run'; run.policyHash = '0'.repeat(64); });
  const sets = [[['run-vulnerable.json', files['run-vulnerable.json']]], [['other-policy.json', other]], [['run-repaired.json', files['run-repaired.json']]]];
  for (const [i, named] of sets.entries()) await append(dir, sign(named, i + 1), named, i + 1);
  const history = permissionHistory(V.verifyLedger({ ...(await L.readLedgerFiles(dir)), ledgerKey: LED.publicPem, evidenceKey: KEY.publicPem }));
  // As before payments runs were recorded: A, B, A is three segments, and the second A is not compared with the first.
  assert.deepEqual(history.segments.map(s => [s.runs.map(r => r.entry), s.changes.length]), [[[0], 0], [[1], 0], [[2], 0]]);
});

test('a payments run holding a 4301-digit integer is recorded, and both verifiers read it back from its run file', async () => {
  const dir = await newLedger('big'), named = [['payments-big.json', BIG]];
  assert.equal((await append(dir, sign(named, 1), named, 1)).runs, 1);
  const { node, python: py } = await bothCli(dir, { runFiles: await runFilesDir([BIG]) });
  assert.deepEqual([node.code, node.verdict, node.runs, node.verdictsCheckedAgainstRunFiles], [0, 'verified', 1, 1]);
  if (PY) assert.deepEqual(py, node);
});

test('a resealed self-inconsistent payments run in a mixed envelope is refused with its reason, and nothing is written', async () => {
  const dir = await newLedger('refused');
  await append(dir, sign([['run-vulnerable.json', files['run-vulnerable.json']]], 1), [['run-vulnerable.json', files['run-vulnerable.json']]], 1);
  const before = await snapshot(dir), named = [['run-repaired.json', files['run-repaired.json']], ['payments-forged.json', reseal(payments.before, flipStatus)]];
  // Signed without signFiles' self-check (which refuses it), naming the identity the signer built.
  const envelope = Buffer.from(signStatement(statementOf(named, 2), KEY.privatePem));
  await assert.rejects(append(dir, envelope, named, 2),
    /^Error: The envelope did not verify \(rejected: payments-run-refused: payments-forged\.json has a row whose status is not what its assertions, reach and settlement give\); nothing was appended\.$/);
  assert.deepEqual(await snapshot(dir), before);
  // Named by no identity it is refused the same way: a payments run is checked whether or not the statement names it.
  await assert.rejects(append(dir, signUnnamed(named, 3), named, 3), /^Error: The envelope did not verify \(rejected: payments-run-refused: /);
  assert.deepEqual(await snapshot(dir), before);
  // A payments run the ledger cannot read back (nested past its depth limit) is refused by the writer, also before anything is written.
  const deep = [['payments-deep.json', Buffer.from(JSON.stringify(payments.after).replace('"comparison":{', `"comparison":{"deep":${nested(300)},`))]];
  await assert.rejects(append(dir, sign(deep, 4), deep, 4),
    /^Error: payments-deep\.json is not a run file the verifiers can read back \(not UTF-8, nested deeper than 256, or not a payments run the pack's reader takes\); nothing was appended\.$/);
  assert.deepEqual(await snapshot(dir), before);
});

test('with run files, both verifiers refuse payments verdicts the run file does not give, and a run file the pack\'s reader refuses', async () => {
  const meta = JSON.parse((await L.readLedgerFiles(await newLedger('held'))).metadata);
  // A key holder's ledger of one entry over this envelope, recording these verdicts, with its checkpoint signed.
  const held = (envelope, run, verdicts) => {
    const entry = { index: 0, prev: null, recordedAt: at(2).toISOString(), envelope: { sha256: sha(envelope), keyid: KEY.keyid }, runs: [{ ...run, verdicts, verdictDigest: sha(JSON.stringify(verdicts)), anchors: [] }] };
    const lines = [JSON.stringify(entry)];
    return ledgerFolder({ metadata: Buffer.from(`${JSON.stringify(meta)}\n`), entries: Buffer.from(`${lines[0]}\n`), checkpoints: Buffer.from(`${L.signCheckpoint({ createdAt: meta.createdAt, log: meta.log, lines, signedAt: at(2).toISOString(), privateKey: LED.privatePem })}\n`), envelopes: new Map([[sha(envelope), envelope]]) });
  };
  const named = [['payments-before.json', files['payments-before.json']]], envelope = sign(named, 1), identity = statementOf(named, 1).predicate.runs[0];
  const flipped = rowsOf(payments.before).map(([id, status], i) => [id, i === 2 ? 'pass' : status]);
  const forged = reseal(payments.before, flipStatus), forgedNamed = [['payments-forged.json', forged]], forgedEnvelope = Buffer.from(signStatement(statementOf(forgedNamed, 1), KEY.privatePem));
  const forgedIdentity = statementOf(forgedNamed, 1).predicate.runs[0];
  // A run export that also carries a payments schema and rows, named under a payments identity by a key holder: never read as a payments run.
  const posing = resealNative(files['run-vulnerable.json'], run => { run.schema = PAYMENTS_RUN_SCHEMA; run.rows = payments.before.rows; });
  const posingNamed = [['posing.json', posing]], posingStatement = statementOf(posingNamed, 1);
  posingStatement.predicate.runs = [{ subject: 'posing.json', id: JSON.parse(posing).id, schema: PAYMENTS_RUN_SCHEMA, coreSha256: posingStatement.predicate.runs[0].coreSha256 }];
  const posingEnvelope = Buffer.from(signStatement(posingStatement, KEY.privatePem));
  const outcomes = [
    ['a run export with rows, under a payments identity', await held(posingEnvelope, posingStatement.predicate.runs[0], rowsOf(payments.before)), [posing], ['verdict-mismatch', 'entry 0: run file unreadable or not a payments run the pack\'s reader takes']],
    ['recorded verdicts the run file does not give', await held(envelope, identity, flipped), [files['payments-before.json']], ['verdict-mismatch', 'entry 0: recorded verdicts differ from the signed run file']],
    ['the run file the entry names', await held(envelope, identity, rowsOf(payments.before)), [files['payments-before.json']], [null, null]],
    ['a resealed inconsistent run, with its run file', await held(forgedEnvelope, forgedIdentity, rowsOf(JSON.parse(forged))), [forged], ['verdict-mismatch', 'entry 0: run file unreadable or not a payments run the pack\'s reader takes']],
    // Without its run file the ledger vouches for it by the keys alone, as for any run (the README says so).
    ['a resealed inconsistent run, without its run file', await held(forgedEnvelope, forgedIdentity, rowsOf(JSON.parse(forged))), undefined, [null, null]],
  ];
  for (const [label, dir, runFiles, [reason, detail]] of outcomes) {
    const { node, python: py } = await bothCli(dir, runFiles ? { runFiles: await runFilesDir(runFiles) } : {});
    assert.deepEqual([node.reason, node.detail === null ? null : node.detail.replace(/^[a-z-]+: /, '')], [reason, detail], label);
    if (PY) assert.deepEqual(py, node, label);
  }
});
