import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { existsSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile, spawn } from 'node:child_process';
import { createHash, createPrivateKey, randomUUID, sign as rawSign } from 'node:crypto';
import { runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { exportRun } from '../../src/export-cli.mjs';
import { digest } from '../../src/domain.mjs';
import { generateSigningKey, signFiles } from '../attest/sign.mjs';
import { appendEnvelope, buildEntry, checkpointLedger, consistencyProof, inclusionProof, initLedger, readLedgerFiles, signCheckpoint, signIntent } from './ledger.mjs';
import { verifyEnvelope } from '../attest/verify.mjs';
import { leafHash, verifyConsistency, verifyInclusion, verifyLedger, verifyInclusionPath, verifyConsistencyPath, treeHead } from './verify.mjs';
import { permissionHistory } from './history.mjs';
import { anchorFor } from './anchors.mjs';
import { main } from './cli.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const at = minutes => new Date(Date.parse('2026-10-06T06:00:00.000Z') + minutes * 60000);
const work = await mkdtemp(join(tmpdir(), 'scopehaven ledger '));
process.on('exit', () => rmSync(work, { recursive: true, force: true }));
const scratch = async t => { const dir = await mkdtemp(join(work, 'case-')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };
const KEY = generateSigningKey(), OTHER = generateSigningKey();
const version = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8')).version;

// Real exports of the owned synthetic fixture: a planted defect, its repair, the defect back, the
// repair again, and one run under a changed suite identity (recomputed integrity: the hash has no key).
const dataDir = join(work, 'data'), exportsDir = join(work, 'exports');
await mkdir(exportsDir, { mode: 0o700 });
const store = createStore(dataDir), runs = [];
for (const target of ['demo-vulnerable', 'demo-repaired', 'demo-vulnerable', 'demo-repaired']) { const run = await runAssessment(target); await store.save(run); runs.push(run); }
const exported = [];
for (const [i, run] of runs.entries()) { const file = join(exportsDir, `run-${i}.json`); await exportRun({ runId: run.id, format: 'json', outputFile: file, dataDir }); exported.push(await readFile(file)); }
const relabelled = (() => {
  const run = JSON.parse(exported[1]); run.suiteHash = 'f'.repeat(64); run.id = randomUUID();
  const { integrity, notes, ...core } = run; run.integrity = { ...integrity, sha256: digest(core) };
  return Buffer.from(`${JSON.stringify(run, null, 2)}\n`);
})();
const files = [...exported, relabelled].map((content, i) => new Map([[`run-${i}.json`, content]]));
// One more real run that is in no ledger, for insertion cases.
const EXTRA = await (async () => { const run = await runAssessment('demo-repaired'); await store.save(run); const file = join(exportsDir, 'run-extra.json'); await exportRun({ runId: run.id, format: 'json', outputFile: file, dataDir }); return readFile(file); })();
const envelopes = files.map((map, i) => Buffer.from(signFiles([...map].map(([name, content]) => ({ name, content })), { privateKey: KEY.privatePem, version, now: at(i) }).envelope));

const ledgerDir = join(work, 'ledger');
await mkdir(ledgerDir, { mode: 0o700 });
await initLedger(ledgerDir, { now: at(0) });
// Unsigned appends, then checkpoints over exactly the lines they report (expectedTail).
const unsignedAppends = async (dir, list) => { const digests = []; for (const [i, m] of list) digests.push((await appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, now: at(m) })).lineSha256); return digests; };
await checkpointLedger(ledgerDir, { privateKey: KEY.privatePem, expectedTail: await unsignedAppends(ledgerDir, [[0, 0.5], [1, 1.5]]), now: at(2) });
await checkpointLedger(ledgerDir, { privateKey: KEY.privatePem, expectedTail: await unsignedAppends(ledgerDir, [[2, 2.5], [3, 3.5]]), now: at(4) });
const BASE = await readLedgerFiles(ledgerDir);
const { log: LOG, createdAt: CREATED } = JSON.parse(BASE.metadata.toString());

// Variants are built from the base files; `rechain` re-links every entry the way a forger would.
const linesOf = bytes => { const text = bytes.toString(); return text ? text.slice(0, -1).split('\n') : []; };
const text = list => Buffer.from(list.length ? `${list.join('\n')}\n` : '');
const ENTRIES = linesOf(BASE.entries).map(line => JSON.parse(line)), POINTS = linesOf(BASE.checkpoints);
const rechain = list => { const out = []; list.forEach((entry, i) => out.push(JSON.stringify({ ...entry, index: i, prev: i ? leafHash(Buffer.from(out[i - 1])).toString('hex') : null }))); return out; };
const pointBody = line => JSON.parse(Buffer.from(JSON.parse(line).payload, 'base64').toString());
const variant = (change = {}) => ({ ...BASE, envelopes: new Map(BASE.envelopes), ...change });
const verifyNode = (files, key = KEY.publicPem, checks) => verifyLedger({ ...files, ledgerKey: key }, checks);
const recordWith = (entry, change) => ({ ...entry, runs: entry.runs.map((run, i) => i ? run : change(run)) });

const TAMPERS = [
  ['two entries reordered', () => variant({ entries: text([ENTRIES[1], ENTRIES[0], ...ENTRIES.slice(2)].map(e => JSON.stringify(e))) }), 'index-mismatch'],
  ['two entries reordered and renumbered', () => variant({ entries: text([ENTRIES[1], ENTRIES[0], ...ENTRIES.slice(2)].map((e, i) => JSON.stringify({ ...e, index: i }))) }), 'chain-broken'],
  ['an entry dropped', () => variant({ entries: text([ENTRIES[0], ...ENTRIES.slice(2)].map(e => JSON.stringify(e))) }), 'index-mismatch'],
  ['an entry dropped and the rest renumbered', () => variant({ entries: text([ENTRIES[0], ...ENTRIES.slice(2)].map((e, i) => JSON.stringify({ ...e, index: i }))) }), 'chain-broken'],
  ['the last entry dropped', () => variant({ entries: text(linesOf(BASE.entries).slice(0, -1)) }), 'checkpoint-mismatch'],
  ['an entry inserted', () => variant({ entries: text([ENTRIES[0], ENTRIES[0], ...ENTRIES.slice(1)].map(e => JSON.stringify(e))) }), 'index-mismatch'],
  ['an earlier run re-signed and replayed at the end, chain rebuilt and re-signed', () => {
    const again = Buffer.from(signFiles([...files[1]].map(([name, content]) => ({ name, content })), { privateKey: KEY.privatePem, version, now: at(3.6) }).envelope);
    const entry = buildEntry({ previousLine: null, index: 0, recordedAt: at(3.7).toISOString(), envelope: again, check: verifyEnvelope({ envelope: again, publicKey: KEY.publicPem, files: files[1] }), files: files[1] });
    const lines = rechain([...ENTRIES, entry]);
    const v = variant({ entries: text(lines), checkpoints: text([...POINTS, signCheckpoint({ log: LOG, createdAt: CREATED, lines, signedAt: at(3.8).toISOString(), privateKey: KEY.privatePem })]) }); v.envelopes.set(sha(again), again); return v;
  }, 'run-replayed'],
  ['ledger.json moved to an earlier creation time', () => variant({ metadata: Buffer.from(`${JSON.stringify({ ...JSON.parse(BASE.metadata), createdAt: '2001-01-01T00:00:00.000Z' })}\n`) }), 'ledger-mismatch'],
  ['a checkpoint line rewritten with spacing', () => variant({ checkpoints: text([POINTS[0], JSON.stringify(JSON.parse(POINTS[1]), null, 1).replace(/\n/g, '')]) }), 'checkpoint-shape'],
  ['a copy of an entry inserted and the chain rebuilt', () => variant({ entries: text(rechain([ENTRIES[0], ENTRIES[0], ...ENTRIES.slice(1)])) }), 'envelope-duplicate'],
  ['another signed run inserted and the chain rebuilt', () => {
    const extraFiles = new Map([['run-extra.json', EXTRA]]);
    const extra = Buffer.from(signFiles([{ name: 'run-extra.json', content: EXTRA }], { privateKey: KEY.privatePem, version, now: at(0.2) }).envelope);
    const entry = buildEntry({ previousLine: null, index: 0, recordedAt: at(2.2).toISOString(), envelope: extra, check: verifyEnvelope({ envelope: extra, publicKey: KEY.publicPem, files: extraFiles }), files: extraFiles });
    const v = variant({ entries: text(rechain([...ENTRIES.slice(0, 2), entry, ...ENTRIES.slice(2)])) }); v.envelopes.set(sha(extra), extra); return v;
  }, 'checkpoint-mismatch'],
  ['an entry dated after the next one, chain rebuilt', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i === 1 ? { ...e, recordedAt: at(3).toISOString() } : e))) }), 'time-regression'],
  ['a signed checkpoint whose head disagrees with its root', () => {
    const body = { ...pointBody(POINTS[1]), headHash: 'b'.repeat(64) }, payload = Buffer.from(JSON.stringify(body)), sigline = JSON.parse(POINTS[1]);
    return variant({ checkpoints: text([POINTS[0], JSON.stringify({ ...sigline, payload: payload.toString('base64'), signatures: [{ keyid: sigline.signatures[0].keyid, sig: resign(payload) }] })]) });
  }, 'checkpoint-mismatch'],
  ['an entry backdated before the previous one', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i === 2 ? { ...e, recordedAt: at(1).toISOString() } : e))) }), 'time-regression'],
  ['an entry backdated before its evidence was signed', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i === 1 ? { ...e, recordedAt: at(0.75).toISOString() } : e))) }), 'time-regression'],
  ['every entry shifted earlier and the chain rebuilt', () => variant({ entries: text(rechain(ENTRIES.map(e => ({ ...e, recordedAt: new Date(Date.parse(e.recordedAt) + 1000).toISOString() })))) }), 'checkpoint-mismatch'],
  ['a verdict rewritten', () => variant({ entries: text(ENTRIES.map((e, i) => JSON.stringify(i === 1 ? recordWith(e, run => ({ ...run, verdicts: run.verdicts.map(([id, s]) => [id, id === 'TENANT-01' ? 'fail' : s]) })) : e))) }), 'verdict-digest-mismatch'],
  ['a verdict and its digest rewritten', () => variant({ entries: text(ENTRIES.map((e, i) => {
    if (i !== 1) return JSON.stringify(e);
    return JSON.stringify(recordWith(e, run => { const verdicts = run.verdicts.map(([id, s]) => [id, id === 'TENANT-01' ? 'fail' : s]); return { ...run, verdicts, verdictDigest: sha(JSON.stringify(verdicts)) }; }));
  })) }), 'chain-broken'],
  ['a verdict rewritten and the chain rebuilt', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i !== 1 ? e : recordWith(e, run => { const verdicts = run.verdicts.map(([id, s]) => [id, id === 'TENANT-01' ? 'fail' : s]); return { ...run, verdicts, verdictDigest: sha(JSON.stringify(verdicts)) }; })))) }), 'checkpoint-mismatch'],
  ['a run identity rewritten and the chain rebuilt', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i === 0 ? recordWith(e, run => ({ ...run, build: 'repaired' })) : e))) }), 'run-mismatch'],
  ['an envelope replaced', () => { const v = variant(); v.envelopes.set(ENTRIES[0].envelope.sha256, envelopes[3]); return v; }, 'envelope-mismatch'],
  ['an envelope removed', () => { const v = variant(); v.envelopes.delete(ENTRIES[0].envelope.sha256); return v; }, 'envelope-missing'],
  ['an entry pointing at an envelope signed by another key', () => {
    const forged = Buffer.from(signFiles([...files[0]].map(([name, content]) => ({ name, content })), { privateKey: OTHER.privatePem, version, now: at(0) }).envelope);
    const v = variant({ entries: text(rechain(ENTRIES.map((e, i) => i ? e : { ...e, envelope: { ...e.envelope, sha256: sha(forged) } }))) }); v.envelopes.set(sha(forged), forged); return v;
  }, 'envelope-invalid'],
  ['a second head signed at the same size (fork)', () => {
    const branch = rechain([...ENTRIES.slice(0, 3), { ...ENTRIES[3], recordedAt: at(3.75).toISOString() }]);
    return variant({ checkpoints: text([...POINTS, signCheckpoint({ log: LOG, createdAt: CREATED, lines: branch, signedAt: at(4.5).toISOString(), privateKey: KEY.privatePem })]) });
  }, 'fork'],
  ['checkpoints reordered', () => variant({ checkpoints: text([POINTS[1], POINTS[0]]) }), 'checkpoint-regression'],
  ['verified against a different ledger key', () => [variant(), OTHER.publicPem], 'keyid-mismatch'],
  ['a checkpoint signed by another key under this key\'s id', () => {
    const forged = JSON.parse(signCheckpoint({ log: LOG, createdAt: CREATED, lines: linesOf(BASE.entries), signedAt: at(5).toISOString(), privateKey: OTHER.privatePem }));
    forged.signatures[0].keyid = JSON.parse(POINTS[0]).signatures[0].keyid;
    return variant({ checkpoints: text([...POINTS, JSON.stringify(forged)]) });
  }, 'checkpoint-signature'],
  ['a checkpoint that claims a witness', () => {
    const body = { ...pointBody(POINTS[1]), witness: 'cosigned' }, sigline = JSON.parse(signCheckpoint({ log: LOG, createdAt: CREATED, lines: linesOf(BASE.entries), signedAt: body.signedAt, privateKey: KEY.privatePem }));
    const payload = Buffer.from(JSON.stringify(body));
    return variant({ checkpoints: text([POINTS[0], JSON.stringify({ ...sigline, payload: payload.toString('base64'), signatures: [{ keyid: sigline.signatures[0].keyid, sig: resign(payload) }] })]) });
  }, 'checkpoint-shape'],
  ['a checkpoint dated before an entry it covers', () => variant({ checkpoints: text([POINTS[0], signCheckpoint({ log: LOG, createdAt: CREATED, lines: linesOf(BASE.entries), signedAt: at(3.25).toISOString(), privateKey: KEY.privatePem })]) }), 'time-regression'],
  ['no checkpoint', () => variant({ checkpoints: Buffer.from('') }), 'no-checkpoint'],
  ['an anchor count beyond what JavaScript holds exactly, chain rebuilt', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i ? e : recordWith(e, run => ({ ...run, anchors: [{ source: 'sql-audit-table', custody: 'subject-writable', count: 2 ** 53, head: 'c'.repeat(64) }] }))))) }), 'entry-shape'],
  ['an unsigned line nested 120,000 deep', () => variant({ entries: Buffer.concat([BASE.entries, Buffer.from(`${'['.repeat(120000)}${']'.repeat(120000)}\n`)]) }), 'entry-shape'],
  ['an entry without its anchors list, chain rebuilt', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i ? e : recordWith(e, ({ anchors, ...run }) => run)))) }), 'entry-shape'],
  ['an anchor claiming a custody class that does not exist, chain rebuilt', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i ? e : recordWith(e, run => ({ ...run, anchors: [{ source: 'sql-audit-table', custody: 'trusted', count: 1, head: 'c'.repeat(64) }] }))))) }), 'entry-shape'],
  ['an entry naming another signer for its envelope, chain rebuilt', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i ? e : { ...e, envelope: { ...e.envelope, keyid: 'a'.repeat(64) } }))) }), 'envelope-invalid'],
  ['a checkpoint signed for a different log', () => variant({ checkpoints: text([...POINTS, signCheckpoint({ log: '00000000-0000-4000-8000-000000000000', createdAt: CREATED, lines: linesOf(BASE.entries), signedAt: at(5).toISOString(), privateKey: KEY.privatePem })]) }), 'checkpoint-shape'],
  ['a verdict with an unknown status, digest and chain rebuilt', () => variant({ entries: text(rechain(ENTRIES.map((e, i) => i !== 1 ? e : recordWith(e, run => { const verdicts = run.verdicts.map(([id, s]) => [id, id === 'TENANT-01' ? 'passish' : s]); return { ...run, verdicts, verdictDigest: sha(JSON.stringify(verdicts)) }; })))) }), 'entry-shape'],
  ['an entry written with spacing', () => variant({ entries: text(linesOf(BASE.entries).map((line, i) => i ? line : JSON.stringify(JSON.parse(line), null, 1).replace(/\n/g, ''))) }), 'entry-not-canonical'],
];
// Signs an arbitrary checkpoint payload with the real key (for the witness-claim case).
function resign(payload) {
  const type = 'application/vnd.scopehaven.ledger-checkpoint+json';
  return rawSign(null, Buffer.concat([Buffer.from(`DSSEv1 ${type.length} ${type} ${payload.length} `), payload]), createPrivateKey(KEY.privatePem)).toString('base64');
}
const build = make => { const made = make(); return Array.isArray(made) ? made : [made, KEY.publicPem]; };

// The independent Python verifier, when a Python 3.8+ is installed at a fixed path.
const PYTHON = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3', '/opt/homebrew/bin/python3', '/usr/bin/python3'].find(path => existsSync(path));
const SCRIPT = fileURLToPath(new URL('./verify_ledger.py', import.meta.url));
const python = (args, input) => new Promise(resolve => {
  const child = execFile(PYTHON, ['-B', ...args], { maxBuffer: 16 << 20, timeout: 120000 }, (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr }));
  if (input !== undefined) child.stdin.end(input);
});
async function writeLedger(dir, files, key) {
  await mkdir(join(dir, 'envelopes'), { recursive: true });
  await writeFile(join(dir, 'ledger.json'), files.metadata); await writeFile(join(dir, 'entries.jsonl'), files.entries); await writeFile(join(dir, 'checkpoints.jsonl'), files.checkpoints);
  for (const [name, bytes] of files.envelopes) await writeFile(join(dir, 'envelopes', `${name}.json`), bytes);
  await writeFile(join(dir, 'key.pem'), key);
}
const verifyPython = async (t, files, key = KEY.publicPem) => {
  const dir = await scratch(t); await writeLedger(dir, files, key);
  const { code, stdout, stderr } = await python([SCRIPT, 'log', '--key', join(dir, 'key.pem'), '--evidence-key', join(dir, 'key.pem'), '--ledger', dir].map(String));
  return { code, result: stdout ? JSON.parse(stdout) : null, stderr };
};
// The evidence key stays the real one when a case swaps the ledger key.
const evidenceFor = key => key === KEY.publicPem ? undefined : KEY.publicPem;

test('a real ledger of signed runs verifies, with every negative control rejected', () => {
  const result = verifyNode(BASE);
  assert.equal(result.verdict, 'verified', result.detail); assert.equal(result.size, 4); assert.equal(result.covered, 4); assert.equal(result.unsignedTail, 0); assert.equal(result.witness, 'none');
  assert.deepEqual(result.checkpoints.map(c => c.treeSize), [2, 4]);
  assert.deepEqual(result.selfChecks.map(c => [c.id, c.observed]), ['checkpoint-payload-tampered', 'checkpoint-wrong-key', 'entry-rewritten', 'inclusion-path-tampered', 'envelope-signature-tampered', 'entries-reordered'].map(id => [id, 'rejected']));
  assert.deepEqual(result.entries.map(e => e.runs[0].id), runs.map(r => r.id));
  for (const [i, entry] of result.entries.entries()) assert.deepEqual(entry.runs[0].verdicts, runs[i].results.map(r => [r.id, r.status]));
});

test('every tamper class is rejected by the Node verifier with its reason', () => {
  for (const [label, make, reason] of TAMPERS) {
    const [files, key] = build(make);
    const result = verifyLedger({ ...files, ledgerKey: key, evidenceKey: evidenceFor(key) });
    assert.equal(result.verdict, 'rejected', label); assert.equal(result.reason, reason, `${label}: ${result.detail}`);
  }
});

test('the Python verifier accepts the ledger and rejects every tamper with the same reason', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  const ok = await verifyPython(t, BASE);
  assert.equal(ok.code, 0, ok.stderr || JSON.stringify(ok.result)); assert.equal(ok.result.covered, 4);
  assert.deepEqual(ok.result.selfChecks.map(c => c.observed), ['rejected', 'rejected', 'rejected', 'rejected', 'rejected', 'rejected']);
  for (const [label, make, reason] of TAMPERS) {
    const [files, key] = build(make);
    const dir = await scratch(t); await writeLedger(dir, files, key); await writeFile(join(dir, 'evidence.pem'), KEY.publicPem);
    const { code, stdout, stderr } = await python([SCRIPT, 'log', '--key', join(dir, 'key.pem'), '--evidence-key', join(dir, 'evidence.pem'), '--ledger', dir]);
    assert.equal(code, 1, `${label}: ${stderr}${stdout}`); assert.equal(JSON.parse(stdout).reason, reason, label);
  }
});

test('inclusion and consistency proofs verify in both languages, and tampered ones do not', async t => {
  const lines = linesOf(BASE.entries), cases = [];
  for (const point of POINTS) {
    const size = pointBody(point).treeSize;
    for (let index = 0; index < size; index++) {
      const proof = inclusionProof({ log: LOG, lines, index, treeSize: size });
      assert.equal(verifyInclusion({ entryLine: lines[index], proof, checkpoint: point, ledgerKey: KEY.publicPem }).verdict, 'verified');
      cases.push(['inclusion', lines[index], proof, point, 'verified']);
      if (proof.path.length) {
        const bad = { ...proof, path: proof.path.map((h, i) => i ? h : 'e'.repeat(64)) };
        assert.equal(verifyInclusion({ entryLine: lines[index], proof: bad, checkpoint: point, ledgerKey: KEY.publicPem }).reason, 'inclusion-proof-invalid');
        cases.push(['inclusion', lines[index], bad, point, 'inclusion-proof-invalid']);
      }
    }
  }
  const proof = consistencyProof({ log: LOG, lines, from: 2, to: 4 });
  assert.equal(verifyConsistency({ older: POINTS[0], newer: POINTS[1], proof, ledgerKey: KEY.publicPem }).verdict, 'verified');
  cases.push(['consistency', POINTS[0], POINTS[1], proof, 'verified']);
  // A head from a different history at size 4 cannot be proven to extend the size-2 head.
  const branch = rechain([ENTRIES[0], { ...ENTRIES[1], recordedAt: at(1.75).toISOString() }, ...ENTRIES.slice(2)]);
  const forked = signCheckpoint({ log: LOG, createdAt: CREATED, lines: branch, signedAt: at(4.5).toISOString(), privateKey: KEY.privatePem });
  for (const [older, newer, p, reason] of [[POINTS[0], forked, proof, 'consistency-proof-invalid'], [POINTS[1], forked, consistencyProof({ log: LOG, lines, from: 4, to: 4 }), 'fork'],
    [POINTS[1], POINTS[0], proof, 'checkpoint-regression']]) {
    assert.equal(verifyConsistency({ older, newer, proof: p, ledgerKey: KEY.publicPem }).reason, reason);
    cases.push(['consistency', older, newer, p, reason]);
  }
  assert.equal(verifyInclusion({ entryLine: lines[0], proof: inclusionProof({ log: LOG, lines, index: 0, treeSize: 4 }), checkpoint: POINTS[1], ledgerKey: OTHER.publicPem }).reason, 'keyid-mismatch');
  // A proof labelled for another entry, size or range is refused even when its path happens to fit.
  const relabelled = { ...inclusionProof({ log: LOG, lines, index: 0, treeSize: 4 }), index: 1 };
  assert.equal(verifyInclusion({ entryLine: lines[0], proof: relabelled, checkpoint: POINTS[1], ledgerKey: KEY.publicPem }).reason, 'inclusion-proof-invalid');
  cases.push(['inclusion', lines[0], relabelled, POINTS[1], 'inclusion-proof-invalid']);
  const sized = { ...inclusionProof({ log: LOG, lines, index: 0, treeSize: 4 }), treeSize: 2 };
  assert.equal(verifyInclusion({ entryLine: lines[0], proof: sized, checkpoint: POINTS[1], ledgerKey: KEY.publicPem }).reason, 'inclusion-proof-invalid');
  cases.push(['inclusion', lines[0], sized, POINTS[1], 'inclusion-proof-invalid']);
  const ranged = { ...proof, from: 3 };
  assert.equal(verifyConsistency({ older: POINTS[0], newer: POINTS[1], proof: ranged, ledgerKey: KEY.publicPem }).reason, 'consistency-proof-invalid');
  cases.push(['consistency', POINTS[0], POINTS[1], ranged, 'consistency-proof-invalid']);
  if (!PYTHON) return;
  const dir = await scratch(t); await writeFile(join(dir, 'key.pem'), KEY.publicPem);
  for (const [n, [kind, a, b, c, expected]] of cases.entries()) {
    const args = kind === 'inclusion'
      ? (await Promise.all([['entry', a], ['proof', JSON.stringify(b)], ['checkpoint', c]].map(async ([k, v]) => { await writeFile(join(dir, `${n}.${k}`), v); return [`--${k}`, join(dir, `${n}.${k}`)]; }))).flat()
      : (await Promise.all([['older', a], ['newer', b], ['proof', JSON.stringify(c)]].map(async ([k, v]) => { await writeFile(join(dir, `${n}.${k}`), v); return [`--${k}`, join(dir, `${n}.${k}`)]; }))).flat();
    const { code, stdout } = await python([SCRIPT, kind, '--key', join(dir, 'key.pem'), ...args]);
    const out = JSON.parse(stdout);
    assert.equal(expected === 'verified' ? out.verdict : out.reason, expected, `${kind} case ${n}`); assert.equal(code, expected === 'verified' ? 0 : 1);
  }
});

test('RFC 9162 proofs agree between the writer and both verifiers for every size up to 20', async () => {
  const fixtures = [];
  for (let n = 1; n <= 20; n++) {
    const lines = Array.from({ length: n }, (_, i) => `line-${i}`), leaves = lines.map(l => leafHash(Buffer.from(l))), root = treeHead(leaves);
    for (let i = 0; i < n; i++) {
      const path = inclusionProof({ log: LOG, lines, index: i, treeSize: n }).path;
      assert.ok(verifyInclusionPath(leaves[i], i, n, path.map(h => Buffer.from(h, 'hex')), root));
      if (i + 1 < n) assert.ok(!verifyInclusionPath(leaves[i + 1], i, n, path.map(h => Buffer.from(h, 'hex')), root));
      fixtures.push({ kind: 'inclusion', leaf: leaves[i].toString('hex'), index: i, size: n, path, root: root.toString('hex') });
    }
    for (let m = 1; m <= n; m++) {
      const path = consistencyProof({ log: LOG, lines, from: m, to: n }).path, first = treeHead(leaves.slice(0, m));
      assert.ok(verifyConsistencyPath(m, n, path.map(h => Buffer.from(h, 'hex')), first, root));
      if (m < n) assert.ok(!verifyConsistencyPath(m, n, path.map(h => Buffer.from(h, 'hex')), treeHead([leafHash(Buffer.from('forged')), ...leaves.slice(1, m)]), root));
      fixtures.push({ kind: 'consistency', from: m, to: n, path, first: first.toString('hex'), root: root.toString('hex') });
    }
  }
  if (!PYTHON) return;
  const program = `import sys, json; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_ledger as v
ok = 0
for f in json.loads(sys.stdin.read()):
    path = [bytes.fromhex(h) for h in f["path"]]
    if f["kind"] == "inclusion":
        ok += v.verify_inclusion_path(bytes.fromhex(f["leaf"]), f["index"], f["size"], path, bytes.fromhex(f["root"]))
        ok -= 1 if f["index"] + 1 < f["size"] and v.verify_inclusion_path(bytes.fromhex(f["leaf"]), f["index"] + 1, f["size"], path, bytes.fromhex(f["root"])) else 0
    else:
        ok += v.verify_consistency_path(f["from"], f["to"], path, bytes.fromhex(f["first"]), bytes.fromhex(f["root"]))
print(ok)`;
  const { code, stdout, stderr } = await python(['-c', program], JSON.stringify(fixtures));
  assert.equal(code, 0, stderr); assert.equal(Number(stdout), fixtures.length);
});

test('the permission history shows verdict changes within one identity and never across identities', async t => {
  const result = verifyNode(BASE), history = permissionHistory(result);
  assert.equal(history.segments.length, 1); assert.equal(history.witness, 'none');
  const tenant = history.segments[0].changes.filter(c => c.check === 'TENANT-01').map(c => [c.from, c.to, c.entry]);
  assert.deepEqual(tenant, [['fail', 'pass', 1], ['pass', 'fail', 2], ['fail', 'pass', 3]]);
  assert.ok(history.segments[0].changes.every(c => runs[0].results.find(r => r.id === c.check).severity !== 'control'), 'controls never changed');
  // Append the run under a changed suite identity: a new segment, nothing compared with the old one.
  const dir = await scratch(t);
  for (const name of ['ledger.json', 'entries.jsonl', 'checkpoints.jsonl']) await writeFile(join(dir, name), await readFile(join(ledgerDir, name)));
  await mkdir(join(dir, 'envelopes'), { mode: 0o700 }); for (const [name, bytes] of BASE.envelopes) await writeFile(join(dir, 'envelopes', `${name}.json`), bytes);
  const added = await appendEnvelope(dir, { envelope: envelopes[4], files: files[4], evidenceKey: KEY.publicPem, now: at(5) });
  const unsigned = verifyNode(await readLedgerFiles(dir));
  assert.equal(unsigned.unsignedTail, 1); assert.equal(permissionHistory(unsigned).segments.length, 1, 'entries past the last checkpoint stay out of history');
  await checkpointLedger(dir, { privateKey: KEY.privatePem, expectedTail: [added.lineSha256], now: at(6) });
  const after = permissionHistory(verifyNode(await readLedgerFiles(dir)));
  assert.equal(after.segments.length, 2); assert.deepEqual(after.segments[1].changes, []); assert.equal(after.segments[1].identity.suiteHash, 'f'.repeat(64));
  assert.throws(() => permissionHistory(verifyNode(variant({ checkpoints: Buffer.from('') }))), /verified ledger/);
  assert.throws(() => permissionHistory(verifyNode(BASE, KEY.publicPem, { signature: () => true })), /verified ledger/, 'never from a verifier that failed its own controls');
});

test('the writer refuses unverified, duplicate, out-of-order and unlocked work', async t => {
  const dir = await scratch(t);
  await initLedger(dir, { now: at(0) });
  await assert.rejects(initLedger(dir, { now: at(0) }), /EEXIST/);
  const tamperedFiles = new Map([['run-0.json', Buffer.concat([exported[0], Buffer.from(' ')])]]);
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[0], files: tamperedFiles, evidenceKey: KEY.publicPem, now: at(1) }), /did not verify/);
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[0], files: files[0], evidenceKey: OTHER.publicPem, now: at(1) }), /did not verify/);
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, now: at(0.5) }), /clock/);
  const one = await appendEnvelope(dir, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, now: at(2) });
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, now: at(3) }), /This envelope is already in the ledger/);
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, now: at(1.5) }), /clock/);
  await assert.rejects(checkpointLedger(dir, { privateKey: KEY.privatePem, expectedTail: [one.lineSha256], now: at(1) }), /clock/);
  await assert.rejects(checkpointLedger(dir, { privateKey: KEY.privatePem, now: at(3) }), /nothing shows this writer wrote them/, 'an unsigned tail is signed only when the caller names its lines');
  await assert.rejects(checkpointLedger(dir, { privateKey: KEY.privatePem, expectedTail: ['0'.repeat(64)], now: at(3) }), /nothing shows this writer wrote them/);
  await checkpointLedger(dir, { privateKey: KEY.privatePem, expectedTail: [one.lineSha256], now: at(3) });
  await assert.rejects(checkpointLedger(dir, { privateKey: KEY.privatePem, now: at(4) }), /Nothing new/);
  await assert.rejects(checkpointLedger(dir, { privateKey: KEY.publicPem, now: at(4) }), /private key/);
  await writeFile(join(dir, '.lock'), 'x');
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, now: at(5) }), /another writer/);
  const open = await scratch(t); await chmod(open, 0o755);
  await assert.rejects(initLedger(open), /private directory/);
});

test('a verifier that accepts every signature fails its own negative controls', () => {
  const result = verifyNode(BASE, KEY.publicPem, { signature: () => true });
  assert.equal(result.verdict, 'self-check-failed'); assert.equal(result.verified, false);
  assert.deepEqual(result.selfChecks.filter(c => c.observed === 'accepted').map(c => c.id), ['checkpoint-payload-tampered', 'checkpoint-wrong-key']);
});

test('the Python verifier catches a signature check that accepts everything', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  const dir = await scratch(t); await writeLedger(dir, BASE, KEY.publicPem);
  const program = `import sys; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))})
import verify_ledger as v
v.attest.ed25519_verify = lambda *args: True
sys.exit(v.main(["log", "--key", ${JSON.stringify(join(dir, 'key.pem'))}, "--ledger", ${JSON.stringify(dir)}]))`;
  const { code, stdout } = await python(['-c', program]);
  assert.equal(code, 3, stdout); assert.equal(JSON.parse(stdout).verdict, 'self-check-failed');
});

test('the CLI runs the whole cycle in a folder whose name has a space', async t => {
  const dir = join(await scratch(t), 'my ledger'), keys = await scratch(t);
  await mkdir(dir, { mode: 0o700 });
  await writeFile(join(keys, 'pub.pem'), KEY.publicPem); await writeFile(join(keys, 'key.pem'), KEY.privatePem, { mode: 0o600 });
  const evidence = await scratch(t);
  await writeFile(join(evidence, 'run-0.json'), exported[0]); await writeFile(join(evidence, 'e.json'), envelopes[0]);
  assert.equal((await main(['init', '--ledger', dir])).code, 0);
  const appended = await main(['append', '--ledger', dir, '--key', join(keys, 'key.pem'), '--evidence-key', join(keys, 'pub.pem'), '--envelope', join(evidence, 'e.json'), '--dir', evidence]);
  assert.equal(appended.code, 0, JSON.stringify(appended.output)); assert.equal(appended.output.index, 0); assert.equal(appended.output.signed, true); assert.equal(appended.output.witness, 'none');
  assert.equal((await main(['checkpoint', '--ledger', dir, '--key', join(keys, 'key.pem')])).code, 2, 'nothing new to sign');
  const verified = await main(['verify', '--ledger', dir, '--key', join(keys, 'pub.pem')]);
  assert.equal(verified.code, 0, JSON.stringify(verified.output)); assert.equal(verified.output.covered, 1); assert.equal(verified.output.entries, undefined);
  const proof = await main(['prove', '--ledger', dir, '--index', '0']);
  assert.equal(proof.output.proof.treeSize, 1);
  assert.equal((await main(['history', '--ledger', dir, '--key', join(keys, 'pub.pem')])).output.segments.length, 1);
  assert.equal((await main(['verify', '--ledger', dir, '--key', join(keys, 'key.pem')])).code, 2, 'verification takes only a public key');
  assert.equal((await main(['verify', '--ledger', relative(process.cwd(), dir), '--key', join(keys, 'pub.pem')])).code, 2, 'a relative ledger path is refused even when it exists');
  assert.equal((await main(['verify', '--ledger', dir, '--key', relative(process.cwd(), join(keys, 'pub.pem'))])).code, 2, 'a relative key path is refused too');
  assert.equal((await main(['verify', '--ledger', dir, '--key', join(keys, 'pub.pem'), '--run-files', relative(process.cwd(), evidence)])).code, 2, 'and a relative --run-files path');
  await chmod(join(keys, 'key.pem'), 0o644);
  const loose = await main(['append', '--ledger', dir, '--key', join(keys, 'key.pem'), '--evidence-key', join(keys, 'pub.pem'), '--envelope', join(evidence, 'e.json'), '--dir', evidence]);
  assert.equal(loose.code, 2); assert.match(loose.output.error, /mode 0600/);
  await chmod(join(keys, 'key.pem'), 0o600);
  const rel = await main(['append', '--ledger', dir, '--key', relative(process.cwd(), join(keys, 'key.pem')), '--evidence-key', join(keys, 'pub.pem'), '--envelope', join(evidence, 'e.json'), '--dir', evidence]);
  assert.equal(rel.code, 2); assert.match(rel.output.error, /must be absolute/);
  const keyless = await main(['append', '--ledger', dir, '--evidence-key', join(keys, 'pub.pem'), '--envelope', join(evidence, 'e.json'), '--dir', evidence]);
  assert.equal(keyless.code, 2, 'append signs in the same step, so it needs --key'); assert.match(keyless.output.error, /^Usage/); assert.equal((await main(['verify', '--ledger', dir, '--key', join(keys, 'pub.pem')])).output.size, 1);
  // A symlink in --run-files is skipped by both verifiers, even when it points at the right run file.
  const linked = await scratch(t); await symlink(join(evidence, 'run-0.json'), join(linked, 'run-0.json'));
  const viaLink = await main(['verify', '--ledger', dir, '--key', join(keys, 'pub.pem'), '--run-files', linked]);
  assert.equal(viaLink.code, 0); assert.equal(viaLink.output.verdictsCheckedAgainstRunFiles, 0);
  await writeFile(join(linked, 'copy.json'), exported[0]);
  assert.equal((await main(['verify', '--ledger', dir, '--key', join(keys, 'pub.pem'), '--run-files', linked])).output.verdictsCheckedAgainstRunFiles, 1, 'the same bytes as a regular file are checked');
  if (PYTHON) {
    const { code, stdout } = await python([SCRIPT, 'log', '--key', join(keys, 'pub.pem'), '--ledger', dir]);
    assert.equal(code, 0, stdout); assert.equal(JSON.parse(stdout).covered, 1);
    await rm(join(linked, 'copy.json'));
    const py = await python([SCRIPT, 'log', '--key', join(keys, 'pub.pem'), '--ledger', dir, '--run-files', linked]);
    assert.equal(py.code, 0, py.stdout); assert.equal(JSON.parse(py.stdout).verdictsCheckedAgainstRunFiles, 0, 'Python skips the symlink too');
    const relKey = await python([SCRIPT, 'log', '--key', relative(process.cwd(), join(keys, 'pub.pem')), '--ledger', dir]);
    assert.equal(relKey.code, 2); assert.match(JSON.parse(relKey.stdout).error, /must be absolute/);
  }
});

// EVID-SUBJECT (integrations/evid-subject): this test skips when its custody module is absent.
const CUSTODY_MODULE = new URL('../evid-subject/custody.mjs', import.meta.url);
test('the ledger is the operator-held, unwitnessed anchor EVID-SUBJECT checks a resealed truncation against', { skip: !existsSync(CUSTODY_MODULE) && 'integrations/evid-subject not present yet' }, async t => {
  const { anchorOf, verifyChain, subjectIntegrityVerdict } = await import(CUSTODY_MODULE);
  // An observer-kept evidence chain for run 0: three records of the subject's own audit table.
  const records = [1, 2, 3].map(n => ({ seq: n, action: 'refund', principal: 'member-aster', effectAtMs: n * 10, recordedAtMs: n * 10 }));
  const kept = anchorOf(records);
  const dir = await scratch(t);
  await initLedger(dir, { now: at(0) });
  const anchored = await appendEnvelope(dir, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, now: at(1),
    anchors: new Map([['run-0.json', [{ source: 'sql-audit-table', count: kept.count, head: kept.head, declaredCustody: 'independent' }]]]) });
  await checkpointLedger(dir, { privateKey: KEY.privatePem, expectedTail: [anchored.lineSha256], now: at(2) });
  const verified = verifyNode(await readLedgerFiles(dir));
  assert.equal(verified.verdict, 'verified', verified.detail);
  const anchor = anchorFor(verified, { runId: runs[0].id, source: 'sql-audit-table' });
  assert.equal(anchor.custody, 'subject-writable', 'a declaration can only lower custody; the app\'s own audit table stays subject-writable');
  assert.deepEqual([anchor.count, anchor.head], [kept.count, kept.head]);
  assert.equal(verifyChain(records, anchor).ok, true);
  // The subject drops the last record and reseals: consistent against its own anchor, caught against the ledger's.
  const truncated = records.slice(0, 2);
  assert.equal(verifyChain(truncated, anchorOf(truncated)).ok, true, 'a resealed chain verifies against a subject-held anchor');
  assert.deepEqual(verifyChain(truncated, anchor).reasons, ['chain-head-mismatch']);
  assert.equal(subjectIntegrityVerdict({ proposed: 'pass', support: [{ source: 'hold-proxy' }], chain: { entries: truncated, anchor } }).verdict, 'inconclusive');
  assert.equal(anchorFor(verified, { runId: runs[0].id, source: 'otel-genai' }), null);
  assert.equal(anchorFor(verified, { runId: runs[1].id, source: 'sql-audit-table' }), null, 'another run\'s anchor is never returned');
  const broken = verifyNode(await readLedgerFiles(dir), KEY.publicPem, { signature: () => true });
  assert.throws(() => anchorFor(broken, { runId: runs[0].id, source: 'sql-audit-table' }), /verified ledger/);
  assert.throws(() => anchorFor(verifyNode(variant({ checkpoints: Buffer.from('') })), { runId: runs[0].id, source: 'sql-audit-table' }), /verified ledger/);
  // Anchors for a run the envelope does not hold are refused.
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, now: at(3),
    anchors: new Map([['run-0.json', [{ source: 'sql-audit-table', count: 0, head: null }]]]) }), /not a run in this envelope/);
  if (PYTHON) {
    await writeFile(join(dir, 'key.pem'), KEY.publicPem);
    const { code, stdout } = await python([SCRIPT, 'log', '--key', join(dir, 'key.pem'), '--ledger', dir]);
    assert.equal(code, 0, stdout);
  }
});

test('rollback is visible only to a holder of the later checkpoint, signed appends leave no editable tail, and the writer refuses what it cannot verify', async t => {
  // Rolling back to the size-2 checkpoint verifies on its own: transparency logs need the later head.
  const rolled = variant({ entries: text(linesOf(BASE.entries).slice(0, 2)), checkpoints: text([POINTS[0]]) });
  const back = verifyNode(rolled);
  assert.equal(back.verdict, 'verified'); assert.equal(back.covered, 2);
  assert.equal(verifyConsistency({ older: POINTS[1], newer: POINTS[0], proof: consistencyProof({ log: LOG, lines: linesOf(BASE.entries), from: 2, to: 4 }), ledgerKey: KEY.publicPem }).reason, 'checkpoint-regression', 'a saved later head exposes it');
  // Signed appends: nothing is ever left unsigned, so editing the newest entry breaks a checkpoint.
  const dir = await scratch(t);
  await initLedger(dir, { now: at(0) });
  for (const i of [0, 1]) assert.equal((await appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) })).signed, true);
  const signed = await readLedgerFiles(dir), signedLines = linesOf(signed.entries);
  assert.equal(verifyNode(signed).unsignedTail, 0);
  assert.equal(JSON.parse(signedLines[1]).runs[0].verdicts.find(([id]) => id === 'TENANT-01')[1], 'pass', 'the repaired run passes TENANT-01, so the edit is a real change');
  const last = JSON.parse(signedLines[1]), edited = recordWith(last, run => { const verdicts = run.verdicts.map(([id, st]) => [id, id === 'TENANT-01' ? 'fail' : st]); return { ...run, verdicts, verdictDigest: sha(JSON.stringify(verdicts)) }; });
  assert.equal(verifyNode({ ...signed, entries: text([signedLines[0], JSON.stringify(edited)]) }).reason, 'checkpoint-mismatch');
  // The writer will not extend or sign over a ledger that does not verify.
  await writeFile(join(dir, 'entries.jsonl'), text([signedLines[0], JSON.stringify(edited)]));
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }), /does not verify/);
  await writeFile(join(dir, 'entries.jsonl'), Buffer.concat([text(signedLines), Buffer.from('{"index":2')]));
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }), /cut off by a crash/);
  await assert.rejects(checkpointLedger(dir, { privateKey: KEY.privatePem, now: at(4) }), /do not verify/);
  // A signed append will not extend an unsigned tail, nor date itself before the last checkpoint.
  const tail = await scratch(t); await initLedger(tail, { now: at(0) });
  await appendEnvelope(tail, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1) });
  await appendEnvelope(tail, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, now: at(1.5) });
  await assert.rejects(appendEnvelope(tail, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }), /not covered by a checkpoint/);
  const bare = await scratch(t); await initLedger(bare, { now: at(0) });
  await appendEnvelope(bare, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, now: at(1) });
  await assert.rejects(appendEnvelope(bare, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(2) }), /no checkpoint/);
  const late = await scratch(t); await initLedger(late, { now: at(0) });
  const early = await appendEnvelope(late, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, now: at(1) });
  await checkpointLedger(late, { privateKey: KEY.privatePem, expectedTail: [early.lineSha256], now: at(5) });
  await assert.rejects(appendEnvelope(late, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }), /clock/);
  // A run whose results the verifiers would reject is never written.
  const odd = (() => { const run = JSON.parse(exported[2]); run.results[0].status = 'skipped'; const { integrity, notes, ...core } = run; run.integrity = { ...integrity, sha256: digest(core) }; return Buffer.from(JSON.stringify(run)); })();
  const oddFiles = new Map([['run-x.json', odd]]), oddEnvelope = Buffer.from(signFiles([{ name: 'run-x.json', content: odd }], { privateKey: KEY.privatePem, version, now: at(0) }).envelope);
  const fresh = await scratch(t); await initLedger(fresh, { now: at(0) });
  await assert.rejects(appendEnvelope(fresh, { envelope: oddEnvelope, files: oddFiles, evidenceKey: KEY.publicPem, now: at(1) }), /cannot be recorded/);
});

test('Node and Python agree on edge inputs', { skip: !PYTHON && 'no Python 3 at a fixed path' }, async t => {
  const lines = linesOf(BASE.entries), dir = await scratch(t);
  await writeFile(join(dir, 'key.pem'), KEY.publicPem);
  const proof = inclusionProof({ log: LOG, lines, index: 1, treeSize: 4 });
  const cases = [
    ['inclusion', { entry: lines[1], proof: JSON.stringify({ ...proof, index: true }), checkpoint: POINTS[1] }, 'inclusion-proof-invalid'],
    ['inclusion', { entry: lines[1], proof: JSON.stringify(proof), checkpoint: `\ufeff${POINTS[1]}` }, 'checkpoint-shape'],
    ['inclusion', { entry: lines[1], proof: JSON.stringify(proof), checkpoint: `${POINTS[1]}\x1f` }, 'checkpoint-shape'],
    ['inclusion', { entry: lines[1], proof: JSON.stringify(proof), checkpoint: ` \n${POINTS[1]}\r\n` }, 'verified'],
    ['consistency', { older: POINTS[0], newer: POINTS[1], proof: JSON.stringify({ ...consistencyProof({ log: LOG, lines, from: 2, to: 4 }), from: 2.0000000001 }) }, 'consistency-proof-invalid'],
  ];
  for (const [n, [kind, inputs, expected]] of cases.entries()) {
    const args = [];
    for (const [k, v] of Object.entries(inputs)) { await writeFile(join(dir, `${n}.${k}`), v); args.push(`--${k}`, join(dir, `${n}.${k}`)); }
    const node = kind === 'inclusion'
      ? verifyInclusion({ entryLine: inputs.entry, proof: JSON.parse(inputs.proof), checkpoint: inputs.checkpoint, ledgerKey: KEY.publicPem })
      : verifyConsistency({ older: inputs.older, newer: inputs.newer, proof: JSON.parse(inputs.proof), ledgerKey: KEY.publicPem });
    const { stdout } = await python([SCRIPT, kind, '--key', join(dir, 'key.pem'), ...args]), py = JSON.parse(stdout);
    for (const [who, out] of [['node', node], ['python', py]]) assert.equal(expected === 'verified' ? out.verdict : out.reason, expected, `${who} case ${n}`);
  }
});

test('anchors name only observer sources EVID-SUBJECT knows', { skip: !existsSync(new URL('../evid-subject/custody.mjs', import.meta.url)) && 'integrations/evid-subject not present yet' }, async t => {
  const dir = await scratch(t); await initLedger(dir, { now: at(0) });
  for (const source of ['constructor', '__proto__', 'my-own-gate']) {
    await assert.rejects(appendEnvelope(dir, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, now: at(1), anchors: new Map([['run-0.json', [{ source, count: 0, head: null }]]]) }), /Unknown observer source/);
  }
});

// Someone who can write the folder but holds no key injects an entry while
// the operator's signed append is in progress. Whatever the timing, that entry is never signed.
test('a concurrent write by someone without the key is never signed by the operator\'s append', async t => {
  const forge = async dir => {
    const lines = linesOf(await readFile(join(dir, 'entries.jsonl')));
    const extra = Buffer.from(signFiles([{ name: 'run-extra.json', content: EXTRA }], { privateKey: KEY.privatePem, version, now: at(2.6) }).envelope);
    const forgedFiles = new Map([['run-extra.json', EXTRA]]);
    const entry = buildEntry({ previousLine: lines.at(-1), index: lines.length, recordedAt: at(2.7).toISOString(), envelope: extra, check: verifyEnvelope({ envelope: extra, publicKey: KEY.publicPem, files: forgedFiles }), files: forgedFiles });
    entry.runs = entry.runs.map(run => { const verdicts = run.verdicts.map(([id]) => [id, 'pass']); return { ...run, verdicts, verdictDigest: sha(JSON.stringify(verdicts)) }; });
    await writeFile(join(dir, 'envelopes', `${sha(extra)}.json`), extra);
    await writeFile(join(dir, 'entries.jsonl'), `${JSON.stringify(entry)}\n`, { flag: 'a' });
  };
  const build = async () => {
    const dir = await scratch(t); await initLedger(dir, { now: at(0) });
    for (const i of [0, 1]) await appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
    return dir;
  };
  const coversForged = result => result.verdict === 'verified' && result.entries.some(e => e.runs.some(r => r.subject === 'run-extra.json'));
  // Injected after verification: the writer sees the change before writing and refuses.
  const early = await build();
  await assert.rejects(appendEnvelope(early, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }, { afterVerify: () => forge(early) }), /changed while this write was being prepared/);
  const afterEarly = verifyNode(await readLedgerFiles(early));
  assert.equal(afterEarly.verdict, 'verified'); assert.equal(afterEarly.unsignedTail, 1); assert.equal(coversForged(afterEarly), false);
  // Injected after the last comparison: the checkpoint covers only what was verified, so the ledger no
  // longer verifies and the forged entry is not covered; the writer reports it.
  const late = await build();
  await assert.rejects(appendEnvelope(late, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }, { beforeWrite: () => forge(late) }), /changed during this write/);
  const afterLate = verifyNode(await readLedgerFiles(late));
  assert.equal(afterLate.verdict, 'rejected'); assert.equal(coversForged(afterLate), false);
  assert.ok(existsSync(join(late, 'pending.json')), 'the signed write is kept after a change is detected');
  // A change to checkpoints.jsonl alone (here, its last line written again) is refused the same way.
  const points = await build();
  const echo = async () => { const last = linesOf(await readFile(join(points, 'checkpoints.jsonl'))).at(-1); await writeFile(join(points, 'checkpoints.jsonl'), `${last}\n`, { flag: 'a' }); };
  await assert.rejects(appendEnvelope(points, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }, { afterVerify: echo }), /changed while this write was being prepared/);
  // The recovery checkpoint command compares too: it never signs over an entry written after it verified.
  const tail = await scratch(t); await initLedger(tail, { now: at(0) });
  const own = await appendEnvelope(tail, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, now: at(0.5) });
  await assert.rejects(checkpointLedger(tail, { privateKey: KEY.privatePem, evidenceKey: KEY.publicPem, expectedTail: [own.lineSha256], now: at(3) }, { afterVerify: () => forge(tail) }), /changed while this write was being prepared/);
  assert.equal((await readFile(join(tail, 'checkpoints.jsonl'))).length, 0, 'nothing was signed');
});

test('recovery finishes only the signed append kept in pending.json, and never signs a line it did not write', async t => {
  // Ledger key OTHER, evidence key KEY, so recovery also needs --evidence-key.
  const keys = await scratch(t);
  await writeFile(join(keys, 'ledger.pem'), OTHER.privatePem, { mode: 0o600 }); await writeFile(join(keys, 'evidence.pub'), KEY.publicPem);
  const fresh = async () => {
    const dir = await scratch(t); await initLedger(dir, { now: at(0) });
    for (const i of [0, 1]) await appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: OTHER.privatePem, now: at(i + 0.5) });
    return dir;
  };
  const state = async dir => verifyLedger({ ...(await readLedgerFiles(dir)), ledgerKey: OTHER.publicPem, evidenceKey: KEY.publicPem });
  const recover = (dir, ...extra) => main(['checkpoint', '--ledger', dir, '--key', join(keys, 'ledger.pem'), ...extra]);
  const recoverWithEvidence = dir => recover(dir, '--evidence-key', join(keys, 'evidence.pub'));
  const append = (dir, i, m, hooks) => appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: OTHER.privatePem, now: at(m) }, hooks);
  // A keyless forgery chained onto the given entries: a real signed envelope, every verdict "pass".
  const forgeLine = async (dir, entriesBytes) => {
    const lines = linesOf(entriesBytes ?? await readFile(join(dir, 'entries.jsonl')));
    const extra = Buffer.from(signFiles([{ name: 'run-extra.json', content: EXTRA }], { privateKey: KEY.privatePem, version, now: at(2.6) }).envelope), forgedFiles = new Map([['run-extra.json', EXTRA]]);
    const entry = buildEntry({ previousLine: lines.at(-1), index: lines.length, recordedAt: at(2.7).toISOString(), envelope: extra, check: verifyEnvelope({ envelope: extra, publicKey: KEY.publicPem, files: forgedFiles }), files: forgedFiles });
    entry.runs = entry.runs.map(run => { const verdicts = run.verdicts.map(([id]) => [id, 'pass']); return { ...run, verdicts, verdictDigest: sha(JSON.stringify(verdicts)) }; });
    await writeFile(join(dir, 'envelopes', `${sha(extra)}.json`), extra);
    return JSON.stringify(entry);
  };
  const forgedCovered = result => result.verdict === 'verified' && result.entries.some(e => e.runs.some(r => r.subject === 'run-extra.json'));
  // A signed append that stops part way: checkpoints.jsonl is a symlink at write time (ELOOP), then put back.
  const stop = async dir => {
    const before = { entries: await readFile(join(dir, 'entries.jsonl')), checkpoints: await readFile(join(dir, 'checkpoints.jsonl')) };
    await assert.rejects(append(dir, 2, 3, { beforeWrite: async () => { await rename(join(dir, 'checkpoints.jsonl'), join(dir, 'cp.real')); await symlink(join(dir, 'cp.real'), join(dir, 'checkpoints.jsonl')); } }), /stopped part way/);
    assert.ok(existsSync(join(dir, 'pending.json')), 'the signed write is kept');
    await rm(join(dir, 'checkpoints.jsonl')); await rename(join(dir, 'cp.real'), join(dir, 'checkpoints.jsonl'));
    return before;
  };

  // A forged line on a fully signed ledger: nothing explains it, so neither the API nor the CLI signs it.
  const A = await fresh();
  await writeFile(join(A, 'entries.jsonl'), `${await forgeLine(A)}\n`, { flag: 'a' });
  assert.equal((await state(A)).unsignedTail, 1);
  const refusedA = await recoverWithEvidence(A);
  assert.equal(refusedA.code, 2); assert.match(refusedA.output.error, /nothing shows this writer wrote them/);
  await assert.rejects(checkpointLedger(A, { privateKey: OTHER.privatePem, evidenceKey: KEY.publicPem, now: at(9) }), /nothing shows this writer wrote them/);
  await assert.rejects(append(A, 2, 9), /A signed append never leaves such lines/);
  assert.equal((await state(A)).covered, 2); assert.equal(forgedCovered(await state(A)), false);

  // A stopped write is finished exactly as signed: its own line stays, its checkpoint is appended.
  const B = await fresh(); await stop(B);
  assert.equal((await state(B)).unsignedTail, 1);
  await assert.rejects(append(B, 3, 4), /pending\.json exists/);
  assert.equal((await recover(B)).code, 2, 'the evidence key is not the ledger key, so it must be given');
  const done = await recoverWithEvidence(B);
  assert.equal(done.code, 0, JSON.stringify(done.output)); assert.equal(done.output.finished, true); assert.equal(done.output.treeSize, 3);
  assert.equal(existsSync(join(B, 'pending.json')), false);
  const afterB = await state(B); assert.equal(afterB.verdict, 'verified'); assert.equal(afterB.covered, 3); assert.equal(afterB.unsignedTail, 0);
  await append(B, 3, 4);

  // The same, after the operator put entries.jsonl back too: recovery writes the line and the checkpoint.
  const C = await fresh(); const beforeC = await stop(C);
  await writeFile(join(C, 'entries.jsonl'), beforeC.entries);
  assert.equal((await recoverWithEvidence(C)).code, 0);
  assert.equal((await state(C)).covered, 3);

  // Someone rewrites the operator's uncovered line into a forgery: refused.
  const D = await fresh(); const beforeD = await stop(D);
  await writeFile(join(D, 'entries.jsonl'), Buffer.concat([beforeD.entries, Buffer.from(`${await forgeLine(D, beforeD.entries)}\n`)]));
  const refusedD = await recoverWithEvidence(D);
  assert.equal(refusedD.code, 2); assert.match(refusedD.output.error, /does not match the pending write/);
  assert.equal(forgedCovered(await state(D)), false); assert.ok(existsSync(join(D, 'pending.json')));

  // ... and also puts the forgery into pending.json: its signed checkpoint does not cover it.
  const F = await fresh(); const beforeF = await stop(F); const forged = await forgeLine(F, beforeF.entries);
  const record = JSON.parse(await readFile(join(F, 'pending.json'), 'utf8')); record.line = forged;
  await writeFile(join(F, 'pending.json'), `${JSON.stringify(record)}\n`, { mode: 0o600 });
  await writeFile(join(F, 'entries.jsonl'), Buffer.concat([beforeF.entries, Buffer.from(`${forged}\n`)]));
  const refusedF = await recoverWithEvidence(F);
  assert.equal(refusedF.code, 2); assert.match(refusedF.output.error, /do not have the head the pending intent signed/);
  assert.equal(forgedCovered(await state(F)), false);

  // Stopped after both appends, before pending.json was removed: recovery appends nothing and tidies up.
  const G = await fresh(); const last = await append(G, 2, 3);
  const metaG = JSON.parse(await readFile(join(G, 'ledger.json'), 'utf8'));
  const intentG = signIntent({ log: metaG.log, createdAt: metaG.createdAt, lines: linesOf(await readFile(join(G, 'entries.jsonl'))), signedAt: JSON.parse(last.line).recordedAt, privateKey: OTHER.privatePem });
  await writeFile(join(G, 'pending.json'), `${JSON.stringify({ _type: 'scopehaven-ledger-pending/2', line: last.line, intent: intentG, envelope: envelopes[2].toString('base64') })}\n`, { mode: 0o600 });
  const pointsBefore = await readFile(join(G, 'checkpoints.jsonl'));
  const tidied = await recoverWithEvidence(G);
  assert.equal(tidied.code, 0, JSON.stringify(tidied.output)); assert.equal(tidied.output.treeSize, 3);
  assert.deepEqual(await readFile(join(G, 'checkpoints.jsonl')), pointsBefore, 'the checkpoint is not appended twice');
  assert.equal(existsSync(join(G, 'pending.json')), false);

  // A line written while recovery runs is refused too, and the pending write is kept.
  const H = await fresh(); await stop(H);
  const injectLine = async () => writeFile(join(H, 'entries.jsonl'), `${await forgeLine(H)}\n`, { flag: 'a' });
  await assert.rejects(checkpointLedger(H, { privateKey: OTHER.privatePem, evidenceKey: KEY.publicPem }, { afterVerify: injectLine }), /changed while this write was being prepared/);
  assert.ok(existsSync(join(H, 'pending.json'))); assert.equal(forgedCovered(await state(H)), false);

  // pending.json removed: the operator's own line is now unexplained too, and is not signed.
  const E = await fresh(); await stop(E); await rm(join(E, 'pending.json'));
  const refusedE = await recoverWithEvidence(E);
  assert.equal(refusedE.code, 2); assert.match(refusedE.output.error, /nothing shows this writer wrote them/);
  assert.equal((await state(E)).covered, 2);
});

test('a writer removes only its own lock, and a swapped envelopes folder is refused', async t => {
  const dir = await scratch(t); await initLedger(dir, { now: at(0) });
  await appendEnvelope(dir, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1) });
  // While this append runs, its lock is taken for a stale one and another writer's lock replaces it.
  await appendEnvelope(dir, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(2) }, {
    afterVerify: async () => { await rm(join(dir, '.lock')); await writeFile(join(dir, '.lock'), 'another writer\n'); } });
  assert.equal(await readFile(join(dir, '.lock'), 'utf8'), 'another writer\n', 'the other writer\'s lock is left alone');
  await rm(join(dir, '.lock'));
  // envelopes/ swapped for a symlink after it was checked: nothing is written outside the folder.
  const outside = await scratch(t);
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }, {
    beforeWrite: async () => { await rename(join(dir, 'envelopes'), join(dir, 'env.real')); await symlink(outside, join(dir, 'envelopes')); } }), /stopped part way/);
  assert.deepEqual(await readdir(outside), []);
});

test('the writer never records a run its verifiers cannot read back', async t => {
  const dir = await scratch(t); await initLedger(dir, { now: at(0) });
  for (const depth of [257, 300]) {
    const run = JSON.parse(exported[3]); run.integrity = { ...run.integrity, sha256: 'P'.repeat(64) };
    let text = JSON.stringify(run).replace(/^\{/, `{"deepField":${'['.repeat(depth)}1${']'.repeat(depth)},`);
    const { integrity, notes, ...core } = JSON.parse(text); text = text.replace('P'.repeat(64), digest(core));
    const content = Buffer.from(text), deepEnvelope = Buffer.from(signFiles([{ name: 'deep.json', content }], { privateKey: KEY.privatePem, version, now: at(1) }).envelope);
    await assert.rejects(appendEnvelope(dir, { envelope: deepEnvelope, files: new Map([['deep.json', content]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(2) }), /verifiers can read back/, `nested ${depth}`);
  }
  assert.equal((await readFile(join(dir, 'entries.jsonl'))).length, 0);
});

test('append and recovery sign the bytes they verified, even if the folder changes and changes back', async t => {
  const dir = await scratch(t); await initLedger(dir, { now: at(0) });
  await appendEnvelope(dir, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1) });
  const entriesFile = join(dir, 'entries.jsonl');
  const changeAndRestore = bytes => ({ afterVerify: () => writeFile(entriesFile, Buffer.concat([bytes, Buffer.from(`${linesOf(bytes).at(-1)}\n`)])), afterSign: () => writeFile(entriesFile, bytes) });
  await appendEnvelope(dir, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(2) }, changeAndRestore(await readFile(entriesFile)));
  let result = verifyNode(await readLedgerFiles(dir));
  assert.equal(result.verdict, 'verified', result.detail); assert.equal(result.covered, 2);
  const own = await appendEnvelope(dir, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, now: at(3) });
  await checkpointLedger(dir, { privateKey: KEY.privatePem, expectedTail: [own.lineSha256], now: at(4) }, changeAndRestore(await readFile(entriesFile)));
  result = verifyNode(await readLedgerFiles(dir));
  assert.equal(result.verdict, 'verified', result.detail); assert.equal(result.covered, 3); assert.equal(result.unsignedTail, 0);
  // envelopes/ replaced after its check: by another folder (reported), or by a symlink (refused, nothing left outside).
  await assert.rejects(appendEnvelope(dir, { envelope: envelopes[3], files: files[3], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(5) }, {
    beforeEnvelope: async () => { await rename(join(dir, 'envelopes'), join(dir, 'env.real')); await mkdir(join(dir, 'envelopes'), { mode: 0o700 }); } }), /envelopes\/ was replaced/);
  const other = await scratch(t); await initLedger(other, { now: at(0) });
  const outside = await scratch(t);
  await assert.rejects(appendEnvelope(other, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1) }, {
    beforeEnvelope: async () => { await rename(join(other, 'envelopes'), join(other, 'env.real')); await symlink(outside, join(other, 'envelopes')); } }), /envelopes\/ was replaced/);
  assert.deepEqual(await readdir(outside), []);
});

test('a write stopped between pending.json and the envelope copy is finished, and pending advice is specific', async t => {
  const fresh = async () => {
    const dir = await scratch(t); await initLedger(dir, { now: at(0) });
    for (const i of [0, 1]) await appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
    return dir;
  };
  const crash = () => { throw new Error('stopped before the envelope copy'); };
  const stopBeforeEnvelope = dir => assert.rejects(appendEnvelope(dir, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }, { beforeEnvelope: crash }), /stopped part way/);
  const digest2 = sha(envelopes[2]);
  // Stopped after pending.json, before the envelope copy: recovery writes the copy, the line and the checkpoint.
  const A = await fresh(); await stopBeforeEnvelope(A);
  assert.equal(existsSync(join(A, 'envelopes', `${digest2}.json`)), false);
  const finished = await checkpointLedger(A, { privateKey: KEY.privatePem, now: at(4) });
  assert.equal(finished.finished, true); assert.equal(finished.treeSize, 3);
  assert.deepEqual(await readFile(join(A, 'envelopes', `${digest2}.json`)), envelopes[2]);
  let result = verifyNode(await readLedgerFiles(A)); assert.equal(result.verdict, 'verified', result.detail); assert.equal(result.covered, 3);
  const strays = dir => [...readdirSync(dir), ...readdirSync(join(dir, 'envelopes'))].filter(n => n.startsWith('.'));
  assert.deepEqual(strays(A), [], 'no temporary files are left after a finished write');
  await appendEnvelope(A, { envelope: envelopes[3], files: files[3], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(5) });
  assert.deepEqual(strays(A), []);
  // A stray copy at that digest with other bytes (as a crash in an older writer could leave) is replaced.
  const B = await fresh(); await stopBeforeEnvelope(B);
  await writeFile(join(B, 'envelopes', `${digest2}.json`), envelopes[2].subarray(0, 100), { mode: 0o600 });
  assert.equal((await checkpointLedger(B, { privateKey: KEY.privatePem, now: at(4) })).treeSize, 3);
  assert.deepEqual(await readFile(join(B, 'envelopes', `${digest2}.json`)), envelopes[2]);
  // A change during recovery's own writes is detected after them, and the pending write is kept.
  const C = await fresh(); await stopBeforeEnvelope(C);
  const extra = async () => writeFile(join(C, 'checkpoints.jsonl'), `${linesOf(await readFile(join(C, 'checkpoints.jsonl'))).at(-1)}\n`, { flag: 'a' });
  await assert.rejects(checkpointLedger(C, { privateKey: KEY.privatePem, now: at(4) }, { afterWrite: extra }), /changed during this write/);
  assert.ok(existsSync(join(C, 'pending.json')));
  // An unreadable pending.json: nothing depends on it when the ledger verifies on its own.
  const D = await fresh(); await writeFile(join(D, 'pending.json'), '{"_type":"scopehaven-ledger-pending/1","line":"', { mode: 0o600 });
  await assert.rejects(appendEnvelope(D, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }), /pending\.json exists/);
  await assert.rejects(checkpointLedger(D, { privateKey: KEY.privatePem, now: at(4) }), /not a whole pending record.*nothing in this folder depends on pending\.json: delete it/s);
  // ... and with unsigned lines after the last checkpoint, the advice is to remove those lines.
  const own = await appendEnvelope(D, { envelope: envelopes[3], files: files[3], evidenceKey: KEY.publicPem, now: at(5) }).catch(e => e);
  assert.match(String(own.message), /pending\.json exists/, 'no append, signed or not, while pending.json exists');
  const garbage = await readFile(join(D, 'pending.json')); await rm(join(D, 'pending.json'));
  await appendEnvelope(D, { envelope: envelopes[3], files: files[3], evidenceKey: KEY.publicPem, now: at(5) });
  await writeFile(join(D, 'pending.json'), garbage, { mode: 0o600 });
  await assert.rejects(checkpointLedger(D, { privateKey: KEY.privatePem, now: at(6) }), /no checkpoint in this folder covers the 1 lines after it.*compare with the last checkpoint you or an auditor hold.*Otherwise remove those lines/s);
  // A stale pending.json: the ledger moved on without it. Advice: delete it.
  const E = await fresh(); await stopBeforeEnvelope(E);
  const stale = await readFile(join(E, 'pending.json')); await rm(join(E, 'pending.json'));
  await appendEnvelope(E, { envelope: envelopes[3], files: files[3], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(5) });
  await writeFile(join(E, 'pending.json'), stale, { mode: 0o600 });
  await assert.rejects(checkpointLedger(E, { privateKey: KEY.privatePem, now: at(6) }), /does not match the pending write.*nothing in this folder depends on pending\.json: delete it/s);
  result = verifyNode(await readLedgerFiles(E)); assert.equal(result.verdict, 'verified'); assert.equal(result.covered, 3);
});

test('a CLI append killed at any point leaves only whole files, and the documented recovery finishes it', async t => {
  const keys = await scratch(t), evidence = await scratch(t);
  await writeFile(join(keys, 'key.pem'), KEY.privatePem, { mode: 0o600 }); await writeFile(join(keys, 'pub.pem'), KEY.publicPem);
  const cli = fileURLToPath(new URL('./cli.mjs', import.meta.url));
  const triggers = {
    'pending temp': dir => readdirSync(dir).some(n => n.startsWith('.pending.json.')),
    pending: dir => existsSync(join(dir, 'pending.json')),
    'envelope temp or copy': (dir, env0) => readdirSync(join(dir, 'envelopes')).some(n => !env0.has(n)),
    entries: (dir, env0, e0) => statSync(join(dir, 'entries.jsonl')).size > e0,
    checkpoints: (dir, env0, e0, c0) => statSync(join(dir, 'checkpoints.jsonl')).size > c0,
  };
  for (const [name, hit] of Object.entries(triggers)) for (let attempt = 0; attempt < 2; attempt++) {
    const dir = await scratch(t); await initLedger(dir, { now: at(0) });
    for (const i of [0, 1]) await appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
    await writeFile(join(evidence, 'run-2.json'), exported[2]); await writeFile(join(evidence, 'e.json'), envelopes[2]);
    const env0 = new Set(readdirSync(join(dir, 'envelopes'))), e0 = statSync(join(dir, 'entries.jsonl')).size, c0 = statSync(join(dir, 'checkpoints.jsonl')).size;
    const child = spawn(process.execPath, [cli, 'append', '--ledger', dir, '--key', join(keys, 'key.pem'), '--evidence-key', join(keys, 'pub.pem'), '--envelope', join(evidence, 'e.json'), '--dir', evidence], { stdio: 'ignore' });
    const exited = new Promise(resolve => child.on('exit', resolve));
    const t0 = Date.now();
    while (child.exitCode === null && Date.now() - t0 < 20000) { if (hit(dir, env0, e0, c0)) { child.kill('SIGKILL'); break; } await new Promise(r => setImmediate(r)); }
    await exited;
    // Whatever is in place is whole: pending.json parses, and every envelope copy matches its name.
    if (existsSync(join(dir, 'pending.json'))) JSON.parse(await readFile(join(dir, 'pending.json'), 'utf8'));
    for (const file of readdirSync(join(dir, 'envelopes')).filter(n => /^[0-9a-f]{64}\.json$/.test(n))) assert.equal(sha(await readFile(join(dir, 'envelopes', file))), file.slice(0, 64), `${name} #${attempt}`);
    await rm(join(dir, '.lock'), { force: true });
    const hadPending = existsSync(join(dir, 'pending.json'));
    const recovered = await main(['checkpoint', '--ledger', dir, '--key', join(keys, 'key.pem')]);
    if (hadPending) assert.equal(recovered.code, 0, `${name} #${attempt}: ${JSON.stringify(recovered.output)}`);
    const result = verifyNode(await readLedgerFiles(dir));
    assert.equal(result.verdict, 'verified', `${name} #${attempt}: ${result.detail}`); assert.equal(result.unsignedTail, 0);
    assert.equal(existsSync(join(dir, 'pending.json')), false);
    assert.ok(result.covered === 3 || (result.covered === 2 && !hadPending), `${name} #${attempt}: covered ${result.covered}`);
  }
});

test('advice never calls a line unsigned just because this folder lost its checkpoint', async t => {
  const dir = await scratch(t); await initLedger(dir, { now: at(0) });
  for (const i of [0, 1, 2]) await appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
  const points = linesOf(await readFile(join(dir, 'checkpoints.jsonl')));
  // A reader holds the last head; someone who can write the folder deletes that checkpoint line.
  await writeFile(join(dir, 'checkpoints.jsonl'), text(points.slice(0, -1)));
  assert.equal(verifyNode(await readLedgerFiles(dir)).unsignedTail, 1);
  const forkSafe = message => {
    assert.match(message, /no checkpoint in this folder covers/, message);
    assert.match(message, /compare with the last checkpoint you or an auditor hold: if it covers more than 2 entries.*restore checkpoints\.jsonl and entries\.jsonl.*\(a fork\)/s, message);
    assert.doesNotMatch(message, /no one signed|signed by no one/, message);
  };
  const append = await appendEnvelope(dir, { envelope: envelopes[3], files: files[3], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(5) }).catch(e => e);
  forkSafe(append.message);
  forkSafe((await checkpointLedger(dir, { privateKey: KEY.privatePem, now: at(5) }).catch(e => e)).message);
  await writeFile(join(dir, 'pending.json'), 'not a pending record\n', { mode: 0o600 });
  forkSafe((await checkpointLedger(dir, { privateKey: KEY.privatePem, now: at(5) }).catch(e => e)).message);
  // Restoring checkpoints.jsonl, as the advice says when a held head covers more, verifies with nothing lost.
  await rm(join(dir, 'pending.json')); await writeFile(join(dir, 'checkpoints.jsonl'), text(points));
  const restored = verifyNode(await readLedgerFiles(dir)); assert.equal(restored.covered, 3); assert.equal(restored.unsignedTail, 0);
  // Even with every entry covered, advice to delete pending.json and append again carries the same check.
  await writeFile(join(dir, 'pending.json'), 'not a pending record\n', { mode: 0o600 });
  assert.match((await checkpointLedger(dir, { privateKey: KEY.privatePem, now: at(5) }).catch(e => e)).message, /nothing in this folder depends on pending\.json.*if it covers more than 3 entries/s);
});

test('stray copies and temporary files never block a write, and odd file types get advice', async t => {
  const fresh = async () => {
    const dir = await scratch(t); await initLedger(dir, { now: at(0) });
    for (const i of [0, 1]) await appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
    return dir;
  };
  const digest2 = sha(envelopes[2]);
  const append2 = (dir, hooks) => appendEnvelope(dir, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }, hooks);
  // A stray copy already at the digest of the envelope being appended is replaced.
  const A = await fresh();
  await writeFile(join(A, 'envelopes', `${digest2}.json`), 'torn', { mode: 0o600 });
  await append2(A);
  assert.deepEqual(await readFile(join(A, 'envelopes', `${digest2}.json`)), envelopes[2]);
  // Stopped after the entry line, before its checkpoint; the copy is then damaged. Recovery replaces it and finishes.
  const B = await fresh();
  await assert.rejects(append2(B, { beforeWrite: async () => { await rename(join(B, 'checkpoints.jsonl'), join(B, 'cp.real')); await symlink(join(B, 'cp.real'), join(B, 'checkpoints.jsonl')); } }), /stopped part way/);
  await rm(join(B, 'checkpoints.jsonl')); await rename(join(B, 'cp.real'), join(B, 'checkpoints.jsonl'));
  assert.equal(linesOf(await readFile(join(B, 'entries.jsonl'))).length, 3, 'the entry line was written');
  await writeFile(join(B, 'envelopes', `${digest2}.json`), 'torn', { mode: 0o600 });
  assert.equal((await checkpointLedger(B, { privateKey: KEY.privatePem, now: at(4) })).treeSize, 3);
  assert.deepEqual(await readFile(join(B, 'envelopes', `${digest2}.json`)), envelopes[2]);
  assert.equal(verifyNode(await readLedgerFiles(B)).covered, 3);
  // Stray temporary files, one holding a whole pending record, are removed by the next write under the lock.
  const C = await fresh();
  await writeFile(join(C, `.pending.json.${randomUUID()}.tmp`), '{"_type":"scopehaven-ledger-pending/1"}\n', { mode: 0o600 });
  await writeFile(join(C, 'envelopes', `.${digest2}.${randomUUID()}.tmp`), 'partial', { mode: 0o600 });
  await append2(C);
  assert.deepEqual([...readdirSync(C), ...readdirSync(join(C, 'envelopes'))].filter(n => n.startsWith('.')), []);
  // A symlink at the copy's name, or at pending.json, is refused with advice rather than a bare ELOOP.
  const D = await fresh(), elsewhere = join(await scratch(t), 'x.json');
  await writeFile(elsewhere, 'x'); await symlink(elsewhere, join(D, 'envelopes', `${digest2}.json`));
  await assert.rejects(append2(D), /envelopes\/[0-9a-f]{64}\.json is a symlink, a folder or too large.*remove it/s);
  const E = await fresh(); await symlink(elsewhere, join(E, 'pending.json'));
  await assert.rejects(checkpointLedger(E, { privateKey: KEY.privatePem, now: at(4) }), /pending\.json is a symlink, a folder or too large/);
});

test('pending.json holds a signed intent, never a checkpoint: an abandoned one is no second head', async t => {
  const fresh = async () => {
    const dir = await scratch(t); await initLedger(dir, { now: at(0) });
    for (const i of [0, 1]) await appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
    return dir;
  };
  const stopBeforeEnvelope = dir => assert.rejects(appendEnvelope(dir, { envelope: envelopes[2], files: files[2], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3) }, { beforeEnvelope: () => { throw new Error('stopped'); } }), /stopped part way/);
  const keys = await scratch(t); await writeFile(join(keys, 'pub.pem'), KEY.publicPem);
  const bothVerdicts = async (dir, label) => {
    const node = verifyNode(await readLedgerFiles(dir));
    if (!PYTHON) return [node.verdict, node.reason];
    const { stdout } = await python([SCRIPT, 'log', '--key', join(keys, 'pub.pem'), '--ledger', dir]); const py = JSON.parse(stdout);
    assert.deepEqual([py.verdict, py.reason], [node.verdict, node.reason], `${label}: Node and Python agree`);
    return [node.verdict, node.reason];
  };
  // An abandoned write: its intent is signed, but it is not a checkpoint, as is or relabelled as one.
  const A = await fresh(); await stopBeforeEnvelope(A);
  const intent = JSON.parse(await readFile(join(A, 'pending.json'), 'utf8')).intent;
  assert.equal(JSON.parse(intent).payloadType, 'application/vnd.scopehaven.ledger-intent+json');
  const B = await fresh(); const kept = await readFile(join(B, 'checkpoints.jsonl'));
  await writeFile(join(B, 'checkpoints.jsonl'), Buffer.concat([kept, Buffer.from(`${intent}\n`)]));
  assert.deepEqual(await bothVerdicts(B, 'intent as a checkpoint line'), ['rejected', 'checkpoint-shape']);
  const relabelled = JSON.stringify({ ...JSON.parse(intent), payloadType: 'application/vnd.scopehaven.ledger-checkpoint+json' });
  await writeFile(join(B, 'checkpoints.jsonl'), Buffer.concat([kept, Buffer.from(`${relabelled}\n`)]));
  assert.equal((await bothVerdicts(B, 'intent relabelled as a checkpoint'))[0], 'rejected');
  const older = linesOf(kept).at(-1);
  assert.equal(verifyConsistency({ older, newer: intent, proof: { _type: 'scopehaven-ledger-consistency/1', log: JSON.parse(Buffer.from(JSON.parse(older).payload, 'base64')).log, from: 2, to: 3, path: [] }, ledgerKey: KEY.publicPem }).verdict, 'rejected');
  // Recovery signs exactly the checkpoint the intent fixes: byte for byte what a fresh signing gives.
  const finished = await checkpointLedger(A, { privateKey: KEY.privatePem, now: at(9) });
  const meta = JSON.parse(await readFile(join(A, 'ledger.json'), 'utf8')), lines = linesOf(await readFile(join(A, 'entries.jsonl')));
  assert.equal(finished.line, signCheckpoint({ log: meta.log, createdAt: meta.createdAt, lines, signedAt: JSON.parse(lines.at(-1)).recordedAt, privateKey: KEY.privatePem }));
  assert.equal(finished.signedAt, JSON.parse(lines.at(-1)).recordedAt, 'the time comes from the intent, not the clock at recovery');
  // An intent signed by another key, or for another log, is refused.
  for (const [label, swap] of [
    ['another key', async (dir, record) => ({ ...record, intent: signIntent({ log: meta.log, createdAt: meta.createdAt, lines: [...linesOf(await readFile(join(dir, 'entries.jsonl'))), record.line], signedAt: JSON.parse(record.line).recordedAt, privateKey: OTHER.privatePem }) })],
    ['another log', async (dir, record) => ({ ...record, intent: signIntent({ log: randomUUID(), createdAt: meta.createdAt, lines: [...linesOf(await readFile(join(dir, 'entries.jsonl'))), record.line], signedAt: JSON.parse(record.line).recordedAt, privateKey: KEY.privatePem }) })]]) {
    const C = await fresh(); await stopBeforeEnvelope(C);
    const record = JSON.parse(await readFile(join(C, 'pending.json'), 'utf8'));
    await writeFile(join(C, 'pending.json'), `${JSON.stringify(await swap(C, record))}\n`, { mode: 0o600 });
    await assert.rejects(checkpointLedger(C, { privateKey: KEY.privatePem, now: at(9) }), /no intent signed by this ledger key for this log/, label);
  }
  // Someone without the key writes a forged line and a matching intent under the operator's keyid,
  // signed by another key: recovery checks the signature itself, so it never signs the forgery.
  const F = await fresh(); await stopBeforeEnvelope(F);
  const record = JSON.parse(await readFile(join(F, 'pending.json'), 'utf8')), entriesF = linesOf(await readFile(join(F, 'entries.jsonl')));
  const forgedEnv = Buffer.from(signFiles([{ name: 'run-extra.json', content: EXTRA }], { privateKey: KEY.privatePem, version, now: at(2.6) }).envelope), extraFiles = new Map([['run-extra.json', EXTRA]]);
  const forgedEntry = buildEntry({ previousLine: entriesF.at(-1), index: entriesF.length, recordedAt: at(2.7).toISOString(), envelope: forgedEnv, check: verifyEnvelope({ envelope: forgedEnv, publicKey: KEY.publicPem, files: extraFiles }), files: extraFiles });
  const forgedLine = JSON.stringify(forgedEntry);
  const otherSigned = JSON.parse(signIntent({ log: meta.log, createdAt: meta.createdAt, lines: [...entriesF, forgedLine], signedAt: forgedEntry.recordedAt, privateKey: OTHER.privatePem }));
  otherSigned.signatures[0].keyid = JSON.parse(record.intent).signatures[0].keyid;
  await writeFile(join(F, 'pending.json'), `${JSON.stringify({ ...record, line: forgedLine, intent: JSON.stringify(otherSigned), envelope: forgedEnv.toString('base64') })}\n`, { mode: 0o600 });
  await assert.rejects(checkpointLedger(F, { privateKey: KEY.privatePem, now: at(9) }), /no intent signed by this ledger key for this log/);
  assert.equal(linesOf(await readFile(join(F, 'entries.jsonl'))).length, 2, 'the forged line was not written');
});
