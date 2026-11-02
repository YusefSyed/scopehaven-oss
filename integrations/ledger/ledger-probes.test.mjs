// Edge probes (K01-K25), kept as tests: each input has one expected outcome, and the Node and Python
// verifiers must both give it. Also: parity inputs (integral floats in proofs,
// deep nesting), signed ledger metadata, canonical checkpoint lines and verdicts checked against run files.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { createHash, createPrivateKey, sign as rawSign } from 'node:crypto';
import { runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { exportRun } from '../../src/export-cli.mjs';
import { generateSigningKey, signFiles } from '../attest/sign.mjs';
import * as L from './ledger.mjs';
import * as V from './verify.mjs';
import { anchorFor } from './anchors.mjs';
import { verifyEnvelope } from '../attest/verify.mjs';

const PYTHON = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3', '/opt/homebrew/bin/python3', '/usr/bin/python3'].find(path => existsSync(path));
const SCRIPT = fileURLToPath(new URL('./verify_ledger.py', import.meta.url));
const python = args => new Promise(res => execFile(PYTHON, ['-B', ...args], { maxBuffer: 64 << 20, timeout: 120000 }, (e, stdout, stderr) => res({ code: e ? (e.code ?? 'signal') : 0, stdout, stderr })));
const sha = b => createHash('sha256').update(b).digest('hex');
const at = m => new Date(Date.parse('2026-10-06T06:00:00.000Z') + m * 60000);
const work = await mkdtemp(join(tmpdir(), 'scopehaven ledger probes '));
process.on('exit', () => rmSync(work, { recursive: true, force: true }));
const dataDir = join(work, 'data'), ex = join(work, 'ex'); await mkdir(ex, { mode: 0o700 });
const store = createStore(dataDir), runs = [];
for (const t of ['demo-vulnerable', 'demo-repaired', 'demo-vulnerable', 'demo-repaired']) { const r = await runAssessment(t); await store.save(r); runs.push(r); }
const exported = []; for (const [i, r] of runs.entries()) { const f = join(ex, `run-${i}.json`); await exportRun({ runId: r.id, format: 'json', outputFile: f, dataDir }); exported.push(await readFile(f)); }
const files = exported.map((c, i) => new Map([[`run-${i}.json`, c]]));
const KEY = generateSigningKey(), OTHER = generateSigningKey();
const keyDir = join(work, 'k'); await mkdir(keyDir, { mode: 0o700 }); await writeFile(join(keyDir, 'KEY.pub'), KEY.publicPem);
const signRun = (i, m, key = KEY) => Buffer.from(signFiles([...files[i]].map(([name, content]) => ({ name, content })), { privateKey: key.privatePem, version: '1.0.0', now: at(m) }).envelope);
const envelopes = files.map((_, i) => signRun(i, i));
const linesOf = b => { const t = b.toString(); return t ? t.slice(0, -1).split('\n') : []; };
const text = list => Buffer.from(list.length ? `${list.join('\n')}\n` : '');
const rechain = list => { const o = []; list.forEach((e, i) => o.push(JSON.stringify({ ...e, index: i, prev: i ? V.leafHash(Buffer.from(o[i - 1])).toString('hex') : null }))); return o; };
const type = 'application/vnd.scopehaven.ledger-checkpoint+json';
const pae = (t, p) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(t)} ${t} ${p.length} `), p]);
const rawCheckpoint = (bodyObj, key = KEY) => { const payload = Buffer.from(JSON.stringify(bodyObj)); return JSON.stringify({ payloadType: type, payload: payload.toString('base64'), signatures: [{ keyid: KEY.keyid, sig: rawSign(null, pae(type, payload), createPrivateKey(key.privatePem)).toString('base64') }] }); };
const body = line => JSON.parse(Buffer.from(JSON.parse(line).payload, 'base64').toString());
async function newLedger(name) { const d = join(work, name); await mkdir(d, { mode: 0o700 }); await L.initLedger(d, { now: at(0) }); return d; }
const S = await newLedger('S'); for (const i of [0, 1, 2, 3]) await L.appendEnvelope(S, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
const SB = await L.readLedgerFiles(S), { log: SLOG, createdAt: SCREATED } = JSON.parse(SB.metadata), Sl = linesOf(SB.entries), SE = Sl.map(l => JSON.parse(l)), SP = linesOf(SB.checkpoints);
const B = await newLedger('B'); for (const i of [0, 1]) await L.appendEnvelope(B, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
const BP = linesOf((await L.readLedgerFiles(B)).checkpoints);
const resignAll = (lines, sizes, t0 = 10) => sizes.map((s, i) => L.signCheckpoint({ log: SLOG, createdAt: SCREATED, lines, treeSize: s, signedAt: at(t0 + i).toISOString(), privateKey: KEY.privatePem }));
const base = (change = {}) => ({ ...SB, envelopes: new Map(SB.envelopes), ...change });
const withRun0 = (e, f) => ({ ...e, runs: e.runs.map((r, i) => i ? r : f(r)) });
const resealed = (mapEntry, t0 = 10) => { const ls = rechain(SE.map(mapEntry)); return base({ entries: text(ls), checkpoints: text(resignAll(ls, [1, 2, 3, 4], t0)) }); };
const nested = depth => `${'['.repeat(depth)}1${']'.repeat(depth)}`;

async function viaBoth(files, { runFiles } = {}) {
  const d = await mkdtemp(join(work, 'c-')); await mkdir(join(d, 'envelopes'));
  await writeFile(join(d, 'ledger.json'), files.metadata); await writeFile(join(d, 'entries.jsonl'), files.entries); await writeFile(join(d, 'checkpoints.jsonl'), files.checkpoints);
  for (const [n, b] of files.envelopes) await writeFile(join(d, 'envelopes', `${n}.json`), b);
  const map = runFiles ? new Map(runFiles.map(b => [sha(b), b])) : undefined;
  const n = V.verifyLedger({ ...(await L.readLedgerFiles(d)), ledgerKey: KEY.publicPem, runFiles: map });
  if (!PYTHON) return { node: n, python: null };
  const args = [SCRIPT, 'log', '--key', join(keyDir, 'KEY.pub'), '--ledger', d];
  if (runFiles) { const rf = await mkdtemp(join(work, 'rf-')); for (const [i, b] of runFiles.entries()) await writeFile(join(rf, `f${i}.json`), b); args.push('--run-files', rf); }
  const p = await python(args);
  let py; try { py = JSON.parse(p.stdout); } catch { py = { verdict: `crash(${p.code})`, reason: p.stderr.trim().split('\n').at(-1) }; }
  return { node: n, python: py };
}
async function proofBoth(kind, inputs) {
  const d = await mkdtemp(join(work, 'q-')), args = [];
  for (const [k, v] of Object.entries(inputs)) { await writeFile(join(d, k), v); args.push(`--${k}`, join(d, k)); }
  let proof; try { proof = JSON.parse(inputs.proof); } catch { proof = null; }
  const n = kind === 'inclusion' ? V.verifyInclusion({ entryLine: inputs.entry, proof, checkpoint: inputs.checkpoint, ledgerKey: KEY.publicPem })
    : V.verifyConsistency({ older: inputs.older, newer: inputs.newer, proof, ledgerKey: KEY.publicPem });
  if (!PYTHON) return { node: n, python: null };
  const p = await python([SCRIPT, kind, '--key', join(keyDir, 'KEY.pub'), ...args]);
  let py; try { py = JSON.parse(p.stdout); } catch { py = { verdict: `crash(${p.code})`, reason: p.stderr.trim().split('\n').at(-1) }; }
  return { node: n, python: py };
}
const outcome = r => r.verdict === 'verified' ? 'verified' : r.reason;
const expectBoth = ({ node, python }, expected, label) => {
  assert.equal(outcome(node), expected, `node: ${label}: ${node.detail ?? ''}`);
  if (python) assert.equal(outcome(python), expected, `python: ${label}: ${python.detail ?? python.reason ?? ''}`);
};

const inc = L.inclusionProof({ log: SLOG, lines: Sl, index: 1, treeSize: 4 });
const LOG_CASES = [
  ['K00 baseline', () => base(), 'verified'],
  ['K01 checkpoint meaning changed (re-signed)', () => base({ checkpoints: text([...SP.slice(0, 3), rawCheckpoint({ ...body(SP[3]), meaning: 'Countersigned by an independent witness.' })]) }), 'checkpoint-shape'],
  ['K02 checkpoints go back in time only (re-signed)', () => base({ checkpoints: text([...resignAll(Sl, [2], 30), ...resignAll(Sl, [4], 20)]) }), 'checkpoint-regression'],
  ['K03 checkpoint rootHash wrong, headHash right (re-signed)', () => base({ checkpoints: text([...SP.slice(0, 3), rawCheckpoint({ ...body(SP[3]), rootHash: 'd'.repeat(64) })]) }), 'checkpoint-mismatch'],
  ['K04 older checkpoint from a forked history, latest matches', () => { const br = rechain([SE[0], { ...SE[1], recordedAt: at(1.75).toISOString() }, ...SE.slice(2)]); return base({ checkpoints: text([L.signCheckpoint({ log: SLOG, createdAt: SCREATED, lines: br, treeSize: 2, signedAt: at(2).toISOString(), privateKey: KEY.privatePem }), SP[3]]) }); }, 'checkpoint-mismatch'],
  ['K05 anchor count 0 with a head (resealed)', () => resealed((e, i) => i ? e : withRun0(e, r => ({ ...r, anchors: [{ source: 'sql-audit-table', custody: 'subject-writable', count: 0, head: 'c'.repeat(64) }] }))), 'entry-shape'],
  ['K06 anchor source twice (resealed)', () => resealed((e, i) => i ? e : withRun0(e, r => ({ ...r, anchors: [1, 2].map(n => ({ source: 'sql-audit-table', custody: 'subject-writable', count: n, head: String(n).repeat(64) })) }))), 'entry-shape'],
  ['K07 duplicate check id in verdicts (resealed)', () => resealed((e, i) => i ? e : withRun0(e, r => { const verdicts = [...r.verdicts, [r.verdicts[0][0], 'pass']]; return { ...r, verdicts, verdictDigest: sha(JSON.stringify(verdicts)) }; })), 'entry-shape'],
  ['K08 run identity with a non-scalar (resealed)', () => resealed((e, i) => i ? e : withRun0(e, r => ({ ...r, build: ['x'] }))), 'entry-shape'],
  ['K09 checkpoint sig base64 with non-zero pad bits', () => base({ checkpoints: text([...SP.slice(0, 3), (() => { const env = JSON.parse(SP[3]); const s = env.signatures[0].sig, i = s.indexOf('='), A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'; env.signatures[0].sig = s.slice(0, i - 1) + A[A.indexOf(s[i - 1]) ^ 1] + s.slice(i); return JSON.stringify(env); })()]) }), 'checkpoint-shape'],
  ['K12 recordedAt 2026-11-31 (rolls over in JS), resealed', () => resealed((e, i) => i === 3 ? { ...e, recordedAt: '2026-11-31T00:00:00.000Z' } : e, 60 * 24 * 90), 'entry-shape'],
  ['K13 anchor source of 129 ASCII chars (resealed)', () => resealed((e, i) => i ? e : withRun0(e, r => ({ ...r, anchors: [{ source: 'a'.repeat(129), custody: 'subject-writable', count: 1, head: 'c'.repeat(64) }] }))), 'entry-shape'],
  ['K14 anchor source of 65 astral chars (resealed)', () => resealed((e, i) => i ? e : withRun0(e, r => ({ ...r, anchors: [{ source: '\u{1F600}'.repeat(65), custody: 'subject-writable', count: 1, head: 'c'.repeat(64) }] }))), 'entry-shape'],
  ['K18 checkpoint signature of 63 bytes', () => base({ checkpoints: text([...SP.slice(0, 3), (() => { const env = JSON.parse(SP[3]); env.signatures[0].sig = Buffer.from(env.signatures[0].sig, 'base64').subarray(0, 63).toString('base64'); return JSON.stringify(env); })()]) }), 'checkpoint-signature'],
  ['K19 envelope forged by another key under the evidence keyid (resealed)', () => {
    const env = JSON.parse(envelopes[0]), payload = Buffer.from(env.payload, 'base64');
    const forged = Buffer.from(JSON.stringify({ ...env, signatures: [{ keyid: env.signatures[0].keyid, sig: rawSign(null, pae(env.payloadType, payload), createPrivateKey(OTHER.privatePem)).toString('base64') }] }));
    const v = resealed((e, i) => i ? e : { ...e, envelope: { ...e.envelope, sha256: sha(forged) } }); v.envelopes.set(sha(forged), forged); return v;
  }, 'envelope-invalid'],
  ['one entry recording the same run twice (resealed)', () => resealed((e, i) => i ? e : { ...e, runs: [e.runs[0], e.runs[0]] }), 'entry-shape'],
  ['a second checkpoint at one size: same root, different head (re-signed)', () => base({ checkpoints: text([...SP, rawCheckpoint({ ...body(SP[3]), headHash: 'e'.repeat(64), signedAt: at(9).toISOString() })]) }), 'fork'],
  ['a run with its id removed (resealed)', () => resealed((e, i) => i ? e : withRun0(e, ({ id, ...r }) => r)), 'entry-shape'],
  ['K21 entries file without its final newline', () => base({ entries: SB.entries.subarray(0, SB.entries.length - 1) }), 'entry-shape'],
  ['ledger.json creation time moved back', () => base({ metadata: Buffer.from(`${JSON.stringify({ ...JSON.parse(SB.metadata), createdAt: '2001-01-01T00:00:00.000Z' })}\n`) }), 'ledger-mismatch'],
  ['checkpoint line with spacing', () => base({ checkpoints: text([...SP.slice(0, 3), JSON.stringify(JSON.parse(SP[3]), null, 1).replace(/\n/g, '')]) }), 'checkpoint-shape'],
  ['checkpoint line nested 100,000 deep', () => base({ checkpoints: text([...SP, nested(100000)]) }), 'checkpoint-shape'],
  ['a replayed run, chain rebuilt and re-signed', () => {
    const again = signRun(1, 3.6);
    const entry = L.buildEntry({ previousLine: null, index: 0, recordedAt: at(3.7).toISOString(), envelope: again, check: verifyEnvelope({ envelope: again, publicKey: KEY.publicPem, files: files[1] }), files: files[1] });
    const ls = rechain([...SE, entry]);
    const v = base({ entries: text(ls), checkpoints: text(resignAll(ls, [1, 2, 3, 4, 5])) }); v.envelopes.set(sha(again), again); return v;
  }, 'run-replayed'],
];

test('every K probe gets its expected outcome from both verifiers', async () => {
  for (const [label, make, expected] of LOG_CASES) expectBoth(await viaBoth(make()), expected, label);
});

test('the depth limit counts brackets outside strings only, the same way in both verifiers', async () => {
  const cases = [['"' + '['.repeat(300) + '"', false], ['"\\"' + '['.repeat(300) + '"', false], ['["\\\\"' + ',['.repeat(300), true], ['['.repeat(256), false], ['['.repeat(257), true], ['{"a":'.repeat(257), true]];
  for (const [input, deep] of cases) assert.equal(V.tooDeep(input), deep, `Node: ${input.slice(0, 12)}`);
  if (!PYTHON) return;
  const program = `import json, sys; sys.path.insert(0, ${JSON.stringify(dirname(SCRIPT))}); import verify_ledger as v; print(json.dumps([v.too_deep(t) for t in json.load(sys.stdin)]))`;
  const p = await new Promise(res => { const c = execFile(PYTHON, ['-B', '-c', program], (e, stdout, stderr) => res({ code: e ? e.code : 0, stdout, stderr })); c.stdin.end(JSON.stringify(cases.map(([input]) => input))); });
  assert.equal(p.code, 0, p.stderr); assert.deepEqual(JSON.parse(p.stdout), cases.map(([, deep]) => deep), 'Python');
});

test('K20: an unsigned tail is reported, not hidden, and stays out of history', async () => {
  const U = await newLedger('U');
  await L.appendEnvelope(U, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1) });
  await L.appendEnvelope(U, { envelope: envelopes[1], files: files[1], evidenceKey: KEY.publicPem, now: at(2) });
  const r = await viaBoth(await L.readLedgerFiles(U));
  expectBoth(r, 'verified', 'K20');
  assert.equal(r.node.unsignedTail, 1); if (r.python) assert.equal(r.python.unsignedTail, 1);
});

test('proof probes and the number and nesting cases agree in both verifiers', async () => {
  const PROOFS = [
    ['K10 inclusion proof labelled with another log', 'inclusion', { entry: Sl[1], proof: JSON.stringify({ ...inc, log: '00000000-0000-4000-8000-000000000000' }), checkpoint: SP[3] }, 'inclusion-proof-invalid'],
    ['K11 consistency from log S to log B, identical prefix', 'consistency', { older: SP[0], newer: BP[1], proof: JSON.stringify(L.consistencyProof({ log: SLOG, lines: Sl, from: 1, to: 2 })) }, 'checkpoint-shape'],
    ['K15 inclusion path with one extra element', 'inclusion', { entry: Sl[1], proof: JSON.stringify({ ...inc, path: [...inc.path, 'e'.repeat(64)] }), checkpoint: SP[3] }, 'inclusion-proof-invalid'],
    ['K16 inclusion path one element short', 'inclusion', { entry: Sl[1], proof: JSON.stringify({ ...inc, path: inc.path.slice(0, -1) }), checkpoint: SP[3] }, 'inclusion-proof-invalid'],
    ['K25 inclusion of an entry line with index -1', 'inclusion', { entry: JSON.stringify({ ...SE[1], index: -1 }), proof: JSON.stringify({ ...inc, index: -1 }), checkpoint: SP[3] }, 'entry-shape'],
    ['inclusion with index 1.0 and treeSize 4e0', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"index":1', '"index":1.0').replace('"treeSize":4', '"treeSize":4e0'), checkpoint: SP[3] }, 'verified'],
    ['consistency with from 2.0', 'consistency', { older: SP[1], newer: SP[3], proof: JSON.stringify(L.consistencyProof({ log: SLOG, lines: Sl, from: 2, to: 4 })).replace('"from":2', '"from":2.0') }, 'verified'],
    ['a valid proof padded past 64 KB with whitespace', 'inclusion', { entry: Sl[1], proof: `${JSON.stringify(inc)}${' '.repeat(70000)}`, checkpoint: SP[3] }, 'verified'],
    ['proof file nested 100,000 deep', 'inclusion', { entry: Sl[1], proof: nested(100000), checkpoint: SP[3] }, 'inclusion-proof-invalid'],
    ['checkpoint file nested 100,000 deep', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc), checkpoint: nested(100000) }, 'checkpoint-shape'],
  ];
  for (const [label, kind, inputs, expected] of PROOFS) expectBoth(await proofBoth(kind, inputs), expected, label);
  // K17: the auditor holds an earlier head; the operator rewrote entry 1, re-signed, and offers a proof from the rewritten log.
  const ls = rechain(SE.map((e, i) => i === 1 ? withRun0(e, r => { const verdicts = r.verdicts.map(([id, s]) => [id, id === 'TENANT-01' ? 'fail' : s]); return { ...r, verdicts, verdictDigest: sha(JSON.stringify(verdicts)) }; }) : e));
  const newer = L.signCheckpoint({ log: SLOG, createdAt: SCREATED, lines: ls, treeSize: 4, signedAt: at(10).toISOString(), privateKey: KEY.privatePem });
  for (const [older, from, label] of [[SP[2], 3, 'K17 saved size-3 head'], [SP[1], 2, 'K17b saved size-2 head']]) {
    expectBoth(await proofBoth('consistency', { older, newer, proof: JSON.stringify(L.consistencyProof({ log: SLOG, lines: ls, from, to: 4 })) }), 'consistency-proof-invalid', label);
  }
});

test('K23: the exported consistency path check refuses equal sizes with different roots', async () => {
  assert.equal(V.verifyConsistencyPath(4, 4, [], Buffer.alloc(32, 1), Buffer.alloc(32, 2)), false);
  if (!PYTHON) return;
  const p = await python(['-c', `import sys; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))}); import verify_ledger as v; print(v.verify_consistency_path(4, 4, [], bytes(32*[1]), bytes(32*[2])))`]);
  assert.equal(p.stdout.trim(), 'False');
});

test('K24: a run id is recorded once, so its anchor can be neither superseded nor replayed', async () => {
  const A = await newLedger('A');
  await L.appendEnvelope(A, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1), anchors: new Map([['run-0.json', [{ source: 'sql-audit-table', count: 3, head: '3'.repeat(64) }]]]) });
  await assert.rejects(L.appendEnvelope(A, { envelope: signRun(0, 2), files: files[0], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3), anchors: new Map([['run-0.json', [{ source: 'sql-audit-table', count: 2, head: '2'.repeat(64) }]]]) }), /already in the ledger/);
  const v = V.verifyLedger({ ...(await L.readLedgerFiles(A)), ledgerKey: KEY.publicPem });
  assert.equal(v.verdict, 'verified'); assert.equal(anchorFor(v, { runId: runs[0].id, source: 'sql-audit-table' }).count, 3);
  assert.equal(anchorFor(v, { runId: runs[0].id, source: 'sql-audit-table' }).heldBy, 'operator');
  // A hand-made result with two anchors for one run: refused rather than choosing one.
  const two = { ...v, entries: [...v.entries, { ...v.entries[0], index: 1 }] };
  assert.throws(() => anchorFor(two, { runId: runs[0].id, source: 'sql-audit-table' }), /refusing to choose/);
});

test('with the signed run files, recorded verdicts are checked against them in both verifiers', async () => {
  // The ledger-key holder rewrites a verdict, rebuilds the chain and re-signs every checkpoint.
  const forged = resealed((e, i) => i !== 1 ? e : withRun0(e, r => { const verdicts = r.verdicts.map(([id, s]) => [id, id === 'TENANT-01' ? 'fail' : s]); return { ...r, verdicts, verdictDigest: sha(JSON.stringify(verdicts)) }; }));
  expectBoth(await viaBoth(forged), 'verified', 'without the run files, the ledger key alone vouches for verdicts');
  expectBoth(await viaBoth(forged, { runFiles: exported }), 'verdict-mismatch', 'with the run files');
  const honest = await viaBoth(base(), { runFiles: exported });
  expectBoth(honest, 'verified', 'honest ledger with its run files');
  assert.equal(honest.node.verdictsCheckedAgainstRunFiles, 4); assert.equal(honest.node.runs, 4);
  if (honest.python) assert.equal(honest.python.verdictsCheckedAgainstRunFiles, 4);
  const some = await viaBoth(base(), { runFiles: exported.slice(0, 2) });
  assert.equal(some.node.verdictsCheckedAgainstRunFiles, 2, 'files not supplied are counted as unchecked, never as checked');
  if (some.python) assert.equal(some.python.verdictsCheckedAgainstRunFiles, 2, 'Python: files not supplied are counted as unchecked, never as checked');
});

test('the writer refuses an envelopes folder that is a symlink or not private', async () => {
  const { symlink, rm, chmod } = await import('node:fs/promises');
  const W = await newLedger('W'); const outside = await mkdtemp(join(work, 'outside-'));
  await rm(join(W, 'envelopes'), { recursive: true }); await symlink(outside, join(W, 'envelopes'));
  await assert.rejects(L.appendEnvelope(W, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1) }), /private directory/);
  const W2 = await newLedger('W2'); await chmod(join(W2, 'envelopes'), 0o777);
  await assert.rejects(L.appendEnvelope(W2, { envelope: envelopes[0], files: files[0], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1) }), /private directory/);
});
