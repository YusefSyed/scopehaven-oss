// Edge probes (E00-E28 and P01-P14): Node and Python on encoding, number and shape edge inputs, writer-produced
// ledgers with large integers, run files the verifiers cannot read back, and proof inputs. Every row
// must get the same verdict, reason and exit code from both, and the stated outcomes must hold.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile, chmod, rm } from 'node:fs/promises';
import { existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { exportRun } from '../../src/export-cli.mjs';
import { stable } from '../../src/domain.mjs';
import { generateSigningKey, signFiles } from '../attest/sign.mjs';
import { verifyEnvelope } from '../attest/verify.mjs';
import * as L from './ledger.mjs';
import * as V from './verify.mjs';
import { main as cli } from './cli.mjs';
import { anchorFor } from './anchors.mjs';

const PY = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3', '/opt/homebrew/bin/python3', '/usr/bin/python3'].find(path => existsSync(path));
const SCRIPT = fileURLToPath(new URL('./verify_ledger.py', import.meta.url));
const CUSTODY_FILE = fileURLToPath(new URL('../evid-subject/custody.mjs', import.meta.url));
const { CUSTODY_BY_SOURCE } = existsSync(CUSTODY_FILE) ? await import('../evid-subject/custody.mjs') : { CUSTODY_BY_SOURCE: { 'sql-audit-table': 'subject-writable' } };
const work = await mkdtemp(join(tmpdir(), 'scopehaven parity3 ')); await chmod(work, 0o700);
process.on('exit', () => rmSync(work, { recursive: true, force: true }));
const sha = b => createHash('sha256').update(b).digest('hex');
const at = m => new Date(Date.parse('2026-10-06T06:00:00.000Z') + m * 60000);
const python = args => new Promise(res => execFile(PY ?? 'python3', ['-B', ...args], { maxBuffer: 64 << 20, timeout: 300000 }, (e, stdout, stderr) => res({ code: e ? (e.code ?? 'signal') : 0, stdout, stderr })));
const dataDir = join(work, 'data'), exportsDir = join(work, 'exports'); await mkdir(exportsDir, { mode: 0o700 });
const store = createStore(dataDir), runs = [];
for (const t of ['demo-vulnerable', 'demo-repaired', 'demo-vulnerable', 'demo-repaired']) { const r = await runAssessment(t); await store.save(r); runs.push(r); }
const exported = [];
for (const [i, r] of runs.entries()) { const f = join(exportsDir, `run-${i}.json`); await exportRun({ runId: r.id, format: 'json', outputFile: f, dataDir }); exported.push(await readFile(f)); }
const KEY = generateSigningKey(); const keyDir = join(work, 'keys'); await mkdir(keyDir, { mode: 0o700 }); await writeFile(join(keyDir, 'KEY.pub'), KEY.publicPem);
const sign = (named, m) => Buffer.from(signFiles(named.map(([name, content]) => ({ name, content })), { privateKey: KEY.privatePem, version: '1.0.0', now: at(m) }).envelope);
const linesOf = b => { const t = b.toString(); return t ? t.slice(0, -1).split('\n') : []; };
const text = list => Buffer.from(list.length ? `${list.join('\n')}\n` : '');
const rechain = list => { const o = []; list.forEach((e, i) => o.push(JSON.stringify({ ...e, index: i, prev: i ? V.leafHash(Buffer.from(o[i - 1])).toString('hex') : null }))); return o; };
let newCount = 0;
async function newLedger() { const d = join(work, `L${newCount++}`); await mkdir(d, { mode: 0o700 }); await L.initLedger(d, { now: at(0) }); return d; }
function runWith(base, { set = {}, raw = '' } = {}) {
  const obj = JSON.parse(base); Object.assign(obj, set);
  obj.integrity = { ...obj.integrity, sha256: 'PLACEHOLDER'.padEnd(64, '0') };
  let t = JSON.stringify(obj); if (raw) t = t.replace(/^\{/, `{${raw},`);
  const parsed = JSON.parse(t); const { integrity, notes, ...core } = parsed;
  return Buffer.from(t.replace('PLACEHOLDER'.padEnd(64, '0'), createHash('sha256').update(stable(core)).digest('hex')));
}
const S = await newLedger();
for (const i of [0, 1, 2, 3]) await L.appendEnvelope(S, { envelope: sign([[`run-${i}.json`, exported[i]]], i), files: new Map([[`run-${i}.json`, exported[i]]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
const SB = await L.readLedgerFiles(S), SLOG = JSON.parse(SB.metadata).log, SCREATED = JSON.parse(SB.metadata).createdAt, Sl = linesOf(SB.entries), SE = Sl.map(l => JSON.parse(l)), SP = linesOf(SB.checkpoints);
const base = (b, change = {}) => ({ ...b, envelopes: new Map(b.envelopes), ...change });
const resign = (lines, sizes, t0 = 30, log = SLOG, created = SCREATED) => sizes.map((s, i) => L.signCheckpoint({ createdAt: created, log, lines, treeSize: s, signedAt: at(t0 + i).toISOString(), privateKey: KEY.privatePem }));
const log = [], proofs = [], notes = {};

async function both(label, files, { runFiles, expect, extraEnv } = {}) {
  const d = await mkdtemp(join(work, 'case-')); await chmod(d, 0o700); await mkdir(join(d, 'envelopes'), { mode: 0o700 });
  await writeFile(join(d, 'ledger.json'), files.metadata); await writeFile(join(d, 'entries.jsonl'), files.entries); await writeFile(join(d, 'checkpoints.jsonl'), files.checkpoints);
  for (const [n, b] of files.envelopes) await writeFile(join(d, 'envelopes', `${n}.json`), b);
  const extra = [];
  if (runFiles) { const rf = await mkdtemp(join(work, 'rf-')); for (const [i, b] of runFiles.entries()) await writeFile(join(rf, `f${i}.json`), b); extra.push('--run-files', rf); }
  const n = await cli(['verify', '--ledger', d, '--key', join(keyDir, 'KEY.pub'), '--evidence-key', join(keyDir, 'KEY.pub'), ...extra]);
  const p = await python([SCRIPT, 'log', '--key', join(keyDir, 'KEY.pub'), '--evidence-key', join(keyDir, 'KEY.pub'), '--ledger', d, ...extra]);
  let pj = null; try { pj = JSON.parse(p.stdout); } catch {}
  const nodeV = n.output.verdict ?? `error(${n.code})`, nodeR = n.output.reason ?? n.output.error ?? null;
  const pyV = pj?.verdict ?? (pj?.error ? `error(${p.code})` : `crash(exit ${p.code})`), pyR = pj?.reason ?? pj?.error ?? (p.stderr.trim().split('\n').at(-1) || null);
  const row = { label, node: [nodeV, nodeR, n.code, n.output.detail ?? null, n.output.covered ?? null, n.output.verdictsCheckedAgainstRunFiles ?? null], python: [pyV, pyR, p.code, pj?.detail ?? null, pj?.covered ?? null, pj?.verdictsCheckedAgainstRunFiles ?? null], agreeVerdict: nodeV === pyV && n.code === p.code, agree: nodeV === pyV && nodeR === pyR && n.code === p.code, expect };
  log.push(row); return row;
}
async function proofBoth(label, kind, inputs, expect) {
  const d = await mkdtemp(join(work, 'proof-')); const args = [];
  for (const [k, v] of Object.entries(inputs)) { await writeFile(join(d, k), v); args.push(`--${k}`, join(d, k)); }
  let node, proof = null;
  try { proof = JSON.parse(inputs.proof); } catch {}
  try {
    // As the Node CLI reads files: Buffer.toString('utf8').
    node = kind === 'inclusion' ? V.verifyInclusion({ entryLine: Buffer.from(inputs.entry).toString('utf8'), proof, checkpoint: Buffer.from(inputs.checkpoint).toString('utf8'), ledgerKey: KEY.publicPem })
      : V.verifyConsistency({ older: Buffer.from(inputs.older).toString('utf8'), newer: Buffer.from(inputs.newer).toString('utf8'), proof, ledgerKey: KEY.publicPem });
  } catch (e) { node = { verdict: 'throw', reason: e.message.slice(0, 80) }; }
  const p = await python([SCRIPT, kind, '--key', join(keyDir, 'KEY.pub'), ...args]); let pj = null; try { pj = JSON.parse(p.stdout); } catch {}
  const pyV = pj?.verdict ?? (pj?.error ? `error(${p.code})` : `crash(exit ${p.code})`), pyR = pj?.reason ?? pj?.error ?? (p.stderr.trim().split('\n').at(-1) || null);
  proofs.push({ label, node: [node.verdict, node.reason], python: [pyV, pyR, p.code], agree: node.verdict === pyV && node.reason === pyR, expect });
}
const swap3 = f => base(SB, { entries: text(Sl.map((l, i) => i === 3 ? f(l) : l)) });

await both('E00 baseline', base(SB), { expect: 'verified' });
// ---- Encoding and framing of entries.jsonl / ledger.json / checkpoints.jsonl ----
await both('E01 entries.jsonl starts with a UTF-8 BOM', base(SB, { entries: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), SB.entries]) }));
await both('E02 entries.jsonl with CRLF line ends', base(SB, { entries: Buffer.from(SB.entries.toString().replace(/\n/g, '\r\n')) }));
await both('E03 entries.jsonl without its final newline', base(SB, { entries: SB.entries.subarray(0, -1) }));
await both('E04 entries.jsonl with a doubled final newline', base(SB, { entries: Buffer.concat([SB.entries, Buffer.from('\n')]) }));
{ const b = Buffer.from(SB.entries); const pos = b.lastIndexOf(Buffer.from('"envelope"')); b[pos + 2] = 0xff; await both('E05b entries.jsonl with a raw 0xFF byte in entry 3', base(SB, { entries: b })); }
await both('E06 ledger.json with a BOM', base(SB, { metadata: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), SB.metadata]) }));
await both('E07 ledger.json with CRLF', base(SB, { metadata: Buffer.from(SB.metadata.toString().replace(/\n$/, '\r\n')) }));
await both('E08 ledger.json without newline', base(SB, { metadata: SB.metadata.subarray(0, -1) }));
await both('E08b ledger.json with two newlines', base(SB, { metadata: Buffer.concat([SB.metadata, Buffer.from('\n')]) }));
await both('E08c ledger.json invalid UTF-8', base(SB, { metadata: Buffer.concat([SB.metadata.subarray(0, -2), Buffer.from([0xff, 0x7d, 0x0a])]) }));
await both('E09 checkpoints.jsonl with a BOM', base(SB, { checkpoints: Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), SB.checkpoints]) }));
await both('E10 checkpoints.jsonl with CRLF', base(SB, { checkpoints: Buffer.from(SB.checkpoints.toString().replace(/\n/g, '\r\n')) }));
await both('E10b checkpoints.jsonl invalid UTF-8 tail', base(SB, { checkpoints: Buffer.concat([SB.checkpoints, Buffer.from([0xc3, 0x0a])]) }));
// ---- JSON tokens in entry 3 (raw, no key) ----
await both('E11 NaN in entry 3', swap3(l => l.replace('"index":3', '"index":NaN')));
await both('E12 Infinity in entry 3', swap3(l => l.replace('"index":3', '"index":Infinity')));
await both('E12b -Infinity in entry 3', swap3(l => l.replace('"index":3', '"index":-Infinity')));
await both('E13 -0 as entry 0 index', base(SB, { entries: text(Sl.map((l, i) => i === 0 ? l.replace('"index":0', '"index":-0') : l)) }));
await both('E14 1e400 in entry 3 index', swap3(l => l.replace('"index":3', '"index":1e400')));
await both('E15 duplicate key "index" in entry 3', swap3(l => l.replace('"index":3', '"index":3,"index":3')));
await both('E15b duplicate key, the later one wrong', swap3(l => l.replace('"index":3', '"index":3,"index":4')));
await both('E16 lone surrogate escape as an extra run key (raw)', swap3(l => l.replace('"verdicts":', '"\\ud800":1,"verdicts":')));
await both('E16b upper-case lone surrogate escape \\uD800 (raw)', swap3(l => l.replace('"verdicts":', '"\\uD800":1,"verdicts":')));
await both('E17 16-digit index 1000000000000000 in entry 3 (raw)', swap3(l => l.replace('"index":3', '"index":1000000000000000')));
await both('E17b 2^53-1 index in entry 3 (raw)', swap3(l => l.replace('"index":3', '"index":9007199254740991')));
await both('E17c 15-digit index in entry 3 (raw)', swap3(l => l.replace('"index":3', '"index":100000000000000')));
await both('E18 run id is a list (raw)', swap3(l => { const e = JSON.parse(l); e.runs[0].id = ['x']; return JSON.stringify(e); }));
await both('E18b run id is an object (raw)', swap3(l => { const e = JSON.parse(l); e.runs[0].id = { a: 1 }; return JSON.stringify(e); }));
await both('E18c run is a list (raw)', swap3(l => { const e = JSON.parse(l); e.runs[0] = []; return JSON.stringify(e); }));
await both('E19 a 262144-byte entry line (raw)', swap3(l => { const e = JSON.parse(l); const pad = 262144 - Buffer.byteLength(JSON.stringify({ ...e, runs: [{ ...e.runs[0], zz: '' }] })); return JSON.stringify({ ...e, runs: [{ ...e.runs[0], zz: 'a'.repeat(pad) }] }); }));
await both('E19b a 262145-byte entry line (raw)', swap3(l => { const e = JSON.parse(l); const pad = 262145 - Buffer.byteLength(JSON.stringify({ ...e, runs: [{ ...e.runs[0], zz: '' }] })); return JSON.stringify({ ...e, runs: [{ ...e.runs[0], zz: 'a'.repeat(pad) }] }); }));
await both('E19c 262144 bytes with multibyte chars (raw)', swap3(l => { const e = JSON.parse(l); const pad = 262144 - Buffer.byteLength(JSON.stringify({ ...e, runs: [{ ...e.runs[0], zz: '' }] })); return JSON.stringify({ ...e, runs: [{ ...e.runs[0], zz: 'é'.repeat(Math.floor(pad / 2)) + 'a'.repeat(pad % 2) }] }); }));
// ---- Empty and degenerate ledgers ----
await both('E20 empty ledger (no entries, no checkpoints)', base(SB, { entries: Buffer.alloc(0), checkpoints: Buffer.alloc(0), envelopes: new Map() }));
await both('E20b empty entries, one checkpoint', base(SB, { entries: Buffer.alloc(0), checkpoints: text([SP[0]]) }));
await both('E20c entries, empty checkpoints', base(SB, { checkpoints: Buffer.alloc(0) }));
await both('E20d ledger.json empty', base(SB, { metadata: Buffer.alloc(0) }));
await both('E20e entries.jsonl is a single newline', base(SB, { entries: Buffer.from('\n') }));
// ---- Key holder (re-sealed) cases with valid signatures ----
{
  const add = (e, run) => ({ ...e, runs: [{ ...e.runs[0], ...run }] });
  const reseal = f => { const ls = rechain(SE.map((e, i) => i === 3 ? f(e) : e)); return base(SB, { entries: text(ls), checkpoints: text(resign(ls, [1, 2, 3, 4])) }); };
  await both('E21 key holder: anchor count 1000000000000000 (16 digits, safe integer)', reseal(e => add(e, { anchors: [{ source: Object.keys(CUSTODY_BY_SOURCE)[0], custody: CUSTODY_BY_SOURCE[Object.keys(CUSTODY_BY_SOURCE)[0]], count: 1e15, head: 'a'.repeat(64) }] })));
  await both('E21b key holder: anchor count 999999999999999 (15 digits)', reseal(e => add(e, { anchors: [{ source: Object.keys(CUSTODY_BY_SOURCE)[0], custody: CUSTODY_BY_SOURCE[Object.keys(CUSTODY_BY_SOURCE)[0]], count: 999999999999999, head: 'a'.repeat(64) }] })));
  await both('E22 key holder: entry with a lone-surrogate verdict check id', reseal(e => { const v = [['g\ud800', 'pass']]; return add(e, { verdicts: v, verdictDigest: sha(JSON.stringify(v)) }); }));
}
// ---- Writer-produced: anchors with large counts ----
{
  const src = Object.keys(CUSTODY_BY_SOURCE)[0];
  for (const count of [999999999999999, 1e15, 2 ** 53 - 1]) {
    const W = await newLedger();
    let r; try { await L.appendEnvelope(W, { envelope: sign([['run-0.json', exported[0]]], 1), files: new Map([['run-0.json', exported[0]]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1.5), anchors: new Map([['run-0.json', [{ source: src, count, head: 'b'.repeat(64) }]]]) }); r = 'appended'; }
    catch (e) { r = `refused: ${e.message.slice(0, 80)}`; }
    notes[`writer anchor count ${count}`] = r;
    const WB = await L.readLedgerFiles(W);
    const row = await both(`E23 writer-appended anchor count ${count} (source ${src})`, base(WB), { expect: 'verified' });
    const v = V.verifyLedger({ ...WB, ledgerKey: KEY.publicPem });
    notes[`anchorFor count ${count}`] = v.verdict === 'verified' ? anchorFor(v, { runId: JSON.parse(exported[0]).id, source: src })?.count : v.reason;
  }
  // Writer-produced: a run field whose value is a 16+ digit integer (identity field `build`).
  for (const build of [1234567890123456, 12345678901234567]) {
    const f = runWith(exported[1], { raw: `"build":${build}` }).toString();
    const file = runWith(exported[1], { set: { build } });
    const W = await newLedger(); let r;
    try { await L.appendEnvelope(W, { envelope: sign([['b.json', file]], 1), files: new Map([['b.json', file]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1.5) }); r = 'appended'; } catch (e) { r = `refused: ${e.message.slice(0, 80)}`; }
    notes[`writer build ${build}`] = r;
    const WB = await L.readLedgerFiles(W);
    await both(`E24 writer-appended run with numeric build ${build}`, base(WB), { expect: 'verified' });
    await both(`E24b same with its run file`, base(WB), { runFiles: [file], expect: 'verified' });
  }
  // Writer-produced: run file with a BOM? (attest decides whether it is a run); results with lone surrogate ids
  {
    const obj = JSON.parse(exported[2]); obj.results[0].id = 'X\ud800'; const { integrity, notes: _n, ...core } = obj; obj.integrity = { ...integrity, sha256: createHash('sha256').update(stable(core)).digest('hex') };
    const file = Buffer.from(JSON.stringify(obj));
    const W = await newLedger(); let r;
    try { await L.appendEnvelope(W, { envelope: sign([['s.json', file]], 1), files: new Map([['s.json', file]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1.5) }); r = 'appended'; } catch (e) { r = `refused: ${e.message.slice(0, 80)}`; }
    notes['writer lone-surrogate check id'] = r;
    const WB = await L.readLedgerFiles(W);
    if (linesOf(WB.entries).length) { await both('E25 writer-appended run with a lone-surrogate check id', base(WB), { expect: 'verified' }); await both('E25b same with its run file', base(WB), { runFiles: [file], expect: 'verified' }); }
  }
  // Writer-produced: run file nested 300 deep in a non-results field, with the run file (writer vs verifier)
  for (const depth of [257, 300]) {
    const nested = `${'['.repeat(depth)}1${']'.repeat(depth)}`;
    const file = runWith(exported[3], { raw: `"deepField":${nested}` });
    const W = await newLedger(); let r;
    try { await L.appendEnvelope(W, { envelope: sign([['d.json', file]], 1), files: new Map([['d.json', file]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1.5) }); r = 'appended'; } catch (e) { r = `refused: ${e.message.slice(0, 80)}`; }
    notes[`writer run file nested ${depth}`] = r;
    const WB = await L.readLedgerFiles(W);
    if (linesOf(WB.entries).length) await both(`E26 writer-appended honest run nested ${depth} deep in another field, with its run file`, base(WB), { runFiles: [file], expect: 'writer refuses or verified' });
  }
}
// ---- Run files that are not plain ----
await both('E27 run file with a BOM', base(SB), { runFiles: [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), exported[0]])], expect: 'verified, 0 checked (different digest)' });
await both('E28 run file over 8 MB', base(SB), { runFiles: [Buffer.alloc(8 * 1024 * 1024 + 1, 0x20)], expect: 'same' });

// ---- Proof inputs ----
const inc = L.inclusionProof({ log: SLOG, lines: Sl, index: 1, treeSize: 4 }), con = L.consistencyProof({ log: SLOG, lines: Sl, from: 2, to: 4 });
await proofBoth('P01 inclusion: entry file with a BOM', 'inclusion', { entry: `﻿${Sl[1]}`, proof: JSON.stringify(inc), checkpoint: SP[3] });
await proofBoth('P02 inclusion: entry file without newline', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc), checkpoint: SP[3] }, 'verified');
await proofBoth('P03 inclusion: entry file with two newlines', 'inclusion', { entry: `${Sl[1]}\n\n`, proof: JSON.stringify(inc), checkpoint: SP[3] });
await proofBoth('P04 inclusion: entry file with invalid UTF-8', 'inclusion', { entry: Buffer.concat([Buffer.from(Sl[1]), Buffer.from([0xff])]), proof: JSON.stringify(inc), checkpoint: SP[3] });
await proofBoth('P04b inclusion: invalid UTF-8 inside a string of the entry', 'inclusion', { entry: Buffer.from(Sl[1].replace('"recordedAt"', '"recordedA\u0000t"')).fill(0xff, Sl[1].indexOf('"recordedAt"') + 10, Sl[1].indexOf('"recordedAt"') + 11), proof: JSON.stringify(inc), checkpoint: SP[3] });
await proofBoth('P05 inclusion: checkpoint with CRLF', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc), checkpoint: `${SP[3]}\r\n` }, 'verified');
await proofBoth('P06 inclusion: proof with duplicate index keys (last wrong)', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"index":1', '"index":1,"index":2'), checkpoint: SP[3] });
await proofBoth('P06b inclusion: proof with duplicate index keys (last right)', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"index":1', '"index":2,"index":1'), checkpoint: SP[3] });
await proofBoth('P07 inclusion: proof index -0', 'inclusion', { entry: Sl[0], proof: JSON.stringify(L.inclusionProof({ log: SLOG, lines: Sl, index: 0, treeSize: 4 })).replace('"index":0', '"index":-0'), checkpoint: SP[3] });
await proofBoth('P08 inclusion: proof index 1e400', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"index":1', '"index":1e400'), checkpoint: SP[3] });
await proofBoth('P09 inclusion: proof with a BOM', 'inclusion', { entry: Sl[1], proof: `﻿${JSON.stringify(inc)}`, checkpoint: SP[3] });
await proofBoth('P10 inclusion: entry with a 16-digit index', 'inclusion', { entry: Sl[1].replace('"index":1', '"index":1000000000000001'), proof: JSON.stringify({ ...inc, index: 1000000000000001 }), checkpoint: SP[3] });
await proofBoth('P11 inclusion: entry whose run id is a list', 'inclusion', { entry: (() => { const e = JSON.parse(Sl[1]); e.runs[0].id = ['x']; return JSON.stringify(e); })(), proof: JSON.stringify(inc), checkpoint: SP[3] });
await proofBoth('P12 consistency: newer checkpoint with BOM', 'consistency', { older: SP[1], newer: `﻿${SP[3]}`, proof: JSON.stringify(con) });
await proofBoth('P13 consistency: empty proof file', 'consistency', { older: SP[1], newer: SP[3], proof: '' });
await proofBoth('P14 consistency: proof path with a lone-surrogate string', 'consistency', { older: SP[1], newer: SP[3], proof: JSON.stringify({ ...con, path: ['\ud800'] }) });


// X07: one envelope with two runs, checked against both run files (the lookup is by each run's subject).
{
  const T = await newLedger();
  const two = sign([['a.json', exported[0]], ['b.json', exported[1]]], 1);
  await L.appendEnvelope(T, { envelope: two, files: new Map([['a.json', exported[0]], ['b.json', exported[1]]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1.5) });
  await both('X07 one envelope, two runs, with both run files', base(await L.readLedgerFiles(T)), { runFiles: [exported[0], exported[1]], expect: 'verified, 2 checked' });
}

// Also: an integer past 2^53 written with 17 digits, an invalid byte inside a value no shape rule checks,
// and a key-holder entry for a run nested deeper than the limit, which the writer now refuses to record.
await both('E17d 17-digit index 12345678901234567 in entry 3 (raw)', swap3(l => l.replace('"index":3', '"index":12345678901234567')));
{ const b = Buffer.from(Sl[3]); const id = JSON.parse(Sl[3]).runs[0].id; b[b.indexOf(Buffer.from(`"id":"${id}"`)) + 6] = 0xff;
  await both('E05c raw 0xFF inside entry 3\'s run id', base(SB, { entries: Buffer.concat([Buffer.from(Sl.slice(0, 3).map(l => `${l}\n`).join('')), b, Buffer.from('\n')]) })); }
{
  const file = runWith(exported[3], { raw: `"deepField":${'['.repeat(300)}1${']'.repeat(300)}` }), named = new Map([['deep.json', file]]);
  const env = sign([['deep.json', file]], 1), check = verifyEnvelope({ envelope: env, publicKey: KEY.publicPem, files: named });
  const D = await newLedger(), meta = JSON.parse((await L.readLedgerFiles(D)).metadata);
  const ls = [JSON.stringify(L.buildEntry({ previousLine: null, index: 0, recordedAt: at(2).toISOString(), envelope: env, check, files: named }))];
  const files = { metadata: Buffer.from(`${JSON.stringify(meta)}\n`), entries: text(ls), checkpoints: text([L.signCheckpoint({ createdAt: meta.createdAt, log: meta.log, lines: ls, signedAt: at(2).toISOString(), privateKey: KEY.privatePem })]), envelopes: new Map([[sha(env), env]]) };
  await both('R04e key holder: a run nested 300 deep, with its run file', files, { runFiles: [file], expect: 'verdict-mismatch' });
}

const row = label => log.find(r => r.label === label) ?? proofs.find(r => r.label === label);
test('every E and P probe gets the same verdict, reason and exit code from Node and Python', { skip: !PY && 'no Python 3' }, () => {
  for (const r of log) assert.ok(r.agree, `${r.label}: node ${JSON.stringify(r.node)} python ${JSON.stringify(r.python)}`);
  for (const r of proofs) assert.ok(r.agree && r.node[0] === r.python[0], `${r.label}: node ${JSON.stringify(r.node)} python ${JSON.stringify(r.python)}`);
  assert.ok(log.length >= 50 && proofs.length >= 14);
});

test('E and P probes with a stated outcome get it', { skip: !PY && 'no Python 3' }, () => {
  const is = (label, verdict, reason = null) => { const r = row(label); assert.deepEqual([r.node[0], r.node[1]], [verdict, reason], label); assert.deepEqual([r.python[0], r.python[1]], [verdict, reason], label); };
  is('E00 baseline', 'verified');
  // Safe integers of 16 digits are integers in both; a list or object id is a shape error, not a crash.
  for (const label of ['E21 key holder: anchor count 1000000000000000 (16 digits, safe integer)', 'E21b key holder: anchor count 999999999999999 (15 digits)']) is(label, 'verified');
  for (const count of [999999999999999, 1e15, 2 ** 53 - 1]) { is(`E23 writer-appended anchor count ${count} (source ${Object.keys(CUSTODY_BY_SOURCE)[0]})`, 'verified'); assert.equal(notes[`anchorFor count ${count}`], count); }
  for (const label of ['E17 16-digit index 1000000000000000 in entry 3 (raw)', 'E17b 2^53-1 index in entry 3 (raw)', 'E17c 15-digit index in entry 3 (raw)']) is(label, 'rejected', 'index-mismatch');
  for (const label of ['E18 run id is a list (raw)', 'E18b run id is an object (raw)', 'E18c run is a list (raw)']) is(label, 'rejected', 'entry-shape');
  for (const build of [1234567890123456, 12345678901234567]) is(`E24 writer-appended run with numeric build ${build}`, 'verified');
  is('E17d 17-digit index 12345678901234567 in entry 3 (raw)', 'rejected', 'entry-not-canonical');
  is('E05c raw 0xFF inside entry 3\'s run id', 'rejected', 'entry-shape');
  is('R04e key holder: a run nested 300 deep, with its run file', 'rejected', 'verdict-mismatch');
  // A BOM is never stripped: the file is judged as it is, the same way in both.
  for (const label of ['E01 entries.jsonl starts with a UTF-8 BOM', 'E06 ledger.json with a BOM', 'E09 checkpoints.jsonl with a BOM']) assert.equal(row(label).node[0], 'rejected', label);
  // The writer refuses a run file nested past the depth limit instead of recording what --run-files would reject.
  for (const depth of [257, 300]) assert.match(notes[`writer run file nested ${depth}`], /^refused: .*read back/, `${depth}`);
  const x07 = row('X07 one envelope, two runs, with both run files');
  assert.deepEqual([x07.node[0], x07.node[5]], ['verified', 2]); assert.deepEqual([x07.python[0], x07.python[5]], ['verified', 2]);
});
