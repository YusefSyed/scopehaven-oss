// Node/Python agreement on edge probes (R00-R10 and Q01-Q21), kept as a test: every
// probe must get the same verdict, reason and exit code from both verifiers, and the probes with a
// stated outcome must get that outcome.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile, chmod } from 'node:fs/promises';
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
import { permissionHistory } from './history.mjs';

const PY = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3', '/opt/homebrew/bin/python3', '/usr/bin/python3'].find(path => existsSync(path));
const SCRIPT = fileURLToPath(new URL('./verify_ledger.py', import.meta.url));
const sha = b => createHash('sha256').update(b).digest('hex');
const at = m => new Date(Date.parse('2026-10-06T06:00:00.000Z') + m * 60000);
const CREATED = at(0).toISOString();
const work = await mkdtemp(join(tmpdir(), 'scopehaven ledger parity '));
process.on('exit', () => rmSync(work, { recursive: true, force: true }));
const python = args => new Promise(res => execFile(PY, ['-B', ...args], { maxBuffer: 64 << 20, timeout: 300000 }, (e, stdout, stderr) => res({ code: e ? (e.code ?? 'signal') : 0, stdout, stderr })));
const log = [], proofs = [], notes = {};
if (PY) {
// ---- Fixture ----
const dataDir = join(work, 'data'), exportsDir = join(work, 'exports');
await mkdir(exportsDir, { mode: 0o700 });
const store = createStore(dataDir), runs = [];
for (const t of ['demo-vulnerable', 'demo-repaired', 'demo-vulnerable', 'demo-repaired']) { const r = await runAssessment(t); await store.save(r); runs.push(r); }
const exported = [];
for (const [i, r] of runs.entries()) { const f = join(exportsDir, `run-${i}.json`); await exportRun({ runId: r.id, format: 'json', outputFile: f, dataDir }); exported.push(await readFile(f)); }
const KEY = generateSigningKey(), LED = generateSigningKey();
const keyDir = join(work, 'keys'); await mkdir(keyDir, { mode: 0o700 });
for (const [n, k] of Object.entries({ KEY, LED })) await writeFile(join(keyDir, `${n}.pub`), k.publicPem);
const sign = (named, m, key = KEY) => Buffer.from(signFiles(named.map(([name, content]) => ({ name, content })), { privateKey: key.privatePem, version: '1.0.0', now: at(m) }).envelope);
const linesOf = b => { const t = b.toString(); return t ? t.slice(0, -1).split('\n') : []; };
const text = list => Buffer.from(list.length ? `${list.join('\n')}\n` : '');
const rechain = list => { const o = []; list.forEach((e, i) => o.push(JSON.stringify({ ...e, index: i, prev: i ? V.leafHash(Buffer.from(o[i - 1])).toString('hex') : null }))); return o; };
const resign = (log, lines, sizes, key = KEY, t0 = 30) => sizes.map((s, i) => L.signCheckpoint({ createdAt: CREATED, log, lines, treeSize: s, signedAt: at(t0 + i).toISOString(), privateKey: key.privatePem }));
async function newLedger(name) { const d = join(work, name); await mkdir(d, { mode: 0o700 }); await L.initLedger(d, { now: at(0) }); return d; }
const nested = depth => `${'['.repeat(depth)}1${']'.repeat(depth)}`;
// A run export with raw JSON spliced in at top level and the integrity hash recomputed the way attest recomputes it.
function runWith(base, { set = {}, raw = '', results, drop = false } = {}) {
  const obj = JSON.parse(base);
  Object.assign(obj, set);
  if (results !== undefined) obj.results = results;
  if (drop) delete obj.results;
  obj.integrity = { ...obj.integrity, sha256: 'PLACEHOLDER'.padEnd(64, '0') };
  let t = JSON.stringify(obj);
  if (raw) t = t.replace(/^\{/, `{${raw},`);
  const parsed = JSON.parse(t); const { integrity, notes, ...core } = parsed;
  const h = createHash('sha256').update(stable(core)).digest('hex');
  return Buffer.from(t.replace('PLACEHOLDER'.padEnd(64, '0'), h));
}

// S: four honest signed appends, same key.
const S = await newLedger('S');
for (const i of [0, 1, 2, 3]) await L.appendEnvelope(S, { envelope: sign([[`run-${i}.json`, exported[i]]], i), files: new Map([[`run-${i}.json`, exported[i]]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
const SB = await L.readLedgerFiles(S), SLOG = JSON.parse(SB.metadata).log, Sl = linesOf(SB.entries), SE = Sl.map(l => JSON.parse(l)), SP = linesOf(SB.checkpoints);
const base = (b, change = {}) => ({ ...b, envelopes: new Map(b.envelopes), ...change });

async function both(label, files, { ledgerKey = 'KEY', runFiles, expect } = {}) {
  const d = await mkdtemp(join(work, 'case-')); await chmod(d, 0o700); await mkdir(join(d, 'envelopes'));
  await writeFile(join(d, 'ledger.json'), files.metadata); await writeFile(join(d, 'entries.jsonl'), files.entries); await writeFile(join(d, 'checkpoints.jsonl'), files.checkpoints);
  for (const [n, b] of files.envelopes) await writeFile(join(d, 'envelopes', `${n}.json`), b);
  const extra = [];
  if (runFiles) { const rf = await mkdtemp(join(work, 'rf-')); for (const [i, b] of runFiles.entries()) await writeFile(join(rf, `f${i}.json`), b); extra.push('--run-files', rf); }
  const t0 = performance.now();
  const n = await cli(['verify', '--ledger', d, '--key', join(keyDir, `${ledgerKey}.pub`), '--evidence-key', join(keyDir, 'KEY.pub'), ...extra]);
  const t1 = performance.now();
  const p = await python([SCRIPT, 'log', '--key', join(keyDir, `${ledgerKey}.pub`), '--evidence-key', join(keyDir, 'KEY.pub'), '--ledger', d, ...extra]);
  let pj = null; try { pj = JSON.parse(p.stdout); } catch {}
  const nodeV = n.output.verdict ?? `error(${n.code})`, nodeR = n.output.reason ?? n.output.error ?? null;
  const pyV = pj?.verdict ?? (pj?.error ? `error(${p.code})` : `crash(exit ${p.code})`), pyR = pj?.reason ?? pj?.error ?? (p.stderr.trim().split('\n').at(-1) || null);
  const row = { label, node: [nodeV, nodeR, n.code, n.output.detail ?? null, n.output.verdictsCheckedAgainstRunFiles ?? null], python: [pyV, pyR, p.code, pj?.detail ?? null, pj?.verdictsCheckedAgainstRunFiles ?? null],
    agree: nodeV === pyV && nodeR === pyR && n.code === p.code, expect, nodeSecs: +((t1 - t0) / 1000).toFixed(2) };
  log.push(row); return row;
}
async function proofBoth(label, kind, inputs, expect) {
  const d = await mkdtemp(join(work, 'proof-')); const args = [];
  for (const [k, v] of Object.entries(inputs)) { await writeFile(join(d, k), v); args.push(`--${k}`, join(d, k)); }
  let node, proof = null;
  try { proof = JSON.parse(inputs.proof); } catch {}
  try {
    node = kind === 'inclusion' ? V.verifyInclusion({ entryLine: String(inputs.entry), proof, checkpoint: String(inputs.checkpoint), ledgerKey: KEY.publicPem })
      : V.verifyConsistency({ older: String(inputs.older), newer: String(inputs.newer), proof, ledgerKey: KEY.publicPem });
  } catch (e) { node = { verdict: 'throw', reason: e.message.slice(0, 80) }; }
  const p = await python([SCRIPT, kind, '--key', join(keyDir, 'KEY.pub'), ...args]); let pj = null; try { pj = JSON.parse(p.stdout); } catch {}
  const pyV = pj?.verdict ?? (pj?.error ? `error(${p.code})` : `crash(exit ${p.code})`), pyR = pj?.reason ?? pj?.error ?? (p.stderr.trim().split('\n').at(-1) || null);
  proofs.push({ label, node: [node.verdict, node.reason], python: [pyV, pyR, p.code], agree: node.verdict === pyV && node.reason === pyR, expect });
}

await both('R00 baseline', base(SB), { expect: 'verified' });
await both('R00b baseline with all run files', base(SB), { runFiles: exported, expect: 'verified, 4 checked' });

// ---- Recursion handling: entry lines nested between the two parsers' limits ----
for (const depth of [200, 400, 450, 500, 600, 900, 1200, 3000, 20000]) {
  const ls = Sl.map((l, i) => i === 3 ? JSON.stringify({ ...SE[3], runs: '@@' }).replace('"@@"', nested(depth)) : l);
  await both(`R01 entry 3 runs replaced by an array nested ${depth} deep (raw, no key)`, base(SB, { entries: text(ls) }), { expect: 'same reason' });
}
// ---- Number semantics in entry lines ----
await both('R02 entry 3 index is a 5000-digit integer (raw, no key)', base(SB, { entries: text(Sl.map((l, i) => i === 3 ? l.replace('"index":3', `"index":${'9'.repeat(5000)}`) : l)) }), { expect: 'same reason' });
await both('R02b entry 3 index is a 400-digit integer (raw, no key)', base(SB, { entries: text(Sl.map((l, i) => i === 3 ? l.replace('"index":3', `"index":${'9'.repeat(400)}`) : l)) }), { expect: 'same reason' });
await both('R02c entry 3 run build is a 5000-digit integer, resealed by key holder', (() => { const ls = rechain(SE).map((l, i) => i === 3 ? l.replace(/"build":"[^"]*"/, `"build":${'9'.repeat(5000)}`) : l); return base(SB, { entries: text(ls), checkpoints: text(resign(SLOG, ls, [4])) }); })(), { expect: 'same reason' });
await both('R02d entry 3 index 1e21 (raw)', base(SB, { entries: text(Sl.map((l, i) => i === 3 ? l.replace('"index":3', '"index":1e+21') : l)) }), { expect: 'same reason' });
// ---- Check order: an early chain fault plus a later deep line ----
await both('R03 entry 0 index changed AND entry 2 nested 1500 deep (raw)', base(SB, { entries: text(Sl.map((l, i) => i === 0 ? l.replace('"index":0', '"index":7') : i === 2 ? JSON.stringify({ ...SE[2], runs: '@@' }).replace('"@@"', nested(1500)) : l)) }), { expect: 'same reason' });
await both('R03b entry 0 index changed AND entry 2 has a 5000-digit integer (raw)', base(SB, { entries: text(Sl.map((l, i) => i === 0 ? l.replace('"index":0', '"index":7') : i === 2 ? l.replace('"index":2', `"index":${'9'.repeat(5000)}`) : l)) }), { expect: 'same reason' });
await both('R03c checkpoint 0 signature tampered AND checkpoint 2 nested 600 deep', base(SB, { checkpoints: text(SP.map((l, i) => i === 0 ? l.replace(/"sig":"(.)/, (m, c) => `"sig":"${c === 'A' ? 'B' : 'A'}`) : i === 2 ? nested(600) : l)) }), { expect: 'same reason' });
await both('R03d ledger.json nested 600 deep', base(SB, { metadata: Buffer.from(`${nested(600)}\n`) }), { expect: 'same reason' });

// ---- Run-file verdict binding ----
{
  // (a) Writer path: a run export with a field nested 2000 deep, signed by attest and appended by the writer.
  const deep = runWith(exported[0], { raw: `"deep":${nested(2000)}` });
  const huge = runWith(exported[1], { raw: `"huge":${'9'.repeat(5000)}` });
  const W = await newLedger('W'); let i = 0;
  for (const [name, content] of [['deep.json', deep], ['huge.json', huge]]) {
    try { await L.appendEnvelope(W, { envelope: sign([[name, content]], ++i), files: new Map([[name, content]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) }); notes[`writer appends ${name}`] = 'appended'; }
    catch (e) { notes[`writer appends ${name}`] = `refused: ${e.message.slice(0, 90)}`; }
  }
  const WB = await L.readLedgerFiles(W);
  await both('R04 writer-appended runs (deep field / 5000-digit field), no run files', base(WB), { expect: 'verified' });
  await both('R04b same, with the deep run file', base(WB), { runFiles: [deep], expect: 'same verdict' });
  await both('R04c same, with the 5000-digit run file', base(WB), { runFiles: [huge], expect: 'same verdict' });
  // notes is outside the integrity core, so Node attest never recurses into it: depth past Python's json parser.
  for (const depth of [5000, 50000]) {
    const deepNotes = runWith(exported[3], { set: { notes: '@@' } }); const t = deepNotes.toString().replace('"notes":"@@"', `"notes":${nested(depth)}`);
    const parsed = JSON.parse(t); const { integrity, notes: _n, ...core } = parsed; const fixed = Buffer.from(t.replace(parsed.integrity.sha256, createHash('sha256').update(stable(core)).digest('hex')));
    const N = await newLedger(`N${depth}`);
    try { await L.appendEnvelope(N, { envelope: sign([['notes.json', fixed]], 1), files: new Map([['notes.json', fixed]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1.5) }); notes[`writer appends notes nested ${depth}`] = 'appended'; }
    catch (e) { notes[`writer appends notes nested ${depth}`] = `refused: ${e.message.slice(0, 90)}`; }
    const NB = await L.readLedgerFiles(N);
    if (linesOf(NB.entries).length) await both(`R04d writer-appended run whose notes are nested ${depth} deep, with its run file`, base(NB), { runFiles: [fixed], expect: 'same verdict' });
  }
  // (b) Key holder: results that are not a list, with an empty verdict list recorded.
  for (const [label, results] of [['empty string', ''], ['empty object', {}], ['non-empty string', 'x'], ['null', null], ['a list of numbers', [1]],
    ['a list of pairs', [['TENANT-01', 'pass']]], ['an object without status', [{ id: 'TENANT-01' }]], ['a numeric status', [{ id: 'TENANT-01', status: 1 }]], ['no results key', undefined]]) {
    const file = runWith(exported[2], { results, drop: results === undefined });
    const name = 'odd.json', env = sign([[name, file]], 1), check = verifyEnvelope({ envelope: env, publicKey: KEY.publicPem, files: new Map([[name, file]]) });
    const D = await newLedger(`odd-${label.replace(/ /g, '')}`); const meta = JSON.parse((await L.readLedgerFiles(D)).metadata);
    let writer; try { await L.appendEnvelope(D, { envelope: env, files: new Map([[name, file]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(2) }); writer = 'appended'; } catch (e) { writer = `refused: ${e.message.slice(0, 60)}`; }
    notes[`writer, results ${label}`] = writer;
    const entry = { index: 0, prev: null, recordedAt: at(2).toISOString(), envelope: { sha256: sha(env), keyid: check.keyid }, runs: check.runs.map(r => ({ ...r, verdicts: [], verdictDigest: sha('[]'), anchors: [] })) };
    const ls = [JSON.stringify(entry)];
    const files = { metadata: Buffer.from(`${JSON.stringify(meta)}\n`), entries: text(ls), checkpoints: text([L.signCheckpoint({ createdAt: meta.createdAt, log: meta.log, lines: ls, signedAt: at(2).toISOString(), privateKey: KEY.privatePem })]), envelopes: new Map([[sha(env), env]]) };
    await both(`R05 key holder: run file results = ${label}, recorded verdicts [], with the run file`, files, { runFiles: [file], expect: 'same verdict' });
  }
  // (c) A run file supplied twice under different names, and a run file that does not match any entry.
  await both('R06 run files: duplicates and an unrelated file', base(SB), { runFiles: [exported[0], exported[0], Buffer.from('{"results":[]}')], expect: 'verified, 1 checked' });
}

// ---- Run-id uniqueness ----
{
  const id0 = JSON.parse(exported[0]).id;
  const variants = [['upper-case id', id0.toUpperCase()], ['id with trailing space', `${id0} `], ['NFD vs NFC (e-acute)', 'run-é'], ['NFD', 'run-é'], ['fullwidth digit', id0.replace(/[0-9]/, d => String.fromCharCode(0xFF10 + +d))], ['lone surrogate A', 'g\ud800'], ['lone surrogate B', 'g\udc00']];
  const U = await newLedger('U'); let m = 0;
  for (const [label, id] of variants) {
    const file = runWith(exported[1], { set: { id } }), name = `v${m}.json`;
    try { await L.appendEnvelope(U, { envelope: sign([[name, file]], ++m), files: new Map([[name, file]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(m + 0.5) }); notes[`id variant ${label}`] = 'appended'; }
    catch (e) { notes[`id variant ${label}`] = `refused: ${e.message.slice(0, 70)}`; }
  }
  // the original id itself after its variants
  try { await L.appendEnvelope(U, { envelope: sign([['orig.json', exported[0]]], 20), files: new Map([['orig.json', exported[0]]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(20.5) }); notes['original id after variants'] = 'appended'; }
  catch (e) { notes['original id after variants'] = `refused: ${e.message.slice(0, 70)}`; }
  await both('R07 ids that differ only by case, space, normalization, width, lone surrogate', base(await L.readLedgerFiles(U)), { expect: 'same verdict' });
  // One envelope that names the same run file twice (two subjects, same run id).
  const T2 = await newLedger('T2');
  try { await L.appendEnvelope(T2, { envelope: sign([['a.json', exported[0]], ['b.json', exported[0]]], 1), files: new Map([['a.json', exported[0]], ['b.json', exported[0]]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(1.5) }); notes['writer: one envelope, same run twice'] = 'appended'; }
  catch (e) { notes['writer: one envelope, same run twice'] = `refused: ${e.message.slice(0, 90)}`; }
  const T2B = await L.readLedgerFiles(T2);
  notes['T2 entries after that append'] = linesOf(T2B.entries).length;
  if (linesOf(T2B.entries).length) await both('R08 writer-built entry recording one run id twice', base(T2B), { expect: 'rejected: writer wrote what the verifiers reject' });
  try { await L.appendEnvelope(T2, { envelope: sign([['run-1.json', exported[1]]], 3), files: new Map([['run-1.json', exported[1]]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(3.5) }); notes['T2 next append'] = 'appended'; }
  catch (e) { notes['T2 next append'] = `refused: ${e.message.slice(0, 90)}`; }
  // Replay under a NEW run id with the old run's verdicts: needs the evidence key (a new signed run file).
  const R = await newLedger('R');
  for (const i of [0, 1, 2]) await L.appendEnvelope(R, { envelope: sign([[`run-${i}.json`, exported[i]]], i + 1), files: new Map([[`run-${i}.json`, exported[i]]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 1.5) });
  const replay = runWith(exported[1], { set: { id: 'replayed-under-a-new-id' } });
  await L.appendEnvelope(R, { envelope: sign([['replay.json', replay]], 5), files: new Map([['replay.json', replay]]), evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(5.5) });
  const RB = await L.readLedgerFiles(R);
  await both('R09 evidence-key holder: old run re-exported under a new run id and appended', base(RB), { runFiles: [...exported.slice(0, 3), replay], expect: 'verified (needs the evidence key)' });
  const h = permissionHistory(V.verifyLedger({ ...RB, ledgerKey: KEY.publicPem }));
  notes.R09history = h.segments.map(s => s.changes.filter(c => c.check === 'TENANT-01').map(c => `${c.from}->${c.to}@${c.entry}:${c.runId}`));
  // Separate ledger key: can the ledger-key holder alone record that replay? Only by reusing an existing envelope.
  const D = await newLedger('D2');
  for (const i of [0, 1, 2]) await L.appendEnvelope(D, { envelope: sign([[`run-${i}.json`, exported[i]]], i + 1), files: new Map([[`run-${i}.json`, exported[i]]]), evidenceKey: KEY.publicPem, privateKey: LED.privatePem, now: at(i + 1.5) });
  const DB = await L.readLedgerFiles(D), DE = linesOf(DB.entries).map(l => JSON.parse(l)), DLOG = JSON.parse(DB.metadata).log;
  const ls = rechain([...DE, { ...DE[1], recordedAt: at(6).toISOString() }]);
  await both('R10 ledger-key holder only: entry 1 replayed at the end, rechained and re-signed', base(DB, { entries: text(ls), checkpoints: text(resign(DLOG, ls, [1, 2, 3, 4], LED)) }), { ledgerKey: 'LED', expect: 'rejected' });
}

// ---- Proofs ----
const inc = L.inclusionProof({ log: SLOG, lines: Sl, index: 1, treeSize: 4 }), con = L.consistencyProof({ log: SLOG, lines: Sl, from: 2, to: 4 });
await proofBoth('Q01 inclusion valid', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc), checkpoint: SP[3] }, 'verified');
for (const depth of [400, 600, 1200]) await proofBoth(`Q02 inclusion: entry line nested ${depth} deep`, 'inclusion', { entry: nested(depth), proof: JSON.stringify(inc), checkpoint: SP[3] }, 'same reason');
await proofBoth('Q03 inclusion: entry line with a 5000-digit index', 'inclusion', { entry: Sl[1].replace('"index":1', `"index":${'9'.repeat(5000)}`), proof: JSON.stringify(inc), checkpoint: SP[3] }, 'same reason');
await proofBoth('Q04 inclusion: proof index a 5000-digit integer', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"index":1', `"index":${'9'.repeat(5000)}`), checkpoint: SP[3] }, 'same reason');
await proofBoth('Q05 inclusion: proof index "1" (string)', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"index":1', '"index":"1"'), checkpoint: SP[3] }, 'same');
await proofBoth('Q06 inclusion: proof index 1.0000000000000002', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"index":1', '"index":1.0000000000000002'), checkpoint: SP[3] }, 'same');
await proofBoth('Q07 inclusion: proof index 1.00000000000000001 (rounds to 1)', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"index":1', '"index":1.00000000000000001'), checkpoint: SP[3] }, 'same');
await proofBoth('Q08 inclusion of entry 0: proof index 1e-400 (underflows to 0)', 'inclusion', { entry: Sl[0], proof: JSON.stringify(L.inclusionProof({ log: SLOG, lines: Sl, index: 0, treeSize: 4 })).replace('"index":0', '"index":1e-400'), checkpoint: SP[3] }, 'same');
await proofBoth('Q09 inclusion of entry 0: proof index -0.0', 'inclusion', { entry: Sl[0], proof: JSON.stringify(L.inclusionProof({ log: SLOG, lines: Sl, index: 0, treeSize: 4 })).replace('"index":0', '"index":-0.0'), checkpoint: SP[3] }, 'same');
await proofBoth('Q10 inclusion: proof treeSize 4 written as 40e-1', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"treeSize":4', '"treeSize":40e-1'), checkpoint: SP[3] }, 'same');
await proofBoth('Q11 inclusion: proof treeSize 9007199254740996.0 (unsafe float)', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"treeSize":4', '"treeSize":9007199254740996.0'), checkpoint: SP[3] }, 'same');
await proofBoth('Q12 inclusion: proof with "index": true', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc).replace('"index":1', '"index":true'), checkpoint: SP[3] }, 'same');
await proofBoth('Q13 inclusion: proof file nested 600 deep', 'inclusion', { entry: Sl[1], proof: nested(600), checkpoint: SP[3] }, 'same');
await proofBoth('Q14 inclusion: proof path nested 600 deep inside a valid object', 'inclusion', { entry: Sl[1], proof: JSON.stringify({ ...inc, path: '@@' }).replace('"@@"', nested(600)), checkpoint: SP[3] }, 'same');
await proofBoth('Q15 inclusion: checkpoint file nested 600 deep', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc), checkpoint: nested(600) }, 'same');
await proofBoth('Q16 inclusion: checkpoint file with invalid UTF-8 bytes', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc), checkpoint: Buffer.concat([Buffer.from(SP[3]), Buffer.from([0xff])]) }, 'same');
await proofBoth('Q17 inclusion: checkpoint with a byte-order mark', 'inclusion', { entry: Sl[1], proof: JSON.stringify(inc), checkpoint: `﻿${SP[3]}` }, 'same');
await proofBoth('Q18 inclusion: entry line with CRLF ending', 'inclusion', { entry: `${Sl[1]}\r\n`, proof: JSON.stringify(inc), checkpoint: SP[3] }, 'same');
await proofBoth('Q19 consistency: proof from 2.0 to 4e0', 'consistency', { older: SP[1], newer: SP[3], proof: JSON.stringify(con).replace('"from":2', '"from":2.0').replace('"to":4', '"to":4e0') }, 'verified');
await proofBoth('Q20 consistency: older checkpoint nested 600 deep', 'consistency', { older: nested(600), newer: SP[3], proof: JSON.stringify(con) }, 'same');
await proofBoth('Q21 consistency: proof from a 5000-digit integer', 'consistency', { older: SP[1], newer: SP[3], proof: JSON.stringify(con).replace('"from":2', `"from":${'9'.repeat(5000)}`) }, 'same');

}

const row = label => log.find(r => r.label === label) ?? proofs.find(r => r.label === label);
test('every R and Q probe gets the same outcome from Node and Python', { skip: !PY && 'no Python 3 at a fixed path' }, () => {
  for (const r of [...log, ...proofs]) assert.ok(r.agree, `${r.label}: node ${JSON.stringify(r.node)} python ${JSON.stringify(r.python)}`);
  assert.ok(log.length >= 30 && proofs.length >= 20);
});

test('R and Q probes with a stated outcome get it', { skip: !PY && 'no Python 3 at a fixed path' }, () => {
  const verdict = label => row(label).node[0];
  for (const label of ['R00 baseline', 'R00b baseline with all run files', 'R04 writer-appended runs (deep field / 5000-digit field), no run files', 'R06 run files: duplicates and an unrelated file',
    'R09 evidence-key holder: old run re-exported under a new run id and appended', 'Q01 inclusion valid', 'Q19 consistency: proof from 2.0 to 4e0']) assert.equal(verdict(label), 'verified', label);
  assert.equal(row('R00b baseline with all run files').node[4], 4); assert.equal(row('R00b baseline with all run files').python[4], 4);
  assert.equal(row('R06 run files: duplicates and an unrelated file').node[4], 1);
  assert.equal(verdict('R10 ledger-key holder only: entry 1 replayed at the end, rechained and re-signed'), 'rejected');
  // Results that are not a list of objects with string id and status are not a run export, in both verifiers.
  for (const r of log.filter(r => r.label.startsWith('R05 '))) { assert.deepEqual([r.node[0], r.node[1]], ['rejected', 'verdict-mismatch'], r.label); assert.match(r.node[3], /not a run export/, r.label); assert.equal(r.python[3], r.node[3], r.label); }
  // R08: the writer refuses an envelope that names one run twice, so it never writes what the verifiers reject.
  assert.match(notes['writer: one envelope, same run twice'], /^refused: This envelope names one run more than once/);
  assert.equal(notes['T2 entries after that append'], 0);
});
