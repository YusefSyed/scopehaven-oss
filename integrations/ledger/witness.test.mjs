// Witnessing: a witness (witness.mjs) countersigns ledger checkpoints in the C2SP cosignature/v1
// format after checking the log only grows; both verifiers check the cosignatures against the witness
// keys a reader trusts, with the same verdicts and reasons. Everything here is local and synthetic.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { runAssessment } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { exportRun } from '../../src/export-cli.mjs';
import { generateSigningKey, signFiles } from '../attest/sign.mjs';
import * as L from './ledger.mjs';
import * as V from './verify.mjs';
import * as W from './witness.mjs';
import { main as cli } from './cli.mjs';

const PYTHON = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3', '/opt/homebrew/bin/python3', '/usr/bin/python3'].find(path => existsSync(path));
const SCRIPT = fileURLToPath(new URL('./verify_ledger.py', import.meta.url));
const python = args => new Promise(res => execFile(PYTHON, ['-B', ...args], { maxBuffer: 64 << 20, timeout: 120000 }, (e, stdout, stderr) => res({ code: e ? (e.code ?? 'signal') : 0, stdout, stderr })));
const at = m => new Date(Date.parse('2026-10-08T06:00:00.000Z') + m * 60000);
const work = await mkdtemp(join(tmpdir(), 'scopehaven witness '));
process.on('exit', () => rmSync(work, { recursive: true, force: true }));
const dataDir = join(work, 'data'), ex = join(work, 'ex'); await mkdir(ex, { mode: 0o700 });
const store = createStore(dataDir), exported = [];
for (const [i, t] of ['demo-vulnerable', 'demo-repaired', 'demo-vulnerable', 'demo-repaired', 'demo-vulnerable'].entries()) {
  const r = await runAssessment(t); await store.save(r); const f = join(ex, `run-${i}.json`); await exportRun({ runId: r.id, format: 'json', outputFile: f, dataDir }); exported.push(await readFile(f));
}
const files = exported.map((c, i) => new Map([[`run-${i}.json`, c]]));
const KEY = generateSigningKey(), OTHER = generateSigningKey();
const envelopes = files.map((m, i) => Buffer.from(signFiles([...m].map(([name, content]) => ({ name, content })), { privateKey: KEY.privatePem, version: '1.0.0', now: at(i) }).envelope));
const keys = join(work, 'keys'); await mkdir(keys, { mode: 0o700 }); await writeFile(join(keys, 'ledger.pub'), KEY.publicPem);
let n = 0;
const fresh = async (count = 3) => {
  const dir = join(work, `ledger-${n++}`); await mkdir(dir, { mode: 0o700 }); await L.initLedger(dir, { now: at(0) });
  for (let i = 0; i < count; i++) await L.appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
  return dir;
};
const append = (dir, i) => L.appendEnvelope(dir, { envelope: envelopes[i], files: files[i], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(i + 0.5) });
const witnessDir = async () => { const d = join(work, `witness-${n++}`); await mkdir(d, { mode: 0o700 }); return d; };
const logOf = async dir => JSON.parse(await readFile(join(dir, 'ledger.json'), 'utf8')).log;
// A witness that has seen this log from the start; returns its key and state folder.
async function newWitness(name, dir) {
  const key = W.generateWitnessKey(name), state = await witnessDir();
  await W.addLog(state, { log: await logOf(dir), ledgerKey: KEY.publicPem });
  return { ...key, state };
}
async function cosignLatest(witness, dir, { oldSize } = {}) {
  const st = JSON.parse(await readFile(join(witness.state, 'witness.json'), 'utf8')), origin = Object.keys(st.logs)[0];
  const request = await L.witnessRequest(dir, { oldSize: oldSize ?? st.logs[origin].size });
  return W.addCheckpoint(witness.state, { name: witness.name, privateKey: witness.privatePem, request, now: at(30) });
}
// Both verifiers, through their CLIs, on a ledger folder and a set of trusted witness vkeys.
async function both(dir, vkeys, quorum, text = `# trusted witnesses\n${vkeys.join('\n')}\n`) {
  const wfile = join(keys, `w-${n++}.txt`); await writeFile(wfile, text);
  const extra = vkeys || text ? ['--witnesses', wfile, ...(quorum ? ['--quorum', String(quorum)] : [])] : [];
  const node = await cli(['verify', '--ledger', dir, '--key', join(keys, 'ledger.pub'), ...extra]);
  if (!PYTHON) return { node: node.output, python: null };
  const p = await python([SCRIPT, 'log', '--key', join(keys, 'ledger.pub'), '--ledger', dir, ...extra]);
  let py; try { py = JSON.parse(p.stdout); } catch { py = { verdict: `crash(${p.code})`, reason: p.stderr.trim().split('\n').at(-1) }; }
  return { node: node.output, python: py };
}
const same = (r, verdict, reason, label) => {
  assert.deepEqual([r.node.verdict, r.node.reason ?? r.node.error ?? null], [verdict, reason], `${label}: Node ${JSON.stringify(r.node).slice(0, 300)}`);
  if (r.python) assert.deepEqual([r.python.verdict, r.python.reason ?? r.python.error ?? null], [verdict, reason], `${label}: Python ${JSON.stringify(r.python).slice(0, 300)}`);
  // When both verified, they report witnessing identically.
  if (r.python && verdict === 'verified') { assert.deepEqual(r.python.witness, r.node.witness, `${label}: witness`); assert.deepEqual(r.python.witnessing, r.node.witnessing, `${label}: witnessing`); }
};

test('the C2SP formats: key id, vkey, signed message and signature line, checked byte by byte', () => {
  const k = W.generateWitnessKey('witness.example/alpha');
  const raw = Buffer.from(createPublicKey(createPrivateKey(k.privatePem)).export({ format: 'jwk' }).x, 'base64url');
  const id = createHash('sha256').update(Buffer.concat([Buffer.from('witness.example/alpha\n'), Buffer.from([4]), raw])).digest().subarray(0, 4).toString('hex');
  assert.equal(k.vkey, `witness.example/alpha+${id}+${Buffer.concat([Buffer.from([4]), raw]).toString('base64')}`);
  const root = 'ab'.repeat(32), line = W.cosign({ name: 'witness.example/alpha', privateKey: k.privatePem, origin: 'scopehaven-ledger/x', treeSize: 7, rootHash: root, time: 1679315147 });
  assert.match(line, /^— witness\.example\/alpha [A-Za-z0-9+/]+={0,2}$/);
  const data = Buffer.from(line.split(' ')[2], 'base64');
  assert.equal(data.length, 76); assert.equal(data.subarray(0, 4).toString('hex'), id); assert.equal(data.readBigUInt64BE(4), 1679315147n);
  assert.equal(V.cosignedMessage('1679315147', V.checkpointNote('scopehaven-ledger/x', 7, root)).toString(), `cosignature/v1\ntime 1679315147\nscopehaven-ledger/x\n7\n${Buffer.from(root, 'hex').toString('base64')}\n`);
});

test('a vkey whose base64 key contains "+" or "/" reads the same in both verifiers', async () => {
  const picked = {};
  for (let i = 0; i < 2000 && !(picked.plus && picked.slash); i++) {
    const k = W.generateWitnessKey(`witness.example/k${i}`), data = k.vkey.split('+').slice(2).join('+');
    if (!picked.plus && data.includes('+')) picked.plus = k.vkey;
    if (!picked.slash && data.includes('/')) picked.slash = k.vkey;
  }
  const vkeys = [picked.plus, picked.slash];
  assert.ok(vkeys.every(Boolean));
  for (const vkey of vkeys) assert.equal(V.readWitnessKey(vkey).name, vkey.slice(0, vkey.indexOf('+')));
  if (!PYTHON) return;
  const program = `import json, sys; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))}); sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('../attest/', import.meta.url)))}); import verify_ledger as v; print(json.dumps([v.read_witness_key(k)["keyId"] for k in json.loads(sys.argv[1])]))`;
  const p = await python(['-c', program, JSON.stringify(vkeys)]);
  assert.equal(p.code, 0, p.stderr);
  assert.deepEqual(JSON.parse(p.stdout), vkeys.map(v => V.readWitnessKey(v).keyId));
});

test('a witness cosigns a growing ledger, and both verifiers report it witnessed', async () => {
  const dir = await fresh(3), alpha = await newWitness('witness.example/alpha', dir);
  assert.equal((await both(dir, [alpha.vkey])).node.witness, 'none', 'no cosignature yet');
  const first = await cosignLatest(alpha, dir);
  assert.equal(first.status, 200, JSON.stringify(first));
  await L.addCosignature(dir, first.cosignature);
  let r = await both(dir, [alpha.vkey]);
  same(r, 'verified', null, 'one witness, size 3');
  assert.deepEqual(r.node.witness, { quorum: 1, witnessedSize: 3, latestCheckpointWitnessed: true });
  if (r.python) { assert.deepEqual(r.python.witness, r.node.witness); assert.deepEqual(r.python.witnessing, r.node.witnessing); }
  assert.deepEqual([r.node.witnessCoverage, r.python?.witnessCoverage ?? 'met'], ['met', 'met']);
  assert.deepEqual(r.node.selfChecks.filter(c => c.id.startsWith('cosignature')).map(c => [c.id, c.observed]), [['cosignature-tampered', 'rejected'], ['cosignature-moved', 'rejected']]);
  // Without a policy the cosignatures are not read, and the result says witness "none" as before.
  const plain = (await cli(['verify', '--ledger', dir, '--key', join(keys, 'ledger.pub')])).output;
  assert.deepEqual([plain.witness, plain.witnessCoverage, 'witnessing' in plain], ['none', 'no-policy', false]);
  if (PYTHON) {
    const p = JSON.parse((await python([SCRIPT, 'log', '--key', join(keys, 'ledger.pub'), '--ledger', dir])).stdout);
    assert.deepEqual([p.witness, p.witnessCoverage, 'witnessing' in p], ['none', 'no-policy', false]);
  }
  // The ledger grows; the witness checks a consistency proof from 3 and cosigns 5.
  await append(dir, 3); await append(dir, 4);
  r = await both(dir, [alpha.vkey]);
  assert.deepEqual(r.node.witness, { quorum: 1, witnessedSize: 3, latestCheckpointWitnessed: false });
  const second = await cosignLatest(alpha, dir);
  assert.equal(second.status, 200); assert.equal(second.cosignature.treeSize, 5);
  await L.addCosignature(dir, second.cosignature);
  r = await both(dir, [alpha.vkey]);
  same(r, 'verified', null, 'size 5');
  assert.equal(r.node.witness.witnessedSize, 5); assert.equal(r.node.witness.latestCheckpointWitnessed, true);
  // Quorum: two trusted witnesses, only one has cosigned, so with quorum 2 nothing counts as witnessed.
  const beta = await newWitness('witness.example/beta', dir);
  r = await both(dir, [alpha.vkey, beta.vkey]);
  same(r, 'verified', null, 'quorum 2, one cosigner');
  assert.equal(r.node.witness, 'none'); assert.equal(r.node.witnessing.witnessedSize, null);
  assert.deepEqual([r.node.witnessCoverage, r.python?.witnessCoverage ?? 'not-met'], ['not-met', 'not-met']);
  assert.equal((await both(dir, [alpha.vkey, beta.vkey], 1)).node.witness.witnessedSize, 5);
  const third = await cosignLatest(beta, dir);
  assert.equal(third.status, 200); await L.addCosignature(dir, third.cosignature);
  r = await both(dir, [alpha.vkey, beta.vkey]);
  assert.deepEqual(r.node.witness, { quorum: 2, witnessedSize: 5, latestCheckpointWitnessed: true });
  if (r.python) assert.deepEqual(r.python.witness, r.node.witness);
});

test('the witness refuses what it must, with tlog-witness status codes, and keeps its state', async () => {
  const dir = await fresh(3), alpha = await newWitness('witness.example/alpha', dir);
  const request = await L.witnessRequest(dir);
  // A witness that throws instead of answering fails the status assertions below, not the test harness.
  const ask = req => W.addCheckpoint(alpha.state, { name: alpha.name, privateKey: alpha.privatePem, request: req, now: at(30) }).catch(error => ({ status: `threw: ${error.message}` }));
  assert.equal((await ask({ ...request, checkpoint: 'not json' })).status, 400);
  assert.equal((await ask({ ...request, oldSize: 4 })).status, 400, 'old size beyond the checkpoint');
  // tlog-witness: a non-empty consistency proof from size 0 does not verify (422), after the 409 check.
  assert.equal((await ask({ ...request, proof: ['00'.repeat(32)] })).status, 422, 'a proof from an empty tree');
  assert.equal((await ask({ ...request, proof: ['00'] })).status, 400, 'a proof hash that is not 32 bytes');
  // Another log's checkpoint: unknown to this witness.
  const other = await fresh(2);
  assert.equal((await ask(await L.witnessRequest(other))).status, 404);
  // Signed by a key the witness does not trust for this log.
  const point = JSON.parse(Buffer.from(JSON.parse(request.checkpoint).payload, 'base64'));
  const meta = JSON.parse(await readFile(join(dir, 'ledger.json'), 'utf8')), lines = (await readFile(join(dir, 'entries.jsonl'), 'utf8')).trim().split('\n');
  const forgedKey = L.signCheckpoint({ log: meta.log, createdAt: meta.createdAt, lines, signedAt: point.signedAt, privateKey: OTHER.privatePem });
  assert.equal((await ask({ ...request, checkpoint: forgedKey })).status, 403);
  // The right key id with a broken signature is refused the same way.
  const broken = JSON.parse(request.checkpoint), sigBytes = Buffer.from(broken.signatures[0].sig, 'base64'); sigBytes[10] ^= 1;
  broken.signatures[0].sig = sigBytes.toString('base64');
  assert.equal((await ask({ ...request, checkpoint: JSON.stringify(broken) })).status, 403);
  // A stale old size: the answer says which size the witness last cosigned.
  assert.equal((await ask(request)).status, 200);
  assert.equal((await ask(request)).status, 409, 'asking again from size 0: the witness is at 3 now');
  assert.equal((await ask({ ...request, oldSize: 3, proof: [] })).status, 200, 'the same checkpoint from size 3 is cosigned again');
  assert.equal((await ask({ ...request, oldSize: 3, proof: ['00'.repeat(32)] })).status, 422, 'a non-empty proof between equal sizes');
  await append(dir, 3);
  const grown = await L.witnessRequest(dir, { oldSize: 1 });
  const conflict = await ask(grown);
  assert.equal(conflict.status, 409); assert.equal(conflict.size, 3);
  // The operator shows a second history: entry 3 replaced. At the same size it is a different root, and
  // grown to 4 it is not a consistent extension of what the witness cosigned. Both are refused (422).
  const fs = await import('node:fs/promises');
  const forkDir = join(work, `fork-${n++}`); await mkdir(forkDir, { mode: 0o700 }); await mkdir(join(forkDir, 'envelopes'), { mode: 0o700 });
  await writeFile(join(forkDir, 'ledger.json'), await readFile(join(dir, 'ledger.json')));
  for (const name of await fs.readdir(join(dir, 'envelopes'))) await writeFile(join(forkDir, 'envelopes', name), await readFile(join(dir, 'envelopes', name)));
  await writeFile(join(forkDir, 'entries.jsonl'), `${lines.slice(0, 2).join('\n')}\n`);
  await writeFile(join(forkDir, 'checkpoints.jsonl'), `${(await readFile(join(dir, 'checkpoints.jsonl'), 'utf8')).trim().split('\n').slice(0, 2).join('\n')}\n`);
  await L.appendEnvelope(forkDir, { envelope: envelopes[4], files: files[4], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(9) });
  const sameSize = await L.witnessRequest(forkDir, { oldSize: 3 });
  assert.equal(JSON.parse(Buffer.from(JSON.parse(sameSize.checkpoint).payload, 'base64')).treeSize, 3);
  assert.equal((await ask(sameSize)).status, 422, 'same size, different root');
  await L.appendEnvelope(forkDir, { envelope: envelopes[3], files: files[3], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(10) });
  assert.equal((await ask(await L.witnessRequest(forkDir, { oldSize: 3 }))).status, 422, 'grown fork');
  // Refusals leave the state where the last cosignature put it.
  assert.equal(JSON.parse(await readFile(join(alpha.state, 'witness.json'), 'utf8')).logs[`scopehaven-ledger/${meta.log}`].size, 3);
});

test('both verifiers reject a bad cosignature, a rollback and a fork, and ignore keys they do not trust', async () => {
  const dir = await fresh(3), alpha = await newWitness('witness.example/alpha', dir);
  await append(dir, 3);
  const cosigned = await cosignLatest(alpha, dir);
  await L.addCosignature(dir, cosigned.cosignature);
  same(await both(dir, [alpha.vkey]), 'verified', null, 'baseline');
  const copy = async (mutate) => {
    const d = join(work, `case-${n++}`); await mkdir(d, { mode: 0o700 }); await mkdir(join(d, 'envelopes'), { mode: 0o700 });
    const fs = await import('node:fs/promises');
    for (const f of ['ledger.json', 'entries.jsonl', 'checkpoints.jsonl', 'cosignatures.jsonl']) await writeFile(join(d, f), await readFile(join(dir, f)));
    for (const name of await fs.readdir(join(dir, 'envelopes'))) await writeFile(join(d, 'envelopes', name), await readFile(join(dir, 'envelopes', name)));
    await mutate(d); return d;
  };
  const record = cosigned.cosignature;
  const line = r => `${JSON.stringify(r)}\n`;
  // A trusted key's signature that does not verify.
  const data = Buffer.from(record.cosignature.split(' ')[2], 'base64'); data[40] ^= 1;
  same(await both(await copy(d => writeFile(join(d, 'cosignatures.jsonl'), line({ ...record, cosignature: `— witness.example/alpha ${data.toString('base64')}` }))), [alpha.vkey]), 'rejected', 'cosignature-invalid', 'flipped signature');
  // A valid signature moved to another size or root does not verify either.
  same(await both(await copy(d => writeFile(join(d, 'cosignatures.jsonl'), line({ ...record, treeSize: 3 }))), [alpha.vkey]), 'rejected', 'cosignature-invalid', 'moved to size 3');
  // Malformed lines.
  for (const [label, text] of [['not JSON', 'nope\n'], ['missing field', line({ treeSize: 4, rootHash: record.rootHash })], ['short signature', line({ ...record, cosignature: '— witness.example/alpha AAAA' })],
    ['not canonical', `${JSON.stringify(record, null, 1).replace(/\n/g, '')}\n`], ['size 0', line({ ...record, treeSize: 0 })],
    ['time past 2^53', line({ ...record, cosignature: `\u2014 witness.example/alpha ${Buffer.concat([data.subarray(0, 4), Buffer.alloc(8, 0xff), data.subarray(12)]).toString('base64')}` })]]) {
    same(await both(await copy(d => writeFile(join(d, 'cosignatures.jsonl'), text)), [alpha.vkey]), 'rejected', 'cosignature-shape', label);
  }
  // Rollback: the operator cuts the ledger back to 3 entries and re-signs; the witness saw 4.
  same(await both(await copy(async d => {
    await writeFile(join(d, 'entries.jsonl'), `${(await readFile(join(dir, 'entries.jsonl'), 'utf8')).trim().split('\n').slice(0, 3).join('\n')}\n`);
    await writeFile(join(d, 'checkpoints.jsonl'), `${(await readFile(join(dir, 'checkpoints.jsonl'), 'utf8')).trim().split('\n').slice(0, 3).join('\n')}\n`);
  }), [alpha.vkey]), 'rejected', 'witness-rollback', 'rolled back to 3');
  // Fork: the operator rewrites entry 4 and re-signs a checkpoint at the same size.
  same(await both(await copy(async d => {
    const lines = (await readFile(join(dir, 'entries.jsonl'), 'utf8')).trim().split('\n').slice(0, 3);
    await writeFile(join(d, 'entries.jsonl'), `${lines.join('\n')}\n`);
    await writeFile(join(d, 'checkpoints.jsonl'), `${(await readFile(join(dir, 'checkpoints.jsonl'), 'utf8')).trim().split('\n').slice(0, 3).join('\n')}\n`);
    await L.appendEnvelope(d, { envelope: envelopes[4], files: files[4], evidenceKey: KEY.publicPem, privateKey: KEY.privatePem, now: at(9) });
  }), [alpha.vkey]), 'rejected', 'witness-fork', 'another entry at size 4');
  // Keys the reader does not trust are ignored, including one that shares the name but not the key id.
  const impostor = W.generateWitnessKey('witness.example/alpha'), other = W.generateWitnessKey('witness.example/other');
  const fake = W.cosign({ name: 'witness.example/alpha', privateKey: impostor.privatePem, origin: `scopehaven-ledger/${await logOf(dir)}`, treeSize: 4, rootHash: record.rootHash, time: 1 });
  const r = await both(await copy(d => writeFile(join(d, 'cosignatures.jsonl'), line({ ...record, cosignature: fake }) + line(record))), [alpha.vkey]);
  same(r, 'verified', null, 'impostor ignored'); assert.equal(r.node.witnessing.ignored, 1);
  if (r.python) assert.equal(r.python.witnessing.ignored, 1);
  const untrusted = await both(dir, [other.vkey]);
  same(untrusted, 'verified', null, 'no trusted cosigner'); assert.equal(untrusted.node.witness, 'none'); assert.equal(untrusted.node.witnessing.ignored, 1);
  // Policy errors: a bad vkey, a key id that does not match, a quorum out of range, two keys one name.
  const parts = [alpha.vkey.slice(0, alpha.vkey.indexOf('+')), alpha.vkey.split('+')[1], alpha.vkey.split('+').slice(2).join('+')];
  const wrongType = Buffer.from(parts[2], 'base64'); wrongType[0] = 1;
  for (const [label, vkeys, quorum] of [['not a vkey', ['nonsense'], undefined], ['key id', [`${parts[0]}+00000000+${parts[2]}`], undefined],
    ['type byte 0x01, same key id', [`${parts[0]}+${parts[1]}+${wrongType.toString('base64')}`], undefined],
    ['same name twice', [alpha.vkey, impostor.vkey], undefined], ['quorum 2 of 1', [alpha.vkey], 2]]) {
    same(await both(dir, vkeys, quorum), 'rejected', 'witness-policy', label);
  }
  // One key under two names (C2SP: distinct cosigners use distinct keys). The cosigned message does not
  // name the cosigner, so the operator can relabel alpha's line as the alias and it verifies; listed
  // together they would count twice toward a quorum of 2. The policy is refused instead.
  const alias = W.vkeyOf('witness.example/alias', createPublicKey(createPrivateKey(alpha.privatePem)));
  const aliasId = alias.split('+')[1], relabelled = Buffer.from(data); relabelled[40] ^= 1; // restore the flipped byte
  Buffer.from(aliasId, 'hex').copy(relabelled, 0);
  const twice = await copy(d => writeFile(join(d, 'cosignatures.jsonl'), line(record) + line({ ...record, cosignature: `\u2014 witness.example/alias ${relabelled.toString('base64')}` })));
  same(await both(twice, [alias]), 'verified', null, 'the relabelled line verifies under the alias alone');
  same(await both(twice, [alpha.vkey, alias], 2), 'rejected', 'witness-policy', 'one key under two names');
  same(await both(twice, [alias, alpha.vkey], 1), 'rejected', 'witness-policy', 'one key under two names, quorum 1');
  // The API's quorum null means the default (all), as Python's None does.
  const api = V.verifyLedger({ ...(await L.readLedgerFiles(dir)), ledgerKey: KEY.publicPem, witnesses: [alpha.vkey], quorum: null });
  assert.deepEqual([api.verdict, api.reason ?? null, api.witness?.quorum], ['verified', null, 1]);
});

test('witness names follow the C2SP cosigner-name rule, the same in both verifiers and the witness', async () => {
  const good = ['witness.example/alpha', 'witness.example/α', '#w', 'w#', 'x\x7f', 'é'.repeat(127) + 'a', '证人/一'];
  const bad = ['', 'a b', 'a+b', 'a\tb', 'a\nb', 'a\x1fb', 'a\x85b', 'a\u00a0b', 'a\u1680b', 'a\u2009b', 'a\u2028b', 'a\u202fb', 'a\u3000b', 'é'.repeat(128), 'a\ud800'];
  assert.deepEqual(good.map(V.cosignerName), good.map(() => true));
  assert.deepEqual(bad.map(V.cosignerName), bad.map(() => false));
  for (const name of bad) assert.throws(() => W.generateWitnessKey(name), /cosigner|witness name/);
  // The exported signing helper checks its inputs too, not only the guarded entry points.
  const signer = W.generateWitnessKey('witness.example/alpha'), args = { name: 'witness.example/alpha', privateKey: signer.privatePem, origin: 'scopehaven-ledger/x', treeSize: 1, rootHash: 'ab'.repeat(32), time: 1 };
  assert.match(W.cosign(args), /^\u2014 witness\.example\/alpha /);
  for (const name of ['a b', 'a\u00a0b', 'é'.repeat(128), '']) assert.throws(() => W.cosign({ ...args, name }), /witness name/, JSON.stringify(name));
  for (const change of [{ treeSize: 0 }, { rootHash: 'AB'.repeat(32) }, { origin: 'other/x' }, { origin: 'scopehaven-ledger/x\n9' }]) assert.throws(() => W.cosign({ ...args, ...change }), /cosign takes/, JSON.stringify(change));
  if (PYTHON) {
    const program = `import json, sys; sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('.', import.meta.url)))}); sys.path.insert(0, ${JSON.stringify(fileURLToPath(new URL('../attest/', import.meta.url)))}); import verify_ledger as v; print(json.dumps([v.cosigner_name(n) for n in json.loads(sys.argv[1])]))`;
    const p = await python(['-c', program, JSON.stringify([...good, ...bad])]);
    assert.equal(p.code, 0, p.stderr);
    assert.deepEqual(JSON.parse(p.stdout), [...good.map(() => true), ...bad.map(() => false)]);
  }
  // A UTF-8 name and a name starting with "#" go through the whole flow: cosign, store, verify, in both.
  const dir = await fresh(3), utf = await newWitness('witness.example/α', dir), hash = await newWitness('#witness', dir);
  for (const w of [utf, hash]) { const r = await cosignLatest(w, dir); assert.equal(r.status, 200, JSON.stringify(r)); await L.addCosignature(dir, r.cosignature); }
  let r = await both(dir, [utf.vkey, hash.vkey]);
  same(r, 'verified', null, 'UTF-8 and "#" names');
  assert.deepEqual(r.node.witness, { quorum: 2, witnessedSize: 3, latestCheckpointWitnessed: true });
  assert.deepEqual(r.node.witnessing.cosigned, [{ treeSize: 3, witnesses: ['#witness', 'witness.example/α'] }]);
  // The key file: a "#" name is a key, "# " starts a comment, spaces and tabs around a line are dropped,
  // and a key disabled as "#vkey" (its key id no longer matches the name) fails instead of being skipped.
  r = await both(dir, null, 1, `#\n# comment\n#\tcomment\n  ${hash.vkey}\t\r\n\n# ${utf.vkey}\n`);
  same(r, 'verified', null, 'key file with comments');
  assert.deepEqual(r.node.witnessing.trusted, ['#witness']);
  same(await both(dir, null, undefined, `${hash.vkey}\n#${utf.vkey}\n`), 'rejected', 'witness-policy', 'a key disabled without a space');
  // Only spaces and tabs are dropped, in both: a byte-order mark or a no-break space stays and the key fails.
  same(await both(dir, null, undefined, `\ufeff${hash.vkey}\n`), 'rejected', 'witness-policy', 'a byte-order mark before the key');
  same(await both(dir, null, undefined, `${hash.vkey}\u00a0\n`), 'rejected', 'witness-policy', 'a no-break space after the key');
  // The witness refuses to sign under a name that breaks the rule, before it moves its state: here the
  // ledger has grown to 4, and the witness must still be at 3 afterwards.
  await append(dir, 3);
  await assert.rejects(W.addCheckpoint(utf.state, { name: 'a b', privateKey: utf.privatePem, request: await L.witnessRequest(dir, { oldSize: 3 }), now: at(30) }), /witness name/);
  assert.equal(Object.values(JSON.parse(await readFile(join(utf.state, 'witness.json'), 'utf8')).logs)[0].size, 3);
  // A cosignature line whose name breaks the rule is malformed in both verifiers; the operator will not store one.
  const { cosignature } = await cosignLatest(utf, dir, { oldSize: 3 });
  const sig = cosignature.cosignature.split(' ')[2];
  for (const name of ['witness.example/a\u00a0b', 'a\u2028b', 'é'.repeat(128)]) {
    const d = await fresh(3);
    await writeFile(join(d, 'cosignatures.jsonl'), `${JSON.stringify({ ...cosignature, cosignature: `\u2014 ${name} ${sig}` })}\n`);
    same(await both(d, [utf.vkey]), 'rejected', 'cosignature-shape', `name ${JSON.stringify(name)}`);
    await assert.rejects(L.addCosignature(d, { ...cosignature, cosignature: `\u2014 ${name} ${sig}` }), /Not a cosignature record/);
  }
});

test('the operator stores only cosignatures that name a tree this ledger has', async () => {
  const dir = await fresh(3), alpha = await newWitness('witness.example/alpha', dir);
  const { cosignature } = await cosignLatest(alpha, dir);
  await assert.rejects(L.addCosignature(dir, { ...cosignature, rootHash: '0'.repeat(64) }), /no tree with that root/);
  await assert.rejects(L.addCosignature(dir, { ...cosignature, treeSize: 9 }), /no tree with that root/);
  await assert.rejects(L.addCosignature(dir, { ...cosignature, extra: 1 }), /Not a cosignature record/);
  assert.equal(existsSync(join(dir, 'cosignatures.jsonl')), false);
  // The CLI path: request from the ledger, cosign with the witness CLI, store with add-cosignature.
  const out = join(work, `cli-${n++}`); await mkdir(out, { mode: 0o700 });
  const keygen = await W.main(['keygen', '--name', 'witness.example/cli', '--out', join(out, 'w')]);
  assert.equal(keygen.code, 0);
  const state = join(out, 'state'); await mkdir(state, { mode: 0o700 });
  assert.equal((await W.main(['add-log', '--state', state, '--ledger-key', join(keys, 'ledger.pub'), '--log', await logOf(dir)])).code, 0);
  const request = await cli(['witness-request', '--ledger', dir]);
  await writeFile(join(out, 'request.json'), JSON.stringify(request.output));
  const answer = await W.main(['add-checkpoint', '--state', state, '--name', 'witness.example/cli', '--key', join(out, 'w', 'witness.key'), '--request', join(out, 'request.json')]);
  assert.equal(answer.code, 0, JSON.stringify(answer.output));
  await writeFile(join(out, 'answer.json'), JSON.stringify(answer.output));
  assert.equal((await cli(['add-cosignature', '--ledger', dir, '--cosignature', join(out, 'answer.json')])).code, 0);
  const r = await both(dir, [keygen.output.vkey]);
  same(r, 'verified', null, 'CLI round trip'); assert.equal(r.node.witness.witnessedSize, 3);
  await chmod(join(out, 'w', 'witness.key'), 0o644);
  assert.match((await W.main(['add-checkpoint', '--state', state, '--name', 'witness.example/cli', '--key', join(out, 'w', 'witness.key'), '--request', join(out, 'request.json')])).output.error, /mode 0600/);
});
