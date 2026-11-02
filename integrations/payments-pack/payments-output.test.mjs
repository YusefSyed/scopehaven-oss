// Writing payments runs (output.mjs writeRun) and reading fresh ones back (savedPaymentsRun). `payments run --out DIR` makes a
// missing DIR 0700 whatever the umask, and keeps an existing one as it is. And the owned demo's two fresh runs, as written to disk,
// are each accepted by savedPaymentsRun: the export's checks copy the pack's run fields, row rules and scope, and
// the checked-in samples are older, so a pack change that made every new run unexportable would fail here first. Owned synthetic
// app and payments double only: every listener and connection is on 127.0.0.1, every file is under a fresh temporary directory,
// and nothing is signed, so no key directory is read or made.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Socket, Server } from 'node:net';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeRun, savedPaymentsRun } from './output.mjs';
import { PAYMENTS_RUN_SCHEMA } from './pack.mjs';
import { runDemo } from './demo/demo.mjs';

const connections = [], listeners = [];
const connect = Socket.prototype.connect, listen = Server.prototype.listen;
Socket.prototype.connect = function (...args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  connections.push(first && typeof first === 'object' ? (first.host ?? first.path ?? 'localhost') : args[1]);
  return connect.apply(this, args);
};
Server.prototype.listen = function (...args) {
  listeners.push(typeof args[0] === 'object' ? args[0].host : args[1]);
  return listen.apply(this, args);
};
const SAMPLE = name => fileURLToPath(new URL(`./sample/${name}`, import.meta.url));
const mode = async path => (await stat(path)).mode & 0o777;
async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven payments output '));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('payments run --out: a missing directory (and a missing parent) is made 0700 under a 022 umask; an existing one keeps its mode', async t => {
  const root = await workspace(t), { comparison: _, ...run } = JSON.parse(await readFile(SAMPLE('before-vulnerable.json'), 'utf8'));
  const umask = process.umask(0o022);
  t.after(() => process.umask(umask));
  const out = join(root, 'new parent', 'runs');
  const files = await writeRun(out, run);
  assert.equal(await mode(join(root, 'new parent')), 0o700); assert.equal(await mode(out), 0o700);
  assert.deepEqual((await readdir(out)).sort(), [`${run.id}.html`, `${run.id}.json`]);
  for (const file of [files.json, files.html]) assert.equal(await mode(file), 0o600, file);
  // A directory the user made is theirs: never chmodded, never replaced.
  const own = join(root, 'my runs'); await mkdir(own, { mode: 0o755 }); await chmod(own, 0o755);
  const inode = (await lstat(own)).ino;
  await writeRun(own, run);
  assert.equal(await mode(own), 0o755); assert.equal((await lstat(own)).ino, inode);
  assert.deepEqual((await readdir(own)).sort(), [`${run.id}.html`, `${run.id}.json`]);
});

test('the owned demo\'s two fresh runs, read back from the files it writes, are each accepted by savedPaymentsRun', async t => {
  const root = await workspace(t), result = await runDemo(join(root, 'demo'));
  const accepted = [];
  for (const side of ['before', 'after']) {
    assert.equal(await mode(join(root, 'demo', side)), 0o700, side);
    const saved = JSON.parse(await readFile(result[side].run, 'utf8'));
    assert.equal(saved.schema, PAYMENTS_RUN_SCHEMA);
    const run = savedPaymentsRun(saved, `the demo's ${side} run`);
    assert.equal(run.id, result[side].id); assert.equal(Object.hasOwn(run, 'comparison'), false, 'a stored comparison is not part of the run');
    accepted.push(run);
  }
  // The after run stores the comparison `payments run --baseline` adds; the before run stores none.
  assert.equal(Object.hasOwn(JSON.parse(await readFile(result.before.run, 'utf8')), 'comparison'), false);
  assert.equal(Object.hasOwn(JSON.parse(await readFile(result.after.run, 'utf8')), 'comparison'), true);
  // Two different runs: the vulnerable build fails rows, the repaired one passes every row.
  assert.notEqual(accepted[0].id, accepted[1].id);
  assert.ok(accepted[0].counts.fail > 0, JSON.stringify(accepted[0].counts)); assert.equal(accepted[1].counts.fail + accepted[1].counts.inconclusive, 0, JSON.stringify(accepted[1].counts));
  assert.ok(listeners.length > 0 && connections.length > 0);
  for (const host of listeners) assert.ok(['127.0.0.1', '::1'].includes(host), `listen on ${host}`);
  for (const host of connections) assert.ok(['127.0.0.1', '::1'].includes(host), `connect to ${host}`);
});
