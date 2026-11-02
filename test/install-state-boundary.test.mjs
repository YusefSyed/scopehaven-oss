import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cp, lstat, mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

// An assessment must keep its state inside the configured data directory.
// Each check runs the real CLI from a private copy of the workbench, so the
// whole copy (including directory mtimes, which change on any transient create
// or delete) can be compared before and after. Only owned synthetic fixtures
// run; no provider or network call.
const PROJECT = fileURLToPath(new URL('../', import.meta.url));

async function snapshot(root) {
  const entries = {};
  async function walk(path) {
    const stat = await lstat(path, { bigint: true });
    const key = relative(root, path) || '.';
    entries[key] = stat.isDirectory() ? `dir:${stat.mode}:${stat.mtimeNs}` : `${stat.isFile() ? 'file' : 'other'}:${stat.mode}:${stat.size}:${stat.mtimeNs}`;
    if (stat.isDirectory()) for (const name of (await readdir(path)).sort()) await walk(join(path, name));
  }
  await walk(root);
  return entries;
}
// Private copy of the CLI's import graph.
async function privateWorkbench(t) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven-install-state-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const app = join(root, 'app'), systemTemp = join(root, 'tmp'), evidence = join(root, 'evidence');
  await mkdir(systemTemp, { mode: 0o700 });
  await cp(join(PROJECT, 'src'), join(app, 'src'), { recursive: true });
  await cp(join(PROJECT, 'package.json'), join(app, 'package.json'));
  // compareRuns attributes model changes: src/runner.mjs imports attribute.mjs and its closure.
  for (const name of ['attribute.mjs', 'identity.mjs', 'tap.mjs']) await cp(join(PROJECT, 'integrations/model-identity', name), join(app, 'integrations/model-identity', name));
  await cp(join(PROJECT, 'integrations/observers/events.mjs'), join(app, 'integrations/observers/events.mjs'));
  // loadProfiles reads every profile through the watch-first drafted-line gate (src/registry.mjs).
  await cp(join(PROJECT, 'integrations/watch-first/lines.mjs'), join(app, 'integrations/watch-first/lines.mjs'));
  // The HTTP effect rules decide effect.only with it (src/http-effects.mjs), and it is in the HTTP evaluator hash.
  await cp(join(PROJECT, 'integrations/collateral/only.mjs'), join(app, 'integrations/collateral/only.mjs'));
  // Store/registry load refund finalization, and the CLI imports the canonical
  // gate. Copy their actual module closure even when assessing another target.
  await cp(join(PROJECT, 'integrations/regression-gate/gate.mjs'), join(app, 'integrations/regression-gate/gate.mjs'));
  for (const name of ['targets.mjs', 'contract.mjs', 'evaluator.mjs', 'runner.mjs', 'identity.mjs', 'persistence.mjs', 'evidence.mjs', 'binding.mjs', 'fixtures/refund-app.mjs']) {
    await cp(join(PROJECT, 'integrations/temporal-contracts', name), join(app, 'integrations/temporal-contracts', name));
  }
  // payments-double imports the observer factory; its adapters must resolve,
  // although these SupportDesk assessments do not instantiate them.
  for (const name of ['payments-double.mjs', 'factory.mjs', 'sink-ledger.mjs', 'audit-file.mjs', 'audit-http.mjs', 'egress-recorder.mjs', 'egress-forward.mjs', 'mcp.mjs',
    'mysql-snapshot.mjs', 'mysql-wire.mjs', 'otel.mjs', 'pg-snapshot.mjs', 'pg-wire.mjs', 'smtp-sink.mjs', 'provider-feed.mjs', 'request-feed.mjs', 'read-back.mjs', 'app-log.mjs', 'sqlite.mjs', 'fixtures/free-port.mjs',
    // The database observers' background-writer rules: the ignore-list reader and its lists, the end barrier, the run lease.
    'end-barrier.mjs', 'run-lease.mjs', 'ignore-lists/ignore-list.mjs', 'ignore-lists/supabase.json', 'ignore-lists/litestream.json',
    // The catalog fingerprint the database observers read at each mark.
    'catalog.mjs',
    // Read (never imported) by src/collector-identity.mjs at import, for the pg-wal/1 and dns-stub/1 collector records.
    'pg-wal.mjs', 'dns-stub.mjs', 'dns-wire.mjs',
    // The actor capture both Postgres observers import, and the Supabase rules pg-snapshot and the factory import.
    'pg-actor.mjs', 'supabase-rules.mjs',
    // pg_net on the wire, which the factory imports for a pg-wal observer's pgNetWire.
    'pg-net-wire.mjs']) {
    await cp(join(PROJECT, 'integrations/observers', name), join(app, 'integrations/observers', name));
  }
  return { root, app, systemTemp, evidence };
}
function cli(copy, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(copy.app, 'src/cli.mjs'), ...args], { cwd: copy.app, env: { TMPDIR: `${copy.systemTemp}/` }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
    child.on('error', reject);
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}
async function assertOnlyEvidenceChanged(copy, before) {
  assert.deepEqual(await snapshot(copy.app), before.app, 'the workbench copy must be unchanged outside the data directory');
  assert.deepEqual(await snapshot(copy.systemTemp), before.systemTemp, 'TMPDIR must not be used');
  const rootEntries = (await readdir(copy.root)).sort();
  assert.deepEqual(rootEntries, ['app', 'evidence', 'tmp']);
  for (const directory of ['', 'runs', 'notes']) assert.equal((await lstat(join(copy.evidence, directory))).mode & 0o777, 0o700);
}

test('state snapshot detects a transient create-and-delete outside the data directory', async t => {
  const copy = await privateWorkbench(t);
  const before = await snapshot(copy.app);
  const marker = join(copy.app, 'src', '.transient-marker');
  await writeFile(marker, 'x'); await rm(marker);
  assert.notDeepEqual(await snapshot(copy.app), before);
});

test('SupportDesk CLI assessments write only inside the configured data directory', async t => {
  const copy = await privateWorkbench(t);
  const before = { app: await snapshot(copy.app), systemTemp: await snapshot(copy.systemTemp) };
  const vulnerable = await cli(copy, ['--target', 'demo-vulnerable', '--out', copy.evidence]);
  assert.equal(vulnerable.code, 1, vulnerable.stderr);
  assert.deepEqual(JSON.parse(vulnerable.stdout).counts, { pass: 18, fail: 26, inconclusive: 0, error: 0 });
  const repaired = await cli(copy, ['--target', 'demo-repaired', '--out', copy.evidence]);
  assert.equal(repaired.code, 0, repaired.stderr);
  assert.equal(JSON.parse(repaired.stdout).counts.pass, 44);
  await assertOnlyEvidenceChanged(copy, before);
  const runs = (await readdir(join(copy.evidence, 'runs'))).sort();
  assert.deepEqual(runs, [`${JSON.parse(vulnerable.stdout).id}.json`, `${JSON.parse(repaired.stdout).id}.json`].sort());
});
