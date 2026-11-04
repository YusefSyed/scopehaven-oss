import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NODE_ENGINES, SECURITY_NODE_LINES, SUPPORTED_NODE_LINES, assertRuntime } from '../src/runtime.mjs';

// Local launcher checks only: fake Node scripts in private temp directories,
// loopback port probes and read-only doctor runs. No install, network or provider.
const PROJECT = fileURLToPath(new URL('../', import.meta.url));
const LAUNCHER = join(PROJECT, 'scopehaven');
const launcherText = await readFile(LAUNCHER, 'utf8');
const BASE_ENV = { PATH: '/usr/bin:/bin' };

function launch(args, { env = {}, cwd = PROJECT, launcher = LAUNCHER } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(launcher, args, { cwd, env: { ...BASE_ENV, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 60000);
    child.stdout.on('data', bytes => { stdout += bytes; });
    child.stderr.on('data', bytes => { stderr += bytes; });
    child.on('error', reject);
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}
async function privateDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), 'scopehaven-install-launcher-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}
// A stand-in "node" that reports a chosen version for the launcher's probe and
// otherwise echoes what the launcher would have executed. It runs nothing else.
async function fakeNode(directory, version) {
  const path = join(directory, `node-${version || 'silent'}`);
  await writeFile(path, `#!/bin/sh\nif [ "$1" = -e ]; then printf '%s' '${version}'; else printf 'EXEC %s\\n' "$*"; fi\n`, { mode: 0o700 });
  return path;
}
// The same stand-in, also naming the folder it was started in.
async function fakeNodeInFolder(directory, version) {
  const path = join(directory, `node-${version}-folder`);
  await writeFile(path, `#!/bin/sh\nif [ "$1" = -e ]; then printf '%s' '${version}'; else printf 'IN %s\\nEXEC %s\\n' "$(pwd -P)" "$*"; fi\n`, { mode: 0o700 });
  return path;
}
// An npm install's layout, with the launcher copied in: node_modules/.bin/scopehaven is a relative symlink to it.
async function npmInstall(directory) {
  const root = join(directory, 'app', 'node_modules', 'scopehaven'), bin = join(directory, 'app', 'node_modules', '.bin');
  await mkdir(root, { recursive: true }); await mkdir(bin);
  await copyFile(LAUNCHER, join(root, 'scopehaven')); await chmod(join(root, 'scopehaven'), 0o755);
  await symlink('../scopehaven/scopehaven', join(bin, 'scopehaven'));
  return { root: await realpath(root), bin: join(bin, 'scopehaven') };
}

test('launcher is POSIX sh and its pins match package.json engines and the runtime gate', async () => {
  assert.equal(launcherText.split('\n')[0], '#!/bin/sh');
  assert.equal(spawnSync('/bin/sh', ['-n', LAUNCHER]).status, 0);
  assert.notEqual((await stat(LAUNCHER)).mode & 0o100, 0, 'launcher must stay executable');
  const pkg = JSON.parse(await readFile(join(PROJECT, 'package.json'), 'utf8'));
  assert.equal(/^scopehaven_engines='([^']+)'$/m.exec(launcherText)?.[1], pkg.engines.node);
  assert.equal(/^scopehaven_min_nodes='([^']+)'$/m.exec(launcherText)?.[1], Object.values(SUPPORTED_NODE_LINES).join(' '));
  assert.equal(/^scopehaven_security_nodes='([^']+)'$/m.exec(launcherText)?.[1], Object.values(SECURITY_NODE_LINES).join(' '));
  assert.equal(pkg.engines.node, NODE_ENGINES);
  assert.equal(NODE_ENGINES, '>=22.13.0 <23 || >=24.0.0 <25', 'the 22 and 24 LTS lines, each from its first release with node:sqlite and no flag');
  // The pinned download, .nvmrc and .node-version name one version, at or above the minimum.
  const pinned = /^scopehaven_pinned_node="\$scopehaven_root\/\.runtime\/node-v(\S+)-darwin-arm64\/bin\/node"$/m.exec(launcherText)?.[1];
  for (const file of ['.nvmrc', '.node-version']) assert.equal((await readFile(join(PROJECT, file), 'utf8')).trim(), pinned, file);
  assert.doesNotThrow(() => assertRuntime(pinned));
  assert.equal(launcherText.includes('/Users/'), false, 'launcher must not contain a home path');
});

test('version gate accepts only the engines range (22 and 24 LTS at their floors) and explains how to get a supported Node', async t => {
  const directory = await privateDirectory(t);
  for (const [version, accepted, warned] of [['24.22.1', true], ['24.22.2', true], ['24.23.0', true], ['24.30.1', true], ['22.23.4', true], ['22.23.10', true], ['22.24.0', true],
    ['24.22.0', true, true], ['24.21.9', true, true], ['24.21.0', true, true], ['24.18.0', true, true], ['24.0.0', true, true], ['22.23.3', true, true], ['22.22.9', true, true], ['22.13.0', true, true],
    ['22.12.9', false], ['22.0.0', false], ['23.0.0', false], ['23.99.0', false],
    ['20.20.2', false], ['25.0.0', false], ['18.20.4', false], ['24.22.1-rc.1', false], ['24.22', false], ['', false]]) {
    const node = await fakeNode(directory, version);
    const result = await launch(['check-config'], { env: { SCOPEHAVEN_NODE: node } });
    if (accepted) {
      assert.equal(result.code, 0, version);
      assert.equal(result.stdout, 'EXEC src/cli.mjs --check-config\n', version);
      if (warned) assert.ok(result.stderr.includes(`Warning: Node v${version} is below the October 2026 security release`), `${version}: ${result.stderr}`);
      else assert.equal(result.stderr, '', version);
      continue;
    }
    assert.equal(result.code, 2, version);
    assert.equal(result.stdout, '', `${version}: nothing may run`);
    assert.ok(result.stderr.includes(`needs Node.js ${NODE_ENGINES}`), `${version}: ${result.stderr}`);
    assert.match(result.stderr, /Get Node\.js 22 LTS \(22\.23\.4 or newer\) or 24 LTS \(24\.22\.1 or newer\) from https:\/\/nodejs\.org\/en\/download \(official installer or tarball; verify it against that release's SHASUMS256\.txt\)\./);
    assert.match(result.stderr, version ? new RegExp(`v${version.replaceAll('.', '\\.')} from SCOPEHAVEN_NODE`) : /did not run/);
    assert.match(result.stderr, /https:\/\/nodejs\.org\/en\/download/);
    assert.match(result.stderr, /SCOPEHAVEN_NODE=\/absolute\/path\/to\/node \.\/scopehaven doctor/);
  }
});

test('SCOPEHAVEN_NODE is resolved from the caller directory; a missing override fails clearly without fallback', async t => {
  const directory = await privateDirectory(t);
  await fakeNode(directory, '24.22.1');
  const relative = await launch(['assess', '--list'], { cwd: directory, env: { SCOPEHAVEN_NODE: 'node-24.22.1' } });
  assert.equal(relative.code, 0);
  assert.equal(relative.stdout, 'EXEC src/cli.mjs --list\n');
  const missing = await launch(['start'], { env: { SCOPEHAVEN_NODE: join(directory, 'absent-node') } });
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /selected runtime from SCOPEHAVEN_NODE did not run/);
  assert.equal(missing.stdout, '');
  const unknown = await launch(['not-an-action'], { env: { SCOPEHAVEN_NODE: process.execPath } });
  assert.equal(unknown.code, 2);
  assert.match(unknown.stderr, /Usage: \.\/scopehaven doctor\|start\|test/);
});

test('every usage action runs with a supported Node, and every package.json script has the same launcher action', async t => {
  const directory = await privateDirectory(t);
  const node = await fakeNode(directory, '24.22.1');
  const actions = /^scopehaven_usage='Usage: \.\/scopehaven ([^']+)'$/m.exec(launcherText)[1].split('|').filter(action => action !== 'doctor');
  const scripts = JSON.parse(await readFile(join(PROJECT, 'package.json'), 'utf8')).scripts;
  for (const action of actions) {
    const result = await launch([action, 'probe-arg'], { env: { SCOPEHAVEN_NODE: node } });
    assert.equal(result.code, 0, `${action}: ${result.stderr}`);
    // test passes its arguments before the file list, where Node reads test-runner options (after it, an option such
    // as --test-shard is silently ignored); every other action appends them.
    assert.match(result.stdout, action === 'test' ? /^EXEC test\/support\/bounded-run\.mjs probe-arg test\/\S+\.test\.mjs .*\.test\.mjs\n$/ : /^EXEC .* probe-arg\n$/, action);
  }
  for (const [name, command] of Object.entries(scripts)) {
    if (name === 'prepublishOnly') continue; // npm's publish hook, not an action (test/npm-bin.test.mjs runs it)
    assert.ok(actions.includes(name), `package.json script ${name} has no launcher action`);
    if (name === 'test') continue; // the launcher expands the same globs, so compare it by exit code only (above)
    const result = await launch([name, 'probe-arg'], { env: { SCOPEHAVEN_NODE: node } });
    assert.equal(result.stdout, `EXEC ${command.replace(/^node /, '')} probe-arg\n`, name);
  }
});

test('a symlink to the launcher finds the project, through a relative chain and a folder with a space; a checkout still runs from its root', async t => {
  const directory = await privateDirectory(t), project = await realpath(PROJECT);
  const node = await fakeNodeInFolder(directory, '24.22.1');
  await mkdir(join(directory, 'with space'));
  await symlink(LAUNCHER, join(directory, 'absolute'));
  await symlink('../absolute', join(directory, 'with space', 'chained'));
  for (const launcher of [LAUNCHER, join(directory, 'absolute'), join(directory, 'with space', 'chained')]) {
    const result = await launch(['assess', '--list'], { launcher, cwd: directory, env: { SCOPEHAVEN_NODE: node } });
    assert.equal(result.stdout, `IN ${project}\nEXEC src/cli.mjs --list\n`, launcher);
  }
});

test('in an npm install the caller keeps its folder, every entry is named by its real path, and hints name npx', async t => {
  const directory = await privateDirectory(t), work = await realpath(directory);
  const { root, bin } = await npmInstall(directory);
  const node = await fakeNodeInFolder(directory, '24.22.1');
  const actions = /^scopehaven_usage='Usage: \.\/scopehaven ([^']+)'$/m.exec(launcherText)[1].split('|').filter(action => action !== 'doctor' && action !== 'test');
  for (const action of actions) {
    const result = await launch([action, 'probe-arg'], { launcher: bin, cwd: directory, env: { SCOPEHAVEN_NODE: node } });
    assert.equal(result.code, 0, `${action}: ${result.stderr}`);
    const entry = result.stdout.split('\n');
    assert.equal(entry[0], `IN ${work}`, `${action} stays in the caller's folder`);
    assert.ok(entry[1].startsWith(`EXEC ${root}/`) && entry[1].endsWith(' probe-arg'), `${action}: ${entry[1]}`);
  }
  // Through a symlinked folder the entry path is still the real one: each entry compares it with its own module path.
  await symlink(join(directory, 'app'), join(directory, 'linked'));
  const linked = await launch(['assess', '--list'], { launcher: join(directory, 'linked', 'node_modules', '.bin', 'scopehaven'), cwd: directory, env: { SCOPEHAVEN_NODE: node } });
  assert.equal(linked.stdout, `IN ${work}\nEXEC ${root}/src/cli.mjs --list\n`);

  const usage = await launch(['help'], { launcher: bin, env: { SCOPEHAVEN_NODE: node } });
  assert.match(usage.stdout, /^Usage: npx scopehaven doctor\|start\|test/);
  const old = await launch(['assess'], { launcher: bin, env: { SCOPEHAVEN_NODE: await fakeNode(directory, '20.20.2') } });
  assert.equal(old.code, 2);
  assert.equal(old.stdout, '', 'nothing may run');
  assert.match(old.stderr, /SCOPEHAVEN_NODE=\/absolute\/path\/to\/node npx scopehaven doctor/);
  assert.match(old.stderr, /Run npx scopehaven doctor for the full local dependency check\./);
});

test('the test action and npm test run node --test through the bounded runner, so a run that never ends fails at its bound', async () => {
  // test/support/bounded-run.mjs (its behaviour: test/bounded-run.test.mjs). A plain --test arm would have no bound.
  assert.match(launcherText, /^\s*test\) exec "\$scopehaven_node" test\/support\/bounded-run\.mjs "\$@" test\//m);
  const scripts = JSON.parse(await readFile(join(PROJECT, 'package.json'), 'utf8')).scripts;
  assert.ok(scripts.test.startsWith('node test/support/bounded-run.mjs test/'), scripts.test);
});

test('doctor reports an unsupported Node as a failure and skips Node-based checks', async t => {
  const directory = await privateDirectory(t);
  const result = await launch(['doctor'], { env: { SCOPEHAVEN_NODE: await fakeNode(directory, '20.20.2') } });
  assert.equal(result.code, 1);
  assert.ok(result.stdout.split('\n').some(line => /^\[fail\] Node v20\.20\.2 from SCOPEHAVEN_NODE .* is outside /.test(line) && line.endsWith(` is outside ${NODE_ENGINES}`)), result.stdout);
  assert.match(result.stdout, /^ {7}Get Node\.js 22 LTS \(22\.23\.4 or newer\) or 24 LTS \(24\.22\.1 or newer\) from https:\/\/nodejs\.org\/en\/download, then put it first on PATH or set SCOPEHAVEN_NODE=\/absolute\/path\/to\/node\.$/m);
  assert.match(result.stdout, /^\[skip\] Module, data directory and port checks need a supported Node runtime first$/m);
  assert.match(result.stdout, /^Result: not ready\./m);
  assert.doesNotMatch(result.stdout, /EXEC/);
});

test('doctor warns on a Node below the October 2026 security release and does not call it a failure', async t => {
  const directory = await privateDirectory(t);
  const result = await launch(['doctor'], { env: { SCOPEHAVEN_NODE: await fakeNode(directory, '24.18.0') } });
  assert.match(result.stdout, /^\[warn\] Node v24\.18\.0 from SCOPEHAVEN_NODE .* runs, but is below the October 2026 security release for its line$/m);
  assert.doesNotMatch(result.stdout, /^\[fail\] Node/m);
});

test('doctor is read-only and reports Node source, data directory and a busy loopback port, and no target it cannot run', async t => {
  const directory = await privateDirectory(t);
  const busy = createServer(); await new Promise(resolve => busy.listen(0, '127.0.0.1', resolve)); t.after(() => busy.close());
  const port = busy.address().port, data = join(directory, 'not-yet', 'data');
  const result = await launch(['doctor', '--data-dir', data, '--port', String(port)], { env: { SCOPEHAVEN_NODE: process.execPath } });
  const lines = result.stdout.split('\n');
  assert.ok(lines.includes(`[ok]   Node v${process.versions.node} from SCOPEHAVEN_NODE (${process.execPath}) satisfies ${NODE_ENGINES}`), result.stdout);
  assert.equal(lines.some(line => line.startsWith('[unavailable]')), false, result.stdout);
  assert.doesNotMatch(result.stdout, /python/i);
  assert.ok(lines.some(line => /^\[(ok|fail)\] +Workbench modules/.test(line)), result.stdout);
  assert.ok(lines.includes(`[ok]   Data directory ${data} does not exist yet; it will be created with mode 0700 on first start or assess`), result.stdout);
  assert.ok(lines.includes(`[warn] 127.0.0.1:${port} is in use, so ./scopehaven start would fail. Stop the other process or use SCOPEHAVEN_PORT=<free port>.`), result.stdout);
  // A busy port is a warning; only [fail] lines make the doctor nonzero.
  assert.equal(result.code, lines.some(line => line.startsWith('[fail]')) ? 1 : 0, result.stdout);
  await assert.rejects(stat(join(directory, 'not-yet')), { code: 'ENOENT' }, 'doctor must not create the data directory');
  assert.equal(result.stderr, '');
});

test('assess --list shows only targets that can run on a fresh checkout', async () => {
  const result = await launch(['assess', '--list'], { env: { SCOPEHAVEN_NODE: process.execPath } });
  assert.equal(result.code, 0, result.stderr);
  const { targets } = JSON.parse(result.stdout);
  assert.ok(targets.length > 0, result.stdout);
  assert.deepEqual(targets.filter(target => target.available !== true).map(target => target.id), []);
});

test('doctor rejects a data directory the store would refuse', async t => {
  const directory = await privateDirectory(t);
  const data = join(directory, 'shared-data'); await mkdir(data); await chmod(data, 0o755);
  const result = await launch(['doctor', '--data-dir', data, '--port', '70000'], { env: { SCOPEHAVEN_NODE: process.execPath } });
  assert.equal(result.code, 1);
  assert.match(result.stdout, /^\[fail\] Data directory .*shared-data has mode 755; the store requires 700/m);
  assert.match(result.stdout, /^\[fail\] Port 70000 is not a valid TCP port/m);
  assert.equal((await stat(data)).mode & 0o777, 0o755, 'doctor must not change permissions');
});
