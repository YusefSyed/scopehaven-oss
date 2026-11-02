// Drive one practice case through the shipped launcher: ./scopehaven assess and ./scopehaven gate, each
// against a fresh owned app instance (the app keeps state: a suspension or a deletion is not undone).
// Loopback only; the profile and outputs live in a private temporary directory the caller removes.
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCorePracticeApp } from './app.mjs';
import { lifecycleProfile, creatorProfile, settlementProfile, manifest } from './profiles.mjs';
import { freePorts } from '../observers/fixtures/free-port.mjs';
import { createStore } from '../../src/store.mjs';
import { writeTestAuthorization } from '../../test/support/authorization.mjs';

export const LAUNCHER = fileURLToPath(new URL('../../scopehaven', import.meta.url));
const PROFILES = { lifecycle: lifecycleProfile, creator: creatorProfile, settlement: settlementProfile };

function launch(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(LAUNCHER, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.stdout.on('data', b => { stdout += b; }); child.stderr.on('data', b => { stderr += b; });
    child.on('error', reject);
    child.on('close', code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}
// command: 'assess' or 'gate'. Returns the exit code, the CLI's JSON output and the saved run.
export async function runCase({ kind, build = {}, observers = true, command, node = process.execPath }) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-core-practice-'));
  // A port the OS never hands out on its own, so no other process is still sending to it (fixtures/free-port.mjs).
  const [sinkPort] = await freePorts(1);
  const app = await createCorePracticeApp({ sinkPort, ...build });
  try {
    const profile = PROFILES[kind]({ origin: app.origin, sinkPort, observers });
    const config = join(dir, 'targets.json'), out = join(dir, command === 'gate' ? 'gate' : 'runs');
    await writeFile(config, JSON.stringify(manifest(profile)), { mode: 0o600 });
    // The owned practice app runs under its own synthetic authorization record (test/authorization.test.mjs pins the refusals).
    const authorization = writeTestAuthorization(join(dir, 'authorization.json'), profile);
    const env = { PATH: '/usr/bin:/bin', SCOPEHAVEN_NODE: node, ...app.env };
    const result = await launch([command, '--config', config, '--target', profile.id, '--out', out, '--authorization', authorization], env);
    let output = null;
    try { output = JSON.parse(result.stdout); } catch {}
    const runId = command === 'gate' ? output?.current?.runId : output?.id;
    const run = runId ? await (async () => { const store = createStore(out); await store.ready; return store.get(runId); })() : null;
    return { code: result.code, output, run, stderr: result.stderr, profile };
  } finally { await app.close(); await rm(dir, { recursive: true, force: true }); }
}
