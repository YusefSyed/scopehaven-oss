#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { createStore } from '../../src/store.mjs';
import { assertRuntime } from '../../src/runtime.mjs';
import { checksumAuthorization, AUTHORIZATION_SCHEMA } from '../../src/authorization.mjs';

// Isolated acceptance of the real project launcher. All requests reach this
// process's synthetic HTTP server or the core's owned fixtures. No credentials,
// existing data, provider calls, persistent processes or automatic retries.
assertRuntime();
const project = fileURLToPath(new URL('../../', import.meta.url));
const sources = ['scopehaven', 'package.json', 'src/registry.mjs', 'src/store.mjs', 'src/runner.mjs', 'src/domain.mjs', 'src/suite.mjs', 'src/fixture.mjs', 'src/http-connector.mjs', 'src/contracts.mjs', 'src/http.mjs', 'src/runtime.mjs', 'integrations/regression-gate/gate.mjs', 'integrations/regression-gate/cli.mjs', 'integrations/regression-gate/launcher-acceptance.mjs'];
const sourceHashes = async () => Object.fromEntries(await Promise.all(sources.map(async path => [path, createHash('sha256').update(await readFile(join(project, path))).digest('hex')])));
const beforeHashes = await sourceHashes();
const directory = await mkdtemp(join(tmpdir(), 'scopehaven-launcher-gate-'));
const output = join(directory, 'evidence'), config = join(directory, 'targets.json');
const sentinel = 'SYNTHETIC_PRIVATE_RESPONSE_NOT_FOR_GATE_SUMMARY';
let repaired = false, requests = 0;
const server = createServer((req, res) => {
  requests++;
  if (req.url === '/error') { req.socket.destroy(); return; }
  res.writeHead(req.url === '/boundary' && !repaired ? 403 : 200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ body: sentinel }));
});
const receipts = [];
// A configured target runs only under an authorization record that covers it: one per owned target here.
let origin;
async function authorizationFor(target) {
  const at = ms => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z'), path = join(directory, `${target}.authorization.json`);
  await writeFile(path, JSON.stringify(checksumAuthorization({ schema: AUTHORIZATION_SCHEMA, id: `owned-launcher-${target}`, target: { id: target, applicationId: 'owned-launcher-acceptance' }, origins: [origin],
    identities: ['synthetic-member'], validFrom: at(Date.now() - 60000), validUntil: at(Date.now() + 3600000), signer: { name: 'Scopehaven owned acceptance', role: 'Owner of the synthetic server' }, signedAt: at(Date.now() - 60000) })), { mode: 0o600 });
  return path;
}
async function invoke(label, target, expectedExit, options = []) {
  const args = ['gate', '--target', target, '--out', output, ...options, ...(options.includes('--config') ? ['--authorization', await authorizationFor(target)] : [])];
  const child = spawn(join(project, 'scopehaven'), args, { cwd: project, env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', excessive = false;
  const capture = (which, bytes) => {
    if (which === 'out') stdout += bytes; else stderr += bytes;
    if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > 1024 * 1024) { excessive = true; child.kill('SIGTERM'); }
  };
  child.stdout.on('data', bytes => capture('out', bytes)); child.stderr.on('data', bytes => capture('err', bytes));
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill('SIGTERM'); }, 30000);
  let exit;
  try { exit = await new Promise((resolve, reject) => { child.once('error', () => reject(new Error('Launcher could not start.'))); child.once('close', resolve); }); }
  finally { clearTimeout(timer); }
  assert(!timedOut && !excessive, 'Launcher exceeded bounded acceptance output or time.');
  assert.equal(stderr, '', 'Launcher emitted unexpected stderr.');
  let summary;
  try { summary = JSON.parse(stdout); } catch { throw new Error('Launcher did not emit a JSON gate summary.'); }
  assert.equal(exit, expectedExit, `Unexpected launcher exit for ${label}.`);
  assert.equal(summary.exitCode, exit, 'Process exit and summary disagree.');
  assert(!stdout.includes(sentinel), 'Summary retained synthetic private content.');
  let integrity = null;
  if (summary.current) {
    const saved = await createStore(output).get(summary.current.runId);
    integrity = saved.integrity.sha256;
    assert.deepEqual(JSON.parse(await readFile(join(output, 'gate-summaries', `${saved.id}.json`), 'utf8')), summary);
    assert.equal(summary.current.allowedControls.status, 'pass');
  }
  receipts.push({ case: label, processExitCode: exit, summary, coreSha256: integrity });
  return summary;
}

try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  const check = (id, path, severity = 'high', evidenceRequirement = 'response') => ({ id, title: sentinel, category: 'Owned acceptance', severity, actorId: 'member', method: 'GET', path, evidenceRequirement, assertions: [{ kind: 'status.equals', expected: 200 }] });
  const profile = (id, checkDefinition) => ({ id, name: sentinel, applicationId: 'owned-launcher-acceptance', origin, buildLabel: 'baseline', contextId: 'isolated-loopback', actors: { member: { principalId: 'synthetic-member' } }, requiredControlIds: ['allowed'], checks: [check('allowed', '/allowed', 'control'), checkDefinition] });
  const targets = [profile('response', check('boundary', '/boundary')),
    profile('inconclusive', check('backend', '/backend', 'high', 'backend')),
    profile('not-applicable', { ...check('excluded', '/excluded'), applicability: { applies: false, reason: 'Synthetic excluded capability' } }),
    profile('runner-error', check('error', '/error'))];
  const writeConfig = () => writeFile(config, JSON.stringify({ schemaVersion: 1, targets }), { mode: 0o600 });
  await writeConfig();
  const baseline = await invoke('synthetic-failed', 'demo-vulnerable', 1);
  const clean = await invoke('synthetic-clean-compatible', 'demo-repaired', 0, ['--baseline', baseline.current.runId]);
  assert.equal(clean.comparison.compatibility, 'compatible');
  assert.equal(clean.comparison.labels.fixed, baseline.current.counts.fail);
  assert.equal(clean.comparison.labels['contract-restored'], 0);
  assert.equal(clean.current.counts.pass, clean.current.checksTotal);
  assert.equal(clean.current.allowedControls.required, baseline.current.allowedControls.required);
  const responseBefore = await invoke('response-failed', 'response', 1, ['--config', config]);
  repaired = true; targets[0].buildLabel = 'repaired'; await writeConfig();
  const responseAfter = await invoke('response-contract-restored', 'response', 0, ['--config', config, '--baseline', responseBefore.current.runId]);
  assert.equal(responseAfter.current.evidenceScope, 'response-only');
  assert.equal(responseAfter.comparison.labels['contract-restored'], 1);
  assert.equal(responseAfter.comparison.labels.fixed, 0);
  const incomplete = await invoke('inconclusive', 'inconclusive', 1, ['--config', config]);
  assert.equal(incomplete.current.counts.inconclusive, 1);
  const na = await invoke('not-applicable', 'not-applicable', 1, ['--config', config]);
  assert.equal(na.current.counts.not_applicable, 1);
  const error = await invoke('runner-error', 'runner-error', 2, ['--config', config]);
  assert.equal(error.current.counts.error, 1);
  const invalid = await invoke('configuration-error', 'unregistered-target', 2);
  assert.deepEqual(invalid.reasons, ['unknown-target']);
  assert.equal(requests, 9, 'Unexpected request count: N/A must not send; errors must not retry.');
  assert.deepEqual(await sourceHashes(), beforeHashes, 'Source changed during acceptance; rerun against stable integration.');
  process.stdout.write(`${JSON.stringify({ schemaVersion: 1, command: './scopehaven gate', runtime: process.versions.node,
    outcome: 'integrated-launcher-acceptance-passed', sourceSha256: beforeHashes, cases: receipts,
    ownedHttpRequests: requests, externalRequests: 0, credentialsUsed: false,
    retention: 'Temporary private core evidence, manifests and gate summaries removed on exit; only minimized receipts and core hashes retained in this output.' }, null, 2)}\n`);
} finally {
  if (server.listening) await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
  await rm(directory, { recursive: true, force: true });
}
