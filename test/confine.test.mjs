// Confined launch: the launch file, the plan and what it refuses, the sandbox profile, the record and its
// binding to a run, the routing tier it gives absence passes, and the --confine CLI path. The record and tier tests use an
// injected transport and sink (no socket). The launch tests start owned loopback processes under macOS sandbox-exec and are
// skipped where it cannot run (Linux, or inside another sandbox, which it cannot nest in); nothing leaves the machine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createServer, request } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import { mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { createStore } from '../src/store.mjs';
import { validateLaunch, readLaunchFile, confinementPlan, providerSidePorts, startConfined, confinementSelfTest, originOwners, portListeners, interfaceAddress, startDenialLog, ConfinementError } from '../src/confine.mjs';
import { confinementProfile, confinementRecord, validConfinementRecord, sealConfinement, confinementOf, routingTierOf, profileDigest, markSealable, CONFINEMENT_LIMITS } from '../src/confinement-record.mjs';
import { networkInterfaces } from 'node:os';
import { absenceScopeEntries, absenceScopeRule, routingScopeOf, ROUTING_SCOPE, ABSENCE_SCOPE_RULE, CONFINED_SCOPE_RULE } from '../src/absence-scope.mjs';
import { ROUTED_ABSENCE_LIMITATION } from '../src/http-scope-text.mjs';
import { renderReport, escape } from '../src/report.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { profile as zeroEgressProfile } from '../integrations/data-handling/zero-egress.mjs';
import { writeTestAuthorization } from './support/authorization.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const PAY = 'api.pay.example', WITNESS = 'witness.scopehaven.invalid', TOKEN = 'synthetic-confine-token';
const CHARGE = { source: 'http-egress', operation: 'send', name: PAY };
const TAG = 'scopehaven-confine-0123456789ab';
const sandboxable = process.platform === 'darwin' && spawnSync('/usr/bin/sandbox-exec', ['-p', '(version 1)(allow default)', '/usr/bin/true']).status === 0;
const live = sandboxable ? {} : { skip: 'needs macOS sandbox-exec outside another sandbox' };
const hasIpv6Loopback = Object.values(networkInterfaces()).flat().some(i => i.family === 'IPv6' && i.address === '::1');
const en0 = interfaceAddress();
const refusal = code => error => error instanceof ConfinementError && error.code === code;

const checks = [
  { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
  { id: 'ALLOWED-CHARGE', title: 'An allowed checkout charges once', category: 'allowed-use', severity: 'control', actorId: 'ops', method: 'POST', path: '/agent/checkout', body: {}, evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: { ...CHARGE, resource: 'POST /v1/charges' } }] },
  { id: 'NO-CHARGE', title: 'Summarizing never charges', category: 'tool-misuse', severity: 'high', actorId: 'ops', method: 'GET', path: '/agent/summarize', evidenceRequirement: 'backend',
    assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.none', select: CHARGE }] },
];
const sinkObserver = port => ({ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges'] }],
  witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, witnessWaitMs: 1500, quietMs: 150, settleMs: 250 });
const target = ({ origin = 'http://127.0.0.1:9', sinkPort = 40996, observers = [] } = {}) => ({ id: 'confine-app', name: 'Confined app', applicationId: 'confine-app', origin, buildLabel: 'c1', contextId: 'synthetic-confine',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'ALLOWED-CHARGE'], checks,
  observers: [sinkObserver(sinkPort), ...observers] });

// An injected transport and egress sink (as test/absence-scope.test.mjs): the honest app charges only at checkout.
let seq = 0;
async function injectedRun() {
  const pending = [];
  const transport = async (_origin, check) => { if (check.path === '/agent/checkout') pending.push('POST /v1/charges'); return { status: 200, complete: true, jsonParsed: true, json: { user: 'ops' }, bytes: 2 }; };
  const observerFactory = configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`;
    let mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { return { events: pending.splice(0).map(resource => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, operation: 'send', name: PAY, resource, outcome: 'committed', content: { b: 1 } })), coverage: 'complete', reason: null }; } };
  });
  // A credential-free actor: the injected transport answers every probe alike, so no identity is proven or needed here.
  const run = await runHttpAssessment({ ...target(), actors: { ops: { principalId: 'ops' } } }, { env: {}, transport, observerFactory });
  validateHttpRunEvidence(run);
  return run;
}
const selfTest = { canaryPort: 51000, outcome: 'refused', error: 'EPERM', otherFamily: { host: '::1', port: 40996, outcome: 'refused' }, interfaceAddress: { host: '192.0.2.10', port: 40996, outcome: 'admitted' } };
// A record whose confinement window holds the run (started before it began, stopped after it ended), as startConfined writes.
const iso = ms => new Date(ms).toISOString();
const recordFor = (run, { sinks = [{ observerId: 'sink', type: 'egress-recorder', port: 40996, routing: 'proxy' }], allow = [], exitedAt = null,
  denials = { collected: true, selfTestSeen: true, markerSeen: true, count: 1, sample: ['Sandbox: node(1) deny(1) network-outbound remote:*:52000'] } } = {}) => {
  const ended = Date.parse(run.createdAt);
  // markSealable: the test-only issuer; a launch marks its own record in stop().
  return markSealable(confinementRecord({ tag: TAG, sinks, allow, selfTest, sinkListeners: { checks: sinks.length ? 3 : 0, soleListener: 'scopehaven' }, origin: { port: 9, servedBy: 'launched-tree' }, command: { executable: '/usr/bin/true', argc: 1, argvDigest: 'a'.repeat(64) }, envKeys: ['PATH', 'HOME'],
    startedAt: iso(ended - run.durationMs - 2000), stoppedAt: iso(ended + 2000), exitedAt, denials }));
};

test('the confinement modules are presentation and launch only: outside the HTTP evaluator hash, and no verdict module reads them', async () => {
  const src = name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
  const hashed = /const evaluatorHash = digest\(\(await Promise\.all\(\[([^\]]+)\]/.exec(await src('http-connector.mjs'))[1];
  assert.doesNotMatch(hashed, /confine/);
  for (const name of ['http-connector.mjs', 'contracts.mjs', 'http-effects.mjs', 'effect-events.mjs', 'http-pairing.mjs', 'http-settlement.mjs', 'custody.mjs', 'collector-identity.mjs'])
    assert.doesNotMatch(await src(name), /confine/, name);
  // The record module imports only node:crypto and the wording module; the launcher only node builtins and the record module.
  const imports = text => [...text.matchAll(/^import .* from '([^']+)';$/gm)].map(m => m[1]);
  assert.deepEqual(imports(await src('confinement-record.mjs')), ['node:crypto', './http-scope-text.mjs']);
  assert.ok(imports(await src('confine.mjs')).every(name => name.startsWith('node:') || name === './confinement-record.mjs'));
});

test('a launch file: an absolute command, its environment by value or by name, an allowlist with reasons; anything else is refused', async () => {
  const ok = validateLaunch({ schemaVersion: 1, command: ['/usr/bin/true'], envFrom: ['APP_KEY'], env: { MODE: 'test' }, allow: [{ port: 5432, reason: 'the app\'s own Postgres' }] }, { base: '/tmp' });
  assert.deepEqual(ok, { command: ['/usr/bin/true'], cwd: '/tmp', env: { MODE: 'test' }, envFrom: ['APP_KEY'], allow: [{ port: 5432, reason: 'the app\'s own Postgres' }], readyTimeoutMs: 15000 });
  const bad = [
    [{ command: ['/usr/bin/true'] }, /schemaVersion/],
    [{ schemaVersion: 1, command: ['node', 'app.mjs'] }, /absolute path/],
    [{ schemaVersion: 1, command: [] }, /"command"/],
    [{ schemaVersion: 1, command: ['/usr/bin/true'], cwd: 'relative' }, /"cwd"/],
    [{ schemaVersion: 1, command: ['/usr/bin/true'], env: { 'BAD-NAME': 'x' } }, /"env"/],
    [{ schemaVersion: 1, command: ['/usr/bin/true'], env: { A: 'x' }, envFrom: ['A'] }, /both/],
    [{ schemaVersion: 1, command: ['/usr/bin/true'], allow: [{ port: 5432 }] }, /"allow"/],
    [{ schemaVersion: 1, command: ['/usr/bin/true'], allow: [{ port: 5432, reason: 'db' }, { port: 5432, reason: 'again' }] }, /twice/],
    [{ schemaVersion: 1, command: ['/usr/bin/true'], allow: [{ port: 70000, reason: 'x' }] }, /"allow"/],
    [{ schemaVersion: 1, command: ['/usr/bin/true'], readyTimeoutMs: 10 }, /readyTimeoutMs/],
    [{ schemaVersion: 1, command: ['/usr/bin/true'], extra: true }, /launch file is/],
  ];
  for (const [input, message] of bad) assert.throws(() => validateLaunch(input, { base: '/tmp' }), e => refusal('launch-invalid')(e) && message.test(e.message), JSON.stringify(input));
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  try {
    await writeFile(join(dir, 'launch.json'), JSON.stringify({ schemaVersion: 1, command: ['/usr/bin/true'] }));
    assert.equal((await readLaunchFile(join(dir, 'launch.json'))).cwd, dir, 'cwd defaults to the launch file\'s directory');
    await symlink(join(dir, 'launch.json'), join(dir, 'link.json'));
    await assert.rejects(readLaunchFile(join(dir, 'link.json')), refusal('launch-invalid'), 'a symlink is refused');
    await writeFile(join(dir, 'bad.json'), '{');
    await assert.rejects(readLaunchFile(join(dir, 'bad.json')), refusal('launch-invalid'));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('the plan allows each declared sink and the allowlist, and refuses a provider-side port or a sink port in the allowlist', () => {
  const launch = allow => validateLaunch({ schemaVersion: 1, command: ['/usr/bin/true'], allow }, { base: '/tmp' });
  const forwarded = { ...sinkObserver(40996), destinations: [{ host: PAY, paths: ['/v1/charges'], forward: { upstream: 'http://127.0.0.1:41001' } }],
    requestFeed: { feedId: 'f', endpoint: { port: 41002, path: '/feed' } } };
  const smtp = { id: 'mail', type: 'smtp-sink', port: 40997, routing: 'smtp-host', domains: ['customers.example'] };
  const feed = { id: 'mailfeed', type: 'provider-feed', feed: { endpoint: { port: 41003, path: '/feed' } } };
  const pg = { id: 'db', type: 'pg-snapshot', port: 5432 };
  const t = { origin: 'http://127.0.0.1:9', observers: [forwarded, smtp, feed, pg] };
  assert.deepEqual([...providerSidePorts(t.observers)].sort(), [41001, 41002, 41003]);
  const plan = confinementPlan(t, launch([{ port: 5432, reason: 'the app\'s own Postgres' }]));
  assert.deepEqual(plan, { originPort: 9, sinks: [{ observerId: 'sink', type: 'egress-recorder', port: 40996, routing: 'proxy' }, { observerId: 'mail', type: 'smtp-sink', port: 40997, routing: 'smtp-host' }],
    allow: [{ port: 5432, reason: 'the app\'s own Postgres' }] });
  for (const port of [41001, 41002, 41003]) assert.throws(() => confinementPlan(t, launch([{ port, reason: 'provider' }])), e => refusal('allow-refused')(e) && /provider-side/.test(e.message), String(port));
  assert.throws(() => confinementPlan(t, launch([{ port: 40996, reason: 'sink' }])), refusal('allow-refused'));
  assert.throws(() => confinementPlan({ origin: 'http://localhost:9', observers: [] }, launch([])), refusal('target-unsupported'));
  assert.equal(confinementPlan({ observers: [] }, launch([])).originPort, null, 'a caller that decides readiness itself may omit the origin');
});

test('the profile refuses every outbound connection except the listed loopback ports (never every loopback port)', () => {
  // tcp4: sandbox-exec names no single address, and plain "ip" would also allow a squatter on [::1] at a sink's port.
  assert.equal(confinementProfile(TAG, [40997, 40996, 40996]), `(version 1)\n(allow default)\n(deny network-outbound (with message "${TAG}"))\n(allow network-outbound (remote tcp4 "localhost:40996"))\n(allow network-outbound (remote tcp4 "localhost:40997"))\n`);
  assert.equal(confinementProfile(TAG, []), `(version 1)\n(allow default)\n(deny network-outbound (with message "${TAG}"))\n`);
  assert.match(zeroEgressProfile('t'), /localhost:\*/, 'zero-egress allows every loopback port, which none of the loopback bypasses would notice');
  assert.doesNotMatch(confinementProfile(TAG, [40996]), /localhost:\*/);
  assert.throws(() => confinementProfile('scopehaven-confine-x"))(allow default', [1]), /tag/);
  assert.throws(() => confinementProfile(TAG, [0]), /ports/);
});

test('a record is valid only as built and bound to the run\'s own sinks', async () => {
  const run = await injectedRun();
  const rec = recordFor(run);
  assert.equal(validConfinementRecord(rec, run), true);
  assert.equal(rec.profileDigest, profileDigest(rec.profile));
  const edits = {
    'profile allows another port': r => ({ ...r, profile: r.profile.replace('localhost:40996', 'localhost:40996"))\n(allow network-outbound (remote ip "localhost:*'), profileDigest: profileDigest(r.profile.replace('localhost:40996', 'localhost:40996"))\n(allow network-outbound (remote ip "localhost:*')) }),
    'profile allows both loopback families': r => ({ ...r, profile: r.profile.replace('tcp4', 'ip'), profileDigest: profileDigest(r.profile.replace('tcp4', 'ip')) }),
    'other family not probed with ports allowed': r => ({ ...r, selfTest: { ...r.selfTest, otherFamily: null } }),
    'other family got through': r => ({ ...r, selfTest: { ...r.selfTest, otherFamily: { ...r.selfTest.otherFamily, outcome: 'connected' } } }),
    'interface probe found a listener': r => ({ ...r, selfTest: { ...r.selfTest, interfaceAddress: { ...r.selfTest.interfaceAddress, outcome: 'listener' } } }),
    'interface probe at a loopback address': r => ({ ...r, selfTest: { ...r.selfTest, interfaceAddress: { ...r.selfTest.interfaceAddress, host: '127.0.0.1' } } }),
    'sink ports never listed': r => ({ ...r, sinkListeners: { checks: 0, soleListener: 'scopehaven' } }),
    'another listener on a sink port': r => ({ ...r, sinkListeners: { checks: 3, soleListener: 'unknown' } }),
    'digest mismatch': r => ({ ...r, profileDigest: 'b'.repeat(64) }),
    'an allowlist entry missing from the profile': r => ({ ...r, allow: [{ port: 5432, reason: 'db' }] }),
    'self-test not refused': r => ({ ...r, selfTest: { ...r.selfTest, outcome: 'connected' } }),
    'canary on an allowed port': r => ({ ...r, selfTest: { ...r.selfTest, canaryPort: 40996 } }),
    'sink of another type': r => ({ ...r, sinks: [{ ...r.sinks[0], type: 'smtp-sink' }] }),
    'an extra key': r => ({ ...r, verdictOverride: 'pass' }),
    'a denial count without collection': r => ({ ...r, denials: { collected: false, selfTestSeen: false, markerSeen: false, count: 2, sample: [] } }),
    'stopped before started': r => ({ ...r, stoppedAt: iso(Date.parse(r.startedAt) - 1) }),
    'a limit dropped': r => ({ ...r, limits: r.limits.slice(1) }),
    'covers widened': r => ({ ...r, covers: `${r.covers} And every other process on the machine.` }),
    'origin not checked': r => ({ ...r, origin: { ...r.origin, servedBy: 'unchecked' } }),
    'confinement stopped before the run ended': r => ({ ...r, stoppedAt: iso(Date.parse(run.createdAt) - 5000) }),
    'confinement started after the run began': r => ({ ...r, startedAt: iso(Date.parse(run.createdAt) + 500) }),
  };
  for (const [name, edit] of Object.entries(edits)) assert.equal(validConfinementRecord(edit(rec), run), false, name);
  // Bound to the run: a sink the run does not declare, or a declared recorder left out of the confinement.
  assert.equal(validConfinementRecord(recordFor(run, { sinks: [{ observerId: 'other', type: 'egress-recorder', port: 40996, routing: 'proxy' }] }), run), false);
  assert.equal(validConfinementRecord(recordFor(run, { sinks: [] }), run), false, 'every declared egress recorder must be a confined sink');
  // The application must outlive the run: an exit before the run ended means something else may have answered.
  const ended = Date.parse(run.createdAt);
  assert.equal(validConfinementRecord(recordFor(run, { exitedAt: iso(ended - 100) }), run), false, 'exited before the run ended');
  assert.equal(validConfinementRecord(recordFor(run, { exitedAt: iso(ended + 100) }), run), true, 'exited after the run ended (a harness that asks it to)');
  // A record from another run of the same target does not transplant: the run's window is outside it.
  assert.equal(validConfinementRecord(recordFor(run), { ...run, createdAt: iso(ended + 60000) }), false);
  const bare = recordFor({ createdAt: run.createdAt, durationMs: run.durationMs }, { sinks: [] });
  assert.equal(validConfinementRecord({ ...bare, selfTest: { ...bare.selfTest, otherFamily: null, interfaceAddress: null } }, { observers: [], createdAt: run.createdAt, durationMs: run.durationMs }), true, 'a run with no sink and no allowlist may still be confined');
});

test('a sealed run states the confined tier per clause in the report, SARIF and the gate; results, counts and hashes are unchanged', async () => {
  const run = await injectedRun();
  assert.deepEqual(['WHOAMI', 'ALLOWED-CHARGE', 'NO-CHARGE'].map(id => run.results.find(r => r.id === id).status), ['pass', 'pass', 'pass']);
  assert.ok(run.limitations.includes(ROUTED_ABSENCE_LIMITATION));
  const sealed = sealConfinement(run, recordFor(run));
  assert.deepEqual([sealed.results, sealed.counts, sealed.evaluatorHash, sealed.profileHash, sealed.suiteHash], [run.results, run.counts, run.evaluatorHash, run.profileHash, run.suiteHash]);
  validateHttpRunEvidence(sealed);
  assert.equal(sealed.limitations.includes(ROUTED_ABSENCE_LIMITATION), false);
  assert.equal(sealed.limitations.filter(l => l.startsWith('Confined launch (macOS sandbox-exec, profile sha256 ')).length, 1);
  assert.equal(sealed.limitations.length, run.limitations.length);
  assert.throws(() => sealConfinement(sealed, recordFor(run)), /once/);
  assert.throws(() => sealConfinement(run, recordFor(run, { sinks: [] })), /does not match/);
  // Provenance: a record that is structurally valid but was not issued (parsed from JSON, or built without the issuer) cannot seal.
  const parsed = JSON.parse(JSON.stringify(recordFor(run)));
  assert.equal(validConfinementRecord(parsed, run), true);
  assert.throws(() => sealConfinement(run, parsed), /only as a confined launch issued it/);
  const unissued = confinementRecord({ tag: TAG, sinks: recordFor(run).sinks, allow: [], selfTest, sinkListeners: { checks: 3, soleListener: 'scopehaven' }, origin: { port: 9, servedBy: 'launched-tree' }, command: recordFor(run).command, envKeys: ['PATH'], startedAt: recordFor(run).startedAt, stoppedAt: recordFor(run).stoppedAt, exitedAt: null, denials: recordFor(run).denials });
  assert.throws(() => sealConfinement(run, unissued), /only as a confined launch issued it/);
  const noCharge = sealed.results.find(r => r.id === 'NO-CHARGE');
  const [entry] = absenceScopeEntries(noCharge, sealed);
  const LABEL = 'routing confined: the kernel refused the launched process tree every outbound connection except to the declared sinks\' ports (see the confinement record\'s limits)';
  assert.deepEqual([entry.tier, entry.routing, entry.observers], ['confined', LABEL, ['egress-recorder-sink']]);
  assert.match(entry.note, /The declared route was live and carried no matching send; the confinement record's limits say what the kernel rule does not cover \(a process outside the launched tree reached by IPC, a file or an inbound connection\)\. Time bound:/);
  assert.doesNotMatch(entry.note, /only way out|no such call by any route/);
  assert.doesNotMatch(CONFINED_SCOPE_RULE, /only way out|no such call by any route/);
  assert.equal(absenceScopeEntries(noCharge, run)[0].tier, 'declared', 'the same row on the unsealed run is declared');
  assert.deepEqual([routingTierOf(sealed), routingScopeOf(sealed), absenceScopeRule(sealed)], ['confined', LABEL, CONFINED_SCOPE_RULE]);
  assert.deepEqual([routingTierOf(run), routingScopeOf(run), absenceScopeRule(run)], ['declared', ROUTING_SCOPE, ABSENCE_SCOPE_RULE]);
  const withAllow = sealConfinement(run, recordFor(run, { allow: [{ port: 5432, reason: 'the app\'s own Postgres' }] }));
  assert.equal(absenceScopeEntries(withAllow.results.find(r => r.id === 'NO-CHARGE'), withAllow)[0].routing, 'routing confined: the kernel refused the launched process tree every outbound connection except to the declared sinks\' ports and 1 allowlisted loopback port (see the confinement record\'s limits)');
  const report = renderReport(sealed);
  assert.match(report, /<h2>Confinement<\/h2>/);
  assert.match(report, /routing confined: the kernel refused the launched process tree/);
  assert.ok(report.includes('before the application started, a connection to 127.0.0.1:51000 (a port the profile does not allow) was refused (EPERM); [::1]:40996 (an allowed port on the other loopback family) was refused; interface address: the rule admitted a connection to 192.0.2.10:40996 (nothing listened there), so ScopeHaven checked that it was the only listener on each sink port'));
  assert.ok(report.includes('listed 3 times (before the launch, about once a second during the run, and at stop); every listener was ScopeHaven&#39;s own process'));
  for (const limit of CONFINEMENT_LIMITS) assert.ok(report.includes(escape(limit)), limit.slice(0, 40));
  assert.ok(!renderReport(run).includes('<h2>Confinement</h2>'));
  const sarif = renderSarif(sealed).runs[0];
  assert.deepEqual(sarif.results.find(r => r.ruleId === 'NO-CHARGE').properties.absenceScope.map(e => [e.tier, e.routing]), [['confined', LABEL]]);
  assert.equal(sarif.results.find(r => r.ruleId === 'NO-CHARGE').properties.absenceScopeNote, CONFINED_SCOPE_RULE);
  assert.deepEqual([sarif.properties.confinement.tier, sarif.properties.confinement.kernelDenials, sarif.properties.confinement.profileDigest], ['confined', 1, sealed.confinement.profileDigest]);
  const gate = summarizeGate({ candidate: sealed });
  assert.deepEqual(gate.current.absenceScope, { tier: 'confined', routing: LABEL, checks: ['NO-CHARGE'], note: CONFINED_SCOPE_RULE });
  assert.deepEqual([gate.outcome, gate.reasons], ['clean', []], 'the tier never becomes a gate reason');
});

test('a forged, edited or unbound record reads declared: the tier comes only from a record that matches the run', async () => {
  const run = await injectedRun();
  const rec = recordFor(run);
  const forged = [{ ...run, confinement: { ...rec, tier: 'confined', profile: rec.profile.replace('localhost:40996', 'localhost:*') } },
    { ...run, confinement: { ...rec, sinks: [] } }, { ...run, confinement: 'confined' }, { ...run, confinement: { tier: 'confined' } }];
  for (const r of forged) {
    assert.equal(confinementOf(r), null);
    assert.equal(absenceScopeEntries(r.results.find(x => x.id === 'NO-CHARGE'), r)[0].tier, 'declared');
    assert.ok(!renderReport(r).includes('<h2>Confinement</h2>'));
  }
});

test('a confined launch is refused off macOS and never falls back to an unconfined start', async () => {
  const launch = validateLaunch({ schemaVersion: 1, command: ['/usr/bin/true'] }, { base: '/tmp' });
  await assert.rejects(startConfined(target(), launch, { platform: 'linux' }), e => refusal('unsupported-platform')(e) && /Nothing was started/.test(e.message));
});

test('the self-test reports a profile that lets a connection through, an unloadable one, and passes the shipped one', live, async t => {
  const P = await freePort();
  const shut = confinementProfile(TAG, [P]), both = shut.replace('tcp4', 'ip');
  assert.equal((await confinementSelfTest('(version 1)\n(allow default)\n')).outcome, 'connected');
  const broken = await confinementSelfTest('(version 1)\n(allow default\n');
  assert.deepEqual([broken.outcome, /^exit \d+: sandbox-exec: /.test(broken.error), broken.otherFamily], ['error', true, null], JSON.stringify(broken));
  const ok = await confinementSelfTest(shut, { otherFamilyPort: P });
  assert.deepEqual([ok.outcome, ok.error, ok.otherFamily], ['refused', 'EPERM', { host: '::1', port: P, outcome: hasIpv6Loopback ? 'refused' : 'unavailable' }]);
  // The rule admits an interface address of this machine at the allowed port (ECONNREFUSED, nothing listening), which is why the sink ports are checked.
  assert.deepEqual(ok.interfaceAddress, en0 ? { host: en0, port: P, outcome: 'admitted' } : null);
  if (!hasIpv6Loopback) return t.skip('no IPv6 loopback on this machine, so the [::1] squatter cases cannot run');
  // A squatter already on [::1] at the allowed port is still probed, and refused.
  const squat = createTcpServer(s => s.destroy());
  await new Promise((resolve, reject) => { squat.once('error', reject); squat.listen({ port: P, host: '::1', ipv6Only: true }, resolve); });
  try { assert.equal((await confinementSelfTest(shut, { otherFamilyPort: P })).otherFamily.outcome, 'refused'); } finally { squat.close(); }
  // A profile that allows the port on every address lets a [::1] squatter through, and the self-test says so.
  const loose = await confinementSelfTest(both, { otherFamilyPort: P });
  assert.deepEqual([loose.outcome, loose.otherFamily.outcome], ['refused', 'connected']);
});

const freePort = () => new Promise(resolve => { const s = createTcpServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const get = (port, path) => new Promise((resolve, reject) => { request({ host: '127.0.0.1', port, path, agent: false }, res => { let body = ''; res.on('data', d => { body += d; }); res.on('end', () => resolve(body)); }).on('error', reject).end(); });

// Owned probe app: GET /try?port=N connects to 127.0.0.1:N itself; GET /child?port=N has a child node with an empty environment try.
const PROBE_APP = `import { createServer } from 'node:http';
import { connect } from 'node:net';
import { spawn } from 'node:child_process';
const attempt = p => new Promise(resolve => { const s = connect({ host: '127.0.0.1', port: p }); s.on('connect', () => { s.destroy(); resolve('connected'); }); s.on('error', e => resolve(e.code)); });
const child = p => new Promise(resolve => { const c = spawn(process.execPath, ['-e', "const s=require('node:net').connect({host:'127.0.0.1',port:" + p + "});s.on('connect',()=>{process.stdout.write('connected');s.destroy()});s.on('error',e=>process.stdout.write(e.code))"], { env: {} }); let out = ''; c.stdout.on('data', d => { out += d; }); c.on('close', () => resolve(out)); });
let sleeper = null;
const attempt6 = p => new Promise(resolve => { const s = connect({ host: '::1', port: p }); s.on('connect', () => { s.destroy(); resolve('connected'); }); s.on('error', e => resolve(e.code)); });
createServer(async (req, res) => { const u = new URL(req.url, 'http://127.0.0.1'); const p = Number(u.searchParams.get('port')); if (u.pathname === '/sleeper') { sleeper = spawn('/bin/sleep', ['60'], { stdio: 'ignore', detached: true }); return res.end(String(sleeper.pid)); } res.end(u.pathname === '/child' ? await child(p) : u.pathname === '/try6' ? await attempt6(p) : await attempt(p)); }).listen(Number(process.argv[2]), '127.0.0.1');
`;

test('a confined application reaches its sink port and nothing else, nor do its children or a [::1] squatter; stop ends its process group', live, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  const sink = createTcpServer(s => s.destroy()), other = createTcpServer(s => s.destroy()), squatter = createTcpServer(s => s.destroy());
  try {
    await writeFile(join(dir, 'app.mjs'), PROBE_APP);
    const [sinkPort, otherPort, appPort] = [await listen(sink), await listen(other), await freePort()];
    const launch = validateLaunch({ schemaVersion: 1, command: [process.execPath, join(dir, 'app.mjs'), String(appPort)] }, { base: dir });
    const handle = await startConfined(target({ origin: `http://127.0.0.1:${appPort}`, sinkPort }), launch, { denialLog: false });
    const pid = handle.child.pid;
    assert.deepEqual([await get(appPort, `/try?port=${sinkPort}`), await get(appPort, `/try?port=${otherPort}`), await get(appPort, `/child?port=${sinkPort}`), await get(appPort, `/child?port=${otherPort}`)],
      ['connected', 'EPERM', 'connected', 'EPERM']);
    // A squatter on the other loopback family at the sink's own port, started after the self-test: still refused by the rule.
    if (hasIpv6Loopback) {
      await new Promise((resolve, reject) => { squatter.once('error', reject); squatter.listen({ port: sinkPort, host: '::1', ipv6Only: true }, resolve); });
      assert.equal(await get(appPort, `/try6?port=${sinkPort}`), 'EPERM');
    }
    const grandchild = Number(await get(appPort, '/sleeper'));
    const record = await handle.stop();
    assert.equal(validConfinementRecord(record), true);
    assert.equal(validConfinementRecord(record, { observers: [{ id: 'sink', type: 'egress-recorder' }], createdAt: iso(Date.parse(record.stoppedAt) - 10), durationMs: 0 }), true);
    assert.deepEqual([record.sinks, record.allow, record.selfTest.outcome, record.origin, record.exitedAt, record.denials, record.sinkListeners.soleListener],
      [[{ observerId: 'sink', type: 'egress-recorder', port: sinkPort, routing: 'proxy' }], [], 'refused', { port: appPort, servedBy: 'launched-tree' }, null, { collected: false, selfTestSeen: false, markerSeen: false, count: 0, sample: [] }, 'scopehaven']);
    assert.ok(record.sinkListeners.checks >= 2, 'listed before the launch and at stop at least');
    assert.deepEqual(record.selfTest.otherFamily, { host: '::1', port: sinkPort, outcome: hasIpv6Loopback ? 'refused' : 'unavailable' });
    assert.deepEqual(record.selfTest.interfaceAddress, en0 ? { host: en0, port: sinkPort, outcome: 'admitted' } : null);
    assert.deepEqual(record.envKeys, ['HOME', 'PATH', ...(process.env.TMPDIR ? ['TMPDIR'] : [])].sort(), 'none of ScopeHaven\'s other environment is passed on');
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' }, 'the application is gone');
    assert.throws(() => process.kill(grandchild, 0), { code: 'ESRCH' }, 'and so is a process it started in a session of its own (the whole tree is stopped)');
    assert.equal(await handle.stop(), record, 'stop is idempotent');
  } finally { sink.close(); other.close(); squatter.close(); await rm(dir, { recursive: true, force: true }); }
});

test('when ScopeHaven is ended by a signal mid-run, the confined application goes with it', live, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  try {
    await writeFile(join(dir, 'app.mjs'), PROBE_APP);
    const appPort = await freePort();
    // A stand-in for the CLI: starts the app confined, prints its pid, then is sent SIGTERM (a Ctrl-C never reaches the detached group).
    await writeFile(join(dir, 'runner.mjs'), `import { startConfined, validateLaunch } from ${JSON.stringify(new URL('../src/confine.mjs', import.meta.url).href)};
const launch = validateLaunch({ schemaVersion: 1, command: [process.execPath, ${JSON.stringify(join(dir, 'app.mjs'))}, '${appPort}'] }, { base: ${JSON.stringify(dir)} });
const handle = await startConfined({ origin: 'http://127.0.0.1:${appPort}', observers: [] }, launch, { denialLog: false });
process.stdout.write(handle.child.pid + '\\n');
setInterval(() => {}, 1000);
`);
    const runner = spawn(process.execPath, [join(dir, 'runner.mjs')], { stdio: ['ignore', 'pipe', 'inherit'] });
    const pid = await new Promise((resolve, reject) => { runner.stdout.once('data', d => resolve(Number(String(d).trim()))); runner.once('exit', code => reject(new Error(`runner exited ${code}`))); });
    process.kill(pid, 0);
    const gone = new Promise(resolve => runner.once('exit', (code, signal) => resolve(signal)));
    runner.kill('SIGTERM');
    assert.equal(await gone, 'SIGTERM', 'the signal is re-raised, so ScopeHaven still dies of it');
    for (let i = 0; i < 20; i++) { try { process.kill(pid, 0); } catch { break; } await new Promise(r => setTimeout(r, 100)); }
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('a confined launch is refused when either self-test probe gets through, before the application starts', live, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  try {
    // Stand-ins for the probe's node: one whose IPv4 probe "connects", one whose [::1] probe does. The application is never started.
    await writeFile(join(dir, 'v4-open'), '#!/bin/sh\nprintf CONNECTED\n', { mode: 0o755 });
    await writeFile(join(dir, 'v6-open'), '#!/bin/sh\ncase "$*" in *"::1"*) printf CONNECTED ;; *) printf E:EPERM ;; esac\n', { mode: 0o755 });
    await writeFile(join(dir, 'marker.mjs'), `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(join(dir, 'started'))}, 'x');`);
    const launch = validateLaunch({ schemaVersion: 1, command: [process.execPath, join(dir, 'marker.mjs')] }, { base: dir });
    const t = target({ origin: `http://127.0.0.1:${await freePort()}`, sinkPort: await freePort() });
    await assert.rejects(startConfined(t, launch, { node: join(dir, 'v4-open'), denialLog: false }), e => refusal('self-test-failed')(e) && /did not refuse a connection to a port it does not allow/.test(e.message));
    await assert.rejects(startConfined(t, launch, { node: join(dir, 'v6-open'), denialLog: false }), e => refusal('self-test-failed')(e) && /did not refuse \[::1\]/.test(e.message));
    await assert.rejects(readFile(join(dir, 'started')), { code: 'ENOENT' }, 'the application never started');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('a confined launch is refused when something else already serves the origin, or serves it beside the launched app', live, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  const squatter = createServer((req, res) => res.end('unconfined'));
  try {
    await writeFile(join(dir, 'marker.mjs'), `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(join(dir, 'started'))}, 'x');`);
    const appPort = await listen(squatter);
    const launch = validateLaunch({ schemaVersion: 1, command: [process.execPath, join(dir, 'marker.mjs')] }, { base: dir });
    await assert.rejects(startConfined(target({ origin: `http://127.0.0.1:${appPort}` }), launch, { denialLog: false }), e => refusal('origin-in-use')(e) && /Nothing was started/.test(e.message));
    await assert.rejects(readFile(join(dir, 'started')), { code: 'ENOENT' });
    // Beside it: the launched app answers readiness on its own, but a listener outside the tree (this test process) holds the port too.
    assert.deepEqual(await originOwners(appPort, 999999), { listeners: [process.pid], foreign: [process.pid] });
    assert.deepEqual((await originOwners(appPort, process.pid)).foreign, []);
    // Through startConfined: a harness whose ready callback reports an origin served outside the launched tree is refused and stopped.
    const sleeps = validateLaunch({ schemaVersion: 1, command: [process.execPath, '-e', 'setTimeout(() => {}, 60000)'] }, { base: dir });
    let pid = null;
    await assert.rejects(startConfined({ observers: [] }, sleeps, { denialLog: false, ready: async c => { pid = c.pid; return `http://127.0.0.1:${appPort}`; } }),
      e => refusal('origin-not-confined')(e) && new RegExp(`served by process ${process.pid}, outside the launched tree`).test(e.message));
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' }, 'the launched process was stopped');
  } finally { squatter.close(); await rm(dir, { recursive: true, force: true }); }
});

// A listener outside ScopeHaven on an interface address or the wildcard at a sink port: the sandbox rule admits it (Seatbelt's
// "localhost" is every IPv4 address of the machine), it needs no root, and it would receive what the app sends there. The sink
// port check refuses it before the launch, during the run and at stop.
test('a process outside ScopeHaven listening on an interface address or the wildcard at a sink port refuses the launch, the run, or the stop', live, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  const sink = createTcpServer(s => s.destroy());
  try {
    await writeFile(join(dir, 'app.mjs'), PROBE_APP);
    const sinkPort = await listen(sink);
    const launch = port => validateLaunch({ schemaVersion: 1, command: [process.execPath, join(dir, 'app.mjs'), String(port)] }, { base: dir });
    // The squatter is another process (lsof reports pids): a node child bound on the given host at the sink port.
    const squatter = async host => { const c = spawn(process.execPath, ['-e', `require('node:net').createServer(s => s.destroy()).listen({ port: ${sinkPort}, host: '${host}' }, () => process.stdout.write('up'))`], { stdio: ['ignore', 'pipe', 'ignore'] }); await new Promise(r => c.stdout.once('data', r)); return c; };
    assert.deepEqual((await portListeners([sinkPort])).map(l => l.pid), [process.pid], 'the sink alone');
    for (const host of [en0, '0.0.0.0'].filter(Boolean)) {
      // Before the launch.
      let c = await squatter(host);
      try {
        assert.ok((await portListeners([sinkPort])).some(l => l.pid === c.pid), `${host}: lsof lists the squatter beside the sink`);
        await assert.rejects(startConfined(target({ origin: `http://127.0.0.1:${await freePort()}`, sinkPort }), launch(1), { denialLog: false }), e => refusal('sink-port-squatted')(e) && /Before the launch/.test(e.message) && e.message.includes(`pid ${c.pid}`));
      } finally { c.kill(); await new Promise(r => c.once('exit', r)); }
      // During the run (the poller lists the ports about once a second), and the app could reach it meanwhile.
      const appPort = await freePort();
      const handle = await startConfined(target({ origin: `http://127.0.0.1:${appPort}`, sinkPort }), launch(appPort), { denialLog: false });
      c = await squatter(host);
      try {
        if (host === en0) assert.equal(await get(appPort, `/try?port=${sinkPort}`), 'connected', 'the sink itself is reachable, and so would the squatter be: the rule admits the address');
        // Two more listings after the bind, so one of them certainly saw the squatter (a fixed wait raced the watch under load).
        const before = handle.portWatchChecks();
        for (let i = 0; i < 80 && handle.portWatchChecks() < before + 2; i++) await new Promise(r => setTimeout(r, 100));
        assert.ok(handle.portWatchChecks() >= before + 2, `${host}: the watch listed the ports twice after the squatter bound`);
      } finally { c.kill(); await new Promise(r => c.once('exit', r)); }
      await assert.rejects(handle.stop(), e => refusal('sink-port-squatted')(e) && /During the run/.test(e.message));
      assert.throws(() => process.kill(handle.child.pid, 0), { code: 'ESRCH' }, 'the app was stopped all the same');
      // At stop: bound after the last poll tick is not distinguishable from during; both refuse. A squatter present only at stop:
      const appPort2 = await freePort();
      const h2 = await startConfined(target({ origin: `http://127.0.0.1:${appPort2}`, sinkPort }), launch(appPort2), { denialLog: false });
      c = await squatter(host);
      try { await assert.rejects(h2.stop(), refusal('sink-port-squatted')); } finally { c.kill(); await new Promise(r => c.once('exit', r)); }
    }
    if (!en0) t.diagnostic('no non-loopback IPv4 address on this machine; only the wildcard case ran');
  } finally { sink.close(); await rm(dir, { recursive: true, force: true }); }
});

// The sink-port poller runs lsof as an asynchronous child: the loop it shares with the in-process sinks (whose quiet windows are
// 150 ms) must not stall. Measured here as timer drift while a confined app runs and the poller ticks at least three times.
test('the sink-port poller does not block the event loop while the application runs', live, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  const sink = createTcpServer(s => s.destroy());
  try {
    await writeFile(join(dir, 'app.mjs'), PROBE_APP);
    const [sinkPort, appPort] = [await listen(sink), await freePort()];
    const launch = validateLaunch({ schemaVersion: 1, command: [process.execPath, join(dir, 'app.mjs'), String(appPort)] }, { base: dir });
    const handle = await startConfined(target({ origin: `http://127.0.0.1:${appPort}`, sinkPort }), launch, { denialLog: false });
    let worst = 0, last = process.hrtime.bigint();
    const ticker = setInterval(() => { const now = process.hrtime.bigint(); worst = Math.max(worst, Number(now - last) / 1e6 - 10); last = now; }, 10);
    await new Promise(r => setTimeout(r, 3500));
    clearInterval(ticker);
    const record = await handle.stop();
    assert.ok(record.sinkListeners.checks >= 4, `the port watch listed the ports (${record.sinkListeners.checks} checks)`);
    assert.ok(worst < 50, `worst timer drift ${worst.toFixed(1)} ms (lsof spawned from this process, synchronous or not, stalls the loop 60 to 130 ms)`);
  } finally { sink.close(); await rm(dir, { recursive: true, force: true }); }
});

test('when lsof cannot run or fails, the sink-port check is unavailable and the launch is refused, never read as no squatter', live, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  try {
    await writeFile(join(dir, 'lsof-exit2'), '#!/bin/sh\nexit 2\n', { mode: 0o755 });
    await writeFile(join(dir, 'lsof-none'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    await writeFile(join(dir, 'marker.mjs'), `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(join(dir, 'started'))}, 'x');`);
    await assert.rejects(portListeners([40996], { lsof: join(dir, 'missing') }), refusal('sink-port-check-unavailable'));
    await assert.rejects(portListeners([40996], { lsof: join(dir, 'lsof-exit2') }), refusal('sink-port-check-unavailable'));
    assert.deepEqual(await portListeners([40996], { lsof: join(dir, 'lsof-none') }), [], 'exit 1 is lsof for nothing found');
    const launch = validateLaunch({ schemaVersion: 1, command: [process.execPath, join(dir, 'marker.mjs')] }, { base: dir });
    const t = target({ origin: `http://127.0.0.1:${await freePort()}`, sinkPort: await freePort() });
    for (const lsof of [join(dir, 'missing'), join(dir, 'lsof-exit2')]) await assert.rejects(startConfined(t, launch, { denialLog: false, tools: { lsof } }), e => refusal('sink-port-check-unavailable')(e) && /unknown/.test(e.message));
    await assert.rejects(readFile(join(dir, 'started')), { code: 'ENOENT' }, 'the application never started');
    // A check that stops working during the run refuses at stop, not as no squatter, even when lsof works again by then: the
    // stub fails while a flag file exists, which the test sets after the launch and clears before stop, so only the port
    // watch's own listings saw the failure.
    const flag = join(dir, 'fail');
    await writeFile(join(dir, 'lsof-flaky'), `#!/bin/sh\nif [ -e "${flag}" ]; then exit 2; fi\nexec /usr/sbin/lsof "$@"\n`, { mode: 0o755 });
    await writeFile(join(dir, 'app.mjs'), PROBE_APP);
    const appPort = await freePort();
    const h = await startConfined(target({ origin: `http://127.0.0.1:${appPort}`, sinkPort: await freePort() }), validateLaunch({ schemaVersion: 1, command: [process.execPath, join(dir, 'app.mjs'), String(appPort)] }, { base: dir }), { denialLog: false, tools: { lsof: join(dir, 'lsof-flaky') } });
    await writeFile(flag, 'x');
    await new Promise(r => setTimeout(r, 2500));
    await rm(flag);
    await assert.rejects(h.stop(), refusal('sink-port-check-unavailable'));
    assert.throws(() => process.kill(h.child.pid, 0), { code: 'ESRCH' });
  } finally { await rm(dir, { recursive: true, force: true }); }
});

// A frozen or dead port watch leaves the sink ports unwatched: the run must then refuse, not seal as confined.
test('a port watch that stops listing mid-run, frozen or killed, refuses the run as stalled', live, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  try {
    await writeFile(join(dir, 'app.mjs'), PROBE_APP);
    // Three cases: frozen and still frozen at stop; frozen 3 s then resumed, so that by stop the listings are fresh again and only
    // the watchdog that saw the gap can refuse; and killed.
    for (const mode of ['frozen', 'frozen-then-resumed', 'killed']) {
      const [appPort, sinkPort] = [await freePort(), await freePort()];
      const launch = validateLaunch({ schemaVersion: 1, command: [process.execPath, join(dir, 'app.mjs'), String(appPort)] }, { base: dir });
      const handle = await startConfined(target({ origin: `http://127.0.0.1:${appPort}`, sinkPort }), launch, { denialLog: false });
      assert.ok(Number.isInteger(handle.portWatchPid));
      process.kill(handle.portWatchPid, mode === 'killed' ? 'SIGKILL' : 'SIGSTOP');
      await new Promise(r => setTimeout(r, 3200));
      if (mode === 'frozen-then-resumed') {
        process.kill(handle.portWatchPid, 'SIGCONT');
        const before = handle.portWatchChecks();
        for (let i = 0; i < 60 && handle.portWatchChecks() < before + 2; i++) await new Promise(r => setTimeout(r, 100));
        assert.ok(handle.portWatchChecks() >= before + 2, 'the resumed watch listed the ports again before stop');
      }
      await assert.rejects(handle.stop(), e => refusal('sink-port-check-stalled')(e) && (mode === 'killed' ? /exited early/ : /no listing for 2500 ms/).test(e.message), mode);
      if (mode !== 'killed') { try { process.kill(handle.portWatchPid, 'SIGKILL'); } catch {} }
      assert.throws(() => process.kill(handle.child.pid, 0), { code: 'ESRCH' }, `${mode}: the app was stopped all the same`);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

// The kernel-log reader, against an injected stream (a script in the place of /usr/bin/log that emits ndjson lines like the
// unified log's): it waits for the probes' own denials, excludes them and the stop marker from the count, counts the
// application's, and reports a marker that never arrives. No live log, so no load-dependent lag.
test('the kernel-log reader attributes probe, marker and application denials from an injected stream', live, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine '));
  try {
    const tag = 'scopehaven-confine-ab12cd34ef56';
    const line = (pid, port) => JSON.stringify({ eventMessage: `Sandbox: node(${pid}) deny(1) network-outbound remote:*:${port}\n${tag}` });
    // Probe 101 after 0.3 s, the app (pid 202) after 0.9 s, the marker 303 after 1.5 s; then the stream stays open.
    await writeFile(join(dir, 'log'), `#!/bin/sh\nsleep 0.3; printf '%s\\n' '${line(101, 50001)}'\nsleep 0.6; printf '%s\\n' '${line(202, 50002)}'\nsleep 0.6; printf '%s\\n' '${line(303, 50001)}'\nsleep 60\n`, { mode: 0o755 });
    const log = await startDenialLog(tag, { warmMs: 100, lagMs: 5000, log: join(dir, 'log') });
    assert.ok(log, 'the reader started');
    assert.equal(await log.awaitProbes([101]), true, 'the probe\'s own denial arrived');
    const denials = await log.stop([303]);
    assert.deepEqual(denials, { collected: true, selfTestSeen: true, markerSeen: true, count: 1, sample: [`Sandbox: node(202) deny(1) network-outbound remote:*:50002`] });
    // A marker that never arrives: the reader waits its bound, then says so, and keeps what it has.
    const late = await startDenialLog(tag, { warmMs: 100, lagMs: 1200, log: join(dir, 'log') });
    assert.equal(await late.awaitProbes([101]), true);
    const partial = await late.stop([999]);
    assert.deepEqual([partial.markerSeen, partial.selfTestSeen, partial.count >= 1], [false, true, true]);
    // No log command at all: nothing is collected, and nothing is claimed.
    assert.equal(await startDenialLog(tag, { log: join(dir, 'missing') }), null);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('a confined launch whose application never listens is refused and stopped', live, async () => {
  const launch = validateLaunch({ schemaVersion: 1, command: [process.execPath, '-e', 'setTimeout(() => {}, 60000)'], readyTimeoutMs: 1000 }, { base: tmpdir() });
  await assert.rejects(startConfined(target({ origin: `http://127.0.0.1:${await freePort()}` }), launch, { denialLog: false }), refusal('app-not-ready'));
  const exits = validateLaunch({ schemaVersion: 1, command: [process.execPath, '-e', 'process.exit(3)'] }, { base: tmpdir() });
  await assert.rejects(startConfined(target({ origin: `http://127.0.0.1:${await freePort()}` }), exits, { denialLog: false }), refusal('app-exited'));
});

// Owned app for the CLI path: /me, the witness relayed through the proxy sink, an allowed charge through the sink at checkout,
// and, while summarizing, a charge sent straight to the provider double around the sink. Its attempts go to a log file.
const BYPASS_APP = `import { createServer, request } from 'node:http';
import { writeFileSync } from 'node:fs';
const [port, sinkPort, providerPort] = process.argv.slice(2, 5).map(Number), logPath = process.argv[5];
const attempts = [];
const send = (opts, body = '') => new Promise(resolve => { const req = request({ ...opts, agent: false, headers: { 'content-length': Buffer.byteLength(body), ...opts.headers } }, res => { res.resume(); res.on('end', () => resolve(String(res.statusCode))); }); req.on('error', e => resolve(e.code)); req.end(body); });
createServer(async (req, res) => {
  req.resume();
  const u = new URL(req.url, 'http://127.0.0.1');
  const json = (status, body) => { res.writeHead(status, { 'content-type': 'application/json', connection: 'close' }); res.end(JSON.stringify(body)); };
  if (req.headers.authorization !== 'Bearer ${TOKEN}') return json(401, {});
  if (u.pathname === '/me') return json(200, { user: 'ops' });
  if (u.pathname === '/ping') { await send({ host: '127.0.0.1', port: sinkPort, path: 'http://${WITNESS}/ping?scopehaven_witness=' + encodeURIComponent(u.searchParams.get('scopehaven_witness') ?? ''), headers: { host: '${WITNESS}' } }); return json(200, { ok: true }); }
  if (u.pathname === '/agent/checkout') { await send({ host: '127.0.0.1', port: sinkPort, method: 'POST', path: 'http://${PAY}/v1/charges', headers: { host: '${PAY}', 'content-type': 'application/json' } }, '{"amount":100}'); return json(200, { status: 'charged' }); }
  if (u.pathname === '/agent/summarize') { attempts.push(await send({ host: '127.0.0.1', port: providerPort, method: 'POST', path: '/v1/charges', headers: { host: '${PAY}', 'content-type': 'application/json' } }, '{"amount":4200}')); writeFileSync(logPath, JSON.stringify(attempts)); return json(200, { summary: 'done' }); }
  json(404, {});
}).listen(port, '127.0.0.1');
`;

// The kernel's denials for every confinement tag, read from the unified log by the test itself, beside the reader under test.
// delivered(tag, port) says whether the line of that tag's denial at that remote port reached the log, waiting up to waitMs for it.
function logWitness({ waitMs = 6000 } = {}) {
  const child = spawn('/usr/bin/log', ['stream', '--style', 'ndjson', '--predicate', 'sender == "Sandbox" AND eventMessage CONTAINS "scopehaven-confine-"'], { stdio: ['ignore', 'pipe', 'ignore'] });
  let text = '';
  child.stdout.on('data', d => { text += d; });
  const has = (tag, port) => text.split('\n').some(line => { try { const m = String(JSON.parse(line).eventMessage ?? ''); return m.includes(tag) && m.split('\n')[0].endsWith(` remote:*:${port}`); } catch { return false; } });
  return {
    async delivered(tag, port) { const deadline = Date.now() + waitMs; while (!has(tag, port) && Date.now() < deadline) await new Promise(r => setTimeout(r, 200)); return has(tag, port); },
    close() { child.kill(); },
  };
}

function cli(args, env) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [join(ROOT, 'src/cli.mjs'), ...args], { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
    child.on('close', code => resolve({ code, stdout, stderr }));
  });
}

test('the --confine CLI: a bypass that passes unconfined is refused under confinement, and the saved run reads confined', live, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine cli '));
  const received = [];
  const provider = createServer((req, res) => { req.resume(); received.push(`${req.method} ${req.url}`); res.writeHead(200, { connection: 'close' }); res.end('{}'); });
  let unconfined = null, witness = null;
  try {
    await writeFile(join(dir, 'app.mjs'), BYPASS_APP);
    const providerPort = await listen(provider);
    // A loaded machine's unified log can drop a kernel line outright, for every reader at once and with no loss event, so the test
    // reads every confinement tag's denials itself, from before the launches: the refused charge's count is asserted whenever its
    // line reached the log.
    witness = logWitness();
    const env = { PATH: '/usr/bin:/bin', HOME: process.env.HOME ?? dir, SCOPEHAVEN_TARGET_OPS: TOKEN };
    const arm = async name => {
      const [appPort, sinkPort] = [await freePort(), await freePort()];
      const logPath = join(dir, `${name}-attempts.json`), out = join(dir, `${name}-evidence`);
      await writeFile(join(dir, `${name}-targets.json`), JSON.stringify({ schemaVersion: 1, targets: [target({ origin: `http://127.0.0.1:${appPort}`, sinkPort })] }));
      const command = [process.execPath, join(dir, 'app.mjs'), String(appPort), String(sinkPort), String(providerPort), logPath];
      const args = ['--config', join(dir, `${name}-targets.json`), '--target', 'confine-app', '--out', out,
        '--authorization', writeTestAuthorization(join(dir, `${name}-authorization.json`), target({ origin: `http://127.0.0.1:${appPort}`, sinkPort }))];
      if (name === 'confined') {
        await writeFile(join(dir, 'launch.json'), JSON.stringify({ schemaVersion: 1, command }));
        args.push('--confine', join(dir, 'launch.json'));
      } else {
        unconfined = spawn(command[0], command.slice(1), { stdio: 'ignore', env: { PATH: '/usr/bin:/bin' } });
        for (let i = 0; i < 50 && await get(appPort, '/me').then(() => false, () => true); i++) await new Promise(r => setTimeout(r, 100));
      }
      const before = received.length;
      const result = await cli(args, env);
      assert.equal(result.code, 0, `${name}: ${result.stderr}`);
      const summary = JSON.parse(result.stdout);
      const store = createStore(out); await store.ready;
      return { summary, run: await store.get(summary.id), attempts: JSON.parse(await readFile(logPath, 'utf8')), received: received.length - before };
    };
    // Unconfined: the charge reaches the provider around the sink, and the pass is false (the gap the confined launch closes).
    const open = await arm('unconfined');
    unconfined.kill(); unconfined = null;
    assert.deepEqual([open.run.results.find(r => r.id === 'NO-CHARGE').status, open.attempts, open.received, Object.hasOwn(open.run, 'confinement')], ['pass', ['200'], 1, false]);
    // Confined: the kernel refuses the same send, the pass is now true, and the saved run carries the record and states its tier.
    const shut = await arm('confined');
    assert.deepEqual([shut.run.results.find(r => r.id === 'NO-CHARGE').status, shut.attempts, shut.received], ['pass', ['EPERM'], 0]);
    assert.deepEqual(shut.run.results.map(r => r.status), open.run.results.map(r => r.status), 'the same verdicts; only the effect differs');
    assert.equal(confinementOf(shut.run)?.tier, 'confined');
    assert.equal(absenceScopeEntries(shut.run.results.find(r => r.id === 'NO-CHARGE'), shut.run)[0].tier, 'confined');
    assert.equal(absenceScopeEntries(open.run.results.find(r => r.id === 'NO-CHARGE'), open.run)[0].tier, 'declared');
    assert.deepEqual([shut.summary.confinement.tier, shut.summary.confinement.sinks.length, shut.summary.confinement.allowlist], ['confined', 1, 0]);
    assert.ok(shut.run.limitations.some(l => l.startsWith('Confined launch')) && !shut.run.limitations.includes(ROUTED_ABSENCE_LIMITATION));
    // When the unified log could be read and kept up (selfTestSeen: the probes' own denials arrived, so the reader was live), the
    // self-test probes' denials are not counted and the app's refused charge is. The log is informative only: on a loaded machine
    // it can lag past the reader's wait, and then the record says so (selfTestSeen false) rather than claiming a count.
    const { denials } = shut.run.confinement;
    assert.ok(denials.sample.every(line => /deny\(\d+\) network-outbound/.test(line)));
    // The app's refused charge is counted once the reader has read through to the stop marker (an event, not a fixed wait),
    // whenever its line reached the log (the test's own reader saw it). A marker the log never delivered within the bound is
    // recorded as such, and a line the log dropped cannot be counted; then the count is not asserted, and the output says why.
    const tag = /with message "(scopehaven-confine-[0-9a-f]{12})"/.exec(shut.run.confinement.profile)[1];
    const delivered = await witness.delivered(tag, providerPort);
    if (denials.collected && denials.selfTestSeen && denials.markerSeen && delivered) assert.ok(denials.count >= 1, 'the refused charge was logged before the marker');
    else t.diagnostic(`refused-charge count not asserted (count ${denials.count}): ${[!denials.collected && 'the log was not read',
      denials.collected && !denials.selfTestSeen && 'the self-test probes\' denials did not arrive before the launch',
      denials.collected && !denials.markerSeen && 'the stop marker did not arrive within the bound',
      !delivered && 'the unified log dropped the charge\'s line (the test\'s own reader never saw it)'].filter(Boolean).join('; ')}`);
    // A refused launch saves no run and leaves a receipt in the evidence directory, with the code on stderr.
    const [busyPort, busySink] = [await freePort(), await freePort()];
    const busy = createServer((req, res) => res.end('{}')); await new Promise(r => busy.listen(busyPort, '127.0.0.1', r));
    try {
      await writeFile(join(dir, 'busy-targets.json'), JSON.stringify({ schemaVersion: 1, targets: [target({ origin: `http://127.0.0.1:${busyPort}`, sinkPort: busySink })] }));
      const refused = await cli(['--config', join(dir, 'busy-targets.json'), '--target', 'confine-app', '--out', join(dir, 'busy-evidence'), '--confine', join(dir, 'launch.json'),
        '--authorization', writeTestAuthorization(join(dir, 'busy-authorization.json'), target({ origin: `http://127.0.0.1:${busyPort}`, sinkPort: busySink }))], env);
      assert.equal(refused.code, 2);
      assert.match(refused.stderr, /confined launch refused \(origin-in-use\)/);
      const receipts = (await readdir(join(dir, 'busy-evidence'))).filter(f => f.startsWith('confine-refusal-'));
      assert.equal(receipts.length, 1);
      const receipt = JSON.parse(await readFile(join(dir, 'busy-evidence', receipts[0]), 'utf8'));
      assert.deepEqual([receipt.schema, receipt.code, receipt.target], ['scopehaven-confine-refusal/1', 'origin-in-use', 'confine-app']);
      assert.ok(!(await readdir(join(dir, 'busy-evidence'))).some(f => f.startsWith('runs')) || (await readdir(join(dir, 'busy-evidence', 'runs')).catch(() => [])).length === 0, 'no run was saved');
    } finally { busy.close(); }
    // A failure that is not a refusal (here the connector cannot run: the actor's credential is missing) leaves a receipt too, code "error".
    const [failPort, failSink] = [await freePort(), await freePort()];
    await writeFile(join(dir, 'fail-targets.json'), JSON.stringify({ schemaVersion: 1, targets: [target({ origin: `http://127.0.0.1:${failPort}`, sinkPort: failSink })] }));
    await writeFile(join(dir, 'fail-launch.json'), JSON.stringify({ schemaVersion: 1, command: [process.execPath, join(dir, 'app.mjs'), String(failPort), String(failSink), String(providerPort), join(dir, 'fail-attempts.json')] }));
    const failed = await cli(['--config', join(dir, 'fail-targets.json'), '--target', 'confine-app', '--out', join(dir, 'fail-evidence'), '--confine', join(dir, 'fail-launch.json'),
      '--authorization', writeTestAuthorization(join(dir, 'fail-authorization.json'), target({ origin: `http://127.0.0.1:${failPort}`, sinkPort: failSink }))], { PATH: env.PATH, HOME: env.HOME });
    assert.equal(failed.code, 2);
    assert.match(failed.stderr, /confined run failed \(receipt written\)/);
    const failReceipts = (await readdir(join(dir, 'fail-evidence'))).filter(f => f.startsWith('confine-refusal-'));
    assert.equal(failReceipts.length, 1);
    assert.equal(JSON.parse(await readFile(join(dir, 'fail-evidence', failReceipts[0]), 'utf8')).code, 'error');
    assert.equal(await get(failPort, '/me').then(() => 'up', () => 'down'), 'down', 'the application was stopped');
    validateHttpRunEvidence(shut.run);
  } finally { unconfined?.kill(); witness?.close(); provider.close(); await rm(dir, { recursive: true, force: true }); }
});

// Under --confine, a run refused because the authorization record's window ended leaves a
// receipt with that code, as every other failure under --confine does, and saves no run. The launched application holds
// every response until just past validUntil, so the window ends while the run waits on it. If the CLI took longer than
// the window just to start (a loaded machine), it refused the record at the start (no receipt: nothing started), and the
// attempt is repeated once with a longer window.
const HELD_APP = `import { createServer } from 'node:http';
const [port, holdUntil] = process.argv.slice(2, 4).map(Number);
createServer((req, res) => { req.resume(); setTimeout(() => { res.writeHead(200, { 'content-type': 'application/json', connection: 'close' }); res.end(JSON.stringify({ user: 'ops' })); }, Math.max(0, holdUntil - Date.now())); }).listen(port, '127.0.0.1');
`;
test('--confine: a run whose authorization window ends during it is refused (authorization-window-ended) with a receipt, and no run is saved', live, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven confine window '));
  try {
    await writeFile(join(dir, 'held.mjs'), HELD_APP);
    const env = { PATH: '/usr/bin:/bin', HOME: process.env.HOME ?? dir, SCOPEHAVEN_TARGET_OPS: TOKEN };
    for (const ms of [3000, 15000]) {
      const [appPort, sinkPort] = [await freePort(), await freePort()], until = Date.now() + ms, out = join(dir, `evidence-${ms}`);
      const profile = target({ origin: `http://127.0.0.1:${appPort}`, sinkPort });
      await writeFile(join(dir, `targets-${ms}.json`), JSON.stringify({ schemaVersion: 1, targets: [profile] }));
      await writeFile(join(dir, `launch-${ms}.json`), JSON.stringify({ schemaVersion: 1, command: [process.execPath, join(dir, 'held.mjs'), String(appPort), String(until + 300)] }));
      const record = writeTestAuthorization(join(dir, `authorization-${ms}.json`), profile, { edit: r => { r.validUntil = new Date(until).toISOString(); } });
      const result = await cli(['--config', join(dir, `targets-${ms}.json`), '--target', 'confine-app', '--out', out, '--confine', join(dir, `launch-${ms}.json`), '--authorization', record], env);
      if (/authorization refused \(authorization-window\)/.test(result.stderr)) continue;
      assert.equal(result.code, 2, result.stderr);
      assert.match(result.stderr, /authorization refused \(authorization-window-ended\)/);
      const receipts = (await readdir(out)).filter(f => f.startsWith('confine-refusal-'));
      assert.equal(receipts.length, 1, 'the refusal left a receipt');
      assert.equal(JSON.parse(await readFile(join(out, receipts[0]), 'utf8')).code, 'authorization-window-ended');
      assert.deepEqual((await readdir(join(out, 'runs')).catch(() => [])).filter(f => f.endsWith('.json')), [], 'no run was saved');
      assert.equal(await get(appPort, '/me').then(() => 'up', () => 'down'), 'down', 'the application was stopped');
      return;
    }
    assert.fail('the CLI never started inside the window');
  } finally { await rm(dir, { recursive: true, force: true }); }
});
