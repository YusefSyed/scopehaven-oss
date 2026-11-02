// Confined launch: ./scopehaven assess --target <id> --confine <launch.json> starts the application
// under OS confinement whose only network ways out are the target's declared sinks and a recorded allowlist of loopback
// ports, runs the assessment, stops the application and seals what it allowed and refused into the run
// (src/confinement-record.mjs). With the route as the application's only way out, a send around it is refused by the
// kernel instead of passing unseen: an internal bypass corpus measured 20 false
// passes on declared routing and none under this confinement.
//
// The launch file (JSON, at most 64 KiB, a regular file and not a symlink):
//   { "schemaVersion": 1,
//     "command": ["/absolute/path/to/executable", "arg", ...],  no PATH search; the application must listen on the target's origin
//     "cwd": "/absolute/dir",                                     default: the launch file's directory
//     "env": { "NAME": "value" },                                 set in the application's environment
//     "envFrom": ["NAME"],                                        copied from ScopeHaven's environment; only the names are recorded
//     "allow": [{ "port": 5432, "reason": "the app's own Postgres" }],  extra loopback ports, each recorded with its reason
//     "readyTimeoutMs": 15000 }                                   how long to wait for the origin to accept a connection
// The application starts with PATH=/usr/bin:/bin and HOME (and TMPDIR when set) plus env and envFrom: none of ScopeHaven's
// other environment is passed on.
//
// What the launch does, in order: plan the allowed ports (each egress recorder's and SMTP sink's declared port, plus the
// allowlist; a declared provider-side port is refused); check that ScopeHaven itself is the only listener on each sink port
// (the sandbox reads "localhost" as every IPv4 address of this machine, so a listener on an interface address or the wildcard
// at a sink port, which needs no root, would receive what the application sends there); start reading the kernel's denials
// for this run's tag from the unified log; self-test the profile, passed inline (a canary on a port it does not allow must be
// refused, [::1] at an allowed port must be refused, and what it admits at an interface address is recorded), and wait until
// the probes' own denials show the log reader is live; start the application under sandbox-exec in its own process group;
// wait for its origin, and check that every listener on it is the launched process tree (a server already on that port, or
// one beside it, would answer for the confined copy). The sink ports are listed again about once a second while the
// application runs and once more at stop; a listener outside ScopeHaven at any point refuses the run. stop() ends the tree
// and returns the record; so does a signal that ends ScopeHaven.
//
// macOS only in this build: sandbox-exec applies the profile to the launched process and every process it starts, and it
// cannot run inside another sandbox. On any other platform, or when the profile cannot be applied, the launch is refused:
// it never falls back to an unconfined run. Opens a canary listener on 127.0.0.1, and checks that a dial to [::1] at a sink
// port is refused (the canary bind there may fail, because the sink holds [::1]); its probe children dial 127.0.0.1, [::1] and
// one interface address of this machine (an allowed port, so the record shows what the rule admits); dials
// 127.0.0.1 at the target origin for readiness; reads the unified log (log stream), the process table (ps) and the listeners
// on the origin and sink ports (lsof).
import { spawn, spawnSync, execFile } from 'node:child_process';
import { connect, createServer } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { constants, existsSync } from 'node:fs';
import { access, open } from 'node:fs/promises';
import { networkInterfaces } from 'node:os';
import { dirname, isAbsolute } from 'node:path';
import { CONFINED_SINK_TYPES, CONFINEMENT_BOUNDS, confinementProfile, confinementRecord, markSealable } from './confinement-record.mjs';

export const SANDBOX_EXEC = '/usr/bin/sandbox-exec';
const LSOF = '/usr/sbin/lsof', PS = '/bin/ps', SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'];
export const LAUNCH_BOUNDS = Object.freeze({ fileBytes: 65536, argv: 64, argBytes: 16384, env: 64, valueBytes: 8192, allow: CONFINEMENT_BOUNDS.allow, reason: CONFINEMENT_BOUNDS.reason, readyTimeoutMs: [1000, 120000] });
const LAUNCH_KEYS = ['schemaVersion', 'command', 'cwd', 'env', 'envFrom', 'allow', 'readyTimeoutMs'];
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const ORIGIN = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})\/?$/;
const LOOPBACK_URL = /^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})(?:[/?#]|$)/i;
const DEFAULT_ENV = ['PATH', 'HOME', 'TMPDIR'];
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const port = value => Number.isInteger(value) && value >= 1 && value <= 65535;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const bytes = value => Buffer.byteLength(value, 'utf8');
const clean = value => typeof value === 'string' && !value.includes('\0');

export class ConfinementError extends Error {
  constructor(code, message) { super(message); this.name = 'ConfinementError'; this.code = code; }
}
const refuse = (code, message) => { throw new ConfinementError(code, message); };

// The normalized launch: { command, cwd, env, envFrom, allow, readyTimeoutMs }. base: the directory cwd defaults to.
export function validateLaunch(input, { base = null } = {}) {
  if (!plain(input) || Object.keys(input).some(k => !LAUNCH_KEYS.includes(k))) refuse('launch-invalid', `a launch file is { ${LAUNCH_KEYS.join(', ')} } (schemaVersion and command required)`);
  if (input.schemaVersion !== 1) refuse('launch-invalid', '"schemaVersion" must be 1');
  const command = input.command;
  if (!Array.isArray(command) || command.length < 1 || command.length > LAUNCH_BOUNDS.argv || !command.every(a => clean(a) && bytes(a) <= LAUNCH_BOUNDS.argBytes))
    refuse('launch-invalid', `"command" is an array of 1 to ${LAUNCH_BOUNDS.argv} strings, each at most ${LAUNCH_BOUNDS.argBytes} bytes`);
  if (!isAbsolute(command[0])) refuse('launch-invalid', '"command"[0] must be an absolute path to the executable (no PATH search)');
  const cwd = input.cwd ?? base;
  if (!clean(cwd) || !isAbsolute(cwd)) refuse('launch-invalid', '"cwd" must be an absolute directory');
  const env = input.env ?? {};
  if (!plain(env) || Object.keys(env).length > LAUNCH_BOUNDS.env || !Object.entries(env).every(([k, v]) => ENV_NAME.test(k) && clean(v) && bytes(v) <= LAUNCH_BOUNDS.valueBytes))
    refuse('launch-invalid', `"env" maps up to ${LAUNCH_BOUNDS.env} variable names to strings of at most ${LAUNCH_BOUNDS.valueBytes} bytes`);
  const envFrom = input.envFrom ?? [];
  if (!Array.isArray(envFrom) || envFrom.length > LAUNCH_BOUNDS.env || !envFrom.every(k => typeof k === 'string' && ENV_NAME.test(k)) || new Set(envFrom).size !== envFrom.length)
    refuse('launch-invalid', '"envFrom" is a list of distinct variable names');
  if (envFrom.some(k => Object.hasOwn(env, k))) refuse('launch-invalid', 'a variable is in both "env" and "envFrom"');
  if (Object.keys(env).length + envFrom.length + DEFAULT_ENV.length > CONFINEMENT_BOUNDS.envKeys) refuse('launch-invalid', 'too many environment variables');
  const allow = input.allow ?? [];
  if (!Array.isArray(allow) || allow.length > LAUNCH_BOUNDS.allow || !allow.every(a => plain(a) && Object.keys(a).length === 2 && port(a.port)
    && typeof a.reason === 'string' && a.reason.trim().length >= 1 && a.reason.length <= LAUNCH_BOUNDS.reason && !a.reason.includes('\0')))
    refuse('launch-invalid', `"allow" is up to ${LAUNCH_BOUNDS.allow} entries { port, reason } with a port from 1 to 65535 and a reason of 1 to ${LAUNCH_BOUNDS.reason} characters`);
  if (new Set(allow.map(a => a.port)).size !== allow.length) refuse('launch-invalid', 'an allowlisted port is listed twice');
  const readyTimeoutMs = input.readyTimeoutMs ?? 15000;
  if (!Number.isInteger(readyTimeoutMs) || readyTimeoutMs < LAUNCH_BOUNDS.readyTimeoutMs[0] || readyTimeoutMs > LAUNCH_BOUNDS.readyTimeoutMs[1]) refuse('launch-invalid', '"readyTimeoutMs" must be an integer from 1000 to 120000');
  return Object.freeze({ command: [...command], cwd, env: { ...env }, envFrom: [...envFrom], allow: allow.map(a => ({ port: a.port, reason: a.reason })), readyTimeoutMs });
}

// Reads and validates a launch file. cwd defaults to the file's directory.
export async function readLaunchFile(path) {
  if (!clean(path) || !isAbsolute(path)) refuse('launch-invalid', 'the launch file path must be absolute');
  let handle;
  try { handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); }
  catch { refuse('launch-invalid', 'the launch file must be a readable regular JSON file, not a symlink'); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > LAUNCH_BOUNDS.fileBytes) refuse('launch-invalid', `the launch file must be a regular file of at most ${LAUNCH_BOUNDS.fileBytes} bytes`);
    const buffer = Buffer.alloc(LAUNCH_BOUNDS.fileBytes + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > LAUNCH_BOUNDS.fileBytes) refuse('launch-invalid', 'the launch file grew past its size limit');
    let input;
    try { input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, bytesRead))); } catch { refuse('launch-invalid', 'the launch file holds invalid JSON or UTF-8'); }
    return validateLaunch(input, { base: dirname(path) });
  } finally { await handle.close(); }
}

// Loopback ports the target declares on the provider side of a sink (a forward upstream, a request feed, a provider feed):
// the application reaching one directly is exactly the way around the sink, so none may be allowlisted.
function collectPorts(value, out) {
  if (Array.isArray(value)) for (const v of value) collectPorts(v, out);
  else if (plain(value)) for (const [key, v] of Object.entries(value)) { if (key === 'port' && port(v)) out.add(v); else collectPorts(v, out); }
  else if (typeof value === 'string') { const m = LOOPBACK_URL.exec(value); if (m && port(Number(m[1]))) out.add(Number(m[1])); }
}
export function providerSidePorts(observers) {
  const out = new Set();
  for (const o of Array.isArray(observers) ? observers : []) {
    if (!plain(o)) continue;
    if (CONFINED_SINK_TYPES.includes(o.type)) { const { port: _sink, ...rest } = o; collectPorts(rest, out); }
    else if (o.type === 'provider-feed') collectPorts(o, out);
  }
  return out;
}

// What the confinement allows for a target: { originPort, sinks: [{ observerId, type, port, routing }], allow: [{ port, reason }] }.
// target: a validated target (origin and observers); the origin may be absent when the caller decides readiness itself.
export function confinementPlan(target, launch) {
  const observers = Array.isArray(target?.observers) ? target.observers : [];
  const originMatch = target?.origin === undefined ? null : ORIGIN.exec(String(target.origin));
  if (target?.origin !== undefined && !originMatch) refuse('target-unsupported', 'a confined target\'s origin must be http://127.0.0.1:<port>');
  const sinks = observers.filter(o => plain(o) && CONFINED_SINK_TYPES.includes(o.type)).map(o => ({ observerId: o.id, type: o.type, port: o.port, routing: o.routing ?? null }));
  if (sinks.length > CONFINEMENT_BOUNDS.sinks || !sinks.every(s => typeof s.observerId === 'string' && port(s.port))) refuse('target-unsupported', 'every egress recorder and SMTP sink needs an id and a port');
  if (new Set(sinks.map(s => s.port)).size !== sinks.length) refuse('target-unsupported', 'two sinks declare the same port');
  const provider = providerSidePorts(observers);
  for (const a of launch.allow) {
    if (sinks.some(s => s.port === a.port)) refuse('allow-refused', `allowlisted port ${a.port} is a declared sink's port, which is already allowed`);
    if (provider.has(a.port)) refuse('allow-refused', `allowlisted port ${a.port} is a declared provider-side endpoint (a forward upstream, request feed or provider feed): the application could reach it around the sink`);
  }
  return Object.freeze({ originPort: originMatch ? Number(originMatch[1]) : null, sinks, allow: launch.allow.map(a => ({ ...a })) });
}

const NO_IPV6 = ['E:EADDRNOTAVAIL', 'E:ENETUNREACH', 'E:EHOSTUNREACH', 'E:EAFNOSUPPORT'];
const PROBE = (host, port) => `const s=require('node:net').connect({host:'${host}',port:${port}});s.setTimeout(4000,()=>{process.stdout.write('E:TIMEOUT');s.destroy()});s.on('connect',()=>{process.stdout.write('CONNECTED');s.destroy()});s.on('error',e=>process.stdout.write('E:'+(e.code||'ERROR')));`;

// One connection attempt from node under the profile (passed inline): resolves the probe's output ('CONNECTED' or 'E:<code>'), exit and pid.
function probeUnder(profile, node, host, port) {
  return new Promise(resolve => {
    const child = spawn(SANDBOX_EXEC, ['-p', profile, node, '-e', PROBE(host, port)], { env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d; }); child.stderr.on('data', d => { stderr += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
    child.on('error', e => { clearTimeout(timer); resolve({ stdout, stderr: String(e.message), code: -1, pid: null }); });
    child.on('close', code => { clearTimeout(timer); resolve({ stdout, stderr, code, pid: child.pid ?? null }); });
  });
}
// A listener that counts connections: { port, connections(), close() }, or { error: code } when it cannot bind.
async function countingListener(options) {
  let connections = 0;
  const server = createServer(socket => { connections++; socket.destroy(); });
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(options, resolve); }); }
  catch (error) { return { error: error?.code ?? 'ERROR' }; }
  return { port: server.address().port, connections: () => connections, close: () => new Promise(resolve => server.close(() => resolve())) };
}

// The first non-loopback IPv4 address of this machine, or null.
export const interfaceAddress = () => Object.values(networkInterfaces()).flat().find(i => i?.family === 'IPv4' && !i.internal)?.address ?? null;

// Runs the canary probes under the profile (inline). Returns { canaryPort, outcome, error, otherFamily, interfaceAddress, probePids }
// (probePids, the probe processes, tell their kernel denials apart from the application's; they are not part of the record):
//   outcome  'refused' when a connection to an IPv4 loopback listener on a port the profile does not allow was denied by the
//            kernel (EPERM) and the listener saw nothing; 'connected' when it got through; 'error' when the probe could not run
//            (sandbox-exec cannot apply a profile inside another sandbox).
//   otherFamily  with otherFamilyPort (an allowed port): { host: '::1', port, outcome } for a connection to [::1] at that port
//            (at a sink port the listener there is normally the sink itself): 'refused', 'connected', 'error', or
//            'unavailable' (the machine has no IPv6 loopback, so nothing can listen there either).
//   interfaceAddress  with otherFamilyPort, on a machine with a non-loopback IPv4 address: { host, port, outcome } for a connection
//            to that address at the allowed port, nothing listening: 'admitted' (ECONNREFUSED: the rule let it try, as it does
//            on macOS, since "localhost" there means every address of the machine), 'refused' (EPERM), 'unreachable' (the
//            address itself), or 'listener' (something answered there: a squatter the sink-port check will refuse).
export async function confinementSelfTest(profile, { node = process.execPath, avoid = [], otherFamilyPort = null } = {}) {
  let canary = null;
  for (let attempt = 0; attempt < 5 && canary === null; attempt++) {
    const listener = await countingListener({ port: 0, host: '127.0.0.1' });
    if (listener.error) refuse('self-test-failed', `no canary listener on 127.0.0.1 (${listener.error})`);
    if (avoid.includes(listener.port)) await listener.close(); else canary = listener;
  }
  if (canary === null) refuse('self-test-failed', 'no canary port outside the allowed set');
  let result;
  const probePids = [];
  try {
    const { stdout, stderr, code, pid } = await probeUnder(profile, node, '127.0.0.1', canary.port);
    probePids.push(pid);
    await sleep(50);
    result = stdout === 'E:EPERM' && canary.connections() === 0 ? { outcome: 'refused', error: 'EPERM' }
      : stdout === 'CONNECTED' || canary.connections() > 0 ? { outcome: 'connected', error: 'none' }
      : { outcome: 'error', error: (stdout || `exit ${code}: ${stderr.trim().split('\n')[0] ?? ''}`).slice(0, 64) };
  } finally { await canary.close(); }
  let otherFamily = null;
  if (otherFamilyPort !== null && result.outcome === 'refused') {
    // Probed whether or not the canary can bind there: at a sink port the listener on [::1] is normally the sink itself. A
    // squatter is a listener whose pid isn't ScopeHaven's, which the sole-listener check on the sink ports decides.
    const listener = await countingListener({ port: otherFamilyPort, host: '::1', ipv6Only: true });
    try {
      const { stdout, pid } = await probeUnder(profile, node, '::1', otherFamilyPort);
      probePids.push(pid);
      await sleep(50);
      const seen = listener.error ? 0 : listener.connections();
      otherFamily = { host: '::1', port: otherFamilyPort, outcome: stdout === 'E:EPERM' && seen === 0 ? 'refused' : stdout === 'CONNECTED' || seen > 0 ? 'connected'
        : NO_IPV6.includes(stdout) ? 'unavailable' : 'error' };
    } finally { if (!listener.error) await listener.close(); }
  }
  let iface = null;
  const host = interfaceAddress();
  if (otherFamilyPort !== null && result.outcome === 'refused' && host) {
    const { stdout, pid } = await probeUnder(profile, node, host, otherFamilyPort);
    probePids.push(pid);
    iface = { host, port: otherFamilyPort, outcome: stdout === 'E:EPERM' ? 'refused' : stdout === 'E:ECONNREFUSED' ? 'admitted' : stdout === 'CONNECTED' ? 'listener' : 'unreachable' };
  }
  return { canaryPort: canary.port, ...result, otherFamily, interfaceAddress: iface, probePids: probePids.filter(Number.isInteger) };
}

// lsof -Fpn output for TCP listeners: [{ pid, port, name }] on the given ports.
function parseListeners(stdout, ports) {
  const found = []; let pid = null;
  for (const line of String(stdout ?? '').split('\n')) {
    if (/^p\d+$/.test(line)) pid = Number(line.slice(1));
    else if (line.startsWith('n') && pid !== null) { const port = Number(line.slice(line.lastIndexOf(':') + 1)); if (ports.includes(port)) found.push({ pid, port, name: line.slice(1) }); }
  }
  return found;
}
const unavailable = (lsof, why) => new ConfinementError('sink-port-check-unavailable', `the sink ports could not be listed (${lsof}: ${why}); whether anything else listens on them is unknown, so the run is refused rather than reported as confined`);
const lsofArgs = ports => ['-nP', ...ports.map(p => `-iTCP:${p}`), '-sTCP:LISTEN', '-Fpn'];

// The listeners on TCP <port>, any address: [{ pid, port, name }] (lsof lists this user's processes). ScopeHaven's own sinks are
// process.pid; any other pid at a sink port is a squatter that the sandbox rule would let the application reach. lsof exits 1
// when it found nothing; anything else (not installed, killed, another exit) is not "nothing found": the check is unavailable,
// and the caller refuses the run rather than reading it as no squatter. One-shot, used before the launch and at stop; during the
// run the port watch below does this, because spawning anything from this process stalls its event loop (measured 60 to 130 ms
// for lsof, synchronous or not: the fork is the cost), and the in-process sinks' quiet windows are 150 ms. tools.lsof (tests).
export function portListeners(ports, { lsof = LSOF } = {}) {
  if (!ports.length) return Promise.resolve([]);
  return new Promise((resolve, reject) => {
    execFile(lsof, lsofArgs(ports), { encoding: 'utf8', timeout: 10000 }, (error, stdout) => {
      if (error && !(error.code === 1 && !error.signal && !error.killed)) return reject(unavailable(lsof, error.code ?? error.signal ?? error.message));
      resolve(parseListeners(stdout, ports));
    });
  });
}
const foreignListeners = async (ports, tools) => (await portListeners(ports, tools)).filter(l => l.pid !== process.pid);

// The port watch: one shell child, started before the application, that runs lsof on the sink ports about once a second and
// streams each listing with its exit status. ScopeHaven only reads lines, so its loop never forks during the run. Returns
// { pid, checks(), foreign(), error(), stop() }: foreign() is the first listing with a listener outside ScopeHaven; error() is
// set when lsof failed (anything but exit 0 or 1), which makes the check unavailable, or when the helper exited early or went
// quiet (no listing for more than stalledAfter times the interval, checked by a timer that forks nothing), which makes it
// stalled: a frozen helper would otherwise leave the ports unwatched while the run still read as confined.
export function startPortWatch(ports, { lsof = LSOF, everyMs = 1000, stalledAfter = 2.5 } = {}) {
  if (!ports.length) return { pid: null, checks: () => 0, foreign: () => [], error: () => null, stop() {} };
  const script = `while :; do "$0" ${lsofArgs(ports).map(a => `'${a}'`).join(' ')}; echo "@@rc=$?"; sleep ${Math.max(1, Math.round(everyMs / 1000))}; done`;
  const child = spawn('/bin/sh', ['-c', script, lsof], { stdio: ['ignore', 'pipe', 'ignore'] });
  let buffer = '', checks = 0, foreign = [], error = null, stopped = false, lastListingAt = Date.now();
  const stalled = why => new ConfinementError('sink-port-check-stalled', `the port watch ${why}, so the sink ports went unwatched; the run is refused rather than reported as confined`);
  child.on('error', e => { error ??= unavailable(lsof, e.message); });
  child.on('exit', code => { if (!stopped) error ??= stalled(`exited early (${code ?? 'signal'})`); });
  const limit = Math.round(stalledAfter * everyMs);
  const watchdog = setInterval(() => { if (!stopped && !error && Date.now() - lastListingAt > limit) error = stalled(`made no listing for ${limit} ms`); }, Math.max(100, Math.round(everyMs / 4)));
  watchdog.unref?.();
  child.stdout.on('data', chunk => {
    buffer += chunk;
    let at;
    while ((at = buffer.indexOf('\n@@rc=')) >= 0 || buffer.startsWith('@@rc=')) {
      const start = at >= 0 ? at + 1 : 0, end = buffer.indexOf('\n', start);
      if (end < 0) return;
      const rc = Number(buffer.slice(start + 5, end)), listing = buffer.slice(0, at >= 0 ? at : 0);
      buffer = buffer.slice(end + 1);
      checks++; lastListingAt = Date.now();
      if (rc !== 0 && rc !== 1) error ??= unavailable(lsof, `exit ${rc}`);
      else if (!foreign.length) foreign = parseListeners(listing, ports).filter(l => l.pid !== process.pid);
    }
  });
  return { pid: child.pid, checks: () => checks, foreign: () => foreign, error: () => error,
    stop() { if (!stopped && !error && Date.now() - lastListingAt > limit) error = stalled(`made no listing for ${limit} ms`); stopped = true; clearInterval(watchdog); try { child.kill(); } catch {} } };
}

// The kernel's denials carrying this run's tag, read from the unified log (informative only). Returns a handle whose
// stop(probePids) gives { collected, selfTestSeen, count, sample }: a denial of a self-test probe process ("name(pid) deny")
// marks the reader live; every other one is the application's. The log lags, more so on a loaded machine, so after the
// self-test awaitProbes waits up to lagMs for the probes' own denials (the reader's readiness signal) before the application
// starts; selfTestSeen false means the lag outran that wait. At stop, the caller sends one more tagged denial (a marker probe)
// and stop(markerPids) waits up to lagMs for it: the log is ordered, so once the marker is in, every earlier denial the log
// delivered is in too (markerSeen); a fixed settle would miss a late line. The log does not deliver every line: on a loaded
// machine it can drop one outright, for every reader and with no loss event, so the count is a lower bound even past the marker.
// tools.log: the log command (tests inject a stream).
export async function startDenialLog(tag, { warmMs = 1200, lagMs = 6000, log = '/usr/bin/log' } = {}) {
  if (!existsSync(log)) return null;
  let child;
  try { child = spawn(log, ['stream', '--style', 'ndjson', '--predicate', `sender == "Sandbox" AND eventMessage CONTAINS "${tag}"`], { stdio: ['ignore', 'pipe', 'ignore'] }); }
  catch { return null; }
  const chunks = []; let size = 0, failed = false;
  child.on('error', () => { failed = true; });
  child.stdout.on('data', chunk => { if (size < 1048576) { chunks.push(chunk); size += chunk.length; } });
  await sleep(warmMs);
  if (failed || child.exitCode !== null) return null;
  const read = () => Buffer.concat(chunks).toString('utf8').split('\n').map(line => { try { return String(JSON.parse(line).eventMessage ?? ''); } catch { return ''; } })
    .filter(m => /deny\(\d+\) network-outbound/.test(m) && m.includes(tag)).map(m => m.split('\n')[0].slice(0, CONFINEMENT_BOUNDS.sampleChars));
  let probes = [];
  const selfTest = m => probes.some(pid => m.includes(`(${pid}) deny(`));
  return {
    // Waits until a probe's denial has arrived, or lagMs: true when the reader is live before the application starts.
    async awaitProbes(probePids) {
      probes = probePids;
      const deadline = Date.now() + lagMs;
      while (Date.now() < deadline && !read().some(selfTest)) await sleep(200);
      return read().some(selfTest);
    },
    async stop(markerPids = []) {
      const marker = m => markerPids.some(pid => m.includes(`(${pid}) deny(`));
      const deadline = Date.now() + lagMs;
      while (markerPids.length && Date.now() < deadline && !read().some(marker)) await sleep(200);
      if (!markerPids.length) await sleep(800);
      child.kill();
      const messages = read();
      const app = messages.filter(m => !selfTest(m) && !marker(m));
      return { collected: true, selfTestSeen: messages.some(selfTest), markerSeen: messages.some(marker), count: app.length, sample: app.slice(0, CONFINEMENT_BOUNDS.sample) };
    },
    kill() { child.kill(); },
  };
}

// One connection attempt to 127.0.0.1:<port>: true when it was accepted.
const originAccepts = port => new Promise(resolve => {
  const socket = connect({ host: '127.0.0.1', port });
  socket.setTimeout(1000, () => { socket.destroy(); resolve(false); });
  socket.once('connect', () => { socket.destroy(); resolve(true); });
  socket.once('error', () => resolve(false));
});

// Resolves when 127.0.0.1:<port> accepts a connection; rejects when the child exits first or the timeout passes.
async function waitForOrigin(originPort, timeoutMs, child, tail) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) refuse('app-exited', `the application exited before its origin was ready (${child.exitCode ?? child.signalCode}): ${tail().slice(-300)}`);
    if (await originAccepts(originPort)) return;
    await sleep(100);
  }
  refuse('app-not-ready', `the application's origin 127.0.0.1:${originPort} did not accept a connection within ${timeoutMs} ms`);
}

// The launched tree: the root, every process in its group, and every descendant by parent (one that left the group too).
export function launchedTree(rootPid) {
  const table = new Map();
  for (const line of (spawnSync(PS, ['-A', '-o', 'pid=,ppid=,pgid='], { encoding: 'utf8' }).stdout ?? '').split('\n')) {
    const [pid, ppid, pgid] = line.trim().split(/\s+/).map(Number);
    if (Number.isInteger(pid) && pid > 0) table.set(pid, { ppid, pgid });
  }
  const tree = new Set([rootPid]);
  for (const [pid, p] of table) if (p.pgid === rootPid) tree.add(pid);
  for (let grew = true; grew;) { grew = false; for (const [pid, p] of table) if (!tree.has(pid) && tree.has(p.ppid)) { tree.add(pid); grew = true; } }
  return tree;
}

// Who listens on TCP <port>, on any address: { listeners: [pid], foreign: [pid] }, foreign being outside the launched tree.
// lsof sees this user's processes; a listener another user started before the launch is caught by the free-origin check.
export async function originOwners(port, rootPid, tools) {
  const listeners = [...new Set((await portListeners([port], tools)).map(l => l.pid))];
  const tree = launchedTree(rootPid);
  return { listeners, foreign: listeners.filter(pid => !tree.has(pid)) };
}

// Signals the launched tree: its group, and every member of the tree found before the first signal.
function signalTree(rootPid, tree, signal) {
  try { process.kill(-rootPid, signal); } catch {}
  for (const pid of tree) if (pid !== rootPid) { try { process.kill(pid, signal); } catch {} }
}
// Ends the launched tree: SIGTERM, then SIGKILL after graceMs (and to any member that outlived the leader).
async function stopTree(child, graceMs = 3000) {
  const tree = launchedTree(child.pid);
  const exited = child.exitCode !== null || child.signalCode !== null ? Promise.resolve() : new Promise(resolve => child.once('exit', resolve));
  signalTree(child.pid, tree, 'SIGTERM');
  const done = await Promise.race([exited.then(() => true), sleep(graceMs).then(() => false)]);
  signalTree(child.pid, tree, 'SIGKILL');
  if (!done) await Promise.race([exited, sleep(2000)]);
}

// Starts the application confined. target: the validated target (origin, observers); launch: validateLaunch's result.
// Options: ready(child) replaces waiting for the origin (a harness that reads the port from the application); stdio replaces
// ['ignore', 'pipe', 'pipe'] (stdout and stderr are always drained); node runs the self-test probe; denialLog false skips the
// unified-log reader; platform overrides process.platform (tests); tools.lsof and tools.log replace those executables (tests).
// ready(child) must resolve with the origin ("http://127.0.0.1:<port>") when the target declares none.
// Returns { child, plan, stop }: stop() ends the launched tree and returns the confinement record.
export async function startConfined(target, launch, { ready = null, stdio = null, node = process.execPath, denialLog = true, platform = process.platform, env = process.env, tools = {} } = {}) {
  if (platform !== 'darwin') refuse('unsupported-platform', `a confined launch needs macOS sandbox-exec; this is ${platform}. Nothing was started. On Linux, run the application in a container whose only network peer is the sink (not yet recorded by ScopeHaven).`);
  if (!existsSync(SANDBOX_EXEC)) refuse('unsupported-platform', `${SANDBOX_EXEC} is not available. Nothing was started.`);
  const plan = confinementPlan(target, launch);
  if (plan.originPort === null && typeof ready !== 'function') refuse('target-unsupported', 'a confined launch waits for the target origin http://127.0.0.1:<port>');
  try { await access(launch.command[0], constants.X_OK); } catch { refuse('launch-invalid', `"command"[0] is not an executable file: ${launch.command[0]}`); }
  const missing = launch.envFrom.filter(k => typeof env[k] !== 'string');
  if (missing.length) refuse('launch-invalid', `"envFrom" names variables ScopeHaven's environment does not set: ${missing.join(', ')}`);
  const tag = `scopehaven-confine-${randomBytes(6).toString('hex')}`;
  const sinkPorts = plan.sinks.map(s => s.port), ports = [...sinkPorts, ...plan.allow.map(a => a.port)];
  const profile = confinementProfile(tag, ports);
  const squat = (when, found) => refuse('sink-port-squatted', `${when}, a process outside ScopeHaven listened on a sink port (${found.map(l => `pid ${l.pid} on ${l.name}`).join(', ')}); the sandbox rule would let the application reach it, so the run is refused rather than reported as confined`);
  let log = null, child = null, poller = null;
  const cleanup = () => { log?.kill(); poller?.stop(); };
  try {
    // Before anything starts: ScopeHaven is the only listener on each sink port (its own sinks, when already up, are process.pid).
    const before = await foreignListeners(sinkPorts, tools);
    if (before.length) squat('Before the launch', before);
    let checks = 1;
    log = denialLog ? await startDenialLog(tag, tools.log ? { log: tools.log } : {}) : null;
    if (plan.originPort !== null && await originAccepts(plan.originPort)) refuse('origin-in-use', `something already accepts connections on the origin 127.0.0.1:${plan.originPort}; stop it first, so the confined copy is the one that answers. Nothing was started.`);
    const { probePids, ...selfTest } = await confinementSelfTest(profile, { node, avoid: ports, otherFamilyPort: sinkPorts[0] ?? plan.allow[0]?.port ?? null });
    if (selfTest.outcome !== 'refused') refuse('self-test-failed', selfTest.outcome === 'connected'
      ? 'the sandbox profile did not refuse a connection to a port it does not allow; the run is refused rather than reported as confined'
      : `the sandbox profile could not be applied (${selfTest.error}); sandbox-exec cannot run inside another sandbox. Nothing was started.`);
    if (!['refused', 'unavailable'].includes(selfTest.otherFamily?.outcome ?? 'refused')) refuse('self-test-failed', `the sandbox profile did not refuse [::1] at allowed port ${selfTest.otherFamily.port} (${selfTest.otherFamily.outcome}); the run is refused rather than reported as confined`);
    if (selfTest.interfaceAddress?.outcome === 'listener') squat('Before the launch', [{ pid: '?', name: `${selfTest.interfaceAddress.host}:${selfTest.interfaceAddress.port}` }]);
    const selfTestSeen = log ? await log.awaitProbes(probePids) : false;
    const appEnv = { PATH: '/usr/bin:/bin', ...(env.HOME ? { HOME: env.HOME } : {}), ...(env.TMPDIR ? { TMPDIR: env.TMPDIR } : {}),
      ...Object.fromEntries(launch.envFrom.map(k => [k, env[k]])), ...launch.env };
    const startedAt = new Date().toISOString();
    let stopping = false, exitedAt = null;
    child = spawn(SANDBOX_EXEC, ['-p', profile, ...launch.command], { cwd: launch.cwd, env: appEnv, detached: true, stdio: stdio ?? ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const keep = d => { output = (output + d).slice(-8192); };
    child.stdout?.on('data', keep); child.stderr?.on('data', keep);
    child.once('exit', () => { if (!stopping) exitedAt = new Date().toISOString(); });
    await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
    // If ScopeHaven exits or is signalled first (Ctrl-C does not reach a detached group), the launched tree goes with it.
    const orphan = () => signalTree(child.pid, launchedTree(child.pid), 'SIGKILL');
    const handlers = SIGNALS.map(signal => [signal, () => { orphan(); release(); process.kill(process.pid, signal); }]);
    const release = () => { process.removeListener('exit', orphan); for (const [signal, handler] of handlers) process.removeListener(signal, handler); };
    process.once('exit', orphan);
    for (const [signal, handler] of handlers) process.once(signal, handler);
    let originPort = plan.originPort;
    // While the application runs, the port watch lists the sink ports about once a second from its own child, so this loop
    // never forks; a listener outside ScopeHaven at any listing, or a listing that could not run, refuses the run at stop.
    poller = startPortWatch(sinkPorts, tools);
    try {
      if (typeof ready === 'function') {
        const reported = ORIGIN.exec(String(await ready(child) ?? ''));
        originPort ??= reported ? Number(reported[1]) : null;
        if (originPort === null) refuse('target-unsupported', 'the ready callback must resolve with the origin http://127.0.0.1:<port>');
      } else await waitForOrigin(originPort, launch.readyTimeoutMs, child, () => output);
      const owners = await originOwners(originPort, child.pid, tools);
      if (!owners.listeners.length || owners.foreign.length) refuse('origin-not-confined', owners.foreign.length
        ? `the origin port ${originPort} is also served by process ${owners.foreign.join(', ')}, outside the launched tree; the run is refused rather than reported as confined`
        : `no listener on the origin port ${originPort} belongs to the launched tree`);
    } catch (error) { stopping = true; release(); await stopTree(child); throw error; }
    let record = null;
    return {
      child, plan, portWatchPid: poller.pid, portWatchChecks: () => poller.checks(),
      async stop() {
        if (record) return record;
        stopping = true;
        poller.stop();
        checks += poller.checks();
        const squatted = poller.foreign();
        // Once more before the tree is stopped, then the tree.
        let last = [];
        try { if (poller.error()) throw poller.error(); checks++; last = await foreignListeners(sinkPorts, tools); } catch (error) { await stopTree(child); release(); cleanup(); throw error; }
        await stopTree(child);
        release();
        const stoppedAt = new Date().toISOString();
        // The marker: one more tagged denial after the tree is stopped, which the log reader waits for before it reads.
        const markerPid = log ? (await probeUnder(profile, node, '127.0.0.1', selfTest.canaryPort)).pid : null;
        const denials = log ? { ...(await log.stop(markerPid ? [markerPid] : [])), selfTestSeen } : { collected: false, selfTestSeen: false, markerSeen: false, count: 0, sample: [] };
        log = null;
        cleanup();
        if (squatted.length || last.length) squat(squatted.length ? 'During the run' : 'At stop', squatted.length ? squatted : last);
        record = markSealable(confinementRecord({ tag, sinks: plan.sinks, allow: plan.allow, selfTest, sinkListeners: { checks, soleListener: 'scopehaven' }, origin: { port: originPort, servedBy: 'launched-tree' },
          startedAt, stoppedAt, exitedAt, denials,
          command: { executable: launch.command[0], argc: launch.command.length, argvDigest: createHash('sha256').update(JSON.stringify(launch.command), 'utf8').digest('hex') },
          envKeys: Object.keys(appEnv) }));
        return record;
      },
    };
  } catch (error) {
    if (child && child.exitCode === null && child.signalCode === null) await stopTree(child);
    cleanup();
    throw error;
  }
}
