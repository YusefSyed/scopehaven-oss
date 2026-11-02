// The confinement record of a confined launch and the routing tier it gives a run's absence passes.
// Pure and presentation-side: it never feeds a verdict, status, count, comparison, gate outcome, note or any suite, policy,
// fixture, evaluator or profile hash, and it is outside the HTTP evaluator hash, so the validator never reads it.
// src/confine.mjs writes the record when it starts the application (./scopehaven assess --confine); src/absence-scope.mjs
// reads it to state each pass's tier, and sealConfinement swaps the run's routed-absence limitation for the confined one.
//
// The two tiers of an absence pass an egress recorder or SMTP sink decided:
//   declared  the declared route was live (the window's witness reached the sink through it) and carried no matching send.
//             Routing is declared, not shown exclusive: a send that never reaches the sink is in no window.
//   confined  the same, and the application ran under OS confinement that refused the launched process tree every
//             outbound connection except to the declared sinks' ports and a recorded allowlist (the record's limits say what
//             that does and does not cover). A clause is confined only when every window that decided it came from a confined sink.
// A record that is malformed, edited, or not bound to its run (the run's own declared sinks, and the run's time inside the
// confinement's) is read as no record: the run is declared. Its covers and limits text must be exactly this build's, so a
// wording change here reads older confined runs as declared, which is the safe direction.
import { createHash } from 'node:crypto';
import { ROUTED_ABSENCE_LIMITATION, confinedAbsenceLimitation } from './http-scope-text.mjs';

export const CONFINEMENT_SCHEMA = 'scopehaven-confinement/1';
export const CONFINEMENT_MECHANISM = 'darwin sandbox-exec';
// The observers the application sends to: their declared port is allowed, and their windows are confined.
export const CONFINED_SINK_TYPES = Object.freeze(['egress-recorder', 'smtp-sink']);
export const CONFINEMENT_BOUNDS = Object.freeze({ sinks: 16, allow: 16, reason: 200, sample: 20, sampleChars: 300, envKeys: 64 });
export const CONFINEMENT_COVERS = 'Outbound network connections made by the launched process and every process it starts (the sandbox is inherited).';
export const CONFINEMENT_LIMITS = Object.freeze([
  'Only outbound connections are confined: the profile allows everything else, so a process outside the launched tree that the application reaches by IPC (a mach lookup, a launchd job, another application it opens), by a file it writes, or by an inbound connection is not confined, and what that process sends is outside every window.',
  'Each allowed port is TCP over IPv4 to "localhost", which the sandbox reads as every IPv4 address of this machine (127.0.0.1, each interface address and the wildcard), not loopback alone; the self-test records what the rule admitted at an interface address. A process outside the tree listening on an interface address or the wildcard at a sink port needs no administrator rights and would receive what the application sends there, so ScopeHaven checks that it is itself the only listener on each sink port before the launch, about once a second during the run and at stop, and refuses the run otherwise. A listener that binds and unbinds between two checks, or one run by another user (lsof lists only this user\'s processes), is not caught. [::1] at a sink port is refused by the rule, and the self-test checks that.',
  'Name lookups through the system resolver are refused with every other connection: the application reaches its sinks by a literal loopback address.',
  'An allowlisted port is a way out no sink sees. Each one is listed with its reason; a declared provider-side endpoint (a forward upstream, a request feed or a provider feed) is never allowed. An application that needs a service off the machine (a hosted model, for one) reaches it only through a loopback relay on an allowlisted port, and whatever that relay forwards is outside every window.',
  'macOS sandbox-exec only in this build, and it cannot run inside another sandbox. An application on Linux or one the buyer launches needs a declared container network instead (not implemented).',
  'The port watch lists the sink ports about once a second and the run is refused when no listing arrives for 2.5 times that interval, so a helper frozen for less than that still seals as confined and the gap between two listings can stretch to just under 2.5 seconds.',
  'Kernel denials are read from the unified log for information only: no verdict reads them, and a zero count means none was logged, not that none was attempted.',
  'A SIGKILL of ScopeHaven cannot be handled: the application, still confined, survives it in its own process group until stopped by hand (Ctrl-C, SIGTERM and SIGHUP do stop it).',
]);

const TAG = /^scopehaven-confine-[0-9a-f]{12}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const RECORD_KEYS = ['schema', 'tier', 'mechanism', 'covers', 'profile', 'profileDigest', 'sinks', 'allow', 'selfTest', 'sinkListeners', 'origin', 'command', 'envKeys', 'startedAt', 'stoppedAt', 'exitedAt', 'denials', 'limits'];
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
// What the rule admitted at an interface address of this machine (an allowed port, nothing listening): admitted means the kernel
// let the connection try (ECONNREFUSED), refused means EPERM, unreachable means the address itself was not reachable.
const INTERFACE_OUTCOMES = ['admitted', 'refused', 'unreachable'];
// Records that a confined launch issued (src/confine.mjs stop()), the only ones sealConfinement accepts: a record parsed from a
// file or built by hand, however well formed, is not one. markSealable is for a launch and for tests; the CLI, the server and the
// application under test cannot reach it.
const issued = new WeakSet();
export const markSealable = record => { issued.add(record); return record; };
// The run's own clock and the confinement's are both wall clock on one machine; this absorbs their rounding.
const CLOCK_SLACK_MS = 1000;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const keysAre = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
const port = value => Number.isInteger(value) && value >= 1 && value <= 65535;
const text = (value, max) => typeof value === 'string' && value.length >= 1 && value.length <= max && !value.includes('\0');
const iso = value => typeof value === 'string' && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;
const observerId = value => typeof value === 'string' && value.length >= 1 && value.length <= 64;

export const confinementTagValid = tag => typeof tag === 'string' && TAG.test(tag);
export const profileDigest = profile => createHash('sha256').update(profile, 'utf8').digest('hex');

// The sandbox profile: every outbound connection is refused (tagged, so the kernel log names this run) except TCP over IPv4
// loopback to the listed ports. sandbox-exec takes only "localhost" or "*" as a host, and "localhost" alone ("remote ip") also
// means [::1], where a squatter could listen at a sink's port; "tcp4" keeps the allowance to the address family the
// sinks listen on. Unix-domain sockets and the system resolver are outbound connections too, so they are refused as well.
export function confinementProfile(tag, ports) {
  if (!confinementTagValid(tag)) throw new Error('a confinement tag is "scopehaven-confine-" and 12 lowercase hex digits');
  if (!Array.isArray(ports) || !ports.every(port)) throw new Error('confinement ports are integers from 1 to 65535');
  const list = [...new Set(ports)].sort((a, b) => a - b);
  return ['(version 1)', '(allow default)', `(deny network-outbound (with message "${tag}"))`, ...list.map(p => `(allow network-outbound (remote tcp4 "localhost:${p}"))`), ''].join('\n');
}

// The record src/confine.mjs seals into the run. sinks: [{ observerId, type, port, routing }]; allow: [{ port, reason }];
// sinkListeners: { checks, soleListener: 'scopehaven' }, how many times the sink ports were listed and that every listener was
// ScopeHaven's own process; origin: { port, servedBy: 'launched-tree' }, the target origin and that every listener on it was the
// launched process tree; exitedAt: when the application exited before ScopeHaven stopped it, or null.
export function confinementRecord({ tag, sinks, allow, selfTest, sinkListeners, origin, command, envKeys, startedAt, stoppedAt, exitedAt, denials }) {
  const profile = confinementProfile(tag, [...sinks.map(s => s.port), ...allow.map(a => a.port)]);
  return { schema: CONFINEMENT_SCHEMA, tier: 'confined', mechanism: CONFINEMENT_MECHANISM, covers: CONFINEMENT_COVERS, profile, profileDigest: profileDigest(profile),
    sinks: sinks.map(s => ({ observerId: s.observerId, type: s.type, port: s.port, routing: s.routing ?? null })), allow: allow.map(a => ({ port: a.port, reason: a.reason })),
    selfTest, sinkListeners, origin, command, envKeys: [...envKeys].sort(), startedAt, stoppedAt, exitedAt, denials, limits: [...CONFINEMENT_LIMITS] };
}

// Whether rec is a well-formed confinement record and, given a run, bound to it: every sink names one of the run's declared
// observers of that type, every declared egress recorder and SMTP sink is a confined sink, the run started after the
// confinement did and ended before it stopped, and the application did not exit before the run ended. The profile must be
// exactly the one the sinks and allowlist produce, and its digest must match it.
export function validConfinementRecord(rec, run = null) {
  try {
    if (!keysAre(rec, RECORD_KEYS) || rec.schema !== CONFINEMENT_SCHEMA || rec.tier !== 'confined' || rec.mechanism !== CONFINEMENT_MECHANISM || rec.covers !== CONFINEMENT_COVERS) return false;
    if (!Array.isArray(rec.sinks) || rec.sinks.length > CONFINEMENT_BOUNDS.sinks || !rec.sinks.every(s => keysAre(s, ['observerId', 'type', 'port', 'routing']) && observerId(s.observerId)
      && CONFINED_SINK_TYPES.includes(s.type) && port(s.port) && (s.routing === null || text(s.routing, 32)))) return false;
    if (!Array.isArray(rec.allow) || rec.allow.length > CONFINEMENT_BOUNDS.allow || !rec.allow.every(a => keysAre(a, ['port', 'reason']) && port(a.port) && text(a.reason, CONFINEMENT_BOUNDS.reason))) return false;
    const ports = [...rec.sinks.map(s => s.port), ...rec.allow.map(a => a.port)];
    if (new Set(ports).size !== ports.length || new Set(rec.sinks.map(s => `${s.type}-${s.observerId}`)).size !== rec.sinks.length) return false;
    if (typeof rec.profile !== 'string' || rec.profileDigest !== profileDigest(rec.profile)) return false;
    const tag = /\(with message "([^"]*)"\)/.exec(rec.profile)?.[1];
    if (!confinementTagValid(tag) || rec.profile !== confinementProfile(tag, ports)) return false;
    // The self-test: a refused IPv4 canary on a port the profile does not allow; [::1] at an allowed port refused, or unavailable
    // (no IPv6 loopback on the machine, so no squatter could listen there either); and what the rule admitted at an interface
    // address (null only when the machine has no non-loopback IPv4 address).
    const t = rec.selfTest, other = t?.otherFamily, iface = t?.interfaceAddress;
    if (!keysAre(t, ['canaryPort', 'outcome', 'error', 'otherFamily', 'interfaceAddress']) || !port(t.canaryPort) || ports.includes(t.canaryPort) || t.outcome !== 'refused' || !text(t.error, 64)) return false;
    if (other === null ? ports.length > 0 : !keysAre(other, ['host', 'port', 'outcome']) || other.host !== '::1' || !ports.includes(other.port) || !['refused', 'unavailable'].includes(other.outcome)) return false;
    if (iface !== null && (!keysAre(iface, ['host', 'port', 'outcome']) || !IPV4.test(iface.host) || iface.host.startsWith('127.') || !ports.includes(iface.port) || !INTERFACE_OUTCOMES.includes(iface.outcome))) return false;
    // Every listener on every sink port was ScopeHaven's own process at each check (there is at least one check when a sink is declared).
    const sl = rec.sinkListeners;
    if (!keysAre(sl, ['checks', 'soleListener']) || !Number.isInteger(sl.checks) || sl.checks < (rec.sinks.length ? 1 : 0) || sl.soleListener !== 'scopehaven') return false;
    if (!keysAre(rec.origin, ['port', 'servedBy']) || !port(rec.origin.port) || rec.origin.servedBy !== 'launched-tree') return false;
    if (!keysAre(rec.command, ['executable', 'argc', 'argvDigest']) || !text(rec.command.executable, 4096) || !rec.command.executable.startsWith('/') || !Number.isInteger(rec.command.argc) || rec.command.argc < 1 || !HEX64.test(rec.command.argvDigest)) return false;
    if (!Array.isArray(rec.envKeys) || rec.envKeys.length > CONFINEMENT_BOUNDS.envKeys || !rec.envKeys.every(k => typeof k === 'string' && ENV_NAME.test(k)) || rec.envKeys.join('\n') !== [...new Set(rec.envKeys)].sort().join('\n')) return false;
    const [started, stopped] = [Date.parse(rec.startedAt), Date.parse(rec.stoppedAt)];
    if (!iso(rec.startedAt) || !iso(rec.stoppedAt) || stopped < started || (rec.exitedAt !== null && (!iso(rec.exitedAt) || Date.parse(rec.exitedAt) < started || Date.parse(rec.exitedAt) > stopped))) return false;
    const d = rec.denials;
    if (!keysAre(d, ['collected', 'selfTestSeen', 'markerSeen', 'count', 'sample']) || typeof d.collected !== 'boolean' || typeof d.selfTestSeen !== 'boolean' || typeof d.markerSeen !== 'boolean' || !Number.isInteger(d.count) || d.count < 0
      || !Array.isArray(d.sample) || d.sample.length > Math.min(d.count, CONFINEMENT_BOUNDS.sample) || !d.sample.every(s => text(s, CONFINEMENT_BOUNDS.sampleChars)) || (!d.collected && (d.count || d.selfTestSeen || d.markerSeen))) return false;
    if (!Array.isArray(rec.limits) || rec.limits.length !== CONFINEMENT_LIMITS.length || !rec.limits.every((l, i) => l === CONFINEMENT_LIMITS[i])) return false;
    if (run !== null) {
      // The run's own window (createdAt is when it ended) lies inside the confinement's, and the application outlived it.
      const ended = Date.parse(run?.createdAt), began = ended - run?.durationMs;
      if (!Number.isFinite(ended) || !Number.isSafeInteger(run?.durationMs) || run.durationMs < 0 || began < started - CLOCK_SLACK_MS || ended > stopped + CLOCK_SLACK_MS) return false;
      if (rec.exitedAt !== null && Date.parse(rec.exitedAt) < ended) return false;
      const declared = Array.isArray(run?.observers) ? run.observers.filter(plain) : [];
      if (!rec.sinks.every(s => declared.some(o => o.id === s.observerId && o.type === s.type))) return false;
      if (!declared.filter(o => CONFINED_SINK_TYPES.includes(o.type)).every(o => rec.sinks.some(s => s.observerId === o.id && s.type === o.type))) return false;
    }
    return true;
  } catch { return false; }
}

// The run's confinement record when it is valid and bound to the run, else null (the run is declared).
export const confinementOf = run => (plain(run) && Object.hasOwn(run, 'confinement') && validConfinementRecord(run.confinement, run) ? run.confinement : null);
// The window instance ids (src/http-effects.mjs: "<type>-<id>") of the run's confined sinks.
export const confinedInstanceIds = run => new Set((confinementOf(run)?.sinks ?? []).map(s => `${s.type}-${s.observerId}`));
export const routingTierOf = run => (confinementOf(run) ? 'confined' : 'declared');

// The run with its confinement record, and the routed-absence limitation replaced by the confined one (stated even when the
// run declares no routed sink). Called before the store seals the run; the results, counts and every hash are unchanged.
export function sealConfinement(run, record) {
  if (!plain(run) || Object.hasOwn(run, 'confinement')) throw new Error('A confinement record can be added once, to an unsaved run.');
  if (!issued.has(record)) throw new Error('A confinement record can be sealed only as a confined launch issued it.');
  if (!validConfinementRecord(record, run)) throw new Error('The confinement record does not match this run\'s declared sinks.');
  const confined = confinedAbsenceLimitation({ allow: record.allow.length, profileDigest: record.profileDigest });
  const limitations = (Array.isArray(run.limitations) ? run.limitations : []).map(l => (l === ROUTED_ABSENCE_LIMITATION ? confined : l));
  return { ...run, confinement: record, limitations: limitations.includes(confined) ? limitations : [...limitations, confined] };
}
