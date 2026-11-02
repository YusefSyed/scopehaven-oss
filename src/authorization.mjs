// A per-target authorization record, checked before any request is sent to a
// target the operator configured, and stamped on the run it authorized.
//
// A record (scopehaven-authorization/1) says who allowed testing what, and until when:
//   id           1-80 letters, digits, "_", "-" or "."
//   target       { id, applicationId }: the profile it covers
//   origins      every endpoint the run may contact: the target's origin and each observer endpoint
//                it reaches (http://127.0.0.1:PORT for HTTP, the forwarder's port for a forwarded
//                staging target; tcp://127.0.0.1:PORT for a database observer), or a remote target's
//                exact https://host[:port] origin
//   addresses    optional, a remote target only: the non-public IP addresses its host may resolve to
//   identities   the principalIds of the test accounts it covers
//   validFrom, validUntil   ISO 8601 UTC instants; the window is [validFrom, validUntil)
//   signer       { name, role }: who signed it (and organization, optional)
//   signedAt     ISO 8601 UTC, not after the check's time and before validUntil
//   rulesOfEngagement  optional { title, sha256 }: the signed rules-of-engagement document
//   forwarded    { destination }, for an operator-forwarded target only, and required for one: the origin the
//                operator's forwarder sends traffic to (https://staging.example.com, or http:// for an internal
//                host). The check cannot see where a forwarder goes; this is the operator's statement, bound by the
//                checksum. It never reaches the run: the stamp carries only the record's id and checksum
//   sha256       an integrity checksum: the SHA-256 of the record without this field (stable JSON).
//                It is unkeyed: it shows an edit made without recomputing it, and anyone can recompute
//                it, so it is not a signature (a keyed signature is a later step; README, Limits)
// The record never changes a verdict: it is checked before the run and copied onto it as
// { schema, id, sha256 } (authorizationStamp). Built-in fixture targets need none. The window is
// checked again before every request the run sends and every observer call it makes (windowGuard,
// guardObserver), and once more immediately before the run is saved or stamped: a run any of whose
// contacts could have come after validUntil is refused, never saved or stamped.
// Pure: no I/O; the caller reads the file and passes the time.
import { digest } from './domain.mjs';
import { remoteOriginOf, isIpAddress } from './remote-target.mjs';
import { REFUND_TARGET_IDS } from '../integrations/temporal-contracts/contract.mjs';

export const AUTHORIZATION_SCHEMA = 'scopehaven-authorization/1';
export class AuthorizationError extends Error {
  constructor(code, message) { super(message); this.name = 'AuthorizationError'; this.code = code; }
}
const fail = (code, message) => { throw new AuthorizationError(code, message); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const text = (value, max) => typeof value === 'string' && value.length >= 1 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const ID = /^[A-Za-z0-9_.-]{1,80}$/, PRINCIPAL = /^[A-Za-z0-9_.@-]{1,120}$/, HEX64 = /^[a-f0-9]{64}$/;
const ORIGIN = /^(?:http|tcp):\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/;
const INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,3})?)?Z$/;
// The longest window a record may cover.
export const MAX_WINDOW_DAYS = 366;
const FIELDS = ['schema', 'id', 'target', 'origins', 'identities', 'validFrom', 'validUntil', 'signer', 'signedAt', 'rulesOfEngagement', 'forwarded', 'addresses', 'sha256'];
const OPTIONAL = ['rulesOfEngagement', 'forwarded', 'addresses'];
// An endpoint a record may list: a loopback one, or a remote target's https origin, written as its origin.
const endpointValid = o => typeof o === 'string' && ((ORIGIN.test(o) && Number(ORIGIN.exec(o)[1]) <= 65535) || remoteOriginOf(o) === o);
// A forwarder's destination: an http or https origin with a host and no credentials, path, query or fragment,
// written exactly as its origin (lower case, no default port).
const destinationOrigin = value => {
  if (typeof value !== 'string' || value.length > 255 || /[\u0000-\u0020\u007f]/.test(value)) return false;
  let url; try { url = new URL(value); } catch { return false; }
  return ['https:', 'http:'].includes(url.protocol) && url.hostname !== '' && !url.username && !url.password && url.origin === value;
};
// A record instant in whole milliseconds, or NaN unless it is a real calendar instant: no 02-30 rolled over to March,
// no hour 24. Exported for the other readers of a record's instants (the GitHub Action's wait, roe check --at).
export function instantMs(value) {
  const m = typeof value === 'string' ? INSTANT.exec(value) : null;
  if (!m) return NaN;
  // Every component survives the round trip (no 02-30, no hour 24, no minute 60).
  const parts = m.slice(1, 7).map(v => Number(v ?? 0)), [y, mo, d, h, mi, sec] = parts;
  const back = new Date(Date.UTC(y, mo - 1, d, h, mi, sec));
  const again = [back.getUTCFullYear(), back.getUTCMonth() + 1, back.getUTCDate(), back.getUTCHours(), back.getUTCMinutes(), back.getUTCSeconds()];
  return again.some((part, i) => part !== parts[i]) ? NaN : Date.parse(value);
}
const instant = (value, name) => {
  const ms = instantMs(value);
  if (!Number.isSafeInteger(ms)) fail('authorization-invalid', `"${name}" must be an ISO 8601 UTC instant (for example 2026-10-07T00:00:00Z)`);
  return ms;
};
const keys = (value, allowed, required, where) => {
  if (!object(value)) fail('authorization-invalid', `${where} must be a JSON object`);
  const extra = Object.keys(value).find(key => !allowed.includes(key));
  if (extra !== undefined) fail('authorization-invalid', `${where} has an unsupported field`);
  const missing = required.find(key => !Object.hasOwn(value, key));
  if (missing !== undefined) fail('authorization-invalid', `${where} is missing "${missing}"`);
};
const withoutChecksum = ({ sha256, ...rest }) => rest;
// The integrity checksum an author adds: the digest of everything else (unkeyed; not a signature).
export const authorizationDigest = record => digest(withoutChecksum(record));
export const checksumAuthorization = record => ({ ...withoutChecksum(record), sha256: authorizationDigest(record) });

// Structure, values and checksum. Returns a frozen copy; errors never echo a field's value.
export function validateAuthorization(input) {
  let record;
  try { record = structuredClone(input); } catch { fail('authorization-invalid', 'the record is not plain JSON'); }
  keys(record, FIELDS, FIELDS.filter(key => !OPTIONAL.includes(key)), 'the record');
  if (record.schema !== AUTHORIZATION_SCHEMA) fail('authorization-invalid', `"schema" must be ${AUTHORIZATION_SCHEMA}`);
  if (typeof record.id !== 'string' || !ID.test(record.id)) fail('authorization-invalid', '"id" must be 1-80 letters, digits, "_", "-" or "."');
  keys(record.target, ['id', 'applicationId'], ['id', 'applicationId'], '"target"');
  if (![record.target.id, record.target.applicationId].every(v => typeof v === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(v))) fail('authorization-invalid', '"target" names a profile id and applicationId');
  if (!Array.isArray(record.origins) || !record.origins.length || record.origins.length > 16 || new Set(record.origins).size !== record.origins.length
    || !record.origins.every(endpointValid)) fail('authorization-invalid', '"origins" lists 1-16 distinct endpoints: literal loopback ones (http://127.0.0.1:PORT, or tcp://127.0.0.1:PORT for a database observer) or a remote target\'s https://host[:port]');
  // addresses (a remote target only): the non-public addresses (loopback, private, link-local, metadata, ...) a remote target's host may
  // resolve to for this run. Without them, a remote host that resolves to any such address is refused (src/remote-target.mjs).
  if (Object.hasOwn(record, 'addresses') && (!Array.isArray(record.addresses) || !record.addresses.length || record.addresses.length > 16 || new Set(record.addresses).size !== record.addresses.length
    || !record.addresses.every(a => isIpAddress(a) && a === a.toLowerCase()))) fail('authorization-invalid', '"addresses" lists 1-16 distinct IP addresses');
  if (!Array.isArray(record.identities) || !record.identities.length || record.identities.length > 50 || new Set(record.identities).size !== record.identities.length
    || !record.identities.every(p => typeof p === 'string' && PRINCIPAL.test(p))) fail('authorization-invalid', '"identities" lists 1-50 distinct test-account principalIds');
  const from = instant(record.validFrom, 'validFrom'), until = instant(record.validUntil, 'validUntil');
  if (!(from < until)) fail('authorization-invalid', '"validFrom" must be before "validUntil"');
  if (until - from > MAX_WINDOW_DAYS * 86400000) fail('authorization-invalid', `the window may cover at most ${MAX_WINDOW_DAYS} days`);
  keys(record.signer, ['name', 'role', 'organization'], ['name', 'role'], '"signer"');
  if (!text(record.signer.name, 120) || !text(record.signer.role, 120) || (Object.hasOwn(record.signer, 'organization') && !text(record.signer.organization, 160))) fail('authorization-invalid', '"signer" has a name and role of 1-120 characters (organization up to 160)');
  if (!(instant(record.signedAt, 'signedAt') < until)) fail('authorization-invalid', '"signedAt" must be before "validUntil"');
  if (Object.hasOwn(record, 'rulesOfEngagement')) {
    keys(record.rulesOfEngagement, ['title', 'sha256'], ['title'], '"rulesOfEngagement"');
    if (!text(record.rulesOfEngagement.title, 200) || (Object.hasOwn(record.rulesOfEngagement, 'sha256') && !(typeof record.rulesOfEngagement.sha256 === 'string' && HEX64.test(record.rulesOfEngagement.sha256)))) fail('authorization-invalid', '"rulesOfEngagement" names a title and optionally the document\'s sha256');
  }
  if (Object.hasOwn(record, 'forwarded')) {
    keys(record.forwarded, ['destination'], ['destination'], '"forwarded"');
    if (!destinationOrigin(record.forwarded.destination)) fail('authorization-invalid', '"forwarded.destination" is the origin the forwarder sends to: http(s)://host[:port], with no path, credentials, query or fragment');
  }
  if (typeof record.sha256 !== 'string' || !HEX64.test(record.sha256) || record.sha256 !== authorizationDigest(record)) fail('authorization-checksum', '"sha256" does not match the record: it was edited after its checksum was computed, or never had one');
  return Object.freeze(record);
}

// Observer types that contact no endpoint: they read a local file or listen on loopback for the
// app to reach them. http-audit reaches an HTTP endpoint and the database snapshots a TCP one, with
// their own credentials. Any other type is refused: the check cannot say what it contacts.
const CONTACT_FREE = Object.freeze(['otel', 'sqlite-audit', 'sqlite-snapshot', 'mcp-log', 'audit-file', 'smtp-sink']);
const trimSlash = origin => typeof origin === 'string' ? origin.replace(/\/$/, '') : origin;
// Every loopback endpoint a run of this profile contacts, as the record lists them.
export function contactedEndpoints(profile) {
  const endpoints = [trimSlash(profile.origin)];
  for (const o of profile.observers ?? []) {
    if (o?.type === 'http-audit') endpoints.push(trimSlash(o.origin));
    else if (o?.type === 'pg-snapshot' || o?.type === 'pg-wal' || o?.type === 'mysql-snapshot') endpoints.push(`tcp://${o.host}:${o.port}`);
    // A provider feed's endpoint (route i) is read over HTTP on 127.0.0.1; its export file (route ii) contacts nothing.
    else if (o?.type === 'provider-feed' && Number.isInteger(o.feed?.endpoint?.port)) endpoints.push(`http://127.0.0.1:${o.feed.endpoint.port}`);
    else if (o?.type === 'provider-feed' && typeof o.feed?.file?.path === 'string') continue;
    // An egress recorder listens on loopback, but it reaches each forwarding destination's upstream (read-back goes there
    // too) and a request feed's endpoint. A malformed one adds an endpoint no record lists, so the check fails closed.
    else if (o?.type === 'egress-recorder') {
      for (const d of Array.isArray(o.destinations) ? o.destinations : []) if (d !== null && typeof d === 'object' && Object.hasOwn(d, 'forward')) endpoints.push(trimSlash(d.forward?.upstream));
      if (Object.hasOwn(o, 'requestFeed')) endpoints.push(Number.isInteger(o.requestFeed?.endpoint?.port) ? `http://127.0.0.1:${o.requestFeed.endpoint.port}` : null);
    }
    else if (!CONTACT_FREE.includes(o?.type)) fail('authorization-origin', 'an observer of a type this check does not know would contact an endpoint the record cannot cover');
  }
  return [...new Set(endpoints)];
}

// The record covers this profile, now: the target, every endpoint the run contacts, every
// credentialed actor's principal, and the validity window. Throws AuthorizationError; returns the stamp.
// alsoContacts: endpoints the caller knows the run reaches beyond the profile's (a sequence's hold-gate upstream).
export function checkAuthorization(input, profile, { now, alsoContacts = [] } = {}) {
  const record = validateAuthorization(input);
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) fail('authorization-clock', 'the check needs the current time');
  if (record.target.id !== profile?.id || record.target.applicationId !== profile?.applicationId) fail('authorization-target', 'the record covers another target or application');
  // An operator-forwarded target runs only under a record that names where its forwarder sends traffic, and
  // a record that names a forwarder covers only a target declared forwarded: the two must agree.
  const forwardedTarget = profile?.targetContext === 'operator-forwarded';
  if (forwardedTarget && !Object.hasOwn(record, 'forwarded')) fail('authorization-forwarded', 'an operator-forwarded target needs a record that names the forwarder\'s destination ("forwarded")');
  if (!forwardedTarget && Object.hasOwn(record, 'forwarded')) fail('authorization-forwarded', 'the record names a forwarder\'s destination, but the target is not declared operator-forwarded');
  const uncoveredEndpoints = [...new Set([...contactedEndpoints(profile), ...alsoContacts.map(trimSlash)])].filter(endpoint => !record.origins.includes(endpoint));
  if (uncoveredEndpoints.length) fail('authorization-origin', `${uncoveredEndpoints.length} endpoint${uncoveredEndpoints.length === 1 ? '' : 's'} the run contacts ${uncoveredEndpoints.length === 1 ? 'is' : 'are'} not one the record allows`);
  const credentialed = Object.values(profile.actors ?? {}).filter(actor => actor && Object.hasOwn(actor, 'credentialEnv')).map(actor => actor.principalId);
  const uncovered = credentialed.filter(principal => !record.identities.includes(principal));
  if (uncovered.length) fail('authorization-identity', `${uncovered.length} test account${uncovered.length === 1 ? ' is' : 's are'} not covered by the record`);
  const t = now.getTime();
  if (t < Date.parse(record.validFrom)) fail('authorization-window', 'the record is not valid yet');
  if (t >= Date.parse(record.validUntil)) fail('authorization-window', 'the record has expired');
  if (Date.parse(record.signedAt) > t) fail('authorization-invalid', '"signedAt" is after the current time');
  return authorizationStamp(record);
}

// The window, checked again immediately before every request a run sends and every observer call it makes, and once
// more immediately before the run is saved or stamped:
// check() throws authorization-window-ended once the current time is outside [validFrom, validUntil), and keeps
// throwing; ended() says whether it ever did. Every entry point refuses a run whose guard ended or whose final check
// fails (exit 2, or a 403 on the dashboard), and saves and stamps nothing. Times are whole milliseconds: an instant's ISO
// text (at most 3 fraction digits, years 0100 to 9999) parses to an integer far inside the exact range of a double, and
// so does Date.now(), so no comparison here can round. now: the clock (tests inject one).
export const WINDOW_ENDED = 'authorization-window-ended';
export function windowGuard(input, { now = Date.now } = {}) {
  const record = validateAuthorization(input), from = Date.parse(record.validFrom), until = Date.parse(record.validUntil);
  let ended = false;
  const check = () => {
    const t = now();
    if (!ended && Number.isSafeInteger(t) && t >= from && t < until) return;
    ended = true;
    throw new AuthorizationError(WINDOW_ENDED, 'the record\'s window ended before the run was saved: nothing was sent after it ended, and the run is not saved or stamped');
  };
  // guard(send): the same transport, with the check made before each call (a refusal is a rejected promise, as a
  // transport failure is, so the caller's own error handling applies and nothing is sent).
  return Object.freeze({ check, ended: () => ended, guard: send => async (...args) => { check(); return send(...args); } });
}
// An observer built for a run (integrations/observers/factory.mjs), with check() made when each call the run makes to
// it starts, except stop(): start, mark, collect, the provider feed's and egress recorder's run-end reads, and the rest.
// Once the window ends no observer call starts: the call throws authorization-window-ended (a rejection where the method
// is async) without reaching the observer. The check is made once per call, not before each read: a call already
// running when the window ends (a provider feed's run-end drain or later-outcome wait, a request feed's run-end read)
// finishes its reads, up to its own cap, and stop() lets a provider feed's queued read finish. stop() is never guarded,
// so cleanup always runs. What an observer does on its own between start and stop (a provider feed's poll timer, an
// egress recorder or hold gate relaying the application's own calls) is not a call the run makes; it ends when the run
// stops the observer. In each case the final check refuses a run that ended at or after validUntil, so nothing from it
// is saved or stamped.
export function guardObserver(observer, check) {
  return new Proxy(observer, { get(target, key) {
    const value = Reflect.get(target, key, target);
    if (typeof value !== 'function' || key === 'stop') return value;
    return function guarded(...args) {
      try { check(); } catch (error) { if (value.constructor?.name === 'AsyncFunction') return Promise.reject(error); throw error; }
      return Reflect.apply(value, target, args);
    };
  } });
}
// An observer factory (runHttpAssessment's observerFactory) whose observers are guarded.
export const guardObserverFactory = (factory, check) => (configs, options) => factory(configs, options).map(observer => guardObserver(observer, check));
// The error a run that threw is reported as: authorization-window-ended when its window ended during the run (a refused
// request or observer call can surface as any error), otherwise its own.
export const windowRefusal = (window, error) => window?.ended() ? new AuthorizationError(WINDOW_ENDED, 'the record\'s window ended during the run: nothing was sent after it ended, and the run is not saved or stamped') : error;
export const authorizationStamp = record => Object.freeze({ schema: AUTHORIZATION_SCHEMA, id: record.id, sha256: record.sha256 });
// What the run's transport needs from a checked record: the non-public addresses it authorizes a remote host to resolve to.
// The grant behind it is made only here, from a record that validates, and names the record's origins:
// runHttpAssessment refuses a remote target unless the remote option carries a grant whose origins name the target's origin
// (remoteGrantOf), so a library caller cannot dial a remote host with no record. The grant rides on a module-private symbol,
// which an object spread copies, so a caller (a test) can add its resolver and CA beside it; the addresses the connector
// allows are read from the grant itself, never from the caller's copy.
const REMOTE_GRANT = Symbol('scopehaven remote grant'), remoteGrants = new WeakSet();
export const authorizedRemote = record => {
  const checked = validateAuthorization(record);
  const grant = Object.freeze({ origins: Object.freeze([...checked.origins]), allowedAddresses: Object.freeze([...(checked.addresses ?? [])]) });
  remoteGrants.add(grant);
  return Object.freeze({ allowedAddresses: grant.allowedAddresses, [REMOTE_GRANT]: grant });
};
// The grant a remote option carries, or null when it carries none that authorizedRemote made.
export const remoteGrantOf = remote => {
  if (remote === null || typeof remote !== 'object') return null;
  let grant; try { grant = remote[REMOTE_GRANT]; } catch { return null; }
  return remoteGrants.has(grant) ? grant : null;
};
// The stamp's shape, for validators that read a saved run: exactly { schema, id, sha256 }, nothing else.
export const isAuthorizationStamp = value => object(value) && Object.keys(value).length === 3 && value.schema === AUTHORIZATION_SCHEMA
  && typeof value.id === 'string' && ID.test(value.id) && typeof value.sha256 === 'string' && HEX64.test(value.sha256);

// Which targets need a record: every one that is not a built-in fixture (the synthetic demos).
// Anything else, an unknown kind or no entry at all, needs one: the check fails closed.
export const BUILT_IN_KINDS = Object.freeze(['owned-demo']);
// Refund exemption is restricted to the exact owned IDs; a prefix or caller kind
// cannot convert a configured HTTP profile into an owned fixture. Registry reserves them.
export const needsAuthorization = registryEntry => !(registryEntry !== null && typeof registryEntry === 'object' && (BUILT_IN_KINDS.includes(registryEntry.kind)
  || (registryEntry.kind==='owned-refund-contract' && REFUND_TARGET_IDS.includes(registryEntry.id))));
