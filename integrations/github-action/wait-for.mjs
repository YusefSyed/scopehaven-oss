#!/usr/bin/env node
// Loopback-only readiness wait for the application under test. No package dependencies (--until is read with the
// authorization record's own instant check, src/authorization.mjs).
// Accepts only http://127.0.0.1:PORT[/path] or http://localhost:PORT[/path];
// localhost is always dialled as the literal 127.0.0.1, with a fresh agent (no
// proxy, no keep-alive) and no redirect following. Ready means any HTTP
// response with a status from 100 to 499; 5xx and connection errors retry.
// --until ISO_INSTANT: the end of the authorization record's window. It is checked before every probe,
// and once it has passed no further probe is sent: the wait stops with authorization-window-ended.
// Exit codes: 0 ready, 1 timed out, 2 invalid options, non-loopback URL or the authorization window ended.
import { Agent, request } from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { instantMs } from '../../src/authorization.mjs';

const LOOPBACK = /^http:\/\/(127\.0\.0\.1|localhost):([0-9]{1,5})((?:\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?)$/;
export const LIMITS = Object.freeze({ minTimeoutSeconds: 1, maxTimeoutSeconds: 900, minIntervalMs: 50, maxIntervalMs: 10000 });
// An authorization record's instant, read as the record's check reads it (src/authorization.mjs instantMs): a real
// calendar instant in whole milliseconds (no 02-31 rolled over to March, no hour 24), so the time is an exact integer.
export function parseUntil(text) {
  const ms = instantMs(text);
  if (!Number.isSafeInteger(ms)) throw new Error('--until must be an ISO 8601 UTC instant (the authorization record\'s validUntil).');
  return ms;
}

export function parseLoopbackUrl(text) {
  const match = typeof text === 'string' && text.length <= 2048 ? LOOPBACK.exec(text) : null;
  const port = match ? Number(match[2]) : 0;
  if (!match || port < 1 || port > 65535) throw new Error('wait-url must be http://127.0.0.1:PORT or http://localhost:PORT with an optional path.');
  const path = match[3] ? (match[3].startsWith('/') ? match[3] : `/${match[3]}`) : '/';
  return { host: '127.0.0.1', port, path, display: `http://${match[1]}:${port}` };
}

export function probe({ host, port, path }, timeoutMs) {
  return new Promise(done => {
    const agent = new Agent({ keepAlive: false, maxSockets: 1 });
    const finish = value => { agent.destroy(); done(value); };
    const req = request({ host, port, path, method: 'GET', agent, timeout: timeoutMs, headers: { Accept: '*/*' } }, res => {
      res.resume(); // discard the body; nothing from the response is printed or stored
      finish(res.statusCode ?? null);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    // A hard deadline: a server that trickles headers cannot hold a probe open.
    const hard = setTimeout(() => req.destroy(new Error('deadline')), timeoutMs);
    req.on('close', () => clearTimeout(hard));
    req.on('error', () => finish(null));
    req.end();
  });
}

export async function waitFor(url, { timeoutSeconds = 60, intervalMs = 500, until } = {}) {
  const target = parseLoopbackUrl(url);
  const endsAt = until === undefined ? null : parseUntil(until);
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < LIMITS.minTimeoutSeconds || timeoutSeconds > LIMITS.maxTimeoutSeconds) throw new Error('wait-timeout-seconds must be an integer from 1 to 900.');
  if (!Number.isInteger(intervalMs) || intervalMs < LIMITS.minIntervalMs || intervalMs > LIMITS.maxIntervalMs) throw new Error('interval must be an integer from 50 to 10000 ms.');
  const started = Date.now(), deadline = started + timeoutSeconds * 1000;
  let attempts = 0, lastStatus = null;
  while (Date.now() < deadline) {
    if (endsAt !== null && Date.now() >= endsAt) return { ready: false, windowEnded: true, attempts, status: lastStatus, elapsedMs: Date.now() - started, display: target.display };
    attempts += 1;
    lastStatus = await probe(target, Math.max(1, Math.min(2000, deadline - Date.now())));
    if (lastStatus !== null && lastStatus >= 100 && lastStatus <= 499) return { ready: true, attempts, status: lastStatus, elapsedMs: Date.now() - started, display: target.display };
    const pause = Math.min(intervalMs, deadline - Date.now());
    if (pause > 0) await new Promise(next => setTimeout(next, pause));
  }
  return { ready: false, attempts, status: lastStatus, elapsedMs: Date.now() - started, display: target.display };
}

export function parseArgs(args) {
  const names = { '--url': 'url', '--timeout-seconds': 'timeoutSeconds', '--interval-ms': 'intervalMs', '--until': 'until' }, options = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = names[args[i]];
    if (!key || Object.hasOwn(options, key) || i + 1 >= args.length) throw new Error('Usage: wait-for.mjs --url http://127.0.0.1:PORT[/path] [--timeout-seconds N] [--interval-ms N] [--until ISO_INSTANT]');
    options[key] = args[i + 1];
  }
  const integer = (value, fallback) => value === undefined ? fallback : /^[0-9]{1,6}$/.test(value) ? Number(value) : NaN;
  return { url: options.url, timeoutSeconds: integer(options.timeoutSeconds, 60), intervalMs: integer(options.intervalMs, 500), ...(options.until === undefined ? {} : { until: options.until }) };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  let result;
  try { const options = parseArgs(process.argv.slice(2)); result = await waitFor(options.url, options); }
  catch (error) { console.error(`Scopehaven wait-for: ${error.message}`); process.exit(2); }
  if (result.windowEnded) { console.error(`Scopehaven wait-for: authorization refused (authorization-window-ended): the record's window ended while waiting for ${result.display}; nothing more was sent.`); process.exit(2); }
  if (result.ready) console.log(`Scopehaven wait-for: ${result.display} answered HTTP ${result.status} after ${result.attempts} attempt${result.attempts === 1 ? '' : 's'}, ${result.elapsedMs} ms.`);
  else console.error(`Scopehaven wait-for: ${result.display} was not ready within the timeout (${result.attempts} attempt${result.attempts === 1 ? '' : 's'}, last status ${result.status ?? 'no response'}).`);
  process.exitCode = result.ready ? 0 : 1;
}
