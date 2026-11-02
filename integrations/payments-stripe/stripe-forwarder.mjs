// The stage-2 forwarder: the desk's Stripe base and the operator's seeding
// path in stage 2. It listens on 127.0.0.1 and sends each request it accepts on to api.stripe.com unchanged, so the money moves at
// Stripe, and gives the slow provider the timeout scenario needs: for the first refund on a named charge it sends Stripe's answer no
// earlier than ms after the request arrived (slowFirstRefund, the stand-in's switch of the same name and timing: committed at once,
// answered ms later). Stripe's own latency and any wait for the request budget count toward the ms, so a hold shorter than the desk's
// tool timeout stays shorter; when Stripe itself answers later than that, its answer goes back at once and the log shows heldMs 0.
// What it forwards, and nothing else:
//   POST /v1/customers, POST /v1/charges, POST /v1/refunds, form-encoded (or empty: the read-key probe), at most 64 KiB, no query
//   string;
//   with Authorization: Bearer <one of the keys it was started with>: the run's desk key and read key, both restricted test keys
//   (rk_test_...), held in memory only. Any other key (another restricted test key, a secret key, a live key, none) is answered 401
//   here and never sent;
//   the headers Authorization, Content-Type, Idempotency-Key and a pinned Stripe-Version; every other request header is dropped.
// A request it cannot parse (a malformed target) is answered 400 here and never sent.
// The upstream is fixed in this file: api.stripe.com on port 443, the certificate checked for that name, no agent (no keep-alive, no
// proxy), redirects not followed (the desk gets the 3xx as is). It never comes from configuration or a request. testTls (tests only)
// supplies a CA, a port and a resolver so a local TLS server can answer for api.stripe.com; the log says upstream "test-tls".
// The request budget (budget.mjs) paces and caps the forwarded requests and is required unless testTls is given; a request it refuses
// is answered 503 here and never sent, and a 429 from Stripe stops the budget.
// What it keeps (log()): per request its sequence number, method, path, the status, Stripe's Request-Id, whether Stripe replayed it
// (Idempotent-Replayed), how long the answer was held, the charge a refund names, and salted digest prefixes that group requests by
// idempotency key and by key (keyGroupOf names a key's group for the operator). Never a key, a header, a body or an amount.
// stop() closes the listener and ends every held answer's wait.
import { createServer } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createHash, randomBytes } from 'node:crypto';
import { STRIPE_VERSION } from './read-back.mjs';

export const FORWARDER_LIMITS = Object.freeze({ bodyBytes: 64 * 1024, replyBytes: 1024 * 1024, idempotencyKeyChars: 255, holdMs: 30000, timeoutMs: Object.freeze([1000, 60000]), keys: 4 });
export const FORWARDED = Object.freeze(['/v1/customers', '/v1/charges', '/v1/refunds']);
const STRIPE_HOST = 'api.stripe.com';
const BEARER = /^Bearer (rk_test_[A-Za-z0-9]{16,128})$/;
const RESTRICTED_TEST_KEY = /^rk_test_[A-Za-z0-9]{16,128}$/;
const CHARGE = /^ch_[A-Za-z0-9]{8,64}$/;
const local = (res, status, type, message) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify({ error: { type, message } })); };
const isTestTls = v => v !== null && typeof v === 'object' && typeof v.ca === 'string' && Number.isSafeInteger(v.port) && v.port > 0 && v.port < 65536 && typeof v.lookup === 'function';

export async function startStripeForwarder({ keys, budget = null, testTls = null, timeoutMs = 20000 } = {}) {
  if (testTls !== null && !isTestTls(testTls)) throw new Error('testTls is { ca, port, lookup }, for tests only.');
  if (budget !== null && !(typeof budget?.take === 'function' && typeof budget?.note === 'function')) throw new Error('budget is a request budget (budget.mjs).');
  if (budget === null && testTls === null) throw new Error('a forwarder to api.stripe.com needs a request budget (budget.mjs).');
  if (!Array.isArray(keys) || !keys.length || keys.length > FORWARDER_LIMITS.keys || !keys.every(k => typeof k === 'string' && RESTRICTED_TEST_KEY.test(k)) || new Set(keys).size !== keys.length)
    throw new Error('keys is the run\'s restricted test keys (rk_test_...), 1 to 4 distinct ones; the forwarder relays no other.');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < FORWARDER_LIMITS.timeoutMs[0] || timeoutMs > FORWARDER_LIMITS.timeoutMs[1]) throw new Error('timeoutMs is 1000 to 60000.');
  const allowed = new Set(keys);
  const salt = randomBytes(16);
  const group = value => createHash('sha256').update(salt).update(String(value)).digest('hex').slice(0, 12);
  const holds = new Map(), log = [], waits = new Set();
  let seq = 0;
  // A held answer's wait; stop() ends every one.
  const hold = ms => new Promise(resolve => { const w = { resolve, timer: setTimeout(() => { waits.delete(w); resolve(); }, ms) }; waits.add(w); });

  function upstream(path, headers, body) {
    return new Promise(resolve => {
      let done = false; const end = v => { if (!done) { done = true; resolve(v); } };
      const req = httpsRequest({ host: STRIPE_HOST, servername: STRIPE_HOST, port: testTls ? testTls.port : 443, method: 'POST', path, agent: false, rejectUnauthorized: true,
        ...(testTls ? { ca: testTls.ca, lookup: testTls.lookup } : {}), headers: { ...headers, Host: STRIPE_HOST, 'Content-Length': body.length, Connection: 'close' } }, res => {
        const chunks = []; let size = 0;
        res.on('data', d => { size += d.length; if (size > FORWARDER_LIMITS.replyBytes) { req.destroy(); end({ error: 'over-cap' }); } else chunks.push(d); });
        res.on('end', () => end({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
        res.on('error', () => end({ error: 'failed' }));
      });
      req.setTimeout(timeoutMs, () => { req.destroy(); end({ error: 'timeout' }); });
      req.on('error', () => end({ error: 'failed' }));
      req.end(body);
    });
  }

  async function handle(req, res, body, over, arrived) {
    const n = ++seq, entry = { seq: n, method: req.method, path: null, status: null, requestId: null, replayed: false, heldMs: 0, charge: null, idemGroup: null, keyGroup: null, local: null };
    const refuse = (status, type, message) => { entry.status = status; entry.local = type; log.push(entry); local(res, status, type, message); };
    let url;
    try { url = new URL(req.url, 'http://127.0.0.1'); } catch { return refuse(400, 'scopehaven_forwarder', 'not forwarded: the request target does not parse'); }
    entry.path = FORWARDED.includes(url.pathname) ? url.pathname : '(other)';
    if (req.method !== 'POST' || !FORWARDED.includes(url.pathname) || url.search) return refuse(404, 'scopehaven_forwarder', 'not forwarded: only POST /v1/customers, /v1/charges and /v1/refunds');
    if (over) return refuse(413, 'scopehaven_forwarder', 'body over 64 KiB');
    if (body.length && (req.headers['content-type'] ?? '').split(';')[0].trim() !== 'application/x-www-form-urlencoded') return refuse(415, 'scopehaven_forwarder', 'form-encoded bodies only');
    const bearer = BEARER.exec(typeof req.headers.authorization === 'string' ? req.headers.authorization : '');
    if (!bearer) return refuse(401, 'scopehaven_forwarder', 'a restricted test key (rk_test_) only; nothing was sent');
    if (!allowed.has(bearer[1])) return refuse(401, 'scopehaven_forwarder', 'a key this run did not start the forwarder with; nothing was sent');
    entry.keyGroup = group(bearer[1]);
    const idem = req.headers['idempotency-key'];
    if (idem !== undefined && (typeof idem !== 'string' || !idem.length || idem.length > FORWARDER_LIMITS.idempotencyKeyChars)) return refuse(400, 'scopehaven_forwarder', 'Idempotency-Key is 1 to 255 characters');
    if (idem !== undefined) entry.idemGroup = group(idem);
    if (url.pathname === '/v1/refunds') {
      const charge = new URLSearchParams(body.toString('utf8')).get('charge');
      entry.charge = typeof charge === 'string' && CHARGE.test(charge) ? charge : null;
    }
    if (budget) { try { await budget.take(); } catch { return refuse(503, 'scopehaven_budget', 'the request budget stopped this invocation; nothing was sent'); } }
    const headers = { Authorization: `Bearer ${bearer[1]}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Stripe-Version': STRIPE_VERSION, ...(idem !== undefined ? { 'Idempotency-Key': idem } : {}) };
    // The first refund on a held charge: Stripe commits it now, and the answer goes back no earlier than hold ms after it arrived.
    const holdMs = entry.charge !== null && holds.has(entry.charge) ? holds.get(entry.charge) : 0;
    if (holdMs) holds.delete(entry.charge);
    const r = await upstream(url.pathname, headers, body);
    budget?.note(r.status ?? null);
    const wait = holdMs ? Math.max(0, arrived + holdMs - Date.now()) : 0;
    if (r.error) { entry.local = r.error; entry.status = 502; entry.heldMs = wait; log.push(entry); if (wait) await hold(wait); return local(res, 502, 'scopehaven_forwarder', `upstream ${r.error}`); }
    entry.status = r.status;
    entry.requestId = typeof r.headers['request-id'] === 'string' ? r.headers['request-id'] : null;
    entry.replayed = r.headers['idempotent-replayed'] === 'true';
    entry.heldMs = wait;
    log.push(entry);
    if (wait) await hold(wait);
    const out = { 'Content-Type': typeof r.headers['content-type'] === 'string' ? r.headers['content-type'] : 'application/json', Connection: 'close',
      ...(entry.requestId ? { 'Request-Id': entry.requestId } : {}), ...(r.headers['idempotent-replayed'] !== undefined ? { 'Idempotent-Replayed': String(r.headers['idempotent-replayed']) } : {}),
      ...(typeof r.headers.location === 'string' ? { Location: r.headers.location } : {}) };
    // The desk may have given up while the answer was held; a write to a closed socket is ignored.
    try { res.writeHead(r.status, out); res.end(r.body); } catch { /* the client is gone */ }
  }

  const server = createServer((req, res) => {
    // Arrival is when the request reached the forwarder, before its body, the budget's wait or Stripe.
    const arrived = Date.now();
    const chunks = []; let size = 0, over = false;
    req.on('data', d => { size += d.length; if (size > FORWARDER_LIMITS.bodyBytes) over = true; else chunks.push(d); });
    req.on('end', () => {
      handle(req, res, Buffer.concat(chunks), over, arrived).catch(() => { try { if (!res.headersSent) local(res, 400, 'scopehaven_forwarder', 'not forwarded'); else res.end(); } catch { /* the client is gone */ } });
    });
    req.on('error', () => {});
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    upstream: testTls ? 'test-tls' : `https://${STRIPE_HOST}`,
    slowFirstRefund(charge, ms) {
      if (typeof charge !== 'string' || !CHARGE.test(charge)) throw new Error('charge is a ch_ id.');
      if (!Number.isSafeInteger(ms) || ms < 1 || ms > FORWARDER_LIMITS.holdMs) throw new Error('ms is 1 to 30000.');
      holds.set(charge, ms);
    },
    keyGroupOf: key => group(key),
    log: () => log.map(e => ({ ...e })),
    held: () => waits.size,
    async stop() {
      for (const w of waits) { clearTimeout(w.timer); w.resolve(); }
      waits.clear();
      await new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); });
    },
  };
}
