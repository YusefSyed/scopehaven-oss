// A stateful Stripe API v1 stand-in on loopback (stage 1). Stripe's own mock server, stripe-mock (MIT), is stateless: it
// answers from fixed fixtures and keeps nothing a request created, so a refunds list from it can never show two refunds. This
// stand-in keeps state for the small subset the refund demos use and follows Stripe's documented semantics for it (pages read
// 2026-10-24). It is not Stripe: no fees, balances, disputes,
// payment intents, webhooks, rate limits or key expiry, and every refund succeeds at once (Stripe's ordinary test cards do the same).
//
// Endpoints (form-encoded bodies, JSON replies, a Request-Id header on every reply):
//   POST /v1/customers          description, source (tok_visa only), metadata[...]
//   POST /v1/charges            amount (>= 50), currency (usd), customer (with a card on file) or source=tok_visa, description, metadata[...]
//   POST /v1/refunds            charge, amount (default: what is left), reason, metadata[...]. A refund can take only what is left on
//                               the charge (400 otherwise); a fully refunded charge answers charge_already_refunded
//   GET  /v1/refunds            charge, created[gte], limit (1 to 100, default 10), starting_after, ending_before: newest first
//   GET  /v1/charges            customer, limit, starting_after, ending_before: newest first
//   GET  /v1/refunds/:id, /v1/charges/:id, /v1/account
// Keys: every request carries Authorization: Bearer <key> (or Basic "<key>:"). Keys are registered at start by role: "write" keys
// (the app's and the operator's seeding key) may do anything; "read" keys answer GETs only (403 on a POST), as a restricted key with
// read permission does. Any other key, a live-mode key included, is refused with 401 and changes nothing. Keys are compared and
// never logged or echoed.
// Idempotency (POST only, Idempotency-Key up to 255 characters, scoped to the account): the first request with a key that passes
// parameter validation is saved once its endpoint begins; a repeat with the same method, path and parameters while it is still
// running answers 409 idempotency_key_in_use, and after it finished replays the saved status and body with Idempotent-Replayed: true.
// A repeat with other parameters answers 400 idempotency_error and changes nothing. A request that fails validation saves nothing,
// so the same key can be used again. Business errors (more than is left, a fully refunded charge, an unknown charge or customer) are
// saved and replayed like a success. Parameters compare as a set, in any order. Not modelled: key expiry after 24 hours, and any
// header on a replay other than Idempotent-Replayed (the pages read name no other).
// slowFirstRefund(charge, ms): the first refund on that charge is committed at once and answered ms later, as a slow provider
// answers after it has already moved the money; its key stays "running" until the answer is sent. This is the harness's control for
// the timeout scenario; Stripe has no such switch.
// truthForTests() returns the stand-in's own state (refunds, charges, request log) for tests and for the harness's check that the
// read-back matched it. No verdict may read it: in stage 2 there is no such view, only the API.
import { createServer } from 'node:http';
import { randomBytes, createHash } from 'node:crypto';

export const STAND_IN_LIMITS = Object.freeze({ bodyBytes: 64 * 1024, objects: 10000, idempotencyKeyChars: 255, metadataKeys: 50, metadataKeyChars: 40, metadataValueChars: 500,
  listMax: 100, listDefault: 10, minChargeAmount: 50, maxAmount: 99999999, slowMs: 30000 });
const KEY = /^(?:sk|rk)_test_[A-Za-z0-9]{16,128}$/;
const LIVE = /(?:sk|rk|pk)_live_/;
const AMOUNT = /^[1-9][0-9]{0,7}$/, SECONDS = /^[0-9]{1,12}$/;
const OBJECT_ID = /^(?:ch|re|cus)_[A-Za-z0-9]{8,64}$/;
const REASONS = Object.freeze(['duplicate', 'fraudulent', 'requested_by_customer']);
const ACCOUNT = /^acct_[A-Za-z0-9]{8,64}$/;
const hex = n => randomBytes(n).toString('hex');
const sha = text => createHash('sha256').update(text).digest('hex');
const err = (status, type, message, extra = {}) => ({ status, body: { error: { type, message, ...extra } } });
const copy = value => JSON.parse(JSON.stringify(value));

// Form fields: each name at most once; metadata[name] collects into one map; anything else is a flat string.
function parseForm(text) {
  const fields = {}, metadata = {}, seen = new Set();
  for (const [name, value] of new URLSearchParams(text)) {
    if (seen.has(name)) return { error: `Received repeated parameter: ${name}` };
    seen.add(name);
    const meta = /^metadata\[([^\[\]]{1,40})\]$/.exec(name);
    if (meta) {
      if (value.length > STAND_IN_LIMITS.metadataValueChars) return { error: `Invalid metadata value for ${meta[1]}` };
      metadata[meta[1]] = value;
    } else if (/^[a-z_]{1,40}$/.test(name)) fields[name] = value;
    else return { error: `Received unknown parameter: ${name}`, code: 'parameter_unknown', param: name };
  }
  if (Object.keys(metadata).length > STAND_IN_LIMITS.metadataKeys) return { error: 'Too many metadata keys' };
  return { fields, metadata };
}

export async function startStripeStandIn({ port = 0, account = `acct_${hex(8)}`, keys = {}, now = () => Date.now() } = {}) {
  if (!ACCOUNT.test(account)) throw new Error('account must be acct_ and 8 to 64 letters or digits.');
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) throw new Error('port must be 0 or a port number.');
  const roles = new Map();
  for (const [role, list] of Object.entries(keys)) {
    if (!['write', 'read'].includes(role) || !Array.isArray(list)) throw new Error('keys is { write: [...], read: [...] }.');
    for (const k of list) { if (typeof k !== 'string' || !KEY.test(k)) throw new Error('every key is a test-mode secret or restricted key (sk_test_ or rk_test_ and 16 to 128 letters or digits).'); if (roles.has(k)) throw new Error('a key is registered once.'); roles.set(k, role); }
  }
  if (![...roles.values()].includes('write')) throw new Error('at least one write key is required.');
  const customers = new Map(), charges = new Map(), refunds = new Map();
  const idem = new Map(); // key -> { method, path, params, state: 'running' | 'done', status, body }
  const log = [], slow = new Map(), seenSlow = new Set(), timers = new Set(), open = new Set();
  let seq = 0, objects = 0;
  const created = () => Math.floor(now() / 1000);
  const next = () => ++seq;

  function newCharge({ amount, currency, customer, description, metadata }) {
    const id = `ch_${hex(12)}`;
    const c = { id, object: 'charge', amount, amount_captured: amount, amount_refunded: 0, captured: true, created: created(), currency, customer: customer ?? null,
      description: description ?? null, livemode: false, metadata, paid: true, payment_method: `card_${hex(12)}`, refunded: false, status: 'succeeded', _seq: next() };
    charges.set(id, c); objects++;
    return c;
  }
  const publicOf = o => { const { _seq, _role, ...rest } = o; return copy(rest); };

  // One POST endpoint, after the key and the form parsed. Returns { status, body } or { validation } (nothing saved).
  function execute(path, fields, metadata, role) {
    if (objects >= STAND_IN_LIMITS.objects) return { validation: err(400, 'invalid_request_error', 'Stand-in object limit reached.') };
    if (path === '/v1/customers') {
      const allowed = ['description', 'source'];
      const extra = Object.keys(fields).find(k => !allowed.includes(k));
      if (extra) return { validation: err(400, 'invalid_request_error', `Received unknown parameter: ${extra}`, { code: 'parameter_unknown', param: extra }) };
      if (fields.source !== undefined && fields.source !== 'tok_visa') return { validation: err(400, 'invalid_request_error', 'The stand-in takes only the test token tok_visa.', { param: 'source' }) };
      const id = `cus_${hex(12)}`;
      const c = { id, object: 'customer', created: created(), description: fields.description ?? null, livemode: false, metadata, default_source: fields.source ? `card_${hex(12)}` : null, _seq: next() };
      customers.set(id, c); objects++;
      return { status: 200, body: publicOf(c) };
    }
    if (path === '/v1/charges') {
      const allowed = ['amount', 'currency', 'customer', 'source', 'description'];
      const extra = Object.keys(fields).find(k => !allowed.includes(k));
      if (extra) return { validation: err(400, 'invalid_request_error', `Received unknown parameter: ${extra}`, { code: 'parameter_unknown', param: extra }) };
      if (!AMOUNT.test(fields.amount ?? '')) return { validation: err(400, 'invalid_request_error', 'Invalid integer: amount', { code: 'parameter_invalid_integer', param: 'amount' }) };
      if (fields.currency !== 'usd') return { validation: err(400, 'invalid_request_error', 'The stand-in takes currency usd only.', { param: 'currency' }) };
      const amount = Number(fields.amount);
      if (amount < STAND_IN_LIMITS.minChargeAmount) return { validation: err(400, 'invalid_request_error', 'Amount must be at least $0.50 usd', { code: 'amount_too_small', param: 'amount' }) };
      if (fields.customer !== undefined && fields.source !== undefined) return { validation: err(400, 'invalid_request_error', 'The stand-in charges a customer\'s card on file or a token, not both.') };
      if (fields.customer !== undefined) {
        const cus = customers.get(fields.customer);
        if (!cus) return err(400, 'invalid_request_error', `No such customer: '${fields.customer}'`, { code: 'resource_missing', param: 'customer' });
        if (!cus.default_source) return err(402, 'card_error', 'Cannot charge a customer that has no active card');
      } else if (fields.source !== 'tok_visa') return { validation: err(400, 'invalid_request_error', 'The stand-in takes only the test token tok_visa.', { param: 'source' }) };
      return { status: 200, body: publicOf(newCharge({ amount, currency: 'usd', customer: fields.customer, description: fields.description, metadata })) };
    }
    if (path === '/v1/refunds') {
      const allowed = ['charge', 'amount', 'reason'];
      const extra = Object.keys(fields).find(k => !allowed.includes(k));
      if (extra) return { validation: err(400, 'invalid_request_error', `Received unknown parameter: ${extra}`, { code: 'parameter_unknown', param: extra }) };
      if (fields.charge === undefined) return { validation: err(400, 'invalid_request_error', 'The stand-in refunds a charge: charge is required.', { code: 'parameter_missing', param: 'charge' }) };
      if (fields.amount !== undefined && !AMOUNT.test(fields.amount)) return { validation: err(400, 'invalid_request_error', 'Invalid integer: amount', { code: 'parameter_invalid_integer', param: 'amount' }) };
      if (fields.reason !== undefined && !REASONS.includes(fields.reason)) return { validation: err(400, 'invalid_request_error', 'Invalid reason', { param: 'reason' }) };
      const charge = charges.get(fields.charge);
      if (!charge) return err(400, 'invalid_request_error', `No such charge: '${fields.charge}'`, { code: 'resource_missing', param: 'charge' });
      const left = charge.amount - charge.amount_refunded;
      if (left === 0) return err(400, 'invalid_request_error', `Charge ${charge.id} has already been refunded.`, { code: 'charge_already_refunded' });
      const amount = fields.amount === undefined ? left : Number(fields.amount);
      // Stripe's create-refund page: a refund "can refund only up to the remaining, unrefunded amount of the charge". The error code
      // for this case is not stated on the pages read, so none is given here.
      if (amount > left) return err(400, 'invalid_request_error', `Refund amount ($${(amount / 100).toFixed(2)}) is greater than unrefunded amount on charge ($${(left / 100).toFixed(2)})`, { param: 'amount' });
      const id = `re_${hex(12)}`;
      const r = { id, object: 'refund', amount, balance_transaction: `txn_${hex(12)}`, charge: charge.id, created: created(), currency: charge.currency, metadata,
        payment_intent: null, reason: fields.reason ?? null, status: 'succeeded', _seq: next(), _role: role };
      refunds.set(id, r); objects++;
      charge.amount_refunded += amount;
      charge.refunded = charge.amount_refunded === charge.amount;
      return { status: 200, body: publicOf(r), charge: charge.id };
    }
    return { validation: err(404, 'invalid_request_error', 'Unrecognized request URL.') };
  }

  // A list in Stripe's shape, newest first; starting_after/ending_before name an object of the list; limit 1 to 100.
  function list(url, path, all, filter) {
    const q = url.searchParams;
    for (const name of new Set(q.keys())) if (q.getAll(name).length > 1) return err(400, 'invalid_request_error', `Received repeated parameter: ${name}`);
    const limitText = q.get('limit');
    if (limitText !== null && !(/^[1-9][0-9]{0,2}$/.test(limitText) && Number(limitText) <= STAND_IN_LIMITS.listMax)) return err(400, 'invalid_request_error', 'Invalid limit', { param: 'limit' });
    const limit = limitText === null ? STAND_IN_LIMITS.listDefault : Number(limitText);
    const items = [...all.values()].filter(filter).sort((a, b) => b._seq - a._seq);
    let start = 0, end = items.length;
    const after = q.get('starting_after'), before = q.get('ending_before');
    if (after !== null && before !== null) return err(400, 'invalid_request_error', 'starting_after and ending_before are exclusive.', { code: 'parameters_exclusive' });
    if (after !== null) { const i = items.findIndex(o => o.id === after); if (i < 0) return err(400, 'invalid_request_error', `No such object: '${after}'`, { code: 'resource_missing', param: 'starting_after' }); start = i + 1; }
    let page;
    if (before !== null) { const i = items.findIndex(o => o.id === before); if (i < 0) return err(400, 'invalid_request_error', `No such object: '${before}'`, { code: 'resource_missing', param: 'ending_before' }); end = i; page = items.slice(Math.max(0, end - limit), end); start = end - page.length; }
    else page = items.slice(start, start + limit);
    const hasMore = before !== null ? start > 0 : start + page.length < items.length;
    return { status: 200, body: { object: 'list', url: path, has_more: hasMore, data: page.map(publicOf) } };
  }

  function read(url) {
    const path = url.pathname, q = url.searchParams;
    if (path === '/v1/account') return { status: 200, body: { id: account, object: 'account', livemode: false } };
    const one = /^\/v1\/(charges|refunds)\/([^/]+)$/.exec(path);
    if (one) {
      const store = one[1] === 'charges' ? charges : refunds, o = OBJECT_ID.test(one[2]) ? store.get(one[2]) : undefined;
      return o ? { status: 200, body: publicOf(o) } : err(404, 'invalid_request_error', `No such ${one[1].slice(0, -1)}: '${one[2]}'`, { code: 'resource_missing', param: 'id' });
    }
    if (path === '/v1/refunds') {
      const known = ['charge', 'created[gte]', 'limit', 'starting_after', 'ending_before'];
      const extra = [...q.keys()].find(k => !known.includes(k));
      if (extra) return err(400, 'invalid_request_error', `Received unknown parameter: ${extra}`, { code: 'parameter_unknown', param: extra });
      const charge = q.get('charge');
      if (charge !== null && !charges.has(charge)) return err(400, 'invalid_request_error', `No such charge: '${charge}'`, { code: 'resource_missing', param: 'charge' });
      const gte = q.get('created[gte]');
      if (gte !== null && !SECONDS.test(gte)) return err(400, 'invalid_request_error', 'Invalid created[gte]', { param: 'created' });
      return list(url, path, refunds, r => (charge === null || r.charge === charge) && (gte === null || r.created >= Number(gte)));
    }
    if (path === '/v1/charges') {
      const known = ['customer', 'limit', 'starting_after', 'ending_before'];
      const extra = [...q.keys()].find(k => !known.includes(k));
      if (extra) return err(400, 'invalid_request_error', `Received unknown parameter: ${extra}`, { code: 'parameter_unknown', param: extra });
      const customer = q.get('customer');
      if (customer !== null && !customers.has(customer)) return err(400, 'invalid_request_error', `No such customer: '${customer}'`, { code: 'resource_missing', param: 'customer' });
      return list(url, path, charges, c => customer === null || c.customer === customer);
    }
    return err(404, 'invalid_request_error', 'Unrecognized request URL.');
  }

  function keyOf(req) {
    const h = req.headers.authorization ?? '';
    const bearer = /^Bearer ([^\s]+)$/.exec(h);
    if (bearer) return bearer[1];
    const basic = /^Basic ([A-Za-z0-9+/=]+)$/.exec(h);
    if (basic) { const text = Buffer.from(basic[1], 'base64').toString('utf8'); const m = /^([^:]+):$/.exec(text); return m ? m[1] : null; }
    return null;
  }

  const server = createServer((req, res) => {
    open.add(res); res.on('close', () => open.delete(res));
    const chunks = []; let size = 0, tooBig = false;
    req.on('data', d => { size += d.length; if (size > STAND_IN_LIMITS.bodyBytes) tooBig = true; else chunks.push(d); });
    req.on('end', () => {
      const requestId = `req_${hex(7)}`, at = now();
      const send = ({ status, body }, { replayed = false } = {}) => {
        if (res.writableEnded || res.destroyed) return;
        res.writeHead(status, { 'Content-Type': 'application/json', 'Request-Id': requestId, Connection: 'close', ...(replayed ? { 'Idempotent-Replayed': 'true' } : {}) });
        res.end(JSON.stringify(body));
      };
      const entry = { seq: log.length + 1, at, method: req.method, path: null, status: null, requestId, role: null, idempotencyKey: null, replayed: false };
      log.push(entry);
      const finish = (reply, extra = {}) => { entry.status = reply.status; Object.assign(entry, extra); send(reply, extra); };
      let url;
      try { url = new URL(req.url, 'http://127.0.0.1'); } catch { return finish(err(400, 'invalid_request_error', 'Invalid URL.')); }
      entry.path = url.pathname;
      const key = keyOf(req);
      if (key !== null && LIVE.test(key)) return finish(err(401, 'invalid_request_error', 'The stand-in is test mode only; a live-mode key is refused.', { code: 'livemode_mismatch' }));
      const role = key === null ? undefined : roles.get(key);
      if (!role) return finish(err(401, 'invalid_request_error', 'Invalid API Key provided.'));
      entry.role = role;
      if (tooBig) return finish(err(413, 'invalid_request_error', 'Request body too large.'));
      const account2 = req.headers['stripe-account'];
      if (account2 !== undefined && account2 !== account) return finish(err(403, 'invalid_request_error', 'The account in the Stripe-Account header is not this stand-in\'s account.', { code: 'account_invalid' }));
      const body = Buffer.concat(chunks).toString('utf8');
      if (req.method === 'GET') {
        if (body.length || req.headers['transfer-encoding']) return finish(err(400, 'invalid_request_error', 'A GET carries no body.'));
        return finish(read(url));
      }
      if (req.method !== 'POST') return finish(err(405, 'invalid_request_error', 'The stand-in answers GET and POST only.'));
      if (role !== 'write') return finish(err(403, 'invalid_request_error', 'The provided key does not have write permission for this endpoint (a read-only restricted key).'));
      if (url.search) return finish(err(400, 'invalid_request_error', 'The stand-in takes POST parameters in the body only.'));
      if (body.length && !/^application\/x-www-form-urlencoded\b/.test(req.headers['content-type'] ?? '')) return finish(err(400, 'invalid_request_error', 'The stand-in takes form-encoded bodies only.'));
      const form = parseForm(body);
      if (form.error) return finish(err(400, 'invalid_request_error', form.error, form.code ? { code: form.code, param: form.param } : {}));
      const idemKey = req.headers['idempotency-key'];
      if (idemKey !== undefined && (typeof idemKey !== 'string' || !idemKey.length || idemKey.length > STAND_IN_LIMITS.idempotencyKeyChars)) return finish(err(400, 'invalid_request_error', 'Invalid Idempotency-Key.'));
      if (idemKey !== undefined) entry.idempotencyKey = sha(`scopehaven-stand-in-key\n${idemKey}`).slice(0, 16);
      // The parameters as a set (order does not matter), with the path.
      const params = sha(JSON.stringify([url.pathname, Object.entries(form.fields).sort(), Object.entries(form.metadata).sort()]));
      if (idemKey !== undefined && idem.has(idemKey)) {
        const saved = idem.get(idemKey);
        if (saved.params !== params) return finish(err(400, 'idempotency_error', 'Keys for idempotent requests can only be used with the same parameters they were first used with.'));
        if (saved.state === 'running') return finish(err(409, 'invalid_request_error', 'There is currently another in-progress request using this Idempotent Key.', { code: 'idempotency_key_in_use' }));
        return finish({ status: saved.status, body: copy(saved.body) }, { replayed: true });
      }
      const result = execute(url.pathname, form.fields, form.metadata, role);
      if (result.validation) return finish(result.validation);
      const saved = idemKey === undefined ? null : { params, state: 'running', status: result.status, body: copy(result.body) };
      if (saved) idem.set(idemKey, saved);
      const delay = url.pathname === '/v1/refunds' && result.status === 200 && slow.has(result.charge) && !seenSlow.has(result.charge) ? slow.get(result.charge) : 0;
      if (delay) {
        seenSlow.add(result.charge);
        const t = setTimeout(() => { timers.delete(t); if (saved) saved.state = 'done'; finish(result); }, delay);
        timers.add(t);
        return;
      }
      if (saved) saved.state = 'done';
      finish(result);
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen({ port, host: '127.0.0.1', exclusive: true }, () => { server.off('error', reject); resolve(); }); });
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    account,
    slowFirstRefund(charge, ms) {
      if (!charges.has(charge)) throw new Error('slowFirstRefund names a charge the stand-in holds.');
      if (!Number.isSafeInteger(ms) || ms < 1 || ms > STAND_IN_LIMITS.slowMs) throw new Error(`ms is 1 to ${STAND_IN_LIMITS.slowMs}.`);
      slow.set(charge, ms);
    },
    // Test and harness use only (see the header): never a verdict input.
    truthForTests: () => ({ account, refunds: [...refunds.values()].sort((a, b) => a._seq - b._seq).map(r => ({ ...publicOf(r), role: r._role })),
      charges: [...charges.values()].sort((a, b) => a._seq - b._seq).map(publicOf), requests: log.map(e => ({ ...e })) }),
    async stop() {
      for (const t of timers) clearTimeout(t);
      timers.clear();
      for (const res of open) res.destroy();
      await new Promise(resolve => { server.closeAllConnections?.(); server.close(() => resolve()); });
    },
  };
}
