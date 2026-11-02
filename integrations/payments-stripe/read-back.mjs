// The Stripe read-back observer: ScopeHaven's own read of the provider's ledger through the provider's API, never through the
// app or its tables. At each mark the operator calls read(label); the observer lists, with a read-only restricted test key the app
// never holds:
//   GET /v1/account                              the account the key reads (compared with the declared one)
//   GET /v1/charges?customer=<cus>               every charge of each declared test customer, all pages
//   GET /v1/charges/<id>                         each declared charge the customer lists did not return
//   GET /v1/refunds?charge=<id>                  every refund of every charge above, all pages
//   GET /v1/refunds?created[gte]=<since>         every refund the account created since the run began, all pages, so a refund on a
//                                                charge outside the declared set is still seen (kept under "outside")
// and seals the result as one ledger read (scopehaven-stripe-ledger/1). A refund on a charge that is not declared, a charge a declared
// customer was given during the run included, is kept under "outside". Each read is taken twice, settleMs apart, and the two must
// agree; anything that could hide a refund makes the read partial, never "nothing happened":
//   a reply that is not 200, not JSON, over the size cap or not in Stripe's list/object shape; a timeout or a failed connection;
//   has_more still true after maxPages; a repeated id; a refund listed under a charge it does not name; a refund whose currency is
//   not its charge's; a charge whose amount_refunded is not the sum of its refunds that move money (succeeded, pending,
//   requires_action); a refund status outside Stripe's list; any object with livemode other than false; another account than the
//   declared one; a declared charge created before `since` (so the account-wide list could start after a refund on it; `since` is
//   taken from the provider's own clock: the seeded charges' created time), or no declared charge at all (since-unverified: nothing
//   on the provider's clock bounds `since`); the two passes disagreeing.
// Every read carries its observer: a random id, a sequence number (strictly increasing per observer, so windows are ordered by it,
// not by a clock), the observer's configuration and whether the default loopback transport made the requests ("default") or a
// caller-supplied one ("injected", tests only; verdict.mjs refuses it unless told otherwise).
// What a read keeps: object ids, amounts, currencies, statuses, created times, the charge's customer id, the declared metadata keys
// (short plain values only) and, per request, the path with its query, the status, the Request-Id and the page shape. Never the key,
// a header, a body or a payment method. The key stays in this module's closure and is sent only as Authorization: Bearer.
// Custody: a read returned by read() is deeply frozen and branded in memory (isAuthenticRead). Its sha256 is an unkeyed checksum of
// its canonical JSON: a saved read can be checked for edits (verifySealedRead) but is not a signature, so a file is not a portable proof.
// Two modes. 'loopback-stand-in' (stage 1, the default): the provider is the loopback stand-in (stand-in.mjs) at
// http://127.0.0.1:<port>. 'stripe-test-mode' (stage 2): the provider is Stripe itself, base exactly
// https://api.stripe.com, over TLS with the certificate checked for api.stripe.com, a pinned Stripe-Version, and a declared sandbox
// account that every read must match (GET /v1/account needs the read key's connected_account_read permission; a 403 there leaves
// the read partial, never a pass). The host is fixed in this file and never comes from configuration or a request. The request
// budget (budget.mjs) paces and caps the requests and is required in stripe-test-mode unless testTls is given; a request it refuses
// leaves the read partial (request-budget).
import { request } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { createHash, randomUUID } from 'node:crypto';

export const LEDGER_SCHEMA = 'scopehaven-stripe-ledger/1';
export const READ_BACK_MODES = Object.freeze(['loopback-stand-in', 'stripe-test-mode']);
export const STRIPE_TEST_BASE = 'https://api.stripe.com';
// Chosen for stage 2 (docs.stripe.com/changelog/endive, read 2026-10-25) and recorded in every stage-2 read.
export const STRIPE_VERSION = '2026-09-30.endive';
const STRIPE_HOST = 'api.stripe.com';
export const READ_BACK_LIMITS = Object.freeze({ pageLimit: 100, maxPages: Object.freeze([1, 100]), timeoutMs: Object.freeze([100, 30000]), settleMs: Object.freeze([0, 120000]),
  charges: 200, customers: 20, metadataKeys: 8, bodyBytes: 4 * 1024 * 1024, metadataValue: /^[A-Za-z0-9_.:@-]{1,64}$/, futureSinceSeconds: 300 });
export const MOVING = Object.freeze(['succeeded', 'pending', 'requires_action']);
export const REFUND_STATUSES = Object.freeze(['succeeded', 'pending', 'requires_action', 'failed', 'canceled']);
const LOOPBACK = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/;
const READ_KEY = /^rk_test_[A-Za-z0-9]{16,128}$/;
const ACCOUNT = /^acct_[A-Za-z0-9]{8,64}$/;
const CHARGE = /^ch_[A-Za-z0-9]{8,64}$/, REFUND = /^re_[A-Za-z0-9]{8,64}$/, CUSTOMER = /^cus_[A-Za-z0-9]{8,64}$/;
const META_KEY = /^[a-z][a-z0-9_]{0,39}$/;
const READS = new WeakSet();

const plain = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const int = v => Number.isSafeInteger(v);
// Canonical JSON: object keys sorted at every level, arrays in order.
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (plain(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const digestOf = value => createHash('sha256').update(canonical(value)).digest('hex');
function deepFreeze(value) { if (value && typeof value === 'object') { for (const v of Object.values(value)) deepFreeze(v); Object.freeze(value); } return value; }

export const isAuthenticRead = read => READS.has(read) && Object.isFrozen(read);
// A saved read (JSON parsed back): its schema and its checksum over everything but the checksum. Integrity only.
export function verifySealedRead(read) {
  if (!plain(read) || read.schema !== LEDGER_SCHEMA || typeof read.sha256 !== 'string') return { ok: false, reason: 'not-a-ledger-read' };
  const { sha256, ...rest } = read;
  return digestOf(rest) === sha256 ? { ok: true } : { ok: false, reason: 'checksum-mismatch' };
}

// One GET on its own connection, made by open(onReply). Resolves { status, requestId, text } or { error }.
function getOnce(open, timeoutMs) {
  return new Promise(resolve => {
    let done = false;
    const end = value => { if (!done) { done = true; resolve(value); } };
    const req = open(res => {
      const chunks = []; let size = 0;
      res.on('data', d => { size += d.length; if (size > READ_BACK_LIMITS.bodyBytes) { req.destroy(); end({ error: 'over-cap' }); } else chunks.push(d); });
      res.on('end', () => end({ status: res.statusCode, requestId: typeof res.headers['request-id'] === 'string' ? res.headers['request-id'] : null, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', () => end({ error: 'failed' }));
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); end({ error: 'timeout' }); });
    req.on('error', () => end({ error: 'failed' }));
    req.end();
  });
}
// The default transport in stage 1: the loopback provider.
function loopbackTransport({ port, path, headers, timeoutMs }) {
  return getOnce(onReply => request({ host: '127.0.0.1', port, method: 'GET', path, agent: false, headers: { ...headers, Connection: 'close' } }, onReply), timeoutMs);
}
// The default transport in stage 2: api.stripe.com on port 443, certificate checked for that name against Node's CA store, no agent
// (so no keep-alive and no proxy), no redirect followed (a redirect is not a 200, so the read is partial). testTls (tests only) gives a
// CA, a port and a resolver so a local TLS server can answer for api.stripe.com; the observer then labels its reads test-tls, which
// verdict.mjs does not accept.
function stripeTransport(testTls) {
  return ({ path, headers, timeoutMs }) => getOnce(onReply => httpsRequest({ host: STRIPE_HOST, servername: STRIPE_HOST, port: testTls ? testTls.port : 443, method: 'GET', path, agent: false,
    rejectUnauthorized: true, ...(testTls ? { ca: testTls.ca, lookup: testTls.lookup } : {}), headers: { ...headers, Host: STRIPE_HOST, 'Stripe-Version': STRIPE_VERSION, Connection: 'close' } }, onReply), timeoutMs);
}
const isTestTls = v => plain(v) && typeof v.ca === 'string' && int(v.port) && v.port > 0 && v.port < 65536 && typeof v.lookup === 'function';

// Stage 2, once per invocation per key before any write: the key (the read key, and the desk key that writes) reads the declared
// sandbox, in test mode. Resolves { ok, status, requestId, account, reason }; never the key or a body.
export async function confirmStripeAccount({ key, account, budget = null, testTls = null, timeoutMs = 10000 } = {}) {
  if (typeof key !== 'string' || !READ_KEY.test(key)) throw new Error('key is a restricted test key (rk_test_...).');
  if (typeof account !== 'string' || !ACCOUNT.test(account)) throw new Error('account is the declared sandbox account, acct_....');
  if (testTls !== null && !isTestTls(testTls)) throw new Error('testTls is { ca, port, lookup }, for tests only.');
  if (budget === null && testTls === null) throw new Error('a request to api.stripe.com needs a request budget (budget.mjs).');
  if (budget) await budget.take();
  const r = await stripeTransport(testTls)({ path: '/v1/account', headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' }, timeoutMs });
  budget?.note(r.status ?? null);
  const out = { ok: false, status: r.status ?? null, requestId: r.requestId ?? null, account: null, reason: null };
  if (r.error) return { ...out, reason: r.error };
  if (r.status !== 200) return { ...out, reason: r.status === 403 ? 'status-403 (the key needs connected_account_read)' : `status-${r.status}` };
  let json; try { json = JSON.parse(r.text); } catch { return { ...out, reason: 'not-json' }; }
  if (!plain(json) || typeof json.id !== 'string' || !ACCOUNT.test(json.id)) return { ...out, reason: 'shape' };
  if (Object.hasOwn(json, 'livemode') && json.livemode !== false) return { ...out, account: json.id, reason: 'livemode' };
  if (json.id !== account) return { ...out, account: json.id, reason: 'account-mismatch' };
  return { ...out, ok: true, account: json.id };
}

// refuseKeys: keys this observer must never be given (the app's own keys): a match is refused, so the app's write key cannot be the read
// key. They are compared once and not kept.
export function createStripeReadBack({ mode = 'loopback-stand-in', base, key, account = null, connectedAccount = null, charges = [], customers = [], since, metadataKeys = [], settleMs = 300, timeoutMs = 2000, maxPages = 20, transport = loopbackTransport, refuseKeys = [], budget = null, testTls = null } = {}) {
  if (!READ_BACK_MODES.includes(mode)) throw new Error('mode is loopback-stand-in or stripe-test-mode.');
  const stripe = mode === 'stripe-test-mode';
  const m = LOOPBACK.exec(base ?? '');
  if (stripe) {
    if (base !== STRIPE_TEST_BASE) throw new Error(`base in stripe-test-mode is exactly ${STRIPE_TEST_BASE}; nothing else hosted is read.`);
    if (typeof account !== 'string' || !ACCOUNT.test(account)) throw new Error('stripe-test-mode needs the declared sandbox account (acct_...); a read of another account is partial.');
    if (testTls !== null && !isTestTls(testTls)) throw new Error('testTls is { ca, port, lookup }, for tests only.');
    if (budget === null && testTls === null && transport === loopbackTransport) throw new Error('stripe-test-mode against api.stripe.com needs a request budget (budget.mjs).');
  } else if (!m || Number(m[1]) > 65535) throw new Error('base is the loopback provider, http://127.0.0.1:<port>; Stripe test mode is mode stripe-test-mode.');
  else if (testTls !== null) throw new Error('testTls is for stripe-test-mode only.');
  if (budget !== null && !(typeof budget?.take === 'function' && typeof budget?.note === 'function')) throw new Error('budget is a request budget (budget.mjs).');
  if (typeof key !== 'string' || !READ_KEY.test(key)) throw new Error('key is a read-only restricted test key (rk_test_...); a secret key, a live key or a write key is refused.');
  if (!Array.isArray(refuseKeys) || refuseKeys.includes(key)) throw new Error('the read key must not be a key the app holds (refuseKeys).');
  if (account !== null && !ACCOUNT.test(account)) throw new Error('account is acct_... or null.');
  if (connectedAccount !== null && !ACCOUNT.test(connectedAccount)) throw new Error('connectedAccount is acct_... or null.');
  if (!Array.isArray(charges) || charges.length > READ_BACK_LIMITS.charges || !charges.every(c => typeof c === 'string' && CHARGE.test(c)) || new Set(charges).size !== charges.length) throw new Error('charges is a list of distinct ch_ ids.');
  if (!Array.isArray(customers) || customers.length > READ_BACK_LIMITS.customers || !customers.every(c => typeof c === 'string' && CUSTOMER.test(c)) || new Set(customers).size !== customers.length) throw new Error('customers is a list of distinct cus_ ids.');
  if (!int(since) || since < 0) throw new Error('since is the run start in Unix seconds, from the provider\'s clock.');
  if (since > Math.floor(Date.now() / 1000) + READ_BACK_LIMITS.futureSinceSeconds) throw new Error('since is in the future.');
  if (!Array.isArray(metadataKeys) || metadataKeys.length > READ_BACK_LIMITS.metadataKeys || !metadataKeys.every(k => typeof k === 'string' && META_KEY.test(k))) throw new Error('metadataKeys is a short list of metadata names.');
  const inRange = (v, [lo, hi]) => int(v) && v >= lo && v <= hi;
  if (!inRange(settleMs, READ_BACK_LIMITS.settleMs) || !inRange(timeoutMs, READ_BACK_LIMITS.timeoutMs) || !inRange(maxPages, READ_BACK_LIMITS.maxPages)) throw new Error('settleMs, timeoutMs or maxPages is out of range.');
  const port = stripe ? null : Number(m[1]);
  const send = stripe && transport === loopbackTransport ? stripeTransport(testTls) : transport;
  const headers = { Authorization: `Bearer ${key}`, Accept: 'application/json', ...(connectedAccount ? { 'Stripe-Account': connectedAccount } : {}) };
  const declared = new Set(charges);
  const observer = { id: randomUUID(), transport: transport === loopbackTransport ? (testTls ? 'test-tls' : 'default') : 'injected', declaredCharges: [...charges].sort(), customers: [...customers].sort(), since,
    metadataKeys: [...metadataKeys], connectedAccount, settleMs, maxPages };
  let seq = 0, reading = false;
  const metaOf = md => Object.fromEntries(metadataKeys.filter(k => plain(md) && Object.hasOwn(md, k)).map(k => [k, typeof md[k] === 'string' && READ_BACK_LIMITS.metadataValue.test(md[k]) ? md[k] : '[omitted]']));

  // One pass over every list. Returns { reasons, requests, account, charges: Map, refunds: Map, outside: Map }.
  async function pass(n) {
    const reasons = new Set(), requests = [], chargesById = new Map(), refundsById = new Map(), extra = new Map();
    let accountSeen = null;
    const get = async (path, query = '') => {
      const full = query ? `${path}?${query}` : path;
      if (budget) {
        try { await budget.take(); } catch { requests.push({ pass: n, method: 'GET', path: full, status: null, requestId: null }); reasons.add('request-budget'); return null; }
      }
      const r = await send({ port, path: full, headers, timeoutMs });
      budget?.note(r.status ?? null);
      const rec = { pass: n, method: 'GET', path: full, status: r.status ?? null, requestId: r.requestId ?? null };
      requests.push(rec);
      if (r.error) { reasons.add(r.error); return null; }
      if (r.status !== 200) { reasons.add(`status-${r.status}`); return null; }
      let json;
      try { json = JSON.parse(r.text); } catch { reasons.add('not-json'); return null; }
      if (!plain(json)) { reasons.add('shape'); return null; }
      return { json, rec };
    };
    const listAll = async (path, query, check) => {
      const items = [], ids = new Set();
      let after = null;
      for (let page = 1; ; page++) {
        const got = await get(path, `${query}&limit=${READ_BACK_LIMITS.pageLimit}${after ? `&starting_after=${encodeURIComponent(after)}` : ''}`);
        if (!got) return null;
        const { json, rec } = got;
        if (json.object !== 'list' || !Array.isArray(json.data) || typeof json.has_more !== 'boolean') { reasons.add('shape'); return null; }
        rec.items = json.data.length; rec.hasMore = json.has_more;
        for (const o of json.data) {
          if (!check(o)) { reasons.add('shape'); return null; }
          if (ids.has(o.id)) { reasons.add('duplicate-id'); return null; }
          ids.add(o.id); items.push(o);
        }
        if (!json.has_more) return items;
        if (!json.data.length) { reasons.add('shape'); return null; }
        if (page >= maxPages) { reasons.add('pagination-cap'); return null; }
        after = json.data[json.data.length - 1].id;
      }
    };
    const isCharge = o => plain(o) && o.object === 'charge' && typeof o.id === 'string' && CHARGE.test(o.id) && int(o.amount) && o.amount > 0 && int(o.amount_refunded) && o.amount_refunded >= 0
      && typeof o.currency === 'string' && typeof o.refunded === 'boolean' && typeof o.status === 'string' && (o.customer === null || typeof o.customer === 'string') && int(o.created) && plain(o.metadata ?? {});
    const isRefund = o => plain(o) && o.object === 'refund' && typeof o.id === 'string' && REFUND.test(o.id) && int(o.amount) && o.amount > 0 && typeof o.charge === 'string'
      && typeof o.currency === 'string' && typeof o.status === 'string' && int(o.created) && plain(o.metadata ?? {});
    const keepCharge = o => {
      if (o.livemode !== false) reasons.add('livemode');
      const rec = { id: o.id, amount: o.amount, amount_refunded: o.amount_refunded, refunded: o.refunded, currency: o.currency, customer: o.customer, status: o.status, created: o.created, metadata: metaOf(o.metadata) };
      const prior = chargesById.get(o.id);
      if (prior && canonical(prior) !== canonical(rec)) reasons.add('list-disagreement');
      chargesById.set(o.id, rec);
    };
    const refundRec = o => ({ id: o.id, charge: o.charge, amount: o.amount, currency: o.currency, status: o.status, created: o.created, reason: typeof o.reason === 'string' ? o.reason : null, metadata: metaOf(o.metadata) });

    const acct = await get('/v1/account');
    if (acct) {
      if (typeof acct.json.id !== 'string' || !ACCOUNT.test(acct.json.id)) reasons.add('shape');
      else { accountSeen = acct.json.id; if (account !== null && accountSeen !== account) reasons.add('account-mismatch'); }
      if (Object.hasOwn(acct.json, 'livemode') && acct.json.livemode !== false) reasons.add('livemode');
    }
    for (const cus of customers) {
      const list = await listAll('/v1/charges', `customer=${encodeURIComponent(cus)}`, isCharge);
      if (!list) continue;
      for (const o of list) { if (o.customer !== cus) reasons.add('customer-mismatch'); keepCharge(o); }
    }
    for (const id of charges) {
      if (chargesById.has(id)) continue;
      const got = await get(`/v1/charges/${encodeURIComponent(id)}`);
      if (!got) continue;
      if (!isCharge(got.json) || got.json.id !== id) { reasons.add('shape'); continue; }
      keepCharge(got.json);
    }
    for (const id of [...chargesById.keys()].sort()) {
      const list = await listAll('/v1/refunds', `charge=${encodeURIComponent(id)}`, isRefund);
      if (!list) continue;
      for (const o of list) {
        if (o.charge !== id) { reasons.add('refund-charge-mismatch'); continue; }
        if (refundsById.has(o.id)) { reasons.add('duplicate-id'); continue; }
        refundsById.set(o.id, refundRec(o));
      }
    }
    const recent = await listAll('/v1/refunds', `created[gte]=${since}`, isRefund);
    if (recent) {
      const ids = new Set(recent.map(o => o.id));
      for (const o of recent) {
        if (chargesById.has(o.charge)) {
          const mine = refundsById.get(o.id);
          if (!mine || canonical(mine) !== canonical(refundRec(o))) reasons.add('list-disagreement');
        } else extra.set(o.id, refundRec(o));
      }
      // Every refund the charge lists returned that was created since the run began must also be in the account-wide list.
      for (const r of refundsById.values()) if (r.created >= since && !ids.has(r.id)) reasons.add('list-disagreement');
    }
    for (const r of [...refundsById.values(), ...extra.values()]) if (!REFUND_STATUSES.includes(r.status)) reasons.add('status-word');
    for (const c of chargesById.values()) {
      const own = [...refundsById.values()].filter(r => r.charge === c.id);
      if (own.some(r => r.currency !== c.currency)) reasons.add('currency-mismatch');
      const moving = own.filter(r => MOVING.includes(r.status)).reduce((s, r) => s + r.amount, 0);
      if (moving !== c.amount_refunded) reasons.add('amount-refunded-mismatch');
    }
    for (const id of declared) if (!chargesById.has(id)) reasons.add('declared-charge-missing');
    for (const id of declared) if (chargesById.has(id) && chargesById.get(id).created < since) reasons.add('since-after-charge');
    // With no declared charge nothing on the provider's clock bounds `since`, so the account-wide list may start too late.
    if (!declared.size) reasons.add('since-unverified');
    // Refunds on declared charges are the ledger's rows; every other refund the reads saw is outside, wherever it was listed.
    const own = new Map([...refundsById].filter(([, r]) => declared.has(r.charge)));
    const outside = new Map([...[...refundsById].filter(([, r]) => !declared.has(r.charge)), ...extra]);
    return { reasons, requests, account: accountSeen, charges: chargesById, refunds: own, outside };
  }

  const sorted = map => [...map.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const body = p => ({ charges: sorted(p.charges), refunds: sorted(p.refunds), outside: sorted(p.outside), account: p.account });

  return {
    async read(label) {
      if (typeof label !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(label)) throw new Error('label is 1 to 64 letters, digits, dots, dashes or underscores.');
      if (reading) throw new Error('one read at a time per observer.');
      reading = true;
      const n = ++seq, startedAt = new Date().toISOString();
      try {
        const first = await pass(1);
        if (settleMs) await new Promise(resolve => setTimeout(resolve, settleMs));
        const second = await pass(2);
        const reasons = new Set([...first.reasons, ...second.reasons]);
        if (canonical(body(first)) !== canonical(body(second))) reasons.add('unsettled');
        const b = body(second);
        const read = { schema: LEDGER_SCHEMA, label, startedAt, readAt: new Date().toISOString(), observer: { ...observer, seq: n },
          provider: { kind: stripe ? 'stripe-test-mode' : 'loopback-stand-in', base, account: b.account, declaredAccount: account, connectedAccount, ...(stripe ? { stripeVersion: STRIPE_VERSION } : {}) },
          credential: { class: 'restricted-test-read' },
          coverage: reasons.size ? 'partial' : 'complete', reasons: [...reasons].sort(),
          charges: b.charges, refunds: b.refunds, outside: b.outside, requests: [...first.requests, ...second.requests] };
        read.sha256 = digestOf(read);
        deepFreeze(read);
        READS.add(read);
        return read;
      } finally { reading = false; }
    },
  };
}
