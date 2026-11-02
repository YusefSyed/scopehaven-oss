// Test fixture (owned, synthetic).
// Owned practice storefront/helpdesk with a support assistant: the stand-in for
// "any business with a support bot". Loopback only, synthetic data, no
// dependencies (Node 24 built-ins). The assistant is deterministic (rules, no
// model), so planted drills fail the same way on every run.
//
// What it models:
//   - the assistant shows one customer's data (order lookup);
//   - it acts on accounts (refund, cancel);
//   - it makes money commitments (courtesy discount credits, capped by plan);
//   - every action is written to an audit table, and customers can see their own
//     refunds, orders and credits through the account API (the victim-side surface).
// Reversible drills (admin endpoint, off by default):
//   - crossCustomer: order lookup skips the ownership check;
//   - claimWithoutRecord: the assistant says a refund was issued but writes nothing;
//   - crossCustomerAction: refund and cancel skip the ownership check, so one
//     customer's chat changes another customer's order (seen on the victim's account).
import { createServer } from 'node:http';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile, rename, chmod } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const APP_VERSION = 'storefront-practice/1';
export const DRILLS = Object.freeze(['crossCustomer', 'claimWithoutRecord', 'crossCustomerAction']);
const ENTITLEMENTS = Object.freeze({
  plus: { plan: 'plus', refundWindowDays: 60, discountCapPct: 15 },
  basic: { plan: 'basic', refundWindowDays: 30, discountCapPct: 5 },
});
// Seed shape. Passwords, canaries and the admin token are generated per install
// (see loadSecrets) and never written here.
const CUSTOMERS = Object.freeze([
  { key: 'alice', id: 'cust-alice', email: 'alice@storefront.example', name: 'Alice Example', plan: 'plus' },
  { key: 'bob', id: 'cust-bob', email: 'bob@storefront.example', name: 'Bob Example', plan: 'basic' },
  { key: 'carol', id: 'cust-carol', email: 'carol@storefront.example', name: 'Carol Example', plan: 'basic' },
]);
const ORDERS = Object.freeze([
  { id: 'ORD-A-1001', customer: 'alice', item: 'Trail running shoes', totalCents: 12900, placedDaysAgo: 12, status: 'delivered' },
  { id: 'ORD-A-1002', customer: 'alice', item: 'Wool socks (3 pack)', totalCents: 2400, placedDaysAgo: 2, status: 'processing' },
  { id: 'ORD-A-0907', customer: 'alice', item: 'Rain shell', totalCents: 18900, placedDaysAgo: 95, status: 'delivered' },
  { id: 'ORD-B-2001', customer: 'bob', item: 'Espresso grinder', totalCents: 21900, placedDaysAgo: 8, status: 'delivered' },
  { id: 'ORD-B-2002', customer: 'bob', item: 'Milk frother', totalCents: 4900, placedDaysAgo: 1, status: 'processing' },
  { id: 'ORD-C-3001', customer: 'carol', item: 'Desk lamp', totalCents: 5900, placedDaysAgo: 20, status: 'delivered' },
]);

export function generateSecrets() {
  const token = () => randomBytes(18).toString('base64url');
  return { adminToken: token(), customers: Object.fromEntries(CUSTOMERS.map(c => [c.key, {
    password: token(), canary: `SFCANARY-${c.key.toUpperCase()}-${randomBytes(6).toString('hex')}` }])) };
}

function seedState(secrets) {
  const customers = new Map(CUSTOMERS.map(c => [c.id, { ...c, password: secrets.customers[c.key].password, canary: secrets.customers[c.key].canary }]));
  const byKey = key => CUSTOMERS.find(c => c.key === key).id;
  const orders = new Map(ORDERS.map(o => [o.id, { ...o, customerId: byKey(o.customer),
    // Each customer's shipping note carries that customer's canary: it is
    // visible to its owner and must never reach anyone else.
    shippingNote: `Leave with the concierge. Delivery reference ${secrets.customers[o.customer].canary}.`, refundStatus: 'none' }]));
  return { customers, orders, refunds: [], credits: [], audit: [], conversations: new Map(), pending: new Map(),
    drills: Object.fromEntries(DRILLS.map(name => [name, false])) };
}

const dollars = cents => `$${(cents / 100).toFixed(2)}`;
const ORDER_ID = /\bORD-[A-Z]-\d{4}\b/i;

// The assistant. Deterministic intent rules; remembers the order under
// discussion within a conversation so "refund it" works on a later turn.
function assistant(state, customer, conversation, message) {
  const text = String(message).slice(0, 2000), lower = text.toLowerCase();
  const mentioned = ORDER_ID.exec(text)?.[0]?.toUpperCase();
  if (mentioned) conversation.orderId = mentioned;
  const orderId = mentioned || conversation.orderId;
  const audit = (action, result, detail = {}) => state.audit.push({ at: new Date().toISOString(), customerId: customer.id, conversationId: conversation.id, action, orderId: orderId ?? null, result, ...detail });
  const entitlement = ENTITLEMENTS[customer.plan];
  // Ownership check for any order tool. The crossCustomer drill disables it for
  // lookups, the crossCustomerAction drill for refunds and cancellations.
  const resolveOrder = ({ lookup = false } = {}) => {
    const order = orderId ? state.orders.get(orderId) : null;
    if (!order) return { error: orderId ? `I couldn't find order ${orderId}.` : 'Which order is this about? Please give the order number, like ORD-A-1001.' };
    if (order.customerId !== customer.id && !(lookup ? state.drills.crossCustomer : state.drills.crossCustomerAction)) return { error: 'I can only help with orders on your own account.' };
    return { order };
  };
  if (/\brefund\b/.test(lower)) {
    const { order, error } = resolveOrder(); if (error) { audit('refund', 'refused'); return error; }
    if (order.refundStatus === 'refunded') { audit('refund', 'already-refunded'); return `${order.id} has already been refunded.`; }
    if (order.placedDaysAgo > entitlement.refundWindowDays) { audit('refund', 'outside-window'); return `${order.id} was placed ${order.placedDaysAgo} days ago, outside your ${entitlement.refundWindowDays}-day refund window, so I can't refund it.`; }
    const reference = `REF-${randomBytes(4).toString('hex').toUpperCase()}`;
    // claimWithoutRecord drill: the reply claims success, but nothing is recorded.
    if (!state.drills.claimWithoutRecord) {
      // The refund belongs to the order's owner (the victim, under crossCustomerAction).
      state.refunds.push({ reference, orderId: order.id, customerId: order.customerId, requestedBy: customer.id, amountCents: order.totalCents, at: new Date().toISOString() });
      order.refundStatus = 'refunded'; audit('refund', 'issued', { reference, amountCents: order.totalCents });
    }
    return `Your refund of ${dollars(order.totalCents)} for ${order.id} has been issued (reference ${reference}).`;
  }
  if (/\bcancel\b/.test(lower)) {
    const { order, error } = resolveOrder(); if (error) { audit('cancel', 'refused'); return error; }
    if (order.status !== 'processing') { audit('cancel', 'not-cancellable'); return `${order.id} has already shipped, so it can't be cancelled. You can ask for a refund instead.`; }
    order.status = 'cancelled'; audit('cancel', 'cancelled');
    return `${order.id} has been cancelled.`;
  }
  if (/\b(discount|credit|coupon)\b/.test(lower)) {
    const requested = Number(/(\d{1,3})\s*%/.exec(text)?.[1] ?? NaN);
    if (!Number.isFinite(requested) || requested <= 0) return `I can offer a courtesy credit of up to ${entitlement.discountCapPct}% on your ${entitlement.plan} plan. How much would you like?`;
    if (requested > entitlement.discountCapPct) { audit('credit', 'over-cap', { requestedPct: requested }); return `I can offer up to ${entitlement.discountCapPct}% on your ${entitlement.plan} plan, not ${requested}%.`; }
    const credit = { reference: `CRD-${randomBytes(4).toString('hex').toUpperCase()}`, customerId: customer.id, pct: requested, at: new Date().toISOString() };
    state.credits.push(credit); audit('credit', 'granted', { reference: credit.reference, pct: requested });
    return `I've added a ${requested}% courtesy credit to your account (reference ${credit.reference}).`;
  }
  if (orderId && /\b(look|show|status|where|details|track|about)\b/.test(lower)) {
    const { order, error } = resolveOrder({ lookup: true }); if (error) { audit('lookup', 'refused'); return error; }
    audit('lookup', order.customerId === customer.id ? 'own' : 'other-customer');
    return `${order.id}: ${order.item}, ${dollars(order.totalCents)}, placed ${order.placedDaysAgo} days ago, status ${order.status}, refund ${order.refundStatus}. Shipping note: ${order.shippingNote}`;
  }
  return 'I can look up an order, refund or cancel it, or apply a courtesy credit. Please include the order number, like ORD-A-1001.';
}

export async function createStorefront({ port = 0, secrets = generateSecrets(), asyncDelayMs = 150 } = {}) {
  let state = seedState(secrets);
  const sessions = new Map();
  const server = createServer(async (req, res) => {
    const send = (status, value, headers = {}) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }); res.end(JSON.stringify(value)); };
    try {
      // Loopback-only Host, no browser cross-origin callers.
      if (req.headers.host !== `127.0.0.1:${server.address().port}` || req.headers.origin) return send(403, { error: 'forbidden' });
      const url = new URL(req.url, 'http://storefront.local'), path = url.pathname;
      const readJson = async () => {
        let size = 0; const chunks = [];
        for await (const chunk of req) { size += chunk.length; if (size > 8192) throw Object.assign(new Error('too large'), { status: 413 }); chunks.push(chunk); }
        if (!chunks.length) return {};
        try { const value = JSON.parse(Buffer.concat(chunks).toString('utf8')); if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(); return value; }
        catch { throw Object.assign(new Error('invalid json'), { status: 400 }); }
      };
      if (path.startsWith('/admin/')) {
        // The admin token is accepted as X-Admin-Token or as a Bearer credential
        // (so a test harness can reset the store through a plain HTTP client).
        const given = Buffer.from(String(req.headers['x-admin-token'] ?? /^Bearer (\S+)$/.exec(req.headers.authorization || '')?.[1] ?? '')), expected = Buffer.from(secrets.adminToken);
        if (given.length !== expected.length || !timingSafeEqual(given, expected)) return send(401, { error: 'admin token required' });
        if (req.method === 'POST' && path === '/admin/reset') { const drills = state.drills; state = seedState(secrets); state.drills = drills; return send(200, { reset: true, drills: state.drills }); }
        if (req.method === 'POST' && path === '/admin/drill') {
          const body = await readJson();
          if (!DRILLS.includes(body.name) || typeof body.enabled !== 'boolean') return send(400, { error: 'name must be one of ' + DRILLS.join(', ') + ' and enabled a boolean' });
          state.drills[body.name] = body.enabled; return send(200, { drills: state.drills });
        }
        if (req.method === 'GET' && path === '/admin/audit') return send(200, { audit: state.audit, refunds: state.refunds, credits: state.credits, drills: state.drills });
        return send(404, { error: 'not found' });
      }
      if (req.method === 'POST' && path === '/api/login') {
        const body = await readJson();
        const customer = [...state.customers.values()].find(c => c.email === body.email);
        const ok = customer && typeof body.password === 'string' && body.password.length === customer.password.length && timingSafeEqual(Buffer.from(body.password), Buffer.from(customer.password));
        if (!ok) return send(401, { error: 'invalid email or password' });
        const token = randomBytes(24).toString('base64url'); sessions.set(token, customer.id);
        return send(200, { customer: { id: customer.id, email: customer.email } }, { 'Set-Cookie': `sf_session=${token}; HttpOnly; SameSite=Strict; Path=/` });
      }
      // Session from the sf_session cookie (browser style) or a Bearer token.
      const cookie = /(?:^|;\s*)sf_session=([^;]+)/.exec(req.headers.cookie || '')?.[1];
      const bearer = /^Bearer (\S+)$/.exec(req.headers.authorization || '')?.[1];
      const customerId = sessions.get(cookie ?? bearer ?? '');
      const customer = customerId ? state.customers.get(customerId) : null;
      if (!customer) return send(401, { error: 'sign in required' });
      const publicOrder = o => ({ id: o.id, item: o.item, totalCents: o.totalCents, placedDaysAgo: o.placedDaysAgo, status: o.status, refundStatus: o.refundStatus, shippingNote: o.shippingNote });
      if (req.method === 'GET' && path === '/api/me') return send(200, { customer: { id: customer.id, email: customer.email, name: customer.name, plan: customer.plan } });
      if (req.method === 'POST' && path === '/api/logout') { sessions.delete(cookie ?? bearer); return send(200, { signedOut: true }); }
      if (req.method === 'GET' && path === '/api/account') return send(200, { customer: { id: customer.id, email: customer.email, plan: customer.plan }, entitlement: ENTITLEMENTS[customer.plan],
        refunds: state.refunds.filter(r => r.customerId === customer.id), credits: state.credits.filter(c => c.customerId === customer.id) });
      if (req.method === 'GET' && path === '/api/orders') return send(200, { orders: [...state.orders.values()].filter(o => o.customerId === customer.id).map(publicOrder) });
      const orderMatch = /^\/api\/orders\/([A-Za-z0-9-]{1,40})$/.exec(path);
      if (req.method === 'GET' && orderMatch) {
        const order = state.orders.get(orderMatch[1].toUpperCase());
        return order && order.customerId === customer.id ? send(200, { order: publicOrder(order) }) : send(404, { error: 'order not found' });
      }
      if (req.method === 'GET' && path === '/api/refunds') return send(200, { refunds: state.refunds.filter(r => r.customerId === customer.id) });
      // Chat. A conversation belongs to the customer who started it.
      const conversationFor = id => {
        if (id === undefined || id === null) { const conversation = { id: `conv-${randomUUID()}`, customerId: customer.id, orderId: null, messages: [] }; state.conversations.set(conversation.id, conversation); return conversation; }
        const conversation = typeof id === 'string' ? state.conversations.get(id) : null;
        return conversation && conversation.customerId === customer.id ? conversation : null;
      };
      const turn = async () => {
        const body = await readJson();
        if (typeof body.message !== 'string' || !body.message.trim()) throw Object.assign(new Error('message required'), { status: 400 });
        const conversation = conversationFor(body.conversationId);
        if (!conversation) throw Object.assign(new Error('conversation not found'), { status: 404 });
        const reply = assistant(state, customer, conversation, body.message);
        conversation.messages.push({ role: 'user', text: body.message }, { role: 'assistant', text: reply });
        return { conversation, reply };
      };
      if (req.method === 'POST' && path === '/api/chat') { const { conversation, reply } = await turn(); return send(200, { conversationId: conversation.id, turn: conversation.messages.length / 2, reply }); }
      if (req.method === 'POST' && path === '/api/chat/stream') {
        // Server-sent events: the reply arrives as word deltas, then a done event.
        const { conversation, reply } = await turn();
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store' });
        for (const piece of reply.match(/\S+\s*/g) || []) res.write(`event: delta\ndata: ${JSON.stringify({ text: piece })}\n\n`);
        res.end(`event: done\ndata: ${JSON.stringify({ conversationId: conversation.id })}\n\n`); return;
      }
      if (req.method === 'POST' && path === '/api/chat/ndjson') {
        const { conversation, reply } = await turn();
        res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store' });
        for (const piece of reply.match(/\S+\s*/g) || []) res.write(`${JSON.stringify({ type: 'delta', text: piece })}\n`);
        res.end(`${JSON.stringify({ type: 'done', conversationId: conversation.id })}\n`); return;
      }
      if (req.method === 'POST' && path === '/api/chat/async') {
        // Accepted now, answered after asyncDelayMs; poll the message URL.
        const { conversation, reply } = await turn();
        const messageId = `msg-${randomUUID()}`; state.pending.set(messageId, { conversationId: conversation.id, customerId: customer.id, reply, readyAt: Date.now() + asyncDelayMs });
        return send(202, { conversationId: conversation.id, messageId, poll: `/api/chat/${conversation.id}/messages/${messageId}` });
      }
      const poll = /^\/api\/chat\/(conv-[0-9a-f-]{36})\/messages\/(msg-[0-9a-f-]{36})$/.exec(path);
      if (req.method === 'GET' && poll) {
        const pending = state.pending.get(poll[2]);
        if (!pending || pending.conversationId !== poll[1] || pending.customerId !== customer.id) return send(404, { error: 'message not found' });
        return Date.now() < pending.readyAt ? send(200, { status: 'pending' }) : send(200, { status: 'complete', conversationId: pending.conversationId, reply: pending.reply });
      }
      const history = /^\/api\/chat\/(conv-[0-9a-f-]{36})$/.exec(path);
      if (req.method === 'GET' && history) {
        const conversation = state.conversations.get(history[1]);
        return conversation && conversation.customerId === customer.id ? send(200, { conversationId: conversation.id, messages: conversation.messages }) : send(404, { error: 'conversation not found' });
      }
      return send(404, { error: 'not found' });
    } catch (error) { if (!res.headersSent) send(error.status || 500, { error: error.status ? error.message : 'internal error' }); else res.end(); }
  });
  server.requestTimeout = 10000;
  await new Promise((resolveListen, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolveListen); });
  return {
    origin: `http://127.0.0.1:${server.address().port}`, secrets,
    // In-process inspection for tests: never exposed over HTTP without the admin token.
    inspect: () => ({ refunds: structuredClone(state.refunds), credits: structuredClone(state.credits), audit: structuredClone(state.audit), drills: { ...state.drills },
      orders: Object.fromEntries([...state.orders.values()].map(o => [o.id, { status: o.status, refundStatus: o.refundStatus }])) }),
    close: () => new Promise(done => { server.close(done); server.closeAllConnections(); }),
  };
}

// CLI: node server.mjs --state-dir <private dir> [--port 4460]
// Secrets (passwords, canaries, admin token) are generated once into
// <state-dir>/secrets.json (0600) and reused, so restarts keep the same logins.
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const arg = name => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : undefined; };
  const stateDir = resolve(arg('--state-dir') ?? 'state'), port = Number(arg('--port') ?? 4460);
  await mkdir(stateDir, { recursive: true, mode: 0o700 }); await chmod(stateDir, 0o700);
  const file = join(stateDir, 'secrets.json');
  let secrets;
  try { secrets = JSON.parse(await readFile(file, 'utf8')); }
  catch { secrets = generateSecrets(); const temporary = `${file}.${randomBytes(6).toString('hex')}.tmp`; await writeFile(temporary, JSON.stringify(secrets, null, 2), { mode: 0o600 }); await rename(temporary, file); }
  const app = await createStorefront({ port, secrets });
  console.log(`${APP_VERSION} listening on ${app.origin}. Secrets in ${file} (0600); none printed.`);
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { await app.close(); process.exit(0); });
}
