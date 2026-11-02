// Frozen copy of scopehaven/integrations/observers/egress-recorder.mjs from before forwarding (imports re-pointed), for the differential compat test. Tests only.
// Egress recorder: a loopback sink for the application's outbound HTTP
// (configuration and routing modes: src/egress-rules.mjs). It answers every
// request itself and never forwards, so nothing the app sends during a test
// leaves this machine through it. Each request that reaches it is one "send"
// effect named by its destination host.
//
// It is authoritative only with declared routing and a witness, and strict
// about what it could have missed. Windows, witnesses and the quiet period are
// kept by the shared sink ledger (sink-ledger.mjs). A window is partial when:
//   - this window's witness (the app's own outbound request carrying the start
//     mark's nonce) did not arrive within witnessWaitMs, arrived twice, or a
//     witness of another window arrived
//   - a request arrived after the witness request was sent (it may be the
//     witness route's own doing, or later than the check): never an effect
//   - a request was malformed, dropped at the connection limit, came from a
//     browser (Origin or Sec-Fetch-Site), named no route (base-url), had a body
//     over maxBodyBytes, was aborted, or was still in flight at collect (its headers
//     included: the server's own parser was mid-message on that connection, also for
//     a request that follows a completed one in the same write)
//   - an HTTPS tunnel (CONNECT) was requested: the destination is recorded and
//     the tunnel refused, but its payload (method, path) is never seen
//   - a path's percent-decoding names a different declared path than the raw path
//   - a proxy request whose Host header names another host than its URL, or whose destination is an IP
//     literal that is not itself declared: a send to a declared host may be addressed under another name
//   - a connection had sent part of a request (headers not yet complete) when collect ran
// and failed when the listener was down at any point since the start mark, or
// the window's records were evicted (retainedRequests).
// Settle: collect() waits up to witnessWaitMs for the witness, then until no
// request has arrived for quietMs. A send the app makes later than that is not
// observed: that bound is the observer's declared limit.
// committed: the request reached the sink in full. The real destination never
// receives it; the effect recorded is the app's attempt to send.
// Correlation (opt-in per destination, src/egress-rules.mjs): the token one well-formed value of the declared
// header carries goes into the event's correlation.settlementToken, a key no selector or pairing pin reads; a
// missing, repeated or malformed header records none. The app writes the value, and the recorder cannot tell
// whether it is the token the connector sent, so settlement reads it only to withhold a pass.
// Bodies: every body is kept only as a salted digest. A destination that declares
// `capture` (src/egress-rules.mjs, src/body-fields.mjs) also has the declared scalar
// fields of its JSON bodies on its declared paths read (a send on another path, or on a
// path whose raw and decoded forms disagree, records status "path-undeclared"): up to capture.maxBytes are buffered beside the digest,
// parsed once at the end of the request, and only the declared fields are stored on the
// event, with a status saying why nothing could be read. CONNECT tunnels and the witness
// request are never captured. The scope publishes the declaration (scope.capture). A destination that also
// declares capture.encodings ["json", "form"] has those fields read from form-encoded bodies too, only when the
// request is a POST whose target has no query or fragment (both are passed to captureBody); the scope lists such hosts
// (scope.captureForm).
import { createServer } from 'node:http';
import { isIP } from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import { makeEffect } from '../events.mjs';
import { createSinkLedger } from '../sink-ledger.mjs';
import { validateEgressConfig, correlationTokenOf } from '../../../src/egress-rules.mjs';
import { captureBody, formEnabled } from '../../../src/body-fields.mjs';
import { readIdempotencyKey, readBodyKey, foldKey, headText, IDEMPOTENCY_TRANSPORT_HEADERS, IDEMPOTENCY_DIRTY, IDEMPOTENCY_BOUNDS } from '../../../src/idempotency.mjs';

export const EGRESS_LIMITS = Object.freeze({ retainedRequests: 20000, maxConnections: 256, headersTimeoutMs: 10000, requestTimeoutMs: 15000, maxHeaderSize: 16384 });

// retainedRequests: operator code only (a profile cannot set it).
// idempotencyKeys: operator code only (a profile cannot set it); a new key past it records status "untracked".
export function createEgressRecorder({ instanceId = 'egress-recorder-1', retainedRequests = EGRESS_LIMITS.retainedRequests, idempotencyKeys = IDEMPOTENCY_BOUNDS.keysPerRecorder, ...config }) {
  const cfg = validateEgressConfig({ ...config, type: 'egress-recorder' }, config.witness ? { [config.witness.actorId]: {} } : undefined);
  const observer = { kind: 'http-egress-recorder', instanceId };
  const byHost = new Map(cfg.destinations.map(d => [d.host, d]));
  // The declared capture, published on the scope: { [host]: [pointer, ...] }, only when some destination declares it.
  const captureScope = cfg.destinations.some(d => d.capture) ? Object.freeze(Object.fromEntries(cfg.destinations.filter(d => d.capture).map(d => [d.host, Object.freeze([...d.capture.pointers])]))) : null;
  // The hosts whose declared fields are also read from form bodies, in profile order, only when some destination declares it.
  const captureFormScope = cfg.destinations.some(d => formEnabled(d.capture)) ? Object.freeze(cfg.destinations.filter(d => formEnabled(d.capture)).map(d => d.host)) : null;
  // Content digests are salted per recorder, so a bodiless request's digest does not reveal its target.
  const salt = randomBytes(16);
  // Keyed retries (src/idempotency.mjs), published on the scope: { [host]: declaration }, only when some destination declares one.
  const idempotencyScope = cfg.destinations.some(d => d.idempotency) ? Object.freeze(Object.fromEntries(cfg.destinations.filter(d => d.idempotency).map(d => [d.host, d.idempotency]))) : null;
  // Run-wide key state: the first seq of each key fold (capped, never evicted), the first seq of a send whose key could not be
  // read, per host, and the sends in flight per key fold (two at once mark each other "overlap"). Keys are sealed with the salt.
  // A body key (a declared pointer) is known only when the body ends: arrival and end ticks order such sends, and a send that ends
  // after another send of its fold arrived marks both "overlap" (lastEnded).
  const keyFirst = new Map(), dirtyFirst = new Map(), keysInFlight = new Map(), lastEnded = new Map();
  let tick = 0;
  const seal = (label, text) => createHash('sha256').update(salt).update(label).update(text).digest('hex');
  const markDirty = (host, seq) => dirtyFirst.set(host, Math.min(dirtyFirst.get(host) ?? Infinity, seq));
  const unkeyed = (r, host, head, status) => { r.idem = { status, key: null, fold: null, head, firstSeq: null }; if (IDEMPOTENCY_DIRTY.includes(status)) markDirty(host, r.seq); };
  // A keyed send: its fold slot and first use, or untracked when the key store is full. Returns the slot, or null.
  function keyed(r, host, head, value) {
    const fold = seal('scopehaven-idempotency-fold/1\n', `${host}\n${foldKey(value)}`), slot = `${host}\n${fold}`;
    if (!keyFirst.has(slot) && keyFirst.size >= idempotencyKeys) { unkeyed(r, host, head, 'untracked'); return null; }
    keyFirst.set(slot, Math.min(keyFirst.get(slot) ?? Infinity, r.seq));
    r.idem = { status: 'keyed', key: seal('scopehaven-idempotency-key/1\n', `${host}\n${value}`), fold, head, firstSeq: null };
    r.idemSlot = slot;
    return slot;
  }
  // The key record of a send to a destination that declares idempotency: a header key read on arrival; a body key once the body
  // ends (finishBodyKey), with a placeholder until then (a window collected before the end is partial anyway).
  function startKey(r, host, method, rawTarget, rawHeaders) {
    const d = byHost.get(host), idem = d.idempotency;
    const head = seal('scopehaven-idempotency-head/1\n', headText({ method, rawTarget, rawHeaders, exclude: [...(idem.header ? [idem.header] : []), ...(d.correlation ? [d.correlation] : []), ...idem.volatile, ...IDEMPOTENCY_TRANSPORT_HEADERS] }));
    if (idem.pointer !== null) { r.idem = { status: 'unreadable', key: null, fold: null, head, firstSeq: null }; r.idemBody = { arrivalTick: ++tick, chunks: [], bytes: 0, max: idem.maxBytes }; return; }
    const read = readIdempotencyKey({ declaration: idem, method, rawHeaders });
    if (read.status !== 'keyed') return unkeyed(r, host, head, read.status);
    const slot = keyed(r, host, head, read.value);
    if (slot === null) return;
    const flying = keysInFlight.get(slot) ?? new Set();
    if (flying.size) { r.idem.status = 'overlap'; for (const other of flying) other.idem.status = 'overlap'; }
    flying.add(r); keysInFlight.set(slot, flying);
  }
  // A send's stored key record. firstSeq, read at collect (a complete window has no request still arriving): the key's first
  // use, or an earlier send to the host whose key could not be read, whichever came first.
  const keyRecord = r => {
    const { status, key, fold, head } = r.idem;
    if (key === null) return { status, key, fold, head, firstSeq: null };
    const dirty = dirtyFirst.get(r.host) ?? Infinity;
    return { status, key, fold, head, firstSeq: Math.min(keyFirst.get(r.idemSlot), dirty < r.seq ? dirty : Infinity) };
  };
  const endKey = r => { if (r.idemSlot === undefined) return; const flying = keysInFlight.get(r.idemSlot); flying?.delete(r); if (flying && !flying.size) keysInFlight.delete(r.idemSlot); };
  // A send whose body or delivery was not seen whole: its key decides nothing, and later uses read earlier-use.
  function finishBodyKey(r, host, method, rawHeaders) {
    const pending = r.idemBody, head = r.idem.head;
    delete r.idemBody;
    const read = readBodyKey({ declaration: byHost.get(host).idempotency, method, rawHeaders, buffer: pending.bytes <= pending.max ? Buffer.concat(pending.chunks) : null, bodyBytes: r.bodyBytes });
    if (read.status !== 'keyed') return unkeyed(r, host, head, read.status);
    const slot = keyed(r, host, head, read.value);
    if (slot === null) return;
    const endTick = ++tick, prior = lastEnded.get(slot);
    if (prior && prior.endTick > pending.arrivalTick) { r.idem.status = 'overlap'; if (prior.r.idem.key !== null) prior.r.idem.status = 'overlap'; }
    lastEnded.set(slot, { endTick, r });
  }
  const spoilKey = (r, host) => { if (!r.idem) return; delete r.idemBody; endKey(r); r.idem = { status: 'unreadable', key: null, fold: null, head: r.idem.head, firstSeq: null }; markDirty(host, r.seq); };
  // Whether the server's own HTTP parser is mid-message on any connection: a request still arriving, headers included,
  // also one behind a completed request in the same write. Node keeps that parser state in the server's connections
  // list for its request timeouts; without it (another runtime) every window is partial. A connection cut off
  // mid-message is a client error, recorded as malformed.
  let requestArriving = null;
  const ledger = createSinkLedger({ prefix: 'egress', unit: 'request', retained: retainedRequests });
  let server = null;
  // A request the recorder refuses, cannot read or files under another name (a host mismatch or an address literal) may have
  // carried any key to any keyed host: it marks them all, so a later use of that key reads as used before.
  const record = fields => {
    const r = ledger.record(fields);
    if (idempotencyScope && (fields.kind !== 'item' || fields.hostMismatch || fields.addressLiteral)) for (const host of Object.keys(idempotencyScope)) markDirty(host, r.seq);
    return r;
  };
  // The declared path prefix a path names ("POST /v1/charges"), or "*".
  const pathName = (host, path) => {
    const paths = byHost.get(host)?.paths ?? [];
    const matchOf = value => paths.find(p => value === p || value.startsWith(p.endsWith('/') ? p : `${p}/`)) ?? null;
    let decoded = null;
    try { decoded = decodeURIComponent(path); } catch {}
    const raw = matchOf(path), dec = decoded === null ? null : matchOf(decoded);
    return { name: dec ?? raw ?? '*', ambiguous: decoded === null || raw !== dec };
  };
  const normalHost = host => host.toLowerCase().replace(/^\[(.*)\]$/, '$1').replace(/\.$/, '');
  // A destination named by an IP literal that is not itself declared could be any declared host.
  const undeclaredLiteral = host => isIP(host) !== 0 && !byHost.has(host);
  // Where a request target points: { host, path, query } or a problem.
  function locate(target) {
    if (/^https?:\/\//i.test(target)) {
      let url;
      try { url = new URL(target); } catch { return { problem: 'malformed' }; }
      if (url.username || url.password) return { problem: 'malformed' };
      return { host: normalHost(url.hostname), path: url.pathname, query: url.searchParams, search: target.includes('#') ? '#' : url.search, via: 'proxy' };
    }
    if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//')) return { problem: 'malformed' };
    if (cfg.routing !== 'base-url') return { problem: 'unrouted' };
    const route = cfg.routes.find(r => target.startsWith(r.prefix));
    if (!route) return { problem: 'unrouted' };
    let url;
    try { url = new URL(`http://sink/${target.slice(route.prefix.length)}`); } catch { return { problem: 'malformed' }; }
    return { host: route.host, path: url.pathname, query: url.searchParams, search: target.includes('#') ? '#' : url.search, via: 'route' };
  }
  // The run token a send to a correlated destination carries (every value of its one declared header, any case of the name).
  const tokenOf = (host, rawHeaders) => {
    const header = byHost.get(host)?.correlation ?? null;
    if (header === null) return null;
    const values = [];
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) if (rawHeaders[i].toLowerCase() === header) values.push(rawHeaders[i + 1]);
    return correlationTokenOf(header, values);
  };
  function onRequest(req, res) {
    // An answered send keeps the connection open: a reused connection's next request is read and recorded too.
    const reply = (status, body = null) => { if (!res.headersSent) { res.writeHead(status, body === null ? { 'Content-Length': '0', ...(status >= 400 ? { Connection: 'close' } : {}) } : { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)), ...(status >= 400 ? { Connection: 'close' } : {}) }); res.end(body ?? undefined); } };
    // A browser page could post here: never the app's own send.
    const site = req.headers['sec-fetch-site'];
    if (req.headers.origin !== undefined || (site !== undefined && site !== 'none')) { record({ kind: 'browser' }); req.resume(); return reply(403); }
    const where = locate(req.url);
    if (where.problem) { record({ kind: where.problem }); req.resume(); return reply(where.problem === 'unrouted' ? 404 : 400); }
    const named = pathName(where.host, where.path);
    // A proxy request names its destination twice; when the Host header names another host, a send to a declared
    // host may be recorded under an undeclared name, and so may one addressed by an IP literal.
    let hostHeader = null;
    try { hostHeader = req.headers.host === undefined ? null : normalHost(new URL(`http://${req.headers.host}`).hostname); } catch { hostHeader = ''; }
    const r = record({ kind: 'item', done: false, method: req.method, host: where.host, resource: `${req.method} ${named.name}`.slice(0, 200), pathAmbiguous: named.ambiguous,
      hostMismatch: where.via === 'proxy' && hostHeader !== null && hostHeader !== where.host, addressLiteral: undeclaredLiteral(where.host),
      witnessNonces: where.host === cfg.witness?.host ? where.query.getAll('scopehaven_witness') : [], bodyBytes: 0, overLimit: false, outcome: 'unknown', token: tokenOf(where.host, req.rawHeaders),
      target: createHash('sha256').update(salt).update(`${where.host}\n${where.path}\n${where.query.toString()}`).digest('hex') });
    const hash = createHash('sha256').update(salt);
    if (where.host !== cfg.witness?.host && byHost.get(where.host)?.idempotency) startKey(r, where.host, req.method, req.url, req.rawHeaders);
    // Declared capture for this destination: buffer at most capture.maxBytes beside the digest (never for the witness host),
    // and only on one of its declared paths; any other path of the host records "path-undeclared" and buffers nothing.
    const capture = where.host === cfg.witness?.host ? null : byHost.get(where.host)?.capture ?? null;
    const captureHere = capture && named.name !== '*' && !named.ambiguous ? capture : null;
    if (capture && !captureHere) r.captured = { status: 'path-undeclared', values: {} };
    const kept = [];
    let keptBytes = 0;
    req.on('data', chunk => {
      if (r.overLimit) return;
      r.bodyBytes += chunk.length;
      if (r.bodyBytes > cfg.maxBodyBytes) { r.overLimit = true; r.done = true; spoilKey(r, where.host); reply(413); req.destroy(); return; }
      hash.update(chunk);
      if (r.idemBody) { r.idemBody.bytes += chunk.length; if (r.idemBody.bytes <= r.idemBody.max) r.idemBody.chunks.push(chunk); else r.idemBody.chunks.length = 0; }
      if (captureHere && keptBytes + chunk.length <= captureHere.maxBytes) { kept.push(chunk); keptBytes += chunk.length; }
      else if (captureHere) keptBytes = captureHere.maxBytes + 1;
    });
    // A declared test-mode reply for this destination, method and path; otherwise the plain reply.
    const declaredReply = cfg.replies.find(x => x.host === where.host && (x.method === null || x.method === req.method) && (x.path === null || where.path === x.path || where.path.startsWith(x.path.endsWith('/') ? x.path : `${x.path}/`)));
    req.on('end', () => {
      if (r.overLimit) return;
      r.body = hash.digest('hex');
      if (captureHere) r.captured = captureBody({ rawHeaders: req.rawHeaders, buffer: keptBytes <= captureHere.maxBytes ? Buffer.concat(kept) : null, bodyBytes: r.bodyBytes, capture: captureHere, search: where.search, method: req.method });
      kept.length = 0;
      // The sink answers now: from here a send under the same key is sequential, not concurrent.
      if (r.idemBody) finishBodyKey(r, where.host, req.method, req.rawHeaders);
      endKey(r);
      r.outcome = 'committed'; r.done = true; declaredReply ? reply(declaredReply.status, declaredReply.body) : reply(cfg.replyStatus);
    });
    req.on('close', () => { if (!r.done) { r.done = true; r.aborted = true; spoilKey(r, where.host); } else endKey(r); });
  }
  // HTTPS through the proxy: record the destination and refuse the tunnel.
  function onConnect(req, socket) {
    const m = /^\[?([^\]]+?)\]?:(\d{1,5})$/.exec(req.url ?? '');
    if (!m) record({ kind: 'malformed' });
    else {
      const host = normalHost(m[1]);
      const r = record({ kind: 'item', method: 'CONNECT', host, resource: `CONNECT :${Number(m[2])}`, tunnel: true, addressLiteral: undeclaredLiteral(host), witnessNonces: [], bodyBytes: 0, outcome: 'committed',
        target: createHash('sha256').update(salt).update(`${host}:${Number(m[2])}`).digest('hex') });
      // A tunnel's request, key included, is never seen.
      if (byHost.get(host)?.idempotency) { startKey(r, host, 'CONNECT', req.url, req.rawHeaders); spoilKey(r, host); }
    }
    socket.on('error', () => {});
    socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  }
  return {
    kind: observer.kind, instanceId, source: 'http-egress', port: cfg.port,
    scope: Object.freeze({ operations: ['send'], names: cfg.destinations.map(d => d.host), actorAttribution: 'none', evidence: cfg.routing ? 'authoritative' : 'presence-only', ...(captureScope ? { capture: captureScope } : {}), ...(captureFormScope ? { captureForm: captureFormScope } : {}),
      ...(idempotencyScope ? { idempotency: idempotencyScope } : {}) }),
    ...(cfg.witness ? { witnessRequest: Object.freeze({ actorId: cfg.witness.actorId, method: 'GET', path: cfg.witness.path }) } : {}),
    // Called by the connector immediately before it sends this window's witness request.
    markWitnessRequest(from) { ledger.markWitnessRequest(from); },
    async start() {
      if (server) return;
      const s = createServer({ headersTimeout: EGRESS_LIMITS.headersTimeoutMs, requestTimeout: EGRESS_LIMITS.requestTimeoutMs, maxHeaderSize: EGRESS_LIMITS.maxHeaderSize }, onRequest);
      s.maxConnections = EGRESS_LIMITS.maxConnections;
      s.on('connect', onConnect);
      s.on('clientError', (_error, socket) => { record({ kind: 'malformed' }); socket.destroy(); });
      s.on('drop', () => { record({ kind: 'dropped' }); });
      await new Promise((resolve, reject) => { s.once('error', reject); s.listen({ port: cfg.port, host: '127.0.0.1', exclusive: true }, () => { s.off('error', reject); resolve(); }); });
      // The server's connections list exists once it listens, before any connection is accepted.
      const connections = s[Object.getOwnPropertySymbols(s).find(k => k.description === 'http.server.connections')];
      requestArriving = typeof connections?.active === 'function' ? () => connections.active().length > 0 : null;
      s.on('error', () => ledger.down());
      s.on('close', () => ledger.down());
      server = s; ledger.started();
    },
    async mark() { return ledger.position(); },
    // gap: a settlement gap window (sink-ledger.mjs), an exact range collected after the run.
    async collect(from, to, { gap = false } = {}) {
      const w = await ledger.window(from, to, { witness: cfg.witness !== null, witnessWaitMs: cfg.witnessWaitMs, quietMs: cfg.quietMs, gap });
      if (w.failed) return { events: [], coverage: 'failed', reason: w.failed };
      const { problems } = w, events = [];
      if (!gap && !requestArriving) problems.add('egress-parser-state-unavailable');
      else if (!gap && requestArriving()) problems.add('egress-request-in-flight');
      for (const r of w.items) {
        if (r.hostMismatch) problems.add('egress-host-mismatch');
        if (r.addressLiteral) problems.add('egress-address-literal');
        if (r.tunnel) problems.add('egress-tunnel-payload-unseen');
        if (r.overLimit) problems.add('egress-body-over-limit');
        if (r.aborted) problems.add('egress-request-incomplete');
        if (r.pathAmbiguous) problems.add('egress-path-ambiguous');
        if (events.length >= 5000) { problems.add('egress-event-limit'); continue; }
        events.push(makeEffect({ source: 'http-egress', observer, seq: r.seq, actor: null, operation: 'send', name: r.host.slice(0, 128), resource: r.resource,
          outcome: r.overLimit || r.aborted ? 'unknown' : r.outcome, correlation: r.token ? { settlementToken: r.token } : {}, content: { target: r.target, body: r.body ?? null, bodyBytes: r.bodyBytes }, ...(r.captured ? { captured: r.captured } : {}),
          ...(r.idem ? { idempotency: keyRecord(r) } : {}) }));
      }
      const reason = problems.size ? [...problems].sort().join(',').slice(0, 200) : null;
      return { events, coverage: reason ? 'partial' : 'complete', reason };
    },
    async stop() {
      const s = server; server = null; ledger.stopped();
      if (s) await new Promise(resolve => { s.close(() => resolve()); s.closeAllConnections(); });
    },
  };
}
