// In-doubt resolution by the request feed: the declaration and its refusals, the run record, the sealed read, every row of the
// derivation (src/request-feed-rules.mjs
// deriveRequestFeed, through the core's binding in src/in-doubt.mjs), and the reader (integrations/observers/request-feed.mjs) against a
// loopback provider stub that signs with a key made in this process. No real provider, no hosted write, no secret: the only sockets are the
// stub's on 127.0.0.1 and the reader's requests to it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { validateEgressConfig } from '../src/egress-rules.mjs';
import { validateTargetFile } from '../src/contracts.mjs';
import { validRequestFeedRecord, validRequestFeedRead, requestFeedRecord, requestFeedRecordOf, requestFeedApplies, deriveRequestFeed, DIRTY_STATUSES, REQUEST_FEED_BOUNDS, requestFeedsDeclared } from '../src/request-feed-rules.mjs';
import { IDEMPOTENCY_DIRTY } from '../src/idempotency.mjs';
import { lateEntriesFor, bindResolutions, fateOf, boundRecords, applicableResolvers, attemptBasis, LATER_RESOLVER_NAMES, inDoubtAttempt } from '../src/in-doubt.mjs';
import { createRequestFeedReader } from '../integrations/observers/request-feed.mjs';
import { createRequestFeedStub, signedEntry, feedKeys } from './fixtures/request-feed-stub.mjs';
import * as C from './fixtures/in-doubt-r1-cases.mjs';

const { CRM, ALT, CLOSE, OTHER, OFFSET, SKEW, SETTLE, send, windowOf, read, entry, supplied } = C;
const cfgOf = (feed = C.requestFeed(), extra = {}) => validateEgressConfig({ ...C.declaration({ feed }), ...extra }, { member: {} });

// ----------------------------------------------------------------------------------------------------------------------------------
test('1. the declaration: normalized on the recorder, its record published; every refusal names what is wrong', () => {
  const cfg = cfgOf();
  assert.deepEqual(Object.keys(cfg.requestFeed).sort(), ['endpoint', 'feedId', 'hosts', 'keyDigest', 'maxSkewMs', 'publicKey', 'routes', 'tenant', 'watermark']);
  assert.deepEqual([cfg.requestFeed.watermark, cfg.requestFeed.tenant, cfg.requestFeed.routes[1].notApplied, cfg.requestFeed.routes[1].settleMs], [true, null, [], null]);
  assert.deepEqual(requestFeedRecord(cfg.requestFeed), C.FEED, 'the scope record and the run record agree');
  assert.ok(validRequestFeedRecord(C.FEED));
  assert.deepEqual(C.RECORD.requestFeed, { ...C.FEED, collector: C.RECORD.requestFeed.collector });
  assert.equal(C.RECORD.requestFeed.collector.label, 'request-feed/1');
  assert.equal(validateEgressConfig(C.declaration({ feed: null }), { member: {} }).requestFeed, null, 'opt-in: absent by default');
  assert.ok(requestFeedsDeclared([C.declaration()]) && !requestFeedsDeclared([C.declaration({ feed: null })]));
  const refused = (feed, pattern, why) => assert.throws(() => cfgOf(feed), pattern, why);
  const rf = C.requestFeed();
  refused({ ...rf, extra: 1 }, /"requestFeed" is/, 'an unknown key');
  refused({ ...rf, feedId: 'a b' }, /feedId/);
  refused({ ...rf, endpoint: { port: 40999, path: '/requests' } }, /endpoint/, 'the recorder\'s own port');
  refused({ ...rf, endpoint: { port: 47120, path: '/requests?x=1' } }, /endpoint/, 'a query');
  refused({ ...rf, endpoint: { port: 47120, path: '/requests/' } }, /endpoint/, 'a trailing slash');
  const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  refused({ ...rf, publicKey: rsa }, /Ed25519/, 'another key type');
  refused({ ...rf, publicKey: 'AAAA' }, /Ed25519/);
  refused({ ...rf, hosts: [ALT] }, /hosts/, 'a host that declares no idempotency');
  refused({ ...rf, hosts: [CRM, CRM] }, /hosts/);
  refused({ ...rf, hosts: ['nowhere.example'] }, /hosts/);
  refused({ ...rf, hosts: [] }, /hosts/);
  refused({ ...rf, routes: [{ ...rf.routes[0], write: 'POST /tickets/T-9/close' }] }, /names a path no feed host declares/);
  refused({ ...rf, routes: [{ ...rf.routes[0], write: 'GET /tickets/T-1/close' }] }, /request-feed route/);
  refused({ ...rf, routes: [{ ...rf.routes[0], applied: ['closed', 'declined'] }] }, /request-feed route/, 'applied and notApplied overlap');
  refused({ ...rf, routes: [{ ...rf.routes[0], types: ['Ticket Closed'] }] }, /request-feed route/);
  refused({ ...rf, routes: [{ ...rf.routes[0], applied: [] }] }, /request-feed route/);
  refused({ ...rf, routes: [{ write: CLOSE, types: ['t'], applied: ['a'], settleMs: 100 }] }, /request-feed route/, 'settleMs without its source');
  refused({ ...rf, routes: [{ write: CLOSE, types: ['t'], applied: ['a'], source: 'doc' }] }, /request-feed route/, 'a source without settleMs');
  refused({ ...rf, routes: [{ write: CLOSE, types: ['t'], applied: ['a'], settleMs: 0, source: 'doc' }] }, /request-feed route/, 'settleMs is at least 1');
  refused({ ...rf, routes: [rf.routes[0], rf.routes[0]] }, /declared once/);
  refused((({ maxSkewMs: _m, ...x }) => x)(rf), /maxSkewMs/, 'maxSkewMs is required');
  refused({ ...rf, maxSkewMs: 2001 }, /maxSkewMs/);
  refused({ ...rf, watermark: false }, /watermark/);
  refused({ ...rf, tenant: { header: 'authorization' } }, /tenant/, 'an identity header');
  refused({ ...rf, tenant: { header: 'idempotency-key' } }, /tenant/, 'the key header');
  assert.equal(cfgOf({ ...rf, tenant: { header: 'x-account' } }).requestFeed.tenant, 'x-account');
  // A witness host is never a feed host; and the record refuses edits.
  for (const edit of [r => { r.hosts = []; }, r => { r.routes[0].applied.push('declined'); }, r => { r.routes[0].settleMs = null; }, r => { r.maxSkewMs = -1; }, r => { r.keyDigest = 'x'; }, r => { r.extra = 1; }, r => { r.watermark = 'yes'; }]) {
    const r = structuredClone(C.FEED); edit(r); assert.equal(validRequestFeedRecord(r), false);
  }
});

test('2. the profile: the feed endpoint never shares a port with the app, an observer, an upstream or another feed', () => {
  const profile = (observers, origin = 'http://127.0.0.1:47200') => ({ schemaVersion: 1, targets: [{ id: 'r1-app', name: 'R1 app', applicationId: 'r1-app', origin, buildLabel: 'b1', contextId: 'synthetic-r1',
    actors: { member: { principalId: 'member-1' } }, requiredControlIds: ['WHOAMI'], observers,
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] }] });
  assert.doesNotThrow(() => validateTargetFile(profile([C.declaration()])));
  assert.throws(() => validateTargetFile(profile([C.declaration()], 'http://127.0.0.1:47120')), /the target origin/);
  assert.throws(() => validateTargetFile(profile([C.declaration({ upstream: 47119 })])), /forward upstream/);
  assert.throws(() => validateTargetFile(profile([C.declaration(), { id: 'sink2', type: 'egress-recorder', port: 47120, destinations: [{ host: 'hooks.example' }] }])), /observer "sink2"/);
  assert.throws(() => validateTargetFile(profile([{ ...C.declaration(), requestFeed: { ...C.requestFeed(), unknown: true } }])), /"requestFeed" is/);
  // A second egress recorder forwarding a feed host is another writer the feed lists and the group never sees: refused.
  assert.throws(() => validateTargetFile(profile([C.declaration(), { id: 'sink2', type: 'egress-recorder', port: 47121, destinations: [{ host: CRM }] }])), /egress recorder "sink2" also declares/);
  assert.doesNotThrow(() => validateTargetFile(profile([C.declaration(), { id: 'sink2', type: 'egress-recorder', port: 47121, destinations: [{ host: 'hooks.example' }] }])));
  assert.doesNotThrow(() => validateTargetFile(profile([C.declaration({ feed: null }), { id: 'sink2', type: 'egress-recorder', port: 47121, destinations: [{ host: CRM }] }])), 'no feed: main\'s rules');
});

test('3. the sealed read, by shape; the dirty statuses equal the key rules\' own', () => {
  assert.deepEqual(DIRTY_STATUSES, IDEMPOTENCY_DIRTY);
  assert.ok(validRequestFeedRead(read({ entries: [entry(), entry({ object: 2 }), entry({ object: 1, state: 'not-applied' })] })));
  assert.ok(validRequestFeedRead(read({ headMono: null, headWall: null, watermark: null, clear: false })));
  const bad = [read({ extra: 1 }), (({ more: _m, ...r }) => r)(read()), read({ clear: 'yes' }), read({ headMono: null }), read({ headMono: -1 }), read({ watermark: 1.5 }), read({ history: -1 }),
    read({ keySends: 1.5 }), read({ entries: [entry({ object: 2 })] }), read({ entries: [entry(), entry({ object: 3 })] }), read({ entries: [entry({ state: 'succeeded' })] }), read({ entries: [{ ...entry(), id: 'x' }] }),
    read({ entries: [entry({ route: 1 })] }), read({ entries: Array.from({ length: REQUEST_FEED_BOUNDS.entriesPerKey + 1 }, () => entry()) }), null, []];
  for (const r of bad) assert.equal(validRequestFeedRead(r), false, JSON.stringify(r));
});

// --- The derivation, row by row, through the core's binding -----------------------------------------------------------------
// Bind the recorder's records for these events (as the run-end stage does) and read each event's fate and request-feed record (r1).
function decide(events, records, { feed } = {}) {
  const w = windowOf(events, { feed });
  bindResolutions([w], lateEntriesFor([w], records));
  return events.map(e => ({ fate: inDoubtAttempt(e) ? fateOf(e) : null, r1: boundRecords(e).find(r => r.resolver === 'r1') ?? null, by: inDoubtAttempt(e) ? attemptBasis(e) : null }));
}
const r1Of = (events, records, options) => decide(events, records, options).map(x => (x.r1 ? (x.r1.status === 'failed' ? `failed:${x.r1.reason}` : x.r1.result) : null));

test('4. applicability: the request feed (r1) applies only to an in-doubt attempt of a request-feed window that connected, is keyed, exact, query-free and on a declared route', () => {
  assert.deepEqual(LATER_RESOLVER_NAMES, ['r1', 'r2']);
  const cases = [[send({ seq: 1 }), ['r0', 'r1']], [send({ seq: 2, outcome: 'refused' }), ['r0']], [send({ seq: 3, outcome: 'missing' }), ['r0']], [send({ seq: 4, outcome: 'applied' }), []],
    [send({ seq: 5, key: null }), ['r0']], [send({ seq: 6, exact: false }), ['r0']], [send({ seq: 7, query: true }), ['r0']], [send({ seq: 8, resource: 'POST /tickets/T-9/close' }), ['r0']],
    [send({ seq: 9, host: ALT }), ['r0']], [send({ seq: 10, outcome: 'server' }), ['r0', 'r1']]];
  windowOf(cases.map(([e]) => e));
  for (const [e, want] of cases) assert.deepEqual(applicableResolvers(e), want, `seq ${e.seq}`);
  // A window without the feed (or a copy of an event) never marks it: r0 alone.
  const plain = send({ seq: 11 }); windowOf([plain], { feed: null });
  assert.deepEqual([applicableResolvers(plain), applicableResolvers(structuredClone(cases[0][0]))], [['r0'], ['r0']]);
  assert.equal(requestFeedApplies(cases[0][0], null), false);
});

test('5. a confirmation: one applied entry for the exact key, bound by time and after the start read, on a clean feed', () => {
  const e = send({ seq: 1 });
  assert.deepEqual(decide([e], [supplied(e, read({ entries: [entry()] }))])[0].fate, 'applied');
  assert.equal(attemptBasis(e).by, 'r1');
  // A group of two same-identity attempts: the provider applied the key once, so the first is confirmed and the retry refuted.
  const a = send({ seq: 1 }), b = send({ seq: 2, firstSeq: 1, arrived: 1200, ended: 1300 });
  assert.deepEqual(r1Of([a, b], [supplied(a, read({ keySends: 2, entries: [entry()] })), supplied(b, read({ keySends: 2, entries: [entry()] }))]), ['confirms', 'refutes']);
  // A member proven applied: the application is that one, and every in-doubt member is refuted as a further application.
  const p = send({ seq: 1, outcome: 'applied' }), r = send({ seq: 2, firstSeq: 1, arrived: 1200, ended: 1300 });
  assert.deepEqual(r1Of([p, r], [supplied(r, read({ keySends: 2, entries: [entry()] }))]), [null, 'refutes']);
  // A proven declared rejection (a 409 while the key was in flight) and a never-connected attempt leave the group; the reset member is confirmed.
  const j = send({ seq: 1, outcome: 'rejected' }), n = send({ seq: 2, firstSeq: 1, outcome: 'refused' }), m = send({ seq: 3, firstSeq: 1 });
  assert.deepEqual(r1Of([j, n, m], [supplied(m, read({ keySends: 3, entries: [entry()] }))]), [null, null, 'confirms']);
  // pending and closed are both applied words; the same object.
  const q = send({ seq: 1 });
  assert.deepEqual(r1Of([q], [supplied(q, read({ entries: [entry(), entry({ at: OFFSET + 1060 })] }))]), ['confirms']);
});

test('6. a refutation: no applied entry, a declared watermark past the bound, the head read past it on the monotonic clock, offsets stable', () => {
  const ok = { headMono: 1100 + SETTLE, headWall: OFFSET + 1100 + SETTLE, watermark: OFFSET + 1100 + SETTLE + SKEW };
  for (const [fields, entries, want, why] of [
    [ok, [], 'refutes', 'absence under the watermark'],
    [ok, [entry({ state: 'not-applied' })], 'refutes', 'a signed declined word, under the watermark'],
    [{ ...ok, watermark: null }, [], 'silent', 'no watermark: confirm-only'],
    [{ ...ok, watermark: null }, [entry({ state: 'not-applied' })], 'silent', 'a declined word alone refutes nothing without the watermark'],
    [{ ...ok, watermark: ok.watermark - 1 }, [], 'silent', 'the watermark short of the bound by 1 ms'],
    [{ ...ok, headMono: ok.headMono - 1 }, [], 'silent', 'the head read 1 ms early on the monotonic clock'],
    [{ ...ok, headWall: ok.headWall + SKEW + 1 }, [], 'silent', 'the wall-to-monotonic offset moved by more than the skew (a step or a sleep)'],
    [{ ...ok, headWall: null }, [], 'silent', 'no wall clock at the head read'],
  ]) { const e = send({ seq: 1 }); assert.deepEqual(r1Of([e], [supplied(e, read({ ...fields, entries }))]), [want], why); }
  // No wall clock at the connection end: never refuted; a route without settleMs or a feed without watermark neither.
  { const e = send({ seq: 1, endWall: null }); assert.deepEqual(r1Of([e], [supplied(e, read(ok))]), ['silent']); }
  { const e = send({ seq: 1, resource: OTHER }); assert.deepEqual(r1Of([e], [supplied(e, read(ok))]), ['silent'], 'the route declares no settleMs'); }
  { const e = send({ seq: 1 }); assert.deepEqual(r1Of([e], [supplied(e, read(ok))], { feed: { ...C.FEED, watermark: false } }), ['silent'], 'the feed declares no watermark'); }
  // A member proven applied and no entry: the feed has not caught up, which decides nothing.
  { const p = send({ seq: 1, outcome: 'applied' }), r = send({ seq: 2, firstSeq: 1, arrived: 1200, ended: 1300 });
    assert.deepEqual(r1Of([p, r], [supplied(r, read({ ...ok, headMono: 1300 + SETTLE, watermark: OFFSET + 1300 + SETTLE + SKEW, keySends: 2 }))]), [null, 'silent']); }
  // Every connected member's bound must hold: the later member's connection end sets it.
  { const a = send({ seq: 1 }), b = send({ seq: 2, firstSeq: 1, arrived: 1200, ended: 1300 });
    const r = read({ ...ok, keySends: 2 });
    assert.deepEqual(r1Of([a, b], [supplied(a, r), supplied(b, r)]), ['silent', 'silent']);
    const later = read({ headMono: 1300 + SETTLE, headWall: OFFSET + 1300 + SETTLE, watermark: OFFSET + 1300 + SETTLE + SKEW, keySends: 2 });
    assert.deepEqual(r1Of([a, b], [supplied(a, later), supplied(b, later)]), ['refutes', 'refutes']); }
});

test('7. in doubt: every anomaly of the feed, the key, the group or the clocks leaves the whole group failed', () => {
  const one = (r, events = [send({ seq: 1 })]) => r1Of(events, events.filter(e => e.upstream.transport?.connected && e.upstream.outcome === 'unknown').map(e => supplied(e, r)));
  for (const [r, reason] of [
    [read({ clear: false, entries: [entry()] }), 'feed-unclear'], [read({ more: true, entries: [entry()] }), 'entries-capped'], [read({ history: 1, entries: [entry()] }), 'key-history'],
    [read({ otherHosts: 1, entries: [entry()] }), 'key-other-host'], [read({ variants: 1 }), 'key-variant-entry'], [read({ entries: [entry({ route: false })] }), 'route-mismatch'], [read({ entries: [entry({ type: false })] }), 'type-unlisted'],
    [read({ entries: [entry({ tenant: false })] }), 'tenant-mismatch'], [read({ entries: [entry({ state: 'other' })] }), 'state-unlisted'], [read({ entries: [entry(), entry({ object: 2 })] }), 'key-objects'],
    [read({ entries: [entry({ at: OFFSET + 1000 - SKEW - 1 })] }), 'entry-outside-interval'], [read({ entries: [entry({ at: OFFSET + 1100 + SETTLE + SKEW + 1 })] }), 'entry-outside-interval'],
    [read({ entries: [entry(), entry({ state: 'not-applied' })] }), 'state-mixed'], [read({ keySends: 2, entries: [entry()] }), 'key-other-window'], [read({ dirtySends: 1, entries: [entry()] }), 'host-dirty'],
  ]) assert.deepEqual(one(r), [`failed:${reason}`], reason);
  // The interval's edges bind (inclusive), with no settleMs on a route the upper edge is the connection end plus the skew.
  assert.deepEqual(one(read({ entries: [entry({ at: OFFSET + 1000 - SKEW }), entry({ at: OFFSET + 1100 + SETTLE + SKEW })] })), ['confirms']);
  { const e = send({ seq: 1, resource: OTHER }); assert.deepEqual(one(read({ entries: [entry({ at: OFFSET + 1100 + SKEW + 1 })] }), [e]), ['failed:entry-outside-interval']); }
  assert.deepEqual(one(read({ entries: [entry()] }), [send({ seq: 1, arrivedWall: null })]), ['failed:clock-missing']);
  // Group anomalies, from the sealed window itself.
  const k = (seq, extra = {}) => send({ seq, firstSeq: 1, arrived: 1000 + 100 * seq, ended: 1050 + 100 * seq, ...extra });
  const two = r => ({ ...r, keySends: 2 });
  const groups = [
    [[send({ seq: 1 }), k(2, { key: { status: 'keyed', key: 'b'.repeat(64), fold: C.send({ seq: 1 }).idempotency.fold, head: C.send({ seq: 1 }).idempotency.head, firstSeq: 1 } })], 'key-variant'],
    [[send({ seq: 1, key: { ...C.send({ seq: 1 }).idempotency, status: 'overlap' } }), k(2, { key: { ...C.send({ seq: 1 }).idempotency, status: 'overlap' } })], 'key-concurrent'],
    [[send({ seq: 2, firstSeq: 1 })], 'key-earlier-use'],
    [[send({ seq: 1 }), k(2, { content: 'other' })], 'key-identity-differs'],
    [[send({ seq: 1 }), send({ seq: 2, key: { status: 'unreadable', key: null, fold: null, head: 'c'.repeat(64), firstSeq: null } })], 'host-dirty'],
  ];
  for (const [events, reason] of groups) assert.ok(one(two(read({ entries: [entry()] })), events).every(x => x === null || x === `failed:${reason}`) && one(two(read({ entries: [entry()] })), events).some(x => x === `failed:${reason}`), reason);
  // An in-doubt member the feed cannot read (no transport record, a sub-path, or no record for it): the whole group is in doubt.
  for (const other of [k(2, { outcome: 'missing' }), k(2, { exact: false })]) { const a = send({ seq: 1 }); assert.deepEqual(r1Of([a, other], [supplied(a, two(read({ entries: [entry()] })))]), ['failed:group-unresolved', null]); }
  { const a = send({ seq: 1 }), b = k(2); assert.deepEqual(r1Of([a, b], [supplied(a, two(read({ entries: [entry()] })))]), ['failed:group-unresolved', null], 'a member with no record'); }
  { const a = send({ seq: 1 }), b = k(2); assert.deepEqual(r1Of([a, b], [supplied(a, two(read({ entries: [entry()] }))), supplied(b, two(read({ entries: [entry({ at: OFFSET + 1060 })] })))]), ['failed:record-mismatch', 'failed:record-mismatch']); }
  { const e = send({ seq: 1 }); assert.deepEqual(r1Of([e], [supplied(e, read({ entries: [entry()] }))], { feed: { ...C.FEED, maxSkewMs: 9999 } }), ['failed:declaration-invalid']); }
  // A failed record from the recorder, or a read the rules refuse, is failed; a bare result is never taken.
  { const e = send({ seq: 1 }); assert.deepEqual(r1Of([e], [{ observer: C.INST, seq: 1, records: [{ resolver: 'r1', status: 'failed', reason: 'read-not-run' }] }]), ['failed:read-not-run']); }
  { const e = send({ seq: 1 }); assert.deepEqual(r1Of([e], [supplied(e, { ...read(), extra: 1 })]), ['failed:record-invalid']); }
  { const e = send({ seq: 1 }); assert.deepEqual(r1Of([e], [{ observer: C.INST, seq: 1, records: [{ resolver: 'r1', status: 'succeeded', result: 'confirms' }] }]), ['failed:record-invalid']); }
  { const e = send({ seq: 1 }); assert.throws(() => bindResolutions([windowOf([e])], [{ observer: C.INST, seq: 1, records: [{ resolver: 'r1', status: 'succeeded', result: 'confirms' }] }]), /resolution-record/); }
});

test('8. an attempt reads only entries carrying its own exact key; a decline under K1 never confirms K1 when K2 later succeeds on the same object', () => {
  const ok = { headMono: 2100 + SETTLE, headWall: OFFSET + 2100 + SETTLE, watermark: OFFSET + 2100 + SETTLE + SKEW };
  const k1 = send({ seq: 1, key: 'K1', content: 'c1' }), k2 = send({ seq: 2, key: 'K2', content: 'c1', arrived: 2000, ended: 2100 });
  const results = r1Of([k1, k2], [supplied(k1, read({ ...ok, entries: [entry({ state: 'not-applied' })] })), supplied(k2, read({ ...ok, entries: [entry({ at: OFFSET + 2050 })] }))]);
  assert.deepEqual(results, ['refutes', 'confirms']);
  // The same, read with K2's applied entry wrongly under K1 (another key's read): K1 would be confirmed. The join is by the exact key's digest only,
  // which the recorder computes, so this is the reader's job (test 10), not a derivation the sealed read can be tricked into.
  const wrong = send({ seq: 1, key: 'K1' });
  assert.deepEqual(r1Of([wrong], [supplied(wrong, read({ entries: [entry()] }))]), ['confirms']);
  // deriveRequestFeed reads only what the window and the reads say.
  const own = supplied(k1, read({ entries: [entry()] })).records[0].read;
  const map = deriveRequestFeed({ window: windowOf([k1]), reads: new Map([[k1, own]]), inDoubt: inDoubtAttempt, applies: () => true });
  assert.equal(map.get(k1).result, 'confirms');
});

// --- The reader, against a loopback stub ------------------------------------------------------------------------------------------
const digests = { key: (host, k) => `k:${host}:${k}`, fold: (host, k) => `f:${host}:${k.toLowerCase()}`, tenant: (host, v) => `t:${host}:${v}`, object: (host, v) => `o:${host}:${v}` };
const readerFor = (stub, { feed = C.requestFeed(), clocks } = {}) => createRequestFeedReader({ config: cfgOf({ ...feed, feedId: stub.feedId, publicKey: stub.publicKey, endpoint: { port: stub.port, path: stub.path } }).requestFeed, digests, ...(clocks ? { clocks } : {}) });
const keyRead = (reader, k, { resource = CLOSE, tenant = 't:crm.example:' } = {}) => reader.keyRead(digests.key(CRM, k), { fold: digests.fold(CRM, k), resource, tenant });
async function withStub(t, fn, options) { const stub = await createRequestFeedStub(options).listen(); t.after(() => stub.close()); return fn(stub); }

test('9. the reader: history before the start read, entries after it, the paired clocks and the signed watermark', async t => withStub(t, async stub => {
  stub.add({ host: CRM, key: 'OLD' });
  const reader = readerFor(stub, { clocks: { mono: () => 4321.5, wall: () => OFFSET + 9999 } });
  await reader.start();
  stub.add({ host: CRM, key: 'K1', object: 'obj-9' }); stub.add({ host: CRM, key: 'K1', type: 'ticket.updated', object: 'obj-9', state: 'pending' });
  stub.add({ host: CRM, key: 'K2', route: OTHER, state: 'closed' }); stub.add({ host: ALT, key: 'K3' }); stub.add({ host: CRM, key: 'K4', type: 'ticket.reopened', state: 'reopened' });
  stub.add({ host: CRM, key: 'K5', tenant: 'acct-b' }); stub.add({ host: CRM, key: 'k7' });
  const state = await reader.readToHead({ capMs: 5000 });
  assert.deepEqual([state.clear, state.headMono, state.headWall, Number.isSafeInteger(state.watermark)], [true, 4321.5, OFFSET + 9999, true]);
  assert.deepEqual([keyRead(reader, 'OLD').history, keyRead(reader, 'OLD').entries.length], [1, 0], 'a key the provider saw before the start read is history');
  const k1 = keyRead(reader, 'K1');
  assert.deepEqual(k1.entries.map(x => [x.route, x.type, x.tenant, x.state, x.object]), [[true, true, true, 'applied', 1], [true, true, true, 'applied', 1]]);
  assert.deepEqual([k1.history, k1.otherHosts, k1.more], [0, 0, false]);
  assert.deepEqual(keyRead(reader, 'K2').entries.map(x => [x.route, x.state]), [[false, 'applied']], 'another route than the send\'s');
  assert.deepEqual(keyRead(reader, 'K2', { resource: OTHER }).entries.map(x => x.route), [true]);
  assert.equal(keyRead(reader, 'K3').otherHosts, 1, 'the same raw key on another host');
  assert.deepEqual(keyRead(reader, 'K4').entries.map(x => [x.type, x.state]), [[false, 'other']], 'an unlisted type and word');
  assert.deepEqual(keyRead(reader, 'K5').entries.map(x => x.tenant), [false], 'a tenant on a feed that declares none');
  assert.deepEqual([keyRead(reader, 'K7').variants, keyRead(reader, 'K7').entries.length, keyRead(reader, 'k7').variants], [1, 0, 0], 'a case variant of the key the provider recorded');
  assert.equal(await reader.readToHead({ capMs: 5000 }), state, 'read once');
  await reader.stop();
}));

test('10. the reader: tenants, object ordinals, the per-key cap, a redelivery read once, and no watermark unless declared', async t => withStub(t, async stub => {
  const reader = readerFor(stub, { feed: C.requestFeed({ tenant: { header: 'x-account' } }) });
  await reader.start();
  stub.add({ host: CRM, key: 'K1', tenant: 'acct-a', object: 'o1' }); const dup = stub.add({ host: CRM, key: 'K1', tenant: 'acct-a', object: 'o2' });
  stub.redeliver(dup);
  for (let i = 0; i < REQUEST_FEED_BOUNDS.entriesPerKey + 1; i++) stub.add({ host: CRM, key: 'K9' });
  stub.add({ host: CRM, key: 'K6' });
  assert.equal((await reader.readToHead({ capMs: 5000 })).clear, true);
  const k1 = reader.keyRead(digests.key(CRM, 'K1'), { resource: CLOSE, tenant: digests.tenant(CRM, 'acct-a') });
  assert.deepEqual(k1.entries.map(x => [x.tenant, x.object]), [[true, 1], [true, 2]], 'two objects; the redelivery is read once');
  assert.deepEqual(reader.keyRead(digests.key(CRM, 'K1'), { resource: CLOSE, tenant: digests.tenant(CRM, 'acct-b') }).entries.map(x => x.tenant), [false, false]);
  assert.deepEqual(reader.keyRead(digests.key(CRM, 'K6'), { resource: CLOSE, tenant: digests.tenant(CRM, '') }).entries.map(x => x.tenant), [true], 'no tenant on either side: the default');
  assert.deepEqual(reader.keyRead(digests.key(CRM, 'K6'), { resource: CLOSE, tenant: null }).entries.map(x => x.tenant), [false], 'a send whose tenant header repeated');
  const capped = reader.keyRead(digests.key(CRM, 'K9'), { resource: CLOSE, tenant: '' });
  assert.deepEqual([capped.entries.length, capped.more], [REQUEST_FEED_BOUNDS.entriesPerKey, true]);
  await reader.stop();
  const plainFeed = readerFor(stub, { feed: C.requestFeed({ watermark: undefined }) });
  await plainFeed.start();
  assert.deepEqual([(await plainFeed.readToHead({ capMs: 5000 })).watermark], [null], 'a feed that declares no watermark never carries one');
  await plainFeed.stop();
}));

test('11. the reader fails closed: unsigned, wrong key, malformed, another feed or epoch, a rewrite, a gap, a reorder, an id reused with another body, an invalid head, a cut read', async t => {
  const cases = {
    'an entry signed with another key': stub => stub.add({ host: CRM, key: 'K1', signer: feedKeys().privateKey }),
    'an unsigned entry': stub => stub.addRaw({ body: JSON.stringify({ feed: stub.feedId, epoch: stub.epoch, seq: stub.entries.length + 1, id: 'x', at: new Date().toISOString(), type: 'ticket.closed', host: CRM, route: CLOSE, key: 'K1', object: 'o', state: 'closed' }), sig: '' }),
    'an unknown field': stub => stub.add({ host: CRM, key: 'K1', extra: { app: 'x' } }),
    'a malformed key': stub => stub.add({ host: CRM, key: 'has space' }),
    'another feed': stub => stub.addRaw(signedEntry(stub.keys.privateKey, { feed: 'other', epoch: stub.epoch, seq: stub.entries.length + 1, id: 'x', at: new Date().toISOString(), type: 't', host: CRM, route: CLOSE, key: 'K1', object: 'o', state: 'closed' })),
    'another epoch': stub => stub.addRaw(signedEntry(stub.keys.privateKey, { feed: stub.feedId, epoch: 'e2', seq: stub.entries.length + 1, id: 'x', at: new Date().toISOString(), type: 't', host: CRM, route: CLOSE, key: 'K1', object: 'o', state: 'closed' })),
    'a second genesis': stub => stub.addRaw(signedEntry(stub.keys.privateKey, { feed: stub.feedId, epoch: stub.epoch, seq: stub.entries.length + 1, id: 'g2', at: new Date().toISOString(), type: 'epoch-start' })),
    'time going backward': stub => { stub.add({ host: CRM, key: 'K1' }); stub.addRaw(signedEntry(stub.keys.privateKey, { feed: stub.feedId, epoch: stub.epoch, seq: stub.entries.length + 1, id: 'y', at: '2001-01-01T00:00:00.000Z', type: 't', host: CRM, route: CLOSE, key: 'K2', object: 'o', state: 'closed' })); },
    'an event id reused with another body': stub => { const s = stub.add({ host: CRM, key: 'K1' }); stub.redeliver(s, b => ({ ...b, state: 'declined' })); },
    'a gap': stub => { stub.add({ host: CRM, key: 'K1' }); stub.add({ host: CRM, key: 'K2' }); stub.serve.drop.add(stub.entries.length - 1); },
    'a page served out of order': stub => { stub.add({ host: CRM, key: 'K1' }); stub.add({ host: CRM, key: 'K2' }); stub.serve.order = 'reverse'; },
    'a head below what was read': stub => { stub.serve.headSeq = () => 1; },
    'a head past what is served': stub => { stub.add({ host: CRM, key: 'K1' }); stub.serve.headSeq = () => stub.entries.length + 5; },
    'the feed down at run end': stub => { stub.serve.status = 503; },
  };
  for (const [why, spoil] of Object.entries(cases)) await withStub(t, async stub => {
    // An entry before the start read, so the start read reaches seq 2 (a head may then sign below it).
    stub.add({ host: CRM, key: 'K0' });
    const reader = readerFor(stub);
    await reader.start();
    spoil(stub);
    const state = await reader.readToHead({ capMs: 5000 });
    assert.deepEqual([state.clear, state.watermark], [false, null], why);
    await reader.stop();
  });
  // A rewrite of an entry already read, seen on a re-read: the stub serves the start read's entries again from 0 after a restart.
  await withStub(t, async stub => {
    stub.add({ host: CRM, key: 'K1' });
    const reader = readerFor(stub); await reader.start();
    stub.entries[1] = signedEntry(stub.keys.privateKey, { ...JSON.parse(stub.entries[1].body), state: 'declined' });
    stub.serve.headSeq = () => stub.entries.length;
    stub.add({ host: CRM, key: 'K2' });
    assert.equal((await reader.readToHead({ capMs: 5000 })).clear, true, 'seq lastSeq + 1 on: an entry already read is never re-read in a run');
    await reader.stop();
  });
  // The start read failed (the feed was down): the run-end read is never clear. A cap of 0 reads nothing.
  await withStub(t, async stub => {
    stub.serve.status = 500;
    const reader = readerFor(stub); await reader.start();
    stub.serve.status = 200;
    assert.equal((await reader.readToHead({ capMs: 5000 })).clear, false);
    await reader.stop();
    const capped = readerFor(stub); await capped.start();
    assert.equal((await capped.readToHead({ capMs: 0 })).clear, false);
    await capped.stop();
  });
});

test('12. property: any fault in the served feed (an entry dropped, reordered, unsigned, re-signed by another key, edited under its old signature, redelivered with another body) is detected, so every request-feed record fails; untouched, the reads are the feed\'s', async t => {
  const g = C.rng(1212), KEYS = ['A', 'B', 'C'];
  const FAULTS = {
    drop: stub => { stub.serve.drop.add(2 + Math.floor(g() * (stub.entries.length - 1))); },
    reorder: stub => { stub.serve.order = 'reverse'; },
    unsign: stub => { const i = 1 + Math.floor(g() * (stub.entries.length - 1)); stub.entries[i] = { ...stub.entries[i], sig: stub.entries[1 + ((i) % (stub.entries.length - 1))].sig }; },
    'other key': stub => { const i = 1 + Math.floor(g() * (stub.entries.length - 1)); stub.entries[i] = signedEntry(feedKeys().privateKey, JSON.parse(stub.entries[i].body)); },
    'edited body': stub => { const i = 1 + Math.floor(g() * (stub.entries.length - 1)), b = JSON.parse(stub.entries[i].body); stub.entries[i] = { body: JSON.stringify({ ...b, state: b.state === 'closed' ? 'declined' : 'closed' }), sig: stub.entries[i].sig }; },
    'redelivery, another body': stub => { stub.redeliver(2, b => ({ ...b, object: `${b.object}-x` })); },
  };
  const counts = Object.fromEntries([...Object.keys(FAULTS), 'none'].map(k => [k, 0]));
  for (let n = 0; n < 42; n++) await withStub(t, async stub => {
    const reader = readerFor(stub); await reader.start();
    const entries = 2 + Math.floor(g() * 5);
    for (let i = 0; i < entries; i++) stub.add({ host: CRM, key: C.pick(g, KEYS), state: C.pick(g, ['closed', 'pending', 'declined']), object: C.pick(g, ['o1', 'o1', 'o2']) });
    const fault = n % 7 === 6 ? 'none' : Object.keys(FAULTS)[n % 6];
    if (fault !== 'none') FAULTS[fault](stub);
    const state = await reader.readToHead({ capMs: 5000 });
    counts[fault]++;
    if (fault === 'none') {
      assert.equal(state.clear, true);
      const want = new Map(KEYS.map(k => [k, stub.entries.slice(1).map(e => JSON.parse(e.body)).filter(b => b.key === k)]));
      for (const k of KEYS) assert.deepEqual(keyRead(reader, k).entries.map(x => x.state), want.get(k).map(b => (b.state === 'declined' ? 'not-applied' : 'applied')), k);
    } else assert.equal(state.clear, false, fault);
    await reader.stop();
  });
  t.diagnostic(`feed faults: ${JSON.stringify(counts)}`);
  assert.ok(Object.values(counts).every(x => x >= 6), JSON.stringify(counts));
});

test('13. an absence refutation needs the key to list at least as many entries as members the provider answered (a positive control, as read-back\'s C1)', () => {
  const ok = read({ headMono: 1300 + SETTLE, headWall: OFFSET + 1300 + SETTLE, watermark: OFFSET + 1300 + SETTLE + SKEW, keySends: 2 });
  const group = first => [send({ seq: 1, outcome: first }), send({ seq: 2, firstSeq: 1, arrived: 1200, ended: 1300 })];
  const readsFor = (events, r) => events.filter(e => e.upstream.transport?.connected && e.upstream.outcome === 'unknown').map(e => supplied(e, r));
  // A proven 409 the feed does not list: the watermark's claim is false for this key, so the reset retry is not refuted.
  { const events = group('rejected'); assert.deepEqual(r1Of(events, readsFor(events, ok)), [null, 'silent']); assert.equal(fateOf(events[1]), 'in-doubt'); }
  // The 409 listed (a declined word): the retry's absence refutes, as before.
  { const events = group('rejected'); assert.deepEqual(r1Of(events, readsFor(events, { ...ok, entries: [entry({ state: 'not-applied' })] })), [null, 'refutes']); }
  // A proven 503 (an answer, in doubt itself) the feed does not list: both stay undecided.
  { const events = group('server'); assert.deepEqual(r1Of(events, readsFor(events, ok)), ['silent', 'silent']); }
  // With no proven reply in the group the absence refutes (test 6).
  { const events = group('reset'); assert.deepEqual(r1Of(events, readsFor(events, ok)), ['refutes', 'refutes']); }
});

test('14. the request feed and the key collapse read a group\'s identity and retention through one function, src/key-identity.mjs keyGroupIdentity; neither module keeps a copy', async () => {
  for (const name of ['idempotency.mjs', 'request-feed-rules.mjs']) {
    const text = await readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
    assert.match(text, /import \{[^}]*\bkeyGroupIdentity\b[^}]*\} from '\.\/key-identity\.mjs';/, name);
    assert.doesNotMatch(text, /function (signedGate|signingGate|keyGroupIdentity|identityOf)\b|const (sendIdentity|identityOf|signingGate|signedGate) =/, name);
  }
});
