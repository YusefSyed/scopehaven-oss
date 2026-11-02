// Later outcomes (collector provider-feed/5): the profile declaration, the run
// record's feed, the settlement record's later list and its binding, and the limitation sentence. Pure: no socket, no file read
// beyond module loading. The observer and the connector are tested over a loopback stub in integrations/observers/provider-feed.test.mjs
// and test/provider-feed-connector.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { validateProviderFeedConfig, providerFeedRecord, validProviderFeedRecord, validLater, laterFeedsOf, LATER_OUTCOMES, LATER_RECORD_WORDS, LATER_TERMINAL, LATER_LIMITS } from '../src/provider-feed-rules.mjs';
import { COLLECTOR_LABELS, KNOWN_COLLECTOR_LABELS, OUTCOME_COLLECTOR_LABELS, LATER_STAGE_LABELS, TEMPLATE_LIFT_LABELS, DRAIN_COLLECTOR_LABELS, SCOPED_COLLECTOR_LABELS, CAPTURED_ENTRY_LABELS, TEMPLATE_COLLECTOR_LABELS } from '../src/collector-identity.mjs';
import { validateSettlementRecord, finalSettleMs } from '../src/http-settlement.mjs';
import { httpLimitations } from '../src/http-scope-text.mjs';

const KEY = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const EXT = 'customers.example';
const actors = { ops: {} };
const feed = extra => ({ type: 'provider-feed', feedId: 'mail', feed: { endpoint: { port: 4471, path: '/feed' } }, publicKey: KEY, domains: [{ domain: EXT }],
  routing: 'provider', witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: 'witness.scopehaven.invalid' }, ...extra });

test('the declaration: outcomes { waitMs? } only on an endpoint feed with a witness; waitMs 0 to 30000, default 0', () => {
  assert.deepEqual(validateProviderFeedConfig(feed({ outcomes: {} }), actors).outcomes, { waitMs: 0 });
  assert.deepEqual(validateProviderFeedConfig(feed({ outcomes: { waitMs: 30000 } }), actors).outcomes, { waitMs: 30000 });
  assert.equal(validateProviderFeedConfig(feed(), actors).outcomes, null, 'without the declaration nothing is read');
  for (const outcomes of [true, [], { waitMs: -1 }, { waitMs: 30001 }, { waitMs: 1.5 }, { waitMs: '10' }, { waitMs: 10, horizon: 1 }])
    assert.throws(() => validateProviderFeedConfig(feed({ outcomes }), actors), /"outcomes/, JSON.stringify(outcomes));
  const { routing, witness, ...unwitnessed } = feed({ outcomes: {} });
  assert.throws(() => validateProviderFeedConfig(unwitnessed, actors), /endpoint feed with a witness/);
  assert.throws(() => validateProviderFeedConfig({ ...unwitnessed, feed: { file: { path: '/tmp/feed.jsonl' } } }, actors), /endpoint feed with a witness/);
});

test('the run record carries outcomes { waitMs } beside the feed identity, and only an endpoint record may', () => {
  const plain = providerFeedRecord(feed()), declared = providerFeedRecord(feed({ outcomes: { waitMs: 2500 } }));
  assert.deepEqual(Object.keys(plain), ['feedId', 'keyDigest', 'route', 'keySource'], 'a feed without outcomes adds only its key source to the record (provider-feed/7)');
  assert.deepEqual(declared.outcomes, { waitMs: 2500 });
  assert.deepEqual(providerFeedRecord(feed({ outcomes: {} })).outcomes, { waitMs: 0 });
  assert.ok(validProviderFeedRecord(plain) && validProviderFeedRecord(declared));
  assert.ok(validProviderFeedRecord({ ...declared, templates: ['order_cancelled'] }));
  for (const bad of [{ ...declared, route: 'file' }, { ...declared, outcomes: { waitMs: 30001 } }, { ...declared, outcomes: { waitMs: 1, extra: 1 } }, { ...declared, outcomes: {} }, { ...declared, outcomes: null }])
    assert.equal(validProviderFeedRecord(bad), false, JSON.stringify(bad.outcomes));
});

test('the vocabulary: six words the adapter maps onto, three of them terminal, and "ambiguous" only as a sealed reading', () => {
  assert.deepEqual(LATER_OUTCOMES, ['succeeded', 'deferred', 'failed', 'reversed', 'contested', 'complained']);
  assert.deepEqual(LATER_TERMINAL, ['succeeded', 'failed', 'reversed']);
  assert.deepEqual(LATER_RECORD_WORDS, [...LATER_OUTCOMES, 'ambiguous']);
  assert.deepEqual(LATER_LIMITS, { records: 20000, perEvent: 16 });
});

test('the collector: provider-feed/6 judges later outcomes (as /7, which adds the key source, and /8, which holds the confirming head of the drain to its quiet read, do), /5 seals them inert, and every earlier feed capability is kept; saved /1 to /7 runs stay known', () => {
  assert.equal(COLLECTOR_LABELS['provider-feed'], 'provider-feed/8');
  assert.deepEqual(OUTCOME_COLLECTOR_LABELS, ['provider-feed/5', 'provider-feed/6', 'provider-feed/7', 'provider-feed/8']);
  assert.deepEqual(LATER_STAGE_LABELS, ['provider-feed/6', 'provider-feed/7', 'provider-feed/8']);
  for (const label of ['provider-feed/1', 'provider-feed/2', 'provider-feed/3', 'provider-feed/4', 'provider-feed/5', 'provider-feed/6', 'provider-feed/7', 'provider-feed/8']) assert.ok(KNOWN_COLLECTOR_LABELS.includes(label), label);
  for (const list of [SCOPED_COLLECTOR_LABELS, CAPTURED_ENTRY_LABELS, TEMPLATE_LIFT_LABELS, TEMPLATE_COLLECTOR_LABELS, DRAIN_COLLECTOR_LABELS]) assert.ok(list.includes('provider-feed/8') && list.includes('provider-feed/7') && list.includes('provider-feed/6') && list.includes('provider-feed/5') && list.includes('provider-feed/4'));
});

// A run's observer record of a feed, as declaredObserverRecord writes it (collector label set by the test).
const record = (id, label, outcomes = { waitMs: 2000 }) => ({ id, type: 'provider-feed', settleMs: 250, collector: { label, digest: '0'.repeat(64), node: '24.21.0' }, witnessed: true,
  feed: { feedId: id, keyDigest: '1'.repeat(64), route: 'endpoint', ...(outcomes ? { outcomes } : {}) } });

test('laterFeedsOf: a feed record that declares outcomes under a label that reads them, in declaration order', () => {
  const a = record('a', 'provider-feed/5'), b = record('b', 'provider-feed/4'), c = record('c', 'provider-feed/5', null), d = record('d', 'provider-feed/5');
  assert.deepEqual(laterFeedsOf([a, b, c, { id: 'e', type: 'egress-recorder' }, d], OUTCOME_COLLECTOR_LABELS).map(o => o.id), ['a', 'd']);
  assert.deepEqual(laterFeedsOf(undefined, OUTCOME_COLLECTOR_LABELS), []);
});

const entry = (records, extra = {}) => ({ instanceId: 'provider-feed-a', clear: true, waitedMs: 120, records, ...extra });
test('validLater: one entry per later feed, its records by event seq, words from the vocabulary, an ambiguous send once, at most 16 words a send', () => {
  const feeds = [record('a', 'provider-feed/5')];
  assert.ok(validLater([entry([])], feeds));
  assert.ok(validLater([entry([{ of: 129, outcome: 'deferred' }, { of: 129, outcome: 'succeeded' }, { of: 130, outcome: 'ambiguous' }, { of: 257, outcome: 'failed' }])], feeds));
  assert.ok(validLater([entry(Array.from({ length: 16 }, () => ({ of: 129, outcome: 'deferred' })))], feeds));
  const refused = {
    'no entry': [],
    'two entries for one feed': [entry([]), entry([])],
    'another instance': [entry([], { instanceId: 'provider-feed-b' })],
    'a waited time past the declaration': [entry([], { waitedMs: 2001 })],
    'a negative waited time': [entry([], { waitedMs: -1 })],
    'clear not a boolean': [entry([], { clear: 'yes' })],
    'an extra key': [entry([], { horizon: 1 })],
    'a word outside the vocabulary': [entry([{ of: 129, outcome: 'bounced' }])],
    'records out of event order': [entry([{ of: 130, outcome: 'failed' }, { of: 129, outcome: 'failed' }])],
    'an ambiguous send with a word too': [entry([{ of: 129, outcome: 'ambiguous' }, { of: 129, outcome: 'succeeded' }])],
    'seventeen words for one send': [entry(Array.from({ length: 17 }, () => ({ of: 129, outcome: 'deferred' })))],
    'a record with a provider id': [entry([{ of: 129, outcome: 'failed', messageId: 'msg_1' }])],
    'an event seq of 0': [entry([{ of: 0, outcome: 'failed' }])],
  };
  for (const [what, list] of Object.entries(refused)) assert.equal(validLater(list, feeds), false, what);
  assert.equal(validLater([entry(Array.from({ length: LATER_LIMITS.records + 1 }, (_, i) => ({ of: i + 1, outcome: 'failed' })))], feeds), false, 'past the record cap');
});

// A one-check settlement record (/1) with empty gap windows: the binding of windows is the caller's (bind is the identity here).
const settlementOf = (observers, extra = {}) => ({ schema: 'scopehaven-settlement/1', settleMs: finalSettleMs(observers), gaps: [{ before: 'c1', after: null, windows: [] }, { before: null, after: 'c1', windows: [] }], ...extra });
const readWith = (input, observers) => validateSettlementRecord(input, { effectRowIds: ['c1'], declaredObservers: observers, bind: windows => windows });

test('the settlement record: a later list exactly when a feed record reads later outcomes, checked on its own and returned', () => {
  const later = [record('a', 'provider-feed/5')], none = [record('a', 'provider-feed/4')];
  const list = [entry([{ of: 129, outcome: 'failed' }])];
  assert.deepEqual(readWith(settlementOf(later, { later: list }), later).later, list);
  assert.equal(readWith(settlementOf(none), none).later, null, 'a run without later feeds has none');
  assert.throws(() => readWith(settlementOf(later), later), /settlement-later/, 'a later feed without its list');
  assert.throws(() => readWith(settlementOf(none, { later: list }), none), /settlement-later/, 'a list without a later feed (a /4 record)');
  assert.throws(() => readWith(settlementOf(later, { later: [entry([{ of: 129, outcome: 'bounced' }])] }), later), /settlement-later/);
  // Read apart like drains: the rest of the record is validated exactly as before (an extra key is still refused).
  assert.throws(() => readWith(settlementOf(later, { later: list, extra: 1 }), later), /settlement-record/);
});

test('the limitation names the later wait and says the records decide nothing, only for a feed that declares outcomes', () => {
  const base = { forwarded: false, observersDeclared: true, declared: [] };
  const feedWith = extra => ({ id: 'mail', route: 'endpoint', witnessed: true, quietMs: 300, templates: false, ...extra });
  const text = list => httpLimitations({ ...base, providerFeeds: list }).join('\n');
  assert.ok(!text([feedWith()]).includes('declares outcomes'));
  const declared = text([feedWith({ outcomesWaitMs: 3000 })]);
  assert.ok(declared.includes('A feed that declares outcomes (mail: later wait up to 3000 ms)'));
  assert.ok(declared.includes('They only ever lower a positive pass'));
  assert.ok(declared.includes('a forbidden send that bounced still fails'));
  assert.ok(declared.includes('never a provider id or an address'));
});
