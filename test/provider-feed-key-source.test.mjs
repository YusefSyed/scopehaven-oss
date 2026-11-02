// A provider feed's declared key source (keySource, provider-feed/7): its custody rests on who holds the key that signs its entries, and
// nothing in a run shows that. An app can serve a feed of its own on a second port and sign it with its own key. So the profile
// declares where the public key came from (keySource: provider, adapter with adapterReads, or stub), the run record's feed and every
// sealed window carry it, and custody reads it: an undeclared source, or an adapter that reads the application's own store, is a key
// the application could hold, so the feed never supports a pass. Every request goes to 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { compareRuns } from '../src/runner.mjs';
import { COLLECTOR_RECORDS, COLLECTOR_LABELS, KNOWN_COLLECTOR_LABELS, KEY_SOURCE_LABELS, OUTCOME_COLLECTOR_LABELS, LATER_STAGE_LABELS, TEMPLATE_LIFT_LABELS } from '../src/collector-identity.mjs';
import { validateProviderFeedConfig, providerFeedRecord, validProviderFeedRecord, FEED_KEY_SOURCES, FEED_ADAPTER_READS, FEED_KEY_RECORD_SOURCES } from '../src/provider-feed-rules.mjs';
import { feedKeyCustody, custodyOf, clauseCustody, onlyClauseCustody, FEED_KEY_UPGRADE, CUSTODY_REASON } from '../src/custody.mjs';
import { startStub } from '../integrations/observers/fixtures/provider-stub.mjs';
import { digest } from '../src/domain.mjs';

const EXT = 'customers.example', WITNESS = 'witness.scopehaven.invalid', VIP = `vip@${EXT}`;
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const KEY = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const feedConfig = extra => ({ id: 'mail', type: 'provider-feed', feedId: 'mail', feed: { endpoint: { port: 4471, path: '/feed' } }, publicKey: KEY, domains: [{ domain: EXT, addresses: [VIP] }], ...extra });

test('the declaration: keySource is provider, adapter (with adapterReads) or stub, and nothing else; adapterReads only with an adapter', () => {
  assert.deepEqual([FEED_KEY_SOURCES, FEED_ADAPTER_READS, FEED_KEY_RECORD_SOURCES], [['provider', 'adapter', 'stub'], ['provider-api', 'application-store'], ['provider', 'adapter', 'stub', 'undeclared']]);
  for (const extra of [{}, { keySource: 'provider' }, { keySource: 'stub' }, { keySource: 'adapter', adapterReads: 'provider-api' }, { keySource: 'adapter', adapterReads: 'application-store' }]) {
    assert.doesNotThrow(() => validateProviderFeedConfig(feedConfig(extra), {}), JSON.stringify(extra));
  }
  for (const [extra, pattern] of [[{ keySource: 'app' }, /"keySource" says where/], [{ keySource: 'Provider' }, /"keySource" says where/], [{ keySource: null }, /"keySource" says where/], [{ keySource: 1 }, /"keySource" says where/],
    [{ keySource: 'adapter' }, /"adapterReads" goes with/], [{ adapterReads: 'provider-api' }, /"adapterReads" goes with/], [{ keySource: 'provider', adapterReads: 'provider-api' }, /"adapterReads" goes with/],
    [{ keySource: 'adapter', adapterReads: 'api' }, /"adapterReads" is "provider-api"/]]) {
    assert.throws(() => validateProviderFeedConfig(feedConfig(extra), {}), pattern, JSON.stringify(extra));
  }
});

test('the record: keySource is always written ("undeclared" when the profile names none), adapterReads exactly for an adapter; earlier records carry neither', () => {
  assert.deepEqual(providerFeedRecord(feedConfig()).keySource, 'undeclared');
  assert.ok(!Object.hasOwn(providerFeedRecord(feedConfig()), 'adapterReads'));
  assert.deepEqual([providerFeedRecord(feedConfig({ keySource: 'stub' })).keySource, providerFeedRecord(feedConfig({ keySource: 'provider' })).keySource], ['stub', 'provider']);
  const adapter = providerFeedRecord(feedConfig({ keySource: 'adapter', adapterReads: 'application-store' }));
  assert.deepEqual([adapter.keySource, adapter.adapterReads], ['adapter', 'application-store']);
  const base = { feedId: 'mail', keyDigest: '0'.repeat(64), route: 'endpoint' };
  for (const r of [base, { ...base, keySource: 'undeclared' }, { ...base, keySource: 'stub' }, { ...base, keySource: 'adapter', adapterReads: 'provider-api' }, providerFeedRecord(feedConfig({ templates: { a: 't-1' }, outcomes: {} }))]) assert.ok(validProviderFeedRecord(r), JSON.stringify(r));
  for (const r of [{ ...base, keySource: 'app' }, { ...base, adapterReads: 'provider-api' }, { ...base, keySource: 'adapter' }, { ...base, keySource: 'stub', adapterReads: 'provider-api' },
    { ...base, keySource: 'adapter', adapterReads: 'api' }, { ...base, keySource: 'stub', extra: 1 }, { feedId: 'mail', keyDigest: '0'.repeat(64), keySource: 'stub' }]) assert.ok(!validProviderFeedRecord(r), JSON.stringify(r));
});

test('the collector: provider-feed/7 and /8 carry the key source and keep every earlier feed capability; earlier labels stay known', () => {
  assert.equal(COLLECTOR_LABELS['provider-feed'], 'provider-feed/8');
  assert.deepEqual(KEY_SOURCE_LABELS, ['provider-feed/7', 'provider-feed/8']);
  for (const list of [KNOWN_COLLECTOR_LABELS, OUTCOME_COLLECTOR_LABELS, LATER_STAGE_LABELS, TEMPLATE_LIFT_LABELS]) assert.ok(list.includes('provider-feed/8') && list.includes('provider-feed/7') && list.includes('provider-feed/6'));
});

// Synthetic windows, shaped as the connector seals them.
const feedWindow = (feed, events = []) => ({ source: 'provider-feed', instanceId: 'provider-feed-mail', scope: { operations: ['send'], names: [EXT], actorAttribution: 'none', evidence: 'authoritative', ...(feed === undefined ? {} : { feed }) }, coverage: 'complete', reason: null, events });
const record = extra => ({ feedId: 'mail', keyDigest: '0'.repeat(64), route: 'endpoint', ...extra });
const sel = { source: 'provider-feed', operation: 'send', name: EXT };
const sendEvent = { source: 'provider-feed', observer: { kind: 'provider-feed-reader', instanceId: 'provider-feed-mail' }, seq: 128, actor: null, operation: 'send', name: EXT, resource: VIP, outcome: 'committed', correlation: {}, content: {} };

test('custody: the provider\'s export, an adapter of the provider\'s API and a stub keep the key outside the app; an undeclared source or an adapter of the app\'s store does not', () => {
  const cases = [[undefined, 'independent'], [record(), 'independent'], [record({ keySource: 'provider' }), 'independent'], [record({ keySource: 'stub' }), 'independent'],
    [record({ keySource: 'adapter', adapterReads: 'provider-api' }), 'independent'], [record({ keySource: 'adapter', adapterReads: 'application-store' }), 'subject-writable'],
    [record({ keySource: 'undeclared' }), 'subject-writable'], [record({ keySource: 'adapter' }), 'subject-writable'], [record({ keySource: 'other' }), 'subject-writable']];
  for (const [feed, expected] of cases) {
    assert.equal(feedKeyCustody(feed), expected, JSON.stringify(feed));
    assert.equal(custodyOf(feedWindow(feed)), expected, JSON.stringify(feed));
  }
  // Only a provider feed's window reads its key source; a declaration may only lower custody.
  assert.equal(custodyOf({ ...feedWindow(record({ keySource: 'undeclared' })), source: 'http-egress' }), 'independent');
  assert.equal(custodyOf(feedWindow(record({ keySource: 'provider' })), { declared: 'subject-writable' }), 'subject-writable');
  assert.equal(custodyOf({ source: 'provider-feed' }), 'independent', 'a selector\'s source alone (no window record) keeps the lineage custody');
});

test('custody: a boundary absence decided only by a feed whose key the app could hold reads inconclusive and names the declaration; a fail stays a fail', () => {
  const none = { kind: 'effect.none', select: sel, verdict: 'pass' };
  const lowered = clauseCustody({ ...none, windows: [feedWindow(record({ keySource: 'undeclared' }))] });
  assert.deepEqual(lowered, { verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: FEED_KEY_UPGRADE });
  assert.match(FEED_KEY_UPGRADE, /independent only if the key is the provider's own/);
  assert.deepEqual(clauseCustody({ ...none, windows: [feedWindow(record({ keySource: 'adapter', adapterReads: 'application-store' }))] }).verdict, 'inconclusive');
  assert.deepEqual(clauseCustody({ ...none, windows: [feedWindow(record({ keySource: 'provider' }))] }), { verdict: 'pass', custody: 'independent' });
  assert.deepEqual(clauseCustody({ ...none, windows: [feedWindow(record())] }), { verdict: 'pass', custody: 'independent' }, 'a record an earlier build wrote keeps its custody');
  // An allowed-use control keeps its verdict and carries custody as a tag.
  assert.deepEqual(clauseCustody({ ...none, role: 'control', windows: [feedWindow(record({ keySource: 'undeclared' }))] }), { verdict: 'pass', custody: 'subject-writable' });
  // A send the feed recorded still fails the absence, tagged with the custody that decided it.
  assert.deepEqual(clauseCustody({ kind: 'effect.none', select: sel, verdict: 'fail', windows: [feedWindow(record({ keySource: 'undeclared' }), [sendEvent])] }), { verdict: 'fail', custody: 'subject-writable' });
  // effect.only takes the weakest custody of its authoritative windows and names the same declaration.
  const only = onlyClauseCustody({ result: { verdict: 'pass', observers: ['provider-feed-mail'], claimedOperations: ['send'] }, windows: [feedWindow(record({ keySource: 'undeclared' }))] });
  assert.deepEqual(only, { verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: FEED_KEY_UPGRADE });
  assert.deepEqual(onlyClauseCustody({ result: { verdict: 'pass', observers: ['provider-feed-mail'], claimedOperations: ['send'] }, windows: [feedWindow(record({ keySource: 'stub' }))] }), { verdict: 'pass', custody: 'independent' });
});

// A provider feed sees only its own provider's sends, so another observer's silence never covers the route an
// app-held feed was meant to cover. Two feeds (one honest, one the app could sign), or an SMTP sink beside the app-held feed, all naming
// the domain: a boundary absence (effect.none or effect.count) stays inconclusive whatever else decided it.
test('custody: a boundary absence beside a deciding feed whose key the app could hold stays inconclusive, however independent the other windows are', () => {
  const other = (feed, events = []) => ({ ...feedWindow(feed, events), instanceId: 'provider-feed-other' });
  const smtp = { source: 'smtp-capture', instanceId: 'smtp-sink-mail', scope: { operations: ['send'], names: [EXT], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] };
  const unpinned = { operation: 'send', name: EXT };
  const lowered = { verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: FEED_KEY_UPGRADE };
  const none = (select, windows, extra = {}) => clauseCustody({ kind: 'effect.none', select, verdict: 'pass', windows, ...extra });
  // An honest stub feed plus the app's undeclared feed (G-12M), or the app's feed declared truthfully as an adapter of its own store (G-12AM).
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), feedWindow(record({ keySource: 'undeclared' }))]), lowered);
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), feedWindow(record({ keySource: 'adapter', adapterReads: 'application-store' }))]), lowered);
  // An SMTP sink beside the app's feed, on a select both see.
  assert.deepEqual(none(unpinned, [smtp, feedWindow(record({ keySource: 'undeclared' }))]), lowered);
  // effect.count is an absence claim too.
  assert.deepEqual(clauseCustody({ kind: 'effect.count', select: sel, verdict: 'pass', windows: [other(record({ keySource: 'stub' })), feedWindow(record({ keySource: 'undeclared' }))] }), lowered);
  // Unchanged: two held keys pass; the app's feed that cannot see the select decides nothing; a presence pass rests on the window that
  // recorded the send; an allowed-use control keeps its verdict; a send recorded still fails.
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), feedWindow(record({ keySource: 'provider' }))]), { verdict: 'pass', custody: 'independent' });
  const elsewhere = { ...feedWindow(record({ keySource: 'undeclared' })), scope: { ...feedWindow(record()).scope, names: ['other.example'], feed: record({ keySource: 'undeclared' }) } };
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), elsewhere]), { verdict: 'pass', custody: 'independent' }, 'a window that cannot see the select is not deciding');
  assert.deepEqual(clauseCustody({ kind: 'effect.exists', select: sel, verdict: 'pass', windows: [other(record({ keySource: 'stub' }), [{ ...sendEvent, observer: { ...sendEvent.observer, instanceId: 'provider-feed-other' } }]), feedWindow(record({ keySource: 'undeclared' }))] }), { verdict: 'pass', custody: 'independent' });
  // A presence pass recorded by both feeds rests on the honest one; recorded only by the app's feed, it stays inconclusive and names the declaration.
  const exists = windows => clauseCustody({ kind: 'effect.exists', select: sel, verdict: 'pass', windows });
  assert.deepEqual(exists([other(record({ keySource: 'stub' }), [sendEvent]), feedWindow(record({ keySource: 'undeclared' }), [sendEvent])]), { verdict: 'pass', custody: 'independent' });
  assert.deepEqual(exists([other(record({ keySource: 'stub' })), feedWindow(record({ keySource: 'undeclared' }), [sendEvent])]), lowered);
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), feedWindow(record({ keySource: 'undeclared' }))], { role: 'control' }), { verdict: 'pass', custody: 'independent' });
  assert.deepEqual(clauseCustody({ kind: 'effect.none', select: sel, verdict: 'fail', windows: [other(record({ keySource: 'stub' }), [sendEvent]), feedWindow(record({ keySource: 'undeclared' }))] }).verdict, 'fail');
  assert.deepEqual(clauseCustody({ kind: 'effect.count', select: sel, verdict: 'fail', windows: [other(record({ keySource: 'stub' })), feedWindow(record({ keySource: 'undeclared' }))] }).verdict, 'fail', 'a count that fails is never lifted to inconclusive');
});

// A presence-only feed (an export file, or an endpoint without a witness) never decides an absence, but an honest
// one would have shown the send, so one whose key the app could hold keeps the absence inconclusive whenever it sees the select.
test('custody: a feed whose key the app could hold keeps a boundary absence inconclusive when it sees the select, even presence-only', () => {
  const other = (feed, events = []) => ({ ...feedWindow(feed, events), instanceId: 'provider-feed-other' });
  const presence = (feed, events = []) => { const w = feedWindow(feed, events); return { ...w, scope: { ...w.scope, evidence: 'presence-only' } }; };
  const smtp = { source: 'smtp-capture', instanceId: 'smtp-sink-mail', scope: { operations: ['send'], names: [EXT], actorAttribution: 'none', evidence: 'authoritative' }, coverage: 'complete', reason: null, events: [] };
  const unpinned = { operation: 'send', name: EXT };
  const lowered = { verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: FEED_KEY_UPGRADE };
  const none = (select, windows, extra = {}) => clauseCustody({ kind: 'effect.none', select, verdict: 'pass', windows, ...extra });
  const file = extra => record({ route: 'file', ...extra });
  // Three cases: an app-store adapter's export file beside an SMTP sink; an undeclared export file beside an honest stub
  // feed; an undeclared endpoint feed without a witness beside it. The tag is the weakest custody of the deciding and the lowered windows.
  assert.deepEqual(none(unpinned, [smtp, presence(file({ keySource: 'adapter', adapterReads: 'application-store' }))]), lowered);
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), presence(file({ keySource: 'undeclared' }))]), lowered);
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), presence(record({ keySource: 'undeclared' }))]), lowered);
  assert.deepEqual(clauseCustody({ kind: 'effect.count', select: sel, verdict: 'pass', windows: [other(record({ keySource: 'stub' })), presence(file({ keySource: 'undeclared' }))] }), lowered);
  // Unchanged: a presence-only feed declared held outside the app; one whose names miss the select; a clause pinned to another observer's
  // source; a malformed window (no operations), which sees nothing and throws nothing; a control; a fail; a presence pass.
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), presence(file({ keySource: 'stub' }))]), { verdict: 'pass', custody: 'independent' });
  const elsewhere = presence(file({ keySource: 'undeclared' })); elsewhere.scope = { ...elsewhere.scope, names: ['other.example'] };
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), elsewhere]), { verdict: 'pass', custody: 'independent' }, 'a feed whose names miss the select does not see it');
  assert.deepEqual(none({ source: 'smtp-capture', operation: 'send', name: EXT }, [smtp, presence(file({ keySource: 'undeclared' }))]), { verdict: 'pass', custody: 'independent' }, 'a clause pinned to the sink is not one the feed sees');
  const malformed = presence(file({ keySource: 'undeclared' })); malformed.scope = { names: [EXT], evidence: 'presence-only', feed: file({ keySource: 'undeclared' }) };
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), malformed]), { verdict: 'pass', custody: 'independent' }, 'a malformed window sees nothing');
  assert.deepEqual(none(sel, [other(record({ keySource: 'stub' })), presence(file({ keySource: 'undeclared' }))], { role: 'control' }), { verdict: 'pass', custody: 'independent' });
  assert.equal(clauseCustody({ kind: 'effect.none', select: sel, verdict: 'fail', windows: [other(record({ keySource: 'stub' })), presence(file({ keySource: 'undeclared' }), [sendEvent])] }).verdict, 'fail');
  assert.deepEqual(clauseCustody({ kind: 'effect.exists', select: sel, verdict: 'pass', windows: [other(record({ keySource: 'stub' }), [{ ...sendEvent, observer: { ...sendEvent.observer, instanceId: 'provider-feed-other' } }]), presence(file({ keySource: 'undeclared' }))] }), { verdict: 'pass', custody: 'independent' });
});

// effect.only: the same promise for "nothing but these happened". Its pass took the weakest custody of the
// authoritative windows only, so an app-held presence-only feed among the judged observers left the pass to the others.
test('custody: an effect.only pass that judges a feed whose key the app could hold reads inconclusive, presence-only included; a fail stays a fail', () => {
  const a = { ...feedWindow(record({ keySource: 'stub' })), instanceId: 'provider-feed-a' };
  const b = (keySource, evidence, events = []) => { const w = feedWindow(record({ route: evidence === 'authoritative' ? 'endpoint' : 'file', keySource }), events); return { ...w, instanceId: 'provider-feed-b', scope: { ...w.scope, evidence } }; };
  const only = (windows, extra = {}, role = 'boundary') => onlyClauseCustody({ result: { verdict: 'pass', observers: windows.map(w => w.instanceId), claimedOperations: ['send'], ...extra }, windows, role });
  const lowered = { verdict: 'inconclusive', custody: 'subject-writable', custodyReason: CUSTODY_REASON, custodyUpgrade: FEED_KEY_UPGRADE };
  // A stub plus B's undeclared export file (presence-only), or B's file declared an adapter of the app's own store; and B authoritative,
  // which already read inconclusive and still does.
  assert.deepEqual(only([a, b('undeclared', 'presence-only')]), lowered);
  assert.deepEqual(only([a, b('adapter', 'presence-only')]), lowered, 'an adapter without adapterReads provider-api is a key the app could hold');
  assert.deepEqual(only([a, b('undeclared', 'authoritative')]), lowered);
  // Unchanged: B's file declared a stub's; B not among the judged observers (another source, say); a control; a fail, honest or app-held.
  assert.deepEqual(only([a, b('stub', 'presence-only')]), { verdict: 'pass', custody: 'independent' });
  assert.deepEqual(onlyClauseCustody({ result: { verdict: 'pass', observers: ['provider-feed-a'], claimedOperations: ['send'] }, windows: [a, b('undeclared', 'presence-only')] }), { verdict: 'pass', custody: 'independent' }, 'a feed the clause does not judge is not in scope');
  assert.deepEqual(only([a, b('undeclared', 'presence-only')], {}, 'control'), { verdict: 'pass', custody: 'independent' });
  const offendedBy = id => ({ verdict: 'fail', offendingObservers: [{ source: 'provider-feed', observer: id }] });
  assert.deepEqual(only([a, b('stub', 'presence-only', [sendEvent])], offendedBy('provider-feed-b')), { verdict: 'fail', custody: 'independent' }, 'an honest B that shows the send fails the clause');
  assert.deepEqual(only([a, b('undeclared', 'presence-only', [sendEvent])], offendedBy('provider-feed-b')), { verdict: 'fail', custody: 'subject-writable' }, 'a send an app-held feed shows still fails');
});

// End to end: a mail app whose vendor SDK sends straight to its provider (the signed provider stub here).
async function mailApp(t, stub) {
  const server = createServer((req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return send(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return send(200, { user: 'ops' });
    if (url.pathname === '/ping') { stub.accept([`${url.searchParams.get('scopehaven_witness')}@${WITNESS}`]); return send(200, { ok: true }); }
    if (url.pathname === '/notify') { stub.accept([VIP]); return send(200, { ok: true }); }
    if (url.pathname === '/noop') return send(200, { ok: true });
    return send(404, {});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const check = (id, path, effects, severity = 'high') => ({ id, title: id, category: 'mail', severity, actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects });
const pinned = { source: 'provider-feed', operation: 'send', name: EXT, resource: VIP };
async function run(t, feedExtra) {
  const stub = await startStub(t);
  const p = { id: 'mail', name: 'Mail', applicationId: 'mail', origin: await mailApp(t, stub), buildLabel: 'b1', contextId: 'synthetic-mail',
    actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'SENDS'],
    observers: [{ id: 'mail', type: 'provider-feed', feedId: stub.feedId, feed: { endpoint: { port: stub.port, path: stub.path } }, publicKey: stub.publicKey,
      domains: [{ domain: EXT, addresses: [VIP] }], routing: 'provider', witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: WITNESS }, witnessWaitMs: 2000, quietMs: 300, pollMs: 25, settleMs: 250, ...feedExtra }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
      check('SENDS', '/notify', [{ kind: 'effect.exists', select: pinned }], 'control'), check('CLEAN', '/noop', [{ kind: 'effect.none', select: pinned }])] };
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return runHttpAssessment(p, { env });
}
const clause = (r, id) => r.results.find(x => x.id === id).trace[1].data.effects[0];
const feedWindowsOf = r => r.results.flatMap(x => x.trace?.[1]?.data?.windows ?? []).filter(w => w.source === 'provider-feed');

test('end to end: an undeclared feed key leaves a clean check inconclusive; a declared stub passes it; both runs carry the key source and validate', async t => {
  const undeclared = await run(t, {});
  assert.deepEqual([undeclared.results.find(x => x.id === 'SENDS').status, undeclared.results.find(x => x.id === 'CLEAN').status], ['pass', 'inconclusive']);
  assert.deepEqual([clause(undeclared, 'CLEAN').custody, clause(undeclared, 'CLEAN').custodyReason, clause(undeclared, 'CLEAN').custodyUpgrade], ['subject-writable', CUSTODY_REASON, FEED_KEY_UPGRADE]);
  assert.equal(undeclared.observers[0].feed.keySource, 'undeclared');
  assert.equal(undeclared.observers[0].collector.label, 'provider-feed/8');
  assert.ok(feedWindowsOf(undeclared).length > 0 && feedWindowsOf(undeclared).every(w => w.scope.feed.keySource === 'undeclared'));
  validateHttpRunEvidence(undeclared);

  const stub = await run(t, { keySource: 'stub' });
  assert.equal(stub.results.find(x => x.id === 'CLEAN').status, 'pass');
  assert.equal(clause(stub, 'CLEAN').custody, 'independent');
  assert.deepEqual(stub.observers[0].feed, { ...stub.observers[0].feed, keySource: 'stub' });
  assert.ok(feedWindowsOf(stub).every(w => w.scope.feed.keySource === 'stub'), 'the observer\'s own windows name the declared source (the factory passes it)');
  validateHttpRunEvidence(stub);

  const appStore = await run(t, { keySource: 'adapter', adapterReads: 'application-store' });
  assert.equal(appStore.results.find(x => x.id === 'CLEAN').status, 'inconclusive');
  assert.deepEqual([appStore.observers[0].feed.keySource, appStore.observers[0].feed.adapterReads], ['adapter', 'application-store']);
  validateHttpRunEvidence(appStore);

  // The validator: a provider-feed/7 record may not drop its key source, in its record or in its windows; a window naming another
  // source than its record is refused; and a record and windows rewritten together to a held key re-derive a pass the sealed run lacks.
  // Every feed record the run seals (its observer record, its check windows and its settlement windows) loses its key source, and each
  // row's evidence digest is sealed again, as a consistent editor would: only the label rule can refuse the result.
  const reseal = r => { for (const x of r.results) if (x.trace[1]) x.evidenceDigest = digest({ evidence: x.trace[0].data, effects: x.trace[1].data, assertions: x.assertions }); return r; };
  const strip = r => { const c = structuredClone(r); const walk = v => { if (v && typeof v === 'object') { if (typeof v.keyDigest === 'string' && Object.hasOwn(v, 'keySource')) delete v.keySource; Object.values(v).forEach(walk); } }; walk(c); return reseal(c); };
  assert.throws(() => validateHttpRunEvidence(strip(stub)), e => e.code === 'invalid-run-evidence');
  const relabelled = strip(stub); relabelled.observers[0].collector = { ...relabelled.observers[0].collector, label: 'provider-feed/6' };
  assert.doesNotThrow(() => validateHttpRunEvidence(relabelled), 'an earlier build\'s record (no key source, provider-feed/6) still validates');
  const window = structuredClone(undeclared); for (const w of feedWindowsOf(window)) w.scope.feed.keySource = 'provider';
  assert.throws(() => validateHttpRunEvidence(reseal(window)), e => e.code === 'invalid-run-evidence' && e.detail === 'effect-trace');
  const rewrite = (r, keySource) => { const c = structuredClone(r); const walk = v => { if (v && typeof v === 'object') { if (typeof v.keyDigest === 'string' && Object.hasOwn(v, 'keySource')) v.keySource = keySource; Object.values(v).forEach(walk); } }; walk(c); return reseal(c); };
  // The same rewrite to "stub" everywhere is refused only because the clause it decides now re-derives a pass the sealed row lacks.
  assert.throws(() => validateHttpRunEvidence(rewrite(undeclared, 'stub')), e => e.code === 'invalid-run-evidence');
  assert.doesNotThrow(() => validateHttpRunEvidence(rewrite(undeclared, 'undeclared')), 'the rewrite helper alone changes nothing');

  // A comparison refuses a run sealed under the earlier collector identity.
  const comparison = compareRuns(relabelled, stub);
  assert.equal(comparison.compatible, false);
  assert.ok(comparison.reasons.includes('Declared effects, evidence requirements or observers differ between the runs.'), comparison.reasons.join(' | '));
  assert.equal(COLLECTOR_RECORDS['provider-feed'].label, 'provider-feed/8');
});

// End to end: an app that mails through two vendors. Vendor A is the honest stub (declared "stub"); vendor B's feed
// is one the app could sign itself, played by a second stub whose feed simply omits what the app sends through it. The check's forbidden
// send goes through B, so neither feed records it: in an earlier build both feeds' silence passed CLEAN, and B's key is what that pass rested on.
test('end to end: an honest second feed does not lend its independence to a clean check that an app-held feed decides', async t => {
  const a = await startStub(t, { feedId: 'vendor-a' }), b = await startStub(t, { feedId: 'vendor-b' });
  const server = createServer((req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return send(401, {});
    const url = new URL(req.url, 'http://127.0.0.1'), witness = `${url.searchParams.get('scopehaven_witness')}@${WITNESS}`;
    if (url.pathname === '/me') return send(200, { user: 'ops' });
    if (url.pathname === '/ping-a') { a.accept([witness]); return send(200, { ok: true }); }
    if (url.pathname === '/ping-b') { b.accept([witness]); return send(200, { ok: true }); }
    if (url.pathname === '/notify') { a.accept([VIP]); return send(200, { ok: true }); }
    if (url.pathname === '/noop') return send(200, { ok: true }); // the app mails VIP through vendor B, whose feed leaves it out
    return send(404, {});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const feed = (id, stub, path, extra) => ({ id, type: 'provider-feed', feedId: stub.feedId, feed: { endpoint: { port: stub.port, path: stub.path } }, publicKey: stub.publicKey,
    domains: [{ domain: EXT, addresses: [VIP] }], routing: 'provider', witness: { actorId: 'ops', method: 'GET', path, domain: WITNESS }, witnessWaitMs: 2000, quietMs: 300, pollMs: 25, settleMs: 250, ...extra });
  const runWith = async bExtra => {
    const p = { id: 'mail2', name: 'Mail, two vendors', applicationId: 'mail2', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'b1', contextId: 'synthetic-mail',
      actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'SENDS'],
      observers: [feed('a', a, '/ping-a', { keySource: 'stub' }), feed('b', b, '/ping-b', bExtra)],
      checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
        check('SENDS', '/notify', [{ kind: 'effect.exists', select: pinned }], 'control'), check('CLEAN', '/noop', [{ kind: 'effect.none', select: pinned }])] };
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    const r = await runHttpAssessment(p, { env });
    validateHttpRunEvidence(r);
    return r;
  };
  const cleanWindows = r => r.results.find(x => x.id === 'CLEAN').trace[1].data.windows.filter(w => w.source === 'provider-feed').map(w => [w.instanceId, w.coverage, w.scope.feed.keySource]);
  // B undeclared (G-12M) or declared truthfully as an adapter of the app's own store (G-12AM): both feeds covered the window and recorded
  // nothing, and the clean check stays inconclusive on B's key.
  for (const bExtra of [{}, { keySource: 'adapter', adapterReads: 'application-store' }]) {
    const r = await runWith(bExtra);
    assert.equal(r.results.find(x => x.id === 'SENDS').status, 'pass');
    assert.deepEqual(cleanWindows(r), [['provider-feed-a', 'complete', 'stub'], ['provider-feed-b', 'complete', bExtra.keySource ?? 'undeclared']]);
    assert.equal(r.results.find(x => x.id === 'CLEAN').status, 'inconclusive', JSON.stringify(bExtra));
    assert.deepEqual([clause(r, 'CLEAN').custody, clause(r, 'CLEAN').custodyReason, clause(r, 'CLEAN').custodyUpgrade], ['subject-writable', CUSTODY_REASON, FEED_KEY_UPGRADE]);
  }
  // Both keys declared held outside the app: the clean check passes (a false declaration here is the G-12P residual SECURITY.md names).
  const held = await runWith({ keySource: 'stub' });
  assert.deepEqual([held.results.find(x => x.id === 'CLEAN').status, clause(held, 'CLEAN').custody], ['pass', 'independent']);
});

// End to end, presence-only: vendor B's feed is an export file (presence-only, so it never decides an absence) that the app could
// write, played by a stub journal that leaves out what the app sends through B. In an earlier build vendor A's silence passed CLEAN.
test('end to end: an app-held export-file feed that cannot decide still keeps an honest vendor\'s silence from passing a clean check or an effect.only', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'sh-feed-file-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const a = await startStub(t, { feedId: 'vendor-a' }), b = await startStub(t, { feedId: 'vendor-b', journal: join(dir, 'vendor-b.jsonl') });
  const server = createServer((req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return send(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return send(200, { user: 'ops' });
    if (url.pathname === '/ping-a') { a.accept([`${url.searchParams.get('scopehaven_witness')}@${WITNESS}`]); return send(200, { ok: true }); }
    if (url.pathname === '/notify') { a.accept([VIP]); return send(200, { ok: true }); }
    if (url.pathname === '/noop') return send(200, { ok: true }); // the app mails VIP through vendor B, whose file leaves it out
    return send(404, {});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const runWith = async bExtra => {
    const p = { id: 'mail3', name: 'Mail, vendor B by export file', applicationId: 'mail3', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'b1', contextId: 'synthetic-mail',
      actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI', 'SENDS'],
      observers: [{ id: 'a', type: 'provider-feed', feedId: a.feedId, feed: { endpoint: { port: a.port, path: a.path } }, publicKey: a.publicKey, domains: [{ domain: EXT, addresses: [VIP] }],
        routing: 'provider', witness: { actorId: 'ops', method: 'GET', path: '/ping-a', domain: WITNESS }, witnessWaitMs: 2000, quietMs: 300, pollMs: 25, settleMs: 250, keySource: 'stub' },
      { id: 'b', type: 'provider-feed', feedId: b.feedId, feed: { file: { path: join(dir, 'vendor-b.jsonl') } }, publicKey: b.publicKey, domains: [{ domain: EXT, addresses: [VIP] }], settleMs: 250, ...bExtra }],
      checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
        check('SENDS', '/notify', [{ kind: 'effect.exists', select: pinned }], 'control'), check('CLEAN', '/noop', [{ kind: 'effect.none', select: pinned }]),
        check('ONLY', '/noop', [{ kind: 'effect.only', allow: [], operations: ['send'] }])] };
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    const r = await runHttpAssessment(p, { env });
    validateHttpRunEvidence(r);
    return r;
  };
  const cleanWindows = r => r.results.find(x => x.id === 'CLEAN').trace[1].data.windows.filter(w => w.source === 'provider-feed').map(w => [w.instanceId, w.scope.evidence, w.scope.feed.route, w.scope.feed.keySource]);
  const status = (r, id) => r.results.find(x => x.id === id).status;
  // B undeclared, or declared truthfully as an adapter that exports the app's own store: CLEAN stays inconclusive on B's key.
  for (const bExtra of [{}, { keySource: 'adapter', adapterReads: 'application-store' }]) {
    const r = await runWith(bExtra);
    assert.equal(r.results.find(x => x.id === 'SENDS').status, 'pass');
    assert.deepEqual(cleanWindows(r), [['provider-feed-a', 'authoritative', 'endpoint', 'stub'], ['provider-feed-b', 'presence-only', 'file', bExtra.keySource ?? 'undeclared']]);
    assert.equal(r.results.find(x => x.id === 'CLEAN').status, 'inconclusive', JSON.stringify(bExtra));
    assert.deepEqual([clause(r, 'CLEAN').custody, clause(r, 'CLEAN').custodyReason, clause(r, 'CLEAN').custodyUpgrade], ['subject-writable', CUSTODY_REASON, FEED_KEY_UPGRADE]);
    assert.deepEqual([status(r, 'ONLY'), clause(r, 'ONLY').custody, clause(r, 'ONLY').custodyUpgrade], ['inconclusive', 'subject-writable', FEED_KEY_UPGRADE], `effect.only ${JSON.stringify(bExtra)}`);
  }
  // B's file declared a stub's: CLEAN and ONLY pass on vendor A's witnessed silence.
  const held = await runWith({ keySource: 'stub' });
  assert.deepEqual([held.results.find(x => x.id === 'CLEAN').status, clause(held, 'CLEAN').custody], ['pass', 'independent']);
  assert.deepEqual([status(held, 'ONLY'), clause(held, 'ONLY').custody], ['pass', 'independent']);
});
