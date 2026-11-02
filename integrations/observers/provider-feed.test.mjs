// Provider-feed observer, over a real loopback stub and a real journal file: each allowed outcome next to the
// forbidden one beside it. Every request goes to 127.0.0.1; recipient domains are names only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, appendFileSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSync } from 'node:crypto';
import { createProviderFeedObserver, PROVIDER_FEED_LIMITS } from './provider-feed.mjs';
import { mailboxOf } from '../../src/mail-address.mjs';
import { startStub, signEntry, publicKeyOf } from './fixtures/provider-stub.mjs';
import { collectWindow, evaluateEffectAssertion } from './events.mjs';
import { buildObservers } from './factory.mjs';
import { validateProviderFeedConfig, providerFeedClash } from '../../src/provider-feed-rules.mjs';
import { custodyOf } from '../../src/custody.mjs';
import { judgeOnly, onlyScopedComplete } from '../collateral/only.mjs';
import { drainersOf, validDrains } from '../../src/run-end-drain.mjs';
import { admitScoped, admitTemplateLift, FEED_LATE_CODE } from '../../src/effect-events.mjs';
import { decideEffects } from '../../src/http-effects.mjs';
import { contactedEndpoints } from '../roe/authorization.mjs';

const EXT = 'customers.example', IDN = 'xn--bcher-kva.example', WITNESS = 'witness.scopehaven.invalid', VIP = `vip@${EXT}`;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const feedOf = (stub, extra = {}) => ({ feedId: stub.feedId, feed: { endpoint: { port: stub.port, path: stub.path } }, publicKey: stub.publicKey,
  domains: [{ domain: EXT, addresses: [VIP] }, { domain: IDN, addresses: [`vip@${IDN}`] }], routing: 'provider', witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: WITNESS },
  witnessWaitMs: 1500, quietMs: 150, pollMs: 25, ...extra });
const fileFeedOf = (stub, path) => { const { routing, witness, ...rest } = feedOf(stub); return { ...rest, feed: { file: { path } } }; };
const observe = async (t, config) => { const o = createProviderFeedObserver({ instanceId: 'provider-feed-mail', ...config }); await o.start(); t.after(() => o.stop()); return o; };
// start() of an observer that must not start; stopped after the test either way.
const startOf = (t, config) => { const o = createProviderFeedObserver(config); t.after(() => o.stop()); return o.start(); };
// One check window as the connector runs it: start mark, the check, the witness request marked (awaited, with the
// signed-head split), the app's witness mail through the provider, the end mark, then collect.
async function windowOf(o, stub, between = async () => {}, { witness = true } = {}) {
  const from = await o.mark();
  await sleep(5); // a send is never stamped in the start mark's own millisecond (the file route's bound is strict)
  await between(from);
  if (o.witnessRequest) await o.markWitnessRequest(from, { headSplit: true });
  if (witness && o.witnessRequest) stub.accept([`${from.witnessNonce}@${WITNESS}`]);
  return collectWindow(o, from, await o.mark());
}
const sel = extra => ({ source: 'provider-feed', operation: 'send', name: EXT, ...extra });
const verdict = (kind, select, windows) => evaluateEffectAssertion({ kind, select }, windows).verdict;
const gapOf = (o, from, to) => collectWindow({ source: o.source, instanceId: o.instanceId, scope: o.scope, collect: (a, b) => o.collect(a, b, { gap: true }) }, from, to);
const tmpFile = t => { const dir = mkdtempSync(join(tmpdir(), 'provider feed ')); t.after(() => rmSync(dir, { recursive: true, force: true })); return join(dir, 'feed.jsonl'); };

test('a signed acceptance in the window is a committed send by recipient domain; one accepted before the start mark is not in it', async t => {
  const stub = await startStub(t);
  // A slow poller: only the signed head and the read in mark() keep the earlier acceptance out of the window.
  const o = await observe(t, feedOf(stub, { pollMs: 500, quietMs: 1000 }));
  stub.accept([`other@${EXT}`]);
  const w = await windowOf(o, stub, async () => { stub.accept([VIP, `x@${EXT}`], { subject: 'Refund of 25 CAD for card 4242' }); });
  assert.deepEqual([w.coverage, w.reason], ['complete', null]);
  assert.deepEqual(w.events.map(e => [e.source, e.operation, e.name, e.resource, e.outcome, e.actor]), [['provider-feed', 'send', EXT, VIP, 'committed', null], ['provider-feed', 'send', EXT, '*', 'committed', null]]);
  assert.ok(!JSON.stringify(w).includes('Refund of 25') && !JSON.stringify(w).includes('x@customers'), 'subjects and undeclared addresses are digested, never stored');
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w]), 'pass');
  assert.equal(verdict('effect.exists', sel({ resource: `other@${EXT}` }), [w]), 'fail', 'the acceptance before the start mark is not this window\'s');
  // The feed declares no key source, so its window names it "undeclared" and custody cannot count the key as held outside the app
  // (`keySource`, provider-feed/7); the same stub declared as one keeps its windows independent.
  assert.equal(custodyOf(w), 'subject-writable');
  assert.deepEqual(Object.keys(w.scope.feed), ['feedId', 'keyDigest', 'route', 'keySource']);
  assert.equal(w.scope.feed.keySource, 'undeclared');
  assert.equal(custodyOf({ ...w, scope: { ...w.scope, feed: { ...w.scope.feed, keySource: 'stub' } } }), 'independent');
  assert.deepEqual([w.scope.feed.feedId, w.scope.feed.route], [stub.feedId, 'endpoint']);
  assert.match(w.scope.feed.keyDigest, /^[a-f0-9]{64}$/);
});

test('absence passes only on a proven feed; a seq gap before the witness leaves it partial (missing)', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const clean = await windowOf(o, stub);
  assert.deepEqual([clean.coverage, clean.reason], ['complete', null]);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [clean]), 'pass');
  // The app sends and the entry is deleted at the stub before the observer reads it: nothing past the gap is read.
  const gapped = await windowOf(o, stub, async () => { const e = stub.accept([VIP]); stub.remove(JSON.parse(e.body).seq); });
  assert.equal(gapped.coverage, 'partial');
  assert.match(gapped.reason, /provider-feed-entry-seq-gap/);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [gapped]), 'missing');
});

test('route (ii): a stub-signed export file can show a send; lines anyone else signed fail the window; it never proves absence', async t => {
  const path = tmpFile(t);
  const stub = await startStub(t, { journal: path });
  const o = await observe(t, fileFeedOf(stub, path));
  assert.deepEqual([o.scope.evidence, o.witnessRequest, o.scope.feed.route], ['presence-only', undefined, 'file']);
  const w = await windowOf(o, stub, async () => { stub.accept([VIP]); });
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w]), 'pass');
  // A file the app may write could lose a line not yet read: absence and counts from it are never decided.
  const clean = await windowOf(o, stub);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [clean]), 'unobservable');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.count', select: sel({ resource: VIP }), expected: 0 }, [clean]).verdict, 'unobservable');
  // The app appends a look-alike acceptance signed with its own key, with the next seq of the real epoch.
  const app = generateKeyPairSync('ed25519');
  const forged = await windowOf(o, stub, async () => {
    const seq = stub.entries.length + 1;
    appendFileSync(path, `${JSON.stringify(signEntry({ feed: stub.feedId, epoch: stub.epoch, seq, id: 'evt_forged', type: 'accepted', at: new Date().toISOString(), messageId: 'msg_forged', recipients: [VIP] }, app.privateKey))}\n`);
  });
  assert.deepEqual([forged.coverage, forged.reason, forged.events.length], ['failed', 'provider-feed-integrity', 0]);
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [forged]) === 'pass', false);
  // A whole look-alike file: no genesis signed by the stub's key, so the observer never starts.
  const lookalike = tmpFile(t), appStub = await startStub(t, { journal: lookalike });
  appStub.accept([VIP]);
  await assert.rejects(startOf(t, fileFeedOf(stub, lookalike)), /provider-feed-entry-signature/);
  // A file feed cannot declare a witness in v1.
  assert.throws(() => createProviderFeedObserver({ ...feedOf(stub), feed: { file: { path } } }), /presence-only in v1/);
});

test('an entry of another epoch under the same key, fresh and next in seq, is an integrity fault: the window fails', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const w = await windowOf(o, stub, async () => {
    stub.append({ type: 'accepted', messageId: 'msg_other_epoch', recipients: [VIP] }, { epoch: 'another-epoch-of-this-key' });
  });
  assert.deepEqual([w.coverage, w.reason, w.events.length], ['failed', 'provider-feed-integrity', 0]);
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w]) === 'pass', false);
});

test('the feed is anchored at a signed genesis; a feed without one never starts, and a stub reset fails every later window', async t => {
  const empty = await startStub(t, { genesis: false });
  await assert.rejects(startOf(t, feedOf(empty)), /provider-feed/);
  // A feed whose seq 1 is an ordinary acceptance has no anchor: it never starts.
  const headless = await startStub(t, { genesis: false });
  headless.accept([VIP]);
  await assert.rejects(startOf(t, feedOf(headless)), /provider-feed-genesis-missing/);
  // A prohibited send, then a reset before the next read, then the witness in the new epoch.
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const w = await windowOf(o, stub, async () => { stub.accept([VIP]); stub.reset(); });
  assert.equal(w.coverage, 'failed');
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [w]) === 'pass', false);
  const later = await windowOf(o, stub);
  assert.equal(later.coverage, 'failed', 'a faulted feed never proves anything again');
});

test('the signed head: a stale, unsigned or backward head is an integrity fault; one that cannot be fetched fails the mark', async t => {
  // A head signed for another nonce, a forged signature, a head one seq behind what was read (same epoch), and an entry's
  // own signed object served as a head (the signatures are domain-separated).
  for (const mode of ['stale', 'unsigned', 'behind', 'entry-as-head', 'entry-prefix-head']) {
    const stub = await startStub(t);
    const o = await observe(t, feedOf(stub));
    // Two entries read first, so a head one seq behind is still a valid seq (2 of 3).
    stub.accept([`a@${EXT}`]); stub.accept([`b@${EXT}`]);
    assert.equal((await o.mark()).headSeq, 3, mode);
    stub.control.headMode = mode;
    const w = await windowOf(o, stub, async () => { stub.accept([VIP]); });
    assert.deepEqual([w.coverage, w.reason], ['failed', 'provider-feed-integrity'], mode);
    assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w]) === 'pass', false, mode);
  }
  const reset = await startStub(t);
  const r = await observe(t, feedOf(reset));
  reset.accept([VIP]); reset.accept([VIP], { messageId: 'msg_b' });
  assert.equal((await r.mark()).ok, true);
  reset.reset(); // the head now names another epoch and a lower seq
  assert.equal((await r.mark()).ok, false, 'a faulted feed never marks ok again');
  const missing = await startStub(t);
  const m = await observe(t, feedOf(missing));
  missing.control.headMode = 'missing';
  await assert.rejects(m.mark(), /provider-feed-catch-up-failed/);
});

test('a stalled feed: a window without a witness (a gap, the tail) reads partial while entries up to the signed head are unread', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const from = await o.mark();
  await o.markWitnessRequest(from, { headSplit: true });
  stub.accept([`${from.witnessNonce}@${WITNESS}`]);
  const end = await o.mark();
  assert.equal((await collectWindow(o, from, end)).coverage, 'complete');
  // The stub stops serving entries, a late forbidden send lands, and the run-end mark is taken.
  stub.stall(); stub.accept([VIP]);
  const tail = await o.mark();
  assert.equal(tail.behind, true);
  const gap = await gapOf(o, end, tail);
  assert.equal(gap.coverage, 'partial');
  assert.match(gap.reason, /provider-feed-head-unread/);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [gap]), 'missing');
});

test('types are an allowlist: an unknown type or a status of an unknown message is partial; a status of an accepted one is no effect', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const delivered = await windowOf(o, stub, async () => { const e = stub.accept([VIP]); stub.status(JSON.parse(e.body).messageId); });
  assert.deepEqual([delivered.coverage, delivered.events.length], ['complete', 1]);
  const unknown = await windowOf(o, stub, async () => { stub.append({ type: 'scheduled', messageId: 'msg_s', recipients: [VIP] }); });
  assert.match(unknown.reason, /provider-feed-type-unknown-entry/);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [unknown]), 'missing');
  const orphan = await windowOf(o, stub, async () => { stub.status('msg_never_accepted'); });
  assert.match(orphan.reason, /provider-feed-status-orphan-entry/);
});

test('duplicates: a repeated event id, message id or recipient is partial and never skipped', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const redelivered = await windowOf(o, stub, async () => { const e = stub.accept([VIP]); stub.redeliver(JSON.parse(e.body).seq); });
  assert.match(redelivered.reason, /provider-feed-duplicate-id-entry/);
  assert.equal(redelivered.events.length, 2, 'both are kept');
  const twice = await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_twice' }); stub.accept([`x@${EXT}`], { messageId: 'msg_twice' }); });
  assert.match(twice.reason, /provider-feed-duplicate-message-entry/);
  const repeated = await windowOf(o, stub, async () => { stub.accept([VIP, 'VIP@customers.example']); });
  assert.match(repeated.reason, /provider-feed-recipient-repeated/);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [repeated]), 'fail');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.count', select: sel({ resource: VIP }), expected: 2 }, [repeated]).verdict, 'missing');
});

test('recipient forms: uppercase, a trailing dot and a U-label reach the declared address; a source route or an unparsable one is partial', async t => {
  // The address rules themselves are tested in test/mail-address.test.mjs; here, what the observer does with them.
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const forms = await windowOf(o, stub, async () => { stub.accept(['VIP@Customers.Example.']); stub.accept(['vip@bücher.example']); });
  assert.deepEqual([forms.coverage, forms.events.map(e => [e.name, e.resource])], ['complete', [[EXT, VIP], [IDN, `vip@${IDN}`]]]);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [forms]), 'fail');
  assert.equal(verdict('effect.none', { ...sel({ resource: `vip@${IDN}` }), name: IDN }, [forms]), 'fail');
  const routed = await windowOf(o, stub, async () => { stub.accept(['@relay.example:vip@customers.example']); });
  // A source route is dropped, as the SMTP sink does: the send is to the declared address (a fail), and the feed's
  // window is partial besides.
  assert.match(routed.reason, /provider-feed-recipient-unusable/);
  assert.deepEqual(routed.events.map(e => e.resource), [VIP]);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [routed]), 'fail');
  const literal = await windowOf(o, stub, async () => { stub.accept(['vip@[192.0.2.1]']); });
  assert.match(literal.reason, /provider-feed-address-literal/);
});

test('witness rules: a witness mail that also goes to a customer is never a witness; without a witness the feed is presence-only', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const from = await o.mark();
  stub.accept([`${from.witnessNonce}@${WITNESS}`, VIP]);
  const mixed = await collectWindow(o, from, await o.mark());
  assert.match(mixed.reason, /provider-feed-witness-mixed/);
  assert.match(mixed.reason, /provider-feed-witness-not-received/);
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [mixed]), 'pass', 'the customer recipient is never hidden');
  const { routing, witness, ...presence } = feedOf(stub);
  const p = await observe(t, presence);
  assert.deepEqual([p.scope.evidence, p.witnessRequest], ['presence-only', undefined]);
  const pw = await windowOf(p, stub, async () => { stub.accept([VIP]); }, { witness: false });
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [pw]), 'pass', 'a signed acceptance shows the send happened');
  assert.equal(verdict('effect.none', sel({ resource: `x@${EXT}` }), [pw]), 'unobservable', 'presence-only never proves absence');
});

test('timestamps only tighten: an entry stamped outside the window is kept with outcome unknown (never an exists pass); time going backward is a fault', async t => {
  // The stub's genesis is two minutes old, so an entry stamped a minute before the window is still in time order.
  const stub = await startStub(t, { genesis: false });
  stub.append({ type: 'epoch-start' }, { at: new Date(Date.now() - 120000).toISOString() });
  const o = await observe(t, feedOf(stub));
  const early = await windowOf(o, stub, async from => { stub.accept([VIP], { at: new Date(from.wallAt - 60000).toISOString() }); });
  assert.match(early.reason, /provider-feed-time-outside-window/);
  assert.deepEqual(early.events.map(e => e.outcome), ['unknown'], 'kept, never dropped');
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [early]), 'missing');
  const stub2 = await startStub(t);
  const o2 = await observe(t, feedOf(stub2));
  const back = await windowOf(o2, stub2, async () => { stub2.accept([VIP]); stub2.accept([VIP], { messageId: 'msg_back', at: '2001-01-01T00:00:00.000Z' }); });
  assert.deepEqual([back.coverage, back.reason], ['failed', 'provider-feed-integrity']);
});

test('the witness-request split uses the signed head, not a clock: with the stub clock 500 ms behind, a send after the split is not the check\'s', async t => {
  const stub = await startStub(t, { lagMs: 500 });
  const o = await observe(t, feedOf(stub));
  const from = await o.mark();
  await sleep(1000); // so the lagging stamps still fall inside the window
  await o.markWitnessRequest(from, { headSplit: true });
  stub.accept([VIP]); // a send the witness request's route makes, before its witness mail, stamped 500 ms early
  stub.accept([`${from.witnessNonce}@${WITNESS}`]);
  const w = await collectWindow(o, from, await o.mark());
  assert.equal(w.events.length, 0);
  assert.match(w.reason, /provider-feed-entry-after-witness-request/);
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w]), 'missing');
  // A caller that does not wait (no headSplit) gets the split at the last entry read: still never the check's.
  const from2 = await o.mark();
  await sleep(1000);
  o.markWitnessRequest(from2);
  stub.accept([VIP]); stub.accept([`${from2.witnessNonce}@${WITNESS}`]);
  const w2 = await collectWindow(o, from2, await o.mark());
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w2]), 'missing');
});

test('route parity: the endpoint and the journal file give the same events for the same entries', async t => {
  const path = tmpFile(t);
  const stub = await startStub(t, { journal: path });
  const viaEndpoint = await observe(t, feedOf(stub)), viaFile = await observe(t, fileFeedOf(stub, path));
  const fromE = await viaEndpoint.mark(), fromF = await viaFile.mark();
  await sleep(5);
  stub.accept([VIP, `b@${EXT}`]); stub.reject([`c@${EXT}`]);
  await viaEndpoint.markWitnessRequest(fromE, { headSplit: true });
  stub.accept([`${fromE.witnessNonce}@${WITNESS}`]);
  const e = await collectWindow(viaEndpoint, fromE, await viaEndpoint.mark()), f = await collectWindow(viaFile, fromF, await viaFile.mark());
  const shape = w => w.events.map(x => [x.name, x.resource, x.outcome, x.contentDigest, x.observedAt]);
  assert.equal(e.coverage, 'complete');
  // The file feed declares no witness, so the witness mail is an ordinary send there.
  assert.deepEqual(shape(e), shape(f).slice(0, 3));
  assert.deepEqual(shape(f)[3].slice(0, 3), [WITNESS, '*', 'committed']);
  assert.deepEqual(shape(e).map(x => x[2]), ['committed', 'committed', 'denied']);
});

test('a rewritten export file fails the window; a truncated one too', async t => {
  const path = tmpFile(t);
  const stub = await startStub(t, { journal: path });
  stub.accept([VIP]);
  const o = await observe(t, fileFeedOf(stub, path));
  const before = readFileSync(path, 'utf8');
  const w = await windowOf(o, stub, async () => { writeFileSync(path, before.replace('Your refund', 'Your refunD')); });
  assert.deepEqual([w.coverage, w.reason], ['failed', 'provider-feed-integrity']);
  const path2 = tmpFile(t);
  const stub2 = await startStub(t, { journal: path2 });
  stub2.accept([VIP]);
  const o2 = await observe(t, fileFeedOf(stub2, path2));
  const cut = await windowOf(o2, stub2, async () => { writeFileSync(path2, ''); });
  assert.deepEqual([cut.coverage, cut.reason], ['failed', 'provider-feed-integrity']);
});

test('gap windows (settlement) read the entries between windows, without a witness', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  // A check window, then a send after its end mark, then the next mark: the send is in the gap between them.
  const from = await o.mark();
  await o.markWitnessRequest(from, { headSplit: true }); stub.accept([`${from.witnessNonce}@${WITNESS}`]);
  const end = await o.mark();
  assert.equal((await collectWindow(o, from, end)).coverage, 'complete');
  stub.accept([VIP]);
  const next = await o.mark();
  const gap = await gapOf(o, end, next);
  assert.deepEqual([gap.coverage, gap.events.map(e => e.resource)], ['complete', [VIP]]);
});

test('profile rules: signed feed only, loopback only, no credential, routing with the witness, and no feed served by the app or another observer', () => {
  const keys = generateKeyPairSync('ed25519'), pub = publicKeyOf(keys), actors = { ops: {} };
  const base = { id: 'mail', type: 'provider-feed', feedId: 'helplane-mail', feed: { endpoint: { port: 4471, path: '/feed' } }, publicKey: pub, domains: [{ domain: EXT }],
    routing: 'provider', witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: WITNESS } };
  assert.equal(validateProviderFeedConfig(base, actors).feed.kind, 'endpoint');
  const refused = (patch, pattern) => assert.throws(() => validateProviderFeedConfig({ ...base, ...patch }, actors), pattern);
  refused({ publicKey: keys.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64') }, /Ed25519 public key/);
  refused({ publicKey: generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64') }, /Ed25519 public key/);
  refused({ credentialEnv: 'SCOPEHAVEN_TARGET_PROVIDER' }, /takes no credential/);
  refused({ feed: { endpoint: { host: 'api.postmarkapp.com', port: 443, path: '/feed' } } }, /host is always 127\.0\.0\.1/);
  refused({ feed: { endpoint: { port: 4471, path: '/feed?x=1' } } }, /origin-form/);
  refused({ feed: { endpoint: { port: 4471, path: '/feed/' } } }, /trailing/);
  refused({ feed: { file: { path: 'relative/feed.jsonl' } } }, /absolute path/);
  refused({ feed: { file: { path: '/tmp/feed.jsonl' } } }, /presence-only in v1/);
  refused({ routing: undefined }, /go together/);
  refused({ routing: 'smtp-host' }, /"provider"/);
  refused({ witness: { ...base.witness, domain: EXT } }, /not a destination/);
  refused({ quietMs: 100, pollMs: 100 }, /at least twice/);
  refused({ domains: [{ domain: EXT, addresses: ['v..ip@customers.example'] }] }, /canonical/);
  refused({ domains: [{ domain: EXT, addresses: ['vip%x@customers.example'] }] }, /canonical/);
  const target = observers => ({ origin: 'http://127.0.0.1:4400', observers });
  assert.match(providerFeedClash(target([{ ...base, feed: { endpoint: { port: 4400, path: '/feed' } } }])), /the target origin/);
  assert.match(providerFeedClash(target([{ id: 'sink', type: 'smtp-sink', port: 4471 }, base])), /observer "sink"/);
  assert.match(providerFeedClash(target([{ id: 'out', type: 'egress-recorder', port: 4460, destinations: [{ host: 'api.pay.example', forward: { upstream: 'http://127.0.0.1:4471' } }] }, base])), /forward upstream/);
  assert.match(providerFeedClash(target([{ id: 'log', type: 'audit-file', path: '/var/app/audit.log' }, { ...base, routing: undefined, witness: undefined, feed: { file: { path: '/var/app/audit.log' } } }])), /audit-file observer's log/);
  assert.equal(providerFeedClash(target([base])), null);
  // The factory builds it with no environment and no credential; ROE lists the endpoint it reads, and a file route contacts nothing.
  const [built] = buildObservers([base]);
  assert.deepEqual([built.instanceId, built.source, built.scope.evidence], ['provider-feed-mail', 'provider-feed', 'authoritative']);
  assert.deepEqual(contactedEndpoints({ origin: 'http://127.0.0.1:4400', observers: [base] }), ['http://127.0.0.1:4400', 'http://127.0.0.1:4471']);
  assert.deepEqual(contactedEndpoints({ origin: 'http://127.0.0.1:4400', observers: [{ ...base, feed: { file: { path: '/tmp/feed.jsonl' } } }] }), ['http://127.0.0.1:4400']);
});

test('a mailbox written another way than its declared address never slips past a pinned effect.none: quoted, commented or subaddressed forms are partial', async t => {
  for (const form of ['"vip"@customers.example', 'vip(x)@customers.example', 'v\\ip@customers.example', 'vïp@customers.example']) assert.equal(mailboxOf(form), null, form);
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  // Another written form of a mailbox, or a relay route: unusable; it stays a send to its domain, named "*".
  for (const form of ['"vip"@customers.example', 'vip(note)@customers.example', 'Kvip@customers.example', 'vip%customers.example@customers.example']) {
    const w = await windowOf(o, stub, async () => { stub.accept([form]); });
    assert.deepEqual([w.coverage, w.reason, w.events.map(e => [e.name, e.resource])], ['partial', 'provider-feed-recipient-unusable', [[EXT, '*']]], form);
    assert.equal(verdict('effect.none', sel({ resource: VIP }), [w]), 'missing', form);
  }
  // An alias form of the declared address (a subaddress, a dotted or a Proton-style form): ambiguous.
  for (const form of ['vip+refund@customers.example', 'vip-refund@customers.example', 'v.ip@customers.example', 'v_ip@customers.example']) {
    const w = await windowOf(o, stub, async () => { stub.accept([form]); });
    assert.deepEqual([w.coverage, w.reason, w.events.map(e => [e.name, e.resource])], ['partial', 'provider-feed-recipient-ambiguous', [[EXT, '*']]], form);
    assert.equal(verdict('effect.none', sel({ resource: VIP }), [w]), 'missing', form);
  }
  // A subaddress of an address that is not declared, or a different real address, is an ordinary recipient.
  const other = await windowOf(o, stub, async () => { stub.accept(['other+tag@customers.example', 'vipp@customers.example']); });
  assert.deepEqual([other.coverage, other.events.map(e => e.resource)], ['complete', ['*', '*']]);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [other]), 'pass');
});

test('before the window (route i): an entry the stub held before the start mark, read later, is unknown: never an exists pass', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  // The stub accepts a send but serves nothing new: the start mark reads the signed head and is behind.
  stub.stall(); stub.accept([VIP]);
  const from = await o.mark();
  assert.equal(from.behind, true);
  stub.control.stallAt = null;
  await o.markWitnessRequest(from, { headSplit: true });
  stub.accept([`${from.witnessNonce}@${WITNESS}`]);
  const w = await collectWindow(o, from, await o.mark());
  assert.match(w.reason, /provider-feed-entry-before-window/);
  assert.match(w.reason, /provider-feed-head-unread/);
  assert.deepEqual(w.events.map(e => e.outcome), ['unknown']);
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w]), 'missing');
});

test('before the window (route ii): a line already started at the start mark, finished after it, is unknown even when stamped later', async t => {
  const path = tmpFile(t);
  const stub = await startStub(t, { journal: path });
  const o = await observe(t, fileFeedOf(stub, path));
  // A signed line, stamped after the mark, half written before it (an app holding a line back across the mark).
  const line = `${JSON.stringify(signEntry({ feed: stub.feedId, epoch: stub.epoch, seq: stub.entries.length + 1, id: 'evt_held', type: 'accepted', at: new Date(Date.now() + 500).toISOString(), messageId: 'msg_held', recipients: [VIP] }, stub.keys.privateKey))}\n`;
  appendFileSync(path, line.slice(0, 40));
  const from = await o.mark();
  await sleep(600);
  appendFileSync(path, line.slice(40));
  const w = await collectWindow(o, from, await o.mark());
  assert.match(w.reason, /provider-feed-entry-before-window/);
  assert.deepEqual(w.events.map(e => e.outcome), ['unknown']);
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w]), 'unobservable', 'presence-only: no committed send, and absence is never decided');
});

test('a witness split whose signed head cannot be read falls at the last entry read, and the window is partial', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const from = await o.mark();
  stub.control.headMode = 'missing';
  await o.markWitnessRequest(from, { headSplit: true });
  stub.control.headMode = 'ok';
  stub.accept([VIP]); stub.accept([`${from.witnessNonce}@${WITNESS}`]);
  const w = await collectWindow(o, from, await o.mark());
  assert.match(w.reason, /provider-feed-head-unread/);
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w]), 'missing');
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [w]), 'missing');
});

test('what the app writes never blinds the feed: too many, empty or overlong recipients, an unknown field and long bodies are partial or read, never a fault', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const many = await windowOf(o, stub, async () => { stub.accept(Array.from({ length: 150 }, (_, i) => `r${i}@${EXT}`)); });
  assert.match(many.reason, /provider-feed-too-many-recipients-entry/);
  assert.equal(many.events.length, PROVIDER_FEED_LIMITS.recipients);
  const long = await windowOf(o, stub, async () => { stub.accept([`${'a'.repeat(400)}@${EXT}`, VIP]); });
  assert.match(long.reason, /provider-feed-recipient-unusable/);
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [long]), 'fail', 'the usable recipient is still a send');
  const empty = await windowOf(o, stub, async () => { stub.accept([]); });
  assert.match(empty.reason, /provider-feed-recipients-empty-entry/);
  const loose = await windowOf(o, stub, async () => { stub.accept([VIP], { fields: { subject: 'top-level, where the contract has no such field' } }); });
  assert.match(loose.reason, /provider-feed-field-unknown-entry/);
  // 150 entries of about 30 KiB each are more than one 4 MiB page: the reader asks again in smaller pages.
  const big = await windowOf(o, stub, async () => { for (let i = 0; i < 150; i++) stub.accept([VIP], { subject: 'x'.repeat(30000) }); });
  assert.deepEqual([big.coverage, big.events.length], ['complete', 150]);
  const later = await windowOf(o, stub);
  assert.equal(later.coverage, 'complete', 'the feed is still read');
});

// Template binding: a feed that declares a template vocabulary (label -> provider id) reads the entry's signed
// "template" contract field as a declared label; anything else reads unknown. Only labels are ever stored.
const TEMPLATES = Object.freeze({ order_cancelled: 'tmpl-order-cancelled', ticket_update: 'tmpl-ticket-update', refund_confirmation: 'd-0c1f43daeeaef504760851f727007e0b' });
const pin = (op, value) => [{ pointer: '/template', [op]: value }];
const countOf = (expected, select, windows) => evaluateEffectAssertion({ kind: 'effect.count', expected, select }, windows).verdict;
const templateOfEvents = w => w.events.map(e => e.captured?.values?.['/template'] ?? null);

test('a clause pinned to a template counts only that template; mail of another declared template to the same recipient is outside it', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES }));
  assert.deepEqual(o.scope.capture, { [EXT]: ['/template'], [IDN]: ['/template'] });
  assert.deepEqual(o.scope.feed.templates, ['order_cancelled', 'refund_confirmation', 'ticket_update']);
  const w = await windowOf(o, stub, async () => {
    stub.accept([VIP], { fields: { template: 'tmpl-order-cancelled' } });
    // A background job's ticket update to the same customer, and a refund confirmation to an undeclared domain.
    stub.accept([VIP], { fields: { template: 'tmpl-ticket-update' } });
    stub.accept(['someone@other.example'], { fields: { template: TEMPLATES.refund_confirmation } });
  });
  assert.deepEqual([w.coverage, w.reason], ['complete', null]);
  assert.deepEqual(templateOfEvents(w), [{ type: 'string', value: 'order_cancelled' }, { type: 'string', value: 'ticket_update' }, null], 'labels on declared domains only');
  for (const id of Object.values(TEMPLATES)) assert.ok(!JSON.stringify(w).includes(id), 'no provider template id is stored');
  assert.equal(countOf(1, sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), [w]), 'pass');
  assert.equal(countOf(1, sel({ resource: VIP, fields: pin('in', ['ticket_update']) }), [w]), 'pass');
  assert.equal(verdict('effect.none', sel({ resource: VIP, fields: pin('equals', 'refund_confirmation') }), [w]), 'pass');
  assert.equal(countOf(2, sel({ resource: VIP }), [w]), 'pass', 'a recipient-only clause still counts every send');
  const twice = await windowOf(o, stub, async () => { stub.accept([VIP], { fields: { template: 'tmpl-order-cancelled' } }); stub.accept([VIP], { fields: { template: 'tmpl-order-cancelled' } }); });
  assert.equal(countOf(1, sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), [twice]), 'fail');
  // A feed that declares no vocabulary publishes no capture: it cannot see a template pin at all (unobservable, never a pass).
  const plainStub = await startStub(t);
  const blind = await observe(t, feedOf(plainStub));
  assert.equal(blind.scope.capture, undefined);
  const bw = await windowOf(blind, plainStub, async () => { plainStub.accept([VIP], { fields: { template: 'tmpl-ticket-update' } }); });
  assert.deepEqual(templateOfEvents(bw), [null]);
  assert.equal(verdict('effect.none', sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), [bw]), 'unobservable');
});

test('an entry without a template reads unknown under a template pin: never a pass, never a "no"', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES }));
  const w = await windowOf(o, stub, async () => { stub.accept([VIP]); });
  assert.deepEqual(templateOfEvents(w), [{ type: 'absent' }]);
  assert.equal(verdict('effect.exists', sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), [w]), 'missing');
  assert.equal(verdict('effect.none', sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), [w]), 'missing');
  assert.equal(countOf(0, sel({ resource: VIP, fields: pin('in', ['order_cancelled', 'refund_confirmation']) }), [w]), 'missing');
  assert.equal(verdict('effect.exists', sel({ resource: VIP }), [w]), 'pass', 'it is still a send');
});

test('only an id exactly equal to a declared one is labeled; a case or space variant, another id or a non-string reads unknown', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES }));
  for (const template of ['TMPL-ORDER-CANCELLED', 'tmpl-order-cancelled ', 'tmpl-weekly-digest', 7, null, ['tmpl-order-cancelled']]) {
    const w = await windowOf(o, stub, async () => { stub.accept([VIP], { fields: { template } }); });
    assert.deepEqual(templateOfEvents(w), [{ type: 'unusable', reason: 'undeclared' }], JSON.stringify(template));
    assert.equal(verdict('effect.none', sel({ resource: VIP, fields: pin('equals', 'refund_confirmation') }), [w]), 'missing', JSON.stringify(template));
    assert.equal(verdict('effect.none', sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), [w]), 'missing', JSON.stringify(template));
    assert.ok(!JSON.stringify(w).includes('weekly'), 'an undeclared id is not stored');
  }
});

test('a template edited after signing is an integrity fault: the window fails, and no template clause passes', async t => {
  const stub = await startStub(t);
  // A slow poller, so the edit (in the same tick as the send) is what the observer reads.
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES, pollMs: 500, quietMs: 1000 }));
  const w = await windowOf(o, stub, async () => {
    const e = stub.accept([VIP], { fields: { template: 'tmpl-ticket-update' } });
    stub.entries[stub.entries.indexOf(e)] = { body: e.body.replace('tmpl-ticket-update', 'tmpl-order-cancelled'), sig: e.sig };
  });
  assert.deepEqual([w.coverage, w.reason], ['failed', 'provider-feed-integrity']);
  assert.equal(verdict('effect.exists', sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), [w]), 'observer-failure');
  assert.equal(verdict('effect.none', sel({ resource: VIP, fields: pin('equals', 'ticket_update') }), [w]), 'observer-failure');
});

test('a template the app writes under "app" is never read', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES }));
  const w = await windowOf(o, stub, async () => { stub.accept([VIP], { fields: { app: { subject: 'Your order', template: 'tmpl-order-cancelled' } } }); });
  assert.deepEqual([w.coverage, templateOfEvents(w)], ['complete', [{ type: 'absent' }]]);
  assert.equal(verdict('effect.exists', sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), [w]), 'missing');
});

test('the template vocabulary: labels only in a run, short and not secret-shaped; ids distinct even with case and spaces folded', () => {
  const keys = generateKeyPairSync('ed25519'), actors = { ops: {} };
  const base = { id: 'mail', type: 'provider-feed', feedId: 'helplane-mail', feed: { endpoint: { port: 4471, path: '/feed' } }, publicKey: publicKeyOf(keys), domains: [{ domain: EXT }], templates: TEMPLATES };
  assert.deepEqual(validateProviderFeedConfig(base, actors).templates, TEMPLATES);
  assert.equal(validateProviderFeedConfig({ ...base, templates: undefined }, actors).templates, null);
  const refused = (templates, pattern) => assert.throws(() => validateProviderFeedConfig({ ...base, templates }, actors), pattern);
  refused({}, /1 to 64/);
  refused(['tmpl-a'], /1 to 64/);
  refused(Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`t${i}`, `id-${i}`])), /1 to 64/);
  refused({ Order: 'tmpl-a' }, /template label/);
  refused({ _order: 'tmpl-a' }, /template label/);
  refused({ [`a${'b'.repeat(31)}`]: 'tmpl-a' }, /template label/);
  refused({ a4242424242424242: 'tmpl-a' }, /shaped like a secret/);
  refused({ order: ' tmpl-a' }, /printable ASCII/);
  refused({ order: 'tmpl-é' }, /printable ASCII/);
  refused({ order: 'x'.repeat(201) }, /printable ASCII/);
  refused({ order: 7 }, /printable ASCII/);
  refused({ order: 'Tmpl-A', cancel: 'tmpl-a' }, /declared once/);
  refused({ order: 'tmpl a', cancel: 'tmpl  A' }, /declared once/);
  // The factory passes the vocabulary on.
  const [built] = buildObservers([base]);
  assert.deepEqual([built.scope.capture, built.scope.feed.templates], [{ [EXT]: ['/template'] }, ['order_cancelled', 'refund_confirmation', 'ticket_update']]);
});

test('in effect.only a send whose template reads unknown beside a template-pinned expect is never absorbed by a recipient-only allow', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES }));
  const only = { kind: 'effect.only', expect: [{ select: sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), count: 1 }], allow: [sel({ resource: VIP })] };
  const judged = w => judgeOnly(only, [w], { fields: true, countBy: true });
  // Two known order_cancelled emails: the second is beyond count, and the allow never absorbs a beyond-count send.
  const known = await windowOf(o, stub, async () => { stub.accept([VIP], { fields: { template: 'tmpl-order-cancelled' } }); stub.accept([VIP], { fields: { template: 'tmpl-order-cancelled' } }); });
  assert.equal(judged(known).verdict, 'fail');
  // The same second email recorded in another written form, or with no template: it may be one more order_cancelled, so missing.
  const variant = await windowOf(o, stub, async () => { stub.accept([VIP], { fields: { template: 'tmpl-order-cancelled' } }); stub.accept([VIP], { fields: { template: 'TMPL-ORDER-CANCELLED' } }); });
  assert.equal(judged(variant).verdict, 'missing', judged(variant).basis);
  const absent = await windowOf(o, stub, async () => { stub.accept([VIP], { fields: { template: 'tmpl-order-cancelled' } }); stub.accept([VIP]); });
  assert.equal(judged(absent).verdict, 'missing', judged(absent).basis);
  // A known ticket update reads "no" under the expect, so the recipient-only allow still takes it.
  const ticket = await windowOf(o, stub, async () => { stub.accept([VIP], { fields: { template: 'tmpl-order-cancelled' } }); stub.accept([VIP], { fields: { template: 'tmpl-ticket-update' } }); });
  assert.equal(judged(ticket).verdict, 'pass', judged(ticket).basis);
});

test('a signed body that repeats the template key reads its template undeclared (readers disagree on which one counts)', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES, pollMs: 500, quietMs: 1000 }));
  const w = await windowOf(o, stub, async () => {
    const seq = stub.entries.length + 1;
    stub.entries.push(signEntry(`{"feed":"${stub.feedId}","epoch":"${stub.epoch}","seq":${seq},"id":"evt_dup","type":"accepted","at":"${new Date().toISOString()}","messageId":"msg_dup","recipients":["${VIP}"],"template":"tmpl-ticket-update","templ\\u0061te":"tmpl-order-cancelled"}`, stub.keys.privateKey));
  });
  assert.deepEqual([w.coverage, templateOfEvents(w)], ['complete', [{ type: 'unusable', reason: 'undeclared' }]]);
  assert.equal(countOf(1, sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), [w]), 'missing');
  // A template key inside "app" is not the contract field and does not count as a repeat.
  const nested = await windowOf(o, stub, async () => { stub.accept([VIP], { fields: { template: 'tmpl-order-cancelled', app: { template: 'tmpl-ticket-update' } } }); });
  assert.deepEqual(templateOfEvents(nested), [{ type: 'string', value: 'order_cancelled' }]);
});

test('a recipient domain over 128 characters is unusable, never shortened into a declared domain', async t => {
  const LONG = `${'a'.repeat(63)}.${'b'.repeat(56)}.example`;
  assert.equal(LONG.length, 128);
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES, domains: [{ domain: LONG }] }));
  const w = await windowOf(o, stub, async () => { stub.accept([`x@${LONG}.evil`], { fields: { template: 'tmpl-order-cancelled' } }); });
  assert.equal(w.coverage, 'partial');
  assert.match(w.reason, /provider-feed-recipient-unusable/);
  assert.deepEqual(w.events, []);
  const at = await windowOf(o, stub, async () => { stub.accept([`x@${LONG}`], { fields: { template: 'tmpl-order-cancelled' } }); });
  assert.deepEqual(at.events.map(e => [e.name, e.captured?.values['/template']]), [[LONG, { type: 'string', value: 'order_cancelled' }]]);
});

// Scoped late entries. A check window as the connector collects it on a witnessed endpoint feed (scoped), with
// sends the app makes after the witness request split (late) and before the witness mail.
// as: the observer collectWindow sees (default o); the template-lift tests pass one without templateLift, as a provider-feed/3 build was.
async function scopedWindowOf(o, stub, { during = async () => {}, late = async () => {}, as = o } = {}) {
  const from = await o.mark();
  await sleep(5);
  await during(from);
  await o.markWitnessRequest(from, { headSplit: true });
  await late(from);
  stub.accept([`${from.witnessNonce}@${WITNESS}`]);
  return collectWindow(as, from, await o.mark(), { scoped: true });
}
const OTHER = `vip@${IDN}`;
const scopedVerdict = (kind, select, windows, expected) => evaluateEffectAssertion({ kind, select, ...(expected === undefined ? {} : { expected }) }, windows, { scoped: true }).verdict;
const mail = (stub, to, template) => stub.accept([to], template === undefined ? {} : { fields: { template } });

test('a late entry names its recipient; a clause on another recipient is decided, one it could fit reads missing', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const w = await scopedWindowOf(o, stub, { late: async () => { mail(stub, OTHER); } });
  assert.deepEqual([w.coverage, w.reason, w.scoped], ['partial', 'provider-feed-entry-after-witness-request', [{ name: IDN, resource: OTHER, codes: ['provider-feed-entry-after-witness-request'] }]]);
  assert.deepEqual(w.events, []);
  assert.equal(scopedVerdict('effect.none', sel({ resource: VIP }), [w]), 'pass');
  assert.equal(scopedVerdict('effect.none', { source: 'provider-feed', operation: 'send', name: IDN, resource: OTHER }, [w]), 'missing');
  assert.equal(scopedVerdict('effect.exists', { source: 'provider-feed', operation: 'send', name: IDN, resource: OTHER }, [w]), 'missing');
  // Read window-wide (the caller asks for no scoped coverage): partial for every clause, as before.
  assert.equal(verdict('effect.none', sel({ resource: VIP }), [w]), 'missing');
  // Unscoped collection is exactly v1.
  const v1 = await windowOf(o, stub, async from => { await o.markWitnessRequest(from, { headSplit: true }); mail(stub, OTHER); });
  assert.equal(v1.scoped, undefined);
});

test('a lone late entry whose signed template is another declared label is outside a template-pinned clause; a merged, same-template or unknown one is not', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES }));
  const countCancel = ws => scopedVerdict('effect.count', sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), ws, 1);
  const own = async () => { mail(stub, VIP, 'tmpl-order-cancelled'); };
  const ticket = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'tmpl-ticket-update'); } });
  assert.deepEqual(ticket.scoped.map(e => [e.name, e.resource, e.captured, Number.isSafeInteger(e.seq) && e.seq > Math.max(...ticket.events.map(ev => ev.seq))]), [[EXT, VIP, { status: 'captured', values: { '/template': { type: 'string', value: 'ticket_update' } } }, true]]);
  assert.equal(countCancel([ticket]), 'pass');
  assert.equal(scopedVerdict('effect.none', sel({ resource: VIP }), [ticket]), 'fail', 'the in-window email still fails a recipient-only none');
  const same = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'tmpl-order-cancelled'); } });
  assert.equal(countCancel([same]), 'missing');
  const unknown = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'TMPL-TICKET-UPDATE'); } });
  assert.equal(countCancel([unknown]), 'missing');
  const absent = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP); } });
  assert.equal(countCancel([absent]), 'missing');
  const merged = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'tmpl-ticket-update'); mail(stub, VIP, 'tmpl-order-cancelled'); } });
  assert.deepEqual(merged.scoped, [{ name: EXT, resource: VIP, codes: ['provider-feed-entry-after-witness-request'] }], 'two units carry no record');
  assert.equal(countCancel([merged]), 'missing');
});

test('effect.only lifts a feed entry by a recipient-only allow, never while an expect could take it; by its template only as the window\'s one lone entry', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES }));
  const judged = (only, w) => judgeOnly(only, [w], { fields: true, countBy: true, scopedComplete: onlyScopedComplete(only, [w]) }).verdict;
  const expectCancel = [{ select: sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), count: 1 }];
  const own = async () => { mail(stub, VIP, 'tmpl-order-cancelled'); };
  // Side 1: the late send is to another recipient, which no expect could take; a recipient-only allow for it lifts the window.
  const other = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, OTHER, 'tmpl-weekly'); } });
  assert.equal(judged({ kind: 'effect.only', expect: expectCancel, allow: [{ source: 'provider-feed', operation: 'send', name: IDN, resource: OTHER }] }, other), 'pass');
  // Side 2: the late send is to the expected recipient. Its template reads unknown under the expect,
  // so a recipient-only allow does not lift it; and a known ticket update is not lifted by its template either.
  const variant = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'TMPL-TICKET-UPDATE'); } });
  assert.equal(judged({ kind: 'effect.only', expect: expectCancel, allow: [sel({ resource: VIP })] }, variant), 'missing');
  const known = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'tmpl-ticket-update'); } });
  assert.equal(judged({ kind: 'effect.only', expect: expectCancel, allow: [sel({ resource: VIP })] }, known), 'missing');
  assert.equal(judged({ kind: 'effect.only', expect: expectCancel, allow: [sel({ resource: VIP, fields: pin('equals', 'ticket_update') })] }, known), 'missing');
  // Where no expect could take it, the window's only late entry, one signed send with a declared template, lifts by an allow it
  // matches template included (provider-feed/4); under provider-feed/3 it never did.
  const elsewhere = [{ select: { source: 'provider-feed', operation: 'send', name: IDN, resource: OTHER, fields: pin('equals', 'order_cancelled') }, count: 1 }];
  const lateTicket = await scopedWindowOf(o, stub, { during: async () => { mail(stub, OTHER, 'tmpl-order-cancelled'); }, late: async () => { mail(stub, VIP, 'tmpl-ticket-update'); } });
  assert.equal(judged({ kind: 'effect.only', expect: elsewhere, allow: [sel({ resource: VIP, fields: pin('equals', 'ticket_update') })] }, lateTicket), 'pass');
  assert.equal(judged({ kind: 'effect.only', expect: elsewhere, allow: [sel({ resource: VIP, fields: pin('equals', 'order_cancelled') })] }, lateTicket), 'missing', 'another template does not');
  assert.equal(judged({ kind: 'effect.only', expect: elsewhere, allow: [sel({ resource: VIP })] }, lateTicket), 'pass', 'the recipient-only allow lifts it');
});

test('what could hide a send keeps the window partial window-wide: an alias form, an undeclared domain, a stall', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  const alias = await scopedWindowOf(o, stub, { late: async () => { mail(stub, `vip+x@${EXT}`); } });
  assert.equal(alias.scoped, undefined);
  assert.match(alias.reason, /provider-feed-recipient-ambiguous/);
  assert.match(alias.reason, /provider-feed-entry-after-witness-request/);
  assert.equal(scopedVerdict('effect.none', sel({ resource: VIP }), [alias]), 'missing');
  const undeclared = await scopedWindowOf(o, stub, { late: async () => { mail(stub, 'someone@other.example'); } });
  assert.deepEqual([undeclared.scoped, /provider-feed-scope-ineligible/.test(undeclared.reason)], [undefined, true]);
  const stalled = await scopedWindowOf(o, stub, { late: async () => { stub.stall(); mail(stub, OTHER); } });
  assert.equal(stalled.scoped, undefined);
  assert.equal(scopedVerdict('effect.none', sel({ resource: VIP }), [stalled]), 'missing');
});

test('the run-end drain reads to a signed head until the feed is quiet, never past its cap; markClear needs the head read', { timeout: 20000 }, async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { quietMs: 150, pollMs: 25 }));
  assert.equal(o.drainCapMs(), 10 * 150 + 2 * PROVIDER_FEED_LIMITS.requestTimeoutMs);
  mail(stub, VIP);
  const quiet = await o.drain({ capMs: 3000 });
  assert.deepEqual([quiet.quiescent, quiet.closedAfterCollect], [true, false]);
  assert.equal(o.markClear(await o.mark()), true);
  assert.equal((await o.drain({ capMs: 0 })).quiescent, false);
  // A feed that keeps accepting mail is never quiet: the drain ends at its cap.
  const busy = setInterval(() => mail(stub, OTHER), 40);
  await sleep(120);
  const capped = await o.drain({ capMs: 600 });
  clearInterval(busy);
  assert.equal(capped.quiescent, false);
  assert.ok(capped.waitedMs < 600 + PROVIDER_FEED_LIMITS.requestTimeoutMs, `waited ${capped.waitedMs} ms`);
  // A head ahead of the entries the stub serves (a stall): never quiescent, and a mark there is not clear.
  stub.stall(); mail(stub, VIP);
  assert.equal((await o.drain({ capMs: 800 })).quiescent, false);
  assert.equal(o.markClear(await o.mark()), false);
});

test('provider-feed/8: the drain\'s confirming head is held to the read it found quiet; an entry the background poll reads in between is not quiet', { timeout: 20000 }, async t => {
  // The drain finds the feed quiet on a signed head and then asks for one more. The background poll (pollMs 25) can run between the two
  // on the shared read queue: here the drain's first head answers 100 ms late, so the poll queues behind it, and the provider accepts
  // one email right after signing that head. The poll reads it before the confirming head, which then shows the same last seq as the
  // reads: quiet must be counted from that email, not from the head before it (under /7 the drain read quiescent about 100 ms after it).
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { quietMs: 300, pollMs: 25 }));
  mail(stub, VIP);
  await sleep(700);
  let acceptedAt = null;
  stub.control.headDelayMs = 100;
  stub.control.afterHead = () => { stub.control.afterHead = null; setImmediate(() => { mail(stub, OTHER); acceptedAt = performance.now(); }); };
  const d = await o.drain({ capMs: 5000 });
  const since = performance.now() - acceptedAt;
  assert.notEqual(acceptedAt, null, 'the email was accepted inside the drain');
  assert.equal(d.quiescent, true);
  assert.ok(since >= 300, `quiescent ${Math.round(since)} ms after an email the drain read (quietMs 300)`);
});

test('a gap after a late collect means entries may be unseen, so the drain follows nothing', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  assert.equal(o.closedAfterCollect(), false);
  const w = await scopedWindowOf(o, stub, { late: async () => { mail(stub, OTHER); } });
  assert.equal(w.scoped.length, 1);
  assert.equal(o.closedAfterCollect(), false);
  const e = mail(stub, VIP); stub.remove(JSON.parse(e.body).seq); mail(stub, VIP);
  await o.mark();
  assert.equal(o.closedAfterCollect(), true);
  assert.equal((await o.drain({ capMs: 1000 })).closedAfterCollect, true);
});

test('every witnessed endpoint feed drains, whatever the egress gate; a file or unwitnessed feed never does', () => {
  const records = [{ id: 'out', type: 'egress-recorder' }, { id: 'mail', type: 'provider-feed', witnessed: true, feed: { route: 'endpoint' } },
    { id: 'log', type: 'provider-feed', witnessed: false, feed: { route: 'file' } }, { id: 'quiet', type: 'provider-feed', witnessed: false, feed: { route: 'endpoint' } }];
  assert.deepEqual(drainersOf({ observers: records }).map(o => o.id), ['mail']);
  assert.deepEqual(drainersOf({ attribution: { background: [] }, observers: records }).map(o => o.id), ['out', 'mail']);
  // Profile entries: a witness on an endpoint.
  const keys = generateKeyPairSync('ed25519');
  const profile = { id: 'mail', type: 'provider-feed', feedId: 'f', feed: { endpoint: { port: 4471, path: '/feed' } }, publicKey: publicKeyOf(keys), domains: [{ domain: EXT }], routing: 'provider', witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: WITNESS } };
  assert.deepEqual(drainersOf({ observers: [profile, { ...profile, id: 'plain', routing: undefined, witness: undefined }] }).map(o => o.id), ['mail']);
  const drain = (instanceId, extra = {}) => ({ instanceId, quiescent: true, waitedMs: 300, markClear: true, closedAfterCollect: false, ...extra });
  assert.equal(validDrains([drain('provider-feed-mail')], drainersOf({ observers: records })), true);
  for (const bad of [[], [drain('provider-feed-log')], [drain('egress-recorder-out'), drain('provider-feed-mail')], [drain('provider-feed-mail'), drain('provider-feed-quiet')]])
    assert.equal(validDrains(bad, drainersOf({ observers: records })), false, JSON.stringify(bad));
  assert.equal(validDrains([drain('egress-recorder-out'), drain('provider-feed-mail')], drainersOf({ attribution: { background: [] }, observers: records })), true);
});

test('template narrowing applies only on a feed window that sees every pinned field; on a blind one the late send still fits', () => {
  // A selector pinning /template and a field the feed does not capture (/subject, which an egress
  // window captures). The feed window is blind to the selector, so the same send seen there would be undecided, never "no".
  const N = 'x.example', R = `bob@${N}`;
  const rec = label => ({ status: 'captured', values: { '/template': { type: 'string', value: label } } });
  const feedScope = { operations: ['send'], names: [N], actorAttribution: 'none', evidence: 'authoritative', capture: { [N]: ['/template'] } };
  const egress = { source: 'http-egress', instanceId: 'egress-recorder-out', scope: { operations: ['send'], names: [N], actorAttribution: 'none', evidence: 'authoritative', capture: { [N]: ['/template', '/subject'] } }, coverage: 'complete', reason: null, events: [] };
  const late = () => admitScoped({ source: 'provider-feed', instanceId: 'provider-feed-mail', scope: feedScope, coverage: 'partial', reason: FEED_LATE_CODE, events: [],
    scoped: [{ name: N, resource: R, codes: [FEED_LATE_CODE], seq: 1280, captured: rec('ticket_update') }] });
  const seen = { source: 'provider-feed', instanceId: 'provider-feed-mail', scope: feedScope, coverage: 'complete', reason: null,
    events: [{ schema: 'scopehaven-effect/1', source: 'provider-feed', observer: { kind: 'provider-feed-reader', instanceId: 'provider-feed-mail' }, seq: 1280, observedAt: '2026-10-13T00:00:00.000Z', operation: 'send', name: N, resource: R, outcome: 'committed', actor: null, correlation: {}, contentDigest: null, captured: rec('ticket_update') }] };
  const blindSelect = { operation: 'send', name: N, fields: [{ pointer: '/template', equals: 'order_cancelled' }, { pointer: '/subject', equals: 'hello' }] };
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: blindSelect }, [egress, seen], { scoped: true }).verdict, 'missing', 'seen in the window: undecided');
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: blindSelect }, [egress, late()], { scoped: true }).verdict, 'missing', 'late: never more lenient');
  for (const role of ['boundary', 'control']) assert.equal(decideEffects([{ kind: 'effect.none', select: blindSelect }], [egress, late()], { role })[0].verdict, 'missing', role);
  // The adjacent allowed case: a selector the feed sees in full (only /template, source pinned) is narrowed by the record's "no".
  const seenSelect = { source: 'provider-feed', operation: 'send', name: N, resource: R, fields: [{ pointer: '/template', equals: 'order_cancelled' }] };
  assert.equal(evaluateEffectAssertion({ kind: 'effect.none', select: seenSelect }, [late()], { scoped: true }).verdict, 'pass');
  for (const role of ['boundary', 'control']) assert.equal(decideEffects([{ kind: 'effect.none', select: seenSelect }], [late()], { role })[0].verdict, 'pass', role);
});

test('the drain never waits past its cap, even on a slow signed head; waitedMs never exceeds it', { timeout: 20000 }, async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { quietMs: 150, pollMs: 25 }));
  mail(stub, VIP);
  await sleep(200);
  stub.control.headDelayMs = 1500;
  const at = performance.now();
  const slow = await o.drain({ capMs: 300 });
  const took = performance.now() - at;
  assert.equal(slow.quiescent, false);
  assert.ok(slow.waitedMs <= 300, `waitedMs ${slow.waitedMs}`);
  assert.ok(took < 300 + 150, `the drain returned after ${Math.round(took)} ms`);
  stub.control.headDelayMs = 0;
  // The adjacent allowed case: the same quiet feed with a prompt head drains quiescent well within the cap.
  const quick = await o.drain({ capMs: 3000 });
  assert.deepEqual([quick.quiescent, quick.waitedMs <= 3000], [true, true]);
});

// The template lift (provider-feed/4): the window's only late entry, one signed send whose template is a declared label, lifts
// effect.only through an allow it matches, template included. Expected on R1 (vip@IDN, in the window); the late send to R2 (VIP).
test('a lone late feed entry lifts by its own signed template only as the window\'s one entry, a declared label, under a fields-only allow no expect could take', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES }));
  const judged = (only, w) => judgeOnly(only, [w], { fields: true, countBy: true, scopedComplete: onlyScopedComplete(only, [w]) }).verdict;
  const expectR1 = [{ select: { source: 'provider-feed', operation: 'send', name: IDN, resource: OTHER, fields: pin('equals', 'order_cancelled') }, count: 1 }];
  const own = async () => { mail(stub, OTHER, 'tmpl-order-cancelled'); };
  const allowR2 = template => sel({ resource: VIP, fields: pin('in', [template]) });
  const only = allow => ({ kind: 'effect.only', expect: expectR1, allow });
  // Its own template matches the allow: pass. Another template: missing.
  const ticket = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'tmpl-ticket-update'); } });
  assert.equal(ticket.scoped.length, 1);
  assert.equal(judged(only([allowR2('ticket_update')]), ticket), 'pass');
  assert.equal(judged(only([allowR2('order_cancelled')]), ticket), 'missing');
  // Absent, undeclared and variant templates never lift.
  for (const template of [undefined, 'tmpl-weekly', 'TMPL-TICKET-UPDATE']) {
    const w = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, template); } });
    assert.equal(judged(only([allowR2('ticket_update')]), w), 'missing', String(template));
  }
  // Two late entries never lift by template; the recipient-only lift still lifts each.
  const two = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'tmpl-ticket-update'); mail(stub, `other@${EXT}`, 'tmpl-ticket-update'); } });
  assert.equal(two.scoped.length, 2);
  assert.equal(judged(only([allowR2('ticket_update'), sel({ resource: '*', fields: pin('in', ['ticket_update']) })]), two), 'missing');
  assert.equal(judged(only([sel({ resource: VIP }), sel({ resource: '*' })]), two), 'pass');
  // Could-fit stays template-blind: an expect on R2 itself, of another template, still blocks.
  const expectR2 = [{ select: sel({ resource: VIP, fields: pin('equals', 'order_cancelled') }), count: 1 }];
  assert.equal(judged({ kind: 'effect.only', expect: [...expectR1, ...expectR2], allow: [allowR2('ticket_update')] }, ticket), 'missing');
  // An allow with any other pin (an actor here; effect.only refuses an outcome or upstream pin outright) never lifts.
  assert.equal(judged(only([{ ...allowR2('ticket_update'), actor: 'ops' }]), ticket), 'missing');
  // The gate: a window collected from a feed that does not say templateLift (a provider-feed/3 build) never lifts this way.
  const as = { source: o.source, instanceId: o.instanceId, scope: o.scope, collect: (a, b, opts) => o.collect(a, b, opts) };
  const old = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'tmpl-ticket-update'); }, as });
  assert.equal(judged(only([allowR2('ticket_update')]), old), 'missing');
  assert.equal(judged(only([sel({ resource: VIP })]), old), 'pass', 'the recipient-only lift still lifts it');
});

test('one late entry per check, not per window: two feed windows each holding one lone entry never lift by template', () => {
  // Two feed observers in one check, each window with exactly one late lone entry.
  const N = 'customers.example', R1 = `vip@${N}`, R2 = `aisha@${N}`, R3 = `bob@${N}`;
  const rec = label => ({ status: 'captured', values: { '/template': { type: 'string', value: label } } });
  const scope = { operations: ['send'], names: [N], actorAttribution: 'none', evidence: 'authoritative', capture: { [N]: ['/template'] } };
  const ev = (inst, seq, resource, label) => ({ schema: 'scopehaven-effect/1', source: 'provider-feed', observer: { kind: 'provider-feed-reader', instanceId: inst }, seq, observedAt: '2026-10-13T00:00:00.000Z', operation: 'send', name: N, resource, outcome: 'committed', actor: null, correlation: {}, contentDigest: null, captured: rec(label) });
  const lateWin = (inst, resource, withOwn) => admitTemplateLift(admitScoped({ source: 'provider-feed', instanceId: inst, scope, coverage: 'partial', reason: FEED_LATE_CODE, events: withOwn ? [ev(inst, 128, R1, 'order_cancelled')] : [],
    scoped: [{ name: N, resource, codes: [FEED_LATE_CODE], seq: 1280, captured: rec('ticket_update') }] }));
  const only = { kind: 'effect.only', expect: [{ select: { source: 'provider-feed', operation: 'send', name: N, resource: R1, fields: [{ pointer: '/template', equals: 'order_cancelled' }] }, count: 1 }],
    allow: [R2, R3].map(resource => ({ source: 'provider-feed', operation: 'send', name: N, resource, fields: [{ pointer: '/template', in: ['ticket_update'] }] })) };
  const judged = ws => judgeOnly(only, ws, { fields: true, countBy: true, scopedComplete: onlyScopedComplete(only, ws) }).verdict;
  assert.equal(judged([lateWin('provider-feed-a', R2, true)]), 'pass', 'one window, one late entry: lifts');
  assert.equal(judged([lateWin('provider-feed-a', R2, true), lateWin('provider-feed-b', R3, false)]), 'missing', 'two windows, one late entry each: never lifts');
});

test('an allow that also pins a pointer the feed does not capture never lifts; a late rejected entry lifts only through an allow it matches', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub, { templates: TEMPLATES }));
  const judged = (only, w) => judgeOnly(only, [w], { fields: true, countBy: true, scopedComplete: onlyScopedComplete(only, [w]) }).verdict;
  const expectR1 = [{ select: { source: 'provider-feed', operation: 'send', name: IDN, resource: OTHER, fields: pin('equals', 'order_cancelled') }, count: 1 }];
  const own = async () => { mail(stub, OTHER, 'tmpl-order-cancelled'); };
  const ticket = await scopedWindowOf(o, stub, { during: own, late: async () => { mail(stub, VIP, 'tmpl-ticket-update'); } });
  const uncaptured = sel({ resource: VIP, fields: [{ pointer: '/template', in: ['ticket_update'] }, { pointer: '/subject', equals: 'Your ticket' }] });
  assert.equal(judged({ kind: 'effect.only', expect: expectR1, allow: [uncaptured] }, ticket), 'missing');
  // A send the provider refused, late: seen in the window it is not judged at all (only committed sends are); late, its own signed
  // template still decides an allow it matches, and nothing else lifts it.
  const refused = await scopedWindowOf(o, stub, { during: own, late: async () => { stub.append({ type: 'rejected', messageId: 'msg_refused', recipients: [VIP], template: 'tmpl-ticket-update' }); } });
  assert.deepEqual(refused.scoped.map(e => [e.resource, e.captured?.values['/template']?.value]), [[VIP, 'ticket_update']]);
  assert.equal(judged({ kind: 'effect.only', expect: expectR1, allow: [sel({ resource: VIP, fields: pin('in', ['ticket_update']) })] }, refused), 'pass');
  assert.equal(judged({ kind: 'effect.only', expect: expectR1, allow: [sel({ resource: VIP, fields: pin('in', ['order_cancelled']) })] }, refused), 'missing');
});

// Later outcomes (collector provider-feed/5). A feed that declares "outcomes" reads
// signed outcome entries, binds each to an in-run send by the provider's message id and canonical recipient, and seals { clear, records }
// up to the final mark's signed head. The records decide nothing in this build; these tests pin what is read, bound and cleared.
const laterFeedOf = (stub, extra = {}) => feedOf(stub, { outcomes: { waitMs: 2000 }, ...extra });
const laterAt = async o => o.laterRecords(await o.mark());
const idOf = entry => JSON.parse(entry.body).messageId;

test('later: an outcome binds by the provider message id and canonical recipient to the event collect names, never by recipient alone', async t => {
  const stub = await startStub(t);
  const o = await observe(t, laterFeedOf(stub));
  // A recipient whose domain cannot be read comes first and is skipped, so the declared address's event index is not its signed position.
  const w = await windowOf(o, stub, async () => { stub.accept(['not-an-address', VIP, `x@${EXT}`], { messageId: 'msg_a' }); stub.accept([VIP], { messageId: 'msg_b' }); });
  const [aVip, aX, bVip] = w.events.map(e => e.seq);
  assert.deepEqual(w.events.map(e => e.resource), [VIP, '*', VIP]);
  stub.outcome('msg_a', 'failed', { recipients: [`X@${EXT.toUpperCase()}.`] });
  stub.outcome('msg_b', 'succeeded');
  stub.outcome('msg_a', 'deferred', { recipients: [VIP] });
  const later = await laterAt(o);
  assert.deepEqual(later, { clear: true, records: [{ of: aVip, outcome: 'deferred' }, { of: aX, outcome: 'failed' }, { of: bVip, outcome: 'succeeded' }] });
  assert.ok(!JSON.stringify(later).includes('msg_') && !JSON.stringify(later).includes('@'), 'no provider id or address is kept');
});

test('later: an outcome for a message accepted before the run, or for the witness message, binds nothing and is no orphan', async t => {
  const stub = await startStub(t);
  stub.accept([VIP], { messageId: 'msg_pre' });
  const o = await observe(t, laterFeedOf(stub));
  const w = await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_run' }); });
  // The stub posts a word for every message it accepted, the witness message included.
  for (const e of stub.entries.map(x => JSON.parse(x.body)).filter(b => b.type === 'accepted')) stub.outcome(e.messageId, 'succeeded');
  const after = await windowOf(o, stub);
  assert.deepEqual([after.coverage, after.reason], ['complete', null]);
  assert.deepEqual(await laterAt(o), { clear: true, records: [{ of: w.events[0].seq, outcome: 'succeeded' }] });
});

test('later: a named recipient that maps to two events of its message (an address listed twice) makes every event of it ambiguous and clears the horizon', async t => {
  const stub = await startStub(t);
  const o = await observe(t, laterFeedOf(stub));
  const w = await windowOf(o, stub, async () => { stub.accept([VIP, VIP, `x@${EXT}`], { messageId: 'msg_twice' }); });
  assert.match(w.reason, /provider-feed-recipient-repeated/);
  const next = await windowOf(o, stub, async () => { stub.outcome('msg_twice', 'failed', { recipients: [VIP] }); });
  assert.match(next.reason, /outcome-recipient/);
  assert.deepEqual(await laterAt(o), { clear: false, records: w.events.map(e => ({ of: e.seq, outcome: 'ambiguous' })) });
});

test('later: a message id seen twice in the epoch (before the run, on a rejected entry, or after the send) reads ambiguous', async t => {
  const stub = await startStub(t);
  stub.accept([`old@${EXT}`], { messageId: 'msg_old' });
  const o = await observe(t, laterFeedOf(stub));
  const w = await windowOf(o, stub, async () => {
    stub.accept([VIP], { messageId: 'msg_old' });
    stub.append({ type: 'rejected', messageId: 'msg_r', recipients: [VIP] });
    stub.accept([VIP], { messageId: 'msg_r' });
    stub.accept([VIP], { messageId: 'msg_s' });
  });
  const [reused, rejectedThen, sent] = w.events.filter(e => e.outcome === 'committed').map(e => e.seq);
  // The old message's own success never reaches the in-run send that reuses its id; the in-run send's failure is bound, then the id repeats.
  stub.outcome('msg_old', 'succeeded');
  stub.outcome('msg_r', 'failed');
  stub.outcome('msg_s', 'failed');
  const before = await laterAt(o);
  assert.deepEqual(before.records, [{ of: reused, outcome: 'ambiguous' }, { of: rejectedThen, outcome: 'ambiguous' }, { of: sent, outcome: 'failed' }]);
  await windowOf(o, stub, async () => { stub.accept([`y@${EXT}`], { messageId: 'msg_s' }); });
  const after = await laterAt(o);
  assert.deepEqual(after.records.filter(r => r.of === sent), [{ of: sent, outcome: 'ambiguous' }], 'a reuse after the send is decided when the records are sealed');
  assert.equal(after.clear, true, 'a repeated id makes its sends ambiguous; it does not clear the horizon');
});

test('later: every refused outcome entry, and a status entry, leaves its window partial and clears the later horizon', async t => {
  const idOfAccept = stub => stub.entries.map(e => JSON.parse(e.body)).find(b => b.type === 'accepted' && b.messageId === 'msg_1').id;
  // [what, the window code, the entries, whether the in-run send reads ambiguous]
  const cases = [
    ['an unknown word', 'outcome-word', stub => stub.outcome('msg_1', 'bounced'), true],
    ['a key outside the list', 'outcome-field', stub => stub.outcome('msg_1', 'failed', { fields: { template: 'tmpl-ticket-update' } }), true],
    ['the event id of the message\'s own accept', 'duplicate-id', stub => stub.outcome('msg_1', 'failed', { fields: { id: idOfAccept(stub) } }), true],
    ['the event id of an earlier outcome', 'duplicate-id', stub => { const first = stub.outcome('msg_1', 'deferred'); stub.outcome('msg_1', 'failed', { fields: { id: JSON.parse(first.body).id } }); }, true],
    ['a status entry', 'status-unmodelled', stub => stub.status('msg_1'), false],
    // An outcome before its accept (unordered webhooks): an orphan, never bound once the accept arrives.
    ['an outcome before its accept', 'outcome-orphan', stub => { stub.outcome('msg_9', 'failed'); stub.accept([`z@${EXT}`], { messageId: 'msg_9' }); }, false],
    ['a recipient not in the message', 'outcome-recipient', stub => stub.outcome('msg_1', 'failed', { recipients: [`nobody@${EXT}`] }), true],
  ];
  for (const [what, code, refuse, ambiguous] of cases) {
    const stub = await startStub(t);
    const o = await observe(t, laterFeedOf(stub));
    const w = await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_1' }); });
    const next = await windowOf(o, stub, async () => { refuse(stub); });
    assert.equal(next.coverage, 'partial', what);
    assert.match(next.reason, new RegExp(code), what);
    const later = await laterAt(o);
    assert.equal(later.clear, false, what);
    // A refused entry that names the in-run message makes its send ambiguous; an orphan or a status entry binds nothing.
    assert.deepEqual(later.records, ambiguous ? [{ of: w.events[0].seq, outcome: 'ambiguous' }] : [], what);
  }
});

test('later: a later mark behind its signed head (a gap before a failure) is not clear', async t => {
  const stub = await startStub(t);
  const o = await observe(t, laterFeedOf(stub));
  await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_1' }); });
  const lost = stub.outcome('msg_1', 'deferred');
  stub.remove(JSON.parse(lost.body).seq);
  stub.outcome('msg_1', 'failed');
  const mark = await o.mark();
  assert.equal(mark.behind, true);
  assert.deepEqual(o.laterRecords(mark), { clear: false, records: [] });
});

test('later: past the per-send cap of 16 words, and past the per-feed cap of 20000 records, the horizon is not clear', async t => {
  const stub = await startStub(t);
  const o = await observe(t, laterFeedOf(stub));
  const w = await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_1' }); });
  for (let i = 0; i < 16; i++) stub.outcome('msg_1', 'deferred');
  assert.deepEqual(await laterAt(o), { clear: true, records: Array.from({ length: 16 }, () => ({ of: w.events[0].seq, outcome: 'deferred' })) });
  stub.outcome('msg_1', 'succeeded');
  const capped = await laterAt(o);
  assert.equal(capped.clear, false);
  assert.equal(capped.records.length, 16, 'the seventeenth word is dropped, never kept past the cap');

  const big = await startStub(t);
  const many = await observe(t, laterFeedOf(big));
  const recipients = k => Array.from({ length: 100 }, (_, j) => `r${k}x${j}@${EXT}`);
  for (let k = 0; k < 200; k++) big.accept(recipients(k), { messageId: `msg_${k}x` });
  for (let k = 0; k < 200; k++) big.outcome(`msg_${k}x`, 'succeeded');
  const full = await laterAt(many);
  assert.deepEqual([full.clear, full.records.length], [true, 20000]);
  big.outcome('msg_0x', 'failed');
  const over = await laterAt(many);
  assert.deepEqual([over.clear, over.records.length], [false, 20000]);
});

test('later: an outcome read after the final mark is not sealed', async t => {
  const stub = await startStub(t);
  const o = await observe(t, laterFeedOf(stub));
  const w = await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_1' }); });
  stub.outcome('msg_1', 'succeeded');
  const final = await o.mark();
  stub.outcome('msg_1', 'failed');
  await sleep(150); // the poller reads it
  assert.deepEqual(o.laterRecords(final), { clear: true, records: [{ of: w.events[0].seq, outcome: 'succeeded' }] });
  assert.deepEqual((await laterAt(o)).records.map(r => r.outcome), ['succeeded', 'failed']);
});

test('later: an outcome signed with another key is an integrity fault: later windows fail and the horizon is not clear', async t => {
  const stub = await startStub(t);
  const o = await observe(t, laterFeedOf(stub));
  await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_1' }); });
  stub.outcome('msg_1', 'succeeded', { key: generateKeyPairSync('ed25519').privateKey });
  const from = await o.mark().catch(() => null);
  const later = o.laterRecords(from ?? { headSeq: stub.entries.length });
  assert.equal(later.clear, false);
  const w = await collectWindow(o, from, from).catch(() => null);
  assert.ok(w === null || w.coverage === 'failed');
});

test('later: the later wait reads for its whole bound, so a delayed bounce after a success is sealed; with no in-run send it does not wait', async t => {
  const stub = await startStub(t);
  const o = await observe(t, laterFeedOf(stub));
  const w = await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_1' }); });
  setTimeout(() => stub.outcome('msg_1', 'succeeded'), 300);
  setTimeout(() => stub.outcome('msg_1', 'failed'), 800);
  const { waitedMs } = await o.laterWait({ capMs: 1500 });
  assert.ok(waitedMs >= 1400 && waitedMs <= 1500, String(waitedMs));
  assert.deepEqual(await laterAt(o), { clear: true, records: [{ of: w.events[0].seq, outcome: 'succeeded' }, { of: w.events[0].seq, outcome: 'failed' }] });
  const idle = await observe(t, laterFeedOf(await startStub(t)));
  assert.deepEqual(await idle.laterWait({ capMs: 1500 }), { waitedMs: 0 });
  assert.deepEqual(await observe(t, feedOf(await startStub(t))).then(x => x.laterWait({ capMs: 1500 })), { waitedMs: 0 }, 'a feed without outcomes never waits');
});

test('later: "outcome" is a key of outcome entries only, and an outcome never makes its message a duplicate', async t => {
  const stub = await startStub(t);
  const o = await observe(t, laterFeedOf(stub));
  const carrying = await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_1', fields: { outcome: 'succeeded' } }); });
  assert.match(carrying.reason, /provider-feed-field-unknown/);
  const twice = await windowOf(o, stub, async () => { stub.outcome('msg_1', 'deferred'); stub.outcome('msg_1', 'succeeded'); });
  assert.deepEqual([twice.coverage, twice.reason], ['complete', null]);
});

test('later, fail closed: a feed that does not declare outcomes reads an outcome entry as an unknown type, and seals nothing', async t => {
  const stub = await startStub(t);
  const o = await observe(t, feedOf(stub));
  await windowOf(o, stub, async () => { stub.accept([VIP], { messageId: 'msg_1' }); });
  const w = await windowOf(o, stub, async () => { stub.outcome('msg_1', 'failed'); });
  assert.match(w.reason, /provider-feed-type-unknown/);
  assert.equal(o.laterRecords(await o.mark()), null);
  assert.equal(o.scope.feed.outcomes, undefined);
  assert.deepEqual((await observe(t, laterFeedOf(await startStub(t)))).scope.feed.outcomes, { waitMs: 2000 });
});
