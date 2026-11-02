// Provider feed end to end: an app whose vendor SDK sends mail straight to its provider (a loopback stub here),
// observed only through the provider's own signed feed. The connector runs the witness, settlement decides what the
// records cannot place, and the run validator binds the sealed windows. Every request goes to 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { COLLECTOR_RECORDS } from '../src/collector-identity.mjs';
import { providerFeedRecord } from '../src/provider-feed-rules.mjs';
import { witnessCloseMs, TIMING_REQUEST_MS } from '../src/http-timing.mjs';
import { PROVIDER_FEED_REQUEST_MS } from '../src/provider-feed-rules.mjs';
import { startStub } from '../integrations/observers/fixtures/provider-stub.mjs';
import { digest } from '../src/domain.mjs';
import { bindSealedWindows } from '../src/http-effects.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';

const EXT = 'customers.example', WITNESS = 'witness.scopehaven.invalid', VIP = `vip@${EXT}`;
const AISHA = `aisha@${EXT}`;
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// The app: /notify sends at once, /late-notify answers and sends later, /hold answers late and sends nothing, /noop
// sends nothing. Its witness route takes WITNESS_DELAY_MS before it mails the witness, like a slow mail path.
const WITNESS_DELAY_MS = 800;
async function mailApp(t, stub, { lateMs = 650, holdMs = 0, other = null, job = null } = {}) {
  const server = createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return send(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return send(200, { user: 'ops' });
    if (url.pathname === '/ping') { await sleep(WITNESS_DELAY_MS); stub.accept([`${url.searchParams.get('scopehaven_witness')}@${WITNESS}`]); return send(200, { ok: true }); }
    if (url.pathname === '/notify') { stub.accept([VIP]); return send(200, { ok: true }); }
    if (url.pathname === '/late-notify') { setTimeout(() => stub.accept([VIP]), lateMs); return send(200, { ok: true }); }
    if (url.pathname === '/hold') { await sleep(holdMs); return send(200, { ok: true }); }
    if (url.pathname === '/noop') return send(200, { ok: true });
    // Later outcomes: the provider accepts the mail now and posts its later word laterMs after (a bounce by default).
    if (url.pathname === '/notify-later') { const id = JSON.parse(stub.accept([VIP]).body).messageId; setTimeout(() => stub.outcome(id, url.searchParams.get('word') ?? 'failed'), lateMs); return send(200, { ok: true }); }
    // The provider accepts mail to VIP and says it succeeded; laterMs after, the app mails another customer, also delivered at once.
    if (url.pathname === '/notify-then-mail') {
      stub.outcome(JSON.parse(stub.accept([VIP]).body).messageId, 'succeeded');
      setTimeout(() => stub.outcome(JSON.parse(stub.accept([`late@${EXT}`]).body).messageId, 'succeeded'), lateMs);
      return send(200, { ok: true });
    }
    if (url.pathname === '/refused') { stub.reject([VIP]); return send(200, { ok: true }); }
    // Later outcomes: delivered at once, then a delayed bounce lateMs after (succeed, then fail).
    if (url.pathname === '/notify-delivered-then-bounced') { const id = JSON.parse(stub.accept([VIP]).body).messageId; stub.outcome(id, 'succeeded'); setTimeout(() => stub.outcome(id, 'failed'), lateMs); return send(200, { ok: true }); }
    // An entry signed with a key that is not the stub's: the feed faults.
    if (url.pathname === '/forge') { stub.accept([VIP], { key: generateKeyPairSync('ed25519').privateKey }); return send(200, { ok: true }); }
    if (url.pathname === '/notify-other') { for (let i = 0; i < 3; i++) other.accept([VIP]); return send(200, { ok: true }); }
    // A background job that keeps mailing for jobMs after the request, one email every 150 ms.
    if (url.pathname === '/mail-job') { const until = Date.now() + Number(url.searchParams.get('ms')); const tick = () => { if (Date.now() < until) { stub.accept([`job@${EXT}`]); setTimeout(tick, 150); } }; tick(); return send(200, { ok: true }); }
    // The same job, ended by the test instead of a clock started here: it mails until job.until, which the test sets from the run-end
    // drain's start.
    if (url.pathname === '/mail-job-until') { const tick = () => { if (Date.now() < job.until) { stub.accept([`job@${EXT}`]); setTimeout(tick, 150); } }; tick(); return send(200, { ok: true }); }
    // Templates: the case's own email plus a background job's ticket update to the same customer, each through its template.
    const mail = template => stub.accept([VIP], template === undefined ? {} : { fields: { template } });
    if (url.pathname === '/cancel') { mail('tmpl-order-cancelled'); mail('tmpl-ticket-update'); return send(200, { ok: true }); }
    if (url.pathname === '/cancel-twice') { mail('tmpl-order-cancelled'); mail('tmpl-ticket-update'); mail('tmpl-order-cancelled'); return send(200, { ok: true }); }
    if (url.pathname === '/ticket') { mail('tmpl-ticket-update'); return send(200, { ok: true }); }
    if (url.pathname === '/untemplated') { mail(); return send(200, { ok: true }); }
    if (url.pathname === '/variant-twice') { mail('tmpl-order-cancelled'); mail('TMPL-ORDER-CANCELLED'); return send(200, { ok: true }); }
    // Late entries: the case's email now, and a background ticket update (or the same template) after the witness request.
    if (url.pathname === '/cancel-late-ticket') { mail('tmpl-order-cancelled'); setTimeout(() => mail('tmpl-ticket-update'), lateMs); return send(200, { ok: true }); }
    if (url.pathname === '/cancel-late-same') { mail('tmpl-order-cancelled'); setTimeout(() => mail('tmpl-order-cancelled'), lateMs); return send(200, { ok: true }); }
    // The lift: the case's email to VIP now, and a background ticket update to another customer late.
    if (url.pathname === '/cancel-late-other') { mail('tmpl-order-cancelled'); setTimeout(() => stub.accept([AISHA], { fields: { template: 'tmpl-ticket-update' } }), lateMs); return send(200, { ok: true }); }
    return send(404, {});
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const exists = { kind: 'effect.exists', select: { source: 'provider-feed', operation: 'send', name: EXT, resource: VIP } };
const none = { kind: 'effect.none', select: { source: 'provider-feed', operation: 'send', name: EXT, resource: VIP } };
const check = (id, path, effects, severity = 'high') => ({ id, title: id, category: 'mail', severity, actorId: 'ops', method: 'POST', path, body: {}, evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }], effects });
// The feed is the signed provider stub, declared as one (keySource "stub"): an undeclared key source never supports a pass.
const profileOf = (origin, stub, checks, feedExtra = {}) => ({ id: 'mail', name: 'Mail', applicationId: 'mail', origin, buildLabel: 'b1', contextId: 'synthetic-mail',
  actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
  observers: [{ id: 'mail', type: 'provider-feed', feedId: stub.feedId, feed: { endpoint: { port: stub.port, path: stub.path } }, publicKey: stub.publicKey,
    domains: [{ domain: EXT, addresses: [VIP] }], routing: 'provider', witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: WITNESS }, witnessWaitMs: 2000, quietMs: 300, pollMs: 25, settleMs: 250, keySource: 'stub', ...feedExtra }],
  checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] }, ...checks] });
// required: further required controls (an allowed-use control with a positive effect guards an unpinned absence).
async function run(t, checks, app, feedExtra, required = []) {
  const stub = await startStub(t);
  const p = profileOf(await mailApp(t, stub, app), stub, checks, feedExtra);
  p.requiredControlIds.push(...required);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  return { p, stub, run: await runHttpAssessment(p, { env }) };
}
const rowOf = (r, id) => r.results.find(x => x.id === id);
const effectRow = (r, id) => rowOf(r, id).assertions.find(a => a.name === 'Observed effect 1 (effect.exists)' || a.name === 'Observed effect 1 (effect.none)');

test('allowed: a send through the provider passes effect.exists, a clean check passes effect.none once paired, and the validator binds both', async t => {
  // SENDS is an allowed-use control: it shows the pinned selector can match (positive pairing), so CLEAN's absence can pass.
  const { p, run: r } = await run(t, [check('SENDS', '/notify', [exists], 'control'), check('CLEAN', '/noop', [none])]);
  assert.deepEqual([rowOf(r, 'SENDS').status, rowOf(r, 'CLEAN').status], ['pass', 'pass'], JSON.stringify([effectRow(r, 'SENDS'), effectRow(r, 'CLEAN')]));
  assert.equal(effectRow(r, 'CLEAN').custody, 'independent');
  assert.deepEqual(r.observers, [{ id: 'mail', type: 'provider-feed', settleMs: 250, collector: COLLECTOR_RECORDS['provider-feed'], witnessed: true, feed: providerFeedRecord(p.observers[0]) }]);
  assert.deepEqual(rowOf(r, 'CLEAN').trace[1].data.windows[0].scope.feed, r.observers[0].feed);
  assert.equal(COLLECTOR_RECORDS['provider-feed'].label, 'provider-feed/8');
  assert.ok(!r.limitations.some(l => l.includes('declares templates')), 'the template sentence only with a vocabulary');
  assert.ok(r.limitations.some(l => l.startsWith('Provider feeds (mail: loopback endpoint, witness') && l.includes('real provider APIs (Postmark, SendGrid, Mailgun, Stripe) are not read directly')));
  const sealed = rowOf(r, 'CLEAN').trace[1].data.windows[0];
  assert.deepEqual([sealed.source, sealed.lineage, sealed.coverage], ['provider-feed', { observer: 'provider-feed-reader', independence: 'provider-record' }, 'complete']);
  validateHttpRunEvidence(r);
  // A run record that says the feed had no witness cannot carry its authoritative windows.
  const unwitnessed = structuredClone(r); unwitnessed.observers[0].witnessed = false;
  // (Its windows are refused, and so is its feed drain: an unwitnessed feed never drains.)
  assert.throws(() => validateHttpRunEvidence(unwitnessed), error => error.code === 'invalid-run-evidence' && ['effect-trace', 'settlement-drains'].includes(error.detail));
  const missing = structuredClone(r); delete missing.observers[0].witnessed;
  // The run record of a provider feed must say whether it had a witness.
  assert.throws(() => validateHttpRunEvidence(missing), error => error.code === 'invalid-run-evidence');
  // A run record naming another key (or feed) than its sealed windows is refused.
  const rekeyed = structuredClone(r); rekeyed.observers[0].feed.keyDigest = '0'.repeat(64);
  assert.throws(() => validateHttpRunEvidence(rekeyed), error => error.code === 'invalid-run-evidence' && error.detail === 'effect-trace');
  // Timing counts the provider feed's witness close like the sinks'.
  assert.equal(witnessCloseMs(p.observers, p.actors), TIMING_REQUEST_MS + 2000 + 10 * 300 + 3 * PROVIDER_FEED_REQUEST_MS);
});

test('a send the records cannot place never passes either check it could belong to (boundary checks)', async t => {
  // A's send is stamped after A's witness request (and before the witness mail): A is partial (missing), and B's own
  // send of the same selector also fits A's, so settlement withholds B's pass (effect-ambiguous-attribution).
  const late = await run(t, [check('A', '/late-notify', [exists]), check('B', '/notify', [exists])]);
  assert.deepEqual([rowOf(late.run, 'A').status, rowOf(late.run, 'B').status], ['inconclusive', 'inconclusive'], JSON.stringify([effectRow(late.run, 'A'), effectRow(late.run, 'B')]));
  assert.match(rowOf(late.run, 'A').trace[1].data.windows[0].reason, /provider-feed-entry-after-witness-request/);
  assert.equal(effectRow(late.run, 'B').settlement, 'effect-ambiguous-attribution');
  validateHttpRunEvidence(late.run);
  // A's send arrives after A's window closed, inside B's: A's complete window shows nothing (a fail stays a fail), and
  // B's pass rests only on a send that fits A's selector, so it is withheld.
  const into = await run(t, [check('A', '/late-notify', [exists]), check('B', '/hold', [exists])], { lateMs: 2400, holdMs: 2500 });
  assert.deepEqual([rowOf(into.run, 'A').status, rowOf(into.run, 'B').status], ['fail', 'inconclusive'], JSON.stringify([effectRow(into.run, 'A'), effectRow(into.run, 'B')]));
  assert.equal(effectRow(into.run, 'B').settlement, 'effect-ambiguous-attribution');
});

// Template binding end to end: a background ticket update to the customer in the case's
// own window no longer decides a template-bound clause, and the run record carries labels only.
const TEMPLATES = Object.freeze({ order_cancelled: 'tmpl-order-cancelled', ticket_update: 'tmpl-ticket-update', refund_confirmation: 'd-0c1f43daeeaef504760851f727007e0b' });
const mailTo = template => ({ source: 'provider-feed', operation: 'send', name: EXT, resource: VIP, fields: [{ pointer: '/template', equals: template }] });
const countOne = { kind: 'effect.count', expected: 1, select: mailTo('order_cancelled') };
const only = { kind: 'effect.only', expect: [{ select: mailTo('order_cancelled'), count: 1 }], allow: [mailTo('ticket_update')] };
const assertionOf = (r, id, i, kind) => rowOf(r, id).assertions.find(a => a.name === `Observed effect ${i} (${kind})`);
// A stored run is JSON: forge on a JSON copy, so no two records share an object.
const reseal = (run, id, mutate) => { const forged = JSON.parse(JSON.stringify(run)), fx = forged.results.find(x => x.id === id); mutate(forged, fx); fx.evidenceDigest = digest({ evidence: fx.trace[0].data, effects: fx.trace[1].data, assertions: fx.assertions }); return forged; };

test('feed templates: a template-bound count decides beside other-template mail to the same customer, settles past it, and the validator binds the labels', async t => {
  const { p, run: r } = await run(t, [check('CANCEL', '/cancel', [countOne]), check('TICKET', '/ticket', [{ kind: 'effect.exists', select: mailTo('ticket_update') }])], undefined, { templates: TEMPLATES });
  // The later ticket update reads "no" under order_cancelled, so settlement does not withhold CANCEL's count.
  assert.deepEqual([rowOf(r, 'CANCEL').status, rowOf(r, 'TICKET').status], ['pass', 'pass'], JSON.stringify([assertionOf(r, 'CANCEL', 1, 'effect.count'), assertionOf(r, 'TICKET', 1, 'effect.exists')]));
  assert.equal(assertionOf(r, 'CANCEL', 1, 'effect.count').custody, 'independent');
  assert.deepEqual(r.observers, [{ id: 'mail', type: 'provider-feed', settleMs: 250, capture: { [EXT]: ['/template'] }, collector: COLLECTOR_RECORDS['provider-feed'], witnessed: true, feed: providerFeedRecord(p.observers[0]) }]);
  assert.deepEqual(r.observers[0].feed.templates, ['order_cancelled', 'refund_confirmation', 'ticket_update']);
  for (const id of Object.values(TEMPLATES)) assert.ok(!JSON.stringify(r).includes(id), 'no provider template id in the run');
  assert.ok(r.limitations.some(l => l.includes('A feed that declares templates also reads one signed contract field') && l.includes('a run stores only the operator label of a declared id')));
  validateHttpRunEvidence(r);
  const refused = (forged, detail) => assert.throws(() => validateHttpRunEvidence(forged), error => error.code === 'invalid-run-evidence' && (detail === undefined || error.detail === detail));
  // A stored label the run record does not list is refused, even resealed.
  refused(reseal(r, 'CANCEL', (_f, fx) => { fx.trace[1].data.windows[0].events[1].captured.values['/template'].value = 'weekly_digest'; }), 'effect-trace');
  // The run record's labels and capture go together, under a collector that reads templates, and match every window.
  refused((() => { const f = structuredClone(r); delete f.observers[0].capture; return f; })());
  refused((() => { const f = structuredClone(r); delete f.observers[0].feed.templates; return f; })());
  refused((() => { const f = structuredClone(r); f.observers[0].collector.label = 'provider-feed/1'; return f; })());
  refused((() => { const f = structuredClone(r); f.observers[0].feed.templates = ['order_cancelled', 'ticket_update']; return f; })(), 'effect-trace');
  refused((() => { const f = structuredClone(r); f.observers[0].capture = { [EXT]: ['/amount'] }; return f; })());
});

test('feed templates: mail with no template after a template-bound pass withholds it (settlement); effect.only allows the background mail only by its template', async t => {
  const late = await run(t, [check('CANCEL', '/cancel', [countOne]), check('LATER', '/untemplated', [exists])], undefined, { templates: TEMPLATES });
  // The later mail reads unknown under order_cancelled: it may be this check's late email.
  assert.equal(rowOf(late.run, 'CANCEL').status, 'inconclusive');
  assert.equal(assertionOf(late.run, 'CANCEL', 1, 'effect.count').settlement, 'effect-outside-window');
  validateHttpRunEvidence(late.run);
  // effect.only: the case's own email is expected once and the ticket update is allowed by its template; a second case email is beyond count.
  // SENDS, a required allowed-use control with a positive effect, guards the effect.only clauses, which pin nothing.
  const o = await run(t, [check('SENDS', '/notify', [exists], 'control'), check('TWICE', '/cancel-twice', [only]), check('ONCE', '/cancel', [only])], undefined, { templates: TEMPLATES }, ['SENDS']);
  assert.deepEqual([rowOf(o.run, 'TWICE').status, rowOf(o.run, 'ONCE').status], ['fail', 'pass'], JSON.stringify([assertionOf(o.run, 'TWICE', 1, 'effect.only'), assertionOf(o.run, 'ONCE', 1, 'effect.only')]));
  assert.match(assertionOf(o.run, 'TWICE', 1, 'effect.only').actual ?? JSON.stringify(assertionOf(o.run, 'TWICE', 1, 'effect.only')), /beyond-count/);
  validateHttpRunEvidence(o.run);
});

test('feed templates: a template-pinned expect keeps a recipient-only allow from absorbing an unknown-template send, end to end', async t => {
  const recipientOnly = { kind: 'effect.only', expect: [{ select: mailTo('order_cancelled'), count: 1 }], allow: [{ source: 'provider-feed', operation: 'send', name: EXT, resource: VIP }] };
  const o = await run(t, [check('KNOWN', '/cancel-twice', [recipientOnly]), check('VARIANT', '/variant-twice', [recipientOnly])], undefined, { templates: TEMPLATES });
  assert.deepEqual([rowOf(o.run, 'KNOWN').status, rowOf(o.run, 'VARIANT').status], ['fail', 'inconclusive'], JSON.stringify([assertionOf(o.run, 'KNOWN', 1, 'effect.only'), assertionOf(o.run, 'VARIANT', 1, 'effect.only')]));
  validateHttpRunEvidence(o.run);
});

test('feed templates: when the profile loads, a template pin on a feed domain must name one of that feed\'s labels', async t => {
  const stub = await startStub(t);
  const load = (effects, feedExtra = { templates: TEMPLATES }, claims) => () => validateTargetFile({ schemaVersion: 1, targets: [profileOf('http://127.0.0.1:4400', stub, [{ ...check('C', '/cancel', effects), ...(claims ? { claims } : {}) }], feedExtra)] });
  const pinned = (op, value, extra = {}) => ({ source: 'provider-feed', operation: 'send', name: EXT, resource: VIP, fields: [{ pointer: '/template', [op]: value }], ...extra });
  load([{ kind: 'effect.none', select: pinned('equals', 'refund_confirmation') }])();
  load([{ kind: 'effect.only', expect: [{ select: pinned('in', ['order_cancelled']), count: 1 }], allow: [pinned('in', ['ticket_update', 'refund_confirmation'])] }])();
  const refused = (fn, pattern) => assert.throws(fn, pattern);
  refused(load([{ kind: 'effect.none', select: pinned('equals', 'order_canceled') }]), /not a label provider-feed observer "mail" declares/);
  refused(load([{ kind: 'effect.none', select: pinned('equals', 'tmpl-order-cancelled') }]), /never a provider id/);
  // A member of another type would hold every send's template unknown (body-fields crossState): refused, not read as a silent missing.
  refused(load([{ kind: 'effect.none', select: pinned('in', ['order_cancelled', true]) }]), /to true, which is not a label/);
  refused(load([{ kind: 'effect.none', select: pinned('in', ['order_cancelled', 2]) }]), /to 2, which is not a label/);
  refused(load([{ kind: 'effect.only', expect: [{ select: pinned('equals', 'order_cancelled'), count: 1 }], allow: [pinned('in', ['ticket_update', 'weekly_digest'])] }]), /weekly_digest/);
  // A selector without a source is seen by the feed too.
  const { source: _source, ...free } = pinned('equals', 'order_canceled');
  refused(load([{ kind: 'effect.none', select: free }]), /order_canceled/);
  refused(load([{ kind: 'effect.none', select: pinned('equals', 'order_cancelled') }], {}), /declares no "templates"/);
  refused(load([], { templates: TEMPLATES }, [{ trigger: { field: { pointer: '/status', success: ['cancelled'], refusal: ['refused'] } }, select: pinned('equals', 'order_cancel') }]), /order_cancel/);
});

// Late entries end to end: a background ticket update to the customer arrives after the witness
// request. It is a scoped entry with its own signed template, outside the case's template-bound clause; the run-end feed drain (or
// a later window of the feed) follows it, and the validator binds the entry and the drain.
const LATE_CODE = 'provider-feed-entry-after-witness-request';
test('feed late entries: a late other-template email to the customer leaves a template-bound count decided, followed by the drain or a later window', async t => {
  const { run: r } = await run(t, [check('CANCEL', '/cancel-late-ticket', [countOne])], undefined, { templates: TEMPLATES });
  assert.equal(rowOf(r, 'CANCEL').status, 'pass', JSON.stringify(assertionOf(r, 'CANCEL', 1, 'effect.count')));
  const own = rowOf(r, 'CANCEL').trace[1].data.windows[0];
  assert.deepEqual([own.coverage, own.reason, own.scoped.map(e => [e.name, e.resource, e.codes, e.captured?.values['/template']])], ['partial', LATE_CODE, [[EXT, VIP, [LATE_CODE], { type: 'string', value: 'ticket_update' }]]]);
  assert.deepEqual(r.settlement.drains.map(d => [d.instanceId, d.quiescent, d.markClear, d.closedAfterCollect]), [['provider-feed-mail', true, true, false]]);
  assert.equal(r.observers[0].collector.label, 'provider-feed/8');
  validateHttpRunEvidence(r);
  const refused = (forged, detail) => assert.throws(() => validateHttpRunEvidence(forged), error => error.code === 'invalid-run-evidence' && (detail === undefined || error.detail === detail));
  // Without the drain the last check's late entry is unfollowed: the window reads window-wide, so the stored pass is refused.
  refused((() => { const f = structuredClone(r); delete f.settlement.drains; return f; })(), 'effect-verdict');
  // The lone entry's record must agree with its own event in the gap after the check, and its seq must follow the window's events.
  refused(reseal(r, 'CANCEL', (_f, fx) => { fx.trace[1].data.windows[0].scoped[0].captured.values['/template'].value = 'refund_confirmation'; }), 'effect-trace');
  refused(reseal(r, 'CANCEL', (_f, fx) => { fx.trace[1].data.windows[0].scoped[0].seq = 1; }), 'effect-trace');
  // Scoped feed windows bind only under provider-feed/3, on a witnessed endpoint feed.
  const sealed = rowOf(r, 'CANCEL').trace[1].data.windows;
  bindSealedWindows(structuredClone(sealed), r.observers, { scoped: true });
  for (const forged of [{ ...r.observers[0], collector: { ...r.observers[0].collector, label: 'provider-feed/2' } }, { ...r.observers[0], witnessed: false }])
    assert.throws(() => bindSealedWindows(structuredClone(sealed), [forged], { scoped: true }), /effect-trace/);
  // Even a consistent presence-only record (no witness, presence-only window) cannot carry scoped entries.
  const presence = structuredClone(sealed); presence[0].scope = { ...presence[0].scope, evidence: 'presence-only' };
  assert.throws(() => bindSealedWindows(presence, [{ ...r.observers[0], witnessed: false }], { scoped: true }), /effect-trace/);
  // The same template late reads missing: it may be this check's own email.
  const same = await run(t, [check('CANCEL', '/cancel-late-same', [countOne])], undefined, { templates: TEMPLATES });
  assert.equal(rowOf(same.run, 'CANCEL').status, 'inconclusive');
  validateHttpRunEvidence(same.run);
  // A later window of the feed follows the first check's late entry; the ticket check's own email reads "no" under order_cancelled.
  const two = await run(t, [check('CANCEL', '/cancel-late-ticket', [countOne]), check('TICKET', '/ticket', [{ kind: 'effect.exists', select: mailTo('ticket_update') }])], undefined, { templates: TEMPLATES });
  assert.deepEqual([rowOf(two.run, 'CANCEL').status, rowOf(two.run, 'TICKET').status], ['pass', 'pass'], JSON.stringify([assertionOf(two.run, 'CANCEL', 1, 'effect.count'), assertionOf(two.run, 'TICKET', 1, 'effect.exists')]));
  validateHttpRunEvidence(two.run);
});

test('feed late entries: a quiescent feed drain whose final mark then fails is recorded as following nothing, so the run the connector makes validates', { timeout: 60000 }, async t => {
  // The drain ends quiescent, then the signed head cannot be fetched at the final mark (a 404).
  const stub = await startStub(t);
  const p = profileOf(await mailApp(t, stub), stub, [check('SENDS', '/notify', [exists], 'control')]);
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const observerFactory = (configs, opts) => buildObservers(configs, opts).map(o => {
    if (o.source !== 'provider-feed') return o;
    const drain = o.drain.bind(o);
    o.drain = async a => { const r = await drain(a); stub.control.headMode = 'missing'; return r; };
    return o;
  });
  const r = await runHttpAssessment(p, { env, observerFactory });
  assert.deepEqual(r.settlement.gaps.at(-1).windows.map(w => [w.instanceId, w.coverage]), [['provider-feed-mail', 'failed']]);
  assert.deepEqual(r.settlement.drains.map(d => [d.instanceId, d.quiescent, d.markClear]), [['provider-feed-mail', false, false]]);
  validateHttpRunEvidence(r);
});

// The lift end to end: the case expects its own order_cancelled email to VIP; a background
// ticket update to another customer lands after the witness request, the window's only late entry. Its own signed template matches
// the template-pinned allow, so under provider-feed/4 the effect.only clause is covered. A stored provider-feed/3 run of the same shape
// keeps the semantics it was judged with: it validates and reads missing.
test('feed lift: a lone late background email lifts by its own template under provider-feed/4; a provider-feed/3 run keeps reading missing', { timeout: 120000 }, async t => {
  const onlyOwn = { kind: 'effect.only', expect: [{ select: mailTo('order_cancelled'), count: 1 }], allow: [{ source: 'provider-feed', operation: 'send', name: EXT, resource: AISHA, fields: [{ pointer: '/template', in: ['ticket_update'] }] }] };
  const shape = { templates: TEMPLATES, domains: [{ domain: EXT, addresses: [VIP, AISHA] }] };
  const runOf = async (settlement, observerFactory) => {
    const stub = await startStub(t);
    // SENDS, a required allowed-use control with a positive effect, guards CASE's effect.only, which pins nothing.
    const base = profileOf(await mailApp(t, stub), stub, [check('SENDS', '/notify', [exists], 'control'), check('CASE', '/cancel-late-other', [onlyOwn])], shape);
    const p = { ...base, requiredControlIds: [...base.requiredControlIds, 'SENDS'], ...(settlement ? { settlement } : {}) };
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    return runHttpAssessment(p, { env, ...(observerFactory ? { observerFactory } : {}) });
  };
  const only = r => assertionOf(r, 'CASE', 1, 'effect.only');
  const judge = { mode: 'run', outsideWindow: 'judge' };
  const lifted = await runOf(judge);
  const own = rowOf(lifted, 'CASE').trace[1].data.windows[0];
  assert.deepEqual(own.scoped.map(e => [e.resource, e.captured?.values['/template']?.value]), [[AISHA, 'ticket_update']]);
  assert.equal(rowOf(lifted, 'CASE').status, 'pass', JSON.stringify(only(lifted)));
  assert.equal(lifted.observers[0].collector.label, 'provider-feed/8');
  validateHttpRunEvidence(lifted);
  // Without the judge declaration the run-level settlement rule still withholds the pass on the later committed send (unchanged).
  const plain = await runOf(null);
  assert.equal(rowOf(plain, 'CASE').status, 'inconclusive');
  assert.equal(only(plain).settlement, 'effect-outside-window');
  validateHttpRunEvidence(plain);
  // A feed that does not take the lift (as a provider-feed/3 build) is recorded under provider-feed/3 by the connector itself, from
  // the same flag it judged with: the run validates and reads missing. The lifted /4 verdict under a /3 label is refused.
  const asV3 = (configs, opts) => buildObservers(configs, opts).map(o => { if (o.source === 'provider-feed') o.templateLift = false; return o; });
  const v3 = await runOf(judge, asV3);
  assert.equal(v3.observers[0].collector.label, 'provider-feed/3');
  assert.equal(rowOf(v3, 'CASE').status, 'inconclusive', JSON.stringify(only(v3)));
  validateHttpRunEvidence(JSON.parse(JSON.stringify(v3)));
  const relabelled = JSON.parse(JSON.stringify(lifted)); relabelled.observers[0].collector.label = 'provider-feed/3';
  assert.throws(() => validateHttpRunEvidence(relabelled), error => error.code === 'invalid-run-evidence' && error.detail === 'effect-verdict');
});

// Later outcomes (provider-feed/5 seals the provider's later words in the settlement record, and
// under provider-feed/6 the later-outcome stage reads them): the run validator binds them to sealed sends and recomputes what they decide.
const laterExtra = waitMs => ({ outcomes: { waitMs } });

test('later end to end: a bounce the provider posts after the check is sealed, withholds the control that expected it, and the validator binds it', { timeout: 60000 }, async t => {
  const { run: r } = await run(t, [check('SENDS', '/notify-later', [exists], 'control'), check('CLEAN', '/noop', [none])], { lateMs: 400 }, laterExtra(2500));
  // The control's expected email bounced: withheld and tagged (the stage never fails a control). CLEAN's absence still passes: its pairing
  // twin matched an accepted send, which shows the selector selects, whatever the provider did with it later.
  assert.deepEqual([rowOf(r, 'SENDS').status, rowOf(r, 'CLEAN').status], ['inconclusive', 'pass'], JSON.stringify([effectRow(r, 'SENDS'), effectRow(r, 'CLEAN')]));
  assert.equal(effectRow(r, 'SENDS').later, 'effect-later-failed');
  assert.equal(r.observers[0].collector.label, 'provider-feed/8');
  assert.deepEqual(r.observers[0].feed.outcomes, { waitMs: 2500 });
  const sent = rowOf(r, 'SENDS').trace[1].data.windows[0].events.find(e => e.resource === VIP);
  assert.equal(r.settlement.later.length, 1);
  const [later] = r.settlement.later;
  assert.deepEqual([later.instanceId, later.clear, later.records], ['provider-feed-mail', true, [{ of: sent.seq, outcome: 'failed' }]]);
  assert.ok(later.waitedMs > 0 && later.waitedMs <= 2500, String(later.waitedMs));
  assert.ok(r.limitations.some(l => l.includes('A feed that declares outcomes (mail: later wait up to 2500 ms)')));
  validateHttpRunEvidence(r);
  const edited = edit => { const x = structuredClone(r); edit(x); return x; };
  const refused = {
    'a record naming no sealed send': x => x.settlement.later[0].records.push({ of: 999999 * 128, outcome: 'failed' }),
    'a word outside the vocabulary': x => { x.settlement.later[0].records[0].outcome = 'bounced'; },
    'the list shed': x => { delete x.settlement.later; },
    'a waited time past the declaration': x => { x.settlement.later[0].waitedMs = 2501; },
    'the feed relabelled provider-feed/4': x => { x.observers[0].collector.label = 'provider-feed/4'; },
  };
  for (const [what, edit] of Object.entries(refused)) assert.throws(() => validateHttpRunEvidence(edited(edit)), error => error.code === 'invalid-run-evidence' && error.detail === 'settlement-later', what);
  // The verdict is recomputed from the records: a success in place of the bounce reads pass, so the stored withholding is refused.
  assert.throws(() => validateHttpRunEvidence(edited(x => { x.settlement.later[0].records[0].outcome = 'succeeded'; })), error => error.code === 'invalid-run-evidence' && error.detail === 'effect-verdict');
});

test('later, no upgrade: with waitMs 0 and no outcome entries, every verdict and window reads as without outcomes', { timeout: 60000 }, async t => {
  const checks = [check('SENDS', '/notify', [exists], 'control'), check('CLEAN', '/noop', [none])];
  const plain = (await run(t, checks)).run, declared = (await run(t, checks, {}, laterExtra(0))).run;
  const verdicts = r => r.results.map(x => [x.id, x.status, x.assertions.map(a => [a.name, a.status, a.custody ?? null, a.settlement ?? null, a.pairing ?? null])]);
  assert.deepEqual(verdicts(declared), verdicts(plain));
  const windows = r => r.results.filter(x => x.trace.length === 2).flatMap(x => x.trace[1].data.windows.map(w => [w.coverage, w.reason, w.events.map(e => [e.resource, e.outcome])]));
  assert.deepEqual(windows(declared), windows(plain));
  const drains = r => r.settlement.drains.map(d => [d.instanceId, d.quiescent, d.markClear, d.closedAfterCollect]);
  assert.deepEqual(drains(declared), drains(plain));
  assert.deepEqual(declared.settlement.later, [{ instanceId: 'provider-feed-mail', clear: true, waitedMs: 0, records: [] }]);
  assert.equal(Object.hasOwn(plain.settlement, 'later'), false);
  validateHttpRunEvidence(declared);
});

test('later: the later wait never widens a drain: a job mailing past the feed drain cap leaves the drain not quiescent within its own cap', { timeout: 120000 }, async t => {
  // The feed drain's cap is 10 x quietMs + 2 x 2000 = 7000 ms. The job mails from JOB's request until 1000 ms past the drain's cap, timed
  // from the moment the drain starts (seen through the observer factory), not from the request: however long the check window takes
  // on a loaded host, the job outlasts the drain's own cap, and it stops well within a 4000 ms later wait.
  const checks = [check('SENDS', '/notify', [exists], 'control'), check('JOB', '/mail-job-until', [none])];
  const drainRun = async feedExtra => {
    const stub = await startStub(t), job = { until: Date.now() + 60000 };
    const p = profileOf(await mailApp(t, stub, { job }), stub, checks, feedExtra);
    validateTargetFile({ schemaVersion: 1, targets: [p] });
    const observerFactory = (configs, opts) => buildObservers(configs, opts).map(o => {
      if (o.source !== 'provider-feed') return o;
      const drain = o.drain.bind(o);
      o.drain = args => { job.until = Date.now() + 7000 + 1000; return drain(args); };
      return o;
    });
    return runHttpAssessment(p, { env, observerFactory });
  };
  const plain = await drainRun(), declared = await drainRun(laterExtra(4000));
  for (const r of [plain, declared]) {
    assert.deepEqual(r.settlement.drains.map(d => [d.instanceId, d.quiescent]), [['provider-feed-mail', false]]);
    assert.ok(r.settlement.drains[0].waitedMs <= 7000, String(r.settlement.drains[0].waitedMs));
  }
  assert.ok(declared.settlement.later[0].waitedMs > 0);
  validateHttpRunEvidence(declared);
});

test('later records and the label fallback: only records of sends the run sealed are kept, and a feed that cannot read outcomes is recorded provider-feed/4', { timeout: 60000 }, async t => {
  // An observer whose records also name a send no sealed window holds (as for a send past an event cap): the connector drops that
  // record, so the run it makes validates.
  const stub = await startStub(t);
  const p = profileOf(await mailApp(t, stub, { lateMs: 300 }), stub, [check('SENDS', '/notify-later', [exists], 'control')], laterExtra(1500));
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const extra = (configs, opts) => buildObservers(configs, opts).map(o => {
    if (o.source !== 'provider-feed') return o;
    const read = o.laterRecords.bind(o);
    o.laterRecords = mark => { const r = read(mark); return r && { ...r, records: [...r.records, { of: 99999 * 128, outcome: 'failed' }] }; };
    return o;
  });
  const r = await runHttpAssessment(p, { env, observerFactory: extra });
  assert.deepEqual(r.settlement.later[0].records.map(x => x.outcome), ['failed']);
  validateHttpRunEvidence(r);
  // An observer that cannot read outcomes (an injected one, or an older build) is recorded under provider-feed/4 and carries no list.
  const stub2 = await startStub(t);
  const p2 = profileOf(await mailApp(t, stub2), stub2, [check('SENDS', '/notify', [exists], 'control')], laterExtra(1500));
  const blind = (configs, opts) => buildObservers(configs, opts).map(o => { if (o.source === 'provider-feed') { delete o.laterOutcomes; delete o.laterRecords; delete o.laterWait; } return o; });
  const old = await runHttpAssessment(p2, { env, observerFactory: blind });
  assert.equal(old.observers[0].collector.label, 'provider-feed/4');
  assert.deepEqual(old.observers[0].feed.outcomes, { waitMs: 1500 });
  assert.equal(Object.hasOwn(old.settlement, 'later'), false);
  validateHttpRunEvidence(old);
});

test('later: the later wait comes after every window, so a send during it is in no window and binds no record', { timeout: 60000 }, async t => {
  // SENDS mails VIP (delivered at once); 5 s later the app mails another customer, while the 8 s later wait runs after the final mark.
  const { run: r } = await run(t, [check('SENDS', '/notify-then-mail', [exists], 'control')], { lateMs: 5000 }, laterExtra(8000));
  const sealed = [...r.results.filter(x => x.trace.length === 2).flatMap(x => x.trace[1].data.windows), ...r.settlement.gaps.flatMap(g => g.windows)];
  const sends = sealed.filter(w => w.instanceId === 'provider-feed-mail').flatMap(w => w.events).filter(e => e.outcome === 'committed');
  assert.deepEqual(sends.map(e => e.resource), [VIP], 'the late mail is in no sealed window');
  assert.ok(r.settlement.later[0].waitedMs > 5000, String(r.settlement.later[0].waitedMs));
  assert.deepEqual(r.settlement.later[0].records, [{ of: sends[0].seq, outcome: 'succeeded' }]);
  assert.equal(r.settlement.later[0].clear, true);
  validateHttpRunEvidence(r);
});

test('later: the validator binds a record only to a committed send of its own feed', { timeout: 90000 }, async t => {
  const stub = await startStub(t), other = await startStub(t, { feedId: 'other-mail' });
  const p = profileOf(await mailApp(t, stub, { other }), stub, [check('SENDS', '/notify', [exists], 'control'), check('REFUSED', '/refused', [none]), check('OTHER', '/notify-other', [{ kind: 'effect.exists', select: { source: 'provider-feed', operation: 'send', name: EXT } }])], laterExtra(500));
  p.observers.push({ id: 'other', type: 'provider-feed', feedId: other.feedId, feed: { endpoint: { port: other.port, path: other.path } }, publicKey: other.publicKey, domains: [{ domain: EXT, addresses: [VIP] }], pollMs: 25, quietMs: 300, settleMs: 250 });
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const r = await runHttpAssessment(p, { env });
  validateHttpRunEvidence(r);
  const sealed = [...r.results.filter(x => x.trace.length === 2).flatMap(x => x.trace[1].data.windows), ...r.settlement.gaps.flatMap(g => g.windows)];
  const eventsOf = id => sealed.filter(w => w.instanceId === id).flatMap(w => w.events);
  const committed = new Set(eventsOf('provider-feed-mail').filter(e => e.outcome === 'committed').map(e => e.seq));
  const denied = eventsOf('provider-feed-mail').find(e => e.outcome === 'denied');
  const foreign = eventsOf('provider-feed-other').map(e => e.seq).find(seq => !committed.has(seq) && seq !== denied?.seq);
  assert.ok(denied && foreign, 'the run holds a refused send of this feed and a send of the other feed');
  for (const [what, of] of [['a refused send of its own feed', denied.seq], ['a send of another feed', foreign]]) {
    const x = structuredClone(r);
    x.settlement.later[0].records = [{ of, outcome: 'failed' }];
    assert.throws(() => validateHttpRunEvidence(x), error => error.code === 'invalid-run-evidence' && error.detail === 'settlement-later', what);
  }
});

test('later, a faulted feed is never clear: the connector writes clear false, and a run that says clear over a failed integrity window is refused', { timeout: 60000 }, async t => {
  const { run: r } = await run(t, [check('SENDS', '/notify', [exists], 'control'), check('FORGE', '/forge', [exists])], {}, laterExtra(500));
  assert.ok(r.settlement.gaps.flatMap(g => g.windows).some(w => w.instanceId === 'provider-feed-mail' && w.coverage === 'failed' && w.reason === 'provider-feed-integrity'));
  assert.equal(r.settlement.later[0].clear, false);
  validateHttpRunEvidence(r);
  const x = structuredClone(r); x.settlement.later[0].clear = true;
  assert.throws(() => validateHttpRunEvidence(x), error => error.code === 'invalid-run-evidence' && error.detail === 'settlement-later');
  // The declaration is refused under a label no build that knows it writes (and a /2 record cannot drain either).
  for (const label of ['provider-feed/1', 'provider-feed/2']) { const y = structuredClone(r); y.observers[0].collector.label = label; assert.throws(() => validateHttpRunEvidence(y), error => error.code === 'invalid-run-evidence', label); }
});

test('later stage over a real stub: a boundary check whose expected email the provider later bounces fails; delivered, it passes at the success strength', { timeout: 120000 }, async t => {
  const bounced = await run(t, [check('CASE', '/notify-later', [exists])], { lateMs: 400 }, laterExtra(2000));
  assert.deepEqual([rowOf(bounced.run, 'CASE').status, effectRow(bounced.run, 'CASE').later], ['fail', 'effect-later-failed'], JSON.stringify(effectRow(bounced.run, 'CASE')));
  validateHttpRunEvidence(bounced.run);
  const delayed = await run(t, [check('CASE', '/notify-delivered-then-bounced', [exists])], { lateMs: 600 }, laterExtra(2000));
  assert.deepEqual([rowOf(delayed.run, 'CASE').status, effectRow(delayed.run, 'CASE').later], ['fail', 'effect-later-failed'], 'a delayed bounce after delivery');
  validateHttpRunEvidence(delayed.run);
  const delivered = await run(t, [check('CASE', '/notify-later?word=succeeded', [exists])], { lateMs: 400 }, laterExtra(2000));
  assert.deepEqual([rowOf(delivered.run, 'CASE').status, effectRow(delivered.run, 'CASE').laterStrength], ['pass', 'succeeded']);
  validateHttpRunEvidence(delivered.run);
});
