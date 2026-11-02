// The later-outcome stage end to end with an injected feed observer, a fake transport and a virtual clock: the connector runs the stage, the
// run validator recomputes it, the lifecycle accepts a change check it withheld, and compareRuns credits a repair over
// a later failure only on a signed success. No socket: the provider feed itself is tested over a loopback stub elsewhere.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeEffect } from '../src/effect-events.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, PRECONDITION_ASSERTION, PRECONDITION_REASONS } from '../src/contracts.mjs';
import { compareRuns } from '../src/runner.mjs';
import { COLLECTOR_RECORDS } from '../src/collector-identity.mjs';
import { providerFeedRecord } from '../src/provider-feed-rules.mjs';
import { digest } from '../src/domain.mjs';

const EXT = 'customers.example', VIP = `vip@${EXT}`, KEN = `ken@${EXT}`, WITNESS = 'witness.scopehaven.invalid';
const KEY = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const FEED = { id: 'mail', type: 'provider-feed', feedId: 'mail', feed: { endpoint: { port: 40997, path: '/feed' } }, publicKey: KEY, domains: [{ domain: EXT, addresses: [VIP, KEN] }],
  routing: 'provider', witness: { actorId: 'admin', method: 'GET', path: '/ping', domain: WITNESS }, outcomes: { waitMs: 0 }, settleMs: 250, keySource: 'stub' };
const sel = resource => ({ source: 'provider-feed', operation: 'send', name: EXT, resource });
const me = (id, actorId) => ({ id, title: id, category: 'Allowed use', severity: 'control', actorId, method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: actorId }] });
const row = (r, id) => r.results.find(x => x.id === id);

// One run: routes mail to the recipients its path names (/mail/<local>), and the provider's later words for each send come from
// wordsFor(recipient). The feed observer is injected: it reports the run's sends in the windows of the marks they fell between.
// coverage: what every feed window reads (a partial one carries a seq-gap reason); onRoute(route): called for each request (an app log line).
async function run(p, wordsFor, { transportExtra = () => null, coverage = 'complete', onRoute = () => {} } = {}) {
  let now = 0, seq = 0;
  const sends = [], tokens = { 'tok-admin': 'admin', 'tok-carol': 'carol' };
  let suspended = false;
  const transport = async (origin, request, { credential }) => {
    now += 10;
    const who = tokens[credential] ?? null, route = request.path.split('?')[0];
    onRoute(route);
    if (route === '/me') return who ? { status: 200, complete: true, jsonParsed: true, json: { user: who }, bytes: 10 } : { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (!who || (who === 'carol' && suspended)) return { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 };
    if (route.startsWith('/mail/')) sends.push({ at: now, seq: ++seq * 128, to: `${route.slice('/mail/'.length)}@${EXT}` });
    if (route === '/users/carol/suspend') { suspended = true; sends.push({ at: now, seq: ++seq * 128, to: VIP }); }
    return transportExtra(route) ?? { status: 200, complete: true, jsonParsed: true, json: { ok: true }, bytes: 11 };
  };
  const clock = { now: () => now, sleep: async ms => { now += ms; } };
  const fake = configs => configs.map(c => ({ kind: 'provider-feed-reader', instanceId: `provider-feed-${c.id}`, source: 'provider-feed', witnessRequest: null, templateLift: true, laterOutcomes: true,
    scope: { operations: ['send'], names: [EXT], actorAttribution: 'none', evidence: 'authoritative', feed: providerFeedRecord(c) }, async start() {}, async stop() {}, async mark() { return { at: now, headSeq: seq + 1 }; },
    async collect(from, to) { return { events: sends.filter(s => s.at > from.at && s.at <= to.at).map(s => makeEffect({ source: 'provider-feed', observer: { kind: 'provider-feed-reader', instanceId: `provider-feed-${c.id}` }, seq: s.seq, operation: 'send', name: EXT, resource: s.to, outcome: 'committed' })), coverage, reason: coverage === 'complete' ? null : 'provider-feed-entry-seq-gap' }; },
    async laterWait() { return { waitedMs: 0 }; },
    laterRecords() { return { clear: true, records: sends.flatMap(s => wordsFor(s.to).map(outcome => ({ of: s.seq, outcome }))) }; } }));
  return runHttpAssessment(p, { env: { SCOPEHAVEN_TARGET_A: 'tok-admin', SCOPEHAVEN_TARGET_C: 'tok-carol' }, clock, transport, observerFactory: fake });
}
const profile = checks => ({ id: 'later-stage', name: 'Later stage', applicationId: 'later-stage', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic',
  actors: { admin: { principalId: 'admin-1', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' } }, observers: [FEED], requiredControlIds: ['ADMIN-ME'], checks: [me('ADMIN-ME', 'admin'), ...checks] });
const CLAIM = { trigger: { field: { pointer: '/ok', success: [true], refusal: [false] } }, select: sel(KEN) };
const checks = [
  { id: 'CASE', title: 'CASE', category: 'Mail', severity: 'high', actorId: 'admin', method: 'POST', path: '/mail/vip', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: sel(VIP) }] },
  { id: 'CLAIMED', title: 'CLAIMED', category: 'Mail', severity: 'high', actorId: 'admin', method: 'POST', path: '/mail/ken', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], claims: [CLAIM] },
];
const assertionOf = (r, id, pattern) => row(r, id).assertions.find(a => pattern.test(a.name));
const reseal = r => { for (const x of r.results) if (x.trace[1]) x.evidenceDigest = digest({ evidence: x.trace[0].data, effects: x.trace[1].data, assertions: x.assertions }); return r; };

test('later stage end to end: a bounced expected email fails the check and its success claim, under provider-feed/6 and later, and the validator recomputes both', async () => {
  const r = await run(profile(checks), () => ['failed']);
  assert.equal(r.observers[0].collector.label, 'provider-feed/8');
  assert.equal(COLLECTOR_RECORDS['provider-feed'].label, 'provider-feed/8');
  const effect = assertionOf(r, 'CASE', /^Observed effect 1/), claim = assertionOf(r, 'CLAIMED', /^Observed claim 1/);
  assert.deepEqual([effect.status, effect.later], ['fail', 'effect-later-failed'], JSON.stringify(effect));
  assert.deepEqual([claim.status, claim.later], ['fail', 'effect-later-failed'], JSON.stringify(claim));
  assert.deepEqual([row(r, 'CASE').status, row(r, 'CLAIMED').status, row(r, 'ADMIN-ME').status], ['fail', 'fail', 'pass']);
  validateHttpRunEvidence(r);
  // The stored verdict is recomputed from the sealed records: a record edited to a success, or a tag dropped, is refused.
  const edited = structuredClone(r); edited.settlement.later[0].records = edited.settlement.later[0].records.map(x => ({ ...x, outcome: 'succeeded' }));
  assert.throws(() => validateHttpRunEvidence(edited), error => error.code === 'invalid-run-evidence');
  // The sealed clause record itself is compared: its tag dropped (the row resealed, its assertion untouched) is refused.
  const untagged = structuredClone(r); delete row(untagged, 'CASE').trace[1].data.effects[0].later;
  assert.throws(() => validateHttpRunEvidence(reseal(untagged)), error => error.code === 'invalid-run-evidence' && error.detail === 'effect-verdict');
  const strengthened = structuredClone(r); row(strengthened, 'CLAIMED').trace[1].data.claims[0].laterStrength = 'succeeded';
  assert.throws(() => validateHttpRunEvidence(reseal(strengthened)), error => error.code === 'invalid-run-evidence' && error.detail === 'effect-verdict');
  // Adjacent: a send the provider says it delivered passes, with the success strength, and so does one with no later word, without it.
  const delivered = await run(profile(checks), () => ['succeeded']);
  assert.deepEqual([assertionOf(delivered, 'CASE', /^Observed effect 1/).status, assertionOf(delivered, 'CASE', /^Observed effect 1/).laterStrength], ['pass', 'succeeded']);
  validateHttpRunEvidence(delivered);
  const silent = await run(profile(checks), () => []);
  assert.deepEqual([assertionOf(silent, 'CASE', /^Observed effect 1/).status, Object.hasOwn(assertionOf(silent, 'CASE', /^Observed effect 1/), 'laterStrength')], ['pass', false]);
  validateHttpRunEvidence(silent);
});

test('later stage: a run whose feed record carries provider-feed/5 keeps its records inert when validated by this build', async () => {
  const r = await run(profile(checks), () => ['failed']);
  // Recorded as a provider-feed/5 build would: label /5, and every verdict as without the stage.
  const old = await run(profile(checks), () => []);
  const v5 = structuredClone(old);
  v5.observers[0].collector = { ...v5.observers[0].collector, label: 'provider-feed/5' };
  v5.settlement.later = structuredClone(r.settlement.later);
  validateHttpRunEvidence(v5);
  assert.equal(row(v5, 'CASE').status, 'pass');
});

test('later stage: a repair over a later failure is credited only on a signed success; anything weaker reads unverified', async () => {
  const baseline = await run(profile(checks), to => to === VIP ? ['failed'] : ['succeeded']);
  assert.equal(row(baseline, 'CASE').status, 'fail');
  const signed = await run(profile(checks), () => ['succeeded']);
  // The candidate whose provider has not (yet) said anything about the send: it passes, at the default strength only.
  const pending = await run(profile(checks), to => to === VIP ? [] : ['succeeded']);
  const weak = compareRuns(baseline, pending);
  const weakRow = weak.rows.find(x => x.id === 'CASE');
  assert.deepEqual([weakRow.before, weakRow.after, weakRow.transition, weakRow.transitionReason], ['fail', 'pass', 'unverified', 'baseline-fail-provider-later']);
  assert.ok(weak.reasons.some(x => x.includes("provider's later outcome")));
  assert.equal(weak.summary.fixed, 0);
  // A success claim is judged the same way (its assertion is named by its reading, the same on both sides).
  const claimBaseline = await run(profile(checks), to => to === KEN ? ['failed'] : ['succeeded']);
  assert.equal(row(claimBaseline, 'CLAIMED').status, 'fail');
  const claimWeak = compareRuns(claimBaseline, await run(profile(checks), to => to === KEN ? [] : ['succeeded'])).rows.find(x => x.id === 'CLAIMED');
  assert.deepEqual([claimWeak.transition, claimWeak.transitionReason], ['unverified', 'baseline-fail-provider-later']);
  const claimStrong = compareRuns(claimBaseline, await run(profile(checks), () => ['succeeded'])).rows.find(x => x.id === 'CLAIMED');
  assert.equal(claimStrong.transitionReason, undefined);
  assert.notEqual(claimStrong.transition, 'unverified');
  const strong = compareRuns(baseline, signed);
  const strongRow = strong.rows.find(x => x.id === 'CASE');
  assert.equal(strong.compatible, true, JSON.stringify(strong.reasons));
  assert.equal(strongRow.transitionReason, undefined);
  assert.equal(strong.summary.fixed, 1, JSON.stringify(strong.rows));
  // The comparison is between compatible runs: the same identities on both sides.
  assert.equal(digest(baseline.observers), digest(signed.observers));
});

// SUSPEND is an allowed-use change check (lifecycle) whose own clause expects the suspension email; the provider later bounces it.
// The stage withholds the control (tagged); its post-change check was sent and reads change-not-attributed; the run stays valid.
test('later stage: a lifecycle change check whose email later bounces keeps the run valid; the post-change check reads change-not-attributed', async () => {
  const p = { ...profile([]), actors: { admin: { principalId: 'admin-1', credentialEnv: 'SCOPEHAVEN_TARGET_A', identityValue: 'admin' }, carol: { principalId: 'carol-1', credentialEnv: 'SCOPEHAVEN_TARGET_C', identityValue: 'carol' } },
    requiredControlIds: ['ADMIN-ME', 'CAROL-ME', 'CAROL-NOTES', 'SUSPEND'], lifecycle: [{ changeCheckId: 'SUSPEND', actorId: 'carol', after: 'refused' }],
    checks: [me('ADMIN-ME', 'admin'), me('CAROL-ME', 'carol'),
      { id: 'CAROL-NOTES', title: 'CAROL-NOTES', category: 'Allowed use', severity: 'control', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'SUSPEND', title: 'SUSPEND', category: 'Allowed use', severity: 'control', actorId: 'admin', method: 'POST', path: '/users/carol/suspend', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.exists', select: sel(VIP) }] },
      { id: 'REUSE', title: 'REUSE', category: 'Lifecycle', severity: 'high', actorId: 'carol', method: 'GET', path: '/notes', evidenceRequirement: 'backend', assertions: [{ kind: 'status.in', expected: [401, 403] }], effects: [{ kind: 'effect.none', select: { source: 'provider-feed', operation: 'send', name: EXT } }] }] };
  const r = await run(p, () => ['failed']);
  validateHttpRunEvidence(r);
  const suspend = row(r, 'SUSPEND');
  assert.equal(suspend.status, 'inconclusive');
  assert.equal(assertionOf(r, 'SUSPEND', /^Observed effect 1/).later, 'effect-later-failed');
  assert.ok(row(r, 'REUSE').assertions.some(a => a.name === PRECONDITION_ASSERTION && a.actual === PRECONDITION_REASONS['change-not-attributed']));
  // Adjacent: delivered, the change is attributed and the post-change check carries no such precondition.
  const ok = await run(p, () => ['succeeded']);
  validateHttpRunEvidence(ok);
  assert.equal(row(ok, 'SUSPEND').status, 'pass');
  assert.ok(!row(ok, 'REUSE').assertions.some(a => a.name === PRECONDITION_ASSERTION));
});

test('later stage: a clause judged again on a partial window reads missing and the run\'s backend row is decided again, so the run validates', async () => {
  const one = [checks[0]];
  const r = await run(profile(one), () => ['failed'], { coverage: 'partial' });
  const effect = assertionOf(r, 'CASE', /^Observed effect 1/);
  assert.deepEqual([effect.status, effect.later], ['inconclusive', 'effect-later-failed'], JSON.stringify(effect));
  assert.equal(row(r, 'CASE').backendEvidence, 'unavailable');
  validateHttpRunEvidence(r);
  // Adjacent: the same window with a delivered send keeps the pass, backed by the feed.
  const ok = await run(profile(one), () => ['succeeded'], { coverage: 'partial' });
  assert.deepEqual([row(ok, 'CASE').status, row(ok, 'CASE').backendEvidence], ['pass', 'observed']);
  validateHttpRunEvidence(ok);
});

test('later stage: an app-log admission applies first, so a repair over it reads unverified as before (baseline-fail-app-admitted)', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'scopehaven-later-admission-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'actions.jsonl');
  const log = { id: 'actions', use: 'admission', log: { file: { path } }, fields: { action: '/event', outcome: '/result', actor: '/actor', target: '/to' }, outcomes: { committed: ['ok'], error: ['error'] },
    rules: [{ action: 'mail.sent', operation: 'send', vocabulary: 'mail', domains: [{ domain: EXT, addresses: [VIP, KEN] }], observedAs: ['provider-feed'] }], logActors: { 'admin-1': 'admin-1' } };
  const p = { ...profile([{ id: 'COUNT', title: 'COUNT', category: 'Mail', severity: 'high', actorId: 'admin', method: 'POST', path: '/mail/vip', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [{ kind: 'effect.count', expected: 1, select: sel(VIP) }] }]), appLogs: [log] };
  // The application logs the email twice (one more than expected: an admission), and the provider later bounces the one it sent.
  const logTwice = lines => route => { if (route === '/mail/vip') for (let i = 0; i < lines; i++) appendFileSync(path, `${JSON.stringify({ event: 'mail.sent', actor: 'admin-1', result: 'ok', to: VIP })}\n`); };
  writeFileSync(path, '');
  const baseline = await run(p, () => ['failed'], { onRoute: logTwice(2) });
  const clause = row(baseline, 'COUNT').trace[1].data.effects[0];
  assert.deepEqual([clause.verdict, clause.appLog?.finding, Object.hasOwn(clause, 'later')], ['fail', 'app-log-unobserved-admission', false], JSON.stringify(clause));
  validateHttpRunEvidence(baseline);
  writeFileSync(path, '');
  const candidate = await run(p, () => ['succeeded'], { onRoute: logTwice(1) });
  assert.equal(row(candidate, 'COUNT').status, 'pass');
  const compared = compareRuns(baseline, candidate).rows.find(x => x.id === 'COUNT');
  assert.deepEqual([compared.transition, compared.transitionReason], ['unverified', 'baseline-fail-app-admitted']);
});
