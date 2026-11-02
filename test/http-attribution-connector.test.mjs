// Background attribution through the connector, the run validator, the exported suite and
// run comparison, with a scripted observer and transport (no sockets, no model, no provider). The acceptance cases are
// general synthetic replays of one class of false alarm: a background job's committed send landing in a check's window.
// Every allowed behaviour sits beside the forbidden or fail-closed behaviour next to it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence, validateTargetFile, contractDigest } from '../src/contracts.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { createRegistry } from '../src/registry.mjs';
import { compareRuns } from '../src/runner.mjs';

const PAY = 'api.pay.example', CRM = 'crm.example';
const sink = (extra = {}) => ({ id: 'sink', type: 'egress-recorder', port: 40998, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/coupons'] }, { host: CRM }],
  witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150, ...extra });
// The application's CRM sync worker posts on its own schedule; it never carries an actor.
const BG = { background: [{ id: 'crm-sync', select: { operation: 'send', name: CRM } }] };
const refundSel = { source: 'http-egress', operation: 'send', name: PAY, resource: 'POST /v1/refunds' };
const PING = { id: 'PING', title: 'Ping', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'GET', path: '/ping', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] };
const noCrm = select => ({ id: 'NO-CRM', title: 'A refused note is not pushed to the CRM', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/tickets/9/note', body: {}, evidenceRequirement: 'backend',
  assertions: [{ kind: 'status.equals', expected: 201 }], effects: [{ kind: 'effect.none', select: { source: 'http-egress', operation: 'send', name: CRM, ...select } }] });
const REFUND = { id: 'REFUND-OWN', title: 'One refund (allowed)', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'response',
  assertions: [{ kind: 'status.equals', expected: 201 }], effects: [{ kind: 'effect.count', select: refundSel, expected: 1 }] };
function profile({ attribution = BG, observers = [sink()], clause = {}, checks = [PING, noCrm(clause), REFUND], requiredControlIds = ['PING', 'REFUND-OWN'] } = {}) {
  return { id: 'g5-scripted', name: 'G5 scripted', applicationId: 'g5-scripted', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { member: { principalId: 'member-1' } },
    requiredControlIds, ...(observers ? { observers } : {}), checks, ...(attribution ? { attribution } : {}) };
}
// The scripted observer reports one queued window per collect (own windows in check order, then the gaps, the run-end
// window last) and records the options each collect was given. The transport answers 200 to GET and 201 otherwise.
function scripted(queue, { startThrows = [], arrivingAtEnd = false } = {}) {
  const calls = { transport: 0, stops: 0, collects: [] };
  const transport = async (_origin, check) => { calls.transport++; return { status: check.method === 'GET' ? 200 : 201, complete: true, jsonParsed: true, json: {}, bytes: 2 }; };
  const factory = configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type], instanceId = `${c.type}-${c.id}`;
    let n = 0;
    return { kind: out.kind, instanceId, source: out.source, scope: { operations: ['send'], names: c.destinations.map(d => d.host), actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() { if (startThrows.includes(c.id)) throw new Error('start-failed'); }, async stop() { calls.stops++; }, async mark() { return { at: ++n }; },
      async collect(_from, _to, options = {}) {
        calls.collects.push(options);
        const next = (queue.shift() ?? empty)(), arriving = arrivingAtEnd && options.final === true;
        return { events: next.events.map((e, i) => makeEffect({ source: out.source, observer: { kind: out.kind, instanceId }, seq: 1000 + i + n * 10, outcome: 'committed', actor: null, operation: 'send', ...e })),
          coverage: arriving ? 'partial' : 'complete', reason: arriving ? 'egress-request-in-flight' : null };
      } };
  });
  return { transport, factory, calls };
}
const empty = () => ({ events: [] });
const crmSync = () => ({ events: [{ name: CRM, resource: 'POST /v1/sync' }] });
const crmNote = () => ({ events: [{ name: CRM, resource: 'POST /v1/notes' }] });
const refund = () => ({ events: [{ name: PAY, resource: 'POST /v1/refunds' }] });
// Collect order: NO-CRM's window, REFUND-OWN's window, the gap before NO-CRM, the gap before REFUND-OWN, the run-end window.
const assess = async (p, queue, options) => { const s = scripted(queue, options); return { run: await runHttpAssessment(p, { env: {}, transport: s.transport, observerFactory: s.factory }), calls: s.calls }; };
const suiteOf = p => createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
const row = (run, id) => run.results.find(r => r.id === id);
const clauseOf = (run, id) => row(run, id).trace[1].data.effects[0];

test('acceptance (a background send in a clean check\'s window): the undeclared run fails the clean check; with the source declared it reads inconclusive, never fail, and the validator agrees', async () => {
  const plain = profile({ attribution: null }), declared = profile();
  const before = await assess(plain, [crmSync, refund]);
  assert.deepEqual([row(before.run, 'NO-CRM').status, clauseOf(before.run, 'NO-CRM').verdict], ['fail', 'fail'], 'the false alarm without a declaration');
  const after = await assess(declared, [crmSync, refund]);
  assert.deepEqual(after.run.results.map(r => [r.id, r.status]), [['PING', 'pass'], ['NO-CRM', 'inconclusive'], ['REFUND-OWN', 'pass']]);
  assert.deepEqual([clauseOf(after.run, 'NO-CRM').verdict, clauseOf(after.run, 'NO-CRM').attribution], ['inconclusive', 'background-unattributed']);
  assert.equal(row(after.run, 'NO-CRM').assertions.find(a => a.name.startsWith('Observed effect 1')).attribution, 'background-unattributed');
  assert.equal(clauseOf(after.run, 'REFUND-OWN').attribution, undefined, 'a clause no source overlaps is untouched');
  validateHttpRunEvidence(after.run, { expectedSuite: suiteOf(declared) });
  validateHttpRunEvidence(after.run);
  validateHttpRunEvidence(before.run, { expectedSuite: suiteOf(plain) });
});

test('acceptance: a background send before the check\'s window decides nothing either way; one after it keeps settlement\'s withholding (attribution never releases)', async () => {
  // In the gap before NO-CRM: both runs pass it.
  for (const p of [profile({ attribution: null }), profile()]) {
    const { run } = await assess(p, [empty, refund, crmSync, empty, empty]);
    assert.equal(row(run, 'NO-CRM').status, 'pass', p.attribution ? 'declared' : 'plain');
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  }
  // In the run-end window: it may be NO-CRM's late send, so both runs withhold it (settlement), and attribution adds nothing.
  for (const p of [profile({ attribution: null }), profile()]) {
    const { run } = await assess(p, [empty, refund, empty, empty, crmSync]);
    assert.deepEqual([row(run, 'NO-CRM').status, clauseOf(run, 'NO-CRM').settlement, clauseOf(run, 'NO-CRM').attribution], ['inconclusive', 'effect-outside-window', undefined]);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
  }
});

test('acceptance (forbidden): the check\'s own forbidden send is never released by a background declaration that covers it; the cost is stated: it reads inconclusive, not fail', async () => {
  for (const clause of [{}, { resource: 'POST /v1/notes' }]) {
    const before = await assess(profile({ attribution: null, clause }), [crmNote, refund]);
    assert.equal(row(before.run, 'NO-CRM').status, 'fail');
    const after = await assess(profile({ clause }), [crmNote, refund]);
    assert.deepEqual([row(after.run, 'NO-CRM').status, clauseOf(after.run, 'NO-CRM').attribution], ['inconclusive', 'background-unattributed'], 'the source covers every CRM send, so the note could be the worker\'s');
    // The note and a sync together: still never a pass.
    const both = await assess(profile({ clause }), [() => ({ events: [...crmSync().events, ...crmNote().events] }), refund]);
    assert.notEqual(row(both.run, 'NO-CRM').status, 'pass');
  }
  // A clause pinned to the note is decided exactly as without the declaration when only the worker's sync lands in its
  // window: no source send fits it. (Unpaired, the resource pin is held by pairing in both runs, as before.)
  const pinned = await assess(profile({ clause: { resource: 'POST /v1/notes' } }), [crmSync, refund]);
  const pinnedPlain = await assess(profile({ attribution: null, clause: { resource: 'POST /v1/notes' } }), [crmSync, refund]);
  const { attribution: _a, ...pinnedClause } = clauseOf(pinned.run, 'NO-CRM');
  assert.equal(_a, undefined);
  assert.deepEqual([row(pinned.run, 'NO-CRM').status, pinnedClause], [row(pinnedPlain.run, 'NO-CRM').status, clauseOf(pinnedPlain.run, 'NO-CRM')]);
  assert.equal(clauseOf(pinned.run, 'NO-CRM').verdict === 'fail', false);
  // Paired by an allowed-use control that shows the pin matching (src/http-pairing.mjs), it passes in both runs.
  const NOTE_OWN = { id: 'NOTE-OWN', title: 'Own note pushed (allowed)', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'POST', path: '/tickets/1/note', body: {}, evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 201 }], effects: [{ kind: 'effect.exists', select: { source: 'http-egress', operation: 'send', name: CRM, resource: 'POST /v1/notes' } }] };
  const paired = attribution => profile({ attribution, clause: { resource: 'POST /v1/notes' }, checks: [PING, NOTE_OWN, noCrm({ resource: 'POST /v1/notes' }), REFUND] });
  for (const attribution of [null, BG]) {
    const { run } = await assess(paired(attribution), [crmNote, crmSync, refund]);
    assert.equal(row(run, 'NO-CRM').status, 'pass', attribution ? 'declared' : 'plain');
    // The control's own note is a CRM send the source covers: a positive control pass resting on it is withheld.
    assert.equal(row(run, 'NOTE-OWN').status, attribution ? 'inconclusive' : 'pass');
  }
  // A source naming another host attributes nothing here: the undeclared verdicts stand.
  const elsewhere = await assess(profile({ attribution: { background: [{ id: 'pay-sync', select: { operation: 'send', name: PAY, actor: 'svc-sync' } }] }, checks: [PING, noCrm({}), REFUND], requiredControlIds: ['PING'] }), [crmNote, empty]);
  assert.equal(row(elsewhere.run, 'NO-CRM').status, 'fail');
});

test('run-end window: collected in final mode only when attribution is declared; a send still arriving there withholds an earlier absence', async () => {
  const declared = await assess(profile(), [empty, refund]);
  // A check window is collected scoped (destination-scoped egress entries); gaps and the run end never are.
  assert.deepEqual(declared.calls.collects, [{ scoped: true }, { scoped: true }, { gap: true }, { gap: true }, { gap: true, final: true }]);
  const plain = await assess(profile({ attribution: null }), [empty, refund]);
  assert.deepEqual(plain.calls.collects, [{ scoped: true }, { scoped: true }, { gap: true }, { gap: true }, { gap: true }]);
  // The recorder reports a request still arriving at the final mark: the run-end window is partial.
  const arriving = await assess(profile(), [empty, refund], { arrivingAtEnd: true });
  assert.deepEqual([row(arriving.run, 'NO-CRM').status, clauseOf(arriving.run, 'NO-CRM').settlement], ['inconclusive', 'settlement-unobserved']);
  validateHttpRunEvidence(arriving.run, { expectedSuite: suiteOf(profile()) });
  const unseen = await assess(profile({ attribution: null }), [empty, refund], { arrivingAtEnd: true });
  assert.equal(row(unseen.run, 'NO-CRM').status, 'pass', 'undeclared: no final mode, collection as before');
});

test('a control\'s positive pass resting on a background send is withheld whether or not settlement tagged it, so a weaker run-end window never releases a repair', async () => {
  const payBg = { background: [{ id: 'pay-sync', select: { operation: 'send', name: PAY } }] };
  const p = profile({ attribution: payBg }), plain = profile({ attribution: null });
  for (const arrivingAtEnd of [false, true]) {
    const { run } = await assess(p, [empty, refund], { arrivingAtEnd });
    const refundClause = clauseOf(run, 'REFUND-OWN');
    assert.deepEqual([row(run, 'REFUND-OWN').status, refundClause.settlement, refundClause.attribution], ['inconclusive', arrivingAtEnd ? 'settlement-unobserved' : undefined, 'background-unattributed'], `arriving ${arrivingAtEnd}`);
    validateHttpRunEvidence(run, { expectedSuite: suiteOf(p) });
    // Against a baseline of the same profile, the controls never pass, so nothing is labelled restored.
    assert.equal(compareRuns(run, run).controlsPass, false);
  }
  // Undeclared, the same control passes (and carries settlement as a tag when the run-end window was partial).
  const { run: before } = await assess(plain, [empty, refund], { arrivingAtEnd: true });
  assert.deepEqual([row(before, 'REFUND-OWN').status, clauseOf(before, 'REFUND-OWN').settlement], ['pass', undefined], 'no final mode without the declaration');
});

test('run start: a source no started observer can see is refused (400) before any mark or request, and every observer is stopped', async () => {
  const unknown = { background: [{ id: 'ghost', select: { name: 'api.unknown.example' } }] };
  const s = scripted([]);
  await assert.rejects(runHttpAssessment(profile({ attribution: unknown }), { env: {}, transport: s.transport, observerFactory: s.factory }), e => e.status === 400 && /attribution-background-unobservable: no started observer can see background source 1\./.test(e.message));
  assert.deepEqual([s.calls.transport, s.calls.collects.length, s.calls.stops], [0, 0, 1]);
  // The only observer that could see the CRM did not start: refused the same way.
  const split = [sink({ destinations: [{ host: PAY, paths: ['/v1/refunds', '/v1/coupons'] }] }), sink({ id: 'crm', port: 40997, destinations: [{ host: CRM }] })];
  const t = scripted([], { startThrows: ['crm'] });
  await assert.rejects(runHttpAssessment(profile({ observers: split }), { env: {}, transport: t.transport, observerFactory: t.factory }), e => e.status === 400 && /attribution-background-unobservable/.test(e.message));
  assert.deepEqual([t.calls.transport, t.calls.stops], [0, 2]);
  // Started, it runs.
  const u = scripted([empty, empty, refund]);
  const run = await runHttpAssessment(profile({ observers: split }), { env: {}, transport: u.transport, observerFactory: u.factory });
  assert.equal(row(run, 'NO-CRM').status, 'pass');
});

test('record, suite and comparison: the declaration is sealed, bound to the suite and to the effects signature; edits and forged tags are refused', async () => {
  const declared = profile(), plain = profile({ attribution: null });
  const { run } = await assess(declared, [crmSync, refund]);
  const { run: plainRun } = await assess(plain, [crmSync, refund]);
  assert.deepEqual(run.attribution, { schema: 'scopehaven-attribution/1', background: BG.background });
  assert.deepEqual(suiteOf(declared).attribution, { background: BG.background });
  assert.ok(run.limitations.some(l => l.startsWith('Background attribution: the target declared background sources (crm-sync)')));
  assert.ok(!Object.hasOwn(plainRun, 'attribution') && !Object.hasOwn(suiteOf(plain), 'attribution') && !plainRun.limitations.some(l => l.startsWith('Background attribution')));
  const edit = (base, change) => { const copy = structuredClone(base); change(copy); return copy; };
  const refused = (copy, detail, options) => assert.throws(() => validateHttpRunEvidence(copy, options), e => detail === 'unexpected-suite-evidence' ? e.code === 'unexpected-suite-evidence' : e.code === 'invalid-run-evidence' && e.detail === detail, detail);
  refused(edit(run, c => { c.attribution.schema = 'scopehaven-attribution/2'; }), 'attribution-record');
  refused(edit(run, c => { c.attribution.lateFails = null; }), 'attribution-record');
  refused(edit(run, c => { c.attribution.background = Array.from({ length: 17 }, (_, i) => ({ id: `s${i}`, select: { operation: 'send', name: CRM } })); }), 'attribution-record');
  refused(edit(run, c => { c.attribution.background[0].select.resource = 'committed'; }), 'attribution-record');
  // A well-formed egress resource pin is a valid shape. Narrowed to the sync's own resource it changes no tag,
  // so it validates without the suite (an out-of-scope consistent edit, as any whole-record forgery); the suite binds the declaration.
  const narrowed = edit(run, c => { c.attribution.background[0].select.resource = 'POST /v1/sync'; });
  refused(narrowed, 'unexpected-suite-evidence', { expectedSuite: suiteOf(declared) });
  // A source no sealed window can see.
  refused(edit(run, c => { c.attribution.background[0].select.name = 'api.unknown.example'; }), 'attribution-record');
  // The clause tag is recomputed: edited, removed, or stripped with the record, it is refused.
  const tagged = c => c.results.find(r => r.id === 'NO-CRM').trace[1].data.effects[0];
  refused(edit(run, c => { tagged(c).attribution = 'background-unobserved'; }), 'effect-verdict');
  refused(edit(run, c => { delete tagged(c).attribution; }), 'effect-verdict');
  // The run carries a drains record (attribution is declared), which a run without attribution may not carry.
  refused(edit(run, c => { delete c.attribution; }), 'settlement-drains');
  refused(edit(run, c => { delete c.attribution; delete c.settlement.drains; }), 'effect-verdict');
  // A tag forged onto a run that declares nothing.
  refused(edit(plainRun, c => { tagged(c).attribution = 'background-unattributed'; }), 'effect-verdict');
  // Against the suite: stripped, edited, or added to a run of the undeclared suite.
  refused(edit(run, c => { delete c.attribution; }), 'unexpected-suite-evidence', { expectedSuite: suiteOf(declared) });
  refused(edit(run, c => { c.attribution.background[0].id = 'other'; }), 'unexpected-suite-evidence', { expectedSuite: suiteOf(declared) });
  refused(run, 'unexpected-suite-evidence', { expectedSuite: suiteOf(plain) });
  // A run of a declared profile never compares as a peer of an undeclared one.
  const comparison = compareRuns(plainRun, run);
  assert.equal(comparison.compatible, false);
  assert.ok(comparison.reasons.includes('Declared effects, evidence requirements or observers differ between the runs.'));
  assert.equal(compareRuns(run, (await assess(declared, [crmSync, refund])).run).compatible, true);
});

test('profile: load refusals name positions; protection that would be silently off is refused; the digest moves only when declared', () => {
  const load = p => validateTargetFile({ schemaVersion: 1, targets: [p] })[0];
  const invalid = (p, pattern) => assert.throws(() => load(p), pattern);
  assert.doesNotThrow(() => load(profile()));
  invalid(profile({ attribution: { background: [] } }), /"attribution": "background" must be a list of 1 to 16 sources/);
  invalid(profile({ attribution: { ...BG, lateFails: 'withhold' } }), /"attribution": attribution is \{ "background"/);
  invalid(profile({ attribution: { background: [{ id: 'x', select: { operation: 'send', name: CRM, source: 'http-egress' } }] } }), /"attribution": background source 1: "select" pins only/);
  // No observers, or no applicable check with effects or claim rules.
  invalid(profile({ observers: null, checks: [PING], requiredControlIds: ['PING'] }), /attribution-needs-observers/);
  const GET = { ...PING, id: 'LIST', severity: 'high', category: 'Collateral' };
  invalid(profile({ checks: [PING, GET], requiredControlIds: ['PING'] }), /attribution-needs-observed-check/);
  // An applicable write check without effects or claim rules: its effects would have no window and no selector.
  const WRITE = { id: 'W-1', title: 'Write', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', path: '/w', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 201 }] };
  invalid(profile({ checks: [PING, noCrm({}), REFUND, WRITE] }), /check "W-1": attribution-unobserved-write/);
  assert.doesNotThrow(() => load(profile({ checks: [PING, noCrm({}), REFUND, { ...WRITE, applicability: { applies: false, reason: 'Not offered in this build.' } }] })));
  assert.doesNotThrow(() => load(profile({ checks: [PING, noCrm({}), REFUND, GET] })));
  assert.doesNotThrow(() => load(profile({ attribution: null, checks: [PING, noCrm({}), REFUND, WRITE] })), 'undeclared: unchanged');
  // The digest: an undeclared profile keeps it; a declaration, or another one, moves it.
  const digests = [profile({ attribution: null }), profile(), profile({ attribution: { background: [{ id: 'crm-sync', select: { operation: 'send', name: PAY } }] } })].map(p => contractDigest(load(p)));
  assert.equal(new Set(digests).size, 3);
  const { attribution: _a, ...stripped } = profile();
  assert.equal(contractDigest(load(stripped)), digests[0]);
  assert.deepEqual(load(stripped), load(profile({ attribution: null })));
});
