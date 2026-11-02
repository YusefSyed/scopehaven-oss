// Run correlation beside declared body fields and claim rules: the integration points where a correlation rule has to
// cover what body fields and claim rules added. Pure decisions over synthetic windows, profile validation and scripted
// runs. No model, no provider and no network: the transport and observers are scripted.
// Every allowed behaviour below sits beside the forbidden or fail-closed behaviour next to it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runHttpAssessment, HTTP_LIMITS } from '../src/http-connector.mjs';
import { validateTargetFile } from '../src/contracts.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { decideEffects, OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { settlementFindings } from '../src/http-settlement.mjs';

const PAY = 'api.pay.example';
const APP = 'e'.repeat(32);
const sinkObserver = (extra = {}) => ({ id: 'sink', type: 'egress-recorder', port: 40999, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/refunds'], correlation: { header: 'traceparent' } }], witness: { actorId: 'member', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 250, quietMs: 150, ...extra });
const paySel = { source: 'http-egress', operation: 'send', name: PAY };
const claimRule = (select = paySel) => ({ trigger: { field: { pointer: '/status', success: ['refunded'], refusal: ['refused'] } }, select });
const base = { title: 'Check', category: 'Collateral', severity: 'high', actorId: 'member', method: 'POST', body: {}, evidenceRequirement: 'backend', assertions: [{ kind: 'status.equals', expected: 201 }] };
const claimCheck = (id, select) => ({ ...base, id, path: `/${id.toLowerCase()}`, claims: [claimRule(select)] });
const effectCheck = id => ({ ...base, id, path: `/${id.toLowerCase()}`, effects: [{ kind: 'effect.none', select: paySel }] });
function profileOf({ correlation = { header: 'traceparent' }, settlement = { mode: 'per-check' }, observers = [sinkObserver()], checks = [] } = {}) {
  return { id: 'w2-merge', name: 'W2 merge', applicationId: 'w2-merge', origin: 'http://127.0.0.1:9', buildLabel: 'b', contextId: 'synthetic', actors: { member: { principalId: 'member-1' } },
    requiredControlIds: ['PING'], observers, ...(correlation ? { correlation } : {}), ...(settlement ? { settlement } : {}),
    checks: [{ id: 'PING', title: 'Ping', category: 'Allowed use', severity: 'control', actorId: 'member', method: 'GET', path: '/ping', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }, ...checks] };
}
const valid = profile => validateTargetFile({ schemaVersion: 1, targets: [profile] });
const invalid = (profile, pattern) => assert.throws(() => valid(profile), pattern);

test('correlation and claim rules (contract): a correlated target refuses a claim selector with a traceId an egress recorder could see', () => {
  for (const select of [{ ...paySel, traceId: APP }, { operation: 'send', name: PAY, traceId: APP }]) {
    invalid(profileOf({ checks: [claimCheck('CLAIM', select)] }), /correlation-token-not-selectable/);
    invalid(profileOf({ settlement: { mode: 'run' }, checks: [claimCheck('CLAIM', select)] }), /correlation-token-not-selectable/);
    // Allowed, adjacent: the same claim rule on a target without correlation.
    assert.doesNotThrow(() => valid(profileOf({ correlation: null, settlement: null, observers: [sinkObserver({ destinations: [{ host: PAY, paths: ['/v1/refunds'] }] })], checks: [claimCheck('CLAIM', select)] })));
  }
  // Allowed, adjacent: a claim selector without a traceId, and one whose source an egress recorder never reports.
  assert.doesNotThrow(() => valid(profileOf({ checks: [claimCheck('CLAIM', paySel)] })));
  assert.doesNotThrow(() => valid(profileOf({ checks: [claimCheck('CLAIM', { source: 'otel-genai', operation: 'send', name: PAY, traceId: APP })] })));
});

test('correlation and claim rules (contract): the per-check barrier total counts checks with claim rules, as the connector bars them', () => {
  const claims = n => Array.from({ length: n }, (_, i) => claimCheck(`CLAIM-${i}`, paySel));
  const effects = n => Array.from({ length: n }, (_, i) => effectCheck(`EFFECT-${i}`));
  const slow = [sinkObserver({ settleMs: 30000 })];
  // 21 barriers of 30000 ms exceed 600000 ms whether the checks declare effects or claim rules.
  invalid(profileOf({ observers: slow, checks: effects(21) }), /per-check barriers .* exceed 600000 ms/);
  invalid(profileOf({ observers: slow, checks: claims(21) }), /per-check barriers .* exceed 600000 ms/);
  invalid(profileOf({ observers: slow, checks: [...effects(11), ...claims(10)] }), /per-check barriers .* exceed 600000 ms/);
  // Allowed, adjacent: 20 such checks fit; run mode adds no barriers.
  assert.doesNotThrow(() => valid(profileOf({ observers: slow, checks: claims(20) })));
  assert.doesNotThrow(() => valid(profileOf({ observers: slow, settlement: { mode: 'run' }, checks: claims(21) })));
});

// Scripted observers that report nothing; the transport answers every request.
function scripted() {
  const sent = [];
  const transport = async (origin, check) => { sent.push(check.path); return { status: check.method === 'GET' ? 200 : 201, complete: true, jsonParsed: true, json: {}, bytes: 2 }; };
  const factory = configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type], instanceId = `${c.type}-${c.id}`;
    let n = 0;
    return { kind: out.kind, instanceId, source: out.source, scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++n }; }, async collect() { return { events: [], coverage: 'complete', reason: null }; } };
  });
  return { transport, factory, sent };
}
test('correlation and claim rules (connector): the run budget includes the barrier after a check with claim rules, as after an effect check', async () => {
  // settle 600 ms and a 900 ms base budget: each observed check takes its settle plus its barrier (about 1200 ms), so the
  // second observed check is sent only when the budget counts the first check's barrier and its own.
  const limits = { ...HTTP_LIMITS, runTimeoutMs: 900 };
  const observers = [sinkObserver({ settleMs: 600 })];
  for (const checks of [[effectCheck('ONE'), effectCheck('TWO')], [claimCheck('ONE', paySel), claimCheck('TWO', paySel)]]) {
    const s = scripted();
    const run = await runHttpAssessment(profileOf({ observers, checks }), { env: {}, transport: s.transport, observerFactory: s.factory, limits });
    assert.deepEqual(run.results.map(r => [r.id, r.trace[0].data.requestAttempted]), [['PING', true], ['ONE', true], ['TWO', true]], checks[0].claims ? 'claim checks' : 'effect checks');
    assert.deepEqual(run.settlement.barriers.map(b => b.after), ['ONE', 'TWO']);
  }
});

// Pure rules over one declared egress pair that captures /amount.
const INST = 'egress-recorder-hooks';
const SINK = { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative', capture: { [PAY]: ['/amount'] } };
const T = i => (i + 1).toString(16).padStart(2, '0').repeat(16);
const tokens = new Map([[T(0), 0], [T(1), 1]]);
const declared = new Set([`${INST}\n${PAY}`]);
const runMode = { mode: 'run', tokens, declared };
let seq = 0;
const amount = value => ({ status: 'captured', values: { '/amount': { type: 'number', value } } });
const ev = (resource, token, captured) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: ++seq, operation: 'send', name: PAY, resource, outcome: 'committed', correlation: token ? { settlementToken: token } : {}, ...(captured ? { captured } : {}) });
const win = (events = []) => ({ source: 'http-egress', instanceId: INST, scope: SINK, coverage: 'complete', reason: null, events });
const rowOf = (effects, windows) => ({ effects: decideEffects(effects, windows, { role: 'boundary' }), windows });
const R = 'POST /v1/refunds', C = 'POST /v1/coupons';
const small = { ...paySel, resource: R, fields: [{ pointer: '/amount', lt: 100 }] };

test('correlation and body fields (settlement): an effect.only pass with a fields selector names effect-correlated-late for a late own-token send outside its set', () => {
  const onlyFields = { kind: 'effect.only', expect: [{ select: { ...paySel, resource: C }, count: 1 }], allow: [small], sources: ['http-egress'] };
  const rows = () => [rowOf([onlyFields], [win([ev(C, T(0))])])];
  assert.equal(rows()[0].effects[0].verdict, 'pass');
  // A late own-token refund of 500 is outside the allowed set (amount not under 100): judged with it, the clause fails.
  assert.deepEqual(settlementFindings(rows(), [[win()], [win([ev(R, T(0), amount(500))])]], runMode), [['effect-correlated-late']]);
  // Adjacent: a late own-token refund of 50 is inside the allowed set, so it only could change the clause.
  assert.deepEqual(settlementFindings(rows(), [[win()], [win([ev(R, T(0), amount(50))])]], runMode), [['effect-correlated-late-unsettled']]);
  // Adjacent: an untagged late refund of 500 withholds by the run-level rule, as without correlation.
  assert.deepEqual(settlementFindings(rows(), [[win()], [win([ev(R, null, amount(500))])]], runMode), [['effect-outside-window']]);
  assert.deepEqual(settlementFindings(rows(), [[win()], [win([ev(R, null, amount(500))])]]), [['effect-outside-window']]);
});

test('correlation and body fields (settlement): a late own-token send whose fields decide the clause names effect-correlated-late; unreadable fields only withhold', () => {
  const noneSmall = { kind: 'effect.none', select: small };
  const rows = () => [rowOf([noneSmall], [win()])];
  assert.equal(rows()[0].effects[0].verdict, 'pass');
  assert.deepEqual(settlementFindings(rows(), [[win()], [win([ev(R, T(0), amount(50))])]], runMode), [['effect-correlated-late']]);
  // Unreadable fields (no captured record, or a body that was not JSON): it could be this clause's effect, never a fail.
  assert.deepEqual(settlementFindings(rows(), [[win()], [win([ev(R, T(0))])]], runMode), [['effect-correlated-late-unsettled']]);
  assert.deepEqual(settlementFindings(rows(), [[win()], [win([ev(R, T(0), { status: 'not-json', values: {} })])]], runMode), [['effect-correlated-late-unsettled']]);
  // Adjacent: a decided non-match (amount 500) does not fit the clause, so its own token withholds nothing.
  assert.deepEqual(settlementFindings(rows(), [[win()], [win([ev(R, T(0), amount(500))])]], runMode), [[null]]);
  // A window blind to the fields (no capture declared) still withholds by the run-level rule, token or not.
  const blind = { ...win([ev(R, T(0))]), scope: { ...SINK, capture: undefined } };
  delete blind.scope.capture;
  assert.deepEqual(settlementFindings(rows(), [[win()], [blind]], runMode), [['effect-outside-window']]);
  assert.deepEqual(settlementFindings(rows(), [[win()], [blind]]), [['effect-outside-window']]);
});

test('correlation and claim rules (exported text matches the code): the per-check limitation and the docs name checks with effects or claim rules', async () => {
  const { readFile } = await import('node:fs/promises');
  const { fileURLToPath } = await import('node:url');
  const { correlationLimitation } = await import('../src/http-scope-text.mjs');
  const text = correlationLimitation({ header: 'traceparent', mode: 'per-check' });
  assert.ok(text.includes('Per-check settlement: after each check with effects or claim rules, the connector waited the largest declared settleMs'));
  assert.ok(!text.includes('after each effect check'));
  assert.ok(!/[–—]/.test(text));
  const doc = name => readFile(fileURLToPath(new URL(`../docs/${name}`, import.meta.url)), 'utf8');
  const onboarding = await doc('ONBOARDING.md'), limits = await doc('KNOWN-LIMITS.md');
  assert.ok(onboarding.includes('adds a drain barrier after each check with effects or claim rules'));
  assert.ok(onboarding.includes('in an effect clause or a claim rule (`correlation-token-not-selectable`)'));
  assert.ok(limits.includes('adds a drain barrier after each check with effects or claim rules'));
});
