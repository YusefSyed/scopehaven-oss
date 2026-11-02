// Form decimals, fail direction only. A form-encoded value such as amount=105.05 read unknown against a
// pinned 105.5, so a field-pinned clause abstained on a refund that plainly differs. A form
// decimal now has two readings (the separator as a decimal mark or as a group mark) and a rounding band at the pinned precision;
// when none gives the pinned value it reads "no", but only inside the fail-only judgements (src/effect-events.mjs
// evaluateEffectAssertion, integrations/collateral/only.mjs judgeOnly), which keep that reading only when it makes a missing clause
// fail. Checked: the reading rule, the default mode against main's frozen body-fields (9f6098e), the combinators, the readers that
// keep today's unknown, a seeded differential against main's frozen judges (only missing -> fail moves), and one connector run over
// real loopback HTTP whose baseline decimal fail and candidate pass compare as a repair (destination hosts are names only and are
// never resolved or contacted).
import test from 'node:test';
import assert from 'node:assert/strict';
import { request, createServer } from 'node:http';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { fieldState, decimalDiffers } from '../src/body-fields.mjs';
import { makeEffect, matchState, evaluateEffectAssertion, otherActorCommit, decidedByGaps } from '../src/effect-events.mjs';
import { decideEffects } from '../src/http-effects.mjs';
import { fitsSelector } from '../src/http-settlement.mjs';
import { judgeOnly } from '../integrations/collateral/only.mjs';
import { onFreePorts, watchingBinds } from '../integrations/observers/fixtures/free-port.mjs';
import { buildObservers } from '../integrations/observers/factory.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { compareRuns, NO_VERIFIED_REPAIR } from '../src/runner.mjs';
import { validateHttpRunEvidence, validateTargetFile } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';

// main before this change: body fields, effect events and effect.only at 9f6098e.
const fixture = name => import(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));
const frozenFields = await fixture('body-fields-9f6098e.mjs'), frozenEvents = await fixture('effect-events-9f6098e.mjs'), frozenOnly = await fixture('only-9f6098e.mjs');

const BILL = 'billing.example.test', INST = 'egress-recorder-sink', REFUND = 'POST /v1/refunds';
const SCOPE = Object.freeze({ operations: ['send'], names: [BILL], actorAttribution: 'none', evidence: 'authoritative', capture: { [BILL]: ['/amount'] }, captureForm: [BILL] });
const form = t => ({ status: 'captured', values: { '/amount': { type: 'text', value: t } } });
const pin = (op, x) => ({ pointer: '/amount', [op]: x });
const DECIMALS = Object.freeze({ formDecimals: true });
// The state of one text against one predicate, today and with formDecimals.
const states = (t, entry) => [fieldState(form(t), entry), fieldState(form(t), entry, DECIMALS)];
let seq = 0;
const send = (t, extra = {}) => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId: INST }, seq: ++seq, observedAt: '2026-10-14T00:00:00.000Z',
  operation: 'send', name: BILL, resource: REFUND, outcome: 'committed', captured: form(t), ...extra });
const win = (events, { coverage = 'complete', scope = SCOPE } = {}) => ({ source: 'http-egress', instanceId: INST, scope, coverage, reason: coverage === 'complete' ? null : 'synthetic', events });
const refunds = (fields, extra = {}) => ({ source: 'http-egress', operation: 'send', name: BILL, resource: REFUND, ...(fields ? { fields } : {}), ...extra });
const LISTED = Object.freeze([pin('in', [105.5, '105.5'])]);
const verdictOf = (clause, texts, opts) => decideEffects([clause], [win(texts.map(t => send(t)), opts)])[0];

// ---------------------------------------------------------------------------
test('1. grammar: one sign, an integer part without a leading zero, one "." or "," and a fraction, at most 15 digits; nothing else is decided', () => {
  for (const t of ['105.05', '105,05', '-105.05', '0.5', '0,50', '123456789012.345']) assert.equal(decimalDiffers(t, 7), true, t);
  for (const t of ['01.5', '00.5', '+105.05', '.5', '5.', '1.050,5', '1,050.5', '1.0.5', '1e3', '1.5e2', '1_000.5', "1'000.5", ' 105.05', '105.05 ', '105. 05', '1234567890123.456',
    '\uff11\uff10\uff15.05', '105.05abc', '$105.05', '0x10.5', '', '-', '-.5']) {
    assert.equal(decimalDiffers(t, 7), false, t);
    assert.deepEqual(states(t, pin('equals', 7)), ['unknown', 'unknown'], t);
  }
});

test('2. readings: the separator as a decimal mark or as a group mark (either character), so both values stay undecided', () => {
  const rows = [
    ['1.050', 1050, 'unknown'], ['1.050', 1.05, 'unknown'], ['1,050', 1050, 'unknown'], ['1,050', 1.05, 'unknown'], ['105.05', 10505, 'unknown'], ['105,05', 105.05, 'unknown'],
    ['1.050', 105, 'no'], ['105.05', 105.5, 'no'], ['105,05', 105.5, 'no'], ['41.5', 14.5, 'no'], ['200.00', 20, 'no'], ['-1.050', -1050, 'unknown'], ['-1.050', 1050, 'no'],
  ];
  for (const [t, x, want] of rows) assert.deepEqual(states(t, pin('equals', x)), ['unknown', want], `${t} vs ${x}`);
});

test('3. rounding: any rounding or truncation of the decimal reading to the pinned precision, and one unit more (floating point), stays undecided', () => {
  const rows = [
    ['105.50', 105.5, 'unknown'], ['105.499', 105.5, 'unknown'], ['105.45', 105.5, 'unknown'], ['105.41', 105.5, 'unknown'], ['105.4', 105.5, 'unknown'], ['105.39', 105.5, 'no'],
    ['105.59', 105.5, 'unknown'], ['105.6', 105.5, 'unknown'], ['105.61', 105.5, 'no'], ['1.15', 1.14, 'unknown'], ['1.10', 1.11, 'unknown'], ['1.12', 1.14, 'no'],
    ['20.00', 20, 'unknown'], ['20.75', 20, 'unknown'], ['19.99', 20, 'unknown'], ['19.0', 20, 'unknown'], ['18.99', 20, 'no'], ['21.0', 20, 'unknown'], ['21.01', 20, 'no'],
    ['0.5', 1, 'unknown'], ['0.5', 2, 'no'], ['105.45', 105.45, 'unknown'], ['105.44', 105.45, 'unknown'], ['105.43', 105.45, 'no'],
    // A stated zero is never decided: a receiver may default a value it cannot parse to 0.
    ['0.5', 0, 'unknown'], ['-0.5', 0, 'unknown'], ['105.05', 0, 'unknown'],
  ];
  for (const [t, x, want] of rows) assert.deepEqual(states(t, pin('equals', x)), ['unknown', want], `${t} vs ${JSON.stringify(x)}`);
  // The precision is the pinned value's, trailing zeros dropped: "105.50" beside 105.5 pins 105.5.
  assert.deepEqual(states('105.38', pin('in', [105.5, '105.50'])), ['unknown', 'no']);
  assert.deepEqual(states('105.42', pin('in', [105.5, '105.50'])), ['unknown', 'unknown']);
});

test('4. pinned values: a number states a value, a canonical decimal string only beside a number stating the same; in decides only when every member does', () => {
  // A string alone may be a version or a date ("1.05" and "1.5" are one version): never read as a number.
  for (const x of ['105.5', '105.50', '1.5']) assert.deepEqual(states('105.05', pin('equals', x)), ['unknown', 'unknown'], x);
  assert.deepEqual(states('1.05', pin('in', ['1.5'])), ['unknown', 'unknown']);
  assert.deepEqual(states('105.05', pin('in', ['105.5', 105.05])), ['unknown', 'unknown'], 'a number stating another value is no intent for this one');
  assert.deepEqual(states('105.05', pin('in', ['105.5', 7])), ['unknown', 'unknown'], 'even when that number reads no');
  assert.deepEqual(states('105.05', pin('in', [105.5, '105.50'])), ['unknown', 'no']);
  for (const x of ['105,5', '1e2', '+105.5', '0105.5', '105.5 ', 'abc', '']) assert.deepEqual(states('105.05', pin('in', [105.5, x])), ['unknown', 'unknown'], x);
  for (const x of [1e21, 1e-7, true, null]) assert.deepEqual(states('105.05', pin('equals', x)), ['unknown', 'unknown'], String(x));
  assert.deepEqual(states('105.05', pin('in', [105.5, '105.5'])), ['unknown', 'no'], 'R62-024');
  assert.deepEqual(states('41.5', pin('in', [14.5, '14.5'])), ['unknown', 'no'], 'R62-133');
  assert.deepEqual(states('105.05', pin('in', [105.5, '105,5'])), ['unknown', 'unknown'], 'a member that states no value keeps it unknown');
  assert.deepEqual(states('105.05', pin('in', [105.5, 105.05])), ['unknown', 'unknown'], 'a compatible member keeps it unknown');
  assert.deepEqual(states('105.05', pin('in', [105.5, 'x'])), ['unknown', 'unknown']);
  // Exact text still matches; a decimal never matches a number (its group-mark reading differs).
  assert.deepEqual(states('105.5', pin('equals', '105.5')), ['match', 'match']);
  assert.deepEqual(states('105.5', pin('equals', 105.5)), ['unknown', 'unknown']);
  // Ranges are not read on decimals.
  for (const op of ['gt', 'gte', 'lt', 'lte']) assert.deepEqual(states('105.05', pin(op, 1)), ['unknown', 'unknown'], op);
});

test('5. the default mode is main\'s, for form text and JSON alike; formDecimals touches only form decimals', () => {
  const texts = ['105.05', '105.5', '105.50', '2000', '0', '-5', '1.050', '1,050', '01.5', '1e3', '5 USD', 'refund', 'Refund', 'true', '', ' 7', '2024-0001'];
  const operands = [105.5, 105.05, 20, 2000, 0, -5, 1050, '105.5', '105,5', '2000', 'refund', 'true', true, null];
  const json = v => ({ status: 'captured', values: { '/amount': { type: typeof v === 'number' ? 'number' : 'string', value: v } } });
  for (const t of texts) for (const x of operands) for (const entry of [pin('equals', x), pin('in', [x, 'zzz']), ...(typeof x === 'number' ? [pin('gt', x)] : [])]) {
    const was = frozenFields.fieldState(form(t), entry);
    assert.equal(fieldState(form(t), entry), was, `form ${t} ${JSON.stringify(entry)}`);
    const decided = fieldState(form(t), entry, DECIMALS);
    if (decided !== was) assert.ok(was === 'unknown' && decided === 'no' && /^-?(0|[1-9][0-9]*)[.,][0-9]+$/.test(t), `form ${t} ${JSON.stringify(entry)}: ${was} -> ${decided}`);
    for (const value of [t, ...(typeof x === 'number' ? [x] : [])]) {
      assert.equal(fieldState(json(value), entry, DECIMALS), frozenFields.fieldState(json(value), entry), `json ${JSON.stringify(value)}`);
    }
  }
});

test('6. integer form text keeps its decided reading in both modes', () => {
  assert.deepEqual(states('2000', pin('equals', 20)), ['no', 'no']);
  assert.deepEqual(states('2000', pin('equals', 2000)), ['match', 'match']);
  assert.deepEqual(states('2000', pin('gt', 1000)), ['match', 'match']);
  assert.deepEqual(states('105', pin('equals', 105.5)), ['no', 'no']);
  assert.deepEqual(states('0105', pin('equals', 105)), ['unknown', 'unknown']);
});

// ---------------------------------------------------------------------------
test('7. evaluateEffectAssertion: only missing moves, and only to fail; a pass it would give is never taken', () => {
  const count = expected => ({ kind: 'effect.count', select: refunds(LISTED), expected });
  const exists = { kind: 'effect.exists', select: refunds(LISTED) }, none = { kind: 'effect.none', select: refunds(LISTED) };
  const failed = verdictOf(count(1), ['105.05', '105.05']);
  assert.equal(failed.verdict, 'fail', 'R62-024: two refunds of 105.05, none of 105.5');
  assert.match(failed.basis, /Decided by 2 committed send\(s\) whose form-encoded decimal differs/);
  assert.doesNotMatch(failed.basis, /105\.05/, 'the basis names counts, never a captured value');
  assert.equal(verdictOf(count(1), ['41.5']).verdict, 'fail', 'R62-133 shape');
  assert.equal(verdictOf(exists, ['105.05']).verdict, 'fail', 'absence of the expected refund');
  assert.equal(verdictOf(count(1), ['105.5', '105.5', '105.05']).verdict, 'fail', 'over count once the decimal is decided');
  // The pass a decided reading would give is never taken.
  assert.equal(verdictOf(count(1), ['105.5', '105.05']).verdict, 'missing', 'the decided count would be exactly 1');
  assert.equal(verdictOf(count(0), ['105.05']).verdict, 'missing');
  assert.equal(verdictOf(none, ['105.05']).verdict, 'missing', 'effect.none fails only on a match');
  // Undecided otherwise, as before.
  assert.equal(verdictOf(count(1), ['105.50']).verdict, 'missing');
  assert.equal(verdictOf(count(1), ['105.05', '105.50']).verdict, 'missing', 'one send still undecided');
  // A gap keeps the earlier verdict, with its decided-by-gaps mark (identity option B reads it).
  const gapped = evaluateEffectAssertion(count(1), [win([send('105.05')], { coverage: 'partial' })], { countBy: true, scoped: true });
  assert.equal(gapped.verdict, 'missing');
  const gapOnly = evaluateEffectAssertion(count(1), [win([], { coverage: 'partial' })], { countBy: true, scoped: true });
  assert.equal(decidedByGaps(gapOnly), true);
  assert.equal(evaluateEffectAssertion(count(1), [win([send('105.5')])], { countBy: true }).verdict, 'pass');
});

test('8. judgeOnly: a decided decimal outside the set fails; one an allow without the pin would absorb stays missing', () => {
  const only = (allow = []) => ({ kind: 'effect.only', expect: [{ select: refunds(LISTED), count: 1 }], allow, sources: ['http-egress'] });
  const judged = (clause, texts) => judgeOnly(clause, [win(texts.map(t => send(t)))], { fields: true, countBy: true });
  const outside = judged(only(), ['105.5', '105.05']);
  assert.equal(outside.verdict, 'fail');
  assert.match(outside.basis, /Decided by 1 committed send\(s\)/);
  assert.equal(judged(only([refunds()]), ['105.5', '105.05']).verdict, 'missing', 'the allow without the pin would pass it: not taken');
  assert.equal(judged(only([refunds([pin('in', [5, 10])])]), ['105.5', '105.05']).verdict, 'fail', 'a pinned allow it misses');
  assert.equal(judged(only([refunds([pin('in', [105.05])])]), ['105.5', '105.05']).verdict, 'missing', 'a pinned allow it could fill');
  assert.equal(judged(only(), ['105.5', '105.50']).verdict, 'missing');
  assert.equal(judged(only(), ['105.5']).verdict, 'pass');
  // Without the fields option (COLLATERAL-02) nothing changes.
  assert.equal(judgeOnly({ kind: 'effect.only', allow: [refunds()], sources: ['http-egress'] }, [win([send('105.05')])]).verdict, 'pass');
  // The HTTP evaluator reads the same.
  assert.equal(verdictOf(only(), ['105.5', '105.05']).verdict, 'fail');
});

test('9. every other reader keeps today\'s unknown: a decimal that differs still "could be" the clause\'s effect', () => {
  const differing = send('105.05');
  assert.equal(matchState(differing, refunds(LISTED)), 'unknown');
  assert.equal(fitsSelector(differing, refunds(LISTED)), true, 'settlement: a late send that could be this check\'s effect');
  const actorScope = { ...SCOPE, actorAttribution: 'principal' };
  const other = send('105.05', { actor: 'bob' });
  assert.equal(otherActorCommit({ kind: 'effect.exists', select: refunds(LISTED, { actor: 'alice' }) }, [win([other], { scope: actorScope })], 'alice'), true, 'rests-on: another actor\'s send that could fit');
  // Only the two fail-only judgements pass formDecimals (a source scan of the product code).
  const root = fileURLToPath(new URL('..', import.meta.url));
  const files = [];
  const walk = dir => { for (const name of readdirSync(dir)) { const path = join(dir, name); if (statSync(path).isDirectory()) { if (!['fixtures', 'node_modules', '.runtime'].includes(name)) walk(path); } else if (name.endsWith('.mjs') && !name.endsWith('.test.mjs')) files.push(path); } };
  for (const dir of ['src', 'integrations']) walk(join(root, dir));
  const uses = files.flatMap(path => (readFileSync(path, 'utf8').match(/formDecimals: true|judgeEffect\([^)]*, true\)|judgeOnlyWith\(true/g) ?? []).map(m => [path.slice(root.length), m]));
  assert.deepEqual(uses.map(([path]) => path).sort(), ['integrations/collateral/only.mjs', 'src/effect-events.mjs', 'src/effect-events.mjs'], JSON.stringify(uses));
  // No other product file names the option at all, however it would pass it.
  assert.deepEqual(files.filter(path => readFileSync(path, 'utf8').includes('formDecimals')).map(path => path.slice(root.length)).sort(),
    ['integrations/collateral/only.mjs', 'src/body-fields.mjs', 'src/effect-events.mjs']);
});

test('10. differential against 9f6098e: over 4,000 seeded clauses a verdict moves only from missing to fail', () => {
  // mulberry32: exact 32-bit integer steps.
  let state = 0x62342fb;
  const rand = n => { state = (state + 0x6d2b79f5) | 0; let t = Math.imul(state ^ (state >>> 15), 1 | state); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) % n; };
  const pick = list => list[rand(list.length)];
  const texts = ['105.05', '105.5', '105.50', '105.499', '41.5', '14.5', '1.050', '1,050', '200.00', '20', '2000', '0.5', '-0.5', '01.5', '1e3', 'refund'];
  const values = [105.5, 14.5, 20, 1050, 0, 105.05];
  const fieldsOf = () => { const x = pick(values); return [rand(2) ? pin('in', [x, String(x)]) : pin('equals', rand(2) ? x : String(x))]; };
  const tally = { cases: 0, changed: 0, byKind: {} };
  for (let i = 0; i < 4000; i++) {
    const events = Array.from({ length: rand(4) }, () => send(pick(texts)));
    const windows = [win(events, { coverage: rand(5) ? 'complete' : 'partial' })];
    const kind = pick(['effect.none', 'effect.exists', 'effect.count', 'effect.only']);
    let now, was;
    if (kind === 'effect.only') {
      const clause = { kind, expect: [{ select: refunds(fieldsOf()), count: 1 + rand(2) }], allow: [[], [refunds()], [refunds(fieldsOf())]][rand(3)], sources: ['http-egress'] };
      now = judgeOnly(clause, windows, { fields: true, countBy: true }).verdict; was = frozenOnly.judgeOnly(clause, windows, { fields: true, countBy: true }).verdict;
    } else {
      const clause = { kind, select: refunds(fieldsOf()), ...(kind === 'effect.count' ? { expected: rand(3) } : {}) };
      now = evaluateEffectAssertion(clause, windows, { countBy: true }).verdict; was = frozenEvents.evaluateEffectAssertion(clause, windows, { countBy: true }).verdict;
    }
    tally.cases++;
    if (now === was) continue;
    assert.deepEqual([was, now], ['missing', 'fail'], `${kind} ${JSON.stringify(events.map(e => e.captured.values['/amount'].value))}`);
    tally.changed++;
    tally.byKind[kind] = (tally.byKind[kind] ?? 0) + 1;
  }
  console.log(`# differential ${JSON.stringify(tally)}`);
  assert.ok(tally.changed > 100 && tally.byKind['effect.count'] > 0 && tally.byKind['effect.exists'] > 0 && tally.byKind['effect.only'] > 0 && !tally.byKind['effect.none'], JSON.stringify(tally));
});

// ---------------------------------------------------------------------------
// End to end: an app sends one refund as a form body through a real egress recorder. The baseline sends amount=105.05 against a
// count pinned to 105.5 (a decided decimal: fail); the candidate sends 105.5 (exact text: pass). The comparison credits the repair,
// as for any fail: the decimal is read from the recorder's own capture of the request bytes, never from an application record.
async function refundApp(t, sinkPort, amount) {
  const outbound = (host, path, body) => new Promise(resolve => { const req = request({ host: '127.0.0.1', port: sinkPort, method: body === undefined ? 'GET' : 'POST', path: `http://${host}${path}`,
    headers: { host, ...(body === undefined ? {} : { 'content-type': 'application/x-www-form-urlencoded' }) } }, res => { res.resume(); res.on('end', resolve); }); req.on('error', resolve); req.end(body); });
  const server = createServer(async (req, res) => {
    const reply = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(body)); };
    req.resume();
    if (req.headers.authorization !== 'Bearer synthetic-ops-token') return reply(401, {});
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/me') return reply(200, { user: 'ops' });
    if (url.pathname === '/ping') { await outbound(WITNESS, `/w?scopehaven_witness=${encodeURIComponent(url.searchParams.get('scopehaven_witness') ?? '')}`); return reply(200, { ok: true }); }
    if (url.pathname === '/refund') { await outbound(BILL, '/v1/refunds', `amount=${amount.value}`); return reply(200, { ok: true }); }
    reply(404, {});
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => { server.close(r); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}`;
}
const WITNESS = 'witness.scopehaven.invalid';
const env = { SCOPEHAVEN_TARGET_OPS: 'synthetic-ops-token' };
const COUNT = Object.freeze({ kind: 'effect.count', select: refunds(LISTED), expected: 1 });
const runs = t => onFreePorts(1, async port => {
  const amount = { value: '105.05' };
  const p = { id: 'refunds', name: 'Refunds', applicationId: 'refunds', origin: await refundApp(t, port, amount), buildLabel: 'b1', contextId: 'synthetic-refunds',
    actors: { ops: { principalId: 'ops', credentialEnv: 'SCOPEHAVEN_TARGET_OPS', identityValue: 'ops' } }, requiredControlIds: ['WHOAMI'],
    observers: [{ id: 'sink', type: 'egress-recorder', port, routing: 'proxy', destinations: [{ host: BILL, paths: ['/v1/refunds'], capture: { pointers: ['/amount'], maxBytes: 1024, encodings: ['json', 'form'] } }],
      witness: { actorId: 'ops', method: 'GET', path: '/ping', host: WITNESS }, settleMs: 250, quietMs: 150 }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'ops', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'ops' }] },
      { id: 'REFUND', title: 'REFUND', category: 'billing', severity: 'high', actorId: 'ops', method: 'POST', path: '/refund', body: {}, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }], effects: [COUNT] }] };
  validateTargetFile({ schemaVersion: 1, targets: [p] });
  const watch = watchingBinds(buildObservers);
  const out = { p };
  for (const [key, value] of [['baseline', '105.05'], ['spelled', '105.50'], ['candidate', '105.5']]) { amount.value = value; out[key] = await runHttpAssessment(p, { env, observerFactory: watch.factory }); }
  return { ...out, lostBind: watch.state.lostBind };
}, r => r.lostBind);

test('11. end to end: a form refund of 105.05 fails a count pinned to 105.5, 105.50 stays inconclusive, and the repair to 105.5 is credited', async t => {
  const r = await runs(t);
  const rowOf = (run, id) => run.results.find(x => x.id === id);
  const clause = run => rowOf(run, 'REFUND').trace[1].data.effects[0];
  const amounts = run => rowOf(run, 'REFUND').trace[1].data.windows[0].events.filter(e => e.name === BILL).map(e => e.captured.values['/amount']);
  assert.deepEqual(amounts(r.baseline), [{ type: 'text', value: '105.05' }]);
  assert.deepEqual([clause(r.baseline).verdict, clause(r.spelled).verdict, clause(r.candidate).verdict], ['fail', 'missing', 'pass']);
  assert.deepEqual(['baseline', 'spelled', 'candidate'].map(k => rowOf(r[k], 'REFUND').status), ['fail', 'inconclusive', 'pass']);
  const suite = createRegistry({ profiles: [r.p], env }).exportSuite(r.p.id);
  for (const k of ['baseline', 'spelled', 'candidate']) validateHttpRunEvidence(r[k], { expectedSuite: suite });
  // A decided-decimal baseline fail is an ordinary fail: the repair is credited.
  const comparison = compareRuns(r.baseline, r.candidate);
  assert.equal(comparison.compatible, true, JSON.stringify(comparison.reasons));
  assert.equal(comparison.summary.fixed, 1, JSON.stringify(comparison.rows));
  assert.notEqual(comparison.restorationLabel, NO_VERIFIED_REPAIR);
  // A baseline that only abstained (105.50) credits nothing.
  assert.equal(compareRuns(r.spelled, r.candidate).summary.fixed, 0);
});
