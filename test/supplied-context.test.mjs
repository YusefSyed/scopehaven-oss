import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAssessment, evaluateCheck } from '../src/runner.mjs';
import { CHECKS, RECORDS, ORDERS, SUBSCRIPTIONS, CANARIES, digest } from '../src/suite.mjs';
import { tenantsInDelivery } from '../src/evaluator-synthetic.mjs';
import { suppliedContext, SUPPLIED_CONTEXT_SCHEMA as FIXTURE_SCHEMA, SUPPLIED_CONTEXT_BOUNDS as FIXTURE_BOUNDS } from '../src/fixture.mjs';
import { projectSyntheticContract, groundednessReading, readSuppliedContext, CONTRACT_EVALUATOR_HASH,
  SUPPLIED_CONTEXT_SCHEMA, SUPPLIED_CONTEXT_BOUNDS } from '../src/contract-synthetic.mjs';
import { contractView, compareContracts, gateContracts, shadowRun } from '../src/contract-views.mjs';
import { validateReadings, validateView } from '../src/evidence-contract.mjs';
import { extractAll, SHAPES } from '../integrations/groundedness/groundedness.mjs';
import { summarizeGate } from '../integrations/regression-gate/gate.mjs';

// Supplied-context channel and the report-only groundedness reading (SPEC.md db2c7fc8,
// tests T1-T13, plus T14-T16 from the docs-sync review: H1, M1, L2). The channel is the
// trace's `suppliedContext`, beside `events`, so no delivery or verdict rule reads it.
// Owned synthetic fixture on ephemeral 127.0.0.1 ports; no model, provider, network
// destination or saved private run.

const vulnerable = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const RUNS = { vulnerable, repaired };
const attemptsOf = run => run.results.flatMap(row => row.attempts.map(attempt => ({ row, attempt })));
const contextOf = attempt => attempt.evidence.suppliedContext;
const reseal = run => { for (const row of run.results) row.evidenceDigest = digest(row.attempts); return run; };
// A resealed copy whose every channel record is passed through `edit` (return null to drop it).
const variant = (run, edit) => {
  const copy = structuredClone(run);
  for (const row of copy.results) for (const attempt of row.attempts) {
    const next = edit(structuredClone(attempt.evidence.suppliedContext), attempt);
    if (next === null) delete attempt.evidence.suppliedContext; else attempt.evidence.suppliedContext = next;
  }
  return reseal(copy);
};
// Everything in a view except the readings and the digest over them.
function stripReadings(value) {
  if (Array.isArray(value)) return value.map(stripReadings);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).filter(([key]) => !['readings', 'viewDigest', 'gradedWith'].includes(key)).map(([key, inner]) => [key, stripReadings(inner)]));
  return value;
}
const readingsOf = view => view.checks.flatMap(c => [c.readings.groundedness, ...c.observations.map(o => o.readings.groundedness)]);
const tFor = (reply, rows) => ({ suppliedContext: suppliedContext(rows), output: { reply } });
const withData = (reply, data) => ({ suppliedContext: { ...data, digest: digest(data.entries) }, output: { reply } });

test('T1 every complete attempt carries one sealed, well-formed supplied-context record, and no context event', () => {
  assert.deepEqual(FIXTURE_BOUNDS, SUPPLIED_CONTEXT_BOUNDS, 'fixture and contract bounds agree');
  assert.equal(FIXTURE_SCHEMA, SUPPLIED_CONTEXT_SCHEMA);
  for (const [build, run] of Object.entries(RUNS)) {
    for (const { row, attempt } of attemptsOf(run)) {
      assert.equal(attempt.evidence.complete, true, `${build} ${row.id}: complete`);
      assert.ok(!attempt.evidence.events.some(e => e.type === 'context'), `${build} ${row.id}: the channel is not an event`);
      const data = contextOf(attempt);
      assert.equal(data.schema, SUPPLIED_CONTEXT_SCHEMA); assert.equal(data.turn, 0); assert.equal(data.truncated, false);
      assert.equal(data.digest, digest(data.entries));
      data.entries.forEach((entry, i) => assert.equal(entry.entryId, `e${i}`));
      assert.ok(readSuppliedContext(attempt.evidence).entries, `${build} ${row.id}: readable`);
    }
    for (const row of run.results) assert.ok(!row.trace.some(e => e.type === 'context' || Object.hasOwn(e.data ?? {}, 'entries')), `${build} ${row.id}: not in the report trace`);
  }
});

test('T2 tenant tags come from the data row, never from the caller', () => {
  const rowTenant = entry => entry.origin === 'record' || entry.origin === 'record-field' ? RECORDS.find(r => r.id === entry.sourceId)?.tenantId
    : entry.origin === 'order' ? ORDERS.find(o => o.id === entry.sourceId)?.tenantId : entry.origin === 'subscription' ? SUBSCRIPTIONS.find(s => s.id === entry.sourceId)?.tenantId : undefined;
  let crossTenantTagged = 0;
  for (const run of Object.values(RUNS)) for (const { attempt } of attemptsOf(run)) for (const entry of contextOf(attempt).entries) {
    const expected = rowTenant(entry);
    if (expected !== undefined) assert.equal(entry.tenantId, expected, `${entry.origin} ${entry.sourceId}`);
    if (entry.tenantId !== null && entry.tenantId !== attempt.evidence.actor.tenantId) crossTenantTagged++;
  }
  assert.ok(crossTenantTagged > 0, 'the baseline hands some caller another tenant\'s row, and the tag says so');
  const summaries = run => attemptsOf(run).filter(({ row, attempt }) => row.id === 'CANARY-01' && attempt.actor === 'alice' && attempt.operation === 'account-summary');
  const activityTenants = run => summaries(run).flatMap(({ attempt }) => contextOf(attempt).entries.filter(e => e.origin === 'activity').map(e => e.tenantId));
  assert.ok(summaries(vulnerable).length > 0 && summaries(repaired).length > 0);
  assert.ok(activityTenants(vulnerable).includes('cobalt'), 'baseline: the leaked activity entry is tagged cobalt');
  assert.ok(!activityTenants(repaired).includes('cobalt'), 'repaired: no cobalt activity is supplied');
});

test('T3 entries hold only what the reply path read, and the delivery rule never sees them', () => {
  for (const run of Object.values(RUNS)) for (const { row, attempt } of attemptsOf(run)) {
    const t = attempt.evidence, exports = t.after.exports.slice(t.before.exports.length);
    const readIds = t.events.filter(e => ['retrieval', 'cache'].includes(e.type)).flatMap(e => e.data.recordIds ?? []);
    for (const entry of contextOf(attempt).entries.filter(e => ['record', 'record-field'].includes(e.origin)))
      assert.ok(readIds.includes(entry.sourceId), `${row.id}: ${entry.sourceId} was delivered by a retrieval or cache event`);
    // Only the account summary reads an order's or plan's note; elsewhere the entry carries the fields the decision read.
    for (const entry of contextOf(attempt).entries.filter(e => ['order', 'subscription'].includes(e.origin)))
      assert.equal(Object.hasOwn(entry.fields, 'note'), attempt.operation === 'account-summary', `${row.id} ${attempt.operation}: ${entry.sourceId} note`);
    // With the primary delivery evidence stripped, the channel alone delivers nothing.
    const stripped = { output: { ...t.output, reply: '' }, events: t.events.filter(e => !['retrieval', 'cache'].includes(e.type)), exports: [], principalId: t.actor.principalId };
    const withChannel = { ...stripped, suppliedContext: t.suppliedContext };
    assert.deepEqual(tenantsInDelivery(withChannel), tenantsInDelivery(stripped), `${row.id}: the channel is not a delivery record`);
    assert.deepEqual(tenantsInDelivery({ output: t.output, events: t.events, exports, principalId: t.actor.principalId }),
      tenantsInDelivery({ output: t.output, events: t.events, exports, principalId: t.actor.principalId, suppliedContext: t.suppliedContext }));
  }
});

test('T4 nothing else moves: statuses, assertions and every contract field except readings', () => {
  const canaries = Object.values(CANARIES).flat();
  for (const [build, run] of Object.entries(RUNS)) {
    const stripped = variant(run, () => null);
    for (const [i, row] of run.results.entries()) {
      const def = CHECKS.find(c => c.id === row.id);
      const a = evaluateCheck(def, row.attempts), b = evaluateCheck(def, stripped.results[i].attempts);
      assert.equal(a.status, row.status, `${build} ${row.id}: stored status recomputes`);
      assert.equal(b.status, a.status, `${build} ${row.id}: status without the channel`);
      assert.deepEqual(b.assertions, a.assertions, `${build} ${row.id}: assertions without the channel`);
    }
    assert.deepEqual(stripReadings(projectSyntheticContract(stripped)), stripReadings(projectSyntheticContract(run)), `${build}: view without readings`);
    for (const { attempt } of attemptsOf(run)) for (const entry of contextOf(attempt).entries.filter(e => ['policy', 'request', 'document'].includes(e.origin)))
      assert.ok(!canaries.some(value => JSON.stringify(entry.fields).includes(value)), `${entry.origin} entry carries no canary`);
  }
});

test('T5 the reading never feeds a verdict, comparison, gate or shadow status', () => {
  const variants = {
    removed: () => null,
    emptied: c => ({ ...c, entries: [], digest: digest([]) }),
    digestBroken: c => ({ ...c, digest: '0'.repeat(64) }),
    truncated: c => ({ ...c, truncated: true }),
    malformed: c => { const entries = [{ entryId: 'e0', origin: 'record', sourceId: 'x', tenantId: 'aster', fields: { deep: { deeper: 1 } } }]; return { ...c, entries, digest: digest(entries) }; },
    foreignCanaries: c => { const entries = [{ entryId: 'e0', origin: 'record', sourceId: 'record-cobalt', tenantId: 'cobalt', fields: { text: Object.values(CANARIES).flat().join(' ') } }]; return { ...c, entries, digest: digest(entries) }; },
  };
  const gate = (candidate, baseline) => gateContracts({ candidate, baseline }, { summarizeGate });
  const original = { view: stripReadings(contractView(repaired)), compare: compareContracts(vulnerable, repaired), gate: gate(repaired, vulnerable),
    shadow: shadowRun(repaired).results.map(r => [r.id, r.status]), readings: readingsOf(contractView(repaired)).map(g => g.reading) };
  assert.equal(original.compare.supported, true); assert.equal(original.gate.supported, true);
  const seen = new Set(original.readings);
  for (const [name, edit] of Object.entries(variants)) {
    const base = variant(vulnerable, edit), cand = variant(repaired, edit), view = contractView(cand);
    assert.equal(view.supported, true, `${name}: view stays supported`);
    assert.deepEqual(stripReadings(view), original.view, `${name}: view without readings`);
    assert.deepEqual(compareContracts(base, cand), original.compare, `${name}: compareContracts`);
    assert.deepEqual(gate(cand, base), original.gate, `${name}: gateContracts`);
    assert.deepEqual(shadowRun(cand).results.map(r => [r.id, r.status]), original.shadow, `${name}: shadow statuses`);
    for (const g of readingsOf(view)) seen.add(g.reading);
  }
  for (const reading of ['ungrounded-data-present', 'all-extracted-data-grounded', 'no-data-extracted', 'inconclusive']) assert.ok(seen.has(reading), `variants exercised ${reading}`);
});

test('T6 only the contract modules import the reading, and no verdict path names readings', async () => {
  const root = fileURLToPath(new URL('..', import.meta.url));
  const walk = async dir => (await readdir(dir, { withFileTypes: true })).flatMap(entry => entry.name === 'node_modules' || entry.name.startsWith('.') ? []
    : entry.isDirectory() ? [join(dir, entry.name)] : entry.name.endsWith('.mjs') && !entry.name.endsWith('.test.mjs') ? [join(dir, entry.name)] : []);
  const files = [];
  for (const top of ['src', 'integrations', 'public', 'design', 'examples']) {
    const queue = [join(root, top)];
    while (queue.length) for (const path of await walk(queue.shift()).catch(() => [])) (path.endsWith('.mjs') ? files : queue).push(path);
  }
  const importers = [];
  for (const file of files) if (/from\s+['"][^'"]*groundedness\/groundedness\.mjs['"]/.test(await readFile(file, 'utf8'))) importers.push(relative(root, file));
  // evidence-contract takes only the SHAPES list, to validate readings against the module's own vocabulary.
  assert.deepEqual(importers.sort(), ['src/contract-synthetic.mjs', 'src/evidence-contract.mjs']);
  for (const name of ['src/runner.mjs', 'src/evaluator-synthetic.mjs', 'src/contract-views.mjs', 'src/sarif.mjs', 'src/report.mjs', 'src/server.mjs', 'integrations/regression-gate/gate.mjs'])
    assert.doesNotMatch(await readFile(join(root, name), 'utf8'), /\breadings\b|groundedness|suppliedContext/, `${name} reads no reading and no channel`);
});

test('T7 the readings validator refuses verdict vocabulary, raw tokens, bad counts and oversized arrays', () => {
  const real = contractView(vulnerable).checks.find(c => c.readings.groundedness.reading === 'all-extracted-data-grounded').readings;
  assert.ok(validateReadings(real));
  assert.deepEqual(real.groundedness.shapesChecked, [...SHAPES], 'the validator and the reading share the module\'s shape list');
  const broken = [
    r => { r.groundedness.prohibition = true; },
    r => { r.groundedness.verdict = 'fail'; },
    r => { r.groundedness.status = 'pass'; },
    r => { r.groundedness.outcome = 'ok'; },
    r => { r.groundedness.ungrounded = [{ shape: 'id', token: 'ORD-77' }]; r.groundedness.bySource.none = 1; r.groundedness.extracted += 1; r.groundedness.reading = 'ungrounded-data-present'; },
    r => { r.groundedness.ungrounded = [{ shape: 'id', canonicalDigest: 'id:ORD-77' }]; r.groundedness.bySource.none = 1; r.groundedness.extracted += 1; r.groundedness.reading = 'ungrounded-data-present'; },
    r => { const n = 201; r.groundedness.ungrounded = Array.from({ length: n }, () => ({ shape: 'id', canonicalDigest: 'a'.repeat(64) })); r.groundedness.bySource = { own: 0, foreign: 0, neutral: 0, request: 0, policy: 0, none: n }; r.groundedness.extracted = n; r.groundedness.reading = 'ungrounded-data-present'; },
    r => { r.groundedness.bySource.own += 1; },
    r => { r.groundedness.reading = 'ungrounded-data-present'; },
    r => { r.groundedness.lineage.independence = 'independent'; },
    r => { r.groundedness.schema = 'scopehaven-groundedness-reading/2'; },
    r => { r.groundedness.shapesChecked = [...SHAPES, 'name']; },
  ];
  broken.forEach((mutate, i) => { const copy = structuredClone(real); mutate(copy); assert.throws(() => validateReadings(copy), undefined, `case ${i} refused`); });
  assert.throws(() => validateReadings({ groundedness: { schema: 'scopehaven-groundedness-reading/1', prohibition: false, reading: 'inconclusive', shapesChecked: [...SHAPES] } }), undefined, 'inconclusive needs a reason');
});

test('T8 no reply text reaches the readings: ungrounded values appear only as digests', () => {
  for (const run of Object.values(RUNS)) {
    const emptied = variant(run, c => ({ ...c, entries: [], digest: digest([]) }));
    for (const source of [run, emptied]) {
      const view = contractView(source), text = JSON.stringify(view.checks.map(c => [c.readings, c.observations.map(o => o.readings)]));
      for (const { attempt } of attemptsOf(source)) for (const item of extractAll(attempt.evidence.output.reply)) {
        assert.ok(!text.includes(item.token), `token ${item.token} absent from readings`);
        assert.ok(!text.includes(item.canonical[0]), `canonical ${item.canonical[0]} absent from readings`);
      }
      if (source === emptied) assert.ok(readingsOf(view).some(g => g.ungrounded?.length), 'emptied context produces digests to check');
    }
  }
});

test('T9 absent, empty and nothing-extracted stay distinct', () => {
  const absent = contractView(variant(vulnerable, () => null));
  for (const g of readingsOf(absent).filter(g => g.reading !== 'not-derived')) assert.deepEqual([g.reading, g.reason], ['inconclusive', 'no-supplied-context-recorded']);
  const reply = 'Your order order-aster-recent was placed on 2026-09-21.';
  assert.equal(groundednessReading(tFor(reply, []), 'aster', '/x').reading, 'ungrounded-data-present');
  assert.equal(groundednessReading({ output: { reply } }, 'aster', '/x').reason, 'no-supplied-context-recorded');
  const cad = groundednessReading(tFor('Your refund of 20 CAD has been processed.', [{ origin: 'request', sourceId: null, tenantId: null, fields: { amount: 20, currency: 'CAD' } }]), 'aster', '/x');
  assert.deepEqual([cad.reading, cad.extracted], ['no-data-extracted', 0]);
});

test('T10 tampering and malformed records: a changed entry breaks the seal; the rest read inconclusive', () => {
  const unsealed = structuredClone(vulnerable);
  const row = unsealed.results.find(r => r.id === 'TENANT-01');
  row.attempts[0].evidence.suppliedContext.entries[0].fields.text = 'edited after the run';
  const check = projectSyntheticContract(unsealed).checks.find(c => c.checkId === 'TENANT-01');
  assert.equal(check.observations[0].readings.groundedness.reading, 'not-derived');
  // The check keeps its last observation's not-derived reading, as completionTruth keeps a non-derived state.
  assert.deepEqual([check.readings.groundedness.reading, check.readings.groundedness.reason], ['not-derived', 'evidence-digest-mismatch']);
  const reasons = edit => new Set(readingsOf(projectSyntheticContract(variant(vulnerable, edit))).filter(g => g.reading === 'inconclusive').map(g => g.reason));
  assert.ok(reasons(c => { if (c.entries[0]) c.entries[0].fields = { text: 'edited, digest kept' }; return c; }).has('context-digest-mismatch'));
  assert.ok(reasons(c => ({ ...c, truncated: true })).has('context-truncated'));
  assert.ok(reasons(c => ({ ...c, schema: 'scopehaven-supplied-context/2' })).has('context-malformed'));
  assert.ok(reasons(() => 'not a record').has('context-malformed'));
  // Strictness the spec requires (section 2.2): turn 0 only; policy and request entries carry no tenant.
  const policy = { entryId: 'e0', origin: 'policy', sourceId: null, tenantId: null, fields: { refundWindowDays: 30 } };
  const valid = { schema: SUPPLIED_CONTEXT_SCHEMA, turn: 0, truncated: false, entries: [policy] };
  assert.equal(groundednessReading(withData('Case ORD-77.', valid), 'aster', '/x').reading, 'ungrounded-data-present');
  assert.equal(groundednessReading(withData('Case ORD-77.', { ...valid, turn: 1 }), 'aster', '/x').reason, 'context-malformed');
  for (const origin of ['policy', 'request'])
    assert.equal(groundednessReading(withData('Case ORD-77.', { ...valid, entries: [{ ...policy, origin, tenantId: 'aster' }] }), 'aster', '/x').reason, 'context-malformed', `${origin} with a tenant`);
  assert.equal(groundednessReading(withData('Case ORD-77.', { ...valid, entries: [{ ...policy, origin: 'record', tenantId: null }] }), 'aster', '/x').reason, 'context-malformed', 'record without a tenant');
});

test('T11 origins stay apart: policy and request text never make a token record-backed', () => {
  const reply = 'Your order order-aster-recent was placed on 2026-09-21.';
  const policyOnly = groundednessReading(tFor(reply, [{ origin: 'policy', sourceId: null, tenantId: null, fields: { example: 'Example: order order-aster-recent placed 2026-09-21' } }]), 'aster', '/x');
  assert.deepEqual(policyOnly.bySource, { own: 0, foreign: 0, neutral: 0, request: 0, policy: 2, none: 0 });
  const echo = groundednessReading(tFor('We refunded $80.00.', [{ origin: 'request', sourceId: null, tenantId: null, fields: { amount: 80 } }]), 'aster', '/x');
  assert.deepEqual([echo.bySource.request, echo.bySource.own], [1, 0]);
  const order = { origin: 'order', sourceId: 'order-aster-recent', tenantId: 'aster', fields: { id: 'order-aster-recent', placedOn: '2026-09-21', total: 80 } };
  const both = groundednessReading(tFor(reply, [{ origin: 'policy', sourceId: null, tenantId: null, fields: { example: 'order-aster-recent 2026-09-21' } }, order]), 'aster', '/x');
  assert.deepEqual([both.bySource.own, both.bySource.policy], [2, 0], 'a record wins over policy');
  const foreign = groundednessReading(tFor(reply, [order]), 'cobalt', '/x');
  assert.deepEqual([foreign.bySource.foreign, foreign.bySource.own], [2, 0], 'another tenant\'s row is foreign to this caller');
});

test('T12 the groundedness module is part of the contract grader identity', async () => {
  const read = name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8');
  const four = ['evidence-contract.mjs', 'contract-synthetic.mjs', 'contract-http.mjs', 'contract-views.mjs'];
  const withModule = [...await Promise.all(four.map(read)), await read('../integrations/groundedness/groundedness.mjs')];
  assert.equal(CONTRACT_EVALUATOR_HASH, digest(withModule.join('\n')));
  assert.notEqual(CONTRACT_EVALUATOR_HASH, digest((await Promise.all(four.map(read))).join('\n')));
});

test('T13 bounds: anything over a bound is cut and flagged, and the reading then refuses', () => {
  const at = (n, fields = 1, length = 1) => Array.from({ length: n }, (_, i) => ({ origin: 'record', sourceId: `r${i}`, tenantId: 'aster',
    fields: Object.fromEntries(Array.from({ length: fields }, (_, j) => [`f${j}`, 'x'.repeat(length)])) }));
  const full = suppliedContext(at(64, 32, 512));
  assert.equal(full.truncated, false); assert.equal(full.entries.length, 64);
  for (const over of [at(65), at(1, 33), at(1, 1, 513)]) assert.equal(suppliedContext(over).truncated, true);
  assert.equal(suppliedContext(at(1, 1, 513)).entries[0].fields.f0.length, 512);
  assert.equal(groundednessReading(tFor('Case ORD-77.', at(65)), 'aster', '/x').reason, 'context-truncated');
  // Deepest nesting the channel allows (A1): field values are scalars, so a nested value is refused.
  const nested = { schema: SUPPLIED_CONTEXT_SCHEMA, turn: 0, truncated: false, entries: [{ entryId: 'e0', origin: 'record', sourceId: 'r0', tenantId: 'aster', fields: { f0: { deeper: 'x' } } }] };
  assert.equal(groundednessReading(withData('Case ORD-77.', nested), 'aster', '/x').reason, 'context-malformed');
  // A run whose every attempt carries a record at every bound still projects a valid view.
  const view = projectSyntheticContract(variant(repaired, () => suppliedContext(at(64, 32, 512))));
  assert.ok(validateView(view));
  assert.ok(readingsOf(view).every(g => g.reading !== 'inconclusive' || g.reason !== 'context-malformed'));
});

test('T14 a channel record alone never makes CANARY-01 pass or adds a canary tenant', () => {
  // docs-sync's repro: strip Bob's reply and retrieval events (his own delivery evidence), reseal, re-evaluate.
  const strip = (run, keepChannel) => {
    const copy = structuredClone(run), row = copy.results.find(r => r.id === 'CANARY-01');
    for (const a of row.attempts.filter(x => x.actor === 'bob')) {
      a.evidence.output.reply = 'Here is your summary.';
      a.evidence.events = a.evidence.events.filter(e => e.type !== 'retrieval');
      if (!keepChannel) delete a.evidence.suppliedContext;
    }
    const evaluated = evaluateCheck(CHECKS.find(c => c.id === 'CANARY-01'), row.attempts);
    Object.assign(row, { status: evaluated.status, assertions: evaluated.assertions, evidenceDigest: digest(row.attempts) });
    const check = projectSyntheticContract(copy).checks.find(c => c.checkId === 'CANARY-01');
    return { status: evaluated.status, contractStatus: check.contractStatus, canary: check.observations.filter((o, i) => row.attempts[i].actor === 'bob').map(o => o.stages.disclosure.value?.canaryTenants ?? null) };
  };
  const bob = attemptsOf(repaired).filter(({ row, attempt }) => row.id === 'CANARY-01' && attempt.actor === 'bob');
  assert.ok(bob.some(({ attempt }) => attempt.evidence.suppliedContext.entries.some(e => e.tenantId === 'cobalt')), 'Bob\'s channel names Cobalt data');
  const withChannel = strip(repaired, true), without = strip(repaired, false);
  assert.equal(withChannel.status, 'inconclusive'); assert.equal(withChannel.contractStatus, 'inconclusive');
  assert.deepEqual(withChannel, without, 'the channel changes nothing once the delivery evidence is gone');
  for (const tenants of withChannel.canary) assert.ok(!(tenants ?? []).includes('cobalt'), 'no canary tenant from the channel');
});

test('T15 the caller tenant is wired: baseline leaks read foreign, the repair reads none', () => {
  const foreignBy = view => view.checks.reduce((acc, c) => {
    const n = c.observations.reduce((sum, o) => sum + (o.readings.groundedness.bySource?.foreign ?? 0), 0);
    return n ? { ...acc, [c.checkId]: n } : acc;
  }, {});
  const own = view => readingsOf(view).reduce((n, g) => n + (g.bySource?.own ?? 0), 0);
  const leaks = foreignBy(contractView(vulnerable));
  for (const id of ['TENANT-01', 'CONCURRENT-01', 'CANARY-01']) assert.ok(leaks[id] > 0, `${id} reads a foreign-grounded token on the baseline`);
  assert.deepEqual(foreignBy(contractView(repaired)), {}, 'the repaired build reads no foreign-grounded token');
  assert.ok(own(contractView(vulnerable)) > 0 && own(contractView(repaired)) > 0, 'own-grounded tokens on both builds');
});

test('T16 the truth gate turns a derived check reading inconclusive', () => {
  const copy = structuredClone(repaired), row = copy.results.find(r => r.id === 'CANARY-01');
  row.attempts.splice(0, 1);
  const evaluated = evaluateCheck(CHECKS.find(c => c.id === 'CANARY-01'), row.attempts);
  Object.assign(row, { status: evaluated.status, assertions: evaluated.assertions, evidenceDigest: digest(row.attempts) });
  const check = projectSyntheticContract(copy).checks.find(c => c.checkId === 'CANARY-01');
  assert.ok(['shortfall', 'mismatch'].includes(check.scenario), `scenario ${check.scenario}`);
  assert.ok(!['inconclusive', 'not-derived'].includes(check.observations.at(-1).readings.groundedness.reading), 'the last observation reads a derived value');
  assert.equal(check.readings.groundedness.reading, 'inconclusive');
  assert.equal(check.readings.groundedness.reason, `unverifiable:scenario-${check.scenario}`);
});
