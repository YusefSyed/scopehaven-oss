// pg-snapshot read-back (src/pg-readback.mjs) against the scripted fake Postgres: a typed table model (pgModel) whose
// scans are evaluated from the observer's own select list, so these tests see exactly which columns a mark reads. No
// real database: the real server's text output for each type is in pg.live.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPgSnapshotObserver } from './pg-snapshot.mjs';
import { evaluateEffectAssertion, validateWindow } from './events.mjs';
import { judgeReadBack, ReadBackError, PG_READBACK_SCHEMA } from '../../src/pg-readback.mjs';
import { validateTargetFile } from '../../src/contracts.mjs';
import { pgModel, scriptedDb, USER, PASSWORD } from './fixtures/fake-postgres.mjs';
import { refundApp } from './fixtures/refund-app.mjs';

const env = { SCOPEHAVEN_TARGET_DB_READER: `${USER}:${PASSWORD}` };
const observerOn = (port, tables) => createPgSnapshotObserver({ env, host: '127.0.0.1', port, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables });
const ORDERS = () => ({ table: 'orders', key: 'id', columns: [{ name: 'refund_amount', type: '1700' }, { name: 'status', type: '25' }, { name: 'note', type: '25' }],
  rows: [{ id: 'A100', refund_amount: null, status: 'paid', note: 'n1' }, { id: 'A101', refund_amount: null, status: 'paid', note: 'n2' }] });
const REFUND = { columns: ['refund_amount', 'status'], expect: [{ key: 'A100', change: { refund_amount: { from: null, to: '40' }, status: { from: 'paid', to: 'refunded' } } }] };
// One window over a model: mark, act, mark, collect. beginState may override a mark's state (index 0 or 1).
async function readBack(t, model, tables, between, { log = [], override = () => ({}) } = {}) {
  const server = await scriptedDb(t, [], log, { beginState: m => ({ ...model.state(), ...override(m) }) });
  const o = observerOn(server.port, tables);
  const from = await o.mark();
  await between();
  const to = await o.mark();
  const out = await o.collect(from, to);
  return { out, record: out.readBack, verdict: judgeReadBack(out.readBack), log };
}
const check = (verdict, fields) => verdict.checks.find(c => Object.entries(fields).every(([k, v]) => c[k] === v));
const updateExists = resource => ({ kind: 'effect.exists', select: { source: 'sql-snapshot', name: 'orders', operation: 'update', resource } });

test('read-back: the defective twin writes 4 for a refund of 40 and reads FAIL; its fixed twin reads PASS, labelled subject-writable', async t => {
  const results = {};
  for (const defective of [true, false]) {
    const model = pgModel([ORDERS()]), app = await refundApp(t, model, { defective });
    const { out, record, verdict } = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: REFUND }], () => app.refund('A100', '40.00'));
    // The window is the same shape for both twins: one committed update of the order, which is all row versions can say.
    assert.equal(out.coverage, 'net-only');
    assert.deepEqual(out.events.map(e => [e.operation, e.resource]), [['update', 'orders/A100']]);
    assert.equal(evaluateEffectAssertion(updateExists('orders/A100'), [validateWindow({ source: 'sql-snapshot', scope: { operations: ['insert', 'update', 'delete'], names: ['orders'], actorAttribution: 'none', evidence: 'authoritative' }, coverage: out.coverage, reason: out.reason, events: out.events, exact: out.exact })]).verdict, 'pass');
    assert.equal(record.schema, PG_READBACK_SCHEMA);
    results[defective ? 'defective' : 'fixed'] = { verdict, after: record.tables[0].rows.find(r => r.key === 'A100').after };
  }
  const { defective, fixed } = results;
  assert.deepEqual(defective.after, { refund_amount: '4', status: 'refunded' });
  assert.equal(defective.verdict.verdict, 'fail');
  assert.deepEqual(defective.verdict.reasons, ['change-mismatch']);
  assert.equal(check(defective.verdict, { column: 'refund_amount' }).status, 'fail');
  assert.equal(check(defective.verdict, { column: 'status' }).status, 'pass');
  assert.deepEqual(fixed.after, { refund_amount: '40', status: 'refunded' });
  assert.equal(fixed.verdict.verdict, 'pass');
  assert.equal(fixed.verdict.custody, 'subject-writable');
  assert.match(fixed.verdict.basis, /custody subject-writable/);
});

test('read-back: a mark reads exactly the declared columns, as text (the rest only as sha256 digests); a table without readBack reads as before', async t => {
  const model = pgModel([ORDERS()]), log = [];
  const { out } = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: REFUND }], () => model.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }), { log });
  assert.equal(out.coverage, 'net-only');
  assert.deepEqual(model.valuesRead, ['orders.refund_amount', 'orders.status', 'orders.refund_amount', 'orders.status']);
  const scan = log.find(s => /FROM "public"\."orders" AS r/.test(s));
  assert.equal(scan, `SELECT (r."id")::text, r.xmin::text, pg_catalog.md5(r::text), r.tableoid::text, pg_catalog.left((r."refund_amount")::pg_catalog.text, 4097), pg_catalog.left((r."status")::pg_catalog.text, 4097), pg_catalog.encode(pg_catalog.sha256(pg_catalog.textsend(ROW(r."note")::pg_catalog.text)), 'hex'), pg_catalog.encode(pg_catalog.sha256(pg_catalog.textsend(r::pg_catalog.text)), 'hex') FROM "public"."orders" AS r ORDER BY 1, r.tableoid, r.ctid LIMIT 200001`);
  assert.ok(!log.some(s => s.includes('pg_catalog.left((r."note")')), 'an undeclared column is never read as a value');
  assert.ok(!log.some(s => /::pg_catalog\.jsonb/.test(s)), 'no cast that could fail the mark');
  // Without readBack: the scan, the statement count and the result are unchanged (no read-back statement, no record).
  const plain = [], states = [{ snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1']] } }, { snapshot: '800:800:', tables: { Chat: [['c1', '700', 'h1']] } }];
  const server = await scriptedDb(t, states, plain);
  const o = observerOn(server.port, [{ table: 'Chat', key: 'id' }]);
  const from = await o.mark(), to = await o.mark(), window = await o.collect(from, to);
  assert.ok(plain.includes('SELECT (r."id")::text, r.xmin::text, pg_catalog.md5(r::text), r.tableoid::text FROM "public"."Chat" AS r ORDER BY 1, r.tableoid, r.ctid LIMIT 200001'));
  assert.ok(!plain.some(s => /typbasetype/.test(s) && !/^\/\* sh:db(catalog|versions) \*\//.test(s)));
  assert.deepEqual(Object.keys(window).sort(), ['coverage', 'events', 'exact', 'reason']);
});

// Each kind, as the server prints it, and the canonical value recorded (two tables: 16 columns at most each).
const TYPED = [
  ['t_text', '25', 'h\u00e9llo', 'h\u00e9llo'], ['t_varchar', '1043', 'v', 'v'], ['t_bpchar', '1042', 'ab', 'ab'], ['t_uuid', '2950', '6f1c2a3e-0000-4000-8000-00000000abcd', '6f1c2a3e-0000-4000-8000-00000000abcd'],
  ['t_int2', '21', '-7', '-7'], ['t_int4', '23', '40', '40'], ['t_int8', '20', '9007199254740993', '9007199254740993'], ['t_numeric', '1700', '40.00', '40'],
  ['t_float4', '700', '0.1', '0.1'], ['t_float8', '701', '1e+21', '1000000000000000000000'], ['t_negzero', '701', '-0', '0'], ['t_bool', '16', 'true', true],
  ['t_ts', '1114', '2026-10-18 06:07:35.1205', '2026-10-18T06:07:35.1205'], ['t_tstz', '1184', '2026-10-18 06:07:35+00', '2026-10-18T06:07:35Z'], ['t_date', '1082', '2026-02-28', '2026-02-28'],
  ['t_json', '114', '{"b": 1, "a": [1.0, "x"], "z": "nul\\u0000"}', '{"a":[1,"x"],"b":1,"z":"nul\\u0000"}'], ['t_jsonb', '3802', '{"k": null}', '{"k":null}'], ['t_null', '25', null, null], ['t_domain', '90001', '12.50', '12.5'],
];
test('read-back: each supported type reads as its canonical value (text, decimal, boolean, ISO time, canonical JSON, a domain as its base)', async t => {
  const table = (name, cols) => ({ table: name, key: 'id', columns: cols.map(([n, type]) => ({ name: n, type, ...(type === '90001' ? { typtype: 'd', basetype: '1700' } : {}) })),
    rows: [{ id: 'r1', ...Object.fromEntries(cols.map(([n, , text]) => [n, text])) }] });
  const halves = [TYPED.slice(0, 10), TYPED.slice(10)];
  const model = pgModel(halves.map((cols, i) => table(`typed${i}`, cols)));
  // Expected as recorded (a json column's canonical value is itself JSON text).
  const tables = halves.map((cols, i) => ({ table: `typed${i}`, key: 'id', readBack: { columns: cols.map(([n]) => n), expect: [{ key: 'r1', values: Object.fromEntries(cols.map(([n, , , v]) => [n, v])) }] } }));
  const { record, verdict } = await readBack(t, model, tables, () => {});
  halves.forEach((cols, i) => {
    assert.equal(record.tables[i].status, 'ok');
    assert.deepEqual(record.tables[i].columns.map(c => c.kind), cols.map(([, type]) => ({ 25: 'text', 1043: 'text', 1042: 'char', 2950: 'uuid', 21: 'numeric', 23: 'numeric', 20: 'numeric', 1700: 'numeric', 700: 'numeric', 701: 'numeric', 16: 'boolean', 1114: 'timestamp', 1184: 'timestamptz', 1082: 'date', 114: 'json', 3802: 'json', 90001: 'numeric' })[type]));
    assert.deepEqual(record.tables[i].rows[0].after, Object.fromEntries(cols.map(([n, , , v]) => [n, v])));
  });
  assert.equal(verdict.verdict, 'pass', JSON.stringify(verdict.reasons));
  // Declared expectations in their usual spellings read as the same canonical values.
  const spelled = { t_int4: 40, t_numeric: '40.0', t_float8: '1e21', t_tstz: '2026-10-18T06:07:35.000+00:00', t_ts: '2026-10-18 06:07:35.120500', t_json: '{"z": "nul\\u0000", "b": 1.0, "a": [1, "x"]}', t_domain: '12.50',
    t_uuid: '6F1C2A3E-0000-4000-8000-00000000ABCD' };
  const model2 = pgModel(halves.map((cols, i) => table(`typed${i}`, cols)));
  const loose = await readBack(t, model2, halves.map((cols, i) => ({ table: `typed${i}`, key: 'id', readBack: { columns: cols.map(([n]) => n), expect: [{ key: 'r1', values: Object.fromEntries(cols.map(([n]) => n).filter(n => Object.hasOwn(spelled, n)).map(n => [n, spelled[n]])) }] } })), () => {});
  assert.equal(loose.verdict.verdict, 'pass', JSON.stringify(loose.verdict.checks));
});

test('read-back: a refused type, a missing or virtual column, or an unreadable value or expectation is inconclusive, and the window is unchanged', async t => {
  const shapes = [
    ['enum', { type: '90002', typtype: 'e' }, 'gold', 'type-refused'], ['array', { type: '1009' }, '{a,b}', 'type-refused'], ['interval', { type: '1186' }, '1 day', 'type-refused'],
    ['bytea', { type: '17' }, '\\x00', 'type-refused'], ['domain over a domain', { type: '90003', typtype: 'd', basetype: '90001' }, '1', 'type-refused'], ['composite', { type: '90004', typtype: 'c' }, '(1,2)', 'type-refused'],
    ['virtual generated', { type: '1700', generated: 'v' }, '1', 'column-virtual'],
  ];
  for (const [label, column, text, reason] of shapes) {
    const model = pgModel([{ table: 'orders', key: 'id', columns: [{ name: 'v', ...column }], rows: [{ id: 'A100', v: text }] }]);
    const { out, record, verdict } = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: { columns: ['v'], expect: [{ key: 'A100', values: { v: '1' } }] } }], () => model.write('orders', 'A100', { v: text }));
    assert.equal(record.tables[0].status, reason, label);
    assert.deepEqual([verdict.verdict, verdict.reasons], ['inconclusive', [reason]], label);
    assert.deepEqual([out.coverage, out.events.length], ['net-only', 1], `${label}: the window is decided as without read-back`);
  }
  // A remainder column whose name holds a control character is refused, never placed in the statement.
  const hostile = pgModel([{ table: 'orders', key: 'id', columns: [{ name: 'v', type: '1700' }, { name: 'x\u0001', type: '25' }], rows: [{ id: 'A100', v: '1' }] }]);
  const named = await readBack(t, hostile, [{ table: 'orders', key: 'id', readBack: { columns: ['v'], expect: [{ key: 'A100', values: { v: '1' } }] } }], () => {});
  assert.deepEqual([named.record.tables[0].status, named.verdict.verdict, named.out.coverage], ['column-name-refused', 'inconclusive', 'net-only']);
  // A declared column retyped between the marks: the window cannot follow the table, so nothing is decided.
  const retyped = pgModel([ORDERS()]);
  const moved = await readBack(t, retyped, [{ table: 'orders', key: 'id', readBack: REFUND }], () => {}, { override: m => (m === 1 ? { attributes: { ...retyped.state().attributes, 16384: retyped.state().attributes[16384].map(a => (a[1] === 'refund_amount' ? [a[0], a[1], '701', a[3], a[4]] : a)) } } : {}) });
  assert.deepEqual([moved.record.status, moved.verdict.verdict], ['columns-changed', 'inconclusive']);
  // An expected row's declared column that no expectation names, unreadable at a mark: no pass rests on it.
  const unread = pgModel([{ table: 'orders', key: 'id', columns: [{ name: 'v', type: '1700' }, { name: 'w', type: '1700' }], rows: [{ id: 'A100', v: '1', w: 'NaN' }] }]);
  const blind = await readBack(t, unread, [{ table: 'orders', key: 'id', readBack: { columns: ['v', 'w'], expect: [{ key: 'A100', values: { v: '1' } }] } }], () => {});
  assert.deepEqual([blind.verdict.verdict, blind.verdict.reasons], ['inconclusive', ['remainder-unreadable']]);
  const missing = pgModel([ORDERS()]);
  const absent = await readBack(t, missing, [{ table: 'orders', key: 'id', readBack: { columns: ['refund'], expect: [{ key: 'A100', values: { refund: '40' } }] } }], () => {});
  assert.deepEqual([absent.record.tables[0].status, absent.verdict.verdict], ['column-missing', 'inconclusive']);
  // Values that are not canonical, and expectations that cannot be read as the column's kind.
  const values = [['numeric', '1700', 'NaN', '40', 'value-not-decimal'], ['timestamp', '1114', 'infinity', '2026-10-18T00:00:00', 'value-not-canonical'], ['date', '1082', '2020-01-01 BC', '2020-01-01', 'value-not-canonical'],
    ['json too deep', '3802', `${'['.repeat(40)}${']'.repeat(40)}`, '[]', 'value-not-canonical'], ['json expectation as a JavaScript value', '3802', '{"n": 1}', { n: 1 }, 'expectation-not-canonical'],
    ['uuid expectation in braces', '2950', '6f1c2a3e-0000-4000-8000-00000000abcd', '{6f1c2a3e-0000-4000-8000-00000000abcd}', 'expectation-not-canonical'], ['text', '25', 'bad \uFFFD byte', 'x', 'value-not-canonical'], ['long text', '25', 'x'.repeat(5000), 'x', 'value-too-long'],
    ['timestamptz expectation off UTC', '1184', '2026-10-18 06:00:00+00', '2026-10-18T08:00:00+02:00', 'expectation-not-canonical'], ['numeric expectation', '1700', '40', 'forty', 'expectation-not-canonical'],
    ['boolean expectation', '16', 'true', 'true', 'expectation-not-canonical']];
  for (const [label, type, text, expected, reason] of values) {
    const model = pgModel([{ table: 'orders', key: 'id', columns: [{ name: 'v', type }], rows: [{ id: 'A100', v: text }] }]);
    const { record, verdict } = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: { columns: ['v'], expect: [{ key: 'A100', values: { v: expected } }] } }], () => {});
    assert.equal(record.tables[0].status, 'ok', label);
    assert.deepEqual([verdict.verdict, verdict.reasons], ['inconclusive', [reason]], label);
  }
});

test('read-back: exact insert and delete counts in a key range; a replay that inserts twice, or a delete that removes more, fails', async t => {
  const refunds = () => ({ table: 'refunds', key: 'id', keyType: '23', columns: [{ name: 'amount', type: '1700' }], rows: [{ id: '7', amount: '10.00' }] });
  const insertOnce = { columns: ['amount'], range: { min: '100' }, inserts: 1 };
  for (const [label, act, verdict, observed] of [['once', m => m.write('refunds', '100', { amount: '40.00' }), 'pass', 1],
    ['replayed', m => { m.write('refunds', '100', { amount: '40.00' }); m.write('refunds', '101', { amount: '40.00' }); }, 'fail', 2], ['never', () => {}, 'fail', 0]]) {
    const model = pgModel([refunds()]);
    const r = await readBack(t, model, [{ table: 'refunds', key: 'id', readBack: insertOnce }], () => act(model));
    assert.equal(r.verdict.verdict, verdict, label);
    assert.equal(check(r.verdict, { check: 'inserts' }).observed, observed, label);
    if (verdict === 'fail') assert.deepEqual(r.verdict.reasons, ['inserts-mismatch'], label);
    // The inserted rows are recorded with their values.
    if (label === 'replayed') assert.deepEqual(r.record.tables[0].rows.map(x => [x.key, x.before, x.after]), [['100', null, { amount: '40' }], ['101', null, { amount: '40' }]]);
  }
  const carts = () => ({ table: 'carts', key: 'id', columns: [{ name: 'owner', type: '25' }], rows: ['cart-1', 'cart-2', 'keep-9'].map(id => ({ id, owner: 'u1' })) });
  const deleteOne = { columns: ['owner'], range: { prefix: 'cart-' }, deletes: 1 };
  for (const [label, keys, verdict, reasons] of [['one', ['cart-1'], 'pass', []], ['two', ['cart-1', 'cart-2'], 'fail', ['deletes-mismatch']],
    ['one plus one outside the range', ['cart-1', 'keep-9'], 'inconclusive', ['remainder-changed']]]) {
    const model = pgModel([carts()]);
    const r = await readBack(t, model, [{ table: 'carts', key: 'id', readBack: deleteOne }], () => keys.forEach(k => model.remove('carts', k)));
    assert.deepEqual([r.verdict.verdict, r.verdict.reasons], [verdict, reasons], label);
  }
  // Only keys in the range are counted; one outside it stays in the remainder.
  const both = pgModel([refunds()]);
  const outside = await readBack(t, both, [{ table: 'refunds', key: 'id', readBack: insertOnce }], () => { both.write('refunds', '100', { amount: '40.00' }); both.write('refunds', '8', { amount: '1.00' }); });
  assert.deepEqual([outside.verdict.verdict, outside.verdict.reasons, check(outside.verdict, { check: 'inserts' }).observed], ['inconclusive', ['remainder-changed'], 1]);
  // An integer range that meets a changed key it cannot place decides no count.
  const model = pgModel([refunds()]);
  const odd = await readBack(t, model, [{ table: 'refunds', key: 'id', readBack: insertOnce }], () => model.write('refunds', 'x1', { amount: '1' }));
  assert.deepEqual([odd.verdict.verdict, odd.verdict.reasons], ['inconclusive', ['range-key-not-integer', 'remainder-changed']]);
  // An insert no count declares stays in the remainder.
  const undeclared = pgModel([ORDERS()]);
  const extra = await readBack(t, undeclared, [{ table: 'orders', key: 'id', readBack: REFUND }], () => { undeclared.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }); undeclared.write('orders', 'A999', { status: 'paid' }); });
  assert.deepEqual([extra.verdict.verdict, extra.verdict.reasons], ['inconclusive', ['remainder-changed']]);
});

test('read-back: anything outside the declared values that moves leaves a pass inconclusive (remainder "unchanged"); a fail stands', async t => {
  const refund = m => m.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' });
  const cases = [
    ['another row', m => { refund(m); m.write('orders', 'A101', { note: 'changed' }); }, REFUND, ['inconclusive', ['remainder-changed']]],
    ['an undeclared column of the expected row', m => m.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded', note: 'changed' }), REFUND, ['inconclusive', ['remainder-changed']]],
    ['a declared column no expectation names', m => m.write('orders', 'A100', { refund_amount: '40.00', status: 'void' }), { columns: ['refund_amount', 'status'], expect: [{ key: 'A100', values: { refund_amount: '40' } }] }, ['inconclusive', ['remainder-changed']]],
    ['another row, remainder may change', m => { refund(m); m.write('orders', 'A101', { note: 'changed' }); }, { ...REFUND, remainder: 'may-change' }, ['pass', []]],
    ['a wrong value beside another row', m => { m.write('orders', 'A100', { refund_amount: '4.00', status: 'refunded' }); m.write('orders', 'A101', { note: 'changed' }); }, REFUND, ['fail', ['change-mismatch', 'remainder-changed']]],
    ['nothing else', refund, REFUND, ['pass', []]],
  ];
  for (const [label, act, decl, expected] of cases) {
    const model = pgModel([ORDERS()]);
    const { verdict } = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: decl }], () => act(model));
    assert.deepEqual([verdict.verdict, verdict.reasons], expected, label);
  }
  // Each pass of the table reads inconclusive with the reason, beside the table's own remainder check.
  const model = pgModel([ORDERS()]);
  const demoted = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: REFUND }], () => { refund(model); model.write('orders', 'A101', { note: 'changed' }); });
  assert.deepEqual(demoted.verdict.checks.map(c => [c.check, c.column ?? null, c.status, c.reason]),
    [['change', 'refund_amount', 'inconclusive', 'remainder-changed'], ['change', 'status', 'inconclusive', 'remainder-changed'], ['remainder', null, 'inconclusive', 'remainder-changed']]);
});

test('read-back: a precondition that does not hold is inconclusive; an expected row absent at the end mark fails', async t => {
  const model = pgModel([ORDERS()]);
  const wrongStart = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: { columns: ['status'], expect: [{ key: 'A100', change: { status: { from: 'open', to: 'refunded' } } }] } }], () => model.write('orders', 'A100', { status: 'refunded' }));
  assert.deepEqual([wrongStart.verdict.verdict, wrongStart.verdict.reasons], ['inconclusive', ['precondition-not-held']]);
  const model2 = pgModel([ORDERS()]);
  const noRow = await readBack(t, model2, [{ table: 'orders', key: 'id', readBack: { columns: ['status'], inserts: 1, expect: [{ key: 'A200', change: { status: { from: 'paid', to: 'refunded' } } }] } }], () => model2.write('orders', 'A200', { status: 'refunded' }));
  assert.equal(check(noRow.verdict, { key: 'A200' }).reason, 'precondition-row-absent');
  const model3 = pgModel([ORDERS()]);
  const gone = await readBack(t, model3, [{ table: 'orders', key: 'id', readBack: { columns: ['status'], deletes: 1, expect: [{ key: 'A100', values: { status: 'refunded' } }] } }], () => model3.remove('orders', 'A100'));
  assert.deepEqual([gone.verdict.verdict, gone.verdict.reasons, check(gone.verdict, { check: 'deletes' }).status], ['fail', ['row-absent'], 'pass']);
  // An inserted row decided by a declared count: its value is read back like any other.
  const model4 = pgModel([ORDERS()]);
  const born = await readBack(t, model4, [{ table: 'orders', key: 'id', readBack: { columns: ['status'], inserts: 1, expect: [{ key: 'A200', values: { status: 'paid' } }] } }], () => model4.write('orders', 'A200', { status: 'paid' }));
  assert.equal(born.verdict.verdict, 'pass');
});

test('read-back: a window the observer cannot follow decides nothing (in-flight writer, failed mark, duplicate key, violated table)', async t => {
  const refund = m => m.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' });
  const run = async (label, override) => {
    const model = pgModel([ORDERS()]);
    const r = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: REFUND }], () => refund(model), { override: m => (m === 1 ? override(model) : {}) });
    assert.equal(r.verdict.verdict, 'inconclusive', label);
    assert.ok(r.verdict.checks.every(c => c.status === 'inconclusive'), label);
    return r;
  };
  // The end mark's snapshot lists a transaction in progress (xip).
  const inflight = await run('in flight', model => { const next = Number(model.state().snapshot.split(':')[0]); return { snapshot: `${next}:${next + 1}:${next}` }; });
  assert.equal(inflight.record.status, 'transaction-in-flight-at-window-end');
  const denied = await run('denied', () => ({ tables: { orders: 'denied' } }));
  assert.equal(denied.record.status, 'permission-denied');
  const duplicate = await run('duplicate key', model => ({ tables: { orders: statement => { const rows = model.state().tables.orders(statement); return [...rows, rows[0]]; } } }));
  assert.equal(duplicate.record.status, 'duplicate-key');
  // Content changed under an unchanged row version (no write): the table is violated, and its read-back unusable.
  const violated = await run('violated', model => { const st = model.state(); return { tables: { orders: statement => st.tables.orders(statement).map(r => (r[0] === 'A101' ? [r[0], r[1], 'f'.repeat(32), ...r.slice(3)] : r)) } }; });
  assert.equal(violated.record.tables[0].status, 'table-violated');
  // A scan row without its declared values and remainder fails the mark itself.
  const short = await run('short row', model => { const st = model.state(); return { tables: { orders: statement => st.tables.orders(statement).map(r => r.slice(0, 4)) } }; });
  assert.deepEqual([short.out.coverage, short.record.status], ['failed', 'read-failed']);
});

test('read-back: a secret or personal column must be declared sensitive; its values are kept sealed unless revealed', async t => {
  const cards = () => ({ table: 'payments', key: 'id', columns: [{ name: 'card_last4', type: '25' }, { name: 'amount', type: '1700' }], rows: [{ id: 'p1', card_last4: '4242', amount: '40.00' }] });
  assert.throws(() => observerOn(5432, [{ table: 'payments', key: 'id', readBack: { columns: ['card_last4'] } }]), e => e instanceof ReadBackError && e.code === 'sensitive-undeclared');
  const sealed = { columns: ['card_last4', 'amount'], sensitive: ['card_last4'], expect: [{ key: 'p1', values: { card_last4: '4242', amount: '40' } }] };
  const model = pgModel([cards()]);
  const kept = await readBack(t, model, [{ table: 'payments', key: 'id', readBack: sealed }], () => {});
  assert.equal(kept.verdict.verdict, 'pass');
  const after = kept.record.tables[0].rows[0].after;
  assert.match(after.card_last4.sealed, /^[a-f0-9]{64}$/);
  assert.equal(after.amount, '40');
  // Outside the sealed digests themselves, whose random hex can hold '4242' by chance.
  assert.ok(!JSON.stringify(kept.record).replace(/[a-f0-9]{64}/g, '').includes('4242'), 'the value appears nowhere in the record, the expectation included');
  const model2 = pgModel([cards()]);
  const wrong = await readBack(t, model2, [{ table: 'payments', key: 'id', readBack: { ...sealed, expect: [{ key: 'p1', values: { card_last4: '1111' } }] } }], () => {});
  assert.deepEqual([wrong.verdict.verdict, wrong.verdict.reasons], ['fail', ['value-mismatch']]);
  // Each observer seals under its own salt; revealing keeps the value in clear.
  const model3 = pgModel([cards()]);
  const other = await readBack(t, model3, [{ table: 'payments', key: 'id', readBack: sealed }], () => {});
  assert.notEqual(other.record.tables[0].rows[0].after.card_last4.sealed, after.card_last4.sealed);
  assert.notEqual(other.record.tables[0].remainder.before, kept.record.tables[0].remainder.before, 'the remainder is sealed too');
  const model4 = pgModel([cards()]);
  const shown = await readBack(t, model4, [{ table: 'payments', key: 'id', readBack: { ...sealed, reveal: ['card_last4'] } }], () => {});
  assert.equal(shown.record.tables[0].rows[0].after.card_last4, '4242');
});

test('read-back: a stored record judges the same again, and a refused declaration never builds an observer', async t => {
  const model = pgModel([ORDERS()]), app = await refundApp(t, model, { defective: true });
  const { record, verdict } = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: REFUND }], () => app.refund('A100', '40.00'));
  assert.deepEqual(judgeReadBack(JSON.parse(JSON.stringify(record))), verdict);
  for (const [readBack, code] of [[{ columns: ['id'] }, 'column-is-key'], [{ columns: ['status'], expect: [{ key: 'A100', values: { note: 'x' } }] }, 'column-undeclared'], [{ columns: [] }, 'nothing-declared'], [{ columns: ['status'], extra: 1 }, 'readback-shape']])
    assert.throws(() => observerOn(5432, [{ table: 'orders', key: 'id', readBack }]), e => e instanceof ReadBackError && e.code === code, code);
});

test('read-back in a profile: a table declares it, and the profile loader refuses a declaration the observer would refuse (src/http-readback.mjs)', () => {
  const profile = { id: 'shop', name: 'Shop', applicationId: 'shop-app', origin: 'http://127.0.0.1:4000', buildLabel: 'b1', contextId: 'synthetic-shop',
    actors: { bob: { principalId: 'bob', credentialEnv: 'SCOPEHAVEN_TARGET_BOB', identityValue: 'bob' } }, requiredControlIds: ['WHOAMI'],
    observers: [{ id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables: [{ table: 'orders', key: 'id', readBack: REFUND }], settleMs: 250 }],
    checks: [{ id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'bob', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] };
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [profile] }));
  profile.observers[0].tables[0].readBack = { columns: ['id'] };
  assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [profile] }), /invalid readBack on orders \(column-is-key\)/);
  delete profile.observers[0].tables[0].readBack;
  assert.doesNotThrow(() => validateTargetFile({ schemaVersion: 1, targets: [profile] }));
});

test('read-back review: a table with no check of its own still guards its remainder, and an unusable one still blocks the pass', async t => {
  const payments = () => ({ table: 'payments', key: 'id', columns: [{ name: 'amount', type: '1700' }], rows: [{ id: 'p1', amount: '40.00' }] });
  const model = pgModel([ORDERS(), payments()]);
  const tables = [{ table: 'orders', key: 'id', readBack: REFUND }, { table: 'payments', key: 'id', readBack: { columns: ['amount'] } }];
  const moved = await readBack(t, model, tables, () => { model.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }); model.write('payments', 'p1', { amount: '0.00' }); model.write('payments', 'p2', { amount: '1.00' }); });
  assert.deepEqual([moved.verdict.verdict, moved.verdict.reasons], ['inconclusive', ['remainder-changed']]);
  assert.deepEqual(check(moved.verdict, { table: 'payments' }), { table: 'payments', check: 'remainder', status: 'inconclusive', reason: 'remainder-changed' });
  const still = pgModel([ORDERS(), payments()]);
  const quiet = await readBack(t, still, tables, () => still.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }));
  assert.equal(quiet.verdict.verdict, 'pass');
  // A table whose read-back is unusable and that declares no expectation still contributes an inconclusive check.
  const odd = pgModel([ORDERS(), { table: 'payments', key: 'id', columns: [{ name: 'amount', type: '1186' }], rows: [{ id: 'p1', amount: '1 day' }] }]);
  const refused = await readBack(t, odd, [{ table: 'orders', key: 'id', readBack: REFUND }, { table: 'payments', key: 'id', readBack: { columns: ['amount'], remainder: 'may-change' } }], () => odd.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }));
  assert.deepEqual([refused.verdict.verdict, check(refused.verdict, { table: 'payments' })], ['inconclusive', { table: 'payments', check: 'table', status: 'inconclusive', reason: 'type-refused' }]);
});

test('read-back review: an inheritance child holding a column its parent lacks leaves read-back unusable, and the window as it was', async t => {
  const model = pgModel([ORDERS()]);
  const child = () => { const st = model.state(); return { descendants: { orders: [['16390', 'r', 'heap']] }, attributes: { ...st.attributes, 16390: [...st.attributes[16384], ['5', 'child_note', '25', 'false']] } }; };
  const r = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: REFUND }], () => model.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }), { override: child });
  assert.deepEqual([r.record.tables[0].status, r.verdict.verdict, r.out.coverage, r.out.events.length], ['descendant-columns', 'inconclusive', 'net-only', 1]);
  // A child with the parent's columns only is read as before.
  const same = pgModel([ORDERS()]);
  const plainChild = () => { const st = same.state(); return { descendants: { orders: [['16390', 'r', 'heap']] }, attributes: { ...st.attributes, 16390: st.attributes[16384] } }; };
  const ok = await readBack(t, same, [{ table: 'orders', key: 'id', readBack: REFUND }], () => same.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }), { override: plainChild });
  assert.equal(ok.verdict.verdict, 'pass');
});

test('read-back review: a mark keeps the other rows\' values only within a small budget; the expected rows are always kept', async t => {
  const big = { table: 'orders', key: 'id', columns: [{ name: 'refund_amount', type: '1700' }, { name: 'status', type: '25' }, { name: 'note', type: '25' }],
    rows: [{ id: 'A100', refund_amount: null, status: 'paid', note: 'n' }, ...Array.from({ length: 40 }, (_, i) => ({ id: `B${String(i).padStart(3, '0')}`, refund_amount: null, status: 'x'.repeat(2000), note: 'n' }))] };
  const model = pgModel([big]);
  const r = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: { ...REFUND, deletes: 1 } }], () => { model.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }); model.remove('orders', 'B001'); });
  assert.equal(r.verdict.verdict, 'pass');
  assert.equal(r.record.tables[0].rowValues, 'over-budget');
  assert.deepEqual(r.record.tables[0].rows.map(x => [x.key, x.before, x.after]), [['A100', { refund_amount: null, status: 'paid' }, { refund_amount: '40', status: 'refunded' }], ['B001', null, null]]);
  const small = pgModel([ORDERS()]);
  const kept = await readBack(t, small, [{ table: 'orders', key: 'id', readBack: { ...REFUND, deletes: 1 } }], () => { small.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }); small.remove('orders', 'A101'); });
  assert.deepEqual([kept.record.tables[0].rowValues, kept.record.tables[0].rows[1]], ['kept', { key: 'A101', before: { refund_amount: null, status: 'paid' }, after: null }]);
});

test('read-back: a 64-bit id in a jsonb column is compared digit for digit; the twin that rounds it through a double fails, its fixed twin passes', async t => {
  const orders = () => ({ table: 'orders', key: 'id', columns: [{ name: 'meta', type: '3802' }], rows: [{ id: 'A100', meta: null }] });
  const body = '{"order_id": 1234567890123456789}';
  const results = {};
  for (const defective of [true, false]) {
    const model = pgModel([orders()]), app = await refundApp(t, model, { defective });
    const { out, record, verdict } = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: { columns: ['meta'], expect: [{ key: 'A100', change: { meta: { from: null, to: body } } }] } }], () => app.meta('A100', body));
    assert.deepEqual([out.coverage, out.events.map(e => [e.operation, e.resource])], ['net-only', [['update', 'orders/A100']]]);
    results[defective ? 'defective' : 'fixed'] = { verdict, after: record.tables[0].rows[0].after.meta };
  }
  assert.equal(results.defective.after, '{"order_id":1234567890123456800}');
  assert.deepEqual([results.defective.verdict.verdict, results.defective.verdict.reasons], ['fail', ['change-mismatch']]);
  assert.equal(results.fixed.after, '{"order_id":1234567890123456789}');
  assert.deepEqual([results.fixed.verdict.verdict, results.fixed.verdict.reasons], ['pass', []]);
  // The same expectation as a JavaScript value has already been rounded by a double, so it equals the rounded store: it
  // reads inconclusive against either twin, never pass.
  for (const defective of [true, false]) {
    const model = pgModel([orders()]), app = await refundApp(t, model, { defective });
    const { verdict } = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: { columns: ['meta'], expect: [{ key: 'A100', values: { meta: JSON.parse(body) } }] } }], () => app.meta('A100', body));
    assert.deepEqual([verdict.verdict, verdict.reasons], ['inconclusive', ['expectation-not-canonical']], defective ? 'defective' : 'fixed');
  }
  // 2^53 + 1 stored as 2^53, the review's second shape.
  const model = pgModel([orders()]);
  const near = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: { columns: ['meta'], expect: [{ key: 'A100', values: { meta: '{"n": 9007199254740993}' } }] } }], () => model.write('orders', 'A100', { meta: '{"n": 9007199254740992}' }));
  assert.deepEqual([near.verdict.verdict, near.verdict.reasons], ['fail', ['value-mismatch']]);
});

test('read-back review m1: the JSON value null is expected as the JSON text "null"; an expected null is SQL NULL, and the two never match', async t => {
  const docs = () => ({ table: 'docs', key: 'id', columns: [{ name: 'body', type: '114' }], rows: [{ id: 'j', body: 'null' }, { id: 's', body: null }] });
  for (const [key, expected, verdict] of [['j', 'null', 'pass'], ['j', null, 'fail'], ['s', null, 'pass'], ['s', 'null', 'fail']]) {
    const model = pgModel([docs()]);
    const r = await readBack(t, model, [{ table: 'docs', key: 'id', readBack: { columns: ['body'], expect: [{ key, values: { body: expected } }] } }], () => {});
    assert.equal(r.verdict.verdict, verdict, `${key} ${JSON.stringify(expected)}`);
  }
});

test('read-back review m4: an exact-key range names the row a count is about, so deleting the wrong cart fails', async t => {
  const carts = () => ({ table: 'carts', key: 'id', columns: [{ name: 'owner', type: '25' }], rows: ['A100', 'A101'].map(id => ({ id, owner: 'u1' })) });
  for (const [label, removed, expected] of [['the named cart', 'A100', ['pass', []]], ['the wrong cart', 'A101', ['fail', ['deletes-mismatch', 'remainder-changed']]]]) {
    const model = pgModel([carts()]);
    const r = await readBack(t, model, [{ table: 'carts', key: 'id', readBack: { columns: ['owner'], range: { keys: ['A100'] }, deletes: 1 } }], () => model.remove('carts', removed));
    assert.deepEqual([r.verdict.verdict, r.verdict.reasons], expected, label);
    assert.deepEqual(r.record.tables[0].range, { keys: ['A100'] }, label);
  }
});

test('read-back review m5: an exact key is compared as the key column reads it, so a forbidden delete of an upper-case uuid fails; a key its kind cannot read never passes', async t => {
  const uuid = '6f1c2a3e-0000-4000-8000-00000000a100', other = '6f1c2a3e-0000-4000-8000-00000000a101';
  // PostgreSQL prints each key; the model holds that text. Output functions the fixture does not list are given here.
  const types = { types: { 1042: ['pg_catalog.bpcharout', 'i'], 701: ['pg_catalog.float8out', 'i'] } };
  const carts = (keyType, ids) => ({ table: 'carts', key: 'id', keyType, columns: [{ name: 'owner', type: '25' }], rows: ids.map(id => ({ id, owner: 'u1' })) });
  const keep = keys => ({ columns: ['owner'], remainder: 'may-change', range: { keys }, deletes: 0 });
  const run = async (table, decl, removed) => {
    const model = pgModel([table]);
    const r = await readBack(t, model, [{ table: 'carts', key: 'id', readBack: decl }], () => removed && model.remove('carts', removed), { override: () => types });
    return [r.verdict.verdict, r.verdict.reasons];
  };
  // The review's scenario: "this cart must not be deleted", the key written in upper case. The defective twin deletes it
  // and FAILS (it read PASS before the fix); the fixed twin deletes only the other cart and PASSES.
  assert.deepEqual(await run(carts('2950', [uuid, other]), keep([uuid.toUpperCase()]), uuid), ['fail', ['deletes-mismatch']], 'defective twin');
  assert.deepEqual(await run(carts('2950', [uuid, other]), keep([uuid.toUpperCase()]), other), ['pass', []], 'fixed twin');
  assert.deepEqual(await run(carts('2950', [uuid, other]), { ...keep([uuid.toUpperCase()]), deletes: 1 }, uuid), ['pass', []], 'the upper-case key names the row');
  // Each other kind the form accepts: a char key with trailing spaces, a numeric key as its decimal, a timestamp in ISO 8601.
  assert.deepEqual(await run(carts('1042', ['A1', 'B2']), keep(['A1  ']), 'A1'), ['fail', ['deletes-mismatch']], 'char');
  assert.deepEqual(await run(carts('1700', ['1.50', '2.00']), keep(['1.5']), '1.50'), ['fail', ['deletes-mismatch']], 'numeric');
  assert.deepEqual(await run(carts('1114', ['2026-10-18 06:07:35', '2026-10-18 06:07:36']), keep(['2026-10-18T06:07:35']), '2026-10-18 06:07:35'), ['fail', ['deletes-mismatch']], 'timestamp');
  // An integer key with a leading zero, a uuid key that is no uuid, and a float key column are refused: inconclusive
  // whether or not the row is deleted, never a pass. A canonical integer key decides as before.
  for (const [label, table, keys, removed, reason] of [['leading zero', carts('23', ['42', '43']), ['042'], '42', 'range-key-not-canonical'], ['not a uuid', carts('2950', [uuid, other]), ['A100'], uuid, 'range-key-not-canonical'],
    ['float key', carts('701', ['0.1', '0.2']), ['0.1'], '0.1', 'range-key-type-refused']])
    for (const deleted of [removed, null]) assert.deepEqual(await run(table, keep(keys), deleted), ['inconclusive', [reason]], `${label} ${deleted ? 'deleted' : 'kept'}`);
  assert.deepEqual(await run(carts('23', ['42', '43']), keep(['42']), '42'), ['fail', ['deletes-mismatch']], 'integer');
  // Text keys are compared exactly: a text key that is not the stored one names another row.
  assert.deepEqual(await run(carts('25', ['a100', 'a101']), keep(['a100']), 'a100'), ['fail', ['deletes-mismatch']], 'text');
});

test('read-back review m3: a scan too large to finish within the statement timeout fails the mark and the window, and read-back decides nothing', async t => {
  const model = pgModel([ORDERS()]);
  const r = await readBack(t, model, [{ table: 'orders', key: 'id', readBack: REFUND }], () => model.write('orders', 'A100', { refund_amount: '40.00', status: 'refunded' }),
    { override: m => (m === 1 ? { tables: { orders: () => ({ error: '57014' }) } } : {}) });
  assert.deepEqual([r.out.coverage, r.out.reason, r.record.status, r.verdict.verdict], ['failed', 'statement-timeout', 'statement-timeout', 'inconclusive']);
  assert.ok(r.verdict.checks.every(c => c.status === 'inconclusive' && c.reason === 'statement-timeout'));
});
