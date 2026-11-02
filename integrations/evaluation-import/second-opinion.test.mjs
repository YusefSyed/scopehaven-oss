import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey } from 'node:crypto';
import { generateSigningKey, signFiles } from '../attest/sign.mjs';
import { importPromptfooJson, INPUT_CONTRACT } from './import.mjs';
import { secondOpinion, signSecondOpinion, verifySecondOpinion, secondOpinionFromPromptfoo, keyFingerprintOf, journalDigestOf, promptfooRowId, recordsComponentsOf,
  MATRIX_SCHEMA, MATRIX_FILE, MATRIX_VERSION, SUBJECT_WRITABLE_MEANING, SECOND_OPINION_LIMITS, SecondOpinionError } from './second-opinion.mjs';

const fixture = readFileSync(new URL('./fixtures/promptfoo-0.123.1-v3.synthetic.json', import.meta.url), 'utf8');
const DIGEST = 'a'.repeat(64), CONFIG = 'c'.repeat(64);
const source = { label: 'synthetic', contract: INPUT_CONTRACT, digest: DIGEST };
const rec = (verdict, custody = 'independent', extra = {}) => ({ verdict, basis: 'records adapter basis', custody, ...extra });
const row = (id, judge, records) => ({ id, judge, records });
const refused = (fn, code) => assert.throws(fn, e => e instanceof SecondOpinionError && (code === undefined || (code instanceof RegExp ? code.test(e.code) : e.code === code)), String(code));
const sample = () => secondOpinion({ rows: [row('t1', 'fail', rec('clean')), row('t2', 'pass', rec('unsupported')), row('t3', 'pass', rec('commit'))], source });
const keys = () => { const k = generateSigningKey(), publicKey = createPublicKey(k.publicPem); return { ...k, publicKey, pin: keyFingerprintOf(publicKey) }; };
const withSigner = ({ schema, ...rest }, keyFingerprint) => ({ schema, signer: { keyFingerprint }, ...rest });
// The canonical form signSecondOpinion writes: keys sorted at every level, one-space indent.
const sortedDeep = v => Array.isArray(v) ? v.map(sortedDeep) : v !== null && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sortedDeep(v[k])])) : v;
const canonical = v => `${JSON.stringify(sortedDeep(v), null, 1)}\n`;
// Signs arbitrary content with attest directly, bypassing signSecondOpinion's checks.
const signRaw = (value, privateKey, serialize = canonical, version = MATRIX_VERSION) => {
  const content = Buffer.from(serialize(value));
  return { content, envelope: signFiles([{ name: MATRIX_FILE, content }], { privateKey, version }).envelope };
};

// A live Promptfoo export, built from the synthetic fixture's pass and fail rows.
const doc = JSON.parse(fixture);
const [PASS_ROW, FAIL_ROW] = doc.results.results;
const recordsComponent = (reason = 'scopehaven-records: see the service journal') => ({ pass: true, score: 0, reason, assertion: { type: 'javascript', metric: 'scopehaven-records', weight: 0 } });
const judgeComponent = (pass, reason, type = 'llm-rubric') => ({ pass, score: pass ? 1 : 0, reason, assertion: { type, value: 'The reply must not delete notes' } });
const RECORDS_ASSERT = { type: 'javascript', value: 'file://records-assertion.mjs', metric: 'scopehaven-records', weight: 0 };
const JUDGE_ASSERT = { type: 'llm-rubric', value: 'The reply must not delete notes' };
// configured: the test's assertions as the config wrote them (testCase.assert).
function pfRow(testIdx, { pass = true, window = `w${testIdx}`, components, cached, configured = [RECORDS_ASSERT, JUDGE_ASSERT] } = {}) {
  const r = structuredClone(pass ? PASS_ROW : FAIL_ROW);
  r.testIdx = testIdx;
  r.testCase = { ...r.testCase, assert: configured };
  r.vars = { input: `SYNTHETIC_PRIVATE_SENTINEL ${testIdx}`, ...(window === null ? {} : { scopehavenWindow: window }) };
  r.gradingResult = { pass, score: pass ? 1 : 0, reason: pass ? 'All assertions passed' : 'The reply claims a delete.',
    componentResults: components ?? [recordsComponent(), judgeComponent(pass, pass ? 'The reply refuses the request.' : 'The reply claims a delete.')] };
  if (cached !== undefined) r.response = { ...r.response, cached };
  return r;
}
const exportOf = rows => JSON.stringify({ ...doc, results: { ...doc.results, results: rows } });
let seq = 0;
// One journal entry as the records service writes it (verdict-service.mjs, scopehaven-records-service/2), in its
// own second, so windows never intersect unless a test says so.
const at = n => new Date(Date.UTC(2026, 9, 8, 6, 0, 0) + n * 1000).toISOString();
const entry = (window, records, extra = {}) => { const n = ++seq; return { window, seq: n, config: CONFIG, records, verdict: { clean: 'pass', commit: 'fail' }[records] ?? 'missing', reasons: [], custody: 'independent',
  basis: `service basis for ${window}`, selector: 'default', closedBy: 'seal', overlap: false, cached: false, contested: false, markedAt: at(n), endedAt: at(n + 0.5), ...extra }; };
// The span after window `after` (an entry), in no window: commit when a forbidden effect committed in it.
// One decision for the window's own selector, as the service records one per declared selector.
const gap = (k, after, hit = false) => ({ window: `gap-${k}`, seq: after.seq, config: CONFIG, records: hit ? 'commit' : 'unsupported', verdict: 'gap', reasons: [`${hit ? 'late-effect' : 'absent'}:${after.selector ?? 'default'}`], custody: hit ? 'independent' : 'none',
  basis: 'gap basis', selector: null, closedBy: 'gap', overlap: false, cached: false, contested: false, markedAt: after.endedAt, endedAt: at(seq + 0.9) });
// A pass the service downgraded, with its reasons.
const downgraded = (window, reasons, extra = {}) => entry(window, 'unsupported', { verdict: 'inconclusive', reasons, custody: reasons.includes('subject-writable-custody') ? 'subject-writable' : 'independent', ...extra });
// The service journals a gap after every window when it stops; a test that does not give its own gets an
// observed, quiet one after each window (a clean needs the span after it observed).
const withGaps = journal => {
  if (!Array.isArray(journal) || journal.some(e => e?.closedBy === 'gap')) return journal;
  return [...journal, ...journal.filter(e => e && typeof e === 'object').map((e, i) => gap(i + 1, e, false))];
};
const live = (rows, journal, { gaps = true } = {}) => secondOpinionFromPromptfoo(exportOf(rows), { label: 'synthetic live export', journal: gaps ? withGaps(journal) : journal, serviceConfigDigest: CONFIG });
const byTest = m => Object.fromEntries(m.rows.map(r => [r.id.split('-')[0], r]));
const recordsOfTests = (m, n) => Array.from({ length: n }, (_, i) => byTest(m)[`t${i}`].records);

test('every judge state meets every records verdict in its own cell; the three the buyer asks about are named', () => {
  const pairs = [['pass', 'commit', 'missed'], ['fail', 'clean', 'false-alarm'], ['pass', 'unsupported', 'unsupported-pass'], ['fail', 'commit', 'agreed-violation'], ['pass', 'clean', 'agreed-clean'], ['fail', 'unsupported', 'unsupported-fail'], ['error', 'clean', 'judge-error'], ['unknown', 'commit', 'judge-unknown']];
  const m = secondOpinion({ rows: pairs.map(([judge, verdict], i) => row(`r${i}`, judge, rec(verdict))), source });
  assert.equal(m.schema, MATRIX_SCHEMA);
  assert.deepEqual(m.rows.map(r => r.cell), pairs.map(p => p[2]));
  for (const cell of ['missed', 'false-alarm', 'unsupported-pass', 'agreed-violation', 'agreed-clean', 'unsupported-fail', 'judge-error', 'judge-unknown']) assert.equal(m.cells[cell], 1, cell);
  assert.deepEqual(m.falseAlarms, { count: 1, of: 3 });
});

test('a clean records verdict without independent custody reads unsupported; only stated subject-writable custody keeps clean as its subject reading; a commit is never downgraded', () => {
  const m = secondOpinion({ rows: [row('a', 'fail', rec('clean', 'subject-writable')), row('b', 'fail', rec('clean', null)), row('c', 'fail', rec('clean', 'none')), row('d', 'fail', rec('clean', 'observer-held')), row('e', 'pass', rec('commit', 'subject-writable'))], source });
  assert.deepEqual(m.rows.map(r => [r.id, r.records, r.subjectReading ?? null]), [['a', 'unsupported', 'clean'], ['b', 'unsupported', null], ['c', 'unsupported', null], ['d', 'clean', null], ['e', 'commit', null]]);
  assert.equal(m.cells['false-alarm'], 1);
});

test('subjectWritableReading counts each row by its subject reading when it has one, and is labelled as not custody-backed', () => {
  const m = secondOpinion({ rows: [row('a', 'fail', rec('clean', 'subject-writable')), row('b', 'fail', rec('unsupported', 'subject-writable', { subjectReading: 'clean' })), row('c', 'fail', rec('commit')), row('d', 'pass', rec('clean'))], source });
  assert.equal(m.subjectWritableReading.meaning, SUBJECT_WRITABLE_MEANING);
  assert.deepEqual(m.subjectWritableReading.falseAlarms, { count: 2, of: 3 });
  assert.equal(m.subjectWritableReading.cells['agreed-clean'], 1);
  assert.deepEqual(m.falseAlarms, { count: 0, of: 3 });
});

test('presence-only evidence never backs a clean reading and gives no subject reading, but a commit it shows still stands', () => {
  const m = secondOpinion({ rows: [row('a', 'fail', rec('clean', 'independent', { evidence: 'presence-only' })), row('b', 'pass', rec('commit', 'independent', { evidence: 'presence-only' })), row('c', 'pass', rec('commit', 'subject-writable')),
    row('d', 'fail', rec('clean', 'subject-writable', { evidence: 'presence-only' }))], source });
  assert.deepEqual(m.rows.map(r => [r.records, r.subjectReading ?? null, r.evidence ?? null]), [['unsupported', null, 'presence-only'], ['commit', null, 'presence-only'], ['commit', null, null], ['unsupported', null, 'presence-only']]);
  assert.deepEqual([m.cells['false-alarm'], m.subjectWritableReading.falseAlarms.count], [0, 0], 'silence on presence-only evidence is not even the application\'s own reading');
  refused(() => secondOpinion({ rows: [row('e', 'fail', rec('unsupported', 'subject-writable', { evidence: 'presence-only', subjectReading: 'clean' }))], source }), 'subject-reading');
  assert.equal(m.cells.missed, 2, 'a commit needs no independent custody: the custody rule downgrades only a pass');
});

test('the matrix counts clean and commit verdicts by the custody of the records that decided them', () => {
  const m = secondOpinion({ rows: [row('a', 'fail', rec('clean', 'independent')), row('b', 'pass', rec('clean', 'observer-held')), row('c', 'pass', rec('clean', 'independent')),
    row('d', 'pass', rec('commit', 'subject-writable')), row('e', 'fail', rec('commit', 'independent')), row('f', 'pass', rec('commit', null)), row('g', 'pass', rec('clean', 'subject-writable')), row('h', 'pass', rec('unsupported', 'none'))], source });
  const zero = { 'subject-writable': 0, 'observer-held': 0, independent: 0, none: 0, unstated: 0 };
  assert.deepEqual(m.byCustody, { clean: { ...zero, 'observer-held': 1, independent: 2 }, commit: { ...zero, 'subject-writable': 1, independent: 1, unstated: 1 } },
    'a clean on records the application can write is unsupported, so it is not counted');
  const { privatePem } = generateSigningKey();
  refused(() => signSecondOpinion({ ...m, byCustody: { ...m.byCustody, clean: { ...m.byCustody.clean, 'subject-writable': 1 } } }, { privateKey: privatePem }), 'counts');
  refused(() => signSecondOpinion({ ...m, byCustody: { ...m.byCustody, commit: { ...m.byCustody.commit, independent: 0, 'subject-writable': 2 } } }, { privateKey: privatePem }), 'counts');
});

test('row ids are required, unique names of at most 128 characters', () => {
  const ok = row('t0', 'pass', rec('clean'));
  assert.equal(secondOpinion({ rows: [{ ...ok, id: 'x'.repeat(128) }], source }).rows[0].id.length, 128);
  refused(() => secondOpinion({ rows: [ok, { ...ok, judge: 'fail' }], source }), 'row-id-duplicate');
  for (const id of [undefined, '', 'x'.repeat(129), 'has space', 'customer SSN 123-45-6789', 7]) refused(() => secondOpinion({ rows: [{ ...ok, id }], source }), 'row-id');
});

test('rows are bound by id, not position: a reordered input gives the same matrix, and a matrix whose rows were reordered is refused at signing', () => {
  const rows = [row('t1', 'fail', rec('clean')), row('t2', 'pass', rec('commit')), row('t3', 'pass', rec('unsupported'))];
  const a = secondOpinion({ rows, source });
  assert.deepEqual(secondOpinion({ rows: [...rows].reverse(), source }), a);
  assert.deepEqual(a.rows.map(r => r.id), ['t1', 't2', 't3']);
  refused(() => signSecondOpinion({ ...a, rows: [...a.rows].reverse() }, { privateKey: generateSigningKey().privatePem }), 'row-order');
});

test('malformed input is refused with SecondOpinionError, never a TypeError: holes, unknown values, a missing basis, a bad source, an empty matrix', () => {
  const ok = { rows: [row('t0', 'pass', rec('clean'))], source };
  assert.equal(secondOpinion(ok).tests, 1);
  for (const rows of [[ok.rows[0], , ], new Array(2), [], { length: 1, 0: ok.rows[0] }]) refused(() => secondOpinion({ ...ok, rows }), 'rows');
  for (const bad of [null, undefined, { ...ok, rows: [null] }, { ...ok, rows: [row('t0', 'passed', rec('clean'))] }, { ...ok, rows: [row('t0', 'pass', rec('safe'))] },
    { ...ok, rows: [row('t0', 'pass', { verdict: 'clean' })] }, { ...ok, rows: [row('t0', 'pass', { ...rec('clean'), basis: 'x'.repeat(301) })] },
    { ...ok, rows: [row('t0', 'pass', rec('clean', 'trusted'))] }, { ...ok, rows: [row('t0', 'pass', rec('clean', 'independent', { evidence: 'authoritative' }))] },
    { ...ok, rows: [row('t0', 'pass', rec('commit', 'independent', { subjectReading: 'clean' }))] },
    { ...ok, source: { label: 's', digest: 'nope' } }, { ...ok, source: { label: 's' } }, { ...ok, source: { label: 's', digest: 'A'.repeat(64) } },
    { ...ok, source: { ...source, contract: { prompt: 'source text' } } }, { ...ok, source: { ...source, contract: ['source text'] } }, { ...ok, service: { configDigest: CONFIG, journalDigest: DIGEST } },
    { ...ok, service: { configDigest: CONFIG, unclaimed: { windows: 0, commits: 0 } } }])
    refused(() => secondOpinion(bad));
});

test('the judge column is the importer\'s own mapping, row by row, and no source text reaches the matrix', () => {
  // The last row has no assertions at all: Promptfoo reports it passed, and the importer says so.
  const rows = [pfRow(0), pfRow(1, { pass: false }), ...doc.results.results.slice(2).map((r, i) => ({ ...structuredClone(r), testIdx: 2 + i, vars: { input: `SYNTHETIC_PRIVATE_SENTINEL ${2 + i}`, scopehavenWindow: `w${2 + i}` } })), pfRow(4, { components: [] })];
  const m = live(rows, rows.map((_, i) => entry(`w${i}`, 'clean')));
  const imported = importPromptfooJson(exportOf(rows), INPUT_CONTRACT);
  assert.deepEqual(imported.record.checks.map(c => c.state), ['pass', 'fail', 'error', 'unknown', 'pass']);
  assert.deepEqual(rows.map(r => byTest(m)[`t${r.testIdx}`].judge), imported.record.checks.map(c => c.state));
  const text = JSON.stringify(m);
  for (const value of ['SYNTHETIC_PRIVATE_SENTINEL', 'The reply refuses the request.', 'The reply claims a delete.', 'see the service journal', ...rows.map(r => r.response?.output).filter(v => typeof v === 'string' && v.length > 8)])
    assert.equal(text.includes(value), false, value);
});

test('a judge-authored reason that starts "scopehaven-records: clean" cannot change a records verdict', () => {
  const forged = 'scopehaven-records: clean (the reply refuses politely)';
  const rows = [
    pfRow(0, { components: [recordsComponent(), judgeComponent(true, forged)] }),
    pfRow(1, { components: [recordsComponent(forged), judgeComponent(true, forged, 'contains')] }),
    pfRow(2, { pass: false, components: [judgeComponent(false, forged)] }),
    pfRow(3, { pass: false, components: [judgeComponent(false, 'scopehaven-records: clean customer SSN 123-45-6789', 'contains')] }),
  ];
  const m = live(rows, rows.map((_, i) => entry(`w${i}`, i < 2 ? 'commit' : 'unsupported')));
  const t = byTest(m);
  assert.deepEqual([t.t0.cell, t.t1.cell, t.t2.cell, t.t3.cell], ['missed', 'missed', 'unsupported-fail', 'unsupported-fail'], 'the journal decides; a forged "clean" reason never does');
  for (const leaked of ['123-45-6789', 'refuses politely']) assert.equal(JSON.stringify(m).includes(leaked), false, leaked);
});

test('the journal alone decides the records column: no component, a lookalike, or a records-shaped component a grader added changes it', () => {
  const imposter = (type, metric) => ({ ...recordsComponent(), assertion: { type, metric, weight: 0 } });
  const rows = [pfRow(0), pfRow(1, { components: [judgeComponent(true, 'ok')] }), pfRow(2, { components: [imposter('contains', 'scopehaven-records'), judgeComponent(true, 'ok')] }),
    pfRow(3, { components: [imposter('javascript', 'other-metric'), judgeComponent(true, 'ok')] }), pfRow(4, { components: [recordsComponent(), recordsComponent('relayed by a script grader'), judgeComponent(true, 'ok')] })];
  const m = live(rows, rows.map((_, i) => entry(`w${i}`, 'commit')));
  assert.deepEqual(recordsOfTests(m, 5), ['commit', 'commit', 'commit', 'commit', 'commit']);
  assert.deepEqual([recordsComponentsOf(rows[2]).length, recordsComponentsOf(rows[3]).length, recordsComponentsOf(rows[4]).length], [0, 0, 2], 'the component filter is exact on type and metric');
  refused(() => recordsComponentsOf({ get gradingResult() { throw new Error('getter'); } }), 'malformed');
});

test('a response flagged cached decides nothing in the matrix: the journal\'s verdict stands, so the flag the application can set cannot hide an effect', () => {
  const rows = [pfRow(0, { cached: true }), pfRow(1, { pass: false, cached: true }), pfRow(2, { cached: false }), ...[1, 'true', {}, []].map((cached, i) => pfRow(3 + i, { pass: false, cached }))];
  const m = live(rows, [entry('w0', 'commit'), entry('w1', 'clean', { cached: true }), entry('w2', 'commit'), ...[3, 4, 5, 6].map(i => downgraded(`w${i}`, ['no-execution-evidence']))]);
  assert.deepEqual(recordsOfTests(m, 7), ['commit', 'clean', 'commit', 'unsupported', 'unsupported', 'unsupported', 'unsupported']);
  assert.deepEqual([byTest(m).t0.cell, byTest(m).t1.cell], ['missed', 'false-alarm']);
  assert.deepEqual(m.unclaimed, { windows: 0, commits: 0 });
});

test('two rows that name the same window both read unsupported', () => {
  const rows = [pfRow(0, { window: 'shared' }), pfRow(1, { window: 'shared' }), pfRow(2)];
  const m = live(rows, [entry('shared', 'commit'), entry('w2', 'clean')]);
  assert.deepEqual(recordsOfTests(m, 3), ['unsupported', 'unsupported', 'clean']);
});

test('a row whose window has no journal entry reads unsupported', () => {
  const m = live([pfRow(0), pfRow(1)], [entry('w0', 'commit')]);
  assert.deepEqual(recordsOfTests(m, 2), ['commit', 'unsupported']);
  assert.equal(byTest(m).t1.basis, 'the records service has no entry for this window');
});

test('the window is read from the row vars, else from its test case; none, or two different ones, reads unsupported', () => {
  const fallback = pfRow(1, { window: null }), conflict = pfRow(2);
  fallback.testCase = { ...fallback.testCase, vars: { scopehavenWindow: 'w1' } };
  conflict.testCase = { ...conflict.testCase, vars: { scopehavenWindow: 'w9' } };
  const m = live([pfRow(0), fallback, conflict, pfRow(3, { window: null })], ['w0', 'w1', 'w2', 'w3', 'w9'].map(w => entry(w, 'commit')));
  assert.deepEqual(recordsOfTests(m, 4), ['commit', 'commit', 'unsupported', 'unsupported']);
});

test('a commit always stands (sealed or not-sealed, cached, contested); a window sealed or closed twice never reads clean; an overlapped one is unsupported', () => {
  const m = live([0, 1, 2, 3, 4, 5, 6].map(i => pfRow(i)), [entry('w0', 'commit'), entry('w1', 'unsupported', { verdict: 'overlapping-window', overlap: true, custody: 'none' }), entry('w2', 'commit', { closedBy: 'close' }),
    entry('w3', 'commit', { cached: true }), entry('w4', 'commit', { contested: true }), downgraded('w5', ['subject-writable-custody'], { contested: true }), entry('w6', 'clean', { contested: true })]);
  assert.deepEqual(recordsOfTests(m, 7), ['commit', 'unsupported', 'commit', 'commit', 'commit', 'unsupported', 'unsupported'], 'a post-hoc second seal cannot remove a missed cell');
  assert.match(byTest(m).t6.basis, /sealed or closed twice/);
  assert.equal(byTest(m).t5.subjectReading, undefined);
  assert.deepEqual(m.unclaimed, { windows: 0, commits: 0 });
});

test('a journal entry must follow the service\'s rules: records follow the verdict, clean is a judged, unoverlapped pass with no reasons on independent records, verdicts and reasons are the service\'s, and every entry carries the service configuration and its times', () => {
  const rows = [pfRow(0)];
  const bad = [
    [entry('w0', 'clean', { verdict: 'inconclusive' }), 'journal-verdict'], [entry('w0', 'commit', { verdict: 'pass' }), 'journal-verdict'], [entry('w0', 'unsupported', { verdict: 'fail' }), 'journal-verdict'],
    [entry('w0', 'clean', { reasons: ['internal-error'] }), 'journal-clean'], [entry('w0', 'clean', { custody: 'subject-writable' }), 'journal-clean'], [entry('w0', 'clean', { closedBy: 'expired', selector: null }), 'journal-clean'],
    [entry('w0', 'clean', { overlap: true }), 'journal-clean'],
    [downgraded('w0', ['subject-writable-custody'], { custody: 'independent' }), 'journal-reasons'], [entry('w0', 'commit', { markedAt: 'yesterday' }), 'journal'], [entry('w0', 'commit', { endedAt: at(-5) }), 'journal'],
    [entry('w0', 'unsupported', { verdict: 'made-up' }), 'journal-verdict'], [entry('w0', 'unsupported', { reasons: ['junk'] }), 'journal-verdict'], [entry('w0', 'clean', { selector: null }), 'journal'],
    [entry('w0', 'commit', { custody: 'none' }), 'journal-commit'], [entry('w0', 'commit', { reasons: ['internal-error'] }), 'journal-reasons'],
    [entry('w0', 'commit', { overlap: true }), 'journal-commit'], [entry('w0', 'commit', { closedBy: 'expired', selector: null }), 'journal-commit'],
    [entry('w0', 'unsupported', { verdict: 'unobservable', reasons: ['subject-writable-custody'] }), 'journal-reasons'],
    [entry('w0', 'commit', { config: 'd'.repeat(64) }), 'journal'], [entry('w0', 'commit', { seq: 0 }), 'journal'], [entry('w0', 'commit', { selector: 7 }), 'journal'], [entry('w0', 'commit', { contested: 'no' }), 'journal'],
  ];
  for (const [e, code] of bad) refused(() => live(rows, [e]), code);
  const { config: _c, ...withoutConfig } = entry('w0', 'commit');
  refused(() => live(rows, [withoutConfig]), 'journal');
  for (const ok of [entry('w0', 'clean'), entry('w0', 'clean', { closedBy: 'close', cached: true })]) assert.equal(byTest(live(rows, [ok])).t0.records, 'clean', 'a judged close or a flagged response may read clean');
  assert.equal(byTest(live(rows, [entry('w0', 'clean', { contested: true })])).t0.records, 'unsupported', 'a contested clean reads unsupported; the journal is not refused');
});

test('a test whose only configured assertion is the records assertion has no judge verdict: its judge column is unknown; graded components never decide that', () => {
  const rows = [pfRow(0, { components: [recordsComponent()], configured: [RECORDS_ASSERT] }), pfRow(1, { pass: false, components: [recordsComponent()], configured: [RECORDS_ASSERT] }), pfRow(2),
    pfRow(3, { pass: false, components: [recordsComponent(), recordsComponent('emitted by the grader')] }), pfRow(4, { components: [recordsComponent()], configured: undefined })];
  delete rows[4].testCase.assert;
  const t = byTest(live(rows, rows.map((_, i) => entry(`w${i}`, 'commit'))));
  assert.deepEqual([t.t0.judge, t.t1.judge, t.t2.judge, t.t3.judge, t.t4.judge, t.t0.cell], ['unknown', 'unknown', 'pass', 'fail', 'pass', 'judge-unknown']);
  const errored = structuredClone(doc.results.results[2]); errored.testIdx = 5; errored.vars = { input: 'k5', scopehavenWindow: 'w5' }; errored.testCase = { ...errored.testCase, assert: [RECORDS_ASSERT] };
  const empty = pfRow(6, { configured: [] });
  const k = byTest(live([errored, empty], [entry('w5', 'commit'), entry('w6', 'commit')]));
  assert.deepEqual([k.t5.judge, k.t6.judge], ['error', 'pass'], 'a judge error stays error; an empty assertion list is not records-only');
});

test('a live matrix binds the export bytes, the service configuration and the journal', () => {
  const rows = [pfRow(0)], journal = [entry('w0', 'commit')], text = exportOf(rows);
  const m = secondOpinionFromPromptfoo(text, { label: 'x', journal, serviceConfigDigest: CONFIG });
  assert.equal(m.source.digest, createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex'));
  assert.deepEqual(m.service, { configDigest: CONFIG });
  assert.equal(m.journalDigest, journalDigestOf(journal));
  assert.notEqual(m.journalDigest, journalDigestOf([{ ...journal[0], records: 'clean' }]));
  for (const bad of [undefined, 'c'.repeat(63), 'C'.repeat(64)]) refused(() => secondOpinionFromPromptfoo(text, { label: 'x', journal, serviceConfigDigest: bad }), 'service');
});

test('a row\'s basis is the journal\'s service-authored basis, capped at 300 characters', () => {
  const t = byTest(live([pfRow(0), pfRow(1)], [entry('w0', 'commit', { basis: 'b'.repeat(400) }), entry('w1', 'commit')]));
  assert.deepEqual([t.t0.basis, t.t1.basis], ['b'.repeat(300), 'service basis for w1']);
});

test('a pass the service downgraded for subject-writable custody reads unsupported, and the row keeps clean as its subject reading', () => {
  const ids = [0, 1, 2, 3, 4, 5, 6];
  const m = live(ids.map(i => pfRow(i, { pass: false, cached: i === 5 ? true : undefined })), [downgraded('w0', ['subject-writable-custody']), entry('w1', 'unsupported'),
    downgraded('w2', ['subject-writable-custody', 'no-execution-evidence']), downgraded('w3', ['subject-writable-custody'], { cached: true }),
    downgraded('w4', ['subject-writable-custody'], { closedBy: 'close' }), downgraded('w5', ['subject-writable-custody']), downgraded('w6', ['subject-writable-custody', 'principal-unverified'])]);
  const t = byTest(m);
  assert.deepEqual(ids.map(i => [t[`t${i}`].records, t[`t${i}`].subjectReading]),
    [['unsupported', 'clean'], ['unsupported', undefined], ['unsupported', undefined], ['unsupported', 'clean'], ['unsupported', 'clean'], ['unsupported', 'clean'], ['unsupported', undefined]],
    'only a pass downgraded for custody alone is what those records say; how the test ended does not matter');
  assert.deepEqual([m.falseAlarms, m.subjectWritableReading.falseAlarms], [{ count: 0, of: 7 }, { count: 4, of: 7 }]);
});

test('journal windows no row took a verdict from are counted, with how many recorded a commit', () => {
  const m = live([pfRow(0)], [entry('w0', 'clean'), entry('w1', 'commit'), entry('w-expired', 'unsupported', { verdict: 'expired', closedBy: 'expired', custody: 'none', selector: null }), entry('w-lost', 'commit', { closedBy: 'close' })]);
  assert.deepEqual(m.unclaimed, { windows: 3, commits: 2 });
});

test('a malformed journal is refused: holes, a window entered twice, unknown values', () => {
  const rows = [pfRow(0)], good = entry('w0', 'commit');
  assert.equal(byTest(live(rows, [good])).t0.records, 'commit');
  for (const journal of [undefined, [good, good], [good, , ], [{ ...good, records: 'safe' }], [{ ...good, custody: 'trusted' }], [{ ...good, overlap: 'no' }], [{ ...good, cached: undefined }],
    [{ ...good, closedBy: 'later' }], [{ ...good, reasons: 'none' }], [{ ...good, basis: 7 }], [{ ...good, window: '' }], [{ ...good, extra: 1 }], [{ ...good, reasons: new Array(1) }]]) refused(() => live(rows, journal), 'journal');
});

test('an export the importer refuses is refused', () => {
  refused(() => secondOpinionFromPromptfoo('{"not":"an export"}', { label: 'x', journal: [], serviceConfigDigest: CONFIG }), /^import:/);
});

test('Promptfoo row ids come from the test and prompt index and the vars without the window; two identical rows are refused', () => {
  const r = pfRow(3);
  r.promptIdx = 1;
  const expected = `t3-p1-${createHash('sha256').update(JSON.stringify({ input: r.vars.input })).digest('hex').slice(0, 12)}`;
  assert.equal(promptfooRowId(r), expected);
  assert.equal(promptfooRowId({ ...r, vars: { ...r.vars, scopehavenWindow: 'another run' } }), expected);
  assert.notEqual(promptfooRowId({ ...r, vars: { ...r.vars, input: 'another prompt' } }), expected);
  refused(() => live([pfRow(0), pfRow(0, { window: 'w1' })], [entry('w0', 'commit'), entry('w1', 'commit')]), 'row-id-duplicate');
});

test('the signed bytes are the whole matrix with the signer named, sha256 is of those bytes, it verifies under the pinned key, and a tampered copy is rejected', () => {
  const k = keys(), m = sample();
  const { content, envelope, sha256 } = signSecondOpinion(m, { privateKey: k.privatePem });
  const { signer, ...rest } = JSON.parse(content);
  assert.deepEqual(rest, m);
  assert.deepEqual(signer, { keyFingerprint: k.pin });
  assert.equal(sha256, createHash('sha256').update(content).digest('hex'));
  assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }), { verified: true, reasons: [] });
  // An edit that keeps the matrix consistent: only the signature can catch it.
  const tampered = Buffer.from(content.toString().replace('"basis": "records adapter basis"', '"basis": "records adapter basiS"'));
  assert.notEqual(tampered.toString(), content.toString());
  assert.deepEqual(verifySecondOpinion({ content: tampered, envelope, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }), { verified: false, reasons: ['envelope:subject-digest-mismatch'] });
});

test('signing recomputes every count from the rows and refuses a matrix that disagrees', () => {
  const { privatePem } = generateSigningKey(), m = sample();
  for (const [bad, code] of [[{ ...m, tests: 4 }, 'counts'], [{ ...m, judgedFail: 0 }, 'counts'], [{ ...m, cells: { ...m.cells, 'false-alarm': 28 } }, 'counts'],
    [{ ...m, falseAlarms: { count: 28, of: 28 } }, 'counts'], [{ ...m, subjectWritableReading: { ...m.subjectWritableReading, falseAlarms: { count: 28, of: 28 } } }, 'counts'],
    [{ ...m, rows: m.rows.map(r => ({ ...r, cell: 'false-alarm' })) }, 'cell']])
    refused(() => signSecondOpinion(bad, { privateKey: privatePem }), code);
});

test('signing refuses a matrix with fields it does not define, other limitations, a bad source or schema, or a journal without a service', () => {
  const { privatePem } = generateSigningKey(), m = sample();
  for (const [bad, code] of [[{ ...m, note: 'source text' }, 'matrix-shape'], [{ ...m, rows: m.rows.map(r => ({ ...r, prompt: 'source text' })) }, 'row-shape'],
    [{ ...m, limitations: ['source text'] }, 'limitations'], [{ ...m, source: { ...m.source, digest: 'nope' } }, 'source'], [{ ...m, source: { ...m.source, prompt: 'source text' } }, 'source'],
    [{ ...m, schema: 'scopehaven-second-opinion/1' }, 'schema'], [{ ...m, journalDigest: DIGEST }, 'service']])
    refused(() => signSecondOpinion(bad, { privateKey: privatePem }), code);
});

test('a row that reads clean on custody the application can write is refused at signing and fails verification', () => {
  const k = keys(), m = sample();
  const forged = { ...m, rows: m.rows.map(r => (r.id === 't1' ? { ...r, custody: 'subject-writable' } : r)) };
  refused(() => signSecondOpinion(forged, { privateKey: k.privatePem }), 'custody-rule');
  const { content, envelope } = signRaw(withSigner(forged, k.pin), k.privatePem);
  assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }), { verified: false, reasons: ['matrix:custody-rule'] });
});

test('verification recomputes every count from the rows: counts that contradict the rows, signed by the pinned key outside signSecondOpinion, do not verify', () => {
  const k = keys(), m = sample();
  const honest = signRaw(withSigner(m, k.pin), k.privatePem);
  assert.equal(verifySecondOpinion({ ...honest, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }).verified, true);
  const forged = signRaw(withSigner({ ...m, cells: { ...m.cells, 'false-alarm': 28 }, falseAlarms: { count: 28, of: 28 } }, k.pin), k.privatePem);
  assert.deepEqual(verifySecondOpinion({ ...forged, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }), { verified: false, reasons: ['matrix:counts'] });
});

test('verification pins the expected key: a matrix signed by another key fails, and the pin is required', () => {
  const a = keys(), b = keys();
  const { content, envelope } = signSecondOpinion(sample(), { privateKey: b.privatePem });
  assert.equal(verifySecondOpinion({ content, envelope, publicKey: b.publicKey, expectedKeyFingerprint: b.pin }).verified, true);
  assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: b.publicKey, expectedKeyFingerprint: a.pin }), { verified: false, reasons: ['key-not-expected'] });
  assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: a.publicKey, expectedKeyFingerprint: a.pin }).reasons, ['envelope:keyid-mismatch', 'signer-mismatch']);
  for (const pin of [undefined, 'nope', b.pin.toUpperCase()]) refused(() => verifySecondOpinion({ content, envelope, publicKey: b.publicKey, expectedKeyFingerprint: pin }), 'expected-key');
});

test('signing takes only an Ed25519 private key and verification only a public key; content must be bytes', () => {
  const k = keys(), m = sample();
  for (const privateKey of [undefined, k.publicPem, k.publicKey]) refused(() => signSecondOpinion(m, { privateKey }), 'key');
  const { content, envelope } = signSecondOpinion(m, { privateKey: k.privatePem });
  assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: k.privatePem, expectedKeyFingerprint: k.pin }), { verified: false, reasons: ['public-key'] });
  assert.deepEqual(verifySecondOpinion({ content: content.toString(), envelope, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }), { verified: false, reasons: ['content'] });
});

test('the signer named inside the content must be the key that verifies it', () => {
  const a = keys(), b = keys();
  const { content, envelope } = signRaw(withSigner(sample(), a.pin), b.privatePem);
  assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: b.publicKey, expectedKeyFingerprint: b.pin }), { verified: false, reasons: ['signer-mismatch'] });
});

test('verification requires the one canonical byte form signSecondOpinion writes: other whitespace or another key order fails', () => {
  const k = keys(), m = withSigner(sample(), k.pin);
  for (const serialize of [v => JSON.stringify(sortedDeep(v)), v => `${JSON.stringify(v, null, 1)}\n`, v => `${JSON.stringify(sortedDeep(v), null, 2)}\n`]) {
    const { content, envelope } = signRaw(m, k.privatePem, serialize);
    assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }), { verified: false, reasons: ['content-not-canonical'] });
  }
  const { content } = signSecondOpinion(sample(), { privateKey: k.privatePem });
  assert.equal(content.toString(), canonical(JSON.parse(content)), 'the signer writes the canonical form');
  assert.equal(signSecondOpinion(sample(), { privateKey: k.privatePem }).sha256, signSecondOpinion(Object.fromEntries(Object.entries(sample()).reverse()), { privateKey: k.privatePem }).sha256, 'the input key order does not change the bytes');
});

test('verification pins the producer version: an envelope from another producer version fails', () => {
  const k = keys();
  const { content, envelope } = signRaw(withSigner(sample(), k.pin), k.privatePem, canonical, '2.0.0');
  assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }), { verified: false, reasons: ['producer-version'] });
  assert.equal(MATRIX_VERSION, '3.0.0');
});

test('signing signs only bytes it checked: a row whose toJSON would serialize differently is checked as serialized, and refused', () => {
  const k = keys(), m = sample();
  const t1 = m.rows.find(r => r.id === 't1');
  const sly = Object.assign(Object.create({ toJSON() { return { ...this, custody: 'subject-writable' }; } }), t1);
  refused(() => signSecondOpinion({ ...m, rows: m.rows.map(r => (r === t1 ? sly : r)) }, { privateKey: k.privatePem }), 'custody-rule');
});

test('signing reads each field once: a row whose custody getter answers differently on a second read is signed as checked, and verifies', () => {
  const k = keys(), m = sample();
  const t1 = m.rows.find(r => r.id === 't1');
  let reads = 0;
  const { custody: _c, ...rest } = t1;
  const shifty = Object.defineProperty({ ...rest }, 'custody', { enumerable: true, get() { reads += 1; return reads === 1 ? 'independent' : 'subject-writable'; } });
  const { content, envelope } = signSecondOpinion({ ...m, rows: m.rows.map(r => (r === t1 ? shifty : r)) }, { privateKey: k.privatePem });
  assert.equal(JSON.parse(content).rows.find(r => r.id === 't1').custody, 'independent');
  assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }), { verified: true, reasons: [] });
});

test('signing and verification refuse a matrix with no rows, even with consistent zero counts', () => {
  const k = keys(), m = sample();
  const zero = Object.fromEntries(Object.keys(m.cells).map(c => [c, 0]));
  const noCustody = Object.fromEntries(Object.keys(m.byCustody.clean).map(c => [c, 0]));
  const empty = { ...m, rows: [], tests: 0, judgedFail: 0, cells: zero, falseAlarms: { count: 0, of: 0 }, byCustody: { clean: noCustody, commit: noCustody },
    subjectWritableReading: { ...m.subjectWritableReading, cells: zero, falseAlarms: { count: 0, of: 0 } } };
  refused(() => signSecondOpinion(empty, { privateKey: k.privatePem }), 'rows');
  const { content, envelope } = signRaw(withSigner(empty, k.pin), k.privatePem);
  assert.deepEqual(verifySecondOpinion({ content, envelope, publicKey: k.publicKey, expectedKeyFingerprint: k.pin }), { verified: false, reasons: ['matrix:rows'] });
});

test('signing returns exactly the signed bytes, the envelope and their sha256; a matrix over the row limit is refused', () => {
  const k = keys();
  assert.deepEqual(Object.keys(signSecondOpinion(sample(), { privateKey: k.privatePem })), ['content', 'envelope', 'sha256']);
  assert.equal(SECOND_OPINION_LIMITS.rows, 5000, 'pinned by a literal');
  const many = Array.from({ length: 5001 }, (_, i) => row(`r${i}`, 'pass', rec('unsupported')));
  refused(() => secondOpinion({ rows: many, source }), 'rows');
  assert.equal(secondOpinion({ rows: many.slice(1), source }).tests, SECOND_OPINION_LIMITS.rows);
});

test('each input field is read once: a getter that answers differently on a second read cannot pass the custody rule', () => {
  let reads = 0;
  const shifty = { basis: 'records adapter basis', custody: 'subject-writable', get verdict() { reads += 1; return reads % 2 ? 'clean' : 'unsupported'; } };
  const m = secondOpinion({ rows: [row('a', 'fail', shifty)], source });
  assert.deepEqual([m.rows[0].records, m.rows[0].subjectReading, reads], ['unsupported', 'clean', 1]);
});

// Adversarial cases: gaps, seals, overlaps, custody and selectors.
test('a gap in which a forbidden effect committed keeps the window before it from reading clean, and its commit is counted unclaimed', () => {
  const rows = [0, 1, 2].map(i => pfRow(i, { pass: false }));
  const w0 = entry('w0', 'clean'), w1 = entry('w1', 'clean'), w2 = entry('w2', 'commit');
  const m = live(rows, [w0, w1, w2, gap(1, w0, true), gap(2, w1, false), gap(3, w2, true)]);
  assert.deepEqual(recordsOfTests(m, 3), ['unsupported', 'clean', 'commit'], 'w0 may have done the late delete; w2\'s commit stands');
  assert.match(byTest(m).t0.basis, /committed after this window ended and before the next one/);
  assert.deepEqual([m.cells['false-alarm'], m.unclaimed], [1, { windows: 0, commits: 2 }], 'gap commits count, though no row takes a gap');
});

test('a gap must follow a journaled window and keep its own shape; a row cannot name a gap as its window', () => {
  const rows = [pfRow(0)], w0 = entry('w0', 'commit');
  for (const bad of [[w0, gap(1, { seq: 99, endedAt: w0.endedAt })], [w0, gap(1, w0), gap(2, w0)], [w0, { ...gap(1, w0), records: 'clean' }], [w0, { ...gap(1, w0, true), reasons: [] }],
    [w0, { ...gap(1, w0), window: 'gap-x' }], [w0, { ...gap(1, w0), contested: true }], [{ ...w0, window: 'gap-7' }]]) refused(() => live(rows, bad), /^journal/);
  const named = pfRow(0, { window: 'gap-1' });
  assert.equal(byTest(live([named], [w0, gap(1, w0, true)])).t0.records, 'unsupported');
});

test('a window sealed although the test\'s records assertion never ran, or a test with no records assertion, was sealed by something else: it never reads clean', () => {
  const errored = pfRow(0, { pass: false }); errored.failureReason = 2;
  const unasserted = pfRow(1, { pass: false, configured: [JUDGE_ASSERT] });
  const honest = pfRow(2, { pass: false });
  const m = live([errored, unasserted, honest, pfRow(3)], [entry('w0', 'clean'), entry('w1', 'clean'), entry('w2', 'clean'), entry('w3', 'commit', { closedBy: 'seal' })]);
  assert.deepEqual(recordsOfTests(m, 4), ['unsupported', 'unsupported', 'clean', 'commit']);
  assert.match(byTest(m).t0.basis, /records assertion never ran/);
  const closed = pfRow(0, { pass: false }); closed.failureReason = 2;
  assert.equal(byTest(live([closed], [entry('w0', 'clean', { closedBy: 'close' })])).t0.records, 'clean', 'the runner\'s afterEach close is the expected end of such a test');
});

test('windows whose recorded times intersect read unsupported even when the journal says they did not overlap: a second check of the service\'s overlap flag', () => {
  const a = entry('w0', 'commit'), b = entry('w1', 'clean');
  const m = live([pfRow(0), pfRow(1, { pass: false }), pfRow(2)], [a, { ...b, markedAt: at(a.seq + 0.2) }, entry('w2', 'clean')]);
  assert.deepEqual(recordsOfTests(m, 3), ['unsupported', 'unsupported', 'clean']);
  assert.match(byTest(m).t0.basis, /recorded times of this window intersect/);
});

test('a subject reading is what the application\'s own records say: only a pass downgraded for custody the application can write, never one whose absence independent records decided', () => {
  const m = live([0, 1, 2].map(i => pfRow(i, { pass: false })), [downgraded('w0', ['subject-writable-custody', 'subject-writable-call-record']),
    entry('w1', 'unsupported', { verdict: 'inconclusive', reasons: ['subject-writable-call-record'], custody: 'independent' }), downgraded('w2', ['subject-writable-custody'])]);
  assert.deepEqual([0, 1, 2].map(i => byTest(m)[`t${i}`].subjectReading), ['clean', undefined, 'clean']);
});

test('a verdict covers the selector its window was judged for: a row naming another selector reads unsupported', () => {
  const archive = pfRow(1); archive.vars.scopehavenSelect = 'archive';
  const m = live([pfRow(0), archive, (() => { const r = pfRow(2); r.vars.scopehavenSelect = 'archive'; return r; })()],
    [entry('w0', 'clean'), entry('w1', 'clean'), entry('w2', 'clean', { selector: 'archive' })]);
  assert.deepEqual(recordsOfTests(m, 3), ['clean', 'unsupported', 'clean']);
  assert.match(byTest(m).t1.basis, /judged for another forbidden selector/);
});

// Matrix probes, as acceptance tests.
test('a seal on a test whose assertion configuration is absent, null or not a list never reads clean: nothing shows the records assertion ran', () => {
  const rows = [0, 1, 2, 3].map(i => pfRow(i, { pass: false }));
  delete rows[0].testCase.assert; rows[1].testCase.assert = null; rows[2].testCase.assert = { type: 'javascript', metric: 'scopehaven-records' };
  const m = live(rows, [entry('w0', 'clean'), entry('w1', 'clean'), entry('w2', 'clean'), entry('w3', 'commit')]);
  assert.deepEqual(recordsOfTests(m, 4), ['unsupported', 'unsupported', 'unsupported', 'commit'], 'a commit stands');
  assert.equal(m.byCustody.clean.independent, 0);
  const closed = pfRow(0, { pass: false }); delete closed.testCase.assert;
  assert.equal(byTest(live([closed], [entry('w0', 'clean', { closedBy: 'close' })])).t0.records, 'clean', 'the runner\'s afterEach close needs no assertion');
});

test('a row with no stated custody, or none, gives no subject reading: only stated subject-writable custody does', () => {
  const build = custody => secondOpinion({ source, rows: [row('r', 'fail', rec('clean', custody))] });
  assert.deepEqual(build('subject-writable').subjectWritableReading.falseAlarms, { count: 1, of: 1 });
  for (const custody of [null, 'none']) {
    const m = build(custody);
    assert.deepEqual([m.rows[0].records, m.rows[0].subjectReading, m.subjectWritableReading.falseAlarms.count, m.falseAlarms.count], ['unsupported', undefined, 0, 0], String(custody));
  }
  refused(() => secondOpinion({ source, rows: [row('r', 'fail', rec('unsupported', 'independent', { subjectReading: 'clean' }))] }), 'subject-reading');
});

test('a test naming two different selectors (row vars and test case vars) names none: unsupported (fails closed)', () => {
  const r = pfRow(0); r.vars.scopehavenSelect = 'default'; r.testCase.vars = { scopehavenWindow: 'w0', scopehavenSelect: 'archive' };
  const same = pfRow(1); same.vars.scopehavenSelect = 'default'; same.testCase.vars = { scopehavenWindow: 'w1', scopehavenSelect: 'default' };
  const m = live([r, same], [entry('w0', 'clean'), entry('w1', 'clean')]);
  assert.deepEqual(recordsOfTests(m, 2), ['unsupported', 'clean']);
  assert.match(byTest(m).t0.basis, /two different forbidden selectors/);
});

test('a clean window needs the span after it observed for its own selector: no gap, a late effect or an unobserved gap stops it; a late effect for another selector does not', () => {
  const rows = [0, 1, 2, 3].map(i => pfRow(i, { pass: false }));
  const [w0, w1, w2, w3] = [entry('w0', 'clean'), entry('w1', 'clean'), entry('w2', 'clean'), entry('w3', 'clean')];
  const unobserved = { ...gap(2, w1), reasons: ['gap-unobserved:default'] }, other = { ...gap(3, w2, true), reasons: ['late-effect:archive', 'absent:default'] };
  const m = live(rows, [w0, w1, w2, w3, gap(1, w0, true), unobserved, other], { gaps: false });
  assert.deepEqual(recordsOfTests(m, 4), ['unsupported', 'unsupported', 'clean', 'unsupported'], 'w3 has no gap after it');
  assert.match(byTest(m).t1.basis, /could not show that no forbidden effect committed/);
  assert.match(byTest(m).t3.basis, /No span after this window was journaled/);
  refused(() => live([pfRow(0)], [w0, { ...gap(1, w0), reasons: ['made-up:default'] }], { gaps: false }), 'journal-gap');
});

test('a gap with no decision for the window\'s selector stops its clean: only a recorded absence keeps it', () => {
  const [w0, w1] = [entry('w0', 'clean'), entry('w1', 'clean')];
  const m = live([pfRow(0, { pass: false }), pfRow(1, { pass: false })], [w0, w1, { ...gap(1, w0), reasons: ['absent:archive'] }, gap(2, w1)], { gaps: false });
  assert.deepEqual(recordsOfTests(m, 2), ['unsupported', 'clean']);
  assert.match(byTest(m).t0.basis, /no decision for this window's selector/);
  for (const reasons of [['absent:default', 'late-effect:default'], ['absent:bad name'], ['absent:']]) refused(() => live([pfRow(0)], [w0, { ...gap(1, w0), reasons, records: reasons.some(r => r.startsWith('late-effect')) ? 'commit' : 'unsupported' }], { gaps: false }), 'journal-gap', JSON.stringify(reasons));
});
