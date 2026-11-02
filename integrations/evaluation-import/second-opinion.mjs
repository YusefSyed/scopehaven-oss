// Second opinion: a judge-vs-records matrix for an external
// evaluation. Each test has two verdicts, reported side by side and never merged:
//   judge    what the evaluation's own grader said, mapped by the importer's rules
//            (import.mjs classify: pass, fail, error, unknown);
//   records  what the records show for that test:
//            commit       a forbidden effect committed, or a record the user may not see
//                         reached them (on any record, the application's own included: a
//                         commit stands, and the row's custody says whose record showed it);
//            clean        complete, settled, authoritative records with independent custody
//                         cover the test's window, show the test's completed call and show none of
//                         that, and the span after the window was observed to show none either;
//            unsupported  nothing decides (no window, a window another test shares or overlaps,
//                         a window sealed or closed twice, no record of the call, a gap, an
//                         observer failure, or a clean reading that rests on presence-only
//                         evidence or on records the application can write).
// The records column is never parsed from text in the export: a live Promptfoo run reads it from
// the records service's journal (verdict-service.mjs), keyed by the window the hook put on the
// test; an archive from a records adapter. Fields the application or a grader can set (a cached
// flag, extra components) decide nothing. The custody rule
// (evid-subject/custody.mjs) is applied again here; what the application's own authoritative
// records would say is kept apart as subjectWritableReading, labelled as not custody-backed.
// The matrix keeps no source text: rows carry a stable id, the two verdicts, custody and a basis
// the service or adapter wrote. Signing recomputes every count from the rows, names the key and
// writes one canonical form (keys sorted at every level); verifying recomputes them again, pins
// the expected key and the producer version, and refuses any other byte form.
import { createHash, createPrivateKey, createPublicKey, KeyObject } from 'node:crypto';
import { stable } from '../../src/domain.mjs';
import { importPromptfooJson, INPUT_CONTRACT } from './import.mjs';
import { parseBoundedJson } from './bounded-json.mjs';
import { signFiles } from '../attest/sign.mjs';
import { verifyEnvelope, keyIdOf, trustedKey } from '../attest/verify.mjs';
import { CUSTODY, INDEPENDENT_CUSTODY } from '../evid-subject/custody.mjs';

export const MATRIX_SCHEMA = 'scopehaven-second-opinion/3';
export const MATRIX_FILE = 'SECOND-OPINION.json';
// The producer version the signed statement carries (integrations/attest requires x.y.z).
export const MATRIX_VERSION = '3.0.0';
export const JUDGE_STATES = Object.freeze(['pass', 'fail', 'error', 'unknown']);
export const RECORDS_VERDICTS = Object.freeze(['commit', 'clean', 'unsupported']);
// The named cells, by judge state and records verdict.
export const CELLS = Object.freeze({
  'pass/commit': 'missed', 'fail/clean': 'false-alarm', 'pass/unsupported': 'unsupported-pass',
  'fail/commit': 'agreed-violation', 'pass/clean': 'agreed-clean', 'fail/unsupported': 'unsupported-fail',
});
// The records assertion as Promptfoo exports it (component.assertion); chosen by these two only.
export const RECORDS_COMPONENT = Object.freeze({ type: 'javascript', metric: 'scopehaven-records' });
export const SUBJECT_WRITABLE_MEANING = 'what the authoritative records the application itself can write would say (presence-only evidence gives no reading); not a custody-backed verdict';
export const SECOND_OPINION_LIMITS = Object.freeze({ rows: 5000, journal: 10000, basis: 300, label: 120, window: 128 });
const LIMITATIONS = Object.freeze([
  'The judge column is the evaluation\'s own grade as exported. The records column is never parsed from text in the export: it comes from the records service\'s journal or a records adapter, and each row\'s custody says whether the application under test could write the records it rests on.',
  'A clean records verdict covers only what the observers watch, and only on records the application cannot write. A commit may rest on the application\'s own records. Unsupported means no record could decide, never that the test was safe.',
  `subjectWritableReading is ${SUBJECT_WRITABLE_MEANING}.`,
]);
const CELL_NAMES = Object.freeze([...Object.values(CELLS), 'judge-error', 'judge-unknown']);
const CUSTODY_VALUES = Object.freeze([...CUSTODY, 'none']);
// byCustody's keys: every custody a row can state, and 'unstated' for a row that states none.
const CUSTODY_KEYS = Object.freeze([...CUSTODY_VALUES, 'unstated']);
// Ids are names, never text: letters, digits and . _ : - only, so no source text rides in one.
const ROW_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const MATRIX_KEYS = Object.freeze(['schema', 'source', 'service', 'journalDigest', 'unclaimed', 'tests', 'judgedFail', 'cells', 'falseAlarms', 'byCustody', 'subjectWritableReading', 'rows', 'limitations']);
// The service journal entry (verdict-service.mjs, scopehaven-records-service/2).
const JOURNAL_KEYS = Object.freeze(['window', 'seq', 'config', 'records', 'verdict', 'reasons', 'custody', 'basis', 'selector', 'closedBy', 'overlap', 'cached', 'contested', 'markedAt', 'endedAt']);
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const GAP_ID = /^gap-[1-9]\d{0,5}$/;
const CUSTODY_REASONS = Object.freeze(['subject-writable-custody', 'subject-writable-call-record']);
// What the service writes: core's verdicts and its own, and the reasons it gives.
const SERVICE_VERDICTS = Object.freeze(['pass', 'fail', 'inconclusive', 'unobservable', 'missing', 'observer-failure', 'overlapping-window', 'expired']);
const SERVICE_REASONS = Object.freeze([...CUSTODY_REASONS, 'no-execution-evidence', 'principal-unverified', 'internal-error']);
const RECORDS_OF = Object.freeze({ pass: 'clean', fail: 'commit' });
const ROW_KEYS = Object.freeze(['id', 'judge', 'records', 'cell', 'custody', 'basis']);
const OPTIONAL_ROW_KEYS = Object.freeze(['evidence', 'subjectReading']);

export class SecondOpinionError extends Error { constructor(code) { super(`Invalid second-opinion input: ${code}.`); this.name = 'SecondOpinionError'; this.code = code; } }
const fail = code => { throw new SecondOpinionError(code); };
// Every check fails closed with SecondOpinionError, never a TypeError from a malformed input.
const guarded = fn => (...args) => { try { return fn(...args); } catch (error) { if (error instanceof SecondOpinionError) throw error; throw new SecondOpinionError('malformed'); } };
const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const hex64 = v => typeof v === 'string' && HEX64.test(v);
const count = v => Number.isSafeInteger(v) && v >= 0;
const exactKeys = (v, keys) => isObj(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
// Array.prototype.every skips holes, so density is checked index by index.
function dense(v, max) {
  if (!Array.isArray(v) || v.length > max) return false;
  for (let i = 0; i < v.length; i++) if (!Object.hasOwn(v, i)) return false;
  return true;
}
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
// The one byte form a signed matrix takes: keys sorted at every level, one-space indent.
const sorted = v => Array.isArray(v) ? v.map(sorted) : isObj(v) ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sorted(v[k])])) : v;
const canonicalBytes = m => Buffer.from(`${JSON.stringify(sorted(m), null, 1)}\n`);
const same = (a, b) => stable(a) === stable(b);
const cellOf = (judge, records) => CELLS[`${judge}/${records}`] ?? `judge-${judge}`;
const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

function countsOf(rows, verdictOf) {
  const cells = Object.fromEntries(CELL_NAMES.map(name => [name, 0]));
  let judgedFail = 0;
  for (const r of rows) { cells[cellOf(r.judge, verdictOf(r))]++; if (r.judge === 'fail') judgedFail++; }
  return { cells, judgedFail, falseAlarms: { count: cells['false-alarm'], of: judgedFail } };
}
// Clean and commit verdicts by the custody of the records that decided them. A clean is only ever
// observer-held or independent (the custody rule); a commit may rest on any custody.
function byCustodyOf(rows) {
  const zero = () => Object.fromEntries(CUSTODY_KEYS.map(k => [k, 0]));
  const counts = { clean: zero(), commit: zero() };
  for (const r of rows) if (r.records !== 'unsupported') counts[r.records][r.custody ?? 'unstated']++;
  return counts;
}
// Every count the matrix states, derived from its rows alone.
function tally(rows) {
  const decided = countsOf(rows, r => r.records), reading = countsOf(rows, r => r.subjectReading ?? r.records);
  return { tests: rows.length, judgedFail: decided.judgedFail, cells: decided.cells, falseAlarms: decided.falseAlarms, byCustody: byCustodyOf(rows),
    subjectWritableReading: { meaning: SUBJECT_WRITABLE_MEANING, cells: reading.cells, falseAlarms: reading.falseAlarms } };
}

// One input row: { id, judge, records: { verdict, basis, custody?, evidence?, subjectReading? } }.
function inputRow(r) {
  if (!isObj(r) || typeof r.id !== 'string' || !ROW_ID.test(r.id)) fail('row-id');
  if (!JUDGE_STATES.includes(r.judge)) fail('judge-state');
  const rec = r.records;
  if (!isObj(rec) || !RECORDS_VERDICTS.includes(rec.verdict)) fail('records-verdict');
  if (typeof rec.basis !== 'string' || !rec.basis.length || rec.basis.length > SECOND_OPINION_LIMITS.basis) fail('basis');
  if (rec.custody !== undefined && rec.custody !== null && !CUSTODY_VALUES.includes(rec.custody)) fail('custody');
  if (rec.evidence !== undefined && rec.evidence !== 'presence-only') fail('evidence');
  if (rec.subjectReading !== undefined && (rec.verdict !== 'unsupported' || !['clean', 'commit'].includes(rec.subjectReading) || rec.evidence === 'presence-only' || rec.custody !== 'subject-writable')) fail('subject-reading');
  const custody = rec.custody ?? null, presenceOnly = rec.evidence === 'presence-only';
  // The custody rule again, after the service (defence in depth): clean needs a deciding window
  // the application cannot write, and presence-only evidence cannot back a clean reading (its
  // silence is not absence). Like core's rule, only clean is downgraded: a commit that presence-only
  // evidence or the application's own records show still stands (it can show an effect happened).
  // A clean reading downgraded for custody alone is what the application's own records say; one
  // on presence-only evidence says nothing, so it gives no reading.
  const unbacked = rec.verdict === 'clean' && (presenceOnly || !INDEPENDENT_CUSTODY.includes(custody));
  const records = unbacked ? 'unsupported' : rec.verdict;
  // Only records stated to be the application's own give the application's own reading: no stated
  // custody, or none, says nothing about whose records they are.
  const reading = presenceOnly || custody !== 'subject-writable' ? undefined : unbacked ? rec.verdict : rec.subjectReading;
  return { id: r.id, judge: r.judge, records, cell: cellOf(r.judge, records), custody, basis: rec.basis,
    ...(presenceOnly ? { evidence: 'presence-only' } : {}), ...(reading ? { subjectReading: reading } : {}) };
}
// A row as the matrix states it; checked again at signing and verification.
function checkRow(r) {
  if (!isObj(r) || ROW_KEYS.some(k => !Object.hasOwn(r, k)) || Object.keys(r).some(k => !ROW_KEYS.includes(k) && !OPTIONAL_ROW_KEYS.includes(k))) fail('row-shape');
  if (typeof r.id !== 'string' || !ROW_ID.test(r.id)) fail('row-id');
  if (!JUDGE_STATES.includes(r.judge)) fail('judge-state');
  if (!RECORDS_VERDICTS.includes(r.records)) fail('records-verdict');
  if (r.custody !== null && !CUSTODY_VALUES.includes(r.custody)) fail('custody');
  if (typeof r.basis !== 'string' || !r.basis.length || r.basis.length > SECOND_OPINION_LIMITS.basis) fail('basis');
  if (Object.hasOwn(r, 'evidence') && r.evidence !== 'presence-only') fail('evidence');
  if (Object.hasOwn(r, 'subjectReading') && (r.records !== 'unsupported' || !['clean', 'commit'].includes(r.subjectReading) || r.evidence === 'presence-only' || r.custody !== 'subject-writable')) fail('subject-reading');
  if (r.records === 'clean' && (!INDEPENDENT_CUSTODY.includes(r.custody) || r.evidence === 'presence-only')) fail('custody-rule');
  if (r.cell !== cellOf(r.judge, r.records)) fail('cell');
}
function sourceOf(s) {
  if (!isObj(s) || typeof s.label !== 'string' || !s.label.length || !hex64(s.digest)) fail('source');
  const contract = s.contract ?? null;
  // Only a short contract name: an arbitrary object here would carry source text into the matrix.
  if (contract !== null && (typeof contract !== 'string' || !contract.length || contract.length > SECOND_OPINION_LIMITS.label)) fail('source');
  return { label: s.label.slice(0, SECOND_OPINION_LIMITS.label), contract, digest: s.digest };
}
// A live run binds the service configuration, the journal and the journal windows no row used;
// an archive matrix has no service and binds none of them.
function serviceOf(s) {
  if (s === null || s === undefined) return { service: null, journalDigest: null, unclaimed: null };
  const u = s?.unclaimed;
  if (!isObj(s) || !hex64(s.configDigest) || !hex64(s.journalDigest) || !isObj(u) || !count(u.windows) || !count(u.commits)) fail('service');
  return { service: { configDigest: s.configDigest }, journalDigest: s.journalDigest, unclaimed: { windows: u.windows, commits: u.commits } };
}

// rows: [{ id, judge, records }] in any order (output is sorted by id); source: { label, contract?,
// digest } of the export; service: { configDigest, journalDigest, unclaimed } for a live run.
export const secondOpinion = guarded(({ rows, source, service = null } = {}) => {
  if (!dense(rows, SECOND_OPINION_LIMITS.rows) || !rows.length) fail('rows');
  // A plain copy first: every field is read once, so no getter can answer two checks differently.
  const built = structuredClone(rows).map(inputRow).sort(byId);
  for (let i = 1; i < built.length; i++) if (built[i - 1].id === built[i].id) fail('row-id-duplicate');
  return { schema: MATRIX_SCHEMA, source: sourceOf(source), ...serviceOf(service), ...tally(built), rows: built, limitations: [...LIMITATIONS] };
});

// The whole matrix, as signing and verification read it: shape, the rule per row, id order, and
// every count recomputed from the rows.
function checkMatrix(m) {
  if (!exactKeys(m, MATRIX_KEYS)) fail('matrix-shape');
  if (m.schema !== MATRIX_SCHEMA) fail('schema');
  if (!exactKeys(m.source, ['label', 'contract', 'digest']) || !same(sourceOf(m.source), m.source)) fail('source');
  const bound = { service: m.service, journalDigest: m.journalDigest, unclaimed: m.unclaimed };
  if (!same(serviceOf(m.service === null ? null : { ...(isObj(m.service) ? m.service : {}), journalDigest: m.journalDigest, unclaimed: m.unclaimed }), bound)) fail('service');
  if (!dense(m.rows, SECOND_OPINION_LIMITS.rows) || !m.rows.length) fail('rows');
  m.rows.forEach(checkRow);
  for (let i = 1; i < m.rows.length; i++) {
    if (m.rows[i - 1].id === m.rows[i].id) fail('row-id-duplicate');
    if (m.rows[i - 1].id > m.rows[i].id) fail('row-order');
  }
  const t = tally(m.rows);
  for (const k of ['tests', 'judgedFail', 'cells', 'falseAlarms', 'byCustody', 'subjectWritableReading']) if (!same(m[k], t[k])) fail('counts');
  if (!same(m.limitations, LIMITATIONS)) fail('limitations');
}

// The records assertion's components on a Promptfoo row, chosen by assertion type and metric only.
// Reason text is never read: the judge can write it. A grader can emit a component of this shape
// too, so components never decide the records column; the journal does.
const isRecordsAssertion = a => isObj(a) && a.type === RECORDS_COMPONENT.type && a.metric === RECORDS_COMPONENT.metric;
export const recordsComponentsOf = guarded(row => {
  const components = row?.gradingResult?.componentResults;
  return Array.isArray(components) ? components.filter(c => isRecordsAssertion(c?.assertion)) : [];
});
// A Promptfoo row's stable id: test and prompt index, and the first 12 hex of the sha256 of the
// canonical JSON of its vars without the per-run window.
export const promptfooRowId = guarded(row => {
  const vars = { ...row.vars };
  delete vars.scopehavenWindow;
  return `t${row.testIdx}-p${row.promptIdx}-${sha256(stable(vars)).slice(0, 12)}`;
});
export const journalDigestOf = guarded(journal => sha256(stable(journal)));

const CONFLICT = Symbol('two windows');
function windowOf(row) {
  const a = row.vars?.scopehavenWindow, b = isObj(row.testCase?.vars) ? row.testCase.vars.scopehavenWindow : undefined;
  if (a !== undefined && b !== undefined && a !== b) return CONFLICT;
  const w = a ?? b;
  return typeof w === 'string' && w.length && w.length <= SECOND_OPINION_LIMITS.window ? w : null;
}
// One journal entry, and the rules the service states for it: records follow the verdict; a clean
// entry is a judged (sealed or closed), unoverlapped pass with no reasons on records the application
// cannot write; a commit is a judged window that no other overlapped; any reason means unsupported,
// and a custody reason only on a downgraded pass on custody the application can write. A gap
// (closedBy 'gap', verdict 'gap') is the span after window <seq>, in no window: commit when a
// forbidden effect committed in it. Every entry carries the service configDigest and its times.
function journalEntry(e, configDigest) {
  if (!exactKeys(e, JOURNAL_KEYS) || typeof e.window !== 'string' || !e.window.length || e.window.length > SECOND_OPINION_LIMITS.window
    || !Number.isSafeInteger(e.seq) || e.seq < 1 || e.config !== configDigest
    || !RECORDS_VERDICTS.includes(e.records) || typeof e.verdict !== 'string' || !dense(e.reasons, 64) || e.reasons.some(x => typeof x !== 'string')
    || !CUSTODY_VALUES.includes(e.custody) || typeof e.basis !== 'string' || !(e.selector === null || typeof e.selector === 'string')
    || !['seal', 'close', 'expired', 'gap'].includes(e.closedBy) || [e.overlap, e.cached, e.contested].some(x => typeof x !== 'boolean')
    || ![e.markedAt, e.endedAt].every(t => typeof t === 'string' && ISO.test(t) && !Number.isNaN(Date.parse(t))) || Date.parse(e.endedAt) < Date.parse(e.markedAt)) fail('journal');
  if (e.closedBy === 'gap') {
    if (!GAP_ID.test(e.window) || e.verdict !== 'gap' || e.records === 'clean' || e.selector !== null || e.overlap || e.cached || e.contested
      || (e.records === 'commit') !== e.reasons.some(r => r.startsWith('late-effect:')) || e.reasons.some(r => !/^(late-effect|gap-unobserved|absent):[A-Za-z0-9._-]{1,64}$/.test(r))
      || new Set(e.reasons.map(r => r.slice(r.indexOf(':') + 1))).size !== e.reasons.length) fail('journal-gap');
    return e;
  }
  if (GAP_ID.test(e.window)) fail('journal-gap');
  if (!SERVICE_VERDICTS.includes(e.verdict) || e.reasons.some(r => !SERVICE_REASONS.includes(r))) fail('journal-verdict');
  if ((e.closedBy === 'expired') !== (e.selector === null)) fail('journal');
  if (e.records !== (RECORDS_OF[e.verdict] ?? 'unsupported')) fail('journal-verdict');
  if (e.records === 'clean' && (e.reasons.length || !INDEPENDENT_CUSTODY.includes(e.custody) || e.closedBy === 'expired' || e.overlap)) fail('journal-clean');
  if (e.records === 'commit' && (e.closedBy === 'expired' || e.overlap || !CUSTODY.includes(e.custody))) fail('journal-commit');
  if (e.reasons.length && e.records !== 'unsupported') fail('journal-reasons');
  if (e.reasons.includes('subject-writable-custody') && (e.verdict !== 'inconclusive' || e.custody !== 'subject-writable')) fail('journal-reasons');
  return e;
}
// The service's journal (contract: one entry per marked window, in the order they ended, then the
// gaps), indexed: windows by id, gaps by the seq of the window they follow, and the windows whose
// recorded times intersect another window's (a second check of the service's overlap flag).
function journalIndex(journal, configDigest) {
  if (!hex64(configDigest)) fail('service');
  if (!dense(journal, SECOND_OPINION_LIMITS.journal)) fail('journal');
  const byWindow = new Map(), gapAfter = new Map(), seqs = new Set();
  for (const e of journal) {
    journalEntry(e, configDigest);
    if (byWindow.has(e.window)) fail('journal');
    byWindow.set(e.window, e);
    if (e.closedBy === 'gap') { if (gapAfter.has(e.seq)) fail('journal-gap'); gapAfter.set(e.seq, e); }
    else { if (seqs.has(e.seq)) fail('journal'); seqs.add(e.seq); }
  }
  for (const seq of gapAfter.keys()) if (!seqs.has(seq)) fail('journal-gap');
  const spans = journal.filter(e => e.closedBy !== 'gap').map(e => [Date.parse(e.markedAt), Date.parse(e.endedAt), e.window]).sort((a, b) => a[0] - b[0]);
  const timeOverlap = new Set();
  let maxEnd = -Infinity, maxId = null;
  for (const [from, to, id] of spans) { if (from < maxEnd) { timeOverlap.add(id); timeOverlap.add(maxId); } if (to > maxEnd) { maxEnd = to; maxId = id; } }
  return { byWindow, gapAfter, timeOverlap };
}
const none = basis => ({ verdict: 'unsupported', basis, custody: 'none' });
// One row's records verdict, from the journal entry for its window and nothing the export says
// about the verdict (its cached flag included). A commit always stands; these only stop a clean
// reading: a window sealed or closed twice, a window sealed although the test's assertions never ran
// or it has no records assertion (something else sealed it), and a window followed by a gap in which
// a forbidden effect committed (it may be this test's late work). A window whose recorded times
// intersect another window's is unsupported, commit or not. `uses` counts rows per window; `claimed`
// collects entries whose verdict a row took.
function recordsOf(row, window, uses, index, claimed) {
  if (window === CONFLICT) return none('the test names two different records windows');
  if (window === null) return none('no records window was marked for this test');
  if (uses.get(window) > 1) return none('more than one test names this records window');
  const entry = index.byWindow.get(window);
  if (!entry || entry.closedBy === 'gap') return none('the records service has no entry for this window');
  if (index.timeOverlap.has(window)) return { verdict: 'unsupported', basis: 'The recorded times of this window intersect another window\'s, so its effects cannot be attributed to this test.', custody: entry.custody };
  // A seal is the runner's only when the test's configured assertions include the records assertion and
  // ran: no configuration (absent, null, not a list) is no evidence that it ran.
  const sealedElsewhere = entry.closedBy === 'seal' && (row.failureReason === 2 || !(Array.isArray(row.testCase?.assert) && row.testCase.assert.some(isRecordsAssertion)));
  // The verdict covers the selector the window was judged for; it must be the one this test names, and
  // a test naming two different ones names none.
  const selects = [row.vars?.scopehavenSelect, isObj(row.testCase?.vars) ? row.testCase.vars.scopehavenSelect : undefined].filter(v => v !== undefined);
  const named = selects.length > 1 && selects[0] !== selects[1] ? null : selects[0] ?? 'default';
  if (entry.closedBy !== 'expired' && entry.selector !== named) { claimed.add(window); return { verdict: 'unsupported', basis: named === null ? 'This test names two different forbidden selectors.' : 'This window was judged for another forbidden selector than the one this test names.', custody: entry.custody }; }
  // The span after the window must have been observed for this selector: only a recorded absence for it
  // keeps a clean. No gap entry (a journal read before the service stopped), a late effect, an absence the
  // gap could not show, or no decision for this selector at all stops it.
  const gap = index.gapAfter.get(entry.seq);
  const after = !gap ? 'missing' : gap.reasons.includes(`late-effect:${entry.selector}`) ? 'late' : gap.reasons.includes(`gap-unobserved:${entry.selector}`) ? 'unobserved'
    : gap.reasons.includes(`absent:${entry.selector}`) ? 'observed' : 'undecided';
  const stop = entry.contested ? 'This window was sealed or closed twice, so something other than the runner held the records token.'
    : sealedElsewhere ? 'This window was sealed although this test\'s records assertion never ran or is not configured, so nothing shows the runner sealed it.'
    : after === 'late' ? 'A forbidden effect committed after this window ended and before the next one: it may be this test\'s late work.'
    : after === 'unobserved' ? 'After this window ended, the records could not show that no forbidden effect committed.'
    : after === 'missing' ? 'No span after this window was journaled, so a late effect could not be ruled out (read the journal after the service stops).'
    : after === 'undecided' ? 'The span after this window has no decision for this window\'s selector.' : null;
  claimed.add(window);
  if (entry.records === 'clean' && stop) return { verdict: 'unsupported', basis: stop, custody: entry.custody };
  const basis = (entry.basis || `records service: ${entry.records}`).slice(0, SECOND_OPINION_LIMITS.basis);
  // A pass the service downgraded only because the records that decided it, and the call record, are
  // ones the application can write, is what those records say.
  const reading = !stop && entry.records === 'unsupported' && entry.verdict === 'inconclusive' && entry.custody === 'subject-writable' && entry.closedBy !== 'expired' && !entry.overlap
    && entry.reasons.includes('subject-writable-custody') && entry.reasons.every(r => CUSTODY_REASONS.includes(r));
  return { verdict: entry.records, basis, custody: entry.custody, ...(reading ? { subjectReading: 'clean' } : {}) };
}
// Promptfoo scores a test whose only assertions carry weight 0 as 0: no judge spoke. Read from the
// test's configured assertions (config-authored), never from the graded components.
function onlyRecordsAssertion(row) {
  const configured = row.testCase?.assert;
  return Array.isArray(configured) && configured.length > 0 && configured.every(isRecordsAssertion);
}

// A live Promptfoo export with the records hook and assertion on its tests: the importer decides
// the judge column (and refuses what it refuses), the service's journal the records column.
// journal: startVerdictService(...).journal(); serviceConfigDigest: its configDigest, which every
// journal entry must carry.
export const secondOpinionFromPromptfoo = guarded((text, { label, journal, serviceConfigDigest } = {}) => {
  const index = journalIndex(journal, serviceConfigDigest);
  const imported = importPromptfooJson(text, INPUT_CONTRACT);
  if (!imported.ok) fail(`import:${imported.error.code}`);
  const exported = parseBoundedJson(text).results.results;
  const windows = exported.map(windowOf), uses = new Map(), claimed = new Set();
  for (const w of windows) if (typeof w === 'string') uses.set(w, (uses.get(w) ?? 0) + 1);
  const rows = exported.map((row, i) => {
    let judge = imported.record.checks[i].state;
    if (judge !== 'error' && onlyRecordsAssertion(row)) judge = 'unknown';
    return { id: promptfooRowId(row), judge, records: recordsOf(row, windows[i], uses, index, claimed) };
  });
  // Windows no row took a verdict from, and the commits in them or in the gaps (no row ever takes a gap).
  const unclaimed = journal.filter(e => e.closedBy !== 'gap' && !claimed.has(e.window)), gapCommits = journal.filter(e => e.closedBy === 'gap' && e.records === 'commit').length;
  return secondOpinion({ rows, source: { label, contract: INPUT_CONTRACT, digest: createHash('sha256').update(text, 'utf8').digest('hex') },
    service: { configDigest: serviceConfigDigest, journalDigest: journalDigestOf(journal), unclaimed: { windows: unclaimed.length, commits: unclaimed.filter(e => e.records === 'commit').length + gapCommits } } });
});

// The pin a verifier holds: sha256 of the Ed25519 public key's SPKI DER (attest's keyid).
export const keyFingerprintOf = guarded(publicKey => keyIdOf(trustedKey(publicKey)));

// Sign the matrix (DSSE/in-toto via integrations/attest). The matrix is copied through JSON first,
// so the bytes signed are the bytes checked; every count is recomputed from the rows, and the
// signed content names the signing key, in canonical form. Returns the exact bytes, the envelope
// and the sha256 of those bytes.
export const signSecondOpinion = guarded((matrix, { privateKey, now } = {}) => {
  let key;
  try { key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey); } catch { fail('key'); }
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') fail('key');
  if (!isObj(matrix)) fail('matrix-shape');
  // A signer already present is replaced by the one this key proves.
  const { signer: _replaced, ...unsigned } = JSON.parse(JSON.stringify(matrix));
  checkMatrix(unsigned);
  const content = canonicalBytes({ ...unsigned, signer: { keyFingerprint: keyIdOf(createPublicKey(key)) } });
  let envelope;
  try { ({ envelope } = signFiles([{ name: MATRIX_FILE, content }], { privateKey: key, version: MATRIX_VERSION, now })); } catch { fail('sign'); }
  return { content, envelope, sha256: sha256(content) };
});

// Verify a signed matrix against a trusted public key and the fingerprint the verifier expects.
// The pin must come from somewhere other than the matrix's own folder (the README publishes the
// receipts' signer): a fingerprint computed from the key handed over with the matrix pins nothing.
// The envelope must verify with this producer version, the signer named inside must be that key,
// the bytes must be the canonical form, and every count must follow from the rows.
// Returns { verified, reasons }.
export const verifySecondOpinion = guarded(({ content, envelope, publicKey, expectedKeyFingerprint } = {}) => {
  if (!hex64(expectedKeyFingerprint)) fail('expected-key');
  const reasons = [];
  let key = null;
  try { key = trustedKey(publicKey); } catch { reasons.push('public-key'); }
  if (!Buffer.isBuffer(content)) reasons.push('content');
  if (reasons.length) return { verified: false, reasons };
  const fingerprint = keyIdOf(key);
  if (fingerprint !== expectedKeyFingerprint) reasons.push('key-not-expected');
  let env;
  try { env = verifyEnvelope({ envelope, publicKey: key, files: new Map([[MATRIX_FILE, content]]) }); } catch { env = { verified: false, reason: 'unreadable' }; }
  if (!env.verified) reasons.push(`envelope:${env.reason}`);
  else if (env.producer?.version !== MATRIX_VERSION) reasons.push('producer-version');
  let parsed = null;
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(content);
    parsed = JSON.parse(text);
    if (!canonicalBytes(parsed).equals(content)) reasons.push('content-not-canonical');
  } catch { reasons.push('content-json'); }
  if (parsed !== null) {
    if (!isObj(parsed) || !exactKeys(parsed.signer, ['keyFingerprint']) || parsed.signer.keyFingerprint !== fingerprint) reasons.push('signer-mismatch');
    try {
      const { signer: _named, ...unsigned } = isObj(parsed) ? parsed : {};
      checkMatrix(unsigned);
    } catch (error) { reasons.push(`matrix:${error instanceof SecondOpinionError ? error.code : 'malformed'}`); }
  }
  return { verified: reasons.length === 0, reasons };
});
