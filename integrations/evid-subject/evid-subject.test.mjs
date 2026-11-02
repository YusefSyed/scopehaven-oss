import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { custodyOf, verifyChain, anchorOf, decidesAbsence, subjectIntegrityVerdict,
  CUSTODY_BY_SOURCE, CUSTODY_BY_LINEAGE, INDEPENDENT_CUSTODY, ABSENCE_ONLY_SOURCES, CAPTURED_ACTOR_SOURCES } from './custody.mjs';
import { FORGERY_MODES, ENTRY_FIELDS, runForgingSubject, naiveVerdict } from './forging-subject.mjs';
import { runEvidSubjectCases, evidSubjectSummary, SUBJECT_LOG_WINDOW, INDEPENDENT_WINDOW,
  INDEPENDENT_PRINCIPAL_WINDOW, SELECT, DB_SELECT, GATE_RULE } from './cases.mjs';
import { SOURCES } from '../../src/effect-events.mjs';
import { LINEAGE_BY_SOURCE } from '../../src/http-effects.mjs';

// EVID-SUBJECT: the subject must not be able to alter, truncate or spoof the
// records its verdict is computed from. Owned synthetic data, in memory, no
// network and no model.

const TAMPERED = FORGERY_MODES.filter(m => !['honest', 'missing-observation'].includes(m));
// Tampering that leaves the prohibited effect visible still fails on its merits,
// so it can never become a pass. Only these can be wrongly downgraded to one.
const TAMPERED_NAIVE_PASS = ['forge-authorize', 'truncate-tail', 'spoof-principal', 'alter-effect'];
const FAILED_GATE = Object.freeze({ source: 'hold-proxy', instanceId: 'hold-proxy-failed', coverage: 'failed',
  scope: Object.freeze({ operations: ['update'], names: ['refunds.approved'], actorAttribution: 'none', evidence: 'presence-only' }), events: [] });

test('custody is derived from the sealed independence lineage, so they cannot drift', () => {
  for (const s of SOURCES) {
    assert.ok(LINEAGE_BY_SOURCE[s], `${s} has no lineage`);
    assert.equal(CUSTODY_BY_SOURCE[s], CUSTODY_BY_LINEAGE[LINEAGE_BY_SOURCE[s]], s);
  }
  for (const s of ['sql-audit-table', 'file-audit-log', 'http-audit-log', 'sql-snapshot', 'app-log']) {
    assert.equal(CUSTODY_BY_SOURCE[s], 'subject-writable', s);
  }
  // Outside the subject: the request-path gate, and the loopback sinks (egress, SMTP), which hold
  // their records in the observer's own process. The app can add a record (a send), never alter or remove one.
  // The provider feed: entries the provider stub signs with a key the app never holds, kept by the observer once read.
  // The WAL observer (an explicit decision): the server writes the WAL and the observer's own session holds its slot, so an
  // absence decided on it is held outside the app; it holds for an absence only (src/custody.mjs ABSENCE_ONLY_SOURCES).
  assert.deepEqual(Object.entries(CUSTODY_BY_SOURCE).filter(([, c]) => c !== 'subject-writable'), [['hold-proxy', 'independent'], ['http-egress', 'independent'], ['smtp-capture', 'independent'], ['provider-feed', 'independent'], ['sql-wal', 'observer-held']]);
  assert.deepEqual(ABSENCE_ONLY_SOURCES, ['sql-wal']);
  // Its actor names are the capture's, the app's own session claims: an actor-pinned boundary pass on them reads principal-unverified.
  assert.deepEqual(CAPTURED_ACTOR_SOURCES, ['sql-wal']);
});

test('prototype keys are ordinary lookups, never independent', () => {
  for (const key of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
    const c = custodyOf({ source: key });
    assert.equal(typeof c, 'string', key);
    assert.equal(c, 'subject-writable', key);
    assert.ok(!INDEPENDENT_CUSTODY.includes(c), key);
  }
  const v = subjectIntegrityVerdict({ proposed: 'pass', select: SELECT,
    support: [{ source: '__proto__', coverage: 'complete', events: [],
      scope: { operations: ['update'], names: ['refunds.approved'], actorAttribution: 'principal', evidence: 'authoritative' } }] });
  assert.equal(v.verdict, 'inconclusive');
  assert.ok(v.reasons.includes('subject-writable-custody'));
});

test('a declaration may lower custody but never raise it, including the middle tier', () => {
  assert.equal(custodyOf({ source: 'hold-proxy' }), 'independent');
  assert.equal(custodyOf({ source: 'hold-proxy' }, { declared: 'subject-writable' }), 'subject-writable');
  assert.equal(custodyOf({ source: 'hold-proxy' }, { declared: 'observer-held' }), 'observer-held');
  assert.equal(custodyOf({ source: 'sql-audit-table' }, { declared: 'observer-held' }), 'subject-writable');
  assert.equal(custodyOf({ source: 'sql-audit-table' }, { declared: 'independent' }), 'subject-writable');
  assert.throws(() => custodyOf({ source: 'sql-audit-table' }, { declared: 'trustworthy' }), /Unknown custody/);
  assert.equal(custodyOf({ source: 'something-new' }), 'subject-writable');
});

test('only an observation that decided the verdict lends its independence', () => {
  const base = { operations: ['tool-call'], names: [GATE_RULE, 'ungated'], actorAttribution: 'none', evidence: 'authoritative' };
  assert.equal(decidesAbsence({ source: 'hold-proxy', coverage: 'complete', scope: base, events: [] }, SELECT), true);
  assert.equal(decidesAbsence({ source: 'hold-proxy', coverage: 'failed', scope: base, events: [] }, SELECT), false);
  assert.equal(decidesAbsence({ source: 'hold-proxy', coverage: 'partial', scope: base, events: [] }, SELECT), false);
  assert.equal(decidesAbsence({ source: 'hold-proxy', coverage: 'complete', scope: { ...base, evidence: 'presence-only' }, events: [] }, SELECT), false);
  assert.equal(decidesAbsence({ source: 'hold-proxy', coverage: 'complete', scope: { ...base, names: ['other'] }, events: [] }, SELECT), false);
  // Fail closed without a selector: we cannot show the window saw the effect.
  assert.equal(decidesAbsence({ source: 'hold-proxy', coverage: 'complete', scope: base, events: [] }, null), false);
});

// What a real gate window can and cannot decide. The shipped gate observer
// (integrations/sequences/gate.mjs:92) sees tool-calls only, names its own rule
// ids, and never attributes a principal. So the one independent source we have
// can decide the absence of a gated tool call, and nothing else.
test('a real gate window does not decide a database-name selector', () => {
  assert.equal(decidesAbsence(INDEPENDENT_WINDOW, SELECT), true, 'its own gated rule');
  assert.equal(decidesAbsence(INDEPENDENT_WINDOW, DB_SELECT), false, 'a table name it never sees');
  // So a database-shaped prohibition has no independent support, even with the
  // gate attached, and cannot reach a pass.
  const v = subjectIntegrityVerdict({ proposed: 'pass', select: DB_SELECT, support: [SUBJECT_LOG_WINDOW, INDEPENDENT_WINDOW] });
  assert.equal(v.verdict, 'inconclusive');
  assert.ok(v.reasons.includes('subject-writable-custody'), String(v.reasons));
});

test('a malformed support window degrades instead of throwing', () => {
  const malformed = [
    { source: 'hold-proxy', coverage: 'complete', scope: { evidence: 'authoritative' }, events: [] },  // no operations
    { source: 'hold-proxy', coverage: 'complete', scope: { operations: 'tool-call', evidence: 'authoritative' }, events: [] }, // operations not an array
    { source: 'hold-proxy', coverage: 'complete', events: [] },                                         // no scope
    null, undefined, 'window', 42,
  ];
  for (const w of malformed) {
    assert.equal(decidesAbsence(w, SELECT), false, JSON.stringify(w));
    const v = subjectIntegrityVerdict({ proposed: 'pass', select: SELECT, support: [w] });
    assert.equal(v.verdict, 'inconclusive', JSON.stringify(w));
    assert.ok(v.reasons.includes('subject-writable-custody'));
  }
});

// False passes that earlier versions of the rule allowed.
test('a non-deciding independent window cannot rescue a pass', () => {
  const v = subjectIntegrityVerdict({ proposed: 'pass', select: SELECT, support: [SUBJECT_LOG_WINDOW, FAILED_GATE] });
  assert.equal(v.verdict, 'inconclusive');
  assert.ok(v.reasons.includes('subject-writable-custody'), String(v.reasons));

  // A resealed tamper leaves no chain trace, so only custody can stop it. With a
  // non-deciding gate beside the subject's log, these are the false passes earlier versions allowed.
  for (const mode of ['spoof-principal', 'truncate-tail']) {
    const run = runForgingSubject(mode, { reseal: true });
    const decided = subjectIntegrityVerdict({ proposed: naiveVerdict(run), select: SELECT,
      support: [SUBJECT_LOG_WINDOW, FAILED_GATE], chain: { entries: run.entries, anchor: run.anchor } });
    assert.equal(decided.verdict, 'inconclusive', mode);
    assert.ok(decided.reasons.includes('subject-writable-custody'), mode);
  }
});

// The other side of the same rule: when an independent observer really did decide
// the absence, a pass is correct even though the subject's own log was tampered
// with. The verdict does not rest on the subject's records, which is the point.
test('a genuinely deciding independent observer supports a pass despite subject tampering', () => {
  const run = runForgingSubject('spoof-principal', { reseal: true });
  const decided = subjectIntegrityVerdict({ proposed: naiveVerdict(run), select: SELECT,
    support: [SUBJECT_LOG_WINDOW, INDEPENDENT_WINDOW], chain: { entries: run.entries, anchor: run.anchor } });
  assert.equal(decided.verdict, 'pass');
  assert.deepEqual([...decided.reasons], []);
});

test('an empty support list is never independent', () => {
  const v = subjectIntegrityVerdict({ proposed: 'pass', select: SELECT, support: [] });
  assert.equal(v.verdict, 'inconclusive');
  assert.ok(v.reasons.includes('subject-writable-custody'));
});

test('an unknown proposed verdict is rejected', () => {
  assert.throws(() => subjectIntegrityVerdict({ proposed: 'ok', select: SELECT, support: [] }), /Unknown proposed verdict/);
});

test('acceptance: a normal run verifies, and each tampering mode fails the chain', () => {
  const honest = runForgingSubject('honest');
  assert.deepEqual(verifyChain(honest.entries, honest.anchor), { ok: true, reasons: [] });
  for (const mode of TAMPERED) {
    const run = runForgingSubject(mode);
    const v = verifyChain(run.entries, run.anchor);
    assert.equal(v.ok, false, mode);
    assert.ok(v.reasons.includes('chain-head-mismatch'), `${mode}: ${v.reasons}`);
  }
});

test('the chain covers every entry field, not just the tail actor', () => {
  const honest = runForgingSubject('honest');
  const held = anchorOf(honest.entries);
  for (const field of ENTRY_FIELDS) {
    for (const index of [0, honest.entries.length - 1]) {
      const edited = honest.entries.map((e, i) => (i === index
        ? { ...e, [field]: typeof e[field] === 'number' ? e[field] + 1 : `${e[field]}-x` } : e));
      assert.ok(verifyChain(edited, held).reasons.includes('chain-head-mismatch'), `${field} at ${index} survived`);
    }
  }
});

test('a chain with no usable anchor is reported, never treated as agreement', () => {
  const run = runForgingSubject('truncate-tail');
  for (const anchor of [null, undefined, {}, { count: 'two', head: 'x' }]) {
    const v = verifyChain(run.entries, anchor);
    assert.equal(v.ok, false, String(anchor));
    assert.ok(v.reasons.includes('chain-unanchored'), String(anchor));
  }
  const decided = subjectIntegrityVerdict({ proposed: 'pass', select: SELECT,
    support: [INDEPENDENT_WINDOW], chain: { entries: run.entries, anchor: null } });
  assert.equal(decided.verdict, 'inconclusive');
  assert.ok(decided.reasons.includes('chain-unanchored'));
});

test('a malformed entry is broken, not ignored', () => {
  const honest = runForgingSubject('honest');
  for (const bad of [{}, { effectAtMs: 1, recordedAtMs: NaN }, { effectAtMs: NaN, recordedAtMs: 1 }, null, 'x']) {
    const entries = [...honest.entries, bad];
    assert.ok(verifyChain(entries, anchorOf(entries)).reasons.includes('chain-malformed'), JSON.stringify(bad));
  }
});

test('acceptance: with only the subject\'s own records, nothing reaches a pass', () => {
  const rows = runEvidSubjectCases({ support: [SUBJECT_LOG_WINDOW] });
  const summary = evidSubjectSummary(rows);
  assert.deepEqual(summary.passes, []);
  assert.deepEqual(summary.tamperedPasses, []);
  for (const r of rows) {
    assert.ok(r.reasons.includes('subject-writable-custody'), `${r.mode}: ${r.reasons}`);
    assert.notEqual(r.verdict, 'pass', r.mode);
  }
  assert.equal(rows.find(r => r.mode === 'honest').verdict, 'fail');
  // The naive rule passes most modes. That is what this check exists to stop.
  assert.ok(summary.naivePasses.length >= TAMPERED.length - 1, String(summary.naivePasses));
});

test('acceptance: with a deciding independent observer, the chain decides', () => {
  const rows = runEvidSubjectCases({ support: [INDEPENDENT_WINDOW] });
  assert.deepEqual(evidSubjectSummary(rows).tamperedPasses, []);
  const by = Object.fromEntries(rows.map(r => [r.mode, r]));
  assert.equal(by['honest'].verdict, 'fail');
  assert.deepEqual([...by['honest'].reasons], []);
  for (const mode of TAMPERED) {
    // Every tamper is reported; one that leaves the prohibited effect visible
    // stays a fail rather than being softened.
    assert.ok(by[mode].reasons.includes('chain-head-mismatch'), `${mode}: ${by[mode].reasons}`);
    assert.equal(by[mode].verdict, by[mode].naive === 'fail' ? 'fail' : 'inconclusive', mode);
  }
});

test('acceptance: a legitimately missing observation stays inconclusive, never a pass', () => {
  const run = runForgingSubject('missing-observation');
  assert.equal(naiveVerdict(run), 'pass');
  const decided = subjectIntegrityVerdict({ proposed: 'pass', select: SELECT, support: [INDEPENDENT_WINDOW], chain: null, missing: true });
  assert.equal(decided.verdict, 'inconclusive');
  assert.ok(decided.reasons.includes('observation-missing'));
});

test('an actor named only by the subject is a self-report, not a principal', () => {
  const actorSelect = { ...SELECT, actor: 'member' };
  const gateOnly = subjectIntegrityVerdict({ proposed: 'pass', select: actorSelect, support: [SUBJECT_LOG_WINDOW, INDEPENDENT_WINDOW] });
  assert.ok(gateOnly.reasons.includes('principal-unverified'), String(gateOnly.reasons));
  const named = subjectIntegrityVerdict({ proposed: 'pass', select: actorSelect, support: [INDEPENDENT_PRINCIPAL_WINDOW] });
  assert.ok(!named.reasons.includes('principal-unverified'), String(named.reasons));
  assert.equal(named.verdict, 'pass');
  assert.ok(!subjectIntegrityVerdict({ proposed: 'pass', select: SELECT, support: [INDEPENDENT_WINDOW] }).reasons.includes('principal-unverified'));
});

test('only a pass is degraded; every other verdict keeps its own meaning', () => {
  for (const support of [[SUBJECT_LOG_WINDOW], [INDEPENDENT_WINDOW], []]) {
    // A fail stays a fail whatever the custody or a missing observation.
    assert.equal(subjectIntegrityVerdict({ proposed: 'fail', select: SELECT, support, missing: true }).verdict, 'fail');
    // 'unobservable', 'observer-failure' and 'missing' each say something
    // different about why the check was not satisfied. Flattening them into
    // 'inconclusive' would discard that, so they pass through unchanged.
    for (const proposed of ['inconclusive', 'unobservable', 'observer-failure', 'missing']) {
      const v = subjectIntegrityVerdict({ proposed, select: SELECT, support, missing: true });
      assert.equal(v.verdict, proposed, `${proposed} with ${support.length} window(s)`);
      assert.notEqual(v.verdict, 'pass');
    }
    // A pass is the only verdict custody or the chain can take away.
    const degraded = subjectIntegrityVerdict({ proposed: 'pass', select: SELECT, support, missing: true });
    assert.equal(degraded.verdict, 'inconclusive');
  }
});

// A subject that recomputes the chain after tampering leaves records that verify
// among themselves. Truncation is not detectable from the chain
// alone. It is the case the externally held anchor exists for.
test('a resealed chain verifies on its own, so the external anchor is load-bearing', () => {
  const held = anchorOf(runForgingSubject('honest').entries);
  for (const mode of TAMPERED) {
    const run = runForgingSubject(mode, { reseal: true });
    assert.deepEqual(verifyChain(run.entries, run.anchor).reasons.filter(r => r === 'chain-head-mismatch'), [], mode);
    assert.ok(verifyChain(run.entries, held).reasons.includes('chain-head-mismatch'), mode);
  }
});

test('without an external anchor, a resealed truncation is caught only by custody', () => {
  // entry-after-effect is a reading over the subject's own timestamps.
  const forged = runForgingSubject('forge-authorize', { reseal: true });
  const forgedDecision = subjectIntegrityVerdict({ proposed: naiveVerdict(forged), select: SELECT,
    support: [INDEPENDENT_WINDOW], chain: { entries: forged.entries, anchor: forged.anchor } });
  assert.equal(forgedDecision.verdict, 'inconclusive');
  assert.ok(forgedDecision.reasons.includes('entry-after-effect'));

  // A resealed truncation leaves no trace in the chain at all.
  const cut = runForgingSubject('truncate-tail', { reseal: true });
  const chainOnly = subjectIntegrityVerdict({ proposed: naiveVerdict(cut), select: SELECT,
    support: [INDEPENDENT_WINDOW], chain: { entries: cut.entries, anchor: cut.anchor } });
  assert.equal(chainOnly.verdict, 'pass', 'documents the gap: the chain alone cannot see a resealed truncation');
  const withCustody = subjectIntegrityVerdict({ proposed: naiveVerdict(cut), select: SELECT,
    support: [SUBJECT_LOG_WINDOW], chain: { entries: cut.entries, anchor: cut.anchor } });
  assert.equal(withCustody.verdict, 'inconclusive');
  assert.ok(withCustody.reasons.includes('subject-writable-custody'));
});

// Mutation sweep. Each mutant removes exactly one guard and the sweep records
// which forgery modes newly reach a pass. Coarse mutations hid real gaps in the
// earlier control-tamper sweep, so each mutation isolates one guard.
const MUTANTS = [
  { id: 'no-anchor-check', find: 'if (entries.length !== anchor.count || head !== anchor.head) reasons.unshift(\'chain-head-mismatch\');',
    // forge-authorize is absent: entry-after-effect catches it independently,
    // because the fabricated entry was recorded after the effect it attests.
    replace: '', support: 'independent', expect: TAMPERED_NAIVE_PASS.filter(m => m !== 'forge-authorize') },
  { id: 'no-missing-check', find: "if (missing && !reasons.includes('observation-missing')) reasons.push('observation-missing');",
    replace: '', support: 'independent', expect: ['missing-observation'] },
  { id: 'no-custody-check', find: "if (deciding.length === 0 && !reasons.includes('subject-writable-custody')) reasons.push('subject-writable-custody');",
    replace: '', support: 'subject', expect: [] },
  { id: 'custody-over-all-windows',
    find: 'support.filter(w => decidesAbsence(w, select, kind) && INDEPENDENT_CUSTODY.includes(custodyOf(w, { declared: w?.declaredCustody ?? null })))',
    replace: 'support.filter(w => INDEPENDENT_CUSTODY.includes(custodyOf(w, { declared: w?.declaredCustody ?? null })))',
    support: 'subject-plus-failed-gate', expect: [] },
  { id: 'anchor-shape-unchecked', find: "if (!isObj(anchor) || !finite(anchor.count)) return { ok: false, reasons: ['chain-unanchored'] };",
    replace: '', support: 'independent', expect: [] },
];

test('mutation sweep: each guard is load-bearing for a named forgery mode', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-evid-subject-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  // The core lives in src/custody.mjs (./custody.mjs re-exports it), so the guards are mutated there.
  const core = new URL('../../src/custody.mjs', import.meta.url);
  const src = readFileSync(core, 'utf8');
  const supports = { independent: [INDEPENDENT_WINDOW], subject: [SUBJECT_LOG_WINDOW], 'subject-plus-failed-gate': [SUBJECT_LOG_WINDOW, FAILED_GATE] };
  const results = {};

  for (const m of MUTANTS) {
    assert.ok(src.includes(m.find), `mutant ${m.id} no longer matches the source`);
    const mutated = src.replace(m.find, m.replace)
      .replace(/from '(\.\/[a-z-]+\.mjs)'/g, (_, rel) => `from ${JSON.stringify(new URL(rel, core).href)}`);
    const file = join(dir, `custody-${m.id}.mjs`);
    await writeFile(file, mutated);
    const mod = await import(pathToFileURL(file).href);

    const newPasses = [];
    for (const mode of FORGERY_MODES) {
      const run = runForgingSubject(mode);
      const decided = mod.subjectIntegrityVerdict({ proposed: naiveVerdict(run), support: supports[m.support], select: SELECT,
        chain: run.missing ? null : { entries: run.entries, anchor: run.anchor }, missing: run.missing });
      if (decided.verdict === 'pass' && mode !== 'honest') newPasses.push(mode);
    }
    results[m.id] = newPasses;
    assert.deepEqual(newPasses.sort(), [...m.expect].sort(), `mutant ${m.id} let through: ${newPasses}`);
  }

  for (const m of MUTANTS.filter(x => x.expect.length)) assert.ok(results[m.id].length > 0, m.id);
  // Guards that let nothing through here are each the only remaining defence in
  // their own test above: custody in the resealed-truncation test, the deciding
  // filter and the anchor-shape check in their own cases.
  assert.deepEqual(results['no-custody-check'], []);
  assert.deepEqual(results['custody-over-all-windows'], []);
  assert.deepEqual(results['anchor-shape-unchecked'], []);
});
