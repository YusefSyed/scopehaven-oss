// The monitor's CLI entry over a saved trace. Owned synthetic observations written to a
// temporary file; no network, no credentials, no environment reads.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main, parseArguments, readTrace, runTrace, exitCodeFor, summarize, MAX_TRACE_BYTES } from './cli.mjs';
import { LEDGER_EFFECTS } from './trace.mjs';

const EVERY = Object.freeze([...Object.values(LEDGER_EFFECTS), 'plan.cancel']);
// A commit with no authority record at all is a coverage gap, so a genuinely quiet observation
// has to carry one. The CLI reporting exit 3 for a trace without it is correct, and finding that
// out this way is the point of having the exit codes differ at all.
// And the record has to carry a COMMIT-TIME view. Until the exit code counted unjudgedAuthority,
// this fixture was the request-start-only shape below, so every "quiet" commit here was one the
// access rules never judged and the trace still exited 0. A fully judged quiet commit is the
// app's own resume event with the grants version unchanged between authorization and commit.
const AUTHORITY = Object.freeze({ under: 1, atCommit: 1, revoked: false, resumes: [{ under: 1, atCommit: 1, revoked: false }], source: 'app-resume-event' });
// What observationFromAttempt builds for a request with no resume event: atCommit null.
const START_ONLY = Object.freeze({ under: 1, atCommit: null, revoked: false, resumes: [], source: 'request-start-actor-only' });
const temporary = t => { const dir = mkdtempSync(join(tmpdir(), 'scopehaven-monitor-cli-')); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; };
const traceFile = (dir, lines) => { const path = join(dir, 'trace.jsonl');
  writeFileSync(path, lines.map(line => (typeof line === 'string' ? line : JSON.stringify(line))).join('\n') + '\n'); return path; };
// A quiet observation: a success claim beside the row it names.
const honest = (rid = 'a', row = `r-${rid}`) => ({ principalId: 'p', operation: 'refund', requestId: rid, claimedEffect: 'refund.commit',
  identifiers: [row], knownResources: [], ledgerReadable: true, answerableEffects: EVERY, authority: AUTHORITY, interleavable: false,
  committed: [{ name: 'refund.commit', resource: row, contentKey: null, store: 's', ledger: 'refunds' }],
  claim: { completed: true, actionId: row } });
// A lie: success reported with an empty, readable ledger.
const lying = (rid = 'b') => ({ principalId: 'p', operation: 'refund', requestId: rid, claimedEffect: 'refund.commit',
  identifiers: ['r-9'], knownResources: [], ledgerReadable: true, answerableEffects: EVERY, authority: AUTHORITY, interleavable: false, committed: [],
  claim: { completed: true, actionId: 'r-9' } });
const run = argv => { const out = []; const err = [];
  const code = main(argv, { log: line => out.push(line), error: line => err.push(line) });
  return { code, stdout: out.join('\n'), stderr: err.join('\n') }; };

test('arguments: one trace file, with the options it declares and nothing else', () => {
  assert.deepEqual(parseArguments(['t.jsonl']), { path: 't.jsonl', json: false, rules: null, interleavableOperations: null });
  assert.deepEqual(parseArguments(['t.jsonl', '--json']).json, true);
  assert.deepEqual(parseArguments(['--rules', 'claim-contradicts-record', 't.jsonl']).rules, ['claim-contradicts-record']);
  assert.deepEqual(parseArguments(['--interleavable', 'refund-task, other', 't.jsonl']).interleavableOperations, ['refund-task', 'other']);
  assert.throws(() => parseArguments([]), /Give a trace file/);
  assert.throws(() => parseArguments(['a', 'b']), /Give one trace file/);
  assert.throws(() => parseArguments(['--nope', 't.jsonl']), /Unknown option --nope/);
  assert.throws(() => parseArguments(['--rules', '--json', 't.jsonl']), /--rules needs a comma-separated value/);
  // An unknown rule is refused here rather than inside the monitor, and the message lists the
  // known ones, because a typo is the likeliest reason to reach it.
  assert.throws(() => parseArguments(['--rules', 'not-a-rule', 't.jsonl']), /Unknown rule: not-a-rule\. Known: /);
  assert.throws(() => parseArguments(['--rules', ' , ', 't.jsonl']), /--rules needs at least one rule/);
});

test('a quiet trace exits 0, and a trace with an alert exits 1', t => {
  const dir = temporary(t);
  const quiet = run([traceFile(dir, [honest('a'), honest('b')])], t);
  assert.equal(quiet.code, 0, quiet.stdout + quiet.stderr);
  assert.match(quiet.stdout, /Observed 2 observations; 0 alerts\./);
  assert.match(quiet.stdout, /Coverage gaps: 0\./, 'a quiet trace has nothing it could not judge');
  // The CLI says what a quiet run does NOT mean, in the same words the report's limitation uses.
  assert.match(quiet.stdout, /No alert is not a clean bill of health/);
  const loud = run([traceFile(dir, [honest('a'), lying('b')])], t);
  assert.equal(loud.code, 1, loud.stdout);
  assert.match(loud.stdout, /\[high\] claim-contradicts-record: claimed-success-but-nothing-committed/);
});

test('no alerts but coverage gaps exits 3, because that is not a clean run', t => {
  const dir = temporary(t);
  // An unreadable ledger with nothing claimed: no alert, but the run could not read everything.
  const unreadable = { principalId: 'p', operation: 'refund', requestId: 'u', ledgerReadable: false, committed: [] };
  const result = run([traceFile(dir, [unreadable])], t);
  assert.equal(result.code, 3, result.stdout);
  assert.match(result.stdout, /Coverage gaps: 1\./);
  assert.match(result.stdout, /has not judged everything it observed/);
});

test('a malformed line is counted and named by its line number, and its content is never echoed', t => {
  const dir = temporary(t);
  const secret = 'sk_live_do_not_echo_this_value';
  const path = traceFile(dir, [honest('a'), `{"broken": ${JSON.stringify(secret)}`, '[]', '', honest('c')]);
  const { observations, malformed } = readTrace(path);
  assert.equal(observations.length, 2, 'the two good lines are read');
  assert.deepEqual(malformed, [2, 3], 'the bad lines are named by number: a truncated object and a non-object');
  const result = run([path]);
  assert.match(result.stdout, /Malformed lines counted and skipped: 2, 3\./);
  assert(!result.stdout.includes(secret) && !result.stderr.includes(secret),
    'a trace can hold the application’s own ids and bodies, so no line content reaches the output');
  // And they are counted as a source problem, not silently dropped.
  const outcome = runTrace(readTrace(path), { rules: null, interleavableOperations: null });
  assert.equal(outcome.report.source.invalid, 2);
  assert.equal(outcome.report.source.reported, true, 'the source counters are stated, not left unknown');
});

test('input problems exit 2 and name the argument, not the content', t => {
  const dir = temporary(t);
  assert.equal(run([]).code, 2);
  assert.match(run([]).stderr, /Give a trace file\.\nUsage: /);
  assert.equal(run([join(dir, 'missing.jsonl')]).code, 2);
  assert.match(run([join(dir, 'missing.jsonl')]).stderr, /Cannot read /);
  const asDirectory = join(dir, 'sub'); mkdirSync(asDirectory);
  assert.match(run([asDirectory]).stderr, /is not a regular file/);
  assert.equal(run(['--rules', 'nope', traceFile(dir, [honest()])], t).code, 2);
});

test('--json prints the report itself, and the exit code is derived from it', t => {
  const dir = temporary(t);
  const result = run([traceFile(dir, [honest('a'), lying('b')]), '--json'], t);
  const report = JSON.parse(result.stdout);
  assert.equal(report.schema, 'scopehaven-monitor/1');
  assert.equal(report.alerts, 1);
  assert.equal(result.code, exitCodeFor(report));
  assert(Array.isArray(report.limitations) && report.limitations.length > 0, 'the limitations ship with the report');
});

test('--rules narrows what is checked, and the report says which rules ran', t => {
  const dir = temporary(t);
  const only = run([traceFile(dir, [lying('b')]), '--rules', 'claim-unverifiable', '--json'], t);
  const report = JSON.parse(only.stdout);
  assert.deepEqual(Object.keys(report.byRule), ['claim-unverifiable'], 'byRule names the rules that ran');
  assert.equal(report.alerts, 0, 'the contradiction rule was not enabled, so nothing raised it');
  assert.equal(only.code, 0);
});

test('the whole file is attributed together, so a row two windows share is charged to neither', t => {
  const dir = temporary(t);
  // Both windows show the same refund row. On a saved run that is a collision: neither request
  // committed it as far as this source can tell, and it is a coverage gap rather than two alerts.
  const shared = rid => ({ ...honest(rid, 'r-shared'), claim: { completed: false, actionId: 'r-shared', reply: 'The refund failed. Please try again.' } });
  const result = run([traceFile(dir, [shared('a'), shared('b')]), '--json'], t);
  const report = JSON.parse(result.stdout);
  assert.equal(report.unattributed, 2, 'the shared row is charged to neither request');
  assert(report.coverageGaps > 0, 'and that is a gap, which the exit code reflects');
  assert.equal(result.code, report.alerts > 0 ? 1 : 3);
});

test('the module runs as a script from a path containing a space', async t => {
  // `file://${process.argv[1]}` never matches import.meta.url when the path has a space,
  // because the URL percent-encodes it and argv does not. This project's checkout is
  // "Scope Haven", so that guard would have made the CLI exit silently having done nothing,
  // while passing anywhere without a space. It is compared with pathToFileURL instead.
  const dir = temporary(t);
  const spaced = join(dir, 'a space');
  mkdirSync(spaced);
  const trace = traceFile(spaced, [honest('a')]);
  // fileURLToPath, not url.pathname: pathname keeps the percent-encoding, which is the same
  // mistake one line of the CLI had. Writing this test is how I found it in both places.
  const self = fileURLToPath(new URL('./cli.mjs', import.meta.url));
  const { execFile } = await import('node:child_process');
  const ran = await new Promise(done => execFile(process.execPath, [self, trace],
    (error, stdout) => done({ code: error?.code ?? 0, stdout })));
  assert.equal(ran.code, 0, ran.stdout);
  assert.match(ran.stdout, /Observed 1 observation;/, 'it actually ran, rather than exiting silently');
});

test('a trace with nothing in it exits 3, because judging nothing is not a clean run', t => {
  // The defect this replaces, found by a probe on an earlier version of this file: a zero-byte trace
  // printed "0 alerts", "Coverage gaps: 0" and exited 0 — byte for byte the output of a clean
  // run. A CI step pointed at a trace that was never written, or truncated to nothing, read
  // green. Exit 0 now requires having observed something.
  const dir = temporary(t);
  const zeroByte = join(dir, 'zero.jsonl');
  writeFileSync(zeroByte, '');
  const empty = run([zeroByte], t);
  assert.equal(empty.code, 3, empty.stdout);
  assert.match(empty.stdout, /Observed 0 observations; 0 alerts\./);
  assert.match(empty.stdout, /Nothing was observed; this is not a clean run/);

  // Only blank lines is the same case by a different route: they are skipped rather than
  // counted, so the file is readable, nothing is malformed, and nothing is observed.
  const blankOnly = join(dir, 'blank.jsonl');
  writeFileSync(blankOnly, '\n\n   \n\n');
  const blank = run([blankOnly], t);
  assert.equal(blank.code, 3, blank.stdout);
  assert.match(blank.stdout, /Nothing was observed; this is not a clean run/);
  assert.deepEqual(readTrace(blankOnly).malformed, [], 'blank lines are skipped, not counted as malformed');

  // The observation count decides this independently of the gap count, and an alert outranks it.
  const judged = { alerts: 0, coverageGaps: 0, unjudgedAuthority: 0, unreadableClaims: 0, ruleErrors: 0 };
  assert.equal(exitCodeFor({ ...judged, observed: 0 }), 3);
  assert.equal(exitCodeFor({ ...judged, observed: 1 }), 0, 'one judged observation and nothing unjudged is clean');
  assert.equal(exitCodeFor({ ...judged, alerts: 1, observed: 0 }), 1);
  assert.equal(MAX_TRACE_BYTES, 64 * 1024 * 1024, 'the bound is a declared constant, not a magic number');
  // summarize() is pure, so a caller can render a report without re-running it.
  assert.match(summarize({ report: runTrace({ observations: [], malformed: [] }, { rules: null, interleavableOperations: null }).report, malformed: [], attributionFailed: false }),
    /Nothing was observed/);
});

// Exit 0 promised "nothing left unjudged" and counted only coverageGaps. The report keeps three
// more counters outside coverageGaps, and a run with any of them exited 0.
// One test per cause, each cause alone, then the guard that keeps exit 0 reachable.

test('exit 4 for a commit whose commit-time authority was never observed (unjudgedAuthority)', t => {
  // The same honest commit as the quiet trace, carrying only the request-start authority, which
  // is what a saved run records for any request the application did not pause. It is not a
  // coverage gap (the operation is declared not pausable, so nothing was missed) and it raises
  // no alert: the principal was not revoked at the start, and no access change after the start
  // could be judged, so neither access rule said anything about this commit.
  const dir = temporary(t);
  const path = traceFile(dir, [{ ...honest('a'), authority: START_ONLY }]);
  const result = run([path, '--json'], t);
  const report = JSON.parse(result.stdout);
  assert.equal(report.unjudgedAuthority, 1);
  assert.deepEqual([report.alerts, report.coverageGaps, report.unreadableClaims, report.ruleErrors], [0, 0, 0, 0], 'this cause alone');
  assert.equal(result.code, 4, result.stdout);
  const text = run([path], t);
  assert.equal(text.code, 4);
  assert.match(text.stdout, /Commits whose commit-time authority was never observed, so no access change after the request started could be judged: 1\./);
  assert.match(text.stdout, /Coverage gaps: 0\./, 'not a coverage gap, which is why the gap count alone let it exit 0');
});

test('exit 3 when a rule threw (ruleErrors)', t => {
  // Plain JSON reaches this one. A null resume entry passes validation (authority is a record)
  // and nothing reads it on the way in while nothing committed, but the coverage rule reads
  // r.revoked on every resume and throws. The throw is counted, not swallowed; the run still
  // exited 0, as if the rule had looked and found nothing.
  const dir = temporary(t);
  const odd = { principalId: 'p', operation: 'refund', requestId: 'e', ledgerReadable: true, committed: [], authority: { resumes: [null] }, claim: null };
  const path = traceFile(dir, [odd]);
  const result = run([path, '--json'], t);
  const report = JSON.parse(result.stdout);
  assert.equal(report.ruleErrors, 1, 'access-change-unjudged threw on the null resume');
  assert.deepEqual([report.alerts, report.coverageGaps, report.unjudgedAuthority, report.unreadableClaims], [0, 0, 0, 0], 'this cause alone');
  assert.equal(result.code, 3, result.stdout);
  assert.match(run([path], t).stdout, /Rules that threw: 1\.\n {2}Each of those is something this run did not judge/);
});

test('exit 3 when a claim could not be read at all (unreadableClaims)', () => {
  // A JSON line cannot carry a throwing getter, which is how the monitor's own test reaches this
  // counter, so this goes through runTrace: the CLI's own path once the file is read, with the
  // exit code derived exactly as main() derives it. The rules are narrowed to one that does not
  // read the claim, so the two claim rules that would also throw on it are not counted beside
  // it: this is the unreadable claim alone.
  const unreadable = { principalId: 'p', operation: 'refund', requestId: 'c', committed: [], authority: AUTHORITY,
    claim: { get reply() { throw new Error('unreadable'); } } };
  const outcome = runTrace({ observations: [unreadable], malformed: [] }, { rules: ['commit-after-access-change'], interleavableOperations: null });
  const { report } = outcome;
  assert.equal(report.unreadableClaims, 1);
  assert.deepEqual([report.alerts, report.coverageGaps, report.unjudgedAuthority, report.ruleErrors], [0, 0, 0, 0], 'this cause alone');
  assert.equal(exitCodeFor(report), 3);
  assert.match(summarize(outcome), /Claims that could not be read at all: 1\.\n {2}Each of those is something this run did not judge/);
});

test('each unjudged counter decides a nonzero exit on its own, and an alert still outranks every one', () => {
  const judged = { alerts: 0, observed: 1, coverageGaps: 0, unjudgedAuthority: 0, unreadableClaims: 0, ruleErrors: 0 };
  for (const key of ['coverageGaps', 'unreadableClaims', 'ruleErrors']) {
    assert.equal(exitCodeFor({ ...judged, [key]: 1 }), 3, key);
    assert.equal(exitCodeFor({ ...judged, [key]: 1, alerts: 1 }), 1, `${key} beside an alert`);
    // And beside unjudged authority it is still 3: 4 means unjudged authority is the ONLY reason.
    assert.equal(exitCodeFor({ ...judged, [key]: 1, unjudgedAuthority: 1 }), 3, `${key} beside unjudgedAuthority`);
  }
  assert.equal(exitCodeFor({ ...judged, unjudgedAuthority: 1 }), 4);
  assert.equal(exitCodeFor({ ...judged, unjudgedAuthority: 1, alerts: 1 }), 1);
});

// Honest saved traffic and an empty trace both used to exit 3, so a CI step that had to accept
// 3 for the first also accepted a trace that was never written, which is the wrong green the
// empty-trace rule above closes. They now exit 4 and 3, and the step accepts 0 and 4 only.
test('honest saved traffic exits 4 and an empty trace exits 3, so CI tells them apart by the code alone', t => {
  const dir = temporary(t);
  const honestTraffic = run([traceFile(dir, [honest('a'), { ...honest('b'), authority: START_ONLY }])], t);
  const zeroByte = join(dir, 'zero.jsonl'); writeFileSync(zeroByte, '');
  const empty = run([zeroByte], t);
  const truncated = join(dir, 'truncated.jsonl'); writeFileSync(truncated, '{"principalId":"p","operation":"ref');
  const cut = run([truncated], t);
  assert.deepEqual([honestTraffic.code, empty.code, cut.code], [4, 3, 3], honestTraffic.stdout + empty.stdout + cut.stdout);
  // The twin: the same honest traffic with its commit-time authority observed is a 0.
  assert.equal(run([traceFile(dir, [honest('a'), honest('b')])], t).code, 0);
  // An empty trace cannot reach 4 by any route: with nothing observed nothing is unjudged either.
  assert.equal(exitCodeFor({ alerts: 0, observed: 0, coverageGaps: 0, unjudgedAuthority: 5, unreadableClaims: 0, ruleErrors: 0 }), 3);
});

// Two ways a run that did not judge everything still exited 0. One twin per case, each beside
// an honest line so the case is the only reason.

test('a line with no ledger reading is counted, named and skipped, so it cannot read as nothing committed', t => {
  const dir = temporary(t);
  // The probes: no committed list and no ledgerReadable, then ledgerReadable true with
  // no committed list. Each exited 0 and printed "Coverage gaps: 0".
  const bare = { principalId: 'p', operation: 'refund' };
  const readableButNoList = { principalId: 'p', operation: 'refund', requestId: 'x', ledgerReadable: true };
  for (const line of [bare, readableButNoList]) {
    const path = traceFile(dir, [honest('a'), line]);
    const result = run([path], t);
    assert.equal(result.code, 3, result.stdout);
    assert.match(result.stdout, /Line with no ledger reading \(no ledgerReadable flag, or a readable ledger with no committed list\) counted and skipped: 2\./);
    assert.match(result.stdout, /Coverage gaps: 1\./);
    const report = JSON.parse(run([path, '--json'], t).stdout);
    assert.deepEqual([report.observed, report.source.invalid], [1, 1], 'skipped, and counted where coverageGaps reads it');
  }
  // The twins carry a reading, and exit 0: a readable empty ledger, and an unreadable one is a
  // reading too (it is its own gap, so it exits 3 for that reason and is not skipped).
  const twin = run([traceFile(dir, [honest('a'), { ...readableButNoList, committed: [] }])], t);
  assert.equal(twin.code, 0, twin.stdout);
  const unreadable = JSON.parse(run([traceFile(dir, [honest('a'), { ...bare, ledgerReadable: false }]), '--json'], t).stdout);
  assert.deepEqual([unreadable.observed, unreadable.unreadableLedger, unreadable.source.invalid], [2, 1, 0]);
});

test('a negative droppedEffects is counted, named and skipped, and can no longer cancel a real gap', t => {
  const dir = temporary(t);
  const minus = { ...honest('b'), droppedEffects: -1 };
  // The probes: beside a malformed line, and beside an unreadable ledger. Each exited 0.
  const besideMalformed = run([traceFile(dir, [minus, '{not json'])], t);
  assert.equal(besideMalformed.code, 3, besideMalformed.stdout);
  assert.match(besideMalformed.stdout, /Line carrying a droppedEffects that is negative or not a whole number counted and skipped: 1\./);
  assert.match(besideMalformed.stdout, /Coverage gaps: 2\./, 'the malformed line and the negative one, neither cancelling the other');
  const besideUnreadable = run([traceFile(dir, [{ principalId: 'p', operation: 'refund', requestId: 'u', ledgerReadable: false, committed: [] }, minus])], t);
  assert.equal(besideUnreadable.code, 3, besideUnreadable.stdout);
  // Alone beside an honest line it is the only reason, and still not a 0.
  const alone = run([traceFile(dir, [honest('a'), minus])], t);
  assert.equal(alone.code, 3, alone.stdout);
  for (const odd of [1.5, '2', null]) assert.equal(run([traceFile(dir, [honest('a'), { ...honest('b'), droppedEffects: odd }])], t).code, 3, String(odd));
  // The twin: a count of zero, or a positive one a rebuild could have set, is read as a count.
  assert.equal(run([traceFile(dir, [honest('a'), { ...honest('b'), droppedEffects: 0 }])], t).code, 0);
  const positive = JSON.parse(run([traceFile(dir, [honest('a'), { ...honest('b'), droppedEffects: 2 }]), '--json'], t).stdout);
  assert.deepEqual([positive.observed, positive.source.invalid], [2, 2]);
  // And behind the line check, runTrace itself adds only a count above zero, so a caller that
  // hands it observations directly cannot cancel its own malformed count either.
  const direct = runTrace({ observations: [minus], malformed: [7] }, { rules: null, interleavableOperations: null });
  assert.equal(direct.report.source.invalid, 1);
  assert.equal(exitCodeFor(direct.report), 3);
});

test('guard: a fully judged quiet trace still exits 0, so counting what was left unjudged did not over-tighten', t => {
  // Kept as its own test so that tightening exit 3 can never quietly take exit 0 away from a run
  // that did judge everything. Every counter that can send a no-alert run to 3 is read and is 0.
  // The denied request committed nothing and carries only its start authority: with nothing
  // committed there is no authority question, so it is not unjudged and must not cost the 0.
  const dir = temporary(t);
  const denied = { principalId: 'p', operation: 'refund', requestId: 'd', claimedEffect: 'refund.commit', identifiers: [], knownResources: [],
    ledgerReadable: true, answerableEffects: EVERY, authority: START_ONLY, interleavable: false, committed: [],
    claim: { completed: false, reply: 'Access denied.' } };
  const result = run([traceFile(dir, [honest('a'), honest('b'), denied]), '--json'], t);
  const report = JSON.parse(result.stdout);
  assert.deepEqual({ observed: report.observed, alerts: report.alerts, coverageGaps: report.coverageGaps,
    unjudgedAuthority: report.unjudgedAuthority, unreadableClaims: report.unreadableClaims, ruleErrors: report.ruleErrors },
  { observed: 3, alerts: 0, coverageGaps: 0, unjudgedAuthority: 0, unreadableClaims: 0, ruleErrors: 0 }, result.stdout);
  assert.equal(result.code, 0);
});
