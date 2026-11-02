// EVID-BOUNDS and PAIR verdicts. Owned synthetic fixture, its two degenerate
// builds (test/self-check-builds.mjs) and a loopback notes app; no model, provider
// or customer system. Presentation only: nothing here changes a verdict.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { runAssessment, compareRuns } from '../../src/runner.mjs';
import { runHttpAssessment, HTTP_LIMITS } from '../../src/http-connector.mjs';
import { createDegenerateFixture } from '../../test/self-check-builds.mjs';
import { evidenceBounds, boundsLines, degenerateBaselines, comparisonSupport, supportDecision, sideBounds, SUITE_PAIRS, UNDECIDED, PAIR_VERDICTS, BOUNDS_NOTE } from './bounds.mjs';
import { contractView } from '../../src/contract-views.mjs';
import { recomputeHttpRow } from '../../src/contract-http.mjs';
import { validateHttpRunEvidence } from '../../src/contracts.mjs';
import { createRegistry } from '../../src/registry.mjs';
import { digest } from '../../src/domain.mjs';
import { validateRun } from '../regression-gate/gate.mjs';

let vulnerable, repaired, doNothing, dumpEverything;
test.before(async () => {
  vulnerable = await runAssessment('demo-vulnerable'); repaired = await runAssessment('demo-repaired');
  [doNothing, dumpEverything] = await Promise.all(['do-nothing', 'dump-everything'].map(mode => runAssessment('demo-vulnerable', { fixtureFactory: build => createDegenerateFixture(mode, build) })));
});
const NO_OVERCLAIM = /\b(secure|certif|safe|guarantee)/i;
// The suite each target exports, as the gate reads it ("supported" needs it).
const suiteOf = (id, profiles = []) => createRegistry({ profiles, env: {} }).exportSuite(id);
const SYNTH = { expectedSuite: suiteOf('demo-repaired') };

test('the suite pairs are exactly the self-check pairs (read from the test file\'s text, not imported)', () => {
  const text = readFileSync(new URL('../../test/self-check.test.mjs', import.meta.url), 'utf8');
  const block = text.slice(text.indexOf('export const SELF_CHECK_PAIRS'), text.indexOf(']);', text.indexOf('export const SELF_CHECK_PAIRS')));
  const declared = [...block.matchAll(/\['([A-Z0-9-]+)', '([A-Z0-9-]+)'\]/g)].map(m => [m[1], m[2]]);
  assert.equal(declared.length, 26);
  assert.deepEqual(SUITE_PAIRS.map(p => [...p]), declared);
});

test('reference builds: the repaired build holds every pair usefully; the vulnerable build violates every pair', () => {
  const r = evidenceBounds(repaired), v = evidenceBounds(vulnerable);
  assert.deepEqual([r.forbidden.n, r.forbidden.lower, r.forbidden.upper, r.allowed.lower], [26, 1, 1, 1]);
  assert.deepEqual(r.pairs.counts, { 'held-and-useful': 26, 'held-by-inaction': 0, violated: 0, undecided: 0 });
  assert.deepEqual([v.forbidden.lower, v.forbidden.upper, v.allowed.lower], [0, 0, 1]);
  assert.deepEqual(v.pairs.counts, { 'held-and-useful': 0, 'held-by-inaction': 0, violated: 26, undecided: 0 });
  for (const b of [r, v]) for (const line of boundsLines(b)) assert.doesNotMatch(line, NO_OVERCLAIM);
});

test('a build that refuses everything is reported as held only by refusal, never as secure, and its undecided share is shown', () => {
  const b = evidenceBounds(doNothing);
  assert.deepEqual([b.allowed.n, b.allowed.pass], [18, 0]);
  assert.equal(b.pairs.counts['held-and-useful'], 0);
  assert.ok(b.pairs.counts['held-by-inaction'] > 0);
  const lines = boundsLines(b).join('\n');
  assert.match(lines, /Pairs: held only by refusal: 0% of allowed actions still work; 0 of 26 held with their allowed action working; 8 held only by inaction; 16 violated; 2 undecided\./);
  assert.match(lines, /Allowed actions that still work: 0% to 0% of 18/);
  assert.match(lines, /2 undecided: 2 not-exercised/);
  assert.doesNotMatch(lines, NO_OVERCLAIM);
  // The degenerate-baseline line: what trivially bad builds score on the same rows.
  const base = degenerateBaselines({ 'do-nothing': doNothing, 'dump-everything': dumpEverything });
  assert.deepEqual(base['do-nothing'].allowed, [0, 0]);
  assert.equal(base['do-nothing'].pairs['held-and-useful'], 0);
  assert.equal(base['dump-everything'].pairs['held-and-useful'], 0, 'neither degenerate build holds a pair usefully');
  assert.ok(base['dump-everything'].allowed[0] > 0.5, 'the permissive build keeps most allowed actions working');
});

test('a stored pass the evidence does not support is counted from the recomputed contract, not the stored status', () => {
  // An evaluator that mapped a missing snapshot to pass: the row says pass, the snapshot is gone.
  const gap = structuredClone(repaired);
  const row = gap.results.find(r => r.id === 'ROLE-01'); delete row.attempts.at(-1).evidence.after;
  assert.equal(row.status, 'pass', 'the stored verdict still claims pass');
  const b = evidenceBounds(gap);
  assert.equal(b.forbidden.pass, 25); assert.ok(b.forbidden.lower < 1);
  assert.notEqual(b.pairs.rows.find(p => p.forbidden === 'ROLE-01').verdict, 'held-and-useful');
});

test('comparison support: a change counts only when the candidate\'s lower bound clears the baseline\'s upper bound', () => {
  const up = comparisonSupport(vulnerable, repaired, SYNTH);
  assert.deepEqual([up.label, up.supported, up.before, up.after, up.candidateControls], ['supported', true, [0, 0], [1, 1], [1, 1]]);
  const same = comparisonSupport(repaired, repaired, SYNTH);
  assert.deepEqual([same.label, same.reason], ['?', 'the bounds overlap, so the evidence does not separate the runs']);
  // checkIds narrows the forbidden side: one check still separates, a control-only list leaves nothing to compare.
  const one = comparisonSupport(vulnerable, repaired, { ...SYNTH, checkIds: ['TENANT-01'] });
  assert.deepEqual([one.after, one.label, one.compared], [[1, 1], 'supported', ['TENANT-01']], 'the compared ids are echoed');
  // A control in checkIds is refused: every control always counts.
  assert.throws(() => comparisonSupport(vulnerable, repaired, { ...SYNTH, checkIds: ['TENANT-01', 'ALLOWED-01'] }), /names an allowed-use control/);
  // Without the expected suite nothing is supported: the bounds are still shown.
  const bare = comparisonSupport(vulnerable, repaired);
  assert.deepEqual([bare.label, bare.supported, bare.suiteChecked, bare.before, bare.after], ['?', false, false, [0, 0], [1, 1]]);
  assert.equal(bare.reason, 'no expected suite was given, so an edit made consistent in both stored runs cannot be ruled out');
});

test('neither degenerate build compares as supported, although both clear the vulnerable build\'s upper bound', () => {
  for (const [build, run, passed] of [['do-nothing', doNothing, 0], ['dump-everything', dumpEverything, 13]]) {
    const s = comparisonSupport(vulnerable, run, SYNTH);
    assert.ok(s.after[0] > s.before[1], `${build}: the forbidden bounds alone would separate`);
    assert.deepEqual([s.label, s.supported], ['?', false], build);
    assert.equal(s.reason, `only ${passed} of 18 allowed-use controls passed in the candidate, so the change may be a refusal`);
  }
});

test('the support decision refuses a candidate without allowed-use controls', () => {
  const side = (pass, n) => sideBounds([...Array(pass).fill({ verdict: 'pass' }), ...Array(n - pass).fill({ verdict: 'fail' })]);
  assert.equal(supportDecision({ before: side(0, 4), after: side(4, 4), controls: side(2, 2) }).supported, true);
  assert.deepEqual(supportDecision({ before: side(0, 4), after: side(4, 4), controls: side(0, 0) }),
    { supported: false, reason: 'the candidate has no allowed-use control, so a refusal cannot be told apart from a repair' });
  assert.equal(supportDecision({ before: side(1, 4), after: side(1, 4), controls: side(2, 2) }).supported, false, 'equal bounds do not separate');
  // Before [0.25, 0.75] (two undecided), after [0.5, 0.5]: the candidate's upper end is above the baseline's
  // lower end, but its lower end is not above the baseline's upper end, so nothing is separated.
  const wide = sideBounds([{ verdict: 'pass' }, { verdict: 'fail' }, { verdict: 'missing' }, { verdict: 'unobservable' }]);
  assert.deepEqual([wide.lower, wide.upper], [0.25, 0.75]);
  assert.deepEqual(supportDecision({ before: wide, after: side(2, 4), controls: side(2, 2) }), { supported: false, reason: 'the bounds overlap, so the evidence does not separate the runs' });
});

// A notes app run with the observers off: every effect check is undecided.
const TOKEN = 'synthetic-member-token', env = { SCOPEHAVEN_TARGET_MEMBER: TOKEN };
async function observersOffRun(t, { limits = HTTP_LIMITS, requiredControlIds = ['WHOAMI', 'OWN-NOTE'] } = {}) {
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const json = (s, b) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(b)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, {});
    if (req.url === '/me') return json(200, { user: 'member-1' });
    if (req.url === '/notes') return json(201, { id: 'n1' });
    return json(403, {});
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const profile = ({ id: 'notes', name: 'Notes app', applicationId: 'notes-app', origin: `http://127.0.0.1:${server.address().port}`, buildLabel: 'b1', contextId: 'synthetic-notes',
    actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' } }, requiredControlIds, observers: [],
    checks: [
      { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] },
      { id: 'OWN-NOTE', title: 'A member can create a note', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response',
        assertions: [{ kind: 'status.equals', expected: 201 }], effects: [{ kind: 'effect.exists', select: { source: 'sql-audit-table', actor: 'member-1', name: 'note.create' } }] },
      { id: 'OTHER-NOTE', title: "A member cannot edit another user's note", category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/notes/n-other/edit', body: {}, evidenceRequirement: 'backend',
        assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: { source: 'sql-audit-table', actor: 'member-1', name: 'note.update' } }] },
      { id: 'OTHER-DELETE', title: "A member cannot delete another user's note", category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/notes/n-other/delete', body: {}, evidenceRequirement: 'backend',
        assertions: [{ kind: 'status.equals', expected: 403 }], effects: [{ kind: 'effect.none', select: { source: 'sql-audit-table', actor: 'member-1', name: 'note.delete' } }] },
    ] });
  const run = await runHttpAssessment(profile, { env, limits });
  OFF_PROFILES.set(run, profile);
  return run;
}
// The profile each observers-off run was made from, so a test can take its exported suite.
const OFF_PROFILES = new WeakMap();

// A response-only notes app: secure answers 403 to the forbidden writes, leaky answers
// 200, hang-delete never answers the delete, reset-delete drops the connection on it, hang-all
// never answers either forbidden write. controlEffect gives OWN-NOTE an effect no observer can see,
// so the control reads undecided. One server per test, its mode switched between runs, so the
// runs share an origin and are comparable (as a baseline and a candidate of one app are).
async function notesServer(t) {
  let mode = 'secure';
  const server = createServer((req, res) => { req.resume(); req.on('end', () => {
    const json = (s, b) => { res.writeHead(s, { 'Content-Type': 'application/json', Connection: 'close' }); res.end(JSON.stringify(b)); };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, {});
    if (req.url === '/me') return json(200, { user: 'member-1' });
    if (req.url === '/notes') return json(201, { id: 'n1' });
    if (req.url === '/notes/mine') return json(200, { items: [] });
    const write = req.url.startsWith('/notes/n-other/');
    if (write && (mode === 'hang-all' || (mode === 'hang-delete' && req.url.endsWith('/delete')))) return;
    if (write && mode === 'reset-delete' && req.url.endsWith('/delete')) { res.writeHead(403, { 'Content-Type': 'application/json' }); res.write('{"err'); req.socket.destroy(); return; }
    // leaky-delete: the edit is refused and the delete leaks (a half-repaired build).
    return json(mode === 'leaky' || (mode === 'leaky-delete' && req.url.endsWith('/delete')) ? 200 : 403, {});
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return { origin: `http://127.0.0.1:${server.address().port}`, set: next => { mode = next; } };
}
// MY-NOTES is the member's surface control (a required GET on a protected route, actor-identity/4): its 403s count as refusals only after it.
const responseProfile = (origin, { controlEffect = false, applicationId = 'notes-app' } = {}) => {
  const forbidden = (id, path) => ({ id, title: id, category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path, body: {}, timeoutMs: 1000, evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }] });
  return { id: 'notes-response', name: 'Notes app', applicationId, origin, buildLabel: 'b1', contextId: 'synthetic-notes',
    actors: { member: { principalId: 'member-1', credentialEnv: 'SCOPEHAVEN_TARGET_MEMBER', identityValue: 'member-1' } }, requiredControlIds: ['WHOAMI', 'MY-NOTES', 'OWN-NOTE'], observers: [],
    checks: [
      { id: 'WHOAMI', title: 'Who am I', category: 'identity', severity: 'control', actorId: 'member', method: 'GET', path: '/me', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/user', expected: 'member-1' }] },
      { id: 'MY-NOTES', title: 'A member lists own notes', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'GET', path: '/notes/mine', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
      { id: 'OWN-NOTE', title: 'A member can create a note', category: 'allowed-use', severity: 'control', actorId: 'member', method: 'POST', path: '/notes', body: {}, evidenceRequirement: 'response',
        assertions: [{ kind: 'status.equals', expected: 201 }], ...(controlEffect ? { effects: [{ kind: 'effect.exists', select: { source: 'sql-audit-table', actor: 'member-1', name: 'note.create' } }] } : {}) },
      forbidden('OTHER-NOTE', '/notes/n-other/edit'), forbidden('OTHER-DELETE', '/notes/n-other/delete'),
    ] };
};
const responseRun = (app, mode = 'secure', options = {}) => { app.set(mode); return runHttpAssessment(responseProfile(app.origin, options), { env }); };
const NOTE_PAIRS = [['OTHER-NOTE', 'OWN-NOTE'], ['OTHER-DELETE', 'OWN-NOTE']];

test('a target that hangs or resets on a forbidden write stays in N as observer-failure', async t => {
  const app = await notesServer(t), expectedSuite = suiteOf('notes-response', [responseProfile(app.origin)]);
  for (const mode of ['hang-delete', 'reset-delete']) {
    const run = await responseRun(app, mode);
    assert.equal(run.results.find(r => r.id === 'OTHER-DELETE').status, 'error', mode);
    const b = evidenceBounds(run, { pairs: NOTE_PAIRS });
    assert.deepEqual([b.forbidden.n, b.forbidden.pass, b.forbidden.undecided['observer-failure'], b.forbidden.lower, b.forbidden.upper, b.neverSent], [2, 1, 1, 0.5, 1, 0], mode);
    assert.deepEqual(b.pairs.counts, { 'held-and-useful': 1, 'held-by-inaction': 0, violated: 0, undecided: 1 }, mode);
    assert.match(boundsLines(b)[0], /^Forbidden checks held: 50% to 100% of 2 \(1 passed, 0 failed, 1 undecided: 1 observer-failure\)\.$/);
    // The share held is supported against the leaky build (0 of 2), and the undecided check is named, never credited.
    const s = comparisonSupport(await responseRun(app, 'leaky'), run, { expectedSuite });
    assert.deepEqual([s.label, s.before, s.after, s.undecidedInCandidate], ['supported (1 undecided)', [0, 0], [0.5, 1], ['OTHER-DELETE']], mode);
    assert.match(s.reason, /undecided in the candidate, so not credited: OTHER-DELETE$/);
  }
  // Every forbidden write hangs: both are undecided, and the declared pairs are still reported.
  const all = evidenceBounds(await responseRun(app, 'hang-all'), { pairs: NOTE_PAIRS });
  assert.equal(boundsLines(all)[0], 'Forbidden checks held: no claim supported (all 2 undecided).');
  assert.deepEqual(all.pairs.counts, { 'held-and-useful': 0, 'held-by-inaction': 0, violated: 0, undecided: 2 });
});

test('support needs comparable runs: another application, or a synthetic run against an HTTP one, reads "?"', async t => {
  const app = await notesServer(t);
  const leaky = await responseRun(app, 'leaky'), secure = await responseRun(app, 'secure'), otherApp = await responseRun(app, 'leaky', { applicationId: 'other-notes-app' });
  const same = comparisonSupport(leaky, secure, { expectedSuite: suiteOf('notes-response', [responseProfile(app.origin)]) });
  assert.deepEqual([same.label, same.comparable, same.before, same.after], ['supported', true, [0, 0], [1, 1]], 'the same application and profile');
  for (const [name, before, after] of [['another application', otherApp, secure], ['HTTP against synthetic', leaky, repaired], ['synthetic against HTTP', vulnerable, secure]]) {
    const s = comparisonSupport(before, after);
    assert.deepEqual([s.label, s.supported, s.comparable], ['?', false, false], name);
    assert.match(s.reason, /^the runs are not comparable \(.+\), so no change is supported$/, name);
  }
});

test('an HTTP run with a deleted or duplicated row gets no bounds, and a failing row relabelled not applicable stays in N', async t => {
  const app = await notesServer(t);
  const half = await responseRun(app, 'hang-delete'), failing = await responseRun(app, 'leaky');
  const expectedSuite = createRegistry({ profiles: [responseProfile(app.origin)], env: {} }).exportSuite('notes-response');
  const deleted = structuredClone(failing); deleted.results = deleted.results.filter(r => r.id !== 'OTHER-NOTE');
  const duplicated = structuredClone(half); duplicated.results.push(structuredClone(duplicated.results.find(r => r.id === 'OTHER-NOTE')));
  for (const [name, run] of [['deleted', deleted], ['duplicated', duplicated]]) {
    const b = evidenceBounds(run);
    assert.deepEqual([b.supported, b.reason], [false, 'check-set'], name);
    assert.equal(comparisonSupport(failing, run).label, '?', name);
  }
  // A deletion made consistent (checksTotal edited too) is caught against the expected suite, as the gate catches it.
  deleted.checksTotal = deleted.results.length;
  assert.deepEqual([evidenceBounds(deleted, { expectedSuite }).supported, evidenceBounds(deleted, { expectedSuite }).reason], [false, 'unexpected-suite-evidence']);
  assert.equal(evidenceBounds(failing, { expectedSuite }).supported, true);
  assert.equal(comparisonSupport(failing, deleted).comparable, false, 'and compareRuns finds the edited run incomparable');
  // Relabelled not applicable: refused (see the relabel test below), never a decided pass.
  const relabelled = structuredClone(failing); relabelled.results.find(r => r.id === 'OTHER-NOTE').status = 'not_applicable';
  assert.deepEqual([evidenceBounds(relabelled).supported, evidenceBounds(relabelled).reason], [false, 'invalid-run-evidence']);
  assert.notEqual(comparisonSupport(failing, relabelled).label, 'supported');
});

test('pair declarations are validated: unknown, role-invalid and duplicate pairs are refused', async t => {
  const run = await responseRun(await notesServer(t));
  for (const [name, pairs, message] of [
    ['a mistyped control', [['OTHER-NOTE', 'OWN-NOTES']], /names a check this run does not have/],
    ['a forbidden check used as a control', [['OTHER-NOTE', 'OTHER-DELETE']], /control is not an allowed-use control/],
    ['a control used as the forbidden check', [['OWN-NOTE', 'WHOAMI']], /forbidden check is an allowed-use control/],
    ['a duplicate pair', [['OTHER-NOTE', 'OWN-NOTE'], ['OTHER-NOTE', 'OWN-NOTE']], /declared twice/],
    ['not a list', 'OTHER-NOTE', /must be a list/],
  ]) assert.throws(() => evidenceBounds(run, { pairs }), message, name);
  assert.equal(evidenceBounds(run, { pairs: NOTE_PAIRS }).pairs.declared, 2);
});

test('a failing HTTP row, a passed check whose control is undecided, and an undecided candidate control are each read as they are', async t => {
  // The leaky build's forbidden rows fail and count as failed, and both pairs are violated.
  const leaky = evidenceBounds(await responseRun(await notesServer(t), 'leaky'), { pairs: NOTE_PAIRS });
  assert.deepEqual([leaky.forbidden.pass, leaky.forbidden.fail, leaky.forbidden.lower, leaky.forbidden.upper], [0, 2, 0, 0]);
  assert.deepEqual(leaky.pairs.counts, { 'held-and-useful': 0, 'held-by-inaction': 0, violated: 2, undecided: 0 });
  // On the repaired build, ALLOWED-02's last snapshot is removed: ROLE-01 still passes, its control is undecided,
  // so the pair is held by inaction, not held and useful.
  const gap = structuredClone(repaired); delete gap.results.find(r => r.id === 'ALLOWED-02').attempts.at(-1).evidence.after;
  const b = evidenceBounds(gap);
  const pair = b.pairs.rows.find(p => p.forbidden === 'ROLE-01');
  assert.deepEqual([pair.forbiddenVerdict, pair.verdict], ['pass', 'held-by-inaction']);
  assert.notEqual(pair.controlVerdict, 'pass');
  // Against the vulnerable build the forbidden bounds separate, but one candidate control is undecided: not supported.
  const s = comparisonSupport(vulnerable, gap, SYNTH);
  assert.equal(s.label, '?'); assert.ok(s.after[0] > s.before[1]);
  assert.equal(s.reason, 'only 17 of 18 allowed-use controls passed in the candidate, so the change may be a refusal');
  assert.equal(supportDecision({ before: sideBounds([{ verdict: 'fail' }]), after: sideBounds([{ verdict: 'pass' }]), controls: sideBounds([{ verdict: 'pass' }, { verdict: 'missing' }]) }).supported, false);
  // Controls only undecided, none refused: no "held only by refusal" label; one refused control: the label.
  const lines = allowed => boundsLines({ supported: true, forbidden: sideBounds([{ verdict: 'pass' }]), allowed, neverSent: 0, pairs: { declared: 1, counts: { 'held-and-useful': 0, 'held-by-inaction': 1, violated: 0, undecided: 0 } } }).join('\n');
  assert.doesNotMatch(lines(sideBounds([{ verdict: 'missing' }])), /held only by refusal/);
  assert.match(lines(sideBounds([{ verdict: 'fail' }, { verdict: 'missing' }])), /held only by refusal/);
});

test('the pair rate and the bounds note are pinned, excluded checks are printed, and the suite pairs are frozen', async t => {
  assert.equal(evidenceBounds(repaired).pairs.heldAndUsefulRate, 1);
  assert.equal(evidenceBounds(doNothing).pairs.heldAndUsefulRate, 0);
  assert.equal(BOUNDS_NOTE, 'Evidence bounds: the lower end counts only checks decided as passing, the upper end also counts every undecided check. They are not confidence intervals.');
  assert.equal(boundsLines(evidenceBounds(repaired)).at(-1), BOUNDS_NOTE);
  // The budget runs out deterministically (the first check takes longer than the whole budget).
  const b = evidenceBounds(await publicRun(['HOME', 'SEARCH', 'F1', 'F2'], ['HOME', 'SEARCH'], { HOME: 200, SEARCH: 200, F1: 401, F2: 401 }, 1000, 200));
  assert.equal(b.neverSent, 3);
  assert.ok(boundsLines(b).includes('Never sent: 3 checks (the run budget ran out), counted as missing.'));
  assert.ok(Object.isFrozen(SUITE_PAIRS) && SUITE_PAIRS.every(pair => Object.isFrozen(pair)));
});

// Never-sent rows through an injected transport,
// uncredentialed actors (no identity probes): a response slower
// than the applied timeout is a transport timeout (sent), and every later check is never sent.
const PUBLIC = {
  HOME: { id: 'HOME', title: 'Public home page loads', category: 'allowed-use', severity: 'control', actorId: 'visitor', method: 'GET', path: '/', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
  SEARCH: { id: 'SEARCH', title: 'Public search works', category: 'allowed-use', severity: 'control', actorId: 'visitor', method: 'GET', path: '/search', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
  CRAWL: { id: 'CRAWL', title: 'A crawler can read the sitemap', category: 'allowed-use', severity: 'control', actorId: 'crawler', method: 'GET', path: '/sitemap', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] },
  ...Object.fromEntries([['F1', 'GET', '/admin'], ['F2', 'GET', '/admin/users'], ['F3', 'POST', '/admin/settings'], ['F4', 'POST', '/admin/export']].map(([id, method, path]) => [id,
    { id, title: id, category: 'object-access', severity: 'high', actorId: 'visitor', method, path, ...(method === 'POST' ? { body: {} } : {}), evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 401 }] }])),
};
const publicProfile = (order, requiredControlIds) => ({ id: 'public', name: 'Public site', applicationId: 'public-site', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-public',
  actors: { visitor: { principalId: 'visitor' }, crawler: { principalId: 'crawler' } }, requiredControlIds, checks: order.map(id => PUBLIC[id]) });
// Every wait is measured by the clock the connector reads (performance.now()), never a timer alone: a timer can fire early
// when the event loop's cached time is stale under load, and a check that held for less than its budget would leave budget
// for a check meant never to be sent (the never-sent baseline test below once failed that way in a loaded full-suite run).
const hold = async ms => { const until = performance.now() + ms; while (performance.now() < until) await new Promise(resolve => setTimeout(resolve, Math.max(1, Math.ceil(until - performance.now())))); };
// slowId: that check holds its request until the budget it was given is spent and times out (it was sent); every other check
// answers at once, whatever delayMs says, so which checks are never sent does not depend on the machine's load.
const publicRun = (order, controls, statusFor, delayMs, runTimeoutMs, slowId = null) => {
  const profile = publicProfile(order, controls);
  const transport = async (origin, check, { timeoutMs }) => {
    const id = profile.checks.find(c => c.path === check.path && c.method === check.method)?.id;
    if (id === slowId || (slowId === null && delayMs > timeoutMs)) { await hold(timeoutMs + 1); return { status: null, complete: false, jsonParsed: false, json: undefined, bytes: 0, error: 'timeout' }; }
    if (delayMs && slowId === null) await hold(delayMs);
    return { status: statusFor[id] ?? 404, complete: true, jsonParsed: true, json: {}, bytes: 2 };
  };
  return runHttpAssessment(profile, { env: {}, limits: { ...HTTP_LIMITS, runTimeoutMs }, transport });
};
// A run whose budget runs out at slowId: slowId is sent and times out, and exactly the checks after it are never sent. Each budget
// is below the per-request timeout (HTTP_LIMITS.requestTimeoutMs), so slowId is given all that is left. Only a run in which the
// checks before slowId spent the budget first (a heavily loaded machine) is retried, with a larger budget.
async function budgetRunsOutAt(order, controls, statusFor, slowId) {
  for (const runTimeoutMs of [500, 1200, 2900]) {
    const run = await publicRun(order, controls, statusFor, 0, runTimeoutMs, slowId);
    const row = run.results.find(r => r.id === slowId);
    if (row.status === 'error' && recomputeHttpRow(row).requestAttempted === true) return run;
  }
  throw new Error(`the checks before ${slowId} spent every budget tried`);
}
const neverSentIds = run => run.results.filter(r => r.status === 'error' && recomputeHttpRow(r).requestAttempted === false).map(r => r.id);

test('a check the candidate never sent is missing in a comparison, forbidden or control, never dropped', async () => {
  // The same vulnerable app, only slow: F3 times out (sent) and F4, which fails, is never sent.
  const order1 = ['HOME', 'SEARCH', 'F1', 'F2', 'F3', 'F4'], vulnerableApp = { HOME: 200, SEARCH: 200, F1: 401, F2: 401, F3: 200, F4: 200 };
  const base1 = await publicRun(order1, ['HOME', 'SEARCH'], vulnerableApp, 0, 60000), cand1 = await budgetRunsOutAt(order1, ['HOME', 'SEARCH'], vulnerableApp, 'F3');
  const unsent1 = neverSentIds(cand1);
  assert.deepEqual(unsent1, ['F4']);
  // The candidate's bounds follow from that set: F1 and F2 passed, F3 timed out and the never-sent checks are missing, of 4.
  const s1 = comparisonSupport(base1, cand1, { expectedSuite: suiteOf('public', [publicProfile(order1, ['HOME', 'SEARCH'])]) });
  assert.deepEqual([s1.label, s1.supported, s1.before, s1.after, s1.reason], ['?', false, [0.5, 0.5], [2 / 4, (2 + 1 + unsent1.length) / 4], 'the bounds overlap, so the evidence does not separate the runs']);
  assert.ok(s1.undecidedInCandidate.includes('F4'), 'the never-sent check is named');
  // The candidate fixed F3, but a required control of another actor (CRAWL, last) was never sent.
  const order2 = ['HOME', 'F1', 'F2', 'F3', 'F4', 'CRAWL'];
  const base2 = await publicRun(order2, ['HOME', 'CRAWL'], { HOME: 200, CRAWL: 200, F1: 401, F2: 401, F3: 200, F4: 200 }, 0, 60000);
  const cand2 = await budgetRunsOutAt(order2, ['HOME', 'CRAWL'], { HOME: 200, CRAWL: 403, F1: 401, F2: 401, F3: 401, F4: 401 }, 'F4');
  assert.deepEqual(neverSentIds(cand2), ['CRAWL']);
  const s2 = comparisonSupport(base2, cand2, { expectedSuite: suiteOf('public', [publicProfile(order2, ['HOME', 'CRAWL'])]) });
  assert.equal(s2.label, '?');
  assert.match(s2.reason, /^only 1 of 2 allowed-use controls passed in the candidate/, 'the never-sent control did not pass');
  // A pair whose control was never sent is held by inaction at best.
  const pair = evidenceBounds(cand2, { pairs: [['F3', 'CRAWL']] }).pairs.rows[0];
  assert.deepEqual([pair.controlVerdict, pair.verdict], ['missing', 'held-by-inaction']);
});

test('a relabelled row, and each identity guard on its own, refuse a half-repaired run that would otherwise read [1, 1]', async t => {
  const app = await notesServer(t), half = await responseRun(app, 'leaky-delete');
  const expectedSuite = createRegistry({ profiles: [responseProfile(app.origin)], env: {} }).exportSuite('notes-response');
  const genuine = evidenceBounds(half, { expectedSuite });
  assert.deepEqual([genuine.forbidden.lower, genuine.forbidden.upper], [0.5, 0.5], 'the genuine half-repaired run');
  const rows = run => run.results, passing = rows(half).find(r => r.id === 'OTHER-NOTE');
  const edit = change => { const run = structuredClone(half); change(run); return run; };
  const cases = [
    // The failing row relabelled not applicable.
    ['relabelled not applicable', edit(run => { rows(run).find(r => r.id === 'OTHER-DELETE').status = 'not_applicable'; }), 'invalid-run-evidence'],
    // The failing row replaced in place by a copy of the passing one (a repeated id; checksTotal unchanged).
    ['a repeated id (D11)', edit(run => { run.results[rows(run).findIndex(r => r.id === 'OTHER-DELETE')] = structuredClone(passing); }), 'unexpected-suite-evidence'],
    // The failing row replaced by a renamed copy of the passing one (an id the suite does not have).
    ['an unknown id (D17)', edit(run => { run.results[rows(run).findIndex(r => r.id === 'OTHER-DELETE')] = { ...structuredClone(passing), id: 'OTHER-NOTE-COPY' }; }), 'unexpected-suite-evidence'],
  ];
  for (const [name, run, reason] of cases) {
    for (const options of name.startsWith('relabelled') ? [{}, { expectedSuite }] : [{ expectedSuite }]) {
      const b = evidenceBounds(run, options);
      // With the suite the shared validator refuses a relabelled not-applicable row first (applicability-mismatch).
      const want = name.startsWith('relabelled') && options.expectedSuite ? 'unexpected-suite-evidence' : reason;
      assert.deepEqual([b.supported, b.reason], [false, want], `${name} ${options.expectedSuite ? 'with' : 'without'} the suite`);
    }
  }
  // A run made under a weakened profile (the delete accepted with 200) is refused against the real suite.
  const weakened = responseProfile(app.origin); weakened.checks.find(c => c.id === 'OTHER-DELETE').assertions = [{ kind: 'status.equals', expected: 200 }];
  app.set('leaky-delete');
  const lenient = await runHttpAssessment(weakened, { env });
  assert.deepEqual([evidenceBounds(lenient).forbidden.lower, evidenceBounds(lenient).forbidden.upper], [1, 1], 'read alone, the weakened run looks repaired');
  assert.deepEqual([evidenceBounds(lenient, { expectedSuite }).supported, evidenceBounds(lenient, { expectedSuite }).reason], [false, 'unexpected-suite-evidence']);
  assert.equal(comparisonSupport(half, lenient, { expectedSuite }).label, '?');
  // The same row deleted from both runs, checksTotal edited to match: compareRuns still finds them comparable, so
  // only the expected suite, applied to both runs, refuses the comparison.
  const leaky = await responseRun(app, 'leaky'), secure = await responseRun(app, 'secure');
  const trim = run => { const copy = forgePoints(structuredClone(run), 'OTHER-DELETE'); copy.results = copy.results.filter(r => r.id !== 'OTHER-DELETE'); copy.checksTotal = copy.results.length; return copy; };
  const [trimmedBase, trimmedCand] = [trim(leaky), trim(secure)];
  assert.equal(comparisonSupport(trimmedBase, trimmedCand).comparable, true, 'the core gap: the edit is consistent in both runs');
  const checked = comparisonSupport(trimmedBase, trimmedCand, { expectedSuite });
  assert.deepEqual([checked.label, checked.supported, checked.comparable, checked.reason], ['?', false, false, "the baseline's evidence was refused (unexpected-suite-evidence), so no change is supported"]);
});

test('a pair rate with an undecided pair, and checkIds naming a check a run does not have', async t => {
  // One pair held and useful, one undecided (the delete hangs): the rate counts the undecided pair in its denominator.
  const hang = evidenceBounds(await responseRun(await notesServer(t), 'hang-delete'), { pairs: NOTE_PAIRS });
  assert.deepEqual(hang.pairs.counts, { 'held-and-useful': 1, 'held-by-inaction': 0, violated: 0, undecided: 1 });
  assert.equal(hang.pairs.heldAndUsefulRate, 0.5);
  assert.throws(() => comparisonSupport(vulnerable, repaired, { checkIds: ['TENANT-01', 'TENANT-99'] }), /checkIds names a check one of the runs does not have/);
  assert.throws(() => comparisonSupport(vulnerable, repaired, { checkIds: 'TENANT-01' }), /checkIds must be a list/);
});

test('observers off: every forbidden check is undecided, the bounds are [0, 1] and no claim is supported', async t => {
  const run = await observersOffRun(t);
  const b = evidenceBounds(run, { pairs: [['OTHER-NOTE', 'OWN-NOTE'], ['OTHER-DELETE', 'OWN-NOTE']] });
  assert.deepEqual([b.forbidden.n, b.forbidden.pass, b.forbidden.fail, b.forbidden.lower, b.forbidden.upper], [2, 0, 0, 0, 1]);
  assert.equal(Object.values(b.forbidden.undecided).reduce((s, x) => s + x, 0), 2);
  assert.equal(b.forbidden.undecided.unobservable, 2, 'no observer can see the effects: the effect assertions say unobservable');
  assert.ok(UNDECIDED.every(reason => reason === 'unobservable' || b.forbidden.undecided[reason] === 0));
  assert.deepEqual(b.pairs.counts, { 'held-and-useful': 0, 'held-by-inaction': 0, violated: 0, undecided: 2 });
  const lines = boundsLines(b);
  assert.equal(lines[0], 'Forbidden checks held: no claim supported (all 2 undecided).');
  assert.match(lines[1], /^Allowed actions that still work: 50% to 100% of 2/, 'the allowed side is printed beside the forbidden side');
  // HTTP v3 runs have no contract view yet: their rows are read after the shared validator recomputes them.
  assert.deepEqual([b.source, b.neverSent], ['validated-http-rows', 0]);
  assert.equal(evidenceBounds(repaired).source, 'contract-view');
  // An edited HTTP run fails the validator and gets no bounds.
  const edited = structuredClone(run); edited.results.find(r => r.id === 'OTHER-NOTE').status = 'pass';
  assert.deepEqual([evidenceBounds(edited).supported, evidenceBounds(edited).reason], [false, 'invalid-run-evidence']);
  // Without declared pairs an HTTP run reports none rather than guessing.
  assert.equal(evidenceBounds(run).pairs.declared, 0);
  assert.equal(boundsLines(evidenceBounds(run))[2], 'Pairs: this run declares no forbidden/control pairs.');
  assert.deepEqual([...PAIR_VERDICTS], ['held-and-useful', 'held-by-inaction', 'violated', 'undecided']);
});

test('overlapping bounds never count as support, and only a pending HTTP version is read from its rows', async t => {
  const off = await observersOffRun(t);
  // [0, 1] against [0, 1]: they overlap entirely, so no change is supported.
  const same = comparisonSupport(off, off, { expectedSuite: suiteOf('notes', [OFF_PROFILES.get(off)]) });
  assert.deepEqual([same.label, same.before, same.after, same.reason], ['?', [0, 1], [0, 1], 'the bounds overlap, so the evidence does not separate the runs']);
  // Any other unsupported view keeps its own reason; it is never read from its rows.
  const unknown = { ...off, adapterVersion: 'loopback-response-contract/9' };
  const reason = contractView(unknown).reason;
  assert.notEqual(reason, 'http-version-pending');
  assert.deepEqual([evidenceBounds(unknown).supported, evidenceBounds(unknown).reason], [false, reason]);
});

test('HTTP roles follow the run\'s required controls, as src/contract-http.mjs assigns them, not the severity field', async t => {
  // OWN-NOTE keeps severity "control" but is not a required control: the contract view counts it with the other checks.
  const run = await observersOffRun(t, { requiredControlIds: ['WHOAMI'] });
  const b = evidenceBounds(run);
  assert.deepEqual([b.allowed.n, b.forbidden.n], [1, 3]);
});

test('a verdict outside the contract vocabulary is refused, never silently counted', () => {
  assert.throws(() => sideBounds([{ verdict: 'pass' }, { verdict: 'probably-fine' }]), /outside the contract vocabulary/);
  assert.deepEqual(sideBounds([{ verdict: 'pass' }, { verdict: 'missing' }]), { n: 2, pass: 1, fail: 0, undecided: { missing: 1, conflicting: 0, 'not-exercised': 0, 'observer-failure': 0, unobservable: 0 }, lower: 0.5, upper: 1 });
});

test('a check the exhausted run budget never sent stays in N as missing, alone as in a comparison', async () => {
  // HOME is sent and times out (the whole budget); SEARCH, F1 and F2 are never sent.
  const run = await publicRun(['HOME', 'SEARCH', 'F1', 'F2'], ['HOME', 'SEARCH'], { HOME: 200, SEARCH: 200, F1: 401, F2: 401 }, 1000, 200);
  assert.deepEqual(neverSentIds(run), ['SEARCH', 'F1', 'F2']);
  const b = evidenceBounds(run);
  assert.deepEqual([b.neverSent, b.forbidden.n, b.forbidden.undecided.missing, b.forbidden.lower, b.forbidden.upper], [3, 2, 2, 0, 1]);
  // The sent request that timed out stays in N as an observer failure; the never-sent control is missing.
  assert.deepEqual([b.allowed.n, b.allowed.undecided['observer-failure'], b.allowed.undecided.missing], [2, 1, 1]);
});

test('an unprojectable run reports that, never a bound', () => {
  const foreign = { ...repaired, suiteHash: 'b'.repeat(64) };
  const b = evidenceBounds(foreign);
  assert.equal(b.supported, false);
  assert.match(boundsLines(b)[0], /^Evidence bounds: not available for this run/);
  assert.equal(comparisonSupport(foreign, repaired).label, '?');
});

// A profile with one forbidden check declared not applicable, as an application without the feature declares it.
const naProfile = origin => { const p = responseProfile(origin); p.checks.push({ id: 'EXPORT-ALL', title: 'EXPORT-ALL', category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: '/notes/export', body: {},
  evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], applicability: { applies: false, reason: 'Export is not offered by this application.' } }); return p; };
// The relabel shapes: a failing row rewritten as a not-applicable one.
// actor-identity/5: every sent row of an actor is followed by a probe point named after it, so a thorough forger who
// removes a row or relabels it not applicable also removes that point (or, for the actor's last bracketed check,
// makes the point before it the closing bracket). The keyless-reseal limit stands; it takes one more consistent edit.
const forgePoints = (run, id) => {
  for (const entry of run.identityEvidence?.actors ?? []) {
    const k = (entry.between ?? []).findIndex(b => b.afterCheckId === id);
    if (k >= 0) entry.between.splice(k, 1);
    else if (run.results.some(r => r.id === id && r.status !== 'not_applicable' && r.trace?.[0]?.data?.actorId === entry.actorId && !entry.identityControlIds.includes(id))) {
      if (entry.between?.length) entry.after = entry.between.pop().probes.map(p => ({ ...p, kind: 'after' }));
      else { entry.before = []; entry.after = []; }
    }
  }
  return run;
};
const relabelNA = (run, id, { trace = false, digestToo = false } = {}) => {
  const e = structuredClone(run), row = e.results.find(r => r.id === id), reason = 'Deleting is not offered by this application.';
  if (digestToo) forgePoints(e, id);
  // A not-applicable row carries no decision (the connector writes none and the shared validator refuses one), so the relabel drops it.
  delete row.decision;
  row.status = 'not_applicable';
  row.assertions = [{ name: 'Declared applicability', status: 'not_applicable', expected: 'Documented scope', actual: reason }];
  row.observed = { reason, requestAttempted: false };
  if (trace) { row.backendEvidence = 'not-assessed'; row.trace = [{ type: 'scope', label: 'No test request sent', data: { reason, requestAttempted: false } }]; }
  if (digestToo) row.evidenceDigest = digest(row.observed);
  e.counts = Object.fromEntries(['pass', 'fail', 'inconclusive', 'error', 'not_applicable'].map(k => [k, e.results.filter(r => r.status === k).length]));
  return e;
};

test('a not-applicable row is one the connector wrote and the suite declares; it stays in N as not exercised', async t => {
  const app = await notesServer(t);
  app.set('leaky-delete');
  const profile = naProfile(app.origin), expectedSuite = suiteOf('notes-response', [profile]);
  const genuine = await runHttpAssessment(profile, { env });
  assert.equal(genuine.results.find(r => r.id === 'EXPORT-ALL').status, 'not_applicable');
  // The allowed use: a declared not-applicable row is read, with and without the suite, as not exercised in N.
  for (const options of [{}, { expectedSuite }]) {
    const b = evidenceBounds(genuine, options);
    assert.deepEqual([b.supported, b.forbidden.n, b.forbidden.pass, b.forbidden.undecided['not-exercised'], b.forbidden.lower, b.forbidden.upper], [true, 3, 1, 1, 1 / 3, 2 / 3], JSON.stringify(Object.keys(options)));
  }
  // The failing OTHER-DELETE relabelled not applicable, with and without a rewritten trace: refused with and without the suite.
  for (const shape of [{}, { trace: true }]) for (const options of [{}, { expectedSuite }]) {
    const b = evidenceBounds(relabelNA(genuine, 'OTHER-DELETE', shape), options);
    // With the suite the shared validator refuses it first (applicability-mismatch); without one the bounds refuse it.
    assert.deepEqual([b.supported, b.reason], [false, options.expectedSuite ? 'unexpected-suite-evidence' : 'invalid-run-evidence'], `${JSON.stringify(shape)} ${Object.keys(options)}`);
  }
  // The digest recomputed as the connector computes it: only the suite can tell, and it does (without it, a stated limit).
  const forged = relabelNA(genuine, 'OTHER-DELETE', { trace: true, digestToo: true });
  assert.equal(evidenceBounds(forged).supported, true, 'without the suite a fully forged relabel is read (README Limits)');
  assert.deepEqual([evidenceBounds(forged, { expectedSuite }).supported, evidenceBounds(forged, { expectedSuite }).reason], [false, 'unexpected-suite-evidence']);
  assert.equal(comparisonSupport(genuine, forged).label, '?', 'and without the suite nothing is supported');
  // A relabel that rewrites observed and its digest but keeps the failing assertions: the row's recomputation refuses it.
  const halfDone = structuredClone(genuine), row = halfDone.results.find(r => r.id === 'OTHER-DELETE');
  row.status = 'not_applicable'; row.observed = { reason: 'Deleting is not offered.', requestAttempted: false }; row.evidenceDigest = digest(row.observed);
  assert.deepEqual([evidenceBounds(halfDone).supported, evidenceBounds(halfDone).reason], [false, 'invalid-run-evidence']);
  // A failing control relabelled not applicable is refused the same way.
  app.set('secure');
  const noteless = await runHttpAssessment(profile, { env });
  for (const options of [{}, { expectedSuite }]) assert.equal(evidenceBounds(relabelNA(noteless, 'OWN-NOTE', { trace: true }), options).supported, false);
});

test('the suite is checked as the gate checks it, for HTTP v1, v3 and synthetic runs alike', async t => {
  const app = await notesServer(t), expectedSuite = suiteOf('notes-response', [responseProfile(app.origin)]);
  const leaky = await responseRun(app, 'leaky'), secure = await responseRun(app, 'secure');
  assert.equal(comparisonSupport(leaky, secure, { expectedSuite }).label, 'supported');
  // The required controls narrowed in both runs, or one check's severity changed: refused, as the gate refuses it.
  const narrow = run => { const e = structuredClone(run); e.requiredControlIds = ['WHOAMI']; return e; };
  const severity = run => { const e = structuredClone(run); e.results.find(r => r.id === 'OTHER-NOTE').severity = 'low'; return e; };
  for (const [name, edit] of [['narrowed controls', narrow], ['another severity', severity]]) {
    assert.deepEqual([evidenceBounds(edit(secure), { expectedSuite }).reason], ['unexpected-suite-evidence'], name);
    const s = comparisonSupport(edit(leaky), edit(secure), { expectedSuite });
    assert.deepEqual([s.label, s.comparable], ['?', false], name);
  }
  // HTTP v1 (the shipped fixture, read through its contract view). Without a suite its contract view is read. With
  // one, it goes through the shared validator as the gate's does, so even a hand-built suite naming its own rows is
  // refused: no current export matches a v1 run.
  const { one, two } = JSON.parse(readFileSync(new URL('../../test/fixtures/contract-http-v1/runs.json', import.meta.url), 'utf8')).runs;
  assert.equal(evidenceBounds(one).source, 'contract-view');
  assert.deepEqual([evidenceBounds(one, { expectedSuite }).supported, evidenceBounds(one, { expectedSuite }).reason], [false, 'unexpected-suite-evidence']);
  const own = { hash: one.profileHash, evidenceOrigin: one.evidenceOrigin, requiredControlIds: one.requiredControlIds,
    checks: one.results.map(r => ({ id: r.id, severity: r.severity, ...(r.status === 'not_applicable' ? { applicability: { applies: false, reason: r.observed.reason } } : {}) })) };
  assert.deepEqual([evidenceBounds(one, { expectedSuite: own }).supported, evidenceBounds(one, { expectedSuite: own }).reason], [false, 'unexpected-suite-evidence']);
  assert.deepEqual([evidenceBounds(narrow(one), { expectedSuite: own }).reason, comparisonSupport(narrow(one), narrow(two), { expectedSuite: own }).comparable], ['unexpected-suite-evidence', false]);
  // A v1 run's not-applicable row without a suite is read as the connector wrote it.
  assert.ok(one.results.some(r => r.status === 'not_applicable'));
  assert.equal(evidenceBounds(one).supported, true);
  // A synthetic run against an HTTP suite is refused, and the refusal is not comparable; its own suite is read.
  const synthetic = comparisonSupport(vulnerable, repaired, { expectedSuite });
  assert.deepEqual([synthetic.label, synthetic.comparable, synthetic.reason], ['?', false, "the baseline's evidence was refused (unexpected-suite-evidence), so no change is supported"]);
  assert.equal(evidenceBounds(repaired, SYNTH).supported, true);
  // A null suite is a suite that matches nothing, never "no suite".
  assert.equal(evidenceBounds(secure, { expectedSuite: null }).reason, 'unexpected-suite-evidence');
});

test('violated pairs stay in the pair rate, and a supported change names a regressed check', async t => {
  const app = await notesServer(t), half = evidenceBounds(await responseRun(app, 'leaky-delete'), { pairs: NOTE_PAIRS });
  assert.deepEqual([half.pairs.counts.violated, half.pairs.counts['held-and-useful'], half.pairs.heldAndUsefulRate], [1, 1, 0.5]);
  // F1 held in the baseline and fails in the candidate; F2-F4 are fixed: the share held rises, and the regression is named.
  const order = ['HOME', 'SEARCH', 'F1', 'F2', 'F3', 'F4'], controls = ['HOME', 'SEARCH'], expectedSuite = suiteOf('public', [publicProfile(order, controls)]);
  const before = await publicRun(order, controls, { HOME: 200, SEARCH: 200, F1: 401, F2: 200, F3: 200, F4: 200 }, 0, 60000);
  const after = await publicRun(order, controls, { HOME: 200, SEARCH: 200, F1: 200, F2: 401, F3: 401, F4: 401 }, 0, 60000);
  const s = comparisonSupport(before, after, { expectedSuite });
  assert.deepEqual([s.label, s.before, s.after, s.regressedInCandidate], ['supported (1 regression)', [0.25, 0.25], [0.75, 0.75], ['F1']]);
  assert.match(s.reason, /; regressed in the candidate: F1$/);
});

test('a baseline check never sent is missing, so a slow baseline and a fixed candidate read "?"', async () => {
  const order = ['HOME', 'SEARCH', 'F1', 'F2', 'F3', 'F4'], controls = ['HOME', 'SEARCH'], expectedSuite = suiteOf('public', [publicProfile(order, controls)]);
  const fixed = { HOME: 200, SEARCH: 200, F1: 401, F2: 401, F3: 401, F4: 401 };
  // The baseline: F3 times out (sent) and F4 is never sent, so its forbidden side is [0.5, 1]: F1 and F2 passed, F3 and the
  // never-sent checks are undecided, of 4. The bounds are derived from the never-sent set, which is asserted exactly.
  const slow = await budgetRunsOutAt(order, controls, { HOME: 200, SEARCH: 200, F1: 401, F2: 401, F3: 200, F4: 200 }, 'F3');
  const unsent = neverSentIds(slow);
  assert.deepEqual(unsent, ['F4']);
  const candidate = await publicRun(order, controls, fixed, 0, 60000);
  const s = comparisonSupport(slow, candidate, { expectedSuite });
  assert.deepEqual([s.label, s.before, s.after], ['?', [2 / 4, (2 + 1 + unsent.length) / 4], [1, 1]]);
  // The allowed use: a baseline that sent everything and failed F3 and F4 is separated from the same candidate.
  const fast = await publicRun(order, controls, { HOME: 200, SEARCH: 200, F1: 401, F2: 401, F3: 200, F4: 200 }, 0, 60000);
  assert.deepEqual([comparisonSupport(fast, candidate, { expectedSuite }).label, comparisonSupport(fast, candidate, { expectedSuite }).before], ['supported', [0.5, 0.5]]);
});

test('each suite rule refuses on its own (row ids, a null entry), and a regression is a check that held before', async t => {
  const app = await notesServer(t), expectedSuite = suiteOf('notes-response', [responseProfile(app.origin)]);
  // Every suite row kept, a renamed copy of a passing row appended and checksTotal matched: only the row-id rule refuses it.
  const half = await responseRun(app, 'leaky-delete');
  const extra = structuredClone(half); extra.results.push({ ...structuredClone(half.results.find(r => r.id === 'OTHER-NOTE')), id: 'OTHER-NOTE-2' }); extra.checksTotal = extra.results.length;
  assert.equal(evidenceBounds(extra, { expectedSuite }).reason, 'unexpected-suite-evidence');
  // A suite with a null entry is refused, never a crash.
  assert.equal(evidenceBounds(half, { expectedSuite: { ...expectedSuite, checks: [...expectedSuite.checks, null] } }).reason, 'unexpected-suite-evidence');
  // OTHER-DELETE fails in both runs, so it is not a regression; the change is supported without one.
  const leaky = await responseRun(app, 'leaky'), stillLeaky = await responseRun(app, 'leaky-delete');
  const s = comparisonSupport(leaky, stillLeaky, { expectedSuite });
  assert.deepEqual([s.label, s.regressedInCandidate, s.before, s.after], ['supported', [], [0, 0], [0.5, 0.5]]);
  // A pair compareRuns refuses was never checked against the suite.
  const other = await responseRun(app, 'leaky', { applicationId: 'other-notes-app' });
  assert.deepEqual([comparisonSupport(other, stillLeaky, { expectedSuite }).comparable, comparisonSupport(other, stillLeaky, { expectedSuite }).suiteChecked], [false, false]);
});

// Mutants that survived earlier mutation sweeps.
test('a repeated row id with checksTotal matching gets no bounds without a suite, and the validator still runs without one', async t => {
  // The suite is checked first, so a row replaced in place by a copy (run with the suite) is refused by the suite's row ids,
  // and a duplicate row appended by checksTotal: neither reaches the unique-id guard alone any more.
  const app = await notesServer(t), half = await responseRun(app, 'leaky-delete');
  // The failing OTHER-DELETE replaced in place by a copy of the passing OTHER-NOTE: checksTotal still matches. The shared
  // validator compares no row ids, but it now refuses the copy on its own because it repeats OTHER-NOTE's requestId;
  // the guard still keeps it from reading [1, 1].
  const repeated = structuredClone(half); repeated.results[repeated.results.findIndex(r => r.id === 'OTHER-DELETE')] = structuredClone(half.results.find(r => r.id === 'OTHER-NOTE'));
  assert.deepEqual([repeated.checksTotal, contractView(repeated).reason], [repeated.results.length, 'http-version-pending']);
  assert.throws(() => validateHttpRunEvidence(repeated), e => e.code === 'invalid-run-evidence' && e.detail === 'duplicate-request-id', 'the shared validator refuses the repeated requestId');
  assert.deepEqual([evidenceBounds(repeated).supported, evidenceBounds(repeated).reason], [false, 'check-set']);
  // The validator at the end of checksOf now runs without the suite (with one it ran first); an edited row without a suite still fails it.
  const flipped = structuredClone(half); flipped.results.find(r => r.id === 'OTHER-DELETE').status = 'pass';
  assert.deepEqual([evidenceBounds(flipped).supported, evidenceBounds(flipped).reason], [false, 'invalid-run-evidence']);
});

test('required controls narrowed in both runs are refused by the suite alone when no identity record names them', async () => {
  // The candidate fixes F3 and F4 but refuses the crawler's sitemap, a required control, so the genuine pair reads "?".
  const order = ['HOME', 'F1', 'F2', 'F3', 'F4', 'CRAWL'], controls = ['HOME', 'CRAWL'], expectedSuite = suiteOf('public', [publicProfile(order, controls)]);
  const base = await publicRun(order, controls, { HOME: 200, CRAWL: 200, F1: 401, F2: 401, F3: 200, F4: 200 }, 0, 60000);
  const cand = await publicRun(order, controls, { HOME: 200, CRAWL: 403, F1: 401, F2: 401, F3: 401, F4: 401 }, 0, 60000);
  assert.equal(comparisonSupport(base, cand, { expectedSuite }).reason, 'only 1 of 2 allowed-use controls passed in the candidate, so the change may be a refusal');
  // CRAWL dropped from the required controls of both runs. No actor has a credential, so no identity record lists the controls,
  // and CRAWL is the crawler's only row, so no row's identity reason changes: the shared validator and compareRuns accept the pair.
  // (A credentialed run's identity evidence, a synthetic run's contract view and a v1 run's suite version refuse the same edit
  // first, as the suite test above shows.) Only the suite's required controls refuse it; without them it reads "supported", [0.6] to [0.8].
  const narrow = run => { const e = structuredClone(run); e.requiredControlIds = ['HOME']; return e; };
  const [nb, nc] = [narrow(base), narrow(cand)];
  // actor-identity/6: the suite binds each required control's declared partners (recordPartners), and CRAWL carries a list
  // there as a required control, so the shared validator refuses the narrowed run with the suite too; without the suite it
  // still accepts it.
  assert.throws(() => validateHttpRunEvidence(nc, { expectedSuite }), e => e.code === 'unexpected-suite-evidence', 'the shared validator refuses the narrowed run with the suite');
  assert.doesNotThrow(() => validateHttpRunEvidence(nc), 'the shared validator accepts the narrowed run without the suite');
  assert.equal(compareRuns(nb, nc).compatible, true, 'compareRuns accepts the narrowed pair');
  const s = comparisonSupport(nb, nc, { expectedSuite });
  assert.deepEqual([s.label, s.supported, s.comparable, s.before, s.after, s.reason], ['?', false, false, null, null, "the baseline's evidence was refused (unexpected-suite-evidence), so no change is supported"]);
  assert.deepEqual([evidenceBounds(nc, { expectedSuite }).supported, evidenceBounds(nc, { expectedSuite }).reason], [false, 'unexpected-suite-evidence']);
});

test('a failing control relabelled not applicable is refused; the shared validator refuses it with the suite and only the bounds without one (an uncredentialed actor\'s only row)', async () => {
  // On a credentialed run the identity record lists the required controls, so the validator refuses a relabelled control as well
  // (see the not-applicable row test above). CRAWL is the crawler's only row and no actor has a credential: only the not-applicable check sees it.
  const order = ['HOME', 'F1', 'F2', 'F3', 'F4', 'CRAWL'], controls = ['HOME', 'CRAWL'], expectedSuite = suiteOf('public', [publicProfile(order, controls)]);
  const cand = await publicRun(order, controls, { HOME: 200, CRAWL: 403, F1: 401, F2: 401, F3: 401, F4: 401 }, 0, 60000);
  assert.deepEqual([evidenceBounds(cand, { expectedSuite }).allowed.lower, evidenceBounds(cand, { expectedSuite }).allowed.upper], [0.5, 0.5], 'the refused control, read as it is');
  for (const [shape, options] of [[{ trace: true }, {}], [{ trace: true }, { expectedSuite }], [{ trace: true, digestToo: true }, { expectedSuite }]]) {
    const relabelled = relabelNA(cand, 'CRAWL', shape), label = `${JSON.stringify(shape)} ${Object.keys(options)}`;
    if (options.expectedSuite) {
      // With the suite the shared validator now refuses it (applicability-mismatch), before the bounds read it.
      assert.throws(() => validateHttpRunEvidence(relabelled, options), /unexpected-suite-evidence/, `the shared validator refuses it with the suite: ${label}`);
      assert.deepEqual([evidenceBounds(relabelled, options).supported, evidenceBounds(relabelled, options).reason], [false, 'unexpected-suite-evidence'], label);
    } else {
      assert.doesNotThrow(() => validateHttpRunEvidence(relabelled, options), `without a suite the shared validator still accepts it: ${label}`);
      assert.deepEqual([evidenceBounds(relabelled, options).supported, evidenceBounds(relabelled, options).reason], [false, 'invalid-run-evidence'], label);
    }
  }
});

test('the suite is applied to the candidate: a severity lowered in the candidate alone, which compareRuns does not compare, is refused', async t => {
  const app = await notesServer(t), expectedSuite = suiteOf('notes-response', [responseProfile(app.origin)]);
  const leaky = await responseRun(app, 'leaky'), secure = await responseRun(app, 'secure');
  const lowered = structuredClone(secure); lowered.results.find(r => r.id === 'OTHER-NOTE').severity = 'low';
  assert.equal(compareRuns(leaky, lowered).compatible, true, 'compareRuns does not compare severities');
  const s = comparisonSupport(leaky, lowered, { expectedSuite });
  assert.deepEqual([s.label, s.supported, s.comparable, s.reason], ['?', false, false, "the candidate's evidence was refused (unexpected-suite-evidence), so no change is supported"]);
  // A forged not-applicable relabel in the candidate alone cannot show this: compareRuns already refuses it (its actor signature changes).
  assert.equal(compareRuns(leaky, relabelNA(secure, 'OTHER-DELETE', { trace: true, digestToo: true })).compatible, false);
});

test('degenerateBaselines passes its options on: a suite the runs do not match, and declared pairs', () => {
  const runs = { 'do-nothing': doNothing, 'dump-everything': dumpEverything }, none = { forbidden: null, allowed: null, pairs: null };
  // Another target's suite refuses every run, so no baseline has bounds.
  const foreign = degenerateBaselines(runs, { expectedSuite: suiteOf('public', [publicProfile(['HOME', 'F1'], ['HOME'])]) });
  assert.deepEqual(foreign, { 'do-nothing': none, 'dump-everything': none });
  // Their own suite reads as no suite does.
  assert.deepEqual(degenerateBaselines(runs, SYNTH), degenerateBaselines(runs));
  // Declared pairs replace the suite pairs: one pair counted, not 26.
  const one = degenerateBaselines(runs, { pairs: [['TENANT-01', 'ALLOWED-01']] });
  for (const build of Object.keys(runs)) assert.equal(Object.values(one[build].pairs).reduce((s, x) => s + x, 0), 1, build);
});

test('a relabel that keeps the sent request is refused, and the undecided count follows checkIds', async t => {
  const app = await notesServer(t), expectedSuite = suiteOf('notes-response', [responseProfile(app.origin)]);
  // The failing OTHER-DELETE relabelled with its assertions rewritten and its digest recomputed over observed, but observed
  // still records the request that was sent: only the row's request check refuses it.
  const half = await responseRun(app, 'leaky-delete'), kept = structuredClone(half), row = kept.results.find(r => r.id === 'OTHER-DELETE');
  row.status = 'not_applicable'; row.assertions = [{ name: 'Declared applicability', status: 'not_applicable', expected: 'Documented scope', actual: 'Deleting is not offered.' }]; row.evidenceDigest = digest(row.observed);
  assert.deepEqual(recomputeHttpRow(row).problems.map(p => p.detail), ['not-applicable-request']);
  assert.deepEqual([evidenceBounds(kept).supported, evidenceBounds(kept).reason], [false, 'invalid-run-evidence']);
  // checkIds leaves out the undecided OTHER-DELETE, so no chosen check is undecided and the label names none.
  const s = comparisonSupport(await responseRun(app, 'leaky'), await responseRun(app, 'hang-delete'), { expectedSuite, checkIds: ['OTHER-NOTE'] });
  assert.deepEqual([s.label, s.undecidedInCandidate, s.compared], ['supported', [], ['OTHER-NOTE']]);
});

test('a passing row copied into another check\'s slot, its id and title set back, repeats a requestId and is refused', async t => {
  const app = await notesServer(t), expectedSuite = suiteOf('notes-response', [responseProfile(app.origin)]);
  const half = await responseRun(app, 'leaky-delete'), leaky = await responseRun(app, 'leaky');
  // The failing OTHER-DELETE replaced by a copy of the passing OTHER-NOTE, its id, title and remediation set back; no digest recomputed.
  const copied = structuredClone(half), i = copied.results.findIndex(r => r.id === 'OTHER-DELETE'), slot = copied.results[i];
  copied.results[i] = { ...structuredClone(half.results.find(r => r.id === 'OTHER-NOTE')), id: slot.id, title: slot.title, remediation: slot.remediation };
  copied.counts = Object.fromEntries(Object.keys(half.counts).map(k => [k, copied.results.filter(r => r.status === k).length]));
  // The shared core now refuses the copy as well:
  // the validator with the suite, the gate's validateRun, and compareRuns, which reads the pair as incompatible.
  assert.throws(() => validateHttpRunEvidence(copied, { expectedSuite }), e => e.code === 'invalid-run-evidence' && e.detail === 'duplicate-request-id');
  assert.throws(() => validateRun(copied, expectedSuite));
  assert.equal(compareRuns(leaky, copied).compatible, false);
  // Here it is refused, with and without the suite, so it never reads [1, 1] or "supported". Without the suite this module's
  // own guard refuses it (check-set); with the suite the shared validator now refuses it first.
  assert.deepEqual([evidenceBounds(copied).supported, evidenceBounds(copied).reason], [false, 'check-set']);
  assert.deepEqual([evidenceBounds(copied, { expectedSuite }).supported, evidenceBounds(copied, { expectedSuite }).reason], [false, 'unexpected-suite-evidence']);
  const s = comparisonSupport(leaky, copied, { expectedSuite });
  assert.deepEqual([s.label, s.comparable], ['?', false]);
  // compareRuns now reads the pair as incompatible first, so the comparison stops there.
  assert.equal(s.reason, 'the runs are not comparable (Evidence origin does not match its producer family or observations.), so no change is supported');
  // The allowed use: the genuine run is read as it is, [0.5, 0.5], and its change from the leaky build is supported.
  assert.deepEqual([evidenceBounds(half, { expectedSuite }).forbidden.lower, evidenceBounds(half, { expectedSuite }).forbidden.upper], [0.5, 0.5]);
  assert.equal(comparisonSupport(leaky, half, { expectedSuite }).label, 'supported');
  // Not-applicable rows send no request and carry no requestId, and two checks may share a path: a genuine run with two of
  // each is read, with and without its suite.
  const twins = { ...responseProfile(app.origin), id: 'notes-twins' };
  twins.checks.push({ ...twins.checks.find(c => c.id === 'OTHER-NOTE'), id: 'OTHER-NOTE-TITLE', title: 'OTHER-NOTE-TITLE', body: { title: 'renamed' } },
    ...['EXPORT-ALL', 'ARCHIVE-ALL'].map(id => ({ id, title: id, category: 'object-access', severity: 'high', actorId: 'member', method: 'POST', path: `/notes/${id.toLowerCase()}`, body: {},
      evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 403 }], applicability: { applies: false, reason: 'Not offered by this application.' } })));
  app.set('leaky-delete');
  const twinRun = await runHttpAssessment(twins, { env }), twinSuite = suiteOf('notes-twins', [twins]);
  const sent = twinRun.results.filter(r => r.status !== 'not_applicable');
  assert.deepEqual([sent.length, new Set(sent.map(r => r.trace[0].data.requestPathHash)).size, twinRun.results.length - sent.length], [6, 5, 2], 'two sent rows share a path; two rows are not applicable (MY-NOTES is the sixth sent row)');
  for (const options of [{}, { expectedSuite: twinSuite }]) {
    const b = evidenceBounds(twinRun, options);
    assert.deepEqual([b.supported, b.forbidden.n, b.forbidden.pass, b.forbidden.fail, b.forbidden.undecided['not-exercised']], [true, 5, 2, 1, 2], JSON.stringify(Object.keys(options)));
  }
});

test('the suite\'s required controls are its own list, not every control-severity check', async () => {
  // SEARCH has severity "control" but is not a required control, so it counts on the forbidden side; the suite lists HOME alone.
  const order = ['HOME', 'SEARCH', 'F1', 'F2', 'F3', 'F4'], controls = ['HOME'], expectedSuite = suiteOf('public', [publicProfile(order, controls)]);
  assert.deepEqual([expectedSuite.requiredControlIds, expectedSuite.checks.filter(c => c.severity === 'control').map(c => c.id)], [['HOME'], ['HOME', 'SEARCH']]);
  const base = await publicRun(order, controls, { HOME: 200, SEARCH: 200, F1: 401, F2: 401, F3: 200, F4: 200 }, 0, 60000);
  const cand = await publicRun(order, controls, { HOME: 200, SEARCH: 200, F1: 401, F2: 401, F3: 401, F4: 401 }, 0, 60000);
  // The allowed use: the genuine runs are read with their suite and the change is supported; the gate accepts the same run and suite.
  const b = evidenceBounds(cand, { expectedSuite });
  assert.deepEqual([b.supported, b.allowed.n, b.forbidden.n, b.forbidden.lower], [true, 1, 5, 1]);
  const s = comparisonSupport(base, cand, { expectedSuite });
  assert.deepEqual([s.label, s.before, s.after, s.candidateControls], ['supported', [0.6, 0.6], [1, 1], [1, 1]]);
  assert.doesNotThrow(() => validateRun(cand, expectedSuite));
  // The other direction: a run whose required controls were widened to both is refused by the suite's own list.
  const widened = structuredClone(cand); widened.requiredControlIds = ['HOME', 'SEARCH'];
  assert.equal(evidenceBounds(widened, { expectedSuite }).reason, 'unexpected-suite-evidence');
});

