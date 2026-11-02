import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { runAssessment, compareRuns } from '../../src/runner.mjs';
import { createStore } from '../../src/store.mjs';
import { scopeStatement } from '../../src/report.mjs';
import { ticketsFor, renderTickets, renderJiraCsv, renderGithubMarkdown, dedupeKey, profileHashOf, resolutionBlocker, REPAIR_TRANSITIONS, TICKET_COLUMNS } from './tickets.mjs';
import { createHttpLab, makeLabProfile } from '../../examples/http-lab.mjs';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { exportTickets } from './cli.mjs';

// Owned synthetic loopback fixture only; no model, provider or hosted service.
const vulnerable = await runAssessment('demo-vulnerable');
const repaired = await runAssessment('demo-repaired');
const copy = value => structuredClone(value);
// A copy of a run with one passing check failing (counts kept consistent): a regression.
// Free text outside the markdown fences: only fixed words, ids, statuses, labels and keys.
const outsideFences = md => md.replace(/^(`{3,})text\n[\s\S]*?\n\1$/gm, '');
// A small RFC 4180 reader for the tests: quoted fields, doubled quotes, CRLF records.
function parseCsv(text) {
  const rows = []; let row = [], field = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) { if (c === '"' && text[i + 1] === '"') { field += '"'; i++; } else if (c === '"') quoted = false; else field += c; continue; }
    if (c === '"') quoted = true; else if (c === ',') { row.push(field); field = ''; } else if (c === '\r' && text[i + 1] === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; } else field += c;
  }
  return rows;
}

test('one Open ticket per failing check, with the columns, the scope qualifier and the evidence hash', async t => {
  // The evidence integrity hash is set when the store saves a run.
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven-tickets-saved-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store = createStore(dir); await store.ready;
  const saved = await store.save(copy(vulnerable));
  assert.match(saved.integrity.sha256, /^[0-9a-f]{64}$/);
  const tickets = ticketsFor(saved);
  assert.equal(tickets.length, vulnerable.counts.fail);
  assert.ok(tickets.every(t => t.status === 'Open'));
  const rows = parseCsv(renderJiraCsv(tickets));
  assert.deepEqual(rows[0], TICKET_COLUMNS);
  assert.equal(rows.length, tickets.length + 1);
  for (const r of rows.slice(1)) {
    assert.equal(r.length, TICKET_COLUMNS.length);
    assert.ok(r[1].includes(`Scope: ${scopeStatement(saved)}`), 'the scope qualifier');
    assert.ok(r[1].includes(saved.integrity.sha256), 'the run evidence hash');
    assert.ok(r[1].includes('These are observed checks, not a safety certification.'));
    assert.ok(['Highest', 'High', 'Medium', 'Low'].includes(r[3]));
    assert.match(r[4], /^[0-9a-f]{64}$/);
  }
});

test('the dedupe key is sha256 of [check id, application id, policy hash, profile hash, target context, target label]: identical across re-exports and across builds of the same application and policy', () => {
  const first = ticketsFor(vulnerable), again = ticketsFor(copy(vulnerable));
  assert.deepEqual(first.map(t => t.dedupeKey), again.map(t => t.dedupeKey));
  assert.equal(renderTickets(vulnerable, { format: 'jira-csv' }), renderTickets(copy(vulnerable), { format: 'jira-csv' }), 'identical bytes');
  const row = vulnerable.results.find(r => r.status === 'fail');
  assert.equal(first.find(t => t.summary.includes(row.id)).dedupeKey, createHash('sha256').update(JSON.stringify([row.id, vulnerable.applicationId, vulnerable.policyHash, vulnerable.profileHash, vulnerable.targetContext ?? 'local-app', vulnerable.targetLabel ?? null])).digest('hex'));
  // The repair of the same check on the same application keeps the key, so an importer can close the issue it opened.
  const resolved = ticketsFor(repaired, { baseline: vulnerable, comparison: compareRuns(vulnerable, repaired) });
  assert.deepEqual(new Set(resolved.map(t => t.dedupeKey)), new Set(first.map(t => t.dedupeKey)));
  assert.notEqual(dedupeKey(row.id, { ...vulnerable, policyHash: 'another-policy' }), dedupeKey(row.id, vulnerable));
  // A local run never shares a key with a forwarded target, nor one forwarded target with another.
  const forwarded = { ...vulnerable, targetContext: 'operator-forwarded', targetLabel: 'Acme staging' };
  assert.notEqual(dedupeKey(row.id, forwarded), dedupeKey(row.id, vulnerable));
  assert.notEqual(dedupeKey(row.id, forwarded), dedupeKey(row.id, { ...forwarded, targetLabel: 'Beta staging' }));
  // The build target (demo-vulnerable, demo-repaired) is not in the key: the repair keeps its failure's key.
  assert.equal(dedupeKey(row.id, { ...vulnerable, targetId: 'demo-repaired' }), dedupeKey(row.id, vulnerable));
  // A legacy synthetic run without a stored profile hash gets the one core's comparison fills in, so its key is unchanged.
  const { profileHash: _p, ...legacy } = vulnerable;
  assert.equal(profileHashOf(legacy), vulnerable.profileHash);
  assert.equal(dedupeKey(row.id, legacy), dedupeKey(row.id, vulnerable));
  // The encoding is injective: a NUL in an id, a missing identity and padding never collide.
  assert.notEqual(dedupeKey('A\u0000B', { ...vulnerable, applicationId: 'C' }), dedupeKey('A', { ...vulnerable, applicationId: 'B\u0000C' }));
  assert.notEqual(dedupeKey(row.id, { ...vulnerable, applicationId: undefined }), dedupeKey(row.id, { ...vulnerable, applicationId: '' }));
  assert.notEqual(dedupeKey(` ${row.id}`, vulnerable), dedupeKey(row.id, vulnerable));
});

test('Resolved candidate appears only for a repair core credits: compatible, controls passing, no new failure, the comparison core\'s own for this pair', () => {
  const comparison = compareRuns(vulnerable, repaired);
  assert.deepEqual([comparison.compatible, comparison.controlsPass, comparison.summary.newFailures], [true, true, 0]);
  const resolved = ticketsFor(repaired, { baseline: vulnerable, comparison });
  assert.equal(resolved.length, comparison.rows.filter(r => r.transition === 'fixed').length);
  assert.ok(resolved.length && resolved.every(t => t.status === 'Resolved candidate' && t.description.includes(`(${comparison.restorationLabel}; transition fixed)`)));
  assert.ok(resolved.every(t => t.description.includes(`Evidence scope: ${comparison.evidenceScope}`)), 'core\'s evidence scope is carried');
  // The comparison is checked against core: a forged, edited or mismatched one is refused.
  assert.throws(() => ticketsFor(repaired, { baseline: vulnerable, comparison: { ...comparison, controlsPass: true, compatible: true, rows: comparison.rows.map(r => ({ ...r, transition: 'fixed' })) } }), /invalid-comparison-evidence/);
  assert.throws(() => ticketsFor(repaired, { baseline: vulnerable, comparison: { ...comparison, restorationLabel: 'Local control restored' } }), /invalid-comparison-evidence/);
  assert.throws(() => ticketsFor(vulnerable, { baseline: repaired, comparison }), /invalid-comparison-evidence/, 'another pair\'s comparison');
  // Not comparable (another policy): the candidate's Open tickets say so, and nothing resolves.
  const otherPolicy = { ...copy(repaired), policyHash: 'f'.repeat(64) };
  const incompatible = ticketsFor(vulnerable, { baseline: otherPolicy, comparison: compareRuns(otherPolicy, vulnerable) });
  assert.ok(incompatible.length > 0 && incompatible.every(t => t.status === 'Open' && t.description.includes('(not comparable)')));
  assert.throws(() => ticketsFor(repaired, { comparison }), /baseline/);
});

test('a repair core does not credit to the application never resolves: model swap, silent weight change, unreadable identity', async t => {
  const lab = await createHttpLab({ build: 'baseline' });
  t.after(() => lab.close?.() ?? lab.stop?.());
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken };
  const base = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  lab.setBuild('repaired');
  const sameLabel = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  const newLabel = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v2'), { env });
  let session = 0;
  const identity = (served, weights) => ({ schema: 'scopehaven-model-identity/2', state: 'observed', strength: 'weights-digest', tapSession: `s-${++session}`, upstream: 'http://127.0.0.1:11434', upstreamKind: 'loopback', window: { from: 0, to: null },
    calls: { total: 3, succeeded: 3, failed: 0, abandoned: 0 }, reasons: [], models: [{ served, requested: [served], fingerprints: [], weightsDigest: weights, apis: ['ollama-chat'], calls: 3, strength: 'weights-digest' }] });
  const A = 'a'.repeat(64), B = 'b'.repeat(64), m = (run, id) => ({ ...run, modelIdentity: id });
  const resolvedFor = (b, c) => ticketsFor(c, { baseline: b, comparison: compareRuns(b, c) }).filter(x => x.status === 'Resolved candidate').length;
  assert.equal(resolvedFor(m(base, identity('qwen3.5:9b', A)), m(sameLabel, identity('gemma4:latest', B))), 0, 'model swap');
  assert.equal(resolvedFor(m(base, identity('gemma4:latest', A)), m(sameLabel, identity('gemma4:latest', B))), 0, 'silent weight change');
  assert.equal(resolvedFor(m(base, identity('gemma4:latest', A)), m(sameLabel, { state: 'observed', models: 'garbage' })), 0, 'unreadable identity');
  const swap = ticketsFor(m(sameLabel, identity('gemma4:latest', B)), { baseline: m(base, identity('qwen3.5:9b', A)), comparison: compareRuns(m(base, identity('qwen3.5:9b', A)), m(sameLabel, identity('gemma4:latest', B))) });
  assert.ok(swap.filter(x => x.status === 'Unverified change').every(x => /not credit|not the application/.test(x.description)));
  // The control: the application changed and the model did not, so the repair is credited and resolves, with core's own label.
  assert.ok(resolvedFor(m(base, identity('gemma4:latest', A)), m(newLabel, identity('gemma4:latest', A))) > 0, 'credited to the application');
  const credited = compareRuns(m(base, identity('gemma4:latest', A)), m(newLabel, identity('gemma4:latest', A)));
  assert.notEqual(credited.restorationLabel, 'Fixed');
  assert.ok(ticketsFor(m(newLabel, identity('gemma4:latest', A)), { baseline: m(base, identity('gemma4:latest', A)), comparison: credited }).filter(x => x.status === 'Resolved candidate').every(x => x.description.includes(`(${credited.restorationLabel}; transition contract-restored)`)));
  // A genuine regression: one more check, a legacy read the repair breaks. Nothing resolves, and each repair says why.
  const withLegacy = origin => { const p = makeLabProfile(origin, 'lab-v1'); p.checks.push({ id: 'LEGACY-READ', title: 'The legacy foreign-record read stays available', category: 'Local application contracts', severity: 'low', actorId: 'member', method: 'GET', path: '/records/foreign', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }); return p; };
  lab.setBuild('baseline');
  const rb = await runHttpAssessment(withLegacy(lab.origin), { env });
  lab.setBuild('repaired');
  const rc = await runHttpAssessment({ ...withLegacy(lab.origin), buildLabel: 'lab-v2' }, { env });
  const regression = compareRuns(rb, rc);
  assert.equal(regression.summary.newFailures, 1);
  const changed = ticketsFor(rc, { baseline: rb, comparison: regression }).filter(x => x.status !== 'Open');
  assert.ok(changed.length && changed.every(x => x.status === 'Unverified change' && x.description.includes('the candidate has 1 new failure')), JSON.stringify(changed.map(x => x.status)));
});

test('two targets never share a key: another origin under the same application, or two forwarded targets with one label; a target keeps its key across builds', async t => {
  const lab = await createHttpLab({ build: 'baseline' }), lab2 = await createHttpLab({ build: 'baseline' });
  t.after(() => lab.close?.() ?? lab.stop?.()); t.after(() => lab2.close?.() ?? lab2.stop?.());
  const env = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab.memberToken }, env2 = { SCOPEHAVEN_TARGET_LAB_MEMBER_TOKEN: lab2.memberToken };
  const a = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v1'), { env });
  const b = await runHttpAssessment({ ...makeLabProfile(lab2.origin, 'lab-v1'), id: 'http-lab-eu', name: 'Separate HTTP application (EU)' }, { env: env2 });
  assert.equal(a.applicationId, b.applicationId, 'the same application');
  assert.equal(compareRuns(a, b).compatible, false, 'core calls them different subjects');
  lab.setBuild('repaired');
  const aRepaired = await runHttpAssessment(makeLabProfile(lab.origin, 'lab-v2'), { env });
  const resolved = ticketsFor(aRepaired, { baseline: a, comparison: compareRuns(a, aRepaired) }).filter(x => x.status === 'Resolved candidate');
  assert.ok(resolved.length >= 1, 'target A has a repair');
  const openB = new Set(ticketsFor(b).filter(x => x.status === 'Open').map(x => x.dedupeKey));
  assert.ok(openB.size >= 1);
  assert.deepEqual(resolved.filter(x => openB.has(x.dedupeKey)).map(x => x.checkId), [], 'a repair on A never closes B\'s issue');
  // A keeps its key across builds: the repair closes A's own issue.
  const openA = new Set(ticketsFor(a).filter(x => x.status === 'Open').map(x => x.dedupeKey));
  assert.ok(resolved.every(x => openA.has(x.dedupeKey)));
  // Two forwarded targets with the same label, on different origins.
  const forwarded = (origin, extra = {}) => ({ ...makeLabProfile(origin, 'lab-v1'), targetContext: 'operator-forwarded', targetLabel: 'Acme staging', ...extra });
  lab.setBuild('baseline');
  const fa = await runHttpAssessment(forwarded(lab.origin), { env }), fb = await runHttpAssessment(forwarded(lab2.origin, { id: 'http-lab-eu' }), { env: env2 });
  const keysA = new Set(ticketsFor(fa).map(x => x.dedupeKey));
  assert.ok(keysA.size >= 1);
  assert.deepEqual(ticketsFor(fb).filter(x => keysA.has(x.dedupeKey)).map(x => x.checkId), []);
});

test('the markdown heading never carries the check id (an id like GH-12 would link to an issue); every limitation is in the fixed lines; bidirectional controls are removed from the fixed lines', () => {
  const md = renderGithubMarkdown([{ checkId: 'GH-12', summary: '[Scopehaven] GH-12: a check', description: 'Check GH-12: a check.', labels: ['scopehaven'], priority: 'High', dedupeKey: 'k'.repeat(64), status: 'Open' }]);
  assert.match(md, /^## Scopehaven ticket 1$/m);
  assert.doesNotMatch(outsideFences(md), /GH-12/);
  const row = vulnerable.results.find(r => r.status === 'fail');
  const limitations = Array.from({ length: 9 }, (_, i) => `Limitation number ${i + 1}.`);
  const run = { ...copy(vulnerable), limitations, targetContext: 'operator-forwarded', targetLabel: 'Acme\u202Estaging', results: vulnerable.results.map(r => (r.id === row.id ? { ...r, summary: 'x'.repeat(20000) } : r)) };
  const ticket = ticketsFor(run).find(x => x.checkId === row.id);
  for (const l of limitations) assert.ok(ticket.description.includes(`Limitation: ${l}`), l);
  assert.ok(ticket.description.indexOf('Limitation number 9.') < ticket.description.indexOf('Expected:'), 'in the fixed part, before the check\'s own text');
  assert.ok(ticket.description.includes('Acmestaging') && !ticket.description.includes('\u202E'), 'the target label is cleaned');
});

test('CSV cells never run as formulas, and markdown never mentions, references or renders HTML', () => {
  const run = copy(vulnerable);
  const row = run.results.find(r => r.status === 'fail');
  Object.assign(row, { title: '=HYPERLINK("http://x","y") @team #12 <img src=x>', summary: '+cmd|calc, "quoted"\nnext line' });
  const rows = parseCsv(renderTickets(run, { format: 'jira-csv' }));
  const mine = rows.find(r => r[0].includes(row.id));
  assert.ok(mine[0].includes('=HYPERLINK') && !/^[=+\-@]/.test(mine[0]), mine[0]);
  assert.ok(mine[1].includes('"quoted"') && mine[1].includes('\n'), 'quotes and newlines survive inside the field');
  // Markdown: every free-text field is inside a fence no backtick run can close; outside it, nothing a reader wrote.
  Object.assign(row, { summary: 'see https://example.com/x and [link](https://e.com) ![i](https://e.com/i.png) GH-12 #12 @team\n## Status: Resolved\n- [ ] task\n~~~\n\\` ```` `' });
  const md = renderTickets(run, { format: 'github-md' }), outside = outsideFences(md);
  for (const live of ['<img', '@team', '#12', 'GH-12', 'http', '](', '## Status', '- [ ]', '~~~']) assert.ok(!outside.includes(live), live);
  assert.ok(md.includes('@team') && md.includes('GH-12'), 'the text is kept, inside the fence');
  assert.match(md, /\n(`{5,})text\n[\s\S]*````[\s\S]*\n\1\n/, 'the fence is longer than any backtick run in the text');
  assert.ok(md.includes(`<!-- scopehaven-dedupe-key: ${dedupeKey(row.id, run)} -->`));
});

test('every CSV cell a spreadsheet would read as a formula is neutralized, whatever the ticket holds', () => {
  const csv = renderJiraCsv([{ summary: '=1+1', description: '@SUM(A1)', labels: ['-2'], priority: '+High', dedupeKey: '\tk', status: '\rOpen' }]);
  const [row] = parseCsv(csv).slice(1);
  assert.deepEqual(row, ["'=1+1", "'@SUM(A1)", "'-2", "'+High", "'\tk", "'\rOpen"]);
  // Every cell is quoted, so a semicolon locale cannot split one, and a leading space never hides a formula.
  const raw = renderJiraCsv([{ summary: ' =1+1', description: 'a;=1+1', labels: ['x'], priority: 'Low', dedupeKey: 'k', status: 'Open' }]).split('\r\n')[1];
  assert.equal(raw, '"\' =1+1","a;=1+1","x","Low","k","Open"');
  // Bidirectional controls are removed, and a long summary is never cut inside a character.
  const [t1] = ticketsFor({ id: 'r', applicationId: 'app', policyHash: 'p', results: [{ id: 'C-1', title: `\u202eevil ${'\u{1F600}'.repeat(200)}`, status: 'fail', severity: 'high' }] });
  assert.ok(!/[\u202a-\u202e\u2066-\u2069]/.test(t1.summary + t1.description));
  assert.ok(!/[\ud800-\udbff]$/.test(t1.summary), 'no split surrogate pair');
});

test('0 network calls: rendering never opens a socket or calls fetch', () => {
  const connect = net.Socket.prototype.connect, fetchBefore = globalThis.fetch;
  let attempts = 0;
  net.Socket.prototype.connect = function () { attempts++; throw new Error('no network'); };
  globalThis.fetch = () => { attempts++; throw new Error('no network'); };
  try {
    for (const format of ['jira-csv', 'github-md']) renderTickets(repaired, { format, baseline: vulnerable, comparison: compareRuns(vulnerable, repaired) });
    renderJiraCsv(ticketsFor(vulnerable)); renderGithubMarkdown(ticketsFor(vulnerable));
  } finally { net.Socket.prototype.connect = connect; globalThis.fetch = fetchBefore; }
  assert.equal(attempts, 0);
  assert.throws(() => renderTickets(vulnerable, { format: 'xlsx' }), /Unknown ticket format/);
});

test('the CLI exports from the local store into a private directory, compares like the local API, and never overwrites', async t => {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven-tickets-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const store = createStore(join(root, 'data')); await store.ready;
  const baseline = await store.save(copy(vulnerable)), candidate = await store.save(copy(repaired));
  const out = join(root, 'out'); await mkdir(out, { mode: 0o700 });
  const csv = await exportTickets({ runId: baseline.id, format: 'jira-csv', outputFile: join(out, 'open.csv'), dataDir: join(root, 'data') });
  assert.equal(parseCsv(await readFile(join(out, 'open.csv'), 'utf8')).length, vulnerable.counts.fail + 1);
  assert.equal(csv.sha256, createHash('sha256').update(await readFile(join(out, 'open.csv'))).digest('hex'));
  await exportTickets({ runId: candidate.id, baselineRunId: baseline.id, format: 'github-md', outputFile: join(out, 'resolved.md'), dataDir: join(root, 'data') });
  assert.match(await readFile(join(out, 'resolved.md'), 'utf8'), /\*\*Status:\*\* Resolved candidate/);
  await assert.rejects(exportTickets({ runId: baseline.id, format: 'jira-csv', outputFile: join(out, 'open.csv'), dataDir: join(root, 'data') }), /EEXIST/);
  await mkdir(join(root, 'open'), { mode: 0o755 });
  await assert.rejects(exportTickets({ runId: baseline.id, format: 'jira-csv', outputFile: join(root, 'open', 'x.csv'), dataDir: join(root, 'data') }), /private/);
});

test('only failing checks open tickets; the restoration label is core\'s; severity sets the priority', () => {
  const run = copy(vulnerable);
  const failing = run.results.filter(r => r.status === 'fail');
  failing[0].status = 'inconclusive';
  assert.equal(ticketsFor(run).length, failing.length - 1, 'an inconclusive check is not an Open ticket');
  const comparison = compareRuns(vulnerable, repaired);
  assert.ok(ticketsFor(repaired, { baseline: vulnerable, comparison }).every(t => t.description.includes(`(${comparison.restorationLabel}; transition fixed)`)));
  const bySeverity = Object.fromEntries(ticketsFor(vulnerable).map(t => [t.labels.find(l => l.startsWith('severity-')), t.priority]));
  for (const [severity, priority] of Object.entries({ 'severity-critical': 'Highest', 'severity-high': 'High', 'severity-medium': 'Medium', 'severity-low': 'Low' }))
    if (bySeverity[severity]) assert.equal(bySeverity[severity], priority, severity);
  assert.ok(Object.keys(bySeverity).length >= 2, JSON.stringify(bySeverity));
  const minimal = { id: 'run-minimal', applicationId: 'app', policyHash: 'p', results: ['critical', 'high', 'medium', 'low', 'control', 'unknown'].map(severity => ({ id: `C-${severity}`, title: severity, status: 'fail', severity })) };
  assert.deepEqual(ticketsFor(minimal).map(t => t.priority), ['Highest', 'High', 'Medium', 'Low', 'Medium', 'Medium']);
  assert.ok(ticketsFor(minimal).find(t => t.summary.includes('C-control')).labels.includes('allowed-use-control'));
  // Labels are single words Jira accepts: a category with spaces and symbols is folded.
  const [spaced] = ticketsFor({ id: 'r', applicationId: 'app', policyHash: 'p', results: [{ id: 'C-1', title: 't', status: 'fail', severity: 'high', category: 'Sessions & cache' }] });
  assert.ok(spaced.labels.includes('category-sessions-cache') && spaced.labels.every(l => /^[a-z0-9._-]+$/.test(l)), JSON.stringify(spaced.labels));
  // The fixed lines come first and are never cut, and the run's limitations are carried.
  const long = { id: 'r', applicationId: 'app', policyHash: 'p', limitations: ['Effects are judged from the configured observers only.'], results: [{ id: 'C-1', title: 't', status: 'fail', severity: 'high', expected: 'x'.repeat(20000) }] };
  const [cutTicket] = ticketsFor(long);
  assert.ok(cutTicket.description.includes('not a safety certification') && cutTicket.description.length <= 8000);
  assert.ok(ticketsFor({ ...long, results: [{ ...long.results[0], expected: 'short' }] })[0].description.includes('Limitation: Effects are judged from the configured observers only.'));
});

test('the resolution decision on a validated comparison: each condition blocks on its own, and only core\'s repair transitions count', () => {
  const ok = { compatible: true, controlsPass: true, summary: { newFailures: 0 } };
  assert.equal(resolutionBlocker(ok, { transition: 'fixed' }), null);
  assert.match(resolutionBlocker({ ...ok, compatible: false }, {}), /not verified/);
  assert.match(resolutionBlocker({ ...ok, controlsPass: false }, {}), /not verified/);
  assert.match(resolutionBlocker({ ...ok, summary: { newFailures: 2 } }, {}), /2 new failure/);
  assert.match(resolutionBlocker({ ...ok, modelAttribution: { state: 'not-recorded', malformed: ['candidate'] } }, {}), /could not be read/);
  assert.equal(resolutionBlocker({ ...ok, modelAttribution: { state: 'not-recorded' } }, {}), null, 'no identity at all: nothing to attribute');
  // The pair and the row are each checked: either alone blocks.
  assert.match(resolutionBlocker({ ...ok, modelAttribution: { state: 'recorded', repairCreditedToApp: false } }, { attribution: 'app' }), /does not credit the repair/);
  assert.match(resolutionBlocker({ ...ok, modelAttribution: { state: 'recorded', repairCreditedToApp: true } }, { attribution: 'model' }), /credits this change to model/);
  assert.equal(resolutionBlocker({ ...ok, modelAttribution: { state: 'recorded', repairCreditedToApp: true } }, { attribution: 'app' }), null);
  // A repair blocked by failing controls is not a repair transition.
  assert.deepEqual(REPAIR_TRANSITIONS, ['fixed', 'contract-restored', 'local-control-restored']);
});
