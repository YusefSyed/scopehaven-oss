// Payments runs exportable and signed: a saved payments run (`payments run` writes <run-id>.json) is exported as
// json, html or sarif and signed by default exactly as `scopehaven export` signs (src/export-cli.mjs): a DSSE envelope beside
// each file with the local Ed25519 key, --unsigned to opt out, --signing-key-dir to override. The export copies every saved status
// and recomputes none, so it can never upgrade a label; a run edited after it was produced, or whose counts are not its rows', is
// refused before anything is written. Inputs are the checked-in sample runs (integrations/payments-pack/sample), so no app, double
// or socket runs here. Every file is written under a fresh private temporary directory, and every key directory is
// --signing-key-dir or a temporary HOME, never this user's ~/.config: its state is taken first and must be the same at the end.
import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { digest } from '../../src/domain.mjs';
import { defaultSigningKeyDir, KEY_FILE, PUBLIC_KEY_FILE, SIGNING_FAILED, signedEvidenceText } from '../../src/export-cli.mjs';
import { verifyEnvelope } from '../attest/verify.mjs';
import { comparePaymentsRuns, LLM06 } from './pack.mjs';
import { renderPaymentsReport, renderPaymentsSarif } from './report.mjs';
import { exportPaymentsRun, savedPaymentsRun, PAYMENTS_RUN_REFUSED } from './output.mjs';

const REAL_KEY_DIR = defaultSigningKeyDir();
const keyDirState = () => lstat(REAL_KEY_DIR).then(s => ({ ino: s.ino, mtimeMs: s.mtimeMs, mode: s.mode }), error => error.code);
const realBefore = await keyDirState();
const SAMPLE = name => fileURLToPath(new URL(`./sample/${name}`, import.meta.url));
const CLI = fileURLToPath(new URL('./cli.mjs', import.meta.url));
const PYTHON_VERIFIER = fileURLToPath(new URL('../attest/verify_envelope.py', import.meta.url));
const python = spawnSync('python3', ['--version'], { encoding: 'utf8' }).status === 0;
const KEYID = /^[0-9a-f]{64}$/;
// The vulnerable run fails three boundaries (no stored comparison); the repaired run passes every row and stores the comparison
// `payments run --baseline` wrote beside it.
const before = JSON.parse(await readFile(SAMPLE('before-vulnerable.json'), 'utf8'));
const afterSaved = JSON.parse(await readFile(SAMPLE('after-repaired.json'), 'utf8'));
const { comparison: storedComparison, ...after } = afterSaved;
const copy = value => structuredClone(value);
// An edited run with its checksum recomputed, as anyone can do: the unkeyed checksum stops a careless edit only.
const reseal = run => { const { sha256: _, ...body } = run; return { ...body, sha256: digest(body) }; };
const recount = run => ({ ...run, counts: Object.fromEntries(['pass', 'fail', 'inconclusive'].map(s => [s, run.rows.filter(r => r.status === s).length])) });
// The repaired run with one boundary withheld (not reached, partial window), resealed: a real inconclusive row.
const withheld = (() => {
  const run = copy(after), row = run.rows.find(r => r.severity === 'boundary');
  row.status = 'inconclusive'; row.coverage = 'partial'; row.coverageReason = 'witness-missing'; row.reach = { reached: false, basis: 'The app answered 502.' };
  row.assertions = row.assertions.map(a => ({ ...a, status: 'inconclusive' }));
  return reseal(recount(run));
})();

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven payments export '));
  t.after(() => rm(root, { recursive: true, force: true }));
  const out = join(root, 'exports'), keys = join(root, 'keys'), inputs = join(root, 'inputs');
  await mkdir(out, { mode: 0o700 }); await mkdir(inputs, { mode: 0o700 });
  return { root, out, keys, inputs };
}
const nodeVerify = async (publicKeyPath, envelopePath, dir) => {
  const name = envelopePath.slice(envelopePath.lastIndexOf('/') + 1, -'.dsse.json'.length);
  return verifyEnvelope({ envelope: await readFile(envelopePath), publicKey: await readFile(publicKeyPath, 'utf8'), files: new Map([[name, await readFile(join(dir, name))]]) });
};
const pythonVerify = (publicKeyPath, envelopePath, dir) => spawnSync('python3', ['-I', PYTHON_VERIFIER, '--key', publicKeyPath, '--envelope', envelopePath, '--dir', dir], { encoding: 'utf8' });
const cli = (args, env = {}) => spawnSync(process.execPath, [CLI, 'export', ...args], { encoding: 'utf8', env: { ...process.env, ...env } });
const mode = async path => (await stat(path)).mode & 0o777;
const exists = path => lstat(path).then(() => true, () => false);
// The throwaway test key's bodies must appear in none of the given texts (exports, envelopes, command output).
const pemBody = pem => pem.split('\n').filter(line => line && !line.startsWith('-----')).join('');
async function noKeyMaterial(keyDir, texts) {
  const privateBody = pemBody(await readFile(join(keyDir, KEY_FILE), 'utf8')), publicBody = pemBody(await readFile(join(keyDir, PUBLIC_KEY_FILE), 'utf8'));
  assert.ok(privateBody.length > 40 && publicBody.length > 40);
  for (const text of await Promise.all(texts)) {
    assert.doesNotMatch(text, /PRIVATE KEY/); assert.equal(text.includes(privateBody), false, 'no private key body');
    assert.equal(text.includes(publicBody), false, 'the public key travels as its own file, not inside the evidence');
  }
}

// Structural checks for the SARIF 2.1.0 subset src/sarif.mjs emits (as test/sarif-export.test.mjs checks it); not a schema validation.
const KINDS = ['pass', 'fail', 'open', 'review', 'notApplicable', 'informational'], LEVELS = ['none', 'note', 'warning', 'error'];
function sarifStructure(log) {
  assert.equal(log.version, '2.1.0'); assert.match(log.$schema, /^https:\/\/.+sarif-2\.1\.0\.json$/);
  assert.equal(log.runs.length, 1);
  const [run] = log.runs, { rules } = run.tool.driver;
  assert.equal(run.tool.driver.name, 'Scopehaven');
  assert.equal(new Set(rules.map(r => r.id)).size, rules.length);
  for (const rule of rules) {
    assert.ok(rule.shortDescription.text && rule.fullDescription.text && rule.help.text); assert.ok(LEVELS.includes(rule.defaultConfiguration.level));
    for (const relation of rule.relationships ?? []) {
      const taxonomy = run.taxonomies?.[relation.target.toolComponent.index];
      assert.equal(taxonomy?.name, relation.target.toolComponent.name); assert.equal(taxonomy.taxa[relation.target.index]?.id, relation.target.id); assert.deepEqual(relation.kinds, ['relevant']);
    }
  }
  run.logicalLocations.forEach((location, index) => { if (location.parentIndex !== undefined) assert.ok(location.parentIndex >= 0 && location.parentIndex < index); });
  assert.equal(typeof run.invocations[0].executionSuccessful, 'boolean');
  for (const result of run.results) {
    assert.equal(rules[result.ruleIndex].id, result.ruleId); assert.ok(KINDS.includes(result.kind)); assert.ok(LEVELS.includes(result.level));
    if (result.kind === 'fail') assert.notEqual(result.level, 'none'); else assert.equal(result.level, 'none');
    const [logical] = result.locations[0].logicalLocations;
    assert.equal(run.logicalLocations[logical.index].fullyQualifiedName, logical.fullyQualifiedName); assert.equal(logical.name, result.ruleId);
    assert.equal(result.locations[0].physicalLocation, undefined);
  }
  assert.doesNotMatch(JSON.stringify(log), /\/Users\/|\/home\/|[A-Za-z]:\\\\/);
  return run;
}

test('a payments run exports as json, html and sarif, each signed with one local key; both verifiers accept every envelope', async t => {
  const w = await workspace(t), results = {};
  for (const format of ['json', 'html', 'sarif']) results[format] = await exportPaymentsRun({ run: copy(afterSaved), format, outputFile: join(w.out, `run.${format}`), signingKeyDir: w.keys });
  assert.deepEqual((await readdir(w.out)).sort(), ['run.html', 'run.html.dsse.json', 'run.json', 'run.json.dsse.json', 'run.sarif', 'run.sarif.dsse.json']);
  const keyids = new Set();
  for (const [format, result] of Object.entries(results)) {
    assert.equal(result.saved, true); assert.equal(result.runId, after.id); assert.equal(result.format, format);
    assert.equal(result.signature.envelope, join(w.out, `run.${format}.dsse.json`)); assert.equal(result.signature.publicKey, join(w.keys, PUBLIC_KEY_FILE));
    assert.match(result.signature.keyid, KEYID); keyids.add(result.signature.keyid);
    assert.equal(await mode(join(w.out, `run.${format}`)), 0o600); assert.equal(await mode(result.signature.envelope), 0o600);
    assert.equal((await nodeVerify(result.signature.publicKey, result.signature.envelope, w.out)).verdict, 'verified', format);
    if (python) { const checked = pythonVerify(result.signature.publicKey, result.signature.envelope, w.out); assert.equal(checked.status, 0, `${format}: ${checked.stdout} ${checked.stderr}`); }
  }
  assert.equal(keyids.size, 1, 'one key signs every export');
  const [keyid] = keyids;
  assert.equal(await mode(w.keys), 0o700); assert.equal(await mode(join(w.keys, KEY_FILE)), 0o600);
  // json: the run record exactly as produced, without the comparison stored beside it (outside the run's checksum).
  assert.equal(await readFile(join(w.out, 'run.json'), 'utf8'), `${JSON.stringify(after, null, 2)}\n`);
  // html: the report with the "Signed evidence" stamp inside the signed bytes, before the closing tag; the newline stays last.
  const report = renderPaymentsReport(after, null), html = await readFile(join(w.out, 'run.html'), 'utf8');
  assert.ok(report.endsWith('</html>\n'));
  assert.equal(html, `${report.slice(0, -'</html>\n'.length)}<p class="signed-evidence">${signedEvidenceText(keyid, 'run.html.dsse.json').replace(/'/g, '&#39;')}</p></html>\n`);
  assert.doesNotMatch(html, /Before and after/, 'no stored comparison is rendered');
  // sarif: the projection of the run, plus the signing block naming the key id; nothing else.
  const sarif = JSON.parse(await readFile(join(w.out, 'run.sarif'), 'utf8')), expected = renderPaymentsSarif(after);
  expected.runs[0].properties.signing = { attest: 'scopehaven-attest/1', keyid, envelope: 'This file name with .dsse.json appended, beside this file.', meaning: 'A valid signature shows that the key holder produced these exact bytes, not that the results are correct.' };
  assert.deepEqual(sarif, expected);
  // No key material in any export or envelope; the public key travels as its own file (as test/export-signing.test.mjs checks).
  await noKeyMaterial(w.keys, (await readdir(w.out)).map(name => readFile(join(w.out, name), 'utf8')));
  assert.deepEqual(await keyDirState(), realBefore, 'the real key directory is untouched');
});

test('the SARIF copies each saved status (fail, pass, inconclusive as open) and never upgrades one; controls carry no standards tag', async () => {
  for (const run of [before, after, withheld]) {
    const log = renderPaymentsSarif(run), sarif = sarifStructure(log);
    assert.deepEqual(renderPaymentsSarif(copy(run)), log, 'deterministic');
    const kinds = { pass: 'pass', fail: 'fail', inconclusive: 'open' };
    sarif.results.forEach((result, index) => {
      const row = run.rows[index];
      assert.equal(result.ruleId, row.id); assert.equal(result.kind, kinds[row.status], `${row.id}: ${row.status}`);
      assert.equal(result.properties.scopehavenStatus, row.status); assert.equal(result.properties.verdictSource, 'provider-ledger');
      assert.equal(result.level, row.status === 'fail' ? (row.severity === 'boundary' ? 'error' : 'warning') : 'none');
      assert.match(result.message.text, new RegExp(`^${{ pass: 'PASS', fail: 'FAIL', inconclusive: 'INCONCLUSIVE' }[row.status]}: `));
      const rule = sarif.tool.driver.rules[index];
      if (row.severity === 'control') {
        assert.equal(rule.relationships, undefined); assert.deepEqual(rule.properties.standards.owaspLlm2025, []); assert.equal(rule.properties.checkRole, 'allowed-use-control');
        assert.deepEqual(rule.properties.tags, ['allowed-use-control', 'payments']);
      } else {
        assert.ok(row.standards.includes(LLM06)); assert.deepEqual(rule.properties.standards.owaspLlm2025, ['LLM06:2025']); assert.equal(rule.relationships[0].target.id, 'LLM06:2025');
        assert.deepEqual(rule.properties.tags, ['security', 'payments', 'OWASP-LLM06:2025']);
      }
      // The settlement caveat the HTML shows travels in the message too.
      for (const f of row.settlement) assert.ok(result.message.text.includes(`${f.code} on ${f.assertion}`), `${row.id}: ${f.code}`);
      if (row.severity === 'control' && row.settlement.length) assert.match(result.message.text, /Settlement tags: .*\(a control keeps its verdict\)\.$/);
    });
    assert.deepEqual(sarif.properties.counts, run.counts);
    assert.equal(sarif.properties.runId, run.id); assert.equal(sarif.properties.packSha256, run.packSha256); assert.equal(sarif.properties.evidenceIntegrity.sha256, run.sha256);
    assert.equal(sarif.properties.provider.livemode, false); assert.equal(sarif.properties.scope, run.scope);
    assert.equal(sarif.properties.certification, 'These are observed checks, not a safety certification.');
    // The agent's reply is not carried: no verdict rests on it.
    for (const row of run.rows) if (row.agentSaid) assert.ok(!JSON.stringify(log).includes(row.agentSaid), `${row.id}: the reply is not in the SARIF`);
  }
  const open = renderPaymentsSarif(withheld).runs[0].results.find(r => r.kind === 'open');
  assert.match(open.message.text, /Unverified assertions: .* Not reached: The app answered 502\. Window coverage: partial \(witness-missing\)\.$/);
  assert.equal(open.properties.reached, false); assert.equal(open.properties.coverage, 'partial');
  assert.equal(renderPaymentsSarif(before).runs[0].results.filter(r => r.kind === 'fail').length, 3);
});

test('a run edited after it was produced, one whose counts are not its rows, a live-mode or a non-payments run is refused before anything is written', async t => {
  const w = await workspace(t);
  const upgraded = copy(before); upgraded.rows.find(r => r.status === 'fail').status = 'pass';
  const miscounted = copy(before); miscounted.counts = { pass: 5, fail: 0, inconclusive: 0 };
  const live = copy(before); live.provider.livemode = true;
  const unknownStatus = copy(before); unknownStatus.rows[0].status = 'passed';
  // A run edited and resealed (anyone can recompute the unkeyed checksum) is still refused when it breaks the pack's own rules.
  const edit = (run, change) => { const next = copy(run); change(next); return reseal(recount(next)); };
  const boundary = run => run.rows.find(r => r.severity === 'boundary'), control = run => run.rows.find(r => r.severity === 'control');
  const cases = {
    'edited (a fail flipped to pass, checksum not recomputed)': upgraded,
    'counts not the rows, resealed': reseal(miscounted),
    'live mode, resealed': reseal(live),
    'an unknown status, resealed': reseal(recount(unknownStatus)),
    'not a payments run': { schemaVersion: 1, id: before.id, results: [] },
    'no rows, resealed': reseal({ ...copy(before), rows: [], counts: { pass: 0, fail: 0, inconclusive: 0 } }),
    'a fail flipped to pass with its failed assertion left, resealed': edit(before, run => { boundary(run).status = 'pass'; }),
    'a pass whose check request never reached the app, resealed': edit(after, run => { boundary(run).reach = { reached: false, basis: 'The app answered 502.' }; }),
    'a boundary pass a settlement finding withholds, resealed': edit(after, run => { const row = boundary(run); row.settlement = [{ code: 'effect-outside-window', detail: 'x', assertion: row.assertions[0].assertion, effect: 'withheld' }]; }),
    'a control settlement marked withheld, resealed': edit(before, run => { control(run).settlement[0].effect = 'withheld'; }),
    'an unknown assertion status, resealed': edit(after, run => { boundary(run).assertions[0].status = 'passed'; }),
    'a row without assertions, resealed': edit(after, run => { boundary(run).assertions = []; }),
    'a severity the pack does not write, resealed': edit(before, run => { boundary(run).severity = 'critical'; }),
    'duplicate check ids, resealed': edit(before, run => { run.rows[1].id = run.rows[0].id; }),
    'a run id the pack does not write, resealed': edit(before, run => { run.id = 'pay-edited'; }),
    'an extra field, resealed': edit(before, run => { run.note = 'added later'; }),
    'a missing field, resealed': edit(before, run => { delete run.settlement; }),
    'a rewritten scope, resealed': edit(before, run => { run.scope = 'Production assurance for live payments.'; }),
    'no finish time, resealed': edit(before, run => { run.finishedAt = 'later'; }),
  };
  for (const [label, run] of Object.entries(cases)) {
    assert.throws(() => savedPaymentsRun(run), error => error.code === PAYMENTS_RUN_REFUSED, label);
    for (const format of ['json', 'html', 'sarif'])
      await assert.rejects(exportPaymentsRun({ run, format, outputFile: join(w.out, `refused.${format}`), signingKeyDir: w.keys }), error => error.code === PAYMENTS_RUN_REFUSED, `${label} ${format}`);
  }
  // A good run as the candidate does not let an edited baseline through either.
  await assert.rejects(exportPaymentsRun({ run: copy(after), baseline: upgraded, format: 'json', outputFile: join(w.out, 'refused-comparison.json'), signingKeyDir: w.keys }), error => error.code === PAYMENTS_RUN_REFUSED);
  assert.deepEqual(await readdir(w.out), [], 'nothing was written');
  assert.equal(await exists(w.keys), false, 'a refused run makes no key');
});

test('with a baseline the comparison is recomputed from both runs, never taken from the run file; sarif takes no baseline', async t => {
  const w = await workspace(t);
  // A stored comparison is ignored: one forged to read "no verified repair" beside the repaired run changes nothing, and the export
  // carries the comparison computed from the two runs.
  const forgedAfter = { ...copy(after), comparison: { ...copy(storedComparison), verdict: 'no verified repair', reason: 'forged' } };
  const json = await exportPaymentsRun({ run: forgedAfter, baseline: copy(before), format: 'json', outputFile: join(w.out, 'comparison.json'), signingKeyDir: w.keys });
  const document = JSON.parse(await readFile(join(w.out, 'comparison.json'), 'utf8'));
  assert.deepEqual(document, comparePaymentsRuns(before, after));
  assert.equal(document.verdict, 'verified repair'); assert.equal(json.document, 'comparison'); assert.equal(json.baselineRunId, before.id);
  // A baseline is an earlier, different run: never the run itself (or an edited copy keeping its id), never one that finished after
  // the run started. Each is refused before anything is written.
  const failedCopy = copy(after);
  for (const row of failedCopy.rows.filter(r => r.severity === 'boundary')) { row.status = 'fail'; row.assertions = row.assertions.map(a => ({ ...a, status: 'fail' })); }
  const earlierCopy = { ...copy(failedCopy), startedAt: before.startedAt, finishedAt: before.finishedAt };
  for (const [label, run, baseline] of [['the run itself', after, after], ['an edited copy keeping the id', after, reseal(recount(failedCopy))],
    ['an edited copy keeping the id, its times moved earlier', after, reseal(recount(earlierCopy))], ['a baseline that finished after the run started', before, after]])
    await assert.rejects(exportPaymentsRun({ run: copy(run), baseline: copy(baseline), format: 'json', outputFile: join(w.out, 'refused.json'), sign: false }),
      error => error.code === PAYMENTS_RUN_REFUSED && /a different run that finished before this run started/.test(error.message), label);
  assert.equal(await exists(join(w.out, 'refused.json')), false);
  // Without a baseline a forged block is not exported at all.
  const forged = { ...copy(before), comparison: { ...copy(storedComparison), verdict: 'verified repair', reason: 'forged' } };
  await exportPaymentsRun({ run: forged, format: 'json', outputFile: join(w.out, 'forged.json'), signingKeyDir: w.keys });
  assert.equal(await readFile(join(w.out, 'forged.json'), 'utf8'), `${JSON.stringify(before, null, 2)}\n`);
  await exportPaymentsRun({ run: forged, format: 'html', outputFile: join(w.out, 'forged.html'), sign: false });
  assert.equal(await readFile(join(w.out, 'forged.html'), 'utf8'), renderPaymentsReport(before, null));
  // The real pair: the html report carries the recomputed before-and-after section.
  const html = await exportPaymentsRun({ run: copy(afterSaved), baseline: copy(before), format: 'html', outputFile: join(w.out, 'repair.html'), sign: false });
  assert.equal(html.document, 'report-with-comparison'); assert.equal(html.signature, null);
  assert.equal(await readFile(join(w.out, 'repair.html'), 'utf8'), renderPaymentsReport(after, comparePaymentsRuns(before, after)));
  assert.match(await readFile(join(w.out, 'repair.html'), 'utf8'), /Before and after <span class="badge" style="background:#1f7a3a">verified repair<\/span>/);
  await assert.rejects(exportPaymentsRun({ run: copy(after), baseline: copy(before), format: 'sarif', outputFile: join(w.out, 'x.sarif'), sign: false }), /Invalid export options/);
});

test('options: an absolute new file in a private directory, never overwritten; the library signs only when asked; a failed sign leaves no export', async t => {
  const w = await workspace(t), run = copy(after);
  const refusedOptions = [
    { format: 'pdf', outputFile: join(w.out, 'a.pdf') }, { format: 'json', outputFile: 'relative.json' }, { format: 'json', outputFile: join(w.out, 'a.json'), sign: 'yes' },
    { format: 'json', outputFile: join(w.out, 'a.json'), signingKeyDir: 'relative-keys' }, { format: 'json', outputFile: join(w.out, 'a.json'), signingKeyDir: w.keys, sign: false },
    { format: 'json', outputFile: join(w.out, 'has space.json'), signingKeyDir: w.keys },
  ];
  for (const options of refusedOptions) await assert.rejects(exportPaymentsRun({ run, ...options }), /Invalid export options/, JSON.stringify(options));
  const open = join(w.root, 'open'); await mkdir(open, { mode: 0o755 }); await chmod(open, 0o755);
  await assert.rejects(exportPaymentsRun({ run, format: 'json', outputFile: join(open, 'a.json'), signingKeyDir: w.keys }), /Export directory must be private/);
  await symlink(w.out, join(w.root, 'linked'));
  await assert.rejects(exportPaymentsRun({ run, format: 'json', outputFile: join(w.root, 'linked', 'a.json'), signingKeyDir: w.keys }), /Export directory must be private/);
  // An export over the size limit, and a run the renderer cannot read, are refused before any key is made.
  const large = copy(after); large.rows[0].ledger.sends = new Array(700000).fill(0);
  await assert.rejects(exportPaymentsRun({ run: reseal(large), format: 'json', outputFile: join(w.out, 'large.json'), signingKeyDir: w.keys }), /Export exceeds its limit/);
  const unreadable = copy(after); unreadable.rows[0].ledger.asks = {};
  await assert.rejects(exportPaymentsRun({ run: reseal(unreadable), format: 'html', outputFile: join(w.out, 'unreadable.html'), signingKeyDir: w.keys }),
    error => error.code === PAYMENTS_RUN_REFUSED && /could not be rendered/.test(error.message));
  assert.equal(await exists(w.keys), false, 'refused options make no key');
  // The library default is unsigned, as exportRun()'s is: no envelope, no key.
  const unsigned = await exportPaymentsRun({ run, format: 'json', outputFile: join(w.out, 'plain.json') });
  assert.equal(unsigned.signature, null); assert.equal(await exists(join(w.out, 'plain.json.dsse.json')), false); assert.equal(await exists(w.keys), false);
  // Never overwritten: an existing export stays as it was.
  await assert.rejects(exportPaymentsRun({ run, format: 'html', outputFile: join(w.out, 'plain.json'), sign: false }), /EEXIST/);
  assert.equal(await readFile(join(w.out, 'plain.json'), 'utf8'), `${JSON.stringify(after, null, 2)}\n`);
  // An envelope name already taken: the sign fails, the export it would have covered is removed, the other file is untouched.
  await writeFile(join(w.out, 'taken.sarif.dsse.json'), 'someone else\'s file', { mode: 0o600 });
  await assert.rejects(exportPaymentsRun({ run, format: 'sarif', outputFile: join(w.out, 'taken.sarif'), signingKeyDir: w.keys }), error => error.code === SIGNING_FAILED && /already exists/.test(error.message));
  assert.equal(await exists(join(w.out, 'taken.sarif')), false, 'no unsigned file that looks like the signed kind');
  assert.equal(await readFile(join(w.out, 'taken.sarif.dsse.json'), 'utf8'), 'someone else\'s file');
  assert.deepEqual(await keyDirState(), realBefore);
});

test('`payments export` signs by default under ~/.config/scopehaven/signing (a temporary HOME here), honours --unsigned, and exits 2 on a refusal', async t => {
  const w = await workspace(t), home = join(w.root, 'home');
  await mkdir(home, { mode: 0o700 });
  const first = cli(['--run', SAMPLE('after-repaired.json'), '--format', 'sarif', '--out', join(w.out, 'home.sarif')], { HOME: home });
  assert.equal(first.status, 0, first.stderr);
  const signed = JSON.parse(first.stdout), dir = join(home, '.config', 'scopehaven', 'signing');
  assert.equal(signed.signature.publicKey, join(dir, PUBLIC_KEY_FILE)); assert.match(signed.signature.keyid, KEYID);
  assert.equal(await mode(dir), 0o700); assert.equal(await mode(join(dir, KEY_FILE)), 0o600);
  assert.equal((await nodeVerify(signed.signature.publicKey, signed.signature.envelope, w.out)).verdict, 'verified');
  // The printed verify commands run as printed (paths with spaces are quoted).
  const printed = spawnSync('sh', ['-c', signed.signature.verify.node], { encoding: 'utf8', env: { ...process.env, PATH: `${join(process.execPath, '..')}:${process.env.PATH ?? ''}` } });
  assert.equal(printed.status, 0, printed.stdout + printed.stderr);
  // A second export under that HOME reuses the key.
  const second = cli(['--run', SAMPLE('after-repaired.json'), '--baseline', SAMPLE('before-vulnerable.json'), '--format', 'json', '--out', join(w.out, 'home-comparison.json')], { HOME: home });
  assert.equal(second.status, 0, second.stderr); assert.equal(JSON.parse(second.stdout).signature.keyid, signed.signature.keyid);
  // --unsigned: no envelope; --signing-key-dir: that directory's key.
  const plain = cli(['--run', SAMPLE('before-vulnerable.json'), '--format', 'html', '--out', join(w.out, 'plain.html'), '--unsigned'], { HOME: home });
  assert.equal(plain.status, 0, plain.stderr); assert.equal(JSON.parse(plain.stdout).signature, null); assert.equal(await exists(join(w.out, 'plain.html.dsse.json')), false);
  const own = cli(['--run', SAMPLE('before-vulnerable.json'), '--format', 'json', '--out', join(w.out, 'own.json'), '--signing-key-dir', w.keys], { HOME: home });
  assert.equal(own.status, 0, own.stderr); assert.equal(JSON.parse(own.stdout).signature.publicKey, join(w.keys, PUBLIC_KEY_FILE));
  // Refusals: exit 2, nothing new written.
  const listed = await readdir(w.out);
  const edited = copy(before); edited.rows.find(r => r.status === 'fail').status = 'pass';
  await writeFile(join(w.inputs, 'edited.json'), JSON.stringify(edited)); await symlink(SAMPLE('after-repaired.json'), join(w.inputs, 'linked.json'));
  for (const [args, pattern] of [
    [['--run', join(w.inputs, 'edited.json'), '--format', 'json', '--out', join(w.out, 'edited.json')], /payments-run-refused: the run was edited after it was produced/],
    [['--run', join(w.inputs, 'linked.json'), '--format', 'json', '--out', join(w.out, 'linked.json')], /not a readable JSON file/],
    [['--run', SAMPLE('after-repaired.json'), '--format', 'json', '--out', join(w.out, 'both.json'), '--unsigned', '--signing-key-dir', w.keys], /not both/],
    [['--run', SAMPLE('after-repaired.json'), '--format', 'json', '--out', join(w.out, 'twice.json'), '--unsigned', '--unsigned'], /Unsupported, repeated or incomplete option/],
    [['--run', SAMPLE('after-repaired.json'), '--format', 'sarif', '--baseline', SAMPLE('before-vulnerable.json'), '--out', join(w.out, 'c.sarif')], /export failed \(Invalid export options\.\)/],
    [['--run', SAMPLE('after-repaired.json'), '--format', 'json', '--out', join(w.out, 'own.json')], /EEXIST/],
  ]) {
    const result = cli(args, { HOME: home });
    assert.equal(result.status, 2, `${args.join(' ')}: ${result.stdout}`); assert.match(result.stderr, pattern); assert.equal(result.stdout, '');
  }
  // An unsafe key: a key directory others can read, or a private key others can read, is refused (exit 2), never repaired, and
  // no export is left.
  const loose = join(w.root, 'loose keys'); await mkdir(loose, { mode: 0o755 }); await chmod(loose, 0o755);
  const looseDir = cli(['--run', SAMPLE('after-repaired.json'), '--format', 'json', '--out', join(w.out, 'loose-dir.json'), '--signing-key-dir', loose], { HOME: home });
  assert.equal(looseDir.status, 2); assert.match(looseDir.stderr, /signing-key-unsafe/); assert.equal(await mode(loose), 0o755); assert.deepEqual(await readdir(loose), []);
  await chmod(join(w.keys, KEY_FILE), 0o644);
  const looseKey = cli(['--run', SAMPLE('after-repaired.json'), '--format', 'html', '--out', join(w.out, 'loose-key.html'), '--signing-key-dir', w.keys], { HOME: home });
  assert.equal(looseKey.status, 2); assert.match(looseKey.stderr, /signing-key-unsafe/); assert.equal(await mode(join(w.keys, KEY_FILE)), 0o644, 'never repaired');
  await chmod(join(w.keys, KEY_FILE), 0o600);
  assert.deepEqual((await readdir(w.out)).sort(), listed.sort(), 'no refusal wrote a file');
  // No key material in anything the command printed or wrote, for either key it used.
  const printedTexts = [first, second, plain, own, looseDir, looseKey].flatMap(r => [r.stdout, r.stderr]);
  for (const keyDir of [dir, w.keys]) await noKeyMaterial(keyDir, [...printedTexts, ...(await readdir(w.out)).map(name => readFile(join(w.out, name), 'utf8'))]);
  // The run command's parser is unchanged: --unsigned is not one of its options.
  const run = spawnSync(process.execPath, [CLI, 'run', '--config', SAMPLE('refund-agent.pack.json'), '--out', join(w.root, 'never'), '--unsigned'], { encoding: 'utf8' });
  assert.equal(run.status, 2); assert.match(run.stderr, /Unsupported, repeated or incomplete option/); assert.equal(await exists(join(w.root, 'never')), false);
  assert.deepEqual(await keyDirState(), realBefore, 'the real key directory is untouched');
});
