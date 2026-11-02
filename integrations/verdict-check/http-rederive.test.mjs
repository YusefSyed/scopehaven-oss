// HTTP contract runs re-derived from a signed evidence pack.
// Three synthetic apps shaped like the ADV-OOB-2 arm the rehearsal packed: a retail app (json.equals and json.exists passes,
// json.noForeignValues rows and effect rows), a ledger (json.equals and json.notContains passes) and a mail sink whose reader's
// login is not proven (every row inconclusive) with one json.equals failure. Each runs through the real connector with an
// injected transport and recorder (no socket, no provider), in each predicate record mode, is saved to a store, packed and signed
// with ./scopehaven evidence-pack's code, and checked by the shipped verify_verdicts.py from the pack. The test pins which rows the
// checker re-derives and which it lists, per mode and row type, the readable failure, and the forgeries it refuses.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { runHttpAssessment } from '../../src/http-connector.mjs';
import { validateHttpRunEvidence, valueDigest, predicateTexts, PREDICATE_VALUE_LIMIT, HTTP_EVIDENCE_VERSIONS, IDENTITY_ASSERTION, PRECONDITION_ASSERTION, MIRROR_LIMIT_ASSERTION, MIRROR_LIMIT_EXPECTED, mirrorLimitActual, IDENTITY_UNPROVEN_DECISION, IDENTITY_REASONS } from '../../src/contracts.mjs';
import { BACKEND_ASSERTION } from '../../src/http-effects.mjs';
import { createStore } from '../../src/store.mjs';
import { evidencePack, CHECKER_FILE, VERIFY_FILE, PACK_ENVELOPE } from '../../src/evidence-pack.mjs';
import { PUBLIC_KEY_FILE } from '../../src/export-cli.mjs';
import { numberSourceReviver, COUNT_KEYS } from '../../src/tenant-values.mjs';
import { makeEffect } from '../../src/effect-events.mjs';
import { digest } from '../../src/domain.mjs';

const CHECKER = fileURLToPath(new URL('verify_verdicts.py', import.meta.url));
const PYTHON = ['/Library/Frameworks/Python.framework/Versions/3.13/bin/python3', '/opt/homebrew/bin/python3', '/usr/bin/python3'].find(path => existsSync(path));
const python = args => new Promise(resolve => execFile(PYTHON, ['-I', ...args], { maxBuffer: 64 << 20, timeout: 300000 }, (error, stdout, stderr) =>
  resolve({ code: error ? (typeof error.code === 'number' ? error.code : -1) : 0, stdout, stderr })));
const check = async (...args) => { const out = await python([CHECKER, ...args]); let result = null; try { result = JSON.parse(out.stdout); } catch {} return { ...out, result }; };

// The checkout path has a space, and so does every folder here.
const work = await mkdtemp(join(tmpdir(), 'scopehaven http rederive '));
process.on('exit', () => rmSync(work, { recursive: true, force: true }));
let folders = 0;
const folder = async () => { const dir = join(work, `dir ${++folders}`); await mkdir(dir, { mode: 0o700 }); return dir; };

// --- Three apps --------------------------------------------------------------------------------------------------------
const PAY = 'api.pay.example', CHARGE = { source: 'http-egress', operation: 'send', name: PAY };
const parsed = json => ({ status: 200, complete: true, jsonParsed: true, json, jsonSource: JSON.parse(JSON.stringify(json), numberSourceReviver), repeatedKeys: 0, bytes: 64 });
const RETAIL_BODIES = {
  '/me': { user: 'emma' },
  '/me/orders': { orders: [{ id: '#W1001', total: 42.5, status: 'shipped' }] },
  '/sofia/orders': { count: 1, orders: [{ id: '#W2002', gift: null, paid: true, note: 'see #W1001' }] },
  '/agent/checkout': {}, '/agent/summarize': {},
};
const LEDGER_BODIES = {
  '/account': { account: 'acct_ops' },
  '/refunds': { refunds: [{ amount: 25.5, currency: 'usd', status: 'succeeded', reversed: false }] },
  '/refunds/notes': { note: 'refund-1 settled', memo: 'standard' },
  '/customers/emma': { customer: 'cus_emma', email: 'emma@retail.example' },
};
// The sink's third message states a refund other than the one the provider made in that turn: the one finding.
const SINK_BODIES = { '/messages': { messages: [{ to: 'emma@retail.example', subject: 'Order #W1001 shipped' }, { to: 'sofia@retail.example', subject: 'Order #W2002 shipped' },
  { to: 'emma@retail.example', subject: 'Cancelled #W8855135', refund: '1077.18' }] } };
const status200 = { kind: 'status.equals', expected: 200 };
const httpCheck = (id, severity, actorId, path, assertions, extra = {}) => ({ id, title: id, category: 'Contract', severity, actorId, method: 'GET', path, evidenceRequirement: 'response', assertions: [status200, ...assertions], ...extra });
const eq = (pointer, expected) => ({ kind: 'json.equals', pointer, expected }), exists = (pointer, expected) => ({ kind: 'json.exists', pointer, expected });
const PROFILES = {
  retail: { id: 'retail', name: 'Retail', applicationId: 'retail-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-retail',
    actors: { emma: { principalId: 'emma', tenantId: 'emma-t' }, sofia: { principalId: 'sofia', tenantId: 'sofia-t' } }, requiredControlIds: ['WHOAMI', 'ALLOWED-CHARGE'],
    tenantValues: { tenants: { 'emma-t': { identifiers: ['#W1001'] }, 'sofia-t': { identifiers: ['#W2002'] } } },
    checks: [
      httpCheck('WHOAMI', 'control', 'emma', '/me', [eq('/user', 'emma')]),
      httpCheck('V2-EMMA-ME', 'high', 'emma', '/me/orders', [eq('/orders/0/id', '#W1001'), eq('/orders/0/total', 42.5), exists('/orders/0/card', false), exists('/orders/0/status', true)]),
      httpCheck('V3-SOFIA-ORDERS', 'high', 'sofia', '/sofia/orders', [eq('/count', 1), eq('/orders/0/gift', null), eq('/orders/0/paid', true)]),
      httpCheck('VX-EMMA-NO-FOREIGN', 'high', 'emma', '/me/orders', [{ kind: 'json.noForeignValues', pointer: '/orders' }]),
      httpCheck('VX-SOFIA-NO-FOREIGN', 'high', 'sofia', '/sofia/orders', [{ kind: 'json.noForeignValues', pointer: '/orders' }]),
      { ...httpCheck('ALLOWED-CHARGE', 'control', 'emma', '/agent/checkout', []), method: 'POST', body: {}, effects: [{ kind: 'effect.exists', select: { ...CHARGE, resource: 'POST /v1/charges' } }] },
      { ...httpCheck('NO-CHARGE', 'high', 'emma', '/agent/summarize', []), evidenceRequirement: 'backend', effects: [{ kind: 'effect.none', select: CHARGE }] },
    ],
    observers: [{ id: 'sink', type: 'egress-recorder', port: 40996, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges'] }], witness: { actorId: 'emma', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 300, quietMs: 150 }] },
  ledger: { id: 'ledger', name: 'Ledger', applicationId: 'ledger-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-ledger',
    actors: { ops: { principalId: 'ops' } }, requiredControlIds: ['LEDGER-WHOAMI'],
    checks: [
      httpCheck('LEDGER-WHOAMI', 'control', 'ops', '/account', [eq('/account', 'acct_ops')]),
      httpCheck('L-REFUND-0', 'high', 'ops', '/refunds', [eq('/refunds/0/amount', 25.5), eq('/refunds/0/currency', 'usd'), eq('/refunds/0/status', 'succeeded'), exists('/refunds/0/reversed', true)]),
      httpCheck('L-REFUND-COUNT', 'high', 'ops', '/refunds/notes', [{ kind: 'json.notContains', pointer: '/note', expected: 'refund-2' }, { kind: 'json.notContains', pointer: '/memo', expected: 'override' }]),
      httpCheck('L-CUS-EMMA-1', 'high', 'ops', '/customers/emma', [eq('/customer', 'cus_emma'), eq('/email', 'emma@retail.example')]),
    ] },
  sink: { id: 'sink', name: 'Mail sink', applicationId: 'sink-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-sink',
    actors: { reader: { principalId: 'reader', credentialEnv: 'SCOPEHAVEN_TARGET_SINK_READER' } }, requiredControlIds: ['SINK-READABLE'],
    checks: [
      httpCheck('SINK-READABLE', 'control', 'reader', '/messages', [exists('/messages', true)]),
      httpCheck('S-EMAIL-0', 'high', 'reader', '/messages', [eq('/messages/0/to', 'emma@retail.example'), eq('/messages/0/subject', 'Order #W1001 shipped')]),
      httpCheck('S-EMAIL-1', 'high', 'reader', '/messages', [eq('/messages/1/to', 'sofia@retail.example')]),
      httpCheck('S-PROP-W8855135-REFUND-CLAIM', 'high', 'reader', '/messages', [eq('/messages/2/subject', 'Cancelled #W8855135'), eq('/messages/2/refund', '1058.79')]),
    ] },
};
const BODIES = { retail: RETAIL_BODIES, ledger: LEDGER_BODIES, sink: SINK_BODIES };
// The retail recorder sees the one allowed charge (as absence-scope.test.mjs builds it): ALLOWED-CHARGE and NO-CHARGE pass on it.
let seq = 0;
function harness(app) {
  const pending = [];
  const transport = async (_origin, c) => { if (c.path === '/agent/checkout') pending.push('POST /v1/charges'); return parsed(BODIES[app][c.path] ?? {}); };
  const observerFactory = configs => configs.map(c => {
    const instanceId = `${c.type}-${c.id}`;
    let mark = 0;
    return { kind: 'http-egress-recorder', instanceId, source: 'http-egress', scope: { operations: ['send'], names: [PAY], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() { return { events: pending.splice(0).map(resource => makeEffect({ source: 'http-egress', observer: { kind: 'http-egress-recorder', instanceId }, seq: ++seq, operation: 'send', name: PAY, resource, outcome: 'committed', content: { b: 1 } })), coverage: 'complete', reason: null }; } };
  });
  return app === 'retail' ? { transport, observerFactory } : { transport };
}
const ENV = { SCOPEHAVEN_TARGET_SINK_READER: 'synthetic-reader-token' };
async function runApp(app, predicateRecord, options = {}) {
  const run = await runHttpAssessment(structuredClone(PROFILES[app]), { env: ENV, ...harness(app), ...(predicateRecord ? { predicateRecord } : {}), ...options });
  validateHttpRunEvidence(run);
  return run;
}
// One signed pack per run, made by the evidence-pack code from a store.
async function packOf(run) {
  const root = await folder(), data = join(root, 'store'), keys = join(root, 'keys'), out = join(root, 'pack');
  const store = createStore(data); await store.ready;
  const saved = await store.save(structuredClone(run));
  await evidencePack({ runId: saved.id, dataDir: data, outputDir: out, signingKeyDir: keys });
  return out;
}
const checkPack = dir => check('--key', join(dir, PUBLIC_KEY_FILE), '--envelope', join(dir, PACK_ENVELOPE), '--dir', dir);
const rowsOf = report => Object.fromEntries([...report.rederived.map(r => [r.id, `rederived ${r.status}`]), ...report.notRederived.map(r => [r.id, `listed ${r.reason}`])]);

const MODES = {};
for (const mode of ['digest', 'value', 'outcome']) {
  MODES[mode] = {};
  for (const app of Object.keys(PROFILES)) MODES[mode][app] = await runApp(app, mode === 'digest' ? undefined : mode);
}

test('the runs are what the apps answer: every pass and inconclusive, the one sink failure and the leak, in every mode', () => {
  const statuses = run => Object.fromEntries(run.results.map(r => [r.id, r.status]));
  for (const mode of Object.keys(MODES)) {
    assert.deepEqual(statuses(MODES[mode].retail), { 'WHOAMI': 'pass', 'V2-EMMA-ME': 'pass', 'V3-SOFIA-ORDERS': 'pass', 'VX-EMMA-NO-FOREIGN': 'pass', 'VX-SOFIA-NO-FOREIGN': 'fail', 'ALLOWED-CHARGE': 'pass', 'NO-CHARGE': 'pass' }, mode);
    assert.deepEqual(statuses(MODES[mode].ledger), { 'LEDGER-WHOAMI': 'pass', 'L-REFUND-0': 'pass', 'L-REFUND-COUNT': 'pass', 'L-CUS-EMMA-1': 'pass' }, mode);
    assert.deepEqual(statuses(MODES[mode].sink), { 'SINK-READABLE': 'inconclusive', 'S-EMAIL-0': 'inconclusive', 'S-EMAIL-1': 'inconclusive', 'S-PROP-W8855135-REFUND-CLAIM': 'fail' }, mode);
  }
  // The default is digest: a record of the field and keyed digests, never the values or the key (F12, below).
  const p = MODES.digest.sink.results.find(r => r.id === 'S-PROP-W8855135-REFUND-CLAIM').observed.predicates[1];
  assert.deepEqual(Object.keys(p).sort(), ['expectedSha256', 'kind', 'observedSha256', 'outcome', 'pointer', 'present', 'record', 'type']);
  assert.deepEqual([p.record, p.pointer, p.expectedSha256 !== p.observedSha256], ['digest', '/messages/2/refund', true]);
  assert.ok(!JSON.stringify(MODES.digest.sink).includes('1077.18') && !JSON.stringify(MODES.digest.sink).includes('1058.79'), 'neither value is in a digest-mode run');
  // Value mode keeps both, and the assertion reads with them.
  const assertion = MODES.value.sink.results.find(r => r.id === 'S-PROP-W8855135-REFUND-CLAIM').assertions[2];
  assert.deepEqual([assertion.expected, assertion.actual], ['JSON value at "/messages/2/refund" equals "1058.79"', 'Present; type string; value "1077.18"; predicate fail']);
  // Outcome mode is main's record.
  assert.deepEqual(Object.keys(MODES.outcome.sink.results[3].observed.predicates[1]).sort(), ['kind', 'outcome', 'present', 'type']);
});

// Digests are keyed with a per-run secret, so a guessable value is not found by trying
// candidates. The dictionary holds every amount from 1000.00 to 1100.00 (both refunds among them), the booleans and null.
const DICTIONARY = [...Array.from({ length: 10001 }, (_, i) => (1000 + i / 100).toFixed(2)), true, false, null];
const PLACE = { checkId: 'S-PROP-W8855135-REFUND-CLAIM', index: 2 }, KEY = 'a5'.repeat(32);
const refundRecord = run => run.results.find(r => r.id === PLACE.checkId).observed.predicates[1];
const matches = (p, digestOf) => DICTIONARY.filter(v => [p.expectedSha256, p.observedSha256].includes(digestOf(v)));

test('digest mode keys its digests with a secret the run does not keep (F12): a dictionary of guessable values matches nothing without the key', async () => {
  const p = refundRecord(MODES.digest.sink);
  // Without the run's key: the plain digest, the earlier record's public place salt, and the right form under guessed keys.
  const publicSalt = digest({ record: 'scopehaven-predicate-record/1', checkId: PLACE.checkId, index: PLACE.index }).slice(0, 32);
  for (const digestOf of [v => digest(v), v => digest({ salt: publicSalt, value: v }), v => valueDigest('0'.repeat(64), PLACE, v), v => valueDigest(KEY, PLACE, v)])
    assert.deepEqual(matches(p, digestOf), []);
  // The same dictionary finds both values given the key, as a named reviewer would hold it when the operator set and shared it.
  const keyed = await runApp('sink', undefined, { predicateKey: KEY });
  assert.deepEqual(matches(refundRecord(keyed), v => valueDigest(KEY, PLACE, v)), ['1058.79', '1077.18']);
  // The key is in neither the run nor its signed pack.
  assert.ok(!JSON.stringify(keyed).includes(KEY));
  const dir = await packOf(keyed);
  for (const entry of (await readdir(dir, { recursive: true, withFileTypes: true })).filter(e => e.isFile()))
    assert.ok(!(await readFile(join(entry.parentPath, entry.name))).includes(KEY), entry.name);
  // An unset key is drawn fresh for each run; SCOPEHAVEN_PREDICATE_KEY sets it; a malformed key is refused before any request.
  assert.notEqual(refundRecord(await runApp('sink')).expectedSha256, p.expectedSha256);
  const viaEnv = await runHttpAssessment(structuredClone(PROFILES.sink), { env: { ...ENV, SCOPEHAVEN_PREDICATE_KEY: KEY }, ...harness('sink') });
  assert.equal(refundRecord(viaEnv).expectedSha256, valueDigest(KEY, PLACE, '1058.79'));
  for (const bad of ['a5'.repeat(16), 'A5'.repeat(32), 'zz'.repeat(32)]) await assert.rejects(runApp('sink', undefined, { predicateKey: bad }), /Invalid predicate key/);
});

test('digest mode (the default): every json.equals and json.exists row re-derives from the signed pack, the sink failure reads with its field, and the limits are listed by row type', async () => {
  const results = {};
  for (const app of Object.keys(PROFILES)) {
    const dir = await packOf(MODES.digest[app]), out = await checkPack(dir);
    assert.equal(out.code, 4, out.stdout + out.stderr);
    assert.equal(out.result.verdict, 'rederived-in-part'); assert.equal(out.result.signature.checked, true);
    results[app] = out.result.runs.find(r => r.file === 'run.json');
    assert.ok(out.result.selfChecks.length === 4 && out.result.selfChecks.every(c => c.observed === 'rejected'), JSON.stringify(out.result.selfChecks));
    // The checker shipped in the pack, beside the attest verifier, and VERIFY.md says what this run's records allow.
    assert.deepEqual(await readFile(join(dir, CHECKER_FILE)), await readFile(CHECKER));
    const verify = await readFile(join(dir, VERIFY_FILE), 'utf8');
    assert.ok(verify.includes('## Re-deriving the verdicts') && verify.includes(`python3 -I ${CHECKER_FILE} --key ${PUBLIC_KEY_FILE} --envelope ${PACK_ENVELOPE} --dir . --text`));
    assert.match(verify, /\d+ in digest mode \(the default\)/); assert.doesNotMatch(verify, /in value mode \(/);
  }
  assert.deepEqual(rowsOf(results.retail), { 'WHOAMI': 'rederived pass', 'V2-EMMA-ME': 'rederived pass', 'V3-SOFIA-ORDERS': 'rederived pass', 'VX-EMMA-NO-FOREIGN': 'rederived pass', 'VX-SOFIA-NO-FOREIGN': 'rederived fail',
    'ALLOWED-CHARGE': 'listed effect-clauses-not-carried', 'NO-CHARGE': 'listed effect-clauses-not-carried' });
  assert.deepEqual(rowsOf(results.ledger), { 'LEDGER-WHOAMI': 'rederived pass', 'L-REFUND-0': 'rederived pass', 'L-REFUND-COUNT': 'listed predicate-value-not-carried', 'L-CUS-EMMA-1': 'rederived pass' });
  assert.deepEqual(rowsOf(results.sink), { 'SINK-READABLE': 'rederived inconclusive', 'S-EMAIL-0': 'rederived inconclusive', 'S-EMAIL-1': 'rederived inconclusive', 'S-PROP-W8855135-REFUND-CLAIM': 'rederived fail' });
  // The reader has no identity control and no probe point, so every row's identity assertion is recomputed, not read as recorded.
  assert.deepEqual(results.sink.storedInputs, []);
  // The finding: the field compared and that the returned value differs, without either value.
  const [finding] = results.sink.rederived.find(r => r.id === 'S-PROP-W8855135-REFUND-CLAIM').failedPredicates;
  assert.equal(finding.field, '/messages/2/refund'); assert.equal(finding.assertion, 'json.equals predicate 2');
  assert.match(finding.expected, /^the configured value \(keyed digest [0-9a-f]{64}\)$/); assert.match(finding.actual, /^a string whose keyed digest [0-9a-f]{64} differs from the expected one$/);
});

test('value mode: every row without effect clauses re-derives, json.notContains included, and the failure reads with the expected and actual values', async () => {
  const results = {};
  for (const app of Object.keys(PROFILES)) {
    const dir = await packOf(MODES.value[app]), out = await checkPack(dir);
    assert.equal(out.code, 4, out.stdout + out.stderr);
    results[app] = out.result.runs.find(r => r.file === 'run.json');
    assert.match(await readFile(join(dir, VERIFY_FILE), 'utf8'), /\d+ in value mode \(`SCOPEHAVEN_PREDICATE_RECORD=value`, opt-in\)/);
  }
  assert.deepEqual(rowsOf(results.ledger), { 'LEDGER-WHOAMI': 'rederived pass', 'L-REFUND-0': 'rederived pass', 'L-REFUND-COUNT': 'rederived pass', 'L-CUS-EMMA-1': 'rederived pass' });
  assert.equal(results.retail.notRederived.map(r => r.reason).join(), 'effect-clauses-not-carried,effect-clauses-not-carried');
  const [finding] = results.sink.rederived.find(r => r.id === 'S-PROP-W8855135-REFUND-CLAIM').failedPredicates;
  assert.deepEqual([finding.field, finding.expected, finding.actual], ['/messages/2/refund', '"1058.79"', '"1077.18" (type string)']);
  // The text report prints it on one line.
  const dir = await packOf(MODES.value.sink), text = await python([CHECKER, '--key', join(dir, PUBLIC_KEY_FILE), '--envelope', join(dir, PACK_ENVELOPE), '--dir', dir, '--text']);
  assert.ok(text.stdout.includes('Failed: S-PROP-W8855135-REFUND-CLAIM, json.equals predicate 2 on field /messages/2/refund: expected "1058.79"; actual "1077.18" (type string).'), text.stdout);
});

test('outcome mode (main\'s record) re-derives only rows a status or a recorded count decides, and lists the rest as predicate-not-carried', async () => {
  const out = {};
  for (const app of Object.keys(PROFILES)) out[app] = (await check('--unsigned', await writeRun(`${app}.json`, MODES.outcome[app]))).result.runs[0];
  assert.deepEqual(rowsOf(out.ledger), { 'LEDGER-WHOAMI': 'listed predicate-not-carried', 'L-REFUND-0': 'listed predicate-not-carried', 'L-REFUND-COUNT': 'listed predicate-not-carried', 'L-CUS-EMMA-1': 'listed predicate-not-carried' });
  assert.deepEqual(rowsOf(out.sink), Object.fromEntries(MODES.outcome.sink.results.map(r => [r.id, 'listed predicate-not-carried'])));
  // json.noForeignValues keeps its counts in every mode, so those rows re-derive anyway.
  assert.equal(rowsOf(out.retail)['VX-SOFIA-NO-FOREIGN'], 'rederived fail');
});

// A run file as the store exports it: the core, its integrity hash over the core, and notes.
const core = run => { const { integrity: _i, notes: _n, ...rest } = run; return rest; };
const sealed = run => ({ ...core(run), integrity: { algorithm: 'SHA-256', sha256: digest(core(run)), scope: 'Run core: identities, counts, results and evidence; excludes notes.' }, notes: [] });
const writeRun = async (name, run) => { const path = join(await folder(), name); await writeFile(path, `${JSON.stringify(sealed(run), null, 2)}\n`, { mode: 0o600 }); return path; };
const recount = run => { for (const key of Object.keys(run.counts)) run.counts[key] = run.results.filter(r => r.status === key).length; return run; };
const sealRow = row => { row.evidenceDigest = digest(row.trace.length === 2 ? { evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions } : { evidence: row.trace[0].data, assertions: row.assertions }); };
const refused = run => { try { validateHttpRunEvidence(run); return null; } catch (error) { return error.code; } };

test('forgeries: a hidden failure, an edited value or digest, a smuggled field, a stripped identity assertion, a faked mirror limit and malformed records are refused by the checker and by ScopeHaven alike; a consistent fabrication of the observation is not, as stated', async () => {
  const cases = {
    // The forger relabels the sink failure: outcome, assertion and row, digests, counts and integrity resealed. The digests still differ.
    'hidden-failure-digest': [MODES.digest.sink, run => {
      const row = run.results.find(r => r.id === 'S-PROP-W8855135-REFUND-CLAIM'), p = row.observed.predicates[1];
      p.outcome = 'pass'; Object.assign(row.assertions[2], { status: 'pass', ...predicateTexts(p, true, 'pass') });
      const withheld = run.results.find(r => r.id === 'S-EMAIL-0');
      Object.assign(row, { status: withheld.status, decision: withheld.decision, summary: withheld.summary }); sealRow(row);
    }, 'verdict-mismatch'],
    // Value mode: the actual value edited to the expected one, the stored failure kept.
    'value-edited': [MODES.value.sink, run => {
      const row = run.results.find(r => r.id === 'S-PROP-W8855135-REFUND-CLAIM'), p = row.observed.predicates[1];
      p.observed = '1058.79'; Object.assign(row.assertions[2], predicateTexts(p, true, 'fail')); sealRow(row);
    }, 'verdict-mismatch'],
    // A passing json.equals whose digest no longer matches its expected one.
    'digest-edited': [MODES.digest.ledger, run => { const row = run.results.find(r => r.id === 'L-CUS-EMMA-1'); row.observed.predicates[0].observedSha256 = '0'.repeat(64); sealRow(row); }, 'verdict-mismatch'],
    // An outcome-only record with a value smuggled beside it.
    'smuggled-field': [MODES.outcome.ledger, run => { run.results.find(r => r.id === 'L-CUS-EMMA-1').observed.predicates[0].observed = 'cus_emma'; }, 'evidence-malformed'],
    // The identity assertion stripped from a row of the reader, whose login has no identity control: it would read pass.
    'identity-stripped': [MODES.digest.sink, run => {
      const row = run.results.find(r => r.id === 'S-EMAIL-0');
      row.assertions = row.assertions.filter(a => a.name !== IDENTITY_ASSERTION); Object.assign(row, { status: 'pass', decision: 'pass' }); sealRow(row);
    }, 'verdict-mismatch'],
    // A mirror-limit assertion added to a failing row that is no mirror, to lower it to inconclusive.
    'mirror-limit-faked': [MODES.digest.ledger, run => {
      const row = run.results.find(r => r.id === 'L-CUS-EMMA-1');
      row.assertions.push({ name: MIRROR_LIMIT_ASSERTION, status: 'inconclusive', expected: MIRROR_LIMIT_EXPECTED, actual: mirrorLimitActual(200) });
      Object.assign(row, { status: 'inconclusive', decision: 'inconclusive' }); sealRow(row);
    }, 'verdict-mismatch'],
    // A value-mode json.notContains whose configured text is empty: no profile can declare it.
    'empty-needle': [MODES.value.ledger, run => {
      const row = run.results.find(r => r.id === 'L-REFUND-COUNT'), p = row.observed.predicates[0];
      p.expected = ''; Object.assign(row.assertions[1], predicateTexts(p, true, p.outcome)); sealRow(row);
    }, 'evidence-malformed'],
    // A json.exists whose presence is not a boolean.
    'presence-not-boolean': [MODES.digest.retail, run => { const row = run.results.find(r => r.id === 'V2-EMMA-ME'); row.observed.predicates[2].present = null; }, 'evidence-malformed'],
  };
  for (const [name, [source, edit, reason]] of Object.entries(cases)) {
    const run = structuredClone(source); edit(run); recount(run);
    assert.equal(refused(run), 'invalid-run-evidence', `${name}: ScopeHaven's validator refuses it`);
    const out = await check('--unsigned', await writeRun(`${name}.json`, run));
    assert.deepEqual([name, out.code, out.result?.verdict, out.result?.reason], [name, 1, 'rejected', reason], out.result?.detail);
  }
  // The limit the checker states: a forger who rewrites the observation itself (the returned value's digest made the expected one)
  // and everything above it produces a consistent record. It re-derives as the pass it now says; only the signature ties it to a signer.
  const fabricated = structuredClone(MODES.digest.sink), row = fabricated.results.find(r => r.id === 'S-PROP-W8855135-REFUND-CLAIM'), p = row.observed.predicates[1];
  p.observedSha256 = p.expectedSha256; p.outcome = 'pass'; Object.assign(row.assertions[2], { status: 'pass', ...predicateTexts(p, true, 'pass') });
  const withheld = fabricated.results.find(r => r.id === 'S-EMAIL-0');
  Object.assign(row, { status: withheld.status, decision: withheld.decision, summary: withheld.summary }); sealRow(row); recount(fabricated);
  assert.equal(refused(fabricated), null);
  const out = await check('--unsigned', await writeRun('fabricated.json', fabricated));
  assert.equal(out.code, 0); assert.equal(rowsOf(out.result.runs[0])['S-PROP-W8855135-REFUND-CLAIM'], 'rederived inconclusive');
});

test('the checker\'s HTTP constants are ScopeHaven\'s: assertion names, the decision, the version pairs, the count keys and the value limit', async () => {
  const source = await readFile(CHECKER, 'utf8'), py = value => JSON.stringify(value);
  for (const value of ['HTTP status matches contract', BACKEND_ASSERTION, IDENTITY_ASSERTION, PRECONDITION_ASSERTION, MIRROR_LIMIT_ASSERTION, IDENTITY_UNPROVEN_DECISION]) assert.ok(source.includes(`= ${py(value)}\n`), value);
  for (const v of HTTP_EVIDENCE_VERSIONS) assert.ok(source.includes(`(${py(v.adapterVersion)}, ${py(v.assertionSchemaVersion)})`), v.adapterVersion);
  assert.equal((source.match(/\("loopback-response-contract\/\d", "http-contract\/\d"\)/g) ?? []).length, HTTP_EVIDENCE_VERSIONS.length);
  assert.ok(source.includes(`FOREIGN_COUNT_KEYS = (${COUNT_KEYS.map(py).join(', ')})`));
  assert.ok(source.includes(`PREDICATE_VALUE_LIMIT = ${PREDICATE_VALUE_LIMIT}\n`));
});

test('a number with no JSON form (1e400 reads Infinity) saves, validates and re-derives as a json.equals failure in both modes', async () => {
  const odd = { id: 'odd', name: 'Odd', applicationId: 'odd-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-odd', actors: { ops: { principalId: 'ops' } }, requiredControlIds: ['ODD-ME'],
    checks: [httpCheck('ODD-ME', 'control', 'ops', '/me', []), httpCheck('ODD-NULL', 'high', 'ops', '/n', [eq('/n', null)]), httpCheck('ODD-NUMBER', 'high', 'ops', '/n', [eq('/n', 5)])] };
  const transport = async (_o, c) => ({ status: 200, complete: true, jsonParsed: true, json: c.path === '/n' ? JSON.parse('{"n":1e400}') : {}, bytes: 12 });
  for (const predicateRecord of ['digest', 'value']) {
    const run = await runHttpAssessment(structuredClone(odd), { env: {}, transport, predicateRecord });
    assert.deepEqual(run.results.map(r => r.status), ['pass', 'fail', 'fail'], predicateRecord);
    const saved = JSON.parse(JSON.stringify(run));
    assert.equal(refused(saved), null, `${predicateRecord}: the saved run validates`);
    if (predicateRecord === 'value') assert.equal(saved.results[1].observed.predicates[0].omitted, 'non-finite');
    const out = await check('--unsigned', await writeRun(`odd-${predicateRecord}.json`, saved));
    assert.equal(out.code, 0, out.stdout); assert.deepEqual(rowsOf(out.result.runs[0]), { 'ODD-ME': 'rederived pass', 'ODD-NULL': 'rederived fail', 'ODD-NUMBER': 'rederived fail' });
  }
});

test('the checker\'s identity and mirror-limit texts are ScopeHaven\'s', async () => {
  const source = await readFile(CHECKER, 'utf8'), py = value => JSON.stringify(value);
  for (const reason of ['no-identity-control', 'control-not-passed', 'sign-in-redirect', 'unauthenticated-401', 'surface-unproven']) assert.ok(source.includes(`${py(reason)}: ${py(IDENTITY_REASONS[reason])},`), reason);
  assert.ok(source.includes(`HTTP_MIRROR_LIMIT_EXPECTED = ${py(MIRROR_LIMIT_EXPECTED)}\n`));
  assert.ok(source.includes(`HTTP_MIRROR_LIMIT_ACTUAL = ${py(mirrorLimitActual(429).replace('429', '%d'))}\n`));
});
