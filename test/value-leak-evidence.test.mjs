// Forbidden-value leak detection wired into the HTTP contract (src/contracts.mjs), the connector, the exported suite and
// saved-evidence validation. Each test covers the allowed and the forbidden side. Synthetic values, stub transports only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateTargetFile, contractDigest, evaluateHttpCheck, validateHttpRunEvidence } from '../src/contracts.mjs';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { createRegistry } from '../src/registry.mjs';
import { compareRuns } from '../src/runner.mjs';
import { TENANT_VALUES_LIMITATION } from '../src/http-scope-text.mjs';
import { TENANT_VALUE_LIMITS, foreignValuesActual, numberSourceReviver } from '../src/tenant-values.mjs';
import { digest } from '../src/domain.mjs';

const SECRET_VALUES = ['ORD-1001', 'Ada Lovelace', 'ada@acme.example', '42.50', 'ORD-2002', 'Lovelace', 'bob@globex.example', 'Blue Widget', '19.99', 'ORD-3003'];
const tenantValues = () => ({ tenants: {
  acme: { identifiers: ['ORD-1001', 'Ada Lovelace', 'ada@acme.example'], attributes: ['42.50'] },
  globex: { identifiers: ['ORD-2002', 'Lovelace', 'bob@globex.example'], attributes: ['Blue Widget', '19.99'] },
  initech: { identifiers: ['ORD-3003'], attributes: [] },
} });
const allow = { id: 'allow', title: 'Allowed', category: 'Access', severity: 'control', actorId: 'anon', method: 'GET', path: '/allowed', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] };
const chat = (extra = {}) => ({ id: 'chat', title: 'Assistant reply', category: 'Disclosure', severity: 'high', actorId: 'alice', method: 'POST', path: '/chat', body: { message: 'show me ORD-2002' },
  evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '/reply' }], ...extra });
const profile = (patch = {}) => ({ id: 'leak', name: 'Leak', applicationId: 'leak-app', origin: 'http://127.0.0.1:4318', buildLabel: 'b', contextId: 'ctx',
  actors: { anon: { principalId: 'anonymous' }, alice: { principalId: 'alice', tenantId: 'acme' } }, requiredControlIds: ['allow'], checks: [allow, chat()], tenantValues: tenantValues(), ...patch });
const validate = target => validateTargetFile({ schemaVersion: 1, targets: [target] })[0];
// A stub body as the connector reports it: the parsed tree, the tree with number source texts, and no repeated member name.
const parsed = json => ({ json, jsonSource: JSON.parse(JSON.stringify(json), numberSourceReviver), repeatedKeys: 0 });
const reply = text => async (origin, check) => ({ status: 200, complete: true, jsonParsed: true, ...parsed(check.path === '/allowed' ? {} : { reply: text }), bytes: 50 });
const suiteOf = target => createRegistry({ profiles: [target], env: {} }).exportSuite(target.id);
const refusal = fn => { try { fn(); } catch (error) { return error; } assert.fail('expected a refusal'); };
const chatRow = run => run.results.find(row => row.id === 'chat');

test('validation: every declaration error is refused, and no message carries a declared value or tenant id', () => {
  const cases = [
    ['kind without tenantValues', p => { delete p.tenantValues; }, /needs the target to declare "tenantValues"/],
    ['tenantValues used by no check', p => { p.checks = [allow]; }, /declared, but no check uses "json.noForeignValues"/],
    ['actor without tenantId', p => { delete p.actors.alice.tenantId; }, /actor to declare "tenantId"/],
    ['actor tenant not declared', p => { p.actors.alice.tenantId = 'hooli'; }, /one of the tenants in "tenantValues"/],
    ['one tenant', p => { p.tenantValues.tenants = { acme: p.tenantValues.tenants.acme }; }, /2 to 16 tenants/],
    ['seventeen tenants', p => { p.tenantValues.tenants = Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`t${i}`, { identifiers: [`VAL-${i}00`] }])); p.actors.alice.tenantId = 't0'; }, /2 to 16 tenants/],
    ['bad tenant key', p => { p.tenantValues.tenants['bad key!'] = { identifiers: ['ORD-9'] }; }, /tenant 4: a tenant id/],
    ['unsafe tenant key', p => { p.tenantValues.tenants = JSON.parse('{"acme":{"identifiers":["ORD-1001"]},"__proto__":{"identifiers":["ORD-2002"]}}'); }, /tenant 2: a tenant id/],
    ['tenant with no values', p => { p.tenantValues.tenants.initech = { identifiers: [], attributes: [] }; }, /tenant 3: declares no values/],
    ['513 values in one class', p => { p.tenantValues.tenants.initech.identifiers = Array.from({ length: 513 }, (_, i) => `ID-${i}00`); }, /at most 512 values/],
    ['2049 values in total', p => { for (const [k, key] of ['acme', 'globex', 'initech'].entries()) p.tenantValues.tenants[key] = { identifiers: Array.from({ length: 512 }, (_, i) => `I${k}-${i}00`), attributes: Array.from({ length: k === 2 ? 1 : 512 }, (_, i) => `A${k}-${i}00`) }; }, /at most 2048 values in total/],
    ['a number', p => { p.tenantValues.tenants.globex.attributes.push(30); }, /tenant 2 attribute 3: a value must be a string/],
    ['a control character', p => { p.tenantValues.tenants.globex.identifiers.push('ORD\u00072002'); }, /tenant 2 identifier 4: a value has no control characters/],
    ['too short', p => { p.tenantValues.tenants.globex.identifiers.push(' a\u200b '); }, /a value must be 3 to 200 characters/],
    ['too long', p => { p.tenantValues.tenants.globex.identifiers.push('Z'.repeat(201)); }, /a value must be 3 to 200 characters/],
    ['no letter or digit', p => { p.tenantValues.tenants.globex.identifiers.push('---'); }, /at least one letter or digit/],
    ['duplicate in the loose reading within a tenant', p => { p.tenantValues.tenants.globex.attributes.push('ord 2002'); }, /tenant 2 attribute 3: duplicates another value/],
    ['a value NFKC changes (compatibility forms, decomposed accents)', p => { p.tenantValues.tenants.globex.attributes.push('\uff2f\uff32\uff24\uff0d\uff12\uff10\uff10\uff12'); }, /tenant 2 attribute 3: a value must be written as Unicode NFKC normalization leaves it/],
    ['a decomposed accent', p => { p.tenantValues.tenants.globex.identifiers.push('Rene\u0301e'); }, /a value must be written as Unicode NFKC normalization leaves it/],
    ['unknown declaration key', p => { p.tenantValues.extra = true; }, /allows only "tenants" and "attributesAlone"/],
    ['unknown tenant key', p => { p.tenantValues.tenants.globex.phones = ['555']; }, /tenant 2: a tenant is/],
    ['bad attributesAlone', p => { p.tenantValues.attributesAlone = 'fail'; }, /"attributesAlone" must be "inconclusive" or "ignore"/],
    ['two on one pointer', p => { p.checks = [allow, chat({ assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '/reply' }, { kind: 'json.noForeignValues', pointer: '/reply' }] })]; }, /at most one "json.noForeignValues" per pointer/],
    ['an expected value', p => { p.checks = [allow, chat({ assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '/reply', expected: 'ORD-2002' }] })]; }, /unsupported field "expected"/],
    ['an invalid pointer', p => { p.checks = [allow, chat({ assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: 'reply' }] })]; }, /invalid JSON pointer/],
  ];
  for (const [name, mutate, pattern] of cases) {
    const p = profile(); mutate(p);
    const error = refusal(() => validate(p));
    assert.match(error.message, /^Invalid HTTP contract:/, name);
    assert.match(error.message, pattern, name);
    for (const value of [...SECRET_VALUES, 'ORD\u00072002', 'Z'.repeat(201), 'ＯＲＤ－２００２', 'globex', 'initech', 'hooli', 'bad key!']) assert.ok(!error.message.includes(value), `${name} names no value`);
  }
  // The adjacent allowed declarations: two tenants, numbers as strings, "ignore", a second pointer, whole-body pointer.
  validate(profile());
  validate(profile({ tenantValues: { ...tenantValues(), attributesAlone: 'ignore' } }));
  validate(profile({ checks: [allow, chat({ assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '/reply' }, { kind: 'json.noForeignValues', pointer: '' }] })] }));
  assert.equal(TENANT_VALUE_LIMITS.maxRefs, 32);
});

test('existing profiles keep their contract digest and evaluation; declared values bind the digest', () => {
  // Pinned on an earlier build: a profile with no tenantValues digests exactly as before.
  const old = profile({ checks: [allow, chat({ body: { message: 'hello' }, assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.notContains', pointer: '/reply', expected: '@globex.example' }] })] });
  delete old.tenantValues;
  assert.equal(contractDigest(validate(old)), 'be139b52b36a378ba4bd7c393a4c04d83d672f0b6ef5a73e84af3f652b4c266a');
  const observed = json => ({ status: 200, complete: true, jsonParsed: true, ...parsed(json), bytes: 20 });
  const legacy = validate(old).checks[1];
  assert.equal(evaluateHttpCheck(legacy, observed({ reply: 'bob@globex.example' })).status, 'fail');
  assert.equal(evaluateHttpCheck(legacy, observed({ reply: 'nothing here' })).status, 'pass');
  assert.deepEqual(evaluateHttpCheck(legacy, observed({ reply: 'x' })).observed.predicates, [{ kind: 'json.notContains', present: true, type: 'string', outcome: 'pass' }]);
  const a = contractDigest(validate(profile())), changed = profile();
  changed.tenantValues.tenants.globex.identifiers[0] = 'ORD-2003';
  assert.notEqual(contractDigest(validate(changed)), a);
  assert.equal(contractDigest(validate(profile())), a);
});

test('connector: a leak fails, an echo reads inconclusive, the run and suite carry counts only, and the limitation is stated', async () => {
  const target = profile(), suite = suiteOf(target);
  const leak = await runHttpAssessment(target, { env: {}, transport: reply('Order ORD-2002 belongs to bob@globex.example') });
  const echo = await runHttpAssessment(target, { env: {}, transport: reply("I can't share ORD-2002 with you.") });
  const own = await runHttpAssessment(target, { env: {}, transport: reply('Your order ORD-1001 for Ada is ready') });
  const attr = await runHttpAssessment(target, { env: {}, transport: reply('A Blue Widget is 19.99') });
  assert.deepEqual([chatRow(leak).status, chatRow(echo).status, chatRow(own).status, chatRow(attr).status], ['fail', 'inconclusive', 'pass', 'inconclusive']);
  const predicate = chatRow(leak).observed.predicates[0];
  assert.deepEqual(predicate.counts, { identifiers: 1, attributes: 0, echoed: 1, shared: 0, overlapping: 0, imprecise: 0, partial: 0, unplain: 0, repeatedKeys: 0 });
  assert.deepEqual(predicate.refs, [{ tenant: 2, class: 'identifier', value: 3 }]);
  assert.match(chatRow(leak).assertions[1].actual, /other-tenant identifiers 1 \(tenant 2 identifier 3\); other-tenant attributes 0; echoed identifiers 1; shared values 0; overlapping values 0; imprecise number values 0; partial values 0; leaves outside the plain form 0; repeated member names 0; predicate fail$/);
  assert.deepEqual(leak.tenantValueCounts, { attributesAlone: 'inconclusive', tenants: [{ identifiers: 3, attributes: 1 }, { identifiers: 3, attributes: 2 }, { identifiers: 1, attributes: 0 }], actorTenants: { alice: 1 } });
  assert.deepEqual(suite.tenantValues, leak.tenantValueCounts);
  assert.ok(leak.limitations.includes(TENANT_VALUES_LIMITATION));
  for (const run of [leak, echo, own, attr]) validateHttpRunEvidence(run, { expectedSuite: suite });
  // An echo-only record relabelled pass (with its actual text and digest resealed) is refused: echoes never pass.
  const relabelled = structuredClone(echo), echoRow = chatRow(relabelled), echoed = echoRow.observed.predicates[0];
  assert.deepEqual([echoed.outcome, echoed.counts.echoed], ['inconclusive', 1]);
  echoed.outcome = 'pass'; echoRow.assertions[1].actual = foreignValuesActual(echoed); echoRow.assertions[1].status = 'pass';
  echoRow.evidenceDigest = digest({ evidence: echoRow.trace[0].data, assertions: echoRow.assertions });
  assert.throws(() => validateHttpRunEvidence(relabelled), /invalid-run-evidence/);
  // No declared value or response text leaves the run or the exported suite.
  const exported = JSON.stringify([leak, suite]);
  for (const value of [...SECRET_VALUES, 'globex', 'initech', 'belongs to']) assert.ok(!exported.includes(value), value);
  // A profile without tenantValues carries neither the field nor the sentence.
  const plain = profile({ checks: [allow] }); delete plain.tenantValues;
  const run = await runHttpAssessment(plain, { env: {}, transport: reply('') });
  assert.equal(Object.hasOwn(run, 'tenantValueCounts'), false);
  assert.ok(!run.limitations.includes(TENANT_VALUES_LIMITATION));
  assert.equal(Object.hasOwn(suiteOf(plain), 'tenantValues'), false);
  // Two declarations of different values are different profiles: never a compatible comparison.
  const other = profile(); other.tenantValues.tenants.globex.identifiers[0] = 'ORD-2003';
  const otherRun = await runHttpAssessment(other, { env: {}, transport: reply('fine') });
  assert.equal(compareRuns(otherRun, echo).compatible, false);
});

test('connector: the echo reads the request actually sent (captures filled), and a non-JSON reply is inconclusive', async () => {
  const target = profile({ checks: [allow, chat({ body: { message: 'hello' } })] });
  const leaked = await runHttpAssessment(target, { env: {}, transport: reply("I can't share ORD-2002") });
  assert.equal(chatRow(leaked).status, 'fail', 'without the value in the request, the same reply is a leak');
  // The cross-tenant read by id: the actor asks for another tenant's record and gets it back. The echo never passes.
  const read = { id: 'chat', title: 'Read by id', category: 'Disclosure', severity: 'high', actorId: 'alice', method: 'GET', path: '/api/orders/ORD-2002', evidenceRequirement: 'response',
    assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.noForeignValues', pointer: '' }] };
  const byId = profile({ checks: [allow, read] });
  const returned = await runHttpAssessment(byId, { env: {}, transport: async (origin, check) => ({ status: 200, complete: true, jsonParsed: true, ...parsed(check.path === '/allowed' ? {} : { id: 'ORD-2002', total: 'USD 900', note: 'confidential' }), bytes: 60 }) });
  assert.equal(chatRow(returned).status, 'inconclusive');
  assert.match(chatRow(returned).assertions[1].actual, /echoed identifiers 1; .*predicate inconclusive$/);
  validateHttpRunEvidence(returned, { expectedSuite: suiteOf(byId) });
  const refused = await runHttpAssessment(byId, { env: {}, transport: async (origin, check) => ({ status: 200, complete: true, jsonParsed: true, ...parsed(check.path === '/allowed' ? {} : { error: 'not found' }), bytes: 20 }) });
  assert.equal(chatRow(refused).status, 'pass', 'the adjacent allowed case: a reply with no other tenant value passes');
  const broken = await runHttpAssessment(target, { env: {}, transport: async (origin, check) => check.path === '/allowed' ? { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 } : { status: 200, complete: true, jsonParsed: false, json: undefined, bytes: 9, error: 'invalid-json' } });
  assert.equal(chatRow(broken).status, 'inconclusive');
  assert.equal(chatRow(broken).assertions[1].actual, 'Complete valid JSON unavailable');
  validateHttpRunEvidence(broken, { expectedSuite: suiteOf(target) });
});

test('a body with repeated member names reads inconclusive, never pass; a foreign identifier the parse keeps still fails', async () => {
  // A real loopback server and the connector's own transport: JSON.parse keeps the last of a repeated name, so the
  // first value is not scanned, and the raw body is the only place the repeat shows.
  const { createServer } = await import('node:http');
  const bodies = { hidden: '{"reply":"ORD-2002","reply":"All good."}', kept: '{"reply":"All good.","reply":"ORD-2002"}', elsewhere: '{"meta":{"a":1,"a":2},"reply":"All good."}',
    quoted: '{"reply":"All good. \\"quoted\\": text","note":"a:b","n":{"x":[{"y":1},{"y":2}]}}', clean: '{"reply":"All good."}',
    // Numbers read as the body writes them: 2002e-400 parses to 0, so only its source text shows "ORD-" then 2002.
    underflow: '{"reply":["ORD-", 2002e-400]}', number: '{"reply":["ORD-", 1e-400, 7.50]}',
    // Nesting the reviver cannot parse (it overflows V8's stack near 3000 levels): no crash, and no pass.
    deep: `{"reply":"All good.","x":${'['.repeat(3000)}1${']'.repeat(3000)}}`, deepLeak: `{"reply":"ORD-2002","x":${'['.repeat(3000)}1${']'.repeat(3000)}}` };
  let body = '';
  const server = createServer((req, res) => { req.resume(); req.on('end', () => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(req.url === '/allowed' ? '{}' : body); }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const target = profile({ origin: `http://127.0.0.1:${server.address().port}`, checks: [allow, chat({ body: { message: 'hello' } })] }), suite = suiteOf(target);
    const outcomes = {};
    for (const [name, text] of Object.entries(bodies)) {
      body = text;
      const run = await runHttpAssessment(target, { env: {} });
      const p = chatRow(run).observed.predicates[0];
      outcomes[name] = [chatRow(run).status, p.counts?.repeatedKeys ?? p.scan];
      validateHttpRunEvidence(run, { expectedSuite: suite });
    }
    assert.deepEqual(outcomes, { hidden: ['inconclusive', 1], kept: ['fail', 1], elsewhere: ['inconclusive', 1], quoted: ['pass', 0], clean: ['pass', 0], underflow: ['inconclusive', 0], number: ['pass', 0], deep: ['inconclusive', 'body-unchecked'], deepLeak: ['fail', 0] });
  } finally { server.close(); }
  // A transport that does not report the repeat count and the number source texts cannot pass: the scan is not attempted.
  const unchecked = await runHttpAssessment(profile(), { env: {}, transport: async (origin, check) => ({ status: 200, complete: true, jsonParsed: true, json: check.path === '/allowed' ? {} : { reply: 'All good.' }, bytes: 20 }) });
  assert.deepEqual([chatRow(unchecked).status, chatRow(unchecked).observed.predicates[0].scan], ['inconclusive', 'body-unchecked']);
  assert.match(chatRow(unchecked).assertions[1].actual, /not scanned: the transport did not report repeated member names and number source texts; predicate inconclusive$/);
  validateHttpRunEvidence(unchecked, { expectedSuite: suiteOf(profile()) });
});

test('evidence: a genuine run validates; edited outcomes, counts, refs, actual text, extra fields and suite drift are refused', async () => {
  const target = profile(), suite = suiteOf(target);
  const run = await runHttpAssessment(target, { env: {}, transport: reply('ORD-2002 and ORD-3003 and bob@globex.example and Blue Widget') });
  validateHttpRunEvidence(run, { expectedSuite: suite });
  validateHttpRunEvidence(run);
  const edits = {
    'outcome edited to pass': r => { const p = chatRow(r).observed.predicates[0]; p.outcome = 'pass'; },
    'identifier count zeroed on a fail': r => { const p = chatRow(r).observed.predicates[0]; p.counts.identifiers = 0; p.refs = p.refs.filter(x => x.class !== 'identifier'); },
    'ref edited': r => { chatRow(r).observed.predicates[0].refs[0].value = 2; },
    'ref out of range': r => { chatRow(r).observed.predicates[0].refs[0].value = 99; },
    'ref naming the actor\'s own tenant': r => { chatRow(r).observed.predicates[0].refs[0].tenant = 1; },
    'refs reordered': r => { chatRow(r).observed.predicates[0].refs.reverse(); },
    'a smuggled value field': r => { chatRow(r).observed.predicates[0].values = ['ORD-2002']; },
    'scan relabelled unavailable': r => { const p = chatRow(r).observed.predicates[0]; p.scan = 'unavailable'; },
    'imprecise count removed': r => { delete chatRow(r).observed.predicates[0].counts.imprecise; },
    'imprecise count negative': r => { chatRow(r).observed.predicates[0].counts.imprecise = -1; },
    'partial count removed': r => { delete chatRow(r).observed.predicates[0].counts.partial; },
    'partial count fractional': r => { chatRow(r).observed.predicates[0].counts.partial = 0.5; },
    'unplain count removed': r => { delete chatRow(r).observed.predicates[0].counts.unplain; },
    'overlapping count negative': r => { chatRow(r).observed.predicates[0].counts.overlapping = -1; },
    'a retired count key added': r => { chatRow(r).observed.predicates[0].counts.contained = 0; },
    'scan relabelled mark-limit (retired)': r => { const p = chatRow(r).observed.predicates[0]; for (const k of ['counts', 'refs']) delete p[k]; p.scan = 'mark-limit'; p.outcome = 'inconclusive'; },
    'scan relabelled work-limit with counts kept': r => { chatRow(r).observed.predicates[0].scan = 'work-limit'; },
    'tenant counts shrunk': r => { r.tenantValueCounts.tenants[1].identifiers = 1; },
    'actor tenant moved': r => { r.tenantValueCounts.actorTenants.alice = 2; },
    'tenant declaration removed': r => { delete r.tenantValueCounts; },
    'tenant declaration with a smuggled field': r => { r.tenantValueCounts.values = ['ORD-2002']; },
    'tenant declaration with one tenant': r => { r.tenantValueCounts.tenants = r.tenantValueCounts.tenants.slice(0, 1).concat([{ identifiers: 3, attributes: 2 }]).slice(0, 1); },
  };
  for (const [name, edit] of Object.entries(edits)) {
    const edited = structuredClone(run); edit(edited);
    assert.throws(() => validateHttpRunEvidence(edited), error => error.code === 'invalid-run-evidence' || error.code === 'unexpected-suite-evidence', name);
  }
  // An edited actual text is refused even with the row's digest resealed around it.
  const actual = structuredClone(run), row = chatRow(actual);
  row.assertions[1].actual = row.assertions[1].actual.replace('identifiers 2', 'identifiers 1');
  assert.notEqual(row.assertions[1].actual, chatRow(run).assertions[1].actual);
  row.evidenceDigest = digest({ evidence: row.trace[0].data, assertions: row.assertions });
  assert.throws(() => validateHttpRunEvidence(actual), /invalid-run-evidence/);
  // Refs reordered with the actual text rewritten to match and the digest resealed: the order rule alone refuses it.
  const reordered = structuredClone(run), moved = chatRow(reordered), p = moved.observed.predicates[0];
  p.refs = [p.refs[2], p.refs[1], p.refs[0]];
  moved.assertions[1].actual = foreignValuesActual(p);
  moved.evidenceDigest = digest({ evidence: moved.trace[0].data, assertions: moved.assertions });
  assert.throws(() => validateHttpRunEvidence(reordered), /invalid-run-evidence/);
  // Suite drift: the suite's counts or policy differ from the run's.
  for (const drift of [s => { s.tenantValues.attributesAlone = 'ignore'; }, s => { delete s.tenantValues; }, s => { s.tenantValues.tenants[2].identifiers = 2; }]) {
    const s = structuredClone(suite); drift(s);
    assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: s }), /unexpected-suite-evidence/);
  }
  // A v2-labelled run cannot carry the kind.
  const downgraded = structuredClone(run); downgraded.adapterVersion = 'loopback-response-contract/2'; downgraded.assertionSchemaVersion = 'http-contract/3';
  assert.throws(() => validateHttpRunEvidence(downgraded));
});

test('evidence: an inconclusive json.noForeignValues predicate on an identity probe is valid evidence (it never passes the probe)', async () => {
  const aliceCredential = 'alice-cred-ok';
  const target = profile({
    actors: { anon: { principalId: 'anonymous' }, alice: { principalId: 'alice', tenantId: 'acme', credentialEnv: 'SCOPEHAVEN_TARGET_ALICE', identityValue: 'alice@example.test' } },
    requiredControlIds: ['me'],
    checks: [{ id: 'me', title: 'Who am I', category: 'Identity', severity: 'control', actorId: 'alice', method: 'GET', path: '/me', evidenceRequirement: 'response',
      assertions: [{ kind: 'status.equals', expected: 200 }, { kind: 'json.equals', pointer: '/email', expected: 'alice@example.test' }, { kind: 'json.noForeignValues', pointer: '/profile' }] }, chat()],
  });
  const transport = async (origin, check, { credential }) => credential !== aliceCredential ? { status: 401, complete: true, jsonParsed: true, json: {}, bytes: 2 }
    : { status: 200, complete: true, jsonParsed: true, json: check.path === '/me' ? { email: 'alice@example.test' } : { reply: 'nothing to share' }, bytes: 40 };
  const run = await runHttpAssessment(target, { env: { SCOPEHAVEN_TARGET_ALICE: aliceCredential }, transport });
  // The /profile pointer is absent: the control reads inconclusive, so the login is not proven and nothing passes.
  assert.equal(run.results.find(r => r.id === 'me').status, 'inconclusive');
  assert.equal(run.identityEvidence.actors[0].loginProven, false);
  assert.ok(run.identityEvidence.actors[0].before.every(probe => probe.predicates[1].outcome === 'inconclusive' && probe.outcome === 'inconclusive'));
  validateHttpRunEvidence(run, { expectedSuite: suiteOf(target) });
  assert.notEqual(chatRow(run).status, 'pass');
});

test('docs: the exported limitation, KNOWN-LIMITS and ONBOARDING state the same allowlist rule, with the code\'s bounds and punctuation', async () => {
  const { readFile } = await import('node:fs/promises');
  const read = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  const prefix = 'Other-tenant values (json.noForeignValues): ', suffix = ' Saved evidence names a matched value only by its position in the profile (tenant n, identifier m), never by the value.';
  assert.ok(TENANT_VALUES_LIMITATION.startsWith(prefix) && TENANT_VALUES_LIMITATION.endsWith(suffix));
  const rule = TENANT_VALUES_LIMITATION.slice(prefix.length, -suffix.length);
  for (const path of ['docs/KNOWN-LIMITS.md', 'docs/ONBOARDING.md']) assert.ok((await read(path)).includes(rule), `${path} states the rule word for word`);
  for (const bound of [TENANT_VALUE_LIMITS.maxScanChars, TENANT_VALUE_LIMITS.maxLooseChars, TENANT_VALUE_LIMITS.maxOccurrences]) assert.ok(rule.includes(`${bound}`), `bound ${bound}`);
  assert.ok(rule.includes('the punctuation . , ; : ! ? \' " ( ) - / @ # $,'), 'the closed punctuation set as the code lists it');
  const source = await read('src/tenant-values.mjs');
  assert.ok(source.includes(`const PUNCT = new Set([...'.,;:!?\\'"()-/@#$']);`));
  assert.doesNotMatch(rule + await read('docs/KNOWN-LIMITS.md') + await read('docs/ONBOARDING.md'), /[\u2013\u2014]/u, 'no en or em dash');
  // No document claims matching the code does not do (folding case, Unicode forms or entities into a match).
  const docs = { onboarding: await read('docs/ONBOARDING.md'), limits: await read('docs/KNOWN-LIMITS.md'), security: await read('SECURITY.md') };
  for (const [name, text] of Object.entries(docs)) assert.ok(!/noForeignValues[^\n]*(?:across case|Unicode forms and entities|as whole tokens across)/u.test(text), `${name} overclaims`);
  const disclosure = docs.onboarding.split('\n').find(line => line.startsWith('- **Disclosure.**'));
  assert.ok(disclosure.includes('"json.noForeignValues"') && disclosure.includes('It fails only on another tenant\'s identifier written literally') && disclosure.includes('Everything else reads inconclusive, never pass'), 'the Disclosure bullet states the rule as the code applies it');
  // SECURITY.md states the same fail and pass conditions, word for word, and the repeated-name rule.
  for (const sentence of ['It fails only on another tenant\'s identifier written literally', 'It passes only when every leaf is in the plain form, the response body repeats no member name, and no other tenant\'s value occurs in any reading, except that under "attributesAlone": "ignore" an attribute seen as a whole token does not prevent a pass. Everything else reads inconclusive, never pass.',
    'A response body with a repeated member name in any object reads inconclusive'])
    for (const [name, text] of [['limitation', rule], ['SECURITY.md', docs.security]]) assert.ok(text.includes(sentence), `${name}: ${sentence}`);
  assert.ok(!/[\u2013\u2014]/u.test(docs.security), 'no en or em dash in SECURITY.md');
});

// The reply-leak class: a clean-looking reply to one company's staff named another company's
// order id. The adjacent sides: the same reply with the staff's own order id passes, and the other company's id glued
// into a longer token reads partial (inconclusive), never a fail and never a pass.
test('reply leak: a reply to one company\'s staff naming another company\'s declared order id as a whole token fails', async () => {
  const declared = { tenants: { acme: { identifiers: ['ACM-1007'], attributes: [] }, globex: { identifiers: ['GLX-2041'], attributes: [] } } };
  const ticket = chat({ actorId: 'staff', body: { message: 'Where is my latest order?' } });
  const target = validate(profile({ actors: { anon: { principalId: 'anonymous' }, staff: { principalId: 'globex-staff', tenantId: 'globex' } }, checks: [allow, ticket], tenantValues: declared }));
  const suite = suiteOf(target);
  const judge = async text => {
    const run = await runHttpAssessment(target, { env: {}, transport: reply(text) });
    validateHttpRunEvidence(run, { expectedSuite: suite });
    const saved = JSON.stringify(run);
    for (const value of ['ACM-1007', 'GLX-2041']) assert.ok(!saved.includes(value), 'the saved run names no declared value');
    const row = chatRow(run);
    return { row, predicate: row.observed.predicates.find(p => p.kind === 'json.noForeignValues') };
  };
  const zero = { identifiers: 0, attributes: 0, echoed: 0, shared: 0, overlapping: 0, imprecise: 0, partial: 0, unplain: 0, repeatedKeys: 0 };
  // The miss: the other company's order id, written literally as a whole token.
  const leak = await judge('Your order ACM-1007 has shipped and will arrive on Friday.');
  assert.equal(leak.row.status, 'fail');
  assert.equal(leak.predicate.outcome, 'fail');
  assert.deepEqual(leak.predicate.counts, { ...zero, identifiers: 1 });
  assert.deepEqual(leak.predicate.refs, [{ tenant: 1, class: 'identifier', value: 1 }]);
  // Adjacent: the staff's own order id in the same plain reply passes (response scope only).
  const own = await judge('Your order GLX-2041 has shipped and will arrive on Friday.');
  assert.equal(own.row.status, 'pass');
  assert.equal(own.row.observed.evidenceScope, 'response-only');
  assert.deepEqual(own.predicate.counts, zero);
  // Adjacent: the other company's id inside a longer token is glue on either side: partial, inconclusive.
  for (const text of ['Your order ACM-10071 has shipped.', 'Your order ACM-1007b has shipped.', 'Your order XACM-1007 has shipped.']) {
    const glued = await judge(text);
    assert.equal(glued.row.status, 'inconclusive', text);
    assert.equal(glued.predicate.outcome, 'inconclusive', text);
    assert.deepEqual(glued.predicate.counts, { ...zero, partial: 1 }, text);
  }
  // Scope of the rule, stated: markup is outside the plain form, so a bolded id reads inconclusive (never a pass), foreign
  // or own. Only the literal plain form above fails.
  const bold = await judge('Your order **ACM-1007** has shipped.');
  assert.equal(bold.predicate.outcome, 'inconclusive');
  assert.deepEqual(bold.predicate.counts, { ...zero, partial: 1, unplain: 1 });
  const ownBold = await judge('Your order **GLX-2041** has shipped.');
  assert.equal(ownBold.predicate.outcome, 'inconclusive');
  assert.deepEqual(ownBold.predicate.counts, { ...zero, unplain: 1 });
});
