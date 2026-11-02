// The Object.hasOwn coercion sweep: Object.hasOwn(T, x), x in T and T[x] coerce x to a string, so an array
// (["mail"], which JSON can hold) or an object whose toString names a known key (which an in-process caller can pass) read as that key,
// while a strict === or includes beside it never matches. Each lookup below decided something on a profile, stored run, suite, spec,
// pack or option value; each now requires a string first. For each: the string control, then an array and a toString object, refused.
// A run recorded and sealed before the sweep by the earlier build's own connector (test/fixtures/pre-hasown-sweep-run-96f15d25.mjs)
// still validates here, and its profile, suite, SARIF and report come out as that build's. Synthetic data, no socket, no model.
import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { validateAppLogs } from '../src/app-log-rules.mjs';
import { validateAuditFileConfig } from '../src/audit-file-rules.mjs';
import { validateEgressConfig } from '../src/egress-rules.mjs';
import { validateProviderFeedConfig } from '../src/provider-feed-rules.mjs';
import { validateSmtpConfig } from '../src/smtp-rules.mjs';
import { catalogIdentity, validCatalogIdentity } from '../src/catalog-identity.mjs';
import { webhookEvidenceProblem } from '../src/webhook-driver.mjs';
import { validateTargetFile, validateHttpRunEvidence, contractDigest } from '../src/contracts.mjs';
import { HTTP_EVALUATOR_HASH } from '../src/http-connector.mjs';
import { COLLECTOR_RECORDS } from '../src/collector-identity.mjs';
import { createRegistry } from '../src/registry.mjs';
import { compareRuns } from '../src/runner.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { renderReport } from '../src/report.mjs';
import { digest } from '../src/domain.mjs';
import { validateSweepSpec } from '../integrations/sequences/sweep/spec.mjs';
import { relaySpec, relayOtherTwinSpec } from '../integrations/sequences/sweep/fixtures/relay-desk.mjs';
import { readPack, validateTemplates } from '../integrations/packs-v2/pack.mjs';
import { SHIPPED_PACKS } from '../integrations/packs-v2/expand.mjs';
import { createMonitor, RULE_IDS } from '../integrations/monitor/monitor.mjs';
import recordedAtMain from './fixtures/pre-hasown-sweep-run-96f15d25.mjs';

const recorded = () => structuredClone(recordedAtMain);
// The recording's SARIF files name the bundled standards map they were written with. These two fields are a file's only link to
// that map, and the map moved when the retired suites left it, so they are put back to compare everything else with the recording.
const RECORDED_STANDARDS_MAP = { mapVersion: '2026-10-19.1', sha256: 'cb1a0f365581309829b6d1b2c5a7cee0788d427afc03b6dcb5bfb429005546c4' };
const named = value => ({ toString: () => value });
const forms = value => [[value], named(value)];
const loads = target => { try { validateTargetFile({ schemaVersion: 1, targets: [target] }); return 'loaded'; } catch (error) { return error.message; } };
const evidence = (run, options) => { try { validateHttpRunEvidence(run, options); return 'ok'; } catch (error) { return `${error.code}${error.detail ? `:${error.detail}` : ''}`; } };
// Each edited row is resealed (its evidenceDigest recomputed), so only the rule under test can refuse it.
const reseal = row => { row.evidenceDigest = digest(row.trace.length === 2 ? { evidence: row.trace[0].data, effects: row.trace[1].data, assertions: row.assertions } : { evidence: row.trace[0].data, assertions: row.assertions }); };
const rowOf = (run, id) => run.results.find(row => row.id === id);

test('an app-log rule vocabulary is read only as a string: ["egress"] no longer loads a rule without its egress checks', () => {
  const profile = recorded().appLog.profile;
  assert.equal(loads(profile), 'loaded');
  for (const vocabulary of forms('egress')) {
    const target = structuredClone(profile);
    target.appLogs[0].rules[0].vocabulary = vocabulary;
    assert.throws(() => validateAppLogs(target), /rule 1: "vocabulary" is "egress", "mail" or "named"/, String(vocabulary));
    // Through the profile loader too. (JSON can hold the array; an in-process toString object reaches this rule as well, where the
    // earlier build accepted it and only the loader's later copy refused it, as an unreadable configuration.)
    assert.match(loads(target), /"vocabulary" is "egress", "mail" or "named"/, String(vocabulary));
  }
});

test('an observer witness actorId is a declared actor only as a string: audit file, egress recorder, provider feed and SMTP sink', () => {
  const publicKey = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const egress = recorded().webhook.profile.observers[0];
  const cases = [
    [validateAuditFileConfig, { type: 'audit-file', path: '/var/empty/scopehaven-audit.log', origin: 'http://127.0.0.1:9', rules: [{ name: 'me', method: 'GET', path: '/me' }], witness: { rule: 'me', actorId: 'ops', method: 'GET', path: '/me' } }],
    [validateEgressConfig, egress],
    [validateProviderFeedConfig, { type: 'provider-feed', feedId: 'mail', feed: { endpoint: { port: 4471, path: '/feed' } }, publicKey, domains: [{ domain: 'customers.example' }], routing: 'provider', witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: 'witness.scopehaven.invalid' } }],
    [validateSmtpConfig, { port: 4198, routing: 'smtp-host', domains: [{ domain: 'mail.example.test' }], witness: { actorId: 'ops', method: 'GET', path: '/ping', domain: 'witness-mail.example.test' } }],
  ];
  const actors = { ops: { principalId: 'ops' } };
  for (const [validate, config] of cases) {
    assert.doesNotThrow(() => validate(config, actors), validate.name);
    for (const actorId of forms('ops')) assert.throws(() => validate({ ...config, witness: { ...config.witness, actorId } }, actors), /the witness "actorId" must be a declared actor/, `${validate.name} ${String(actorId)}`);
  }
  // From a profile file: the earlier build loaded ["ops"], and then the connector's credential filter and the lifecycle witness rule (both strict)
  // never matched it.
  const profile = recorded().webhook.profile;
  assert.equal(loads(profile), 'loaded');
  profile.observers[0].witness.actorId = ['ops'];
  assert.match(loads(profile), /the witness "actorId" must be a declared actor/);
});

test('a catalog record engine is read only as a string, in the identity validator and in a stored run', () => {
  const { run } = recorded().catalog, ids = run.catalog.observers.map(r => r.instanceId);
  assert.equal(validCatalogIdentity(run.catalog, ids), true);
  assert.equal(evidence(run), 'ok');
  for (const engine of forms('sqlite')) {
    const identity = catalogIdentity(run.catalog.observers.map(r => ({ ...r, engine })));
    assert.equal(validCatalogIdentity(identity, ids), false, String(engine));
    assert.equal(evidence({ ...run, catalog: identity }), 'invalid-run-evidence', String(engine));
  }
});

test('a webhook provider is read only as a string: an unsigned record, a driver key and a suite view', () => {
  const { run, suite } = recorded().webhook;
  assert.equal(webhookEvidenceProblem(run), null);
  assert.equal(webhookEvidenceProblem(run, { checks: suite.checks }), null);
  for (const provider of forms('twilio')) {
    // An unsigned record, in a stored run validated without its suite (the earlier build accepted it; a signed one was refused by the key binding).
    const edited = structuredClone(run), row = rowOf(edited, 'SMS-UNSIGNED');
    row.trace[0].data.webhook.provider = provider; reseal(row);
    assert.equal(webhookEvidenceProblem(edited), 'webhook-record', String(provider));
    assert.equal(evidence(edited), 'invalid-run-evidence', String(provider));
    // A driver key that no signed record names, without a suite.
    const keys = run.webhookDriver.keys.map((k, i) => (i === 0 ? { ...k, provider } : k));
    assert.equal(webhookEvidenceProblem({ results: [], webhookDriver: run.webhookDriver }), null);
    assert.equal(webhookEvidenceProblem({ results: [], webhookDriver: { ...run.webhookDriver, keys } }), 'webhook-driver-record', String(provider));
    // A suite view of an unsigned check whose row the run does not hold.
    const view = suite.checks.find(c => c.id === 'SMS-UNSIGNED');
    assert.equal(webhookEvidenceProblem({ results: [] }, { checks: [view] }), null);
    assert.equal(webhookEvidenceProblem({ results: [] }, { checks: [{ ...view, webhook: { ...view.webhook, provider } }] }), 'webhook-declaration', String(provider));
  }
});

test('a stored row status is a SARIF outcome only as a string: ["pass"] reads as an unrecognized status, never as PASS', () => {
  const { run } = recorded().catalog;
  const resultOf = status => { const shaped = structuredClone(run); shaped.results[0].status = status; return renderSarif(shaped).runs[0].results[0]; };
  assert.equal(resultOf('pass').kind, 'pass');
  const unknown = resultOf('not-a-status');
  assert.equal(unknown.properties.scopehavenStatus, 'unrecognized');
  for (const status of forms('pass')) assert.deepEqual(resultOf(status), unknown, String(status));
});

test('a sweep spec request actorId is a declared actor only as a string, so a same-actor twin cannot pass for another actor', () => {
  assert.equal(validateSweepSpec(relayOtherTwinSpec('other-twin')).twinTurn.actorId, 'other');
  const sameActor = relaySpec('same'); delete sameActor.restore; sameActor.twinTurn = { ...sameActor.turn };
  assert.throws(() => validateSweepSpec(sameActor), /needs "restore", or a "twinTurn"/);
  for (const actorId of forms(relaySpec('x').turn.actorId)) {
    const spec = relaySpec('coerced'); delete spec.restore; spec.twinTurn = { ...spec.turn, actorId };
    assert.throws(() => validateSweepSpec(spec), /twinTurn needs an actorId from actors/, String(actorId));
    const turn = relaySpec('turn'); turn.turn = { ...turn.turn, actorId };
    assert.throws(() => validateSweepSpec(turn), /turn needs an actorId from actors/, String(actorId));
  }
});

test('a pack check "when" names an optional parameter only as a string, so an optional line is never always included', async () => {
  const pack = await readPack(join(SHIPPED_PACKS, 'tenant-isolation'));
  assert.doesNotThrow(() => validateTemplates(pack.checks, pack.manifest));
  const at = pack.checks.checks.findIndex(c => typeof c.when === 'string' || (Array.isArray(c.assertions) && c.assertions.some(a => typeof a?.when === 'string')));
  assert.ok(at >= 0, 'the shipped pack has a "when" line');
  for (const when of forms('leakPointer')) {
    const checks = structuredClone(pack.checks), check = checks.checks[at];
    if (typeof check.when === 'string') check.when = when; else check.assertions.find(a => typeof a?.when === 'string').when = when;
    assert.throws(() => validateTemplates(checks, pack.manifest), /which is not a parameter/);
  }
});

test('a monitor rule id is known only as a string', () => {
  assert.doesNotThrow(() => createMonitor({ rules: [RULE_IDS[0]] }));
  for (const id of forms(RULE_IDS[0])) assert.throws(() => createMonitor({ rules: [id] }), /Unknown monitor rule/, String(id));
});

test('runs recorded and sealed before the sweep validate here, and their profiles, suites, SARIF and reports come out as they did then', () => {
  const r = recorded();
  assert.equal(r.recordedAt, '96f15d25');
  const env = { SCOPEHAVEN_TARGET_OPS: ['synthetic', 'webhook', 'ops', 'bearer', 'k7'].join('-') };
  for (const name of ['webhook', 'catalog', 'appLog']) {
    const { profile, contractDigest: profileDigest, suite, sarifDigest, reportDigest, run } = r[name];
    assert.equal(run.evaluatorHash, r.httpEvaluatorHash, name);
    assert.equal(evidence(run), 'ok', name);
    assert.equal(evidence(run, { expectedSuite: suite }), 'ok', name);
    assert.equal(compareRuns(run, run).compatible, true, name);
    assert.equal(contractDigest(validateTargetFile({ schemaVersion: 1, targets: [profile] })[0]), profileDigest, name);
    // Cross-recorder destinations moved the collector records (egress-recorder/13, and every collector's files' digest, since
    // factory.mjs is in each list): the suite comes out as recorded with this build's records in their place, and nothing else differs.
    const exported = createRegistry({ profiles: [profile], env }).exportSuite(profile.id);
    assert.ok(exported.observers.every(o => o.collector === undefined || digest(o.collector) === digest(COLLECTOR_RECORDS[o.type])), name);
    // An app-log record also names the Node that exported it, and the recorded one was 24.21.0: only that field may differ.
    assert.ok((exported.appLogs ?? []).every(a => a.collector.node === process.versions.node), name);
    const appLogs = exported.appLogs ? { appLogs: exported.appLogs.map((a, i) => ({ ...a, collector: { ...a.collector, node: suite.appLogs[i]?.collector.node } })) } : {};
    assert.deepEqual({ ...exported, ...appLogs, observers: exported.observers.map((o, i) => o.collector === undefined ? o : { ...o, collector: suite.observers[i]?.collector }) }, suite, name);
    const sarif = renderSarif(run);
    Object.assign(sarif.runs[0].properties.standardsMap, RECORDED_STANDARDS_MAP);
    assert.equal(digest(sarif), sarifDigest, name);
    assert.equal(digest(renderReport(run)), reportDigest, name);
  }
  // Last, so that on the earlier build everything above runs and passes: the HTTP evaluator moved.
  assert.notEqual(HTTP_EVALUATOR_HASH, r.httpEvaluatorHash);
});
