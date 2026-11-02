// The catalog identity through the connector: each database observer's catalog() record read after the final mark,
// recorded in the run as its catalog identity (src/catalog-identity.mjs catalogIdentity), validated by the shared HTTP validator, and
// named by the exported suite. Owned synthetic data only: in-memory observers with an injected transport, then the owned
// example app (examples/observed-support-app.mjs) with its real SQLite observers on a private copy, every listener on
// 127.0.0.1. No model, no provider, no database server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { createRegistry } from '../src/registry.mjs';
import { catalogIdentity, CATALOG_IDENTITY_SCHEMA } from '../src/suite.mjs';
import { catalogRecord, CATALOG_KINDS } from '../integrations/observers/catalog.mjs';
import { createObservedSupportApp, bindExampleProfile } from '../examples/observed-support-app.mjs';

const PROFILE = JSON.parse(await readFile(new URL('../integrations/collateral/refund-only.profile.json', import.meta.url), 'utf8'));
const hex = c => c.repeat(64);
const record = (sha = hex('a')) => catalogRecord({ engine: 'sqlite', baseline: { ok: true, sha256: sha, kinds: CATALOG_KINDS.sqlite.map(kind => ({ kind, objects: 1, sha256: hex('b') })) },
  latest: { ok: true, sha256: sha }, drifted: false, excluded: { schemas: [], tables: [] } });
// The profile's observers as in-memory ones (no events, complete windows), each database one with a catalog() record.
function fakeFactory({ catalogs = true } = {}) {
  return configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type];
    return { kind: out.kind, instanceId: `${c.type}-${c.id}`, source: out.source, scope: { operations: ['insert', 'update', 'delete', 'send'], names: null, actorAttribution: 'none', evidence: c.type === 'otel' ? 'presence-only' : 'authoritative' },
      witnessRequest: null, async start() {}, async stop() {}, async mark() { return {}; },
      async collect() { return { events: [], coverage: c.type === 'sqlite-snapshot' ? 'net-only' : 'complete', reason: null }; },
      ...(catalogs && ['sqlite-snapshot', 'sqlite-audit'].includes(c.type) ? { catalog: () => record() } : {}) };
  });
}
const transport = async () => ({ status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 });
const target = () => bindExampleProfile(PROFILE, { origin: 'http://127.0.0.1:9', dbPath: '/nonexistent/app.db', env: {} }).targets[0];
// A synthetic token for each actor credential the profile names (the transport is injected: nothing is sent).
const envOf = p => Object.fromEntries(Object.values(p.actors).flatMap(a => (a.credentialEnv ? [[a.credentialEnv, 'synthetic-token']] : [])));

test('the run records each database observer\'s catalog record as its catalog identity; the validator recomputes it and the exported suite names it', async () => {
  const p = target(), run = await runHttpAssessment(p, { env: envOf(p), transport, observerFactory: fakeFactory() });
  const dbIds = p.observers.filter(o => ['sqlite-snapshot', 'sqlite-audit'].includes(o.type)).map(o => `${o.type}-${o.id}`).sort();
  assert.ok(dbIds.length > 0, 'the example profile declares a database observer');
  assert.equal(run.catalog.schema, CATALOG_IDENTITY_SCHEMA);
  assert.deepEqual(run.catalog.observers.map(r => r.instanceId), dbIds);
  assert.equal(run.catalog.sha256, catalogIdentity(run.catalog.observers).sha256);
  const suite = createRegistry({ profiles: [p], env: {} }).exportSuite(p.id);
  assert.equal(suite.catalogSchema, CATALOG_IDENTITY_SCHEMA);
  assert.deepEqual([...suite.catalogObservers].sort(), dbIds, 'by instance, as the run names them');
  validateHttpRunEvidence(run, { expectedSuite: suite });
  // A catalog identity that does not recompute, names an undeclared observer, or meets a suite that names none is refused.
  const tampered = [{ ...run, catalog: { ...run.catalog, sha256: hex('f') } },
    { ...run, catalog: catalogIdentity([...run.catalog.observers, { instanceId: 'sqlite-snapshot-other', ...record() }]) },
    { ...run, catalog: catalogIdentity(run.catalog.observers.map(r => ({ ...r, kinds: { table: { objects: 1, sha256: 'x' } } }))) }];
  for (const bad of tampered) assert.throws(() => validateHttpRunEvidence(bad), /invalid-run-evidence|run evidence/i);
  const { catalogSchema: _s, catalogObservers: _o, ...plainSuite } = suite;
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: plainSuite }), /unexpected-suite-evidence|suite/i, 'a suite exported before the catalog identity names no catalog');
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: { ...suite, catalogObservers: suite.catalogObservers.slice(1) } }), /unexpected-suite-evidence|suite/i, 'an observer the suite does not name');
  // An observer outside the catalog types (here a trace observer) never contributes a record, whatever it exposes.
  const withTraces = { ...p, observers: [...p.observers, { id: 'traces', type: 'otel', port: 4318, services: ['support'], tools: ['refund'], principals: [], settleMs: 250 }] };
  const odd = await runHttpAssessment(withTraces, { env: envOf(p), transport, observerFactory: configs => fakeFactory()(configs).map(o => ({ ...o, catalog: () => record() })) });
  assert.deepEqual(odd.catalog.observers.map(r => r.instanceId), dbIds);
});

test('a run whose observers read no catalog has no catalog identity, as before; a suite without database observers names none', async () => {
  const p = target(), run = await runHttpAssessment(p, { env: envOf(p), transport, observerFactory: fakeFactory({ catalogs: false }) });
  assert.equal(Object.hasOwn(run, 'catalog'), false);
  validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [p], env: {} }).exportSuite(p.id) });
  const { observers: _x, ...noObservers } = p;
  const suite = createRegistry({ profiles: [{ ...noObservers, checks: p.checks.map(({ effects: _e, ...c }) => ({ ...c, evidenceRequirement: 'response' })) }], env: {} }).exportSuite(p.id);
  assert.equal(Object.hasOwn(suite, 'catalogSchema'), false);
});

test('practice: the owned example app with its real SQLite observers records the catalog it ran against; a schema change between runs moves it', async t => {
  const fingerprints = [];
  for (const migrate of [false, true]) {
    const app = await createObservedSupportApp({ build: 'secure' }); t.after(() => app.close());
    if (migrate) { const db = new DatabaseSync(app.dbPath); db.exec('CREATE INDEX IF NOT EXISTS n13_added ON refunds (id)'); db.close(); }
    const profile = bindExampleProfile(PROFILE, app).targets[0];
    const run = await runHttpAssessment(profile, { env: app.env });
    validateHttpRunEvidence(run, { expectedSuite: createRegistry({ profiles: [profile], env: app.env }).exportSuite(profile.id) });
    assert.ok(run.catalog.observers.length > 0 && run.catalog.observers.every(r => r.engine === 'sqlite' && /^[0-9a-f]{64}$/.test(r.sha256) && r.changedDuringRun === false));
    fingerprints.push(run.catalog.sha256);
  }
  assert.notEqual(fingerprints[0], fingerprints[1], 'an index added between the runs is another schema');
});
