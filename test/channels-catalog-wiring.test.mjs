// Declared channels and the catalog identity on one run: both are recorded, both survive the store, and the
// exported suite binds both, so a later reorder of the shared validator's suite checks cannot drop either binding.
// Owned synthetic data only: in-memory observers with an injected transport; no network, no model, no database server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runHttpAssessment } from '../src/http-connector.mjs';
import { validateHttpRunEvidence } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import { createStore } from '../src/store.mjs';
import { makeEffect } from '../src/effect-events.mjs';
import { OBSERVER_OUTPUT } from '../src/http-effects.mjs';
import { catalogRecord, CATALOG_KINDS } from '../integrations/observers/catalog.mjs';

const PAY = 'api.pay.example';
const hex = c => c.repeat(64);
const record = sha => catalogRecord({ engine: 'sqlite', baseline: { ok: true, sha256: sha, kinds: CATALOG_KINDS.sqlite.map(kind => ({ kind, objects: 1, sha256: hex('b') })) },
  latest: { ok: true, sha256: sha }, drifted: false, excluded: { schemas: [], tables: [] } });

function harness() {
  const pending = [];
  let seq = 0;
  const transport = async (_origin, check) => { if (check.path === '/agent/checkout') pending.push('POST /v1/charges'); return { status: 200, complete: true, jsonParsed: true, json: {}, bytes: 2 }; };
  const scopes = { 'egress-recorder': { operations: ['send'], names: [PAY] }, 'sqlite-snapshot': { operations: ['insert', 'update', 'delete'], names: ['orders', 'jobs'] },
    'sqlite-audit': { operations: ['insert', 'update'], names: ['jobs', 'refunds'] } };
  const observerFactory = configs => configs.map(c => {
    const out = OBSERVER_OUTPUT[c.type], instanceId = `${c.type}-${c.id}`;
    let mark = 0;
    return { kind: out.kind, instanceId, source: out.source, scope: { ...scopes[c.type], actorAttribution: 'none', evidence: 'authoritative' }, witnessRequest: null,
      async start() {}, async stop() {}, async mark() { return { at: ++mark }; },
      async collect() {
        const coverage = c.type === 'sqlite-snapshot' ? 'net-only' : 'complete';
        const effects = c.type === 'egress-recorder' ? pending.splice(0).map(resource => ({ operation: 'send', name: PAY, resource })) : [];
        return { events: effects.map(e => makeEffect({ source: out.source, observer: { kind: out.kind, instanceId }, seq: ++seq, outcome: 'committed', content: { b: 1 }, ...e })),
          coverage, reason: coverage === 'net-only' ? 'net-change-between-snapshots' : null };
      },
      ...(c.type === 'egress-recorder' ? {} : { catalog: () => record(hex('a')) }) };
  });
  return { transport, observerFactory };
}

const CHARGE = { source: 'http-egress', operation: 'send', name: PAY };
const check = (id, severity, method, path, effects) => ({ id, title: id, category: severity === 'control' ? 'allowed-use' : 'tool-misuse', severity, actorId: 'ops', method, path,
  ...(method === 'POST' ? { body: {} } : {}), evidenceRequirement: effects && severity !== 'control' ? 'backend' : 'response',
  assertions: [{ kind: 'status.equals', expected: 200 }], ...(effects ? { effects } : {}) });
const CHANNELS = { confinement: 'unconfined', list: [{ id: 'payments', kind: 'egress', observedBy: ['sink'], names: [PAY] }, { id: 'jobs', kind: 'queue', observedBy: ['audit'], names: ['jobs'] }] };
const profile = { id: 'combo-app', name: 'Combo app', applicationId: 'combo-app', origin: 'http://127.0.0.1:9', buildLabel: 'b1', contextId: 'synthetic-combo',
  actors: { ops: { principalId: 'ops' } }, requiredControlIds: ['WHOAMI', 'ALLOWED-CHARGE'],
  checks: [check('WHOAMI', 'control', 'GET', '/me'), check('ALLOWED-CHARGE', 'control', 'POST', '/agent/checkout', [{ kind: 'effect.exists', select: { ...CHARGE, resource: 'POST /v1/charges' } }]),
    check('NO-CHARGE', 'high', 'GET', '/agent/summarize', [{ kind: 'effect.none', select: CHARGE }])],
  observers: [{ id: 'sink', type: 'egress-recorder', port: 40996, routing: 'proxy', destinations: [{ host: PAY, paths: ['/v1/charges'] }],
    witness: { actorId: 'ops', method: 'GET', path: '/ping', host: 'witness.scopehaven.invalid' }, settleMs: 300, quietMs: 150 },
    { id: 'db', type: 'sqlite-snapshot', settleMs: 300 }, { id: 'audit', type: 'sqlite-audit', settleMs: 300 }],
  channels: CHANNELS };

test('a run with declared channels and a catalog validates against its exported suite, before and after the store', async t => {
  const suite = createRegistry({ profiles: [profile], env: {} }).exportSuite('combo-app');
  assert.deepEqual(suite.channels, CHANNELS);
  assert.deepEqual(suite.catalogObservers, ['sqlite-snapshot-db', 'sqlite-audit-audit']);
  const run = await runHttpAssessment(profile, { env: {}, ...harness() });
  assert.deepEqual(run.channels, CHANNELS);
  assert.deepEqual(run.catalog.observers.map(r => r.instanceId).sort(), ['sqlite-audit-audit', 'sqlite-snapshot-db']);
  assert.doesNotThrow(() => validateHttpRunEvidence(run, { expectedSuite: suite }));

  const root = await mkdtemp(join(tmpdir(), 'channels catalog '));
  t.after(() => rm(root, { recursive: true, force: true }));
  const store = createStore(join(root, 'store'));
  await store.ready;
  const saved = await store.get((await store.save(run)).id);
  assert.deepEqual(saved.catalog, run.catalog);
  assert.deepEqual(saved.channels, run.channels);
  assert.doesNotThrow(() => validateHttpRunEvidence(saved, { expectedSuite: suite }));

  // Each binding holds with the other present: stripping the channels, a suite from before the catalog, or a changed digest.
  const { channels: _channels, ...noChannels } = run;
  assert.throws(() => validateHttpRunEvidence(noChannels, { expectedSuite: suite }), /unexpected-suite-evidence/);
  const { catalogSchema: _schema, catalogObservers: _observers, ...staleSuite } = suite;
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: staleSuite }), /unexpected-suite-evidence/);
  assert.throws(() => validateHttpRunEvidence({ ...run, catalog: { ...run.catalog, sha256: hex('f') } }, { expectedSuite: suite }), /invalid-run-evidence/);
});
