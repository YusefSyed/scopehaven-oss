// check-config and assess --list refused a target whose http-audit observer has
// no usable credential, but the dashboard (registry.list, served by /api/bootstrap) still read such a target ready.
// The dashboard now reads readiness through the same rule. Offline only: nothing connects, and a reason names the
// environment reference, never its value. Synthetic profile and an explicit environment, never local credentials.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRegistry, loadProfiles } from '../src/registry.mjs';
import { startServer } from '../src/server.mjs';

const ACTOR = 'SCOPEHAVEN_TARGET_DASH_READY_ACTOR';
const AUDIT = 'SCOPEHAVEN_TARGET_DASH_READY_AUDIT';
const actorToken = 'synthetic-dashboard-actor-token';
const auditToken = 'synthetic-dashboard-audit-token';
const profile = () => ({ id: 'dashboard-audit-readiness', name: 'Synthetic dashboard audit readiness', applicationId: 'dashboard-readiness-test',
  origin: 'http://127.0.0.1:1', buildLabel: 'synthetic', contextId: 'local-only',
  actors: { reader: { principalId: 'reader', credentialEnv: ACTOR } },
  observers: [{ id: 'audit', type: 'http-audit', origin: 'http://127.0.0.1:1', path: '/audit', credentialEnv: AUDIT, itemsPointer: '/items', pageLimit: 100,
    fields: { id: '/id', actor: '/actor', action: '/action' }, actions: { read: 'update' }, principals: ['reader'] }],
  requiredControlIds: ['READ'], checks: [{ id: 'READ', title: 'Allowed read', category: 'Allowed use', severity: 'control',
    actorId: 'reader', method: 'GET', path: '/read', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] });

async function profiles(t) {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven dashboard readiness '));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const config = join(dir, 'targets.json');
  await writeFile(config, JSON.stringify({ schemaVersion: 1, targets: [profile()] }), { mode: 0o600 });
  return { dir, loaded: await loadProfiles(config) };
}
const noValues = text => { for (const value of [actorToken, auditToken]) assert.equal(text.includes(value), false, 'credential values must never be reported'); };

test('the dashboard registry reads a target with a missing audit observer credential as not ready', async t => {
  const { loaded } = await profiles(t);
  const missing = createRegistry({ profiles: loaded, env: { [ACTOR]: actorToken } }).list().find(row => row.id === profile().id);
  assert.equal(missing.available, false); assert.equal(missing.ready, false);
  assert.match(missing.readinessReason, /audit observer credential.*missing or invalid/i);
  assert.deepEqual(missing.missingCredentialRefs, [AUDIT]);
  assert.match(missing.description, /Required credentials are missing or invalid/);
  noValues(JSON.stringify(missing));
  // Both credentials present: ready, with nothing reported missing.
  const ready = createRegistry({ profiles: loaded, env: { [ACTOR]: actorToken, [AUDIT]: auditToken } }).list().find(row => row.id === profile().id);
  assert.equal(ready.available, true); assert.deepEqual(ready.missingCredentialRefs, []); assert.equal(ready.readinessReason, undefined);
  noValues(JSON.stringify(ready));
});

test('the served dashboard (/api/bootstrap) shows the same not-ready target, names only', async t => {
  const { dir, loaded } = await profiles(t);
  const app = await startServer({ port: 0, dataDir: join(dir, 'data'), profiles: loaded, env: { [ACTOR]: actorToken } }); t.after(() => app.close());
  const text = await (await fetch(`${app.origin}/api/bootstrap`, { headers: { Authorization: `Bearer ${app.accessToken}` } })).text();
  noValues(text);
  const row = JSON.parse(text).targets.find(target => target.id === profile().id);
  assert.ok(row, 'the configured target is listed');
  assert.equal(row.available, false); assert.deepEqual(row.missingCredentialRefs, [AUDIT]);
  assert.match(row.readinessReason, /audit observer credential.*missing or invalid/i);
});
