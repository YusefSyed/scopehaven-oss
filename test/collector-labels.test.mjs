// The Postgres and DNS collector labels (src/collector-identity.mjs; pg-wal/5 since pg_net on the wire): pg-wal/3 over the WAL observer, the
// background-writer rules, the actor capture and the Supabase rules it reads, and dns-stub/1 equal to the stub's own record. Neither is yet an observer type a profile
// declares, so no run carries either until the type is wired. Reads local files only.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, appendFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { COLLECTOR_RECORDS, COLLECTOR_FILES, COLLECTOR_LABELS, KNOWN_COLLECTOR_LABELS, collectorDigest, validCollector } from '../src/collector-identity.mjs';
import { OBSERVER_TYPES } from '../src/http-effects.mjs';
import { validateTargetFile, validateHttpRunEvidence } from '../src/contracts.mjs';
import { createRegistry } from '../src/registry.mjs';
import recordedBeforeWire from './fixtures/pre-pgnet-run-8ecfe737.mjs';
import { DNS_STUB_COLLECTOR, DNS_STUB_FILES, DNS_STUB_LABEL } from '../integrations/observers/dns-stub.mjs';

// A copy of a collector's files in a spaced folder: the digest is path-independent, and each edit moves it.
async function copyOf(t, names) {
  const root = await mkdtemp(join(tmpdir(), 'scopehaven collector labels '));
  t.after(() => rm(root, { recursive: true, force: true }));
  const observers = join(root, 'integrations', 'observers');
  for (const name of names) {
    const to = join(observers, name);
    await mkdir(dirname(to), { recursive: true });
    await copyFile(new URL(`../integrations/observers/${name}`, import.meta.url), to);
  }
  return { observers, base: pathToFileURL(`${observers}/`) };
}

test('pg-wal/5: the WAL observer, its wire client, the read-back seal, the catalog, the background-writer rules, the actor capture, the Supabase rules and pg_net on the wire; any edit moves it', async t => {
  assert.deepEqual(COLLECTOR_FILES['pg-wal'], ['factory.mjs', 'pg-wire.mjs', 'pg-wal.mjs', '../../src/pg-readback.mjs', 'catalog.mjs',
    'end-barrier.mjs', 'run-lease.mjs', 'ignore-lists/ignore-list.mjs', 'ignore-lists/supabase.json', 'ignore-lists/litestream.json', 'pg-actor.mjs', 'supabase-rules.mjs', 'pg-net-wire.mjs']);
  // The same files as pg-snapshot's, with the WAL observer in place of the snapshot observer, and pg_net on the wire.
  assert.deepEqual(COLLECTOR_FILES['pg-wal'].filter(n => n !== 'pg-wal.mjs' && n !== 'pg-net-wire.mjs'), COLLECTOR_FILES['pg-snapshot'].filter(n => n !== 'pg-snapshot.mjs'));
  assert.equal(COLLECTOR_LABELS['pg-wal'], 'pg-wal/5');
  assert.equal(COLLECTOR_RECORDS['pg-wal'].label, 'pg-wal/5');
  assert.ok(KNOWN_COLLECTOR_LABELS.includes('pg-wal/5') && validCollector('pg-wal', COLLECTOR_RECORDS['pg-wal']));
  for (const label of ['pg-wal/1', 'pg-wal/2', 'pg-wal/3', 'pg-wal/4']) assert.ok(validCollector('pg-wal', { ...COLLECTOR_RECORDS['pg-wal'], label }), `${label} stays known`);
  assert.equal(COLLECTOR_RECORDS['pg-wal'].digest, await collectorDigest(COLLECTOR_FILES['pg-wal']));
  assert.equal(COLLECTOR_RECORDS['pg-wal'].node, process.versions.node);
  assert.notEqual(COLLECTOR_RECORDS['pg-wal'].digest, COLLECTOR_RECORDS['pg-snapshot'].digest);
  const copy = await copyOf(t, COLLECTOR_FILES['pg-wal'].filter(n => !n.startsWith('../')));
  await mkdir(join(copy.observers, '..', '..', 'src'), { recursive: true });
  await copyFile(new URL('../src/pg-readback.mjs', import.meta.url), join(copy.observers, '..', '..', 'src', 'pg-readback.mjs'));
  assert.equal(await collectorDigest(COLLECTOR_FILES['pg-wal'], copy.base), COLLECTOR_RECORDS['pg-wal'].digest, 'path-independent');
  for (const name of ['pg-wal.mjs', 'ignore-lists/litestream.json', 'run-lease.mjs', 'pg-actor.mjs', 'supabase-rules.mjs', 'pg-net-wire.mjs']) {
    await appendFile(join(copy.observers, name), '\n');
    assert.notEqual(await collectorDigest(COLLECTOR_FILES['pg-wal'], copy.base), COLLECTOR_RECORDS['pg-wal'].digest, name);
    await copyFile(new URL(`../integrations/observers/${name}`, import.meta.url), join(copy.observers, name));
  }
  assert.equal(await collectorDigest(COLLECTOR_FILES['pg-wal'], copy.base), COLLECTOR_RECORDS['pg-wal'].digest, 'restored');
});

test('docs/PG-WAL.md names pg-wal\'s label and every file its digest covers', async () => {
  const { readFile } = await import('node:fs/promises');
  const doc = await readFile(new URL('../docs/PG-WAL.md', import.meta.url), 'utf8');
  assert.ok(doc.includes(`Its collector is \`${COLLECTOR_LABELS['pg-wal']}\``));
  // The doc ships, so it names src/pg-readback.mjs from the folder's root: a release refuses a path that climbs out of it.
  for (const name of COLLECTOR_FILES['pg-wal']) assert.ok(doc.includes(`\`${name.replace('../../', '')}\``), name);
});

test('pg-wal/4 is refused as this head\'s record: a suite exported here does not accept a run an earlier build recorded under it', () => {
  const { profile, suite, run } = structuredClone(recordedBeforeWire);
  assert.deepEqual([suite.observers[0].collector.label, COLLECTOR_RECORDS['pg-wal'].label], ['pg-wal/4', 'pg-wal/5']);
  // The earlier label stays known, so that build's run still validates against its own suite (test/pg-wal-profile.test.mjs).
  validateHttpRunEvidence(run, { expectedSuite: suite });
  const here = createRegistry({ profiles: [profile], env: { SCOPEHAVEN_TARGET_BOB: 'x', SCOPEHAVEN_TARGET_WAL: 'u:p' } }).exportSuite(profile.id);
  assert.deepEqual(here.observers[0].collector, COLLECTOR_RECORDS['pg-wal']);
  assert.throws(() => validateHttpRunEvidence(run, { expectedSuite: here }), /unexpected-suite-evidence/);
});

test('dns-stub/1: the registry record is the stub\'s own record, over the same files in the same order', async t => {
  assert.equal(COLLECTOR_LABELS['dns-stub'], DNS_STUB_LABEL);
  assert.deepEqual(COLLECTOR_FILES['dns-stub'], [...DNS_STUB_FILES]);
  assert.deepEqual(COLLECTOR_RECORDS['dns-stub'], DNS_STUB_COLLECTOR);
  assert.ok(KNOWN_COLLECTOR_LABELS.includes('dns-stub/1') && validCollector('dns-stub', COLLECTOR_RECORDS['dns-stub']));
  const copy = await copyOf(t, COLLECTOR_FILES['dns-stub']);
  assert.equal(await collectorDigest(COLLECTOR_FILES['dns-stub'], copy.base), DNS_STUB_COLLECTOR.digest, 'path-independent');
  await appendFile(join(copy.observers, 'dns-wire.mjs'), '\n');
  assert.notEqual(await collectorDigest(COLLECTOR_FILES['dns-stub'], copy.base), DNS_STUB_COLLECTOR.digest);
});

test('a collector record\'s label must name its own type: no label is valid for another type, and an unregistered one is refused', () => {
  assert.equal(validCollector('pg-snapshot', COLLECTOR_RECORDS['pg-wal']), false);
  assert.equal(validCollector('pg-wal', COLLECTOR_RECORDS['pg-snapshot']), false);
  assert.equal(validCollector('egress-recorder', COLLECTOR_RECORDS['dns-stub']), false);
  for (const label of ['pg-wal/6', 'pg-snapshot/6', 'dns-stub/2']) assert.equal(validCollector(label.split('/')[0], { ...COLLECTOR_RECORDS['pg-wal'], label }), false, label);
});

// pg-wal is a profile observer type (test/pg-wal-profile.test.mjs); dns-stub stays a registered collector only.
test('dns-stub is a registered collector only: not an observer type a profile may declare yet', () => {
  assert.ok(OBSERVER_TYPES.includes('pg-wal'));
  for (const type of ['dns-stub']) {
    assert.ok(!OBSERVER_TYPES.includes(type), type);
    const target = { id: 'labels', name: 'Labels', applicationId: 'labels', origin: 'http://127.0.0.1:4318', buildLabel: 'b1', contextId: 'synthetic',
      actors: { anon: { principalId: 'anonymous' } }, requiredControlIds: ['allow'], observers: [{ id: 'o1', type, host: '127.0.0.1', port: 5432 }],
      checks: [{ id: 'allow', title: 'Allowed', category: 'Synthetic', severity: 'control', actorId: 'anon', method: 'GET', path: '/allowed', evidenceRequirement: 'response', assertions: [{ kind: 'status.equals', expected: 200 }] }] };
    assert.throws(() => validateTargetFile({ schemaVersion: 1, targets: [target] }), /observer "type" must be one of/, type);
  }
});
