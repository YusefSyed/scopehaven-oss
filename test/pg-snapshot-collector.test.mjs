// The pg-snapshot collector identity (pg-snapshot/5, src/collector-identity.mjs): a pg-snapshot observer's run record names
// the reader code that read it, read-back rules, the background-writer rules, the actor capture's join and the Supabase rules
// included, and a run recorded before it (no collector, pg-snapshot/1 to /4) still validates.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, appendFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { COLLECTOR_RECORDS, COLLECTOR_FILES, KNOWN_COLLECTOR_LABELS, collectorDigest, validCollector } from '../src/collector-identity.mjs';
import { declaredObserverRecord } from '../src/http-effects.mjs';

test('pg-snapshot/5: the record covers the observer, its wire client, the read-back and background-writer rules, the actor capture, the Supabase rules, and any edit to them moves it', async () => {
  // The catalog fingerprint the observer reads at each mark joins its files; pg-snapshot/2: the end barrier, the run lease,
  // and the ignore-list reader with the two lists it reads at import; pg-snapshot/3: the actor capture the join reads; /4: the Supabase rules.
  assert.deepEqual(COLLECTOR_FILES['pg-snapshot'], ['factory.mjs', 'pg-wire.mjs', 'pg-snapshot.mjs', '../../src/pg-readback.mjs', 'catalog.mjs',
    'end-barrier.mjs', 'run-lease.mjs', 'ignore-lists/ignore-list.mjs', 'ignore-lists/supabase.json', 'ignore-lists/litestream.json', 'pg-actor.mjs', 'supabase-rules.mjs']);
  assert.equal(COLLECTOR_RECORDS['pg-snapshot'].label, 'pg-snapshot/5');
  assert.ok(KNOWN_COLLECTOR_LABELS.includes('pg-snapshot/5') && validCollector('pg-snapshot', COLLECTOR_RECORDS['pg-snapshot']));
  // A run an earlier reader recorded still validates; it never compares with this one (the digest differs).
  for (const label of ['pg-snapshot/1', 'pg-snapshot/2', 'pg-snapshot/3', 'pg-snapshot/4']) assert.ok(validCollector('pg-snapshot', { ...COLLECTOR_RECORDS['pg-snapshot'], label }), label);
  assert.equal(COLLECTOR_RECORDS['pg-snapshot'].digest, await collectorDigest(COLLECTOR_FILES['pg-snapshot']));
  // The same bytes in another place hash the same; a change to the read-back rules does not.
  const root = await mkdtemp(join(tmpdir(), 'scopehaven pg collector '));
  try {
    const observers = join(root, 'integrations', 'observers'), src = join(root, 'src');
    await mkdir(join(observers, 'ignore-lists'), { recursive: true }); await mkdir(src, { recursive: true });
    for (const name of COLLECTOR_FILES['pg-snapshot']) await copyFile(new URL(`../integrations/observers/${name}`, import.meta.url), join(observers, name));
    const base = pathToFileURL(`${observers}/`);
    assert.equal(await collectorDigest(COLLECTOR_FILES['pg-snapshot'], base), COLLECTOR_RECORDS['pg-snapshot'].digest, 'path-independent');
    // An edit to a platform list the reader reads at import moves it (one edit at a time, the copy restored between them).
    await appendFile(join(observers, 'ignore-lists', 'supabase.json'), '\n');
    assert.notEqual(await collectorDigest(COLLECTOR_FILES['pg-snapshot'], base), COLLECTOR_RECORDS['pg-snapshot'].digest, 'ignore list');
    await copyFile(new URL('../integrations/observers/ignore-lists/supabase.json', import.meta.url), join(observers, 'ignore-lists', 'supabase.json'));
    assert.equal(await collectorDigest(COLLECTOR_FILES['pg-snapshot'], base), COLLECTOR_RECORDS['pg-snapshot'].digest, 'restored');
    await appendFile(join(src, 'pg-readback.mjs'), '\n');
    assert.notEqual(await collectorDigest(COLLECTOR_FILES['pg-snapshot'], base), COLLECTOR_RECORDS['pg-snapshot'].digest);
  } finally { await rm(root, { recursive: true, force: true }); }
  const [declared] = declaredObserverRecord([{ id: 'db', type: 'pg-snapshot', host: '127.0.0.1', port: 5432, database: 'app', credentialEnv: 'SCOPEHAVEN_TARGET_DB_READER', tables: [{ table: 'Chat', key: 'id' }], settleMs: 250 }]);
  assert.deepEqual(declared.collector, COLLECTOR_RECORDS['pg-snapshot']);
});
