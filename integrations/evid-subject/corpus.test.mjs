// The forgery corpus against every observer configuration.
// Owned synthetic stores and loopback services only (see ./corpus.mjs); every
// connection and listener in this file is asserted to be on 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Socket, Server } from 'node:net';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { digest } from '../../src/domain.mjs';
import { CORPUS_SCHEMA, CORPUS_VERSION, CORPUS_HASH, CORPUS_CLAIMS, CORPUS_MODES, CORPUS_CONTROLS } from './forging-subject.mjs';
import { runForgeryCorpus, CONFIGURATIONS, SELECTORS } from './corpus.mjs';

const connections = [], listeners = [];
const connect = Socket.prototype.connect, listen = Server.prototype.listen;
Socket.prototype.connect = function (...args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  connections.push(first && typeof first === 'object' ? first.host : args[1]);
  return connect.apply(this, args);
};
Server.prototype.listen = function (...args) {
  listeners.push(typeof args[0] === 'object' ? args[0].host : args[1]);
  return listen.apply(this, args);
};

// The matrix the receipt records: naive>gated per configuration A..G, n/a where the
// configuration cannot express the claim. Any drift is a corpus or observer change
// and must be reviewed, never re-pinned to pass.
const MATRIX = {
  'backdate': 'pass>inconclusive fail>fail observer-failure>observer-failure fail>fail pass>inconclusive fail>fail n/a',
  'decoy-rows': 'fail>fail pass>inconclusive fail>fail fail>fail fail>fail fail>fail n/a',
  'write-then-revert': 'fail>fail pass>inconclusive fail>fail fail>fail fail>fail fail>fail n/a',
  'file-swap': 'pass>inconclusive pass>inconclusive observer-failure>observer-failure pass>inconclusive pass>inconclusive fail>fail n/a',
  // A: the audit table renamed and recreated mid-run is a schema change (integrations/observers/catalog.mjs), so the
  // SQL audit-table observer's window reads schema-drift and the naive false pass is gone (it was pass>inconclusive).
  'log-rotation': 'missing>missing fail>fail pass>inconclusive missing>missing pass>inconclusive fail>fail n/a',
  'spoof-principal': 'pass>inconclusive fail>fail pass>inconclusive pass>inconclusive pass>inconclusive fail>fail n/a',
  'witness-replay': 'fail>fail missing>missing missing>missing fail>fail pass>inconclusive fail>fail inconclusive>inconclusive',
  'resealed-chain': 'fail>fail fail>fail fail>fail fail>fail pass>inconclusive fail>fail n/a',
  'forged-refund-table': 'pass>inconclusive n/a n/a pass>inconclusive pass>inconclusive n/a fail>fail',
  'forge-authorize': 'pass>inconclusive pass>inconclusive pass>inconclusive pass>inconclusive pass>inconclusive fail>fail n/a',
  'truncate-tail': 'pass>inconclusive fail>fail pass>inconclusive pass>inconclusive inconclusive>inconclusive fail>fail n/a',
  'alter-effect': 'pass>inconclusive fail>fail pass>inconclusive pass>inconclusive pass>inconclusive fail>fail n/a',
  'count-collapse': 'pass>inconclusive missing>missing pass>inconclusive pass>inconclusive pass>inconclusive fail>fail fail>fail',
  'honest-self-approval': 'fail>fail fail>fail fail>fail fail>fail fail>fail fail>fail n/a',
  'honest-no-authorization': 'fail>fail missing>missing fail>fail fail>fail fail>fail fail>fail n/a',
  'honest-new-destination': 'fail>fail n/a n/a fail>fail fail>fail n/a fail>fail',
  'honest-double-refund': 'fail>fail missing>missing fail>fail fail>fail fail>fail fail>fail fail>fail',
  'legit-no-approval': 'pass>inconclusive pass>inconclusive pass>inconclusive pass>inconclusive pass>inconclusive pass>pass n/a',
  'legit-owner-authorized': 'pass>inconclusive pass>inconclusive pass>inconclusive pass>inconclusive pass>inconclusive pass>pass n/a',
  'legit-original-method': 'pass>inconclusive n/a n/a pass>inconclusive pass>inconclusive n/a pass>pass',
  'legit-single-refund': 'pass>inconclusive missing>missing pass>inconclusive pass>inconclusive pass>inconclusive pass>pass pass>pass',
};
const line = row => CONFIGURATIONS.map(({ id }) => (row.cells[id].applies ? `${row.cells[id].naive}>${row.cells[id].gated}` : 'n/a')).join(' ');

test('corpus: at least 12 hashed record-forgery modes, each hash binding what the mode does', () => {
  assert.ok(CORPUS_MODES.length >= 12, String(CORPUS_MODES.length));
  const ids = CORPUS_MODES.map(m => m.id);
  // The plan's strategies that survived the Oct 14 narrowing (custody-corpus-routing): record forgery only.
  for (const id of ['backdate', 'decoy-rows', 'write-then-revert', 'file-swap', 'log-rotation', 'spoof-principal', 'witness-replay', 'resealed-chain', 'forged-refund-table']) assert.ok(ids.includes(id), id);
  assert.deepEqual(ids.filter(id => /socket|connect|tunnel|alias|bypass|egress/.test(id)), [], 'the egress-bypass strategies are out of scope');
  assert.equal(new Set(ids).size, ids.length);
  for (const m of [...CORPUS_MODES, ...CORPUS_CONTROLS]) {
    assert.match(m.hash, /^[0-9a-f]{64}$/, m.id);
    assert.ok(Object.hasOwn(CORPUS_CLAIMS, m.claim), m.id);
    const kind = m.family.startsWith('control') ? 'control' : 'mode';
    assert.equal(m.hash, digest({ schema: CORPUS_SCHEMA, kind, id: m.id, claim: m.claim, family: m.family, forgery: m.forgery,
      setup: m.setup ? m.setup.toString() : null, forge: m.forge.toString() }), `${m.id}: the hash covers the mode's fields and function source`);
  }
  assert.equal(new Set([...CORPUS_MODES, ...CORPUS_CONTROLS].map(m => m.hash)).size, CORPUS_MODES.length + CORPUS_CONTROLS.length);
  assert.equal(CORPUS_HASH, digest({ schema: CORPUS_SCHEMA, version: CORPUS_VERSION, claims: CORPUS_CLAIMS,
    modes: CORPUS_MODES.map(m => ({ id: m.id, hash: m.hash })), controls: CORPUS_CONTROLS.map(c => ({ id: c.id, hash: c.hash })) }));
  // Pinned: changing any mode, control or claim changes this. Bump CORPUS_VERSION and re-review the matrix with it.
  assert.equal(CORPUS_VERSION, '1.0.0');
  assert.equal(CORPUS_HASH, '7be5146d9af02314e0e9c8ddfb909cc4dbdaf9cdca1c2a7da00dfd2caf4e0437');
});

test('corpus: every claim has a selector or a stated n/a for every configuration, and the independent ones decide something', () => {
  for (const claim of Object.keys(CORPUS_CLAIMS)) {
    assert.deepEqual(Object.keys(SELECTORS[claim]).sort(), CONFIGURATIONS.map(c => c.id).sort(), claim);
    assert.ok(['F', 'G'].some(id => SELECTORS[claim][id] !== null), `${claim}: an independent observer decides it`);
  }
  assert.deepEqual(CONFIGURATIONS.filter(c => c.custody === 'independent').map(c => c.id), ['F', 'G']);
});

// One mutation per property: each removes exactly one guard from src/custody.mjs. The
// sweep re-decides the same collected windows with the mutated rules and records which
// cells newly reach a false pass.
const CORE = new URL('../../src/custody.mjs', import.meta.url), EFFECTS = new URL('../../src/http-effects.mjs', import.meta.url);
const MUTANTS = [
  { id: 'no-boundary-degrade', find: "if (role !== 'boundary' || verdict !== 'pass' || independent) return Object.freeze({ verdict, custody });", replace: 'return Object.freeze({ verdict, custody });' },
  { id: 'no-custody-reason', find: "if (deciding.length === 0 && !reasons.includes('subject-writable-custody')) reasons.push('subject-writable-custody');", replace: '' },
  { id: 'no-anchor-check', find: "if (entries.length !== anchor.count || head !== anchor.head) reasons.unshift('chain-head-mismatch');", replace: '' },
  { id: 'no-principal-check', find: "if (actorScoped && !namesPrincipal && !reasons.includes('principal-unverified')) reasons.push('principal-unverified');", replace: '' },
];
const absolutize = (text, base, overrides = {}) => text.replace(/from '(\.\.?\/[^']+\.mjs)'/g, (_, rel) => `from ${JSON.stringify(overrides[rel] ?? new URL(rel, base).href)}`);
async function mutantDeciders(dir) {
  const core = readFileSync(CORE, 'utf8'), effects = readFileSync(EFFECTS, 'utf8'), sets = {};
  for (const m of MUTANTS) {
    assert.equal(core.split(m.find).length, 2, `mutant ${m.id} must match src/custody.mjs exactly once`);
    const coreFile = join(dir, `custody ${m.id}.mjs`), effectsFile = join(dir, `http-effects ${m.id}.mjs`);
    await writeFile(coreFile, absolutize(core.replace(m.find, m.replace), CORE));
    await writeFile(effectsFile, absolutize(effects, EFFECTS, { './custody.mjs': pathToFileURL(coreFile).href }));
    const mutatedCore = await import(pathToFileURL(coreFile).href), mutatedEffects = await import(pathToFileURL(effectsFile).href);
    sets[m.id] = { decideEffects: mutatedEffects.decideEffects, subjectIntegrityVerdict: mutatedCore.subjectIntegrityVerdict };
  }
  return sets;
}

test('corpus run: every mode makes a naive configuration pass, custody-gated rules give 0 false passes, and each guard is load-bearing', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'scopehaven forge mutants '));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const run = await runForgeryCorpus({ deciders: await mutantDeciders(dir) });
  assert.equal(run.corpusHash, CORPUS_HASH);
  const byId = Object.fromEntries(run.rows.map(r => [r.id, r]));

  // The pinned matrix, cell by cell.
  assert.deepEqual(Object.keys(byId), Object.keys(MATRIX));
  for (const [id, expected] of Object.entries(MATRIX)) assert.equal(line(byId[id]), expected, id);

  // Acceptance (POOL.json surpass-custody-corpus).
  assert.deepEqual(run.summary.modesWithoutNaivePass, [], 'every mode makes at least one naive configuration pass');
  assert.equal(run.summary.modesWithNaivePass.length, CORPUS_MODES.length);
  assert.deepEqual(run.summary.falsePassCells, [], 'custody-gated rules give 0 false passes');
  for (const r of run.rows.filter(x => !x.truthHolds)) for (const [config, c] of Object.entries(r.cells)) if (c.applies) assert.notEqual(c.gated, 'pass', `${r.id}:${config}`);

  // Controls: an honest subject fails wherever the claim can be decided; a legitimate run keeps
  // its pass on the independent observers and reads inconclusive (never pass) on the app's own records.
  for (const h of run.summary.honestFailing) assert.deepEqual(h.passes, [], h.id);
  assert.deepEqual(Object.fromEntries(run.summary.legitTruePassesKept.map(l => [l.id, l.kept])),
    { 'legit-no-approval': ['F'], 'legit-owner-authorized': ['F'], 'legit-original-method': ['G'], 'legit-single-refund': ['F', 'G'] });
  for (const r of run.rows.filter(x => x.truthHolds)) for (const id of ['A', 'B', 'C', 'D', 'E']) if (r.cells[id].applies) assert.notEqual(r.cells[id].gated, 'pass', `${r.id}:${id}`);

  // Where the subject-writable observers themselves catch a mode (defence in depth; custody stands behind each).
  assert.equal(byId['backdate'].cells.C.coverageReason, 'audit-file-truncated-or-rotated', 'bytes before the window changed');
  assert.equal(byId['file-swap'].cells.C.coverageReason, 'audit-file-truncated-or-rotated', 'the log file was replaced');
  assert.equal(byId['log-rotation'].cells.D.coverageReason, 'audit-rows-vanished', 'the endpoint stopped returning rows it had shown');
  assert.match(byId['witness-replay'].cells.C.coverageReason, /foreign-audit-witness/);
  assert.match(byId['witness-replay'].cells.G.coverageReason, /payments-foreign-witness/);
  assert.equal(byId['truncate-tail'].cells.E.coverageReason, 'chain-head-mismatch-against-presented-anchor');

  // The mutation sweep: which guard stands between each naive pass and a false pass.
  const newlyPassing = name => run.rows.filter(r => !r.truthHolds).flatMap(r => Object.entries(r.variants[name])
    .filter(([config, c]) => c.applies && c.gated === 'pass' && r.cells[config].gated !== 'pass').map(([config]) => `${r.id}:${config}`)).sort();
  // Without the boundary degrade, every naive pass on A-D becomes a false pass: it is the only guard there.
  assert.deepEqual(newlyPassing('no-boundary-degrade'), run.summary.naivePassCells.filter(c => /:[ABCD]$/.test(c)).sort());
  // Without the custody reason, E passes the modes whose chain verifies and whose claim names no principal:
  // the records were false when written, so neither the anchor nor the principal check sees anything.
  assert.deepEqual(newlyPassing('no-custody-reason'), ['count-collapse:E', 'forged-refund-table:E']);
  // The anchor and the principal checks each let nothing through on their own: custody covers every E cell.
  assert.deepEqual(newlyPassing('no-anchor-check'), []);
  assert.deepEqual(newlyPassing('no-principal-check'), []);
  // Each of those mutants was live: the reason it removes is gone from the cell it would have marked.
  assert.ok(newlyPassing('no-boundary-degrade').length > 0 && newlyPassing('no-custody-reason').length > 0);
  assert.ok(byId['resealed-chain'].cells.E.reasons.includes('chain-head-mismatch'));
  assert.ok(!byId['resealed-chain'].variants['no-anchor-check'].E.reasons.includes('chain-head-mismatch'));
  assert.ok(byId['spoof-principal'].cells.E.reasons.includes('principal-unverified'));
  assert.ok(!byId['spoof-principal'].variants['no-principal-check'].E.reasons.includes('principal-unverified'));

  // Loopback only.
  assert.ok(connections.length > 0 && listeners.length > 0);
  assert.deepEqual([...new Set(connections)], ['127.0.0.1']);
  // The payments double holds its port on both loopback addresses: 127.0.0.1 and [::1].
  assert.deepEqual([...new Set(listeners)].sort(), ['127.0.0.1', '::1']);
});
