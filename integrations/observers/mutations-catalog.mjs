#!/usr/bin/env node
// Mutation sweep for the catalog fingerprint: its reader, rule, exclusions and record (./catalog.mjs), and its use in
// pg-snapshot, pg-wal and the SQLite observers. One mutation per property; each must make a test fail. A survivor is a
// test gap.
//   node integrations/observers/mutations-catalog.mjs [--out FILE] [--only ID,ID...]
// As mutations-background-writers.mjs: a temporary copy (in a folder whose name has spaces) of the modules the tests load,
// never the checkout; the tests run once unmutated (they must pass), then once per mutation. Each edit must match once. A
// mutation runs the unit tests first; one marked live that survives them runs the live tests too when SCOPEHAVEN_PG_LIVE
// names a disposable server (else it reads needs-live). Tests run in-process (--test-isolation=none), one file at a time.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const UNIT = ['integrations/observers/catalog.test.mjs', 'integrations/observers/pg-wal.test.mjs'];
const LIVE = ['integrations/observers/catalog.live.test.mjs'];
const m = (id, property, file, edits, { live = false } = {}) => ({ id, property, file, edits, live });
const I = 'src/catalog-identity.mjs', C = 'integrations/observers/catalog.mjs', S = 'integrations/observers/pg-snapshot.mjs', W = 'integrations/observers/pg-wal.mjs', Q = 'integrations/observers/sqlite.mjs';
export const MUTATIONS = [
  // The rule.
  m('R1', 'the start mark\'s definitions are compared with the baseline', C, [['if (before.sha256 !== baseline.sha256 || after.sha256', 'if (after.sha256']]),
  m('R2', 'the end mark\'s definitions are compared with the baseline', C, [['before.sha256 !== baseline.sha256 || after.sha256 !== baseline.sha256 || ', 'before.sha256 !== baseline.sha256 || ']]),
  m('R3', 'a change made and changed back between the marks (the instance) reads schema-drift', C, [[' || before.instance !== after.instance) return [SCHEMA_DRIFT];', ') return [SCHEMA_DRIFT];']]),
  m('R4', 'a relation\'s catalog row moved under the same file node reads schema-drift', C, [["if (was !== undefined && was !== version && was.split('/')[1] === version.split('/')[1]) return [SCHEMA_DRIFT];", 'if (false) return [SCHEMA_DRIFT];']]),
  m('R5', 'a rewrite (a new file node) is not a schema change', C, [["was !== version && was.split('/')[1] === version.split('/')[1]) return", 'was !== version) return']]),
  m('R6', 'no baseline reads catalog-unreadable', C, [['if (!baseline?.ok || !before?.ok || !after?.ok) return [CATALOG_UNREADABLE];', 'if (!before?.ok || !after?.ok) return [CATALOG_UNREADABLE];\n  if (!baseline?.ok) return [];']]),
  m('R7', 'an unreadable mark reads catalog-unreadable', C, [['if (!baseline?.ok || !before?.ok || !after?.ok) return [CATALOG_UNREADABLE];', 'if (!baseline?.ok) return [CATALOG_UNREADABLE];\n  if (!before?.ok || !after?.ok) return [];']]),
  // The reader.
  m('P1', 'the kinds are read in order, one row each', C, [['rows.length !== kinds.length || !rows.every((r, i) => r.length === 4 && r[0] === kinds[i] && ', 'rows.length !== kinds.length || !rows.every((r, i) => r.length === 4 && ']]),
  m('P2', 'a digest that is not sha256 hex has no fingerprint', C, [['&& HEX64.test(r[2]) && HEX64.test(r[3])))', '))']]),
  m('P4', 'a count is part of the definition digest', C, [['kinds: kinds.map(k => [k.kind, k.objects, k.sha256])', 'kinds: kinds.map(k => [k.kind, k.sha256])']]),
  m('P5', 'the definition digest leaves the instance out', C, [['kinds: kinds.map(k => [k.kind, k.objects, k.sha256]) }),', 'kinds: kinds.map(k => [k.kind, k.objects, k.sha256, k.instance]) }),']]),
  // The exclusions.
  m('X1', 'a platform entry that covers a declared table or queue is not applied', C, [['const kept = (ignoreList?.platformEntries ?? []).filter(e => !covers(e));', 'const kept = (ignoreList?.platformEntries ?? []);']]),
  m('X2', 'a profile\'s own ignore entries stay in the fingerprint', C, [['const kept = (ignoreList?.platformEntries ?? []).filter', 'const kept = (ignoreList?.entries ?? []).filter']]),
  m('X3', 'SQLite names compare without case for the exclusions', C, [["const fold = n => (engine === 'sqlite' ? n.replace(/[A-Z]/g, c => c.toLowerCase()) : n);", 'const fold = n => n;']]),
  m('X4', 'an excluded schema is left out of both statements', C, [['const outSchemas = schemas.length ? ` AND n.nspname NOT IN (${schemas.map(literal).join(\', \')})` : \'\';', "const outSchemas = '';"]]),
  m('X6', 'identifiers in the exclusions are checked', C, [['const literal = name => { if (!IDENT.test(name)) throw', 'const literal = name => { if (false) throw']]),
  // What the Postgres read covers (live).
  m('L1', 'partitions are not relations of their own', C, [['rel AS (SELECT * FROM relall WHERE NOT relispartition)', 'rel AS (SELECT * FROM relall)']], { live: true }),
  m('L2', 'the clones a partitioned table\'s trigger makes are left out', C, [['WHERE NOT g.tgisinternal AND g.tgparentid = 0', 'WHERE NOT g.tgisinternal']], { live: true }),
  m('L3', 'another session\'s temporary schema is left out', C, [["AND n.nspname !~ '^pg_(toast_)?temp_'", '']], { live: true }),
  m('L5', 'a column\'s position is among the live columns, not its attnum', C, [['pg_catalog.row_number() OVER (PARTITION BY a.attrelid ORDER BY a.attnum)', 'a.attnum']], { live: true }),
  m('L7', 'a trigger\'s row version is its token (disabled and enabled again)', C, [["pg_catalog.json_build_array(pg_catalog.pg_get_triggerdef(g.oid), g.tgenabled)::pg_catalog.text, g.xmin::pg_catalog.text", "pg_catalog.json_build_array(pg_catalog.pg_get_triggerdef(g.oid), g.tgenabled)::pg_catalog.text, ''"]], { live: true }),
  m('L8', 'a policy\'s definition is its USING and WITH CHECK', C, [['pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))', 'NULL, NULL)']], { live: true }),
  m('L9', 'a relation\'s row-level security flag is in its definition', C, [['pg_catalog.json_build_array(r.relkind, r.relpersistence, r.relrowsecurity, r.relforcerowsecurity,', 'pg_catalog.json_build_array(r.relkind, r.relpersistence, r.relforcerowsecurity,']], { live: true }),
  m('P3', 'more versioned rows than the limit have no fingerprint', C, [['if (versions.length > CATALOG_LIMITS.versions || ', 'if (']]),
  m('X5', 'a platform table entry stays in on Postgres (its grants, policies and triggers)', C, [["tables: Object.freeze(engine === 'sqlite' ? kept.filter(e => e.table !== null).map(e => `${e.schema}.${e.table}`).sort() : [])", 'tables: Object.freeze(kept.filter(e => e.table !== null).map(e => `${e.schema}.${e.table}`).sort())']]),
  // The catalog's own session and the bracket.
  m('B1', 'a mark\'s two catalog reads that differ make it unstable', C, [['stable: catalogReasons(first, first, second).length === 0', 'stable: true']]),
  m('B2', 'an unstable mark or baseline reads schema-drift', C, [['  if (baseline.stable === false || before.stable === false || after.stable === false) return [SCHEMA_DRIFT];\n', '']]),
  m('B3', 'an error on the catalog\'s session reads as no fingerprint, never as a failed mark', C, [['      } catch { return UNREADABLE; }', '      } catch (error) { throw error; }']]),
  m('B4', 'the catalog\'s session waits for a lock at most lockTimeoutMs', C, [['`SET lock_timeout = ${Math.min(CATALOG_LIMITS.lockTimeoutMs, statementTimeoutMs)}`, ', '']]),
  m('B5', 'the catalog\'s session pins identifier quoting', C, [["'SET quote_all_identifiers = off', ", '']]),
  m('B6', 'the catalog\'s session turns JIT off', C, [[", 'SET jit = off']);", ']);']]),
  m('W6', 'pg-wal: its own policy read prints nothing, so it takes no lock on what a policy names', W, [['po.polroles::text, po.polqual::text, po.polwithcheck::text, po.xmin::text)', 'po.polroles::text, pg_catalog.pg_get_expr(po.polqual, po.polrelid), pg_catalog.pg_get_expr(po.polwithcheck, po.polrelid), po.xmin::text)']], { live: true }),
  // More of what the Postgres read covers (live).
  m('L6', 'a relation\'s kind token is its oid, not its row version (a rewrite is not a change)', C, [['        r.oid::pg_catalog.text FROM rel r', '        r.xmin::pg_catalog.text FROM rel r']], { live: true }),
  m('L10', 'the relations\' versions are read with their row versions', C, [['SELECT r.oid::pg_catalog.text AS id, r.xmin::pg_catalog.text AS xmin', 'SELECT r.oid::pg_catalog.text AS id, r.oid::pg_catalog.text AS xmin']], { live: true }),
  m('T1', 'a partition\'s trigger whose enabled state differs from its parent\'s is kept', C, [['FROM trg g WHERE g.tgparentid <> 0 AND g.tgenabled IS DISTINCT FROM g.parentenabled', 'FROM trg g WHERE false']], { live: true }),
  m('T2', 'an internal trigger that is not enabled is kept', C, [["FROM trg g WHERE g.tgisinternal AND g.tgparentid = 0 AND g.tgenabled <> 'O'", 'FROM trg g WHERE false']], { live: true }),
  m('T3', 'clones and internal triggers are versioned (disabled and enabled again)', C, [["\n      UNION ALL SELECT 't' || g.oid::pg_catalog.text, g.xmin::pg_catalog.text, '' FROM trg g WHERE g.tgisinternal OR g.tgparentid <> 0", '']], { live: true }),
  m('K10', 'a constraint a partition attach clones is its parent\'s', C, [['WHERE k.conparentid = 0 AND ((k.conrelid', 'WHERE ((k.conrelid']], { live: true }),
  m('M1', 'a materialized view\'s own row is not versioned (REFRESH ... CONCURRENTLY)', C, [["FROM relall r WHERE r.relkind <> 'm'", 'FROM relall r']], { live: true }),
  m('D1', 'replica identity is in a relation\'s definition', C, [["${user('r.relowner')}, r.relreplident,", "${user('r.relowner')},"]], { live: true }),
  m('D2', 'inheritance parents are in a relation\'s definition', C, [["${agg(`SELECT ${qname('pn.nspname', 'pc.relname')} AS x FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class pc ON pc.oid = i.inhparent", "${agg(`SELECT ${qname('pn.nspname', 'pc.relname')} AS x FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class pc ON false"]], { live: true }),
  m('D3', 'a partitioned table carries its partitions\' grants and row-level security', C, [["CASE WHEN r.relkind = 'p' THEN ${agg(`WITH RECURSIVE down(oid)", "CASE WHEN false THEN ${agg(`WITH RECURSIVE down(oid)"]], { live: true }),
  m('D4', 'a policy\'s roles are sorted by name', C, [["${agg(`SELECT CASE WHEN g = 0 THEN 'public' ELSE ${user('g')}::pg_catalog.text END AS x FROM pg_catalog.unnest(p.polroles) g`)}", "(SELECT pg_catalog.array_agg(CASE WHEN g = 0 THEN 'public' ELSE ${user('g')}::pg_catalog.text END) FROM pg_catalog.unnest(p.polroles) g)::pg_catalog.text"]], { live: true }),
  m('N1', 'publications are covered', C, [['      FROM pg_catalog.pg_publication p\n', '      FROM pg_catalog.pg_publication p WHERE false\n']], { live: true }),
  m('N2', 'default privileges are covered', C, [['      FROM pg_catalog.pg_default_acl d\n', '      FROM pg_catalog.pg_default_acl d WHERE false\n']], { live: true }),
  m('N3', 'operators are covered', C, [['      FROM pg_catalog.pg_operator o JOIN nsp n ON n.oid = o.oprnamespace\n', '      FROM pg_catalog.pg_operator o JOIN nsp n ON n.oid = o.oprnamespace WHERE false\n']], { live: true }),
  m('N4', 'casts are covered', C, [['FROM pg_catalog.pg_cast c WHERE c.oid >= 16384),', 'FROM pg_catalog.pg_cast c WHERE false),']], { live: true }),
  m('N5', 'foreign servers are covered', C, [['FROM pg_catalog.pg_foreign_server s JOIN pg_catalog.pg_foreign_data_wrapper w ON w.oid = s.srvfdw', 'FROM pg_catalog.pg_foreign_server s JOIN pg_catalog.pg_foreign_data_wrapper w ON false']], { live: true }),
  m('L4', 'an extension\'s own objects are read like any other (a member function\'s SECURITY DEFINER and grants)', C, [['      FROM pg_catalog.pg_proc p JOIN nsp n ON n.oid = p.pronamespace\n', "      FROM pg_catalog.pg_proc p JOIN nsp n ON n.oid = p.pronamespace WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid = p.oid AND d.deptype = 'e')\n"]], { live: true }),
  m('P6', 'a partitioned table\'s set carries its partitions\' column grants', C, [['(SELECT pg_catalog.json_agg(pg_catalog.json_build_array(a.attname, a.attacl::pg_catalog.text) ORDER BY a.attname) FROM pg_catalog.pg_attribute a WHERE a.attrelid = pc.oid AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL))', 'NULL))']], { live: true }),
  m('P7', 'a partitioned table\'s set covers its partitions at every level', C, [[' UNION SELECT i.inhrelid FROM pg_catalog.pg_inherits i JOIN down ON i.inhparent = down.oid)', ')']], { live: true }),
  m('O1', 'an option whose name reads as a secret is kept by its name only', C, [["THEN pg_catalog.split_part(o, '=', 1) ELSE o END", 'THEN o ELSE o END']], { live: true }),
  m('R8', 'the baseline is tried again when it does not read', C, [['export const CATALOG_BASELINE = Object.freeze({ attempts: 3, pauseMs: 250 });', 'export const CATALOG_BASELINE = Object.freeze({ attempts: 1, pauseMs: 250 });']]),
  m('S6', 'pg-snapshot: each mark is bracketed by two catalog reads', S, [['return { ...mark, catalog: bracketCatalog(first, second), catalogLatest: second };', 'return { ...mark, catalog: first, catalogLatest: second };']]),
  m('S7', 'pg-snapshot: a start without a baseline is refused', S, [['        if (!baseline.ok) throw new Error(BASELINE_REFUSED);\n', '']]),
  m('W2', 'pg-wal: start() reads the baseline', W, [['        try { baseline = await readPgCatalogBaseline(catalogSession); } finally { catalogSession.close(); }', "        try { baseline = { ok: false, reason: 'catalog-unreadable' }; } finally { catalogSession.close(); }"]]),
  m('W3', 'pg-wal: a baseline that never reads refuses the start, and the slot goes with it', W, [['        if (!baseline.ok) { await drop(); throw new Error(BASELINE_REFUSED); }\n', '']]),
  m('W4', 'pg-wal: each mark is bracketed by two catalog reads', W, [['return { ...mark, dbCatalog: bracketCatalog(first, second), dbCatalogLatest: second, ...(actors ? { actor: await actorMark() } : {}) };', 'return { ...mark, dbCatalog: first, dbCatalogLatest: second, ...(actors ? { actor: await actorMark() } : {}) };']]),
  // The run's catalog identity (src/catalog-identity.mjs).
  m('I1', 'the identity\'s records are in instance order', I, [['.filter(r => r !== null && typeof r === \'object\').sort(byInstance);', '.filter(r => r !== null && typeof r === \'object\');']]),
  m('I2', 'the identity\'s digest covers each record\'s exclusions', I, [['r.schema, r.sha256, r.excluded ?? null]', 'r.schema, r.sha256]']]),
  m('I3', 'an unknown start leaves the identity\'s digest null', I, [['sha256: known ? digest(', 'sha256: true ? digest(']]),
  m('I4', 'the validator recomputes the digest', I, [['return identity.sha256 === catalogIdentity(observers).sha256 && observers', 'return observers']]),
  m('I5', 'the validator accepts the declared database observers only', I, [["typeof r.instanceId === 'string' && instanceIds.includes(r.instanceId) &&", "typeof r.instanceId === 'string' &&"]]),
  m('I6', 'the validator holds the records to instance order (and each instance to once)', I, [['&& observers.every((r, i) => i === 0 || byInstance(observers[i - 1], r) < 0);', ';']]),
  m('I7', 'a record holds its engine\'s kinds exactly', I, [['&& Object.keys(kinds).length === CATALOG_RECORD_KINDS[engine].length', '']]),
  m('I8', 'a Postgres record has no table exclusions', I, [[" && (r.engine === 'sqlite' || r.excluded.tables.length === 0)", '']]),
  m('I9', 'a record without a baseline never drifted', I, [[" && r.changedDuringRun === false", '']]),
  // SQLite.
  m('Q1', 'SQLite\'s own objects are left out (its statistics table)', C, [["SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite\\\\_%' ESCAPE '\\\\' ORDER BY type, name", 'SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name']]),
  m('Q2', 'a platform\'s SQLite tables are left out with their indexes and triggers', C, [['.filter(r => !out.has(fold(String(r.tbl_name))));', '.filter(() => true);']]),
  m('Q3', 'user_version is part of the SQLite definition', C, [["byKind.pragma = [['user_version', pragma('user_version')], ['application_id'", "byKind.pragma = [['application_id'"]]),
  m('Q4', 'the schema cookie is the SQLite instance', C, [['instance: digest([byKind[kind], cookie])', 'instance: digest([byKind[kind]])']]),
  m('Q5', 'sqlite-snapshot: the catalog reasons join the window', Q, [['...(before.otherRuns > 0 || after.otherRuns > 0 ? [\'shared-database\'] : []), ...catalogReasons(baseline, before.catalog, after.catalog)].sort();', "...(before.otherRuns > 0 || after.otherRuns > 0 ? ['shared-database'] : [])].sort();"]]),
  m('Q6', 'sqlite-snapshot: the baseline is start()\'s own reading', Q, [['      try { baseline = (await read()).catalog; } catch (error) { lease?.release(); throw error; }', '      try { await read(); } catch (error) { lease?.release(); throw error; }']]),
  m('Q7', 'sqlite-snapshot: marked without start(), the first mark is the baseline', Q, [['      const taken = snapshots.at(-1);\n      if (taken.ok) baseline ??= taken.catalog;\n', '      const taken = snapshots.at(-1);\n']]),
  m('Q8', 'sqlite-snapshot: the record says the run changed', Q, [["      drifted ||= reasons.includes(SCHEMA_DRIFT);\n      const background = watchOthers", '      const background = watchOthers'],
    ['if (taken.ok && taken.catalog.ok) { latest = taken.catalog; drifted ||= Boolean(baseline?.ok) && taken.catalog.sha256 !== baseline.sha256; }', 'if (taken.ok && taken.catalog.ok) { latest = taken.catalog; }']]),
  m('Q9', 'sqlite audit table: the catalog reasons make the window partial', Q, [["return { events, coverage: reasons.length ? 'partial' : 'complete', reason: reasons.length ? reasons.join(',') : null };", "return { events, coverage: truncated ? 'partial' : 'complete', reason: truncated ? 'audit-row-limit' : null };"]]),
  m('Q10', 'sqlite audit table: the baseline is start()\'s own reading', Q, [['    async start() { baseline = (await maxId()).catalog; },', '    async start() { await maxId(); },']]),
  // Two runs' records.
  m('K1', 'runs from before the catalog fingerprint (no records) read as before', C, [["if (!listed(before) && !listed(after)) return { state: 'not-recorded', flags: [], duringRun: [] };", "if (!listed(before) && !listed(after)) return notComparable('none');"]]),
  m('K2', 'one run alone recorded is not comparable', C, [["if (!listed(before) || !listed(after)) return notComparable('one-run-only');", "if (!listed(before) || !listed(after)) return { state: 'unchanged', flags: [], duringRun: during };"]]),
  m('K3', 'another set of observers is not comparable', C, [["if (!sameIds || new Set(ids(before)).size !== before.length || ", 'if (']]),
  m('K4', 'other exclusions are not comparable', C, [["if (digest(a.excluded ?? null) !== digest(b.excluded ?? null)) return notComparable('exclusions-differ');", '']]),
  m('K5', 'an unreadable baseline is not comparable', C, [["if (!HEX64.test(a.sha256 ?? '') || !HEX64.test(b.sha256 ?? '')) return notComparable('baseline-unreadable');", '']]),
  m('K6', 'a changed observer names the kinds that changed', C, [['.filter(k => digest(a.kinds?.[k] ?? null) !== digest(b.kinds?.[k] ?? null)).sort();', '.sort();']]),
  m('K7', 'a run whose catalog changed during it says so', C, [["if (listed(records) && records.some(r => r?.changedDuringRun === true)) during.push(side);", '']]),
  m('K8', 'changed definitions are migration-between-runs', C, [["return observers.length ? { state: 'changed', flags: flags([MIGRATION_BETWEEN_RUNS])", "return observers.length ? { state: 'changed', flags: flags([])"]]),
  m('K9', 'another engine or record version is not comparable', C, [["if (a.schema !== CATALOG_SCHEMA || b.schema !== CATALOG_SCHEMA || a.engine !== b.engine) return notComparable('record-differs');", '']]),
  // pg-snapshot.
  m('S1', 'pg-snapshot: the catalog reasons join the window', S, [['        ...catalogReasons(baseline, before.catalog, after.catalog)].sort();', '        ].sort();']]),
  m('S2', 'pg-snapshot: the baseline is start()\'s own reading, not the first mark\'s', S, [['        if (!baseline.ok) throw new Error(BASELINE_REFUSED);\n', '        if (!baseline.ok) throw new Error(BASELINE_REFUSED);\n        baseline = null;\n']]),
  m('S3', 'pg-snapshot: marked without start(), the first mark is the baseline', S, [['      if (taken.ok) baseline ??= taken.catalogLatest;\n', '']]),
  m('S4', 'pg-snapshot: the record says the run changed', S, [['      drifted ||= reasons.includes(SCHEMA_DRIFT);\n', ''], ['drifted ||= Boolean(baseline?.ok) && taken.catalog.sha256 !== baseline.sha256; }', '}']]),
  // pg-wal.
  m('W1', 'pg-wal: the catalog reasons join the window', W, [['    for (const r of catalogReasons(baseline, a.dbCatalog, b.dbCatalog)) reasons.add(r);\n', '']]),
  m('W5', 'pg-wal: the record says the run changed', W, [['    drifted ||= reasons.has(SCHEMA_DRIFT);\n', ''], ['drifted ||= Boolean(baseline?.ok) && taken.dbCatalog.sha256 !== baseline.sha256; }', '}']]),
];

function runFiles(root, files) {
  const failed = [];
  for (const file of files) {
    const out = spawnSync(process.execPath, ['--test', '--test-isolation=none', '--test-timeout=120000', file], { cwd: root, encoding: 'utf8', timeout: 600000, env: process.env });
    const lines = (out.stdout ?? '').split('\n');
    if (out.status !== 0) failed.push(...new Set(lines.filter(l => /^✖ /.test(l)).map(l => `${file.split('/').pop()}: ${l.slice(2).replace(/ \([\d.]+ms\)$/, '')}`)), ...(out.status === null ? [`${file.split('/').pop()}: timed out`] : []));
  }
  return failed;
}

async function main() {
  const arg = flag => (process.argv.includes(flag) ? process.argv[process.argv.indexOf(flag) + 1] : null);
  const outFile = arg('--out'), only = arg('--only')?.split(',') ?? null, live = Boolean(process.env.SCOPEHAVEN_PG_LIVE);
  const tmp = mkdtempSync(join(tmpdir(), 'scopehaven catalog mutations '));
  try {
    for (const dir of ['src', 'integrations', 'test']) cpSync(join(ROOT, dir), join(tmp, dir), { recursive: true });
    cpSync(join(ROOT, 'package.json'), join(tmp, 'package.json'));
    const base = runFiles(tmp, [...UNIT, ...(live ? LIVE : [])]);
    if (base.length) throw new Error(`Unmutated tests fail: ${base.join('; ')}`);
    const results = [];
    for (const mu of MUTATIONS.filter(x => !only || only.includes(x.id))) {
      const path = join(tmp, mu.file), original = readFileSync(path, 'utf8');
      const counts = mu.edits.map(([find]) => original.split(find).length - 1);
      if (counts.some(c => c !== 1)) { results.push({ id: mu.id, property: mu.property, status: 'not-applied', reason: `finds matched ${counts.join(', ')} times` }); process.stderr.write(`${mu.id} not-applied ${counts.join(',')}\n`); continue; }
      writeFileSync(path, mu.edits.reduce((text, [find, replace]) => text.replace(find, () => replace), original));
      try {
        let failed = runFiles(tmp, UNIT), by = 'unit';
        if (!failed.length && mu.live) { if (live) { failed = runFiles(tmp, LIVE); by = 'live'; } else by = 'needs-live'; }
        results.push({ id: mu.id, property: mu.property, file: mu.file, status: failed.length ? 'killed' : by === 'needs-live' ? 'needs-live' : 'SURVIVED', by, killedBy: failed.slice(0, 3) });
      } finally { writeFileSync(path, original); }
      process.stderr.write(`${mu.id} ${results.at(-1).status} ${results.at(-1).by ?? ''}\n`);
    }
    const summary = { schema: 'scopehaven-catalog-mutations/1', at: new Date().toISOString(), node: process.version, live, unit: UNIT, liveTests: LIVE, total: results.length, killed: results.filter(r => r.status === 'killed').length, results };
    if (outFile) writeFileSync(outFile, `${JSON.stringify(summary, null, 1)}\n`);
    process.stdout.write(`${JSON.stringify({ total: summary.total, killed: summary.killed, survivors: results.filter(r => r.status !== 'killed').map(r => `${r.id} ${r.status}`) })}\n`);
    if (summary.killed !== summary.total) process.exitCode = 1;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
